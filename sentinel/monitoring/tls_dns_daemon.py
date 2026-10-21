"""Continuous TLS Certificate Expiration & DNS Drift Monitoring Daemon for Sentinel.

Monitors critical assets (defaulting to friday-universe.duckdns.org and registered targets)
for TLS certificate expiration (<30d WARNING, <7d CRITICAL), unauthorized DNS drift,
and records all tamper-evident alerts to the cryptographic audit ledger.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import audit_logger
from sentinel.core.events.bus import emit_event
from sentinel.core.models import EventType, SeverityLevel
from sentinel.monitoring.continuous import (
    ContinuousMonitor,
    DriftAlert,
)
from sentinel.monitoring.continuous import (
    continuous_monitor as default_monitor,
)

logger = logging.getLogger("sentinel.monitoring.tls_dns")


class TLSCertificateCheckResult(BaseModel):
    """Result of an asynchronous TLS certificate inspection."""

    hostname: str
    port: int = 443
    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    san_list: list[str] = Field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_remaining: int = 90
    severity: SeverityLevel = SeverityLevel.LOW
    is_expired: bool = False
    status: str = "HEALTHY"
    error_message: str | None = None


class DNSDriftCheckResult(BaseModel):
    """Result of DNS record resolution and baseline drift evaluation."""

    hostname: str
    observed_records: dict[str, list[str]] = Field(default_factory=dict)
    baseline_records: dict[str, list[str]] = Field(default_factory=dict)
    drift_detected: bool = False
    drift_details: list[str] = Field(default_factory=list)
    severity: SeverityLevel = SeverityLevel.LOW


class TLSCertificateChecker:
    """Asynchronous TLS certificate probe using SNI socket handshake."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    async def check_certificate(
        self,
        hostname: str,
        port: int = 443,
    ) -> TLSCertificateCheckResult:
        """Inspect TLS certificate expiration and subject alternative names."""
        clean_host = hostname.strip().lower()
        now = datetime.now(UTC)

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(clean_host, port, ssl=ctx, server_hostname=clean_host),
                timeout=self.timeout,
            )
            ssl_sock = writer.get_extra_info("ssl_object")
            if not ssl_sock:
                writer.close()
                await writer.wait_closed()
                return TLSCertificateCheckResult(
                    hostname=clean_host,
                    port=port,
                    status="ERROR",
                    error_message="SSL object unavailable from transport",
                )

            peercert = ssl_sock.getpeercert()
            writer.close()
            await writer.wait_closed()

            if not peercert:
                return TLSCertificateCheckResult(
                    hostname=clean_host,
                    port=port,
                    status="ERROR",
                    error_message="No peer certificate returned",
                )

            # Parse expiration
            not_after_str = peercert.get("notAfter", "")
            not_before_str = peercert.get("notBefore", "")

            # e.g. "May 10 23:59:59 2026 GMT"
            fmt = "%b %d %H:%M:%S %Y %Z"
            not_after = datetime.strptime(not_after_str, fmt).replace(tzinfo=UTC) if not_after_str else None
            not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=UTC) if not_before_str else None

            days_remaining = (not_after - now).days if not_after else 0
            is_expired = days_remaining <= 0

            # Determine status & severity
            if is_expired:
                severity = SeverityLevel.CRITICAL
                status = "EXPIRED"
            elif days_remaining <= 7:
                severity = SeverityLevel.CRITICAL
                status = "EXPIRING_IMMINENT"
            elif days_remaining <= 30:
                severity = SeverityLevel.HIGH
                status = "EXPIRING_SOON"
            elif days_remaining <= 60:
                severity = SeverityLevel.MEDIUM
                status = "ATTENTION_NEEDED"
            else:
                severity = SeverityLevel.LOW
                status = "HEALTHY"

            # Parse Subject Alternative Names
            sans: list[str] = [entry[1] for entry in peercert.get("subjectAltName", ()) if len(entry) == 2]

            return TLSCertificateCheckResult(
                hostname=clean_host,
                port=port,
                not_before=not_before,
                not_after=not_after,
                days_remaining=days_remaining,
                severity=severity,
                is_expired=is_expired,
                status=status,
                san_list=sans,
            )

        except (TimeoutError, OSError, ssl.SSLError) as exc:
            logger.warning(f"TLS check failed for '{clean_host}:{port}': {exc}")
            return TLSCertificateCheckResult(
                hostname=clean_host,
                port=port,
                status="ERROR",
                severity=SeverityLevel.HIGH,
                error_message=str(exc),
            )


class DNSDriftMonitor:
    """Non-blocking DNS record resolution and baseline drift analyzer."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    async def query_records(self, hostname: str) -> dict[str, list[str]]:
        """Asynchronously resolve A (IPv4) and AAAA (IPv6) records for hostname."""
        clean_host = hostname.strip().lower()
        loop = asyncio.get_running_loop()
        records: dict[str, list[str]] = {"A": [], "AAAA": []}

        try:
            # Query IPv4
            addr_info_v4 = await asyncio.wait_for(
                loop.getaddrinfo(clean_host, None, family=socket.AF_INET),
                timeout=self.timeout,
            )
            v4_ips = sorted(list({str(info[4][0]) for info in addr_info_v4 if info[4]}))
            records["A"] = v4_ips
        except Exception as exc:
            logger.debug(f"DNS A lookup for '{clean_host}' failed: {exc}")

        try:
            # Query IPv6
            addr_info_v6 = await asyncio.wait_for(
                loop.getaddrinfo(clean_host, None, family=socket.AF_INET6),
                timeout=self.timeout,
            )
            v6_ips = sorted(list({str(info[4][0]) for info in addr_info_v6 if info[4]}))
            records["AAAA"] = v6_ips
        except Exception as exc:
            logger.debug(f"DNS AAAA lookup for '{clean_host}' failed: {exc}")

        return records

    def evaluate_drift(
        self,
        hostname: str,
        observed: dict[str, list[str]],
        baseline: dict[str, list[str]],
    ) -> DNSDriftCheckResult:
        """Compare observed DNS records against approved baseline."""
        drift_details: list[str] = []
        drift_detected = False
        highest_severity = SeverityLevel.LOW

        for rtype in ("A", "AAAA", "CNAME", "TXT"):
            base_vals = sorted(baseline.get(rtype, []))
            obs_vals = sorted(observed.get(rtype, []))

            if base_vals and obs_vals and base_vals != obs_vals:
                drift_detected = True
                diff = f"{rtype} record drifted: baseline={base_vals} observed={obs_vals}"
                drift_details.append(diff)
                if rtype in ("A", "AAAA"):
                    highest_severity = SeverityLevel.HIGH
                elif highest_severity != SeverityLevel.HIGH:
                    highest_severity = SeverityLevel.MEDIUM

        return DNSDriftCheckResult(
            hostname=hostname,
            observed_records=observed,
            baseline_records=baseline,
            drift_detected=drift_detected,
            drift_details=drift_details,
            severity=highest_severity,
        )


class TLSDNSMonitoringDaemon:
    """Continuous background daemon monitoring TLS certificates and DNS records."""

    def __init__(
        self,
        monitored_domains: list[str] | None = None,
        interval_seconds: float = 300.0,
        monitor: ContinuousMonitor | None = None,
        cert_checker: TLSCertificateChecker | None = None,
        dns_monitor: DNSDriftMonitor | None = None,
    ) -> None:
        self.monitored_domains = monitored_domains or self._default_domains()
        self.interval_seconds = max(10.0, interval_seconds)
        self.monitor = monitor or default_monitor
        self.cert_checker = cert_checker or TLSCertificateChecker()
        self.dns_monitor = dns_monitor or DNSDriftMonitor()
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._last_cycle_results: dict[str, Any] = {}

    @staticmethod
    def _default_domains() -> list[str]:
        env_domains = os.getenv("SENTINEL_MONITORED_DOMAINS", "").strip()
        if env_domains:
            return [d.strip() for d in env_domains.split(",") if d.strip()]
        return ["friday-universe.duckdns.org"]

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    def add_target(self, domain: str) -> None:
        """Add domain to active watch schedule."""
        clean = domain.strip().lower()
        if clean and clean not in self.monitored_domains:
            self.monitored_domains.append(clean)

    async def run_check_cycle(self) -> dict[str, Any]:
        """Execute a full TLS and DNS check across all monitored targets."""
        cycle_start = datetime.now(UTC)
        results: dict[str, Any] = {
            "cycle_timestamp": cycle_start.isoformat(),
            "targets": {},
            "alerts_generated": 0,
        }

        for domain in self.monitored_domains:
            target_res: dict[str, Any] = {"domain": domain}

            # 1. Check TLS certificate
            cert_res = await self.cert_checker.check_certificate(domain)
            target_res["tls"] = cert_res.model_dump()

            if cert_res.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
                alert_id = f"cert-{int(cycle_start.timestamp())}-{domain}"
                alert = DriftAlert(
                    alert_id=alert_id,
                    asset_id=f"ast-{domain}",
                    target=domain,
                    drift_type="tls_certificate_expiration",
                    severity=cert_res.severity,
                    description=(
                        f"TLS certificate for {domain} status is {cert_res.status}: "
                        f"{cert_res.days_remaining} days remaining (expires {cert_res.not_after})."
                    ),
                    details=cert_res.model_dump(mode="json"),
                )
                self.monitor.alerts.append(alert)
                results["alerts_generated"] += 1
                await emit_event(
                    EventType.ALERT,
                    "monitoring.tls.expiry",
                    "sentinel_tls_daemon",
                    {
                        "type": "tls_cert_expiry",
                        "target": domain,
                        "days_remaining": cert_res.days_remaining,
                        "severity": cert_res.severity.value,
                    },
                    f"tls-{domain}",
                )
                audit_logger.log_event(
                    entry_id=alert_id,
                    event_type="TLS_CERT_ALERT",
                    actor="sentinel_tls_daemon",
                    action_type="EXPIRY_WARNING",
                    scope_policy="POL-TLS-EXPIRY",
                    decision="ALERT",
                    target=domain,
                    details=cert_res.model_dump(mode="json"),
                )

            # 2. Check DNS drift
            observed_dns = await self.dns_monitor.query_records(domain)
            baseline = self.monitor.baselines.get(f"ast-{domain}")
            base_records = baseline.dns_records if baseline else {}

            if base_records:
                drift_res = self.dns_monitor.evaluate_drift(domain, observed_dns, base_records)
                target_res["dns_drift"] = drift_res.model_dump()
                if drift_res.drift_detected:
                    dns_alert_id = f"dns-{int(cycle_start.timestamp())}-{domain}"
                    dns_alert = DriftAlert(
                        alert_id=dns_alert_id,
                        asset_id=f"ast-{domain}",
                        target=domain,
                        drift_type="dns_record_drift",
                        severity=drift_res.severity,
                        description=f"DNS drift on {domain}: {'; '.join(drift_res.drift_details)}",
                        details=drift_res.model_dump(mode="json"),
                    )
                    self.monitor.alerts.append(dns_alert)
                    results["alerts_generated"] += 1
                    await emit_event(
                        EventType.ALERT,
                        "monitoring.dns.drift",
                        "sentinel_dns_daemon",
                        {
                            "type": "dns_drift",
                            "target": domain,
                            "severity": drift_res.severity.value,
                            "drift": drift_res.drift_details,
                        },
                        f"dns-{domain}",
                    )
                    audit_logger.log_event(
                        entry_id=dns_alert_id,
                        event_type="DNS_DRIFT_ALERT",
                        actor="sentinel_dns_daemon",
                        action_type="DRIFT_DETECTED",
                        scope_policy="POL-DNS-DRIFT",
                        decision="ALERT",
                        target=domain,
                        details=drift_res.model_dump(mode="json"),
                    )
            else:
                # Auto-initialize baseline if not yet present
                if observed_dns.get("A"):
                    self.monitor.register_asset_from_scan(domain, {"dns_records": observed_dns})
                target_res["dns_drift"] = {"status": "baseline_initialized", "observed": observed_dns}

            results["targets"][domain] = target_res

        self._last_cycle_results = results
        return results

    async def _run_loop(self) -> None:
        """Background continuous execution loop."""
        logger.info(
            f"TLS & DNS Sentinel Daemon started (monitoring {self.monitored_domains} every {self.interval_seconds}s)"
        )
        while self._running:
            try:
                await self.run_check_cycle()
            except Exception as exc:
                logger.error(f"Error in TLS & DNS monitoring cycle: {exc}", exc_info=True)
            try:
                await asyncio.sleep(self.interval_seconds)
            except asyncio.CancelledError:
                break
        logger.info("TLS & DNS Sentinel Daemon stopped cleanly.")

    def start(self) -> asyncio.Task[None]:
        """Start the daemon in the active event loop."""
        if self._running and self._task and not self._task.done():
            return self._task
        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name="sentinel_tls_dns_daemon")
        return self._task

    async def stop(self) -> None:
        """Gracefully terminate background daemon."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task


# Global singleton instance
tls_dns_daemon = TLSDNSMonitoringDaemon()
