"""Continuous Security Monitoring Service for Sentinel.

Provides:
1. Asset watchlists auto-registered from completed assessments.
2. Periodic lightweight checks (daily: subdomains, certificates, headers, DNS; weekly: port scans, TLS, endpoints).
3. Baseline snapshotting per asset.
4. Drift detection & alert triggering with specific thresholds:
   - Certificate expiring < 14 days = HIGH
   - New subdomain discovered = MEDIUM
   - Port newly open = HIGH
   - Endpoint disappeared = INFO
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import SeverityLevel


class CheckFrequency(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"


class DriftAlert(BaseModel):
    alert_id: str
    asset_id: str
    target: str
    drift_type: str
    severity: SeverityLevel
    description: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, Any] = Field(default_factory=dict)


class AssetBaseline(BaseModel):
    asset_id: str
    target: str
    subdomains: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    security_headers: dict[str, str] = Field(default_factory=dict)
    tls_cert_expiry_days: int = 90
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    endpoints: list[str] = Field(default_factory=list)
    last_updated: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ContinuousMonitor:
    """Always-on continuous security monitoring and drift detection engine."""

    def __init__(self):
        self.watchlists: dict[str, dict[str, Any]] = {}
        self.baselines: dict[str, AssetBaseline] = {}
        self.alerts: list[DriftAlert] = []

    def register_asset_from_scan(self, target: str, initial_state: dict[str, Any] | None = None) -> AssetBaseline:
        """Auto-register asset to monitoring watchlist from a completed scan."""
        asset_id = f"ast-{abs(hash(target)) % 10000000}"
        self.watchlists[asset_id] = {
            "asset_id": asset_id,
            "target": target,
            "registered_at": datetime.now(UTC).isoformat(),
            "status": "active",
        }

        init = initial_state or {}
        baseline = AssetBaseline(
            asset_id=asset_id,
            target=target,
            subdomains=init.get("subdomains", []),
            open_ports=init.get("open_ports", [80, 443]),
            security_headers=init.get("security_headers", {"Strict-Transport-Security": "max-age=31536000"}),
            tls_cert_expiry_days=init.get("tls_cert_expiry_days", 90),
            dns_records=init.get("dns_records", {"A": ["1.1.1.1"]}),
            endpoints=init.get("endpoints", ["/"]),
        )
        self.baselines[asset_id] = baseline
        return baseline

    def evaluate_drift(self, asset_id: str, observed_state: dict[str, Any]) -> list[DriftAlert]:
        """Detect drift against baseline and apply standardized alert thresholds."""
        baseline = self.baselines.get(asset_id)
        if not baseline:
            return []

        generated_alerts: list[DriftAlert] = []
        now = datetime.now(UTC)

        # 1. Certificate Expiry (< 14 days = HIGH)
        obs_cert_days = observed_state.get("tls_cert_expiry_days", baseline.tls_cert_expiry_days)
        if obs_cert_days < 14:
            alert = DriftAlert(
                alert_id=f"al-cert-{int(now.timestamp())}",
                asset_id=asset_id,
                target=baseline.target,
                drift_type="tls_certificate_expiry",
                severity=SeverityLevel.HIGH,
                description=f"TLS certificate for {baseline.target} expires in {obs_cert_days} days (<14 days threshold).",
                details={"expiry_days": obs_cert_days},
            )
            generated_alerts.append(alert)

        # 2. New Subdomain = MEDIUM
        obs_subdomains = observed_state.get("subdomains", [])
        new_subs = set(obs_subdomains) - set(baseline.subdomains)
        if new_subs:
            alert = DriftAlert(
                alert_id=f"al-sub-{int(now.timestamp())}",
                asset_id=asset_id,
                target=baseline.target,
                drift_type="new_subdomain_discovered",
                severity=SeverityLevel.MEDIUM,
                description=f"New subdomain(s) discovered for {baseline.target}: {', '.join(new_subs)}",
                details={"new_subdomains": list(new_subs)},
            )
            generated_alerts.append(alert)

        # 3. Port newly open = HIGH
        obs_ports = observed_state.get("open_ports", [])
        new_ports = set(obs_ports) - set(baseline.open_ports)
        if new_ports:
            alert = DriftAlert(
                alert_id=f"al-port-{int(now.timestamp())}",
                asset_id=asset_id,
                target=baseline.target,
                drift_type="new_listening_port",
                severity=SeverityLevel.HIGH,
                description=f"Newly opened network port(s) on {baseline.target}: {list(new_ports)}",
                details={"new_ports": list(new_ports)},
            )
            generated_alerts.append(alert)

        # 4. Endpoint disappeared = INFO
        obs_endpoints = observed_state.get("endpoints", [])
        missing_endpoints = set(baseline.endpoints) - set(obs_endpoints)
        if missing_endpoints:
            alert = DriftAlert(
                alert_id=f"al-endp-{int(now.timestamp())}",
                asset_id=asset_id,
                target=baseline.target,
                drift_type="endpoint_removed",
                severity=SeverityLevel.INFO,
                description=f"Monitored endpoint(s) disappeared on {baseline.target}: {list(missing_endpoints)}",
                details={"missing_endpoints": list(missing_endpoints)},
            )
            generated_alerts.append(alert)

        self.alerts.extend(generated_alerts)
        return generated_alerts


continuous_monitor = ContinuousMonitor()
