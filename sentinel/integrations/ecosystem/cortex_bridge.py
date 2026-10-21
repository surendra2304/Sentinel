"""Cortex Web Operations & SSRF Guardrail Bridge.

Provides strict pre-flight URL verification, private IP & loopback filtering,
cloud metadata access prevention, and domain scope enforcement for Cortex web crawlers and workers.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import audit_logger

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918 Private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918 Private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud Metadata
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
]


class CortexTargetValidationRequest(BaseModel):
    """Outbound crawl/fetch request from Cortex for validation."""

    task_id: str
    target_url: str
    initiator_agent: str = "cortex"
    allowed_domains: list[str] = Field(default_factory=list)
    allow_private_ips: bool = False


class CortexValidationDecision(BaseModel):
    """Decision returned to Cortex."""

    task_id: str
    target_url: str
    is_safe: bool
    decision: str  # "ALLOWED" | "BLOCKED"
    reason: str = ""
    resolved_ip: str | None = None


class CortexSecurityGate:
    """SSRF and Ingress/Egress Guardrail for Cortex."""

    def __init__(self, dns_resolver_fn=None) -> None:
        self.dns_resolver_fn = dns_resolver_fn or socket.gethostbyname

    def validate_outbound_url(self, request: CortexTargetValidationRequest) -> CortexValidationDecision:
        """Inspect proposed outbound URL against SSRF and scope rules."""
        raw_url = request.target_url.strip()
        parsed = urlparse(raw_url)

        # 1. Scheme Check
        if parsed.scheme.lower() not in ("http", "https"):
            return self._record_decision(
                request,
                is_safe=False,
                reason=f"Forbidden protocol scheme '{parsed.scheme}'. Only HTTP/HTTPS allowed.",
            )

        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return self._record_decision(
                request,
                is_safe=False,
                reason="Malformed URL: Missing valid hostname.",
            )

        # 2. Blacklisted Hostnames
        if hostname in FORBIDDEN_HOSTNAMES:
            return self._record_decision(
                request,
                is_safe=False,
                reason=f"Target hostname '{hostname}' is explicitly blocked (internal/metadata service).",
            )

        # 3. Scope Check (if allowed_domains provided) - check before network calls
        if request.allowed_domains:
            domain_matched = False
            for allowed in request.allowed_domains:
                allowed_clean = allowed.strip().lower().lstrip("*.")
                if hostname == allowed_clean or hostname.endswith(f".{allowed_clean}"):
                    domain_matched = True
                    break
            if not domain_matched:
                return self._record_decision(
                    request,
                    is_safe=False,
                    reason=f"Target '{hostname}' is out of declared scope. Allowed: {request.allowed_domains}",
                )

        # 4. Resolve IP and Check Forbidden Subnets
        resolved_ip_str: str | None = None
        try:
            # Check if hostname is already a raw IP
            try:
                ip_obj = ipaddress.ip_address(hostname)
                resolved_ip_str = str(ip_obj)
            except ValueError:
                # Resolve via DNS
                resolved_ip_str = self.dns_resolver_fn(hostname)
                ip_obj = ipaddress.ip_address(resolved_ip_str)

            if not request.allow_private_ips:
                for net in FORBIDDEN_NETWORKS:
                    if ip_obj in net:
                        return self._record_decision(
                            request,
                            is_safe=False,
                            reason=f"SSRF violation: Hostname '{hostname}' resolves to forbidden network {net} ({resolved_ip_str}).",
                            resolved_ip=resolved_ip_str,
                        )
        except Exception as exc:
            return self._record_decision(
                request,
                is_safe=False,
                reason=f"DNS resolution failure or invalid host: {exc}",
            )

        return self._record_decision(
            request,
            is_safe=True,
            reason="Target passed SSRF and scope security checks.",
            resolved_ip=resolved_ip_str,
        )

    def _record_decision(
        self,
        request: CortexTargetValidationRequest,
        is_safe: bool,
        reason: str,
        resolved_ip: str | None = None,
    ) -> CortexValidationDecision:
        decision_str = "ALLOWED" if is_safe else "BLOCKED"

        audit_logger.log_event(
            event_type="CORTEX_SSRF_GATE",
            actor=request.initiator_agent,
            target=request.target_url,
            action_type="ssrf_preflight_check",
            scope_policy="cortex_outbound_guardrail",
            decision=decision_str,
            details={
                "task_id": request.task_id,
                "target_url": request.target_url,
                "resolved_ip": resolved_ip,
                "reason": reason,
                "is_safe": is_safe,
            },
        )

        return CortexValidationDecision(
            task_id=request.task_id,
            target_url=request.target_url,
            is_safe=is_safe,
            decision=decision_str,
            reason=reason,
            resolved_ip=resolved_ip,
        )
