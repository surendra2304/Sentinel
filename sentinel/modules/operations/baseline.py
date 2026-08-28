"""Baseline & Differential Security Assessment Engine for Sentinel.

Tracks asset snapshots, open ports, DNS records, certificates, and findings per target.
Computes delta changes between consecutive runs to trigger proactive change alerts.
"""

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import SeverityLevel


class ChangeType(StrEnum):
    NEW_ASSET = "new_asset"
    REMOVED_ASSET = "removed_asset"
    NEW_PORT = "new_port"
    CLOSED_PORT = "closed_port"
    DNS_RECORD_CHANGED = "dns_record_changed"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    NEW_FINDING = "new_finding"
    RESOLVED_FINDING = "resolved_finding"
    CLOUD_RESOURCE_EXPOSED = "cloud_resource_exposed"


class SecurityBaselineSnapshot(BaseModel):
    snapshot_id: str
    target_ref: str
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    open_ports: list[int] = Field(default_factory=list)
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    active_findings: list[str] = Field(default_factory=list)  # Finding IDs or Titles
    cert_expiry_days: int | None = None
    cloud_public_resources: list[str] = Field(default_factory=list)


class BaselineDelta(BaseModel):
    delta_id: str
    target_ref: str
    change_type: ChangeType
    severity: SeverityLevel
    description: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    old_state: Any = None
    new_state: Any = None


class BaselineEngine:
    """Stores and evaluates temporal baseline diffs across targets."""

    def __init__(self):
        self._baselines: dict[str, SecurityBaselineSnapshot] = {}

    def get_baseline(self, target_ref: str) -> SecurityBaselineSnapshot | None:
        return self._baselines.get(target_ref)

    def record_snapshot(self, snapshot: SecurityBaselineSnapshot):
        self._baselines[snapshot.target_ref] = snapshot

    def compute_deltas(
        self,
        target_ref: str,
        current_snapshot: SecurityBaselineSnapshot,
    ) -> list[BaselineDelta]:
        previous = self._baselines.get(target_ref)
        deltas: list[BaselineDelta] = []

        if not previous:
            # First run: Record baseline without generating noisy change deltas
            self._baselines[target_ref] = current_snapshot
            return deltas

        # 1. Port Changes
        new_ports = set(current_snapshot.open_ports) - set(previous.open_ports)
        for p in new_ports:
            deltas.append(
                BaselineDelta(
                    delta_id=f"delta-port-{p}-{int(datetime.now(UTC).timestamp())}",
                    target_ref=target_ref,
                    change_type=ChangeType.NEW_PORT,
                    severity=SeverityLevel.HIGH if p in [22, 3389, 445, 1433, 3306, 5432, 27017] else SeverityLevel.MEDIUM,
                    description=f"New open network port {p} detected on '{target_ref}'.",
                    old_state=previous.open_ports,
                    new_state=current_snapshot.open_ports,
                )
            )

        # 2. DNS Record Changes
        for record_type, new_vals in current_snapshot.dns_records.items():
            old_vals = previous.dns_records.get(record_type, [])
            if sorted(new_vals) != sorted(old_vals):
                deltas.append(
                    BaselineDelta(
                        delta_id=f"delta-dns-{record_type}-{int(datetime.now(UTC).timestamp())}",
                        target_ref=target_ref,
                        change_type=ChangeType.DNS_RECORD_CHANGED,
                        severity=SeverityLevel.MEDIUM,
                        description=f"DNS {record_type} records changed for '{target_ref}' (Old: {old_vals}, New: {new_vals}).",
                        old_state=old_vals,
                        new_state=new_vals,
                    )
                )

        # 3. Certificate Expiry Threshold Alerts
        if current_snapshot.cert_expiry_days is not None:
            days = current_snapshot.cert_expiry_days
            if days <= 7:
                deltas.append(
                    BaselineDelta(
                        delta_id=f"delta-cert-crit-{int(datetime.now(UTC).timestamp())}",
                        target_ref=target_ref,
                        change_type=ChangeType.CERTIFICATE_EXPIRING,
                        severity=SeverityLevel.CRITICAL,
                        description=f"TLS/SSL Certificate for '{target_ref}' expires in {days} day(s)!",
                        new_state={"days_remaining": days},
                    )
                )
            elif days <= 14 and (previous.cert_expiry_days is None or previous.cert_expiry_days > 14):
                deltas.append(
                    BaselineDelta(
                        delta_id=f"delta-cert-high-{int(datetime.now(UTC).timestamp())}",
                        target_ref=target_ref,
                        change_type=ChangeType.CERTIFICATE_EXPIRING,
                        severity=SeverityLevel.HIGH,
                        description=f"TLS/SSL Certificate for '{target_ref}' expires in {days} day(s).",
                        new_state={"days_remaining": days},
                    )
                )

        # 4. New Findings vs Resolved Findings
        new_findings = set(current_snapshot.active_findings) - set(previous.active_findings)
        for nf in new_findings:
            deltas.append(
                BaselineDelta(
                    delta_id=f"delta-find-new-{hashlib.sha256(nf.encode()).hexdigest()[:8]}",
                    target_ref=target_ref,
                    change_type=ChangeType.NEW_FINDING,
                    severity=SeverityLevel.HIGH,
                    description=f"New security finding detected on '{target_ref}': {nf}",
                    new_state=nf,
                )
            )

        resolved_findings = set(previous.active_findings) - set(current_snapshot.active_findings)
        for rf in resolved_findings:
            deltas.append(
                BaselineDelta(
                    delta_id=f"delta-find-res-{hashlib.sha256(rf.encode()).hexdigest()[:8]}",
                    target_ref=target_ref,
                    change_type=ChangeType.RESOLVED_FINDING,
                    severity=SeverityLevel.INFO,
                    description=f"Security finding resolved on '{target_ref}': {rf}",
                    old_state=rf,
                )
            )

        # Update baseline store to latest snapshot
        self._baselines[target_ref] = current_snapshot
        return deltas


# Global Baseline Engine Singleton
baseline_engine = BaselineEngine()
