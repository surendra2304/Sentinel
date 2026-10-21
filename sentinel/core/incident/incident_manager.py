"""Sentinel Incident Management Engine.

Provides incident lifecycle state machines, severity containment SLAs,
automated quarantine action dispatch, event bus integration, and MTTR telemetry.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sentinel.audit.audit_logger import audit_logger
from sentinel.core.gateway.models import RiskLevel


class IncidentState(StrEnum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    CONTAINED = "CONTAINED"
    REMEDIATED = "REMEDIATED"
    CLOSED = "CLOSED"


# Default SLAs in seconds by severity
DEFAULT_CONTAINMENT_SLAS: dict[RiskLevel, float] = {
    RiskLevel.CRITICAL: 900.0,    # 15 minutes
    RiskLevel.HIGH: 3600.0,       # 1 hour
    RiskLevel.MEDIUM: 14400.0,    # 4 hours
    RiskLevel.LOW: 86400.0,       # 24 hours
}


@dataclass(slots=True)
class Incident:
    """Enterprise Incident record."""

    id: str
    tenant_id: str
    title: str
    severity: RiskLevel
    reason: str
    created_at: float = field(default_factory=time.time)
    contained: bool = False
    evidence_refs: list[str] = field(default_factory=list)
    state: IncidentState = IncidentState.OPEN
    assigned_to: str | None = None
    contained_at: float | None = None
    closed_at: float | None = None
    containment_actions_taken: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def sla_seconds(self) -> float:
        return DEFAULT_CONTAINMENT_SLAS.get(self.severity, 3600.0)

    @property
    def is_sla_breached(self) -> bool:
        if self.contained and self.contained_at:
            return (self.contained_at - self.created_at) > self.sla_seconds
        return (time.time() - self.created_at) > self.sla_seconds

    @property
    def time_to_contain(self) -> float | None:
        if self.contained and self.contained_at:
            return round(self.contained_at - self.created_at, 2)
        return None


class IncidentManager:
    """Enterprise Incident Lifecycle and Response Orchestrator."""

    def __init__(self, quarantine_manager: Any | None = None, event_bus: Any | None = None) -> None:
        self.incidents: dict[str, Incident] = {}
        self.quarantine_manager = quarantine_manager
        self.event_bus = event_bus

    def open(self, incident: Incident) -> Incident:
        """Register and open a new security incident."""
        self.incidents[incident.id] = incident

        audit_logger.log_event(
            event_type="INCIDENT_OPENED",
            actor=incident.tenant_id,
            target=incident.id,
            action_type="open_incident",
            scope_policy="incident_response_policy",
            decision="RECORDED",
            details={
                "incident_id": incident.id,
                "title": incident.title,
                "severity": incident.severity.value if hasattr(incident.severity, "value") else str(incident.severity),
                "reason": incident.reason,
            },
        )
        return incident

    def get(self, incident_id: str) -> Incident | None:
        """Retrieve an incident by ID."""
        return self.incidents.get(incident_id)

    def create(
        self,
        id: str,
        tenant_id: str,
        title: str,
        severity: RiskLevel,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> Incident:
        """Construct, open, and record a new incident."""
        inc = Incident(
            id=id,
            tenant_id=tenant_id,
            title=title,
            severity=severity,
            reason=reason,
            metadata=metadata or {},
        )
        return self.open(inc)

    def triage(self, incident_id: str, assigned_to: str, notes: str = "") -> Incident | None:
        """Transition incident to TRIAGED state and assign ownership."""
        inc = self.incidents.get(incident_id)
        if not inc:
            return None
        inc.state = IncidentState.TRIAGED
        inc.assigned_to = assigned_to
        if notes:
            inc.metadata["triage_notes"] = notes

        audit_logger.log_event(
            event_type="INCIDENT_TRIAGED",
            actor=assigned_to,
            target=incident_id,
            action_type="triage_incident",
            scope_policy="incident_response_policy",
            decision="ASSIGNED",
            details={"assigned_to": assigned_to, "notes": notes},
        )
        return inc

    def contain(
        self,
        incident_id: str,
        auto_quarantine_subject: str | None = None,
        quarantine_ttl: float = 3600.0,
    ) -> None:
        """Contain an active incident and execute containment actions."""
        inc = self.incidents.get(incident_id)
        if not inc:
            return

        inc.contained = True
        inc.state = IncidentState.CONTAINED
        inc.contained_at = time.time()

        if auto_quarantine_subject and self.quarantine_manager:
            self.quarantine_manager.put(
                subject=auto_quarantine_subject,
                reason=f"Automated containment for incident {incident_id}: {inc.reason}",
                ttl=quarantine_ttl,
            )
            inc.containment_actions_taken.append(f"quarantine:{auto_quarantine_subject}")

        audit_logger.log_event(
            event_type="INCIDENT_CONTAINED",
            actor="sentinel-incident-orchestrator",
            target=incident_id,
            action_type="contain_incident",
            scope_policy="incident_response_policy",
            decision="CONTAINED",
            details={
                "time_to_contain": inc.time_to_contain,
                "sla_breached": inc.is_sla_breached,
                "quarantine_applied": auto_quarantine_subject,
            },
        )

    def close(self, incident_id: str, resolution_notes: str = "") -> Incident | None:
        """Mark incident fully remediated and closed."""
        inc = self.incidents.get(incident_id)
        if not inc:
            return None

        inc.contained = True
        inc.state = IncidentState.CLOSED
        inc.closed_at = time.time()
        if resolution_notes:
            inc.metadata["resolution_notes"] = resolution_notes

        audit_logger.log_event(
            event_type="INCIDENT_CLOSED",
            actor="sentinel-incident-orchestrator",
            target=incident_id,
            action_type="close_incident",
            scope_policy="incident_response_policy",
            decision="CLOSED",
            details={"resolution_notes": resolution_notes},
        )
        return inc

    def active(self, tenant_id: str) -> list[Incident]:
        """List active uncontained incidents for a tenant."""
        return [
            i for i in self.incidents.values()
            if i.tenant_id == tenant_id and not i.contained
        ]

    def list_sla_breaches(self, tenant_id: str | None = None) -> list[Incident]:
        """Find incidents that have breached their containment SLAs."""
        results = [i for i in self.incidents.values() if i.is_sla_breached]
        if tenant_id:
            results = [i for i in results if i.tenant_id == tenant_id]
        return results

    def get_mttr_metrics(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Compute Mean-Time-To-Contain (MTTC) metrics."""
        candidates = [i for i in self.incidents.values() if i.contained and i.time_to_contain is not None]
        if tenant_id:
            candidates = [i for i in candidates if i.tenant_id == tenant_id]

        if not candidates:
            return {"total_contained": 0, "mttc_seconds": 0.0, "breach_rate_pct": 0.0}

        total_ttc = sum(c.time_to_contain for c in candidates if c.time_to_contain is not None)
        breaches = sum(1 for c in candidates if c.is_sla_breached)

        return {
            "total_contained": len(candidates),
            "mttc_seconds": round(total_ttc / len(candidates), 2),
            "breach_rate_pct": round((breaches / len(candidates)) * 100.0, 2),
        }
