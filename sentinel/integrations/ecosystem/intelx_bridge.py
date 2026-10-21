"""IntelX OSINT & Research De-confliction Bridge.

Provides target de-confliction, scope authorization, and automated threat feed
synchronization between IntelX and Sentinel.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import audit_logger
from sentinel.modules.threat_intel.models import IOCItem, IOCType
from sentinel.modules.threat_intel.reputation import ThreatIntelEngine


class IntelXTargetRegistration(BaseModel):
    """Investigation target submitted by IntelX to avoid friendly fire."""

    investigation_id: str
    target: str  # IP, domain, or handle
    target_type: str
    purpose: str
    requested_by: str = "intelx"
    authorized_until: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetDeconflictionStatus(BaseModel):
    """De-confliction clearance or conflict report."""

    target: str
    is_cleared: bool
    status: str  # "CLEARED" | "CONFLICT_DETECTED" | "OUT_OF_SCOPE"
    conflicting_operations: list[str] = Field(default_factory=list)
    reason: str = ""


class IntelXCoordinationBridge:
    """Manages active research targets, deconfliction, and threat feed ingestion."""

    def __init__(self, threat_engine: ThreatIntelEngine | None = None) -> None:
        self.threat_engine = threat_engine or ThreatIntelEngine()
        self._active_targets: dict[str, IntelXTargetRegistration] = {}
        self._sentinel_active_engagements: set[str] = set()

    def register_sentinel_engagement(self, target: str) -> None:
        """Register an active offensive or defensive engagement target in Sentinel."""
        self._sentinel_active_engagements.add(target.lower().strip())

    def unregister_sentinel_engagement(self, target: str) -> None:
        self._sentinel_active_engagements.discard(target.lower().strip())

    def deconflict_target(self, registration: IntelXTargetRegistration) -> TargetDeconflictionStatus:
        """Check target against active Sentinel tasks to prevent collisions."""
        clean_target = registration.target.lower().strip()

        # Check if already under active high-impact penetration test
        if clean_target in self._sentinel_active_engagements:
            conflict_msg = (
                f"Target '{clean_target}' is currently undergoing an active Sentinel pentest task. "
                "OSINT scans paused to prevent interference."
            )
            audit_logger.log_event(
                event_type="INTELX_DECONFLICTION_CONFLICT",
                actor=registration.requested_by,
                target=clean_target,
                action_type="target_deconfliction",
                scope_policy="mesh_coordination_policy",
                decision="CONFLICT_DETECTED",
                details={"investigation_id": registration.investigation_id, "reason": conflict_msg},
            )
            return TargetDeconflictionStatus(
                target=clean_target,
                is_cleared=False,
                status="CONFLICT_DETECTED",
                conflicting_operations=["sentinel_active_pentest"],
                reason=conflict_msg,
            )

        # Register target as active
        self._active_targets[clean_target] = registration

        audit_logger.log_event(
            event_type="INTELX_TARGET_REGISTERED",
            actor=registration.requested_by,
            target=clean_target,
            action_type="target_registration",
            scope_policy="mesh_coordination_policy",
            decision="CLEARED",
            details={"investigation_id": registration.investigation_id},
        )

        return TargetDeconflictionStatus(
            target=clean_target,
            is_cleared=True,
            status="CLEARED",
            reason="Target cleared with no active engagement conflicts.",
        )

    def ingest_osint_findings(
        self,
        investigation_id: str,
        iocs: list[dict[str, str]],
    ) -> list[IOCItem]:
        """Ingest external OSINT discoveries from IntelX into Sentinel's threat intelligence engine."""
        ingested: list[IOCItem] = []
        for raw in iocs:
            val = raw.get("value", "")
            raw_type = raw.get("type", "domain").lower()
            try:
                ioc_type = IOCType(raw_type)
            except ValueError:
                ioc_type = IOCType.DOMAIN

            rep = self.threat_engine.score_indicator(val, ioc_type)
            ingested.append(
                IOCItem(
                    value=val,
                    ioc_type=ioc_type,
                    context=f"IntelX investigation {investigation_id} (reputation score: {rep.score})",
                    confidence=0.85,
                    normalized_value=val.lower().strip(),
                )
            )

        audit_logger.log_event(
            event_type="INTELX_OSINT_INGESTION",
            actor="intelx",
            target=investigation_id,
            action_type="feed_ingestion",
            scope_policy="threat_intelligence_policy",
            decision="INGESTED",
            details={"count": len(ingested), "investigation_id": investigation_id},
        )
        return ingested
