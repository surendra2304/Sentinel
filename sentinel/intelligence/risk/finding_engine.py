"""Finding Engine for Sentinel.

Converts raw observations into deduplicated, evidence-anchored Finding models,
prevents observation noise, and manages finding lifecycle states with repository persistence.
"""

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.events.bus import emit_event
from sentinel.core.models import (
    EventType,
    Finding,
    FindingStatus,
    SeverityLevel,
)
from sentinel.storage.repositories.factory import get_finding_repository


class Observation(BaseModel):
    """Raw structured observation submitted by domain modules or agents."""
    task_id: str
    target_ref: str
    source_module: str
    title: str
    description: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    related_cwes: list[str] = Field(default_factory=list)
    exploitability_context: str | None = None
    impact: str | None = None
    remediation: str | None = None


class FindingEngine:
    """Finding ingestion, deduplication, and lifecycle transition manager."""

    def __init__(self, audit_logger: AuditLogger | None = None):
        self.settings = get_settings()
        self.audit = audit_logger or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )
        self._findings: dict[str, Finding] = {}
        # Composite deduplication index: (task_id, target_ref, title) -> finding_id
        self._dedup_index: dict[tuple[str, str, str], str] = {}

    @property
    def repo(self):
        return get_finding_repository()

    async def ingest_observation(self, observation: Observation) -> Finding:
        """Process, validate, and deduplicate an incoming observation into a Finding."""
        # Evidence-First validation: observation must reference at least one evidence artifact
        if not observation.evidence_refs:
            raise ValueError(f"Evidence-First violation: Observation '{observation.title}' must contain valid evidence_refs.")

        dedup_key = (observation.task_id, observation.target_ref.lower(), observation.title.strip().lower())

        # Check for existing duplicate finding on same asset
        if dedup_key in self._dedup_index:
            finding_id = self._dedup_index[dedup_key]
            existing = self._findings.get(finding_id) or await self.repo.get_finding(finding_id)
            if existing:
                # Merge evidence references without duplicates
                for ref in observation.evidence_refs:
                    if ref not in existing.evidence_refs:
                        existing.evidence_refs.append(ref)

                for cve in observation.related_cves:
                    if cve not in existing.related_cves:
                        existing.related_cves.append(cve)

                # Update confidence (weighted average) and last seen
                existing.confidence = round((existing.confidence + observation.confidence) / 2.0, 2)
                existing.last_seen = datetime.now(UTC)

                self._findings[finding_id] = existing
                await self.repo.save_finding(existing)

                # Audit update & emit event
                await emit_event(
                    event_type=EventType.FINDING,
                    topic="finding.updated",
                    source="sentinel.finding_engine",
                    payload={"finding_id": existing.id, "task_id": existing.task_id, "evidence_count": len(existing.evidence_refs)},
                    correlation_id=existing.task_id,
                )
                return existing

        # Create new finding
        finding_id = f"find-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)

        finding = Finding(
            id=finding_id,
            task_id=observation.task_id,
            title=observation.title,
            description=observation.description,
            target_ref=observation.target_ref,
            severity=observation.severity,
            confidence=observation.confidence,
            exploitability_context=observation.exploitability_context,
            impact=observation.impact,
            evidence_refs=observation.evidence_refs,
            related_cves=observation.related_cves,
            related_cwes=observation.related_cwes,
            remediation=observation.remediation,
            status=FindingStatus.OPEN,
            first_seen=now,
            last_seen=now,
        )

        self._findings[finding_id] = finding
        self._dedup_index[dedup_key] = finding_id
        await self.repo.save_finding(finding)

        # Audit creation
        self.audit.log_event(
            entry_id=f"audit-find-{finding_id}",
            event_type="FINDING_CREATED",
            actor=observation.source_module,
            target=observation.target_ref,
            action_type="FINDING_INGEST",
            scope_policy=observation.task_id,
            decision="RECORDED",
            details={
                "finding_id": finding_id,
                "severity": finding.severity.value,
                "title": finding.title,
                "evidence_count": len(finding.evidence_refs),
            },
        )

        # Emit finding.created
        await emit_event(
            event_type=EventType.FINDING,
            topic="finding.created",
            source="sentinel.finding_engine",
            payload={
                "finding_id": finding.id,
                "task_id": finding.task_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "target_ref": finding.target_ref,
            },
            correlation_id=finding.task_id,
        )

        return finding

    async def update_status(
        self,
        finding_id: str,
        new_status: FindingStatus,
        operator: str,
        notes: str = "",
    ) -> Finding:
        """Transition finding status (open, verified, false_positive, remediated, accepted)."""
        finding = self._findings.get(finding_id) or await self.repo.get_finding(finding_id)
        if not finding:
            raise KeyError(f"Finding '{finding_id}' not found.")

        old_status = finding.status
        finding.status = new_status
        finding.last_seen = datetime.now(UTC)

        self._findings[finding_id] = finding
        await self.repo.save_finding(finding)

        self.audit.log_event(
            entry_id=f"audit-find-status-{finding_id}",
            event_type="FINDING_STATUS_CHANGED",
            actor=operator,
            target=finding.target_ref,
            action_type="FINDING_LIFECYCLE",
            scope_policy=finding.task_id,
            decision=new_status.value,
            details={"old_status": old_status.value, "new_status": new_status.value, "notes": notes},
        )

        await emit_event(
            event_type=EventType.FINDING,
            topic="finding.updated",
            source="sentinel.finding_engine",
            payload={"finding_id": finding.id, "status": new_status.value, "operator": operator},
            correlation_id=finding.task_id,
        )

        return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def list_findings(
        self,
        task_id: str | None = None,
        severity: SeverityLevel | None = None,
        status: FindingStatus | None = None,
        target_ref: str | None = None,
    ) -> list[Finding]:
        """Query and filter security findings from memory/cache."""
        results = []
        for f in self._findings.values():
            if task_id and f.task_id != task_id:
                continue
            if severity and f.severity != severity:
                continue
            if status and f.status != status:
                continue
            if target_ref and f.target_ref != target_ref:
                continue
            results.append(f)
        return results

    def adjust_confidence(self, finding_id: str, delta: float, reason: str = "") -> Finding | None:
        """Apply a confidence delta (positive or negative) from quality review.

        Called synchronously by SecurityIntelligenceAgent during quality review.
        Confidence is clamped to [0.0, 1.0].
        """
        finding = self._findings.get(finding_id)
        if not finding:
            return None
        finding.confidence = round(max(0.0, min(1.0, finding.confidence + delta)), 4)
        finding.last_seen = datetime.now(UTC)
        self.audit.log_event(
            entry_id=f"audit-qr-{finding_id}",
            event_type="QUALITY_REVIEW_ADJUSTMENT",
            actor="security_intelligence_agent",
            target=finding.target_ref,
            action_type="CONFIDENCE_ADJUSTMENT",
            scope_policy=finding.task_id,
            decision=f"delta={delta:+.2f}",
            details={"finding_id": finding_id, "reason": reason,
                     "new_confidence": finding.confidence},
        )
        return finding

    def flag_finding(self, finding_id: str, new_status: FindingStatus, reason: str = "") -> Finding | None:
        """Synchronous status update for quality-review flagging (no async event emission)."""
        finding = self._findings.get(finding_id)
        if not finding:
            return None
        old_status = finding.status
        finding.status = new_status
        finding.last_seen = datetime.now(UTC)
        self.audit.log_event(
            entry_id=f"audit-flag-{finding_id}",
            event_type="FINDING_FLAGGED",
            actor="quality_review",
            target=finding.target_ref,
            action_type="FINDING_LIFECYCLE",
            scope_policy=finding.task_id,
            decision=new_status.value,
            details={"old_status": old_status.value, "new_status": new_status.value,
                     "reason": reason},
        )
        return finding


# Global Finding Engine Singleton
finding_engine = FindingEngine()
