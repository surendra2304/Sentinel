"""Fast in-memory Repository implementation for unit testing and local development."""

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from sentinel.audit.audit_logger import AuditEntry
from sentinel.core.models import (
    Event,
    Evidence,
    Finding,
    FindingStatus,
    Risk,
    RiskTier,
    SeverityLevel,
    Task,
    TaskStatus,
)
from sentinel.core.policy.engine import ApprovalRecord
from sentinel.storage.repositories.interfaces import (
    ApprovalRepository,
    AuditRepository,
    EventRepository,
    EvidenceRepository,
    FindingRepository,
    RiskRepository,
    TaskRepository,
)


class InMemoryTaskRepository(TaskRepository):
    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._checkpoints: dict[str, dict[str, Any]] = {}

    async def create_task(self, task: Task) -> Task:
        self._tasks[task.id] = task.model_copy(deep=True)
        return self._tasks[task.id]

    async def get_task(self, task_id: str) -> Task | None:
        task = self._tasks.get(task_id)
        return task.model_copy(deep=True) if task else None

    async def update_task(self, task: Task) -> Task:
        task.updated_at = datetime.now(UTC)
        self._tasks[task.id] = task.model_copy(deep=True)
        return self._tasks[task.id]

    async def list_tasks(
        self,
        status: TaskStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Task]:
        tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        return [t.model_copy(deep=True) for t in tasks[offset : offset + limit]]

    async def get_active_non_terminal_tasks(self) -> list[Task]:
        terminal = {
            TaskStatus.COMPLETE,
            TaskStatus.COMPLETED,
            TaskStatus.BLOCKED,
            TaskStatus.PARTIALLY_COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
        return [
            t.model_copy(deep=True)
            for t in self._tasks.values()
            if t.status not in terminal
        ]

    async def save_checkpoint(self, task_id: str, payload: dict[str, Any]) -> int:
        current = self._checkpoints.get(task_id)
        version = int(current["version"]) + 1 if current else 1
        self._checkpoints[task_id] = {"version": version, "payload": deepcopy(payload)}
        return version

    async def get_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        checkpoint = self._checkpoints.get(task_id)
        return deepcopy(checkpoint) if checkpoint else None


class InMemoryFindingRepository(FindingRepository):
    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}

    async def save_finding(self, finding: Finding) -> Finding:
        self._findings[finding.id] = finding.model_copy(deep=True)
        return self._findings[finding.id]

    async def get_finding(self, finding_id: str) -> Finding | None:
        f = self._findings.get(finding_id)
        return f.model_copy(deep=True) if f else None

    async def list_findings(
        self,
        task_id: str | None = None,
        severity: SeverityLevel | None = None,
        status: FindingStatus | None = None,
        target_ref: str | None = None,
    ) -> list[Finding]:
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
            results.append(f.model_copy(deep=True))
        return results

    async def update_status(
        self,
        finding_id: str,
        status: FindingStatus,
    ) -> Finding | None:
        f = self._findings.get(finding_id)
        if not f:
            return None
        f.status = status
        f.last_seen = datetime.now(UTC)
        return f.model_copy(deep=True)


class InMemoryEvidenceRepository(EvidenceRepository):
    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}

    async def save_evidence_record(self, evidence: Evidence) -> Evidence:
        self._evidence[evidence.id] = evidence.model_copy(deep=True)
        return self._evidence[evidence.id]

    async def get_evidence_record(self, evidence_id: str) -> Evidence | None:
        e = self._evidence.get(evidence_id)
        return e.model_copy(deep=True) if e else None

    async def list_evidence(
        self,
        task_id: str | None = None,
        target_ref: str | None = None,
    ) -> list[Evidence]:
        results = []
        for e in self._evidence.values():
            if task_id and e.task_id != task_id:
                continue
            if target_ref and e.target_ref != target_ref:
                continue
            results.append(e.model_copy(deep=True))
        return results


class InMemoryApprovalRepository(ApprovalRepository):
    def __init__(self) -> None:
        self._approvals: dict[str, ApprovalRecord] = {}

    async def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        self._approvals[approval.approval_id] = approval.model_copy(deep=True)
        return self._approvals[approval.approval_id]

    async def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        a = self._approvals.get(approval_id)
        return a.model_copy(deep=True) if a else None

    async def list_approvals(
        self,
        task_id: str | None = None,
        status: str | None = None,
    ) -> list[ApprovalRecord]:
        results = []
        for a in self._approvals.values():
            if task_id and a.task_id != task_id:
                continue
            if status and a.status != status:
                continue
            results.append(a.model_copy(deep=True))
        return results


class InMemoryRiskRepository(RiskRepository):
    def __init__(self) -> None:
        self._risks: dict[str, Risk] = {}

    async def save_risk(self, risk: Risk) -> Risk:
        self._risks[risk.id] = risk.model_copy(deep=True)
        return self._risks[risk.id]

    async def get_risk(self, risk_id: str) -> Risk | None:
        r = self._risks.get(risk_id)
        return r.model_copy(deep=True) if r else None

    async def list_risks(
        self,
        task_id: str | None = None,
        finding_id: str | None = None,
        risk_tier: RiskTier | None = None,
    ) -> list[Risk]:
        results = []
        for r in self._risks.values():
            if task_id and r.task_id != task_id:
                continue
            if finding_id and r.finding_id != finding_id:
                continue
            if risk_tier and r.risk_tier != risk_tier:
                continue
            results.append(r.model_copy(deep=True))
        return results


class InMemoryAuditRepository(AuditRepository):
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._by_id: dict[str, AuditEntry] = {}

    async def save_audit_entry(self, entry: AuditEntry) -> AuditEntry:
        copied = entry.model_copy(deep=True)
        self._entries.append(copied)
        self._by_id[entry.entry_id] = copied
        return copied

    async def get_audit_entry(self, entry_id: str) -> AuditEntry | None:
        e = self._by_id.get(entry_id)
        return e.model_copy(deep=True) if e else None

    async def get_last_entry(self) -> AuditEntry | None:
        if not self._entries:
            return None
        return self._entries[-1].model_copy(deep=True)

    async def list_audit_entries(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        return [e.model_copy(deep=True) for e in self._entries[offset : offset + limit]]

    async def verify_audit_chain(self) -> tuple[bool, str]:
        if not self._entries:
            return True, "Audit ledger is empty (genesis state)."
        prev_hash = "GENESIS_BLOCK_000000000000000000000000000000000000000000000000000000"
        for idx, entry in enumerate(self._entries, start=1):
            if entry.previous_hash != prev_hash:
                return False, f"Hash chain broken at entry {idx} (entry_id={entry.entry_id})"
            prev_hash = entry.current_hash
        return True, f"Audit chain valid across {len(self._entries)} entries."


class InMemoryEventRepository(EventRepository):
    """Fast in-memory System Event repository."""

    def __init__(self) -> None:
        self._events: dict[str, Event] = {}

    async def save_event(self, event: Event) -> Event:
        self._events[event.event_id] = event.model_copy(deep=True)
        return self._events[event.event_id]

    async def get_event(self, event_id: str) -> Event | None:
        ev = self._events.get(event_id)
        return ev.model_copy(deep=True) if ev else None

    async def list_events(
        self,
        topic: str | None = None,
        event_type: str | None = None,
        correlation_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Event]:
        events = list(self._events.values())
        if topic:
            events = [e for e in events if e.topic == topic]
        if event_type:
            events = [
                e for e in events
                if str(e.event_type) == event_type or (hasattr(e.event_type, "value") and e.event_type.value == event_type)
            ]
        if correlation_id:
            events = [e for e in events if e.correlation_id == correlation_id]

        events.sort(key=lambda e: e.timestamp, reverse=True)
        return [e.model_copy(deep=True) for e in events[offset : offset + limit]]
