"""Fast in-memory Repository implementation for unit testing and local development."""

from datetime import UTC, datetime

from sentinel.core.models import (
    Evidence,
    Finding,
    FindingStatus,
    SeverityLevel,
    Task,
    TaskStatus,
)
from sentinel.core.policy.engine import ApprovalRecord
from sentinel.storage.repositories.interfaces import (
    ApprovalRepository,
    EvidenceRepository,
    FindingRepository,
    TaskRepository,
)


class InMemoryTaskRepository(TaskRepository):
    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}

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
        terminal = {TaskStatus.COMPLETE, TaskStatus.FAILED, TaskStatus.CANCELLED}
        return [
            t.model_copy(deep=True)
            for t in self._tasks.values()
            if t.status not in terminal
        ]


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
