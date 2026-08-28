"""Repository Provider Factory for Sentinel."""

from sentinel.config.settings import get_settings
from sentinel.storage.repositories.in_memory import (
    InMemoryApprovalRepository,
    InMemoryEvidenceRepository,
    InMemoryFindingRepository,
    InMemoryTaskRepository,
)
from sentinel.storage.repositories.interfaces import (
    ApprovalRepository,
    EvidenceRepository,
    FindingRepository,
    TaskRepository,
)
from sentinel.storage.repositories.postgres import (
    PostgresApprovalRepository,
    PostgresEvidenceRepository,
    PostgresFindingRepository,
    PostgresTaskRepository,
)

_task_repo: TaskRepository | None = None
_finding_repo: FindingRepository | None = None
_evidence_repo: EvidenceRepository | None = None
_approval_repo: ApprovalRepository | None = None


def get_task_repository() -> TaskRepository:
    global _task_repo
    if _task_repo is None:
        settings = get_settings()
        if getattr(settings, "storage_backend", "memory") == "postgres":
            _task_repo = PostgresTaskRepository()
        else:
            _task_repo = InMemoryTaskRepository()
    return _task_repo


def get_finding_repository() -> FindingRepository:
    global _finding_repo
    if _finding_repo is None:
        settings = get_settings()
        if getattr(settings, "storage_backend", "memory") == "postgres":
            _finding_repo = PostgresFindingRepository()
        else:
            _finding_repo = InMemoryFindingRepository()
    return _finding_repo


def get_evidence_repository() -> EvidenceRepository:
    global _evidence_repo
    if _evidence_repo is None:
        settings = get_settings()
        if getattr(settings, "storage_backend", "memory") == "postgres":
            _evidence_repo = PostgresEvidenceRepository()
        else:
            _evidence_repo = InMemoryEvidenceRepository()
    return _evidence_repo


def get_approval_repository() -> ApprovalRepository:
    global _approval_repo
    if _approval_repo is None:
        settings = get_settings()
        if getattr(settings, "storage_backend", "memory") == "postgres":
            _approval_repo = PostgresApprovalRepository()
        else:
            _approval_repo = InMemoryApprovalRepository()
    return _approval_repo
