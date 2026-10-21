"""Repository Provider Factory for Sentinel."""

from sentinel.config.settings import get_settings
from sentinel.storage.repositories.in_memory import (
    InMemoryApprovalRepository,
    InMemoryAuditRepository,
    InMemoryEventRepository,
    InMemoryEvidenceRepository,
    InMemoryFindingRepository,
    InMemoryRiskRepository,
    InMemoryTaskRepository,
)
from sentinel.storage.repositories.interfaces import (
    ApprovalRepository,
    AuditRepository,
    EventRepository,
    EvidenceRepository,
    FindingRepository,
    RiskRepository,
    TaskRepository,
)
from sentinel.storage.repositories.postgres import (
    PostgresApprovalRepository,
    PostgresAuditRepository,
    PostgresEventRepository,
    PostgresEvidenceRepository,
    PostgresFindingRepository,
    PostgresRiskRepository,
    PostgresTaskRepository,
)

_task_repo: TaskRepository | None = None
_finding_repo: FindingRepository | None = None
_evidence_repo: EvidenceRepository | None = None
_approval_repo: ApprovalRepository | None = None
_risk_repo: RiskRepository | None = None
_audit_repo: AuditRepository | None = None
_event_repo: EventRepository | None = None


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


def get_risk_repository() -> RiskRepository:
    global _risk_repo
    if _risk_repo is None:
        settings = get_settings()
        if getattr(settings, "storage_backend", "memory") == "postgres":
            _risk_repo = PostgresRiskRepository()
        else:
            _risk_repo = InMemoryRiskRepository()
    return _risk_repo


def get_audit_repository() -> AuditRepository:
    global _audit_repo
    if _audit_repo is None:
        settings = get_settings()
        if getattr(settings, "storage_backend", "memory") == "postgres":
            _audit_repo = PostgresAuditRepository()
        else:
            _audit_repo = InMemoryAuditRepository()
    return _audit_repo


def get_event_repository() -> EventRepository:
    global _event_repo
    if _event_repo is None:
        settings = get_settings()
        if getattr(settings, "storage_backend", "memory") == "postgres":
            _event_repo = PostgresEventRepository()
        else:
            _event_repo = InMemoryEventRepository()
    return _event_repo
