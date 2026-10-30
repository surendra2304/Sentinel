"""Repository Provider Factory for Sentinel.

The backend is chosen from ``settings.storage_backend``:

* ``oracle`` (default) — ``Oracle*`` subclasses of the SQLAlchemy repositories.
* ``postgres`` / ``postgresql`` — the legacy SQLAlchemy repositories, retained
  only until an existing deployment finishes its cut-over.
* ``memory`` — process-local repositories for tests and local development.
"""

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
from sentinel.storage.repositories.oracle import (
    OracleApprovalRepository,
    OracleAuditRepository,
    OracleEventRepository,
    OracleEvidenceRepository,
    OracleFindingRepository,
    OracleRiskRepository,
    OracleTaskRepository,
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


def _durable_repository(oracle_repo: type, legacy_repo: type, memory_repo: type):
    """Pick the repository class for the configured backend."""
    settings = get_settings()
    if not getattr(settings, "uses_database_backend", False):
        return memory_repo
    if getattr(settings, "is_oracle_database", False):
        return oracle_repo
    return legacy_repo


def get_task_repository() -> TaskRepository:
    global _task_repo
    if _task_repo is None:
        repo = _durable_repository(OracleTaskRepository, PostgresTaskRepository, InMemoryTaskRepository)
        _task_repo = repo()
    return _task_repo


def get_finding_repository() -> FindingRepository:
    global _finding_repo
    if _finding_repo is None:
        repo = _durable_repository(
            OracleFindingRepository, PostgresFindingRepository, InMemoryFindingRepository
        )
        _finding_repo = repo()
    return _finding_repo


def get_evidence_repository() -> EvidenceRepository:
    global _evidence_repo
    if _evidence_repo is None:
        repo = _durable_repository(
            OracleEvidenceRepository, PostgresEvidenceRepository, InMemoryEvidenceRepository
        )
        _evidence_repo = repo()
    return _evidence_repo


def get_approval_repository() -> ApprovalRepository:
    global _approval_repo
    if _approval_repo is None:
        repo = _durable_repository(
            OracleApprovalRepository, PostgresApprovalRepository, InMemoryApprovalRepository
        )
        _approval_repo = repo()
    return _approval_repo


def get_risk_repository() -> RiskRepository:
    global _risk_repo
    if _risk_repo is None:
        repo = _durable_repository(OracleRiskRepository, PostgresRiskRepository, InMemoryRiskRepository)
        _risk_repo = repo()
    return _risk_repo


def get_audit_repository() -> AuditRepository:
    global _audit_repo
    if _audit_repo is None:
        repo = _durable_repository(OracleAuditRepository, PostgresAuditRepository, InMemoryAuditRepository)
        _audit_repo = repo()
    return _audit_repo


def get_event_repository() -> EventRepository:
    global _event_repo
    if _event_repo is None:
        repo = _durable_repository(OracleEventRepository, PostgresEventRepository, InMemoryEventRepository)
        _event_repo = repo()
    return _event_repo
