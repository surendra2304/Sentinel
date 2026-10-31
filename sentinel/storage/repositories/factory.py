"""Repository Provider Factory for Sentinel.

The backend is chosen from ``settings.storage_backend``:

* ``oracle`` (default, and the only durable backend) — the ``Oracle*`` SQLAlchemy
  repositories.
* ``memory`` — process-local repositories for tests and local development.

SQLite and PostgreSQL are not supported: both silently lose the security record
on redeploy or move it to a database Sentinel does not own.
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

_task_repo: TaskRepository | None = None
_finding_repo: FindingRepository | None = None
_evidence_repo: EvidenceRepository | None = None
_approval_repo: ApprovalRepository | None = None
_risk_repo: RiskRepository | None = None
_audit_repo: AuditRepository | None = None
_event_repo: EventRepository | None = None


def _durable_repository(oracle_repo: type, memory_repo: type):
    """Pick the repository class for the configured backend.

    A durable backend means Oracle, and Oracle is the only durable backend. There
    is no fallback: ``settings.uses_database_backend`` is true only for
    ``storage_backend=oracle`` and the Oracle settings fail closed when no DSN is
    configured.
    """
    settings = get_settings()
    if not getattr(settings, "uses_database_backend", False):
        return memory_repo
    return oracle_repo


def get_task_repository() -> TaskRepository:
    global _task_repo
    if _task_repo is None:
        repo = _durable_repository(OracleTaskRepository, InMemoryTaskRepository)
        _task_repo = repo()
    return _task_repo


def get_finding_repository() -> FindingRepository:
    global _finding_repo
    if _finding_repo is None:
        repo = _durable_repository(OracleFindingRepository, InMemoryFindingRepository)
        _finding_repo = repo()
    return _finding_repo


def get_evidence_repository() -> EvidenceRepository:
    global _evidence_repo
    if _evidence_repo is None:
        repo = _durable_repository(OracleEvidenceRepository, InMemoryEvidenceRepository)
        _evidence_repo = repo()
    return _evidence_repo


def get_approval_repository() -> ApprovalRepository:
    global _approval_repo
    if _approval_repo is None:
        repo = _durable_repository(OracleApprovalRepository, InMemoryApprovalRepository)
        _approval_repo = repo()
    return _approval_repo


def get_risk_repository() -> RiskRepository:
    global _risk_repo
    if _risk_repo is None:
        repo = _durable_repository(OracleRiskRepository, InMemoryRiskRepository)
        _risk_repo = repo()
    return _risk_repo


def get_audit_repository() -> AuditRepository:
    global _audit_repo
    if _audit_repo is None:
        repo = _durable_repository(OracleAuditRepository, InMemoryAuditRepository)
        _audit_repo = repo()
    return _audit_repo


def get_event_repository() -> EventRepository:
    global _event_repo
    if _event_repo is None:
        repo = _durable_repository(OracleEventRepository, InMemoryEventRepository)
        _event_repo = repo()
    return _event_repo
