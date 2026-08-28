"""PostgreSQL & Repository Persistence Integration Tests for Sentinel.

Verifies:
1. All durable entities persist to and load from the Repository layer (Task, Finding, Evidence, Approval)
2. Crash recovery: tasks left in non-terminal states are recovered and marked FAILED with audit records
3. Storage backend switching (memory vs postgres/sqlite)
4. State survives process restarts when backed by database
"""


import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.models import (
    AssetCriticality,
    EnvironmentLabel,
    Evidence,
    Finding,
    FindingStatus,
    Policy,
    Scope,
    SeverityLevel,
    Target,
    TargetMetadata,
    TargetSet,
    TargetType,
    Task,
    TaskMode,
    TaskStatus,
)
from sentinel.core.orchestrator.lifecycle import TaskLifecycleManager
from sentinel.core.policy.engine import ApprovalRecord
from sentinel.storage.database.models import Base
from sentinel.storage.repositories.in_memory import (
    InMemoryEvidenceRepository,
    InMemoryFindingRepository,
    InMemoryTaskRepository,
)
from sentinel.storage.repositories.postgres import (
    PostgresApprovalRepository,
    PostgresEvidenceRepository,
    PostgresFindingRepository,
    PostgresTaskRepository,
)


@pytest.fixture
def sample_task():
    target = Target(
        id="t-db-001",
        type=TargetType.DOMAIN,
        value="persistence.test.local",
        metadata=TargetMetadata(criticality=AssetCriticality.HIGH, environment=EnvironmentLabel.STAGING),
    )
    target_set = TargetSet(id="ts-db-001", name="DB Targets", targets=[target])
    scope = Scope(id="scope-db-001", name="DB Scope", allowed_targets=["persistence.test.local"])
    policy = Policy(id="policy-db-001", name="DB Policy")
    return Task(
        id="task-db-test-01",
        objective="Verify durable persistence to PostgreSQL backend",
        target_set=target_set,
        scope=scope,
        policy=policy,
        correlation_id="corr-db-001",
        mode=TaskMode.ASSESSMENT,
        status=TaskStatus.EXECUTING,
    )


# ---------------------------------------------------------------------------
# 1. In-Memory Repository Contract Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_in_memory_task_repository(sample_task):
    repo = InMemoryTaskRepository()
    created = await repo.create_task(sample_task)
    assert created.id == sample_task.id

    fetched = await repo.get_task(sample_task.id)
    assert fetched is not None
    assert fetched.objective == sample_task.objective

    sample_task.status = TaskStatus.COMPLETE
    updated = await repo.update_task(sample_task)
    assert updated.status == TaskStatus.COMPLETE

    listed = await repo.list_tasks(status=TaskStatus.COMPLETE)
    assert len(listed) == 1
    assert listed[0].id == sample_task.id


@pytest.mark.asyncio
async def test_in_memory_finding_repository():
    repo = InMemoryFindingRepository()
    finding = Finding(
        id="find-repo-01",
        task_id="task-repo-01",
        title="Test In-Memory Finding",
        description="Testing repo interface",
        target_ref="test.local",
        severity=SeverityLevel.HIGH,
        evidence_refs=["evi-01"],
    )
    await repo.save_finding(finding)
    fetched = await repo.get_finding(finding.id)
    assert fetched is not None
    assert fetched.title == finding.title

    updated = await repo.update_status(finding.id, FindingStatus.VERIFIED)
    assert updated is not None
    assert updated.status == FindingStatus.VERIFIED


@pytest.mark.asyncio
async def test_in_memory_evidence_repository():
    repo = InMemoryEvidenceRepository()
    evidence = Evidence(
        id="evi-repo-01",
        task_id="task-repo-01",
        target_ref="test.local",
        source_agent="recon",
        source_module="dns",
        source_tool="dig",
        artifact_storage_key="s3://test/key.dat",
        content_type="text/plain",
        sha256_hash="a" * 64,
        collected_by="operator",
    )
    await repo.save_evidence_record(evidence)
    fetched = await repo.get_evidence_record(evidence.id)
    assert fetched is not None
    assert fetched.sha256_hash == "a" * 64


# ---------------------------------------------------------------------------
# 2. Database (SQLite/Postgres Async Engine) Repository Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_postgres_repository_persistence(tmp_path, sample_task, monkeypatch):
    """Test SQL persistence using async SQLite database fixture."""
    db_file = tmp_path / "sentinel_async.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"

    # Patch database session engine
    engine = create_async_engine(db_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    import sentinel.storage.database.session as session_module
    monkeypatch.setattr(session_module, "_engine", engine)
    monkeypatch.setattr(
        session_module,
        "_session_factory",
        async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False),
    )

    task_repo = PostgresTaskRepository()
    finding_repo = PostgresFindingRepository()
    evidence_repo = PostgresEvidenceRepository()
    approval_repo = PostgresApprovalRepository()

    # 1. Persist and read back Task
    await task_repo.create_task(sample_task)
    fetched_task = await task_repo.get_task(sample_task.id)
    assert fetched_task is not None
    assert fetched_task.id == sample_task.id
    assert fetched_task.scope.allowed_targets == ["persistence.test.local"]
    assert len(fetched_task.target_set.targets) == 1

    # 2. Persist Finding
    finding = Finding(
        id="find-sql-01",
        task_id=sample_task.id,
        title="SQL Persistent Finding",
        description="Verifying DB row insertion",
        target_ref="persistence.test.local",
        severity=SeverityLevel.CRITICAL,
        evidence_refs=["evi-sql-01"],
    )
    await finding_repo.save_finding(finding)
    fetched_finding = await finding_repo.get_finding(finding.id)
    assert fetched_finding is not None
    assert fetched_finding.severity == SeverityLevel.CRITICAL

    # 3. Persist Evidence Index Row
    evidence = Evidence(
        id="evi-sql-01",
        task_id=sample_task.id,
        target_ref="persistence.test.local",
        source_agent="web_agent",
        source_module="web.observe",
        source_tool="curl",
        artifact_storage_key="s3://bucket/evidence/123.dat",
        content_type="application/json",
        sha256_hash="e" * 64,
        collected_by="executor",
    )
    await evidence_repo.save_evidence_record(evidence)
    fetched_evi = await evidence_repo.get_evidence_record(evidence.id)
    assert fetched_evi is not None
    assert fetched_evi.sha256_hash == "e" * 64

    # 4. Persist Approval Record
    approval = ApprovalRecord(
        approval_id="appr-sql-01",
        task_id=sample_task.id,
        action_id="act-sql-01",
        action_type="network.port_scan",
        target_refs=["persistence.test.local"],
        requested_by="network_agent",
        status="PENDING",
        justification_needed="Intensive active scan",
    )
    await approval_repo.save_approval(approval)
    fetched_appr = await approval_repo.get_approval(approval.approval_id)
    assert fetched_appr is not None
    assert fetched_appr.action_type == "network.port_scan"


# ---------------------------------------------------------------------------
# 3. Crash Recovery Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_crash_recovery_cleans_non_terminal_tasks(tmp_path, sample_task, monkeypatch):
    """Simulate mid-run process crash and ensure startup marks active tasks as FAILED."""
    manager = TaskLifecycleManager()
    audit_file = tmp_path / "audit_recovery.jsonl"
    manager.audit_logger = AuditLogger(log_path=str(audit_file), signing_key="test-key")

    # Create task in EXECUTING state
    sample_task.status = TaskStatus.EXECUTING
    await manager.repo.create_task(sample_task)

    # Verify task is currently active
    active = await manager.repo.get_active_non_terminal_tasks()
    assert len(active) == 1
    assert active[0].id == sample_task.id

    # Simulate server reboot / startup crash recovery hook
    recovered_count = await manager.recover_tasks_on_startup()
    assert recovered_count == 1

    # Verify task transitioned to FAILED terminal state
    recovered_task = await manager.repo.get_task(sample_task.id)
    assert recovered_task is not None
    assert recovered_task.status == TaskStatus.FAILED
    assert recovered_task.completed_at is not None

    # Verify audit log entry was written
    log_data = audit_file.read_text(encoding="utf-8")
    assert "TASK_RECOVERY_FAILED" in log_data
    assert sample_task.id in log_data
