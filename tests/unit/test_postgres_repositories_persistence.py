"""Unit and integration tests for PostgreSQL/SQL repositories persistence (Findings, Risks, and Audit Logs)."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import sentinel.storage.database.session as session_module
from sentinel.audit.audit_logger import AuditEntry
from sentinel.core.models import (
    AssetCriticality,
    Event,
    EventType,
    Finding,
    FindingStatus,
    Risk,
    RiskTier,
    SeverityLevel,
)
from sentinel.storage.database.models import Base
from sentinel.storage.repositories.factory import (
    get_audit_repository,
    get_event_repository,
    get_risk_repository,
)
from sentinel.storage.repositories.postgres import (
    PostgresAuditRepository,
    PostgresEventRepository,
    PostgresFindingRepository,
    PostgresRiskRepository,
)


@pytest.fixture
async def async_db(tmp_path, monkeypatch):
    """Sets up an isolated SQLite async database engine simulating PostgreSQL storage."""
    db_file = tmp_path / "sentinel_test_repo.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"

    engine = create_async_engine(db_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(session_module, "_engine", engine)
    monkeypatch.setattr(session_module, "_session_factory", session_factory)

    yield engine

    await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_finding_repository_persistence(async_db):
    repo = PostgresFindingRepository()
    finding = Finding(
        id="find-db-test-01",
        task_id="task-db-test-01",
        title="Remote Code Execution",
        description="Unauthenticated remote command execution",
        target_ref="10.0.0.1",
        severity=SeverityLevel.CRITICAL,
        confidence=0.95,
        evidence_refs=["evi-01"],
        related_cves=["CVE-2026-9999"],
        status=FindingStatus.OPEN,
    )

    saved = await repo.save_finding(finding)
    assert saved.id == finding.id

    fetched = await repo.get_finding(finding.id)
    assert fetched is not None
    assert fetched.title == "Remote Code Execution"
    assert fetched.severity == SeverityLevel.CRITICAL
    assert fetched.confidence == 0.95

    # Update status
    updated = await repo.update_status(finding.id, FindingStatus.REMEDIATED)
    assert updated is not None
    assert updated.status == FindingStatus.REMEDIATED

    # List findings
    listed = await repo.list_findings(task_id="task-db-test-01")
    assert len(listed) == 1
    assert listed[0].id == finding.id


@pytest.mark.asyncio
async def test_postgres_risk_repository_persistence(async_db):
    repo = PostgresRiskRepository()

    risk1 = Risk(
        id="risk-db-01",
        finding_id="find-db-test-01",
        task_id="task-db-test-01",
        severity=SeverityLevel.CRITICAL,
        asset_criticality=AssetCriticality.CRITICAL,
        exposure_score=1.0,
        exploitability_score=0.9,
        confidence_score=1.0,
        rationale="Critical asset exposed on internet",
    )

    risk2 = Risk(
        id="risk-db-02",
        finding_id="find-db-test-02",
        task_id="task-db-test-01",
        severity=SeverityLevel.LOW,
        asset_criticality=AssetCriticality.LOW,
        exposure_score=0.2,
        exploitability_score=0.3,
        confidence_score=0.8,
        rationale="Low asset internal only",
    )

    await repo.save_risk(risk1)
    await repo.save_risk(risk2)

    fetched = await repo.get_risk(risk1.id)
    assert fetched is not None
    assert fetched.severity == SeverityLevel.CRITICAL
    assert fetched.computed_risk_score > 70.0
    assert fetched.risk_tier == RiskTier.CRITICAL

    # Update existing risk
    risk1.exposure_score = 0.5
    risk1.rationale = "Mitigated exposure with WAF"
    await repo.save_risk(risk1)
    updated_risk = await repo.get_risk(risk1.id)
    assert updated_risk is not None
    assert updated_risk.exposure_score == 0.5

    # List by task_id and finding_id
    all_risks = await repo.list_risks(task_id="task-db-test-01")
    assert len(all_risks) == 2

    finding_risks = await repo.list_risks(finding_id="find-db-test-01")
    assert len(finding_risks) == 1

    # List by risk_tier
    crit_risks = await repo.list_risks(task_id="task-db-test-01", risk_tier=RiskTier.CRITICAL)
    assert len(crit_risks) == 1
    assert crit_risks[0].id == risk1.id


@pytest.mark.asyncio
async def test_postgres_audit_repository_hash_chain(async_db):
    repo = PostgresAuditRepository()

    # Empty chain check
    empty_valid, empty_msg = await repo.verify_audit_chain()
    assert empty_valid is True
    assert "empty" in empty_msg.lower()

    # Genesis entry
    genesis_hash = "GENESIS_BLOCK_000000000000000000000000000000000000000000000000000000"
    entry1_hash = "1111111111111111111111111111111111111111111111111111111111111111"
    entry2_hash = "2222222222222222222222222222222222222222222222222222222222222222"

    entry1 = AuditEntry(
        seq=1,
        entry_id="audit-entry-001",
        timestamp="2026-10-20T12:00:00+00:00",
        event_type="TASK_CREATED",
        actor="operator",
        previous_hash=genesis_hash,
        current_hash=entry1_hash,
        signature="sig-1",
        decision="ALLOWED",
    )

    entry2 = AuditEntry(
        seq=2,
        entry_id="audit-entry-002",
        timestamp="2026-10-20T12:05:00+00:00",
        event_type="PRE_DELIVERY_AUDIT",
        actor="forge",
        previous_hash=entry1_hash,
        current_hash=entry2_hash,
        signature="sig-2",
        decision="PASS",
    )

    await repo.save_audit_entry(entry1)
    # Save again to verify update branch
    await repo.save_audit_entry(entry1)
    await repo.save_audit_entry(entry2)

    # Fetch single entry
    fetched = await repo.get_audit_entry("audit-entry-001")
    assert fetched is not None
    assert fetched.actor == "operator"

    # Get last entry
    last = await repo.get_last_entry()
    assert last is not None
    assert last.entry_id == "audit-entry-002"

    # Verify audit chain integrity
    is_valid, msg = await repo.verify_audit_chain()
    assert is_valid is True
    assert "verified" in msg.lower()

    # Verify tamper detection: Corrupt entry 3's previous_hash
    tampered_entry = AuditEntry(
        seq=3,
        entry_id="audit-entry-003",
        timestamp="2026-10-20T12:10:00+00:00",
        event_type="FORGED_EVENT",
        actor="adversary",
        previous_hash="BROKEN_HASH_CHAIN_POINTER",
        current_hash="3333333333333333333333333333333333333333333333333333333333333333",
        signature="sig-3",
        decision="ALLOWED",
    )
    await repo.save_audit_entry(tampered_entry)

    tampered_valid, tamper_msg = await repo.verify_audit_chain()
    assert tampered_valid is False
    assert "hash break" in tamper_msg.lower()


@pytest.mark.asyncio
async def test_factory_switching_and_retrieval(monkeypatch):
    import sentinel.storage.repositories.factory as factory

    # Default to memory
    factory._risk_repo = None
    factory._audit_repo = None
    risk_repo = get_risk_repository()
    audit_repo = get_audit_repository()
    assert "InMemory" in type(risk_repo).__name__
    assert "InMemory" in type(audit_repo).__name__

    # Switch to postgres
    factory._risk_repo = None
    factory._audit_repo = None
    factory._event_repo = None
    monkeypatch.setenv("SENTINEL_STORAGE_BACKEND", "postgres")
    from sentinel.config.settings import get_settings
    get_settings.cache_clear()

    pg_risk_repo = get_risk_repository()
    pg_audit_repo = get_audit_repository()
    pg_event_repo = get_event_repository()
    assert "Postgres" in type(pg_risk_repo).__name__
    assert "Postgres" in type(pg_audit_repo).__name__
    assert "Postgres" in type(pg_event_repo).__name__


@pytest.mark.asyncio
async def test_postgres_event_repository_persistence(async_db):
    repo = PostgresEventRepository()

    event1 = Event(
        event_id="evt-db-001",
        event_type=EventType.TASK,
        topic="task.created",
        source="sentinel-orchestrator",
        payload={"task_id": "tsk-001", "mode": "active_recon"},
        correlation_id="corr-12345",
    )
    event2 = Event(
        event_id="evt-db-002",
        event_type=EventType.ALERT,
        topic="alert.critical",
        source="sentinel-threat-intel",
        payload={"threat": "C2 activity detected", "ip": "198.51.100.200"},
        correlation_id="corr-12345",
    )

    await repo.save_event(event1)
    await repo.save_event(event2)

    # Fetch by ID
    fetched1 = await repo.get_event("evt-db-001")
    assert fetched1 is not None
    assert fetched1.event_type == EventType.TASK
    assert fetched1.topic == "task.created"
    assert fetched1.payload["mode"] == "active_recon"

    # List by correlation_id
    corr_events = await repo.list_events(correlation_id="corr-12345")
    assert len(corr_events) == 2

    # List by topic
    alert_events = await repo.list_events(topic="alert.critical")
    assert len(alert_events) == 1
    assert alert_events[0].event_id == "evt-db-002"

    # Non-existent event
    missing = await repo.get_event("evt-nonexistent")
    assert missing is None
