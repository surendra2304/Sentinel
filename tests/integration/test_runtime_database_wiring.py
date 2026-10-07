"""Runtime Persistence Integration Test.

Verifies:
1. API Task submission persistence through database repository backend.
2. Server/App simulated restart maintains persistent state.
3. Tasks submitted prior to restart remain queryable with intact state.
"""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

from sentinel.apps.api import main as api_main
from sentinel.apps.api.main import app
from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.models import SeverityLevel
from sentinel.intelligence.risk.finding_engine import FindingEngine, Observation
from sentinel.storage.artifacts.storage import LocalFileSystemStorage
from sentinel.storage.database import session as db_session_module
from sentinel.storage.database.models import Base
from sentinel.storage.evidence.store import EvidenceStore
from sentinel.storage.repositories import factory as repo_factory


@pytest.mark.asyncio
async def test_api_runtime_database_persistence_across_app_restarts(tmp_path, monkeypatch):
    # 1. Configure SQLite database backend for deterministic test persistence
    db_file = tmp_path / "sentinel_runtime_test.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"

    monkeypatch.setenv("SENTINEL_STORAGE_BACKEND", "postgres")
    monkeypatch.setenv("SENTINEL_DB_HOST", "localhost")
    monkeypatch.setenv("SENTINEL_DB_NAME", str(db_file))
    get_settings.cache_clear()

    # Reset repository singletons & engine
    repo_factory._task_repo = None
    repo_factory._finding_repo = None
    repo_factory._evidence_repo = None
    repo_factory._approval_repo = None
    db_session_module._engine = None
    db_session_module._session_factory = None

    test_engine = create_async_engine(db_url, echo=False)
    monkeypatch.setattr(db_session_module, "get_async_engine", lambda: test_engine)

    # Initialize tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Start API client instance A and submit a task
    transport_a = ASGITransport(app=app)
    async with AsyncClient(transport=transport_a, base_url="http://testserver") as client_a:
        now = datetime.now(UTC)
        submit_payload = {
            "objective": "Runtime database persistence audit",
            "mode": "authorized_assessment",
            "targets": [{"type": "domain", "value": "persistent-target.internal"}],
            "scope": {
                "id": "scope-persist-01",
                "name": "Persist Scope",
                "owner": "runtime-test-operator",
                "written_authorization_reference": "CHG-RUNTIME-1001",
                "allowed_targets": ["persistent-target.internal"],
                "allowed_methods": ["validation"],
                "time_window": {
                    "start_time": (now - timedelta(minutes=1)).isoformat(),
                    "end_time": (now + timedelta(hours=2)).isoformat(),
                },
                "rate_limit": 23,
                "maximum_impact": "medium",
                "authorization": {"allow_third_party_enrichment": True},
            },
            "policy": {
                "id": "policy-persist-01",
                "name": "Persist Policy",
                "allowed_module_classes": ["web"],
                "allowed_action_classes": ["web.validate"],
                "max_intensity": 3,
                "credential_handling_rules": {"disallow_stored_credentials": True},
                "require_approval_for_offensive": False,
                "kill_switch_active": False,
            },
        }
        res = await client_a.post("/api/v1/tasks", json=submit_payload)
        assert res.status_code == 201
        data = res.json()
        task_id = data["task_id"]
        assert data["objective"] == "Runtime database persistence audit"

        api_main.evidence_store.storage = LocalFileSystemStorage(str(tmp_path / "artifact-store"))
        evidence = await api_main.evidence_store.record_evidence(
            task_id=task_id,
            target_ref="persistent-target.internal",
            source_agent="runtime_test_agent",
            source_module="runtime_test",
            source_tool="fixture",
            raw_data=b"persisted evidence artifact",
            content_type="text/plain",
        )
        finding = await api_main.finding_engine.ingest_observation(
            Observation(
                task_id=task_id,
                target_ref="persistent-target.internal",
                source_module="runtime_test",
                title="Persisted finding",
                description="Finding must be available after service reinitialization.",
                severity=SeverityLevel.HIGH,
                evidence_refs=[evidence.id],
            )
        )

    await test_engine.dispose()

    # 3. Simulate Complete App Restart (flush singletons and rebind to the same DB file)
    repo_factory._task_repo = None
    repo_factory._finding_repo = None
    repo_factory._evidence_repo = None
    repo_factory._approval_repo = None
    db_session_module._engine = None
    db_session_module._session_factory = None

    restart_engine = create_async_engine(db_url, echo=False)
    monkeypatch.setattr(db_session_module, "get_async_engine", lambda: restart_engine)

    # New service objects start with empty caches and must hydrate from repositories.
    restart_audit = AuditLogger(str(tmp_path / "restart-audit.jsonl"), signing_key="runtime-restart-test-key")
    monkeypatch.setattr(api_main, "finding_engine", FindingEngine(audit_logger=restart_audit))
    monkeypatch.setattr(
        api_main,
        "evidence_store",
        EvidenceStore(
            storage=LocalFileSystemStorage(str(tmp_path / "artifact-store")),
            audit_logger=restart_audit,
        ),
    )

    # 4. Start API client instance B and assert task is still queryable
    transport_b = ASGITransport(app=app)
    async with AsyncClient(transport=transport_b, base_url="http://testserver") as client_b:
        query_res = await client_b.get(f"/api/v1/tasks/{task_id}")
        assert query_res.status_code == 200
        restarted_task = query_res.json()
        assert restarted_task["id"] == task_id
        assert restarted_task["objective"] == "Runtime database persistence audit"
        assert restarted_task["target_set"]["targets"][0]["value"] == "persistent-target.internal"
        assert restarted_task["scope"]["owner"] == "runtime-test-operator"
        assert restarted_task["scope"]["written_authorization_reference"] == "CHG-RUNTIME-1001"
        assert restarted_task["scope"]["allowed_methods"] == ["validation"]
        assert restarted_task["scope"]["maximum_impact"] == "medium"
        assert restarted_task["scope"]["rate_limit"] == 23
        assert restarted_task["scope"]["authorization"]["allow_third_party_enrichment"] is True
        assert restarted_task["policy"]["allowed_module_classes"] == ["web"]
        assert restarted_task["policy"]["allowed_action_classes"] == ["web.validate"]
        assert restarted_task["policy"]["max_intensity"] == 3
        assert restarted_task["policy"]["require_approval_for_offensive"] is False

        findings_res = await client_b.get(f"/api/v1/tasks/{task_id}/findings")
        assert findings_res.status_code == 200
        assert findings_res.json()["count"] == 1
        assert findings_res.json()["findings"][0]["id"] == finding.id

        evidence_res = await client_b.get(f"/api/v1/tasks/{task_id}/evidence")
        assert evidence_res.status_code == 200
        assert evidence_res.json()["count"] == 1
        assert evidence_res.json()["evidence"][0]["id"] == evidence.id

    await restart_engine.dispose()


@pytest.fixture(autouse=True)
def reset_db_singletons_after_test():
    yield
    repo_factory._task_repo = None
    repo_factory._finding_repo = None
    repo_factory._evidence_repo = None
    repo_factory._approval_repo = None
    db_session_module._engine = None
    db_session_module._session_factory = None
