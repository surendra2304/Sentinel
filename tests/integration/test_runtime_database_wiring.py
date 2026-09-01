"""Runtime Persistence Integration Test.

Verifies:
1. API Task submission persistence through database repository backend.
2. Server/App simulated restart maintains persistent state.
3. Tasks submitted prior to restart remain queryable with intact state.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

from sentinel.apps.api.main import app
from sentinel.storage.database import session as db_session_module
from sentinel.storage.database.models import Base
from sentinel.storage.repositories import factory as repo_factory


@pytest.mark.asyncio
async def test_api_runtime_database_persistence_across_app_restarts(tmp_path, monkeypatch):
    # 1. Configure SQLite database backend for deterministic test persistence
    db_file = tmp_path / "sentinel_runtime_test.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"

    monkeypatch.setenv("SENTINEL_STORAGE_BACKEND", "postgres")
    monkeypatch.setenv("SENTINEL_DB_HOST", "localhost")
    monkeypatch.setenv("SENTINEL_DB_NAME", str(db_file))

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
        submit_payload = {
            "objective": "Runtime database persistence audit",
            "mode": "authorized_assessment",
            "targets": [{"type": "domain", "value": "persistent-target.internal"}],
            "scope": {
                "id": "scope-persist-01",
                "name": "Persist Scope",
                "allowed_targets": ["persistent-target.internal"]
            }
        }
        res = await client_a.post("/api/v1/tasks", json=submit_payload)
        assert res.status_code == 201
        data = res.json()
        task_id = data["task_id"]
        assert data["objective"] == "Runtime database persistence audit"

    # 3. Simulate Complete App Restart (flush singletons and rebind to the same DB file)
    repo_factory._task_repo = None
    repo_factory._finding_repo = None
    repo_factory._evidence_repo = None
    repo_factory._approval_repo = None
    db_session_module._engine = None
    db_session_module._session_factory = None

    restart_engine = create_async_engine(db_url, echo=False)
    monkeypatch.setattr(db_session_module, "get_async_engine", lambda: restart_engine)

    # 4. Start API client instance B and assert task is still queryable
    transport_b = ASGITransport(app=app)
    async with AsyncClient(transport=transport_b, base_url="http://testserver") as client_b:
        query_res = await client_b.get(f"/api/v1/tasks/{task_id}")
        assert query_res.status_code == 200
        restarted_task = query_res.json()
        assert restarted_task["id"] == task_id
        assert restarted_task["objective"] == "Runtime database persistence audit"
        assert restarted_task["target_set"]["targets"][0]["value"] == "persistent-target.internal"

@pytest.fixture(autouse=True)
def reset_db_singletons_after_test():
    yield
    repo_factory._task_repo = None
    repo_factory._finding_repo = None
    repo_factory._evidence_repo = None
    repo_factory._approval_repo = None
    db_session_module._engine = None
    db_session_module._session_factory = None
