"""FRIDAY must carry real, complete scope data; advisory context is not consent."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api import main as api_main
from sentinel.apps.api.main import app


def _scope(target: str) -> dict:
    now = datetime.now(UTC)
    return {
        "owner": "local-test-owner",
        "written_authorization_reference": "LOCAL-ONLY-FRIDAY-TEST",
        "targets": [target],
        "allowed_methods": ["passive_recon"],
        "time_window": {
            "start_time": (now - timedelta(minutes=1)).isoformat(),
            "end_time": (now + timedelta(minutes=5)).isoformat(),
        },
        "rate_limit": 5,
        "maximum_impact": "low",
        "authorization": {"allow_third_party_enrichment": False},
    }


@pytest.mark.asyncio
async def test_friday_rejects_missing_and_partial_scope_even_with_advisory_reference():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.post(
            "/api/v1/friday/delegate",
            json={
                "target": {"type": "ip", "value": "127.0.0.1"},
                "policy_context": {"authorization_reference": "ADVISORY-IS-NOT-AUTHORIZATION"},
            },
        )
        assert missing.status_code == 400
        assert "complete explicit scope" in missing.json()["detail"]

        partial = await client.post(
            "/api/v1/friday/delegate",
            json={
                "target": {"type": "ip", "value": "127.0.0.1"},
                "scope_override": {"allowed_targets": ["127.0.0.1"]},
            },
        )
        assert partial.status_code == 400
        assert "owner" in partial.json()["detail"]


@pytest.mark.asyncio
async def test_friday_default_assessment_mode_is_not_silently_downgraded_to_passive(monkeypatch):
    monkeypatch.setattr(api_main.lifecycle_manager, "_start_task_job", lambda _task_id: None)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/friday/delegate",
            json={
                "target": {"type": "ip", "value": "127.0.0.1"},
                "scope": _scope("127.0.0.1"),
            },
        )
        assert response.status_code == 200, response.text
        task_id = response.json()["task_id"]

        task_response = await client.get(f"/api/v1/tasks/{task_id}")
        assert task_response.status_code == 200
        assert task_response.json()["mode"] == "assessment"


@pytest.mark.asyncio
async def test_friday_rejects_modes_without_a_safe_execution_mapping():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/friday/delegate",
            json={
                "target": {"type": "ip", "value": "127.0.0.1"},
                "mode": "forensics",
                "scope": _scope("127.0.0.1"),
            },
        )
        assert response.status_code == 400
        assert "Unsupported FRIDAY task mode" in response.json()["detail"]
