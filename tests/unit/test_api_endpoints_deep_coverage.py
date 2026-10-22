"""Comprehensive API endpoint coverage tests for Sentinel FastAPI gateway."""

import httpx
import pytest

from sentinel.apps.api.main import app


@pytest.mark.asyncio
async def test_findings_and_approvals_endpoints():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Findings listing
        resp = await client.get("/api/v1/findings")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

        # Non-existent finding detail
        resp_404 = await client.get("/api/v1/findings/nonexistent-find-id")
        assert resp_404.status_code == 404

        # Approvals listing
        resp_appr = await client.get("/api/v1/approvals")
        assert resp_appr.status_code == 200
        assert isinstance(resp_appr.json(), list)

        # Decide non-existent approval
        resp_dec = await client.post(
            "/api/v1/approvals/nonexistent-appr-id/decide",
            json={"approve": True, "operator": "sec-admin", "justification": "Authorized test"},
        )
        assert resp_dec.status_code == 404


@pytest.mark.asyncio
async def test_task_diagnostic_subendpoints():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Task findings & evidence listing for task
        r_f = await client.get("/api/v1/tasks/task-test-sub/findings")
        assert r_f.status_code == 200
        assert r_f.json()["count"] >= 0

        r_e = await client.get("/api/v1/tasks/task-test-sub/evidence")
        assert r_e.status_code == 200
        assert r_e.json()["count"] >= 0

        # Task risk summary
        r_r = await client.get("/api/v1/tasks/task-test-sub/risk-summary")
        assert r_r.status_code == 200
        assert "overall_risk_score" in r_r.json()

        # Task attack surface
        r_a = await client.get("/api/v1/tasks/task-test-sub/attack-surface")
        assert r_a.status_code == 200
        assert "total_nodes" in r_a.json()

        # Nonexistent task report
        r_rep = await client.get("/api/v1/tasks/task-test-sub/report")
        assert r_rep.status_code == 404


@pytest.mark.asyncio
async def test_friday_posture_and_asset_endpoints():
    headers = {"X-Service-Identity": "friday"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        # Security posture
        resp_posture = await client.get("/api/v1/friday/posture")
        assert resp_posture.status_code == 200
        data = resp_posture.json()
        assert "overall_posture_score" in data
        assert "per_domain_scores" in data
        assert "open_findings_by_severity" in data

        # Asset inventory
        resp_assets = await client.get("/api/v1/friday/assets")
        assert resp_assets.status_code == 200
        assert "total_assets" in resp_assets.json()

        # Scheduling
        resp_sched = await client.post(
            "/api/v1/friday/schedule",
            json={
                "target": "security.internal.corp",
                "frequency": "daily",
                "mode": "passive",
                "notify_on": "critical_only",
            },
        )
        assert resp_sched.status_code == 200
        assert resp_sched.json()["status"] == "active"


@pytest.mark.asyncio
async def test_security_incidents_and_quarantine():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # List incidents
        resp_list = await client.get("/api/v1/incidents")
        assert resp_list.status_code == 200
        assert isinstance(resp_list.json(), list)

        # Create incident
        resp_create = await client.post(
            "/api/v1/incidents",
            json={
                "id": "inc-test-api-99",
                "tenant_id": "default",
                "title": "Brute Force Ingress Attempt",
                "severity": "high",
                "reason": "Repeated anomalous SSH login failures from untrusted network",
            },
        )
        assert resp_create.status_code == 201
        assert resp_create.json()["id"] == "inc-test-api-99"

        # Contain incident
        resp_contain = await client.post("/api/v1/incidents/inc-test-api-99/contain")
        assert resp_contain.status_code == 200
        assert resp_contain.json()["status"] == "CONTAINED"

        # Quarantine check
        resp_q_check = await client.get("/api/v1/quarantine?subject=198.51.100.42")
        assert resp_q_check.status_code == 200
        assert resp_q_check.json()["quarantined"] is False

        # Put quarantine
        resp_q_put = await client.post(
            "/api/v1/quarantine",
            json={"subject": "198.51.100.42", "reason": "Host isolated", "ttl": 120.0},
        )
        assert resp_q_put.status_code == 200
        assert resp_q_put.json()["subject"] == "198.51.100.42"

        # Check again
        resp_q_recheck = await client.get("/api/v1/quarantine?subject=198.51.100.42")
        assert resp_q_recheck.status_code == 200
        assert resp_q_recheck.json()["quarantined"] is True


@pytest.mark.asyncio
async def test_capabilities_and_system_kill_switch():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Capabilities issue probe
        resp_cap = await client.post(
            "/api/v1/capabilities/issue",
            json={
                "actor_id": "cortex-worker-1",
                "tenant_id": "default",
                "actions": ["read:evidence", "execute:recon"],
                "resources": ["scope:internal"],
                "ttl": 300.0,
            },
        )
        assert resp_cap.status_code in (200, 503)

        # System Kill Switch
        resp_ks_get = await client.get("/api/v1/system/kill-switch")
        assert resp_ks_get.status_code == 200

        resp_ks_post = await client.post(
            "/api/v1/system/kill-switch",
            json={"active": False, "reason": "System operating normally"},
        )
        assert resp_ks_post.status_code == 200
        assert resp_ks_post.json()["action"] == "DEACTIVATED"

        # Ask inference fallback without credentials
        resp_inf = await client.post(
            "/api/v1/ask-inference",
            json={"question": "What are CVE mitigations?", "task_type": "security"},
        )
        assert resp_inf.status_code == 503

        # Security Readiness fail-closed probe
        resp_ready = await client.get("/api/v1/health/ready")
        assert resp_ready.status_code in (200, 503)
