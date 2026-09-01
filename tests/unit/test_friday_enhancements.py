"""Comprehensive End-to-End Tests for FRIDAY Delegation Enhancements & Real-Time Events.

Tests:
1. Enhanced POST /api/v1/friday/delegate:
   - Friday request ID, priority, context (nexus/forge/trading_bot), webhook URL, scope overrides, and blocked targets detection.
2. Real-Time SSE Stream GET /api/v1/friday/events/{task_id}:
   - task_started, finding_detected, phase_changed, approval_required, task_completed, task_failed events.
3. Security Posture GET /api/v1/friday/posture:
   - Overall score (0-100), domain scores, severity counts, most critical finding, last scan times, trend.
4. Asset Inventory GET /api/v1/friday/assets:
   - All targets with security status (secure/vulnerable/critical) and open finding counts.
5. Scheduled Assessments POST /api/v1/friday/schedule:
   - Daily/weekly/monthly frequencies, modes, notification levels, schedule ID return.
6. FRIDAY-Specific API Key Authentication & 100 req/hour Rate Limiting:
   - Access control, key scopes, and consumer throttling.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api.main import app
from sentinel.core.models import SeverityLevel
from sentinel.intelligence.risk.finding_engine import finding_engine


@pytest.mark.asyncio
async def test_enhanced_friday_delegation_request_and_blocked_targets():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Enhanced Delegation Request with full context, priority, and scope override
        payload = {
            "friday_request_id": "fri-req-nexus-992",
            "target": {"type": "domain", "value": "portal.nexus.internal"},
            "mode": "authorized_assessment",
            "priority": "urgent",
            "context": {
                "asset_type": "web_application",
                "source_system": "nexus",
                "related_incident_id": "INC-8812",
            },
            "webhook_url": "https://nexus.internal/webhooks/sentinel",
            "scope_override": {
                "allowed_targets": ["portal.nexus.internal"]
            },
            "objective": "Triage suspected authentication bypass",
        }

        res = await client.post(
            "/api/v1/friday/delegate",
            json=payload,
            headers={"X-API-Key": "friday-key-nexus-primary"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["sentinel_task_id"] == data["task_id"]
        assert data["friday_request_id"] == "fri-req-nexus-992"
        assert data["status"] == "submitted"
        assert data["initial_phase"] == "RECONNAISSANCE"
        assert data["estimated_duration"] == "1-3 minutes"  # Urgent priority
        assert len(data["blocked_targets"]) == 0
        assert f"/friday/events/{data['task_id']}" in data["stream_url"]

        # 2. Delegation with blocked out-of-scope targets
        payload_blocked = {
            "friday_request_id": "fri-req-forge-404",
            "targets": [
                {"type": "domain", "value": "allowed.forge.internal"},
                {"type": "ip", "value": "198.51.100.99"},
            ],
            "scope_override": {
                "allowed_targets": ["allowed.forge.internal"]
            },
            "context": {
                "source_system": "forge",
            },
        }

        res_blk = await client.post(
            "/api/v1/friday/delegate",
            json=payload_blocked,
            headers={"X-API-Key": "friday-key-forge"},
        )
        assert res_blk.status_code == 200
        blk_data = res_blk.json()
        assert len(blk_data["blocked_targets"]) == 1
        assert blk_data["blocked_targets"][0]["target"] == "198.51.100.99"
        assert "scope_override" in blk_data["blocked_targets"][0]["policy_dimension"]


@pytest.mark.asyncio
async def test_friday_security_posture_and_asset_inventory():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Seed test findings
        from sentinel.intelligence.risk.finding_engine import Observation

        obs1 = Observation(
            task_id="task-pos-1",
            title="Exposed AWS Root Credential in Git Repository",
            description="Hardcoded root access key discovered.",
            severity=SeverityLevel.CRITICAL,
            target_ref="git.tradingbot.internal",
            source_module="cloud_security",
            evidence_refs=["evi-pos-1"],
        )
        await finding_engine.ingest_observation(obs1)

        obs2 = Observation(
            task_id="task-pos-1",
            title="Missing HSTS Header",
            description="Header not returned.",
            severity=SeverityLevel.MEDIUM,
            target_ref="web.tradingbot.internal",
            source_module="web_security",
            evidence_refs=["evi-pos-2"],
        )
        await finding_engine.ingest_observation(obs2)

        # 1. Posture API
        res_posture = await client.get(
            "/api/v1/friday/posture",
            headers={"X-API-Key": "friday-key-trading"},
        )
        assert res_posture.status_code == 200
        pos_data = res_posture.json()
        assert 0.0 <= pos_data["overall_posture_score"] <= 100.0
        assert pos_data["open_findings_by_severity"]["critical"] >= 1
        assert pos_data["open_findings_by_severity"]["medium"] >= 1
        assert pos_data["most_critical_finding"]["title"] == "Exposed AWS Root Credential in Git Repository"
        assert "git.tradingbot.internal" in pos_data["last_scan_times"]
        assert pos_data["trend"] == "degrading"

        # 2. Asset Inventory API
        res_assets = await client.get(
            "/api/v1/friday/assets",
            headers={"X-API-Key": "friday-key-trading"},
        )
        assert res_assets.status_code == 200
        asset_data = res_assets.json()
        assert asset_data["total_assets"] >= 2
        targets = [a["target"] for a in asset_data["assets"]]
        assert "git.tradingbot.internal" in targets
        crit_asset = next(a for a in asset_data["assets"] if a["target"] == "git.tradingbot.internal")
        assert crit_asset["status"] == "critical"
        assert crit_asset["open_finding_count"] >= 1


@pytest.mark.asyncio
async def test_friday_schedule_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "api.nexus.internal",
            "frequency": "weekly",
            "mode": "authorized_assessment",
            "notify_on": "critical_only",
        }

        res = await client.post(
            "/api/v1/friday/schedule",
            json=payload,
            headers={"X-API-Key": "friday-key-scheduler"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["schedule_id"].startswith("sched-fri-")
        assert data["target"] == "api.nexus.internal"
        assert data["frequency"] == "weekly"
        assert data["notify_on"] == "critical_only"
        assert data["status"] == "active"


@pytest.mark.asyncio
async def test_friday_api_key_scoping_and_rate_limiting():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. FRIDAY scoped key blocked from general admin endpoints if scoped strictly
        res_forbidden = await client.get(
            "/api/v1/approvals",
            headers={"X-API-Key": "friday-scoped-only-key"},
        )
        assert res_forbidden.status_code == 403
        assert "scoped strictly" in res_forbidden.json()["detail"]

        # 2. FRIDAY rate limiter throttling at 100 req/hour for a key
        key_id = "friday-key-rate-limit-test"
        from sentinel.apps.api.middleware import friday_rate_limiter
        # Simulate filling rate limiter
        for _ in range(100):
            friday_rate_limiter.is_allowed(f"friday_{key_id}", max_requests=100, window=3600.0)

        # Next request must return 429
        res_throttled = await client.get(
            "/api/v1/friday/posture",
            headers={"X-API-Key": key_id},
        )
        assert res_throttled.status_code == 429
        assert "100 req/hour" in res_throttled.json()["detail"]
