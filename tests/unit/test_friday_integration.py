import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api.main import app
from sentinel.core.models import (
    Finding,
    Policy,
    Scope,
    SeverityLevel,
    Target,
    TargetSet,
    TargetType,
    Task,
)
from sentinel.integrations.friday.models import (
    BlockedActionRecord,
    FridaySummarizer,
)


@pytest.mark.asyncio
async def test_friday_delegation_lifecycle_end_to_end():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Delegate Task from FRIDAY
        payload = {
            "capability": "sentinel.security_assessment",
            "objective": "Verify staging web application posture",
            "targets": [{"type": "domain", "value": "staging.example.com"}],
            "mode": "authorized_assessment",
            "requested_output": "technical_and_executive",
            "policy_context": {
                "environment": "staging",
                "authorization_reference": "FRIDAY-TEST-001",
            },
        }

        res_del = await client.post("/api/v1/friday/delegate", json=payload)
        assert res_del.status_code == 200
        del_data = res_del.json()
        assert "del-" in del_data["delegation_id"]
        assert del_data["status"] == "submitted"
        assert "/events" in del_data["stream_url"]

        delegation_id = del_data["delegation_id"]

        # 2. Retrieve Delegation Result
        res_res = await client.get(f"/api/v1/friday/delegations/{delegation_id}")
        assert res_res.status_code == 200
        res_payload = res_res.json()
        assert res_payload["delegation_id"] == delegation_id
        assert isinstance(res_payload["findings"], list)
        assert "human_summary" in res_payload
        assert "Sentinel security assessment" in res_payload["human_summary"]

        # 3. Cancel Delegation (Emergency Stop)
        res_cancel = await client.post(f"/api/v1/friday/delegations/{delegation_id}/cancel?reason=TestHalt")
        assert res_cancel.status_code == 200
        assert res_cancel.json()["status"] == "cancelled"


def test_friday_deterministic_summarizer():
    task = Task(
        id="task-sum-01",
        objective="Assess payment gateway resilience",
        target_set=TargetSet(
            id="ts-1",
            name="TS-1",
            targets=[Target(id="t-1", type=TargetType.DOMAIN, value="pay.example.com")],
        ),
        scope=Scope(id="s-1", name="S-1", allowed_targets=["pay.example.com"]),
        policy=Policy(id="p-1", name="P-1", allowed_module_classes=["*"]),
        correlation_id="corr-01",
    )

    finding = Finding(
        id="f-01",
        task_id=task.id,
        title="Unencrypted Payment Token Header",
        description="Cleartext token observed.",
        severity=SeverityLevel.CRITICAL,
        target_ref="pay.example.com",
        evidence_refs=["evi-01"],
    )

    blocked = [
        BlockedActionRecord(
            action_type="network.raw_packet_injection",
            target="pay.example.com",
            reason="Blocked by hardcoded safety policy",
        )
    ]

    summary = FridaySummarizer.generate_summary(task, [finding], blocked)
    assert "Sentinel security assessment for 'Assess payment gateway resilience'" in summary
    assert "1 Critical" in summary
    assert "Sentinel governance blocked 1 elevated action" in summary
