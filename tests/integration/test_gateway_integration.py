import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

from sentinel.apps.api.main import app
from sentinel.apps.cli.main import app as cli_app
from sentinel.core.events.bus import InMemoryEventBus
from sentinel.core.models import Event, EventType
from sentinel.core.orchestrator.lifecycle import TaskLifecycleManager

# ---------------------------------------------------------------------------
# 1. API Integration Tests (Submit -> Status -> Cancel -> Telemetry)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_task_gateway_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Health and Readiness checks
        res_health = await client.get("/health")
        assert res_health.status_code == 200
        assert res_health.json()["status"] == "HEALTHY"

        res_ready = await client.get("/ready")
        assert res_ready.status_code == 200
        assert res_ready.json()["status"] == "READY"

        # 2. Submit Task
        payload = {
            "objective": "Comprehensive perimeter security scan",
            "targets": [
                {"type": "domain", "value": "api.sentinel.security"},
                {"type": "ip", "value": "192.168.1.100"},
            ],
            "mode": "assessment",
            "requested_output": "comprehensive_report",
        }
        res_submit = await client.post("/api/v1/tasks", json=payload)
        assert res_submit.status_code == 201
        data = res_submit.json()
        task_id = data["task_id"]
        assert task_id.startswith("task-")
        assert data["target_count"] == 2

        # 3. Get Task List and Status
        res_list = await client.get("/api/v1/tasks")
        assert res_list.status_code == 200
        task_ids = [t["task_id"] for t in res_list.json()]
        assert task_id in task_ids

        res_get = await client.get(f"/api/v1/tasks/{task_id}")
        assert res_get.status_code == 200
        assert res_get.json()["id"] == task_id

        # 4. Check Stubs (Findings, Evidence, Report)
        res_findings = await client.get(f"/api/v1/tasks/{task_id}/findings")
        assert res_findings.status_code == 200
        assert "findings" in res_findings.json()

        res_evidence = await client.get(f"/api/v1/tasks/{task_id}/evidence")
        assert res_evidence.status_code == 200
        assert "evidence" in res_evidence.json()

        res_report = await client.get(f"/api/v1/tasks/{task_id}/report")
        assert res_report.status_code == 200
        assert res_report.json()["status"] in ["submitted", "planning", "executing", "reporting", "complete", "cancelled"]

        # 5. Cancel Task (Kill Switch)
        res_cancel = await client.post(f"/api/v1/tasks/{task_id}/cancel?reason=TestOperatorHalt")
        assert res_cancel.status_code == 200
        assert res_cancel.json()["status"] == "cancelled"


# ---------------------------------------------------------------------------
# 2. CLI Integration Tests
# ---------------------------------------------------------------------------

def test_cli_operations():
    runner = CliRunner()

    # 1. CLI Status
    result_status = runner.invoke(cli_app, ["status"])
    assert result_status.exit_code == 0
    assert "CYBERSECURITY PLATFORM" in result_status.output

    # 2. CLI Task Submit
    result_submit = runner.invoke(
        cli_app,
        ["task", "submit", "--objective", "Audit internal host", "--target", "10.0.0.50", "--mode", "passive_recon"],
    )
    assert result_submit.exit_code == 0
    assert "Task submitted successfully" in result_submit.output

    # Extract task id from output
    lines = result_submit.output.split("\n")
    task_id = ""
    for line in lines:
        if "Task ID:" in line:
            task_id = line.split("Task ID:")[1].strip()
            break
    assert task_id != ""

    # 3. CLI Task Status
    result_task_status = runner.invoke(cli_app, ["task", "status", task_id])
    assert result_task_status.exit_code == 0
    assert task_id in result_task_status.output

    # 4. CLI Task Findings
    result_findings = runner.invoke(cli_app, ["task", "findings", task_id])
    assert result_findings.exit_code == 0

    # 5. CLI Report
    result_report = runner.invoke(cli_app, ["report", task_id])
    assert result_report.exit_code == 0

    # 6. CLI Cancel
    result_cancel = runner.invoke(cli_app, ["task", "cancel", task_id, "--reason", "CLI test cancel"])
    assert result_cancel.exit_code == 0
    assert "HALTED" in result_cancel.output


# ---------------------------------------------------------------------------
# 3. Event Bus Multi-Subscriber Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_event_bus_pub_sub_multiple_subscribers():
    bus = InMemoryEventBus()
    received_events_1: list[Event] = []
    received_events_2: list[Event] = []
    received_events_wildcard: list[Event] = []

    async def sub1(evt: Event):
        received_events_1.append(evt)

    async def sub2(evt: Event):
        received_events_2.append(evt)

    async def sub_wildcard(evt: Event):
        received_events_wildcard.append(evt)

    await bus.subscribe("task.created", sub1)
    await bus.subscribe("task.created", sub2)
    await bus.subscribe("task.*", sub_wildcard)

    event = Event(
        event_id="evt-101",
        event_type=EventType.TASK,
        topic="task.created",
        source="sentinel.test",
        payload={"task_id": "task-test-01"},
        correlation_id="corr-test",
    )

    await bus.publish(event)
    await asyncio.sleep(0.05)  # Allow async dispatch to yield

    assert len(received_events_1) == 1
    assert len(received_events_2) == 1
    assert len(received_events_wildcard) == 1
    assert received_events_1[0].event_id == "evt-101"

    # Test unsubscribe
    await bus.unsubscribe("task.created", sub1)
    event2 = Event(
        event_id="evt-102",
        event_type=EventType.STATUS,
        topic="task.created",
        source="sentinel.test",
        payload={"task_id": "task-test-02"},
        correlation_id="corr-test",
    )
    await bus.publish(event2)
    await asyncio.sleep(0.05)

    assert len(received_events_1) == 1  # Unsubscribed, no increase
    assert len(received_events_2) == 2
    assert len(received_events_wildcard) == 2


# ---------------------------------------------------------------------------
# 4. Crash Recovery Lifecycle Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_task_crash_recovery():
    manager = TaskLifecycleManager()
    task = await manager.create_and_submit_task(
        objective="Crash recovery resilience test",
        targets=[{"type": "domain", "value": "test.recovery.internal"}],
    )
    # Simulate mid-flight crash where task is left in EXECUTING state
    task.status = task.status.__class__.EXECUTING

    recovered_count = await manager.recover_tasks_on_startup()
    assert recovered_count == 1
    assert task.status == task.status.__class__.FAILED
