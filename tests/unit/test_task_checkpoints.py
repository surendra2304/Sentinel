"""Durable task-memory checkpoints and conservative restart recovery tests."""

import asyncio
from datetime import UTC, datetime

import pytest

from sentinel.core.memory.working_memory import MemoryStore, TaskWorkingMemory
from sentinel.core.models import ActionRequest, Policy, Scope, Target, TargetSet, Task, TaskStatus
from sentinel.core.orchestrator.lifecycle import TaskLifecycleManager
from sentinel.core.planner.heuristic import PlannedStep
from sentinel.core.policy.engine import ApprovalRecord, PolicyEngine
from sentinel.storage.repositories.in_memory import InMemoryTaskRepository


def make_task(task_id: str, status: TaskStatus = TaskStatus.EXECUTING) -> Task:
    target = Target(id=f"{task_id}-target", type="domain", value="checkpoint.example.invalid")
    return Task(
        id=task_id,
        objective="Test durable checkpoint recovery using an isolated fixture.",
        target_set=TargetSet(id=f"{task_id}-targets", name="checkpoint fixtures", targets=[target]),
        scope=Scope(
            id=f"{task_id}-scope",
            name="checkpoint fixture scope",
            allowed_targets=[target.value],
        ),
        policy=Policy(id=f"{task_id}-policy", name="checkpoint fixture policy"),
        correlation_id=f"{task_id}-correlation",
        status=status,
    )


@pytest.mark.asyncio
async def test_memory_store_rehydrates_versioned_checkpoint():
    repository = InMemoryTaskRepository()
    first_process = MemoryStore(checkpoint_repository=repository)
    memory = await first_process.load_memory("memory-checkpoint")
    memory.state_flags["phase_recon_baseline_done"] = True
    memory.proposal_fingerprints.add("proposal-fingerprint")
    memory.agent_action_counts["recon_agent"] = 3
    memory.last_iteration = 4
    memory.action_outcomes["action-fingerprint"] = {
        "action_id": "action-1",
        "action_type": "recon.ip_intel",
        "status": "success",
    }
    memory.deferred_plan_steps = [
        {
            "step_id": "step-deferred",
            "agent_name": "network_agent",
            "action_request": {
                "id": "action-deferred",
                "task_id": "memory-checkpoint",
                "agent": "network_agent",
                "action_type": "network.service_scan",
                "target_refs": ["checkpoint.example.invalid"],
                "parameters": {},
                "expected_impact_level": "low",
                "requires_approval": False,
                "status": "pending_approval",
                "created_at": datetime.now(UTC).isoformat(),
            },
            "phase": "AGENT_HANDOFF",
            "justification": "Resume the validated specialist request.",
        }
    ]

    assert await first_process.persist_memory(memory) == 1
    restarted_process = MemoryStore(checkpoint_repository=repository)
    restored = await restarted_process.load_memory("memory-checkpoint")

    assert restored.state_flags["phase_recon_baseline_done"] is True
    assert restored.proposal_fingerprints == {"proposal-fingerprint"}
    assert restored.agent_action_counts == {"recon_agent": 3}
    assert restored.last_iteration == 4
    assert restored.action_outcomes["action-fingerprint"]["status"] == "success"
    assert restored.deferred_plan_steps[0]["step_id"] == "step-deferred"


@pytest.mark.asyncio
async def test_checkpoint_size_limit_fails_before_repository_write():
    repository = InMemoryTaskRepository()
    store = MemoryStore(checkpoint_repository=repository, max_checkpoint_bytes=128)
    memory = TaskWorkingMemory(task_id="oversized-checkpoint")
    memory.state_flags["oversized"] = "x" * 1_024

    with pytest.raises(ValueError, match="exceeds configured in-memory safety bound"):
        await store.persist_memory(memory)

    assert await repository.get_checkpoint(memory.task_id) is None


@pytest.mark.asyncio
async def test_recovery_resumes_checkpoint_safe_task(monkeypatch):
    manager = TaskLifecycleManager()
    repository = manager.repo
    task = make_task("resume-safe")
    await repository.create_task(task)
    checkpoint_store = MemoryStore(checkpoint_repository=repository)
    memory = await checkpoint_store.load_memory(task.id)
    memory.state_flags["phase_recon_baseline_done"] = True
    memory.deferred_plan_steps = [{"step_id": "remaining-step"}]
    await checkpoint_store.persist_memory(memory)

    resumed: list[str] = []

    async def fake_pipeline(task_id: str) -> None:
        resumed.append(task_id)

    monkeypatch.setattr(manager, "_execute_task_pipeline", fake_pipeline)
    recovered_count = await manager.recover_tasks_on_startup()
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert recovered_count == 1
    assert resumed == [task.id]
    assert task.id not in manager._running_jobs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("version", "payload_update"),
    [
        ("corrupt-version", {}),
        (0, {}),
        (1, {"task_id": "another-task"}),
        (1, {"state_flags": ["not-a-mapping"]}),
    ],
)
async def test_recovery_fails_closed_for_corrupt_checkpoint(version, payload_update):
    manager = TaskLifecycleManager()
    repository = manager.repo
    task = make_task(f"resume-corrupt-{str(version).replace('-', '')}-{len(payload_update)}")
    await repository.create_task(task)
    checkpoint_store = MemoryStore(checkpoint_repository=repository)
    memory = await checkpoint_store.load_memory(task.id)
    payload = memory.model_dump(mode="json")
    payload.update(payload_update)
    await repository.save_checkpoint(task.id, payload)
    repository._checkpoints[task.id]["version"] = version

    recovered_count = await manager.recover_tasks_on_startup()
    persisted = await repository.get_task(task.id)

    assert recovered_count == 1
    assert persisted is not None
    assert persisted.status == TaskStatus.FAILED
    assert task.id not in manager._running_jobs


@pytest.mark.asyncio
async def test_recovery_fails_closed_for_ambiguous_in_flight_action():
    manager = TaskLifecycleManager()
    repository = manager.repo
    task = make_task("resume-ambiguous")
    await repository.create_task(task)
    checkpoint_store = MemoryStore(checkpoint_repository=repository)
    memory = await checkpoint_store.load_memory(task.id)
    memory.in_flight_action = {
        "fingerprint": "possibly-executed",
        "step": {"step_id": "step-uncertain"},
    }
    await checkpoint_store.persist_memory(memory)

    recovered_count = await manager.recover_tasks_on_startup()
    persisted = await repository.get_task(task.id)

    assert recovered_count == 1
    assert persisted is not None
    assert persisted.status == TaskStatus.FAILED
    assert task.id not in manager._running_jobs


@pytest.mark.asyncio
async def test_awaiting_approval_tasks_are_not_replayed_on_restart():
    manager = TaskLifecycleManager()
    repository = manager.repo
    task = make_task("resume-awaiting-approval", status=TaskStatus.AWAITING_APPROVAL)
    await repository.create_task(task)

    recovered_count = await manager.recover_tasks_on_startup()
    persisted = await repository.get_task(task.id)

    assert recovered_count == 0
    assert persisted is not None
    assert persisted.status == TaskStatus.AWAITING_APPROVAL


@pytest.mark.asyncio
@pytest.mark.parametrize("approval_status", ["APPROVED", "REJECTED"])
async def test_restart_resolves_finalized_approval_from_checkpoint(monkeypatch, approval_status):
    from sentinel.storage.repositories.factory import get_approval_repository

    manager = TaskLifecycleManager()
    repository = manager.repo
    task = make_task(f"resume-finalized-{approval_status.lower()}", status=TaskStatus.AWAITING_APPROVAL)
    await repository.create_task(task)
    action = ActionRequest(
        id=f"action-{approval_status.lower()}",
        task_id=task.id,
        agent="network_agent",
        action_type="network.service_scan",
        target_refs=["checkpoint.example.invalid"],
        requires_approval=True,
    )
    step = PlannedStep(
        step_id=f"step-{approval_status.lower()}",
        agent_name="network_agent",
        action_request=action,
        phase="AGENT_HANDOFF",
        justification="Operator-gated network service assessment.",
    )
    approval = ApprovalRecord(
        approval_id=f"approval-{approval_status.lower()}",
        task_id=task.id,
        action_id=action.id,
        action_type=action.action_type,
        target_refs=action.target_refs,
        requested_by=action.agent,
        action_fingerprint=PolicyEngine._approval_action_fingerprint(action),
        status=approval_status,
        justification_needed="Explicit operator decision required.",
        justification_provided="Reviewed the authorized task scope.",
        approved_by="test-operator",
    )
    await get_approval_repository().save_approval(approval)

    checkpoint_store = MemoryStore(checkpoint_repository=repository)
    memory = await checkpoint_store.load_memory(task.id)
    memory.state_flags["awaiting_approval_id"] = approval.approval_id
    memory.deferred_plan_steps = [step.model_dump(mode="json")]
    await checkpoint_store.persist_memory(memory)

    resumed: list[str] = []

    async def fake_pipeline(task_id: str) -> None:
        resumed.append(task_id)

    monkeypatch.setattr(manager, "_execute_task_pipeline", fake_pipeline)
    recovered_count = await manager.recover_tasks_on_startup()
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    persisted_task = await repository.get_task(task.id)
    persisted_checkpoint = await repository.get_checkpoint(task.id)
    assert recovered_count == 1
    assert resumed == [task.id]
    assert persisted_task is not None
    assert persisted_task.status == TaskStatus.EXECUTING
    assert persisted_checkpoint is not None
    resumed_memory = TaskWorkingMemory.model_validate(persisted_checkpoint["payload"])
    assert "awaiting_approval_id" not in resumed_memory.state_flags
    if approval_status == "APPROVED":
        assert resumed_memory.deferred_plan_steps[0]["action_request"]["id"] == action.id
    else:
        assert resumed_memory.deferred_plan_steps == []
        assert next(iter(resumed_memory.action_outcomes.values()))["status"] == "blocked"
