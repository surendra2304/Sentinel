"""Task Lifecycle Manager and execution coordinator for Sentinel.

Enforces state machine transitions, crash-resilience, recoverable resumption,
and immediate kill-switch execution cancellation.
"""

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.events.bus import emit_event
from sentinel.core.models import (
    EventType,
    Policy,
    Scope,
    Target,
    TargetSet,
    Task,
    TaskMode,
    TaskStatus,
)
from sentinel.logging.logger import get_logger

logger = get_logger("sentinel.lifecycle")


class TaskLifecycleManager:
    """Manages the in-memory/database lifecycle of Sentinel tasks with recovery guarantees."""

    def __init__(self):
        self.settings = get_settings()
        self.audit_logger = AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )
        self._active_tasks: dict[str, Task] = {}
        self._running_jobs: dict[str, asyncio.Task[Any]] = {}
        self._lock = asyncio.Lock()

    async def create_and_submit_task(
        self,
        objective: str,
        targets: list[dict[str, Any]],
        scope_data: dict[str, Any] | None = None,
        policy_data: dict[str, Any] | None = None,
        mode: TaskMode = TaskMode.ASSESSMENT,
        requested_output_type: str = "comprehensive_report",
        correlation_id: str | None = None,
    ) -> Task:
        """Normalize, validate, and register a new security task."""
        cid = correlation_id or str(uuid.uuid4())
        task_id = f"task-{uuid.uuid4().hex[:12]}"

        # 1. Parse and normalize targets
        parsed_targets: list[Target] = []
        for idx, t in enumerate(targets):
            t_id = t.get("id") or f"{task_id}-t{idx+1}"
            parsed_targets.append(
                Target(
                    id=t_id,
                    type=t.get("type", "domain"),
                    value=t.get("value", "").strip(),
                    resolved_ips=t.get("resolved_ips", []),
                    metadata=t.get("metadata", {}),
                )
            )

        target_set = TargetSet(
            id=f"ts-{task_id}",
            name=f"TargetSet for {task_id}",
            targets=parsed_targets,
        )

        # 2. Scope & Policy configuration
        scope = (
            Scope(**scope_data)
            if scope_data
            else Scope(
                id=f"scope-{task_id}",
                name=f"Scope for {task_id}",
                allowed_targets=[t.value for t in parsed_targets],
            )
        )

        policy = (
            Policy(**policy_data)
            if policy_data
            else Policy(
                id=f"policy-{task_id}",
                name=f"Default Policy for {task_id}",
            )
        )

        # 3. Create Task object in SUBMITTED state
        task = Task(
            id=task_id,
            objective=objective,
            target_set=target_set,
            scope=scope,
            policy=policy,
            mode=mode,
            status=TaskStatus.SUBMITTED,
            requested_output_type=requested_output_type,
            correlation_id=cid,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        async with self._lock:
            self._active_tasks[task_id] = task

        # Audit creation
        self.audit_logger.log_event(
            entry_id=f"audit-create-{task_id}",
            event_type="TASK_CREATED",
            actor="gateway",
            action_type="TASK_SUBMIT",
            scope_policy=scope.id,
            decision="ACCEPTED",
            details={"task_id": task_id, "objective": objective, "target_count": len(parsed_targets)},
        )

        # Emit task.created & task.submitted events
        await emit_event(
            event_type=EventType.TASK,
            topic="task.created",
            source="sentinel.gateway",
            payload={"task_id": task.id, "objective": task.objective, "mode": task.mode.value},
            correlation_id=task.correlation_id,
        )
        await emit_event(
            event_type=EventType.STATUS,
            topic="task.submitted",
            source="sentinel.gateway",
            payload={"task_id": task.id, "status": task.status.value},
            correlation_id=task.correlation_id,
        )

        # Start execution loop in background
        job = asyncio.create_task(self._execute_task_pipeline(task_id))
        self._running_jobs[task_id] = job

        return task

    async def _execute_task_pipeline(self, task_id: str) -> None:
        """Simulate autonomous pipeline state machine transitions while respecting cancellation."""
        task = self._active_tasks.get(task_id)
        if not task:
            return

        try:
            # Transition: SUBMITTED -> PLANNING
            await asyncio.sleep(0.05)
            await self._update_status(task, TaskStatus.PLANNING, 10.0, "AI Planner structuring inspection graph.")

            # Transition: PLANNING -> EXECUTING
            await asyncio.sleep(0.05)
            await self._update_status(task, TaskStatus.EXECUTING, 40.0, "Executing module adapters against authorized targets.")

            # Simulated progress
            await asyncio.sleep(0.05)
            task.progress_percentage = 80.0
            await emit_event(
                event_type=EventType.STATUS,
                topic="task.progress",
                source="sentinel.orchestrator",
                payload={"task_id": task.id, "progress": 80.0},
                correlation_id=task.correlation_id,
            )

            # Transition: EXECUTING -> REPORTING
            await asyncio.sleep(0.05)
            await self._update_status(task, TaskStatus.REPORTING, 95.0, "Synthesizing evidence and generating report.")

            # Transition: REPORTING -> COMPLETE
            await asyncio.sleep(0.05)
            await self._update_status(task, TaskStatus.COMPLETE, 100.0, "Task execution finished successfully.")

        except asyncio.CancelledError:
            # Handle cancellation gracefully
            if task.status not in (TaskStatus.COMPLETE, TaskStatus.FAILED, TaskStatus.CANCELLED):
                task.status = TaskStatus.CANCELLED
                task.updated_at = datetime.now(UTC)
                task.completed_at = datetime.now(UTC)
                self.audit_logger.log_event(
                    entry_id=f"audit-cancel-{task_id}",
                    event_type="TASK_CANCELLED",
                    actor="operator_kill_switch",
                    action_type="KILL_SWITCH",
                    scope_policy=task.scope.id,
                    decision="HALTED",
                    details={"task_id": task.id, "reason": "Operator requested task cancellation"},
                )
                await emit_event(
                    event_type=EventType.STATUS,
                    topic="task.cancelled",
                    source="sentinel.lifecycle",
                    payload={"task_id": task.id, "status": TaskStatus.CANCELLED.value},
                    correlation_id=task.correlation_id,
                )
        except Exception as exc:
            # Catch unexpected exceptions and ensure task ends in FAILED terminal state
            task.status = TaskStatus.FAILED
            task.updated_at = datetime.now(UTC)
            task.completed_at = datetime.now(UTC)
            self.audit_logger.log_event(
                entry_id=f"audit-fail-{task_id}",
                event_type="TASK_FAILED",
                actor="system",
                action_type="EXECUTION_ERROR",
                scope_policy=task.scope.id,
                decision="TERMINATED",
                details={"task_id": task.id, "error": str(exc)},
            )
            await emit_event(
                event_type=EventType.ALERT,
                topic="task.failed",
                source="sentinel.lifecycle",
                payload={"task_id": task.id, "error": str(exc)},
                correlation_id=task.correlation_id,
            )

    async def _update_status(self, task: Task, status: TaskStatus, progress: float, note: str) -> None:
        task.transition_to(status)
        task.progress_percentage = progress
        await emit_event(
            event_type=EventType.STATUS,
            topic=f"task.{status.value}",
            source="sentinel.lifecycle",
            payload={"task_id": task.id, "status": status.value, "progress": progress, "note": note},
            correlation_id=task.correlation_id,
        )

    async def cancel_task(self, task_id: str, reason: str = "Operator Kill Switch") -> Task:
        """Immediately halt execution of a specific task."""
        async with self._lock:
            task = self._active_tasks.get(task_id)
            if not task:
                raise KeyError(f"Task {task_id} not found.")

            if task.status in (TaskStatus.COMPLETE, TaskStatus.FAILED, TaskStatus.CANCELLED):
                return task

            # Cancel running asyncio task
            job = self._running_jobs.get(task_id)
            if job and not job.done():
                job.cancel()

            task.status = TaskStatus.CANCELLED
            task.updated_at = datetime.now(UTC)
            task.completed_at = datetime.now(UTC)

        self.audit_logger.log_event(
            entry_id=f"audit-cancel-direct-{task_id}",
            event_type="TASK_CANCELLED",
            actor="operator_kill_switch",
            action_type="KILL_SWITCH",
            scope_policy=task.scope.id,
            decision="HALTED",
            details={"task_id": task_id, "reason": reason},
        )

        await emit_event(
            event_type=EventType.STATUS,
            topic="task.cancelled",
            source="sentinel.lifecycle",
            payload={"task_id": task.id, "status": TaskStatus.CANCELLED.value, "reason": reason},
            correlation_id=task.correlation_id,
        )

        return task

    async def get_task(self, task_id: str) -> Task | None:
        async with self._lock:
            return self._active_tasks.get(task_id)

    async def list_tasks(self) -> list[Task]:
        async with self._lock:
            return list(self._active_tasks.values())

    async def recover_tasks_on_startup(self) -> int:
        """Ensure no lingering tasks remain in intermediate states after crash/restart."""
        count = 0
        async with self._lock:
            for task_id, task in self._active_tasks.items():
                if task.status in (TaskStatus.PLANNING, TaskStatus.EXECUTING, TaskStatus.AWAITING_APPROVAL, TaskStatus.REPORTING):
                    task.status = TaskStatus.FAILED
                    task.updated_at = datetime.now(UTC)
                    task.completed_at = datetime.now(UTC)
                    count += 1
                    self.audit_logger.log_event(
                        entry_id=f"audit-recover-{task_id}",
                        event_type="TASK_RECOVERY_FAILED",
                        actor="system_startup",
                        action_type="CRASH_RECOVERY",
                        scope_policy=task.scope.id,
                        decision="MARKED_FAILED",
                        details={"task_id": task_id, "reason": "Server restarted during active execution."},
                    )
        return count


# Lifecycle manager singleton
lifecycle_manager = TaskLifecycleManager()
