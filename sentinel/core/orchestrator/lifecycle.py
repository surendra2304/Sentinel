"""Task Lifecycle Manager and execution coordinator for Sentinel.

Enforces state machine transitions, crash-resilience, recoverable resumption,
and immediate kill-switch execution cancellation across repository backends.
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
from sentinel.storage.repositories.factory import get_task_repository
from sentinel.storage.repositories.interfaces import TaskRepository

logger = get_logger("sentinel.lifecycle")


class TaskLifecycleManager:
    """Manages the in-memory/database lifecycle of Sentinel tasks with recovery guarantees."""

    def __init__(self):
        self.settings = get_settings()
        self.audit_logger = AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )
        self._running_jobs: dict[str, asyncio.Task[Any]] = {}
        self._lock = asyncio.Lock()

    @property
    def repo(self) -> TaskRepository:
        return get_task_repository()

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

        # 0. Global Kill Switch Check
        if self.settings.kill_switch_active:
            raise PermissionError("Global kill switch is ACTIVE. Task creation and execution is halted.")

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
        from sentinel.core.scope.resolver import ScopeResolver

        if not scope_data:
            raise ValueError("An explicit authorization scope is required; Sentinel will not synthesize consent.")

        s_dict = dict(scope_data)
        if not str(s_dict.get("owner", "")).strip():
            raise ValueError("Scope must include the actual authorizing owner.")
        if not str(s_dict.get("written_authorization_reference", "")).strip():
            authorization = s_dict.get("authorization")
            auth_reference = (
                authorization.get("reference_ticket_id")
                if isinstance(authorization, dict)
                else getattr(authorization, "reference_ticket_id", None)
            )
            if not str(auth_reference or "").strip():
                raise ValueError("Scope must include a written authorization reference; synthetic references are prohibited.")
        if not s_dict.get("time_window"):
            raise ValueError("Scope must include an explicit authorization time window.")
        if not s_dict.get("allowed_methods"):
            raise ValueError("Scope must explicitly allow at least one assessment method.")
        if "maximum_impact" not in s_dict:
            raise ValueError("Scope must explicitly set a maximum impact level.")
        if "rate_limit" not in s_dict:
            raise ValueError("Scope must explicitly set a positive rate limit.")

        # These identifiers are descriptive, not authorization claims.
        s_dict.setdefault("id", f"scope-{task_id}")
        s_dict.setdefault("name", f"Scope for {task_id}")
        scope = Scope(**s_dict)

        # Validate the authorization contract and bind every requested target to it.
        ScopeResolver.validate_scope(scope)
        resolver = ScopeResolver(scope)
        for target in parsed_targets:
            is_in_scope, _verdict, explanation = resolver.is_target_in_scope(target)
            if not is_in_scope:
                raise ValueError(f"Requested target '{target.value}' is outside the explicit scope: {explanation}")

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

        # Persist task through repository
        await self.repo.create_task(task)

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

        # Start execution loop in background.
        self._start_task_job(task_id)

        return task

    def _start_task_job(self, task_id: str) -> asyncio.Task[Any]:
        """Start at most one local worker for a task and discard completed handles."""
        current = self._running_jobs.get(task_id)
        if current is not None and not current.done():
            return current

        job = asyncio.create_task(self._execute_task_pipeline(task_id))
        self._running_jobs[task_id] = job

        def forget_completed(completed_job: asyncio.Task[Any]) -> None:
            if self._running_jobs.get(task_id) is completed_job:
                self._running_jobs.pop(task_id, None)

        job.add_done_callback(forget_completed)
        return job

    async def _execute_task_pipeline(self, task_id: str) -> None:
        """Sequential autonomous lifecycle execution pipeline."""
        task = await self.repo.get_task(task_id)
        if not task:
            return

        try:
            if task.status == TaskStatus.SUBMITTED:
                await self._update_status(
                    task,
                    TaskStatus.PLANNING,
                    10.0,
                    "AI Planner structuring inspection graph.",
                )
            elif task.status not in (TaskStatus.PLANNING, TaskStatus.EXECUTING, TaskStatus.REPORTING):
                return

            from sentinel.core.orchestrator.orchestrator import AutonomousOrchestrator
            from sentinel.intelligence.reporting.generator import ReportType, report_generator
            from sentinel.intelligence.risk.finding_engine import finding_engine

            orchestrator = AutonomousOrchestrator()
            task = await orchestrator.run_task(
                task,
                max_iterations=self.settings.max_task_iterations,
            )

            if task.status == TaskStatus.AWAITING_APPROVAL:
                await self.repo.update_task(task)
                return

            terminal_statuses = {
                TaskStatus.COMPLETE,
                TaskStatus.COMPLETED,
                TaskStatus.BLOCKED,
                TaskStatus.PARTIALLY_COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
            }
            if task.status != TaskStatus.CANCELLED:
                if task.status not in terminal_statuses:
                    await self._update_status(
                        task,
                        TaskStatus.REPORTING,
                        90.0,
                        "Synthesizing evidence and generating report.",
                    )

                task_findings = await finding_engine.list_findings_async(task_id=task.id)
                try:
                    report_generator.generate_report(task, findings=task_findings, report_type=ReportType.TECHNICAL)
                except Exception as exc:
                    logger.exception("Task report generation failed", extra={"task_id": task.id})
                    raise RuntimeError("Task report generation failed; task cannot be marked complete.") from exc

                if task.status == TaskStatus.REPORTING:
                    await self._update_status(task, TaskStatus.COMPLETE, 100.0, "Task execution finished successfully.")

            # Persist final outcomes, including terminal statuses returned by the orchestrator.
            await self.repo.update_task(task)

        except asyncio.CancelledError:
            # Handle cancellation gracefully
            if task.status not in (TaskStatus.COMPLETE, TaskStatus.FAILED, TaskStatus.CANCELLED):
                task.status = TaskStatus.CANCELLED
                task.updated_at = datetime.now(UTC)
                task.completed_at = datetime.now(UTC)
                await self.repo.update_task(task)
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
            await self.repo.update_task(task)
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
        await self.repo.update_task(task)
        await emit_event(
            event_type=EventType.STATUS,
            topic=f"task.{status.value}",
            source="sentinel.lifecycle",
            payload={"task_id": task.id, "status": status.value, "progress": progress, "note": note},
            correlation_id=task.correlation_id,
        )

    async def cancel_task(self, task_id: str, reason: str = "Operator Kill Switch") -> Task:
        """Immediately halt execution of a specific task."""
        task = await self.repo.get_task(task_id)
        if not task:
            raise KeyError(f"Task {task_id} not found.")

        if task.status in (
            TaskStatus.COMPLETE,
            TaskStatus.COMPLETED,
            TaskStatus.BLOCKED,
            TaskStatus.PARTIALLY_COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        ):
            return task

        # Cancel running asyncio task
        job = self._running_jobs.get(task_id)
        if job and not job.done():
            job.cancel()

        task.status = TaskStatus.CANCELLED
        task.updated_at = datetime.now(UTC)
        task.completed_at = datetime.now(UTC)
        await self.repo.update_task(task)

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

    async def activate_global_kill_switch(self, reason: str = "Emergency Kill Switch Activated") -> int:
        """Activate global kill switch and terminate all running tasks."""
        self.settings.kill_switch_active = True
        cancelled_count = 0
        for task_id in list(self._running_jobs.keys()):
            try:
                await self.cancel_task(task_id, reason=reason)
                cancelled_count += 1
            except Exception:
                pass

        self.audit_logger.log_event(
            entry_id=f"audit-global-kill-{int(datetime.now(UTC).timestamp())}",
            event_type="GLOBAL_KILL_SWITCH_ACTIVATED",
            actor="operator_kill_switch",
            action_type="KILL_SWITCH",
            scope_policy="GLOBAL",
            decision="HALTED",
            details={"reason": reason, "cancelled_tasks_count": cancelled_count},
        )
        return cancelled_count

    async def deactivate_global_kill_switch(self, operator: str = "operator") -> None:
        """Deactivate global kill switch."""
        self.settings.kill_switch_active = False
        self.audit_logger.log_event(
            entry_id=f"audit-global-unkill-{int(datetime.now(UTC).timestamp())}",
            event_type="GLOBAL_KILL_SWITCH_DEACTIVATED",
            actor=operator,
            action_type="KILL_SWITCH",
            scope_policy="GLOBAL",
            decision="RESTORED",
            details={},
        )

    async def get_task(self, task_id: str) -> Task | None:
        return await self.repo.get_task(task_id)

    async def list_tasks(self) -> list[Task]:
        return await self.repo.list_tasks()

    async def resolve_approval(self, approval: Any) -> bool:
        """Resume a paused task after its exact checkpointed action is approved or denied."""
        if approval.status not in {"APPROVED", "REJECTED"}:
            raise ValueError("Only a finalized approval can resolve a paused task.")

        task = await self.repo.get_task(approval.task_id)
        if task is None:
            return False
        current_job = self._running_jobs.get(task.id)
        if current_job is not None and not current_job.done():
            await asyncio.shield(current_job)
            task = await self.repo.get_task(approval.task_id)
        if task is None or task.status != TaskStatus.AWAITING_APPROVAL:
            return False

        checkpoint = await self.repo.get_checkpoint(task.id)
        checkpoint_version = checkpoint.get("version") if isinstance(checkpoint, dict) else None
        if not isinstance(checkpoint_version, int) or isinstance(checkpoint_version, bool) or checkpoint_version < 1:
            raise ValueError("The paused task checkpoint has an invalid version.")
        payload = checkpoint.get("payload") if isinstance(checkpoint, dict) else None
        if not isinstance(payload, dict):
            raise ValueError("The paused task has no valid checkpoint for approval resumption.")

        from sentinel.core.memory.working_memory import MemoryStore, TaskWorkingMemory, memory_store
        from sentinel.core.orchestrator.coordination import AgentCoordinator
        from sentinel.core.planner.heuristic import PlannedStep
        from sentinel.core.policy.engine import PolicyEngine

        try:
            memory = TaskWorkingMemory.model_validate(payload)
        except ValueError as exc:
            raise ValueError("The paused task checkpoint failed schema validation.") from exc
        if memory.in_flight_action is not None or not memory.deferred_plan_steps:
            raise ValueError("The paused task checkpoint is not safe to resume.")

        first_step = PlannedStep.model_validate(memory.deferred_plan_steps[0])
        action = first_step.action_request
        if (
            action is None
            or action.id != approval.action_id
            or action.action_type != approval.action_type
            or action.target_refs != approval.target_refs
            or approval.action_fingerprint != PolicyEngine._approval_action_fingerprint(action)
        ):
            raise ValueError("The finalized approval does not match the next checkpointed action.")

        if approval.status == "REJECTED":
            memory.deferred_plan_steps.pop(0)
            fingerprint = AgentCoordinator.action_fingerprint(first_step.agent_name, action)
            memory.attempted_action_fingerprints.add(fingerprint)
            memory.completed_actions.append(action.id)
            memory.action_outcomes[fingerprint] = {
                "status": "blocked",
                "detail": "Operator denied the action approval request.",
                "action_id": action.id,
                "agent": first_step.agent_name,
            }

        memory.state_flags.pop("awaiting_approval_id", None)
        await MemoryStore(checkpoint_repository=self.repo).persist_memory(memory)
        memory_store.clear_memory(task.id)
        task.status = TaskStatus.EXECUTING
        task.progress_percentage = min(task.progress_percentage, 85.0)
        await self.repo.update_task(task)
        self._start_task_job(task.id)
        self.audit_logger.log_event(
            entry_id=f"audit-approval-resume-{approval.approval_id}-{uuid.uuid4().hex[:8]}",
            event_type="TASK_APPROVAL_RESUMED",
            actor=approval.approved_by or "operator",
            action_type="ACTION_APPROVAL",
            scope_policy=task.scope.id,
            decision=approval.status,
            details={"task_id": task.id, "action_id": action.id},
        )
        return True

    async def recover_tasks_on_startup(self) -> int:
        """Resume checkpoint-safe tasks; fail closed when a side effect is ambiguous."""
        recovered_count = 0
        active_tasks = await self.repo.get_active_non_terminal_tasks()
        resumable_statuses = {
            TaskStatus.PLANNING,
            TaskStatus.EXECUTING,
            TaskStatus.REPORTING,
        }

        for task in active_tasks:
            if task.status == TaskStatus.AWAITING_APPROVAL:
                checkpoint = await self.repo.get_checkpoint(task.id)
                payload = checkpoint.get("payload") if isinstance(checkpoint, dict) else None
                state_flags = payload.get("state_flags") if isinstance(payload, dict) else None
                approval_id = state_flags.get("awaiting_approval_id") if isinstance(state_flags, dict) else None
                approval = None
                if isinstance(approval_id, str):
                    from sentinel.storage.repositories.factory import get_approval_repository

                    approval = await get_approval_repository().get_approval(approval_id)
                if approval is not None and approval.status in {"APPROVED", "REJECTED"}:
                    try:
                        if await self.resolve_approval(approval):
                            recovered_count += 1
                            self.audit_logger.log_event(
                                entry_id=f"audit-recovery-approval-{task.id}-{uuid.uuid4().hex[:8]}",
                                event_type="TASK_RECOVERY_RESUMED",
                                actor="system_startup",
                                action_type="CRASH_RECOVERY",
                                scope_policy=task.scope.id,
                                decision="FINALIZED_APPROVAL_RECOVERED",
                                details={"task_id": task.id, "approval_id": approval.approval_id},
                            )
                            continue
                    except ValueError as exc:
                        logger.error(
                            "Unable to resume finalized approval after restart",
                            extra={"task_id": task.id, "approval_id": approval.approval_id, "error": str(exc)},
                        )

                self.audit_logger.log_event(
                    entry_id=f"audit-recovery-awaiting-{task.id}-{uuid.uuid4().hex[:8]}",
                    event_type="TASK_RECOVERY_PAUSED",
                    actor="system_startup",
                    action_type="CRASH_RECOVERY",
                    scope_policy=task.scope.id,
                    decision="AWAITING_OPERATOR",
                    details={"task_id": task.id, "reason": "Explicit operator approval is still pending."},
                )
                continue

            if task.status == TaskStatus.SUBMITTED:
                self._start_task_job(task.id)
                recovered_count += 1
                self.audit_logger.log_event(
                    entry_id=f"audit-recovery-submit-{task.id}-{uuid.uuid4().hex[:8]}",
                    event_type="TASK_RECOVERY_RESUMED",
                    actor="system_startup",
                    action_type="CRASH_RECOVERY",
                    scope_policy=task.scope.id,
                    decision="RESUBMITTED",
                    details={"task_id": task.id, "reason": "Task was submitted before the previous process stopped."},
                )
                continue

            if task.status not in resumable_statuses:
                continue

            checkpoint = await self.repo.get_checkpoint(task.id)
            checkpoint_data = checkpoint if isinstance(checkpoint, dict) else {}
            version_value = checkpoint_data.get("version")
            checkpoint_version = (
                version_value
                if isinstance(version_value, int) and not isinstance(version_value, bool)
                else 0
            )
            payload = checkpoint_data.get("payload")
            failure_reason: str | None = None
            if checkpoint_version < 1:
                failure_reason = "Checkpoint version is missing or invalid."
            elif not isinstance(payload, dict):
                failure_reason = "No valid durable checkpoint exists for the interrupted task."
            elif payload.get("task_id") != task.id:
                failure_reason = "Checkpoint task identity does not match the persisted task."
            elif payload.get("in_flight_action") is not None:
                failure_reason = "Action outcome is ambiguous after restart; automatic replay is unsafe."
            else:
                from sentinel.core.memory.working_memory import TaskWorkingMemory

                try:
                    TaskWorkingMemory.model_validate(payload)
                except ValueError:
                    failure_reason = "Checkpoint data failed schema validation."

            if failure_reason is not None:
                task.status = TaskStatus.FAILED
                task.updated_at = datetime.now(UTC)
                task.completed_at = datetime.now(UTC)
                await self.repo.update_task(task)
                recovered_count += 1
                self.audit_logger.log_event(
                    entry_id=f"audit-recover-fail-{task.id}-{uuid.uuid4().hex[:8]}",
                    event_type="TASK_RECOVERY_FAILED",
                    actor="system_startup",
                    action_type="CRASH_RECOVERY",
                    scope_policy=task.scope.id,
                    decision="MARKED_FAILED",
                    details={"task_id": task.id, "reason": failure_reason},
                )
                continue

            from sentinel.core.memory.working_memory import memory_store

            memory_store.clear_memory(task.id)
            self._start_task_job(task.id)
            recovered_count += 1
            self.audit_logger.log_event(
                entry_id=f"audit-recovery-resume-{task.id}-{uuid.uuid4().hex[:8]}",
                event_type="TASK_RECOVERY_RESUMED",
                actor="system_startup",
                action_type="CRASH_RECOVERY",
                scope_policy=task.scope.id,
                decision="RESUMED_FROM_CHECKPOINT",
                details={
                    "task_id": task.id,
                    "checkpoint_version": checkpoint_version,
                    "deferred_steps": len(payload.get("deferred_plan_steps", [])) if isinstance(payload, dict) else 0,
                },
            )

        return recovered_count


# Lifecycle manager singleton
lifecycle_manager = TaskLifecycleManager()
