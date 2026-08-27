"""Sentinel Action Execution Engine.

Coordinates the full action lifecycle:
1. ActionRequest submission
2. PolicyEngine validation (Zero-tolerance guardrails)
3. Approval gate interception
4. ToolAdapter selection and sandboxed execution
5. Output capture and Evidence artifact storage (SHA-256 hashed)
6. Event bus dispatch and ActionResult return
7. Resilient failure recovery (Transient retry with backoff)
"""

import asyncio
import time
import uuid
from datetime import UTC, datetime

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.events.bus import emit_event
from sentinel.core.models import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    EventType,
    Evidence,
    Task,
)
from sentinel.core.orchestrator.adapter import ToolAdapterRegistry, adapter_registry
from sentinel.core.policy.engine import PolicyDecisionType, PolicyEngine, policy_engine
from sentinel.integrations.scanners.dns_adapter import DNSAdapter
from sentinel.integrations.scanners.http_adapter import HTTPObserverAdapter
from sentinel.integrations.scanners.network_adapter import NetworkScannerAdapter
from sentinel.logging.logger import get_logger
from sentinel.storage.artifacts.storage import ArtifactStorage, get_artifact_storage

logger = get_logger("sentinel.executor")


class ExecutionEngine:
    """Production action execution orchestrator."""

    def __init__(
        self,
        registry: ToolAdapterRegistry | None = None,
        policy: PolicyEngine | None = None,
        storage: ArtifactStorage | None = None,
        audit: AuditLogger | None = None,
        max_global_concurrency: int = 25,
    ):
        self.registry = registry or adapter_registry
        self.policy = policy or policy_engine
        self.storage = storage or get_artifact_storage()
        self.settings = get_settings()
        self.audit = audit or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )
        self.concurrency_semaphore = asyncio.Semaphore(max_global_concurrency)

    async def execute_action(
        self,
        action: ActionRequest,
        task: Task,
        max_retries: int = 2,
    ) -> ActionResult:
        """Safely execute an ActionRequest through the full policy and tool pipeline."""
        start_time = time.time()

        # 1. Event: action.requested
        await emit_event(
            event_type=EventType.ACTION,
            topic="action.requested",
            source="sentinel.executor",
            payload={"action_id": action.id, "action_type": action.action_type, "task_id": task.id},
            correlation_id=task.correlation_id,
        )

        # 2. Evaluate Policy
        decision = await self.policy.evaluate_action(action, task)
        if decision.decision == PolicyDecisionType.DENY:
            action.status = ActionStatus.BLOCKED_BY_POLICY
            await emit_event(
                event_type=EventType.ALERT,
                topic="action.blocked",
                source="sentinel.policy",
                payload={"action_id": action.id, "reason": decision.reason},
                correlation_id=task.correlation_id,
            )
            return ActionResult(
                action_id=action.id,
                task_id=task.id,
                success=False,
                output_summary=f"BLOCKED_BY_POLICY: {decision.reason}",
                duration_seconds=round(time.time() - start_time, 3),
                error_info={"policy_decision": "DENY", "reason": decision.reason},
            )

        if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL:
            action.status = ActionStatus.PENDING_APPROVAL
            await emit_event(
                event_type=EventType.ACTION,
                topic="action.approval_requested",
                source="sentinel.policy",
                payload={"action_id": action.id, "approval_id": decision.approval_id, "reason": decision.reason},
                correlation_id=task.correlation_id,
            )
            return ActionResult(
                action_id=action.id,
                task_id=task.id,
                success=False,
                output_summary=f"REQUIRE_APPROVAL: Action placed in approval queue (Approval ID: {decision.approval_id})",
                duration_seconds=round(time.time() - start_time, 3),
                error_info={"approval_id": decision.approval_id},
            )

        # 3. Locate Adapter
        adapter = self.registry.get_adapter_for_action(action.action_type)
        if not adapter:
            action.status = ActionStatus.FAILED
            err_msg = f"No registered ToolAdapter capable of executing action_type '{action.action_type}'"
            await emit_event(
                event_type=EventType.ALERT,
                topic="action.failed",
                source="sentinel.executor",
                payload={"action_id": action.id, "error": err_msg},
                correlation_id=task.correlation_id,
            )
            return ActionResult(
                action_id=action.id,
                task_id=task.id,
                success=False,
                output_summary=err_msg,
                duration_seconds=round(time.time() - start_time, 3),
                error_info={"error": "ADAPTER_NOT_FOUND"},
            )

        # 4. Validate Adapter Parameters
        valid, param_err = adapter.validate_params(action)
        if not valid:
            action.status = ActionStatus.FAILED
            err_msg = f"Invalid parameters for {adapter.name}: {param_err}"
            return ActionResult(
                action_id=action.id,
                task_id=task.id,
                success=False,
                output_summary=err_msg,
                duration_seconds=round(time.time() - start_time, 3),
                error_info={"error": "INVALID_PARAMS", "detail": param_err},
            )

        # 5. Sandboxed Execution with Concurrency Gate & Retries
        action.status = ActionStatus.RUNNING
        raw_output_bytes: bytes = b""
        mime_type: str = "application/octet-stream"
        act_result: ActionResult | None = None

        for attempt in range(max_retries + 1):
            try:
                async with self.concurrency_semaphore:
                    act_result, raw_output_bytes, mime_type = await adapter.run(action)
                    if act_result.success:
                        break
            except Exception as e:
                logger.warning(
                    f"Action {action.id} attempt {attempt+1} failed with exception: {e}",
                    extra={"action_id": action.id, "attempt": attempt + 1},
                )
                if attempt == max_retries:
                    act_result = ActionResult(
                        action_id=action.id,
                        task_id=task.id,
                        success=False,
                        output_summary=f"Execution error on {adapter.name}: {e}",
                        duration_seconds=round(time.time() - start_time, 3),
                        error_info={"exception": str(e)},
                    )
                    raw_output_bytes = str(e).encode("utf-8")
                else:
                    await asyncio.sleep(0.5 * (2**attempt))  # Exponential backoff

        # 6. Capture Raw Output as Evidence Artifact
        target_ref = action.target_refs[0] if action.target_refs else "task_target"
        storage_key = f"evidence/{task.id}/{action.id}_{int(time.time())}.dat"
        storage_uri, sha256_hash = await self.storage.store_artifact(
            key=storage_key,
            data=raw_output_bytes,
            content_type=mime_type,
        )

        if act_result is not None:
            act_result.raw_output_uri = storage_uri

        evidence = Evidence(
            id=f"evi-{uuid.uuid4().hex[:12]}",
            task_id=task.id,
            target_ref=target_ref,
            source_agent=action.agent,
            source_module=action.action_type.split(".")[0],
            source_tool=adapter.name,
            timestamp=datetime.now(UTC),
            artifact_storage_key=storage_key,
            content_type=mime_type,
            sha256_hash=sha256_hash,
            collected_by="sentinel_executor",
            integrity_metadata={"storage_uri": storage_uri, "size_bytes": len(raw_output_bytes)},
            context_metadata={"action_id": action.id, "action_type": action.action_type},
        )

        # 7. Audit & Event Dispatch
        final_result = act_result if act_result is not None else ActionResult(
            action_id=action.id,
            task_id=task.id,
            success=False,
            output_summary="Unknown execution state",
            duration_seconds=round(time.time() - start_time, 3),
        )

        action.status = ActionStatus.COMPLETED if final_result.success else ActionStatus.FAILED

        self.audit.log_event(
            entry_id=f"audit-exec-{action.id}",
            event_type="ACTION_COMPLETED" if final_result.success else "ACTION_FAILED",
            actor=action.agent,
            target=target_ref,
            action_type=action.action_type,
            scope_policy=task.scope.id,
            decision="SUCCESS" if final_result.success else "FAILED",
            details={
                "evidence_id": evidence.id,
                "sha256": sha256_hash,
                "summary": final_result.output_summary,
                "duration_seconds": final_result.duration_seconds,
            },
        )

        # Emit evidence.collected and action.completed / action.failed
        await emit_event(
            event_type=EventType.EVIDENCE,
            topic="evidence.collected",
            source="sentinel.executor",
            payload={"evidence_id": evidence.id, "task_id": task.id, "sha256": sha256_hash},
            correlation_id=task.correlation_id,
        )

        event_topic = "action.completed" if final_result.success else "action.failed"
        await emit_event(
            event_type=EventType.ACTION,
            topic=event_topic,
            source="sentinel.executor",
            payload={"action_id": action.id, "success": final_result.success, "summary": final_result.output_summary},
            correlation_id=task.correlation_id,
        )

        return final_result


# Register reference adapters
adapter_registry.register(DNSAdapter())
adapter_registry.register(HTTPObserverAdapter())
adapter_registry.register(NetworkScannerAdapter())

# Global Execution Engine Singleton
execution_engine = ExecutionEngine()
