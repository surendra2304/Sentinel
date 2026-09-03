"""Sentinel ActionRouter — Central Security Choke Point.

Every action intent passes through this single mandatory gateway for policy,
approval, capability token verification, idempotency, quotas, execution, and audit.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from sentinel.core.auth.approvals import ApprovalManager
from sentinel.core.auth.capabilities import CapabilityIssuer
from sentinel.core.gateway.models import (
    ActionRequest,
    Decision,
    ExecutionResult,
    PolicyDecision,
)
from sentinel.storage.persistence.durable_store import SentinelPersistence


class ActionRouter:
    """Single security choke point for all tool/adapter execution."""

    def __init__(
        self,
        policy_evaluator: Callable[[ActionRequest], Coroutine[Any, Any, PolicyDecision]],
        audit_logger,
        store: SentinelPersistence,
        approval_manager: ApprovalManager | None = None,
        capability_issuer: CapabilityIssuer | None = None,
    ):
        self.policy_evaluator = policy_evaluator
        self.audit = audit_logger
        self.store = store
        self.approval_manager = approval_manager or ApprovalManager(store)
        self.capability_issuer = capability_issuer

    async def authorize(self, action: ActionRequest) -> PolicyDecision:
        # 1. If capability token present, verify it
        if action.capability_token and self.capability_issuer:
            self.capability_issuer.verify(
                action.capability_token,
                actor_id=action.actor.id,
                tenant_id=action.actor.tenant_id,
                action=action.action_type,
                resource=action.targets[0] if action.targets else "*",
            )

        # 2. Evaluate Policy
        decision = await self.policy_evaluator(action)
        self.audit.append(
            event_type="policy.decision",
            actor_id=action.actor.id,
            tenant_id=action.actor.tenant_id,
            action_id=action.id,
            payload={
                "decision": decision.decision.value,
                "reason": decision.reason,
                "fingerprint": decision.fingerprint,
                "approval_id": decision.approval_id,
            },
        )
        return decision

    async def execute_once(
        self,
        action: ActionRequest,
        executor: Callable[[ActionRequest], Coroutine[Any, Any, ExecutionResult]],
    ) -> ExecutionResult:
        # 1. Idempotency check
        if action.idempotency_key:
            cached = self.store.get_idempotency(action.idempotency_key)
            if cached:
                cached_fp, cached_res = cached
                if cached_fp != action.fingerprint():
                    raise PermissionError("idempotency key reused for a different action")
                return cached_res

        # 2. Authorize
        decision = await self.authorize(action)
        if decision.decision == Decision.DENY:
            return ExecutionResult(action.id, False, error=decision.reason)
        if decision.decision == Decision.REQUIRE_APPROVAL:
            return ExecutionResult(
                action.id, False, error=f"approval_required:{decision.approval_id}"
            )

        # 3. If action required approval, consume it atomically
        if action.requires_approval or decision.approval_id:
            self.approval_manager.consume(action)

        # 4. Execute controlled action
        result = await executor(action)

        # 5. Store idempotency result
        if action.idempotency_key:
            self.store.put_idempotency(action.idempotency_key, action.fingerprint(), result)

        # 6. Audit execution
        self.audit.append(
            event_type="action.executed",
            actor_id=action.actor.id,
            tenant_id=action.actor.tenant_id,
            action_id=action.id,
            payload={
                "success": result.success,
                "exit_code": result.exit_code,
                "error": result.error,
                "duration_ms": result.duration_ms,
            },
        )
        return result
