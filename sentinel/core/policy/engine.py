"""Scope & Policy Engine for Sentinel.

Evaluates every executable ActionRequest against all policy dimensions:
1. Target Allowlists & Exclusions (via ScopeResolver)
2. Allowed Module & Action Classes (Deny-by-default)
3. Rate & Intensity Limits (Actions/min, concurrency, tool intensity)
4. Credential-Handling Boundaries (Usage permission & redaction rules)
5. Human Approval Gates (Impact level & sensitive action types)
6. Kill-Switch (Immediate task-level and global halt)

All evaluations append immutable, tamper-evident cryptographic audit logs.
"""

import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.events.bus import emit_event
from sentinel.core.models import (
    ActionRequest,
    EventType,
    ImpactLevel,
    Policy,
    Scope,
    Task,
)
from sentinel.core.scope.resolver import ScopeResolver


class PolicyDecisionType(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PolicyDecision(BaseModel):
    """Structured decision output of the Policy Engine."""
    decision: PolicyDecisionType
    allowed: bool
    reason: str
    action_id: str
    task_id: str
    requires_approval: bool = False
    approval_id: str | None = None
    redacted_parameters: dict[str, Any] = Field(default_factory=dict)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApprovalRecord(BaseModel):
    """Persistent Human Approval Record."""
    approval_id: str
    task_id: str
    action_id: str
    action_type: str
    target_refs: list[str]
    requested_by: str
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED, EXPIRED
    justification_needed: str
    justification_provided: str | None = None
    approved_by: str | None = None
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    decided_at: datetime | None = None
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + timedelta(hours=24))

    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at


class PolicyEngine:
    """Comprehensive, zero-trust Scope and Policy Validation Engine."""

    def __init__(self, audit_logger: AuditLogger | None = None):
        self.settings = get_settings()
        self.audit = audit_logger or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )
        self._action_rate_windows: dict[str, list[float]] = defaultdict(list)
        self._approvals: dict[str, ApprovalRecord] = {}

    async def evaluate_action(
        self,
        action: ActionRequest,
        task: Task,
        scope: Scope | None = None,
        policy: Policy | None = None,
        actor: str = "agent",
    ) -> PolicyDecision:
        """Exhaustively validate an ActionRequest against all policy dimensions."""
        eff_scope = scope or task.scope
        eff_policy = policy or task.policy
        resolver = ScopeResolver(eff_scope)

        # -------------------------------------------------------------------
        # Dimension 1: Kill Switch Gates
        # -------------------------------------------------------------------
        if self.settings.kill_switch_active or eff_policy.kill_switch_active:
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason="Execution halted by Global or Task Kill Switch.",
                actor=actor,
            )

        # -------------------------------------------------------------------
        # Dimension 2: Target Scope Boundary Validation (Zero Tolerance)
        # -------------------------------------------------------------------
        for target_ref in action.target_refs:
            is_in_scope, verdict, explanation = resolver.is_target_in_scope(target_ref)
            if not is_in_scope:
                return self._record_and_return_decision(
                    action=action,
                    task=task,
                    decision_type=PolicyDecisionType.DENY,
                    reason=f"Target '{target_ref}' is out of authorized scope: {explanation}",
                    actor=actor,
                )

        # -------------------------------------------------------------------
        # Dimension 3: Module & Action Class Allowlists (Deny-by-default)
        # -------------------------------------------------------------------
        if eff_policy.allowed_action_classes:
            matched_action = any(
                self._matches_pattern(pattern, action.action_type)
                for pattern in eff_policy.allowed_action_classes
            )
            if not matched_action:
                return self._record_and_return_decision(
                    action=action,
                    task=task,
                    decision_type=PolicyDecisionType.DENY,
                    reason=f"Action type '{action.action_type}' is not in policy allowed_action_classes (Deny-by-default).",
                    actor=actor,
                )

        # Module class matching: e.g. "network" or "web"
        module_prefix = action.action_type.split(".")[0] if "." in action.action_type else action.action_type
        if eff_policy.allowed_module_classes and module_prefix not in eff_policy.allowed_module_classes:
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason=f"Module class '{module_prefix}' is disabled or not permitted by policy.",
                actor=actor,
            )

        # -------------------------------------------------------------------
        # Dimension 4: Rate & Intensity Limits
        # -------------------------------------------------------------------
        # Check task action intensity limit
        if action.parameters.get("intensity", 1) > eff_policy.max_intensity:
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason=f"Action intensity {action.parameters.get('intensity')} exceeds maximum allowed intensity ({eff_policy.max_intensity}).",
                actor=actor,
            )

        # Check rate limit (sliding window actions per minute)
        if not self._check_rate_limit(task.id, eff_policy.rate_limit_rps):
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason=f"Rate limit exceeded: Task {task.id} exceeded {eff_policy.rate_limit_rps} actions per minute limit.",
                actor=actor,
            )

        # -------------------------------------------------------------------
        # Dimension 5: Credential-Handling Boundaries & Redaction Rules
        # -------------------------------------------------------------------
        redacted_params = dict(action.parameters)
        cred_rules = eff_policy.credential_handling_rules
        if cred_rules.get("disallow_stored_credentials", False) and any(k in action.parameters for k in ["credentials", "password", "api_token"]):
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason="Credential policy violation: Stored credentials are forbidden for this task.",
                actor=actor,
            )

        # Redact sensitive values for logging
        for sensitive_key in ["password", "token", "secret", "private_key", "api_key"]:
            if sensitive_key in redacted_params:
                redacted_params[sensitive_key] = "********[REDACTED]********"

        # -------------------------------------------------------------------
        # Dimension 6: Human Approval Requirements
        # -------------------------------------------------------------------
        needs_approval = (
            action.requires_approval
            or action.expected_impact_level in (ImpactLevel.HIGH, ImpactLevel.CRITICAL)
            or (eff_policy.require_approval_for_offensive and eff_scope.offensive_actions_enabled)
        )

        if needs_approval:
            approval = self._create_approval_request(action, task, "High-impact / sensitive action requires operator sign-off.")
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.REQUIRE_APPROVAL,
                reason="Action requires explicit operator human approval before execution.",
                actor=actor,
                approval_id=approval.approval_id,
                redacted_params=redacted_params,
            )

        # -------------------------------------------------------------------
        # Decision: ALLOW
        # -------------------------------------------------------------------
        return self._record_and_return_decision(
            action=action,
            task=task,
            decision_type=PolicyDecisionType.ALLOW,
            reason="Action conforms to all policy and scope constraints.",
            actor=actor,
            redacted_params=redacted_params,
        )

    def _matches_pattern(self, pattern: str, action_type: str) -> bool:
        if pattern in ("*", action_type):
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return action_type.startswith(prefix)
        return False

    def _check_rate_limit(self, task_id: str, limit_rpm: int) -> bool:
        now = time.time()
        window_start = now - 60.0
        self._action_rate_windows[task_id] = [
            t for t in self._action_rate_windows[task_id] if t > window_start
        ]
        if len(self._action_rate_windows[task_id]) >= limit_rpm:
            return False
        self._action_rate_windows[task_id].append(now)
        return True

    def _create_approval_request(self, action: ActionRequest, task: Task, justification: str) -> ApprovalRecord:
        app_id = f"appr-{uuid.uuid4().hex[:12]}"
        record = ApprovalRecord(
            approval_id=app_id,
            task_id=task.id,
            action_id=action.id,
            action_type=action.action_type,
            target_refs=action.target_refs,
            requested_by=action.agent,
            justification_needed=justification,
        )
        self._approvals[app_id] = record
        return record

    def get_pending_approvals(self, task_id: str | None = None) -> list[ApprovalRecord]:
        """List active pending approvals with expiration pruning."""
        pending = []
        for rec in list(self._approvals.values()):
            if rec.status == "PENDING":
                if rec.is_expired():
                    rec.status = "EXPIRED"
                elif not task_id or rec.task_id == task_id:
                    pending.append(rec)
        return pending

    async def decide_approval(
        self,
        approval_id: str,
        approve: bool,
        operator: str,
        justification: str,
    ) -> ApprovalRecord:
        """Approve or deny a pending action approval request."""
        record = self._approvals.get(approval_id)
        if not record:
            raise KeyError(f"Approval record '{approval_id}' not found.")

        if record.status != "PENDING":
            raise ValueError(f"Approval '{approval_id}' is already finalized with status: {record.status}")

        if record.is_expired():
            record.status = "EXPIRED"
            raise ValueError(f"Approval '{approval_id}' has expired.")

        record.status = "APPROVED" if approve else "REJECTED"
        record.approved_by = operator
        record.justification_provided = justification
        record.decided_at = datetime.now(UTC)

        # Audit and emit event
        decision_label = "APPROVED" if approve else "DENIED"
        self.audit.log_event(
            entry_id=f"audit-appr-{approval_id}",
            event_type=f"ACTION_APPROVAL_{decision_label}",
            actor=operator,
            action_type=record.action_type,
            scope_policy=record.task_id,
            decision=decision_label,
            details={"approval_id": approval_id, "justification": justification},
        )

        topic = "action.approved" if approve else "action.denied"
        await emit_event(
            event_type=EventType.ACTION,
            topic=topic,
            source="sentinel.policy.approvals",
            payload={"approval_id": approval_id, "action_id": record.action_id, "decision": decision_label},
            correlation_id=record.task_id,
        )

        return record

    def _record_and_return_decision(
        self,
        action: ActionRequest,
        task: Task,
        decision_type: PolicyDecisionType,
        reason: str,
        actor: str,
        approval_id: str | None = None,
        redacted_params: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        allowed = (decision_type == PolicyDecisionType.ALLOW)
        decision = PolicyDecision(
            decision=decision_type,
            allowed=allowed,
            reason=reason,
            action_id=action.id,
            task_id=task.id,
            requires_approval=(decision_type == PolicyDecisionType.REQUIRE_APPROVAL),
            approval_id=approval_id,
            redacted_parameters=redacted_params or {},
        )

        # Write to tamper-evident cryptographic audit log
        self.audit.log_event(
            entry_id=f"audit-eval-{action.id}-{int(time.time()*1000)}",
            event_type="POLICY_EVALUATION",
            actor=actor,
            target=",".join(action.target_refs),
            action_type=action.action_type,
            scope_policy=task.scope.id,
            decision=decision_type.value,
            details={
                "reason": reason,
                "action_id": action.id,
                "task_id": task.id,
                "impact": action.expected_impact_level.value,
                "approval_id": approval_id,
                "parameters": redacted_params or {},
            },
        )

        return decision


# Global Policy Engine Singleton
policy_engine = PolicyEngine()
