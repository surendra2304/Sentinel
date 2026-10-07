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

import hashlib
import json
import logging
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
    TaskMode,
)
from sentinel.core.scope.resolver import ScopeResolver

logger = logging.getLogger(__name__)

_IMPACT_ORDER = {
    ImpactLevel.NONE: 0,
    ImpactLevel.LOW: 1,
    ImpactLevel.MEDIUM: 2,
    ImpactLevel.HIGH: 3,
    ImpactLevel.CRITICAL: 4,
}

# Only actions with no direct probing of the assessed host are allowed in
# passive mode. The two mixed-mode adapters must be explicitly restricted to
# their passive data sources by the planner.
_PASSIVE_ACTIONS = frozenset({"dns.full_enum", "recon.subdomains", "recon.ip_intel"})
_PASSIVE_ONLY_ADAPTER_ACTIONS = frozenset({"dns.full_enum", "recon.subdomains"})


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
    action_fingerprint: str | None = None
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED, EXPIRED
    justification_needed: str
    justification_provided: str | None = None
    approved_by: str | None = None
    authorization_reference: str | None = None
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    decided_at: datetime | None = None
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + timedelta(hours=24))

    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at


class PolicyEngine:
    """Comprehensive, zero-trust Scope and Policy Validation Engine."""

    def __init__(self, audit_logger: AuditLogger | None = None, approval_repository: Any | None = None):
        self.settings = get_settings()
        self._approval_repository = approval_repository
        self.audit = audit_logger or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )
        self._action_rate_windows: dict[str, list[float]] = defaultdict(list)
        self._target_rate_windows: dict[str, list[float]] = defaultdict(list)
        self._approvals: dict[str, ApprovalRecord] = {}

    async def evaluate_action(
        self,
        action: ActionRequest,
        task: Task,
        scope: Scope | None = None,
        policy: Policy | None = None,
        actor: str = "agent",
    ) -> PolicyDecision:
        """Exhaustively validate an ActionRequest against all policy dimensions.
        Note: Any caller-provided advisory context (e.g. from FRIDAY) cannot
        override these hard policy boundaries.
        """
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

        allow_third_party_enrichment = action.parameters.get("allow_third_party_enrichment") is True
        authorized_for_external_enrichment = getattr(
            getattr(eff_scope, "authorization", None),
            "allow_third_party_enrichment",
            False,
        )
        if allow_third_party_enrichment and not authorized_for_external_enrichment:
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason="Third-party enrichment was requested but is not authorized by the scope.",
                actor=actor,
            )

        # -------------------------------------------------------------------
        # Dimension 2: Scope validity, impact ceiling, and task-mode boundary
        # -------------------------------------------------------------------
        time_window = getattr(eff_scope, "time_window", None)
        if time_window is not None and not time_window.is_active():
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason="Scope authorization is outside its active time window.",
                actor=actor,
            )

        maximum_impact = getattr(eff_scope, "maximum_impact", ImpactLevel.LOW)
        if _IMPACT_ORDER[action.expected_impact_level] > _IMPACT_ORDER[maximum_impact]:
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason=(
                    f"Action impact '{action.expected_impact_level.value}' exceeds "
                    f"scope maximum '{maximum_impact.value}'."
                ),
                actor=actor,
            )

        if task.mode == TaskMode.PASSIVE_RECON:
            is_passive = action.action_type in _PASSIVE_ACTIONS
            requires_passive_adapter_mode = action.action_type in _PASSIVE_ONLY_ADAPTER_ACTIONS
            passive_adapter_mode_enabled = action.parameters.get("passive_only") is True
            if not is_passive or (requires_passive_adapter_mode and not passive_adapter_mode_enabled):
                return self._record_and_return_decision(
                    action=action,
                    task=task,
                    decision_type=PolicyDecisionType.DENY,
                    reason=f"Action '{action.action_type}' is not permitted in passive reconnaissance mode.",
                    actor=actor,
                )

        # -------------------------------------------------------------------
        # Dimension 3: Target Scope Boundary Validation (Zero Tolerance)
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
        # Dimension 4: Module & Action Class Allowlists & Methods (Deny-by-default)
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

        # Method allowance in Scope
        allowed_methods = getattr(eff_scope, "allowed_methods", [])
        if allowed_methods:
            method_allowed = any(
                m in ("*", action.action_type, module_prefix)
                or (m.endswith(".*") and action.action_type.startswith(m[:-2]))
                or (m == "passive_recon" and module_prefix in ("recon", "dns", "osint", "cert"))
                or (m == "discovery" and module_prefix in ("recon", "network", "web", "api", "cloud", "intel"))
                or (m == "validation" and module_prefix in ("web", "api", "vulnerability", "cloud", "mobile", "network", "endpoint"))
                for m in allowed_methods
            )
            if not method_allowed:
                return self._record_and_return_decision(
                    action=action,
                    task=task,
                    decision_type=PolicyDecisionType.DENY,
                    reason=f"Action method '{action.action_type}' is not permitted by scope allowed_methods ({allowed_methods}).",
                    actor=actor,
                )

        # -------------------------------------------------------------------
        # Dimension 4: Intensity Limits
        # -------------------------------------------------------------------
        if action.parameters.get("intensity", 1) > eff_policy.max_intensity:
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason=f"Action intensity {action.parameters.get('intensity')} exceeds maximum allowed intensity ({eff_policy.max_intensity}).",
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
        is_offensive_action = any(
            k in action.action_type.lower()
            for k in ("exploit", "attack", "payload", "bruteforce", "takeover", "destructive")
        )

        needs_approval = (
            action.requires_approval
            or action.expected_impact_level in (ImpactLevel.HIGH, ImpactLevel.CRITICAL)
            or (eff_policy.require_approval_for_offensive and eff_scope.offensive_actions_enabled and is_offensive_action)
        )

        if needs_approval and not await self._consume_approved_action(action, task):
            approval = await self._create_approval_request(
                action,
                task,
                "High-impact / sensitive action requires operator sign-off.",
            )
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
        # Dimension 7: Exploitation Separation (Prohibited by Default)
        # -------------------------------------------------------------------
        if is_offensive_action:
            if not getattr(eff_scope, "offensive_actions_enabled", False):
                return self._record_and_return_decision(
                    action=action,
                    task=task,
                    decision_type=PolicyDecisionType.DENY,
                    reason=f"Exploitation prohibited by default: '{action.action_type}' requires explicit offensive_actions_enabled in scope.",
                    actor=actor,
                )
            if not any("exploit" in m.lower() or m == action.action_type for m in allowed_methods):
                return self._record_and_return_decision(
                    action=action,
                    task=task,
                    decision_type=PolicyDecisionType.DENY,
                    reason=f"Exploitation prohibited: method '{action.action_type}' is not listed in scope allowed_methods.",
                    actor=actor,
                )

        # -------------------------------------------------------------------
        # Dimension 8: Rate Limits (Task and Per-Target Sliding Windows)
        # -------------------------------------------------------------------
        # Check task rate limit (sliding window actions per minute)
        if not self._check_rate_limit(task.id, eff_policy.rate_limit_rps):
            return self._record_and_return_decision(
                action=action,
                task=task,
                decision_type=PolicyDecisionType.DENY,
                reason=f"Rate limit exceeded: Task {task.id} exceeded {eff_policy.rate_limit_rps} actions per minute limit.",
                actor=actor,
            )

        # Check per-target rate limit
        target_rpm = getattr(eff_scope, "rate_limit", eff_policy.rate_limit_rps)
        for target_ref in action.target_refs:
            if not self._check_target_rate_limit(target_ref, target_rpm):
                return self._record_and_return_decision(
                    action=action,
                    task=task,
                    decision_type=PolicyDecisionType.DENY,
                    reason=f"Rate limit exceeded: Target '{target_ref}' exceeded {target_rpm} actions per minute limit.",
                    actor=actor,
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

    def _check_target_rate_limit(self, target: str, limit_rpm: int) -> bool:
        now = time.time()
        window_start = now - 60.0
        norm = target.lower().strip()
        self._target_rate_windows[norm] = [
            t for t in self._target_rate_windows[norm] if t > window_start
        ]
        if len(self._target_rate_windows[norm]) >= limit_rpm:
            return False
        self._target_rate_windows[norm].append(now)
        return True

    @property
    def approval_repository(self) -> Any:
        if self._approval_repository is not None:
            return self._approval_repository
        from sentinel.storage.repositories.factory import get_approval_repository

        return get_approval_repository()

    async def _create_approval_request(
        self,
        action: ActionRequest,
        task: Task,
        justification: str,
    ) -> ApprovalRecord:
        app_id = f"appr-{uuid.uuid4().hex[:12]}"
        record = ApprovalRecord(
            approval_id=app_id,
            task_id=task.id,
            action_id=action.id,
            action_type=action.action_type,
            target_refs=action.target_refs,
            requested_by=action.agent,
            action_fingerprint=self._approval_action_fingerprint(action),
            justification_needed=justification,
        )
        await self.approval_repository.save_approval(record)
        self._approvals[app_id] = record
        return record

    async def _consume_approved_action(self, action: ActionRequest, task: Task) -> bool:
        """Consume an approval only for the exact task/action/targets/parameters once."""
        persisted = await self.approval_repository.list_approvals(
            task_id=task.id,
            status="APPROVED",
        )
        self._approvals.update({record.approval_id: record for record in persisted})
        candidates = [
            record
            for record in self._approvals.values()
            if record.task_id == task.id and record.status == "APPROVED"
        ]

        action_fingerprint = self._approval_action_fingerprint(action)
        for record in candidates:
            if (
                record.action_id != action.id
                or record.action_type != action.action_type
                or record.target_refs != action.target_refs
                or record.action_fingerprint != action_fingerprint
            ):
                continue
            if record.is_expired():
                record.status = "EXPIRED"
                await self.approval_repository.save_approval(record)
                continue
            if not (record.approved_by and record.justification_provided):
                continue

            record.status = "CONSUMED"
            record.decided_at = datetime.now(UTC)
            await self.approval_repository.save_approval(record)
            self.audit.log_event(
                entry_id=f"audit-appr-consumed-{record.approval_id}",
                event_type="ACTION_APPROVAL_CONSUMED",
                actor="sentinel_executor",
                action_type=record.action_type,
                scope_policy=record.task_id,
                decision="CONSUMED",
                details={"approval_id": record.approval_id, "action_id": record.action_id},
            )
            return True
        return False

    @staticmethod
    def _approval_action_fingerprint(action: ActionRequest) -> str:
        payload = action.model_dump(mode="json", exclude={"id", "created_at", "status"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get_pending_approvals(self, task_id: str | None = None) -> list[ApprovalRecord]:
        """List cached pending approvals; async service callers should use the repository method."""
        pending = []
        for record in list(self._approvals.values()):
            if record.status == "PENDING":
                if record.is_expired():
                    record.status = "EXPIRED"
                elif not task_id or record.task_id == task_id:
                    pending.append(record)
        return pending

    async def list_pending_approvals(self, task_id: str | None = None) -> list[ApprovalRecord]:
        """Load durable pending approvals and expire stale records."""
        records = await self.approval_repository.list_approvals(task_id=task_id, status="PENDING")
        pending: list[ApprovalRecord] = []
        for record in records:
            if record.is_expired():
                record.status = "EXPIRED"
                await self.approval_repository.save_approval(record)
            else:
                pending.append(record)
            self._approvals[record.approval_id] = record
        return pending

    async def decide_approval(
        self,
        approval_id: str,
        approve: bool,
        operator: str,
        justification: str,
        authorization_reference: str | None = None,
    ) -> ApprovalRecord:
        """Approve or deny a pending action approval request with full attribution."""
        record: ApprovalRecord | None = await self.approval_repository.get_approval(approval_id)
        if record is None:
            record = self._approvals.get(approval_id)
        if not record:
            raise KeyError(f"Approval record '{approval_id}' not found.")

        if record.status != "PENDING":
            raise ValueError(f"Approval '{approval_id}' is already finalized with status: {record.status}")
        if record.is_expired():
            record.status = "EXPIRED"
            await self.approval_repository.save_approval(record)
            self._approvals[approval_id] = record
            raise ValueError(f"Approval '{approval_id}' has expired.")
        if not operator.strip() or not justification.strip():
            raise ValueError("An operator identity and non-empty justification are required.")

        decided = record.model_copy(deep=True)
        decided.status = "APPROVED" if approve else "REJECTED"
        decided.approved_by = operator.strip()
        decided.authorization_reference = authorization_reference
        decided.justification_provided = justification.strip()
        decided.decided_at = datetime.now(UTC)

        decision_label = "APPROVED" if approve else "DENIED"
        self.audit.log_event(
            entry_id=f"audit-appr-{approval_id}",
            event_type=f"ACTION_APPROVAL_{decision_label}",
            actor=decided.approved_by,
            action_type=decided.action_type,
            scope_policy=decided.task_id,
            decision=decision_label,
            details={"approval_id": approval_id, "justification": decided.justification_provided},
        )
        await self.approval_repository.save_approval(decided)
        self._approvals[approval_id] = decided

        await emit_event(
            event_type=EventType.ACTION,
            topic="action.approved" if approve else "action.denied",
            source="sentinel.policy.approvals",
            payload={"approval_id": approval_id, "action_id": decided.action_id, "decision": decision_label},
            correlation_id=decided.task_id,
        )
        return decided

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
        # Learn defensive security constraints into Memora Experience memory
        if decision_type == PolicyDecisionType.DENY:
            try:
                from sentinel.memora_client import memora_client
                memora_client.learn_from_outcome(
                    agent_name="sentinel",
                    task_name=action.action_type,
                    status="failure",
                    error_log=f"Policy Block: {reason}. Targets: {','.join(action.target_refs)}",
                    actions_taken=f"action:{action.action_type}",
                    context=f"actor:{actor} task:{task.id}",
                    domain="security_defense"
                )
            except Exception as exc:
                logger.warning("Memora learning write failed for Sentinel policy denial (%s)", type(exc).__name__)

        return decision


# Global Policy Engine Singleton
policy_engine = PolicyEngine()
