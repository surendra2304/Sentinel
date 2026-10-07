"""Bounded, evidence-backed specialist-agent handoff validation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel

from sentinel.core.agents.base import AgentRegistry, AgentReport, BaseAgent
from sentinel.core.memory.working_memory import TaskWorkingMemory
from sentinel.core.models import (
    ActionRequest,
    ActionStatus,
    AgentHandoff,
    Task,
)
from sentinel.core.planner.heuristic import PlannedStep
from sentinel.core.scope.resolver import ScopeResolver


class HandoffDecision(BaseModel):
    """Auditable result of validating one agent-proposed action."""

    accepted: bool
    source_agent: str
    target_agent: str | None = None
    action_type: str
    reason: str
    handoff_id: str | None = None


class AgentCoordinator:
    """Validate and queue typed agent requests without bypassing execution policy."""

    def __init__(self, max_proposals_per_task: int = 8) -> None:
        self.max_proposals_per_task = max_proposals_per_task

    def accept_report_actions(
        self,
        *,
        task: Task,
        reporting_agent: BaseAgent,
        report: AgentReport,
        available_evidence_ids: set[str],
        memory: TaskWorkingMemory,
        iteration: int,
        registry: AgentRegistry,
    ) -> list[HandoffDecision]:
        """Queue only in-scope, capability-matched, evidence-backed proposals."""
        decisions: list[HandoffDecision] = []
        if not report.actions_requested:
            return decisions

        identity_error: str | None = None
        if report.agent_name != reporting_agent.name:
            identity_error = "report_agent_mismatch"
        elif report.task_id != task.id:
            identity_error = "report_task_mismatch"

        cited_evidence = set(report.evidence_refs)
        if identity_error is None:
            if not cited_evidence:
                identity_error = "evidence_required"
            elif not cited_evidence.issubset(available_evidence_ids):
                identity_error = "unverified_evidence_reference"

        resolver = ScopeResolver(task.scope)
        for action in report.actions_requested:
            reason = identity_error
            target_agent = registry.get_agent(action.agent)

            if reason is None and action.task_id != task.id:
                reason = "action_task_mismatch"
            elif reason is None and target_agent is None:
                reason = "unregistered_target_agent"
            elif reason is None and not registry.supports_action(action.agent, action.action_type):
                reason = "agent_capability_mismatch"
            elif reason is None and not action.target_refs:
                reason = "target_required"
            elif reason is None:
                for target_ref in action.target_refs:
                    in_scope, _verdict, _explanation = resolver.is_target_in_scope(target_ref)
                    if not in_scope:
                        reason = "target_out_of_scope"
                        break

            if reason is None and len(memory.proposal_fingerprints) >= self.max_proposals_per_task:
                reason = "task_proposal_budget_exhausted"

            fingerprint: str | None = None
            proposal_key: str | None = None
            if reason is None:
                fingerprint = self.action_fingerprint(report.agent_name, action)
                proposal_key = self._proposal_key(action)
                prior = memory.proposal_keys.get(proposal_key)
                if prior == "CONFLICT":
                    reason = "conflicting_proposal_suppressed"
                elif prior is not None and prior != fingerprint:
                    # Do not execute either queued variant when peers disagree on
                    # parameters for the same specialist/action/target tuple.
                    memory.pending_handoffs = [
                        handoff
                        for handoff in memory.pending_handoffs
                        if self._proposal_key(handoff.action_request) != proposal_key
                    ]
                    memory.proposal_keys[proposal_key] = "CONFLICT"
                    reason = "conflicting_proposal_suppressed"
                elif fingerprint in memory.proposal_fingerprints:
                    reason = "duplicate_proposal"

            handoff_id: str | None = None
            if reason is None and fingerprint is not None and proposal_key is not None:
                request_data = action.model_dump(mode="python")
                request_data["id"] = f"handoff-action-{fingerprint[:20]}"
                request_data["status"] = ActionStatus.PENDING_APPROVAL
                normalized_action = ActionRequest.model_validate(request_data)
                justification = (
                    report.recommended_next_step
                    or report.reasoning
                    or f"{report.agent_name} proposed a follow-up based on task evidence."
                )
                handoff = AgentHandoff(
                    id=f"handoff-{fingerprint[:20]}",
                    task_id=task.id,
                    source_agent=report.agent_name,
                    target_agent=normalized_action.agent,
                    action_request=normalized_action,
                    evidence_refs=sorted(cited_evidence),
                    justification=justification[:512],
                    created_iteration=iteration,
                )
                memory.pending_handoffs.append(handoff)
                memory.proposal_fingerprints.add(fingerprint)
                memory.proposal_keys[proposal_key] = fingerprint
                handoff_id = handoff.id
                reason = "accepted"
                accepted = True
            else:
                accepted = False
                reason = reason or "rejected"

            decision = HandoffDecision(
                accepted=accepted,
                source_agent=report.agent_name,
                target_agent=action.agent,
                action_type=action.action_type,
                reason=reason,
                handoff_id=handoff_id,
            )
            decisions.append(decision)
            memory.handoff_trace.append(decision.model_dump(mode="json"))

        if len(memory.handoff_trace) > 256:
            del memory.handoff_trace[:-256]
        return decisions

    @staticmethod
    def take_pending_steps(
        memory: TaskWorkingMemory,
        limit: int,
    ) -> list[PlannedStep]:
        """Drain a bounded FIFO batch of validated handoffs into executable steps."""
        selected = memory.pending_handoffs[:limit]
        del memory.pending_handoffs[: len(selected)]
        return [
            PlannedStep(
                agent_name=handoff.target_agent,
                action_request=handoff.action_request,
                phase="AGENT_HANDOFF",
                justification=(
                    f"Evidence-backed handoff from {handoff.source_agent}; "
                    f"evidence={','.join(handoff.evidence_refs[:5])}; {handoff.justification}"
                )[:1024],
            )
            for handoff in selected
        ]

    @staticmethod
    def action_fingerprint(source_agent: str, action: ActionRequest) -> str:
        payload = action.model_dump(
            mode="json",
            exclude={"id", "created_at", "status"},
        )
        canonical = json.dumps(
            {"source_agent": source_agent, "action": payload},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _proposal_key(action: ActionRequest) -> str:
        payload: dict[str, Any] = {
            "agent": action.agent,
            "action_type": action.action_type,
            "target_refs": sorted(action.target_refs),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
