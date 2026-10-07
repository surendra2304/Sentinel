"""Sentinel Autonomous Orchestrator.

Implements the autonomous execution loop:
1. Gather context & working memory
2. Generate execution plan via Planner
3. Check each planned action against PolicyEngine (No direct execution bypass)
4. Execute action through ExecutionEngine and store Evidence
5. Ingest observations via FindingEngine and recalculate Risk
6. Handle approvals, cancellations, and confidence-driven termination
7. Stream real-time progress events
"""

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.agents.api_agent import APISecurityAgent
from sentinel.core.agents.base import AgentRegistry, agent_registry
from sentinel.core.agents.cloud_agent import CloudAgent
from sentinel.core.agents.device_agents import EndpointAgent, MobileAgent, WirelessAgent
from sentinel.core.agents.dfir_agents import ForensicsAgent, IncidentResponseAgent
from sentinel.core.agents.intel_agents import ThreatIntelligenceAgent, VulnerabilityAgent
from sentinel.core.agents.network_agent import NetworkAgent
from sentinel.core.agents.recon_agent import ReconAgent
from sentinel.core.agents.security_intelligence_agent import SecurityIntelligenceAgent
from sentinel.core.agents.web_agent import WebSecurityAgent
from sentinel.core.events.bus import emit_event
from sentinel.core.memory.working_memory import MemoryStore, memory_store
from sentinel.core.models import (
    AssetCriticality,
    EventType,
    Task,
    TaskStatus,
)
from sentinel.core.orchestrator.coordination import AgentCoordinator
from sentinel.core.orchestrator.executor import ExecutionEngine, execution_engine
from sentinel.core.planner.heuristic import (
    BasePlanner,
    ExecutionPlan,
    PlannedStep,
    heuristic_planner,
)
from sentinel.core.policy.engine import PolicyEngine, policy_engine
from sentinel.intelligence.risk.finding_engine import FindingEngine, finding_engine
from sentinel.intelligence.risk.risk_engine import RiskEngine, risk_engine
from sentinel.logging.logger import get_logger
from sentinel.storage.evidence.store import EvidenceStore, evidence_store

logger = get_logger("sentinel.orchestrator")

# Register reference, domain, and intelligence agents
agent_registry.register(ReconAgent())
agent_registry.register(NetworkAgent())
agent_registry.register(WebSecurityAgent())
agent_registry.register(APISecurityAgent())
agent_registry.register(WirelessAgent())
agent_registry.register(MobileAgent())
agent_registry.register(EndpointAgent())
agent_registry.register(CloudAgent())
agent_registry.register(VulnerabilityAgent())
agent_registry.register(ThreatIntelligenceAgent())
agent_registry.register(ForensicsAgent())
agent_registry.register(IncidentResponseAgent())
agent_registry.register(SecurityIntelligenceAgent())


class AutonomousOrchestrator:
    """Master loop orchestrator managing autonomous task lifecycle."""

    def __init__(
        self,
        planner: BasePlanner | None = None,
        executor: ExecutionEngine | None = None,
        policy: PolicyEngine | None = None,
        findings: FindingEngine | None = None,
        risk: RiskEngine | None = None,
        evidence: EvidenceStore | None = None,
        memory: MemoryStore | None = None,
        agents: AgentRegistry | None = None,
        audit: AuditLogger | None = None,
        coordinator: AgentCoordinator | None = None,
    ):
        self.planner = planner or heuristic_planner
        self.executor = executor or execution_engine
        self.policy = policy or policy_engine
        self.findings = findings or finding_engine
        self.risk = risk or risk_engine
        self.evidence = evidence or evidence_store
        self.memory_store = memory or memory_store
        self.agents = agents or agent_registry
        self.settings = get_settings()
        self.coordinator = coordinator or AgentCoordinator(
            max_proposals_per_task=self.settings.max_agent_proposals_per_task,
        )
        self.audit = audit or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )

    async def run_task(self, task: Task, max_iterations: int = 10) -> Task:
        """Execute a bounded plan, persisting checkpoints around every side-effect boundary."""
        logger.info(f"Starting autonomous loop for Task '{task.id}'", extra={"task_id": task.id})
        task_mem = await self.memory_store.load_memory(task.id)
        if task_mem.in_flight_action is not None:
            raise RuntimeError(
                "Task has an unresolved in-flight action; automatic replay is refused to avoid duplicate side effects."
            )

        task.status = TaskStatus.EXECUTING
        task.updated_at = datetime.now(UTC)
        for target in task.target_set.targets:
            task_mem.add_asset(target)
        await self.memory_store.persist_memory(task_mem)

        successful_actions = [
            str(outcome.get("action_id", fingerprint))
            for fingerprint, outcome in task_mem.action_outcomes.items()
            if outcome.get("status") == "success"
        ]
        blocked_actions = [
            outcome
            for outcome in task_mem.action_outcomes.values()
            if outcome.get("status") == "blocked"
        ]
        failed_actions = [
            outcome
            for outcome in task_mem.action_outcomes.values()
            if outcome.get("status") in {"failed", "budget_exhausted"}
        ]

        iteration = 0
        terminal_plan_observed = bool(task_mem.state_flags.get("terminal_plan_observed", False))

        def record_outcome(step: Any, fingerprint: str, status: str, detail: str | None = None) -> None:
            action = step.action_request
            record: dict[str, Any] = {
                "action_id": action.id,
                "action_type": action.action_type,
                "agent": step.agent_name,
                "target": action.target_refs[0] if action.target_refs else "unknown",
                "status": status,
            }
            if detail:
                record["detail"] = detail[:512]
            task_mem.action_outcomes[fingerprint] = record
            task_mem.attempted_action_fingerprints.add(fingerprint)
            if status == "success":
                task_mem.completed_action_fingerprints.add(fingerprint)
            if action.id not in task_mem.completed_actions:
                task_mem.completed_actions.append(action.id)

        while iteration < max_iterations:
            iteration += 1
            task_mem.last_iteration += 1

            if self.settings.kill_switch_active or task.policy.kill_switch_active:
                task.status = TaskStatus.CANCELLED
                task.updated_at = datetime.now(UTC)
                task.completed_at = datetime.now(UTC)
                task_mem.record_step("Task_Halted", {"reason": "kill_switch"})
                await self.memory_store.persist_memory(task_mem)
                logger.warning(f"Task {task.id} halted immediately by kill switch.")
                break

            if task.status in (TaskStatus.CANCELLED, TaskStatus.FAILED):
                logger.warning(f"Task {task.id} halted with status {task.status.value}")
                break

            if (
                task_mem.state_flags.get("terminal_plan_observed") is True
                and not task_mem.deferred_plan_steps
                and not task_mem.pending_handoffs
            ):
                terminal_plan_observed = True
                break

            incoming_handoffs = self.coordinator.take_pending_steps(
                task_mem,
                limit=self.settings.max_plan_steps_per_iteration,
            )
            if incoming_handoffs:
                task_mem.deferred_plan_steps = [
                    step.model_dump(mode="json") for step in incoming_handoffs
                ] + task_mem.deferred_plan_steps
                task_mem.record_step(
                    "Agent_Handoffs_Scheduled",
                    {"count": len(incoming_handoffs)},
                )

            if task_mem.deferred_plan_steps:
                queued_steps = [
                    PlannedStep.model_validate(step)
                    for step in task_mem.deferred_plan_steps
                ]
            else:
                plan: ExecutionPlan = await self.planner.generate_plan(task, task_mem, self.agents)
                task_mem.record_step(
                    f"Iteration_{iteration}_Plan",
                    {"steps_count": len(plan.steps), "trace": plan.reasoning_trace},
                )
                if plan.is_terminal:
                    terminal_plan_observed = True
                    task_mem.state_flags["terminal_plan_observed"] = True
                    await self.memory_store.persist_memory(task_mem)
                    break
                if not plan.steps:
                    task_mem.record_step(
                        "Planner_Produced_No_Actions",
                        {"iteration": iteration},
                    )
                    task.status = TaskStatus.FAILED
                    failed_actions.append({
                        "action_id": "",
                        "action_type": "planner.generate_plan",
                        "agent": "planner",
                        "target": "unknown",
                        "status": "failed",
                        "detail": "Planner returned a non-terminal plan without steps.",
                    })
                    await self.memory_store.persist_memory(task_mem)
                    break
                # Persist the complete queue before executing any step. The planner's
                # phase flags may already have advanced, so the serialized queue is
                # the source of truth if the process stops before the first action.
                task_mem.deferred_plan_steps = [
                    step.model_dump(mode="json") for step in plan.steps
                ]
                queued_steps = list(plan.steps)

            batch_size = self.settings.max_plan_steps_per_iteration
            batch = queued_steps[:batch_size]
            task_mem.deferred_plan_steps = [
                step.model_dump(mode="json") for step in queued_steps[batch_size:]
            ]
            await self.memory_store.persist_memory(task_mem)

            total_steps = len(batch)
            for idx, step in enumerate(batch):
                if task.status == TaskStatus.CANCELLED or self.settings.kill_switch_active:
                    task.status = TaskStatus.CANCELLED
                    task.completed_at = datetime.now(UTC)
                    task_mem.record_step("Task_Halted", {"reason": "kill_switch"})
                    await self.memory_store.persist_memory(task_mem)
                    break

                action = step.action_request
                fingerprint = self.coordinator.action_fingerprint(step.agent_name, action)
                if fingerprint in task_mem.attempted_action_fingerprints:
                    task_mem.record_step(
                        "Duplicate_Action_Skipped",
                        {"agent": step.agent_name, "action_type": action.action_type},
                    )
                    await self.memory_store.persist_memory(task_mem)
                    continue

                target_ref = action.target_refs[0] if action.target_refs else None
                agent_actions = task_mem.agent_action_counts.get(step.agent_name, 0)
                if agent_actions >= self.settings.max_actions_per_agent_per_task:
                    detail = "Per-agent task action budget exhausted."
                    failed_actions.append({
                        "action_id": action.id,
                        "action_type": action.action_type,
                        "agent": step.agent_name,
                        "target": target_ref or "unknown",
                        "status": "budget_exhausted",
                        "detail": detail,
                    })
                    record_outcome(step, fingerprint, "budget_exhausted", detail)
                    task_mem.record_step(
                        "Agent_Action_Budget_Exceeded",
                        {"agent": step.agent_name, "action_type": action.action_type},
                    )
                    await self.memory_store.persist_memory(task_mem)
                    continue

                task_mem.agent_action_counts[step.agent_name] = agent_actions + 1
                task_mem.in_flight_action = {
                    "fingerprint": fingerprint,
                    "step": step.model_dump(mode="json"),
                    "started_at": datetime.now(UTC).isoformat(),
                }
                # This durable marker is written before the executor can contact a
                # target. Startup recovery will never replay an ambiguous action.
                await self.memory_store.persist_memory(task_mem)

                await emit_event(
                    event_type=EventType.TASK,
                    topic="task.step_started",
                    source="sentinel.orchestrator",
                    payload={
                        "task_id": task.id,
                        "step_id": step.step_id,
                        "action": action.action_type,
                        "phase": step.phase,
                        "target": target_ref,
                        "progress": task.progress_percentage,
                    },
                    correlation_id=task.correlation_id,
                )

                act_result = await self.executor.execute_action(action, task)

                if act_result.error_info and "approval_id" in act_result.error_info:
                    task.status = TaskStatus.AWAITING_APPROVAL
                    task.updated_at = datetime.now(UTC)
                    task_mem.in_flight_action = None
                    task_mem.deferred_plan_steps.insert(0, step.model_dump(mode="json"))
                    task_mem.state_flags["awaiting_approval_id"] = act_result.error_info["approval_id"]
                    task_mem.record_step(
                        "Action_Awaiting_Approval",
                        {"action_id": action.id, "approval_id": act_result.error_info["approval_id"]},
                    )
                    await self.memory_store.persist_memory(task_mem)
                    logger.info(f"Task {task.id} paused awaiting approval {act_result.error_info['approval_id']}")
                    return task

                if act_result.error_info and act_result.error_info.get("policy_decision") == "DENY":
                    detail = str(act_result.error_info.get("reason", "Denied by policy"))
                    blocked_actions.append({
                        "action_id": action.id,
                        "action_type": action.action_type,
                        "agent": step.agent_name,
                        "target": target_ref or "unknown",
                        "status": "blocked",
                        "detail": detail,
                    })
                    record_outcome(step, fingerprint, "blocked", detail)
                elif act_result.success:
                    successful_actions.append(action.id)
                    record_outcome(step, fingerprint, "success")
                else:
                    detail = act_result.output_summary
                    failed_actions.append({
                        "action_id": action.id,
                        "action_type": action.action_type,
                        "agent": step.agent_name,
                        "target": target_ref or "unknown",
                        "status": "failed",
                        "detail": detail,
                    })
                    record_outcome(step, fingerprint, "failed", detail)

                task_mem.in_flight_action = None
                task_mem.state_flags.pop("awaiting_approval_id", None)
                await self.memory_store.persist_memory(task_mem)

                agent = self.agents.get_agent(step.agent_name)
                if agent and act_result.success:
                    latest_evidence = await self.evidence.query_evidence_async(task_id=task.id)
                    evidence_payloads: list[dict[str, Any]] = []
                    for evidence_item in latest_evidence:
                        _, raw_bytes = await self.evidence.get_evidence(
                            evidence_item.id,
                            actor="sentinel_agent",
                        )
                        evidence_payloads.append({
                            "id": evidence_item.id,
                            "target_ref": evidence_item.target_ref,
                            "source_tool": evidence_item.source_tool,
                            "raw_payload": raw_bytes.decode("utf-8", errors="replace"),
                        })
                        if evidence_item.id not in task_mem.evidence_ids:
                            task_mem.evidence_ids.append(evidence_item.id)

                    try:
                        report = await asyncio.wait_for(
                            agent.analyze(
                                task=task,
                                target_set=task.target_set,
                                scope=task.scope,
                                policy=task.policy,
                                available_evidence=evidence_payloads,
                                working_memory=task_mem.model_dump(mode="json"),
                            ),
                            timeout=self.settings.max_agent_analysis_seconds,
                        )
                    except TimeoutError:
                        task_mem.record_step(
                            "Agent_Analysis_Timeout",
                            {"agent": agent.name, "timeout_seconds": self.settings.max_agent_analysis_seconds},
                        )
                        logger.warning(
                            "Specialist agent analysis timed out",
                            extra={"task_id": task.id, "agent": agent.name},
                        )
                        report = None

                    if report is not None and (report.agent_name != agent.name or report.task_id != task.id):
                        task_mem.record_step(
                            "Agent_Report_Rejected",
                            {"expected_agent": agent.name, "expected_task_id": task.id},
                        )
                        logger.error(
                            "Specialist agent returned a mismatched report identity",
                            extra={"task_id": task.id},
                        )
                        report = None

                    if report is not None:
                        valid_evidence_ids = {item["id"] for item in evidence_payloads}
                        for observation in report.observations:
                            if (
                                observation.task_id != task.id
                                or not observation.evidence_refs
                                or not set(observation.evidence_refs).issubset(valid_evidence_ids)
                            ):
                                task_mem.record_step(
                                    "Agent_Observation_Rejected",
                                    {"agent": agent.name, "reason": "task_or_evidence_reference_mismatch"},
                                )
                                continue
                            try:
                                finding = await self.findings.ingest_observation(observation)
                                if not any(existing.id == finding.id for existing in task_mem.findings):
                                    task_mem.findings.append(finding)
                                await self.risk.calculate_finding_risk(
                                    finding=finding,
                                    asset_criticality=AssetCriticality.HIGH,
                                    is_internet_facing=True,
                                )
                            except Exception as err:
                                logger.error(f"Failed to ingest observation: {err}")

                        decisions = self.coordinator.accept_report_actions(
                            task=task,
                            reporting_agent=agent,
                            report=report,
                            available_evidence_ids=valid_evidence_ids,
                            memory=task_mem,
                            iteration=iteration,
                            registry=self.agents,
                        )
                        for decision in decisions:
                            handoff_event_id = decision.handoff_id or f"rejected-{uuid.uuid4().hex}"
                            self.audit.log_event(
                                entry_id=f"audit-{handoff_event_id}",
                                event_type=("AGENT_HANDOFF_ACCEPTED" if decision.accepted else "AGENT_HANDOFF_REJECTED"),
                                actor=decision.source_agent,
                                action_type=decision.action_type,
                                scope_policy=task.scope.id,
                                decision="QUEUED" if decision.accepted else "REJECTED",
                                details=decision.model_dump(mode="json"),
                            )
                            await emit_event(
                                event_type=EventType.ACTION,
                                topic="agent.handoff_queued" if decision.accepted else "agent.handoff_rejected",
                                source="sentinel.orchestrator",
                                payload={
                                    "task_id": task.id,
                                    "source_agent": decision.source_agent,
                                    "target_agent": decision.target_agent,
                                    "action_type": decision.action_type,
                                    "reason": decision.reason,
                                },
                                correlation_id=task.correlation_id,
                            )

                progress = min(
                    95.0,
                    round(
                        ((iteration - 1) / max_iterations + (idx + 1) / (total_steps * max_iterations))
                        * 100,
                        1,
                    ),
                )
                task.progress_percentage = progress
                task.updated_at = datetime.now(UTC)
                await self.memory_store.persist_memory(task_mem)

        incomplete = bool(task_mem.deferred_plan_steps or task_mem.pending_handoffs) or not terminal_plan_observed
        if task.status not in (TaskStatus.CANCELLED, TaskStatus.AWAITING_APPROVAL, TaskStatus.FAILED):
            if incomplete:
                task.status = TaskStatus.PARTIALLY_COMPLETED
                task_mem.record_step(
                    "Iteration_Budget_Exhausted",
                    {
                        "max_iterations": max_iterations,
                        "deferred_steps": len(task_mem.deferred_plan_steps),
                        "pending_handoffs": len(task_mem.pending_handoffs),
                    },
                )
                task.progress_percentage = min(task.progress_percentage, 95.0)
            elif blocked_actions and not successful_actions:
                task.status = TaskStatus.BLOCKED
                task.progress_percentage = 100.0
            elif blocked_actions or failed_actions:
                task.status = TaskStatus.PARTIALLY_COMPLETED if successful_actions else TaskStatus.FAILED
                task.progress_percentage = 100.0
            else:
                task.status = TaskStatus.COMPLETED
                task.progress_percentage = 100.0

            task.completed_at = datetime.now(UTC)
            task.updated_at = datetime.now(UTC)
            await self.memory_store.persist_memory(task_mem)

        await emit_event(
            event_type=EventType.TASK,
            topic="task.completed" if task.status in (TaskStatus.COMPLETE, TaskStatus.COMPLETED) else "task.halted",
            source="sentinel.orchestrator",
            payload={
                "task_id": task.id,
                "status": task.status.value,
                "progress": task.progress_percentage,
                "blocked_actions_count": len(blocked_actions),
                "successful_actions_count": len(successful_actions),
                "failed_actions_count": len(failed_actions),
            },
            correlation_id=task.correlation_id,
        )
        return task



# Global Autonomous Orchestrator Singleton
orchestrator = AutonomousOrchestrator()
