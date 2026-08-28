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

from datetime import UTC, datetime

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.agents.base import AgentRegistry, agent_registry
from sentinel.core.agents.network_agent import NetworkAgent
from sentinel.core.agents.recon_agent import ReconAgent
from sentinel.core.events.bus import emit_event
from sentinel.core.memory.working_memory import MemoryStore, memory_store
from sentinel.core.models import (
    AssetCriticality,
    EventType,
    Task,
    TaskStatus,
)
from sentinel.core.orchestrator.executor import ExecutionEngine, execution_engine
from sentinel.core.planner.heuristic import BasePlanner, ExecutionPlan, heuristic_planner
from sentinel.core.policy.engine import PolicyEngine, policy_engine
from sentinel.intelligence.risk.finding_engine import FindingEngine, finding_engine
from sentinel.intelligence.risk.risk_engine import RiskEngine, risk_engine
from sentinel.logging.logger import get_logger
from sentinel.storage.evidence.store import EvidenceStore, evidence_store

logger = get_logger("sentinel.orchestrator")

# Register reference and domain agents
agent_registry.register(ReconAgent())
agent_registry.register(NetworkAgent())


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
        self.audit = audit or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )

    async def run_task(self, task: Task, max_iterations: int = 10) -> Task:
        """Execute the full autonomous loop for a Task until completion or pause."""
        logger.info(f"Starting autonomous loop for Task '{task.id}'", extra={"task_id": task.id})
        task.status = TaskStatus.EXECUTING
        task.updated_at = datetime.now(UTC)
        task_mem = self.memory_store.get_memory(task.id)

        # Seed targets into memory
        for target in task.target_set.targets:
            task_mem.add_asset(target)

        iteration = 0

        while iteration < max_iterations:
            iteration += 1

            # 1. Check Kill-Switch / Task Status
            if task.status in (TaskStatus.CANCELLED, TaskStatus.FAILED):
                logger.warning(f"Task {task.id} halted with status {task.status.value}")
                break

            # 2. Planner: Generate Execution Plan
            plan: ExecutionPlan = await self.planner.generate_plan(task, task_mem, self.agents)
            task_mem.record_step(f"Iteration_{iteration}_Plan", {"steps_count": len(plan.steps), "trace": plan.reasoning_trace})

            # Check if planner reached terminal state
            if plan.is_terminal:
                task.status = TaskStatus.COMPLETE
                task.progress_percentage = 100.0
                task.completed_at = datetime.now(UTC)
                task.updated_at = datetime.now(UTC)
                break

            # 3. Process Planned Steps
            total_steps = len(plan.steps)
            for idx, step in enumerate(plan.steps):
                if task.status == TaskStatus.CANCELLED:
                    break

                # Emit Step Telemetry
                await emit_event(
                    event_type=EventType.TASK,
                    topic="task.step_started",
                    source="sentinel.orchestrator",
                    payload={"task_id": task.id, "step_id": step.step_id, "action": step.action_request.action_type, "phase": step.phase},
                    correlation_id=task.correlation_id,
                )

                # Execute action safely through policy & execution engine
                act_result = await self.executor.execute_action(step.action_request, task)

                # Check if approval required
                if act_result.error_info and "approval_id" in act_result.error_info:
                    task.status = TaskStatus.AWAITING_APPROVAL
                    task.updated_at = datetime.now(UTC)
                    logger.info(f"Task {task.id} paused awaiting approval {act_result.error_info['approval_id']}")
                    return task

                task_mem.completed_actions.append(step.action_request.id)

                # 4. Agent Analysis & Observation Generation
                agent = self.agents.get_agent(step.agent_name)
                if agent and act_result.success:
                    # Fetch latest evidence for this action
                    latest_evidence = self.evidence.query_evidence(task_id=task.id)
                    evidence_payloads = []
                    for e in latest_evidence:
                        _, raw_b = await self.evidence.get_evidence(e.id, actor="sentinel_agent")
                        evidence_payloads.append({
                            "id": e.id,
                            "target_ref": e.target_ref,
                            "source_tool": e.source_tool,
                            "raw_payload": raw_b.decode("utf-8", errors="replace"),
                        })

                    report = await agent.analyze(
                        task=task,
                        target_set=task.target_set,
                        scope=task.scope,
                        policy=task.policy,
                        available_evidence=evidence_payloads,
                        working_memory=task_mem.model_dump(),
                    )

                    # Ingest observations into Findings
                    for obs in report.observations:
                        try:
                            finding = await self.findings.ingest_observation(obs)
                            task_mem.findings.append(finding)

                            # Recalculate Risk
                            await self.risk.calculate_finding_risk(
                                finding=finding,
                                asset_criticality=AssetCriticality.HIGH,
                                is_internet_facing=True,
                            )
                        except Exception as err:
                            logger.error(f"Failed to ingest observation: {err}")

                # Update progress
                progress = min(95.0, round(((iteration - 1) / max_iterations + (idx + 1) / (total_steps * max_iterations)) * 100, 1))
                task.progress_percentage = progress
                task.updated_at = datetime.now(UTC)

        if task.status == TaskStatus.EXECUTING:
            task.status = TaskStatus.COMPLETE
            task.progress_percentage = 100.0
            task.completed_at = datetime.now(UTC)
            task.updated_at = datetime.now(UTC)

        await emit_event(
            event_type=EventType.TASK,
            topic="task.completed" if task.status == TaskStatus.COMPLETE else "task.halted",
            source="sentinel.orchestrator",
            payload={"task_id": task.id, "status": task.status.value, "progress": task.progress_percentage},
            correlation_id=task.correlation_id,
        )

        return task


# Global Autonomous Orchestrator Singleton
orchestrator = AutonomousOrchestrator()
