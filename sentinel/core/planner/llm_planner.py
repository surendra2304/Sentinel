"""LLMPlanner - BasePlanner implementation using the intelligence router's planning role."""

import uuid

from sentinel.core.agents.base import AgentRegistry
from sentinel.core.intelligence.interface import IntelligenceRequest, IntelligenceRole
from sentinel.core.memory.working_memory import TaskWorkingMemory
from sentinel.core.models import ActionRequest, ImpactLevel, Task
from sentinel.core.planner.heuristic import (
    BasePlanner,
    ExecutionPlan,
    HeuristicPlanner,
    PlannedStep,
)
from sentinel.logging.logger import get_logger

logger = get_logger("sentinel.planner.llm")


class LLMPlanner(BasePlanner):
    """Planning-role IntelligenceRouter-backed planner with HeuristicPlanner fallback."""

    def __init__(self) -> None:
        self._fallback = HeuristicPlanner()

    async def generate_plan(
        self,
        task: Task,
        memory: TaskWorkingMemory,
        registry: AgentRegistry,
    ) -> ExecutionPlan:
        from sentinel.core.intelligence.router import intelligence_router

        context = {
            "task_id": task.id,
            "objective": task.objective,
            "targets": [
                {"type": t.type.value, "value": t.value}
                for t in task.target_set.targets
            ],
            "state_flags": dict(memory.state_flags),
            "evidence_count": len(memory.evidence_ids),
            "agent_capabilities": [
                cap for agent in registry.list_agents() for cap in agent.capabilities
            ],
        }

        req = IntelligenceRequest(
            role=IntelligenceRole.PLANNING,
            context=context,
            request_id=f"plan-{task.id[:8]}",
        )
        result = await intelligence_router.request(req)

        if result.ok and result.structured_output.get("steps"):
            return self._deserialise_plan(task.id, result.structured_output)

        logger.warning(
            "LLMPlanner falling back to heuristic",
            extra={"task_id": task.id, "error": result.error},
        )
        return await self._fallback.generate_plan(task, memory, registry)

    @staticmethod
    def _deserialise_plan(task_id: str, output: dict) -> ExecutionPlan:
        plan = ExecutionPlan(
            task_id=task_id,
            reasoning_trace=output.get("reasoning_trace", []),
            is_terminal=bool(output.get("is_terminal", False)),
            confidence_is_sufficient=bool(output.get("confidence_is_sufficient", False)),
        )
        for raw_step in output.get("steps", []):
            plan.steps.append(
                PlannedStep(
                    step_id=f"step-{uuid.uuid4().hex[:8]}",
                    agent_name=raw_step.get("agent", "recon_agent"),
                    action_request=ActionRequest(
                        id=f"act-llm-{uuid.uuid4().hex[:8]}",
                        task_id=task_id,
                        agent=raw_step.get("agent", "recon_agent"),
                        action_type=raw_step.get("action_type", "recon.generic"),
                        target_refs=[],
                        expected_impact_level=ImpactLevel.LOW,
                    ),
                    phase=raw_step.get("phase", "UNKNOWN"),
                    justification=raw_step.get("justification", ""),
                )
            )
        return plan
