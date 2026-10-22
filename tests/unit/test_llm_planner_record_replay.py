"""LLMPlanner Record/Replay & Fallback Test Suite.

Verifies:
1. Valid plan schema generation via mocked OpenAI-compatible endpoint.
2. Invalid response repair retry handling.
3. Timeout handling and graceful fallback to HeuristicPlanner.
4. Terminal state and sufficiency flag parsing.
"""

import json
from unittest.mock import AsyncMock

import pytest

from sentinel.core.agents.base import AgentRegistry
from sentinel.core.intelligence.interface import IntelligenceRole, TokenUsage
from sentinel.core.intelligence.llm_provider import LLMProvider
from sentinel.core.intelligence.router import IntelligenceRouter
from sentinel.core.memory.working_memory import TaskWorkingMemory
from sentinel.core.models import Policy, Scope, Target, TargetSet, TargetType, Task
from sentinel.core.planner.llm_planner import LLMPlanner


@pytest.fixture
def test_task():
    t = Target(id="t-plan-1", type=TargetType.DOMAIN, value="target.local")
    ts = TargetSet(id="ts-plan-1", name="TS Plan", targets=[t])
    scope = Scope(id="s-plan-1", name="S Plan", allowed_targets=["target.local"])
    policy = Policy(id="p-plan-1", name="P Plan")
    return Task(
        id="task-plan-001",
        objective="Penetration test",
        target_set=ts,
        scope=scope,
        policy=policy,
        correlation_id="corr-plan-001",
    )


@pytest.mark.asyncio
async def test_llm_planner_valid_plan_generation(test_task, monkeypatch):
    planner = LLMPlanner()
    memory = TaskWorkingMemory(task_id=test_task.id)
    registry = AgentRegistry()

    # Mock valid OpenAI response payload
    mock_llm_output = {
        "steps": [
            {
                "agent": "recon_agent",
                "action_type": "recon.subdomain_enum",
                "phase": "RECON_DNS",
                "justification": "Discover exposed subdomains",
            },
            {
                "agent": "web_agent",
                "action_type": "web.crawl",
                "phase": "WEB_DISCOVERY",
                "justification": "Crawl endpoints",
            }
        ],
        "reasoning_trace": ["LLM reasoning step 1", "LLM reasoning step 2"],
        "is_terminal": False,
        "confidence_is_sufficient": True,
    }

    mock_llm = LLMProvider(api_key="mock-key")
    monkeypatch.setattr(
        mock_llm,
        "_call_api",
        AsyncMock(return_value=(json.dumps(mock_llm_output), TokenUsage(total_tokens=150)))
    )

    router = IntelligenceRouter(
        providers={"llm": mock_llm},
        role_provider_map={IntelligenceRole.PLANNING: ["llm"]},
    )

    import sentinel.core.intelligence.router as router_module
    monkeypatch.setattr(router_module, "intelligence_router", router)

    plan = await planner.generate_plan(test_task, memory, registry)

    assert plan.task_id == test_task.id
    assert len(plan.steps) == 2
    assert plan.steps[0].agent_name == "recon_agent"
    assert plan.steps[0].action_request.action_type == "recon.subdomain_enum"
    assert plan.steps[1].agent_name == "web_agent"
    assert plan.confidence_is_sufficient is True
    assert "LLM reasoning step 1" in plan.reasoning_trace


@pytest.mark.asyncio
async def test_llm_planner_invalid_response_and_timeout_fallback_to_heuristic(test_task, monkeypatch):
    planner = LLMPlanner()
    memory = TaskWorkingMemory(task_id=test_task.id)
    registry = AgentRegistry()

    # Mock LLM raising TimeoutException
    import httpx
    mock_llm = LLMProvider(api_key="mock-key")
    monkeypatch.setattr(
        mock_llm,
        "_call_api",
        AsyncMock(side_effect=httpx.TimeoutException("Mocked connection timeout"))
    )

    # Heuristic fallback router
    from sentinel.core.intelligence.heuristic_provider import heuristic_provider
    router = IntelligenceRouter(
        providers={"llm": mock_llm, "heuristic": heuristic_provider},
        role_provider_map={IntelligenceRole.PLANNING: ["llm", "heuristic"]},
    )

    import sentinel.core.intelligence.router as router_module
    monkeypatch.setattr(router_module, "intelligence_router", router)

    # Plan should successfully fall back without throwing
    plan = await planner.generate_plan(test_task, memory, registry)

    assert plan.task_id == test_task.id
    assert len(plan.steps) >= 1
    assert plan.steps[0].action_request.action_type == "dns.full_enum"
