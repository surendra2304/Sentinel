"""Regression tests for bounded specialist routing and evidence-backed handoffs."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.agents.base import AgentRegistry, AgentReport, BaseAgent
from sentinel.core.memory.working_memory import MemoryStore, TaskWorkingMemory
from sentinel.core.models import (
    ActionRequest,
    ActionResult,
    AgentHandoff,
    Policy,
    Scope,
    Target,
    TargetSet,
    Task,
    TaskMode,
    TaskStatus,
    TimeWindow,
)
from sentinel.core.orchestrator.coordination import AgentCoordinator
from sentinel.core.orchestrator.orchestrator import AutonomousOrchestrator
from sentinel.core.planner.heuristic import ExecutionPlan, HeuristicPlanner, PlannedStep
from sentinel.core.policy.engine import PolicyDecisionType, PolicyEngine


class StubAgent(BaseAgent):
    def __init__(self, agent_name: str, capabilities: list[str], report_factory=None) -> None:
        self._name = agent_name
        self._capabilities = capabilities
        self._report_factory = report_factory
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def domain(self) -> str:
        return self._name.removesuffix("_agent")

    @property
    def capabilities(self) -> list[str]:
        return self._capabilities

    async def analyze(self, task, target_set, scope, policy, available_evidence, working_memory):
        self.calls += 1
        if self._report_factory is not None:
            return self._report_factory(task, available_evidence)
        return AgentReport(
            agent_name=self.name,
            task_id=task.id,
            evidence_refs=[item["id"] for item in available_evidence],
            reasoning="Peer review completed against supplied evidence.",
        )


def make_task(task_id: str = "coordination-task") -> Task:
    target = Target(id=f"{task_id}-target", type="domain", value="service.example.invalid")
    now = datetime.now(UTC)
    return Task(
        id=task_id,
        objective="Exercise local specialist coordination without external network activity.",
        target_set=TargetSet(id=f"{task_id}-targets", name="loopback-free fixture", targets=[target]),
        scope=Scope(
            id=f"{task_id}-scope",
            name="fixture scope",
            owner="coordination-test-operator",
            written_authorization_reference="CHG-COORDINATION-1001",
            allowed_targets=[target.value],
            allowed_methods=["discovery", "validation"],
            time_window=TimeWindow(
                start_time=now - timedelta(minutes=1),
                end_time=now + timedelta(hours=1),
            ),
        ),
        policy=Policy(
            id=f"{task_id}-policy",
            name="fixture policy",
            allowed_module_classes=["recon", "network"],
            allowed_action_classes=["*"],
            require_approval_for_offensive=False,
        ),
        mode=TaskMode.AUTHORIZED_ASSESSMENT,
        status=TaskStatus.EXECUTING,
        correlation_id=f"{task_id}-correlation",
    )


def make_action(task_id: str, *, agent: str = "network_agent", ports: list[int] | None = None) -> ActionRequest:
    return ActionRequest(
        id="agent-proposed-action",
        task_id=task_id,
        agent=agent,
        action_type="network.service_scan",
        target_refs=["service.example.invalid"],
        parameters={"ports": ports or [80]},
    )


def test_registry_exposes_only_declared_agent_capabilities():
    registry = AgentRegistry()
    registry.register(StubAgent("recon_agent", ["recon.ip_intel"]))
    registry.register(StubAgent("network_agent", ["network.service_scan"]))

    assert registry.supports_action("network_agent", "network.service_scan") is True
    assert registry.supports_action("recon_agent", "network.service_scan") is False
    assert [agent.name for agent in registry.agents_for_action("network.service_scan")] == ["network_agent"]


@pytest.mark.asyncio
async def test_planner_actions_match_registered_specialist_capabilities():
    task = make_task("specialist-routing")
    memory = TaskWorkingMemory(task_id=task.id)
    planner = HeuristicPlanner()
    registry = AgentRegistry()
    registry.register(StubAgent("recon_agent", ["dns.full_enum", "recon.subdomains", "recon.ip_intel", "recon.tech_fingerprint", "recon.osint"]))
    registry.register(StubAgent("web_security_agent", ["http.observe"]))
    registry.register(StubAgent("network_agent", ["network.service_scan"]))

    baseline = await planner.generate_plan(task, memory, registry)
    assert all(step.agent_name == "recon_agent" for step in baseline.steps)
    assert all(registry.supports_action(step.agent_name, step.action_request.action_type) for step in baseline.steps)

    memory.state_flags["phase_recon_baseline_done"] = True
    web_phase = await planner.generate_plan(task, memory, registry)
    http_step = next(step for step in web_phase.steps if step.action_request.action_type == "http.observe")
    fingerprint_step = next(step for step in web_phase.steps if step.action_request.action_type == "recon.tech_fingerprint")
    assert http_step.agent_name == "web_security_agent"
    assert fingerprint_step.agent_name == "recon_agent"
    assert all(step.action_request.agent == step.agent_name for step in web_phase.steps)

    memory.state_flags["phase_web_fingerprint_done"] = True
    network_phase = await planner.generate_plan(task, memory, registry)
    assert len(network_phase.steps) == 1
    assert network_phase.steps[0].agent_name == "network_agent"
    assert registry.supports_action("network_agent", "network.service_scan")


@pytest.mark.asyncio
async def test_coordinator_requires_in_scope_capability_and_evidence():
    task = make_task("handoff-validation")
    reporting_agent = StubAgent("recon_agent", ["recon.ip_intel"])
    network_agent = StubAgent("network_agent", ["network.service_scan"])
    registry = AgentRegistry()
    registry.register(reporting_agent)
    registry.register(network_agent)
    coordinator = AgentCoordinator(max_proposals_per_task=4)
    memory = TaskWorkingMemory(task_id=task.id)

    valid_report = AgentReport(
        agent_name=reporting_agent.name,
        task_id=task.id,
        evidence_refs=["evi-task-local"],
        actions_requested=[make_action(task.id)],
        recommended_next_step="Ask the network specialist to validate the observed service.",
    )
    decisions = coordinator.accept_report_actions(
        task=task,
        reporting_agent=reporting_agent,
        report=valid_report,
        available_evidence_ids={"evi-task-local"},
        memory=memory,
        iteration=1,
        registry=registry,
    )
    assert len(decisions) == 1 and decisions[0].accepted
    assert len(memory.pending_handoffs) == 1
    handoff = memory.pending_handoffs[0]
    assert isinstance(handoff, AgentHandoff)
    assert handoff.source_agent == "recon_agent"
    assert handoff.target_agent == "network_agent"
    assert handoff.evidence_refs == ["evi-task-local"]

    steps = coordinator.take_pending_steps(memory, limit=1)
    assert len(steps) == 1
    assert steps[0].phase == "AGENT_HANDOFF"
    assert steps[0].agent_name == "network_agent"
    assert steps[0].action_request.id.startswith("handoff-action-")
    assert memory.pending_handoffs == []

    out_of_scope = make_action(task.id)
    out_of_scope.target_refs = ["outside.example.invalid"]
    bad_report = AgentReport(
        agent_name="recon_agent",
        task_id=task.id,
        evidence_refs=["evi-task-local"],
        actions_requested=[out_of_scope],
    )
    rejected = coordinator.accept_report_actions(
        task=task,
        reporting_agent=reporting_agent,
        report=bad_report,
        available_evidence_ids={"evi-task-local"},
        memory=memory,
        iteration=2,
        registry=registry,
    )
    assert rejected[0].accepted is False
    assert rejected[0].reason == "target_out_of_scope"

    missing_evidence = AgentReport(
        agent_name="recon_agent",
        task_id=task.id,
        actions_requested=[make_action(task.id)],
    )
    rejected = coordinator.accept_report_actions(
        task=task,
        reporting_agent=reporting_agent,
        report=missing_evidence,
        available_evidence_ids={"evi-task-local"},
        memory=memory,
        iteration=3,
        registry=registry,
    )
    assert rejected[0].reason == "evidence_required"

    unsupported = make_action(task.id, agent="recon_agent")
    unsupported_report = AgentReport(
        agent_name="recon_agent",
        task_id=task.id,
        evidence_refs=["evi-task-local"],
        actions_requested=[unsupported],
    )
    rejected = coordinator.accept_report_actions(
        task=task,
        reporting_agent=reporting_agent,
        report=unsupported_report,
        available_evidence_ids={"evi-task-local"},
        memory=memory,
        iteration=4,
        registry=registry,
    )
    assert rejected[0].reason == "agent_capability_mismatch"


@pytest.mark.asyncio
async def test_agent_handoff_is_replanned_and_checked_by_policy(tmp_path):
    task = make_task("handoff-execution")
    evidence_item = SimpleNamespace(
        id="evi-handoff-1",
        target_ref="service.example.invalid",
        source_tool="fixture",
    )
    evidence_bytes = b"bounded local fixture evidence"
    registry = AgentRegistry()
    peer_action = make_action(task.id)

    def recon_report(received_task, evidence):
        return AgentReport(
            agent_name="recon_agent",
            task_id=received_task.id,
            evidence_refs=[item["id"] for item in evidence],
            actions_requested=[peer_action],
            recommended_next_step="Validate the observed service using the network specialist.",
        )

    recon_agent = StubAgent("recon_agent", ["recon.ip_intel"], recon_report)
    network_agent = StubAgent("network_agent", ["network.service_scan"])
    registry.register(recon_agent)
    registry.register(network_agent)

    class Planner:
        def __init__(self):
            self.calls = 0

        async def generate_plan(self, received_task, memory, agents):
            self.calls += 1
            if self.calls == 1:
                action = ActionRequest(
                    id="planned-recon-action",
                    task_id=received_task.id,
                    agent="recon_agent",
                    action_type="recon.ip_intel",
                    target_refs=["service.example.invalid"],
                )
                return ExecutionPlan(
                    task_id=received_task.id,
                    steps=[
                        PlannedStep(
                            agent_name="recon_agent",
                            action_request=action,
                            phase="RECON",
                            justification="Gather evidence for the specialist handoff.",
                        )
                    ],
                )
            return ExecutionPlan(task_id=received_task.id, is_terminal=True)

    class Evidence:
        async def query_evidence_async(self, *, task_id):
            assert task_id == task.id
            return [evidence_item]

        async def get_evidence(self, evidence_id, *, actor):
            assert evidence_id == evidence_item.id
            assert actor == "sentinel_agent"
            return evidence_item, evidence_bytes

    class PolicyCheckingExecutor:
        def __init__(self):
            self.policy = PolicyEngine(
                audit_logger=AuditLogger(str(tmp_path / "handoff-policy.jsonl"), signing_key="handoff-test-key")
            )
            self.actions: list[ActionRequest] = []
            self.decisions = []
            self.reasons: list[str] = []

        async def execute_action(self, action, received_task):
            self.actions.append(action.model_copy(deep=True))
            decision = await self.policy.evaluate_action(action, received_task)
            self.decisions.append(decision.decision)
            self.reasons.append(decision.reason)
            return ActionResult(
                action_id=action.id,
                task_id=received_task.id,
                success=decision.decision == PolicyDecisionType.ALLOW,
                output_summary="fixture action accepted by policy",
                duration_seconds=0.0,
                error_info=(None if decision.decision == PolicyDecisionType.ALLOW else {"policy_decision": "DENY"}),
            )

    executor = PolicyCheckingExecutor()
    orchestrator = AutonomousOrchestrator(
        planner=Planner(),
        executor=executor,
        policy=executor.policy,
        evidence=Evidence(),
        memory=MemoryStore(),
        agents=registry,
        audit=AuditLogger(str(tmp_path / "handoff-audit.jsonl"), signing_key="handoff-test-key"),
        coordinator=AgentCoordinator(max_proposals_per_task=2),
    )

    completed = await orchestrator.run_task(task, max_iterations=5)

    assert completed.status == TaskStatus.COMPLETED, (
        completed.status,
        executor.decisions,
        executor.reasons,
        [action.action_type for action in executor.actions],
    )
    assert [action.action_type for action in executor.actions] == [
        "recon.ip_intel",
        "network.service_scan",
    ]
    assert [action.agent for action in executor.actions] == ["recon_agent", "network_agent"]
    assert executor.decisions == [PolicyDecisionType.ALLOW, PolicyDecisionType.ALLOW]
    assert recon_agent.calls == 1
    assert network_agent.calls == 1
