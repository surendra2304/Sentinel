"""Regression tests for scope boundaries, passive-mode gates, and redirect safety."""

import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.agents.base import AgentRegistry
from sentinel.core.memory.working_memory import TaskWorkingMemory
from sentinel.core.models import (
    ActionRequest,
    ImpactLevel,
    Policy,
    Scope,
    Target,
    TargetSet,
    TargetType,
    Task,
    TaskMode,
    TimeWindow,
)
from sentinel.core.planner.heuristic import HeuristicPlanner
from sentinel.core.policy.engine import PolicyDecisionType, PolicyEngine
from sentinel.core.scope.resolver import ScopeResolver
from sentinel.integrations.scanners.http_adapter import HTTPObserverAdapter


def test_cidr_target_must_be_contained_by_authorized_network():
    narrow_scope = Scope(id="cidr-narrow", name="narrow", allowed_targets=["192.168.0.0/24"])
    resolver = ScopeResolver(narrow_scope)

    assert resolver.is_target_in_scope("192.168.0.0/16")[0] is False
    assert resolver.is_target_in_scope("192.168.0.0/24")[0] is True


def test_ipv6_cidr_containment_and_mixed_address_families():
    resolver = ScopeResolver(Scope(id="ipv6-cidr", name="ipv6", allowed_targets=["2001:db8::/32"]))

    assert resolver.is_target_in_scope("2001:db8:1::/48")[0] is True
    assert resolver.is_target_in_scope("2001:db9::/32")[0] is False
    assert resolver.is_target_in_scope("192.0.2.0/24")[0] is False


def test_url_scope_uses_scheme_port_and_normalized_path_segments():
    resolver = ScopeResolver(
        Scope(id="url-scope", name="url", allowed_targets=["https://authorized.invalid/api"])
    )

    assert resolver.is_target_in_scope("https://authorized.invalid/api")[0] is True
    assert resolver.is_target_in_scope("https://authorized.invalid/api/v2")[0] is True
    assert resolver.is_target_in_scope("https://authorized.invalid/apix")[0] is False
    assert resolver.is_target_in_scope("https://authorized.invalid/api/../admin")[0] is False
    assert resolver.is_target_in_scope("http://authorized.invalid/api")[0] is False
    assert resolver.is_target_in_scope("https://authorized.invalid:8443/api")[0] is False

    domain_resolver = ScopeResolver(
        Scope(id="domain-scope", name="domain", allowed_targets=["authorized.invalid"])
    )
    assert domain_resolver.is_target_in_scope("https://authorized.invalid/api")[0] is True
    assert domain_resolver.is_target_in_scope("https://authorized.invalid:8443/api")[0] is False


def _make_policy_task(scope: Scope, mode: TaskMode = TaskMode.ASSESSMENT) -> Task:
    target = Target(id="scope-target", type=TargetType.DOMAIN, value="authorized.invalid")
    return Task(
        id=f"task-{scope.id}",
        objective="Scope enforcement regression",
        target_set=TargetSet(id=f"targets-{scope.id}", name="targets", targets=[target]),
        scope=scope,
        policy=Policy(id=f"policy-{scope.id}", name="test", allowed_action_classes=["*"]),
        mode=mode,
        correlation_id=f"correlation-{scope.id}",
    )


@pytest.mark.asyncio
async def test_policy_denies_expired_scope_and_impact_above_ceiling(tmp_path):
    now = datetime.now(UTC)
    expired_scope = Scope(
        id="expired",
        name="expired",
        allowed_targets=["authorized.invalid"],
        allowed_methods=["discovery"],
        time_window=TimeWindow(start_time=now - timedelta(days=2), end_time=now - timedelta(days=1)),
        maximum_impact=ImpactLevel.CRITICAL,
    )
    impact_scope = Scope(
        id="low-impact",
        name="low impact",
        allowed_targets=["authorized.invalid"],
        allowed_methods=["discovery"],
        time_window=TimeWindow(start_time=now - timedelta(minutes=1), end_time=now + timedelta(minutes=5)),
        maximum_impact=ImpactLevel.LOW,
    )
    engine = PolicyEngine(
        audit_logger=AuditLogger(str(tmp_path / "audit.jsonl"), signing_key="scope-policy-test-key")
    )

    expired_task = _make_policy_task(expired_scope)
    expired_action = ActionRequest(
        id="expired-action",
        task_id=expired_task.id,
        agent="network_agent",
        action_type="network.service_scan",
        target_refs=["authorized.invalid"],
        expected_impact_level=ImpactLevel.LOW,
    )
    expired_decision = await engine.evaluate_action(expired_action, expired_task)
    assert expired_decision.decision == PolicyDecisionType.DENY
    assert "time window" in expired_decision.reason.lower()

    impact_task = _make_policy_task(impact_scope)
    impact_action = ActionRequest(
        id="impact-action",
        task_id=impact_task.id,
        agent="network_agent",
        action_type="network.service_scan",
        target_refs=["authorized.invalid"],
        expected_impact_level=ImpactLevel.MEDIUM,
    )
    impact_decision = await engine.evaluate_action(impact_action, impact_task)
    assert impact_decision.decision == PolicyDecisionType.DENY
    assert "exceeds scope maximum" in impact_decision.reason.lower()


@pytest.mark.asyncio
async def test_discovery_scope_allows_http_observation_but_passive_mode_still_denies_it(tmp_path):
    now = datetime.now(UTC)
    target_url = "http://127.0.0.1:8000"
    scope = Scope(
        id="http-discovery",
        name="HTTP discovery",
        allowed_targets=[target_url, "127.0.0.1"],
        allowed_methods=["discovery"],
        time_window=TimeWindow(start_time=now - timedelta(minutes=1), end_time=now + timedelta(minutes=5)),
        maximum_impact=ImpactLevel.LOW,
    )
    engine = PolicyEngine(
        audit_logger=AuditLogger(str(tmp_path / "http-discovery.jsonl"), signing_key="http-discovery-test-key")
    )
    active_task = _make_policy_task(scope)
    action = ActionRequest(
        id="http-observe-discovery",
        task_id=active_task.id,
        agent="web_security_agent",
        action_type="http.observe",
        target_refs=[target_url],
        expected_impact_level=ImpactLevel.LOW,
    )

    decision = await engine.evaluate_action(action, active_task)
    assert decision.decision == PolicyDecisionType.ALLOW

    passive_task = _make_policy_task(scope, mode=TaskMode.PASSIVE_RECON)
    passive_action = action.model_copy(update={"task_id": passive_task.id})
    passive_decision = await engine.evaluate_action(passive_action, passive_task)
    assert passive_decision.decision == PolicyDecisionType.DENY
    assert "not permitted in passive reconnaissance mode" in passive_decision.reason.lower()


@pytest.mark.asyncio
async def test_passive_mode_only_allows_explicit_passive_actions(tmp_path):
    now = datetime.now(UTC)
    scope = Scope(
        id="passive",
        name="passive",
        allowed_targets=["authorized.invalid"],
        allowed_methods=["passive_recon", "discovery"],
        time_window=TimeWindow(start_time=now - timedelta(minutes=1), end_time=now + timedelta(minutes=5)),
        maximum_impact=ImpactLevel.LOW,
    )
    task = _make_policy_task(scope, mode=TaskMode.PASSIVE_RECON)
    engine = PolicyEngine(
        audit_logger=AuditLogger(str(tmp_path / "passive-audit.jsonl"), signing_key="passive-policy-test-key")
    )

    active_action = ActionRequest(
        id="active-service-scan",
        task_id=task.id,
        agent="network_agent",
        action_type="network.service_scan",
        target_refs=["authorized.invalid"],
        expected_impact_level=ImpactLevel.LOW,
    )
    active_decision = await engine.evaluate_action(active_action, task)
    assert active_decision.decision == PolicyDecisionType.DENY
    assert "passive reconnaissance" in active_decision.reason.lower()

    passive_action = ActionRequest(
        id="passive-subdomains",
        task_id=task.id,
        agent="recon_agent",
        action_type="recon.subdomains",
        target_refs=["authorized.invalid"],
        parameters={"passive_only": True},
        expected_impact_level=ImpactLevel.LOW,
    )
    passive_decision = await engine.evaluate_action(passive_action, task)
    assert passive_decision.decision == PolicyDecisionType.ALLOW

    mixed_adapter_action = ActionRequest(
        id="active-subdomains",
        task_id=task.id,
        agent="recon_agent",
        action_type="recon.subdomains",
        target_refs=["authorized.invalid"],
        expected_impact_level=ImpactLevel.LOW,
    )
    mixed_decision = await engine.evaluate_action(mixed_adapter_action, task)
    assert mixed_decision.decision == PolicyDecisionType.DENY


@pytest.mark.asyncio
async def test_third_party_enrichment_requires_scope_authorization(tmp_path):
    now = datetime.now(UTC)
    scope = Scope(
        id="third-party-enrichment",
        name="third-party-enrichment",
        allowed_targets=["authorized.invalid"],
        allowed_methods=["passive_recon"],
        time_window=TimeWindow(start_time=now - timedelta(minutes=1), end_time=now + timedelta(minutes=5)),
        maximum_impact=ImpactLevel.LOW,
    )
    task = _make_policy_task(scope, mode=TaskMode.PASSIVE_RECON)
    action = ActionRequest(
        id="third-party-enrichment-action",
        task_id=task.id,
        agent="recon_agent",
        action_type="recon.ip_intel",
        target_refs=["authorized.invalid"],
        parameters={"allow_third_party_enrichment": True},
        expected_impact_level=ImpactLevel.LOW,
    )
    engine = PolicyEngine(
        audit_logger=AuditLogger(str(tmp_path / "third-party-audit.jsonl"), signing_key="third-party-policy-test-key")
    )

    denied = await engine.evaluate_action(action, task)
    assert denied.decision == PolicyDecisionType.DENY
    assert "not authorized by the scope" in denied.reason.lower()

    task.scope.authorization.allow_third_party_enrichment = True
    allowed = await engine.evaluate_action(action, task)
    assert allowed.decision == PolicyDecisionType.ALLOW


@pytest.mark.asyncio
async def test_passive_planner_omits_target_probes_and_stops_after_baseline():

    target = Target(id="target", type=TargetType.DOMAIN, value="authorized.invalid")
    task = Task(
        id="passive-plan",
        objective="Passive reconnaissance",
        target_set=TargetSet(id="targets", name="targets", targets=[target]),
        scope=Scope(id="scope", name="scope", allowed_targets=[target.value]),
        policy=Policy(id="policy", name="policy"),
        mode=TaskMode.PASSIVE_RECON,
        correlation_id="correlation-passive",
    )
    memory = TaskWorkingMemory(task_id=task.id)
    planner = HeuristicPlanner()

    baseline = await planner.generate_plan(task, memory, AgentRegistry())
    action_types = {step.action_request.action_type for step in baseline.steps}
    assert action_types == {"dns.full_enum", "recon.subdomains", "recon.ip_intel"}
    assert all(
        step.action_request.parameters.get("passive_only") is True
        for step in baseline.steps
        if step.action_request.action_type in {"dns.full_enum", "recon.subdomains"}
    )
    assert all(
        step.action_request.parameters.get("allow_third_party_enrichment") is False
        for step in baseline.steps
        if step.action_request.action_type in {"recon.subdomains", "recon.ip_intel"}
    )

    task.scope.authorization.allow_third_party_enrichment = True
    authorized_plan = await planner.generate_plan(
        task,
        TaskWorkingMemory(task_id=f"{task.id}-authorized"),
        AgentRegistry(),
    )
    assert all(
        step.action_request.parameters.get("allow_third_party_enrichment") is True
        for step in authorized_plan.steps
        if step.action_request.action_type in {"recon.subdomains", "recon.ip_intel"}
    )

    terminal = await planner.generate_plan(task, memory, AgentRegistry())
    assert terminal.is_terminal is True
    assert terminal.steps == []


@pytest.mark.asyncio
async def test_passive_subdomain_adapter_skips_target_dns_and_wordlist_probes(monkeypatch):
    from sentinel.modules.recon import adapters as recon_adapters

    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=AssertionError("target DNS probe attempted")))
    monkeypatch.setattr(recon_adapters.dns.asyncresolver, "Resolver", lambda: resolver)
    requests: list[str] = []

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return []

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url):
            requests.append(url)
            return FakeResponse()

    monkeypatch.setattr(recon_adapters.httpx, "AsyncClient", FakeAsyncClient)
    action = ActionRequest(
        id="passive-subdomain-adapter",
        task_id="passive-adapter-task",
        agent="recon_agent",
        action_type="recon.subdomains",
        target_refs=["authorized.invalid"],
        parameters={"passive_only": True, "allow_third_party_enrichment": True},
    )

    await recon_adapters.SubdomainEnumAdapter().run(action)
    assert resolver.resolve.await_count == 0
    assert requests == ["https://crt.sh/?q=%.authorized.invalid&output=json"]


@pytest.mark.asyncio
async def test_passive_dns_adapter_skips_axfr(monkeypatch):
    from sentinel.modules.dns import dns_intel

    class NSRecord:
        @staticmethod
        def to_text():
            return "ns1.authorized.invalid."

    class FakeResolver:
        timeout = 0
        lifetime = 0

        @staticmethod
        async def resolve(_target, record_type):
            return [NSRecord()] if record_type == "NS" else []

    monkeypatch.setattr(dns_intel.dns.asyncresolver, "Resolver", FakeResolver)
    xfr = MagicMock(side_effect=AssertionError("AXFR attempted in passive mode"))
    monkeypatch.setattr(dns_intel.dns.query, "xfr", xfr)
    action = ActionRequest(
        id="passive-dns-adapter",
        task_id="passive-dns-task",
        agent="recon_agent",
        action_type="dns.full_enum",
        target_refs=["authorized.invalid"],
        parameters={"passive_only": True},
    )

    await dns_intel.DNSIntelligenceAdapter().run(action)
    xfr.assert_not_called()


@pytest.mark.asyncio
async def test_http_observer_does_not_follow_out_of_scope_redirect():
    sink_requests = {"count": 0}

    class SinkHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            sink_requests["count"] += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"sink")

        def log_message(self, *_args):
            pass

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/sink")
            self.end_headers()

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    redirector = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (sink, redirector)]
    for thread in threads:
        thread.start()

    try:
        action = ActionRequest(
            id="redirect-action",
            task_id="redirect-task",
            agent="recon_agent",
            action_type="http.observe",
            target_refs=[f"http://127.0.0.1:{redirector.server_port}/start"],
        )
        _result, raw_bytes, _content_type = await HTTPObserverAdapter().run(action)
        observation = json.loads(raw_bytes)
        assert observation["http"]["status_code"] == 302
        assert observation["http"]["redirect_count"] == 0
        assert sink_requests["count"] == 0
    finally:
        for server in (redirector, sink):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_assessment_adapters_do_not_enable_automatic_redirects():
    from pathlib import Path

    adapter_paths = (
        Path("sentinel/modules/web/adapters.py"),
        Path("sentinel/modules/recon/adapters.py"),
        Path("sentinel/modules/api_security/adapters.py"),
        Path("sentinel/integrations/scanners/http_adapter.py"),
    )
    for path in adapter_paths:
        assert "follow_redirects=True" not in path.read_text(encoding="utf-8")
