# Module Development Guide

This guide shows how to add a new security domain module (adapter + agent) to SENTINEL without modifying the orchestrator.

---

## Concepts

| Concept | Role |
|---|---|
| **ToolAdapter** | Wraps one external tool or service; returns raw evidence bytes |
| **Agent** | Owns a domain; calls N adapters; submits observations to FindingEngine |
| **AgentRegistry** | Auto-discovers agents by subclassing BaseAgent |
| **ActionRequest** | Typed unit of work assigned by the Planner to an Agent |

---

## Worked Minimal Example: ssl_audit Domain

### 1. Create the adapter

python
# sentinel/modules/ssl_audit/adapters.py
from sentinel.core.execution.adapters import ToolAdapter, ToolOutput
from sentinel.core.models import ActionRequest

class SSLCertAuditAdapter(ToolAdapter):
    """Checks TLS certificate validity, expiry, and cipher strength."""

    name = "ssl.cert_audit"
    supported_actions = ["ssl.cert_audit"]

    async def execute(self, request: ActionRequest) -> ToolOutput:
        import ssl, socket, datetime
        host = request.target_refs[0] if request.target_refs else ""
        findings: list[str] = []
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, 443))
                cert = s.getpeercert()
            expiry_str = cert.get("notAfter", "")
            expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 30:
                findings.append(f"Certificate expires in {days_left} days")
        except Exception as exc:
            findings.append(f"TLS error: {exc}")
        raw = "\n".join(findings) or "Certificate OK"
        return ToolOutput(raw_output=raw.encode(), exit_code=0 if not findings else 1)


### 2. Create the agent

python
# sentinel/modules/ssl_audit/agent.py
from sentinel.core.agents.base import BaseAgent, AgentReport
from sentinel.core.models import Task, TargetSet, Scope, Policy
from sentinel.core.execution.adapters import ToolAdapter
from sentinel.modules.ssl_audit.adapters import SSLCertAuditAdapter
from typing import Any

class SSLAuditAgent(BaseAgent):
    name = "ssl_audit_agent"
    domain = "ssl_audit"
    capabilities = ["ssl.cert_audit"]

    def __init__(self) -> None:
        self._adapter = SSLCertAuditAdapter()

    async def analyze(
        self, task: Task, target_set: TargetSet, scope: Scope, policy: Policy,
        available_evidence: list[dict[str, Any]], working_memory: dict[str, Any],
    ) -> AgentReport:
        report = AgentReport(agent_name=self.name, task_id=task.id)
        for target in target_set.targets:
            from sentinel.core.models import ActionRequest, ImpactLevel
            action = ActionRequest(
                id=f"ssl-{target.value[:8]}", task_id=task.id, agent=self.name,
                action_type="ssl.cert_audit", target_refs=[target.value],
                expected_impact_level=ImpactLevel.LOW,
            )
            result = await self._adapter.execute(action)
            if result.exit_code != 0 and result.raw_output:
                report.observations.append({
                    "target": target.value,
                    "finding": result.raw_output.decode(),
                })
        return report


### 3. Register in __init__.py

python
# sentinel/modules/ssl_audit/__init__.py
from sentinel.modules.ssl_audit.agent import SSLAuditAgent
from sentinel.core.agents.base import agent_registry

agent_registry.register(SSLAuditAgent())


### 4. Add a planned step

The planner picks up the new agent automatically via egistry.list_agents(). To have the HeuristicPlanner include a step, add to sentinel/core/planner/heuristic.py:

python
plan.steps.append(PlannedStep(
    agent_name="ssl_audit_agent",
    action_request=ActionRequest(
        id=f"act-ssl-{uuid.uuid4().hex[:8]}",
        task_id=task.id,
        agent="ssl_audit_agent",
        action_type="ssl.cert_audit",
        target_refs=[hostname],
        expected_impact_level=ImpactLevel.LOW,
    ),
    phase="TLS_AUDIT",
    justification=f"Audit TLS certificate validity and expiry for '{hostname}'.",
))


### 5. Write a unit test

python
# tests/unit/test_ssl_audit_module.py
import pytest
from sentinel.modules.ssl_audit.adapters import SSLCertAuditAdapter
from sentinel.core.models import ActionRequest, ImpactLevel

@pytest.mark.asyncio
async def test_ssl_audit_adapter_bad_host():
    adapter = SSLCertAuditAdapter()
    action = ActionRequest(
        id="act-ssl-test", task_id="t-001", agent="ssl_audit_agent",
        action_type="ssl.cert_audit", target_refs=["nonexistent.invalid"],
        expected_impact_level=ImpactLevel.LOW,
    )
    result = await adapter.execute(action)
    assert result.exit_code != 0
    assert b"TLS error" in result.raw_output


---

## Key Extension Points

| Extension Point | File |
|---|---|
| New ToolAdapter | sentinel/modules/<domain>/adapters.py |
| New Agent | sentinel/modules/<domain>/agent.py |
| Register agent | sentinel/modules/<domain>/__init__.py |
| Add planner phase | sentinel/core/planner/heuristic.py |
| New policy action class | sentinel/core/models.py → ActionClass enum |
| New report section | sentinel/intelligence/reporting/templates/ |
| New intelligence role | sentinel/core/intelligence/interface.py + heuristic_provider.py + schema |