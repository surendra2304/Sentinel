"""Endpoint Security Agent for Sentinel.

Coordinates host posture assessment across Linux, Windows, and macOS endpoints.
Supports both local live audit and offline export ingestion modes, synthesizes
evidence-backed observations, and records findings in FindingEngine.
"""

from typing import Any

from sentinel.core.agents.base import AgentReport, BaseAgent
from sentinel.core.models import (
    ActionRequest,
    ImpactLevel,
    Policy,
    Scope,
    SeverityLevel,
    TargetSet,
    Task,
)
from sentinel.intelligence.risk.finding_engine import Observation


class EndpointAgent(BaseAgent):
    """Specialized autonomous agent for Endpoint & Host Security operations."""

    @property
    def name(self) -> str:
        return "endpoint_agent"

    @property
    def domain(self) -> str:
        return "endpoint_security"

    @property
    def capabilities(self) -> list[str]:
        return [
            "endpoint.posture_assess",
            "endpoint.process_inventory",
            "endpoint.hardening_check",
            "endpoint.offline_assess",
        ]

    async def analyze(
        self,
        task: Task,
        target_set: TargetSet,
        scope: Scope,
        policy: Policy,
        available_evidence: list[dict[str, Any]],
        working_memory: dict[str, Any],
    ) -> AgentReport:
        report = AgentReport(
            agent_name=self.name,
            task_id=task.id,
            reasoning="Analyzed endpoint security evidence to evaluate OS hardening, persistence mechanisms, and user privileges.",
        )

        has_endpoint_evidence = False

        for evi in available_evidence:
            data = evi.get("data")
            evi_id = evi.get("id", f"evi-{task.id}")
            if not isinstance(data, dict):
                continue

            findings = data.get("findings", [])
            hostname = data.get("hostname", "local-host")
            os_platform = data.get("os_platform", "unknown")

            if "findings" in data or "process_count" in data:
                has_endpoint_evidence = True

            for f in findings:
                sev_str = str(f.get("severity", "MEDIUM")).upper()
                try:
                    sev = SeverityLevel(sev_str.lower())
                except ValueError:
                    sev = SeverityLevel.MEDIUM

                rule_id = f.get("rule_id", "EP-GEN-001")
                target_val = f.get("target") or hostname

                obs = Observation(
                    task_id=task.id,
                    target_ref=target_val,
                    source_module=f"endpoint.{os_platform.lower()}",
                    title=f.get("title", f"Endpoint Finding: {rule_id}"),
                    description=f.get("description", "Endpoint posture rule violation."),
                    severity=sev,
                    confidence=0.95,
                    evidence_refs=[evi_id],
                    remediation=f.get("remediation"),
                    exploitability_context=f"Local/Offline endpoint inspection rule {rule_id} triggered on host {hostname}.",
                    impact=f"Elevated risk of privilege escalation, lateral movement, or unauthorized persistence on {hostname}.",
                )
                report.observations.append(obs)

        # If no endpoint assessment has run yet, request one
        if not has_endpoint_evidence:
            report.actions_requested.append(
                ActionRequest(
                    id=f"act-ep-{task.id}",
                    task_id=task.id,
                    agent=self.name,
                    action_type="endpoint.posture_assess",
                    target_refs=[t.value for t in target_set.targets] if target_set.targets else ["localhost"],
                    parameters={},
                    expected_impact_level=ImpactLevel.LOW,
                    requires_approval=False,
                )
            )
            report.recommended_next_step = "Execute endpoint posture and hardening check on targets."

        return report
