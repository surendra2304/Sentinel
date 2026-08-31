"""Cloud Security Agent for Sentinel.

Coordinates read-only cloud infrastructure inventory across AWS, Azure, and GCP,
evaluates configurations against data-driven posture rulesets, and logs verified Findings.
"""

import json
from typing import Any

from sentinel.core.agents.base import AgentReport, BaseAgent
from sentinel.core.models import (
    Policy,
    Scope,
    SeverityLevel,
    TargetSet,
    Task,
)
from sentinel.intelligence.risk.finding_engine import Observation


class CloudAgent(BaseAgent):
    """Specialized autonomous agent for Cloud Security Posture Management (CSPM)."""

    @property
    def name(self) -> str:
        return "cloud_agent"

    @property
    def domain(self) -> str:
        return "cloud_security"

    @property
    def capabilities(self) -> list[str]:
        return [
            "cloud.aws_inventory",
            "cloud.aws_posture_assess",
            "cloud.azure_inventory",
            "cloud.azure_posture_assess",
            "cloud.gcp_inventory",
            "cloud.gcp_posture_assess",
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
            reasoning="Analyzed cloud infrastructure configuration evidence and posture compliance.",
        )

        for evi in available_evidence:
            report.evidence_refs.append(evi["id"])
            raw_payload = evi.get("raw_payload", "{}")
            source_tool = evi.get("source_tool", "")
            target_ref = evi.get("target_ref", "target")

            try:
                data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
            except Exception:
                data = {}

            if source_tool in ("aws_cloud_adapter", "azure_cloud_adapter", "gcp_cloud_adapter"):
                for f in data.get("findings", []):
                    res_id = f.get("resource_arn") or f.get("resource_id") or target_ref
                    obs = Observation(
                        task_id=task.id,
                        target_ref=res_id,
                        source_module="cloud",
                        title=f.get("title", "Cloud Security Posture Violation"),
                        description=f.get("description", "Misconfigured cloud resource exposure."),
                        severity=SeverityLevel(f.get("severity", "high").lower()),
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Update cloud resource configuration."),
                    )
                    report.observations.append(obs)

        return report
