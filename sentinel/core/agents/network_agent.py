"""Network Security Agent for Sentinel.

Coordinates host liveness, exposure analysis, segmentation testing,
firewall reviews, and traffic inspection. Produces structured Findings.
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


class NetworkAgent(BaseAgent):
    """Specialized autonomous agent for Network Security operations."""

    @property
    def name(self) -> str:
        return "network_agent"

    @property
    def domain(self) -> str:
        return "network_security"

    @property
    def capabilities(self) -> list[str]:
        return [
            "network.host_discovery",
            "network.ping_sweep",
            "network.exposure_analysis",
            "network.full_service_scan",
            "network.segmentation_check",
            "network.firewall_review",
            "network.security_group_audit",
            "network.traffic_analysis",
            "network.pcap_inspect",
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
            reasoning="Analyzed network security evidence to extract exposure, segmentation, and firewall vulnerabilities.",
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

            # 1. Process Exposure Analysis Violations
            if source_tool == "network_exposure_adapter":
                exposure_flags = data.get("exposure_flags", [])
                for flag in exposure_flags:
                    sev = SeverityLevel(flag.get("severity", "medium").lower())
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="network",
                        title=f"Unexpected Exposed Service: {flag.get('service')} on Port {flag.get('port')}",
                        description=flag.get("description", "Exposed sensitive network service."),
                        severity=sev,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=flag.get("remediation", "Restrict network port access."),
                    )
                    report.observations.append(obs)

            # 2. Process Segmentation Violations
            elif source_tool == "segmentation_analyzer_adapter":
                violations = data.get("violations", [])
                for viol in violations:
                    obs = Observation(
                        task_id=task.id,
                        target_ref=viol.get("destination_zone", target_ref),
                        source_module="network",
                        title=f"Network Segmentation Boundary Breach on Port {viol.get('port')}",
                        description=viol.get("violation", "Cross-zone isolation failure."),
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation="Enforce strict firewall ingress ACLs between zones.",
                    )
                    report.observations.append(obs)

            # 3. Process Firewall / Security Group Review
            elif source_tool == "firewall_config_review_adapter":
                findings_list = data.get("findings", [])
                for f in findings_list:
                    sev = SeverityLevel(f.get("severity", "high").lower())
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="network",
                        title=f.get("title", "Overly Permissive Firewall Rule"),
                        description=f.get("description", "Security group misconfiguration."),
                        severity=sev,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation="Remove 0.0.0.0/0 ingress and restrict to explicit subnets.",
                    )
                    report.observations.append(obs)

        return report
