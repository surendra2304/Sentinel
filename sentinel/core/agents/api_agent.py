"""API Security Agent for Sentinel.

Coordinates API surface discovery, OpenAPI schema ingestion, JWT audit,
input validation boundary testing, and CORS misconfiguration checks.
Produces structured Findings with attached Evidence references.
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


class APISecurityAgent(BaseAgent):
    """Specialized autonomous agent for API and REST/GraphQL security."""

    @property
    def name(self) -> str:
        return "api_security_agent"

    @property
    def domain(self) -> str:
        return "api_security"

    @property
    def capabilities(self) -> list[str]:
        return [
            "api.discovery",
            "api.spec_locate",
            "api.schema_parse",
            "api.inventory",
            "api.jwt_audit",
            "api.auth_analysis",
            "api.input_validation",
            "api.type_confusion_probe",
            "api.cors_analysis",
            "api.misconfig_check",
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
            reasoning="Analyzed API security evidence artifacts to identify schema exposures, weak JWT claims, and CORS flaws.",
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

            # 1. Process JWT Vulnerabilities
            if source_tool == "jwt_auth_analysis_adapter":
                findings_list = data.get("findings", [])
                for f in findings_list:
                    sev = SeverityLevel(f.get("severity", "high").lower())
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="api_security",
                        title=f.get("title", "JWT Authentication Flaw"),
                        description=f.get("description", "Insecure JWT structure."),
                        severity=sev,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Enforce secure JWT validation."),
                    )
                    report.observations.append(obs)

            # 2. Process CORS & Misconfiguration Flaws
            elif source_tool == "api_misconfig_adapter":
                findings_list = data.get("findings", [])
                for f in findings_list:
                    sev = SeverityLevel(f.get("severity", "medium").lower())
                    obs = Observation(
                        task_id=task.id,
                        target_ref=f.get("url", target_ref),
                        source_module="api_security",
                        title=f.get("title", "API CORS Misconfiguration"),
                        description=f.get("description", "Permissive CORS reflection detected."),
                        severity=sev,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Restrict CORS Origin headers."),
                    )
                    report.observations.append(obs)

            # 3. Process Input Validation Failures
            elif source_tool == "input_validation_probe_adapter":
                findings_list = data.get("findings", [])
                for f in findings_list:
                    sev = SeverityLevel(f.get("severity", "low").lower())
                    obs = Observation(
                        task_id=task.id,
                        target_ref=f.get("url", target_ref),
                        source_module="api_security",
                        title=f.get("title", "API Input Validation Weakness"),
                        description=f.get("description", "Input validation anomaly."),
                        severity=sev,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Enforce strict schema validation."),
                    )
                    report.observations.append(obs)

        return report
