"""Web Security Agent for Sentinel.

Coordinates crawling, endpoint mapping, security header analysis,
authentication flow inspection, and vulnerability validation checks.
Produces structured, evidence-backed security Findings.
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


class WebSecurityAgent(BaseAgent):
    """Specialized autonomous agent for Web Application & API Security."""

    @property
    def name(self) -> str:
        return "web_security_agent"

    @property
    def domain(self) -> str:
        return "web_security"

    @property
    def capabilities(self) -> list[str]:
        return [
            "web.crawl",
            "web.endpoint_mapping",
            "web.header_analysis",
            "web.cookie_audit",
            "web.config_review",
            "web.auth_test",
            "web.session_audit",
            "web.vuln_validation",
            "web.sensitive_file_check",
            "web.directory_listing_check",
            "browser.capture",
            "browser.screenshot",
            "browser.dom_snapshot",
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
            reasoning="Analyzed web application evidence to identify misconfigurations, missing security headers, and exposed resources.",
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

            # 1. Process Web Config & Header Findings
            if source_tool == "web_config_analysis_adapter":
                findings_list = data.get("findings", [])
                for f in findings_list:
                    sev = SeverityLevel(f.get("severity", "low").lower())
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="web",
                        title=f.get("title", "Web Security Header Misconfiguration"),
                        description=f.get("description", "Security header or cookie flag missing."),
                        severity=sev,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Update web server configuration."),
                    )
                    report.observations.append(obs)

            # 2. Process Vulnerability Validation Checks (Directory Listing / Sensitive Files)
            elif source_tool == "vulnerability_validator_adapter":
                findings_list = data.get("findings", [])
                for f in findings_list:
                    sev = SeverityLevel(f.get("severity", "medium").lower())
                    obs = Observation(
                        task_id=task.id,
                        target_ref=f.get("url", target_ref),
                        source_module="web",
                        title=f.get("title", "Web Security Vulnerability Detected"),
                        description=f.get("description", "Sensitive file or directory exposure."),
                        severity=sev,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Restrict access and review server configuration."),
                    )
                    report.observations.append(obs)

        return report
