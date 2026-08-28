"""Wireless, Mobile, and Endpoint Domain Agents for Sentinel."""

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


class WirelessAgent(BaseAgent):
    """Domain agent specialized in Wireless & RF security assessment."""

    @property
    def name(self) -> str:
        return "wireless_agent"

    @property
    def domain(self) -> str:
        return "wireless_security"

    @property
    def capabilities(self) -> list[str]:
        return [
            "wireless.inventory",
            "wireless.interface_list",
            "wireless.config_audit",
            "wireless.posture_assess",
            "wireless.traffic_analysis",
            "wireless.deauth_detect",
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
            reasoning="Analyzed wireless configuration and RF capture evidence.",
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

            if source_tool == "wireless_config_assessment_adapter":
                for f in data.get("findings", []):
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="wireless",
                        title=f.get("title", "Wireless Security Flaw"),
                        description=f.get("description", "Insecure wireless AP configuration."),
                        severity=SeverityLevel(f.get("severity", "high").lower()),
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Update wireless settings."),
                    )
                    report.observations.append(obs)

        return report


class MobileAgent(BaseAgent):
    """Domain agent specialized in Mobile application (APK/IPA) static analysis."""

    @property
    def name(self) -> str:
        return "mobile_agent"

    @property
    def domain(self) -> str:
        return "mobile_security"

    @property
    def capabilities(self) -> list[str]:
        return [
            "mobile.apk_analyze",
            "mobile.android_manifest_audit",
            "mobile.ipa_analyze",
            "mobile.ios_plist_audit",
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
            reasoning="Analyzed mobile APK/IPA static manifest structures and permissions.",
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

            if source_tool in ("android_apk_static_adapter", "ios_ipa_static_adapter"):
                for f in data.get("findings", []):
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="mobile",
                        title=f.get("title", "Mobile Security Issue"),
                        description=f.get("description", "Mobile permission or configuration vulnerability."),
                        severity=SeverityLevel(f.get("severity", "medium").lower()),
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Update application manifest/plist settings."),
                    )
                    report.observations.append(obs)

        return report


class EndpointAgent(BaseAgent):
    """Domain agent specialized in Endpoint posture and host security audits."""

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
            reasoning="Analyzed local host endpoint configuration and process inventory.",
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

            if source_tool == "endpoint_assessment_adapter":
                for f in data.get("findings", []):
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="endpoint",
                        title=f.get("title", "Endpoint Posture Issue"),
                        description=f.get("description", "Endpoint hardening issue detected."),
                        severity=SeverityLevel(f.get("severity", "low").lower()),
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Review host security configurations."),
                    )
                    report.observations.append(obs)

        return report
