"""Vulnerability Intelligence and Threat Intelligence Domain Agents for Sentinel."""

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


class VulnerabilityAgent(BaseAgent):
    """Domain agent specialized in CVE correlation and vulnerability assessment."""

    @property
    def name(self) -> str:
        return "vulnerability_agent"

    @property
    def domain(self) -> str:
        return "vulnerability_intelligence"

    @property
    def capabilities(self) -> list[str]:
        return ["vulnerability.correlate", "vulnerability.cve_match"]

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
            reasoning="Correlated asset technologies with the KnowledgeBase CVE catalog.",
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

            if source_tool == "vulnerability_correlation_adapter":
                for vuln in data.get("vulnerabilities", []):
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="vulnerability",
                        title=vuln.get("title", f"Vulnerability {vuln.get('cve_id')} Detected"),
                        description=vuln.get("description", "Known software vulnerability."),
                        severity=SeverityLevel(vuln.get("severity", "high").lower()),
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=vuln.get("remediation", "Apply vendor security patches."),
                    )
                    report.observations.append(obs)

        return report


class ThreatIntelligenceAgent(BaseAgent):
    """Domain agent specialized in IOC threat feed enrichment and campaign tracking."""

    @property
    def name(self) -> str:
        return "threat_intelligence_agent"

    @property
    def domain(self) -> str:
        return "threat_intelligence"

    @property
    def capabilities(self) -> list[str]:
        return [
            "threat_intel.cisa_kev_sync",
            "threat_intel.exploit_check",
            "threat_intel.ioc_enrich",
            "threat_intel.ip_reputation",
            "threat_intel.custom_feed_load",
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
            reasoning="Enriched findings with CISA KEV and threat intelligence reputation feeds.",
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

            if source_tool == "abuse_ip_feed_adapter" and data.get("is_malicious"):
                obs = Observation(
                    task_id=task.id,
                    target_ref=target_ref,
                    source_module="threat_intel",
                    title=f"Malicious IOC Match: {data.get('ioc')}",
                    description=f"Asset matched active threat feed: {data.get('feed_context')}",
                    severity=SeverityLevel.HIGH,
                    confidence=float(data.get("confidence", 1.0)),
                    evidence_refs=[evi["id"]],
                    remediation="Block network communications to/from this malicious IOC.",
                )
                report.observations.append(obs)

        return report
