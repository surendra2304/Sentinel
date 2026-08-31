"""Forensics and Incident Response Domain Agents for Sentinel."""

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


class ForensicsAgent(BaseAgent):
    """Domain agent specialized in digital artifact collection, super-timelines, and sequence correlation."""

    @property
    def name(self) -> str:
        return "forensics_agent"

    @property
    def domain(self) -> str:
        return "digital_forensics"

    @property
    def capabilities(self) -> list[str]:
        return [
            "forensics.log_collect",
            "forensics.auth_log_parse",
            "forensics.timeline_build",
            "forensics.event_correlate",
            "forensics.sequence_detect",
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
            reasoning="Constructed forensic timeline and evaluated suspicious event sequences.",
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

            if source_tool == "forensic_event_correlation_adapter":
                for f in data.get("findings", []):
                    obs = Observation(
                        task_id=task.id,
                        target_ref=f.get("source_ip", target_ref),
                        source_module="forensics",
                        title=f.get("title", "Forensic Attack Sequence Detected"),
                        description=f.get("description", "Correlated multi-stage attack pattern."),
                        severity=SeverityLevel(f.get("severity", "high").lower()),
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation=f.get("remediation", "Isolate compromised credentials and host."),
                    )
                    report.observations.append(obs)

        return report


class IncidentResponseAgent(BaseAgent):
    """Domain agent specialized in alert triage, root-cause analysis, and response containment proposals."""

    @property
    def name(self) -> str:
        return "incident_response_agent"

    @property
    def domain(self) -> str:
        return "incident_response"

    @property
    def capabilities(self) -> list[str]:
        return [
            "ir.alert_triage",
            "ir.containment_recommend",
            "ir.root_cause_analysis",
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
            reasoning="Triaged security alerts and generated approval-gated containment recommendations.",
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

            if source_tool == "ir_triage_adapter":
                verdict = data.get("verdict")
                if verdict in ("suspicious", "confirmed_incident"):
                    obs = Observation(
                        task_id=task.id,
                        target_ref=data.get("indicator", target_ref),
                        source_module="incident_response",
                        title=f"Incident Confirmed: Malicious Activity Detected on {data.get('indicator')}",
                        description=f"Alert triage verdict '{verdict.upper()}' with confidence {data.get('confidence')}.",
                        severity=SeverityLevel.HIGH if verdict == "suspicious" else SeverityLevel.CRITICAL,
                        confidence=float(data.get("confidence", 0.9)),
                        evidence_refs=[evi["id"]],
                        remediation="Review proposed containment actions and approve network isolation.",
                    )
                    report.observations.append(obs)

        return report
