"""Reconnaissance Agent for Sentinel.

Coordinates DNS lookups, HTTP surface audits, and service scans. Synthesizes
raw tool outputs into structured Observation and Finding objects.
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


class ReconAgent(BaseAgent):
    """Domain agent specialized in reconnaissance and perimeter mapping."""

    @property
    def name(self) -> str:
        return "recon_agent"

    @property
    def domain(self) -> str:
        return "reconnaissance"

    @property
    def capabilities(self) -> list[str]:
        return ["dns.lookup", "dns.zone_info", "http.observe", "tls.inspect", "network.service_scan"]

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
            reasoning="Analyzed newly collected evidence artifacts to formulate security observations.",
        )

        for evi in available_evidence:
            report.evidence_refs.append(evi["id"])
            raw_payload = evi.get("raw_payload", "{}")

            try:
                data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
            except Exception:
                data = {}

            # Analyze HTTP Observations
            if evi.get("source_tool") == "http_observer_adapter":
                sec_headers = data.get("security_headers", {})
                missing_headers = [k for k, v in sec_headers.items() if v == "MISSING"]

                if missing_headers:
                    obs = Observation(
                        task_id=task.id,
                        target_ref=evi.get("target_ref", "target"),
                        source_module="recon",
                        title=f"Missing Critical Security Headers: {', '.join(missing_headers[:2])}",
                        description=f"HTTP endpoint '{evi.get('target_ref')}' is missing defensive headers: {', '.join(missing_headers)}",
                        severity=SeverityLevel.LOW,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation="Configure server response headers to include Strict-Transport-Security and Content-Security-Policy.",
                    )
                    report.observations.append(obs)

            # Analyze Open Network Ports
            if evi.get("source_tool") == "network_scanner_adapter":
                open_ports = data.get("open_ports", [])
                if open_ports:
                    obs = Observation(
                        task_id=task.id,
                        target_ref=evi.get("target_ref", "target"),
                        source_module="network",
                        title=f"Exposed Network Services on Ports {open_ports}",
                        description=f"Host '{evi.get('target_ref')}' has accessible listening ports: {open_ports}",
                        severity=SeverityLevel.MEDIUM if any(p in [21, 23, 8080] for p in open_ports) else SeverityLevel.LOW,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation="Close unused network ports or restrict access using perimeter firewalls.",
                    )
                    report.observations.append(obs)

        return report
