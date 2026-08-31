"""Reconnaissance Agent for Sentinel.

Coordinates DNS lookups, Subdomain enumeration, IP intelligence, OSINT,
HTTP observation, technology fingerprinting, and network service scans.
Enriches the central AssetGraph and synthesizes structured findings.
"""

import json
import urllib.parse
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
from sentinel.modules.recon.graph import (
    EdgeType,
    NodeType,
    asset_graph_store,
)


class ReconAgent(BaseAgent):
    """Domain agent specialized in reconnaissance and attack surface mapping."""

    @property
    def name(self) -> str:
        return "recon_agent"

    @property
    def domain(self) -> str:
        return "reconnaissance"

    @property
    def capabilities(self) -> list[str]:
        return [
            "dns.lookup",
            "dns.full_enum",
            "dns.zone_info",
            "recon.subdomains",
            "recon.ip_intel",
            "recon.certificate_inspect",
            "recon.tech_fingerprint",
            "recon.osint",
            "http.observe",
            "tls.inspect",
            "network.service_scan",
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
            reasoning="Analyzed newly collected evidence artifacts to formulate security observations and build AssetGraph.",
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

            # Seed base Domain/IP node
            parsed = urllib.parse.urlparse(target_ref if "://" in target_ref else f"http://{target_ref}")
            host = parsed.hostname or target_ref
            base_node = asset_graph_store.add_node(
                task_id=task.id,
                node_type=NodeType.DOMAIN if not all(c.isdigit() or c == "." for c in host) else NodeType.IP,
                label=host,
                is_internet_facing=True,
            )

            # 1. Process Subdomain Enumeration
            if source_tool == "subdomain_enum_adapter":
                subdomains = data.get("subdomains", [])
                for sub in subdomains:
                    sub_node = asset_graph_store.add_node(
                        task_id=task.id,
                        node_type=NodeType.SUBDOMAIN,
                        label=sub,
                    )
                    asset_graph_store.add_edge(
                        task_id=task.id,
                        source_id=base_node.id,
                        target_id=sub_node.id,
                        edge_type=EdgeType.HAS_SUBDOMAIN,
                    )

            # 2. Process IP & ASN Intelligence
            elif source_tool == "ip_intelligence_adapter":
                ip_val = data.get("ip", host)
                ip_node = asset_graph_store.add_node(
                    task_id=task.id,
                    node_type=NodeType.IP,
                    label=ip_val,
                    properties={"asn": data.get("asn"), "org": data.get("org"), "country": data.get("country")},
                )
                if base_node.id != ip_node.id:
                    asset_graph_store.add_edge(
                        task_id=task.id,
                        source_id=base_node.id,
                        target_id=ip_node.id,
                        edge_type=EdgeType.RESOLVES_TO,
                    )

            # 3. Process Technology Fingerprinting
            elif source_tool == "technology_fingerprint_adapter":
                techs = data.get("technologies", [])
                for tech in techs:
                    tech_node = asset_graph_store.add_node(
                        task_id=task.id,
                        node_type=NodeType.TECHNOLOGY,
                        label=tech,
                    )
                    asset_graph_store.add_edge(
                        task_id=task.id,
                        source_id=base_node.id,
                        target_id=tech_node.id,
                        edge_type=EdgeType.USES_TECHNOLOGY,
                    )

            # 4. Process HTTP Observations
            elif source_tool == "http_observer_adapter":
                sec_headers = data.get("security_headers", {})
                missing_headers = [k for k, v in sec_headers.items() if v == "MISSING"]

                if missing_headers:
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="recon",
                        title=f"Missing Defensive Security Headers: {', '.join(missing_headers[:2])}",
                        description=f"HTTP endpoint '{target_ref}' is missing defensive headers: {', '.join(missing_headers)}",
                        severity=SeverityLevel.LOW,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation="Configure server response headers to include Strict-Transport-Security, X-Frame-Options, and Content-Security-Policy.",
                    )
                    report.observations.append(obs)

            # 5. Process Network Service Scans
            elif source_tool == "network_scanner_adapter":
                open_ports = data.get("open_ports", [])
                for p in open_ports:
                    port_node = asset_graph_store.add_node(
                        task_id=task.id,
                        node_type=NodeType.PORT,
                        label=f"{host}:{p}",
                        properties={"port": p},
                    )
                    asset_graph_store.add_edge(
                        task_id=task.id,
                        source_id=base_node.id,
                        target_id=port_node.id,
                        edge_type=EdgeType.LISTENS_ON,
                    )

                if open_ports:
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="network",
                        title=f"Exposed Listening Network Services on Ports {open_ports}",
                        description=f"Host '{target_ref}' has accessible listening ports: {open_ports}",
                        severity=SeverityLevel.MEDIUM if any(p in [21, 23, 8080] for p in open_ports) else SeverityLevel.LOW,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation="Close unused network ports or restrict access using perimeter firewalls.",
                    )
                    report.observations.append(obs)

            # 6. Process DNS Intelligence (AXFR)
            elif source_tool == "dns_intelligence_adapter":
                axfr = data.get("zone_transfer", {})
                if axfr.get("vulnerable"):
                    obs = Observation(
                        task_id=task.id,
                        target_ref=target_ref,
                        source_module="dns",
                        title="Critical DNS Zone Transfer (AXFR) Allowed",
                        description=axfr.get("details", "Nameserver permits unauthenticated AXFR zone transfers."),
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        evidence_refs=[evi["id"]],
                        remediation="Restrict DNS zone transfers to authorized secondary nameservers only.",
                    )
                    report.observations.append(obs)

        return report
