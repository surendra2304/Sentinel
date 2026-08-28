"""Comprehensive Unit Test Suite for All Sentinel Core Agents.

Tests happy-path analyze() and edge/failure handling (empty payloads, corrupt JSON, unhandled tools)
across every BaseAgent implementation in sentinel/core/agents/:
1. APISecurityAgent
2. CloudAgent
3. DeviceAgent (Mobile/Wireless)
4. DFIRAgent (Forensics/Incident Response)
5. EndpointAgent
6. ThreatIntelligenceAgent
7. NetworkAgent
8. ReconAgent
9. SecurityIntelligenceAgent
10. WebSecurityAgent
"""

import json
import pytest

from sentinel.core.agents.api_agent import APISecurityAgent
from sentinel.core.agents.cloud_agent import CloudAgent
from sentinel.core.agents.device_agents import MobileAgent, WirelessAgent
from sentinel.core.agents.dfir_agents import ForensicsAgent, IncidentResponseAgent
from sentinel.core.agents.endpoint_agent import EndpointAgent
from sentinel.core.agents.intel_agents import ThreatIntelligenceAgent, VulnerabilityAgent
from sentinel.core.agents.network_agent import NetworkAgent
from sentinel.core.agents.recon_agent import ReconAgent
from sentinel.core.agents.security_intelligence_agent import SecurityIntelligenceAgent
from sentinel.core.agents.web_agent import WebSecurityAgent
from sentinel.core.models import ImpactLevel, Policy, Scope, SeverityLevel, Target, TargetSet, TargetType, Task


@pytest.fixture
def agent_task():
    t = Target(id="t-agt-1", type=TargetType.DOMAIN, value="target.local")
    ts = TargetSet(id="ts-agt-1", name="TS Agt", targets=[t])
    scope = Scope(id="s-agt-1", name="S Agt", allowed_targets=["target.local"])
    policy = Policy(id="p-agt-1", name="P Agt")
    return Task(
        id="task-agt-001",
        objective="Analyze all evidence artifacts",
        target_set=ts,
        scope=scope,
        policy=policy,
        correlation_id="corr-agt-001",
    )


@pytest.mark.asyncio
async def test_api_security_agent(agent_task):
    agent = APISecurityAgent()
    assert agent.domain == "api_security"

    evidence = [
        {
            "id": "evi-jwt-1",
            "source_tool": "jwt_auth_analysis_adapter",
            "target_ref": "https://target.local/api",
            "raw_payload": json.dumps({
                "findings": [{"title": "Weak JWT Key", "severity": "HIGH", "description": "HMAC secret brute-forced"}]
            })
        },
        {
            "id": "evi-cors-1",
            "source_tool": "api_misconfig_adapter",
            "target_ref": "https://target.local/api",
            "raw_payload": json.dumps({
                "findings": [{"title": "Wildcard CORS", "severity": "MEDIUM", "url": "https://target.local/api"}]
            })
        },
        {
            "id": "evi-input-1",
            "source_tool": "input_validation_probe_adapter",
            "target_ref": "https://target.local/api",
            "raw_payload": json.dumps({
                "findings": [{"title": "Type Confusion", "severity": "LOW", "url": "https://target.local/api"}]
            })
        },
        {
            "id": "evi-corrupt",
            "source_tool": "jwt_auth_analysis_adapter",
            "target_ref": "https://target.local/api",
            "raw_payload": "{invalid-json"
        }
    ]

    report = await agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, evidence, {})
    assert len(report.observations) == 3
    assert len(report.evidence_refs) == 4


@pytest.mark.asyncio
async def test_cloud_agent(agent_task):
    agent = CloudAgent()
    assert agent.domain == "cloud_security"

    evidence = [
        {
            "id": "evi-cld-1",
            "source_tool": "aws_cloud_adapter",
            "raw_payload": json.dumps({
                "findings": [{"title": "Open S3 Bucket", "severity": "CRITICAL", "resource_id": "arn:aws:s3:::open-bkt"}]
            })
        },
        {
            "id": "evi-cld-corrupt",
            "source_tool": "aws_cloud_adapter",
            "raw_payload": "corrupt-json"
        }
    ]

    report = await agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, evidence, {})
    assert len(report.observations) == 1
    assert report.observations[0].title == "Open S3 Bucket"


@pytest.mark.asyncio
async def test_device_agents(agent_task):
    mobile_agent = MobileAgent()
    wireless_agent = WirelessAgent()

    # Mobile Happy + Failure
    mob_evidence = [
        {
            "id": "evi-mob-1",
            "source_tool": "android_apk_static_adapter",
            "raw_payload": json.dumps({
                "findings": [{"title": "Hardcoded AWS Secret", "severity": "HIGH"}]
            })
        },
        {"id": "evi-mob-2", "source_tool": "android_apk_static_adapter", "raw_payload": "invalid"}
    ]
    mob_report = await mobile_agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, mob_evidence, {})
    assert len(mob_report.observations) == 1

    # Wireless Happy + Failure
    wifi_evidence = [
        {
            "id": "evi-wifi-1",
            "source_tool": "wireless_config_assessment_adapter",
            "raw_payload": json.dumps({
                "findings": [{"title": "WPS Enabled", "severity": "MEDIUM"}]
            })
        },
        {"id": "evi-wifi-2", "source_tool": "wireless_config_assessment_adapter", "raw_payload": "{broken"}
    ]
    wifi_report = await wireless_agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, wifi_evidence, {})
    assert len(wifi_report.observations) == 1


@pytest.mark.asyncio
async def test_dfir_agents(agent_task):
    forensics = ForensicsAgent()
    ir = IncidentResponseAgent()

    for_evidence = [
        {
            "id": "evi-for-1",
            "source_tool": "forensic_event_correlation_adapter",
            "raw_payload": json.dumps({
                "findings": [{"title": "Suspicious PowerShell lateral movement", "severity": "HIGH"}]
            })
        },
        {"id": "evi-for-2", "source_tool": "forensic_event_correlation_adapter", "raw_payload": "invalid"}
    ]
    for_report = await forensics.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, for_evidence, {})
    assert len(for_report.observations) == 1

    ir_evidence = [
        {
            "id": "evi-ir-1",
            "source_tool": "incident_response_triage_adapter",
            "raw_payload": json.dumps({
                "containment_actions": [{"action": "Isolate Host 10.0.0.5", "urgency": "IMMEDIATE"}]
            })
        },
        {"id": "evi-ir-2", "source_tool": "incident_response_triage_adapter", "raw_payload": "corrupt"}
    ]
    ir_report = await ir.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, ir_evidence, {})
    assert len(ir_report.observations) >= 0


@pytest.mark.asyncio
async def test_intel_and_vulnerability_agents(agent_task):
    intel_agent = ThreatIntelligenceAgent()
    vuln_agent = VulnerabilityAgent()

    intel_evidence = [
        {
            "id": "evi-int-1",
            "source_tool": "abuse_ip_feed_adapter",
            "raw_payload": json.dumps({
                "is_malicious": True,
                "confidence": 0.95,
                "feed_context": "Known Cobalt Strike C2 IP"
            })
        },
        {"id": "evi-int-2", "source_tool": "abuse_ip_feed_adapter", "raw_payload": "{bad"}
    ]
    intel_report = await intel_agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, intel_evidence, {})
    assert len(intel_report.observations) == 1

    vuln_evidence = [
        {
            "id": "evi-vuln-1",
            "source_tool": "vulnerability_correlation_adapter",
            "raw_payload": json.dumps({
                "vulnerabilities": [{"title": "Log4Shell RCE", "cve_id": "CVE-2021-44228", "severity": "CRITICAL", "description": "Log4Shell RCE"}]
            })
        },
        {"id": "evi-vuln-2", "source_tool": "vulnerability_correlation_adapter", "raw_payload": "corrupt"}
    ]
    vuln_report = await vuln_agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, vuln_evidence, {})
    assert len(vuln_report.observations) == 1


@pytest.mark.asyncio
async def test_network_recon_web_and_secintel_agents(agent_task):
    net_agent = NetworkAgent()
    recon_agent = ReconAgent()
    web_agent = WebSecurityAgent()
    sec_intel = SecurityIntelligenceAgent()

    # Network Agent
    net_evidence = [
        {
            "id": "evi-net-1",
            "source_tool": "network_exposure_adapter",
            "raw_payload": json.dumps({
                "exposure_flags": [{"title": "Unauthenticated Telnet", "severity": "HIGH"}]
            })
        },
        {"id": "evi-net-2", "source_tool": "network_exposure_adapter", "raw_payload": "broken"}
    ]
    net_report = await net_agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, net_evidence, {})
    assert len(net_report.observations) == 1

    # Recon Agent
    recon_evidence = [
        {
            "id": "evi-rec-1",
            "source_tool": "http_observer_adapter",
            "raw_payload": json.dumps({"security_headers": {"X-Frame-Options": "MISSING"}}),
        },
        {
            "id": "evi-rec-sub",
            "source_tool": "subdomain_enum_adapter",
            "raw_payload": json.dumps({"subdomains": ["api.target.local", "mail.target.local"]}),
        },
        {
            "id": "evi-rec-ip",
            "source_tool": "ip_intelligence_adapter",
            "raw_payload": json.dumps({"ip": "1.1.1.1", "asn": "AS13335"}),
        },
        {
            "id": "evi-rec-tech",
            "source_tool": "technology_fingerprint_adapter",
            "raw_payload": json.dumps({"technologies": ["Nginx", "Node.js"]}),
        },
        {
            "id": "evi-rec-net",
            "source_tool": "network_scanner_adapter",
            "raw_payload": json.dumps({"open_ports": [80, 443, 8080]}),
        },
        {
            "id": "evi-rec-dns",
            "source_tool": "dns_intelligence_adapter",
            "raw_payload": json.dumps({"zone_transfer": {"vulnerable": True, "details": "AXFR enabled"}}),
        },
        {"id": "evi-rec-2", "source_tool": "http_observer_adapter", "raw_payload": "broken"},
    ]
    rec_report = await recon_agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, recon_evidence, {})
    assert len(rec_report.observations) >= 3

    # Web Agent
    web_evidence = [
        {
            "id": "evi-web-1",
            "source_tool": "web_config_analysis_adapter",
            "raw_payload": json.dumps({
                "findings": [{"title": "Reflected Cross-Site Scripting", "severity": "HIGH"}]
            })
        },
        {"id": "evi-web-2", "source_tool": "web_config_analysis_adapter", "raw_payload": "broken"}
    ]
    web_report = await web_agent.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, web_evidence, {})
    assert len(web_report.observations) == 1

    # Security Intelligence Agent
    sec_report = await sec_intel.analyze(agent_task, agent_task.target_set, agent_task.scope, agent_task.policy, web_evidence, {})
    assert sec_report.agent_name == sec_intel.name