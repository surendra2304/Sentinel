"""Unit tests for Sentinel Threat Intelligence Module."""

import pytest

from sentinel.core.models import ActionRequest, RiskTier, SeverityLevel
from sentinel.modules.threat_intel import (
    IOCType,
    MitreMapper,
    ThreatIntelAdapter,
    ThreatIntelEngine,
    ThreatIntelReport,
    defang_ioc,
    extract_iocs,
    is_valid_ipv4,
    is_valid_ipv6,
    refang_ioc,
)


def test_defang_and_refang_ioc() -> None:
    raw_url = "https://malicious-c2.example.com/payload.exe"
    defanged = defang_ioc(raw_url)
    assert defanged == "hxxps://malicious-c2[.]example[.]com/payload[.]exe"

    refanged = refang_ioc(defanged)
    assert refanged == raw_url

    email = "attacker@evil.org"
    assert defang_ioc(email) == "attacker[@]evil[.]org"
    assert refang_ioc("attacker[@]evil[.]org") == email


def test_ip_validation() -> None:
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("8.8.8.8") is True
    assert is_valid_ipv4("999.999.999.999") is False
    assert is_valid_ipv4("not-an-ip") is False

    assert is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert is_valid_ipv6("::1") is True
    assert is_valid_ipv6("invalid:ipv6") is False


def test_extract_iocs_comprehensive() -> None:
    sample_text = """
    Incident Report: Alert triggered from 198.51.100.200 contacting hxxp://badactor-exfil[.]com/c2.
    Additional connections were observed to 2001:0db8:85a3:0000:0000:8a2e:0370:7334 and 10.0.0.15.
    Attacker email: phish[@]evil-c2[.]darknet.
    Dedicated C2 server domain: apt28-exfil-control.net.
    Exploited vulnerability CVE-2023-38606 on target web application.
    Dropper MD5: 44d88612fea8a8f36de82e1278abb02f
    Payload SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    Secondary SHA1: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
    Benign file mentioned: script.py, report.pdf, readme.txt (should not be extracted as domains).
    """

    iocs = extract_iocs(sample_text)
    types_found = {ioc.ioc_type for ioc in iocs}

    assert IOCType.IPV4 in types_found
    assert IOCType.IPV6 in types_found
    assert IOCType.URL in types_found
    assert IOCType.EMAIL in types_found
    assert IOCType.CVE in types_found
    assert IOCType.MD5 in types_found
    assert IOCType.SHA256 in types_found
    assert IOCType.SHA1 in types_found
    assert IOCType.DOMAIN in types_found

    # Verify normalization
    cve_ioc = next(i for i in iocs if i.ioc_type == IOCType.CVE)
    assert cve_ioc.value == "CVE-2023-38606"
    assert cve_ioc.severity == SeverityLevel.HIGH

    url_ioc = next(i for i in iocs if i.ioc_type == IOCType.URL)
    assert url_ioc.is_defanged is True
    assert url_ioc.normalized_value.startswith("http://badactor-exfil.com")

    # Verify no bogus domains from file extensions
    extracted_domains = [i.normalized_value for i in iocs if i.ioc_type == IOCType.DOMAIN]
    assert "script.py" not in extracted_domains
    assert "report.pdf" not in extracted_domains


def test_mitre_mapper_text_matching() -> None:
    mapper = MitreMapper()

    powershell_log = "Executed powershell.exe -EncodedCommand SQBFAFgA"
    techniques = mapper.map_text(powershell_log)
    tech_ids = [t.id for t in techniques]
    assert "T1059.001" in tech_ids

    unix_reverse_shell = "Attacker invoked /bin/bash reverse shell via nc -e"
    techniques_unix = mapper.map_text(unix_reverse_shell)
    tech_ids_unix = [t.id for t in techniques_unix]
    assert "T1059.004" in tech_ids_unix

    cred_dump = "Attempted mimikatz procdump against lsass"
    techniques_cred = mapper.map_text(cred_dump)
    tech_ids_cred = [t.id for t in techniques_cred]
    assert "T1003" in tech_ids_cred

    # Check finding correlation with CVE
    finding_techs = mapper.map_finding(
        title="Unauthenticated SQL Injection in Portal",
        description="Exploited publicly accessible login endpoint",
        related_cves=["CVE-2024-1234"],
    )
    assert any(t.id == "T1190" for t in finding_techs)


def test_mitre_tactic_lookup() -> None:
    mapper = MitreMapper()
    tactic = mapper.get_tactic("TA0001")
    assert tactic is not None
    assert tactic.name == "Initial Access"
    assert mapper.get_tactic("NONEXISTENT") is None


def test_reputation_scoring_and_threat_actors() -> None:
    engine = ThreatIntelEngine()

    # Known EICAR hash
    score_eicar = engine.score_indicator("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5)
    assert score_eicar.score == 100.0
    assert score_eicar.risk_tier == RiskTier.CRITICAL
    assert score_eicar.is_malicious is True

    # Known malicious domain
    score_dom = engine.score_indicator("evil-c2.darknet", IOCType.DOMAIN)
    assert score_dom.score >= 90.0
    assert score_dom.is_malicious is True

    # Safe DNS resolver
    score_dns = engine.score_indicator("1.1.1.1", IOCType.IPV4)
    assert score_dns.score == 0.0
    assert score_dns.risk_tier == RiskTier.MINIMAL
    assert score_dns.is_malicious is False

    # Cache hit check
    score_dns_cached = engine.score_indicator("1.1.1.1", IOCType.IPV4)
    assert score_dns_cached == score_dns

    # Threat actor correlation
    actors = engine.correlate_actors(["T1190", "T1059.001"])
    actor_names = [a.name for a in actors]
    assert "APT28" in actor_names


def test_threat_intel_full_analysis() -> None:
    engine = ThreatIntelEngine()
    sample_text = (
        "Adversary launched attack from 198.51.100.200 abusing valid accounts (T1078) "
        "and executed powershell downloadstring. Targeted defense domain evil-c2.darknet. "
        "Payload hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f."
    )

    report = engine.analyze_text(sample_text)
    assert isinstance(report, ThreatIntelReport)
    assert len(report.iocs) >= 3
    assert len(report.mitre_techniques) >= 1
    assert report.overall_threat_score >= 80.0
    assert report.overall_risk_tier == RiskTier.CRITICAL
    assert "Threat assessment identified" in report.summary


@pytest.mark.asyncio
async def test_threat_intel_tool_adapter() -> None:
    adapter = ThreatIntelAdapter()
    assert await adapter.health_check() is True
    assert adapter.name == "threat_intel_adapter"
    assert "threat_intel.analyze_threat" in adapter.capabilities

    # 1. Validation failure
    action_invalid = ActionRequest(
        id="act-1",
        task_id="tsk-1",
        agent="sentinel",
        action_type="threat_intel.score_reputation",
        parameters={},
        target_refs=[],
    )
    valid, err = adapter.validate_params(action_invalid)
    assert valid is False
    assert err is not None

    # 2. Extract IOCs execution
    action_extract = ActionRequest(
        id="act-2",
        task_id="tsk-1",
        agent="sentinel",
        action_type="threat_intel.extract_iocs",
        parameters={"text": "Investigate 198.51.100.200 and hxxp://evil-c2[.]darknet"},
        target_refs=[],
    )
    res, raw_bytes, mime = await adapter.run(action_extract)
    assert res.success is True
    assert "Extracted 2 indicators" in res.output_summary
    assert mime == "application/json"

    # 3. Analyze threat execution
    action_analyze = ActionRequest(
        id="act-3",
        task_id="tsk-1",
        agent="sentinel",
        action_type="threat_intel.analyze_threat",
        parameters={"text": "Detected mimikatz on domain controller from evil-c2.darknet"},
        target_refs=[],
    )
    res_ana, _, _ = await adapter.run(action_analyze)
    assert res_ana.success is True
    assert res_ana.error_info is None

    # 4. Unknown capability execution
    action_unknown = ActionRequest(
        id="act-4",
        task_id="tsk-1",
        agent="sentinel",
        action_type="threat_intel.unknown_subaction",
        parameters={"text": "test"},
        target_refs=[],
    )
    res_unk, _, _ = await adapter.run(action_unknown)
    assert res_unk.success is False
    assert "Unknown capability" in res_unk.output_summary
