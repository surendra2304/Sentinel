"""Recon and Asset Discovery Deep Unit Tests."""

import json

import pytest

from sentinel.core.models import ActionRequest
from sentinel.modules.recon.adapters import (
    CertificateInspectorAdapter,
    IPIntelligenceAdapter,
    OSINTAdapter,
    SubdomainEnumAdapter,
    TechnologyFingerprintAdapter,
)


@pytest.mark.asyncio
async def test_subdomain_enum_adapter(monkeypatch):
    adp = SubdomainEnumAdapter()
    req = ActionRequest(
        id="act-sub-01",
        task_id="t1",
        agent="recon_agent",
        action_type="recon.subdomain_enum",
        target_refs=["example.com"],
        parameters={"wordlist": ["api", "www"]},
    )
    res, raw, _ = await adp.run(req)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert data["domain"] == "example.com"
    assert "sources" in data


@pytest.mark.asyncio
async def test_ip_intelligence_adapter():
    adp = IPIntelligenceAdapter()
    req = ActionRequest(
        id="act-ip-01",
        task_id="t1",
        agent="recon_agent",
        action_type="recon.ip_intel",
        target_refs=["8.8.8.8"],
    )
    res, raw, _ = await adp.run(req)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert data["ip"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_certificate_inspector_adapter():
    adp = CertificateInspectorAdapter()
    req = ActionRequest(
        id="act-cert-01",
        task_id="t1",
        agent="recon_agent",
        action_type="recon.certificate_inspect",
        target_refs=["https://localhost:8443"],
    )
    res, raw, _ = await adp.run(req)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert "has_certificate" in data


@pytest.mark.asyncio
async def test_tech_fingerprint_and_osint_adapters():
    # 1. Tech fingerprint
    tech_adp = TechnologyFingerprintAdapter()
    req_t = ActionRequest(
        id="act-tf-01",
        task_id="t1",
        agent="recon_agent",
        action_type="recon.tech_fingerprint",
        target_refs=["http://target.local"],
        parameters={"headers": {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.3"}},
    )
    res_t, raw_t, _ = await tech_adp.run(req_t)
    assert res_t.success is True
    data_t = json.loads(raw_t.decode("utf-8"))
    assert "technologies" in data_t

    # 2. OSINT
    osint_adp = OSINTAdapter()
    req_o = ActionRequest(
        id="act-os-01",
        task_id="t1",
        agent="recon_agent",
        action_type="recon.osint_gather",
        target_refs=["target.local"],
    )
    res_o, raw_o, _ = await osint_adp.run(req_o)
    assert res_o.success is True
