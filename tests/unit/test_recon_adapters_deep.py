"""Recon and Asset Discovery Deep Unit Tests."""

import json

import pytest

from sentinel.core.models import ActionRequest
from sentinel.modules.recon import adapters as recon_adapters
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
        target_refs=["authorized.invalid"],
        parameters={"passive_only": True, "wordlist": ["api", "www"]},
    )
    res, raw, _ = await adp.run(req)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert data["domain"] == "authorized.invalid"
    assert data["sources"]["external_lookup_performed"] is False
    assert "sources" in data


@pytest.mark.asyncio
async def test_subdomain_adapter_requires_explicit_third_party_consent(monkeypatch):
    def reject_external_request(*_args, **_kwargs):
        raise AssertionError("third-party CT lookup must require scope consent")

    monkeypatch.setattr(recon_adapters.httpx, "AsyncClient", reject_external_request)
    action = ActionRequest(
        id="no-third-party-consent",
        task_id="no-third-party-consent-task",
        agent="recon_agent",
        action_type="recon.subdomains",
        target_refs=["private.example.invalid"],
        parameters={"passive_only": True},
    )

    _, raw, _ = await SubdomainEnumAdapter().run(action)
    sources = json.loads(raw)["sources"]
    assert sources["external_lookup_performed"] is False
    assert "not authorized" in sources["crt_sh_skipped"]


@pytest.mark.asyncio
async def test_ip_intelligence_adapter_uses_mocked_public_enrichment(monkeypatch):
    requests = []
    transport = recon_adapters.httpx.MockTransport(
        lambda request: _mock_ip_intelligence_response(request, requests)
    )
    real_async_client = recon_adapters.httpx.AsyncClient

    def client_factory(*args, **kwargs):
        return real_async_client(*args, transport=transport, **kwargs)

    monkeypatch.setattr(recon_adapters.httpx, "AsyncClient", client_factory)
    action = ActionRequest(
        id="act-ip-01",
        task_id="t1",
        agent="recon_agent",
        action_type="recon.ip_intel",
        target_refs=["8.8.8.8"],
        parameters={"allow_third_party_enrichment": True},
    )
    result, raw, _ = await IPIntelligenceAdapter().run(action)
    data = json.loads(raw)

    assert result.success is True
    assert data["ip"] == "8.8.8.8"
    assert data["country"] == "United States"
    assert data["external_lookup_performed"] is True
    assert requests == ["http://ip-api.com/json/8.8.8.8"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "consent"),
    [
        ("8.8.8.8", False),
        ("172.31.9.10", True),
        ("https://[fc00::1]/", True),
        ("db.internal", True),
    ],
)
async def test_ip_intelligence_never_looks_up_without_consent_or_for_non_public_hosts(monkeypatch, target, consent):
    def reject_external_request(*_args, **_kwargs):
        raise AssertionError("unapproved or non-public GeoIP lookup attempted")

    monkeypatch.setattr(recon_adapters.httpx, "AsyncClient", reject_external_request)
    action = ActionRequest(
        id=f"ip-no-lookup-{target}",
        task_id="ip-no-lookup-task",
        agent="recon_agent",
        action_type="recon.ip_intel",
        target_refs=[target],
        parameters={"allow_third_party_enrichment": consent},
    )

    result, raw, _ = await IPIntelligenceAdapter().run(action)
    data = json.loads(raw)
    assert result.success is True
    assert data["external_lookup_performed"] is False
    assert "skipped" in data["fallback_note"].lower()


def _mock_ip_intelligence_response(request, captured):
    captured.append(str(request.url))
    return recon_adapters.httpx.Response(
        200,
        json={
            "query": "8.8.8.8",
            "country": "United States",
            "city": "Mountain View",
            "as": "AS15169 Google LLC",
            "org": "Google LLC",
        },
    )


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
