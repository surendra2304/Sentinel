"""Deep adapter coverage tests for recon, api_security, and endpoint modules."""

import base64
import json

import httpx
import pytest
import respx

from sentinel.core.models import ActionRequest
from sentinel.modules.api_security.adapters import (
    JWTAuthAnalysisAdapter,
    OpenAPISchemaParserAdapter,
)
from sentinel.modules.endpoint.adapters import (
    OfflineAssessmentAdapter,
)
from sentinel.modules.recon.adapters import (
    IPIntelligenceAdapter,
    TechnologyFingerprintAdapter,
)


@pytest.mark.asyncio
async def test_ip_intelligence_adapter_private_and_hostname():
    adapter = IPIntelligenceAdapter()
    assert adapter.name == "ip_intelligence_adapter"
    assert await adapter.health_check() is True

    # Validation failure
    invalid_action = ActionRequest(
        id="act-ip-1",
        task_id="tsk-ip-1",
        agent="recon",
        action_type="recon.ip_intel",
        parameters={},
        target_refs=[],
    )
    ok, err = adapter.validate_params(invalid_action)
    assert ok is False

    # Private IP
    priv_action = ActionRequest(
        id="act-ip-2",
        task_id="tsk-ip-1",
        agent="recon",
        action_type="recon.ip_intel",
        parameters={},
        target_refs=["192.168.1.1"],
    )
    res, raw, mime = await adapter.run(priv_action)
    assert res.success is True
    data = json.loads(raw.decode())
    assert data["is_private"] is True
    assert "Internal" in data["org"]

    # Hostname (skipped external lookup)
    host_action = ActionRequest(
        id="act-ip-3",
        task_id="tsk-ip-1",
        agent="recon",
        action_type="recon.ip_intel",
        parameters={},
        target_refs=["api.example.com"],
    )
    res_h, raw_h, _ = await adapter.run(host_action)
    assert res_h.success is True
    assert "External GeoIP lookup skipped" in json.loads(raw_h.decode())["fallback_note"]


@pytest.mark.asyncio
@respx.mock
async def test_ip_intelligence_adapter_public_ip_with_consent():
    adapter = IPIntelligenceAdapter()
    respx.get("http://ip-api.com/json/8.8.8.8").mock(
        return_value=httpx.Response(200, json={
            "query": "8.8.8.8",
            "country": "United States",
            "city": "Ashburn",
            "as": "AS15169 Google LLC",
            "org": "Google LLC",
        })
    )
    action = ActionRequest(
        id="act-ip-pub",
        task_id="tsk-ip-1",
        agent="recon",
        action_type="recon.ip_intel",
        parameters={"allow_third_party_enrichment": True},
        target_refs=["8.8.8.8"],
    )
    res, raw, _ = await adapter.run(action)
    assert res.success is True
    data = json.loads(raw.decode())
    assert data["country"] == "United States"
    assert "Google" in data["org"]


@pytest.mark.asyncio
async def test_jwt_auth_analysis_adapter_alg_none():
    adapter = JWTAuthAnalysisAdapter()
    assert adapter.name == "jwt_auth_analysis_adapter"
    assert await adapter.health_check() is True

    # Validate failure
    invalid_action = ActionRequest(
        id="act-jwt-1",
        task_id="tsk-jwt-1",
        agent="api_sec",
        action_type="api.jwt_audit",
        parameters={},
        target_refs=[],
    )
    ok, err = adapter.validate_params(invalid_action)
    assert ok is False

    # Alg: none token
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"admin","role":"root"}').decode().rstrip("=")
    raw_token = f"{header}.{payload}."

    action = ActionRequest(
        id="act-jwt-2",
        task_id="tsk-jwt-1",
        agent="api_sec",
        action_type="api.jwt_audit",
        parameters={"token": raw_token},
        target_refs=[],
    )
    res, raw, _ = await adapter.run(action)
    assert res.success is True
    data = json.loads(raw.decode())
    findings = data["findings"]
    assert any(f["type"] == "JWT_INSECURE_ALGORITHM" for f in findings)


@pytest.mark.asyncio
async def test_openapi_schema_parser_adapter():
    adapter = OpenAPISchemaParserAdapter()
    assert adapter.name == "openapi_schema_parser_adapter"
    assert await adapter.health_check() is True

    sample_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {"responses": {"200": {"description": "OK"}}},
                "post": {"responses": {"201": {"description": "Created"}}},
            }
        },
    }
    action = ActionRequest(
        id="act-oa-1",
        task_id="tsk-oa-1",
        agent="api_sec",
        action_type="api.schema_parse",
        parameters={"spec_json": sample_spec},
        target_refs=[],
    )
    res, raw, _ = await adapter.run(action)
    assert res.success is True
    data = json.loads(raw.decode())
    assert data["total_endpoints"] == 2


@pytest.mark.asyncio
async def test_technology_fingerprint_adapter():
    adapter = TechnologyFingerprintAdapter()
    assert adapter.name == "technology_fingerprint_adapter"

    action = ActionRequest(
        id="act-tf-1",
        task_id="tsk-tf-1",
        agent="recon",
        action_type="recon.fingerprint",
        parameters={"headers": {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4"}},
        target_refs=["http://target.corp"],
    )
    res, raw, _ = await adapter.run(action)
    assert res.success is True
    data = json.loads(raw.decode())
    assert "technologies" in data


@pytest.mark.asyncio
async def test_offline_assessment_adapter():
    from sentinel.modules.endpoint.models import EndpointExportData

    adapter = OfflineAssessmentAdapter()
    export = EndpointExportData(
        hostname="test-host",
        os_platform="linux",
        kernel_version="5.10.0",
        raw_configs={
            "/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes",
            "/etc/sudoers": "admin ALL=(ALL) NOPASSWD: ALL",
        },
    )
    rules = {
        "linux_rules": [
            {
                "id": "EP-LNX-001",
                "name": "SSH Root Login",
                "severity": "HIGH",
                "description": "desc",
                "remediation": "rem",
            },
            {
                "id": "EP-LNX-002",
                "name": "Password Auth",
                "severity": "MEDIUM",
                "description": "desc",
                "remediation": "rem",
            },
            {
                "id": "EP-LNX-003",
                "name": "Sudo NOPASSWD",
                "severity": "HIGH",
                "description": "desc",
                "remediation": "rem",
            },
        ]
    }
    findings = adapter.evaluate_export(export, rules)
    assert len(findings) == 3

