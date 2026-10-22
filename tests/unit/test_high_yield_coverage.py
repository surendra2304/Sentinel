"""High-yield unit test suite expanding coverage across critical Sentinel subsystems."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

import sentinel.modules.threat_intel as threat_intel_mod
from sentinel.core.models import ActionRequest
from sentinel.intelligence.threat_context import threat_context_enricher
from sentinel.memora_cloud_fallback import MemoraClient
from sentinel.modules.vulnerability.correlation import VulnerabilityCorrelationAdapter
from sentinel.storage.artifacts.storage import (
    LocalFileSystemStorage,
    get_artifact_storage,
)


@pytest.mark.asyncio
async def test_threat_context_enricher():
    class DummyResearch:
        exploitation_active = True
        threat_actors = ["APT29"]
        patch_available = False
        urgency_multiplier = 1.8
        citations = ["https://cve.mitre.org/cve/1"]
        cached = False

    with patch("sentinel.intelligence.threat_context.intelx_research_client.submit_research", new_callable=AsyncMock) as mock_submit:
        mock_submit.return_value = DummyResearch()
        res = await threat_context_enricher.enrich_finding_with_research("CVE-2026-9999", force=True)
        assert res["exploitation_active"] is True
        assert res["threat_actors"] == ["APT29"]
        assert res["urgency_multiplier"] == 1.8
        assert res["cached"] is False
        mock_submit.assert_called_once_with("CVE-2026-9999", force=True)


def test_threat_intel_module():
    assert threat_intel_mod.__version__ == "0.1.0"


@pytest.mark.asyncio
async def test_local_filesystem_artifact_storage(tmp_path):
    storage = LocalFileSystemStorage(base_dir=str(tmp_path))
    key = "evidence/scan_results.json"
    data = b'{"status": "clean"}'

    # Store
    uri, digest = await storage.store_artifact(key, data, content_type="application/json")
    assert uri.startswith("file://")
    assert digest is not None

    # Exists
    assert await storage.exists(key) is True
    assert await storage.exists("nonexistent.txt") is False

    # Get
    retrieved = await storage.get_artifact(key)
    assert retrieved == data

    # Delete
    assert await storage.delete_artifact(key) is True
    assert await storage.delete_artifact(key) is False
    assert await storage.exists(key) is False

    # Path traversal rejection
    with pytest.raises(ValueError):
        await storage.get_artifact("../outside.txt")
    with pytest.raises(ValueError):
        await storage.get_artifact("/absolute.txt")


def test_get_artifact_storage_factory():
    storage = get_artifact_storage()
    assert isinstance(storage, LocalFileSystemStorage)


def test_memora_client_unconfigured_and_methods():
    client = MemoraClient(base_url="", api_key=None)

    # Missing API key
    res_no_key = client.record_interaction("sentinel", "hello", "world")
    assert res_no_key["status"] == "error"
    assert "is not configured" in res_no_key["error"]

    client_with_key = MemoraClient(base_url="", api_key="secret-key")
    res_no_url = client_with_key.record_fact("sentinel", "test fact")
    assert res_no_url["status"] == "error"
    assert "MEMORA_URL is not configured" in res_no_url["error"]


@pytest.mark.asyncio
@respx.mock
async def test_memora_client_request_async():
    client = MemoraClient(base_url="https://memora.example", api_key="test-key")
    respx.post("https://memora.example/v1/memories").mock(
        return_value=httpx.Response(200, json={"status": "recorded"})
    )
    res = await client._request_async(
        "sentinel", "/v1/memories", method="POST", payload={"data": "test"}
    )
    assert res["status"] == "recorded"
    assert res["cloud"] is True



@pytest.mark.asyncio
async def test_vulnerability_correlation_adapter():
    adapter = VulnerabilityCorrelationAdapter()
    assert adapter.name == "vulnerability_correlation_adapter"
    assert adapter.version == "1.0.0"
    assert "vulnerability.correlate" in adapter.capabilities
    assert await adapter.health_check() is True

    # Validate params: invalid
    invalid_action = ActionRequest(
        id="act-1",
        task_id="tsk-1",
        agent="test",
        action_type="vulnerability.correlate",
        parameters={},
        target_refs=[],
    )
    ok, err = adapter.validate_params(invalid_action)
    assert ok is False
    assert err is not None

    # Validate params: valid
    valid_action = ActionRequest(
        id="act-2",
        task_id="tsk-1",
        agent="test",
        action_type="vulnerability.correlate",
        parameters={"technology": "nginx", "version": "1.18.0"},
        target_refs=["asset-1"],
    )
    ok_valid, err_valid = adapter.validate_params(valid_action)
    assert ok_valid is True
    assert err_valid is None

    # Run
    result, raw_evidence, mime = await adapter.run(valid_action)
    assert result.success is True
    assert mime == "application/json"
