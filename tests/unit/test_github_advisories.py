"""Unit tests for GitHub Advisory Database Feed Ingestion & CVE Synchronization."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from sentinel.core.memory.knowledge_base import KnowledgeBaseStore
from sentinel.core.models import ActionRequest, SeverityLevel
from sentinel.core.orchestrator.adapter import adapter_registry
from sentinel.modules.vulnerability.github_advisories import (
    GitHubAdvisoryClient,
    GitHubAdvisoryFeedAdapter,
    GitHubSecurityAdvisory,
    _map_github_severity,
)


def test_map_github_severity():
    assert _map_github_severity("critical") == SeverityLevel.CRITICAL
    assert _map_github_severity("CRIT") == SeverityLevel.CRITICAL
    assert _map_github_severity("high") == SeverityLevel.HIGH
    assert _map_github_severity("low") == SeverityLevel.LOW
    assert _map_github_severity("moderate") == SeverityLevel.MEDIUM
    assert _map_github_severity(None) == SeverityLevel.MEDIUM
    assert _map_github_severity("unknown") == SeverityLevel.MEDIUM


def test_parse_advisory_payload():
    client = GitHubAdvisoryClient(api_token="test-gh-token")
    raw_payload = {
        "ghsa_id": "GHSA-1234-5678-90ab",
        "cve_id": "CVE-2026-9999",
        "summary": "Remote Code Execution in SamplePkg",
        "description": "Full vulnerability explanation and exploit chain.",
        "severity": "critical",
        "cvss": {
            "score": 9.8,
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "samplepkg"},
                "vulnerable_version_range": "< 2.4.0",
                "first_patched_version": "2.4.0",
            }
        ],
        "references": [
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999"},
            "https://github.com/example/samplepkg/commit/abcdef",
        ],
        "withdrawn_at": None,
    }

    advisory = client.parse_advisory_payload(raw_payload)
    assert advisory.ghsa_id == "GHSA-1234-5678-90ab"
    assert advisory.cve_id == "CVE-2026-9999"
    assert advisory.summary == "Remote Code Execution in SamplePkg"
    assert advisory.severity == SeverityLevel.CRITICAL
    assert advisory.cvss_score == 9.8
    assert advisory.ecosystem == "pip"
    assert advisory.package_name == "samplepkg"
    assert advisory.vulnerable_version_range == "< 2.4.0"
    assert advisory.first_patched_version == "2.4.0"
    assert not advisory.is_withdrawn
    assert len(advisory.references) == 2


@pytest.mark.asyncio
async def test_fetch_advisories_success():
    mock_items = [
        {
            "ghsa_id": "GHSA-test-0001",
            "cve_id": "CVE-2026-0001",
            "summary": "SQL Injection in fast-db",
            "severity": "high",
            "cvss": {"score": 8.5},
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "fast-db"},
                    "vulnerable_version_range": "< 1.2.0",
                }
            ],
        }
    ]

    mock_resp = httpx.Response(
        status_code=200,
        json=mock_items,
        request=httpx.Request("GET", "https://api.github.com/advisories"),
    )
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.return_value = mock_resp

    client = GitHubAdvisoryClient(api_token="ghp_test_token", http_client=mock_client)
    advisories = await client.fetch_advisories(ecosystem="npm", severity="high", limit=10)

    assert len(advisories) == 1
    assert advisories[0].ghsa_id == "GHSA-test-0001"
    assert advisories[0].package_name == "fast-db"
    assert advisories[0].severity == SeverityLevel.HIGH


@pytest.mark.asyncio
async def test_fetch_advisories_rate_limit_and_error_handling():
    mock_resp_403 = httpx.Response(
        status_code=403,
        json={"message": "API rate limit exceeded"},
        request=httpx.Request("GET", "https://api.github.com/advisories"),
    )
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.return_value = mock_resp_403

    client = GitHubAdvisoryClient(http_client=mock_client)
    res_403 = await client.fetch_advisories()
    assert res_403 == []

    # Network exception
    mock_client.get.side_effect = httpx.ConnectError("Connection refused")
    res_err = await client.fetch_advisories()
    assert res_err == []


@pytest.mark.asyncio
async def test_fetch_advisory_by_ghsa():
    mock_data = {
        "ghsa_id": "GHSA-single-test",
        "cve_id": "CVE-2026-8888",
        "summary": "Path traversal in file-server",
        "severity": "critical",
    }
    mock_resp_200 = httpx.Response(
        status_code=200,
        json=mock_data,
        request=httpx.Request("GET", "https://api.github.com/advisories/GHSA-single-test"),
    )
    mock_resp_404 = httpx.Response(
        status_code=404,
        json={"message": "Not Found"},
        request=httpx.Request("GET", "https://api.github.com/advisories/GHSA-nonexistent"),
    )

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.side_effect = [mock_resp_200, mock_resp_404]

    client = GitHubAdvisoryClient(http_client=mock_client)
    adv = await client.fetch_advisory_by_ghsa("GHSA-single-test")
    assert adv is not None
    assert adv.ghsa_id == "GHSA-single-test"
    assert adv.cve_id == "CVE-2026-8888"

    adv_none = await client.fetch_advisory_by_ghsa("GHSA-nonexistent")
    assert adv_none is None


def test_sync_to_knowledge_base():
    kb = KnowledgeBaseStore()
    client = GitHubAdvisoryClient()

    advisories = [
        GitHubSecurityAdvisory(
            ghsa_id="GHSA-sync-01",
            cve_id="CVE-2026-5555",
            summary="Zero-day Auth Bypass",
            description="Allows unauthenticated admin login",
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.9,
            ecosystem="pip",
            package_name="vuln-auth",
            vulnerable_version_range="< 3.0",
        ),
        GitHubSecurityAdvisory(
            ghsa_id="GHSA-sync-02",
            cve_id=None,
            summary="Denial of Service via Regex",
            severity=SeverityLevel.MEDIUM,
            cvss_score=5.3,
            ecosystem="pip",
            package_name="regex-parser",
            vulnerable_version_range="<= 1.0.4",
        ),
    ]

    synced_count = client.sync_to_knowledge_base(advisories, kb=kb)
    assert synced_count == 2

    cve1 = kb.get_cve("CVE-2026-5555")
    assert cve1 is not None
    assert cve1.affected_product == "vuln-auth"
    assert cve1.is_known_exploited is True  # critical + >= 9.0

    cve2 = kb.get_cve("GHSA-SYNC-02")
    assert cve2 is not None
    assert cve2.affected_product == "regex-parser"
    assert cve2.severity == SeverityLevel.MEDIUM


@pytest.mark.asyncio
async def test_github_advisory_feed_adapter_execution():
    adapter = GitHubAdvisoryFeedAdapter()
    assert await adapter.health_check() is True
    assert "vulnerability.github_sync" in adapter.capabilities
    assert "vulnerability.advisory_lookup" in adapter.capabilities

    # Validation failure: lookup without ghsa_id
    invalid_req = ActionRequest(
        id="act-adv-01",
        task_id="tsk-adv-01",
        agent="vulnerability_agent",
        action_type="vulnerability.advisory_lookup",
        parameters={},
    )
    valid, err = adapter.validate_params(invalid_req)
    assert not valid
    assert "ghsa_id" in err

    # Execution: vulnerability.github_sync with mocked client
    mock_adv = GitHubSecurityAdvisory(
        ghsa_id="GHSA-adapter-test",
        cve_id="CVE-2026-4444",
        summary="Remote Buffer Overflow",
        severity=SeverityLevel.HIGH,
        cvss_score=8.1,
        ecosystem="pip",
        package_name="c-extension",
    )

    with patch.object(adapter.client, "fetch_advisories", AsyncMock(return_value=[mock_adv])):
        sync_req = ActionRequest(
            id="act-adv-02",
            task_id="tsk-adv-02",
            agent="vulnerability_agent",
            action_type="vulnerability.github_sync",
            parameters={"ecosystem": "pip", "sync_kb": True},
        )
        result, payload, mime = await adapter.run(sync_req)
        assert result.success is True
        assert "fetched 1 advisories" in result.output_summary
        assert mime == "application/json"

    # Execution: vulnerability.advisory_lookup with mocked client
    with patch.object(adapter.client, "fetch_advisory_by_ghsa", AsyncMock(return_value=mock_adv)):
        lookup_req = ActionRequest(
            id="act-adv-03",
            task_id="tsk-adv-03",
            agent="vulnerability_agent",
            action_type="vulnerability.advisory_lookup",
            parameters={"ghsa_id": "GHSA-adapter-test", "sync_kb": False},
        )
        res_lookup, pay_lookup, _ = await adapter.run(lookup_req)
        assert res_lookup.success is True
        assert "GHSA-adapter-test" in res_lookup.output_summary


def test_github_advisory_adapter_registered_in_orchestrator():
    import sentinel.core.orchestrator.executor  # noqa: F401
    adapter = adapter_registry.get_adapter_for_action("vulnerability.github_sync")
    assert adapter is not None
    assert adapter.name == "github_advisory_feed_adapter"

    adapter_lookup = adapter_registry.get_adapter_for_action("vulnerability.advisory_lookup")
    assert adapter_lookup is not None
    assert adapter_lookup.name == "github_advisory_feed_adapter"
