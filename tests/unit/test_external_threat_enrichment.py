"""Unit and integration tests for External Threat Intelligence & Vulnerability Enrichment."""

import pytest
from httpx import ASGITransport, AsyncClient, Response

from sentinel.apps.api.main import app
from sentinel.modules.threat_intel import (
    ExternalThreatIntelEnricher,
)


@pytest.mark.asyncio
async def test_shodan_enrichment_success_and_offline_mock():
    """Verify Shodan enrichment parses open ports, vulnerabilities, and formats verdict."""
    enricher = ExternalThreatIntelEnricher()

    mock_shodan_response = {
        "ip_str": "140.245.208.100",
        "ports": [80, 443],
        "vulns": ["CVE-2023-1234"],
        "org": "Oracle Corporation",
        "os": "Linux",
    }

    mock_client = AsyncClient()

    async def mock_get(url, **kwargs):
        if "140.245.208.100" in url:
            return Response(200, json=mock_shodan_response)
        elif "1.1.1.1" in url:
            return Response(404, json={"error": "No information available"})
        return Response(500, text="Internal error")

    mock_client.get = mock_get  # type: ignore[assignment]

    # Test IP with vulns
    res1 = await enricher.enrich_ip_shodan("140.245.208.100", client=mock_client)
    assert res1.status == "SUCCESS"
    assert res1.provider == "shodan"
    assert res1.threat_verdict == "MALICIOUS"
    assert "CVE-2023-1234" in res1.data["vulns"]

    # Test 404 IP
    res2 = await enricher.enrich_ip_shodan("1.1.1.1", client=mock_client)
    assert res2.status == "SUCCESS"
    assert res2.threat_verdict == "BENIGN"


@pytest.mark.asyncio
async def test_virustotal_enrichment_mock():
    """Verify VirusTotal hash reputation parsing and caching."""
    enricher = ExternalThreatIntelEnricher()

    mock_vt_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 3,
                    "undetected": 55,
                    "harmless": 0,
                },
                "meaningful_name": "trojan_dropper.exe",
            }
        }
    }

    mock_client = AsyncClient()

    async def mock_get(url, **kwargs):
        if "badhash123" in url:
            return Response(200, json=mock_vt_response)
        return Response(404, json={"error": "not found"})

    mock_client.get = mock_get  # type: ignore[assignment]

    res = await enricher.enrich_hash_virustotal("badhash123", client=mock_client)
    assert res.status == "SUCCESS"
    assert res.provider == "virustotal"
    assert res.threat_verdict == "MALICIOUS"
    assert res.data["malicious_count"] == 12


@pytest.mark.asyncio
async def test_nvd_cve_enrichment_mock():
    """Verify NVD CVE 2.0 API parsing and CVSS score extraction."""
    enricher = ExternalThreatIntelEnricher()

    mock_nvd_response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Log4j RCE vulnerability."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "published": "2021-12-10T10:00:00.000",
                }
            }
        ]
    }

    mock_client = AsyncClient()

    async def mock_get(url, **kwargs):
        if "CVE-2021-44228" in url:
            return Response(200, json=mock_nvd_response)
        return Response(404, json={"vulnerabilities": []})

    mock_client.get = mock_get  # type: ignore[assignment]

    res = await enricher.enrich_cve_nvd("CVE-2021-44228", client=mock_client)
    assert res.status == "SUCCESS"
    assert res.provider == "nvd"
    assert res.threat_verdict == "MALICIOUS"
    assert res.data["cvss_score"] == 10.0


@pytest.mark.asyncio
async def test_enrichment_api_endpoint():
    """Verify POST /v1/intel/enrich endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Enrich CVE with Auto-detection
        res = await client.post("/v1/intel/enrich", json={"indicator": "CVE-2021-44228"})
        assert res.status_code == 200
        data = res.json()
        assert "enrichment" in data
        assert data["enrichment"]["provider"] == "nvd"

        # 2. Enrich Hash with explicit indicator_type
        res_hash = await client.post(
            "/v1/intel/enrich",
            json={
                "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "indicator_type": "hash",
            },
        )
        assert res_hash.status_code == 200
        assert res_hash.json()["enrichment"]["provider"] == "virustotal"
