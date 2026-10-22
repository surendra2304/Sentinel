"""Integration and contract tests for Threat Intelligence and Incident/Quarantine REST APIs."""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api.main import app


@pytest.mark.asyncio
async def test_threat_intel_extract_iocs_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "text": "Outbound connection to 198.51.100.200 and hxxp://evil-c2[.]darknet/c2 via CVE-2023-38606"
        }
        res = await client.post("/v1/intel/extract-iocs", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["count"] >= 3
        types = {i["ioc_type"] for i in data["iocs"]}
        assert "ipv4" in types
        assert "url" in types
        assert "cve" in types


@pytest.mark.asyncio
async def test_threat_intel_mitre_map_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "text": "Invoked powershell.exe -EncodedCommand base64",
            "title": "Suspicious PowerShell Execution",
        }
        res = await client.post("/v1/intel/mitre-map", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["count"] >= 1
        tech_ids = [t["id"] for t in data["techniques"]]
        assert "T1059.001" in tech_ids


@pytest.mark.asyncio
async def test_threat_intel_reputation_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Known malicious domain
        res_mal = await client.post(
            "/v1/intel/reputation",
            json={"indicator": "evil-c2.darknet", "ioc_type": "domain"},
        )
        assert res_mal.status_code == 200
        assert res_mal.json()["reputation"]["is_malicious"] is True
        assert res_mal.json()["reputation"]["score"] >= 90.0

        # 2. Invalid ioc_type
        res_bad = await client.post(
            "/v1/intel/reputation",
            json={"indicator": "test", "ioc_type": "unsupported_type"},
        )
        assert res_bad.status_code == 400


@pytest.mark.asyncio
async def test_threat_intel_full_analyze_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "text": "Attack from 198.51.100.200 using mimikatz to dump lsass memory. Targeted evil-c2.darknet."
        }
        res = await client.post("/v1/intel/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "report" in data
        assert data["report"]["overall_threat_score"] >= 80.0
        assert data["report"]["overall_risk_tier"] == "critical"


@pytest.mark.asyncio
async def test_incident_and_quarantine_api_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Open Incident
        inc_payload = {
            "id": "inc-api-001",
            "tenant_id": "tenant-api-test",
            "title": "API Key Leak in Public Repo",
            "severity": "CRITICAL",
            "reason": "Exposed OpenAI API key in client bundle",
            "evidence_refs": ["evi-bundle-01"],
        }
        res_open = await client.post("/v1/incidents", json=inc_payload)
        assert res_open.status_code == 200
        assert res_open.json()["incident"]["id"] == "inc-api-001"
        assert res_open.json()["incident"]["state"] == "OPEN"

        # 2. List Incidents
        res_list = await client.get("/v1/incidents?tenant_id=tenant-api-test")
        assert res_list.status_code == 200
        assert res_list.json()["count"] >= 1

        # 3. Triage
        res_triage = await client.post(
            "/v1/incidents/inc-api-001/triage",
            json={"assigned_to": "analyst-bob", "notes": "Revocation in progress"},
        )
        assert res_triage.status_code == 200
        assert res_triage.json()["incident"]["state"] == "TRIAGED"

        # 4. Contain (with quarantine)
        res_contain = await client.post(
            "/v1/incidents/inc-api-001/contain",
            json={
                "auto_quarantine_subject": "compromised-key-12345",
                "quarantine_ttl_seconds": 1800.0,
            },
        )
        assert res_contain.status_code == 200
        assert res_contain.json()["incident"]["contained"] is True
        assert res_contain.json()["incident"]["state"] == "CONTAINED"

        # 5. Check Quarantine Endpoint
        res_q_list = await client.get("/v1/quarantine")
        assert res_q_list.status_code == 200
        subjects = [item["subject"] for item in res_q_list.json()["quarantined_items"]]
        assert "compromised-key-12345" in subjects

        # 6. Close Incident
        res_close = await client.post(
            "/v1/incidents/inc-api-001/close",
            json={"resolution_notes": "API key rotated and invalidated on provider."},
        )
        assert res_close.status_code == 200
        assert res_close.json()["incident"]["state"] == "CLOSED"

        # 7. Check MTTC metrics
        res_metrics = await client.get("/v1/incidents/metrics/mttc?tenant_id=tenant-api-test")
        assert res_metrics.status_code == 200
        assert res_metrics.json()["metrics"]["total_contained"] >= 1

        # 8. Lift Quarantine
        res_lift = await client.delete("/v1/quarantine/compromised-key-12345")
        assert res_lift.status_code == 200
        assert res_lift.json()["lifted"] is True
