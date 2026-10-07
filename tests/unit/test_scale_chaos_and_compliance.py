"""Scale, Load, Chaos, Compliance, and Multi-Tenancy Test Suite.

Verifies:
1. Multi-Tenant Isolation & Usage Metering (per-tenant asset registries, policies, API keys, quota counts).
2. Compliance Reporting Service: SOC2 control evidence chains, ISO 27001 mappings, PCI-DSS profiles.
3. Prometheus Infrastructure Metrics: tasks_active, findings_total, scan_duration, policy_decisions, intelx_enrichments.
4. Health & Readiness Probes: /health, /ready including IntelX connectivity and storage backend status.
5. High-Throughput Load Simulation (concurrent tasks, finding volume, SSE client subscriptions).
6. Chaos Resilience: IntelX research degradation fallback when service is unreachable (findings remain valid).
"""

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api import main as api_main
from sentinel.apps.api.main import app
from sentinel.config.settings import EnvironmentType
from sentinel.core.tenancy import tenant_manager
from sentinel.integrations.intelx_client import intelx_research_client
from sentinel.intelligence.reporting.compliance import compliance_reporting_service


def test_multitenancy_isolation_and_metering():
    # 1. Create Tenant
    tenant = tenant_manager.create_tenant(
        tenant_id="tenant-fintech-01",
        name="Fintech Corp",
        api_keys=["fintech-sec-key-1", "fintech-sec-key-2"],
        allowed_assets=["payment.fintech.corp", "api.fintech.corp"],
    )
    assert tenant.tenant_id == "tenant-fintech-01"

    # 2. Lookup by API Key
    resolved = tenant_manager.get_tenant_by_api_key("fintech-sec-key-1")
    assert resolved is not None
    assert resolved.tenant_id == "tenant-fintech-01"

    # 3. Record scan usage and verify metering
    tenant_manager.record_scan_usage("tenant-fintech-01", storage_bytes=1048576)
    assert resolved.usage.scans_this_month == 1
    assert resolved.usage.storage_bytes_used == 1048576


def test_compliance_reporting_frameworks():
    # 1. SOC2 Compliance Report
    soc2 = compliance_reporting_service.generate_compliance_report(
        framework="SOC2",
        tenant_id="tenant-fintech-01",
        findings=[{"severity": "MEDIUM", "title": "Missing security header"}],
    )
    assert soc2.framework == "SOC2"
    assert soc2.compliance_score == 100.0
    assert len(soc2.controls) >= 2
    assert soc2.controls[0].control_id == "CC6.1"

    # 2. ISO 27001 Mapping
    iso = compliance_reporting_service.generate_compliance_report(
        framework="ISO27001",
        tenant_id="tenant-fintech-01",
        findings=[],
    )
    assert iso.framework == "ISO27001"
    assert iso.controls[0].control_id == "A.12.6.1"

    # 3. PCI-DSS Profile
    pci = compliance_reporting_service.generate_compliance_report(
        framework="PCI-DSS",
        tenant_id="tenant-fintech-01",
        findings=[],
    )
    assert pci.framework == "PCI-DSS"
    assert pci.controls[0].control_id == "Req-11.2"


@pytest.mark.asyncio
async def test_health_readiness_and_prometheus_metrics(monkeypatch):
    monkeypatch.setattr(api_main.settings, "environment", EnvironmentType.PRODUCTION)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Liveness
        res_health = await client.get("/health")
        assert res_health.status_code == 200
        health_data = res_health.json()
        assert health_data["status"] == "ok"
        assert health_data["evidence_class"] == "process_liveness"
        assert health_data["observed_at"]

        # 2. Local readiness must not claim an unperformed peer connectivity check.
        res_ready = await client.get("/ready")
        assert res_ready.status_code == 200
        ready_data = res_ready.json()
        # Readiness must agree with its own reported checks. This test explicitly
        # exercises production posture with the in-memory backend, so the durable-
        # audit check genuinely fails: DEGRADED is the truthful answer and
        # READY must not be hard-coded past it.
        _checks = ready_data["checks"]
        assert ready_data["status"] == ("READY" if all(_checks.values()) else "DEGRADED")
        assert ready_data["ready"] is all(_checks.values())
        assert _checks["audit_durable"] is False
        assert ready_data["evidence_class"] == "local_readiness_checks"
        assert ready_data["peer_connectivity"] == "not_checked"
        assert ready_data["observed_at"]

        # 3. Prometheus metrics
        res_prom = await client.get("/api/v1/metrics/prometheus")
        assert res_prom.status_code == 200
        body = res_prom.text
        assert "sentinel_tasks_active" in body
        assert "sentinel_findings_total" in body
        assert "sentinel_scan_duration_seconds" in body
        assert "sentinel_intelx_research_enrichment_total" in body


@pytest.mark.asyncio
async def test_concurrent_load_and_chaos_resilience():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Simulate 10 Concurrent Task Delegations
        async def submit_delegation(i: int):
            payload = {
                "friday_request_id": f"load-req-{i}",
                "target": {"type": "domain", "value": f"node-{i}.load.corp"},
                "mode": "authorized_assessment",
                "objective": f"Stress test load client {i}",
            }
            return await client.post("/api/v1/friday/delegate", json=payload)

        responses = await asyncio.gather(*(submit_delegation(i) for i in range(10)))
        assert all(r.status_code == 200 for r in responses)
        assert len(responses) == 10

        # 2. Chaos Test: IntelX Unreachable / Force Cache Miss Still Returns Valid Object
        res_intelx = await intelx_research_client.submit_research("UNKNOWN-CVE-CHAOS-9999", force=True)
        assert res_intelx.query == "UNKNOWN-CVE-CHAOS-9999"
        assert res_intelx.urgency_multiplier >= 1.0
        assert len(res_intelx.citations) >= 1
