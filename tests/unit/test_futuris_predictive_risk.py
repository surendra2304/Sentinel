"""Futuris Threat Forecasting & Predictive Risk Integration Test Suite.

Verifies:
1. FuturisThreatClient: 48h threat escalation forecast, vulnerability exploitation risk, and risk trajectory calculations.
2. PredictiveRiskWorkflow: Finding enrichment with predicted exploitation probability and proactive scan trigger evaluations.
3. API Endpoint /metrics/predictive-forecasts: Returning forecast confidence, risk trajectory, and automated scan recommendations.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api.main import app
from sentinel.core.models import Finding, SeverityLevel
from sentinel.integrations.futuris_client import futuris_threat_client, ForecastType, RiskTrajectory
from sentinel.intelligence.predictive_workflow import predictive_risk_workflow


@pytest.mark.asyncio
async def test_futuris_threat_client_forecasts():
    # 1. Threat Escalation Forecast (with active threat actor telemetry)
    escalation = await futuris_threat_client.get_threat_escalation_forecast(
        asset_target="api.payment.corp",
        threat_intel_context={"threat_actors": ["APT28"], "exploitation_active": True},
    )
    assert escalation.forecast_type == ForecastType.THREAT_ESCALATION
    assert escalation.probability >= 0.8
    assert escalation.risk_trajectory == RiskTrajectory.GROWING
    assert escalation.proactive_scan_recommended is True
    assert escalation.recommended_scan_interval_hours == 6

    # 2. Vulnerability Exploitation Risk Forecast
    exploit_forecast = await futuris_threat_client.get_vulnerability_exploitation_risk(
        cve_id="CVE-2024-3400",
        target_ref="vpn.corp.internal",
        intelx_context={"exploitation_active": True},
    )
    assert exploit_forecast.forecast_type == ForecastType.VULNERABILITY_EXPLOITATION_RISK
    assert exploit_forecast.probability > 0.9
    assert exploit_forecast.proactive_scan_recommended is True


@pytest.mark.asyncio
async def test_predictive_risk_workflow_enrichment_and_proactive_scans():
    # 1. Finding enrichment
    finding = Finding(
        id="find-futuris-01",
        task_id="task-f-01",
        title="Palo Alto PAN-OS Command Injection",
        description="Active zero-day command injection in GlobalProtect portal.",
        target_ref="vpn.corp.internal",
        severity=SeverityLevel.CRITICAL,
        evidence_refs=["evi-01"],
        related_cves=["CVE-2024-3400"],
    )

    enriched = await predictive_risk_workflow.enrich_finding_with_futuris(
        finding=finding,
        intelx_ctx={"exploitation_active": True},
    )
    assert enriched["predicted_exploitation_probability"] > 0.9
    assert enriched["auto_escalate_priority"] is True
    assert enriched["risk_trajectory"] == "growing"

    # 2. Proactive scanning needs evaluation
    recs = await predictive_risk_workflow.evaluate_proactive_scanning_needs(
        assets=["gateway.prod.corp", "auth.prod.corp"],
        threat_intel_context={"exploitation_active": True},
    )
    assert len(recs) == 2
    assert recs[0]["priority"] == "URGENT"
    assert recs[0]["scan_frequency_hours"] == 6


@pytest.mark.asyncio
async def test_predictive_forecasts_api_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/metrics/predictive-forecasts")
        assert res.status_code == 200
        data = res.json()
        assert "threat_forecasts" in data
        assert len(data["threat_forecasts"]) >= 1
        assert data["risk_trajectory"] == "growing"
        assert len(data["proactive_scan_recommendations"]) >= 1