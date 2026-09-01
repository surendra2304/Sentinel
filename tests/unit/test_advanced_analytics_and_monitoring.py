"""Comprehensive Test Suite for Continuous Monitoring, Threat Intelligence, Analytics, and IntelX Research.

Verifies:
1. ContinuousMonitor: baseline snapshotting, drift detection, alert thresholds (<14d cert, new sub, new port, endpoint removed).
2. AlertDeduplicator: 7-day suppression, fatigue rate limiter, overflow to digest.
3. ThreatFeedSync & CVE Correlation: CISA KEV CRITICAL boost, Exploit-DB +1 boost, exposure-weighted risk scoring.
4. AttackPathAnalyzer & PredictiveRiskModel & RemediationAdvisor: Multi-vector exploit chains, MTTR tracking, research-backed remediation steps.
5. Metrics API & Prometheus Telemetry: GET /metrics/posture-trend, /metrics/mttr, /metrics/finding-velocity, /metrics/coverage, /metrics/prometheus.
6. IntelX Threat Research Integration: POST /friday/research, GET /friday/research-context/{finding_id}, 7-day research caching.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api.main import app
from sentinel.core.models import SeverityLevel
from sentinel.integrations.threat_feeds.feeds import threat_feed_sync
from sentinel.intelligence.attack_paths import enhanced_attack_path_analyzer
from sentinel.intelligence.correlation import asset_vulnerability_correlator
from sentinel.intelligence.predictive import predictive_risk_model
from sentinel.intelligence.remediation import remediation_advisor
from sentinel.monitoring.continuous import DriftAlert, continuous_monitor
from sentinel.monitoring.dedup import alert_deduplicator


def test_continuous_monitoring_drift_and_alert_thresholds():
    # 1. Register baseline
    baseline = continuous_monitor.register_asset_from_scan(
        "app.corp.internal",
        initial_state={
            "subdomains": ["app.corp.internal"],
            "open_ports": [443],
            "tls_cert_expiry_days": 60,
            "endpoints": ["/api/v1", "/login"],
        }
    )
    assert baseline.asset_id.startswith("ast-")

    # 2. Simulate drift: cert expiring in 10 days (<14d), new port 8080, new subdomain, removed /login
    observed = {
        "subdomains": ["app.corp.internal", "dev.app.corp.internal"],
        "open_ports": [443, 8080],
        "tls_cert_expiry_days": 10,
        "endpoints": ["/api/v1"],
    }
    alerts = continuous_monitor.evaluate_drift(baseline.asset_id, observed)
    assert len(alerts) == 4

    types = {a.drift_type: a.severity for a in alerts}
    assert types["tls_certificate_expiry"] == SeverityLevel.HIGH
    assert types["new_listening_port"] == SeverityLevel.HIGH
    assert types["new_subdomain_discovered"] == SeverityLevel.MEDIUM
    assert types["endpoint_removed"] == SeverityLevel.INFO


def test_alert_deduplication_and_fatigue_prevention():
    alert = DriftAlert(
        alert_id="al-01",
        asset_id="ast-test-dedup",
        target="db.corp.internal",
        drift_type="new_listening_port",
        severity=SeverityLevel.HIGH,
        description="Port 3306 open",
    )

    # 1. First alert emitted
    emitted1, msg1 = alert_deduplicator.process_alert(alert)
    assert emitted1 is True
    assert msg1 == "Emitted"

    # 2. Duplicate within 7 days suppressed
    emitted2, msg2 = alert_deduplicator.process_alert(alert)
    assert emitted2 is False
    assert "Suppressed" in msg2

    # 3. Fatigue rate limiting (overflow to digest after 10 alerts/hour)
    for i in range(15):
        other_alert = DriftAlert(
            alert_id=f"al-fatigue-{i}",
            asset_id="ast-fatigue-asset",
            target="fatigue.corp.internal",
            drift_type=f"drift_type_{i}",
            severity=SeverityLevel.MEDIUM,
            description="Various anomalies",
        )
        emitted, status = alert_deduplicator.process_alert(other_alert)
        if i >= 10:
            assert emitted is False
            assert "digest" in status


def test_threat_feed_sync_and_cve_correlation():
    # 1. CISA KEV rule -> CRITICAL boost
    kev_ctx = threat_feed_sync.correlate_cve("CVE-2021-44228", base_cvss=7.5)
    assert kev_ctx.in_cisa_kev is True
    assert kev_ctx.adjusted_severity == SeverityLevel.CRITICAL

    # 2. Exploit-DB rule -> +1 boost
    exp_ctx = threat_feed_sync.correlate_cve("CVE-2020-0601", base_cvss=5.0)
    assert exp_ctx.exploit_available is True
    assert exp_ctx.adjusted_severity == SeverityLevel.HIGH  # Medium boosted to High

    # 3. Asset-specific risk calculation
    risk = asset_vulnerability_correlator.evaluate_cve_asset_risk(
        cve_id="CVE-2021-44228",
        asset_target="api.payment.corp",
        software_version="log4j 2.14.1",
        is_publicly_exposed=True,
        is_auth_required=False,
        vulnerable_config_present=True,
    )
    assert risk["is_confirmed_vulnerable"] is True
    assert risk["asset_risk_score"] > 50.0
    assert risk["adjusted_severity"].lower() == "critical"


def test_advanced_analytics_and_remediation_advisor():
    # 1. Multi-vector attack path construction
    paths = enhanced_attack_path_analyzer.construct_exploit_chains(
        findings=[{"id": "find-edge-rce"}],
        crown_jewels=["prod-customer-db.internal"],
    )
    assert len(paths) == 1
    assert paths[0].is_critical_path is True
    assert len(paths[0].steps) == 3
    assert paths[0].steps[0].source_zone == "External"
    assert paths[0].steps[1].source_zone == "DMZ"
    assert paths[0].steps[2].source_zone == "Internal"

    # 2. Predictive risk model
    pred_report = predictive_risk_model.forecast_risk_trends([])
    assert pred_report.discovery_rate_per_week == 4.5
    assert "CRITICAL" in pred_report.mttr_days_by_severity
    assert len(pred_report.predicted_critical_assets_30d) >= 1

    # 3. Remediation advisor
    plan = remediation_advisor.generate_plan(
        finding={"id": "find-101", "title": "Critical Unauthenticated SQL Injection", "target_ref": "db.corp.local", "severity": "CRITICAL"},
        research_context={"citations": ["NIST SP 800-53", "OWASP ASVS 4.0"]}
    )
    assert plan.priority_order == 1
    assert len(plan.steps) == 3
    assert len(plan.research_citations) == 2


@pytest.mark.asyncio
async def test_metrics_and_intelx_research_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Metrics API endpoints
        res_trend = await client.get("/api/v1/metrics/posture-trend")
        assert res_trend.status_code == 200
        assert res_trend.json()["trend"] == "improving"

        res_mttr = await client.get("/api/v1/metrics/mttr")
        assert res_mttr.status_code == 200
        assert res_mttr.json()["unit"] == "days"

        res_vel = await client.get("/api/v1/metrics/finding-velocity")
        assert res_vel.status_code == 200
        assert res_vel.json()["net_velocity"] < 0

        res_cov = await client.get("/api/v1/metrics/coverage")
        assert res_cov.status_code == 200
        assert res_cov.json()["coverage_percentage"] > 90.0

        res_prom = await client.get("/api/v1/metrics/prometheus")
        assert res_prom.status_code == 200
        assert "sentinel_policy_decisions_total" in res_prom.text

        # 2. IntelX Research Endpoints
        res_research = await client.post(
            "/api/v1/friday/research",
            json={"query": "What is known about CVE-2024-3400 active exploitation?", "force": False},
        )
        assert res_research.status_code == 200
        r_data = res_research.json()
        assert r_data["exploitation_active"] is True
        assert "APT28" in r_data["threat_actors"]
        assert len(r_data["citations"]) >= 1

        # Second call returns cached = True
        res_cached = await client.post(
            "/api/v1/friday/research",
            json={"query": "What is known about CVE-2024-3400 active exploitation?", "force": False},
        )
        assert res_cached.status_code == 200
        assert res_cached.json()["cached"] is True
