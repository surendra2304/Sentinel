import pytest

from sentinel.core.models import SeverityLevel
from sentinel.modules.operations.alerting import AlertEngine, AlertStatus
from sentinel.modules.operations.baseline import (
    BaselineEngine,
    ChangeType,
    SecurityBaselineSnapshot,
)
from sentinel.modules.operations.dashboard import DashboardAggregator
from sentinel.modules.operations.scheduler import AssessmentScheduler


@pytest.mark.asyncio
async def test_continuous_monitoring_baseline_and_alerting():
    b_engine = BaselineEngine()
    a_engine = AlertEngine()
    scheduler = AssessmentScheduler()
    job = scheduler.add_monitoring_job("job-1", "Prod App Watch", "prod-app.sentinel.internal", 60)
    assert job.status.value == "active"

    target = "prod-app.sentinel.internal"

    # 1. Establish Initial Baseline Snapshot
    snap_1 = SecurityBaselineSnapshot(
        snapshot_id="snap-001",
        target_ref=target,
        open_ports=[80, 443],
        dns_records={"A": ["10.0.0.5"]},
        active_findings=["Missing HSTS Header"],
        cert_expiry_days=45,
    )
    deltas_1 = b_engine.compute_deltas(target, snap_1)
    assert len(deltas_1) == 0  # Initial baseline generates no deltas

    # 2. Mutate Target (Open New SSH Port + Expirying Cert + DNS changed)
    snap_2 = SecurityBaselineSnapshot(
        snapshot_id="snap-002",
        target_ref=target,
        open_ports=[80, 443, 22],
        dns_records={"A": ["10.0.0.6"]},
        active_findings=["Missing HSTS Header", "Exposed Git Repository"],
        cert_expiry_days=5,
    )
    deltas_2 = b_engine.compute_deltas(target, snap_2)
    assert len(deltas_2) >= 3

    # Verify deltas contain new port 22, DNS change, certificate expiring, and new finding
    change_types = [d.change_type for d in deltas_2]
    assert ChangeType.NEW_PORT in change_types
    assert ChangeType.DNS_RECORD_CHANGED in change_types
    assert ChangeType.CERTIFICATE_EXPIRING in change_types
    assert ChangeType.NEW_FINDING in change_types

    # 3. Process Deltas into Alerts
    alerts = []
    for d in deltas_2:
        alert = a_engine.process_delta(d)
        alerts.append(alert)

    assert len(alerts) >= 3
    port_alert = next(a for a in alerts if a.change_type == ChangeType.NEW_PORT)
    assert port_alert.severity == SeverityLevel.HIGH
    assert port_alert.status == AlertStatus.OPEN

    # 4. Verify Deduplication
    # Processing the same delta again must not create a new alert, but increment occurrence_count
    for d in deltas_2:
        re_alert = a_engine.process_delta(d)
        assert re_alert.occurrence_count >= 2

    # 5. Verify Operator Acknowledgment & Resolution
    ack_alert = a_engine.acknowledge_alert(port_alert.alert_id, operator="sec_engineer")
    assert ack_alert.status == AlertStatus.ACKNOWLEDGED
    assert ack_alert.acknowledged_by == "sec_engineer"

    res_alert = a_engine.resolve_alert(port_alert.alert_id)
    assert res_alert.status == AlertStatus.RESOLVED


def test_dashboard_aggregator_metrics():
    aggregator = DashboardAggregator()
    metrics = aggregator.get_operational_metrics()

    assert metrics.mean_time_to_remediate_hours > 0
    assert "critical" in metrics.severity_breakdown
    assert isinstance(metrics.top_risk_assets, list)
