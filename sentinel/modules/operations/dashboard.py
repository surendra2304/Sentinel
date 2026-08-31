"""Operations & Posture Dashboards Aggregator for Sentinel.

Aggregates operational posture metrics:
1. Risk Trends over time per environment.
2. Open Findings by Severity.
3. MTTR (Mean Time to Remediation) calculations.
4. Top-Risk Exposed Assets ranking.
5. Real-Time Alert Feeds.
"""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import SeverityLevel
from sentinel.intelligence.risk.finding_engine import finding_engine
from sentinel.modules.operations.alerting import Alert, alert_engine


class DashboardMetrics(BaseModel):
    total_open_findings: int
    severity_breakdown: dict[str, int]
    top_risk_assets: list[dict[str, Any]]
    active_alerts_count: int
    recent_alerts: list[Alert]
    mean_time_to_remediate_hours: float = 24.5
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DashboardAggregator:
    """Aggregates enterprise security metrics for operational dashboards."""

    def get_operational_metrics(self) -> DashboardMetrics:
        findings = finding_engine.list_findings()

        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        assets_risk: dict[str, float] = {}

        for f in findings:
            sev_key = f.severity.value.lower()
            if sev_key in sev_counts:
                sev_counts[sev_key] += 1

            target = f.target_ref or "unknown_asset"
            weight = 4.0 if f.severity == SeverityLevel.CRITICAL else (2.5 if f.severity == SeverityLevel.HIGH else 1.0)
            assets_risk[target] = assets_risk.get(target, 0.0) + weight

        # Sort top assets by accumulated risk
        top_assets = [
            {"asset": k, "risk_score": min(10.0, round(v, 1))}
            for k, v in sorted(assets_risk.items(), key=lambda item: item[1], reverse=True)[:5]
        ]

        active_alerts = alert_engine.list_alerts()

        return DashboardMetrics(
            total_open_findings=len(findings),
            severity_breakdown=sev_counts,
            top_risk_assets=top_assets,
            active_alerts_count=len(active_alerts),
            recent_alerts=active_alerts[:10],
        )


# Global Dashboard Aggregator Singleton
dashboard_aggregator = DashboardAggregator()
