"""Proactive Scanning Workflow and Predictive Risk Scoring using Futuris Telemetry."""

from typing import Any

from sentinel.core.models import Finding
from sentinel.integrations.futuris_client import (
    FuturisForecastResult,
    futuris_threat_client,
)


class PredictiveRiskWorkflow:
    """Enriches Sentinel findings and triggers proactive assessments based on forecast signals."""

    @staticmethod
    async def enrich_finding_with_futuris(
        finding: Finding,
        intelx_ctx: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Calculates predicted exploitation probability and risk trajectory."""
        cve = finding.related_cves[0] if finding.related_cves else finding.title
        forecast: FuturisForecastResult = await futuris_threat_client.get_vulnerability_exploitation_risk(
            cve_id=cve,
            target_ref=finding.target_ref,
            is_public=True,
            intelx_context=intelx_ctx,
        )

        return {
            "finding_id": finding.id,
            "title": finding.title,
            "target_ref": finding.target_ref,
            "predicted_exploitation_probability": forecast.probability,
            "forecast_confidence": forecast.confidence,
            "risk_trajectory": forecast.risk_trajectory.value,
            "auto_escalate_priority": forecast.probability > 0.7,
            "proactive_scan_recommended": forecast.proactive_scan_recommended,
            "reasoning": forecast.reasoning,
        }

    @staticmethod
    async def evaluate_proactive_scanning_needs(
        assets: list[str],
        threat_intel_context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Determines if threat escalation warrants automatic proactive scan scheduling."""
        recommendations = []
        for asset in assets:
            forecast = await futuris_threat_client.get_threat_escalation_forecast(
                asset_target=asset,
                threat_intel_context=threat_intel_context,
            )
            if forecast.proactive_scan_recommended:
                recommendations.append({
                    "asset": asset,
                    "reason": forecast.reasoning,
                    "escalation_probability": forecast.probability,
                    "scan_frequency_hours": forecast.recommended_scan_interval_hours,
                    "priority": "URGENT" if forecast.probability > 0.8 else "HIGH",
                })
        return recommendations


predictive_risk_workflow = PredictiveRiskWorkflow()
