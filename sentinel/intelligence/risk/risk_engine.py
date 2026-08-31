"""Risk Engine for Sentinel.

Calculates and dynamically updates numeric risk scores and tiers per finding,
asset, environment, and task. Emits risk.updated events.
"""

import uuid

from pydantic import BaseModel, Field

from sentinel.core.events.bus import emit_event
from sentinel.core.models import (
    AssetCriticality,
    EventType,
    Finding,
    Risk,
    RiskTier,
)


class TaskRiskSummary(BaseModel):
    """Aggregated risk profile for a specific task."""
    task_id: str
    total_findings: int
    overall_risk_score: float
    highest_risk_tier: RiskTier
    tier_counts: dict[str, int]
    severity_counts: dict[str, int]
    top_risks: list[Risk] = Field(default_factory=list)


class RiskEngine:
    """Dynamic contextual risk calculator and aggregator."""

    def __init__(self):
        self._risks: dict[str, Risk] = {}

    async def calculate_finding_risk(
        self,
        finding: Finding,
        asset_criticality: AssetCriticality = AssetCriticality.MEDIUM,
        is_internet_facing: bool = True,
        exploitability_factor: float = 0.8,
    ) -> Risk:
        """Calculate contextual risk score combining severity, asset, exposure, and confidence."""
        risk_id = f"risk-{uuid.uuid4().hex[:12]}"
        exposure_score = 1.0 if is_internet_facing else 0.4

        rationale = (
            f"Evaluated severity ({finding.severity.value}) on {asset_criticality.value}-critical asset "
            f"({'Internet-Facing' if is_internet_facing else 'Internal-Only'}) with confidence {finding.confidence}."
        )

        risk = Risk(
            id=risk_id,
            finding_id=finding.id,
            task_id=finding.task_id,
            severity=finding.severity,
            asset_criticality=asset_criticality,
            exposure_score=exposure_score,
            exploitability_score=exploitability_factor,
            confidence_score=finding.confidence,
            rationale=rationale,
        )

        self._risks[finding.id] = risk

        await emit_event(
            event_type=EventType.ALERT,
            topic="risk.updated",
            source="sentinel.risk_engine",
            payload={
                "risk_id": risk.id,
                "finding_id": finding.id,
                "task_id": finding.task_id,
                "score": risk.computed_risk_score,
                "tier": risk.risk_tier.value,
            },
            correlation_id=finding.task_id,
        )

        return risk

    def get_task_risk_summary(self, task_id: str, findings: list[Finding]) -> TaskRiskSummary:
        """Aggregate all finding risks into a comprehensive task risk profile."""
        task_risks = [self._risks[f.id] for f in findings if f.id in self._risks]

        tier_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0}
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for r in task_risks:
            tier_counts[r.risk_tier.value] = tier_counts.get(r.risk_tier.value, 0) + 1
            sev_counts[r.severity.value] = sev_counts.get(r.severity.value, 0) + 1

        total_findings = len(findings)
        avg_score = (
            round(sum(r.computed_risk_score for r in task_risks) / len(task_risks), 2)
            if task_risks
            else 0.0
        )

        # Determine highest tier
        highest_tier = RiskTier.MINIMAL
        if tier_counts["critical"] > 0:
            highest_tier = RiskTier.CRITICAL
        elif tier_counts["high"] > 0:
            highest_tier = RiskTier.HIGH
        elif tier_counts["medium"] > 0:
            highest_tier = RiskTier.MEDIUM
        elif tier_counts["low"] > 0:
            highest_tier = RiskTier.LOW

        sorted_risks = sorted(task_risks, key=lambda x: x.computed_risk_score, reverse=True)

        return TaskRiskSummary(
            task_id=task_id,
            total_findings=total_findings,
            overall_risk_score=avg_score,
            highest_risk_tier=highest_tier,
            tier_counts=tier_counts,
            severity_counts=sev_counts,
            top_risks=sorted_risks[:5],
        )


# Global Risk Engine Singleton
risk_engine = RiskEngine()
