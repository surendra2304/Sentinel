"""Remediation & Compensating Control Recommendation Engine for Sentinel.

Synthesizes prioritized remediation action plans with effort estimates,
compensating mitigations, and explicit Sentinel verification validation checks.
"""

from pydantic import BaseModel, Field

from sentinel.core.models import Finding, SeverityLevel
from sentinel.intelligence.attack_paths.analyzer import AttackPath


class RemediationRecommendation(BaseModel):
    recommendation_id: str
    target_asset: str
    priority: str
    title: str
    action_plan: str
    compensating_control: str
    estimated_effort: str
    verification_check_action: str
    linked_finding_ids: list[str] = Field(default_factory=list)


class RecommendationEngine:
    """Generates ordered remediation plans with verification methods."""

    def generate_recommendations(
        self,
        findings: list[Finding],
        attack_paths: list[AttackPath] | None = None,
    ) -> list[RemediationRecommendation]:
        recs: list[RemediationRecommendation] = []

        for idx, f in enumerate(findings):
            prio = "P1" if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "P2"
            effort = "Low (Config change)" if "config" in f.title.lower() or "header" in f.title.lower() else "Medium (Patch / Upgrade)"

            # Map verification action
            verif_action = "web.config_analysis"
            if "port" in f.title.lower() or "service" in f.title.lower():
                verif_action = "network.port_scan"
            elif "cve" in f.title.lower() or "vulnerability" in f.title.lower() or "struts" in f.title.lower() or f.related_cves:
                verif_action = "vulnerability.correlate"
            elif "s3" in f.title.lower() or "cloud" in f.title.lower():
                verif_action = "cloud.aws_posture_assess"

            comp_control = "Deploy WAF rate-limiting rule or restrict IP allowlist on perimeter firewall."

            rec = RemediationRecommendation(
                recommendation_id=f"REC-{idx+1:03d}",
                target_asset=f.target_ref or "global",
                priority=prio,
                title=f"Remediate {f.title}",
                action_plan=f.remediation or "Apply latest vendor security patch and re-verify baseline configuration.",
                compensating_control=comp_control,
                estimated_effort=effort,
                verification_check_action=verif_action,
                linked_finding_ids=[f.id],
            )
            recs.append(rec)

        return recs


# Global Recommendation Engine Singleton
recommendation_engine = RecommendationEngine()
