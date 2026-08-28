"""Cross-Domain Security Intelligence Agent for Sentinel.

Acts as the strategic reasoning core:
- Reviews cross-domain findings across all active domains.
- Executes finding correlation via IntelligenceRouter (correlation role).
- Runs quality review via IntelligenceRouter (quality_review role).
- Flags weak/overclaimed findings and adjusts confidence scores.
"""

from typing import Any

from sentinel.core.agents.base import AgentReport, BaseAgent
from sentinel.core.intelligence.interface import IntelligenceRequest, IntelligenceRole
from sentinel.core.models import (
    FindingStatus,
    Policy,
    Scope,
    TargetSet,
    Task,
)
from sentinel.logging.logger import get_logger

logger = get_logger("sentinel.agent.security_intelligence")


class SecurityIntelligenceAgent(BaseAgent):
    """Cross-domain reasoning and strategic security advisory agent."""

    @property
    def name(self) -> str:
        return "security_intelligence_agent"

    @property
    def domain(self) -> str:
        return "security_intelligence"

    @property
    def capabilities(self) -> list[str]:
        return [
            "intelligence.correlate_findings",
            "intelligence.analyze_attack_paths",
            "intelligence.generate_recommendations",
            "intelligence.gap_analysis",
            "intelligence.quality_review",
        ]

    async def analyze(
        self,
        task: Task,
        target_set: TargetSet,
        scope: Scope,
        policy: Policy,
        available_evidence: list[dict[str, Any]],
        working_memory: dict[str, Any],
    ) -> AgentReport:
        # Import here to avoid circular at module load
        from sentinel.core.intelligence.router import intelligence_router
        from sentinel.intelligence.risk.finding_engine import finding_engine

        report = AgentReport(
            agent_name=self.name,
            task_id=task.id,
            reasoning="Performed cross-domain finding correlation and quality review.",
        )

        findings = finding_engine.list_findings(task_id=task.id)
        findings_payload = [
            {
                "id": f.id,
                "severity": f.severity.value,
                "title": f.title,
                "cvss_score": 0.0,          # Finding model stores severity, not raw CVSS
                "evidence_refs": f.evidence_refs,
                "affected_assets": [f.target_ref],
                "target": f.target_ref,
            }
            for f in findings
        ]

        # Step 1: Correlation
        correlation_result = await intelligence_router.request(
            IntelligenceRequest(
                role=IntelligenceRole.CORRELATION,
                context={"findings": findings_payload, "task_id": task.id},
                request_id=f"corr-{task.id[:8]}",
            )
        )
        if correlation_result.ok:
            clusters = correlation_result.structured_output.get("clusters", [])
            report.reasoning = (
                (report.reasoning or "") + f" Identified {len(clusters)} correlated cluster(s)."
            )

        # Step 2: Quality review — challenge findings before finalization
        quality_result = await intelligence_router.request(
            IntelligenceRequest(
                role=IntelligenceRole.QUALITY_REVIEW,
                context={"findings": findings_payload, "task_id": task.id},
                request_id=f"qr-{task.id[:8]}",
            )
        )
        if quality_result.ok:
            reviewed = quality_result.structured_output.get("reviewed_findings", [])
            flagged_count = 0
            for review in reviewed:
                fid = review.get("finding_id", "")
                verdict = review.get("verdict", "pass")
                adjustment = float(review.get("confidence_adjustment", 0.0))
                if verdict in ("flag", "weak") and adjustment < 0:
                    finding_engine.adjust_confidence(
                        finding_id=fid,
                        delta=adjustment,
                        reason=str(review.get("flag_reason") or "Quality review flagged"),
                    )
                    if verdict == "flag":
                        finding_engine.flag_finding(fid, FindingStatus.REVIEW_REQUIRED,
                                                    reason=str(review.get("flag_reason") or ""))
                        flagged_count += 1
            report.reasoning = (
                (report.reasoning or "") + f" Quality review flagged {flagged_count} finding(s)."
            )

        return report


