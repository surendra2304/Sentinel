"""Remediation Advisory, Step-by-Step Guidance, and Research-Backed Validation."""

from typing import Any

from pydantic import BaseModel, Field


class RemediationPlanItem(BaseModel):
    finding_id: str
    title: str
    target: str
    steps: list[str]
    effort: str  # quick_win | major_refactor
    priority_order: int
    research_citations: list[str] = Field(default_factory=list)
    mitigation_command: str | None = None


class RemediationAdvisor:
    """Generates prioritized, research-backed remediation guidance."""

    @staticmethod
    def generate_plan(finding: dict[str, Any], research_context: dict[str, Any] | None = None) -> RemediationPlanItem:
        title = finding.get("title", "Security Vulnerability")
        target = finding.get("target_ref", "target")
        fid = finding.get("id", "find-01")

        citations = []
        if research_context and "citations" in research_context:
            citations = research_context["citations"]

        return RemediationPlanItem(
            finding_id=fid,
            title=title,
            target=target,
            steps=[
                f"1. Patch or upgrade vulnerable dependency on {target}.",
                "2. Apply ingress perimeter firewall rules to block unauthorized networks.",
                "3. Re-scan endpoint with Sentinel to verify resolution.",
            ],
            effort="quick_win" if "header" in title.lower() or "cors" in title.lower() else "major_refactor",
            priority_order=1 if "critical" in str(finding.get("severity", "")).lower() else 2,
            research_citations=citations,
            mitigation_command="systemctl restart hardened-service && ufw allow from 10.0.0.0/8",
        )


remediation_advisor = RemediationAdvisor()
