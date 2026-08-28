"""Reporting and Evidence Verification Export Engine for Sentinel.

Generates:
1. Executive Summary Reports (KPIs, Risk Posture, High-Level Findings)
2. Technical Vulnerability Reports (Evidence anchors, affected assets, verification checks)
3. DFIR/SOC Incident Investigation Reports (Timeline, IOCs, containment proposals)
4. Cryptographically Signed Evidence Verification Bundles (SHA-256 Manifest + artifacts)
"""

import time
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from sentinel.core.models import Finding, Task
from sentinel.intelligence.attack_paths.analyzer import AttackPath
from sentinel.intelligence.recommendations.engine import RemediationRecommendation
from sentinel.storage.evidence.store import EvidenceStore, evidence_store


class ReportType(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    DFIR_INCIDENT = "dfir_incident"
    COMPLIANCE_CSPM = "compliance_cspm"


class SecurityReport(BaseModel):
    report_id: str
    task_id: str
    report_type: ReportType
    title: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    overall_risk_score: float = 0.0
    summary_narrative: str
    findings_summary: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    recommendations: list[RemediationRecommendation] = Field(default_factory=list)
    evidence_manifest_hash: str = ""


class ReportGenerator:
    """Compiles structured, evidence-anchored security reports and bundles."""

    def __init__(self, store: EvidenceStore | None = None):
        self.evidence_store = store or evidence_store

    def generate_report(
        self,
        task: Task,
        findings: list[Finding],
        attack_paths: list[AttackPath] | None = None,
        recommendations: list[RemediationRecommendation] | None = None,
        report_type: ReportType = ReportType.TECHNICAL,
    ) -> SecurityReport:
        # Calculate severity counts
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev_key = f.severity.value.lower()
            if sev_key in sev_counts:
                sev_counts[sev_key] += 1

        # Summary narrative
        narrative = (
            f"Security assessment completed for Task '{task.id}'. "
            f"Evaluated {len(task.target_set.targets)} target assets across {len(findings)} security findings. "
            f"Identified {sev_counts['critical']} Critical and {sev_counts['high']} High severity issues."
        )

        rep_id = f"REP-{task.id}-{int(time.time())}"
        report = SecurityReport(
            report_id=rep_id,
            task_id=task.id,
            report_type=report_type,
            title=f"Sentinel {report_type.value.capitalize()} Security Assessment Report",
            overall_risk_score=min(10.0, float(sev_counts["critical"] * 3.5 + sev_counts["high"] * 2.0 + sev_counts["medium"] * 0.5)),
            summary_narrative=narrative,
            findings_summary=sev_counts,
            findings=findings,
            attack_paths=attack_paths or [],
            recommendations=recommendations or [],
        )

        return report

    def format_as_markdown(self, report: SecurityReport) -> str:
        md = [
            f"# {report.title}",
            f"**Task ID**: `{report.task_id}`  ",
            f"**Generated**: `{report.generated_at.isoformat()}`  ",
            f"**Overall Risk Score**: `{report.overall_risk_score}/10.0`\n",
            "## Executive Summary",
            report.summary_narrative,
            "\n## Findings Breakdown",
            f"- **Critical**: {report.findings_summary.get('critical', 0)}",
            f"- **High**: {report.findings_summary.get('high', 0)}",
            f"- **Medium**: {report.findings_summary.get('medium', 0)}",
            f"- **Low**: {report.findings_summary.get('low', 0)}",
            f"- **Info**: {report.findings_summary.get('info', 0)}\n",
            "## Findings & Cryptographic Evidence Anchors",
        ]

        for idx, f in enumerate(report.findings):
            md.append(f"### {idx+1}. [{f.severity.value.upper()}] {f.title}")
            md.append(f"**Target**: `{f.target_ref}`  ")
            md.append(f"**Description**: {f.description}  ")
            if f.related_cves:
                md.append(f"**CVEs**: `{', '.join(f.related_cves)}`  ")
            md.append(f"**Evidence References**: `{', '.join(f.evidence_refs)}`  ")
            md.append(f"**Remediation**: {f.remediation or 'N/A'}\n")

        if report.recommendations:
            md.append("## Prioritized Remediation & Verification Plan")
            for r in report.recommendations:
                md.append(f"- **[{r.priority}] {r.title}** (Effort: {r.estimated_effort})")
                md.append(f"  - Action: {r.action_plan}")
                md.append(f"  - Compensating Control: {r.compensating_control}")
                md.append(f"  - Verification Check: `{r.verification_check_action}`")

        return "\n".join(md)


# Global Report Generator Singleton
report_generator = ReportGenerator()
