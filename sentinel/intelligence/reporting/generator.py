"""Reporting Service and Template Rendering Engine for Sentinel.

Supports:
1. Executive Reports (Business risk, attack paths, strategic roadmap)
2. Technical Pentest Reports (Scope, finding evidence anchors, CVE/CWE, verification retest actions)
3. SOC/IR Reports (Timeline, IOCs, containment proposals)
4. Machine-Readable JSON Export (Schema conforming)

Renders into Markdown and HTML via Jinja2 templates.
Enforces Evidence-First Quality Rules (Rejects findings without evidence references).
"""

import json
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field

from sentinel.core.models import Finding, Task
from sentinel.intelligence.attack_paths.analyzer import AttackPath
from sentinel.intelligence.recommendations.engine import RemediationRecommendation
from sentinel.storage.evidence.store import EvidenceStore, evidence_store


class ReportType(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    SOC_IR = "soc_ir"
    MACHINE_JSON = "json"


class ReportFormat(StrEnum):
    MARKDOWN = "md"
    HTML = "html"
    JSON = "json"


class SecurityReport(BaseModel):
    report_id: str
    task_id: str
    task_status: str = "complete"
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
    """Production reporting service compiling and rendering multi-format assessment reports."""

    def __init__(self, template_dir: str | None = None, store: EvidenceStore | None = None):
        self.template_dir = template_dir or str(Path(__file__).parent / "templates")
        self.evidence_store = store or evidence_store
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True,
        )

    def generate_report(
        self,
        task: Task,
        findings: list[Finding],
        attack_paths: list[AttackPath] | None = None,
        recommendations: list[RemediationRecommendation] | None = None,
        report_type: ReportType = ReportType.TECHNICAL,
    ) -> SecurityReport:
        # Quality Gate Rule: Evidence-First Enforcement
        # Findings without evidence references MUST NOT appear in published reports
        valid_findings: list[Finding] = []
        for f in findings:
            if not f.evidence_refs:
                continue  # Reject evidence-less finding
            if not f.remediation:
                f.remediation = "Apply security hardening best practices and verify with Sentinel re-tests."
            valid_findings.append(f)

        # Severity distribution
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in valid_findings:
            sev_key = f.severity.value.lower()
            if sev_key in sev_counts:
                sev_counts[sev_key] += 1

        narrative = (
            f"Security evaluation for Task '{task.id}'. "
            f"Evaluated {len(task.target_set.targets)} targets across {len(valid_findings)} verified findings. "
            f"Identified {sev_counts['critical']} Critical and {sev_counts['high']} High severity issues."
        )

        rep_id = f"REP-{task.id}-{int(time.time())}"
        report = SecurityReport(
            report_id=rep_id,
            task_id=task.id,
            task_status=task.status.value,
            report_type=report_type,
            title=f"Sentinel {report_type.value.capitalize()} Assessment Report",
            overall_risk_score=min(10.0, float(sev_counts["critical"] * 3.5 + sev_counts["high"] * 2.0 + sev_counts["medium"] * 0.5)),
            summary_narrative=narrative,
            findings_summary=sev_counts,
            findings=valid_findings,
            attack_paths=attack_paths or [],
            recommendations=recommendations or [],
        )
        return report

    def render_markdown(self, report: SecurityReport) -> str:
        tpl_name = f"{report.report_type.value}.md"
        if tpl_name not in self.jinja_env.list_templates():
            tpl_name = "technical.md"

        template = self.jinja_env.get_template(tpl_name)
        return template.render(report=report.model_dump(mode="json"))

    def render_html(self, report: SecurityReport) -> str:
        md_content = self.render_markdown(report)
        # Wrap Markdown in styled HTML shell
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{report.title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; line-height: 1.6; color: #1a202c; }}
        h1, h2, h3 {{ color: #2d3748; }}
        code {{ background: #edf2f7; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
        pre {{ background: #2d3748; color: #f7fafc; padding: 15px; border-radius: 6px; overflow-x: auto; }}
        hr {{ border: 0; border-top: 1px solid #e2e8f0; margin: 30px 0; }}
    </style>
</head>
<body>
    <pre>{md_content}</pre>
</body>
</html>"""
        return html

    def export_machine_json(self, report: SecurityReport) -> str:
        data = report.model_dump(mode="json")
        data["status"] = report.task_status
        return json.dumps(data, indent=2)


# Global Report Generator Singleton
report_generator = ReportGenerator()
