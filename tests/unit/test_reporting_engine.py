
from sentinel.core.models import (
    Finding,
    Policy,
    Scope,
    SeverityLevel,
    Target,
    TargetSet,
    TargetType,
    Task,
)
from sentinel.intelligence.recommendations.engine import RemediationRecommendation
from sentinel.intelligence.reporting.generator import ReportGenerator, ReportType


def test_report_generator_end_to_end():
    generator = ReportGenerator()

    task = Task(
        id="task-rep-01",
        objective="Assess enterprise perimeter posture",
        target_set=TargetSet(
            id="ts-rep",
            name="TS-Rep",
            targets=[Target(id="t-1", type=TargetType.DOMAIN, value="api.example.com")],
        ),
        scope=Scope(id="s-rep", name="S-Rep", allowed_targets=["api.example.com"]),
        policy=Policy(id="p-rep", name="P-Rep", allowed_module_classes=["*"]),
        correlation_id="corr-rep-01",
    )

    finding = Finding(
        id="f-rep-01",
        task_id=task.id,
        title="Critical API Insecure Direct Object Reference",
        description="IDOR allows accessing arbitrary tenant records.",
        severity=SeverityLevel.CRITICAL,
        target_ref="api.example.com",
        evidence_refs=["evi-api-01"],
        remediation="Enforce tenant-isolated ownership checks in database query.",
    )

    rec = RemediationRecommendation(
        recommendation_id="REC-001",
        target_asset="api.example.com",
        priority="P1",
        title="Fix IDOR on API",
        action_plan="Add user identity checks.",
        compensating_control="WAF rate limiting.",
        estimated_effort="Low",
        verification_check_action="api.input_validation",
        linked_finding_ids=[finding.id],
    )

    report = generator.generate_report(
        task=task,
        findings=[finding],
        recommendations=[rec],
        report_type=ReportType.TECHNICAL,
    )

    assert report.task_id == task.id
    assert report.overall_risk_score > 0.0
    assert report.findings_summary["critical"] == 1

    md_output = generator.render_markdown(report)
    assert "Technical Security Assessment" in md_output
    assert "Critical API Insecure Direct Object Reference" in md_output
    assert "evi-api-01" in md_output
    assert "api.input_validation" in md_output
