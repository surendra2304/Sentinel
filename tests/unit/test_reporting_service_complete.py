import json

import pytest

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
from sentinel.intelligence.attack_paths.analyzer import AttackPath, AttackStep
from sentinel.intelligence.recommendations.engine import RemediationRecommendation
from sentinel.intelligence.reporting.generator import ReportGenerator, ReportType


@pytest.fixture
def reporting_task_fixture():
    task = Task(
        id="task-rep-e2e",
        objective="Assess enterprise perimeter",
        target_set=TargetSet(
            id="ts-rep",
            name="TS-Rep",
            targets=[Target(id="t-1", type=TargetType.DOMAIN, value="api.example.com")],
        ),
        scope=Scope(id="s-rep", name="S-Rep", allowed_targets=["api.example.com"]),
        policy=Policy(id="p-rep", name="P-Rep", allowed_module_classes=["*"]),
        correlation_id="corr-rep-e2e",
    )

    f1 = Finding(
        id="f-01",
        task_id=task.id,
        title="Remote Code Execution on Web App",
        description="Struts RCE vulnerability.",
        severity=SeverityLevel.CRITICAL,
        target_ref="api.example.com",
        evidence_refs=["evi-struts-01"],
        related_cves=["CVE-2017-5638"],
        remediation="Upgrade Apache Struts.",
    )

    # planted finding without evidence references
    f_no_evidence = Finding.model_construct(
        id="f-no-evi",
        task_id=task.id,
        title="Unverified Phantom Bug",
        description="Bug without proof.",
        severity=SeverityLevel.HIGH,
        target_ref="api.example.com",
        evidence_refs=[],
        remediation="None",
    )

    rec = RemediationRecommendation(
        recommendation_id="REC-001",
        target_asset="api.example.com",
        priority="P1",
        title="Patch Apache Struts",
        action_plan="Upgrade package.",
        compensating_control="WAF filter.",
        estimated_effort="Low",
        verification_check_action="vulnerability.correlate",
        linked_finding_ids=[f1.id],
    )

    path = AttackPath(
        path_id="AP-001",
        entry_point="api.example.com",
        target_crown_jewel="db-cluster.internal",
        path_confidence=0.85,
        total_steps=1,
        steps=[
            AttackStep(
                step_number=1,
                source_asset="Internet",
                target_asset="api.example.com",
                action_or_technique="Exploit CVE-2017-5638",
                supporting_finding_ids=[f1.id],
            )
        ],
    )

    return task, [f1, f_no_evidence], [path], [rec]


def test_four_report_types_generation_and_evidence_gate(reporting_task_fixture):
    task, findings, paths, recs = reporting_task_fixture
    generator = ReportGenerator()

    # 1. Executive Report
    exec_rep = generator.generate_report(task, findings, paths, recs, ReportType.EXECUTIVE)
    assert len(exec_rep.findings) == 1  # Evidence-less finding was rejected
    assert exec_rep.findings[0].id == "f-01"
    exec_md = generator.render_markdown(exec_rep)
    assert "Executive Cybersecurity Risk Assessment Report" in exec_md
    assert "Attack Path Hypothesis: AP-001" in exec_md

    # 2. Technical Report
    tech_rep = generator.generate_report(task, findings, paths, recs, ReportType.TECHNICAL)
    tech_md = generator.render_markdown(tech_rep)
    assert "Technical Security Assessment & Penetration Testing Report" in tech_md
    assert "evi-struts-01" in tech_md
    assert "CVE-2017-5638" in tech_md

    # 3. SOC/IR Report
    soc_rep = generator.generate_report(task, findings, paths, recs, ReportType.SOC_IR)
    soc_md = generator.render_markdown(soc_rep)
    assert "SOC Incident Response & Forensic Investigation Report" in soc_md

    # 4. Machine-Readable JSON Export
    json_export = generator.export_machine_json(tech_rep)
    data = json.loads(json_export)
    assert data["task_id"] == task.id
    assert len(data["findings"]) == 1
    assert data["findings"][0]["evidence_refs"] == ["evi-struts-01"]

    # 5. HTML Rendering
    tech_html = generator.render_html(tech_rep)
    assert "<html>" in tech_html
    assert "evi-struts-01" in tech_html
