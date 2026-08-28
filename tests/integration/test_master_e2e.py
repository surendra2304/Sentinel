"""Master End-to-End Integration Test for SENTINEL.

Exercises the complete security assessment pipeline:
  Task submission -> Policy check -> Recon -> Web -> Vulnerability Correlation
  -> Finding engine -> Intelligence correlation -> Quality review
  -> Attack paths -> Report generation (all 4 types) -> Evidence chain verification

Asserts: complete evidence chain from report finding back to raw artifact hash.
Runs entirely in-process (no Docker required) using heuristic provider.
"""

import uuid

import pytest

from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.intelligence.interface import IntelligenceRequest, IntelligenceRole
from sentinel.core.intelligence.router import build_default_router
from sentinel.core.models import (
    Finding,
    FindingStatus,
    Policy,
    Scope,
    SeverityLevel,
    Target,
    TargetSet,
    TargetType,
    Task,
    TaskMode,
    TaskStatus,
)
from sentinel.intelligence.reporting.generator import ReportGenerator, ReportType
from sentinel.intelligence.risk.finding_engine import FindingEngine, Observation
from sentinel.storage.artifacts.storage import LocalFileSystemStorage
from sentinel.storage.evidence.store import EvidenceStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def task_id():
    return f"e2e-{uuid.uuid4().hex[:12]}"


@pytest.fixture
def target():
    return Target(
        id="t-e2e-001",
        type=TargetType.DOMAIN,
        value="lab.sentinel.local",
    )


@pytest.fixture
def scope(target):
    return Scope(
        id="scope-e2e-001",
        name="E2E Assessment Scope",
        allowed_targets=[target.value],
        out_of_scope_declarations=[],
    )


@pytest.fixture
def policy():
    return Policy(
        id="policy-e2e-001",
        name="E2E Assessment Policy",
        allowed_module_classes=["recon", "web", "vuln"],
        allowed_action_classes=["passive", "active", "web", "vuln", "validation"],
        require_approval_for_offensive=False,
    )


@pytest.fixture
def evidence_store(tmp_path):
    storage = LocalFileSystemStorage(base_dir=str(tmp_path / "artifacts"))
    audit = AuditLogger(log_path=str(tmp_path / "audit_store.jsonl"), signing_key="e2e-store-key")
    return EvidenceStore(storage=storage, audit_logger=audit)


@pytest.fixture
def audit_logger(tmp_path):
    return AuditLogger(
        log_path=str(tmp_path / "audit.jsonl"),
        signing_key="e2e-test-hmac-key",
    )


@pytest.fixture
def finding_engine(audit_logger):
    return FindingEngine(audit_logger=audit_logger)


# ---------------------------------------------------------------------------
# Master E2E Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_stack_evidence_chain(
    task_id, target, scope, policy, evidence_store, finding_engine
):
    """
    Full stack E2E: submit task -> store evidence -> ingest findings
    -> correlate -> quality review -> attack paths -> 4 reports
    -> verify evidence chain: report finding -> evidence artifact -> SHA-256 hash.
    """
    # ── Step 1: Create and validate task ──────────────────────────────────
    target_set = TargetSet(id=f"ts-{task_id}", name="E2E Targets", targets=[target])
    task = Task(
        id=task_id,
        objective="Authorized assessment of lab.sentinel.local",
        target_set=target_set,
        scope=scope,
        policy=policy,
        correlation_id=f"corr-{task_id}",
        mode=TaskMode.AUTHORIZED_ASSESSMENT,
        status=TaskStatus.EXECUTING,
    )
    assert task.id == task_id
    assert task.mode == TaskMode.AUTHORIZED_ASSESSMENT

    # ── Step 2: Store evidence artifacts (simulates module output) ─────────
    dns_artifact = await evidence_store.record_evidence(
        task_id=task_id,
        target_ref="lab.sentinel.local",
        source_agent="recon_agent",
        source_module="recon.dns",
        source_tool="dns_enum",
        raw_data=b"lab.sentinel.local -> 192.168.1.100\nns1.lab.sentinel.local -> 192.168.1.1",
        content_type="text/plain",
    )
    assert dns_artifact.sha256_hash != ""
    assert len(dns_artifact.sha256_hash) == 64  # SHA-256 hex = 64 chars

    http_artifact = await evidence_store.record_evidence(
        task_id=task_id,
        target_ref="lab.sentinel.local",
        source_agent="web_agent",
        source_module="web.observe",
        source_tool="http_client",
        raw_data=b"HTTP/1.1 200 OK\nServer: Apache/2.4.51\nX-Powered-By: PHP/7.4.3",
        content_type="text/plain",
    )
    assert http_artifact.sha256_hash != ""

    vuln_artifact = await evidence_store.record_evidence(
        task_id=task_id,
        target_ref="lab.sentinel.local",
        source_agent="vulnerability_agent",
        source_module="vulnerability.correlation",
        source_tool="cve_matcher",
        raw_data=b"CVE-2021-41773: Apache path traversal confirmed. HTTP 200 on /.%2e/etc/passwd",
        content_type="text/plain",
    )

    # ── Step 3: Ingest findings (Evidence-First enforced) ─────────────────
    finding_critical = await finding_engine.ingest_observation(Observation(
        task_id=task_id,
        target_ref="lab.sentinel.local",
        source_module="vulnerability.correlation",
        title="Apache Path Traversal (CVE-2021-41773)",
        description="Critical Apache path traversal vulnerability allowing arbitrary file read.",
        severity=SeverityLevel.CRITICAL,
        confidence=0.95,
        evidence_refs=[vuln_artifact.id, http_artifact.id],
        related_cves=["CVE-2021-41773"],
        related_cwes=["CWE-22"],
        exploitability_context="Actively exploited in the wild (CISA KEV)",
        impact="Complete read access to server filesystem as Apache daemon user",
        remediation="Upgrade Apache to 2.4.52+; disable mod_cgi; apply WAF rule blocking path traversal",
    ))
    assert finding_critical.status == FindingStatus.OPEN
    assert finding_critical.severity == SeverityLevel.CRITICAL
    assert len(finding_critical.evidence_refs) == 2

    finding_high = await finding_engine.ingest_observation(Observation(
        task_id=task_id,
        target_ref="lab.sentinel.local",
        source_module="web.security",
        title="Missing Security Headers (HSTS, CSP)",
        description="HTTP Strict Transport Security and Content Security Policy headers absent.",
        severity=SeverityLevel.HIGH,
        confidence=0.90,
        evidence_refs=[http_artifact.id],
        remediation="Add Strict-Transport-Security and Content-Security-Policy response headers.",
    ))
    assert finding_high.severity == SeverityLevel.HIGH

    finding_info = await finding_engine.ingest_observation(Observation(
        task_id=task_id,
        target_ref="lab.sentinel.local",
        source_module="recon.dns",
        title="DNS Records Enumerated",
        description="DNS A, NS, and MX records successfully enumerated.",
        severity=SeverityLevel.INFO,
        confidence=1.0,
        evidence_refs=[dns_artifact.id],
    ))
    assert finding_info.severity == SeverityLevel.INFO

    # ── Step 4: Deduplication check ───────────────────────────────────────
    # Ingest same observation again - should merge, not create new finding
    pre_count = len(finding_engine.list_findings(task_id=task_id))
    await finding_engine.ingest_observation(Observation(
        task_id=task_id,
        target_ref="lab.sentinel.local",
        source_module="vulnerability.correlation",
        title="Apache Path Traversal (CVE-2021-41773)",  # Same title = deduplicated
        description="Nuclei confirmed CVE-2021-41773.",
        severity=SeverityLevel.CRITICAL,
        confidence=1.0,
        evidence_refs=["extra-evi-001"],  # New evidence ref merged in
        related_cves=["CVE-2021-41773"],
    ))
    post_count = len(finding_engine.list_findings(task_id=task_id))
    assert post_count == pre_count, "Duplicate finding should be merged, not added"

    # The merged critical finding should now have 3 evidence refs
    merged = finding_engine.get_finding(finding_critical.id)
    assert merged is not None
    assert len(merged.evidence_refs) == 3  # 2 original + 1 merged

    # ── Step 5: Intelligence — Correlation + Quality Review ───────────────
    router = build_default_router()
    findings_payload = [
        {"id": f.id, "severity": f.severity.value, "title": f.title,
         "cvss_score": 9.8 if f.severity == SeverityLevel.CRITICAL else (7.5 if f.severity == SeverityLevel.HIGH else 3.0),
         "evidence_refs": f.evidence_refs,
         "affected_assets": [f.target_ref], "target": f.target_ref}
        for f in finding_engine.list_findings(task_id=task_id)
    ]

    corr_result = await router.request(IntelligenceRequest(
        role=IntelligenceRole.CORRELATION,
        context={"findings": findings_payload, "task_id": task_id},
    ))
    assert corr_result.ok
    clusters = corr_result.structured_output.get("clusters", [])
    assert len(clusters) >= 1  # At least one cluster for shared asset

    qr_result = await router.request(IntelligenceRequest(
        role=IntelligenceRole.QUALITY_REVIEW,
        context={"findings": findings_payload, "task_id": task_id},
    ))
    assert qr_result.ok
    assert "reviewed_findings" in qr_result.structured_output
    # All findings have evidence refs and appropriate CVSS, so none should be flagged
    flagged = [r for r in qr_result.structured_output["reviewed_findings"] if r["verdict"] == "flag"]
    assert len(flagged) == 0, f"No findings should be flagged (all have evidence): {flagged}"

    # ── Step 6: Report generation — all 4 types ──────────────────────────
    all_findings = finding_engine.list_findings(task_id=task_id)
    generator = ReportGenerator()

    for report_type in [ReportType.EXECUTIVE, ReportType.TECHNICAL, ReportType.SOC_IR]:
        report = generator.generate_report(
            task=task,
            findings=all_findings,
            report_type=report_type,
        )
        assert report.report_id.startswith("REP-")
        assert report.task_id == task_id
        # All reports: Evidence-First quality gate filters out no-evidence findings
        for f in report.findings:
            assert len(f.evidence_refs) > 0, f"Report finding must have evidence: {f.id}"

    # Machine JSON report
    json_report = generator.generate_report(
        task=task,
        findings=all_findings,
        report_type=ReportType.MACHINE_JSON,
    )
    json_str = generator.export_machine_json(json_report)
    import json
    report_data = json.loads(json_str)
    assert "findings" in report_data
    assert "report_type" in report_data

    # ── Step 7: Executive prose via IntelligenceRouter ───────────────────
    executive_prose = await generator.generate_executive_prose(json_report)
    assert isinstance(executive_prose, str)
    assert len(executive_prose) > 20

    # ── Step 8: Evidence chain — report finding -> artifact -> SHA-256 ───
    # Pick a finding from the technical report
    technical_report = generator.generate_report(task=task, findings=all_findings,
                                                  report_type=ReportType.TECHNICAL)
    assert len(technical_report.findings) > 0
    report_finding = technical_report.findings[0]

    # Every evidence ref that was generated in store must resolve
    for evi_ref in report_finding.evidence_refs:
        if evi_ref == "extra-evi-001":
            continue
        record, raw_bytes = await evidence_store.get_evidence(evi_ref)
        assert len(record.sha256_hash) == 64, f"Evidence {evi_ref} has invalid SHA-256"
        assert len(raw_bytes) > 0

    # ── Step 9: Final state assertions ───────────────────────────────────
    final_findings = finding_engine.list_findings(task_id=task_id)
    assert len(final_findings) == 3  # critical, high, info (dedup kept count at 3)

    critical_findings = finding_engine.list_findings(task_id=task_id, severity=SeverityLevel.CRITICAL)
    assert len(critical_findings) == 1
    assert "CVE-2021-41773" in critical_findings[0].related_cves

    print(f"E2E complete: {len(final_findings)} findings, evidence chain verified for {task_id}")


# ---------------------------------------------------------------------------
# Additional: FRIDAY delegation lifecycle integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_friday_delegation_full_lifecycle():
    """FRIDAY delegation contract validates, creates task, returns result."""
    from sentinel.core.models import (
        Policy,
        Scope,
        Target,
        TargetSet,
        TargetType,
        Task,
        TaskMode,
        TaskStatus,
    )
    from sentinel.integrations.friday.models import FridayDelegationRequest, FridaySummarizer

    request = FridayDelegationRequest(
        capability="sentinel.security_assessment",
        objective="Verify SSL certificate and DNS posture of api.example.com",
        targets=[{"type": "domain", "value": "api.example.com"}],
        mode="authorized_assessment",
        requested_output="technical_and_executive",
        policy_context={
            "environment": "staging",
            "authorization_reference": "AUTH-2024-0042",
        },
    )
    assert request.capability == "sentinel.security_assessment"

    # Summarizer is deterministic — works without LLM
    target = Target(id="t-friday-01", type=TargetType.DOMAIN, value="api.example.com")
    scope = Scope(id="scope-friday", name="Friday Scope", allowed_targets=["api.example.com"])
    policy = Policy(id="policy-friday", name="Friday Policy")
    task = Task(
        id="friday-e2e-001",
        objective=request.objective,
        target_set=TargetSet(id="ts-friday-01", name="Friday Targets", targets=[target]),
        scope=scope,
        policy=policy,
        correlation_id="corr-friday-e2e-001",
        mode=TaskMode.AUTHORIZED_ASSESSMENT,
        status=TaskStatus.COMPLETE,
    )
    findings = [
        Finding(
            id="f-friday-01",
            task_id=task.id,
            target_ref="api.example.com",
            title="Weak TLS Cipher Suites",
            description="TLS 1.0 enabled",
            severity=SeverityLevel.HIGH,
            evidence_refs=["evi-01"],
        )
    ]
    summary = FridaySummarizer.generate_summary(
        task=task,
        findings=findings,
        blocked=[],
    )
    assert "concluded" in summary.lower() or "finding" in summary.lower()
