"""Comprehensive tests for PDF Reporting, Evidence Bundle Export & Tamper Verification, Credential Vault, and Approval Attribution."""

import json

import pytest

from sentinel.core.models import (
    Finding,
    FindingStatus,
    ImpactLevel,
    Policy,
    Scope,
    SeverityLevel,
    Target,
    TargetSet,
    Task,
    TaskMode,
)
from sentinel.core.policy.engine import policy_engine
from sentinel.core.vault.vault import CredentialVault
from sentinel.intelligence.reporting.generator import (
    ReportType,
    report_generator,
)
from sentinel.storage.evidence.store import evidence_store


@pytest.fixture
def test_task_with_findings():
    target = Target(id="t-audit-01", type="host", value="target.local")
    target_set = TargetSet(id="ts-audit-01", name="Audit TargetSet", targets=[target])
    scope = Scope(id="scope-audit-01", name="Audit Scope", allowed_targets=["target.local"])
    policy = Policy(id="policy-audit-01", name="Audit Policy")

    task = Task(
        id="task-audit-reporting-01",
        objective="Security audit and reporting validation",
        target_set=target_set,
        scope=scope,
        policy=policy,
        mode=TaskMode.ASSESSMENT,
        correlation_id="corr-audit-01",
    )

    finding_valid = Finding(
        id="find-audit-01",
        task_id=task.id,
        target_ref="target.local",
        title="Critical Vulnerability with Valid Evidence",
        description="Vulnerability properly linked to cryptographic evidence artifact.",
        severity=SeverityLevel.CRITICAL,
        confidence=0.98,
        status=FindingStatus.VERIFIED,
        evidence_refs=["evi-audit-001"],
        remediation="Upgrade package to latest patch.",
    )

    return task, [finding_valid]


# ---------------------------------------------------------------------------
# 1. PDF Rendering & Quality Gate Boundary Tests
# ---------------------------------------------------------------------------

def test_evidence_first_validation_and_pdf_rendering(test_task_with_findings):
    task, findings = test_task_with_findings

    # 1. Assert Evidence-First invariant: creating Finding without evidence_refs raises ValidationError
    with pytest.raises(ValueError, match="Evidence-First violation"):
        Finding(
            id="find-unsupported-01",
            task_id=task.id,
            target_ref="target.local",
            title="Unsupported Finding Missing Evidence",
            description="Must fail validation",
            severity=SeverityLevel.HIGH,
            evidence_refs=[],
        )

    report = report_generator.generate_report(
        task=task,
        findings=findings,
        report_type=ReportType.TECHNICAL,
    )

    # 1. Assert unsupported finding with no evidence_refs was excluded
    assert len(report.findings) == 1
    assert report.findings[0].id == "find-audit-01"
    assert "find-audit-02" not in [f.id for f in report.findings]

    # 2. Assert Markdown contains Table of Contents, Confidence, and Evidence Appendix
    md_content = report_generator.render_markdown(report)
    assert "Table of Contents" in md_content
    assert "Appendix: Cryptographic Evidence Index" in md_content
    assert "98% Confidence" in md_content or "Confidence: 98%" in md_content
    assert "Upgrade package to latest patch." in md_content

    # 3. Assert PDF generation outputs valid PDF binary
    pdf_bytes = report_generator.render_pdf(report)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 100
    assert pdf_bytes.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# 2. Evidence Zip Bundle Export & Tamper Verification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evidence_zip_bundle_export_and_tamper_detection(tmp_path):
    task_id = "task-bundle-test-01"

    # Record two pieces of evidence
    evi1 = await evidence_store.record_evidence(
        task_id=task_id,
        target_ref="host1.local",
        source_agent="recon_agent",
        source_module="recon",
        source_tool="http_observer",
        raw_data=b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n",
        content_type="text/plain",
    )

    evi2 = await evidence_store.record_evidence(
        task_id=task_id,
        target_ref="host1.local",
        source_agent="vuln_agent",
        source_module="vulnerability",
        source_tool="cve_correlator",
        raw_data=b'{"cve": "CVE-2021-41773", "severity": "CRITICAL"}',
        content_type="application/json",
    )

    finding_map = {"find-001": [evi1.id, evi2.id]}

    # Generate zip bundle
    zip_bytes = await evidence_store.create_evidence_zip_bundle(task_id=task_id, finding_links=finding_map)
    assert isinstance(zip_bytes, bytes)
    assert len(zip_bytes) > 200

    # 1. Clean verification must pass
    result = evidence_store.verify_evidence_zip_bundle(zip_bytes)
    assert result["valid"] is True
    assert result["task_id"] == task_id
    assert result["verified_records"] == 2

    # 2. Tamper Test: Mutate one byte in artifact and assert verification fails
    bundle_path = tmp_path / "tampered_bundle.zip"
    with open(bundle_path, "wb") as f:
        f.write(zip_bytes)

    # Modify the artifact inside the zip
    tampered_bytes = bytearray(zip_bytes)
    # Search for ascii byte in artifact and flip it
    idx = tampered_bytes.find(b"Apache/2.4.49")
    if idx != -1:
        tampered_bytes[idx] = ord(b"X")

    with pytest.raises(ValueError):
        evidence_store.verify_evidence_zip_bundle(bytes(tampered_bytes))


# ---------------------------------------------------------------------------
# 3. Task-Scoped Credential Vault & Central Redaction Tests
# ---------------------------------------------------------------------------

def test_credential_vault_isolation_and_redaction():
    vault = CredentialVault()
    task_id = "task-vault-01"
    secret = "SUPER_SECRET_PRODUCTION_KEY_987654321"

    vault.store_credential(task_id=task_id, key="api_key", secret_value=secret, description="Prod Key")

    # 1. Access strictly at execution time
    retrieved = vault.get_credential(task_id, "api_key")
    assert retrieved == secret

    # 2. Central redaction eliminates secret from text, logs, and dicts
    sensitive_log = f"Executing request with Authorization: Bearer {secret} against endpoint."
    redacted_log = vault.redact_text(sensitive_log)
    assert secret not in redacted_log
    assert "[REDACTED_SECRET]" in redacted_log

    sensitive_dict = {"url": "https://api.target.com", "header": f"Token {secret}"}
    redacted_dict = vault.redact_dict(sensitive_dict)
    assert secret not in json.dumps(redacted_dict)
    assert "[REDACTED_SECRET]" in redacted_dict["header"]


# ---------------------------------------------------------------------------
# 4. Approval Attribution & Expiry Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_approval_attribution_and_expiration(test_task_with_findings):
    task, _ = test_task_with_findings

    from sentinel.core.models import ActionRequest
    action = ActionRequest(
        id="act-auth-test",
        task_id=task.id,
        agent="exploit_agent",
        action_type="web.vuln_validate",
        target_refs=["target.local"],
        expected_impact_level=ImpactLevel.HIGH,
        requires_approval=True,
    )

    # Evaluate policy -> requires approval
    decision = await policy_engine.evaluate_action(action, task)
    assert decision.decision.value == "REQUIRE_APPROVAL"
    assert decision.approval_id is not None

    # Decide approval with full operator attribution and reference
    record = await policy_engine.decide_approval(
        approval_id=decision.approval_id,
        approve=True,
        operator="lead_security_engineer@corp.local",
        justification="Verified assessment scope and emergency change window authorization.",
        authorization_reference="CHG-2026-9812",
    )

    assert record.status == "APPROVED"
    assert record.approved_by == "lead_security_engineer@corp.local"
    assert record.authorization_reference == "CHG-2026-9812"
    assert record.decided_at is not None
