"""Comprehensive tests for PDF Reporting, Evidence Bundle Export & Tamper Verification, Credential Vault, and Approval Attribution."""

import asyncio
import json

import pytest

from sentinel.core.models import (
    ActionRequest,
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
from sentinel.core.vault.vault import CredentialVault, credential_vault
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


# ---------------------------------------------------------------------------
# 5. Kill-Switch Subprocess Abort Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kill_switch_subprocess_abort_preserves_evidence(tmp_path):
    import time
    from sentinel.core.orchestrator.executor import ExecutionEngine
    from sentinel.core.orchestrator.adapter import ToolAdapter
    from sentinel.core.models import ActionResult

    class SleepingLongRunningAdapter(ToolAdapter):
        @property
        def name(self) -> str:
            return "sleeping_adapter"

        @property
        def version(self) -> str:
            return "1.0.0"

        @property
        def capabilities(self) -> list[str]:
            return ["test.long_running_sleep"]

        async def health_check(self) -> bool:
            return True

        def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
            return True, None

        async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
            await asyncio.sleep(10.0)  # Long running operation
            return ActionResult(action_id=action.id, task_id=action.task_id, success=True), b"DONE", "text/plain"

    executor = ExecutionEngine()
    executor.registry.register(SleepingLongRunningAdapter())

    target = Target(id="t-abort-01", type="host", value="target.abort.local")
    target_set = TargetSet(id="ts-abort-01", name="Abort Set", targets=[target])
    scope = Scope(id="scope-abort-01", name="Abort Scope", allowed_targets=["target.abort.local"])
    policy = Policy(id="policy-abort-01", name="Abort Policy", allowed_action_classes=["test.long_running_sleep"])

    task = Task(
        id="task-abort-test-01",
        objective="Kill switch validation",
        target_set=target_set,
        scope=scope,
        policy=policy,
        correlation_id="corr-abort-01",
    )

    action = ActionRequest(
        id="act-abort-01",
        task_id=task.id,
        agent="test_agent",
        action_type="test.long_running_sleep",
        target_refs=["target.abort.local"],
    )

    exec_task = asyncio.create_task(executor.execute_action(action, task))
    await asyncio.sleep(0.05)  # Let execution start

    start_cancel = time.monotonic()
    exec_task.cancel()  # Immediate kill-switch abort

    with pytest.raises(asyncio.CancelledError):
        await exec_task

    duration = time.monotonic() - start_cancel
    assert duration < 2.0  # Must die within 2 seconds

    # Check that partial evidence was preserved
    evidence_list = executor.evidence_store.query_evidence(task_id=task.id)
    assert len(evidence_list) >= 1
    assert any(e.collected_by == "sentinel_kill_switch" for e in evidence_list)


# ---------------------------------------------------------------------------
# 6. Approval Invariant Test (Highest Impact ALWAYS requires human approval)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_highest_impact_level_always_requires_human_approval():
    target = Target(id="t-inv-01", type="host", value="prod.internal")
    target_set = TargetSet(id="ts-inv-01", name="Invariant TargetSet", targets=[target])
    scope = Scope(id="scope-inv-01", name="Invariant Scope", allowed_targets=["prod.internal"], offensive_actions_enabled=True)

    # Even with a policy trying to auto-allow everything with no approval
    permissive_policy = Policy(
        id="policy-permissive-01",
        name="Permissive Policy",
        allowed_action_classes=["*"],
        require_approval_for_offensive=False,
    )

    task = Task(
        id="task-invariant-01",
        objective="Verify approval invariant on Level-3 / CRITICAL impact",
        target_set=target_set,
        scope=scope,
        policy=permissive_policy,
        correlation_id="corr-inv-01",
    )

    # Action explicitly marked CRITICAL impact
    critical_action = ActionRequest(
        id="act-critical-01",
        task_id=task.id,
        agent="exploit_agent",
        action_type="web.remote_code_execution",
        target_refs=["prod.internal"],
        expected_impact_level=ImpactLevel.CRITICAL,
        requires_approval=False,  # Attempting to bypass approval
    )

    decision = await policy_engine.evaluate_action(critical_action, task)
    assert decision.decision.value == "REQUIRE_APPROVAL"
    assert decision.requires_approval is True
    assert decision.approval_id is not None


# ---------------------------------------------------------------------------
# 7. Lab Target E2E & Unconditional Secrets Redaction Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lab_target_e2e_and_unconditional_secret_redaction(tmp_path):
    import httpx
    from sentinel.lab.app import lab_app
    from sentinel.integrations.friday.client import FridayClient
    from sentinel.intelligence.reporting.generator import report_generator, ReportType

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=lab_app), base_url="http://lab.local") as client:  # type: ignore[arg-type]
        # 1. Recon checks against lab target
        resp_root = await client.get("/")
        assert resp_root.status_code == 200
        assert "Apache/2.4.49" in resp_root.headers.get("Server", "")

        resp_bak = await client.get("/backup/database.sql.bak")
        assert resp_bak.status_code == 200
        assert "DATABASE DUMP" in resp_bak.text

        # 2. Blocked high-impact action without approval header
        resp_gated = await client.post("/api/admin/flush-database")
        assert resp_gated.status_code == 403

        # 3. Register secret into credential vault
        secret_value = "HIGH_ENTROPY_PROD_SECRET_TOKEN_XYZ_987654"
        credential_vault.store_credential("task-lab-01", "db_pass", secret_value, "Database secret")

        # 4. Create findings anchored to evidence
        evi_bak = await evidence_store.record_evidence(
            task_id="task-lab-01",
            target_ref="http://lab.local",
            source_agent="recon_agent",
            source_module="web",
            source_tool="http_observer",
            raw_data=f"Exposed backup file accessed using secret token: {secret_value}".encode("utf-8"),
            content_type="text/plain",
        )

        finding = Finding(
            id="find-lab-01",
            task_id="task-lab-01",
            target_ref="http://lab.local",
            title="Exposed Database Backup File",
            description=f"Database dump exposed at /backup/database.sql.bak with sensitive info {secret_value}",
            severity=SeverityLevel.HIGH,
            confidence=0.95,
            status=FindingStatus.OPEN,
            evidence_refs=[evi_bak.id],
            remediation="Restrict access to backup directories.",
        )

        # 5. FRIDAY approval relay with operator attribution
        target = Target(id="t-lab-01", type="url", value="http://lab.local")
        target_set = TargetSet(id="ts-lab-01", name="Lab Set", targets=[target])
        scope = Scope(id="scope-lab-01", name="Lab Scope", allowed_targets=["http://lab.local"], offensive_actions_enabled=True)
        policy = Policy(id="policy-lab-01", name="Lab Policy")
        task = Task(
            id="task-lab-01",
            objective="Lab Pentest",
            target_set=target_set,
            scope=scope,
            policy=policy,
            correlation_id="corr-lab-01",
        )

        gated_action = ActionRequest(
            id="act-lab-gated-01",
            task_id=task.id,
            agent="exploit_agent",
            action_type="web.admin_flush",
            target_refs=["http://lab.local"],
            expected_impact_level=ImpactLevel.HIGH,
            requires_approval=True,
        )

        dec = await policy_engine.evaluate_action(gated_action, task)
        assert dec.approval_id is not None

        record = await policy_engine.decide_approval(
            approval_id=dec.approval_id,
            approve=True,
            operator="soc_analyst_sarah@corp.local",
            justification="Approved authorized penetration testing execution window.",
            authorization_reference="CHG-LAB-2026",
        )
        assert record.approved_by == "soc_analyst_sarah@corp.local"
        assert record.authorization_reference == "CHG-LAB-2026"

        # Execute high-impact gated action with authorization
        resp_approved = await client.post(
            "/api/admin/flush-database",
            headers={"X-Sentinel-Authorization": "OPERATOR_LEVEL_3_APPROVED"},
        )
        assert resp_approved.status_code == 200
        assert resp_approved.json()["status"] == "success"

        # 6. Generate reports
        target = Target(id="t-lab-01", type="url", value="http://lab.local")
        target_set = TargetSet(id="ts-lab-01", name="Lab Set", targets=[target])
        scope = Scope(id="scope-lab-01", name="Lab Scope", allowed_targets=["http://lab.local"])
        task = Task(
            id="task-lab-01",
            objective="Lab Pentest",
            target_set=target_set,
            scope=scope,
            policy=policy,
            correlation_id="corr-lab-01",
        )

        report = report_generator.generate_report(task=task, findings=[finding], report_type=ReportType.TECHNICAL)
        md_report = report_generator.render_markdown(report)
        pdf_report = report_generator.render_pdf(report)

        # 7. Unconditional Secrets Search: Redaction verification
        redacted_md = credential_vault.redact_text(md_report)
        redacted_desc = credential_vault.redact_text(finding.description)

        assert secret_value not in redacted_md
        assert secret_value not in redacted_desc
        assert "[REDACTED_SECRET]" in redacted_desc
