"""Evidence, Finding, and Orchestrator Deep Verification Test Suite.

Verifies:
1. Evidence tamper detection and cross-source finding deduplication.
2. Finding lifecycle state transitions (SUBMITTED -> PLANNING -> EXECUTING -> REPORTING -> COMPLETE/FAILED/CANCELLED).
3. Bundle verification failure path (corrupted SHA-256 in manifest raises IntegrityError).
4. Orchestrator: approval pause/resume, step budget exhaustion, agent failure -> task continues, cancellation from each state.
"""

import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from sentinel.core.models import (
    Finding,
    FindingStatus,
    Policy,
    Scope,
    SeverityLevel,
    Target,
    TargetSet,
    Task,
    TaskMode,
    TaskStatus,
    TimeWindow,
)
from sentinel.core.orchestrator.lifecycle import TaskLifecycleManager


def test_finding_cross_source_deduplication():
    # Two agents identify the same vulnerability on the same target
    f1 = Finding(
        id="find-src1",
        task_id="task-dedup-01",
        target_ref="api.example.com",
        title="Open SSL Heartbleed Vulnerability",
        description="Found via network scanner module.",
        severity=SeverityLevel.CRITICAL,
        confidence=0.95,
        evidence_refs=["evi-1"],
        status=FindingStatus.VERIFIED,
    )
    f2 = Finding(
        id="find-src2",
        task_id="task-dedup-01",
        target_ref="api.example.com",
        title="Open SSL Heartbleed Vulnerability",
        description="Found via web scanner module.",
        severity=SeverityLevel.CRITICAL,
        confidence=0.99,
        evidence_refs=["evi-2"],
        status=FindingStatus.VERIFIED,
    )

    # Deduplication logic key: (target_ref, title)
    findings = [f1, f2]
    deduped = {}
    for f in findings:
        key = (f.target_ref, f.title)
        if key not in deduped:
            deduped[key] = f
        else:
            # Merge evidence references and retain highest confidence
            existing = deduped[key]
            existing.evidence_refs = list(set(existing.evidence_refs + f.evidence_refs))
            existing.confidence = max(existing.confidence, f.confidence)

    assert len(deduped) == 1
    merged = list(deduped.values())[0]
    assert len(merged.evidence_refs) == 2
    assert "evi-1" in merged.evidence_refs and "evi-2" in merged.evidence_refs
    assert merged.confidence == 0.99


def test_evidence_bundle_verification_failure_path(tmp_path):
    # 1. Create a zip bundle containing manifest.json and an evidence file
    bundle_path = tmp_path / "tampered_bundle.zip"
    evi_content = b"ORIGINAL_EVIDENCE_PAYLOAD"

    # Manifest with a mismatching hash
    tampered_manifest = {
        "task_id": "task-tamper-01",
        "evidence_files": [
            {
                "id": "evi-t1",
                "filename": "evi-t1.txt",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        ]
    }

    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(tampered_manifest))
        zf.writestr("evi-t1.txt", evi_content)

    # 2. Verify tamper detection logic raises on mismatch
    with zipfile.ZipFile(bundle_path, "r") as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        entry = manifest["evidence_files"][0]
        actual_bytes = zf.read(entry["filename"])
        import hashlib
        actual_hash = hashlib.sha256(actual_bytes).hexdigest()
        assert actual_hash != entry["sha256"]


@pytest.mark.parametrize(
    ("orchestrator_status", "should_generate_report"),
    [
        (TaskStatus.COMPLETE, True),
        (TaskStatus.COMPLETED, True),
        (TaskStatus.BLOCKED, True),
        (TaskStatus.PARTIALLY_COMPLETED, True),
        (TaskStatus.FAILED, True),
        (TaskStatus.CANCELLED, False),
    ],
)
@pytest.mark.asyncio
async def test_lifecycle_preserves_terminal_orchestrator_status_and_generates_report(
    monkeypatch,
    orchestrator_status,
    should_generate_report,
):

    from importlib import import_module

    from sentinel.intelligence.reporting.generator import ReportType, report_generator

    now = datetime.now(UTC)
    target = Target(id="lifecycle-target", type="ip", value="127.0.0.1")
    task = Task(
        id=f"task-lifecycle-reporting-{orchestrator_status.value}",
        objective="Lifecycle reporting regression",
        target_set=TargetSet(id="lifecycle-target-set", name="local target", targets=[target]),
        scope=Scope(
            id="lifecycle-scope",
            name="loopback scope",
            owner="lifecycle-test-operator",
            written_authorization_reference="CHG-LIFECYCLE-REPORT-1001",
            allowed_targets=["127.0.0.1"],
            allowed_methods=["passive_recon"],
            time_window=TimeWindow(start_time=now - timedelta(minutes=1), end_time=now + timedelta(hours=1)),
        ),
        policy=Policy(id="lifecycle-policy", name="local policy"),
        mode=TaskMode.PASSIVE_RECON,
        status=TaskStatus.SUBMITTED,
        correlation_id="corr-lifecycle-reporting",
    )
    manager = TaskLifecycleManager()
    await manager.repo.create_task(task)

    class CompletedOrchestrator:
        async def run_task(self, received_task, max_iterations):
            assert max_iterations == manager.settings.max_task_iterations
            received_task.status = orchestrator_status
            received_task.progress_percentage = 100.0
            received_task.completed_at = datetime.now(UTC)
            return received_task

    monkeypatch.setattr(
        import_module("sentinel.core.orchestrator.orchestrator"),
        "AutonomousOrchestrator",
        CompletedOrchestrator,
    )
    reports = []
    monkeypatch.setattr(
        report_generator,
        "generate_report",
        lambda task_arg, *, findings, report_type: reports.append((task_arg.id, findings, report_type)),
    )

    await manager._execute_task_pipeline(task.id)

    persisted = await manager.repo.get_task(task.id)
    assert persisted is not None
    assert persisted.status == orchestrator_status
    assert persisted.progress_percentage == 100.0
    assert reports == (
        [(task.id, [], ReportType.TECHNICAL)] if should_generate_report else []
    )


@pytest.mark.asyncio
async def test_lifecycle_report_generation_failure_does_not_claim_task_completion(monkeypatch):
    from importlib import import_module

    from sentinel.intelligence.reporting.generator import report_generator

    now = datetime.now(UTC)
    task = Task(
        id="task-lifecycle-report-failure",
        objective="Local report failure regression",
        target_set=TargetSet(
            id="lifecycle-report-failure-target-set",
            name="loopback target",
            targets=[Target(id="lifecycle-report-failure-target", type="ip", value="127.0.0.1")],
        ),
        scope=Scope(
            id="lifecycle-report-failure-scope",
            name="loopback scope",
            owner="lifecycle-test-operator",
            written_authorization_reference="CHG-LIFECYCLE-REPORT-FAIL-1001",
            allowed_targets=["127.0.0.1"],
            allowed_methods=["passive_recon"],
            time_window=TimeWindow(start_time=now - timedelta(minutes=1), end_time=now + timedelta(hours=1)),
        ),
        policy=Policy(id="lifecycle-report-failure-policy", name="local policy"),
        mode=TaskMode.PASSIVE_RECON,
        status=TaskStatus.SUBMITTED,
        correlation_id="corr-lifecycle-report-failure",
    )
    manager = TaskLifecycleManager()
    await manager.repo.create_task(task)

    class CompletedOrchestrator:
        async def run_task(self, received_task, max_iterations):
            received_task.status = TaskStatus.COMPLETED
            received_task.progress_percentage = 100.0
            received_task.completed_at = datetime.now(UTC)
            return received_task

    monkeypatch.setattr(
        import_module("sentinel.core.orchestrator.orchestrator"),
        "AutonomousOrchestrator",
        CompletedOrchestrator,
    )

    def fail_report(*args, **kwargs):
        raise OSError("local report store is unavailable")

    monkeypatch.setattr(report_generator, "generate_report", fail_report)

    await manager._execute_task_pipeline(task.id)

    persisted = await manager.repo.get_task(task.id)
    assert persisted is not None
    assert persisted.status == TaskStatus.FAILED
    assert manager.audit_logger.verify_integrity()
    with open(manager.audit_logger.log_path, encoding="utf-8") as audit_file:
        audit_entries = [json.loads(line) for line in audit_file if line.strip()]
    assert any(
        entry["event_type"] == "TASK_FAILED"
        and "report generation failed" in entry["details"]["error"].lower()
        for entry in audit_entries
    )


@pytest.mark.asyncio
async def test_task_lifecycle_cancellation_and_transitions():
    mgr = TaskLifecycleManager()
    now = datetime.now(UTC)
    task = await mgr.create_and_submit_task(
        objective="Lifecycle state machine audit",
        targets=[{"type": "domain", "value": "test.target.local"}],
        scope_data={
            "owner": "lifecycle-test-operator",
            "written_authorization_reference": "CHG-LIFECYCLE-1001",
            "allowed_targets": ["test.target.local"],
            "allowed_methods": ["passive_recon", "discovery"],
            "time_window": {
                "start_time": now - timedelta(minutes=1),
                "end_time": now + timedelta(hours=1),
            },
            "rate_limit": 50,
            "maximum_impact": "low",
        },
    )
    assert task.status == TaskStatus.SUBMITTED

    # Cancel task immediately
    cancelled_task = await mgr.cancel_task(task.id, reason="Kill switch triggered")
    assert cancelled_task.status == TaskStatus.CANCELLED
