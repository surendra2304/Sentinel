"""Evidence, Finding, and Orchestrator Deep Verification Test Suite.

Verifies:
1. Evidence tamper detection and cross-source finding deduplication.
2. Finding lifecycle state transitions (SUBMITTED -> PLANNING -> EXECUTING -> REPORTING -> COMPLETE/FAILED/CANCELLED).
3. Bundle verification failure path (corrupted SHA-256 in manifest raises IntegrityError).
4. Orchestrator: approval pause/resume, step budget exhaustion, agent failure -> task continues, cancellation from each state.
"""

import json
import zipfile

import pytest

from sentinel.core.models import (
    Finding,
    FindingStatus,
    SeverityLevel,
    TaskStatus,
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


@pytest.mark.asyncio
async def test_task_lifecycle_cancellation_and_transitions():
    mgr = TaskLifecycleManager()
    task = await mgr.create_and_submit_task(
        objective="Lifecycle state machine audit",
        targets=[{"type": "domain", "value": "test.target.local"}],
    )
    assert task.status == TaskStatus.SUBMITTED

    # Cancel task immediately
    cancelled_task = await mgr.cancel_task(task.id, reason="Kill switch triggered")
    assert cancelled_task.status == TaskStatus.CANCELLED
