import json
import os

import pytest

from sentinel.core.models import (
    ActionRequest,
    ActionResult,
    AssetCriticality,
    Event,
    EventType,
    Evidence,
    Finding,
    FindingStatus,
    ImpactLevel,
    Policy,
    Risk,
    RiskTier,
    Scope,
    SeverityLevel,
    Target,
    TargetSet,
    TargetType,
    Task,
    TaskStatus,
)
from sentinel.storage.artifacts.storage import LocalFileSystemStorage

# ---------------------------------------------------------------------------
# 1. Target & TargetSet Tests
# ---------------------------------------------------------------------------

def test_target_ip_validation():
    t_ip = Target(id="t-1", type=TargetType.IP, value="192.168.1.10")
    assert t_ip.value == "192.168.1.10"

    with pytest.raises(ValueError, match="Invalid IP address"):
        Target(id="t-2", type=TargetType.IP, value="invalid-ip-999")


def test_target_cidr_normalization():
    t_cidr = Target(id="t-3", type=TargetType.CIDR, value="10.0.0.1/24")
    # Network normalization produces 10.0.0.0/24
    assert t_cidr.value == "10.0.0.0/24"

    with pytest.raises(ValueError, match="Invalid CIDR format"):
        Target(id="t-4", type=TargetType.CIDR, value="not-a-cidr")


def test_target_url_validation():
    t_url = Target(id="t-5", type=TargetType.URL, value="https://api.sentinel.security")
    assert t_url.value == "https://api.sentinel.security"

    with pytest.raises(ValueError, match="URL target must start with"):
        Target(id="t-6", type=TargetType.URL, value="ftp://invalid.url")


def test_target_set_collection():
    t1 = Target(id="t-1", type=TargetType.IP, value="10.0.0.1")
    t2 = Target(id="t-2", type=TargetType.DOMAIN, value="sentinel.internal")
    ts = TargetSet(id="ts-1", name="Perimeter Cluster", targets=[t1, t2])
    assert len(ts.targets) == 2
    assert ts.name == "Perimeter Cluster"


# ---------------------------------------------------------------------------
# 2. Scope & Policy Tests
# ---------------------------------------------------------------------------

def test_scope_and_policy_validation():
    scope = Scope(
        id="scope-1",
        name="PCI Audit Scope",
        allowed_targets=["10.0.0.0/24", "auth.sentinel.internal"],
        max_intensity=7,
        offensive_actions_enabled=True,
    )
    assert scope.max_intensity == 7

    policy = Policy(
        id="pol-1",
        name="Strict Safeguard Policy",
        rate_limit_rps=100,
        kill_switch_active=False,
    )
    assert policy.rate_limit_rps == 100
    assert policy.require_approval_for_offensive is True


# ---------------------------------------------------------------------------
# 3. Task State Machine Tests
# ---------------------------------------------------------------------------

def test_task_state_machine_transitions():
    t1 = Target(id="t-1", type=TargetType.DOMAIN, value="target.example")
    ts = TargetSet(id="ts-1", name="TargetSet", targets=[t1])
    scope = Scope(id="s-1", name="Scope")
    policy = Policy(id="p-1", name="Policy")

    task = Task(
        id="task-001",
        objective="Recon and Asset Discovery",
        target_set=ts,
        scope=scope,
        policy=policy,
        correlation_id="corr-1234",
    )
    assert task.status == TaskStatus.SUBMITTED

    # Valid progression: SUBMITTED -> PLANNING -> EXECUTING -> REPORTING -> COMPLETE
    task.transition_to(TaskStatus.PLANNING)
    assert task.status == TaskStatus.PLANNING

    task.transition_to(TaskStatus.EXECUTING)
    assert task.status == TaskStatus.EXECUTING

    task.transition_to(TaskStatus.REPORTING)
    assert task.status == TaskStatus.REPORTING

    task.transition_to(TaskStatus.COMPLETE)
    assert task.status == TaskStatus.COMPLETE
    assert task.completed_at is not None

    # Invalid progression: COMPLETE -> EXECUTING should raise ValueError
    with pytest.raises(ValueError, match="Invalid status transition"):
        task.transition_to(TaskStatus.EXECUTING)


# ---------------------------------------------------------------------------
# 4. ActionRequest & ActionResult Tests
# ---------------------------------------------------------------------------

def test_action_request_and_result():
    action = ActionRequest(
        id="act-001",
        task_id="task-001",
        agent="recon_agent",
        action_type="network.port_scan",
        parameters={"ports": "1-1000", "timing": "T4"},
        expected_impact_level=ImpactLevel.LOW,
    )
    assert action.agent == "recon_agent"
    assert action.action_type == "network.port_scan"

    result = ActionResult(
        action_id="act-001",
        task_id="task-001",
        success=True,
        output_summary="Found 3 open ports: 22, 80, 443",
        duration_seconds=4.25,
    )
    assert result.success is True
    assert result.duration_seconds == 4.25


# ---------------------------------------------------------------------------
# 5. Evidence & Finding Tests (Evidence-First Anchor)
# ---------------------------------------------------------------------------

def test_evidence_hashing_and_finding_anchor():
    valid_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    evidence = Evidence(
        id="evi-001",
        task_id="task-001",
        target_ref="10.0.0.1",
        source_agent="recon_agent",
        source_module="network",
        source_tool="nmap",
        artifact_storage_key="tasks/task-001/nmap_scan.xml",
        content_type="application/xml",
        sha256_hash=valid_hash,
        collected_by="operator_surendra",
    )
    assert evidence.sha256_hash == valid_hash

    # Invalid SHA-256 hash must fail
    with pytest.raises(ValueError, match="Invalid SHA-256 hash format"):
        Evidence(
            id="evi-002",
            task_id="task-001",
            target_ref="10.0.0.1",
            source_agent="recon_agent",
            source_module="network",
            source_tool="nmap",
            artifact_storage_key="bad.xml",
            content_type="application/xml",
            sha256_hash="bad-hash",
            collected_by="operator",
        )

    # Finding MUST anchor to evidence
    finding = Finding(
        id="find-001",
        task_id="task-001",
        title="Exposed Open SSH Service",
        description="SSH service running on non-standard port with default banner.",
        target_ref="10.0.0.1:2222",
        severity=SeverityLevel.MEDIUM,
        confidence=0.95,
        evidence_refs=["evi-001"],
    )
    assert finding.status == FindingStatus.OPEN
    assert "evi-001" in finding.evidence_refs

    # Evidence-First violation: Empty evidence refs
    with pytest.raises(ValueError, match="Evidence-First violation"):
        Finding(
            id="find-002",
            task_id="task-001",
            title="Unanchored Finding",
            description="No proof attached",
            target_ref="10.0.0.1",
            severity=SeverityLevel.HIGH,
            evidence_refs=[],
        )


# ---------------------------------------------------------------------------
# 6. Risk Model Calculation Tests
# ---------------------------------------------------------------------------

def test_risk_score_calculation():
    risk_critical = Risk(
        id="risk-001",
        finding_id="find-001",
        task_id="task-001",
        severity=SeverityLevel.CRITICAL,
        asset_criticality=AssetCriticality.CRITICAL,
        exposure_score=1.0,
        exploitability_score=1.0,
        confidence_score=1.0,
    )
    assert risk_critical.computed_risk_score == 100.0
    assert risk_critical.risk_tier == RiskTier.CRITICAL

    risk_info = Risk(
        id="risk-002",
        finding_id="find-002",
        task_id="task-001",
        severity=SeverityLevel.INFO,
        asset_criticality=AssetCriticality.LOW,
        exposure_score=0.2,
        exploitability_score=0.1,
        confidence_score=0.8,
    )
    assert risk_info.risk_tier == RiskTier.MINIMAL


# ---------------------------------------------------------------------------
# 7. Event Model Tests
# ---------------------------------------------------------------------------

def test_event_envelope():
    event = Event(
        event_id="evt-999",
        event_type=EventType.ALERT,
        topic="sentinel.policy.violation",
        source="sentinel.core.policy",
        payload={"action_id": "act-001", "reason": "Target out of bounds"},
        correlation_id="corr-1234",
    )
    assert event.event_type == EventType.ALERT
    assert event.topic == "sentinel.policy.violation"


# ---------------------------------------------------------------------------
# 8. Artifact Storage Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_local_artifact_storage(tmp_path):
    storage = LocalFileSystemStorage(base_dir=str(tmp_path))
    data = b"NMAP SCAN RESULTS EVIDENCE PAYLOAD"
    key = "evidence/scan_001.txt"

    uri, sha256 = await storage.store_artifact(key, data, "text/plain")
    assert uri.startswith("file://")
    assert sha256 is not None

    assert await storage.exists(key) is True
    retrieved = await storage.get_artifact(key)
    assert retrieved == data

    deleted = await storage.delete_artifact(key)
    assert deleted is True
    assert await storage.exists(key) is False


# ---------------------------------------------------------------------------
# 9. JSON Schema Generation Tests
# ---------------------------------------------------------------------------

def test_json_schemas_exist():
    schemas = [
        "task.schema.json",
        "action.schema.json",
        "evidence.schema.json",
        "finding.schema.json",
        "risk.schema.json",
        "event.schema.json",
        "policy.schema.json",
        "scope.schema.json",
    ]
    for schema_file in schemas:
        path = os.path.join("sentinel", "contracts", schema_file)
        assert os.path.exists(path), f"Missing schema file: {path}"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            assert data.get("schema_version") == "1.0.0"
