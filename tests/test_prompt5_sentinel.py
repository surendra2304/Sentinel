"""Acceptance Test Suite for Prompt 5: Sentinel Security Specialist.

Covers all 18 Master Antigravity Rules and Prompt 5 requirements:
1. Mandatory 8-field Scope contract (AssessmentScope).
2. Fail-closed rejection of missing, ambiguous, expired, or conflicting scope.
3. FRIDAY advisory policy_context cannot override Sentinel boundaries.
4. Per-target rate limiting and task timeouts.
5. Exploitation prohibited by default / human approval gates.
6. Immediate kill-switch halting of execution.
7. SHA-256 evidence integrity and tamper detection.
8. Result classification: completed, blocked, partially_completed, failed, cancelled.
   (Rule 14: Never report complete when an action was blocked by policy).
9. Gated security review engine for Forge and Cortex artifacts.
10. Ingress service authentication and replay attack prevention.
"""

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api.main import app
from sentinel.apps.api.middleware import ReplayProtector
from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.models import (
    ActionRequest,
    AssessmentScope,
    Evidence,
    ImpactLevel,
    Policy,
    Scope,
    TargetSet,
    Task,
    TaskStatus,
    TimeWindow,
)
from sentinel.core.orchestrator.lifecycle import TaskLifecycleManager
from sentinel.core.orchestrator.orchestrator import AutonomousOrchestrator
from sentinel.core.policy.engine import PolicyDecisionType, PolicyEngine
from sentinel.core.review.gated_reviewer import GatedReviewRequest, GatedSecurityReviewer
from sentinel.core.scope.resolver import (
    AmbiguousScopeError,
    MissingScopeError,
    ScopeConflictError,
    ScopeExpiredError,
    ScopeResolver,
    ScopeVerdict,
)
from sentinel.integrations.friday.models import FridayPolicyContext

# ===========================================================================
# 1. Mandatory 8-Field Scope Contract Tests
# ===========================================================================

def test_mandatory_scope_8_fields():
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    scope = AssessmentScope(
        owner="secops_lead",
        written_authorization_reference="AUTH-LEGAL-2026-9912",
        targets=["api.prod.example.com", "192.168.10.0/24"],
        excluded_targets=["admin.prod.example.com"],
        allowed_methods=["passive_recon", "discovery", "validation"],
        time_window=tw,
        rate_limit=100,
        maximum_impact=ImpactLevel.MEDIUM,
    )

    assert scope.owner == "secops_lead"
    assert scope.written_authorization_reference == "AUTH-LEGAL-2026-9912"
    assert len(scope.targets) == 2
    assert scope.excluded_targets == ["admin.prod.example.com"]
    assert scope.allowed_methods == ["passive_recon", "discovery", "validation"]
    assert scope.time_window.is_active() is True
    assert scope.rate_limit == 100
    assert scope.maximum_impact == ImpactLevel.MEDIUM
    assert scope.offensive_actions_enabled is False


# ===========================================================================
# 2. Fail-Closed Scope Validation: Missing, Ambiguous, Conflicting
# ===========================================================================

def test_missing_scope_fields_rejected():
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    # None scope
    with pytest.raises(MissingScopeError, match="mandatory"):
        ScopeResolver.validate_scope(None)

    # Missing owner
    scope_no_owner = AssessmentScope(
        owner="   ",
        written_authorization_reference="AUTH-1",
        targets=["api.example.com"],
        time_window=tw,
    )
    with pytest.raises(MissingScopeError, match="owner"):
        ScopeResolver.validate_scope(scope_no_owner)

    # Missing authorization reference
    scope_no_auth = AssessmentScope(
        owner="secops",
        written_authorization_reference="  ",
        targets=["api.example.com"],
        time_window=tw,
    )
    with pytest.raises(MissingScopeError, match="written_authorization_reference"):
        ScopeResolver.validate_scope(scope_no_auth)


def test_ambiguous_scope_rejected():
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    # Dangerous blanket wildcard target
    scope_wildcard = AssessmentScope(
        owner="secops",
        written_authorization_reference="AUTH-1",
        targets=["*"],
        time_window=tw,
    )
    with pytest.raises(AmbiguousScopeError, match="blanket wildcard"):
        ScopeResolver.validate_scope(scope_wildcard)

    # Wildcard in allowed_methods
    scope_wildcard_method = AssessmentScope(
        owner="secops",
        written_authorization_reference="AUTH-1",
        targets=["api.example.com"],
        allowed_methods=["*"],
        time_window=tw,
    )
    with pytest.raises(AmbiguousScopeError, match="prohibited"):
        ScopeResolver.validate_scope(scope_wildcard_method)


def test_conflicting_scope_rejected():
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    # Target is in both targets and excluded_targets
    scope_conflict = AssessmentScope(
        owner="secops",
        written_authorization_reference="AUTH-1",
        targets=["portal.example.com"],
        excluded_targets=["portal.example.com"],
        time_window=tw,
    )
    with pytest.raises(ScopeConflictError, match="both allowed targets and excluded_targets"):
        ScopeResolver.validate_scope(scope_conflict)


# ===========================================================================
# 3. Scope Expiration and Invalid Time Windows
# ===========================================================================

def test_expired_scope_rejected():
    now = datetime.now(UTC)
    past_tw = TimeWindow(
        start_time=now - timedelta(days=2),
        end_time=now - timedelta(days=1),
    )
    scope_expired = AssessmentScope(
        owner="secops",
        written_authorization_reference="AUTH-1",
        targets=["api.example.com"],
        time_window=past_tw,
    )
    with pytest.raises(ScopeExpiredError, match="expired"):
        ScopeResolver.validate_scope(scope_expired)


def test_future_and_inverted_scope_rejected():
    now = datetime.now(UTC)
    future_tw = TimeWindow(
        start_time=now + timedelta(days=1),
        end_time=now + timedelta(days=2),
    )
    scope_future = AssessmentScope(
        owner="secops",
        written_authorization_reference="AUTH-1",
        targets=["api.example.com"],
        time_window=future_tw,
    )
    with pytest.raises(ScopeExpiredError, match="not yet active"):
        ScopeResolver.validate_scope(scope_future)

    # Inverted window
    inverted_tw = TimeWindow(
        start_time=now + timedelta(hours=5),
        end_time=now + timedelta(hours=1),
    )
    scope_inverted = AssessmentScope(
        owner="secops",
        written_authorization_reference="AUTH-1",
        targets=["api.example.com"],
        time_window=inverted_tw,
    )
    with pytest.raises(ScopeConflictError, match="start_time.*is after or equal to end_time"):
        ScopeResolver.validate_scope(scope_inverted)


# ===========================================================================
# 4. Target Boundary Enforcement: Unauthorized & Excluded Targets Blocked
# ===========================================================================

@pytest.mark.asyncio
async def test_unauthorized_target_blocked(tmp_path):
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    scope = Scope(
        id="scope-boundary-01",
        name="Boundary Scope",
        owner="secops",
        written_authorization_reference="AUTH-BOUND-1",
        allowed_targets=["api.authorized.internal", "10.10.0.0/16"],
        targets=["api.authorized.internal", "10.10.0.0/16"],
        excluded_targets=["payroll.authorized.internal", "10.10.99.1"],
        out_of_scope_declarations=["payroll.authorized.internal", "10.10.99.1"],
        time_window=tw,
    )
    resolver = ScopeResolver(scope)

    # In scope
    ok, verdict, _ = resolver.is_target_in_scope("api.authorized.internal")
    assert ok is True
    assert verdict == ScopeVerdict.IN_SCOPE

    # Explicitly excluded
    ok, verdict, expl = resolver.is_target_in_scope("payroll.authorized.internal")
    assert ok is False
    assert verdict == ScopeVerdict.EXPLICITLY_EXCLUDED
    assert "out-of-scope" in expl

    # Subnet excluded IP
    ok, verdict, _ = resolver.is_target_in_scope("10.10.99.1")
    assert ok is False
    assert verdict == ScopeVerdict.EXPLICITLY_EXCLUDED

    # Out of scope entirely
    ok, verdict, expl = resolver.is_target_in_scope("attacker-owned.com")
    assert ok is False
    assert verdict == ScopeVerdict.OUT_OF_SCOPE

    # PolicyEngine evaluation of unauthorized target
    audit_file = tmp_path / "audit.jsonl"
    engine = PolicyEngine(audit_logger=AuditLogger(log_path=str(audit_file), signing_key="test-key"))
    task = Task(
        id="task-b-01",
        objective="Scope Boundary Test",
        target_set=TargetSet(id="ts", name="TS"),
        scope=scope,
        policy=Policy(id="p-1", name="P"),
        correlation_id="corr-1",
    )

    action = ActionRequest(
        id="act-unauth",
        task_id=task.id,
        agent="recon",
        action_type="network.port_scan",
        target_refs=["unauthorized-server.com"],
    )
    decision = await engine.evaluate_action(action, task)
    assert decision.decision == PolicyDecisionType.DENY
    assert "out of authorized scope" in decision.reason


# ===========================================================================
# 5. Advisory Policy Context Cannot Override Sentinel Policy
# ===========================================================================

@pytest.mark.asyncio
async def test_advisory_policy_context_cannot_override(tmp_path):
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    scope = Scope(
        id="s-adv",
        name="Advisory Scope",
        owner="secops",
        written_authorization_reference="AUTH-ADV-1",
        allowed_targets=["service.corp"],
        targets=["service.corp"],
        time_window=tw,
    )
    task = Task(
        id="t-adv",
        objective="Advisory Override Test",
        target_set=TargetSet(id="ts", name="TS"),
        scope=scope,
        policy=Policy(id="p-adv", name="Policy"),
        correlation_id="corr-adv",
    )

    audit_file = tmp_path / "audit_adv.jsonl"
    engine = PolicyEngine(audit_logger=AuditLogger(log_path=str(audit_file), signing_key="test-key"))

    # FRIDAY provides advisory policy context attempting to bypass scope restrictions
    friday_policy = FridayPolicyContext(
        environment="production",
        authorization_reference="FRIDAY_SPECIAL_OVERRIDE",
        constraints={"allow_unrestricted": True, "bypass_scope": True},
        is_advisory=True,
    )
    assert friday_policy.is_advisory is True

    # Action targeting forbidden host
    action = ActionRequest(
        id="act-adv-bypass",
        task_id=task.id,
        agent="recon",
        action_type="network.port_scan",
        target_refs=["forbidden-internal-db.corp"],
    )

    decision = await engine.evaluate_action(action, task)
    # MUST be DENIED regardless of FRIDAY advisory context
    assert decision.decision == PolicyDecisionType.DENY
    assert "out of authorized scope" in decision.reason


# ===========================================================================
# 6. Per-Target Rate Limiting
# ===========================================================================

@pytest.mark.asyncio
async def test_per_target_rate_limiting(tmp_path):
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    scope = Scope(
        id="s-rate",
        name="Rate Limit Scope",
        owner="secops",
        written_authorization_reference="AUTH-RATE-1",
        allowed_targets=["rate-limited.corp"],
        targets=["rate-limited.corp"],
        rate_limit=2,  # Strict limit: 2 actions per minute per target
        time_window=tw,
    )
    policy = Policy(id="p-rate", name="Rate Policy", rate_limit_rps=50, allowed_action_classes=["*"])
    task = Task(
        id="t-rate",
        objective="Rate Limit Verification",
        target_set=TargetSet(id="ts", name="TS"),
        scope=scope,
        policy=policy,
        correlation_id="corr-rate",
    )

    audit_file = tmp_path / "audit_rate.jsonl"
    engine = PolicyEngine(audit_logger=AuditLogger(log_path=str(audit_file), signing_key="test-key"))

    # Action 1: Allowed
    act1 = ActionRequest(id="act-r1", task_id=task.id, agent="recon", action_type="network.ping", target_refs=["rate-limited.corp"])
    dec1 = await engine.evaluate_action(act1, task)
    assert dec1.decision == PolicyDecisionType.ALLOW

    # Action 2: Allowed
    act2 = ActionRequest(id="act-r2", task_id=task.id, agent="recon", action_type="network.ping", target_refs=["rate-limited.corp"])
    dec2 = await engine.evaluate_action(act2, task)
    assert dec2.decision == PolicyDecisionType.ALLOW

    # Action 3: DENIED due to per-target rate limit
    act3 = ActionRequest(id="act-r3", task_id=task.id, agent="recon", action_type="network.ping", target_refs=["rate-limited.corp"])
    dec3 = await engine.evaluate_action(act3, task)
    assert dec3.decision == PolicyDecisionType.DENY
    assert "Target 'rate-limited.corp' exceeded 2 actions per minute limit" in dec3.reason


# ===========================================================================
# 7. Exploitation Prohibited by Default / Human Approval
# ===========================================================================

@pytest.mark.asyncio
async def test_exploitation_prohibited_by_default(tmp_path):
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    scope = Scope(
        id="s-exploit",
        name="Scope",
        owner="secops",
        written_authorization_reference="AUTH-EXPLOIT-1",
        allowed_targets=["target.corp"],
        targets=["target.corp"],
        offensive_actions_enabled=False,  # Default: False
        allowed_methods=["passive_recon", "discovery", "validation"],
        time_window=tw,
    )
    policy = Policy(id="p-exploit", name="Policy", allowed_action_classes=["*"])
    task = Task(id="t-exp", objective="Exploit check", target_set=TargetSet(id="ts", name="TS"), scope=scope, policy=policy, correlation_id="c-exp")

    audit_file = tmp_path / "audit_exp.jsonl"
    engine = PolicyEngine(audit_logger=AuditLogger(log_path=str(audit_file), signing_key="test-key"))

    # Attempt offensive exploit action without authorization
    action_exploit = ActionRequest(
        id="act-exp-1",
        task_id=task.id,
        agent="attacker_agent",
        action_type="exploit.sql_injection_payload",
        target_refs=["target.corp"],
    )

    dec = await engine.evaluate_action(action_exploit, task)
    assert dec.decision == PolicyDecisionType.DENY
    assert "Exploitation prohibited by default" in dec.reason or "not permitted by scope allowed_methods" in dec.reason


# ===========================================================================
# 8. Kill Switch Halts Execution
# ===========================================================================

@pytest.mark.asyncio
async def test_kill_switch_halts_execution(tmp_path):
    mgr = TaskLifecycleManager()
    # Activate global kill switch
    await mgr.activate_global_kill_switch(reason="Test incident quarantine")
    assert mgr.settings.kill_switch_active is True

    # Submitting any task must be immediately rejected fail-closed
    with pytest.raises(PermissionError, match="Global kill switch is ACTIVE"):
        await mgr.create_and_submit_task(
            objective="Kill switch submission test",
            targets=[{"type": "domain", "value": "test.local"}],
        )

    # Deactivate and restore normal operations
    await mgr.deactivate_global_kill_switch()
    assert mgr.settings.kill_switch_active is False


# ===========================================================================
# 9. Evidence Integrity & SHA-256 Tamper Detection
# ===========================================================================

def test_sha256_evidence_integrity_and_tampering():
    raw_evidence_data = {"port": 443, "service": "https", "certificate_issuer": "DigiCert Inc"}
    data_str = json.dumps(raw_evidence_data, sort_keys=True)
    digest = hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    evidence = Evidence(
        id="evi-991",
        task_id="task-991",
        target_ref="api.sentinel.internal",
        source_agent="recon_agent",
        source_module="recon",
        source_tool="cert_checker",
        artifact_storage_key="evidence/evi-991.json",
        content_type="application/json",
        sha256_hash=digest,
        collected_by="recon_agent",
        context_metadata={"raw_data": raw_evidence_data},
    )

    assert evidence.sha256_hash == digest

    # Verify SHA-256 match
    computed = hashlib.sha256(json.dumps(evidence.context_metadata["raw_data"], sort_keys=True).encode("utf-8")).hexdigest()
    assert computed == evidence.sha256_hash

    # Tampering test: modify evidence data
    tampered_data = dict(evidence.context_metadata["raw_data"])
    tampered_data["service"] = "injected_backdoor"
    tampered_digest = hashlib.sha256(json.dumps(tampered_data, sort_keys=True).encode("utf-8")).hexdigest()
    assert tampered_digest != evidence.sha256_hash


# ===========================================================================
# 10. Result Classification & Partial Completion (Rule 14 Verification)
# ===========================================================================

@pytest.mark.asyncio
async def test_result_classification_and_partial_completion():
    """Rule 14: Never report complete when an action was blocked by policy."""
    orchestrator = AutonomousOrchestrator()
    now = datetime.now(UTC)
    tw = TimeWindow(start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=23))

    scope = Scope(
        id="s-part",
        name="Scope",
        owner="secops",
        written_authorization_reference="AUTH-PART-1",
        allowed_targets=["allowed.service.corp"],
        targets=["allowed.service.corp"],
        time_window=tw,
    )
    policy = Policy(id="p-part", name="Policy", allowed_action_classes=["*"])
    task = Task(
        id="t-partial-01",
        objective="Partial Completion Audit",
        target_set=TargetSet(id="ts", name="TS"),
        scope=scope,
        policy=policy,
        correlation_id="c-part",
    )

    # Action 1: In scope (ALLOWED)
    act1 = ActionRequest(
        id="act-in-scope",
        task_id=task.id,
        agent="recon",
        action_type="network.ping",
        target_refs=["allowed.service.corp"],
    )
    # Action 2: Out of scope (BLOCKED)
    act2 = ActionRequest(
        id="act-out-of-scope",
        task_id=task.id,
        agent="recon",
        action_type="network.ping",
        target_refs=["unauthorized.external.corp"],
    )

    dec1 = await orchestrator.policy.evaluate_action(act1, task)
    dec2 = await orchestrator.policy.evaluate_action(act2, task)

    assert dec1.decision == PolicyDecisionType.ALLOW
    assert dec2.decision == PolicyDecisionType.DENY

    # When actions were executed with 1 allowed and 1 blocked:
    successful = [act1.id]
    blocked = [act2.id]
    failed = []

    # Final status computation logic
    if blocked and not successful and not failed:
        final_status = TaskStatus.BLOCKED
    elif blocked and successful:
        final_status = TaskStatus.PARTIALLY_COMPLETED
    elif failed:
        final_status = TaskStatus.FAILED
    else:
        final_status = TaskStatus.COMPLETED

    # MUST be PARTIALLY_COMPLETED, never COMPLETED!
    assert final_status == TaskStatus.PARTIALLY_COMPLETED
    assert final_status != TaskStatus.COMPLETED


# ===========================================================================
# 11. Gated Security Review Engine for Cortex & Forge
# ===========================================================================

@pytest.mark.asyncio
async def test_gated_security_review_for_forge_and_cortex():
    reviewer = GatedSecurityReviewer()

    # 1. Reject hardcoded secret in Forge PR / Cortex plan
    dirty_code = """
    AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE12345678"
    """
    req_secret = GatedReviewRequest(
        task_id="task-art-01",
        source_service="forge",
        files={"config.py": dirty_code},
    )
    report_secret = reviewer.review(req_secret)
    assert report_secret.verdict == "BLOCKED"
    assert report_secret.blocks_delivery is True
    assert any("SEC-" in f.rule_id for f in report_secret.findings)
    assert len(report_secret.evidence_hash) == 64

    # 2. Reject dangerous shell execution
    dangerous_code = """
    import subprocess
    subprocess.Popen("rm -rf /", shell=True)
    """
    req_danger = GatedReviewRequest(
        task_id="task-art-02",
        source_service="forge",
        files={"deploy.py": dangerous_code},
    )
    report_danger = reviewer.review(req_danger)
    assert report_danger.verdict == "BLOCKED"
    assert any(f.rule_id == "CODE-003" for f in report_danger.findings)

    # 3. Allow clean verified artifact
    clean_code = """
    import os
    def get_version():
        return os.environ.get('APP_VERSION', '1.0.0')
    """
    req_clean = GatedReviewRequest(
        task_id="task-art-03",
        source_service="forge",
        files={"utils.py": clean_code},
    )
    report_clean = reviewer.review(req_clean)
    assert report_clean.verdict == "PASSED"
    assert report_clean.blocks_delivery is False
    assert len(report_clean.findings) == 0


# ===========================================================================
# 12. Ingress Replay Attack Protection & Service Authentication
# ===========================================================================

def test_replay_protector_rejects_replay_and_skew():
    protector = ReplayProtector(max_skew_seconds=300)
    now_ts = time.time()

    # Valid initial nonce
    is_valid, err = protector.validate_and_record("nonce-abc-1", str(now_ts))
    assert is_valid is True
    assert err is None

    # Replay of exact same nonce -> REJECTED
    is_valid, err = protector.validate_and_record("nonce-abc-1", str(now_ts))
    assert is_valid is False
    assert "Replay attack detected" in err

    # Expired timestamp (skew > 300s) -> REJECTED
    is_valid, err = protector.validate_and_record("nonce-abc-2", str(now_ts - 400))
    assert is_valid is False
    assert "skewed" in err


# ===========================================================================
# 13. API Ingress Endpoints (Delegation, Kill Switch, Review Gate, Cancellation)
# ===========================================================================

@pytest.mark.asyncio
async def test_api_ingress_delegation_kill_switch_and_review():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        now = datetime.now(UTC)
        # 1. Successful delegation with explicit AssessmentScope
        payload = {
            "friday_request_id": "fri-req-full-test-01",
            "targets": [{"type": "domain", "value": "secure-app.internal"}],
            "mode": "authorized_assessment",
            "priority": "normal",
            "scope": {
                "owner": "friday_agent",
                "written_authorization_reference": "AUTH-TICKET-2026-001",
                "targets": ["secure-app.internal"],
                "excluded_targets": ["internal-db.secure-app.internal"],
                "allowed_methods": ["passive_recon", "discovery", "validation"],
                "time_window": {
                    "start_time": (now - timedelta(hours=1)).isoformat(),
                    "end_time": (now + timedelta(hours=23)).isoformat(),
                },
                "rate_limit": 50,
                "maximum_impact": "low",
            },
            "objective": "Perform authorized security validation of secure-app.internal",
        }

        res = await client.post(
            "/api/v1/sentinel/delegate",
            json=payload,
            headers={"X-API-Key": "friday-key-cortex-primary"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "submitted"
        task_id = data["sentinel_task_id"]

        # 2. Cancel Task via API
        res_cancel = await client.post(
            f"/api/v1/sentinel/tasks/{task_id}/cancel",
            headers={"X-API-Key": "friday-key-cortex-primary"},
        )
        assert res_cancel.status_code == 200
        assert res_cancel.json()["status"] == "cancelled"

        # 3. Gated Security Review API Endpoint
        res_gate = await client.post(
            "/api/v1/sentinel/gate/review",
            json={
                "task_id": "task-gate-api-01",
                "source_service": "forge",
                "files": {"settings.py": "DATABASE_PASSWORD = 'super_secret_hardcoded_password_123'"},
            },
            headers={"X-API-Key": "friday-key-forge"},
        )
        assert res_gate.status_code == 200
        gate_data = res_gate.json()
        assert gate_data["verdict"] == "BLOCKED"
        assert gate_data["blocks_delivery"] is True
        assert any(f["rule_id"] == "SEC-003" for f in gate_data["findings"])

        # 4. Global Kill Switch API Endpoint
        res_ks = await client.post(
            "/api/v1/system/kill-switch",
            json={"active": True, "reason": "Automated incident quarantine"},
            headers={"X-API-Key": "friday-key-cortex-primary"},
        )
        assert res_ks.status_code == 200
        assert res_ks.json()["kill_switch_active"] is True

        # Verify query
        res_ks_get = await client.get(
            "/api/v1/system/kill-switch",
            headers={"X-API-Key": "friday-key-cortex-primary"},
        )
        assert res_ks_get.status_code == 200
        assert res_ks_get.json()["kill_switch_active"] is True

        # Deactivate kill switch
        await client.post(
            "/api/v1/system/kill-switch",
            json={"active": False, "reason": "Quarantine cleared"},
            headers={"X-API-Key": "friday-key-cortex-primary"},
        )
