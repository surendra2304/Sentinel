from datetime import UTC, datetime, timedelta

import pytest

from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.models import (
    ActionRequest,
    ImpactLevel,
    Policy,
    Scope,
    TargetSet,
    TargetType,
    Task,
)
from sentinel.core.policy.engine import PolicyDecisionType, PolicyEngine
from sentinel.core.scope.resolver import (
    ScopeResolver,
    ScopeVerdict,
    TargetResolutionError,
)

# ---------------------------------------------------------------------------
# 1. Target Normalization & Scope Resolver Tests
# ---------------------------------------------------------------------------

def test_scope_resolver_target_normalization():
    # Domain
    t_dom = ScopeResolver.normalize_target("API.Sentinel.Security")
    assert t_dom.type == TargetType.DOMAIN
    assert t_dom.value == "api.sentinel.security"

    # IP
    t_ip = ScopeResolver.normalize_target("192.168.1.1")
    assert t_ip.type == TargetType.IP
    assert t_ip.value == "192.168.1.1"

    # CIDR
    t_cidr = ScopeResolver.normalize_target("10.0.0.1/24")
    assert t_cidr.type == TargetType.CIDR
    assert t_cidr.value == "10.0.0.0/24"

    # URL with port and path
    t_url = ScopeResolver.normalize_target("https://api.sentinel.security:8443/v1/auth/login")
    assert t_url.type == TargetType.URL
    assert t_url.value == "https://api.sentinel.security:8443/v1/auth/login"

    # Wireless BSSID
    t_wifi = ScopeResolver.normalize_target("00:14:22:01:23:45")
    assert t_wifi.type == TargetType.WIRELESS_NETWORK
    assert t_wifi.value == "00:14:22:01:23:45"

    # Cloud Account
    t_cloud = ScopeResolver.normalize_target("123456789012")
    assert t_cloud.type == TargetType.CLOUD_ACCOUNT

    # Invalid / Ambiguous
    with pytest.raises(TargetResolutionError):
        ScopeResolver.normalize_target("")

    with pytest.raises(TargetResolutionError):
        ScopeResolver.normalize_target("??? invalid !!!")


def test_scope_resolver_wildcards_and_cidrs():
    scope = Scope(
        id="scope-01",
        name="Production Multi-Tier",
        allowed_targets=[
            "*.sentinel.security",
            "10.0.0.0/24",
            "https://target.corp/api/v1",
        ],
        out_of_scope_declarations=[
            "admin.sentinel.security",
            "10.0.0.254",
        ],
    )
    resolver = ScopeResolver(scope)

    # 1. Wildcard subdomain matching
    in_scope, verdict, _ = resolver.is_target_in_scope("app.sentinel.security")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    # 2. Apex domain NOT matched by *.domain (unless explicit)
    in_scope, verdict, _ = resolver.is_target_in_scope("sentinel.security")
    assert in_scope is False

    # 3. Explicit Exclusion override
    in_scope, verdict, _ = resolver.is_target_in_scope("admin.sentinel.security")
    assert in_scope is False
    assert verdict == ScopeVerdict.EXPLICITLY_EXCLUDED

    # 4. CIDR subnet matching
    in_scope, verdict, _ = resolver.is_target_in_scope("10.0.0.15")
    assert in_scope is True

    # 5. Excluded IP in CIDR
    in_scope, verdict, _ = resolver.is_target_in_scope("10.0.0.254")
    assert in_scope is False
    assert verdict == ScopeVerdict.EXPLICITLY_EXCLUDED

    # 6. URL path scoping
    in_scope, verdict, _ = resolver.is_target_in_scope("https://target.corp/api/v1/users")
    assert in_scope is True

    in_scope, verdict, _ = resolver.is_target_in_scope("https://target.corp/admin")
    assert in_scope is False


def test_scope_resolver_adversarial_cases():
    scope = Scope(
        id="scope-adv",
        name="Adversarial Boundary Check",
        allowed_targets=["*.target.com", "172.16.0.0/16"],
        out_of_scope_declarations=["secret.target.com"],
    )
    resolver = ScopeResolver(scope)

    # Target smuggling via embedded fake domains
    in_scope, _, _ = resolver.is_target_in_scope("evil.com?.target.com")
    assert in_scope is False

    # Subdomain spoofing: nottarget.com should NOT match *.target.com
    in_scope, _, _ = resolver.is_target_in_scope("nottarget.com")
    assert in_scope is False

    # IDN / Unicode spoofing detection
    in_scope, _, _ = resolver.is_target_in_scope("xn--tget-qqa.com")
    assert in_scope is False


# ---------------------------------------------------------------------------
# 2. Policy Engine Multi-Dimension Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_policy_engine_all_dimensions(tmp_path):
    audit_file = tmp_path / "audit_test.jsonl"
    audit_logger = AuditLogger(log_path=str(audit_file), signing_key="test-key")
    engine = PolicyEngine(audit_logger=audit_logger)

    scope = Scope(
        id="scope-pci",
        name="PCI Perimeter",
        allowed_targets=["10.0.0.0/24", "app.example.com"],
        max_intensity=5,
        offensive_actions_enabled=False,
    )
    policy = Policy(
        id="pol-pci",
        name="Standard Defense Policy",
        allowed_module_classes=["recon", "network"],
        allowed_action_classes=["network.port_scan", "recon.*"],
        rate_limit_rps=5,
        max_intensity=5,
        credential_handling_rules={"disallow_stored_credentials": True},
        require_approval_for_offensive=True,
        kill_switch_active=False,
    )
    task = Task(
        id="task-pci",
        objective="Security Scan",
        target_set=TargetSet(id="ts-pci", name="Targets"),
        scope=scope,
        policy=policy,
        correlation_id="corr-pci",
    )

    # 1. ALLOW: Compliant Action
    act_allow = ActionRequest(
        id="act-01",
        task_id=task.id,
        agent="recon_agent",
        action_type="network.port_scan",
        target_refs=["10.0.0.10"],
        parameters={"intensity": 3},
        expected_impact_level=ImpactLevel.LOW,
    )
    dec1 = await engine.evaluate_action(act_allow, task)
    assert dec1.decision == PolicyDecisionType.ALLOW
    assert dec1.allowed is True

    # 2. DENY: Out of scope target
    act_out_of_scope = ActionRequest(
        id="act-02",
        task_id=task.id,
        agent="recon_agent",
        action_type="network.port_scan",
        target_refs=["192.168.100.1"],
        parameters={"intensity": 3},
    )
    dec2 = await engine.evaluate_action(act_out_of_scope, task)
    assert dec2.decision == PolicyDecisionType.DENY
    assert "out of authorized scope" in dec2.reason

    # 3. DENY: Action not in allowed_action_classes
    act_unauthorized_action = ActionRequest(
        id="act-03",
        task_id=task.id,
        agent="recon_agent",
        action_type="web.sql_injection",
        target_refs=["10.0.0.10"],
    )
    dec3 = await engine.evaluate_action(act_unauthorized_action, task)
    assert dec3.decision == PolicyDecisionType.DENY
    assert "not in policy allowed_action_classes" in dec3.reason

    # 4. DENY: Intensity exceeds limit
    act_high_intensity = ActionRequest(
        id="act-04",
        task_id=task.id,
        agent="recon_agent",
        action_type="network.port_scan",
        target_refs=["10.0.0.10"],
        parameters={"intensity": 9},
    )
    dec4 = await engine.evaluate_action(act_high_intensity, task)
    assert dec4.decision == PolicyDecisionType.DENY
    assert "exceeds maximum allowed intensity" in dec4.reason

    # 5. DENY: Stored credentials violation
    act_cred_violation = ActionRequest(
        id="act-05",
        task_id=task.id,
        agent="recon_agent",
        action_type="network.port_scan",
        target_refs=["10.0.0.10"],
        parameters={"password": "secret_root_password"},
    )
    dec5 = await engine.evaluate_action(act_cred_violation, task)
    assert dec5.decision == PolicyDecisionType.DENY
    assert "Credential policy violation" in dec5.reason

    # 6. REQUIRE_APPROVAL: High-impact action
    act_high_impact = ActionRequest(
        id="act-06",
        task_id=task.id,
        agent="exploit_agent",
        action_type="recon.deep_inspection",
        target_refs=["10.0.0.10"],
        expected_impact_level=ImpactLevel.HIGH,
    )
    dec6 = await engine.evaluate_action(act_high_impact, task)
    assert dec6.decision == PolicyDecisionType.REQUIRE_APPROVAL
    assert dec6.requires_approval is True
    assert dec6.approval_id is not None

    # 7. DENY: Kill Switch Activation
    policy.kill_switch_active = True
    act_kill = ActionRequest(
        id="act-07",
        task_id=task.id,
        agent="recon_agent",
        action_type="network.port_scan",
        target_refs=["10.0.0.10"],
    )
    dec7 = await engine.evaluate_action(act_kill, task)
    assert dec7.decision == PolicyDecisionType.DENY
    assert "Kill Switch" in dec7.reason


# ---------------------------------------------------------------------------
# 3. Human Approval Workflow Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_approval_workflow(tmp_path):
    audit_file = tmp_path / "audit_approval.jsonl"
    engine = PolicyEngine(audit_logger=AuditLogger(log_path=str(audit_file), signing_key="test-key"))

    scope = Scope(id="s-appr", name="Scope", allowed_targets=["10.0.0.1"])
    policy = Policy(id="p-appr", name="Policy", allowed_action_classes=["*"])
    task = Task(id="t-appr", objective="Obj", target_set=TargetSet(id="ts", name="TS"), scope=scope, policy=policy, correlation_id="c-appr")

    action = ActionRequest(
        id="act-req-appr",
        task_id=task.id,
        agent="test_agent",
        action_type="exploit.payload_delivery",
        target_refs=["10.0.0.1"],
        requires_approval=True,
    )

    dec = await engine.evaluate_action(action, task)
    assert dec.decision == PolicyDecisionType.REQUIRE_APPROVAL
    assert dec.approval_id is not None

    # List pending
    pending = engine.get_pending_approvals(task_id=task.id)
    assert len(pending) == 1
    assert pending[0].approval_id == dec.approval_id

    # Approve
    approved_rec = await engine.decide_approval(
        approval_id=dec.approval_id,
        approve=True,
        operator="lead_security_officer",
        justification="Authorized under change ticket CHG-89412",
    )
    assert approved_rec.status == "APPROVED"
    assert approved_rec.approved_by == "lead_security_officer"

    # Pending list should now be empty
    assert len(engine.get_pending_approvals(task_id=task.id)) == 0

    # Expired approval check
    expired_rec = engine._create_approval_request(action, task, "Expired test")
    expired_rec.expires_at = datetime.now(UTC) - timedelta(minutes=5)
    with pytest.raises(ValueError, match="expired"):
        await engine.decide_approval(expired_rec.approval_id, True, "operator", "Justification")
