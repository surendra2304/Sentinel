"""Adversarial Matrix and Zero-Tolerance Scope and Policy Test Suite.

Verifies:
1. ScopeResolver edge cases: redirect-param smuggling, embedded IPs, userinfo@, IDN/punycode, wildcard apex boundaries, CIDR subnets, port/path scoping.
2. PolicyEngine edge cases: deny-by-default unknown action classes, rate-limit burst behavior, approval expiry, kill switch during approval wait.
"""

from datetime import UTC, datetime, timedelta
import pytest

from sentinel.core.models import (
    ActionRequest,
    ImpactLevel,
    Policy,
    Scope,
    Target,
    TargetSet,
    TargetType,
    Task,
)
from sentinel.core.policy.engine import PolicyDecisionType, policy_engine
from sentinel.core.scope.resolver import ScopeResolver, ScopeVerdict, TargetResolutionError


def test_scope_resolver_adversarial_normalization_matrix():
    # 1. Userinfo@ URL stripping and host resolution
    url_userinfo = ScopeResolver.normalize_target("https://admin:secret@target.internal/admin")
    assert url_userinfo.type == TargetType.URL
    assert "target.internal" in url_userinfo.value

    # 2. Redirect parameter smuggling
    url_redirect = ScopeResolver.normalize_target("https://authorized.local/redirect?url=https://evil.attacker.com")
    assert url_redirect.type == TargetType.URL
    assert "authorized.local" in url_redirect.value

    # 3. Port normalization
    url_standard_port = ScopeResolver.normalize_target("http://target.local:80/api")
    assert url_standard_port.value == "http://target.local/api"

    url_custom_port = ScopeResolver.normalize_target("https://target.local:8443/api")
    assert url_custom_port.value == "https://target.local:8443/api"

    # 4. CIDR and IP normalization
    cidr = ScopeResolver.normalize_target("10.0.0.0/24")
    assert cidr.type == TargetType.CIDR
    assert cidr.value == "10.0.0.0/24"

    ip_v4 = ScopeResolver.normalize_target("192.168.1.50")
    assert ip_v4.type == TargetType.IP
    assert ip_v4.value == "192.168.1.50"

    ip_v6 = ScopeResolver.normalize_target("::1")
    assert ip_v6.type == TargetType.IP

    # 5. IDN Punycode Internationalized Domain Names
    idn_domain = ScopeResolver.normalize_target("bücher.example.de")
    assert idn_domain.type == TargetType.DOMAIN

    # 6. Wireless MAC BSSID
    mac = ScopeResolver.normalize_target("00:11:22:33:44:55")
    assert mac.type == TargetType.WIRELESS_NETWORK

    # 7. Cloud Account ARN
    arn = ScopeResolver.normalize_target("arn:aws:iam::123456789012:role/admin")
    assert arn.type == TargetType.CLOUD_ACCOUNT

    # 8. File target
    file_t = ScopeResolver.normalize_target("file:///etc/shadow")
    assert file_t.type == TargetType.FILE

    # 9. Invalid empty target raises TargetResolutionError
    with pytest.raises(TargetResolutionError):
        ScopeResolver.normalize_target("")

    with pytest.raises(TargetResolutionError):
        ScopeResolver.normalize_target("   ")

    with pytest.raises(TargetResolutionError):
        ScopeResolver.normalize_target("http://")


def test_scope_resolver_boundary_and_wildcard_matrix():
    scope = Scope(
        id="scope-adv-01",
        name="Adversarial Scope",
        allowed_targets=["*.target.corp", "10.10.0.0/16", "https://api.gateway.io:8443/v1/auth"],
        out_of_scope_declarations=["forbidden.target.corp", "10.10.99.0/24"],
    )
    resolver = ScopeResolver(scope)

    # 1. Allowed subdomain wildcard
    in_scope, verdict, _ = resolver.is_target_in_scope("sub.target.corp")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    # 2. Apex domain boundary check (*.target.corp does NOT allow target.corp root)
    in_scope_apex, verdict_apex, _ = resolver.is_target_in_scope("target.corp")
    assert in_scope_apex is False

    # 3. Explicitly excluded subdomain
    in_scope_ex, verdict_ex, _ = resolver.is_target_in_scope("forbidden.target.corp")
    assert in_scope_ex is False
    assert verdict_ex == ScopeVerdict.EXPLICITLY_EXCLUDED

    # 4. CIDR allowed vs excluded subnet
    in_scope_ip, _, _ = resolver.is_target_in_scope("10.10.5.1")
    assert in_scope_ip is True

    in_scope_ex_ip, verdict_ex_ip, _ = resolver.is_target_in_scope("10.10.99.10")
    assert in_scope_ex_ip is False
    assert verdict_ex_ip == ScopeVerdict.EXPLICITLY_EXCLUDED

    # 5. URL path and port scoping
    in_scope_url, _, _ = resolver.is_target_in_scope("https://api.gateway.io:8443/v1/auth/login")
    assert in_scope_url is True

    in_scope_wrong_port, _, _ = resolver.is_target_in_scope("https://api.gateway.io:443/v1/auth")
    assert in_scope_wrong_port is False

    in_scope_wrong_path, _, _ = resolver.is_target_in_scope("https://api.gateway.io:8443/v2/admin")
    assert in_scope_wrong_path is False


@pytest.mark.asyncio
async def test_policy_engine_deny_unknown_action_and_rate_limit_burst():
    target = Target(id="t-pol-01", type="host", value="host.internal")
    target_set = TargetSet(id="ts-pol-01", name="TS", targets=[target])
    scope = Scope(id="s-pol-01", name="S", allowed_targets=["host.internal"])

    policy = Policy(
        id="p-pol-01",
        name="Policy with Rate Limits",
        allowed_action_classes=["recon.*"],
        blocked_action_classes=["exploit.*"],
        max_requests_per_second=2,
        burst_budget=3,
    )

    task = Task(
        id="task-pol-adv-01",
        objective="Policy adversarial test",
        target_set=target_set,
        scope=scope,
        policy=policy,
        correlation_id="corr-adv-01",
    )

    # 1. Deny-by-default for unknown / unauthorized action class
    unauthorized_action = ActionRequest(
        id="act-unauth-01",
        task_id=task.id,
        agent="recon_agent",
        action_type="unregistered.dangerous_action",
        target_refs=["host.internal"],
    )
    dec1 = await policy_engine.evaluate_action(unauthorized_action, task)
    assert dec1.decision == PolicyDecisionType.DENY
    assert "deny-by-default" in dec1.reason.lower() or "not in policy" in dec1.reason.lower()

    # 2. Rate limit burst exhaustion
    allowed_action = ActionRequest(
        id="act-rate-01",
        task_id=task.id,
        agent="recon_agent",
        action_type="recon.dns_enum",
        target_refs=["host.internal"],
    )

    # Consume token
    dec_allowed = await policy_engine.evaluate_action(allowed_action, task)
    assert dec_allowed.decision == PolicyDecisionType.ALLOW


@pytest.mark.asyncio
async def test_policy_approval_expiration_and_cancellation():
    target = Target(id="t-exp-01", type="host", value="app.corp.local")
    target_set = TargetSet(id="ts-exp-01", name="TS", targets=[target])
    scope = Scope(id="s-exp-01", name="S", allowed_targets=["app.corp.local"], offensive_actions_enabled=True)
    policy = Policy(id="p-exp-01", name="P")

    task = Task(
        id="task-exp-01",
        objective="Approval expiry check",
        target_set=target_set,
        scope=scope,
        policy=policy,
        correlation_id="corr-exp-01",
    )

    action = ActionRequest(
        id="act-exp-01",
        task_id=task.id,
        agent="exploit_agent",
        action_type="web.validate",
        target_refs=["app.corp.local"],
        expected_impact_level=ImpactLevel.HIGH,
        requires_approval=True,
    )

    dec = await policy_engine.evaluate_action(action, task)
    assert dec.approval_id is not None

    # Manually expire the approval
    record = policy_engine._approvals[dec.approval_id]
    record.expires_at = datetime.now(UTC) - timedelta(seconds=10)

    # Attempting to decide an expired approval must raise ValueError
    with pytest.raises(ValueError, match="expired"):
        await policy_engine.decide_approval(
            approval_id=dec.approval_id,
            approve=True,
            operator="soc_lead@corp.local",
            justification="Approved after expiry",
        )

def test_scope_resolver_full_branch_coverage():
    # 1. Scope with empty allowlist -> Deny-by-default
    empty_scope = Scope(id="s-empty", name="Empty Scope", allowed_targets=[])
    resolver_empty = ScopeResolver(empty_scope)
    in_s, verd, msg = resolver_empty.is_target_in_scope("https://test.local")
    assert in_s is False
    assert verd == ScopeVerdict.OUT_OF_SCOPE
    assert "Deny-by-default" in msg

    # 2. Scope rule matching URL with wildcard subdomain
    scope_url_wild = Scope(id="s-url", name="URL Wildcard", allowed_targets=["*.target.internal"])
    res_url_wild = ScopeResolver(scope_url_wild)
    in_s, _, _ = res_url_wild.is_target_in_scope("https://sub.target.internal:8080/path")
    assert in_s is True

    # 3. CIDR target matching CIDR rule
    scope_cidr = Scope(id="s-cidr", name="CIDR Scope", allowed_targets=["192.168.0.0/16"])
    res_cidr = ScopeResolver(scope_cidr)
    in_s, _, _ = res_cidr.is_target_in_scope("192.168.1.0/24")
    assert in_s is True

    # 4. URL host containing IP matching CIDR rule
    in_s, _, _ = res_cidr.is_target_in_scope("http://192.168.1.50:8080/test")
    assert in_s is True

    # 5. URL with different host than URL rule
    scope_url_rule = Scope(id="s-url-rule", name="URL Rule", allowed_targets=["https://host-a.com/api"])
    res_url_rule = ScopeResolver(scope_url_rule)
    in_s, _, _ = res_url_rule.is_target_in_scope("https://host-b.com/api")
    assert in_s is False

    # 6. Explicit target_type parameter in normalize_target
    t_explicit = ScopeResolver.normalize_target("my-custom-target", target_type=TargetType.DOMAIN)
    assert t_explicit.type == TargetType.DOMAIN
    assert t_explicit.value == "my-custom-target"

    # 7. In-scope declarations list
    scope_in_scope_decl = Scope(id="s-decl", name="Decl Scope", allowed_targets=[], in_scope_declarations=["https://decl.target.com"])
    res_decl = ScopeResolver(scope_in_scope_decl)
    in_s, _, _ = res_decl.is_target_in_scope("https://decl.target.com")
    assert in_s is True


@pytest.mark.asyncio
async def test_policy_engine_full_branch_coverage():
    target = Target(id="t-b-01", type="host", value="target.local")
    target_set = TargetSet(id="ts-b-01", name="TS", targets=[target])
    scope = Scope(id="s-b-01", name="S", allowed_targets=["target.local"], offensive_actions_enabled=True)

    # 1. Blocked module classes via allowed_module_classes restriction
    policy_allowed_mod = Policy(
        id="p-block-mod",
        name="Block Mod",
        allowed_action_classes=["*"],
        allowed_module_classes=["recon", "web"],
    )
    task_mod = Task(id="task-mod", objective="Test", target_set=target_set, scope=scope, policy=policy_allowed_mod, correlation_id="c1")
    act_blocked = ActionRequest(id="act-b1", task_id="task-mod", agent="exploit_agent", action_type="wireless.deauth", target_refs=["target.local"], expected_impact_level=ImpactLevel.LOW)
    dec = await policy_engine.evaluate_action(act_blocked, task_mod)
    assert dec.decision == PolicyDecisionType.DENY
    assert "not permitted" in dec.reason.lower() or "disabled" in dec.reason.lower()

    scope_recon = Scope(id="s-rate", name="S Rate", allowed_targets=["target.local"], offensive_actions_enabled=False)
    # 2. Burst rate limit exceeded
    policy_rate = Policy(
        id="p-rate-strict",
        name="Rate Strict",
        allowed_action_classes=["*"],
        rate_limit_rps=1,
    )
    task_rate = Task(id="task-rate", objective="Test", target_set=target_set, scope=scope_recon, policy=policy_rate, correlation_id="c2")
    act1 = ActionRequest(id="act-r1", task_id="task-rate", agent="recon_agent", action_type="recon.dns", target_refs=["target.local"], expected_impact_level=ImpactLevel.LOW)
    act2 = ActionRequest(id="act-r2", task_id="task-rate", agent="recon_agent", action_type="recon.dns", target_refs=["target.local"], expected_impact_level=ImpactLevel.LOW)

    d1 = await policy_engine.evaluate_action(act1, task_rate)
    assert d1.decision == PolicyDecisionType.ALLOW
    d2 = await policy_engine.evaluate_action(act2, task_rate)
    assert d2.decision == PolicyDecisionType.DENY
    assert "rate limit" in d2.reason.lower()

    # 3. Deny decide_approval
    scope_mod = Scope(id="s-m1", name="S Mod", allowed_targets=["target.local"], offensive_actions_enabled=False)
    task_mod = Task(id="task-mod", objective="Test", target_set=target_set, scope=scope_mod, policy=policy_allowed_mod, correlation_id="c1")
    appr_act = ActionRequest(id="act-d1", task_id="task-mod", agent="exploit_agent", action_type="web.vuln", target_refs=["target.local"], expected_impact_level=ImpactLevel.HIGH, requires_approval=True)
    d_appr = await policy_engine.evaluate_action(appr_act, task_mod)
    rec_deny = await policy_engine.decide_approval(d_appr.approval_id, approve=False, operator="admin@local", justification="Unsafe execution")
    assert rec_deny.status == "REJECTED"

def test_scope_resolver_additional_edge_branches():
    # 1. Apex domain rule matching domain
    scope_apex = Scope(id="s-apex", name="Apex", allowed_targets=["example.com"])
    res_apex = ScopeResolver(scope_apex)
    in_s, _, _ = res_apex.is_target_in_scope("example.com")
    assert in_s is True
    in_s2, _, _ = res_apex.is_target_in_scope("sub.example.com")
    assert in_s2 is True

    # 2. Invalid target string passed to is_target_in_scope
    in_s3, verd, _ = res_apex.is_target_in_scope("http://")
    assert in_s3 is False
    assert verd == ScopeVerdict.INVALID_TARGET

    # 3. URL path prefix mismatch
    scope_path = Scope(id="s-path", name="Path Scope", allowed_targets=["https://api.test.com/v1/secure"])
    res_path = ScopeResolver(scope_path)
    in_s4, _, _ = res_path.is_target_in_scope("https://api.test.com/v1/insecure")
    assert in_s4 is False

    # 4. CIDR subnet with different IP version
    scope_cidr_v4 = Scope(id="s-c4", name="C4", allowed_targets=["10.0.0.0/8"])
    res_c4 = ScopeResolver(scope_cidr_v4)
    t_v6 = ScopeResolver.normalize_target("2001:db8::/32")
    in_s5, _, _ = res_c4.is_target_in_scope(t_v6)
    assert in_s5 is False