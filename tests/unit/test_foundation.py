from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import EnvironmentType, get_settings
from sentinel.contracts.schemas.core import (
    ActionRequest,
    ScopeDefinition,
    TargetAsset,
)
from sentinel.core.policy.engine import ScopePolicyEngine


def test_settings_load():
    settings = get_settings()
    assert settings.app_name == "Sentinel Cybersecurity Platform"
    assert settings.environment == EnvironmentType.DEVELOPMENT
    assert settings.modules.recon is True
    assert settings.modules.vulnerability is True


def test_audit_logger_hash_chain(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_path=str(log_file), signing_key="test-secret-key")

    entry1 = logger.log_event(
        entry_id="evt-1",
        event_type="POLICY_EVAL",
        actor="system",
        action_type="SCAN",
        scope_policy="scope-1",
        decision="ALLOWED",
        target="192.168.1.1",
    )
    assert entry1.previous_hash == "GENESIS_BLOCK_000000000000000000000000000000000000000000000000000000"

    entry2 = logger.log_event(
        entry_id="evt-2",
        event_type="ACTION_EXEC",
        actor="system",
        action_type="PORT_SCAN",
        scope_policy="scope-1",
        decision="EXECUTED",
        target="192.168.1.1",
    )
    assert entry2.previous_hash == entry1.current_hash
    assert logger.verify_integrity() is True


def test_scope_policy_engine_allowlist():
    scope = ScopeDefinition(
        scope_id="scope-101",
        name="Production Web Perimeter",
        allowed_targets=["10.0.0.0/24", "*.example.com"],
        excluded_targets=["10.0.0.254"],
        max_intensity=5,
        allowed_modules=["recon", "web"],
        offensive_actions_enabled=False,
    )
    engine = ScopePolicyEngine(scope)

    # Allowed target in subnet
    target_in_scope = TargetAsset(
        target_id="t-1", identifier="10.0.0.15", asset_type="IP_ADDRESS", authorized=True
    )
    action1 = ActionRequest(
        action_id="act-1",
        task_id="tsk-1",
        module_name="recon",
        tool_adapter="nmap",
        target=target_in_scope,
        intensity=3,
        is_offensive=False,
    )
    dec1 = engine.evaluate_action(action1)
    assert dec1.allowed is True

    # Excluded target
    target_excluded = TargetAsset(
        target_id="t-2", identifier="10.0.0.254", asset_type="IP_ADDRESS", authorized=True
    )
    action2 = ActionRequest(
        action_id="act-2",
        task_id="tsk-1",
        module_name="recon",
        tool_adapter="nmap",
        target=target_excluded,
        intensity=3,
    )
    dec2 = engine.evaluate_action(action2)
    assert dec2.allowed is False
    assert "explicitly excluded" in dec2.reason

    # Out of scope target
    target_out_of_scope = TargetAsset(
        target_id="t-3", identifier="192.168.1.1", asset_type="IP_ADDRESS", authorized=True
    )
    action3 = ActionRequest(
        action_id="act-3",
        task_id="tsk-1",
        module_name="recon",
        tool_adapter="nmap",
        target=target_out_of_scope,
        intensity=3,
    )
    dec3 = engine.evaluate_action(action3)
    assert dec3.allowed is False
    assert "outside authorized scope" in dec3.reason

    # Unauthorized offensive action
    action4 = ActionRequest(
        action_id="act-4",
        task_id="tsk-1",
        module_name="web",
        tool_adapter="sqlmap",
        target=target_in_scope,
        intensity=3,
        is_offensive=True,
    )
    dec4 = engine.evaluate_action(action4)
    assert dec4.allowed is False
    assert "Offensive capabilities are disabled" in dec4.reason
