import pytest

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import EnvironmentType, get_settings
from sentinel.core.models import (
    ActionRequest,
    ImpactLevel,
    Policy,
    Scope,
    TargetSet,
    Task,
)
from sentinel.core.policy.engine import PolicyEngine


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


@pytest.mark.asyncio
async def test_scope_policy_engine_allowlist(tmp_path):
    audit_file = tmp_path / "test_audit_engine.jsonl"
    audit_logger = AuditLogger(log_path=str(audit_file), signing_key="test-secret-key")
    engine = PolicyEngine(audit_logger=audit_logger)

    scope = Scope(
        id="scope-101",
        name="Production Web Perimeter",
        allowed_targets=["10.0.0.0/24", "*.example.com"],
        out_of_scope_declarations=["10.0.0.254"],
        max_intensity=5,
        offensive_actions_enabled=False,
    )
    policy = Policy(
        id="pol-101",
        name="Standard Policy",
        allowed_action_classes=["recon.*"],
        allowed_module_classes=["recon"],
    )
    task = Task(
        id="task-101",
        objective="Perimeter test",
        target_set=TargetSet(id="ts-1", name="TS"),
        scope=scope,
        policy=policy,
        correlation_id="corr-101",
    )

    # 1. Allowed target in subnet
    action1 = ActionRequest(
        id="act-1",
        task_id=task.id,
        agent="recon_agent",
        module_name="recon",
        action_type="recon.port_scan",
        target_refs=["10.0.0.15"],
        parameters={"intensity": 3},
        expected_impact_level=ImpactLevel.LOW,
    )
    dec1 = await engine.evaluate_action(action1, task)
    assert dec1.allowed is True

    # 2. Excluded target
    action2 = ActionRequest(
        id="act-2",
        task_id=task.id,
        agent="recon_agent",
        action_type="recon.port_scan",
        target_refs=["10.0.0.254"],
        parameters={"intensity": 3},
    )
    dec2 = await engine.evaluate_action(action2, task)
    assert dec2.allowed is False
    assert "out of authorized scope" in dec2.reason

    # 3. Out of scope target
    action3 = ActionRequest(
        id="act-3",
        task_id=task.id,
        agent="recon_agent",
        action_type="recon.port_scan",
        target_refs=["192.168.1.1"],
        parameters={"intensity": 3},
    )
    dec3 = await engine.evaluate_action(action3, task)
    assert dec3.allowed is False
    assert "out of authorized scope" in dec3.reason
