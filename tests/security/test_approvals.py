import pytest

from sentinel.core.auth.approvals import ApprovalManager
from sentinel.core.gateway.models import ActionKind, ActionRequest, Actor, ApprovalStatus
from sentinel.storage.persistence.durable_store import SentinelPersistence


def _make_action(act_id="act_1", actor="agent_a", tenant="tenant_1"):
    return ActionRequest(
        id=act_id,
        task_id="task_100",
        actor=Actor(id=actor, tenant_id=tenant),
        kind=ActionKind.EXECUTE,
        action_type="exploit_verify",
        parameters={"port": 443},
        targets=("target.corp",),
        requires_approval=True,
    )

def test_approval_request_decide_consume(tmp_path):
    store = SentinelPersistence(str(tmp_path / "sec.db"))
    mgr = ApprovalManager(store)
    action = _make_action()

    appr = mgr.request(action)
    assert appr.status == ApprovalStatus.PENDING

    appr_decided = mgr.decide(appr.id, approve=True)
    assert appr_decided.status == ApprovalStatus.APPROVED

    consumed = mgr.consume(action)
    assert consumed.status == ApprovalStatus.CONSUMED

def test_approval_double_consumption_prevented(tmp_path):
    store = SentinelPersistence(str(tmp_path / "sec.db"))
    mgr = ApprovalManager(store)
    action = _make_action()

    appr = mgr.request(action)
    mgr.decide(appr.id, approve=True)
    mgr.consume(action)

    with pytest.raises(PermissionError, match="status is consumed"):
        mgr.consume(action)

def test_approval_actor_swap_rejected(tmp_path):
    store = SentinelPersistence(str(tmp_path / "sec.db"))
    mgr = ApprovalManager(store)
    action = _make_action(actor="agent_legit")

    appr = mgr.request(action)
    mgr.decide(appr.id, approve=True)

    hijacked = _make_action(actor="agent_rogue")
    with pytest.raises(PermissionError, match="not bound to this exact action"):
        mgr.consume(hijacked)

def test_approval_mutation_after_approval_rejected(tmp_path):
    store = SentinelPersistence(str(tmp_path / "sec.db"))
    mgr = ApprovalManager(store)
    action = _make_action()

    appr = mgr.request(action)
    mgr.decide(appr.id, approve=True)

    mutated = ActionRequest(
        id=action.id,
        task_id=action.task_id,
        actor=action.actor,
        kind=action.kind,
        action_type=action.action_type,
        parameters={"port": 8080},
        targets=action.targets,
        requires_approval=True,
    )
    with pytest.raises(PermissionError, match="not bound to this exact action"):
        mgr.consume(mutated)
