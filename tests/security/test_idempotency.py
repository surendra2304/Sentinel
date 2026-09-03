from sentinel.core.gateway.models import ActionKind, ActionRequest, Actor, ExecutionResult
from sentinel.storage.persistence.durable_store import SentinelPersistence


def test_idempotency_store_and_replay(tmp_path):
    store = SentinelPersistence(str(tmp_path / "sec.db"))
    action = ActionRequest(
        id="act_1",
        task_id="t1",
        actor=Actor("agent"),
        kind=ActionKind.EXECUTE,
        action_type="scan",
        idempotency_key="key_abc123",
    )
    res = ExecutionResult(action_id="act_1", success=True, stdout="scan output")
    store.put_idempotency("key_abc123", action.fingerprint(), res)

    cached = store.get_idempotency("key_abc123")
    assert cached is not None
    fp, cached_res = cached
    assert fp == action.fingerprint()
    assert cached_res.stdout == "scan output"
    assert cached_res.replayed is True

def test_idempotency_collision_fails_closed(tmp_path):
    store = SentinelPersistence(str(tmp_path / "sec.db"))
    action1 = ActionRequest(
        id="act_1", task_id="t1", actor=Actor("agent"), kind=ActionKind.EXECUTE,
        action_type="scan", parameters={"target": "site1"}, idempotency_key="key_collide",
    )
    store.put_idempotency("key_collide", action1.fingerprint(), ExecutionResult("act_1", True))

    action2 = ActionRequest(
        id="act_2", task_id="t1", actor=Actor("agent"), kind=ActionKind.EXECUTE,
        action_type="scan", parameters={"target": "site2"}, idempotency_key="key_collide",
    )
    cached = store.get_idempotency("key_collide")
    assert cached[0] != action2.fingerprint()
