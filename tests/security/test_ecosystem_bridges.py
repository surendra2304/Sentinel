import pytest

from sentinel.core.gateway.models import ActionKind, ActionRequest, Actor, Decision, PolicyDecision
from sentinel.integrations.ecosystem.friday_bridge import FridaySentinelAdapter
from sentinel.integrations.ecosystem.memora_bridge import MemoraSentinelAdapter


class MockRouter:
    async def authorize(self, action):
        if action.action_type == "forbidden":
            return PolicyDecision(Decision.DENY, "Denied by policy", action.id, action.fingerprint())
        return PolicyDecision(Decision.ALLOW, "Allowed", action.id, action.fingerprint())

@pytest.mark.asyncio
async def test_friday_bridge_intent_authorization():
    router = MockRouter()
    bridge = FridaySentinelAdapter(router)
    action = ActionRequest("a1", "t1", Actor("friday"), ActionKind.EXECUTE, "dns_scan")
    dec = await bridge.authorize_intent(action)
    assert dec.decision == Decision.ALLOW

def test_memora_bridge_redaction():
    bridge = MemoraSentinelAdapter()
    redacted = bridge.format_event_for_memory({
        "event": "login",
        "secret": "AKIAIOSFODNN7EXAMPLE",
        "actor": "operator",
    })
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted["secret"]
    assert "[REDACTED]" in redacted["secret"]
