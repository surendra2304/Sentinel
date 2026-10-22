from sentinel.core.health.readiness import FailClosedHealth


def test_health_readiness_all_ok():
    health = FailClosedHealth()
    rep = health.check(audit_ok=True, persistence_ok=True, signing_key_ok=True, policy_loaded=True)
    assert rep.ok is True

def test_health_readiness_fails_when_audit_corrupted():
    health = FailClosedHealth()
    rep = health.check(audit_ok=False, persistence_ok=True, signing_key_ok=True, policy_loaded=True)
    assert rep.ok is False
    assert rep.checks["audit_integrity"] is False

def test_health_readiness_fails_when_signing_key_missing():
    health = FailClosedHealth()
    rep = health.check(audit_ok=True, persistence_ok=True, signing_key_ok=False, policy_loaded=True)
    assert rep.ok is False
    assert rep.checks["signing_key"] is False
