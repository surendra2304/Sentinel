import time

from sentinel.core.gateway.models import RiskLevel
from sentinel.core.incident.incident_manager import Incident, IncidentManager
from sentinel.core.incident.quarantine_manager import QuarantineManager


def test_incident_lifecycle():
    mgr = IncidentManager()
    inc = mgr.open(Incident(
        id="inc_001",
        tenant_id="tenant_a",
        title="Repeated Auth Failure",
        severity=RiskLevel.HIGH,
        reason="5 failed capability checks",
    ))
    assert inc.contained is False
    assert len(mgr.active("tenant_a")) == 1

    mgr.contain("inc_001")
    assert inc.contained is True
    assert len(mgr.active("tenant_a")) == 0

def test_quarantine_enforcement_and_expiration():
    qm = QuarantineManager()
    qm.put("actor_rogue", "Prompt injection attempt", ttl=0.1)
    assert qm.is_quarantined("actor_rogue") is True

    time.sleep(0.15)
    assert qm.is_quarantined("actor_rogue") is False

def test_quarantine_manual_lift():
    qm = QuarantineManager()
    qm.put("actor_blocked", "Policy violation", ttl=3600.0)
    assert qm.is_quarantined("actor_blocked") is True

    assert qm.lift("actor_blocked") is True
    assert qm.is_quarantined("actor_blocked") is False
