"""Deep unit tests for upgraded Incident and Quarantine engines."""

import time

from sentinel.core.gateway.models import RiskLevel
from sentinel.core.incident.incident_manager import (
    DEFAULT_CONTAINMENT_SLAS,
    Incident,
    IncidentManager,
    IncidentState,
)
from sentinel.core.incident.quarantine_manager import (
    QuarantineCategory,
    QuarantineManager,
)


def test_incident_lifecycle_full_flow() -> None:
    qm = QuarantineManager()
    im = IncidentManager(quarantine_manager=qm)

    inc = im.open(
        Incident(
            id="inc-soc-001",
            tenant_id="tenant-prod",
            title="Unauthorized SSH Brute Force",
            severity=RiskLevel.HIGH,
            reason="Observed 50 failed SSH logins from single IP",
        )
    )

    assert inc.state == IncidentState.OPEN
    assert inc.contained is False

    # 1. Triage
    triaged = im.triage(inc.id, assigned_to="analyst-alice", notes="Initial investigation confirmed attack pattern.")
    assert triaged is not None
    assert triaged.state == IncidentState.TRIAGED
    assert triaged.assigned_to == "analyst-alice"
    assert "triage_notes" in triaged.metadata

    # 2. Contain with automated quarantine
    im.contain(inc.id, auto_quarantine_subject="198.51.100.50", quarantine_ttl=1800.0)
    assert inc.contained is True
    assert inc.state == IncidentState.CONTAINED
    assert inc.time_to_contain is not None
    assert "quarantine:198.51.100.50" in inc.containment_actions_taken

    # Verify subject was quarantined in QuarantineManager
    assert qm.is_quarantined("198.51.100.50") is True

    # 3. Close
    closed = im.close(inc.id, resolution_notes="Host isolated and firewall rule permanently added.")
    assert closed is not None
    assert closed.state == IncidentState.CLOSED
    assert closed.closed_at is not None


def test_incident_sla_breach_detection() -> None:
    im = IncidentManager()

    # Simulate an incident created 2 hours ago with CRITICAL severity (SLA = 15 mins)
    past_time = time.time() - 7200.0
    inc_breached = Incident(
        id="inc-breach-001",
        tenant_id="tenant-prod",
        title="Uncontained Ransomware Encryption",
        severity=RiskLevel.CRITICAL,
        reason="Active file encryption detected on file server",
        created_at=past_time,
    )
    im.open(inc_breached)

    assert inc_breached.sla_seconds == DEFAULT_CONTAINMENT_SLAS[RiskLevel.CRITICAL]
    assert inc_breached.is_sla_breached is True

    breaches = im.list_sla_breaches()
    assert len(breaches) == 1
    assert breaches[0].id == "inc-breach-001"

    # Contain it now; since past_time was 2 hrs ago, it was breached
    im.contain("inc-breach-001")
    assert inc_breached.is_sla_breached is True


def test_incident_mttc_metrics() -> None:
    im = IncidentManager()

    im.open(
        Incident(
            id="inc-m1",
            tenant_id="t1",
            title="Alert 1",
            severity=RiskLevel.LOW,
            reason="r1",
            created_at=time.time() - 100.0,
        )
    )
    im.contain("inc-m1")

    im.open(
        Incident(
            id="inc-m2",
            tenant_id="t1",
            title="Alert 2",
            severity=RiskLevel.LOW,
            reason="r2",
            created_at=time.time() - 200.0,
        )
    )
    im.contain("inc-m2")

    metrics = im.get_mttr_metrics("t1")
    assert metrics["total_contained"] == 2
    assert metrics["mttc_seconds"] > 0


def test_quarantine_categories_and_ttl_extension() -> None:
    qm = QuarantineManager()

    # Quarantine IP
    qm.put(
        subject="203.0.113.99",
        reason="Suspicious Port Scanner",
        ttl=300.0,
        category=QuarantineCategory.IP,
        initiator="sentinel-threat-intel",
    )
    # Quarantine User Token
    qm.put(
        subject="jwt-compromised-token-xyz",
        reason="Exposed on public pastebin",
        ttl=600.0,
        category=QuarantineCategory.TOKEN,
        initiator="sentinel-secret-scanner",
    )

    active_tokens = qm.list_active(QuarantineCategory.TOKEN)
    assert len(active_tokens) == 1
    assert active_tokens[0]["subject"] == "jwt-compromised-token-xyz"
    assert active_tokens[0]["category"] == "token"

    all_active = qm.list_active()
    assert len(all_active) == 2

    # Extend TTL
    extended = qm.extend_ttl("203.0.113.99", additional_ttl_seconds=500.0)
    assert extended is True

    # Lift
    lifted = qm.lift("203.0.113.99")
    assert lifted is True
    assert qm.is_quarantined("203.0.113.99") is False
