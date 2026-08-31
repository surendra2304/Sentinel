import json

import pytest

from sentinel.core.memory.knowledge_base import (
    IOCType,
    ThreatIndicator,
    knowledge_base_store,
)
from sentinel.core.models import ActionRequest
from sentinel.modules.forensics.adapters import (
    ForensicEventCorrelationAdapter,
    LogArtifactCollectorAdapter,
    SuperTimelineConstructorAdapter,
)
from sentinel.modules.incident_response.adapters import IncidentResponseTriageAdapter


@pytest.fixture(autouse=True)
def seed_ir_threat_intel():
    ioc = ThreatIndicator(
        indicator_type=IOCType.IP,
        value="203.0.113.99",
        context="Known Ransomware Operator Ingress Node",
        source_feed="DFIR_ThreatFeed",
        confidence=1.0,
    )
    knowledge_base_store.add_ioc(ioc)


@pytest.mark.asyncio
async def test_forensic_log_collector_and_timeline():
    # 1. Log Artifact Collector
    log_adp = LogArtifactCollectorAdapter()
    raw_auth_log = """
    Aug 28 04:00:01 web01 sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 4422 ssh2
    Aug 28 04:00:02 web01 sshd[1235]: Failed password for invalid user admin from 192.168.1.50 port 4423 ssh2
    Aug 28 04:00:03 web01 sshd[1236]: Failed password for invalid user admin from 192.168.1.50 port 4424 ssh2
    Aug 28 04:00:05 web01 sshd[1237]: Accepted password for ubuntu from 192.168.1.50 port 4425 ssh2
    """
    req_log = ActionRequest(
        id="act-log-collect",
        task_id="task-dfir-test",
        agent="forensics_agent",
        action_type="forensics.auth_log_parse",
        target_refs=["web01:/var/log/auth.log"],
        parameters={"log_data": raw_auth_log},
    )
    res_log, raw_log_bytes, _ = await log_adp.run(req_log)
    assert res_log.success is True
    data_log = json.loads(raw_log_bytes.decode("utf-8"))
    assert data_log["events_count"] == 4

    # 2. Super Timeline Constructor
    timeline_adp = SuperTimelineConstructorAdapter()
    req_tl = ActionRequest(
        id="act-tl",
        task_id="task-dfir-test",
        agent="forensics_agent",
        action_type="forensics.timeline_build",
        target_refs=["web01"],
        parameters={"events": data_log["events"]},
    )
    res_tl, raw_tl_bytes, _ = await timeline_adp.run(req_tl)
    assert res_tl.success is True
    data_tl = json.loads(raw_tl_bytes.decode("utf-8"))
    assert data_tl["timeline_count"] == 4

    # 3. Forensic Event Correlation (Brute Force Followed by Success)
    corr_adp = ForensicEventCorrelationAdapter()
    req_corr = ActionRequest(
        id="act-corr",
        task_id="task-dfir-test",
        agent="forensics_agent",
        action_type="forensics.event_correlate",
        target_refs=["web01"],
        parameters={"events": data_log["events"]},
    )
    res_corr, raw_corr_bytes, _ = await corr_adp.run(req_corr)
    assert res_corr.success is True
    data_corr = json.loads(raw_corr_bytes.decode("utf-8"))
    assert data_corr["findings_count"] == 1
    assert "Brute Force" in data_corr["findings"][0]["title"]
    assert data_corr["findings"][0]["source_ip"] == "192.168.1.50"


@pytest.mark.asyncio
async def test_incident_response_triage_and_containment():
    ir_adp = IncidentResponseTriageAdapter()
    req_ir = ActionRequest(
        id="act-ir-triage",
        task_id="task-dfir-test",
        agent="incident_response_agent",
        action_type="ir.alert_triage",
        target_refs=["203.0.113.99"],
        parameters={
            "alert_data": {
                "alert_id": "ALT-9001",
                "indicator": "203.0.113.99",
                "description": "Suspicious outbound beaconing",
            }
        },
    )

    res_ir, raw_ir_bytes, _ = await ir_adp.run(req_ir)
    assert res_ir.success is True
    data_ir = json.loads(raw_ir_bytes.decode("utf-8"))

    assert data_ir["verdict"] == "confirmed_incident"
    assert data_ir["confidence"] >= 0.9
    assert len(data_ir["recommendations"]) == 1
    rec = data_ir["recommendations"][0]
    assert rec["requires_human_approval"] is True
    assert "firewall" in rec["action_proposal"].lower()
