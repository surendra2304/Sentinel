import json
import socketserver
import threading

import pytest

from sentinel.core.models import (
    ActionRequest,
    Policy,
    Scope,
    TargetSet,
    Task,
)
from sentinel.core.orchestrator.executor import execution_engine
from sentinel.modules.network.adapters import (
    FirewallConfigReviewAdapter,
    HostDiscoveryAdapter,
    NetworkExposureAdapter,
    SegmentationAnalyzerAdapter,
)

# ---------------------------------------------------------------------------
# 1. Local Network Test Socket Mock (Simulating open MySQL & Telnet ports)
# ---------------------------------------------------------------------------

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class MockServiceHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Send fake MySQL greeting
        self.request.sendall(b"5.7.34-MySQL-Community-Server (GPL)\n")


@pytest.fixture(scope="module")
def local_mock_services():
    server = ThreadedTCPServer(("127.0.0.1", 13306), MockServiceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "127.0.0.1:13306"
    server.shutdown()


# ---------------------------------------------------------------------------
# 2. Network Security Adapters Unit Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_adapters_unit(local_mock_services):
    # 1. Host Discovery Adapter
    discovery_adp = HostDiscoveryAdapter()
    req_disc = ActionRequest(
        id="act-disc",
        task_id="task-net-unit",
        agent="network_agent",
        action_type="network.host_discovery",
        target_refs=["127.0.0.1"],
        parameters={"probe_ports": [13306]},
    )
    res_disc, raw_disc, _ = await discovery_adp.run(req_disc)
    assert res_disc.success is True
    data_disc = json.loads(raw_disc.decode("utf-8"))
    assert "127.0.0.1" in data_disc["live_hosts"]

    # 2. Exposure & Service Scan Adapter (with MySQL port 3306 flag)
    exposure_adp = NetworkExposureAdapter()
    req_exp = ActionRequest(
        id="act-exp",
        task_id="task-net-unit",
        agent="network_agent",
        action_type="network.exposure_analysis",
        target_refs=["127.0.0.1"],
        parameters={"ports": [13306, 3306]},
    )
    res_exp, raw_exp, _ = await exposure_adp.run(req_exp)
    assert res_exp.success is True
    data_exp = json.loads(raw_exp.decode("utf-8"))
    assert 13306 in data_exp["open_ports"]

    # 3. Segmentation Analyzer Adapter
    seg_adp = SegmentationAnalyzerAdapter()
    req_seg = ActionRequest(
        id="act-seg",
        task_id="task-net-unit",
        agent="network_agent",
        action_type="network.segmentation_check",
        target_refs=["dmz-subnet", "127.0.0.1"],
        parameters={"restricted_ports": [13306]},
    )
    res_seg, raw_seg, _ = await seg_adp.run(req_seg)
    assert res_seg.success is True
    data_seg = json.loads(raw_seg.decode("utf-8"))
    assert len(data_seg["violations"]) > 0

    # 4. Firewall & Cloud Security Group Review Adapter
    fw_adp = FirewallConfigReviewAdapter()
    aws_sg_sample = {
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
    }
    req_fw = ActionRequest(
        id="act-fw",
        task_id="task-net-unit",
        agent="network_agent",
        action_type="network.firewall_review",
        target_refs=["sg-12345678"],
        parameters={"config_data": aws_sg_sample},
    )
    res_fw, raw_fw, _ = await fw_adp.run(req_fw)
    assert res_fw.success is True
    data_fw = json.loads(raw_fw.decode("utf-8"))
    assert len(data_fw["findings"]) > 0


# ---------------------------------------------------------------------------
# 3. Network Policy Scope Enforcement & Execution Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_policy_scope_enforcement():
    scope = Scope(
        id="scope-net-policy",
        name="Network Scope",
        allowed_targets=["10.0.0.0/24"],
        out_of_scope_declarations=["10.0.0.254"],
    )
    policy = Policy(
        id="pol-net-policy",
        name="Net Policy",
        allowed_module_classes=["network"],
        allowed_action_classes=["network.*"],
    )
    task = Task(
        id="task-net-scope-01",
        objective="Verify network actions are strictly scope-gated",
        target_set=TargetSet(id="ts", name="TS"),
        scope=scope,
        policy=policy,
        correlation_id="corr-net-scope",
    )

    # 1. Blocked: Out of Scope Target
    act_out = ActionRequest(
        id="act-out",
        task_id=task.id,
        agent="network_agent",
        action_type="network.exposure_analysis",
        target_refs=["192.168.1.1"],
    )
    res_out = await execution_engine.execute_action(act_out, task)
    assert res_out.success is False
    assert "BLOCKED_BY_POLICY" in res_out.output_summary

    # 2. Blocked: Explicitly Excluded IP
    act_excl = ActionRequest(
        id="act-excl",
        task_id=task.id,
        agent="network_agent",
        action_type="network.exposure_analysis",
        target_refs=["10.0.0.254"],
    )
    res_excl = await execution_engine.execute_action(act_excl, task)
    assert res_excl.success is False
    assert "BLOCKED_BY_POLICY" in res_excl.output_summary
