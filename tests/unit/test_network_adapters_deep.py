"""Network Security Deep Unit Tests."""

import json
import pytest

from sentinel.core.models import ActionRequest
from sentinel.modules.network.adapters import (
    NetworkExposureAdapter,
    SegmentationAnalyzerAdapter,
    FirewallConfigReviewAdapter,
    TrafficAnalysisAdapter,
)


@pytest.mark.asyncio
async def test_network_exposure_adapter():
    adp = NetworkExposureAdapter()
    req = ActionRequest(
        id="act-exp-01",
        task_id="t1",
        agent="network_agent",
        action_type="network.exposure_analysis",
        target_refs=["127.0.0.1"],
        parameters={"ports": [80, 443]},
    )
    res, raw, _ = await adp.run(req)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert "open_ports" in data
    assert "exposure_flags" in data


@pytest.mark.asyncio
async def test_segmentation_analyzer_adapter():
    adp = SegmentationAnalyzerAdapter()
    req = ActionRequest(
        id="act-seg-01",
        task_id="t1",
        agent="network_agent",
        action_type="network.segmentation_check",
        target_refs=["zone-dmz", "127.0.0.1"],
        parameters={"restricted_ports": [22, 3306]},
    )
    res, raw, _ = await adp.run(req)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert "violations" in data
    assert data["source_zone"] == "zone-dmz"


@pytest.mark.asyncio
async def test_firewall_config_review_adapter():
    adp = FirewallConfigReviewAdapter()
    req = ActionRequest(
        id="act-fw-01",
        task_id="t1",
        agent="network_agent",
        action_type="network.firewall_review",
        target_refs=["fw.corp.local"],
        parameters={
            "config_data": {
                "IpPermissions": [
                    {"FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ]
            }
        },
    )
    res, raw, _ = await adp.run(req)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert data["count"] >= 1
    assert data["findings"][0]["rule_id"] in ["FW-001", "FW-002"]


@pytest.mark.asyncio
async def test_traffic_analysis_adapter():
    adp = TrafficAnalysisAdapter()
    req = ActionRequest(
        id="act-pcap-01",
        task_id="t1",
        agent="network_agent",
        action_type="network.pcap_inspect",
        target_refs=["sample.pcap"],
        parameters={"pcap_path": "non_existent_file.pcap"},
    )
    res, raw, _ = await adp.run(req)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert "packet_count" in data
    assert "protocols" in data