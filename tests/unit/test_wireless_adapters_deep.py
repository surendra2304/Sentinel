"""Wireless Security Deep Unit Tests."""

import json

import pytest

from sentinel.core.models import ActionRequest
from sentinel.modules.wireless.adapters import (
    WirelessConfigAssessmentAdapter,
    WirelessInventoryAdapter,
    WirelessTrafficAnalysisAdapter,
)


@pytest.mark.asyncio
async def test_wireless_inventory_and_traffic_analysis_adapters():
    # 1. Inventory adapter
    inv_adp = WirelessInventoryAdapter()
    req_inv = ActionRequest(
        id="act-winv-01",
        task_id="t1",
        agent="device_agent",
        action_type="wireless.inventory",
        target_refs=["00:11:22:33:44:55"],
    )
    res_inv, raw_inv, _ = await inv_adp.run(req_inv)
    assert res_inv.success is True
    data_inv = json.loads(raw_inv.decode("utf-8"))
    assert "networks" in data_inv

    # 2. Config Assessment adapter
    cfg_adp = WirelessConfigAssessmentAdapter()
    req_cfg = ActionRequest(
        id="act-wcfg-01",
        task_id="t1",
        agent="device_agent",
        action_type="wireless.config_audit",
        target_refs=["00:11:22:33:44:55"],
        parameters={"config_data": {"wps_enabled": True, "security_mode": "WEP"}},
    )
    res_cfg, raw_cfg, _ = await cfg_adp.run(req_cfg)
    assert res_cfg.success is True
    data_cfg = json.loads(raw_cfg.decode("utf-8"))
    assert len(data_cfg["findings"]) >= 1
    assert data_cfg["findings"][0]["rule_id"] == "WIFI-001"

    # 3. Traffic Analysis adapter
    traff_adp = WirelessTrafficAnalysisAdapter()
    req_tr = ActionRequest(
        id="act-wtr-01",
        task_id="t1",
        agent="device_agent",
        action_type="wireless.traffic_analysis",
        target_refs=["00:11:22:33:44:55"],
        parameters={"pcap_path": "non_existent.pcap"},
    )
    res_tr, raw_tr, _ = await traff_adp.run(req_tr)
    assert res_tr.success is True
