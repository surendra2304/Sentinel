"""DNS Intelligence Deep Unit Tests."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel.core.models import ActionRequest
from sentinel.modules.dns.dns_intel import DNSIntelligenceAdapter


@pytest.mark.asyncio
async def test_dns_intelligence_adapter_flow():
    adp = DNSIntelligenceAdapter()
    
    # 1. Forward DNS enum
    req_fwd = ActionRequest(
        id="act-dns-01",
        task_id="t1",
        agent="recon_agent",
        action_type="dns.full_enum",
        target_refs=["localhost"],
    )
    res, raw, _ = await adp.run(req_fwd)
    assert res.success is True
    data = json.loads(raw.decode("utf-8"))
    assert "records" in data
    assert "zone_transfer" in data

    # 2. Reverse DNS lookup
    req_rev = ActionRequest(
        id="act-dns-02",
        task_id="t1",
        agent="recon_agent",
        action_type="dns.reverse_lookup",
        target_refs=["127.0.0.1"],
    )
    res_r, raw_r, _ = await adp.run(req_rev)
    assert res_r.success is True
    data_r = json.loads(raw_r.decode("utf-8"))
    assert data_r["target"] == "127.0.0.1"