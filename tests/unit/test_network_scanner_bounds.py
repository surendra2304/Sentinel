"""Resource-bound and input-validation regressions for the network scanner."""

import asyncio
import json

import pytest

from sentinel.core.models import ActionRequest, ImpactLevel
from sentinel.integrations.scanners import network_adapter as network_adapter_module
from sentinel.integrations.scanners.network_adapter import NetworkScannerAdapter


def _action(ports: object) -> ActionRequest:
    return ActionRequest(
        id="action-local-port-bounds",
        task_id="task-local-port-bounds",
        agent="recon_agent",
        action_type="network.service_scan",
        target_refs=["127.0.0.1"],
        parameters={"ports": ports, "force_python_fallback": True},
        expected_impact_level=ImpactLevel.LOW,
    )


@pytest.mark.parametrize(
    ("ports", "message"),
    [
        (None, "list of integers"),
        ("1-1000", "list of integers"),
        ([], "at least one port"),
        ([0], "between 1 and 65535"),
        ([65536], "between 1 and 65535"),
        ([True], "between 1 and 65535"),
        ([80.0], "between 1 and 65535"),
        (list(range(1, 258)), "at most 256 ports"),
    ],
)
def test_network_scanner_rejects_invalid_or_excessive_port_lists(ports: object, message: str):
    adapter = NetworkScannerAdapter()

    valid, reason = adapter.validate_params(_action(ports))

    assert not valid
    assert reason is not None and message in reason


def test_network_scanner_accepts_valid_port_boundary_values():
    adapter = NetworkScannerAdapter()

    valid, reason = adapter.validate_params(_action([1, 80, 443, 65535]))

    assert valid
    assert reason is None


@pytest.mark.asyncio
async def test_network_scanner_shares_concurrency_limit_across_local_scans(monkeypatch):
    monkeypatch.setattr(network_adapter_module, "MAX_CONCURRENT_PORT_CHECKS", 3, raising=False)
    adapter = NetworkScannerAdapter()
    adapter.has_nmap = False

    active_connections = 0
    peak_connections = 0
    attempted_ports: list[int] = []

    class FakeReader:
        async def read(self, count: int) -> bytes:
            await asyncio.sleep(0)
            return b"HTTP/1.0 204 No Content\r\n\r\n"

    class FakeWriter:
        def write(self, data: bytes) -> None:
            return None

        async def drain(self) -> None:
            await asyncio.sleep(0)

        def close(self) -> None:
            nonlocal active_connections
            active_connections -= 1

        async def wait_closed(self) -> None:
            await asyncio.sleep(0)

    async def fake_open_connection(host: str, port: int):
        nonlocal active_connections, peak_connections
        assert host == "127.0.0.1"
        active_connections += 1
        peak_connections = max(peak_connections, active_connections)
        attempted_ports.append(port)
        await asyncio.sleep(0.01)
        return FakeReader(), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    ports = list(range(10000, 10016))

    results = await asyncio.gather(
        adapter.run(_action(ports)),
        adapter.run(_action(ports)),
    )

    assert all(result.success for result, _, _ in results)
    assert len(attempted_ports) == len(ports) * 2
    assert peak_connections == 3
    assert active_connections == 0
    for _, raw_output, _ in results:
        assert json.loads(raw_output)["open_ports"]
