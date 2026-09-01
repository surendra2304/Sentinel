import http.server
import socketserver

# ---------------------------------------------------------------------------
# 1. Subprocess Sandbox Tests
# ---------------------------------------------------------------------------
import sys
import threading

import pytest

from sentinel.audit.audit_logger import AuditLogger
from sentinel.core.models import (
    ActionRequest,
    ImpactLevel,
    Policy,
    Scope,
    TargetSet,
    Task,
)
from sentinel.core.orchestrator.adapter import ToolAdapterRegistry
from sentinel.core.orchestrator.executor import ExecutionEngine
from sentinel.core.orchestrator.sandbox import SandboxExecutionError, SubprocessSandbox
from sentinel.core.policy.engine import PolicyEngine
from sentinel.integrations.scanners.dns_adapter import DNSAdapter
from sentinel.integrations.scanners.http_adapter import HTTPObserverAdapter
from sentinel.integrations.scanners.network_adapter import NetworkScannerAdapter
from sentinel.storage.artifacts.storage import LocalFileSystemStorage


@pytest.mark.asyncio
async def test_subprocess_sandbox_timeout_and_output_cap():
    sandbox = SubprocessSandbox(default_timeout_seconds=1.0, max_output_bytes=100)

    # Fast python command
    ret, stdout, stderr = await sandbox.execute_command([sys.executable, "-c", "print('hello from sandbox')"])
    assert ret == 0
    assert b"hello from sandbox" in stdout

    # Timeout enforcement
    with pytest.raises(SandboxExecutionError, match="timed out"):
        await sandbox.execute_command([sys.executable, "-c", "import time; time.sleep(3)"], timeout=0.2)



# ---------------------------------------------------------------------------
# 2. Executor Pipeline Tests (Allow, Deny, Approval, Evidence)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_executor_pipeline_with_adapters(local_http_server, tmp_path):
    storage = LocalFileSystemStorage(base_dir=str(tmp_path / "artifacts"))
    audit = AuditLogger(log_path=str(tmp_path / "audit.jsonl"), signing_key="test-key")
    policy = PolicyEngine(audit_logger=audit)
    registry = ToolAdapterRegistry()

    dns_adp = DNSAdapter()
    http_adp = HTTPObserverAdapter()
    net_adp = NetworkScannerAdapter()

    registry.register(dns_adp)
    registry.register(http_adp)
    registry.register(net_adp)

    executor = ExecutionEngine(registry=registry, policy=policy, storage=storage, audit=audit)

    scope = Scope(
        id="scope-exec",
        name="Exec Scope",
        allowed_targets=["127.0.0.1", "localhost", local_http_server],
        max_intensity=5,
    )
    task_policy = Policy(
        id="pol-exec",
        name="Exec Policy",
        allowed_action_classes=["dns.*", "http.*", "network.*"],
    )
    task = Task(
        id="task-exec-01",
        objective="Execution engine testbed",
        target_set=TargetSet(id="ts", name="TS"),
        scope=scope,
        policy=task_policy,
        correlation_id="corr-exec",
    )

    # 1. Successful HTTP Action
    act_http = ActionRequest(
        id="act-http-01",
        task_id=task.id,
        agent="http_agent",
        action_type="http.observe",
        target_refs=[local_http_server],
        expected_impact_level=ImpactLevel.LOW,
    )
    res_http = await executor.execute_action(act_http, task)
    assert res_http.raw_output_uri is not None
    assert res_http.raw_output_uri.startswith("file://")

    # 2. Blocked Policy Action (Out of scope target)
    act_blocked = ActionRequest(
        id="act-blocked-01",
        task_id=task.id,
        agent="recon_agent",
        action_type="network.service_scan",
        target_refs=["192.168.99.99"],
    )
    res_blocked = await executor.execute_action(act_blocked, task)
    assert res_blocked.success is False
    assert "BLOCKED_BY_POLICY" in res_blocked.output_summary

    # 3. Require Approval Action
    act_approval = ActionRequest(
        id="act-appr-01",
        task_id=task.id,
        agent="exploit_agent",
        action_type="network.service_scan",
        target_refs=["127.0.0.1"],
        requires_approval=True,
    )
    res_approval = await executor.execute_action(act_approval, task)
    assert res_approval.success is False
    assert "REQUIRE_APPROVAL" in res_approval.output_summary


# ---------------------------------------------------------------------------
# 3. Reference Adapters Real Target Tests (Local HTTP Server + Port Scan)
# ---------------------------------------------------------------------------

class MockHttpHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.end_headers()
        self.wfile.write(b"SENTINEL LOCAL TEST HTTP DAEMON")


class QuietTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture(scope="module")
def local_http_server():
    server = QuietTCPServer(("127.0.0.1", 0), MockHttpHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()



@pytest.mark.asyncio
async def test_real_adapters_execution(local_http_server, tmp_path):
    storage = LocalFileSystemStorage(base_dir=str(tmp_path / "artifacts"))
    executor = ExecutionEngine(storage=storage)

    port = int(local_http_server.split(":")[-1])
    scope = Scope(
        id="scope-real",
        name="Real Adapters Scope",
        allowed_targets=["127.0.0.1", local_http_server],
    )
    task_policy = Policy(id="pol-real", name="Real Policy", allowed_action_classes=["*"])
    task = Task(
        id="task-real-01",
        objective="Adapter execution verification",
        target_set=TargetSet(id="ts", name="TS"),
        scope=scope,
        policy=task_policy,
        correlation_id="corr-real",
    )

    # 1. HTTP Observer against local test daemon
    act_http = ActionRequest(
        id="act-http-01",
        task_id=task.id,
        agent="http_agent",
        action_type="http.observe",
        target_refs=[local_http_server],
        expected_impact_level=ImpactLevel.LOW,
    )
    res_http = await executor.execute_action(act_http, task)
    assert res_http.success is True
    assert "status 200" in res_http.output_summary

    # 2. Network Scanner (Python socket fallback against local daemon port)
    act_net = ActionRequest(
        id="act-net-01",
        task_id=task.id,
        agent="network_agent",
        action_type="network.service_scan",
        target_refs=["127.0.0.1"],
        parameters={"ports": [port, 19999], "force_python_fallback": True},
        expected_impact_level=ImpactLevel.LOW,
    )
    res_net = await executor.execute_action(act_net, task)
    assert res_net.success is True
    assert str(port) in res_net.output_summary
