import json
import socketserver
import threading
from http import server

import pytest

from sentinel.core.models import (
    ActionRequest,
    AssetCriticality,
    EnvironmentLabel,
    Policy,
    Scope,
    Target,
    TargetMetadata,
    TargetSet,
    TargetType,
    Task,
    TaskMode,
    TaskStatus,
)
from sentinel.core.orchestrator.orchestrator import orchestrator
from sentinel.intelligence.risk.finding_engine import finding_engine
from sentinel.modules.recon.adapters import (
    OSINTAdapter,
    TechnologyFingerprintAdapter,
)
from sentinel.modules.recon.graph import (
    asset_graph_store,
)
from sentinel.storage.evidence.store import evidence_store

# ---------------------------------------------------------------------------
# 1. Local HTTP Server Mock with Security.txt and Headers
# ---------------------------------------------------------------------------

class MockReconTargetServer(server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Contact: mailto:security@sentinel.local\nExpires: 2027-01-01T00:00:00.000Z\n")
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /internal\n")
        elif self.path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.end_headers()
            self.wfile.write(b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.51 (Unix) OpenSSL/1.1.1")
            self.send_header("X-Powered-By", "PHP/8.1.2")
            self.send_header("Set-Cookie", "PHPSESSID=testsessionid12345; path=/")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>SENTINEL LOCAL RECON TARGET</h1></body></html>")


@pytest.fixture(scope="module")
def recon_test_target():
    test_server = socketserver.TCPServer(("127.0.0.1", 18895), MockReconTargetServer)
    thread = threading.Thread(target=test_server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:18895"
    test_server.shutdown()


# ---------------------------------------------------------------------------
# 2. Recon Adapters Unit Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recon_adapters_standalone(recon_test_target):
    # 1. Tech Fingerprint Adapter
    tech_adp = TechnologyFingerprintAdapter()
    req_tech = ActionRequest(
        id="act-tech",
        task_id="task-recon-test",
        agent="recon_agent",
        action_type="recon.tech_fingerprint",
        target_refs=[recon_test_target],
    )
    res_tech, raw_bytes, _ = await tech_adp.run(req_tech)
    assert res_tech.success is True
    data_tech = json.loads(raw_bytes.decode("utf-8"))
    assert any("Apache" in t for t in data_tech["technologies"])
    assert any("PHP" in t for t in data_tech["technologies"])
    assert data_tech["favicon_hash"] is not None

    # 2. OSINT Adapter
    osint_adp = OSINTAdapter()
    req_osint = ActionRequest(
        id="act-osint",
        task_id="task-recon-test",
        agent="recon_agent",
        action_type="recon.osint",
        target_refs=[recon_test_target],
    )
    res_osint, raw_osint, _ = await osint_adp.run(req_osint)
    assert res_osint.success is True
    data_osint = json.loads(raw_osint.decode("utf-8"))
    assert data_osint["security_txt_found"] is True
    assert "mailto:security@sentinel.local" in data_osint["security_contacts"]
    assert "/admin" in data_osint["robots_txt_entries"]


# ---------------------------------------------------------------------------
# 3. Full Recon Module & Asset Graph End-to-End Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recon_module_and_asset_graph_e2e(recon_test_target):
    target = Target(
        id="t-recon-e2e",
        type=TargetType.URL,
        value=recon_test_target,
        metadata=TargetMetadata(
            criticality=AssetCriticality.HIGH,
            environment=EnvironmentLabel.STAGING,
            owner="infosec",
        ),
    )
    target_set = TargetSet(id="ts-recon-e2e", name="Recon E2E Target Set", targets=[target])

    scope = Scope(
        id="scope-recon-e2e",
        name="Recon Scope",
        allowed_targets=["127.0.0.1", "127.0.0.1:18895", recon_test_target],
        max_intensity=5,
    )

    policy = Policy(
        id="pol-recon-e2e",
        name="Recon Policy",
        allowed_module_classes=["recon", "network", "dns"],
        allowed_action_classes=["*"],
    )

    task = Task(
        id="task-recon-e2e-01",
        objective="Perform full autonomous reconnaissance against local web service",
        target_set=target_set,
        scope=scope,
        policy=policy,
        mode=TaskMode.ASSESSMENT,
        correlation_id="corr-recon-e2e",
    )

    # Run full orchestrator loop across all 3 recon phases
    completed_task = await orchestrator.run_task(task, max_iterations=6)
    assert completed_task.status == TaskStatus.COMPLETE

    # Verify Evidence was recorded in EvidenceStore
    evidences = evidence_store.query_evidence(task_id=task.id)
    assert len(evidences) >= 3

    # Verify Findings were generated
    findings = finding_engine.list_findings(task_id=task.id)
    assert len(findings) > 0

    # Verify AttackSurface Report and AssetGraph
    attack_surface = asset_graph_store.get_task_attack_surface(task.id)
    assert attack_surface.total_nodes > 0
    assert attack_surface.total_edges > 0
    assert len(attack_surface.technologies) > 0
    assert attack_surface.internet_facing_ratio > 0.0
