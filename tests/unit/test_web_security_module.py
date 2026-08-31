import json
import socketserver
import threading
from http import server

import pytest

from sentinel.core.models import (
    ActionRequest,
    Policy,
    Scope,
    TargetSet,
    Task,
)
from sentinel.integrations.browsers.playwright_adapter import BrowserAdapter
from sentinel.modules.web.adapters import (
    AuthSessionTestingAdapter,
    VulnerabilityValidatorAdapter,
    WebConfigAnalysisAdapter,
    WebCrawlerAdapter,
)

# ---------------------------------------------------------------------------
# 1. Deliberately Misconfigured Local Web App Mock
# ---------------------------------------------------------------------------

class MisconfiguredWebAppHandler(server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # 1. Exposed Sensitive File (.env)
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=SuperSecretPass123!\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n")

        # 2. Directory Listing
        elif self.path == "/files/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Index of /files/</title></head><body><h1>Directory listing for /files/</h1><hr></body></html>")

        # 3. Main Page with Missing Defensive Headers, Insecure Cookie, and Login Form
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # Insecure cookie (missing HttpOnly and Secure)
            self.send_header("Set-Cookie", "session_token=insecure_token_abc; Path=/")
            # Note: Deliberately omitting HSTS, CSP, X-Frame-Options
            self.end_headers()
            self.wfile.write(b"""
            <html>
                <head><title>Vulnerable Portal</title></head>
                <body>
                    <h1>Welcome to Vulnerable Portal</h1>
                    <form action="/login" method="POST">
                        <input type="text" name="username" />
                        <input type="password" name="password" />
                        <button type="submit">Sign In</button>
                    </form>
                    <a href="/files/">Browse Files</a>
                </body>
            </html>
            """)


@pytest.fixture(scope="module")
def vulnerable_web_target():
    test_server = socketserver.TCPServer(("127.0.0.1", 18898), MisconfiguredWebAppHandler)
    thread = threading.Thread(target=test_server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:18898"
    test_server.shutdown()


# ---------------------------------------------------------------------------
# 2. Web Security Adapters Unit Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_web_adapters_standalone(vulnerable_web_target):
    task = Task(
        id="task-web-unit",
        objective="Audit vulnerable web target",
        target_set=TargetSet(id="ts", name="TS"),
        scope=Scope(id="s", name="S", allowed_targets=["127.0.0.1:18898"]),
        policy=Policy(id="p", name="P", allowed_module_classes=["web"], allowed_action_classes=["web.*"]),
        correlation_id="corr-web-unit",
    )

    # 1. Web Crawler Adapter
    crawler = WebCrawlerAdapter()
    req_crawl = ActionRequest(
        id="act-crawl",
        task_id=task.id,
        agent="web_security_agent",
        action_type="web.crawl",
        target_refs=[vulnerable_web_target],
    )
    res_crawl, raw_crawl, _ = await crawler.run(req_crawl)
    assert res_crawl.success is True
    data_crawl = json.loads(raw_crawl.decode("utf-8"))
    assert data_crawl["endpoints_count"] >= 1

    # 2. Web Configuration & Security Header Audit
    config_adp = WebConfigAnalysisAdapter()
    req_cfg = ActionRequest(
        id="act-cfg",
        task_id=task.id,
        agent="web_security_agent",
        action_type="web.header_analysis",
        target_refs=[vulnerable_web_target],
    )
    res_cfg, raw_cfg, _ = await config_adp.run(req_cfg)
    assert res_cfg.success is True
    data_cfg = json.loads(raw_cfg.decode("utf-8"))
    findings = data_cfg["findings"]
    assert any("HSTS" in f["title"] or "Strict-Transport-Security" in f["title"] for f in findings)
    assert any("CSP" in f["title"] or "Content-Security-Policy" in f["title"] for f in findings)
    assert any("HttpOnly" in f["title"] for f in findings)

    # 3. Auth & Session Testing Adapter
    auth_adp = AuthSessionTestingAdapter()
    req_auth = ActionRequest(
        id="act-auth",
        task_id=task.id,
        agent="web_security_agent",
        action_type="web.auth_test",
        target_refs=[vulnerable_web_target],
    )
    res_auth, raw_auth, _ = await auth_adp.run(req_auth)
    assert res_auth.success is True
    data_auth = json.loads(raw_auth.decode("utf-8"))
    assert data_auth["password_field_present"] is True

    # 4. Vulnerability Validator Adapter (.env and directory listing)
    vuln_adp = VulnerabilityValidatorAdapter()
    req_vuln = ActionRequest(
        id="act-vuln",
        task_id=task.id,
        agent="web_security_agent",
        action_type="web.vuln_validation",
        target_refs=[f"{vulnerable_web_target}/files/"],
    )
    res_vuln, raw_vuln, _ = await vuln_adp.run(req_vuln)
    assert res_vuln.success is True
    data_vuln = json.loads(raw_vuln.decode("utf-8"))
    assert any(f["type"] == "DIRECTORY_LISTING" for f in data_vuln["findings"])
    assert any(f["type"] == "SENSITIVE_FILE_EXPOSURE" for f in data_vuln["findings"])

    # 5. Browser Adapter (DOM and Snapshot capture)
    browser_adp = BrowserAdapter()
    req_brw = ActionRequest(
        id="act-brw",
        task_id=task.id,
        agent="web_security_agent",
        action_type="browser.capture",
        target_refs=[vulnerable_web_target],
    )
    res_brw, raw_brw, _ = await browser_adp.run(req_brw)
    assert res_brw.success is True
    data_brw = json.loads(raw_brw.decode("utf-8"))
    assert "Vulnerable Portal" in data_brw["dom_snapshot"]
