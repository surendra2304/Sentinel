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
from sentinel.modules.api_security.adapters import (
    APIDiscoveryAdapter,
    APIMisconfigAdapter,
    InputValidationProbeAdapter,
    JWTAuthAnalysisAdapter,
    OpenAPISchemaParserAdapter,
)

# ---------------------------------------------------------------------------
# 1. Mock Vulnerable API Server (FastAPI / OpenAPI / Insecure CORS & Type Errors)
# ---------------------------------------------------------------------------

class MockVulnerableAPIServer(server.SimpleHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        # Reflect Origin
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        # 1. OpenAPI Specification Endpoint
        if self.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test Vulnerable API", "version": "1.0.0"},
                "paths": {
                    "/api/v1/users": {
                        "get": {"summary": "List Users", "parameters": [{"name": "limit"}]},
                        "post": {"summary": "Create User", "security": [{"OAuth2": []}]},
                    }
                },
                "components": {
                    "securitySchemes": {"OAuth2": {"type": "oauth2"}}
                },
            }
            self.wfile.write(json.dumps(spec).encode("utf-8"))

        # 2. CORS Endpoint with Arbitrary Origin Reflection
        elif self.path == "/api/v1/cors-test":
            self.send_response(200)
            origin = self.headers.get("Origin", "")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "message": "cors data"}')

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # 3. Endpoint lacking input validation / crashing with 500
        if self.path == "/api/v1/unvalidated":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
            # If body has string in count, crash with 500
            if "not_a_number" in body:
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Traceback (most recent call last):\nValueError: invalid literal for int()")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "success"}')
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def api_test_server():
    test_server = socketserver.TCPServer(("127.0.0.1", 18899), MockVulnerableAPIServer)
    thread = threading.Thread(target=test_server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:18899"
    test_server.shutdown()


# ---------------------------------------------------------------------------
# 2. API Security Adapters Unit Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_security_adapters_suite(api_test_server):
    task = Task(
        id="task-api-unit",
        objective="Perform API security assessment",
        target_set=TargetSet(id="ts", name="TS"),
        scope=Scope(id="s", name="S", allowed_targets=["127.0.0.1:18899"]),
        policy=Policy(id="p", name="P", allowed_module_classes=["api_security"], allowed_action_classes=["api.*"]),
        correlation_id="corr-api-unit",
    )

    # 1. API Discovery Adapter
    disc_adp = APIDiscoveryAdapter()
    req_disc = ActionRequest(
        id="act-disc",
        task_id=task.id,
        agent="api_security_agent",
        action_type="api.discovery",
        target_refs=[api_test_server],
    )
    res_disc, raw_disc, _ = await disc_adp.run(req_disc)
    assert res_disc.success is True
    data_disc = json.loads(raw_disc.decode("utf-8"))
    assert any("/openapi.json" in s for s in data_disc["discovered_specs"])

    # 2. OpenAPI Schema Parser Adapter
    parser_adp = OpenAPISchemaParserAdapter()
    req_parse = ActionRequest(
        id="act-parse",
        task_id=task.id,
        agent="api_security_agent",
        action_type="api.schema_parse",
        target_refs=[f"{api_test_server}/openapi.json"],
    )
    res_parse, raw_parse, _ = await parser_adp.run(req_parse)
    assert res_parse.success is True
    data_parse = json.loads(raw_parse.decode("utf-8"))
    assert data_parse["total_endpoints"] == 2
    assert "OAuth2" in data_parse["auth_schemes"]

    # 3. JWT Authentication Analysis (alg: none and missing exp)
    jwt_adp = JWTAuthAnalysisAdapter()
    # Fake JWT with {"alg": "none"} and payload {"user": "admin", "password": "supersecretpassword123"}
    # Header: eyJhbGciOiAibm9uZSIgfQ ({"alg": "none"})
    # Payload: eyJ1c2VyIjogImFkbWluIiwgInBhc3N3b3JkIjogInN1cGVyc2VjcmV0In0 ({"user": "admin", "password": "supersecret"})
    fake_weak_jwt = "eyJhbGciOiAibm9uZSIgfQ.eyJ1c2VyIjogImFkbWluIiwgInBhc3N3b3JkIjogInN1cGVyc2VjcmV0In0."
    req_jwt = ActionRequest(
        id="act-jwt",
        task_id=task.id,
        agent="api_security_agent",
        action_type="api.jwt_audit",
        target_refs=["jwt-test"],
        parameters={"token": fake_weak_jwt},
    )
    res_jwt, raw_jwt, _ = await jwt_adp.run(req_jwt)
    assert res_jwt.success is True
    data_jwt = json.loads(raw_jwt.decode("utf-8"))
    jwt_findings = data_jwt["findings"]
    assert any(f["type"] == "JWT_INSECURE_ALGORITHM" for f in jwt_findings)
    assert any(f["type"] == "JWT_MISSING_EXPIRATION" for f in jwt_findings)
    assert any(f["type"] == "JWT_SENSITIVE_DATA_EXPOSURE" for f in jwt_findings)

    # 4. Input Validation Boundary Probing (Handling 500 on type confusion)
    probe_adp = InputValidationProbeAdapter()
    req_probe = ActionRequest(
        id="act-probe",
        task_id=task.id,
        agent="api_security_agent",
        action_type="api.input_validation",
        target_refs=[f"{api_test_server}/api/v1/unvalidated"],
    )
    res_probe, raw_probe, _ = await probe_adp.run(req_probe)
    assert res_probe.success is True
    data_probe = json.loads(raw_probe.decode("utf-8"))
    assert any(f["type"] == "VERBOSE_UNHANDLED_EXCEPTION" for f in data_probe["findings"])

    # 5. CORS Analysis Adapter
    cors_adp = APIMisconfigAdapter()
    req_cors = ActionRequest(
        id="act-cors",
        task_id=task.id,
        agent="api_security_agent",
        action_type="api.cors_analysis",
        target_refs=[f"{api_test_server}/api/v1/cors-test"],
    )
    res_cors, raw_cors, _ = await cors_adp.run(req_cors)
    assert res_cors.success is True
    data_cors = json.loads(raw_cors.decode("utf-8"))
    assert any(f["type"] == "CORS_ORIGIN_REFLECTION" for f in data_cors["findings"])
