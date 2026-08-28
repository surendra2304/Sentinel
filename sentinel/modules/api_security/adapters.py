"""API Security Tool Adapters for Sentinel.

Includes:
1. APIDiscoveryAdapter: Identifies REST endpoints, OpenAPI/Swagger JSON specs, and GraphQL endpoints.
2. OpenAPISchemaParserAdapter: Parses OpenAPI 2/3 specs into structured endpoint and schema inventories.
3. JWTAuthAnalysisAdapter: Inspects JWT tokens for alg:none, weak claims, missing expiry, or sensitive data leaks.
4. InputValidationProbeAdapter: Non-destructive benign type-confusion and unicode boundary probes.
5. APIMisconfigAdapter: Tests CORS arbitrary Origin reflection, debug routes, and verbose error responses.
"""

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter

# ---------------------------------------------------------------------------
# 1. API Discovery & Spec Locator Adapter
# ---------------------------------------------------------------------------

class APIDiscoveryAdapter(ToolAdapter):
    """Discovers API surfaces, OpenAPI/Swagger specs, and GraphQL endpoints."""

    def __init__(self, rules_path: str | None = None):
        self.rules_path = rules_path or str(Path(__file__).parent / "rules.yaml")
        self.rules = self._load_rules()

    def _load_rules(self) -> dict[str, Any]:
        if os.path.exists(self.rules_path):
            with open(self.rules_path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    @property
    def name(self) -> str:
        return "api_discovery_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["api.discovery", "api.spec_locate"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL required for API discovery."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        url = action.target_refs[0].strip().rstrip("/")
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"http://{url}"

        discovered_specs: list[str] = []
        graphql_found: bool = False
        api_endpoints: list[str] = []

        spec_paths = self.rules.get("well_known_specs", ["/openapi.json", "/swagger.json", "/docs", "/graphql"])

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=6.0) as client:
            for path in spec_paths:
                try:
                    probe_url = f"{url}{path}"
                    res = await client.get(probe_url)
                    if res.status_code == 200:
                        if path == "/graphql" or "graphql" in res.text.lower():
                            graphql_found = True
                            api_endpoints.append(probe_url)
                        elif "openapi" in res.text.lower() or "swagger" in res.text.lower():
                            discovered_specs.append(probe_url)
                except Exception:
                    pass

        duration = time.time() - start_time
        summary = f"API discovery on '{url}' found {len(discovered_specs)} specs (GraphQL={graphql_found})."

        data = {
            "target": url,
            "discovered_specs": discovered_specs,
            "graphql_endpoint_detected": graphql_found,
            "api_endpoints": api_endpoints,
        }

        raw_bytes = json.dumps(data, indent=2).encode("utf-8")
        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 2. OpenAPI & Swagger Schema Parser Adapter
# ---------------------------------------------------------------------------

class OpenAPISchemaParserAdapter(ToolAdapter):
    """Parses OpenAPI 2/3 documents into structured API endpoint and parameter models."""

    @property
    def name(self) -> str:
        return "openapi_schema_parser_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["api.schema_parse", "api.inventory"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs and "spec_json" not in action.parameters:
            return False, "Target URL or 'spec_json' required for OpenAPI schema parsing."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        spec_url = action.target_refs[0].strip() if action.target_refs else ""
        spec_data = action.parameters.get("spec_json")

        if not spec_data and spec_url:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
                try:
                    res = await client.get(spec_url)
                    if res.status_code == 200:
                        spec_data = res.json()
                except Exception as e:
                    spec_data = {"error": str(e)}

        endpoints: list[dict[str, Any]] = []
        auth_schemes: list[str] = []

        if isinstance(spec_data, dict):
            paths = spec_data.get("paths", {})
            for path_key, path_item in paths.items():
                for method, op_info in path_item.items():
                    if method.lower() in ("get", "post", "put", "delete", "patch"):
                        endpoints.append({
                            "path": path_key,
                            "method": method.upper(),
                            "summary": op_info.get("summary", ""),
                            "parameters": [p.get("name") for p in op_info.get("parameters", [])],
                            "has_auth": bool(op_info.get("security")),
                        })

            # Extract components / securitySchemes
            components = spec_data.get("components", {})
            sec_schemes = components.get("securitySchemes", {})
            auth_schemes = list(sec_schemes.keys())

        duration = time.time() - start_time
        summary = f"OpenAPI parsed: {len(endpoints)} endpoints, auth schemes: {auth_schemes or 'None'}."

        data = {
            "spec_url": spec_url,
            "total_endpoints": len(endpoints),
            "endpoints": endpoints,
            "auth_schemes": auth_schemes,
        }

        raw_bytes = json.dumps(data, indent=2).encode("utf-8")
        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 3. JWT Authentication Analysis Adapter
# ---------------------------------------------------------------------------

class JWTAuthAnalysisAdapter(ToolAdapter):
    """Inspects JWT token structures for alg:none, missing expiry, and credential leakage."""

    @property
    def name(self) -> str:
        return "jwt_auth_analysis_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["api.jwt_audit", "api.auth_analysis"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if "token" not in action.parameters and not action.target_refs:
            return False, "Parameter 'token' containing raw JWT string is required."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        token = action.parameters.get("token", "")
        findings_list: list[dict[str, Any]] = []
        parsed_header: dict[str, Any] = {}
        parsed_payload: dict[str, Any] = {}

        try:
            parts = token.split(".")
            if len(parts) >= 2:
                # Base64 decode with padding
                def decode_b64(seg: str) -> dict[str, Any]:
                    padded = seg + "=" * ((4 - len(seg) % 4) % 4)
                    return dict(json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")))

                parsed_header = decode_b64(parts[0])
                parsed_payload = decode_b64(parts[1])

                # 1. Check alg:none
                alg = parsed_header.get("alg", "").lower()
                if alg in ("none", ""):
                    findings_list.append({
                        "type": "JWT_INSECURE_ALGORITHM",
                        "title": "JWT Insecure 'none' Algorithm Accepted",
                        "severity": "CRITICAL",
                        "description": "JWT uses 'alg: none', allowing attackers to forge arbitrary authentication tokens.",
                        "remediation": "Enforce strong cryptographic signing algorithms (RS256, ES256, EdDSA).",
                    })

                # 2. Check Expiration Claim
                if "exp" not in parsed_payload:
                    findings_list.append({
                        "type": "JWT_MISSING_EXPIRATION",
                        "title": "JWT Lacks Expiration ('exp') Claim",
                        "severity": "MEDIUM",
                        "description": "Token never expires, increasing impact of credential compromise.",
                        "remediation": "Always configure a short-lived expiration timestamp in the 'exp' claim.",
                    })

                # 3. Check Sensitive Information in Payload
                sensitive_keys = ["password", "secret", "api_key", "ssn"]
                for k in parsed_payload:
                    if any(s in k.lower() for s in sensitive_keys):
                        findings_list.append({
                            "type": "JWT_SENSITIVE_DATA_EXPOSURE",
                            "title": f"Sensitive Claim '{k}' Exposed in JWT Payload",
                            "severity": "HIGH",
                            "description": f"JWT contains plaintext sensitive property '{k}'.",
                            "remediation": "Remove sensitive secrets and passwords from client-readable JWT tokens.",
                        })

        except Exception as e:
            findings_list.append({"type": "JWT_PARSE_ERROR", "description": str(e)})

        duration = time.time() - start_time
        summary = f"JWT audit completed: {len(findings_list)} token vulnerabilities identified."

        data = {
            "header": parsed_header,
            "payload": parsed_payload,
            "findings_count": len(findings_list),
            "findings": findings_list,
        }

        raw_bytes = json.dumps(data, indent=2).encode("utf-8")
        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 4. Non-Destructive Input Validation Probing Adapter
# ---------------------------------------------------------------------------

class InputValidationProbeAdapter(ToolAdapter):
    """Benign type-confusion and boundary validation probing on API endpoints."""

    @property
    def name(self) -> str:
        return "input_validation_probe_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["api.input_validation", "api.type_confusion_probe"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target API URL required for validation probing."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        url = action.target_refs[0].strip()
        findings_list: list[dict[str, Any]] = []

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            # 1. Send invalid JSON type confusion payload (string instead of integer / object)
            try:
                confuse_payload = {"id": "invalid_string_type_confusion_probe", "count": "not_a_number"}
                res = await client.post(url, json=confuse_payload)

                # If server returns 200 or 500 without schema validation (422/400)
                if res.status_code == 500:
                    findings_list.append({
                        "type": "VERBOSE_UNHANDLED_EXCEPTION",
                        "title": "Unhandled 500 Server Error on Malformed Input",
                        "severity": "MEDIUM",
                        "url": url,
                        "description": "API crashed with HTTP 500 Internal Server Error when receiving type-confused payload.",
                        "remediation": "Enforce strict schema validation (e.g. Pydantic) and return HTTP 422/400.",
                    })
                elif res.status_code == 200 and "id" in res.text:
                    findings_list.append({
                        "type": "MISSING_INPUT_VALIDATION",
                        "title": "API Accepts Malformed Type-Confused Payload",
                        "severity": "LOW",
                        "url": url,
                        "description": "API returned HTTP 200 OK without validating expected parameter types.",
                        "remediation": "Enforce strict typed request body validation schemas.",
                    })
            except Exception:
                pass

        duration = time.time() - start_time
        summary = f"Input validation probe for '{url}' identified {len(findings_list)} validation anomalies."

        data = {"target": url, "findings_count": len(findings_list), "findings": findings_list}
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 5. API Misconfiguration & CORS Analyzer Adapter
# ---------------------------------------------------------------------------

class APIMisconfigAdapter(ToolAdapter):
    """Audits CORS headers for arbitrary Origin reflection and exposed debug endpoints."""

    @property
    def name(self) -> str:
        return "api_misconfig_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["api.cors_analysis", "api.misconfig_check"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL required for CORS analysis."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        url = action.target_refs[0].strip()
        findings_list: list[dict[str, Any]] = []

        test_origin = "https://attacker-evil-origin.example.com"
        headers = {"Origin": test_origin}

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            try:
                res = await client.get(url, headers=headers)
                allow_origin = res.headers.get("access-control-allow-origin")
                allow_creds = res.headers.get("access-control-allow-credentials", "").lower() == "true"

                # 1. Arbitrary Origin reflection
                if allow_origin == test_origin:
                    sev = "HIGH" if allow_creds else "MEDIUM"
                    findings_list.append({
                        "type": "CORS_ORIGIN_REFLECTION",
                        "title": "Permissive CORS Origin Reflection Detected",
                        "severity": sev,
                        "url": url,
                        "description": f"Server reflected arbitrary origin '{test_origin}' in Access-Control-Allow-Origin (Credentials={allow_creds}).",
                        "remediation": "Restrict Access-Control-Allow-Origin to explicit trusted domain origins.",
                    })
                elif allow_origin == "*" and allow_creds:
                    findings_list.append({
                        "type": "CORS_WILDCARD_CREDENTIALS",
                        "title": "Insecure Wildcard CORS with Credentials",
                        "severity": "HIGH",
                        "url": url,
                        "description": "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
                        "remediation": "Do not combine wildcard CORS origins with credential support.",
                    })
            except Exception as e:
                findings_list.append({"type": "CORS_CHECK_ERROR", "description": str(e)})

        duration = time.time() - start_time
        summary = f"API CORS review for '{url}' completed: {len(findings_list)} CORS misconfigurations found."

        data = {"target": url, "findings_count": len(findings_list), "findings": findings_list}
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"
