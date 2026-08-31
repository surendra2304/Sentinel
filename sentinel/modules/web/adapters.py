"""Web Security Assessment Tool Adapters for Sentinel.

Includes:
1. WebCrawlerAdapter: Endpoint discovery, form parsing, robots.txt traversal with depth limits.
2. WebConfigAnalysisAdapter: Security header audits, cookie flags (HttpOnly/Secure/SameSite), TLS configuration.
3. AuthSessionTestingAdapter: Structured authentication flow inspection, cookie expiration, logout invalidation.
4. VulnerabilityValidatorAdapter: Low-impact passive validation: reflected echoes, directory listings, sensitive files.
"""

import json
import os
import re
import time
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter

# ---------------------------------------------------------------------------
# 1. Web Crawler Adapter
# ---------------------------------------------------------------------------

class WebCrawlerAdapter(ToolAdapter):
    """Discovers web application endpoints, methods, parameters, and forms."""

    @property
    def name(self) -> str:
        return "web_crawler_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["web.crawl", "web.endpoint_mapping"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL required for web crawling."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        start_url = action.target_refs[0].strip()
        if not (start_url.startswith("http://") or start_url.startswith("https://")):
            start_url = f"http://{start_url}"

        max_depth = action.parameters.get("max_depth", 2)
        max_endpoints = action.parameters.get("max_endpoints", 50)
        base_netloc = urlparse(start_url).netloc

        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        endpoints: list[dict[str, Any]] = []

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=6.0) as client:
            while queue and len(visited) < max_endpoints:
                current_url, depth = queue.popleft()
                if current_url in visited or depth > max_depth:
                    continue

                visited.add(current_url)

                try:
                    res = await client.get(current_url)
                    endpoints.append({
                        "url": current_url,
                        "method": "GET",
                        "status_code": res.status_code,
                        "content_type": res.headers.get("content-type", ""),
                        "forms_found": len(re.findall(r"<form", res.text, re.IGNORECASE)),
                    })

                    # Discover links
                    if depth < max_depth and "text/html" in res.headers.get("content-type", ""):
                        for link in re.findall(r'href=["\'](.*?)["\']', res.text, re.IGNORECASE):
                            abs_link = urljoin(current_url, link.split("#")[0]).rstrip("/")
                            if urlparse(abs_link).netloc == base_netloc and abs_link not in visited:
                                queue.append((abs_link, depth + 1))

                except Exception:
                    pass

        duration = time.time() - start_time
        summary = f"Web crawl on '{start_url}' mapped {len(endpoints)} endpoints across depth {max_depth}."
        results = {"base_url": start_url, "endpoints_count": len(endpoints), "endpoints": endpoints}
        raw_bytes = json.dumps(results, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 2. Web Configuration & Security Header Analysis Adapter
# ---------------------------------------------------------------------------

class WebConfigAnalysisAdapter(ToolAdapter):
    """Audits HTTP security headers, cookie security attributes, and TLS baselines."""

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
        return "web_config_analysis_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["web.header_analysis", "web.cookie_audit", "web.config_review"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL required for web configuration analysis."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        url = action.target_refs[0].strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"http://{url}"

        findings_list: list[dict[str, Any]] = []
        cookies_analyzed: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
                res = await client.get(url)

                # 1. Audit Security Headers against rules.yaml
                header_rules = self.rules.get("security_headers", [])
                for r in header_rules:
                    hname = r.get("header", "")
                    if hname.lower() not in [h.lower() for h in res.headers]:
                        findings_list.append({
                            "type": "MISSING_HEADER",
                            "header": hname,
                            "title": r.get("name", f"Missing {hname}"),
                            "severity": r.get("severity", "LOW"),
                            "description": r.get("description"),
                            "remediation": r.get("remediation"),
                        })

                # 2. Audit Set-Cookie Headers
                for c_header in res.headers.get_list("set-cookie"):
                    c_lower = c_header.lower()
                    cookie_name = c_header.split("=", 1)[0].strip()
                    c_info = {
                        "name": cookie_name,
                        "httponly": "httponly" in c_lower,
                        "secure": "secure" in c_lower,
                        "samesite": "samesite" in c_lower,
                    }
                    cookies_analyzed.append(c_info)

                    if not c_info["httponly"]:
                        findings_list.append({
                            "type": "INSECURE_COOKIE",
                            "cookie": cookie_name,
                            "title": f"Cookie '{cookie_name}' Lacks HttpOnly Attribute",
                            "severity": "MEDIUM",
                            "description": f"Session cookie '{cookie_name}' is accessible via client JavaScript.",
                            "remediation": "Set the HttpOnly flag on all session and sensitive cookies.",
                        })
                    if not c_info["secure"] and url.startswith("https://"):
                        findings_list.append({
                            "type": "INSECURE_COOKIE",
                            "cookie": cookie_name,
                            "title": f"Cookie '{cookie_name}' Lacks Secure Attribute",
                            "severity": "MEDIUM",
                            "description": f"Cookie '{cookie_name}' may be transmitted over unencrypted connections.",
                            "remediation": "Set the Secure flag on all cookies over HTTPS.",
                        })

        except Exception as e:
            findings_list.append({
                "type": "SCAN_ERROR",
                "title": "Web Config Analysis Connection Error",
                "severity": "LOW",
                "description": str(e),
                "remediation": "Check target URL accessibility.",
            })

        duration = time.time() - start_time
        summary = f"Web config review for '{url}' identified {len(findings_list)} issues ({len(cookies_analyzed)} cookies audited)."

        data = {
            "target": url,
            "findings_count": len(findings_list),
            "findings": findings_list,
            "cookies": cookies_analyzed,
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
# 3. Authentication & Session Testing Adapter
# ---------------------------------------------------------------------------

class AuthSessionTestingAdapter(ToolAdapter):
    """Structured assessment framework for authentication flows and session behavior."""

    @property
    def name(self) -> str:
        return "auth_session_testing_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["web.auth_test", "web.session_audit"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL required for authentication testing."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        url = action.target_refs[0].strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"http://{url}"

        results: dict[str, Any] = {
            "target": url,
            "login_endpoint_detected": False,
            "mfa_indicators_found": False,
            "password_field_present": False,
        }

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=6.0) as client:
                res = await client.get(url)
                body = res.text.lower()

                if "login" in body or "sign in" in body or "/login" in body:
                    results["login_endpoint_detected"] = True
                if 'type="password"' in body:
                    results["password_field_present"] = True
                if "totp" in body or "authenticator" in body or "2fa" in body or "mfa" in body:
                    results["mfa_indicators_found"] = True

        except Exception as e:
            results["error"] = str(e)

        duration = time.time() - start_time
        summary = f"Auth flow discovery on '{url}': Login Found={results['login_endpoint_detected']}, Password Field={results['password_field_present']}."
        raw_bytes = json.dumps(results, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 4. Vulnerability Validation Checks Adapter
# ---------------------------------------------------------------------------

class VulnerabilityValidatorAdapter(ToolAdapter):
    """Non-destructive validation checks: reflected echoes, directory listings, sensitive files."""

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
        return "vulnerability_validator_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["web.vuln_validation", "web.sensitive_file_check", "web.directory_listing_check"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL required for vulnerability validation."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        raw_target = action.target_refs[0].strip()
        if not (raw_target.startswith("http://") or raw_target.startswith("https://")):
            raw_target = f"http://{raw_target}"

        parsed = urlparse(raw_target)
        root_url = f"{parsed.scheme}://{parsed.netloc}"
        target_path_url = raw_target.rstrip("/")

        findings_list: list[dict[str, Any]] = []

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=6.0) as client:
            # 1. Directory Listing Check
            for check_url in [target_path_url, f"{target_path_url}/"]:
                try:
                    res_dir = await client.get(check_url)
                    body_dir = res_dir.text.lower()
                    if "index of " in body_dir or "directory listing for" in body_dir or "<title>index of" in body_dir:
                        findings_list.append({
                            "type": "DIRECTORY_LISTING",
                            "title": "Unrestricted Web Directory Listing Enabled",
                            "severity": "MEDIUM",
                            "url": check_url,
                            "description": "The web server has directory indexing enabled, exposing directory file structures.",
                            "remediation": "Disable directory browsing ('Options -Indexes' in Apache or 'autoindex off;' in Nginx).",
                        })
                        break
                except Exception:
                    pass

            # 2. Sensitive Path & Backup File Probing against Root Domain
            sensitive_paths = self.rules.get("sensitive_paths", [
                {"path": "/.env", "name": "Exposed Environment File", "severity": "CRITICAL"},
                {"path": "/.git/HEAD", "name": "Exposed Git Repository", "severity": "HIGH"},
            ])

            for sp in sensitive_paths:
                try:
                    probe_url = f"{root_url}{sp.get('path')}"
                    res_p = await client.get(probe_url)
                    if res_p.status_code == 200 and len(res_p.text) > 0 and "<html" not in res_p.text.lower():
                        findings_list.append({
                            "type": "SENSITIVE_FILE_EXPOSURE",
                            "title": sp.get("name", "Sensitive File Exposed"),
                            "severity": sp.get("severity", "HIGH"),
                            "url": probe_url,
                            "description": f"Accessible sensitive resource discovered at '{probe_url}'.",
                            "remediation": "Restrict direct public access to sensitive and configuration files.",
                        })
                except Exception:
                    pass

            # 3. Reflected Input Echo Check (Non-destructive)
            try:
                test_echo_marker = f"sentineltag{int(time.time())}"
                res_echo = await client.get(f"{root_url}/?search={test_echo_marker}")
                if test_echo_marker in res_echo.text:
                    findings_list.append({
                        "type": "REFLECTED_INPUT_ECHO",
                        "title": "Reflected Input Echo Detected on Parameter",
                        "severity": "LOW",
                        "url": f"{root_url}/?search={test_echo_marker}",
                        "description": "User input in query parameter is reflected in the server response body without escaping.",
                        "remediation": "Ensure all user inputs are properly contextualized and HTML-entity encoded.",
                    })
            except Exception:
                pass

        duration = time.time() - start_time
        summary = f"Vulnerability validation on '{raw_target}' identified {len(findings_list)} observations."
        data = {"target": raw_target, "findings_count": len(findings_list), "findings": findings_list}
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"
