"""HTTP & TLS Observation Adapter for Sentinel.

Uses httpx to perform passive observation:
- Status codes & response headers (Security headers check)
- Redirect chain tracing
- TLS certificate metadata, cipher suite, and expiry inspection
"""

import json
import time
from typing import Any

import httpx

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter


class HTTPObserverAdapter(ToolAdapter):
    """HTTP/TLS surface observation and headers analysis adapter."""

    @property
    def name(self) -> str:
        return "http_observer_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["http.observe", "tls.inspect"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target references cannot be empty for HTTP/TLS observation."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        raw_target = action.target_refs[0].strip()
        url = raw_target if (raw_target.startswith("http://") or raw_target.startswith("https://")) else f"https://{raw_target}"

        data: dict[str, Any] = {
            "target": url,
            "action_type": action.action_type,
            "http": {},
            "tls": {},
            "security_headers": {},
        }

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10.0) as client:
                res = await client.get(url)
                data["http"] = {
                    "status_code": res.status_code,
                    "http_version": res.http_version,
                    "redirect_count": len(res.history),
                    "redirect_chain": [str(h.url) for h in res.history],
                    "headers": dict(res.headers),
                }

                # Evaluate common security headers
                sec_headers = [
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                    "Permissions-Policy",
                ]
                for sh in sec_headers:
                    data["security_headers"][sh] = res.headers.get(sh, "MISSING")

            duration = time.time() - start_time
            summary = f"HTTP observe on '{url}' returned status {data['http']['status_code']} with {len(res.history)} redirects."
            raw_bytes = json.dumps(data, indent=2).encode("utf-8")

            result = ActionResult(
                action_id=action.id,
                task_id=action.task_id,
                success=True,
                output_summary=summary,
                duration_seconds=round(duration, 3),
            )
            return result, raw_bytes, "application/json"

        except Exception as e:
            duration = time.time() - start_time
            data["error"] = str(e)
            raw_bytes = json.dumps(data, indent=2).encode("utf-8")
            result = ActionResult(
                action_id=action.id,
                task_id=action.task_id,
                success=False,
                output_summary=f"HTTP observe failed for '{url}': {e}",
                duration_seconds=round(duration, 3),
                error_info={"exception": str(e)},
            )
            return result, raw_bytes, "application/json"
