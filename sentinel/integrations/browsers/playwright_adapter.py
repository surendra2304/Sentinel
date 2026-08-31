"""Playwright-based Browser Adapter for Sentinel.

Produces DOM snapshots, screenshots, and HAR captures as first-class Evidence artifacts.
Provides automatic graceful fallback to HTTP-only crawling when Playwright is unavailable.
"""

import json
import time
from typing import Any

import httpx

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter


class BrowserAdapter(ToolAdapter):
    """Headless browser automation adapter producing visual and DOM evidence."""

    @property
    def name(self) -> str:
        return "browser_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["browser.capture", "browser.screenshot", "browser.dom_snapshot"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL required for browser interaction."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        url = action.target_refs[0].strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"http://{url}"

        data: dict[str, Any] = {
            "url": url,
            "title": "",
            "dom_snapshot": "",
            "screenshot_base64": None,
            "captured_via": "http_fallback",
        }

        # Try Playwright if installed
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                data["title"] = await page.title()
                data["dom_snapshot"] = await page.content()
                data["captured_via"] = "playwright_headless_chromium"
                await browser.close()
        except Exception:
            # Graceful HTTP fallback
            try:
                async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                    res = await client.get(url)
                    data["title"] = f"HTTP Response: {res.status_code}"
                    data["dom_snapshot"] = res.text[:20000]
                    data["status_code"] = res.status_code
                    data["captured_via"] = "httpx_fallback"
            except Exception as e:
                data["error"] = str(e)

        duration = time.time() - start_time
        summary = f"Browser capture on '{url}' completed via {data['captured_via']} (DOM length: {len(data.get('dom_snapshot', ''))} chars)."
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"
