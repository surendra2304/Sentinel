"""FRIDAY Reference Client for Service-to-Service Automation.

Enables FRIDAY to:
1. Delegate security assessments.
2. Consume real-time SSE progress telemetry.
3. Query structured results with human summaries and blocked actions.
4. Trigger emergency cancellation (Kill Switch).
5. Relay human decisions for pending policy approvals.
"""

from typing import Any, cast

import httpx


class FridayClient:
    """Production reference client for FRIDAY delegating tasks to Sentinel."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", api_key: str = "sentinel-local-dev-key"):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }

    async def delegate_task(self, payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(base_url=self.base_url, headers=self.headers, timeout=30.0) as client:
            res = await client.post("/api/v1/friday/delegate", json=payload)
            res.raise_for_status()
            return cast(dict[str, Any], res.json())

    async def get_delegation_result(self, delegation_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(base_url=self.base_url, headers=self.headers, timeout=30.0) as client:
            res = await client.get(f"/api/v1/friday/delegations/{delegation_id}")
            res.raise_for_status()
            return cast(dict[str, Any], res.json())

    async def cancel_delegation(self, delegation_id: str, reason: str = "FRIDAY Kill Switch") -> dict[str, Any]:
        async with httpx.AsyncClient(base_url=self.base_url, headers=self.headers, timeout=30.0) as client:
            res = await client.post(f"/api/v1/friday/delegations/{delegation_id}/cancel?reason={reason}")
            res.raise_for_status()
            return cast(dict[str, Any], res.json())

    async def decide_approval(self, approval_id: str, approve: bool, operator: str, justification: str) -> dict[str, Any]:
        async with httpx.AsyncClient(base_url=self.base_url, headers=self.headers, timeout=30.0) as client:
            res = await client.post(
                f"/api/v1/approvals/{approval_id}/decide",
                json={"approve": approve, "operator": operator, "justification": justification},
            )
            res.raise_for_status()
            return cast(dict[str, Any], res.json())

