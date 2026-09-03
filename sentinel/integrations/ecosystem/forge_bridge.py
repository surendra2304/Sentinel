"""Sentinel Forge Ecosystem Bridge."""

from __future__ import annotations

from sentinel.core.gateway.models import ActionRequest, ExecutionResult
from sentinel.core.gateway.router import ActionRouter


class ForgeSentinelAdapter:
    """Forge requests build/test execution; Sentinel validates and executes."""

    def __init__(self, sentinel_router: ActionRouter):
        self.router = sentinel_router

    async def execute_task(self, action: ActionRequest, executor) -> ExecutionResult:
        return await self.router.execute_once(action, executor)
