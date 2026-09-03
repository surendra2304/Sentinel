"""Sentinel FRIDAY Ecosystem Bridge."""

from __future__ import annotations

from sentinel.core.gateway.models import ActionRequest, PolicyDecision
from sentinel.core.gateway.router import ActionRouter


class FridaySentinelAdapter:
    """FRIDAY submits intents; Sentinel remains the policy authority."""

    def __init__(self, sentinel_router: ActionRouter):
        self.router = sentinel_router

    async def authorize_intent(self, action: ActionRequest) -> PolicyDecision:
        return await self.router.authorize(action)
