"""Sentinel Inference Ecosystem Bridge."""

from __future__ import annotations

from sentinel.core.gateway.models import ActionRequest, PolicyDecision
from sentinel.core.gateway.router import ActionRouter


class InferenceSentinelAdapter:
    """Model output is untrusted recommendation; Sentinel is the authority."""

    def __init__(self, sentinel_router: ActionRouter):
        self.router = sentinel_router

    async def evaluate_recommendation(self, action: ActionRequest) -> PolicyDecision:
        return await self.router.authorize(action)
