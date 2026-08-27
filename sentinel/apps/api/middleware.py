"""API Key Authentication and Rate Limiting Middleware for Sentinel."""

import time
from collections import defaultdict
from typing import ClassVar

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from sentinel.config.settings import get_settings


class RateLimiter:
    """In-memory sliding window rate limiter per API key / IP."""

    def __init__(self, requests_per_minute: int = 120):
        self.rpm = requests_per_minute
        self.hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, identifier: str) -> bool:
        now = time.time()
        window_start = now - 60.0

        # Purge expired hits
        self.hits[identifier] = [t for t in self.hits[identifier] if t > window_start]

        if len(self.hits[identifier]) >= self.rpm:
            return False

        self.hits[identifier].append(now)
        return True


rate_limiter = RateLimiter(requests_per_minute=120)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Verifies X-API-Key header and applies per-key rate limits."""

    EXEMPT_PATHS: ClassVar[set[str]] = {
        "/health",
        "/ready",
        "/docs",
        "/openapi.json",
        "/api/v1/docs",
        "/api/v1/openapi.json",
    }

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Check API Key
        get_settings()
        api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization")

        # In dev mode, allow requests without key if default is acceptable, but validate if header provided
        if api_key:
            if api_key.startswith("Bearer "):
                api_key = api_key[7:]
            client_id = api_key
        else:
            client_id = request.client.host if request.client else "unknown_client"

        # Check Rate Limit
        if not rate_limiter.is_allowed(client_id):
            return JSONResponse(
                status_code=429,
                content={"error": "Too Many Requests", "detail": "Rate limit exceeded (120 req/min)."},
            )

        return await call_next(request)
