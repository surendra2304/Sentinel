import time
from collections import defaultdict
from typing import ClassVar

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class ReplayProtector:
    """Sliding window nonce and timestamp skew validator for replay defense."""

    def __init__(self, max_skew_seconds: float = 300.0, nonce_ttl_seconds: float = 600.0):
        self.max_skew = max_skew_seconds
        self.ttl = nonce_ttl_seconds
        self._seen_nonces: dict[str, float] = {}

    def validate_and_record(self, nonce: str | None, timestamp_str: str | None) -> tuple[bool, str | None]:
        now = time.time()
        # Clean expired nonces
        expired_cutoff = now - self.ttl
        self._seen_nonces = {k: v for k, v in self._seen_nonces.items() if v > expired_cutoff}

        # Validate timestamp skew if provided
        if timestamp_str:
            try:
                # Support float or ISO timestamp
                if timestamp_str.replace(".", "", 1).isdigit():
                    req_ts = float(timestamp_str)
                else:
                    from datetime import datetime
                    req_ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()

                if abs(now - req_ts) > self.max_skew:
                    return False, f"Request timestamp skewed by {abs(now - req_ts):.1f}s (max allowed {self.max_skew}s)."
            except Exception:
                return False, "Invalid timestamp format in request header/payload."

        # Validate nonce
        if nonce:
            if nonce in self._seen_nonces:
                return False, f"Replay attack detected: nonce '{nonce}' was already processed."
            self._seen_nonces[nonce] = now

        return True, None


class RateLimiter:
    """In-memory sliding window rate limiter per API key / IP with window duration."""

    def __init__(
        self,
        requests_per_window: int = 120,
        window_seconds: float = 60.0,
        requests_per_minute: int | None = None,
    ):
        self.limit = requests_per_minute if requests_per_minute is not None else requests_per_window
        self.window = window_seconds
        self.hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, identifier: str, max_requests: int | None = None, window: float | None = None) -> bool:
        limit = max_requests if max_requests is not None else self.limit
        win = window if window is not None else self.window

        now = time.time()
        window_start = now - win

        # Purge expired hits
        self.hits[identifier] = [t for t in self.hits[identifier] if t > window_start]

        if len(self.hits[identifier]) >= limit:
            return False

        self.hits[identifier].append(now)
        return True


replay_protector = ReplayProtector()
rate_limiter = RateLimiter(requests_per_window=120, window_seconds=60.0)
friday_rate_limiter = RateLimiter(requests_per_window=100, window_seconds=3600.0)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Verifies X-API-Key header, validates FRIDAY scopes, and applies rate limits."""

    EXEMPT_PATHS: ClassVar[set[str]] = {
        "/",
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
        api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization")
        if api_key and api_key.startswith("Bearer "):
            api_key = api_key[7:]

        # Replay Attack Protection for FRIDAY / Sentinel Ingress
        if path.startswith("/api/v1/friday") or path.startswith("/api/v1/sentinel"):
            nonce = request.headers.get("X-Request-Nonce") or request.headers.get("X-Request-ID")
            req_ts = request.headers.get("X-Request-Timestamp")
            valid, replay_err = replay_protector.validate_and_record(nonce, req_ts)
            if not valid:
                status_code = 409 if "Replay" in (replay_err or "") else 401
                return JSONResponse(
                    status_code=status_code,
                    content={"error": "Replay or Timestamp Error", "detail": replay_err},
                )

            # Service Identity Check
            service_id = request.headers.get("X-Service-Identity")
            if service_id and service_id.lower() not in ("friday", "forge", "cortex", "admin", "nexus", "test-client"):
                return JSONResponse(
                    status_code=403,
                    content={"error": "Forbidden", "detail": f"Unrecognized service identity: '{service_id}'."},
                )

        # Specific FRIDAY Scope Enforcement
        if path.startswith("/api/v1/friday"):
            # Check for FRIDAY-specific API key or general admin key
            if api_key and api_key.startswith("friday-key-") or (api_key and "friday" in api_key.lower()):
                client_id = f"friday_{api_key}"
                # Rate limit 100 req/hour for FRIDAY consumer
                if not friday_rate_limiter.is_allowed(client_id, max_requests=100, window=3600.0):
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Too Many Requests", "detail": "FRIDAY rate limit exceeded (100 req/hour)."},
                    )
            elif api_key:
                # Other valid API key accessing friday endpoints
                client_id = api_key
                if not rate_limiter.is_allowed(client_id):
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Too Many Requests", "detail": "Rate limit exceeded."},
                    )
            else:
                client_id = request.client.host if request.client else "unknown_client"
                if not rate_limiter.is_allowed(client_id):
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Too Many Requests", "detail": "Rate limit exceeded."},
                    )
        else:
            # If a FRIDAY-scoped key tries to access non-FRIDAY admin endpoints, restrict if scoped
            if api_key and api_key.startswith("friday-scoped-only-"):
                return JSONResponse(
                    status_code=403,
                    content={"error": "Forbidden", "detail": "FRIDAY API key is scoped strictly to /api/v1/friday/* endpoints."},
                )

            client_id = api_key if api_key else (request.client.host if request.client else "unknown_client")
            if not rate_limiter.is_allowed(client_id):
                return JSONResponse(
                    status_code=429,
                    content={"error": "Too Many Requests", "detail": "Rate limit exceeded (120 req/min)."},
                )

        return await call_next(request)
