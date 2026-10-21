import hmac
import math
import os
import time
from collections import OrderedDict
from threading import Lock
from typing import ClassVar

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Send
from starlette.types import Scope as ASGIScope

from sentinel.config.settings import get_settings


class ReplayProtector:
    """Bounded sliding-window nonce and timestamp validator for replay defense.

    Nonce retention uses a monotonic clock and insertion-ordered storage. Expired
    entries are removed from the head in amortized O(1) time rather than scanning
    every active nonce on every request. Active nonces are never evicted to make
    room for new ones: when the fixed capacity is exhausted, new nonces fail
    closed until existing entries expire.
    """

    def __init__(
        self,
        max_skew_seconds: float = 300.0,
        nonce_ttl_seconds: float = 600.0,
        max_nonces: int = 100_000,
        max_nonce_length: int = 256,
    ) -> None:
        if not math.isfinite(max_skew_seconds) or max_skew_seconds < 0:
            raise ValueError("max_skew_seconds must be finite and non-negative.")
        if not math.isfinite(nonce_ttl_seconds) or nonce_ttl_seconds <= 0:
            raise ValueError("nonce_ttl_seconds must be finite and positive.")
        if isinstance(max_nonces, bool) or not isinstance(max_nonces, int) or max_nonces < 1:
            raise ValueError("max_nonces must be a positive integer.")
        if (
            isinstance(max_nonce_length, bool)
            or not isinstance(max_nonce_length, int)
            or max_nonce_length < 1
        ):
            raise ValueError("max_nonce_length must be a positive integer.")

        self.max_skew = max_skew_seconds
        self.ttl = nonce_ttl_seconds
        self.max_nonces = max_nonces
        self.max_nonce_length = max_nonce_length
        self._seen_nonces: OrderedDict[str, float] = OrderedDict()
        self._lock = Lock()

    def _purge_expired_nonces_locked(self, now_monotonic: float) -> None:
        """Remove expired nonces from the ordered head; caller must hold _lock."""
        while self._seen_nonces:
            _, first_seen = next(iter(self._seen_nonces.items()))
            if now_monotonic - first_seen < self.ttl:
                break
            self._seen_nonces.popitem(last=False)

    def validate_and_record(
        self,
        nonce: str | None,
        timestamp_str: str | None,
    ) -> tuple[bool, str | None]:
        now = time.time()

        # Validate timestamp skew if provided using wall-clock time, which is the
        # time base carried by external request timestamps.
        if timestamp_str:
            try:
                # Support float or ISO timestamp.
                if timestamp_str.replace(".", "", 1).isdigit():
                    req_ts = float(timestamp_str)
                else:
                    from datetime import datetime

                    req_ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()

                skew = abs(now - req_ts)
                if skew > self.max_skew:
                    return False, (
                        f"Request timestamp skewed by {skew:.1f}s "
                        f"(max allowed {self.max_skew}s)."
                    )
            except (TypeError, ValueError, OverflowError):
                return False, "Invalid timestamp format in request header/payload."

        # Preserve optional-nonce behavior, but reject malformed supplied values
        # before they can occupy memory or be reflected to users.
        if nonce:
            normalized_nonce = nonce.strip()
            if not normalized_nonce:
                return False, "Invalid request nonce: nonce must not be blank."
            if len(normalized_nonce) > self.max_nonce_length:
                return False, (
                    f"Invalid request nonce: maximum length is {self.max_nonce_length} characters."
                )
            if any(ord(char) < 0x21 or ord(char) == 0x7F for char in normalized_nonce):
                return False, "Invalid request nonce: control characters and spaces are not allowed."

            now_monotonic = time.monotonic()
            with self._lock:
                self._purge_expired_nonces_locked(now_monotonic)

                if normalized_nonce in self._seen_nonces:
                    return False, "Replay attack detected: request nonce has already been processed."

                if len(self._seen_nonces) >= self.max_nonces:
                    return False, "Replay protection capacity reached; retry after nonce entries expire."

                self._seen_nonces[normalized_nonce] = now_monotonic

        return True, None


class RateLimiter:
    """Bounded in-memory sliding-window limiter keyed by API identity or source IP.

    Stale identity buckets are swept periodically and when the map reaches its
    capacity. Active buckets are not evicted to create slots for new identities;
    new identities are rejected until a bucket expires. The limiter is local to
    this process, so a multi-worker deployment still needs a shared store for a
    deployment-wide quota.
    """

    def __init__(
        self,
        requests_per_window: int = 120,
        window_seconds: float = 60.0,
        requests_per_minute: int | None = None,
        max_identities: int = 10_000,
        cleanup_interval_seconds: float = 30.0,
    ) -> None:
        limit = requests_per_minute if requests_per_minute is not None else requests_per_window
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("Rate limit must be a positive integer.")
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be finite and positive.")
        if isinstance(max_identities, bool) or not isinstance(max_identities, int) or max_identities < 1:
            raise ValueError("max_identities must be a positive integer.")
        if not math.isfinite(cleanup_interval_seconds) or cleanup_interval_seconds <= 0:
            raise ValueError("cleanup_interval_seconds must be finite and positive.")

        self.limit = limit
        self.window = window_seconds
        self.max_identities = max_identities
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self.hits: OrderedDict[str, list[float]] = OrderedDict()
        self._identity_windows: dict[str, float] = {}
        self._last_cleanup = time.monotonic()
        self._last_capacity_sweep = float("-inf")
        self._lock = Lock()

    def _purge_expired_locked(self, now: float) -> None:
        """Remove only identities whose most recent allowed hit has expired."""
        expired: list[str] = []
        for identity, timestamps in self.hits.items():
            identity_window = self._identity_windows.get(identity, self.window)
            if not timestamps or now - timestamps[-1] >= identity_window:
                expired.append(identity)
        for identity in expired:
            self.hits.pop(identity, None)
            self._identity_windows.pop(identity, None)

    def is_allowed(
        self,
        identifier: str,
        max_requests: int | None = None,
        window: float | None = None,
    ) -> bool:
        limit = max_requests if max_requests is not None else self.limit
        win = window if window is not None else self.window
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("max_requests must be a positive integer.")
        if not math.isfinite(win) or win <= 0:
            raise ValueError("window must be finite and positive.")

        now = time.monotonic()
        with self._lock:
            is_new_identity = identifier not in self.hits
            capacity_sweep = (
                is_new_identity
                and len(self.hits) >= self.max_identities
                and now - self._last_capacity_sweep >= self.cleanup_interval_seconds
            )
            periodic_sweep = now - self._last_cleanup >= self.cleanup_interval_seconds
            if capacity_sweep or periodic_sweep:
                self._purge_expired_locked(now)
                self._last_cleanup = now
                if capacity_sweep:
                    self._last_capacity_sweep = now

            timestamps = self.hits.get(identifier)
            if timestamps is None:
                # Never evict active identities under attacker-controlled key
                # churn: fail closed when all buckets are still live.
                if len(self.hits) >= self.max_identities:
                    return False
                timestamps = []
                self.hits[identifier] = timestamps
                self._identity_windows[identifier] = win
            else:
                self.hits.move_to_end(identifier)
                self._identity_windows[identifier] = max(
                    self._identity_windows.get(identifier, win),
                    win,
                )

            window_start = now - win
            timestamps[:] = [timestamp for timestamp in timestamps if timestamp > window_start]
            if len(timestamps) >= limit:
                return False

            timestamps.append(now)
            return True


replay_protector = ReplayProtector()
rate_limiter = RateLimiter(requests_per_window=120, window_seconds=60.0)
friday_rate_limiter = RateLimiter(requests_per_window=100, window_seconds=3600.0)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Verifies X-API-Key header, validates FRIDAY scopes, and applies rate limits."""

    EXEMPT_PATHS: ClassVar[set[str]] = {
        "/",
        "/dashboard",
        "/dashboard/",
        "/health",
        "/ready",
        "/status",
        "/api/v1/status",
        "/metrics",
        "/audit",
        "/api/v1/audit",
        "/sign",
        "/api/v1/sign",
        "/verify",
        "/api/v1/verify",
        "/public-key",
        "/api/v1/public-key",
        "/docs",
        "/openapi.json",
        "/api/v1/docs",
        "/api/v1/openapi.json",
    }

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self.EXEMPT_PATHS or path.startswith("/assets/"):
            return await call_next(request)

        # Deployed APIs must opt into authentication explicitly; Render remains a
        # supported deployment signal for existing installs. Local development can
        # remain credential-free unless this setting is enabled.
        api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization")
        if api_key and api_key.startswith("Bearer "):
            api_key = api_key[7:]

        is_render = os.getenv("RENDER", "").strip().lower() in {"1", "true", "yes"}
        env_auth_req = os.getenv("SENTINEL_API_AUTH_REQUIRED", "").strip().lower() in {"1", "true", "yes"}
        settings = get_settings()
        auth_required = is_render or env_auth_req or settings.api_auth_required
        configured_key = os.getenv("SENTINEL_API_KEY", "").strip()
        if is_render or auth_required:
            if len(configured_key) < 32 or configured_key.lower() in {
                "sentinel_api", "change-me", "changeme", "password", "secret",
            }:
                return JSONResponse(
                    status_code=503,
                    content={"error": "service_auth_unconfigured", "detail": "A unique SENTINEL_API_KEY is required."},
                )
            if not api_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "unauthorized", "detail": "An API key is required."},
                )
            if not hmac.compare_digest(api_key.encode("utf-8"), configured_key.encode("utf-8")):
                return JSONResponse(
                    status_code=403,
                    content={"error": "forbidden", "detail": "The API key is invalid."},
                )

        # Replay Attack Protection for FRIDAY / Sentinel Ingress
        if path.startswith("/api/v1/friday") or path.startswith("/api/v1/sentinel"):
            nonce = request.headers.get("X-Request-Nonce") or request.headers.get("X-Request-ID")
            req_ts = request.headers.get("X-Request-Timestamp")
            valid, replay_err = replay_protector.validate_and_record(nonce, req_ts)
            if not valid:
                if "capacity reached" in (replay_err or "").lower():
                    return JSONResponse(
                        status_code=503,
                        headers={"Retry-After": "1"},
                        content={
                            "error": "replay_protection_overloaded",
                            "detail": "Replay protection is at capacity; retry shortly.",
                        },
                    )
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


class RequestCapacityMiddleware:
    """Bound concurrent ASGI work and reserve a small independent health-check budget."""

    HEALTH_PATHS: ClassVar[frozenset[str]] = frozenset({"/health", "/ready"})

    def __init__(
        self,
        app: ASGIApp,
        max_concurrent_requests: int = 256,
        max_health_requests: int = 16,
    ) -> None:
        if max_concurrent_requests < 1 or max_health_requests < 1:
            raise ValueError("Request concurrency limits must be positive integers.")
        self.app = app
        self.max_concurrent_requests = max_concurrent_requests
        self.max_health_requests = max_health_requests
        self._active_requests = 0
        self._active_health_requests = 0
        self._state_lock = Lock()

    async def __call__(self, scope: ASGIScope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        is_health_request = scope.get("path") in self.HEALTH_PATHS
        with self._state_lock:
            if is_health_request:
                overloaded = self._active_health_requests >= self.max_health_requests
                if not overloaded:
                    self._active_health_requests += 1
            else:
                overloaded = self._active_requests >= self.max_concurrent_requests
                if not overloaded:
                    self._active_requests += 1

        if overloaded:
            response = JSONResponse(
                status_code=503,
                headers={"Retry-After": "1"},
                content={
                    "error": "service_overloaded",
                    "detail": "The request concurrency limit is reached; retry shortly.",
                },
            )
            await response(scope, receive, send)
            return

        try:
            await self.app(scope, receive, send)
        finally:
            with self._state_lock:
                if is_health_request:
                    self._active_health_requests -= 1
                else:
                    self._active_requests -= 1
