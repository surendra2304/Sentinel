"""Resilient connection-pooled asynchronous HTTP mesh client for FRIDAY Universe."""

from __future__ import annotations

import logging
from typing import Any, cast
from urllib.parse import urlparse

import httpx

from sentinel.core.resilience.circuit_breaker import CircuitBreaker, CircuitBreakerOpenError
from sentinel.core.resilience.retry import retry_async

logger = logging.getLogger("sentinel.resilience.mesh_client")


class ResilientMeshClient:
    """Connection-pooled, circuit-broken, and retry-resilient HTTP client for friday_mesh communication."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_connections: int = 50,
        max_keepalive_connections: int = 20,
    ) -> None:
        self.timeout = timeout
        limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=30.0,
        )
        self._client = httpx.AsyncClient(limits=limits, timeout=timeout)
        self._circuit_breakers: dict[str, CircuitBreaker] = {}

    def _get_circuit_breaker(self, url: str) -> CircuitBreaker:
        parsed = urlparse(url)
        host_key = parsed.netloc or "default"
        if host_key not in self._circuit_breakers:
            self._circuit_breakers[host_key] = CircuitBreaker(
                name=f"mesh_{host_key}",
                failure_threshold=5,
                recovery_timeout=20.0,
                expected_exceptions=(httpx.RequestError, httpx.HTTPStatusError),
            )
        return self._circuit_breakers[host_key]

    async def request(
        self,
        method: str,
        url: str,
        fallback: Any = None,
        max_retries: int = 2,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Perform a guarded HTTP request across the mesh with retries and circuit breaking."""
        cb = self._get_circuit_breaker(url)

        async def _execute():
            resp = await self._client.request(method, url, **kwargs)
            resp.raise_for_status()
            if resp.content:
                try:
                    return resp.json()
                except Exception:
                    return {"text": resp.text}
            return {}

        async def _guarded():
            return await retry_async(
                lambda: cb.call(_execute),
                max_retries=max_retries,
                base_delay=0.3,
                max_delay=3.0,
                retry_exceptions=(httpx.RequestError, httpx.HTTPStatusError),
            )

        try:
            res = await _guarded()
            return cast(dict[str, Any], res if isinstance(res, dict) else {"data": res})
        except CircuitBreakerOpenError as exc:
            logger.warning(f"Upstream circuit breaker open for {url}: {exc}")
            if fallback is not None:
                return fallback if isinstance(fallback, dict) else {"data": fallback, "degraded": True}
            return {"error": "circuit_breaker_open", "message": str(exc), "degraded": True, "success": False}
        except Exception as exc:
            logger.error(f"Upstream call to {url} failed: {exc}")
            if fallback is not None:
                return fallback if isinstance(fallback, dict) else {"data": fallback, "degraded": True}
            return {"error": "upstream_unavailable", "message": str(exc), "degraded": True, "success": False}

    def get_breaker_metrics(self) -> list[dict[str, Any]]:
        """Return operational metrics for all tracked upstream circuit breakers."""
        return [cb.get_metrics() for cb in self._circuit_breakers.values()]

    async def aclose(self) -> None:
        """Cleanly close underlying connection pool."""
        await self._client.aclose()
