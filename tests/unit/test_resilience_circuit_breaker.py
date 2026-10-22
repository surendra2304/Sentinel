"""Unit tests for Circuit Breaker, Exponential Backoff Retry, and ResilientMeshClient."""

import asyncio

import httpx
import pytest
import respx

from sentinel.core.resilience.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
)
from sentinel.core.resilience.mesh_client import ResilientMeshClient
from sentinel.core.resilience.retry import calculate_backoff, retry_async, retry_sync


@pytest.mark.asyncio
async def test_circuit_breaker_transitions():
    cb = CircuitBreaker(
        name="test_service",
        failure_threshold=2,
        recovery_timeout=0.2,
        half_open_success_threshold=1,
    )
    assert cb.get_state() == CircuitState.CLOSED

    async def failing_func():
        raise ValueError("simulated network failure")

    # First failure
    with pytest.raises(ValueError):
        await cb.call(failing_func)
    assert cb.get_state() == CircuitState.CLOSED

    # Second failure trips breaker to OPEN
    with pytest.raises(ValueError):
        await cb.call(failing_func)
    assert cb.get_state() == CircuitState.OPEN

    # While OPEN, calls raise CircuitBreakerOpenError immediately
    with pytest.raises(CircuitBreakerOpenError) as exc_info:
        await cb.call(failing_func)
    assert exc_info.value.service_name == "test_service"

    # Wait for recovery timeout -> transitions to HALF_OPEN
    await asyncio.sleep(0.25)
    assert cb.get_state() == CircuitState.HALF_OPEN

    # Successful call in HALF_OPEN recovers breaker to CLOSED
    async def successful_func():
        return "success"

    result = await cb.call(successful_func)
    assert result == "success"
    assert cb.get_state() == CircuitState.CLOSED


def test_circuit_breaker_sync_and_reset():
    cb = CircuitBreaker(name="sync_service", failure_threshold=1, recovery_timeout=10.0)

    def failing():
        raise RuntimeError("sync fail")

    with pytest.raises(RuntimeError):
        cb.call_sync(failing)
    assert cb.get_state() == CircuitState.OPEN

    metrics = cb.get_metrics()
    assert metrics["failure_count"] == 1
    assert metrics["rejected_calls"] == 0

    cb.reset()
    assert cb.get_state() == CircuitState.CLOSED


def test_calculate_backoff_and_retry_sync():
    delay_no_jitter = calculate_backoff(attempt=2, base_delay=0.1, max_delay=10.0, jitter=False)
    assert delay_no_jitter == pytest.approx(0.4)

    delay_jitter = calculate_backoff(attempt=2, base_delay=0.1, max_delay=10.0, jitter=True)
    assert 0.0 <= delay_jitter <= 0.4

    attempts = 0

    def unreliable():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise OSError("transient error")
        return "ok"

    res = retry_sync(unreliable, max_retries=3, base_delay=0.01, jitter=False)
    assert res == "ok"
    assert attempts == 3


@pytest.mark.asyncio
async def test_retry_async_exhaustion():
    async def always_fails():
        raise ConnectionResetError("unreachable")

    with pytest.raises(ConnectionResetError):
        await retry_async(always_fails, max_retries=2, base_delay=0.01)


@pytest.mark.asyncio
@respx.mock
async def test_resilient_mesh_client_success_and_fallback():
    client = ResilientMeshClient(timeout=2.0)
    target_url = "http://friday:10000/api/v1/ping"

    # Mock success
    respx.get(target_url).mock(return_value=httpx.Response(200, json={"status": "pong"}))
    resp = await client.request("GET", target_url)
    assert resp == {"status": "pong"}

    # Mock failure with fallback
    fail_url = "http://friday:10000/api/v1/fail"
    respx.get(fail_url).mock(return_value=httpx.Response(503))
    fallback_val = {"cached_status": "offline_ready"}
    fallback_resp = await client.request("GET", fail_url, fallback=fallback_val, max_retries=1)
    assert fallback_resp == fallback_val

    metrics = client.get_breaker_metrics()
    assert len(metrics) >= 1
    await client.aclose()
