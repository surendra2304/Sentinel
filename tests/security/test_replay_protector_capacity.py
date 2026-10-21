"""Capacity, expiry, and ingress tests for replay-protection nonce storage."""

import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi import FastAPI

import sentinel.apps.api.middleware as middleware
from sentinel.apps.api.middleware import APIKeyAuthMiddleware, ReplayProtector


def test_nonce_store_is_bounded_and_fails_closed_without_evicting_active_nonces(monkeypatch):
    wall_clock = 1_800_000_000.0
    monotonic_clock = [100.0]
    monkeypatch.setattr(time, "time", lambda: wall_clock)
    monkeypatch.setattr(time, "monotonic", lambda: monotonic_clock[0])

    protector = ReplayProtector(nonce_ttl_seconds=10, max_nonces=2)
    assert protector.validate_and_record("nonce-a", None) == (True, None)
    assert protector.validate_and_record("nonce-b", None) == (True, None)

    allowed, reason = protector.validate_and_record("nonce-c", None)
    assert allowed is False
    assert "capacity reached" in reason.lower()
    assert len(protector._seen_nonces) == 2
    assert "nonce-a" in protector._seen_nonces
    assert "nonce-b" in protector._seen_nonces

    # Repeated nonces are still identified as replay attempts at full capacity.
    allowed, reason = protector.validate_and_record("nonce-a", None)
    assert allowed is False
    assert "Replay attack detected" in reason

    # Once entries expire, the oldest entries are reclaimed and a new nonce can be stored.
    monotonic_clock[0] = 110.0
    assert protector.validate_and_record("nonce-c", None) == (True, None)
    assert len(protector._seen_nonces) == 1


def test_nonce_store_uses_monotonic_expiry_and_reclaims_only_expired_entries(monkeypatch):
    wall_clock = [1_800_000_000.0]
    monotonic_clock = [50.0]
    monkeypatch.setattr(time, "time", lambda: wall_clock[0])
    monkeypatch.setattr(time, "monotonic", lambda: monotonic_clock[0])

    protector = ReplayProtector(nonce_ttl_seconds=5, max_nonces=2)
    assert protector.validate_and_record("old", None) == (True, None)
    monotonic_clock[0] = 53.0
    assert protector.validate_and_record("newer", None) == (True, None)

    # Wall time can move backward without prolonging or resurrecting nonce entries.
    wall_clock[0] -= 50_000
    monotonic_clock[0] = 55.0
    assert protector.validate_and_record("next", None) == (True, None)
    assert list(protector._seen_nonces.keys()) == ["newer", "next"]


def test_nonce_size_and_constructor_bounds_are_validated():
    with pytest.raises(ValueError, match="max_skew_seconds"):
        ReplayProtector(max_skew_seconds=-1)
    with pytest.raises(ValueError, match="max_skew_seconds"):
        ReplayProtector(max_skew_seconds=float("nan"))
    with pytest.raises(ValueError, match="nonce_ttl_seconds"):
        ReplayProtector(nonce_ttl_seconds=0)
    with pytest.raises(ValueError, match="nonce_ttl_seconds"):
        ReplayProtector(nonce_ttl_seconds=float("inf"))
    with pytest.raises(ValueError, match="max_nonces"):
        ReplayProtector(max_nonces=0)
    with pytest.raises(ValueError, match="max_nonces"):
        ReplayProtector(max_nonces=True)
    with pytest.raises(ValueError, match="max_nonce_length"):
        ReplayProtector(max_nonce_length=0)
    with pytest.raises(ValueError, match="max_nonce_length"):
        ReplayProtector(max_nonce_length=True)

    protector = ReplayProtector(max_nonce_length=8)
    allowed, reason = protector.validate_and_record("nonce-too-long", None)
    assert allowed is False
    assert "maximum length" in reason

    allowed, reason = protector.validate_and_record("x\x00y", None)
    assert allowed is False
    assert "control characters" in reason
    assert len(protector._seen_nonces) == 0


def test_concurrent_duplicate_nonce_is_recorded_at_most_once():
    protector = ReplayProtector(max_nonces=32)

    def submit():
        return protector.validate_and_record("one-shared-nonce", None)[0]

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: submit(), range(32)))

    assert sum(results) == 1
    assert list(protector._seen_nonces.keys()) == ["one-shared-nonce"]


@pytest.mark.asyncio
async def test_nonce_capacity_returns_retryable_503_from_ingress(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    middleware.get_settings.cache_clear()
    monkeypatch.setattr(
        middleware,
        "replay_protector",
        ReplayProtector(max_nonces=1, nonce_ttl_seconds=600),
    )

    app = FastAPI()

    @app.get("/api/v1/friday/probe")
    async def probe():
        return {"status": "ok"}

    app.add_middleware(APIKeyAuthMiddleware)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.get(
                "/api/v1/friday/probe",
                headers={"X-Request-Nonce": "first-nonce"},
            )
            second = await client.get(
                "/api/v1/friday/probe",
                headers={"X-Request-Nonce": "second-nonce"},
            )

        assert first.status_code == 200
        assert second.status_code == 503
        assert second.headers["retry-after"] == "1"
        assert second.json()["error"] == "replay_protection_overloaded"
    finally:
        middleware.get_settings.cache_clear()

def test_malformed_timestamps_and_blank_nonces_are_rejected_without_storage():
    protector = ReplayProtector()

    allowed, reason = protector.validate_and_record("nonce-not-stored", "not-a-timestamp")
    assert allowed is False
    assert "Invalid timestamp format" in reason
    assert len(protector._seen_nonces) == 0

    allowed, reason = protector.validate_and_record("   ", None)
    assert allowed is False
    assert "must not be blank" in reason
    assert len(protector._seen_nonces) == 0


def test_timestamp_without_a_nonce_remains_supported():
    protector = ReplayProtector()
    allowed, reason = protector.validate_and_record(None, str(time.time()))
    assert allowed is True
    assert reason is None
    assert len(protector._seen_nonces) == 0
