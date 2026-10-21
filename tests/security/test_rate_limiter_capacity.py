"""Regression tests for bounded per-identity rate-limit state."""

import time

import pytest

from sentinel.apps.api.middleware import RateLimiter


def test_rate_limiter_identity_store_is_bounded_without_evicting_active_buckets(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    limiter = RateLimiter(
        requests_per_window=2,
        window_seconds=10,
        max_identities=2,
        cleanup_interval_seconds=30,
    )

    assert limiter.is_allowed("client-a")
    clock[0] = 101.0
    assert limiter.is_allowed("client-b")

    clock[0] = 102.0
    assert limiter.is_allowed("client-c") is False
    for i in range(100):
        assert limiter.is_allowed(f"new-client-{i}") is False

    assert len(limiter.hits) == 2
    assert set(limiter.hits) == {"client-a", "client-b"}

    # Existing identities retain their own windows and are not reset by churn.
    assert limiter.is_allowed("client-a")
    assert limiter.is_allowed("client-a") is False
    assert len(limiter.hits) == 2


def test_rate_limiter_capacity_sweep_reclaims_only_expired_identities(monkeypatch):
    clock = [200.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    limiter = RateLimiter(
        requests_per_window=1,
        window_seconds=10,
        max_identities=2,
        cleanup_interval_seconds=30,
    )

    assert limiter.is_allowed("stale-a")
    clock[0] = 201.0
    assert limiter.is_allowed("stale-b")

    # At capacity, one sweep removes expired buckets before admitting new identity.
    clock[0] = 211.0
    assert limiter.is_allowed("fresh-c")
    assert set(limiter.hits) == {"fresh-c"}
    assert len(limiter.hits) == 1


def test_rate_limiter_periodic_cleanup_reclaims_idle_identity_buckets(monkeypatch):
    clock = [300.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    limiter = RateLimiter(
        requests_per_window=3,
        window_seconds=5,
        max_identities=4,
        cleanup_interval_seconds=2,
    )

    assert limiter.is_allowed("idle-client")
    clock[0] = 303.0
    assert limiter.is_allowed("active-client")
    assert set(limiter.hits) == {"idle-client", "active-client"}

    clock[0] = 305.0
    assert limiter.is_allowed("active-client")
    assert set(limiter.hits) == {"active-client"}


def test_rate_limiter_validates_capacity_and_window_parameters():
    with pytest.raises(ValueError, match="max_identities"):
        RateLimiter(max_identities=0)
    with pytest.raises(ValueError, match="max_identities"):
        RateLimiter(max_identities=True)
    with pytest.raises(ValueError, match="window_seconds"):
        RateLimiter(window_seconds=0)
    with pytest.raises(ValueError, match="cleanup_interval_seconds"):
        RateLimiter(cleanup_interval_seconds=float("inf"))

    limiter = RateLimiter()
    with pytest.raises(ValueError, match="max_requests"):
        limiter.is_allowed("client", max_requests=0)
    with pytest.raises(ValueError, match="window"):
        limiter.is_allowed("client", window=float("nan"))


def test_rate_limiter_enforces_request_limits_and_independent_windows():
    clock = [400.0]
    original_monotonic = time.monotonic
    try:
        time.monotonic = lambda: clock[0]
        limiter = RateLimiter(requests_per_window=2, window_seconds=10)

        assert limiter.is_allowed("a")
        assert limiter.is_allowed("a")
        assert limiter.is_allowed("a") is False
        assert limiter.is_allowed("b")
        clock[0] = 411.0
        assert limiter.is_allowed("a")
    finally:
        time.monotonic = original_monotonic
