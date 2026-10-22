"""Unit and integration tests for Authoritative Target Scope Specification."""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api.main import app
from sentinel.core.scope import (
    SOVEREIGN_PRODUCTION_SCOPE,
    ScopeResolver,
    ScopeVerdict,
    seed_sovereign_scope_into_database,
)


def test_sovereign_scope_invariants():
    """Verify core invariants of the authoritative sovereign scope."""
    assert SOVEREIGN_PRODUCTION_SCOPE.id == "scope_friday_universe_production"
    assert SOVEREIGN_PRODUCTION_SCOPE.offensive_actions_enabled is False
    assert SOVEREIGN_PRODUCTION_SCOPE.max_intensity == 5
    assert SOVEREIGN_PRODUCTION_SCOPE.owner == "Surendra (System Architect)"
    assert SOVEREIGN_PRODUCTION_SCOPE.authorization.authorization_type.value == "owned"
    assert "friday-universe.duckdns.org" in SOVEREIGN_PRODUCTION_SCOPE.allowed_targets
    assert "140.245.208.100/32" in SOVEREIGN_PRODUCTION_SCOPE.allowed_targets
    assert "surendra2304/FRIDAY" in SOVEREIGN_PRODUCTION_SCOPE.allowed_targets
    assert "surendra2304/Sentinel" in SOVEREIGN_PRODUCTION_SCOPE.allowed_targets


def test_sovereign_scope_resolver_evaluations():
    """Verify target authorization verdicts under Sovereign Production Scope."""
    resolver = ScopeResolver(SOVEREIGN_PRODUCTION_SCOPE)

    # In-scope public perimeter & ingress
    in_scope, verdict, _ = resolver.is_target_in_scope("friday-universe.duckdns.org")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    # In-scope public IP
    in_scope, verdict, _ = resolver.is_target_in_scope("140.245.208.100")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    # In-scope container mesh
    in_scope, verdict, _ = resolver.is_target_in_scope("http://forge:8000")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    in_scope, verdict, _ = resolver.is_target_in_scope("http://sentinel:8000")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    # In-scope local dev
    in_scope, verdict, _ = resolver.is_target_in_scope("127.0.0.1")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    # In-scope code repositories
    in_scope, verdict, _ = resolver.is_target_in_scope("surendra2304/Sentinel")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    in_scope, verdict, _ = resolver.is_target_in_scope("surendra2304/VyralX")
    assert in_scope is True
    assert verdict == ScopeVerdict.IN_SCOPE

    # Explicitly excluded third-party APIs
    in_scope, verdict, _ = resolver.is_target_in_scope("api.binance.com")
    assert in_scope is False
    assert verdict == ScopeVerdict.EXPLICITLY_EXCLUDED

    # Out of scope target
    in_scope, verdict, _ = resolver.is_target_in_scope("unauthorized-target.attacker.com")
    assert in_scope is False
    assert verdict == ScopeVerdict.OUT_OF_SCOPE


@pytest.mark.asyncio
async def test_seed_sovereign_scope_in_memory():
    """Verify database seeding in in-memory mode returns cleanly."""
    result = await seed_sovereign_scope_into_database()
    assert result is True


@pytest.mark.asyncio
async def test_telemetry_scope_api_endpoints():
    """Verify GET /v1/telemetry/scope and POST /v1/telemetry/verify-target."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Fetch scope definition
        res = await client.get("/v1/telemetry/scope")
        assert res.status_code == 200
        data = res.json()
        assert data["scope"]["id"] == "scope_friday_universe_production"
        assert data["scope"]["offensive_actions_enabled"] is False

        # 2. Verify in-scope target
        res_v1 = await client.post(
            "/v1/telemetry/verify-target",
            json={"target": "friday-universe.duckdns.org"},
        )
        assert res_v1.status_code == 200
        assert res_v1.json()["authorized"] is True
        assert res_v1.json()["verdict"] == "IN_SCOPE"

        # 3. Verify out-of-scope target
        res_v2 = await client.post(
            "/v1/telemetry/verify-target",
            json={"target": "malicious-host.c2.io"},
        )
        assert res_v2.status_code == 200
        assert res_v2.json()["authorized"] is False
        assert res_v2.json()["verdict"] == "OUT_OF_SCOPE"
