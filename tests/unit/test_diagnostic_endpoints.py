"""Unit tests for /health, /ready, /status diagnostic endpoints and correlation headers."""

import httpx
import pytest

from sentinel.apps.api.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "sentinel"
        assert data["evidence_class"] == "process_liveness"
        assert "observed_at" in data
        assert "X-Correlation-ID" in resp.headers


@pytest.mark.asyncio
async def test_ready_endpoint():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "READY"
        assert data["checks"]["crypto_keys"] is True
        assert data["checks"]["database_wal"] is True
        assert "audit_integrity" in data["checks"]


@pytest.mark.asyncio
async def test_status_endpoint():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "operational"
        assert data["service"] == "sentinel"
        assert data["uptime_seconds"] >= 0.0
        assert data["requests_total"] >= 1
        assert "subsystems" in data
        assert data["subsystems"]["cryptographic_gatekeeper"] == "active"


@pytest.mark.asyncio
async def test_correlation_id_propagation():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        custom_cid = "custom-test-correlation-uuid-9999"
        resp = await client.get("/health", headers={"X-Correlation-ID": custom_cid})
        assert resp.status_code == 200
        assert resp.headers.get("X-Correlation-ID") == custom_cid
