"""Regression tests: /health and /ready must not imply a durable security record.

Sentinel's production manifest selects the in-memory storage backend. That made
two endpoints quietly misleading:

* ``audit_logger.verify_integrity()`` returns True when the ledger file does not
  exist, so ``audit_chain_valid: true`` could mean "nothing was ever written".
* ``/ready`` derived ``storage_backend_configured`` from ``bool("memory")`` --
  a non-empty string is always truthy -- and so reported READY while findings,
  evidence and approvals were discarded on every redeploy.

``/api/v1/health/ready`` already failed closed here; these tests pin the same
truthfulness for the two endpoints that did not.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.apps.api import main as api_main
from sentinel.apps.api.main import app
from sentinel.config.settings import EnvironmentType


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_health_reports_memory_backend_as_non_durable(monkeypatch):
    monkeypatch.setattr(api_main.settings, "storage_backend", "memory")
    async with _client() as c:
        body = (await c.get("/health")).json()
    assert body["audit_durable"] is False
    assert body["audit_persistence_evidence"] == "in_memory_backend_lost_on_redeploy"


@pytest.mark.asyncio
async def test_health_reports_durable_backend_honestly(monkeypatch):
    monkeypatch.setattr(api_main.settings, "storage_backend", "postgres")
    async with _client() as c:
        body = (await c.get("/health")).json()
    assert body["audit_durable"] is True
    assert body["audit_persistence_evidence"] == "durable_store_configured"


@pytest.mark.asyncio
async def test_empty_audit_chain_is_flagged_vacuous(monkeypatch, tmp_path):
    monkeypatch.setattr(api_main.audit_logger, "log_path", str(tmp_path / "missing.jsonl"))
    async with _client() as c:
        body = (await c.get("/health")).json()
    # verify_integrity() is still True -- an empty chain is trivially intact.
    assert body["audit_chain_valid"] is True
    # ...which is exactly why it must not be reported as evidence of integrity.
    assert body["audit_chain_entries"] == 0
    assert body["audit_chain_vacuous"] is True


@pytest.mark.asyncio
async def test_populated_audit_chain_is_not_vacuous(monkeypatch, tmp_path):
    ledger = tmp_path / "audit.jsonl"
    ledger.write_text('{"entry_id": 1}\n{"entry_id": 2}\n\n', encoding="utf-8")
    monkeypatch.setattr(api_main.audit_logger, "log_path", str(ledger))
    async with _client() as c:
        body = (await c.get("/health")).json()
    assert body["audit_chain_entries"] == 2
    assert body["audit_chain_vacuous"] is False


@pytest.mark.asyncio
async def test_production_readiness_fails_closed_on_memory_backend(monkeypatch):
    monkeypatch.setattr(api_main.settings, "storage_backend", "memory")
    monkeypatch.setattr(api_main.settings, "environment", EnvironmentType.PRODUCTION)
    async with _client() as c:
        body = (await c.get("/ready")).json()
    # The old check still passes trivially -- that is the bug being pinned.
    assert body["checks"]["storage_backend_configured"] is True
    assert body["checks"]["audit_durable"] is False
    assert body["ready"] is False
    assert body["status"] == "DEGRADED"


@pytest.mark.asyncio
async def test_production_readiness_ready_with_durable_backend(monkeypatch):
    monkeypatch.setattr(api_main.settings, "storage_backend", "postgres")
    monkeypatch.setattr(api_main.settings, "environment", EnvironmentType.PRODUCTION)
    async with _client() as c:
        body = (await c.get("/ready")).json()
    assert body["checks"]["audit_durable"] is True


@pytest.mark.asyncio
async def test_non_production_readiness_keeps_memory_backend_acceptable(monkeypatch):
    """Dev/test must stay usable; only production demands a durable backend."""
    monkeypatch.setattr(api_main.settings, "storage_backend", "memory")
    monkeypatch.setattr(api_main.settings, "environment", EnvironmentType.DEVELOPMENT)
    async with _client() as c:
        body = (await c.get("/ready")).json()
    assert body["checks"]["audit_durable"] is True