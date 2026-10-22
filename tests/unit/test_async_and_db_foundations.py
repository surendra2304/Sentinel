"""Unit tests for async and database foundations (Milestone 1)."""

import pytest

from sentinel.core.security.crypto_gatekeeper import CryptoGatekeeper
from sentinel.storage.database.session import close_async_engine, get_async_engine
from sentinel.storage.persistence.durable_store import SentinelPersistence


@pytest.mark.asyncio
async def test_crypto_gatekeeper_async_offloading_and_cache():
    gatekeeper = CryptoGatekeeper(hmac_key="test-key-async-foundations")
    payload = {"tenant_id": "test_corp", "action": "scan", "target": "10.0.0.1"}

    # Async signing
    signed = await gatekeeper.sign_async(payload, algorithm="HMAC-SHA256")
    assert signed["status"] == "success"
    sig = signed["signature"]

    # Initial async verify (miss in cache)
    valid, err = await gatekeeper.verify_async(payload, sig, algorithm="HMAC-SHA256")
    assert valid is True
    assert err is None

    stats_after_first = gatekeeper.cache_stats()
    assert stats_after_first["misses"] >= 1

    # Second async verify (hit in cache)
    valid2, err2 = await gatekeeper.verify_async(payload, sig, algorithm="HMAC-SHA256")
    assert valid2 is True
    assert err2 is None

    stats_after_second = gatekeeper.cache_stats()
    assert stats_after_second["hits"] >= 1

    # ECDSA async signing & verify
    signed_ecdsa = await gatekeeper.sign_async(payload, algorithm="ECDSA-SHA256")
    assert signed_ecdsa["status"] == "success"
    valid_ecdsa, _ = await gatekeeper.verify_async(payload, signed_ecdsa["signature"], algorithm="ECDSA-SHA256")
    assert valid_ecdsa is True


@pytest.mark.asyncio
async def test_database_engine_and_clean_disposal():
    engine = get_async_engine()
    assert engine is not None
    await close_async_engine()


def test_durable_store_lifecycle(tmp_path):
    db_file = tmp_path / "test_lifecycle.db"
    store = SentinelPersistence(str(db_file))
    assert store.db is not None
    store.close()
