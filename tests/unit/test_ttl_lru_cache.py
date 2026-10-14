"""Unit tests for TTLLRUCache."""

import threading
import time

import pytest

from sentinel.core.cache.ttl_lru_cache import TTLLRUCache


def test_ttl_lru_cache_basic_ops():
    cache: TTLLRUCache[str, str] = TTLLRUCache(maxsize=3, ttl_seconds=10.0)
    assert len(cache) == 0

    cache.set("a", "1")
    cache.set("b", "2")
    assert cache.get("a") == "1"
    assert cache.get("b") == "2"
    assert cache.get("c") is None
    assert "a" in cache
    assert "c" not in cache
    assert len(cache) == 2

    assert cache.delete("a") is True
    assert cache.delete("a") is False
    assert cache.get("a") is None


def test_ttl_lru_cache_lru_eviction():
    cache: TTLLRUCache[str, int] = TTLLRUCache(maxsize=3, ttl_seconds=60.0)
    cache.set("k1", 1)
    cache.set("k2", 2)
    cache.set("k3", 3)

    # Access k1 to make it most recently used
    assert cache.get("k1") == 1

    # Inserting k4 should evict k2 (oldest / least recently used)
    cache.set("k4", 4)
    assert cache.get("k2") is None
    assert cache.get("k1") == 1
    assert cache.get("k3") == 3
    assert cache.get("k4") == 4

    stats = cache.stats()
    assert stats["evictions"] == 1
    assert stats["size"] == 3


def test_ttl_lru_cache_expiration():
    cache: TTLLRUCache[str, str] = TTLLRUCache(maxsize=10, ttl_seconds=0.1)
    cache.set("ephemeral", "val")
    assert cache.get("ephemeral") == "val"

    time.sleep(0.15)
    assert cache.get("ephemeral") is None
    stats = cache.stats()
    assert stats["expirations"] >= 1


def test_ttl_lru_cache_invalid_parameters():
    with pytest.raises(ValueError, match="maxsize must be greater than 0"):
        TTLLRUCache(maxsize=0)

    with pytest.raises(ValueError, match="ttl_seconds must be greater than 0"):
        TTLLRUCache(maxsize=10, ttl_seconds=-1)


def test_ttl_lru_cache_concurrent_thread_safety():
    cache: TTLLRUCache[str, int] = TTLLRUCache(maxsize=50, ttl_seconds=5.0)

    def worker(worker_id: int):
        for i in range(100):
            key = f"key_{i % 30}"
            cache.set(key, worker_id * 1000 + i)
            _ = cache.get(key)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stats = cache.stats()
    assert stats["size"] <= 50
    assert stats["hits"] > 0
