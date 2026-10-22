"""Thread-safe TTL/LRU bounded cache implementation."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class TTLLRUCache(Generic[K, V]):
    """Thread-safe LRU cache with per-item or default time-to-live (TTL) expiration."""

    def __init__(self, maxsize: int = 1000, ttl_seconds: float = 300.0) -> None:
        if maxsize <= 0:
            raise ValueError("maxsize must be greater than 0")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than 0")

        self.maxsize = maxsize
        self.default_ttl = ttl_seconds
        self._lock = threading.RLock()
        self._cache: OrderedDict[K, tuple[V, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._expirations = 0

    def get(self, key: K, default: V | None = None) -> V | None:
        """Retrieve an item from the cache if not expired. Updates LRU order on hit."""
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return default

            value, expiry = self._cache[key]
            if time.time() > expiry:
                del self._cache[key]
                self._expirations += 1
                self._misses += 1
                return default

            self._cache.move_to_end(key)
            self._hits += 1
            return value

    def set(self, key: K, value: V, ttl_seconds: float | None = None) -> None:
        """Store an item in the cache with the given or default TTL. Evicts LRU if capacity exceeded."""
        ttl = ttl_seconds if ttl_seconds is not None and ttl_seconds > 0 else self.default_ttl
        expiry = time.time() + ttl

        with self._lock:
            if key in self._cache:
                self._cache[key] = (value, expiry)
                self._cache.move_to_end(key)
                return

            # Check if purge of expired items frees up space before evicting LRU
            if len(self._cache) >= self.maxsize:
                self._purge_expired_locked()

            # If still full, evict least recently used (first item)
            if len(self._cache) >= self.maxsize:
                self._cache.popitem(last=False)
                self._evictions += 1

            self._cache[key] = (value, expiry)

    def delete(self, key: K) -> bool:
        """Explicitly remove a key from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all entries and reset stats."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            self._expirations = 0

    def stats(self) -> dict[str, Any]:
        """Return cache telemetry and hit/miss statistics."""
        with self._lock:
            self._purge_expired_locked()
            total_lookups = self._hits + self._misses
            hit_ratio = (self._hits / total_lookups) if total_lookups > 0 else 0.0
            return {
                "size": len(self._cache),
                "maxsize": self.maxsize,
                "hits": self._hits,
                "misses": self._misses,
                "hit_ratio": round(hit_ratio, 4),
                "evictions": self._evictions,
                "expirations": self._expirations,
            }

    def _purge_expired_locked(self) -> None:
        """Purge all expired items (caller must hold _lock)."""
        now = time.time()
        expired_keys = [k for k, (_, exp) in self._cache.items() if now > exp]
        for k in expired_keys:
            del self._cache[k]
            self._expirations += 1

    def __len__(self) -> int:
        with self._lock:
            self._purge_expired_locked()
            return len(self._cache)

    def __contains__(self, key: K) -> bool:
        return self.get(key) is not None
