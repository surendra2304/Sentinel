"""Sentinel Quarantine Manager."""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import RLock


@dataclass(frozen=True, slots=True)
class QuarantineRecord:
    subject: str
    reason: str
    expires_at: float


class QuarantineManager:
    def __init__(self):
        self._lock = RLock()
        self._items: dict[str, QuarantineRecord] = {}

    def put(self, subject: str, reason: str, ttl: float = 900.0) -> QuarantineRecord:
        with self._lock:
            rec = QuarantineRecord(subject, reason, time.time() + ttl)
            self._items[subject] = rec
            return rec

    def is_quarantined(self, subject: str) -> bool:
        with self._lock:
            rec = self._items.get(subject)
            if not rec:
                return False
            if rec.expires_at <= time.time():
                self._items.pop(subject, None)
                return False
            return True

    def lift(self, subject: str) -> bool:
        with self._lock:
            return self._items.pop(subject, None) is not None
