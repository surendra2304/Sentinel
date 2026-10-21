"""Sentinel Quarantine Manager.

Provides thread-safe subject isolation, categorized quarantine enforcement
(IP, domain, user, token, container), TTL tracking, and cryptographic audit trails.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from threading import RLock
from typing import Any

from sentinel.audit.audit_logger import audit_logger


class QuarantineCategory(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    USER = "user"
    TOKEN = "token"
    CONTAINER = "container"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class QuarantineRecord:
    """Immutable record of an isolated entity."""

    subject: str
    reason: str
    expires_at: float
    category: QuarantineCategory = QuarantineCategory.IP
    initiator: str = "sentinel"
    incident_id: str | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def remaining_seconds(self) -> float:
        rem = self.expires_at - time.time()
        return max(0.0, round(rem, 2))

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at


class QuarantineManager:
    """Thread-safe Quarantine Enforcement and Lifecycle Engine."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._items: dict[str, QuarantineRecord] = {}

    def put(
        self,
        subject: str,
        reason: str,
        ttl: float = 900.0,
        category: QuarantineCategory = QuarantineCategory.IP,
        initiator: str = "sentinel-guard",
        incident_id: str | None = None,
    ) -> QuarantineRecord:
        """Place subject in quarantine for the specified duration."""
        with self._lock:
            rec = QuarantineRecord(
                subject=subject,
                reason=reason,
                expires_at=time.time() + ttl,
                category=category,
                initiator=initiator,
                incident_id=incident_id,
            )
            self._items[subject] = rec

            audit_logger.log_event(
                event_type="QUARANTINE_ENFORCED",
                actor=initiator,
                target=subject,
                action_type="enforce_quarantine",
                scope_policy="quarantine_policy",
                decision="QUARANTINED",
                details={
                    "subject": subject,
                    "category": category.value,
                    "ttl_seconds": ttl,
                    "reason": reason,
                    "incident_id": incident_id,
                },
            )
            return rec

    def get(self, subject: str) -> QuarantineRecord | None:
        """Retrieve active quarantine record for a subject, evicting if expired."""
        with self._lock:
            rec = self._items.get(subject)
            if not rec:
                return None
            if rec.is_expired:
                self._items.pop(subject, None)
                return None
            return rec

    def is_quarantined(self, subject: str) -> bool:
        """Check if subject is actively quarantined (auto-evicting if expired)."""
        with self._lock:
            rec = self._items.get(subject)
            if not rec:
                return False
            if rec.is_expired:
                self._items.pop(subject, None)
                return False
            return True

    def lift(self, subject: str, operator: str = "sentinel-operator") -> bool:
        """Lift quarantine on a subject."""
        with self._lock:
            rec = self._items.pop(subject, None)
            if rec is not None:
                audit_logger.log_event(
                    event_type="QUARANTINE_LIFTED",
                    actor=operator,
                    target=subject,
                    action_type="lift_quarantine",
                    scope_policy="quarantine_policy",
                    decision="LIFTED",
                    details={"subject": subject, "original_reason": rec.reason},
                )
                return True
            return False

    def extend_ttl(self, subject: str, additional_ttl_seconds: float, operator: str = "sentinel") -> bool:
        """Extend quarantine on an active subject."""
        with self._lock:
            rec = self._items.get(subject)
            if not rec or rec.is_expired:
                return False
            new_expires = max(rec.expires_at, time.time()) + additional_ttl_seconds
            new_rec = QuarantineRecord(
                subject=rec.subject,
                reason=rec.reason,
                expires_at=new_expires,
                category=rec.category,
                initiator=rec.initiator,
                incident_id=rec.incident_id,
                created_at=rec.created_at,
            )
            self._items[subject] = new_rec

            audit_logger.log_event(
                event_type="QUARANTINE_EXTENDED",
                actor=operator,
                target=subject,
                action_type="extend_quarantine",
                scope_policy="quarantine_policy",
                decision="EXTENDED",
                details={"additional_seconds": additional_ttl_seconds, "new_expires_at": new_expires},
            )
            return True

    def prune_expired(self) -> int:
        """Remove all expired quarantine records and return count."""
        with self._lock:
            now = time.time()
            expired = [k for k, v in self._items.items() if v.expires_at <= now]
            for k in expired:
                del self._items[k]
            return len(expired)

    def list_active(self, category: QuarantineCategory | None = None) -> list[dict[str, Any]]:
        """List currently active quarantined entities."""
        with self._lock:
            self.prune_expired()
            records = list(self._items.values())
            if category:
                records = [r for r in records if r.category == category]
            return [
                {
                    "subject": r.subject,
                    "category": r.category.value,
                    "reason": r.reason,
                    "initiator": r.initiator,
                    "remaining_seconds": r.remaining_seconds,
                    "incident_id": r.incident_id,
                }
                for r in records
            ]
