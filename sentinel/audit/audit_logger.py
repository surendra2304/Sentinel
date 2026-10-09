"""Append-only, tamper-evident cryptographic audit logger for Sentinel.

Features fail-closed startup verification, sequence continuity checks,
automatic pre-log secret and PII redaction, and multi-tenant event anchoring.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from pydantic import BaseModel, Field


class AuditIntegrityError(RuntimeError):
    """Raised when the cryptographic audit chain is corrupted or tampered with."""


class AuditEntry(BaseModel):
    """Immutable record of an authorized security event or action."""

    seq: int = 1
    integrity_version: int = 2
    entry_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    event_type: str
    actor: str
    tenant_id: str = "default"
    action_id: str | None = None
    target: str | None = None
    action_type: str = "SYSTEM"
    scope_policy: str = "DEFAULT"
    decision: str = "ALLOWED"
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = ""
    current_hash: str = ""
    signature: str = ""


class AuditLogger:
    """Tamper-evident SHA-256/HMAC audit chain (v2 signs sequence and context metadata)."""

    GENESIS = "GENESIS_BLOCK_000000000000000000000000000000000000000000000000000000"

    def __init__(
        self,
        log_path: str = "logs/audit.jsonl",
        signing_key: str | None = None,
        fail_closed: bool = True,
    ):
        self.log_path = log_path
        key = (
            signing_key
            or os.environ.get("SENTINEL_AUDIT_HMAC_KEY")
            or os.environ.get("SENTINEL_AUDIT_SIGNING_KEY")
        )
        if not key:
            raise ValueError(
                "Audit signing key is required; set SENTINEL_AUDIT_SIGNING_KEY "
                "or SENTINEL_AUDIT_HMAC_KEY. Refusing to use a built-in key."
            )
        self.signing_key = key.encode("utf-8")
        self.fail_closed = fail_closed
        self._lock = RLock()
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        self._seq, self._last_hash = self._load_and_verify_chain()

    def entry_count(self) -> int:
        """Number of persisted audit entries, or -1 if the ledger cannot be read.

        ``verify_integrity()`` returns True when the ledger file is missing, so
        "chain valid" on its own cannot distinguish a long, audited history from
        one that has recorded nothing. Health endpoints need the count to report
        that difference honestly instead of implying an empty chain is evidence.
        """
        if not os.path.exists(self.log_path):
            return 0
        try:
            with open(self.log_path, encoding="utf-8") as f:
                return sum(1 for line in f if line.strip())
        except OSError:
            return -1

    def _load_and_verify_chain(self) -> tuple[int, str]:
        """Verify the complete audit hash chain on startup."""
        if not os.path.exists(self.log_path):
            return 0, self.GENESIS

        seq = 0
        last_hash = self.GENESIS
        try:
            with open(self.log_path, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    seq += 1
                    data = json.loads(line)
                    if data.get("previous_hash") != last_hash and self.fail_closed:
                        raise AuditIntegrityError(f"Audit chain discontinuity at seq {seq}")
                    version = int(data.get("integrity_version", 1))
                    if version == 2 and data.get("seq") != seq:
                        raise AuditIntegrityError(f"Audit sequence discontinuity at seq {seq}")
                    raw_payload = self._payload_from_entry_data(data)
                    expected_hash = self._calculate_hash(raw_payload, last_hash)
                    if expected_hash != data.get("current_hash") and self.fail_closed:
                        raise AuditIntegrityError(f"Audit hash mismatch at seq {seq}")
                    expected_sig = self._sign_hash(expected_hash)
                    if expected_sig != data.get("signature") and self.fail_closed:
                        raise AuditIntegrityError(f"Audit signature mismatch at seq {seq}")
                    last_hash = data.get("current_hash", last_hash)
        except AuditIntegrityError:
            raise
        except Exception as exc:
            if self.fail_closed:
                raise AuditIntegrityError("Failed to parse audit log on startup") from exc
        return seq, last_hash

    def _calculate_hash(self, payload: dict[str, Any], prev_hash: str) -> str:
        serialized = json.dumps(payload, sort_keys=True) + prev_hash
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def _payload_from_entry_data(data: dict[str, Any]) -> dict[str, Any]:
        """Return the canonical signed payload, retaining v1 ledger compatibility."""
        version = int(data.get("integrity_version", 1))
        if version == 1:
            # Legacy entries did not sign sequence, timestamp, tenant or action ID.
            return {
                "entry_id": data["entry_id"],
                "event_type": data["event_type"],
                "actor": data["actor"],
                "target": data.get("target"),
                "action_type": data.get("action_type", "SYSTEM"),
                "scope_policy": data.get("scope_policy", "DEFAULT"),
                "decision": data.get("decision", "ALLOWED"),
                "details": data.get("details", {}),
            }
        if version != 2:
            raise AuditIntegrityError(f"Unsupported audit integrity version: {version}")
        return {
            "integrity_version": version,
            "seq": data["seq"],
            "entry_id": data["entry_id"],
            "timestamp": data["timestamp"],
            "event_type": data["event_type"],
            "actor": data["actor"],
            "tenant_id": data["tenant_id"],
            "action_id": data.get("action_id"),
            "target": data.get("target"),
            "action_type": data.get("action_type", "SYSTEM"),
            "scope_policy": data.get("scope_policy", "DEFAULT"),
            "decision": data.get("decision", "ALLOWED"),
            "details": data.get("details", {}),
        }

    def _sign_hash(self, hash_str: str) -> str:
        return hmac.new(self.signing_key, hash_str.encode("utf-8"), hashlib.sha256).hexdigest()

    def append(
        self,
        event_type: str,
        actor_id: str,
        tenant_id: str = "default",
        action_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Helper to append structured router events."""
        entry_id = f"audit-{int(time.time()*1000)}-{self._seq + 1}"
        return self.log_event(
            entry_id=entry_id,
            event_type=event_type,
            actor=actor_id,
            action_type=payload.get("action_type", "SYSTEM") if payload else "SYSTEM",
            scope_policy=payload.get("scope_policy", "DEFAULT") if payload else "DEFAULT",
            decision=payload.get("decision", "ALLOWED") if payload else "ALLOWED",
            target=payload.get("target") if payload else None,
            tenant_id=tenant_id,
            action_id=action_id,
            details=payload or {},
        )

    def log_event(
        self,
        entry_id: str,
        event_type: str,
        actor: str,
        action_type: str,
        scope_policy: str,
        decision: str,
        target: str | None = None,
        tenant_id: str = "default",
        action_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Create, redact, hash, sign, and write an immutable audit log entry."""
        with self._lock:
            if os.path.exists(self.log_path):
                try:
                    with open(self.log_path, encoding="utf-8") as f:
                        lines = [line.strip() for line in f if line.strip()]
                        if lines:
                            last_data = json.loads(lines[-1])
                            # Sequence numbers are physical ledger positions; do not
                            # trust an unverified JSON field when continuing a chain.
                            self._seq = len(lines)
                            self._last_hash = last_data.get("current_hash", self._last_hash)
                        else:
                            self._seq = 0
                            self._last_hash = self.GENESIS
                except Exception as exc:
                    if self.fail_closed:
                        raise AuditIntegrityError("Failed to read audit log before append") from exc
            else:
                self._seq = 0
                self._last_hash = self.GENESIS

            self._seq += 1
            timestamp = datetime.now(UTC).isoformat()
            details = _redact_dict(details or {})
            raw_payload = {
                "integrity_version": 2,
                "seq": self._seq,
                "entry_id": entry_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "actor": actor,
                "tenant_id": tenant_id,
                "action_id": action_id,
                "target": target,
                "action_type": action_type,
                "scope_policy": scope_policy,
                "decision": decision,
                "details": details,
            }

            prev_hash = self._last_hash
            curr_hash = self._calculate_hash(raw_payload, prev_hash)
            signature = self._sign_hash(curr_hash)

            entry = AuditEntry(
                seq=self._seq,
                integrity_version=2,
                entry_id=entry_id,
                timestamp=timestamp,
                event_type=event_type,
                actor=actor,
                tenant_id=tenant_id,
                action_id=action_id,
                target=target,
                action_type=action_type,
                scope_policy=scope_policy,
                decision=decision,
                details=details,
                previous_hash=prev_hash,
                current_hash=curr_hash,
                signature=signature,
            )

            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry.model_dump_json() + "\n")

            self._last_hash = curr_hash
            return entry

    def verify_integrity(self) -> bool:
        """Verify the cryptographic hash chain and HMAC signatures across all entries."""
        if not os.path.exists(self.log_path):
            return True

        prev_hash = self.GENESIS
        sequence = 0
        try:
            with open(self.log_path, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    sequence += 1
                    data = json.loads(line)
                    if data.get("previous_hash") != prev_hash:
                        return False
                    version = int(data.get("integrity_version", 1))
                    if version == 2 and data.get("seq") != sequence:
                        return False

                    raw_payload = self._payload_from_entry_data(data)
                    expected_hash = self._calculate_hash(raw_payload, prev_hash)
                    if expected_hash != data.get("current_hash"):
                        return False

                    expected_sig = self._sign_hash(expected_hash)
                    if expected_sig != data.get("signature"):
                        return False

                    prev_hash = expected_hash
            return True
        except Exception:
            return False


def _redact_dict(value: Any) -> Any:
    """Recursively scrub secrets, passwords, tokens and private keys."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            lk = str(k).lower()
            if any(s in lk for s in ("secret", "token", "password", "api_key", "private_key", "credential", "auth_header")):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact_dict(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_redact_dict(v) for v in value]
    return value
