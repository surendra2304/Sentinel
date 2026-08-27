"""Append-only, tamper-evident cryptographic audit logger for Sentinel."""

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditEntry(BaseModel):
    """Immutable record of an authorized security event or action."""
    entry_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    event_type: str
    actor: str
    target: str | None = None
    action_type: str
    scope_policy: str
    decision: str  # e.g., ALLOWED, BLOCKED, APPROVED, REJECTED, EXECUTED
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = ""
    current_hash: str = ""
    signature: str = ""


class AuditLogger:
    """Tamper-evident audit logger maintaining a cryptographic SHA-256 hash chain."""

    def __init__(self, log_path: str = "logs/audit.jsonl", signing_key: str = "sentinel-default-audit-key"):
        self.log_path = log_path
        self.signing_key = signing_key.encode("utf-8")
        self._last_hash = self._get_last_hash()

        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)

    def _get_last_hash(self) -> str:
        """Read the last entry's current_hash to maintain the unbroken chain."""
        if not os.path.exists(self.log_path):
            return "GENESIS_BLOCK_000000000000000000000000000000000000000000000000000000"

        last_hash = "GENESIS_BLOCK_000000000000000000000000000000000000000000000000000000"
        try:
            with open(self.log_path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        last_hash = data.get("current_hash", last_hash)
        except Exception:
            pass
        return last_hash

    def _calculate_hash(self, payload: dict[str, Any], prev_hash: str) -> str:
        serialized = json.dumps(payload, sort_keys=True) + prev_hash
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _sign_hash(self, hash_str: str) -> str:
        return hmac.new(self.signing_key, hash_str.encode("utf-8"), hashlib.sha256).hexdigest()

    def log_event(
        self,
        entry_id: str,
        event_type: str,
        actor: str,
        action_type: str,
        scope_policy: str,
        decision: str,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Create, hash, sign, and write an immutable audit log entry."""
        details = details or {}
        raw_payload = {
            "entry_id": entry_id,
            "event_type": event_type,
            "actor": actor,
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
            entry_id=entry_id,
            event_type=event_type,
            actor=actor,
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

        prev_hash = "GENESIS_BLOCK_000000000000000000000000000000000000000000000000000000"
        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                if data.get("previous_hash") != prev_hash:
                    return False

                raw_payload = {
                    "entry_id": data["entry_id"],
                    "event_type": data["event_type"],
                    "actor": data["actor"],
                    "target": data.get("target"),
                    "action_type": data["action_type"],
                    "scope_policy": data["scope_policy"],
                    "decision": data["decision"],
                    "details": data.get("details", {}),
                }

                expected_hash = self._calculate_hash(raw_payload, prev_hash)
                if expected_hash != data.get("current_hash"):
                    return False

                expected_sig = self._sign_hash(expected_hash)
                if expected_sig != data.get("signature"):
                    return False

                prev_hash = expected_hash
        return True
