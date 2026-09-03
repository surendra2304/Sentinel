"""Sentinel SQLite WAL Durable Security Store."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from sentinel.core.gateway.models import Approval, ApprovalStatus, ExecutionResult


class SentinelPersistence:
    """SQLite durable store for idempotency, approvals, incidents and audit metadata."""

    def __init__(self, db_path: str = "data/sentinel_security.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.lock = threading.RLock()
        self._init()

    def _init(self):
        with self.lock, self.db:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS idempotency(
              key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result_json TEXT NOT NULL, expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approvals(
              id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, actor_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
              action_type TEXT NOT NULL, status TEXT NOT NULL, expires_at REAL NOT NULL, nonce TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents(
              id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
              reason TEXT NOT NULL, created_at REAL NOT NULL, contained INTEGER NOT NULL
            );
            """)

    def put_idempotency(self, key: str, fingerprint: str, result: ExecutionResult, ttl: float = 3600.0) -> None:
        payload = {
            "action_id": result.action_id,
            "success": result.success,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": result.error,
            "replayed": True,
        }
        with self.lock, self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO idempotency VALUES(?,?,?,?)",
                (key, fingerprint, json.dumps(payload), time.time() + ttl),
            )

    def get_idempotency(self, key: str) -> tuple[str, ExecutionResult] | None:
        with self.lock:
            row = self.db.execute(
                "SELECT fingerprint, result_json, expires_at FROM idempotency WHERE key=?",
                (key,),
            ).fetchone()
        if not row:
            return None
        if row[2] <= time.time():
            with self.lock, self.db:
                self.db.execute("DELETE FROM idempotency WHERE key=?", (key,))
            return None
        data = json.loads(row[1])
        res = ExecutionResult(
            action_id=data["action_id"],
            success=data["success"],
            exit_code=data.get("exit_code"),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            error=data.get("error"),
            replayed=True,
        )
        return row[0], res

    def save_approval(self, approval: Approval) -> None:
        with self.lock, self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO approvals VALUES(?,?,?,?,?,?,?,?)",
                (
                    approval.id,
                    approval.fingerprint,
                    approval.actor_id,
                    approval.tenant_id,
                    approval.action_type,
                    approval.status.value,
                    approval.expires_at,
                    approval.nonce,
                ),
            )

    def get_approval(self, approval_id: str) -> Approval | None:
        with self.lock:
            row = self.db.execute(
                "SELECT id, fingerprint, actor_id, tenant_id, action_type, status, expires_at, nonce FROM approvals WHERE id=?",
                (approval_id,),
            ).fetchone()
        if not row:
            return None
        return Approval(
            id=row[0],
            fingerprint=row[1],
            actor_id=row[2],
            tenant_id=row[3],
            action_type=row[4],
            status=ApprovalStatus(row[5]),
            expires_at=row[6],
            nonce=row[7],
        )
