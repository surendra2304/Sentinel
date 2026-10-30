"""Sentinel durable security store: idempotency keys and gateway approvals.

Historically this module opened a raw ``sqlite3`` file under ``/dev/shm`` (or
``data/``) and used ``INSERT OR REPLACE``. Both are gone: the store now writes to
the configured Sentinel database (Oracle Autonomous Database by default) through
SQLAlchemy, creates its tables from metadata, and upserts with ``MERGE`` on
Oracle.

Notes for Oracle:
* binds are named (``:name``), never positional ``?``;
* there is no ``LIMIT`` -- the single-row lookup is by primary key (and the
  dialect compiles ``LIMIT`` to ``FETCH FIRST n ROWS ONLY`` if one is ever added);
* empty strings are stored as ``NULL``;
* JSON payloads are ``json.dumps`` text;
* result rows are read through labelled columns, so Oracle's upper-case column
  names never leak into the parsed ``ExecutionResult``;
* identity retrieval uses ``RETURNING`` (e.g. ``INSERT ... RETURNING audit_id INTO :audit_id``).
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from typing import Any

from sqlalchemy import (
    Column,
    Engine,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    bindparam,
    create_engine,
    delete,
    select,
    text,
    update,
)

from sentinel.config.settings import get_settings
from sentinel.core.gateway.models import Approval, ApprovalStatus, ExecutionResult
from sentinel.storage.database.oracle import build_merge_sql, normalise_row

metadata = MetaData()

IDEMPOTENCY_TABLE = "sentinel_idempotency"
APPROVALS_TABLE = "sentinel_gateway_approvals"

idempotency_table = Table(
    IDEMPOTENCY_TABLE,
    metadata,
    Column("idempotency_key", String(256), primary_key=True),
    Column("fingerprint", String(128), nullable=False),
    Column("result_json", Text, nullable=False),
    Column("expires_at", Float, nullable=False),
)

approvals_table = Table(
    APPROVALS_TABLE,
    metadata,
    Column("approval_id", String(128), primary_key=True),
    Column("fingerprint", String(128), nullable=False),
    Column("actor_id", String(128), nullable=False),
    Column("tenant_id", String(128), nullable=False),
    Column("action_type", String(128), nullable=False),
    Column("status", String(32), nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("nonce", String(128), nullable=False),
)


def get_database_url() -> str:
    """Return the configured sync database URL, refusing SQLite."""
    url = get_settings().db.sync_url
    if "sqlite" in url.split("://", 1)[0].lower():
        raise RuntimeError(
            "SentinelPersistence requires the Oracle database URL "
            "(DATABASE_URL=oracle+oracledb://...); SQLite is no longer supported."
        )
    return url


class SentinelPersistence:
    """Database-backed store for idempotency keys, approvals and their TTLs."""

    def __init__(
        self,
        engine: Engine | str | None = None,
        *,
        create_schema: bool = True,
    ):
        """Create the store.

        ``engine`` may be a SQLAlchemy ``Engine`` or an explicit SQLAlchemy URL
        (unit tests use ``sqlite:///...``). When omitted, the configured Sentinel
        database URL is used and SQLite is refused. A bare filesystem path is
        rejected: that was the old SQLite default and it is not durable.
        """
        self._owns_engine = False
        if isinstance(engine, Engine):
            self._engine = engine
        elif isinstance(engine, str):
            if "://" not in engine:
                raise ValueError(
                    "SentinelPersistence no longer accepts a filesystem path; pass a "
                    "SQLAlchemy URL (e.g. 'sqlite:///test.db' in tests) or omit it to use "
                    "the configured Oracle database."
                )
            self._engine = create_engine(engine, future=True)
            self._owns_engine = True
        else:
            self._engine = create_engine(get_database_url(), future=True, pool_pre_ping=True)
            self._owns_engine = True

        self.lock = threading.RLock()
        if create_schema:
            metadata.create_all(self._engine, checkfirst=True)

    @property
    def db(self) -> Engine:
        """The underlying SQLAlchemy engine (kept for backward compatibility)."""
        return self._engine

    # -- idempotency -------------------------------------------------------
    def put_idempotency(
        self,
        key: str,
        fingerprint: str,
        result: ExecutionResult,
        ttl: float = 3600.0,
    ) -> None:
        payload = {
            "action_id": result.action_id,
            "success": result.success,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": result.error,
            "replayed": True,
        }
        row = normalise_row(
            {
                "idempotency_key": key,
                "fingerprint": fingerprint,
                "result_json": json.dumps(payload),
                "expires_at": time.time() + ttl,
            }
        )
        self._upsert(idempotency_table, row, ["idempotency_key"])

    def get_idempotency(self, key: str) -> tuple[str, ExecutionResult] | None:
        stmt = select(
            idempotency_table.c.fingerprint,
            idempotency_table.c.result_json,
            idempotency_table.c.expires_at,
        ).where(idempotency_table.c.idempotency_key == key)
        with self.lock, self._engine.connect() as conn:
            row = conn.execute(stmt).first()
        if row is None:
            return None
        fingerprint, result_json, expires_at = row
        if float(expires_at) <= time.time():
            with self.lock, self._engine.begin() as conn:
                conn.execute(
                    delete(idempotency_table).where(idempotency_table.c.idempotency_key == key)
                )
            return None
        data = json.loads(result_json)
        result = ExecutionResult(
            action_id=data["action_id"],
            success=data["success"],
            exit_code=data.get("exit_code"),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            error=data.get("error"),
            replayed=True,
        )
        return str(fingerprint), result

    # -- approvals ---------------------------------------------------------
    def save_approval(self, approval: Approval) -> None:
        row = normalise_row(
            {
                "approval_id": approval.id,
                "fingerprint": approval.fingerprint,
                "actor_id": approval.actor_id,
                "tenant_id": approval.tenant_id,
                "action_type": approval.action_type,
                "status": approval.status.value,
                "expires_at": approval.expires_at,
                "nonce": approval.nonce,
            }
        )
        self._upsert(approvals_table, row, ["approval_id"])

    def get_approval(self, approval_id: str) -> Approval | None:
        stmt = select(approvals_table).where(approvals_table.c.approval_id == approval_id)
        with self.lock, self._engine.connect() as conn:
            row = conn.execute(stmt).mappings().first()
        if row is None:
            return None
        return Approval(
            id=str(row["approval_id"]),
            fingerprint=str(row["fingerprint"]),
            actor_id=str(row["actor_id"]),
            tenant_id=str(row["tenant_id"]),
            action_type=str(row["action_type"]),
            status=ApprovalStatus(str(row["status"])),
            expires_at=float(row["expires_at"]),
            nonce=str(row["nonce"]),
        )

    def count_approvals(self) -> int:
        """Number of persisted approvals (used by health probes)."""
        stmt = select(approvals_table.c.approval_id)
        with self.lock, self._engine.connect() as conn:
            return len(conn.execute(stmt).all())

    # -- internals ---------------------------------------------------------
    def _upsert(self, table: Table, values: dict[str, Any], key_columns: list[str]) -> None:
        """Insert or update a row: ``MERGE`` on Oracle, update-then-insert elsewhere."""
        with self.lock, self._engine.begin() as conn:
            if conn.dialect.name == "oracle":
                value_columns = [column for column in values if column not in key_columns]
                sql = build_merge_sql(table.name, key_columns, value_columns)
                conn.execute(text(sql), values)
                return

            # SQLAlchemy reserves column-named bind parameters inside update(),
            # so the non-Oracle path uses prefixed parameter names.
            key_predicates = and_(
                *[table.c[column] == bindparam(f"k_{column}") for column in key_columns]
            )
            update_values = {
                column: bindparam(f"v_{column}")
                for column in values
                if column not in key_columns
            }
            params = {f"k_{column}": values[column] for column in key_columns}
            params.update(
                {
                    f"v_{column}": values[column]
                    for column in values
                    if column not in key_columns
                }
            )
            result = conn.execute(
                update(table).where(key_predicates).values(**update_values),
                params,
            )
            if result.rowcount == 0:
                conn.execute(table.insert(), values)

    def close(self) -> None:
        """Dispose the engine when this store created it."""
        with self.lock, contextlib.suppress(Exception):
            if self._owns_engine:
                self._engine.dispose()

    def __enter__(self) -> SentinelPersistence:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


__all__ = [
    "APPROVALS_TABLE",
    "IDEMPOTENCY_TABLE",
    "SentinelPersistence",
    "get_database_url",
    "metadata",
]
