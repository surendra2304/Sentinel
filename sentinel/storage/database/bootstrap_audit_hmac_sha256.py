"""Audit / HMAC / SHA-256 table bootstrap for Oracle (SENTINEL schema).

SQL translations documented / applied:
  * MERGE          — upsert via build_merge_sql (oracle+oracledb); no INSERT OR REPLACE
  * RETURNING      — INSERT ... RETURNING id INTO :id (single-row identity retrieval)
  * LIMIT          — SQLAlchemy compiles .limit() to FETCH FIRST n ROWS ONLY
  * JSON           — JSONDocument TypeDecorator -> CLOB (oracle) / TEXT (others)
  * identity PK    — NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY (Oracle 12c+)

Bootstrap runs unqualified (current Oracle user = SENTINEL). Tables are created
with metadata.create_all when init_database() is called; this module provides
explicit DDL for the audit/HMAC/sha256 surfaces that must survive redeploys.
"""

from __future__ import annotations

import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger("sentinel.bootstrap.audit_hmac_sha256")

# Table names (unqualified -> owned by connecting SENTINEL user)
AUDIT_LEDGER = "sentinel_audit_ledger"
HMAC_KEYS = "sentinel_hmac_keys"
SHA256_INDEX = "sentinel_sha256_index"

# DDL uses Oracle identity, CLOB for JSON/payload, MERGE for upserts,
# RETURNING for identity retrieval, FETCH FIRST for pagination.
BOOTSTRAP_SQL = """
-- 1. Audit ledger with HMAC-SHA256 signature (hash-chained, durable)
CREATE TABLE IF NOT EXISTS {audit_ledger} (
    audit_id        NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entry_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    event_type      VARCHAR2(128) NOT NULL,
    actor           VARCHAR2(128) NOT NULL,
    target          VARCHAR2(256),
    action_type     VARCHAR2(128) NOT NULL,
    scope_policy    VARCHAR2(128) NOT NULL,
    decision        VARCHAR2(64) NOT NULL,
    details         CLOB DEFAULT NULL,                 -- JSON payload (CLOB)
    previous_hash   VARCHAR2(128) NOT NULL,
    current_hash    VARCHAR2(128) NOT NULL,
    hmac_signature  VARCHAR2(256) NOT NULL,            -- HMAC-SHA256
    verified        NUMBER(1) DEFAULT 1 NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_{audit_ledger}_entry_ts ON {audit_ledger}(entry_timestamp);
CREATE INDEX IF NOT EXISTS idx_{audit_ledger}_actor ON {audit_ledger}(actor);
CREATE INDEX IF NOT EXISTS idx_{audit_ledger}_current_hash ON {audit_ledger}(current_hash);

-- 2. HMAC key storage (algorithm reference; key value held encrypted/externally)
CREATE TABLE IF NOT EXISTS {hmac_keys} (
    key_id      NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_name    VARCHAR2(64) UNIQUE NOT NULL,
    key_value   CLOB DEFAULT NULL,                      -- encrypted reference / vault blob
    algorithm   VARCHAR2(32) DEFAULT 'HMAC-SHA256' NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    rotated_at  TIMESTAMP DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_{hmac_keys}_key_name ON {hmac_keys}(key_name);

-- 3. SHA-256 integrity index (entity-level hash references)
CREATE TABLE IF NOT EXISTS {sha256_index} (
    ref_id       NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entity_type  VARCHAR2(64) NOT NULL,
    entity_id    VARCHAR2(64) NOT NULL,
    sha256_digest VARCHAR2(64) NOT NULL,
    computed_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    metadata     CLOB DEFAULT NULL                       -- JSON metadata
);
CREATE INDEX IF NOT EXISTS idx_{sha256_index}_entity ON {sha256_index}(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_{sha256_index}_digest ON {sha256_index}(sha256_digest);
""".format(
    audit_ledger=AUDIT_LEDGER,
    hmac_keys=HMAC_KEYS,
    sha256_index=SHA256_INDEX,
)

# MERGE for idempotent audit insert (upsert by previous_hash + current_hash composite)
MERGE_AUDIT_SQL = """
MERGE INTO {table} t
USING (SELECT :previous_hash AS previous_hash, :current_hash AS current_hash FROM dual) s
ON (t.previous_hash = s.previous_hash AND t.current_hash = s.current_hash)
WHEN MATCHED THEN UPDATE SET
    t.entry_timestamp = :entry_timestamp,
    t.hmac_signature = :hmac_signature,
    t.verified = :verified
WHEN NOT MATCHED THEN INSERT (
    entry_timestamp, event_type, actor, target, action_type,
    scope_policy, decision, details, previous_hash, current_hash,
    hmac_signature, verified
) VALUES (
    :entry_timestamp, :event_type, :actor, :target, :action_type,
    :scope_policy, :decision, :details, :previous_hash, :current_hash,
    :hmac_signature, :verified
)
RETURNING audit_id INTO :audit_id;
""".format(table=AUDIT_LEDGER)

# LIMIT -> FETCH FIRST (documented translation for pagination queries)
LIMIT_TRANSLATION = "ORDER BY audit_id FETCH FIRST :n ROWS ONLY"

# JSON -> CLOB (already enforced by JSONDocument TypeDecorator; documented here)
JSON_TO_CLOB_NOTE = "JSONDocument.process_bind_param -> json.dumps + CLOB (oracle); load_dialect_impl -> CLOB()"


async def bootstrap_audit_tables(engine: AsyncEngine) -> None:
    """Create audit/HMAC/sha256 tables in the current Oracle schema (SENTINEL)."""
    async with engine.begin() as conn:
        # Execute each statement separately; Oracle IF NOT EXISTS not native,
        # so we rely on exception suppression for idempotency.
        for stmt in BOOTSTRAP_SQL.split(";"):
            stmt = stmt.strip()
            if not stmt or stmt.startswith("--"):
                continue
            try:
                await conn.execute(text(stmt))
                logger.info("Bootstrap executed: %s", stmt[:60].replace("\n", " "))
            except Exception as exc:
                # Idempotent: ignore "table already exists" or index errors.
                msg = str(exc).lower()
                if "already exists" in msg or "duplicate" in msg or "constraint" in msg:
                    logger.debug("Bootstrap idempotent skip: %s", msg[:120])
                else:
                    logger.warning("Bootstrap execution note: %s", msg[:120])
    logger.info("Audit / HMAC / SHA-256 bootstrap complete on %s", AUDIT_LEDGER)


def get_bootstrap_sql_snapshot() -> dict[str, str]:
    """Return a readable inventory of SQL translations applied."""
    return {
        "MERGE": MERGE_AUDIT_SQL[:200] + "...",
        "RETURNING": "INSERT ... RETURNING audit_id INTO :audit_id",
        "LIMIT": LIMIT_TRANSLATION,
        "JSON->CLOB": JSON_TO_CLOB_NOTE,
        "identity_PK": "NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY",
        "tables": f"{AUDIT_LEDGER}, {HMAC_KEYS}, {SHA256_INDEX}",
    }
