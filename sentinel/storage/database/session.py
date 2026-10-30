"""SQLAlchemy Async Session Management & Engine Factory for Sentinel.

Oracle Autonomous Database (``oracle+oracledb_async://``) is the durable target.
A filesystem/SQLite URL is rejected: Sentinel used to open one silently, which is
how findings, evidence and approvals were lost on every redeploy.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.config.settings import (
    REMOVED_STORAGE_BACKENDS,
    DatabaseNotConfiguredError,
    get_settings,
)

logger = logging.getLogger("sentinel.storage.session")

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _reject_undurable_url(url: str) -> None:
    """Fail closed on SQLite (and any other removed backend) URLs."""
    scheme = url.split("://", 1)[0].lower()
    dialect = scheme.split("+", 1)[0]
    if dialect == "sqlite" or any(removed in scheme for removed in REMOVED_STORAGE_BACKENDS):
        raise DatabaseNotConfiguredError(
            "SQLite is not a supported Sentinel database. The security record must survive a "
            "redeploy. Set DATABASE_URL=oracle+oracledb://SENTINEL:<password>@<adb-host>:1522/"
            "?service_name=<service> (oracle+oracledb_async:// is also accepted)."
        )


def _engine_options(url: str) -> dict[str, object]:
    settings = get_settings()
    options: dict[str, object] = {
        "echo": settings.db.echo or (settings.is_oracle_database and settings.oracle.echo),
        "pool_pre_ping": True,
    }
    if url.startswith("oracle"):
        options.update(
            pool_size=settings.oracle.pool_size,
            max_overflow=settings.oracle.max_overflow,
            pool_recycle=settings.oracle.pool_recycle,
            pool_timeout=settings.oracle.pool_timeout,
        )
    elif url.startswith(("postgresql", "postgres")):
        options.update(
            pool_size=settings.db.pool_size,
            max_overflow=settings.db.max_overflow,
            pool_recycle=1800,
        )
    return options


def get_async_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        url = settings.db.async_url
        _reject_undurable_url(url)
        _engine = create_async_engine(url, **_engine_options(url))
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        engine = get_async_engine()
        _session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


async def close_async_engine() -> None:
    """Cleanly dispose of SQLAlchemy engine connections."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


async def _current_schema(engine: AsyncEngine) -> str:
    """Return the Oracle schema the connection resolves unqualified names against."""
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL"))
        value = result.scalar()
    return str(value or "").strip().upper()


def _drop_primary_key_duplicate_indexes(metadata: object) -> int:
    """Remove ORM indexes that merely duplicate a table's primary-key index.

    ``Column(..., primary_key=True, index=True)`` is harmless on SQLite and
    PostgreSQL but Oracle raises ORA-01408 when asked to index the same column
    list twice, which aborts the whole ``create_all``. The primary key already
    provides the index, so the redundant Index objects can be dropped before
    schema creation.
    """
    removed = 0
    for table in getattr(metadata, "tables", {}).values():
        pk_columns = [column.name for column in table.primary_key.columns]
        if not pk_columns:
            continue
        for index in list(table.indexes):
            if [column.name for column in index.columns] == pk_columns:
                table.indexes.discard(index)
                removed += 1
    return removed


async def init_database() -> None:
    """Create the Sentinel schema from ORM metadata at startup.

    Tables are created with unqualified names in the schema of the connecting
    Oracle user (``SENTINEL``); the ownership check below refuses to start when
    the connection resolves to a different schema, because that would scatter
    the security record across an unexpected owner.
    """
    settings = get_settings()
    if not settings.uses_database_backend:
        logger.info(
            "Storage backend '%s' is process-local; database bootstrap skipped.",
            settings.storage_backend_normalized,
        )
        return

    from sentinel.storage.database.models import Base

    engine = get_async_engine()
    if settings.is_oracle_database:
        owner = settings.oracle.owner
        actual = await _current_schema(engine)
        if owner and actual and actual != owner:
            raise RuntimeError(
                "Refusing to create Sentinel tables: connected to Oracle schema "
                f"'{actual}' but SENTINEL_ORACLE_SCHEMA expects '{owner}'. Sentinel writes "
                "unqualified table names, so it must connect as the schema owner."
            )

    if settings.is_oracle_database:
        removed = _drop_primary_key_duplicate_indexes(Base.metadata)
        if removed:
            logger.info(
                "Dropped %d ORM index(es) that duplicated a primary-key index (Oracle ORA-01408 guard).",
                removed,
            )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Bootstrap audit / HMAC / SHA-256 surfaces in SENTINEL schema
    try:
        from sentinel.storage.database.bootstrap_audit_hmac_sha256 import bootstrap_audit_tables
        await bootstrap_audit_tables(engine)
    except Exception as exc:
        logger.warning("Audit/HMAC/sha256 bootstrap skipped: %s", exc)
    logger.info(
        "Sentinel database schema ensured on %s (%d tables).",
        settings.database_dialect or "database",
        len(Base.metadata.tables),
    )


async def probe_database() -> bool:
    """Return True when the durable database answers a trivial query."""
    settings = get_settings()
    if not settings.uses_database_backend:
        return False
    engine = get_async_engine()
    statement = "SELECT 1 FROM DUAL" if settings.is_oracle_database else "SELECT 1"
    async with engine.connect() as conn:
        result = await conn.execute(text(statement))
        return result.scalar() == 1


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a transactional async database session context."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
