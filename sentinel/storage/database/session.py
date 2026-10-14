"""SQLAlchemy Async Session Management & Engine Factory for Sentinel."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.config.settings import get_settings

logger = logging.getLogger("sentinel.storage.session")

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Enforce WAL mode, 5000ms busy timeout, and synchronous NORMAL on SQLite connections."""
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.close()
    except Exception as e:
        logger.warning(f"Failed to apply SQLite PRAGMAs: {e}")


def get_async_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        url = settings.db.async_url
        # Handle SQLite for testing / memory fallback
        if "sqlite" in url:
            _engine = create_async_engine(url, echo=settings.db.echo)
            event.listen(_engine.sync_engine, "connect", _set_sqlite_pragmas)
        else:
            _engine = create_async_engine(
                url,
                echo=settings.db.echo,
                pool_size=settings.db.pool_size,
                max_overflow=settings.db.max_overflow,
            )
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
