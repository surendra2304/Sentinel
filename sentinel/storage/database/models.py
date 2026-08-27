"""SQLAlchemy Database connection and Audit Log Table schema."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from sentinel.config.settings import get_settings


class Base(DeclarativeBase):
    """Declarative base class for Sentinel SQLAlchemy models."""
    pass


class AuditLogRecord(Base):
    """Database entity representing immutable audit events."""
    __tablename__ = "sentinel_audit_logs"

    entry_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    event_type = Column(String(128), index=True, nullable=False)
    actor = Column(String(128), index=True, nullable=False)
    target = Column(String(256), nullable=True)
    action_type = Column(String(128), index=True, nullable=False)
    scope_policy = Column(String(128), nullable=False)
    decision = Column(String(64), index=True, nullable=False)
    details = Column(JSON, default=dict, nullable=False)
    previous_hash = Column(String(128), nullable=False)
    current_hash = Column(String(128), nullable=False)
    signature = Column(String(256), nullable=False)
    verified = Column(Boolean, default=True)


class DatabaseSessionManager:
    """Manages async PostgreSQL sessions."""

    def __init__(self):
        self._settings = get_settings()
        self.engine = create_async_engine(
            self._settings.db.async_url,
            echo=self._settings.db.echo,
            pool_size=self._settings.db.pool_size,
            max_overflow=self._settings.db.max_overflow,
        )
        self.session_maker = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False
        )

    async def close(self):
        if self.engine is not None:
            await self.engine.dispose()

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self.session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


db_manager = DatabaseSessionManager()
