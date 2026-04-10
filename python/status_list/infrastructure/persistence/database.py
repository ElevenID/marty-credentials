"""Database configuration for status list service.

Follows the pattern from subscription/database.py for consistency.
Uses the same database as subscription service to share infrastructure
for both PKI certificate revocation and W3C credential status tracking.
"""

import logging
import os
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import Base

logger = logging.getLogger(__name__)

# Global engine and session factory (lazy initialization)
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_database_url() -> str:
    """Get database URL from environment.
    
    Defaults to subscription database URL for infrastructure sharing.
    Can be overridden with STATUS_LIST_DATABASE_URL for separate database.
    """
    status_list_url = os.environ.get("STATUS_LIST_DATABASE_URL")
    if status_list_url:
        return status_list_url
    
    # Fallback to subscription database (shared infrastructure)
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "Neither STATUS_LIST_DATABASE_URL nor DATABASE_URL is set"
        )
    return url


def get_engine() -> AsyncEngine:
    """Get or create the async engine (lazy initialization)."""
    global _engine
    if _engine is None:
        db_url = get_database_url()
        _engine = create_async_engine(
            db_url,
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
        logger.info(f"Status list database engine created: {db_url.split('@')[-1]}")
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create the session factory (lazy initialization)."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency for database sessions.
    
    Usage:
        @router.get("/endpoint")
        async def endpoint(db: AsyncSession = Depends(get_db_session)):
            ...
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_status_list_db() -> None:
    """Initialize status list database tables.
    
    Creates tables: status_lists, status_list_shards, status_entries
    Called during application startup (fail-fast pattern).
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Status list database tables created")


async def close_database() -> None:
    """Close database connections on shutdown."""
    global _engine, _session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Status list database connections closed")
