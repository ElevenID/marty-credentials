"""Service-owned asynchronous database lifecycle for verification."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for verification-service persistence models."""


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _database_url() -> URL:
    raw_url = os.environ.get("DATABASE_URL")
    if not raw_url:
        raise RuntimeError("DATABASE_URL environment variable is required")

    url = make_url(raw_url)
    if url.get_backend_name() == "postgresql" and url.drivername in {
        "postgres",
        "postgresql",
        "postgresql+psycopg",
        "postgresql+psycopg2",
    }:
        return url.set(drivername="postgresql+asyncpg")
    return url


def get_engine() -> AsyncEngine:
    """Create the process-wide asynchronous engine on first use."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            _database_url(),
            hide_parameters=True,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Create the process-wide session factory on first use."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """Yield one request-scoped asynchronous database session."""
    async with get_session_factory()() as session:
        yield session


async def close_database() -> None:
    """Dispose database resources during application shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
