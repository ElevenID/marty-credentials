from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

os.environ.setdefault("TOKEN_HMAC_KEY", "test-only-oid4vci-capability-hmac-key")

from issuance.infrastructure.adapters.postgres_repository import (  # noqa: E402
    PostgresIssuanceRepository,
)


@pytest.mark.asyncio
async def test_real_postgres_capabilities_are_shared_digest_only_and_single_use() -> None:
    database_url = os.environ.get("OID4VCI_CAPABILITY_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("OID4VCI_CAPABILITY_TEST_DATABASE_URL is not configured")

    migrations = (
        Path(__file__).resolve().parents[1]
        / "services"
        / "issuance"
        / "infrastructure"
        / "migrations"
    )
    config = Config(str(migrations / "alembic.ini"))
    config.set_main_option("script_location", str(migrations))
    sync_url = database_url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
    sync_engine = create_engine(sync_url)
    with sync_engine.begin() as connection:
        connection.execute(text("CREATE SCHEMA IF NOT EXISTS issuance_service"))
        connection.execute(text("CREATE SCHEMA IF NOT EXISTS organization_service"))
        connection.execute(
            text(
                """
                CREATE TABLE organization_service.organizations (
                    id VARCHAR PRIMARY KEY,
                    name VARCHAR,
                    slug VARCHAR
                )
                """
            )
        )
    sync_engine.dispose()
    config.set_main_option(
        "sqlalchemy.url",
        sync_url,
    )
    command.upgrade(config, "head")

    engine = create_async_engine(database_url)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    creator = PostgresIssuanceRepository(session_factory)
    consumer = PostgresIssuanceRepository(session_factory)
    request_uri = "urn:ietf:params:oauth:request_uri:cross-instance-secret"
    nonce = "cross-instance-wallet-proof-nonce"

    try:
        assert await creator.save_pushed_authorization_request(
            request_uri,
            {"client_id": "wallet", "organization_id": "org-a"},
            ttl_seconds=90,
        )
        assert await creator.save_proof_nonce(nonce, ttl_seconds=300)

        async with session_factory() as session:
            rows = (
                (
                    await session.execute(
                        text(
                            "SELECT purpose, key_digest, payload "
                            "FROM issuance_service.oid4vci_ephemeral_capabilities"
                        )
                    )
                )
                .mappings()
                .all()
            )
        assert {row["key_digest"] for row in rows} == {
            hashlib.sha256(request_uri.encode()).hexdigest(),
            hashlib.sha256(nonce.encode()).hexdigest(),
        }
        assert all(request_uri not in str(row) and nonce not in str(row) for row in rows)

        assert await consumer.consume_pushed_authorization_request(request_uri) == {
            "client_id": "wallet",
            "organization_id": "org-a",
        }
        assert await creator.consume_pushed_authorization_request(request_uri) is None

        contenders = [PostgresIssuanceRepository(session_factory) for _ in range(12)]
        winners = await asyncio.gather(*(repo.consume_proof_nonce(nonce) for repo in contenders))
        assert sum(winners) == 1

        async with session_factory() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO issuance_service.oid4vci_ephemeral_capabilities
                        (purpose, key_digest, payload, created_at, expires_at)
                    SELECT
                        'par',
                        lpad(series::text, 64, '0'),
                        '{}'::json,
                        clock_timestamp() - interval '2 seconds',
                        clock_timestamp() - interval '1 second'
                    FROM generate_series(1, 1002) AS series
                    """
                )
            )
            await session.commit()
        cleanup_probe = "bounded-cleanup-live-proof-nonce"
        assert await creator.save_proof_nonce(cleanup_probe, ttl_seconds=300)
        async with session_factory() as session:
            expired_count = await session.scalar(
                text(
                    "SELECT count(*) FROM issuance_service.oid4vci_ephemeral_capabilities "
                    "WHERE expires_at <= clock_timestamp()"
                )
            )
        assert expired_count == 2
        assert await consumer.consume_proof_nonce(cleanup_probe)

        expired_nonce = "database-clock-expired-proof-nonce"
        assert await creator.save_proof_nonce(expired_nonce, ttl_seconds=300)
        expired_digest = hashlib.sha256(expired_nonce.encode()).hexdigest()
        async with session_factory() as session:
            await session.execute(
                text(
                    "UPDATE issuance_service.oid4vci_ephemeral_capabilities "
                    "SET expires_at = clock_timestamp() - interval '1 second' "
                    "WHERE purpose = 'proof_nonce' AND key_digest = :key_digest"
                ),
                {"key_digest": expired_digest},
            )
            await session.commit()
        assert not await consumer.consume_proof_nonce(expired_nonce)
        async with session_factory() as session:
            remaining = await session.scalar(
                text(
                    "SELECT count(*) FROM issuance_service.oid4vci_ephemeral_capabilities "
                    "WHERE purpose = 'proof_nonce' AND key_digest = :key_digest"
                ),
                {"key_digest": expired_digest},
            )
        assert remaining == 0
    finally:
        await engine.dispose()
