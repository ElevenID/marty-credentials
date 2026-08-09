from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from issuance.domain.entities import (
    IssuanceIdempotencyConflictError,
    IssuanceTransaction,
)
from issuance.infrastructure.adapters.postgres_repository import (
    PostgresIssuanceRepository,
)
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DATABASE_URL = os.environ["DATABASE_URL"]
RESULT_PATH = Path(os.environ["CONTRACT_RESULT_PATH"])
SOURCE_REVISION = os.environ.get("CONTRACT_SOURCE_REVISION", "local-worktree")
RAW_KEY = "c" * 64
KEY_HASH = hashlib.sha256(f"marty:issuance-idempotency-key:v1:{RAW_KEY}".encode()).hexdigest()
REQUEST_HASH = "b" * 64
CHANGED_REQUEST_HASH = "d" * 64


def _upgrade() -> None:
    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute("CREATE SCHEMA IF NOT EXISTS issuance_service")
        connection.execute("CREATE SCHEMA IF NOT EXISTS organization_service")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS organization_service.organizations (
                id VARCHAR PRIMARY KEY,
                name VARCHAR,
                slug VARCHAR
            )
            """
        )
        connection.commit()

    config = Config("/contract/migrations/alembic.ini")
    config.set_main_option("script_location", "/contract/migrations")
    config.set_main_option(
        "sqlalchemy.url",
        DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1),
    )
    command.upgrade(config, "head")


def _transaction(*, request_hash: str = REQUEST_HASH) -> IssuanceTransaction:
    return IssuanceTransaction(
        id=str(uuid.uuid4()),
        organization_id="org-race",
        credential_template_id="template-race",
        idempotency_key_hash=KEY_HASH,
        idempotency_request_hash=request_hash,
        pre_auth_code=f"pre-{uuid.uuid4()}",
        claims={"achievement": "production-repository-contract"},
    )


async def _exercise_production_repository() -> tuple[list[tuple[IssuanceTransaction, bool]], bool]:
    async_database_url = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    engine = create_async_engine(async_database_url)
    repository = PostgresIssuanceRepository(async_sessionmaker(engine, expire_on_commit=False))
    assert repository.__class__.__module__ == (
        "issuance.infrastructure.adapters.postgres_repository"
    )

    try:
        results = await asyncio.gather(
            repository.reserve_transaction_idempotently(_transaction()),
            repository.reserve_transaction_idempotently(_transaction()),
        )

        changed_semantics_rejected = False
        try:
            await repository.reserve_transaction_idempotently(
                _transaction(request_hash=CHANGED_REQUEST_HASH)
            )
        except IssuanceIdempotencyConflictError:
            changed_semantics_rejected = True
        assert changed_semantics_rejected
        return list(results), changed_semantics_rejected
    finally:
        await engine.dispose()


def main() -> None:
    _upgrade()
    results, changed_semantics_rejected = asyncio.run(_exercise_production_repository())

    assert sorted(created for _, created in results) == [False, True]
    assert len({transaction.id for transaction, _ in results}) == 1
    assert len({transaction.pre_auth_code for transaction, _ in results}) == 1
    assert all(transaction.idempotency_request_hash == REQUEST_HASH for transaction, _ in results)

    with psycopg.connect(DATABASE_URL) as connection:
        count, stored_key_hash, stored_request_hash = connection.execute(
            """
            SELECT count(*), min(idempotency_key_hash), min(idempotency_request_hash)
            FROM issuance_service.issuance_transactions
            WHERE organization_id = 'org-race'
            """
        ).fetchone()
        assert count == 1
        assert stored_key_hash == KEY_HASH
        assert stored_request_hash == REQUEST_HASH
        raw_key_persisted = connection.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM issuance_service.issuance_transactions
                WHERE idempotency_key_hash = %s
                   OR idempotency_request_hash = %s
            )
            """,
            (RAW_KEY, RAW_KEY),
        ).fetchone()[0]
        assert raw_key_persisted is False
        version = connection.execute(
            "SELECT version_num FROM issuance_service.alembic_version"
        ).fetchone()[0]
        assert version == "issuance_offer_idempotency"

    created_count = sum(created for _, created in results)
    recovered_count = len(results) - created_count
    same_transaction = len({transaction.id for transaction, _ in results}) == 1
    same_pre_authorized_code = len({transaction.pre_auth_code for transaction, _ in results}) == 1

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(
        json.dumps(
            {
                "status": "passed",
                "source_revision": SOURCE_REVISION,
                "migration_revision": "issuance_offer_idempotency",
                "created_count": created_count,
                "recovered_count": recovered_count,
                "same_transaction": same_transaction,
                "same_pre_authorized_code": same_pre_authorized_code,
                "raw_key_persisted": raw_key_persisted,
                "production_repository_exercised": True,
                "changed_semantics_rejected": changed_semantics_rejected,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
