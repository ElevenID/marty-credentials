from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from issuance.domain.entities import (
    CredentialStatus,
    IssuanceIdempotencyConflictError,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
    stable_issuance_credential_id,
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


async def _exercise_production_repository() -> tuple[
    list[tuple[IssuanceTransaction, bool]], list[bool], bool, bool
]:
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

        committed = results[0][0]
        recovered = await repository.recover_transaction_idempotently(
            organization_id=committed.organization_id,
            idempotency_key_hash=committed.idempotency_key_hash or "",
            idempotency_request_hash=committed.idempotency_request_hash or "",
        )
        assert recovered is not None
        assert recovered.id == committed.id
        assert recovered.pre_auth_code == committed.pre_auth_code
        early_recovery_exercised = True

        changed_semantics_rejected = False
        try:
            await repository.recover_transaction_idempotently(
                organization_id=committed.organization_id,
                idempotency_key_hash=committed.idempotency_key_hash or "",
                idempotency_request_hash=CHANGED_REQUEST_HASH,
            )
        except IssuanceIdempotencyConflictError:
            changed_semantics_rejected = True
        assert changed_semantics_rejected

        issued_at = datetime.now(UTC)
        credential = IssuedCredential(
            id=stable_issuance_credential_id(committed.id),
            transaction_id=committed.id,
            organization_id=committed.organization_id,
            credential_template_id=committed.credential_template_id,
            credential_jwt="contract-signed-credential",
            credential_hash=hashlib.sha256(b"contract-signed-credential").hexdigest(),
            status=CredentialStatus.ACTIVE,
            issued_at=issued_at,
        )
        finalization_results = await asyncio.gather(
            repository.finalize_direct_credential_issuance(committed, credential),
            repository.finalize_direct_credential_issuance(committed, credential),
        )
        finalized = await repository.get_transaction(committed.id)
        assert finalized is not None
        assert finalized.status == IssuanceStatus.ISSUED
        assert finalized.issued_at == issued_at
        assert (await repository.get_credential_by_transaction_id(committed.id)).id == credential.id
        return (
            list(results),
            list(finalization_results),
            changed_semantics_rejected,
            early_recovery_exercised,
        )
    finally:
        await engine.dispose()


def main() -> None:
    _upgrade()
    (
        results,
        finalization_results,
        changed_semantics_rejected,
        early_recovery_exercised,
    ) = asyncio.run(_exercise_production_repository())

    assert sorted(created for _, created in results) == [False, True]
    assert len({transaction.id for transaction, _ in results}) == 1
    assert len({transaction.pre_auth_code for transaction, _ in results}) == 1
    assert all(transaction.idempotency_request_hash == REQUEST_HASH for transaction, _ in results)
    assert sorted(finalization_results) == [False, True]

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
        issued_count, issued_transaction_count = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM issuance_service.issued_credentials
                 WHERE transaction_id = %s),
                (SELECT count(*) FROM issuance_service.issuance_transactions
                 WHERE id = %s AND status = 'issued' AND issued_at IS NOT NULL)
            """,
            (results[0][0].id, results[0][0].id),
        ).fetchone()
        assert issued_count == 1
        assert issued_transaction_count == 1
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
        assert version == "merge_issuance_heads"

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
                "migration_revision": "merge_issuance_heads",
                "created_count": created_count,
                "recovered_count": recovered_count,
                "same_transaction": same_transaction,
                "same_pre_authorized_code": same_pre_authorized_code,
                "raw_key_persisted": raw_key_persisted,
                "production_repository_exercised": True,
                "changed_semantics_rejected": changed_semantics_rejected,
                "early_recovery_exercised": early_recovery_exercised,
                "delivered_finalization_winner_count": sum(finalization_results),
                "issued_credential_count": issued_count,
                "issued_transaction_count": issued_transaction_count,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
