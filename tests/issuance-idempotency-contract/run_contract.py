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
    list[tuple[IssuanceTransaction, bool]], list[bool], bool, bool, str, int, str
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

        grpc_transaction = IssuanceTransaction(
            id=str(uuid.uuid4()),
            organization_id="org-grpc-signing-race",
            credential_template_id="template-grpc-signing-race",
            status=IssuanceStatus.AUTHORIZED,
            access_token="grpc-signing-race-token",
            claims={"achievement": "grpc-signing-race"},
            credential_type="OpenBadgeCredential",
            issuer_profile_id="issuer-profile-grpc-signing-race",
            issuer_did_override="did:web:issuer.example",
            issuer_algorithm="ES256",
            signing_service_id="openbao-transit",
        )
        await repository.save_transaction(grpc_transaction)
        grpc_credential_id = stable_issuance_credential_id(grpc_transaction.id)
        grpc_claims = await asyncio.gather(
            repository.claim_transaction_for_signing(grpc_transaction, grpc_credential_id),
            repository.claim_transaction_for_signing(grpc_transaction, grpc_credential_id),
        )
        grpc_winners = [claim for claim in grpc_claims if claim is not None]
        assert len(grpc_winners) == 1
        grpc_winner = grpc_winners[0]
        assert grpc_winner.status == IssuanceStatus.SIGNING
        assert grpc_winner.reserved_credential_id == grpc_credential_id
        grpc_issued_at = datetime.now(UTC)
        grpc_credential = IssuedCredential(
            id=grpc_credential_id,
            transaction_id=grpc_winner.id,
            organization_id=grpc_winner.organization_id,
            credential_template_id=grpc_winner.credential_template_id,
            credential_jwt="grpc-contract-signed-credential",
            credential_hash=hashlib.sha256(b"grpc-contract-signed-credential").hexdigest(),
            status=CredentialStatus.ACTIVE,
            issued_at=grpc_issued_at,
        )
        await repository.finalize_credential_issuance(grpc_winner, grpc_credential)
        grpc_finalized = await repository.get_transaction(grpc_winner.id)
        assert grpc_finalized is not None
        assert grpc_finalized.status == IssuanceStatus.ISSUED
        assert grpc_finalized.issued_at == grpc_issued_at
        assert (
            await repository.get_credential_by_transaction_id(grpc_winner.id)
        ).id == grpc_credential_id

        grpc_failed_transaction = IssuanceTransaction(
            id=str(uuid.uuid4()),
            organization_id="org-grpc-signing-failure",
            credential_template_id="template-grpc-signing-failure",
            status=IssuanceStatus.AUTHORIZED,
            access_token="grpc-signing-failure-token",
            claims={"achievement": "grpc-signing-failure"},
            credential_type="OpenBadgeCredential",
            issuer_profile_id="issuer-profile-grpc-signing-failure",
            issuer_did_override="did:web:issuer.example",
            issuer_algorithm="ES256",
            signing_service_id="openbao-transit",
        )
        await repository.save_transaction(grpc_failed_transaction)
        grpc_failed_credential_id = stable_issuance_credential_id(grpc_failed_transaction.id)
        grpc_failed_claim = await repository.claim_transaction_for_signing(
            grpc_failed_transaction,
            grpc_failed_credential_id,
        )
        assert grpc_failed_claim is not None
        grpc_failed_claim.fail("KMS unavailable")
        await repository.save_transaction(grpc_failed_claim)
        grpc_failed = await repository.get_transaction(grpc_failed_claim.id)
        assert grpc_failed is not None
        assert grpc_failed.status == IssuanceStatus.FAILED
        assert grpc_failed.reserved_credential_id == grpc_failed_credential_id
        assert await repository.get_credential_by_transaction_id(grpc_failed_claim.id) is None
        return (
            list(results),
            list(finalization_results),
            changed_semantics_rejected,
            early_recovery_exercised,
            grpc_transaction.id,
            len(grpc_winners),
            grpc_failed_transaction.id,
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
        grpc_transaction_id,
        grpc_signing_claim_winner_count,
        grpc_failed_transaction_id,
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
        grpc_issued_count, grpc_issued_transaction_count = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM issuance_service.issued_credentials
                 WHERE transaction_id = %s),
                (SELECT count(*) FROM issuance_service.issuance_transactions
                 WHERE id = %s AND status = 'issued' AND issued_at IS NOT NULL)
            """,
            (grpc_transaction_id, grpc_transaction_id),
        ).fetchone()
        assert grpc_issued_count == 1
        assert grpc_issued_transaction_count == 1
        (
            grpc_failed_reserved_transaction_count,
            grpc_failed_issued_credential_count,
        ) = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM issuance_service.issuance_transactions
                 WHERE id = %s AND status = 'failed'
                   AND reserved_credential_id = %s),
                (SELECT count(*) FROM issuance_service.issued_credentials
                 WHERE transaction_id = %s)
            """,
            (
                grpc_failed_transaction_id,
                stable_issuance_credential_id(grpc_failed_transaction_id),
                grpc_failed_transaction_id,
            ),
        ).fetchone()
        assert grpc_failed_reserved_transaction_count == 1
        assert grpc_failed_issued_credential_count == 0
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
        assert version == "canvas_review_recovery_claim"

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
                "migration_revision": version,
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
                "grpc_signing_claim_winner_count": grpc_signing_claim_winner_count,
                "grpc_issued_credential_count": grpc_issued_count,
                "grpc_issued_transaction_count": grpc_issued_transaction_count,
                "grpc_failed_reserved_transaction_count": (grpc_failed_reserved_transaction_count),
                "grpc_failed_issued_credential_count": grpc_failed_issued_credential_count,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
