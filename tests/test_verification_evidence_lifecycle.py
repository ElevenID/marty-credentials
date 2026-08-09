from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import types
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from alembic import command
from alembic.config import Config
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

if "mmf.core.exceptions" not in sys.modules:
    mmf_module = types.ModuleType("mmf")
    mmf_core_module = types.ModuleType("mmf.core")
    mmf_exceptions_module = types.ModuleType("mmf.core.exceptions")

    class ValidationError(Exception):
        pass

    mmf_exceptions_module.ValidationError = ValidationError
    sys.modules["mmf"] = mmf_module
    sys.modules["mmf.core"] = mmf_core_module
    sys.modules["mmf.core.exceptions"] = mmf_exceptions_module

if "mmf.infrastructure.database.base" not in sys.modules:
    infrastructure_module = types.ModuleType("mmf.infrastructure")
    database_module = types.ModuleType("mmf.infrastructure.database")
    database_base_module = types.ModuleType("mmf.infrastructure.database.base")
    database_base_module.Base = declarative_base()
    sys.modules["mmf.infrastructure"] = infrastructure_module
    sys.modules["mmf.infrastructure.database"] = database_module
    sys.modules["mmf.infrastructure.database.base"] = database_base_module

from verification.application.service import (
    UnsupportedSessionPresentationError,
    VerificationService,
    VerificationSessionConflictError,
)
from verification.domain.entities import (
    SubmissionClaimState,
    VerificationMethod,
    VerificationSession,
    VerificationStatus,
    VerificationSubmissionClaim,
)
from verification.infrastructure.api.models import SubmitPresentationRequest
from verification.infrastructure.persistence.postgres_repository import (
    PostgresVerificationRepository,
    VerificationSessionModel,
)

ROOT = Path(__file__).resolve().parents[1]


def _pending_session() -> VerificationSession:
    return VerificationSession(
        id="session-1",
        organization_id="org-1",
        verifier_did="did:web:verifier.example",
        presentation_definition={"id": "pd-1", "input_descriptors": [{"id": "employee"}]},
        nonce="n" * 43,
    )


def _claimed_repository(session: VerificationSession) -> MagicMock:
    repository = MagicMock()
    repository.claim_submission = AsyncMock(
        return_value=VerificationSubmissionClaim(
            SubmissionClaimState.CLAIMED,
            session=session,
            verifier_nonce=session.nonce,
        )
    )

    async def finalize(
        outcome: VerificationSession,
        _presentation_sha256: str,
        _processing_token: str,
    ) -> VerificationSubmissionClaim:
        outcome.nonce = None
        return VerificationSubmissionClaim(
            SubmissionClaimState.FINALIZED,
            session=outcome,
        )

    repository.finalize_submission = AsyncMock(side_effect=finalize)
    return repository


@pytest.mark.asyncio
async def test_success_persists_claim_free_evidence_without_raw_presentation() -> None:
    session = _pending_session()
    repository = _claimed_repository(session)
    verifier = MagicMock()
    verifier.verify_jwt_vp = AsyncMock(
        return_value={
            "valid": True,
            "cryptographic_valid": True,
            "trust_chain_valid": True,
            "revocation_checked": True,
            "revocation_status": "VALID",
            "verified_claims": {"employee_id": "sensitive-employee-id"},
        }
    )
    presentation = "header.sensitive-employee-id.signature"

    result = await VerificationService(repository, verifier).submit_presentation(
        session.id,
        presentation,
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.presentation_data is None
    assert result.verification_evidence == {
        "schema_version": 1,
        "overall_result": "PASS",
        "cryptographic_valid": True,
        "trust_chain_valid": True,
        "revocation_checked": True,
        "revocation_status": "VALID",
        "verification_method": "jwt_vp",
        "presentation_sha256": result.verification_evidence["presentation_sha256"],
        "evaluated_at": result.verification_evidence["evaluated_at"],
    }
    serialized_evidence = json.dumps(result.verification_evidence)
    assert "sensitive-employee-id" not in serialized_evidence
    assert "header." not in serialized_evidence
    assert len(result.verification_evidence["presentation_sha256"]) == 64
    repository.claim_submission.assert_awaited_once()
    repository.finalize_submission.assert_awaited_once()


@pytest.mark.asyncio
async def test_failed_decision_persists_negative_evidence() -> None:
    session = _pending_session()
    repository = _claimed_repository(session)
    verifier = MagicMock()
    verifier.verify_jwt_vp = AsyncMock(
        return_value={
            "valid": False,
            "cryptographic_valid": False,
            "trust_chain_valid": False,
            "revocation_checked": False,
            "revocation_status": "SKIPPED",
            "error": "signature invalid",
        }
    )

    result = await VerificationService(repository, verifier).submit_presentation(
        session.id,
        "header.sensitive-payload.signature",
    )

    assert result.status is VerificationStatus.FAILED
    assert result.presentation_data is None
    assert result.verification_evidence["overall_result"] == "FAIL"
    assert result.verification_evidence["cryptographic_valid"] is False
    assert result.verification_evidence["verification_method"] == "jwt_vp"
    assert "sensitive-payload" not in json.dumps(result.verification_evidence)
    assert result.error_message == "Verification failed"


@pytest.mark.asyncio
async def test_verifier_exception_is_not_persisted() -> None:
    session = _pending_session()
    repository = _claimed_repository(session)
    verifier = MagicMock()
    verifier.verify_jwt_vp = AsyncMock(
        side_effect=RuntimeError("failed while parsing sensitive-payload")
    )

    result = await VerificationService(repository, verifier).submit_presentation(
        session.id,
        "header.sensitive-payload.signature",
    )

    assert result.status is VerificationStatus.FAILED
    assert result.error_message == "Verification failed due to verifier error"
    assert "sensitive-payload" not in json.dumps(result.verification_evidence)


@pytest.mark.asyncio
async def test_same_digest_terminal_retry_returns_without_reverification() -> None:
    session = _pending_session()
    session.status = VerificationStatus.VERIFIED
    session.nonce = None
    repository = MagicMock()
    repository.claim_submission = AsyncMock(
        return_value=VerificationSubmissionClaim(
            SubmissionClaimState.TERMINAL,
            session=session,
        )
    )
    repository.finalize_submission = AsyncMock()
    verifier = MagicMock()
    verifier.verify_jwt_vp = AsyncMock()

    result = await VerificationService(repository, verifier).submit_presentation(
        session.id,
        "header.payload.signature",
    )

    assert result is session
    verifier.verify_jwt_vp.assert_not_awaited()
    repository.finalize_submission.assert_not_awaited()


@pytest.mark.asyncio
async def test_conflicting_digest_fails_before_verifier() -> None:
    repository = MagicMock()
    repository.claim_submission = AsyncMock(
        return_value=VerificationSubmissionClaim(SubmissionClaimState.CONFLICT)
    )
    verifier = MagicMock()
    verifier.verify_jwt_vp = AsyncMock()

    with pytest.raises(VerificationSessionConflictError):
        await VerificationService(repository, verifier).submit_presentation(
            "session-1",
            "different.payload.signature",
        )

    verifier.verify_jwt_vp.assert_not_awaited()


@pytest.mark.asyncio
async def test_session_structured_presentation_fails_before_nonce_claim() -> None:
    repository = MagicMock()
    repository.claim_submission = AsyncMock()

    with pytest.raises(UnsupportedSessionPresentationError, match="session nonce"):
        await VerificationService(repository, MagicMock()).submit_presentation(
            "session-1",
            {"vp": "not-transaction-bound"},
        )

    repository.claim_submission.assert_not_awaited()


def test_session_submit_contract_advertises_only_nonce_bindable_jwt() -> None:
    assert SubmitPresentationRequest(presentation="header.payload.signature").presentation == (
        "header.payload.signature"
    )
    with pytest.raises(PydanticValidationError):
        SubmitPresentationRequest(presentation={"vp": "not-transaction-bound"})


@pytest.mark.asyncio
async def test_stale_worker_cannot_report_its_terminal_result() -> None:
    session = _pending_session()
    repository = _claimed_repository(session)
    repository.finalize_submission = AsyncMock(
        return_value=VerificationSubmissionClaim(SubmissionClaimState.STALE)
    )
    verifier = MagicMock()
    verifier.verify_jwt_vp = AsyncMock(
        return_value={
            "valid": True,
            "cryptographic_valid": True,
            "trust_chain_valid": True,
            "revocation_checked": True,
            "revocation_status": "VALID",
        }
    )

    with pytest.raises(VerificationSessionConflictError, match="no longer owns"):
        await VerificationService(repository, verifier).submit_presentation(
            session.id,
            "header.payload.signature",
        )


@pytest.mark.asyncio
async def test_postgres_adapter_round_trips_evidence_and_redacts_legacy_raw_data() -> None:
    database_session = MagicMock()
    clock_result = MagicMock()
    clock_result.scalar_one.return_value = datetime(2026, 8, 9, 12, 0, 0)
    database_session.execute = AsyncMock(return_value=clock_result)
    database_session.commit = AsyncMock()
    database_session.rollback = AsyncMock()
    entity = _pending_session()
    entity.verification_evidence = {
        "schema_version": 1,
        "overall_result": "FAIL",
        "presentation_sha256": "a" * 64,
    }
    entity.presentation_data = {"legacy": "raw-credential"}

    repository = PostgresVerificationRepository(database_session)
    await repository.create_session(entity, 600)

    model = database_session.add.call_args.args[0]
    assert isinstance(model, VerificationSessionModel)
    assert model.presentation_data is None
    assert model.verification_evidence == {}

    model.presentation_data = {"legacy": "raw-credential"}
    model.verification_evidence = entity.verification_evidence
    restored = repository._to_entity(model)
    assert restored.presentation_data is None
    assert restored.verification_evidence == entity.verification_evidence


@pytest.mark.asyncio
async def test_terminal_decision_remains_immutable_after_session_deadline() -> None:
    now = datetime(2026, 8, 9, 12, 0, 0)
    digest = "a" * 64
    model = VerificationSessionModel(
        id="terminal-session",
        organization_id="org-1",
        verifier_did="did:web:verifier.example",
        presentation_definition={"id": "pd-1", "input_descriptors": []},
        status=VerificationStatus.VERIFIED,
        verification_evidence={"presentation_sha256": digest},
        created_at=now - timedelta(minutes=11),
        updated_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=1),
        nonce=None,
        submission_sha256=digest,
    )
    locked_result = MagicMock()
    locked_result.scalar_one_or_none.return_value = model
    clock_result = MagicMock()
    clock_result.scalar_one.return_value = now
    database_session = MagicMock()
    database_session.execute = AsyncMock(side_effect=[locked_result, clock_result])
    database_session.commit = AsyncMock()

    async def expire_model_on_rollback() -> None:
        model.submission_sha256 = None

    database_session.rollback = AsyncMock(side_effect=expire_model_on_rollback)

    claim = await PostgresVerificationRepository(database_session).claim_submission(
        model.id,
        digest,
        "retry-token",
        60,
    )

    assert claim.state is SubmissionClaimState.TERMINAL
    assert claim.session is not None
    assert claim.session.status is VerificationStatus.VERIFIED
    database_session.commit.assert_not_awaited()
    database_session.rollback.assert_awaited_once()


def test_verification_migration_redacts_raw_data_and_adds_evidence_column() -> None:
    migration = (
        ROOT
        / "services"
        / "verification"
        / "infrastructure"
        / "migrations"
        / "versions"
        / "20260808_1900_persist_verification_evidence.py"
    ).read_text(encoding="utf-8")

    assert "ADD COLUMN IF NOT EXISTS verification_evidence" in migration
    assert "ALTER COLUMN verification_evidence SET NOT NULL" in migration
    assert "SET presentation_data = NULL" in migration
    assert "DROP TABLE" not in migration


def test_atomic_session_migration_fails_closed_and_adds_database_guards() -> None:
    migrations = ROOT / "services" / "verification" / "infrastructure" / "migrations"
    migration = (
        migrations / "versions" / "20260809_1200_atomic_verification_sessions.py"
    ).read_text(encoding="utf-8")
    environment = (migrations / "env.py").read_text(encoding="utf-8")

    assert "submission_sha256" in migration
    assert "processing_token_sha256" in migration
    assert "ck_verification_atomic_state" in migration
    assert "ux_verification_sessions_live_nonce" in migration
    assert "Historical terminal decisions are immutable" in migration
    assert "expired before atomic migration" in migration
    assert "clock_timestamp()" in migration
    assert "Verification interrupted before atomic session migration" in migration
    assert "cannot be safely removed" in migration
    assert "disable_existing_loggers=False" in environment


def test_verification_model_enums_match_varchar_migration_columns() -> None:
    status_type = VerificationSessionModel.__table__.c.status.type
    method_type = VerificationSessionModel.__table__.c.verification_method.type

    assert status_type.native_enum is False
    assert status_type.length == 32
    assert method_type.native_enum is False
    assert method_type.length == 32


def test_verification_image_contains_migration_runtime() -> None:
    dockerfile = (ROOT / "services" / "verification" / "Dockerfile").read_text(encoding="utf-8")

    assert "alembic==" in dockerfile
    assert "psycopg[binary]==" in dockerfile


@pytest.mark.asyncio
async def test_real_postgres_claim_recovery_and_terminal_fencing() -> None:
    database_url = os.environ.get("VERIFICATION_SESSION_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("VERIFICATION_SESSION_TEST_DATABASE_URL is not configured")

    migrations = ROOT / "services" / "verification" / "infrastructure" / "migrations"
    sync_url = database_url.replace("postgresql+asyncpg://", "postgresql+psycopg://")
    sync_engine = create_engine(sync_url)
    with sync_engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS public.verification_sessions"))
        connection.execute(text("CREATE SCHEMA IF NOT EXISTS verification_service"))
        connection.execute(text("DROP TABLE IF EXISTS verification_service.alembic_version"))
    sync_engine.dispose()

    config = Config(str(migrations / "alembic.ini"))
    config.set_main_option("script_location", str(migrations))
    config.set_main_option("sqlalchemy.url", sync_url)
    command.upgrade(config, "202608081900")

    duplicate_nonce = "d" * 43
    terminal_digest = hashlib.sha256(b"legacy-terminal").hexdigest()
    sync_engine = create_engine(sync_url)
    with sync_engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO public.verification_sessions (
                    id, organization_id, verifier_did, presentation_definition,
                    status, verification_evidence, created_at, updated_at,
                    expires_at, nonce
                ) VALUES
                    ('legacy-terminal', 'org-1', 'did:web:verifier.example', '{}'::jsonb,
                     'VERIFIED', jsonb_build_object(
                         'presentation_sha256', CAST(:terminal_digest AS TEXT)
                     ),
                     clock_timestamp(), clock_timestamp(), clock_timestamp() + interval '1 hour',
                     :duplicate_nonce),
                    ('legacy-pending-a', 'org-1', 'did:web:verifier.example', '{}'::jsonb,
                     'PENDING', '{}'::jsonb, clock_timestamp(), clock_timestamp(),
                     clock_timestamp() + interval '1 hour', :duplicate_nonce),
                    ('legacy-pending-b', 'org-1', 'did:web:verifier.example', '{}'::jsonb,
                     'PENDING', '{}'::jsonb, clock_timestamp(), clock_timestamp(),
                     clock_timestamp() + interval '1 hour', :duplicate_nonce),
                    ('legacy-in-progress', 'org-1', 'did:web:verifier.example', '{}'::jsonb,
                     'IN_PROGRESS', '{}'::jsonb, clock_timestamp(), clock_timestamp(),
                     clock_timestamp() + interval '1 hour', :in_progress_nonce),
                    ('legacy-invalid', 'org-1', 'did:web:verifier.example', '{}'::jsonb,
                     'PENDING', '{}'::jsonb, clock_timestamp(), clock_timestamp(),
                     clock_timestamp() + interval '1 hour', 'short'),
                    ('legacy-deadline', 'org-1', 'did:web:verifier.example', '{}'::jsonb,
                     'PENDING', '{}'::jsonb, clock_timestamp(), clock_timestamp(),
                     clock_timestamp() - interval '1 second', :deadline_nonce)
                """
            ),
            {
                "terminal_digest": terminal_digest,
                "duplicate_nonce": duplicate_nonce,
                "in_progress_nonce": "i" * 43,
                "deadline_nonce": "e" * 43,
            },
        )
    sync_engine.dispose()

    command.upgrade(config, "head")

    sync_engine = create_engine(sync_url)
    with sync_engine.connect() as connection:
        migrated = {
            row.id: row
            for row in connection.execute(
                text(
                    "SELECT id, status, nonce, submission_sha256 "
                    "FROM public.verification_sessions WHERE id LIKE 'legacy-%'"
                )
            )
        }
    sync_engine.dispose()
    assert migrated["legacy-terminal"].status == "VERIFIED"
    assert migrated["legacy-terminal"].nonce is None
    assert migrated["legacy-terminal"].submission_sha256 == terminal_digest
    for unsafe_id in (
        "legacy-pending-a",
        "legacy-pending-b",
        "legacy-in-progress",
        "legacy-invalid",
        "legacy-deadline",
    ):
        assert migrated[unsafe_id].status == "EXPIRED"
        assert migrated[unsafe_id].nonce is None

    async_engine = create_async_engine(database_url)
    sessions = async_sessionmaker(async_engine, expire_on_commit=False)

    async def create(session_id: str) -> VerificationSession:
        async with sessions() as database_session:
            return await PostgresVerificationRepository(database_session).create_session(
                VerificationSession(
                    id=session_id,
                    organization_id="org-1",
                    verifier_did="did:web:verifier.example",
                    presentation_definition={"id": "pd-1", "input_descriptors": []},
                    nonce=(f"{session_id}:" + ("n" * 43))[:43],
                ),
                600,
            )

    async def claim(
        session_id: str,
        digest: str,
        token: str,
    ) -> VerificationSubmissionClaim:
        async with sessions() as database_session:
            return await PostgresVerificationRepository(database_session).claim_submission(
                session_id,
                digest,
                token,
                60,
            )

    try:
        await create("race-session")
        digest = hashlib.sha256(b"header.payload.signature").hexdigest()
        first, second = await asyncio.gather(
            claim("race-session", digest, "worker-token-1"),
            claim("race-session", digest, "worker-token-2"),
        )
        states = {first.state, second.state}
        assert states == {SubmissionClaimState.CLAIMED, SubmissionClaimState.BUSY}
        winner = first if first.state is SubmissionClaimState.CLAIMED else second
        winner_token = (
            "worker-token-1" if first.state is SubmissionClaimState.CLAIMED else "worker-token-2"
        )
        loser_token = "worker-token-2" if winner_token == "worker-token-1" else "worker-token-1"
        assert winner.session is not None
        winner.session.verify(
            verified_claims={"role": "member"},
            method=VerificationMethod.JWT_VP,
            verification_evidence={
                "schema_version": 1,
                "overall_result": "PASS",
                "presentation_sha256": digest,
            },
        )

        async with sessions() as database_session:
            repository = PostgresVerificationRepository(database_session)
            stale = await repository.finalize_submission(
                winner.session,
                digest,
                loser_token,
            )
        assert stale.state is SubmissionClaimState.STALE

        async with sessions() as database_session:
            repository = PostgresVerificationRepository(database_session)
            finalized = await repository.finalize_submission(
                winner.session,
                digest,
                winner_token,
            )
        assert finalized.state is SubmissionClaimState.FINALIZED
        assert finalized.session is not None
        assert finalized.session.status is VerificationStatus.VERIFIED
        assert finalized.session.nonce is None

        async with async_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE public.verification_sessions "
                    "SET expires_at = clock_timestamp() - interval '1 second' "
                    "WHERE id = 'race-session'"
                )
            )
        same_digest = await claim("race-session", digest, "retry-token")
        different_digest = await claim(
            "race-session",
            hashlib.sha256(b"different").hexdigest(),
            "conflict-token",
        )
        assert same_digest.state is SubmissionClaimState.TERMINAL
        assert same_digest.session is not None
        assert same_digest.session.status is VerificationStatus.VERIFIED
        assert different_digest.state is SubmissionClaimState.CONFLICT

        await create("recovery-session")
        recovery_digest = hashlib.sha256(b"recovery").hexdigest()
        original = await claim(
            "recovery-session",
            recovery_digest,
            "original-token",
        )
        assert original.state is SubmissionClaimState.CLAIMED
        async with async_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE public.verification_sessions "
                    "SET processing_started_at = clock_timestamp() - interval '2 seconds', "
                    "processing_expires_at = clock_timestamp() - interval '1 second' "
                    "WHERE id = 'recovery-session'"
                )
            )
        recovered = await claim(
            "recovery-session",
            recovery_digest,
            "recovery-token",
        )
        assert recovered.state is SubmissionClaimState.CLAIMED
        assert recovered.session is not None
        recovered.session.fail(
            "Verification failed",
            method=VerificationMethod.JWT_VP,
            verification_evidence={
                "schema_version": 1,
                "overall_result": "FAIL",
                "presentation_sha256": recovery_digest,
            },
        )
        assert original.session is not None
        original.session.verify(
            verified_claims={"stale": True},
            method=VerificationMethod.JWT_VP,
            verification_evidence={
                "schema_version": 1,
                "overall_result": "PASS",
                "presentation_sha256": recovery_digest,
            },
        )
        async with sessions() as database_session:
            repository = PostgresVerificationRepository(database_session)
            stale_original = await repository.finalize_submission(
                original.session,
                recovery_digest,
                "original-token",
            )
            recovered_final = await repository.finalize_submission(
                recovered.session,
                recovery_digest,
                "recovery-token",
            )
        assert stale_original.state is SubmissionClaimState.STALE
        assert recovered_final.state is SubmissionClaimState.FINALIZED
        assert recovered_final.session is not None
        assert recovered_final.session.status is VerificationStatus.FAILED

        await create("expired-session")
        async with async_engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE public.verification_sessions "
                    "SET expires_at = clock_timestamp() - interval '1 second' "
                    "WHERE id = 'expired-session'"
                )
            )
        expired = await claim(
            "expired-session",
            hashlib.sha256(b"expired").hexdigest(),
            "expired-token",
        )
        assert expired.state is SubmissionClaimState.EXPIRED
        assert expired.session is not None
        assert expired.session.nonce is None
    finally:
        await async_engine.dispose()
