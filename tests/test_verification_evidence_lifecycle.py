from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
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

from verification.application.service import VerificationService
from verification.domain.entities import VerificationSession, VerificationStatus
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
        nonce="nonce-1",
    )


@pytest.mark.asyncio
async def test_success_persists_claim_free_evidence_without_raw_presentation() -> None:
    session = _pending_session()
    repository = MagicMock()
    repository.get_by_id = AsyncMock(return_value=session)
    repository.save_session = AsyncMock()
    verifier = MagicMock()
    verifier.verify_presentation = AsyncMock(
        return_value={
            "valid": True,
            "cryptographic_valid": True,
            "trust_chain_valid": True,
            "revocation_checked": True,
            "revocation_status": "VALID",
            "verified_claims": {"employee_id": "sensitive-employee-id"},
        }
    )
    presentation = {
        "verifiableCredential": [{"credentialSubject": {"employee_id": "sensitive-employee-id"}}]
    }

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
        "verification_method": "w3c_vc",
        "presentation_sha256": result.verification_evidence["presentation_sha256"],
        "evaluated_at": result.verification_evidence["evaluated_at"],
    }
    serialized_evidence = json.dumps(result.verification_evidence)
    assert "sensitive-employee-id" not in serialized_evidence
    assert "verifiableCredential" not in serialized_evidence
    assert len(result.verification_evidence["presentation_sha256"]) == 64
    assert repository.save_session.await_count == 2


@pytest.mark.asyncio
async def test_failed_decision_persists_negative_evidence() -> None:
    session = _pending_session()
    repository = MagicMock()
    repository.get_by_id = AsyncMock(return_value=session)
    repository.save_session = AsyncMock()
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
    repository = MagicMock()
    repository.get_by_id = AsyncMock(return_value=session)
    repository.save_session = AsyncMock()
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
async def test_postgres_adapter_round_trips_evidence_and_redacts_legacy_raw_data() -> None:
    database_session = MagicMock()
    database_session.get = AsyncMock(return_value=None)
    database_session.commit = AsyncMock()
    entity = _pending_session()
    entity.verification_evidence = {
        "schema_version": 1,
        "overall_result": "FAIL",
        "presentation_sha256": "a" * 64,
    }
    entity.presentation_data = {"legacy": "raw-credential"}

    repository = PostgresVerificationRepository(database_session)
    await repository.save_session(entity)

    model = database_session.add.call_args.args[0]
    assert isinstance(model, VerificationSessionModel)
    assert model.presentation_data is None
    assert model.verification_evidence == entity.verification_evidence

    model.presentation_data = {"legacy": "raw-credential"}
    restored = repository._to_entity(model)
    assert restored.presentation_data is None
    assert restored.verification_evidence == entity.verification_evidence


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


def test_verification_image_contains_migration_runtime() -> None:
    dockerfile = (ROOT / "services" / "verification" / "Dockerfile").read_text(encoding="utf-8")

    assert "alembic==" in dockerfile
    assert "psycopg[binary]==" in dockerfile
