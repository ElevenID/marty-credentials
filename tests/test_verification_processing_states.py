from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from verification.application import rust_verifier
from verification.application.canonical_result import adapter_processing_status
from verification.application.rust_verifier import RustCredentialVerifier
from verification.application.service import VerificationService
from verification.domain.entities import (
    SubmissionClaimState,
    VerificationSession,
    VerificationSubmissionClaim,
)
from verification.infrastructure.api import routes


@pytest.mark.parametrize(
    "processing_status",
    ["COMPLETED", "UNSUPPORTED", "UNAVAILABLE", "ERROR"],
)
def test_adapter_processing_status_preserves_every_canonical_state(
    processing_status: str,
) -> None:
    assert adapter_processing_status({"processing_status": processing_status}) == processing_status


def test_adapter_processing_status_keeps_legacy_completed_default() -> None:
    assert adapter_processing_status({"valid": False}) == "COMPLETED"


@pytest.mark.parametrize("processing_status", ["completed", "UNKNOWN", True, 1, []])
def test_adapter_processing_status_rejects_malformed_state(processing_status: object) -> None:
    assert adapter_processing_status({"processing_status": processing_status}) == "ERROR"


def test_explicit_processing_error_overrides_conflicting_completed_state() -> None:
    assert (
        adapter_processing_status({"processing_status": "COMPLETED", "processing_error": True})
        == "ERROR"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "processing_status",
    ["COMPLETED", "UNSUPPORTED", "UNAVAILABLE", "ERROR"],
)
async def test_direct_service_preserves_adapter_processing_state(
    monkeypatch: pytest.MonkeyPatch,
    processing_status: str,
) -> None:
    verifier = SimpleNamespace(
        verify_jwt_vp=AsyncMock(
            return_value={"valid": False, "processing_status": processing_status}
        )
    )
    governance = MagicMock()
    governance.trust_profile.trusted_issuers = ()
    governance.trust_profile.allow_public_did_fallback = False
    governance.organization_id = "123e4567-e89b-42d3-a456-426614174000"
    observed: dict[str, object] = {}

    def build_result(**kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        return {"canonical_result": {"processing_status": processing_status}}

    monkeypatch.setattr(
        "verification.application.service.build_canonical_result",
        build_result,
    )

    await VerificationService(MagicMock(), verifier).verify_presentation_direct(
        presentation="header.payload.signature",
        presentation_definition={"id": "definition-1"},
        verifier_did="did:web:verifier.example",
        governance=governance,
    )

    assert observed["processing_status"] == processing_status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "processing_status",
    ["COMPLETED", "UNSUPPORTED", "UNAVAILABLE", "ERROR"],
)
async def test_session_service_preserves_adapter_processing_state(
    monkeypatch: pytest.MonkeyPatch,
    processing_status: str,
) -> None:
    organization_id = "123e4567-e89b-42d3-a456-426614174000"
    session = VerificationSession(
        id="session-1",
        organization_id=organization_id,
        verifier_did="did:web:verifier.example",
        presentation_definition={"id": "definition-1", "input_descriptors": []},
        verification_evidence={},
        nonce="nonce-1",
    )
    repository = MagicMock()
    repository.claim_submission = AsyncMock(
        return_value=VerificationSubmissionClaim(
            SubmissionClaimState.CLAIMED,
            session=session,
            verifier_nonce=session.nonce,
        )
    )
    repository.finalize_submission = AsyncMock(
        return_value=VerificationSubmissionClaim(
            SubmissionClaimState.FINALIZED,
            session=session,
        )
    )
    verifier = SimpleNamespace(
        verify_jwt_vp=AsyncMock(
            return_value={"valid": False, "processing_status": processing_status}
        )
    )
    governance = MagicMock()
    governance.organization_id = organization_id
    registry = MagicMock()
    registry.resume_session.return_value = governance
    observed: dict[str, object] = {}

    def build_result(**kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        decision = "FAIL" if processing_status == "COMPLETED" else "INDETERMINATE"
        return {
            "schema_version": 2,
            "canonical_result": {
                "valid": False,
                "decision": decision,
                "processing_status": processing_status,
            },
            "evidence_records": [],
        }

    monkeypatch.setattr("verification.application.service.load_governance", lambda: registry)
    monkeypatch.setattr("verification.application.service.build_canonical_result", build_result)

    await VerificationService(repository, verifier).submit_presentation(
        session.id,
        "header.payload.signature",
    )

    assert observed["processing_status"] == processing_status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "processing_status",
    ["COMPLETED", "UNSUPPORTED", "UNAVAILABLE", "ERROR"],
)
async def test_vds_route_preserves_adapter_processing_state(
    monkeypatch: pytest.MonkeyPatch,
    processing_status: str,
) -> None:
    organization_id = "123e4567-e89b-42d3-a456-426614174000"
    issuer_did = "did:web:issuer.example"
    verification_method_id = f"{issuer_did}#key-1"
    governance = MagicMock()
    governance.organization_id = organization_id
    governance.trust_profile.trusted_issuers = (issuer_did,)
    governance.trust_profile.allow_public_did_fallback = False
    verifier = SimpleNamespace(
        verify_vds_nc=AsyncMock(
            return_value={"valid": False, "processing_status": processing_status}
        )
    )
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        routes,
        "resolve_issuer_did",
        AsyncMock(return_value={"public_jwk": {"kty": "EC"}}),
    )

    def build_result(**kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        return {"canonical_result": {"valid": False}}

    monkeypatch.setattr(routes, "build_canonical_result", build_result)
    monkeypatch.setattr(routes, "_verification_result", lambda evidence, **_kwargs: evidence)

    await routes.verify_vds_nc_barcode(
        routes.VerifyVdsNcRequest(
            barcode="header~payload~signature",
            issuer_did=issuer_did,
            verification_method_id=verification_method_id,
            algorithm="ES256",
        ),
        verifier=verifier,
        governance=governance,
    )

    assert observed["processing_status"] == processing_status


@pytest.mark.asyncio
async def test_missing_native_credential_verifier_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = SimpleNamespace()
    monkeypatch.setattr(
        rust_verifier,
        "resolve_issuer_did",
        AsyncMock(
            return_value={
                "did_document": {"id": "did:example:issuer"},
                "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
                "verification_method_id": "did:example:issuer#key-1",
            }
        ),
    )
    monkeypatch.setattr(
        rust_verifier,
        "extract_credential_verification_method",
        lambda _credential: "did:example:issuer#key-1",
    )

    result = await verifier.verify_w3c_vc(
        {
            "issuer": "did:example:issuer",
            "proof": {"verificationMethod": "did:example:issuer#key-1"},
        },
        verifier_did="did:web:verifier.example",
        trusted_issuers=["did:example:issuer"],
        organization_id="123e4567-e89b-42d3-a456-426614174000",
    )

    assert result["valid"] is False
    assert result["processing_status"] == "UNAVAILABLE"


@pytest.mark.asyncio
async def test_unsupported_embedded_credential_preserves_unsupported_state() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = SimpleNamespace()

    result = await verifier.verify_presentation(
        presentation={
            "verifiableCredential": ["compact-credential"],
            "presentation_submission": {
                "id": "submission-1",
                "definition_id": "definition-1",
                "descriptor_map": [],
            },
        },
        presentation_definition={
            "id": "definition-1",
            "input_descriptors": [{"id": "credential-1"}],
        },
        verifier_did="did:web:verifier.example",
    )

    assert result["valid"] is False
    assert result["processing_status"] == "UNSUPPORTED"


@pytest.mark.asyncio
async def test_native_processing_exception_preserves_error_state() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)

    def fail_processing(*_args: object) -> str:
        raise RuntimeError("native processing failed")

    verifier.marty_rs = SimpleNamespace(oid4vp_verify_vp_token=fail_processing)

    result = await verifier.verify_jwt_vp(
        "header.payload.signature",
        expected_audience="did:web:verifier.example",
        expected_nonce="nonce-1",
    )

    assert result["valid"] is False
    assert result["processing_status"] == "ERROR"
