import base64
import json
import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest

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

from verification.application.rust_verifier import RustCredentialVerifier  # noqa: E402
from verification.application.service import reduce_verification_result  # noqa: E402


def test_reducer_does_not_invent_trust_or_revocation_from_valid() -> None:
    result = reduce_verification_result(
        {"valid": True, "verified_claims": {"employee_id": "E-123"}}
    )

    assert result["valid"] is False
    assert result["overall_result"] == "FAIL"
    assert result["cryptographic_valid"] is True
    assert result["trust_chain_valid"] is False
    assert result["revocation_checked"] is False
    assert result["revocation_status"] == "SKIPPED"
    assert result["verified_claims"] == {}


def test_reducer_passes_only_with_all_required_evidence() -> None:
    result = reduce_verification_result(
        {
            "valid": True,
            "cryptographic_valid": True,
            "trust_chain_valid": True,
            "revocation_checked": True,
            "revocation_status": "VALID",
            "verified_claims": {"employee_id": "E-123"},
        }
    )

    assert result["valid"] is True
    assert result["overall_result"] == "PASS"
    assert result["verified_claims"] == {"employee_id": "E-123"}


@pytest.mark.asyncio
async def test_empty_structured_presentation_fails_closed() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = MagicMock()

    result = await verifier.verify_presentation(
        presentation={"verifiableCredential": []},
        presentation_definition={
            "id": "pd-1",
            "input_descriptors": [{"id": "employee"}],
        },
        verifier_did="did:web:verifier.example",
        organization_id="org-1",
    )

    assert result["valid"] is False
    assert "no verifiable credentials" in result["error"].lower()


@pytest.mark.asyncio
async def test_missing_presentation_submission_fails_closed() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = MagicMock()

    result = await verifier.verify_presentation(
        presentation={"verifiableCredential": [{"id": "credential-1"}]},
        presentation_definition={
            "id": "pd-1",
            "input_descriptors": [{"id": "employee"}],
        },
        verifier_did="did:web:verifier.example",
        organization_id="org-1",
    )

    assert result["valid"] is False
    assert "submission is required" in result["error"].lower()


@pytest.mark.asyncio
async def test_structural_verifier_error_is_fatal() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = MagicMock()
    verifier.marty_rs.verify_presentation_structure.side_effect = RuntimeError(
        "binding unavailable"
    )
    verifier.verify_w3c_vc = AsyncMock(
        return_value={
            "valid": True,
            "issuer_trusted": True,
            "claims": {"employee_id": "E-123"},
        }
    )

    result = await verifier.verify_presentation(
        presentation={
            "verifiableCredential": [{"id": "credential-1"}],
            "presentation_submission": {
                "definition_id": "pd-1",
                "descriptor_map": [],
            },
        },
        presentation_definition={
            "id": "pd-1",
            "input_descriptors": [{"id": "employee"}],
        },
        verifier_did="did:web:verifier.example",
        organization_id="org-1",
    )

    assert result["valid"] is False
    assert "structure verification failed" in result["error"].lower()


@pytest.mark.asyncio
async def test_outer_jwt_proof_does_not_authenticate_embedded_claims() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = MagicMock()
    verifier.marty_rs.verify_vp_token_jwt.return_value = json.dumps({"valid": True})
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "iss": "did:example:holder",
                    "vp": {"verifiableCredential": [{"credentialSubject": {"admin": True}}]},
                }
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    token = f"header.{payload}.signature"

    result = await verifier.verify_jwt_vp(
        token,
        expected_audience="did:web:verifier.example",
        expected_nonce="nonce-1",
    )

    assert result["valid"] is False
    assert result["presentation_proof_valid"] is True
    assert result["credential_proofs_valid"] is False
    assert result["claims"] == []
