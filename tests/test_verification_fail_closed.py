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

from verification.application.canonical_result import _mapped_check  # noqa: E402
from verification.application.rust_verifier import RustCredentialVerifier  # noqa: E402


def test_adapter_mapping_does_not_invent_trust_or_status_from_valid() -> None:
    evidence: list[dict[str, str]] = []
    trust = _mapped_check(
        "issuer.trust",
        {"valid": True, "verified_claims": {"employee_id": "E-123"}},
        component_id="marty-credentials",
        evaluated_at="2026-08-11T00:00:00Z",
        evidence_records=evidence,
    )
    status = _mapped_check(
        "credential.status",
        {"valid": True},
        component_id="marty-credentials",
        evaluated_at="2026-08-11T00:00:00Z",
        evidence_records=evidence,
    )

    assert trust["outcome"] == "NOT_PERFORMED"
    assert status["outcome"] == "NOT_PERFORMED"
    assert evidence == []


def test_adapter_mapping_records_only_explicit_required_evidence() -> None:
    evidence: list[dict[str, str]] = []
    trust = _mapped_check(
        "issuer.trust",
        {"trust_chain_valid": True},
        component_id="marty-credentials",
        evaluated_at="2026-08-11T00:00:00Z",
        evidence_records=evidence,
    )
    status = _mapped_check(
        "credential.status",
        {"revocation_checked": True, "revocation_status": "VALID"},
        component_id="marty-credentials",
        evaluated_at="2026-08-11T00:00:00Z",
        evidence_records=evidence,
    )

    assert trust["outcome"] == "PASSED"
    assert status["outcome"] == "PASSED"
    assert [record["check_id"] for record in evidence] == [
        "issuer.trust",
        "credential.status",
    ]


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
            "valid": False,
            "signature_verified": True,
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
async def test_structural_verifier_requires_scoped_low_level_evidence() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = MagicMock()
    verifier.marty_rs.verify_presentation_structure.return_value = json.dumps(
        {
            "valid": False,
            "check_valid": True,
            "decision_ready": False,
            "scope": "presentation_structure",
            "evidence": {"presentation_structure": "passed"},
            "descriptor_results": [],
            "errors": [],
        }
    )
    verifier.verify_w3c_vc = AsyncMock(
        return_value={
            "valid": False,
            "signature_verified": True,
            "issuer_trusted": True,
            "claims": {"employee_id": "E-123"},
        }
    )

    result = await verifier.verify_presentation(
        presentation={
            "verifiableCredential": [{"id": "credential-1"}],
            "presentation_submission": {
                "id": "submission-1",
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
    assert result["cryptographic_valid"] is False
    assert result["credential_proofs_valid"] is True
    assert result["presentation_structure_valid"] is True
    assert "presentation_constraints_valid" not in result
    assert result["decision_ready"] is False
    assert result["trust_chain_valid"] is True
    assert result["revocation_checked"] is False


@pytest.mark.asyncio
async def test_structural_verifier_rejects_legacy_valid_only_result() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = MagicMock()
    verifier.marty_rs.verify_presentation_structure.return_value = json.dumps({"valid": True})
    verifier.verify_w3c_vc = AsyncMock(
        return_value={
            "valid": False,
            "signature_verified": True,
            "issuer_trusted": True,
            "claims": {},
        }
    )

    result = await verifier.verify_presentation(
        presentation={
            "verifiableCredential": [{"id": "credential-1"}],
            "presentation_submission": {
                "id": "submission-1",
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
    assert "evidence was incomplete" in result["error"]


@pytest.mark.asyncio
async def test_outer_jwt_proof_does_not_authenticate_embedded_claims() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = MagicMock()
    verifier.marty_rs.oid4vp_verify_vp_token.return_value = json.dumps(
        {
            "valid": False,
            "check_valid": True,
            "decision_ready": False,
            "scope": "presentation_proof",
            "evidence": {
                "presentation_proof": "passed",
                "transaction_binding": "passed",
            },
            "errors": [],
        }
    )
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
    assert "credential_proofs_valid" not in result
    assert result["claims"] == []


@pytest.mark.asyncio
async def test_outer_jwt_rejects_incomplete_low_level_evidence() -> None:
    verifier = RustCredentialVerifier.__new__(RustCredentialVerifier)
    verifier.marty_rs = MagicMock()
    verifier.marty_rs.oid4vp_verify_vp_token.return_value = json.dumps(
        {
            "valid": False,
            "check_valid": True,
            "decision_ready": False,
            "scope": "presentation_proof",
            "evidence": {"presentation_proof": "passed"},
            "errors": [],
        }
    )

    result = await verifier.verify_jwt_vp(
        "header.payload.signature",
        expected_audience="did:web:verifier.example",
        expected_nonce="nonce-1",
    )

    assert result["valid"] is False
    assert "evidence was incomplete" in result["error"]
