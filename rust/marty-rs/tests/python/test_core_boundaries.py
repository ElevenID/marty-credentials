"""First-party contracts for the exact pinned Marty core revision."""

import json

import pytest
from _marty_rs import (
    create_zk_age_verification,
    generate_issuer_metadata,
    sd_jwt_create_presentation,
    verify_mdoc_issuer,
    verify_vcdm_jwt,
)


def test_zk_request_requires_a_native_zk_enabled_verifier() -> None:
    with pytest.raises(NotImplementedError, match="native ZK-enabled verifier"):
        create_zk_age_verification(
            "did:example:verifier", "https://verifier.example.test/response"
        )


def test_core_metadata_advertises_only_es256_for_mdoc_proofs() -> None:
    metadata = json.loads(
        generate_issuer_metadata(
            "https://issuer.example.test",
            "Pinned core contract issuer",
            json.dumps(
                [
                    {
                        "id": "EmployeeCredential",
                        "name": "Employee credential",
                        "formats": ["mso_mdoc", "dc+sd-jwt"],
                        "doctype": "org.iso.18013.5.1.mDL",
                        "vct": "https://credentials.example.test/employee",
                    }
                ]
            ),
        )
    )
    configurations = metadata["credential_configurations_supported"]

    assert configurations["EmployeeCredential_mso_mdoc"]["proof_types_supported"]["jwt"][
        "proof_signing_alg_values_supported"
    ] == ["ES256"]
    assert configurations["EmployeeCredential_sd_jwt"]["proof_types_supported"]["jwt"][
        "proof_signing_alg_values_supported"
    ] == ["ES256", "EdDSA"]


def test_retained_sd_jwt_adapter_rejects_unimplemented_holder_binding() -> None:
    with pytest.raises(ValueError, match="holder-key-aware OID4VP flow"):
        sd_jwt_create_presentation("not-an-sd-jwt", [], "nonce", "audience")


def test_retained_vcdm_jwt_adapter_fails_closed_without_a_token() -> None:
    result = json.loads(verify_vcdm_jwt("{}"))

    assert result["valid"] is False
    assert result["claims"] is None
    assert result["errors"]


def test_retained_mdoc_issuer_adapter_preserves_failure_evidence() -> None:
    result = verify_mdoc_issuer(b"\xff", [])

    assert result.signature_valid is False
    assert result.issuer_trusted is False
    assert result.document_evidence == []
    assert result.revocation_checked is False
    assert result.not_revoked is None
    assert result.error
