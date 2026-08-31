"""First-party contracts for the exact pinned Marty core revision."""

import json

import pytest
from _marty_rs import (
    create_verifiable_credential,
    generate_issuer_metadata,
    generate_p256_key,
)


def test_local_core_metadata_advertises_only_es256_for_mdoc_proofs() -> None:
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


def test_local_issuance_rejects_contradictory_jwk_algorithm_metadata() -> None:
    _, private_jwk_json = generate_p256_key()
    private_jwk = json.loads(private_jwk_json)
    private_jwk["alg"] = "EdDSA"
    private_scalar = private_jwk["d"]

    with pytest.raises(RuntimeError) as raised:
        create_verifiable_credential(
            "did:example:contract-issuer",
            json.dumps(private_jwk),
            "did:example:holder",
            "EmployeeCredential",
            json.dumps({"employee_id": "employee-123"}),
            "jwt_vc_json",
        )

    assert private_scalar not in str(raised.value)
