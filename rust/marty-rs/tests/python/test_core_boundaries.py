"""First-party contracts for the exact pinned Marty core revision."""

import json

import pytest
from _marty_rs import (
    create_presentation_definition,
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


@pytest.mark.parametrize(
    "record",
    [
        pytest.param(None, id="null-record"),
        pytest.param(12, id="numeric-record"),
        pytest.param("jwt_vc_json", id="string-record"),
        pytest.param([], id="array-record"),
    ],
)
def test_issuer_metadata_rejects_non_object_records(record: object) -> None:
    with pytest.raises(ValueError, match="Each credential type must be a JSON object"):
        generate_issuer_metadata(
            "https://issuer.example.test",
            "Pinned core contract issuer",
            json.dumps([record]),
        )


@pytest.mark.parametrize(
    "format_fields",
    [
        pytest.param({"format": "typo"}, id="unknown-single-format"),
        pytest.param({"format": 12}, id="numeric-single-format"),
        pytest.param({"format": None}, id="null-single-format"),
        pytest.param({"formats": ["jwt_vc_json", "typo"]}, id="unknown-array-format"),
        pytest.param({"formats": ["jwt_vc_json", 12]}, id="numeric-array-format"),
        pytest.param({"formats": []}, id="empty-format-array"),
        pytest.param({"formats": "jwt_vc_json"}, id="string-format-array"),
        pytest.param({"formats": None}, id="null-format-array"),
    ],
)
def test_issuer_metadata_rejects_explicit_invalid_formats(
    format_fields: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="Credential formats must be"):
        generate_issuer_metadata(
            "https://issuer.example.test",
            "Pinned core contract issuer",
            json.dumps([{"id": "example", **format_fields}]),
        )


def test_issuer_metadata_defaults_only_when_format_is_omitted() -> None:
    metadata = json.loads(
        generate_issuer_metadata(
            "https://issuer.example.test",
            "Pinned core contract issuer",
            json.dumps([{"id": "example"}]),
        )
    )

    configurations = metadata["credential_configurations_supported"]
    assert set(configurations) == {"example"}
    assert configurations["example"]["format"] == "jwt_vc_json"


@pytest.mark.parametrize("format_field", ["format", "formats"])
@pytest.mark.parametrize(
    ("alias", "expected"),
    [
        ("jwt_vc_json", "jwt_vc_json"),
        ("jwt_vc", "jwt_vc_json"),
        ("dc+sd-jwt", "dc+sd-jwt"),
        ("spruce-vc+sd-jwt", "dc+sd-jwt"),
        ("vc+sd-jwt", "dc+sd-jwt"),
        ("sd_jwt", "dc+sd-jwt"),
        ("sd-jwt", "dc+sd-jwt"),
        ("mso_mdoc", "mso_mdoc"),
        ("mdoc", "mso_mdoc"),
        ("zk_mdoc", "zk_mdoc"),
        ("zk-mdoc", "zk_mdoc"),
        ("zkp_mdoc", "zk_mdoc"),
        ("vds_nc", "vds_nc"),
        ("vds-nc", "vds_nc"),
        ("VDS-NC", "vds_nc"),
    ],
)
def test_issuer_metadata_preserves_supported_aliases(
    format_field: str, alias: str, expected: str
) -> None:
    value = [alias] if format_field == "formats" else alias
    metadata = json.loads(
        generate_issuer_metadata(
            "https://issuer.example.test",
            "Pinned core contract issuer",
            json.dumps([{"id": "example", format_field: value}]),
        )
    )

    configurations = metadata["credential_configurations_supported"]
    assert len(configurations) == 1
    assert next(iter(configurations.values()))["format"] == expected


def test_issuer_metadata_preserves_multiple_formats() -> None:
    metadata = json.loads(
        generate_issuer_metadata(
            "https://issuer.example.test",
            "Pinned core contract issuer",
            json.dumps(
                [
                    {
                        "id": "example",
                        "formats": ["jwt_vc_json", "sd_jwt"],
                        "vct": "urn:example:credential",
                    }
                ]
            ),
        )
    )

    configurations = metadata["credential_configurations_supported"]
    assert set(configurations) == {"example", "example_sd_jwt"}
    assert configurations["example"]["format"] == "jwt_vc_json"
    assert configurations["example_sd_jwt"]["format"] == "dc+sd-jwt"
    assert configurations["example_sd_jwt"]["vct"] == "urn:example:credential"


@pytest.mark.parametrize("format_args", [{}, {"credential_format": "mso_mdoc"}])
def test_presentation_definition_preserves_mdl_fields(
    format_args: dict[str, str],
) -> None:
    definition = json.loads(
        create_presentation_definition(
            verifier_id="did:example:verifier",
            response_uri="https://verifier.example.test/response",
            requested_fields=["age_over_18", "family_name"],
            **format_args,
        )
    )

    assert len(definition["input_descriptors"]) == 1
    descriptor = definition["input_descriptors"][0]
    assert set(descriptor["format"]) == {"mso_mdoc"}
    assert [field["path"] for field in descriptor["constraints"]["fields"]] == [
        ["$.org\\.iso\\.18013\\.5\\.1.age_over_18"],
        ["$.org\\.iso\\.18013\\.5\\.1.family_name"],
    ]


@pytest.mark.parametrize("credential_format", ["jwt_vc_json", "sd_jwt", "unknown", ""])
def test_presentation_definition_rejects_unsupported_formats(
    credential_format: str,
) -> None:
    with pytest.raises(ValueError, match="only supports mso_mdoc"):
        create_presentation_definition(
            "did:example:verifier",
            "https://verifier.example.test/response",
            ["age_over_18"],
            credential_format,
        )


def test_presentation_definition_rejects_unavailable_zk_capability() -> None:
    with pytest.raises(NotImplementedError, match="native ZK-enabled verifier"):
        create_presentation_definition(
            "did:example:verifier",
            "https://verifier.example.test/response",
            ["age_over_18"],
            "zk_mdoc",
        )
