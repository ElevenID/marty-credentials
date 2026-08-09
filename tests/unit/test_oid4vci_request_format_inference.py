"""Unit tests for OID4VCI credential request format inference."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_SERVICES = os.path.join(_REPO_ROOT, "services")
_PYTHON = os.path.join(_REPO_ROOT, "python")

for _path in (_SERVICES, _PYTHON):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from issuance.infrastructure.api.routes import (  # noqa: E402
    CredentialRequest,
    CredentialResponse,
    _credential_configuration_id_for_format,
    _credential_format_for_remote_context,
    _effective_request_format,
    _format_from_configuration_id,
)


def test_credential_request_model_exposes_only_final_selectors() -> None:
    request = CredentialRequest.model_validate({})

    assert request.credential_configuration_id is None
    assert request.credential_identifier is None
    assert not hasattr(request, "format")


def test_credential_request_accepts_only_canonical_proofs_object() -> None:
    request = CredentialRequest.model_validate(
        {
            "credential_configuration_id": "OpenBadge#sd-jwt",
            "proofs": {"jwt": ["header.payload.signature"]},
        }
    )

    assert request.proofs == {"jwt": ["header.payload.signature"]}


def test_credential_request_rejects_legacy_singular_proof() -> None:
    with pytest.raises(ValidationError, match="proof"):
        CredentialRequest.model_validate(
            {
                "credential_configuration_id": "OpenBadge#sd-jwt",
                "proof": {"proof_type": "jwt", "jwt": "header.payload.signature"},
            }
        )


def test_credential_request_ignores_unknown_extension_parameters() -> None:
    request = CredentialRequest.model_validate(
        {
            "credential_configuration_id": "OpenBadge#sd-jwt",
            "proofs": {"jwt": ["header.payload.signature"]},
            "official_conformance_extension": "ignored",
        }
    )

    assert request.credential_configuration_id == "OpenBadge#sd-jwt"
    assert request.proofs == {"jwt": ["header.payload.signature"]}


def test_removed_format_member_is_rejected() -> None:
    with pytest.raises(ValidationError, match="removed 'format'"):
        CredentialRequest.model_validate({"format": "vc+sd-jwt"})

    with pytest.raises(ValidationError, match="removed 'format'"):
        CredentialRequest.model_validate(
            {
                "credential_configuration_id": "OpenBadge#sd-jwt",
                "format": "jwt_vc_json",
            }
        )


def test_credential_response_has_only_the_final_object_array_shape() -> None:
    response = CredentialResponse(credentials=[{"credential": "encoded", "format": "dc+sd-jwt"}])

    assert response.model_dump(exclude_none=True) == {
        "credentials": [{"credential": "encoded", "format": "dc+sd-jwt"}]
    }
    assert "credential" not in CredentialResponse.model_json_schema()["properties"]


def test_configuration_id_infers_expected_protocol_format() -> None:
    assert _format_from_configuration_id("OpenBadge#sd-jwt") == "dc+sd-jwt"
    assert _format_from_configuration_id("OpenBadge#credential-manager") == "dc+sd-jwt"
    assert _format_from_configuration_id("OpenBadge#spruce-sd-jwt") is None
    assert _format_from_configuration_id("org.iso.18013.5.1.mDL#mdoc") == "mso_mdoc"
    assert _format_from_configuration_id("icaoCredential#vds-nc") == "vds_nc"
    assert _format_from_configuration_id("EmployeeCredential#ldp-vc") == "ldp_vc"


@pytest.mark.parametrize(
    ("payload_format", "expected_configuration_id"),
    [
        ("w3c_vcdm_v2_jwt_vc", "EmployeeCredential"),
        ("w3c_vcdm_v2_sd_jwt", "EmployeeCredential#sd-jwt"),
        ("w3c_vcdm_v2_di", "EmployeeCredential#ldp-vc"),
        ("mso_mdoc", "EmployeeCredential#mdoc"),
    ],
)
def test_offer_configuration_matches_template_representation(
    payload_format: str, expected_configuration_id: str
) -> None:
    assert (
        _credential_configuration_id_for_format("EmployeeCredential", payload_format)
        == expected_configuration_id
    )


def test_effective_request_format_prefers_configuration_id_when_wallet_omits_format() -> None:
    tx = SimpleNamespace(credential_payload_format="w3c_vcdm_v2_sd_jwt")
    request = CredentialRequest.model_validate(
        {"credential_configuration_id": "OpenBadge#credential-manager"}
    )

    assert _effective_request_format(request, tx) == "dc+sd-jwt"
    assert (
        _credential_format_for_remote_context(
            tx.credential_payload_format, _effective_request_format(request, tx)
        )
        == "dc+sd-jwt"
    )


def test_effective_request_format_falls_back_to_payload_format_for_standard_sd_jwt() -> None:
    tx = SimpleNamespace(credential_payload_format="w3c_vcdm_v2_sd_jwt")
    request = CredentialRequest.model_validate({"credential_configuration_id": "default"})

    assert _effective_request_format(request, tx) == "vc+sd-jwt"
    assert (
        _credential_format_for_remote_context(
            tx.credential_payload_format, _effective_request_format(request, tx)
        )
        == "dc+sd-jwt"
    )


def test_effective_request_format_still_defaults_to_jwt_vc_for_non_sd_payloads() -> None:
    tx = SimpleNamespace(credential_payload_format="w3c_vcdm_v2_jwt_vc")
    request = CredentialRequest.model_validate({"credential_configuration_id": "default"})

    assert _effective_request_format(request, tx) == "jwt_vc_json"
    assert (
        _credential_format_for_remote_context(
            tx.credential_payload_format, _effective_request_format(request, tx)
        )
        == "jwt_vc_json"
    )
