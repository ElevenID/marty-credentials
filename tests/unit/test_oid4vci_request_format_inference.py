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
    _credential_format_for_remote_context,
    _effective_request_format,
    _format_from_configuration_id,
    _requests_legacy_credential_alias,
)


def test_credential_request_format_defaults_to_none() -> None:
    request = CredentialRequest.model_validate({})

    assert request.format is None


def test_credential_request_accepts_only_canonical_proofs_object() -> None:
    request = CredentialRequest.model_validate({"proofs": {"jwt": ["header.payload.signature"]}})

    assert request.proofs == {"jwt": ["header.payload.signature"]}


def test_credential_request_rejects_legacy_singular_proof() -> None:
    with pytest.raises(ValidationError, match="proof"):
        CredentialRequest.model_validate({
            "proof": {"proof_type": "jwt", "jwt": "header.payload.signature"},
        })


def test_credential_request_ignores_unknown_extension_parameters() -> None:
    request = CredentialRequest.model_validate({
        "credential_configuration_id": "OpenBadge#sd-jwt",
        "proofs": {"jwt": ["header.payload.signature"]},
        "official_conformance_extension": "ignored",
    })

    assert request.credential_configuration_id == "OpenBadge#sd-jwt"
    assert request.proofs == {"jwt": ["header.payload.signature"]}


def test_only_explicit_legacy_format_requests_get_legacy_credential_alias() -> None:
    assert _requests_legacy_credential_alias(CredentialRequest.model_validate({"format": "vc+sd-jwt"}))
    assert not _requests_legacy_credential_alias(
        CredentialRequest.model_validate({"credential_configuration_id": "OpenBadge#sd-jwt"})
    )


def test_configuration_id_infers_expected_protocol_format() -> None:
    assert _format_from_configuration_id("OpenBadge#sd-jwt") == "dc+sd-jwt"
    assert _format_from_configuration_id("OpenBadge#credential-manager") == "dc+sd-jwt"
    assert _format_from_configuration_id("OpenBadge#spruce-sd-jwt") == "spruce-vc+sd-jwt"
    assert _format_from_configuration_id("org.iso.18013.5.1.mDL#mdoc") == "mso_mdoc"
    assert _format_from_configuration_id("icaoCredential#vds-nc") == "vds_nc"


def test_effective_request_format_prefers_configuration_id_when_wallet_omits_format() -> None:
    tx = SimpleNamespace(credential_payload_format="w3c_vcdm_v2_sd_jwt")
    request = CredentialRequest.model_validate({"credential_configuration_id": "OpenBadge#credential-manager"})

    assert _effective_request_format(request, tx) == "dc+sd-jwt"
    assert _credential_format_for_remote_context(tx.credential_payload_format, _effective_request_format(request, tx)) == "dc+sd-jwt"


def test_effective_request_format_falls_back_to_payload_format_for_standard_sd_jwt() -> None:
    tx = SimpleNamespace(credential_payload_format="w3c_vcdm_v2_sd_jwt")
    request = CredentialRequest.model_validate({})

    assert _effective_request_format(request, tx) == "vc+sd-jwt"
    assert _credential_format_for_remote_context(tx.credential_payload_format, _effective_request_format(request, tx)) == "dc+sd-jwt"


def test_effective_request_format_still_defaults_to_jwt_vc_for_non_sd_payloads() -> None:
    tx = SimpleNamespace(credential_payload_format="w3c_vcdm_v2_jwt_vc")
    request = CredentialRequest.model_validate({})

    assert _effective_request_format(request, tx) == "jwt_vc_json"
    assert _credential_format_for_remote_context(tx.credential_payload_format, _effective_request_format(request, tx)) == "jwt_vc_json"
