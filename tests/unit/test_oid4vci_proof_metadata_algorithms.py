from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from issuance import main
from issuance.infrastructure.api import signing_context

_ES256_ONLY = ["ES256"]
_ES256_AND_EDDSA = ["ES256", "EdDSA"]


class _MetadataRepository:
    def __init__(
        self,
        *,
        type_formats: list[tuple[str, list[str]]],
        display_metadata: dict[str, dict[str, Any]],
    ) -> None:
        self._type_formats = type_formats
        self._display_metadata = display_metadata

    async def get_credential_types_for_org(self, _organization_id: str) -> list[str]:
        return [credential_type for credential_type, _formats in self._type_formats]

    async def get_credential_type_formats_for_org(
        self, _organization_id: str
    ) -> list[tuple[str, list[str]]]:
        return self._type_formats

    async def get_credential_display_metadata_for_org(
        self, _organization_id: str
    ) -> dict[str, dict[str, Any]]:
        return self._display_metadata


def _proof_algorithms(configuration: dict[str, Any]) -> list[str]:
    return configuration["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"]


def _key_attestation_requirement(configuration: dict[str, Any]) -> dict[str, list[str]]:
    return configuration["proof_types_supported"]["jwt"]["key_attestations_required"]


def test_root_metadata_advertises_format_specific_proof_algorithms(
    monkeypatch,
) -> None:
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")

    response = TestClient(main.create_app()).get("/.well-known/openid-credential-issuer")

    assert response.status_code == 200
    configurations = response.json()["credential_configurations_supported"]
    assert _proof_algorithms(configurations["default#mdoc"]) == _ES256_ONLY
    assert _proof_algorithms(configurations["default"]) == _ES256_AND_EDDSA
    assert _proof_algorithms(configurations["default#credential-manager"]) == _ES256_AND_EDDSA
    assert _proof_algorithms(configurations["default#ldp-vc"]) == _ES256_AND_EDDSA
    assert {
        configuration_id: configuration["credential_signing_alg_values_supported"]
        for configuration_id, configuration in configurations.items()
    } == {
        "default": ["ES256", "EdDSA"],
        "default#credential-manager": ["ES256", "EdDSA"],
        "default#ldp-vc": ["eddsa-rdfc-2022"],
        "default#mdoc": [-7, -8],
    }
    assert all(
        _key_attestation_requirement(configuration) == {}
        for configuration in configurations.values()
    )


def test_bound_tenant_metadata_preserves_attestation_and_signing_algorithms(
    monkeypatch,
) -> None:
    issuer_did = "did:web:issuer.example:orgs:org-a"
    requirement = {
        "key_storage": ["iso_18045_high"],
        "user_authentication": ["iso_18045_moderate"],
    }
    resolver_calls: list[dict[str, Any]] = []
    repository = _MetadataRepository(
        type_formats=[("EmployeeBadge", ["sd_jwt_vc", "mso_mdoc"])],
        display_metadata={"EmployeeBadge": {"issuer_did": issuer_did}},
    )

    async def resolve(organization_id: str, **kwargs: Any) -> dict[str, Any]:
        resolver_calls.append({"organization_id": organization_id, **kwargs})
        return {
            "issuer_profile": {
                "key_attestation_policy": {
                    "mode": "required",
                    "required_key_storage": requirement["key_storage"],
                    "required_user_authentication": requirement["user_authentication"],
                }
            }
        }

    monkeypatch.setattr(main, "_repo", repository)
    monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", resolve)
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")

    response = TestClient(main.create_app()).get("/.well-known/openid-credential-issuer/org/org-a")

    assert response.status_code == 200
    configurations = response.json()["credential_configurations_supported"]
    mdoc = configurations["EmployeeBadge#mdoc"]
    sd_jwt = configurations["EmployeeBadge#sd-jwt"]
    assert _proof_algorithms(mdoc) == _ES256_ONLY
    assert _proof_algorithms(sd_jwt) == _ES256_AND_EDDSA
    assert _key_attestation_requirement(mdoc) == requirement
    assert _key_attestation_requirement(sd_jwt) == requirement
    assert mdoc["credential_signing_alg_values_supported"] == [-7, -8]
    assert sd_jwt["credential_signing_alg_values_supported"] == ["ES256", "EdDSA"]
    assert resolver_calls == [
        {
            "organization_id": "org-a",
            "issuer_did": issuer_did,
            "credential_format": "dc+sd-jwt",
            "key_purpose": "vc_jwt_issuer",
        },
        {
            "organization_id": "org-a",
            "issuer_did": issuer_did,
            "credential_format": "mso_mdoc",
            "key_purpose": "mdoc_dsc",
        },
    ]


def test_tenant_metadata_without_issuer_uses_format_specific_unbound_fallback(
    monkeypatch,
) -> None:
    repository = _MetadataRepository(
        type_formats=[("EmployeeBadge", ["sd_jwt_vc", "mso_mdoc"])],
        display_metadata={"EmployeeBadge": {}},
    )

    async def unexpected_resolve(_organization_id: str, **_kwargs: Any) -> None:
        raise AssertionError("unbound metadata must not resolve an issuer profile")

    monkeypatch.setattr(main, "_repo", repository)
    monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", unexpected_resolve)
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")

    response = TestClient(main.create_app()).get("/.well-known/openid-credential-issuer/org/org-a")

    assert response.status_code == 200
    configurations = response.json()["credential_configurations_supported"]
    mdoc = configurations["EmployeeBadge#mdoc"]
    sd_jwt = configurations["EmployeeBadge#sd-jwt"]
    assert _proof_algorithms(mdoc) == _ES256_ONLY
    assert _proof_algorithms(sd_jwt) == _ES256_AND_EDDSA
    assert _key_attestation_requirement(mdoc) == {}
    assert _key_attestation_requirement(sd_jwt) == {}
    assert mdoc["credential_signing_alg_values_supported"] == [-7, -8]
    assert sd_jwt["credential_signing_alg_values_supported"] == ["ES256", "EdDSA"]


def test_apple_metadata_uses_es256_proofs_for_iso_and_non_iso_mdoc(
    monkeypatch,
) -> None:
    requirement = {"key_storage": ["iso_18045_high"]}
    resolver_calls: list[dict[str, Any]] = []
    repository = _MetadataRepository(
        type_formats=[
            ("EmployeeBadge", ["sd_jwt_vc"]),
            ("org.iso.18013.5.1.mDL", ["mso_mdoc"]),
        ],
        display_metadata={"EmployeeBadge": {}, "org.iso.18013.5.1.mDL": {}},
    )

    async def resolve(organization_id: str, **kwargs: Any) -> dict[str, Any]:
        resolver_calls.append({"organization_id": organization_id, **kwargs})
        return {
            "issuer_profile": {
                "key_attestation_policy": {
                    "mode": "required",
                    "required_key_storage": requirement["key_storage"],
                    "required_user_authentication": [],
                }
            }
        }

    monkeypatch.setattr(main, "_repo", repository)
    monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", resolve)
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")

    response = TestClient(main.create_app()).get(
        "/.well-known/openid-credential-issuer/org/org-a/apple-wallet"
    )

    assert response.status_code == 200
    configurations = response.json()["credential_configurations_supported"]
    assert set(configurations) == {
        "EmployeeBadge#apple-wallet",
        "org.iso.18013.5.1.mDL#apple-wallet",
    }
    for configuration in configurations.values():
        assert configuration["format"] == "mso_mdoc"
        assert _proof_algorithms(configuration) == _ES256_ONLY
        assert _key_attestation_requirement(configuration) == requirement
        assert configuration["credential_signing_alg_values_supported"] == [-7, -8]
    assert resolver_calls == [
        {
            "organization_id": "org-a",
            "issuer_did": None,
            "credential_format": "mso_mdoc",
            "key_purpose": "mdoc_dsc",
        }
    ]
