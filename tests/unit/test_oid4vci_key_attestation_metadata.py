from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException
from issuance import main
from issuance.infrastructure.api import signing_context


@pytest.mark.asyncio
async def test_metadata_publishes_resolved_required_key_attestation_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def resolve(organization_id: str, **kwargs: Any) -> dict[str, Any]:
        captured["organization_id"] = organization_id
        captured.update(kwargs)
        return {
            "organization_id": organization_id,
            "issuer_profile": {
                "organization_id": organization_id,
                "key_attestation_policy": {
                    "mode": "required",
                    "required_key_storage": ["iso_18045_high"],
                    "required_user_authentication": ["iso_18045_moderate"],
                },
            },
        }

    monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", resolve)

    proof_types = await main._oid4vci_proof_types_for_org(
        "org-a",
        credential_format="dc+sd-jwt",
    )

    assert captured == {
        "organization_id": "org-a",
        "credential_format": "dc+sd-jwt",
        "key_purpose": "vc_jwt_issuer",
    }
    assert proof_types == {
        "jwt": {
            "proof_signing_alg_values_supported": ["ES256", "EdDSA"],
            "key_attestations_required": {
                "key_storage": ["iso_18045_high"],
                "user_authentication": ["iso_18045_moderate"],
            },
        }
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["disabled", "optional"])
async def test_metadata_does_not_claim_optional_attestation_is_required(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    async def resolve(_organization_id: str, **_kwargs: Any) -> dict[str, Any]:
        return {
            "issuer_profile": {
                "key_attestation_policy": {
                    "mode": mode,
                    "required_key_storage": ["iso_18045_high"],
                }
            }
        }

    monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", resolve)

    proof_types = await main._oid4vci_proof_types_for_org(
        "org-a",
        credential_format="mso_mdoc",
    )

    assert "key_attestations_required" not in proof_types["jwt"]


@pytest.mark.asyncio
async def test_metadata_fails_closed_when_profile_policy_cannot_be_resolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve(_organization_id: str, **_kwargs: Any) -> None:
        raise RuntimeError("ambiguous issuer profiles")

    monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", resolve)

    with pytest.raises(HTTPException) as error:
        await main._oid4vci_proof_types_for_org(
            "org-a",
            credential_format="dc+sd-jwt",
        )

    assert error.value.status_code == 503
    assert error.value.detail == "Issuer proof policy is temporarily unavailable"
