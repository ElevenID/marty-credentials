"""Exact credential-issuer audience validation for OID4VCI proof JWTs."""

from __future__ import annotations

import base64
import json


def allowed_credential_issuer_audience_paths(
    organization_id: str,
) -> tuple[str, ...]:
    """Return the exact credential issuer paths supported for one tenant."""
    issuer_path = f"/org/{organization_id}"
    return (
        issuer_path,
        f"{issuer_path}/credential-manager",
        f"{issuer_path}/apple-wallet",
        f"{issuer_path}/waltid",
    )


def allowed_credential_issuer_audiences(
    issuer_base_url: str,
    organization_id: str,
) -> tuple[str, ...]:
    """Return the exact credential issuer URLs supported for one tenant."""
    return tuple(
        f"{issuer_base_url}{path}"
        for path in allowed_credential_issuer_audience_paths(organization_id)
    )


def match_credential_issuer_audience(
    audience: object,
    *,
    issuer_base_url: str,
    organization_id: str,
) -> str | None:
    """Return an exact configured issuer audience, rejecting URL lookalikes."""
    if not isinstance(audience, str):
        return None
    if audience not in allowed_credential_issuer_audiences(
        issuer_base_url,
        organization_id,
    ):
        return None
    return audience


def unverified_proof_audience(proof_jwt: str) -> object:
    """Decode only the audience needed to select the verifier's exact expectation.

    The returned claim is untrusted. Callers must allow-list it with
    :func:`match_credential_issuer_audience` and then pass the exact result to
    the cryptographic proof verifier.
    """
    try:
        parts = proof_jwt.split(".")
        if len(parts) != 3:
            raise ValueError("proof JWT must contain three segments")
        padding = "=" * (-len(parts[1]) % 4)
        payload: object = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
    except ValueError as exc:
        raise ValueError("Could not decode proof JWT audience") from exc
    if not isinstance(payload, dict):
        raise ValueError("Could not decode proof JWT audience")
    audience: object = payload.get("aud")
    return audience
