"""Capability-gated ICAO eMRTD signing adapter."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import HTTPException


async def require_managed_issuer_identity(organization_id: str, issuer_did: str) -> None:
    """Reject a foreign or inactive DSC selector before storing a rollback job."""
    base_url = os.environ.get("SIGNING_KEYS_INTERNAL_URL", "").strip().rstrip("/")
    key_file = os.environ.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE", "").strip()
    if not base_url or not key_file:
        raise HTTPException(
            status_code=503, detail="Managed passport issuer resolver is unavailable"
        )
    try:
        key = Path(key_file).read_text(encoding="ascii").strip()
        if len(key) < 32:
            raise ValueError("internal key is invalid")
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.post(
                f"{base_url}/compat/resolve-issuer-did",
                json={
                    "organization_id": organization_id,
                    "issuer_did": issuer_did,
                    "credential_format": "ICAO_EMRTD",
                    "key_purpose": "x509_doc_signer",
                    "algorithm": "",
                },
                headers={"X-API-Key": key},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=422, detail="Issuer DID is not active for organization")
        resolved = response.json()
    except HTTPException:
        raise
    except (OSError, UnicodeError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(
            status_code=503, detail="Managed passport issuer resolver is unavailable"
        ) from exc
    if (
        not isinstance(resolved, dict)
        or resolved.get("organization_id") != organization_id
        or resolved.get("issuer_did") != issuer_did
        or resolved.get("key_purpose") != "x509_doc_signer"
        or not isinstance(resolved.get("issuer_profile"), dict)
        or resolved["issuer_profile"].get("credential_format") != "ICAO_EMRTD"
    ):
        raise HTTPException(status_code=422, detail="Issuer DID is not active for organization")


def signer_capabilities() -> dict[str, Any]:
    remote_url = os.environ.get("ICAO_DOCUMENT_SIGNER_URL", "").strip()
    test_signing = os.environ.get("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "").lower() == "true"
    blockers = (
        []
        if remote_url or test_signing
        else [
            "Configure ICAO_DOCUMENT_SIGNER_URL. Self-signed document certificates are permitted only in explicit test mode."
        ]
    )
    return {
        "configured": not blockers,
        "mode": "REMOTE" if remote_url else ("SELF_SIGNED_TEST" if test_signing else "UNAVAILABLE"),
        "blockers": blockers,
    }


async def sign_emrtd(
    *,
    country_code: str,
    organization: str,
    issuer_did: str | None = None,
    data_groups: dict[int, str],
) -> dict[str, Any]:
    """Return signed SOD/certificate material without persisting it locally."""
    capabilities = signer_capabilities()
    if not capabilities["configured"]:
        raise RuntimeError(capabilities["blockers"][0])

    signer_url = os.environ.get("ICAO_DOCUMENT_SIGNER_URL", "").strip()
    if issuer_did is not None and not signer_url:
        raise RuntimeError("Managed issuer DID requires a profile-backed document signer")
    if signer_url:
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{signer_url.rstrip('/')}/v1/icao/emrtd/sign",
                json={
                    "country_code": country_code,
                    "organization": organization,
                    **({"issuer_did": issuer_did} if issuer_did is not None else {}),
                    "data_groups": {
                        f"DG{number}": value for number, value in sorted(data_groups.items())
                    },
                },
                headers={
                    "Authorization": f"Bearer {os.environ.get('ICAO_DOCUMENT_SIGNER_API_KEY', '')}",
                },
            )
            response.raise_for_status()
            result = response.json()
    else:
        import _marty_rs

        request_json = json.dumps(
            {
                "country_code": country_code,
                "organization": organization,
                "data_groups": [
                    {
                        "number": number,
                        "content": list(base64.b64decode(content, validate=True)),
                    }
                    for number, content in sorted(data_groups.items())
                ],
            }
        )
        result = json.loads(_marty_rs.issue_emrtd_passport_self_signed(request_json))

    required = ("sod_der_base64", "dsc_cert_pem")
    if any(not result.get(field) for field in required):
        raise RuntimeError("ICAO document signer returned incomplete signing material")
    return result
