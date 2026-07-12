"""Capability-gated ICAO eMRTD signing adapter."""

from __future__ import annotations

import base64
import json
import os
from typing import Any


def signer_capabilities() -> dict[str, Any]:
    remote_url = os.environ.get("ICAO_DOCUMENT_SIGNER_URL", "").strip()
    test_signing = os.environ.get("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "").lower() == "true"
    blockers = [] if remote_url or test_signing else [
        "Configure ICAO_DOCUMENT_SIGNER_URL. Self-signed document certificates are permitted only in explicit test mode."
    ]
    return {
        "configured": not blockers,
        "mode": "REMOTE" if remote_url else ("SELF_SIGNED_TEST" if test_signing else "UNAVAILABLE"),
        "blockers": blockers,
    }


async def sign_emrtd(
    *,
    country_code: str,
    organization: str,
    data_groups: dict[int, str],
) -> dict[str, Any]:
    """Return signed SOD/certificate material without persisting it locally."""
    capabilities = signer_capabilities()
    if not capabilities["configured"]:
        raise RuntimeError(capabilities["blockers"][0])

    signer_url = os.environ.get("ICAO_DOCUMENT_SIGNER_URL", "").strip()
    if signer_url:
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{signer_url.rstrip('/')}/v1/icao/emrtd/sign",
                json={
                    "country_code": country_code,
                    "organization": organization,
                    "data_groups": {f"DG{number}": value for number, value in sorted(data_groups.items())},
                },
                headers={
                    "Authorization": f"Bearer {os.environ.get('ICAO_DOCUMENT_SIGNER_API_KEY', '')}",
                },
            )
            response.raise_for_status()
            result = response.json()
    else:
        import _marty_rs

        request_json = json.dumps({
            "country_code": country_code,
            "organization": organization,
            "data_groups": [
                {
                    "number": number,
                    "content": list(base64.b64decode(content, validate=True)),
                }
                for number, content in sorted(data_groups.items())
            ],
        })
        result = json.loads(_marty_rs.issue_emrtd_passport_self_signed(request_json))

    required = ("sod_der_base64", "dsc_cert_pem")
    if any(not result.get(field) for field in required):
        raise RuntimeError("ICAO document signer returned incomplete signing material")
    return result
