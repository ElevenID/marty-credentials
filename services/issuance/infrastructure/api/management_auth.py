"""Shared management authentication for private issuance HTTP routes."""

from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import Header, HTTPException, Request

_ISSUANCE_API_KEY = os.environ.get("ISSUANCE_API_KEY", "")
_api_key_header = Header(None, alias="X-API-Key")


def _configured_management_api_key() -> str:
    key_file = os.environ.get("ISSUANCE_API_KEY_FILE", "").strip()
    if key_file and _ISSUANCE_API_KEY:
        raise HTTPException(status_code=503, detail="ISSUANCE_API_KEY configuration is ambiguous")
    if key_file:
        try:
            key = Path(key_file).read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise HTTPException(
                status_code=503, detail="ISSUANCE_API_KEY_FILE is unavailable"
            ) from exc
    else:
        key = _ISSUANCE_API_KEY
    if not key:
        raise HTTPException(status_code=503, detail="ISSUANCE_API_KEY not configured on server")
    return key


async def _verify_management_api_key(
    x_api_key: str | None = _api_key_header,
) -> str:
    """Verify X-API-Key header for management endpoints."""
    configured_key = _configured_management_api_key()
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header is missing")
    if not hmac.compare_digest(x_api_key, configured_key):
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key


def _trusted_organization_id(http_request: Request) -> str:
    """Return the gateway-authenticated organization for management calls."""
    organization_id = str(http_request.headers.get("X-Organization-ID") or "").strip()
    if not organization_id:
        raise HTTPException(status_code=403, detail="Trusted organization context is required")
    return organization_id
