"""Service-to-service helpers for KMS-backed issuer identity resolution."""
from __future__ import annotations

import base64
import os
from typing import Any

import httpx


def _read_secret_value(name: str) -> str:
    direct = os.environ.get(name)
    if direct:
        return direct
    file_path = os.environ.get(f"{name}_FILE")
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _internal_signing_base_url() -> str:
    return os.environ.get("SIGNING_KEYS_INTERNAL_URL", "http://gateway:8000/internal/signing-keys").rstrip("/")


def _internal_headers() -> dict[str, str]:
    api_key = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value("ISSUANCE_API_KEY")
    return {"X-API-Key": api_key} if api_key else {}


def _response_error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("error_description") or payload.get("error")
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
        if isinstance(detail, dict):
            return str(detail)

    text = response.text.strip()
    return text[:500] if text else response.reason_phrase


async def resolve_remote_issuer_context(
    organization_id: str,
    *,
    issuer_profile_id: str | None = None,
    issuer_mode: str | None = None,
    credential_format: str | None = None,
    key_purpose: str | None = None,
    algorithm: str | None = None,
) -> dict[str, Any] | None:
    """Resolve the active issuer DID and remote signing service for an org."""
    if not organization_id:
        return None

    params: dict[str, str] = {"organization_id": organization_id}
    if issuer_profile_id:
        params["issuer_profile_id"] = issuer_profile_id
    if issuer_mode:
        params["issuer_mode"] = issuer_mode
    if credential_format:
        params["credential_format"] = credential_format
    if key_purpose:
        params["key_purpose"] = key_purpose
    if algorithm:
        params["algorithm"] = algorithm

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{_internal_signing_base_url()}/issuer-context",
            params=params,
            headers=_internal_headers(),
        )

    if response.status_code == 404:
        return None
    if response.status_code == 401:
        raise RuntimeError("Internal signing API rejected the service API key")
    if response.status_code >= 400:
        raise RuntimeError(
            f"DID issuer context resolution failed (HTTP {response.status_code}): {_response_error_detail(response)}"
        )
    data = response.json()
    return data if isinstance(data, dict) and data.get("ok") else None


async def sign_payload_with_remote_service(
    *,
    organization_id: str,
    signing_service_id: str,
    payload: bytes,
    algorithm: str | None = None,
    key_reference: str | None = None,
) -> dict[str, Any]:
    """Ask the registered remote KMS service to sign a payload."""
    if not organization_id:
        raise RuntimeError("organization_id is required for remote signing")
    if not signing_service_id:
        raise RuntimeError("signing_service_id is required for remote signing")
    if not payload:
        raise RuntimeError("payload is required for remote signing")

    body: dict[str, Any] = {
        "payload_b64": base64.urlsafe_b64encode(payload).decode().rstrip("="),
    }
    if algorithm:
        body["algorithm"] = algorithm
    if key_reference:
        body["key_reference"] = key_reference

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"{_internal_signing_base_url()}/services/{signing_service_id}/sign",
            params={"organization_id": organization_id},
            json=body,
            headers=_internal_headers(),
        )

    if response.status_code == 401:
        raise RuntimeError("Internal signing API rejected the service API key")
    if response.status_code >= 400:
        raise RuntimeError(
            f"DID-backed signing failed (HTTP {response.status_code}): {_response_error_detail(response)}"
        )
    data = response.json()
    if not isinstance(data, dict) or not data.get("ok"):
        raise RuntimeError("Remote signing service returned an invalid response")

    signature = str(data.get("signature_raw_b64") or data.get("signature_b64") or "")
    if not signature:
        raise RuntimeError("Remote signing service did not return a signature")
    return data
