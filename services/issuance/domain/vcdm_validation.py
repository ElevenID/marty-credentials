"""Thin orchestration adapters for the canonical Rust VCDM v2 validator."""

from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable
from typing import Any

from marty_credentials.native_backend import require_marty_rs

BASE_CONTEXT = "https://www.w3.org/ns/credentials/v2"
EXAMPLES_CONTEXT = "https://www.w3.org/ns/credentials/examples/v2"

ResourceFetcher = Callable[[str], Awaitable[bytes]]

_native = require_marty_rs(
    (
        "validate_vcdm_issuance_document",
        "validate_vcdm_related_resource_digests",
    )
)


class VcdmValidationError(ValueError):
    """A stable production validation failure safe to map to a client error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _native_error_code(exc: Exception, fallback: str) -> str:
    code = str(exc).strip()
    return code if code else fallback


def validate_credential_document(
    credential: dict[str, Any],
    *,
    issuer_did: str | None = None,
) -> None:
    """Validate unsigned issuance input in the canonical Rust kernel."""

    request = json.dumps(
        {"credential": credential, "issuer_did": issuer_did},
        allow_nan=False,
        separators=(",", ":"),
    )
    try:
        _native.validate_vcdm_issuance_document(request)
    except (TypeError, ValueError) as exc:
        raise VcdmValidationError(_native_error_code(exc, "invalid_credential")) from exc


async def validate_related_resource_digests(
    credential: dict[str, Any],
    *,
    fetch_resource: ResourceFetcher,
) -> None:
    """Fetch resources in Python and verify all digest decisions in Rust."""

    resources = credential.get("relatedResource")
    if resources is None:
        return
    values = resources if isinstance(resources, list) else [resources]
    contents: dict[str, str] = {}
    for resource in values:
        if not isinstance(resource, dict):
            continue
        resource_id = resource.get("id")
        if not isinstance(resource_id, str) or resource_id in contents:
            continue
        try:
            content = await fetch_resource(resource_id)
            contents[resource_id] = base64.b64encode(content).decode("ascii")
        except VcdmValidationError:
            raise
        except Exception as exc:
            raise VcdmValidationError("related_resource_unavailable") from exc

    request = json.dumps(
        {"credential": credential, "resource_contents": contents},
        allow_nan=False,
        separators=(",", ":"),
    )
    try:
        _native.validate_vcdm_related_resource_digests(request)
    except (TypeError, ValueError) as exc:
        raise VcdmValidationError(
            _native_error_code(exc, "invalid_related_resource")
        ) from exc
