"""Canonical, privacy-preserving issuance-initiation idempotency helpers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def normalize_idempotency_key(value: str | None) -> str | None:
    """Validate an opaque caller key without persisting it verbatim."""

    raw = value or ""
    normalized = raw.strip()
    if not normalized:
        return None
    if raw != normalized:
        raise ValueError("idempotency key must not contain surrounding whitespace")
    if not _IDEMPOTENCY_KEY_PATTERN.fullmatch(normalized):
        raise ValueError(
            "idempotency key must contain 1-128 ASCII letters, digits, '.', '_', ':', or '-'"
        )
    return normalized


def hash_idempotency_key(value: str) -> str:
    """Return the non-reversible database lookup value for a validated key."""

    return hashlib.sha256(f"marty:issuance-idempotency-key:v1:{value}".encode()).hexdigest()


def issuance_request_hash(payload: dict[str, Any]) -> str:
    """Bind one idempotency key to exact cross-transport request semantics."""

    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(
        f"marty:issuance-initiate-request:v1:{canonical}".encode()
    ).hexdigest()


def canonical_issuance_request(
    *,
    organization_id: str,
    credential_template_id: str | None,
    application_id: str | None,
    applicant_id: str | None,
    subject_did: str | None,
    holder_did: str | None,
    issuer_did: str | None,
    authorized_client_id: str | None,
    delivery_mode: str,
    claims: dict[str, Any],
    credential_subject: dict[str, Any] | list[dict[str, Any]] | None = None,
    credential_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the semantic payload shared by HTTP and gRPC adapters."""

    return {
        "organization_id": organization_id,
        "credential_template_id": credential_template_id or "",
        "application_id": application_id or "",
        "applicant_id": applicant_id or "",
        "subject_did": subject_did or "",
        "holder_did": holder_did or "",
        "issuer_did": issuer_did or "",
        "authorized_client_id": authorized_client_id or "",
        "delivery_mode": delivery_mode,
        "claims": claims,
        "credential_subject": credential_subject,
        "credential_document": credential_document,
    }
