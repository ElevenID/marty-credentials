"""Credential input validation for the W3C VC Data Model 2.0.

This module belongs to the production issuance boundary.  Interoperability
adapters may translate protocols, but they must not own semantic rules that
can make a conformance test pass while ordinary issuance accepts the same
invalid document.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

BASE_CONTEXT = "https://www.w3.org/ns/credentials/v2"
EXAMPLES_CONTEXT = "https://www.w3.org/ns/credentials/examples/v2"

_ABSOLUTE_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")
_RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_PROTECTED_VCDM_TERMS = frozenset(
    {
        "VerifiableCredential",
        "VerifiablePresentation",
        "credentialSubject",
        "issuer",
        "proof",
        "type",
        "id",
        "@context",
    }
)

ResourceFetcher = Callable[[str], Awaitable[bytes]]


class VcdmValidationError(ValueError):
    """A stable production validation failure safe to map to a client error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise VcdmValidationError(code)


def _is_absolute_uri(value: Any) -> bool:
    return isinstance(value, str) and bool(_ABSOLUTE_URI.fullmatch(value))


def _context_term_map(context: list[Any]) -> dict[str, str]:
    terms: dict[str, str] = {}
    for item in context[1:]:
        if isinstance(item, str):
            if not _is_absolute_uri(item):
                _fail("invalid_context")
            # The published examples context supplies this compact term. Keep
            # known remote terms explicit until the JSON-LD processor exposes
            # its resolved context as a stable validation API.
            if item == EXAMPLES_CONTEXT:
                terms["RelationshipCredential"] = (
                    "https://www.w3.org/ns/credentials/examples#RelationshipCredential"
                )
            continue
        if not isinstance(item, dict):
            _fail("invalid_context")
        for term, target in item.items():
            if term in _PROTECTED_VCDM_TERMS:
                _fail("invalid_context")
            if term.startswith("@"):
                # JSON-LD context controls are not credential type aliases.
                continue
            target_id = target.get("@id") if isinstance(target, dict) else target
            if not _is_absolute_uri(target_id):
                _fail("invalid_context")
            terms[term] = target_id
    return terms


def _validate_type(
    value: Any,
    terms: dict[str, str],
    required: str | None = None,
) -> None:
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(item, str) and item for item in values):
        _fail("invalid_type")
    if required and required not in values:
        _fail("invalid_type")
    for item in values:
        if not _is_absolute_uri(item) and item not in _PROTECTED_VCDM_TERMS and item not in terms:
            _fail("invalid_type")


def _validate_typed_resource(
    value: Any,
    terms: dict[str, str],
    *,
    require_id: bool = False,
) -> None:
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(item, dict) for item in values):
        _fail("invalid_resource")
    for item in values:
        _validate_type(item.get("type"), terms)
        if require_id and not _is_absolute_uri(item.get("id")):
            _fail("invalid_resource")


def _validate_language_value(value: Any) -> bool:
    if isinstance(value, str):
        return True
    if isinstance(value, list):
        return bool(value) and all(
            not isinstance(item, list) and _validate_language_value(item) for item in value
        )
    if not isinstance(value, dict) or not isinstance(value.get("@value"), str):
        return False
    return all(
        key in {"@value", "@language", "@direction"} and (key == "@value" or isinstance(entry, str))
        for key, entry in value.items()
    )


def _is_rfc3339_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not _RFC3339_DATETIME.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def validate_credential_document(
    credential: dict[str, Any],
    *,
    issuer_did: str | None = None,
) -> None:
    """Validate an unsigned VCDM v2 credential at the production boundary."""

    if not isinstance(credential, dict) or not credential:
        _fail("invalid_credential")
    if "proof" in credential:
        _fail("credential_must_be_unsigned")

    context = credential.get("@context")
    if not isinstance(context, list) or not context or context[0] != BASE_CONTEXT:
        _fail("invalid_context")
    terms = _context_term_map(context)
    _validate_type(credential.get("type"), terms, "VerifiableCredential")

    if "id" in credential and not _is_absolute_uri(credential["id"]):
        _fail("invalid_id")

    if "issuer" in credential:
        issuer = credential.get("issuer")
        issuer_id = issuer.get("id") if isinstance(issuer, dict) else issuer
        if not _is_absolute_uri(issuer_id):
            _fail("invalid_issuer")
        if issuer_did is not None and issuer_id != issuer_did:
            _fail("issuer_did_mismatch")

    subjects = credential.get("credentialSubject")
    subject_values = subjects if isinstance(subjects, list) else [subjects]
    if not subject_values or not all(
        isinstance(subject, dict) and subject for subject in subject_values
    ):
        _fail("invalid_subject")
    for subject in subject_values:
        if "id" in subject and not _is_absolute_uri(subject["id"]):
            _fail("invalid_subject")

    for key in ("validFrom", "validUntil"):
        if key in credential and not _is_rfc3339_datetime(credential[key]):
            _fail("invalid_validity")
    if "validFrom" in credential and "validUntil" in credential:
        valid_from = datetime.fromisoformat(credential["validFrom"].replace("Z", "+00:00"))
        valid_until = datetime.fromisoformat(credential["validUntil"].replace("Z", "+00:00"))
        if valid_from > valid_until:
            _fail("invalid_validity")

    if "credentialStatus" in credential:
        _validate_typed_resource(credential["credentialStatus"], terms)
        statuses = credential["credentialStatus"]
        statuses = statuses if isinstance(statuses, list) else [statuses]
        for status in statuses:
            if "id" in status and not _is_absolute_uri(status["id"]):
                _fail("invalid_status")

    if "credentialSchema" in credential:
        _validate_typed_resource(credential["credentialSchema"], terms, require_id=True)
    for key in ("termsOfUse", "refreshService", "evidence"):
        if key in credential:
            _validate_typed_resource(credential[key], terms)

    if "relatedResource" in credential:
        resources = credential["relatedResource"]
        resources = resources if isinstance(resources, list) else [resources]
        seen_resource_ids: set[str] = set()
        if not resources or not all(isinstance(resource, dict) for resource in resources):
            _fail("invalid_related_resource")
        for resource in resources:
            resource_id = resource.get("id")
            if not _is_absolute_uri(resource_id) or resource_id in seen_resource_ids:
                _fail("invalid_related_resource")
            if not isinstance(
                resource.get("digestSRI") or resource.get("digestMultibase"),
                str,
            ):
                _fail("invalid_related_resource")
            seen_resource_ids.add(resource_id)

    for key in ("name", "description"):
        if key in credential and not _validate_language_value(credential[key]):
            _fail("invalid_language_value")
    if isinstance(credential.get("issuer"), dict):
        for key in ("name", "description"):
            if key in credential["issuer"] and not _validate_language_value(
                credential["issuer"][key]
            ):
                _fail("invalid_language_value")


async def validate_related_resource_digests(
    credential: dict[str, Any],
    *,
    fetch_resource: ResourceFetcher,
) -> None:
    """Validate VCDM related-resource digests using a caller-controlled fetcher."""

    resources = credential.get("relatedResource")
    if resources is None:
        return
    values = resources if isinstance(resources, list) else [resources]
    documents: dict[str, bytes] = {}

    for resource in values:
        resource_id = resource["id"]
        if resource_id not in documents:
            try:
                documents[resource_id] = await fetch_resource(resource_id)
            except VcdmValidationError:
                raise
            except Exception as exc:
                raise VcdmValidationError("related_resource_unavailable") from exc
        content = documents[resource_id]

        digest_sri = resource.get("digestSRI")
        if digest_sri:
            try:
                algorithm, expected = digest_sri.split("-", 1)
                if algorithm not in {"sha256", "sha384", "sha512"}:
                    raise ValueError("unsupported SRI digest")
                digest = hashlib.new(algorithm, content).digest()
            except (ValueError, TypeError):
                _fail("invalid_related_resource")
            actual = base64.b64encode(digest).decode("ascii")
            if not hmac.compare_digest(actual, expected):
                _fail("related_resource_digest_mismatch")

        digest_multibase = resource.get("digestMultibase")
        if digest_multibase:
            actual = "u" + base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode(
                "ascii"
            ).rstrip("=")
            if not hmac.compare_digest(actual, digest_multibase):
                _fail("related_resource_digest_mismatch")
