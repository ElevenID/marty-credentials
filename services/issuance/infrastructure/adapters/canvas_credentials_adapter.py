"""Canvas Credentials integration adapter for wallet-native issuance."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode

import httpx
from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError

from issuance.application.mip_integration_primitives import (
    MipEvidenceReceipt,
    canvas_completion_to_mip_evidence_receipt,
)
from issuance.application.canvas_runtime import (
    CanvasRuntimeConfig,
    canvas_feature_enabled,
    canvas_runtime_from_program_binding,
    resolve_canvas_program_binding_for_scope,
)
from issuance.application.evidence_transition import persist_evidence_fact_and_apply_policy
from issuance.domain.entities import (
    ApplicationStatus,
    Application,
    ApplicationTemplate,
    CanvasEventReceipt,
    CanvasPlatform,
    CredentialDeliveryRecord,
    EvidenceFact,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.domain.ports import IIssuanceRepository


CANVAS_SIGNATURE_HEADER = "x-canvas-signature-256"
CANVAS_TIMESTAMP_HEADER = "x-canvas-timestamp"
_CANVAS_SIGNATURE_TOLERANCE_SECONDS = int(os.environ.get("CANVAS_CREDENTIALS_SIGNATURE_TOLERANCE_SECONDS", "300"))
_CANVAS_PUBLISH_TIMEOUT_SECONDS = float(os.environ.get("CANVAS_CREDENTIALS_PUBLISH_TIMEOUT_SECONDS", "20"))
_CANVAS_STATUS_SYNC_TIMEOUT_SECONDS = float(
    os.environ.get(
        "CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS",
        str(_CANVAS_PUBLISH_TIMEOUT_SECONDS),
    )
)
_CANVAS_CREDENTIALS_DEFAULT_API_BASE_URL = "https://api.badgr.io"
_CANVAS_CREDENTIALS_REAL_PROVIDERS = {"badgr_api", "canvas_credentials_api"}
CanvasSecretResolver = Callable[[str, str], Awaitable[str | None]]


class CanvasCredentialEvent(BaseModel):
    """Inbound Canvas completion event contract for credential issuance."""

    canvas_event_id: str = Field(min_length=1)
    organization_id: str | None = None
    credential_template_id: str | None = None
    canvas_account_id: str = Field(min_length=1)
    canvas_course_id: str = Field(min_length=1)
    canvas_course_name: str = Field(min_length=1)
    canvas_enrollment_id: str = Field(min_length=1)
    canvas_user_id: str = Field(min_length=1)
    learner_email: str = Field(min_length=1)
    learner_name: str | None = None
    learner_given_name: str | None = None
    learner_family_name: str | None = None
    achievement_name: str = Field(min_length=1)
    achievement_description: str | None = None
    completion_at: str = Field(min_length=1)


class CanvasEvidenceEvent(CanvasCredentialEvent):
    """Inbound Canvas completion evidence for an ElevenID application."""

    application_id: str = Field(min_length=1)
    evidence_type: str = "canvas.course_completion"
    canvas_assignment_id: str | None = None
    canvas_module_id: str | None = None
    canvas_quiz_id: str | None = None
    submitted: bool | None = None
    completed: bool | None = None
    passed: bool | None = None
    score: float | None = None
    score_percent: float | None = None
    roles: list[str] | None = None
    membership_status: str | None = None
    eligible: bool | None = None


class CanvasAgsScoreEvent(BaseModel):
    """Inbound Canvas Assignment and Grade Services score as MIP evidence input."""

    canvas_event_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    organization_id: str | None = None
    credential_template_id: str | None = None
    canvas_account_id: str = Field(min_length=1)
    canvas_course_id: str = Field(min_length=1)
    canvas_course_name: str | None = None
    canvas_user_id: str = Field(min_length=1)
    canvas_enrollment_id: str | None = None
    learner_email: str | None = None
    learner_name: str | None = None
    learner_given_name: str | None = None
    learner_family_name: str | None = None
    evidence_type: str | None = None
    canvas_assignment_id: str | None = None
    canvas_module_id: str | None = None
    canvas_quiz_id: str | None = None
    line_item_id: str | None = None
    line_item_url: str | None = None
    line_item_label: str | None = None
    activity_progress: str | None = None
    grading_progress: str | None = None
    submitted: bool | None = None
    completed: bool | None = None
    passed: bool | None = None
    score: float | None = None
    score_given: float | None = None
    score_maximum: float | None = None
    score_percent: float | None = None
    submitted_at: str | None = None
    graded_at: str | None = None
    timestamp: str | None = None


class CanvasNrpsMembershipEvent(BaseModel):
    """Inbound Canvas Names and Role Provisioning membership as MIP evidence input."""

    canvas_event_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    organization_id: str | None = None
    credential_template_id: str | None = None
    canvas_account_id: str = Field(min_length=1)
    canvas_course_id: str = Field(min_length=1)
    canvas_course_name: str | None = None
    canvas_user_id: str = Field(min_length=1)
    canvas_enrollment_id: str | None = None
    membership_id: str | None = None
    context_memberships_url: str | None = None
    learner_email: str | None = None
    learner_name: str | None = None
    learner_given_name: str | None = None
    learner_family_name: str | None = None
    roles: list[str] = Field(default_factory=list)
    membership_status: str | None = None
    eligible: bool | None = None
    evidence_type: str = "canvas.nrps_membership"
    timestamp: str | None = None


class CanvasEvidenceEventResponse(BaseModel):
    """Replay-safe response for Canvas evidence attached to an application."""

    id: str
    application_id: str
    organization_id: str
    canvas_account_id: str
    evidence_type: str
    status: str
    application_status: str | None = None
    source_event_id: str
    replayed: bool = False
    evidence: dict[str, Any]
    mip_primitives: dict[str, Any]
    evidence_facts: list[dict[str, Any]] = Field(default_factory=list)
    policy_decision: dict[str, Any] | None = None


class CanvasCredentialsPublishResult(BaseModel):
    """Normalized result from an outbound Canvas Credentials publish attempt."""

    external_credential_id: str | None = None
    external_issuer_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CanvasCredentialsStatusSyncResult(BaseModel):
    """Normalized result from an outbound Canvas Credentials lifecycle sync."""

    metadata: dict[str, Any] = Field(default_factory=dict)


class CanvasCredentialsConfigValidationResult(BaseModel):
    """Safe validation result for Canvas Credentials provider configuration."""

    ok: bool
    provider: str
    api_base_url: str | None = None
    assertion_scope: str | None = None
    issuer_id: str | None = None
    badgeclass_id: str | None = None
    token_configured: bool = False
    validation_url: str | None = None
    status_code: int | None = None
    request_id: str | None = None
    error: str | None = None
    response_excerpt: dict[str, Any] | None = None
    validated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


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


def _read_secret_file(file_path: str | None) -> str:
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _canvas_credentials_metadata_sources(delivery_record: CredentialDeliveryRecord | None) -> list[dict[str, Any]]:
    if delivery_record is None or not isinstance(delivery_record.metadata, dict):
        return []
    metadata = delivery_record.metadata
    sources: list[dict[str, Any]] = []
    for key in ("canvas_credentials", "canvas_credentials_config", "provider_config"):
        nested = metadata.get(key)
        if isinstance(nested, dict):
            sources.append(nested)
    sources.append(metadata)
    return sources


def _canvas_credentials_config_value(
    delivery_record: CredentialDeliveryRecord | None,
    *metadata_keys: str,
    env_names: tuple[str, ...] = (),
) -> str:
    for source in _canvas_credentials_metadata_sources(delivery_record):
        for key in metadata_keys:
            value = source.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
    for env_name in env_names:
        value = os.environ.get(env_name)
        if value is not None and value.strip():
            return value.strip()
    return ""


def _canvas_credentials_secret_reference(source: dict[str, Any]) -> str:
    return str(
        source.get("api_token_secret_id")
        or source.get("api_token_secret_ref")
        or source.get("api_token_ref")
        or source.get("canvas_credentials_api_token_secret_id")
        or source.get("canvas_credentials_api_token_secret_ref")
        or ""
    ).strip()


def _integration_secret_id_from_ref(value: str) -> str:
    ref = value.strip()
    if ref.startswith("org_secret://"):
        return ref.rstrip("/").split("/")[-1]
    return ref


async def _canvas_credentials_secret_value(
    delivery_record: CredentialDeliveryRecord | None,
    *,
    default_secret_name: str,
    secret_resolver: CanvasSecretResolver | None = None,
) -> str:
    for source in _canvas_credentials_metadata_sources(delivery_record):
        secret_ref = _canvas_credentials_secret_reference(source)
        if secret_ref and secret_resolver and delivery_record is not None:
            secret = await secret_resolver(
                delivery_record.organization_id,
                _integration_secret_id_from_ref(secret_ref),
            )
            if secret:
                return secret
        direct = source.get("api_token") or source.get("canvas_credentials_api_token")
        if direct is not None and str(direct).strip():
            return str(direct).strip()
        env_name = (
            source.get("api_token_env")
            or source.get("api_token_secret_env")
            or source.get("canvas_credentials_api_token_env")
        )
        if env_name is not None and str(env_name).strip():
            secret = _read_secret_value(str(env_name).strip())
            if secret:
                return secret
        file_path = (
            source.get("api_token_file")
            or source.get("api_token_secret_file")
            or source.get("canvas_credentials_api_token_file")
        )
        if file_path is not None and str(file_path).strip():
            secret = _read_secret_file(str(file_path).strip())
            if secret:
                return secret
    return _read_secret_value(default_secret_name)


def _truncate_text(value: str, limit: int = 1000) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}…"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _canvas_credentials_provider(delivery_record: CredentialDeliveryRecord | None = None) -> str:
    raw_provider = _canvas_credentials_config_value(
        delivery_record,
        "provider",
        "canvas_credentials_provider",
        env_names=("CANVAS_CREDENTIALS_PROVIDER",),
    ).lower()
    if not raw_provider:
        if (os.environ.get("CANVAS_CREDENTIALS_PUBLISH_URL") or "").strip():
            return "bridge"
        if _canvas_credentials_config_value(
            delivery_record,
            "badgeclass_id",
            "canvas_credentials_badgeclass_id",
            env_names=("CANVAS_CREDENTIALS_BADGECLASS_ID",),
        ):
            return "badgr_api"
        return "bridge"
    aliases = {
        "badgr": "badgr_api",
        "canvas_credentials": "badgr_api",
        "credentials_api": "badgr_api",
        "canvas": "badgr_api",
        "sandbox": "bridge",
        "proxy": "bridge",
        "bridge_api": "bridge",
    }
    return aliases.get(raw_provider, raw_provider)


def _is_real_canvas_credentials_provider(delivery_record: CredentialDeliveryRecord | None = None) -> bool:
    return _canvas_credentials_provider(delivery_record) in _CANVAS_CREDENTIALS_REAL_PROVIDERS


def _normalize_publish_url() -> str:
    publish_url = (os.environ.get("CANVAS_CREDENTIALS_PUBLISH_URL") or "").strip()
    if not publish_url:
        raise RuntimeError("CANVAS_CREDENTIALS_PUBLISH_URL is not configured")
    return publish_url


def _normalize_canvas_credentials_api_base_url(delivery_record: CredentialDeliveryRecord | None = None) -> str:
    return (
        _canvas_credentials_config_value(
            delivery_record,
            "api_base_url",
            "base_url",
            "canvas_credentials_api_base_url",
            "canvas_credentials_base_url",
            env_names=("CANVAS_CREDENTIALS_API_BASE_URL", "CANVAS_CREDENTIALS_BASE_URL"),
        )
        or _CANVAS_CREDENTIALS_DEFAULT_API_BASE_URL
    ).strip().rstrip("/")


def _normalize_status_sync_url() -> str:
    sync_url = (os.environ.get("CANVAS_CREDENTIALS_STATUS_SYNC_URL") or "").strip()
    if not sync_url:
        raise RuntimeError("CANVAS_CREDENTIALS_STATUS_SYNC_URL is not configured")
    return sync_url


def _response_json_or_excerpt(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {"body_excerpt": _truncate_text(response.text or "")}
    if isinstance(payload, dict):
        return payload
    return {"payload": payload}


def _first_non_empty_string(*values: object) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _first_badgr_result(response_payload: dict[str, Any]) -> dict[str, Any]:
    result = response_payload.get("result")
    if isinstance(result, list) and result:
        first = result[0]
        return first if isinstance(first, dict) else {}
    if isinstance(result, dict):
        return result
    data = response_payload.get("data")
    if isinstance(data, list) and data:
        first = data[0]
        return first if isinstance(first, dict) else {}
    if isinstance(data, dict):
        return data
    return response_payload if isinstance(response_payload, dict) else {}


def _extract_badgr_assertion_id(response_payload: dict[str, Any]) -> str | None:
    assertion = _first_badgr_result(response_payload)
    value = (
        assertion.get("entityId")
        or assertion.get("id")
        or assertion.get("openBadgeId")
        or ((assertion.get("assertionRef") or {}).get("assertionUrl") if isinstance(assertion.get("assertionRef"), dict) else None)
    )
    return str(value) if value is not None else None


def _extract_badgr_issuer_id(response_payload: dict[str, Any], fallback: str | None) -> str | None:
    assertion = _first_badgr_result(response_payload)
    value = assertion.get("issuer") or assertion.get("issuerOpenBadgeId") or fallback
    return str(value) if value is not None else None


def _extract_badgr_public_assertion_url(response_payload: dict[str, Any]) -> str | None:
    assertion = _first_badgr_result(response_payload)
    value = (
        assertion.get("openBadgeId")
        or ((assertion.get("assertionRef") or {}).get("assertionUrl") if isinstance(assertion.get("assertionRef"), dict) else None)
        or assertion.get("sourceUrl")
    )
    return str(value) if value is not None else None


def _canvas_credentials_assertion_scope(delivery_record: CredentialDeliveryRecord | None = None) -> str:
    scope = (
        _canvas_credentials_config_value(
            delivery_record,
            "assertion_scope",
            "canvas_credentials_assertion_scope",
            env_names=("CANVAS_CREDENTIALS_ASSERTION_SCOPE",),
        )
        or "badgeclasses"
    ).lower()
    if scope not in {"badgeclasses", "issuers"}:
        raise RuntimeError("CANVAS_CREDENTIALS_ASSERTION_SCOPE must be 'badgeclasses' or 'issuers'")
    return scope


def _canvas_credentials_badgeclass_id(delivery_record: CredentialDeliveryRecord) -> str:
    badgeclass_id = _first_non_empty_string(
        _canvas_credentials_config_value(
            delivery_record,
            "canvas_credentials_badgeclass_id",
            "badgeclass_id",
            env_names=("CANVAS_CREDENTIALS_BADGECLASS_ID",),
        ),
    )
    if not badgeclass_id:
        raise RuntimeError("CANVAS_CREDENTIALS_BADGECLASS_ID is required for real Canvas Credentials publish")
    return badgeclass_id


def _canvas_credentials_issuer_id(delivery_record: CredentialDeliveryRecord) -> str | None:
    return _first_non_empty_string(
        _canvas_credentials_config_value(
            delivery_record,
            "canvas_credentials_issuer_id",
            "issuer_id",
            "external_issuer_id",
            env_names=("CANVAS_CREDENTIALS_ISSUER_ID",),
        ),
    )


def _badgr_assertion_url(
    *,
    scope: str,
    badgeclass_id: str,
    issuer_id: str | None,
    api_base_url: str,
) -> str:
    template = (os.environ.get("CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE") or "").strip()
    if template:
        return template.format(
            api_base_url=api_base_url,
            scope=quote(scope, safe=""),
            badgeclass_id=quote(badgeclass_id, safe=""),
            issuer_id=quote(issuer_id or "", safe=""),
        )
    id_or_entity_id = issuer_id if scope == "issuers" else badgeclass_id
    if not id_or_entity_id:
        raise RuntimeError("CANVAS_CREDENTIALS_ISSUER_ID is required when assertion scope is 'issuers'")
    return (
        f"{api_base_url}"
        f"/v2/{quote(scope, safe='')}/{quote(id_or_entity_id, safe='')}/assertions"
    )


def _badgr_validation_url(
    *,
    delivery_record: CredentialDeliveryRecord,
    scope: str,
    badgeclass_id: str | None,
    issuer_id: str | None,
    api_base_url: str,
) -> str:
    template = _canvas_credentials_config_value(
        delivery_record,
        "validation_url_template",
        "validate_url_template",
        "canvas_credentials_validation_url_template",
        env_names=("CANVAS_CREDENTIALS_VALIDATE_URL_TEMPLATE",),
    )
    if template:
        return template.format(
            api_base_url=api_base_url,
            scope=quote(scope, safe=""),
            badgeclass_id=quote(badgeclass_id or "", safe=""),
            issuer_id=quote(issuer_id or "", safe=""),
        )
    id_or_entity_id = issuer_id if scope == "issuers" else badgeclass_id
    if not id_or_entity_id:
        if scope == "issuers":
            raise RuntimeError("CANVAS_CREDENTIALS_ISSUER_ID is required when assertion scope is 'issuers'")
        raise RuntimeError("CANVAS_CREDENTIALS_BADGECLASS_ID is required for Canvas Credentials validation")
    return f"{api_base_url}/v2/{quote(scope, safe='')}/{quote(id_or_entity_id, safe='')}"


def _badgr_revoke_url(external_credential_id: str, *, api_base_url: str) -> str:
    template = (os.environ.get("CANVAS_CREDENTIALS_REVOKE_URL_TEMPLATE") or "").strip()
    if template:
        return template.format(
            api_base_url=api_base_url,
            external_credential_id=quote(external_credential_id, safe=""),
        )
    return (
        f"{api_base_url}"
        f"/v2/assertions/{quote(external_credential_id, safe='')}"
    )


def _public_marty_base_url() -> str:
    for name in (
        "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL",
        "MARTY_ISSUER_BASE_URL",
        "ISSUER_BASE_URL",
        "PUBLIC_API_URL",
        "PUBLIC_BASE_URL",
    ):
        value = (os.environ.get(name) or "").strip().rstrip("/")
        if value:
            return value
    raise RuntimeError(
        "Canvas Credentials verification base URL is required; set "
        "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL or a public issuer/base URL"
    )


def _build_elevenid_provenance_url(
    *,
    credential: IssuedCredential,
    platform: CanvasPlatform,
    delivery_record: CredentialDeliveryRecord,
) -> str:
    params = {
        "delivery_record_id": delivery_record.id,
        "credential_id": credential.id,
    }
    if platform.canvas_account_id:
        params["canvas_account_id"] = platform.canvas_account_id
    if credential.organization_id:
        params["organization_id"] = credential.organization_id
    return f"{_public_marty_base_url()}/console/org/operate/verify?{urlencode(params)}"


def _canvas_credentials_recipient_identity(
    *,
    transaction: IssuanceTransaction,
    delivery_record: CredentialDeliveryRecord,
) -> str:
    claims = transaction.claims or {}
    metadata = delivery_record.metadata or {}
    identity = _first_non_empty_string(
        metadata.get("recipient_email"),
        metadata.get("learner_email"),
        metadata.get("canvas_learner_email"),
        claims.get("email"),
        claims.get("learner_email"),
        claims.get("recipient_email"),
        claims.get("holder_email"),
        claims.get("lis_person_contact_email_primary"),
    )
    if not identity:
        raise RuntimeError("Canvas Credentials publish requires a recipient email in transaction claims or delivery metadata")
    return identity


def _build_badgr_assertion_payload(
    *,
    credential: IssuedCredential,
    transaction: IssuanceTransaction,
    platform: CanvasPlatform,
    delivery_record: CredentialDeliveryRecord,
    badgeclass_id: str,
    scope: str,
) -> dict[str, Any]:
    claims = transaction.claims or {}
    provenance_url = _build_elevenid_provenance_url(
        credential=credential,
        platform=platform,
        delivery_record=delivery_record,
    )
    narrative = _first_non_empty_string(
        os.environ.get("CANVAS_CREDENTIALS_ASSERTION_NARRATIVE"),
        claims.get("achievement_description"),
        claims.get("description"),
        "Issued by ElevenID from verified Canvas course activity.",
    )
    payload: dict[str, Any] = {
        "issuedOn": credential.issued_at.isoformat(),
        "recipient": {
            "identity": _canvas_credentials_recipient_identity(
                transaction=transaction,
                delivery_record=delivery_record,
            ),
            "type": "email",
            "hashed": _env_bool("CANVAS_CREDENTIALS_RECIPIENT_HASHED", True),
        },
        "allowDuplicateAwards": _env_bool("CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS", False),
        "narrative": narrative,
        "evidence": [
            {
                "url": provenance_url,
                "name": "ElevenID canonical credential record",
                "description": "Links this Canvas Credentials badge to the canonical ElevenID issuance, issuer DID, and lifecycle status.",
                "narrative": "Canvas was the learning context; ElevenID holds the signed credential, issuer identity, and revocation status.",
                "genre": "Credential provenance",
                "audience": "Verifiers and employers",
            }
        ],
        "extensions": {
            "value": {
                "elevenid": {
                    "credential_id": credential.id,
                    "credential_hash": credential.credential_hash,
                    "issuer_did": credential.issuer_did or transaction.issuer_did_override,
                    "delivery_record_id": delivery_record.id,
                    "canvas_account_id": platform.canvas_account_id,
                    "provenance_url": provenance_url,
                },
            }
        },
    }
    if scope == "issuers":
        payload["badgeclass"] = badgeclass_id
    if credential.expires_at:
        payload["expires"] = credential.expires_at.isoformat()
    ob3_award_properties = claims.get("ob3AwardProperties")
    if isinstance(ob3_award_properties, dict):
        payload["ob3AwardProperties"] = ob3_award_properties
    return payload


def _build_canvas_publish_payload(
    *,
    credential: IssuedCredential,
    transaction: IssuanceTransaction,
    platform: CanvasPlatform,
    delivery_record: CredentialDeliveryRecord,
    issuer_id: str | None,
) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "organization_id": credential.organization_id or transaction.organization_id,
        "canvas_platform_id": platform.id,
        "canvas_program_binding_id": (delivery_record.metadata or {}).get("canvas_program_binding_id"),
        "canvas_account_id": platform.canvas_account_id,
        "canvas_base_url": platform.canvas_base_url,
        "credential": {
            "id": credential.id,
            "transaction_id": transaction.id,
            "credential_template_id": credential.credential_template_id,
            "format": transaction.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
            "jwt": credential.credential_jwt,
            "hash": credential.credential_hash,
            "issuer_did": credential.issuer_did or transaction.issuer_did_override,
            "revocation_profile_id": credential.revocation_profile_id,
            "status_list_entries": credential.status_list_entries,
            "issued_at": credential.issued_at.isoformat(),
            "expires_at": credential.expires_at.isoformat() if credential.expires_at else None,
        },
        "recipient": {
            "applicant_id": credential.applicant_id or transaction.applicant_id,
            "subject_did": credential.subject_did or transaction.subject_did,
        },
        "source": {
            "delivery_record_id": delivery_record.id,
            "delivery_mode": delivery_record.delivery_mode,
            "application_id": transaction.application_id,
        },
        "metadata": delivery_record.metadata or {},
    }


def _build_canvas_status_sync_payload(
    *,
    credential: IssuedCredential,
    platform: CanvasPlatform,
    delivery_record: CredentialDeliveryRecord,
    lifecycle_action: str,
    reason: str | None,
    issuer_id: str | None,
) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "canvas_platform_id": platform.id,
        "canvas_program_binding_id": (delivery_record.metadata or {}).get("canvas_program_binding_id"),
        "canvas_account_id": platform.canvas_account_id,
        "lifecycle_action": lifecycle_action,
        "credential": {
            "id": credential.id,
            "external_credential_id": delivery_record.external_credential_id,
            "external_issuer_id": delivery_record.external_issuer_id,
            "issuer_did": credential.issuer_did,
            "status": credential.status.value,
            "status_updated_at": credential.status_updated_at.isoformat(),
            "revoked_at": credential.revoked_at.isoformat() if credential.revoked_at else None,
            "reason": reason,
        },
        "metadata": {
            "delivery_record_id": delivery_record.id,
            "organization_id": credential.organization_id,
            "credential_template_id": credential.credential_template_id,
        },
    }


def _canvas_credentials_headers(api_token: str) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    return headers


async def validate_canvas_credentials_config(
    delivery_record: CredentialDeliveryRecord,
    secret_resolver: CanvasSecretResolver | None = None,
) -> CanvasCredentialsConfigValidationResult:
    """Validate Canvas Credentials provider configuration without publishing an assertion."""

    provider = _canvas_credentials_provider(delivery_record)
    if provider == "bridge":
        token = await _canvas_credentials_secret_value(
            delivery_record,
            default_secret_name="CANVAS_CREDENTIALS_API_TOKEN",
            secret_resolver=secret_resolver,
        )
        try:
            publish_url = _normalize_publish_url()
        except RuntimeError as exc:
            return CanvasCredentialsConfigValidationResult(
                ok=False,
                provider=provider,
                token_configured=bool(token),
                error=str(exc),
            )
        return CanvasCredentialsConfigValidationResult(
            ok=True,
            provider=provider,
            token_configured=bool(token),
            validation_url=publish_url,
        )

    if provider not in _CANVAS_CREDENTIALS_REAL_PROVIDERS:
        return CanvasCredentialsConfigValidationResult(
            ok=False,
            provider=provider,
            error=f"Unsupported Canvas Credentials provider: {provider}",
        )

    try:
        api_base_url = _normalize_canvas_credentials_api_base_url(delivery_record)
        scope = _canvas_credentials_assertion_scope(delivery_record)
        issuer_id = _canvas_credentials_issuer_id(delivery_record)
        badgeclass_id = _canvas_credentials_badgeclass_id(delivery_record)
        api_token = await _canvas_credentials_secret_value(
            delivery_record,
            default_secret_name="CANVAS_CREDENTIALS_API_TOKEN",
            secret_resolver=secret_resolver,
        )
        validation_url = _badgr_validation_url(
            delivery_record=delivery_record,
            scope=scope,
            badgeclass_id=badgeclass_id,
            issuer_id=issuer_id,
            api_base_url=api_base_url,
        )
    except RuntimeError as exc:
        return CanvasCredentialsConfigValidationResult(
            ok=False,
            provider=provider,
            api_base_url=_canvas_credentials_config_value(
                delivery_record,
                "api_base_url",
                "base_url",
                "canvas_credentials_api_base_url",
                "canvas_credentials_base_url",
                env_names=("CANVAS_CREDENTIALS_API_BASE_URL", "CANVAS_CREDENTIALS_BASE_URL"),
            )
            or _CANVAS_CREDENTIALS_DEFAULT_API_BASE_URL,
            token_configured=bool(
                await _canvas_credentials_secret_value(
                    delivery_record,
                    default_secret_name="CANVAS_CREDENTIALS_API_TOKEN",
                    secret_resolver=secret_resolver,
                )
            ),
            error=str(exc),
        )

    if not api_token:
        return CanvasCredentialsConfigValidationResult(
            ok=False,
            provider=provider,
            api_base_url=api_base_url,
            assertion_scope=scope,
            issuer_id=issuer_id,
            badgeclass_id=badgeclass_id,
            token_configured=False,
            validation_url=validation_url,
            error="CANVAS_CREDENTIALS_API_TOKEN is required for Canvas Credentials validation",
        )

    try:
        async with httpx.AsyncClient(timeout=_CANVAS_STATUS_SYNC_TIMEOUT_SECONDS) as client:
            response = await client.get(validation_url, headers=_canvas_credentials_headers(api_token))
    except httpx.HTTPError as exc:
        return CanvasCredentialsConfigValidationResult(
            ok=False,
            provider=provider,
            api_base_url=api_base_url,
            assertion_scope=scope,
            issuer_id=issuer_id,
            badgeclass_id=badgeclass_id,
            token_configured=True,
            validation_url=validation_url,
            error=f"Canvas Credentials validation request failed: {exc}",
        )

    ok = 200 <= response.status_code < 300
    return CanvasCredentialsConfigValidationResult(
        ok=ok,
        provider=provider,
        api_base_url=api_base_url,
        assertion_scope=scope,
        issuer_id=issuer_id,
        badgeclass_id=badgeclass_id,
        token_configured=True,
        validation_url=validation_url,
        status_code=response.status_code,
        request_id=response.headers.get("x-request-id"),
        error=None if ok else f"Canvas Credentials validation failed with HTTP {response.status_code}",
        response_excerpt=None if ok else _response_json_or_excerpt(response),
    )


async def _publish_canvas_badgr_assertion(
    *,
    credential: IssuedCredential,
    transaction: IssuanceTransaction,
    platform: CanvasPlatform,
    delivery_record: CredentialDeliveryRecord,
    secret_resolver: CanvasSecretResolver | None = None,
) -> CanvasCredentialsPublishResult:
    api_token = await _canvas_credentials_secret_value(
        delivery_record,
        default_secret_name="CANVAS_CREDENTIALS_API_TOKEN",
        secret_resolver=secret_resolver,
    )
    if not api_token:
        raise RuntimeError("CANVAS_CREDENTIALS_API_TOKEN is required for real Canvas Credentials publish")

    api_base_url = _normalize_canvas_credentials_api_base_url(delivery_record)
    scope = _canvas_credentials_assertion_scope(delivery_record)
    badgeclass_id = _canvas_credentials_badgeclass_id(delivery_record)
    issuer_id = _canvas_credentials_issuer_id(delivery_record)
    assertion_url = _badgr_assertion_url(
        scope=scope,
        badgeclass_id=badgeclass_id,
        issuer_id=issuer_id,
        api_base_url=api_base_url,
    )
    payload = _build_badgr_assertion_payload(
        credential=credential,
        transaction=transaction,
        platform=platform,
        delivery_record=delivery_record,
        badgeclass_id=badgeclass_id,
        scope=scope,
    )
    headers = _canvas_credentials_headers(api_token)

    try:
        async with httpx.AsyncClient(timeout=_CANVAS_PUBLISH_TIMEOUT_SECONDS) as client:
            response = await client.post(assertion_url, json=payload, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        body = _truncate_text(exc.response.text or "")
        raise RuntimeError(
            f"Canvas Credentials assertion publish failed (HTTP {exc.response.status_code}): {body}"
        ) from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Canvas Credentials assertion publish request failed: {exc}") from exc

    response_payload = _response_json_or_excerpt(response)
    open_badge_url = _extract_badgr_public_assertion_url(response_payload)
    external_credential_id = _extract_badgr_assertion_id(response_payload)
    if not external_credential_id:
        raise RuntimeError("Canvas Credentials assertion publish response did not include an assertion id")
    return CanvasCredentialsPublishResult(
        external_credential_id=external_credential_id,
        external_issuer_id=_extract_badgr_issuer_id(response_payload, issuer_id),
        metadata={
            "provider": "badgr_api",
            "api_base_url": api_base_url,
            "assertion_scope": scope,
            "badgeclass_id": badgeclass_id,
            "publish_url": assertion_url,
            "published_at": datetime.now(timezone.utc).isoformat(),
            "http_status": response.status_code,
            "publish_response": response_payload,
            "request_id": response.headers.get("x-request-id"),
            "credential_url": open_badge_url,
            "open_badge_id": open_badge_url,
            "provenance_url": _build_elevenid_provenance_url(
                credential=credential,
                platform=platform,
                delivery_record=delivery_record,
            ),
        },
    )


async def _sync_canvas_badgr_assertion_status(
    *,
    credential: IssuedCredential,
    delivery_record: CredentialDeliveryRecord,
    lifecycle_action: str,
    reason: str | None,
    secret_resolver: CanvasSecretResolver | None = None,
) -> CanvasCredentialsStatusSyncResult:
    normalized_action = lifecycle_action.strip().lower()
    if normalized_action in {"suspend", "suspended", "reinstate", "reinstated"}:
        return CanvasCredentialsStatusSyncResult(
            metadata={
                "provider": "badgr_api",
                "status_sync_mode": "canonical_provenance_only",
                "status_sync_skipped": True,
                "status_sync_reason": (
                    "Canvas Credentials API does not expose suspend/reinstate operations; "
                    "canonical ElevenID status and provenance remain authoritative."
                ),
                "status_synced_at": datetime.now(timezone.utc).isoformat(),
                "canvas_credentials_lifecycle_mapping": {
                    "requested_action": normalized_action,
                    "external_action": None,
                    "canonical_status": credential.status.value,
                },
            }
        )
    if normalized_action not in {"revoke", "revoked"}:
        raise RuntimeError(
            f"Unsupported Canvas Credentials lifecycle action: {lifecycle_action}"
        )
    if not delivery_record.external_credential_id:
        raise RuntimeError("Canvas Credentials revoke requires external_credential_id")

    api_token = await _canvas_credentials_secret_value(
        delivery_record,
        default_secret_name="CANVAS_CREDENTIALS_API_TOKEN",
        secret_resolver=secret_resolver,
    )
    if not api_token:
        raise RuntimeError("CANVAS_CREDENTIALS_API_TOKEN is required for real Canvas Credentials status sync")

    api_base_url = _normalize_canvas_credentials_api_base_url(delivery_record)
    revoke_url = _badgr_revoke_url(delivery_record.external_credential_id, api_base_url=api_base_url)
    payload = {
        "revocation_reason": reason
        or credential.revocation_reason
        or "Canonical ElevenID credential was revoked.",
    }
    headers = _canvas_credentials_headers(api_token)

    try:
        async with httpx.AsyncClient(timeout=_CANVAS_STATUS_SYNC_TIMEOUT_SECONDS) as client:
            response = await client.request("DELETE", revoke_url, json=payload, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        body = _truncate_text(exc.response.text or "")
        raise RuntimeError(
            f"Canvas Credentials assertion revoke failed (HTTP {exc.response.status_code}): {body}"
        ) from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Canvas Credentials assertion revoke request failed: {exc}") from exc

    response_payload = _response_json_or_excerpt(response)
    return CanvasCredentialsStatusSyncResult(
        metadata={
            "provider": "badgr_api",
            "status_sync_url": revoke_url,
            "status_sync_http_status": response.status_code,
            "status_sync_response": response_payload,
            "status_sync_request_id": response.headers.get("x-request-id"),
            "status_synced_at": datetime.now(timezone.utc).isoformat(),
        }
    )


async def publish_canvas_credential_mirror(
    *,
    credential: IssuedCredential,
    transaction: IssuanceTransaction,
    platform: CanvasPlatform,
    delivery_record: CredentialDeliveryRecord,
    secret_resolver: CanvasSecretResolver | None = None,
) -> CanvasCredentialsPublishResult:
    """Publish a canonical issued credential to the Canvas Credentials bridge/API."""

    if _is_real_canvas_credentials_provider(delivery_record):
        return await _publish_canvas_badgr_assertion(
            credential=credential,
            transaction=transaction,
            platform=platform,
            delivery_record=delivery_record,
            secret_resolver=secret_resolver,
        )

    publish_url = _normalize_publish_url()
    api_token = await _canvas_credentials_secret_value(
        delivery_record,
        default_secret_name="CANVAS_CREDENTIALS_API_TOKEN",
        secret_resolver=secret_resolver,
    )
    issuer_id = _canvas_credentials_issuer_id(delivery_record)
    payload = _build_canvas_publish_payload(
        credential=credential,
        transaction=transaction,
        platform=platform,
        delivery_record=delivery_record,
        issuer_id=issuer_id,
    )
    headers = _canvas_credentials_headers(api_token)

    try:
        async with httpx.AsyncClient(timeout=_CANVAS_PUBLISH_TIMEOUT_SECONDS) as client:
            response = await client.post(publish_url, json=payload, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        body = _truncate_text(exc.response.text or "")
        raise RuntimeError(
            f"Canvas Credentials publish failed (HTTP {exc.response.status_code}): {body}"
        ) from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Canvas Credentials publish request failed: {exc}") from exc

    response_payload = _response_json_or_excerpt(response)
    external_credential_id = None
    external_issuer_id = issuer_id
    if isinstance(response_payload, dict):
        external_credential_id = (
            response_payload.get("credential_id")
            or response_payload.get("id")
            or ((response_payload.get("credential") or {}).get("id") if isinstance(response_payload.get("credential"), dict) else None)
            or ((response_payload.get("data") or {}).get("id") if isinstance(response_payload.get("data"), dict) else None)
        )
        external_issuer_id = (
            response_payload.get("issuer_id")
            or ((response_payload.get("issuer") or {}).get("id") if isinstance(response_payload.get("issuer"), dict) else None)
            or ((response_payload.get("data") or {}).get("issuer_id") if isinstance(response_payload.get("data"), dict) else None)
            or issuer_id
        )

    return CanvasCredentialsPublishResult(
        external_credential_id=str(external_credential_id) if external_credential_id is not None else None,
        external_issuer_id=str(external_issuer_id) if external_issuer_id is not None else None,
        metadata={
            "publish_url": publish_url,
            "published_at": datetime.now(timezone.utc).isoformat(),
            "http_status": response.status_code,
            "publish_response": response_payload,
            "request_id": response.headers.get("x-request-id"),
        },
    )


async def sync_canvas_credential_status(
    *,
    credential: IssuedCredential,
    platform: CanvasPlatform,
    delivery_record: CredentialDeliveryRecord,
    lifecycle_action: str,
    reason: str | None = None,
    secret_resolver: CanvasSecretResolver | None = None,
) -> CanvasCredentialsStatusSyncResult:
    """Propagate canonical credential lifecycle changes to Canvas Credentials."""

    if _is_real_canvas_credentials_provider(delivery_record):
        return await _sync_canvas_badgr_assertion_status(
            credential=credential,
            delivery_record=delivery_record,
            lifecycle_action=lifecycle_action,
            reason=reason,
            secret_resolver=secret_resolver,
        )

    sync_url = _normalize_status_sync_url()
    api_token = await _canvas_credentials_secret_value(
        delivery_record,
        default_secret_name="CANVAS_CREDENTIALS_API_TOKEN",
        secret_resolver=secret_resolver,
    )
    issuer_id = delivery_record.external_issuer_id or _canvas_credentials_issuer_id(delivery_record)
    payload = _build_canvas_status_sync_payload(
        credential=credential,
        platform=platform,
        delivery_record=delivery_record,
        lifecycle_action=lifecycle_action,
        reason=reason,
        issuer_id=issuer_id,
    )
    headers = _canvas_credentials_headers(api_token)

    try:
        async with httpx.AsyncClient(timeout=_CANVAS_STATUS_SYNC_TIMEOUT_SECONDS) as client:
            response = await client.post(sync_url, json=payload, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        body = _truncate_text(exc.response.text or "")
        raise RuntimeError(
            f"Canvas Credentials status sync failed (HTTP {exc.response.status_code}): {body}"
        ) from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Canvas Credentials status sync request failed: {exc}") from exc

    response_payload = _response_json_or_excerpt(response)
    return CanvasCredentialsStatusSyncResult(
        metadata={
            "status_sync_url": sync_url,
            "status_sync_http_status": response.status_code,
            "status_sync_response": response_payload,
            "status_sync_request_id": response.headers.get("x-request-id"),
            "status_synced_at": datetime.now(timezone.utc).isoformat(),
        }
    )


def _canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_canvas_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_payload(payload)).hexdigest()


def _coerce_headers(headers: Mapping[str, str] | Any) -> dict[str, str]:
    coerced: dict[str, str] = {}
    for key, value in headers.items():
        coerced[str(key).lower()] = str(value)
    return coerced


def verify_canvas_signature(
    *,
    raw_body: bytes,
    timestamp: str,
    signature: str,
    secret: str,
    now: int | None = None,
    tolerance_seconds: int = _CANVAS_SIGNATURE_TOLERANCE_SECONDS,
) -> bool:
    """Verify HMAC-SHA256 over ``{timestamp}.{raw_body}`` with replay window."""

    if not secret or not timestamp or not signature:
        return False

    try:
        timestamp_int = int(timestamp)
    except (TypeError, ValueError):
        return False

    current = now if now is not None else int(time.time())
    if abs(current - timestamp_int) > tolerance_seconds:
        return False

    expected_digest = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + raw_body,
        hashlib.sha256,
    ).hexdigest()
    normalized_signature = signature.strip()
    if normalized_signature.startswith("sha256="):
        normalized_signature = normalized_signature.split("=", 1)[1]
    return hmac.compare_digest(normalized_signature, expected_digest)


def map_canvas_event_to_mip_evidence_receipt(
    event: CanvasEvidenceEvent,
    *,
    payload_hash: str | None = None,
) -> MipEvidenceReceipt:
    """Map Canvas into a provider-neutral MIP evidence primitive."""

    return canvas_completion_to_mip_evidence_receipt(
        event,
        application_id=event.application_id,
        payload_hash=payload_hash,
    )


def _ags_score_percent(event: CanvasAgsScoreEvent) -> float | None:
    if event.score_percent is not None:
        return event.score_percent
    if event.score_given is None or event.score_maximum in (None, 0):
        return None
    return round((float(event.score_given) / float(event.score_maximum)) * 100, 6)


def _ags_evidence_type(event: CanvasAgsScoreEvent) -> str:
    if event.evidence_type:
        return event.evidence_type
    if event.canvas_quiz_id:
        return "canvas.quiz_score"
    return "canvas.assignment_score"


def _ags_completion_status(event: CanvasAgsScoreEvent) -> bool:
    if event.completed is not None:
        return event.completed
    progress = str(event.activity_progress or "").lower()
    grading = str(event.grading_progress or "").lower()
    return progress in {"completed", "submitted"} or grading in {"fullygraded", "fully_graded", "graded"}


def _ags_submitted_status(event: CanvasAgsScoreEvent) -> bool | None:
    if event.submitted is not None:
        return event.submitted
    progress = str(event.activity_progress or "").lower()
    if progress in {"submitted", "completed"}:
        return True
    return None


def _ags_subject_identifier(event: CanvasAgsScoreEvent) -> str:
    if event.learner_email:
        return event.learner_email
    return f"canvas:{event.canvas_account_id}:user:{event.canvas_user_id}"


def map_canvas_ags_score_to_evidence_event(event: CanvasAgsScoreEvent) -> CanvasEvidenceEvent:
    """Normalize a Canvas AGS score payload into the existing Canvas evidence contract."""

    completion_at = event.graded_at or event.submitted_at or event.timestamp or datetime.now(timezone.utc).isoformat()
    score = event.score if event.score is not None else event.score_given
    line_item_id = event.line_item_id or event.canvas_assignment_id or event.canvas_quiz_id
    achievement_name = event.line_item_label or line_item_id or "Canvas AGS score"
    return CanvasEvidenceEvent(
        canvas_event_id=event.canvas_event_id,
        organization_id=event.organization_id,
        credential_template_id=event.credential_template_id,
        canvas_account_id=event.canvas_account_id,
        canvas_course_id=event.canvas_course_id,
        canvas_course_name=event.canvas_course_name or "Canvas course",
        canvas_enrollment_id=event.canvas_enrollment_id or f"canvas-user:{event.canvas_user_id}",
        canvas_user_id=event.canvas_user_id,
        learner_email=_ags_subject_identifier(event),
        learner_name=event.learner_name,
        learner_given_name=event.learner_given_name,
        learner_family_name=event.learner_family_name,
        achievement_name=achievement_name,
        achievement_description=f"Canvas AGS score for {achievement_name}",
        completion_at=completion_at,
        application_id=event.application_id,
        evidence_type=_ags_evidence_type(event),
        canvas_assignment_id=event.canvas_assignment_id or event.line_item_id,
        canvas_module_id=event.canvas_module_id,
        canvas_quiz_id=event.canvas_quiz_id,
        submitted=_ags_submitted_status(event),
        completed=_ags_completion_status(event),
        passed=event.passed,
        score=score,
        score_percent=_ags_score_percent(event),
    )


def _nrps_subject_identifier(event: CanvasNrpsMembershipEvent) -> str:
    if event.learner_email:
        return event.learner_email
    return f"canvas:{event.canvas_account_id}:user:{event.canvas_user_id}"


def _nrps_membership_active(event: CanvasNrpsMembershipEvent) -> bool:
    if event.eligible is not None:
        return event.eligible
    status = str(event.membership_status or "").lower()
    return status in {"active", "enrolled", "current", "eligible", ""}


def map_canvas_nrps_membership_to_evidence_event(event: CanvasNrpsMembershipEvent) -> CanvasEvidenceEvent:
    """Normalize Canvas NRPS membership into the existing Canvas evidence contract."""

    status_text = event.membership_status or ("eligible" if _nrps_membership_active(event) else "ineligible")
    return CanvasEvidenceEvent(
        canvas_event_id=event.canvas_event_id,
        organization_id=event.organization_id,
        credential_template_id=event.credential_template_id,
        canvas_account_id=event.canvas_account_id,
        canvas_course_id=event.canvas_course_id,
        canvas_course_name=event.canvas_course_name or "Canvas course",
        canvas_enrollment_id=event.canvas_enrollment_id or event.membership_id or f"canvas-user:{event.canvas_user_id}",
        canvas_user_id=event.canvas_user_id,
        learner_email=_nrps_subject_identifier(event),
        learner_name=event.learner_name,
        learner_given_name=event.learner_given_name,
        learner_family_name=event.learner_family_name,
        achievement_name="Canvas roster membership",
        achievement_description=f"Canvas NRPS membership status: {status_text}",
        completion_at=event.timestamp or datetime.now(timezone.utc).isoformat(),
        application_id=event.application_id,
        evidence_type=event.evidence_type,
        completed=_nrps_membership_active(event),
        passed=_nrps_membership_active(event),
        roles=event.roles,
        membership_status=status_text,
        eligible=_nrps_membership_active(event),
    )


def _default_canvas_evidence_requirements() -> list[Any]:
    return ["canvas.course_completion"]


def _effective_evidence_requirements(runtime_config: Any | None, template: Any | None) -> list[Any]:
    runtime_requirements = list(getattr(runtime_config, "evidence_requirements", None) or [])
    if runtime_requirements:
        return runtime_requirements
    template_requirements = list(getattr(template, "evidence_requirements", None) or [])
    if template_requirements:
        return template_requirements
    return _default_canvas_evidence_requirements()


def _requirement_evidence_type(requirement: Any) -> str:
    if isinstance(requirement, str):
        return requirement
    if isinstance(requirement, dict):
        for key in ("fact_type", "evidence_type", "type"):
            value = requirement.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _requirement_provider(requirement: Any) -> str:
    if not isinstance(requirement, dict):
        return ""
    provider = requirement.get("provider")
    return provider if isinstance(provider, str) else ""


def _event_matches_any_requirement(event: CanvasEvidenceEvent, requirements: list[Any]) -> bool:
    for requirement in requirements:
        provider = _requirement_provider(requirement)
        if provider and provider != "canvas":
            continue
        evidence_type = _requirement_evidence_type(requirement)
        if not evidence_type or evidence_type == "EXTERNAL_FACT" or evidence_type == event.evidence_type:
            return True
    return False


def _canvas_scope_from_event(event: CanvasEvidenceEvent) -> dict[str, Any]:
    scope = {
        "canvas_account_id": event.canvas_account_id,
        "course_id": event.canvas_course_id,
        "enrollment_id": event.canvas_enrollment_id,
        "user_id": event.canvas_user_id,
    }
    optional_fields = {
        "assignment_id": event.canvas_assignment_id,
        "module_id": event.canvas_module_id,
        "quiz_id": event.canvas_quiz_id,
    }
    scope.update({key: value for key, value in optional_fields.items() if value is not None})
    return scope


async def _resolve_evidence_runtime_config(
    *,
    event: CanvasEvidenceEvent,
    repo: IIssuanceRepository,
    app: Application,
    template: ApplicationTemplate | None,
) -> tuple[CanvasEvidenceEvent, CanvasRuntimeConfig]:
    organization_id = event.organization_id or app.organization_id
    platform, binding = await resolve_canvas_program_binding_for_scope(
        repo=repo,
        organization_id=organization_id,
        canvas_account_id=event.canvas_account_id,
        actual_scope=_canvas_scope_from_event(event),
        application_template_id=app.application_template_id,
    )
    if platform is not None and binding is not None:
        if event.credential_template_id and event.credential_template_id != binding.credential_template_id:
            raise HTTPException(status_code=409, detail="Canvas evidence credential template does not match program binding")
        updated_event = event.model_copy(
            update={
                "organization_id": binding.organization_id,
                "credential_template_id": event.credential_template_id or binding.credential_template_id,
            }
        )
        return updated_event, canvas_runtime_from_program_binding(
            platform=platform,
            binding=binding,
        )

    raise HTTPException(
        status_code=404,
        detail="No Canvas program binding found for canvas_account_id, application template, and scope",
    )


def _canvas_assertion_from_event(event: CanvasEvidenceEvent) -> dict[str, Any]:
    assertion: dict[str, Any] = {
        "completed": True if event.completed is None else event.completed,
        "completion_at": event.completion_at,
    }
    optional_fields = {
        "submitted": event.submitted,
        "passed": event.passed,
        "score": event.score,
        "score_percent": event.score_percent,
        "course_name": event.canvas_course_name,
        "achievement_name": event.achievement_name,
        "roles": event.roles,
        "membership_status": event.membership_status,
        "eligible": event.eligible,
    }
    assertion.update({key: value for key, value in optional_fields.items() if value is not None})
    return assertion


def _evidence_fact_to_dict(fact: EvidenceFact) -> dict[str, Any]:
    return {
        "id": fact.id,
        "organization_id": fact.organization_id,
        "application_id": fact.application_id,
        "subject_id": fact.subject_id,
        "provider": fact.provider,
        "fact_type": fact.fact_type,
        "scope": fact.scope,
        "assertion": fact.assertion,
        "verification": fact.verification,
        "source": fact.source,
        "created_at": fact.created_at.isoformat(),
    }


def _canvas_evidence_fact_from_receipt(
    *,
    event: CanvasEvidenceEvent,
    evidence_receipt: MipEvidenceReceipt,
    receipt_id: str,
    payload_hash: str,
    verified_at: datetime,
    verification_method: str = "SIGNED_WEBHOOK",
) -> EvidenceFact:
    return EvidenceFact(
        organization_id=event.organization_id or "",
        application_id=event.application_id,
        subject_id=event.learner_email,
        provider="canvas",
        fact_type=evidence_receipt.evidence_type,
        scope=_canvas_scope_from_event(event),
        assertion=_canvas_assertion_from_event(event),
        verification={
            "method": verification_method,
            "status": "VERIFIED",
            "verified_at": verified_at.isoformat(),
        },
        source={
            "receipt_id": receipt_id,
            "provider_event_id": event.canvas_event_id,
            "payload_hash": payload_hash,
            "mip_receipt": evidence_receipt.to_dict(),
        },
        created_at=verified_at,
    )


def _coerce_evidence_response(payload: Any, *, source_event_id: str, replayed: bool) -> CanvasEvidenceEventResponse:
    if isinstance(payload, CanvasEvidenceEventResponse):
        return payload.model_copy(update={"source_event_id": source_event_id, "replayed": replayed})
    if hasattr(payload, "model_dump"):
        raw = payload.model_dump()
    elif isinstance(payload, dict):
        raw = dict(payload)
    else:
        raw = dict(vars(payload))
    raw["source_event_id"] = source_event_id
    raw["replayed"] = replayed
    return CanvasEvidenceEventResponse.model_validate(raw)


def _parse_signed_canvas_payload(
    *,
    raw_body: bytes,
    headers: Mapping[str, str] | Any,
) -> dict[str, Any]:
    normalized_headers = _coerce_headers(headers)
    secret = _read_secret_value("CANVAS_CREDENTIALS_SHARED_SECRET")
    timestamp = normalized_headers.get(CANVAS_TIMESTAMP_HEADER, "")
    signature = normalized_headers.get(CANVAS_SIGNATURE_HEADER, "")

    if not verify_canvas_signature(
        raw_body=raw_body,
        timestamp=timestamp,
        signature=signature,
        secret=secret,
    ):
        raise HTTPException(status_code=403, detail="Invalid Canvas event signature")

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Malformed Canvas event payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Canvas event payload must be a JSON object")
    return payload


async def _process_canvas_evidence_event_model(
    *,
    event: CanvasEvidenceEvent,
    payload_hash: str,
    repo: IIssuanceRepository,
    audit_source: str = "canvas_evidence_event",
    verification_method: str = "SIGNED_WEBHOOK",
    required_feature_flag: str = "enable_canvas_evidence",
    issuer_context_applier: Callable[[IssuanceTransaction], Awaitable[None]] | None = None,
) -> CanvasEvidenceEventResponse:
    existing_receipt = await repo.get_canvas_event_receipt(
        event.canvas_event_id,
        event.canvas_account_id,
    )
    if existing_receipt is not None:
        if existing_receipt.payload_hash != payload_hash:
            raise HTTPException(status_code=409, detail="canvas_event_id already exists with different payload")
        if existing_receipt.status != "evidence_received":
            raise HTTPException(status_code=409, detail="canvas_event_id already exists for a different Canvas flow")
        existing_receipt.last_seen_at = datetime.now(timezone.utc)
        await repo.save_canvas_event_receipt(existing_receipt)
        return _coerce_evidence_response(
            existing_receipt.issuance_response,
            source_event_id=event.canvas_event_id,
            replayed=True,
        )

    app = await repo.get_application(event.application_id)
    if app is None:
        raise HTTPException(status_code=404, detail="Application not found")

    template = await repo.get_application_template(app.application_template_id)
    event, runtime_config = await _resolve_evidence_runtime_config(
        event=event,
        repo=repo,
        app=app,
        template=template,
    )
    if not canvas_feature_enabled(runtime_config, required_feature_flag):
        raise HTTPException(
            status_code=409,
            detail=f"Canvas feature gate is disabled: {required_feature_flag}",
        )
    if app.organization_id != event.organization_id:
        raise HTTPException(status_code=409, detail="Canvas evidence organization does not match application")
    if app.status != ApplicationStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot submit evidence for application in {app.status} status")

    if runtime_config.application_template_id and app.application_template_id != runtime_config.application_template_id:
        raise HTTPException(status_code=409, detail="Canvas runtime binding application template does not match application")

    if (
        template is not None
        and template.credential_template_id
        and event.credential_template_id
        and template.credential_template_id != event.credential_template_id
    ):
        raise HTTPException(status_code=409, detail="Canvas evidence credential template does not match application")

    requirements = _effective_evidence_requirements(runtime_config, template)
    if not _event_matches_any_requirement(event, requirements):
        raise HTTPException(status_code=409, detail="Canvas evidence type is not required for this application")

    evidence_receipt = map_canvas_event_to_mip_evidence_receipt(event, payload_hash=payload_hash)
    now = datetime.now(timezone.utc)
    submitted_at = now.isoformat()
    receipt = CanvasEventReceipt(
        provider_event_id=event.canvas_event_id,
        organization_id=event.organization_id,
        credential_template_id=event.credential_template_id,
        canvas_account_id=event.canvas_account_id,
        payload_hash=payload_hash,
        issuance_transaction_id=None,
        status="evidence_received",
        first_seen_at=now,
        last_seen_at=now,
    )
    evidence_fact = _canvas_evidence_fact_from_receipt(
        event=event,
        evidence_receipt=evidence_receipt,
        receipt_id=receipt.id,
        payload_hash=payload_hash,
        verified_at=now,
        verification_method=verification_method,
    )
    canvas_context = {
        "runtime_source": runtime_config.runtime_source,
        "canvas_platform_id": runtime_config.platform_id,
        "canvas_program_binding_id": runtime_config.program_binding_id,
        "deployment_profile_id": runtime_config.deployment_profile_id,
        "feature_flags": dict(runtime_config.feature_flags or {}),
        "delivery_mode": runtime_config.delivery_mode,
        "canvas_account_id": event.canvas_account_id,
        "canvas_course_id": event.canvas_course_id,
        "canvas_user_id": event.canvas_user_id,
        "canvas_enrollment_id": event.canvas_enrollment_id,
        "source_event_id": event.canvas_event_id,
        "evidence_fact_id": evidence_fact.id,
        "standard_source": audit_source,
    }
    existing_context = getattr(app, "integration_context", None) or {}
    existing_delivery = existing_context.get("delivery") if isinstance(existing_context, dict) else {}
    if not isinstance(existing_delivery, dict):
        existing_delivery = {}
    transition = await persist_evidence_fact_and_apply_policy(
        repo=repo,
        app=app,
        template=template,
        evidence_fact=evidence_fact,
        evidence_submission={
            "evidence_type": evidence_receipt.evidence_type,
            "evidence_data": evidence_receipt.evidence_data,
            "submitted_at": submitted_at,
            "source": evidence_receipt.source.to_dict(),
            "mip_primitives": evidence_receipt.to_dict(),
            "evidence_fact_ids": [evidence_fact.id],
            "verification": {
                "status": "verified",
                "method": verification_method,
                "requirements": requirements,
                "auto_approve_on_evidence": bool(getattr(runtime_config, "auto_approve_on_evidence", False)),
            },
        },
        integration_context_updates={
            "canvas": canvas_context,
            "delivery_mode": runtime_config.delivery_mode,
            "delivery": {
                **existing_delivery,
                "mode": runtime_config.delivery_mode,
            },
        },
        requirements=requirements,
        source=audit_source,
        audit_metadata={
            "provider_event_id": event.canvas_event_id,
            "canvas_account_id": event.canvas_account_id,
            "verification_method": verification_method,
        },
        binding=runtime_config,
        evaluate_policy=bool(getattr(runtime_config, "auto_approve_on_evidence", False)),
        issue_on_permit=True,
        auto_issue_on_permit=True,
        reviewer_id="canvas:auto-approval",
        review_notes="Auto-approved by MIP policy after verified Canvas evidence satisfied requirements",
        issuer_context_applier=issuer_context_applier,
    )
    policy_decision = transition.policy_decision
    tx = transition.issuance_transaction

    response = CanvasEvidenceEventResponse(
        id=evidence_receipt.source.provider_event_id,
        application_id=event.application_id,
        organization_id=event.organization_id or "",
        canvas_account_id=event.canvas_account_id,
        evidence_type=evidence_receipt.evidence_type,
        status="evidence_received",
        application_status=app.status.value,
        source_event_id=event.canvas_event_id,
        replayed=False,
        evidence=evidence_receipt.evidence_data,
        mip_primitives=evidence_receipt.to_dict(),
        evidence_facts=[_evidence_fact_to_dict(evidence_fact)],
        policy_decision=policy_decision.to_dict() if policy_decision else None,
    )
    receipt.issuance_transaction_id = tx.id if tx else None
    receipt.issuance_response = response.model_dump(exclude={"source_event_id", "replayed"})
    await repo.save_canvas_event_receipt(receipt)
    return response


async def process_canvas_ags_score_event(
    *,
    raw_body: bytes,
    headers: Mapping[str, str] | Any,
    repo: IIssuanceRepository,
    issuer_context_applier: Callable[[IssuanceTransaction], Awaitable[None]] | None = None,
) -> CanvasEvidenceEventResponse:
    """Validate Canvas AGS score input and convert it into MIP evidence facts."""

    payload = _parse_signed_canvas_payload(raw_body=raw_body, headers=headers)
    try:
        ags_event = CanvasAgsScoreEvent.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    evidence_event = map_canvas_ags_score_to_evidence_event(ags_event)
    return await _process_canvas_evidence_event_model(
        event=evidence_event,
        payload_hash=_hash_canvas_payload(payload),
        repo=repo,
        audit_source="canvas_ags_score_event",
        verification_method="SIGNED_AGS_SCORE",
        required_feature_flag="enable_canvas_ags",
        issuer_context_applier=issuer_context_applier,
    )


async def process_canvas_nrps_membership_event(
    *,
    raw_body: bytes,
    headers: Mapping[str, str] | Any,
    repo: IIssuanceRepository,
    issuer_context_applier: Callable[[IssuanceTransaction], Awaitable[None]] | None = None,
) -> CanvasEvidenceEventResponse:
    """Validate Canvas NRPS membership input and convert it into MIP evidence facts."""

    payload = _parse_signed_canvas_payload(raw_body=raw_body, headers=headers)
    try:
        nrps_event = CanvasNrpsMembershipEvent.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    evidence_event = map_canvas_nrps_membership_to_evidence_event(nrps_event)
    return await _process_canvas_evidence_event_model(
        event=evidence_event,
        payload_hash=_hash_canvas_payload(payload),
        repo=repo,
        audit_source="canvas_nrps_membership_event",
        verification_method="SIGNED_NRPS_MEMBERSHIP",
        required_feature_flag="enable_canvas_nrps",
        issuer_context_applier=issuer_context_applier,
    )


async def process_canvas_evidence_event(
    *,
    raw_body: bytes,
    headers: Mapping[str, str] | Any,
    repo: IIssuanceRepository,
    issuer_context_applier: Callable[[IssuanceTransaction], Awaitable[None]] | None = None,
) -> CanvasEvidenceEventResponse:
    """Validate, dedupe, and attach Canvas evidence to an ElevenID application."""

    normalized_headers = _coerce_headers(headers)
    secret = _read_secret_value("CANVAS_CREDENTIALS_SHARED_SECRET")
    timestamp = normalized_headers.get(CANVAS_TIMESTAMP_HEADER, "")
    signature = normalized_headers.get(CANVAS_SIGNATURE_HEADER, "")

    if not verify_canvas_signature(
        raw_body=raw_body,
        timestamp=timestamp,
        signature=signature,
        secret=secret,
    ):
        raise HTTPException(status_code=403, detail="Invalid Canvas event signature")

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Malformed Canvas event payload") from exc

    try:
        event = CanvasEvidenceEvent.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    payload_hash = _hash_canvas_payload(payload)
    return await _process_canvas_evidence_event_model(
        event=event,
        payload_hash=payload_hash,
        repo=repo,
        audit_source="canvas_evidence_event",
        verification_method="SIGNED_WEBHOOK",
        required_feature_flag="enable_canvas_evidence",
        issuer_context_applier=issuer_context_applier,
    )
