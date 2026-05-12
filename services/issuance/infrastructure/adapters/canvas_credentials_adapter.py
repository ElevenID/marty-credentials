"""Canvas credential event adapter for wallet-native issuance."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from issuance.application.mip_integration_primitives import (
    MipCredentialIssuanceCommand,
    MipEvidenceReceipt,
    canvas_completion_to_mip_evidence_receipt,
    canvas_completion_to_mip_issuance_command,
)
from issuance.domain.entities import ApplicationStatus, CanvasEventReceipt
from issuance.domain.ports import IIssuanceRepository


CANVAS_SIGNATURE_HEADER = "x-canvas-signature-256"
CANVAS_TIMESTAMP_HEADER = "x-canvas-timestamp"
_CANVAS_SIGNATURE_TOLERANCE_SECONDS = int(os.environ.get("CANVAS_CREDENTIALS_SIGNATURE_TOLERANCE_SECONDS", "300"))


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


class CanvasCredentialEventResponse(BaseModel):
    """Issuance response extended with Canvas replay metadata."""

    id: str
    organization_id: str
    credential_template_id: str
    status: str
    credential_offer_uri: str
    credential_offer_uris: dict[str, str] = Field(default_factory=dict)
    credential_offer_labels: dict[str, str] = Field(default_factory=dict)
    pre_auth_code: str
    expires_at: str
    source_event_id: str
    replayed: bool = False


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


class CanvasInitiateIssuanceRequest(BaseModel):
    """Minimal request shape needed by the existing issuance pipeline."""

    organization_id: str
    credential_template_id: str | None = None
    applicant_id: str | None = None
    subject_did: str | None = None
    holder_did: str | None = None
    claims: dict[str, Any] = Field(default_factory=dict)


IssueCredentialFn = Callable[[CanvasInitiateIssuanceRequest, Request | None, IIssuanceRepository], Awaitable[Any]]


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


def map_canvas_event_to_mip_issuance_command(
    event: CanvasCredentialEvent,
    *,
    payload_hash: str | None = None,
) -> MipCredentialIssuanceCommand:
    """Map Canvas into a provider-neutral MIP issuance primitive."""

    return canvas_completion_to_mip_issuance_command(event, payload_hash=payload_hash)


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


def mip_issuance_command_to_request(command: MipCredentialIssuanceCommand) -> CanvasInitiateIssuanceRequest:
    """Adapt a MIP issuance primitive into the current OID4VCI request."""

    return CanvasInitiateIssuanceRequest(
        organization_id=command.organization_id,
        credential_template_id=command.credential_template_id,
        applicant_id=command.subject_id,
        claims=command.claims,
    )


def map_canvas_event_to_issuance_request(event: CanvasCredentialEvent) -> CanvasInitiateIssuanceRequest:
    """Map a Canvas completion event into the existing issuance request shape."""

    return mip_issuance_command_to_request(map_canvas_event_to_mip_issuance_command(event))


async def _resolve_event_connector(
    event: CanvasCredentialEvent,
    repo: IIssuanceRepository,
    *,
    require_connector: bool = False,
    require_direct_issue_enabled: bool = False,
) -> tuple[CanvasCredentialEvent, Any | None]:
    connector = await repo.get_canvas_connector_by_account_id(event.canvas_account_id)
    if connector is None:
        if require_connector or not (event.organization_id and event.credential_template_id):
            raise HTTPException(
                status_code=404,
                detail="No enabled Canvas connector found for canvas_account_id",
            )
        return event, None

    if require_direct_issue_enabled and not getattr(connector, "direct_issue_enabled", False):
        raise HTTPException(
            status_code=409,
            detail=(
                "Canvas credential events are disabled for this connector; "
                "submit Canvas completion to /v1/integrations/canvas/evidence-events"
            ),
        )

    if event.organization_id and event.organization_id != connector.organization_id:
        raise HTTPException(status_code=409, detail="Canvas event organization does not match connector")
    if event.credential_template_id and event.credential_template_id != connector.credential_template_id:
        raise HTTPException(status_code=409, detail="Canvas event credential template does not match connector")

    updates: dict[str, Any] = {}
    if not event.organization_id:
        updates["organization_id"] = connector.organization_id
    if not event.credential_template_id:
        updates["credential_template_id"] = connector.credential_template_id
    return event.model_copy(update=updates), connector


def _default_canvas_evidence_requirements() -> list[str]:
    return ["canvas.course_completion"]


def _effective_evidence_requirements(connector: Any | None, template: Any | None) -> list[str]:
    connector_requirements = list(getattr(connector, "evidence_requirements", None) or [])
    if connector_requirements:
        return connector_requirements
    template_requirements = list(getattr(template, "evidence_requirements", None) or [])
    if template_requirements:
        return template_requirements
    return _default_canvas_evidence_requirements()


def _submitted_evidence_types(app: Any) -> set[str]:
    submitted: set[str] = set()
    for submission in getattr(app, "evidence_submissions", []) or []:
        evidence_type = submission.get("evidence_type") if isinstance(submission, dict) else None
        if isinstance(evidence_type, str) and evidence_type:
            submitted.add(evidence_type)
    return submitted


def _canvas_evidence_requirements_satisfied(app: Any, requirements: list[str]) -> bool:
    submitted = _submitted_evidence_types(app)
    return all(requirement in submitted for requirement in requirements)


def _coerce_issuance_response(payload: Any, *, source_event_id: str, replayed: bool) -> CanvasCredentialEventResponse:
    if isinstance(payload, CanvasCredentialEventResponse):
        return payload.model_copy(update={"source_event_id": source_event_id, "replayed": replayed})
    if hasattr(payload, "model_dump"):
        raw = payload.model_dump()
    elif isinstance(payload, dict):
        raw = dict(payload)
    else:
        raw = dict(vars(payload))
    raw["source_event_id"] = source_event_id
    raw["replayed"] = replayed
    return CanvasCredentialEventResponse.model_validate(raw)


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


async def process_canvas_credential_event(
    *,
    raw_body: bytes,
    headers: Mapping[str, str] | Any,
    repo: IIssuanceRepository,
    issue_credential: IssueCredentialFn,
    http_request: Request | None = None,
) -> CanvasCredentialEventResponse:
    """Validate, dedupe, and issue a credential for a Canvas completion event."""

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
        event = CanvasCredentialEvent.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    event, _connector = await _resolve_event_connector(
        event,
        repo,
        require_connector=True,
        require_direct_issue_enabled=True,
    )

    payload_hash = _hash_canvas_payload(payload)
    existing_receipt = await repo.get_canvas_event_receipt(
        event.canvas_event_id,
        event.canvas_account_id,
    )
    if existing_receipt is not None:
        if existing_receipt.payload_hash != payload_hash:
            raise HTTPException(status_code=409, detail="canvas_event_id already exists with different payload")
        existing_receipt.last_seen_at = datetime.now(timezone.utc)
        await repo.save_canvas_event_receipt(existing_receipt)
        return _coerce_issuance_response(
            existing_receipt.issuance_response,
            source_event_id=event.canvas_event_id,
            replayed=True,
        )

    issuance_command = map_canvas_event_to_mip_issuance_command(event, payload_hash=payload_hash)
    issuance_request = mip_issuance_command_to_request(issuance_command)
    issuance_response = await issue_credential(issuance_request, http_request, repo)
    response = _coerce_issuance_response(
        issuance_response,
        source_event_id=event.canvas_event_id,
        replayed=False,
    )
    now = datetime.now(timezone.utc)
    receipt = CanvasEventReceipt(
        provider_event_id=event.canvas_event_id,
        organization_id=event.organization_id,
        credential_template_id=event.credential_template_id,
        canvas_account_id=event.canvas_account_id,
        payload_hash=payload_hash,
        issuance_transaction_id=response.id,
        issuance_response=response.model_dump(exclude={"source_event_id", "replayed"}),
        status="processed",
        first_seen_at=now,
        last_seen_at=now,
    )
    await repo.save_canvas_event_receipt(receipt)
    return response


async def process_canvas_evidence_event(
    *,
    raw_body: bytes,
    headers: Mapping[str, str] | Any,
    repo: IIssuanceRepository,
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

    event, connector = await _resolve_event_connector(
        event,
        repo,
        require_connector=True,
    )
    payload_hash = _hash_canvas_payload(payload)
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
    if app.organization_id != event.organization_id:
        raise HTTPException(status_code=409, detail="Canvas evidence organization does not match application")
    if app.status != ApplicationStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot submit evidence for application in {app.status} status")

    if connector is not None and connector.application_template_id and app.application_template_id != connector.application_template_id:
        raise HTTPException(status_code=409, detail="Canvas connector application template does not match application")

    template = await repo.get_application_template(app.application_template_id)
    if (
        template is not None
        and template.credential_template_id
        and event.credential_template_id
        and template.credential_template_id != event.credential_template_id
    ):
        raise HTTPException(status_code=409, detail="Canvas evidence credential template does not match application")

    requirements = _effective_evidence_requirements(connector, template)
    if event.evidence_type not in requirements:
        raise HTTPException(status_code=409, detail="Canvas evidence type is not required for this application")

    evidence_receipt = map_canvas_event_to_mip_evidence_receipt(event, payload_hash=payload_hash)
    now = datetime.now(timezone.utc)
    submitted_at = now.isoformat()
    canvas_context = {
        "connector_id": getattr(connector, "id", None),
        "canvas_account_id": event.canvas_account_id,
        "canvas_course_id": event.canvas_course_id,
        "canvas_user_id": event.canvas_user_id,
        "canvas_enrollment_id": event.canvas_enrollment_id,
        "source_event_id": event.canvas_event_id,
    }
    app.evidence_submissions.append(
        {
            "evidence_type": evidence_receipt.evidence_type,
            "evidence_data": evidence_receipt.evidence_data,
            "submitted_at": submitted_at,
            "source": evidence_receipt.source.to_dict(),
            "mip_primitives": evidence_receipt.to_dict(),
            "verification": {
                "status": "verified",
                "requirements": requirements,
                "auto_approve_on_evidence": bool(getattr(connector, "auto_approve_on_evidence", False)),
            },
        }
    )
    app.integration_context = {
        **(getattr(app, "integration_context", None) or {}),
        "canvas": canvas_context,
    }
    if getattr(connector, "auto_approve_on_evidence", False) and _canvas_evidence_requirements_satisfied(app, requirements):
        app.status = ApplicationStatus.APPROVED
        app.review_notes = "Auto-approved after verified Canvas evidence satisfied all requirements"
        app.reviewer_id = "canvas:auto-approval"
        app.reviewed_at = now
    app.updated_at = now
    await repo.save_application(app)

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
    )
    now = datetime.now(timezone.utc)
    receipt = CanvasEventReceipt(
        provider_event_id=event.canvas_event_id,
        organization_id=event.organization_id,
        credential_template_id=event.credential_template_id,
        canvas_account_id=event.canvas_account_id,
        payload_hash=payload_hash,
        issuance_transaction_id=None,
        issuance_response=response.model_dump(exclude={"source_event_id", "replayed"}),
        status="evidence_received",
        first_seen_at=now,
        last_seen_at=now,
    )
    await repo.save_canvas_event_receipt(receipt)
    return response
