"""MIP protocol primitives for external integration adapters.

Provider adapters should translate external systems into these primitives before
touching service-specific infrastructure. That keeps integrations organization
scoped while issuance remains an OID4VCI infrastructure service.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


MIP_PROVIDER_CANVAS = "canvas"

MIP_ACTION_CREDENTIALS_ISSUE = "credentials:issue"
MIP_ACTION_APPLICATIONS_READ = "applications:read"
MIP_ACTION_APPLICATIONS_WRITE = "applications:write"
MIP_ACTION_WEBHOOKS_WRITE = "webhooks:write"
MIP_ACTION_TRUST_WRITE = "trust:write"
MIP_ACTION_INTEGRATIONS_READ = "integrations:read"
MIP_ACTION_INTEGRATIONS_WRITE = "integrations:write"

MIP_RESOURCE_APPLICATION = "Application"
MIP_RESOURCE_APPLICATION_TEMPLATE = "ApplicationTemplate"
MIP_RESOURCE_CREDENTIAL_TEMPLATE = "CredentialTemplate"
MIP_RESOURCE_INTEGRATION_CONNECTOR = "IntegrationConnector"
MIP_RESOURCE_ORGANIZATION = "Organization"
MIP_RESOURCE_TRUST_PROFILE = "TrustProfile"
MIP_RESOURCE_WEBHOOK_ENDPOINT = "WebhookEndpoint"

MIP_PROTOCOL_OID4VCI_PRE_AUTH = "OID4VCI_PRE_AUTH"
MIP_PROTOCOL_OIDC_ID_TOKEN = "OIDC_ID_TOKEN"
MIP_PROTOCOL_LTI_1_3_OIDC = "LTI_1_3_OIDC"
MIP_PROTOCOL_SIGNED_EVIDENCE_RECEIPT = "SIGNED_EVIDENCE_RECEIPT"
MIP_PROTOCOL_ELEVENID_EXPERIENCE = "ELEVENID_EXPERIENCE"
MIP_SIGNATURE_HMAC_SHA256_TIMESTAMPED = "HMAC_SHA256_TIMESTAMPED"


@dataclass(frozen=True)
class MipExternalEventRef:
    """Provider-neutral reference to an inbound event."""

    provider: str
    provider_account_id: str
    provider_event_id: str
    event_type: str
    subject_id: str
    signature_scheme: str | None = None
    payload_hash: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MipEvidenceReceipt:
    """A provider event normalized as evidence attached to an application."""

    organization_id: str
    application_id: str
    evidence_type: str
    subject_id: str
    evidence_data: dict[str, Any]
    source: MipExternalEventRef
    action: str = MIP_ACTION_APPLICATIONS_WRITE
    resource_type: str = MIP_RESOURCE_APPLICATION
    protocol: str = MIP_PROTOCOL_SIGNED_EVIDENCE_RECEIPT

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["source"] = self.source.to_dict()
        return payload


@dataclass(frozen=True)
class MipLtiExperienceLaunch:
    """A verified LTI launch normalized as an ElevenID experience handoff."""

    organization_id: str
    platform_id: str
    provider_account_id: str
    state: str
    subject_id: str
    launch_url: str
    source: MipExternalEventRef
    context: dict[str, Any] = field(default_factory=dict)
    action: str = MIP_ACTION_APPLICATIONS_READ
    resource_type: str = MIP_RESOURCE_APPLICATION
    protocol: str = MIP_PROTOCOL_ELEVENID_EXPERIENCE

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["source"] = self.source.to_dict()
        return payload


def _getattr_text(obj: Any, name: str) -> str:
    value = getattr(obj, name, "")
    if value is None:
        return ""
    return str(value)


def _split_external_name(event: Any) -> tuple[str, str]:
    given_name = _getattr_text(event, "learner_given_name").strip()
    family_name = _getattr_text(event, "learner_family_name").strip()
    if given_name or family_name:
        return given_name, family_name

    full_name = _getattr_text(event, "learner_name").strip()
    if not full_name:
        return "", ""
    first, _separator, rest = full_name.partition(" ")
    return first.strip(), rest.strip()


def canvas_completion_to_mip_evidence_receipt(
    event: Any,
    *,
    application_id: str,
    payload_hash: str | None = None,
) -> MipEvidenceReceipt:
    """Normalize a Canvas completion into application evidence."""

    given_name, family_name = _split_external_name(event)
    evidence_type = _getattr_text(event, "evidence_type").strip() or "canvas.course_completion"
    evidence_data = {
        "email": event.learner_email,
        "given_name": given_name,
        "family_name": family_name,
        "achievement_name": event.achievement_name,
        "achievement_description": event.achievement_description or "",
        "canvas_account_id": event.canvas_account_id,
        "canvas_course_id": event.canvas_course_id,
        "canvas_course_name": event.canvas_course_name,
        "canvas_enrollment_id": event.canvas_enrollment_id,
        "canvas_user_id": event.canvas_user_id,
        "completion_at": event.completion_at,
        "source_event_id": event.canvas_event_id,
    }
    source = MipExternalEventRef(
        provider=MIP_PROVIDER_CANVAS,
        provider_account_id=event.canvas_account_id,
        provider_event_id=event.canvas_event_id,
        event_type=evidence_type,
        subject_id=event.learner_email,
        signature_scheme=MIP_SIGNATURE_HMAC_SHA256_TIMESTAMPED,
        payload_hash=payload_hash,
        attributes={
            "canvas_course_id": event.canvas_course_id,
            "canvas_enrollment_id": event.canvas_enrollment_id,
            "canvas_user_id": event.canvas_user_id,
        },
    )
    return MipEvidenceReceipt(
        organization_id=event.organization_id or "",
        application_id=application_id,
        evidence_type=evidence_type,
        subject_id=event.learner_email,
        evidence_data=evidence_data,
        source=source,
    )


def canvas_lti_launch_to_mip_experience(
    platform: Any,
    *,
    state: str,
    verified_launch: dict[str, Any],
    launch_url: str,
) -> MipLtiExperienceLaunch:
    """Normalize a verified Canvas LTI launch into an ElevenID experience handoff."""

    subject = str(verified_launch.get("subject") or "")
    context = verified_launch.get("context") if isinstance(verified_launch.get("context"), dict) else {}
    source = MipExternalEventRef(
        provider=MIP_PROVIDER_CANVAS,
        provider_account_id=_getattr_text(platform, "canvas_account_id"),
        provider_event_id=state,
        event_type="canvas.lti_launch",
        subject_id=subject,
        signature_scheme=MIP_PROTOCOL_OIDC_ID_TOKEN,
        attributes={
            "issuer": verified_launch.get("issuer"),
            "deployment_id": verified_launch.get("deployment_id"),
            "canvas_context_id": context.get("id"),
            "roles": verified_launch.get("roles", []),
            "lti_capabilities": verified_launch.get("lti_capabilities") or {},
        },
    )
    return MipLtiExperienceLaunch(
        organization_id=_getattr_text(platform, "organization_id"),
        platform_id=_getattr_text(platform, "id"),
        provider_account_id=_getattr_text(platform, "canvas_account_id"),
        state=state,
        subject_id=subject,
        launch_url=launch_url,
        source=source,
        context={
            "canvas_platform_id": getattr(platform, "id", None),
            "canvas_account_id": _getattr_text(platform, "canvas_account_id"),
            "canvas_context": context,
            "learner_identity": verified_launch.get("learner_identity") or {},
            "roles": verified_launch.get("roles", []),
            "lti_capabilities": verified_launch.get("lti_capabilities") or {},
        },
    )
