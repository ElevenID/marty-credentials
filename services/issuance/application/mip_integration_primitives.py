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
class MipCredentialIssuanceCommand:
    """A provider event normalized into a MIP credential issuance primitive."""

    organization_id: str
    credential_template_id: str | None
    subject_id: str
    claims: dict[str, Any]
    source: MipExternalEventRef
    protocol: str = MIP_PROTOCOL_OID4VCI_PRE_AUTH
    action: str = MIP_ACTION_CREDENTIALS_ISSUE
    resource_type: str = MIP_RESOURCE_CREDENTIAL_TEMPLATE

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["source"] = self.source.to_dict()
        return payload


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
class MipIntegrationPlan:
    """Provider-neutral plan for an organization-scoped integration flow."""

    provider: str
    organization_id: str
    connector_id: str
    mode: str
    primitives: list[str]
    resources: dict[str, Any]
    protocols: list[str]
    actions: list[str]
    endpoints: dict[str, str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MipLtiExperienceLaunch:
    """A verified LTI launch normalized as an ElevenID experience handoff."""

    organization_id: str
    connector_id: str
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


@dataclass(frozen=True)
class MipConnectorBinding:
    """Organization-scoped external trust and protocol binding."""

    provider: str
    organization_id: str
    provider_account_id: str
    credential_template_id: str
    enabled: bool
    primitives: list[str]
    resources: dict[str, Any]
    protocols: list[str]
    actions: list[str]
    trust: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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


def canvas_completion_to_mip_issuance_command(
    event: Any,
    *,
    payload_hash: str | None = None,
) -> MipCredentialIssuanceCommand:
    """Normalize a Canvas completion into a MIP OID4VCI issuance command."""

    given_name, family_name = _split_external_name(event)
    claims = {
        "email": event.learner_email,
        "given_name": given_name,
        "family_name": family_name,
        "achievement_name": event.achievement_name,
        "achievement_description": event.achievement_description or "",
        "issued_at": event.completion_at,
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
        event_type="canvas.course_completion",
        subject_id=event.learner_email,
        signature_scheme=MIP_SIGNATURE_HMAC_SHA256_TIMESTAMPED,
        payload_hash=payload_hash,
        attributes={
            "canvas_course_id": event.canvas_course_id,
            "canvas_enrollment_id": event.canvas_enrollment_id,
            "canvas_user_id": event.canvas_user_id,
        },
    )
    return MipCredentialIssuanceCommand(
        organization_id=event.organization_id or "",
        credential_template_id=event.credential_template_id,
        subject_id=event.learner_email,
        claims=claims,
        source=source,
    )


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


def canvas_evidence_flow_to_mip_plan(
    connector: Any,
    *,
    application_id: str | None = None,
    application_template_id: str | None = None,
    canvas_course_id: str | None = None,
    canvas_user_id: str | None = None,
    evidence_requirements: list[str] | None = None,
    auto_issue_on_completion: bool = False,
) -> MipIntegrationPlan:
    """Describe ElevenID-orchestrated Canvas evidence collection."""

    primitives = [
        "organization_connector",
        "application_evidence_request",
        "signed_evidence_receipt",
        "application_evidence_submission",
    ]
    actions = [
        MIP_ACTION_INTEGRATIONS_READ,
        MIP_ACTION_INTEGRATIONS_WRITE,
        MIP_ACTION_APPLICATIONS_WRITE,
        MIP_ACTION_WEBHOOKS_WRITE,
    ]
    if auto_issue_on_completion:
        primitives.append("oid4vci_pre_authorized_issuance_gate")
        actions.append(MIP_ACTION_CREDENTIALS_ISSUE)

    organization_id = _getattr_text(connector, "organization_id")
    credential_template_id = _getattr_text(connector, "credential_template_id")
    return MipIntegrationPlan(
        provider=MIP_PROVIDER_CANVAS,
        organization_id=organization_id,
        connector_id=_getattr_text(connector, "id"),
        mode="elevenid_orchestrated_canvas_evidence",
        primitives=primitives,
        resources={
            "integration_connector": {
                "type": MIP_RESOURCE_INTEGRATION_CONNECTOR,
                "id": getattr(connector, "id", None),
            },
            "organization": {
                "type": MIP_RESOURCE_ORGANIZATION,
                "id": organization_id,
            },
            "application": {
                "type": MIP_RESOURCE_APPLICATION,
                "id": application_id,
            },
            "credential_template": {
                "type": MIP_RESOURCE_CREDENTIAL_TEMPLATE,
                "id": credential_template_id,
            },
            "application_template": {
                "type": MIP_RESOURCE_APPLICATION_TEMPLATE,
                "id": application_template_id or getattr(connector, "application_template_id", None),
            },
            "webhook_endpoint": {
                "type": MIP_RESOURCE_WEBHOOK_ENDPOINT,
                "provider": MIP_PROVIDER_CANVAS,
                "event": "canvas.course_completion",
                "path": "/v1/integrations/canvas/evidence-events",
            },
        },
        protocols=[
            MIP_PROTOCOL_SIGNED_EVIDENCE_RECEIPT,
            MIP_PROTOCOL_OID4VCI_PRE_AUTH,
        ],
        actions=actions,
        endpoints={
            "evidence_receipt": "/v1/integrations/canvas/evidence-events",
            "credential_event": "/v1/integrations/canvas/credential-events",
        },
        metadata={
            "application_id": application_id,
            "application_template_id": application_template_id,
            "canvas_account_id": _getattr_text(connector, "canvas_account_id"),
            "canvas_course_id": canvas_course_id,
            "canvas_user_id": canvas_user_id,
            "evidence_requirements": evidence_requirements or ["canvas.course_completion"],
            "auto_issue_on_completion": auto_issue_on_completion,
            "flow_mode": getattr(connector, "flow_mode", "elevenid_orchestrated_canvas_evidence"),
            "direct_issue_enabled": bool(getattr(connector, "direct_issue_enabled", False)),
            "auto_approve_on_evidence": bool(getattr(connector, "auto_approve_on_evidence", False)),
        },
    )


def canvas_lti_launch_to_mip_experience(
    connector: Any,
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
        provider_account_id=_getattr_text(connector, "canvas_account_id"),
        provider_event_id=state,
        event_type="canvas.lti_launch",
        subject_id=subject,
        signature_scheme=MIP_PROTOCOL_OIDC_ID_TOKEN,
        attributes={
            "issuer": verified_launch.get("issuer"),
            "deployment_id": verified_launch.get("deployment_id"),
            "canvas_context_id": context.get("id"),
            "roles": verified_launch.get("roles", []),
        },
    )
    return MipLtiExperienceLaunch(
        organization_id=_getattr_text(connector, "organization_id"),
        connector_id=_getattr_text(connector, "id"),
        provider_account_id=_getattr_text(connector, "canvas_account_id"),
        state=state,
        subject_id=subject,
        launch_url=launch_url,
        source=source,
        context={
            "connector_id": getattr(connector, "id", None),
            "canvas_account_id": _getattr_text(connector, "canvas_account_id"),
            "canvas_context": context,
            "learner_identity": verified_launch.get("learner_identity") or {},
            "roles": verified_launch.get("roles", []),
        },
    )


def canvas_connector_to_mip_binding(connector: Any) -> MipConnectorBinding:
    """Describe a Canvas connector as organization-scoped MIP primitives."""

    primitives = [
        "organization_connector",
        "webhook_endpoint",
        "signed_inbound_event",
        "credential_template_binding",
        "application_evidence_request",
        "signed_evidence_receipt",
        "oid4vci_pre_authorized_issuance",
    ]
    protocols = [MIP_PROTOCOL_OID4VCI_PRE_AUTH, MIP_PROTOCOL_SIGNED_EVIDENCE_RECEIPT]
    actions = [
        MIP_ACTION_INTEGRATIONS_READ,
        MIP_ACTION_INTEGRATIONS_WRITE,
        MIP_ACTION_WEBHOOKS_WRITE,
        MIP_ACTION_APPLICATIONS_WRITE,
        MIP_ACTION_CREDENTIALS_ISSUE,
    ]
    trust: dict[str, Any] = {}

    has_lti_trust = bool(
        getattr(connector, "lti_client_id", None)
        or getattr(connector, "lti_deployment_id", None)
        or getattr(connector, "lti_issuer", None)
        or getattr(connector, "lti_jwks_url", None)
    )
    if has_lti_trust:
        primitives.extend(
            [
                "oidc_login_state",
                "oidc_id_token_verification",
                "canvas_launched_elevenid_experience",
                "jwks_trust_cache",
            ]
        )
        protocols.extend([MIP_PROTOCOL_OIDC_ID_TOKEN, MIP_PROTOCOL_LTI_1_3_OIDC, MIP_PROTOCOL_ELEVENID_EXPERIENCE])
        actions.append(MIP_ACTION_TRUST_WRITE)
        trust = {
            "issuer": getattr(connector, "lti_issuer", None),
            "client_id": getattr(connector, "lti_client_id", None),
            "deployment_id": getattr(connector, "lti_deployment_id", None),
            "jwks_uri": getattr(connector, "lti_jwks_url", None),
            "jwks_fetched_at": (
                connector.lti_jwks_fetched_at.isoformat()
                if getattr(connector, "lti_jwks_fetched_at", None)
                else None
            ),
            "jwks_expires_at": (
                connector.lti_jwks_expires_at.isoformat()
                if getattr(connector, "lti_jwks_expires_at", None)
                else None
            ),
        }

    return MipConnectorBinding(
        provider=MIP_PROVIDER_CANVAS,
        organization_id=_getattr_text(connector, "organization_id"),
        provider_account_id=_getattr_text(connector, "canvas_account_id"),
        credential_template_id=_getattr_text(connector, "credential_template_id"),
        enabled=bool(getattr(connector, "enabled", False)),
        primitives=primitives,
        resources={
            "integration_connector": {
                "type": MIP_RESOURCE_INTEGRATION_CONNECTOR,
                "id": getattr(connector, "id", None),
            },
            "organization": {
                "type": MIP_RESOURCE_ORGANIZATION,
                "id": _getattr_text(connector, "organization_id"),
            },
            "credential_template": {
                "type": MIP_RESOURCE_CREDENTIAL_TEMPLATE,
                "id": _getattr_text(connector, "credential_template_id"),
            },
            "webhook_endpoint": {
                "type": MIP_RESOURCE_WEBHOOK_ENDPOINT,
                "provider": MIP_PROVIDER_CANVAS,
                "event": "canvas.course_completion",
                "path": (
                    "/v1/integrations/canvas/credential-events"
                    if getattr(connector, "direct_issue_enabled", False)
                    else "/v1/integrations/canvas/evidence-events"
                ),
            },
            "application_template": {
                "type": MIP_RESOURCE_APPLICATION_TEMPLATE,
                "id": getattr(connector, "application_template_id", None),
            },
            "trust_profile": {
                "type": MIP_RESOURCE_TRUST_PROFILE,
                "provider": MIP_PROVIDER_CANVAS,
            },
        },
        protocols=protocols,
        actions=actions,
        trust=trust,
    )
