"""Repository port interfaces for issuance service."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    ApprovalPolicySet,
    CanvasEventReceipt,
    CanvasLtiLaunchState,
    CanvasPlatform,
    CanvasProgramBinding,
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    DeliveryTarget,
    EvidenceFact,
    AuthorizationSession,
    IssuanceEvent,
    IssuanceTransaction,
    IssuedCredential,
    OrganizationIntegrationSecret,
)


class IIssuanceRepository(ABC):
    """Port for issuance data persistence."""
    
    # Transaction methods
    @abstractmethod
    async def save_transaction(self, tx: IssuanceTransaction) -> None:
        """Save or update a transaction."""
        pass
    
    @abstractmethod
    async def get_transaction(self, tx_id: str) -> IssuanceTransaction | None:
        """Get transaction by ID."""
        pass
    
    @abstractmethod
    async def get_by_pre_auth_code(self, code: str) -> IssuanceTransaction | None:
        """Get transaction by pre-authorization code."""
        pass
    
    @abstractmethod
    async def get_by_access_token(self, token: str) -> IssuanceTransaction | None:
        """Get transaction by access token."""
        pass
    
    @abstractmethod
    async def list_transactions(self, org_id: str) -> list[IssuanceTransaction]:
        """List all transactions for an organization."""
        pass
    
    # Credential methods
    @abstractmethod
    async def save_credential(self, cred: IssuedCredential) -> None:
        """Save or update a credential."""
        pass
    
    @abstractmethod
    async def get_credential(self, cred_id: str) -> IssuedCredential | None:
        """Get credential by ID."""
        pass

    @abstractmethod
    async def get_credential_by_transaction_id(self, transaction_id: str) -> IssuedCredential | None:
        """Get credential by the issuance transaction that created it."""
        pass
    
    @abstractmethod
    async def list_credentials(self, applicant_id: str) -> list[IssuedCredential]:
        """List credentials by applicant."""
        pass
    
    @abstractmethod
    async def list_credentials_by_org(self, org_id: str) -> list[IssuedCredential]:
        """List all credentials for an organization."""
        pass

    @abstractmethod
    async def save_delivery_record(self, record: CredentialDeliveryRecord) -> None:
        """Save or update a credential delivery record."""
        pass

    @abstractmethod
    async def get_delivery_record(self, record_id: str) -> CredentialDeliveryRecord | None:
        """Get a credential delivery record by ID."""
        pass

    @abstractmethod
    async def get_canvas_delivery_record_by_external_credential_id(
        self,
        external_credential_id: str,
        *,
        canvas_account_id: str | None = None,
        organization_id: str | None = None,
    ) -> CredentialDeliveryRecord | None:
        """Get a Canvas mirror delivery record by its external Canvas credential ID."""
        pass

    @abstractmethod
    async def list_delivery_records_for_credential(self, credential_id: str) -> list[CredentialDeliveryRecord]:
        """List delivery records for a credential."""
        pass

    @abstractmethod
    async def list_delivery_records(
        self,
        *,
        delivery_target: DeliveryTarget | None = None,
        statuses: list[CredentialDeliveryStatus] | None = None,
        organization_id: str | None = None,
        limit: int | None = None,
    ) -> list[CredentialDeliveryRecord]:
        """List delivery records filtered by target/status/organization."""
        pass

    @abstractmethod
    async def save_evidence_fact(self, fact: EvidenceFact) -> None:
        """Save or update a normalized evidence fact."""
        pass

    @abstractmethod
    async def list_evidence_facts_for_application(self, application_id: str) -> list[EvidenceFact]:
        """List normalized evidence facts for an application."""
        pass

    @abstractmethod
    async def get_approval_policy_set(
        self,
        organization_id: str,
        policy_set_id: str,
    ) -> ApprovalPolicySet | None:
        """Get an organization-owned approval PolicySet referenced by issuance."""
        pass
    
    # Application Template methods
    @abstractmethod
    async def save_application_template(self, template: ApplicationTemplate) -> None:
        """Save or update an application template."""
        pass
    
    @abstractmethod
    async def get_application_template(self, template_id: str) -> ApplicationTemplate | None:
        """Get application template by ID."""
        pass
    
    @abstractmethod
    async def list_application_templates(self, org_id: str) -> list[ApplicationTemplate]:
        """List application templates for an organization."""
        pass

    @abstractmethod
    async def delete_application_template(self, template_id: str) -> bool:
        """Delete an application template and return whether it existed."""
        pass
    
    # Application methods
    @abstractmethod
    async def save_application(self, app: Application) -> None:
        """Save or update an application."""
        pass
    
    @abstractmethod
    async def get_application(self, app_id: str) -> Application | None:
        """Get application by ID."""
        pass
    
    @abstractmethod
    async def list_applications(
        self,
        org_id: str | None = None,
        status: ApplicationStatus | None = None,
        template_id: str | None = None,
    ) -> list[Application]:
        """List applications with optional filters."""
        pass

    # Lifecycle event methods
    @abstractmethod
    async def save_event(self, event: IssuanceEvent) -> None:
        """Append an immutable lifecycle event to the audit log."""
        pass

    @abstractmethod
    async def list_events_for_application(self, application_id: str) -> list[IssuanceEvent]:
        """Return all events recorded for a given application, oldest first."""
        pass

    @abstractmethod
    async def save_canvas_event_receipt(self, receipt: CanvasEventReceipt) -> None:
        """Persist an inbound Canvas event receipt for replay-safe processing."""
        pass

    @abstractmethod
    async def get_canvas_event_receipt(
        self,
        provider_event_id: str,
        canvas_account_id: str | None = None,
    ) -> CanvasEventReceipt | None:
        """Look up a previously-processed Canvas event receipt by provider event ID and account."""
        pass

    @abstractmethod
    async def list_canvas_event_receipts(
        self,
        *,
        organization_id: str | None = None,
        status: str | None = None,
        limit: int | None = None,
    ) -> list[CanvasEventReceipt]:
        """List Canvas event receipts for reconciliation and reporting."""
        pass

    @abstractmethod
    async def save_canvas_platform(self, platform: CanvasPlatform) -> None:
        """Persist Canvas tenant/platform trust configuration."""
        pass

    @abstractmethod
    async def get_canvas_platform(self, platform_id: str) -> CanvasPlatform | None:
        """Look up a Canvas platform by ID."""
        pass

    @abstractmethod
    async def get_canvas_platform_by_account_id(
        self,
        organization_id: str,
        canvas_account_id: str,
    ) -> CanvasPlatform | None:
        """Look up a Canvas platform by organization and Canvas account ID."""
        pass

    @abstractmethod
    async def list_canvas_platforms(self, organization_id: str) -> list[CanvasPlatform]:
        """List Canvas platforms for an organization."""
        pass

    @abstractmethod
    async def delete_canvas_platform(self, platform_id: str) -> None:
        """Delete a Canvas platform and its program bindings."""
        pass

    @abstractmethod
    async def save_canvas_program_binding(self, binding: CanvasProgramBinding) -> None:
        """Persist a program-level Canvas binding."""
        pass

    @abstractmethod
    async def get_canvas_program_binding(self, binding_id: str) -> CanvasProgramBinding | None:
        """Look up a Canvas program binding by ID."""
        pass

    @abstractmethod
    async def list_canvas_program_bindings(
        self,
        organization_id: str,
        platform_id: str | None = None,
        application_template_id: str | None = None,
    ) -> list[CanvasProgramBinding]:
        """List Canvas program bindings with optional filters."""
        pass

    @abstractmethod
    async def delete_canvas_program_binding(self, binding_id: str) -> None:
        """Delete a Canvas program binding."""
        pass

    @abstractmethod
    async def save_integration_secret(self, secret: OrganizationIntegrationSecret) -> None:
        """Persist or rotate an organization integration secret."""
        pass

    @abstractmethod
    async def get_integration_secret(self, secret_id: str) -> OrganizationIntegrationSecret | None:
        """Look up integration secret metadata by ID without exposing plaintext."""
        pass

    @abstractmethod
    async def list_integration_secrets(
        self,
        organization_id: str,
        provider: str | None = None,
    ) -> list[OrganizationIntegrationSecret]:
        """List organization integration secret metadata."""
        pass

    @abstractmethod
    async def get_integration_secret_value(self, organization_id: str, secret_id: str) -> str | None:
        """Resolve a plaintext integration secret for runtime use."""
        pass

    @abstractmethod
    async def delete_integration_secret(self, secret_id: str) -> None:
        """Delete an organization integration secret."""
        pass

    @abstractmethod
    async def save_canvas_lti_launch_state(self, launch_state: CanvasLtiLaunchState) -> None:
        """Persist a server-owned Canvas LTI launch state."""
        pass

    @abstractmethod
    async def get_canvas_lti_launch_state(self, state: str) -> CanvasLtiLaunchState | None:
        """Look up a Canvas LTI launch state by opaque state value."""
        pass

    @abstractmethod
    async def consume_canvas_lti_launch_state(self, state: str) -> CanvasLtiLaunchState | None:
        """Atomically consume a pending Canvas LTI launch state when possible."""
        pass

    @abstractmethod
    async def get_credential_types_for_org(self, org_id: str) -> list[str]:
        """Return credential_type values for an org's active credential templates.

        Used to build ``credential_configurations_supported`` in the per-org
        OID4VCI issuer metadata.  Implementations must source this from the
        credential templates configuration (not from historical issuance data)
        so that metadata reflects current issuer capability.
        """
        pass

    @abstractmethod
    async def get_credential_type_formats_for_org(self, org_id: str) -> list[tuple[str, list[str]]]:
        """Return (credential_type, supported_formats) for an org's active templates.

        Like ``get_credential_types_for_org`` but also returns the
        ``supported_formats`` JSON array from each template so that issuer
        metadata can emit the correct format-specific configuration entries
        (e.g. ``com.icao.dtc#mdoc`` for mDoc-capable templates that don't
        start with ``org.iso.18013``).
        """
        pass

    @abstractmethod
    async def get_credential_display_metadata_for_org(self, org_id: str) -> dict[str, dict[str, Any]]:
        """Return human display metadata keyed by credential_type."""
        pass

    # Authorization session methods (OID4VCI authorization code flow)
    @abstractmethod
    async def save_authorization_session(self, session: AuthorizationSession) -> None:
        """Persist an authorization session (insert or update)."""
        pass

    @abstractmethod
    async def get_authorization_session_by_code(self, code: str) -> AuthorizationSession | None:
        """Look up a session by its authorization code."""
        pass

    @abstractmethod
    async def get_authorization_session_by_access_token(self, token: str) -> AuthorizationSession | None:
        """Look up a session by its access token (post-exchange)."""
        pass

    @abstractmethod
    async def get_retention_summary(self, org_id: str, retention_days: int) -> dict[str, Any]:
        """Return Hosted Pilot retention status for an organization."""
        pass

    @abstractmethod
    async def purge_retention_records(self, org_id: str, retention_days: int) -> dict[str, Any]:
        """Purge Hosted Pilot data older than the retention window."""
        pass
