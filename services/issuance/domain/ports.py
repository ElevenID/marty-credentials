"""Repository port interfaces for issuance service."""

from __future__ import annotations

from abc import ABC, abstractmethod

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    AuthorizationSession,
    IssuanceEvent,
    IssuanceTransaction,
    IssuedCredential,
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
    async def list_credentials(self, applicant_id: str) -> list[IssuedCredential]:
        """List credentials by applicant."""
        pass
    
    @abstractmethod
    async def list_credentials_by_org(self, org_id: str) -> list[IssuedCredential]:
        """List all credentials for an organization."""
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
    async def get_credential_types_for_org(self, org_id: str) -> list[str]:
        """Return credential_type values for an org's active credential templates.

        Used to build ``credential_configurations_supported`` in the per-org
        OID4VCI issuer metadata.  Implementations must source this from the
        credential templates configuration (not from historical issuance data)
        so that metadata reflects current issuer capability.
        """
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
