"""In-memory repository adapter for development."""

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    IssuanceEvent,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.domain.ports import IIssuanceRepository


class InMemoryIssuanceRepository(IIssuanceRepository):
    """In-memory implementation for development and testing."""
    
    def __init__(self):
        self._transactions: dict[str, IssuanceTransaction] = {}
        self._credentials: dict[str, IssuedCredential] = {}
        self._applications: dict[str, Application] = {}
        self._application_templates: dict[str, ApplicationTemplate] = {}
        self._events: list[IssuanceEvent] = []
    
    async def save_transaction(self, tx: IssuanceTransaction) -> None:
        self._transactions[tx.id] = tx
    
    async def get_transaction(self, tx_id: str) -> IssuanceTransaction | None:
        return self._transactions.get(tx_id)
    
    async def get_by_pre_auth_code(self, code: str) -> IssuanceTransaction | None:
        for tx in self._transactions.values():
            if tx.pre_auth_code == code:
                return tx
        return None
    
    async def get_by_access_token(self, token: str) -> IssuanceTransaction | None:
        for tx in self._transactions.values():
            if tx.access_token == token:
                return tx
        return None
    
    async def list_transactions(self, org_id: str) -> list[IssuanceTransaction]:
        return [tx for tx in self._transactions.values() if tx.organization_id == org_id]
    
    async def save_credential(self, cred: IssuedCredential) -> None:
        self._credentials[cred.id] = cred
    
    async def get_credential(self, cred_id: str) -> IssuedCredential | None:
        return self._credentials.get(cred_id)

    async def get_credential_by_transaction_id(self, transaction_id: str) -> IssuedCredential | None:
        for cred in self._credentials.values():
            if cred.transaction_id == transaction_id:
                return cred
        return None
    
    async def list_credentials(self, applicant_id: str) -> list[IssuedCredential]:
        return [c for c in self._credentials.values() if c.applicant_id == applicant_id]
    
    async def list_credentials_by_org(self, org_id: str) -> list[IssuedCredential]:
        return [c for c in self._credentials.values() if c.organization_id == org_id]
    
    async def save_application_template(self, template: ApplicationTemplate) -> None:
        from datetime import datetime, timezone
        template.updated_at = datetime.now(timezone.utc)
        self._application_templates[template.id] = template
    
    async def get_application_template(self, template_id: str) -> ApplicationTemplate | None:
        return self._application_templates.get(template_id)
    
    async def list_application_templates(self, org_id: str) -> list[ApplicationTemplate]:
        return [t for t in self._application_templates.values() if t.organization_id == org_id]
    
    async def save_application(self, app: Application) -> None:
        self._applications[app.id] = app
    
    async def get_application(self, app_id: str) -> Application | None:
        return self._applications.get(app_id)
    
    async def list_applications(
        self,
        org_id: str | None = None,
        status: ApplicationStatus | None = None,
        template_id: str | None = None,
    ) -> list[Application]:
        apps = list(self._applications.values())
        
        if org_id:
            apps = [a for a in apps if a.organization_id == org_id]
        if status:
            apps = [a for a in apps if a.status == status]
        if template_id:
            apps = [a for a in apps if a.application_template_id == template_id]
        
        return apps

    # Lifecycle event methods
    async def save_event(self, event: IssuanceEvent) -> None:
        self._events.append(event)

    async def list_events_for_application(
        self, application_id: str
    ) -> list[IssuanceEvent]:
        return sorted(
            [e for e in self._events if e.application_id == application_id],
            key=lambda e: e.created_at,
        )

    async def get_credential_types_for_org(self, org_id: str) -> list[str]:
        seen: set[str] = set()
        for tx in self._transactions.values():
            if tx.organization_id == org_id and tx.credential_type:
                seen.add(tx.credential_type)
        return sorted(seen)
