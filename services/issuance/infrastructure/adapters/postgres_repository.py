"""PostgreSQL adapter for Issuance Repository."""

from datetime import datetime, timezone

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
    CredentialStatus,
    EventType,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.models import (
    application_templates_table,
    applications_table,
    issued_credentials_table,
    issuance_events_table,
    issuance_transactions_table,
)


class PostgresIssuanceRepository(IIssuanceRepository):
    """PostgreSQL implementation of issuance repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
    
    # Transaction methods
    async def save_transaction(self, tx: IssuanceTransaction) -> None:
        async with self._session_factory() as session:
            stmt = select(issuance_transactions_table).where(
                issuance_transactions_table.c.id == tx.id
            )
            result = await session.execute(stmt)
            existing = result.first()
            
            tx_data = {
                "id": tx.id,
                "organization_id": tx.organization_id,
                "credential_template_id": tx.credential_template_id,
                "applicant_id": tx.applicant_id,
                "application_id": tx.application_id,
                "subject_did": tx.subject_did,
                "status": tx.status.value,
                "pre_auth_code": tx.pre_auth_code,
                "access_token": tx.access_token,
                "c_nonce": tx.c_nonce,
                "claims": tx.claims,
                "credential_type": tx.credential_type,
                "expires_at": tx.expires_at,
                "issued_at": tx.issued_at,
            }
            
            if existing:
                stmt = (
                    issuance_transactions_table.update()
                    .where(issuance_transactions_table.c.id == tx.id)
                    .values(**tx_data)
                )
                await session.execute(stmt)
            else:
                tx_data["created_at"] = tx.created_at
                stmt = issuance_transactions_table.insert().values(**tx_data)
                await session.execute(stmt)
            
            await session.commit()
    
    async def get_transaction(self, tx_id: str) -> IssuanceTransaction | None:
        async with self._session_factory() as session:
            stmt = select(issuance_transactions_table).where(
                issuance_transactions_table.c.id == tx_id
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return IssuanceTransaction(
                id=row.id,
                organization_id=row.organization_id,
                credential_template_id=row.credential_template_id,
                applicant_id=row.applicant_id,
                application_id=row.application_id,
                subject_did=row.subject_did,
                status=IssuanceStatus(row.status),
                pre_auth_code=row.pre_auth_code,
                access_token=row.access_token,
                c_nonce=row.c_nonce,
                claims=row.claims or {},
                credential_type=row.credential_type,
                created_at=row.created_at,
                expires_at=row.expires_at,
                issued_at=row.issued_at,
            )
    
    async def get_by_pre_auth_code(self, code: str) -> IssuanceTransaction | None:
        async with self._session_factory() as session:
            stmt = select(issuance_transactions_table).where(
                issuance_transactions_table.c.pre_auth_code == code
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return IssuanceTransaction(
                id=row.id,
                organization_id=row.organization_id,
                credential_template_id=row.credential_template_id,
                applicant_id=row.applicant_id,
                application_id=row.application_id,
                subject_did=row.subject_did,
                status=IssuanceStatus(row.status),
                pre_auth_code=row.pre_auth_code,
                access_token=row.access_token,
                c_nonce=row.c_nonce,
                claims=row.claims or {},
                credential_type=row.credential_type,
                created_at=row.created_at,
                expires_at=row.expires_at,
                issued_at=row.issued_at,
            )
    
    async def get_by_access_token(self, token: str) -> IssuanceTransaction | None:
        async with self._session_factory() as session:
            stmt = select(issuance_transactions_table).where(
                issuance_transactions_table.c.access_token == token
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return IssuanceTransaction(
                id=row.id,
                organization_id=row.organization_id,
                credential_template_id=row.credential_template_id,
                applicant_id=row.applicant_id,
                application_id=row.application_id,
                subject_did=row.subject_did,
                status=IssuanceStatus(row.status),
                pre_auth_code=row.pre_auth_code,
                access_token=row.access_token,
                c_nonce=row.c_nonce,
                claims=row.claims or {},
                credential_type=row.credential_type,
                created_at=row.created_at,
                expires_at=row.expires_at,
                issued_at=row.issued_at,
            )
    
    async def list_transactions(self, org_id: str) -> list[IssuanceTransaction]:
        async with self._session_factory() as session:
            stmt = select(issuance_transactions_table).where(
                issuance_transactions_table.c.organization_id == org_id
            )
            result = await session.execute(stmt)
            rows = result.all()
            
            transactions = []
            for row in rows:
                tx = await self.get_transaction(row.id)
                if tx:
                    transactions.append(tx)
            
            return transactions
    
    # Credential methods
    async def save_credential(self, cred: IssuedCredential) -> None:
        async with self._session_factory() as session:
            stmt = select(issued_credentials_table).where(
                issued_credentials_table.c.id == cred.id
            )
            result = await session.execute(stmt)
            existing = result.first()
            
            cred_data = {
                "id": cred.id,
                "transaction_id": cred.transaction_id,
                "organization_id": cred.organization_id,
                "credential_template_id": cred.credential_template_id,
                "applicant_id": cred.applicant_id,
                "subject_did": cred.subject_did,
                "credential_jwt": cred.credential_jwt,
                "credential_hash": cred.credential_hash,
                "status": cred.status.value,
                "status_updated_at": cred.status_updated_at,
                "revoked": cred.revoked,
                "revoked_at": cred.revoked_at,
                "revocation_reason": cred.revocation_reason,
                "expires_at": cred.expires_at,
            }
            
            if existing:
                stmt = (
                    issued_credentials_table.update()
                    .where(issued_credentials_table.c.id == cred.id)
                    .values(**cred_data)
                )
                await session.execute(stmt)
            else:
                cred_data["issued_at"] = cred.issued_at
                stmt = issued_credentials_table.insert().values(**cred_data)
                await session.execute(stmt)
            
            await session.commit()
    
    async def get_credential(self, cred_id: str) -> IssuedCredential | None:
        async with self._session_factory() as session:
            stmt = select(issued_credentials_table).where(
                issued_credentials_table.c.id == cred_id
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return IssuedCredential(
                id=row.id,
                transaction_id=row.transaction_id,
                organization_id=row.organization_id,
                credential_template_id=row.credential_template_id,
                applicant_id=row.applicant_id,
                subject_did=row.subject_did,
                credential_jwt=row.credential_jwt,
                credential_hash=row.credential_hash,
                status=CredentialStatus(row.status),
                status_updated_at=row.status_updated_at,
                revoked=row.revoked,
                revoked_at=row.revoked_at,
                revocation_reason=row.revocation_reason,
                issued_at=row.issued_at,
                expires_at=row.expires_at,
            )
    
    async def list_credentials(self, applicant_id: str) -> list[IssuedCredential]:
        async with self._session_factory() as session:
            stmt = select(issued_credentials_table).where(
                issued_credentials_table.c.applicant_id == applicant_id
            )
            result = await session.execute(stmt)
            rows = result.all()
            
            credentials = []
            for row in rows:
                cred = await self.get_credential(row.id)
                if cred:
                    credentials.append(cred)
            
            return credentials
    
    async def list_credentials_by_org(self, org_id: str) -> list[IssuedCredential]:
        async with self._session_factory() as session:
            stmt = select(issued_credentials_table).where(
                issued_credentials_table.c.organization_id == org_id
            )
            result = await session.execute(stmt)
            rows = result.all()
            
            credentials = []
            for row in rows:
                cred = await self.get_credential(row.id)
                if cred:
                    credentials.append(cred)
            
            return credentials
    
    # Application Template methods
    async def save_application_template(self, template: ApplicationTemplate) -> None:
        async with self._session_factory() as session:
            stmt = select(application_templates_table).where(
                application_templates_table.c.id == template.id
            )
            result = await session.execute(stmt)
            existing = result.first()
            
            template_data = {
                "id": template.id,
                "organization_id": template.organization_id,
                "name": template.name,
                "description": template.description,
                "credential_template_id": template.credential_template_id,
                "form_fields": template.form_fields,
                "evidence_requirements": template.evidence_requirements,
                "claim_collection_rules": template.claim_collection_rules,
                "required_checks": template.required_checks,
                "approval_strategy": template.approval_strategy,
                "application_validity_days": template.application_validity_days,
                "auto_approval_rules": template.auto_approval_rules,
                "ui_config": template.ui_config,
                "notification_config": template.notification_config,
                "status": template.status,
                "updated_at": datetime.now(timezone.utc),
            }
            
            if existing:
                stmt = (
                    application_templates_table.update()
                    .where(application_templates_table.c.id == template.id)
                    .values(**template_data)
                )
                await session.execute(stmt)
            else:
                template_data["created_at"] = template.created_at
                stmt = application_templates_table.insert().values(**template_data)
                await session.execute(stmt)
            
            await session.commit()
    
    async def get_application_template(self, template_id: str) -> ApplicationTemplate | None:
        async with self._session_factory() as session:
            stmt = select(application_templates_table).where(
                application_templates_table.c.id == template_id
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return ApplicationTemplate(
                id=row.id,
                organization_id=row.organization_id,
                name=row.name,
                description=row.description,
                credential_template_id=row.credential_template_id,
                form_fields=row.form_fields or [],
                evidence_requirements=row.evidence_requirements or [],
                claim_collection_rules=row.claim_collection_rules or [],
                required_checks=row.required_checks or [],
                approval_strategy=row.approval_strategy,
                application_validity_days=row.application_validity_days,
                auto_approval_rules=row.auto_approval_rules or [],
                ui_config=row.ui_config or {},
                notification_config=row.notification_config or {},
                status=row.status,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
    
    async def list_application_templates(self, org_id: str) -> list[ApplicationTemplate]:
        async with self._session_factory() as session:
            stmt = select(application_templates_table).where(
                application_templates_table.c.organization_id == org_id
            )
            result = await session.execute(stmt)
            rows = result.all()
            
            templates = []
            for row in rows:
                template = await self.get_application_template(row.id)
                if template:
                    templates.append(template)
            
            return templates
    
    # Application methods
    async def save_application(self, app: Application) -> None:
        async with self._session_factory() as session:
            stmt = select(applications_table).where(
                applications_table.c.id == app.id
            )
            result = await session.execute(stmt)
            existing = result.first()
            
            app_data = {
                "id": app.id,
                "organization_id": app.organization_id,
                "application_template_id": app.application_template_id,
                "applicant_identifier": app.applicant_identifier,
                "form_data": app.form_data,
                "submitted_evidence": app.evidence_submissions,
                "status": app.status.value,
                "review_notes": app.review_notes,
                "reviewer_id": app.reviewer_id,
                "rejection_reason": app.rejection_reason,
                "derived_claims": app.derived_claims,
                "issuance_transaction_id": app.issuance_transaction_id,
                "credential_id": app.credential_id,
                "updated_at": datetime.now(timezone.utc),
                "submitted_at": app.submitted_at,
                "reviewed_at": app.reviewed_at,
                "expires_at": app.expires_at,
            }
            
            if existing:
                stmt = (
                    applications_table.update()
                    .where(applications_table.c.id == app.id)
                    .values(**app_data)
                )
                await session.execute(stmt)
            else:
                app_data["created_at"] = app.created_at
                stmt = applications_table.insert().values(**app_data)
                await session.execute(stmt)
            
            await session.commit()
    
    async def get_application(self, app_id: str) -> Application | None:
        async with self._session_factory() as session:
            stmt = select(applications_table).where(
                applications_table.c.id == app_id
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return Application(
                id=row.id,
                organization_id=row.organization_id,
                application_template_id=row.application_template_id,
                applicant_identifier=row.applicant_identifier,
                form_data=row.form_data or {},
                evidence_submissions=row.submitted_evidence or [],
                status=ApplicationStatus(row.status),
                review_notes=row.review_notes,
                reviewer_id=row.reviewer_id,
                rejection_reason=row.rejection_reason,
                derived_claims=row.derived_claims or {},
                issuance_transaction_id=row.issuance_transaction_id,
                credential_id=row.credential_id,
                created_at=row.created_at,
                updated_at=row.updated_at,
                submitted_at=row.submitted_at,
                reviewed_at=row.reviewed_at,
                expires_at=row.expires_at,
            )
    
    async def list_applications(
        self,
        org_id: str | None = None,
        status: ApplicationStatus | None = None,
        template_id: str | None = None,
    ) -> list[Application]:
        async with self._session_factory() as session:
            conditions = []
            if org_id:
                conditions.append(applications_table.c.organization_id == org_id)
            if status:
                conditions.append(applications_table.c.status == status.value)
            if template_id:
                conditions.append(applications_table.c.application_template_id == template_id)
            
            if conditions:
                stmt = select(applications_table).where(and_(*conditions))
            else:
                stmt = select(applications_table)
            
            result = await session.execute(stmt)
            rows = result.all()
            
            applications = []
            for row in rows:
                app = await self.get_application(row.id)
                if app:
                    applications.append(app)
            
            return applications

    # Lifecycle event methods
    async def save_event(self, event: IssuanceEvent) -> None:
        async with self._session_factory() as session:
            stmt = issuance_events_table.insert().values(
                id=event.id,
                transaction_id=event.transaction_id,
                application_id=event.application_id,
                event_type=event.event_type.value,
                metadata=event.metadata,
                created_at=event.created_at,
            )
            await session.execute(stmt)
            await session.commit()

    async def list_events_for_application(
        self, application_id: str
    ) -> list[IssuanceEvent]:
        async with self._session_factory() as session:
            stmt = (
                select(issuance_events_table)
                .where(issuance_events_table.c.application_id == application_id)
                .order_by(issuance_events_table.c.created_at)
            )
            result = await session.execute(stmt)
            rows = result.all()
            return [
                IssuanceEvent(
                    id=row.id,
                    transaction_id=row.transaction_id,
                    application_id=row.application_id,
                    event_type=EventType(row.event_type),
                    metadata=row.metadata or {},
                    created_at=row.created_at,
                )
                for row in rows
            ]