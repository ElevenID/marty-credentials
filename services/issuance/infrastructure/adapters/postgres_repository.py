"""PostgreSQL adapter for Issuance Repository."""

import hashlib
import hmac
import os
from datetime import datetime, timezone

from sqlalchemy import select, and_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    AuthorizationSession,
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
    authorization_sessions_table,
    issued_credentials_table,
    issuance_events_table,
    issuance_transactions_table,
)

# Key for HMAC-SHA256 token hashing.  Falls back to a deterministic
# default so that existing rows remain queryable even when the env var
# is absent (e.g. local dev), but production deployments MUST set this
# to a securely-generated random value.
_TOKEN_HMAC_KEY_RAW = os.environ.get("TOKEN_HMAC_KEY", "")
if not _TOKEN_HMAC_KEY_RAW:
    import warnings
    warnings.warn(
        "TOKEN_HMAC_KEY is not set — using insecure default. "
        "Set TOKEN_HMAC_KEY to a securely-generated random value in production.",
        stacklevel=1,
    )
    _TOKEN_HMAC_KEY_RAW = "marty-token-hmac-default-key"
_TOKEN_HMAC_KEY: bytes = _TOKEN_HMAC_KEY_RAW.encode()


def _hash_token(raw_token: str | None) -> str | None:
    """Return the HMAC-SHA256 hex digest of *raw_token*, or None."""
    if not raw_token:
        return None
    return hmac.new(_TOKEN_HMAC_KEY, raw_token.encode(), hashlib.sha256).hexdigest()


class PostgresIssuanceRepository(IIssuanceRepository):
    """PostgreSQL implementation of issuance repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    @staticmethod
    def _normalize_optional_template_id(value: str | None) -> str:
        """Persist absent application-template credential links as empty strings.

        The legacy issuance schema stores ``credential_template_id`` as NOT NULL,
        while the application layer treats it as optional. Normalizing here keeps
        omitted values from surfacing as 500s while preserving existing behavior.
        """
        return value or ""

    @staticmethod
    def _denormalize_optional_template_id(value: str | None) -> str | None:
        """Return stored empty-string sentinels as ``None`` to callers."""
        return value or None
    
    # Transaction methods
    async def save_transaction(self, tx: IssuanceTransaction) -> None:
        async with self._session_factory() as session:
            tx_data = {
                "id": tx.id,
                "organization_id": tx.organization_id,
                "credential_template_id": tx.credential_template_id,
                "applicant_id": tx.applicant_id,
                "application_id": tx.application_id,
                "subject_did": tx.subject_did,
                "status": tx.status.value,
                "pre_auth_code": tx.pre_auth_code,
                "access_token": _hash_token(tx.access_token),
                "c_nonce": tx.nonce,
                "claims": tx.claims,
                "credential_type": tx.credential_type,
                "zk_predicate_claims": tx.zk_predicate_claims or [],
                "selective_disclosure_claims": tx.selective_disclosure_claims or [],
                "credential_payload_format": tx.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
                "wallet_configs": tx.wallet_configs or [],
                "created_at": tx.created_at,
                "expires_at": tx.expires_at,
                "issued_at": tx.issued_at,
                "revoked_at": tx.revoked_at,
                "revocation_reason": tx.revocation_reason,
            }

            update_data = {k: v for k, v in tx_data.items() if k not in ("id", "created_at")}
            stmt = (
                pg_insert(issuance_transactions_table)
                .values(**tx_data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_=update_data,
                )
            )
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
                nonce=row.c_nonce,
                claims=row.claims or {},
                credential_type=row.credential_type,
                zk_predicate_claims=list(row.zk_predicate_claims or []),
                selective_disclosure_claims=list(getattr(row, 'selective_disclosure_claims', None) or []),
                credential_payload_format=row.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
                wallet_configs=list(row.wallet_configs or []),
                created_at=row.created_at,
                expires_at=row.expires_at,
                issued_at=row.issued_at,
                revoked_at=getattr(row, 'revoked_at', None),
                revocation_reason=getattr(row, 'revocation_reason', None),
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
                nonce=row.c_nonce,
                claims=row.claims or {},
                credential_type=row.credential_type,
                zk_predicate_claims=list(row.zk_predicate_claims or []),
                selective_disclosure_claims=list(getattr(row, 'selective_disclosure_claims', None) or []),
                credential_payload_format=row.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
                wallet_configs=list(row.wallet_configs or []),
                created_at=row.created_at,
                expires_at=row.expires_at,
                issued_at=row.issued_at,
                revoked_at=getattr(row, 'revoked_at', None),
                revocation_reason=getattr(row, 'revocation_reason', None),
            )
    
    async def get_by_access_token(self, token: str) -> IssuanceTransaction | None:
        async with self._session_factory() as session:
            stmt = select(issuance_transactions_table).where(
                issuance_transactions_table.c.access_token == _hash_token(token)
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
                nonce=row.c_nonce,
                claims=row.claims or {},
                credential_type=row.credential_type,
                zk_predicate_claims=list(row.zk_predicate_claims or []),
                selective_disclosure_claims=list(getattr(row, 'selective_disclosure_claims', None) or []),
                credential_payload_format=row.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
                wallet_configs=list(row.wallet_configs or []),
                created_at=row.created_at,
                expires_at=row.expires_at,
                issued_at=row.issued_at,
                revoked_at=getattr(row, 'revoked_at', None),
                revocation_reason=getattr(row, 'revocation_reason', None),
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

    async def get_credential_types_for_org(self, org_id: str) -> list[str]:
        """Return distinct credential_type values for an org's issuable templates.

        Reads from ``credential_template_service.credential_templates`` (same
        PostgreSQL instance, different schema) so that issuer metadata reflects
        what the org is *configured* to issue — not historical issuance data.
        This means new templates appear in metadata immediately after creation
        and deprecated templates are removed without any delay.

        Both 'draft' and 'active' templates are included because the issuance
        endpoint accepts both statuses.  OID4VCI wallets (e.g. Walt.id stable)
        strictly validate that the credential_configuration_id in the offer
        appears in the issuer metadata, so draft templates must be discoverable.
        Only 'deprecated' templates are excluded.
        """
        from sqlalchemy import text
        async with self._session_factory() as session:
            stmt = text(
                """
                SELECT DISTINCT credential_type
                FROM credential_template_service.credential_templates
                WHERE organization_id = :org_id
                  AND status IN ('active', 'draft')
                  AND credential_type IS NOT NULL
                ORDER BY credential_type
                """
            )
            result = await session.execute(stmt, {"org_id": org_id})
            return [row[0] for row in result.all()]

    async def get_credential_type_formats_for_org(self, org_id: str) -> list[tuple[str, list[str]]]:
        """Return (credential_type, supported_formats) for an org's active templates.

        Queries the credential_template_service schema for both the credential_type
        and the supported_formats JSON array so that issuer metadata can emit
        format-specific configuration entries for non-ISO-prefixed types that
        support mDoc (e.g. ``com.icao.dtc`` with ``supported_formats=["mdoc"]``).
        """
        from sqlalchemy import text
        async with self._session_factory() as session:
            stmt = text(
                """
                SELECT credential_type, supported_formats
                FROM credential_template_service.credential_templates
                WHERE organization_id = :org_id
                  AND status IN ('active', 'draft')
                  AND credential_type IS NOT NULL
                ORDER BY credential_type
                """
            )
            result = await session.execute(stmt, {"org_id": org_id})
            rows = result.all()
            # Deduplicate: merge formats across templates with the same credential_type
            type_formats: dict[str, set[str]] = {}
            for ctype, formats in rows:
                if ctype not in type_formats:
                    type_formats[ctype] = set()
                if formats:
                    fmts = formats if isinstance(formats, list) else []
                    type_formats[ctype].update(fmts)
            return [(ct, sorted(fmts)) for ct, fmts in sorted(type_formats.items())]

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

    async def get_credential_by_transaction_id(self, transaction_id: str) -> IssuedCredential | None:
        async with self._session_factory() as session:
            stmt = select(issued_credentials_table).where(
                issued_credentials_table.c.transaction_id == transaction_id
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
                "credential_template_id": self._normalize_optional_template_id(
                    template.credential_template_id
                ),
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
                credential_template_id=self._denormalize_optional_template_id(
                    row.credential_template_id
                ),
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

    # Authorization session methods
    async def save_authorization_session(self, auth_session: AuthorizationSession) -> None:
        async with self._session_factory() as session:
            stmt = select(authorization_sessions_table).where(
                authorization_sessions_table.c.id == auth_session.id
            )
            result = await session.execute(stmt)
            existing = result.first()

            data = {
                "id": auth_session.id,
                "code": auth_session.code,
                "client_id": auth_session.client_id,
                "redirect_uri": auth_session.redirect_uri,
                "scope": auth_session.scope,
                "state": auth_session.state,
                "issuer_state": auth_session.issuer_state,
                "credential_configuration_ids": auth_session.credential_configuration_ids,
                "organization_id": auth_session.organization_id,
                "code_challenge": auth_session.code_challenge,
                "code_challenge_method": auth_session.code_challenge_method,
                "access_token": _hash_token(auth_session.access_token),
                "c_nonce": auth_session.nonce,
                "status": auth_session.status,
                "created_at": auth_session.created_at,
                "expires_at": auth_session.expires_at,
            }

            if existing:
                stmt = (
                    authorization_sessions_table.update()
                    .where(authorization_sessions_table.c.id == auth_session.id)
                    .values(**data)
                )
            else:
                stmt = authorization_sessions_table.insert().values(**data)

            await session.execute(stmt)
            await session.commit()

    def _row_to_auth_session(self, row) -> AuthorizationSession:
        """Map a DB row to an AuthorizationSession entity."""
        return AuthorizationSession(
            id=row.id,
            code=row.code,
            client_id=row.client_id,
            redirect_uri=row.redirect_uri,
            scope=row.scope,
            state=row.state,
            issuer_state=row.issuer_state,
            credential_configuration_ids=row.credential_configuration_ids or [],
            organization_id=row.organization_id,
            code_challenge=row.code_challenge,
            code_challenge_method=row.code_challenge_method,
            access_token=row.access_token,
            nonce=row.c_nonce,
            status=row.status,
            created_at=row.created_at,
            expires_at=row.expires_at,
        )

    async def get_authorization_session_by_code(self, code: str) -> AuthorizationSession | None:
        async with self._session_factory() as session:
            stmt = select(authorization_sessions_table).where(
                authorization_sessions_table.c.code == code
            )
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_auth_session(row) if row else None

    async def get_authorization_session_by_access_token(self, token: str) -> AuthorizationSession | None:
        async with self._session_factory() as session:
            stmt = select(authorization_sessions_table).where(
                authorization_sessions_table.c.access_token == _hash_token(token)
            )
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_auth_session(row) if row else None