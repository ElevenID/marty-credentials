"""PostgreSQL adapter for Issuance Repository."""

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    AuthorizationSession,
    CanvasConnectorConfig,
    CanvasEventReceipt,
    CanvasLtiLaunchState,
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
    canvas_connectors_table,
    canvas_event_receipts_table,
    canvas_lti_launch_states_table,
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

    @staticmethod
    def _event_org_condition(org_id: str):
        transaction_ids = select(issuance_transactions_table.c.id).where(
            issuance_transactions_table.c.organization_id == org_id
        )
        application_ids = select(applications_table.c.id).where(
            applications_table.c.organization_id == org_id
        )
        return or_(
            issuance_events_table.c.transaction_id.in_(transaction_ids),
            issuance_events_table.c.application_id.in_(application_ids),
        )

    @staticmethod
    def _old_transaction_ids_query(org_id: str, cutoff_at: datetime):
        return select(issuance_transactions_table.c.id).where(
            issuance_transactions_table.c.organization_id == org_id,
            issuance_transactions_table.c.created_at < cutoff_at,
        )

    @staticmethod
    def _result_rowcount(result: Any) -> int:
        return int(result.rowcount or 0)

    @staticmethod
    def _row_to_canvas_event_receipt(row) -> CanvasEventReceipt:
        return CanvasEventReceipt(
            id=row.id,
            provider_event_id=row.provider_event_id,
            organization_id=row.organization_id,
            credential_template_id=row.credential_template_id,
            canvas_account_id=row.canvas_account_id,
            payload_hash=row.payload_hash,
            issuance_transaction_id=row.issuance_transaction_id,
            issuance_response=row.issuance_response or {},
            status=row.status,
            error_summary=row.error_summary,
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
        )

    @staticmethod
    def _row_to_canvas_connector(row) -> CanvasConnectorConfig:
        return CanvasConnectorConfig(
            id=row.id,
            organization_id=row.organization_id,
            canvas_account_id=row.canvas_account_id,
            credential_template_id=row.credential_template_id,
            application_template_id=getattr(row, "application_template_id", None),
            flow_mode=getattr(row, "flow_mode", None) or "elevenid_orchestrated_canvas_evidence",
            direct_issue_enabled=bool(getattr(row, "direct_issue_enabled", False)),
            auto_approve_on_evidence=bool(getattr(row, "auto_approve_on_evidence", False)),
            evidence_requirements=list(getattr(row, "evidence_requirements", None) or []),
            display_name=row.display_name,
            canvas_base_url=row.canvas_base_url,
            lti_client_id=getattr(row, "lti_client_id", None),
            lti_deployment_id=getattr(row, "lti_deployment_id", None),
            lti_issuer=getattr(row, "lti_issuer", None),
            lti_jwks_url=getattr(row, "lti_jwks_url", None),
            lti_jwks_json=getattr(row, "lti_jwks_json", None),
            lti_jwks_fetched_at=getattr(row, "lti_jwks_fetched_at", None),
            lti_jwks_expires_at=getattr(row, "lti_jwks_expires_at", None),
            lti_openid_configuration=getattr(row, "lti_openid_configuration", None),
            enabled=row.enabled,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_canvas_lti_launch_state(row) -> CanvasLtiLaunchState:
        return CanvasLtiLaunchState(
            id=row.id,
            connector_id=row.connector_id,
            organization_id=row.organization_id,
            canvas_account_id=row.canvas_account_id,
            state=row.state,
            nonce=row.nonce,
            login_hint=row.login_hint,
            target_link_uri=row.target_link_uri,
            lti_message_hint=row.lti_message_hint,
            redirect_uri=row.redirect_uri,
            status=row.status,
            metadata=row.metadata or {},
            created_at=row.created_at,
            expires_at=row.expires_at,
            consumed_at=row.consumed_at,
        )

    @staticmethod
    def _row_to_transaction(row) -> IssuanceTransaction:
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
            issuer_profile_id=getattr(row, "issuer_profile_id", None),
            issuer_mode=getattr(row, "issuer_mode", None) or "org_managed",
            issuer_did_override=getattr(row, "issuer_did_override", None),
            signing_service_id=getattr(row, "signing_service_id", None),
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
                "issuer_profile_id": tx.issuer_profile_id,
                "issuer_mode": tx.issuer_mode or "org_managed",
                "issuer_did_override": tx.issuer_did_override,
                "signing_service_id": tx.signing_service_id,
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
            
            return self._row_to_transaction(row)
    
    async def get_by_pre_auth_code(self, code: str) -> IssuanceTransaction | None:
        async with self._session_factory() as session:
            stmt = select(issuance_transactions_table).where(
                issuance_transactions_table.c.pre_auth_code == code
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return self._row_to_transaction(row)
    
    async def get_by_access_token(self, token: str) -> IssuanceTransaction | None:
        async with self._session_factory() as session:
            stmt = select(issuance_transactions_table).where(
                issuance_transactions_table.c.access_token == _hash_token(token)
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return self._row_to_transaction(row)
    
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

    async def get_credential_display_metadata_for_org(self, org_id: str) -> dict[str, dict[str, Any]]:
        """Return display metadata for issuer metadata from credential templates."""
        from sqlalchemy import text
        async with self._session_factory() as session:
            stmt = text(
                """
                SELECT credential_type, name, description, claims, display_style, vct
                FROM credential_template_service.credential_templates
                WHERE organization_id = :org_id
                  AND status IN ('active', 'draft')
                  AND credential_type IS NOT NULL
                ORDER BY
                  credential_type,
                  CASE WHEN status = 'active' THEN 0 ELSE 1 END,
                  updated_at DESC
                """
            )
            result = await session.execute(stmt, {"org_id": org_id})
            metadata: dict[str, dict[str, Any]] = {}
            for ctype, name, description, claims, display_style, vct in result.all():
                if ctype in metadata:
                    continue
                metadata[ctype] = {
                    "name": name or ctype,
                    "description": description,
                    "claims": claims if isinstance(claims, list) else [],
                    "display_style": display_style if isinstance(display_style, dict) else {},
                    "vct": vct,
                }
            return metadata

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
                "integration_context": app.integration_context,
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
                integration_context=getattr(row, "integration_context", None) or {},
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

    async def save_canvas_event_receipt(self, receipt: CanvasEventReceipt) -> None:
        async with self._session_factory() as session:
            receipt_data = {
                "id": receipt.id,
                "provider_event_id": receipt.provider_event_id,
                "organization_id": receipt.organization_id,
                "credential_template_id": receipt.credential_template_id,
                "canvas_account_id": receipt.canvas_account_id,
                "payload_hash": receipt.payload_hash,
                "issuance_transaction_id": receipt.issuance_transaction_id,
                "issuance_response": receipt.issuance_response,
                "status": receipt.status,
                "error_summary": receipt.error_summary,
                "first_seen_at": receipt.first_seen_at,
                "last_seen_at": receipt.last_seen_at,
            }
            update_data = {
                key: value
                for key, value in receipt_data.items()
                if key not in {"id", "provider_event_id", "first_seen_at"}
            }
            stmt = (
                pg_insert(canvas_event_receipts_table)
                .values(**receipt_data)
                .on_conflict_do_update(
                    index_elements=["canvas_account_id", "provider_event_id"],
                    set_=update_data,
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def get_canvas_event_receipt(
        self,
        provider_event_id: str,
        canvas_account_id: str | None = None,
    ) -> CanvasEventReceipt | None:
        async with self._session_factory() as session:
            stmt = select(canvas_event_receipts_table).where(
                canvas_event_receipts_table.c.provider_event_id == provider_event_id
            )
            if canvas_account_id is not None:
                stmt = stmt.where(canvas_event_receipts_table.c.canvas_account_id == canvas_account_id)
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_canvas_event_receipt(row) if row else None

    async def save_canvas_connector(self, connector: CanvasConnectorConfig) -> None:
        async with self._session_factory() as session:
            data = {
                "id": connector.id,
                "organization_id": connector.organization_id,
                "canvas_account_id": connector.canvas_account_id,
                "credential_template_id": connector.credential_template_id,
                "application_template_id": connector.application_template_id,
                "flow_mode": connector.flow_mode,
                "direct_issue_enabled": connector.direct_issue_enabled,
                "auto_approve_on_evidence": connector.auto_approve_on_evidence,
                "evidence_requirements": connector.evidence_requirements or [],
                "display_name": connector.display_name,
                "canvas_base_url": connector.canvas_base_url,
                "lti_client_id": connector.lti_client_id,
                "lti_deployment_id": connector.lti_deployment_id,
                "lti_issuer": connector.lti_issuer,
                "lti_jwks_url": connector.lti_jwks_url,
                "lti_jwks_json": connector.lti_jwks_json,
                "lti_jwks_fetched_at": connector.lti_jwks_fetched_at,
                "lti_jwks_expires_at": connector.lti_jwks_expires_at,
                "lti_openid_configuration": connector.lti_openid_configuration,
                "enabled": connector.enabled,
                "created_at": connector.created_at,
                "updated_at": connector.updated_at,
            }
            update_data = {
                key: value
                for key, value in data.items()
                if key not in {"id", "created_at"}
            }
            stmt = (
                pg_insert(canvas_connectors_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_=update_data,
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def get_canvas_connector(self, connector_id: str) -> CanvasConnectorConfig | None:
        async with self._session_factory() as session:
            stmt = select(canvas_connectors_table).where(canvas_connectors_table.c.id == connector_id)
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_canvas_connector(row) if row else None

    async def get_canvas_connector_by_account_id(self, canvas_account_id: str) -> CanvasConnectorConfig | None:
        async with self._session_factory() as session:
            stmt = select(canvas_connectors_table).where(
                canvas_connectors_table.c.canvas_account_id == canvas_account_id,
                canvas_connectors_table.c.enabled.is_(True),
            )
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_canvas_connector(row) if row else None

    async def list_canvas_connectors(self, organization_id: str) -> list[CanvasConnectorConfig]:
        async with self._session_factory() as session:
            stmt = select(canvas_connectors_table).where(
                canvas_connectors_table.c.organization_id == organization_id
            )
            result = await session.execute(stmt)
            rows = result.all()
            return [self._row_to_canvas_connector(row) for row in rows]

    async def delete_canvas_connector(self, connector_id: str) -> None:
        async with self._session_factory() as session:
            stmt = delete(canvas_connectors_table).where(canvas_connectors_table.c.id == connector_id)
            await session.execute(stmt)
            await session.commit()

    async def save_canvas_lti_launch_state(self, launch_state: CanvasLtiLaunchState) -> None:
        async with self._session_factory() as session:
            data = {
                "id": launch_state.id,
                "connector_id": launch_state.connector_id,
                "organization_id": launch_state.organization_id,
                "canvas_account_id": launch_state.canvas_account_id,
                "state": launch_state.state,
                "nonce": launch_state.nonce,
                "login_hint": launch_state.login_hint,
                "target_link_uri": launch_state.target_link_uri,
                "lti_message_hint": launch_state.lti_message_hint,
                "redirect_uri": launch_state.redirect_uri,
                "status": launch_state.status,
                "metadata": launch_state.metadata,
                "created_at": launch_state.created_at,
                "expires_at": launch_state.expires_at,
                "consumed_at": launch_state.consumed_at,
            }
            update_data = {
                key: value
                for key, value in data.items()
                if key not in {"id", "state", "created_at"}
            }
            stmt = (
                pg_insert(canvas_lti_launch_states_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["state"],
                    set_=update_data,
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def get_canvas_lti_launch_state(self, state: str) -> CanvasLtiLaunchState | None:
        async with self._session_factory() as session:
            stmt = select(canvas_lti_launch_states_table).where(
                canvas_lti_launch_states_table.c.state == state
            )
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_canvas_lti_launch_state(row) if row else None

    async def consume_canvas_lti_launch_state(self, state: str) -> CanvasLtiLaunchState | None:
        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            stmt = (
                update(canvas_lti_launch_states_table)
                .where(
                    canvas_lti_launch_states_table.c.state == state,
                    canvas_lti_launch_states_table.c.status == "pending",
                    canvas_lti_launch_states_table.c.expires_at > now,
                )
                .values(status="consumed", consumed_at=now)
                .returning(canvas_lti_launch_states_table)
            )
            result = await session.execute(stmt)
            row = result.first()
            await session.commit()
            return self._row_to_canvas_lti_launch_state(row) if row else None

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

    async def get_retention_summary(self, org_id: str, retention_days: int) -> dict[str, Any]:
        cutoff_at = datetime.now(timezone.utc) - timedelta(days=retention_days)
        old_transaction_ids = self._old_transaction_ids_query(org_id, cutoff_at)

        async with self._session_factory() as session:
            expired_transactions = await session.execute(
                select(func.count())
                .select_from(issuance_transactions_table)
                .where(
                    issuance_transactions_table.c.organization_id == org_id,
                    issuance_transactions_table.c.created_at < cutoff_at,
                )
            )
            expired_applications = await session.execute(
                select(func.count())
                .select_from(applications_table)
                .where(
                    applications_table.c.organization_id == org_id,
                    applications_table.c.created_at < cutoff_at,
                )
            )
            expired_auth_sessions = await session.execute(
                select(func.count())
                .select_from(authorization_sessions_table)
                .where(
                    authorization_sessions_table.c.organization_id == org_id,
                    authorization_sessions_table.c.created_at < cutoff_at,
                )
            )
            expired_events = await session.execute(
                select(func.count())
                .select_from(issuance_events_table)
                .where(
                    issuance_events_table.c.created_at < cutoff_at,
                    self._event_org_condition(org_id),
                )
            )
            expired_credentials = await session.execute(
                select(func.count())
                .select_from(issued_credentials_table)
                .where(
                    issued_credentials_table.c.organization_id == org_id,
                    issued_credentials_table.c.transaction_id.in_(old_transaction_ids),
                )
            )

            eligible_for_purge = {
                "issuance_transactions": int(expired_transactions.scalar_one() or 0),
                "applications": int(expired_applications.scalar_one() or 0),
                "authorization_sessions": int(expired_auth_sessions.scalar_one() or 0),
                "issuance_events": int(expired_events.scalar_one() or 0),
                "issued_credentials": int(expired_credentials.scalar_one() or 0),
            }
            eligible_for_purge["total"] = sum(eligible_for_purge.values())

            transaction_min = await session.execute(
                select(func.min(issuance_transactions_table.c.created_at)).where(
                    issuance_transactions_table.c.organization_id == org_id,
                    issuance_transactions_table.c.created_at >= cutoff_at,
                )
            )
            application_min = await session.execute(
                select(func.min(applications_table.c.created_at)).where(
                    applications_table.c.organization_id == org_id,
                    applications_table.c.created_at >= cutoff_at,
                )
            )
            auth_session_min = await session.execute(
                select(func.min(authorization_sessions_table.c.created_at)).where(
                    authorization_sessions_table.c.organization_id == org_id,
                    authorization_sessions_table.c.created_at >= cutoff_at,
                )
            )
            event_min = await session.execute(
                select(func.min(issuance_events_table.c.created_at)).where(
                    issuance_events_table.c.created_at >= cutoff_at,
                    self._event_org_condition(org_id),
                )
            )

            retained_candidates = [
                transaction_min.scalar_one_or_none(),
                application_min.scalar_one_or_none(),
                auth_session_min.scalar_one_or_none(),
                event_min.scalar_one_or_none(),
            ]
            retained_candidates = [candidate for candidate in retained_candidates if candidate is not None]

        oldest_retained_record_at = min(retained_candidates) if retained_candidates else None
        next_expiry_at = (
            oldest_retained_record_at + timedelta(days=retention_days)
            if oldest_retained_record_at else None
        )

        return {
            "organization_id": org_id,
            "retention_days": retention_days,
            "cutoff_at": cutoff_at.isoformat(),
            "oldest_retained_record_at": oldest_retained_record_at.isoformat() if oldest_retained_record_at else None,
            "next_expiry_at": next_expiry_at.isoformat() if next_expiry_at else None,
            "eligible_for_purge": eligible_for_purge,
            "tracked_scope": [
                "applications",
                "submitted_evidence",
                "issuance_transactions",
                "issued_credentials",
                "authorization_sessions",
                "issuance_events",
            ],
        }

    async def purge_retention_records(self, org_id: str, retention_days: int) -> dict[str, Any]:
        summary = await self.get_retention_summary(org_id, retention_days)
        cutoff_at = datetime.now(timezone.utc) - timedelta(days=retention_days)
        old_transaction_ids = self._old_transaction_ids_query(org_id, cutoff_at)

        async with self._session_factory() as session:
            delete_events_result = await session.execute(
                delete(issuance_events_table).where(
                    issuance_events_table.c.created_at < cutoff_at,
                    self._event_org_condition(org_id),
                )
            )
            delete_auth_sessions_result = await session.execute(
                delete(authorization_sessions_table).where(
                    authorization_sessions_table.c.organization_id == org_id,
                    authorization_sessions_table.c.created_at < cutoff_at,
                )
            )
            delete_applications_result = await session.execute(
                delete(applications_table).where(
                    applications_table.c.organization_id == org_id,
                    applications_table.c.created_at < cutoff_at,
                )
            )
            delete_transactions_result = await session.execute(
                delete(issuance_transactions_table).where(
                    issuance_transactions_table.c.organization_id == org_id,
                    issuance_transactions_table.c.created_at < cutoff_at,
                )
            )
            await session.commit()

        post_purge = await self.get_retention_summary(org_id, retention_days)
        purged_records = {
            "issuance_transactions": self._result_rowcount(delete_transactions_result),
            "applications": self._result_rowcount(delete_applications_result),
            "authorization_sessions": self._result_rowcount(delete_auth_sessions_result),
            "issuance_events": self._result_rowcount(delete_events_result),
            "issued_credentials": int(summary["eligible_for_purge"].get("issued_credentials", 0)),
        }
        purged_records["total"] = sum(purged_records.values())

        return {
            "organization_id": org_id,
            "retention_days": retention_days,
            "cutoff_at": cutoff_at.isoformat(),
            "purged_at": datetime.now(timezone.utc).isoformat(),
            "purged_records": purged_records,
            "next_expiry_at": post_purge["next_expiry_at"],
            "oldest_retained_record_at": post_purge["oldest_retained_record_at"],
            "tracked_scope": summary["tracked_scope"],
        }
