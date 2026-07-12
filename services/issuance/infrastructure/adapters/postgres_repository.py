"""PostgreSQL adapter for Issuance Repository."""

import hashlib
import hmac
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, case, delete, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    ApprovalPolicySet,
    AuthorizationSession,
    CanvasEventReceipt,
    CanvasLtiLaunchState,
    CanvasPlatform,
    CanvasProgramBinding,
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    DeliveryTarget,
    EvidenceFact,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
    CredentialStatus,
    EventType,
    OrganizationIntegrationSecret,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.models import (
    application_templates_table,
    applications_table,
    authorization_sessions_table,
    canvas_event_receipts_table,
    canvas_lti_launch_states_table,
    canvas_platforms_table,
    canvas_program_bindings_table,
    credential_delivery_records_table,
    evidence_facts_table,
    issued_credentials_table,
    issuance_events_table,
    issuance_transactions_table,
    organization_integration_secrets_table,
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
logger = logging.getLogger(__name__)
_integration_secret_encryption = None


def _get_integration_secret_encryption():
    """Return AES-GCM encryption for organization integration secrets."""
    global _integration_secret_encryption
    if _integration_secret_encryption is None:
        try:
            from status_list.infrastructure.security.encryption import SymmetricEncryption
        except ImportError as exc:  # pragma: no cover - deployment packaging guard
            raise RuntimeError("status_list encryption package is required for integration secrets") from exc
        env_name = os.environ.get("INTEGRATION_SECRET_MASTER_KEY_ENV", "INTEGRATION_SECRET_MASTER_KEY")
        if not os.environ.get(env_name):
            key_file = os.environ.get(f"{env_name}_FILE")
            if key_file:
                try:
                    with open(key_file, "r", encoding="utf-8") as handle:
                        os.environ[env_name] = handle.read().strip()
                except OSError as exc:
                    raise RuntimeError(f"{env_name}_FILE could not be read: {key_file}") from exc
        _integration_secret_encryption = SymmetricEncryption.from_env(env_name)
    return _integration_secret_encryption


def _hash_token(raw_token: str | None) -> str | None:
    """Return the HMAC-SHA256 hex digest of *raw_token*, or None."""
    if not raw_token:
        return None
    return hmac.new(_TOKEN_HMAC_KEY, raw_token.encode(), hashlib.sha256).hexdigest()


class PostgresIssuanceRepository(IIssuanceRepository):
    """PostgreSQL implementation of issuance repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
        self._approval_policy_cache_ttl_seconds = int(
            os.environ.get("ISSUANCE_APPROVAL_POLICY_CACHE_SECONDS", "60")
        )
        self._approval_policy_cache: dict[
            tuple[str, str],
            tuple[datetime, ApprovalPolicySet | None],
        ] = {}

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
    def _row_to_canvas_platform(row) -> CanvasPlatform:
        return CanvasPlatform(
            id=row.id,
            organization_id=row.organization_id,
            canvas_account_id=row.canvas_account_id,
            display_name=row.display_name,
            canvas_base_url=row.canvas_base_url,
            lti_client_id=row.lti_client_id,
            lti_deployment_id=row.lti_deployment_id,
            lti_issuer=row.lti_issuer,
            lti_jwks_url=row.lti_jwks_url,
            lti_jwks_json=row.lti_jwks_json,
            lti_jwks_fetched_at=row.lti_jwks_fetched_at,
            lti_jwks_expires_at=row.lti_jwks_expires_at,
            lti_openid_configuration=row.lti_openid_configuration,
            enabled=row.enabled,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_canvas_program_binding(row) -> CanvasProgramBinding:
        return CanvasProgramBinding(
            id=row.id,
            organization_id=row.organization_id,
            platform_id=row.platform_id,
            application_template_id=row.application_template_id,
            credential_template_id=row.credential_template_id,
            display_name=row.display_name,
            flow_mode=row.flow_mode or "elevenid_orchestrated_canvas_evidence",
            direct_issue_enabled=bool(row.direct_issue_enabled),
            auto_approve_on_evidence=bool(row.auto_approve_on_evidence),
            evidence_requirements=list(row.evidence_requirements or []),
            canvas_scope=row.canvas_scope or {},
            delivery_mode=row.delivery_mode or "wallet_only",
            issuer_mode=row.issuer_mode or "org_managed",
            approval_policy_set_id=row.approval_policy_set_id,
            deployment_profile_id=getattr(row, "deployment_profile_id", None),
            feature_flags=dict(getattr(row, "feature_flags", None) or {}),
            canvas_credentials=dict(getattr(row, "canvas_credentials", None) or {}),
            enabled=row.enabled,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_canvas_lti_launch_state(row) -> CanvasLtiLaunchState:
        return CanvasLtiLaunchState(
            id=row.id,
            platform_id=row.platform_id,
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
    def _row_to_integration_secret(row) -> OrganizationIntegrationSecret:
        return OrganizationIntegrationSecret(
            id=row.id,
            organization_id=row.organization_id,
            name=row.name,
            provider=row.provider,
            purpose=row.purpose,
            secret_value="",
            secret_hint=row.secret_hint,
            metadata=row.metadata or {},
            enabled=bool(row.enabled),
            created_at=row.created_at,
            updated_at=row.updated_at,
            last_used_at=row.last_used_at,
        )

    @staticmethod
    def _row_to_delivery_record(row) -> CredentialDeliveryRecord:
        return CredentialDeliveryRecord(
            id=row.id,
            credential_id=row.credential_id,
            transaction_id=row.transaction_id,
            organization_id=row.organization_id,
            delivery_target=DeliveryTarget(row.delivery_target),
            delivery_mode=row.delivery_mode or "wallet_only",
            status=CredentialDeliveryStatus(row.status),
            canvas_account_id=row.canvas_account_id,
            external_credential_id=row.external_credential_id,
            external_issuer_id=row.external_issuer_id,
            last_error=row.last_error,
            metadata=row.metadata or {},
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_evidence_fact(row) -> EvidenceFact:
        return EvidenceFact(
            id=row.id,
            organization_id=row.organization_id,
            application_id=row.application_id,
            subject_id=row.subject_id,
            provider=row.provider,
            fact_type=row.fact_type,
            scope=row.scope or {},
            assertion=row.assertion or {},
            verification=row.verification or {},
            source=row.source or {},
            created_at=row.created_at,
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
            delivery_mode=getattr(row, "delivery_mode", None) or "wallet_only",
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
                "delivery_mode": tx.delivery_mode or "wallet_only",
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
                "issuer_did": cred.issuer_did,
                "revocation_profile_id": cred.revocation_profile_id,
                "status_list_entries": cred.status_list_entries,
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
                issuer_did=row.issuer_did,
                revocation_profile_id=getattr(row, "revocation_profile_id", None),
                status_list_entries=getattr(row, "status_list_entries", None) or [],
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
                issuer_did=row.issuer_did,
                revocation_profile_id=getattr(row, "revocation_profile_id", None),
                status_list_entries=getattr(row, "status_list_entries", None) or [],
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

    async def save_delivery_record(self, record: CredentialDeliveryRecord) -> None:
        async with self._session_factory() as session:
            data = {
                "id": record.id,
                "credential_id": record.credential_id,
                "transaction_id": record.transaction_id,
                "organization_id": record.organization_id,
                "delivery_target": record.delivery_target.value,
                "delivery_mode": record.delivery_mode,
                "status": record.status.value,
                "canvas_account_id": record.canvas_account_id,
                "external_credential_id": record.external_credential_id,
                "external_issuer_id": record.external_issuer_id,
                "last_error": record.last_error,
                "metadata": record.metadata,
                "created_at": record.created_at,
                "updated_at": record.updated_at,
            }
            update_data = {
                key: value
                for key, value in data.items()
                if key not in {"id", "created_at"}
            }
            stmt = (
                pg_insert(credential_delivery_records_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_=update_data,
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def get_delivery_record(self, record_id: str) -> CredentialDeliveryRecord | None:
        async with self._session_factory() as session:
            stmt = select(credential_delivery_records_table).where(
                credential_delivery_records_table.c.id == record_id
            )
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_delivery_record(row) if row else None

    async def get_canvas_delivery_record_by_external_credential_id(
        self,
        external_credential_id: str,
        *,
        canvas_account_id: str | None = None,
        organization_id: str | None = None,
    ) -> CredentialDeliveryRecord | None:
        async with self._session_factory() as session:
            stmt = select(credential_delivery_records_table).where(
                credential_delivery_records_table.c.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS.value,
                credential_delivery_records_table.c.external_credential_id == external_credential_id,
            )
            if canvas_account_id is not None:
                stmt = stmt.where(credential_delivery_records_table.c.canvas_account_id == canvas_account_id)
            if organization_id is not None:
                stmt = stmt.where(credential_delivery_records_table.c.organization_id == organization_id)
            stmt = stmt.order_by(credential_delivery_records_table.c.created_at.desc()).limit(1)
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_delivery_record(row) if row else None

    async def list_delivery_records_for_credential(self, credential_id: str) -> list[CredentialDeliveryRecord]:
        async with self._session_factory() as session:
            stmt = (
                select(credential_delivery_records_table)
                .where(credential_delivery_records_table.c.credential_id == credential_id)
                .order_by(
                    credential_delivery_records_table.c.created_at,
                    case(
                        (credential_delivery_records_table.c.delivery_target == "wallet", 0),
                        (credential_delivery_records_table.c.delivery_target == "didcomm_v2", 1),
                        (credential_delivery_records_table.c.delivery_target == "canvas_credentials", 2),
                        else_=99,
                    ),
                    credential_delivery_records_table.c.delivery_target,
                )
            )
            result = await session.execute(stmt)
            rows = result.all()
            return [self._row_to_delivery_record(row) for row in rows]

    async def list_delivery_records(
        self,
        *,
        delivery_target: DeliveryTarget | None = None,
        statuses: list[CredentialDeliveryStatus] | None = None,
        organization_id: str | None = None,
        limit: int | None = None,
    ) -> list[CredentialDeliveryRecord]:
        async with self._session_factory() as session:
            stmt = select(credential_delivery_records_table)
            if delivery_target is not None:
                stmt = stmt.where(
                    credential_delivery_records_table.c.delivery_target == delivery_target.value
                )
            if statuses is not None:
                stmt = stmt.where(
                    credential_delivery_records_table.c.status.in_([status.value for status in statuses])
                )
            if organization_id is not None:
                stmt = stmt.where(
                    credential_delivery_records_table.c.organization_id == organization_id
                )
            stmt = stmt.order_by(
                credential_delivery_records_table.c.created_at,
                case(
                    (credential_delivery_records_table.c.delivery_target == "wallet", 0),
                    (credential_delivery_records_table.c.delivery_target == "didcomm_v2", 1),
                    (credential_delivery_records_table.c.delivery_target == "canvas_credentials", 2),
                    else_=99,
                ),
                credential_delivery_records_table.c.delivery_target,
            )
            if limit is not None:
                stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            rows = result.all()
            return [self._row_to_delivery_record(row) for row in rows]

    async def save_evidence_fact(self, fact: EvidenceFact) -> None:
        async with self._session_factory() as session:
            data = {
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
                "created_at": fact.created_at,
            }
            stmt = (
                pg_insert(evidence_facts_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        key: value
                        for key, value in data.items()
                        if key not in {"id", "created_at"}
                    },
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def list_evidence_facts_for_application(self, application_id: str) -> list[EvidenceFact]:
        async with self._session_factory() as session:
            stmt = (
                select(evidence_facts_table)
                .where(evidence_facts_table.c.application_id == application_id)
                .order_by(evidence_facts_table.c.created_at)
            )
            result = await session.execute(stmt)
            rows = result.all()
            return [self._row_to_evidence_fact(row) for row in rows]

    async def get_approval_policy_set(
        self,
        organization_id: str,
        policy_set_id: str,
    ) -> ApprovalPolicySet | None:
        cache_key = (organization_id, policy_set_id)
        now = datetime.now(timezone.utc)
        cached = self._approval_policy_cache.get(cache_key)
        if cached is not None:
            cached_at, cached_policy = cached
            cache_age = (now - cached_at).total_seconds()
            if cache_age <= self._approval_policy_cache_ttl_seconds:
                return cached_policy

        try:
            async with self._session_factory() as session:
                result = await session.execute(
                    text(
                        """
                        SELECT
                            id,
                            organization_id,
                            policy_type,
                            status,
                            cedar_policies,
                            cedar_schema_version,
                            updated_at
                        FROM organization_service.policy_sets
                        WHERE id = :policy_set_id
                          AND organization_id = :organization_id
                        """
                    ),
                    {
                        "policy_set_id": policy_set_id,
                        "organization_id": organization_id,
                    },
                )
                row = result.mappings().first()
        except SQLAlchemyError as exc:
            logger.warning(
                "Unable to load approval PolicySet %s for organization %s: %s",
                policy_set_id,
                organization_id,
                exc,
            )
            self._approval_policy_cache[cache_key] = (now, None)
            return None

        policy_set = (
            ApprovalPolicySet(
                id=str(row["id"]),
                organization_id=str(row["organization_id"]),
                policy_type=str(row["policy_type"] or ""),
                status=str(row["status"] or ""),
                cedar_policies=row["cedar_policies"],
                cedar_schema_version=row.get("cedar_schema_version"),
                updated_at=row.get("updated_at"),
            )
            if row
            else None
        )
        self._approval_policy_cache[cache_key] = (now, policy_set)
        return policy_set
    
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
                "approval_policy_set_id": template.approval_policy_set_id,
                "application_validity_days": template.application_validity_days,
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
                approval_policy_set_id=getattr(row, "approval_policy_set_id", None),
                application_validity_days=row.application_validity_days,
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

    async def delete_application_template(self, template_id: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                application_templates_table.delete().where(
                    application_templates_table.c.id == template_id
                )
            )
            await session.commit()
            return bool(result.rowcount)
    
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

    async def list_canvas_event_receipts(
        self,
        *,
        organization_id: str | None = None,
        status: str | None = None,
        limit: int | None = None,
    ) -> list[CanvasEventReceipt]:
        async with self._session_factory() as session:
            conditions = []
            if organization_id is not None:
                conditions.append(canvas_event_receipts_table.c.organization_id == organization_id)
            if status is not None:
                conditions.append(canvas_event_receipts_table.c.status == status)

            stmt = select(canvas_event_receipts_table).order_by(
                canvas_event_receipts_table.c.last_seen_at
            )
            if conditions:
                stmt = stmt.where(and_(*conditions))
            if limit is not None:
                stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return [
                self._row_to_canvas_event_receipt(row)
                for row in result.all()
            ]

    async def save_canvas_platform(self, platform: CanvasPlatform) -> None:
        async with self._session_factory() as session:
            data = {
                "id": platform.id,
                "organization_id": platform.organization_id,
                "canvas_account_id": platform.canvas_account_id,
                "display_name": platform.display_name,
                "canvas_base_url": platform.canvas_base_url,
                "lti_client_id": platform.lti_client_id,
                "lti_deployment_id": platform.lti_deployment_id,
                "lti_issuer": platform.lti_issuer,
                "lti_jwks_url": platform.lti_jwks_url,
                "lti_jwks_json": platform.lti_jwks_json,
                "lti_jwks_fetched_at": platform.lti_jwks_fetched_at,
                "lti_jwks_expires_at": platform.lti_jwks_expires_at,
                "lti_openid_configuration": platform.lti_openid_configuration,
                "enabled": platform.enabled,
                "created_at": platform.created_at,
                "updated_at": platform.updated_at,
            }
            update_data = {
                key: value
                for key, value in data.items()
                if key not in {"id", "created_at"}
            }
            stmt = (
                pg_insert(canvas_platforms_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_=update_data,
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def get_canvas_platform(self, platform_id: str) -> CanvasPlatform | None:
        async with self._session_factory() as session:
            stmt = select(canvas_platforms_table).where(canvas_platforms_table.c.id == platform_id)
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_canvas_platform(row) if row else None

    async def get_canvas_platform_by_account_id(
        self,
        organization_id: str,
        canvas_account_id: str,
    ) -> CanvasPlatform | None:
        async with self._session_factory() as session:
            stmt = select(canvas_platforms_table).where(
                canvas_platforms_table.c.organization_id == organization_id,
                canvas_platforms_table.c.canvas_account_id == canvas_account_id,
            )
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_canvas_platform(row) if row else None

    async def list_canvas_platforms(self, organization_id: str) -> list[CanvasPlatform]:
        async with self._session_factory() as session:
            stmt = (
                select(canvas_platforms_table)
                .where(canvas_platforms_table.c.organization_id == organization_id)
                .order_by(canvas_platforms_table.c.created_at)
            )
            result = await session.execute(stmt)
            return [self._row_to_canvas_platform(row) for row in result.all()]

    async def delete_canvas_platform(self, platform_id: str) -> None:
        async with self._session_factory() as session:
            stmt = delete(canvas_platforms_table).where(canvas_platforms_table.c.id == platform_id)
            await session.execute(stmt)
            await session.commit()

    async def save_canvas_program_binding(self, binding: CanvasProgramBinding) -> None:
        async with self._session_factory() as session:
            data = {
                "id": binding.id,
                "organization_id": binding.organization_id,
                "platform_id": binding.platform_id,
                "application_template_id": binding.application_template_id,
                "credential_template_id": binding.credential_template_id,
                "display_name": binding.display_name,
                "flow_mode": binding.flow_mode,
                "direct_issue_enabled": binding.direct_issue_enabled,
                "auto_approve_on_evidence": binding.auto_approve_on_evidence,
                "evidence_requirements": binding.evidence_requirements or [],
                "canvas_scope": binding.canvas_scope or {},
                "delivery_mode": binding.delivery_mode or "wallet_only",
                "issuer_mode": binding.issuer_mode or "org_managed",
                "approval_policy_set_id": binding.approval_policy_set_id,
                "deployment_profile_id": binding.deployment_profile_id,
                "feature_flags": binding.feature_flags or {},
                "canvas_credentials": binding.canvas_credentials or {},
                "enabled": binding.enabled,
                "created_at": binding.created_at,
                "updated_at": binding.updated_at,
            }
            update_data = {
                key: value
                for key, value in data.items()
                if key not in {"id", "created_at"}
            }
            stmt = (
                pg_insert(canvas_program_bindings_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_=update_data,
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def get_canvas_program_binding(self, binding_id: str) -> CanvasProgramBinding | None:
        async with self._session_factory() as session:
            stmt = select(canvas_program_bindings_table).where(
                canvas_program_bindings_table.c.id == binding_id
            )
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_canvas_program_binding(row) if row else None

    async def list_canvas_program_bindings(
        self,
        organization_id: str,
        platform_id: str | None = None,
        application_template_id: str | None = None,
    ) -> list[CanvasProgramBinding]:
        async with self._session_factory() as session:
            conditions = [canvas_program_bindings_table.c.organization_id == organization_id]
            if platform_id is not None:
                conditions.append(canvas_program_bindings_table.c.platform_id == platform_id)
            if application_template_id is not None:
                conditions.append(
                    canvas_program_bindings_table.c.application_template_id == application_template_id
                )
            stmt = (
                select(canvas_program_bindings_table)
                .where(and_(*conditions))
                .order_by(canvas_program_bindings_table.c.created_at)
            )
            result = await session.execute(stmt)
            return [self._row_to_canvas_program_binding(row) for row in result.all()]

    async def delete_canvas_program_binding(self, binding_id: str) -> None:
        async with self._session_factory() as session:
            stmt = delete(canvas_program_bindings_table).where(
                canvas_program_bindings_table.c.id == binding_id
            )
            await session.execute(stmt)
            await session.commit()

    async def save_integration_secret(self, secret: OrganizationIntegrationSecret) -> None:
        encryption = _get_integration_secret_encryption()
        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            existing_result = await session.execute(
                select(organization_integration_secrets_table).where(
                    organization_integration_secrets_table.c.id == secret.id
                )
            )
            existing = existing_result.first()
            encrypted_value = (
                encryption.encrypt(secret.secret_value)
                if secret.secret_value
                else (existing.encrypted_secret_value if existing else None)
            )
            if not encrypted_value:
                raise ValueError("secret_value is required when creating an integration secret")
            secret_hint = secret.secret_hint
            if not secret_hint and secret.secret_value:
                secret_hint = f"...{secret.secret_value[-4:]}"
            data = {
                "id": secret.id,
                "organization_id": secret.organization_id,
                "name": secret.name,
                "provider": secret.provider,
                "purpose": secret.purpose or "api_token",
                "encrypted_secret_value": encrypted_value,
                "secret_hint": secret_hint,
                "metadata": secret.metadata or {},
                "enabled": secret.enabled,
                "created_at": existing.created_at if existing else secret.created_at,
                "updated_at": now,
                "last_used_at": secret.last_used_at if secret.last_used_at else (existing.last_used_at if existing else None),
            }
            stmt = (
                pg_insert(organization_integration_secrets_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_={key: value for key, value in data.items() if key not in {"id", "created_at"}},
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def get_integration_secret(self, secret_id: str) -> OrganizationIntegrationSecret | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(organization_integration_secrets_table).where(
                    organization_integration_secrets_table.c.id == secret_id
                )
            )
            row = result.first()
            return self._row_to_integration_secret(row) if row else None

    async def list_integration_secrets(
        self,
        organization_id: str,
        provider: str | None = None,
    ) -> list[OrganizationIntegrationSecret]:
        async with self._session_factory() as session:
            conditions = [organization_integration_secrets_table.c.organization_id == organization_id]
            if provider is not None:
                conditions.append(organization_integration_secrets_table.c.provider == provider)
            stmt = (
                select(organization_integration_secrets_table)
                .where(and_(*conditions))
                .order_by(organization_integration_secrets_table.c.created_at)
            )
            result = await session.execute(stmt)
            return [self._row_to_integration_secret(row) for row in result.all()]

    async def get_integration_secret_value(self, organization_id: str, secret_id: str) -> str | None:
        encryption = _get_integration_secret_encryption()
        async with self._session_factory() as session:
            result = await session.execute(
                select(organization_integration_secrets_table).where(
                    organization_integration_secrets_table.c.id == secret_id,
                    organization_integration_secrets_table.c.organization_id == organization_id,
                    organization_integration_secrets_table.c.enabled == True,  # noqa: E712
                )
            )
            row = result.first()
            if row is None:
                return None
            await session.execute(
                update(organization_integration_secrets_table)
                .where(organization_integration_secrets_table.c.id == secret_id)
                .values(last_used_at=datetime.now(timezone.utc))
            )
            await session.commit()
        return encryption.decrypt(row.encrypted_secret_value)

    async def delete_integration_secret(self, secret_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                delete(organization_integration_secrets_table).where(
                    organization_integration_secrets_table.c.id == secret_id
                )
            )
            await session.commit()

    async def save_canvas_lti_launch_state(self, launch_state: CanvasLtiLaunchState) -> None:
        async with self._session_factory() as session:
            data = {
                "id": launch_state.id,
                "platform_id": launch_state.platform_id,
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
