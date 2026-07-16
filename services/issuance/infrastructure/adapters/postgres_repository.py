"""PostgreSQL adapter for Issuance Repository."""

import copy
import hashlib
import hmac
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    ApprovalPolicySet,
    AuthorizationSession,
    CanvasAwardCandidate,
    CanvasAwardCandidateState,
    CanvasCandidateObservation,
    CanvasEventReceipt,
    CanvasEvidenceSyncJob,
    CanvasEvidenceSyncJobStatus,
    CanvasEvidenceSyncTarget,
    CanvasEvidenceSyncTargetType,
    CanvasLearnerIdentity,
    CanvasLearnerIdentityStatus,
    CanvasLtiLaunchState,
    CanvasOAuthAuthorization,
    CanvasOAuthConnection,
    CanvasOAuthConnectionStatus,
    CanvasPlatform,
    CanvasProgramBinding,
    CanvasSyncReadinessState,
    CanvasWorkerHeartbeat,
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    CredentialStatus,
    DeliveryTarget,
    EventType,
    EvidenceFact,
    EvidenceFactHead,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
    OrganizationIntegrationSecret,
    canvas_evidence_requirements_to_json,
    issuance_save_predecessors,
)
from issuance.domain.ports import (
    CanvasEvidenceAtomicCommit,
    CanvasEvidenceTransitionPlanner,
    IIssuanceRepository,
    merge_application_integration_context,
)
from issuance.infrastructure.models import (
    application_templates_table,
    applications_table,
    authorization_sessions_table,
    canvas_award_candidates_table,
    canvas_candidate_observations_table,
    canvas_event_receipts_table,
    canvas_evidence_sync_jobs_table,
    canvas_evidence_sync_targets_table,
    canvas_learner_identities_table,
    canvas_lti_launch_states_table,
    canvas_oauth_authorizations_table,
    canvas_oauth_connections_table,
    canvas_platforms_table,
    canvas_program_bindings_table,
    canvas_worker_heartbeats_table,
    credential_delivery_records_table,
    evidence_fact_heads_table,
    evidence_facts_table,
    evidence_policy_reviews_table,
    issuance_events_table,
    issuance_transactions_table,
    issued_credentials_table,
    organization_integration_secrets_table,
)
from sqlalchemy import and_, case, delete, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _read_required_secret(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value

    secret_file = os.environ.get(f"{name}_FILE", "").strip()
    if secret_file:
        try:
            value = Path(secret_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(f"{name}_FILE could not be read: {secret_file}") from exc
        if value:
            return value

    raise RuntimeError(f"{name} or {name}_FILE is required")


_TOKEN_HMAC_KEY_RAW = _read_required_secret("TOKEN_HMAC_KEY")
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
                    with open(key_file, encoding="utf-8") as handle:
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


def _canvas_application_context(integration_context: Any) -> dict[str, Any] | None:
    context = integration_context if isinstance(integration_context, dict) else {}
    canvas = context.get("canvas")
    if not isinstance(canvas, dict):
        return None
    source = str(canvas.get("source") or "").strip().lower()
    if not (
        str(canvas.get("canvas_platform_id") or "").strip()
        or str(canvas.get("canvas_program_binding_id") or "").strip()
        or str(canvas.get("canvas_account_id") or "").strip()
        or source.startswith("canvas")
    ):
        return None
    return canvas


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
            lti_trust_profile=(
                getattr(row, "lti_trust_profile", None) or "hosted_global"
            ),
            lti_issuer=row.lti_issuer,
            lti_jwks_url=row.lti_jwks_url,
            lti_jwks_json=row.lti_jwks_json,
            lti_jwks_fetched_at=row.lti_jwks_fetched_at,
            lti_jwks_expires_at=row.lti_jwks_expires_at,
            lti_openid_configuration=row.lti_openid_configuration,
            registration_status=getattr(row, "registration_status", None) or "draft",
            connection_config=dict(getattr(row, "connection_config", None) or {}),
            capability_snapshot=dict(getattr(row, "capability_snapshot", None) or {}),
            last_validated_at=getattr(row, "last_validated_at", None),
            last_connection_error=getattr(row, "last_connection_error", None),
            config_version=getattr(row, "config_version", None) or 1,
            archived_at=getattr(row, "archived_at", None),
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
            config_version=getattr(row, "config_version", None) or 1,
            validated_config_version=getattr(row, "validated_config_version", None),
            readiness_checks=list(getattr(row, "readiness_checks", None) or []),
            readiness_validated_at=getattr(row, "readiness_validated_at", None),
            activated_at=getattr(row, "activated_at", None),
            archived_at=getattr(row, "archived_at", None),
            credential_template_snapshot=dict(
                getattr(row, "credential_template_snapshot", None) or {}
            ),
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
            requirement_id=getattr(row, "requirement_id", None),
            logical_key=getattr(row, "logical_key", None) or "",
            source_revision=getattr(row, "source_revision", None) or "",
            payload_hash=getattr(row, "payload_hash", None) or "",
            observed_at=getattr(row, "observed_at", None) or row.created_at,
            effective_at=getattr(row, "effective_at", None) or row.created_at,
            superseded_fact_id=getattr(row, "superseded_fact_id", None),
            created_at=row.created_at,
        )

    @staticmethod
    def _row_to_application(row) -> Application:
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

    @staticmethod
    def _row_to_evidence_fact_head(row) -> EvidenceFactHead:
        return EvidenceFactHead(
            organization_id=row.organization_id,
            application_id=row.application_id,
            logical_key=row.logical_key,
            fact_id=row.fact_id,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_canvas_learner_identity(row) -> CanvasLearnerIdentity:
        return CanvasLearnerIdentity(
            id=row.id,
            organization_id=row.organization_id,
            platform_id=row.platform_id,
            deployment_id=row.deployment_id,
            lti_subject=row.lti_subject,
            canvas_user_id=row.canvas_user_id,
            sis_user_id=row.sis_user_id,
            status=CanvasLearnerIdentityStatus(row.status),
            conflict_reason=row.conflict_reason,
            verified_at=row.verified_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_canvas_oauth_authorization(row) -> CanvasOAuthAuthorization:
        return CanvasOAuthAuthorization(
            id=row.id,
            organization_id=row.organization_id,
            platform_id=row.platform_id,
            canvas_base_url=row.canvas_base_url,
            platform_config_version=row.platform_config_version,
            client_id=row.client_id,
            client_secret_ref=row.client_secret_ref,
            state_hash=row.state_hash,
            capabilities=list(row.capabilities or []),
            scopes=list(row.scopes or []),
            redirect_uri=row.redirect_uri,
            expires_at=row.expires_at,
            consumed_at=row.consumed_at,
            created_at=row.created_at,
        )

    @staticmethod
    def _row_to_canvas_oauth_connection(row) -> CanvasOAuthConnection:
        return CanvasOAuthConnection(
            id=row.id,
            organization_id=row.organization_id,
            platform_id=row.platform_id,
            canvas_base_url=row.canvas_base_url,
            platform_config_version=row.platform_config_version,
            client_id=row.client_id,
            client_secret_ref=row.client_secret_ref,
            capabilities=list(row.capabilities or []),
            scopes=list(row.scopes or []),
            access_token_secret_ref=row.access_token_secret_ref,
            refresh_token_secret_ref=row.refresh_token_secret_ref,
            token_expires_at=row.token_expires_at,
            status=CanvasOAuthConnectionStatus(row.status),
            reauthorization_required=bool(row.reauthorization_required),
            refresh_lease_owner=row.refresh_lease_owner,
            refresh_lease_expires_at=row.refresh_lease_expires_at,
            revoke_retry_count=row.revoke_retry_count,
            revoke_retry_at=row.revoke_retry_at,
            revoke_last_error_code=row.revoke_last_error_code,
            connected_at=row.connected_at,
            last_refreshed_at=row.last_refreshed_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_canvas_sync_target(row) -> CanvasEvidenceSyncTarget:
        return CanvasEvidenceSyncTarget(
            id=row.id,
            organization_id=row.organization_id,
            platform_id=row.platform_id,
            binding_id=row.binding_id,
            target_type=CanvasEvidenceSyncTargetType(row.target_type),
            logical_key=row.logical_key,
            application_id=row.application_id,
            candidate_id=row.candidate_id,
            enabled=bool(row.enabled),
            schedule_seconds=row.schedule_seconds,
            next_run_at=row.next_run_at,
            last_enqueued_at=row.last_enqueued_at,
            last_succeeded_at=row.last_succeeded_at,
            config_version=row.config_version,
            metadata=row.metadata or {},
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_canvas_sync_job(row) -> CanvasEvidenceSyncJob:
        return CanvasEvidenceSyncJob(
            id=row.id,
            organization_id=row.organization_id,
            target_id=row.target_id,
            status=CanvasEvidenceSyncJobStatus(row.status),
            attempt_count=row.attempt_count,
            max_attempts=row.max_attempts,
            available_at=row.available_at,
            lease_owner=row.lease_owner,
            lease_expires_at=row.lease_expires_at,
            last_error_code=row.last_error_code,
            last_error_summary=row.last_error_summary,
            result=row.result or {},
            created_at=row.created_at,
            updated_at=row.updated_at,
            started_at=row.started_at,
            completed_at=row.completed_at,
        )

    @staticmethod
    def _row_to_canvas_worker_heartbeat(row) -> CanvasWorkerHeartbeat:
        return CanvasWorkerHeartbeat(
            worker_id=row.worker_id,
            role=row.role,
            started_at=row.started_at,
            last_heartbeat_at=row.last_heartbeat_at,
            metadata=row.metadata or {},
        )

    @staticmethod
    def _row_to_canvas_award_candidate(row) -> CanvasAwardCandidate:
        return CanvasAwardCandidate(
            id=row.id,
            organization_id=row.organization_id,
            platform_id=row.platform_id,
            binding_id=row.binding_id,
            candidate_key=row.candidate_key,
            learner_identity_id=row.learner_identity_id,
            canvas_user_id=row.canvas_user_id,
            lti_subject=row.lti_subject,
            state=CanvasAwardCandidateState(row.state),
            application_id=row.application_id,
            claimed_credential_id=row.claimed_credential_id,
            observed_at=row.observed_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_canvas_candidate_observation(row) -> CanvasCandidateObservation:
        return CanvasCandidateObservation(
            id=row.id,
            organization_id=row.organization_id,
            candidate_id=row.candidate_id,
            requirement_id=row.requirement_id,
            logical_key=row.logical_key,
            assertion=row.assertion or {},
            verification=row.verification or {},
            payload_hash=row.payload_hash,
            superseded_observation_id=row.superseded_observation_id,
            is_current=bool(row.is_current),
            observed_at=row.observed_at,
            created_at=row.created_at,
        )

    @staticmethod
    def _row_to_evidence_policy_review(row) -> EvidencePolicyReview:
        return EvidencePolicyReview(
            id=row.id,
            organization_id=row.organization_id,
            application_id=row.application_id,
            credential_id=row.credential_id,
            binding_id=row.binding_id,
            status=EvidencePolicyReviewStatus(row.status),
            prior_decision=row.prior_decision or {},
            current_decision=row.current_decision or {},
            triggering_fact_id=row.triggering_fact_id,
            resolution_action=row.resolution_action,
            resolution_notes=row.resolution_notes,
            resolved_by=row.resolved_by,
            resolved_at=row.resolved_at,
            resolution_claim_token=getattr(row, "resolution_claim_token", None),
            resolution_claim_action=getattr(row, "resolution_claim_action", None),
            resolution_claimed_at=getattr(row, "resolution_claimed_at", None),
            resolution_recovery_pending=bool(
                getattr(row, "resolution_recovery_pending", False)
            ),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _row_to_transaction(row) -> IssuanceTransaction:
        return IssuanceTransaction(
            id=row.id,
            organization_id=row.organization_id,
            credential_template_id=row.credential_template_id,
            revocation_profile_id=getattr(row, "revocation_profile_id", None),
            renewal_of_credential_id=getattr(row, "renewal_of_credential_id", None),
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
            reserved_credential_id=getattr(row, "reserved_credential_id", None),
            delivery_mode=getattr(row, "delivery_mode", None) or "wallet_only",
            claims=row.claims or {},
            credential_type=row.credential_type,
            zk_predicate_claims=list(row.zk_predicate_claims or []),
            selective_disclosure_claims=list(getattr(row, 'selective_disclosure_claims', None) or []),
            credential_payload_format=row.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
            wallet_configs=list(row.wallet_configs or []),
            validity_days=getattr(row, "validity_days", None) or 365,
            renewable=bool(getattr(row, "renewable", False)),
            renewal_window_days=getattr(row, "renewal_window_days", None) or 30,
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
                "revocation_profile_id": tx.revocation_profile_id,
                "renewal_of_credential_id": tx.renewal_of_credential_id,
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
                "reserved_credential_id": tx.reserved_credential_id,
                "delivery_mode": tx.delivery_mode or "wallet_only",
                "claims": tx.claims,
                "credential_type": tx.credential_type,
                "zk_predicate_claims": tx.zk_predicate_claims or [],
                "selective_disclosure_claims": tx.selective_disclosure_claims or [],
                "credential_payload_format": tx.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
                "wallet_configs": tx.wallet_configs or [],
                "validity_days": tx.validity_days,
                "renewable": tx.renewable,
                "renewal_window_days": tx.renewal_window_days,
                "created_at": tx.created_at,
                "expires_at": tx.expires_at,
                "issued_at": tx.issued_at,
                "revoked_at": tx.revoked_at,
                "revocation_reason": tx.revocation_reason,
            }

            update_data = {k: v for k, v in tx_data.items() if k not in ("id", "created_at")}
            allowed_predecessors = [status.value for status in issuance_save_predecessors(tx.status)]
            stmt = (
                pg_insert(issuance_transactions_table)
                .values(**tx_data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_=update_data,
                    where=issuance_transactions_table.c.status.in_(allowed_predecessors),
                )
            )
            result = await session.execute(stmt)
            if result.rowcount == 0:
                await session.rollback()
                raise ValueError(
                    f"Stale issuance transaction transition to {tx.status.value}"
                )
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
                "renewed_from_credential_id": cred.renewed_from_credential_id,
                "renewed_to_credential_id": cred.renewed_to_credential_id,
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
                renewed_from_credential_id=getattr(row, "renewed_from_credential_id", None),
                renewed_to_credential_id=getattr(row, "renewed_to_credential_id", None),
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
                renewed_from_credential_id=getattr(row, "renewed_from_credential_id", None),
                renewed_to_credential_id=getattr(row, "renewed_to_credential_id", None),
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
        """Append an immutable fact and advance its application evidence head."""

        stored_fact, _changed = await self.record_evidence_revision(fact)
        if stored_fact.id != fact.id:
            fact.id = stored_fact.id
            fact.superseded_fact_id = stored_fact.superseded_fact_id

    async def record_evidence_revision(self, fact: EvidenceFact) -> tuple[EvidenceFact, bool]:
        """Atomically append a revision and move its head only when newer.

        The boolean return value is ``head_changed``. Out-of-order observations
        remain in immutable history but cannot roll policy back to stale state.
        """

        async with self._session_factory() as session, session.begin():
            await self._lock_evidence_application(session, fact)
            stored_fact, _inserted, head_changed = await self._record_evidence_revision_in_session(
                session,
                fact,
            )
            return stored_fact, head_changed

    async def commit_authoritative_canvas_evidence_revision(
        self,
        fact: EvidenceFact,
        *,
        transition: CanvasEvidenceTransitionPlanner,
    ) -> CanvasEvidenceAtomicCommit:
        """Commit the complete authoritative evidence transition atomically."""

        async with self._session_factory() as session, session.begin():
            app = await self._lock_evidence_application(session, fact)
            previous_facts = await self._list_current_evidence_facts_in_session(
                session,
                application_id=fact.application_id,
                organization_id=fact.organization_id,
            )
            stored_fact, inserted, changed = await self._record_evidence_revision_in_session(
                session,
                fact,
            )
            current_facts = await self._list_current_evidence_facts_in_session(
                session,
                application_id=fact.application_id,
                organization_id=fact.organization_id,
            )
            open_review = await self._get_open_evidence_policy_review_in_session(
                session,
                organization_id=fact.organization_id,
                application_id=fact.application_id,
            )
            mutation = transition(
                app=app,
                previous_facts=previous_facts,
                evidence_fact=stored_fact,
                inserted=inserted,
                changed=changed,
                current_facts=current_facts,
                open_review=open_review,
            )
            if mutation.review_changed:
                review = mutation.correction_review
                if review is None:
                    raise ValueError("Evidence transition marked a missing review as changed")
                if (
                    review.organization_id != fact.organization_id
                    or review.application_id != fact.application_id
                ):
                    raise ValueError("Evidence policy review does not belong to the locked application")
                await self._save_evidence_policy_review_in_session(session, review)
            for event in mutation.audit_events:
                if event.application_id != fact.application_id:
                    raise ValueError("Evidence audit event does not belong to the locked application")
                await self._save_event_in_session(session, event)
            return CanvasEvidenceAtomicCommit(
                evidence_fact=stored_fact,
                inserted=inserted,
                changed=changed,
                current_facts=current_facts,
                policy_decision=mutation.policy_decision,
                correction_review=mutation.correction_review,
            )

    async def _lock_evidence_application(
        self,
        session: AsyncSession,
        fact: EvidenceFact,
    ) -> Application:
        result = await session.execute(
            select(applications_table)
            .where(
                applications_table.c.id == fact.application_id,
                applications_table.c.organization_id == fact.organization_id,
            )
            .with_for_update()
        )
        row = result.first()
        if row is None:
            raise ValueError("Evidence application was not found for this organization")
        return self._row_to_application(row)

    async def _list_current_evidence_facts_in_session(
        self,
        session: AsyncSession,
        *,
        application_id: str,
        organization_id: str,
    ) -> list[EvidenceFact]:
        result = await session.execute(
            select(evidence_facts_table)
            .join(
                evidence_fact_heads_table,
                evidence_fact_heads_table.c.fact_id == evidence_facts_table.c.id,
            )
            .where(
                evidence_fact_heads_table.c.application_id == application_id,
                evidence_fact_heads_table.c.organization_id == organization_id,
            )
            .order_by(
                evidence_facts_table.c.observed_at,
                evidence_facts_table.c.created_at,
                evidence_facts_table.c.id,
            )
        )
        return [self._row_to_evidence_fact(row) for row in result.all()]

    async def _record_evidence_revision_in_session(
        self,
        session: AsyncSession,
        fact: EvidenceFact,
    ) -> tuple[EvidenceFact, bool, bool]:
        head_result = await session.execute(
            select(evidence_facts_table)
            .join(
                evidence_fact_heads_table,
                evidence_fact_heads_table.c.fact_id == evidence_facts_table.c.id,
            )
            .where(
                evidence_fact_heads_table.c.application_id == fact.application_id,
                evidence_fact_heads_table.c.logical_key == fact.logical_key,
            )
            .with_for_update()
        )
        current = head_result.first()
        if current is not None and current.payload_hash == fact.payload_hash:
            return self._row_to_evidence_fact(current), False, False

        advances_head = current is None
        if current is None:
            fact.superseded_fact_id = None
        if current is not None:
            incoming_order = (
                fact.effective_at or fact.observed_at,
                fact.observed_at,
                fact.created_at,
                fact.id,
            )
            current_order = (
                current.effective_at or current.observed_at,
                current.observed_at,
                current.created_at,
                current.id,
            )
            advances_head = incoming_order > current_order
            if advances_head:
                fact.superseded_fact_id = current.id
            elif not advances_head:
                fact.superseded_fact_id = None

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
            "requirement_id": fact.requirement_id,
            "logical_key": fact.logical_key,
            "source_revision": fact.source_revision,
            "payload_hash": fact.payload_hash,
            "observed_at": fact.observed_at,
            "effective_at": fact.effective_at,
            "superseded_fact_id": fact.superseded_fact_id,
            "created_at": fact.created_at,
        }
        inserted = await session.execute(
            pg_insert(evidence_facts_table)
            .values(**data)
            .on_conflict_do_nothing(index_elements=["id"])
            .returning(evidence_facts_table)
        )
        inserted_row = inserted.first()
        if inserted_row is None:
            existing = await session.execute(
                select(evidence_facts_table).where(evidence_facts_table.c.id == fact.id)
            )
            existing_row = existing.first()
            if existing_row is None:
                raise RuntimeError("Evidence revision insert did not return a row")
            return self._row_to_evidence_fact(existing_row), False, False

        if advances_head:
            now = datetime.now(UTC)
            await session.execute(
                pg_insert(evidence_fact_heads_table)
                .values(
                    organization_id=fact.organization_id,
                    application_id=fact.application_id,
                    logical_key=fact.logical_key,
                    fact_id=fact.id,
                    updated_at=now,
                )
                .on_conflict_do_update(
                    index_elements=["application_id", "logical_key"],
                    set_={
                        "organization_id": fact.organization_id,
                        "fact_id": fact.id,
                        "updated_at": now,
                    },
                )
            )
        return self._row_to_evidence_fact(inserted_row), True, advances_head

    async def _get_open_evidence_policy_review_in_session(
        self,
        session: AsyncSession,
        *,
        organization_id: str,
        application_id: str,
    ) -> EvidencePolicyReview | None:
        result = await session.execute(
            select(evidence_policy_reviews_table)
            .where(
                evidence_policy_reviews_table.c.organization_id == organization_id,
                evidence_policy_reviews_table.c.application_id == application_id,
                evidence_policy_reviews_table.c.status == EvidencePolicyReviewStatus.OPEN.value,
            )
            .with_for_update()
        )
        row = result.first()
        return self._row_to_evidence_policy_review(row) if row else None

    async def _save_evidence_policy_review_in_session(
        self,
        session: AsyncSession,
        review: EvidencePolicyReview,
    ) -> None:
        review.updated_at = datetime.now(UTC)
        data = {
            "id": review.id,
            "organization_id": review.organization_id,
            "application_id": review.application_id,
            "credential_id": review.credential_id,
            "binding_id": review.binding_id,
            "status": review.status.value,
            "prior_decision": review.prior_decision or {},
            "current_decision": review.current_decision or {},
            "triggering_fact_id": review.triggering_fact_id,
            "resolution_action": review.resolution_action,
            "resolution_notes": review.resolution_notes,
            "resolved_by": review.resolved_by,
            "resolved_at": review.resolved_at,
            "resolution_claim_token": review.resolution_claim_token,
            "resolution_claim_action": review.resolution_claim_action,
            "resolution_claimed_at": review.resolution_claimed_at,
            "resolution_recovery_pending": review.resolution_recovery_pending,
            "created_at": review.created_at,
            "updated_at": review.updated_at,
        }
        await session.execute(
            pg_insert(evidence_policy_reviews_table)
            .values(**data)
            .on_conflict_do_update(
                index_elements=["id"],
                set_={key: value for key, value in data.items() if key not in {"id", "created_at"}},
            )
        )

    @staticmethod
    async def _save_event_in_session(session: AsyncSession, event: IssuanceEvent) -> None:
        await session.execute(
            issuance_events_table.insert().values(
                id=event.id,
                transaction_id=event.transaction_id,
                application_id=event.application_id,
                event_type=event.event_type.value,
                metadata=event.metadata,
                created_at=event.created_at,
            )
        )

    async def list_evidence_fact_heads_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFactHead]:
        async with self._session_factory() as session:
            conditions = [evidence_fact_heads_table.c.application_id == application_id]
            if organization_id is not None:
                conditions.append(evidence_fact_heads_table.c.organization_id == organization_id)
            result = await session.execute(
                select(evidence_fact_heads_table)
                .where(and_(*conditions))
                .order_by(evidence_fact_heads_table.c.logical_key)
            )
            return [self._row_to_evidence_fact_head(row) for row in result.all()]

    async def list_current_evidence_facts_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFact]:
        async with self._session_factory() as session:
            conditions = [evidence_fact_heads_table.c.application_id == application_id]
            if organization_id is not None:
                conditions.append(evidence_fact_heads_table.c.organization_id == organization_id)
            result = await session.execute(
                select(evidence_facts_table)
                .join(
                    evidence_fact_heads_table,
                    evidence_fact_heads_table.c.fact_id == evidence_facts_table.c.id,
                )
                .where(and_(*conditions))
                .order_by(evidence_facts_table.c.observed_at, evidence_facts_table.c.created_at)
            )
            return [self._row_to_evidence_fact(row) for row in result.all()]

    async def list_evidence_facts_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFact]:
        async with self._session_factory() as session:
            conditions = [evidence_facts_table.c.application_id == application_id]
            if organization_id is not None:
                conditions.append(evidence_facts_table.c.organization_id == organization_id)
            stmt = (
                select(evidence_facts_table)
                .where(and_(*conditions))
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
        now = datetime.now(UTC)
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
                "updated_at": datetime.now(UTC),
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
                "updated_at": datetime.now(UTC),
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

    async def _project_canvas_claim_in_session(
        self,
        session: AsyncSession,
        app_row: Any,
        *,
        credential_id: str,
        projected_at: datetime,
    ) -> Any:
        """Link a canonical credential to its Canvas application under one lock."""

        canvas = _canvas_application_context(app_row.integration_context)
        if canvas is None:
            return app_row
        if app_row.credential_id not in (None, credential_id):
            raise ValueError("Canvas application already has a different credential")

        candidate_id = str(canvas.get("canvas_award_candidate_id") or "").strip()
        candidate_row = None
        if candidate_id:
            candidate_result = await session.execute(
                select(canvas_award_candidates_table)
                .where(
                    canvas_award_candidates_table.c.id == candidate_id,
                    canvas_award_candidates_table.c.organization_id == app_row.organization_id,
                )
                .with_for_update()
            )
            candidate_row = candidate_result.first()
            if candidate_row is not None:
                expected_binding_id = str(canvas.get("canvas_program_binding_id") or "").strip()
                expected_platform_id = str(canvas.get("canvas_platform_id") or "").strip()
                if (
                    candidate_row.application_id != app_row.id
                    or (expected_binding_id and candidate_row.binding_id != expected_binding_id)
                    or (expected_platform_id and candidate_row.platform_id != expected_platform_id)
                ):
                    raise ValueError("Canvas award candidate does not match application")
                if candidate_row.claimed_credential_id not in (None, credential_id):
                    raise ValueError("Canvas award candidate already has a different credential")

        updated_application = await session.execute(
            update(applications_table)
            .where(
                applications_table.c.id == app_row.id,
                applications_table.c.organization_id == app_row.organization_id,
                or_(
                    applications_table.c.credential_id.is_(None),
                    applications_table.c.credential_id == credential_id,
                ),
            )
            .values(credential_id=credential_id, updated_at=projected_at)
            .returning(applications_table)
        )
        projected_row = updated_application.first()
        if projected_row is None:
            raise ValueError("Canvas credential claim lost its application reservation")

        if candidate_row is not None:
            candidate_updated = await session.execute(
                update(canvas_award_candidates_table)
                .where(
                    canvas_award_candidates_table.c.id == candidate_row.id,
                    canvas_award_candidates_table.c.organization_id == app_row.organization_id,
                    or_(
                        canvas_award_candidates_table.c.claimed_credential_id.is_(None),
                        canvas_award_candidates_table.c.claimed_credential_id == credential_id,
                    ),
                )
                .values(
                    state=CanvasAwardCandidateState.CLAIMED.value,
                    claimed_credential_id=credential_id,
                    updated_at=projected_at,
                )
            )
            if candidate_updated.rowcount != 1:
                raise ValueError("Canvas credential claim lost its candidate reservation")
        return projected_row

    async def reserve_canvas_application_issuance(
        self,
        prepared_transaction: IssuanceTransaction,
        *,
        reviewer_id: str,
        review_notes: str,
        reviewed_at: datetime,
    ) -> tuple[Application, IssuanceTransaction, bool]:
        application_id = str(prepared_transaction.application_id or "").strip()
        if not application_id:
            raise ValueError("Canvas issuance transaction requires an application")

        async with self._session_factory() as session, session.begin():
            application_result = await session.execute(
                select(applications_table)
                .where(
                    applications_table.c.id == application_id,
                    applications_table.c.organization_id == prepared_transaction.organization_id,
                )
                .with_for_update()
            )
            app_row = application_result.first()
            if app_row is None or _canvas_application_context(app_row.integration_context) is None:
                raise ValueError("Canvas application was not found for issuance")
            if app_row.status not in {
                ApplicationStatus.PENDING.value,
                ApplicationStatus.APPROVED.value,
            }:
                raise ValueError(f"Cannot approve application in {app_row.status} status")

            current_row = None
            if app_row.issuance_transaction_id:
                current_result = await session.execute(
                    select(issuance_transactions_table).where(
                        issuance_transactions_table.c.id == app_row.issuance_transaction_id,
                        issuance_transactions_table.c.organization_id == app_row.organization_id,
                        issuance_transactions_table.c.application_id == app_row.id,
                    )
                )
                current_row = current_result.first()

            if app_row.credential_id:
                if current_row is None or current_row.status != IssuanceStatus.ISSUED.value:
                    raise ValueError("Canvas application already has a claimed credential")
                return self._row_to_application(app_row), self._row_to_transaction(current_row), True

            if current_row is not None and current_row.status == IssuanceStatus.ISSUED.value:
                credential_result = await session.execute(
                    select(issued_credentials_table.c.id).where(
                        issued_credentials_table.c.transaction_id == current_row.id
                    )
                )
                credential_row = credential_result.first()
                if credential_row is None:
                    raise ValueError("Issued Canvas transaction has no credential")
                repaired_row = await self._project_canvas_claim_in_session(
                    session,
                    app_row,
                    credential_id=credential_row.id,
                    projected_at=reviewed_at,
                )
                return (
                    self._row_to_application(repaired_row),
                    self._row_to_transaction(current_row),
                    True,
                )

            current_is_active = bool(
                current_row is not None
                and (
                    current_row.status
                    in {
                        IssuanceStatus.AUTHORIZED.value,
                        IssuanceStatus.SIGNING.value,
                    }
                    or (
                        current_row.status == IssuanceStatus.PENDING.value
                        and current_row.expires_at > reviewed_at
                    )
                )
            )
            if current_is_active:
                reserved_row = current_row
            else:
                tx_data = {
                    "id": prepared_transaction.id,
                    "organization_id": prepared_transaction.organization_id,
                    "credential_template_id": prepared_transaction.credential_template_id,
                    "revocation_profile_id": prepared_transaction.revocation_profile_id,
                    "renewal_of_credential_id": prepared_transaction.renewal_of_credential_id,
                    "applicant_id": prepared_transaction.applicant_id,
                    "application_id": prepared_transaction.application_id,
                    "subject_did": prepared_transaction.subject_did,
                    "status": prepared_transaction.status.value,
                    "pre_auth_code": prepared_transaction.pre_auth_code,
                    "access_token": _hash_token(prepared_transaction.access_token),
                    "c_nonce": prepared_transaction.nonce,
                    "issuer_profile_id": prepared_transaction.issuer_profile_id,
                    "issuer_mode": prepared_transaction.issuer_mode or "org_managed",
                    "issuer_did_override": prepared_transaction.issuer_did_override,
                    "signing_service_id": prepared_transaction.signing_service_id,
                    "reserved_credential_id": prepared_transaction.reserved_credential_id,
                    "delivery_mode": prepared_transaction.delivery_mode or "wallet_only",
                    "claims": prepared_transaction.claims,
                    "credential_type": prepared_transaction.credential_type,
                    "zk_predicate_claims": prepared_transaction.zk_predicate_claims or [],
                    "selective_disclosure_claims": prepared_transaction.selective_disclosure_claims or [],
                    "credential_payload_format": prepared_transaction.credential_payload_format,
                    "wallet_configs": prepared_transaction.wallet_configs or [],
                    "validity_days": prepared_transaction.validity_days,
                    "renewable": prepared_transaction.renewable,
                    "renewal_window_days": prepared_transaction.renewal_window_days,
                    "created_at": prepared_transaction.created_at,
                    "expires_at": prepared_transaction.expires_at,
                    "issued_at": prepared_transaction.issued_at,
                    "revoked_at": prepared_transaction.revoked_at,
                    "revocation_reason": prepared_transaction.revocation_reason,
                }
                inserted = await session.execute(
                    issuance_transactions_table.insert().values(**tx_data).returning(
                        issuance_transactions_table
                    )
                )
                reserved_row = inserted.first()
                if reserved_row is None:
                    raise ValueError("Canvas issuance transaction could not be reserved")

            updated = await session.execute(
                update(applications_table)
                .where(
                    applications_table.c.id == app_row.id,
                    applications_table.c.organization_id == app_row.organization_id,
                )
                .values(
                    status=ApplicationStatus.APPROVED.value,
                    review_notes=review_notes,
                    reviewer_id=reviewer_id,
                    reviewed_at=reviewed_at,
                    issuance_transaction_id=reserved_row.id,
                    updated_at=reviewed_at,
                )
                .returning(applications_table)
            )
            updated_row = updated.first()
            if updated_row is None:
                raise ValueError("Canvas application lost its issuance reservation")
            return (
                self._row_to_application(updated_row),
                self._row_to_transaction(reserved_row),
                False,
            )

    async def patch_application_integration_context(
        self,
        organization_id: str,
        application_id: str,
        *,
        patch: dict[str, Any],
        expected_updated_at: datetime | None = None,
    ) -> Application | None:
        """Lock and deep-merge only integration_context, preserving lifecycle fields."""

        if not isinstance(patch, dict):
            raise ValueError("Application integration context patch must be an object")
        async with self._session_factory() as session, session.begin():
            current_result = await session.execute(
                select(applications_table)
                .where(
                    applications_table.c.id == application_id,
                    applications_table.c.organization_id == organization_id,
                )
                .with_for_update()
            )
            current_row = current_result.first()
            if current_row is None:
                return None
            if expected_updated_at is not None and current_row.updated_at != expected_updated_at:
                return None
            integration_context = merge_application_integration_context(
                current_row.integration_context or {},
                patch,
            )
            updated = await session.execute(
                update(applications_table)
                .where(
                    applications_table.c.id == application_id,
                    applications_table.c.organization_id == organization_id,
                )
                .values(
                    integration_context=integration_context,
                    updated_at=datetime.now(UTC),
                )
                .returning(applications_table)
            )
            row = updated.first()
            return self._row_to_application(row) if row else None

    async def get_application(self, app_id: str) -> Application | None:
        async with self._session_factory() as session:
            stmt = select(applications_table).where(
                applications_table.c.id == app_id
            )
            result = await session.execute(stmt)
            row = result.first()

            if not row:
                return None

            return self._row_to_application(row)

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
                "lti_trust_profile": platform.lti_trust_profile,
                "lti_issuer": platform.lti_issuer,
                "lti_jwks_url": platform.lti_jwks_url,
                "lti_jwks_json": platform.lti_jwks_json,
                "lti_jwks_fetched_at": platform.lti_jwks_fetched_at,
                "lti_jwks_expires_at": platform.lti_jwks_expires_at,
                "lti_openid_configuration": platform.lti_openid_configuration,
                "registration_status": platform.registration_status or "draft",
                "connection_config": platform.connection_config or {},
                "capability_snapshot": platform.capability_snapshot or {},
                "last_validated_at": platform.last_validated_at,
                "last_connection_error": platform.last_connection_error,
                "config_version": platform.config_version,
                "archived_at": platform.archived_at,
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

    async def claim_transaction_for_signing(
        self,
        prepared_transaction: IssuanceTransaction,
        credential_id: str,
    ) -> IssuanceTransaction | None:
        """Atomically persist prepared context and reserve one KMS signing call."""

        transaction_id = prepared_transaction.id
        async with self._session_factory() as session:
            stmt = (
                update(issuance_transactions_table)
                .where(
                    issuance_transactions_table.c.id == transaction_id,
                    issuance_transactions_table.c.status == IssuanceStatus.AUTHORIZED.value,
                )
                .values(
                    status=IssuanceStatus.SIGNING.value,
                    reserved_credential_id=credential_id,
                    credential_type=prepared_transaction.credential_type,
                    issuer_profile_id=prepared_transaction.issuer_profile_id,
                    issuer_mode=prepared_transaction.issuer_mode or "org_managed",
                    issuer_did_override=prepared_transaction.issuer_did_override,
                    signing_service_id=prepared_transaction.signing_service_id,
                )
                .returning(issuance_transactions_table)
            )
            result = await session.execute(stmt)
            row = result.first()
            await session.commit()
            return self._row_to_transaction(row) if row is not None else None

    async def finalize_credential_issuance(
        self,
        tx: IssuanceTransaction,
        credential: IssuedCredential,
    ) -> None:
        """Persist the credential and SIGNING-to-ISSUED transition atomically."""

        if tx.status != IssuanceStatus.SIGNING:
            raise ValueError("Issuance transaction must remain in signing state until finalization")
        if tx.reserved_credential_id != credential.id or credential.transaction_id != tx.id:
            raise ValueError("Issued credential does not match the signing reservation")

        cred_data = {
            "id": credential.id,
            "transaction_id": credential.transaction_id,
            "organization_id": credential.organization_id,
            "credential_template_id": credential.credential_template_id,
            "applicant_id": credential.applicant_id,
            "subject_did": credential.subject_did,
            "issuer_did": credential.issuer_did,
            "revocation_profile_id": credential.revocation_profile_id,
            "renewed_from_credential_id": credential.renewed_from_credential_id,
            "renewed_to_credential_id": credential.renewed_to_credential_id,
            "status_list_entries": credential.status_list_entries,
            "credential_jwt": credential.credential_jwt,
            "credential_hash": credential.credential_hash,
            "status": credential.status.value,
            "status_updated_at": credential.status_updated_at,
            "revoked": credential.revoked,
            "revoked_at": credential.revoked_at,
            "revocation_reason": credential.revocation_reason,
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
        }

        async with self._session_factory() as session, session.begin():
            locked = await session.execute(
                select(issuance_transactions_table)
                .where(issuance_transactions_table.c.id == tx.id)
                .with_for_update()
            )
            row = locked.first()
            if row is None or row.status != IssuanceStatus.SIGNING.value:
                raise ValueError("Issuance transaction is not reserved for signing")
            if row.reserved_credential_id != credential.id:
                raise ValueError("Issuance credential reservation changed")

            existing = await session.execute(
                select(issued_credentials_table.c.id).where(
                    issued_credentials_table.c.transaction_id == tx.id
                )
            )
            if existing.first() is not None:
                raise ValueError("Issuance transaction already has a credential")

            canvas_app_row = None
            if tx.application_id:
                application_result = await session.execute(
                    select(applications_table)
                    .where(
                        applications_table.c.id == tx.application_id,
                        applications_table.c.organization_id == tx.organization_id,
                    )
                    .with_for_update()
                )
                candidate_app_row = application_result.first()
                if (
                    candidate_app_row is not None
                    and _canvas_application_context(candidate_app_row.integration_context)
                    is not None
                ):
                    canvas_app_row = candidate_app_row

            await session.execute(issued_credentials_table.insert().values(**cred_data))
            if canvas_app_row is not None:
                await self._project_canvas_claim_in_session(
                    session,
                    canvas_app_row,
                    credential_id=credential.id,
                    projected_at=credential.issued_at,
                )
            finalized = await session.execute(
                update(issuance_transactions_table)
                .where(
                    issuance_transactions_table.c.id == tx.id,
                    issuance_transactions_table.c.status == IssuanceStatus.SIGNING.value,
                    issuance_transactions_table.c.reserved_credential_id == credential.id,
                )
                .values(
                    status=IssuanceStatus.ISSUED.value,
                    c_nonce=None,
                    issued_at=tx.issued_at,
                )
            )
            if finalized.rowcount != 1:
                raise ValueError("Issuance transaction finalization lost its reservation")

    async def patch_canvas_platform_validation_state(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_config_version: int,
        last_validated_at: datetime | None,
        last_connection_error: str | None,
    ) -> CanvasPlatform | None:
        """CAS-write operational validation state without touching configuration."""

        async with self._session_factory() as session, session.begin():
            updated = await session.execute(
                update(canvas_platforms_table)
                .where(
                    canvas_platforms_table.c.id == platform_id,
                    canvas_platforms_table.c.organization_id == organization_id,
                    canvas_platforms_table.c.config_version == expected_config_version,
                )
                .values(
                    last_validated_at=last_validated_at,
                    last_connection_error=last_connection_error,
                    updated_at=datetime.now(UTC),
                )
                .returning(canvas_platforms_table)
            )
            row = updated.first()
            return self._row_to_canvas_platform(row) if row else None

    async def patch_canvas_platform_connection_config(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_config_version: int,
        patch: dict[str, Any],
        remove_keys: tuple[str, ...] = (),
    ) -> CanvasPlatform | None:
        """Lock and merge only operational connection metadata."""

        async with self._session_factory() as session, session.begin():
            selected = await session.execute(
                select(canvas_platforms_table)
                .where(
                    canvas_platforms_table.c.id == platform_id,
                    canvas_platforms_table.c.organization_id == organization_id,
                    canvas_platforms_table.c.config_version == expected_config_version,
                )
                .with_for_update()
            )
            row = selected.first()
            if row is None:
                return None
            connection_config = dict(row.connection_config or {})
            connection_config.update(copy.deepcopy(patch))
            for key in remove_keys:
                connection_config.pop(key, None)
            updated = await session.execute(
                update(canvas_platforms_table)
                .where(
                    canvas_platforms_table.c.id == platform_id,
                    canvas_platforms_table.c.organization_id == organization_id,
                    canvas_platforms_table.c.config_version == expected_config_version,
                )
                .values(
                    connection_config=connection_config,
                    updated_at=datetime.now(UTC),
                )
                .returning(canvas_platforms_table)
            )
            updated_row = updated.first()
            return self._row_to_canvas_platform(updated_row) if updated_row else None

    async def get_canvas_platform(self, platform_id: str) -> CanvasPlatform | None:
        async with self._session_factory() as session:
            stmt = select(canvas_platforms_table).where(canvas_platforms_table.c.id == platform_id)
            result = await session.execute(stmt)
            row = result.first()
            return self._row_to_canvas_platform(row) if row else None

    async def get_canvas_platform_for_org(
        self,
        organization_id: str,
        platform_id: str,
    ) -> CanvasPlatform | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_platforms_table).where(
                    canvas_platforms_table.c.id == platform_id,
                    canvas_platforms_table.c.organization_id == organization_id,
                )
            )
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
                "evidence_requirements": canvas_evidence_requirements_to_json(
                    binding.evidence_requirements or []
                ),
                "canvas_scope": binding.canvas_scope or {},
                "delivery_mode": binding.delivery_mode or "wallet_only",
                "issuer_mode": binding.issuer_mode or "org_managed",
                "approval_policy_set_id": binding.approval_policy_set_id,
                "deployment_profile_id": binding.deployment_profile_id,
                "feature_flags": binding.feature_flags or {},
                "canvas_credentials": binding.canvas_credentials or {},
                "config_version": binding.config_version,
                "validated_config_version": binding.validated_config_version,
                "readiness_checks": binding.readiness_checks or [],
                "readiness_validated_at": binding.readiness_validated_at,
                "activated_at": binding.activated_at,
                "archived_at": binding.archived_at,
                "credential_template_snapshot": binding.credential_template_snapshot or {},
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

    async def get_canvas_program_binding_for_org(
        self,
        organization_id: str,
        binding_id: str,
    ) -> CanvasProgramBinding | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_program_bindings_table).where(
                    canvas_program_bindings_table.c.id == binding_id,
                    canvas_program_bindings_table.c.organization_id == organization_id,
                )
            )
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

    async def save_canvas_learner_identity(self, identity: CanvasLearnerIdentity) -> None:
        now = datetime.now(UTC)
        identity.updated_at = now
        async with self._session_factory() as session:
            data = {
                "id": identity.id,
                "organization_id": identity.organization_id,
                "platform_id": identity.platform_id,
                "deployment_id": identity.deployment_id,
                "lti_subject": identity.lti_subject,
                "canvas_user_id": identity.canvas_user_id,
                "sis_user_id": identity.sis_user_id,
                "status": identity.status.value,
                "conflict_reason": identity.conflict_reason,
                "verified_at": identity.verified_at,
                "created_at": identity.created_at,
                "updated_at": now,
            }
            await session.execute(
                pg_insert(canvas_learner_identities_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["platform_id", "deployment_id", "lti_subject"],
                    set_={key: value for key, value in data.items() if key not in {"id", "created_at"}},
                )
            )
            await session.commit()

    async def get_canvas_learner_identity_for_org(
        self,
        organization_id: str,
        identity_id: str,
    ) -> CanvasLearnerIdentity | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_learner_identities_table).where(
                    canvas_learner_identities_table.c.id == identity_id,
                    canvas_learner_identities_table.c.organization_id == organization_id,
                )
            )
            row = result.first()
            return self._row_to_canvas_learner_identity(row) if row else None

    async def get_canvas_learner_identity_by_subject(
        self,
        *,
        organization_id: str,
        platform_id: str,
        deployment_id: str,
        lti_subject: str,
    ) -> CanvasLearnerIdentity | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_learner_identities_table).where(
                    canvas_learner_identities_table.c.organization_id == organization_id,
                    canvas_learner_identities_table.c.platform_id == platform_id,
                    canvas_learner_identities_table.c.deployment_id == deployment_id,
                    canvas_learner_identities_table.c.lti_subject == lti_subject,
                )
            )
            row = result.first()
            return self._row_to_canvas_learner_identity(row) if row else None

    async def get_canvas_learner_identity_by_canvas_user(
        self,
        *,
        organization_id: str,
        platform_id: str,
        deployment_id: str,
        canvas_user_id: str,
    ) -> CanvasLearnerIdentity | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_learner_identities_table).where(
                    canvas_learner_identities_table.c.organization_id == organization_id,
                    canvas_learner_identities_table.c.platform_id == platform_id,
                    canvas_learner_identities_table.c.deployment_id == deployment_id,
                    canvas_learner_identities_table.c.canvas_user_id == canvas_user_id,
                    canvas_learner_identities_table.c.status == CanvasLearnerIdentityStatus.LINKED.value,
                )
            )
            row = result.first()
            return self._row_to_canvas_learner_identity(row) if row else None

    async def save_canvas_oauth_authorization(
        self,
        authorization: CanvasOAuthAuthorization,
    ) -> None:
        """Persist an immutable authorization transaction containing only a state hash."""

        async with self._session_factory() as session:
            await session.execute(
                pg_insert(canvas_oauth_authorizations_table)
                .values(
                    id=authorization.id,
                    organization_id=authorization.organization_id,
                    platform_id=authorization.platform_id,
                    canvas_base_url=authorization.canvas_base_url,
                    platform_config_version=authorization.platform_config_version,
                    client_id=authorization.client_id,
                    client_secret_ref=authorization.client_secret_ref,
                    state_hash=authorization.state_hash,
                    capabilities=authorization.capabilities or [],
                    scopes=authorization.scopes or [],
                    redirect_uri=authorization.redirect_uri,
                    expires_at=authorization.expires_at,
                    consumed_at=authorization.consumed_at,
                    created_at=authorization.created_at,
                )
                .on_conflict_do_nothing(index_elements=["state_hash"])
            )
            await session.commit()

    async def consume_canvas_oauth_authorization(
        self,
        state_hash: str,
        *,
        now: datetime | None = None,
    ) -> CanvasOAuthAuthorization | None:
        """Atomically consume an unexpired state hash exactly once."""

        consumed_at = now or datetime.now(UTC)
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_oauth_authorizations_table)
                .where(
                    canvas_oauth_authorizations_table.c.state_hash == state_hash,
                    canvas_oauth_authorizations_table.c.consumed_at.is_(None),
                    canvas_oauth_authorizations_table.c.expires_at > consumed_at,
                )
                .values(consumed_at=consumed_at)
                .returning(canvas_oauth_authorizations_table)
            )
            row = result.first()
            await session.commit()
            return self._row_to_canvas_oauth_authorization(row) if row else None

    async def get_canvas_oauth_authorization_for_org(
        self,
        organization_id: str,
        authorization_id: str,
    ) -> CanvasOAuthAuthorization | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_oauth_authorizations_table).where(
                    canvas_oauth_authorizations_table.c.id == authorization_id,
                    canvas_oauth_authorizations_table.c.organization_id == organization_id,
                )
            )
            row = result.first()
            return self._row_to_canvas_oauth_authorization(row) if row else None

    async def save_canvas_oauth_connection(self, connection: CanvasOAuthConnection) -> None:
        connection.updated_at = datetime.now(UTC)
        async with self._session_factory() as session:
            data = {
                "id": connection.id,
                "organization_id": connection.organization_id,
                "platform_id": connection.platform_id,
                "canvas_base_url": connection.canvas_base_url,
                "platform_config_version": connection.platform_config_version,
                "client_id": connection.client_id,
                "client_secret_ref": connection.client_secret_ref,
                "capabilities": connection.capabilities or [],
                "scopes": connection.scopes or [],
                "access_token_secret_ref": connection.access_token_secret_ref,
                "refresh_token_secret_ref": connection.refresh_token_secret_ref,
                "token_expires_at": connection.token_expires_at,
                "status": connection.status.value,
                "reauthorization_required": connection.reauthorization_required,
                "refresh_lease_owner": connection.refresh_lease_owner,
                "refresh_lease_expires_at": connection.refresh_lease_expires_at,
                "revoke_retry_count": connection.revoke_retry_count,
                "revoke_retry_at": connection.revoke_retry_at,
                "revoke_last_error_code": connection.revoke_last_error_code,
                "connected_at": connection.connected_at,
                "last_refreshed_at": connection.last_refreshed_at,
                "created_at": connection.created_at,
                "updated_at": connection.updated_at,
            }
            await session.execute(
                pg_insert(canvas_oauth_connections_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["organization_id", "platform_id"],
                    set_={key: value for key, value in data.items() if key not in {"id", "created_at"}},
                )
            )
            await session.commit()

    async def save_canvas_oauth_connection_cas(
        self,
        connection: CanvasOAuthConnection,
        *,
        expected_updated_at: datetime | None,
    ) -> bool:
        """Publish a connection only if the pre-network snapshot is still current."""

        now = datetime.now(UTC)
        connection.updated_at = now
        data = {
            "id": connection.id,
            "organization_id": connection.organization_id,
            "platform_id": connection.platform_id,
            "canvas_base_url": connection.canvas_base_url,
            "platform_config_version": connection.platform_config_version,
            "client_id": connection.client_id,
            "client_secret_ref": connection.client_secret_ref,
            "capabilities": connection.capabilities or [],
            "scopes": connection.scopes or [],
            "access_token_secret_ref": connection.access_token_secret_ref,
            "refresh_token_secret_ref": connection.refresh_token_secret_ref,
            "token_expires_at": connection.token_expires_at,
            "status": connection.status.value,
            "reauthorization_required": connection.reauthorization_required,
            "refresh_lease_owner": connection.refresh_lease_owner,
            "refresh_lease_expires_at": connection.refresh_lease_expires_at,
            "revoke_retry_count": connection.revoke_retry_count,
            "revoke_retry_at": connection.revoke_retry_at,
            "revoke_last_error_code": connection.revoke_last_error_code,
            "connected_at": connection.connected_at,
            "last_refreshed_at": connection.last_refreshed_at,
            "created_at": connection.created_at,
            "updated_at": now,
        }
        async with self._session_factory() as session:
            # Lock and validate the exact platform snapshot in the same
            # transaction as the connection CAS.  This closes the race where
            # an in-flight OAuth callback could otherwise publish a token grant
            # after the platform had been archived or reconfigured.
            platform_result = await session.execute(
                select(canvas_platforms_table.c.id)
                .where(
                    canvas_platforms_table.c.id == connection.platform_id,
                    canvas_platforms_table.c.organization_id
                    == connection.organization_id,
                    canvas_platforms_table.c.config_version
                    == connection.platform_config_version,
                    canvas_platforms_table.c.archived_at.is_(None),
                )
                .with_for_update()
            )
            if platform_result.first() is None:
                await session.rollback()
                return False
            if expected_updated_at is None:
                result = await session.execute(
                    pg_insert(canvas_oauth_connections_table)
                    .values(**data)
                    .on_conflict_do_nothing(index_elements=["organization_id", "platform_id"])
                )
            else:
                result = await session.execute(
                    update(canvas_oauth_connections_table)
                    .where(
                        canvas_oauth_connections_table.c.organization_id
                        == connection.organization_id,
                        canvas_oauth_connections_table.c.platform_id == connection.platform_id,
                        canvas_oauth_connections_table.c.updated_at == expected_updated_at,
                    )
                    .values(
                        **{
                            key: value
                            for key, value in data.items()
                            if key not in {"id", "organization_id", "platform_id", "created_at"}
                        }
                    )
                )
            await session.commit()
            return self._result_rowcount(result) == 1

    async def get_canvas_oauth_connection(
        self,
        organization_id: str,
        platform_id: str,
    ) -> CanvasOAuthConnection | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_oauth_connections_table).where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                )
            )
            row = result.first()
            return self._row_to_canvas_oauth_connection(row) if row else None

    async def list_canvas_oauth_connections(
        self,
        organization_id: str,
    ) -> list[CanvasOAuthConnection]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_oauth_connections_table)
                .where(canvas_oauth_connections_table.c.organization_id == organization_id)
                .order_by(canvas_oauth_connections_table.c.created_at)
            )
            return [self._row_to_canvas_oauth_connection(row) for row in result.all()]

    async def mark_canvas_oauth_reauthorization_required(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_updated_at: datetime,
    ) -> CanvasOAuthConnection | None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_oauth_connections_table)
                .where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                    canvas_oauth_connections_table.c.updated_at == expected_updated_at,
                    canvas_oauth_connections_table.c.status
                    != CanvasOAuthConnectionStatus.DISCONNECTED.value,
                    or_(
                        canvas_oauth_connections_table.c.refresh_lease_owner.is_(None),
                        canvas_oauth_connections_table.c.refresh_lease_expires_at.is_(None),
                        canvas_oauth_connections_table.c.refresh_lease_expires_at <= now,
                    ),
                )
                .values(
                    status=CanvasOAuthConnectionStatus.REAUTHORIZATION_REQUIRED.value,
                    reauthorization_required=True,
                    refresh_lease_owner=None,
                    refresh_lease_expires_at=None,
                    updated_at=now,
                )
                .returning(canvas_oauth_connections_table)
            )
            row = result.first()
            await session.commit()
            return self._row_to_canvas_oauth_connection(row) if row else None

    async def acquire_canvas_oauth_refresh_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=max(30, lease_seconds))
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_oauth_connections_table)
                .where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                    canvas_oauth_connections_table.c.status
                    == CanvasOAuthConnectionStatus.CONNECTED.value,
                    canvas_oauth_connections_table.c.reauthorization_required.is_(False),
                    or_(
                        canvas_oauth_connections_table.c.refresh_lease_owner.is_(None),
                        canvas_oauth_connections_table.c.refresh_lease_expires_at <= now,
                        canvas_oauth_connections_table.c.refresh_lease_owner == lease_owner,
                    ),
                )
                .values(
                    refresh_lease_owner=lease_owner,
                    refresh_lease_expires_at=expires_at,
                    updated_at=now,
                )
                .returning(canvas_oauth_connections_table)
            )
            row = result.first()
            await session.commit()
            return self._row_to_canvas_oauth_connection(row) if row else None

    async def complete_canvas_oauth_refresh(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        access_token_secret_ref: str,
        refresh_token_secret_ref: str | None,
        token_expires_at: datetime | None,
    ) -> CanvasOAuthConnection | None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_oauth_connections_table)
                .where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                    canvas_oauth_connections_table.c.refresh_lease_owner == lease_owner,
                    canvas_oauth_connections_table.c.refresh_lease_expires_at > now,
                )
                .values(
                    access_token_secret_ref=access_token_secret_ref,
                    refresh_token_secret_ref=func.coalesce(
                        refresh_token_secret_ref,
                        canvas_oauth_connections_table.c.refresh_token_secret_ref,
                    ),
                    token_expires_at=token_expires_at,
                    status=CanvasOAuthConnectionStatus.CONNECTED.value,
                    reauthorization_required=False,
                    refresh_lease_owner=None,
                    refresh_lease_expires_at=None,
                    last_refreshed_at=now,
                    updated_at=now,
                )
                .returning(canvas_oauth_connections_table)
            )
            row = result.first()
            await session.commit()
            return self._row_to_canvas_oauth_connection(row) if row else None

    async def release_canvas_oauth_refresh_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        reauthorization_required: bool = False,
    ) -> bool:
        now = datetime.now(UTC)
        values: dict[str, Any] = {
            "refresh_lease_owner": None,
            "refresh_lease_expires_at": None,
            "updated_at": now,
        }
        if reauthorization_required:
            values.update(
                status=CanvasOAuthConnectionStatus.REAUTHORIZATION_REQUIRED.value,
                reauthorization_required=True,
            )
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_oauth_connections_table)
                .where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                    canvas_oauth_connections_table.c.refresh_lease_owner == lease_owner,
                )
                .values(**values)
            )
            await session.commit()
            return self._result_rowcount(result) == 1

    async def list_canvas_oauth_revocation_retries(
        self,
        *,
        limit: int = 100,
    ) -> list[CanvasOAuthConnection]:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_oauth_connections_table)
                .where(
                    canvas_oauth_connections_table.c.status
                    == CanvasOAuthConnectionStatus.REVOCATION_PENDING.value,
                    or_(
                        canvas_oauth_connections_table.c.revoke_retry_at.is_(None),
                        canvas_oauth_connections_table.c.revoke_retry_at <= now,
                    ),
                    or_(
                        canvas_oauth_connections_table.c.refresh_lease_owner.is_(None),
                        canvas_oauth_connections_table.c.refresh_lease_expires_at.is_(None),
                        canvas_oauth_connections_table.c.refresh_lease_expires_at <= now,
                    ),
                )
                .order_by(canvas_oauth_connections_table.c.revoke_retry_at)
                .limit(max(1, min(limit, 500)))
            )
            return [self._row_to_canvas_oauth_connection(row) for row in result.all()]

    async def begin_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        expected_updated_at: datetime,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_oauth_connections_table)
                .where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                    canvas_oauth_connections_table.c.updated_at == expected_updated_at,
                    canvas_oauth_connections_table.c.status
                    != CanvasOAuthConnectionStatus.DISCONNECTED.value,
                )
                .values(
                    status=CanvasOAuthConnectionStatus.REVOCATION_PENDING.value,
                    reauthorization_required=False,
                    revoke_retry_at=None,
                    revoke_last_error_code=None,
                    refresh_lease_owner=lease_owner,
                    refresh_lease_expires_at=now + timedelta(seconds=max(30, lease_seconds)),
                    updated_at=now,
                )
                .returning(canvas_oauth_connections_table)
            )
            row = result.first()
            await session.commit()
            return self._row_to_canvas_oauth_connection(row) if row else None

    async def acquire_canvas_oauth_revocation_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_oauth_connections_table)
                .where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                    canvas_oauth_connections_table.c.status
                    == CanvasOAuthConnectionStatus.REVOCATION_PENDING.value,
                    or_(
                        canvas_oauth_connections_table.c.revoke_retry_at.is_(None),
                        canvas_oauth_connections_table.c.revoke_retry_at <= now,
                    ),
                    or_(
                        canvas_oauth_connections_table.c.refresh_lease_owner.is_(None),
                        canvas_oauth_connections_table.c.refresh_lease_expires_at.is_(None),
                        canvas_oauth_connections_table.c.refresh_lease_expires_at <= now,
                        canvas_oauth_connections_table.c.refresh_lease_owner == lease_owner,
                    ),
                )
                .values(
                    refresh_lease_owner=lease_owner,
                    refresh_lease_expires_at=now + timedelta(seconds=max(30, lease_seconds)),
                    updated_at=now,
                )
                .returning(canvas_oauth_connections_table)
            )
            row = result.first()
            await session.commit()
            return self._row_to_canvas_oauth_connection(row) if row else None

    async def reschedule_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        retry_at: datetime,
        error_code: str,
    ) -> bool:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_oauth_connections_table)
                .where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                    canvas_oauth_connections_table.c.status
                    == CanvasOAuthConnectionStatus.REVOCATION_PENDING.value,
                    canvas_oauth_connections_table.c.refresh_lease_owner == lease_owner,
                )
                .values(
                    revoke_retry_count=canvas_oauth_connections_table.c.revoke_retry_count + 1,
                    revoke_retry_at=retry_at,
                    revoke_last_error_code=str(error_code)[:120],
                    refresh_lease_owner=None,
                    refresh_lease_expires_at=None,
                    updated_at=now,
                )
            )
            await session.commit()
            return self._result_rowcount(result) == 1

    async def complete_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
    ) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                delete(canvas_oauth_connections_table).where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                    canvas_oauth_connections_table.c.status
                    == CanvasOAuthConnectionStatus.REVOCATION_PENDING.value,
                    canvas_oauth_connections_table.c.refresh_lease_owner == lease_owner,
                )
            )
            await session.commit()
            return self._result_rowcount(result) == 1

    async def delete_canvas_oauth_connection(
        self,
        organization_id: str,
        platform_id: str,
    ) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                delete(canvas_oauth_connections_table).where(
                    canvas_oauth_connections_table.c.organization_id == organization_id,
                    canvas_oauth_connections_table.c.platform_id == platform_id,
                )
            )
            await session.commit()
            return self._result_rowcount(result) == 1

    async def save_canvas_sync_target(self, target: CanvasEvidenceSyncTarget) -> None:
        now = datetime.now(UTC)
        target.updated_at = now
        async with self._session_factory() as session:
            data = {
                "id": target.id,
                "organization_id": target.organization_id,
                "platform_id": target.platform_id,
                "binding_id": target.binding_id,
                "target_type": target.target_type.value,
                "logical_key": target.logical_key,
                "application_id": target.application_id,
                "candidate_id": target.candidate_id,
                "enabled": target.enabled,
                "schedule_seconds": target.schedule_seconds,
                "next_run_at": target.next_run_at,
                "last_enqueued_at": target.last_enqueued_at,
                "last_succeeded_at": target.last_succeeded_at,
                "config_version": target.config_version,
                "metadata": target.metadata or {},
                "created_at": target.created_at,
                "updated_at": now,
            }
            result = await session.execute(
                pg_insert(canvas_evidence_sync_targets_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["organization_id", "logical_key"],
                    set_={key: value for key, value in data.items() if key not in {"id", "created_at"}},
                )
                .returning(
                    canvas_evidence_sync_targets_table.c.id,
                    canvas_evidence_sync_targets_table.c.created_at,
                )
            )
            canonical = result.first()
            await session.commit()
            # Concurrent creators may race on (organization_id, logical_key).
            # PostgreSQL retains the first row's primary key on conflict, so
            # callers must receive that canonical ID before enqueueing the FK.
            if canonical is not None:
                target.id = canonical.id
                target.created_at = canonical.created_at

    async def get_canvas_sync_target_for_org(
        self,
        organization_id: str,
        target_id: str,
    ) -> CanvasEvidenceSyncTarget | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_evidence_sync_targets_table).where(
                    canvas_evidence_sync_targets_table.c.id == target_id,
                    canvas_evidence_sync_targets_table.c.organization_id == organization_id,
                )
            )
            row = result.first()
            return self._row_to_canvas_sync_target(row) if row else None

    async def get_canvas_sync_target_by_logical_key(
        self,
        organization_id: str,
        logical_key: str,
    ) -> CanvasEvidenceSyncTarget | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_evidence_sync_targets_table).where(
                    canvas_evidence_sync_targets_table.c.organization_id == organization_id,
                    canvas_evidence_sync_targets_table.c.logical_key == logical_key,
                )
            )
            row = result.first()
            return self._row_to_canvas_sync_target(row) if row else None

    async def touch_canvas_sync_target_worker_heartbeat(
        self,
        *,
        organization_id: str,
        target_id: str,
        expected_config_version: int,
        worker_id: str,
        heartbeat_at: datetime,
    ) -> bool:
        """Merge heartbeat metadata under a row lock without rewriting config."""

        conditions = (
            canvas_evidence_sync_targets_table.c.id == target_id,
            canvas_evidence_sync_targets_table.c.organization_id == organization_id,
            canvas_evidence_sync_targets_table.c.config_version
            == expected_config_version,
            canvas_evidence_sync_targets_table.c.enabled.is_(True),
        )
        async with self._session_factory() as session, session.begin():
            selected = await session.execute(
                select(canvas_evidence_sync_targets_table.c.metadata)
                .where(*conditions)
                .with_for_update()
            )
            row = selected.first()
            if row is None:
                return False
            metadata = dict(row.metadata) if isinstance(row.metadata, dict) else {}
            metadata.update(
                {
                    "worker_id": worker_id,
                    "worker_heartbeat_at": heartbeat_at.isoformat(),
                }
            )
            updated = await session.execute(
                update(canvas_evidence_sync_targets_table)
                .where(*conditions)
                .values(metadata=metadata, updated_at=heartbeat_at)
                .returning(canvas_evidence_sync_targets_table.c.id)
            )
            return updated.first() is not None

    async def mark_canvas_sync_target_succeeded(
        self,
        *,
        organization_id: str,
        target_id: str,
        expected_config_version: int,
        succeeded_at: datetime,
    ) -> bool:
        """Record success without writing target configuration or scheduling fields."""

        async with self._session_factory() as session:
            updated = await session.execute(
                update(canvas_evidence_sync_targets_table)
                .where(
                    canvas_evidence_sync_targets_table.c.id == target_id,
                    canvas_evidence_sync_targets_table.c.organization_id
                    == organization_id,
                    canvas_evidence_sync_targets_table.c.config_version
                    == expected_config_version,
                    canvas_evidence_sync_targets_table.c.enabled.is_(True),
                )
                .values(last_succeeded_at=succeeded_at, updated_at=succeeded_at)
                .returning(canvas_evidence_sync_targets_table.c.id)
            )
            marked = updated.first() is not None
            await session.commit()
            return marked

    async def enqueue_canvas_sync_job(
        self,
        target: CanvasEvidenceSyncTarget,
        *,
        available_at: datetime | None = None,
    ) -> CanvasEvidenceSyncJob:
        job = CanvasEvidenceSyncJob(
            organization_id=target.organization_id,
            target_id=target.id,
            available_at=available_at or datetime.now(UTC),
        )
        async with self._session_factory() as session, session.begin():
            inserted = await session.execute(
                pg_insert(canvas_evidence_sync_jobs_table)
                .values(
                    id=job.id,
                    organization_id=job.organization_id,
                    target_id=job.target_id,
                    status=job.status.value,
                    attempt_count=job.attempt_count,
                    max_attempts=job.max_attempts,
                    available_at=job.available_at,
                    result={},
                    created_at=job.created_at,
                    updated_at=job.updated_at,
                )
                .on_conflict_do_nothing()
                .returning(canvas_evidence_sync_jobs_table)
            )
            row = inserted.first()
            if row is None:
                existing = await session.execute(
                    select(canvas_evidence_sync_jobs_table).where(
                        canvas_evidence_sync_jobs_table.c.target_id == target.id,
                        canvas_evidence_sync_jobs_table.c.status.in_(
                            [
                                CanvasEvidenceSyncJobStatus.QUEUED.value,
                                CanvasEvidenceSyncJobStatus.LEASED.value,
                                CanvasEvidenceSyncJobStatus.RETRY.value,
                            ]
                        ),
                    )
                )
                row = existing.first()
            if row is None:
                raise RuntimeError("Could not enqueue or locate active Canvas sync job")
            now = datetime.now(UTC)
            await session.execute(
                update(canvas_evidence_sync_targets_table)
                .where(canvas_evidence_sync_targets_table.c.id == target.id)
                .values(last_enqueued_at=now, updated_at=now)
            )
            return self._row_to_canvas_sync_job(row)

    async def enqueue_due_canvas_sync_jobs(self, *, limit: int = 100) -> list[CanvasEvidenceSyncJob]:
        """Claim due targets across competing schedulers and enqueue one active job each."""

        now = datetime.now(UTC)
        jobs: list[CanvasEvidenceSyncJob] = []
        async with self._session_factory() as session, session.begin():
            due = await session.execute(
                select(canvas_evidence_sync_targets_table)
                .where(
                    canvas_evidence_sync_targets_table.c.enabled.is_(True),
                    canvas_evidence_sync_targets_table.c.next_run_at <= now,
                )
                .order_by(canvas_evidence_sync_targets_table.c.next_run_at)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
            for row in due.all():
                job = CanvasEvidenceSyncJob(
                    organization_id=row.organization_id,
                    target_id=row.id,
                    available_at=now,
                )
                inserted = await session.execute(
                    pg_insert(canvas_evidence_sync_jobs_table)
                    .values(
                        id=job.id,
                        organization_id=job.organization_id,
                        target_id=job.target_id,
                        status=job.status.value,
                        attempt_count=0,
                        max_attempts=8,
                        available_at=now,
                        result={},
                        created_at=now,
                        updated_at=now,
                    )
                    .on_conflict_do_nothing()
                    .returning(canvas_evidence_sync_jobs_table)
                )
                inserted_row = inserted.first()
                if inserted_row is not None:
                    jobs.append(self._row_to_canvas_sync_job(inserted_row))
                await session.execute(
                    update(canvas_evidence_sync_targets_table)
                    .where(canvas_evidence_sync_targets_table.c.id == row.id)
                    .values(
                        last_enqueued_at=now,
                        next_run_at=now + timedelta(seconds=max(60, row.schedule_seconds)),
                        updated_at=now,
                    )
                )
        return jobs

    async def lease_canvas_sync_jobs(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 120,
    ) -> list[CanvasEvidenceSyncJob]:
        """Lease ready jobs using PostgreSQL ``FOR UPDATE SKIP LOCKED``."""

        now = datetime.now(UTC)
        lease_expires_at = now + timedelta(seconds=max(30, lease_seconds))
        leased: list[CanvasEvidenceSyncJob] = []
        async with self._session_factory() as session, session.begin():
            # A worker crash on the final allowed attempt must not resurrect a
            # ninth attempt when its lease expires.
            expired_final_targets = select(
                canvas_evidence_sync_jobs_table.c.target_id
            ).where(
                canvas_evidence_sync_jobs_table.c.status
                == CanvasEvidenceSyncJobStatus.LEASED.value,
                canvas_evidence_sync_jobs_table.c.lease_expires_at <= now,
                canvas_evidence_sync_jobs_table.c.attempt_count
                >= canvas_evidence_sync_jobs_table.c.max_attempts,
            )
            await session.execute(
                update(canvas_evidence_sync_targets_table)
                .where(canvas_evidence_sync_targets_table.c.id.in_(expired_final_targets))
                .values(enabled=False, updated_at=now)
            )
            await session.execute(
                update(canvas_evidence_sync_jobs_table)
                .where(
                    canvas_evidence_sync_jobs_table.c.status
                    == CanvasEvidenceSyncJobStatus.LEASED.value,
                    canvas_evidence_sync_jobs_table.c.lease_expires_at <= now,
                    canvas_evidence_sync_jobs_table.c.attempt_count
                    >= canvas_evidence_sync_jobs_table.c.max_attempts,
                )
                .values(
                    status=CanvasEvidenceSyncJobStatus.DEAD_LETTER.value,
                    lease_owner=None,
                    lease_expires_at=None,
                    last_error_code="canvas_worker_lease_expired",
                    last_error_summary="Canvas worker lease expired on final attempt",
                    completed_at=now,
                    updated_at=now,
                )
            )
            expired_retry = await session.execute(
                select(canvas_evidence_sync_jobs_table)
                .where(
                    canvas_evidence_sync_jobs_table.c.status
                    == CanvasEvidenceSyncJobStatus.LEASED.value,
                    canvas_evidence_sync_jobs_table.c.lease_expires_at <= now,
                    canvas_evidence_sync_jobs_table.c.attempt_count
                    < canvas_evidence_sync_jobs_table.c.max_attempts,
                )
                .with_for_update(skip_locked=True)
            )
            for expired in expired_retry.all():
                exponent = min(max(expired.attempt_count - 1, 0), 10)
                base_delay = min(3600, 15 * (2**exponent))
                jitter = secrets.randbelow(max(1, base_delay // 3 + 1))
                await session.execute(
                    update(canvas_evidence_sync_jobs_table)
                    .where(canvas_evidence_sync_jobs_table.c.id == expired.id)
                    .values(
                        status=CanvasEvidenceSyncJobStatus.RETRY.value,
                        available_at=now + timedelta(seconds=base_delay + jitter),
                        lease_owner=None,
                        lease_expires_at=None,
                        last_error_code="canvas_worker_lease_expired",
                        last_error_summary="Canvas worker lease expired before completion",
                        updated_at=now,
                    )
                )
            ready = await session.execute(
                select(canvas_evidence_sync_jobs_table)
                .where(
                    canvas_evidence_sync_jobs_table.c.status.in_(
                        [
                            CanvasEvidenceSyncJobStatus.QUEUED.value,
                            CanvasEvidenceSyncJobStatus.RETRY.value,
                        ]
                    ),
                    canvas_evidence_sync_jobs_table.c.available_at <= now,
                    canvas_evidence_sync_jobs_table.c.attempt_count
                    < canvas_evidence_sync_jobs_table.c.max_attempts,
                )
                .order_by(
                    canvas_evidence_sync_jobs_table.c.available_at,
                    canvas_evidence_sync_jobs_table.c.created_at,
                )
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
            for row in ready.all():
                updated = await session.execute(
                    update(canvas_evidence_sync_jobs_table)
                    .where(canvas_evidence_sync_jobs_table.c.id == row.id)
                    .values(
                        status=CanvasEvidenceSyncJobStatus.LEASED.value,
                        attempt_count=row.attempt_count + 1,
                        lease_owner=worker_id,
                        lease_expires_at=lease_expires_at,
                        started_at=row.started_at or now,
                        updated_at=now,
                    )
                    .returning(canvas_evidence_sync_jobs_table)
                )
                leased_row = updated.first()
                if leased_row is not None:
                    leased.append(self._row_to_canvas_sync_job(leased_row))
        return leased

    async def save_canvas_sync_job(self, job: CanvasEvidenceSyncJob) -> None:
        job.updated_at = datetime.now(UTC)
        async with self._session_factory() as session:
            await session.execute(
                pg_insert(canvas_evidence_sync_jobs_table)
                .values(
                    id=job.id,
                    organization_id=job.organization_id,
                    target_id=job.target_id,
                    status=job.status.value,
                    attempt_count=job.attempt_count,
                    max_attempts=job.max_attempts,
                    available_at=job.available_at,
                    lease_owner=job.lease_owner,
                    lease_expires_at=job.lease_expires_at,
                    last_error_code=job.last_error_code,
                    last_error_summary=job.last_error_summary,
                    result=job.result or {},
                    created_at=job.created_at,
                    updated_at=job.updated_at,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                )
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        "status": job.status.value,
                        "attempt_count": job.attempt_count,
                        "max_attempts": job.max_attempts,
                        "available_at": job.available_at,
                        "lease_owner": job.lease_owner,
                        "lease_expires_at": job.lease_expires_at,
                        "last_error_code": job.last_error_code,
                        "last_error_summary": job.last_error_summary,
                        "result": job.result or {},
                        "updated_at": job.updated_at,
                        "started_at": job.started_at,
                        "completed_at": job.completed_at,
                    },
                )
            )
            await session.commit()

    async def save_canvas_sync_job_if_leased(
        self,
        job: CanvasEvidenceSyncJob,
        *,
        worker_id: str,
    ) -> bool:
        """Fence a renewal or outcome against the current PostgreSQL lease."""

        now = datetime.now(UTC)
        job.updated_at = now
        async with self._session_factory() as session:
            result = await session.execute(
                update(canvas_evidence_sync_jobs_table)
                .where(
                    canvas_evidence_sync_jobs_table.c.id == job.id,
                    canvas_evidence_sync_jobs_table.c.organization_id
                    == job.organization_id,
                    canvas_evidence_sync_jobs_table.c.status
                    == CanvasEvidenceSyncJobStatus.LEASED.value,
                    canvas_evidence_sync_jobs_table.c.lease_owner == worker_id,
                    canvas_evidence_sync_jobs_table.c.lease_expires_at > now,
                    canvas_evidence_sync_jobs_table.c.attempt_count
                    == job.attempt_count,
                )
                .values(
                    status=job.status.value,
                    attempt_count=job.attempt_count,
                    max_attempts=job.max_attempts,
                    available_at=job.available_at,
                    lease_owner=job.lease_owner,
                    lease_expires_at=job.lease_expires_at,
                    last_error_code=job.last_error_code,
                    last_error_summary=job.last_error_summary,
                    result=job.result or {},
                    updated_at=now,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                )
                .returning(canvas_evidence_sync_jobs_table.c.id)
            )
            updated = result.first() is not None
            if updated and job.status == CanvasEvidenceSyncJobStatus.DEAD_LETTER:
                # Keep dead-letter terminal: the scheduler must not create a
                # fresh job until an administrator explicitly retries it.
                await session.execute(
                    update(canvas_evidence_sync_targets_table)
                    .where(
                        canvas_evidence_sync_targets_table.c.id == job.target_id,
                        canvas_evidence_sync_targets_table.c.organization_id
                        == job.organization_id,
                    )
                    .values(enabled=False, updated_at=now)
                )
            await session.commit()
            return updated

    async def retry_canvas_sync_job_from_dead_letter(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        now = datetime.now(UTC)
        async with self._session_factory() as session, session.begin():
            updated = await session.execute(
                update(canvas_evidence_sync_jobs_table)
                .where(
                    canvas_evidence_sync_jobs_table.c.id == job_id,
                    canvas_evidence_sync_jobs_table.c.organization_id
                    == organization_id,
                    canvas_evidence_sync_jobs_table.c.status
                    == CanvasEvidenceSyncJobStatus.DEAD_LETTER.value,
                )
                .values(
                    status=CanvasEvidenceSyncJobStatus.QUEUED.value,
                    attempt_count=0,
                    max_attempts=8,
                    available_at=now,
                    lease_owner=None,
                    lease_expires_at=None,
                    last_error_code=None,
                    last_error_summary=None,
                    result={},
                    completed_at=None,
                    updated_at=now,
                )
                .returning(canvas_evidence_sync_jobs_table)
            )
            row = updated.first()
            if row is None:
                return None
            await session.execute(
                update(canvas_evidence_sync_targets_table)
                .where(
                    canvas_evidence_sync_targets_table.c.id == row.target_id,
                    canvas_evidence_sync_targets_table.c.organization_id
                    == organization_id,
                )
                .values(enabled=True, updated_at=now)
            )
            return self._row_to_canvas_sync_job(row)

    async def resolve_canvas_sync_job_dead_letter(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        now = datetime.now(UTC)
        async with self._session_factory() as session, session.begin():
            updated = await session.execute(
                update(canvas_evidence_sync_jobs_table)
                .where(
                    canvas_evidence_sync_jobs_table.c.id == job_id,
                    canvas_evidence_sync_jobs_table.c.organization_id
                    == organization_id,
                    canvas_evidence_sync_jobs_table.c.status
                    == CanvasEvidenceSyncJobStatus.DEAD_LETTER.value,
                )
                .values(
                    status=CanvasEvidenceSyncJobStatus.CANCELLED.value,
                    completed_at=now,
                    updated_at=now,
                )
                .returning(canvas_evidence_sync_jobs_table)
            )
            row = updated.first()
            return self._row_to_canvas_sync_job(row) if row is not None else None

    async def get_canvas_sync_job_for_org(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_evidence_sync_jobs_table).where(
                    canvas_evidence_sync_jobs_table.c.id == job_id,
                    canvas_evidence_sync_jobs_table.c.organization_id == organization_id,
                )
            )
            row = result.first()
            return self._row_to_canvas_sync_job(row) if row else None

    async def list_canvas_sync_jobs(
        self,
        organization_id: str,
        *,
        target_id: str | None = None,
        status: CanvasEvidenceSyncJobStatus | None = None,
        limit: int = 100,
    ) -> list[CanvasEvidenceSyncJob]:
        conditions = [canvas_evidence_sync_jobs_table.c.organization_id == organization_id]
        if target_id is not None:
            conditions.append(canvas_evidence_sync_jobs_table.c.target_id == target_id)
        if status is not None:
            conditions.append(canvas_evidence_sync_jobs_table.c.status == status.value)
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_evidence_sync_jobs_table)
                .where(and_(*conditions))
                .order_by(canvas_evidence_sync_jobs_table.c.created_at.desc())
                .limit(max(1, min(limit, 500)))
            )
            return [self._row_to_canvas_sync_job(row) for row in result.all()]

    async def get_canvas_sync_readiness_state(
        self,
        organization_id: str,
        platform_id: str,
        binding_id: str,
        *,
        now: datetime | None = None,
    ) -> CanvasSyncReadinessState:
        evaluated_at = now or datetime.now(UTC)
        if evaluated_at.tzinfo is None:
            evaluated_at = evaluated_at.replace(tzinfo=UTC)
        else:
            evaluated_at = evaluated_at.astimezone(UTC)
        target_scope = (
            canvas_evidence_sync_targets_table.c.organization_id == organization_id,
            canvas_evidence_sync_targets_table.c.platform_id == platform_id,
            canvas_evidence_sync_targets_table.c.binding_id == binding_id,
        )
        joined_jobs = canvas_evidence_sync_jobs_table.join(
            canvas_evidence_sync_targets_table,
            and_(
                canvas_evidence_sync_targets_table.c.id
                == canvas_evidence_sync_jobs_table.c.target_id,
                canvas_evidence_sync_targets_table.c.organization_id
                == canvas_evidence_sync_jobs_table.c.organization_id,
            ),
        )
        dead_lettered = (
            select(1)
            .select_from(joined_jobs)
            .where(
                *target_scope,
                canvas_evidence_sync_jobs_table.c.organization_id
                == organization_id,
                canvas_evidence_sync_jobs_table.c.status
                == CanvasEvidenceSyncJobStatus.DEAD_LETTER.value,
            )
            .exists()
        )
        normal_interval = func.greatest(
            60,
            canvas_evidence_sync_targets_table.c.schedule_seconds,
        )
        stale_active_job = (
            select(1)
            .select_from(joined_jobs)
            .where(
                *target_scope,
                canvas_evidence_sync_jobs_table.c.organization_id
                == organization_id,
                canvas_evidence_sync_jobs_table.c.status.in_(
                    [
                        CanvasEvidenceSyncJobStatus.QUEUED.value,
                        CanvasEvidenceSyncJobStatus.LEASED.value,
                        CanvasEvidenceSyncJobStatus.RETRY.value,
                    ]
                ),
                func.extract(
                    "epoch",
                    evaluated_at - canvas_evidence_sync_jobs_table.c.created_at,
                )
                > 2 * normal_interval,
            )
            .exists()
        )
        stale_due_target = (
            select(1)
            .select_from(canvas_evidence_sync_targets_table)
            .where(
                *target_scope,
                canvas_evidence_sync_targets_table.c.enabled.is_(True),
                func.extract(
                    "epoch",
                    evaluated_at - canvas_evidence_sync_targets_table.c.next_run_at,
                )
                > 2 * normal_interval,
            )
            .exists()
        )
        async with self._session_factory() as session:
            result = await session.execute(
                select(
                    dead_lettered.label("dead_lettered"),
                    stale_active_job.label("stale_active_job"),
                    stale_due_target.label("stale_due_target"),
                )
            )
            row = result.one()
        return CanvasSyncReadinessState(
            dead_lettered=bool(row.dead_lettered),
            stale_backlog=bool(row.stale_active_job or row.stale_due_target),
        )

    async def upsert_canvas_worker_heartbeat(self, heartbeat: CanvasWorkerHeartbeat) -> None:
        async with self._session_factory() as session:
            await session.execute(
                pg_insert(canvas_worker_heartbeats_table)
                .values(
                    worker_id=heartbeat.worker_id,
                    role=heartbeat.role,
                    started_at=heartbeat.started_at,
                    last_heartbeat_at=heartbeat.last_heartbeat_at,
                    metadata=heartbeat.metadata or {},
                )
                .on_conflict_do_update(
                    index_elements=["worker_id"],
                    set_={
                        "role": heartbeat.role,
                        "last_heartbeat_at": heartbeat.last_heartbeat_at,
                        "metadata": heartbeat.metadata or {},
                    },
                )
            )
            await session.commit()

    async def get_fresh_canvas_worker_heartbeat(
        self,
        *,
        role: str = "canvas_sync",
        max_age_seconds: int = 120,
    ) -> CanvasWorkerHeartbeat | None:
        fresh_after = datetime.now(UTC) - timedelta(seconds=max(1, max_age_seconds))
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_worker_heartbeats_table)
                .where(
                    canvas_worker_heartbeats_table.c.role == role,
                    canvas_worker_heartbeats_table.c.last_heartbeat_at >= fresh_after,
                )
                .order_by(canvas_worker_heartbeats_table.c.last_heartbeat_at.desc())
                .limit(1)
            )
            row = result.first()
            return self._row_to_canvas_worker_heartbeat(row) if row else None

    async def list_canvas_worker_heartbeats(
        self,
        *,
        role: str | None = None,
    ) -> list[CanvasWorkerHeartbeat]:
        async with self._session_factory() as session:
            stmt = select(canvas_worker_heartbeats_table)
            if role is not None:
                stmt = stmt.where(canvas_worker_heartbeats_table.c.role == role)
            result = await session.execute(
                stmt.order_by(canvas_worker_heartbeats_table.c.last_heartbeat_at.desc())
            )
            return [self._row_to_canvas_worker_heartbeat(row) for row in result.all()]

    async def save_canvas_award_candidate(self, candidate: CanvasAwardCandidate) -> None:
        candidate.updated_at = datetime.now(UTC)
        async with self._session_factory() as session:
            data = {
                "id": candidate.id,
                "organization_id": candidate.organization_id,
                "platform_id": candidate.platform_id,
                "binding_id": candidate.binding_id,
                "learner_identity_id": candidate.learner_identity_id,
                "candidate_key": candidate.candidate_key,
                "canvas_user_id": candidate.canvas_user_id,
                "lti_subject": candidate.lti_subject,
                "state": candidate.state.value,
                "application_id": candidate.application_id,
                "claimed_credential_id": candidate.claimed_credential_id,
                "observed_at": candidate.observed_at,
                "created_at": candidate.created_at,
                "updated_at": candidate.updated_at,
            }
            result = await session.execute(
                pg_insert(canvas_award_candidates_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["binding_id", "candidate_key"],
                    set_={key: value for key, value in data.items() if key not in {"id", "created_at"}},
                )
                .returning(
                    canvas_award_candidates_table.c.id,
                    canvas_award_candidates_table.c.created_at,
                )
            )
            row = result.first()
            if row is not None:
                candidate.id = row.id
                candidate.created_at = row.created_at
            await session.commit()

    async def get_canvas_award_candidate_for_org(
        self,
        organization_id: str,
        candidate_id: str,
    ) -> CanvasAwardCandidate | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_award_candidates_table).where(
                    canvas_award_candidates_table.c.id == candidate_id,
                    canvas_award_candidates_table.c.organization_id == organization_id,
                )
            )
            row = result.first()
            return self._row_to_canvas_award_candidate(row) if row else None

    async def list_canvas_award_candidates(
        self,
        organization_id: str,
        *,
        state: CanvasAwardCandidateState | None = None,
        binding_id: str | None = None,
        limit: int = 100,
    ) -> list[CanvasAwardCandidate]:
        conditions = [canvas_award_candidates_table.c.organization_id == organization_id]
        if state is not None:
            conditions.append(canvas_award_candidates_table.c.state == state.value)
        if binding_id is not None:
            conditions.append(canvas_award_candidates_table.c.binding_id == binding_id)
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_award_candidates_table)
                .where(and_(*conditions))
                .order_by(canvas_award_candidates_table.c.updated_at.desc())
                .limit(max(1, min(limit, 500)))
            )
            return [self._row_to_canvas_award_candidate(row) for row in result.all()]

    async def save_canvas_candidate_observation(
        self,
        observation: CanvasCandidateObservation,
    ) -> tuple[CanvasCandidateObservation, bool]:
        async with self._session_factory() as session, session.begin():
            candidate = await session.execute(
                select(canvas_award_candidates_table.c.id)
                .where(
                    canvas_award_candidates_table.c.id == observation.candidate_id,
                    canvas_award_candidates_table.c.organization_id == observation.organization_id,
                )
                .with_for_update()
            )
            if candidate.first() is None:
                raise ValueError("Canvas award candidate was not found for this organization")
            current_result = await session.execute(
                select(canvas_candidate_observations_table).where(
                    canvas_candidate_observations_table.c.candidate_id == observation.candidate_id,
                    canvas_candidate_observations_table.c.logical_key == observation.logical_key,
                    canvas_candidate_observations_table.c.is_current.is_(True),
                )
            )
            current = current_result.first()
            if current is not None and current.payload_hash == observation.payload_hash:
                return self._row_to_canvas_candidate_observation(current), False
            if current is not None:
                observation.superseded_observation_id = current.id
                await session.execute(
                    update(canvas_candidate_observations_table)
                    .where(canvas_candidate_observations_table.c.id == current.id)
                    .values(is_current=False)
                )
            inserted = await session.execute(
                pg_insert(canvas_candidate_observations_table)
                .values(
                    id=observation.id,
                    organization_id=observation.organization_id,
                    candidate_id=observation.candidate_id,
                    requirement_id=observation.requirement_id,
                    logical_key=observation.logical_key,
                    assertion=observation.assertion or {},
                    verification=observation.verification or {},
                    payload_hash=observation.payload_hash,
                    superseded_observation_id=observation.superseded_observation_id,
                    is_current=True,
                    observed_at=observation.observed_at,
                    created_at=observation.created_at,
                )
                .returning(canvas_candidate_observations_table)
            )
            return self._row_to_canvas_candidate_observation(inserted.first()), True

    async def list_current_canvas_candidate_observations(
        self,
        organization_id: str,
        candidate_id: str,
    ) -> list[CanvasCandidateObservation]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(canvas_candidate_observations_table)
                .where(
                    canvas_candidate_observations_table.c.organization_id == organization_id,
                    canvas_candidate_observations_table.c.candidate_id == candidate_id,
                    canvas_candidate_observations_table.c.is_current.is_(True),
                )
                .order_by(canvas_candidate_observations_table.c.requirement_id)
            )
            return [self._row_to_canvas_candidate_observation(row) for row in result.all()]

    async def save_evidence_policy_review(self, review: EvidencePolicyReview) -> None:
        review.updated_at = datetime.now(UTC)
        async with self._session_factory() as session:
            data = {
                "id": review.id,
                "organization_id": review.organization_id,
                "application_id": review.application_id,
                "credential_id": review.credential_id,
                "binding_id": review.binding_id,
                "status": review.status.value,
                "prior_decision": review.prior_decision or {},
                "current_decision": review.current_decision or {},
                "triggering_fact_id": review.triggering_fact_id,
                "resolution_action": review.resolution_action,
                "resolution_notes": review.resolution_notes,
                "resolved_by": review.resolved_by,
                "resolved_at": review.resolved_at,
                "resolution_claim_token": review.resolution_claim_token,
                "resolution_claim_action": review.resolution_claim_action,
                "resolution_claimed_at": review.resolution_claimed_at,
                "resolution_recovery_pending": review.resolution_recovery_pending,
                "created_at": review.created_at,
                "updated_at": review.updated_at,
            }
            await session.execute(
                pg_insert(evidence_policy_reviews_table)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=["id"],
                    set_={key: value for key, value in data.items() if key not in {"id", "created_at"}},
                )
            )
            await session.commit()

    async def get_open_evidence_policy_review(
        self,
        organization_id: str,
        application_id: str,
    ) -> EvidencePolicyReview | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(evidence_policy_reviews_table).where(
                    evidence_policy_reviews_table.c.organization_id == organization_id,
                    evidence_policy_reviews_table.c.application_id == application_id,
                    evidence_policy_reviews_table.c.status == EvidencePolicyReviewStatus.OPEN.value,
                )
            )
            row = result.first()
            return self._row_to_evidence_policy_review(row) if row else None

    async def claim_evidence_policy_review_resolution(
        self,
        organization_id: str,
        review_id: str,
        *,
        claim_token: str,
        action: str,
    ) -> EvidencePolicyReview | None:
        """Claim one OPEN review after taking the shared application lock."""

        now = datetime.now(UTC)
        async with self._session_factory() as session, session.begin():
            review_result = await session.execute(
                select(evidence_policy_reviews_table.c.application_id).where(
                    evidence_policy_reviews_table.c.id == review_id,
                    evidence_policy_reviews_table.c.organization_id == organization_id,
                )
            )
            review_row = review_result.first()
            if review_row is None:
                return None
            app_result = await session.execute(
                select(applications_table.c.id)
                .where(
                    applications_table.c.id == review_row.application_id,
                    applications_table.c.organization_id == organization_id,
                )
                .with_for_update()
            )
            if app_result.first() is None:
                return None
            claimed = await session.execute(
                update(evidence_policy_reviews_table)
                .where(
                    evidence_policy_reviews_table.c.id == review_id,
                    evidence_policy_reviews_table.c.organization_id == organization_id,
                    evidence_policy_reviews_table.c.status
                    == EvidencePolicyReviewStatus.OPEN.value,
                    evidence_policy_reviews_table.c.resolution_claim_token.is_(None),
                )
                .values(
                    resolution_claim_token=claim_token,
                    resolution_claim_action=action,
                    resolution_claimed_at=now,
                    updated_at=now,
                )
                .returning(evidence_policy_reviews_table)
            )
            row = claimed.first()
            return self._row_to_evidence_policy_review(row) if row else None

    async def release_evidence_policy_review_resolution(
        self,
        organization_id: str,
        review_id: str,
        *,
        claim_token: str,
    ) -> bool:
        async with self._session_factory() as session, session.begin():
            released = await session.execute(
                update(evidence_policy_reviews_table)
                .where(
                    evidence_policy_reviews_table.c.id == review_id,
                    evidence_policy_reviews_table.c.organization_id == organization_id,
                    evidence_policy_reviews_table.c.status
                    == EvidencePolicyReviewStatus.OPEN.value,
                    evidence_policy_reviews_table.c.resolution_claim_token == claim_token,
                )
                .values(
                    resolution_claim_token=None,
                    resolution_claim_action=None,
                    resolution_claimed_at=None,
                    updated_at=datetime.now(UTC),
                )
                .returning(evidence_policy_reviews_table.c.id)
            )
            return released.first() is not None

    async def finalize_evidence_policy_review_resolution(
        self,
        organization_id: str,
        review_id: str,
        *,
        claim_token: str,
        status: EvidencePolicyReviewStatus,
        resolution_action: str,
        resolution_notes: str | None,
        resolved_by: str | None,
        resolved_at: datetime,
        audit_event: IssuanceEvent,
    ) -> EvidencePolicyReview | None:
        if status == EvidencePolicyReviewStatus.OPEN:
            raise ValueError("A claimed evidence review cannot finalize as OPEN")
        async with self._session_factory() as session, session.begin():
            finalized = await session.execute(
                update(evidence_policy_reviews_table)
                .where(
                    evidence_policy_reviews_table.c.id == review_id,
                    evidence_policy_reviews_table.c.organization_id == organization_id,
                    evidence_policy_reviews_table.c.status
                    == EvidencePolicyReviewStatus.OPEN.value,
                    evidence_policy_reviews_table.c.resolution_claim_token == claim_token,
                    evidence_policy_reviews_table.c.resolution_claim_action
                    == resolution_action,
                )
                .values(
                    status=status.value,
                    resolution_action=resolution_action,
                    resolution_notes=resolution_notes,
                    resolved_by=resolved_by,
                    resolved_at=resolved_at,
                    resolution_claim_token=None,
                    resolution_claim_action=None,
                    resolution_claimed_at=None,
                    resolution_recovery_pending=False,
                    updated_at=resolved_at,
                )
                .returning(evidence_policy_reviews_table)
            )
            row = finalized.first()
            if row is None:
                return None
            review = self._row_to_evidence_policy_review(row)
            if audit_event.application_id != review.application_id:
                raise ValueError("Evidence review audit event does not belong to the application")
            await self._save_event_in_session(session, audit_event)
            return review

    async def get_evidence_policy_review_for_org(
        self,
        organization_id: str,
        review_id: str,
    ) -> EvidencePolicyReview | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(evidence_policy_reviews_table).where(
                    evidence_policy_reviews_table.c.id == review_id,
                    evidence_policy_reviews_table.c.organization_id == organization_id,
                )
            )
            row = result.first()
            return self._row_to_evidence_policy_review(row) if row else None

    async def list_evidence_policy_reviews(
        self,
        organization_id: str,
        *,
        status: EvidencePolicyReviewStatus | None = None,
        limit: int = 100,
    ) -> list[EvidencePolicyReview]:
        conditions = [evidence_policy_reviews_table.c.organization_id == organization_id]
        if status is not None:
            conditions.append(evidence_policy_reviews_table.c.status == status.value)
        async with self._session_factory() as session:
            result = await session.execute(
                select(evidence_policy_reviews_table)
                .where(and_(*conditions))
                .order_by(evidence_policy_reviews_table.c.created_at.desc())
                .limit(max(1, min(limit, 500)))
            )
            return [self._row_to_evidence_policy_review(row) for row in result.all()]

    async def save_integration_secret(self, secret: OrganizationIntegrationSecret) -> None:
        encryption = _get_integration_secret_encryption()
        now = datetime.now(UTC)
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
                .values(last_used_at=datetime.now(UTC))
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
        now = datetime.now(UTC)
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
        cutoff_at = datetime.now(UTC) - timedelta(days=retention_days)
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
        cutoff_at = datetime.now(UTC) - timedelta(days=retention_days)

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
            "purged_at": datetime.now(UTC).isoformat(),
            "purged_records": purged_records,
            "next_expiry_at": post_purge["next_expiry_at"],
            "oldest_retained_record_at": post_purge["oldest_retained_record_at"],
            "tracked_scope": summary["tracked_scope"],
        }
