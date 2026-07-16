"""Repository port interfaces for issuance service."""

from __future__ import annotations

import copy
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

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
    CanvasLearnerIdentity,
    CanvasLtiLaunchState,
    CanvasOAuthAuthorization,
    CanvasOAuthConnection,
    CanvasPlatform,
    CanvasProgramBinding,
    CanvasSyncReadinessState,
    CanvasWorkerHeartbeat,
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    DeliveryTarget,
    EvidenceFact,
    EvidenceFactHead,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
    IssuanceEvent,
    IssuanceTransaction,
    IssuedCredential,
    OrganizationIntegrationSecret,
)


@dataclass(frozen=True)
class CanvasEvidenceAtomicMutation:
    """Policy/review writes planned while an application's evidence is locked."""

    policy_decision: Any
    correction_review: EvidencePolicyReview | None = None
    review_changed: bool = False
    audit_events: tuple[IssuanceEvent, ...] = ()


@dataclass(frozen=True)
class CanvasEvidenceAtomicCommit:
    """Committed authoritative evidence state returned by repository adapters."""

    evidence_fact: EvidenceFact
    inserted: bool
    changed: bool
    current_facts: list[EvidenceFact]
    policy_decision: Any
    correction_review: EvidencePolicyReview | None = None


class CanvasEvidenceTransitionPlanner(Protocol):
    """Synchronous policy transition evaluated inside the persistence transaction."""

    def __call__(
        self,
        *,
        app: Application,
        previous_facts: list[EvidenceFact],
        evidence_fact: EvidenceFact,
        inserted: bool,
        changed: bool,
        current_facts: list[EvidenceFact],
        open_review: EvidencePolicyReview | None,
    ) -> CanvasEvidenceAtomicMutation: ...


def merge_application_integration_context(
    current: dict[str, Any] | None,
    patch: dict[str, Any],
) -> dict[str, Any]:
    """Recursively merge a narrow integration patch without sharing values."""

    merged = copy.deepcopy(current or {})
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_application_integration_context(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class IIssuanceRepository(ABC):
    """Port for issuance data persistence."""
    
    # Transaction methods
    @abstractmethod
    async def save_transaction(self, tx: IssuanceTransaction) -> None:
        """Save or update a transaction."""
        pass

    @abstractmethod
    async def claim_transaction_for_signing(
        self,
        prepared_transaction: IssuanceTransaction,
        credential_id: str,
    ) -> IssuanceTransaction | None:
        """Atomically persist signing context and transition AUTHORIZED to SIGNING.

        ``prepared_transaction`` may contain issuer context resolved while the
        transaction was still authorized. Implementations must apply those
        mutable signing fields in the same compare-and-set that reserves the
        credential ID. A failed compare-and-set must not persist any part of the
        prepared snapshot.
        """
        pass

    @abstractmethod
    async def finalize_credential_issuance(
        self,
        tx: IssuanceTransaction,
        credential: IssuedCredential,
    ) -> None:
        """Atomically persist one credential and transition SIGNING to ISSUED.

        The supplied transaction remains in ``SIGNING`` state until this method
        succeeds; callers must not expose an issued state before the database
        transaction commits.
        """
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
    async def list_evidence_facts_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFact]:
        """List normalized evidence facts for an application."""
        pass

    @abstractmethod
    async def record_evidence_revision(self, fact: EvidenceFact) -> tuple[EvidenceFact, bool]:
        """Append an immutable revision and atomically advance its evidence head."""
        pass

    @abstractmethod
    async def commit_authoritative_canvas_evidence_revision(
        self,
        fact: EvidenceFact,
        *,
        transition: CanvasEvidenceTransitionPlanner,
    ) -> CanvasEvidenceAtomicCommit:
        """Commit fact, head, policy review, and audit event under one app lock."""
        pass

    @abstractmethod
    async def list_evidence_fact_heads_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFactHead]:
        """List organization-scoped evidence heads for an application."""
        pass

    @abstractmethod
    async def list_current_evidence_facts_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFact]:
        """Load only policy-effective evidence revisions."""
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
    async def reserve_canvas_application_issuance(
        self,
        prepared_transaction: IssuanceTransaction,
        *,
        reviewer_id: str,
        review_notes: str,
        reviewed_at: datetime,
    ) -> tuple[Application, IssuanceTransaction, bool]:
        """Atomically approve a Canvas application and reserve one transaction.

        Implementations must lock the application, reuse any transaction that
        another approver already made active, and link a newly inserted
        transaction in the same database commit.  The boolean result is true
        when an already-issued credential was repaired onto stale Canvas
        application/candidate projection state instead of reserving a new
        claim.
        """
        pass

    @abstractmethod
    async def patch_application_integration_context(
        self,
        organization_id: str,
        application_id: str,
        *,
        patch: dict[str, Any],
        expected_updated_at: datetime | None = None,
    ) -> Application | None:
        """Deep-merge only integration context, optionally using updated_at CAS."""
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
    async def patch_canvas_platform_validation_state(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_config_version: int,
        last_validated_at: datetime | None,
        last_connection_error: str | None,
    ) -> CanvasPlatform | None:
        """CAS-update only operational validation fields for one platform."""
        pass

    @abstractmethod
    async def patch_canvas_platform_connection_config(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_config_version: int,
        patch: dict[str, Any],
        remove_keys: tuple[str, ...] = (),
    ) -> CanvasPlatform | None:
        """CAS-merge connection metadata without replacing platform configuration."""
        pass

    @abstractmethod
    async def get_canvas_platform(self, platform_id: str) -> CanvasPlatform | None:
        """Look up a Canvas platform by ID."""
        pass

    @abstractmethod
    async def get_canvas_platform_for_org(
        self,
        organization_id: str,
        platform_id: str,
    ) -> CanvasPlatform | None:
        """Resolve a platform only when it belongs to the trusted organization."""
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
    async def save_canvas_program_binding(self, binding: CanvasProgramBinding) -> None:
        """Persist a program-level Canvas binding."""
        pass

    @abstractmethod
    async def get_canvas_program_binding(self, binding_id: str) -> CanvasProgramBinding | None:
        """Look up a Canvas program binding by ID."""
        pass

    @abstractmethod
    async def get_canvas_program_binding_for_org(
        self,
        organization_id: str,
        binding_id: str,
    ) -> CanvasProgramBinding | None:
        """Resolve a binding only when it belongs to the trusted organization."""
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
    async def save_canvas_learner_identity(self, identity: CanvasLearnerIdentity) -> None:
        """Persist a verified or quarantined Canvas learner identity mapping."""
        pass

    @abstractmethod
    async def get_canvas_learner_identity_for_org(
        self,
        organization_id: str,
        identity_id: str,
    ) -> CanvasLearnerIdentity | None:
        """Resolve an identity by tenant-scoped ID."""
        pass

    @abstractmethod
    async def get_canvas_learner_identity_by_subject(
        self,
        *,
        organization_id: str,
        platform_id: str,
        deployment_id: str,
        lti_subject: str,
    ) -> CanvasLearnerIdentity | None:
        """Resolve an opaque LTI subject within a verified deployment."""
        pass

    @abstractmethod
    async def get_canvas_learner_identity_by_canvas_user(
        self,
        *,
        organization_id: str,
        platform_id: str,
        deployment_id: str,
        canvas_user_id: str,
    ) -> CanvasLearnerIdentity | None:
        """Resolve an active numeric Canvas identity mapping."""
        pass

    @abstractmethod
    async def save_canvas_oauth_authorization(
        self,
        authorization: CanvasOAuthAuthorization,
    ) -> None:
        """Persist a hashed, expiring Canvas OAuth transaction."""
        pass

    @abstractmethod
    async def consume_canvas_oauth_authorization(
        self,
        state_hash: str,
        *,
        now: datetime | None = None,
    ) -> CanvasOAuthAuthorization | None:
        """Atomically consume an unexpired OAuth state hash once."""
        pass

    @abstractmethod
    async def get_canvas_oauth_authorization_for_org(
        self,
        organization_id: str,
        authorization_id: str,
    ) -> CanvasOAuthAuthorization | None:
        """Resolve authorization metadata by tenant-scoped ID."""
        pass

    @abstractmethod
    async def save_canvas_oauth_connection(self, connection: CanvasOAuthConnection) -> None:
        """Persist a normalized connection containing token secret references only."""
        pass

    @abstractmethod
    async def save_canvas_oauth_connection_cas(
        self,
        connection: CanvasOAuthConnection,
        *,
        expected_updated_at: datetime | None,
    ) -> bool:
        """Insert-if-absent or replace the exact connection snapshot atomically."""
        pass

    @abstractmethod
    async def get_canvas_oauth_connection(
        self,
        organization_id: str,
        platform_id: str,
    ) -> CanvasOAuthConnection | None:
        """Resolve the organization's Canvas OAuth connection for a platform."""
        pass

    @abstractmethod
    async def list_canvas_oauth_connections(
        self,
        organization_id: str,
    ) -> list[CanvasOAuthConnection]:
        """List normalized Canvas OAuth connections for an organization."""
        pass

    @abstractmethod
    async def mark_canvas_oauth_reauthorization_required(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_updated_at: datetime,
    ) -> CanvasOAuthConnection | None:
        """CAS-fail closed after Canvas rejects the currently stored access token."""
        pass

    @abstractmethod
    async def acquire_canvas_oauth_refresh_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        """Serialize refresh with an expiring database lease."""
        pass

    @abstractmethod
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
        """Atomically publish refreshed token references and release the lease."""
        pass

    @abstractmethod
    async def release_canvas_oauth_refresh_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        reauthorization_required: bool = False,
    ) -> bool:
        """Release a refresh lease, optionally failing closed for reauthorization."""
        pass

    @abstractmethod
    async def list_canvas_oauth_revocation_retries(
        self,
        *,
        limit: int = 100,
    ) -> list[CanvasOAuthConnection]:
        """List due remote token-revocation retries for the worker."""
        pass

    @abstractmethod
    async def begin_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        expected_updated_at: datetime,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        """CAS-transition the current connection to a leased revocation."""
        pass

    @abstractmethod
    async def acquire_canvas_oauth_revocation_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        """Conditionally lease one pending remote token revocation."""
        pass

    @abstractmethod
    async def reschedule_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        retry_at: datetime,
        error_code: str,
    ) -> bool:
        """Conditionally release and reschedule a worker-owned revocation."""
        pass

    @abstractmethod
    async def complete_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
    ) -> bool:
        """Delete a remotely revoked connection only when the lease is owned."""
        pass

    @abstractmethod
    async def delete_canvas_oauth_connection(
        self,
        organization_id: str,
        platform_id: str,
    ) -> bool:
        """Delete local token references after successful remote revocation."""
        pass

    @abstractmethod
    async def save_canvas_sync_target(self, target: CanvasEvidenceSyncTarget) -> None:
        """Persist a durable Canvas synchronization target."""
        pass

    @abstractmethod
    async def get_canvas_sync_target_for_org(
        self,
        organization_id: str,
        target_id: str,
    ) -> CanvasEvidenceSyncTarget | None:
        """Resolve a synchronization target by tenant-scoped ID."""
        pass

    @abstractmethod
    async def get_canvas_sync_target_by_logical_key(
        self,
        organization_id: str,
        logical_key: str,
    ) -> CanvasEvidenceSyncTarget | None:
        """Resolve the idempotent organization/logical target key."""
        pass

    @abstractmethod
    async def touch_canvas_sync_target_worker_heartbeat(
        self,
        *,
        organization_id: str,
        target_id: str,
        expected_config_version: int,
        worker_id: str,
        heartbeat_at: datetime,
    ) -> bool:
        """Patch only worker heartbeat metadata on the expected active target."""
        pass

    @abstractmethod
    async def mark_canvas_sync_target_succeeded(
        self,
        *,
        organization_id: str,
        target_id: str,
        expected_config_version: int,
        succeeded_at: datetime,
    ) -> bool:
        """Patch only success metadata on the expected active target."""
        pass

    @abstractmethod
    async def enqueue_canvas_sync_job(
        self,
        target: CanvasEvidenceSyncTarget,
        *,
        available_at: datetime | None = None,
    ) -> CanvasEvidenceSyncJob:
        """Enqueue or return the one active synchronization job for a target."""
        pass

    @abstractmethod
    async def enqueue_due_canvas_sync_jobs(self, *, limit: int = 100) -> list[CanvasEvidenceSyncJob]:
        """Atomically enqueue due targets across competing schedulers."""
        pass

    @abstractmethod
    async def lease_canvas_sync_jobs(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 120,
    ) -> list[CanvasEvidenceSyncJob]:
        """Lease ready jobs for a separate worker process."""
        pass

    @abstractmethod
    async def save_canvas_sync_job(self, job: CanvasEvidenceSyncJob) -> None:
        """Persist a leased job outcome or retry schedule."""
        pass

    @abstractmethod
    async def save_canvas_sync_job_if_leased(
        self,
        job: CanvasEvidenceSyncJob,
        *,
        worker_id: str,
    ) -> bool:
        """Persist a renewal/outcome only while this exact worker lease is current.

        Implementations must fence on the stored leased status, owner, unexpired
        lease, and attempt count.  A stale worker must never overwrite a lease
        reclaimed by another worker after a pause or crash.
        """
        pass

    @abstractmethod
    async def retry_canvas_sync_job_from_dead_letter(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        """Atomically re-enable the target and queue its dead-letter job."""
        pass

    @abstractmethod
    async def resolve_canvas_sync_job_dead_letter(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        """Atomically acknowledge a dead-letter job without retrying it."""
        pass

    @abstractmethod
    async def get_canvas_sync_job_for_org(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        """Resolve a synchronization job by tenant-scoped ID."""
        pass

    @abstractmethod
    async def list_canvas_sync_jobs(
        self,
        organization_id: str,
        *,
        target_id: str | None = None,
        status: CanvasEvidenceSyncJobStatus | None = None,
        limit: int = 100,
    ) -> list[CanvasEvidenceSyncJob]:
        """List sanitized job history for an organization."""
        pass

    @abstractmethod
    async def get_canvas_sync_readiness_state(
        self,
        organization_id: str,
        platform_id: str,
        binding_id: str,
        *,
        now: datetime | None = None,
    ) -> CanvasSyncReadinessState:
        """Return tenant-scoped dead-letter and stale-backlog blockers."""
        pass

    @abstractmethod
    async def upsert_canvas_worker_heartbeat(self, heartbeat: CanvasWorkerHeartbeat) -> None:
        """Create or update liveness for a separate Canvas worker process."""
        pass

    @abstractmethod
    async def get_fresh_canvas_worker_heartbeat(
        self,
        *,
        role: str = "canvas_sync",
        max_age_seconds: int = 120,
    ) -> CanvasWorkerHeartbeat | None:
        """Return the freshest non-stale heartbeat for readiness."""
        pass

    @abstractmethod
    async def list_canvas_worker_heartbeats(
        self,
        *,
        role: str | None = None,
    ) -> list[CanvasWorkerHeartbeat]:
        """List worker heartbeat history by role."""
        pass

    @abstractmethod
    async def save_canvas_award_candidate(self, candidate: CanvasAwardCandidate) -> None:
        """Persist an unsigned Canvas award candidate."""
        pass

    @abstractmethod
    async def get_canvas_award_candidate_for_org(
        self,
        organization_id: str,
        candidate_id: str,
    ) -> CanvasAwardCandidate | None:
        """Resolve an award candidate by tenant-scoped ID."""
        pass

    @abstractmethod
    async def list_canvas_award_candidates(
        self,
        organization_id: str,
        *,
        state: CanvasAwardCandidateState | None = None,
        binding_id: str | None = None,
        limit: int = 100,
    ) -> list[CanvasAwardCandidate]:
        """List organization-scoped background award candidates."""
        pass

    @abstractmethod
    async def save_canvas_candidate_observation(
        self,
        observation: CanvasCandidateObservation,
    ) -> tuple[CanvasCandidateObservation, bool]:
        """Append and head an immutable candidate observation."""
        pass

    @abstractmethod
    async def list_current_canvas_candidate_observations(
        self,
        organization_id: str,
        candidate_id: str,
    ) -> list[CanvasCandidateObservation]:
        """List current observations for a tenant-owned candidate."""
        pass

    @abstractmethod
    async def save_evidence_policy_review(self, review: EvidencePolicyReview) -> None:
        """Persist a post-issuance correction review."""
        pass

    @abstractmethod
    async def get_open_evidence_policy_review(
        self,
        organization_id: str,
        application_id: str,
    ) -> EvidencePolicyReview | None:
        """Return the single open correction review for an application."""
        pass

    @abstractmethod
    async def claim_evidence_policy_review_resolution(
        self,
        organization_id: str,
        review_id: str,
        *,
        claim_token: str,
        action: str,
    ) -> EvidencePolicyReview | None:
        """Atomically claim an OPEN review for one lifecycle side effect."""
        pass

    @abstractmethod
    async def release_evidence_policy_review_resolution(
        self,
        organization_id: str,
        review_id: str,
        *,
        claim_token: str,
    ) -> bool:
        """Return a claimed review to OPEN when its handler fails safely."""
        pass

    @abstractmethod
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
        """CAS-finalize a claim and append its audit event in one transaction."""
        pass

    @abstractmethod
    async def get_evidence_policy_review_for_org(
        self,
        organization_id: str,
        review_id: str,
    ) -> EvidencePolicyReview | None:
        """Resolve a correction review by tenant-scoped ID."""
        pass

    @abstractmethod
    async def list_evidence_policy_reviews(
        self,
        organization_id: str,
        *,
        status: EvidencePolicyReviewStatus | None = None,
        limit: int = 100,
    ) -> list[EvidencePolicyReview]:
        """List correction reviews for an organization."""
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
