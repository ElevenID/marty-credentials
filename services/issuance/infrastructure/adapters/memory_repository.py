"""In-memory repository adapter for development."""

import asyncio
import copy
import secrets
from datetime import UTC, datetime, timedelta
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
    DeliveryTarget,
    EvidenceFact,
    EvidenceFactHead,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
    OrganizationIntegrationSecret,
    issuance_save_predecessors,
)
from issuance.domain.ports import (
    CanvasEvidenceAtomicCommit,
    CanvasEvidenceTransitionPlanner,
    IIssuanceRepository,
    merge_application_integration_context,
)


class InMemoryIssuanceRepository(IIssuanceRepository):
    """In-memory implementation for development and testing."""

    @staticmethod
    def _delivery_record_sort_key(record: CredentialDeliveryRecord):
        target_priority = {
            "wallet": 0,
            "didcomm_v2": 1,
            "canvas_credentials": 2,
        }
        return (
            record.created_at,
            target_priority.get(record.delivery_target.value, 99),
            record.delivery_target.value,
        )
    
    def __init__(self):
        self._transactions: dict[str, IssuanceTransaction] = {}
        self._transaction_locks: dict[str, asyncio.Lock] = {}
        self._credentials: dict[str, IssuedCredential] = {}
        self._applications: dict[str, Application] = {}
        self._application_templates: dict[str, ApplicationTemplate] = {}
        self._authorization_sessions: dict[str, AuthorizationSession] = {}
        self._canvas_event_receipts: dict[tuple[str | None, str], CanvasEventReceipt] = {}
        self._canvas_lti_launch_states: dict[str, CanvasLtiLaunchState] = {}
        self._canvas_platforms: dict[str, CanvasPlatform] = {}
        self._canvas_platform_locks: dict[str, asyncio.Lock] = {}
        self._canvas_program_bindings: dict[str, CanvasProgramBinding] = {}
        self._integration_secrets: dict[str, OrganizationIntegrationSecret] = {}
        self._delivery_records: dict[str, CredentialDeliveryRecord] = {}
        self._evidence_facts: dict[str, EvidenceFact] = {}
        self._evidence_fact_heads: dict[tuple[str, str], EvidenceFactHead] = {}
        self._canvas_learner_identities: dict[str, CanvasLearnerIdentity] = {}
        self._canvas_oauth_authorizations: dict[str, CanvasOAuthAuthorization] = {}
        self._canvas_oauth_connections: dict[tuple[str, str], CanvasOAuthConnection] = {}
        self._canvas_sync_targets: dict[str, CanvasEvidenceSyncTarget] = {}
        self._canvas_sync_jobs: dict[str, CanvasEvidenceSyncJob] = {}
        self._canvas_worker_heartbeats: dict[str, CanvasWorkerHeartbeat] = {}
        self._canvas_award_candidates: dict[str, CanvasAwardCandidate] = {}
        self._canvas_candidate_observations: dict[str, CanvasCandidateObservation] = {}
        self._evidence_policy_reviews: dict[str, EvidencePolicyReview] = {}
        self._application_evidence_locks: dict[str, asyncio.Lock] = {}
        self._application_issuance_locks: dict[str, asyncio.Lock] = {}
        self._approval_policy_sets: dict[tuple[str, str], ApprovalPolicySet] = {}
        self._events: list[IssuanceEvent] = []
    
    async def save_transaction(self, tx: IssuanceTransaction) -> None:
        lock = self._transaction_locks.setdefault(tx.id, asyncio.Lock())
        async with lock:
            stored = self._transactions.get(tx.id)
            if stored is not None and stored.status not in issuance_save_predecessors(tx.status):
                raise ValueError(
                    f"Stale issuance transaction transition {stored.status.value}->{tx.status.value}"
                )
            self._transactions[tx.id] = copy.deepcopy(tx)

    async def claim_transaction_for_signing(
        self,
        prepared_transaction: IssuanceTransaction,
        credential_id: str,
    ) -> IssuanceTransaction | None:
        transaction_id = prepared_transaction.id
        lock = self._transaction_locks.setdefault(transaction_id, asyncio.Lock())
        async with lock:
            stored = self._transactions.get(transaction_id)
            if stored is None or stored.status != IssuanceStatus.AUTHORIZED:
                return None
            claimed = copy.deepcopy(prepared_transaction)
            claimed.status = IssuanceStatus.SIGNING
            claimed.reserved_credential_id = credential_id
            self._transactions[transaction_id] = copy.deepcopy(claimed)
            return claimed

    async def finalize_credential_issuance(
        self,
        tx: IssuanceTransaction,
        credential: IssuedCredential,
    ) -> None:
        if tx.status != IssuanceStatus.SIGNING:
            raise ValueError("Issuance transaction must remain in signing state until finalization")
        lock = self._transaction_locks.setdefault(tx.id, asyncio.Lock())
        async with lock:
            stored = self._transactions.get(tx.id)
            if stored is None or stored.status != IssuanceStatus.SIGNING:
                raise ValueError("Issuance transaction is not reserved for signing")
            if stored.reserved_credential_id != credential.id or credential.transaction_id != tx.id:
                raise ValueError("Issued credential does not match the signing reservation")
            duplicate = next(
                (item for item in self._credentials.values() if item.transaction_id == tx.id),
                None,
            )
            if duplicate is not None:
                raise ValueError("Issuance transaction already has a credential")
            application_lock = self._application_issuance_locks.setdefault(
                tx.application_id or f"transaction:{tx.id}",
                asyncio.Lock(),
            )
            async with application_lock:
                app = self._applications.get(tx.application_id or "")
                candidate = None
                if app is not None and self._canvas_context(app) is not None:
                    if app.organization_id != credential.organization_id:
                        raise ValueError("Canvas credential organization does not match application")
                    if app.credential_id not in (None, credential.id):
                        raise ValueError("Canvas application already has a different credential")
                    candidate_id = str(
                        self._canvas_context(app).get("canvas_award_candidate_id") or ""
                    ).strip()
                    if candidate_id:
                        candidate = self._canvas_award_candidates.get(candidate_id)
                        if candidate is not None:
                            if (
                                candidate.organization_id != app.organization_id
                                or candidate.application_id != app.id
                            ):
                                raise ValueError("Canvas award candidate does not match application")
                            if candidate.claimed_credential_id not in (None, credential.id):
                                raise ValueError("Canvas award candidate already has a different credential")

                finalized = copy.deepcopy(tx)
                finalized.status = IssuanceStatus.ISSUED
                finalized.nonce = None
                finalized.issued_at = credential.issued_at
                self._credentials[credential.id] = copy.deepcopy(credential)
                self._transactions[tx.id] = finalized
                if app is not None and self._canvas_context(app) is not None:
                    app.credential_id = credential.id
                    app.updated_at = credential.issued_at
                    if candidate is not None:
                        candidate.state = CanvasAwardCandidateState.CLAIMED
                        candidate.claimed_credential_id = credential.id
                        candidate.updated_at = credential.issued_at
    
    async def get_transaction(self, tx_id: str) -> IssuanceTransaction | None:
        tx = self._transactions.get(tx_id)
        return copy.deepcopy(tx) if tx is not None else None
    
    async def get_by_pre_auth_code(self, code: str) -> IssuanceTransaction | None:
        for tx in self._transactions.values():
            if tx.pre_auth_code == code:
                return copy.deepcopy(tx)
        return None
    
    async def get_by_access_token(self, token: str) -> IssuanceTransaction | None:
        import hmac as _hmac
        for tx in self._transactions.values():
            if tx.access_token and _hmac.compare_digest(tx.access_token, token):
                return copy.deepcopy(tx)
        return None
    
    async def list_transactions(self, org_id: str) -> list[IssuanceTransaction]:
        return [copy.deepcopy(tx) for tx in self._transactions.values() if tx.organization_id == org_id]
    
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

    async def save_delivery_record(self, record: CredentialDeliveryRecord) -> None:
        existing = self._delivery_records.get(record.id)
        if existing is not None:
            record.created_at = existing.created_at
        record.updated_at = datetime.now(UTC)
        self._delivery_records[record.id] = record

    async def get_delivery_record(self, record_id: str) -> CredentialDeliveryRecord | None:
        return self._delivery_records.get(record_id)

    async def get_canvas_delivery_record_by_external_credential_id(
        self,
        external_credential_id: str,
        *,
        canvas_account_id: str | None = None,
        organization_id: str | None = None,
    ) -> CredentialDeliveryRecord | None:
        for record in sorted(self._delivery_records.values(), key=self._delivery_record_sort_key):
            if record.delivery_target != DeliveryTarget.CANVAS_CREDENTIALS:
                continue
            if record.external_credential_id != external_credential_id:
                continue
            if canvas_account_id is not None and record.canvas_account_id != canvas_account_id:
                continue
            if organization_id is not None and record.organization_id != organization_id:
                continue
            return record
        return None

    async def list_delivery_records_for_credential(self, credential_id: str) -> list[CredentialDeliveryRecord]:
        return sorted(
            [record for record in self._delivery_records.values() if record.credential_id == credential_id],
            key=self._delivery_record_sort_key,
        )

    async def list_delivery_records(
        self,
        *,
        delivery_target: DeliveryTarget | None = None,
        statuses: list[CredentialDeliveryStatus] | None = None,
        organization_id: str | None = None,
        limit: int | None = None,
    ) -> list[CredentialDeliveryRecord]:
        records = list(self._delivery_records.values())
        if delivery_target is not None:
            records = [record for record in records if record.delivery_target == delivery_target]
        if statuses is not None:
            allowed_statuses = set(statuses)
            records = [record for record in records if record.status in allowed_statuses]
        if organization_id is not None:
            records = [record for record in records if record.organization_id == organization_id]
        records = sorted(records, key=self._delivery_record_sort_key)
        if limit is not None:
            records = records[:limit]
        return records

    async def save_evidence_fact(self, fact: EvidenceFact) -> None:
        stored, _changed = await self.record_evidence_revision(fact)
        if stored.id != fact.id:
            fact.id = stored.id
            fact.superseded_fact_id = stored.superseded_fact_id

    async def record_evidence_revision(self, fact: EvidenceFact) -> tuple[EvidenceFact, bool]:
        app = self._applications.get(fact.application_id)
        if app is None or app.organization_id != fact.organization_id:
            raise ValueError("Evidence application was not found for this organization")
        key = (fact.application_id, fact.logical_key)
        head = self._evidence_fact_heads.get(key)
        advances_head = head is None
        if head is None:
            fact.superseded_fact_id = None
        if head is not None:
            current = self._evidence_facts[head.fact_id]
            if current.payload_hash == fact.payload_hash:
                return current, False
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
        existing = self._evidence_facts.get(fact.id)
        if existing is not None:
            return existing, False
        self._evidence_facts[fact.id] = fact
        if advances_head:
            self._evidence_fact_heads[key] = EvidenceFactHead(
                organization_id=fact.organization_id,
                application_id=fact.application_id,
                logical_key=fact.logical_key,
                fact_id=fact.id,
            )
        return fact, advances_head

    async def commit_authoritative_canvas_evidence_revision(
        self,
        fact: EvidenceFact,
        *,
        transition: CanvasEvidenceTransitionPlanner,
    ) -> CanvasEvidenceAtomicCommit:
        """Mirror the production application transaction for deterministic tests."""

        lock = self._application_evidence_locks.setdefault(fact.application_id, asyncio.Lock())
        async with lock:
            app = self._applications.get(fact.application_id)
            if app is None or app.organization_id != fact.organization_id:
                raise ValueError("Evidence application was not found for this organization")

            facts_snapshot = copy.deepcopy(self._evidence_facts)
            heads_snapshot = copy.deepcopy(self._evidence_fact_heads)
            reviews_snapshot = copy.deepcopy(self._evidence_policy_reviews)
            events_snapshot = list(self._events)
            try:
                previous_facts = await self.list_current_evidence_facts_for_application(
                    fact.application_id,
                    organization_id=fact.organization_id,
                )
                stored_fact, changed = await self.record_evidence_revision(copy.deepcopy(fact))
                inserted = stored_fact.id not in facts_snapshot
                current_facts = await self.list_current_evidence_facts_for_application(
                    fact.application_id,
                    organization_id=fact.organization_id,
                )
                open_review = await self.get_open_evidence_policy_review(
                    fact.organization_id,
                    fact.application_id,
                )
                mutation = transition(
                    app=copy.deepcopy(app),
                    previous_facts=list(previous_facts),
                    evidence_fact=stored_fact,
                    inserted=inserted,
                    changed=changed,
                    current_facts=list(current_facts),
                    open_review=copy.deepcopy(open_review),
                )
                if mutation.review_changed:
                    if mutation.correction_review is None:
                        raise ValueError("Evidence transition marked a missing review as changed")
                    if (
                        mutation.correction_review.organization_id != fact.organization_id
                        or mutation.correction_review.application_id != fact.application_id
                    ):
                        raise ValueError(
                            "Evidence policy review does not belong to the locked application"
                        )
                    await self.save_evidence_policy_review(mutation.correction_review)
                for event in mutation.audit_events:
                    if event.application_id != fact.application_id:
                        raise ValueError(
                            "Evidence audit event does not belong to the locked application"
                        )
                    await self.save_event(event)
                return CanvasEvidenceAtomicCommit(
                    evidence_fact=stored_fact,
                    inserted=inserted,
                    changed=changed,
                    current_facts=current_facts,
                    policy_decision=mutation.policy_decision,
                    correction_review=mutation.correction_review,
                )
            except Exception:
                self._evidence_facts = facts_snapshot
                self._evidence_fact_heads = heads_snapshot
                self._evidence_policy_reviews = reviews_snapshot
                self._events = events_snapshot
                raise

    async def list_evidence_fact_heads_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFactHead]:
        return sorted(
            [
                head
                for head in self._evidence_fact_heads.values()
                if head.application_id == application_id
                and (organization_id is None or head.organization_id == organization_id)
            ],
            key=lambda head: head.logical_key,
        )

    async def list_current_evidence_facts_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFact]:
        heads = await self.list_evidence_fact_heads_for_application(
            application_id,
            organization_id=organization_id,
        )
        return sorted(
            [self._evidence_facts[head.fact_id] for head in heads],
            key=lambda fact: (fact.observed_at, fact.created_at, fact.id),
        )

    async def list_evidence_facts_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFact]:
        return sorted(
            [
                fact
                for fact in self._evidence_facts.values()
                if fact.application_id == application_id
                and (organization_id is None or fact.organization_id == organization_id)
            ],
            key=lambda fact: fact.created_at,
        )

    async def save_approval_policy_set(self, policy_set: ApprovalPolicySet) -> None:
        self._approval_policy_sets[(policy_set.organization_id, policy_set.id)] = policy_set

    async def get_approval_policy_set(
        self,
        organization_id: str,
        policy_set_id: str,
    ) -> ApprovalPolicySet | None:
        return self._approval_policy_sets.get((organization_id, policy_set_id))
    
    async def save_application_template(self, template: ApplicationTemplate) -> None:
        from datetime import datetime
        template.updated_at = datetime.now(UTC)
        self._application_templates[template.id] = template
    
    async def get_application_template(self, template_id: str) -> ApplicationTemplate | None:
        return self._application_templates.get(template_id)
    
    async def list_application_templates(self, org_id: str) -> list[ApplicationTemplate]:
        return [t for t in self._application_templates.values() if t.organization_id == org_id]

    async def delete_application_template(self, template_id: str) -> bool:
        return self._application_templates.pop(template_id, None) is not None
    
    async def save_application(self, app: Application) -> None:
        self._applications[app.id] = app

    @staticmethod
    def _canvas_context(app: Application) -> dict[str, Any] | None:
        integration_context = app.integration_context if isinstance(app.integration_context, dict) else {}
        canvas = integration_context.get("canvas")
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
        lock = self._application_issuance_locks.setdefault(application_id, asyncio.Lock())
        async with lock:
            app = self._applications.get(application_id)
            if (
                app is None
                or app.organization_id != prepared_transaction.organization_id
                or self._canvas_context(app) is None
            ):
                raise ValueError("Canvas application was not found for issuance")
            if app.status not in (ApplicationStatus.PENDING, ApplicationStatus.APPROVED):
                raise ValueError(f"Cannot approve application in {app.status} status")

            current_tx = (
                self._transactions.get(app.issuance_transaction_id)
                if app.issuance_transaction_id
                else None
            )
            if app.credential_id:
                if current_tx is None or current_tx.status != IssuanceStatus.ISSUED:
                    raise ValueError("Canvas application already has a claimed credential")
                return copy.deepcopy(app), copy.deepcopy(current_tx), True

            if current_tx is not None and current_tx.status == IssuanceStatus.ISSUED:
                issued = next(
                    (
                        item
                        for item in self._credentials.values()
                        if item.transaction_id == current_tx.id
                    ),
                    None,
                )
                if issued is None:
                    raise ValueError("Issued Canvas transaction has no credential")
                app.credential_id = issued.id
                app.updated_at = reviewed_at
                canvas = self._canvas_context(app) or {}
                candidate_id = str(canvas.get("canvas_award_candidate_id") or "").strip()
                candidate = self._canvas_award_candidates.get(candidate_id) if candidate_id else None
                if candidate is not None and candidate.application_id == app.id:
                    if candidate.claimed_credential_id not in (None, issued.id):
                        raise ValueError("Canvas award candidate already has a different credential")
                    candidate.state = CanvasAwardCandidateState.CLAIMED
                    candidate.claimed_credential_id = issued.id
                    candidate.updated_at = reviewed_at
                return copy.deepcopy(app), copy.deepcopy(current_tx), True

            current_is_active = bool(
                current_tx is not None
                and (
                    current_tx.status in {
                        IssuanceStatus.AUTHORIZED,
                        IssuanceStatus.SIGNING,
                    }
                    or (
                        current_tx.status == IssuanceStatus.PENDING
                        and not current_tx.is_expired
                    )
                )
            )
            if current_is_active:
                reserved = current_tx
            else:
                if prepared_transaction.id in self._transactions:
                    raise ValueError("Canvas issuance transaction identifier is already in use")
                self._transactions[prepared_transaction.id] = copy.deepcopy(prepared_transaction)
                reserved = prepared_transaction

            app.status = ApplicationStatus.APPROVED
            app.review_notes = review_notes
            app.reviewer_id = reviewer_id
            app.reviewed_at = reviewed_at
            app.issuance_transaction_id = reserved.id
            app.updated_at = reviewed_at
            return copy.deepcopy(app), copy.deepcopy(reserved), False

    async def patch_application_integration_context(
        self,
        organization_id: str,
        application_id: str,
        *,
        patch: dict,
        expected_updated_at: datetime | None = None,
    ) -> Application | None:
        if not isinstance(patch, dict):
            raise ValueError("Application integration context patch must be an object")
        lock = self._application_evidence_locks.setdefault(application_id, asyncio.Lock())
        async with lock:
            app = self._applications.get(application_id)
            if app is None or app.organization_id != organization_id:
                return None
            if expected_updated_at is not None and app.updated_at != expected_updated_at:
                return None
            app.integration_context = merge_application_integration_context(
                app.integration_context,
                patch,
            )
            app.updated_at = datetime.now(UTC)
            return copy.deepcopy(app)
    
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

    async def save_canvas_event_receipt(self, receipt: CanvasEventReceipt) -> None:
        self._canvas_event_receipts[(receipt.canvas_account_id, receipt.provider_event_id)] = receipt

    async def get_canvas_event_receipt(
        self,
        provider_event_id: str,
        canvas_account_id: str | None = None,
    ) -> CanvasEventReceipt | None:
        if canvas_account_id is not None:
            return self._canvas_event_receipts.get((canvas_account_id, provider_event_id))
        for (_account_id, event_id), receipt in self._canvas_event_receipts.items():
            if event_id == provider_event_id:
                return receipt
        return None

    async def list_canvas_event_receipts(
        self,
        *,
        organization_id: str | None = None,
        status: str | None = None,
        limit: int | None = None,
    ) -> list[CanvasEventReceipt]:
        receipts = list(self._canvas_event_receipts.values())
        if organization_id is not None:
            receipts = [
                receipt
                for receipt in receipts
                if receipt.organization_id == organization_id
            ]
        if status is not None:
            receipts = [receipt for receipt in receipts if receipt.status == status]
        receipts = sorted(receipts, key=lambda receipt: receipt.last_seen_at)
        if limit is not None:
            receipts = receipts[:limit]
        return receipts

    async def save_canvas_platform(self, platform: CanvasPlatform) -> None:
        platform.updated_at = datetime.now(UTC)
        self._canvas_platforms[platform.id] = platform

    async def patch_canvas_platform_validation_state(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_config_version: int,
        last_validated_at: datetime | None,
        last_connection_error: str | None,
    ) -> CanvasPlatform | None:
        lock = self._canvas_platform_locks.setdefault(platform_id, asyncio.Lock())
        async with lock:
            platform = self._canvas_platforms.get(platform_id)
            if (
                platform is None
                or platform.organization_id != organization_id
                or platform.config_version != expected_config_version
            ):
                return None
            platform.last_validated_at = last_validated_at
            platform.last_connection_error = last_connection_error
            platform.updated_at = datetime.now(UTC)
            return copy.deepcopy(platform)

    async def patch_canvas_platform_connection_config(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_config_version: int,
        patch: dict[str, Any],
        remove_keys: tuple[str, ...] = (),
    ) -> CanvasPlatform | None:
        lock = self._canvas_platform_locks.setdefault(platform_id, asyncio.Lock())
        async with lock:
            platform = self._canvas_platforms.get(platform_id)
            if (
                platform is None
                or platform.organization_id != organization_id
                or platform.config_version != expected_config_version
            ):
                return None
            connection_config = copy.deepcopy(platform.connection_config or {})
            connection_config.update(copy.deepcopy(patch))
            for key in remove_keys:
                connection_config.pop(key, None)
            platform.connection_config = connection_config
            platform.updated_at = datetime.now(UTC)
            return copy.deepcopy(platform)

    async def get_canvas_platform(self, platform_id: str) -> CanvasPlatform | None:
        return self._canvas_platforms.get(platform_id)

    async def get_canvas_platform_for_org(
        self,
        organization_id: str,
        platform_id: str,
    ) -> CanvasPlatform | None:
        platform = self._canvas_platforms.get(platform_id)
        if platform is None or platform.organization_id != organization_id:
            return None
        return platform

    async def get_canvas_platform_by_account_id(
        self,
        organization_id: str,
        canvas_account_id: str,
    ) -> CanvasPlatform | None:
        for platform in self._canvas_platforms.values():
            if (
                platform.organization_id == organization_id
                and platform.canvas_account_id == canvas_account_id
            ):
                return platform
        return None

    async def list_canvas_platforms(self, organization_id: str) -> list[CanvasPlatform]:
        return sorted(
            [
                platform
                for platform in self._canvas_platforms.values()
                if platform.organization_id == organization_id
            ],
            key=lambda platform: platform.created_at,
        )

    async def save_canvas_program_binding(self, binding: CanvasProgramBinding) -> None:
        binding.updated_at = datetime.now(UTC)
        self._canvas_program_bindings[binding.id] = binding

    async def get_canvas_program_binding(self, binding_id: str) -> CanvasProgramBinding | None:
        return self._canvas_program_bindings.get(binding_id)

    async def get_canvas_program_binding_for_org(
        self,
        organization_id: str,
        binding_id: str,
    ) -> CanvasProgramBinding | None:
        binding = self._canvas_program_bindings.get(binding_id)
        if binding is None or binding.organization_id != organization_id:
            return None
        return binding

    async def list_canvas_program_bindings(
        self,
        organization_id: str,
        platform_id: str | None = None,
        application_template_id: str | None = None,
    ) -> list[CanvasProgramBinding]:
        bindings = [
            binding
            for binding in self._canvas_program_bindings.values()
            if binding.organization_id == organization_id
        ]
        if platform_id is not None:
            bindings = [binding for binding in bindings if binding.platform_id == platform_id]
        if application_template_id is not None:
            bindings = [
                binding
                for binding in bindings
                if binding.application_template_id == application_template_id
            ]
        return sorted(bindings, key=lambda binding: binding.created_at)

    async def save_canvas_learner_identity(self, identity: CanvasLearnerIdentity) -> None:
        for existing_id, existing in list(self._canvas_learner_identities.items()):
            if (
                existing.platform_id == identity.platform_id
                and existing.deployment_id == identity.deployment_id
                and existing.lti_subject == identity.lti_subject
                and existing_id != identity.id
            ):
                identity.id = existing.id
                identity.created_at = existing.created_at
                self._canvas_learner_identities.pop(existing_id)
                break
        identity.updated_at = datetime.now(UTC)
        self._canvas_learner_identities[identity.id] = identity

    async def get_canvas_learner_identity_for_org(
        self,
        organization_id: str,
        identity_id: str,
    ) -> CanvasLearnerIdentity | None:
        identity = self._canvas_learner_identities.get(identity_id)
        if identity is None or identity.organization_id != organization_id:
            return None
        return identity

    async def get_canvas_learner_identity_by_subject(
        self,
        *,
        organization_id: str,
        platform_id: str,
        deployment_id: str,
        lti_subject: str,
    ) -> CanvasLearnerIdentity | None:
        for identity in self._canvas_learner_identities.values():
            if (
                identity.organization_id == organization_id
                and identity.platform_id == platform_id
                and identity.deployment_id == deployment_id
                and identity.lti_subject == lti_subject
            ):
                return identity
        return None

    async def get_canvas_learner_identity_by_canvas_user(
        self,
        *,
        organization_id: str,
        platform_id: str,
        deployment_id: str,
        canvas_user_id: str,
    ) -> CanvasLearnerIdentity | None:
        for identity in self._canvas_learner_identities.values():
            if (
                identity.organization_id == organization_id
                and identity.platform_id == platform_id
                and identity.deployment_id == deployment_id
                and identity.canvas_user_id == canvas_user_id
                and identity.status == CanvasLearnerIdentityStatus.LINKED
            ):
                return identity
        return None

    async def save_canvas_oauth_authorization(
        self,
        authorization: CanvasOAuthAuthorization,
    ) -> None:
        self._canvas_oauth_authorizations.setdefault(authorization.state_hash, authorization)

    async def consume_canvas_oauth_authorization(
        self,
        state_hash: str,
        *,
        now: datetime | None = None,
    ) -> CanvasOAuthAuthorization | None:
        authorization = self._canvas_oauth_authorizations.get(state_hash)
        consumed_at = now or datetime.now(UTC)
        if (
            authorization is None
            or authorization.consumed_at is not None
            or authorization.expires_at <= consumed_at
        ):
            return None
        authorization.consumed_at = consumed_at
        return authorization

    async def get_canvas_oauth_authorization_for_org(
        self,
        organization_id: str,
        authorization_id: str,
    ) -> CanvasOAuthAuthorization | None:
        for authorization in self._canvas_oauth_authorizations.values():
            if authorization.id == authorization_id and authorization.organization_id == organization_id:
                return authorization
        return None

    async def save_canvas_oauth_connection(self, connection: CanvasOAuthConnection) -> None:
        key = (connection.organization_id, connection.platform_id)
        existing = self._canvas_oauth_connections.get(key)
        if existing is not None and existing.id != connection.id:
            connection.id = existing.id
            connection.created_at = existing.created_at
        connection.updated_at = datetime.now(UTC)
        self._canvas_oauth_connections[key] = connection

    async def save_canvas_oauth_connection_cas(
        self,
        connection: CanvasOAuthConnection,
        *,
        expected_updated_at: datetime | None,
    ) -> bool:
        # Publishing a token grant and validating the platform snapshot must be
        # one logical operation.  Otherwise an OAuth callback that started
        # before archival could create a live connection after the platform was
        # disabled.  The PostgreSQL adapter enforces the same invariant while
        # holding a row lock on the platform.
        platform_lock = self._canvas_platform_locks.setdefault(
            connection.platform_id,
            asyncio.Lock(),
        )
        async with platform_lock:
            platform = self._canvas_platforms.get(connection.platform_id)
            if (
                platform is None
                or platform.organization_id != connection.organization_id
                or platform.archived_at is not None
                or platform.config_version != connection.platform_config_version
            ):
                return False
            key = (connection.organization_id, connection.platform_id)
            existing = self._canvas_oauth_connections.get(key)
            if expected_updated_at is None:
                if existing is not None:
                    return False
            elif existing is None or existing.updated_at != expected_updated_at:
                return False
            if existing is not None:
                connection.id = existing.id
                connection.created_at = existing.created_at
            connection.updated_at = datetime.now(UTC)
            self._canvas_oauth_connections[key] = connection
            return True

    async def get_canvas_oauth_connection(
        self,
        organization_id: str,
        platform_id: str,
    ) -> CanvasOAuthConnection | None:
        return self._canvas_oauth_connections.get((organization_id, platform_id))

    async def list_canvas_oauth_connections(
        self,
        organization_id: str,
    ) -> list[CanvasOAuthConnection]:
        return sorted(
            [
                connection
                for connection in self._canvas_oauth_connections.values()
                if connection.organization_id == organization_id
            ],
            key=lambda connection: connection.created_at,
        )

    async def mark_canvas_oauth_reauthorization_required(
        self,
        organization_id: str,
        platform_id: str,
        *,
        expected_updated_at: datetime,
    ) -> CanvasOAuthConnection | None:
        connection = await self.get_canvas_oauth_connection(organization_id, platform_id)
        if connection is None or connection.updated_at != expected_updated_at:
            return None
        connection.status = CanvasOAuthConnectionStatus.REAUTHORIZATION_REQUIRED
        connection.reauthorization_required = True
        connection.refresh_lease_owner = None
        connection.refresh_lease_expires_at = None
        connection.updated_at = datetime.now(UTC)
        return connection

    async def acquire_canvas_oauth_refresh_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        connection = await self.get_canvas_oauth_connection(organization_id, platform_id)
        now = datetime.now(UTC)
        if connection is None:
            return None
        if (
            connection.status != CanvasOAuthConnectionStatus.CONNECTED
            or connection.reauthorization_required
        ):
            return None
        lease_active = (
            connection.refresh_lease_owner is not None
            and connection.refresh_lease_expires_at is not None
            and connection.refresh_lease_expires_at > now
        )
        if lease_active and connection.refresh_lease_owner != lease_owner:
            return None
        connection.refresh_lease_owner = lease_owner
        connection.refresh_lease_expires_at = now + timedelta(seconds=max(30, lease_seconds))
        connection.updated_at = now
        return connection

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
        connection = await self.get_canvas_oauth_connection(organization_id, platform_id)
        now = datetime.now(UTC)
        if (
            connection is None
            or connection.refresh_lease_owner != lease_owner
            or connection.refresh_lease_expires_at is None
            or connection.refresh_lease_expires_at <= now
        ):
            return None
        connection.access_token_secret_ref = access_token_secret_ref
        if refresh_token_secret_ref is not None:
            connection.refresh_token_secret_ref = refresh_token_secret_ref
        connection.token_expires_at = token_expires_at
        connection.status = CanvasOAuthConnectionStatus.CONNECTED
        connection.reauthorization_required = False
        connection.refresh_lease_owner = None
        connection.refresh_lease_expires_at = None
        connection.last_refreshed_at = now
        connection.updated_at = now
        return connection

    async def release_canvas_oauth_refresh_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        reauthorization_required: bool = False,
    ) -> bool:
        connection = await self.get_canvas_oauth_connection(organization_id, platform_id)
        if connection is None or connection.refresh_lease_owner != lease_owner:
            return False
        connection.refresh_lease_owner = None
        connection.refresh_lease_expires_at = None
        if reauthorization_required:
            connection.status = CanvasOAuthConnectionStatus.REAUTHORIZATION_REQUIRED
            connection.reauthorization_required = True
        connection.updated_at = datetime.now(UTC)
        return True

    async def list_canvas_oauth_revocation_retries(
        self,
        *,
        limit: int = 100,
    ) -> list[CanvasOAuthConnection]:
        now = datetime.now(UTC)
        return sorted(
            [
                connection
                for connection in self._canvas_oauth_connections.values()
                if connection.status == CanvasOAuthConnectionStatus.REVOCATION_PENDING
                and (connection.revoke_retry_at is None or connection.revoke_retry_at <= now)
                and (
                    connection.refresh_lease_owner is None
                    or connection.refresh_lease_expires_at is None
                    or connection.refresh_lease_expires_at <= now
                )
            ],
            key=lambda connection: connection.revoke_retry_at or connection.created_at,
        )[:limit]

    async def begin_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        expected_updated_at: datetime,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        connection = await self.get_canvas_oauth_connection(organization_id, platform_id)
        if connection is None or connection.updated_at != expected_updated_at:
            return None
        now = datetime.now(UTC)
        if (
            connection.refresh_lease_owner is not None
            and connection.refresh_lease_expires_at is not None
            and connection.refresh_lease_expires_at > now
        ):
            return None
        connection.status = CanvasOAuthConnectionStatus.REVOCATION_PENDING
        connection.reauthorization_required = False
        connection.revoke_retry_at = None
        connection.revoke_last_error_code = None
        connection.refresh_lease_owner = lease_owner
        connection.refresh_lease_expires_at = now + timedelta(seconds=max(30, lease_seconds))
        connection.updated_at = now
        return connection

    async def acquire_canvas_oauth_revocation_lease(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> CanvasOAuthConnection | None:
        connection = await self.get_canvas_oauth_connection(organization_id, platform_id)
        now = datetime.now(UTC)
        if (
            connection is None
            or connection.status != CanvasOAuthConnectionStatus.REVOCATION_PENDING
            or (connection.revoke_retry_at is not None and connection.revoke_retry_at > now)
        ):
            return None
        if (
            connection.refresh_lease_owner is not None
            and connection.refresh_lease_owner != lease_owner
            and connection.refresh_lease_expires_at is not None
            and connection.refresh_lease_expires_at > now
        ):
            return None
        connection.refresh_lease_owner = lease_owner
        connection.refresh_lease_expires_at = now + timedelta(seconds=max(30, lease_seconds))
        connection.updated_at = now
        return connection

    async def reschedule_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
        retry_at: datetime,
        error_code: str,
    ) -> bool:
        connection = await self.get_canvas_oauth_connection(organization_id, platform_id)
        if (
            connection is None
            or connection.status != CanvasOAuthConnectionStatus.REVOCATION_PENDING
            or connection.refresh_lease_owner != lease_owner
        ):
            return False
        connection.revoke_retry_count += 1
        connection.revoke_retry_at = retry_at
        connection.revoke_last_error_code = str(error_code)[:120]
        connection.refresh_lease_owner = None
        connection.refresh_lease_expires_at = None
        connection.updated_at = datetime.now(UTC)
        return True

    async def complete_canvas_oauth_revocation(
        self,
        *,
        organization_id: str,
        platform_id: str,
        lease_owner: str,
    ) -> bool:
        connection = await self.get_canvas_oauth_connection(organization_id, platform_id)
        if (
            connection is None
            or connection.status != CanvasOAuthConnectionStatus.REVOCATION_PENDING
            or connection.refresh_lease_owner != lease_owner
        ):
            return False
        self._canvas_oauth_connections.pop((organization_id, platform_id), None)
        return True

    async def delete_canvas_oauth_connection(
        self,
        organization_id: str,
        platform_id: str,
    ) -> bool:
        return self._canvas_oauth_connections.pop((organization_id, platform_id), None) is not None

    async def save_canvas_sync_target(self, target: CanvasEvidenceSyncTarget) -> None:
        for existing_id, existing in list(self._canvas_sync_targets.items()):
            if (
                existing.organization_id == target.organization_id
                and existing.logical_key == target.logical_key
                and existing_id != target.id
            ):
                target.id = existing.id
                target.created_at = existing.created_at
                self._canvas_sync_targets.pop(existing_id)
                break
        target.updated_at = datetime.now(UTC)
        self._canvas_sync_targets[target.id] = target

    async def get_canvas_sync_target_for_org(
        self,
        organization_id: str,
        target_id: str,
    ) -> CanvasEvidenceSyncTarget | None:
        target = self._canvas_sync_targets.get(target_id)
        if target is None or target.organization_id != organization_id:
            return None
        return target

    async def get_canvas_sync_target_by_logical_key(
        self,
        organization_id: str,
        logical_key: str,
    ) -> CanvasEvidenceSyncTarget | None:
        for target in self._canvas_sync_targets.values():
            if target.organization_id == organization_id and target.logical_key == logical_key:
                return target
        return None

    async def touch_canvas_sync_target_worker_heartbeat(
        self,
        *,
        organization_id: str,
        target_id: str,
        expected_config_version: int,
        worker_id: str,
        heartbeat_at: datetime,
    ) -> bool:
        target = self._canvas_sync_targets.get(target_id)
        if (
            target is None
            or target.organization_id != organization_id
            or target.config_version != expected_config_version
            or not target.enabled
        ):
            return False
        target.metadata = {
            **(target.metadata if isinstance(target.metadata, dict) else {}),
            "worker_id": worker_id,
            "worker_heartbeat_at": heartbeat_at.isoformat(),
        }
        target.updated_at = heartbeat_at
        return True

    async def mark_canvas_sync_target_succeeded(
        self,
        *,
        organization_id: str,
        target_id: str,
        expected_config_version: int,
        succeeded_at: datetime,
    ) -> bool:
        target = self._canvas_sync_targets.get(target_id)
        if (
            target is None
            or target.organization_id != organization_id
            or target.config_version != expected_config_version
            or not target.enabled
        ):
            return False
        target.last_succeeded_at = succeeded_at
        target.updated_at = succeeded_at
        return True

    async def enqueue_canvas_sync_job(
        self,
        target: CanvasEvidenceSyncTarget,
        *,
        available_at: datetime | None = None,
    ) -> CanvasEvidenceSyncJob:
        active = {
            CanvasEvidenceSyncJobStatus.QUEUED,
            CanvasEvidenceSyncJobStatus.LEASED,
            CanvasEvidenceSyncJobStatus.RETRY,
        }
        for job in self._canvas_sync_jobs.values():
            if job.target_id == target.id and job.status in active:
                return job
        job = CanvasEvidenceSyncJob(
            organization_id=target.organization_id,
            target_id=target.id,
            available_at=available_at or datetime.now(UTC),
        )
        self._canvas_sync_jobs[job.id] = job
        target.last_enqueued_at = datetime.now(UTC)
        return job

    async def enqueue_due_canvas_sync_jobs(self, *, limit: int = 100) -> list[CanvasEvidenceSyncJob]:
        now = datetime.now(UTC)
        due = sorted(
            [target for target in self._canvas_sync_targets.values() if target.enabled and target.next_run_at <= now],
            key=lambda target: target.next_run_at,
        )[:limit]
        jobs: list[CanvasEvidenceSyncJob] = []
        for target in due:
            before = set(self._canvas_sync_jobs)
            job = await self.enqueue_canvas_sync_job(target, available_at=now)
            if job.id not in before:
                jobs.append(job)
            target.next_run_at = now + timedelta(seconds=max(60, target.schedule_seconds))
            target.updated_at = now
        return jobs

    async def lease_canvas_sync_jobs(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 120,
    ) -> list[CanvasEvidenceSyncJob]:
        now = datetime.now(UTC)
        for job in self._canvas_sync_jobs.values():
            if (
                job.status == CanvasEvidenceSyncJobStatus.LEASED
                and job.lease_expires_at is not None
                and job.lease_expires_at <= now
            ):
                if job.attempt_count >= job.max_attempts:
                    job.status = CanvasEvidenceSyncJobStatus.DEAD_LETTER
                    job.last_error_code = "canvas_worker_lease_expired"
                    job.last_error_summary = "Canvas worker lease expired on final attempt"
                    job.completed_at = now
                    target = self._canvas_sync_targets.get(job.target_id)
                    if target is not None and target.organization_id == job.organization_id:
                        target.enabled = False
                        target.updated_at = now
                else:
                    job.status = CanvasEvidenceSyncJobStatus.RETRY
                    exponent = min(max(job.attempt_count - 1, 0), 10)
                    base_delay = min(3600, 15 * (2**exponent))
                    jitter = secrets.randbelow(max(1, base_delay // 3 + 1))
                    job.available_at = now + timedelta(seconds=base_delay + jitter)
                    job.last_error_code = "canvas_worker_lease_expired"
                    job.last_error_summary = "Canvas worker lease expired before completion"
                job.lease_owner = None
                job.lease_expires_at = None
                job.updated_at = now
        ready = sorted(
            [
                job
                for job in self._canvas_sync_jobs.values()
                if job.status in {CanvasEvidenceSyncJobStatus.QUEUED, CanvasEvidenceSyncJobStatus.RETRY}
                and job.available_at <= now
                and job.attempt_count < job.max_attempts
            ],
            key=lambda job: (job.available_at, job.created_at),
        )[:limit]
        for job in ready:
            job.status = CanvasEvidenceSyncJobStatus.LEASED
            job.attempt_count += 1
            job.lease_owner = worker_id
            job.lease_expires_at = now + timedelta(seconds=max(30, lease_seconds))
            job.started_at = job.started_at or now
            job.updated_at = now
        return ready

    async def save_canvas_sync_job(self, job: CanvasEvidenceSyncJob) -> None:
        job.updated_at = datetime.now(UTC)
        self._canvas_sync_jobs[job.id] = job

    async def save_canvas_sync_job_if_leased(
        self,
        job: CanvasEvidenceSyncJob,
        *,
        worker_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        current = self._canvas_sync_jobs.get(job.id)
        if (
            current is None
            or current.organization_id != job.organization_id
            or current.status != CanvasEvidenceSyncJobStatus.LEASED
            or current.lease_owner != worker_id
            or current.lease_expires_at is None
            or current.lease_expires_at <= now
            or current.attempt_count != job.attempt_count
        ):
            return False
        job.updated_at = now
        self._canvas_sync_jobs[job.id] = job
        if job.status == CanvasEvidenceSyncJobStatus.DEAD_LETTER:
            target = self._canvas_sync_targets.get(job.target_id)
            if target is not None and target.organization_id == job.organization_id:
                target.enabled = False
                target.updated_at = now
        return True

    async def retry_canvas_sync_job_from_dead_letter(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        job = self._canvas_sync_jobs.get(job_id)
        if (
            job is None
            or job.organization_id != organization_id
            or job.status != CanvasEvidenceSyncJobStatus.DEAD_LETTER
        ):
            return None
        now = datetime.now(UTC)
        target = self._canvas_sync_targets.get(job.target_id)
        if target is None or target.organization_id != organization_id:
            return None
        target.enabled = True
        target.updated_at = now
        job.status = CanvasEvidenceSyncJobStatus.QUEUED
        job.attempt_count = 0
        job.max_attempts = 8
        job.available_at = now
        job.lease_owner = None
        job.lease_expires_at = None
        job.last_error_code = None
        job.last_error_summary = None
        job.result = {}
        job.completed_at = None
        job.updated_at = now
        return job

    async def resolve_canvas_sync_job_dead_letter(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        job = self._canvas_sync_jobs.get(job_id)
        if (
            job is None
            or job.organization_id != organization_id
            or job.status != CanvasEvidenceSyncJobStatus.DEAD_LETTER
        ):
            return None
        now = datetime.now(UTC)
        job.status = CanvasEvidenceSyncJobStatus.CANCELLED
        job.updated_at = now
        job.completed_at = job.completed_at or now
        return job

    async def get_canvas_sync_job_for_org(
        self,
        organization_id: str,
        job_id: str,
    ) -> CanvasEvidenceSyncJob | None:
        job = self._canvas_sync_jobs.get(job_id)
        if job is None or job.organization_id != organization_id:
            return None
        return job

    async def list_canvas_sync_jobs(
        self,
        organization_id: str,
        *,
        target_id: str | None = None,
        status: CanvasEvidenceSyncJobStatus | None = None,
        limit: int = 100,
    ) -> list[CanvasEvidenceSyncJob]:
        jobs = [job for job in self._canvas_sync_jobs.values() if job.organization_id == organization_id]
        if target_id is not None:
            jobs = [job for job in jobs if job.target_id == target_id]
        if status is not None:
            jobs = [job for job in jobs if job.status == status]
        return sorted(jobs, key=lambda job: job.created_at, reverse=True)[:limit]

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
        targets = {
            target.id: target
            for target in self._canvas_sync_targets.values()
            if target.organization_id == organization_id
            and target.platform_id == platform_id
            and target.binding_id == binding_id
        }
        dead_lettered = any(
            job.organization_id == organization_id
            and job.target_id in targets
            and job.status == CanvasEvidenceSyncJobStatus.DEAD_LETTER
            for job in self._canvas_sync_jobs.values()
        )
        active_statuses = {
            CanvasEvidenceSyncJobStatus.QUEUED,
            CanvasEvidenceSyncJobStatus.LEASED,
            CanvasEvidenceSyncJobStatus.RETRY,
        }
        stale_active_job = any(
            job.organization_id == organization_id
            and job.target_id in targets
            and job.status in active_statuses
            and (evaluated_at - job.created_at).total_seconds()
            > 2 * max(60, targets[job.target_id].schedule_seconds)
            for job in self._canvas_sync_jobs.values()
        )
        stale_due_target = any(
            target.enabled
            and (evaluated_at - target.next_run_at).total_seconds()
            > 2 * max(60, target.schedule_seconds)
            for target in targets.values()
        )
        return CanvasSyncReadinessState(
            dead_lettered=dead_lettered,
            stale_backlog=stale_active_job or stale_due_target,
        )

    async def upsert_canvas_worker_heartbeat(self, heartbeat: CanvasWorkerHeartbeat) -> None:
        existing = self._canvas_worker_heartbeats.get(heartbeat.worker_id)
        if existing is not None:
            heartbeat.started_at = existing.started_at
        self._canvas_worker_heartbeats[heartbeat.worker_id] = heartbeat

    async def get_fresh_canvas_worker_heartbeat(
        self,
        *,
        role: str = "canvas_sync",
        max_age_seconds: int = 120,
    ) -> CanvasWorkerHeartbeat | None:
        fresh_after = datetime.now(UTC) - timedelta(seconds=max(1, max_age_seconds))
        heartbeats = [
            heartbeat
            for heartbeat in self._canvas_worker_heartbeats.values()
            if heartbeat.role == role and heartbeat.last_heartbeat_at >= fresh_after
        ]
        if not heartbeats:
            return None
        return max(heartbeats, key=lambda heartbeat: heartbeat.last_heartbeat_at)

    async def list_canvas_worker_heartbeats(
        self,
        *,
        role: str | None = None,
    ) -> list[CanvasWorkerHeartbeat]:
        return sorted(
            [
                heartbeat
                for heartbeat in self._canvas_worker_heartbeats.values()
                if role is None or heartbeat.role == role
            ],
            key=lambda heartbeat: heartbeat.last_heartbeat_at,
            reverse=True,
        )

    async def save_canvas_award_candidate(self, candidate: CanvasAwardCandidate) -> None:
        for existing_id, existing in list(self._canvas_award_candidates.items()):
            if (
                existing.binding_id == candidate.binding_id
                and existing.candidate_key == candidate.candidate_key
                and existing_id != candidate.id
            ):
                candidate.id = existing.id
                candidate.created_at = existing.created_at
                self._canvas_award_candidates.pop(existing_id)
                break
        candidate.updated_at = datetime.now(UTC)
        self._canvas_award_candidates[candidate.id] = candidate

    async def get_canvas_award_candidate_for_org(
        self,
        organization_id: str,
        candidate_id: str,
    ) -> CanvasAwardCandidate | None:
        candidate = self._canvas_award_candidates.get(candidate_id)
        if candidate is None or candidate.organization_id != organization_id:
            return None
        return candidate

    async def list_canvas_award_candidates(
        self,
        organization_id: str,
        *,
        state: CanvasAwardCandidateState | None = None,
        binding_id: str | None = None,
        limit: int = 100,
    ) -> list[CanvasAwardCandidate]:
        candidates = [
            candidate
            for candidate in self._canvas_award_candidates.values()
            if candidate.organization_id == organization_id
        ]
        if state is not None:
            candidates = [candidate for candidate in candidates if candidate.state == state]
        if binding_id is not None:
            candidates = [candidate for candidate in candidates if candidate.binding_id == binding_id]
        return sorted(candidates, key=lambda candidate: candidate.updated_at, reverse=True)[:limit]

    async def save_canvas_candidate_observation(
        self,
        observation: CanvasCandidateObservation,
    ) -> tuple[CanvasCandidateObservation, bool]:
        candidate = self._canvas_award_candidates.get(observation.candidate_id)
        if candidate is None or candidate.organization_id != observation.organization_id:
            raise ValueError("Canvas award candidate was not found for this organization")
        current = next(
            (
                item
                for item in self._canvas_candidate_observations.values()
                if item.candidate_id == observation.candidate_id
                and item.logical_key == observation.logical_key
                and item.is_current
            ),
            None,
        )
        if current is not None and current.payload_hash == observation.payload_hash:
            return current, False
        if current is not None:
            current.is_current = False
            observation.superseded_observation_id = current.id
        self._canvas_candidate_observations[observation.id] = observation
        return observation, True

    async def list_current_canvas_candidate_observations(
        self,
        organization_id: str,
        candidate_id: str,
    ) -> list[CanvasCandidateObservation]:
        return sorted(
            [
                observation
                for observation in self._canvas_candidate_observations.values()
                if observation.organization_id == organization_id
                and observation.candidate_id == candidate_id
                and observation.is_current
            ],
            key=lambda observation: observation.requirement_id,
        )

    async def save_evidence_policy_review(self, review: EvidencePolicyReview) -> None:
        review.updated_at = datetime.now(UTC)
        self._evidence_policy_reviews[review.id] = review

    async def get_open_evidence_policy_review(
        self,
        organization_id: str,
        application_id: str,
    ) -> EvidencePolicyReview | None:
        for review in self._evidence_policy_reviews.values():
            if (
                review.organization_id == organization_id
                and review.application_id == application_id
                and review.status == EvidencePolicyReviewStatus.OPEN
            ):
                return review
        return None

    async def claim_evidence_policy_review_resolution(
        self,
        organization_id: str,
        review_id: str,
        *,
        claim_token: str,
        action: str,
    ) -> EvidencePolicyReview | None:
        review = self._evidence_policy_reviews.get(review_id)
        if review is None or review.organization_id != organization_id:
            return None
        lock = self._application_evidence_locks.setdefault(review.application_id, asyncio.Lock())
        async with lock:
            review = self._evidence_policy_reviews.get(review_id)
            if (
                review is None
                or review.organization_id != organization_id
                or review.status != EvidencePolicyReviewStatus.OPEN
                or review.resolution_claim_token is not None
            ):
                return None
            now = datetime.now(UTC)
            review.resolution_claim_token = claim_token
            review.resolution_claim_action = action
            review.resolution_claimed_at = now
            review.updated_at = now
            return copy.deepcopy(review)

    async def release_evidence_policy_review_resolution(
        self,
        organization_id: str,
        review_id: str,
        *,
        claim_token: str,
    ) -> bool:
        review = self._evidence_policy_reviews.get(review_id)
        if review is None or review.organization_id != organization_id:
            return False
        lock = self._application_evidence_locks.setdefault(review.application_id, asyncio.Lock())
        async with lock:
            review = self._evidence_policy_reviews.get(review_id)
            if (
                review is None
                or review.organization_id != organization_id
                or review.status != EvidencePolicyReviewStatus.OPEN
                or review.resolution_claim_token != claim_token
            ):
                return False
            review.resolution_claim_token = None
            review.resolution_claim_action = None
            review.resolution_claimed_at = None
            review.updated_at = datetime.now(UTC)
            return True

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
        review = self._evidence_policy_reviews.get(review_id)
        if review is None or review.organization_id != organization_id:
            return None
        lock = self._application_evidence_locks.setdefault(review.application_id, asyncio.Lock())
        async with lock:
            review = self._evidence_policy_reviews.get(review_id)
            if (
                review is None
                or review.organization_id != organization_id
                or review.status != EvidencePolicyReviewStatus.OPEN
                or review.resolution_claim_token != claim_token
                or review.resolution_claim_action != resolution_action
            ):
                return None
            if audit_event.application_id != review.application_id:
                raise ValueError("Evidence review audit event does not belong to the application")
            review.status = status
            review.resolution_action = resolution_action
            review.resolution_notes = resolution_notes
            review.resolved_by = resolved_by
            review.resolved_at = resolved_at
            review.resolution_claim_token = None
            review.resolution_claim_action = None
            review.resolution_claimed_at = None
            review.resolution_recovery_pending = False
            review.updated_at = resolved_at
            self._events.append(audit_event)
            return copy.deepcopy(review)

    async def get_evidence_policy_review_for_org(
        self,
        organization_id: str,
        review_id: str,
    ) -> EvidencePolicyReview | None:
        review = self._evidence_policy_reviews.get(review_id)
        if review is None or review.organization_id != organization_id:
            return None
        return review

    async def list_evidence_policy_reviews(
        self,
        organization_id: str,
        *,
        status: EvidencePolicyReviewStatus | None = None,
        limit: int = 100,
    ) -> list[EvidencePolicyReview]:
        reviews = [
            review
            for review in self._evidence_policy_reviews.values()
            if review.organization_id == organization_id
            and (status is None or review.status == status)
        ]
        return sorted(reviews, key=lambda review: review.created_at, reverse=True)[:limit]

    async def save_integration_secret(self, secret: OrganizationIntegrationSecret) -> None:
        existing = self._integration_secrets.get(secret.id)
        if existing is not None:
            secret.created_at = existing.created_at
            if not secret.secret_value:
                secret.secret_value = existing.secret_value
        secret.updated_at = datetime.now(UTC)
        if not secret.secret_hint and secret.secret_value:
            secret.secret_hint = f"...{secret.secret_value[-4:]}"
        self._integration_secrets[secret.id] = secret

    async def get_integration_secret(self, secret_id: str) -> OrganizationIntegrationSecret | None:
        secret = self._integration_secrets.get(secret_id)
        if secret is None:
            return None
        return OrganizationIntegrationSecret(
            id=secret.id,
            organization_id=secret.organization_id,
            name=secret.name,
            provider=secret.provider,
            purpose=secret.purpose,
            secret_value="",
            secret_hint=secret.secret_hint,
            metadata=dict(secret.metadata or {}),
            enabled=secret.enabled,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            last_used_at=secret.last_used_at,
        )

    async def list_integration_secrets(
        self,
        organization_id: str,
        provider: str | None = None,
    ) -> list[OrganizationIntegrationSecret]:
        secrets = [
            secret
            for secret in self._integration_secrets.values()
            if secret.organization_id == organization_id
            and (provider is None or secret.provider == provider)
        ]
        return sorted(
            [
                OrganizationIntegrationSecret(
                    id=secret.id,
                    organization_id=secret.organization_id,
                    name=secret.name,
                    provider=secret.provider,
                    purpose=secret.purpose,
                    secret_value="",
                    secret_hint=secret.secret_hint,
                    metadata=dict(secret.metadata or {}),
                    enabled=secret.enabled,
                    created_at=secret.created_at,
                    updated_at=secret.updated_at,
                    last_used_at=secret.last_used_at,
                )
                for secret in secrets
            ],
            key=lambda secret: secret.created_at,
        )

    async def get_integration_secret_value(self, organization_id: str, secret_id: str) -> str | None:
        secret = self._integration_secrets.get(secret_id)
        if secret is None or secret.organization_id != organization_id or not secret.enabled:
            return None
        secret.last_used_at = datetime.now(UTC)
        return secret.secret_value

    async def delete_integration_secret(self, secret_id: str) -> None:
        self._integration_secrets.pop(secret_id, None)

    async def save_canvas_lti_launch_state(self, launch_state: CanvasLtiLaunchState) -> None:
        self._canvas_lti_launch_states[launch_state.state] = launch_state

    async def get_canvas_lti_launch_state(self, state: str) -> CanvasLtiLaunchState | None:
        return self._canvas_lti_launch_states.get(state)

    async def consume_canvas_lti_launch_state(self, state: str) -> CanvasLtiLaunchState | None:
        launch_state = self._canvas_lti_launch_states.get(state)
        if launch_state is None or launch_state.status != "pending" or launch_state.is_expired:
            return None
        launch_state.mark_consumed()
        self._canvas_lti_launch_states[state] = launch_state
        return launch_state

    async def get_credential_types_for_org(self, org_id: str) -> list[str]:
        seen: set[str] = set()
        for tx in self._transactions.values():
            if tx.organization_id == org_id and tx.credential_type:
                seen.add(tx.credential_type)
        return sorted(seen)

    async def get_credential_type_formats_for_org(self, org_id: str) -> list[tuple[str, list[str]]]:
        seen: set[str] = set()
        for tx in self._transactions.values():
            if tx.organization_id == org_id and tx.credential_type:
                seen.add(tx.credential_type)
        return [(ct, []) for ct in sorted(seen)]

    async def get_credential_display_metadata_for_org(self, org_id: str) -> dict[str, dict[str, object]]:
        return {
            credential_type: {
                "name": credential_type,
                "description": None,
                "claims": [],
                "display_style": {},
            }
            for credential_type, _formats in await self.get_credential_type_formats_for_org(org_id)
        }

    async def save_authorization_session(self, auth_session: AuthorizationSession) -> None:
        self._authorization_sessions[auth_session.id] = auth_session

    async def get_authorization_session_by_code(self, code: str) -> AuthorizationSession | None:
        for auth_session in self._authorization_sessions.values():
            if auth_session.code == code:
                return auth_session
        return None

    async def get_authorization_session_by_access_token(self, token: str) -> AuthorizationSession | None:
        import hmac as _hmac

        for auth_session in self._authorization_sessions.values():
            if auth_session.access_token and _hmac.compare_digest(auth_session.access_token, token):
                return auth_session
        return None

    async def get_retention_summary(self, org_id: str, retention_days: int) -> dict[str, object]:
        cutoff_at = datetime.now(UTC) - timedelta(days=retention_days)
        expired_transactions = [tx for tx in self._transactions.values() if tx.organization_id == org_id and tx.created_at < cutoff_at]
        expired_applications = [app for app in self._applications.values() if app.organization_id == org_id and app.created_at < cutoff_at]
        expired_auth_sessions = [session for session in self._authorization_sessions.values() if session.organization_id == org_id and session.created_at < cutoff_at]
        expired_events = [event for event in self._events if self._event_belongs_to_org(event, org_id) and event.created_at < cutoff_at]
        expired_credentials = [
            credential for credential in self._credentials.values()
            if credential.organization_id == org_id and credential.transaction_id in {tx.id for tx in expired_transactions}
        ]

        retained_candidates = [
            tx.created_at for tx in self._transactions.values()
            if tx.organization_id == org_id and tx.created_at >= cutoff_at
        ]
        retained_candidates.extend(
            app.created_at for app in self._applications.values()
            if app.organization_id == org_id and app.created_at >= cutoff_at
        )
        retained_candidates.extend(
            session.created_at for session in self._authorization_sessions.values()
            if session.organization_id == org_id and session.created_at >= cutoff_at
        )
        retained_candidates.extend(
            event.created_at for event in self._events
            if self._event_belongs_to_org(event, org_id) and event.created_at >= cutoff_at
        )

        oldest_retained_record_at = min(retained_candidates) if retained_candidates else None
        next_expiry_at = (
            oldest_retained_record_at + timedelta(days=retention_days)
            if oldest_retained_record_at else None
        )

        eligible_for_purge = {
            "issuance_transactions": len(expired_transactions),
            "applications": len(expired_applications),
            "authorization_sessions": len(expired_auth_sessions),
            "issuance_events": len(expired_events),
            "issued_credentials": len(expired_credentials),
        }
        eligible_for_purge["total"] = sum(eligible_for_purge.values())

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

    async def purge_retention_records(self, org_id: str, retention_days: int) -> dict[str, object]:
        summary = await self.get_retention_summary(org_id, retention_days)
        cutoff_at = datetime.fromisoformat(str(summary["cutoff_at"]))
        expired_transaction_ids = {
            tx.id for tx in self._transactions.values()
            if tx.organization_id == org_id and tx.created_at < cutoff_at
        }
        expired_credential_ids = {
            credential.id for credential in self._credentials.values()
            if credential.organization_id == org_id and credential.transaction_id in expired_transaction_ids
        }

        self._events = [
            event for event in self._events
            if not (self._event_belongs_to_org(event, org_id) and event.created_at < cutoff_at)
        ]
        self._authorization_sessions = {
            key: value for key, value in self._authorization_sessions.items()
            if not (value.organization_id == org_id and value.created_at < cutoff_at)
        }
        self._applications = {
            key: value for key, value in self._applications.items()
            if not (value.organization_id == org_id and value.created_at < cutoff_at)
        }
        self._credentials = {
            key: value for key, value in self._credentials.items()
            if not (value.organization_id == org_id and value.transaction_id in expired_transaction_ids)
        }
        self._delivery_records = {
            key: value for key, value in self._delivery_records.items()
            if not (
                value.organization_id == org_id
                and (
                    value.transaction_id in expired_transaction_ids
                    or value.credential_id in expired_credential_ids
                )
            )
        }
        self._evidence_facts = {
            key: value for key, value in self._evidence_facts.items()
            if value.organization_id != org_id or value.application_id in self._applications
        }
        self._transactions = {
            key: value for key, value in self._transactions.items()
            if not (value.organization_id == org_id and value.created_at < cutoff_at)
        }

        post_purge = await self.get_retention_summary(org_id, retention_days)
        return {
            "organization_id": org_id,
            "retention_days": retention_days,
            "cutoff_at": summary["cutoff_at"],
            "purged_at": datetime.now(UTC).isoformat(),
            "purged_records": summary["eligible_for_purge"],
            "next_expiry_at": post_purge["next_expiry_at"],
            "oldest_retained_record_at": post_purge["oldest_retained_record_at"],
            "tracked_scope": summary["tracked_scope"],
        }

    def _event_belongs_to_org(self, event: IssuanceEvent, org_id: str) -> bool:
        if event.transaction_id:
            tx = self._transactions.get(event.transaction_id)
            if tx and tx.organization_id == org_id:
                return True
        if event.application_id:
            app = self._applications.get(event.application_id)
            if app and app.organization_id == org_id:
                return True
        return False
