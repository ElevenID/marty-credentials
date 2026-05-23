"""In-memory repository adapter for development."""

from datetime import datetime, timedelta, timezone

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
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.domain.ports import IIssuanceRepository


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
        self._credentials: dict[str, IssuedCredential] = {}
        self._applications: dict[str, Application] = {}
        self._application_templates: dict[str, ApplicationTemplate] = {}
        self._authorization_sessions: dict[str, AuthorizationSession] = {}
        self._canvas_event_receipts: dict[tuple[str | None, str], CanvasEventReceipt] = {}
        self._canvas_lti_launch_states: dict[str, CanvasLtiLaunchState] = {}
        self._canvas_platforms: dict[str, CanvasPlatform] = {}
        self._canvas_program_bindings: dict[str, CanvasProgramBinding] = {}
        self._delivery_records: dict[str, CredentialDeliveryRecord] = {}
        self._evidence_facts: dict[str, EvidenceFact] = {}
        self._approval_policy_sets: dict[tuple[str, str], ApprovalPolicySet] = {}
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
        import hmac as _hmac
        for tx in self._transactions.values():
            if tx.access_token and _hmac.compare_digest(tx.access_token, token):
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

    async def save_delivery_record(self, record: CredentialDeliveryRecord) -> None:
        existing = self._delivery_records.get(record.id)
        if existing is not None:
            record.created_at = existing.created_at
        record.updated_at = datetime.now(timezone.utc)
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
        self._evidence_facts[fact.id] = fact

    async def list_evidence_facts_for_application(self, application_id: str) -> list[EvidenceFact]:
        return sorted(
            [
                fact
                for fact in self._evidence_facts.values()
                if fact.application_id == application_id
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
        platform.updated_at = datetime.now(timezone.utc)
        self._canvas_platforms[platform.id] = platform

    async def get_canvas_platform(self, platform_id: str) -> CanvasPlatform | None:
        return self._canvas_platforms.get(platform_id)

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

    async def delete_canvas_platform(self, platform_id: str) -> None:
        self._canvas_platforms.pop(platform_id, None)
        self._canvas_program_bindings = {
            binding_id: binding
            for binding_id, binding in self._canvas_program_bindings.items()
            if binding.platform_id != platform_id
        }

    async def save_canvas_program_binding(self, binding: CanvasProgramBinding) -> None:
        binding.updated_at = datetime.now(timezone.utc)
        self._canvas_program_bindings[binding.id] = binding

    async def get_canvas_program_binding(self, binding_id: str) -> CanvasProgramBinding | None:
        return self._canvas_program_bindings.get(binding_id)

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

    async def delete_canvas_program_binding(self, binding_id: str) -> None:
        self._canvas_program_bindings.pop(binding_id, None)

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
        cutoff_at = datetime.now(timezone.utc) - timedelta(days=retention_days)
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
            "purged_at": datetime.now(timezone.utc).isoformat(),
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
