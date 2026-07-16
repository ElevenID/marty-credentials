"""Unit tests for the Canvas credential issuance adapter."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time

import pytest
from fastapi import HTTPException

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_SERVICES = os.path.join(_REPO_ROOT, "services")
_PYTHON = os.path.join(_REPO_ROOT, "python")
_MARTY_COMMON_PACKAGES = os.path.join(os.path.dirname(_REPO_ROOT), "marty-ui", "packages")

for _path in (_SERVICES, _PYTHON):
    if _path not in sys.path:
        sys.path.insert(0, _path)
if os.path.isdir(_MARTY_COMMON_PACKAGES) and _MARTY_COMMON_PACKAGES not in sys.path:
    sys.path.insert(0, _MARTY_COMMON_PACKAGES)

from issuance.infrastructure.adapters.canvas_credentials_adapter import (
    CanvasAgsScoreEvent,
    CanvasEvidenceEvent,
    CanvasNrpsMembershipEvent,
    map_canvas_ags_score_to_evidence_event,
    map_canvas_nrps_membership_to_evidence_event,
    map_canvas_event_to_mip_evidence_receipt,
    process_canvas_ags_score_event,
    process_canvas_evidence_event,
    process_canvas_nrps_membership_event,
    publish_canvas_credential_mirror,
    sync_canvas_credential_status,
    validate_canvas_credentials_config,
    verify_canvas_signature,
)
from issuance.infrastructure.api.application_routes import get_application_evidence_summary
from issuance.infrastructure.api.canvas_routes import get_canvas_evidence_event_status
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.application.evidence_policy import EvidencePolicyDecision
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    ApprovalPolicySet,
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    CredentialStatus,
    CanvasPlatform,
    CanvasProgramBinding,
    DeliveryTarget,
    IssuanceTransaction,
    IssuedCredential,
)


CANVAS_SECRET = "canvas-test-secret"


@pytest.fixture(autouse=True)
def _enable_portable_canvas_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv(
        "CANVAS_PILOT_ORGANIZATION_IDS",
        "org-123,org-from-binding,org-from-connector",
    )


def _sample_event(**overrides) -> dict[str, object]:
    payload: dict[str, object] = {
        "canvas_event_id": "evt-123",
        "organization_id": "org-123",
        "credential_template_id": "tmpl-456",
        "canvas_account_id": "acct-1",
        "canvas_course_id": "course-42",
        "canvas_course_name": "Introduction to Portable Trust",
        "canvas_enrollment_id": "enroll-9",
        "canvas_user_id": "user-7",
        "learner_email": "ada@example.com",
        "learner_given_name": "Ada",
        "learner_family_name": "Lovelace",
        "achievement_name": "Course Completion",
        "achievement_description": "Completed all required modules.",
        "completion_at": "2026-05-07T12:34:56Z",
    }
    payload.update(overrides)
    return payload


def _sample_ags_score_event(**overrides) -> dict[str, object]:
    payload: dict[str, object] = {
        "canvas_event_id": "ags-evt-123",
        "application_id": "app-ags-123",
        "organization_id": "org-123",
        "credential_template_id": "tmpl-456",
        "canvas_account_id": "acct-1",
        "canvas_course_id": "course-42",
        "canvas_course_name": "Introduction to Portable Trust",
        "canvas_user_id": "user-7",
        "canvas_enrollment_id": "enroll-9",
        "learner_email": "ada@example.com",
        "learner_given_name": "Ada",
        "learner_family_name": "Lovelace",
        "evidence_type": "canvas.assignment_score",
        "canvas_assignment_id": "assignment-9",
        "line_item_id": "assignment-9",
        "line_item_label": "Final project",
        "activity_progress": "Completed",
        "grading_progress": "FullyGraded",
        "score_given": 46,
        "score_maximum": 50,
        "graded_at": "2026-05-07T12:34:56Z",
    }
    payload.update(overrides)
    return payload


def _sample_nrps_membership_event(**overrides) -> dict[str, object]:
    payload: dict[str, object] = {
        "canvas_event_id": "nrps-evt-123",
        "application_id": "app-nrps-123",
        "organization_id": "org-123",
        "credential_template_id": "tmpl-456",
        "canvas_account_id": "acct-1",
        "canvas_course_id": "course-42",
        "canvas_course_name": "Introduction to Portable Trust",
        "canvas_user_id": "user-7",
        "canvas_enrollment_id": "enroll-9",
        "membership_id": "member-9",
        "learner_email": "ada@example.com",
        "learner_given_name": "Ada",
        "learner_family_name": "Lovelace",
        "roles": ["Learner"],
        "membership_status": "Active",
        "timestamp": "2026-05-07T12:34:56Z",
    }
    payload.update(overrides)
    return payload


def _sign_payload(raw_body: bytes, *, timestamp: str, secret: str = CANVAS_SECRET) -> str:
    digest = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def _save_canvas_program_binding(
    repo: InMemoryIssuanceRepository,
    *,
    canvas_account_id: str = "acct-1",
    organization_id: str = "org-from-connector",
    credential_template_id: str = "tmpl-from-connector",
    application_template_id: str,
    auto_approve_on_evidence: bool = False,
    evidence_requirements: list[object] | None = None,
    canvas_scope: dict[str, object] | None = None,
    approval_policy_set_id: str | None = None,
) -> tuple[CanvasPlatform, CanvasProgramBinding]:
    platform = CanvasPlatform(
        id=f"platform-{application_template_id}",
        organization_id=organization_id,
        canvas_account_id=canvas_account_id,
        display_name="Canvas Test Tenant",
    )
    binding = CanvasProgramBinding(
        id=f"binding-{application_template_id}",
        organization_id=organization_id,
        platform_id=platform.id,
        application_template_id=application_template_id,
        credential_template_id=credential_template_id,
        auto_approve_on_evidence=auto_approve_on_evidence,
        evidence_requirements=evidence_requirements or [],
        canvas_scope=canvas_scope or {},
        approval_policy_set_id=approval_policy_set_id,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    return platform, binding


class TestCanvasEventMapping:
    def test_map_canvas_event_to_mip_evidence_receipt_uses_application_primitive(self) -> None:
        event = CanvasEvidenceEvent.model_validate(_sample_event(application_id="app-123"))

        receipt = map_canvas_event_to_mip_evidence_receipt(event, payload_hash="payload-sha256")

        assert receipt.action == "applications:write"
        assert receipt.protocol == "SIGNED_EVIDENCE_RECEIPT"
        assert receipt.resource_type == "Application"
        assert receipt.organization_id == "org-123"
        assert receipt.application_id == "app-123"
        assert receipt.evidence_type == "canvas.course_completion"
        assert receipt.source.provider == "canvas"
        assert receipt.source.provider_event_id == "evt-123"
        assert receipt.source.payload_hash == "payload-sha256"
        assert receipt.evidence_data["canvas_course_id"] == "course-42"

    def test_map_canvas_ags_score_to_evidence_event(self) -> None:
        event = CanvasAgsScoreEvent.model_validate(_sample_ags_score_event())

        evidence = map_canvas_ags_score_to_evidence_event(event)

        assert evidence.canvas_event_id == "ags-evt-123"
        assert evidence.evidence_type == "canvas.assignment_score"
        assert evidence.canvas_assignment_id == "assignment-9"
        assert evidence.score == 46
        assert evidence.score_percent == 92
        assert evidence.completed is True
        assert evidence.submitted is True
        assert evidence.achievement_name == "Final project"

    def test_map_canvas_nrps_membership_to_evidence_event(self) -> None:
        event = CanvasNrpsMembershipEvent.model_validate(_sample_nrps_membership_event())

        evidence = map_canvas_nrps_membership_to_evidence_event(event)

        assert evidence.canvas_event_id == "nrps-evt-123"
        assert evidence.evidence_type == "canvas.nrps_membership"
        assert evidence.roles == ["Learner"]
        assert evidence.membership_status == "Active"
        assert evidence.eligible is True
        assert evidence.completed is True
        assert evidence.passed is True


class TestCanvasSignatureVerification:
    def test_verify_canvas_signature_accepts_valid_signature(self) -> None:
        raw_body = json.dumps(_sample_event(), separators=(",", ":")).encode("utf-8")
        now = int(time.time())
        timestamp = str(now)
        signature = _sign_payload(raw_body, timestamp=timestamp)

        assert verify_canvas_signature(
            raw_body=raw_body,
            timestamp=timestamp,
            signature=signature,
            secret=CANVAS_SECRET,
            now=now,
        ) is True

    def test_verify_canvas_signature_rejects_stale_timestamp(self) -> None:
        raw_body = json.dumps(_sample_event(), separators=(",", ":")).encode("utf-8")
        now = int(time.time())
        timestamp = str(now - 3600)
        signature = _sign_payload(raw_body, timestamp=timestamp)

        assert verify_canvas_signature(
            raw_body=raw_body,
            timestamp=timestamp,
            signature=signature,
            secret=CANVAS_SECRET,
            now=now,
            tolerance_seconds=300,
        ) is False

    def test_verify_canvas_signature_rejects_missing_secret(self) -> None:
        raw_body = json.dumps(_sample_event(), separators=(",", ":")).encode("utf-8")
        now = int(time.time())
        timestamp = str(now)
        signature = _sign_payload(raw_body, timestamp=timestamp)

        assert verify_canvas_signature(
            raw_body=raw_body,
            timestamp=timestamp,
            signature=signature,
            secret="",
            now=now,
        ) is False


class TestCanvasCredentialsRealApi:
    def _issued_credential(self) -> IssuedCredential:
        return IssuedCredential(
            id="cred-real-1",
            transaction_id="tx-real-1",
            organization_id="org-123",
            credential_template_id="tmpl-456",
            applicant_id="applicant-1",
            subject_did="did:key:zSubject",
            issuer_did="did:web:beta.elevenidllc.com:orgs:marty",
            credential_jwt="eyJhbGciOiJFZERTQSJ9.real.sig",
            credential_hash="hash-real-1",
            status=CredentialStatus.ACTIVE,
        )

    def _transaction(self) -> IssuanceTransaction:
        return IssuanceTransaction(
            id="tx-real-1",
            organization_id="org-123",
            credential_template_id="tmpl-456",
            applicant_id="applicant-1",
            application_id="app-real-1",
            issuer_did_override="did:web:beta.elevenidllc.com:orgs:marty",
            delivery_mode="wallet_plus_canvas_mirror",
            claims={
                "email": "learner@example.edu",
                "achievement_description": "Completed Canvas interoperability foundations.",
            },
        )

    def _platform(self) -> CanvasPlatform:
        return CanvasPlatform(
            id="platform-real-1",
            organization_id="org-123",
            canvas_account_id="canvas-account-1",
            canvas_base_url="https://canvas-test.elevenidllc.com",
        )

    def _delivery_record(self) -> CredentialDeliveryRecord:
        return CredentialDeliveryRecord(
            id="delivery-real-1",
            credential_id="cred-real-1",
            transaction_id="tx-real-1",
            organization_id="org-123",
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.PENDING,
            canvas_account_id="canvas-account-1",
            metadata={
                "canvas_platform_id": "platform-real-1",
                "canvas_program_binding_id": "binding-real-1",
            },
        )

    async def test_delivery_rejects_mixed_tenant_aggregates_before_provider_io(
        self,
    ) -> None:
        platform = self._platform()
        platform.organization_id = "org-foreign"

        with pytest.raises(RuntimeError, match="resources are unavailable"):
            await publish_canvas_credential_mirror(
                credential=self._issued_credential(),
                transaction=self._transaction(),
                platform=platform,
                delivery_record=self._delivery_record(),
            )
        with pytest.raises(RuntimeError, match="resources are unavailable"):
            await sync_canvas_credential_status(
                credential=self._issued_credential(),
                platform=platform,
                delivery_record=self._delivery_record(),
                lifecycle_action="suspend",
            )

    async def test_publish_posts_badgr_assertion_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from issuance.infrastructure.adapters import canvas_credentials_adapter

        monkeypatch.delenv("CANVAS_CREDENTIALS_PUBLISH_URL", raising=False)
        monkeypatch.setenv("CANVAS_CREDENTIALS_PROVIDER", "badgr_api")
        monkeypatch.setenv("CANVAS_CREDENTIALS_API_BASE_URL", "https://api.badgr.test")
        monkeypatch.setenv("CANVAS_CREDENTIALS_API_TOKEN", "real-token")
        monkeypatch.setenv("CANVAS_CREDENTIALS_ISSUER_ID", "issuer-entity-1")
        monkeypatch.setenv("CANVAS_CREDENTIALS_BADGECLASS_ID", "badgeclass-entity-1")
        monkeypatch.setenv("CANVAS_CREDENTIALS_PROVENANCE_BASE_URL", "https://beta.elevenidllc.com")

        captured: dict[str, object] = {}

        class FakeResponse:
            status_code = 201
            headers = {"x-request-id": "req-real-1"}
            text = "{}"

            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "result": [
                        {
                            "entityId": "assertion-entity-1",
                            "openBadgeId": "https://api.badgr.test/public/assertions/assertion-entity-1",
                            "issuer": "issuer-entity-1",
                        }
                    ]
                }

        class FakeClient:
            def __init__(self, *args, **kwargs):
                captured["timeout"] = kwargs.get("timeout")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, json=None, headers=None):
                captured["url"] = url
                captured["json"] = json
                captured["headers"] = headers
                return FakeResponse()

        monkeypatch.setattr(canvas_credentials_adapter, "canvas_http_client", FakeClient)

        result = await publish_canvas_credential_mirror(
            credential=self._issued_credential(),
            transaction=self._transaction(),
            platform=self._platform(),
            delivery_record=self._delivery_record(),
        )

        assert result.external_credential_id == "assertion-entity-1"
        assert result.external_issuer_id == "issuer-entity-1"
        assert result.metadata["provider"] == "badgr_api"
        assert result.metadata["badgeclass_id"] == "badgeclass-entity-1"
        assert result.metadata["credential_url"] == "https://api.badgr.test/public/assertions/assertion-entity-1"
        assert captured["url"] == "https://api.badgr.test/v2/badgeclasses/badgeclass-entity-1/assertions"
        assert captured["headers"] == {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer real-token",
        }
        payload = captured["json"]
        assert payload["recipient"] == {
            "identity": "learner@example.edu",
            "type": "email",
            "hashed": True,
        }
        assert payload["allowDuplicateAwards"] is False
        assert payload["evidence"][0]["url"].startswith("https://beta.elevenidllc.com/console/org/operate/verify?")
        assert payload["extensions"]["value"]["elevenid"]["credential_id"] == "cred-real-1"

    async def test_publish_can_use_delivery_record_canvas_credentials_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from issuance.infrastructure.adapters import canvas_credentials_adapter

        monkeypatch.setenv("CANVAS_CREDENTIALS_PROVIDER", "bridge")
        monkeypatch.setenv("CANVAS_CREDENTIALS_PUBLISH_URL", "https://bridge.example/publish")
        monkeypatch.setenv("CANVAS_CREDENTIALS_API_BASE_URL", "https://api.global.badgr.test")
        monkeypatch.setenv("CANVAS_CREDENTIALS_API_TOKEN", "global-token")
        monkeypatch.setenv("CANVAS_CREDENTIALS_BADGECLASS_ID", "global-badgeclass")
        monkeypatch.setenv("CANVAS_CREDENTIALS_PROVENANCE_BASE_URL", "https://verify.example")
        monkeypatch.setenv(
            "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST",
            "https://api.record.badgr.test",
        )

        record = self._delivery_record()
        record.metadata["canvas_credentials"] = {
            "provider": "badgr_api",
            "api_base_url": "https://api.record.badgr.test",
            "api_token_secret_id": "record-secret",
            "issuer_id": "issuer-record-1",
            "badgeclass_id": "badgeclass-record-1",
            "assertion_scope": "badgeclasses",
        }

        captured: dict[str, object] = {}

        class FakeResponse:
            status_code = 201
            headers = {"x-request-id": "req-record-1"}
            text = "{}"

            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "result": [
                        {
                            "entityId": "assertion-record-1",
                            "openBadgeId": "https://api.record.badgr.test/public/assertions/assertion-record-1",
                            "issuer": "issuer-record-1",
                        }
                    ]
                }

        class FakeClient:
            def __init__(self, *args, **kwargs):
                captured["timeout"] = kwargs.get("timeout")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, json=None, headers=None):
                captured["url"] = url
                captured["json"] = json
                captured["headers"] = headers
                return FakeResponse()

        monkeypatch.setattr(canvas_credentials_adapter, "canvas_http_client", FakeClient)

        async def resolve_secret(organization_id: str, secret_id: str) -> str | None:
            assert organization_id == "org-123"
            assert secret_id == "record-secret"
            return "record-token"

        result = await publish_canvas_credential_mirror(
            credential=self._issued_credential(),
            transaction=self._transaction(),
            platform=self._platform(),
            delivery_record=record,
            secret_resolver=resolve_secret,
        )

        assert result.external_credential_id == "assertion-record-1"
        assert result.metadata["api_base_url"] == "https://api.record.badgr.test"
        assert result.metadata["badgeclass_id"] == "badgeclass-record-1"
        assert captured["url"] == "https://api.record.badgr.test/v2/badgeclasses/badgeclass-record-1/assertions"
        assert captured["headers"]["Authorization"] == "Bearer record-token"
        assert captured["json"]["extensions"]["value"]["elevenid"]["delivery_record_id"] == record.id

    async def test_validate_real_api_uses_delivery_record_canvas_credentials_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from issuance.infrastructure.adapters import canvas_credentials_adapter

        monkeypatch.setenv(
            "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST",
            "https://api.record.badgr.test",
        )
        record = self._delivery_record()
        record.metadata["canvas_credentials"] = {
            "provider": "badgr_api",
            "api_base_url": "https://api.record.badgr.test",
            "api_token_secret_id": "record-secret",
            "issuer_id": "issuer-record-1",
            "badgeclass_id": "badgeclass-record-1",
            "assertion_scope": "badgeclasses",
        }
        captured: dict[str, object] = {}

        class FakeResponse:
            status_code = 200
            headers = {"x-request-id": "req-validate-1"}
            text = "{}"

            def json(self):
                return {"result": [{"entityId": "badgeclass-record-1"}]}

        class FakeClient:
            def __init__(self, *args, **kwargs):
                captured["timeout"] = kwargs.get("timeout")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, url, headers=None):
                captured["url"] = url
                captured["headers"] = headers
                return FakeResponse()

        monkeypatch.setattr(canvas_credentials_adapter, "canvas_http_client", FakeClient)

        async def resolve_secret(organization_id: str, secret_id: str) -> str | None:
            assert organization_id == "org-123"
            assert secret_id == "record-secret"
            return "record-token"

        result = await validate_canvas_credentials_config(
            record,
            secret_resolver=resolve_secret,
        )

        assert result.ok is True
        assert result.provider == "badgr_api"
        assert result.api_base_url == "https://api.record.badgr.test"
        assert result.badgeclass_id == "badgeclass-record-1"
        assert result.token_configured is True
        assert result.status_code == 200
        assert result.request_id == "req-validate-1"
        assert captured["url"] == "https://api.record.badgr.test/v2/badgeclasses/badgeclass-record-1"
        assert captured["headers"]["Authorization"] == "Bearer record-token"

    async def test_validate_real_api_reports_missing_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CANVAS_CREDENTIALS_API_TOKEN", raising=False)
        monkeypatch.setenv(
            "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST",
            "https://api.record.badgr.test",
        )
        record = self._delivery_record()
        record.metadata["canvas_credentials"] = {
            "provider": "badgr_api",
            "api_base_url": "https://api.record.badgr.test",
            "badgeclass_id": "badgeclass-record-1",
        }

        result = await validate_canvas_credentials_config(record)

        assert result.ok is False
        assert result.token_configured is False
        assert "CANVAS_CREDENTIALS_API_TOKEN" in result.error

    async def test_tenant_metadata_cannot_select_environment_or_file_secrets(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("CANVAS_CREDENTIALS_API_TOKEN", raising=False)
        monkeypatch.setenv("INTEGRATION_SECRET_MASTER_KEY", "must-not-be-used")
        monkeypatch.setenv(
            "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST",
            "https://api.record.badgr.test",
        )
        record = self._delivery_record()
        record.metadata["canvas_credentials"] = {
            "provider": "badgr_api",
            "api_base_url": "https://api.record.badgr.test",
            "api_token_env": "INTEGRATION_SECRET_MASTER_KEY",
            "api_token_file": "C:/secrets/internal-api-key",
            "badgeclass_id": "badgeclass-record-1",
        }

        result = await validate_canvas_credentials_config(record)

        assert result.ok is False
        assert result.token_configured is False
        assert "CANVAS_CREDENTIALS_API_TOKEN" in (result.error or "")

    async def test_publish_real_api_requires_badgeclass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CANVAS_CREDENTIALS_PUBLISH_URL", raising=False)
        monkeypatch.delenv("CANVAS_CREDENTIALS_BADGECLASS_ID", raising=False)
        monkeypatch.setenv("CANVAS_CREDENTIALS_PROVIDER", "badgr_api")
        monkeypatch.setenv("CANVAS_CREDENTIALS_API_TOKEN", "real-token")

        with pytest.raises(RuntimeError) as excinfo:
            await publish_canvas_credential_mirror(
                credential=self._issued_credential(),
                transaction=self._transaction(),
                platform=self._platform(),
                delivery_record=self._delivery_record(),
            )

        assert "CANVAS_CREDENTIALS_BADGECLASS_ID" in str(excinfo.value)

    async def test_revoke_real_api_deletes_badgr_assertion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from issuance.infrastructure.adapters import canvas_credentials_adapter

        monkeypatch.setenv("CANVAS_CREDENTIALS_PROVIDER", "badgr_api")
        monkeypatch.setenv("CANVAS_CREDENTIALS_API_BASE_URL", "https://api.badgr.test")
        monkeypatch.setenv("CANVAS_CREDENTIALS_API_TOKEN", "real-token")

        record = self._delivery_record()
        record.status = CredentialDeliveryStatus.DELIVERED
        record.external_credential_id = "assertion-entity-1"

        captured: dict[str, object] = {}

        class FakeResponse:
            status_code = 204
            headers = {"x-request-id": "req-revoke-1"}
            text = ""

            def raise_for_status(self):
                return None

            def json(self):
                raise ValueError("no json")

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def request(self, method, url, json=None, headers=None):
                captured["method"] = method
                captured["url"] = url
                captured["json"] = json
                captured["headers"] = headers
                return FakeResponse()

        monkeypatch.setattr(
            canvas_credentials_adapter,
            "canvas_http_client",
            lambda *args, **kwargs: FakeClient(),
        )

        result = await sync_canvas_credential_status(
            credential=self._issued_credential(),
            platform=self._platform(),
            delivery_record=record,
            lifecycle_action="revoke",
            reason="Learner request",
        )

        assert captured["method"] == "DELETE"
        assert captured["url"] == "https://api.badgr.test/v2/assertions/assertion-entity-1"
        assert captured["json"] == {"revocation_reason": "Learner request"}
        assert result.metadata["provider"] == "badgr_api"
        assert result.metadata["status_sync_http_status"] == 204

    async def test_suspend_real_api_maps_to_canonical_provenance_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from issuance.infrastructure.adapters import canvas_credentials_adapter

        monkeypatch.setenv("CANVAS_CREDENTIALS_PROVIDER", "badgr_api")

        class UnexpectedClient:
            async def __aenter__(self):
                raise AssertionError("suspend should not call the Canvas Credentials API")

        monkeypatch.setattr(
            canvas_credentials_adapter,
            "canvas_http_client",
            lambda *args, **kwargs: UnexpectedClient(),
        )
        credential = self._issued_credential()
        credential.status = CredentialStatus.SUSPENDED

        result = await sync_canvas_credential_status(
            credential=credential,
            platform=self._platform(),
            delivery_record=self._delivery_record(),
            lifecycle_action="suspend",
            reason="Policy pause",
        )

        assert result.metadata["provider"] == "badgr_api"
        assert result.metadata["status_sync_mode"] == "canonical_provenance_only"
        assert result.metadata["status_sync_skipped"] is True
        assert result.metadata["canvas_credentials_lifecycle_mapping"] == {
            "requested_action": "suspend",
            "external_action": None,
            "canonical_status": "suspended",
        }


class TestCanvasEventProcessing:
    async def test_process_canvas_evidence_event_attaches_application_evidence_and_replays(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-1",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=["canvas.course_completion"],
        )
        app = Application(
            id="app-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        platform, binding = await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            evidence_requirements=template.evidence_requirements,
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        first = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        second = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        stored_app = await repo.get_application(app.id)
        receipt = await repo.get_canvas_event_receipt("evt-123", "acct-1")

        assert first.status == "evidence_received"
        assert first.application_id == app.id
        assert first.organization_id == "org-from-connector"
        assert first.mip_primitives["protocol"] == "SIGNED_EVIDENCE_RECEIPT"
        assert second.replayed is True
        assert stored_app is not None
        assert len(stored_app.evidence_submissions) == 1
        assert stored_app.evidence_submissions[0]["evidence_type"] == "canvas.course_completion"
        assert stored_app.evidence_submissions[0]["evidence_data"]["canvas_user_id"] == "user-7"
        assert stored_app.evidence_submissions[0]["verification"]["status"] == "verified"
        assert len(first.evidence_facts) == 1
        assert first.evidence_facts[0]["fact_type"] == "canvas.course_completion"
        stored_facts = await repo.list_evidence_facts_for_application(app.id)
        assert len(stored_facts) == 1
        assert stored_app.integration_context["canvas"]["canvas_platform_id"] == platform.id
        assert stored_app.integration_context["canvas"]["canvas_program_binding_id"] == binding.id
        assert receipt is not None
        assert receipt.status == "evidence_received"

        summary = await get_application_evidence_summary(app.id, repo=repo)
        assert summary.application_id == app.id
        assert summary.evidence_facts[0].fact_type == "canvas.course_completion"
        assert summary.canvas["canvas_platform_id"] == platform.id
        assert summary.canvas["canvas_program_binding_id"] == binding.id

        event_status = await get_canvas_evidence_event_status("acct-1", "evt-123", repo=repo)
        assert event_status.application_id == app.id
        assert event_status.evidence_facts[0]["fact_type"] == "canvas.course_completion"
        assert event_status.response["application_id"] == app.id

    async def test_process_canvas_evidence_event_auto_approves_when_requirements_satisfied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-auto",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=["canvas.course_completion"],
        )
        app = Application(
            id="app-auto-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=template.evidence_requirements,
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        response = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        stored_app = await repo.get_application(app.id)

        assert response.status == "evidence_received"
        assert response.application_status == "approved"
        assert stored_app is not None
        assert stored_app.status == ApplicationStatus.APPROVED
        assert stored_app.reviewer_id == "canvas:auto-approval"
        assert stored_app.issuance_transaction_id is not None
        tx = await repo.get_transaction(stored_app.issuance_transaction_id)
        assert tx is not None
        assert tx.application_id == app.id
        assert response.policy_decision is not None
        assert response.policy_decision["allowed"] is True
        summary = await get_application_evidence_summary(app.id, repo=repo)
        assert summary.policy_decision["allowed"] is True
        assert summary.policy_source == "bundled"
        assert summary.issuance_transaction_id == stored_app.issuance_transaction_id

    async def test_process_canvas_evidence_event_uses_program_binding_without_legacy_connector(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-binding",
            organization_id="org-from-binding",
            credential_template_id="tmpl-from-binding",
            evidence_requirements=["canvas.course_completion"],
        )
        platform = CanvasPlatform(
            id="canvas-platform-1",
            organization_id="org-from-binding",
            canvas_account_id="acct-1",
            display_name="Canvas Tenant",
        )
        binding = CanvasProgramBinding(
            id="canvas-binding-1",
            organization_id="org-from-binding",
            platform_id=platform.id,
            application_template_id=template.id,
            credential_template_id="tmpl-from-binding",
            auto_approve_on_evidence=True,
            evidence_requirements=["canvas.course_completion"],
            canvas_scope={"course_id": "course-42"},
        )
        app = Application(
            id="app-binding-123",
            organization_id="org-from-binding",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await repo.save_canvas_platform(platform)
        await repo.save_canvas_program_binding(binding)
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        response = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        stored_app = await repo.get_application(app.id)
        receipt = await repo.get_canvas_event_receipt("evt-123", "acct-1")

        assert response.organization_id == "org-from-binding"
        assert response.application_status == "approved"
        assert response.policy_decision is not None
        assert response.policy_decision["allowed"] is True
        assert stored_app is not None
        assert stored_app.status == ApplicationStatus.APPROVED
        assert stored_app.integration_context["canvas"]["runtime_source"] == "program_binding"
        assert stored_app.integration_context["canvas"]["canvas_platform_id"] == platform.id
        assert stored_app.integration_context["canvas"]["canvas_program_binding_id"] == binding.id
        assert receipt is not None
        assert receipt.credential_template_id == "tmpl-from-binding"

    async def test_process_canvas_evidence_event_rejects_disabled_profile_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-gated",
            organization_id="org-from-binding",
            credential_template_id="tmpl-from-binding",
            evidence_requirements=["canvas.course_completion"],
        )
        platform = CanvasPlatform(
            id="canvas-platform-gated",
            organization_id="org-from-binding",
            canvas_account_id="acct-1",
        )
        binding = CanvasProgramBinding(
            id="canvas-binding-gated",
            organization_id="org-from-binding",
            platform_id=platform.id,
            application_template_id=template.id,
            credential_template_id="tmpl-from-binding",
            auto_approve_on_evidence=True,
            evidence_requirements=["canvas.course_completion"],
            canvas_scope={"course_id": "course-42"},
            deployment_profile_id="deployment-profile-gated",
            feature_flags={"enable_canvas_evidence": False},
        )
        app = Application(
            id="app-gated-123",
            organization_id="org-from-binding",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await repo.save_canvas_platform(platform)
        await repo.save_canvas_program_binding(binding)
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        with pytest.raises(HTTPException) as exc_info:
            await process_canvas_evidence_event(raw_body=raw_body, headers=headers, repo=repo)

        stored_app = await repo.get_application(app.id)
        receipt = await repo.get_canvas_event_receipt("evt-123", "acct-1")
        assert exc_info.value.status_code == 409
        assert "enable_canvas_evidence" in str(exc_info.value.detail)
        assert stored_app is not None
        assert stored_app.status == ApplicationStatus.PENDING
        assert receipt is None

    async def test_process_canvas_evidence_event_policy_denies_wrong_scope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-scope",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=[
                {
                    "fact_type": "canvas.course_completion",
                    "scope": {"course_id": "course-other"},
                }
            ],
        )
        app = Application(
            id="app-scope-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        platform, binding = await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=template.evidence_requirements,
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        response = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        stored_app = await repo.get_application(app.id)

        assert response.application_status == "pending"
        assert response.policy_decision is not None
        assert response.policy_decision["allowed"] is False
        assert response.policy_decision["context"]["evidence_scope_matched"] is False
        assert stored_app is not None
        assert stored_app.issuance_transaction_id is None

    async def test_process_canvas_evidence_event_supports_external_fact_requirements(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-assignment-score",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=[
                {
                    "evidence_type": "EXTERNAL_FACT",
                    "provider": "canvas",
                    "fact_type": "canvas.assignment_score",
                    "scope": {"assignment_id": "assignment-9"},
                    "pass_rule": {"min_score_percent": 80},
                    "verification_method": "SIGNED_WEBHOOK",
                }
            ],
        )
        app = Application(
            id="app-assignment-score-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=template.evidence_requirements,
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
                evidence_type="canvas.assignment_score",
                canvas_assignment_id="assignment-9",
                score_percent=92,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        response = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )

        assert response.application_status == "approved"
        assert response.evidence_facts[0]["scope"]["assignment_id"] == "assignment-9"
        assert response.policy_decision is not None
        assert response.policy_decision["context"]["all_required_evidence_satisfied"] is True

    async def test_process_canvas_ags_score_event_creates_score_fact_and_auto_approves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-ags-score",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=[
                {
                    "evidence_type": "EXTERNAL_FACT",
                    "provider": "canvas",
                    "fact_type": "canvas.assignment_score",
                    "scope": {"assignment_id": "assignment-9"},
                    "pass_rule": {"min_score_percent": 80},
                    "verification_method": "SIGNED_AGS_SCORE",
                }
            ],
        )
        app = Application(
            id="app-ags-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        platform, binding = await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=template.evidence_requirements,
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_ags_score_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        first = await process_canvas_ags_score_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        replay = await process_canvas_ags_score_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        stored_app = await repo.get_application(app.id)
        stored_facts = await repo.list_evidence_facts_for_application(app.id)
        receipt = await repo.get_canvas_event_receipt("ags-evt-123", "acct-1")

        assert first.application_status == "approved"
        assert first.evidence_type == "canvas.assignment_score"
        assert first.evidence_facts[0]["scope"]["assignment_id"] == "assignment-9"
        assert first.evidence_facts[0]["assertion"]["score_percent"] == 92
        assert first.evidence_facts[0]["verification"]["method"] == "SIGNED_AGS_SCORE"
        assert first.policy_decision is not None
        assert first.policy_decision["context"]["all_required_evidence_satisfied"] is True
        assert replay.replayed is True
        assert stored_app is not None
        assert stored_app.status == ApplicationStatus.APPROVED
        assert stored_app.integration_context["canvas"]["standard_source"] == "canvas_ags_score_event"
        assert len(stored_facts) == 1
        assert receipt is not None
        assert receipt.issuance_transaction_id == stored_app.issuance_transaction_id

    async def test_process_canvas_nrps_membership_event_creates_role_fact_and_auto_approves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-nrps",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=[
                {
                    "evidence_type": "EXTERNAL_FACT",
                    "provider": "canvas",
                    "fact_type": "canvas.nrps_membership",
                    "scope": {"course_id": "course-42"},
                    "pass_rule": {
                        "roles_include": "Learner",
                        "membership_status": "Active",
                        "eligible": True,
                    },
                    "verification_method": "SIGNED_NRPS_MEMBERSHIP",
                }
            ],
        )
        app = Application(
            id="app-nrps-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=template.evidence_requirements,
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_nrps_membership_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        response = await process_canvas_nrps_membership_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        stored_app = await repo.get_application(app.id)

        assert response.application_status == "approved"
        assert response.evidence_type == "canvas.nrps_membership"
        assert response.evidence_facts[0]["assertion"]["roles"] == ["Learner"]
        assert response.evidence_facts[0]["assertion"]["membership_status"] == "Active"
        assert response.evidence_facts[0]["verification"]["method"] == "SIGNED_NRPS_MEMBERSHIP"
        assert response.policy_decision is not None
        assert response.policy_decision["context"]["all_required_evidence_satisfied"] is True
        assert stored_app is not None
        assert stored_app.status == ApplicationStatus.APPROVED
        assert stored_app.integration_context["canvas"]["standard_source"] == "canvas_nrps_membership_event"

    async def test_process_canvas_evidence_event_uses_configured_approval_policy_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-custom-policy",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=["canvas.course_completion"],
            approval_policy_set_id="policy-set-quiz-only",
        )
        app = Application(
            id="app-custom-policy-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=template.evidence_requirements,
            approval_policy_set_id=template.approval_policy_set_id,
        )
        await repo.save_approval_policy_set(
            ApprovalPolicySet(
                id="policy-set-quiz-only",
                organization_id="org-from-connector",
                policy_type="APPROVAL_RULES",
                status="active",
                cedar_policies="""
@id("custom-quiz-only")
permit (
    principal is MIP::ServiceAccount,
    action == MIP::Action::"applications:approve",
    resource
)
when {
    principal.service_name == "canvas-evidence-policy" &&
    context.evidence_provider == "canvas" &&
    context.evidence_fact_type == "canvas.quiz_score" &&
    context.all_required_evidence_satisfied
};
""",
            )
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        response = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        stored_app = await repo.get_application(app.id)

        assert response.application_status == "pending"
        assert response.policy_decision is not None
        assert response.policy_decision["allowed"] is False
        assert response.policy_decision["policy_source"] == "policy_set"
        assert response.policy_decision["policy_set_id"] == "policy-set-quiz-only"
        assert stored_app is not None
        assert stored_app.issuance_transaction_id is None

    async def test_process_canvas_evidence_event_missing_approval_policy_set_denies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-missing-policy",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=["canvas.course_completion"],
            approval_policy_set_id="missing-policy-set",
        )
        app = Application(
            id="app-missing-policy-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=template.evidence_requirements,
            approval_policy_set_id=template.approval_policy_set_id,
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        response = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )

        assert response.application_status == "pending"
        assert response.policy_decision is not None
        assert response.policy_decision["allowed"] is False
        assert response.policy_decision["engine"] == "policy_set_unavailable"
        assert response.policy_decision["policy_set_id"] == "missing-policy-set"

    async def test_process_canvas_evidence_event_policy_deny_records_metadata(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-policy-deny",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=["canvas.course_completion"],
        )
        app = Application(
            id="app-policy-deny-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=template.evidence_requirements,
        )
        await repo.save_application(app)

        def _deny_policy(**kwargs):
            return EvidencePolicyDecision(
                allowed=False,
                engine="test",
                errors=["denied by test"],
                context={"all_required_evidence_satisfied": True},
            )

        monkeypatch.setattr(
            "issuance.application.evidence_transition.evaluate_application_evidence_policy",
            _deny_policy,
        )
        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        response = await process_canvas_evidence_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
        )
        stored_app = await repo.get_application(app.id)

        assert response.application_status == "pending"
        assert response.policy_decision == {
            "allowed": False,
            "engine": "test",
            "policy_source": "bundled",
            "policy_set_id": None,
            "reasons": [],
            "errors": ["denied by test"],
            "context": {"all_required_evidence_satisfied": True},
        }
        assert stored_app is not None
        assert stored_app.integration_context["policy"]["errors"] == ["denied by test"]

    async def test_process_canvas_evidence_event_rejects_unrequired_evidence_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-requirements",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=["canvas.assignment_completion"],
        )
        app = Application(
            id="app-requirements-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_application_template(template)
        await _save_canvas_program_binding(
            repo,
            application_template_id=template.id,
            evidence_requirements=template.evidence_requirements,
        )
        await repo.save_application(app)

        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
                application_id=app.id,
                evidence_type="canvas.course_completion",
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        with pytest.raises(HTTPException) as exc_info:
            await process_canvas_evidence_event(
                raw_body=raw_body,
                headers=headers,
                repo=repo,
            )

        assert exc_info.value.status_code == 409

