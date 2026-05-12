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

if _SERVICES not in sys.path:
    sys.path.insert(0, _SERVICES)

from issuance.infrastructure.adapters.canvas_credentials_adapter import (
    CanvasCredentialEvent,
    CanvasEvidenceEvent,
    map_canvas_event_to_mip_evidence_receipt,
    map_canvas_event_to_mip_issuance_command,
    map_canvas_event_to_issuance_request,
    process_canvas_credential_event,
    process_canvas_evidence_event,
    verify_canvas_signature,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.domain.entities import Application, ApplicationStatus, ApplicationTemplate, CanvasConnectorConfig


CANVAS_SECRET = "canvas-test-secret"


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


def _sign_payload(raw_body: bytes, *, timestamp: str, secret: str = CANVAS_SECRET) -> str:
    digest = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def _save_direct_issue_connector(
    repo: InMemoryIssuanceRepository,
    *,
    canvas_account_id: str = "acct-1",
    organization_id: str = "org-123",
    credential_template_id: str = "tmpl-456",
) -> CanvasConnectorConfig:
    connector = CanvasConnectorConfig(
        organization_id=organization_id,
        canvas_account_id=canvas_account_id,
        credential_template_id=credential_template_id,
        direct_issue_enabled=True,
    )
    await repo.save_canvas_connector(connector)
    return connector


class TestCanvasEventMapping:
    def test_map_canvas_event_to_initiate_request_uses_open_badge_claims(self) -> None:
        event = CanvasCredentialEvent.model_validate(_sample_event())

        request = map_canvas_event_to_issuance_request(event)

        assert request.organization_id == "org-123"
        assert request.credential_template_id == "tmpl-456"
        assert request.applicant_id == "ada@example.com"
        assert request.claims["email"] == "ada@example.com"
        assert request.claims["given_name"] == "Ada"
        assert request.claims["family_name"] == "Lovelace"
        assert request.claims["achievement_name"] == "Course Completion"
        assert request.claims["achievement_description"] == "Completed all required modules."
        assert request.claims["canvas_account_id"] == "acct-1"
        assert request.claims["canvas_course_id"] == "course-42"
        assert request.claims["canvas_course_name"] == "Introduction to Portable Trust"
        assert request.claims["canvas_enrollment_id"] == "enroll-9"
        assert request.claims["canvas_user_id"] == "user-7"
        assert request.claims["completion_at"] == "2026-05-07T12:34:56Z"
        assert request.claims["source_event_id"] == "evt-123"
        assert request.claims["issued_at"] == "2026-05-07T12:34:56Z"

    def test_map_canvas_event_to_mip_issuance_command_uses_protocol_primitives(self) -> None:
        event = CanvasCredentialEvent.model_validate(_sample_event())

        command = map_canvas_event_to_mip_issuance_command(event, payload_hash="payload-sha256")

        assert command.action == "credentials:issue"
        assert command.protocol == "OID4VCI_PRE_AUTH"
        assert command.resource_type == "CredentialTemplate"
        assert command.organization_id == "org-123"
        assert command.credential_template_id == "tmpl-456"
        assert command.subject_id == "ada@example.com"
        assert command.source.provider == "canvas"
        assert command.source.provider_account_id == "acct-1"
        assert command.source.provider_event_id == "evt-123"
        assert command.source.event_type == "canvas.course_completion"
        assert command.source.signature_scheme == "HMAC_SHA256_TIMESTAMPED"
        assert command.source.payload_hash == "payload-sha256"
        assert command.claims["canvas_user_id"] == "user-7"

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


class TestCanvasEventProcessing:
    async def test_process_canvas_event_resolves_org_and_template_from_connector(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        connector = CanvasConnectorConfig(
            organization_id="org-from-connector",
            canvas_account_id="acct-1",
            credential_template_id="tmpl-from-connector",
            display_name="Canvas Production",
            direct_issue_enabled=True,
        )
        await repo.save_canvas_connector(connector)
        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }
        calls: list[object] = []

        async def _issue(request, http_request, issuance_repo):
            calls.append(request)
            return {
                "id": "tx-from-connector",
                "organization_id": request.organization_id,
                "credential_template_id": request.credential_template_id,
                "status": "pending",
                "credential_offer_uri": "openid-credential-offer://?credential_offer=test",
                "credential_offer_uris": {},
                "credential_offer_labels": {},
                "pre_auth_code": "pre-auth-connector",
                "expires_at": "2026-05-14T00:00:00+00:00",
            }

        response = await process_canvas_credential_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
            issue_credential=_issue,
        )

        assert response.id == "tx-from-connector"
        assert len(calls) == 1
        assert calls[0].organization_id == "org-from-connector"
        assert calls[0].credential_template_id == "tmpl-from-connector"

    async def test_process_canvas_event_rejects_missing_connector_when_org_and_template_omitted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        raw_body = json.dumps(
            _sample_event(
                organization_id=None,
                credential_template_id=None,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        async def _issue(request, http_request, issuance_repo):  # pragma: no cover - must not be called
            raise AssertionError("issue_credential should not be called without connector resolution")

        with pytest.raises(HTTPException) as exc_info:
            await process_canvas_credential_event(
                raw_body=raw_body,
                headers=headers,
                repo=repo,
                issue_credential=_issue,
            )

        assert exc_info.value.status_code == 404

    async def test_process_canvas_event_rejects_direct_issue_when_connector_not_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        await repo.save_canvas_connector(
            CanvasConnectorConfig(
                organization_id="org-123",
                canvas_account_id="acct-1",
                credential_template_id="tmpl-456",
                direct_issue_enabled=False,
            )
        )
        raw_body = json.dumps(_sample_event(), separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        async def _issue(request, http_request, issuance_repo):  # pragma: no cover - must not be called
            raise AssertionError("issue_credential should not be called when connector direct issue is disabled")

        with pytest.raises(HTTPException) as exc_info:
            await process_canvas_credential_event(
                raw_body=raw_body,
                headers=headers,
                repo=repo,
                issue_credential=_issue,
            )

        assert exc_info.value.status_code == 409
        assert "evidence-events" in str(exc_info.value.detail)

    async def test_process_canvas_evidence_event_attaches_application_evidence_and_replays(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        connector = CanvasConnectorConfig(
            organization_id="org-from-connector",
            canvas_account_id="acct-1",
            credential_template_id="tmpl-from-connector",
            display_name="Canvas Evidence",
        )
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
        await repo.save_canvas_connector(connector)
        await repo.save_application_template(template)
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
        assert stored_app.integration_context["canvas"]["connector_id"] == connector.id
        assert receipt is not None
        assert receipt.status == "evidence_received"

    async def test_process_canvas_evidence_event_auto_approves_when_requirements_satisfied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        template = ApplicationTemplate(
            id="application-template-auto",
            organization_id="org-from-connector",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=["canvas.course_completion"],
        )
        connector = CanvasConnectorConfig(
            organization_id="org-from-connector",
            canvas_account_id="acct-1",
            credential_template_id="tmpl-from-connector",
            application_template_id=template.id,
            auto_approve_on_evidence=True,
            evidence_requirements=["canvas.course_completion"],
        )
        app = Application(
            id="app-auto-123",
            organization_id="org-from-connector",
            application_template_id=template.id,
            applicant_identifier="ada@example.com",
            form_data={"email": "ada@example.com"},
        )
        await repo.save_canvas_connector(connector)
        await repo.save_application_template(template)
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
        assert stored_app.issuance_transaction_id is None

    async def test_process_canvas_evidence_event_rejects_unrequired_evidence_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        connector = CanvasConnectorConfig(
            organization_id="org-from-connector",
            canvas_account_id="acct-1",
            credential_template_id="tmpl-from-connector",
            evidence_requirements=["canvas.assignment_completion"],
        )
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
        await repo.save_canvas_connector(connector)
        await repo.save_application_template(template)
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

    async def test_process_canvas_event_returns_offer_and_persists_receipt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        await _save_direct_issue_connector(repo)
        raw_body = json.dumps(_sample_event(), separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }
        calls: list[object] = []

        async def _issue(request, http_request, issuance_repo):
            calls.append(request)
            return {
                "id": "tx-001",
                "organization_id": request.organization_id,
                "credential_template_id": request.credential_template_id or "tmpl-456",
                "status": "pending",
                "credential_offer_uri": "openid-credential-offer://?credential_offer=test",
                "credential_offer_uris": {"wr-default": "openid-credential-offer://?credential_offer=test"},
                "credential_offer_labels": {"wr-default": "Default Wallet"},
                "pre_auth_code": "pre-auth-123",
                "expires_at": "2026-05-14T00:00:00+00:00",
            }

        response = await process_canvas_credential_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
            issue_credential=_issue,
        )

        assert response.id == "tx-001"
        assert response.replayed is False
        assert response.source_event_id == "evt-123"
        assert response.credential_offer_uri.startswith("openid-credential-offer://")
        assert len(calls) == 1
        receipt = await repo.get_canvas_event_receipt("evt-123")
        assert receipt is not None
        assert receipt.issuance_transaction_id == "tx-001"
        assert receipt.payload_hash

    async def test_process_canvas_event_replays_duplicate_without_reissuing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        await _save_direct_issue_connector(repo)
        raw_body = json.dumps(_sample_event(), separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }
        calls: list[object] = []

        async def _issue(request, http_request, issuance_repo):
            calls.append(request)
            return {
                "id": "tx-dup",
                "organization_id": request.organization_id,
                "credential_template_id": request.credential_template_id or "tmpl-456",
                "status": "pending",
                "credential_offer_uri": "openid-credential-offer://?credential_offer=test",
                "credential_offer_uris": {},
                "credential_offer_labels": {},
                "pre_auth_code": "pre-auth-dup",
                "expires_at": "2026-05-14T00:00:00+00:00",
            }

        first = await process_canvas_credential_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
            issue_credential=_issue,
        )
        second = await process_canvas_credential_event(
            raw_body=raw_body,
            headers=headers,
            repo=repo,
            issue_credential=_issue,
        )

        assert first.replayed is False
        assert second.replayed is True
        assert second.id == "tx-dup"
        assert len(calls) == 1

    async def test_process_canvas_event_allows_same_event_id_for_different_accounts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        await _save_direct_issue_connector(repo, canvas_account_id="acct-1")
        await _save_direct_issue_connector(repo, canvas_account_id="acct-2")
        timestamp = str(int(time.time()))
        first_body = json.dumps(_sample_event(canvas_account_id="acct-1"), separators=(",", ":")).encode("utf-8")
        second_body = json.dumps(_sample_event(canvas_account_id="acct-2"), separators=(",", ":")).encode("utf-8")
        first_headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(first_body, timestamp=timestamp),
        }
        second_headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(second_body, timestamp=timestamp),
        }
        calls: list[object] = []

        async def _issue(request, http_request, issuance_repo):
            calls.append(request)
            return {
                "id": f"tx-{request.claims['canvas_account_id']}",
                "organization_id": request.organization_id,
                "credential_template_id": request.credential_template_id or "tmpl-456",
                "status": "pending",
                "credential_offer_uri": "openid-credential-offer://?credential_offer=test",
                "credential_offer_uris": {},
                "credential_offer_labels": {},
                "pre_auth_code": f"pre-auth-{request.claims['canvas_account_id']}",
                "expires_at": "2026-05-14T00:00:00+00:00",
            }

        first = await process_canvas_credential_event(
            raw_body=first_body,
            headers=first_headers,
            repo=repo,
            issue_credential=_issue,
        )
        second = await process_canvas_credential_event(
            raw_body=second_body,
            headers=second_headers,
            repo=repo,
            issue_credential=_issue,
        )

        assert first.id == "tx-acct-1"
        assert second.id == "tx-acct-2"
        assert len(calls) == 2

    async def test_process_canvas_event_rejects_changed_duplicate_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        await _save_direct_issue_connector(repo)
        first_body = json.dumps(_sample_event(), separators=(",", ":")).encode("utf-8")
        second_body = json.dumps(
            _sample_event(achievement_name="Final Course Completion"),
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        first_headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(first_body, timestamp=timestamp),
        }
        second_headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(second_body, timestamp=timestamp),
        }

        async def _issue(request, http_request, issuance_repo):
            return {
                "id": "tx-dup-conflict",
                "organization_id": request.organization_id,
                "credential_template_id": request.credential_template_id or "tmpl-456",
                "status": "pending",
                "credential_offer_uri": "openid-credential-offer://?credential_offer=test",
                "credential_offer_uris": {},
                "credential_offer_labels": {},
                "pre_auth_code": "pre-auth-conflict",
                "expires_at": "2026-05-14T00:00:00+00:00",
            }

        await process_canvas_credential_event(
            raw_body=first_body,
            headers=first_headers,
            repo=repo,
            issue_credential=_issue,
        )

        with pytest.raises(HTTPException) as exc_info:
            await process_canvas_credential_event(
                raw_body=second_body,
                headers=second_headers,
                repo=repo,
                issue_credential=_issue,
            )

        assert exc_info.value.status_code == 409

    async def test_process_canvas_event_rejects_malformed_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CANVAS_CREDENTIALS_SHARED_SECRET", CANVAS_SECRET)
        repo = InMemoryIssuanceRepository()
        raw_body = b"{not-json"
        timestamp = str(int(time.time()))
        headers = {
            "x-canvas-timestamp": timestamp,
            "x-canvas-signature-256": _sign_payload(raw_body, timestamp=timestamp),
        }

        async def _issue(request, http_request, issuance_repo):  # pragma: no cover - must not be called
            raise AssertionError("issue_credential should not be called for malformed payloads")

        with pytest.raises(HTTPException) as exc_info:
            await process_canvas_credential_event(
                raw_body=raw_body,
                headers=headers,
                repo=repo,
                issue_credential=_issue,
            )

        assert exc_info.value.status_code == 400
