"""Tests for declarative external evidence API checks."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_SERVICES = os.path.join(_REPO_ROOT, "services")
_PYTHON = os.path.join(_REPO_ROOT, "python")

for _path in (_SERVICES, _PYTHON):
    if _path not in sys.path:
        sys.path.insert(0, _path)

CONTRACT = json.loads(
    (Path(_REPO_ROOT) / "contracts" / "issuance-internal-applications.json").read_text(
        encoding="utf-8"
    )
)

from issuance.domain.entities import Application, ApplicationTemplate, IssuanceEvent
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api.application_routes import (
    ExternalEvidenceApiCheckRequest,
    get_application_evidence_summary,
    reject_application,
    run_external_evidence_api_check,
)
from issuance.infrastructure.api.routes import ApplicationRejection


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeAsyncClient:
    response_payload: dict[str, Any] = {}
    status_code: int = 200
    requests: list[dict[str, Any]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.timeout = kwargs.get("timeout")

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def request(self, method: str, url: str, **kwargs: Any) -> _FakeResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        return _FakeResponse(self.response_payload, self.status_code)


class _FailingAuditRepository(InMemoryIssuanceRepository):
    def __init__(self, fail_at: int) -> None:
        super().__init__()
        self._fail_at = fail_at
        self._audit_writes = 0

    async def save_event(self, event: IssuanceEvent) -> None:
        self._audit_writes += 1
        if self._audit_writes == self._fail_at:
            raise RuntimeError(f"audit-write-{self._fail_at}-failed")
        await super().save_event(event)


def _passport_requirement(*, auto_issue: bool = True) -> dict[str, Any]:
    return {
        "evidence_id": "passport-document-check",
        "evidence_type": "EXTERNAL_API",
        "description": "Verify passport document authenticity through a configured provider API.",
        "required": True,
        "provider": "passport_verifier",
        "fact_type": "passport.document_verified",
        "scope": {"document_type": "passport"},
        "api": {
            "method": "POST",
            "url": "https://verify.example.test/passports",
            "headers": {"content-type": "application/json"},
            "secret_headers": {"authorization": "PASSPORT_VERIFY_API_TOKEN"},
            "body": {
                "passport_number": "{{application.form_data.passport_number}}",
                "birth_date": "{{application.form_data.birth_date}}",
            },
        },
        "expected_response": {
            "status_codes": [200],
            "json": {
                "all": [
                    {"path": "$.status", "op": "eq", "value": "verified"},
                    {"path": "$.checks.passive_auth_valid", "op": "eq", "value": True},
                    {"path": "$.biometric.face_match_score", "op": ">=", "value": 0.85},
                ]
            },
        },
        "response_mapping": {
            "provider_event_id_path": "$.id",
            "verification_status_path": "$.status",
            "verification_verified_values": ["verified"],
            "scope": {
                "issuing_country": "$.document.issuing_country",
            },
            "assertion": {
                "passive_auth_valid": "$.checks.passive_auth_valid",
                "face_match_score": "$.biometric.face_match_score",
                "document_not_expired": "$.document.not_expired",
            },
        },
        "pass_rule": {
            "all": [
                {"path": "assertion.passive_auth_valid", "op": "eq", "value": True},
                {"path": "assertion.face_match_score", "op": ">=", "value": 0.85},
                {"path": "assertion.document_not_expired", "op": "eq", "value": True},
            ]
        },
        "verification_method": "EXTERNAL_API_RESPONSE",
        "auto_issue_on_permit": auto_issue,
    }


async def _seed_application(repo: InMemoryIssuanceRepository, requirement: dict[str, Any]) -> Application:
    template = ApplicationTemplate(
        id="application-template-passport",
        organization_id="org-passport",
        credential_template_id="credential-template-passport",
        evidence_requirements=[requirement],
        approval_strategy="RULES_BASED",
    )
    app = Application(
        id="application-passport",
        organization_id=template.organization_id,
        application_template_id=template.id,
        applicant_identifier="ada@example.com",
        form_data={
            "passport_number": "X1234567",
            "birth_date": "1990-01-01",
        },
    )
    await repo.save_application_template(template)
    await repo.save_application(app)
    return app


async def test_external_api_check_creates_fact_and_auto_issues(monkeypatch) -> None:
    expected = CONTRACT["lifecycle"]["external_api_outcomes"]["permit"]
    monkeypatch.setenv("PASSPORT_VERIFY_API_TOKEN", "Bearer secret-token")
    monkeypatch.setattr(
        "issuance.application.external_evidence_api.httpx.AsyncClient",
        _FakeAsyncClient,
    )
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.response_payload = {
        "id": "passport-event-1",
        "status": "verified",
        "checks": {"passive_auth_valid": True},
        "biometric": {"face_match_score": 0.91},
        "document": {"issuing_country": "US", "not_expired": True},
    }
    repo = InMemoryIssuanceRepository()
    app = await _seed_application(repo, _passport_requirement())

    response = await run_external_evidence_api_check(
        application_id=app.id,
        check_id="passport-document-check",
        request=ExternalEvidenceApiCheckRequest(),
        repo=repo,
    )

    stored_app = await repo.get_application(app.id)
    facts = await repo.list_evidence_facts_for_application(app.id)

    assert response.application_status == expected["application_status"]
    assert (response.issuance_transaction_id is not None) is expected["transaction_created"]
    assert response.policy_decision["allowed"] is expected["policy_allowed"]
    assert response.policy_decision["context"]["evidence_provider"] == expected["provider"]
    assert response.policy_decision["context"]["all_required_evidence_satisfied"] is True
    assert stored_app is not None
    assert stored_app.status.value == expected["application_status"]
    assert stored_app.issuance_transaction_id == response.issuance_transaction_id
    assert len(facts) == expected["fact_count"]
    assert facts[0].provider == expected["provider"]
    assert facts[0].fact_type == expected["fact_type"]
    assert facts[0].scope == expected["scope"]
    assert facts[0].assertion["face_match_score"] == 0.91
    assert facts[0].verification["status"] == expected["verification_status"]
    assert (
        _FakeAsyncClient.requests[0]["json"]["passport_number"]
        == expected["request_passport_number"]
    )
    assert (
        _FakeAsyncClient.requests[0]["headers"]["authorization"]
        == expected["request_authorization"]
    )

    events = await repo.list_events_for_application(app.id)
    assert [event.event_type.value for event in events] == expected["event_types"]

    summary = await get_application_evidence_summary(app.id, repo=repo)
    assert summary.available_api_checks[0]["check_id"] == expected["summary_check_id"]
    assert summary.available_api_checks[0]["provider"] == expected["provider"]
    for forbidden_field in expected["summary_forbidden_fields"]:
        assert forbidden_field not in summary.available_api_checks[0]


async def test_external_api_check_denies_when_expected_response_fails(monkeypatch) -> None:
    expected = CONTRACT["lifecycle"]["external_api_outcomes"]["deny"]
    monkeypatch.setattr(
        "issuance.application.external_evidence_api.httpx.AsyncClient",
        _FakeAsyncClient,
    )
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.response_payload = {
        "id": "passport-event-2",
        "status": "verified",
        "checks": {"passive_auth_valid": True},
        "biometric": {"face_match_score": 0.4},
        "document": {"issuing_country": "US", "not_expired": True},
    }
    repo = InMemoryIssuanceRepository()
    app = await _seed_application(repo, _passport_requirement())

    response = await run_external_evidence_api_check(
        application_id=app.id,
        check_id="passport-document-check",
        request=ExternalEvidenceApiCheckRequest(),
        repo=repo,
    )

    stored_app = await repo.get_application(app.id)
    facts = await repo.list_evidence_facts_for_application(app.id)

    assert response.application_status == expected["application_status"]
    assert (response.issuance_transaction_id is not None) is expected["transaction_created"]
    assert response.policy_decision["allowed"] is expected["policy_allowed"]
    assert response.policy_decision["context"]["all_required_evidence_satisfied"] is False
    assert stored_app is not None
    assert stored_app.status.value == expected["application_status"]
    assert stored_app.issuance_transaction_id is None
    assert len(facts) == expected["fact_count"]
    assert facts[0].verification["status"] == expected["verification_status"]
    events = await repo.list_events_for_application(app.id)
    assert [event.event_type.value for event in events] == expected["event_types"]


async def test_external_api_check_loses_rejection_race_without_resurrecting_application(
    monkeypatch,
) -> None:
    from issuance.infrastructure.api import application_routes

    expected = CONTRACT["lifecycle"]["external_api_outcomes"]["lifecycle_conflict"]
    monkeypatch.setenv("PASSPORT_VERIFY_API_TOKEN", "Bearer secret-token")
    monkeypatch.setattr(
        "issuance.application.external_evidence_api.httpx.AsyncClient",
        _FakeAsyncClient,
    )
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.response_payload = {
        "id": "passport-event-race",
        "status": "verified",
        "checks": {"passive_auth_valid": True},
        "biometric": {"face_match_score": 0.91},
        "document": {"issuing_country": "US", "not_expired": True},
    }
    repo = InMemoryIssuanceRepository()
    app = await _seed_application(repo, _passport_requirement())
    approval_reached_signing = asyncio.Event()
    allow_approval_reservation = asyncio.Event()

    async def pause_remote_issuer_context(_transaction) -> None:
        approval_reached_signing.set()
        await allow_approval_reservation.wait()

    monkeypatch.setattr(
        application_routes,
        "apply_remote_issuer_context",
        pause_remote_issuer_context,
    )

    evidence_task = asyncio.create_task(
        run_external_evidence_api_check(
            application_id=app.id,
            check_id="passport-document-check",
            request=ExternalEvidenceApiCheckRequest(),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    )
    await approval_reached_signing.wait()
    rejected = await reject_application(
        application_id=app.id,
        rejection=ApplicationRejection(review_notes="Reject while evidence runs"),
        trusted_organization_id=app.organization_id,
        repo=repo,
    )
    assert rejected.status == expected["final_application_status"]
    allow_approval_reservation.set()

    with pytest.raises(HTTPException) as raised:
        await evidence_task
    assert raised.value.status_code == expected["status"]
    assert raised.value.detail == expected["detail"]

    stored = await repo.get_application(app.id)
    assert stored is not None
    assert stored.status.value == expected["final_application_status"]
    assert len(stored.evidence_submissions) == expected[
        "application_evidence_submission_count"
    ]
    assert len(await repo.list_transactions(app.organization_id)) == expected[
        "transaction_count"
    ]
    assert len(await repo.list_evidence_facts_for_application(app.id)) == expected[
        "retained_fact_count"
    ]
    events = await repo.list_events_for_application(app.id)
    assert [event.event_type.value for event in events] == expected["event_types"]


@pytest.mark.parametrize("fail_at", [1, 2, 3])
async def test_external_api_atomic_write_set_rolls_back_every_audit_failure(
    monkeypatch,
    fail_at: int,
) -> None:
    expected = CONTRACT["lifecycle"]["external_api_outcomes"][
        "atomic_persistence_failure"
    ]
    monkeypatch.setenv("PASSPORT_VERIFY_API_TOKEN", "Bearer secret-token")
    monkeypatch.setattr(
        "issuance.application.external_evidence_api.httpx.AsyncClient",
        _FakeAsyncClient,
    )
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.response_payload = {
        "id": f"passport-event-failure-{fail_at}",
        "status": "verified",
        "checks": {"passive_auth_valid": True},
        "biometric": {"face_match_score": 0.91},
        "document": {"issuing_country": "US", "not_expired": True},
    }
    repo = _FailingAuditRepository(fail_at)
    app = await _seed_application(repo, _passport_requirement())

    with pytest.raises(RuntimeError, match=f"audit-write-{fail_at}-failed"):
        await run_external_evidence_api_check(
            application_id=app.id,
            check_id="passport-document-check",
            request=ExternalEvidenceApiCheckRequest(),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )

    stored = await repo.get_application(app.id)
    assert stored is not None
    assert stored.status.value == expected["application_status"]
    assert len(stored.evidence_submissions) == expected[
        "application_evidence_submission_count"
    ]
    assert len(await repo.list_evidence_facts_for_application(app.id)) == expected["fact_count"]
    assert len(await repo.list_transactions(app.organization_id)) == expected[
        "transaction_count"
    ]
    events = await repo.list_events_for_application(app.id)
    assert [event.event_type.value for event in events] == expected["event_types"]
