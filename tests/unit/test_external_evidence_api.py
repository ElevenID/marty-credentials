"""Tests for declarative external evidence API checks."""

from __future__ import annotations

import os
import sys
from typing import Any

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_SERVICES = os.path.join(_REPO_ROOT, "services")
_PYTHON = os.path.join(_REPO_ROOT, "python")
_MARTY_COMMON_PACKAGES = os.path.join(os.path.dirname(_REPO_ROOT), "marty-ui", "packages")

for _path in (_SERVICES, _PYTHON):
    if _path not in sys.path:
        sys.path.insert(0, _path)
if os.path.isdir(_MARTY_COMMON_PACKAGES) and _MARTY_COMMON_PACKAGES not in sys.path:
    sys.path.insert(0, _MARTY_COMMON_PACKAGES)

from issuance.domain.entities import Application, ApplicationStatus, ApplicationTemplate
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api.application_routes import (
    ExternalEvidenceApiCheckRequest,
    get_application_evidence_summary,
    run_external_evidence_api_check,
)


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

    assert response.application_status == "approved"
    assert response.issuance_transaction_id is not None
    assert response.policy_decision["allowed"] is True
    assert response.policy_decision["context"]["evidence_provider"] == "passport_verifier"
    assert response.policy_decision["context"]["all_required_evidence_satisfied"] is True
    assert stored_app is not None
    assert stored_app.status == ApplicationStatus.APPROVED
    assert stored_app.issuance_transaction_id == response.issuance_transaction_id
    assert len(facts) == 1
    assert facts[0].provider == "passport_verifier"
    assert facts[0].fact_type == "passport.document_verified"
    assert facts[0].scope == {"document_type": "passport", "issuing_country": "US"}
    assert facts[0].assertion["face_match_score"] == 0.91
    assert facts[0].verification["status"] == "VERIFIED"
    assert _FakeAsyncClient.requests[0]["json"]["passport_number"] == "X1234567"
    assert _FakeAsyncClient.requests[0]["headers"]["authorization"] == "Bearer secret-token"

    summary = await get_application_evidence_summary(app.id, repo=repo)
    assert summary.available_api_checks[0]["check_id"] == "passport-document-check"
    assert summary.available_api_checks[0]["provider"] == "passport_verifier"
    assert "secret_headers" not in summary.available_api_checks[0]


async def test_external_api_check_denies_when_expected_response_fails(monkeypatch) -> None:
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

    assert response.application_status == "pending"
    assert response.issuance_transaction_id is None
    assert response.policy_decision["allowed"] is False
    assert response.policy_decision["context"]["all_required_evidence_satisfied"] is False
    assert stored_app is not None
    assert stored_app.status == ApplicationStatus.PENDING
    assert stored_app.issuance_transaction_id is None
    assert len(facts) == 1
    assert facts[0].verification["status"] == "UNVERIFIED"
