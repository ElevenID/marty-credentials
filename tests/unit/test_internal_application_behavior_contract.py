import asyncio
import json
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    EventType,
    EvidenceFact,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import application_routes
from issuance.infrastructure.api.application_routes import (
    ApplicationEvidenceSummaryResponse,
    EvidenceFactResponse,
    EvidenceReconciliationRequest,
    ExternalEvidenceApiCheckRequest,
    ExternalEvidenceApiCheckResponse,
    IssuanceEventResponse,
    IssuanceOfferResponse,
    IssuanceOfferWallet,
)
from issuance.infrastructure.api.routes import (
    ApplicationApproval,
    ApplicationCreate,
    ApplicationRejection,
    ApplicationResponse,
    EvidenceSubmission,
    internal_application_router,
)
from pydantic import ValidationError
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts" / "issuance-internal-applications.json").read_text(
        encoding="utf-8"
    )
)

REQUEST_MODELS = {
    model.__name__: model
    for model in (
        ApplicationCreate,
        EvidenceSubmission,
        ApplicationApproval,
        ApplicationRejection,
        EvidenceReconciliationRequest,
        ExternalEvidenceApiCheckRequest,
    )
}

RESPONSE_MODELS = {
    model.__name__: model
    for model in (
        ApplicationResponse,
        EvidenceFactResponse,
        ApplicationEvidenceSummaryResponse,
        ExternalEvidenceApiCheckResponse,
        IssuanceOfferWallet,
        IssuanceOfferResponse,
        IssuanceEventResponse,
    )
}


def _response_model_name(value: object) -> str:
    return getattr(value, "__name__", str(value))


def _evidence_fact_from_contract(value: dict) -> EvidenceFact:
    return EvidenceFact(
        id=value["id"],
        organization_id=value["organization_id"],
        application_id=value["application_id"],
        subject_id=value["subject_id"],
        provider=value["provider"],
        fact_type=value["fact_type"],
        scope=value["scope"],
        assertion=value["assertion"],
        verification=value["verification"],
        source=value["source"],
        requirement_id=value["requirement_id"],
        logical_key=value["logical_key"],
        source_revision=value["source_revision"],
        payload_hash=value["payload_hash"],
        observed_at=datetime.fromisoformat(value["observed_at"]),
        effective_at=datetime.fromisoformat(value["effective_at"]),
        superseded_fact_id=value["superseded_fact_id"],
        created_at=datetime.fromisoformat(value["created_at"]),
    )


def test_internal_application_route_surface_matches_contract() -> None:
    actual = [
        {
            "method": method,
            "path": route.path,
            "operation": route.name,
            "response_model": _response_model_name(route.response_model),
            "success_status": route.status_code or 200,
        }
        for route in internal_application_router.routes
        for method in sorted(route.methods)
    ]

    assert actual == CONTRACT["surface"]["routes"]
    assert len(actual) == 14


def test_every_internal_application_route_keeps_both_security_dependencies() -> None:
    required = set(CONTRACT["security"]["route_dependencies"])
    for route in internal_application_router.routes:
        dependencies = {
            getattr(dependency.call, "__name__", str(dependency.call))
            for dependency in route.dependant.dependencies
        }
        assert required <= dependencies, route.name


@pytest.mark.parametrize(
    "case", CONTRACT["security"]["route_probes"], ids=lambda case: case["operation"]
)
def test_every_route_enforces_key_then_tenant_at_http_boundary(
    monkeypatch, case
) -> None:
    from issuance.infrastructure.api import routes

    monkeypatch.setattr(routes, "_ISSUANCE_API_KEY", "secret")
    app = FastAPI()
    app.include_router(internal_application_router)
    client = TestClient(app)
    request_kwargs = {"json": case["json"]} if "json" in case else {}

    missing_key = client.request(
        case["method"],
        case["path"],
        headers={"X-Organization-ID": "org-123"},
        **request_kwargs,
    )
    assert missing_key.status_code == 401
    assert missing_key.json() == {"detail": "X-API-Key header is missing"}

    invalid_key = client.request(
        case["method"],
        case["path"],
        headers={"X-API-Key": "wrong", "X-Organization-ID": "org-123"},
        **request_kwargs,
    )
    assert invalid_key.status_code == 401
    assert invalid_key.json() == {"detail": "Invalid API Key"}

    missing_tenant = client.request(
        case["method"],
        case["path"],
        headers={"X-API-Key": "secret"},
        **request_kwargs,
    )
    tenant_failure = CONTRACT["security"]["tenant_cases"]["missing_header"]
    assert missing_tenant.status_code == tenant_failure["status"]
    assert missing_tenant.json() == {"detail": tenant_failure["detail"]}


def test_unsupported_sibling_routes_remain_unowned() -> None:
    app = FastAPI()
    app.include_router(internal_application_router)
    client = TestClient(app)

    for case in CONTRACT["surface"]["unsupported_siblings"]:
        response = client.request(case["method"], case["path"])
        assert response.status_code == case["status"], case["path"]


@pytest.mark.asyncio
async def test_complete_http_success_lifecycle_replays_against_python_owner(
    monkeypatch,
) -> None:
    from issuance.infrastructure.api import routes

    expected = CONTRACT["lifecycle"]["http_success_replay"]
    repo = InMemoryIssuanceRepository()
    template = ApplicationTemplate(
        id="application-template-http",
        organization_id="org-123",
        name="HTTP lifecycle",
        credential_template_id="credential-template-1",
        status="ACTIVE",
        evidence_requirements=[
            {
                "evidence_id": "check-1",
                "evidence_type": "EXTERNAL_API",
                "description": "Contract API check",
                "provider": "contract-provider",
                "fact_type": "identity.document",
                "required": True,
                "api": {
                    "method": "POST",
                    "url": "https://provider.example.test/check",
                },
            }
        ],
    )
    await repo.save_application_template(template)

    async def fetch_template(_template_id: str):
        return _valid_live_credential_template()

    async def require_revocation_binding(**_kwargs) -> None:
        return None

    async def apply_issuer_context(transaction) -> None:
        transaction.issuer_profile_id = "issuer-profile-1"
        transaction.signing_service_id = "kms-service-1"

    async def fetch_wallets(_template_id: str | None):
        return []

    async def execute_check(*, app, requirement, inputs):
        assert requirement["evidence_id"] == "check-1"
        assert inputs == {"document": "passport"}
        fact = EvidenceFact(
            id="fact-http-1",
            organization_id=app.organization_id,
            application_id=app.id,
            subject_id=app.applicant_identifier,
            provider="contract-provider",
            fact_type="identity.document",
            scope={"document_type": "passport"},
            assertion={"verified": True},
            verification={"method": "CONTRACT", "status": "VERIFIED"},
            source={"event_id": "provider-event-1"},
            requirement_id="check-1",
            logical_key="logical-http-1",
            source_revision="revision-http-1",
            payload_hash="payload-http-1",
        )
        return SimpleNamespace(
            evidence_fact=fact,
            response_metadata={"provider_status": 200},
        )

    async def persist_transition(**kwargs):
        await kwargs["repo"].save_evidence_fact(kwargs["evidence_fact"])
        return SimpleNamespace(policy_decision=None, issuance_transaction=None)

    async def reconcile(**_kwargs):
        return SimpleNamespace(to_dict=lambda: {"processed": 1, "dry_run": False})

    async def reconciliation_report(**_kwargs):
        return SimpleNamespace(to_dict=lambda: {"processed": 1, "dry_run": True})

    monkeypatch.setattr(routes, "_ISSUANCE_API_KEY", "secret")
    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        require_revocation_binding,
    )
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_issuer_context,
    )
    monkeypatch.setattr(application_routes, "_fetch_wallets_for_template", fetch_wallets)
    monkeypatch.setattr(application_routes, "execute_external_evidence_api_check", execute_check)
    monkeypatch.setattr(
        application_routes,
        "persist_evidence_fact_and_apply_policy",
        persist_transition,
    )
    monkeypatch.setattr(
        application_routes,
        "reconcile_canvas_evidence_transitions",
        reconcile,
    )
    monkeypatch.setattr(
        application_routes,
        "build_canvas_evidence_reconciliation_report",
        reconciliation_report,
    )
    monkeypatch.setattr(
        application_routes,
        "_build_offer_uri",
        lambda **_kwargs: "openid-credential-offer://?credential_offer=contract",
    )
    monkeypatch.setattr(
        application_routes,
        "_build_wallet_offer_uris",
        lambda **_kwargs: {},
    )

    api = FastAPI()
    api.include_router(internal_application_router)
    api.dependency_overrides[IIssuanceRepository] = lambda: repo
    headers = {"X-API-Key": "secret", "X-Organization-ID": "org-123"}
    transport = httpx.ASGITransport(app=api)
    visited: list[str] = []

    async with httpx.AsyncClient(transport=transport, base_url="http://contract") as client:
        created = await client.post(
            "/internal/applications",
            headers=headers,
            json={
                "application_template_id": template.id,
                "applicant_data": {
                    "given_name": "Ada",
                    "family_name": "Lovelace",
                },
            },
        )
        assert created.status_code == 200
        application_id = created.json()["id"]
        assert created.json()["status"] == expected["created_status"]
        assert (
            created.json()["applicant_identifier"]
            == expected["created_applicant_identifier"]
        )
        visited.append("create_application")

        requests = [
            ("list_applications", "GET", "/internal/applications?organization_id=org-123", None),
            ("get_application", "GET", f"/internal/applications/{application_id}", None),
            (
                "run_external_evidence_api_check",
                "POST",
                f"/internal/applications/{application_id}/evidence/api-checks/check-1/run",
                {"inputs": {"document": "passport"}, "issue_on_permit": False},
            ),
            (
                "list_application_evidence_facts",
                "GET",
                f"/internal/applications/{application_id}/evidence-facts",
                None,
            ),
            (
                "get_application_evidence_summary",
                "GET",
                f"/internal/applications/{application_id}/evidence-summary",
                None,
            ),
            (
                "reconcile_application_evidence",
                "POST",
                "/internal/applications/evidence/reconcile",
                {"organization_id": "org-123", "issue_on_permit": False},
            ),
            (
                "get_application_evidence_reconciliation_report",
                "GET",
                "/internal/applications/evidence/reconciliation-report?organization_id=org-123",
                None,
            ),
            (
                "submit_evidence",
                "POST",
                f"/internal/applications/{application_id}/submit-evidence",
                {"evidence_type": "DOCUMENT_SCAN", "evidence_data": {"verified": True}},
            ),
            (
                "approve_application",
                "POST",
                f"/internal/applications/{application_id}/approve",
                {"review_notes": "Reviewed"},
            ),
            (
                "generate_issuance_offer",
                "POST",
                f"/internal/applications/{application_id}/issuance-offer",
                None,
            ),
            (
                "get_issuance_offer",
                "GET",
                f"/internal/applications/{application_id}/issuance-offer",
                None,
            ),
            (
                "list_issuance_events",
                "GET",
                f"/internal/applications/{application_id}/issuance-events",
                None,
            ),
        ]
        responses: dict[str, httpx.Response] = {}
        for operation, method, path, body in requests:
            response = await client.request(method, path, headers=headers, json=body)
            assert response.status_code == 200, (operation, response.text)
            responses[operation] = response
            visited.append(operation)

        assert len(responses["submit_evidence"].json()["evidence_submissions"]) == expected[
            "submitted_evidence_count"
        ]
        assert responses["approve_application"].json()["status"] == expected[
            "approved_status"
        ]
        assert len(responses["list_issuance_events"].json()) >= expected[
            "minimum_offer_event_count"
        ]

        rejection_candidate = await client.post(
            "/internal/applications",
            headers=headers,
            json={
                "application_template_id": template.id,
                "applicant_data": {"email": "reject@example.test"},
            },
        )
        assert rejection_candidate.status_code == 200
        rejected = await client.post(
            f"/internal/applications/{rejection_candidate.json()['id']}/reject",
            headers=headers,
            json={"review_notes": "Rejected by contract"},
        )
        assert rejected.status_code == 200
        assert rejected.json()["status"] == expected["rejected_status"]
        visited.append("reject_application")

    assert visited == expected["operation_order"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", CONTRACT["security"]["authentication_cases"], ids=lambda case: case["id"]
)
async def test_management_authentication_matches_contract(monkeypatch, case) -> None:
    monkeypatch.setattr(
        application_routes, "_ISSUANCE_API_KEY", case["configured_key"], raising=False
    )
    from issuance.infrastructure.api import routes

    monkeypatch.setattr(routes, "_ISSUANCE_API_KEY", case["configured_key"])
    if "status" in case:
        with pytest.raises(HTTPException) as raised:
            await routes._verify_management_api_key(case["supplied_key"])
        assert raised.value.status_code == case["status"]
        assert raised.value.detail == case["detail"]
    else:
        assert (
            await routes._verify_management_api_key(case["supplied_key"])
            == case["result"]
        )


def test_missing_and_mismatched_tenant_failures_match_contract() -> None:
    request = Request({"type": "http", "headers": []})
    missing = CONTRACT["security"]["tenant_cases"]["missing_header"]
    with pytest.raises(HTTPException) as raised:
        application_routes._trusted_application_organization_id(request)
    assert raised.value.status_code == missing["status"]
    assert raised.value.detail == missing["detail"]

    mismatch = CONTRACT["security"]["tenant_cases"]["claimed_mismatch"]
    with pytest.raises(HTTPException) as raised:
        application_routes._application_management_organization_id(
            "org-trusted", "org-claimed"
        )
    assert raised.value.status_code == mismatch["status"]
    assert raised.value.detail == mismatch["detail"]


def test_request_model_inventory_and_unknown_field_policy_match_contract() -> None:
    for name, expected in CONTRACT["request_models"].items():
        model = REQUEST_MODELS[name]
        assert list(model.model_fields) == expected["fields"]
        assert (model.model_config.get("extra") or "ignore") == expected["unknown_fields"]


@pytest.mark.parametrize(
    "case", CONTRACT["request_cases"], ids=lambda case: case["id"]
)
def test_request_cases_replay_against_python_owner(case) -> None:
    model = REQUEST_MODELS[case["model"]]
    if case["outcome"] == "reject":
        with pytest.raises(ValidationError):
            model.model_validate(case["input"])
        return

    value = model.model_validate(case["input"])
    assert value.model_dump(mode="json") == case["normalized"]


def test_typed_response_projection_matches_contract() -> None:
    assert set(RESPONSE_MODELS) == set(CONTRACT["response_models"])
    for name, fields in CONTRACT["response_models"].items():
        assert list(RESPONSE_MODELS[name].model_fields) == fields


def test_application_status_domain_matches_contract() -> None:
    assert [status.value for status in ApplicationStatus] == CONTRACT["lifecycle"][
        "application_statuses"
    ]


@pytest.mark.asyncio
async def test_application_evidence_and_event_reads_match_contract() -> None:
    expected = CONTRACT["lifecycle"]["read_projection"]
    application_value = expected["application"]
    previous_fact_value = expected["previous_evidence_fact"]
    fact_value = expected["evidence_fact"]
    event_value = expected["issuance_event"]
    summary_value = expected["evidence_summary"]
    repo = InMemoryIssuanceRepository()
    app = Application(
        id=application_value["id"],
        organization_id=application_value["organization_id"],
        application_template_id=application_value["application_template_id"],
        applicant_identifier=application_value["applicant_identifier"],
        form_data=application_value["form_data"],
        evidence_submissions=application_value["evidence_submissions"],
        integration_context=application_value["integration_context"],
        status=ApplicationStatus(application_value["status"]),
        review_notes=application_value["review_notes"],
        reviewer_id=application_value["reviewer_id"],
        submitted_at=datetime.fromisoformat(application_value["submitted_at"]),
        reviewed_at=datetime.fromisoformat(application_value["reviewed_at"]),
        expires_at=datetime.fromisoformat(application_value["expires_at"]),
        issuance_transaction_id=application_value["issuance_transaction_id"],
    )
    previous_fact = _evidence_fact_from_contract(previous_fact_value)
    fact = _evidence_fact_from_contract(fact_value)
    event = IssuanceEvent(
        id=event_value["id"],
        transaction_id=event_value["transaction_id"],
        application_id=event_value["application_id"],
        event_type=EventType(event_value["event_type"]),
        metadata=event_value["metadata"],
        created_at=datetime.fromisoformat(event_value["created_at"]),
    )
    template = ApplicationTemplate(
        id=app.application_template_id,
        organization_id=app.organization_id,
        name="Contract template",
        status="ACTIVE",
        evidence_requirements=[
            {
                "evidence_id": "check-1",
                "evidence_type": "EXTERNAL_API",
                "description": "Contract API check",
                "provider": "contract-provider",
                "fact_type": "identity.document",
                "required": True,
                "verification_method": "CONTRACT_API",
                "auto_issue_on_permit": False,
                "api": {"method": "GET", "url": "https://provider.example/check"},
                "scope": {"document_type": "passport"},
            }
        ],
    )
    await repo.save_application_template(template)
    await repo.save_application(app)
    await repo.save_evidence_fact(previous_fact)
    await repo.save_evidence_fact(fact)
    await repo.save_event(event)

    listed = await application_routes.list_applications(
        organization_id=app.organization_id,
        status=app.status.value,
        application_template_id=app.application_template_id,
        trusted_organization_id=app.organization_id,
        repo=repo,
    )
    fetched = await application_routes.get_application(
        application_id=app.id,
        trusted_organization_id=app.organization_id,
        repo=repo,
    )
    facts = await application_routes.list_application_evidence_facts(
        application_id=app.id,
        trusted_organization_id=app.organization_id,
        repo=repo,
    )
    events = await application_routes.list_issuance_events(
        application_id=app.id,
        trusted_organization_id=app.organization_id,
        repo=repo,
    )
    summary = await application_routes.get_application_evidence_summary(
        application_id=app.id,
        trusted_organization_id=app.organization_id,
        repo=repo,
    )

    assert [value.model_dump(mode="json") for value in listed] == [application_value]
    assert fetched.model_dump(mode="json") == application_value
    assert [value.model_dump(mode="json") for value in facts] == [
        previous_fact_value,
        fact_value,
    ]
    assert [value.model_dump(mode="json") for value in events] == [event_value]
    assert summary.model_dump(mode="json") == {
        **summary_value,
        "evidence_facts": [previous_fact_value, fact_value],
    }


@pytest.mark.asyncio
async def test_invalid_list_status_is_a_stable_validation_failure() -> None:
    case = CONTRACT["lifecycle"]["read_projection"]["invalid_status"]
    repo = InMemoryIssuanceRepository()
    with pytest.raises(HTTPException) as raised:
        await application_routes.list_applications(
            organization_id="org-123",
            status=case["value"],
            application_template_id=None,
            trusted_organization_id="org-123",
            repo=repo,
        )
    assert raised.value.status_code == case["status"]
    assert raised.value.detail == case["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    CONTRACT["lifecycle"]["template_failure_cases"],
    ids=lambda case: case["id"],
)
async def test_create_template_failures_do_not_write(case) -> None:
    repo = InMemoryIssuanceRepository()
    if case["template"] != "missing":
        await repo.save_application_template(
            ApplicationTemplate(
                id="template-1",
                organization_id="org-123",
                name="Membership",
                status=case["template"],
            )
        )

    with pytest.raises(HTTPException) as raised:
        await application_routes.create_application(
            request=ApplicationCreate(
                application_template_id="template-1",
                applicant_data={"email": "applicant@example.test"},
            ),
            trusted_organization_id=case["trusted_organization_id"],
            repo=repo,
        )

    assert raised.value.status_code == case["status"]
    assert raised.value.detail == case["detail"]
    assert await repo.list_applications(org_id="org-123") == []


def _valid_live_credential_template() -> dict[str, object]:
    return {
        "organization_id": "org-123",
        "status": "ACTIVE",
        "credential_type": "EmployeeCredential",
        "vct": "https://issuer.example/credentials/employee",
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "revocation_profile_id": "revocation-profile-1",
        "issuer_did": "did:web:issuer.example:orgs:org-123",
        "issuer_algorithm": "ES256",
    }


async def _apply_revocation_dependency_case(
    case: dict[str, object],
    *,
    organization_id: str,
    revocation_profile_id: str | None,
) -> None:
    assert organization_id == "org-123"
    arrange = case["arrange"]
    if arrange == "revocation_missing_binding":
        assert revocation_profile_id is None
    else:
        assert revocation_profile_id == "revocation-profile-1"
    failures = {
        "revocation_missing_binding": (
            422,
            "Credential Templates must reference an active Revocation Profile before issuance.",
        ),
        "revocation_not_found": (422, "Revocation Profile not found."),
        "revocation_foreign": (
            422,
            "The Revocation Profile belongs to another organization.",
        ),
        "revocation_inactive": (
            422,
            "Credential Templates must reference an active Revocation Profile before issuance.",
        ),
        "revocation_unavailable": (
            503,
            "Revocation Profile validation is unavailable.",
        ),
    }
    if failure := failures.get(str(arrange)):
        raise HTTPException(status_code=failure[0], detail=failure[1])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    CONTRACT["lifecycle"]["approval_dependency_cases"],
    ids=lambda case: case["id"],
)
async def test_ordinary_approval_dependency_failures_are_atomic(
    monkeypatch, case
) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-1",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
        form_data={"employee_id": "E-1"},
    )
    await repo.save_application(app)

    if case["arrange"] != "missing_application_template":
        await repo.save_application_template(
            ApplicationTemplate(
                id=app.application_template_id,
                organization_id=app.organization_id,
                name="Membership",
                credential_template_id=(
                    None
                    if case["arrange"] == "missing_credential_template_id"
                    else "credential-template-1"
                ),
                status="ACTIVE",
            )
        )

    async def fetch_template(_template_id: str):
        if case["arrange"] == "remote_unavailable":
            raise application_routes._CredentialTemplateLookupUnavailable
        if case["arrange"] == "remote_not_found":
            return None
        template = _valid_live_credential_template()
        template.update(case.get("override", {}))
        return template

    async def require_revocation_binding(**kwargs) -> None:
        await _apply_revocation_dependency_case(case, **kwargs)

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        require_revocation_binding,
    )
    if case["arrange"] == "issuer_context_unavailable":

        async def apply_issuer_context(_transaction) -> None:
            raise RuntimeError("Bearer secret-token")

        monkeypatch.setattr(
            application_routes,
            "apply_required_remote_issuer_context",
            apply_issuer_context,
        )
    before = asdict(deepcopy(app))

    with pytest.raises(HTTPException) as raised:
        await application_routes.approve_application(
            application_id=app.id,
            approval=ApplicationApproval(review_notes="Reviewed"),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )

    assert raised.value.status_code == case["status"]
    assert raised.value.detail == case["detail"]
    if forbidden := case.get("forbidden_detail"):
        assert forbidden not in str(raised.value.detail)
    stored = await repo.get_application(app.id)
    assert stored is not None
    assert asdict(stored) == before
    assert await repo.list_transactions(app.organization_id) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    CONTRACT["lifecycle"]["offer_dependency_cases"],
    ids=lambda case: case["id"],
)
async def test_offer_dependency_failures_are_atomic_and_redacted(
    monkeypatch, case
) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-1",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
        form_data={"employee_id": "E-1"},
        status=ApplicationStatus.APPROVED,
    )
    await repo.save_application(app)
    if case["arrange"] != "missing_application_template":
        await repo.save_application_template(
            ApplicationTemplate(
                id=app.application_template_id,
                organization_id=app.organization_id,
                name="Membership",
                credential_template_id=(
                    None
                    if case["arrange"] == "missing_credential_template_id"
                    else "credential-template-1"
                ),
                status="ACTIVE",
            )
        )

    async def fetch_template(_template_id: str):
        if case["arrange"] == "remote_unavailable":
            raise application_routes._CredentialTemplateLookupUnavailable
        if case["arrange"] == "remote_not_found":
            return None
        template = _valid_live_credential_template()
        template.update(case.get("override", {}))
        return template

    async def require_revocation_binding(**kwargs) -> None:
        await _apply_revocation_dependency_case(case, **kwargs)

    async def apply_issuer_context(_transaction) -> None:
        if case["arrange"] == "issuer_context_unavailable":
            raise RuntimeError("Bearer secret-token")

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        require_revocation_binding,
    )
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_issuer_context,
    )
    before = asdict(deepcopy(app))

    with pytest.raises(HTTPException) as raised:
        await application_routes.generate_issuance_offer(
            application_id=app.id,
            trusted_organization_id=app.organization_id,
            repo=repo,
        )

    assert raised.value.status_code == case["status"]
    assert raised.value.detail == case["detail"]
    if forbidden := case.get("forbidden_detail"):
        assert forbidden not in str(raised.value.detail)
    stored = await repo.get_application(app.id)
    assert stored is not None
    assert asdict(stored) == before
    assert await repo.list_transactions(app.organization_id) == []
    assert await repo.list_events_for_application(app.id) == []


@pytest.mark.asyncio
async def test_ordinary_approval_success_matches_contract(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-1",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
        form_data={"employee_id": "E-1"},
    )
    await repo.save_application_template(
        ApplicationTemplate(
            id=app.application_template_id,
            organization_id=app.organization_id,
            name="Membership",
            credential_template_id="credential-template-1",
            status="ACTIVE",
        )
    )
    await repo.save_application(app)

    async def fetch_template(_template_id: str):
        return _valid_live_credential_template()

    async def apply_issuer_context(transaction) -> None:
        transaction.issuer_profile_id = "issuer-profile-1"
        transaction.signing_service_id = "kms-service-1"

    async def require_revocation_binding(**kwargs) -> None:
        assert kwargs == {
            "organization_id": "org-123",
            "revocation_profile_id": "revocation-profile-1",
        }

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        require_revocation_binding,
    )
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_issuer_context,
    )

    response = await application_routes.approve_application(
        application_id=app.id,
        approval=ApplicationApproval(review_notes="Reviewed"),
        trusted_organization_id=app.organization_id,
        repo=repo,
    )

    expected = CONTRACT["lifecycle"]["ordinary_approval_success"]
    assert response.status == expected["application_status"]
    assert response.reviewer_id == expected["reviewer_id"]
    assert response.review_notes == expected["review_notes"]
    assert response.reviewed_at is not None
    assert response.issuance_transaction_id is not None
    transaction = await repo.get_transaction(response.issuance_transaction_id)
    assert transaction is not None
    for field, value in expected["transaction"].items():
        assert getattr(transaction, field) == value


@pytest.mark.asyncio
async def test_rejection_wins_forced_race_without_orphaning_approval_transaction(
    monkeypatch,
) -> None:
    expected = CONTRACT["lifecycle"]["concurrent_transition"][
        "approval_rejection_race"
    ]
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-race",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
        form_data={"employee_id": "E-1"},
    )
    await repo.save_application_template(
        ApplicationTemplate(
            id=app.application_template_id,
            organization_id=app.organization_id,
            name="Membership",
            credential_template_id="credential-template-1",
            status="ACTIVE",
        )
    )
    await repo.save_application(app)

    approval_reached_dependency_gate = asyncio.Event()
    allow_approval_to_reserve = asyncio.Event()

    async def fetch_template(_template_id: str):
        return _valid_live_credential_template()

    async def require_revocation_binding(**_kwargs) -> None:
        approval_reached_dependency_gate.set()
        await allow_approval_to_reserve.wait()

    async def apply_issuer_context(_transaction) -> None:
        return None

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        require_revocation_binding,
    )
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_issuer_context,
    )

    approval_task = asyncio.create_task(
        application_routes.approve_application(
            application_id=app.id,
            approval=ApplicationApproval(review_notes="Approve"),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    )
    await approval_reached_dependency_gate.wait()
    rejection = await application_routes.reject_application(
        application_id=app.id,
        rejection=ApplicationRejection(review_notes="Reject"),
        trusted_organization_id=app.organization_id,
        repo=repo,
    )
    assert rejection.status == expected["final_application_status"]

    allow_approval_to_reserve.set()
    with pytest.raises(HTTPException) as raised:
        await approval_task
    assert raised.value.status_code == expected["approval_loser_status"]
    assert raised.value.detail == expected["approval_loser_detail"]

    stored = await repo.get_application(app.id)
    assert stored is not None
    assert stored.status.value == expected["final_application_status"]
    assert len(await repo.list_transactions(app.organization_id)) == expected[
        "transaction_count"
    ]


@pytest.mark.asyncio
async def test_concurrent_approvals_reserve_exactly_one_transaction(monkeypatch) -> None:
    expected = CONTRACT["lifecycle"]["concurrent_transition"][
        "approval_approval_race"
    ]
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-double-approval",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
        form_data={"employee_id": "E-1"},
    )
    await repo.save_application_template(
        ApplicationTemplate(
            id=app.application_template_id,
            organization_id=app.organization_id,
            name="Membership",
            credential_template_id="credential-template-1",
            status="ACTIVE",
        )
    )
    await repo.save_application(app)

    issuer_context_waiters = 0
    both_prepared = asyncio.Event()
    release_reservations = asyncio.Event()

    async def fetch_template(_template_id: str):
        return _valid_live_credential_template()

    async def require_revocation_binding(**_kwargs) -> None:
        return None

    async def apply_issuer_context(transaction) -> None:
        nonlocal issuer_context_waiters
        issuer_context_waiters += 1
        if issuer_context_waiters == 2:
            both_prepared.set()
        await release_reservations.wait()
        transaction.issuer_profile_id = "issuer-profile-1"
        transaction.signing_service_id = "kms-service-1"

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        require_revocation_binding,
    )
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_issuer_context,
    )

    tasks = [
        asyncio.create_task(
            application_routes.approve_application(
                application_id=app.id,
                approval=ApplicationApproval(review_notes=f"Approve {index}"),
                trusted_organization_id=app.organization_id,
                repo=repo,
            )
        )
        for index in range(2)
    ]
    await both_prepared.wait()
    release_reservations.set()
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)

    successes = [outcome for outcome in outcomes if isinstance(outcome, ApplicationResponse)]
    conflicts = [outcome for outcome in outcomes if isinstance(outcome, HTTPException)]
    assert len(successes) == expected["success_count"]
    assert len(conflicts) == expected["conflict_count"]
    assert conflicts[0].status_code == expected["conflict_status"]
    stored = await repo.get_application(app.id)
    assert stored is not None
    assert stored.status.value == expected["final_application_status"]
    assert len(await repo.list_transactions(app.organization_id)) == expected[
        "transaction_count"
    ]


@pytest.mark.asyncio
async def test_rejection_wins_forced_evidence_race_without_retaining_submission() -> None:
    expected = CONTRACT["lifecycle"]["concurrent_transition"][
        "evidence_rejection_race"
    ]
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-evidence-race",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
    )
    await repo.save_application(app)
    original_save = repo.save_application_if_status
    evidence_reached_commit = asyncio.Event()
    allow_evidence_commit = asyncio.Event()

    async def controlled_save(
        candidate,
        *,
        expected_status,
        expected_updated_at=None,
    ):
        if candidate.status == ApplicationStatus.PENDING and candidate.evidence_submissions:
            evidence_reached_commit.set()
            await allow_evidence_commit.wait()
        return await original_save(
            candidate,
            expected_status=expected_status,
            expected_updated_at=expected_updated_at,
        )

    repo.save_application_if_status = controlled_save  # type: ignore[method-assign]
    evidence_task = asyncio.create_task(
        application_routes.submit_evidence(
            application_id=app.id,
            evidence=EvidenceSubmission(
                evidence_type="DOCUMENT_SCAN",
                evidence_data={"document": "passport"},
            ),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    )
    await evidence_reached_commit.wait()
    rejection = await application_routes.reject_application(
        application_id=app.id,
        rejection=ApplicationRejection(review_notes="Reject"),
        trusted_organization_id=app.organization_id,
        repo=repo,
    )
    assert rejection.status == expected["final_application_status"]

    allow_evidence_commit.set()
    with pytest.raises(HTTPException) as raised:
        await evidence_task
    assert raised.value.status_code == expected["evidence_loser_status"]
    assert raised.value.detail == expected["evidence_loser_detail"]
    stored = await repo.get_application(app.id)
    assert stored is not None
    assert stored.status.value == expected["final_application_status"]
    assert len(stored.evidence_submissions) == expected["evidence_submission_count"]


@pytest.mark.asyncio
async def test_offer_generation_replay_and_issued_transaction_read_match_contract(
    monkeypatch,
) -> None:
    expected = CONTRACT["lifecycle"]["offer_replay_success"]
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-1",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
        form_data={"employee_id": "E-1"},
        status=ApplicationStatus(expected["application_status"]),
    )
    template = ApplicationTemplate(
        id=app.application_template_id,
        organization_id=app.organization_id,
        name="Membership",
        credential_template_id="credential-template-1",
        status="ACTIVE",
    )
    await repo.save_application_template(template)
    await repo.save_application(app)

    async def fetch_template(_template_id: str):
        return _valid_live_credential_template()

    async def apply_issuer_context(transaction) -> None:
        transaction.issuer_profile_id = "issuer-profile-1"
        transaction.signing_service_id = "kms-service-1"

    async def require_revocation_binding(**_kwargs) -> None:
        return None

    async def fetch_wallets(_template_id: str):
        wallet = expected["wallet"]
        return [
            IssuanceOfferWallet(
                id=wallet["id"],
                name=wallet["name"],
                logo_url=wallet["logo_url"],
                deep_link_url="",
                platforms=wallet["platforms"],
            )
        ]

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_issuer_context,
    )
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        require_revocation_binding,
    )
    monkeypatch.setattr(application_routes, "_fetch_wallets_for_template", fetch_wallets)

    first = await application_routes.generate_issuance_offer(
        application_id=app.id,
        trusted_organization_id=app.organization_id,
        repo=repo,
    )
    second = await application_routes.generate_issuance_offer(
        application_id=app.id,
        trusted_organization_id=app.organization_id,
        repo=repo,
    )

    assert second.transaction_id == first.transaction_id
    assert second.offer_url == first.offer_url
    assert second.qr_payload == first.offer_url
    assert second.offer_url.startswith(expected["offer_scheme"])
    assert second.status == expected["offer_status"]
    assert second.email_payload["subject"] == expected["email_subject"]
    assert second.email_payload["offer_url"] == second.offer_url
    assert second.wallets[0].model_dump(exclude={"deep_link_url"}) == expected["wallet"]
    assert second.wallets[0].deep_link_url == second.offer_url
    assert second.credential_offer_uris == {}
    transactions = await repo.list_transactions(app.organization_id)
    assert len(transactions) == expected["transaction_count_after_two_generations"]

    generation_events = await repo.list_events_for_application(app.id)

    issued_repo = InMemoryIssuanceRepository()
    issued_transaction = IssuanceTransaction(
        id="issued-transaction",
        organization_id=app.organization_id,
        credential_template_id=template.credential_template_id,
        application_id=app.id,
        applicant_id=app.applicant_identifier,
        credential_type="EmployeeCredential",
        status=IssuanceStatus(expected["transaction_status_still_readable"]),
    )
    issued_app = deepcopy(app)
    issued_app.issuance_transaction_id = issued_transaction.id
    await issued_repo.save_application_template(template)
    await issued_repo.save_transaction(issued_transaction)
    await issued_repo.save_application(issued_app)
    read = await application_routes.get_issuance_offer(
        application_id=issued_app.id,
        trusted_organization_id=issued_app.organization_id,
        repo=issued_repo,
    )
    assert read.transaction_id == issued_transaction.id
    assert read.offer_url.startswith(expected["offer_scheme"])
    assert read.status == expected["offer_status"]

    read_events = await issued_repo.list_events_for_application(issued_app.id)
    assert [
        event.event_type.value for event in [*generation_events, *read_events]
    ] == expected["event_types"]


@pytest.mark.asyncio
async def test_concurrent_offer_generation_reserves_one_transaction(
    monkeypatch,
) -> None:
    expected = CONTRACT["lifecycle"]["offer_replay_success"]
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-concurrent",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
        form_data={"employee_id": "E-1"},
        status=ApplicationStatus.APPROVED,
    )
    await repo.save_application_template(
        ApplicationTemplate(
            id=app.application_template_id,
            organization_id=app.organization_id,
            name="Membership",
            credential_template_id="credential-template-1",
            status="ACTIVE",
        )
    )
    await repo.save_application(app)

    async def fetch_template(_template_id: str):
        return _valid_live_credential_template()

    arrivals = 0
    both_resolvers_ready = asyncio.Event()

    async def apply_issuer_context(transaction) -> None:
        nonlocal arrivals
        transaction.issuer_profile_id = "issuer-profile-1"
        transaction.signing_service_id = "kms-service-1"
        arrivals += 1
        if arrivals == 2:
            both_resolvers_ready.set()
        await both_resolvers_ready.wait()

    async def require_revocation_binding(**_kwargs) -> None:
        return None

    async def fetch_wallets(_template_id: str):
        return []

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_issuer_context,
    )
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        require_revocation_binding,
    )
    monkeypatch.setattr(application_routes, "_fetch_wallets_for_template", fetch_wallets)

    first, second = await asyncio.gather(
        application_routes.generate_issuance_offer(
            application_id=app.id,
            trusted_organization_id=app.organization_id,
            repo=repo,
        ),
        application_routes.generate_issuance_offer(
            application_id=app.id,
            trusted_organization_id=app.organization_id,
            repo=repo,
        ),
    )

    assert arrivals == 2
    assert (first.transaction_id == second.transaction_id) is expected[
        "concurrent_responses_share_offer"
    ]
    assert (first.offer_url == second.offer_url) is expected[
        "concurrent_responses_share_offer"
    ]
    transactions = await repo.list_transactions(app.organization_id)
    assert len(transactions) == expected[
        "transaction_count_after_concurrent_generation"
    ]
    transaction = transactions[0]
    assert len(transaction.idempotency_key_hash or "") == expected[
        "reservation_hash_length"
    ]
    assert len(transaction.idempotency_request_hash or "") == expected[
        "reservation_hash_length"
    ]
    raw_key = f"internal-application-offer:{app.id}:initial"
    assert (transaction.idempotency_key_hash == raw_key) is expected[
        "raw_reservation_key_persisted"
    ]


async def _invoke_invalid_transition(
    operation: str, app: Application, repo: InMemoryIssuanceRepository
) -> None:
    if operation == "submit_evidence":
        await application_routes.submit_evidence(
            application_id=app.id,
            evidence=EvidenceSubmission(
                evidence_type="DOCUMENT_SCAN", evidence_data={"digest": "sha256:1"}
            ),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    elif operation == "approve":
        await application_routes.approve_application(
            application_id=app.id,
            approval=ApplicationApproval(review_notes="approved"),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    elif operation == "reject":
        await application_routes.reject_application(
            application_id=app.id,
            rejection=ApplicationRejection(review_notes="rejected"),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    elif operation == "run_external_evidence_api_check":
        await application_routes.run_external_evidence_api_check(
            application_id=app.id,
            check_id="check-1",
            request=ExternalEvidenceApiCheckRequest(),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    elif operation == "generate_issuance_offer":
        await application_routes.generate_issuance_offer(
            application_id=app.id,
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    elif operation == "get_issuance_offer":
        await application_routes.get_issuance_offer(
            application_id=app.id,
            trusted_organization_id=app.organization_id,
            repo=repo,
        )
    else:  # pragma: no cover - the contract inventory owns this branch
        raise AssertionError(f"Unsupported contract operation: {operation}")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    CONTRACT["lifecycle"]["invalid_state_cases"],
    ids=lambda case: case["id"],
)
async def test_invalid_lifecycle_transitions_preserve_exact_application(case) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-1",
        organization_id="org-123",
        application_template_id="template-1",
        applicant_identifier="applicant-1",
        status=ApplicationStatus(case["application_status"]),
    )
    await repo.save_application(app)
    before = asdict(deepcopy(app))

    with pytest.raises(HTTPException) as raised:
        await _invoke_invalid_transition(case["operation"], app, repo)

    assert raised.value.status_code == case["status"]
    assert raised.value.detail == case["detail"]
    stored = await repo.get_application(app.id)
    assert stored is not None
    assert asdict(stored) == before


@pytest.mark.asyncio
async def test_pending_evidence_and_rejection_successes_match_contract() -> None:
    repo = InMemoryIssuanceRepository()
    evidence_app = Application(
        id="application-evidence",
        organization_id="org-123",
        application_template_id="template-1",
        applicant_identifier="applicant-1",
    )
    rejection_app = Application(
        id="application-rejection",
        organization_id="org-123",
        application_template_id="template-1",
        applicant_identifier="applicant-2",
    )
    await repo.save_application(evidence_app)
    await repo.save_application(rejection_app)

    evidence_response = await application_routes.submit_evidence(
        application_id=evidence_app.id,
        evidence=EvidenceSubmission(
            evidence_type="DOCUMENT_SCAN", evidence_data={"digest": "sha256:1"}
        ),
        trusted_organization_id="org-123",
        repo=repo,
    )
    assert evidence_response.status == ApplicationStatus.PENDING.value
    assert evidence_response.evidence_submissions[0]["evidence_type"] == "DOCUMENT_SCAN"
    assert evidence_response.evidence_submissions[0]["evidence_data"] == {
        "digest": "sha256:1"
    }
    assert evidence_response.evidence_submissions[0]["submitted_at"].endswith("+00:00")

    rejection_response = await application_routes.reject_application(
        application_id=rejection_app.id,
        rejection=ApplicationRejection(review_notes="insufficient evidence"),
        trusted_organization_id="org-123",
        repo=repo,
    )
    assert rejection_response.status == ApplicationStatus.REJECTED.value
    assert rejection_response.review_notes == "insufficient evidence"
    assert rejection_response.reviewer_id == CONTRACT["lifecycle"]["reviewer_id"]
    assert rejection_response.reviewed_at is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    CONTRACT["lifecycle"]["external_api_failure_cases"],
    ids=lambda case: case["id"],
)
async def test_external_api_failures_are_atomic_and_do_not_leak_secrets(
    monkeypatch, case
) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-1",
        organization_id="org-123",
        application_template_id="application-template-1",
        applicant_identifier="applicant-1",
    )
    await repo.save_application(app)
    if case["arrange"] != "missing_template":
        requirements = []
        if case["arrange"] != "missing_requirement":
            requirement = {
                "evidence_id": "check-1",
                "evidence_type": "EXTERNAL_API",
            }
            if case["arrange"] != "invalid_configuration":
                requirement["api"] = {
                    "method": "POST",
                    "url": "https://provider.example/check",
                }
            requirements = [requirement]
        await repo.save_application_template(
            ApplicationTemplate(
                id=app.application_template_id,
                organization_id=app.organization_id,
                name="Membership",
                evidence_requirements=requirements,
                status="ACTIVE",
            )
        )

    if case["arrange"] == "provider_transport":

        async def execute_check(**_kwargs):
            raise httpx.ReadTimeout("Bearer secret-token")

        monkeypatch.setattr(
            application_routes, "execute_external_evidence_api_check", execute_check
        )
    before = asdict(deepcopy(app))

    with pytest.raises(HTTPException) as raised:
        await application_routes.run_external_evidence_api_check(
            application_id=app.id,
            check_id="check-1",
            request=ExternalEvidenceApiCheckRequest(),
            trusted_organization_id=app.organization_id,
            repo=repo,
        )

    assert raised.value.status_code == case["status"]
    assert raised.value.detail == case["detail"]
    if forbidden := case.get("forbidden_detail"):
        assert forbidden not in str(raised.value.detail)
    stored = await repo.get_application(app.id)
    assert stored is not None
    assert asdict(stored) == before
    assert await repo.list_evidence_facts_for_application(app.id) == []
    assert await repo.list_transactions(app.organization_id) == []


def test_contract_authorizes_rust_only_after_behavior_freeze_is_complete() -> None:
    coverage = CONTRACT["coverage"]
    assert coverage["rust_implementation_authorized"] is True
    assert coverage["required_before_rust_implementation"] == []
    assert {
        "external_evidence_failure_injection_and_postgres_write_set_replay",
        "reconciliation_failure_injection_and_postgres_write_set_replay",
    }.issubset(coverage["implemented_case_groups"])
