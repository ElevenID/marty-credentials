import asyncio
import json
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

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


def test_unsupported_sibling_routes_remain_unowned() -> None:
    app = FastAPI()
    app.include_router(internal_application_router)
    client = TestClient(app)

    for case in CONTRACT["surface"]["unsupported_siblings"]:
        response = client.request(case["method"], case["path"])
        assert response.status_code == case["status"], case["path"]


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

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
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
    stored = await repo.get_application(app.id)
    assert stored is not None
    assert asdict(stored) == before
    assert await repo.list_transactions(app.organization_id) == []


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

    monkeypatch.setattr(application_routes, "_fetch_credential_template", fetch_template)
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


def test_contract_does_not_authorize_rust_before_behavior_freeze_is_complete() -> None:
    coverage = CONTRACT["coverage"]
    assert coverage["rust_implementation_authorized"] is False
    assert coverage["required_before_rust_implementation"]
