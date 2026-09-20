import json
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from issuance.domain.entities import ApplicationStatus
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


def test_contract_does_not_authorize_rust_before_behavior_freeze_is_complete() -> None:
    coverage = CONTRACT["coverage"]
    assert coverage["rust_implementation_authorized"] is False
    assert coverage["required_before_rust_implementation"]
