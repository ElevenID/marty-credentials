"""Executable language-neutral contract for Application Template management."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

from issuance.domain.entities import ApplicationTemplate  # noqa: E402
from issuance.domain.ports import IIssuanceRepository  # noqa: E402
from issuance.infrastructure.adapters.memory_repository import (  # noqa: E402
    InMemoryIssuanceRepository,
)
from issuance.infrastructure.api import application_routes, routes  # noqa: E402

CONTRACT = json.loads(
    (ROOT / "contracts/issuance-application-templates.json").read_text(encoding="utf-8")
)


def _resolve_ref(reference: str) -> Any:
    assert reference.startswith("#/")
    value: Any = CONTRACT
    for segment in reference[2:].split("/"):
        value = value[segment]
    return deepcopy(value)


def _template_from_arrangement(values: dict[str, Any]) -> ApplicationTemplate:
    resolved = dict(values)
    overlay_ref = resolved.pop("overlay_ref", None)
    if overlay_ref:
        resolved.update(_resolve_ref(overlay_ref))
    resolved.setdefault("name", "Contract template")
    return ApplicationTemplate(**resolved)


def _contract_app(repo: InMemoryIssuanceRepository) -> FastAPI:
    app = FastAPI()
    app.include_router(routes.application_template_router)
    app.dependency_overrides[IIssuanceRepository] = lambda: repo
    return app


async def _persisted_templates(repo: InMemoryIssuanceRepository) -> list[ApplicationTemplate]:
    templates: list[ApplicationTemplate] = []
    for organization_id in ("org-123", "org-other"):
        templates.extend(await repo.list_application_templates(organization_id))
    return templates


def test_surface_security_dependencies_and_request_models_are_frozen() -> None:
    assert CONTRACT["schema"] == "marty.issuance-application-templates/v1"
    expected_routes = {
        (item["method"], item["path"], item["operation"]) for item in CONTRACT["surface"]["routes"]
    }
    actual_routes: set[tuple[str, str, str]] = set()
    for route in routes.application_template_router.routes:
        methods = route.methods or set()
        for method in methods - {"HEAD", "OPTIONS"}:
            actual_routes.add((method, route.path, route.endpoint.__name__))
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        assert routes._verify_management_api_key in dependencies
        assert application_routes._trusted_application_organization_id in dependencies
    assert actual_routes == expected_routes

    create_contract = CONTRACT["models"]["create"]
    assert set(routes.ApplicationTemplateCreate.model_fields) == {
        field["name"] for field in create_contract["fields"]
    }
    assert routes.ApplicationTemplateCreate.model_config["extra"] == "forbid"
    assert set(routes.ApplicationTemplatePatch.model_fields) == set(
        CONTRACT["models"]["patch"]["fields"]
    )
    assert routes.ApplicationTemplatePatch.model_config["extra"] == "forbid"
    assert set(routes.ApplicationTemplateResponse.model_fields) == set(
        CONTRACT["models"]["response_fields"]
    )

    canonical = routes.ApplicationTemplateCreate(
        **_resolve_ref("#/vectors/canonical_create/request")
    )
    assert canonical.approval_strategy == "MANUAL"
    assert canonical.application_validity_days == 30
    assert canonical.form_fields[0].options == [
        "PENDING",
        routes.ApplicationFieldOption(label="Cleared", value="CLEARED"),
    ]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        routes.ApplicationTemplateCreate(
            **_resolve_ref("#/vectors/canonical_create/request"),
            status="ACTIVE",
        )


@pytest.mark.asyncio
async def test_shared_http_cases_match_the_python_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routes, "_ISSUANCE_API_KEY", "valid")

    async def unexpected_catalog_lookup(_template_id: str) -> dict[str, Any] | None:
        raise AssertionError("tenant and missing-reference cases must not call the catalog")

    monkeypatch.setattr(
        application_routes,
        "_fetch_credential_template",
        unexpected_catalog_lookup,
    )

    for case in CONTRACT["cases"]:
        repo = InMemoryIssuanceRepository()
        for arranged in case["arrange"].get("application_templates", []):
            await repo.save_application_template(_template_from_arrangement(arranged))
        before = [deepcopy(template.__dict__) for template in await _persisted_templates(repo)]

        request = case["request"]
        body = _resolve_ref(request["json_ref"]) if "json_ref" in request else request.get("json")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=_contract_app(repo)),
            base_url="http://contract.test",
        ) as client:
            response = await client.request(
                request["method"],
                request["path"],
                headers=request.get("headers"),
                params=request.get("query"),
                json=body,
            )

        expected = case["expected"]
        assert response.status_code == expected["status"], case["name"]
        if expected.get("body_empty"):
            assert response.content == b"", case["name"]
        elif "json" in expected:
            expected_json = deepcopy(expected["json"])
            errors_ref = expected_json.pop("errors_ref", None)
            if errors_ref:
                expected_json["errors"] = _resolve_ref(errors_ref)
            assert response.json() == expected_json, case["name"]
        elif "body_contains_ref" in expected:
            response_json = response.json()
            for key, value in _resolve_ref(expected["body_contains_ref"]).items():
                assert response_json[key] == value, (case["name"], key)

        after_templates = await _persisted_templates(repo)
        if "persisted_template_count" in expected:
            assert len(after_templates) == expected["persisted_template_count"], case["name"]
        if expected.get("persisted_state") == "unchanged":
            assert [template.__dict__ for template in after_templates] == before, case["name"]


@pytest.mark.asyncio
async def test_management_authentication_and_tenant_header_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    app = _contract_app(repo)
    request_json = _resolve_ref("#/vectors/canonical_create/request")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://contract.test",
    ) as client:
        monkeypatch.setattr(routes, "_ISSUANCE_API_KEY", "")
        unconfigured = await client.post(
            "/v1/application-templates",
            headers={"X-Organization-ID": "org-123"},
            json=request_json,
        )
        assert (unconfigured.status_code, unconfigured.json()) == (
            503,
            {"detail": "ISSUANCE_API_KEY not configured on server"},
        )

        monkeypatch.setattr(routes, "_ISSUANCE_API_KEY", "valid")
        missing_key = await client.post(
            "/v1/application-templates",
            headers={"X-Organization-ID": "org-123"},
            json=request_json,
        )
        assert (missing_key.status_code, missing_key.json()) == (
            401,
            {"detail": "X-API-Key header is missing"},
        )

        wrong_key = await client.post(
            "/v1/application-templates",
            headers={"X-API-Key": "wrong", "X-Organization-ID": "org-123"},
            json=request_json,
        )
        assert (wrong_key.status_code, wrong_key.json()) == (
            401,
            {"detail": "Invalid API Key"},
        )

        missing_tenant = await client.post(
            "/v1/application-templates",
            headers={"X-API-Key": "valid"},
            json=request_json,
        )
        assert (missing_tenant.status_code, missing_tenant.json()) == (
            CONTRACT["security"]["missing_trusted_tenant"]["status"],
            {"detail": CONTRACT["security"]["missing_trusted_tenant"]["detail"]},
        )

    assert await _persisted_templates(repo) == []
