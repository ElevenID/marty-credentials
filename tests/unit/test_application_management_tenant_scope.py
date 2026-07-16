from __future__ import annotations

import inspect

import pytest
from fastapi import HTTPException, Request
from issuance.domain.entities import Application
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import application_routes
from issuance.infrastructure.api.routes import internal_application_router


def test_internal_application_routes_require_trusted_organization_dependency() -> None:
    endpoints = [
        route.endpoint
        for route in internal_application_router.routes
        if route.endpoint.__module__ == application_routes.__name__
    ]
    assert endpoints
    assert all(
        "trusted_organization_id" in inspect.signature(endpoint).parameters
        for endpoint in endpoints
    )


def test_application_management_rejects_missing_trusted_organization_header() -> None:
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/internal/applications",
            "headers": [],
        }
    )
    with pytest.raises(HTTPException) as rejected:
        application_routes._trusted_application_organization_id(request)
    assert rejected.value.status_code == 400


@pytest.mark.asyncio
async def test_application_management_returns_not_found_for_foreign_application() -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="application-owned-by-org-1",
        organization_id="org-1",
        application_template_id="template-1",
    )
    await repo.save_application(app)

    with pytest.raises(HTTPException) as rejected:
        await application_routes.get_application(
            app.id,
            trusted_organization_id="org-2",
            repo=repo,
        )
    assert rejected.value.status_code == 404


@pytest.mark.asyncio
async def test_application_management_rejects_foreign_organization_filter() -> None:
    repo = InMemoryIssuanceRepository()
    with pytest.raises(HTTPException) as rejected:
        await application_routes.list_applications(
            organization_id="org-1",
            trusted_organization_id="org-2",
            repo=repo,
        )
    assert rejected.value.status_code == 404
