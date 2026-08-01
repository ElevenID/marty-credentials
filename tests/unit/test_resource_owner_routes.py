"""Tests for the gateway's service-authenticated resource-owner lookups."""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.api.routes import (
    _verify_management_api_key,
    resource_owner_router,
)


class _Repository:
    def __init__(self) -> None:
        self.transactions = {
            "transaction-b": SimpleNamespace(organization_id="organization-b")
        }
        self.credentials = {
            "credential-b": SimpleNamespace(organization_id="organization-b")
        }
        self.templates = {
            "template-b": SimpleNamespace(organization_id="organization-b")
        }

    async def get_transaction(self, resource_id: str):
        return self.transactions.get(resource_id)

    async def get_credential(self, resource_id: str):
        return self.credentials.get(resource_id)

    async def get_application_template(self, resource_id: str):
        return self.templates.get(resource_id)


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(resource_owner_router)
    app.dependency_overrides[IIssuanceRepository] = _Repository
    app.dependency_overrides[_verify_management_api_key] = lambda: "gateway-service-key"
    return TestClient(app)


def test_internal_owner_lookups_return_only_the_organization() -> None:
    client = _client()

    for path in (
        "/internal/v1/resource-owners/issuance-transactions/transaction-b",
        "/internal/v1/resource-owners/issued-credentials/credential-b",
        "/internal/v1/resource-owners/application-templates/template-b",
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json() == {"organization_id": "organization-b"}


def test_internal_owner_lookups_do_not_enumerate_missing_resources() -> None:
    client = _client()

    for path in (
        "/internal/v1/resource-owners/issuance-transactions/missing",
        "/internal/v1/resource-owners/issued-credentials/missing",
        "/internal/v1/resource-owners/application-templates/missing",
    ):
        response = client.get(path)
        assert response.status_code == 404
        assert response.json() == {"detail": "Resource not found"}


def test_internal_owner_lookups_require_the_management_key_dependency() -> None:
    for route in resource_owner_router.routes:
        assert _verify_management_api_key in [
            dependency.call for dependency in route.dependant.dependencies
        ]
