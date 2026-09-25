"""Language-neutral HTTP boundary and response floor for retention migration."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import routes

CONTRACT = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts/issuance-retention-management.json").read_text(
        encoding="utf-8"
    )
)
COUNTS = {
    "issuance_transactions": 1,
    "applications": 2,
    "authorization_sessions": 3,
    "issuance_events": 4,
    "issued_credentials": 1,
    "total": 11,
}


class _Repository:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []

    def _result(self, org_id: str, days: int) -> dict:
        return {
            "organization_id": org_id,
            "retention_days": days,
            "cutoff_at": "2026-01-01T00:00:00+00:00",
            "oldest_retained_record_at": "2026-01-02T00:00:00+00:00",
            "next_expiry_at": "2026-02-01T00:00:00+00:00",
            "tracked_scope": CONTRACT["tracked_scope"],
        }

    async def get_retention_summary(self, org_id: str, days: int) -> dict:
        self.calls.append(("summary", org_id, days))
        return {**self._result(org_id, days), "eligible_for_purge": COUNTS}

    async def purge_retention_records(self, org_id: str, days: int) -> dict:
        self.calls.append(("purge", org_id, days))
        return {
            **self._result(org_id, days),
            "purged_at": "2026-02-01T00:00:00+00:00",
            "purged_records": COUNTS,
        }


def _client(monkeypatch, *, raise_server_exceptions: bool = True) -> tuple[TestClient, _Repository]:
    monkeypatch.setattr(routes, "_ISSUANCE_API_KEY", "synthetic-management-key")
    repository = _Repository()
    app = FastAPI()
    app.include_router(routes.issuance_router)
    app.dependency_overrides[IIssuanceRepository] = lambda: repository
    return TestClient(app, raise_server_exceptions=raise_server_exceptions), repository


def test_retention_routes_are_complete_and_management_authenticated() -> None:
    assert CONTRACT["schema"] == "marty.issuance-retention-management/v1"
    for expected in CONTRACT["routes"]:
        matches = [
            route
            for route in routes.issuance_router.routes
            if expected["method"] in route.methods
            and route.path == expected["path"]
            and route.endpoint.__name__ == expected["operation"]
        ]
        assert len(matches) == 1
        assert routes._verify_management_api_key in {
            dependency.call for dependency in matches[0].dependant.dependencies
        }


def test_retention_auth_and_tenant_boundary_precede_any_repository_call(monkeypatch) -> None:
    client, repository = _client(monkeypatch)
    for route in CONTRACT["routes"]:
        path = route["path"].replace("{organization_id}", "organization-a")
        request = client.get if route["method"] == "GET" else client.post
        for headers, expected_status in (
            ({}, CONTRACT["boundary"]["missing_api_key"]),
            ({"X-API-Key": "wrong"}, CONTRACT["boundary"]["invalid_api_key"]),
            (
                {"X-API-Key": "synthetic-management-key"},
                CONTRACT["boundary"]["missing_trusted_organization"],
            ),
            (
                {"X-API-Key": "synthetic-management-key", "X-Organization-ID": "organization-b"},
                CONTRACT["boundary"]["different_trusted_organization"],
            ),
        ):
            assert request(path, headers=headers).status_code == expected_status
            assert repository.calls == []


def test_retention_responses_defaults_bounds_and_counts(monkeypatch) -> None:
    client, repository = _client(monkeypatch)
    headers = {
        "X-API-Key": "synthetic-management-key",
        "X-Organization-ID": "organization-a",
    }
    assert sorted(COUNTS) == sorted(CONTRACT["record_count_fields"])
    for route in CONTRACT["routes"]:
        path = route["path"].replace("{organization_id}", "organization-a")
        request = client.get if route["method"] == "GET" else client.post
        for invalid_days in (0, 3651):
            assert request(path, params={"retention_days": invalid_days}, headers=headers).status_code == (
                CONTRACT["retention_days"]["invalid"]
            )
        assert request(path, headers=headers).json()["retention_days"] == CONTRACT["retention_days"][
            "default"
        ]
        for days in (CONTRACT["retention_days"]["minimum"], CONTRACT["retention_days"]["maximum"]):
            response = request(path, params={"retention_days": days}, headers=headers)
            assert response.status_code == CONTRACT["boundary"]["authorized"]
            body = response.json()
            assert body["organization_id"] == "organization-a"
            assert body["retention_days"] == days
            assert body["tracked_scope"] == CONTRACT["tracked_scope"]
            counts = body["eligible_for_purge" if route["method"] == "GET" else "purged_records"]
            assert counts == COUNTS
    assert repository.calls == [
        (operation, "organization-a", days)
        for operation in ("summary", "purge")
        for days in (30, 1, 3650)
    ]


def test_retention_repository_failure_is_generic_for_both_routes(monkeypatch) -> None:
    client, repository = _client(monkeypatch, raise_server_exceptions=False)
    calls = []

    async def fail_summary(org_id: str, days: int) -> dict:
        calls.append(("summary", org_id, days))
        raise RuntimeError("synthetic-private-repository-detail")

    async def fail_purge(org_id: str, days: int) -> dict:
        calls.append(("purge", org_id, days))
        raise RuntimeError("synthetic-private-repository-detail")

    repository.get_retention_summary = fail_summary
    repository.purge_retention_records = fail_purge
    headers = {
        "X-API-Key": "synthetic-management-key",
        "X-Organization-ID": "organization-a",
    }
    failure = CONTRACT["repository_failure"]
    for route in CONTRACT["routes"]:
        path = route["path"].replace("{organization_id}", "organization-a")
        request = client.get if route["method"] == "GET" else client.post
        response = request(path, headers=headers)
        assert response.status_code == failure["status"]
        assert response.text == failure["body"]
        assert "synthetic-private-repository-detail" not in response.text
    assert calls == [("summary", "organization-a", 30), ("purge", "organization-a", 30)]


@pytest.mark.asyncio
async def test_retention_repository_preserves_new_and_other_tenant_records() -> None:
    """Freeze the data rule separately from the HTTP response adapter."""
    repository = InMemoryIssuanceRepository()
    now = datetime.now(UTC)
    old, recent = now - timedelta(days=40), now - timedelta(days=5)
    repository._transactions = {
        "old-a": SimpleNamespace(id="old-a", organization_id="organization-a", created_at=old),
        "new-a": SimpleNamespace(id="new-a", organization_id="organization-a", created_at=recent),
        "old-b": SimpleNamespace(id="old-b", organization_id="organization-b", created_at=old),
    }
    repository._applications = {
        "app-a": SimpleNamespace(id="app-a", organization_id="organization-a", created_at=old),
        "app-b": SimpleNamespace(id="app-b", organization_id="organization-b", created_at=old),
    }
    repository._authorization_sessions = {
        "auth-a": SimpleNamespace(organization_id="organization-a", created_at=old),
        "auth-b": SimpleNamespace(organization_id="organization-b", created_at=old),
    }
    repository._credentials = {
        "cred-a": SimpleNamespace(id="cred-a", organization_id="organization-a", transaction_id="old-a"),
        "cred-b": SimpleNamespace(id="cred-b", organization_id="organization-b", transaction_id="old-b"),
    }
    repository._events = [
        SimpleNamespace(transaction_id=transaction_id, application_id=None, created_at=old)
        for transaction_id in ("old-a", "old-b")
    ]
    repository._events.append(
        SimpleNamespace(transaction_id="old-a", application_id=None, created_at=recent)
    )

    before = await repository.get_retention_summary("organization-a", 30)
    assert before["eligible_for_purge"] == {
        "issuance_transactions": 1,
        "applications": 1,
        "authorization_sessions": 1,
        "issuance_events": 1,
        "issued_credentials": 1,
        "total": 5,
    }
    assert before["tracked_scope"] == CONTRACT["tracked_scope"]
    assert before["oldest_retained_record_at"] == recent.isoformat()
    assert before["next_expiry_at"] == (recent + timedelta(days=30)).isoformat()

    purged = await repository.purge_retention_records("organization-a", 30)
    assert purged["purged_records"] == before["eligible_for_purge"]
    assert set(repository._transactions) == {"new-a", "old-b"}
    assert set(repository._applications) == {"app-b"}
    assert set(repository._authorization_sessions) == {"auth-b"}
    assert set(repository._credentials) == {"cred-b"}
    assert [event.transaction_id for event in repository._events] == ["old-b", "old-a"]
    assert (
        await repository.get_retention_summary("organization-a", 30)
    )["oldest_retained_record_at"] == recent.isoformat()
    assert repository._event_belongs_to_org(repository._events[1], "organization-a")
    again = await repository.purge_retention_records("organization-a", 30)
    assert again["purged_records"]["total"] == 0
