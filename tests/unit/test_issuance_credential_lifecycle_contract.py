from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from issuance.domain.entities import CredentialStatus
from issuance.infrastructure.api import routes
from marty_proto.v1 import issuance_service_pb2 as pb2

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-credential-lifecycle.json").read_text(encoding="utf-8")
)


class RecordingRepository:
    def __init__(self, credential, calls: list[str]) -> None:
        self.credential = credential
        self.calls = calls

    async def get_credential(self, credential_id: str):
        if self.credential is None or self.credential.id != credential_id:
            return None
        return self.credential

    async def save_credential(self, credential) -> None:
        self.calls.append("persist-local-status")
        self.credential = credential


def credential(*, status: CredentialStatus = CredentialStatus.ACTIVE):
    return SimpleNamespace(
        id="credential-1",
        organization_id="org-1",
        credential_template_id="template-1",
        transaction_id="transaction-1",
        issuer_did="did:jwk:issuer",
        status=status,
        status_updated_at=datetime(2026, 8, 30, tzinfo=UTC),
        revoked=False,
        revoked_at=None,
        revocation_reason=None,
    )


def test_contract_freezes_http_and_grpc_surface() -> None:
    assert CONTRACT["schema"] == "marty.issuance-credential-lifecycle/v1"
    expected_http = {(entry["method"], entry["path"]) for entry in CONTRACT["scope"]["http"]}
    actual_http = {
        (method, route.path)
        for route in routes.issuance_router.routes
        for method in route.methods
        if (method, route.path) in expected_http
    }
    assert actual_http == expected_http

    service = pb2.DESCRIPTOR.services_by_name["IssuanceService"]
    assert set(CONTRACT["scope"]["grpc"]) <= {method.name for method in service.methods}


def test_contract_freezes_cross_transport_state_and_failure_policy() -> None:
    assert CONTRACT["mutation_order"] == [
        "load-credential",
        "enforce-resource-organization-when-http",
        "validate-transition",
        "publish-revocation-profile-status",
        "persist-local-status",
        "synchronize-canvas-delivery-records",
        "emit-grpc-stream-event",
        "return-response",
    ]
    assert CONTRACT["publication"] == {
        "revocation_profile": "required-before-local-persistence",
        "canvas_delivery_records": "after-local-persistence-with-failure-recorded-for-retry",
        "grpc_stream_event": "after-canonical-handler-success",
    }
    unavailable = next(
        failure
        for failure in CONTRACT["failures"]
        if failure["name"] == "revocation_publication_unavailable"
    )
    assert unavailable["local_status_changes"] == unavailable["stream_events"] == 0






@pytest.mark.asyncio
async def test_http_wrong_organization_is_hidden_before_mutation() -> None:
    calls: list[str] = []
    issued = credential()
    repo = RecordingRepository(issued, calls)
    wrong_organization = SimpleNamespace(headers={"X-Organization-ID": "org-other"})

    with pytest.raises(HTTPException) as read_error:
        await routes.get_credential_status(
            issued.id,
            http_request=wrong_organization,
            repo=repo,
        )
    assert read_error.value.status_code == 404
    assert read_error.value.detail == "Resource not found"

    with pytest.raises(HTTPException) as mutation_error:
        await routes.revoke_credential(
            issued.id,
            routes.CredentialStatusRequest(reason="review"),
            repo,
            http_request=wrong_organization,
        )
    assert mutation_error.value.status_code == 404
    assert mutation_error.value.detail == "Resource not found"
    assert issued.status == CredentialStatus.ACTIVE
    assert calls == []
