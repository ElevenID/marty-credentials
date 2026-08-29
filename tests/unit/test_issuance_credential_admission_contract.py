from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from issuance.domain.entities import (
    CredentialStatus,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import routes
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-credential-admission.json").read_text(encoding="utf-8")
)


class ContractRepository:
    def __init__(self, setup: str) -> None:
        self._delegate = InMemoryIssuanceRepository()
        self.setup = setup
        self.calls: list[dict[str, str]] = []
        status = {
            "issued_with_credential": IssuanceStatus.ISSUED,
            "issued_without_credential": IssuanceStatus.ISSUED,
            "pending_transaction": IssuanceStatus.PENDING,
        }.get(setup, IssuanceStatus.AUTHORIZED)
        self.transaction = IssuanceTransaction(
            id=CONTRACT["inputs"]["transaction_id"],
            organization_id=CONTRACT["inputs"]["organization_id"],
            credential_template_id="template-credential",
            status=status,
            access_token=CONTRACT["inputs"]["access_token"],
            nonce=CONTRACT["inputs"]["proof_nonce"],
            claims=(
                {"_dpop_jkt": "contract-dpop-jkt"} if setup == "dpop_bound_transaction" else {}
            ),
            credential_type=CONTRACT["inputs"]["credential_type"],
            credential_payload_format="w3c_vcdm_v2_sd_jwt",
            issuer_profile_id="issuer-profile-1",
            issuer_did_override="did:web:issuer.example",
            issuer_algorithm="ES256",
        )
        self.issued_credential = IssuedCredential(
            id="credential-canonical",
            transaction_id=self.transaction.id,
            organization_id=self.transaction.organization_id,
            credential_template_id=self.transaction.credential_template_id,
            credential_jwt="signed-credential",
            credential_hash="credential-hash",
            status=CredentialStatus.ACTIVE,
            issued_at=datetime(2026, 8, 20, 12, 0, tzinfo=UTC),
        )

    async def get_by_access_token(self, access_token: str) -> Any:
        self.calls.append({"method": "get_by_access_token", "value": access_token})
        if self.setup == "missing_transaction" or access_token != self.transaction.access_token:
            return None
        return self.transaction

    async def get_authorization_session_by_access_token(self, access_token: str) -> None:
        self.calls.append(
            {"method": "get_authorization_session_by_access_token", "value": access_token}
        )
        return None

    async def get_credential_by_transaction_id(self, transaction_id: str) -> Any:
        self.calls.append({"method": "get_credential_by_transaction_id", "value": transaction_id})
        if self.setup == "issued_with_credential":
            return self.issued_credential
        return None

    async def consume_proof_nonce(self, nonce: str) -> bool:
        self.calls.append({"method": "consume_proof_nonce", "value": nonce})
        if self.setup == "nonce_store_unavailable":
            raise RuntimeError("contract nonce store unavailable")
        return self.setup != "nonce_replayed"

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


def encode(value: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )


def proof(kind: str) -> str:
    if kind == "malformed":
        return "malformed"
    audience = {
        "wrong_audience": "https://issuer.example/org/other",
        "prefixed_audience": "https://issuer.example/evil/org/org-a",
        "alternate_scheme_audience": "http://issuer.example/org/org-a",
        "alternate_host_audience": "https://other.example/org/org-a",
        "alternate_port_audience": "https://issuer.example:444/org/org-a",
        "userinfo_audience": "https://issuer.example@other.example/org/org-a",
        "relative_audience": "/org/org-a",
    }.get(kind, CONTRACT["inputs"]["proof_audience"])
    payload = {"aud": audience}
    if kind != "missing_nonce":
        payload["nonce"] = CONTRACT["inputs"]["proof_nonce"]
    return f"{encode({'alg': 'ES256'})}.{encode(payload)}.signature"


def request(headers: dict[str, str]) -> Request:
    raw_headers = [(b"host", b"issuer.example")]
    raw_headers.extend((name.lower().encode(), value.encode()) for name, value in headers.items())
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/v1/issuance/credential",
            "raw_path": b"/v1/issuance/credential",
            "query_string": b"",
            "headers": raw_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("issuer.example", 443),
        }
    )


async def invoke(
    case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    *,
    verification_error: str = "invalid signature",
) -> tuple[int, Any, list]:
    repository = ContractRepository(case["setup"])

    async def issuer_context(_transaction: Any, **_kwargs: Any) -> dict[str, Any]:
        return {}

    async def verify_proof(*_args: Any, **_kwargs: Any) -> tuple:
        assert _kwargs["issuer_url"] == CONTRACT["inputs"]["proof_audience"]
        if case["setup"] == "invalid_signature":
            return False, "", None, verification_error
        return True, "did:key:contract-holder", {}, None

    def validate_dpop(value: str, **_kwargs: Any) -> str:
        if value == "invalid-dpop":
            raise ValueError("invalid DPoP")
        if value == "other-dpop":
            return "other-dpop-jkt"
        return "contract-dpop-jkt"

    monkeypatch.setattr(routes, "apply_remote_issuer_context", issuer_context)
    monkeypatch.setattr(routes, "verify_oid4vci_proof_with_issuer_policy", verify_proof)
    monkeypatch.setattr(routes, "_validated_dpop_jkt", validate_dpop)
    monkeypatch.setattr(routes, "ISSUER_BASE_URL", "https://issuer.example")
    monkeypatch.setattr(
        uuid,
        "uuid4",
        lambda: uuid.UUID(CONTRACT["inputs"]["notification_id"]),
    )

    request_values = dict(case["request"])
    proof_kind = request_values.pop("proof", None)
    if proof_kind is not None:
        request_values["proofs"] = {"jwt": [proof(proof_kind)]}
    credential_request = routes.CredentialRequest(**request_values)
    try:
        response = await routes.issue_credential(
            request(case.get("headers", {})),
            credential_request,
            authorization=case.get("authorization"),
            repo=repository,
        )
    except HTTPException as error:
        return error.status_code, {"detail": error.detail}, repository.calls
    if isinstance(response, JSONResponse):
        return response.status_code, json.loads(response.body), repository.calls
    return 200, response.model_dump(exclude_none=True), repository.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CONTRACT["cases"], ids=lambda case: case["name"])
async def test_credential_admission_matches_language_neutral_contract(
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
) -> None:
    status_code, body, repository_calls = await invoke(case, monkeypatch)

    assert status_code == case["status_code"]
    assert body == case["body"]
    assert repository_calls == case["repository_calls"]


@pytest.mark.asyncio
async def test_credential_admission_logs_do_not_reflect_proof_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    case = next(
        item
        for item in CONTRACT["cases"]
        if item["name"] == "invalid_signature_does_not_consume_nonce"
    )
    sensitive_error = "proof-error-MUST-NOT-ENTER-LOGS-4a2f6dc1"
    caplog.set_level(logging.INFO, logger="issuance.infrastructure.api.routes")

    status_code, _, _ = await invoke(
        case,
        monkeypatch,
        verification_error=sensitive_error,
    )

    assert status_code == case["status_code"]
    route_records = [
        record for record in caplog.records if record.name == "issuance.infrastructure.api.routes"
    ]
    assert route_records
    rendered_logs = "\n".join(record.getMessage() for record in route_records)
    structured_logs = "\n".join(repr(record.__dict__) for record in route_records)
    assert sensitive_error not in rendered_logs
    assert sensitive_error not in structured_logs
    assert "proof verification failed" in rendered_logs


@pytest.mark.asyncio
async def test_credential_admission_logs_do_not_echo_proof_audiences(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    case = next(
        item
        for item in CONTRACT["cases"]
        if item["name"] == "proof_audience_rejects_alternate_host"
    )
    unexpected_audience = "https://other.example/org/org-a"
    expected_paths = routes._allowed_credential_issuer_audience_paths("org-a")
    caplog.set_level(logging.INFO, logger="issuance.infrastructure.api.routes")

    status_code, _, _ = await invoke(case, monkeypatch)

    assert status_code == case["status_code"]
    route_records = [
        record for record in caplog.records if record.name == "issuance.infrastructure.api.routes"
    ]
    assert route_records
    rendered_logs = "\n".join(record.getMessage() for record in route_records)
    structured_logs = "\n".join(repr(record.__dict__) for record in route_records)
    for sensitive_value in (unexpected_audience, *expected_paths):
        assert sensitive_value not in rendered_logs
        assert sensitive_value not in structured_logs
    assert "proof audience did not match configured issuer" in rendered_logs


def test_credential_admission_contract_has_required_security_boundaries() -> None:
    assert CONTRACT["schema"] == "marty.issuance-credential-admission/v1"
    names = {case["name"] for case in CONTRACT["cases"]}
    assert len(names) == len(CONTRACT["cases"]) == 26
    assert {
        "proof_audience_rejects_alternate_scheme",
        "proof_audience_rejects_alternate_host",
        "proof_audience_rejects_unconfigured_port",
        "proof_audience_rejects_userinfo_confusion",
        "proof_audience_rejects_relative_url",
        "invalid_signature_does_not_consume_nonce",
        "proof_nonce_is_single_use",
        "proof_nonce_store_fails_closed",
        "dpop_bound_token_requires_proof",
        "invalid_dpop_proof",
        "dpop_key_must_match_access_token",
        "issued_retry_returns_canonical_credential",
    } <= names
