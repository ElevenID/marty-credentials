from __future__ import annotations

import base64
import copy
import json
import logging
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / "contracts/issuance-token-exchange.json").read_text(encoding="utf-8"))


class ContractRepository:
    def __init__(self, setup: str) -> None:
        from issuance.domain.entities import (
            AuthorizationSession,
            IssuanceStatus,
            IssuanceTransaction,
        )
        from issuance.infrastructure.adapters.memory_repository import (
            InMemoryIssuanceRepository,
        )

        self._delegate = InMemoryIssuanceRepository()
        self.calls: list[dict[str, str]] = []
        self.fail_transaction_claim = setup == "transaction_claim_lost"
        self.fail_authorization_claim = setup == "authorization_claim_lost"
        inputs = CONTRACT["inputs"]
        self.transaction = IssuanceTransaction(
            id=inputs["transaction_id"],
            organization_id=inputs["organization_id"],
            credential_template_id="template-token",
            pre_auth_code=inputs["pre_authorized_code"],
            status=IssuanceStatus(
                {
                    "authorized_transaction": "authorized",
                    "failed_transaction": "failed",
                }.get(setup, "pending")
            ),
            created_at=datetime.fromisoformat("2026-08-20T12:00:00+00:00"),
            expires_at=datetime.fromisoformat(
                "2000-08-20T12:15:00+00:00"
                if setup == "expired_transaction"
                else "2099-08-20T12:15:00+00:00"
            ),
        )
        self.authorization_session = AuthorizationSession(
            id=inputs["authorization_session_id"],
            code=inputs["authorization_code"],
            client_id=inputs["client_id"],
            organization_id=inputs["organization_id"],
            redirect_uri=(
                "https://wallet.example/callback"
                if setup in {"redirect_authorization_session", "pkce_authorization_session"}
                else None
            ),
            code_challenge=(
                base64.urlsafe_b64encode(sha256(b"correct-verifier").digest())
                .decode("ascii")
                .rstrip("=")
                if setup == "pkce_authorization_session"
                else None
            ),
            code_challenge_method=("S256" if setup == "pkce_authorization_session" else None),
            status=("exchanged" if setup == "exchanged_authorization_session" else "pending"),
            created_at=datetime.fromisoformat("2026-08-20T12:00:00+00:00"),
            expires_at=datetime.fromisoformat(
                "2000-08-20T12:15:00+00:00"
                if setup == "expired_authorization_session"
                else "2099-08-20T12:15:00+00:00"
            ),
        )
        self._setup = setup

    async def initialize(self) -> None:
        if self._setup in {
            "pending_transaction",
            "expired_transaction",
            "authorized_transaction",
            "failed_transaction",
            "transaction_claim_lost",
        }:
            await self._delegate.save_transaction(self.transaction)
        if self._setup in {
            "pending_authorization_session",
            "expired_authorization_session",
            "exchanged_authorization_session",
            "authorization_claim_lost",
            "redirect_authorization_session",
            "pkce_authorization_session",
        }:
            await self._delegate.save_authorization_session(self.authorization_session)

    async def get_by_pre_auth_code(self, code: str) -> Any:
        self.calls.append({"method": "get_by_pre_auth_code", "value": code})
        if self._setup == "repository_unavailable":
            raise RuntimeError("contract repository unavailable")
        return await self._delegate.get_by_pre_auth_code(code)

    async def claim_transaction_for_token(self, prepared: Any) -> Any:
        self.calls.append({"method": "claim_transaction_for_token", "value": prepared.id})
        if self.fail_transaction_claim:
            return None
        return await self._delegate.claim_transaction_for_token(prepared)

    async def get_authorization_session_by_code(self, code: str) -> Any:
        self.calls.append({"method": "get_authorization_session_by_code", "value": code})
        return await self._delegate.get_authorization_session_by_code(code)

    async def claim_authorization_session_for_token(self, prepared: Any) -> Any:
        self.calls.append({"method": "claim_authorization_session_for_token", "value": prepared.id})
        if self.fail_authorization_claim:
            return None
        return await self._delegate.claim_authorization_session_for_token(prepared)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)

    async def final_state(self, expected: dict[str, Any]) -> dict[str, Any]:
        if expected["kind"] == "transaction":
            value = await self._delegate.get_transaction(self.transaction.id)
        else:
            value = await self._delegate.get_authorization_session_by_code(
                self.authorization_session.code
            )
        assert value is not None
        result = {
            "kind": expected["kind"],
            "status": value.status.value if hasattr(value.status, "value") else value.status,
            "access_token": value.access_token,
        }
        if "dpop_jkt" in expected:
            result["dpop_jkt"] = (
                value.claims.get("_dpop_jkt")
                if expected["kind"] == "transaction"
                else value.dpop_jkt
            )
        return result


def client(
    monkeypatch,
    repository: ContractRepository,
    *,
    raise_server_exceptions: bool = True,
) -> TestClient:
    from issuance import main
    from issuance.infrastructure.api import routes

    inputs = CONTRACT["inputs"]
    monkeypatch.setattr(main, "_repo", repository)
    monkeypatch.setattr(routes, "ISSUER_BASE_URL", "https://issuer.example")
    monkeypatch.setattr(
        routes,
        "oid4vci_create_token_response",
        lambda _code, _lifetime: {
            "access_token": inputs["generated_pre_authorized_token"],
            "expires_in": 1800,
        },
    )
    if repository._setup not in {
        "redirect_authorization_session",
        "pkce_authorization_session",
    }:
        monkeypatch.setattr(
            routes,
            "oid4vci_exchange_auth_code_for_token",
            lambda _request, _session, _lifetime: {
                "access_token": inputs["generated_authorization_code_token"],
                "expires_in": 1800,
            },
        )
    else:
        from issuance.application.rust_integration import (
            oid4vci_exchange_auth_code_for_token,
        )

        monkeypatch.setattr(
            routes,
            "oid4vci_exchange_auth_code_for_token",
            oid4vci_exchange_auth_code_for_token,
        )

    def validate_dpop(proof: str, **_kwargs: Any) -> str:
        if proof == "invalid-proof":
            raise ValueError("invalid proof")
        return "contract-dpop-jkt"

    monkeypatch.setattr(routes, "_validated_dpop_jkt", validate_dpop)
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")
    return TestClient(main.create_app(), raise_server_exceptions=raise_server_exceptions)


def test_token_exchange_contract_matches_python_oracle(monkeypatch) -> None:
    import asyncio

    for case in [*CONTRACT["cases"], *CONTRACT["failures"]]:
        repository = ContractRepository(case["setup"])
        asyncio.run(repository.initialize())
        http = client(monkeypatch, repository)
        response = http.post(
            CONTRACT["inputs"]["path"],
            data=copy.deepcopy(case["form"]),
            headers=case.get("headers", {}),
        )
        assert response.status_code == case["status_code"], case["name"]
        assert response.headers["content-type"].split(";", 1)[0] == "application/json"
        assert response.json() == case["body"], case["name"]
        assert repository.calls == case["repository_calls"], case["name"]
        if "final_state" in case:
            assert asyncio.run(repository.final_state(case["final_state"])) == case["final_state"]


def test_token_exchange_logs_presence_without_grant_capabilities(
    monkeypatch: Any, caplog: Any
) -> None:
    import asyncio

    cases = {
        case["name"]: copy.deepcopy(case)
        for case in CONTRACT["cases"]
        if case["name"] in {"pre_authorized_code_success", "authorization_code_success"}
    }
    attempts = (
        (
            cases["pre_authorized_code_success"],
            "pre-authorized_code",
            "pre-auth-MUST-NOT-ENTER-LOGS-7e912af0",
            "pre_authorized_code",
        ),
        (
            cases["authorization_code_success"],
            "code",
            "authorization-MUST-NOT-ENTER-LOGS-d3b1f682",
            "authorization_code",
        ),
    )
    caplog.set_level(logging.INFO, logger="issuance.infrastructure.api.routes")

    for case, form_field, capability, grant_type_label in attempts:
        repository = ContractRepository(case["setup"])
        if form_field == "pre-authorized_code":
            repository.transaction.pre_auth_code = capability
        else:
            repository.authorization_session.code = capability
        asyncio.run(repository.initialize())
        case["form"][form_field] = capability
        caplog.clear()

        response = client(monkeypatch, repository).post(
            CONTRACT["inputs"]["path"],
            data=case["form"],
            headers=case.get("headers", {}),
        )

        assert response.status_code == case["status_code"]
        route_records = [
            record
            for record in caplog.records
            if record.name == "issuance.infrastructure.api.routes"
        ]
        assert route_records
        rendered_logs = "\n".join(record.getMessage() for record in route_records)
        structured_logs = "\n".join(repr(record.__dict__) for record in route_records)
        assert capability not in rendered_logs
        assert capability not in structured_logs
        assert f"grant_type={grant_type_label}" in rendered_logs
        assert "pre_authorized_code_present=" in rendered_logs
        assert "authorization_code_present=" in rendered_logs


def test_token_exchange_rate_limit_matches_language_neutral_contract(monkeypatch) -> None:
    from issuance.infrastructure.api import routes

    expected = CONTRACT["rate_limit"]
    repository = ContractRepository("no_state")
    monkeypatch.setattr(
        routes,
        "_token_limiter",
        routes._InMemoryRateLimiter(expected["requests"], expected["window_seconds"]),
    )
    http = client(monkeypatch, repository)
    for _ in range(expected["requests"]):
        response = http.post(
            CONTRACT["inputs"]["path"],
            data=copy.deepcopy(expected["request"]["form"]),
        )
        assert response.status_code == expected["allowed_status_code"]

    response = http.post(
        CONTRACT["inputs"]["path"],
        data=copy.deepcopy(expected["request"]["form"]),
    )
    assert response.status_code == expected["status_code"]
    assert response.headers["content-type"].split(";", 1)[0] == "application/json"
    for name, value in expected["headers"].items():
        assert response.headers[name] == value
    assert response.json() == expected["body"]


def test_token_exchange_dependency_failures_match_python_oracle(monkeypatch) -> None:
    for case in CONTRACT["dependency_failures"]:
        repository = ContractRepository(case["setup"])
        http = client(monkeypatch, repository, raise_server_exceptions=False)
        response = http.post(
            CONTRACT["inputs"]["path"],
            data=copy.deepcopy(case["form"]),
        )
        assert response.status_code == case["status_code"], case["name"]
        assert response.headers["content-type"].split(";", 1)[0] == case["content_type"]
        assert response.text == case["body"]
        assert repository.calls == case["repository_calls"]
