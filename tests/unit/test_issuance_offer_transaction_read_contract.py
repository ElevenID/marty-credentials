from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-offer-transaction-reads.json").read_text(encoding="utf-8")
)


class ContractRepository:
    def __init__(self, transactions: list[dict[str, Any]]) -> None:
        from issuance.domain.entities import IssuanceStatus, IssuanceTransaction

        self.transactions = {
            value["id"]: IssuanceTransaction(
                **{
                    **value,
                    "status": IssuanceStatus(value["status"]),
                    "created_at": datetime.fromisoformat(value["created_at"]),
                    "expires_at": datetime.fromisoformat(value["expires_at"]),
                    "issued_at": (
                        datetime.fromisoformat(value["issued_at"])
                        if value.get("issued_at")
                        else None
                    ),
                    "revoked_at": (
                        datetime.fromisoformat(value["revoked_at"])
                        if value.get("revoked_at")
                        else None
                    ),
                }
            )
            for value in transactions
        }
        self.calls: list[dict[str, str]] = []

    async def get_transaction(self, transaction_id: str) -> Any:
        self.calls.append({"method": "get_transaction", "value": transaction_id})
        return self.transactions.get(transaction_id)

    async def list_transactions(self, organization_id: str) -> list[Any]:
        self.calls.append({"method": "list_transactions", "value": organization_id})
        return [
            transaction
            for transaction in self.transactions.values()
            if transaction.organization_id == organization_id
            and transaction.id in {"tx-pending", "tx-revoked"}
        ]


def client(monkeypatch) -> tuple[TestClient, ContractRepository]:
    from issuance import main
    from issuance.infrastructure.api import routes

    inputs = CONTRACT["inputs"]
    repository = ContractRepository(inputs["transactions"])
    monkeypatch.setattr(main, "_repo", repository)
    monkeypatch.setattr(routes, "ISSUER_BASE_URL", inputs["issuer_base_url"])
    monkeypatch.setattr(routes, "_ISSUANCE_API_KEY", inputs["management_api_key"])
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")
    return TestClient(main.create_app()), repository


def test_offer_transaction_read_contract_matches_python_oracle(monkeypatch) -> None:
    http, repository = client(monkeypatch)

    for case in CONTRACT["cases"]:
        repository.calls.clear()
        response = http.request(
            case["method"],
            case["path"],
            headers=case.get("headers", {}),
        )
        assert response.status_code == case["status_code"], case["operation"]
        assert response.headers["content-type"].split(";", 1)[0] == "application/json"
        assert response.json() == case["body"], case["operation"]
        assert repository.calls == case["repository_calls"], case["operation"]


def test_offer_transaction_read_failures_match_python_oracle(monkeypatch) -> None:
    http, _repository = client(monkeypatch)

    for failure in CONTRACT["failures"]:
        response = http.get(failure["path"], headers=failure.get("headers", {}))
        assert response.status_code == failure["status_code"], failure["name"]
        assert response.json() == failure["body"], failure["name"]
