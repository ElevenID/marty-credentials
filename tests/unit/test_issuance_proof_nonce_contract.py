from __future__ import annotations

import asyncio
import json
import re
import secrets
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / "contracts/issuance-proof-nonce.json").read_text(encoding="utf-8"))


class ContractRepository:
    def __init__(self, setup: str = "stored") -> None:
        from issuance.infrastructure.adapters.memory_repository import (
            InMemoryIssuanceRepository,
        )

        self._delegate = InMemoryIssuanceRepository()
        self.setup = setup
        self.calls: list[dict[str, Any]] = []

    async def save_proof_nonce(self, nonce: str, *, ttl_seconds: int) -> bool:
        self.calls.append(
            {
                "method": "save_proof_nonce",
                "value": nonce,
                "ttl_seconds": ttl_seconds,
            }
        )
        if self.setup == "store_raises":
            raise RuntimeError("contract nonce store unavailable")
        return self.setup != "store_returns_false"

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


def client(monkeypatch: pytest.MonkeyPatch, repository: ContractRepository) -> TestClient:
    from issuance import main

    monkeypatch.setattr(main, "_repo", repository)
    return TestClient(main.create_app())


def assert_json_response(response: Any, expected: dict[str, Any]) -> None:
    assert response.status_code == expected["status_code"]
    assert response.headers["content-type"].split(";", 1)[0] == expected["content_type"]
    assert response.json() == expected["body"]


def test_proof_nonce_success_matches_language_neutral_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = CONTRACT["success"]
    repository = ContractRepository()
    monkeypatch.setattr(
        secrets, "token_urlsafe", lambda _size: CONTRACT["inputs"]["generated_nonce"]
    )

    response = client(monkeypatch, repository).post(CONTRACT["inputs"]["path"])

    assert_json_response(response, expected)
    for name, value in expected["headers"].items():
        assert response.headers[name] == value
    assert repository.calls == expected["repository_calls"]


@pytest.mark.parametrize("case", CONTRACT["failures"], ids=lambda case: case["name"])
def test_proof_nonce_failures_match_language_neutral_contract(
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
) -> None:
    repository = ContractRepository(case["setup"])
    monkeypatch.setattr(
        secrets, "token_urlsafe", lambda _size: CONTRACT["inputs"]["generated_nonce"]
    )

    response = client(monkeypatch, repository).post(CONTRACT["inputs"]["path"])

    assert_json_response(response, case)
    assert repository.calls == CONTRACT["success"]["repository_calls"]


def test_proof_nonce_entropy_shape_is_language_neutral() -> None:
    expected = CONTRACT["nonce_shape"]
    nonce = secrets.token_urlsafe(expected["source_bytes"])

    assert len(nonce) == expected["encoded_length"]
    assert re.fullmatch(expected["pattern"], nonce)


def test_proof_nonce_persistence_is_digest_only_and_single_use() -> None:
    from issuance.infrastructure.adapters.memory_repository import (
        InMemoryIssuanceRepository,
    )

    expected = CONTRACT["persistence"]
    nonce = CONTRACT["inputs"]["generated_nonce"]
    repository = InMemoryIssuanceRepository()

    assert asyncio.run(
        repository.save_proof_nonce(nonce, ttl_seconds=CONTRACT["inputs"]["ttl_seconds"])
    )
    stored_keys = {key_digest for _, key_digest in repository._oid4vci_ephemeral_capabilities}
    assert expected["digest_algorithm"] == "sha-256"
    assert all(len(key_digest) == expected["digest_length"] for key_digest in stored_keys)
    assert (nonce not in str(repository._oid4vci_ephemeral_capabilities)) is (
        not expected["plaintext_retained"]
    )
    assert asyncio.run(repository.consume_proof_nonce(nonce)) is expected["single_use"]
    assert not asyncio.run(repository.consume_proof_nonce(nonce))


def test_proof_nonce_rate_limit_matches_language_neutral_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from issuance.infrastructure.api import routes

    expected = CONTRACT["rate_limit"]
    repository = ContractRepository()
    monkeypatch.setattr(
        secrets, "token_urlsafe", lambda _size: CONTRACT["inputs"]["generated_nonce"]
    )
    monkeypatch.setattr(
        routes,
        "_token_limiter",
        routes._InMemoryRateLimiter(expected["requests"], expected["window_seconds"]),
    )
    http = client(monkeypatch, repository)

    for _ in range(expected["requests"]):
        response = http.post(CONTRACT["inputs"]["path"])
        assert response.status_code == expected["allowed_status_code"]

    response = http.post(CONTRACT["inputs"]["path"])
    assert response.status_code == expected["status_code"]
    assert response.headers["content-type"].split(";", 1)[0] == "application/json"
    for name, value in expected["headers"].items():
        assert response.headers[name] == value
    assert response.json() == expected["body"]
    assert len(repository.calls) == expected["repository_call_count"]
