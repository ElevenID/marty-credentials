from __future__ import annotations

import asyncio
import json

import pytest
from fastapi import HTTPException, Response
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import routes
from starlette.requests import Request


def _request(path: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("issuer.example", 443),
            "path": path,
            "query_string": b"",
            "headers": [(b"host", b"issuer.example")],
            "client": ("127.0.0.1", 12345),
        }
    )


@pytest.mark.asyncio
async def test_memory_capabilities_are_digest_keyed_and_single_use() -> None:
    repo = InMemoryIssuanceRepository()
    request_uri = "urn:ietf:params:oauth:request_uri:secret-capability"
    nonce = "wallet-proof-nonce"

    assert await repo.save_pushed_authorization_request(
        request_uri,
        {"client_id": "wallet"},
        ttl_seconds=90,
    )
    assert await repo.save_proof_nonce(nonce, ttl_seconds=300)

    stored_keys = {key_digest for _, key_digest in repo._oid4vci_ephemeral_capabilities}
    assert request_uri not in stored_keys
    assert nonce not in stored_keys
    assert all(len(key_digest) == 64 for key_digest in stored_keys)

    par_results = await asyncio.gather(
        *(repo.consume_pushed_authorization_request(request_uri) for _ in range(8))
    )
    nonce_results = await asyncio.gather(*(repo.consume_proof_nonce(nonce) for _ in range(8)))

    assert par_results.count({"client_id": "wallet"}) == 1
    assert sum(nonce_results) == 1


@pytest.mark.asyncio
async def test_par_rejects_payload_over_storage_boundary() -> None:
    repo = InMemoryIssuanceRepository()

    response = await routes.pushed_authorization_request(
        http_request=_request("/v1/issuance/par"),
        response_type="code",
        client_id="wallet",
        redirect_uri="https://wallet.example/callback",
        scope=None,
        state=None,
        code_challenge="challenge",
        code_challenge_method="S256",
        issuer_state=None,
        authorization_details="x" * routes._PAR_MAX_PAYLOAD_BYTES,
        organization_id=None,
        issuer_org="org-a",
        repo=repo,
    )

    assert response.status_code == 400
    assert json.loads(response.body)["error"] == "invalid_request"
    assert repo._oid4vci_ephemeral_capabilities == {}


@pytest.mark.asyncio
async def test_nonce_endpoint_fails_closed_when_shared_store_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()

    async def unavailable(*_args, **_kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(repo, "save_proof_nonce", unavailable)

    with pytest.raises(HTTPException) as exc_info:
        await routes.nonce_endpoint(Response(), repo=repo)

    assert exc_info.value.status_code == 503
    assert "database unavailable" not in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_nonce_endpoint_persists_digest_only_single_use_state() -> None:
    repo = InMemoryIssuanceRepository()
    response = Response()

    result = await routes.nonce_endpoint(response, repo=repo)

    assert response.headers["Cache-Control"] == "no-store"
    assert result.c_nonce not in str(repo._oid4vci_ephemeral_capabilities)
    assert await repo.consume_proof_nonce(result.c_nonce)
    assert not await repo.consume_proof_nonce(result.c_nonce)


@pytest.mark.asyncio
async def test_par_endpoint_fails_closed_when_shared_store_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()

    async def unavailable(*_args, **_kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(repo, "save_pushed_authorization_request", unavailable)

    response = await routes.pushed_authorization_request(
        http_request=_request("/v1/issuance/par"),
        response_type="code",
        client_id="wallet",
        redirect_uri="https://wallet.example/callback",
        scope=None,
        state=None,
        code_challenge="challenge",
        code_challenge_method="S256",
        issuer_state=None,
        authorization_details=None,
        organization_id=None,
        issuer_org="org-a",
        repo=repo,
    )

    assert response.status_code == 503
    payload = json.loads(response.body)
    assert payload["error"] == "temporarily_unavailable"
    assert "database unavailable" not in payload["error_description"]
