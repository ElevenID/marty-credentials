from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException, Response
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import routes


@pytest.mark.asyncio
async def test_memory_proof_nonces_are_digest_keyed_and_single_use() -> None:
    repo = InMemoryIssuanceRepository()
    nonce = "wallet-proof-nonce"

    assert await repo.save_proof_nonce(nonce, ttl_seconds=300)

    stored_keys = {key_digest for _, key_digest in repo._oid4vci_ephemeral_capabilities}
    assert nonce not in stored_keys
    assert all(len(key_digest) == 64 for key_digest in stored_keys)

    nonce_results = await asyncio.gather(*(repo.consume_proof_nonce(nonce) for _ in range(8)))

    assert sum(nonce_results) == 1


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
