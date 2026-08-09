from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from issuance.application.issuance_idempotency import (
    canonical_issuance_request,
    hash_idempotency_key,
    issuance_request_hash,
    normalize_idempotency_key,
)
from issuance.domain.entities import (
    IssuanceIdempotencyConflictError,
    IssuanceTransaction,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.models import issuance_transactions_table


def _transaction(*, raw_key: str, claims: dict[str, object]) -> IssuanceTransaction:
    semantics = canonical_issuance_request(
        organization_id="org-1",
        credential_template_id="template-1",
        application_id="application-1",
        applicant_id="applicant-1",
        subject_did="did:key:holder",
        holder_did=None,
        issuer_did="did:web:issuer.example",
        authorized_client_id=None,
        delivery_mode="wallet_only",
        claims=claims,
    )
    return IssuanceTransaction(
        organization_id="org-1",
        credential_template_id="template-1",
        application_id="application-1",
        applicant_id="applicant-1",
        subject_did="did:key:holder",
        issuer_did_override="did:web:issuer.example",
        claims={**claims, "_vct": "https://issuer.example/credentials/example"},
        idempotency_key_hash=hash_idempotency_key(raw_key),
        idempotency_request_hash=issuance_request_hash(semantics),
    )


def test_idempotency_key_is_validated_and_hashed_before_persistence() -> None:
    raw_key = "flow:application-1:stable-retry"

    assert normalize_idempotency_key(raw_key) == raw_key
    assert raw_key not in hash_idempotency_key(raw_key)
    assert len(hash_idempotency_key(raw_key)) == 64
    with pytest.raises(ValueError, match="1-128 ASCII"):
        normalize_idempotency_key("contains a space")
    with pytest.raises(ValueError, match="surrounding whitespace"):
        normalize_idempotency_key(" padded")


def test_request_hash_is_canonical_and_binds_nested_claims() -> None:
    first = {"claims": {"roles": ["student", "member"], "profile": {"level": 2}}}
    reordered = {"claims": {"profile": {"level": 2}, "roles": ["student", "member"]}}
    changed = {"claims": {"profile": {"level": 3}, "roles": ["student", "member"]}}

    assert issuance_request_hash(first) == issuance_request_hash(reordered)
    assert issuance_request_hash(first) != issuance_request_hash(changed)


@pytest.mark.asyncio
async def test_concurrent_identical_reservations_return_one_transaction() -> None:
    repo = InMemoryIssuanceRepository()
    first = _transaction(raw_key="same-logical-offer", claims={"degree": "BSc"})
    second = _transaction(raw_key="same-logical-offer", claims={"degree": "BSc"})

    results = await asyncio.gather(
        repo.reserve_transaction_idempotently(first),
        repo.reserve_transaction_idempotently(second),
    )

    assert sorted(created for _, created in results) == [False, True]
    assert results[0][0].id == results[1][0].id
    assert results[0][0].pre_auth_code == results[1][0].pre_auth_code


@pytest.mark.asyncio
async def test_conflicting_request_reuse_is_rejected_without_an_extra_offer() -> None:
    repo = InMemoryIssuanceRepository()
    original = _transaction(raw_key="same-logical-offer", claims={"degree": "BSc"})
    conflict = _transaction(raw_key="same-logical-offer", claims={"degree": "MSc"})
    stored, created = await repo.reserve_transaction_idempotently(original)

    with pytest.raises(IssuanceIdempotencyConflictError):
        await repo.reserve_transaction_idempotently(conflict)

    assert created is True
    transactions = await repo.list_transactions("org-1")
    assert [transaction.id for transaction in transactions] == [stored.id]


@pytest.mark.asyncio
async def test_committed_offer_can_be_recovered_before_mutable_dependency_reads() -> None:
    repo = InMemoryIssuanceRepository()
    original = _transaction(raw_key="stable-key", claims={"name": "Ada"})
    stored, _ = await repo.reserve_transaction_idempotently(original)

    recovered = await repo.recover_transaction_idempotently(
        organization_id=original.organization_id,
        idempotency_key_hash=original.idempotency_key_hash or "",
        idempotency_request_hash=original.idempotency_request_hash or "",
    )

    assert recovered == stored
    assert recovered is not stored
    assert (
        await repo.recover_transaction_idempotently(
            organization_id="another-org",
            idempotency_key_hash=original.idempotency_key_hash or "",
            idempotency_request_hash=original.idempotency_request_hash or "",
        )
        is None
    )
    with pytest.raises(IssuanceIdempotencyConflictError):
        await repo.recover_transaction_idempotently(
            organization_id=original.organization_id,
            idempotency_key_hash=original.idempotency_key_hash or "",
            idempotency_request_hash="f" * 64,
        )


@pytest.mark.asyncio
async def test_http_retry_recovers_before_template_resolution(monkeypatch) -> None:
    from issuance.infrastructure.api import routes

    repo = InMemoryIssuanceRepository()
    raw_key = "stable-http-key"
    stored, _ = await repo.reserve_transaction_idempotently(
        _transaction(raw_key=raw_key, claims={"name": "Ada"})
    )
    request = routes.InitiateIssuanceRequest(
        organization_id="org-1",
        credential_template_id="template-1",
        application_id="application-1",
        applicant_id="applicant-1",
        subject_did="did:key:holder",
        issuer_did="did:web:issuer.example",
        claims={"name": "Ada"},
    )
    channel_calls = 0

    def unavailable_channel(*_args, **_kwargs):
        nonlocal channel_calls
        channel_calls += 1
        raise RuntimeError("dependency unavailable")

    monkeypatch.setattr(routes, "_create_grpc_channel", unavailable_channel)
    monkeypatch.setattr(
        routes,
        "oid4vci_create_credential_offer",
        lambda **_kwargs: '{"credential_issuer":"https://issuer.example"}',
    )

    response = await routes.initiate_issuance(
        request=request,
        http_request=SimpleNamespace(headers={"Idempotency-Key": raw_key}),
        repo=repo,
    )

    assert response.id == stored.id
    assert response.pre_auth_code == stored.pre_auth_code
    assert channel_calls == 1  # Organization validation only; no template lookup.


@pytest.mark.asyncio
async def test_grpc_retry_recovers_before_template_resolution(monkeypatch) -> None:
    from issuance.infrastructure.adapters import grpc_adapter
    from marty_proto.v1 import issuance_service_pb2 as pb2

    repo = InMemoryIssuanceRepository()
    raw_key = "stable-grpc-key"
    stored, _ = await repo.reserve_transaction_idempotently(
        _transaction(raw_key=raw_key, claims={"name": "Ada"})
    )
    request = pb2.InitiateIssuanceRequest(
        organization_id="org-1",
        credential_template_id="template-1",
        application_id="application-1",
        applicant_id="applicant-1",
        subject_did="did:key:holder",
        issuer_did="did:web:issuer.example",
        claims={"name": "Ada"},
        idempotency_key=raw_key,
        delivery_mode="wallet_only",
    )
    channel_calls = 0

    def unavailable_channel(*_args, **_kwargs):
        nonlocal channel_calls
        channel_calls += 1
        raise RuntimeError("dependency unavailable")

    context = SimpleNamespace(
        set_code=lambda _code: None,
        set_details=lambda _details: None,
    )
    service = grpc_adapter.IssuanceServiceGrpc(lambda: repo)
    monkeypatch.setattr(grpc_adapter, "create_service_channel", unavailable_channel)
    monkeypatch.setattr(
        service,
        "_issuance_response_from_transaction",
        lambda tx: pb2.IssuanceResponse(id=tx.id, pre_auth_code=tx.pre_auth_code),
    )

    response = await service.InitiateIssuance(request, context)

    assert response.id == stored.id
    assert response.pre_auth_code == stored.pre_auth_code
    assert channel_calls == 1  # Organization validation only; no template lookup.


def test_database_contract_scopes_unique_hash_to_organization() -> None:
    assert issuance_transactions_table.c.idempotency_key_hash.type.length == 64
    assert issuance_transactions_table.c.idempotency_request_hash.type.length == 64
    unique_indexes = {
        index.name: tuple(column.name for column in index.columns)
        for index in issuance_transactions_table.indexes
        if index.unique
    }
    assert unique_indexes["ux_issuance_transactions_org_idempotency_key_hash"] == (
        "organization_id",
        "idempotency_key_hash",
    )
