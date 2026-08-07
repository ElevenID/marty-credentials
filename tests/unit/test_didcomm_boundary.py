from __future__ import annotations

import json
import ssl
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException
from issuance.application import rust_integration
from issuance.domain.entities import IssuanceTransaction
from issuance.infrastructure.api import routes
from pydantic import ValidationError
from starlette.requests import Request


def _request(organization_id: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/issuance/didcomm/deliver",
            "headers": [(b"x-organization-id", organization_id.encode())],
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )


def test_delivery_contract_rejects_caller_selected_resolver() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        routes.DidcommDeliverRequest(
            organization_id="org-a",
            transaction_id="tx-a",
            holder_did="did:peer:2.EzExample",
            universal_resolver_url="https://attacker.example/resolve",
        )


def test_resolver_uses_only_deployment_managed_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None]] = []

    class Binding:
        @staticmethod
        def didcomm_resolve_did(did: str, resolver_url: str | None) -> str:
            calls.append((did, resolver_url))
            return json.dumps({"id": did})

    monkeypatch.setenv(
        "DIDCOMM_UNIVERSAL_RESOLVER_URL",
        "https://resolver.internal.example/1.0/identifiers",
    )
    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: Binding())

    assert rust_integration.didcomm_resolve_did("did:example:holder") == {
        "id": "did:example:holder"
    }
    assert calls == [
        (
            "did:example:holder",
            "https://resolver.internal.example/1.0/identifiers",
        )
    ]
    with pytest.raises(TypeError):
        rust_integration.didcomm_resolve_did(  # type: ignore[call-arg]
            "did:example:holder",
            "https://attacker.example/resolve",
        )


def test_delivery_uses_normal_web_pki_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DIDCOMM_TLS_CA_FILE", raising=False)

    assert routes._didcomm_tls_verifier() is True


def test_delivery_adds_operator_ca_to_default_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = Mock(spec=ssl.SSLContext)
    create_default_context = Mock(return_value=context)
    monkeypatch.setenv("DIDCOMM_TLS_CA_FILE", "/run/secrets/didcomm-root-ca.pem")
    monkeypatch.setattr(routes.ssl, "create_default_context", create_default_context)

    assert routes._didcomm_tls_verifier() is context
    create_default_context.assert_called_once_with()
    context.load_verify_locations.assert_called_once_with(
        cafile="/run/secrets/didcomm-root-ca.pem"
    )


def test_delivery_fails_closed_when_operator_ca_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DIDCOMM_TLS_CA_FILE", "/missing/didcomm-root-ca.pem")
    monkeypatch.setattr(
        routes.ssl,
        "create_default_context",
        Mock(side_effect=OSError("missing")),
    )

    with pytest.raises(HTTPException, match="trust configuration is unavailable") as exc:
        routes._didcomm_tls_verifier()

    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_delivery_rechecks_gateway_tenant_against_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = IssuanceTransaction(id="tx-a", organization_id="org-a")
    repo = SimpleNamespace(get_transaction=AsyncMock(return_value=transaction))
    deliver = AsyncMock(return_value=SimpleNamespace(status="delivered"))
    monkeypatch.setattr(routes, "_didcomm_sign_and_deliver", deliver)

    response = await routes.didcomm_deliver(
        routes.DidcommDeliverRequest(
            organization_id="org-a",
            transaction_id="tx-a",
            holder_did="did:peer:2.EzExample",
        ),
        _request("org-a"),
        repo,
    )

    assert response.status == "delivered"
    deliver.assert_awaited_once_with(
        tx=transaction,
        holder_did="did:peer:2.EzExample",
        repo=repo,
    )


@pytest.mark.asyncio
async def test_delivery_hides_cross_tenant_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = IssuanceTransaction(id="tx-b", organization_id="org-b")
    repo = SimpleNamespace(get_transaction=AsyncMock(return_value=transaction))
    deliver = AsyncMock()
    monkeypatch.setattr(routes, "_didcomm_sign_and_deliver", deliver)

    with pytest.raises(HTTPException) as exc:
        await routes.didcomm_deliver(
            routes.DidcommDeliverRequest(
                organization_id="org-a",
                transaction_id="tx-b",
                holder_did="did:peer:2.EzExample",
            ),
            _request("org-a"),
            repo,
        )

    assert exc.value.status_code == 404
    deliver.assert_not_awaited()


@pytest.mark.asyncio
async def test_delivery_rejects_claimed_tenant_before_transaction_lookup() -> None:
    repo = SimpleNamespace(get_transaction=AsyncMock())

    with pytest.raises(HTTPException) as exc:
        await routes.didcomm_deliver(
            routes.DidcommDeliverRequest(
                organization_id="org-b",
                transaction_id="tx-b",
                holder_did="did:peer:2.EzExample",
            ),
            _request("org-a"),
            repo,
        )

    assert exc.value.status_code == 404
    repo.get_transaction.assert_not_awaited()


@pytest.mark.asyncio
async def test_delivery_rejects_private_or_plaintext_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(HTTPException, match="not publicly routable") as private_exc:
        await routes._validated_didcomm_delivery_endpoint("https://127.0.0.1/inbox")
    assert private_exc.value.status_code == 422

    transaction = IssuanceTransaction(
        id="tx-a",
        organization_id="org-a",
        credential_template_id="template-a",
        issuer_profile_id="profile-a",
        issuer_did_override="did:web:issuer.example",
        claims={"given_name": "Alice"},
    )
    repo = SimpleNamespace(save_transaction=AsyncMock())
    remote_context = {
        "issuer_did": "did:web:issuer.example",
        "issuer_profile_id": "profile-a",
        "verification_method_id": "did:web:issuer.example#key-1",
        "service": {"algorithm": "ES256"},
    }
    monkeypatch.setattr(
        routes,
        "apply_remote_issuer_context",
        AsyncMock(return_value=remote_context),
    )
    monkeypatch.setattr(
        routes,
        "_allocate_credential_status_list_entries",
        AsyncMock(return_value=(None, [])),
    )
    monkeypatch.setattr(
        routes,
        "create_sd_jwt_vc_with_remote_signing",
        AsyncMock(return_value=("signed-credential", "urn:uuid:credential-a")),
    )
    packed: dict = {}

    def pack(**kwargs) -> str:
        packed.update(kwargs)
        return json.dumps({"id": "message-a"})

    monkeypatch.setattr(routes, "didcomm_pack_credential", pack)
    monkeypatch.setattr(
        routes,
        "didcomm_resolve_did",
        lambda _did: {"id": "did:peer:holder"},
    )
    monkeypatch.setattr(
        routes,
        "didcomm_extract_endpoint",
        lambda _doc: "https://wallet.example/inbox",
    )
    monkeypatch.setattr(
        routes,
        "_validated_didcomm_delivery_endpoint",
        AsyncMock(return_value="https://wallet.example/inbox"),
    )
    monkeypatch.setattr(
        routes,
        "didcomm_encrypt",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("missing key agreement")),
    )

    with pytest.raises(HTTPException, match="compatible DIDComm key agreement") as exc:
        await routes._didcomm_sign_and_deliver(
            transaction,
            "did:peer:holder",
            repo,
        )

    assert exc.value.status_code == 422
    assert packed["thread_id"] == "tx-a"
