from __future__ import annotations

import json
import ssl
from pathlib import Path
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


def _write_encryption_policy(tmp_path: Path, issuers: dict) -> str:
    policy_path = tmp_path / "didcomm-encryption-policy.json"
    policy_path.write_text(
        json.dumps({"version": 1, "issuers": issuers}),
        encoding="utf-8",
    )
    return str(policy_path)


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
    calls: list[tuple[str, dict[str, object]]] = []

    class Binding:
        @staticmethod
        def didcomm_resolve_did_with_metadata(
            did: str, **configuration: object
        ) -> str:
            calls.append((did, configuration))
            return json.dumps(
                {
                    "document": {"id": did},
                    "source": "configured_internal_resolver",
                    "retrieved_at": "2026-08-15T00:00:00Z",
                    "content_sha256": "0" * 64,
                }
            )

    monkeypatch.setenv(
        "DIDCOMM_UNIVERSAL_RESOLVER_URL",
        "https://resolver.internal.example/1.0/identifiers",
    )
    monkeypatch.setenv(
        "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
        "http://gateway:8000",
    )
    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: Binding())

    assert rust_integration.didcomm_resolve_did("did:example:holder") == {
        "id": "did:example:holder"
    }
    assert calls == [
        (
            "did:example:holder",
            {
                "universal_resolver_url": (
                    "https://resolver.internal.example/1.0/identifiers"
                ),
                "did_web_internal_base_urls": ["http://gateway:8000"],
                "did_web_allowed_hosts": None,
            },
        )
    ]
    with pytest.raises(TypeError):
        rust_integration.didcomm_resolve_did(  # type: ignore[call-arg]
            "did:example:holder",
            "https://attacker.example/resolve",
        )


def test_resolver_rejects_a_mismatched_native_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Binding:
        @staticmethod
        def didcomm_resolve_did_with_metadata(
            did: str, **configuration: object
        ) -> str:
            del did, configuration
            return json.dumps(
                {
                    "document": {"id": "did:web:other.example"},
                    "source": "configured_internal_resolver",
                    "retrieved_at": "2026-08-15T00:00:00Z",
                    "content_sha256": "0" * 64,
                }
            )

    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: Binding())

    with pytest.raises(RuntimeError, match="mismatched document"):
        rust_integration.didcomm_resolve_did("did:web:issuer.example")


def test_authcrypt_binding_delegates_all_crypto_to_rust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    class Binding:
        @staticmethod
        def didcomm_encrypt_authcrypt(*args: object) -> str:
            calls.append(args)
            return "encrypted"

    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: Binding())
    sender_document = {"id": "did:web:issuer.example"}
    recipient_document = {"id": "did:peer:holder"}
    private_key = bytes(range(32))

    assert (
        rust_integration.didcomm_encrypt_authcrypt(
            '{"from":"did:web:issuer.example","to":["did:peer:holder"]}',
            sender_document,
            private_key,
            recipient_document,
        )
        == "encrypted"
    )
    assert calls == [
        (
            '{"from":"did:web:issuer.example","to":["did:peer:holder"]}',
            json.dumps(sender_document),
            private_key,
            json.dumps(recipient_document),
        )
    ]


def test_delivery_defaults_to_anoncrypt_without_a_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DIDCOMM_ENCRYPTION_POLICY_FILE", raising=False)
    anoncrypt = Mock(return_value="anonymous")
    authcrypt = Mock()
    monkeypatch.setattr(rust_integration, "didcomm_encrypt", anoncrypt)
    monkeypatch.setattr(rust_integration, "didcomm_encrypt_authcrypt", authcrypt)
    recipient_document = {"id": "did:peer:holder"}

    assert (
        rust_integration.didcomm_encrypt_delivery(
            "message",
            "did:web:issuer.example",
            recipient_document,
        )
        == "anonymous"
    )
    anoncrypt.assert_called_once_with("message", recipient_document)
    authcrypt.assert_not_called()


def test_configured_authcrypt_resolves_and_binds_the_sender(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_key = bytes(range(32))
    monkeypatch.setenv(
        "DIDCOMM_ENCRYPTION_POLICY_FILE",
        _write_encryption_policy(
            tmp_path,
            {
                "did:web:issuer.example": {
                    "mode": "authcrypt",
                    "sender_x25519_private_key": rust_integration.base64url_encode(
                        private_key
                    ),
                }
            },
        ),
    )
    sender_document = {"id": "did:web:issuer.example"}
    recipient_document = {"id": "did:peer:holder"}
    resolve = Mock(return_value=sender_document)
    authcrypt = Mock(return_value="authenticated")
    anoncrypt = Mock()
    monkeypatch.setattr(rust_integration, "didcomm_resolve_did", resolve)
    monkeypatch.setattr(rust_integration, "didcomm_encrypt_authcrypt", authcrypt)
    monkeypatch.setattr(rust_integration, "didcomm_encrypt", anoncrypt)

    assert (
        rust_integration.didcomm_encrypt_delivery(
            "message",
            "did:web:issuer.example",
            recipient_document,
        )
        == "authenticated"
    )
    resolve.assert_called_once_with("did:web:issuer.example")
    authcrypt.assert_called_once_with(
        "message",
        sender_document,
        private_key,
        recipient_document,
    )
    anoncrypt.assert_not_called()


def test_prepared_authcrypt_context_is_validated_once_and_frozen_for_delivery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer_did = "did:web:issuer.example"
    private_key = bytes(range(32))
    policy_path = Path(
        _write_encryption_policy(
            tmp_path,
            {
                issuer_did: {
                    "mode": "authcrypt",
                    "sender_x25519_private_key": rust_integration.base64url_encode(
                        private_key
                    ),
                }
            },
        )
    )
    monkeypatch.setenv("DIDCOMM_ENCRYPTION_POLICY_FILE", str(policy_path))
    sender_document = {
        "id": issuer_did,
        "keyAgreement": [f"{issuer_did}#didcomm-authcrypt-x25519"],
    }
    recipient_document = {
        "id": "did:peer:holder",
        "keyAgreement": ["did:peer:holder#key-1"],
    }
    monkeypatch.setattr(
        rust_integration,
        "didcomm_resolve_did",
        Mock(return_value=sender_document),
    )
    calls: list[tuple[str, str, bytes, str]] = []

    class Binding:
        @staticmethod
        def didcomm_encrypt_authcrypt(
            plaintext: str,
            sender_document_json: str,
            sender_private_key: bytes,
            recipient_document_json: str,
        ) -> str:
            calls.append(
                (
                    plaintext,
                    sender_document_json,
                    sender_private_key,
                    recipient_document_json,
                )
            )
            return "authenticated"

    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: Binding())

    prepared = rust_integration.prepare_didcomm_delivery_encryption(
        issuer_did,
        recipient_document,
    )
    policy_path.write_text(
        json.dumps({"version": 1, "issuers": {issuer_did: {"mode": "anoncrypt"}}}),
        encoding="utf-8",
    )

    assert (
        rust_integration.didcomm_encrypt_prepared_delivery(
            "signed-message",
            prepared,
        )
        == "authenticated"
    )
    assert len(calls) == 2
    assert json.loads(calls[0][0])["body"] == {"preflight": True}
    assert calls[1][0] == "signed-message"
    assert json.loads(calls[1][1]) == sender_document
    assert calls[1][2] == private_key
    assert json.loads(calls[1][3]) == recipient_document


def test_configured_policy_requires_an_exact_active_issuer_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "DIDCOMM_ENCRYPTION_POLICY_FILE",
        _write_encryption_policy(
            tmp_path,
            {"did:web:other.example": {"mode": "anoncrypt"}},
        ),
    )
    anoncrypt = Mock()
    monkeypatch.setattr(rust_integration, "didcomm_encrypt", anoncrypt)

    with pytest.raises(
        rust_integration.DidcommEncryptionPolicyError,
        match="no entry for the active issuer",
    ):
        rust_integration.didcomm_encrypt_delivery(
            "message",
            "did:web:issuer.example",
            {"id": "did:peer:holder"},
        )

    anoncrypt.assert_not_called()


@pytest.mark.parametrize(
    "policy_text",
    [
        '{"version":1,"issuers":{"did:web:issuer.example":{"mode":"anoncrypt","mode":"authcrypt"}}}',
        json.dumps(
            {
                "version": True,
                "issuers": {"did:web:issuer.example": {"mode": "anoncrypt"}},
            }
        ),
        json.dumps(
            {
                "version": 1,
                "issuers": {
                    "did:web:issuer.example": {
                        "mode": "authcrypt",
                        "sender_x25519_private_key": "AA==",
                    }
                },
            }
        ),
        json.dumps(
            {
                "version": 1,
                "issuers": {
                    "did:web:issuer.example": {
                        "mode": "anoncrypt",
                        "unexpected": True,
                    }
                },
            }
        ),
    ],
)
def test_policy_rejects_ambiguous_or_noncanonical_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    policy_text: str,
) -> None:
    policy_path = tmp_path / "invalid-policy.json"
    policy_path.write_text(policy_text, encoding="utf-8")
    monkeypatch.setenv("DIDCOMM_ENCRYPTION_POLICY_FILE", str(policy_path))

    with pytest.raises(rust_integration.DidcommEncryptionPolicyError):
        rust_integration.didcomm_encrypt_delivery(
            "message",
            "did:web:issuer.example",
            {"id": "did:peer:holder"},
        )


def test_authcrypt_failure_never_falls_back_to_anoncrypt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "DIDCOMM_ENCRYPTION_POLICY_FILE",
        _write_encryption_policy(
            tmp_path,
            {
                "did:web:issuer.example": {
                    "mode": "authcrypt",
                    "sender_x25519_private_key": rust_integration.base64url_encode(
                        bytes(range(32))
                    ),
                }
            },
        ),
    )
    monkeypatch.setattr(
        rust_integration,
        "didcomm_resolve_did",
        Mock(return_value={"id": "did:web:issuer.example"}),
    )
    monkeypatch.setattr(
        rust_integration,
        "didcomm_encrypt_authcrypt",
        Mock(side_effect=RuntimeError("sender key mismatch")),
    )
    anoncrypt = Mock()
    monkeypatch.setattr(rust_integration, "didcomm_encrypt", anoncrypt)

    with pytest.raises(rust_integration.DidcommAuthcryptError, match="without fallback"):
        rust_integration.didcomm_encrypt_delivery(
            "message",
            "did:web:issuer.example",
            {"id": "did:peer:holder"},
        )

    anoncrypt.assert_not_called()


def test_policy_rejects_cross_issuer_authcrypt_key_reuse(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_key = rust_integration.base64url_encode(bytes(range(32)))
    monkeypatch.setenv(
        "DIDCOMM_ENCRYPTION_POLICY_FILE",
        _write_encryption_policy(
            tmp_path,
            {
                "did:web:issuer-a.example": {
                    "mode": "authcrypt",
                    "sender_x25519_private_key": private_key,
                },
                "did:web:issuer-b.example": {
                    "mode": "authcrypt",
                    "sender_x25519_private_key": private_key,
                },
            },
        ),
    )

    with pytest.raises(
        rust_integration.DidcommEncryptionPolicyError,
        match="must not be reused across issuers",
    ):
        rust_integration.didcomm_encrypt_delivery(
            "message",
            "did:web:issuer-a.example",
            {"id": "did:peer:holder"},
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
@pytest.mark.parametrize(
    ("encryption_error", "expected_status", "expected_detail"),
    [
        (RuntimeError("missing key agreement"), 422, "compatible DIDComm key agreement"),
        (
            rust_integration.DidcommAuthcryptError("sender key mismatch"),
            503,
            "sender-authentication configuration is unavailable",
        ),
    ],
)
async def test_delivery_rejects_private_or_unavailable_encryption(
    monkeypatch: pytest.MonkeyPatch,
    encryption_error: Exception,
    expected_status: int,
    expected_detail: str,
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
    allocate_status = AsyncMock(return_value=(None, []))
    sign_credential = AsyncMock(
        return_value=("signed-credential", "urn:uuid:credential-a")
    )
    pack_credential = Mock(return_value=json.dumps({"id": "message-a"}))
    monkeypatch.setattr(
        routes,
        "_allocate_credential_status_list_entries",
        allocate_status,
    )
    monkeypatch.setattr(
        routes,
        "create_sd_jwt_vc_with_remote_signing",
        sign_credential,
    )
    monkeypatch.setattr(routes, "didcomm_pack_credential", pack_credential)
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
        "prepare_didcomm_delivery_encryption",
        Mock(side_effect=encryption_error),
    )

    with pytest.raises(HTTPException, match=expected_detail) as exc:
        await routes._didcomm_sign_and_deliver(
            transaction,
            "did:peer:holder",
            repo,
        )

    assert exc.value.status_code == expected_status
    allocate_status.assert_not_awaited()
    sign_credential.assert_not_awaited()
    pack_credential.assert_not_called()


@pytest.mark.asyncio
async def test_delivery_validates_holder_endpoint_before_context_or_status_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = IssuanceTransaction(
        id="tx-a",
        organization_id="org-a",
        credential_template_id="template-a",
        issuer_profile_id="profile-a",
        issuer_did_override="did:web:issuer.example",
        claims={"given_name": "Alice"},
    )
    apply_context = AsyncMock()
    allocate_status = AsyncMock()
    validate_endpoint = AsyncMock(
        side_effect=HTTPException(status_code=422, detail="endpoint denied")
    )
    monkeypatch.setattr(
        routes,
        "didcomm_resolve_did",
        lambda _did: {"id": "did:peer:holder"},
    )
    monkeypatch.setattr(
        routes,
        "didcomm_extract_endpoint",
        lambda _doc: "https://127.0.0.1/inbox",
    )
    monkeypatch.setattr(routes, "_validated_didcomm_delivery_endpoint", validate_endpoint)
    monkeypatch.setattr(routes, "apply_remote_issuer_context", apply_context)
    monkeypatch.setattr(
        routes,
        "_allocate_credential_status_list_entries",
        allocate_status,
    )

    with pytest.raises(HTTPException, match="endpoint denied") as exc:
        await routes._didcomm_sign_and_deliver(
            transaction,
            "did:peer:holder",
            SimpleNamespace(save_transaction=AsyncMock()),
        )

    assert exc.value.status_code == 422
    validate_endpoint.assert_awaited_once_with("https://127.0.0.1/inbox")
    apply_context.assert_not_awaited()
    allocate_status.assert_not_awaited()


@pytest.mark.asyncio
async def test_private_test_agent_still_requires_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DIDCOMM_ALLOW_PRIVATE_IPS", "true")

    assert (
        await routes._validated_didcomm_delivery_endpoint(
            "https://127.0.0.1:18444/inbox"
        )
        == "https://127.0.0.1:18444/inbox"
    )
    with pytest.raises(HTTPException, match="must use HTTPS") as exc:
        await routes._validated_didcomm_delivery_endpoint(
            "http://127.0.0.1:18444/inbox"
        )

    assert exc.value.status_code == 422
