from __future__ import annotations

import json
import logging
import ssl
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException
from issuance.application import rust_integration
from issuance.domain.entities import (
    IssuanceStatus,
    IssuanceTransaction,
    stable_issuance_credential_id,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
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


def _configure_delivery_through_transport(
    monkeypatch: pytest.MonkeyPatch,
    *,
    holder_did: str,
    preflight_error: Exception | None = None,
    encryption_error: Exception | None = None,
) -> tuple[IssuanceTransaction, SimpleNamespace]:
    transaction = IssuanceTransaction(
        id="tx-didcomm-diagnostic-privacy",
        organization_id="org-a",
        credential_template_id="template-a",
        issuer_profile_id="profile-a",
        issuer_did_override="did:web:issuer.example",
        issuer_algorithm="ES256",
        claims={"given_name": "Alice"},
    )
    repo = SimpleNamespace(save_transaction=AsyncMock())
    remote_context = {
        "issuer_did": transaction.issuer_did_override,
        "issuer_profile_id": transaction.issuer_profile_id,
        "algorithm": transaction.issuer_algorithm,
        "verification_method_id": "did:web:issuer.example#key-1",
        "service": {"algorithm": "ES256"},
    }

    monkeypatch.setattr(routes, "didcomm_resolve_did", lambda _did: {"id": holder_did})
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
        "apply_remote_issuer_context",
        AsyncMock(return_value=remote_context),
    )
    monkeypatch.setattr(
        routes,
        "prepare_didcomm_delivery_encryption",
        Mock(side_effect=preflight_error) if preflight_error else Mock(return_value=object()),
    )
    monkeypatch.setattr(
        routes,
        "_allocate_credential_status_list_entries",
        AsyncMock(return_value=(None, [])),
    )
    monkeypatch.setattr(
        routes,
        "create_sd_jwt_vc_with_remote_signing",
        AsyncMock(
            return_value=(
                "signed-credential",
                stable_issuance_credential_id(transaction.id),
            )
        ),
    )
    monkeypatch.setattr(
        routes,
        "didcomm_pack_credential",
        Mock(return_value=json.dumps({"id": "message-a"})),
    )
    monkeypatch.setattr(
        routes,
        "didcomm_encrypt_prepared_delivery",
        Mock(side_effect=encryption_error) if encryption_error else Mock(return_value=b"packed"),
    )
    monkeypatch.setattr(routes, "_didcomm_tls_verifier", Mock(return_value=True))
    return transaction, repo


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
        def didcomm_resolve_did_with_metadata(did: str, **configuration: object) -> str:
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
                "universal_resolver_url": ("https://resolver.internal.example/1.0/identifiers"),
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
        def didcomm_resolve_did_with_metadata(did: str, **configuration: object) -> str:
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
                    "sender_x25519_private_key": rust_integration.base64url_encode(private_key),
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
                    "sender_x25519_private_key": rust_integration.base64url_encode(private_key),
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
    context.load_verify_locations.assert_called_once_with(cafile="/run/secrets/didcomm-root-ca.pem")


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
async def test_auto_delivery_logs_only_sanitized_stage_and_exception_type(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    holder_did = "did:peer:holder-MUST-NOT-ENTER-LOGS-1b9266d5"
    sensitive_error = "transport-secret-MUST-NOT-ENTER-LOGS-9f76ae42"
    transaction = IssuanceTransaction(
        id="tx-auto-delivery-privacy",
        organization_id="org-a",
        credential_type="EmployeeCredential",
        wallet_configs=[
            {
                "wallet_id": "didcomm-wallet",
                "format_variant": "didcomm_v2",
            }
        ],
    )
    request = routes.InitiateIssuanceRequest(
        organization_id="org-a",
        issuer_did="did:web:issuer.example",
        holder_did=holder_did,
    )
    monkeypatch.setattr(routes, "oid4vci_create_credential_offer", Mock(return_value="{}"))
    monkeypatch.setattr(
        routes,
        "_didcomm_sign_and_deliver",
        AsyncMock(side_effect=RuntimeError(sensitive_error)),
    )
    caplog.set_level(logging.INFO, logger="issuance.infrastructure.api.routes")

    response = await routes._issuance_response_from_transaction(
        tx=transaction,
        request=request,
        repo=SimpleNamespace(),
    )

    assert response.credential_offer_uris == {
        "didcomm-wallet": "didcomm://pending?transaction_id=tx-auto-delivery-privacy"
    }
    route_records = [
        record for record in caplog.records if record.name == "issuance.infrastructure.api.routes"
    ]
    rendered_logs = "\n".join(item.getMessage() for item in route_records)
    structured_logs = "\n".join(repr(item.__dict__) for item in route_records)
    for sensitive_value in (holder_did, sensitive_error):
        assert sensitive_value not in rendered_logs
        assert sensitive_value not in structured_logs
    records = [
        record
        for record in route_records
        if getattr(record, "didcomm_stage", None) == "auto-delivery"
    ]
    assert len(records) == 1
    record = records[0]
    assert record.getMessage() == "DIDComm auto-delivery failed (RuntimeError)"
    assert record.didcomm_exception_type == "RuntimeError"
    assert record.args == ()
    assert record.exc_info is None


@pytest.mark.asyncio
async def test_missing_endpoint_detail_does_not_echo_holder_did(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder_did = "did:peer:holder-MUST-NOT-ENTER-RESPONSE-8d85cf16"
    transaction = IssuanceTransaction(
        id="tx-missing-didcomm-endpoint",
        organization_id="org-a",
        claims={"given_name": "Alice"},
    )
    monkeypatch.setattr(routes, "didcomm_resolve_did", lambda _did: {"id": holder_did})
    monkeypatch.setattr(routes, "didcomm_extract_endpoint", lambda _doc: None)

    with pytest.raises(HTTPException) as exc:
        await routes._didcomm_sign_and_deliver(
            transaction,
            holder_did,
            SimpleNamespace(),
        )

    assert exc.value.status_code == 422
    assert exc.value.detail == "Holder DID has no DIDComm service endpoint"
    assert holder_did not in str(exc.value.detail)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_stage", "expected_stage"),
    [
        ("preflight", "encryption-preflight"),
        ("encryption", "encryption"),
    ],
)
async def test_encryption_logs_do_not_retain_holder_or_exception_details(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure_stage: str,
    expected_stage: str,
) -> None:
    holder_did = "did:peer:holder-MUST-NOT-ENTER-LOGS-6791f3f2"
    sensitive_error = "encryption-secret-MUST-NOT-ENTER-LOGS-1ba2e8d7"
    failure = RuntimeError(sensitive_error)
    transaction, repo = _configure_delivery_through_transport(
        monkeypatch,
        holder_did=holder_did,
        preflight_error=failure if failure_stage == "preflight" else None,
        encryption_error=failure if failure_stage == "encryption" else None,
    )
    caplog.set_level(logging.INFO, logger="issuance.infrastructure.api.routes")

    with pytest.raises(HTTPException) as exc:
        await routes._didcomm_sign_and_deliver(transaction, holder_did, repo)

    assert exc.value.status_code == 422
    route_records = [
        record for record in caplog.records if record.name == "issuance.infrastructure.api.routes"
    ]
    rendered_logs = "\n".join(item.getMessage() for item in route_records)
    structured_logs = "\n".join(repr(item.__dict__) for item in route_records)
    for sensitive_value in (holder_did, sensitive_error):
        assert sensitive_value not in rendered_logs
        assert sensitive_value not in structured_logs
    records = [
        record
        for record in route_records
        if getattr(record, "didcomm_stage", None) == expected_stage
    ]
    assert len(records) == 1
    record = records[0]
    assert record.getMessage() == f"DIDComm {expected_stage} failed (RuntimeError)"
    assert record.didcomm_exception_type == "RuntimeError"
    assert record.args == ()
    assert record.exc_info is None


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_kind", ["http", "transport"])
async def test_delivery_error_omits_remote_body_and_transport_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure_kind: str,
) -> None:
    holder_did = "did:peer:holder-a"
    response_body = "wallet-body-MUST-NOT-ENTER-RESPONSE-757f9c55"
    transport_detail = "transport-secret-MUST-NOT-ENTER-RESPONSE-309c60e7"
    transaction, repo = _configure_delivery_through_transport(
        monkeypatch,
        holder_did=holder_did,
    )

    class FakeResponse:
        status_code = 502
        text = response_body

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            if failure_kind == "transport":
                raise RuntimeError(transport_detail)
            return FakeResponse()

    monkeypatch.setattr(routes.httpx, "AsyncClient", FakeClient)
    caplog.set_level(logging.INFO, logger="issuance.infrastructure.api.routes")

    response = await routes._didcomm_sign_and_deliver(transaction, holder_did, repo)

    body = response.model_dump()
    serialized_body = json.dumps(body, sort_keys=True)
    assert body["status"] == "delivery_failed"
    assert "error" in body
    assert body["error"] == ("HTTP 502" if failure_kind == "http" else "DIDComm transport failed")
    assert response_body not in serialized_body
    assert transport_detail not in serialized_body
    route_records = [
        record for record in caplog.records if record.name == "issuance.infrastructure.api.routes"
    ]
    rendered_logs = "\n".join(item.getMessage() for item in route_records)
    structured_logs = "\n".join(repr(item.__dict__) for item in route_records)
    for sensitive_value in (holder_did, response_body, transport_detail):
        assert sensitive_value not in rendered_logs
        assert sensitive_value not in structured_logs
    if failure_kind == "http":
        assert "502" in body["error"]
    else:
        records = [
            record
            for record in route_records
            if getattr(record, "didcomm_stage", None) == "transport"
        ]
        assert len(records) == 1
        assert records[0].getMessage() == "DIDComm transport failed (RuntimeError)"
        assert records[0].args == ()
        assert transport_detail not in repr(records[0].__dict__)


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
    caplog: pytest.LogCaptureFixture,
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
    sign_credential = AsyncMock(return_value=("signed-credential", "urn:uuid:credential-a"))
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

    sensitive_holder = "did:peer:holder-MUST-NOT-ENTER-LOGS-41fe379c"
    caplog.set_level(logging.INFO, logger="issuance.infrastructure.api.routes")

    with pytest.raises(HTTPException, match=expected_detail) as exc:
        await routes._didcomm_sign_and_deliver(
            transaction,
            sensitive_holder,
            repo,
        )

    assert exc.value.status_code == expected_status
    allocate_status.assert_not_awaited()
    sign_credential.assert_not_awaited()
    pack_credential.assert_not_called()
    route_records = [
        record for record in caplog.records if record.name == "issuance.infrastructure.api.routes"
    ]
    rendered_logs = "\n".join(record.getMessage() for record in route_records)
    structured_logs = "\n".join(repr(record.__dict__) for record in route_records)
    for sensitive_value in (sensitive_holder, str(encryption_error)):
        assert sensitive_value not in rendered_logs
        assert sensitive_value not in structured_logs


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
async def test_signing_and_delivery_failures_retry_one_stable_status_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = IssuanceTransaction(
        id="tx-didcomm-retry",
        organization_id="org-a",
        credential_template_id="template-a",
        revocation_profile_id="profile-a",
        issuer_profile_id="issuer-profile-a",
        issuer_did_override="did:web:issuer.example",
        issuer_algorithm="ES256",
        claims={"given_name": "Alice"},
        credential_type="EmployeeCredential",
        status=IssuanceStatus.PENDING,
    )
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(transaction)
    stable_id = stable_issuance_credential_id(transaction.id)
    remote_context = {
        "issuer_did": transaction.issuer_did_override,
        "issuer_profile_id": transaction.issuer_profile_id,
        "algorithm": transaction.issuer_algorithm,
        "verification_method_id": "did:web:issuer.example#key-1",
        "service": {"algorithm": "ES256"},
    }
    allocation = AsyncMock(
        return_value=(
            transaction.revocation_profile_id,
            [
                {
                    "status_list_id": transaction.revocation_profile_id,
                    "index": 9,
                    "status_list_uri": "https://issuer.example/status/1",
                }
            ],
        )
    )
    signing_attempts = 0

    async def sign_credential(**kwargs):
        nonlocal signing_attempts
        signing_attempts += 1
        if signing_attempts == 1:
            raise RuntimeError("simulated signing outage")
        return "signed-credential", kwargs["credential_id"]

    delivery_statuses = [500, 200]

    class FakeResponse:
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code
            self.text = "wallet response"

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse(delivery_statuses.pop(0))

    monkeypatch.setattr(routes, "didcomm_resolve_did", lambda _did: {"id": "did:peer:holder"})
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
        "apply_remote_issuer_context",
        AsyncMock(return_value=remote_context),
    )
    monkeypatch.setattr(routes, "prepare_didcomm_delivery_encryption", Mock(return_value=object()))
    monkeypatch.setattr(routes, "_allocate_credential_status_list_entries", allocation)
    monkeypatch.setattr(routes, "create_sd_jwt_vc_with_remote_signing", sign_credential)
    monkeypatch.setattr(
        routes,
        "didcomm_pack_credential",
        Mock(return_value=json.dumps({"id": "message-a"})),
    )
    monkeypatch.setattr(routes, "didcomm_encrypt_prepared_delivery", Mock(return_value=b"packed"))
    monkeypatch.setattr(routes, "_didcomm_tls_verifier", Mock(return_value=True))
    monkeypatch.setattr(routes.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(routes, "record_canvas_credential_claim", AsyncMock())
    monkeypatch.setattr(routes, "_finalize_credential_renewal", AsyncMock())
    monkeypatch.setattr(routes, "record_post_issuance_deliveries", AsyncMock())

    with pytest.raises(RuntimeError, match="signing outage"):
        await routes._didcomm_sign_and_deliver(transaction, "did:peer:holder", repo)
    after_signing_failure = await repo.get_transaction(transaction.id)
    assert after_signing_failure is not None
    assert after_signing_failure.status == IssuanceStatus.PENDING
    assert await repo.get_credential_by_transaction_id(transaction.id) is None

    failed_delivery = await routes._didcomm_sign_and_deliver(
        after_signing_failure,
        "did:peer:holder",
        repo,
    )
    assert failed_delivery.status == "delivery_failed"
    after_delivery_failure = await repo.get_transaction(transaction.id)
    assert after_delivery_failure is not None
    assert after_delivery_failure.status == IssuanceStatus.PENDING
    assert await repo.get_credential_by_transaction_id(transaction.id) is None

    delivered = await routes._didcomm_sign_and_deliver(
        after_delivery_failure,
        "did:peer:holder",
        repo,
    )
    assert delivered.status == "delivered"
    assert delivered.credential_id == stable_id
    finalized = await repo.get_transaction(transaction.id)
    assert finalized is not None
    assert finalized.status == IssuanceStatus.ISSUED
    assert (await repo.get_credential_by_transaction_id(transaction.id)).id == stable_id
    assert [call.kwargs["credential_id"] for call in allocation.await_args_list] == [
        stable_id,
        stable_id,
        stable_id,
    ]


@pytest.mark.asyncio
async def test_private_test_agent_still_requires_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DIDCOMM_ALLOW_PRIVATE_IPS", "true")

    assert (
        await routes._validated_didcomm_delivery_endpoint("https://127.0.0.1:18444/inbox")
        == "https://127.0.0.1:18444/inbox"
    )
    with pytest.raises(HTTPException, match="must use HTTPS") as exc:
        await routes._validated_didcomm_delivery_endpoint("http://127.0.0.1:18444/inbox")

    assert exc.value.status_code == 422
