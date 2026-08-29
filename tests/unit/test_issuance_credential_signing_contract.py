from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from issuance.domain.entities import (
    IssuanceStatus,
    IssuanceTransaction,
    stable_issuance_credential_id,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import routes
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-credential-signing.json").read_text(encoding="utf-8")
)


def encode(value: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )


def proof_jwt() -> str:
    inputs = CONTRACT["inputs"]
    return (
        f"{encode({'alg': 'ES256'})}."
        f"{encode({'aud': inputs['proof_audience'], 'nonce': inputs['proof_nonce']})}."
        "signature"
    )


def http_request() -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": CONTRACT["inputs"]["path"],
            "raw_path": CONTRACT["inputs"]["path"].encode(),
            "query_string": b"",
            "headers": [(b"host", b"issuer.example")],
            "client": ("127.0.0.1", 12345),
            "server": ("issuer.example", 443),
        }
    )


def transaction(case: dict[str, Any]) -> IssuanceTransaction:
    claims = dict(CONTRACT["claim_policy"]["preserved_fixture"])
    claims.update({field: f"internal-{field}" for field in CONTRACT["claim_policy"]["excluded"]})
    claims["_vct"] = f"https://issuer.example/credentials/{case['credential_type']}"
    claims["_credential_subject"] = {"id": "did:key:stored-subject", "role": "member"}
    claims["_credential_document"] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", case["credential_type"]],
        **({"id": case["credential_document_id"]} if case.get("credential_document_id") else {}),
    }
    return IssuanceTransaction(
        id=CONTRACT["inputs"]["transaction_id"],
        organization_id=CONTRACT["inputs"]["organization_id"],
        credential_template_id="template-signing-contract",
        application_id="application-signing-contract",
        applicant_id="applicant-signing-contract",
        status=IssuanceStatus.AUTHORIZED,
        access_token=CONTRACT["inputs"]["access_token"],
        nonce=CONTRACT["inputs"]["proof_nonce"],
        claims=claims,
        credential_type=case["credential_type"],
        credential_payload_format=case["payload_format"],
        issuer_did_override=CONTRACT["inputs"]["issuer_did"],
        issuer_algorithm=case["algorithm"],
    )


def assert_subsequence(actual: list[str], expected: list[str]) -> None:
    position = 0
    for value in actual:
        if position < len(expected) and value == expected[position]:
            position += 1
    assert position == len(expected), {"actual": actual, "missing_from": expected[position:]}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CONTRACT["formats"], ids=lambda case: case["name"])
async def test_all_credential_formats_match_language_neutral_signing_contract(
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
) -> None:
    repo = InMemoryIssuanceRepository()
    tx = transaction(case)
    await repo.save_transaction(tx)
    events: list[str] = []
    captured: dict[str, Any] = {"remote_formats": []}
    verification_method_id = f"{CONTRACT['inputs']['issuer_did']}#contract-key"
    remote_context = {
        "issuer_profile_id": "issuer-profile-contract",
        "issuer_did": CONTRACT["inputs"]["issuer_did"],
        "signing_service_id": "managed-custody-contract",
        "verification_method_id": verification_method_id,
        "public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "contract-public-key"},
        "algorithm": case["algorithm"],
        "service": {"algorithm": case["algorithm"]},
    }

    async def resolve_context(transaction: IssuanceTransaction, **kwargs: Any) -> dict[str, Any]:
        captured["remote_formats"].append(kwargs["credential_format"])
        transaction.issuer_profile_id = remote_context["issuer_profile_id"]
        transaction.issuer_did_override = remote_context["issuer_did"]
        transaction.signing_service_id = remote_context["signing_service_id"]
        return remote_context

    async def verify_proof(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        events.append("verify_proof")
        return (
            True,
            CONTRACT["inputs"]["holder_did"],
            {"kty": "EC", "crv": "P-256", "x": "holder-x", "y": "holder-y"},
            None,
        )

    async def consume_nonce(_nonce: str) -> bool:
        events.append("consume_nonce")
        return True

    async def canvas_readiness(**_kwargs: Any) -> None:
        events.append("canvas_readiness")

    original_claim = repo.claim_transaction_for_signing

    async def claim_for_signing(
        prepared: IssuanceTransaction, credential_id: str
    ) -> IssuanceTransaction | None:
        events.append("claim_transaction_for_signing")
        return await original_claim(prepared, credential_id)

    async def allocate_status(**_kwargs: Any) -> tuple[None, list[Any]]:
        events.append("allocate_status")
        return None, []

    async def did_sign(**kwargs: Any) -> dict[str, Any]:
        events.append("issuer_did_sign")
        captured["sign"] = kwargs
        raw_signature = base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")
        return {
            "ok": True,
            "issuer_did": kwargs["issuer_did"],
            "verification_method_id": verification_method_id,
            "algorithm": case["algorithm"],
            "signature_b64": raw_signature,
            "signature_encoding": "raw_ieee_p1363",
        }

    async def builder(name: str, **kwargs: Any) -> tuple[str, str]:
        assert name == case["builder"]
        events.append("credential_builder")
        captured["builder"] = name
        captured["builder_arguments"] = kwargs
        callback: Callable[..., Awaitable[Any]] | None = kwargs.get("remote_sign")
        if callback is not None:
            await callback(b"contract-signing-input", case["algorithm"])
        profile_sign: Callable[..., Awaitable[Any]] | None = kwargs.get("profile_sign")
        if profile_sign is not None:
            await profile_sign(b"contract-mdoc-input", case["algorithm"])
        encoded_credential = (
            json.dumps(
                {
                    "id": kwargs["credential_id"],
                    "proof": {"type": "DataIntegrityProof"},
                },
                separators=(",", ":"),
            )
            if name == "data_integrity"
            else f"contract-{name}-credential"
        )
        return encoded_credential, kwargs["credential_id"]

    async def sd_jwt_builder(**kwargs: Any) -> tuple[str, str]:
        return await builder("sd_jwt", **kwargs)

    async def jwt_vc_builder(**kwargs: Any) -> tuple[str, str]:
        return await builder("jwt_vc", **kwargs)

    async def data_integrity_builder(**kwargs: Any) -> tuple[str, str]:
        return await builder("data_integrity", **kwargs)

    async def mdoc_builder(**kwargs: Any) -> tuple[str, str]:
        return await builder("mdoc", **kwargs)

    original_finalize = repo.finalize_credential_issuance

    async def finalize(*args: Any, **kwargs: Any) -> None:
        events.append("finalize_credential_issuance")
        await original_finalize(*args, **kwargs)

    async def post_side_effect(*_args: Any, **_kwargs: Any) -> None:
        if not events or events[-1] != "post_issuance_side_effects":
            events.append("post_issuance_side_effects")

    monkeypatch.setattr(routes, "ISSUER_BASE_URL", "https://issuer.example")
    monkeypatch.setattr(routes, "apply_remote_issuer_context", resolve_context)
    monkeypatch.setattr(routes, "verify_oid4vci_proof_with_issuer_policy", verify_proof)
    monkeypatch.setattr(repo, "consume_proof_nonce", consume_nonce)
    monkeypatch.setattr(routes, "require_canvas_issuance_ready", canvas_readiness)
    monkeypatch.setattr(repo, "claim_transaction_for_signing", claim_for_signing)
    monkeypatch.setattr(routes, "_allocate_credential_status_list_entries", allocate_status)
    monkeypatch.setattr(routes, "sign_payload_with_issuer_did", did_sign)
    monkeypatch.setattr(routes, "create_sd_jwt_vc_with_remote_signing", sd_jwt_builder)
    monkeypatch.setattr(routes, "create_jwt_vc_with_remote_signing", jwt_vc_builder)
    monkeypatch.setattr(
        routes, "create_vcdm_data_integrity_with_remote_signing", data_integrity_builder
    )
    monkeypatch.setattr(routes, "create_mdoc_credential_with_issuer_profile_signing", mdoc_builder)
    monkeypatch.setattr(repo, "finalize_credential_issuance", finalize)
    monkeypatch.setattr(routes, "record_canvas_credential_claim", post_side_effect)
    monkeypatch.setattr(routes, "_finalize_credential_renewal", post_side_effect)
    monkeypatch.setattr(routes, "record_post_issuance_deliveries", post_side_effect)
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID(CONTRACT["inputs"]["notification_id"]))

    response = await routes.issue_credential(
        http_request(),
        routes.CredentialRequest(
            credential_configuration_id=case["credential_configuration_id"],
            proofs={"jwt": [proof_jwt()]},
        ),
        authorization=f"Bearer {CONTRACT['inputs']['access_token']}",
        repo=repo,
    )

    assert isinstance(response, routes.CredentialResponse)
    body = response.model_dump(exclude_none=True)
    assert body["credentials"][0]["format"] == case["response_format"]
    assert body["notification_id"] == CONTRACT["inputs"]["notification_id"]
    assert captured["builder"] == case["builder"]
    assert captured["remote_formats"] == [
        case["remote_credential_format"],
        case["remote_credential_format"],
    ]
    assert captured["sign"]["credential_format"] == case["remote_credential_format"]
    assert captured["sign"]["issuer_did"] == CONTRACT["inputs"]["issuer_did"]

    builder_arguments = captured["builder_arguments"]
    expected_credential_id = case.get("credential_document_id") or stable_issuance_credential_id(
        tx.id
    )
    assert builder_arguments["credential_id"] == expected_credential_id
    if case["holder_did_required"]:
        assert builder_arguments.get("subject_id") == CONTRACT["inputs"]["holder_did"]
    else:
        assert "subject_id" not in builder_arguments
    assert (
        json.loads(builder_arguments["claims_json"])
        == CONTRACT["claim_policy"]["preserved_fixture"]
    )
    if case["builder"] == "sd_jwt":
        assert (
            builder_arguments["selective_disclosure_claims"]
            == CONTRACT["claim_policy"]["sd_jwt_default_disclosures"]
        )
    if case["holder_jwk_required"]:
        assert builder_arguments["holder_jwk"]["kty"] == "EC"

    assert_subsequence(events, CONTRACT["critical_order"])
    stored = await repo.get_transaction(tx.id)
    assert stored is not None
    assert stored.status == IssuanceStatus.ISSUED
    assert stored.nonce is None
    credentials = await repo.list_credentials_by_org(tx.organization_id)
    assert len(credentials) == 1
    assert credentials[0].id == expected_credential_id


def test_signing_contract_pins_all_production_formats_and_atomic_state() -> None:
    assert CONTRACT["schema"] == "marty.issuance-credential-signing/v1"
    assert {case["response_format"] for case in CONTRACT["formats"]} == {
        "dc+sd-jwt",
        "jwt_vc_json",
        "ldp_vc",
        "mso_mdoc",
    }
    assert CONTRACT["identity"]["builder_must_return_reserved_id"] is True
    assert CONTRACT["state_machine"]["claim"] == {
        "from": "authorized",
        "to": "signing",
        "single_winner": True,
    }
    assert CONTRACT["state_machine"]["concurrent_loser"]["may_sign"] is False
