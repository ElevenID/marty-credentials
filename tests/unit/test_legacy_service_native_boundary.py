from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from marty_credentials.adapters.services import issuance_service, verification_service
from marty_credentials.native_backend import (
    NativeBackendUnavailable,
    NativeOperationError,
    require_marty_verification,
)

ROOT = Path(__file__).resolve().parents[2]
SERVICE_FILES = (
    ROOT / "python/marty_credentials/adapters/services/issuance_service.py",
    ROOT / "python/marty_credentials/adapters/services/verification_service.py",
)


def test_service_kernels_do_not_import_python_crypto_or_legacy_native_package() -> None:
    imported_modules: set[str] = set()
    for path in SERVICE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)

    assert not any(name == "cryptography" or name.startswith("cryptography.") for name in imported_modules)
    assert "marty_verification_py" not in imported_modules


def test_verification_loader_rejects_missing_capability(monkeypatch) -> None:
    monkeypatch.setattr(
        "marty_credentials.native_backend.importlib.import_module",
        lambda name: SimpleNamespace(public_key_pem_to_jwk=lambda value: value),
    )

    with pytest.raises(NativeBackendUnavailable, match="open_badge_ob3_verify"):
        require_marty_verification(("public_key_pem_to_jwk", "open_badge_ob3_verify"))


def test_issuance_uses_native_jwk_generation_and_sd_jwt_selection(monkeypatch) -> None:
    backend = SimpleNamespace(
        generate_p256_jwk=lambda: ("private", "public"),
        sd_jwt_create_presentation=lambda token, fields, nonce, audience: (
            token,
            fields,
            nonce,
            audience,
        ),
    )
    monkeypatch.setattr(issuance_service, "_marty_rs", backend)
    service = issuance_service.IssuanceService.__new__(issuance_service.IssuanceService)

    assert service._generate_keys() == ("private", "public")
    assert service.create_sd_jwt_presentation("token", ["name"]) == (
        "token",
        ["name"],
        None,
        None,
    )


def test_open_badge_x509_private_key_path_fails_closed() -> None:
    service = issuance_service.IssuanceService.__new__(issuance_service.IssuanceService)

    with pytest.raises(NativeOperationError, match="X.509 private-key conversion"):
        service.issue_open_badge_ob3(
            issuer_did="did:example:issuer",
            recipient_did="did:example:holder",
            badge_name="Example",
            badge_description="Example badge",
            x509_cert_pem="certificate",
            x509_key_pem="private key",
        )


def test_mdoc_issuance_rejects_ambiguous_multiple_namespaces(monkeypatch) -> None:
    monkeypatch.setattr(
        issuance_service,
        "_marty_rs",
        SimpleNamespace(generate_p256_jwk=lambda: ("private", "public")),
    )
    service = issuance_service.IssuanceService.__new__(issuance_service.IssuanceService)

    with pytest.raises(NativeOperationError, match="exactly one namespace"):
        service.issue_mdoc(
            issuer_did="did:example:issuer",
            subject_did="did:example:holder",
            doc_type="org.iso.18013.5.1.mDL",
            namespaces={"one": {"name": "Alice"}, "two": {"name": "Alice"}},
        )


def test_sd_jwt_verification_passes_public_jwk_to_native_backend(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def verify(token: str, jwk: str, audience: object, nonce: object) -> str:
        captured.update(token=token, jwk=jwk, audience=audience, nonce=nonce)
        return '{"iss":"did:example:issuer","name":"Alice"}'

    monkeypatch.setattr(
        verification_service,
        "_marty_verification",
        SimpleNamespace(public_key_pem_to_jwk=lambda value: '{"kty":"EC"}'),
    )
    monkeypatch.setattr(
        verification_service,
        "_marty_rs",
        SimpleNamespace(verify_sd_jwt=verify),
    )
    service = verification_service.VerificationService.__new__(
        verification_service.VerificationService
    )
    service._log_verification = lambda *args, **kwargs: None

    result = service.verify_sd_jwt(
        "issuer~disclosure~",
        "did:example:verifier",
        "public key",
    )

    assert result["valid"] is True
    assert captured == {
        "token": "issuer~disclosure~",
        "jwk": '{"kty": "EC"}',
        "audience": None,
        "nonce": None,
    }


def test_mdoc_verification_uses_native_claim_and_issuer_kernels(monkeypatch) -> None:
    calls: list[str] = []

    def verify_claims(value: list[int]) -> dict[str, object]:
        calls.append("claims")
        return {
            "family_name": "Doe",
            "_mdoc": {
                "documents": [
                    {
                        "doc_type": "org.iso.18013.5.1.mDL",
                        "namespaces": {"org.iso.18013.5.1": {"family_name": "Doe"}},
                    }
                ]
            },
        }

    def verify_issuer(value: list[int], roots: list[str]) -> SimpleNamespace:
        calls.append("issuer")
        return SimpleNamespace(
            signature_valid=True,
            issuer_trusted=True,
            error=None,
        )

    monkeypatch.setattr(
        verification_service,
        "_marty_rs",
        SimpleNamespace(
            verify_mdoc_cbor=verify_claims,
            verify_mdoc_issuer=verify_issuer,
        ),
    )
    service = verification_service.VerificationService.__new__(
        verification_service.VerificationService
    )
    service._log_verification = lambda *args, **kwargs: None

    result = service.verify_mdoc(
        b"native fixture",
        "did:example:verifier",
        trusted_issuer_keys=["root certificate"],
    )

    assert result["valid"] is True
    assert result["details"]["issuer_verified"] is True
    assert result["details"]["document_types"] == ["org.iso.18013.5.1.mDL"]
    assert calls == ["claims", "issuer"]
