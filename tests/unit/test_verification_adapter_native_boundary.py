from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from marty_credentials.adapters.services import verification_service


def _public_pem() -> str:
    return (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def _service() -> verification_service.VerificationService:
    service = verification_service.VerificationService.__new__(
        verification_service.VerificationService
    )
    service.db = MagicMock()
    service._log_verification = MagicMock()
    return service


def test_vc_jwt_verification_passes_only_public_jwk_to_core(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def verify(request_json: str) -> str:
        captured.update(json.loads(request_json))
        return json.dumps(
            {
                "valid": True,
                "claims": {"iss": "did:example:issuer", "vc": {}},
                "errors": [],
            }
        )

    monkeypatch.setattr(
        verification_service,
        "_marty_rs",
        SimpleNamespace(verify_vcdm_jwt=verify),
    )

    result = _service().verify_w3c_vc(
        "header.payload.signature",
        verifier_did="did:example:verifier",
        public_key_pem=_public_pem(),
    )

    assert result["valid"] is False
    assert result["cryptographic_valid"] is True
    assert result["trust_chain_valid"] is False
    assert result["revocation_checked"] is False
    assert captured["token"] == "header.payload.signature"
    jwk = captured["issuer_public_jwk"]
    assert isinstance(jwk, dict)
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert "d" not in jwk


def test_vc_jwt_verification_fails_closed_on_native_error(monkeypatch) -> None:
    monkeypatch.setattr(
        verification_service,
        "_marty_rs",
        SimpleNamespace(
            verify_vcdm_jwt=lambda request_json: json.dumps(
                {"valid": False, "claims": None, "errors": ["signature is invalid"]}
            )
        ),
    )

    result = _service().verify_w3c_vc(
        "header.payload.signature",
        verifier_did="did:example:verifier",
        public_key_pem=_public_pem(),
    )

    assert result["valid"] is False
    assert "signature is invalid" in result["error"]
