from __future__ import annotations

import json

import pytest

import _marty_rs


def _issued_jwt() -> tuple[str, dict[str, object], str]:
    issuer_did, private_jwk_json = _marty_rs.generate_p256_key()
    token, _credential_id = _marty_rs.create_verifiable_credential(
        issuer_did=issuer_did,
        issuer_jwk_json=private_jwk_json,
        subject_id="did:example:holder",
        credential_type="EmployeeCredential",
        claims_json='{"employee_id":"E-123"}',
        format="jwt_vc_json",
        expiration_seconds=3600,
    )
    private_jwk = json.loads(private_jwk_json)
    public_jwk = {key: value for key, value in private_jwk.items() if key != "d"}
    return token, public_jwk, issuer_did


def test_native_jws_verification_returns_only_authenticated_claims() -> None:
    token, public_jwk, issuer_did = _issued_jwt()

    claims = json.loads(_marty_rs.verify_jws_with_jwk(token, json.dumps(public_jwk)))
    public_pem = _marty_rs.p256_public_jwk_to_pem(json.dumps(public_jwk))
    pem_claims = json.loads(_marty_rs.verify_jws_with_pem(token, public_pem))

    assert claims == pem_claims
    assert claims["iss"] == issuer_did
    assert claims["vc"]["credentialSubject"]["employee_id"] == "E-123"


def test_native_jws_verification_rejects_altered_signature() -> None:
    token, public_jwk, _issuer_did = _issued_jwt()
    prefix, payload, signature = token.split(".")
    replacement = "A" if signature[-1] != "A" else "B"
    altered = f"{prefix}.{payload}.{signature[:-1]}{replacement}"

    with pytest.raises(ValueError, match="signature verification failed"):
        _marty_rs.verify_jws_with_jwk(altered, json.dumps(public_jwk))
