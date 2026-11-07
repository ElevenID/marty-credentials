"""The shared verification backend returns Python errors for bad public keys."""

import base64
import json
from pathlib import Path

import _marty_rs
import pytest


@pytest.mark.parametrize("algorithm", ["ES256", "ES384", "RS256", "EdDSA"])
def test_invalid_public_key_is_a_value_error(algorithm):
    with pytest.raises(ValueError, match="Invalid .* public key PEM"):
        _marty_rs.verify_sd_jwt("invalid~", "invalid PEM", algorithm)


def test_unsupported_algorithm_is_a_value_error():
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        _marty_rs.verify_sd_jwt("invalid~", "invalid PEM", "HS256")


def test_signed_credential_discloses_claims_and_rejects_changed_signature():
    fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "sd_jwt_signed_public.json").read_text())
    credential, pem = fixture["credential"], fixture["issuer_public_pem"]
    claims = json.loads(_marty_rs.verify_sd_jwt(credential, pem))
    assert claims["iss"] == "did:web:issuer.example"
    assert claims["role"] == "member"
    assert claims["email"] == "member@example.com"
    compact, *disclosures = credential.split("~")
    header, payload, signature = compact.split(".")
    signature_bytes = bytearray(base64.urlsafe_b64decode(signature + "=="))
    signature_bytes[0] ^= 1
    changed_signature = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode()
    changed = "~".join([f"{header}.{payload}.{changed_signature}", *disclosures])
    with pytest.raises(RuntimeError, match="Verification failed"):
        _marty_rs.verify_sd_jwt(changed, pem)


def test_configured_algorithm_is_bound_to_the_issuer_signature():
    fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "sd_jwt_signed_public.json").read_text())
    credential, pem = fixture["credential"], fixture["issuer_public_pem"]
    assert json.loads(_marty_rs.verify_sd_jwt(credential, pem, "ES256"))["role"] == "member"
    # Both settings parse an EC PEM. The configured algorithm must constrain
    # verification rather than only choose the PEM decoder.
    with pytest.raises(RuntimeError, match="Verification failed"):
        _marty_rs.verify_sd_jwt(credential, pem, "ES384")


@pytest.mark.parametrize("issuer", [None, 42])
def test_provider_adoption_retains_the_string_issuer_boundary(issuer):
    fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "sd_jwt_signed_public.json").read_text())
    compact, *disclosures = fixture["credential"].split("~")
    header, payload, signature = compact.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    if issuer is None:
        claims.pop("iss")
    else:
        claims["iss"] = issuer
    changed_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    changed = "~".join([f"{header}.{changed_payload}.{signature}", *disclosures])
    # The role boundary rejects this malformed issuer before signature checking.
    with pytest.raises(RuntimeError, match="must contain a string iss"):
        _marty_rs.verify_sd_jwt(changed, fixture["issuer_public_pem"])
