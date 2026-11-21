"""The shared verification backend returns Python errors for bad public keys."""

import base64
import json
from pathlib import Path

import _marty_rs
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

DIGEST_PROFILE_ERROR = "SD-JWT digest algorithm is not admitted by this compatibility profile"


@pytest.fixture(scope="module")
def signed_digest_vectors():
    # Unmodified public vectors from marty-core 64601c9; the original signing
    # keys stayed in a disposable non-exportable OpenBao instance.
    fixture = json.loads(
        (Path(__file__).parents[1] / "fixtures" / "sd_jwt_multi_digest_public.json").read_text()
    )
    jwk = fixture["issuer_public_jwk"]
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256" and "d" not in jwk
    public_key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big"),
        int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big"),
        ec.SECP256R1(),
    ).public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return {vector["digest_algorithm"]: vector["credential"] for vector in fixture["vectors"]}, pem


def changed_issuer_signature(credential):
    compact, *disclosures = credential.split("~")
    header, payload, signature = compact.split(".")
    signature_bytes = bytearray(base64.urlsafe_b64decode(signature + "=="))
    signature_bytes[0] ^= 1
    changed_signature = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode()
    return "~".join([f"{header}.{payload}.{changed_signature}", *disclosures])


@pytest.fixture(scope="module")
def published_rsa_credential():
    fixture = json.loads(
        (Path(__file__).parents[1] / "fixtures" / "rfc7515_a2_rsa_public.json").read_text()
    )
    jwk = fixture["issuer_public_jwk"]
    assert set(jwk) == {"kty", "n", "e"} and jwk["kty"] == "RSA"
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big"),
        int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big"),
    ).public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    # A compact SD-JWT with no disclosures retains the RFC's exact signed bytes.
    return fixture["compact_jws"] + "~", pem


@pytest.mark.parametrize("use_class", [False, True])
def test_rsa_pem_signature_verifies_before_the_existing_expiry_rejection(
    published_rsa_credential, use_class
):
    credential, pem = published_rsa_credential
    verify = _marty_rs.SdJwtVerifier(pem, "RS256").verify if use_class else lambda value: _marty_rs.verify_sd_jwt(value, pem, "RS256")
    # The unchanged RFC payload expired in 2011. The fork checks its signature
    # before its NumericDate, so this specific error proves the RSA PEM path
    # authenticated it while preserving credential expiry policy.
    with pytest.raises(RuntimeError, match="Cannot decode jwt: ExpiredSignature"):
        verify(credential)


def test_rsa_pem_tampered_signature_fails_before_expiry(published_rsa_credential):
    credential, pem = published_rsa_credential
    with pytest.raises(RuntimeError, match="Verification failed") as error:
        _marty_rs.verify_sd_jwt(changed_issuer_signature(credential), pem, "RS256")
    assert "ExpiredSignature" not in str(error.value)


@pytest.mark.parametrize("algorithm", ["RS384", "PS256"])
def test_rsa_pem_configured_algorithm_fails_before_expiry(published_rsa_credential, algorithm):
    credential, pem = published_rsa_credential
    with pytest.raises(RuntimeError, match="Verification failed") as error:
        _marty_rs.verify_sd_jwt(credential, pem, algorithm)
    assert "ExpiredSignature" not in str(error.value)


@pytest.mark.parametrize("use_class", [False, True])
def test_compatibility_profile_accepts_signed_sha256(signed_digest_vectors, use_class):
    credentials, pem = signed_digest_vectors
    verify = _marty_rs.SdJwtVerifier(pem).verify if use_class else lambda value: _marty_rs.verify_sd_jwt(value, pem)
    claims = json.loads(verify(credentials["sha-256"]))
    assert claims["iss"] == "did:web:issuer.example"
    assert claims["given_name"] == "Alice"
    assert claims["family_name"] == "Smith"
    assert "_sd_alg" not in claims


@pytest.mark.parametrize("digest", ["sha-384", "sha-512"])
@pytest.mark.parametrize("use_class", [False, True])
def test_compatibility_profile_does_not_inherit_generic_fork_digests(
    signed_digest_vectors, digest, use_class
):
    credentials, pem = signed_digest_vectors
    verify = _marty_rs.SdJwtVerifier(pem).verify if use_class else lambda value: _marty_rs.verify_sd_jwt(value, pem)
    with pytest.raises(RuntimeError, match=DIGEST_PROFILE_ERROR):
        verify(credentials[digest])


@pytest.mark.parametrize("digest", ["sha-384", "sha-512"])
def test_issuer_signature_failure_precedes_digest_profile_admission(signed_digest_vectors, digest):
    credentials, pem = signed_digest_vectors
    with pytest.raises(RuntimeError, match="Verification failed") as error:
        _marty_rs.verify_sd_jwt(changed_issuer_signature(credentials[digest]), pem)
    assert DIGEST_PROFILE_ERROR not in str(error.value)


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
    with pytest.raises(RuntimeError, match="Verification failed"):
        _marty_rs.verify_sd_jwt(changed_issuer_signature(credential), pem)


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
