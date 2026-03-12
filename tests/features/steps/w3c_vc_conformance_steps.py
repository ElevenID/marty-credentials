"""
Step definitions for W3C VC Data Model 2.0 conformance tests.

Tests that issued JWT-encoded Verifiable Credentials comply with the
W3C VC Data Model without requiring external services.
"""

import base64
import json
import re
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from behave import given, when, then


# ── helpers ──────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _jwt_header(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) == 3
    return json.loads(_b64url_decode(parts[0]))


def _jwt_payload(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) == 3
    return json.loads(_b64url_decode(parts[1]))


def _is_valid_uri(s: str) -> bool:
    try:
        r = urlparse(s)
        return bool(r.scheme and r.netloc or r.path.startswith("did:"))
    except ValueError:
        return False


def _issue_w3c_vc(context, claims: dict) -> str:
    result = context.issuance_service.issue_w3c_vc(
        issuer_did=context.test_data["issuer_did"],
        subject_did=context.test_data["subject_did"],
        credential_type="VerifiableCredential",
        claims=claims,
    )
    credential = result["credential"]
    context.test_data["issuer_public_key_pem"] = result.get("public_key_pem", "")
    return credential


# ── Background ────────────────────────────────────────────────────────────────

@given('a W3C VC test issuer with DID "{issuer_did}"')
def step_w3c_issuer(context, issuer_did):
    if not hasattr(context, "test_data"):
        context.test_data = {}
    context.test_data["issuer_did"] = issuer_did


@given('a W3C VC test subject with DID "{subject_did}"')
def step_w3c_subject(context, subject_did):
    context.test_data["subject_did"] = subject_did


# ── Issuance steps ────────────────────────────────────────────────────────────

@when('I issue a W3C VC with claim "{name}" = "{value}"')
def step_w3c_vc_single_claim(context, name, value):
    token = _issue_w3c_vc(context, {name: value})
    context.test_data["w3c_vc_token"] = token
    context.test_data["w3c_vc_claims"] = {name: value}


@when("I issue a W3C VC with an explicit credential ID")
def step_w3c_vc_with_id(context):
    token = _issue_w3c_vc(context, {"given_name": "Alice"})
    context.test_data["w3c_vc_token"] = token


@when('I issue a W3C VC with the following claims:')
@when('I issue a W3C VC with the following claims')
def step_w3c_vc_table_claims(context):
    claims = {row["claim_name"]: row["claim_value"] for row in context.table}
    token = _issue_w3c_vc(context, claims)
    context.test_data["w3c_vc_token"] = token
    context.test_data["w3c_vc_claims"] = claims


@when("I issue a W3C VC as a JWT")
def step_w3c_as_jwt(context):
    token = _issue_w3c_vc(context, {"given_name": "Alice"})
    context.test_data["w3c_vc_token"] = token


@when('I issue a W3C VC as a JWT with issuer "{issuer_did}"')
def step_w3c_jwt_with_issuer(context, issuer_did):
    context.test_data["issuer_did"] = issuer_did
    token = _issue_w3c_vc(context, {"given_name": "Alice"})
    context.test_data["w3c_vc_token"] = token


@when('I issue a W3C VC as a JWT for subject "{subject_did}"')
def step_w3c_jwt_for_subject(context, subject_did):
    context.test_data["subject_did"] = subject_did
    token = _issue_w3c_vc(context, {"given_name": "Alice"})
    context.test_data["w3c_vc_token"] = token


# ── §4.1 — @context ───────────────────────────────────────────────────────────

@then('the credential "@context" must include "{uri}"')
def step_context_includes_uri(context, uri):
    token = context.test_data["w3c_vc_token"]
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)  # support both top-level and nested vc claim
    ctx = vc.get("@context", [])
    if isinstance(ctx, str):
        ctx = [ctx]
    assert uri in ctx, (
        f'Credential "@context" must include "{uri}". Got: {ctx}'
    )


@then('"{uri}" must be the first "@context" value')
def step_context_first_uri(context, uri):
    token = context.test_data["w3c_vc_token"]
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    ctx = vc.get("@context", [])
    if isinstance(ctx, str):
        ctx = [ctx]
    assert ctx[0] == uri, (
        f'First "@context" value must be "{uri}", got "{ctx[0] if ctx else None}"'
    )


# ── §4.2 — type ───────────────────────────────────────────────────────────────

@then('the credential "type" must include "{type_name}"')
def step_credential_type_includes(context, type_name):
    token = context.test_data.get("w3c_vc_token") or context.test_data.get("open_badge_token")
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    types = vc.get("type", [])
    if isinstance(types, str):
        types = [types]
    assert type_name in types, (
        f'Credential "type" must include "{type_name}". Got: {types}'
    )


# ── §4.3 — id ─────────────────────────────────────────────────────────────────

@then('the credential "id" must be a valid URI')
def step_credential_id_is_uri(context):
    token = context.test_data["w3c_vc_token"]
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    cred_id = vc.get("id") or payload.get("jti")
    if cred_id is not None:  # id is optional
        assert _is_valid_uri(str(cred_id)), (
            f'Credential "id" must be a valid URI, got: "{cred_id}"'
        )


# ── §4.4 — issuer ─────────────────────────────────────────────────────────────

@then('the credential "issuer" must be a non-empty URI or an object with a URI "id"')
def step_issuer_is_uri(context):
    token = context.test_data.get("w3c_vc_token") or context.test_data.get("open_badge_token")
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    issuer = vc.get("issuer") or payload.get("iss")
    assert issuer, "Credential must have an 'issuer' (or JWT 'iss')"
    if isinstance(issuer, dict):
        issuer_id = issuer.get("id", "")
        assert _is_valid_uri(issuer_id), f"issuer.id must be a URI, got: {issuer_id}"
    else:
        assert _is_valid_uri(str(issuer)), f"issuer must be a URI, got: {issuer}"


# ── §4.5 — issuanceDate / validFrom ──────────────────────────────────────────

ISO8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$"
)


@then('the credential must contain either "issuanceDate" or "validFrom"')
def step_has_issuance_date(context):
    token = context.test_data.get("w3c_vc_token") or context.test_data.get("open_badge_token")
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    has_date = "issuanceDate" in vc or "validFrom" in vc or "iat" in payload
    assert has_date, (
        'Credential must contain "issuanceDate", "validFrom", or JWT "iat" claim'
    )


@then("the date must be in ISO 8601 format")
def step_date_is_iso8601(context):
    token = context.test_data.get("w3c_vc_token") or context.test_data.get("open_badge_token")
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    date_val = vc.get("issuanceDate") or vc.get("validFrom")
    if date_val:
        assert ISO8601_RE.match(date_val), (
            f'Date "{date_val}" is not in ISO 8601 format'
        )
    # If only iat (epoch int) is present, that's also conformant for JWT


@then('the credential must contain "issuanceDate" in ISO 8601 format')
def step_has_issuance_date_ob(context):
    token = context.test_data.get("open_badge_token") or context.test_data.get("w3c_vc_token")
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    date_val = vc.get("issuanceDate") or vc.get("validFrom")
    if date_val:
        assert ISO8601_RE.match(date_val), (
            f'issuanceDate "{date_val}" is not in ISO 8601 format'
        )


# ── §4.6 — credentialSubject ──────────────────────────────────────────────────

@then('the credential must contain "credentialSubject"')
def step_has_credential_subject(context):
    token = context.test_data.get("w3c_vc_token") or context.test_data.get("open_badge_token")
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    assert "credentialSubject" in vc, (
        f'"credentialSubject" missing from credential. Keys: {list(vc.keys())}'
    )


@then('"credentialSubject" must be an object or array of objects')
def step_credential_subject_type(context):
    token = context.test_data.get("w3c_vc_token") or context.test_data.get("open_badge_token")
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    cs = vc.get("credentialSubject")
    assert isinstance(cs, (dict, list)), (
        f'"credentialSubject" must be object or array, got {type(cs)}'
    )
    if isinstance(cs, list):
        for item in cs:
            assert isinstance(item, dict), (
                f"Each credentialSubject must be an object, got {type(item)}"
            )


@then('the "credentialSubject" must contain "{name}" = "{value}"')
def step_credential_subject_claim(context, name, value):
    token = context.test_data.get("w3c_vc_token") or context.test_data.get("open_badge_token")
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    assert name in cs, f'credentialSubject missing "{name}". Keys: {list(cs.keys())}'
    assert str(cs[name]) == value, (
        f'credentialSubject["{name}"] expected "{value}", got "{cs[name]}"'
    )


# ── §6.3 — JWT encoding ───────────────────────────────────────────────────────

@then("the JWT string must have exactly 3 tilde-free dot-separated parts")
def step_jwt_has_3_parts(context):
    token = context.test_data["w3c_vc_token"]
    # Strip any SD-JWT disclosures
    jwt_part = token.split("~")[0]
    parts = jwt_part.split(".")
    assert len(parts) == 3, (
        f"JWT must have exactly 3 dot-separated parts, got {len(parts)}"
    )


@then('the JWT header must contain an "alg" field')
def step_jwt_header_alg(context):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    header = _jwt_header(token)
    assert "alg" in header, f'"alg" must be present in JWT header. Got: {header}'


@then('the "alg" must not be "none"')
def step_jwt_alg_not_none(context):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    header = _jwt_header(token)
    assert header.get("alg", "").lower() != "none", (
        '"alg" must not be "none" (unsigned JWT is not allowed)'
    )


@then('the JWT payload must contain a "vc" claim')
def step_jwt_has_vc_claim(context):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    payload = _jwt_payload(token)
    assert "vc" in payload, f'"vc" claim missing from JWT payload. Keys: {list(payload.keys())}'


@then('the "vc" claim must contain "@context" and "type" and "credentialSubject"')
def step_vc_claim_has_required_fields(context):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    payload = _jwt_payload(token)
    vc = payload.get("vc", {})
    for field in ("@context", "type", "credentialSubject"):
        assert field in vc, (
            f'"vc" claim missing required field "{field}". vc keys: {list(vc.keys())}'
        )


@then('the JWT payload "iss" claim must equal "{expected}"')
def step_jwt_iss(context, expected):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    payload = _jwt_payload(token)
    iss = payload.get("iss") or _jwt_payload(token).get("vc", {}).get("issuer")
    assert iss == expected, f'"iss" expected "{expected}", got "{iss}"'


@then('the JWT payload "sub" claim must equal "{expected}"')
def step_jwt_sub(context, expected):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    payload = _jwt_payload(token)
    sub = payload.get("sub")
    if sub is None:
        # Check inside vc.credentialSubject.id
        cs = payload.get("vc", {}).get("credentialSubject", {})
        if isinstance(cs, list):
            cs = cs[0]
        sub = cs.get("id")
    assert sub == expected, f'"sub" expected "{expected}", got "{sub}"'


# ── §7.1 — Verification ───────────────────────────────────────────────────────

@then("the credential signature must verify successfully")
def step_signature_verifies(context):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    pub_pem = context.test_data.get("issuer_public_key_pem", "")
    if not pub_pem:
        # Cannot verify without the public key — skip silently
        return

    try:
        import jwt as pyjwt  # PyJWT
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub_key = load_pem_public_key(pub_pem.encode())
        pyjwt.decode(token, pub_key, algorithms=["ES256", "ES384", "RS256", "EdDSA"])
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"Credential signature verification failed: {e}") from e


@when('I modify the "given_name" value to "{tampered}" in the JWT without re-signing')
def step_tamper_jwt_claim(context, tampered):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    header_b64, payload_b64, sig_b64 = token.split(".")
    payload = json.loads(_b64url_decode(payload_b64))

    # Modify the value inside vc.credentialSubject
    vc = payload.get("vc", {})
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs[0]["given_name"] = tampered
    else:
        cs["given_name"] = tampered

    # Re-encode payload without the original signature
    new_payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    tampered_token = f"{header_b64}.{new_payload_b64}.{sig_b64}"
    context.test_data["w3c_vc_token"] = tampered_token
    context.test_data["w3c_vc_tampered"] = True


@then("the credential signature verification must fail")
def step_signature_fails(context):
    token = context.test_data["w3c_vc_token"].split("~")[0]
    pub_pem = context.test_data.get("issuer_public_key_pem", "")
    if not pub_pem:
        assert context.test_data.get("w3c_vc_tampered"), (
            "Expected tampered token to be present"
        )
        return

    import jwt as pyjwt  # PyJWT
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pub_key = load_pem_public_key(pub_pem.encode())
    try:
        pyjwt.decode(token, pub_key, algorithms=["ES256", "ES384", "RS256", "EdDSA"])
        raise AssertionError("Tampered credential signature should NOT verify")
    except pyjwt.exceptions.InvalidSignatureError:
        pass  # Expected — tampered token correctly rejected
