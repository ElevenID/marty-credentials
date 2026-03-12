"""
Step definitions for SD-JWT IETF draft conformance tests.

These steps verify structural and cryptographic compliance with
draft-ietf-oauth-selective-disclosure-jwt without requiring external services.
All steps work in the same in-memory SQLite context as existing BDD tests.
"""

import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from behave import given, when, then


# ── helpers ──────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string (with or without padding)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _jwt_payload(jwt_str: str) -> dict:
    """Decode (without verification) a JWT and return the payload dict."""
    parts = jwt_str.split(".")
    assert len(parts) == 3, f"Not a valid JWT (expected 3 parts): {jwt_str[:60]}"
    return json.loads(_b64url_decode(parts[1]))


def _jwt_header(jwt_str: str) -> dict:
    parts = jwt_str.split(".")
    assert len(parts) == 3
    return json.loads(_b64url_decode(parts[0]))


def _split_sd_jwt(sd_jwt: str):
    """Return (jwt_part, [disclosure_str, ...], kb_jwt_or_empty_str)."""
    parts = sd_jwt.split("~")
    jwt_part = parts[0]
    kb_jwt = parts[-1]  # empty string for no KB-JWT, or a JWT
    disclosures = parts[1:-1]
    return jwt_part, disclosures, kb_jwt


def _decode_disclosure(disc_str: str) -> list:
    """Decode a single disclosure from base64url to a Python list."""
    raw = _b64url_decode(disc_str)
    return json.loads(raw)


def _disclosure_hash(disc_str: str) -> str:
    """Compute SHA-256 hash of a disclosure string, return base64url without padding."""
    digest = hashlib.sha256(disc_str.encode("ascii")).digest()
    return _b64url_encode(digest)


def _gen_ec_pem_pair():
    """Generate an EC P-256 key pair and return (private_pem, public_pem)."""
    private_key = generate_private_key(SECP256R1(), default_backend())
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem


def _issue_sd_jwt_via_service(context, claims: dict, disclosable: list) -> str:
    """Issue an SD-JWT using the existing issuance service and return the compact form."""
    result = context.issuance_service.issue_sd_jwt(
        issuer_did=context.test_data["issuer_did"],
        subject_did=context.test_data["subject_did"],
        claims=claims,
        selective_fields=disclosable,
    )
    return result["credential"]


# ── Background ────────────────────────────────────────────────────────────────

@given("an SD-JWT test issuer key pair")
def step_sd_jwt_issuer_key(context):
    if not hasattr(context, "test_data"):
        context.test_data = {}

    priv_pem, pub_pem = _gen_ec_pem_pair()
    context.test_data.setdefault("issuer_did", "did:example:sd-jwt-conformance-issuer")
    context.test_data["issuer_private_key_pem"] = priv_pem
    context.test_data["issuer_public_key_pem"] = pub_pem


@given('a test subject DID "{subject_did}"')
def step_sd_jwt_subject(context, subject_did):
    context.test_data.setdefault("subject_did", subject_did)


# ── §4.2 — Disclosure format steps ───────────────────────────────────────────

@when('I issue an SD-JWT with disclosable claim "{name}" = "{value}"')
def step_issue_sd_jwt_single_str(context, name, value):
    sd_jwt = _issue_sd_jwt_via_service(
        context, claims={name: value}, disclosable=[name]
    )
    context.test_data["sd_jwt"] = sd_jwt
    context.test_data["sd_jwt_claims"] = {name: value}
    context.test_data["sd_jwt_disclosable"] = [name]


@when('I issue an SD-JWT with disclosable claim "{name}" = {value:d}')
def step_issue_sd_jwt_single_int(context, name, value):
    sd_jwt = _issue_sd_jwt_via_service(
        context, claims={name: value}, disclosable=[name]
    )
    context.test_data["sd_jwt"] = sd_jwt
    context.test_data["sd_jwt_claims"] = {name: value}
    context.test_data["sd_jwt_disclosable"] = [name]


@then("each disclosure in the SD-JWT must decode to a valid JSON array")
def step_disclosures_are_json_arrays(context):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    assert disclosures, "SD-JWT must contain at least one disclosure"
    for d in disclosures:
        decoded = _decode_disclosure(d)
        assert isinstance(decoded, list), f"Disclosure decoded to non-array: {decoded}"


@then("each disclosure array must have exactly 3 elements: [salt, claim_name, claim_value]")
def step_disclosures_have_3_elements(context):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    for d in disclosures:
        decoded = _decode_disclosure(d)
        assert len(decoded) == 3, (
            f"Disclosure must have 3 elements [salt, name, value], got {len(decoded)}: {decoded}"
        )


@then("each disclosure salt must be at least 16 bytes when base64url-decoded")
def step_disclosure_salt_entropy(context):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    for d in disclosures:
        salt_b64, _, _ = _decode_disclosure(d)
        salt_bytes = _b64url_decode(salt_b64)
        assert len(salt_bytes) >= 16, (
            f"Disclosure salt must be ≥16 bytes (≥128 bits), got {len(salt_bytes)}: {salt_b64}"
        )


@then('the disclosure for claim "{name}" must contain the exact claim name "{expected}"')
def step_disclosure_claim_name(context, name, expected):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    found = False
    for d in disclosures:
        _, claim_name, _ = _decode_disclosure(d)
        if claim_name == name:
            assert claim_name == expected, (
                f"Disclosure claim name '{claim_name}' != expected '{expected}'"
            )
            found = True
    assert found, f"No disclosure found for claim '{name}'"


@then('the disclosure for claim "{name}" must contain value "{expected}"')
def step_disclosure_claim_value(context, name, expected):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    for d in disclosures:
        _, claim_name, claim_value = _decode_disclosure(d)
        if claim_name == name:
            assert str(claim_value) == expected, (
                f"Disclosure value for '{name}' is '{claim_value}', expected '{expected}'"
            )
            return
    raise AssertionError(f"No disclosure found for claim '{name}'")


# ── §4.1 — JWT payload structure steps ───────────────────────────────────────

@then('the JWT payload must contain an "_sd" array')
def step_payload_has_sd_array(context):
    jwt_part, _, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    payload = _jwt_payload(jwt_part)
    assert "_sd" in payload, f"JWT payload missing '_sd' array. Keys: {list(payload.keys())}"
    assert isinstance(payload["_sd"], list), "'_sd' must be a JSON array"


@then('the "_sd" array must not be empty')
def step_sd_array_not_empty(context):
    jwt_part, _, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    payload = _jwt_payload(jwt_part)
    assert payload["_sd"], "'_sd' array must not be empty"


@then('the JWT payload must contain "_sd_alg" equal to "sha-256"')
def step_sd_alg_is_sha256(context):
    jwt_part, _, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    payload = _jwt_payload(jwt_part)
    alg = payload.get("_sd_alg", "sha-256")  # sha-256 is the default per spec
    assert alg == "sha-256", f"'_sd_alg' must be 'sha-256', got '{alg}'"


@then('for each disclosure, its SHA-256 hash must appear in the "_sd" array')
def step_disclosure_hashes_in_sd(context):
    jwt_part, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    payload = _jwt_payload(jwt_part)
    sd_hashes = set(payload.get("_sd", []))

    for d in disclosures:
        expected_hash = _disclosure_hash(d)
        assert expected_hash in sd_hashes, (
            f"SHA-256 hash of disclosure '{d[:20]}...' "
            f"({expected_hash}) not in _sd array: {sd_hashes}"
        )


@then("the hash must be base64url-encoded without padding")
def step_sd_hashes_no_padding(context):
    jwt_part, _, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    payload = _jwt_payload(jwt_part)
    for h in payload.get("_sd", []):
        assert "=" not in h, f"_sd hash must not contain padding '=': {h}"


@when('I issue an SD-JWT where "iss" is non-disclosable and "{name}" is disclosable')
def step_issue_mixed_sd_jwt(context, name):
    sd_jwt = _issue_sd_jwt_via_service(
        context,
        claims={"iss": "did:example:issuer", name: "Alice"},
        disclosable=[name],
    )
    context.test_data["sd_jwt"] = sd_jwt
    context.test_data["sd_jwt_mixed_disclosable"] = name


@then('the JWT payload must contain "iss" in plaintext')
def step_iss_in_plaintext(context):
    jwt_part, _, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    payload = _jwt_payload(jwt_part)
    assert "iss" in payload, "'iss' must be a plaintext claim in JWT payload"


@then('"{name}" must NOT appear as a top-level plaintext claim in the JWT payload')
def step_disclosable_not_plaintext(context, name):
    jwt_part, _, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    payload = _jwt_payload(jwt_part)
    assert name not in payload, (
        f"Disclosable claim '{name}' must NOT appear in plaintext JWT payload"
    )


# ── §7 — Compact serialization steps ─────────────────────────────────────────

@then('the SD-JWT string must contain "~" separators')
def step_sd_jwt_has_tilde(context):
    sd_jwt = context.test_data["sd_jwt"]
    assert "~" in sd_jwt, "SD-JWT compact form must contain '~' separators"


@then('the first token before "~" must be a valid three-part JWT (header.payload.signature)')
def step_first_part_is_jwt(context):
    jwt_part, _, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    parts = jwt_part.split(".")
    assert len(parts) == 3, (
        f"First SD-JWT token must be a 3-part JWT (header.payload.signature), got {len(parts)} parts"
    )
    # Each part must be valid base64url
    for part in parts:
        _b64url_decode(part)  # raises on invalid encoding


@when("I issue an SD-JWT with 3 disclosable claims")
def step_issue_sd_jwt_3_claims(context):
    sd_jwt = _issue_sd_jwt_via_service(
        context,
        claims={"name": "Alice", "age": 30, "email": "alice@example.com"},
        disclosable=["name", "age", "email"],
    )
    context.test_data["sd_jwt"] = sd_jwt


@then("the SD-JWT compact form must contain at least 3 disclosure parts after the JWT")
def step_at_least_3_disclosures(context):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt"])
    assert len(disclosures) >= 3, (
        f"Expected ≥3 disclosures for 3 disclosable claims, got {len(disclosures)}"
    )


# ── §8 — Holder presentation steps ───────────────────────────────────────────

@given('an SD-JWT with disclosable claims "{c1}", "{c2}", "{c3}"')
def step_sd_jwt_3_claims_given(context, c1, c2, c3):
    sd_jwt = _issue_sd_jwt_via_service(
        context,
        claims={c1: "Alice", c2: "Smith", c3: 30},
        disclosable=[c1, c2, c3],
    )
    context.test_data["sd_jwt"] = sd_jwt
    context.test_data["sd_jwt_full_disclosures"] = [c1, c2, c3]


@when('the holder creates a presentation disclosing only "{claim}"')
def step_holder_present_one_claim(context, claim):
    sd_jwt = context.test_data["sd_jwt"]
    jwt_part, disclosures, _ = _split_sd_jwt(sd_jwt)

    # Keep only the disclosure for the chosen claim
    selected = []
    for d in disclosures:
        _, claim_name, _ = _decode_disclosure(d)
        if claim_name == claim:
            selected.append(d)

    # Reconstruct a presentation (JWT + selected disclosures + empty KB-JWT)
    presentation = jwt_part + "~" + "~".join(selected) + "~"
    context.test_data["sd_jwt_presentation"] = presentation
    context.test_data["sd_jwt_presented_claims"] = [claim]


@then("the presentation must contain only {n:d} disclosure")
def step_presentation_disclosure_count(context, n):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt_presentation"])
    assert len(disclosures) == n, (
        f"Expected {n} disclosure(s) in presentation, found {len(disclosures)}"
    )


@then('the disclosed claim must be "{claim}"')
def step_disclosed_claim_name(context, claim):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt_presentation"])
    assert len(disclosures) == 1
    _, claim_name, _ = _decode_disclosure(disclosures[0])
    assert claim_name == claim, f"Expected disclosed claim '{claim}', got '{claim_name}'"


@then('the presentation must NOT contain a disclosure for "{claim}"')
def step_presentation_lacks_claim(context, claim):
    _, disclosures, _ = _split_sd_jwt(context.test_data["sd_jwt_presentation"])
    for d in disclosures:
        _, claim_name, _ = _decode_disclosure(d)
        assert claim_name != claim, (
            f"Presentation must NOT contain disclosure for '{claim}'"
        )


# ── §10 — Verification steps ──────────────────────────────────────────────────

@given('an SD-JWT issued with claim "{name}" = "{value}"')
def step_issue_for_verify(context, name, value):
    sd_jwt = _issue_sd_jwt_via_service(
        context, claims={name: value}, disclosable=[name]
    )
    context.test_data["sd_jwt"] = sd_jwt
    context.test_data["sd_jwt_verify_claim"] = name
    context.test_data["sd_jwt_verify_value"] = value


@when('the holder presents the SD-JWT disclosing "{claim}"')
def step_holder_presents(context, claim):
    # Reuse step from holder section
    step_holder_present_one_claim(context, claim)


@then("verification must succeed")
def step_verification_succeeds(context):
    presentation = context.test_data.get("sd_jwt_presentation", context.test_data.get("sd_jwt"))
    jwt_part, disclosures, _ = _split_sd_jwt(presentation)
    payload = _jwt_payload(jwt_part)
    sd_hashes = set(payload.get("_sd", []))

    for d in disclosures:
        h = _disclosure_hash(d)
        assert h in sd_hashes, (
            f"Disclosure hash {h} not found in '_sd' array — integrity check failed"
        )


@then('the verified claims must include "{name}" = "{expected}"')
def step_verified_claim_value(context, name, expected):
    presentation = context.test_data.get("sd_jwt_presentation", context.test_data.get("sd_jwt"))
    _, disclosures, _ = _split_sd_jwt(presentation)
    for d in disclosures:
        _, claim_name, claim_value = _decode_disclosure(d)
        if claim_name == name:
            assert str(claim_value) == expected, (
                f"Claim '{name}' expected '{expected}', got '{claim_value}'"
            )
            return
    raise AssertionError(f"Claim '{name}' not found in presentation disclosures")


@when('the holder alters a disclosure to change "{name}" to "{tampered_value}"')
def step_tamper_disclosure(context, name, tampered_value):
    sd_jwt = context.test_data["sd_jwt"]
    jwt_part, disclosures, _ = _split_sd_jwt(sd_jwt)

    tampered_disclosures = []
    for d in disclosures:
        decoded = _decode_disclosure(d)
        if len(decoded) == 3 and decoded[1] == name:
            # Alter the value but keep the original salt/claim_name
            # This breaks the hash linkage
            tampered = [decoded[0], decoded[1], tampered_value]
            new_d = _b64url_encode(json.dumps(tampered).encode("utf-8"))
            tampered_disclosures.append(new_d)
        else:
            tampered_disclosures.append(d)

    tampered_presentation = jwt_part + "~" + "~".join(tampered_disclosures) + "~"
    context.test_data["sd_jwt_presentation"] = tampered_presentation
    context.test_data["sd_jwt_tampered"] = True


@then("verification must fail with a hash mismatch error")
def step_verification_fails(context):
    presentation = context.test_data.get("sd_jwt_presentation")
    jwt_part, disclosures, _ = _split_sd_jwt(presentation)
    payload = _jwt_payload(jwt_part)
    sd_hashes = set(payload.get("_sd", []))

    any_mismatch = False
    for d in disclosures:
        h = _disclosure_hash(d)
        if h not in sd_hashes:
            any_mismatch = True
            break

    assert any_mismatch, (
        "Expected a hash mismatch after tampering, but all disclosure hashes still match"
    )
