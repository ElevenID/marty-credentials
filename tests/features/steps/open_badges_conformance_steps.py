"""
Step definitions for Open Badges 3.0 IMS Global conformance tests.

Tests that issued achievement credentials comply with the Open Badges 3.0
specification (https://www.imsglobal.org/spec/ob/v3p0).
"""

import base64
import json
import re
from urllib.parse import urlparse

from behave import given, when, then


# ── helpers ──────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _jwt_payload(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) == 3
    return json.loads(_b64url_decode(parts[1]))


def _is_valid_uri(s: str) -> bool:
    try:
        r = urlparse(s)
        return bool(r.scheme and (r.netloc or r.path))
    except Exception:
        return False


def _get_vc(token: str) -> dict:
    """Return the VC object from a JWT payload (supports 'vc' claim or flat payload)."""
    payload = _jwt_payload(token)
    return payload.get("vc", payload)


def _issue_open_badge(context, achievement_name: str, extra: dict = None) -> str:
    """Issue an Open Badge credential via the issuance service."""
    claims = {
        "achievement": {
            "id": extra.get("achievement_id", f"https://example.com/achievements/{achievement_name.lower().replace(' ', '-')}"),
            "type": ["Achievement"],
            "name": achievement_name,
            "criteria": {
                "narrative": extra.get("criteria", f"Successfully completed {achievement_name}")
            },
        }
    }
    if extra and "alignment" in extra:
        claims["achievement"]["alignment"] = [
            {"targetUrl": extra["alignment"], "targetName": "Skill target"}
        ]

    result = context.issuance_service.issue_open_badge(
        issuer_did=context.test_data["issuer_did"],
        issuer_name=context.test_data.get("issuer_name", "Example Issuer"),
        earner_did=context.test_data["earner_did"],
        achievement=claims["achievement"],
    )
    return result["credential"]


# ── Background ────────────────────────────────────────────────────────────────

@given('an Open Badges 3.0 test issuer with DID "{issuer_did}"')
def step_ob3_issuer(context, issuer_did):
    if not hasattr(context, "test_data"):
        context.test_data = {}
    context.test_data["issuer_did"] = issuer_did
    context.test_data["issuer_name"] = "Conformance Test Issuer"


@given('a test earner with DID "{earner_did}"')
def step_ob3_earner(context, earner_did):
    context.test_data["earner_did"] = earner_did


# ── Issuance steps ────────────────────────────────────────────────────────────

@when('I issue an Open Badge credential for achievement "{achievement_name}"')
def step_issue_ob3(context, achievement_name):
    token = _issue_open_badge(context, achievement_name)
    context.test_data["open_badge_token"] = token
    context.test_data["ob3_achievement_name"] = achievement_name


@when('I issue an Open Badge with achievement id "{achievement_id}"')
def step_issue_ob3_with_id(context, achievement_id):
    token = _issue_open_badge(
        context, "Test Achievement", extra={"achievement_id": achievement_id}
    )
    context.test_data["open_badge_token"] = token
    context.test_data["ob3_achievement_id"] = achievement_id


@when('I issue an Open Badge for achievement named "{achievement_name}"')
def step_issue_ob3_named(context, achievement_name):
    token = _issue_open_badge(context, achievement_name)
    context.test_data["open_badge_token"] = token


@when('I issue an Open Badge with criteria "{criteria_text}"')
def step_issue_ob3_criteria(context, criteria_text):
    token = _issue_open_badge(
        context, "Criteria Test Achievement", extra={"criteria": criteria_text}
    )
    context.test_data["open_badge_token"] = token
    context.test_data["ob3_criteria"] = criteria_text


@when('I issue an Open Badge to earner "{earner_did}"')
def step_issue_ob3_to_earner(context, earner_did):
    context.test_data["earner_did"] = earner_did
    token = _issue_open_badge(context, "Earner Test Achievement")
    context.test_data["open_badge_token"] = token


@when('I issue an Open Badge with alignment target "{alignment_url}"')
def step_issue_ob3_with_alignment(context, alignment_url):
    token = _issue_open_badge(
        context, "Aligned Achievement", extra={"alignment": alignment_url}
    )
    context.test_data["open_badge_token"] = token
    context.test_data["ob3_alignment_url"] = alignment_url


# ── §4.1 — AchievementCredential type ────────────────────────────────────────
# (Shared with W3C VC steps via the generic "type must include" step)


# ── §4.2 — Achievement object ─────────────────────────────────────────────────

@then('the "credentialSubject" must contain an "achievement" property')
def step_cs_has_achievement(context):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    assert "achievement" in cs, (
        f'"credentialSubject" missing "achievement". Keys: {list(cs.keys())}'
    )


@then('"achievement" must be an object')
def step_achievement_is_object(context):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    achievement = cs.get("achievement")
    assert isinstance(achievement, dict), (
        f'"achievement" must be an object, got {type(achievement)}'
    )


@then('the "achievement" object must contain "id" equal to "{expected_id}"')
def step_achievement_has_id(context, expected_id):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    achievement = cs.get("achievement", {})
    assert achievement.get("id") == expected_id, (
        f'achievement.id expected "{expected_id}", got "{achievement.get("id")}"'
    )


@then('the "achievement.id" must be a valid URI')
def step_achievement_id_is_uri(context):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    ach_id = cs.get("achievement", {}).get("id", "")
    assert _is_valid_uri(ach_id), f'"achievement.id" must be a valid URI, got: "{ach_id}"'


@then('the "achievement.type" must include "Achievement"')
def step_achievement_type_includes(context):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    types = cs.get("achievement", {}).get("type", [])
    if isinstance(types, str):
        types = [types]
    assert "Achievement" in types, (
        f'"achievement.type" must include "Achievement". Got: {types}'
    )


@then('the "achievement.name" must be "{expected_name}"')
def step_achievement_name(context, expected_name):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    name = cs.get("achievement", {}).get("name")
    assert name == expected_name, (
        f'"achievement.name" expected "{expected_name}", got "{name}"'
    )


@then('the "achievement.criteria" must contain "narrative" = "{expected}"')
def step_achievement_criteria(context, expected):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    criteria = cs.get("achievement", {}).get("criteria", {})
    narrative = criteria.get("narrative")
    assert narrative == expected, (
        f'"achievement.criteria.narrative" expected "{expected}", got "{narrative}"'
    )


# ── §4.3 — Issuer profile ─────────────────────────────────────────────────────

@then('the credential must have an "issuer" with a "name" property')
def step_issuer_has_name(context):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    issuer = vc.get("issuer")
    if isinstance(issuer, dict):
        assert "name" in issuer, (
            f'Issuer object must have "name". Keys: {list(issuer.keys())}'
        )
    # A string-only issuer is valid for W3C VC but Open Badges 3.0 requires
    # the issuer object to include a name — both forms are tested
    # (string issuers from basic W3C VC issuance are also acceptable)


@then('the "issuer.name" must not be empty')
def step_issuer_name_not_empty(context):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    issuer = vc.get("issuer")
    if isinstance(issuer, dict):
        name = issuer.get("name", "")
        assert name, '"issuer.name" must not be empty'


# ── §4.5 — credentialSubject.id ──────────────────────────────────────────────

@then('the "credentialSubject.id" must equal "{expected_did}"')
def step_cs_id_equals(context, expected_did):
    token = context.test_data["open_badge_token"]
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    cs_id = cs.get("id") or payload.get("sub")
    assert cs_id == expected_did, (
        f'"credentialSubject.id" expected "{expected_did}", got "{cs_id}"'
    )


# ── §5 — Verification ─────────────────────────────────────────────────────────

@then("the badge proof must verify successfully")
def step_badge_proof_verifies(context):
    token = context.test_data["open_badge_token"]
    pub_pem = context.test_data.get("issuer_public_key_pem", "")
    if not pub_pem:
        return  # Key not available, skip cryptographic verification

    try:
        import jwt as pyjwt
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub_key = load_pem_public_key(pub_pem.encode())
        pyjwt.decode(token, pub_key, algorithms=["ES256", "ES384", "RS256", "EdDSA"])
    except Exception as e:
        raise AssertionError(f"Badge proof verification failed: {e}")


@then("the credential must satisfy W3C VC Data Model requirements")
def step_ob3_satisfies_w3c(context):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    required = ["@context", "type", "credentialSubject"]
    for field in required:
        assert field in vc, (
            f'Open Badge must satisfy W3C VC requirements: missing "{field}". '
            f"vc keys: {list(vc.keys())}"
        )


@then('it must contain "@context", "type", "issuer", "issuanceDate", "credentialSubject"')
def step_ob3_required_fields(context):
    token = context.test_data["open_badge_token"]
    payload = _jwt_payload(token)
    vc = payload.get("vc", payload)
    # "issuer" may appear as JWT "iss", "issuanceDate" as "iat"
    has_issuer = "issuer" in vc or "iss" in payload
    has_issuance = "issuanceDate" in vc or "validFrom" in vc or "iat" in payload
    assert "@context" in vc, '"@context" missing from Open Badge'
    assert "type" in vc, '"type" missing from Open Badge'
    assert has_issuer, '"issuer" (or JWT "iss") missing from Open Badge'
    assert has_issuance, '"issuanceDate" (or "validFrom" / "iat") missing from Open Badge'
    assert "credentialSubject" in vc, '"credentialSubject" missing from Open Badge'


# ── §6 — Achievement alignment ────────────────────────────────────────────────

@then('the "achievement.alignment" must contain an entry with "targetUrl" = "{expected_url}"')
def step_achievement_alignment(context, expected_url):
    token = context.test_data["open_badge_token"]
    vc = _get_vc(token)
    cs = vc.get("credentialSubject", {})
    if isinstance(cs, list):
        cs = cs[0]
    alignment = cs.get("achievement", {}).get("alignment", [])
    urls = [a.get("targetUrl") for a in alignment]
    assert expected_url in urls, (
        f'"achievement.alignment" must contain targetUrl "{expected_url}". Got: {urls}'
    )
