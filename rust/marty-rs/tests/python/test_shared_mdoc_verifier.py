"""Public Python boundary over the shared Rust mdoc verifier."""
import base64
import json
from pathlib import Path

import _marty_rs
import pytest


@pytest.fixture
def signed_presentation():
    # Unmodified public-only vector from marty-core 4404027.
    fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "mdoc_presentation_signed_public.json").read_text())
    return (
        base64.b64decode(fixture["response_b64"]),
        base64.b64decode(fixture["transcript_b64"]),
        fixture["certificate_pem"],
    )


def test_presentation_preserves_trust_evidence_and_rejects_changed_holder_binding(signed_presentation):
    response, transcript, certificate = signed_presentation
    result = _marty_rs.verify_mdoc_presentation(response, transcript, [], [certificate])
    assert result.issuer_signature_valid
    assert result.issuer_trusted
    assert result.device_authentication_valid
    assert result.error is None
    assert len(result.document_evidence) == 1
    evidence = result.document_evidence[0]
    assert evidence.validity_checked
    assert evidence.valid_at_verification_time
    assert len(evidence.issuer_certificate_sha256) == 64
    assert result.revocation_checked is False
    assert result.not_revoked is None
    changed = _marty_rs.verify_mdoc_presentation(response, b"\x80", [], [certificate])
    assert changed.device_authentication_valid is False
    untrusted = _marty_rs.verify_mdoc_presentation(response, transcript, [], [])
    assert untrusted.issuer_trusted is False


@pytest.mark.parametrize("response", [b"", b"\xff", b"\xa0"])
def test_signature_compatibility_api_returns_failure_evidence(response):
    result = _marty_rs.verify_mdoc_signature(response, [])
    assert result.signature_valid is False
    assert result.issuer_verified is False
    assert result.document_evidence == []
    assert result.error
