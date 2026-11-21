"""Public Python boundary over the shared Rust mdoc verifier."""
import base64
import json
import os
from pathlib import Path

import _marty_rs
import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization


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
    assert evidence.status_references == []
    assert evidence.revocation_checked is False
    assert evidence.not_revoked is None
    with pytest.raises(AttributeError):
        evidence.status_references = []
    assert result.revocation_checked is False
    assert result.not_revoked is None
    changed = _marty_rs.verify_mdoc_presentation(response, b"\x80", [], [certificate])
    assert changed.device_authentication_valid is False
    untrusted = _marty_rs.verify_mdoc_presentation(response, transcript, [], [])
    assert untrusted.issuer_trusted is False


def test_status_reference_projection_is_registered_without_an_evidence_constructor():
    # Only Core verification constructs these read-only data objects. Their
    # presence is not permission to fetch a URI or establish status authority.
    with pytest.raises(TypeError):
        _marty_rs.MdocStatusReference()


def test_unsigned_status_reference_cannot_become_authenticated_evidence(signed_presentation):
    response, transcript, certificate = signed_presentation
    parsed = cbor2.loads(response)
    issuer_auth = parsed["documents"][0]["issuerSigned"]["issuerAuth"]
    tagged_mso = cbor2.loads(issuer_auth[2])
    assert isinstance(tagged_mso, cbor2.CBORTag) and tagged_mso.tag == 24
    mso = cbor2.loads(tagged_mso.value)
    mso["status"] = {"status_list": {"idx": 0, "uri": "https://attacker.invalid/list"}}
    issuer_auth[2] = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))
    tampered = cbor2.dumps(parsed)
    result = _marty_rs.verify_mdoc_presentation(tampered, transcript, [], [certificate])
    assert result.issuer_signature_valid is False
    assert result.device_authentication_valid is False
    assert result.document_evidence == []
    assert result.revocation_checked is False
    assert result.not_revoked is None
    assert result.error


@pytest.fixture(scope="module")
def signed_status_presentations():
    directory = os.environ.get("MARTY_TEST_MDOC_STATUS_PUBLIC_FIXTURE_DIR")
    if not directory:
        pytest.skip("Generate fresh public status fixtures with Core's owned OpenBao regression")
    # The accepted Core generator writes this public-only file once in a fresh,
    # owned directory. Missing/expired/invalid supplied fixtures must fail rather
    # than silently falling back to synthetic evidence.
    path = Path(directory)
    assert path.is_absolute() and path.is_dir() and not path.is_symlink()
    return json.loads((path / "native-mdoc-public.json").read_text())


@pytest.mark.parametrize("variant", ["bit", "identifier"])
@pytest.mark.parametrize("api", ["issuer", "presentation", "signature"])
def test_signed_status_references_remain_data_without_revocation_authority(
    signed_status_presentations, variant, api
):
    fixture = signed_status_presentations
    response = base64.b64decode(fixture[f"{variant}_presentation_base64"], validate=True)
    transcript = base64.b64decode(fixture["transcript_base64"], validate=True)
    roots = [fixture["root_a_pem"]]
    if api == "issuer":
        result = _marty_rs.verify_mdoc_issuer(response, roots)
        assert result.signature_valid and result.issuer_trusted
    elif api == "presentation":
        result = _marty_rs.verify_mdoc_presentation(response, transcript, roots, [])
        assert result.issuer_signature_valid and result.issuer_trusted
        assert result.device_authentication_valid
    else:
        result = _marty_rs.verify_mdoc_signature(response, roots)
        assert result.signature_valid and result.issuer_verified
    assert result.error is None
    assert len(result.document_evidence) == 1
    evidence = result.document_evidence[0]
    assert evidence.validity_checked and evidence.valid_at_verification_time
    assert evidence.revocation_checked is False
    assert evidence.not_revoked is None
    if api != "signature":
        assert result.revocation_checked is False
        assert result.not_revoked is None
    references = evidence.status_references
    assert len(references) == 1
    reference = references[0]
    assert isinstance(reference, _marty_rs.MdocStatusReference)
    assert reference.uri == fixture["origin"] + "/list"
    if variant == "bit":
        assert reference.kind == "STATUS_LIST"
        assert reference.index == 3
        assert reference.identifier is None
        assert reference.certificate_der is None
    else:
        assert reference.kind == "IDENTIFIER_LIST"
        assert reference.index is None
        assert bytes(reference.identifier) == bytes([7, 8])
        certificate = x509.load_pem_x509_certificate(fixture["root_b_pem"].encode())
        assert bytes(reference.certificate_der) == certificate.public_bytes(serialization.Encoding.DER)
    for field in ("kind", "uri", "index", "identifier", "certificate_der"):
        with pytest.raises(AttributeError):
            setattr(reference, field, getattr(reference, field))
    references.clear()
    assert len(evidence.status_references) == 1


@pytest.mark.parametrize("variant", ["bit", "identifier"])
def test_signed_status_reference_does_not_replace_holder_or_issuer_trust(
    signed_status_presentations, variant
):
    fixture = signed_status_presentations
    response = base64.b64decode(fixture[f"{variant}_presentation_base64"], validate=True)
    transcript = base64.b64decode(fixture["transcript_base64"], validate=True)
    wrong_session = _marty_rs.verify_mdoc_presentation(response, b"\x80", [fixture["root_a_pem"]], [])
    assert wrong_session.issuer_signature_valid and wrong_session.issuer_trusted
    assert wrong_session.device_authentication_valid is False
    assert wrong_session.revocation_checked is False
    assert wrong_session.not_revoked is None
    untrusted = _marty_rs.verify_mdoc_presentation(response, transcript, [], [])
    assert untrusted.issuer_trusted is False
    assert untrusted.revocation_checked is False
    assert untrusted.not_revoked is None


@pytest.mark.parametrize("response", [b"", b"\xff", b"\xa0"])
def test_signature_compatibility_api_returns_failure_evidence(response):
    result = _marty_rs.verify_mdoc_signature(response, [])
    assert result.signature_valid is False
    assert result.issuer_verified is False
    assert result.document_evidence == []
    assert result.error
