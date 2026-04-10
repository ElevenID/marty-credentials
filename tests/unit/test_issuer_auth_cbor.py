"""Unit tests for the mDoc issuerAuth CBOR fix (Bug #3).

The Rust signing engine wraps the COSE_Sign1 ``issuerAuth`` as a CBOR byte
string (``bstr``), but ISO 18013-5 §9.1.2.4 requires the COSE_Sign1 *array*
to be embedded directly in the IssuerSigned map — no extra ``bstr`` wrapper.

``_fix_mdoc_issuer_auth()`` detects the byte-string encoding and unwraps
it, preserving the inner COSE_Sign1 array (optionally stripping CBOR Tag 18).

These tests use hand-crafted CBOR payloads so no Rust FFI is needed.
"""

import cbor2
import pytest

from tests.unit._helpers import _fix_mdoc_issuer_auth, b64url, b64url_decode


class TestIssuerAuthCborFix:
    """Bug #3: issuerAuth must be an embedded COSE_Sign1 array, not bstr."""

    # -- helper: build a minimal IssuerSigned map -------------------------

    @staticmethod
    def _make_cose_sign1_array() -> list:
        """Return a minimal COSE_Sign1 structure ([protected, unprotected, payload, signature])."""
        return [b"\xa0", {}, b"payload-bytes", b"signature-bytes"]

    def _make_issuer_signed_b64(self, auth_value) -> str:
        """Encode an IssuerSigned CBOR map to base64url."""
        issuer_signed = {"issuerAuth": auth_value, "nameSpaces": {}}
        return b64url(cbor2.dumps(issuer_signed))

    # -- tests: bstr-wrapped (the bug) ------------------------------------

    def test_bstr_wrapped_issuer_auth_is_unwrapped(self) -> None:
        """If issuerAuth is a CBOR byte string wrapping a COSE_Sign1 array,
        the fix must unwrap it to an embedded array."""
        cose_array = self._make_cose_sign1_array()
        bstr_wrapped = cbor2.dumps(cose_array)  # encode the array into bytes

        b64 = self._make_issuer_signed_b64(bstr_wrapped)
        fixed_b64 = _fix_mdoc_issuer_auth(b64)

        result = cbor2.loads(b64url_decode(fixed_b64))
        assert isinstance(result["issuerAuth"], list), (
            "issuerAuth should be a CBOR array after fix, got "
            + type(result["issuerAuth"]).__name__
        )
        assert result["issuerAuth"] == cose_array

    def test_tag_18_stripped(self) -> None:
        """If the wrapped value carries CBOR Tag 18 (COSE_Sign1 semantic tag),
        the tag must be stripped — wallets expect a plain array."""
        cose_array = self._make_cose_sign1_array()
        tagged = cbor2.CBORTag(18, cose_array)
        bstr_wrapped = cbor2.dumps(tagged)

        b64 = self._make_issuer_signed_b64(bstr_wrapped)
        fixed_b64 = _fix_mdoc_issuer_auth(b64)

        result = cbor2.loads(b64url_decode(fixed_b64))
        assert isinstance(result["issuerAuth"], list)
        assert result["issuerAuth"] == cose_array

    # -- tests: already-correct (no-op) -----------------------------------

    def test_already_correct_array_unchanged(self) -> None:
        """If issuerAuth is already an array, the function should be a no-op."""
        cose_array = self._make_cose_sign1_array()
        b64 = self._make_issuer_signed_b64(cose_array)

        fixed_b64 = _fix_mdoc_issuer_auth(b64)
        # Compare decoded CBOR content (base64 padding may differ)
        original = cbor2.loads(b64url_decode(b64))
        result = cbor2.loads(b64url_decode(fixed_b64))
        assert result == original, "No change expected when issuerAuth is already an array"

    # -- tests: round-trip integrity --------------------------------------

    def test_namespaces_preserved_after_fix(self) -> None:
        """Other map keys (nameSpaces) must survive the fix untouched."""
        cose_array = self._make_cose_sign1_array()
        bstr_wrapped = cbor2.dumps(cose_array)

        ns = {"org.example": [b"attr1", b"attr2"]}
        issuer_signed = {"issuerAuth": bstr_wrapped, "nameSpaces": ns}
        b64 = b64url(cbor2.dumps(issuer_signed))

        fixed_b64 = _fix_mdoc_issuer_auth(b64)
        result = cbor2.loads(b64url_decode(fixed_b64))
        assert result["nameSpaces"] == ns

    def test_base64url_padding_handled(self) -> None:
        """The function must tolerate base64url without padding."""
        cose_array = self._make_cose_sign1_array()
        b64 = self._make_issuer_signed_b64(cose_array)
        # Strip padding
        b64_no_pad = b64.rstrip("=")
        result = _fix_mdoc_issuer_auth(b64_no_pad)
        # Should not raise — and the output should be valid
        cbor2.loads(b64url_decode(result))
