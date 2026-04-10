"""Unit tests exposing CBOR edge cases in _fix_mdoc_issuer_auth().

Issue 5.1: Corrupt base64url or truncated CBOR → uncaught exception (500)
Issue 5.2: Missing 'issuerAuth' key → silently returns original (no error)
Issue 6.1: 'suspended' template status not tested in status filter
"""

import cbor2
import pytest

from tests.unit._helpers import _fix_mdoc_issuer_auth, b64url, b64url_decode


class TestCborCorruptInput:
    """Issue 5.1: _fix_mdoc_issuer_auth has no error handling for bad input."""

    def test_corrupt_base64_raises_unhandled(self) -> None:
        """BUG: Invalid base64url input propagates binascii.Error as 500."""
        with pytest.raises(Exception):
            _fix_mdoc_issuer_auth("!!!not-valid-base64!!!")

    def test_truncated_cbor_raises_unhandled(self) -> None:
        """BUG: Valid base64url but truncated CBOR raises CBORDecodeError."""
        # Encode partial CBOR (first 3 bytes of a map)
        partial_cbor = b"\xa2\x6a"  # Start of a 2-item map with truncated key
        b64 = b64url(partial_cbor)

        with pytest.raises(Exception):
            _fix_mdoc_issuer_auth(b64)

    def test_empty_string_raises_unhandled(self) -> None:
        """BUG: Empty string produces empty base64 decode → CBOR error."""
        with pytest.raises(Exception):
            _fix_mdoc_issuer_auth("")

    def test_valid_base64_but_not_cbor_map(self) -> None:
        """BUG: Base64 encoding of a plain integer — cbor2.loads returns int,
        then .get("issuerAuth") fails with AttributeError."""
        int_cbor = cbor2.dumps(42)
        b64 = b64url(int_cbor)

        with pytest.raises((AttributeError, Exception)):
            _fix_mdoc_issuer_auth(b64)


class TestCborMissingIssuerAuth:
    """Issue 5.2: Missing 'issuerAuth' key passes silently."""

    def test_missing_issuer_auth_returns_original_silently(self) -> None:
        """BUG: If the CBOR map has no 'issuerAuth', the function returns
        the original without any error — potentially passing an invalid
        credential downstream."""
        cbor_map = {"nameSpaces": {}, "some_other_key": "value"}
        b64 = b64url(cbor2.dumps(cbor_map))

        result = _fix_mdoc_issuer_auth(b64)

        # It silently returns the original — this is the bug
        decoded = cbor2.loads(b64url_decode(result))
        assert "issuerAuth" not in decoded

    def test_issuer_auth_is_none_returns_original(self) -> None:
        """If issuerAuth is explicitly None, isinstance(None, bytes) is False
        so it returns original. Downstream won't have a valid credential."""
        cbor_map = {"issuerAuth": None, "nameSpaces": {}}
        b64 = b64url(cbor2.dumps(cbor_map))

        result = _fix_mdoc_issuer_auth(b64)
        decoded = cbor2.loads(b64url_decode(result))
        assert decoded["issuerAuth"] is None

    def test_issuer_auth_is_integer_returns_original(self) -> None:
        """Non-bytes, non-list issuerAuth values pass through untouched."""
        cbor_map = {"issuerAuth": 999, "nameSpaces": {}}
        b64 = b64url(cbor2.dumps(cbor_map))

        result = _fix_mdoc_issuer_auth(b64)
        decoded = cbor2.loads(b64url_decode(result))
        assert decoded["issuerAuth"] == 999


class TestCborDoubleWrapping:
    """Issue 5.3: Double-nested Tag 18 — only one level is stripped."""

    def test_double_tag_18_only_strips_one_level(self) -> None:
        """If issuerAuth is bstr(Tag18(bstr(array))), only the outer
        bstr + Tag 18 is stripped; the inner bstr remains."""
        cose_array = [b"\xa0", {}, b"payload", b"sig"]

        # Inner: Tag18(array) as bytes
        inner = cbor2.dumps(cbor2.CBORTag(18, cose_array))
        # Outer: Tag18(inner_bytes)
        outer = cbor2.dumps(cbor2.CBORTag(18, inner))

        cbor_map = {"issuerAuth": outer, "nameSpaces": {}}
        b64 = b64url(cbor2.dumps(cbor_map))

        result = _fix_mdoc_issuer_auth(b64)
        decoded = cbor2.loads(b64url_decode(result))

        # After one level of unwrap, we get the inner bytes (still wrapped)
        # This is NOT the final array — it's the Tag18(array) bytes
        auth = decoded["issuerAuth"]
        # If fix only strips one level, the result is bytes, not a list
        assert isinstance(auth, bytes), (
            "Double-wrapped Tag 18: only one level stripped, inner remains as bytes"
        )
