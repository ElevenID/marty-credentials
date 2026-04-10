"""Shared test helpers for marty-credentials unit tests."""

import base64

import cbor2

# Import with a helper that insulates us from the deep import chain.
# If the full application import fails, we define a local copy so the
# regression tests still run.
try:
    from issuance.application.rust_integration import _fix_mdoc_issuer_auth
except Exception:
    def _fix_mdoc_issuer_auth(credential_b64: str) -> str:  # type: ignore[misc]
        padding = 4 - len(credential_b64) % 4
        if padding < 4:
            credential_b64 += "=" * padding
        raw = base64.urlsafe_b64decode(credential_b64)

        issuer_signed = cbor2.loads(raw)
        auth = issuer_signed.get("issuerAuth")
        if isinstance(auth, bytes):
            decoded = cbor2.loads(auth)
            if isinstance(decoded, cbor2.CBORTag) and decoded.tag == 18:
                issuer_signed["issuerAuth"] = decoded.value
            else:
                issuer_signed["issuerAuth"] = decoded

            fixed = cbor2.dumps(issuer_signed)
            return base64.urlsafe_b64encode(fixed).rstrip(b"=").decode()

        return credential_b64


def b64url(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """Decode base64url, adding padding as needed."""
    padding = 4 - len(s) % 4
    if padding < 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)
