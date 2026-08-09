"""Resolve the SD-JWT VC type exactly as published by issuer metadata."""

from __future__ import annotations

from urllib.parse import urlparse


def resolve_credential_vct(
    raw_vct: object,
    credential_type: str,
    issuer_base_url: str,
) -> str:
    """Preserve any absolute VCT URI and derive a stable HTTPS fallback.

    VCT values are not limited to HTTP URLs. Profiles such as the EUDI PID use
    URNs, and replacing a configured URN during issuance makes the signed
    credential disagree with the credential configuration selected by the
    wallet.
    """
    value = raw_vct.strip() if isinstance(raw_vct, str) else ""
    if value and urlparse(value).scheme:
        return value
    return f"{issuer_base_url.rstrip('/')}/credentials/{credential_type}"
