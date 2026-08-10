"""Retired Python Multipaz-compatible cryptographic adapters.

The historical implementation in this module generated keys and implemented
mDoc CBOR/COSE issuance and verification in Python. Those operations now have
one supported implementation in the canonical Marty Rust bindings. The class
names remain importable for compatibility, but instantiation fails closed so
an adapter selection can never restore the retired protocol kernel.
"""

from __future__ import annotations

from typing import NoReturn

from marty_credentials.native_backend import NativeOperationError

CASE_ALG_ES256 = -7
CASE_ALG_ES384 = -35
CASE_ALG_EDDSA = -8
CASE_HDR_ALG = 1
CASE_HDR_X5CHAIN = 33
MDOC_DOCTYPE_MDL = "org.iso.18013.5.1.mDL"
MDOC_NAMESPACE_MDL = "org.iso.18013.5.1"


def _retired() -> NoReturn:
    raise NativeOperationError(
        "The Python Multipaz-compatible cryptographic adapter was retired; "
        "use the canonical Rust mDoc issuance, presentation, and verification services"
    )


class MultipazKeyManager:
    """Compatibility name for the retired Python key manager."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        _retired()


class MultipazCredentialIssuer:
    """Compatibility name for the retired Python mDoc issuer."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        _retired()


class MultipazCredentialWallet:
    """Compatibility name for the retired Python mDoc wallet."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        _retired()


class MultipazCredentialVerifier:
    """Compatibility name for the retired Python mDoc verifier."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        _retired()
