"""
Marty Credentials

Credential domain logic and adapters for the Marty ecosystem.
"""

__version__ = "0.1.1"

__all__ = [
    # Core types
    "CredentialData",
    "CredentialFormat",
    "CredentialOffer",
    "CredentialSubject",
    "PresentationRequest",
    "VerificationResult",
    # Port interfaces
    "ICredentialVerifier",
    "ICredentialWallet",
]

_ports_symbols = {
    "CredentialData",
    "CredentialFormat",
    "CredentialOffer",
    "CredentialSubject",
    "ICredentialVerifier",
    "ICredentialWallet",
    "PresentationRequest",
    "VerificationResult",
}


def __getattr__(name: str):
    if name in _ports_symbols:
        from marty_credentials import ports as _ports

        return getattr(_ports, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
