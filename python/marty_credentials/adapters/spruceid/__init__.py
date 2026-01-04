"""
SpruceID Adapter

Credential adapters implementing the credential ports using SpruceID's SSI library
via Rust FFI bindings (marty-rs).
"""

from marty_credentials.adapters.spruceid.adapter import (
    SpruceIDCredentialIssuer,
    SpruceIDCredentialVerifier,
    SpruceIDCredentialWallet,
    SpruceIDKeyManager,
    create_spruceid_adapters,
    get_issuer,
    get_key_manager,
    get_verifier,
    get_wallet,
)

__all__ = [
    "SpruceIDKeyManager",
    "SpruceIDCredentialIssuer",
    "SpruceIDCredentialWallet",
    "SpruceIDCredentialVerifier",
    "create_spruceid_adapters",
    "get_key_manager",
    "get_issuer",
    "get_wallet",
    "get_verifier",
]
