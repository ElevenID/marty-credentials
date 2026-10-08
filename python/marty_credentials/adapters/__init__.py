"""
Credential Adapters

Concrete implementations of credential ports for various libraries and services.

Available adapters:
- rust: OID4VCI/OID4VP adapters via marty-rs (Rust FFI)
- persistence: SQLAlchemy database layer (wraps other adapters)
"""

# Adapters are imported as needed to avoid heavy dependencies
# from marty_credentials.adapters.rust import RustCredentialWallet, RustCredentialVerifier
# from marty_credentials.adapters.persistence import SQLAlchemyCredentialWallet

__all__: list[str] = []
