"""
Persistence Adapter

SQLAlchemy-based persistence for credential management.
Wraps other adapters to add database persistence.
"""

from marty_credentials.adapters.persistence.adapter import (
    Base,
    CredentialModel,
    KeyModel,
    SQLAlchemyCredentialWallet,
    SQLAlchemyKeyManager,
)

__all__ = [
    "Base",
    "KeyModel",
    "CredentialModel",
    "SQLAlchemyKeyManager",
    "SQLAlchemyCredentialWallet",
]
