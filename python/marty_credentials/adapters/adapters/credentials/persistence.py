"""Credential persistence through the canonical SQLAlchemy adapter."""

from marty_credentials.adapters.persistence.adapter import (
    Base,
    CredentialModel,
    SQLAlchemyCredentialWallet,
)

__all__ = ["Base", "CredentialModel", "SQLAlchemyCredentialWallet"]
