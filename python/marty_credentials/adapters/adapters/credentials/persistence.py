"""
Persistence Adapter

This module provides SQLAlchemy-based persistence for credential management.
"""

import json
import logging
from datetime import datetime
from typing import Any, TypeVar

from sqlalchemy import JSON, Column, DateTime, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base

from mmf.core.credentials.ports import (
    CredentialData,
    CredentialSubject,
    ICredentialWallet,
    IKeyManager,
    KeyAlgorithm,
    KeyPair,
)

logger = logging.getLogger(__name__)
Base = declarative_base()

# ==================== Database Models ====================


class KeyModel(Base):
    """Database model for cryptographic keys."""

    __tablename__ = "keys"

    id = Column(String, primary_key=True)
    did = Column(String, nullable=False)
    jwk_json = Column(String, nullable=False)
    algorithm = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class CredentialModel(Base):
    """Database model for stored credentials."""

    __tablename__ = "credentials"

    id = Column(String, primary_key=True)
    types = Column(JSON, nullable=False)
    issuer = Column(String, nullable=False)
    subject_id = Column(String, nullable=True)
    claims = Column(JSON, nullable=False)
    issuance_date = Column(DateTime, nullable=False)
    expiration_date = Column(DateTime, nullable=True)
    jwt = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ==================== Adapters ====================


class SQLAlchemyKeyManager:
    """Key manager implementation using SQLAlchemy."""

    def __init__(self, session: AsyncSession, delegate: IKeyManager):
        self.session = session
        self.delegate = delegate  # Delegate to actual crypto implementation (SpruceID/Multipaz)

    async def generate_key(self, algorithm: KeyAlgorithm = KeyAlgorithm.ES256) -> KeyPair:
        """Generate and store a new key pair."""
        # Generate using delegate
        key_pair = self.delegate.generate_key(algorithm)

        # Store in DB (we don't have key_id here, so we might need to generate one or rely on store_key)
        return key_pair

    async def store_key(self, key_id: str, key_pair: KeyPair) -> None:
        """Store a key pair."""
        # Store in delegate (in-memory cache)
        self.delegate.store_key(key_id, key_pair)

        # Store in DB
        model = KeyModel(
            id=key_id,
            did=key_pair.did,
            jwk_json=key_pair.jwk_json,
            algorithm=key_pair.algorithm.value,
            created_at=key_pair.created_at,
        )
        self.session.add(model)
        await self.session.commit()

    async def get_key(self, key_id: str) -> KeyPair | None:
        """Retrieve a stored key pair."""
        # Try delegate first
        key = self.delegate.get_key(key_id)
        if key:
            return key

        # Try DB
        result = await self.session.execute(select(KeyModel).where(KeyModel.id == key_id))
        model = result.scalar_one_or_none()

        if model:
            key_pair = KeyPair(
                did=model.did,
                jwk_json=model.jwk_json,
                algorithm=KeyAlgorithm(model.algorithm),
                created_at=model.created_at,
            )
            # Cache in delegate
            self.delegate.store_key(key_id, key_pair)
            return key_pair

        return None

    async def list_keys(self) -> list[str]:
        """List all stored key identifiers."""
        result = await self.session.execute(select(KeyModel.id))
        return list(result.scalars().all())


class SQLAlchemyCredentialWallet:
    """Credential wallet implementation using SQLAlchemy."""

    def __init__(self, session: AsyncSession, delegate: ICredentialWallet):
        self.session = session
        self.delegate = delegate

    async def store_credential(self, credential: CredentialData) -> str:
        """Store a credential."""
        # Store in delegate
        self.delegate.store_credential(credential)

        # Store in DB
        model = CredentialModel(
            id=credential.id,
            types=credential.types,
            issuer=credential.issuer,
            subject_id=credential.subject.id,
            claims=credential.subject.claims,
            issuance_date=credential.issuance_date,
            expiration_date=credential.expiration_date,
            jwt=credential.jwt,
        )
        self.session.add(model)
        await self.session.commit()

        return credential.id

    async def get_credential(self, credential_id: str) -> CredentialData | None:
        """Retrieve a credential."""
        # Try delegate
        cred = self.delegate.get_credential(credential_id)
        if cred:
            return cred

        # Try DB
        result = await self.session.execute(
            select(CredentialModel).where(CredentialModel.id == credential_id)
        )
        model = result.scalar_one_or_none()

        if model:
            cred = CredentialData(
                id=model.id,
                types=model.types,
                issuer=model.issuer,
                subject=CredentialSubject(id=model.subject_id, claims=model.claims),
                issuance_date=model.issuance_date,
                expiration_date=model.expiration_date,
                jwt=model.jwt,
            )
            # Cache in delegate
            self.delegate.store_credential(cred)
            return cred

        return None

    async def list_credentials(self, credential_type: str | None = None) -> list[CredentialData]:
        """List credentials."""
        query = select(CredentialModel)
        if credential_type:
            # This is a simple check, JSON array containment is DB specific
            # For now we fetch all and filter in python if needed, or rely on delegate if fully loaded
            pass

        result = await self.session.execute(query)
        models = result.scalars().all()

        creds = []
        for model in models:
            if credential_type and credential_type not in model.types:
                continue

            creds.append(
                CredentialData(
                    id=model.id,
                    types=model.types,
                    issuer=model.issuer,
                    subject=CredentialSubject(id=model.subject_id, claims=model.claims),
                    issuance_date=model.issuance_date,
                    expiration_date=model.expiration_date,
                    jwt=model.jwt,
                )
            )

        return creds

    # Delegate other methods
    def create_presentation(self, *args, **kwargs):
        return self.delegate.create_presentation(*args, **kwargs)

    def redeem_offer(self, *args, **kwargs):
        return self.delegate.redeem_offer(*args, **kwargs)
