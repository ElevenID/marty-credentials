"""
Persistence Adapter Implementation

SQLAlchemy-based persistence for credential management.
"""

import logging
from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base

from marty_credentials.ports import (
    CredentialData,
    CredentialSubject,
    ICredentialWallet,
)

logger = logging.getLogger(__name__)
Base = declarative_base()


# ==================== Database Models ====================


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


class SQLAlchemyCredentialWallet:
    """Credential wallet implementation using SQLAlchemy for persistence.

    Wraps a delegate wallet (SpruceID, Multipaz, etc.) and adds
    database persistence for credentials.
    """

    def __init__(self, session: AsyncSession, delegate: ICredentialWallet):
        self.session = session
        self.delegate = delegate

    async def store_credential(self, credential: CredentialData) -> str:
        """Store a credential in both delegate and database."""
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
        """Retrieve a stored credential."""
        # Try delegate first
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
        """List stored credentials."""
        result = await self.session.execute(select(CredentialModel))
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

    async def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential from both delegate and database."""
        # Delete from delegate
        deleted = self.delegate.delete_credential(credential_id)

        # Delete from DB
        result = await self.session.execute(
            select(CredentialModel).where(CredentialModel.id == credential_id)
        )
        model = result.scalar_one_or_none()
        if model:
            await self.session.delete(model)
            await self.session.commit()
            return True

        return deleted
