"""PostgreSQL repository for verification sessions."""

import logging
from datetime import datetime
from typing import Any

from mmf.infrastructure.database.base import Base
from sqlalchemy import JSON, DateTime, Enum, String, Text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import Mapped, mapped_column

from ...domain.entities import VerificationMethod, VerificationSession, VerificationStatus
from ...domain.ports import IVerificationRepository

logger = logging.getLogger(__name__)


class VerificationSessionModel(Base):  # type: ignore[misc]
    """SQLAlchemy model for verification sessions."""

    __tablename__ = "verification_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    organization_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    verifier_did: Mapped[str] = mapped_column(String, nullable=False)
    presentation_definition: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus),
        nullable=False,
        default=VerificationStatus.PENDING,
    )

    # Optional constraints
    required_credential_types: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    trusted_issuers: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    required_claims: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # Verification results
    presentation_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    verified_claims: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    verification_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    verification_method: Mapped[VerificationMethod | None] = mapped_column(
        Enum(VerificationMethod),
        nullable=True,
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # State tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_uri: Mapped[str | None] = mapped_column(String, nullable=True)
    nonce: Mapped[str | None] = mapped_column(String, nullable=True, index=True)


class PostgresVerificationRepository(IVerificationRepository):
    """PostgreSQL implementation of verification repository."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_session(self, session: VerificationSession) -> None:
        """Save or update a verification session."""
        model = await self.session.get(VerificationSessionModel, session.id)

        if model:
            # Update existing
            model.organization_id = session.organization_id
            model.verifier_did = session.verifier_did
            model.presentation_definition = session.presentation_definition
            model.status = session.status
            model.required_credential_types = session.required_credential_types
            model.trusted_issuers = session.trusted_issuers
            model.required_claims = session.required_claims
            model.presentation_data = None
            model.verified_claims = session.verified_claims
            model.verification_evidence = session.verification_evidence
            model.verification_method = session.verification_method
            model.verified_at = session.verified_at
            model.updated_at = session.updated_at
            model.expires_at = session.expires_at
            model.error_message = session.error_message
            model.request_uri = session.request_uri
            model.nonce = session.nonce
        else:
            # Create new
            model = VerificationSessionModel(
                id=session.id,
                organization_id=session.organization_id,
                verifier_did=session.verifier_did,
                presentation_definition=session.presentation_definition,
                status=session.status,
                required_credential_types=session.required_credential_types,
                trusted_issuers=session.trusted_issuers,
                required_claims=session.required_claims,
                presentation_data=None,
                verified_claims=session.verified_claims,
                verification_evidence=session.verification_evidence,
                verification_method=session.verification_method,
                verified_at=session.verified_at,
                created_at=session.created_at,
                updated_at=session.updated_at,
                expires_at=session.expires_at,
                error_message=session.error_message,
                request_uri=session.request_uri,
                nonce=session.nonce,
            )
            self.session.add(model)

        await self.session.commit()

    async def get_by_id(self, session_id: str) -> VerificationSession | None:
        """Retrieve a verification session by ID."""
        model = await self.session.get(VerificationSessionModel, session_id)
        if not model:
            return None
        return self._to_entity(model)

    async def get_by_nonce(self, nonce: str) -> VerificationSession | None:
        """Retrieve a verification session by nonce."""
        result = await self.session.execute(
            select(VerificationSessionModel).where(VerificationSessionModel.nonce == nonce)
        )
        model = result.scalar_one_or_none()
        if not model:
            return None
        return self._to_entity(model)

    async def list_by_organization(
        self, organization_id: str, limit: int = 100, offset: int = 0
    ) -> list[VerificationSession]:
        """List verification sessions for an organization."""
        result = await self.session.execute(
            select(VerificationSessionModel)
            .where(VerificationSessionModel.organization_id == organization_id)
            .order_by(VerificationSessionModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        models = result.scalars().all()
        return [self._to_entity(model) for model in models]

    def _to_entity(self, model: VerificationSessionModel) -> VerificationSession:
        """Convert SQLAlchemy model to domain entity."""
        return VerificationSession(
            id=model.id,
            organization_id=model.organization_id,
            verifier_did=model.verifier_did,
            presentation_definition=model.presentation_definition,
            status=model.status,
            required_credential_types=model.required_credential_types or [],
            trusted_issuers=model.trusted_issuers or [],
            required_claims=model.required_claims or [],
            presentation_data=None,
            verified_claims=model.verified_claims,
            verification_evidence=model.verification_evidence or {},
            verification_method=model.verification_method,
            verified_at=model.verified_at,
            created_at=model.created_at,
            updated_at=model.updated_at,
            expires_at=model.expires_at,
            error_message=model.error_message,
            request_uri=model.request_uri,
            nonce=model.nonce,
        )
