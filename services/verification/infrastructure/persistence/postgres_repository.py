"""PostgreSQL repository for verification sessions."""

import hashlib
import hmac
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from mmf.infrastructure.database.base import Base
from sqlalchemy import JSON, CheckConstraint, DateTime, Enum, Index, String, Text, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import Mapped, mapped_column

from ...domain.entities import (
    SubmissionClaimState,
    VerificationMethod,
    VerificationSession,
    VerificationStatus,
    VerificationSubmissionClaim,
)
from ...domain.ports import IVerificationRepository

logger = logging.getLogger(__name__)


class VerificationSessionModel(Base):  # type: ignore[misc]
    """SQLAlchemy model for verification sessions."""

    __tablename__ = "verification_sessions"
    __table_args__ = (
        Index(
            "ux_verification_sessions_live_nonce",
            "nonce",
            unique=True,
            postgresql_where=text("nonce IS NOT NULL"),
        ),
        CheckConstraint(
            "nonce IS NULL OR length(nonce) = 43",
            name="ck_verification_nonce_length",
        ),
        CheckConstraint(
            "submission_sha256 IS NULL OR submission_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_verification_submission_digest",
        ),
        CheckConstraint(
            "processing_token_sha256 IS NULL OR processing_token_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_verification_processing_token_digest",
        ),
        CheckConstraint(
            "processing_started_at IS NULL OR processing_expires_at > processing_started_at",
            name="ck_verification_processing_lease",
        ),
        CheckConstraint(
            "(status = 'PENDING' AND nonce IS NOT NULL "
            "AND submission_sha256 IS NULL "
            "AND processing_token_sha256 IS NULL "
            "AND processing_started_at IS NULL AND processing_expires_at IS NULL) "
            "OR (status = 'IN_PROGRESS' AND submission_sha256 IS NOT NULL "
            "AND processing_token_sha256 IS NOT NULL "
            "AND processing_started_at IS NOT NULL "
            "AND processing_expires_at IS NOT NULL AND nonce IS NOT NULL) "
            "OR (status IN ('VERIFIED', 'FAILED') "
            "AND processing_token_sha256 IS NULL "
            "AND processing_started_at IS NULL "
            "AND processing_expires_at IS NULL AND nonce IS NULL) "
            "OR (status = 'EXPIRED' AND processing_token_sha256 IS NULL "
            "AND processing_started_at IS NULL "
            "AND processing_expires_at IS NULL AND nonce IS NULL)",
            name="ck_verification_atomic_state",
        ),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    organization_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    verifier_did: Mapped[str] = mapped_column(String, nullable=False)
    presentation_definition: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus, native_enum=False, length=32),
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
        Enum(VerificationMethod, native_enum=False, length=32),
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
    submission_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    processing_token_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    processing_started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    processing_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class PostgresVerificationRepository(IVerificationRepository):
    """PostgreSQL implementation of verification repository."""

    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def _token_sha256(processing_token: str) -> str:
        return hashlib.sha256(processing_token.encode("ascii")).hexdigest()

    @staticmethod
    def _naive_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value
        return value.astimezone(UTC).replace(tzinfo=None)

    async def _database_now(self) -> datetime:
        result = await self.session.execute(select(func.clock_timestamp()))
        return self._naive_utc(result.scalar_one())

    @staticmethod
    def _clear_processing(model: VerificationSessionModel) -> None:
        model.processing_token_sha256 = None
        model.processing_started_at = None
        model.processing_expires_at = None

    @classmethod
    def _expire_model(
        cls,
        model: VerificationSessionModel,
        now: datetime,
    ) -> None:
        model.status = VerificationStatus.EXPIRED
        model.nonce = None
        model.updated_at = now
        model.error_message = "Verification session expired"
        cls._clear_processing(model)

    async def _locked_model(self, session_id: str) -> VerificationSessionModel | None:
        result = await self.session.execute(
            select(VerificationSessionModel)
            .where(VerificationSessionModel.id == session_id)
            .with_for_update()
        )
        return result.scalar_one_or_none()

    async def create_session(
        self,
        session: VerificationSession,
        duration_seconds: int,
    ) -> VerificationSession:
        """Insert a new session whose lifetime starts on the storage clock."""
        try:
            now = await self._database_now()
            session.created_at = now
            session.updated_at = now
            session.expires_at = now + timedelta(seconds=duration_seconds)
            model = VerificationSessionModel(
                id=session.id,
                organization_id=session.organization_id,
                verifier_did=session.verifier_did,
                presentation_definition=session.presentation_definition,
                status=VerificationStatus.PENDING,
                required_credential_types=session.required_credential_types,
                trusted_issuers=session.trusted_issuers,
                required_claims=session.required_claims,
                presentation_data=None,
                verified_claims=None,
                verification_evidence={},
                verification_method=None,
                verified_at=None,
                created_at=now,
                updated_at=now,
                expires_at=session.expires_at,
                error_message=None,
                request_uri=session.request_uri,
                nonce=session.nonce,
                submission_sha256=None,
                processing_token_sha256=None,
                processing_started_at=None,
                processing_expires_at=None,
            )
            self.session.add(model)
            entity = self._to_entity(model)
            await self.session.commit()
            return entity
        except Exception:
            await self.session.rollback()
            raise

    async def claim_submission(
        self,
        session_id: str,
        presentation_sha256: str,
        processing_token: str,
        lease_seconds: int,
    ) -> VerificationSubmissionClaim:
        """Bind one digest to the nonce under a row lock and bounded lease."""
        try:
            model = await self._locked_model(session_id)
            if model is None:
                await self.session.rollback()
                return VerificationSubmissionClaim(SubmissionClaimState.NOT_FOUND)

            now = await self._database_now()
            if model.status in {VerificationStatus.VERIFIED, VerificationStatus.FAILED}:
                entity = self._to_entity(model)
                await self.session.rollback()
                state = (
                    SubmissionClaimState.TERMINAL
                    if model.submission_sha256 == presentation_sha256
                    else SubmissionClaimState.CONFLICT
                )
                return VerificationSubmissionClaim(state, session=entity)

            if model.expires_at is not None and model.expires_at <= now:
                self._expire_model(model, now)
                entity = self._to_entity(model)
                await self.session.commit()
                return VerificationSubmissionClaim(
                    SubmissionClaimState.EXPIRED,
                    session=entity,
                )

            if model.status == VerificationStatus.EXPIRED:
                entity = self._to_entity(model)
                await self.session.rollback()
                return VerificationSubmissionClaim(
                    SubmissionClaimState.EXPIRED,
                    session=entity,
                )

            if model.status == VerificationStatus.IN_PROGRESS:
                if model.submission_sha256 != presentation_sha256:
                    await self.session.rollback()
                    return VerificationSubmissionClaim(SubmissionClaimState.CONFLICT)
                if (
                    model.processing_expires_at is None
                    or model.processing_token_sha256 is None
                    or model.nonce is None
                ):
                    self._expire_model(model, now)
                    entity = self._to_entity(model)
                    await self.session.commit()
                    return VerificationSubmissionClaim(
                        SubmissionClaimState.EXPIRED,
                        session=entity,
                    )
                if model.processing_expires_at > now:
                    entity = self._to_entity(model)
                    await self.session.rollback()
                    return VerificationSubmissionClaim(
                        SubmissionClaimState.BUSY,
                        session=entity,
                    )
            elif model.status == VerificationStatus.PENDING:
                if model.nonce is None:
                    self._expire_model(model, now)
                    entity = self._to_entity(model)
                    await self.session.commit()
                    return VerificationSubmissionClaim(
                        SubmissionClaimState.EXPIRED,
                        session=entity,
                    )
                model.submission_sha256 = presentation_sha256
            else:
                await self.session.rollback()
                return VerificationSubmissionClaim(SubmissionClaimState.CONFLICT)

            lease_deadline = now + timedelta(seconds=lease_seconds)
            if model.expires_at is not None:
                lease_deadline = min(lease_deadline, model.expires_at)
            model.status = VerificationStatus.IN_PROGRESS
            model.processing_token_sha256 = self._token_sha256(processing_token)
            model.processing_started_at = now
            model.processing_expires_at = lease_deadline
            model.updated_at = now
            verifier_nonce = model.nonce
            entity = self._to_entity(model)
            await self.session.commit()
            return VerificationSubmissionClaim(
                SubmissionClaimState.CLAIMED,
                session=entity,
                verifier_nonce=verifier_nonce,
            )
        except Exception:
            await self.session.rollback()
            raise

    async def finalize_submission(
        self,
        session: VerificationSession,
        presentation_sha256: str,
        processing_token: str,
    ) -> VerificationSubmissionClaim:
        """Fence stale workers and make the first terminal result immutable."""
        try:
            model = await self._locked_model(session.id)
            if model is None:
                await self.session.rollback()
                return VerificationSubmissionClaim(SubmissionClaimState.NOT_FOUND)

            now = await self._database_now()
            if model.status in {VerificationStatus.VERIFIED, VerificationStatus.FAILED}:
                entity = self._to_entity(model)
                await self.session.rollback()
                state = (
                    SubmissionClaimState.TERMINAL
                    if model.submission_sha256 == presentation_sha256
                    else SubmissionClaimState.CONFLICT
                )
                return VerificationSubmissionClaim(state, session=entity)

            if model.expires_at is not None and model.expires_at <= now:
                self._expire_model(model, now)
                entity = self._to_entity(model)
                await self.session.commit()
                return VerificationSubmissionClaim(
                    SubmissionClaimState.EXPIRED,
                    session=entity,
                )

            if (
                model.status != VerificationStatus.IN_PROGRESS
                or model.submission_sha256 != presentation_sha256
            ):
                await self.session.rollback()
                return VerificationSubmissionClaim(SubmissionClaimState.CONFLICT)

            expected_token = self._token_sha256(processing_token)
            if (
                model.processing_token_sha256 is None
                or not hmac.compare_digest(model.processing_token_sha256, expected_token)
                or model.processing_expires_at is None
                or model.processing_expires_at <= now
            ):
                await self.session.rollback()
                return VerificationSubmissionClaim(SubmissionClaimState.STALE)

            if session.status not in {VerificationStatus.VERIFIED, VerificationStatus.FAILED}:
                await self.session.rollback()
                return VerificationSubmissionClaim(SubmissionClaimState.CONFLICT)

            model.status = session.status
            model.presentation_data = None
            model.verified_claims = session.verified_claims
            model.verification_evidence = session.verification_evidence
            model.verification_method = session.verification_method
            model.verified_at = now if session.status == VerificationStatus.VERIFIED else None
            model.updated_at = now
            model.error_message = session.error_message
            model.nonce = None
            self._clear_processing(model)
            entity = self._to_entity(model)
            await self.session.commit()
            return VerificationSubmissionClaim(
                SubmissionClaimState.FINALIZED,
                session=entity,
            )
        except Exception:
            await self.session.rollback()
            raise

    async def get_by_id(self, session_id: str) -> VerificationSession | None:
        """Retrieve a verification session by ID."""
        model = await self.session.get(VerificationSessionModel, session_id)
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
            submission_sha256=model.submission_sha256,
            processing_started_at=model.processing_started_at,
            processing_expires_at=model.processing_expires_at,
        )
