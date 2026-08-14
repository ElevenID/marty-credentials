"""Application service for verification."""

import hashlib
import json
import os
import secrets
from typing import Any

from ..domain.entities import (
    SubmissionClaimState,
    VerificationMethod,
    VerificationSession,
    VerificationSubmissionClaim,
)
from ..domain.ports import ICredentialVerifier, IVerificationRepository
from .canonical_result import (
    adapter_processing_status,
    build_canonical_result,
    pending_evidence,
)
from .governance import (
    DIRECT_VERIFY_PURPOSE,
    SESSION_CREATE_PURPOSE,
    GovernanceConfigurationError,
    GovernancePolicyMismatchError,
    VerificationGovernanceContext,
    load_governance,
)

DEFAULT_PROCESSING_LEASE_SECONDS = 60
MIN_PROCESSING_LEASE_SECONDS = 5
MAX_PROCESSING_LEASE_SECONDS = 300
MIN_SESSION_DURATION_SECONDS = 30
MAX_SESSION_DURATION_SECONDS = 3600


class VerificationValidationError(ValueError):
    """A verification request violates the application contract."""


class VerificationSessionNotFoundError(VerificationValidationError):
    """The requested verification session does not exist."""


class VerificationSessionExpiredError(VerificationValidationError):
    """The storage-authoritative session deadline elapsed."""


class VerificationSessionBusyError(VerificationValidationError):
    """The exact presentation is already being processed under a live lease."""


class VerificationSessionConflictError(VerificationValidationError):
    """A different presentation or stale worker attempted to use the session."""


class UnsupportedSessionPresentationError(VerificationValidationError):
    """The presentation shape cannot be bound to the session nonce."""


def processing_lease_seconds() -> int:
    """Return the bounded server-owned worker lease configuration."""
    raw = os.environ.get(
        "VERIFICATION_PROCESSING_LEASE_SECONDS",
        str(DEFAULT_PROCESSING_LEASE_SECONDS),
    )
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("VERIFICATION_PROCESSING_LEASE_SECONDS must be an integer") from exc
    if not MIN_PROCESSING_LEASE_SECONDS <= value <= MAX_PROCESSING_LEASE_SECONDS:
        raise RuntimeError(
            "VERIFICATION_PROCESSING_LEASE_SECONDS must be between "
            f"{MIN_PROCESSING_LEASE_SECONDS} and {MAX_PROCESSING_LEASE_SECONDS}"
        )
    return value


def _require_claimed_or_terminal(
    claim: VerificationSubmissionClaim,
) -> VerificationSubmissionClaim:
    """Map storage outcomes to stable application errors."""
    if claim.state in {SubmissionClaimState.CLAIMED, SubmissionClaimState.TERMINAL}:
        return claim
    if claim.state is SubmissionClaimState.NOT_FOUND:
        raise VerificationSessionNotFoundError("Verification session not found")
    if claim.state is SubmissionClaimState.EXPIRED:
        raise VerificationSessionExpiredError("Verification session has expired")
    if claim.state is SubmissionClaimState.BUSY:
        raise VerificationSessionBusyError("Verification session is already processing")
    raise VerificationSessionConflictError("Verification session submission conflicts")


def _require_finalized_or_terminal(
    result: VerificationSubmissionClaim,
) -> VerificationSession:
    """Return the immutable winning terminal state or raise a stable error."""
    if result.state in {SubmissionClaimState.FINALIZED, SubmissionClaimState.TERMINAL}:
        if result.session is None:
            raise RuntimeError("Terminal repository result omitted the session")
        return result.session
    if result.state is SubmissionClaimState.NOT_FOUND:
        raise VerificationSessionNotFoundError("Verification session not found")
    if result.state is SubmissionClaimState.EXPIRED:
        raise VerificationSessionExpiredError("Verification session has expired")
    raise VerificationSessionConflictError("Verification worker no longer owns the session")


def _presentation_sha256(presentation: dict[str, Any] | str) -> str:
    """Return a deterministic digest without retaining credential-bearing input."""
    if isinstance(presentation, str):
        encoded = presentation.encode("utf-8")
    else:
        encoded = json.dumps(
            presentation,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class VerificationService:
    """Application service coordinating verification operations."""

    def __init__(self, repository: IVerificationRepository, verifier: ICredentialVerifier):
        self.repository = repository
        self.verifier = verifier

    async def create_verification_session(
        self,
        verifier_did: str,
        presentation_definition: dict[str, Any],
        governance: VerificationGovernanceContext,
        session_duration_seconds: int = 600,
    ) -> VerificationSession:
        """Create a new verification session (OID4VP flow)."""
        governance.require_purpose(SESSION_CREATE_PURPOSE)
        governance.validate_request(
            verifier_id=verifier_did,
            presentation_definition=presentation_definition,
        )
        if (
            not MIN_SESSION_DURATION_SECONDS
            <= session_duration_seconds
            <= MAX_SESSION_DURATION_SECONDS
        ):
            raise VerificationValidationError(
                "Verification session duration must be between "
                f"{MIN_SESSION_DURATION_SECONDS} and {MAX_SESSION_DURATION_SECONDS} seconds"
            )
        session_id = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        session = VerificationSession(
            id=session_id,
            organization_id=governance.organization_id,
            verifier_did=verifier_did,
            presentation_definition=presentation_definition,
            trusted_issuers=list(governance.trust_profile.trusted_issuers),
            verification_evidence=pending_evidence(governance),
            nonce=nonce,
            request_uri=f"oid4vp://request?session_id={session_id}",
        )

        return await self.repository.create_session(session, session_duration_seconds)

    async def verify_presentation_direct(
        self,
        presentation: dict[str, Any] | str,
        presentation_definition: dict[str, Any],
        verifier_did: str,
        governance: VerificationGovernanceContext,
    ) -> dict[str, Any]:
        """Verify a presentation directly without session (stateless)."""
        governance.require_purpose(DIRECT_VERIFY_PURPOSE)
        governance.validate_request(
            verifier_id=verifier_did,
            presentation_definition=presentation_definition,
        )
        # Determine verification method
        if isinstance(presentation, str):
            # JWT VP
            result = await self.verifier.verify_jwt_vp(
                presentation_jwt=presentation, expected_audience=verifier_did, expected_nonce=None
            )
            method = VerificationMethod.JWT_VP
        else:
            # Structured presentation
            result = await self.verifier.verify_presentation(
                presentation=presentation,
                presentation_definition=presentation_definition,
                verifier_did=verifier_did,
                trusted_issuers=list(governance.trust_profile.trusted_issuers),
                organization_id=governance.organization_id,
                allow_public_did_fallback=governance.trust_profile.allow_public_did_fallback,
            )
            method = VerificationMethod.W3C_VC

        processing_status = adapter_processing_status(result)
        return {
            "evidence": build_canonical_result(
                governance=governance,
                verification_id=f"verification:{secrets.token_urlsafe(24)}",
                transaction_id=f"transaction:{secrets.token_urlsafe(24)}",
                presentation=presentation,
                adapter_result=result,
                processing_status=processing_status,
            ),
            "verification_method": method.value,
        }

    async def submit_presentation(
        self, session_id: str, presentation: dict[str, Any] | str
    ) -> VerificationSession:
        """Atomically claim, verify, and finalize one nonce-bound presentation."""
        if not isinstance(presentation, str):
            raise UnsupportedSessionPresentationError(
                "Session-bound structured presentations are unsupported because "
                "the verifier cannot bind them to the session nonce"
            )

        method = VerificationMethod.JWT_VP
        presentation_digest = _presentation_sha256(presentation)
        processing_token = secrets.token_urlsafe(32)
        claim = _require_claimed_or_terminal(
            await self.repository.claim_submission(
                session_id,
                presentation_digest,
                processing_token,
                processing_lease_seconds(),
            )
        )
        if claim.state is SubmissionClaimState.TERMINAL:
            if claim.session is None:
                raise RuntimeError("Terminal repository claim omitted the session")
            return claim.session
        if claim.session is None or claim.verifier_nonce is None:
            raise RuntimeError("Claimed session omitted nonce-bound verification state")
        session = claim.session

        try:
            governance = load_governance().resume_session(
                session.verification_evidence.get("governance")
                if isinstance(session.verification_evidence, dict)
                else None
            )
            if governance.organization_id != session.organization_id:
                raise GovernanceConfigurationError(
                    "persisted governance organization does not match session"
                )
            governance.require_purpose(SESSION_CREATE_PURPOSE)
            governance.validate_request(
                verifier_id=session.verifier_did,
                presentation_definition=session.presentation_definition,
            )
        except (GovernanceConfigurationError, GovernancePolicyMismatchError):
            session.fail(
                "Verification provenance unavailable",
                method=method,
                verification_evidence={
                    "schema_version": 1,
                    "legacy": True,
                    "reason_code": "MISSING_GOVERNANCE_PROVENANCE",
                    "presentation_sha256": presentation_digest,
                },
            )
        else:
            try:
                result = await self.verifier.verify_jwt_vp(
                    presentation_jwt=presentation,
                    expected_audience=session.verifier_did,
                    expected_nonce=claim.verifier_nonce,
                )
            except Exception:
                result = {"processing_status": "ERROR"}

            processing_status = adapter_processing_status(result)

            try:
                evidence = build_canonical_result(
                    governance=governance,
                    verification_id=f"verification:{session.id}",
                    transaction_id=session.id,
                    presentation=presentation,
                    adapter_result=result,
                    processing_status=processing_status,
                )
            except Exception:
                session.fail(
                    "Canonical verification result unavailable",
                    method=method,
                    verification_evidence={
                        "schema_version": 1,
                        "legacy": True,
                        "reason_code": "CANONICAL_RESULT_BUILD_FAILED",
                        "presentation_sha256": presentation_digest,
                    },
                )
            else:
                canonical_result = evidence["canonical_result"]
                if canonical_result["valid"] is True:
                    session.verify(
                        verified_claims={},
                        method=method,
                        verification_evidence=evidence,
                    )
                else:
                    session.fail(
                        "Verification did not produce a passing canonical decision",
                        method=method,
                        verification_evidence=evidence,
                    )

        return _require_finalized_or_terminal(
            await self.repository.finalize_submission(
                session,
                presentation_digest,
                processing_token,
            )
        )

    async def get_session(self, session_id: str) -> VerificationSession | None:
        """Retrieve a verification session."""
        return await self.repository.get_by_id(session_id)

    async def list_sessions(
        self, organization_id: str, limit: int = 100, offset: int = 0
    ) -> list[VerificationSession]:
        """List verification sessions for an organization."""
        return await self.repository.list_by_organization(organization_id, limit, offset)
