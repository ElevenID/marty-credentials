"""Application service for verification."""

import hashlib
import json
import os
import secrets
from datetime import UTC, datetime
from typing import Any

from mmf.core.exceptions import ValidationError

from ..domain.entities import (
    SubmissionClaimState,
    VerificationMethod,
    VerificationSession,
    VerificationSubmissionClaim,
)
from ..domain.ports import ICredentialVerifier, IVerificationRepository

DEFAULT_PROCESSING_LEASE_SECONDS = 60
MIN_PROCESSING_LEASE_SECONDS = 5
MAX_PROCESSING_LEASE_SECONDS = 300
MIN_SESSION_DURATION_SECONDS = 30
MAX_SESSION_DURATION_SECONDS = 3600


class VerificationSessionNotFoundError(ValidationError):
    """The requested verification session does not exist."""


class VerificationSessionExpiredError(ValidationError):
    """The storage-authoritative session deadline elapsed."""


class VerificationSessionBusyError(ValidationError):
    """The exact presentation is already being processed under a live lease."""


class VerificationSessionConflictError(ValidationError):
    """A different presentation or stale worker attempted to use the session."""


class UnsupportedSessionPresentationError(ValidationError):
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


def reduce_verification_result(result: dict[str, Any]) -> dict[str, Any]:
    """Derive the authorization result only from explicit required evidence."""
    cryptographic_valid = result.get("cryptographic_valid", result.get("valid")) is True
    trust_chain_valid = result.get("trust_chain_valid") is True
    revocation_checked = result.get("revocation_checked") is True
    revocation_status = str(result.get("revocation_status") or "SKIPPED").upper()
    not_revoked = revocation_checked and revocation_status == "VALID"
    valid = cryptographic_valid and trust_chain_valid and not_revoked

    error = result.get("error")
    if not error and not valid:
        missing: list[str] = []
        if not cryptographic_valid:
            missing.append("cryptographic verification")
        if not trust_chain_valid:
            missing.append("issuer trust")
        if not revocation_checked:
            missing.append("revocation check")
        elif not not_revoked:
            missing.append(f"non-revoked status ({revocation_status})")
        error = f"Required verification evidence unavailable or failed: {', '.join(missing)}"

    return {
        **result,
        "valid": valid,
        "overall_result": "PASS" if valid else "FAIL",
        "cryptographic_valid": cryptographic_valid,
        "trust_chain_valid": trust_chain_valid,
        "revocation_checked": revocation_checked,
        "revocation_status": revocation_status,
        "error": error,
        "verified_claims": (
            result.get("claims", result.get("verified_claims", {})) if valid else {}
        ),
    }


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


def _session_evidence(
    result: dict[str, Any],
    method: VerificationMethod,
    presentation_digest: str,
) -> dict[str, Any]:
    """Build the claim-free, versioned decision record persisted with a session."""
    return {
        "schema_version": 1,
        "overall_result": result.get("overall_result", "ERROR"),
        "cryptographic_valid": result.get("cryptographic_valid") is True,
        "trust_chain_valid": result.get("trust_chain_valid") is True,
        "revocation_checked": result.get("revocation_checked") is True,
        "revocation_status": str(result.get("revocation_status") or "SKIPPED").upper(),
        "verification_method": method.value,
        "presentation_sha256": presentation_digest,
        "evaluated_at": datetime.now(UTC).isoformat(),
    }


class VerificationService:
    """Application service coordinating verification operations."""

    def __init__(self, repository: IVerificationRepository, verifier: ICredentialVerifier):
        self.repository = repository
        self.verifier = verifier

    async def create_verification_session(
        self,
        organization_id: str,
        verifier_did: str,
        presentation_definition: dict[str, Any],
        required_credential_types: list[str] | None = None,
        trusted_issuers: list[str] | None = None,
        session_duration_seconds: int = 600,
    ) -> VerificationSession:
        """Create a new verification session (OID4VP flow)."""
        if (
            not MIN_SESSION_DURATION_SECONDS
            <= session_duration_seconds
            <= MAX_SESSION_DURATION_SECONDS
        ):
            raise ValidationError(
                "Verification session duration must be between "
                f"{MIN_SESSION_DURATION_SECONDS} and {MAX_SESSION_DURATION_SECONDS} seconds"
            )
        session_id = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        session = VerificationSession(
            id=session_id,
            organization_id=organization_id,
            verifier_did=verifier_did,
            presentation_definition=presentation_definition,
            required_credential_types=required_credential_types or [],
            trusted_issuers=trusted_issuers or [],
            nonce=nonce,
            request_uri=f"oid4vp://request?session_id={session_id}",
        )

        return await self.repository.create_session(session, session_duration_seconds)

    async def verify_presentation_direct(
        self,
        organization_id: str,
        presentation: dict[str, Any] | str,
        presentation_definition: dict[str, Any],
        verifier_did: str,
        trusted_issuers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Verify a presentation directly without session (stateless)."""
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
                trusted_issuers=trusted_issuers,
                organization_id=organization_id,
            )
            method = VerificationMethod.W3C_VC

        reduced = reduce_verification_result(result)
        return {
            **reduced,
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
            result = await self.verifier.verify_jwt_vp(
                presentation_jwt=presentation,
                expected_audience=session.verifier_did,
                expected_nonce=claim.verifier_nonce,
            )

            reduced = reduce_verification_result(result)
            evidence = _session_evidence(reduced, method, presentation_digest)
            if reduced["valid"]:
                session.verify(
                    verified_claims=reduced["verified_claims"],
                    method=method,
                    verification_evidence=evidence,
                )
            else:
                session.fail(
                    "Verification failed",
                    method=method,
                    verification_evidence=evidence,
                )

        except Exception:
            session.fail(
                "Verification failed due to verifier error",
                method=method,
                verification_evidence=_session_evidence(
                    {
                        "overall_result": "ERROR",
                        "cryptographic_valid": False,
                        "trust_chain_valid": False,
                        "revocation_checked": False,
                        "revocation_status": "SKIPPED",
                    },
                    method,
                    presentation_digest,
                ),
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
