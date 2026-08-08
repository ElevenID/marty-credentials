"""Application service for verification."""

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from mmf.core.exceptions import ValidationError

from ..domain.entities import VerificationMethod, VerificationSession, VerificationStatus
from ..domain.ports import ICredentialVerifier, IVerificationRepository


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
            expires_at=datetime.utcnow() + timedelta(seconds=session_duration_seconds),
            request_uri=f"oid4vp://request?session_id={session_id}",
        )

        await self.repository.save_session(session)
        return session

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
        """Submit a presentation to an existing session."""
        session = await self.repository.get_by_id(session_id)
        if not session:
            raise ValidationError("Verification session not found")

        if session.is_expired():
            session.expire()
            await self.repository.save_session(session)
            raise ValidationError("Verification session has expired")

        if session.status != VerificationStatus.PENDING:
            raise ValidationError(f"Session is not in pending state: {session.status}")

        # Mark as in progress
        session.status = VerificationStatus.IN_PROGRESS
        await self.repository.save_session(session)

        method = (
            VerificationMethod.JWT_VP
            if isinstance(presentation, str)
            else VerificationMethod.W3C_VC
        )
        presentation_digest = _presentation_sha256(presentation)

        try:
            # Verify the presentation
            if isinstance(presentation, str):
                # JWT VP
                result = await self.verifier.verify_jwt_vp(
                    presentation_jwt=presentation,
                    expected_audience=session.verifier_did,
                    expected_nonce=session.nonce,
                )
            else:
                # Structured presentation
                result = await self.verifier.verify_presentation(
                    presentation=presentation,
                    presentation_definition=session.presentation_definition,
                    verifier_did=session.verifier_did,
                    trusted_issuers=session.trusted_issuers,
                    organization_id=session.organization_id,
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

        await self.repository.save_session(session)
        return session

    async def get_session(self, session_id: str) -> VerificationSession | None:
        """Retrieve a verification session."""
        return await self.repository.get_by_id(session_id)

    async def list_sessions(
        self, organization_id: str, limit: int = 100, offset: int = 0
    ) -> list[VerificationSession]:
        """List verification sessions for an organization."""
        return await self.repository.list_by_organization(organization_id, limit, offset)
