"""
Credential Verifier Port

Interface for credential verification operations (verifier role in OID4VCI/OID4VP).
"""

from typing import Protocol, runtime_checkable

from marty_credentials.ports.types import PresentationRequest, VerificationResult, ZkChallengeSession


@runtime_checkable
class ICredentialVerifier(Protocol):
    """Interface for credential verification (verifier role in OID4VCI/OID4VP)."""

    def verify_credential(
        self,
        credential_jwt: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult:
        """
        Verify a credential JWT.

        Args:
            credential_jwt: Credential JWT to verify
            expected_issuer: Expected issuer DID (optional)

        Returns:
            Verification result with claims if valid
        """
        ...

    def verify_presentation(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None,
    ) -> VerificationResult:
        """
        Verify a presentation JWT.

        Args:
            presentation_jwt: Presentation JWT to verify
            expected_audience: Expected audience (verifier)
            expected_nonce: Expected nonce if provided in request

        Returns:
            Verification result with claims if valid
        """
        ...

    def create_presentation_request(
        self,
        verifier_id: str,
        requested_credentials: list[str],
    ) -> PresentationRequest:
        """
        Create a presentation request for OID4VP.

        Args:
            verifier_id: Identifier for the verifier
            requested_credentials: Types of credentials requested

        Returns:
            Presentation request with nonce
        """
        ...

    # ZK Proof Methods (Longfellow/LibZK integration)
    
    def create_zk_challenge(
        self,
        doctype: str,
        verifier_id: str | None = None,
    ) -> ZkChallengeSession:
        """
        Create a ZK proof challenge session.

        Args:
            doctype: mDoc document type (e.g., 'org.iso.18013.5.1.mDL')
            verifier_id: Optional verifier identifier

        Returns:
            Challenge session with nonce and expiry
        """
        ...

    def verify_zk_proof(
        self,
        session_id: str,
        proof: bytes,
        mso: bytes,
    ) -> VerificationResult:
        """
        Verify a ZK proof against a challenge session.

        Args:
            session_id: Challenge session ID from create_zk_challenge
            proof: ZK proof bytes (Ligero proof)
            mso: Mobile Security Object bytes

        Returns:
            Verification result with verification_method='zk_ligero'
        """
        ...
