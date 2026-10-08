"""
SpruceID Adapter

Wallet and verifier helpers for the credential ports. Issuer signing is owned
by the remote-KMS-backed native service.
"""

import secrets
from uuid import uuid4

from marty_credentials.native_backend import NativeOperationError
from marty_credentials.ports.credential_ports import (
    CredentialData,
    PresentationRequest,
    VerificationResult,
)


class SpruceIDCredentialWallet:
    """In-memory wallet helper for the credential port."""

    def __init__(self) -> None:
        self._credentials: dict[str, CredentialData] = {}

    def store_credential(self, credential: CredentialData) -> str:
        """Store a credential in the wallet."""
        self._credentials[credential.id] = credential
        return credential.id

    def get_credential(self, credential_id: str) -> CredentialData | None:
        """Retrieve a stored credential."""
        return self._credentials.get(credential_id)

    def list_credentials(self, credential_type: str | None = None) -> list[CredentialData]:
        """List stored credentials."""
        if credential_type is None:
            return list(self._credentials.values())
        return [c for c in self._credentials.values() if credential_type in c.types]


class SpruceIDCredentialVerifier:
    """Verifier helper for the credential port."""

    def verify_credential(
        self,
        credential_jwt: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult:
        """Verify a credential JWT."""
        raise NativeOperationError(
            "Credential verification requires explicit issuer public key or trust-profile "
            "input; use VerificationService.verify_w3c_vc"
        )

    def verify_presentation(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None,
    ) -> VerificationResult:
        """Verify a presentation JWT."""
        raise NativeOperationError(
            "Presentation verification requires verifier-owned OID4VP request state; "
            "use the canonical OID4VP verifier flow"
        )

    def create_presentation_request(
        self,
        verifier_id: str,
        requested_credentials: list[str],
    ) -> PresentationRequest:
        """Create a presentation request for OID4VP."""
        return PresentationRequest(
            request_id=str(uuid4()),
            verifier=verifier_id,
            requested_credentials=requested_credentials,
            nonce=secrets.token_urlsafe(16),
            audience=verifier_id,
        )


# Singleton instances for wallet and verifier adapters
_wallet: SpruceIDCredentialWallet | None = None
_verifier: SpruceIDCredentialVerifier | None = None


def get_wallet() -> SpruceIDCredentialWallet:
    """Get or create the wallet singleton."""
    global _wallet
    if _wallet is None:
        _wallet = SpruceIDCredentialWallet()
    return _wallet


def get_verifier() -> SpruceIDCredentialVerifier:
    """Get or create the verifier singleton."""
    global _verifier
    if _verifier is None:
        _verifier = SpruceIDCredentialVerifier()
    return _verifier
