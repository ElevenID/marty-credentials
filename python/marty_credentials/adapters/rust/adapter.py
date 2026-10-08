"""
Rust Adapter Implementation

Credential adapters using marty-rs Rust library via PyO3 bindings.
Provides high-performance OID4VCI/OID4VP operations.
"""

import secrets
from uuid import uuid4

from marty_credentials.native_backend import (
    NativeOperationError,
)
from marty_credentials.ports import (
    CredentialData,
    PresentationRequest,
    VerificationResult,
)


class RustCredentialWallet:
    """Credential wallet implementation using marty-rs Rust library."""

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

    def delete_credential(self, credential_id: str) -> bool:
        """Delete a stored credential."""
        if credential_id in self._credentials:
            del self._credentials[credential_id]
            return True
        return False

class RustCredentialVerifier:
    """Credential verifier implementation using marty-rs Rust library."""

    def verify_credential(
        self,
        credential_jwt: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult:
        """Verify a credential JWT using Rust."""
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
        """Verify a presentation JWT using Rust."""
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


# Singleton instances
_wallet: RustCredentialWallet | None = None
_verifier: RustCredentialVerifier | None = None


def get_wallet() -> RustCredentialWallet:
    """Get or create the wallet singleton."""
    global _wallet
    if _wallet is None:
        _wallet = RustCredentialWallet()
    return _wallet


def get_verifier() -> RustCredentialVerifier:
    """Get or create the verifier singleton."""
    global _verifier
    if _verifier is None:
        _verifier = RustCredentialVerifier()
    return _verifier
