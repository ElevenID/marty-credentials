"""
Credential Issuer Port

Interface for credential issuance operations (issuer role in OID4VCI).
"""

from typing import Any, Protocol, runtime_checkable

from marty_credentials.ports.types import (
    CredentialData,
    CredentialOffer,
    CredentialSubject,
    KeyPair,
)


@runtime_checkable
class ICredentialIssuer(Protocol):
    """Interface for credential issuance (issuer role in OID4VCI)."""

    def create_credential(
        self,
        issuer_key: KeyPair,
        credential_type: str,
        subject: CredentialSubject,
        expiration_seconds: int | None = None,
    ) -> CredentialData:
        """
        Create and sign a verifiable credential.

        Args:
            issuer_key: Key pair for signing
            credential_type: Type of credential (e.g., "UniversityDegreeCredential")
            subject: Subject and claims for the credential
            expiration_seconds: Credential validity period in seconds (optional)

        Returns:
            Created credential with signed JWT
        """
        ...

    def create_offer(
        self,
        issuer_url: str,
        credential_types: list[str],
        pre_authorized: bool = True,
        user_pin_required: bool = False,
        wallet_format: str = "standard",
    ) -> CredentialOffer:
        """
        Create an OID4VCI credential offer.

        Args:
            issuer_url: Base URL of the issuer
            credential_types: Types of credentials to offer
            pre_authorized: Use pre-authorized code flow
            user_pin_required: Require user PIN for redemption
            wallet_format: Target wallet format ("standard" or "microsoft")

        Returns:
            Credential offer with URI for QR code display
        """
        ...

    def generate_issuer_metadata(
        self,
        issuer_url: str,
        issuer_name: str,
        supported_credentials: list[dict[str, Any]],
    ) -> str:
        """
        Generate OID4VCI issuer metadata for discovery.

        Args:
            issuer_url: Base URL of the issuer
            issuer_name: Display name of the issuer
            supported_credentials: List of supported credential configurations

        Returns:
            JSON string of issuer metadata
        """
        ...
