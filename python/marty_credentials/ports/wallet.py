"""
Credential Wallet Port

Interface for credential wallet operations (holder role in OID4VCI).
"""

from typing import Protocol, runtime_checkable

from marty_credentials.ports.types import CredentialData, KeyPair


@runtime_checkable
class ICredentialWallet(Protocol):
    """Interface for credential wallet operations (holder role in OID4VCI)."""

    def store_credential(self, credential: CredentialData) -> str:
        """
        Store a credential in the wallet.

        Args:
            credential: Credential to store

        Returns:
            Storage identifier for the credential
        """
        ...

    def get_credential(self, credential_id: str) -> CredentialData | None:
        """
        Retrieve a stored credential.

        Args:
            credential_id: Identifier of the credential

        Returns:
            The credential if found, None otherwise
        """
        ...

    def list_credentials(self, credential_type: str | None = None) -> list[CredentialData]:
        """
        List stored credentials.

        Args:
            credential_type: Filter by type (optional)

        Returns:
            List of matching credentials
        """
        ...

    def delete_credential(self, credential_id: str) -> bool:
        """
        Delete a stored credential.

        Args:
            credential_id: Identifier of the credential

        Returns:
            True if the credential was deleted, False if not found
        """
        ...

    def create_presentation(
        self,
        holder_key: KeyPair,
        credentials: list[CredentialData],
        audience: str,
        nonce: str | None = None,
    ) -> str:
        """
        Create a verifiable presentation.

        Args:
            holder_key: Holder's key for signing
            credentials: Credentials to include
            audience: Verifier identifier
            nonce: Cryptographic nonce (optional)

        Returns:
            Signed presentation JWT
        """
        ...

    def redeem_offer(self, offer_uri: str, holder_key: KeyPair) -> CredentialData:
        """
        Redeem a credential offer from an issuer.

        Args:
            offer_uri: URI from the credential offer
            holder_key: Holder's key for binding

        Returns:
            Received credential
        """
        ...
