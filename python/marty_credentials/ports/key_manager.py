"""
Key Manager Port

Interface for cryptographic key management operations.
"""

from typing import Protocol, runtime_checkable

from marty_credentials.ports.types import KeyAlgorithm, KeyPair


@runtime_checkable
class IKeyManager(Protocol):
    """Interface for cryptographic key management."""

    def generate_key(self, algorithm: KeyAlgorithm = KeyAlgorithm.ES256) -> KeyPair:
        """
        Generate a new key pair.

        Args:
            algorithm: Key algorithm to use (default: ES256 for P-256 curve)

        Returns:
            Generated key pair with DID and JWK
        """
        ...

    def store_key(self, key_id: str, key_pair: KeyPair) -> None:
        """
        Store a key pair securely.

        Args:
            key_id: Identifier for the key
            key_pair: Key pair to store
        """
        ...

    def get_key(self, key_id: str) -> KeyPair | None:
        """
        Retrieve a stored key pair.

        Args:
            key_id: Identifier for the key

        Returns:
            The key pair if found, None otherwise
        """
        ...

    def list_keys(self) -> list[str]:
        """
        List all stored key identifiers.

        Returns:
            List of key identifiers
        """
        ...

    def delete_key(self, key_id: str) -> bool:
        """
        Delete a stored key pair.

        Args:
            key_id: Identifier for the key

        Returns:
            True if the key was deleted, False if not found
        """
        ...
