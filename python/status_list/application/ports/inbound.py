"""
Inbound Ports (Driving Ports) for Status List

These protocols define the interface that the application layer
exposes to inbound adapters (REST controllers, gRPC handlers, etc.).
"""

from __future__ import annotations

from typing import Protocol, Optional, runtime_checkable

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import (
    StatusPurpose,
    BitstringStatusListEntry,
    ShardConfig,
)


@runtime_checkable
class StatusListServicePort(Protocol):
    """
    Port for status list management operations.
    
    This is the primary inbound port that driving adapters
    use to interact with the status list functionality.
    """
    
    async def create_status_list(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        config: Optional[ShardConfig] = None,
    ) -> StatusList:
        """
        Create a new status list for an issuer.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            config: Optional shard configuration
            
        Returns:
            The created StatusList
        """
        ...
    
    async def get_status_list(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
    ) -> Optional[StatusList]:
        """
        Get an existing status list.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            
        Returns:
            StatusList if found, None otherwise
        """
        ...
    
    async def get_or_create_status_list(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        config: Optional[ShardConfig] = None,
    ) -> StatusList:
        """
        Get or create a status list for an issuer.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            config: Optional shard configuration (used if creating)
            
        Returns:
            Existing or newly created StatusList
        """
        ...
    
    async def allocate_status_entry(
        self,
        credential_id: str,
        issuer_id: str,
        purpose: StatusPurpose,
    ) -> StatusEntry:
        """
        Allocate a new status entry for a credential.
        
        Args:
            credential_id: ID of the credential
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            
        Returns:
            The allocated StatusEntry
        """
        ...
    
    async def update_status(
        self,
        credential_id: str,
        purpose: StatusPurpose,
        status: int,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Update the status of a credential.
        
        Args:
            credential_id: ID of the credential
            purpose: revocation or suspension
            status: New status value (0=valid, 1=invalid)
            reason: Optional reason for the change
            
        Returns:
            True if status was updated, False if credential not found
        """
        ...
    
    async def check_status(
        self,
        credential_id: str,
        purpose: StatusPurpose,
    ) -> Optional[int]:
        """
        Check the current status of a credential.
        
        Args:
            credential_id: ID of the credential
            purpose: revocation or suspension
            
        Returns:
            Status value if found, None if credential has no status entry
        """
        ...
    
    async def get_shard(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> Optional[Shard]:
        """
        Get a specific shard from a status list.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            Shard if found, None otherwise
        """
        ...


@runtime_checkable
class CredentialStatusServicePort(Protocol):
    """
    Port for credential status operations.
    
    This port is used during credential issuance to allocate
    status entries and generate the credentialStatus field.
    """
    
    async def allocate_credential_status(
        self,
        credential_id: str,
        issuer_id: str,
        base_url: str,
        include_revocation: bool = True,
        include_suspension: bool = True,
    ) -> list[BitstringStatusListEntry]:
        """
        Allocate status entries for a credential.
        
        This allocates indices in both revocation and suspension
        status lists (if enabled) and returns the credentialStatus
        entries to embed in the credential.
        
        Args:
            credential_id: ID of the credential being issued
            issuer_id: ID of the issuer
            base_url: Base URL for status list endpoints
            include_revocation: Whether to include revocation status
            include_suspension: Whether to include suspension status
            
        Returns:
            List of BitstringStatusListEntry objects to embed
        """
        ...
    
    async def revoke_credential(
        self,
        credential_id: str,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Revoke a credential.
        
        Args:
            credential_id: ID of the credential to revoke
            reason: Optional revocation reason
            
        Returns:
            True if revoked, False if credential not found
        """
        ...
    
    async def suspend_credential(
        self,
        credential_id: str,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Suspend a credential.
        
        Args:
            credential_id: ID of the credential to suspend
            reason: Optional suspension reason
            
        Returns:
            True if suspended, False if credential not found
        """
        ...
    
    async def unsuspend_credential(
        self,
        credential_id: str,
    ) -> bool:
        """
        Lift suspension from a credential.
        
        Args:
            credential_id: ID of the credential to unsuspend
            
        Returns:
            True if unsuspended, False if credential not found
        """
        ...
    
    async def is_revoked(self, credential_id: str) -> Optional[bool]:
        """
        Check if a credential is revoked.
        
        Args:
            credential_id: ID of the credential
            
        Returns:
            True if revoked, False if valid, None if no status entry
        """
        ...
    
    async def is_suspended(self, credential_id: str) -> Optional[bool]:
        """
        Check if a credential is suspended.
        
        Args:
            credential_id: ID of the credential
            
        Returns:
            True if suspended, False if active, None if no status entry
        """
        ...


@runtime_checkable
class StatusListCredentialServicePort(Protocol):
    """
    Port for status list credential operations.
    
    Handles generation and publishing of BitstringStatusListCredential
    documents that verifiers fetch to check credential status.
    """
    
    async def generate_status_list_credential(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> dict:
        """
        Generate a signed status list credential.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            Signed BitstringStatusListCredential as dict
        """
        ...
    
    async def publish_status_list_credential(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> str:
        """
        Publish an updated status list credential.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            URL where the credential is published
        """
        ...
    
    async def get_published_credential(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> Optional[dict]:
        """
        Get a previously published status list credential.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            The published credential if found, None otherwise
        """
        ...
