"""
Credential Status Service - Application Service

High-level service for credential status operations used during
credential issuance and lifecycle management.

This service coordinates between the StatusListService and
provides a simplified API for:
- Allocating status entries during issuance
- Revoking credentials
- Suspending/unsuspending credentials
- Checking credential status
"""

from __future__ import annotations

import logging
from typing import Optional

from status_list.domain.value_objects import (
    StatusPurpose,
    BitstringStatusListEntry,
    StatusCode,
)
from status_list.application.services.status_list_service import StatusListService

logger = logging.getLogger(__name__)


class CredentialStatusService:
    """
    Application service for credential status operations.
    
    Provides a high-level API for managing credential status
    during issuance and throughout the credential lifecycle.
    
    This service is designed to be injected into credential
    issuance flows (e.g., Open Badge v3 issuance).
    
    Attributes:
        _status_list_service: Core status list service
        _base_url: Base URL for status list endpoints
    """
    
    def __init__(
        self,
        status_list_service: StatusListService,
        base_url: str,
    ) -> None:
        """
        Initialize the service.
        
        Args:
            status_list_service: Core status list service
            base_url: Base URL for status list endpoints
        """
        self._status_list_service = status_list_service
        self._base_url = base_url.rstrip("/")
    
    async def allocate_credential_status(
        self,
        credential_id: str,
        issuer_id: str,
        include_revocation: bool = True,
        include_suspension: bool = True,
    ) -> list[BitstringStatusListEntry]:
        """
        Allocate status entries for a credential.
        
        This allocates indices in both revocation and suspension
        status lists (if enabled) and returns the credentialStatus
        entries to embed in the credential.
        
        Per W3C Bitstring Status List v1.0, a credential can have
        multiple status entries for different purposes.
        
        Args:
            credential_id: ID of the credential being issued
            issuer_id: ID of the issuer
            include_revocation: Whether to include revocation status
            include_suspension: Whether to include suspension status
            
        Returns:
            List of BitstringStatusListEntry objects to embed
        """
        entries: list[BitstringStatusListEntry] = []
        
        if include_revocation:
            revocation_entry = await self._status_list_service.allocate_status_entry(
                credential_id=credential_id,
                issuer_id=issuer_id,
                purpose=StatusPurpose.REVOCATION,
            )
            entries.append(
                revocation_entry.to_status_list_entry(self._base_url)
            )
            logger.debug(
                "Allocated revocation entry for credential %s at shard %d index %d",
                credential_id,
                revocation_entry.shard_index,
                revocation_entry.bit_index,
            )
        
        if include_suspension:
            suspension_entry = await self._status_list_service.allocate_status_entry(
                credential_id=credential_id,
                issuer_id=issuer_id,
                purpose=StatusPurpose.SUSPENSION,
            )
            entries.append(
                suspension_entry.to_status_list_entry(self._base_url)
            )
            logger.debug(
                "Allocated suspension entry for credential %s at shard %d index %d",
                credential_id,
                suspension_entry.shard_index,
                suspension_entry.bit_index,
            )
        
        return entries
    
    def build_credential_status_field(
        self,
        entries: list[BitstringStatusListEntry],
    ) -> list[dict] | dict:
        """
        Build the credentialStatus field for a credential.
        
        Per spec, if there's only one entry, it can be an object.
        If multiple entries, it should be an array.
        
        Args:
            entries: List of status list entries
            
        Returns:
            credentialStatus field value (object or array)
        """
        if not entries:
            return []
        
        dicts = [entry.to_dict() for entry in entries]
        
        # Single entry can be an object per spec
        if len(dicts) == 1:
            return dicts[0]
        
        return dicts
    
    async def revoke_credential(
        self,
        credential_id: str,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Revoke a credential.
        
        Sets the revocation status bit to 1 (invalid).
        This is permanent - revocation cannot be undone.
        
        Args:
            credential_id: ID of the credential to revoke
            reason: Optional revocation reason
            
        Returns:
            True if revoked, False if credential not found
        """
        result = await self._status_list_service.update_status(
            credential_id=credential_id,
            purpose=StatusPurpose.REVOCATION,
            status=StatusCode.INVALID,
            reason=reason,
        )
        
        if result:
            logger.info(
                "Revoked credential %s (reason: %s)",
                credential_id,
                reason or "not specified",
            )
        
        return result
    
    async def suspend_credential(
        self,
        credential_id: str,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Suspend a credential.
        
        Sets the suspension status bit to 1 (suspended).
        This can be reversed by calling unsuspend_credential.
        
        Args:
            credential_id: ID of the credential to suspend
            reason: Optional suspension reason
            
        Returns:
            True if suspended, False if credential not found
        """
        result = await self._status_list_service.update_status(
            credential_id=credential_id,
            purpose=StatusPurpose.SUSPENSION,
            status=StatusCode.INVALID,
            reason=reason,
        )
        
        if result:
            logger.info(
                "Suspended credential %s (reason: %s)",
                credential_id,
                reason or "not specified",
            )
        
        return result
    
    async def unsuspend_credential(
        self,
        credential_id: str,
    ) -> bool:
        """
        Lift suspension from a credential.
        
        Sets the suspension status bit back to 0 (valid).
        
        Args:
            credential_id: ID of the credential to unsuspend
            
        Returns:
            True if unsuspended, False if credential not found
        """
        result = await self._status_list_service.update_status(
            credential_id=credential_id,
            purpose=StatusPurpose.SUSPENSION,
            status=StatusCode.VALID,
            reason="Suspension lifted",
        )
        
        if result:
            logger.info("Unsuspended credential %s", credential_id)
        
        return result
    
    async def is_revoked(self, credential_id: str) -> Optional[bool]:
        """
        Check if a credential is revoked.
        
        Args:
            credential_id: ID of the credential
            
        Returns:
            True if revoked, False if valid, None if no status entry
        """
        status = await self._status_list_service.check_status(
            credential_id=credential_id,
            purpose=StatusPurpose.REVOCATION,
        )
        
        if status is None:
            return None
        
        return status == StatusCode.INVALID
    
    async def is_suspended(self, credential_id: str) -> Optional[bool]:
        """
        Check if a credential is suspended.
        
        Args:
            credential_id: ID of the credential
            
        Returns:
            True if suspended, False if active, None if no status entry
        """
        status = await self._status_list_service.check_status(
            credential_id=credential_id,
            purpose=StatusPurpose.SUSPENSION,
        )
        
        if status is None:
            return None
        
        return status == StatusCode.INVALID
    
    async def get_credential_status(
        self,
        credential_id: str,
    ) -> dict[str, Optional[bool]]:
        """
        Get the full status of a credential.
        
        Args:
            credential_id: ID of the credential
            
        Returns:
            Dict with revoked and suspended status
        """
        return {
            "revoked": await self.is_revoked(credential_id),
            "suspended": await self.is_suspended(credential_id),
        }
