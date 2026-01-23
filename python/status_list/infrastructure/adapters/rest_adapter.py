"""
REST API Adapter for Status List

FastAPI router providing HTTP endpoints for status list operations.
This is an inbound adapter that handles HTTP requests and delegates
to the application services.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from status_list.domain.value_objects import StatusPurpose, ShardConfig
from status_list.application.services.status_list_service import StatusListService
from status_list.application.services.credential_status_service import CredentialStatusService
from status_list.application.services.status_list_credential_service import StatusListCredentialService

logger = logging.getLogger(__name__)


# Request/Response Models
class CreateStatusListRequest(BaseModel):
    """Request to create a new status list."""
    
    issuer_id: str = Field(..., description="ID of the issuer")
    purpose: str = Field(..., description="Status purpose: 'revocation' or 'suspension'")
    shard_size_bits: Optional[int] = Field(
        None,
        description="Shard size in bits (minimum 131072)",
        ge=131072,
    )
    cache_ttl_seconds: Optional[int] = Field(
        None,
        description="Cache TTL in seconds",
        ge=0,
    )


class UpdateStatusRequest(BaseModel):
    """Request to update a credential's status."""
    
    status: int = Field(..., description="New status value (0=valid, 1=invalid)", ge=0, le=1)
    reason: Optional[str] = Field(None, description="Reason for status change")


class RevokeCredentialRequest(BaseModel):
    """Request to revoke a credential."""
    
    reason: Optional[str] = Field(None, description="Revocation reason")


class SuspendCredentialRequest(BaseModel):
    """Request to suspend a credential."""
    
    reason: Optional[str] = Field(None, description="Suspension reason")


class CredentialStatusResponse(BaseModel):
    """Response with credential status."""
    
    credential_id: str
    revoked: Optional[bool] = None
    suspended: Optional[bool] = None


class StatusListRouter:
    """
    FastAPI router for status list endpoints.
    
    This adapter handles HTTP requests and delegates to the
    appropriate application services.
    
    Endpoints:
        GET /v3/status/{issuer_id}/{purpose}/{shard_index}
            - Returns signed BitstringStatusListCredential
        
        POST /v3/status/lists
            - Create a new status list
        
        GET /v3/status/credentials/{credential_id}
            - Get status of a credential
        
        POST /v3/status/credentials/{credential_id}/revoke
            - Revoke a credential
        
        POST /v3/status/credentials/{credential_id}/suspend
            - Suspend a credential
        
        POST /v3/status/credentials/{credential_id}/unsuspend
            - Unsuspend a credential
    
    Attributes:
        router: FastAPI APIRouter instance
        _status_list_service: Core status list service
        _credential_status_service: Credential status service
        _status_list_credential_service: Status list credential service
        _config: Shard configuration
    """
    
    def __init__(
        self,
        status_list_service: StatusListService,
        credential_status_service: CredentialStatusService,
        status_list_credential_service: StatusListCredentialService,
        config: Optional[ShardConfig] = None,
    ) -> None:
        """
        Initialize the router.
        
        Args:
            status_list_service: Core status list service
            credential_status_service: Credential status service
            status_list_credential_service: Status list credential service
            config: Optional shard configuration
        """
        self._status_list_service = status_list_service
        self._credential_status_service = credential_status_service
        self._status_list_credential_service = status_list_credential_service
        self._config = config or ShardConfig()
        
        self.router = APIRouter(prefix="/v3/status", tags=["Status List"])
        self._register_routes()
    
    def _register_routes(self) -> None:
        """Register all routes on the router."""
        
        # Public endpoint for verifiers to fetch status list credentials
        @self.router.get(
            "/{issuer_id}/{purpose}/{shard_index}",
            response_class=JSONResponse,
            summary="Get Status List Credential",
            description="Returns a signed BitstringStatusListCredential for verifiers",
        )
        async def get_status_list_credential(
            issuer_id: str,
            purpose: str,
            shard_index: int,
        ) -> Response:
            """Get a signed status list credential."""
            try:
                status_purpose = StatusPurpose(purpose)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid purpose: {purpose}. Must be 'revocation' or 'suspension'",
                )
            
            credential = await self._status_list_credential_service.get_published_credential(
                issuer_id=issuer_id,
                purpose=status_purpose,
                shard_index=shard_index,
            )
            
            if credential is None:
                raise HTTPException(
                    status_code=404,
                    detail="Status list not found",
                )
            
            # Set cache headers per configuration
            headers = {
                "Cache-Control": f"public, max-age={self._config.cache_ttl_seconds}",
                "Content-Type": "application/vc+ld+json",
            }
            
            return JSONResponse(
                content=credential,
                headers=headers,
            )
        
        # Admin endpoint to create status lists
        @self.router.post(
            "/lists",
            summary="Create Status List",
            description="Create a new status list for an issuer",
        )
        async def create_status_list(
            request: CreateStatusListRequest,
        ) -> dict:
            """Create a new status list."""
            try:
                purpose = StatusPurpose(request.purpose)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid purpose: {request.purpose}",
                )
            
            config = None
            if request.shard_size_bits or request.cache_ttl_seconds:
                config = ShardConfig(
                    size_bits=request.shard_size_bits or 131072,
                    cache_ttl_seconds=request.cache_ttl_seconds or 300,
                )
            
            try:
                status_list = await self._status_list_service.create_status_list(
                    issuer_id=request.issuer_id,
                    purpose=purpose,
                    config=config,
                )
            except ValueError as e:
                raise HTTPException(status_code=409, detail=str(e))
            
            return {
                "id": status_list.id,
                "issuer_id": status_list.issuer_id,
                "purpose": str(status_list.purpose),
                "created_at": status_list.created_at.isoformat(),
            }
        
        # Get credential status
        @self.router.get(
            "/credentials/{credential_id}",
            response_model=CredentialStatusResponse,
            summary="Get Credential Status",
            description="Get the revocation and suspension status of a credential",
        )
        async def get_credential_status(
            credential_id: str,
        ) -> CredentialStatusResponse:
            """Get credential status."""
            status = await self._credential_status_service.get_credential_status(
                credential_id
            )
            
            return CredentialStatusResponse(
                credential_id=credential_id,
                revoked=status.get("revoked"),
                suspended=status.get("suspended"),
            )
        
        # Revoke credential
        @self.router.post(
            "/credentials/{credential_id}/revoke",
            summary="Revoke Credential",
            description="Permanently revoke a credential",
        )
        async def revoke_credential(
            credential_id: str,
            request: RevokeCredentialRequest,
        ) -> dict:
            """Revoke a credential."""
            success = await self._credential_status_service.revoke_credential(
                credential_id=credential_id,
                reason=request.reason,
            )
            
            if not success:
                raise HTTPException(
                    status_code=404,
                    detail="Credential not found or has no status entry",
                )
            
            return {
                "credential_id": credential_id,
                "status": "revoked",
                "reason": request.reason,
            }
        
        # Suspend credential
        @self.router.post(
            "/credentials/{credential_id}/suspend",
            summary="Suspend Credential",
            description="Temporarily suspend a credential",
        )
        async def suspend_credential(
            credential_id: str,
            request: SuspendCredentialRequest,
        ) -> dict:
            """Suspend a credential."""
            success = await self._credential_status_service.suspend_credential(
                credential_id=credential_id,
                reason=request.reason,
            )
            
            if not success:
                raise HTTPException(
                    status_code=404,
                    detail="Credential not found or has no suspension status entry",
                )
            
            return {
                "credential_id": credential_id,
                "status": "suspended",
                "reason": request.reason,
            }
        
        # Unsuspend credential
        @self.router.post(
            "/credentials/{credential_id}/unsuspend",
            summary="Unsuspend Credential",
            description="Lift suspension from a credential",
        )
        async def unsuspend_credential(
            credential_id: str,
        ) -> dict:
            """Unsuspend a credential."""
            success = await self._credential_status_service.unsuspend_credential(
                credential_id=credential_id,
            )
            
            if not success:
                raise HTTPException(
                    status_code=404,
                    detail="Credential not found or has no suspension status entry",
                )
            
            return {
                "credential_id": credential_id,
                "status": "active",
            }
        
        # Health check
        @self.router.get(
            "/health",
            summary="Health Check",
            description="Status list service health check",
        )
        async def health_check() -> dict:
            """Health check endpoint."""
            return {
                "status": "healthy",
                "service": "status-list",
            }


def create_status_list_router(
    status_list_service: StatusListService,
    credential_status_service: CredentialStatusService,
    status_list_credential_service: StatusListCredentialService,
    config: Optional[ShardConfig] = None,
) -> APIRouter:
    """
    Factory function to create a configured status list router.
    
    Args:
        status_list_service: Core status list service
        credential_status_service: Credential status service
        status_list_credential_service: Status list credential service
        config: Optional shard configuration
        
    Returns:
        Configured FastAPI APIRouter
    """
    router_instance = StatusListRouter(
        status_list_service=status_list_service,
        credential_status_service=credential_status_service,
        status_list_credential_service=status_list_credential_service,
        config=config,
    )
    return router_instance.router
