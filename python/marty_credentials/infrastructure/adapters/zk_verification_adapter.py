"""
ZK Verification REST Adapter

FastAPI router providing HTTP endpoints for interactive ZK proof verification.
Follows the status_list plugin router pattern.
"""

import logging
import base64
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime

from marty_credentials.ports.verifier import ICredentialVerifier

logger = logging.getLogger(__name__)


# Request/Response Models
class ZkChallengeRequest(BaseModel):
    """Request to initiate a ZK proof challenge."""
    doctype: str = Field(..., description="mDoc document type (e.g., 'org.iso.18013.5.1.mDL')")
    verifier_id: Optional[str] = Field(None, description="Identifier for the verifier")


class ZkChallengeResponse(BaseModel):
    """Response with ZK proof challenge."""
    session_id: str = Field(..., description="Unique session identifier")
    nonce: str = Field(..., description="Base64 encoded cryptographic nonce")
    expires_at: datetime = Field(..., description="When the challenge expires")


class ZkVerifyRequest(BaseModel):
    """Request to verify a ZK proof."""
    session_id: str = Field(..., description="Session identifier from challenge")
    proof: str = Field(..., description="Base64 encoded ZK proof (Ligero)")
    mso: str = Field(..., description="Base64 encoded Mobile Security Object (MSO)")


class ZkVerifyResponse(BaseModel):
    """Response with verification result."""
    valid: bool = Field(..., description="Whether the proof is valid")
    verification_method: str = Field("zk_ligero", description="Verification method used")
    claims: dict = Field(default_factory=dict, description="Extracted claims/assertions")
    error: Optional[str] = Field(None, description="Error message if verification failed")


class ZkVerificationRouter:
    """
    FastAPI router for ZK verification endpoints.
    
    Endpoints:
        POST /api/verify/zkp/challenge
            - Create a new ZK challenge session
        
        POST /api/verify/zkp/verify
            - Verify a ZK proof against a session
    """

    def __init__(self, verifier_service: ICredentialVerifier):
        self._verifier = verifier_service
        self.router = APIRouter(prefix="/api/verify/zkp", tags=["ZK Verification"])
        self._register_routes()

    def _register_routes(self):
        """Register routes on the router."""

        @self.router.post(
            "/challenge",
            response_model=ZkChallengeResponse,
            summary="Create ZK Challenge",
            description="Initiate an interactive ZK proof session and get a nonce."
        )
        async def create_challenge(request: ZkChallengeRequest):
            try:
                session = self._verifier.create_zk_challenge(
                    doctype=request.doctype,
                    verifier_id=request.verifier_id
                )
                
                return ZkChallengeResponse(
                    session_id=session.session_id,
                    nonce=base64.b64encode(session.nonce).decode('utf-8'),
                    expires_at=session.expires_at
                )
            except Exception as e:
                logger.error(f"Failed to create ZK challenge: {e}")
                raise HTTPException(status_code=500, detail="Failed to create ZK challenge")

        @self.router.post(
            "/verify",
            response_model=ZkVerifyResponse,
            summary="Verify ZK Proof",
            description="Submit a ZK proof and MSO for verification against a session."
        )
        async def verify_proof(request: ZkVerifyRequest):
            try:
                # Decode base64 inputs
                try:
                    proof_bytes = base64.b64decode(request.proof)
                    mso_bytes = base64.b64decode(request.mso)
                except (ValueError, Exception) as exc:
                    raise HTTPException(status_code=400, detail="Invalid base64 encoding in proof or mso")
                
                result = self._verifier.verify_zk_proof(
                    session_id=request.session_id,
                    proof=proof_bytes,
                    mso=mso_bytes
                )
                
                return ZkVerifyResponse(
                    valid=result.valid,
                    verification_method=result.verification_method or "zk_ligero",
                    claims=result.claims,
                    error=result.error
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"ZK verification endpoint error: {e}")
                raise HTTPException(status_code=500, detail="ZK verification failed")


def create_zk_verification_router(verifier_service: ICredentialVerifier) -> APIRouter:
    """Factory function to create the ZK verification router."""
    return ZkVerificationRouter(verifier_service).router
