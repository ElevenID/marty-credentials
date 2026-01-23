"""
Rust Signing Adapter

Adapter that wraps the Rust-based signing infrastructure
(via ssi crate bindings) to satisfy the SigningServicePort.
"""

from __future__ import annotations

import json
import logging
from typing import Optional, Any

from status_list.application.ports.outbound import SigningServicePort

logger = logging.getLogger(__name__)


class RustSigningAdapter:
    """
    Signing adapter using Rust FFI bindings.
    
    This adapter wraps the existing Rust signing infrastructure
    (ssi crate) to provide credential signing with Data Integrity proofs.
    
    The actual Rust bindings are imported from the marty_verification
    module which provides the FFI interface.
    
    Attributes:
        _issuer_registry: Registry mapping issuer IDs to DIDs/keys
        _default_proof_type: Default proof type for signing
    """
    
    def __init__(
        self,
        issuer_registry: Optional[dict[str, dict]] = None,
        default_proof_type: str = "DataIntegrityProof",
        default_cryptosuite: str = "eddsa-rdfc-2022",
    ) -> None:
        """
        Initialize the adapter.
        
        Args:
            issuer_registry: Optional mapping of issuer IDs to DID/key info
            default_proof_type: Default proof type
            default_cryptosuite: Default cryptographic suite
        """
        self._issuer_registry = issuer_registry or {}
        self._default_proof_type = default_proof_type
        self._default_cryptosuite = default_cryptosuite
        self._rust_available = self._check_rust_bindings()
    
    def _check_rust_bindings(self) -> bool:
        """Check if Rust bindings are available."""
        try:
            # Try to import the Rust bindings
            # This would be the actual FFI module in production
            from marty_verification import sign_vc  # type: ignore
            return True
        except ImportError:
            logger.warning(
                "Rust signing bindings not available, using fallback"
            )
            return False
    
    async def sign_credential(
        self,
        credential: dict,
        issuer_id: str,
        key_id: Optional[str] = None,
    ) -> dict:
        """
        Sign a verifiable credential.
        
        Uses the Rust ssi crate to add a Data Integrity proof
        to the credential.
        
        Args:
            credential: The unsigned credential
            issuer_id: ID of the issuer
            key_id: Optional specific key to use
            
        Returns:
            The signed credential with proof
        """
        if self._rust_available:
            return await self._sign_with_rust(credential, issuer_id, key_id)
        else:
            return await self._sign_fallback(credential, issuer_id, key_id)
    
    async def _sign_with_rust(
        self,
        credential: dict,
        issuer_id: str,
        key_id: Optional[str] = None,
    ) -> dict:
        """Sign using Rust FFI bindings."""
        try:
            from marty_verification import sign_vc  # type: ignore
            
            # Get the verification method
            verification_method = await self.get_verification_method(issuer_id, key_id)
            
            # Get the private key material
            issuer_info = self._issuer_registry.get(issuer_id, {})
            private_key = issuer_info.get("private_key")
            
            if not private_key:
                raise ValueError(f"No private key found for issuer {issuer_id}")
            
            # Call Rust signing function
            credential_json = json.dumps(credential)
            signed_json = sign_vc(
                credential_json,
                private_key,
                verification_method,
                self._default_cryptosuite,
            )
            
            return json.loads(signed_json)
            
        except Exception as e:
            logger.error("Rust signing failed: %s", e)
            raise
    
    async def _sign_fallback(
        self,
        credential: dict,
        issuer_id: str,
        key_id: Optional[str] = None,
    ) -> dict:
        """
        Fallback signing when Rust bindings unavailable.
        
        This creates a placeholder proof structure for testing.
        In production, the Rust bindings should always be available.
        """
        from datetime import datetime, timezone
        
        verification_method = await self.get_verification_method(issuer_id, key_id)
        
        # Create a placeholder proof (NOT for production use)
        proof = {
            "type": self._default_proof_type,
            "cryptosuite": self._default_cryptosuite,
            "created": datetime.now(timezone.utc).isoformat(),
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod",
            "proofValue": "PLACEHOLDER_PROOF_VALUE_USE_RUST_BINDINGS",
        }
        
        signed = credential.copy()
        signed["proof"] = proof
        
        logger.warning(
            "Using fallback signing for issuer %s - NOT FOR PRODUCTION",
            issuer_id,
        )
        
        return signed
    
    async def get_issuer_did(self, issuer_id: str) -> str:
        """
        Get the DID for an issuer.
        
        Args:
            issuer_id: ID of the issuer
            
        Returns:
            The issuer's DID
        """
        issuer_info = self._issuer_registry.get(issuer_id)
        
        if issuer_info and "did" in issuer_info:
            return issuer_info["did"]
        
        # Default to a did:web based on issuer ID
        return f"did:web:{issuer_id}"
    
    async def get_verification_method(
        self,
        issuer_id: str,
        key_id: Optional[str] = None,
    ) -> str:
        """
        Get the verification method URI for signing.
        
        Args:
            issuer_id: ID of the issuer
            key_id: Optional specific key
            
        Returns:
            Verification method URI
        """
        issuer_did = await self.get_issuer_did(issuer_id)
        
        if key_id:
            return f"{issuer_did}#{key_id}"
        
        # Check if issuer has a default key
        issuer_info = self._issuer_registry.get(issuer_id, {})
        default_key = issuer_info.get("default_key_id", "key-1")
        
        return f"{issuer_did}#{default_key}"
    
    def register_issuer(
        self,
        issuer_id: str,
        did: str,
        private_key: Any,
        default_key_id: str = "key-1",
    ) -> None:
        """
        Register an issuer with their DID and key material.
        
        Args:
            issuer_id: ID of the issuer
            did: The issuer's DID
            private_key: Private key material
            default_key_id: Default key ID for the verification method
        """
        self._issuer_registry[issuer_id] = {
            "did": did,
            "private_key": private_key,
            "default_key_id": default_key_id,
        }
        logger.info("Registered issuer %s with DID %s", issuer_id, did)
