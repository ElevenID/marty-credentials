"""Rust-based credential verification."""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def get_marty_rs():
    """Import and return the marty-rs Python bindings."""
    try:
        import _marty_rs
        return _marty_rs
    except ImportError as e:
        logger.error("marty-rs bindings not available - verification will be limited")
        raise ImportError(
            "marty-rs Python bindings are required for credential verification. "
            "Ensure the marty-bindings crate is built and installed."
        ) from e


class RustCredentialVerifier:
    """Credential verifier using Rust cryptography via PyO3 bindings."""
    
    def __init__(self):
        self.marty_rs = get_marty_rs()
    
    async def verify_w3c_vc(
        self,
        credential: dict[str, Any],
        verifier_did: str,
        trusted_issuers: list[str] | None = None
    ) -> dict[str, Any]:
        """Verify a W3C Verifiable Credential."""
        try:
            # Extract proof and credential data
            proof = credential.get("proof", {})
            if not proof:
                return {"valid": False, "error": "No proof found in credential"}
            
            # Get issuer
            issuer = credential.get("issuer")
            if isinstance(issuer, dict):
                issuer = issuer.get("id")
            
            # Check trusted issuers if provided
            if trusted_issuers and issuer not in trusted_issuers:
                return {"valid": False, "error": f"Issuer {issuer} not trusted"}
            
            # For now, return basic validation
            # TODO: Implement full Rust-based signature verification
            return {
                "valid": True,
                "issuer": issuer,
                "claims": credential.get("credentialSubject", {}),
                "method": "w3c_vc"
            }
            
        except Exception as e:
            logger.error(f"W3C VC verification failed: {e}")
            return {"valid": False, "error": str(e)}
    
    async def verify_jwt_vp(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None
    ) -> dict[str, Any]:
        """Verify a JWT Verifiable Presentation."""
        try:
            # TODO: Add JWT verification via Rust bindings
            # For now, parse JWT payload
            import base64
            parts = presentation_jwt.split(".")
            if len(parts) != 3:
                return {"valid": False, "error": "Invalid JWT format"}
            
            # Decode payload (base64url)
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            
            payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
            
            # Check audience
            aud = payload.get("aud")
            if aud != expected_audience:
                return {"valid": False, "error": f"Audience mismatch: expected {expected_audience}, got {aud}"}
            
            # Check nonce if provided
            if expected_nonce:
                nonce = payload.get("nonce")
                if nonce != expected_nonce:
                    return {"valid": False, "error": "Nonce mismatch"}
            
            # Extract claims from VP
            vp = payload.get("vp", {})
            
            return {
                "valid": True,
                "claims": vp.get("verifiableCredential", []),
                "holder": vp.get("holder"),
                "method": "jwt_vp"
            }
            
        except Exception as e:
            logger.error(f"JWT VP verification failed: {e}")
            return {"valid": False, "error": str(e)}
    
    async def verify_presentation(
        self,
        presentation: dict[str, Any],
        presentation_definition: dict[str, Any],
        verifier_did: str
    ) -> dict[str, Any]:
        """Verify a presentation against a presentation definition."""
        try:
            # Extract credentials from presentation
            credentials = presentation.get("verifiableCredential", [])
            if not isinstance(credentials, list):
                credentials = [credentials]
            
            # Verify each credential
            all_valid = True
            verified_creds = []
            all_claims = {}
            
            for cred in credentials:
                result = await self.verify_w3c_vc(cred, verifier_did)
                if not result.get("valid"):
                    all_valid = False
                    return {"valid": False, "error": f"Credential verification failed: {result.get('error')}"}
                
                verified_creds.append(result)
                if result.get("claims"):
                    all_claims.update(result["claims"])
            
            # TODO: Check presentation definition constraints
            
            return {
                "valid": all_valid,
                "verified_claims": all_claims,
                "credentials_verified": len(verified_creds),
                "method": "presentation"
            }
            
        except Exception as e:
            logger.error(f"Presentation verification failed: {e}")
            return {"valid": False, "error": str(e)}
