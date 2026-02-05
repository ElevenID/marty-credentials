"""Rust integration for credential signing operations."""

import base64
import json
import logging
from typing import Any, Dict, Tuple
import datetime
import uuid

logger = logging.getLogger(__name__)


def base64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def base64url_decode(data: str) -> bytes:
    """Decode base64url string."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def get_marty_rs():
    """Import Rust bindings for credential operations.
    
    Raises:
        ImportError: If marty-rs bindings are not available.
    """
    try:
        import _marty_rs
        return _marty_rs
    except ImportError as e:
        logger.error("marty-rs bindings not available - credential signing will fail")
        raise ImportError(
            "marty-rs Python bindings are required for credential signing. "
            "Ensure the marty-bindings crate is built and installed."
        ) from e


def get_or_generate_issuer_key(organization_id: str = "default") -> dict:
    """Get or generate signing key for organization.
    
    Args:
        organization_id: Organization identifier
        
    Returns:
        dict with 'did', 'private_key', and 'public_key' keys
        (private_key and public_key are raw bytes for signing)
        
    Raises:
        ImportError: If Rust bindings are not available
    """
    marty_rs = get_marty_rs()
    
    # Generate new P-256 key for this issuance
    # TODO: Cache and reuse organization keys from database
    private_key, public_key = marty_rs.generate_p256_key()
    
    # TODO: Generate proper DID from public key
    did = f"did:example:issuer-{organization_id}"
    
    # Return bytes directly - they will be used for signing
    return {
        "did": did,
        "private_key": bytes(private_key),  # Keep as bytes for signing
        "public_key": bytes(public_key),    # Keep as bytes
    }


def create_verifiable_credential_wrapper(
    issuer_did: str,
    issuer_jwk_json: str,  # Not used - we use private_key directly
    subject_id: str,
    credential_type: str,
    claims_json: str,
    expiration_seconds: int = 31536000,
) -> Tuple[str, str]:
    """Wrapper for create_verifiable_credential to match old API.
    
    This function bridges the old API (from routes.py) to the new implementation.
    
    Args:
        issuer_did: Issuer's DID
        issuer_jwk_json: JWK JSON (ignored, we get key from context)
        subject_id: Subject's DID or identifier
        credential_type: Type of credential
        claims_json: JSON string of claims
        expiration_seconds: Validity period
        
    Returns:
        Tuple of (credential_json, credential_id)
    """
    # Get issuer key (in production, this would come from secure storage)
    issuer_key = get_or_generate_issuer_key()
    
    claims = json.loads(claims_json)
    
    return create_verifiable_credential(
        issuer_did=issuer_did,
        subject_id=subject_id,
        credential_type=credential_type,
        claims=claims,
        private_key=issuer_key["private_key"],
        expiration_seconds=expiration_seconds,
    )


def create_verifiable_credential(
    issuer_did: str,
    subject_id: str,
    credential_type: str,
    claims: Dict[str, Any],
    private_key: bytes,
    expiration_seconds: int = 31536000,
) -> Tuple[str, str]:
    """Create a signed verifiable credential as a JWT (VC-JWT).
    
    Args:
        issuer_did: Issuer's DID
        subject_id: Subject's DID or identifier
        credential_type: Type of credential (e.g., "org.iso.18013.5.1.mDL")
        claims: Credential claims as dict
        private_key: Issuer's private key (32 bytes for P-256)
        expiration_seconds: Credential validity in seconds
    
    Returns:
        Tuple of (jwt_credential, credential_id) where jwt_credential is a compact JWT string
    """
    marty_rs = get_marty_rs()
    
    # Generate credential ID
    credential_id = str(uuid.uuid4())
    
    # Build JWT header
    now = datetime.datetime.now(datetime.timezone.utc)
    expiration = now + datetime.timedelta(seconds=expiration_seconds)
    
    header = {
        "alg": "ES256",  # P-256 ECDSA
        "typ": "JWT"
    }
    
    # Build JWT payload (VC as JWT claims)
    # Following W3C VC-JWT specification
    payload = {
        "iss": issuer_did,  # Issuer
        "sub": subject_id,  # Subject
        "iat": int(now.timestamp()),  # Issued at
        "exp": int(expiration.timestamp()),  # Expiration
        "jti": f"urn:uuid:{credential_id}",  # JWT ID (becomes VC id)
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "type": ["VerifiableCredential", credential_type],
            "credentialSubject": {
                "id": subject_id,
                **claims
            }
        }
    }
    
    # Create JWT: header.payload.signature
    header_json = json.dumps(header, separators=(',', ':'))
    payload_json = json.dumps(payload, separators=(',', ':'))
    
    header_b64 = base64url_encode(header_json.encode('utf-8'))
    payload_b64 = base64url_encode(payload_json.encode('utf-8'))
    
    # Sign the header.payload
    signing_input = f"{header_b64}.{payload_b64}"
    signature = marty_rs.sign_p256(private_key, signing_input.encode('utf-8'))
    signature_b64 = base64url_encode(bytes(signature))
    
    # Construct JWT
    jwt_credential = f"{signing_input}.{signature_b64}"
    
    logger.info(f"Created VC-JWT credential: {credential_id}")
    return jwt_credential, credential_id
