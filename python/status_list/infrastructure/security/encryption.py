"""Symmetric encryption for protecting sensitive data.

Uses AES-256-GCM encryption pattern from vdstools_db_key_manager.py.
Provides secure storage for private key material in the database.

TODO: Enhance with platform keychain integration per marty-secure-storage/keychain.rs
      for production deployments. Current implementation uses environment variable
      for master key, which should be replaced with proper key management systems
      (Azure Key Vault, AWS KMS, or platform keychain) in production environments.
"""

import base64
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


class SymmetricEncryption:
    """AES-256-GCM symmetric encryption for sensitive data protection.
    
    Format: base64(nonce || ciphertext || tag)
    - Nonce: 12 bytes (96 bits) random
    - Ciphertext: encrypted data
    - Tag: 16 bytes (128 bits) authentication tag
    
    Example:
        encryption = SymmetricEncryption.from_env()
        encrypted = encryption.encrypt('{"kty":"EC",...}')
        decrypted = encryption.decrypt(encrypted)
    """
    
    def __init__(self, master_key: bytes):
        """Initialize encryption with 32-byte master key.
        
        Args:
            master_key: 32-byte (256-bit) encryption key
            
        Raises:
            ValueError: If master key is not 32 bytes
        """
        if len(master_key) != 32:
            raise ValueError(f"Master key must be 32 bytes, got {len(master_key)}")
        
        self._cipher = AESGCM(master_key)
        logger.info("Symmetric encryption initialized with AES-256-GCM")
    
    @classmethod
    def from_env(cls, env_var: str = "STATUS_LIST_MASTER_KEY") -> "SymmetricEncryption":
        """Create encryption service from environment variable.
        
        Args:
            env_var: Environment variable name containing base64-encoded key
            
        Returns:
            SymmetricEncryption instance
            
        Raises:
            ValueError: If environment variable not set or invalid
            
        Example:
            # Generate key: python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
            export STATUS_LIST_MASTER_KEY="base64_encoded_32_byte_key"
        """
        key_b64 = os.environ.get(env_var)
        if not key_b64:
            raise ValueError(
                f"Environment variable {env_var} not set. "
                f"Generate with: python -c \"import os, base64; print(base64.b64encode(os.urandom(32)).decode())\""
            )
        
        try:
            master_key = base64.b64decode(key_b64)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding in {env_var}: {e}")
        
        return cls(master_key)
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string.
        
        Args:
            plaintext: String to encrypt (e.g., JSON JWK)
            
        Returns:
            Base64-encoded encrypted data: nonce || ciphertext || tag
            
        Example:
            encrypted = encryption.encrypt('{"kty":"EC","d":"..."}')
        """
        # Generate random 12-byte nonce
        nonce = os.urandom(12)
        
        # Encrypt with AES-256-GCM (includes authentication tag)
        ciphertext = self._cipher.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Combine: nonce || ciphertext (already includes tag from AESGCM)
        encrypted = nonce + ciphertext
        
        # Encode as base64 for storage
        return base64.b64encode(encrypted).decode('ascii')
    
    def decrypt(self, ciphertext_b64: str) -> str:
        """Decrypt ciphertext string.
        
        Args:
            ciphertext_b64: Base64-encoded encrypted data
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            Exception: If decryption fails (wrong key, corrupted data, etc.)
            
        Example:
            decrypted = encryption.decrypt(encrypted_jwk)
            jwk = json.loads(decrypted)
        """
        try:
            # Decode from base64
            encrypted = base64.b64decode(ciphertext_b64)
            
            # Extract nonce and ciphertext
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            
            # Decrypt and verify authentication tag
            plaintext_bytes = self._cipher.decrypt(nonce, ciphertext, None)
            
            return plaintext_bytes.decode('utf-8')
        
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError(f"Failed to decrypt data: {e}")
    
    def encrypt_optional(self, plaintext: Optional[str]) -> Optional[str]:
        """Encrypt plaintext if not None, otherwise return None.
        
        Convenience method for optional fields.
        """
        return self.encrypt(plaintext) if plaintext is not None else None
    
    def decrypt_optional(self, ciphertext: Optional[str]) -> Optional[str]:
        """Decrypt ciphertext if not None, otherwise return None.
        
        Convenience method for optional fields.
        """
        return self.decrypt(ciphertext) if ciphertext is not None else None
