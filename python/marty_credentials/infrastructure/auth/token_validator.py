"""OAuth2 token validation with caching"""
import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class TokenValidationError(Exception):
    """Raised when token validation fails"""
    pass


class InvalidTokenError(TokenValidationError):
    """Raised when token is invalid or inactive"""
    pass


class CredentialVerificationError(Exception):
    """Raised when credential verification fails"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}


@dataclass
class TokenInfo:
    """Information about a validated token"""
    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    username: Optional[str] = None
    token_type: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    iss: Optional[str] = None
    jti: Optional[str] = None


class TokenValidator:
    """Validates OAuth2 access tokens using issuer's introspection endpoint"""
    
    def __init__(
        self,
        redis_client: Redis,
        issuer_base_url: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        cache_enabled: bool = True
    ):
        """
        Initialize token validator
        
        Args:
            redis_client: Redis client for caching
            issuer_base_url: Base URL of the credential issuer
            client_id: OAuth2 client ID for introspection
            client_secret: OAuth2 client secret for introspection
            cache_enabled: Whether to enable token caching
        """
        self.redis = redis_client
        self.issuer_base_url = issuer_base_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.cache_enabled = cache_enabled
        self._metadata_cache: Optional[dict] = None
        self._metadata_cache_time: Optional[float] = None
        self._metadata_cache_ttl = 3600  # Cache metadata for 1 hour
        
    async def validate_token(self, token: str) -> TokenInfo:
        """
        Validate an access token
        
        Args:
            token: The access token to validate
            
        Returns:
            TokenInfo with validation results
            
        Raises:
            InvalidTokenError: If token is not active
            TokenValidationError: If validation fails
        """
        # Check cache first if enabled
        if self.cache_enabled:
            cached_info = await self._get_cached_token_info(token)
            if cached_info:
                logger.debug("Token found in cache")
                return cached_info
        
        # Validate with introspection endpoint
        token_info = await self._introspect_token(token)
        
        if not token_info.active:
            logger.warning("Token is not active", extra={"token_jti": token_info.jti})
            raise InvalidTokenError("Token is not active or has been revoked")
        
        # Cache the result if enabled
        if self.cache_enabled and token_info.exp:
            await self._cache_token_info(token, token_info)
        
        logger.info(
            "Token validated successfully",
            extra={
                "client_id": token_info.client_id,
                "scope": token_info.scope,
                "exp": token_info.exp
            }
        )
        
        return token_info
    
    async def _get_cached_token_info(self, token: str) -> Optional[TokenInfo]:
        """Get token info from cache"""
        try:
            cache_key = self._get_cache_key(token)
            cached_data = await self.redis.get(cache_key)
            
            if cached_data:
                import json
                data = json.loads(cached_data)
                return TokenInfo(**data)
        except Exception as e:
            logger.warning(f"Failed to get token from cache: {e}")
        
        return None
    
    async def _cache_token_info(self, token: str, token_info: TokenInfo) -> None:
        """Cache token info with TTL"""
        try:
            cache_key = self._get_cache_key(token)
            
            # Calculate TTL based on token expiry
            if token_info.exp:
                ttl = token_info.exp - int(time.time())
                # Don't cache if already expired or expiring soon
                if ttl < 30:
                    return
            else:
                # Default TTL if no expiry
                ttl = 300  # 5 minutes
            
            import json
            data = json.dumps({
                "active": token_info.active,
                "scope": token_info.scope,
                "client_id": token_info.client_id,
                "username": token_info.username,
                "token_type": token_info.token_type,
                "exp": token_info.exp,
                "iat": token_info.iat,
                "sub": token_info.sub,
                "aud": token_info.aud,
                "iss": token_info.iss,
                "jti": token_info.jti,
            })
            
            await self.redis.setex(cache_key, ttl, data)
            logger.debug(f"Cached token info with TTL {ttl} seconds")
            
        except Exception as e:
            logger.warning(f"Failed to cache token info: {e}")
    
    def _get_cache_key(self, token: str) -> str:
        """Generate cache key for token"""
        # Use SHA-256 hash of token to avoid storing full token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return f"token_validation:{token_hash}"
    
    async def _introspect_token(self, token: str) -> TokenInfo:
        """Introspect token with issuer"""
        try:
            # Get issuer metadata
            metadata = await self._fetch_issuer_metadata()
            introspection_endpoint = metadata.get("token_introspection_endpoint")
            
            if not introspection_endpoint:
                raise TokenValidationError(
                    "Issuer metadata does not contain token_introspection_endpoint"
                )
            
            logger.debug(f"Introspecting token at {introspection_endpoint}")
            
            # Prepare request
            data = {"token": token}
            auth = None
            if self.client_id and self.client_secret:
                auth = (self.client_id, self.client_secret)
            
            # Call introspection endpoint
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    introspection_endpoint,
                    data=data,
                    auth=auth,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                response.raise_for_status()
                token_data = response.json()
            
            return TokenInfo(**token_data)
            
        except httpx.HTTPError as e:
            logger.error(f"HTTP error during token introspection: {e}")
            raise TokenValidationError(f"Failed to introspect token: {e}") from e
        except Exception as e:
            logger.error(f"Error during token introspection: {e}")
            raise TokenValidationError(f"Token introspection failed: {e}") from e
    
    async def _fetch_issuer_metadata(self) -> dict:
        """Fetch and cache issuer metadata"""
        # Check cache
        current_time = time.time()
        if (self._metadata_cache 
            and self._metadata_cache_time 
            and (current_time - self._metadata_cache_time) < self._metadata_cache_ttl):
            return self._metadata_cache
        
        # Fetch metadata
        metadata_url = f"{self.issuer_base_url}/.well-known/openid-credential-issuer"
        
        try:
            logger.debug(f"Fetching issuer metadata from {metadata_url}")
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(metadata_url)
                response.raise_for_status()
                metadata = response.json()
            
            # Cache it
            self._metadata_cache = metadata
            self._metadata_cache_time = current_time
            
            return metadata
            
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch issuer metadata: {e}")
            raise TokenValidationError(
                f"Failed to fetch issuer metadata from {metadata_url}: {e}"
            ) from e
