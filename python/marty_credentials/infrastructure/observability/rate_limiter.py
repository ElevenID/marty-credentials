"""Rate limiting implementation using Redis"""
import logging
from typing import Optional, Tuple

from redis.asyncio import Redis

from marty_credentials.infrastructure.observability.metrics import rate_limit_remaining

logger = logging.getLogger(__name__)


class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded"""
    def __init__(self, message: str, retry_after_seconds: int):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class RateLimiter:
    """Redis-based rate limiter using sliding window pattern"""
    
    def __init__(
        self,
        redis_client: Redis,
        default_limit: int = 100,
        window_seconds: int = 60
    ):
        """Initialize rate limiter
        
        Args:
            redis_client: Redis client for storing rate limit state
            default_limit: Default number of requests allowed per window
            window_seconds: Time window in seconds
        """
        self.redis = redis_client
        self.default_limit = default_limit
        self.window = window_seconds
    
    async def check_rate_limit(
        self,
        key: str,
        limit: Optional[int] = None,
        resource_type: str = "credential",
        resource_id: str = "unknown"
    ) -> Tuple[bool, int]:
        """Check if request is within rate limit
        
        Args:
            key: Unique identifier for rate limiting (e.g., "issuer:123", "verifier:456")
            limit: Optional override for the rate limit
            resource_type: Type of resource for metrics (e.g., "issuer", "verifier")
            resource_id: ID of the resource for metrics
        
        Returns:
            Tuple of (allowed, remaining) where:
                - allowed: True if request is allowed, False if rate limit exceeded
                - remaining: Number of remaining requests in current window
        
        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        limit = limit or self.default_limit
        redis_key = f"rate_limit:{key}"
        
        try:
            # Increment counter
            current = await self.redis.incr(redis_key)
            
            # Set expiry on first increment
            if current == 1:
                await self.redis.expire(redis_key, self.window)
            
            # Calculate remaining
            allowed = current <= limit
            remaining = max(0, limit - current)
            
            # Update metrics
            rate_limit_remaining.labels(
                resource_type=resource_type,
                resource_id=resource_id
            ).set(remaining)
            
            if not allowed:
                # Get TTL to tell user when they can retry
                ttl = await self.redis.ttl(redis_key)
                logger.warning(
                    f"Rate limit exceeded for {key}",
                    extra={
                        "key": key,
                        "current": current,
                        "limit": limit,
                        "ttl": ttl
                    }
                )
                raise RateLimitExceededError(
                    f"Rate limit exceeded for {key}. Try again in {ttl} seconds.",
                    retry_after_seconds=ttl if ttl > 0 else self.window
                )
            
            logger.debug(
                f"Rate limit check passed for {key}",
                extra={
                    "key": key,
                    "current": current,
                    "limit": limit,
                    "remaining": remaining
                }
            )
            
            return allowed, remaining
            
        except RateLimitExceededError:
            # Re-raise rate limit errors
            raise
        except Exception as e:
            # Log error but don't block requests on Redis failures
            logger.error(
                f"Rate limit check failed for {key}: {e}",
                extra={"key": key, "error": str(e)}
            )
            # Fail open - allow request if Redis is unavailable
            return True, limit
    
    async def reset_rate_limit(self, key: str) -> None:
        """Reset rate limit for a key (useful for testing or admin operations)
        
        Args:
            key: Unique identifier for rate limiting
        """
        redis_key = f"rate_limit:{key}"
        await self.redis.delete(redis_key)
        logger.info(f"Reset rate limit for {key}")
    
    async def get_current_usage(self, key: str) -> Tuple[int, int]:
        """Get current usage and remaining quota
        
        Args:
            key: Unique identifier for rate limiting
        
        Returns:
            Tuple of (current_usage, remaining_quota)
        """
        redis_key = f"rate_limit:{key}"
        try:
            current = await self.redis.get(redis_key)
            current = int(current) if current else 0
            remaining = max(0, self.default_limit - current)
            return current, remaining
        except Exception as e:
            logger.error(f"Failed to get rate limit usage for {key}: {e}")
            return 0, self.default_limit
