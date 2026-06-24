"""
Redis Client for Token Blacklisting and Rate Limiting.

Token blacklisting strategy:
- On logout or key rotation, add token JTI (JWT ID) to Redis with TTL = token expiry.
- On every request, check if JTI is blacklisted before allowing access.
- Redis TTL auto-cleans expired entries — no manual cleanup needed.
"""

import logging
from datetime import timedelta
from typing import Optional

import redis

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_redis_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    """Get or create Redis connection."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )
    return _redis_client


def blacklist_token(token_jti: str, expires_in: timedelta):
    """
    Add a token JTI to the blacklist with auto-expiry.

    Args:
        token_jti: Unique JWT ID from token payload.
        expires_in: How long until the token would have expired anyway.
    """
    try:
        client = get_redis()
        key = f"blacklist:{token_jti}"
        client.setex(key, int(expires_in.total_seconds()), "1")
        logger.info(f"Token {token_jti} blacklisted for {expires_in}")
    except redis.RedisError as e:
        logger.error(f"Failed to blacklist token: {e}")
        raise


def is_token_blacklisted(token_jti: str) -> bool:
    """Check if a token JTI is in the blacklist."""
    try:
        client = get_redis()
        return client.exists(f"blacklist:{token_jti}") == 1
    except redis.RedisError as e:
        logger.error(f"Redis check failed: {e}")
        # Fail-safe: if Redis is down, reject the token
        return True


def store_refresh_token(user_id: int, token_jti: str, expires_in: timedelta):
    """Store refresh token reference for a user (enables logout-all-devices)."""
    try:
        client = get_redis()
        key = f"refresh:{user_id}:{token_jti}"
        client.setex(key, int(expires_in.total_seconds()), token_jti)
    except redis.RedisError as e:
        logger.error(f"Failed to store refresh token: {e}")


def revoke_all_user_tokens(user_id: int):
    """Revoke all refresh tokens for a user (logout from all devices)."""
    try:
        client = get_redis()
        pattern = f"refresh:{user_id}:*"
        keys = client.keys(pattern)
        if keys:
            client.delete(*keys)
        logger.info(f"All tokens revoked for user_id={user_id}")
    except redis.RedisError as e:
        logger.error(f"Failed to revoke user tokens: {e}")


def rate_limit_check(identifier: str, limit: int = 10, window: int = 60) -> bool:
    """
    Simple sliding window rate limiter.

    Args:
        identifier: e.g. IP address or user email.
        limit: Max requests allowed in window.
        window: Time window in seconds.

    Returns:
        True if request is allowed, False if rate limit exceeded.
    """
    try:
        client = get_redis()
        key = f"rate_limit:{identifier}"
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window)
        results = pipe.execute()
        count = results[0]
        return count <= limit
    except redis.RedisError:
        return True  # Fail open if Redis is down
