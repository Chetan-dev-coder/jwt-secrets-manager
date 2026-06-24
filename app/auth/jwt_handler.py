"""
JWT Token Handler using RSA asymmetric signing.

Why RSA (RS256) over HMAC (HS256)?
- RS256: Private key signs, public key verifies. Verifiers never see the private key.
- HS256: Same secret used to sign AND verify — shared secret must be distributed.
- RS256 is mandatory for distributed systems and microservice architectures.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError

from app.auth.rsa_keys import load_private_key, load_public_key
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

ALGORITHM = "RS256"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a short-lived JWT access token signed with RSA private key.

    Token payload includes:
    - sub: subject (user email)
    - role: user role for RBAC
    - type: 'access' to distinguish from refresh tokens
    - exp: expiration timestamp
    - iat: issued at timestamp
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })

    private_key = load_private_key()
    token = jwt.encode(to_encode, private_key, algorithm=ALGORITHM)
    logger.info(f"Access token created for subject: {data.get('sub')}")
    return token


def create_refresh_token(data: dict) -> str:
    """
    Create a long-lived JWT refresh token.
    Refresh tokens are stored in Redis and can be blacklisted on logout.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh"
    })

    private_key = load_private_key()
    token = jwt.encode(to_encode, private_key, algorithm=ALGORITHM)
    logger.info(f"Refresh token created for subject: {data.get('sub')}")
    return token


def verify_token(token: str) -> dict:
    """
    Verify JWT token using RSA public key.

    Raises:
        ExpiredSignatureError: Token has expired.
        JWTError: Token is invalid or tampered.
    """
    try:
        public_key = load_public_key()
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError:
        logger.warning("Token verification failed: token expired")
        raise
    except JWTError as e:
        logger.warning(f"Token verification failed: {e}")
        raise


def decode_token_unverified(token: str) -> dict:
    """
    Decode token without verification (for extracting claims from expired tokens).
    NEVER use this for authentication — only for reading metadata.
    """
    return jwt.get_unverified_claims(token)
