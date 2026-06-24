"""
RBAC Middleware and Authentication Dependencies.

Role hierarchy:
  ADMIN > USER > GUEST

How RBAC works here:
- Each JWT contains the user's role in the payload.
- FastAPI dependencies enforce role requirements per route.
- Roles are checked after token verification — no extra DB call needed.
"""

import logging
from typing import Optional
from uuid import uuid4

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from sqlalchemy.orm import Session

from app.auth.jwt_handler import verify_token
from app.auth.redis_client import is_token_blacklisted, rate_limit_check
from app.database import get_db, User, AuditLog, UserRole

logger = logging.getLogger(__name__)
security = HTTPBearer()

ROLE_HIERARCHY = {
    UserRole.ADMIN: 3,
    UserRole.USER: 2,
    UserRole.GUEST: 1
}


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI dependency: extract and validate JWT, return current user.

    Steps:
    1. Extract Bearer token from Authorization header.
    2. Verify RSA signature.
    3. Check token not blacklisted in Redis.
    4. Load user from PostgreSQL.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token = credentials.credentials

    # Rate limiting by IP
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limit_check(f"auth:{client_ip}", limit=100, window=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )

    try:
        payload = verify_token(token)
    except JWTError:
        raise credentials_exception

    # Check token type
    if payload.get("type") != "access":
        raise credentials_exception

    # Check blacklist
    jti = payload.get("jti")
    if jti and is_token_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked"
        )

    email: Optional[str] = payload.get("sub")
    if email is None:
        raise credentials_exception

    user = db.query(User).filter(User.email == email, User.is_active == True).first()
    if user is None:
        raise credentials_exception

    return user


def require_role(minimum_role: UserRole):
    """
    FastAPI dependency factory: enforce minimum role requirement.

    Usage:
        @router.get("/admin-only")
        def admin_endpoint(user: User = Depends(require_role(UserRole.ADMIN))):
            ...
    """
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_level = ROLE_HIERARCHY.get(current_user.role, 0)
        required_level = ROLE_HIERARCHY.get(minimum_role, 0)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {minimum_role.value}"
            )
        return current_user

    return role_checker


def log_audit(
    db: Session,
    action: str,
    status: str,
    user_id: Optional[int] = None,
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[str] = None
):
    """Write an audit log entry for all cryptographic operations."""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        ip_address=ip_address,
        status=status,
        details=details
    )
    db.add(log)
    db.commit()
    logger.info(f"AUDIT | {action} | user={user_id} | status={status} | {details or ''}")
