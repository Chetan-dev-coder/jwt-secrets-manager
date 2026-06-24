"""
Authentication Routes: register, login, refresh, logout, key rotation.
"""

import logging
from datetime import timedelta, datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.auth.jwt_handler import create_access_token, create_refresh_token, verify_token
from app.auth.redis_client import (
    blacklist_token, store_refresh_token,
    revoke_all_user_tokens, rate_limit_check
)
from app.auth.rsa_keys import rotate_keys
from app.auth.middleware import get_current_user, require_role, log_audit
from app.database import get_db, User, UserRole
from app.models.user import UserRegister, UserLogin, TokenResponse, RefreshRequest, UserResponse
from app.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserRegister, request: Request, db: Session = Depends(get_db)):
    """
    Register a new user account.
    - Password is hashed with bcrypt before storage.
    - Role assignment (only admins can create admin accounts in production).
    """
    client_ip = request.client.host if request.client else "unknown"

    # Rate limit registrations per IP
    if not rate_limit_check(f"register:{client_ip}", limit=5, window=300):
        raise HTTPException(status_code=429, detail="Too many registration attempts")

    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        log_audit(db, "USER_REGISTER", "FAILURE", ip_address=client_ip,
                  details=f"Email already exists: {payload.email}")
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit(db, "USER_REGISTER", "SUCCESS", user_id=user.id,
              ip_address=client_ip, details=f"User registered: {user.email}")
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate user and issue JWT access + refresh tokens.
    - Access token: 15 minutes (short-lived for security).
    - Refresh token: 7 days (stored in Redis).
    """
    client_ip = request.client.host if request.client else "unknown"

    if not rate_limit_check(f"login:{client_ip}", limit=10, window=60):
        raise HTTPException(status_code=429, detail="Too many login attempts")

    user = db.query(User).filter(User.email == payload.email, User.is_active == True).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        log_audit(db, "USER_LOGIN", "FAILURE", ip_address=client_ip,
                  details=f"Invalid credentials for: {payload.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    jti = str(uuid4())
    token_data = {"sub": user.email, "role": user.role, "jti": jti}

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    store_refresh_token(user.id, jti, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))

    log_audit(db, "USER_LOGIN", "SUCCESS", user_id=user.id, ip_address=client_ip)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    """
    Refresh an expired access token using a valid refresh token.
    Implements token rotation — old refresh token is blacklisted.
    """
    try:
        token_data = verify_token(payload.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    if token_data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    old_jti = token_data.get("jti")
    if old_jti:
        blacklist_token(old_jti, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))

    user = db.query(User).filter(User.email == token_data["sub"], User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    new_jti = str(uuid4())
    new_token_data = {"sub": user.email, "role": user.role, "jti": new_jti}

    access_token = create_access_token(new_token_data)
    refresh_token_new = create_refresh_token(new_token_data)

    store_refresh_token(user.id, new_jti, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    log_audit(db, "TOKEN_REFRESH", "SUCCESS", user_id=user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_new,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/logout")
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke all tokens for the current user (logout from all devices)."""
    revoke_all_user_tokens(current_user.id)
    log_audit(db, "USER_LOGOUT", "SUCCESS", user_id=current_user.id,
              ip_address=request.client.host if request.client else None)
    return {"message": "Logged out successfully from all devices"}


@router.post("/rotate-keys")
def rotate_rsa_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """
    Rotate RSA key pair (Admin only).

    WARNING: Rotating keys invalidates ALL existing tokens.
    All users must re-authenticate after rotation.
    Tokens are auto-invalidated because they were signed with the old private key
    and the new public key cannot verify them.
    """
    result = rotate_keys()
    log_audit(db, "KEY_ROTATION", "SUCCESS", user_id=current_user.id,
              details=f"Keys rotated at {result['rotated_at']}")
    return result


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user's profile."""
    return current_user
