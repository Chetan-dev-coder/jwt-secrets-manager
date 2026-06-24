"""
Pydantic Models for Request Validation and Response Serialization.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator
from app.database import UserRole


# --- Auth Models ---

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.USER

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str


# --- Secret Models ---

class SecretCreate(BaseModel):
    name: str
    value: str
    description: Optional[str] = None
    rotate_after_days: int = 90

    @field_validator("name")
    @classmethod
    def name_format(cls, v: str) -> str:
        if len(v) < 1 or len(v) > 255:
            raise ValueError("Name must be between 1 and 255 characters")
        return v.strip()


class SecretUpdate(BaseModel):
    name: Optional[str] = None
    value: Optional[str] = None
    description: Optional[str] = None
    rotate_after_days: Optional[int] = None


class SecretResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    rotate_after_days: int
    created_at: datetime
    updated_at: Optional[datetime]
    # NOTE: 'value' is never included in list responses — only in single GET

    class Config:
        from_attributes = True


class SecretDetailResponse(SecretResponse):
    value: str  # Decrypted value — only returned on explicit GET /{id}


# --- Audit Models ---

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    resource: Optional[str]
    status: str
    details: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
