"""
Secret Management Routes — CRUD with AES-256 encryption at rest.

Security design:
- Secrets are encrypted before DB storage using per-user AES-256-GCM keys.
- Decrypted values are ONLY returned on explicit single-secret GET requests.
- All operations are audit logged.
- Users can only access their own secrets. Admins can access all.
"""

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.aes_encrypt import encrypt_secret, decrypt_secret
from app.auth.middleware import get_current_user, require_role, log_audit
from app.database import get_db, Secret, User, UserRole
from app.models.user import SecretCreate, SecretUpdate, SecretResponse, SecretDetailResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/secrets", tags=["Secrets"])


@router.get("/", response_model=List[SecretResponse])
def list_secrets(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List all secrets for the current user.
    Admins see all secrets. Values are NOT included in list responses.
    """
    if current_user.role == UserRole.ADMIN:
        secrets = db.query(Secret).all()
    else:
        secrets = db.query(Secret).filter(Secret.user_id == current_user.id).all()

    log_audit(db, "SECRET_LIST", "SUCCESS", user_id=current_user.id,
              ip_address=request.client.host if request.client else None,
              details=f"Listed {len(secrets)} secrets")
    return secrets


@router.post("/", response_model=SecretResponse, status_code=status.HTTP_201_CREATED)
def create_secret(
    payload: SecretCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Store a new secret with AES-256-GCM encryption.
    The plaintext value is encrypted before writing to PostgreSQL.
    """
    # Check for duplicate name per user
    existing = db.query(Secret).filter(
        Secret.user_id == current_user.id,
        Secret.name == payload.name
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="A secret with that name already exists")

    encrypted = encrypt_secret(payload.value, current_user.id)

    secret = Secret(
        user_id=current_user.id,
        name=payload.name,
        encrypted_value=encrypted,
        description=payload.description,
        rotate_after_days=payload.rotate_after_days
    )
    db.add(secret)
    db.commit()
    db.refresh(secret)

    log_audit(db, "SECRET_CREATED", "SUCCESS", user_id=current_user.id,
              resource=f"secret:{secret.id}",
              ip_address=request.client.host if request.client else None,
              details=f"Secret '{secret.name}' created")
    return secret


@router.get("/{secret_id}", response_model=SecretDetailResponse)
def get_secret(
    secret_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve and decrypt a specific secret.
    This is the ONLY endpoint that returns the decrypted value.
    All access is audit logged.
    """
    secret = db.query(Secret).filter(Secret.id == secret_id).first()

    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    # Access control: users can only read their own secrets
    if current_user.role != UserRole.ADMIN and secret.user_id != current_user.id:
        log_audit(db, "SECRET_ACCESS", "FAILURE", user_id=current_user.id,
                  resource=f"secret:{secret_id}",
                  details="Unauthorized access attempt")
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        decrypted_value = decrypt_secret(secret.encrypted_value, secret.user_id)
    except ValueError:
        log_audit(db, "SECRET_DECRYPT", "FAILURE", user_id=current_user.id,
                  resource=f"secret:{secret_id}", details="Decryption failed")
        raise HTTPException(status_code=500, detail="Failed to decrypt secret")

    log_audit(db, "SECRET_ACCESSED", "SUCCESS", user_id=current_user.id,
              resource=f"secret:{secret_id}",
              ip_address=request.client.host if request.client else None)

    return SecretDetailResponse(
        id=secret.id,
        name=secret.name,
        value=decrypted_value,
        description=secret.description,
        rotate_after_days=secret.rotate_after_days,
        created_at=secret.created_at,
        updated_at=secret.updated_at
    )


@router.put("/{secret_id}", response_model=SecretResponse)
def update_secret(
    secret_id: int,
    payload: SecretUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a secret. New value is re-encrypted with AES-256-GCM."""
    secret = db.query(Secret).filter(Secret.id == secret_id).first()

    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    if current_user.role != UserRole.ADMIN and secret.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    if payload.name is not None:
        secret.name = payload.name
    if payload.value is not None:
        secret.encrypted_value = encrypt_secret(payload.value, secret.user_id)
    if payload.description is not None:
        secret.description = payload.description
    if payload.rotate_after_days is not None:
        secret.rotate_after_days = payload.rotate_after_days

    db.commit()
    db.refresh(secret)

    log_audit(db, "SECRET_UPDATED", "SUCCESS", user_id=current_user.id,
              resource=f"secret:{secret_id}",
              ip_address=request.client.host if request.client else None)
    return secret


@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secret(
    secret_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a secret. Permanently removes encrypted value from DB."""
    secret = db.query(Secret).filter(Secret.id == secret_id).first()

    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    if current_user.role != UserRole.ADMIN and secret.user_id != current_user.id:
        log_audit(db, "SECRET_DELETE", "FAILURE", user_id=current_user.id,
                  resource=f"secret:{secret_id}", details="Unauthorized delete attempt")
        raise HTTPException(status_code=403, detail="Access denied")

    db.delete(secret)
    db.commit()

    log_audit(db, "SECRET_DELETED", "SUCCESS", user_id=current_user.id,
              resource=f"secret:{secret_id}",
              ip_address=request.client.host if request.client else None)
