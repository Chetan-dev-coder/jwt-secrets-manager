"""
AES-256 Encryption/Decryption for Secret Storage.

How AES-256 works:
- Symmetric block cipher with a 256-bit (32-byte) key.
- Encrypts data in 128-bit blocks.
- We use AES-GCM mode: provides both encryption AND authentication (AEAD).
- GCM prevents tampering — any modification to ciphertext is detected.

Security design:
- Master key stored in environment variable (never in DB).
- Each secret gets a unique 12-byte random nonce (IV).
- Per-user derived keys using HKDF to isolate user data.
- Ciphertext stored as: nonce(12) + tag(16) + ciphertext.
"""

import base64
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def _get_master_key() -> bytes:
    """Decode the master AES key from base64 config."""
    return base64.b64decode(settings.AES_MASTER_KEY)


def derive_user_key(user_id: int) -> bytes:
    """
    Derive a unique 256-bit AES key per user using HKDF.

    Why per-user keys?
    - Compromise of one user's key doesn't affect others.
    - Derived deterministically from master key + user_id.
    - No need to store derived keys in the database.
    """
    master_key = _get_master_key()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"user-{user_id}-secrets".encode(),
        backend=default_backend()
    )
    return hkdf.derive(master_key)


def encrypt_secret(plaintext: str, user_id: int) -> str:
    """
    Encrypt a secret value using AES-256-GCM with a per-user derived key.

    Returns:
        Base64-encoded string of: nonce(12) + tag(16) + ciphertext.
    """
    key = derive_user_key(user_id)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)  # 96-bit nonce, unique per encryption
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Prepend nonce to ciphertext+tag
    combined = nonce + ciphertext_with_tag
    encoded = base64.b64encode(combined).decode("utf-8")

    logger.debug(f"Secret encrypted for user_id={user_id}")
    return encoded


def decrypt_secret(encrypted_value: str, user_id: int) -> str:
    """
    Decrypt a secret value using AES-256-GCM.

    Raises:
        ValueError: If decryption fails (wrong key or tampered data).
    """
    try:
        key = derive_user_key(user_id)
        aesgcm = AESGCM(key)

        combined = base64.b64decode(encrypted_value)
        nonce = combined[:12]
        ciphertext_with_tag = combined[12:]

        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        logger.debug(f"Secret decrypted for user_id={user_id}")
        return plaintext.decode("utf-8")

    except Exception as e:
        logger.error(f"Decryption failed for user_id={user_id}: {type(e).__name__}")
        raise ValueError("Decryption failed: invalid key or tampered ciphertext")


def encrypt_string(plaintext: str, key: Optional[bytes] = None) -> str:
    """Generic AES-256-GCM encryption with master key (for non-user data)."""
    if key is None:
        key = _get_master_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_string(encrypted: str, key: Optional[bytes] = None) -> str:
    """Generic AES-256-GCM decryption with master key (for non-user data)."""
    if key is None:
        key = _get_master_key()
    aesgcm = AESGCM(key)
    combined = base64.b64decode(encrypted)
    nonce, ciphertext = combined[:12], combined[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()
