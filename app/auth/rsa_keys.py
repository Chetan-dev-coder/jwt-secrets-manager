"""
RSA 2048-bit Key Pair Generation and Management.
Handles key generation, persistence, loading, and rotation.
"""

import os
import logging
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

KEYS_DIR = Path("keys")


def ensure_keys_dir():
    """Create keys directory with secure permissions."""
    KEYS_DIR.mkdir(exist_ok=True)
    os.chmod(KEYS_DIR, 0o700)


def generate_rsa_key_pair() -> tuple[bytes, bytes]:
    """
    Generate RSA 2048-bit key pair.

    Returns:
        Tuple of (private_key_pem, public_key_pem) as bytes.

    Why RSA over HMAC for JWT?
    - Asymmetric: verifiers only need the public key.
    - Private key never leaves the auth server.
    - Ideal for distributed microservices.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    logger.info("RSA 2048-bit key pair generated successfully")
    return private_pem, public_pem


def save_key_pair(private_pem: bytes, public_pem: bytes, version: str = "current"):
    """Save key pair to disk with secure file permissions."""
    ensure_keys_dir()

    private_path = KEYS_DIR / f"private_{version}.pem"
    public_path = KEYS_DIR / f"public_{version}.pem"

    private_path.write_bytes(private_pem)
    os.chmod(private_path, 0o600)  # Owner read/write only

    public_path.write_bytes(public_pem)
    os.chmod(public_path, 0o644)  # Owner read/write, others read

    logger.info(f"Key pair saved with version: {version}")


def load_private_key() -> bytes:
    """Load current private key from disk."""
    path = KEYS_DIR / "private_current.pem"
    if not path.exists():
        raise FileNotFoundError("Private key not found. Run key initialization first.")
    return path.read_bytes()


def load_public_key() -> bytes:
    """Load current public key from disk."""
    path = KEYS_DIR / "public_current.pem"
    if not path.exists():
        raise FileNotFoundError("Public key not found. Run key initialization first.")
    return path.read_bytes()


def rotate_keys() -> dict:
    """
    Rotate RSA key pair.

    Key rotation strategy:
    1. Archive current keys with timestamp.
    2. Generate fresh key pair.
    3. Save as new current keys.
    4. Return new public key for distribution.
    """
    ensure_keys_dir()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Archive current keys if they exist
    current_private = KEYS_DIR / "private_current.pem"
    current_public = KEYS_DIR / "public_current.pem"

    if current_private.exists():
        current_private.rename(KEYS_DIR / f"private_{timestamp}.pem")
        os.chmod(KEYS_DIR / f"private_{timestamp}.pem", 0o600)

    if current_public.exists():
        current_public.rename(KEYS_DIR / f"public_{timestamp}.pem")

    # Generate and save new keys
    private_pem, public_pem = generate_rsa_key_pair()
    save_key_pair(private_pem, public_pem)

    logger.info(f"Key rotation completed. Old keys archived with timestamp: {timestamp}")

    return {
        "rotated_at": timestamp,
        "public_key": public_pem.decode(),
        "message": "Key rotation successful. Old tokens will be invalidated."
    }


def initialize_keys():
    """Initialize keys on startup if they don't exist."""
    if not (KEYS_DIR / "private_current.pem").exists():
        logger.info("No keys found. Generating initial RSA key pair...")
        private_pem, public_pem = generate_rsa_key_pair()
        save_key_pair(private_pem, public_pem)
        logger.info("Initial key pair generated and saved.")
