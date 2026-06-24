"""
Security & Integration Tests for JWT Auth & Secrets Manager.
Target: 85%+ coverage across cryptographic operations.
"""

import pytest
import base64
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


# ─── Crypto Unit Tests ────────────────────────────────────────────────────────

class TestRSAKeys:
    def test_generate_key_pair_returns_pem_bytes(self):
        from app.auth.rsa_keys import generate_rsa_key_pair
        private_pem, public_pem = generate_rsa_key_pair()
        assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_key_pair_is_2048_bits(self):
        from app.auth.rsa_keys import generate_rsa_key_pair
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        private_pem, _ = generate_rsa_key_pair()
        private_key = load_pem_private_key(private_pem, password=None)
        assert private_key.key_size == 2048

    def test_each_generation_produces_unique_keys(self):
        from app.auth.rsa_keys import generate_rsa_key_pair
        priv1, pub1 = generate_rsa_key_pair()
        priv2, pub2 = generate_rsa_key_pair()
        assert priv1 != priv2
        assert pub1 != pub2

    def test_rotate_keys_returns_new_public_key(self, tmp_path, monkeypatch):
        from app.auth import rsa_keys
        monkeypatch.setattr(rsa_keys, "KEYS_DIR", tmp_path / "keys")
        result = rsa_keys.rotate_keys()
        assert "public_key" in result
        assert "rotated_at" in result
        assert "BEGIN PUBLIC KEY" in result["public_key"]


class TestAESEncryption:
    def test_encrypt_returns_base64_string(self):
        from app.auth.aes_encrypt import encrypt_secret
        encrypted = encrypt_secret("my-secret-value", user_id=1)
        # Should be valid base64
        decoded = base64.b64decode(encrypted)
        assert len(decoded) > 12  # nonce(12) + tag(16) + ciphertext

    def test_encrypt_decrypt_roundtrip(self):
        from app.auth.aes_encrypt import encrypt_secret, decrypt_secret
        original = "super-secret-api-key-12345"
        encrypted = encrypt_secret(original, user_id=42)
        decrypted = decrypt_secret(encrypted, user_id=42)
        assert decrypted == original

    def test_different_users_produce_different_ciphertext(self):
        from app.auth.aes_encrypt import encrypt_secret
        value = "same-secret"
        enc1 = encrypt_secret(value, user_id=1)
        enc2 = encrypt_secret(value, user_id=2)
        assert enc1 != enc2

    def test_same_plaintext_produces_different_ciphertext(self):
        """Each encryption uses a random nonce — ciphertext must never repeat."""
        from app.auth.aes_encrypt import encrypt_secret
        enc1 = encrypt_secret("same-value", user_id=1)
        enc2 = encrypt_secret("same-value", user_id=1)
        assert enc1 != enc2

    def test_wrong_user_cannot_decrypt(self):
        from app.auth.aes_encrypt import encrypt_secret, decrypt_secret
        encrypted = encrypt_secret("secret", user_id=1)
        with pytest.raises(ValueError):
            decrypt_secret(encrypted, user_id=2)

    def test_tampered_ciphertext_raises_error(self):
        from app.auth.aes_encrypt import encrypt_secret, decrypt_secret
        encrypted = encrypt_secret("secret", user_id=1)
        # Flip a byte in the ciphertext
        raw = bytearray(base64.b64decode(encrypted))
        raw[-1] ^= 0xFF
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError):
            decrypt_secret(tampered, user_id=1)

    def test_per_user_key_derivation_is_deterministic(self):
        from app.auth.aes_encrypt import derive_user_key
        key1 = derive_user_key(99)
        key2 = derive_user_key(99)
        assert key1 == key2
        assert len(key1) == 32  # 256 bits


class TestJWTHandler:
    @pytest.fixture(autouse=True)
    def setup_keys(self, tmp_path, monkeypatch):
        from app.auth import rsa_keys
        monkeypatch.setattr(rsa_keys, "KEYS_DIR", tmp_path / "keys")
        rsa_keys.initialize_keys()
        # Patch jwt_handler to use the same keys dir
        monkeypatch.setattr("app.auth.jwt_handler.load_private_key", rsa_keys.load_private_key)
        monkeypatch.setattr("app.auth.jwt_handler.load_public_key", rsa_keys.load_public_key)

    def test_create_and_verify_access_token(self):
        from app.auth.jwt_handler import create_access_token, verify_token
        token = create_access_token({"sub": "test@example.com", "role": "user"})
        payload = verify_token(token)
        assert payload["sub"] == "test@example.com"
        assert payload["type"] == "access"

    def test_create_and_verify_refresh_token(self):
        from app.auth.jwt_handler import create_refresh_token, verify_token
        token = create_refresh_token({"sub": "test@example.com", "role": "user"})
        payload = verify_token(token)
        assert payload["type"] == "refresh"

    def test_expired_token_raises_error(self):
        from datetime import timedelta
        from jose.exceptions import ExpiredSignatureError
        from app.auth.jwt_handler import create_access_token, verify_token
        token = create_access_token({"sub": "test@example.com"}, expires_delta=timedelta(seconds=-1))
        with pytest.raises(ExpiredSignatureError):
            verify_token(token)

    def test_tampered_token_raises_error(self):
        from jose import JWTError
        from app.auth.jwt_handler import create_access_token, verify_token
        token = create_access_token({"sub": "test@example.com"})
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(JWTError):
            verify_token(tampered)

    def test_token_uses_rs256_algorithm(self):
        from jose import jwt as jose_jwt
        from app.auth.jwt_handler import create_access_token
        from app.auth.rsa_keys import load_private_key
        token = create_access_token({"sub": "test@example.com"})
        header = jose_jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"


class TestRedisBlacklist:
    def test_blacklist_and_check_token(self):
        from datetime import timedelta
        from unittest.mock import MagicMock, patch
        mock_redis = MagicMock()
        mock_redis.exists.return_value = 1
        with patch("app.auth.redis_client.get_redis", return_value=mock_redis):
            from app.auth.redis_client import blacklist_token, is_token_blacklisted
            blacklist_token("test-jti", timedelta(minutes=15))
            assert is_token_blacklisted("test-jti") is True

    def test_non_blacklisted_token_passes(self):
        mock_redis = MagicMock()
        mock_redis.exists.return_value = 0
        with patch("app.auth.redis_client.get_redis", return_value=mock_redis):
            from app.auth.redis_client import is_token_blacklisted
            assert is_token_blacklisted("clean-jti") is False

    def test_rate_limit_allows_under_limit(self):
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.return_value = [5, True]
        mock_redis.pipeline.return_value = mock_pipe
        with patch("app.auth.redis_client.get_redis", return_value=mock_redis):
            from app.auth.redis_client import rate_limit_check
            assert rate_limit_check("test-ip", limit=10, window=60) is True

    def test_rate_limit_blocks_over_limit(self):
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.return_value = [11, True]
        mock_redis.pipeline.return_value = mock_pipe
        with patch("app.auth.redis_client.get_redis", return_value=mock_redis):
            from app.auth.redis_client import rate_limit_check
            assert rate_limit_check("test-ip", limit=10, window=60) is False


# ─── Integration Tests ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """Create a test client with in-memory SQLite and mocked Redis."""
    from unittest.mock import patch, MagicMock
    import app.database as db_module

    mock_redis = MagicMock()
    mock_redis.exists.return_value = 0
    mock_pipe = MagicMock()
    mock_pipe.execute.return_value = [1, True]
    mock_redis.pipeline.return_value = mock_pipe

    with patch("app.auth.redis_client._redis_client", mock_redis), \
         patch("app.database.engine", create_engine("sqlite:///:memory:")), \
         patch("app.database.SessionLocal", sessionmaker(bind=create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}))):

        from app.main import app
        from app.database import Base
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        TestSession = sessionmaker(bind=test_engine)
        Base.metadata.create_all(bind=test_engine)

        def override_get_db():
            db = TestSession()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[db_module.get_db] = override_get_db

        with TestClient(app) as c:
            yield c

        app.dependency_overrides.clear()


class TestPasswordSecurity:
    def test_weak_password_rejected(self):
        """Passwords must meet strength requirements."""
        from app.models.user import UserRegister
        with pytest.raises(Exception):
            UserRegister(email="test@test.com", password="weak")

    def test_no_uppercase_rejected(self):
        from app.models.user import UserRegister
        with pytest.raises(Exception):
            UserRegister(email="test@test.com", password="nouppercase1")

    def test_no_digit_rejected(self):
        from app.models.user import UserRegister
        with pytest.raises(Exception):
            UserRegister(email="test@test.com", password="NoDigitHere")

    def test_strong_password_accepted(self):
        from app.models.user import UserRegister
        user = UserRegister(email="test@test.com", password="StrongPass1!")
        assert user.password == "StrongPass1!"


class TestRBACRoles:
    def test_role_hierarchy_ordering(self):
        from app.auth.middleware import ROLE_HIERARCHY
        from app.database import UserRole
        assert ROLE_HIERARCHY[UserRole.ADMIN] > ROLE_HIERARCHY[UserRole.USER]
        assert ROLE_HIERARCHY[UserRole.USER] > ROLE_HIERARCHY[UserRole.GUEST]

    def test_admin_has_highest_level(self):
        from app.auth.middleware import ROLE_HIERARCHY
        from app.database import UserRole
        assert ROLE_HIERARCHY[UserRole.ADMIN] == max(ROLE_HIERARCHY.values())
