# JWT Auth \& Secrets Manager

A production-grade cryptographic service implementing RSA 2048-bit JWT signing, AES-256 secret storage, role-based access control, and automated key rotation — built to demonstrate applied cryptographic engineering.

[!\[CI/CD](https://github.com/YOUR_USERNAME/jwt-secrets-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/Chetan-dev-coder/jwt-secrets-manager/actions)
[!\[Coverage](https://codecov.io/gh/YOUR_USERNAME/jwt-secrets-manager/branch/main/graph/badge.svg)](https://codecov.io/gh/Chetan-dev-coder/jwt-secrets-manager)
!\[Python](https://img.shields.io/badge/Python-3.11-blue)
!\[FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)

\---

## Architecture

```
┌─────────────┐    JWT (RS256)    ┌──────────────────┐
│   Client    │ ────────────────► │   FastAPI App    │
└─────────────┘                   └────────┬─────────┘
                                           │
              ┌────────────────────────────┼────────────────────────┐
              │                            │                         │
    ┌─────────▼──────┐         ┌──────────▼───────┐      ┌─────────▼──────┐
    │  PostgreSQL    │         │     Redis         │      │   RSA Keys     │
    │  Users +       │         │  Token Blacklist  │      │  /keys/\\\*.pem   │
    │  AES-256       │         │  Rate Limiting    │      │  (disk, 0600)  │
    │  Secrets       │         └───────────────────┘      └────────────────┘
    └────────────────┘
```

## Security Design

### Why RSA (RS256) over HMAC (HS256) for JWT?

||RS256|HS256|
|-|-|-|
|Key type|Asymmetric (public/private)|Symmetric (shared secret)|
|Verification|Public key only — never exposes private key|Requires sharing the secret key|
|Best for|Distributed systems, microservices|Single-server, simple setups|
|Key rotation|Rotate private key; distribute new public key|Must re-distribute secret to all verifiers|

This project uses RS256: the private key lives only on the auth server. Any service can verify tokens using the public key without ever seeing the private key.

### AES-256-GCM Secret Encryption

```
Master Key (env var)
       │
       ▼ HKDF(SHA-256, user\\\_id)
Per-User Key (256-bit)
       │
       ▼ AES-256-GCM + random 12-byte nonce
Ciphertext = nonce(12B) + auth\\\_tag(16B) + encrypted\\\_data
       │
       ▼ base64 encode
Stored in PostgreSQL
```

Key design decisions:

* **Per-user derived keys** — compromise of one user's key doesn't affect others
* **GCM mode** — authenticated encryption detects any tampering with ciphertext
* **Random nonce per encryption** — same plaintext never produces the same ciphertext
* **Master key in environment** — never stored in the database

### Token Lifecycle

```
Login → Access Token (15min) + Refresh Token (7 days)
                │                      │
                ▼                      ▼
         Used for API auth      Stored JTI in Redis
                │                      │
         Expires → use Refresh   Blacklisted on logout
                │
         New Access + Refresh (rotation)
                │
         Old Refresh blacklisted in Redis
```

### RBAC (Role-Based Access Control)

|Role|Permissions|
|-|-|
|ADMIN|All secrets, key rotation, all users|
|USER|Own secrets CRUD|
|GUEST|Read-only own secrets|

\---

## Tech Stack

|Layer|Technology|Purpose|
|-|-|-|
|Language|Python 3.11|Primary language|
|Framework|FastAPI|REST API + async|
|Cryptography|RSA 2048 + AES-256-GCM|Token signing + secret encryption|
|Key Derivation|HKDF-SHA256|Per-user encryption keys|
|Auth|python-jose|JWT generation and validation|
|Database|PostgreSQL + SQLAlchemy|Users, secrets, audit logs|
|Cache|Redis|Token blacklisting + rate limiting|
|Hashing|bcrypt|Password storage|
|Container|Docker + Compose|Deployment|
|CI/CD|GitHub Actions|Automated testing + build|
|Testing|Pytest + httpx|85%+ coverage|

\---

## API Endpoints

|Method|Endpoint|Auth|Description|
|-|-|-|-|
|POST|`/auth/register`|None|Create user account|
|POST|`/auth/login`|None|Get JWT access + refresh tokens|
|POST|`/auth/refresh`|Refresh token|Rotate and get new tokens|
|POST|`/auth/logout`|Bearer|Revoke all user tokens|
|POST|`/auth/rotate-keys`|Admin|Rotate RSA key pair|
|GET|`/auth/me`|Bearer|Current user profile|
|GET|`/secrets/`|Bearer|List secrets (no values)|
|POST|`/secrets/`|Bearer|Store encrypted secret|
|GET|`/secrets/{id}`|Bearer|Retrieve + decrypt secret|
|PUT|`/secrets/{id}`|Bearer|Update secret|
|DELETE|`/secrets/{id}`|Bearer|Delete secret|
|GET|`/health`|None|Health check|

\---

## Quick Start

### With Docker (recommended)

```bash
git clone https://github.com/Chetan-dev-coder/jwt-secrets-manager
cd jwt-secrets-manager
cp .env.example .env
docker compose up --build
```

API docs at: http://localhost:8000/docs

### Local Development

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\\\\Scripts\\\\activate
pip install -r requirements.txt

# Start PostgreSQL and Redis (or use Docker)
docker compose up db redis -d

cp .env.example .env
uvicorn app.main:app --reload
```

### Run Tests

```bash
pytest tests/ -v --cov=app --cov-report=term-missing
```

\---

## Example Usage

```bash
# Register
curl -X POST http://localhost:8000/auth/register \\\\
  -H "Content-Type: application/json" \\\\
  -d '{"email": "user@example.com", "password": "SecurePass1!"}'

# Login → get tokens
curl -X POST http://localhost:8000/auth/login \\\\
  -H "Content-Type: application/json" \\\\
  -d '{"email": "user@example.com", "password": "SecurePass1!"}'

# Store a secret (encrypted with AES-256)
curl -X POST http://localhost:8000/secrets/ \\\\
  -H "Authorization: Bearer <access\\\_token>" \\\\
  -H "Content-Type: application/json" \\\\
  -d '{"name": "stripe-api-key", "value": "sk\\\_live\\\_...", "rotate\\\_after\\\_days": 30}'

# Retrieve and decrypt secret
curl http://localhost:8000/secrets/1 \\\\
  -H "Authorization: Bearer <access\\\_token>"
```

\---

## Project Structure

```
jwt-secrets-manager/
├── app/
│   ├── main.py              # FastAPI entry point, lifespan hooks
│   ├── config.py            # Pydantic settings from env vars
│   ├── database.py          # SQLAlchemy models + session
│   ├── auth/
│   │   ├── rsa\\\_keys.py      # RSA 2048-bit key generation + rotation
│   │   ├── jwt\\\_handler.py   # JWT sign/verify with RS256
│   │   ├── aes\\\_encrypt.py   # AES-256-GCM encryption/decryption
│   │   ├── redis\\\_client.py  # Token blacklisting + rate limiting
│   │   └── middleware.py    # RBAC dependencies + audit logging
│   ├── routes/
│   │   ├── auth.py          # /auth/\\\* endpoints
│   │   └── secrets.py       # /secrets/\\\* endpoints
│   └── models/
│       └── user.py          # Pydantic request/response schemas
├── tests/
│   └── test\\\_auth.py         # Security + integration tests (85%+ coverage)
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
└── requirements.txt
```

\---

## Interview Q\&A

**Why RSA over HMAC for JWT?**
RSA is asymmetric — the private key signs tokens and never leaves the auth server. Any downstream service verifies using the public key only. With HMAC, every verifier needs the same shared secret, which is a security risk in distributed systems.

**How does AES-256-GCM work here?**
Each secret is encrypted with a 256-bit key derived per-user via HKDF. GCM mode provides authenticated encryption — it generates an authentication tag that detects any tampering. The ciphertext format is `nonce(12B) + tag(16B) + ciphertext`, all base64-encoded before PostgreSQL storage.

**What is key rotation?**
Periodically replacing cryptographic keys limits the damage if a key is compromised. Here, rotation archives the old key pair and generates a new RSA pair. All existing tokens become invalid (they were signed with the old private key, which the new public key cannot verify), forcing users to re-authenticate.

**How are tokens revoked?**
Redis stores a blacklist of JWT IDs (JTI claims). On logout or rotation, the JTI is added to Redis with TTL equal to the token's remaining lifetime. Every authenticated request checks the blacklist. Redis TTL auto-cleans expired entries.

**How are secrets secured at rest?**
AES-256-GCM encryption before DB write. Per-user keys derived from a master key (stored only in env vars). Keys are never stored in the database. Decrypted values are only returned on explicit single-GET requests, never in list responses.

\---

## License

MIT

