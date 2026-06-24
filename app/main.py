"""
JWT Auth & Secrets Manager — FastAPI Application Entry Point.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth.rsa_keys import initialize_keys
from app.database import create_tables
from app.routes import auth, secrets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("Starting JWT Auth & Secrets Manager...")
    create_tables()
    initialize_keys()
    logger.info("Startup complete — RSA keys ready, DB tables initialized.")
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="JWT Auth & Secrets Manager",
    description=(
        "Production-grade cryptographic service: RSA 2048-bit JWT signing, "
        "AES-256 secret storage, RBAC, Redis token blacklisting, and audit logging."
    ),
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(secrets.router)


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "jwt-secrets-manager"}


@app.get("/")
def root():
    return {
        "service": "JWT Auth & Secrets Manager",
        "docs": "/docs",
        "health": "/health"
    }
