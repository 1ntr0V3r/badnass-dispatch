"""API dependency injection — JWT authentication and infrastructure wiring.

Security controls:
  - Argon2id password hashing (OWASP recommended)
  - JWT validation with jti revocation check in Redis
  - DB session lifecycle management
  - Audit registry injection into request state
"""

from __future__ import annotations

import os
from typing import Annotated

import jwt
import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.models import SecurityIdentity, UserRole

# ---------------------------------------------------------------------------
# Password Hashing
# ---------------------------------------------------------------------------

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

bearer_scheme = HTTPBearer(auto_error=True)

# ---------------------------------------------------------------------------
# Settings (loaded from environment)
# ---------------------------------------------------------------------------

_SECRET_KEY = os.getenv("SECRET_KEY", "INSECURE_FALLBACK_FOR_TESTS_ONLY")
_JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
_REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


def hash_password(plain: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    return pwd_context.verify(plain, hashed)


# ---------------------------------------------------------------------------
# JWT Authentication Dependency
# ---------------------------------------------------------------------------


async def get_current_identity(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> SecurityIdentity:
    """Decode and validate JWT, then verify jti is not revoked in Redis.

    Raises:
        HTTPException 401: If token is missing, invalid, expired, or revoked.
    """
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except jwt.InvalidTokenError:
        raise credentials_exception from None

    jti: str | None = payload.get("jti")
    user_id: str | None = payload.get("sub")
    client_id: str | None = payload.get("client_id", "SYSTEM")
    role_str: str | None = payload.get("role")

    if not jti or not user_id or not role_str:
        raise credentials_exception

    try:
        role = UserRole(role_str)
    except ValueError:
        raise credentials_exception from None

    # Check jti revocation list in Redis
    redis_client: aioredis.Redis = getattr(request.app.state, "redis", None)
    if redis_client is not None:
        is_revoked = await redis_client.exists(f"revoked_jti:{jti}")
        if is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    identity = SecurityIdentity(
        user_id=user_id,
        client_id=client_id,
        role=role,
        jti=jti,
        has_privilege=(role in {UserRole.SEC_ADMIN, UserRole.TECHNICIAN}),
    )

    # Inject identity into request state for error handler access
    request.state.identity = identity

    return identity


# ---------------------------------------------------------------------------
# Role Guards
# ---------------------------------------------------------------------------


def require_privilege(identity: Annotated[SecurityIdentity, Depends(get_current_identity)]) -> SecurityIdentity:
    """Dependency that enforces TECHNICIAN or SEC_ADMIN role.

    Raises:
        HTTPException 403: If the caller lacks privilege.
    """
    if not identity.has_privilege:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires TECHNICIAN or SEC_ADMIN role.",
        )
    return identity


# ---------------------------------------------------------------------------
# Database Session Dependency
# ---------------------------------------------------------------------------


async def get_db_session(request: Request) -> AsyncSession:  # type: ignore[misc]
    """Yield an async DB session from the app-level session factory."""
    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        yield session


# ---------------------------------------------------------------------------
# MOCK client secret resolver (replace with DB lookup in production)
# ---------------------------------------------------------------------------


def get_client_secret(client_id: str) -> str:
    """Resolve the pre-shared HMAC secret for a B2B client.

    In production this queries the clients table with decryption.
    For testing, returns the MOCK_CLIENT_SECRET env var.
    """
    return os.getenv("MOCK_CLIENT_SECRET", "test_secret_do_not_use_in_prod")
