"""Pytest configuration — shared fixtures for all test suites.

Uses SQLite in-memory database for fast, isolated unit and integration tests.
No external services required for the test suite.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from uuid import uuid4

import jwt
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.domain.models import SecurityIdentity, UserRole
from src.infrastructure.audit import AuditEventORM, SqlAlchemyAuditRegistry
from src.infrastructure.crypto import HmacIntegrityService
from src.infrastructure.persistence import (
    Base,
    SqlAlchemyDispatchRepository,
)
from src.main import create_app

# ---------------------------------------------------------------------------
# Environment setup for tests
# ---------------------------------------------------------------------------

os.environ.setdefault("SECRET_KEY", "test_secret_key_for_pytest_only_64chars_aabbccddee")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("AES_256_KEY_HEX", "a" * 64)
os.environ.setdefault("MOCK_CLIENT_SECRET", "test_mock_client_secret_hmac_key")

_TEST_DB_URL = "sqlite+aiosqlite:///./test_badnass.db"
_SECRET_KEY = os.environ["SECRET_KEY"]
_JWT_ALGORITHM = os.environ["JWT_ALGORITHM"]
_MOCK_SECRET = os.environ["MOCK_CLIENT_SECRET"]


# ---------------------------------------------------------------------------
# Async Engine / Session Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Create a fresh in-memory SQLite engine for each test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Also create audit events table
        await conn.run_sync(AuditEventORM.__table__.create, checkfirst=True)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a clean async DB session per test."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def dispatch_repo(db_session: AsyncSession) -> SqlAlchemyDispatchRepository:
    """Dispatch repository backed by in-memory SQLite."""
    return SqlAlchemyDispatchRepository(db_session)


@pytest_asyncio.fixture(scope="function")
async def audit_registry(db_session: AsyncSession) -> SqlAlchemyAuditRegistry:
    """Audit registry backed by in-memory SQLite."""
    return SqlAlchemyAuditRegistry(db_session)


# ---------------------------------------------------------------------------
# Domain Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def hmac_verifier() -> HmacIntegrityService:
    return HmacIntegrityService()


@pytest.fixture
def operator_identity() -> SecurityIdentity:
    return SecurityIdentity(
        user_id="user-operator-001",
        client_id="client-erp-001",
        role=UserRole.OPERATOR,
        jti=str(uuid4()),
        has_privilege=False,
    )


@pytest.fixture
def technician_identity() -> SecurityIdentity:
    return SecurityIdentity(
        user_id="user-tech-001",
        client_id="client-it-001",
        role=UserRole.TECHNICIAN,
        jti=str(uuid4()),
        has_privilege=True,
    )


@pytest.fixture
def admin_identity() -> SecurityIdentity:
    return SecurityIdentity(
        user_id="user-admin-001",
        client_id="client-admin-001",
        role=UserRole.SEC_ADMIN,
        jti=str(uuid4()),
        has_privilege=True,
    )


# ---------------------------------------------------------------------------
# JWT Token Helpers
# ---------------------------------------------------------------------------


def make_jwt(role: UserRole, user_id: str = "test-user") -> str:
    """Generate a valid JWT token for testing."""
    jti = str(uuid4())
    now = datetime.now(UTC)
    from datetime import timedelta
    payload = {
        "sub": user_id,
        "role": role.value,
        "client_id": "client-test-001",
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(hours=1),
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_JWT_ALGORITHM)


def make_hmac(payload: bytes, secret: str = _MOCK_SECRET) -> str:
    """Generate an HMAC-SHA256 signature for the given payload."""
    return hmac_lib.new(secret.encode(), payload, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# FastAPI Test Client Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def test_app(db_engine) -> FastAPI:
    """Create a test FastAPI app wired to the in-memory DB."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)
    app = create_app(
        database_url="sqlite+aiosqlite:///:memory:",
        redis_url=None,
    )
    app.state.engine = db_engine
    app.state.session_factory = factory
    app.state.redis = None  # No Redis in tests
    return app


@pytest_asyncio.fixture(scope="function")
async def async_client(test_app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client for integration tests."""
    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client
