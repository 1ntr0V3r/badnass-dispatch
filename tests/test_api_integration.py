"""API integration tests — full stack tests using httpx.AsyncClient.

Tests (per specification):
  1. POST /dispatch nominal → 201 Created
  2. POST /dispatch missing JWT → 401/403 Unauthorized
  3. POST /dispatch duplicate idempotency key → 409 Conflict
  4. POST /dispatch tampered HMAC signature → 400 Bad Request
  5. POST /dispatch overweight order → 422 Unprocessable Entity (Pydantic) or 400
  6. Forced internal crash → opaque RFC 7807 with incident_id (no stack trace)
  7. RBAC gating: OPERATOR denied, TECHNICIAN authorized on /tech/incidents/{id}
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.api.dependencies import hash_password
from src.api.errors import register_exception_handlers
from src.api.routes import router
from src.infrastructure.audit import AuditEventORM, SqlAlchemyAuditRegistry
from src.infrastructure.persistence import Base, UserORM

# ── Constants — MUST match what the app reads from os.getenv ───────────────
_SECRET_KEY = "test_secret_key_for_pytest_only_64chars_aabbccddee"
_JWT_ALGORITHM = "HS256"
_MOCK_SECRET = "test_mock_client_secret_hmac_key"

os.environ["SECRET_KEY"] = _SECRET_KEY
os.environ["JWT_ALGORITHM"] = _JWT_ALGORITHM
os.environ["MOCK_CLIENT_SECRET"] = _MOCK_SECRET


# ---------------------------------------------------------------------------
# Test App Factory — builds the app inline with the seeded engine
# ---------------------------------------------------------------------------


def _build_test_app(engine, factory) -> FastAPI:
    """Build a minimal FastAPI app wired directly to the provided engine+session."""
    app = FastAPI(title="BADNASS Test App")
    register_exception_handlers(app)
    app.include_router(router)

    @app.get("/health", include_in_schema=False)
    async def health() -> dict:
        return {"status": "healthy"}

    app.state.engine = engine
    app.state.session_factory = factory
    app.state.redis = None
    return app


@pytest_asyncio.fixture
async def app_with_db() -> AsyncGenerator[FastAPI, None]:
    """Create a test app with a single shared in-memory SQLite DB."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(AuditEventORM.__table__.create, checkfirst=True)

    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    # Seed test users
    async with factory() as session:
        session.add(UserORM(
            id=uuid4(),
            username="test_operator",
            role="OPERATOR",
            password_hash=hash_password("SecurePass123!"),
            is_active=True,
        ))
        session.add(UserORM(
            id=uuid4(),
            username="test_technician",
            role="TECHNICIAN",
            password_hash=hash_password("TechPass123!"),
            is_active=True,
        ))
        await session.commit()

    app = _build_test_app(engine, factory)
    yield app
    await engine.dispose()


@pytest_asyncio.fixture
async def client(app_with_db: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(
        transport=ASGITransport(app=app_with_db),
        base_url="http://testserver",
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# JWT Token Helpers
# ---------------------------------------------------------------------------


def make_jwt_token(role: str, user_id: str | None = None) -> str:
    """Generate a valid JWT signed with the test SECRET_KEY."""
    now = datetime.now(UTC)
    payload = {
        "sub": user_id or str(uuid4()),
        "role": role,
        "client_id": "client-test-001",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + timedelta(hours=1),
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_JWT_ALGORITHM)


def make_dispatch_headers(
    payload: bytes,
    idempotency_key: str | None = None,
    token: str | None = None,
    timestamp: float | None = None,
    hmac_sig: str | None = None,
    client_id: str = "client-test-001",
) -> dict:
    now_ts = timestamp or datetime.now(UTC).timestamp()
    sig = hmac_sig or hmac_lib.new(_MOCK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return {
        "Authorization": f"Bearer {token or make_jwt_token('OPERATOR')}",
        "X-Client-ID": client_id,
        "X-Timestamp": str(now_ts),
        "X-Idempotency-Key": idempotency_key or str(uuid4()),
        "X-Signature-HMAC": sig,
        "Content-Type": "application/json",
    }


def valid_dispatch_payload(tracking_ref: str = "TNG-TEST-001") -> dict:
    return {
        "tracking_ref": tracking_ref,
        "origin_hub": "TANGIER_MED",
        "destination_hub": "CASABLANCA_PORT",
        "transport_mode": "ROAD_TIR",
        "gross_weight_kg": 20000.0,
    }


# ---------------------------------------------------------------------------
# Test 1: Nominal 201 Response
# ---------------------------------------------------------------------------


class TestDispatchNominal:
    @pytest.mark.asyncio
    async def test_submit_dispatch_returns_201(self, client: AsyncClient) -> None:
        """Nominal dispatch submission with valid JWT and HMAC → 201 Created."""
        body = json.dumps(valid_dispatch_payload()).encode()
        headers = make_dispatch_headers(body)

        response = await client.post("/api/v1/dispatch", content=body, headers=headers)

        assert response.status_code == 201, response.text
        data = response.json()
        assert "order_id" in data
        assert data["status"] == "PENDING_CUSTOMS"
        assert data["tracking_ref"] == "TNG-TEST-001"


# ---------------------------------------------------------------------------
# Test 2: Missing/Invalid JWT → 401/403
# ---------------------------------------------------------------------------


class TestMissingJwt:
    @pytest.mark.asyncio
    async def test_missing_jwt_returns_unauthenticated(self, client: AsyncClient) -> None:
        """No Authorization header → 403 (HTTPBearer) or 401."""
        body = json.dumps(valid_dispatch_payload()).encode()
        headers = {
            "X-Client-ID": "client-test-001",
            "X-Timestamp": str(datetime.now(UTC).timestamp()),
            "X-Idempotency-Key": str(uuid4()),
            "X-Signature-HMAC": "deadbeef",
            "Content-Type": "application/json",
        }

        response = await client.post("/api/v1/dispatch", content=body, headers=headers)

        # HTTPBearer raises 403 when no token provided, 401 when invalid
        assert response.status_code in {401, 403}, response.text

    @pytest.mark.asyncio
    async def test_invalid_jwt_returns_401(self, client: AsyncClient) -> None:
        """Invalid JWT → 401 Unauthorized."""
        body = json.dumps(valid_dispatch_payload()).encode()
        headers = make_dispatch_headers(body, token="invalid.jwt.token")

        response = await client.post("/api/v1/dispatch", content=body, headers=headers)

        assert response.status_code == 401, response.text


# ---------------------------------------------------------------------------
# Test 3: Duplicate Idempotency Key → 409
# ---------------------------------------------------------------------------


class TestDuplicateIdempotencyKey:
    @pytest.mark.asyncio
    async def test_duplicate_key_returns_409(self, client: AsyncClient) -> None:
        """Second request with same idempotency key → 409 Conflict."""
        body = json.dumps(valid_dispatch_payload("TNG-IDEM-001")).encode()
        idem_key = str(uuid4())
        headers = make_dispatch_headers(body, idempotency_key=idem_key)

        # First request — should succeed
        r1 = await client.post("/api/v1/dispatch", content=body, headers=headers)
        assert r1.status_code == 201, r1.text

        # Second request with SAME idempotency key
        body2 = json.dumps(valid_dispatch_payload("TNG-IDEM-002")).encode()
        headers2 = make_dispatch_headers(body2, idempotency_key=idem_key)
        r2 = await client.post("/api/v1/dispatch", content=body2, headers=headers2)

        assert r2.status_code == 409, r2.text


# ---------------------------------------------------------------------------
# Test 4: Tampered HMAC Signature → 400
# ---------------------------------------------------------------------------


class TestTamperedSignature:
    @pytest.mark.asyncio
    async def test_tampered_hmac_returns_400(self, client: AsyncClient) -> None:
        """Wrong HMAC signature → 400 Bad Request."""
        body = json.dumps(valid_dispatch_payload("TNG-HMAC-001")).encode()
        bad_sig = "0" * 64  # All zeros — invalid signature
        headers = make_dispatch_headers(body, hmac_sig=bad_sig)

        response = await client.post("/api/v1/dispatch", content=body, headers=headers)

        assert response.status_code == 400, response.text


# ---------------------------------------------------------------------------
# Test 5: Overweight Order → 422 (Pydantic schema) or 400 (domain)
# ---------------------------------------------------------------------------


class TestOverweightOrder:
    @pytest.mark.asyncio
    async def test_overweight_returns_4xx(self, client: AsyncClient) -> None:
        """Order exceeding 44t TIR limit → 422 (Pydantic le=44000) or 400 (domain)."""
        overweight = valid_dispatch_payload("TNG-OVRW-001")
        overweight["gross_weight_kg"] = 50000.0  # Exceeds 44t limit
        body = json.dumps(overweight).encode()
        headers = make_dispatch_headers(body)

        response = await client.post("/api/v1/dispatch", content=body, headers=headers)

        # Pydantic catches it at schema level (le=44000) → 422
        # Or domain validation catches it → 400/422
        assert response.status_code in {400, 422}, response.text


# ---------------------------------------------------------------------------
# Test 6: Internal Crash → Opaque RFC 7807 with incident_id
# ---------------------------------------------------------------------------


class TestInternalCrashHandler:
    @pytest.mark.asyncio
    async def test_forced_crash_returns_opaque_rfc7807(
        self, app_with_db: FastAPI
    ) -> None:
        """Unhandled exception → opaque RFC 7807 JSON with incident_id, no stack trace."""

        # Register crash endpoint BEFORE creating client
        @app_with_db.get("/api/v1/test/crash-endpoint")
        async def crash_endpoint() -> None:
            msg = "Simulated internal system failure"
            raise RuntimeError(msg)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_db, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as c:
            response = await c.get("/api/v1/test/crash-endpoint")

        assert response.status_code == 500, response.text
        data = response.json()

        # Must have incident_id (for technician lookup)
        assert "incident_id" in data, f"RFC 7807 must have incident_id. Got: {data}"

        # Must NOT contain any stack trace information or sensitive fields
        response_text = response.text
        assert "RuntimeError" not in response_text, "Stack trace must not leak to client"
        assert "Traceback" not in response_text, "Traceback must not leak to client"
        assert "detail" not in data, "RFC 7807: 'detail' field must not expose internal info"
        assert "exception" not in data, "RFC 7807: 'exception' field must not be present"

        # Must have all RFC 7807 mandatory fields
        assert "type" in data, "RFC 7807 requires 'type'"
        assert "title" in data, "RFC 7807 requires 'title'"
        assert "status" in data, "RFC 7807 requires 'status'"
        assert data["status"] == 500
        assert data["type"] == "https://badnass.ma/errors/internal-system-error", (
            f"Expected canonical error type URI, got: {data['type']}"
        )


# ---------------------------------------------------------------------------
# Test 7: RBAC Gating — /tech/incidents/{id}
# ---------------------------------------------------------------------------


class TestRbacIncidentEndpoint:
    @pytest.mark.asyncio
    async def test_operator_is_denied_incident_access(self, client: AsyncClient) -> None:
        """OPERATOR role must be denied access to incident endpoint → 403."""
        operator_token = make_jwt_token("OPERATOR")
        response = await client.get(
            "/api/v1/tech/incidents/nonexistent-id",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert response.status_code == 403, response.text

    @pytest.mark.asyncio
    async def test_b2b_client_is_denied_incident_access(self, client: AsyncClient) -> None:
        """B2B_CLIENT role must be denied access to incident endpoint → 403."""
        b2b_token = make_jwt_token("B2B_CLIENT")
        response = await client.get(
            "/api/v1/tech/incidents/nonexistent-id",
            headers={"Authorization": f"Bearer {b2b_token}"},
        )
        assert response.status_code == 403, response.text

    @pytest.mark.asyncio
    async def test_technician_can_access_incident_endpoint(
        self, client: AsyncClient
    ) -> None:
        """TECHNICIAN passes RBAC → 404 (incident not found, not 403)."""
        tech_token = make_jwt_token("TECHNICIAN")
        response = await client.get(
            "/api/v1/tech/incidents/nonexistent-id",
            headers={"Authorization": f"Bearer {tech_token}"},
        )
        # 404 means they PASSED RBAC but the incident doesn't exist — correct behavior
        assert response.status_code == 404, response.text

    @pytest.mark.asyncio
    async def test_sec_admin_can_access_incident_endpoint(
        self, client: AsyncClient
    ) -> None:
        """SEC_ADMIN passes RBAC → 404 (incident not found, not 403)."""
        admin_token = make_jwt_token("SEC_ADMIN")
        response = await client.get(
            "/api/v1/tech/incidents/nonexistent-id",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404, response.text

    @pytest.mark.asyncio
    async def test_technician_retrieves_real_incident(
        self, app_with_db: FastAPI
    ) -> None:
        """Technician retrieves a real incident with unmasked stack trace."""
        factory = app_with_db.state.session_factory
        incident_id = str(uuid4())

        async with factory() as session:
            audit = SqlAlchemyAuditRegistry(session)
            await audit.capture_incident(
                incident_id=incident_id,
                actor_id="system",
                error_type="TestError",
                stack_trace="File test.py line 42 in test\n  raise TestError()",
                metadata={"path": "/api/v1/test"},
            )

        tech_token = make_jwt_token("TECHNICIAN")

        async with AsyncClient(
            transport=ASGITransport(app=app_with_db),
            base_url="http://testserver",
        ) as c:
            response = await c.get(
                f"/api/v1/tech/incidents/{incident_id}",
                headers={"Authorization": f"Bearer {tech_token}"},
            )

        assert response.status_code == 200, response.text
        data = response.json()
        assert data["incident_id"] == incident_id
        assert "stack_trace" in data  # Unmasked for privileged roles
        assert data["error_type"] == "TestError"
