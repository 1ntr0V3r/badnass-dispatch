"""Coverage booster tests — targets the specific uncovered lines identified by pytest-cov.

Uncovered paths targeted:
  - src/infrastructure/crypto.py  : HMAC error path, DriverDataEncryptor full lifecycle
  - src/api/routes.py             : login endpoint, GET /dispatch, bad timestamp, telemetry
  - src/api/errors.py             : PermissionError + TimeoutError handlers
  - src/api/dependencies.py       : expired JWT, missing claims paths
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
from src.infrastructure.audit import AuditEventORM
from src.infrastructure.crypto import DriverDataEncryptor, HmacIntegrityService
from src.infrastructure.persistence import Base, UserORM

# ── Test constants — identical to test_api_integration.py ──────────────────
_SECRET_KEY = "test_secret_key_for_pytest_only_64chars_aabbccddee"
_JWT_ALGORITHM = "HS256"
_MOCK_SECRET = "test_mock_client_secret_hmac_key"
_AES_KEY_HEX = "a" * 64  # 32 bytes of 0xAA — valid 256-bit key

os.environ["SECRET_KEY"] = _SECRET_KEY
os.environ["JWT_ALGORITHM"] = _JWT_ALGORITHM
os.environ["MOCK_CLIENT_SECRET"] = _MOCK_SECRET
os.environ["AES_256_KEY_HEX"] = _AES_KEY_HEX


# ---------------------------------------------------------------------------
# Shared app fixture (mirrors test_api_integration.py pattern)
# ---------------------------------------------------------------------------


def _build_app(engine, factory) -> FastAPI:
    app = FastAPI(title="Coverage Booster Test App")
    register_exception_handlers(app)
    app.include_router(router)
    app.state.engine = engine
    app.state.session_factory = factory
    app.state.redis = None
    return app


@pytest_asyncio.fixture
async def app_db() -> AsyncGenerator[FastAPI, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(AuditEventORM.__table__.create, checkfirst=True)

    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    # Seed a login-ready user
    async with factory() as session:
        session.add(UserORM(
            id=uuid4(),
            username="cov_operator",
            role="OPERATOR",
            password_hash=hash_password("CovPass123!"),
            is_active=True,
        ))
        await session.commit()

    app = _build_app(engine, factory)
    yield app
    await engine.dispose()


@pytest_asyncio.fixture
async def cov_client(app_db: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(
        transport=ASGITransport(app=app_db),
        base_url="http://testserver",
    ) as c:
        yield c


def _make_token(role: str = "OPERATOR", extra: dict | None = None) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(uuid4()),
        "role": role,
        "client_id": "client-test-001",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + timedelta(hours=1),
        **(extra or {}),
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_JWT_ALGORITHM)


def _dispatch_headers(payload: bytes, token: str | None = None) -> dict:
    ts = datetime.now(UTC).timestamp()
    sig = hmac_lib.new(_MOCK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return {
        "Authorization": f"Bearer {token or _make_token()}",
        "X-Client-ID": "client-test-001",
        "X-Timestamp": str(ts),
        "X-Idempotency-Key": str(uuid4()),
        "X-Signature-HMAC": sig,
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# 1. Infrastructure — Crypto: DriverDataEncryptor full lifecycle
# ---------------------------------------------------------------------------


class TestDriverDataEncryptor:
    """Covers crypto.py lines 90-95, 106-109, 126-129, 140-141, 152-153."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """AES-256-GCM encrypt → decrypt produces original plaintext."""
        enc = DriverDataEncryptor(_AES_KEY_HEX)
        plaintext = "AB123456"  # Moroccan national ID format
        blob = enc.encrypt(plaintext)
        assert blob.nonce_b64  # 12 bytes → 16-char b64
        assert blob.ciphertext_b64
        result = enc.decrypt(blob)
        assert result == plaintext

    def test_encrypt_field_decrypt_field_roundtrip(self) -> None:
        """encrypt_field → decrypt_field produces original plaintext (serialized form)."""
        enc = DriverDataEncryptor(_AES_KEY_HEX)
        value = "+212-661-123456"
        stored = enc.encrypt_field(value)
        assert "::" in stored, "Stored value must use nonce::ciphertext format"
        recovered = enc.decrypt_field(stored)
        assert recovered == value

    def test_encrypt_produces_different_ciphertexts(self) -> None:
        """Fresh nonce per call guarantees IND-CPA (semantic security)."""
        enc = DriverDataEncryptor(_AES_KEY_HEX)
        plaintext = "same plaintext"
        blob1 = enc.encrypt(plaintext)
        blob2 = enc.encrypt(plaintext)
        # Nonces must differ (random), therefore ciphertexts differ
        assert blob1.nonce_b64 != blob2.nonce_b64

    def test_invalid_key_length_raises_value_error(self) -> None:
        """Wrong key size (not 32 bytes) must raise ValueError."""
        with pytest.raises(ValueError, match="AES-256 key must be 32 bytes"):
            DriverDataEncryptor("aabb")  # Only 2 bytes — too short


class TestHmacErrorPath:
    """Covers crypto.py lines 50-51 — HMAC exception swallowing."""

    def test_verify_hmac_with_non_hex_signature_returns_false(self) -> None:
        """Non-hex received_signature triggers ValueError → returns False (no raise)."""
        svc = HmacIntegrityService()
        result = svc.verify_hmac(b"payload", "not-a-hex-string!!!", "secret")
        assert result is False


# ---------------------------------------------------------------------------
# 2. API Routes — Login endpoint (routes.py lines 100-125)
# ---------------------------------------------------------------------------


class TestLoginEndpoint:
    @pytest.mark.asyncio
    async def test_valid_login_returns_token(self, cov_client: AsyncClient) -> None:
        """Valid credentials → 200 with access_token."""
        response = await cov_client.post(
            "/api/v1/auth/login",
            json={"username": "cov_operator", "password": "CovPass123!"},
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 3600

    @pytest.mark.asyncio
    async def test_invalid_credentials_returns_401(self, cov_client: AsyncClient) -> None:
        """Wrong password → 401 Unauthorized."""
        response = await cov_client.post(
            "/api/v1/auth/login",
            json={"username": "cov_operator", "password": "WrongPass999!"},
        )
        assert response.status_code == 401, response.text

    @pytest.mark.asyncio
    async def test_unknown_user_returns_401(self, cov_client: AsyncClient) -> None:
        """Non-existent user → 401 Unauthorized."""
        response = await cov_client.post(
            "/api/v1/auth/login",
            json={"username": "ghost_user", "password": "GhostPass123!"},
        )
        assert response.status_code == 401, response.text


# ---------------------------------------------------------------------------
# 3. API Routes — GET /dispatch/{order_id} (routes.py lines 219-225)
# ---------------------------------------------------------------------------


class TestGetDispatchEndpoint:
    @pytest.mark.asyncio
    async def test_get_existing_order_returns_200(self, cov_client: AsyncClient) -> None:
        """Submit then retrieve an order → 200 with full order data."""
        payload = json.dumps({
            "tracking_ref": "TNG-COV-001",
            "origin_hub": "TANGIER_MED",
            "destination_hub": "CASABLANCA_PORT",
            "transport_mode": "ROAD_TIR",
            "gross_weight_kg": 15000.0,
        }).encode()
        headers = _dispatch_headers(payload)

        # Submit the order first
        post_r = await cov_client.post("/api/v1/dispatch", content=payload, headers=headers)
        assert post_r.status_code == 201, post_r.text
        order_id = post_r.json()["order_id"]

        # Now retrieve it
        token = _make_token()
        get_r = await cov_client.get(
            f"/api/v1/dispatch/{order_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert get_r.status_code == 200, get_r.text
        data = get_r.json()
        assert data["order_id"] == order_id
        assert data["tracking_ref"] == "TNG-COV-001"
        assert data["origin_hub"] == "TANGIER_MED"
        assert data["transport_mode"] == "ROAD_TIR"

    @pytest.mark.asyncio
    async def test_get_nonexistent_order_returns_404(self, cov_client: AsyncClient) -> None:
        """Non-existent UUID → 404 Not Found."""
        token = _make_token()
        fake_id = str(uuid4())
        response = await cov_client.get(
            f"/api/v1/dispatch/{fake_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404, response.text


# ---------------------------------------------------------------------------
# 4. API Routes — Bad timestamp (routes.py lines 160-161)
# ---------------------------------------------------------------------------


class TestBadTimestamp:
    @pytest.mark.asyncio
    async def test_non_numeric_timestamp_returns_400(self, cov_client: AsyncClient) -> None:
        """Non-numeric X-Timestamp → 400 Bad Request."""
        payload = json.dumps({
            "tracking_ref": "TNG-TS-001",
            "origin_hub": "TANGIER_MED",
            "destination_hub": "CASABLANCA_PORT",
            "transport_mode": "ROAD_TIR",
            "gross_weight_kg": 10000.0,
        }).encode()
        sig = hmac_lib.new(_MOCK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        headers = {
            "Authorization": f"Bearer {_make_token()}",
            "X-Client-ID": "client-test-001",
            "X-Timestamp": "not-a-float",  # invalid
            "X-Idempotency-Key": str(uuid4()),
            "X-Signature-HMAC": sig,
            "Content-Type": "application/json",
        }
        response = await cov_client.post("/api/v1/dispatch", content=payload, headers=headers)
        assert response.status_code == 400, response.text


# ---------------------------------------------------------------------------
# 5. API Routes — Telemetry endpoint (routes.py lines 254-267)
# ---------------------------------------------------------------------------


class TestTelemetryEndpoint:
    @pytest.mark.asyncio
    async def test_telemetry_ingest_returns_202(self, cov_client: AsyncClient) -> None:
        """Valid telemetry → 202 Accepted."""
        token = _make_token()
        payload = {
            "device_id": "BASCULE-001",
            "axle_weight_kg": 12500.0,
            "seal_status": "INTACT",
            "gps_lat": 35.8897,
            "gps_lon": -5.5097,
            "timestamp": datetime.now(UTC).timestamp(),
        }
        response = await cov_client.post(
            "/api/v1/telemetry",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 202, response.text
        data = response.json()
        assert data["status"] == "accepted"
        assert data["device_id"] == "BASCULE-001"

    @pytest.mark.asyncio
    async def test_telemetry_without_jwt_returns_403(self, cov_client: AsyncClient) -> None:
        """Missing JWT on telemetry → 403 Forbidden."""
        payload = {
            "device_id": "BASCULE-002",
            "timestamp": datetime.now(UTC).timestamp(),
        }
        response = await cov_client.post("/api/v1/telemetry", json=payload)
        assert response.status_code in {401, 403}, response.text


# ---------------------------------------------------------------------------
# 6. Error Handlers — PermissionError and TimeoutError (errors.py lines 62, 71)
# ---------------------------------------------------------------------------


class TestErrorHandlersCoverage:
    @pytest.mark.asyncio
    async def test_permission_error_handler_returns_403(self, app_db: FastAPI) -> None:
        """PermissionError exception → RFC 7807 403 response."""

        @app_db.get("/api/v1/test/raise-permission")
        async def _raise_perm():
            raise PermissionError("Access denied")

        async with AsyncClient(
            transport=ASGITransport(app=app_db, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as c:
            r = await c.get("/api/v1/test/raise-permission")

        assert r.status_code == 403, r.text
        data = r.json()
        assert data["type"] == "https://badnass.ma/errors/forbidden"
        assert data["status"] == 403

    @pytest.mark.asyncio
    async def test_timeout_error_handler_returns_400(self, app_db: FastAPI) -> None:
        """TimeoutError exception → RFC 7807 400 response (anti-replay)."""

        @app_db.get("/api/v1/test/raise-timeout")
        async def _raise_timeout():
            raise TimeoutError("Request timestamp expired")

        async with AsyncClient(
            transport=ASGITransport(app=app_db, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as c:
            r = await c.get("/api/v1/test/raise-timeout")

        assert r.status_code == 400, r.text
        data = r.json()
        assert data["type"] == "https://badnass.ma/errors/request-expired"
        assert data["status"] == 400


# ---------------------------------------------------------------------------
# 7. JWT edge cases — expired token (dependencies.py lines 77-82)
# ---------------------------------------------------------------------------


class TestJwtEdgeCases:
    @pytest.mark.asyncio
    async def test_expired_jwt_returns_401(self, cov_client: AsyncClient) -> None:
        """Expired JWT → 401 with specific 'expired' message path."""
        now = datetime.now(UTC)
        expired_payload = {
            "sub": str(uuid4()),
            "role": "OPERATOR",
            "client_id": "client-test-001",
            "jti": str(uuid4()),
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),  # already expired
        }
        expired_token = jwt.encode(expired_payload, _SECRET_KEY, algorithm=_JWT_ALGORITHM)
        token_str = expired_token if isinstance(expired_token, str) else expired_token.decode()

        payload = json.dumps({
            "tracking_ref": "TNG-EXP-001",
            "origin_hub": "TANGIER_MED",
            "destination_hub": "CASABLANCA_PORT",
            "transport_mode": "ROAD_TIR",
            "gross_weight_kg": 10000.0,
        }).encode()
        headers = _dispatch_headers(payload, token=token_str)
        response = await cov_client.post("/api/v1/dispatch", content=payload, headers=headers)
        assert response.status_code == 401, response.text
