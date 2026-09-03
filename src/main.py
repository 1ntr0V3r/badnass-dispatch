"""BADNASS Dispatch Platform — FastAPI application entry point.

Wires together all hexagonal architecture adapters:
  - FastAPI app with security middleware
  - PostgreSQL async engine (SQLAlchemy)
  - Redis async client (JTI revocation)
  - Global exception handlers (RFC 7807, zero trace leakage)
  - API routes
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from src.api.errors import register_exception_handlers
from src.api.routes import router
from src.infrastructure.persistence import (
    Base,
    create_engine_and_session,
)

# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------


def create_app(database_url: str | None = None, redis_url: str | None = None) -> FastAPI:
    """Factory function to create and configure the FastAPI application.

    Args:
        database_url: Override the database URL (useful for testing with SQLite).
        redis_url: Override the Redis URL (useful for testing with fakeredis).

    Returns:
        Configured FastAPI instance.
    """

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
        """Manage application startup and shutdown via the modern lifespan protocol."""
        # ── Startup ───────────────────────────────────────────────────────
        _db_url = database_url or _build_postgres_url()
        engine, session_factory = create_engine_and_session(_db_url)
        _app.state.engine = engine
        _app.state.session_factory = session_factory

        # Create all tables (idempotent in development)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Redis client for JTI revocation
        _redis_url = redis_url or (
            f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}"
        )
        try:
            redis_client = aioredis.from_url(_redis_url, decode_responses=True)
            await redis_client.ping()
            _app.state.redis = redis_client
        except Exception:  # noqa: BLE001
            _app.state.redis = None  # Degraded mode — JTI revocation skipped

        yield  # Application is running

        # ── Shutdown ──────────────────────────────────────────────────────
        if hasattr(_app.state, "engine"):
            await _app.state.engine.dispose()
        if hasattr(_app.state, "redis") and _app.state.redis:
            await _app.state.redis.aclose()

    app = FastAPI(
        title="BADNASS Dispatch Platform",
        description=(
            "Defense-grade freight forwarding, customs transit, and multimodal "
            "dispatch API for Tanger Med Port, Morocco."
        ),
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ── Security Middleware ───────────────────────────────────────────────
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"],  # Nginx handles host validation upstream
    )

    # ── Global Exception Handlers ─────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routes ───────────────────────────────────────────────────────────
    app.include_router(router)

    # ── Health Check ──────────────────────────────────────────────────────
    @app.get("/health", tags=["Health"], include_in_schema=False)
    async def health() -> dict:
        return {"status": "healthy", "service": "badnass-dispatch"}

    # ── Root redirect → Swagger UI ────────────────────────────────────────
    from fastapi.responses import RedirectResponse  # noqa: PLC0415

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse(url="/api/docs")

    return app


def _build_postgres_url() -> str:
    """Build the async PostgreSQL connection URL from environment variables."""
    user = os.getenv("POSTGRES_USER", "badnass_admin")
    password = os.getenv("POSTGRES_PASSWORD", "badnass_secure_pass_2026")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "badnass_dispatch")
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db}"


# ---------------------------------------------------------------------------
# ASGI entry point
# ---------------------------------------------------------------------------

app = create_app()
