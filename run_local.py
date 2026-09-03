"""Local development runner — starts BADNASS Dispatch with SQLite (no Docker required).

Usage:
    python run_local.py

The app will be available at:
    http://127.0.0.1:8000/health
    http://127.0.0.1:8000/api/docs
"""

import os

import uvicorn

# ── Dev secrets (for local testing ONLY — never use in production) ──────────
os.environ.setdefault("SECRET_KEY", "local_dev_secret_key_aabbccddeeff112233445566")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("MOCK_CLIENT_SECRET", "local_dev_hmac_secret_key_testing")
os.environ.setdefault("AES_256_KEY_HEX", "a" * 64)  # 32 bytes of 0xAA

from src.main import create_app  # noqa: E402

# Start with SQLite in-memory — no Postgres/Redis needed
app = create_app(
    database_url="sqlite+aiosqlite:///./local_dev.db",
    redis_url=None,
)

if __name__ == "__main__":
    print("=" * 60)
    print("BADNASS Dispatch Platform — Local Dev Server")
    print("=" * 60)
    print("  Dashboard UI : http://127.0.0.1:8001/ui")
    print("  API Docs     : http://127.0.0.1:8001/api/docs")
    print("  Health       : http://127.0.0.1:8001/health")
    print("  ReDoc        : http://127.0.0.1:8001/api/redoc")
    print("=" * 60)
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8001,
        log_level="info",
        access_log=True,
    )
