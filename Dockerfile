# ============================================================
# Stage 1: Dependency Builder
# ============================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools for native extensions (cryptography, argon2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ============================================================
# Stage 2: Production Runtime (hardened)
# ============================================================
FROM python:3.12-slim AS runtime

# Security: Create unprivileged user (UID 10001, GID 10001)
RUN groupadd --gid 10001 nonroot \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /bin/false nonroot

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source (no tests, no dev files)
COPY src/ ./src/

# Set file ownership to nonroot before dropping privileges
RUN chown -R nonroot:nonroot /app

# Drop all Linux capabilities — minimal attack surface
# Read-only root filesystem enforced in docker-compose.yml
USER nonroot:nonroot

# Expose application port
EXPOSE 8000

# Container healthcheck — FastAPI /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

# ENTRYPOINT: uvicorn with production settings
CMD ["uvicorn", "src.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--no-access-log"]
