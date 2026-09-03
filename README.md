# BADNASS Dispatch Platform

**Defense-grade freight forwarding, customs transit, and multimodal dispatch microservice for Tanger Med Port, Morocco.**

[![DevSecOps Pipeline](https://github.com/YOUR_ORG/badnass-dispatch/actions/workflows/devsecops.yml/badge.svg)](https://github.com/YOUR_ORG/badnass-dispatch/actions/workflows/devsecops.yml)

---

## Architecture

Hexagonal Architecture (Ports & Adapters) with zero-trust network topology:

```
ERP/Sensor → HTTPS → Nginx (TLS 1.3) → FastAPI → PostgreSQL (air-gapped)
                                              ↓
                                         Redis (JTI revocation)
                                              ↓
                                    WORM Audit Log (SHA-256 chained)
```

### Security Controls
| Control | Implementation |
|---|---|
| Authentication | JWT HS256 + Argon2id passwords |
| Authorization | RBAC (SEC_ADMIN, TECHNICIAN, OPERATOR, B2B_CLIENT) |
| Anti-Replay | ±300s timestamp window |
| Payload Integrity | HMAC-SHA256 (constant-time) |
| PII Protection | AES-256-GCM (CNDP Loi 09-08 + GDPR) |
| Audit Trail | WORM SHA-256 hash chain |
| Error Handling | RFC 7807 — zero stack trace leakage |
| Network Isolation | 4 segregated Docker bridge networks |
| TLS | TLS 1.3 only (Nginx) |

### Database Schema (per architecture diagrams)
- **USERS** — System users with Argon2id hashes and RBAC roles
- **CLIENTS** — B2B partners with AES-256-GCM encrypted HMAC secrets
- **DRIVERS** — PII-encrypted driver data with CNDP 30-day purge timestamp
- **ORDERS** — Dispatch order aggregate with HMAC payload digest
- **AUDIT_EVENTS** — WORM hash-chained event log (tamper-evident)
- **IDEMPOTENCY_RECORDS** — Durable deduplication (complements Redis cache)

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/YOUR_ORG/badnass-dispatch.git
cd badnass-dispatch
cp .env.example .env
# Edit .env with your secrets
```

### 2. Generate secrets

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('AES_256_KEY_HEX=' + secrets.token_hex(32))"
```

### 3. Run locally (Docker Compose)

```bash
docker compose up -d
# API available at: https://localhost:8443/api/docs
```

### 4. Run tests

```bash
python -m venv .venv
.venv/Scripts/activate  # Windows
pip install -r requirements.txt
pytest tests/ --cov=src --cov-report=term-missing
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/login` | None | Issue JWT token |
| POST | `/api/v1/dispatch` | JWT + HMAC | Submit dispatch order |
| GET | `/api/v1/dispatch/{id}` | JWT | Get order by UUID |
| POST | `/api/v1/telemetry` | JWT | Ingest sensor data |
| GET | `/api/v1/tech/incidents/{id}` | JWT (TECH/ADMIN) | Get incident details |
| GET | `/health` | None | Health check |

### Required Headers for `/dispatch`
```
Authorization: Bearer <jwt>
X-Client-ID: <client_identifier>
X-Timestamp: <unix_epoch_float>
X-Idempotency-Key: <uuid>
X-Signature-HMAC: <hmac_sha256_hex>
```

---

## DevSecOps Pipeline

6 deterministic quality gates:

1. **Secret Scan** — Gitleaks (full history)
2. **SAST & Lint** — Ruff + Semgrep (OWASP Top 10)
3. **Tests** — Pytest ≥85% coverage enforced
4. **Dependency SCA** — Trivy fs (CRITICAL/HIGH CVE = fail)
5. **Container Scan** — Trivy image (CRITICAL/HIGH = fail)
6. **SBOM + Signing** — Syft (SPDX) + Cosign (keyless OIDC)

---

## Compliance

- **CNDP Loi 09-08** — Moroccan data protection: AES-256-GCM driver PII, 30-day purge
- **GDPR Article 32** — Appropriate technical security measures
- **ISO 27001 A.12.4** — WORM audit trail logging
- **TIR Convention** — 44-tonne gross weight limit enforced
- **CMR/IATA/SOLAS** — Multimodal transport classification

---

## License

Proprietary — BADNASS Logistics © 2026. All rights reserved.
