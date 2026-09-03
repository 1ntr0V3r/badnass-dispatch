"""API routes — all FastAPI endpoint definitions.

Endpoints:
  POST /api/v1/auth/login       — Argon2id auth + JWT issuance
  POST /api/v1/dispatch         — Submit dispatch order (HMAC-signed)
  GET  /api/v1/dispatch/{id}    — Retrieve order by UUID
  POST /api/v1/telemetry        — Ingest axle scale / seal sensor data
  GET  /api/v1/tech/incidents/{id} — Retrieve incident (TECHNICIAN/SEC_ADMIN only)
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID, uuid4

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import (
    get_client_secret,
    get_current_identity,
    get_db_session,
    hash_password,
    require_privilege,
    verify_password,
)
from src.application.use_cases import ProcessDispatchUseCase, SubmitDispatchCommand
from src.domain.models import SecurityIdentity, UserRole
from src.infrastructure.audit import SqlAlchemyAuditRegistry
from src.infrastructure.crypto import HmacIntegrityService
from src.infrastructure.persistence import (
    SqlAlchemyDispatchRepository,
    UserORM,
)

router = APIRouter(prefix="/api/v1")

_SECRET_KEY = os.getenv("SECRET_KEY", "INSECURE_FALLBACK_FOR_TESTS_ONLY")
_JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_JWT_EXPIRE_MINUTES = 60


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=128)
    password: str = Field(..., min_length=8)
    mfa_code: str | None = Field(None, description="TOTP code for privileged roles")


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = _JWT_EXPIRE_MINUTES * 60


class DispatchPayload(BaseModel):
    tracking_ref: str = Field(..., pattern=r"^[A-Z0-9\-_]{6,32}$")
    origin_hub: str = Field(..., min_length=2, max_length=128)
    destination_hub: str = Field(..., min_length=2, max_length=128)
    transport_mode: str = Field(..., description="ROAD_TIR | MARITIME_CONTAINER | AIR_FREIGHT")
    gross_weight_kg: float = Field(..., gt=0, le=44000)


class TelemetryPayload(BaseModel):
    device_id: str
    axle_weight_kg: float | None = None
    seal_status: str | None = None
    gps_lat: float | None = None
    gps_lon: float | None = None
    timestamp: float


# ---------------------------------------------------------------------------
# Auth Route
# ---------------------------------------------------------------------------


@router.post("/auth/login", response_model=LoginResponse, tags=["Auth"])
async def login(
    body: LoginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> LoginResponse:
    """Authenticate with Argon2id password verification.

    Returns:
        JWT access token with embedded user_id, role, client_id, and jti.
    """
    # Look up user in database
    stmt = select(UserORM).where(UserORM.username == body.username, UserORM.is_active.is_(True))
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = str(uuid4())
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "client_id": str(user.id),
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(minutes=_JWT_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, _SECRET_KEY, algorithm=_JWT_ALGORITHM)

    return LoginResponse(access_token=token)


# ---------------------------------------------------------------------------
# Dispatch Routes
# ---------------------------------------------------------------------------


@router.post(
    "/dispatch",
    status_code=status.HTTP_201_CREATED,
    tags=["Dispatch"],
    summary="Submit a new dispatch order",
)
async def submit_dispatch(
    request: Request,
    identity: Annotated[SecurityIdentity, Depends(get_current_identity)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    x_client_id: str = Header(..., alias="X-Client-ID"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_idempotency_key: str = Header(..., alias="X-Idempotency-Key"),
    x_signature_hmac: str = Header(..., alias="X-Signature-HMAC"),
) -> JSONResponse:
    """Submit a freight dispatch order with HMAC integrity verification.

    Required Headers:
      X-Client-ID: B2B client identifier
      X-Timestamp: Unix epoch float (for anti-replay window check)
      X-Idempotency-Key: Unique key to prevent duplicate submissions
      X-Signature-HMAC: HMAC-SHA256 hex signature of raw request body
    """
    raw_body = await request.body()

    try:
        client_timestamp = float(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="X-Timestamp must be a valid Unix epoch float.")

    # Parse JSON body
    try:
        body_data = json.loads(raw_body)
        payload = DispatchPayload(**body_data)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Resolve client secret
    client_secret = get_client_secret(x_client_id)

    repo = SqlAlchemyDispatchRepository(db)
    verifier = HmacIntegrityService()
    audit = SqlAlchemyAuditRegistry(db)

    # Inject audit registry into request state for error handler
    request.state.audit_registry = audit

    cmd = SubmitDispatchCommand(
        tracking_ref=payload.tracking_ref,
        origin_hub=payload.origin_hub,
        destination_hub=payload.destination_hub,
        transport_mode=payload.transport_mode,
        gross_weight_kg=payload.gross_weight_kg,
        client_id=x_client_id,
        client_secret=client_secret,
        idempotency_key=x_idempotency_key,
        raw_payload=raw_body,
        received_hmac=x_signature_hmac,
        client_timestamp=client_timestamp,
        identity=identity,
    )

    use_case = ProcessDispatchUseCase(repo, verifier, audit)
    order = await use_case.execute(cmd)

    return JSONResponse(
        status_code=201,
        content={
            "order_id": str(order.order_id),
            "tracking_ref": order.tracking_ref,
            "status": order.status.value,
            "created_at": order.created_at.isoformat(),
        },
    )


@router.get("/dispatch/{order_id}", tags=["Dispatch"], summary="Retrieve a dispatch order")
async def get_dispatch(
    order_id: UUID,
    identity: Annotated[SecurityIdentity, Depends(get_current_identity)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> JSONResponse:
    """Retrieve a dispatch order by UUID."""
    repo = SqlAlchemyDispatchRepository(db)
    order = await repo.get_by_id(order_id)

    if order is None:
        raise HTTPException(status_code=404, detail=f"Order '{order_id}' not found.")

    return JSONResponse(
        content={
            "order_id": str(order.order_id),
            "tracking_ref": order.tracking_ref,
            "origin_hub": order.origin_hub,
            "destination_hub": order.destination_hub,
            "transport_mode": order.transport_mode.value,
            "gross_weight_kg": order.gross_weight_kg,
            "status": order.status.value,
            "created_at": order.created_at.isoformat(),
        }
    )


# ---------------------------------------------------------------------------
# Telemetry Route (Pont-Bascule / axle scale / seal sensor)
# ---------------------------------------------------------------------------


@router.post("/telemetry", tags=["Telemetry"], summary="Ingest axle scale / seal sensor data")
async def ingest_telemetry(
    body: TelemetryPayload,
    identity: Annotated[SecurityIdentity, Depends(get_current_identity)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> JSONResponse:
    """Receive telemetry from Pont-Bascule axle scale boxes and seal sensors.

    Actors: Boîtier Pont-Bascule (automated IoT devices).
    """
    audit = SqlAlchemyAuditRegistry(db)
    await audit.record_event(
        actor_id=identity.user_id,
        action="TELEMETRY_INGESTED",
        resource_id=body.device_id,
        metadata={
            "device_id": body.device_id,
            "axle_weight_kg": body.axle_weight_kg,
            "seal_status": body.seal_status,
            "gps_lat": body.gps_lat,
            "gps_lon": body.gps_lon,
        },
    )
    return JSONResponse(
        status_code=202,
        content={"status": "accepted", "device_id": body.device_id},
    )


# ---------------------------------------------------------------------------
# Technical Incident Route (RBAC: TECHNICIAN + SEC_ADMIN only)
# ---------------------------------------------------------------------------


@router.get(
    "/tech/incidents/{incident_id}",
    tags=["Security Operations"],
    summary="Retrieve full incident details (privileged access only)",
)
async def get_incident(
    incident_id: str,
    identity: Annotated[SecurityIdentity, Depends(require_privilege)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> JSONResponse:
    """Retrieve unmasked incident details including full stack trace.

    RBAC: Restricted to TECHNICIAN and SEC_ADMIN roles.
    Aligned with architecture diagram: 'Inspecter erreurs démasquées'.
    """
    audit = SqlAlchemyAuditRegistry(db)
    incident = await audit.get_incident(incident_id)

    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    return JSONResponse(
        content={
            "incident_id": incident.event_id,
            "timestamp": incident.timestamp.isoformat(),
            "actor_id": incident.actor_id,
            "error_type": incident.event_type,
            "stack_trace": incident.stack_trace,
            "metadata": json.loads(incident.metadata_json or "{}"),
            "record_hash": incident.record_hash,
        }
    )
