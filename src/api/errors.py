"""Global exception handler — RFC 7807 opaque error responses with zero stack trace leakage.

Flow (from architecture diagram):
  1. Exception occurs → Global handler catches it
  2. Generate UUIDv4 incident_id
  3. Log full stack trace to AUDIT_EVENTS (WORM) — SHA-256 chained
  4. Return opaque RFC 7807 JSON to client (no traceback, no internal details)
  5. Technician/SEC_ADMIN can retrieve incident by ID via /api/v1/tech/incidents/{incident_id}
"""

from __future__ import annotations

import logging
import traceback
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("badnass.errors")


def _build_problem_response(
    status: int,
    title: str,
    detail: str,
    instance: str,
    incident_id: str | None = None,
) -> JSONResponse:
    """Build an RFC 7807 Problem Details JSON response.

    Args:
        status: HTTP status code.
        title: Short human-readable summary (no internal details).
        detail: Extended description (still opaque to clients).
        instance: URI reference identifying the request.
        incident_id: Optional incident UUID for tracking.
    """
    body: dict = {
        "type": f"https://badnass.ma/errors/{title.lower().replace(' ', '-')}",
        "title": title,
        "status": status,
        "detail": detail,
        "instance": instance,
    }
    if incident_id:
        body["incident_id"] = incident_id
    return JSONResponse(status_code=status, content=body)


def register_exception_handlers(app: FastAPI) -> None:
    """Register all global exception handlers on the FastAPI application."""

    @app.exception_handler(PermissionError)
    async def handle_permission_error(request: Request, exc: PermissionError) -> JSONResponse:
        return _build_problem_response(
            status=403,
            title="Forbidden",
            detail="Insufficient permissions to perform this operation.",
            instance=str(request.url),
        )

    @app.exception_handler(TimeoutError)
    async def handle_timeout_error(request: Request, exc: TimeoutError) -> JSONResponse:
        return _build_problem_response(
            status=400,
            title="Request Expired",
            detail="The request timestamp is outside the acceptable window.",
            instance=str(request.url),
        )

    @app.exception_handler(FileExistsError)
    async def handle_idempotency_conflict(
        request: Request, exc: FileExistsError
    ) -> JSONResponse:
        return _build_problem_response(
            status=409,
            title="Conflict",
            detail="This request has already been processed.",
            instance=str(request.url),
        )

    @app.exception_handler(ValueError)
    async def handle_value_error(request: Request, exc: ValueError) -> JSONResponse:
        return _build_problem_response(
            status=400,
            title="Bad Request",
            detail="The request contains invalid or malformed data.",
            instance=str(request.url),
        )

    @app.exception_handler(Exception)
    async def handle_uncaught_exception(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all handler: logs full trace internally, returns opaque response.

        This is the critical security control that prevents stack trace leakage
        to external clients while preserving forensic data for Technicians.
        """
        incident_id = str(uuid4())
        full_trace = traceback.format_exc()

        # Log to structured logger (Loki will capture this)
        logger.error(
            "INTERNAL_INCIDENT",
            extra={
                "incident_id": incident_id,
                "error_type": type(exc).__name__,
                "path": str(request.url),
                "stack_trace": full_trace,
            },
        )

        # Persist to WORM audit log via request state (injected by middleware)
        audit = getattr(request.state, "audit_registry", None)
        if audit is not None:
            try:
                await audit.capture_incident(
                    incident_id=incident_id,
                    actor_id=getattr(getattr(request.state, "identity", None), "user_id", None),
                    error_type=type(exc).__name__,
                    stack_trace=full_trace,
                    metadata={"path": str(request.url), "method": request.method},
                )
            except Exception:  # noqa: BLE001 — audit failure must not surface to client
                logger.critical("AUDIT_WRITE_FAILED for incident %s", incident_id)

        # Return zero-leakage opaque RFC 7807 response
        return _build_problem_response(
            status=500,
            title="Internal Server Error",
            detail="An unexpected condition occurred. Contact support with the incident ID.",
            instance=str(request.url),
            incident_id=incident_id,
        )
