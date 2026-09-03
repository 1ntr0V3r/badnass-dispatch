"""Application ports — abstract protocols defining the hexagonal boundary."""

from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import UUID

from src.domain.models import DispatchOrder

# ---------------------------------------------------------------------------
# Repository Port
# ---------------------------------------------------------------------------


@runtime_checkable
class IDispatchRepository(Protocol):
    """Persistence port — implemented by infrastructure adapters."""

    async def is_idempotent(self, idempotency_key: str) -> bool:
        """Return True if this idempotency key has already been processed."""
        ...

    async def save(self, order: DispatchOrder, idempotency_key: str) -> None:
        """Persist the dispatch order and record the idempotency key atomically."""
        ...

    async def get_by_id(self, order_id: UUID) -> DispatchOrder | None:
        """Retrieve a dispatch order by its UUID, or None if not found."""
        ...


# ---------------------------------------------------------------------------
# HMAC Integrity Port
# ---------------------------------------------------------------------------


@runtime_checkable
class IIntegrityVerifier(Protocol):
    """Payload integrity port — protects against in-flight tampering."""

    def verify_hmac(
        self,
        payload: bytes,
        received_signature: str,
        client_secret: str,
    ) -> bool:
        """Verify HMAC-SHA256 signature using constant-time comparison.

        Args:
            payload: Raw request body bytes.
            received_signature: Hex-encoded HMAC signature from request header.
            client_secret: Shared secret for the client (from secure store).

        Returns:
            True if signature is valid, False otherwise.
        """
        ...


# ---------------------------------------------------------------------------
# Audit Registry Port
# ---------------------------------------------------------------------------


@runtime_checkable
class IAuditRegistry(Protocol):
    """Audit registry port — WORM append-only event log."""

    async def record_event(
        self,
        actor_id: str,
        action: str,
        resource_id: str,
        metadata: dict,
    ) -> None:
        """Record a domain event in the WORM hash-chained audit log."""
        ...

    async def capture_incident(
        self,
        incident_id: str,
        actor_id: str | None,
        error_type: str,
        stack_trace: str,
        metadata: dict | None = None,
    ) -> None:
        """Record a security incident with full stack trace (internal only)."""
        ...
