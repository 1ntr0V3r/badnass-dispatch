"""Application use cases — orchestration layer enforcing security policies.

Security controls implemented:
  - RBAC: Only OPERATOR, B2B_CLIENT, SEC_ADMIN, TECHNICIAN may submit orders
  - Temporal anti-replay: |T_server - T_client| <= 300 seconds
  - Idempotency: Duplicate idempotency key raises FileExistsError
  - HMAC payload integrity validation
  - Domain invariant enforcement
  - WORM hash-chained audit recording
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from src.application.ports import IAuditRegistry, IDispatchRepository, IIntegrityVerifier
from src.domain.models import (
    DispatchOrder,
    OrderStatus,
    SecurityIdentity,
    TransportMode,
    UserRole,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ANTI_REPLAY_WINDOW_SECONDS: int = 300  # 5-minute temporal drift tolerance
_ALLOWED_SUBMISSION_ROLES: frozenset[UserRole] = frozenset(
    {UserRole.OPERATOR, UserRole.B2B_CLIENT, UserRole.SEC_ADMIN, UserRole.TECHNICIAN}
)


# ---------------------------------------------------------------------------
# Command Object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubmitDispatchCommand:
    """Immutable command object carrying all data needed to submit an order."""

    tracking_ref: str
    origin_hub: str
    destination_hub: str
    transport_mode: str
    gross_weight_kg: float
    client_id: str
    client_secret: str
    idempotency_key: str
    raw_payload: bytes       # Raw request body for HMAC verification
    received_hmac: str       # X-Signature-HMAC header value
    client_timestamp: float  # X-Timestamp header value (Unix epoch)
    identity: SecurityIdentity


# ---------------------------------------------------------------------------
# Use Case
# ---------------------------------------------------------------------------


class ProcessDispatchUseCase:
    """Orchestrates secure dispatch order submission through all security gates."""

    def __init__(
        self,
        repository: IDispatchRepository,
        integrity_verifier: IIntegrityVerifier,
        audit_registry: IAuditRegistry,
    ) -> None:
        self._repo = repository
        self._verifier = integrity_verifier
        self._audit = audit_registry

    async def execute(self, cmd: SubmitDispatchCommand) -> DispatchOrder:
        """Execute the full security pipeline and persist the order.

        Security gates (in order):
          1. RBAC role authorization
          2. Temporal anti-replay drift check
          3. Idempotency uniqueness check
          4. HMAC payload integrity validation
          5. Domain entity invariant validation
          6. Persistence
          7. Audit recording

        Raises:
            PermissionError: RBAC gate failure
            TimeoutError: Temporal drift exceeds 300s window
            FileExistsError: Duplicate idempotency key
            ValueError: HMAC validation failure or domain invariant violation
        """

        # ── Gate 1: RBAC ─────────────────────────────────────────────────
        if cmd.identity.role not in _ALLOWED_SUBMISSION_ROLES:
            raise PermissionError(
                f"Role '{cmd.identity.role.value}' is not authorized to submit dispatch orders"
            )

        # ── Gate 2: Temporal Anti-Replay ─────────────────────────────────
        server_ts = datetime.now(UTC).timestamp()
        drift = abs(server_ts - cmd.client_timestamp)
        if drift > _ANTI_REPLAY_WINDOW_SECONDS:
            raise TimeoutError(
                f"Timestamp drift {drift:.1f}s exceeds allowed window of "
                f"{_ANTI_REPLAY_WINDOW_SECONDS}s — possible replay attack"
            )

        # ── Gate 3: Idempotency ───────────────────────────────────────────
        already_exists = await self._repo.is_idempotent(cmd.idempotency_key)
        if already_exists:
            raise FileExistsError(
                f"Idempotency key '{cmd.idempotency_key}' has already been processed"
            )

        # ── Gate 4: HMAC Payload Integrity ────────────────────────────────
        is_valid = self._verifier.verify_hmac(
            payload=cmd.raw_payload,
            received_signature=cmd.received_hmac,
            client_secret=cmd.client_secret,
        )
        if not is_valid:
            raise ValueError("HMAC signature verification failed — payload may be tampered")

        # ── Gate 5: Domain Entity Invariants ──────────────────────────────
        try:
            transport = TransportMode(cmd.transport_mode)
        except ValueError as exc:
            raise ValueError(f"Invalid transport_mode '{cmd.transport_mode}'") from exc

        order = DispatchOrder(
            order_id=uuid4(),
            tracking_ref=cmd.tracking_ref,
            origin_hub=cmd.origin_hub,
            destination_hub=cmd.destination_hub,
            transport_mode=transport,
            gross_weight_kg=cmd.gross_weight_kg,
            status=OrderStatus.PENDING_CUSTOMS,
        )
        # __post_init__ already called — any violation raises ValueError here

        # ── Gate 6: Persistence ───────────────────────────────────────────
        await self._repo.save(order, cmd.idempotency_key)

        # ── Gate 7: WORM Audit Recording ──────────────────────────────────
        await self._audit.record_event(
            actor_id=cmd.identity.user_id,
            action="DISPATCH_ORDER_SUBMITTED",
            resource_id=str(order.order_id),
            metadata={
                "tracking_ref": order.tracking_ref,
                "transport_mode": order.transport_mode.value,
                "gross_weight_kg": order.gross_weight_kg,
                "client_id": cmd.client_id,
                "idempotency_key": cmd.idempotency_key,
            },
        )

        return order
