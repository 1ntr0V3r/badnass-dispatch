"""BADNASS Dispatch Platform — Domain Models (Pure Python, no framework imports).

Implements freight forwarding, customs transit, and multimodal dispatch domain
for Tanger Med Port, Morocco. Complies with CNDP Loi 09-08 and GDPR constraints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4


# ---------------------------------------------------------------------------
# Domain Enumerations
# ---------------------------------------------------------------------------


class TransportMode(str, Enum):
    """Multimodal transport classification per CMR/IATA/SOLAS standards."""

    ROAD_TIR = "ROAD_TIR"
    MARITIME_CONTAINER = "MARITIME_CONTAINER"
    AIR_FREIGHT = "AIR_FREIGHT"


class OrderStatus(str, Enum):
    """Lifecycle states of a customs dispatch order."""

    PENDING_CUSTOMS = "PENDING_CUSTOMS"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    SECURITY_HOLD = "SECURITY_HOLD"


class UserRole(str, Enum):
    """RBAC roles — enforced at application and API layers."""

    SEC_ADMIN = "SEC_ADMIN"        # Full system access + incident traces
    TECHNICIAN = "TECHNICIAN"      # Technical ops + incident traces
    OPERATOR = "OPERATOR"          # Dispatch operations, no traces
    B2B_CLIENT = "B2B_CLIENT"      # Read-only external partner access


# ---------------------------------------------------------------------------
# Domain Value Objects / Identities
# ---------------------------------------------------------------------------

_TRACKING_REF_RE = re.compile(r"^[A-Z0-9\-_]{6,32}$")
_MAX_WEIGHT_KG: float = 44_000.0
_MIN_WEIGHT_KG: float = 0.0


@dataclass(frozen=True)
class SecurityIdentity:
    """Authenticated security principal extracted from a validated JWT."""

    user_id: str
    client_id: str
    role: UserRole
    jti: str  # JWT ID — used for token revocation checks in Redis
    has_privilege: bool  # True when role is SEC_ADMIN or TECHNICIAN

    def __post_init__(self) -> None:
        if not self.user_id:
            raise ValueError("user_id must be non-empty")
        if not self.client_id:
            raise ValueError("client_id must be non-empty")
        if not self.jti:
            raise ValueError("jti must be non-empty")
        if not isinstance(self.role, UserRole):
            raise TypeError(f"role must be a UserRole, got {type(self.role)!r}")


@dataclass
class DispatchOrder:
    """Aggregate root for a multimodal dispatch order.

    Enforces business invariants at construction time:
    - Gross weight: 0 < gross_weight_kg <= 44_000 kg (44t TIR limit)
    - Hubs must differ: origin_hub != destination_hub
    - Tracking reference format: ^[A-Z0-9-_]{6,32}$
    """

    order_id: UUID = field(default_factory=uuid4)
    tracking_ref: str = field(default="")
    origin_hub: str = field(default="")
    destination_hub: str = field(default="")
    transport_mode: TransportMode = field(default=TransportMode.ROAD_TIR)
    gross_weight_kg: float = field(default=0.0)
    status: OrderStatus = field(default=OrderStatus.PENDING_CUSTOMS)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        """Enforce all domain invariants — raises ValueError on violation."""
        # Weight invariant: TIR Convention max gross vehicle weight is 44t
        if not (_MIN_WEIGHT_KG < self.gross_weight_kg <= _MAX_WEIGHT_KG):
            raise ValueError(
                f"gross_weight_kg must be in range (0, 44000], "
                f"got {self.gross_weight_kg}"
            )

        # Hub invariant: origin and destination must differ
        if self.origin_hub == self.destination_hub:
            raise ValueError(
                f"origin_hub and destination_hub must differ, "
                f"both are '{self.origin_hub}'"
            )

        # Tracking reference format: uppercase alphanumeric + hyphens + underscores
        if not _TRACKING_REF_RE.match(self.tracking_ref):
            raise ValueError(
                f"tracking_ref '{self.tracking_ref}' does not match "
                f"pattern ^[A-Z0-9-_]{{6,32}}$"
            )

        if not self.origin_hub:
            raise ValueError("origin_hub must be non-empty")

        if not self.destination_hub:
            raise ValueError("destination_hub must be non-empty")

    def transition_to(self, new_status: OrderStatus) -> None:
        """Apply a status transition — future guard for state machine."""
        self.status = new_status
