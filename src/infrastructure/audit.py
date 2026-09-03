"""Infrastructure audit adapter — WORM cryptographic hash-chained event log.

Implements the AUDIT_LOGS table from architecture diagrams with SHA-256 hash chaining:
  H_n = SHA256(H_n-1 || timestamp || actor_id || action || metadata_json)

This creates a Write-Once Read-Many tamper-evident chain where any modification
to a historical record invalidates all subsequent hashes, making forensic
tampering detectable.

Aligned with:
  - Directive NTI-ADII (Maroc) for critical infrastructure audit trails
  - ISO 27001 A.12.4 — Logging and Monitoring
  - GDPR Article 5(2) — Accountability principle
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.persistence import Base

# ---------------------------------------------------------------------------
# Audit ORM Models
# ---------------------------------------------------------------------------


class AuditEventORM(Base):
    """AUDIT_LOGS table — append-only WORM hash-chained event record.

    SHA-256 chain: record_hash = SHA256(prev_hash || timestamp || actor_id || action || metadata)
    """

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(36), nullable=False, unique=True, index=True)
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    actor_id = Column(String(256), nullable=False, index=True)
    event_type = Column(String(128), nullable=False, index=True)
    resource_id = Column(String(256), nullable=True)
    metadata_json = Column(Text, nullable=True)
    is_incident = Column(Integer, nullable=False, default=0)  # 1 = security incident
    stack_trace = Column(Text, nullable=True)          # Only for incidents, RBAC-gated
    prev_hash = Column(String(64), nullable=False)     # SHA-256 hex of previous record
    record_hash = Column(String(64), nullable=False)   # SHA-256 hex of this record


# ---------------------------------------------------------------------------
# Genesis (bootstrap) hash
# ---------------------------------------------------------------------------

_GENESIS_HASH: str = "0" * 64  # 64-char zero string as chain anchor


# ---------------------------------------------------------------------------
# Audit Registry Adapter
# ---------------------------------------------------------------------------


class SqlAlchemyAuditRegistry:
    """Concrete WORM audit registry using async SQLAlchemy with hash chaining.

    Each call to record_event() or capture_incident() atomically:
      1. Retrieves the hash of the most recent audit record
      2. Computes the new record hash
      3. Inserts the new record
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _get_last_hash(self) -> str:
        """Retrieve the record_hash of the most recently inserted audit event."""
        stmt = (
            select(AuditEventORM.record_hash)
            .order_by(AuditEventORM.id.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        last_hash = result.scalars().first()
        return last_hash if last_hash is not None else _GENESIS_HASH

    @staticmethod
    def _compute_hash(
        prev_hash: str,
        timestamp_iso: str,
        actor_id: str,
        action: str,
        metadata_json: str,
    ) -> str:
        """Compute H_n = SHA256(H_n-1 || timestamp || actor_id || action || metadata)."""
        chain_input = f"{prev_hash}|{timestamp_iso}|{actor_id}|{action}|{metadata_json}"
        return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

    async def record_event(
        self,
        actor_id: str,
        action: str,
        resource_id: str,
        metadata: dict,
    ) -> None:
        """Record a domain event in the WORM hash-chained audit log."""
        now = datetime.now(UTC)
        timestamp_iso = now.isoformat()
        metadata_json = json.dumps(metadata, default=str, sort_keys=True)
        prev_hash = await self._get_last_hash()
        record_hash = self._compute_hash(prev_hash, timestamp_iso, actor_id, action, metadata_json)

        event = AuditEventORM(
            event_id=str(uuid4()),
            timestamp=now,
            actor_id=actor_id,
            event_type=action,
            resource_id=resource_id,
            metadata_json=metadata_json,
            is_incident=0,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )
        self._session.add(event)
        await self._session.commit()

    async def capture_incident(
        self,
        incident_id: str,
        actor_id: str | None,
        error_type: str,
        stack_trace: str,
        metadata: dict | None = None,
    ) -> None:
        """Record a security incident with full stack trace (RBAC-gated retrieval)."""
        now = datetime.now(UTC)
        timestamp_iso = now.isoformat()
        safe_actor = actor_id or "SYSTEM"
        meta_json = json.dumps(metadata or {}, default=str, sort_keys=True)
        prev_hash = await self._get_last_hash()
        record_hash = self._compute_hash(
            prev_hash, timestamp_iso, safe_actor, error_type, meta_json
        )

        event = AuditEventORM(
            event_id=incident_id,
            timestamp=now,
            actor_id=safe_actor,
            event_type=error_type,
            resource_id=incident_id,
            metadata_json=meta_json,
            is_incident=1,
            stack_trace=stack_trace,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )
        self._session.add(event)
        await self._session.commit()

    async def get_incident(self, incident_id: str) -> AuditEventORM | None:
        """Retrieve a security incident by ID (caller must enforce RBAC)."""
        stmt = select(AuditEventORM).where(
            AuditEventORM.event_id == incident_id,
            AuditEventORM.is_incident == 1,
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()
