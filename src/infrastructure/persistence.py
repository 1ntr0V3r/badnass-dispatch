"""Infrastructure persistence adapters — async SQLAlchemy implementations.

Database schema (per architecture diagrams):
  - users: System users with Argon2id password hashes
  - clients: B2B partners with encrypted HMAC secrets
  - drivers: PII-encrypted driver data with CNDP 30-day purge timestamp
  - orders: Dispatch orders (main aggregate)
  - idempotency_records: Deduplication cache (mirrors Redis for durability)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

from src.domain.models import DispatchOrder, OrderStatus, TransportMode

# ---------------------------------------------------------------------------
# SQLAlchemy Base and Engine
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


def create_engine_and_session(
    database_url: str,
) -> tuple[Any, async_sessionmaker[AsyncSession]]:
    """Create async engine and session factory.

    Args:
        database_url: Async SQLAlchemy connection string.

    Returns:
        Tuple of (engine, session_factory).
    """
    engine = create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )
    session_factory = async_sessionmaker(
        engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )
    return engine, session_factory


# ---------------------------------------------------------------------------
# ORM Models (exact schema from architecture diagrams)
# ---------------------------------------------------------------------------


class UserORM(Base):
    """USERS table — system users with RBAC roles."""

    __tablename__ = "users"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(128), unique=True, nullable=False, index=True)
    role = Column(String(32), nullable=False)  # SEC_ADMIN | TECHNICIAN | OPERATOR | B2B_CLIENT
    password_hash = Column(String(512), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


class ClientORM(Base):
    """CLIENTS table — B2B partners with encrypted HMAC secrets."""

    __tablename__ = "clients"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    client_code = Column(String(64), unique=True, nullable=False, index=True)
    hmac_secret_enc = Column(Text, nullable=False)  # AES-256-GCM encrypted secret

    orders = relationship("OrderORM", back_populates="client", lazy="noload")


class DriverORM(Base):
    """DRIVERS table — PII-encrypted driver data per CNDP Loi 09-08.

    purge_at field implements automatic 30-day data retention enforcement.
    cin_encrypted stores national ID encrypted with AES-256-GCM.
    """

    __tablename__ = "drivers"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    cin_encrypted = Column(Text, nullable=False)    # CIN — CNDP Loi 09-08 encrypted
    full_name = Column(String(256), nullable=False)
    phone_encrypted = Column(Text, nullable=True)   # Optional — GDPR minimal data
    purge_at = Column(                              # CNDP 30-day retention
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC) + timedelta(days=30),
    )

    orders = relationship("OrderORM", back_populates="driver", lazy="noload")


class OrderORM(Base):
    """ORDERS table — main dispatch order aggregate.

    Stores HMAC digest of original payload for post-hoc integrity verification.
    """

    __tablename__ = "orders"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    client_id = Column(PG_UUID(as_uuid=True), ForeignKey("clients.id"), nullable=True)
    driver_id = Column(PG_UUID(as_uuid=True), ForeignKey("drivers.id"), nullable=True)
    tracking_ref = Column(String(32), unique=True, nullable=False, index=True)
    origin_hub = Column(String(128), nullable=False)
    destination_hub = Column(String(128), nullable=False)
    transport_mode = Column(String(32), nullable=False)
    gross_weight_kg = Column(Float, nullable=False)
    status = Column(String(32), nullable=False, default="PENDING_CUSTOMS")
    hmac_digest = Column(String(128), nullable=True)  # SHA-256 hex of original payload
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    client = relationship("ClientORM", back_populates="orders", lazy="noload")
    driver = relationship("DriverORM", back_populates="orders", lazy="noload")


class IdempotencyRecordORM(Base):
    """IDEMPOTENCY table — durable deduplication (complements Redis cache).

    Composite PK on (key, client_id) allows same key across different clients.
    """

    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint("idempotency_key", "client_id", name="uq_idempotency_client"),
    )

    idempotency_key = Column(String(256), primary_key=True)
    client_id = Column(String(64), primary_key=True)
    order_id = Column(PG_UUID(as_uuid=True), ForeignKey("orders.id"), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Repository Adapter
# ---------------------------------------------------------------------------


class SqlAlchemyDispatchRepository:
    """Concrete implementation of IDispatchRepository using async SQLAlchemy."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def is_idempotent(self, idempotency_key: str) -> bool:
        """Check if the idempotency key has already been processed."""
        stmt = select(IdempotencyRecordORM).where(
            IdempotencyRecordORM.idempotency_key == idempotency_key
        )
        result = await self._session.execute(stmt)
        return result.scalars().first() is not None

    async def save(self, order: DispatchOrder, idempotency_key: str) -> None:
        """Persist the dispatch order and idempotency record atomically."""
        order_orm = OrderORM(
            id=order.order_id,
            tracking_ref=order.tracking_ref,
            origin_hub=order.origin_hub,
            destination_hub=order.destination_hub,
            transport_mode=order.transport_mode.value,
            gross_weight_kg=order.gross_weight_kg,
            status=order.status.value,
            created_at=order.created_at,
        )
        self._session.add(order_orm)

        idempotency_orm = IdempotencyRecordORM(
            idempotency_key=idempotency_key,
            client_id="system",
            order_id=order.order_id,
        )
        self._session.add(idempotency_orm)
        await self._session.commit()

    async def get_by_id(self, order_id: UUID) -> DispatchOrder | None:
        """Retrieve a dispatch order by UUID."""
        stmt = select(OrderORM).where(OrderORM.id == order_id)
        result = await self._session.execute(stmt)
        orm_obj = result.scalars().first()

        if orm_obj is None:
            return None

        return DispatchOrder(
            order_id=orm_obj.id,
            tracking_ref=orm_obj.tracking_ref,
            origin_hub=orm_obj.origin_hub,
            destination_hub=orm_obj.destination_hub,
            transport_mode=TransportMode(orm_obj.transport_mode),
            gross_weight_kg=orm_obj.gross_weight_kg,
            status=OrderStatus(orm_obj.status),
            created_at=orm_obj.created_at,
        )
