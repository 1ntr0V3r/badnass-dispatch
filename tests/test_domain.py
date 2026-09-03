"""Domain model tests — pure unit tests with zero infrastructure dependencies.

Tests:
  - Nominal entity creation (all valid fields)
  - Overweight rejection (> 44,000 kg TIR limit)
  - Zero weight rejection (<= 0 kg)
  - Identical hubs rejection (origin == destination)
  - Invalid tracking reference format rejection
  - SecurityIdentity validation
"""

from __future__ import annotations

import pytest

from src.domain.models import (
    DispatchOrder,
    OrderStatus,
    SecurityIdentity,
    TransportMode,
    UserRole,
)

# ---------------------------------------------------------------------------
# DispatchOrder — Nominal
# ---------------------------------------------------------------------------


class TestDispatchOrderNominal:
    """Valid order creation — all invariants satisfied."""

    def test_creates_road_tir_order(self) -> None:
        order = DispatchOrder(
            tracking_ref="TNG-MED-001",
            origin_hub="TANGIER_MED",
            destination_hub="CASABLANCA_PORT",
            transport_mode=TransportMode.ROAD_TIR,
            gross_weight_kg=20_000.0,
        )
        assert order.tracking_ref == "TNG-MED-001"
        assert order.transport_mode == TransportMode.ROAD_TIR
        assert order.status == OrderStatus.PENDING_CUSTOMS
        assert order.gross_weight_kg == 20_000.0
        assert order.order_id is not None

    def test_creates_maritime_order(self) -> None:
        order = DispatchOrder(
            tracking_ref="MCT-SEA-99",
            origin_hub="TANGER_MED",
            destination_hub="ROTTERDAM",
            transport_mode=TransportMode.MARITIME_CONTAINER,
            gross_weight_kg=44_000.0,  # Maximum allowed
        )
        assert order.transport_mode == TransportMode.MARITIME_CONTAINER
        assert order.gross_weight_kg == 44_000.0

    def test_creates_air_freight_order(self) -> None:
        order = DispatchOrder(
            tracking_ref="AFR-MNR-2026",
            origin_hub="CASABLANCA_CMN",
            destination_hub="PARIS_CDG",
            transport_mode=TransportMode.AIR_FREIGHT,
            gross_weight_kg=5_000.5,
        )
        assert order.transport_mode == TransportMode.AIR_FREIGHT

    def test_tracking_ref_minimum_length(self) -> None:
        order = DispatchOrder(
            tracking_ref="TNG001",  # Exactly 6 chars — minimum
            origin_hub="HUB_A",
            destination_hub="HUB_B",
            gross_weight_kg=1000.0,
        )
        assert order.tracking_ref == "TNG001"

    def test_tracking_ref_maximum_length(self) -> None:
        ref = "A" * 32  # Exactly 32 chars — maximum
        order = DispatchOrder(
            tracking_ref=ref,
            origin_hub="HUB_A",
            destination_hub="HUB_B",
            gross_weight_kg=1000.0,
        )
        assert order.tracking_ref == ref

    def test_tracking_ref_with_hyphens_and_underscores(self) -> None:
        order = DispatchOrder(
            tracking_ref="TNG-MED_2026-001",
            origin_hub="HUB_A",
            destination_hub="HUB_B",
            gross_weight_kg=1000.0,
        )
        assert order.tracking_ref == "TNG-MED_2026-001"

    def test_order_has_utc_created_at(self) -> None:
        order = DispatchOrder(
            tracking_ref="TNG001",
            origin_hub="ORIGIN",
            destination_hub="DEST",
            gross_weight_kg=100.0,
        )
        assert order.created_at.tzinfo is not None

    def test_minimum_valid_weight(self) -> None:
        order = DispatchOrder(
            tracking_ref="MIN001",
            origin_hub="HUB_A",
            destination_hub="HUB_B",
            gross_weight_kg=0.001,  # Just above 0
        )
        assert order.gross_weight_kg == 0.001


# ---------------------------------------------------------------------------
# DispatchOrder — Weight Invariant Violations
# ---------------------------------------------------------------------------


class TestDispatchOrderWeightInvariants:
    """Weight boundary enforcement — TIR Convention limits."""

    def test_rejects_overweight_order(self) -> None:
        """Cargo exceeding 44t TIR limit must be rejected."""
        with pytest.raises(ValueError, match="gross_weight_kg must be in range"):
            DispatchOrder(
                tracking_ref="HEAVY001",
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=44_001.0,  # 1 kg over the limit
            )

    def test_rejects_exactly_zero_weight(self) -> None:
        """Zero weight is physically impossible for a loaded vehicle."""
        with pytest.raises(ValueError, match="gross_weight_kg must be in range"):
            DispatchOrder(
                tracking_ref="ZERO001",
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=0.0,
            )

    def test_rejects_negative_weight(self) -> None:
        """Negative weight is nonsensical and indicates tampered data."""
        with pytest.raises(ValueError, match="gross_weight_kg must be in range"):
            DispatchOrder(
                tracking_ref="NEG0001",
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=-100.0,
            )

    def test_rejects_massively_overweight(self) -> None:
        with pytest.raises(ValueError):
            DispatchOrder(
                tracking_ref="FAT0001",
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=1_000_000.0,
            )


# ---------------------------------------------------------------------------
# DispatchOrder — Hub Invariant Violations
# ---------------------------------------------------------------------------


class TestDispatchOrderHubInvariants:
    """Hub identity enforcement — origin must differ from destination."""

    def test_rejects_identical_hubs(self) -> None:
        """Same origin and destination is logistically impossible."""
        with pytest.raises(ValueError, match="origin_hub and destination_hub must differ"):
            DispatchOrder(
                tracking_ref="SAME001",
                origin_hub="TANGIER_MED",
                destination_hub="TANGIER_MED",  # Same!
                gross_weight_kg=10_000.0,
            )

    def test_rejects_identical_hubs_case_sensitive(self) -> None:
        """Case-sensitive match — TANGIER_MED != tangier_med."""
        order = DispatchOrder(
            tracking_ref="CASE001",
            origin_hub="TANGIER_MED",
            destination_hub="tangier_med",  # Different case = allowed
            gross_weight_kg=10_000.0,
        )
        assert order.origin_hub != order.destination_hub


# ---------------------------------------------------------------------------
# DispatchOrder — Tracking Reference Invariant Violations
# ---------------------------------------------------------------------------


class TestDispatchOrderTrackingRefInvariants:
    """Tracking reference format enforcement."""

    def test_rejects_too_short_ref(self) -> None:
        """Tracking ref shorter than 6 chars is invalid."""
        with pytest.raises(ValueError, match="tracking_ref"):
            DispatchOrder(
                tracking_ref="TNG",  # Only 3 chars
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=1000.0,
            )

    def test_rejects_too_long_ref(self) -> None:
        """Tracking ref longer than 32 chars is invalid."""
        with pytest.raises(ValueError, match="tracking_ref"):
            DispatchOrder(
                tracking_ref="A" * 33,  # 33 chars — too long
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=1000.0,
            )

    def test_rejects_lowercase_ref(self) -> None:
        """Tracking ref must be uppercase alphanumeric."""
        with pytest.raises(ValueError, match="tracking_ref"):
            DispatchOrder(
                tracking_ref="tng-med-001",  # lowercase
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=1000.0,
            )

    def test_rejects_special_chars_in_ref(self) -> None:
        """Spaces and special chars are not allowed."""
        with pytest.raises(ValueError, match="tracking_ref"):
            DispatchOrder(
                tracking_ref="TNG MED 001",  # space
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=1000.0,
            )

    def test_rejects_empty_ref(self) -> None:
        with pytest.raises(ValueError):
            DispatchOrder(
                tracking_ref="",
                origin_hub="HUB_A",
                destination_hub="HUB_B",
                gross_weight_kg=1000.0,
            )


# ---------------------------------------------------------------------------
# SecurityIdentity
# ---------------------------------------------------------------------------


class TestSecurityIdentity:
    """SecurityIdentity validation tests."""

    def test_creates_valid_identity(self) -> None:
        identity = SecurityIdentity(
            user_id="u-001",
            client_id="c-001",
            role=UserRole.OPERATOR,
            jti="jwt-id-001",
            has_privilege=False,
        )
        assert identity.user_id == "u-001"
        assert identity.role == UserRole.OPERATOR
        assert not identity.has_privilege

    def test_privileged_roles(self) -> None:
        for role in (UserRole.SEC_ADMIN, UserRole.TECHNICIAN):
            identity = SecurityIdentity(
                user_id="u-001",
                client_id="c-001",
                role=role,
                jti="jwt-id-001",
                has_privilege=True,
            )
            assert identity.has_privilege

    def test_rejects_empty_user_id(self) -> None:
        with pytest.raises(ValueError, match="user_id"):
            SecurityIdentity(
                user_id="",
                client_id="c-001",
                role=UserRole.OPERATOR,
                jti="jwt-id-001",
                has_privilege=False,
            )

    def test_rejects_empty_jti(self) -> None:
        with pytest.raises(ValueError, match="jti"):
            SecurityIdentity(
                user_id="u-001",
                client_id="c-001",
                role=UserRole.OPERATOR,
                jti="",
                has_privilege=False,
            )

    def test_is_frozen(self) -> None:
        identity = SecurityIdentity(
            user_id="u-001",
            client_id="c-001",
            role=UserRole.OPERATOR,
            jti="jwt-id-001",
            has_privilege=False,
        )
        with pytest.raises((TypeError, AttributeError)):
            identity.user_id = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TransportMode and OrderStatus Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_transport_modes(self) -> None:
        assert TransportMode("ROAD_TIR") == TransportMode.ROAD_TIR
        assert TransportMode("MARITIME_CONTAINER") == TransportMode.MARITIME_CONTAINER
        assert TransportMode("AIR_FREIGHT") == TransportMode.AIR_FREIGHT

    def test_order_statuses(self) -> None:
        assert OrderStatus("PENDING_CUSTOMS") == OrderStatus.PENDING_CUSTOMS
        assert OrderStatus("ACCEPTED") == OrderStatus.ACCEPTED
        assert OrderStatus("REJECTED") == OrderStatus.REJECTED
        assert OrderStatus("SECURITY_HOLD") == OrderStatus.SECURITY_HOLD

    def test_user_roles(self) -> None:
        assert UserRole("SEC_ADMIN") == UserRole.SEC_ADMIN
        assert UserRole("TECHNICIAN") == UserRole.TECHNICIAN
        assert UserRole("OPERATOR") == UserRole.OPERATOR
        assert UserRole("B2B_CLIENT") == UserRole.B2B_CLIENT
