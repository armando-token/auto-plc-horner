"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Interval Tree SCADA Canvas (W300).

Work Package: W300 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Interval Tree SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Constants, viewport dimensions, WCAG AAA palettes, status bits, and diagnostic codes (0x8417..0x8419)
2. 1D Interval1D / Interval creation, validation, length, span, center, point containment, overlaps, intersection, distance
3. Invalid intervals validation (low > high raises ValueError, NaN/Inf coordinate rejection)
4. IntervalNode AVL balance factor, height tracking, and augmented max_high calculation
5. IntervalTree dynamic insertions, AVL rebalancing, query_overlap, query_point, deletion, and in-order traversal
6. Box2D / SpatialInterval2D geometry and dual-tree SpatialIntervalTree2D orthogonal projection
7. 2D spatial window queries, point containment queries, collisions, and conflict detection
8. Spatial conflict hazard alarm tripping (%M610, diagnostic code 0x8417)
9. W3C SVG 1.1 vector graphic generation, valid XML parsing, and WCAG 2.1 AAA contrast (> 18:1)
10. Horner OCS register space synchronization (%R2610..%R2617, %M609..%M610) and signed 16-bit masking
11. Pure IEC 61131-3 Structured Text validation & anti-ladder rejection with LadderForbiddenError
12. ILogicUnit interface compliance (scan_step with args/kwargs, step, execute, reset, multi-cycle soak)
13. Deterministic 9-stage verification runner execution and artifact export
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.interval_tree_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    TOTAL_DOMAIN_AREA,
    DEFAULT_DOMAIN_MIN,
    DEFAULT_DOMAIN_MAX,
    DEFAULT_CONFLICT_THRESHOLD,
    DEFAULT_HAZARD_THRESHOLD,
    DEFAULT_MAX_DEPTH,
    COLOR_SCADA_BG,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_BORDER,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_SAMPLE_NODE,
    COLOR_SAMPLE_BORDER,
    COLOR_NOMINAL_EMERALD,
    COLOR_WARNING_AMBER,
    COLOR_ALARM_CRIMSON,
    COLOR_RETICLE_CYAN,
    DEPTH_COLORS,
    REG_INTERVAL_TOTAL_COUNT,
    REG_INTERVAL_TOTAL_INTERVALS,
    REG_INTERVAL_TOTAL_OBJECTS,
    REG_INTERVAL_TREE_DEPTH,
    REG_INTERVAL_HIERARCHY_DEPTH,
    REG_INTERVAL_MATCH_COUNT,
    REG_INTERVAL_QUERY_MATCH_COUNT,
    REG_INTERVAL_ACTIVE_ID,
    REG_INTERVAL_SELECTED_OBJECT_ID,
    REG_INTERVAL_PV_SCALED,
    REG_INTERVAL_TOTAL_SPAN_SCALED,
    REG_INTERVAL_CONFLICT_COUNT,
    REG_INTERVAL_CONFLICT_THRESHOLD_SCALED,
    REG_INTERVAL_CONFLICT_VIOLATIONS_COUNT,
    REG_INTERVAL_STATUS_WORD,
    REG_INTERVAL_DIAGNOSTIC_CODE,
    COIL_INTERVAL_ONLINE,
    COIL_INTERVAL_INDEXING_ONLINE,
    COIL_INTERVAL_CONFLICT_ALARM,
    COIL_INTERVAL_HAZARD_ALARM,
    COIL_INTERVAL_ACTIVE,
    REG_W300_TOTAL_COUNT,
    REG_W300_TREE_DEPTH,
    REG_W300_MATCH_COUNT,
    REG_W300_ACTIVE_ID,
    REG_W300_PV_SCALED,
    REG_W300_CONFLICT_COUNT,
    REG_W300_STATUS_WORD,
    REG_W300_DIAGNOSTIC_CODE,
    COIL_W300_INDEXING_ONLINE,
    COIL_W300_CONFLICT_ALARM,
    COIL_W300_HAZARD_ALARM,
    DiagnosticCode,
    IntervalDiagnosticCode,
    DIAG_OK,
    DIAG_ERR_SPATIAL_INTERVAL_CONFLICT,
    DIAG_ERR_INVALID_RANGE,
    DIAG_ERR_EMPTY_TREE,
    DIAG_ERR_CONFLICT,
    DIAG_ERR_INTERVAL_CONFLICT,
    DIAG_ERR_INTERVAL_CONFLICT_HAZARD,
    IntervalStatusBits,
    IntervalTreeStatusBits,
    Interval,
    Interval1D,
    IntervalNode,
    IntervalTree,
    Box2D,
    Interval2D,
    SpatialBox2D,
    SpatialInterval2D,
    SpatialIntervalTree2D,
    SpatialConflictRecord,
    IntervalMetrics,
    IntervalTreeMetrics,
    IntervalTreeCanvasEngine,
    IntervalTreeCanvas,
    IntervalTreeCanvasLogicUnit,
    ST_PROGRAM_INTERVAL_TREE_CANVAS_SYNC,
    INTERVAL_TREE_CANVAS_PURE_ST_POU,
    IntervalTreeCanvasSync,
    verify_interval_tree_canvas_pure_st,
    _srgb_to_linear,
    _hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    generate_interval_tree_canvas_svg,
    create_canonical_interval_tree_canvas,
    run_interval_tree_canvas_verification,
)


# ============================================================================
# 1. Constants, Palette, Register Maps, and Diagnostic Codes
# ============================================================================

class TestIntervalConstantsAndRegisters:
    """Test suite for W300 constants, palettes, register maps, and diagnostic codes."""

    def test_viewport_dimensions_and_domain(self) -> None:
        """Verify canvas dimensions and domain calculations."""
        assert CANVAS_VIEWPORT_WIDTH == 1200.0
        assert CANVAS_VIEWPORT_HEIGHT == 750.0
        assert TOTAL_DOMAIN_AREA == 1200.0 * 750.0
        assert DEFAULT_DOMAIN_MIN == 0.0
        assert DEFAULT_DOMAIN_MAX == 100.0
        assert DEFAULT_CONFLICT_THRESHOLD == 25.0
        assert DEFAULT_HAZARD_THRESHOLD == 25.0
        assert DEFAULT_MAX_DEPTH == 16

    def test_scada_wcag_palette_colors(self) -> None:
        """Verify SCADA high-contrast color palette definitions."""
        assert COLOR_SCADA_BG == "#0D1117"
        assert COLOR_DARK_SURFACE == "#161B22"
        assert COLOR_DECOUPLED_BADGE == "#05080C"
        assert COLOR_BORDER == "#334155"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_TEXT_MUTED == "#CBD5E1"
        assert COLOR_NOMINAL_EMERALD == "#10B981"
        assert COLOR_WARNING_AMBER == "#F59E0B"
        assert COLOR_ALARM_CRIMSON == "#EF4444"
        assert COLOR_RETICLE_CYAN == "#06B6D4"

    def test_depth_colors_hierarchy(self) -> None:
        """Verify depth colors list structure and entries."""
        assert len(DEPTH_COLORS) >= 13
        for hex_color in DEPTH_COLORS:
            assert hex_color.startswith("#")
            assert len(hex_color) == 7

    def test_horner_register_map_addresses_and_aliases(self) -> None:
        """Verify Horner OCS register addresses %R2610..%R2617 and alias equivalence."""
        assert REG_INTERVAL_TOTAL_COUNT == "%R2610"
        assert REG_INTERVAL_TOTAL_INTERVALS == "%R2610"
        assert REG_INTERVAL_TOTAL_OBJECTS == "%R2610"
        assert REG_INTERVAL_TREE_DEPTH == "%R2611"
        assert REG_INTERVAL_HIERARCHY_DEPTH == "%R2611"
        assert REG_INTERVAL_MATCH_COUNT == "%R2612"
        assert REG_INTERVAL_QUERY_MATCH_COUNT == "%R2612"
        assert REG_INTERVAL_ACTIVE_ID == "%R2613"
        assert REG_INTERVAL_SELECTED_OBJECT_ID == "%R2613"
        assert REG_INTERVAL_PV_SCALED == "%R2614"
        assert REG_INTERVAL_TOTAL_SPAN_SCALED == "%R2614"
        assert REG_INTERVAL_CONFLICT_COUNT == "%R2615"
        assert REG_INTERVAL_CONFLICT_THRESHOLD_SCALED == "%R2615"
        assert REG_INTERVAL_STATUS_WORD == "%R2616"
        assert REG_INTERVAL_CONFLICT_VIOLATIONS_COUNT == "%R2616"
        assert REG_INTERVAL_DIAGNOSTIC_CODE == "%R2617"

        # W300 aliases
        assert REG_W300_TOTAL_COUNT == "%R2610"
        assert REG_W300_TREE_DEPTH == "%R2611"
        assert REG_W300_MATCH_COUNT == "%R2612"
        assert REG_W300_ACTIVE_ID == "%R2613"
        assert REG_W300_PV_SCALED == "%R2614"
        assert REG_W300_CONFLICT_COUNT == "%R2615"
        assert REG_W300_STATUS_WORD == "%R2616"
        assert REG_W300_DIAGNOSTIC_CODE == "%R2617"

    def test_horner_coil_addresses_and_aliases(self) -> None:
        """Verify Horner OCS discrete coil addresses %M609..%M610 and aliases."""
        assert COIL_INTERVAL_ONLINE == "%M609"
        assert COIL_INTERVAL_INDEXING_ONLINE == "%M609"
        assert COIL_INTERVAL_CONFLICT_ALARM == "%M610"
        assert COIL_INTERVAL_HAZARD_ALARM == "%M610"
        assert COIL_INTERVAL_ACTIVE == "%M609"
        assert COIL_W300_INDEXING_ONLINE == "%M609"
        assert COIL_W300_CONFLICT_ALARM == "%M610"
        assert COIL_W300_HAZARD_ALARM == "%M610"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        """Verify diagnostic codes match W300 specification."""
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_ERR_SPATIAL_INTERVAL_CONFLICT) == 0x8417
        assert int(DIAG_ERR_INVALID_RANGE) == 0x8418
        assert int(DIAG_ERR_EMPTY_TREE) == 0x8419

        assert int(DIAG_ERR_CONFLICT) == 0x8417
        assert int(DIAG_ERR_INTERVAL_CONFLICT) == 0x8417
        assert int(DIAG_ERR_INTERVAL_CONFLICT_HAZARD) == 0x8417

        assert "0x0000" in str(DIAG_OK)
        assert "0x8417" in str(DIAG_ERR_SPATIAL_INTERVAL_CONFLICT)
        assert repr(DIAG_OK) == "DiagnosticCode(0x0000)"

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        """Verify DiagnosticCode handles 16-bit signed/unsigned equivalence."""
        # 0x8417 unsigned = 33815, signed = -31721
        code_8417 = DiagnosticCode(0x8417)
        assert code_8417 == 0x8417
        assert code_8417 == 33815
        assert code_8417 == -31721
        assert code_8417 == DiagnosticCode(0x8417)
        assert code_8417 == DIAG_ERR_SPATIAL_INTERVAL_CONFLICT

        # 0x8418 unsigned = 33816, signed = -31720
        code_8418 = DiagnosticCode(0x8418)
        assert code_8418 == 0x8418
        assert code_8418 == 33816
        assert code_8418 == -31720

        # 0x8419 unsigned = 33817, signed = -31719
        code_8419 = DiagnosticCode(0x8419)
        assert code_8419 == 0x8419
        assert code_8419 == 33817
        assert code_8419 == -31719

        assert hash(code_8417) == hash(0x8417)
        assert code_8417 != "invalid_type"

    def test_status_bits_enumeration(self) -> None:
        """Verify IntervalTreeStatusBits bitmask flags."""
        assert IntervalTreeStatusBits.INDEXING_ONLINE == 1
        assert IntervalTreeStatusBits.CONFLICT_HAZARD_ALARM == 2
        assert IntervalTreeStatusBits.OUT_OF_TOLERANCE == 4
        assert IntervalTreeStatusBits.BALANCED == 8
        assert IntervalTreeStatusBits.MAX_DEPTH_REACHED == 16
        assert IntervalTreeStatusBits.DEGENERATE_INTERVAL == 32
        assert IntervalTreeStatusBits.INVALID_DOMAIN == 64
        assert IntervalTreeStatusBits.SVG_RENDER_VALID == 128
        assert IntervalTreeStatusBits.ONLINE == 1
        assert IntervalTreeStatusBits.CONFLICT_DETECTED == 2


# ============================================================================
# 2. 1D Interval Creation, Validation, Geometry, and Incompatibilities
# ============================================================================

class TestIntervalGeometry:
    """Test suite for 1D Interval1D data structure, queries, and validation."""

    def test_interval_creation_and_properties(self) -> None:
        """Verify valid Interval creation, length, span, center, and metadata."""
        iv = Interval(10.0, 50.0, id=1, label="FEED_ZONE", category="feed", tolerance_band="warning", priority=2)
        assert iv.id == 1
        assert iv.low == 10.0
        assert iv.high == 50.0
        assert iv.length == 40.0
        assert iv.span == 40.0
        assert iv.center == 30.0
        assert iv.label == "FEED_ZONE"
        assert iv.category == "feed"
        assert iv.tolerance_band == "warning"
        assert iv.priority == 2

    def test_interval_point_containment(self) -> None:
        """Verify inclusive point containment and boundary edge cases."""
        iv = Interval(20.0, 80.0, id=1)
        assert iv.contains_point(20.0) is True  # Left boundary
        assert iv.contains_point(80.0) is True  # Right boundary
        assert iv.contains_point(50.0) is True  # Interior point
        assert iv.contains_point(19.9) is False  # Left exterior
        assert iv.contains_point(80.1) is False  # Right exterior

    def test_interval_overlap_detection(self) -> None:
        """Verify overlaps with other intervals and arbitrary ranges."""
        iv1 = Interval(10.0, 30.0, id=1)
        iv2 = Interval(20.0, 40.0, id=2)  # Partial overlap
        iv3 = Interval(30.0, 50.0, id=3)  # Touching boundary
        iv4 = Interval(31.0, 50.0, id=4)  # Disjoint
        iv5 = Interval(12.0, 25.0, id=5)  # Strict subset

        assert iv1.overlaps(20.0, 40.0) is True
        assert iv1.overlaps(iv2) is True
        assert iv2.overlaps(iv1) is True
        assert iv1.overlaps(iv3) is True  # Touching boundary
        assert iv1.overlaps(iv4) is False
        assert iv1.overlaps(iv5) is True

    def test_interval_overlap_length(self) -> None:
        """Verify overlap_length calculation between two intervals."""
        iv1 = Interval(10.0, 50.0, id=1)
        iv2 = Interval(30.0, 80.0, id=2)
        iv3 = Interval(90.0, 120.0, id=3)

        assert iv1.overlap_length(iv2) == 20.0
        assert iv2.overlap_length(iv1) == 20.0
        assert iv1.overlap_length(iv3) == 0.0

    def test_interval_incompatibility_rules(self) -> None:
        """Verify is_incompatible_with flags incompatible control categories."""
        iv_cooling = Interval(40.0, 60.0, id=1, category="cooling")
        iv_heating = Interval(50.0, 70.0, id=2, category="heating")
        iv_nominal = Interval(45.0, 65.0, id=3, category="nominal")

        # Cooling and heating overlapping is strictly incompatible
        assert iv_cooling.is_incompatible_with(iv_heating) is True
        assert iv_heating.is_incompatible_with(iv_cooling) is True

        # Cooling and nominal is compatible
        assert iv_cooling.is_incompatible_with(iv_nominal) is False

        # Acid and base incompatibility
        iv_acid = Interval(10.0, 30.0, id=4, category="acid")
        iv_base = Interval(20.0, 40.0, id=5, category="base")
        assert iv_acid.is_incompatible_with(iv_base) is True

        # Non-overlapping cooling and heating is not incompatible
        iv_cooling_far = Interval(10.0, 20.0, id=6, category="cooling")
        assert iv_cooling_far.is_incompatible_with(iv_heating) is False

    def test_interval_invalid_low_greater_than_high_raises(self) -> None:
        """Verify low > high raises ValueError."""
        with pytest.raises(ValueError, match="Invalid range"):
            Interval(50.0, 10.0, id=1)

        with pytest.raises(ValueError):
            Interval(100.0, -10.0, id=2)

    def test_interval_nan_and_inf_coordinates_raises(self) -> None:
        """Verify NaN and Inf coordinates raise ValueError."""
        with pytest.raises(ValueError, match="Degenerate interval"):
            Interval(float("nan"), 10.0, id=1)

        with pytest.raises(ValueError, match="Degenerate interval"):
            Interval(10.0, float("nan"), id=2)

        with pytest.raises(ValueError, match="Degenerate interval"):
            Interval(float("-inf"), 10.0, id=3)

        with pytest.raises(ValueError, match="Degenerate interval"):
            Interval(10.0, float("inf"), id=4)

    def test_interval_zero_length_point_interval(self) -> None:
        """Verify zero-length degenerate interval [x, x] is valid."""
        iv = Interval(42.0, 42.0, id=99)
        assert iv.length == 0.0
        assert iv.center == 42.0
        assert iv.contains_point(42.0) is True
        assert iv.contains_point(42.1) is False


# ============================================================================
# 3. Augmented AVL IntervalTree Data Structure (CLRS)
# ============================================================================

class TestIntervalTreeAugmentedAVL:
    """Test suite for AVL-balanced Augmented IntervalTree."""

    def test_interval_node_initialization(self) -> None:
        """Verify IntervalNode initial state, center, and max_high augmentation."""
        iv = Interval(15.0, 25.0, id=1)
        node = IntervalNode(interval=iv)
        assert node.interval == iv
        assert node.center == 20.0
        assert node.max_high == 25.0
        assert node.left is None
        assert node.right is None
        assert node.height == 1
        assert node.balance_factor == 0

    def test_interval_node_augmentation_update(self) -> None:
        """Verify update_augmentation correctly computes height and max_high."""
        iv_parent = Interval(20.0, 30.0, id=1)
        iv_left = Interval(5.0, 45.0, id=2)
        iv_right = Interval(50.0, 60.0, id=3)

        node = IntervalNode(interval=iv_parent)
        node.left = IntervalNode(interval=iv_left)
        node.right = IntervalNode(interval=iv_right)

        node.update_augmentation()
        assert node.height == 2
        assert node.max_high == 60.0
        assert node.balance_factor == 0

    def test_interval_tree_insertion_and_count(self) -> None:
        """Verify tree insertion increments count and rejects duplicate IDs."""
        tree = IntervalTree()
        assert len(tree) == 0
        assert tree.count == 0
        assert tree.root is None

        ok1 = tree.insert(Interval(10.0, 20.0, id=1))
        assert ok1 is True
        assert len(tree) == 1
        assert tree.count == 1
        assert tree.root is not None
        assert tree.root.max_high == 20.0

        # Duplicate ID should be rejected
        ok_dup = tree.insert(Interval(15.0, 25.0, id=1))
        assert ok_dup is False
        assert len(tree) == 1

        ok2 = tree.insert(Interval(30.0, 50.0, id=2))
        assert ok2 is True
        assert len(tree) == 2
        assert tree.root.max_high == 50.0

    def test_interval_tree_height_and_avl_balance(self) -> None:
        """Verify inserting sequential sorted intervals maintains AVL balance (height <= log2(N) + 2)."""
        tree = IntervalTree()
        for i in range(1, 32):
            tree.insert(Interval(float(i * 10), float(i * 10 + 5), id=i))

        assert len(tree) == 31
        assert tree.is_balanced is True
        assert tree.height <= 6
        assert tree.depth == tree.height

    def test_interval_tree_deletion_and_rebalance(self) -> None:
        """Verify tree deletion removes item, updates count, and maintains balance."""
        tree = IntervalTree()
        tree.insert(Interval(10.0, 20.0, id=1))
        tree.insert(Interval(30.0, 40.0, id=2))
        tree.insert(Interval(50.0, 60.0, id=3))

        assert len(tree) == 3
        ok_del = tree.delete(2)
        assert ok_del is True
        assert len(tree) == 2
        assert tree.is_balanced is True

        assert tree.delete(999) is False

    def test_interval_tree_query_overlap(self) -> None:
        """Verify range overlap search returns all intersecting intervals."""
        tree = IntervalTree()
        tree.insert(Interval(10.0, 30.0, id=1, label="A", tag="A"))
        tree.insert(Interval(25.0, 45.0, id=2, label="B", tag="B"))
        tree.insert(Interval(50.0, 80.0, id=3, label="C", tag="C"))
        tree.insert(Interval(100.0, 150.0, id=4, label="D", tag="D"))

        # Query range [28.0, 45.0] matches A (10..30), B (25..45), and C (50..80 touching at 50 if up to 55)
        matches = tree.query_overlap(28.0, 45.0)
        match_ids = {iv.id for iv in matches}
        assert match_ids == {1, 2}

        # Query non-overlapping range returns empty
        assert tree.query_overlap(200.0, 300.0) == []

    def test_interval_tree_query_point(self) -> None:
        """Verify point containment query returns enclosing intervals."""
        tree = IntervalTree()
        tree.insert(Interval(10.0, 50.0, id=1))
        tree.insert(Interval(20.0, 30.0, id=2))
        tree.insert(Interval(40.0, 60.0, id=3))

        matches_25 = tree.query_point(25.0)
        assert {iv.id for iv in matches_25} == {1, 2}

        matches_45 = tree.query_point(45.0)
        assert {iv.id for iv in matches_45} == {1, 3}

        assert len(tree.query_point(100.0)) == 0

    def test_interval_tree_get_all_intervals(self) -> None:
        """Verify get_all_intervals returns all indexed intervals."""
        tree = IntervalTree()
        tree.insert(Interval(10.0, 20.0, id=1))
        tree.insert(Interval(30.0, 40.0, id=2))

        all_ivs = tree.get_all_intervals()
        assert len(all_ivs) == 2
        assert {iv.id for iv in all_ivs} == {1, 2}

    def test_interval_tree_clear(self) -> None:
        """Verify clear resets tree to empty state."""
        tree = IntervalTree()
        tree.insert(Interval(10.0, 20.0, id=1))
        tree.clear()
        assert len(tree) == 0
        assert tree.root is None
        assert tree.height == 0

    def test_interval_tree_brute_force_equivalence(self) -> None:
        """Verify 50 random overlap queries match brute-force ground truth."""
        rng = random.Random(42)
        intervals: List[Interval] = []
        tree = IntervalTree()

        for i in range(50):
            low = rng.uniform(0.0, 1000.0)
            high = low + rng.uniform(5.0, 100.0)
            iv = Interval(low, high, id=i + 1)
            intervals.append(iv)
            tree.insert(iv)

        for _ in range(50):
            q_low = rng.uniform(0.0, 1000.0)
            q_high = q_low + rng.uniform(10.0, 150.0)

            tree_ids = {iv.id for iv in tree.query_overlap(q_low, q_high)}
            brute_ids = {iv.id for iv in intervals if iv.overlaps(q_low, q_high)}
            assert tree_ids == brute_ids


# ============================================================================
# 4. 2D Bounding Box & SpatialIntervalTree2D (Dual Orthogonal Trees)
# ============================================================================

class TestSpatialIntervalTree2D:
    """Test suite for SpatialInterval2D and dual orthogonal SpatialIntervalTree2D."""

    def test_box2d_properties_and_calculations(self) -> None:
        """Verify SpatialInterval2D geometric dimensions, area, and center."""
        box = SpatialInterval2D(id=1, xmin=100.0, ymin=50.0, xmax=250.0, ymax=150.0, tag="VESSEL_1")
        assert box.id == 1
        assert box.xmin == 100.0
        assert box.ymin == 50.0
        assert box.xmax == 250.0
        assert box.ymax == 150.0
        assert box.width == 150.0
        assert box.height == 100.0
        assert box.area == 15000.0
        assert box.center_x == 175.0
        assert box.center_y == 100.0
        assert box.center == (175.0, 100.0)

    def test_box2d_invalid_coordinates_raises(self) -> None:
        """Verify invalid bounds (xmin > xmax, NaN, Inf) raise ValueError."""
        with pytest.raises(ValueError, match="bounding box.*xmin cannot be greater than xmax"):
            SpatialInterval2D(id=1, xmin=200.0, ymin=50.0, xmax=100.0, ymax=150.0)

        with pytest.raises(ValueError, match="bounding box.*NaN or Inf"):
            SpatialInterval2D(id=2, xmin=float("nan"), ymin=50.0, xmax=100.0, ymax=150.0)

    def test_box2d_intersection_and_distance(self) -> None:
        """Verify SpatialInterval2D intersects, overlaps_2d, and distance_to."""
        b1 = SpatialInterval2D(id=1, xmin=100.0, ymin=100.0, xmax=200.0, ymax=200.0)
        b2 = SpatialInterval2D(id=2, xmin=150.0, ymin=150.0, xmax=250.0, ymax=250.0)
        b3 = SpatialInterval2D(id=3, xmin=300.0, ymin=300.0, xmax=400.0, ymax=400.0)

        assert b1.intersects(b2) is True
        assert b1.overlaps_2d(b2) is True
        assert b1.intersects(b3) is False
        assert b1.overlaps_2d(b3) is False

        assert b1.distance_to(b2) == 0.0
        assert b1.distance_to(b3) > 0.0

    def test_box2d_containment_queries(self) -> None:
        """Verify SpatialInterval2D point containment."""
        outer = SpatialInterval2D(id=1, xmin=50.0, ymin=50.0, xmax=300.0, ymax=300.0)
        assert outer.contains_point(150.0, 150.0) is True
        assert outer.contains_point(40.0, 150.0) is False

    def test_spatial_interval_tree_2d_insertion_and_deletion(self) -> None:
        """Verify SpatialIntervalTree2D inserts and deletes 2D entities across dual trees."""
        sp_tree = SpatialIntervalTree2D()
        b1 = SpatialInterval2D(id=1, xmin=10.0, ymin=10.0, xmax=50.0, ymax=50.0)
        b2 = SpatialInterval2D(id=2, xmin=60.0, ymin=60.0, xmax=100.0, ymax=100.0)

        assert sp_tree.insert(b1) is True
        assert sp_tree.insert(b2) is True
        assert len(sp_tree) == 2

        # Delete
        assert sp_tree.delete(1) is True
        assert len(sp_tree) == 1
        assert sp_tree.delete(999) is False

    def test_spatial_interval_tree_2d_query_window(self) -> None:
        """Verify 2D window query via dual orthogonal interval tree search."""
        sp_tree = SpatialIntervalTree2D()
        b1 = SpatialInterval2D(id=101, xmin=10.0, ymin=10.0, xmax=30.0, ymax=30.0)
        b2 = SpatialInterval2D(id=102, xmin=50.0, ymin=50.0, xmax=80.0, ymax=80.0)
        b3 = SpatialInterval2D(id=103, xmin=200.0, ymin=200.0, xmax=250.0, ymax=250.0)

        sp_tree.insert(b1)
        sp_tree.insert(b2)
        sp_tree.insert(b3)

        # Window covering only b1 and b2
        query_rect = SpatialInterval2D(id=0, xmin=5.0, ymin=5.0, xmax=90.0, ymax=90.0)
        matches = sp_tree.query_window(query_rect)
        assert {b.id for b in matches} == {101, 102}

    def test_spatial_interval_tree_2d_query_point(self) -> None:
        """Verify 2D point containment query."""
        sp_tree = SpatialIntervalTree2D()
        b = SpatialInterval2D(id=1, xmin=100.0, ymin=100.0, xmax=200.0, ymax=200.0)
        sp_tree.insert(b)

        assert len(sp_tree.query_point(150.0, 150.0)) == 1
        assert sp_tree.query_point(150.0, 150.0)[0].id == 1
        assert len(sp_tree.query_point(50.0, 50.0)) == 0

    def test_spatial_interval_tree_2d_detect_conflicts(self) -> None:
        """Verify detect_conflicts identifies all intersecting pairs."""
        sp_tree = SpatialIntervalTree2D()
        b1 = SpatialInterval2D(id=1, xmin=100.0, ymin=100.0, xmax=200.0, ymax=200.0)
        b2 = SpatialInterval2D(id=2, xmin=150.0, ymin=150.0, xmax=250.0, ymax=250.0)
        b3 = SpatialInterval2D(id=3, xmin=500.0, ymin=500.0, xmax=600.0, ymax=600.0)

        sp_tree.insert(b1)
        sp_tree.insert(b2)
        sp_tree.insert(b3)

        conflicts = sp_tree.detect_conflicts()
        assert len(conflicts) == 1
        assert (conflicts[0][0].id, conflicts[0][1].id) == (1, 2)

    def test_spatial_interval_tree_2d_clear(self) -> None:
        """Verify clear empties dual trees."""
        sp_tree = SpatialIntervalTree2D()
        sp_tree.insert(SpatialInterval2D(id=1, xmin=10.0, ymin=10.0, xmax=20.0, ymax=20.0))
        sp_tree.clear()
        assert len(sp_tree) == 0


# ============================================================================
# 5. IntervalTreeCanvasEngine & Spatial Conflict Hazard Alarms
# ============================================================================

class TestCanvasEngineAndConflictHazard:
    """Test suite for IntervalTreeCanvasEngine, 1D/2D management, and hazard alarms."""

    def test_engine_initialization_defaults(self) -> None:
        """Verify engine initialization with defaults."""
        eng = IntervalTreeCanvasEngine()
        assert eng.viewport_width == 1200.0
        assert eng.viewport_height == 750.0
        assert len(eng.tree_1d) == 0
        assert len(eng.objects) == 0
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        assert eng.online is True

    def test_engine_insert_and_delete_intervals(self) -> None:
        """Verify inserting and deleting 1D intervals in engine."""
        eng = IntervalTreeCanvasEngine()
        ok = eng.insert_interval(1, 10.0, 50.0, label="PUMP_SPEED")
        assert ok is True
        assert len(eng.tree_1d) == 1

        del_ok = eng.delete_interval(1)
        assert del_ok is True
        assert len(eng.tree_1d) == 0

    def test_engine_insert_interval_validation_errors(self) -> None:
        """Verify invalid ranges set DIAG_ERR_INVALID_RANGE or DIAG_ERR_INVALID_INTERVAL."""
        eng = IntervalTreeCanvasEngine()
        assert eng.insert_interval(1, 100.0, 50.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_RANGE

        assert eng.insert_interval(2, float("nan"), 50.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_RANGE

    def test_engine_query_point_and_empty_tree_diagnostic(self) -> None:
        """Verify query_point sets DIAG_ERR_EMPTY_TREE on empty tree and updates selected ID."""
        eng = IntervalTreeCanvasEngine()
        matches_empty = eng.query_point(45.0)
        assert len(matches_empty) == 0
        assert eng.diagnostic_code == DIAG_ERR_EMPTY_TREE
        assert eng.out_of_tolerance is True

        # Insert nominal intervals and query
        eng.insert_interval(1, 40.0, 60.0, label="NOMINAL", priority=1)
        matches = eng.query_point(50.0)
        assert len(matches) == 1
        assert eng.selected_object_id == 1
        assert eng.diagnostic_code == DIAG_OK
        assert eng.out_of_tolerance is False

    def test_engine_query_overlap_ranges(self) -> None:
        """Verify query_overlap on engine returns matching intervals and updates selected ID."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_interval(1, 10.0, 30.0, priority=1)
        eng.insert_interval(2, 25.0, 45.0, priority=5)

        matches = eng.query_overlap(20.0, 40.0)
        assert len(matches) == 2
        # Highest priority item should be selected as active ID
        assert eng.selected_object_id == 2

    def test_engine_insert_and_query_box_2d(self) -> None:
        """Verify 2D box insertion and window search in engine."""
        eng = IntervalTreeCanvasEngine()
        ok = eng.insert_box_2d(1, 100.0, 100.0, 200.0, 200.0, label="REACTOR_01")
        assert ok is True
        assert len(eng.objects) == 1

        matches = eng.search_window(50.0, 50.0, 250.0, 250.0)
        assert len(matches) == 1
        assert matches[0].id == 1

    def test_spatial_conflict_hazard_alarm_tripping(self) -> None:
        """Verify overlapping objects trigger alarm %M610 and code 0x8417."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0, risk_level="high_risk")
        eng.insert_object(2, 150.0, 150.0, 250.0, 250.0, risk_level="high_risk")

        assert eng.alarm_active is True
        assert eng.diagnostic_code == 0x8417
        assert eng.diagnostic_code == DIAG_ERR_SPATIAL_INTERVAL_CONFLICT

    def test_inject_spatial_conflict_and_clear_alarm(self) -> None:
        """Verify inject_spatial_conflict and clear_alarm."""
        eng = IntervalTreeCanvasEngine()
        assert eng.alarm_active is False

        eng.inject_spatial_conflict()
        assert eng.alarm_active is True
        assert eng.diagnostic_code == 0x8417
        assert eng.conflict_violations_count >= 1

        eng.clear_alarm()
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        assert eng.conflict_violations_count == 0

    def test_metrics_snapshot_properties(self) -> None:
        """Verify IntervalTreeMetrics snapshot accurately reflects engine state."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)
        eng.search_window(50.0, 50.0, 300.0, 300.0)

        m = eng.metrics
        assert isinstance(m, IntervalTreeMetrics)
        assert m.total_objects == 1
        assert m.query_match_count == 1
        assert m.selected_object_id == 1
        assert m.indexing_online is True
        assert m.conflict_alarm is False
        assert m.diagnostic_code == DIAG_OK


# ============================================================================
# 6. Horner OCS Register Synchronization & Signed 16-Bit Masking
# ============================================================================

class TestHornerRegisterSynchronization:
    """Test suite for Horner OCS register space synchronization (%R2610..%R2617, %M609..%M610)."""

    def test_sync_to_registers_normal_state(self) -> None:
        """Verify register synchronization under normal operations."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)
        eng.search_window(50.0, 50.0, 250.0, 250.0)

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert (rt.read_word(REG_INTERVAL_TOTAL_OBJECTS) & 0xFFFF) == 1
        assert (rt.read_word(REG_INTERVAL_QUERY_MATCH_COUNT) & 0xFFFF) == 1
        assert (rt.read_word(REG_INTERVAL_SELECTED_OBJECT_ID) & 0xFFFF) == 1
        assert (rt.read_word(REG_INTERVAL_CONFLICT_THRESHOLD_SCALED) & 0xFFFF) == 250
        assert (rt.read_word(REG_INTERVAL_CONFLICT_VIOLATIONS_COUNT) & 0xFFFF) == 0
        assert (rt.read_word(REG_INTERVAL_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        assert rt.read_bit(COIL_INTERVAL_INDEXING_ONLINE) is True
        assert rt.read_bit(COIL_INTERVAL_CONFLICT_ALARM) is False

    def test_sync_to_registers_alarm_state_and_signed_masking(self) -> None:
        """Verify register sync under conflict alarm and signed 16-bit diagnostic masking."""
        eng = IntervalTreeCanvasEngine()
        eng.inject_spatial_conflict()

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        raw_diag = rt.read_word(REG_INTERVAL_DIAGNOSTIC_CODE)
        diag_u = raw_diag & 0xFFFF
        diag_s = diag_u - 0x10000 if diag_u >= 0x8000 else diag_u

        assert diag_u == 0x8417
        assert diag_s == -31721
        assert (rt.read_word(REG_INTERVAL_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8417
        assert rt.read_bit(COIL_INTERVAL_INDEXING_ONLINE) is True
        assert rt.read_bit(COIL_INTERVAL_CONFLICT_ALARM) is True

    def test_sync_to_registers_status_word_bitmask(self) -> None:
        """Verify status word and online indexing flag."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)

        assert (eng.status_word & IntervalTreeStatusBits.INDEXING_ONLINE) != 0

        rt = RegisterTable()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_INTERVAL_INDEXING_ONLINE) is True

    def test_sync_to_registers_privilege_modes(self) -> None:
        """Verify register synchronization accepts USER and SYSTEM privilege modes."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)

        rt_user = RegisterTable()
        eng.sync_to_registers(rt_user, privilege=PrivilegeMode.USER)
        assert rt_user.read_word(REG_INTERVAL_TOTAL_OBJECTS) == 1

        rt_sys = RegisterTable()
        eng.sync_to_registers(rt_sys, privilege=PrivilegeMode.SYSTEM)
        assert rt_sys.read_word(REG_INTERVAL_TOTAL_OBJECTS) == 1


# ============================================================================
# 7. ILogicUnit Interface Compliance & Simulation
# ============================================================================

class TestILogicUnitCompliance:
    """Test suite for ILogicUnit interface compliance and simulation."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify standard ILogicUnit properties."""
        eng = IntervalTreeCanvasEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "IntervalTreeCanvasEngine"
        assert eng.priority == 100
        assert eng.is_enabled is True

    def test_scan_step_with_and_without_context(self) -> None:
        """Verify scan_step executes with None or ScanContext returning ExecutionResult."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)

        res1 = eng.scan_step()
        assert isinstance(res1, ExecutionResult)
        assert res1.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 1

        ctx = ScanContext(cycle=2, dt_ms=10.0, register_table=eng.reg_table)
        res2 = eng.scan_step(ctx)
        assert res2.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 2

    def test_step_and_execute_delegation(self) -> None:
        """Verify step() and execute() delegate to scan_step()."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 10.0, 10.0, 20.0, 20.0)

        eng.step(0.01)
        assert eng.cycle_count == 1

        ctx = ScanContext(cycle=2, dt_ms=10.0)
        res = eng.execute(ctx)
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 2

    def test_engine_reset(self) -> None:
        """Verify reset restores clean initial state."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)
        eng.scan_step()

        eng.reset()
        assert eng.cycle_count == 0
        assert len(eng.tree_1d) == 0
        assert len(eng.objects) == 0
        assert eng.selected_object_id == 0
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK

    def test_continuous_scan_cycle_soak(self) -> None:
        """Verify continuous 50-cycle simulation soak with dynamic updates."""
        eng = IntervalTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)
        rt = RegisterTable()

        for c in range(1, 51):
            ctx = ScanContext(cycle=c, dt_ms=10.0, register_table=rt)
            eng.query_point(10.0 + (c % 20))
            res = eng.execute(ctx)
            assert res.status == AgentStatus.SUCCESS
            assert eng.cycle_count == c
            assert rt.read_bit(COIL_INTERVAL_INDEXING_ONLINE) is True


# ============================================================================
# 8. Vector SCADA SVG 1.1 Generation & WCAG 2.1 AAA Contrast
# ============================================================================

class TestSvgRenderingAndWcagContrast:
    """Test suite for SVG 1.1 vector graphic generation and WCAG 2.1 AAA contrast."""

    def test_srgb_to_linear_and_luminance_calculation(self) -> None:
        """Verify sRGB conversion and relative luminance formula."""
        assert _srgb_to_linear(0.0) == 0.0
        assert _srgb_to_linear(1.0) == 1.0

        lum_black = _hex_to_relative_luminance("#000000")
        lum_white = _hex_to_relative_luminance("#FFFFFF")
        assert lum_black == 0.0
        assert pytest.approx(lum_white, abs=1e-3) == 1.0

    def test_wcag_contrast_ratio_calculation(self) -> None:
        """Verify WCAG contrast ratio calculations."""
        ratio_max = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert pytest.approx(ratio_max, abs=0.01) == 21.0

        ratio_same = calculate_contrast_ratio("#10B981", "#10B981")
        assert pytest.approx(ratio_same, abs=0.01) == 1.0

    def test_validate_wcag_aaa_contrast(self) -> None:
        """Verify validate_wcag_aaa_contrast meets > 18:1 standard."""
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True
        assert validate_wcag_aaa_contrast("#334155", "#161B22", 18.0) is False

    def test_generate_interval_tree_canvas_svg_xml_validity(self) -> None:
        """Verify generated SVG is well-formed XML with valid root svg element."""
        eng = create_canonical_interval_tree_canvas()
        svg_text = generate_interval_tree_canvas_svg(eng)

        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_svg_structural_elements_and_hud(self) -> None:
        """Verify required interval tracks, 2D objects, and HUD scorecard are rendered."""
        eng = create_canonical_interval_tree_canvas()
        svg_text = generate_interval_tree_canvas_svg(eng)

        assert 'id="hud-telemetry-scorecard"' in svg_text
        assert 'id="interval-tracks"' in svg_text
        assert 'id="range-segment-bar"' in svg_text
        assert 'id="spatial-objects"' in svg_text
        assert "HORNER OCS" in svg_text and "(W300)" in svg_text


# ============================================================================
# 9. Pure IEC 61131-3 Structured Text & Anti-Ladder Security
# ============================================================================

class TestStructuredTextValidation:
    """Test suite for pure Structured Text POU validation and anti-ladder security."""

    def test_st_program_text_contains_registers_and_logic(self) -> None:
        """Verify ST program text contains registers %R2610..%R2617 and %M609..%M610."""
        text = ST_PROGRAM_INTERVAL_TREE_CANVAS_SYNC
        assert "PROGRAM IntervalTreeCanvasSync" in text
        assert "%R2610" in text
        assert "%R2617" in text
        assert "%M609" in text
        assert "%M610" in text
        assert "bOnline" in text
        assert "bConflictAlarm" in text

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify STParser compiles ST POU into valid AST."""
        res = STParser.validate_code(ST_PROGRAM_INTERVAL_TREE_CANVAS_SYNC)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ST_PROGRAM_INTERVAL_TREE_CANVAS_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "IntervalTreeCanvasSync"

    def test_verify_interval_tree_canvas_pure_st_function(self) -> None:
        """Verify helper verify_interval_tree_canvas_pure_st returns True."""
        assert verify_interval_tree_canvas_pure_st() is True
        assert verify_interval_tree_canvas_pure_st(INTERVAL_TREE_CANVAS_PURE_ST_POU) is True

    def test_anti_ladder_ladder_forbidden_error_rejection(self) -> None:
        """Verify SecurityGuard rejects ladder logic constructs."""
        ladder_snippets = [
            "PROGRAM P ---[ ]--- END_PROGRAM",
            "PROGRAM P ---[/]--- END_PROGRAM",
            "PROGRAM P ---( )--- END_PROGRAM",
            "PROGRAM P RUNG 1 END_PROGRAM",
            "PROGRAM P NETWORK 1 END_PROGRAM",
            "PROGRAM P XIC bit END_PROGRAM",
            "PROGRAM P OTE coil END_PROGRAM",
        ]
        for snip in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)
            assert verify_interval_tree_canvas_pure_st(snip) is False


# ============================================================================
# 10. Deterministic Verification Runner (9 Stages)
# ============================================================================

class TestVerificationRunner9Stages:
    """Test suite for run_interval_tree_canvas_verification."""

    def test_canonical_canvas_factory(self) -> None:
        """Verify create_canonical_interval_tree_canvas creates deterministic populated engine."""
        eng = create_canonical_interval_tree_canvas(seed=42)
        assert len(eng.objects) >= 5
        assert len(eng.tree_1d) >= 5

    def test_run_interval_tree_canvas_verification_9_stages_success(self, tmp_path: Path) -> None:
        """Verify 9-stage verification runner passes all stages with success status."""
        evidence_file = str(tmp_path / "test_evidence.json")
        svg_file = str(tmp_path / "test_sample.svg")

        res = run_interval_tree_canvas_verification(
            output_path=evidence_file,
            sample_svg_path=svg_file,
            work_package="W300",
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9
        assert all(s["passed"] for s in res["data"]["stages"])

    def test_verification_runner_exports_artifacts(self, tmp_path: Path) -> None:
        """Verify runner creates evidence JSON and SVG files with valid content."""
        evidence_file = str(tmp_path / "evidence.json")
        svg_file = str(tmp_path / "sample.svg")

        res = run_interval_tree_canvas_verification(
            output_path=evidence_file,
            sample_svg_path=svg_file,
            work_package="W300",
        )

        assert Path(evidence_file).exists()
        assert Path(svg_file).exists()

        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W300"
