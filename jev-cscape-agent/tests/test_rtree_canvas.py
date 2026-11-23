"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial R-Tree SCADA Canvas (W297).

Work Package: W297 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial R-Tree SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Constants, viewport dimensions, color palettes, status bits, and diagnostic codes (0x8411..0x8416)
2. RTreeRect geometry, area, intersection, union, containment, point containment, and degenerate box rejection
3. RTreeObject attributes, validation, centers, and risk levels
4. RTreeNode structure, entry addition, capacity limits (M=4, m=2), MBR computation, and quadratic split algorithm
5. Spatial window / range queries, strict containment queries, and point queries vs ground truth
6. Proximity hazard and spatial collision detection: overlapping high-risk zones trigger alarm %M603 and code 0x8416
7. W3C SVG 1.1 vector graphic generation, valid XML parsing, and WCAG 2.1 AAA contrast (> 18:1)
8. Horner OCS register space synchronization (%R2580..%R2587, %M602..%M603) and privilege levels
9. Pure IEC 61131-3 Structured Text validation & anti-ladder rejection
10. ILogicUnit interface compliance (scan_step, step, execute, reset, multi-cycle soak)
11. Deterministic 9-stage verification runner execution and artifact export
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.rtree_canvas import (
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    TOTAL_DOMAIN_AREA,
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MIN_ENTRIES,
    DEFAULT_HAZARD_THRESHOLD,
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
    COLOR_CONNECTOR_VECTOR,
    DEPTH_COLORS,
    REG_RTREE_TOTAL_OBJECTS,
    REG_RTREE_HIERARCHY_DEPTH,
    REG_RTREE_QUERY_MATCH_COUNT,
    REG_RTREE_SELECTED_OBJECT_ID,
    REG_RTREE_TOTAL_BOUNDING_AREA_SCALED,
    REG_RTREE_HAZARD_THRESHOLD_SCALED,
    REG_RTREE_HAZARD_VIOLATIONS_COUNT,
    REG_RTREE_DIAGNOSTIC_CODE,
    COIL_RTREE_INDEXING_ONLINE,
    COIL_RTREE_SPATIAL_COLLISION_ALARM,
    REG_W297_TOTAL_OBJECTS,
    REG_W297_HIERARCHY_DEPTH,
    REG_W297_QUERY_MATCH_COUNT,
    REG_W297_SELECTED_OBJECT_ID,
    REG_W297_TOTAL_BOUNDING_AREA_SCALED,
    REG_W297_HAZARD_THRESHOLD_SCALED,
    REG_W297_HAZARD_VIOLATIONS_COUNT,
    REG_W297_DIAGNOSTIC_CODE,
    COIL_W297_INDEXING_ONLINE,
    COIL_W297_SPATIAL_COLLISION_ALARM,
    REG_RTREE_OBJECT_COUNT,
    REG_RTREE_DEPTH,
    REG_RTREE_MATCH_COUNT,
    REG_RTREE_TARGET_ID,
    REG_RTREE_AREA_SCALED,
    REG_RTREE_HAZARD_THRESHOLD,
    REG_RTREE_VIOLATIONS_COUNT,
    COIL_RTREE_CANVAS_ACTIVE,
    COIL_RTREE_HAZARD_ALARM,
    COIL_W297_HAZARD_ALARM,
    COIL_RTREE_ACTIVE,
    COIL_RTREE_COLLISION_ALARM,
    COIL_RTREE_SPATIAL_HAZARD,
    COIL_W297_CANVAS_ACTIVE,
    COIL_W297_SPATIAL_HAZARD,
    DiagnosticCode,
    RTreeDiagnosticCode,
    DIAG_OK,
    DIAG_ERR_INVALID_DOMAIN,
    DIAG_ERR_EMPTY_TREE,
    DIAG_ERR_INVALID_CAPACITY,
    DIAG_ERR_DEGENERATE_BOUNDS,
    DIAG_ERR_QUERY_OUT_OF_BOUNDS,
    DIAG_ERR_SPATIAL_COLLISION_HAZARD,
    DIAG_ERR_HAZARD_ALARM,
    DIAG_ERR_COLLISION_HAZARD,
    RTreeStatusBits,
    RTreeRect,
    BoundingBox,
    RTreeBounds,
    RTreeObject,
    RTreeNode,
    RTreeMetrics,
    RTreeCanvasEngine,
    RTreeCanvas,
    RTreeCanvasLogicUnit,
    RTreeIndex,
    ST_PROGRAM_RTREE_CANVAS_SYNC,
    RTREE_CANVAS_PURE_ST_POU,
    RTreeCanvasSync,
    verify_rtree_canvas_pure_st,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    generate_rtree_canvas_svg,
    create_canonical_rtree_canvas,
    run_rtree_canvas_verification,
)


class TestRTreeConstantsAndRegisters:
    """Test suite for W297 constants, palettes, register maps, and diagnostic codes."""

    def test_viewport_and_capacity_constants(self) -> None:
        """Verify canvas dimensions, total domain area, and R-Tree capacity settings."""
        assert CANVAS_VIEWPORT_WIDTH == 1200.0
        assert CANVAS_VIEWPORT_HEIGHT == 750.0
        assert TOTAL_DOMAIN_AREA == 1200.0 * 750.0
        assert DEFAULT_MAX_ENTRIES == 4
        assert DEFAULT_MIN_ENTRIES == 2
        assert DEFAULT_HAZARD_THRESHOLD == 30.0

    def test_palette_colors_and_depth_styling(self) -> None:
        """Verify WCAG 2.1 AAA SCADA palette colors and depth levels."""
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

        assert len(DEPTH_COLORS) == 13
        for c in DEPTH_COLORS:
            assert c.startswith("#")
            assert len(c) == 7

    def test_register_mappings_and_aliases(self) -> None:
        """Verify Horner OCS register addresses %R2580..%R2587 and %M602..%M603."""
        assert REG_RTREE_TOTAL_OBJECTS == "%R2580"
        assert REG_RTREE_HIERARCHY_DEPTH == "%R2581"
        assert REG_RTREE_QUERY_MATCH_COUNT == "%R2582"
        assert REG_RTREE_SELECTED_OBJECT_ID == "%R2583"
        assert REG_RTREE_TOTAL_BOUNDING_AREA_SCALED == "%R2584"
        assert REG_RTREE_HAZARD_THRESHOLD_SCALED == "%R2585"
        assert REG_RTREE_HAZARD_VIOLATIONS_COUNT == "%R2586"
        assert REG_RTREE_DIAGNOSTIC_CODE == "%R2587"

        assert COIL_RTREE_INDEXING_ONLINE == "%M602"
        assert COIL_RTREE_SPATIAL_COLLISION_ALARM == "%M603"

        # W297 aliases
        assert REG_W297_TOTAL_OBJECTS == "%R2580"
        assert REG_W297_HIERARCHY_DEPTH == "%R2581"
        assert REG_W297_QUERY_MATCH_COUNT == "%R2582"
        assert REG_W297_SELECTED_OBJECT_ID == "%R2583"
        assert REG_W297_TOTAL_BOUNDING_AREA_SCALED == "%R2584"
        assert REG_W297_HAZARD_THRESHOLD_SCALED == "%R2585"
        assert REG_W297_HAZARD_VIOLATIONS_COUNT == "%R2586"
        assert REG_W297_DIAGNOSTIC_CODE == "%R2587"
        assert COIL_W297_INDEXING_ONLINE == "%M602"
        assert COIL_W297_SPATIAL_COLLISION_ALARM == "%M603"

        # Compatibility aliases
        assert REG_RTREE_OBJECT_COUNT == "%R2580"
        assert REG_RTREE_DEPTH == "%R2581"
        assert REG_RTREE_MATCH_COUNT == "%R2582"
        assert REG_RTREE_TARGET_ID == "%R2583"
        assert REG_RTREE_AREA_SCALED == "%R2584"
        assert REG_RTREE_HAZARD_THRESHOLD == "%R2585"
        assert REG_RTREE_VIOLATIONS_COUNT == "%R2586"
        assert COIL_RTREE_CANVAS_ACTIVE == "%M602"
        assert COIL_RTREE_HAZARD_ALARM == "%M603"
        assert COIL_W297_HAZARD_ALARM == "%M603"
        assert COIL_RTREE_ACTIVE == "%M602"
        assert COIL_RTREE_COLLISION_ALARM == "%M603"
        assert COIL_RTREE_SPATIAL_HAZARD == "%M603"
        assert COIL_W297_CANVAS_ACTIVE == "%M602"
        assert COIL_W297_SPATIAL_HAZARD == "%M603"

    def test_diagnostic_codes_and_equality(self) -> None:
        """Verify 16-bit diagnostic codes, signed/unsigned comparisons, and string representations."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_INVALID_DOMAIN == 0x8411
        assert DIAG_ERR_EMPTY_TREE == 0x8412
        assert DIAG_ERR_INVALID_CAPACITY == 0x8413
        assert DIAG_ERR_DEGENERATE_BOUNDS == 0x8414
        assert DIAG_ERR_QUERY_OUT_OF_BOUNDS == 0x8415
        assert DIAG_ERR_SPATIAL_COLLISION_HAZARD == 0x8416

        # Compatibility aliases
        assert DIAG_ERR_HAZARD_ALARM == 0x8416
        assert DIAG_ERR_COLLISION_HAZARD == 0x8416
        assert RTreeDiagnosticCode == DiagnosticCode

        # String representation
        assert str(DIAG_ERR_SPATIAL_COLLISION_HAZARD) == "0x8416"
        assert repr(DIAG_ERR_SPATIAL_COLLISION_HAZARD) == "DiagnosticCode(0x8416)"

        # Signed 16-bit negative equivalence check
        val_signed = 0x8416 - 0x10000
        assert DIAG_ERR_SPATIAL_COLLISION_HAZARD == val_signed

    def test_status_bits(self) -> None:
        """Verify RTreeStatusBits IntFlag bitmask."""
        flags = RTreeStatusBits.INDEXING_ONLINE | RTreeStatusBits.SVG_RENDER_VALID
        assert RTreeStatusBits.INDEXING_ONLINE in flags
        assert RTreeStatusBits.SPATIAL_COLLISION_ALARM not in flags


class TestRTreeRectGeometry:
    """Test suite for RTreeRect mathematical and geometric operations."""

    def test_rect_dimensions_and_area(self) -> None:
        """Verify width, height, area, and center calculations."""
        r = RTreeRect(100.0, 50.0, 400.0, 250.0)
        assert r.width == 300.0
        assert r.height == 200.0
        assert r.area == 60000.0
        assert r.center_x == 250.0
        assert r.center_y == 150.0

    def test_rect_intersection_and_intersects(self) -> None:
        """Verify intersecting and disjoint rectangle operations."""
        r1 = RTreeRect(100.0, 100.0, 300.0, 300.0)
        r2 = RTreeRect(200.0, 200.0, 400.0, 400.0)
        r3 = RTreeRect(500.0, 500.0, 600.0, 600.0)

        assert r1.intersects(r2) is True
        assert r1.intersects(r3) is False

        inter = r1.intersection(r2)
        assert inter is not None
        assert inter.x_min == 200.0
        assert inter.y_min == 200.0
        assert inter.x_max == 300.0
        assert inter.y_max == 300.0
        assert inter.area == 10000.0

        assert r1.intersection(r3) is None

    def test_rect_union_and_enlargement(self) -> None:
        """Verify union bounding box and enlargement area computation."""
        r1 = RTreeRect(100.0, 100.0, 200.0, 200.0)  # Area 10000
        r2 = RTreeRect(300.0, 300.0, 400.0, 400.0)  # Area 10000

        u = r1.union(r2)
        assert u.x_min == 100.0
        assert u.y_min == 100.0
        assert u.x_max == 400.0
        assert u.y_max == 400.0
        assert u.area == 90000.0

        enl = r1.enlargement_area(r2)
        assert enl == 90000.0 - 10000.0 == 80000.0

    def test_rect_contains_and_contains_point(self) -> None:
        """Verify rectangle containment and point containment."""
        outer = RTreeRect(50.0, 50.0, 500.0, 500.0)
        inner = RTreeRect(100.0, 100.0, 200.0, 200.0)
        overlap = RTreeRect(400.0, 400.0, 600.0, 600.0)

        assert outer.contains(inner) is True
        assert inner.contains(outer) is False
        assert outer.contains(overlap) is False

        assert outer.contains_point(150.0, 250.0) is True
        assert outer.contains_point(50.0, 50.0) is True  # Boundary inclusive
        assert outer.contains_point(10.0, 250.0) is False

    def test_rect_distance_to_rect(self) -> None:
        """Verify minimum Euclidean distance between disjoint and overlapping rects."""
        r1 = RTreeRect(0.0, 0.0, 10.0, 10.0)
        r2 = RTreeRect(13.0, 4.0, 20.0, 10.0)  # dx = 3, dy = 0 -> dist = 3
        r3 = RTreeRect(13.0, 14.0, 20.0, 20.0)  # dx = 3, dy = 4 -> dist = 5
        r4 = RTreeRect(5.0, 5.0, 15.0, 15.0)  # Overlapping -> dist = 0

        assert r1.distance_to_rect(r2) == 3.0
        assert r1.distance_to_rect(r3) == 5.0
        assert r1.distance_to_rect(r4) == 0.0

    def test_degenerate_box_rejection(self) -> None:
        """Verify rejection of inverted coordinates or NaN/Inf."""
        with pytest.raises(ValueError, match="Degenerate bounding box"):
            RTreeRect(300.0, 100.0, 200.0, 400.0)  # x_min > x_max

        with pytest.raises(ValueError, match="Degenerate bounding box"):
            RTreeRect(100.0, 500.0, 200.0, 400.0)  # y_min > y_max

        with pytest.raises(ValueError, match="NaN or Inf"):
            RTreeRect(float("nan"), 100.0, 200.0, 400.0)

        with pytest.raises(ValueError, match="NaN or Inf"):
            RTreeRect(100.0, float("inf"), 200.0, 400.0)

        # Aliases
        assert BoundingBox == RTreeRect
        assert RTreeBounds == RTreeRect


class TestRTreeObject:
    """Test suite for RTreeObject dataclass."""

    def test_object_attributes_and_delegation(self) -> None:
        """Verify object creation, delegation properties, and center coordinates."""
        r = RTreeRect(100.0, 150.0, 250.0, 350.0)
        obj = RTreeObject(id=42, rect=r, tag="VESSEL_42", risk_level="warning", data={"temp": 88.5})

        assert obj.id == 42
        assert obj.tag == "VESSEL_42"
        assert obj.risk_level == "warning"
        assert obj.data["temp"] == 88.5
        assert obj.area == 150.0 * 200.0
        assert obj.center == (175.0, 250.0)
        assert obj.x_min == 100.0
        assert obj.y_min == 150.0
        assert obj.x_max == 250.0
        assert obj.y_max == 350.0

    def test_object_validation(self) -> None:
        """Verify type checking and negative ID rejection."""
        r = RTreeRect(0.0, 0.0, 10.0, 10.0)
        with pytest.raises(ValueError, match="Object ID must be non-negative"):
            RTreeObject(id=-1, rect=r)

        with pytest.raises(TypeError, match="RTreeObject rect must be RTreeRect"):
            RTreeObject(id=1, rect="not_a_rect")  # type: ignore


class TestRTreeNodeStructureAndSplitting:
    """Test suite for RTreeNode structure, capacity limits, and quadratic split algorithm."""

    def test_node_entry_addition_and_mbr(self) -> None:
        """Verify adding entries computes MBR correctly."""
        node = RTreeNode(is_leaf=True, max_entries=4, min_entries=2)
        assert node.mbr is None
        assert node.count_objects() == 0

        o1 = RTreeObject(id=1, rect=RTreeRect(100.0, 100.0, 200.0, 200.0))
        node.add_entry(o1)
        assert node.mbr == RTreeRect(100.0, 100.0, 200.0, 200.0)
        assert node.count_objects() == 1

        o2 = RTreeObject(id=2, rect=RTreeRect(300.0, 150.0, 450.0, 300.0))
        node.add_entry(o2)
        assert node.mbr == RTreeRect(100.0, 100.0, 450.0, 300.0)
        assert node.count_objects() == 2

    def test_quadratic_node_split(self) -> None:
        """Verify quadratic split distributes entries to two nodes obeying min_entries."""
        node = RTreeNode(is_leaf=True, max_entries=4, min_entries=2)
        # Cluster A
        o1 = RTreeObject(id=1, rect=RTreeRect(10.0, 10.0, 30.0, 30.0))
        o2 = RTreeObject(id=2, rect=RTreeRect(20.0, 20.0, 40.0, 40.0))
        # Cluster B
        o3 = RTreeObject(id=3, rect=RTreeRect(800.0, 600.0, 830.0, 630.0))
        o4 = RTreeObject(id=4, rect=RTreeRect(820.0, 610.0, 850.0, 640.0))
        # Extra object to cause split
        o5 = RTreeObject(id=5, rect=RTreeRect(25.0, 15.0, 45.0, 35.0))

        for o in (o1, o2, o3, o4, o5):
            node.add_entry(o)

        assert len(node.entries) == 5
        n1, n2 = node.split()

        assert len(n1.entries) >= 2
        assert len(n2.entries) >= 2
        assert len(n1.entries) + len(n2.entries) == 5

        # All original objects must be preserved
        all_ids = {e.id for e in n1.entries} | {e.id for e in n2.entries}
        assert all_ids == {1, 2, 3, 4, 5}

        # Cluster A and Cluster B should be partitioned separately
        n1_ids = {e.id for e in n1.entries}
        n2_ids = {e.id for e in n2.entries}
        if 1 in n1_ids:
            assert {1, 2, 5}.issubset(n1_ids)
            assert {3, 4}.issubset(n2_ids)
        else:
            assert {3, 4}.issubset(n1_ids)
            assert {1, 2, 5}.issubset(n2_ids)

    def test_split_with_fewer_than_two_entries_fails(self) -> None:
        """Verify split raises ValueError if fewer than 2 entries exist."""
        node = RTreeNode(is_leaf=True)
        node.add_entry(RTreeObject(id=1, rect=RTreeRect(0.0, 0.0, 10.0, 10.0)))
        with pytest.raises(ValueError, match="Cannot split node with fewer than 2 entries"):
            node.split()


class TestRTreeSpatialQueries:
    """Test suite for spatial queries: window/range search, containment, and point queries."""

    def test_window_range_query(self) -> None:
        """Verify window range query returns all intersecting objects."""
        eng = RTreeCanvasEngine(max_entries=4, min_entries=2)
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0, tag="O1")
        eng.insert_object(2, 250.0, 150.0, 350.0, 250.0, tag="O2")
        eng.insert_object(3, 800.0, 500.0, 900.0, 600.0, tag="O3")

        # Window overlapping O1 and O2 only
        q_rect = RTreeRect(150.0, 120.0, 300.0, 220.0)
        matches = eng.search_window(q_rect)
        match_ids = {m.id for m in matches}

        assert len(matches) == 2
        assert match_ids == {1, 2}
        assert eng.selected_object_id in (1, 2)

    def test_containment_query(self) -> None:
        """Verify strict containment query only returns objects wholly within window."""
        eng = RTreeCanvasEngine(max_entries=4, min_entries=2)
        # O1 completely inside [50, 50, 300, 300]
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0, tag="O1")
        # O2 partially overlaps [50, 50, 300, 300]
        eng.insert_object(2, 250.0, 150.0, 350.0, 250.0, tag="O2")

        q_rect = RTreeRect(50.0, 50.0, 300.0, 300.0)
        contained = eng.search_containment(q_rect)
        assert len(contained) == 1
        assert contained[0].id == 1

    def test_point_query(self) -> None:
        """Verify point query finds objects covering the coordinate."""
        eng = RTreeCanvasEngine(max_entries=4, min_entries=2)
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0, tag="O1")
        eng.insert_object(2, 150.0, 150.0, 250.0, 250.0, tag="O2")

        # Point (175, 175) is inside both O1 and O2
        matches = eng.search_point(175.0, 175.0)
        assert len(matches) == 2
        assert {m.id for m in matches} == {1, 2}

        # Point (50, 50) is inside none
        assert len(eng.search_point(50.0, 50.0)) == 0

    def test_query_on_empty_tree(self) -> None:
        """Verify queries on empty tree return empty lists without exceptions."""
        eng = RTreeCanvasEngine()
        q_rect = RTreeRect(0.0, 0.0, 500.0, 500.0)
        assert eng.search_window(q_rect) == []
        assert eng.search_containment(q_rect) == []
        assert eng.search_point(100.0, 100.0) == []

    def test_invalid_domain_rejection(self) -> None:
        """Verify objects outside canvas viewport are rejected with DIAG_ERR_INVALID_DOMAIN."""
        eng = RTreeCanvasEngine(viewport_width=1200.0, viewport_height=750.0)
        assert eng.insert_object(1, -10.0, 50.0, 100.0, 150.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

        assert eng.insert_object(2, 100.0, 50.0, 1300.0, 150.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN


class TestSpatialCollisionHazard:
    """Test suite for proximity hazard and spatial collision detection."""

    def test_nominal_non_colliding_objects(self) -> None:
        """Verify non-overlapping objects do not trigger alarms."""
        eng = RTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0, risk_level="normal")
        eng.insert_object(2, 300.0, 300.0, 400.0, 400.0, risk_level="high_risk")

        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        assert eng.hazard_violations_count == 0

    def test_high_risk_overlapping_trips_alarm(self) -> None:
        """Verify overlapping high-risk zones trigger alarm %M603 and code 0x8416."""
        eng = RTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0, tag="ZONE_1", risk_level="high_risk")
        eng.insert_object(2, 180.0, 180.0, 280.0, 280.0, tag="ZONE_2", risk_level="normal")

        assert eng.alarm_active is True
        assert eng.diagnostic_code == DIAG_ERR_SPATIAL_COLLISION_HAZARD
        assert eng.diagnostic_code == 0x8416
        assert eng.hazard_violations_count >= 1

    def test_clear_alarm_and_injection(self) -> None:
        """Verify clear_alarm restores nominal state and inject_spatial_collision_hazard trips alarm."""
        eng = RTreeCanvasEngine()
        eng.inject_spatial_collision_hazard()
        assert eng.alarm_active is True
        assert eng.diagnostic_code == 0x8416

        eng.clear_alarm()
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        assert eng.hazard_violations_count == 0


class TestSVGAndWCAGContrast:
    """Test suite for SVG 1.1 generation and WCAG 2.1 AAA contrast verification."""

    def test_wcag_aaa_contrast_ratio(self) -> None:
        """Verify high contrast ratio exceeds 18:1."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, target_ratio=18.0) is True

    def test_svg_generation_and_valid_xml(self) -> None:
        """Verify SVG text parses as valid XML and contains required elements."""
        eng = create_canonical_rtree_canvas(sample_count=8, seed=123)
        eng.search_window(RTreeRect(200.0, 200.0, 600.0, 500.0))

        svg_text = generate_rtree_canvas_svg(eng)
        root = ET.fromstring(svg_text)

        assert root.tag.endswith("svg")
        assert "viewBox" in root.attrib
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"

        # Check key components
        assert "rtree-mbr-depth-" in svg_text
        assert "scada-object" in svg_text
        assert "query-window-reticle" in svg_text
        assert "hud-telemetry-scorecard" in svg_text


class TestHornerOcsRegisterSync:
    """Test suite for Horner OCS memory synchronization (%R2580..%R2587, %M602..%M603)."""

    def test_nominal_register_sync(self) -> None:
        """Verify register table reflects nominal state bit-for-bit."""
        eng = RTreeCanvasEngine(max_entries=4, hazard_threshold=30.0)
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)
        eng.insert_object(2, 300.0, 200.0, 400.0, 300.0)
        eng.search_window(RTreeRect(80.0, 80.0, 250.0, 250.0))

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert rt.read_word(REG_RTREE_TOTAL_OBJECTS) == 2
        assert rt.read_word(REG_RTREE_HIERARCHY_DEPTH) == eng.current_depth
        assert rt.read_word(REG_RTREE_QUERY_MATCH_COUNT) == 1
        assert rt.read_word(REG_RTREE_SELECTED_OBJECT_ID) == 1
        assert rt.read_word(REG_RTREE_HAZARD_THRESHOLD_SCALED) == 300  # 30.0 * 10
        assert rt.read_word(REG_RTREE_HAZARD_VIOLATIONS_COUNT) == 0
        assert rt.read_word(REG_RTREE_DIAGNOSTIC_CODE) == 0x0000

        assert rt.read_bit(COIL_RTREE_INDEXING_ONLINE) is True
        assert rt.read_bit(COIL_RTREE_SPATIAL_COLLISION_ALARM) is False

    def test_alarmed_register_sync(self) -> None:
        """Verify register table reflects alarm state bit-for-bit."""
        eng = RTreeCanvasEngine()
        eng.inject_spatial_collision_hazard()

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert (rt.read_word(REG_RTREE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8416
        assert rt.read_bit(COIL_RTREE_INDEXING_ONLINE) is False
        assert rt.read_bit(COIL_RTREE_SPATIAL_COLLISION_ALARM) is True

    def test_privilege_modes(self) -> None:
        """Verify register sync operates under USER and SYSTEM privileges."""
        eng = RTreeCanvasEngine()
        eng.insert_object(1, 50.0, 50.0, 100.0, 100.0)

        rt = RegisterTable()
        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert rt.read_word(REG_RTREE_TOTAL_OBJECTS) == 1

        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word(REG_RTREE_TOTAL_OBJECTS) == 1


class TestPureSTAndSecurityRejection:
    """Test suite for pure Structured Text and anti-ladder security enforcement."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify ST_PROGRAM_RTREE_CANVAS_SYNC parses into valid IEC 61131-3 AST."""
        assert verify_rtree_canvas_pure_st() is True
        res = STParser.validate_code(ST_PROGRAM_RTREE_CANVAS_SYNC)
        assert res.status == AgentStatus.SUCCESS
        ast = STParser.parse_pou(ST_PROGRAM_RTREE_CANVAS_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "RTreeCanvasSync"

    def test_ladder_contacts_rejection(self) -> None:
        """Verify rejection of ladder logic contacts ---[ ]---."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_coils_rejection(self) -> None:
        """Verify rejection of ladder logic coils ---( )---."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_rung_delimiters_rejection(self) -> None:
        """Verify rejection of ladder rung delimiters RUNG."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR RUNG 1: A := B; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_mnemonics_rejection(self) -> None:
        """Verify rejection of ladder mnemonics XIC and OTE."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR XIC b; OTE c; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


class TestILogicUnitCompliance:
    """Test suite for ILogicUnit interface compliance."""

    def test_ilogic_unit_properties_and_step(self) -> None:
        """Verify ILogicUnit interface properties and step execution."""
        eng = RTreeCanvasEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "RTreeCanvasEngine"
        assert eng.priority == 100
        assert eng.is_enabled is True

        res = eng.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 1

        eng.step()
        assert eng.cycle_count == 2

        eng.execute()
        assert eng.cycle_count == 3

    def test_reset(self) -> None:
        """Verify reset restores empty state."""
        eng = RTreeCanvasEngine()
        eng.insert_object(1, 10.0, 10.0, 20.0, 20.0)
        eng.scan_step()
        assert len(eng.objects) == 1
        assert eng.cycle_count == 1

        eng.reset()
        assert len(eng.objects) == 0
        assert eng.cycle_count == 0
        assert eng.root is None
        assert eng.current_depth == 0

    def test_continuous_scan_cycle_soak(self) -> None:
        """Verify continuous scan cycle soak (50+ cycles) with zero faults."""
        eng = RTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)
        rt = RegisterTable()
        for c in range(1, 55):
            ctx = ScanContext(cycle=c, dt_ms=10.0, register_table=rt)
            res = eng.execute(ctx)
            assert res.status == AgentStatus.SUCCESS
            assert eng.cycle_count == c
            assert rt.read_bit(COIL_RTREE_INDEXING_ONLINE) is True


class TestDeterministicVerificationRunner:
    """Test suite for run_rtree_canvas_verification."""

    def test_9_stage_verification_runner_success(self, tmp_path: Path) -> None:
        """Verify 9-stage verification runner passes and exports artifacts."""
        out_json = str(tmp_path / "w297_rtree_evidence.json")
        out_svg = str(tmp_path / "w297_rtree_sample.svg")

        res = run_rtree_canvas_verification(
            output_path=out_json,
            sample_svg_path=out_svg,
            work_package="W297",
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9

        # Verify artifacts
        assert Path(out_json).exists()
        assert Path(out_svg).exists()

        with open(out_json, "r", encoding="utf-8") as f:
            evidence = json.load(f)
        assert evidence["status"] == "success"

        with open(out_svg, "r", encoding="utf-8") as f:
            svg_text = f.read()
        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")


class TestRTreeEdgeCasesAndCoverage:
    """Test suite covering edge cases, multi-level hierarchy, and deep traversal."""

    def test_invalid_capacity_configuration(self) -> None:
        """Verify invalid capacity parameters raise ValueError."""
        with pytest.raises(ValueError, match="Invalid R-Tree capacity configuration"):
            RTreeCanvasEngine(max_entries=1)
        with pytest.raises(ValueError, match="Invalid R-Tree capacity configuration"):
            RTreeCanvasEngine(max_entries=4, min_entries=0)
        with pytest.raises(ValueError, match="Invalid R-Tree capacity configuration"):
            RTreeCanvasEngine(max_entries=4, min_entries=3)  # min_entries > max_entries // 2

    def test_multilevel_hierarchy_growth_and_traversal(self) -> None:
        """Verify inserting 16 objects creates a balanced multi-level tree with depth >= 2."""
        eng = RTreeCanvasEngine(max_entries=4, min_entries=2)
        for i in range(16):
            x = (i % 4) * 200.0 + 50.0
            y = (i // 4) * 150.0 + 50.0
            ok = eng.insert_object(i + 1, x, y, x + 80.0, y + 60.0, tag=f"NODE_{i+1}")
            assert ok is True

        assert len(eng.objects) == 16
        assert eng.current_depth >= 2
        assert eng.root is not None
        assert not eng.root.is_leaf
        assert eng.root.count_objects() == 16

        all_nodes = eng.root.get_all_nodes()
        assert len(all_nodes) > 3
        all_objs = eng.root.get_all_objects()
        assert len(all_objs) == 16
        assert {o.id for o in all_objs} == set(range(1, 17))

    def test_warning_level_collision_detection(self) -> None:
        """Verify two overlapping warning-level objects trigger collision hazard."""
        eng = RTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0, risk_level="warning")
        eng.insert_object(2, 150.0, 150.0, 250.0, 250.0, risk_level="warning")

        assert eng.alarm_active is True
        assert eng.diagnostic_code == DIAG_ERR_SPATIAL_COLLISION_HAZARD
        assert eng.hazard_violations_count == 1

    def test_metrics_telemetry_snapshot(self) -> None:
        """Verify RTreeMetrics snapshot accurately captures state."""
        eng = RTreeCanvasEngine()
        eng.insert_object(1, 100.0, 100.0, 200.0, 200.0)
        eng.search_window(RTreeRect(50.0, 50.0, 300.0, 300.0))

        m = eng.metrics
        assert isinstance(m, RTreeMetrics)
        assert m.total_objects == 1
        assert m.query_match_count == 1
        assert m.selected_object_id == 1
        assert m.indexing_online is True
        assert m.spatial_collision_alarm is False
        assert m.diagnostic_code == DIAG_OK
