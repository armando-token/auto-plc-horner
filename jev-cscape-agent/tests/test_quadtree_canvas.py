"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Quadtree SCADA Canvas (W303 & W291).

Work Package: W303 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Quadtree SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Constants, viewport dimensions, color palettes, status bits, and diagnostic codes (0x8401..0x8405, 0x8418)
2. QuadRect geometry, bounds, containment, intersection, union, point containment, and degenerate box rejection
3. QuadtreeNode hierarchical subdivision, capacity thresholds (K=4), 4-way subdivision (NW, NE, SW, SE), max depth (8)
4. Dynamic node insertion, domain boundary validation, degenerate coordinate rejection
5. Window / range queries (circular query_range, rectangular query_rect/query_box), point queries (query_point), boundary conditions, empty queries
6. Spatial cluster hazard detection (%M617, diagnostic code 0x8418) and blind spot alarms (%M589, 0x8405)
7. W3C SVG 1.1 vector generation, valid XML parsing, styling, and WCAG 2.1 AAA contrast calculation (> 18:1)
8. Horner RegisterTable synchronization with signed 16-bit masking (rt.read_word(...) & 0xFFFF) == expected
9. Pure IEC 61131-3 Structured Text validation & anti-ladder rejection with LadderForbiddenError
10. ILogicUnit interface compliance (scan_step with args/kwargs, step, execute, reset, multi-cycle soak)
11. Deterministic 9-stage verification runner execution passing all stages
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

from jev_cscape.hmi.quadtree_canvas import (
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    TOTAL_DOMAIN_AREA,
    DEFAULT_CAPACITY,
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
    COLOR_CONGESTION_AMBER,
    COLOR_ALARM_CRIMSON,
    COLOR_RETICLE_CYAN,
    COLOR_QUAD_BOUNDARY,
    COLOR_QUAD_ACTIVE,
    COLOR_QUAD_HOTSPOT,
    COLOR_QUERY_HIGHLIGHT,
    DEPTH_COLORS,
    # W291 Register mappings (%R2520..%R2527, %M588..%M589)
    REG_QUADTREE_TOTAL_NODES,
    REG_QUADTREE_SUBDIVISION_DEPTH,
    REG_QUADTREE_ACTIVE_LEAF_CELLS,
    REG_QUADTREE_QUERY_RADIUS_PX,
    REG_QUADTREE_CONGESTION_DENSITY,
    REG_QUADTREE_SELECTED_TARGET_ID,
    REG_QUADTREE_HOTSPOT_NODE_COUNT,
    REG_QUADTREE_DIAGNOSTIC_CODE,
    COIL_QUADTREE_INDEXING_ONLINE,
    COIL_QUADTREE_CONGESTION_ALARM,
    REG_W291_TOTAL_NODES,
    REG_W291_SUBDIVISION_DEPTH,
    REG_W291_ACTIVE_LEAF_CELLS,
    REG_W291_QUERY_RADIUS_PX,
    REG_W291_CONGESTION_DENSITY,
    REG_W291_SELECTED_TARGET_ID,
    REG_W291_HOTSPOT_NODE_COUNT,
    REG_W291_DIAGNOSTIC_CODE,
    COIL_W291_INDEXING_ONLINE,
    COIL_W291_CONGESTION_ALARM,
    # W303 Register mappings (%R2640..%R2647, %M616..%M617)
    REG_W303_TOTAL_NODES,
    REG_W303_SUBDIVISION_DEPTH,
    REG_W303_ACTIVE_LEAF_CELLS,
    REG_W303_QUERY_RADIUS_PX,
    REG_W303_CONGESTION_DENSITY,
    REG_W303_SELECTED_TARGET_ID,
    REG_W303_HOTSPOT_NODE_COUNT,
    REG_W303_DIAGNOSTIC_CODE,
    COIL_W303_INDEXING_ONLINE,
    COIL_W303_CONGESTION_ALARM,
    COIL_W303_CLUSTER_HAZARD,
    COIL_W303_HAZARD_ALARM,
    COIL_QUADTREE_HAZARD_ALARM,
    COIL_QUADTREE_CLUSTER_HAZARD,
    # Diagnostic Codes
    DiagnosticCode,
    QuadtreeDiagnosticCode,
    DIAG_OK,
    DIAG_ERR_INVALID_DOMAIN,
    DIAG_ERR_MAX_DEPTH_EXCEEDED,
    DIAG_ERR_CAPACITY_OVERFLOW,
    DIAG_ERR_DEGENERATE_NODE_COORDS,
    DIAG_ERR_SPATIAL_CONGESTION_ALARM,
    DIAG_ERR_BLIND_SPOT_ALARM,
    DIAG_ERR_SPATIAL_CLUSTER_HAZARD,
    DIAG_ERR_CLUSTER_HAZARD,
    QuadtreeStatusBits,
    QuadPoint,
    QuadRect,
    BoundingBox,
    QuadNode,
    QuadtreeNode,
    QuadtreeMetrics,
    QuadtreeCanvasEngine,
    QuadtreeCanvas,
    ST_PROGRAM_QUADTREE_CANVAS_SYNC,
    ST_PROGRAM_W303_QUADTREE_CANVAS_SYNC,
    QUADTREE_CANVAS_PURE_ST_POU,
    QuadtreeCanvasSync,
    verify_quadtree_canvas_pure_st,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    generate_quadtree_canvas_svg,
    create_canonical_quadtree_canvas,
    run_quadtree_canvas_verification,
)


class TestQuadtreeConstantsAndDiagnostics:
    """Test suite for W303 & W291 constants, dimensions, palettes, and diagnostic codes."""

    def test_viewport_and_domain_constants(self) -> None:
        """Verify canvas dimensions and domain area."""
        assert CANVAS_VIEWPORT_WIDTH == 1200.0
        assert CANVAS_VIEWPORT_HEIGHT == 750.0
        assert TOTAL_DOMAIN_AREA == 1200.0 * 750.0
        assert DEFAULT_CAPACITY == 4
        assert DEFAULT_MAX_DEPTH == 8

    def test_palette_and_theme_constants(self) -> None:
        """Verify high-contrast SCADA theme color definitions."""
        assert COLOR_SCADA_BG == "#0D1117"
        assert COLOR_DARK_SURFACE == "#161B22"
        assert COLOR_DECOUPLED_BADGE == "#05080C"
        assert COLOR_BORDER == "#334155"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_TEXT_MUTED == "#CBD5E1"
        assert COLOR_SAMPLE_NODE == "#38BDF8"
        assert COLOR_NOMINAL_EMERALD == "#10B981"
        assert COLOR_CONGESTION_AMBER == "#F59E0B"
        assert COLOR_ALARM_CRIMSON == "#EF4444"
        assert COLOR_RETICLE_CYAN == "#06B6D4"

    def test_depth_colors_length(self) -> None:
        """Verify depth colors provide entries for levels 0 to 8."""
        assert len(DEPTH_COLORS) >= 9
        for c in DEPTH_COLORS:
            assert c.startswith("#")

    def test_w291_register_mappings_and_aliases(self) -> None:
        """Verify primary Horner OCS register addresses for W291 (%R2520..%R2527, %M588..%M589)."""
        assert REG_QUADTREE_TOTAL_NODES == "%R2520"
        assert REG_QUADTREE_SUBDIVISION_DEPTH == "%R2521"
        assert REG_QUADTREE_ACTIVE_LEAF_CELLS == "%R2522"
        assert REG_QUADTREE_QUERY_RADIUS_PX == "%R2523"
        assert REG_QUADTREE_CONGESTION_DENSITY == "%R2524"
        assert REG_QUADTREE_SELECTED_TARGET_ID == "%R2525"
        assert REG_QUADTREE_HOTSPOT_NODE_COUNT == "%R2526"
        assert REG_QUADTREE_DIAGNOSTIC_CODE == "%R2527"
        assert COIL_QUADTREE_INDEXING_ONLINE == "%M588"
        assert COIL_QUADTREE_CONGESTION_ALARM == "%M589"

        assert REG_W291_TOTAL_NODES == "%R2520"
        assert REG_W291_SUBDIVISION_DEPTH == "%R2521"
        assert REG_W291_ACTIVE_LEAF_CELLS == "%R2522"
        assert REG_W291_QUERY_RADIUS_PX == "%R2523"
        assert REG_W291_CONGESTION_DENSITY == "%R2524"
        assert REG_W291_SELECTED_TARGET_ID == "%R2525"
        assert REG_W291_HOTSPOT_NODE_COUNT == "%R2526"
        assert REG_W291_DIAGNOSTIC_CODE == "%R2527"
        assert COIL_W291_INDEXING_ONLINE == "%M588"
        assert COIL_W291_CONGESTION_ALARM == "%M589"

    def test_w303_register_mappings_and_coils(self) -> None:
        """Verify Horner OCS register addresses for W303 (%R2640..%R2647, %M616..%M617)."""
        assert REG_W303_TOTAL_NODES == "%R2640"
        assert REG_W303_SUBDIVISION_DEPTH == "%R2641"
        assert REG_W303_ACTIVE_LEAF_CELLS == "%R2642"
        assert REG_W303_QUERY_RADIUS_PX == "%R2643"
        assert REG_W303_CONGESTION_DENSITY == "%R2644"
        assert REG_W303_SELECTED_TARGET_ID == "%R2645"
        assert REG_W303_HOTSPOT_NODE_COUNT == "%R2646"
        assert REG_W303_DIAGNOSTIC_CODE == "%R2647"

        assert COIL_W303_INDEXING_ONLINE == "%M616"
        assert COIL_W303_CONGESTION_ALARM == "%M617"
        assert COIL_W303_CLUSTER_HAZARD == "%M617"
        assert COIL_W303_HAZARD_ALARM == "%M617"
        assert COIL_QUADTREE_HAZARD_ALARM == "%M617"
        assert COIL_QUADTREE_CLUSTER_HAZARD == "%M617"

    def test_diagnostic_code_values_and_equality(self) -> None:
        """Verify 16-bit diagnostic codes including 0x8418 cluster hazard."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_INVALID_DOMAIN == 0x8401
        assert DIAG_ERR_MAX_DEPTH_EXCEEDED == 0x8402
        assert DIAG_ERR_CAPACITY_OVERFLOW == 0x8403
        assert DIAG_ERR_DEGENERATE_NODE_COORDS == 0x8404
        assert DIAG_ERR_SPATIAL_CONGESTION_ALARM == 0x8405
        assert DIAG_ERR_BLIND_SPOT_ALARM == 0x8405
        assert DIAG_ERR_SPATIAL_CLUSTER_HAZARD == 0x8418
        assert DIAG_ERR_CLUSTER_HAZARD == 0x8418

        assert repr(DIAG_ERR_SPATIAL_CLUSTER_HAZARD) == "DiagnosticCode(0x8418)"
        assert str(DIAG_ERR_SPATIAL_CLUSTER_HAZARD) == "0x8418"
        # Signed 16-bit equivalence check
        assert DIAG_ERR_SPATIAL_CLUSTER_HAZARD == (0x8418 - 0x10000)

    def test_status_bits(self) -> None:
        """Verify status flag bitmask including cluster hazard alarm."""
        b = (
            QuadtreeStatusBits.INDEXING_ONLINE
            | QuadtreeStatusBits.SVG_RENDER_VALID
            | QuadtreeStatusBits.CLUSTER_HAZARD_ALARM
        )
        assert QuadtreeStatusBits.INDEXING_ONLINE in b
        assert QuadtreeStatusBits.SVG_RENDER_VALID in b
        assert QuadtreeStatusBits.CLUSTER_HAZARD_ALARM in b
        assert QuadtreeStatusBits.CONGESTION_ALARM not in b


class TestQuadRectGeometry:
    """Test suite for QuadRect spatial primitive, containment, and intersection."""

    def test_dimensions_and_properties(self) -> None:
        """Verify rectangle dimension properties (width, height, area, centers)."""
        rect = QuadRect(100.0, 50.0, 300.0, 250.0)
        assert rect.width == 200.0
        assert rect.height == 200.0
        assert rect.area == 40000.0
        assert rect.center_x == 200.0
        assert rect.center_y == 150.0

    def test_contains_coord_and_point(self) -> None:
        """Verify coordinate and point containment including boundaries."""
        rect = QuadRect(100.0, 50.0, 300.0, 250.0)
        assert rect.contains_coord(150.0, 150.0) is True
        assert rect.contains_coord(50.0, 150.0) is False
        assert rect.contains_coord(100.0, 50.0) is True   # Top-left boundary inclusive
        assert rect.contains_coord(300.0, 250.0) is True  # Bottom-right boundary inclusive

        p1 = QuadPoint(x=200.0, y=100.0, id=1)
        p2 = QuadPoint(x=500.0, y=100.0, id=2)
        assert rect.contains_point(p1) is True
        assert rect.contains_point(p2) is False

    def test_contains_point_with_tuples_and_objects(self) -> None:
        """Verify contains_point handles tuple coordinates, (x, y) arguments, and point objects."""
        rect = QuadRect(10.0, 20.0, 100.0, 200.0)
        assert rect.contains_point((50.0, 60.0)) is True
        assert rect.contains_point([50.0, 60.0]) is True
        assert rect.contains_point((5.0, 60.0)) is False
        assert rect.contains_point(50.0, 60.0) is True
        assert rect.contains_point(5.0, 60.0) is False

    def test_intersects_rect(self) -> None:
        """Verify rectangle intersection logic."""
        r1 = QuadRect(0.0, 0.0, 100.0, 100.0)
        r2 = QuadRect(50.0, 50.0, 150.0, 150.0)
        r3 = QuadRect(120.0, 120.0, 200.0, 200.0)
        r4 = QuadRect(100.0, 0.0, 200.0, 100.0)  # Touching boundary edge
        assert r1.intersects_rect(r2) is True
        assert r2.intersects_rect(r1) is True
        assert r1.intersects_rect(r3) is False
        assert r1.intersects_rect(r4) is True

    def test_contains_rect(self) -> None:
        """Verify rectangle full enclosure logic."""
        parent = QuadRect(0.0, 0.0, 500.0, 500.0)
        inner = QuadRect(100.0, 100.0, 200.0, 200.0)
        partial = QuadRect(400.0, 400.0, 600.0, 600.0)
        outside = QuadRect(600.0, 600.0, 700.0, 700.0)

        assert parent.contains_rect(inner) is True
        assert parent.contains_rect(partial) is False
        assert parent.contains_rect(outside) is False

    def test_intersection_and_union(self) -> None:
        """Verify analytical rectangle intersection and bounding box union."""
        r1 = QuadRect(10.0, 10.0, 50.0, 50.0)
        r2 = QuadRect(30.0, 20.0, 80.0, 70.0)
        r_disjoint = QuadRect(100.0, 100.0, 120.0, 120.0)

        ix = r1.intersection(r2)
        assert ix is not None
        assert ix.x_min == 30.0
        assert ix.y_min == 20.0
        assert ix.x_max == 50.0
        assert ix.y_max == 50.0

        assert r1.intersection(r_disjoint) is None

        u = r1.union(r2)
        assert u.x_min == 10.0
        assert u.y_min == 10.0
        assert u.x_max == 80.0
        assert u.y_max == 70.0

    def test_intersects_circle(self) -> None:
        """Verify circle intersection with axis-aligned rectangle."""
        rect = QuadRect(100.0, 100.0, 200.0, 200.0)
        # Center inside
        assert rect.intersects_circle(150.0, 150.0, 10.0) is True
        # Center outside, circle overlaps corner
        assert rect.intersects_circle(210.0, 210.0, 20.0) is True
        # Center outside, too far
        assert rect.intersects_circle(300.0, 300.0, 50.0) is False
        # Negative radius
        assert rect.intersects_circle(150.0, 150.0, -5.0) is False

    def test_degenerate_rect_rejection(self) -> None:
        """Verify degenerate rectangle instantiation raises ValueError."""
        with pytest.raises(ValueError):
            QuadRect(100.0, 50.0, 50.0, 250.0)  # x_min > x_max

        with pytest.raises(ValueError):
            QuadRect(50.0, 300.0, 100.0, 100.0)  # y_min > y_max


class TestQuadtreeSubdivisionAndInsertion:
    """Test suite for hierarchical subdivision, capacity thresholds, and depth limits."""

    def test_capacity_and_delayed_subdivision(self) -> None:
        """Verify that leaf does not subdivide when points <= capacity (K=4)."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8)
        assert eng.current_depth == 0
        assert eng.total_leaves == 1

        for i in range(4):
            res = eng.insert_point(100.0 * (i + 1), 100.0 * (i + 1), node_id=i + 1)
            assert res is True

        assert len(eng.points) == 4
        assert eng.current_depth == 0
        assert eng.total_leaves == 1
        assert eng.root.is_divided is False
        assert eng.hot_spot_node_count == 4

    def test_subdivision_on_capacity_exceeded(self) -> None:
        """Verify subdivision into 4 child quadrants when 5th point is added."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8)
        for i in range(4):
            eng.insert_point(100.0 * (i + 1), 100.0 * (i + 1), node_id=i + 1)

        ok5 = eng.insert_point(250.0, 250.0, node_id=5)
        assert ok5 is True
        assert eng.root.is_divided is True
        assert eng.current_depth >= 1
        assert eng.total_leaves >= 4
        assert eng.root.nw is not None
        assert eng.root.ne is not None
        assert eng.root.sw is not None
        assert eng.root.se is not None

    def test_subdivision_quadrant_routing(self) -> None:
        """Verify deterministic routing of points into NW, NE, SW, and SE child quadrants."""
        eng = QuadtreeCanvasEngine(viewport_width=1000.0, viewport_height=1000.0, capacity=1, max_depth=2)
        # Midpoint is (500, 500)
        eng.insert_point(200.0, 200.0, node_id=1)  # NW
        eng.insert_point(800.0, 200.0, node_id=2)  # NE -> triggers root subdivision
        eng.insert_point(200.0, 800.0, node_id=3)  # SW
        eng.insert_point(800.0, 800.0, node_id=4)  # SE

        assert eng.root.nw is not None and len(eng.root.nw.points) >= 1
        assert eng.root.ne is not None and len(eng.root.ne.points) >= 1
        assert eng.root.sw is not None and len(eng.root.sw.points) >= 1
        assert eng.root.se is not None and len(eng.root.se.points) >= 1

    def test_recursive_subdivision_depth(self) -> None:
        """Verify multi-level recursive subdivision up to depth >= 2."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8)
        # Place tightly clustered points in NW quadrant
        for i in range(12):
            eng.insert_point(50.0 + i * 5.0, 50.0 + i * 5.0, node_id=i + 1)

        assert len(eng.points) == 12
        assert eng.current_depth >= 2
        assert eng.total_leaves > 4

    def test_max_depth_enforcement(self) -> None:
        """Verify quadtree respects max_depth parameter and does not subdivide deeper."""
        eng = QuadtreeCanvasEngine(capacity=2, max_depth=3)
        for i in range(20):
            eng.insert_point(50.0, 50.0, node_id=i + 1)

        assert eng.current_depth <= 3
        assert eng.current_depth == 3

    def test_max_depth_capacity_overflow(self) -> None:
        """Verify capacity overflow behavior when leaf reaches max depth."""
        eng = QuadtreeCanvasEngine(capacity=2, max_depth=3)
        # Insert identical coordinates to force subdivision to max depth
        for i in range(8):
            eng.insert_point(100.0, 100.0, node_id=i + 1)

        assert eng.current_depth == 3
        assert eng.diagnostic_code == DIAG_ERR_CAPACITY_OVERFLOW

    def test_invalid_domain_rejection(self) -> None:
        """Verify that coordinates outside domain [0, 1200] x [0, 750] are rejected."""
        eng = QuadtreeCanvasEngine()
        assert eng.insert_point(-10.0, 100.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

        assert eng.insert_point(1300.0, 100.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

        assert eng.insert_point(100.0, -5.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

        assert eng.insert_point(100.0, 800.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

    def test_degenerate_coords_rejection(self) -> None:
        """Verify NaN and Inf coordinate rejection asserting 0x8404."""
        eng = QuadtreeCanvasEngine()
        assert eng.insert_point(float("nan"), 100.0) is False
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_NODE_COORDS

        assert eng.insert_point(100.0, float("inf")) is False
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_NODE_COORDS

        assert eng.insert_point(float("-inf"), 100.0) is False
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_NODE_COORDS

    def test_batch_insert_points(self) -> None:
        """Verify batch insertion helper counts successful points."""
        eng = QuadtreeCanvasEngine()
        pts = [(100.0, 100.0), (200.0, 200.0), (1500.0, 100.0), (300.0, 300.0)]
        count = eng.insert_points(pts)
        assert count == 3
        assert len(eng.points) == 3


class TestRangeAndPointQueryFiltering:
    """Test suite for spatial range queries (circular/rectangular), point queries, and edge cases."""

    def test_circular_range_query_matches_ground_truth(self) -> None:
        """Verify circular range query matches analytical ground truth."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8)
        points_data = [
            (500.0, 300.0),
            (510.0, 310.0),
            (520.0, 305.0),
            (530.0, 320.0),
            (800.0, 600.0),
            (100.0, 100.0),
        ]
        for idx, (x, y) in enumerate(points_data, start=1):
            eng.insert_point(x, y, node_id=idx)

        res = eng.query_range(center_x=515.0, center_y=310.0, radius=30.0)
        expected_ids = {1, 2, 3, 4}
        assert {p.id for p in res} == expected_ids

    def test_circular_range_query_empty(self) -> None:
        """Verify circular range query returning empty when no points in radius."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)
        res = eng.query_range(center_x=900.0, center_y=600.0, radius=50.0)
        assert len(res) == 0

    def test_circular_range_query_full_domain(self) -> None:
        """Verify circular range query with large radius covering all points."""
        eng = QuadtreeCanvasEngine()
        for i in range(10):
            eng.insert_point(50.0 * (i + 1), 50.0 * (i + 1), node_id=i + 1)
        res = eng.query_range(center_x=600.0, center_y=375.0, radius=1000.0)
        assert len(res) == 10

    def test_circular_range_query_boundary_points(self) -> None:
        """Verify circular range query inclusive boundary behavior."""
        eng = QuadtreeCanvasEngine()
        # Point exactly at distance 50 from (100, 100)
        eng.insert_point(150.0, 100.0, node_id=1)
        res = eng.query_range(center_x=100.0, center_y=100.0, radius=50.0)
        assert len(res) == 1
        assert res[0].id == 1

    def test_circular_range_query_negative_radius(self) -> None:
        """Verify circular range query with negative radius returns empty list."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)
        res = eng.query_range(center_x=100.0, center_y=100.0, radius=-10.0)
        assert len(res) == 0

    def test_rectangular_range_query(self) -> None:
        """Verify rectangular range query matches ground truth."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8)
        for i in range(20):
            eng.insert_point(i * 50.0 + 20.0, i * 30.0 + 20.0, node_id=i + 1)

        rect = QuadRect(100.0, 50.0, 400.0, 300.0)
        res = eng.query_rect(rect)
        for p in res:
            assert rect.contains_point(p) is True

        expected = [p for p in eng.points if rect.contains_point(p)]
        assert len(res) == len(expected)
        assert sorted(p.id for p in res) == sorted(p.id for p in expected)

    def test_rectangular_range_query_empty_window(self) -> None:
        """Verify rectangular range query returns empty list when window does not intersect points."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)
        empty_rect = QuadRect(800.0, 600.0, 900.0, 700.0)
        res = eng.query_rect(empty_rect)
        assert len(res) == 0

    def test_rectangular_box_queries_aliases(self) -> None:
        """Verify query_box and query_rectangular_window aliases."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(250.0, 250.0, node_id=42)
        res1 = eng.query_box(200.0, 200.0, 300.0, 300.0)
        res2 = eng.query_rectangular_window(200.0, 200.0, 300.0, 300.0)
        assert len(res1) == 1 and res1[0].id == 42
        assert len(res2) == 1 and res2[0].id == 42

    def test_query_point_exact_match(self) -> None:
        """Verify query_point accurately locates points at exact coordinates."""
        eng = QuadtreeCanvasEngine(capacity=2, max_depth=5)
        eng.insert_point(150.0, 220.0, node_id=10)
        eng.insert_point(300.0, 400.0, node_id=20)
        eng.insert_point(150.0, 220.0, node_id=30)  # Co-located point

        pts = eng.query_point(150.0, 220.0)
        assert len(pts) == 2
        assert {p.id for p in pts} == {10, 30}

    def test_query_point_with_tolerance(self) -> None:
        """Verify query_point with radius tolerance catches nearby points."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)
        eng.insert_point(103.0, 104.0, node_id=2)
        eng.insert_point(120.0, 120.0, node_id=3)

        # Distance between (100, 100) and (103, 104) is 5.0
        pts = eng.query_point(100.0, 100.0, tolerance=5.1)
        assert len(pts) == 2
        assert {p.id for p in pts} == {1, 2}

    def test_query_point_missing_returns_empty(self) -> None:
        """Verify query_point returns empty list when coordinate is unoccupied."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)
        pts = eng.query_point(500.0, 500.0, tolerance=1.0)
        assert len(pts) == 0

    def test_query_point_with_quadpoint_and_tuple(self) -> None:
        """Verify query_point accepts QuadPoint objects or coordinate tuples."""
        eng = QuadtreeCanvasEngine()
        target = QuadPoint(x=350.0, y=250.0, id=7)
        eng.insert_point(350.0, 250.0, node_id=7)

        res_pt = eng.query_point(target)
        assert len(res_pt) == 1 and res_pt[0].id == 7

        res_tup = eng.query_point((350.0, 250.0))
        assert len(res_tup) == 1 and res_tup[0].id == 7


class TestSpatialClusterHazardAndCongestion:
    """Test suite for hotspot detection, density index, and spatial cluster hazard (%M617 / 0x8418)."""

    def test_hotspot_and_congestion_density(self) -> None:
        """Verify detection of congested leaf and density index calculation."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8)
        for i in range(6):
            eng.insert_point(100.0 + i * 10.0, 100.0 + i * 10.0, node_id=i + 1)

        assert eng.hot_spot_node_count >= 1
        assert eng.congestion_density_index > 0.0
        assert eng.hot_spot_quadrant is not None
        assert eng.calculate_congestion_index() > 0.0

    def test_blind_spot_detection(self) -> None:
        """Verify detection of unmonitored cardinal quadrants."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8)
        eng.insert_point(200.0, 150.0, node_id=1)
        eng.insert_point(800.0, 150.0, node_id=2)

        blind_spots = eng.detect_blind_spots()
        assert "SW" in blind_spots
        assert "SE" in blind_spots
        assert "NW" not in blind_spots
        assert "NE" not in blind_spots

    def test_blind_spot_alarm_injection_and_clearing(self) -> None:
        """Verify %M589 and diagnostic code 0x8405 assertion on blind spot alarm."""
        eng = QuadtreeCanvasEngine()
        eng.inject_blind_spot_alarm()
        assert eng.alarm_active is True
        assert eng.diagnostic_code == DIAG_ERR_SPATIAL_CONGESTION_ALARM

        rt = RegisterTable()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_QUADTREE_CONGESTION_ALARM) is True
        assert rt.read_bit(COIL_QUADTREE_INDEXING_ONLINE) is False
        assert (rt.read_word(REG_QUADTREE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8405

        eng.clear_anomalies()
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_QUADTREE_CONGESTION_ALARM) is False
        assert rt.read_bit(COIL_QUADTREE_INDEXING_ONLINE) is True
        assert (rt.read_word(REG_QUADTREE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_spatial_cluster_hazard_injection(self) -> None:
        """Verify spatial cluster hazard injection asserts %M617 and diagnostic code 0x8418."""
        eng = QuadtreeCanvasEngine()
        eng.inject_cluster_hazard_alarm()
        assert eng.alarm_active is True
        assert eng.diagnostic_code == DIAG_ERR_SPATIAL_CLUSTER_HAZARD
        assert eng.cluster_hazard_active is True

    def test_spatial_cluster_hazard_detection(self) -> None:
        """Verify detect_cluster_hazard detects tightly clustered nodes and triggers alarm."""
        eng = QuadtreeCanvasEngine(capacity=2, max_depth=4)
        for i in range(5):
            eng.insert_point(150.0, 150.0, node_id=i + 1)

        detected = eng.detect_cluster_hazard(threshold_count=4)
        assert detected is True
        assert eng.cluster_hazard_active is True
        assert eng.diagnostic_code == DIAG_ERR_SPATIAL_CLUSTER_HAZARD

    def test_cluster_hazard_register_sync(self) -> None:
        """Verify spatial cluster hazard alarm asserts %M617 coil and code 0x8418 in RegisterTable."""
        eng = QuadtreeCanvasEngine()
        eng.inject_cluster_hazard_alarm()

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        # Check W303 coils & register
        assert rt.read_bit(COIL_W303_CLUSTER_HAZARD) is True
        assert rt.read_bit(COIL_W303_HAZARD_ALARM) is True
        assert rt.read_bit(COIL_W303_INDEXING_ONLINE) is False
        assert (rt.read_word(REG_W303_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8418

    def test_cluster_hazard_clearing(self) -> None:
        """Verify clearing anomalies clears cluster hazard and restores online bit %M616."""
        eng = QuadtreeCanvasEngine()
        eng.inject_cluster_hazard_alarm()
        eng.clear_anomalies()

        assert eng.cluster_hazard_active is False
        assert eng.diagnostic_code == DIAG_OK

        rt = RegisterTable()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_W303_CLUSTER_HAZARD) is False
        assert rt.read_bit(COIL_W303_INDEXING_ONLINE) is True
        assert (rt.read_word(REG_W303_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000


class TestSvgGenerationAndWcagContrast:
    """Test suite for SVG 1.1 vector graphics and WCAG 2.1 AAA contrast."""

    def test_wcag_aaa_contrast_ratio(self) -> None:
        """Verify text-to-badge contrast exceeds WCAG 2.1 AAA threshold (> 18:1)."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True

    def test_contrast_ratio_edge_cases(self) -> None:
        """Verify calculate_contrast_ratio edge cases (identical colors = 1.0, black & white = 21.0)."""
        assert calculate_contrast_ratio("#FFFFFF", "#FFFFFF") == pytest.approx(1.0, abs=0.01)
        assert calculate_contrast_ratio("#000000", "#000000") == pytest.approx(1.0, abs=0.01)
        assert calculate_contrast_ratio("#FFFFFF", "#000000") == pytest.approx(21.0, abs=0.1)

    def test_svg_xml_validity_and_root_attributes(self) -> None:
        """Verify SVG 1.1 output is valid XML and contains required viewport attributes."""
        eng = create_canonical_quadtree_canvas(sample_count=20, seed=42)
        svg_text = generate_quadtree_canvas_svg(eng)

        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")
        assert root.attrib["viewBox"] == "0 0 1200 750"
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"

    def test_svg_visual_elements_presence(self) -> None:
        """Verify SVG contains essential SCADA HUD and reticle graphic components."""
        eng = create_canonical_quadtree_canvas(sample_count=20, seed=42)
        svg_text = generate_quadtree_canvas_svg(eng)

        assert "sensor-node" in svg_text
        assert "range-reticle" in svg_text
        assert "hud-telemetry-scorecard" in svg_text
        assert "DYNAMIC SPATIAL QUADTREE SCADA CANVAS" in svg_text

    def test_svg_hotspot_highlight_presence(self) -> None:
        """Verify SVG highlights hot-spot cell when points exist in tree."""
        eng = QuadtreeCanvasEngine(capacity=2, max_depth=4)
        for i in range(5):
            eng.insert_point(200.0, 200.0, node_id=i + 1)
        svg_text = generate_quadtree_canvas_svg(eng)
        assert "HOT-SPOT" in svg_text

    def test_svg_cluster_hazard_styling(self) -> None:
        """Verify SVG reflects alarm state styling when cluster hazard is injected."""
        eng = create_canonical_quadtree_canvas(sample_count=10, seed=42)
        eng.inject_cluster_hazard_alarm()
        svg_text = generate_quadtree_canvas_svg(eng)
        assert COLOR_ALARM_CRIMSON in svg_text
        assert "ALARM" in svg_text


class TestHornerOcsRegisterSync:
    """Test suite for Horner OCS memory synchronization with signed 16-bit masking."""

    def test_bit_exact_register_sync_w291(self) -> None:
        """Verify registers %R2520..%R2527 and coils %M588..%M589 for W291."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8, query_radius=120.0)
        eng.insert_point(200.0, 150.0, node_id=101)
        eng.insert_point(400.0, 250.0, node_id=102)

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert rt.read_word(REG_QUADTREE_TOTAL_NODES) == 2
        assert rt.read_word(REG_QUADTREE_SUBDIVISION_DEPTH) == eng.current_depth
        assert rt.read_word(REG_QUADTREE_ACTIVE_LEAF_CELLS) == eng.total_leaves
        assert rt.read_word(REG_QUADTREE_QUERY_RADIUS_PX) == 1200
        assert rt.read_word(REG_QUADTREE_SELECTED_TARGET_ID) == 101
        assert rt.read_word(REG_QUADTREE_HOTSPOT_NODE_COUNT) == 2
        assert (rt.read_word(REG_QUADTREE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert rt.read_bit(COIL_QUADTREE_INDEXING_ONLINE) is True
        assert rt.read_bit(COIL_QUADTREE_CONGESTION_ALARM) is False

    def test_bit_exact_register_sync_w303(self) -> None:
        """Verify registers %R2640..%R2647 and coils %M616..%M617 for W303."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8, query_radius=150.0)
        eng.insert_point(150.0, 100.0, node_id=201)
        eng.insert_point(350.0, 200.0, node_id=202)

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert rt.read_word(REG_W303_TOTAL_NODES) == 2
        assert rt.read_word(REG_W303_SUBDIVISION_DEPTH) == eng.current_depth
        assert rt.read_word(REG_W303_ACTIVE_LEAF_CELLS) == eng.total_leaves
        assert rt.read_word(REG_W303_QUERY_RADIUS_PX) == 1500
        assert rt.read_word(REG_W303_SELECTED_TARGET_ID) == 201
        assert rt.read_word(REG_W303_HOTSPOT_NODE_COUNT) == 2
        assert (rt.read_word(REG_W303_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert rt.read_bit(COIL_W303_INDEXING_ONLINE) is True
        assert rt.read_bit(COIL_W303_CLUSTER_HAZARD) is False

    def test_signed_16bit_masking_for_diagnostics(self) -> None:
        """Verify signed 16-bit masking (rt.read_word(...) & 0xFFFF) == expected."""
        eng = QuadtreeCanvasEngine()
        rt = RegisterTable()

        # 1. Cluster hazard: 0x8418
        eng.inject_cluster_hazard_alarm()
        eng.sync_to_registers(rt)
        raw_word = rt.read_word(REG_W303_DIAGNOSTIC_CODE)
        assert (raw_word & 0xFFFF) == 0x8418

        # 2. Congestion/blind spot alarm: 0x8405
        eng.inject_blind_spot_alarm()
        eng.sync_to_registers(rt)
        raw_word = rt.read_word(REG_W303_DIAGNOSTIC_CODE)
        assert (raw_word & 0xFFFF) == 0x8405

        # 3. Nominal OK: 0x0000
        eng.clear_anomalies()
        eng.sync_to_registers(rt)
        raw_word = rt.read_word(REG_W303_DIAGNOSTIC_CODE)
        assert (raw_word & 0xFFFF) == 0x0000

    def test_scaled_register_fields(self) -> None:
        """Verify scaled fields (query radius x10, density index x10)."""
        eng = QuadtreeCanvasEngine(query_radius=85.5)
        for i in range(6):
            eng.insert_point(200.0, 200.0, node_id=i + 1)

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert rt.read_word(REG_W303_QUERY_RADIUS_PX) == 855
        expected_density = int(round(eng.congestion_density_index * 10.0)) & 0xFFFF
        assert (rt.read_word(REG_W303_CONGESTION_DENSITY) & 0xFFFF) == expected_density

    def test_privilege_modes_access(self) -> None:
        """Verify sync_to_registers functions under both USER and SYSTEM privilege modes."""
        eng = QuadtreeCanvasEngine(capacity=4, max_depth=8)
        eng.insert_point(200.0, 150.0, node_id=101)

        rt = RegisterTable()
        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert rt.read_word(REG_W303_TOTAL_NODES) == 1

        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word(REG_W303_TOTAL_NODES) == 1

    def test_selected_target_id_register_tracking(self) -> None:
        """Verify selected target node ID updates properly and writes to register."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=55)
        eng.insert_point(200.0, 200.0, node_id=99)

        eng.selected_node_id = 99
        rt = RegisterTable()
        eng.sync_to_registers(rt)
        assert rt.read_word(REG_W303_SELECTED_TARGET_ID) == 99


class TestPureSTAndSecurityRejection:
    """Test suite for pure Structured Text programs and anti-ladder security guards."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify ST_PROGRAM_QUADTREE_CANVAS_SYNC compiles under pure ST parser."""
        assert verify_quadtree_canvas_pure_st() is True
        res = STParser.validate_code(ST_PROGRAM_QUADTREE_CANVAS_SYNC)
        assert res.status == AgentStatus.SUCCESS
        ast = STParser.parse_pou(ST_PROGRAM_QUADTREE_CANVAS_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "QuadtreeCanvasSync"

    def test_w303_pure_st_pou_syntax_validation(self) -> None:
        """Verify ST_PROGRAM_W303_QUADTREE_CANVAS_SYNC compiles under pure ST parser."""
        assert verify_quadtree_canvas_pure_st(ST_PROGRAM_W303_QUADTREE_CANVAS_SYNC) is True
        res = STParser.validate_code(ST_PROGRAM_W303_QUADTREE_CANVAS_SYNC)
        assert res.status == AgentStatus.SUCCESS
        ast = STParser.parse_pou(ST_PROGRAM_W303_QUADTREE_CANVAS_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "QuadtreeCanvasSync"

    def test_verify_quadtree_canvas_pure_st_helper(self) -> None:
        """Verify verify_quadtree_canvas_pure_st helper returns False on invalid ST."""
        assert verify_quadtree_canvas_pure_st("INVALID NOT POU CODE") is False

    def test_ladder_contacts_rejection(self) -> None:
        """Verify strict rejection of ladder logic contacts ---[ ]--- and ---[/]---."""
        bad_st_1 = "PROGRAM P VAR b : BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)

        bad_st_2 = "PROGRAM P VAR b : BOOL; END_VAR ---[/]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)

    def test_ladder_coils_rejection(self) -> None:
        """Verify strict rejection of ladder logic coils ---( )--- and ---(/)---."""
        bad_st_1 = "PROGRAM P VAR b : BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)

        bad_st_2 = "PROGRAM P VAR b : BOOL; END_VAR ---(/)--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)

    def test_ladder_rung_delimiters_rejection(self) -> None:
        """Verify strict rejection of ladder rung delimiters RUNG and NETWORK."""
        bad_st_1 = "PROGRAM P VAR b : BOOL; END_VAR RUNG 1: A := B; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)

        bad_st_2 = "PROGRAM P VAR b : BOOL; END_VAR NETWORK 1: A := B; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)

    def test_ladder_mnemonics_rejection(self) -> None:
        """Verify strict rejection of ladder mnemonics XIC, XIO, OTE, OTL, and OTU."""
        for mnemonic in ["XIC b;", "XIO b;", "OTE c;", "OTL c;", "OTU c;"]:
            bad_st = f"PROGRAM P VAR b : BOOL; END_VAR {mnemonic} END_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_st)


class TestILogicUnitCompliance:
    """Test suite for ILogicUnit scan cycle execution, methods, and reset."""

    def test_ilogic_unit_properties_and_step(self) -> None:
        """Verify ILogicUnit interface compliance and properties."""
        eng = QuadtreeCanvasEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "QuadtreeCanvasEngine"
        assert eng.priority == 100
        assert eng.is_enabled is True

        res = eng.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 1

    def test_scan_step_with_args_and_kwargs(self) -> None:
        """Verify scan_step accepts ScanContext, positional args, and keyword args."""
        eng = QuadtreeCanvasEngine()
        rt = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=20.0, register_table=rt)

        res = eng.scan_step(ctx, "extra_pos_arg", flag=True)
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 1
        assert rt.read_bit(COIL_W303_INDEXING_ONLINE) is True

    def test_step_and_execute_with_args_kwargs(self) -> None:
        """Verify step and execute methods accept args and kwargs."""
        eng = QuadtreeCanvasEngine()
        eng.step("step_arg", extra_kw="val")
        assert eng.cycle_count == 1

        rt = RegisterTable()
        ctx = ScanContext(cycle=2, dt_ms=20.0, register_table=rt)
        res = eng.execute(ctx, "exec_arg", mode=1)
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 2

    def test_reset_restores_clean_state(self) -> None:
        """Verify reset clears points, cycles, diagnostics, and restores root leaf."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)
        eng.inject_cluster_hazard_alarm()
        eng.scan_step()

        assert len(eng.points) == 1
        assert eng.cycle_count == 1
        assert eng.alarm_active is True

        eng.reset()
        assert len(eng.points) == 0
        assert eng.cycle_count == 0
        assert eng.current_depth == 0
        assert eng.total_leaves == 1
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK

    def test_simulation_scan_cycle_soak(self) -> None:
        """Verify scan cycle soak stability over 50 consecutive cycles."""
        eng = QuadtreeCanvasEngine()
        eng.insert_point(150.0, 150.0, node_id=1)
        rt = RegisterTable()
        for c in range(1, 51):
            ctx = ScanContext(cycle=c, dt_ms=10.0, register_table=rt)
            eng.execute(ctx)
            assert eng.cycle_count == c
            assert rt.read_bit(COIL_QUADTREE_INDEXING_ONLINE) is True
            assert rt.read_bit(COIL_W303_INDEXING_ONLINE) is True


class TestDeterministicVerificationRunner:
    """Test suite for run_quadtree_canvas_verification function."""

    def test_9_stage_verification_runner_default(self, tmp_path: Path) -> None:
        """Verify that all 9 stages pass deterministically with default configuration."""
        out_json = str(tmp_path / "w291_quadtree_evidence.json")
        out_svg = str(tmp_path / "w291_quadtree_sample.svg")

        res = run_quadtree_canvas_verification(
            output_path=out_json,
            sample_svg_path=out_svg,
            work_package="W291",
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9

        assert Path(out_json).exists()
        assert Path(out_svg).exists()

    def test_9_stage_verification_runner_w303(self, tmp_path: Path) -> None:
        """Verify that all 9 stages pass deterministically when invoked for W303."""
        out_json = str(tmp_path / "w303_quadtree_evidence.json")
        out_svg = str(tmp_path / "w303_quadtree_sample.svg")

        res = run_quadtree_canvas_verification(
            output_path=out_json,
            sample_svg_path=out_svg,
            work_package="W303",
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["work_package"] == "W303"

    def test_verification_runner_artifact_generation(self, tmp_path: Path) -> None:
        """Verify generated JSON evidence structure and SVG XML validity."""
        out_json = str(tmp_path / "evidence.json")
        out_svg = str(tmp_path / "canvas.svg")

        run_quadtree_canvas_verification(
            output_path=out_json,
            sample_svg_path=out_svg,
        )

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert "data" in data
        assert len(data["data"]["stages"]) == 9

        with open(out_svg, "r", encoding="utf-8") as f:
            svg_content = f.read()
        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
