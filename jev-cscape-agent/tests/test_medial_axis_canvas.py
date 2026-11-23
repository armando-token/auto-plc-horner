"""Comprehensive unit test suite for Cscape HMI Dynamic Spatial Medial Axis Skeletonization Canvas (W282).

Work Package: W282 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Medial Axis Transform Voronoi Skeletonization SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Comprehensive Test Coverage:
1. Diagnostic codes (MedialAxisDiagnosticCode) with 16-bit unsigned hash behavior and representations.
2. Analog registers (%R2430..%R2437) and discrete coils (%M567..%M568) mappings and aliases.
3. Canvas configuration and geometry models (Point2D, Edge2D, Triangle2D, MedialNode, MedialBranch, Polygon2D).
4. Boundary point sampling and polygon point-in-polygon containment (convex and concave ray casting).
5. Medial axis extraction for standard shapes (rectangle, L-shape, dumbbell/dogbone with bottleneck, T-shape).
6. Inscribed circle radius calculation, accuracy, and boundary clearance consistency.
7. Branch pruning filter: verifying branch count reduction with higher pruning thresholds while preserving main spine.
8. Bottleneck detection: correctly identifying neck in dumbbell/constriction, threshold variation, %M568 alarm.
9. Degenerate cases: collinear points, 2-point lines, single points, empty polygon, self-intersecting polygons.
10. SVG vector generation: XML validity, viewBox, color contrast WCAG AAA compliance (> 18:1), element markers.
11. ILogicUnit protocol compliance (name, priority, is_enabled, scan_step, step, execute, reset).
12. Horner OCS register space synchronization (%R2430..%R2437, %M567..%M568) and 50-step scan cycle soak stability.
13. Pure IEC 61131-3 Structured Text generation and validation with STParser and SecurityGuard.
14. Anti-ladder security guard: rejects ladder contacts, coils, rung/network delimiters, and mnemonics.
15. Deterministic verification runner run_medial_axis_canvas_verification returning strict 4-state contract JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.medial_axis_canvas import (
    # Diagnostic Codes
    DIAG_OK,
    DIAG_EVENT_OK,
    NOMINAL_OK,
    MEDIAL_AXIS_OK,
    DIAG_ERR_INVALID_POLYGON,
    INVALID_POLYGON_FAULT,
    DIAG_ERR_SELF_INTERSECTING,
    SELF_INTERSECTING_FAULT,
    DIAG_ERR_INSUFFICIENT_VERTICES,
    INSUFFICIENT_VERTICES_FAULT,
    DIAG_ERR_BOTTLENECK_DETECTED,
    BOTTLENECK_DETECTED_ALARM,
    DIAG_ERR_TOPOLOGY_COLLAPSE,
    TOPOLOGY_COLLAPSE_FAULT,
    DIAG_ERR_BOTTLENECK_CHOKE,
    DIAG_ERR_CLEARANCE_VIOLATION,
    DIAG_ERR_DEGENERATE_GEOMETRY,
    DIAG_ERR_COLINEAR_FAULT,
    MedialAxisDiagnosticCode,
    DiagnosticCode,
    # Registers & Coils
    REG_W282_BOUNDARY_VERTICES,
    REG_W282_MEDIAL_BRANCHES,
    REG_W282_MAX_CLEARANCE,
    REG_W282_MEAN_CLEARANCE,
    REG_W282_SKELETON_LENGTH,
    REG_W282_SELECTED_BRANCH,
    REG_W282_PRUNING_THRESHOLD,
    REG_W282_DIAGNOSTIC_CODE,
    REG_BOUNDARY_CONTOUR_VERTEX_COUNT,
    REG_INTERNAL_MEDIAL_BRANCH_COUNT,
    REG_MAX_CLEARANCE_RADIUS_SCALED,
    REG_MEAN_CLEARANCE_RADIUS_SCALED,
    REG_SKELETON_TOTAL_LENGTH,
    REG_SELECTED_BRANCH_ID,
    REG_PRUNING_THRESHOLD_SCALED,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_MEDIAL_AXIS_BOUNDARY_VERTICES,
    REG_MEDIAL_AXIS_BRANCH_COUNT,
    REG_MEDIAL_AXIS_MAX_CLEARANCE,
    REG_MEDIAL_AXIS_MEAN_CLEARANCE,
    REG_MEDIAL_AXIS_SKELETON_LENGTH,
    REG_MEDIAL_AXIS_SELECTED_BRANCH,
    REG_MEDIAL_AXIS_PRUNING_THRESHOLD,
    REG_MEDIAL_AXIS_DIAGNOSTIC_CODE,
    REG_W282_STATUS_WORD,
    REG_W282_BOUNDARY_POINTS,
    REG_W282_MEDIAL_NODES,
    REG_W282_BRANCH_SEGMENTS,
    REG_W282_MAX_INSCRIBED_RADIUS,
    REG_W282_MIN_CLEARANCE_RADIUS,
    REG_W282_BOTTLENECK_COUNT,
    REG_MEDIAL_AXIS_STATUS_WORD,
    REG_MEDIAL_AXIS_BOUNDARY_POINTS,
    REG_MEDIAL_AXIS_NODE_COUNT,
    REG_MEDIAL_AXIS_MAX_INSCRIBED_RADIUS,
    REG_MEDIAL_AXIS_MIN_CLEARANCE_RADIUS,
    REG_MEDIAL_AXIS_BOTTLENECK_COUNT,
    COIL_W282_SKELETON_VALID,
    COIL_W282_BOTTLENECK_WARNING,
    COIL_W282_CANVAS_ACTIVE,
    COIL_W282_BOTTLENECK_ALARM,
    COIL_SKELETON_VALID,
    COIL_BOTTLENECK_WARNING,
    COIL_BOTTLENECK_ALARM,
    COIL_CLEARANCE_VIOLATION,
    COIL_MEDIAL_AXIS_CANVAS_ACTIVE,
    COIL_MEDIAL_AXIS_ACTIVE,
    # Status Bits
    MedialAxisStatusBits,
    MedialAxisCanvasStatusBits,
    # Colors & Contrast
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_POLYGON_BOUNDARY,
    COLOR_POLYGON_FILL,
    COLOR_SKELETON_BRANCH,
    COLOR_CLEARANCE_DISK,
    COLOR_MAX_DISK,
    COLOR_BOTTLENECK,
    COLOR_NOMINAL_EMERALD,
    COLOR_ALARM_CRIMSON,
    COLOR_WARNING_AMBER,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    srgb_channel_to_linear,
    hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    ContrastResult,
    # Geometry Primitives & Data Models
    PointTuple,
    Point2D,
    Edge2D,
    Segment2D,
    Triangle2D,
    MedialNode,
    MedialBranch,
    MedialAxisNode,
    MedialAxisBranch,
    BottleneckChoke,
    Polygon2D,
    MedialAxisMetrics,
    # Geometry Algorithms
    cross_product_2d,
    compute_shoelace_area,
    compute_polygon_perimeter,
    segments_strictly_intersect,
    is_polygon_self_intersecting,
    is_collinear_set,
    validate_polygon,
    is_point_in_polygon,
    point_to_segment_distance,
    shortest_distance_to_polygon,
    is_segment_inside_polygon,
    sample_polygon_boundary,
    compute_delaunay_triangulation,
    prune_skeleton_graph,
    compute_medial_axis_transform,
    create_canonical_polygon,
    create_canonical_venturi_polygon,
    # Canvas Engine
    MedialAxisCanvasEngine,
    MedialAxisCanvas,
    create_canonical_medial_axis_canvas,
    generate_medial_axis_canvas_svg,
    create_mock_scan_context,
    # Pure ST POU
    MEDIAL_AXIS_CANVAS_PURE_ST_POU,
    W282_MEDIAL_AXIS_PURE_ST_POU,
    ST_PROGRAM_MEDIAL_AXIS_CANVAS_SYNC,
    MEDIAL_AXIS_PURE_ST_POU,
    verify_medial_axis_canvas_pure_st,
    # Verification Runner
    run_medial_axis_canvas_verification,
)


# ============================================================================
# 1. Diagnostic Codes & Status Bits
# ============================================================================

class TestDiagnosticAndStatusCodes:
    """Validate 16-bit diagnostic codes and status bit flags."""

    def test_diagnostic_code_values(self) -> None:
        """Verify integer enumeration codes for all 6 states."""
        assert MedialAxisDiagnosticCode.OK == 0
        assert MedialAxisDiagnosticCode.INVALID_POLYGON == 1
        assert MedialAxisDiagnosticCode.SELF_INTERSECTING == 2
        assert MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES == 3
        assert MedialAxisDiagnosticCode.BOTTLENECK_DETECTED == 4
        assert MedialAxisDiagnosticCode.TOPOLOGY_COLLAPSE == 5

    def test_diagnostic_code_hash_and_equality(self) -> None:
        """Verify 16-bit unsigned hash behavior and signed/unsigned equality."""
        code_ok = MedialAxisDiagnosticCode.OK
        assert hash(code_ok) == hash(0)
        assert code_ok == 0

        code_bot = MedialAxisDiagnosticCode.BOTTLENECK_DETECTED
        assert hash(code_bot) == hash(4)
        assert code_bot == 4

        # Verify DiagnosticCode integer subclass comparison across signed 16-bit
        diag_8201 = DiagnosticCode(0x8201)
        assert diag_8201 == 0x8201
        assert diag_8201 == (0x8201 - 0x10000)  # -32255
        assert str(diag_8201) == "0x8201"
        assert repr(diag_8201) == "DiagnosticCode(0x8201)"

        diag_8202 = DiagnosticCode(0x8202)
        assert diag_8202 == 0x8202
        assert diag_8202 == (0x8202 - 0x10000)  # -32254
        assert str(diag_8202) == "0x8202"

    def test_diagnostic_aliases(self) -> None:
        """Verify nominal and fault diagnostic constant aliases."""
        assert DIAG_OK == MedialAxisDiagnosticCode.OK
        assert DIAG_EVENT_OK == MedialAxisDiagnosticCode.OK
        assert NOMINAL_OK == MedialAxisDiagnosticCode.OK
        assert MEDIAL_AXIS_OK == MedialAxisDiagnosticCode.OK

        assert DIAG_ERR_INVALID_POLYGON == MedialAxisDiagnosticCode.INVALID_POLYGON
        assert INVALID_POLYGON_FAULT == MedialAxisDiagnosticCode.INVALID_POLYGON

        assert DIAG_ERR_SELF_INTERSECTING == MedialAxisDiagnosticCode.SELF_INTERSECTING
        assert SELF_INTERSECTING_FAULT == MedialAxisDiagnosticCode.SELF_INTERSECTING

        assert DIAG_ERR_INSUFFICIENT_VERTICES == MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES
        assert INSUFFICIENT_VERTICES_FAULT == MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES

        assert DIAG_ERR_BOTTLENECK_DETECTED == MedialAxisDiagnosticCode.BOTTLENECK_DETECTED
        assert BOTTLENECK_DETECTED_ALARM == MedialAxisDiagnosticCode.BOTTLENECK_DETECTED

        assert DIAG_ERR_TOPOLOGY_COLLAPSE == MedialAxisDiagnosticCode.TOPOLOGY_COLLAPSE
        assert TOPOLOGY_COLLAPSE_FAULT == MedialAxisDiagnosticCode.TOPOLOGY_COLLAPSE

        assert DIAG_ERR_BOTTLENECK_CHOKE == MedialAxisDiagnosticCode.BOTTLENECK_DETECTED
        assert DIAG_ERR_CLEARANCE_VIOLATION == MedialAxisDiagnosticCode.BOTTLENECK_DETECTED
        assert DIAG_ERR_DEGENERATE_GEOMETRY == MedialAxisDiagnosticCode.INVALID_POLYGON
        assert DIAG_ERR_COLINEAR_FAULT == MedialAxisDiagnosticCode.INVALID_POLYGON

    def test_status_bits_flags(self) -> None:
        """Verify MedialAxisStatusBits bitmask flags."""
        assert MedialAxisStatusBits.CANVAS_ACTIVE == (1 << 0)
        assert MedialAxisStatusBits.SKELETON_COMPUTED == (1 << 1)
        assert MedialAxisStatusBits.BOTTLENECK_WARNING == (1 << 2)
        assert MedialAxisStatusBits.CLEARANCE_VIOLATION == (1 << 2)
        assert MedialAxisStatusBits.TOPOLOGY_INTACT == (1 << 3)
        assert MedialAxisStatusBits.POLYGON_VALID == (1 << 4)
        assert MedialAxisStatusBits.SVG_RENDER_VALID == (1 << 5)
        assert MedialAxisStatusBits.PRUNING_COMPLETED == (1 << 6)

        assert MedialAxisCanvasStatusBits is MedialAxisStatusBits


# ============================================================================
# 2. Register and Coil Mappings (%R2430..%R2437, %M567..%M568)
# ============================================================================

class TestRegisterAndCoilMappings:
    """Validate analog register (%R2430..%R2437) and discrete coil (%M567..%M568) addresses."""

    def test_analog_register_addresses(self) -> None:
        """Verify word register assignments %R2430..%R2437."""
        assert REG_W282_BOUNDARY_VERTICES == "%R2430"
        assert REG_W282_MEDIAL_BRANCHES == "%R2431"
        assert REG_W282_MAX_CLEARANCE == "%R2432"
        assert REG_W282_MEAN_CLEARANCE == "%R2433"
        assert REG_W282_SKELETON_LENGTH == "%R2434"
        assert REG_W282_SELECTED_BRANCH == "%R2435"
        assert REG_W282_PRUNING_THRESHOLD == "%R2436"
        assert REG_W282_DIAGNOSTIC_CODE == "%R2437"

    def test_register_aliases(self) -> None:
        """Verify functional alias mapping for registers."""
        assert REG_BOUNDARY_CONTOUR_VERTEX_COUNT == "%R2430"
        assert REG_INTERNAL_MEDIAL_BRANCH_COUNT == "%R2431"
        assert REG_MAX_CLEARANCE_RADIUS_SCALED == "%R2432"
        assert REG_MEAN_CLEARANCE_RADIUS_SCALED == "%R2433"
        assert REG_SKELETON_TOTAL_LENGTH == "%R2434"
        assert REG_SELECTED_BRANCH_ID == "%R2435"
        assert REG_PRUNING_THRESHOLD_SCALED == "%R2436"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2437"

        assert REG_MEDIAL_AXIS_BOUNDARY_VERTICES == "%R2430"
        assert REG_MEDIAL_AXIS_BRANCH_COUNT == "%R2431"
        assert REG_MEDIAL_AXIS_MAX_CLEARANCE == "%R2432"
        assert REG_MEDIAL_AXIS_MEAN_CLEARANCE == "%R2433"
        assert REG_MEDIAL_AXIS_SKELETON_LENGTH == "%R2434"
        assert REG_MEDIAL_AXIS_SELECTED_BRANCH == "%R2435"
        assert REG_MEDIAL_AXIS_PRUNING_THRESHOLD == "%R2436"
        assert REG_MEDIAL_AXIS_DIAGNOSTIC_CODE == "%R2437"

        assert REG_W282_STATUS_WORD == "%R2430"
        assert REG_W282_BOUNDARY_POINTS == "%R2430"
        assert REG_W282_MEDIAL_NODES == "%R2431"
        assert REG_W282_BRANCH_SEGMENTS == "%R2431"
        assert REG_W282_MAX_INSCRIBED_RADIUS == "%R2432"
        assert REG_W282_MIN_CLEARANCE_RADIUS == "%R2433"
        assert REG_W282_BOTTLENECK_COUNT == "%R2436"

    def test_discrete_coil_addresses(self) -> None:
        """Verify discrete coil assignments %M567 and %M568."""
        assert COIL_W282_SKELETON_VALID == "%M567"
        assert COIL_W282_BOTTLENECK_WARNING == "%M568"
        assert COIL_W282_CANVAS_ACTIVE == "%M567"
        assert COIL_W282_BOTTLENECK_ALARM == "%M568"
        assert COIL_SKELETON_VALID == "%M567"
        assert COIL_BOTTLENECK_WARNING == "%M568"
        assert COIL_BOTTLENECK_ALARM == "%M568"
        assert COIL_CLEARANCE_VIOLATION == "%M568"
        assert COIL_MEDIAL_AXIS_CANVAS_ACTIVE == "%M567"
        assert COIL_MEDIAL_AXIS_ACTIVE == "%M567"


# ============================================================================
# 3. Canvas Configuration & Model Initialization
# ============================================================================

class TestCanvasConfigurationAndModelInit:
    """Validate canvas engine configuration and underlying geometry models."""

    def test_engine_default_initialization(self) -> None:
        """Verify engine initialization with canonical default settings."""
        engine = MedialAxisCanvasEngine()
        assert engine.name == "MedialAxisCanvasEngine"
        assert engine.priority == 88
        assert engine.is_enabled is True
        assert engine.cycle_count == 0
        assert len(engine.polygon) == 12
        assert engine.sample_spacing == 30.0
        assert engine.pruning_threshold_pct == 10.0
        assert engine.bottleneck_threshold == 30.0

    def test_engine_custom_configuration(self) -> None:
        """Verify engine initialization with custom parameters."""
        poly = [(0.0, 0.0), (200.0, 0.0), (200.0, 100.0), (0.0, 100.0)]
        engine = MedialAxisCanvasEngine(
            polygon=poly,
            sample_spacing=15.0,
            pruning_threshold_pct=20.0,
            bottleneck_threshold=40.0,
        )
        assert len(engine.polygon) == 4
        assert engine.sample_spacing == 15.0
        assert engine.pruning_threshold_pct == 20.0
        assert engine.bottleneck_threshold == 40.0

    def test_point2d_model(self) -> None:
        """Verify Point2D coordinates, distance, and equality behavior."""
        p1 = Point2D(10.0, 20.0, point_id=1)
        p2 = Point2D(40.0, 60.0, point_id=2)
        assert p1.coords == (10.0, 20.0)
        assert p1.distance_to(p2) == pytest.approx(50.0)
        assert Point2D(10.0, 20.0) == p1
        assert hash(p1) == hash((round(10.0, 4), round(20.0, 4)))

    def test_edge2d_model(self) -> None:
        """Verify Edge2D undirected invariant and length."""
        e1 = Edge2D((10.0, 20.0), (30.0, 40.0))
        e2 = Edge2D((30.0, 40.0), (10.0, 20.0))
        assert e1 == e2
        assert hash(e1) == hash(e2)
        assert e1.length == pytest.approx(math.hypot(20.0, 20.0))

    def test_segment2d_model(self) -> None:
        """Verify Segment2D distance to point calculation."""
        p1 = Point2D(0.0, 0.0)
        p2 = Point2D(100.0, 0.0)
        seg = Segment2D(p1, p2)
        assert seg.length == 100.0
        # Point projecting directly onto segment
        assert seg.distance_to_point(Point2D(50.0, 25.0)) == pytest.approx(25.0)
        # Point projecting before p1
        assert seg.distance_to_point(Point2D(-30.0, 40.0)) == pytest.approx(50.0)
        # Point projecting past p2
        assert seg.distance_to_point(Point2D(130.0, 40.0)) == pytest.approx(50.0)

    def test_triangle2d_model(self) -> None:
        """Verify Triangle2D circumcenter and circumradius properties."""
        p1 = (0.0, 0.0)
        p2 = (4.0, 0.0)
        p3 = (0.0, 3.0)
        tri = Triangle2D(p1, p2, p3)
        assert tri.area == pytest.approx(6.0)
        assert tri.circumcenter == pytest.approx((2.0, 1.5))
        assert tri.circumradius == pytest.approx(2.5)
        # Inscribed point inside circumcircle
        assert tri.circumcircle_contains((1.0, 1.0)) is True
        # Far external point outside circumcircle
        assert tri.circumcircle_contains((10.0, 10.0)) is False

    def test_medial_node_and_branch_models(self) -> None:
        """Verify MedialNode and MedialBranch dataclasses and aliases."""
        node = MedialNode(
            node_id=1,
            x=150.0,
            y=200.0,
            clearance_radius=45.5,
            is_bottleneck=False,
            is_max_clearance=True,
            degree=3,
        )
        assert node.coords == (150.0, 200.0)
        assert node.clearance_radius == 45.5
        assert node.is_max_clearance is True
        assert node.point.coords == (150.0, 200.0)
        assert MedialAxisNode is MedialNode

        branch = MedialBranch(
            branch_id=10,
            p1=(100.0, 100.0),
            p2=(140.0, 130.0),
            length=50.0,
            avg_clearance=35.0,
            is_pruned=False,
            is_bottleneck=False,
        )
        assert branch.length == 50.0
        assert branch.avg_clearance == 35.0
        assert MedialAxisBranch is MedialBranch

    def test_medial_axis_metrics_model(self) -> None:
        """Verify MedialAxisMetrics initialization and defaults."""
        m = MedialAxisMetrics()
        assert m.boundary_vertex_count == 0
        assert m.medial_branch_count == 0
        assert m.max_clearance_radius == 0.0
        assert m.diagnostic_code == MedialAxisDiagnosticCode.OK

    def test_canonical_polygons(self) -> None:
        """Verify canonical polygon generators."""
        poly = create_canonical_polygon()
        assert len(poly) == 12
        assert compute_shoelace_area(poly) > 100000.0

        venturi = create_canonical_venturi_polygon()
        assert len(venturi.vertices) == 12
        assert venturi.is_valid is True


# ============================================================================
# 4. Boundary Point Sampling & Containment Tests
# ============================================================================

class TestBoundarySamplingAndContainment:
    """Validate boundary point contour sampling, ray-casting containment, and Delaunay."""

    def test_shoelace_area_and_perimeter_rectangle(self) -> None:
        """Verify Shoelace formula area and perimeter on rectangle."""
        rect = [(0.0, 0.0), (400.0, 0.0), (400.0, 200.0), (0.0, 200.0)]
        assert compute_shoelace_area(rect) == pytest.approx(80000.0)
        assert compute_polygon_perimeter(rect) == pytest.approx(1200.0)

    def test_point_to_segment_distance(self) -> None:
        """Verify Euclidean distance from point to segment."""
        a = (0.0, 0.0)
        b = (100.0, 0.0)
        assert point_to_segment_distance((50.0, 25.0), a, b) == pytest.approx(25.0)
        assert point_to_segment_distance((-10.0, 0.0), a, b) == pytest.approx(10.0)
        assert point_to_segment_distance((120.0, 0.0), a, b) == pytest.approx(20.0)

    def test_point_in_polygon_ray_casting(self) -> None:
        """Verify ray casting point-in-polygon containment test."""
        poly = [(0.0, 0.0), (200.0, 0.0), (200.0, 100.0), (0.0, 100.0)]
        assert is_point_in_polygon((50.0, 50.0), poly) is True
        assert is_point_in_polygon((100.0, 50.0), poly) is True
        assert is_point_in_polygon((250.0, 50.0), poly) is False
        assert is_point_in_polygon((50.0, 150.0), poly) is False

    def test_shortest_distance_to_polygon(self) -> None:
        """Verify shortest Euclidean distance to polygon boundary."""
        poly = [(0.0, 0.0), (200.0, 0.0), (200.0, 100.0), (0.0, 100.0)]
        # Center point (100, 50) is distance 50 from top and bottom walls
        assert shortest_distance_to_polygon((100.0, 50.0), poly) == pytest.approx(50.0)
        # Point (20, 20) is distance 20 from left and bottom walls
        assert shortest_distance_to_polygon((20.0, 20.0), poly) == pytest.approx(20.0)

    def test_segments_strictly_intersect(self) -> None:
        """Verify segment intersection predicate."""
        # Strictly crossing segments
        assert segments_strictly_intersect((0.0, 0.0), (10.0, 10.0), (0.0, 10.0), (10.0, 0.0)) is True
        # Parallel non-intersecting segments
        assert segments_strictly_intersect((0.0, 0.0), (10.0, 0.0), (0.0, 5.0), (10.0, 5.0)) is False
        # T-junction touching at endpoint (non-strict)
        assert segments_strictly_intersect((0.0, 0.0), (10.0, 0.0), (5.0, 0.0), (5.0, 10.0)) is False

    def test_boundary_point_sampling(self) -> None:
        """Verify boundary point sampling along polygon edges."""
        poly = create_canonical_polygon()
        samples, edge_map = sample_polygon_boundary(poly, spacing=25.0)
        assert len(samples) >= 80
        assert len(edge_map) == len(samples)
        for pt, e_idx in edge_map.items():
            assert 0 <= e_idx < len(poly)
            # Sampled points must lie exactly on polygon boundary
            assert shortest_distance_to_polygon(pt, poly) < 1e-2

    def test_delaunay_triangulation_empty_circumcircle(self) -> None:
        """Verify Delaunay triangulation satisfies empty circumcircle criterion."""
        pts = [(10.0, 10.0), (100.0, 10.0), (100.0, 100.0), (10.0, 100.0), (55.0, 55.0)]
        tris = compute_delaunay_triangulation(pts)
        assert len(tris) >= 2
        for t in tris:
            for p in pts:
                if p not in (t.p1, t.p2, t.p3):
                    assert not t.circumcircle_contains(p, eps=1e-5)


# ============================================================================
# 5. Medial Axis Extraction for Standard Shapes
# ============================================================================

class TestMedialAxisStandardShapes:
    """Validate MAT extraction for standard shapes: rectangle, L-shape, dumbbell, T-shape."""

    def test_medial_axis_rectangle(self) -> None:
        """Extract medial axis of a 400x200 rectangle (central spine + corner branches)."""
        rect = [(100.0, 100.0), (500.0, 100.0), (500.0, 300.0), (100.0, 300.0)]
        nodes, branches, metrics, diag = compute_medial_axis_transform(rect, sample_spacing=20.0)

        assert len(nodes) > 10
        assert len(branches) > 10
        # In a 400x200 rectangle, the max inscribed disk radius analytically equals half the height (100.0)
        assert metrics.max_clearance_radius == pytest.approx(100.0, abs=1.0)
        assert diag in (MedialAxisDiagnosticCode.OK, MedialAxisDiagnosticCode.BOTTLENECK_DETECTED)

        # All nodes must be inside rectangle
        for n in nodes:
            assert is_point_in_polygon((n.x, n.y), rect) is True
            assert n.clearance_radius > 0.0

    def test_medial_axis_l_shape(self) -> None:
        """Extract medial axis of an L-shape polygon with internal corner bend."""
        l_shape = [
            (100.0, 100.0), (300.0, 100.0), (300.0, 300.0),
            (500.0, 300.0), (500.0, 500.0), (100.0, 500.0),
        ]
        nodes, branches, metrics, diag = compute_medial_axis_transform(l_shape, sample_spacing=25.0)

        assert len(nodes) > 10
        assert len(branches) > 10
        assert metrics.max_clearance_radius > 90.0

        for n in nodes:
            assert is_point_in_polygon((n.x, n.y), l_shape) is True

    def test_medial_axis_dumbbell_dogbone_bottleneck(self) -> None:
        """Extract medial axis of a dumbbell/dogbone shape with a narrow constriction neck."""
        dumbbell = [
            (100.0, 100.0), (300.0, 100.0), (300.0, 220.0), (500.0, 220.0),
            (500.0, 100.0), (700.0, 100.0), (700.0, 400.0), (500.0, 400.0),
            (500.0, 280.0), (300.0, 280.0), (300.0, 400.0), (100.0, 400.0),
        ]
        nodes, branches, metrics, diag = compute_medial_axis_transform(
            dumbbell,
            sample_spacing=25.0,
            bottleneck_threshold=35.0,
        )

        assert len(nodes) > 15
        assert len(branches) > 15
        # The central neck (height 60px, y in [220, 280]) has clearance ~30px
        assert metrics.min_clearance_radius < 35.0
        assert metrics.bottleneck_count > 0
        assert diag == MedialAxisDiagnosticCode.BOTTLENECK_DETECTED

        # Verify bottleneck nodes are located in the neck region (x in [300, 500])
        neck_bottlenecks = [n for n in nodes if n.is_bottleneck and 300.0 <= n.x <= 500.0]
        assert len(neck_bottlenecks) > 0

    def test_medial_axis_t_shape(self) -> None:
        """Extract medial axis of a T-shape polygon with 3-way branching junction."""
        t_shape = [
            (100.0, 100.0), (400.0, 100.0), (400.0, 200.0), (300.0, 200.0),
            (300.0, 500.0), (200.0, 500.0), (200.0, 200.0), (100.0, 200.0),
        ]
        nodes, branches, metrics, diag = compute_medial_axis_transform(t_shape, sample_spacing=25.0)

        assert len(nodes) > 10
        assert len(branches) > 10
        # Arms are 100px wide, so clearance is ~50px
        assert metrics.max_clearance_radius >= 50.0

        for n in nodes:
            assert is_point_in_polygon((n.x, n.y), t_shape) is True


# ============================================================================
# 6. Inscribed Circle Radius Calculation & Accuracy
# ============================================================================

class TestInscribedCircleRadiusCalculation:
    """Validate maximal inscribed circle (MIC) radius accuracy and distance fields."""

    def test_inscribed_circle_radius_accuracy_rectangle(self) -> None:
        """In a 400x200 rectangle, the maximum inscribed circle radius must match height/2 (100.0)."""
        rect = [(0.0, 0.0), (400.0, 0.0), (400.0, 200.0), (0.0, 200.0)]
        nodes, _, metrics, _ = compute_medial_axis_transform(rect, sample_spacing=20.0)
        assert metrics.max_clearance_radius == pytest.approx(100.0, abs=1.0)

    def test_all_medial_nodes_have_positive_clearance(self) -> None:
        """Verify that every interior medial node has positive clearance to the boundary."""
        poly = create_canonical_polygon()
        nodes, _, _, _ = compute_medial_axis_transform(poly, sample_spacing=30.0)
        for n in nodes:
            assert n.clearance_radius > 0.0
            dist = shortest_distance_to_polygon((n.x, n.y), poly)
            assert math.isclose(n.clearance_radius, dist, abs_tol=1e-1)

    def test_maximal_inscribed_circle_fits_within_polygon(self) -> None:
        """Verify maximal inscribed circle center plus radius does not overshoot boundary."""
        poly = create_canonical_polygon()
        nodes, _, metrics, _ = compute_medial_axis_transform(poly, sample_spacing=30.0)
        max_node = max(nodes, key=lambda n: n.clearance_radius)
        # Shortest distance from max node to boundary equals its clearance radius
        dist = shortest_distance_to_polygon((max_node.x, max_node.y), poly)
        assert dist == pytest.approx(metrics.max_clearance_radius, abs=1e-1)


# ============================================================================
# 7. Branch Pruning Filter
# ============================================================================

class TestBranchPruningFilter:
    """Validate noise branch pruning with progressive thresholds."""

    def test_pruning_reduces_or_maintains_branches(self) -> None:
        """Higher pruning threshold reduces spurious noise branches."""
        poly = create_canonical_polygon()
        _, unpruned_b, _, _ = compute_medial_axis_transform(poly, pruning_threshold_pct=0.0)
        _, pruned_b, _, _ = compute_medial_axis_transform(poly, pruning_threshold_pct=30.0)

        assert len(pruned_b) <= len(unpruned_b)
        assert len(pruned_b) > 0  # Core backbone topology preserved

    def test_progressive_pruning_threshold(self) -> None:
        """Verify branch counts across progression: 0% -> 15% -> 30%."""
        poly = create_canonical_polygon()
        _, b0, _, _ = compute_medial_axis_transform(poly, pruning_threshold_pct=0.0)
        _, b15, _, _ = compute_medial_axis_transform(poly, pruning_threshold_pct=15.0)
        _, b30, _, _ = compute_medial_axis_transform(poly, pruning_threshold_pct=30.0)

        assert len(b0) >= len(b15)
        assert len(b15) >= len(b30)
        assert len(b30) > 0

    def test_pruning_threshold_setter_updates_state(self) -> None:
        """Verify set_pruning_threshold updates analytics dynamically."""
        engine = MedialAxisCanvasEngine(pruning_threshold_pct=5.0)
        initial_threshold = engine.pruning_threshold_pct
        assert initial_threshold == 5.0

        engine.set_pruning_threshold(25.0)
        assert engine.pruning_threshold_pct == 25.0
        assert engine.reg_table.read_word(REG_W282_PRUNING_THRESHOLD) == 250


# ============================================================================
# 8. Bottleneck Detection & Alarms
# ============================================================================

class TestBottleneckDetection:
    """Validate bottleneck identification in constrictions and alarm coil %M568."""

    def test_bottleneck_detection_alarm_active(self) -> None:
        """Constriction with clearance ~25 px triggers alarm when threshold is 30 px."""
        poly = create_canonical_polygon()
        engine = MedialAxisCanvasEngine(polygon=poly, bottleneck_threshold=30.0)
        assert engine.is_bottleneck_detected is True
        assert engine.diagnostic_code == MedialAxisDiagnosticCode.BOTTLENECK_DETECTED
        assert engine.reg_table.read_bit(COIL_W282_BOTTLENECK_WARNING) is True

    def test_bottleneck_detection_alarm_cleared(self) -> None:
        """When threshold is 10 px, no bottleneck is triggered."""
        poly = create_canonical_polygon()
        engine = MedialAxisCanvasEngine(polygon=poly, bottleneck_threshold=10.0)
        assert engine.is_bottleneck_detected is False
        assert engine.diagnostic_code == MedialAxisDiagnosticCode.OK
        assert engine.reg_table.read_bit(COIL_W282_BOTTLENECK_WARNING) is False

    def test_set_bottleneck_threshold_toggles_alarm(self) -> None:
        """Verify dynamically changing bottleneck threshold updates coil %M568."""
        poly = create_canonical_polygon()
        engine = MedialAxisCanvasEngine(polygon=poly, bottleneck_threshold=10.0)
        assert engine.is_bottleneck_detected is False
        assert engine.reg_table.read_bit(COIL_W282_BOTTLENECK_WARNING) is False

        # Raise threshold to 30.0 px (above neck clearance) -> alarm triggers
        engine.set_bottleneck_threshold(30.0)
        assert engine.is_bottleneck_detected is True
        assert engine.reg_table.read_bit(COIL_W282_BOTTLENECK_WARNING) is True

        # Alias set_clearance_threshold also works
        engine.set_clearance_threshold(10.0)
        assert engine.is_bottleneck_detected is False
        assert engine.reg_table.read_bit(COIL_W282_BOTTLENECK_WARNING) is False


# ============================================================================
# 9. Degenerate Geometry Cases
# ============================================================================

class TestDegenerateCases:
    """Validate handling of collinear points, 2-point lines, single points, and self-intersections."""

    def test_insufficient_vertices_two_points(self) -> None:
        """Polygon with 2 points fails with INSUFFICIENT_VERTICES."""
        poly = [(0.0, 0.0), (100.0, 50.0)]
        assert validate_polygon(poly) == MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES

    def test_insufficient_vertices_single_point(self) -> None:
        """Polygon with 1 point fails with INSUFFICIENT_VERTICES."""
        poly = [(50.0, 50.0)]
        assert validate_polygon(poly) == MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES

    def test_empty_polygon(self) -> None:
        """Empty polygon fails with INSUFFICIENT_VERTICES."""
        poly: List[PointTuple] = []
        assert validate_polygon(poly) == MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES

    def test_collinear_three_points(self) -> None:
        """Collinear vertices producing zero area fail with INVALID_POLYGON."""
        poly = [(0.0, 0.0), (50.0, 0.0), (100.0, 0.0)]
        assert validate_polygon(poly) == MedialAxisDiagnosticCode.INVALID_POLYGON

    def test_self_intersecting_bowtie_polygon(self) -> None:
        """Self-intersecting bowtie polygon fails with SELF_INTERSECTING."""
        poly = [(0.0, 0.0), (100.0, 100.0), (0.0, 100.0), (100.0, 0.0)]
        assert validate_polygon(poly) == MedialAxisDiagnosticCode.SELF_INTERSECTING

    def test_is_collinear_set_function(self) -> None:
        """Verify is_collinear_set utility function."""
        collinear_pts = [Point2D(0.0, 0.0), Point2D(10.0, 10.0), Point2D(20.0, 20.0)]
        assert is_collinear_set(collinear_pts) is True

        non_collinear_pts = [Point2D(0.0, 0.0), Point2D(10.0, 10.0), Point2D(20.0, 0.0)]
        assert is_collinear_set(non_collinear_pts) is False

    def test_degenerate_polygon_in_engine_execution(self) -> None:
        """Verify engine gracefully sets diagnostic code without unhandled exception."""
        deg_poly = [(0.0, 0.0), (50.0, 0.0), (100.0, 0.0)]
        engine = MedialAxisCanvasEngine(polygon=deg_poly)
        assert engine.diagnostic_code == MedialAxisDiagnosticCode.INVALID_POLYGON
        assert len(engine.medial_nodes) == 0
        assert len(engine.medial_branches) == 0
        assert engine.is_skeleton_valid is False


# ============================================================================
# 10. Standalone W3C SVG 1.1 Vector Generation
# ============================================================================

class TestW3CSvgGeneration:
    """Validate SVG XML markup, viewBox, visual markers, and rendering."""

    def test_svg_xml_validity_and_viewbox(self) -> None:
        """Verify generate_medial_axis_canvas_svg produces valid XML with standard viewBox."""
        svg = generate_medial_axis_canvas_svg()
        root = ET.fromstring(svg)
        assert root.tag.endswith("svg")
        assert root.attrib.get("viewBox") == "0 0 1200 750"
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"

    def test_svg_visual_element_markers(self) -> None:
        """Verify presence of polygon, line branches, circles, and telemetry HUD card."""
        svg = generate_medial_axis_canvas_svg()
        root = ET.fromstring(svg)

        # Polygon boundary element
        polygons = root.findall(".//{http://www.w3.org/2000/svg}polygon")
        assert len(polygons) >= 1

        # Skeleton line branches
        lines = root.findall(".//{http://www.w3.org/2000/svg}line")
        assert len(lines) >= 10

        # Clearance disks and node dots
        circles = root.findall(".//{http://www.w3.org/2000/svg}circle")
        assert len(circles) >= 10

        # Telemetry HUD text
        texts = root.findall(".//{http://www.w3.org/2000/svg}text")
        assert len(texts) >= 5
        text_content = " ".join("".join(t.itertext()) for t in texts)
        assert "MEDIAL AXIS" in text_content
        assert "%R2430" in text_content
        assert "%M567" in text_content

    def test_svg_bottleneck_marker_rendering(self) -> None:
        """Verify bottleneck choke markers are rendered when bottleneck is active."""
        poly = create_canonical_polygon()
        engine = MedialAxisCanvasEngine(polygon=poly, bottleneck_threshold=30.0)
        svg = generate_medial_axis_canvas_svg(engine)
        assert "CHOKE" in svg or "BOTTLENECK DETECTED" in svg


# ============================================================================
# 11. WCAG 2.1 AAA Contrast Compliance
# ============================================================================

class TestWCAGAAACompliance:
    """Validate WCAG 2.1 AAA contrast targets (> 18:1 for decoupled badges, > 7:1 for text)."""

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        """Verify contrast between primary text and decoupled HUD badge exceeds 18:1."""
        badge_contrast = validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert badge_contrast.is_compliant is True
        assert badge_contrast.contrast_ratio >= 18.0

    def test_primary_text_contrast_exceeds_7_to_1(self) -> None:
        """Verify contrast between primary text and dark backing surface exceeds 7:1."""
        text_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert text_contrast >= 7.0

    def test_relative_luminance_and_contrast_ratio_functions(self) -> None:
        """Verify sRGB channel linear conversion and relative luminance calculations."""
        # Pure white #FFFFFF luminance == 1.0
        assert hex_to_relative_luminance("#FFFFFF") == pytest.approx(1.0)
        # Pure black #000000 luminance == 0.0
        assert hex_to_relative_luminance("#000000") == pytest.approx(0.0)
        # Ratio between pure white and pure black is 21.0
        assert calculate_contrast_ratio("#FFFFFF", "#000000") == pytest.approx(21.0)

    def test_contrast_result_boolean_behavior(self) -> None:
        """Verify ContrastResult dict subclass behaves as boolean."""
        res_pass = ContrastResult({"is_compliant": True, "contrast_ratio": 19.5})
        assert bool(res_pass) is True
        assert res_pass.is_compliant is True
        assert res_pass.contrast_ratio == 19.5

        res_fail = ContrastResult({"is_compliant": False, "contrast_ratio": 4.5})
        assert bool(res_fail) is False


# ============================================================================
# 12. ILogicUnit Interface Compliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit scan cycle protocol implementation."""

    def test_engine_properties(self) -> None:
        """Verify priority, name, and enabled properties."""
        engine = MedialAxisCanvasEngine()
        assert engine.name == "MedialAxisCanvasEngine"
        assert engine.priority == 88
        assert engine.is_enabled is True
        assert engine.cycle_count == 0

    def test_scan_step_execution(self) -> None:
        """Verify scan_step execution increments cycle and returns telemetry dict."""
        engine = MedialAxisCanvasEngine()
        res = engine.scan_step(dt=0.01)
        assert res["cycle"] == 1
        assert res["boundary_vertices"] == 12
        assert res["medial_branches"] > 0
        assert engine.cycle_count == 1

    def test_step_and_execute_methods(self) -> None:
        """Verify step and execute return ExecutionResult with AgentStatus.SUCCESS."""
        engine = MedialAxisCanvasEngine()
        engine.step(0.01)
        assert engine.cycle_count == 1

        exec_res = engine.execute()
        assert exec_res.status == AgentStatus.SUCCESS
        assert exec_res.data["cycle"] == 2

    def test_reset_clears_cycle_count(self) -> None:
        """Verify reset restores cycle count to zero."""
        engine = MedialAxisCanvasEngine()
        engine.scan_step()
        assert engine.cycle_count == 1
        engine.reset()
        assert engine.cycle_count == 0


# ============================================================================
# 13. Horner RegisterTable Synchronization & Soak Stability
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate %R2430..%R2437 and %M567..%M568 synchronization and soak stability."""

    def test_analog_and_discrete_synchronization(self) -> None:
        """Verify registers are synchronized bit-exact."""
        reg = RegisterTable()
        engine = MedialAxisCanvasEngine(register_table=reg, bottleneck_threshold=30.0)

        assert reg.read_word(REG_W282_BOUNDARY_VERTICES) == 12
        assert reg.read_word(REG_W282_MEDIAL_BRANCHES) == len(engine.medial_branches)
        assert reg.read_word(REG_W282_MAX_CLEARANCE) == int(round(engine.max_clearance * 10))
        assert reg.read_word(REG_W282_MEAN_CLEARANCE) == int(round(engine.mean_clearance * 10))
        assert reg.read_word(REG_W282_SKELETON_LENGTH) == int(round(engine.skeleton_length))
        assert reg.read_word(REG_W282_PRUNING_THRESHOLD) == int(round(engine.pruning_threshold_pct * 10))
        assert reg.read_word(REG_W282_DIAGNOSTIC_CODE) == int(MedialAxisDiagnosticCode.BOTTLENECK_DETECTED)

        assert reg.read_bit(COIL_W282_SKELETON_VALID) is True
        assert reg.read_bit(COIL_W282_BOTTLENECK_WARNING) is True

    def test_fifty_step_scan_cycle_soak_stability(self) -> None:
        """Verify 50 consecutive scan cycles execute without NaNs or drift."""
        reg = RegisterTable()
        engine = MedialAxisCanvasEngine(register_table=reg)

        for _ in range(50):
            engine.scan_step(dt=0.01)
            assert not math.isnan(engine.max_clearance)
            assert not math.isnan(engine.mean_clearance)
            assert not math.isnan(engine.skeleton_length)
            assert reg.read_word(REG_W282_BOUNDARY_VERTICES) == 12

        assert engine.cycle_count == 50


# ============================================================================
# 14. Pure IEC 61131-3 ST POU Validation
# ============================================================================

class TestPureSTPouValidation:
    """Validate Pure ST POU syntax, AST parsing, and bound registers."""

    def test_pure_st_pou_syntax_and_ast_parsing(self) -> None:
        """Verify MedialAxisCanvasSync passes SecurityGuard and STParser."""
        SecurityGuard.assert_pure_st_content(MEDIAL_AXIS_CANVAS_PURE_ST_POU)
        res = STParser.validate_code(MEDIAL_AXIS_CANVAS_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(MEDIAL_AXIS_CANVAS_PURE_ST_POU)
        assert ast.name == "MedialAxisCanvasSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_bound_registers_r2430_to_r2437_and_m567_to_m568(self) -> None:
        """Verify analog registers %R2430..%R2437 and coils %M567..%M568 are bound."""
        ast = STParser.parse_pou(MEDIAL_AXIS_CANVAS_PURE_ST_POU)
        expected_regs = [
            "%R2430", "%R2431", "%R2432", "%R2433",
            "%R2434", "%R2435", "%R2436", "%R2437",
        ]
        for r in expected_regs:
            assert r in ast.bound_registers

        assert "%M567" in ast.bound_registers
        assert "%M568" in ast.bound_registers

    def test_verify_helper_function(self) -> None:
        """Verify verify_medial_axis_canvas_pure_st() helper returns True."""
        assert verify_medial_axis_canvas_pure_st() is True
        assert verify_medial_axis_canvas_pure_st(W282_MEDIAL_AXIS_PURE_ST_POU) is True


# ============================================================================
# 15. Anti-Ladder Construct Rejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Validate aggressive interception and rejection of ladder logic constructs."""

    def test_ladder_contacts_rejection(self) -> None:
        """Verify contacts construct '---[ ]---' is rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad VAR X : BOOL; END_VAR ---[/]--- END_PROGRAM")

    def test_ladder_coils_rejection(self) -> None:
        """Verify coils construct '---( )---', '---(S)---', '---(R)---' are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad VAR Y : BOOL; END_VAR ---( )--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad VAR Y : BOOL; END_VAR ---(S)--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad VAR Y : BOOL; END_VAR ---(R)--- END_PROGRAM")

    def test_ladder_delimiters_rejection(self) -> None:
        """Verify RUNG and NETWORK delimiters are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad\nRUNG 1:\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM")

    def test_ladder_mnemonics_rejection(self) -> None:
        """Verify mnemonics XIC, XIO, OTE, OTL, OTU are rejected."""
        for mnem in ["XIC InBit;", "XIO InBit;", "OTE OutBit;", "OTL OutBit;", "OTU OutBit;"]:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(f"PROGRAM Bad\n{mnem}\nEND_PROGRAM")


# ============================================================================
# 16. Verification Suite Runner
# ============================================================================

class TestVerificationRunner:
    """Validate complete deterministic 10-stage verification suite."""

    def test_runner_returns_strict_4_state_success(self) -> None:
        """Verify run_medial_axis_canvas_verification returns success and 10/10 checks pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            res = run_medial_axis_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
                work_package="W282",
            )

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["checks_passed"] == 10
            assert res["data"]["total_checks"] == 10
            assert res["data"]["work_package"] == "W282"
            assert ev_path.is_file()
            assert svg_path.is_file()

            # Verify evidence JSON structure
            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"
            assert len(data["data"]["tests"]) == 10
