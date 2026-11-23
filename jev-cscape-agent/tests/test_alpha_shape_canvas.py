"""Comprehensive unit test suite for Cscape HMI Dynamic Spatial Alpha Shape SCADA Canvas (W279).

Work Package: W279 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Alpha Shape Non-Convex Concave Boundary SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Must test:
- Diagnostic codes signed/unsigned 16-bit values and string representations (0x0000, 0xEE77, 0xEE78, 0xEE81)
- Register and coil mappings (%R2400..%R2407, %M560..%M561)
- 2D Point geometries, cross-product calculations, collinear sorting
- Alpha shape boundary edge calculation for simple regular shapes (square, triangle, concave star, donut/ring)
- Degenerate cases: empty set, single point, collinear points (< 3 non-collinear -> 0xEE78)
- Convex vs. concave perimeter and area calculations (shoelace)
- Concavity index calculation (Area_alpha / Area_convex)
- Boundary breach detection (%M561 and 0xEE77) and high concavity alert (%M560 and 0xEE81)
- Standalone W3C SVG 1.1 markup generation and XML validity parsing with xml.etree.ElementTree
- WCAG 2.1 AAA contrast verification (> 18:1 for decoupled badges)
- ILogicUnit protocol compliance (scan_step, step, execute, reset, name, priority, is_enabled)
- Horner register table synchronization (%R2400..%R2407, %M560..%M561) with 50-step scan cycle soak stability
- Pure ST POU syntax parsing with STParser and SecurityGuard.assert_pure_st_content
- Anti-ladder security guard: rejects ladder constructs with LadderForbiddenError, accepts valid ST
- Verification runner run_alpha_shape_canvas_verification 9 stages
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

from jev_cscape.hmi.alpha_shape_canvas import (
    # Diagnostic Codes
    DIAG_OK,
    DIAG_EVENT_OK,
    NOMINAL_OK,
    ALPHA_SHAPE_OK,
    ALPHA_SHAPE_CANVAS_OK,
    BOUNDARY_BREACH_ALARM,
    BOUNDARY_BREACH_FAULT,
    DIAG_ERR_BOUNDARY_BREACH,
    DIAG_ERR_BOUNDARY_BREACH_ALARM,
    DEGENERATE_SET_FAULT,
    DEGENERATE_POINTS_FAULT,
    DIAG_ERR_DEGENERATE_SET,
    DIAG_ERR_DEGENERATE_POINTS,
    HIGH_CONCAVITY_ALARM,
    HIGH_CONCAVITY_FAULT,
    DIAG_ERR_HIGH_CONCAVITY,
    DiagnosticCode,
    # Registers & Coils
    REG_W279_STATUS_WORD,
    REG_W279_TOTAL_POINTS,
    REG_W279_BOUNDARY_EDGES,
    REG_W279_ALPHA_RADIUS,
    REG_W279_CONCAVE_AREA,
    REG_W279_CONVEX_AREA,
    REG_W279_CONCAVITY_INDEX,
    REG_W279_DIAGNOSTIC_CODE,
    REG_ALPHA_SHAPE_STATUS_WORD,
    REG_ALPHA_SHAPE_TOTAL_POINTS,
    REG_ALPHA_SHAPE_BOUNDARY_EDGES,
    REG_ALPHA_SHAPE_ALPHA_RADIUS,
    REG_ALPHA_SHAPE_CONCAVE_AREA,
    REG_ALPHA_SHAPE_CONVEX_AREA,
    REG_ALPHA_SHAPE_CONCAVITY_INDEX,
    REG_ALPHA_SHAPE_DIAGNOSTIC_CODE,
    COIL_W279_HIGH_CONCAVITY,
    COIL_HIGH_CONCAVITY_ALARM,
    COIL_CONCAVITY_ALARM,
    COIL_W279_CONCAVITY_ALARM,
    COIL_ALPHA_SHAPE_HIGH_CONCAVITY,
    COIL_W279_CANVAS_ACTIVE,
    COIL_ALPHA_SHAPE_CANVAS_ACTIVE,
    COIL_W279_BOUNDARY_BREACH,
    COIL_BOUNDARY_BREACH_ALARM,
    COIL_BOUNDARY_BREACH,
    COIL_ALPHA_SHAPE_BOUNDARY_BREACH,
    # Status Bits
    AlphaCanvasStatusBits,
    AlphaShapeStatusBits,
    AlphaShapeStatus,
    # Colors & Contrast
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_ALPHA_BOUNDARY_CYAN,
    COLOR_ALPHA_FILL_CYAN,
    COLOR_CONVEX_HULL_AMBER,
    COLOR_NOMINAL_EMERALD,
    COLOR_ALARM_CRIMSON,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    srgb_channel_to_linear,
    hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    # Models & Primitives
    PointTuple,
    AlphaPoint,
    ScatterPoint,
    Edge2D,
    Triangle2D,
    cross_product_2d,
    compute_convex_hull_2d,
    compute_convex_hull,
    compute_graham_scan_2d,
    compute_shoelace_area,
    compute_polygon_perimeter,
    compute_concavity_index,
    point_to_segment_distance,
    is_collinear_set,
    compute_delaunay_triangulation,
    compute_alpha_shape,
    compute_alpha_shape_edges,
    compute_alpha_shape_area,
    compute_alpha_boundary_perimeter,
    is_point_inside_alpha_shape,
    # Canvas Engine
    AlphaShapeCanvasEngine,
    AlphaShapeCanvas,
    create_canonical_alpha_shape_canvas,
    generate_alpha_shape_canvas_svg,
    create_mock_scan_context,
    # Pure ST POU
    ALPHA_SHAPE_CANVAS_PURE_ST_POU,
    W279_ALPHA_SHAPE_PURE_ST_POU,
    ST_PROGRAM_ALPHA_SHAPE_CANVAS_SYNC,
    verify_alpha_shape_canvas_pure_st,
    # Verification Suite
    run_alpha_shape_canvas_verification,
)


# ============================================================================
# 1. Diagnostic Codes Signed/Unsigned 16-Bit Values & Representations
# ============================================================================

class TestDiagnosticCodes:
    """Validate 16-bit diagnostic codes (0x0000, 0xEE77, 0xEE78, 0xEE81), signed/unsigned values, and formats."""

    def test_diagnostic_code_values_and_representations(self) -> None:
        """Verify signed and unsigned 16-bit values and string representations."""
        # 0x0000 OK
        assert DIAG_OK == 0x0000
        assert DIAG_EVENT_OK == 0x0000
        assert NOMINAL_OK == 0x0000
        assert ALPHA_SHAPE_OK == 0x0000
        assert ALPHA_SHAPE_CANVAS_OK == 0x0000
        assert int(DIAG_OK) == 0
        assert f"0x{int(DIAG_OK) & 0xFFFF:04X}" == "0x0000"

        # 0xEE77 Boundary Breach Alarm
        assert BOUNDARY_BREACH_ALARM == 0xEE77
        assert BOUNDARY_BREACH_FAULT == 0xEE77
        assert DIAG_ERR_BOUNDARY_BREACH == 0xEE77
        assert DIAG_ERR_BOUNDARY_BREACH_ALARM == 0xEE77
        assert int(BOUNDARY_BREACH_ALARM) == 61047
        assert f"0x{int(BOUNDARY_BREACH_ALARM) & 0xFFFF:04X}" == "0xEE77"

        # 0xEE78 Degenerate Set Fault
        assert DEGENERATE_SET_FAULT == 0xEE78
        assert DEGENERATE_POINTS_FAULT == 0xEE78
        assert DIAG_ERR_DEGENERATE_SET == 0xEE78
        assert DIAG_ERR_DEGENERATE_POINTS == 0xEE78
        assert int(DEGENERATE_SET_FAULT) == 61048
        assert f"0x{int(DEGENERATE_SET_FAULT) & 0xFFFF:04X}" == "0xEE78"

        # 0xEE81 High Concavity Alarm
        assert HIGH_CONCAVITY_ALARM == 0xEE81
        assert HIGH_CONCAVITY_FAULT == 0xEE81
        assert DIAG_ERR_HIGH_CONCAVITY == 0xEE81
        assert int(HIGH_CONCAVITY_ALARM) == 61057
        assert f"0x{int(HIGH_CONCAVITY_ALARM) & 0xFFFF:04X}" == "0xEE81"

    def test_diagnostic_code_signed_vs_unsigned_equality(self) -> None:
        """Verify signed and unsigned comparison across INT16 boundaries."""
        code_neg = DiagnosticCode(-1)
        assert code_neg == 0xFFFF
        assert code_neg == -1

        # 0xEE77 unsigned 61047 == signed -4489
        code_ee77 = DiagnosticCode(0xEE77)
        assert code_ee77 == 61047
        assert code_ee77 == -4489
        assert code_ee77 == 0xEE77

        # 0xEE78 unsigned 61048 == signed -4488
        code_ee78 = DiagnosticCode(0xEE78)
        assert code_ee78 == 61048
        assert code_ee78 == -4488
        assert code_ee78 == 0xEE78

        # 0xEE81 unsigned 61057 == signed -4479
        code_ee81 = DiagnosticCode(0xEE81)
        assert code_ee81 == 61057
        assert code_ee81 == -4479
        assert code_ee81 == 0xEE81

        # Hashing and container behavior
        diag_set: Set[DiagnosticCode] = {
            DIAG_OK,
            BOUNDARY_BREACH_ALARM,
            DEGENERATE_SET_FAULT,
            HIGH_CONCAVITY_ALARM,
        }
        assert len(diag_set) == 4
        assert DiagnosticCode(0xEE77) in diag_set
        assert DiagnosticCode(0xEE78) in diag_set
        assert DiagnosticCode(0xEE81) in diag_set
        assert DiagnosticCode(0x0000) in diag_set


# ============================================================================
# 2. Register and Coil Mappings (%R2400..%R2407, %M560..%M561)
# ============================================================================

class TestRegisterAndCoilMappings:
    """Validate register mappings (%R2400..%R2407) and coil mappings (%M560..%M561)."""

    def test_w279_analog_word_registers(self) -> None:
        """Verify %R2400..%R2407 primary register assignments and aliases."""
        assert REG_W279_STATUS_WORD == "%R2400"
        assert REG_W279_TOTAL_POINTS == "%R2401"
        assert REG_W279_BOUNDARY_EDGES == "%R2402"
        assert REG_W279_ALPHA_RADIUS == "%R2403"
        assert REG_W279_CONCAVE_AREA == "%R2404"
        assert REG_W279_CONVEX_AREA == "%R2405"
        assert REG_W279_CONCAVITY_INDEX == "%R2406"
        assert REG_W279_DIAGNOSTIC_CODE == "%R2407"

        # Aliases
        assert REG_ALPHA_SHAPE_STATUS_WORD == "%R2400"
        assert REG_ALPHA_SHAPE_TOTAL_POINTS == "%R2401"
        assert REG_ALPHA_SHAPE_BOUNDARY_EDGES == "%R2402"
        assert REG_ALPHA_SHAPE_ALPHA_RADIUS == "%R2403"
        assert REG_ALPHA_SHAPE_CONCAVE_AREA == "%R2404"
        assert REG_ALPHA_SHAPE_CONVEX_AREA == "%R2405"
        assert REG_ALPHA_SHAPE_CONCAVITY_INDEX == "%R2406"
        assert REG_ALPHA_SHAPE_DIAGNOSTIC_CODE == "%R2407"

    def test_w279_discrete_coils(self) -> None:
        """Verify %M560..%M561 discrete coils and aliases."""
        assert COIL_W279_HIGH_CONCAVITY == "%M560"
        assert COIL_HIGH_CONCAVITY_ALARM == "%M560"
        assert COIL_CONCAVITY_ALARM == "%M560"
        assert COIL_W279_CONCAVITY_ALARM == "%M560"
        assert COIL_ALPHA_SHAPE_HIGH_CONCAVITY == "%M560"
        assert COIL_W279_CANVAS_ACTIVE == "%M560"

        assert COIL_W279_BOUNDARY_BREACH == "%M561"
        assert COIL_BOUNDARY_BREACH_ALARM == "%M561"
        assert COIL_BOUNDARY_BREACH == "%M561"
        assert COIL_ALPHA_SHAPE_BOUNDARY_BREACH == "%M561"

    def test_status_bits_definitions(self) -> None:
        """Verify AlphaCanvasStatusBits and AlphaShapeStatusBits definitions."""
        assert AlphaCanvasStatusBits.CANVAS_ACTIVE == 1 << 0
        assert AlphaCanvasStatusBits.ALPHA_SHAPE_COMPUTED == 1 << 1
        assert AlphaCanvasStatusBits.HIGH_CONCAVITY_ALARM == 1 << 2
        assert AlphaCanvasStatusBits.BOUNDARY_BREACH_ALARM == 1 << 3
        assert AlphaCanvasStatusBits.DEGENERATE_SET_FAULT == 1 << 4
        assert AlphaCanvasStatusBits.SVG_RENDER_VALID == 1 << 5
        assert AlphaCanvasStatusBits.CLUSTERS_ENCLOSED == 1 << 6
        assert AlphaShapeStatusBits == AlphaCanvasStatusBits


# ============================================================================
# 3. 2D Point Geometries, Cross-Product & Primitives
# ============================================================================

class TestPointGeometriesAndPrimitives:
    """Validate 2D Point structures, edge structures, triangle circumcircles, and cross-products."""

    def test_alpha_point_initialization(self) -> None:
        """Verify AlphaPoint / ScatterPoint dataclass fields, coordinates, and default values."""
        p = AlphaPoint(point_id="P01", x=120.5, y=340.2, value=42.7)
        assert p.point_id == "P01"
        assert math.isclose(p.x, 120.5)
        assert math.isclose(p.y, 340.2)
        assert math.isclose(p.value, 42.7)
        assert p.is_outlier is False
        assert p.coords == (120.5, 340.2)

        p_alias = ScatterPoint(point_id="SP02", x=50.0, y=60.0)
        assert p_alias.point_id == "SP02"

    def test_edge2d_endpoints_ordering_and_length(self) -> None:
        """Verify Edge2D canonical endpoint ordering and Euclidean length."""
        e1 = Edge2D((10.0, 20.0), (30.0, 40.0))
        e2 = Edge2D((30.0, 40.0), (10.0, 20.0))
        assert e1 == e2
        assert hash(e1) == hash(e2)
        assert math.isclose(e1.length, math.hypot(20.0, 20.0))

    def test_triangle2d_circumcircle_and_area(self) -> None:
        """Verify Triangle2D circumcenter, circumradius, area, and containment."""
        # Right triangle with hypotenuse 10*sqrt(2)
        t = Triangle2D((0.0, 0.0), (10.0, 0.0), (0.0, 10.0))
        assert math.isclose(t.area, 50.0)
        assert math.isclose(t.center_x, 5.0)
        assert math.isclose(t.center_y, 5.0)
        assert math.isclose(t.circumradius, math.sqrt(50.0))

        # Circumcircle containment
        assert t.circumcircle_contains((5.0, 5.0)) is True
        assert t.circumcircle_contains((100.0, 100.0)) is False

        # Interior containment
        assert t.contains_point((2.0, 2.0)) is True
        assert t.contains_point((8.0, 8.0)) is False

    def test_cross_product_2d_turns(self) -> None:
        """Verify cross product OA x OB for CCW, CW, and collinear turns."""
        o = (0.0, 0.0)
        a = (10.0, 0.0)
        b = (5.0, 10.0)
        assert cross_product_2d(o, a, b) > 0.0   # CCW
        assert cross_product_2d(o, b, a) < 0.0   # CW
        assert math.isclose(cross_product_2d(o, a, (20.0, 0.0)), 0.0, abs_tol=1e-12)

    def test_point_to_segment_distance(self) -> None:
        """Verify point-to-segment distance calculation."""
        a = (0.0, 0.0)
        b = (10.0, 0.0)
        assert math.isclose(point_to_segment_distance((5.0, 4.0), a, b), 4.0)
        assert math.isclose(point_to_segment_distance((15.0, 0.0), a, b), 5.0)
        assert math.isclose(point_to_segment_distance((-5.0, 0.0), a, b), 5.0)


# ============================================================================
# 4. Alpha Shape Boundary Edge Calculation for Regular Shapes
# ============================================================================

class TestAlphaShapeRegularShapes:
    """Validate alpha shape boundary extraction for square, triangle, concave star, and donut/ring."""

    def test_alpha_shape_square(self) -> None:
        """Verify square extracts exactly 4 boundary edges and CI == 1.0."""
        sq_pts: List[PointTuple] = [(0.0, 0.0), (100.0, 0.0), (100.0, 100.0), (0.0, 100.0)]
        edges, tris = compute_alpha_shape(sq_pts, alpha=150.0)

        assert len(edges) == 4
        assert len(tris) == 2
        area_alpha = compute_alpha_shape_area(tris)
        perim_alpha = compute_alpha_boundary_perimeter(edges)
        ci = compute_concavity_index(area_alpha, 10000.0)

        assert math.isclose(area_alpha, 10000.0)
        assert math.isclose(perim_alpha, 400.0)
        assert math.isclose(ci, 1.0)

    def test_alpha_shape_triangle(self) -> None:
        """Verify triangle extracts exactly 3 boundary edges and CI == 1.0."""
        tri_pts: List[PointTuple] = [(0.0, 0.0), (100.0, 0.0), (50.0, 80.0)]
        edges, tris = compute_alpha_shape(tri_pts, alpha=150.0)

        assert len(edges) == 3
        assert len(tris) == 1
        area_alpha = compute_alpha_shape_area(tris)
        perim_alpha = compute_alpha_boundary_perimeter(edges)
        area_convex = compute_shoelace_area(tri_pts)
        ci = compute_concavity_index(area_alpha, area_convex)

        assert math.isclose(area_alpha, 4000.0)
        assert math.isclose(ci, 1.0)

    def test_alpha_shape_concave_star(self) -> None:
        """Verify 5-pointed concave star retains concave bays: concave area < convex area and CI < 1.0."""
        # 10 points alternating outer radius 100 and inner radius 40
        cx, cy = 200.0, 200.0
        star_pts: List[PointTuple] = []
        for i in range(10):
            ang = i * (2.0 * math.pi / 10.0)
            r = 100.0 if (i % 2 == 0) else 40.0
            star_pts.append((cx + r * math.cos(ang), cy + r * math.sin(ang)))

        # With center point to ensure triangulation inside star arms
        all_pts = star_pts + [(cx, cy)]
        # Filter with alpha smaller than convex bridge circumradius
        edges, tris = compute_alpha_shape(all_pts, alpha=75.0)

        assert len(tris) >= 8
        assert len(edges) >= 10
        area_alpha = compute_alpha_shape_area(tris)
        hull = compute_convex_hull_2d(all_pts)
        area_convex = compute_shoelace_area(hull)
        ci = compute_concavity_index(area_alpha, area_convex)

        assert area_alpha < area_convex
        assert ci < 0.70
        assert ci > 0.20

    def test_alpha_shape_donut_ring(self) -> None:
        """Verify donut / ring shape: extracts outer and inner circular boundary edges."""
        cx, cy = 400.0, 400.0
        r_out, r_in = 120.0, 60.0
        ring_pts: List[PointTuple] = []
        n_pts = 16
        for i in range(n_pts):
            ang = i * (2.0 * math.pi / n_pts)
            ring_pts.append((cx + r_out * math.cos(ang), cy + r_out * math.sin(ang)))
            ring_pts.append((cx + r_in * math.cos(ang), cy + r_in * math.sin(ang)))

        # Alpha radius between annular spacing and inner hole diameter
        edges, tris = compute_alpha_shape(ring_pts, alpha=50.0)

        # Should extract boundary edges for outer ring and inner hole
        assert len(edges) >= 20
        area_alpha = compute_alpha_shape_area(tris)
        hull = compute_convex_hull_2d(ring_pts)
        area_convex = compute_shoelace_area(hull)
        ci = compute_concavity_index(area_alpha, area_convex)

        # Concave area is smaller than full convex hull due to central hole
        assert area_alpha < area_convex
        assert ci < 0.90
        assert ci > 0.50


# ============================================================================
# 5. Degenerate Set Handling (< 3 Points or Collinear Points)
# ============================================================================

class TestDegenerateSetHandling:
    """Validate robust handling of empty set, single point, two points, and collinear sets."""

    def test_empty_point_set(self) -> None:
        """Verify empty point set returns empty boundary and triggers DEGENERATE_SET_FAULT."""
        edges, tris = compute_alpha_shape([])
        assert edges == []
        assert tris == []
        assert compute_alpha_shape_area(tris) == 0.0
        assert compute_alpha_boundary_perimeter(edges) == 0.0

        engine = AlphaShapeCanvasEngine()
        engine.set_points([])
        assert engine.degenerate_set is True
        assert engine.diagnostic_code == DEGENERATE_SET_FAULT
        assert engine.concave_area == 0.0
        assert engine.concavity_index == 0.0

    def test_single_point(self) -> None:
        """Verify single point returns empty edges and triggers DEGENERATE_SET_FAULT."""
        pt = [(50.0, 50.0)]
        edges, tris = compute_alpha_shape(pt)
        assert edges == []
        assert tris == []

        engine = AlphaShapeCanvasEngine()
        engine.set_points(pt)
        assert engine.degenerate_set is True
        assert engine.diagnostic_code == DEGENERATE_SET_FAULT
        assert engine.concavity_index == 0.0

    def test_two_points(self) -> None:
        """Verify two points return single segment edge and DEGENERATE_SET_FAULT."""
        pts = [(10.0, 20.0), (50.0, 20.0)]
        edges, tris = compute_alpha_shape(pts)
        assert len(edges) == 1
        assert tris == []
        assert math.isclose(edges[0].length, 40.0)

        engine = AlphaShapeCanvasEngine()
        engine.set_points(pts)
        assert engine.degenerate_set is True
        assert engine.diagnostic_code == DEGENERATE_SET_FAULT

    def test_collinear_points_collapse(self) -> None:
        """Verify collinear points (3 or more) form 1D line segments with 0 area and DEGENERATE_SET_FAULT."""
        collinear_pts = [(0.0, 0.0), (25.0, 25.0), (50.0, 50.0), (75.0, 75.0), (100.0, 100.0)]
        assert is_collinear_set(collinear_pts) is True

        edges, tris = compute_alpha_shape(collinear_pts, alpha=100.0)
        assert len(edges) == 4
        assert tris == []

        engine = AlphaShapeCanvasEngine()
        engine.set_points(collinear_pts)
        assert engine.degenerate_set is True
        assert engine.diagnostic_code == DEGENERATE_SET_FAULT
        assert engine.concave_area == 0.0
        assert engine.concavity_index == 0.0


# ============================================================================
# 6. Convex vs. Concave Perimeter & Area Calculations (Shoelace)
# ============================================================================

class TestShoelaceAreaAndPerimeter:
    """Validate Shoelace area, Euclidean perimeter, and convex vs. concave area summation."""

    def test_shoelace_area_known_polygons(self) -> None:
        """Verify Shoelace formula on unit square and right triangle."""
        sq: List[PointTuple] = [(0.0, 0.0), (10.0, 0.0), (10.0, 10.0), (0.0, 10.0)]
        assert math.isclose(compute_shoelace_area(sq), 100.0)
        assert math.isclose(compute_polygon_perimeter(sq), 40.0)

        tri: List[PointTuple] = [(0.0, 0.0), (30.0, 0.0), (0.0, 40.0)]
        assert math.isclose(compute_shoelace_area(tri), 600.0)
        assert math.isclose(compute_polygon_perimeter(tri), 120.0)

    def test_convex_hull_and_graham_scan(self) -> None:
        """Verify Andrew's Monotone Chain and Graham scan produce identical convex hulls."""
        pts: List[PointTuple] = [
            (10.0, 10.0), (90.0, 10.0), (90.0, 90.0), (10.0, 90.0),
            (50.0, 50.0), (30.0, 40.0), (70.0, 60.0),
        ]
        h_mono = compute_convex_hull_2d(pts)
        h_graham = compute_graham_scan_2d(pts)
        h_alias = compute_convex_hull(pts)

        assert len(h_mono) == 4
        assert set(h_mono) == set(h_graham)
        assert set(h_mono) == set(h_alias)
        assert math.isclose(compute_shoelace_area(h_mono), 6400.0)


# ============================================================================
# 7. Concavity Index Calculation
# ============================================================================

class TestConcavityIndexCalculation:
    """Validate concavity index calculation CI = Area_alpha / Area_convex."""

    def test_concavity_index_convex_shape(self) -> None:
        """Verify convex shape has CI == 1.0."""
        ci = compute_concavity_index(5000.0, 5000.0)
        assert math.isclose(ci, 1.0)

    def test_concavity_index_concave_shape(self) -> None:
        """Verify concave shape has CI < 1.0."""
        ci = compute_concavity_index(2500.0, 5000.0)
        assert math.isclose(ci, 0.5)

    def test_concavity_index_boundary_clamping(self) -> None:
        """Verify CI handles edge cases: zero convex area, negative values, and upper clamping."""
        assert compute_concavity_index(0.0, 0.0) == 0.0
        assert compute_concavity_index(100.0, 0.0) == 0.0
        assert compute_concavity_index(6000.0, 5000.0) == 1.0
        assert compute_concavity_index(-10.0, 5000.0) == 0.0


# ============================================================================
# 8. Boundary Breach Detection & High Concavity Alerting
# ============================================================================

class TestSafetyDiagnosticsBreachAndConcavityAlert:
    """Validate boundary breach detection (%M561, 0xEE77) and high concavity alert (%M560, 0xEE81)."""

    def test_boundary_breach_detection(self) -> None:
        """Verify coordinate outside alpha shape triggers BOUNDARY_BREACH_ALARM and sets %M561."""
        engine = AlphaShapeCanvasEngine()
        # Default engine is indented star around (600, 375)
        # Coordinate inside
        assert engine.check_boundary_breach(test_point=(600.0, 375.0)) is False
        assert engine.reg_table.read_bit(COIL_W279_BOUNDARY_BREACH) is False

        # Coordinate far outside
        assert engine.check_boundary_breach(test_point=(50.0, 50.0)) is True
        assert engine.boundary_breach is True
        assert engine.diagnostic_code == BOUNDARY_BREACH_ALARM
        assert engine.reg_table.read_bit(COIL_W279_BOUNDARY_BREACH) is True
        assert engine.reg_table.read_uword(REG_W279_DIAGNOSTIC_CODE) == 0xEE77

    def test_high_concavity_alarm_assertion(self) -> None:
        """Verify high concavity (CI < threshold) asserts %M560 and sets 0xEE81."""
        engine = AlphaShapeCanvasEngine(concavity_threshold=0.75)
        # Default indented star has CI ~ 0.33 < 0.75
        assert engine.concavity_index < 0.75
        assert engine.high_concavity is True
        assert engine.reg_table.read_bit(COIL_W279_HIGH_CONCAVITY) is True
        assert engine.reg_table.read_uword(REG_W279_DIAGNOSTIC_CODE) == 0xEE81

    def test_nominal_state_without_alarms(self) -> None:
        """Verify fully convex polygon clears high concavity and breach alarms."""
        engine = AlphaShapeCanvasEngine(alpha_radius=200.0, concavity_threshold=0.75)
        # Set convex square
        engine.set_points([(100.0, 100.0), (300.0, 100.0), (300.0, 300.0), (100.0, 300.0)])
        assert math.isclose(engine.concavity_index, 1.0)
        assert engine.high_concavity is False
        assert engine.boundary_breach is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.reg_table.read_bit(COIL_W279_HIGH_CONCAVITY) is False
        assert engine.reg_table.read_bit(COIL_W279_BOUNDARY_BREACH) is False


# ============================================================================
# 9. Standalone W3C SVG 1.1 Generation & XML Validity
# ============================================================================

class TestW3CSvgGeneration:
    """Validate standalone W3C SVG 1.1 markup generation and XML syntax."""

    def test_svg_generation_and_xml_validity(self) -> None:
        """Verify SVG 1.1 string parses cleanly with xml.etree.ElementTree."""
        engine = AlphaShapeCanvasEngine()
        svg_str = engine.render_svg()

        # Parse XML
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib.get("viewBox") == "0 0 1200 750"
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"

        # Check essential graphic elements
        assert "<polygon" in svg_str
        assert "<line" in svg_str
        assert "<circle" in svg_str
        assert "<text" in svg_str
        assert "SPATIAL ALPHA SHAPE" in svg_str

    def test_standalone_svg_generator_function(self) -> None:
        """Verify generate_alpha_shape_canvas_svg() helper function."""
        svg_str = generate_alpha_shape_canvas_svg()
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")


# ============================================================================
# 10. WCAG 2.1 AAA Accessibility Contrast Verification
# ============================================================================

class TestWCAG21AAAContrast:
    """Validate WCAG 2.1 AAA contrast compliance (> 18:1 for decoupled badges)."""

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        """Verify decoupled dark badge backing (#05080C) against primary text (#F8FAFC) exceeds 18:1."""
        ratio = calculate_contrast_ratio(COLOR_DECOUPLED_BADGE, COLOR_TEXT_PRIMARY)
        assert ratio >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert ratio >= 18.0

        val = validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert val["is_compliant"] is True
        assert val["contrast_ratio"] >= 18.0

    def test_theme_background_text_contrast_exceeds_7_to_1(self) -> None:
        """Verify dark theme background (#0F172A) against primary text (#F8FAFC) exceeds 7:1."""
        ratio = calculate_contrast_ratio(COLOR_DARK_THEME_BACKING, COLOR_TEXT_PRIMARY)
        assert ratio >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert ratio >= 7.0

    def test_relative_luminance_monotonicity(self) -> None:
        """Verify hex_to_relative_luminance for black, white, and midtones."""
        assert math.isclose(hex_to_relative_luminance("#000000"), 0.0, abs_tol=1e-5)
        assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-5)
        lum_slate = hex_to_relative_luminance("#0F172A")
        assert 0.0 < lum_slate < 0.1


# ============================================================================
# 11. ILogicUnit Protocol Compliance
# ============================================================================

class TestILogicUnitProtocol:
    """Validate ILogicUnit interface compliance (scan_step, step, execute, reset)."""

    def test_interface_attributes(self) -> None:
        """Verify name, priority, and is_enabled properties."""
        engine = AlphaShapeCanvasEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "AlphaShapeCanvasEngine"
        assert engine.priority == 88
        assert engine.is_enabled is True

    def test_scan_step_and_execute(self) -> None:
        """Verify scan_step and execute methods update cycle counts."""
        engine = AlphaShapeCanvasEngine()
        res = engine.scan_step(dt=0.01)
        assert res["cycle"] == 1
        assert res["total_points"] == 12
        assert engine._cycle_count == 1

        engine.step()
        assert engine._cycle_count == 2

        ctx = create_mock_scan_context(cycle=3, dt_ms=10.0, reg_table=engine.reg_table)
        engine.execute(ctx)
        assert engine._cycle_count == 3

    def test_reset_method(self) -> None:
        """Verify reset restores baseline state."""
        engine = AlphaShapeCanvasEngine()
        engine.check_boundary_breach(test_point=(0.0, 0.0))
        assert engine.boundary_breach is True

        engine.reset()
        assert engine._cycle_count == 0
        assert engine.boundary_breach is False
        assert len(engine.points) == 12


# ============================================================================
# 12. RegisterTable Synchronization & Scan Cycle Soak Stability
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate RegisterTable synchronization (%R2400..%R2407, %M560..%M561) and soak stability."""

    def test_analog_and_discrete_synchronization(self) -> None:
        """Verify registers are synchronized accurately."""
        reg = RegisterTable()
        engine = AlphaShapeCanvasEngine(register_table=reg)
        engine.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word(REG_W279_TOTAL_POINTS) == 12
        assert reg.read_word(REG_W279_BOUNDARY_EDGES) > 0
        assert reg.read_word(REG_W279_ALPHA_RADIUS) == int(round(engine.alpha_radius * 10))
        assert reg.read_word(REG_W279_CONCAVE_AREA) > 0
        assert reg.read_word(REG_W279_CONVEX_AREA) > 0
        assert reg.read_word(REG_W279_CONCAVITY_INDEX) == int(round(engine.concavity_index * 1000))

    def test_fifty_step_scan_cycle_soak_stability(self) -> None:
        """Verify 50 consecutive scan cycles execute without NaNs or drift."""
        reg = RegisterTable()
        engine = AlphaShapeCanvasEngine(register_table=reg)
        ctx = create_mock_scan_context(cycle=0, dt_ms=10.0, reg_table=reg)

        for step in range(50):
            ctx.cycle = step + 1
            engine.scan_step(dt=0.01)
            assert not math.isnan(engine.concavity_index)
            assert not math.isnan(engine.concave_area)
            assert not math.isnan(engine.convex_area)
            assert reg.read_word(REG_W279_TOTAL_POINTS) == 12


# ============================================================================
# 13. Pure IEC 61131-3 ST POU Validation
# ============================================================================

class TestPureSTPouValidation:
    """Validate Pure ST POU syntax, AST parsing, and bound registers."""

    def test_pure_st_pou_syntax_and_ast_parsing(self) -> None:
        """Verify AlphaShapeCanvasSync passes SecurityGuard and STParser."""
        SecurityGuard.assert_pure_st_content(ALPHA_SHAPE_CANVAS_PURE_ST_POU)
        res = STParser.validate_code(ALPHA_SHAPE_CANVAS_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ALPHA_SHAPE_CANVAS_PURE_ST_POU)
        assert ast.name == "AlphaShapeCanvasSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_bound_registers_r2400_to_r2407_and_m560_to_m561(self) -> None:
        """Verify analog registers %R2400..%R2407 and coils %M560..%M561 are bound in AST."""
        ast = STParser.parse_pou(ALPHA_SHAPE_CANVAS_PURE_ST_POU)
        expected_regs = [
            "%R2400", "%R2401", "%R2402", "%R2403",
            "%R2404", "%R2405", "%R2406", "%R2407",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

        assert "%M560" in ast.bound_registers
        assert "%M561" in ast.bound_registers

    def test_verify_helper_function(self) -> None:
        """Verify verify_alpha_shape_canvas_pure_st() helper returns True."""
        assert verify_alpha_shape_canvas_pure_st() is True
        assert verify_alpha_shape_canvas_pure_st(W279_ALPHA_SHAPE_PURE_ST_POU) is True


# ============================================================================
# 14. Anti-Ladder Construct Rejection
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
# 15. Verification Suite Runner
# ============================================================================

class TestVerificationRunner:
    """Validate complete deterministic 9-stage verification suite."""

    def test_runner_returns_strict_4_state_success(self) -> None:
        """Verify run_alpha_shape_canvas_verification returns success and 9/9 checks pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            res = run_alpha_shape_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
                work_package="W279",
            )

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
            assert res["data"]["work_package"] == "W279"
            assert ev_path.is_file()
            assert svg_path.is_file()

            # Verify evidence JSON structure
            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"
            assert len(data["data"]["tests"]) == 9
