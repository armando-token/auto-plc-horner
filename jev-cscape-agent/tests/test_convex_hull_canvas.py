"""Comprehensive unit test suite for Cscape HMI Dynamic Spatial Convex Hull Boundary SCADA Canvas (W276).

Work Package: W276 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Convex Hull Boundary SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Must test:
- Diagnostic codes signed/unsigned 16-bit values and string representations (0x0000, 0xEE77, 0xEE78)
- Register and coil mappings (%R2370..%R2377, %M553..%M554)
- 2D Point geometries, cross-product calculations, collinear sorting
- Convex hull algorithm on standard shapes (squares, triangles, random clusters, collinear sets)
- Degenerate set handling (< 3 unique points -> 0xEE78)
- Shoelace area calculation and perimeter summation
- Centroid calculation and dispersion radius (R_rms = sqrt(sigma_total^2))
- Boundary breach detection (inside vs outside, alarm %M554 and 0xEE77)
- Standalone W3C SVG 1.1 markup generation, valid SVG XML, polygon points, node markers
- WCAG 2.1 AAA contrast compliance (>= 18:1 decoupled badges, >= 7:1 text, >= 3:1 graphics)
- Process safety diagnostics, statistical outlier detection (> 2.5 * R_rms), and alarm coils
- ILogicUnit interface compliance (scan_step, execute, reset, name, priority, is_enabled)
- RegisterTable synchronization (%R2370..%R2377, %M553..%M554) with PrivilegeMode.SYSTEM, plus 50-step scan cycle soak stability
- Pure ST POU validation with STParser and SecurityGuard.assert_pure_st_content
- Anti-ladder construct rejection raising LadderForbiddenError
- 9-stage verification suite run_convex_hull_canvas_verification() returning status 'success'
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

from jev_cscape.hmi.convex_hull_canvas import (
    # Diagnostic Codes
    DIAG_OK,
    DIAG_EVENT_OK,
    NOMINAL_OK,
    CONVEX_HULL_OK,
    CONVEX_HULL_CANVAS_OK,
    BOUNDARY_BREACH_ALARM,
    BOUNDARY_BREACH_FAULT,
    DIAG_ERR_BOUNDARY_BREACH,
    DIAG_ERR_BOUNDARY_BREACH_ALARM,
    DEGENERATE_SET_FAULT,
    DEGENERATE_POINTS_FAULT,
    DIAG_ERR_DEGENERATE_SET,
    DIAG_ERR_DEGENERATE_POINTS,
    DiagnosticCode,
    # Registers & Coils (W276 Primary)
    REG_W276_STATUS_WORD,
    REG_W276_TOTAL_POINTS,
    REG_W276_ACTIVE_CLUSTERS,
    REG_W276_MAX_PERIMETER,
    REG_W276_MAX_DISPERSION,
    REG_W276_MIN_DISTANCE,
    REG_W276_OUTLIER_COUNT,
    REG_W276_DIAGNOSTIC_CODE,
    REG_W276_CRITICAL_ZONE,
    COIL_W276_CANVAS_ACTIVE,
    COIL_W276_BOUNDARY_BREACH,
    # Standard W276 Aliases
    REG_CONVEX_HULL_STATUS_WORD,
    REG_CONVEX_HULL_TOTAL_POINTS,
    REG_CONVEX_HULL_ACTIVE_CLUSTERS,
    REG_CONVEX_HULL_MAX_PERIMETER,
    REG_CONVEX_HULL_MAX_DISPERSION,
    REG_CONVEX_HULL_MIN_DISTANCE,
    REG_CONVEX_HULL_OUTLIER_COUNT,
    REG_CONVEX_HULL_DIAGNOSTIC_CODE,
    REG_CONVEX_HULL_CRITICAL_ZONE,
    COIL_CONVEX_HULL_CANVAS_ACTIVE,
    COIL_BOUNDARY_BREACH_ALARM,
    COIL_CONVEX_HULL_BOUNDARY_BREACH,
    # Legacy Registers & Coils (Dual-write compatibility)
    REG_W201_STATUS_WORD,
    REG_W201_TOTAL_POINTS,
    REG_W201_ACTIVE_CLUSTERS,
    REG_W201_MAX_PERIMETER,
    REG_W201_MAX_DISPERSION,
    REG_W201_MIN_DISTANCE,
    REG_W201_OUTLIER_COUNT,
    REG_W201_CRITICAL_ZONE,
    COIL_W201_DISPERSION_ALARM,
    COIL_W201_OUTLIER_DETECTED,
    REG_W102_STATUS_WORD,
    REG_W102_TOTAL_POINTS,
    REG_W102_ACTIVE_CLUSTERS,
    REG_W102_MAX_PERIMETER,
    REG_W102_MAX_DISPERSION,
    REG_W102_MIN_DISTANCE,
    REG_W102_OUTLIER_COUNT,
    REG_W102_CRITICAL_ZONE,
    COIL_W102_DISPERSION_ALARM,
    COIL_W102_OUTLIER_DETECTED,
    # Status Bits
    HullCanvasStatusBits,
    # Colors & Contrast
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_FEED_CONDITIONING_BLUE,
    COLOR_REACTION_SYNTHESIS_EMERALD,
    COLOR_SEPARATION_POLISHING_AMBER,
    COLOR_ALARM_CRIMSON,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    srgb_channel_to_linear,
    hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    # Models & Primitives
    ScatterPoint,
    ProcessCluster,
    PointTuple,
    cross_product_2d,
    compute_convex_hull_2d,
    compute_graham_scan_2d,
    compute_polygon_perimeter,
    compute_shoelace_area,
    compute_outward_padded_polygon,
    is_point_in_polygon,
    winding_number_2d,
    is_point_in_polygon_winding,
    point_to_segment_distance,
    distance_to_polygon_perimeter,
    signed_distance_to_polygon,
    # Canvas Engine
    ConvexHullCanvas,
    ConvexHullCanvasEngine,
    create_canonical_convex_hull_canvas,
    generate_convex_hull_canvas_svg,
    create_mock_scan_context,
    # Pure ST POUs
    W276_CONVEX_HULL_PURE_ST_POU,
    W201_CONVEX_HULL_PURE_ST_POU,
    W102_CONVEX_HULL_PURE_ST_POU,
    CONVEX_HULL_CANVAS_PURE_ST_POU,
    CONVEX_HULL_PURE_ST_POU,
    verify_convex_hull_canvas_pure_st,
    # Verification Suite
    run_convex_hull_verification,
    run_convex_hull_canvas_verification,
)


# ============================================================================
# 1. Diagnostic Codes Signed/Unsigned 16-Bit Values & Representations
# ============================================================================

class TestDiagnosticCodesSignedUnsigned:
    """Validate 16-bit diagnostic codes (0x0000, 0xEE77, 0xEE78), signed/unsigned values, and formats."""

    def test_diagnostic_code_values_and_representations(self) -> None:
        """Verify signed and unsigned 16-bit values and string representations."""
        # 0x0000 OK
        assert DIAG_OK == 0x0000
        assert DIAG_EVENT_OK == 0x0000
        assert NOMINAL_OK == 0x0000
        assert CONVEX_HULL_OK == 0x0000
        assert CONVEX_HULL_CANVAS_OK == 0x0000
        assert int(DIAG_OK) == 0
        assert f"0x{int(DIAG_OK) & 0xFFFF:04X}" == "0x0000"

        # 0xEE77 Boundary Breach Alarm
        assert BOUNDARY_BREACH_ALARM == 0xEE77
        assert BOUNDARY_BREACH_FAULT == 0xEE77
        assert DIAG_ERR_BOUNDARY_BREACH == 0xEE77
        assert DIAG_ERR_BOUNDARY_BREACH_ALARM == 0xEE77
        assert int(BOUNDARY_BREACH_ALARM) == 61047
        assert f"0x{int(BOUNDARY_BREACH_ALARM) & 0xFFFF:04X}" == "0xEE77"

        # 0xEE78 Degenerate Set Fault (< 3 unique points)
        assert DEGENERATE_SET_FAULT == 0xEE78
        assert DEGENERATE_POINTS_FAULT == 0xEE78
        assert DIAG_ERR_DEGENERATE_SET == 0xEE78
        assert DIAG_ERR_DEGENERATE_POINTS == 0xEE78
        assert int(DEGENERATE_SET_FAULT) == 61048
        assert f"0x{int(DEGENERATE_SET_FAULT) & 0xFFFF:04X}" == "0xEE78"

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

        # Hashing and container behavior
        diag_set: Set[DiagnosticCode] = {
            DIAG_OK,
            BOUNDARY_BREACH_ALARM,
            DEGENERATE_SET_FAULT,
        }
        assert len(diag_set) == 3
        assert DiagnosticCode(0xEE77) in diag_set
        assert DiagnosticCode(0xEE78) in diag_set
        assert DiagnosticCode(0x0000) in diag_set


# ============================================================================
# 2. Register and Coil Mappings (%R2370..%R2377, %M553..%M554)
# ============================================================================

class TestRegisterAndCoilMappings:
    """Validate register mappings (%R2370..%R2377) and coil mappings (%M553..%M554)."""

    def test_w276_analog_word_registers(self) -> None:
        """Verify %R2370..%R2377 primary register assignments and aliases."""
        assert REG_W276_STATUS_WORD == "%R2370"
        assert REG_W276_TOTAL_POINTS == "%R2371"
        assert REG_W276_ACTIVE_CLUSTERS == "%R2372"
        assert REG_W276_MAX_PERIMETER == "%R2373"
        assert REG_W276_MAX_DISPERSION == "%R2374"
        assert REG_W276_MIN_DISTANCE == "%R2375"
        assert REG_W276_OUTLIER_COUNT == "%R2376"
        assert REG_W276_DIAGNOSTIC_CODE == "%R2377"
        assert REG_W276_CRITICAL_ZONE == "%R2377"

        # Compatibility aliases
        assert REG_CONVEX_HULL_STATUS_WORD == "%R2370"
        assert REG_CONVEX_HULL_TOTAL_POINTS == "%R2371"
        assert REG_CONVEX_HULL_ACTIVE_CLUSTERS == "%R2372"
        assert REG_CONVEX_HULL_MAX_PERIMETER == "%R2373"
        assert REG_CONVEX_HULL_MAX_DISPERSION == "%R2374"
        assert REG_CONVEX_HULL_MIN_DISTANCE == "%R2375"
        assert REG_CONVEX_HULL_OUTLIER_COUNT == "%R2376"
        assert REG_CONVEX_HULL_DIAGNOSTIC_CODE == "%R2377"
        assert REG_CONVEX_HULL_CRITICAL_ZONE == "%R2377"

    def test_w276_discrete_coils(self) -> None:
        """Verify %M553..%M554 discrete coils and aliases."""
        assert COIL_W276_CANVAS_ACTIVE == "%M553"
        assert COIL_W276_BOUNDARY_BREACH == "%M554"
        assert COIL_CONVEX_HULL_CANVAS_ACTIVE == "%M553"
        assert COIL_BOUNDARY_BREACH_ALARM == "%M554"
        assert COIL_CONVEX_HULL_BOUNDARY_BREACH == "%M554"

    def test_legacy_register_backward_compatibility(self) -> None:
        """Verify legacy W201 and W102 registers are preserved for dual-write compatibility."""
        assert REG_W201_STATUS_WORD == "%R1620"
        assert REG_W201_TOTAL_POINTS == "%R1621"
        assert REG_W201_ACTIVE_CLUSTERS == "%R1622"
        assert REG_W201_MAX_PERIMETER == "%R1623"
        assert REG_W201_MAX_DISPERSION == "%R1624"
        assert REG_W201_MIN_DISTANCE == "%R1625"
        assert REG_W201_OUTLIER_COUNT == "%R1626"
        assert REG_W201_CRITICAL_ZONE == "%R1627"
        assert COIL_W201_DISPERSION_ALARM == "%M378"
        assert COIL_W201_OUTLIER_DETECTED == "%M379"

        assert REG_W102_STATUS_WORD == "%R630"
        assert REG_W102_TOTAL_POINTS == "%R631"
        assert COIL_W102_DISPERSION_ALARM == "%M147"
        assert COIL_W102_OUTLIER_DETECTED == "%M148"

    def test_status_bits_definitions(self) -> None:
        """Verify HullCanvasStatusBits definitions including W276 additions."""
        assert HullCanvasStatusBits.CANVAS_ACTIVE == 1 << 0
        assert HullCanvasStatusBits.CLUSTERS_ENCLOSED == 1 << 1
        assert HullCanvasStatusBits.DISPERSION_ALARM == 1 << 2
        assert HullCanvasStatusBits.OUTLIER_DETECTED == 1 << 3
        assert HullCanvasStatusBits.CLUSTER_OVERLAP_WARNING == 1 << 4
        assert HullCanvasStatusBits.HIGH_PERIMETER_WARNING == 1 << 5
        assert HullCanvasStatusBits.SVG_RENDER_VALID == 1 << 6
        assert HullCanvasStatusBits.EMERGENCY_ISOLATION_ACTIVE == 1 << 7
        assert HullCanvasStatusBits.BOUNDARY_BREACH_ALARM == 1 << 8
        assert HullCanvasStatusBits.DEGENERATE_SET_FAULT == 1 << 9


# ============================================================================
# 3. 2D Point Geometries, Cross-Product Calculations & Sorting
# ============================================================================

class TestPointGeometriesAndCrossProductCalculations:
    """Validate 2D Point structures, cross-product calculations, and collinearity detection."""

    def test_scatter_point_initialization(self) -> None:
        """Verify ScatterPoint dataclass fields, coordinates, and default values."""
        p = ScatterPoint(point_id="P01", x=120.5, y=340.2, value=42.7)
        assert p.point_id == "P01"
        assert math.isclose(p.x, 120.5)
        assert math.isclose(p.y, 340.2)
        assert math.isclose(p.value, 42.7)
        assert p.is_outlier is False
        assert p.distance_to_centroid == 0.0

    def test_cross_product_counter_clockwise_turn(self) -> None:
        """Verify cross product OA x OB > 0 for strict counter-clockwise turn."""
        o = (0.0, 0.0)
        a = (10.0, 0.0)
        b = (5.0, 10.0)
        cp = cross_product_2d(o, a, b)
        assert cp > 0.0
        assert math.isclose(cp, 100.0)

    def test_cross_product_clockwise_turn(self) -> None:
        """Verify cross product OA x OB < 0 for strict clockwise turn."""
        o = (0.0, 0.0)
        a = (0.0, 10.0)
        b = (10.0, 5.0)
        cp = cross_product_2d(o, a, b)
        assert cp < 0.0
        assert math.isclose(cp, -100.0)

    def test_cross_product_collinear_zero(self) -> None:
        """Verify cross product OA x OB == 0 for strictly collinear points."""
        o = (0.0, 0.0)
        a = (5.0, 5.0)
        b = (15.0, 15.0)
        cp = cross_product_2d(o, a, b)
        assert math.isclose(cp, 0.0, abs_tol=1e-12)

    def test_point_to_segment_distance_orthogonal(self) -> None:
        """Verify point-to-segment distance when point projects orthogonally onto segment."""
        a = (0.0, 0.0)
        b = (10.0, 0.0)
        p = (5.0, 4.0)
        dist = point_to_segment_distance(p, a, b)
        assert math.isclose(dist, 4.0)

    def test_point_to_segment_distance_clamped(self) -> None:
        """Verify point-to-segment distance clamps to endpoints outside segment bounds."""
        a = (0.0, 0.0)
        b = (10.0, 0.0)
        p = (15.0, 0.0)
        dist = point_to_segment_distance(p, a, b)
        assert math.isclose(dist, 5.0)

    def test_point_to_segment_distance_coincident_endpoints(self) -> None:
        """Verify point-to-segment distance handles degenerate zero-length segment."""
        a = (3.0, 4.0)
        b = (3.0, 4.0)
        p = (0.0, 0.0)
        dist = point_to_segment_distance(p, a, b)
        assert math.isclose(dist, 5.0)


# ============================================================================
# 4. Convex Hull Algorithm on Standard Shapes & Collinear Sets
# ============================================================================

class TestConvexHullAlgorithmsMonotoneAndGraham:
    """Validate Andrew's Monotone Chain and Graham Scan algorithms across diverse point distributions."""

    def test_convex_hull_square_with_interior_points(self) -> None:
        """Verify convex hull extracts exact 4 square vertices while filtering interior points."""
        pts: List[PointTuple] = [
            (0.0, 0.0), (100.0, 0.0), (100.0, 100.0), (0.0, 100.0),
            (50.0, 50.0), (20.0, 30.0), (80.0, 70.0), (10.0, 90.0),
        ]
        hull_mono = compute_convex_hull_2d(pts)
        hull_graham = compute_graham_scan_2d(pts)

        assert len(hull_mono) == 4
        expected_vertices = {(0.0, 0.0), (100.0, 0.0), (100.0, 100.0), (0.0, 100.0)}
        assert set(hull_mono) == expected_vertices
        assert set(hull_graham) == expected_vertices

    def test_convex_hull_right_triangle_with_interior_points(self) -> None:
        """Verify convex hull extracts 3 triangle vertices while filtering interior points."""
        pts: List[PointTuple] = [
            (0.0, 0.0), (60.0, 0.0), (0.0, 80.0),
            (10.0, 10.0), (20.0, 20.0), (15.0, 30.0),
        ]
        hull = compute_convex_hull_2d(pts)
        assert len(hull) == 3
        assert set(hull) == {(0.0, 0.0), (60.0, 0.0), (0.0, 80.0)}

    def test_convex_hull_collinear_subset(self) -> None:
        """Verify collinear points along an edge: only extreme endpoints are retained."""
        pts: List[PointTuple] = [
            (0.0, 0.0), (25.0, 0.0), (50.0, 0.0), (75.0, 0.0), (100.0, 0.0),
            (50.0, 50.0),
        ]
        hull = compute_convex_hull_2d(pts)
        assert len(hull) == 3
        assert (50.0, 0.0) not in hull
        assert (25.0, 0.0) not in hull
        assert (75.0, 0.0) not in hull
        assert set(hull) == {(0.0, 0.0), (100.0, 0.0), (50.0, 50.0)}

    def test_convex_hull_duplicate_points_handling(self) -> None:
        """Verify duplicated points are deduplicated without generating zero-length edges."""
        pts: List[PointTuple] = [
            (10.0, 10.0), (10.0, 10.0), (10.0, 10.0),
            (50.0, 10.0), (50.0, 10.0),
            (30.0, 40.0), (30.0, 40.0),
        ]
        hull = compute_convex_hull_2d(pts)
        assert len(hull) == 3
        assert set(hull) == {(10.0, 10.0), (50.0, 10.0), (30.0, 40.0)}

    def test_graham_scan_equivalence_to_monotone_chain(self) -> None:
        """Verify Graham Scan and Monotone Chain algorithms produce identical vertex sets."""
        pts: List[PointTuple] = [
            (15.0, 25.0), (45.0, 10.0), (80.0, 30.0), (95.0, 70.0),
            (60.0, 90.0), (20.0, 75.0), (50.0, 50.0), (40.0, 60.0),
        ]
        hull_mono = compute_convex_hull_2d(pts)
        hull_graham = compute_graham_scan_2d(pts)
        assert set(hull_mono) == set(hull_graham)


# ============================================================================
# 5. Degenerate Set Handling (< 3 Unique Points -> 0xEE78)
# ============================================================================

class TestDegenerateSetHandling:
    """Validate handling of degenerate point sets (< 3 unique points -> 0xEE78)."""

    def test_degenerate_empty_set(self) -> None:
        """Verify empty point set returns empty hull without raising exceptions."""
        assert compute_convex_hull_2d([]) == []
        assert compute_graham_scan_2d([]) == []

    def test_degenerate_single_point(self) -> None:
        """Verify single point returns 1-element list."""
        pt = [(10.0, 20.0)]
        assert compute_convex_hull_2d(pt) == pt
        assert compute_graham_scan_2d(pt) == pt

    def test_degenerate_two_points(self) -> None:
        """Verify two points return 2-element segment list."""
        pts = [(10.0, 20.0), (30.0, 40.0)]
        assert compute_convex_hull_2d(pts) == sorted(pts)
        assert compute_graham_scan_2d(pts) == pts

    def test_degenerate_set_triggers_0xee78_in_engine(self) -> None:
        """Verify engine detects < 3 points, asserts 0xEE78 and sets status bit."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)

        # Clear clusters to create degenerate state
        for c in engine.clusters.values():
            c.points = []

        # Add only 2 points total
        engine.clusters[1].points = [
            ScatterPoint("D01", 100.0, 100.0),
            ScatterPoint("D02", 150.0, 150.0),
        ]
        engine.update_analytics()

        assert engine.degenerate_set is True
        assert engine.diagnostic_code == DEGENERATE_SET_FAULT
        assert engine.diagnostic_code == 0xEE78
        assert bool(engine.reg_table.read_word(REG_W276_STATUS_WORD) & int(HullCanvasStatusBits.DEGENERATE_SET_FAULT))
        assert engine.reg_table.read_uword(REG_W276_DIAGNOSTIC_CODE) == 0xEE78


# ============================================================================
# 6. Shoelace Area Calculation and Perimeter Summation
# ============================================================================

class TestShoelaceAreaAndPerimeterSummation:
    """Validate Green's theorem Shoelace area and Euclidean perimeter summation."""

    def test_shoelace_area_square(self) -> None:
        """Verify 100x100 square has analytical area 10,000 px^2."""
        poly: List[PointTuple] = [(0.0, 0.0), (100.0, 0.0), (100.0, 100.0), (0.0, 100.0)]
        area = compute_shoelace_area(poly)
        assert math.isclose(area, 10000.0)

    def test_shoelace_area_triangle(self) -> None:
        """Verify right triangle (base=60, height=80) has analytical area 2,400 px^2."""
        poly: List[PointTuple] = [(0.0, 0.0), (60.0, 0.0), (0.0, 80.0)]
        area = compute_shoelace_area(poly)
        assert math.isclose(area, 2400.0)

    def test_shoelace_area_degenerate(self) -> None:
        """Verify degenerate polygons (< 3 vertices) return zero area."""
        assert compute_shoelace_area([]) == 0.0
        assert compute_shoelace_area([(10.0, 10.0)]) == 0.0
        assert compute_shoelace_area([(10.0, 10.0), (20.0, 20.0)]) == 0.0

    def test_perimeter_square(self) -> None:
        """Verify 100x100 square has analytical perimeter 400 px."""
        poly: List[PointTuple] = [(0.0, 0.0), (100.0, 0.0), (100.0, 100.0), (0.0, 100.0)]
        perim = compute_polygon_perimeter(poly)
        assert math.isclose(perim, 400.0)

    def test_perimeter_degenerate(self) -> None:
        """Verify degenerate polygons (< 2 vertices) return zero perimeter."""
        assert compute_polygon_perimeter([]) == 0.0
        assert compute_polygon_perimeter([(10.0, 10.0)]) == 0.0

    def test_outward_minkowski_padding_expands_area(self) -> None:
        """Verify outward Minkowski vertex expansion strictly increases polygon area."""
        poly: List[PointTuple] = [(0.0, 0.0), (100.0, 0.0), (100.0, 100.0), (0.0, 100.0)]
        orig_area = compute_shoelace_area(poly)
        padded = compute_outward_padded_polygon(poly, padding=10.0)
        padded_area = compute_shoelace_area(padded)

        assert len(padded) == len(poly)
        assert padded_area > orig_area

    def test_outward_minkowski_padding_degenerate(self) -> None:
        """Verify outward padding on degenerate polygons returns input untouched."""
        poly: List[PointTuple] = [(0.0, 0.0), (10.0, 10.0)]
        assert compute_outward_padded_polygon(poly, padding=10.0) == poly


# ============================================================================
# 7. Centroid Calculation & Dispersion Radius
# ============================================================================

class TestCentroidCalculationAndDispersionRadius:
    """Validate center-of-mass centroid, variance (sigma_x, sigma_y), and dispersion radius R_rms."""

    def test_cluster_centroid_center_of_mass(self) -> None:
        """Verify symmetrical points yield exact expected centroid."""
        pts = [
            ScatterPoint("P1", 100.0, 100.0),
            ScatterPoint("P2", 200.0, 100.0),
            ScatterPoint("P3", 200.0, 200.0),
            ScatterPoint("P4", 100.0, 200.0),
        ]
        cluster = ProcessCluster(zone_id=1, name="Test", color_hex="#3B82F6", points=pts)
        cluster.compute_metrics()

        assert math.isclose(cluster.centroid[0], 150.0)
        assert math.isclose(cluster.centroid[1], 150.0)

    def test_cluster_variance_and_dispersion_rms(self) -> None:
        """Verify dispersion radius R_rms equals sqrt(variance_total)."""
        pts = [
            ScatterPoint("P1", 120.0, 150.0),
            ScatterPoint("P2", 180.0, 150.0),
            ScatterPoint("P3", 150.0, 120.0),
            ScatterPoint("P4", 150.0, 180.0),
        ]
        cluster = ProcessCluster(zone_id=1, name="Test", color_hex="#3B82F6", points=pts)
        cluster.compute_metrics()

        assert cluster.variance_total > 0.0
        assert math.isclose(cluster.dispersion_rms, math.sqrt(cluster.variance_total))
        assert math.isclose(cluster.variance_total, cluster.variance_x + cluster.variance_y)

    def test_inter_cluster_distance_between_centroids(self) -> None:
        """Verify minimum Euclidean distance between cluster centroids."""
        engine = ConvexHullCanvasEngine()
        min_d = engine.get_min_inter_cluster_distance()
        assert min_d > 0.0
        assert not math.isinf(min_d)

    def test_empty_cluster_resets_metrics(self) -> None:
        """Verify empty cluster resets all metrics to zero nominal values."""
        cluster = ProcessCluster(zone_id=1, name="Empty", color_hex="#3B82F6", points=[])
        cluster.compute_metrics()
        assert cluster.centroid == (0.0, 0.0)
        assert cluster.dispersion_rms == 0.0
        assert cluster.variance_total == 0.0
        assert cluster.hull_area == 0.0
        assert cluster.hull_perimeter == 0.0


# ============================================================================
# 8. Boundary Breach Detection (Inside vs Outside, Alarm %M554 and 0xEE77)
# ============================================================================

class TestBoundaryBreachDetectionAndContainment:
    """Validate ray-casting and winding number containment, signed distance, and %M554 alarm."""

    def test_point_in_polygon_ray_casting(self) -> None:
        """Verify ray-casting containment algorithm for interior and exterior points."""
        poly: List[PointTuple] = [(100.0, 100.0), (300.0, 100.0), (300.0, 300.0), (100.0, 300.0)]
        assert is_point_in_polygon((200.0, 200.0), poly) is True
        assert is_point_in_polygon((50.0, 200.0), poly) is False
        assert is_point_in_polygon((400.0, 400.0), poly) is False

    def test_point_in_polygon_winding_number(self) -> None:
        """Verify winding number algorithm detects interior points."""
        poly: List[PointTuple] = [(100.0, 100.0), (300.0, 100.0), (300.0, 300.0), (100.0, 300.0)]
        assert winding_number_2d((200.0, 200.0), poly) != 0
        assert winding_number_2d((50.0, 200.0), poly) == 0
        assert is_point_in_polygon_winding((200.0, 200.0), poly) is True
        assert is_point_in_polygon_winding((50.0, 200.0), poly) is False

    def test_signed_distance_to_polygon(self) -> None:
        """Verify signed distance convention: negative inside, positive outside."""
        poly: List[PointTuple] = [(100.0, 100.0), (300.0, 100.0), (300.0, 300.0), (100.0, 300.0)]
        d_in = signed_distance_to_polygon((200.0, 200.0), poly)
        d_out = signed_distance_to_polygon((400.0, 200.0), poly)

        assert d_in < 0.0
        assert d_out > 0.0
        assert math.isclose(d_out, 100.0)

    def test_boundary_breach_detection_triggers_0xee77_and_m554(self) -> None:
        """Verify breach detection triggers 0xEE77 and asserts alarm coil %M554."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)

        # Initially nominal
        assert engine.boundary_breach is False
        assert engine.diagnostic_code == DIAG_OK
        assert reg.read_bit(COIL_W276_BOUNDARY_BREACH) is False

        # Test point outside all cluster envelopes
        breach = engine.check_boundary_breach(test_point=(50.0, 50.0), zone_id=1)
        assert breach is True
        assert engine.boundary_breach is True
        assert engine.diagnostic_code == BOUNDARY_BREACH_ALARM
        assert engine.diagnostic_code == 0xEE77
        assert reg.read_bit(COIL_W276_BOUNDARY_BREACH) is True
        assert reg.read_uword(REG_W276_DIAGNOSTIC_CODE) == 0xEE77

    def test_boundary_breach_detection_inside_nominal(self) -> None:
        """Verify testing a point strictly inside cluster returns nominal 0x0000."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)
        z1_centroid = engine.clusters[1].centroid

        breach = engine.check_boundary_breach(test_point=z1_centroid, zone_id=1)
        assert breach is False
        assert engine.boundary_breach is False
        assert engine.diagnostic_code == DIAG_OK
        assert reg.read_bit(COIL_W276_BOUNDARY_BREACH) is False


# ============================================================================
# 9. Standalone W3C SVG 1.1 Generation & WCAG 2.1 AAA Compliance
# ============================================================================

class TestHighContrastSvgGenerationAndWcagCompliance:
    """Validate standalone W3C SVG 1.1 XML markup, polygons, markers, and WCAG contrast."""

    def test_svg_xml_structure_and_dimensions(self) -> None:
        """Verify SVG output is well-formed XML with 1200x750 viewport dimensions."""
        engine = ConvexHullCanvasEngine()
        svg_str = engine.render_svg()

        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg") or root.tag == "svg"
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"
        assert root.attrib["viewBox"] == "0 0 1200 750"

    def test_svg_contains_polygon_points_and_node_markers(self) -> None:
        """Verify SVG contains polygon elements for hulls and circle markers for scatter points."""
        engine = ConvexHullCanvasEngine()
        svg_str = engine.render_svg()

        assert "<polygon points=" in svg_str
        assert "<circle cx=" in svg_str
        assert "<line x1=" in svg_str
        assert "<text" in svg_str
        assert "<defs>" in svg_str

    def test_wcag_aaa_contrast_decoupled_badge_exceeds_18_to_1(self) -> None:
        """Verify decoupled dark badge contrast (COLOR_TEXT_PRIMARY on COLOR_DECOUPLED_BADGE) >= 18.0:1."""
        contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert contrast > 18.0

    def test_wcag_aaa_contrast_primary_text_exceeds_7_to_1(self) -> None:
        """Verify primary text on dark surface >= 7.0:1."""
        contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_SURFACE)
        assert contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET

    def test_wcag_graphical_contrast_accents_exceed_3_to_1(self) -> None:
        """Verify plant zone color accents against dark theme backing >= 3.0:1."""
        blue_c = calculate_contrast_ratio(COLOR_FEED_CONDITIONING_BLUE, COLOR_DARK_THEME_BACKING)
        emerald_c = calculate_contrast_ratio(COLOR_REACTION_SYNTHESIS_EMERALD, COLOR_DARK_THEME_BACKING)
        amber_c = calculate_contrast_ratio(COLOR_SEPARATION_POLISHING_AMBER, COLOR_DARK_THEME_BACKING)

        assert blue_c >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert emerald_c >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert amber_c >= WCAG_GRAPHICAL_CONTRAST_TARGET

    def test_generate_convex_hull_canvas_svg_helper(self) -> None:
        """Verify generate_convex_hull_canvas_svg helper creates valid SVG."""
        svg = generate_convex_hull_canvas_svg()
        assert svg.startswith("<?xml")
        root = ET.fromstring(svg)
        assert root is not None


# ============================================================================
# 10. Process Safety Diagnostics & Statistical Outlier Alerts
# ============================================================================

class TestProcessSafetyDiagnosticsAndAlarms:
    """Validate statistical outlier detection (> 2.5 * R_rms), alarm assertions, and zone tracking."""

    def test_statistical_outlier_detection_and_alarm(self) -> None:
        """Verify process point exceeding 2.5 * R_rms is flagged as outlier and triggers alarm."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)

        # Add extreme outlier point
        outlier = ScatterPoint(point_id="OUT_99", x=500.0, y=500.0, value=99.9)
        res = engine.add_point(zone_id=1, point=outlier)

        assert res.status == AgentStatus.SUCCESS
        assert outlier.is_outlier is True
        assert engine.get_total_outlier_count() >= 1
        assert engine.boundary_breach is True
        assert engine.diagnostic_code == BOUNDARY_BREACH_ALARM
        assert reg.read_bit(COIL_W276_BOUNDARY_BREACH) is True

    def test_cluster_overlap_warning_bit(self) -> None:
        """Verify cluster overlap generates CLUSTER_OVERLAP_WARNING status bit."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg, min_cluster_sep_limit=800.0)
        # Normal clusters are ~400px apart, which is < 800px threshold
        engine.update_analytics()
        status = reg.read_word(REG_W276_STATUS_WORD)
        assert bool(status & int(HullCanvasStatusBits.CLUSTER_OVERLAP_WARNING))

    def test_high_perimeter_warning_bit(self) -> None:
        """Verify perimeter exceeding 1200px asserts HIGH_PERIMETER_WARNING bit."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)

        # Expand cluster 1 far outwards to exceed 1200px perimeter
        engine.clusters[1].points.extend([
            ScatterPoint("EXP1", 0.0, 0.0),
            ScatterPoint("EXP2", 600.0, 0.0),
            ScatterPoint("EXP3", 600.0, 600.0),
            ScatterPoint("EXP4", 0.0, 600.0),
        ])
        engine.update_analytics()
        status = reg.read_word(REG_W276_STATUS_WORD)
        assert bool(status & int(HullCanvasStatusBits.HIGH_PERIMETER_WARNING))

    def test_critical_zone_identification(self) -> None:
        """Verify get_critical_zone_id returns zone ID containing the active outlier."""
        engine = ConvexHullCanvasEngine()
        outlier = ScatterPoint("OUT_Z2", x=900.0, y=900.0)
        engine.add_point(zone_id=2, point=outlier)
        assert engine.get_critical_zone_id() == 2


# ============================================================================
# 11. ILogicUnit Interface Compliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance (scan_step, execute, reset)."""

    def test_ilogicunit_protocol_interface(self) -> None:
        """Verify ConvexHullCanvasEngine implements ILogicUnit protocol."""
        engine = ConvexHullCanvasEngine()
        assert isinstance(engine, ILogicUnit)

    def test_ilogicunit_properties(self) -> None:
        """Verify name, priority, and is_enabled properties."""
        engine = ConvexHullCanvasEngine()
        assert engine.name == "ConvexHullCanvasEngine"
        assert engine.priority == 88
        assert engine.is_enabled is True

    def test_scan_step_and_step_advancement(self) -> None:
        """Verify scan_step and step alias increment cycle count."""
        engine = ConvexHullCanvasEngine()
        res1 = engine.scan_step(dt=0.01)
        assert res1["cycle"] == 1
        assert engine._cycle_count == 1

        engine.step()
        assert engine._cycle_count == 2

    def test_execute_with_scan_context(self) -> None:
        """Verify execute(context) runs scan cycle using ScanContext."""
        engine = ConvexHullCanvasEngine()
        ctx = create_mock_scan_context(cycle=1, dt_ms=20.0, reg_table=engine.reg_table)
        engine.execute(ctx)
        assert engine._cycle_count == 1

    def test_reset_restores_nominal_state(self) -> None:
        """Verify reset restores default cluster configuration and clears alarms."""
        engine = ConvexHullCanvasEngine()
        outlier = ScatterPoint("OUT_RESET", x=600.0, y=600.0)
        engine.add_point(zone_id=1, point=outlier)
        assert engine.boundary_breach is True

        engine.reset()
        assert engine._cycle_count == 0
        assert engine.boundary_breach is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.get_total_outlier_count() == 0


# ============================================================================
# 12. RegisterTable Synchronization (%R2370..%R2377, %M553..%M554)
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate RegisterTable synchronization (%R2370..%R2377, %M553..%M554) with PrivilegeMode.SYSTEM."""

    def test_w276_analog_registers_nominal_synchronization(self) -> None:
        """Verify analog registers %R2370..%R2377 in nominal operating state."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)
        engine.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word(REG_W276_TOTAL_POINTS) == 24  # 8 * 3 clusters
        assert reg.read_word(REG_W276_ACTIVE_CLUSTERS) == 3
        assert reg.read_word(REG_W276_MAX_PERIMETER) > 0
        assert reg.read_word(REG_W276_MAX_DISPERSION) > 0
        assert reg.read_word(REG_W276_MIN_DISTANCE) > 0
        assert reg.read_word(REG_W276_OUTLIER_COUNT) == 0
        assert reg.read_word(REG_W276_DIAGNOSTIC_CODE) == 0

    def test_w276_discrete_coils_nominal_synchronization(self) -> None:
        """Verify discrete coils %M553 and %M554 in nominal state."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)
        engine.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit(COIL_W276_CANVAS_ACTIVE) is True
        assert reg.read_bit(COIL_W276_BOUNDARY_BREACH) is False

    def test_w276_breach_asserts_coil_m554_and_diagnostic(self) -> None:
        """Verify breach sets %M554 to True and %R2377 to 0xEE77."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)
        engine.check_boundary_breach(test_point=(10.0, 10.0))

        assert reg.read_bit(COIL_W276_BOUNDARY_BREACH) is True
        assert reg.read_uword(REG_W276_DIAGNOSTIC_CODE) == 0xEE77

    def test_dual_write_w201_and_w102_backward_compatibility(self) -> None:
        """Verify legacy %R1620..%R1627 and %R630..%R637 are synchronized concurrently."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)

        assert reg.read_word(REG_W201_TOTAL_POINTS) == 24
        assert reg.read_word(REG_W102_TOTAL_POINTS) == 24
        assert reg.read_bit(COIL_W201_DISPERSION_ALARM) is False
        assert reg.read_bit(COIL_W102_DISPERSION_ALARM) is False

    def test_fifty_step_scan_cycle_soak_stability(self) -> None:
        """Verify 50 consecutive scan cycles execute without NaN values, memory leaks, or drift."""
        reg = RegisterTable()
        engine = ConvexHullCanvasEngine(register_table=reg)
        ctx = create_mock_scan_context(cycle=0, dt_ms=20.0, reg_table=reg)

        for step in range(50):
            ctx.cycle = step + 1
            engine.scan_step(dt=0.02)
            assert not math.isnan(engine.get_max_dispersion_rms())
            assert not math.isnan(engine.get_max_hull_perimeter())
            assert engine.diagnostic_code == DIAG_OK
            assert reg.read_bit(COIL_W276_CANVAS_ACTIVE) is True
            assert reg.read_bit(COIL_W276_BOUNDARY_BREACH) is False


# ============================================================================
# 13. Pure IEC 61131-3 ST POU Validation
# ============================================================================

class TestPureStPouValidation:
    """Validate Pure ST POU syntax, AST parsing, and register bindings."""

    def test_w276_pure_st_pou_syntax_and_ast_parsing(self) -> None:
        """Verify W276 ST POU passes SecurityGuard and STParser cleanly."""
        SecurityGuard.assert_pure_st_content(W276_CONVEX_HULL_PURE_ST_POU)
        res = STParser.validate_code(W276_CONVEX_HULL_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(W276_CONVEX_HULL_PURE_ST_POU)
        assert ast.name == "ConvexHullClusterSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_w276_pure_st_bound_registers_r2370_to_r2377(self) -> None:
        """Verify analog registers %R2370..%R2377 are strictly bound in POU AST."""
        ast = STParser.parse_pou(W276_CONVEX_HULL_PURE_ST_POU)
        expected = [
            "%R2370", "%R2371", "%R2372", "%R2373",
            "%R2374", "%R2375", "%R2376", "%R2377",
        ]
        for reg in expected:
            assert reg in ast.bound_registers, f"Register {reg} missing from AST bound registers."

    def test_w276_pure_st_bound_coils_m553_and_m554(self) -> None:
        """Verify discrete coils %M553 and %M554 are bound in POU AST."""
        ast = STParser.parse_pou(W276_CONVEX_HULL_PURE_ST_POU)
        assert "%M553" in ast.bound_registers
        assert "%M554" in ast.bound_registers

    def test_pure_st_validator_function(self) -> None:
        """Verify verify_convex_hull_canvas_pure_st() helper returns True."""
        assert verify_convex_hull_canvas_pure_st() is True

    def test_legacy_w201_and_w102_pous_validate(self) -> None:
        """Verify legacy W201 and W102 POUs also validate cleanly."""
        assert verify_convex_hull_canvas_pure_st(W201_CONVEX_HULL_PURE_ST_POU) is True
        assert verify_convex_hull_canvas_pure_st(W102_CONVEX_HULL_PURE_ST_POU) is True


# ============================================================================
# 14. Anti-Ladder Construct Rejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Validate aggressive interception and rejection of ladder logic constructs."""

    def test_ladder_contacts_rejection(self) -> None:
        """Verify contacts construct '---[ ]---' and '---[/]---' are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR X: BOOL; END_VAR ---[/]--- END_PROGRAM")

    def test_ladder_coils_rejection(self) -> None:
        """Verify coils construct '---( )---', '---(S)---', '---(R)---' are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR Y: BOOL; END_VAR ---(S)--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR Y: BOOL; END_VAR ---(R)--- END_PROGRAM")

    def test_ladder_rung_delimiters_rejection(self) -> None:
        """Verify RUNG and NETWORK delimiters are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nRUNG 1:\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nNETWORK 1:\nEND_PROGRAM")

    def test_ladder_mnemonics_rejection(self) -> None:
        """Verify mnemonics XIC, XIO, OTE, OTL, OTU are rejected with LadderForbiddenError."""
        for mnem in ["XIC InBit;", "XIO InBit;", "OTE OutBit;", "OTL OutBit;", "OTU OutBit;"]:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(f"PROGRAM Test\n{mnem}\nEND_PROGRAM")


# ============================================================================
# 15. Verification Suite Runner
# ============================================================================

class TestDeterministicVerificationRunner:
    """Validate complete deterministic 9-stage verification suite."""

    def test_runner_returns_strict_4_state_success(self) -> None:
        """Verify run_convex_hull_canvas_verification returns success and 9/9 stages pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_p = Path(tmpdir) / "sample.svg"

            res = run_convex_hull_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_p),
                work_package="W276",
            )

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
            assert res["data"]["work_package"] == "W276"
            assert ev_path.is_file()
            assert svg_p.is_file()

    def test_runner_w201_work_package_compatibility(self) -> None:
        """Verify runner executes cleanly under legacy W201 work package."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "w201_evidence.json"
            res = run_convex_hull_canvas_verification(
                output_path=str(ev_path),
                work_package="W201",
            )
            assert res["status"] == "success"
            assert res["data"]["work_package"] == "W201"
