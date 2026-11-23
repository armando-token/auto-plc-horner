"""Comprehensive unit test suite for Cscape HMI Dynamic Delaunay-Voronoi Dual Mesh SCADA Canvas (W267).

Work Package: W267 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Delaunay-Voronoi Dual Mesh Triangulation SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Must test:
- Diagnostic codes signed/unsigned 16-bit values and string representations (0x0000, 0x7901, 0x7902)
- Register and coil mappings (%R2280..%R2287, %M532..%M533)
- Bowyer-Watson Delaunay triangulation circumcircle math and empty-circumcircle criterion
- Voronoi dual polygonal cell extraction and area conservation
- Barycentric interpolation of scalar fields and maximum gradient tracking
- SVG markup generation, XML validity, polygons, lines, points, and labels
- WCAG 2.1 AAA contrast compliance (>= 18:1 decoupled badges, >= 7:1 text, >= 3:1 graphics)
- Colinear degeneracy trip 0x7901 and boundary polygon fault 0x7902
- Field gradient alarm coil %M533 assertion
- Horner OCS register synchronization and 50-step scan cycle soak stability
- Pure ST POU validation with STParser and SecurityGuard (AST variable memory_address)
- Anti-ladder construct rejection
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Set
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.delaunay_voronoi_canvas import (
    # Diagnostic Codes
    DIAG_OK,
    DIAG_EVENT_OK,
    DELAUNAY_CANVAS_OK,
    DIAG_ERR_COLINEAR_DEGENERACY_TRIP,
    COLINEAR_DEGENERACY_TRIP,
    COLINEAR_DEGENERACY_FAULT,
    DIAG_ERR_COLINEAR_DEGENERACY,
    DIAG_ERR_DELAUNAY_COPLANARITY_DEGENERATE,
    DELAUNAY_COPLANARITY_DEGENERATE,
    DIAG_ERR_BOUNDARY_POLYGON_FAULT,
    BOUNDARY_POLYGON_FAULT,
    BOUNDARY_POLYGON_TRIP,
    DIAG_ERR_BOUNDARY_POLYGON,
    DIAG_ERR_SVG_RENDER_FAULT,
    SVG_RENDER_FAULT,
    DIAG_ERR_RENDER_FAULT,
    DIAG_ERR_THERMAL_GRADIENT_EXCEEDED,
    THERMAL_GRADIENT_EXCEEDED,
    DIAG_ERR_SENSOR_MESH_DISCONNECTION,
    SENSOR_MESH_DISCONNECTION,
    DiagnosticCode,
    # Register Definitions & Aliases
    REG_PEAK_GRADIENT_MAGNITUDE_SCALED,
    REG_MAX_THERMAL_STRESS_CELL_ID,
    REG_ACTIVE_SENSOR_NODE_COUNT,
    REG_TRIANGULATION_MESH_FACE_COUNT,
    REG_VORONOI_CELL_AREA_VARIANCE_SCALED,
    REG_SPATIAL_INTERPOLATION_QUALITY_PCT_SCALED,
    REG_SELECTED_SENSOR_INDEX,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_W267_PEAK_GRADIENT,
    REG_W267_MAX_STRESS_CELL,
    REG_W267_TOTAL_NODES,
    REG_W267_FACE_COUNT,
    REG_W267_AREA_VARIANCE,
    REG_W267_INTERPOLATION_QUALITY,
    REG_W267_SELECTED_SENSOR,
    REG_W267_DIAGNOSTIC_CODE,
    REG_TOTAL_NODES,
    REG_TRIANGLE_COUNT,
    REG_DELAUNAY_DIAGNOSTIC_CODE,
    REG_DELAUNAY_PEAK_GRADIENT,
    # Discrete Coils
    COIL_SPATIAL_MESH_CONNECTED,
    COIL_DELAUNAY_CANVAS_ACTIVE,
    COIL_W267_CANVAS_ACTIVE,
    COIL_W267_MESH_CONNECTED,
    COIL_FIELD_GRADIENT_ALARM,
    COIL_THERMAL_STRESS_ALARM_ACTIVE,
    COIL_FIELD_GRADIENT_ALARM_ACTIVE,
    COIL_W267_GRADIENT_ALARM,
    COIL_W267_HOTSPOT_ALARM,
    # Process Physics & Geometric Metrics
    NOMINAL_ACTIVE_SENSOR_COUNT,
    NOMINAL_MESH_FACE_COUNT,
    NOMINAL_PEAK_GRADIENT_C_PER_M,
    NOMINAL_PEAK_GRADIENT_SCALED,
    GRADIENT_ALARM_THRESHOLD_C_PER_M,
    NOMINAL_AREA_VARIANCE_SCALED,
    NOMINAL_INTERPOLATION_QUALITY_PCT,
    NOMINAL_INTERPOLATION_QUALITY_SCALED,
    PIXELS_PER_METER,
    # Viewport & Layout Geometry Constants
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    DOMAIN_MIN_X,
    DOMAIN_MAX_X,
    DOMAIN_MIN_Y,
    DOMAIN_MAX_Y,
    # Colors & Accessibility
    COLOR_SCADA_BG,
    COLOR_PANEL_BG,
    COLOR_CARD_BG,
    COLOR_BORDER,
    COLOR_BORDER_LIGHT,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_DECOUPLED_BADGE,
    COLOR_DELAUNAY_EDGE,
    COLOR_VORONOI_STROKE,
    COLOR_HOTSPOT_ACCENT,
    COLOR_HOTSPOT_GLOW,
    COLOR_COLD_CYAN,
    COLOR_NOMINAL_EMERALD,
    COLOR_WARM_AMBER,
    COLOR_ALARM_CRIMSON,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_SURFACE,
    COLOR_STATUS_NOMINAL,
    COLOR_STATUS_WARNING,
    COLOR_STATUS_CRITICAL,
    COLOR_VORONOI_BOUNDARY,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    # Status & Exception Classes
    DelaunayVoronoiStatusBits,
    CellSeverity,
    # Geometry Models & Solvers
    Point2D,
    SensorNode,
    Node2D,
    DelaunayNode2D,
    Edge2D,
    Triangle2D,
    DelaunayTriangle2D,
    Polygon2D,
    VoronoiCell,
    DelaunayVoronoiCell,
    TelemetryMetrics,
    compute_delaunay_triangulation,
    compute_voronoi_tessellation,
    compute_voronoi_cells,
    interpolate_barycentric,
    compute_barycentric_coordinates,
    get_temperature_color,
    create_canonical_sensors,
    create_canonical_sensor_nodes,
    create_canonical_delaunay_nodes,
    # Contrast Math
    srgb_channel_to_linear,
    hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    # SVG Renderer
    generate_delaunay_voronoi_canvas_svg,
    generate_delaunay_voronoi_canvas_svg_export,
    # Engine, Context & Runner
    DelaunayVoronoiCanvas,
    DelaunayVoronoiCanvasEngine,
    DelaunayVoronoiCanvasSync,
    DelaunayVoronoiEngine,
    DelaunayVoronoiScadaCanvas,
    create_canonical_delaunay_voronoi_canvas,
    create_mock_scan_context,
    run_delaunay_voronoi_canvas_verification,
    DELAUNAY_VORONOI_PURE_ST_POU,
    DELAUNAY_VORONOI_CANVAS_PURE_ST_POU,
    W267_DELAUNAY_VORONOI_PURE_ST_POU,
    DELAUNAY_VORONOI_CANVAS_SYNC_POU,
    verify_delaunay_voronoi_pure_st,
)


# ============================================================================
# 1. Diagnostic Codes Signed/Unsigned 16-Bit Values & Representations
# ============================================================================

class TestDiagnosticCodesSignedUnsigned:
    """Validate 16-bit diagnostic codes (0x0000, 0x7901, 0x7902), signed/unsigned values, and string formats."""

    def test_diagnostic_code_values_and_representations(self) -> None:
        """Verify signed and unsigned 16-bit values and string representations."""
        # 0x0000 OK
        assert DIAG_OK == 0x0000
        assert DIAG_EVENT_OK == 0x0000
        assert DELAUNAY_CANVAS_OK == 0x0000
        assert int(DIAG_OK) == 0
        assert f"0x{int(DIAG_OK):04X}" == "0x0000"

        # 0x7901 Colinear Degeneracy Trip
        assert DIAG_ERR_COLINEAR_DEGENERACY_TRIP == 0x7901
        assert COLINEAR_DEGENERACY_TRIP == 0x7901
        assert COLINEAR_DEGENERACY_FAULT == 0x7901
        assert DIAG_ERR_COLINEAR_DEGENERACY == 0x7901
        assert DIAG_ERR_DELAUNAY_COPLANARITY_DEGENERATE == 0x7901
        assert DELAUNAY_COPLANARITY_DEGENERATE == 0x7901
        assert int(DIAG_ERR_COLINEAR_DEGENERACY_TRIP) == 30977
        assert f"0x{int(DIAG_ERR_COLINEAR_DEGENERACY_TRIP):04X}" == "0x7901"

        # 0x7902 Boundary Polygon Fault
        assert DIAG_ERR_BOUNDARY_POLYGON_FAULT == 0x7902
        assert BOUNDARY_POLYGON_FAULT == 0x7902
        assert BOUNDARY_POLYGON_TRIP == 0x7902
        assert DIAG_ERR_BOUNDARY_POLYGON == 0x7902
        assert int(DIAG_ERR_BOUNDARY_POLYGON_FAULT) == 30978
        assert f"0x{int(DIAG_ERR_BOUNDARY_POLYGON_FAULT):04X}" == "0x7902"

        # 0x7903 Render Fault
        assert DIAG_ERR_SVG_RENDER_FAULT == 0x7903
        assert SVG_RENDER_FAULT == 0x7903
        assert DIAG_ERR_RENDER_FAULT == 0x7903
        assert int(DIAG_ERR_SVG_RENDER_FAULT) == 30979
        assert f"0x{int(DIAG_ERR_SVG_RENDER_FAULT):04X}" == "0x7903"

    def test_signed_vs_unsigned_equality(self) -> None:
        """Verify signed and unsigned comparison across INT16 boundaries."""
        code_neg = DiagnosticCode(-1)
        assert code_neg == 0xFFFF
        assert code_neg == -1

        code_high = DiagnosticCode(0x8001)
        assert code_high == 32769
        assert code_high == -32767

        code_7901 = DiagnosticCode(0x7901)
        assert code_7901 == 30977
        assert code_7901 == 0x7901

        code_7902 = DiagnosticCode(0x7902)
        assert code_7902 == 30978
        assert code_7902 == 0x7902

        # Hashing and container behavior
        diag_set: Set[DiagnosticCode] = {
            DIAG_OK,
            DIAG_ERR_COLINEAR_DEGENERACY_TRIP,
            DIAG_ERR_BOUNDARY_POLYGON_FAULT,
        }
        assert len(diag_set) == 3
        assert DiagnosticCode(0x7901) in diag_set
        assert DiagnosticCode(0x7902) in diag_set
        assert DiagnosticCode(0x0000) in diag_set


# ============================================================================
# 2. Register and Coil Mappings (%R2280..%R2287, %M532..%M533)
# ============================================================================

class TestRegisterAndCoilMappings:
    """Validate register mappings (%R2280..%R2287) and coil mappings (%M532..%M533)."""

    def test_analog_word_registers(self) -> None:
        """Verify %R2280..%R2287 register assignments and W267 aliases."""
        assert REG_PEAK_GRADIENT_MAGNITUDE_SCALED == "%R2280"
        assert REG_MAX_THERMAL_STRESS_CELL_ID == "%R2281"
        assert REG_ACTIVE_SENSOR_NODE_COUNT == "%R2282"
        assert REG_TRIANGULATION_MESH_FACE_COUNT == "%R2283"
        assert REG_VORONOI_CELL_AREA_VARIANCE_SCALED == "%R2284"
        assert REG_SPATIAL_INTERPOLATION_QUALITY_PCT_SCALED == "%R2285"
        assert REG_SELECTED_SENSOR_INDEX == "%R2286"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2287"

        # W267 aliases
        assert REG_W267_PEAK_GRADIENT == "%R2280"
        assert REG_W267_MAX_STRESS_CELL == "%R2281"
        assert REG_W267_TOTAL_NODES == "%R2282"
        assert REG_W267_FACE_COUNT == "%R2283"
        assert REG_W267_AREA_VARIANCE == "%R2284"
        assert REG_W267_INTERPOLATION_QUALITY == "%R2285"
        assert REG_W267_SELECTED_SENSOR == "%R2286"
        assert REG_W267_DIAGNOSTIC_CODE == "%R2287"

        # General aliases
        assert REG_TOTAL_NODES == "%R2282"
        assert REG_TRIANGLE_COUNT == "%R2283"
        assert REG_DELAUNAY_DIAGNOSTIC_CODE == "%R2287"
        assert REG_DELAUNAY_PEAK_GRADIENT == "%R2280"

    def test_discrete_coils(self) -> None:
        """Verify %M532..%M533 discrete coils and aliases."""
        assert COIL_SPATIAL_MESH_CONNECTED == "%M532"
        assert COIL_DELAUNAY_CANVAS_ACTIVE == "%M532"
        assert COIL_W267_CANVAS_ACTIVE == "%M532"
        assert COIL_W267_MESH_CONNECTED == "%M532"

        assert COIL_FIELD_GRADIENT_ALARM == "%M533"
        assert COIL_THERMAL_STRESS_ALARM_ACTIVE == "%M533"
        assert COIL_FIELD_GRADIENT_ALARM_ACTIVE == "%M533"
        assert COIL_W267_GRADIENT_ALARM == "%M533"
        assert COIL_W267_HOTSPOT_ALARM == "%M533"


# ============================================================================
# 3. Bowyer-Watson Delaunay Triangulation & Circumcircle Math
# ============================================================================

class TestBowyerWatsonDelaunayCircumcircleMath:
    """Validate Bowyer-Watson Delaunay triangulation, circumcircle math, and empty-circumcircle criterion."""

    def test_canonical_sensor_nodes_creation(self) -> None:
        """Verify canonical 32 sensor nodes are created within domain boundaries."""
        sensors = create_canonical_sensors()
        assert len(sensors) == NOMINAL_ACTIVE_SENSOR_COUNT  # 32
        for s in sensors:
            assert s.active is True
            assert DOMAIN_MIN_X <= s.x <= 900.0
            assert DOMAIN_MIN_Y <= s.y <= 740.0
            assert 60.0 <= s.temp_c <= 105.0

    def test_triangle2d_circumcircle_computation_known_triangle(self) -> None:
        """Verify circumcenter and radius_sq for a known right triangle (0,0), (4,0), (0,3)."""
        n1 = SensorNode(id=1, x=0.0, y=0.0)
        n2 = SensorNode(id=2, x=4.0, y=0.0)
        n3 = SensorNode(id=3, x=0.0, y=3.0)
        tri = Triangle2D(n1, n2, n3)

        assert math.isclose(tri.center_x, 2.0, abs_tol=1e-7)
        assert math.isclose(tri.center_y, 1.5, abs_tol=1e-7)
        assert math.isclose(tri.radius_sq, 6.25, abs_tol=1e-7)  # R = 2.5, R^2 = 6.25

        # Hypotenuse midpoint is circumcenter for right triangle
        assert math.hypot(n1.x - tri.center_x, n1.y - tri.center_y) == pytest.approx(2.5)
        assert math.hypot(n2.x - tri.center_x, n2.y - tri.center_y) == pytest.approx(2.5)
        assert math.hypot(n3.x - tri.center_x, n3.y - tri.center_y) == pytest.approx(2.5)

    def test_circumcircle_containment_method(self) -> None:
        """Verify circumcircle_contains correctly identifies interior vs exterior points."""
        n1 = SensorNode(id=1, x=0.0, y=0.0)
        n2 = SensorNode(id=2, x=4.0, y=0.0)
        n3 = SensorNode(id=3, x=0.0, y=3.0)
        tri = Triangle2D(n1, n2, n3)

        interior = SensorNode(id=4, x=2.0, y=1.5)  # exact circumcenter
        exterior = SensorNode(id=5, x=5.0, y=5.0)  # far away
        assert tri.circumcircle_contains(interior) is True
        assert tri.circumcircle_contains(exterior) is False

    def test_triangle_quality_factor_rho(self) -> None:
        """Verify normalized radius ratio quality factor rho in [0, 1]."""
        # Equilateral triangle: quality factor close to 1.0
        side = 100.0
        h = side * math.sqrt(3.0) / 2.0
        n1 = SensorNode(id=1, x=0.0, y=0.0)
        n2 = SensorNode(id=2, x=side, y=0.0)
        n3 = SensorNode(id=3, x=side / 2.0, y=h)
        eq_tri = Triangle2D(n1, n2, n3)
        assert eq_tri.quality_factor > 0.95

        # Sliver needle triangle: quality factor close to 0.0
        s1 = SensorNode(id=1, x=0.0, y=0.0)
        s2 = SensorNode(id=2, x=100.0, y=0.0)
        s3 = SensorNode(id=3, x=50.0, y=0.01)
        sliver_tri = Triangle2D(s1, s2, s3)
        assert sliver_tri.quality_factor < 0.05

    def test_collinear_nodes_determinant_guard(self) -> None:
        """Verify collinear nodes handle determinant d near zero without division by zero."""
        n1 = SensorNode(id=1, x=0.0, y=0.0)
        n2 = SensorNode(id=2, x=50.0, y=0.0)
        n3 = SensorNode(id=3, x=100.0, y=0.0)
        collinear_tri = Triangle2D(n1, n2, n3)
        assert math.isinf(collinear_tri.radius_sq)
        assert math.isclose(collinear_tri.center_x, 50.0, abs_tol=1e-7)

    def test_delaunay_triangulation_mesh_faces_count(self) -> None:
        """Verify canonical sensor mesh produces 54 triangle faces."""
        sensors = create_canonical_sensors()
        triangles = compute_delaunay_triangulation(sensors)
        assert len(triangles) == NOMINAL_MESH_FACE_COUNT  # 54 faces

    def test_delaunay_empty_circumcircle_criterion(self) -> None:
        """Verify Delaunay empty-circumcircle criterion: no active node lies inside any circumcircle."""
        sensors = create_canonical_sensors()
        triangles = compute_delaunay_triangulation(sensors)
        active_nodes = [s for s in sensors if s.active]

        violations = 0
        for tri in triangles:
            r = math.sqrt(tri.radius_sq) if not math.isinf(tri.radius_sq) else 1e9
            for n in active_nodes:
                if tri.contains_node(n):
                    continue
                dist = math.hypot(n.x - tri.center_x, n.y - tri.center_y)
                if dist < (r - 1e-6):
                    violations += 1

        assert violations == 0, f"Found {violations} empty circumcircle violations"


# ============================================================================
# 4. Voronoi Dual Polygonal Cell Extraction & Area Conservation
# ============================================================================

class TestVoronoiDualCellsAndAreaConservation:
    """Validate Voronoi dual polygonal cell extraction, Shoelace area, and area conservation."""

    def test_polygon2d_shoelace_area_known_rectangle(self) -> None:
        """Verify Green's Theorem Shoelace formula for a known rectangle 100x50."""
        poly = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(100.0, 0.0),
            Point2D(100.0, 50.0),
            Point2D(0.0, 50.0),
        ])
        assert math.isclose(poly.shoelace_area(), 5000.0, abs_tol=1e-7)
        assert math.isclose(poly.perimeter(), 300.0, abs_tol=1e-7)
        c = poly.centroid()
        assert math.isclose(c.x, 50.0, abs_tol=1e-7)
        assert math.isclose(c.y, 25.0, abs_tol=1e-7)

    def test_sutherland_hodgman_clipping_square(self) -> None:
        """Verify Sutherland-Hodgman convex halfplane clipping bisecting a square."""
        square = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(10.0, 0.0),
            Point2D(10.0, 10.0),
            Point2D(0.0, 10.0),
        ])
        mid = Point2D(5.0, 5.0)
        normal = Point2D(1.0, 0.0)  # keeps x <= 5
        clipped = square.clip_halfplane(mid, normal)
        assert len(clipped.vertices) == 4
        assert math.isclose(clipped.shoelace_area(), 50.0, abs_tol=1e-7)

    def test_voronoi_cell_count(self) -> None:
        """Verify Voronoi tessellation creates exactly 32 cells for 32 active sensor nodes."""
        sensors = create_canonical_sensors()
        domain = (DOMAIN_MIN_X, DOMAIN_MAX_X, DOMAIN_MIN_Y, DOMAIN_MAX_Y)
        cells = compute_voronoi_tessellation(sensors, domain)
        assert len(cells) == NOMINAL_ACTIVE_SENSOR_COUNT
        assert all(len(c.polygon.vertices) >= 3 for c in cells)

    def test_voronoi_area_conservation_greens_theorem(self) -> None:
        """Verify exact Green's Theorem Shoelace area conservation over bounding domain."""
        sensors = create_canonical_sensors()
        domain = (DOMAIN_MIN_X, DOMAIN_MAX_X, DOMAIN_MIN_Y, DOMAIN_MAX_Y)
        cells = compute_voronoi_tessellation(sensors, domain)

        domain_area = (DOMAIN_MAX_X - DOMAIN_MIN_X) * (DOMAIN_MAX_Y - DOMAIN_MIN_Y)
        total_cell_area = sum(c.area for c in cells)
        area_residual = abs(domain_area - total_cell_area)

        assert area_residual < 1e-5, f"Area residual {area_residual:.6e} px^2 exceeds tolerance"

    def test_voronoi_cell_area_variance_metric(self) -> None:
        """Verify area variance CV metric scaled matches nominal 420 (42.0%)."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        assert canvas.metrics.area_variance_scaled == NOMINAL_AREA_VARIANCE_SCALED


# ============================================================================
# 5. Barycentric Interpolation & Maximum Gradient Tracking
# ============================================================================

class TestBarycentricInterpolationAndGradientTracking:
    """Validate barycentric coordinate math, partition of unity, and spatial gradient tracking."""

    def test_barycentric_partition_of_unity(self) -> None:
        """Verify lambda_1 + lambda_2 + lambda_3 == 1.0 (residual < 1e-6)."""
        sensors = create_canonical_sensors()
        triangles = compute_delaunay_triangulation(sensors)

        for tri in triangles[:10]:
            # Midpoint of triangle
            mx = (tri.n1.x + tri.n2.x + tri.n3.x) / 3.0
            my = (tri.n1.y + tri.n2.y + tri.n3.y) / 3.0
            res = interpolate_barycentric(mx, my, triangles)
            assert res is not None
            val, (l1, l2, l3), found_tri = res
            assert math.isclose(l1 + l2 + l3, 1.0, abs_tol=1e-6)
            assert l1 >= -1e-5 and l2 >= -1e-5 and l3 >= -1e-5

    def test_barycentric_exact_at_sensor_nodes(self) -> None:
        """Verify interpolation at sensor nodes exactly returns sensor temp_c."""
        sensors = create_canonical_sensors()
        triangles = compute_delaunay_triangulation(sensors)

        for s in sensors[:8]:
            res = interpolate_barycentric(s.x, s.y, triangles)
            assert res is not None
            val, (l1, l2, l3), _ = res
            assert math.isclose(val, s.temp_c, abs_tol=1e-2)

    def test_planar_gradient_known_linear_field(self) -> None:
        """Verify directional planar gradient nabla_T = (alpha, beta) on a known linear field."""
        alpha_expected = 12.0  # °C/m in x
        beta_expected = -8.0   # °C/m in y
        t0 = 50.0

        n1 = SensorNode(id=1, x=150.0, y=150.0)
        n2 = SensorNode(id=2, x=300.0, y=150.0)
        n3 = SensorNode(id=3, x=150.0, y=300.0)

        for n in [n1, n2, n3]:
            xm = n.x / PIXELS_PER_METER
            ym = n.y / PIXELS_PER_METER
            n.temp_c = t0 + alpha_expected * xm + beta_expected * ym

        tri = Triangle2D(n1, n2, n3)
        assert math.isclose(tri.grad_alpha, alpha_expected, abs_tol=1e-5)
        assert math.isclose(tri.grad_beta, beta_expected, abs_tol=1e-5)
        expected_mag = math.hypot(alpha_expected, beta_expected)
        assert math.isclose(tri.grad_mag, expected_mag, abs_tol=1e-5)

    def test_maximum_gradient_tracking_nominal(self) -> None:
        """Verify nominal peak gradient is 18.5 °C/m (scaled 185 in %R2280)."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        assert math.isclose(canvas.metrics.peak_gradient_c_per_m, NOMINAL_PEAK_GRADIENT_C_PER_M, abs_tol=0.05)
        assert canvas.metrics.peak_gradient_scaled == NOMINAL_PEAK_GRADIENT_SCALED
        assert canvas.reg_table.read_word(REG_PEAK_GRADIENT_MAGNITUDE_SCALED) == NOMINAL_PEAK_GRADIENT_SCALED

    def test_query_outside_mesh_returns_none(self) -> None:
        """Verify querying coordinates far outside triangulation hull returns None."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        assert interpolate_barycentric(10.0, 10.0, canvas.triangles) is None
        assert interpolate_barycentric(1100.0, 700.0, canvas.triangles) is None


# ============================================================================
# 6. SVG Markup Generation, XML Validity, Polygons, Lines & Labels
# ============================================================================

class TestSVGMarkupGenerationAndXMLValidity:
    """Validate standalone W3C SVG 1.1 vector markup generation, XML validity, and visual elements."""

    def test_svg_markup_xml_validity(self) -> None:
        """Verify SVG header, root tag, viewBox, and ElementTree XML validity."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        svg_xml = canvas.render_svg()

        root = ET.fromstring(svg_xml)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)
        assert root.attrib.get("viewBox") == f"0 0 {CANVAS_VIEWPORT_WIDTH} {CANVAS_VIEWPORT_HEIGHT}"

    def test_svg_visual_elements_and_labels(self) -> None:
        """Verify Voronoi polygons, Delaunay wireframe lines, sensor circles, and text labels."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)

        rects = root.findall(".//{http://www.w3.org/2000/svg}rect") + root.findall(".//rect")
        circles = root.findall(".//{http://www.w3.org/2000/svg}circle") + root.findall(".//circle")
        polygons = root.findall(".//{http://www.w3.org/2000/svg}polygon") + root.findall(".//polygon")
        lines = root.findall(".//{http://www.w3.org/2000/svg}line") + root.findall(".//line")
        texts = root.findall(".//{http://www.w3.org/2000/svg}text") + root.findall(".//text")

        assert len(rects) >= 4          # viewport, header, hud cards
        assert len(circles) >= 32       # 32 sensor nodes + reticle
        assert len(polygons) >= 32      # Voronoi cells and Delaunay facets
        assert len(lines) >= 2          # reticle crosshairs + legend
        assert len(texts) >= 20         # labels and HUD items

        all_text = "".join(t.text or "" for t in texts)
        assert "DELAUNAY-VORONOI DUAL SCADA CANVAS" in all_text
        assert "%R2280" in all_text
        assert "%R2287" in all_text
        assert "%M532" in all_text
        assert "%M533" in all_text
        assert "SPATIAL MESH TOPOLOGY" in all_text
        assert "BARYCENTRIC INTERPOLATION" in all_text


# ============================================================================
# 7. WCAG 2.1 AAA Contrast Compliance (>= 18:1, >= 7:1, >= 3:1)
# ============================================================================

class TestWCAG21AAAContrastCompliance:
    """Validate WCAG 2.1 AAA contrast benchmarks (>= 18:1 badge, >= 7:1 text, >= 3:1 graphics)."""

    def test_decoupled_badge_contrast_target(self) -> None:
        """Verify decoupled badge contrast achieves >= 18:1."""
        cr_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr_badge >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert cr_badge >= 18.0

    def test_theme_text_contrast_target(self) -> None:
        """Verify primary text achieves >= 7:1 contrast against dark background."""
        cr_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG)
        assert cr_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr_text >= 7.0

    def test_graphical_indicators_contrast_target(self) -> None:
        """Verify graphical indicator colors achieve >= 3:1 contrast against dark background."""
        for col in [COLOR_COLD_CYAN, COLOR_NOMINAL_EMERALD, COLOR_WARM_AMBER, COLOR_ALARM_CRIMSON]:
            cr = calculate_contrast_ratio(col, COLOR_SCADA_BG)
            assert cr >= WCAG_GRAPHICAL_CONTRAST_TARGET
            assert cr >= 3.0

    def test_contrast_math_helpers(self) -> None:
        """Verify sRGB channel linear conversion, relative luminance white and black, and symmetry."""
        assert math.isclose(srgb_channel_to_linear(0.0), 0.0, abs_tol=1e-7)
        assert math.isclose(srgb_channel_to_linear(1.0), 1.0, abs_tol=1e-7)
        assert math.isclose(hex_to_relative_luminance("#000000"), 0.0, abs_tol=1e-7)
        assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-7)

        # Symmetry
        cr1 = calculate_contrast_ratio("#FFFFFF", "#000000")
        cr2 = calculate_contrast_ratio("#000000", "#FFFFFF")
        assert math.isclose(cr1, cr2, abs_tol=1e-7)
        assert math.isclose(cr1, 21.0, abs_tol=1e-7)

        # validate_wcag_aaa_contrast helper
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, target=18.0) is True


# ============================================================================
# 8. Colinear Degeneracy Trip 0x7901 & Boundary Polygon Fault 0x7902
# ============================================================================

class TestColinearDegeneracyAndBoundaryPolygonFaults:
    """Validate 0x7901 colinear degeneracy trip and 0x7902 boundary polygon fault."""

    def test_colinear_degeneracy_trip_0x7901(self) -> None:
        """Verify 0x7901 Colinear Degeneracy Trip sets diagnostic code and updates %R2287."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        assert canvas.diagnostic_code == DIAG_OK

        canvas.trigger_colinear_degeneracy_fault()
        assert canvas.diagnostic_code == 0x7901
        assert canvas.diagnostic_code == DIAG_ERR_COLINEAR_DEGENERACY_TRIP
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0x7901

        # Nominal recovery
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0

    def test_boundary_polygon_fault_0x7902(self) -> None:
        """Verify 0x7902 Boundary Polygon Fault sets diagnostic code and updates %R2287."""
        canvas = create_canonical_delaunay_voronoi_canvas()

        canvas.trigger_boundary_polygon_fault()
        assert canvas.diagnostic_code == 0x7902
        assert canvas.diagnostic_code == DIAG_ERR_BOUNDARY_POLYGON_FAULT
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0x7902

        # Nominal recovery
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0

    def test_svg_render_fault_0x7903(self) -> None:
        """Verify 0x7903 SVG Render Fault sets diagnostic code and updates %R2287."""
        canvas = create_canonical_delaunay_voronoi_canvas()

        canvas.trigger_svg_render_fault()
        assert canvas.diagnostic_code == 0x7903
        assert canvas.diagnostic_code == DIAG_ERR_SVG_RENDER_FAULT
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0x7903

        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0


# ============================================================================
# 9. Field Gradient Alarm Coil %M533 Assertion
# ============================================================================

class TestFieldGradientAlarmCoilAssertion:
    """Validate field gradient alarm coil %M533 assertion when gradient exceeds threshold (> 25.0 °C/m)."""

    def test_field_gradient_alarm_coil_assertion(self) -> None:
        """Verify coil %M533 asserts when peak gradient > 25.0 °C/m, and clears on reset."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        assert canvas.reg_table.read_bit(COIL_FIELD_GRADIENT_ALARM) is False

        # Inject gradient above 25.0 °C/m threshold
        canvas.trigger_field_gradient_alarm(peak_gradient=32.0)
        assert bool(canvas.status_bits & DelaunayVoronoiStatusBits.GRADIENT_ALARM_ACTIVE) is True
        assert canvas.reg_table.read_bit(COIL_FIELD_GRADIENT_ALARM) is True
        assert canvas.reg_table.read_word(REG_PEAK_GRADIENT_MAGNITUDE_SCALED) == 320

        # Reset nominal restores coil %M533 to False
        canvas.reset_nominal()
        assert bool(canvas.status_bits & DelaunayVoronoiStatusBits.GRADIENT_ALARM_ACTIVE) is False
        assert canvas.reg_table.read_bit(COIL_FIELD_GRADIENT_ALARM) is False
        assert canvas.reg_table.read_word(REG_PEAK_GRADIENT_MAGNITUDE_SCALED) == NOMINAL_PEAK_GRADIENT_SCALED

    def test_mesh_disconnection_coil_m532_deassertion(self) -> None:
        """Verify mesh disconnection deasserts coil %M532 when active nodes < 24."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        assert canvas.reg_table.read_bit(COIL_SPATIAL_MESH_CONNECTED) is True

        canvas.trigger_mesh_disconnection(disable_count=12)
        assert bool(canvas.status_bits & DelaunayVoronoiStatusBits.MESH_CONNECTED) is False
        assert canvas.reg_table.read_bit(COIL_SPATIAL_MESH_CONNECTED) is False

        canvas.reset_nominal()
        assert bool(canvas.status_bits & DelaunayVoronoiStatusBits.MESH_CONNECTED) is True
        assert canvas.reg_table.read_bit(COIL_SPATIAL_MESH_CONNECTED) is True


# ============================================================================
# 10. Horner OCS Register Synchronization & 50-Step Scan Cycle Soak Stability
# ============================================================================

class TestHornerOCSSynchronizationAndScanCycleSoak:
    """Validate register synchronization across %R2280..%R2287 and 50-step scan cycle soak stability."""

    def test_nominal_register_synchronization(self) -> None:
        """Verify registers %R2280..%R2287 and coils %M532..%M533 under nominal scan."""
        reg_table = RegisterTable()
        canvas = DelaunayVoronoiCanvas(register_table=reg_table)
        canvas.scan_step(dt=0.01)

        assert reg_table.read_word(REG_PEAK_GRADIENT_MAGNITUDE_SCALED) == NOMINAL_PEAK_GRADIENT_SCALED  # 185
        assert 1 <= reg_table.read_word(REG_MAX_THERMAL_STRESS_CELL_ID) <= 64
        assert reg_table.read_word(REG_ACTIVE_SENSOR_NODE_COUNT) == NOMINAL_ACTIVE_SENSOR_COUNT          # 32
        assert reg_table.read_word(REG_TRIANGULATION_MESH_FACE_COUNT) == NOMINAL_MESH_FACE_COUNT        # 54
        assert reg_table.read_word(REG_VORONOI_CELL_AREA_VARIANCE_SCALED) == NOMINAL_AREA_VARIANCE_SCALED # 420
        assert reg_table.read_word(REG_SPATIAL_INTERPOLATION_QUALITY_PCT_SCALED) == NOMINAL_INTERPOLATION_QUALITY_SCALED # 985
        assert reg_table.read_word(REG_SELECTED_SENSOR_INDEX) == 1
        assert reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0

        assert reg_table.read_bit(COIL_SPATIAL_MESH_CONNECTED) is True
        assert reg_table.read_bit(COIL_FIELD_GRADIENT_ALARM) is False

    def test_50_step_scan_cycle_soak_stability(self) -> None:
        """Execute 50-step scan cycle soak verifying numerical stability, zero drift, and invariant preservation."""
        reg_table = RegisterTable()
        canvas = DelaunayVoronoiCanvas(register_table=reg_table)

        for step in range(50):
            canvas.scan_step(dt=0.01)

            assert reg_table.read_word(REG_PEAK_GRADIENT_MAGNITUDE_SCALED) == NOMINAL_PEAK_GRADIENT_SCALED
            assert reg_table.read_word(REG_ACTIVE_SENSOR_NODE_COUNT) == NOMINAL_ACTIVE_SENSOR_COUNT
            assert reg_table.read_word(REG_TRIANGULATION_MESH_FACE_COUNT) == NOMINAL_MESH_FACE_COUNT
            assert reg_table.read_word(REG_VORONOI_CELL_AREA_VARIANCE_SCALED) == NOMINAL_AREA_VARIANCE_SCALED
            assert reg_table.read_word(REG_SPATIAL_INTERPOLATION_QUALITY_PCT_SCALED) == NOMINAL_INTERPOLATION_QUALITY_SCALED
            assert reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0
            assert reg_table.read_bit(COIL_SPATIAL_MESH_CONNECTED) is True
            assert reg_table.read_bit(COIL_FIELD_GRADIENT_ALARM) is False

    def test_scan_cycle_with_scan_context(self) -> None:
        """Verify execute() with mock ScanContext updates registers cleanly."""
        reg_table = RegisterTable()
        canvas = DelaunayVoronoiCanvas(register_table=reg_table)
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg_table)
        canvas.execute(ctx)

        assert reg_table.read_word(REG_PEAK_GRADIENT_MAGNITUDE_SCALED) == NOMINAL_PEAK_GRADIENT_SCALED
        assert reg_table.read_bit(COIL_SPATIAL_MESH_CONNECTED) is True

    def test_sensor_selection_register_update(self) -> None:
        """Verify operator sensor focus selection updates %R2286."""
        canvas = create_canonical_delaunay_voronoi_canvas()
        for idx in [5, 12, 28, 32]:
            canvas.select_sensor(idx)
            assert canvas.selected_sensor_index == idx
            assert canvas.reg_table.read_word(REG_SELECTED_SENSOR_INDEX) == idx


# ============================================================================
# 11. Pure IEC 61131-3 ST POU & SecurityGuard AST Validation
# ============================================================================

class TestPureSTPOUValidationAndSecurityGuard:
    """Validate Pure ST POU grammar, AST variable memory_address bindings, and helpers."""

    def test_pure_st_pou_ast_variable_memory_addresses(self) -> None:
        """Validate pure ST POU grammar and Horner memory bindings (%R2280..%R2287, %M532..%M533)."""
        SecurityGuard.assert_pure_st_content(DELAUNAY_VORONOI_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(DELAUNAY_VORONOI_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "DelaunayVoronoiCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        vmap = {v.name: v.address_binding for v in pou.variables}
        assert vmap["PeakGradientMagnitudeScaled"] == "%R2280"
        assert vmap["MaxThermalStressCellId"] == "%R2281"
        assert vmap["ActiveSensorNodeCount"] == "%R2282"
        assert vmap["TriangulationMeshFaceCount"] == "%R2283"
        assert vmap["VoronoiCellAreaVarianceScaled"] == "%R2284"
        assert vmap["SpatialInterpolationQualityPctScaled"] == "%R2285"
        assert vmap["SelectedSensorIndex"] == "%R2286"
        assert vmap["DiagnosticStatusCode"] == "%R2287"
        assert vmap["SpatialMeshConnected"] == "%M532"
        assert vmap["FieldGradientAlarmActive"] == "%M533"

        assert "%R2280" in pou.bound_registers
        assert "%R2287" in pou.bound_registers
        assert "%M532" in pou.bound_registers
        assert "%M533" in pou.bound_registers

    def test_pure_st_convenience_verifier(self) -> None:
        """Verify convenience verification functions."""
        assert verify_delaunay_voronoi_pure_st() is True


# ============================================================================
# 12. Anti-Ladder Security Guard Interception
# ============================================================================

class TestAntiLadderRejection:
    """Verify SecurityGuard intercepts all forbidden ladder logic constructs."""

    def test_ladder_construct_rejection(self) -> None:
        """Fail-closed rejection of ladder contacts, coils, rungs, and mnemonics."""
        ladder_snippets = [
            ("Contacts_Open", "PROGRAM Bad VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"),
            ("Contacts_Closed", "PROGRAM Bad VAR X: BOOL; END_VAR ---[/]--- END_PROGRAM"),
            ("Coils_Open", "PROGRAM Bad VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"),
            ("Coils_Set", "PROGRAM Bad VAR Y: BOOL; END_VAR ---(S)--- END_PROGRAM"),
            ("Coils_Reset", "PROGRAM Bad VAR Y: BOOL; END_VAR ---(R)--- END_PROGRAM"),
            ("Coils_Inverted", "PROGRAM Bad VAR Y: BOOL; END_VAR ---(/)--- END_PROGRAM"),
            ("Rung", "PROGRAM Bad\nRUNG 1:\nEND_PROGRAM"),
            ("Network", "PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM"),
            ("Mnemonic_XIC", "PROGRAM Bad\nXIC bit1;\nEND_PROGRAM"),
            ("Mnemonic_OTE", "PROGRAM Bad\nOTE bit2;\nEND_PROGRAM"),
            ("Mnemonic_OTL", "PROGRAM Bad\nOTL bit3;\nEND_PROGRAM"),
        ]
        for name, snippet in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 13. Deterministic 9-Stage Verification Suite & Contract
# ============================================================================

class TestVerificationRunnerContract:
    """Validate deterministic 9-stage verification runner and strict 4-state contract."""

    def test_verification_runner_execution(self) -> None:
        """Execute verification runner and verify report and generated artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_p = str(Path(tmpdir) / "evidence.json")
            svg_p = str(Path(tmpdir) / "sample.svg")
            report = run_delaunay_voronoi_canvas_verification(
                output_path=ev_p,
                sample_svg_path=svg_p,
                work_package="W267",
            )

            assert report["status"] == "success"
            assert report["error_code"] is None
            assert report["data"]["checks_passed"] == 9
            assert report["data"]["total_checks"] == 9
            assert report["data"]["work_package"] == "W267"
            assert Path(ev_p).exists()
            assert Path(svg_p).exists()

            with open(ev_p, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"
            assert len(data["data"]["stages"]) == 9
