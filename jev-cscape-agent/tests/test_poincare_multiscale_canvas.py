"""Comprehensive unit test suite for Cscape HMI Dynamic Hyperbolic Poincaré Multiscale Canvas (W264).

Work Package: W264 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Hyperbolic Poincaré Multiscale Radial Asset SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Must test:
- Diagnostic codes signed/unsigned 16-bit values and string representations (0x0000, 0x7801, 0x7802)
- Register and coil mappings (%R2250..%R2257, %M525..%M526)
- Poincare disk hyperbolic metric, Mobius transformations, conformal angle preservation
- Geodesic circle arc calculations between node pairs
- SVG markup generation, XML validity, boundary circle, geodesic paths, labels
- WCAG 2.1 AAA contrast compliance (>= 18:1 decoupled badges, >= 7:1 text, >= 3:1 graphics)
- Boundary overflow trip 0x7801 and conformal singularity trip 0x7802
- Boundary approach alarm coil %M526 assertion
- Horner OCS register synchronization and 50-step scan cycle soak stability
- Pure ST POU validation with STParser and SecurityGuard (AST variable memory_address)
- Anti-ladder rejection
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

from jev_cscape.hmi.poincare_multiscale_canvas import (
    # Diagnostic Codes
    DIAG_OK,
    DIAG_EVENT_OK,
    POINCARE_CANVAS_OK,
    DIAG_ERR_BOUNDARY_OVERFLOW_TRIP,
    BOUNDARY_OVERFLOW_TRIP,
    DIAG_ERR_BOUNDARY_OVERFLOW,
    DIAG_ERR_CONFORMAL_SINGULARITY_TRIP,
    CONFORMAL_SINGULARITY_TRIP,
    DIAG_ERR_CONFORMAL_SINGULARITY,
    DIAG_ERR_RENDER_FAULT,
    SVG_RENDER_FAULT,
    DiagnosticCode,
    # Register Definitions & Aliases
    REG_POINCARE_TOTAL_NODES_COUNT,
    REG_POINCARE_HIERARCHY_LEVELS,
    REG_HYPERBOLIC_RADIUS_SCALED,
    REG_SELECTED_POINCARE_NODE_ID,
    REG_CONFORMAL_DISTORTION_FACTOR_SCALED,
    REG_EDGE_GEODESIC_COUNT,
    REG_NETWORK_DENSITY_SCORE,
    REG_POINCARE_CANVAS_DIAGNOSTIC_CODE,
    REG_W264_TOTAL_NODES,
    REG_W264_HIERARCHY_LEVELS,
    REG_W264_HYPERBOLIC_RADIUS,
    REG_W264_SELECTED_NODE_ID,
    REG_W264_CONFORMAL_DISTORTION,
    REG_W264_EDGE_COUNT,
    REG_W264_DENSITY_SCORE,
    REG_W264_DIAGNOSTIC_CODE,
    # Discrete Coils
    COIL_POINCARE_CANVAS_ACTIVE,
    COIL_BOUNDARY_APPROACH_ALARM,
    COIL_W264_CANVAS_ACTIVE,
    COIL_W264_BOUNDARY_ALARM,
    # Viewport & Layout Geometry Constants
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    POINCARE_DISK_RADIUS,
    MAX_HYPERBOLIC_RADIUS,
    BOUNDARY_ALARM_THRESHOLD,
    # Canonical Hierarchy Levels & Dimensions
    LEVEL_0_RADIUS,
    LEVEL_1_RADIUS,
    LEVEL_2_RADIUS,
    LEVEL_3_RADIUS,
    LEVEL_4_RADIUS,
    CANONICAL_LEVEL_RADII,
    NOMINAL_NODE_COUNT,
    NOMINAL_HIERARCHY_LEVELS,
    NOMINAL_MAX_RADIUS,
    NOMINAL_SELECTED_NODE_ID,
    NOMINAL_CONFORMAL_DISTORTION,
    NOMINAL_EDGE_COUNT,
    NOMINAL_DENSITY_SCORE,
    # Colors & Accessibility
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_NOMINAL_EMERALD,
    COLOR_WARM_AMBER,
    COLOR_ALARM_CRIMSON,
    COLOR_FOCUS_BLUE,
    COLOR_DISK_BOUNDARY,
    COLOR_GEODESIC_TREE,
    COLOR_GEODESIC_CROSS,
    COLOR_CONCENTRIC_GUIDE,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    # Status & Exception Classes
    PoincareCanvasStatusBits,
    BoundaryOverflowError,
    ConformalSingularityError,
    # Hierarchy Models
    NodeHealthState,
    PoincareNode,
    PoincareEdge,
    PoincareMultiscaleMetrics,
    # Geometry & Math Functions
    ComplexPoint,
    to_complex_point,
    poincare_hyperbolic_distance,
    poincare_conformal_map,
    poincare_conformal_inverse,
    calculate_conformal_distortion_factor,
    is_in_poincare_disk,
    clamp_to_disk,
    disk_to_pixel,
    pixel_to_disk,
    GeodesicArc,
    compute_geodesic_arc,
    compute_network_density_score,
    create_canonical_32_node_hierarchy,
    # Contrast Math
    relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    # Engine, Context & Runner
    PoincareMultiscaleCanvas,
    PoincareMultiscaleCanvasEngine,
    PoincareMultiscaleCanvasSync,
    create_mock_scan_context,
    run_poincare_multiscale_canvas_verification,
    POINCARE_MULTISCALE_CANVAS_PURE_ST_POU,
    W264_POINCARE_MULTISCALE_CANVAS_PURE_ST_POU,
    verify_poincare_multiscale_canvas_pure_st,
)


# ============================================================================
# 1. Diagnostic Codes Signed/Unsigned 16-Bit Values & Representations
# ============================================================================

class TestDiagnosticCodesSignedUnsigned:
    """Validate 16-bit diagnostic codes (0x0000, 0x7801, 0x7802, 0x7803), signed/unsigned values, and string formats."""

    def test_diagnostic_code_values_and_representations(self) -> None:
        """Verify signed and unsigned 16-bit values and string representations."""
        # 0x0000 OK
        assert DIAG_OK == 0x0000
        assert DIAG_EVENT_OK == 0x0000
        assert POINCARE_CANVAS_OK == 0x0000
        assert int(DIAG_OK) == 0
        assert f"0x{int(DIAG_OK):04X}" == "0x0000"

        # 0x7801 Boundary Overflow Trip
        assert DIAG_ERR_BOUNDARY_OVERFLOW_TRIP == 0x7801
        assert BOUNDARY_OVERFLOW_TRIP == 0x7801
        assert DIAG_ERR_BOUNDARY_OVERFLOW == 0x7801
        assert int(DIAG_ERR_BOUNDARY_OVERFLOW_TRIP) == 30721
        assert f"0x{int(DIAG_ERR_BOUNDARY_OVERFLOW_TRIP):04X}" == "0x7801"

        # 0x7802 Conformal Singularity Trip
        assert DIAG_ERR_CONFORMAL_SINGULARITY_TRIP == 0x7802
        assert CONFORMAL_SINGULARITY_TRIP == 0x7802
        assert DIAG_ERR_CONFORMAL_SINGULARITY == 0x7802
        assert int(DIAG_ERR_CONFORMAL_SINGULARITY_TRIP) == 30722
        assert f"0x{int(DIAG_ERR_CONFORMAL_SINGULARITY_TRIP):04X}" == "0x7802"

        # 0x7803 Render Fault
        assert DIAG_ERR_RENDER_FAULT == 0x7803
        assert SVG_RENDER_FAULT == 0x7803
        assert int(DIAG_ERR_RENDER_FAULT) == 30723
        assert f"0x{int(DIAG_ERR_RENDER_FAULT):04X}" == "0x7803"

    def test_signed_vs_unsigned_equality(self) -> None:
        """Verify signed and unsigned comparison across INT16 boundaries."""
        code_neg = DiagnosticCode(-1)
        assert code_neg == 0xFFFF
        assert code_neg == -1

        code_high = DiagnosticCode(0x8001)
        assert code_high == 32769
        assert code_high == -32767

        # Hashing and container behavior
        diag_set: Set[DiagnosticCode] = {DIAG_OK, DIAG_ERR_BOUNDARY_OVERFLOW_TRIP, DIAG_ERR_CONFORMAL_SINGULARITY_TRIP}
        assert len(diag_set) == 3
        assert DiagnosticCode(0x7801) in diag_set
        assert DiagnosticCode(0x7802) in diag_set
        assert DiagnosticCode(0x0000) in diag_set


# ============================================================================
# 2. Register and Coil Mappings (%R2250..%R2257, %M525..%M526)
# ============================================================================

class TestRegisterAndCoilMappings:
    """Validate register mappings (%R2250..%R2257) and coil mappings (%M525..%M526)."""

    def test_analog_word_registers(self) -> None:
        """Verify %R2250..%R2257 register assignments and W264 aliases."""
        assert REG_POINCARE_TOTAL_NODES_COUNT == "%R2250"
        assert REG_POINCARE_HIERARCHY_LEVELS == "%R2251"
        assert REG_HYPERBOLIC_RADIUS_SCALED == "%R2252"
        assert REG_SELECTED_POINCARE_NODE_ID == "%R2253"
        assert REG_CONFORMAL_DISTORTION_FACTOR_SCALED == "%R2254"
        assert REG_EDGE_GEODESIC_COUNT == "%R2255"
        assert REG_NETWORK_DENSITY_SCORE == "%R2256"
        assert REG_POINCARE_CANVAS_DIAGNOSTIC_CODE == "%R2257"

        # W264 aliases
        assert REG_W264_TOTAL_NODES == "%R2250"
        assert REG_W264_HIERARCHY_LEVELS == "%R2251"
        assert REG_W264_HYPERBOLIC_RADIUS == "%R2252"
        assert REG_W264_SELECTED_NODE_ID == "%R2253"
        assert REG_W264_CONFORMAL_DISTORTION == "%R2254"
        assert REG_W264_EDGE_COUNT == "%R2255"
        assert REG_W264_DENSITY_SCORE == "%R2256"
        assert REG_W264_DIAGNOSTIC_CODE == "%R2257"

    def test_discrete_coils(self) -> None:
        """Verify %M525..%M526 discrete coils and aliases."""
        assert COIL_POINCARE_CANVAS_ACTIVE == "%M525"
        assert COIL_BOUNDARY_APPROACH_ALARM == "%M526"
        assert COIL_W264_CANVAS_ACTIVE == "%M525"
        assert COIL_W264_BOUNDARY_ALARM == "%M526"


# ============================================================================
# 3. Poincaré Metric, Möbius Transformations & Conformal Angle Preservation
# ============================================================================

class TestPoincareMetricAndMobiusTransformations:
    """Validate Poincaré metric axioms, Möbius map, and conformal angle preservation."""

    def test_hyperbolic_distance_axioms(self) -> None:
        """Verify positive definiteness, symmetry, triangle inequality, and origin formula."""
        u = ComplexPoint(0.2, 0.1)
        v = ComplexPoint(-0.4, 0.3)
        w = ComplexPoint(0.1, -0.4)

        # d(u, u) = 0
        assert math.isclose(poincare_hyperbolic_distance(u, u), 0.0, abs_tol=1e-12)

        # d(u, v) > 0 for u != v
        assert poincare_hyperbolic_distance(u, v) > 0.0

        # Symmetry: d(u, v) = d(v, u)
        assert math.isclose(
            poincare_hyperbolic_distance(u, v),
            poincare_hyperbolic_distance(v, u),
            abs_tol=1e-10,
        )

        # Triangle inequality: d(u, w) <= d(u, v) + d(v, w)
        d_uw = poincare_hyperbolic_distance(u, w)
        d_uv = poincare_hyperbolic_distance(u, v)
        d_vw = poincare_hyperbolic_distance(v, w)
        assert d_uw <= d_uv + d_vw + 1e-10

        # Origin distance: d(0, v) = 2 * artanh(|v|)
        d_0v = poincare_hyperbolic_distance(ComplexPoint(0.0, 0.0), v)
        assert math.isclose(d_0v, 2.0 * math.atanh(v.magnitude()), abs_tol=1e-10)

    def test_mobius_transformation_properties(self) -> None:
        """Verify origin mapping w(c) = 0, identity w(z) = z for c = 0, and invertibility."""
        c = ComplexPoint(0.3, -0.4)
        z = ComplexPoint(0.2, 0.5)

        # Focus c maps to origin
        w_origin = poincare_conformal_map(c, c)
        assert w_origin.magnitude() < 1e-12

        # Identity map
        w_id = poincare_conformal_map(z, ComplexPoint(0.0, 0.0))
        assert math.isclose(w_id.x, z.x, abs_tol=1e-12)
        assert math.isclose(w_id.y, z.y, abs_tol=1e-12)

        # Exact invertibility: inverse(map(z, c), c) = z
        w = poincare_conformal_map(z, c)
        z_rec = poincare_conformal_inverse(w, c)
        assert math.isclose(z_rec.x, z.x, abs_tol=1e-7)
        assert math.isclose(z_rec.y, z.y, abs_tol=1e-7)

        # Hyperbolic isometry preservation: d(T(u), T(v)) = d(u, v)
        u_pt = ComplexPoint(0.15, 0.25)
        v_pt = ComplexPoint(-0.35, 0.15)
        d_orig = poincare_hyperbolic_distance(u_pt, v_pt)
        d_trans = poincare_hyperbolic_distance(
            poincare_conformal_map(u_pt, c),
            poincare_conformal_map(v_pt, c),
        )
        assert math.isclose(d_orig, d_trans, abs_tol=1e-9)

    def test_conformal_angle_preservation(self) -> None:
        """Verify conformal angle preservation between intersecting tangent vectors."""
        base_z = ComplexPoint(0.3, 0.1)
        c = ComplexPoint(-0.2, 0.4)
        eps = 1e-6
        phi1 = 0.5
        phi2 = 1.8
        expected_angle = (phi2 - phi1) % (2.0 * math.pi)

        v1 = ComplexPoint(eps * math.cos(phi1), eps * math.sin(phi1))
        v2 = ComplexPoint(eps * math.cos(phi2), eps * math.sin(phi2))

        w0 = poincare_conformal_map(base_z, c)
        w1 = poincare_conformal_map(base_z + v1, c)
        w2 = poincare_conformal_map(base_z + v2, c)

        dw1 = w1 - w0
        dw2 = w2 - w0

        trans_angle = (dw2.angle() - dw1.angle()) % (2.0 * math.pi)
        diff = abs(trans_angle - expected_angle)
        if diff > math.pi:
            diff = 2.0 * math.pi - diff

        assert diff < 1e-4

    def test_boundary_overflow_defense(self) -> None:
        """Verify BoundaryOverflowError raised when translation point |c| >= 1.0."""
        with pytest.raises(BoundaryOverflowError):
            poincare_conformal_map(ComplexPoint(0.1, 0.1), ComplexPoint(1.0, 0.0))

        with pytest.raises(BoundaryOverflowError):
            poincare_conformal_inverse(ComplexPoint(0.1, 0.1), ComplexPoint(0.8, 0.8))


# ============================================================================
# 4. Geodesic Circle Arc Calculations Between Node Pairs
# ============================================================================

class TestGeodesicCircleArcCalculations:
    """Validate geodesic arc circle geometry, boundary circle orthogonality, and diameters."""

    def test_geodesic_arc_orthogonality(self) -> None:
        """Verify Euclidean circle orthogonal to unit boundary (|c|^2 - R^2 = 1.0, |c - u| = |c - v| = R)."""
        u = ComplexPoint(0.2, 0.3)
        v = ComplexPoint(-0.4, 0.4)

        arc = compute_geodesic_arc(u, v, CANVAS_CENTER_X, CANVAS_CENTER_Y, POINCARE_DISK_RADIUS)
        assert not arc.is_straight_line
        assert arc.center_disk is not None
        assert arc.radius_disk is not None

        c_mag_sq = arc.center_disk.magnitude_squared()
        r_sq = arc.radius_disk * arc.radius_disk
        assert math.isclose(c_mag_sq - r_sq, 1.0, abs_tol=1e-7)

        assert math.isclose((arc.center_disk - u).magnitude(), arc.radius_disk, abs_tol=1e-7)
        assert math.isclose((arc.center_disk - v).magnitude(), arc.radius_disk, abs_tol=1e-7)
        assert " A " in arc.svg_path

    def test_geodesic_collinear_diameter(self) -> None:
        """Verify straight line diameters through origin when collinear."""
        u = ComplexPoint(0.0, 0.0)
        v = ComplexPoint(0.3, 0.6)
        arc = compute_geodesic_arc(u, v, CANVAS_CENTER_X, CANVAS_CENTER_Y, POINCARE_DISK_RADIUS)
        assert arc.is_straight_line
        assert " L " in arc.svg_path

    def test_pixel_and_disk_projection_round_trip(self) -> None:
        """Verify coordinate conversions between screen pixels and unit disk."""
        cx, cy, R = CANVAS_CENTER_X, CANVAS_CENTER_Y, POINCARE_DISK_RADIUS
        for pt in [ComplexPoint(0.0, 0.0), ComplexPoint(0.5, -0.4), ComplexPoint(-0.6, 0.3)]:
            px, py = disk_to_pixel(pt, cx, cy, R)
            rec = pixel_to_disk(px, py, cx, cy, R)
            assert math.isclose(rec.x, pt.x, abs_tol=1e-4)
            assert math.isclose(rec.y, pt.y, abs_tol=1e-4)


# ============================================================================
# 5. SVG Markup Generation, XML Validity, Paths & Labels
# ============================================================================

class TestSVGMarkupGenerationAndXMLValidity:
    """Validate standalone W3C SVG 1.1 vector markup generation and XML structure."""

    def test_svg_markup_xml_validity(self) -> None:
        """Verify SVG header, root tag, viewBox, and ElementTree XML validity."""
        canvas = PoincareMultiscaleCanvas()
        svg_xml = canvas.generate_svg()

        assert svg_xml.startswith("<?xml")
        root = ET.fromstring(svg_xml)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)
        assert root.attrib.get("viewBox") == f"0 0 {CANVAS_VIEWPORT_WIDTH} {CANVAS_VIEWPORT_HEIGHT}"

    def test_svg_visual_elements_and_labels(self) -> None:
        """Verify unit boundary circle, concentric guide rings, 48 geodesic paths, and 32 asset nodes."""
        canvas = PoincareMultiscaleCanvas()
        svg_xml = canvas.generate_svg()
        root = ET.fromstring(svg_xml)

        rects = root.findall(".//{http://www.w3.org/2000/svg}rect") + root.findall(".//rect")
        circles = root.findall(".//{http://www.w3.org/2000/svg}circle") + root.findall(".//circle")
        paths = root.findall(".//{http://www.w3.org/2000/svg}path") + root.findall(".//path")
        texts = root.findall(".//{http://www.w3.org/2000/svg}text") + root.findall(".//text")

        assert len(rects) >= 3      # viewport, badge, hud
        assert len(circles) >= 32   # disk boundary + guide rings + 32 nodes
        assert len(paths) >= 48     # 48 geodesic arcs

        all_text_content = "".join(t.text or "" for t in texts)
        assert "POINCARÉ SCADA HUD" in all_text_content
        assert "%R2250" in all_text_content
        assert "%R2257" in all_text_content
        assert "%M525" in all_text_content
        assert "%M526" in all_text_content
        assert "ASSET TELEMETRY BADGE" in all_text_content


# ============================================================================
# 6. WCAG 2.1 AAA Contrast Compliance (>= 18:1, >= 7:1, >= 3:1)
# ============================================================================

class TestWCAG21AAAContrastCompliance:
    """Validate WCAG 2.1 AAA contrast benchmarks (>= 18:1 badge, >= 7:1 text, >= 3:1 graphics)."""

    def test_decoupled_badge_contrast_ratio(self) -> None:
        """Verify decoupled badge contrast achieves >= 18:1."""
        cr_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr_badge >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert cr_badge >= 18.0

    def test_secondary_text_contrast_ratio(self) -> None:
        """Verify secondary text achieves >= 7:1 contrast on badge."""
        cr_text = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
        assert cr_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr_text >= 7.0

    def test_graphical_indicators_contrast_ratio(self) -> None:
        """Verify graphical indicator colors achieve >= 3:1 contrast against dark background."""
        for col in [COLOR_NOMINAL_EMERALD, COLOR_WARM_AMBER, COLOR_ALARM_CRIMSON, COLOR_FOCUS_BLUE]:
            cr = calculate_contrast_ratio(col, COLOR_DARK_THEME_BACKING)
            assert cr >= 3.0, f"Color {col} failed >= 3:1 contrast benchmark: {cr}"

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """Verify validate_wcag_aaa_contrast helper function."""
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast(
            text_color=COLOR_TEXT_PRIMARY,
            theme_backing=COLOR_DARK_THEME_BACKING,
            badge_backing=COLOR_DECOUPLED_BADGE,
        )
        assert is_aaa is True
        assert badge_cr >= 18.0
        assert text_cr >= 7.0


# ============================================================================
# 7. Boundary Overflow Trip (0x7801) and Conformal Singularity Trip (0x7802)
# ============================================================================

class TestBoundaryOverflowAndConformalSingularityTrips:
    """Validate 0x7801 and 0x7802 fault trips, register updates, and recovery."""

    def test_boundary_overflow_trip_0x7801(self) -> None:
        """Verify 0x7801 Boundary Overflow Trip asserts %M526 and updates %R2257."""
        canvas = PoincareMultiscaleCanvas()
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.boundary_approach_alarm is False

        canvas.inject_boundary_overflow()
        assert canvas.diagnostic_code == 0x7801
        assert canvas.diagnostic_code == DIAG_ERR_BOUNDARY_OVERFLOW_TRIP
        assert canvas.boundary_approach_alarm is True

        assert canvas.reg_table.read_word(REG_POINCARE_CANVAS_DIAGNOSTIC_CODE) == 0x7801
        assert canvas.reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is True

        # Nominal recovery
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.boundary_approach_alarm is False
        assert canvas.reg_table.read_word(REG_POINCARE_CANVAS_DIAGNOSTIC_CODE) == 0
        assert canvas.reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is False

    def test_conformal_singularity_trip_0x7802(self) -> None:
        """Verify 0x7802 Conformal Singularity Trip asserts %M526 and updates %R2257."""
        canvas = PoincareMultiscaleCanvas()

        canvas.inject_conformal_singularity()
        assert canvas.diagnostic_code == 0x7802
        assert canvas.diagnostic_code == DIAG_ERR_CONFORMAL_SINGULARITY_TRIP
        assert canvas.boundary_approach_alarm is True

        assert canvas.reg_table.read_word(REG_POINCARE_CANVAS_DIAGNOSTIC_CODE) == 0x7802
        assert canvas.reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is True

        # Nominal recovery
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.reg_table.read_word(REG_POINCARE_CANVAS_DIAGNOSTIC_CODE) == 0
        assert canvas.reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is False


# ============================================================================
# 8. Boundary Approach Alarm Coil %M526 Assertion
# ============================================================================

class TestBoundaryApproachAlarmCoilAssertion:
    """Validate discrete coil %M526 assertion upon radial threshold approach (>= 0.900)."""

    def test_boundary_approach_radial_threshold(self) -> None:
        """Verify %M526 asserts when max view radius >= BOUNDARY_ALARM_THRESHOLD (0.900)."""
        canvas = PoincareMultiscaleCanvas()
        assert canvas.reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is False

        # Position node 10 at 0.920 radius (> 0.900 threshold)
        canvas.nodes[10].z_view = ComplexPoint(0.92, 0.0)
        canvas.scan_step()

        assert canvas.boundary_approach_alarm is True
        assert canvas.reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is True

        # Restore within safe threshold
        canvas.nodes[10].z_view = canvas.nodes[10].z_canonical
        canvas.scan_step()

        assert canvas.boundary_approach_alarm is False
        assert canvas.reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is False


# ============================================================================
# 9. Horner OCS Register Synchronization & 50-Step Scan Cycle Soak Stability
# ============================================================================

class TestHornerOCSSynchronizationAndScanCycleSoak:
    """Validate register synchronization across %R2250..%R2257 and 50-step scan cycle stability."""

    def test_nominal_register_synchronization(self) -> None:
        """Verify registers %R2250..%R2257 and coils %M525..%M526 under nominal scan."""
        reg_table = RegisterTable()
        canvas = PoincareMultiscaleCanvas(reg_table=reg_table)
        canvas.scan_step(dt=0.01)

        assert reg_table.read_word(REG_POINCARE_TOTAL_NODES_COUNT) == 32
        assert reg_table.read_word(REG_POINCARE_HIERARCHY_LEVELS) == 5
        assert reg_table.read_word(REG_HYPERBOLIC_RADIUS_SCALED) == 850
        assert reg_table.read_word(REG_SELECTED_POINCARE_NODE_ID) == 0
        assert reg_table.read_word(REG_CONFORMAL_DISTORTION_FACTOR_SCALED) == 125
        assert reg_table.read_word(REG_EDGE_GEODESIC_COUNT) == 48
        assert reg_table.read_word(REG_NETWORK_DENSITY_SCORE) == 72
        assert reg_table.read_word(REG_POINCARE_CANVAS_DIAGNOSTIC_CODE) == 0

        assert reg_table.read_bit(COIL_POINCARE_CANVAS_ACTIVE) is True
        assert reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is False

    def test_50_step_scan_cycle_soak_stability(self) -> None:
        """Execute 50-step scan cycle soak verifying numerical stability and zero drift."""
        reg_table = RegisterTable()
        canvas = PoincareMultiscaleCanvas(reg_table=reg_table)

        for step in range(50):
            canvas.scan_step(dt=0.01)

            assert reg_table.read_word(REG_POINCARE_TOTAL_NODES_COUNT) == 32
            assert reg_table.read_word(REG_POINCARE_HIERARCHY_LEVELS) == 5
            assert reg_table.read_word(REG_HYPERBOLIC_RADIUS_SCALED) == 850
            assert reg_table.read_word(REG_EDGE_GEODESIC_COUNT) == 48
            assert reg_table.read_word(REG_NETWORK_DENSITY_SCORE) == 72
            assert reg_table.read_word(REG_POINCARE_CANVAS_DIAGNOSTIC_CODE) == 0
            assert reg_table.read_bit(COIL_POINCARE_CANVAS_ACTIVE) is True
            assert reg_table.read_bit(COIL_BOUNDARY_APPROACH_ALARM) is False

    def test_100_step_interactive_recentering_soak(self) -> None:
        """Execute 100 scan cycles cycling across different asset nodes without disk violation."""
        canvas = PoincareMultiscaleCanvas()
        target_nodes = [0, 1, 2, 5, 8, 12, 18, 25, 30]

        for step in range(100):
            target = target_nodes[step % len(target_nodes)]
            canvas.select_node(target, recenter=True)
            canvas.scan_step(dt=0.01)

            assert canvas.selected_node_id == target
            assert canvas.reg_table.read_word(REG_SELECTED_POINCARE_NODE_ID) == target

            # Invariant: all nodes must remain strictly inside the open unit disk
            for node in canvas.nodes.values():
                assert node.z_view.magnitude() < 1.0


# ============================================================================
# 10. Pure IEC 61131-3 ST POU & SecurityGuard AST Validation
# ============================================================================

class TestPureSTPOUValidationAndSecurityGuard:
    """Validate Pure ST POU grammar, AST variable memory_address bindings, and helpers."""

    def test_pure_st_pou_ast_variable_memory_addresses(self) -> None:
        """Validate pure ST POU grammar and Horner memory bindings."""
        SecurityGuard.assert_pure_st_content(POINCARE_MULTISCALE_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(POINCARE_MULTISCALE_CANVAS_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "PoincareMultiscaleCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        vmap = {v.name: v.address_binding for v in pou.variables}
        assert vmap["PoincareTotalNodesCount"] == "%R2250"
        assert vmap["PoincareHierarchyLevels"] == "%R2251"
        assert vmap["HyperbolicRadiusScaled"] == "%R2252"
        assert vmap["SelectedPoincareNodeId"] == "%R2253"
        assert vmap["ConformalDistortionFactorScaled"] == "%R2254"
        assert vmap["EdgeGeodesicCount"] == "%R2255"
        assert vmap["NetworkDensityScore"] == "%R2256"
        assert vmap["PoincareCanvasDiagnosticCode"] == "%R2257"
        assert vmap["PoincareCanvasActive"] == "%M525"
        assert vmap["BoundaryApproachAlarm"] == "%M526"

        assert "%R2250" in pou.bound_registers
        assert "%R2257" in pou.bound_registers
        assert "%M525" in pou.bound_registers
        assert "%M526" in pou.bound_registers

    def test_pure_st_convenience_verifier(self) -> None:
        """Verify convenience verification functions."""
        assert verify_poincare_multiscale_canvas_pure_st() is True


# ============================================================================
# 11. Anti-Ladder Security Guard Interception
# ============================================================================

class TestAntiLadderRejection:
    """Verify SecurityGuard intercepts all forbidden ladder logic constructs."""

    def test_ladder_construct_rejection(self) -> None:
        """Fail-closed rejection of ladder contacts, coils, rungs, and mnemonics."""
        ladder_snippets = [
            ("Contacts", "PROGRAM Bad VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"),
            ("Coils", "PROGRAM Bad VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"),
            ("Rung", "PROGRAM Bad\nRUNG 1:\nEND_PROGRAM"),
            ("Network", "PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM"),
            ("Mnemonic_XIC", "PROGRAM Bad\nXIC bit1;\nEND_PROGRAM"),
            ("Mnemonic_OTE", "PROGRAM Bad\nOTE bit2;\nEND_PROGRAM"),
            ("Inverted_Contact", "PROGRAM Bad\n---[/]---\nEND_PROGRAM"),
            ("Inverted_Coil", "PROGRAM Bad\n---(/)---\nEND_PROGRAM"),
        ]
        for name, snippet in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 12. Deterministic 9-Stage Verification Suite & Contract
# ============================================================================

class TestVerificationRunnerContract:
    """Validate deterministic 9-stage verification runner and strict 4-state contract."""

    def test_verification_runner_execution(self) -> None:
        """Execute verification runner and verify report and generated artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_p = str(Path(tmpdir) / "evidence.json")
            svg_p = str(Path(tmpdir) / "sample.svg")
            report = run_poincare_multiscale_canvas_verification(
                output_path=ev_p,
                sample_svg_path=svg_p,
            )

            assert report["status"] == "success"
            assert report["error_code"] is None
            assert report["data"]["checks_passed"] == 9
            assert report["data"]["total_checks"] == 9
            assert Path(ev_p).exists()
            assert Path(svg_p).exists()
