"""Comprehensive pytest test suite for Cscape HMI Dynamic Radar / Spider Process KPI Canvas (W162).

Work Package: W162 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1230..%R1237, %M287..%M288).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: 6-axis spider radar geometry, polar-to-Cartesian vertex projection, and regular hexagon/polygon symmetry.
4. Section 4: Concentric grid web calculation, axis rays, and dual polygon path synthesis (target baseline vs real-time).
5. Section 5: Standalone W3C SVG 1.1 XML generation, polygon overlays, vertex markers, and KPI HUD metrics card.
6. Section 6: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
7. Section 7: Process safety trips (0xBB01 safety margin breach, 0xBB02 axis out of bounds) and Horner coil assertion (%M287, %M288).
8. Section 8: Horner OCS register space synchronization (%R1230..%R1237, %M287..%M288).
9. Section 9: 9-stage verification suite integration test writing evidence JSON and sample SVG.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import re
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.radar_canvas import (
    AMBER_GRAPHICAL_CONTRAST_RATIO,
    AxisAlarmState,
    CANONICAL_AXIS_COUNT,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ALERT_HALO,
    COLOR_AMBER,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CRIMSON,
    COLOR_CYAN,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_DISTRESS_RED,
    COLOR_EMERALD,
    COLOR_FOCUS_BLUE,
    COLOR_GRID_WEB,
    COLOR_GRID_WEB_LIGHT,
    COLOR_INDIGO,
    COLOR_NOMINAL_GREEN,
    COLOR_PURPLE,
    COLOR_REALTIME_FILL,
    COLOR_REALTIME_TRIP,
    COLOR_SPOKE,
    COLOR_TARGET_BASELINE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    CONCENTRIC_GRID_LEVELS,
    CRIMSON_GRAPHICAL_CONTRAST_RATIO,
    CYAN_GRAPHICAL_CONTRAST_RATIO,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_AXES_COUNT,
    DIAG_EVENT_AXIS_OUT_OF_BOUNDS,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DIAG_EVENT_SAFETY_MARGIN_BREACH,
    DIAG_EVENT_SAFETY_MARGIN_DEVIATION,
    DiagnosticCode,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    MAX_ALLOWED_AXES,
    MAX_AXIS_COUNT,
    MIN_ALLOWED_AXES,
    MIN_AXIS_COUNT,
    PROCESS_KPI_RADAR_PURE_ST_POU,
    ProcessKpiRadarCanvas,
    ProcessKpiRadarHmiSync,
    RADAR_CANVAS_PURE_ST_POU,
    RADAR_CENTER_X,
    RADAR_CENTER_Y,
    RADAR_ERR_AXIS_OUT_OF_BOUNDS,
    RADAR_ERR_OK,
    RADAR_ERR_RENDER_FAULT,
    RADAR_ERR_SAFETY_MARGIN_BREACH,
    RADAR_ERR_SAFETY_MARGIN_DEVIATION,
    RADAR_MAX_RADIUS,
    RADAR_PURE_ST_POU,
    RADAR_RADIUS,
    RADAR_SPIDER_CANVAS_PURE_ST_POU,
    RadarAxis,
    RadarCanvas,
    RadarCanvasEngine,
    RadarCanvasStatusBits,
    RadarCanvasSync,
    RadarMetrics,
    RadarPoint,
    RadarSpiderCanvasSync,
    RadarStatusBits,
    SAFETY_MARGIN_THRESHOLD_PCT,
    SAFETY_MARGIN_TRIP_THRESHOLD_PCT,
    SCADA_PALETTE,
    SpiderRadarCanvas,
    calculate_contrast_ratio,
    compute_axis_angles,
    compute_concentric_web_polygons,
    compute_radar_metrics,
    compute_realtime_polygon,
    compute_target_baseline_polygon,
    create_canonical_radar_axes,
    create_canonical_radar_canvas,
    create_mock_scan_context,
    format_polygon_svg_points,
    generate_radar_canvas_svg,
    hex_to_relative_luminance,
    polar_to_cartesian,
    run_radar_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_process_kpi_radar_pure_st,
    verify_radar_canvas_pure_st,
    verify_radar_pure_st,
    verify_radar_spider_canvas_pure_st,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Validation (%R1230..%R1237, %M287..%M288)
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1 Check: Verify RadarSpiderCanvasSync POU conforms to IEC 61131-3 Pure ST grammar (%R1230..%R1237, %M287..%M288)."""
    SecurityGuard.assert_pure_st_content(RADAR_SPIDER_CANVAS_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(RADAR_SPIDER_CANVAS_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "RadarSpiderCanvasSync"
    assert pou.pou_type == POUType.PROGRAM

    var_dict = {v.name: v for v in pou.variables}

    # Verify Word Registers %R1230..%R1237
    assert "OverallKpiScorePct" in var_dict
    assert var_dict["OverallKpiScorePct"].address_binding == "%R1230"
    assert var_dict["OverallKpiScorePct"].data_type == "INT"

    assert "ActiveAxesCount" in var_dict
    assert var_dict["ActiveAxesCount"].address_binding == "%R1231"
    assert var_dict["ActiveAxesCount"].data_type == "INT"

    assert "ThermalEfficiencyPct" in var_dict
    assert var_dict["ThermalEfficiencyPct"].address_binding == "%R1232"
    assert var_dict["ThermalEfficiencyPct"].data_type == "INT"

    assert "ProductPurityPct" in var_dict
    assert var_dict["ProductPurityPct"].address_binding == "%R1233"
    assert var_dict["ProductPurityPct"].data_type == "INT"

    assert "EnergyUtilizationPct" in var_dict
    assert var_dict["EnergyUtilizationPct"].address_binding == "%R1234"
    assert var_dict["EnergyUtilizationPct"].data_type == "INT"

    assert "SafetyMarginPct" in var_dict
    assert var_dict["SafetyMarginPct"].address_binding == "%R1235"
    assert var_dict["SafetyMarginPct"].data_type == "INT"

    assert "SelectedAxisIndex" in var_dict
    assert var_dict["SelectedAxisIndex"].address_binding == "%R1236"
    assert var_dict["SelectedAxisIndex"].data_type == "INT"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1237"
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"

    # Verify Discrete Coils %M287..%M288
    assert "RadarSafetyTrip" in var_dict
    assert var_dict["RadarSafetyTrip"].address_binding == "%M287"
    assert var_dict["RadarSafetyTrip"].data_type == "BOOL"

    assert "RadarCanvasActive" in var_dict
    assert var_dict["RadarCanvasActive"].address_binding == "%M288"
    assert var_dict["RadarCanvasActive"].data_type == "BOOL"

    # Verify pure ST helper functions
    assert verify_radar_spider_canvas_pure_st() is True
    assert verify_radar_canvas_pure_st() is True
    assert verify_radar_pure_st() is True


def test_process_kpi_radar_st_pou_alias_validation() -> None:
    """Verify ProcessKpiRadarHmiSync POU alias parses cleanly with STParser."""
    SecurityGuard.assert_pure_st_content(PROCESS_KPI_RADAR_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(PROCESS_KPI_RADAR_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "ProcessKpiRadarHmiSync"
    assert pou.pou_type == POUType.PROGRAM
    assert verify_process_kpi_radar_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_contacts_rejection() -> None:
    """Verify ladder logic contacts ---[ ]--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadRadarContacts
    VAR RadarCanvasActive : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_coils_rejection() -> None:
    """Verify ladder logic coils ---( )--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadRadarCoils
    VAR RadarSafetyTrip : BOOL; END_VAR
    ---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_rung_delimiters_rejection() -> None:
    """Verify ladder logic RUNG / NETWORK delimiters trigger LadderForbiddenError."""
    ladder_text1 = """
    PROGRAM BadRadarRung
    RUNG 1:
        RadarCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text1)

    ladder_text2 = """
    PROGRAM BadRadarNetwork
    NETWORK 1:
        RadarCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text2)


def test_anti_ladder_mnemonics_rejection() -> None:
    """Verify ladder logic mnemonics XIC / OTE trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadRadarMnemonics
    VAR OverallKpi : INT; END_VAR
    XIC %M288 OTE %M287;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


# ============================================================================
# Section 3: 6-Axis Spider Radar Geometry & Regular Hexagon Symmetry
# ============================================================================

def test_canonical_radar_axes_geometry_and_parameters() -> None:
    """Verify 6 canonical process KPI axes conform to engineering specifications."""
    axes = create_canonical_radar_axes()
    assert len(axes) == 6

    # Axis 0: Thermal Efficiency (%R1232)
    assert axes[0].index == 0
    assert axes[0].name == "Thermal Efficiency"
    assert axes[0].tag == "KPI_THERMAL_EFF"
    assert axes[0].register_addr == "%R1232"
    assert math.isclose(axes[0].target_val, 90.0, abs_tol=1e-3)
    assert math.isclose(axes[0].current_val, 91.0, abs_tol=1e-3)

    # Axis 1: Product Purity (%R1233)
    assert axes[1].index == 1
    assert axes[1].name == "Product Purity"
    assert axes[1].tag == "KPI_PROD_PURITY"
    assert axes[1].register_addr == "%R1233"
    assert math.isclose(axes[1].target_val, 98.0, abs_tol=1e-3)
    assert math.isclose(axes[1].current_val, 98.5, abs_tol=1e-3)

    # Axis 2: Energy Utilization (%R1234)
    assert axes[2].index == 2
    assert axes[2].name == "Energy Utilization"
    assert axes[2].tag == "KPI_ENERGY_UTIL"
    assert axes[2].register_addr == "%R1234"
    assert math.isclose(axes[2].target_val, 85.0, abs_tol=1e-3)
    assert math.isclose(axes[2].current_val, 84.0, abs_tol=1e-3)

    # Axis 3: Catalyst Health
    assert axes[3].index == 3
    assert axes[3].name == "Catalyst Health"
    assert axes[3].tag == "KPI_CATALYST_HEALTH"
    assert math.isclose(axes[3].target_val, 85.0, abs_tol=1e-3)
    assert math.isclose(axes[3].current_val, 88.0, abs_tol=1e-3)

    # Axis 4: Safety Margin (%R1235, trip_low = 25.0%)
    assert axes[4].index == 4
    assert axes[4].name == "Safety Margin"
    assert axes[4].tag == "KPI_SAFETY_MARGIN"
    assert axes[4].register_addr == "%R1235"
    assert axes[4].trip_low == SAFETY_MARGIN_TRIP_THRESHOLD_PCT
    assert math.isclose(axes[4].target_val, 95.0, abs_tol=1e-3)
    assert math.isclose(axes[4].current_val, 92.0, abs_tol=1e-3)

    # Axis 5: Environmental Emission Index
    assert axes[5].index == 5
    assert axes[5].name == "Environmental Emission Index"
    assert axes[5].tag == "KPI_ENV_EMISSION"
    assert math.isclose(axes[5].target_val, 80.0, abs_tol=1e-3)
    assert math.isclose(axes[5].current_val, 77.5, abs_tol=1e-3)

    # Check normalization and safe initial conditions
    for a in axes:
        assert 0.0 <= a.normalized_target <= 1.0
        assert 0.0 <= a.normalized_current <= 1.0
        assert not a.is_out_of_bounds
        assert not a.is_tripped


def test_polar_to_cartesian_projection_and_axes_angles() -> None:
    """Verify polar-to-Cartesian vertex projection angles and coordinates."""
    angles = compute_axis_angles(6)
    assert len(angles) == 6

    # Top vertex (index 0, theta = 0): directly UP from center (12 o'clock)
    pt0 = polar_to_cartesian(angles[0], RADAR_MAX_RADIUS, RADAR_CENTER_X, RADAR_CENTER_Y, 0)
    assert math.isclose(pt0.x, RADAR_CENTER_X, abs_tol=1e-2)
    assert math.isclose(pt0.y, RADAR_CENTER_Y - RADAR_MAX_RADIUS, abs_tol=1e-2)

    # All spoke angles are separated by 60 degrees (pi / 3 radians)
    for i in range(6):
        a_curr = angles[i]
        a_next = angles[(i + 1) % 6]
        diff = (a_next - a_curr) % (2.0 * math.pi)
        assert math.isclose(diff, math.pi / 3.0, abs_tol=1e-5)


def test_regular_hexagon_symmetry_and_invariants() -> None:
    """Verify regular hexagonal polygon symmetry: distances, side lengths, centroid, area."""
    angles = compute_axis_angles(6)
    vertices = [
        polar_to_cartesian(angles[i], RADAR_MAX_RADIUS, RADAR_CENTER_X, RADAR_CENTER_Y, i)
        for i in range(6)
    ]

    # Check 1: All vertices are equidistant from center (r == RADAR_MAX_RADIUS)
    for pt in vertices:
        dist = math.hypot(pt.x - RADAR_CENTER_X, pt.y - RADAR_CENTER_Y)
        assert math.isclose(dist, RADAR_MAX_RADIUS, abs_tol=0.5)

    # Check 2: Side length between consecutive vertices equals radius (R) for regular hexagon
    for i in range(6):
        p1 = vertices[i]
        p2 = vertices[(i + 1) % 6]
        side = math.hypot(p2.x - p1.x, p2.y - p1.y)
        assert math.isclose(side, RADAR_MAX_RADIUS, abs_tol=0.5)

    # Check 3: Centroid matches canvas center
    mean_x = sum(p.x for p in vertices) / 6.0
    mean_y = sum(p.y for p in vertices) / 6.0
    assert math.isclose(mean_x, RADAR_CENTER_X, abs_tol=0.5)
    assert math.isclose(mean_y, RADAR_CENTER_Y, abs_tol=0.5)

    # Check 4: Regular hexagon theoretical area = (3 * sqrt(3) / 2) * R^2
    expected_area = (3.0 * math.sqrt(3.0) / 2.0) * (RADAR_MAX_RADIUS ** 2)
    shoelace_area = 0.5 * abs(
        sum(vertices[i].x * vertices[(i + 1) % 6].y - vertices[(i + 1) % 6].x * vertices[i].y for i in range(6))
    )
    assert math.isclose(shoelace_area, expected_area, rel_tol=1e-3)


# ============================================================================
# Section 4: Concentric Grid Web Calculation & Dual Polygon Path Synthesis
# ============================================================================

def test_concentric_grid_web_rings() -> None:
    """Verify 5 concentric regular polygonal web rings at 20%, 40%, 60%, 80%, 100%."""
    web_rings = compute_concentric_web_polygons(
        center_x=RADAR_CENTER_X,
        center_y=RADAR_CENTER_Y,
        max_radius=RADAR_MAX_RADIUS,
        num_axes=6,
        levels=CONCENTRIC_GRID_LEVELS,
    )
    assert len(web_rings) == 5

    for idx, ring in enumerate(web_rings):
        assert len(ring) == 6
        expected_r = RADAR_MAX_RADIUS * CONCENTRIC_GRID_LEVELS[idx]
        for pt in ring:
            d = math.hypot(pt.x - RADAR_CENTER_X, pt.y - RADAR_CENTER_Y)
            assert math.isclose(d, expected_r, abs_tol=0.5)

        # SVG points formatting check
        pts_str = format_polygon_svg_points(ring)
        assert len(pts_str.split()) == 6
        assert "," in pts_str


def test_axis_rays_and_spokes_geometry() -> None:
    """Verify 6 axis rays extend radially from center to outer perimeter."""
    angles = compute_axis_angles(6)
    for i in range(6):
        pt = polar_to_cartesian(angles[i], RADAR_MAX_RADIUS, RADAR_CENTER_X, RADAR_CENTER_Y, i)
        ray_len = math.hypot(pt.x - RADAR_CENTER_X, pt.y - RADAR_CENTER_Y)
        assert math.isclose(ray_len, RADAR_MAX_RADIUS, abs_tol=0.5)


def test_dual_polygon_path_synthesis() -> None:
    """Verify synthesis of dual closed SVG polygons: target baseline vs real-time operating point."""
    axes = create_canonical_radar_axes()
    target_pts = compute_target_baseline_polygon(axes, max_radius=RADAR_MAX_RADIUS, center_x=RADAR_CENTER_X, center_y=RADAR_CENTER_Y)
    realtime_pts = compute_realtime_polygon(axes, max_radius=RADAR_MAX_RADIUS, center_x=RADAR_CENTER_X, center_y=RADAR_CENTER_Y)

    assert len(target_pts) == 6
    assert len(realtime_pts) == 6

    # Verify scaling: pt radius equals max_radius * normalized value
    for i, a in enumerate(axes):
        t_r = math.hypot(target_pts[i].x - RADAR_CENTER_X, target_pts[i].y - RADAR_CENTER_Y)
        r_r = math.hypot(realtime_pts[i].x - RADAR_CENTER_X, realtime_pts[i].y - RADAR_CENTER_Y)
        assert math.isclose(t_r, RADAR_MAX_RADIUS * a.normalized_target, abs_tol=0.5)
        assert math.isclose(r_r, RADAR_MAX_RADIUS * a.normalized_current, abs_tol=0.5)


# ============================================================================
# Section 5: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def test_standalone_svg_xml_validation() -> None:
    """Verify SVG output is well-formed XML and contains required industrial SVG elements."""
    canvas = create_canonical_radar_canvas()
    svg_str = canvas.render_svg()

    # Parse with standard XML parser to verify strictly valid XML
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)

    # Check required SVG structure
    assert 'id="canvas-header"' in svg_str
    assert 'id="radar-diagram"' in svg_str
    assert 'id="grid-web"' in svg_str
    assert 'id="radial-spokes"' in svg_str
    assert 'id="target-polygon"' in svg_str
    assert 'id="realtime-polygon"' in svg_str
    assert 'id="vertex-markers"' in svg_str
    assert 'id="kpi-summary-panel"' in svg_str


def test_svg_polygon_overlays_and_kpi_hud_metrics_card() -> None:
    """Verify target and real-time polygon overlays, vertex markers, and HUD metrics card."""
    canvas = create_canonical_radar_canvas(selected_axis_index=2)
    svg_str = canvas.render_svg()

    # Dual polygon elements
    assert 'stroke-dasharray' in svg_str
    assert '6,4' in svg_str  # Target dashed line indicator

    # Markers for all 6 axes
    for i in range(6):
        assert f'id="spoke-{i}"' in svg_str
        assert f'id="axis-badge-{i}"' in svg_str

    # Selected axis highlight
    assert 'spoke-selected' in svg_str

    # HUD metrics card text
    assert "RADAR KPI OVERALL SCORE (%R1230)" in svg_str
    assert "ACTIVE AXES COUNT (%R1231)" in svg_str
    assert "%R1232 ThermalEfficiencyPct" in svg_str
    assert "%R1233 ProductPurityPct" in svg_str
    assert "%R1234 EnergyUtilizationPct" in svg_str
    assert "%R1235 SafetyMarginPct" in svg_str
    assert "%R1236 SelectedAxisIndex" in svg_str
    assert "%R1237 DiagnosticStatusCode" in svg_str
    assert "%M287 RadarSafetyTrip" in svg_str
    assert "%M288 RadarCanvasActive" in svg_str


# ============================================================================
# Section 6: WCAG 2.1 AAA Accessibility & Contrast Targets
# ============================================================================

def test_wcag_aaa_contrast_compliance() -> None:
    """Verify contrast ratios satisfy WCAG 2.1 AAA targets (> 7:1 text, > 3:1 graphical, > 18:1 badge)."""
    # Decoupled dark badge contrast (> 18:1)
    contrast_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    assert contrast_badge >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert contrast_badge > 18.0

    # Primary light text on theme backing (> 7:1)
    contrast_theme = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    assert contrast_theme >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_theme > 7.0

    # Graphical SCADA indicators on dark theme backing (> 3:1)
    contrast_emerald = calculate_contrast_ratio(COLOR_EMERALD, COLOR_DARK_THEME_BACKING)
    assert contrast_emerald >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_cyan = calculate_contrast_ratio(COLOR_CYAN, COLOR_DARK_THEME_BACKING)
    assert contrast_cyan >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_indigo = calculate_contrast_ratio(COLOR_INDIGO, COLOR_DARK_THEME_BACKING)
    assert contrast_indigo >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_amber = calculate_contrast_ratio(COLOR_AMBER, COLOR_DARK_THEME_BACKING)
    assert contrast_amber >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_crimson = calculate_contrast_ratio(COLOR_CRIMSON, COLOR_DARK_THEME_BACKING)
    assert contrast_crimson >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_purple = calculate_contrast_ratio(COLOR_PURPLE, COLOR_DARK_THEME_BACKING)
    assert contrast_purple >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_blue = calculate_contrast_ratio(COLOR_FOCUS_BLUE, COLOR_DARK_THEME_BACKING)
    assert contrast_blue >= WCAG_GRAPHICAL_CONTRAST_TARGET

    # Helper function validation
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0) is True
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, min_contrast=7.0) is True


# ============================================================================
# Section 7: Process Safety Trips & Horner Coil Assertion
# ============================================================================

def test_safety_margin_trip_0xbb01_and_coil_assertion() -> None:
    """Verify 0xBB01 trip when safety margin falls below 25.0%, asserting coil %M287."""
    canvas = create_canonical_radar_canvas()
    assert canvas.safety_trip is False
    assert canvas.reg_table.read_bit("%M287") is False
    assert canvas.reg_table.read_bit("%M288") is True
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # Trigger safety margin deviation (< 25.0% threshold, e.g. 18.0%)
    canvas.trigger_safety_margin_trip(injected_safety_margin_pct=18.0)

    assert canvas.safety_trip is True
    assert canvas.reg_table.read_bit("%M287") is True
    assert canvas.reg_table.read_bit("%M288") is True
    assert canvas.diagnostic_code == RADAR_ERR_SAFETY_MARGIN_DEVIATION
    assert canvas.diagnostic_code == 0xBB01
    assert canvas.diagnostic_code == -17663
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1237")) == 0xBB01)
    assert canvas.reg_table.read_word("%R1235") == 180  # 18.0% scaled x10
    assert bool(canvas.status_bits & RadarStatusBits.SAFETY_MARGIN_TRIP)

    # Verify trip status in rendered SVG
    svg_trip = canvas.render_svg()
    assert "ASSERTED (TRIP)" in svg_trip
    assert 'id="anomaly-halos"' in svg_trip
    assert "SAFETY INTERLOCK TRIP: 0xBB01" in svg_trip


def test_axis_out_of_bounds_fault_0xbb02() -> None:
    """Verify 0xBB02 diagnostic trip on process variable out of physical bounds."""
    canvas = create_canonical_radar_canvas()
    canvas.trigger_axis_out_of_bounds(axis_index=0, injected_val=115.0)

    assert canvas.diagnostic_code == RADAR_ERR_AXIS_OUT_OF_BOUNDS
    assert canvas.diagnostic_code == 0xBB02
    assert canvas.diagnostic_code == -17662
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1237")) == 0xBB02)
    assert bool(canvas.status_bits & RadarStatusBits.AXIS_OUT_OF_BOUNDS_FAULT)


def test_render_fault_0xbb03_and_nominal_reset() -> None:
    """Verify 0xBB03 render fault condition and clean nominal reset."""
    canvas = create_canonical_radar_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == RADAR_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xBB03
    assert canvas.diagnostic_code == -17661
    assert bool(canvas.status_bits & RadarStatusBits.RENDER_FAULT)

    # Reset nominal state
    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.safety_trip is False
    assert canvas.reg_table.read_bit("%M287") is False
    assert canvas.reg_table.read_bit("%M288") is True
    assert canvas.reg_table.read_word("%R1237") == 0


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization & Scan Cycle
# ============================================================================

def test_horner_register_space_synchronization() -> None:
    """Verify register table synchronization conforms to %R1230..%R1237, %M287..%M288."""
    canvas = create_canonical_radar_canvas()
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute(ctx)

    reg = canvas.reg_table
    assert reg.read_word("%R1230") == 885  # OverallKpiScorePct (88.5% -> 885)
    assert reg.read_word("%R1231") == 6    # ActiveAxesCount
    assert reg.read_word("%R1232") == 910  # ThermalEfficiencyPct (91.0% -> 910)
    assert reg.read_word("%R1233") == 985  # ProductPurityPct (98.5% -> 985)
    assert reg.read_word("%R1234") == 840  # EnergyUtilizationPct (84.0% -> 840)
    assert reg.read_word("%R1235") == 920  # SafetyMarginPct (92.0% -> 920)
    assert reg.read_word("%R1236") == 0    # SelectedAxisIndex (0)
    assert reg.read_word("%R1237") == 0    # Diag OK

    assert reg.read_bit("%M287") is False  # RadarSafetyTrip = False
    assert reg.read_bit("%M288") is True   # RadarCanvasActive = True


def test_interactive_axis_selection_and_scan_cycle() -> None:
    """Verify axis selection and scan cycle trip on safety margin breach in %R1235."""
    canvas = create_canonical_radar_canvas()

    # Select Axis 3 (Catalyst Health)
    canvas.selected_axis_index = 3
    canvas.update_telemetry()
    canvas.sync_to_registers()

    assert canvas.selected_axis_index == 3
    assert canvas.reg_table.read_word("%R1236") == 3

    # Scan cycle execution: Nominal
    ctx = create_mock_scan_context(cycle=1, reg_table=canvas.reg_table)
    canvas.execute_scan(ctx)
    assert canvas.reg_table.read_bit("%M287") is False
    assert canvas.reg_table.read_word("%R1237") == 0

    # Scan cycle execution: Injected low margin into %R1235 (< 250)
    canvas.reg_table.write_word("%R1235", 180, privilege=PrivilegeMode.SYSTEM)  # 18.0% < 25.0%
    canvas.execute_scan(ctx)
    assert canvas.reg_table.read_bit("%M287") is True
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1237")) == RADAR_ERR_SAFETY_MARGIN_DEVIATION)


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration
# ============================================================================

def test_run_radar_canvas_verification_suite(tmp_path: Path) -> None:
    """Execute complete deterministic 9-stage verification suite."""
    ev_path = tmp_path / "radar_evidence.json"
    svg_path = tmp_path / "radar_sample.svg"

    report = run_radar_canvas_verification(
        output_path=str(ev_path),
        sample_svg_path=str(svg_path),
    )

    assert report["status"] == "success"
    assert report["error_code"] is None
    assert report["data"]["work_package"] == "W162"
    assert report["data"]["checks_passed"] == 9
    assert report["data"]["total_checks"] == 9
    assert len(report["data"]["tests"]) == 9

    # Verify all 9 stages passed
    for t in report["data"]["tests"]:
        assert t["passed"] is True, f"Failed stage {t['stage']}: {t['check']}"

    # Verify files created on disk
    assert ev_path.exists()
    assert svg_path.exists()

    with open(ev_path, "r", encoding="utf-8") as f:
        saved_ev = json.load(f)
    assert saved_ev["status"] == "success"
    assert saved_ev["data"]["work_package"] == "W162"

    with open(svg_path, "r", encoding="utf-8") as f:
        saved_svg = f.read()
    assert "<svg" in saved_svg
    assert "</svg>" in saved_svg


# ============================================================================
# DiagnosticCode, Edge Cases & Scan Lifecycle
# ============================================================================

def test_diagnostic_code_edge_cases() -> None:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and hash consistency."""
    code_smb = DiagnosticCode(0xBB01)
    assert code_smb == 0xBB01
    assert code_smb == -17663
    assert code_smb == 47873
    assert int(code_smb) == 47873
    assert hash(code_smb) == hash(47873)
    assert code_smb != "not_an_int"
    assert code_smb != 0x0000

    code_oob = DiagnosticCode(0xBB02)
    assert code_oob == 0xBB02
    assert code_oob == -17662
    assert code_oob == 47874

    code_rf = DiagnosticCode(0xBB03)
    assert code_rf == 0xBB03
    assert code_rf == -17661
    assert code_rf == 47875


def test_color_and_wcag_math_branches() -> None:
    """Verify sRGB channel linear conversion and hex luminance for 3-char and 6-char hex."""
    assert abs(srgb_channel_to_linear(0.02) - (0.02 / 12.92)) < 1e-6
    assert abs(srgb_channel_to_linear(0.5) - (((0.5 + 0.055) / 1.055) ** 2.4)) < 1e-6

    # 3-char hex #FFF vs 6-char #FFFFFF
    lum_white_3 = hex_to_relative_luminance("#FFF")
    lum_white_6 = hex_to_relative_luminance("#FFFFFF")
    assert abs(lum_white_3 - lum_white_6) < 1e-4

    # 3-char hex #000 vs 6-char #000000
    lum_black_3 = hex_to_relative_luminance("#000")
    lum_black_6 = hex_to_relative_luminance("#000000")
    assert abs(lum_black_3 - lum_black_6) < 1e-4


def test_aliases_and_boundary_branches() -> None:
    """Verify class aliases, helper functions, and boundary configurations."""
    c1 = RadarCanvasSync()
    c2 = RadarCanvasEngine()
    c3 = ProcessKpiRadarHmiSync()
    c4 = SpiderRadarCanvas()
    c5 = RadarSpiderCanvasSync()
    c6 = create_canonical_radar_canvas()

    for c in (c1, c2, c3, c4, c5, c6):
        assert isinstance(c, RadarCanvas)

    axes = create_canonical_radar_axes()
    assert len(axes) == 6

    assert MIN_ALLOWED_AXES == 3
    assert MAX_ALLOWED_AXES == 16
    assert DEFAULT_AXES_COUNT == 6
    assert SAFETY_MARGIN_THRESHOLD_PCT == 25.0


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface execution within simulated Horner PLC scan cycle."""
    canvas = create_canonical_radar_canvas()
    assert canvas.name == "RadarSpiderCanvasSync"
    assert canvas.priority == 90
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)
    canvas.execute(ctx)
    assert canvas.reg_table.read_bit("%M288") is True

    canvas.step()
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
