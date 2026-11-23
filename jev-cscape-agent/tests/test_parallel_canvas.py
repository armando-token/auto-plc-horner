"""Comprehensive pytest test suite for Cscape HMI Dynamic Parallel Coordinates Canvas (W165).

Work Package: W165 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1260..%R1267, %M294..%M295).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: 6 vertical parallel coordinate axes geometry, spacing, and range scaling.
4. Section 4: Dual polyline trajectory synthesis (Golden Baseline dashed cyan vs Real-time emerald green).
5. Section 5: Standalone W3C SVG 1.1 XML generation, axis tick lines, vertex markers, and HUD metrics card.
6. Section 6: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
7. Section 7: Process safety trips (0xBE01 envelope breach, 0xBE02 axis out of bounds) and Horner coil assertion (%M294, %M295).
8. Section 8: Horner OCS register space synchronization (%R1260..%R1267, %M294..%M295) with PrivilegeMode.SYSTEM.
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
from jev_cscape.hmi.parallel_canvas import (
    AMBER_GRAPHICAL_CONTRAST_RATIO,
    AxisAlarmState,
    CANONICAL_AXIS_COUNT,
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
    COLOR_GRID_AXIS,
    COLOR_GRID_TICK,
    COLOR_INDIGO,
    COLOR_NOMINAL_GREEN,
    COLOR_PURPLE,
    COLOR_REALTIME_FILL,
    COLOR_REALTIME_NOMINAL,
    COLOR_REALTIME_TRIP,
    COLOR_TARGET_BASELINE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    CRIMSON_GRAPHICAL_CONTRAST_RATIO,
    CYAN_GRAPHICAL_CONTRAST_RATIO,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_AXES_COUNT,
    DEFAULT_AXIS_SPACING,
    DIAG_EVENT_AXIS_OUT_OF_BOUNDS,
    DIAG_EVENT_ENVELOPE_BREACH,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DIAG_EVENT_SAFETY_MARGIN_BREACH,
    DIAG_EVENT_SAFETY_MARGIN_DEVIATION,
    DiagnosticCode,
    EMERALD_GRAPHICAL_CONTRAST_RATIO,
    ENVELOPE_BREACH_THRESHOLD_PCT,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    MAX_ALLOWED_AXES,
    MAX_AXIS_COUNT,
    MIN_ALLOWED_AXES,
    MIN_AXIS_COUNT,
    PARALLEL_CANVAS_PURE_ST_POU,
    PARALLEL_COORDINATE_CANVAS_PURE_ST_POU,
    PARALLEL_ERR_AXIS_OUT_OF_BOUNDS,
    PARALLEL_ERR_ENVELOPE_BREACH,
    PARALLEL_ERR_OK,
    PARALLEL_ERR_RENDER_FAULT,
    PARALLEL_ERR_SAFETY_MARGIN_BREACH,
    PARALLEL_ERR_SAFETY_MARGIN_DEVIATION,
    PARALLEL_PURE_ST_POU,
    PARALLEL_TRAJECTORY_PURE_ST_POU,
    PROCESS_PARALLEL_PURE_ST_POU,
    ParallelAxis,
    ParallelCanvas,
    ParallelCanvasEngine,
    ParallelCanvasStatusBits,
    ParallelCanvasSync,
    ParallelCoordinateCanvas,
    ParallelMetrics,
    ParallelPoint,
    ParallelStatusBits,
    ParallelTrajectoryCanvas,
    ParallelTrajectoryHmiSync,
    ProcessParallelCanvasSync,
    PLOT_X_LEFT,
    PLOT_X_RIGHT,
    AXIS_X_MIN,
    AXIS_X_MAX,
    AXIS_Y_TOP,
    AXIS_Y_BOTTOM,
    AXIS_HEIGHT,
    AXIS_TICK_LEVELS,
    SAFETY_MARGIN_THRESHOLD_PCT,
    SAFETY_MARGIN_TRIP_THRESHOLD_PCT,
    SCADA_PALETTE,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    compute_axis_x_positions,
    compute_baseline_trajectory_points,
    compute_parallel_metrics,
    compute_realtime_trajectory_points,
    create_canonical_parallel_axes,
    create_canonical_parallel_canvas,
    create_mock_scan_context,
    format_polyline_svg_points,
    generate_parallel_canvas_svg,
    hex_to_relative_luminance,
    map_value_to_screen_y,
    run_parallel_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_parallel_canvas_pure_st,
    verify_parallel_pure_st,
    verify_parallel_trajectory_pure_st,
    verify_process_parallel_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Validation (%R1260..%R1267, %M294..%M295)
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1 Check: Verify ParallelCanvasSync POU conforms to IEC 61131-3 Pure ST grammar (%R1260..%R1267, %M294..%M295)."""
    SecurityGuard.assert_pure_st_content(PARALLEL_CANVAS_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(PARALLEL_CANVAS_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "ParallelCanvasSync"
    assert pou.pou_type == POUType.PROGRAM

    var_dict = {v.name: v for v in pou.variables}

    # Verify Word Registers %R1260..%R1267
    assert "OverallTrajectoryScorePct" in var_dict
    assert var_dict["OverallTrajectoryScorePct"].address_binding == "%R1260"
    assert var_dict["OverallTrajectoryScorePct"].data_type == "INT"

    assert "ActiveAxesCount" in var_dict
    assert var_dict["ActiveAxesCount"].address_binding == "%R1261"
    assert var_dict["ActiveAxesCount"].data_type == "INT"

    assert "ThermalEfficiencyPct" in var_dict
    assert var_dict["ThermalEfficiencyPct"].address_binding == "%R1262"
    assert var_dict["ThermalEfficiencyPct"].data_type == "INT"

    assert "ProductPurityPct" in var_dict
    assert var_dict["ProductPurityPct"].address_binding == "%R1263"
    assert var_dict["ProductPurityPct"].data_type == "INT"

    assert "EnergyUtilizationPct" in var_dict
    assert var_dict["EnergyUtilizationPct"].address_binding == "%R1264"
    assert var_dict["EnergyUtilizationPct"].data_type == "INT"

    assert "SafetyMarginPct" in var_dict
    assert var_dict["SafetyMarginPct"].address_binding == "%R1265"
    assert var_dict["SafetyMarginPct"].data_type == "INT"

    assert "SelectedAxisIndex" in var_dict
    assert var_dict["SelectedAxisIndex"].address_binding == "%R1266"
    assert var_dict["SelectedAxisIndex"].data_type == "INT"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1267"
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"

    # Verify Discrete Coils %M294..%M295
    assert "ParallelSafetyTrip" in var_dict
    assert var_dict["ParallelSafetyTrip"].address_binding == "%M294"
    assert var_dict["ParallelSafetyTrip"].data_type == "BOOL"

    assert "ParallelCanvasActive" in var_dict
    assert var_dict["ParallelCanvasActive"].address_binding == "%M295"
    assert var_dict["ParallelCanvasActive"].data_type == "BOOL"

    # Verify pure ST helper functions
    assert verify_parallel_canvas_pure_st() is True
    assert verify_parallel_pure_st() is True
    assert verify_process_parallel_pure_st() is True


def test_parallel_trajectory_st_pou_alias_validation() -> None:
    """Verify ParallelTrajectoryHmiSync POU alias parses cleanly with STParser."""
    SecurityGuard.assert_pure_st_content(PARALLEL_TRAJECTORY_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(PARALLEL_TRAJECTORY_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "ParallelTrajectoryHmiSync"
    assert pou.pou_type == POUType.PROGRAM
    assert verify_parallel_trajectory_pure_st() is True


def test_parallel_coordinate_canvas_st_pou_alias_validation() -> None:
    """Verify ParallelCoordinateCanvasSync POU alias parses cleanly with STParser."""
    SecurityGuard.assert_pure_st_content(PARALLEL_COORDINATE_CANVAS_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(PARALLEL_COORDINATE_CANVAS_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "ParallelCoordinateCanvasSync"
    assert pou.pou_type == POUType.PROGRAM


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_contacts_rejection() -> None:
    """Verify ladder logic contacts ---[ ]--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadParallelContacts
    VAR ParallelCanvasActive : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_coils_rejection() -> None:
    """Verify ladder logic coils ---( )--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadParallelCoils
    VAR ParallelSafetyTrip : BOOL; END_VAR
    ---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_rung_delimiters_rejection() -> None:
    """Verify ladder logic RUNG / NETWORK delimiters trigger LadderForbiddenError."""
    ladder_text1 = """
    PROGRAM BadParallelRung
    RUNG 1:
        ParallelCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text1)

    ladder_text2 = """
    PROGRAM BadParallelNetwork
    NETWORK 1:
        ParallelCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text2)


def test_anti_ladder_mnemonics_rejection() -> None:
    """Verify ladder logic mnemonics XIC / OTE trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadParallelMnemonics
    VAR OverallScore : INT; END_VAR
    XIC %M295 OTE %M294;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


# ============================================================================
# Section 3: 6 Vertical Parallel Coordinate Axes Geometry & Spacing
# ============================================================================

def test_canonical_parallel_axes_geometry_and_parameters() -> None:
    """Verify 6 canonical process trajectory axes conform to engineering specifications."""
    axes = create_canonical_parallel_axes()
    assert len(axes) == 6

    # Axis 0: Thermal Efficiency (%R1262)
    assert axes[0].index == 0
    assert axes[0].name == "Thermal Efficiency"
    assert axes[0].tag == "PARALLEL_THERMAL_EFF"
    assert axes[0].register_addr == "%R1262"
    assert math.isclose(axes[0].target_val, 90.0, abs_tol=1e-3)
    assert math.isclose(axes[0].current_val, 91.0, abs_tol=1e-3)

    # Axis 1: Product Purity (%R1263)
    assert axes[1].index == 1
    assert axes[1].name == "Product Purity"
    assert axes[1].tag == "PARALLEL_PROD_PURITY"
    assert axes[1].register_addr == "%R1263"
    assert math.isclose(axes[1].target_val, 98.0, abs_tol=1e-3)
    assert math.isclose(axes[1].current_val, 98.5, abs_tol=1e-3)

    # Axis 2: Energy Utilization (%R1264)
    assert axes[2].index == 2
    assert axes[2].name == "Energy Utilization"
    assert axes[2].tag == "PARALLEL_ENERGY_UTIL"
    assert axes[2].register_addr == "%R1264"
    assert math.isclose(axes[2].target_val, 85.0, abs_tol=1e-3)
    assert math.isclose(axes[2].current_val, 84.0, abs_tol=1e-3)

    # Axis 3: Catalyst Health
    assert axes[3].index == 3
    assert axes[3].name == "Catalyst Health"
    assert axes[3].tag == "PARALLEL_CATALYST_HEALTH"
    assert math.isclose(axes[3].target_val, 85.0, abs_tol=1e-3)
    assert math.isclose(axes[3].current_val, 88.0, abs_tol=1e-3)

    # Axis 4: Safety Margin (%R1265, trip_low = 25.0%)
    assert axes[4].index == 4
    assert axes[4].name == "Safety Margin"
    assert axes[4].tag == "PARALLEL_SAFETY_MARGIN"
    assert axes[4].register_addr == "%R1265"
    assert axes[4].trip_low == SAFETY_MARGIN_TRIP_THRESHOLD_PCT
    assert math.isclose(axes[4].target_val, 95.0, abs_tol=1e-3)
    assert math.isclose(axes[4].current_val, 92.0, abs_tol=1e-3)

    # Axis 5: Environmental Emission Index
    assert axes[5].index == 5
    assert axes[5].name == "Environmental Emission Index"
    assert axes[5].tag == "PARALLEL_ENV_EMISSION"
    assert math.isclose(axes[5].target_val, 80.0, abs_tol=1e-3)
    assert math.isclose(axes[5].current_val, 77.5, abs_tol=1e-3)

    # Check normalization and safe initial conditions
    for a in axes:
        assert 0.0 <= a.normalized_target <= 1.0
        assert 0.0 <= a.normalized_current <= 1.0
        assert not a.is_out_of_bounds
        assert not a.is_tripped


def test_vertical_axes_horizontal_spacing_and_positions() -> None:
    """Verify horizontal spacing and coordinates for 6 vertical axes across viewport."""
    x_positions = compute_axis_x_positions(6, PLOT_X_LEFT, PLOT_X_RIGHT)
    assert len(x_positions) == 6
    assert math.isclose(x_positions[0], PLOT_X_LEFT, abs_tol=1e-3)
    assert math.isclose(x_positions[-1], PLOT_X_RIGHT, abs_tol=1e-3)

    # Distance between consecutive axes equals DEFAULT_AXIS_SPACING = 124.0 px
    for i in range(5):
        spacing = x_positions[i + 1] - x_positions[i]
        assert math.isclose(spacing, DEFAULT_AXIS_SPACING, abs_tol=1e-3)
        assert math.isclose(spacing, 124.0, abs_tol=1e-3)


def test_vertical_range_scaling_affine_mapping() -> None:
    """Verify affine screen mapping for vertical coordinate axis."""
    # 100% full scale maps to AXIS_Y_TOP (160.0 px)
    y_max = map_value_to_screen_y(100.0, 0.0, 100.0, AXIS_Y_TOP, AXIS_Y_BOTTOM)
    assert math.isclose(y_max, AXIS_Y_TOP, abs_tol=1e-3)
    assert math.isclose(y_max, 160.0, abs_tol=1e-3)

    # 0% scale maps to AXIS_Y_BOTTOM (620.0 px)
    y_min = map_value_to_screen_y(0.0, 0.0, 100.0, AXIS_Y_TOP, AXIS_Y_BOTTOM)
    assert math.isclose(y_min, AXIS_Y_BOTTOM, abs_tol=1e-3)
    assert math.isclose(y_min, 620.0, abs_tol=1e-3)

    # 50% scale maps to midpoint = 160 + (620 - 160) / 2 = 390.0 px
    y_mid = map_value_to_screen_y(50.0, 0.0, 100.0, AXIS_Y_TOP, AXIS_Y_BOTTOM)
    assert math.isclose(y_mid, 390.0, abs_tol=1e-3)

    # Full vertical height equals 460.0 px
    assert math.isclose(AXIS_HEIGHT, 460.0, abs_tol=1e-3)
    assert math.isclose(AXIS_Y_BOTTOM - AXIS_Y_TOP, 460.0, abs_tol=1e-3)


# ============================================================================
# Section 4: Dual Polyline Trajectory Synthesis
# ============================================================================

def test_dual_polyline_trajectory_synthesis() -> None:
    """Verify synthesis of dual polyline trajectories: Golden Baseline vs Real-Time."""
    axes = create_canonical_parallel_axes()
    baseline_pts = compute_baseline_trajectory_points(axes, AXIS_Y_TOP, AXIS_Y_BOTTOM)
    realtime_pts = compute_realtime_trajectory_points(axes, AXIS_Y_TOP, AXIS_Y_BOTTOM)

    assert len(baseline_pts) == 6
    assert len(realtime_pts) == 6

    # Verify X positions align with axes
    for i, a in enumerate(axes):
        assert math.isclose(baseline_pts[i].x, a.x_pos, abs_tol=1e-3)
        assert math.isclose(realtime_pts[i].x, a.x_pos, abs_tol=1e-3)

        expected_b_y = map_value_to_screen_y(a.target_val, a.min_val, a.max_val, AXIS_Y_TOP, AXIS_Y_BOTTOM)
        expected_r_y = map_value_to_screen_y(a.current_val, a.min_val, a.max_val, AXIS_Y_TOP, AXIS_Y_BOTTOM)
        assert math.isclose(baseline_pts[i].y, expected_b_y, abs_tol=1e-3)
        assert math.isclose(realtime_pts[i].y, expected_r_y, abs_tol=1e-3)

    # SVG points string formatting check
    b_str = format_polyline_svg_points(baseline_pts)
    r_str = format_polyline_svg_points(realtime_pts)
    assert len(b_str.split()) == 6
    assert len(r_str.split()) == 6
    assert b_str != r_str


def test_parallel_metrics_calculation() -> None:
    """Verify aggregated trajectory metrics and Horner register scaling."""
    axes = create_canonical_parallel_axes()
    metrics = compute_parallel_metrics(axes)

    assert math.isclose(metrics.overall_trajectory_score_pct, 88.5, abs_tol=1e-3)
    assert metrics.overall_trajectory_score_scaled == 885
    assert metrics.overall_kpi_score_scaled == 885
    assert metrics.active_axes_count == 6
    assert metrics.active_axes_count_reg == 6

    assert math.isclose(metrics.thermal_efficiency_pct, 91.0, abs_tol=1e-3)
    assert metrics.thermal_efficiency_scaled == 910

    assert math.isclose(metrics.product_purity_pct, 98.5, abs_tol=1e-3)
    assert metrics.product_purity_scaled == 985

    assert math.isclose(metrics.energy_utilization_pct, 84.0, abs_tol=1e-3)
    assert metrics.energy_utilization_scaled == 840

    assert math.isclose(metrics.catalyst_health_pct, 88.0, abs_tol=1e-3)

    assert math.isclose(metrics.safety_margin_pct, 92.0, abs_tol=1e-3)
    assert metrics.safety_margin_scaled == 920

    assert math.isclose(metrics.environmental_emission_pct, 77.5, abs_tol=1e-3)

    assert metrics.has_safety_trip is False
    assert metrics.diagnostic_status_code == DIAG_EVENT_OK


# ============================================================================
# Section 5: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def test_standalone_svg_xml_validation() -> None:
    """Verify SVG output is well-formed XML and contains required industrial SVG elements."""
    canvas = create_canonical_parallel_canvas()
    svg_str = canvas.render_svg()

    # Parse with standard XML parser to verify strictly valid XML
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)

    # Check required SVG structure
    assert 'id="canvas-header"' in svg_str
    assert 'id="parallel-diagram"' in svg_str
    assert 'id="parallel-canvas"' in svg_str
    assert 'id="axis-tick-lines"' in svg_str
    assert 'id="tick-marks"' in svg_str
    assert 'id="parallel-axes"' in svg_str
    assert 'id="axis-lines"' in svg_str
    assert 'id="baseline-trajectory"' in svg_str
    assert 'id="realtime-trajectory"' in svg_str
    assert 'id="vertex-markers"' in svg_str
    assert 'id="axis-labels"' in svg_str
    assert 'id="hud-metrics-card"' in svg_str
    assert 'id="kpi-summary-panel"' in svg_str
    assert 'id="overall-score-card"' in svg_str
    assert 'id="axis-breakdown-rows"' in svg_str
    assert 'id="diagnostics-safety-card"' in svg_str


def test_svg_tick_lines_vertex_markers_and_hud_metrics_card() -> None:
    """Verify dual trajectory polylines, vertex markers, and HUD metrics card."""
    canvas = create_canonical_parallel_canvas(selected_axis_index=2)
    svg_str = canvas.render_svg()

    # Dual polyline elements
    assert 'stroke-dasharray' in svg_str
    assert '6,4' in svg_str  # Target baseline dashed line indicator

    # Markers and lines for all 6 axes
    for i in range(6):
        assert f'id="axis-line-{i}"' in svg_str
        assert f'id="vertex-{i}"' in svg_str
        assert f'id="axis-badge-{i}"' in svg_str

    # Selected axis highlight
    assert 'axis-line-selected' in svg_str
    assert 'selected-axis-indicator' in svg_str

    # HUD metrics card text
    assert "PARALLEL TRAJECTORY OVERALL SCORE (%R1260)" in svg_str
    assert "ACTIVE AXES COUNT (%R1261)" in svg_str
    assert "%R1262 ThermalEfficiencyPct" in svg_str
    assert "%R1263 ProductPurityPct" in svg_str
    assert "%R1264 EnergyUtilizationPct" in svg_str
    assert "%R1265 SafetyMarginPct" in svg_str
    assert "%R1266 SelectedAxisIndex" in svg_str
    assert "%R1267 DiagnosticStatusCode" in svg_str
    assert "%M294 ParallelSafetyTrip" in svg_str
    assert "%M295 ParallelCanvasActive" in svg_str


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

def test_envelope_breach_trip_0xbe01_and_coil_assertion() -> None:
    """Verify 0xBE01 trip when safety margin falls below 25.0%, asserting coil %M294."""
    canvas = create_canonical_parallel_canvas()
    assert canvas.safety_trip is False
    assert canvas.reg_table.read_bit("%M294") is False
    assert canvas.reg_table.read_bit("%M295") is True
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # Trigger envelope breach / safety margin deviation (< 25.0% threshold, e.g. 18.0%)
    canvas.trigger_safety_margin_trip(injected_safety_margin_pct=18.0)

    assert canvas.safety_trip is True
    assert canvas.reg_table.read_bit("%M294") is True
    assert canvas.reg_table.read_bit("%M295") is True
    assert canvas.diagnostic_code == PARALLEL_ERR_ENVELOPE_BREACH
    assert canvas.diagnostic_code == 0xBE01
    assert canvas.diagnostic_code == -16895
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1267")) == 0xBE01)
    assert canvas.reg_table.read_word("%R1265") == 180  # 18.0% scaled x10
    assert bool(canvas.status_bits & ParallelStatusBits.ENVELOPE_BREACH_TRIP)

    # Verify trip status in rendered SVG
    svg_trip = canvas.render_svg()
    assert "ASSERTED (TRIP)" in svg_trip
    assert 'id="anomaly-halos"' in svg_trip
    assert "SAFETY INTERLOCK TRIP: 0xBE01" in svg_trip


def test_axis_out_of_bounds_fault_0xbe02() -> None:
    """Verify 0xBE02 diagnostic trip on process variable out of physical bounds."""
    canvas = create_canonical_parallel_canvas()
    canvas.trigger_axis_out_of_bounds(axis_index=0, injected_val=115.0)

    assert canvas.diagnostic_code == PARALLEL_ERR_AXIS_OUT_OF_BOUNDS
    assert canvas.diagnostic_code == 0xBE02
    assert canvas.diagnostic_code == -16894
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1267")) == 0xBE02)
    assert bool(canvas.status_bits & ParallelStatusBits.AXIS_OUT_OF_BOUNDS_FAULT)


def test_render_fault_0xbe03_and_nominal_reset() -> None:
    """Verify 0xBE03 render fault condition and clean nominal reset."""
    canvas = create_canonical_parallel_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == PARALLEL_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xBE03
    assert canvas.diagnostic_code == -16893
    assert bool(canvas.status_bits & ParallelStatusBits.RENDER_FAULT)

    # Reset nominal state
    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.safety_trip is False
    assert canvas.reg_table.read_bit("%M294") is False
    assert canvas.reg_table.read_bit("%M295") is True
    assert canvas.reg_table.read_word("%R1267") == 0


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization & Scan Cycle
# ============================================================================

def test_horner_register_space_synchronization() -> None:
    """Verify register table synchronization conforms to %R1260..%R1267, %M294..%M295."""
    canvas = create_canonical_parallel_canvas()
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute(ctx)

    reg = canvas.reg_table
    assert reg.read_word("%R1260") == 885  # OverallTrajectoryScorePct (88.5% -> 885)
    assert reg.read_word("%R1261") == 6    # ActiveAxesCount
    assert reg.read_word("%R1262") == 910  # ThermalEfficiencyPct (91.0% -> 910)
    assert reg.read_word("%R1263") == 985  # ProductPurityPct (98.5% -> 985)
    assert reg.read_word("%R1264") == 840  # EnergyUtilizationPct (84.0% -> 840)
    assert reg.read_word("%R1265") == 920  # SafetyMarginPct (92.0% -> 920)
    assert reg.read_word("%R1266") == 0    # SelectedAxisIndex (0)
    assert reg.read_word("%R1267") == 0    # Diag OK

    assert reg.read_bit("%M294") is False  # ParallelSafetyTrip = False
    assert reg.read_bit("%M295") is True   # ParallelCanvasActive = True


def test_interactive_axis_selection_and_scan_cycle() -> None:
    """Verify axis selection and scan cycle trip on envelope breach in %R1265."""
    canvas = create_canonical_parallel_canvas()

    # Select Axis 3 (Catalyst Health)
    canvas.select_axis(3)
    canvas.update_telemetry()
    canvas.sync_to_registers()

    assert canvas.selected_axis_index == 3
    assert canvas.reg_table.read_word("%R1266") == 3

    # Scan cycle execution: Nominal
    ctx = create_mock_scan_context(cycle=1, reg_table=canvas.reg_table)
    canvas.execute_scan(ctx)
    assert canvas.reg_table.read_bit("%M294") is False
    assert canvas.reg_table.read_word("%R1267") == 0

    # Scan cycle execution: Injected low margin into %R1265 (< 250)
    canvas.reg_table.write_word("%R1265", 180, privilege=PrivilegeMode.SYSTEM)  # 18.0% < 25.0%
    canvas.execute_scan(ctx)
    assert canvas.reg_table.read_bit("%M294") is True
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1267")) == PARALLEL_ERR_ENVELOPE_BREACH)


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration
# ============================================================================

def test_run_parallel_canvas_verification_suite(tmp_path: Path) -> None:
    """Execute complete deterministic 9-stage verification suite."""
    ev_path = tmp_path / "parallel_evidence.json"
    svg_path = tmp_path / "parallel_sample.svg"

    report = run_parallel_canvas_verification(
        output_path=str(ev_path),
        sample_svg_path=str(svg_path),
    )

    assert report["status"] == "success"
    assert report["error_code"] is None
    assert report["data"]["work_package"] == "W165"
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
    assert saved_ev["data"]["work_package"] == "W165"

    with open(svg_path, "r", encoding="utf-8") as f:
        saved_svg = f.read()
    assert "<svg" in saved_svg
    assert "</svg>" in saved_svg


# ============================================================================
# DiagnosticCode, Edge Cases & Scan Lifecycle
# ============================================================================

def test_diagnostic_code_edge_cases() -> None:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and hash consistency."""
    code_eb = DiagnosticCode(0xBE01)
    assert code_eb == 0xBE01
    assert code_eb == -16895
    assert code_eb == 48641
    assert int(code_eb) == 48641
    assert hash(code_eb) == hash(48641)
    assert code_eb != "not_an_int"
    assert code_eb != 0x0000

    code_oob = DiagnosticCode(0xBE02)
    assert code_oob == 0xBE02
    assert code_oob == -16894
    assert code_oob == 48642

    code_rf = DiagnosticCode(0xBE03)
    assert code_rf == 0xBE03
    assert code_rf == -16893
    assert code_rf == 48643


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
    c1 = ParallelCanvasSync()
    c2 = ParallelCanvasEngine()
    c3 = ParallelTrajectoryHmiSync()
    c4 = ParallelTrajectoryCanvas()
    c5 = ParallelCoordinateCanvas()
    c6 = ProcessParallelCanvasSync()
    c7 = create_canonical_parallel_canvas()

    for c in (c1, c2, c3, c4, c5, c6, c7):
        assert isinstance(c, ParallelCanvas)

    axes = create_canonical_parallel_axes()
    assert len(axes) == 6

    assert MIN_ALLOWED_AXES == 3
    assert MAX_ALLOWED_AXES == 16
    assert DEFAULT_AXES_COUNT == 6
    assert SAFETY_MARGIN_THRESHOLD_PCT == 25.0
    assert ENVELOPE_BREACH_THRESHOLD_PCT == 15.0


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface execution within simulated Horner PLC scan cycle."""
    canvas = create_canonical_parallel_canvas()
    assert canvas.name == "ParallelCanvasSync"
    assert canvas.priority == 90
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)
    canvas.execute(ctx)
    assert canvas.reg_table.read_bit("%M295") is True

    canvas.step()
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
