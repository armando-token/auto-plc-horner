"""Comprehensive pytest test suite for Cscape HMI Dynamic Polar / Radar Multi-Axis Spectral Signature SCADA Canvas (W186).

Work Package: W186 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1470..%R1477, %M343..%M344).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: 8-axis polar radar spider geometry, spoke angles theta_0..theta_7, polar to Cartesian projection.
4. Section 4: Concentric polar grid rings & ISO 10816 limits (25%, 50%, 75%, 100%), octagonal web polygons.
5. Section 5: Smooth Bézier splines (Catmull-Rom cubic splines M...C...Z) and linear boundary polygon points.
6. Section 6: Dual-state representation (golden baseline dashed cyan #06B6D4 vs live vibration polygon with glow filter).
7. Section 7: Process safety interlocks (0xD301 resonance trip asserts %M343, 0xD302 bearing demod warning, 0xD303 render fault).
8. Section 8: Standalone W3C SVG 1.1 XML generation, XML validity, dark theme backing, machine train selector, HUD card.
9. Section 9: WCAG 2.1 AAA accessibility and contrast ratio checks (> 18:1 badge, > 7:1 text, > 3:1 graphics).
10. Section 10: Horner OCS memory space synchronization (%R1470..%R1477, %M343..%M344) with PrivilegeMode.SYSTEM.
11. Section 11: ILogicUnit discrete scan cycle execution (scan_step, step, execute).
12. Section 12: Interactive machine train selection (0..3) and diagnostic axis selection.
13. Section 13: DiagnosticCode signed/unsigned 16-bit equality and math.
14. Section 14: Deterministic 9-stage verification suite integration test writing evidence JSON and sample SVG.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.polar_spectral_canvas import (
    AMBER_GRAPHICAL_CONTRAST_RATIO,
    AxisAlarmState,
    BEARING_CREST_FACTOR_WARNING_THRESHOLD,
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
    COLOR_GOLDEN_BASELINE,
    COLOR_GOLDEN_DESIGN,
    COLOR_GRID_LINE,
    COLOR_GRID_WEB,
    COLOR_GRID_WEB_OUTER,
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
    CRITICAL_RESONANCE_TRIP_LIMIT_PCT,
    CYAN_GRAPHICAL_CONTRAST_RATIO,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_AXES_COUNT,
    DIAG_EVENT_BEARING_DEMOD_WARNING,
    DIAG_EVENT_CRITICAL_RESONANCE_TRIP,
    DIAG_EVENT_DEMOD_WARNING,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DIAG_EVENT_RESONANCE_TRIP,
    DiagnosticCode,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    HFE_DEMOD_WARNING_THRESHOLD_PCT,
    ISO10816Zone,
    MachineTrain,
    MAX_AXIS_COUNT,
    MIN_AXIS_COUNT,
    NOMINAL_BEARING_CREST_FACTOR,
    NOMINAL_BEARING_CREST_FACTOR_SCALED,
    NOMINAL_MACHINERY_HEALTH_SCORE_PCT,
    NOMINAL_MACHINERY_HEALTH_SCORE_SCALED,
    NOMINAL_MAX_SPECTRAL_AXIS_SCORE_PCT,
    NOMINAL_MAX_SPECTRAL_AXIS_SCORE_SCALED,
    NOMINAL_OVERALL_VIB_RMS,
    NOMINAL_OVERALL_VIB_RMS_SCALED,
    NOMINAL_PEAK_HARMONIC_ORDER,
    NOMINAL_PEAK_HARMONIC_ORDER_SCALED,
    NOMINAL_SELECTED_MACHINE_INDEX,
    NOMINAL_SPECTRAL_ENTROPY_SCORE_PCT,
    NOMINAL_SPECTRAL_ENTROPY_SCORE_SCALED,
    POLAR_CENTER_X,
    POLAR_CENTER_Y,
    POLAR_MAX_RADIUS,
    POLAR_RADIUS,
    POLAR_SPECTRAL_CANVAS_PURE_ST_POU,
    POLAR_SPECTRAL_PURE_ST_POU,
    PolarPoint,
    PolarSpectralCanvas,
    PolarSpectralCanvasEngine,
    PolarSpectralCanvasStatusBits,
    PolarSpectralCanvasSync,
    PolarSpectralSignatureCanvas,
    PolarSpectralSignatureCanvasSync,
    PolarSpectralStatusBits,
    SCADA_PALETTE,
    SPECTRAL_ERR_BEARING_DEMOD_WARNING,
    SPECTRAL_ERR_CRITICAL_RESONANCE_TRIP,
    SPECTRAL_ERR_DEMOD_WARNING,
    SPECTRAL_ERR_OK,
    SPECTRAL_ERR_RENDER_FAULT,
    SPECTRAL_ERR_RESONANCE_TRIP,
    SPECTRAL_SIGNATURE_RADAR_PURE_ST_POU,
    SpectralAxis,
    SpectralAxisAlarmState,
    SpectralMetrics,
    SpectralSignatureRadarCanvas,
    SpectralSignatureRadarHmiSync,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    compute_axis_angles,
    compute_concentric_polar_rings,
    compute_concentric_web_points,
    compute_live_signature_polygon_points,
    compute_spectral_axis_angles,
    compute_spectral_metrics,
    compute_target_baseline_polygon_points,
    create_canonical_machine_trains,
    create_canonical_polar_canvas,
    create_canonical_polar_spectral_canvas,
    create_canonical_spectral_axes,
    create_canonical_spectral_canvas,
    create_mock_scan_context,
    format_polar_polygon_points,
    generate_polar_spectral_canvas_svg,
    generate_smooth_bezier_spline_path,
    hex_to_relative_luminance,
    polar_to_cartesian,
    run_polar_spectral_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_polar_spectral_canvas_pure_st,
    verify_polar_spectral_pure_st,
    verify_spectral_signature_radar_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Symbol Binding Validation
# ============================================================================

def test_pure_st_pou_ast_parsing() -> None:
    """Verify primary PolarSpectralSignatureCanvasSync ST POU conforms to pure ST."""
    SecurityGuard.assert_pure_st_content(POLAR_SPECTRAL_CANVAS_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(POLAR_SPECTRAL_CANVAS_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "PolarSpectralSignatureCanvasSync"
    assert pou.pou_type == POUType.PROGRAM

    var_dict = {v.name: v for v in pou.variables}

    # Verify Bound Word Registers %R1470..%R1477
    assert "OverallVibrationRmsScaled" in var_dict
    assert var_dict["OverallVibrationRmsScaled"].address_binding == "%R1470"
    assert var_dict["OverallVibrationRmsScaled"].data_type == "INT"

    assert "MaxSpectralAxisScoreScaled" in var_dict
    assert var_dict["MaxSpectralAxisScoreScaled"].address_binding == "%R1471"
    assert var_dict["MaxSpectralAxisScoreScaled"].data_type == "INT"

    assert "SelectedMachineIndex" in var_dict
    assert var_dict["SelectedMachineIndex"].address_binding == "%R1472"
    assert var_dict["SelectedMachineIndex"].data_type == "INT"

    assert "PeakHarmonicOrderScaled" in var_dict
    assert var_dict["PeakHarmonicOrderScaled"].address_binding == "%R1473"
    assert var_dict["PeakHarmonicOrderScaled"].data_type == "INT"

    assert "BearingCrestFactorScaled" in var_dict
    assert var_dict["BearingCrestFactorScaled"].address_binding == "%R1474"
    assert var_dict["BearingCrestFactorScaled"].data_type == "INT"

    assert "SpectralEntropyScoreScaled" in var_dict
    assert var_dict["SpectralEntropyScoreScaled"].address_binding == "%R1475"
    assert var_dict["SpectralEntropyScoreScaled"].data_type == "INT"

    assert "MachineryHealthScoreScaled" in var_dict
    assert var_dict["MachineryHealthScoreScaled"].address_binding == "%R1476"
    assert var_dict["MachineryHealthScoreScaled"].data_type == "INT"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1477"
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"

    # Verify Discrete Coils %M343..%M344
    assert "MachineryVibrationTrip" in var_dict
    assert var_dict["MachineryVibrationTrip"].address_binding == "%M343"
    assert var_dict["MachineryVibrationTrip"].data_type == "BOOL"

    assert "SpectralCanvasActive" in var_dict
    assert var_dict["SpectralCanvasActive"].address_binding == "%M344"
    assert var_dict["SpectralCanvasActive"].data_type == "BOOL"


def test_alias_st_pou_ast_parsing() -> None:
    """Verify alias SpectralSignatureRadarHmiSync ST POU conforms to pure ST."""
    SecurityGuard.assert_pure_st_content(SPECTRAL_SIGNATURE_RADAR_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(SPECTRAL_SIGNATURE_RADAR_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "SpectralSignatureRadarHmiSync"
    assert pou.pou_type == POUType.PROGRAM

    assert verify_polar_spectral_canvas_pure_st() is True
    assert verify_spectral_signature_radar_pure_st() is True
    assert verify_polar_spectral_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_contacts_rejection() -> None:
    """Verify ladder logic contacts ---[ ]--- trigger LadderForbiddenError."""
    ladder = """
    PROGRAM BadPolarLadderContacts
    VAR SpectralCanvasActive : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder)


def test_anti_ladder_coils_rejection() -> None:
    """Verify ladder logic coils ---( )--- trigger LadderForbiddenError."""
    ladder = """
    PROGRAM BadPolarLadderCoils
    VAR MachineryVibrationTrip : BOOL; END_VAR
    ---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder)


def test_anti_ladder_rung_delimiters_rejection() -> None:
    """Verify ladder logic RUNG and NETWORK delimiters trigger LadderForbiddenError."""
    rung_ladder = """
    PROGRAM BadPolarRung
    RUNG 1:
        SpectralCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(rung_ladder)

    network_ladder = """
    PROGRAM BadPolarNetwork
    NETWORK 1:
        MachineryVibrationTrip := FALSE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(network_ladder)


def test_anti_ladder_mnemonics_rejection() -> None:
    """Verify ladder logic mnemonics XIC and OTE trigger LadderForbiddenError."""
    mnemonic = """
    PROGRAM BadPolarMnemonic
    XIC %M344 OTE %M343
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(mnemonic)


# ============================================================================
# Section 3: 8-Axis Polar Radar Spider Geometry & Spoke Layout
# ============================================================================

def test_canonical_spectral_axes_definition() -> None:
    """Verify all 8 orthogonal spectral diagnostic axes are initialized correctly."""
    axes = create_canonical_spectral_axes()
    assert len(axes) == 8

    expected_tags = [
        "VIB_RMS", "HARMONIC_1X", "HARMONIC_2X", "BPF_FLOW",
        "CREST_FACTOR", "ACOUSTIC_EMISSION", "HFE_DEMOD", "THERMAL_GRADIENT"
    ]
    for i, tag in enumerate(expected_tags):
        assert axes[i].index == i
        assert axes[i].tag == tag

    # Overall Vibration RMS
    assert axes[0].name == "Overall Vibration RMS"
    assert axes[0].unit == "mm/s"
    assert math.isclose(axes[0].current_val, 4.25, abs_tol=1e-4)
    assert math.isclose(axes[0].trip_limit, 7.10, abs_tol=1e-4)

    # Bearing Crest Factor
    assert axes[4].name == "Bearing Crest Factor"
    assert axes[4].unit == "ratio"
    assert math.isclose(axes[4].current_val, 3.80, abs_tol=1e-4)
    assert axes[4].warning_limit == 4.50

    # HFE Demod
    assert axes[6].name == "High-Frequency Demodulation (HFE)"
    assert axes[6].unit == "g-pk"
    assert math.isclose(axes[6].score_pct, 74.2, abs_tol=0.1)


def test_polar_angles_and_cartesian_projection() -> None:
    """Verify spoke angle layout and polar to Cartesian mapping."""
    angles = compute_spectral_axis_angles(8)
    assert len(angles) == 8

    # Each spoke separated by 45 degrees (pi/4)
    for i in range(7):
        assert math.isclose(angles[i + 1] - angles[i], math.pi / 4.0, abs_tol=1e-5)

    # Top spoke at theta = 0 (12 o'clock)
    pt0 = polar_to_cartesian(angles[0], POLAR_MAX_RADIUS, POLAR_CENTER_X, POLAR_CENTER_Y, 0)
    assert math.isclose(pt0.x, POLAR_CENTER_X, abs_tol=1e-4)
    assert math.isclose(pt0.y, POLAR_CENTER_Y - POLAR_MAX_RADIUS, abs_tol=1e-4)

    # Right spoke at theta = pi/2 (3 o'clock)
    pt2 = polar_to_cartesian(angles[2], POLAR_MAX_RADIUS, POLAR_CENTER_X, POLAR_CENTER_Y, 2)
    assert math.isclose(pt2.x, POLAR_CENTER_X + POLAR_MAX_RADIUS, abs_tol=1e-4)
    assert math.isclose(pt2.y, POLAR_CENTER_Y, abs_tol=1e-4)

    # Bottom spoke at theta = pi (6 o'clock)
    pt4 = polar_to_cartesian(angles[4], POLAR_MAX_RADIUS, POLAR_CENTER_X, POLAR_CENTER_Y, 4)
    assert math.isclose(pt4.x, POLAR_CENTER_X, abs_tol=1e-4)
    assert math.isclose(pt4.y, POLAR_CENTER_Y + POLAR_MAX_RADIUS, abs_tol=1e-4)

    # Left spoke at theta = 3*pi/2 (9 o'clock)
    pt6 = polar_to_cartesian(angles[6], POLAR_MAX_RADIUS, POLAR_CENTER_X, POLAR_CENTER_Y, 6)
    assert math.isclose(pt6.x, POLAR_CENTER_X - POLAR_MAX_RADIUS, abs_tol=1e-4)
    assert math.isclose(pt6.y, POLAR_CENTER_Y, abs_tol=1e-4)


# ============================================================================
# Section 4: Concentric Polar Grid Rings & ISO 10816 Limit Levels
# ============================================================================

def test_concentric_polar_grid_rings() -> None:
    """Verify 4 concentric polar rings at 25%, 50%, 75%, 100% ISO 10816 limits."""
    rings = compute_concentric_polar_rings(POLAR_CENTER_X, POLAR_CENTER_Y, POLAR_MAX_RADIUS)
    assert len(rings) == 4

    levels = [r[1] for r in rings]
    assert levels == [0.25, 0.50, 0.75, 1.00]

    # Verify calculated radii
    radii = [r[0] for r in rings]
    assert math.isclose(radii[0], POLAR_MAX_RADIUS * 0.25, abs_tol=1e-4)
    assert math.isclose(radii[1], POLAR_MAX_RADIUS * 0.50, abs_tol=1e-4)
    assert math.isclose(radii[2], POLAR_MAX_RADIUS * 0.75, abs_tol=1e-4)
    assert math.isclose(radii[3], POLAR_MAX_RADIUS * 1.00, abs_tol=1e-4)


def test_concentric_web_points() -> None:
    """Verify regular octagonal grid web polygon calculation."""
    web_pts = compute_concentric_web_points(8, 0.50, POLAR_MAX_RADIUS, POLAR_CENTER_X, POLAR_CENTER_Y)
    assert len(web_pts) == 8
    for pt in web_pts:
        assert math.isclose(pt.radius, POLAR_MAX_RADIUS * 0.50, abs_tol=1e-4)


# ============================================================================
# Section 5: Smooth Bézier Splines & Linear Polygon Synthesis
# ============================================================================

def test_bezier_spline_path_synthesis() -> None:
    """Verify Catmull-Rom cubic Bézier spline synthesis generates C1-continuous SVG path."""
    points = [(100.0, 100.0), (200.0, 50.0), (300.0, 150.0), (150.0, 250.0)]
    path_d = generate_smooth_bezier_spline_path(points, closed=True)

    assert path_d.startswith("M 100.00,100.00")
    assert " C " in path_d
    assert path_d.endswith("Z")

    # Degenerate cases
    assert generate_smooth_bezier_spline_path([], closed=True) == ""
    assert generate_smooth_bezier_spline_path([(10.0, 20.0)], closed=True) == "M 10.00,20.00"
    assert generate_smooth_bezier_spline_path([(10.0, 20.0), (30.0, 40.0)], closed=True) == "M 10.00,20.00 L 30.00,40.00"


def test_linear_polygon_formatting() -> None:
    """Verify format_polar_polygon_points converts PolarPoint list to SVG points string."""
    pts = [
        PolarPoint(10.0, 20.0, 50.0, 0.0, 0),
        PolarPoint(30.0, 40.0, 50.0, 1.0, 1),
    ]
    res = format_polar_polygon_points(pts)
    assert res == "10.00,20.00 30.00,40.00"


# ============================================================================
# Section 6: Dual-State Representation (Golden Baseline vs Live Signature)
# ============================================================================

def test_dual_state_rendering_in_svg() -> None:
    """Verify SVG contains both golden baseline (dashed cyan) and live vibration signature."""
    canvas = create_canonical_polar_spectral_canvas()
    svg = canvas.render_svg()

    # Golden baseline elements
    assert 'id="golden-baseline-signature"' in svg
    assert 'id="golden-baseline-polygon"' in svg
    assert 'id="golden-baseline-bezier"' in svg
    assert COLOR_GOLDEN_BASELINE in svg
    assert 'stroke-dasharray="6,4"' in svg

    # Live vibration signature elements
    assert 'id="live-spectral-signature"' in svg
    assert 'id="live-signature-polygon"' in svg
    assert 'id="live-signature-bezier"' in svg
    assert 'filter="url(#spectral-glow)"' in svg


# ============================================================================
# Section 7: Process Safety Interlocks & Diagnostics
# ============================================================================

def test_critical_resonance_trip_0xd301() -> None:
    """Verify 0xD301 trip when harmonic axis exceeds 100% limit, asserting coil %M343."""
    canvas = create_canonical_polar_spectral_canvas()
    assert canvas.vibration_trip is False
    assert canvas.reg_table.read_bit("%M343") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # Trigger trip
    canvas.trigger_critical_resonance_trip(axis_index=1, score_pct=105.0)
    assert canvas.vibration_trip is True
    assert canvas.reg_table.read_bit("%M343") is True
    assert canvas.diagnostic_code == SPECTRAL_ERR_CRITICAL_RESONANCE_TRIP
    assert canvas.diagnostic_code == 0xD301
    assert canvas.diagnostic_code == -11519
    assert DiagnosticCode(canvas.reg_table.read_word("%R1477")) == 0xD301


def test_bearing_demod_warning_0xd302() -> None:
    """Verify 0xD302 warning when bearing crest factor >= 4.5, with %M343 remaining False."""
    canvas = create_canonical_polar_spectral_canvas()
    canvas.trigger_bearing_demod_warning(crest_factor=5.2)

    assert canvas.vibration_trip is False
    assert canvas.reg_table.read_bit("%M343") is False
    assert canvas.diagnostic_code == SPECTRAL_ERR_BEARING_DEMOD_WARNING
    assert canvas.diagnostic_code == 0xD302
    assert canvas.diagnostic_code == -11518
    assert DiagnosticCode(canvas.reg_table.read_word("%R1477")) == 0xD302


def test_render_fault_0xd303() -> None:
    """Verify 0xD303 render fault code assignment."""
    canvas = create_canonical_polar_spectral_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == SPECTRAL_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xD303
    assert canvas.diagnostic_code == -11517
    assert DiagnosticCode(canvas.reg_table.read_word("%R1477")) == 0xD303


def test_nominal_restoration() -> None:
    """Verify clean restoration of nominal operating state after trip."""
    canvas = create_canonical_polar_spectral_canvas()
    canvas.trigger_critical_resonance_trip()
    assert canvas.vibration_trip is True

    canvas.reset_nominal()
    assert canvas.vibration_trip is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.reg_table.read_bit("%M343") is False
    assert DiagnosticCode(canvas.reg_table.read_word("%R1477")) == 0x0000


# ============================================================================
# Section 8: Standalone W3C SVG 1.1 Vector Canvas & XML Validity
# ============================================================================

def test_svg_xml_validity_and_dimensions() -> None:
    """Verify SVG is valid standalone XML and conforms to 1200x750 viewport."""
    canvas = create_canonical_polar_spectral_canvas()
    svg = canvas.render_svg()

    # XML Parser validation
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == "1200"
    assert root.attrib["height"] == "750"

    # Core Structural Groups
    assert 'id="canvas-header"' in svg
    assert 'id="machine-train-selector"' in svg
    assert 'id="polar-spectral-spider"' in svg
    assert 'id="machinery-health-hud"' in svg
    assert COLOR_DARK_THEME_BACKING in svg


# ============================================================================
# Section 9: WCAG 2.1 AAA Accessibility & Contrast Ratio Checks
# ============================================================================

def test_wcag_aaa_contrast_compliance() -> None:
    """Verify color pairs meet WCAG 2.1 AAA targets (> 18:1 badge, > 7:1 text, > 3:1 graphics)."""
    # Decoupled dark badge contrast (> 18:1)
    contrast_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    assert contrast_badge >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert contrast_badge > 18.0

    # Primary light text on theme backing (> 7:1)
    contrast_theme = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    assert contrast_theme >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_theme > 7.0

    # Graphical SCADA colors on dark theme backing (> 3:1)
    contrast_cyan = calculate_contrast_ratio(COLOR_CYAN, COLOR_DARK_THEME_BACKING)
    assert contrast_cyan >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_emerald = calculate_contrast_ratio(COLOR_EMERALD, COLOR_DARK_THEME_BACKING)
    assert contrast_emerald >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_amber = calculate_contrast_ratio(COLOR_AMBER, COLOR_DARK_THEME_BACKING)
    assert contrast_amber >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_crimson = calculate_contrast_ratio(COLOR_CRIMSON, COLOR_DARK_THEME_BACKING)
    assert contrast_crimson >= WCAG_GRAPHICAL_CONTRAST_TARGET

    # Helper function validation
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0) is True
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, min_contrast=7.0) is True


# ============================================================================
# Section 10: Horner OCS Register Space Synchronization (%R1470..%R1477)
# ============================================================================

def test_horner_register_synchronization() -> None:
    """Verify register table synchronization conforms to %R1470..%R1477, %M343..%M344."""
    canvas = create_canonical_polar_spectral_canvas()
    reg = canvas.reg_table

    assert reg.read_word("%R1470") == NOMINAL_OVERALL_VIB_RMS_SCALED             # 425 (4.25 mm/s)
    assert reg.read_word("%R1471") == NOMINAL_MAX_SPECTRAL_AXIS_SCORE_SCALED     # 742 (74.2%)
    assert reg.read_word("%R1472") == NOMINAL_SELECTED_MACHINE_INDEX             # 0
    assert reg.read_word("%R1473") == NOMINAL_PEAK_HARMONIC_ORDER_SCALED         # 20 (2.0X)
    assert reg.read_word("%R1474") == NOMINAL_BEARING_CREST_FACTOR_SCALED        # 38 (3.8)
    assert reg.read_word("%R1475") == NOMINAL_SPECTRAL_ENTROPY_SCORE_SCALED      # 815 (81.5%)
    assert reg.read_word("%R1476") == NOMINAL_MACHINERY_HEALTH_SCORE_SCALED      # 895 (89.5%)
    assert reg.read_word("%R1477") == 0                                          # DIAG OK
    assert reg.read_bit("%M343") is False                                        # Trip coil = False
    assert reg.read_bit("%M344") is True                                         # Active coil = True


# ============================================================================
# Section 11: ILogicUnit Discrete Scan Cycle Execution
# ============================================================================

def test_ilogicunit_scan_step_execution() -> None:
    """Verify ILogicUnit scan cycle execution and protocol compliance."""
    canvas = create_canonical_polar_spectral_canvas()
    assert isinstance(canvas, ILogicUnit)
    assert canvas.name == "PolarSpectralSignatureCanvasSync"
    assert canvas.priority == 90
    assert canvas.is_enabled is True

    canvas.scan_step(0.01)
    assert canvas.reg_table.read_bit("%M344") is True
    assert canvas.reg_table.read_bit("%M343") is False

    # Execute with injected high score in %R1471 (>= 1000)
    canvas.reg_table.write_word("%R1471", 1020, privilege=PrivilegeMode.SYSTEM)
    canvas.scan_step(0.01)
    assert canvas.reg_table.read_bit("%M343") is True
    assert DiagnosticCode(canvas.reg_table.read_word("%R1477")) == SPECTRAL_ERR_CRITICAL_RESONANCE_TRIP


# ============================================================================
# Section 12: Interactive Machine Train Selection & Axis Selection
# ============================================================================

def test_machine_train_selection() -> None:
    """Verify switching machine train index updates %R1472 and canvas state."""
    canvas = create_canonical_polar_spectral_canvas()
    assert canvas.selected_machine_index == 0

    canvas.select_machine(2)
    assert canvas.selected_machine_index == 2
    assert canvas.reg_table.read_word("%R1472") == 2

    canvas.select_machine(1)
    assert canvas.selected_machine_index == 1
    assert canvas.reg_table.read_word("%R1472") == 1


def test_axis_selection() -> None:
    """Verify interactive diagnostic axis selection."""
    canvas = create_canonical_polar_spectral_canvas()
    canvas.select_axis(4)
    assert canvas.selected_axis_index == 4
    assert bool(canvas.status_bits & PolarSpectralStatusBits.AXIS_SELECTED) is True


# ============================================================================
# Section 13: DiagnosticCode Signed/Unsigned 16-Bit Math
# ============================================================================

def test_diagnostic_code_signed_unsigned_equality() -> None:
    """Verify DiagnosticCode handles signed/unsigned 16-bit integers symmetrically."""
    code = DiagnosticCode(0xD301)
    assert code == 0xD301
    assert code == -11519
    assert code == 54017
    assert hash(code) == hash(int(code))

    code2 = DiagnosticCode(0xD302)
    assert code2 == 0xD302
    assert code2 == -11518

    code3 = DiagnosticCode(0xD303)
    assert code3 == 0xD303
    assert code3 == -11517

    code0 = DiagnosticCode(0x0000)
    assert code0 == 0


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite Integration
# ============================================================================

def test_run_polar_spectral_canvas_verification(tmp_path: Path) -> None:
    """Execute complete deterministic 9-stage verification suite with file outputs."""
    ev_path = tmp_path / "spectral_evidence.json"
    svg_path = tmp_path / "spectral_sample.svg"

    report = run_polar_spectral_canvas_verification(
        output_path=ev_path,
        sample_svg_path=svg_path,
    )

    assert report["status"] == "success"
    assert report["error_code"] is None
    assert report["data"]["checks_passed"] == 9
    assert report["data"]["total_checks"] == 9
    assert len(report["data"]["tests"]) == 9

    assert ev_path.exists()
    assert svg_path.exists()

    with open(ev_path, "r", encoding="utf-8") as f:
        ev_data = json.load(f)
    assert ev_data["status"] == "success"
    assert ev_data["data"]["work_package"] == "W186"
