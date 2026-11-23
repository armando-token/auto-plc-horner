"""Comprehensive pytest test suite for Cscape HMI Dynamic Ridge Plot / Joyplot Multi-Distribution Elevation Canvas (W147).

Work Package: W147 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1080..%R1087, %M252..%M253).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Ridge Plot / Joyplot multi-distribution elevation geometry and Gaussian KDE.
4. Section 4: Standalone W3C SVG 1.1 XML generation, stacked ridge lanes, and gradient ribbon fills.
5. Section 5: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
6. Section 6: Process safety trips (distribution excursion 0xAC01, invalid ridge count 0xAC02, render fault 0xAC03)
   and Horner coil assertions (%M252, %M253).
7. Section 7: Horner OCS register space synchronization (%R1080..%R1087, %M252..%M253).
8. Section 8: 9-stage verification suite integration test writing evidence JSON and sample SVG.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import re
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.ridge_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ADVISORY_AMBER,
    COLOR_ADVISORY_AMBER_DARK,
    COLOR_BASELINE_AXIS,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_DISTRESS_RED,
    COLOR_FOCUS_BLUE,
    COLOR_GRID_LINE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_DARK,
    COLOR_QUANTILE_IQR,
    COLOR_QUANTILE_MEDIAN,
    COLOR_RIDGE_CREST_CYAN,
    COLOR_RIDGE_CREST_WHITE,
    COLOR_RIDGE_CYAN,
    COLOR_RIDGE_DEEP_INDIGO,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_RED,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_OVERLAP_RATIO,
    DEFAULT_RIDGE_COUNT,
    DEFAULT_SKEWNESS_THRESHOLD,
    DEFAULT_VARIANCE_THRESHOLD,
    DIAG_EVENT_DISTRIBUTION_EXCURSION,
    DIAG_EVENT_INVALID_RIDGE_COUNT,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DOMAIN_SPAN,
    DOMAIN_X_MAX,
    DOMAIN_X_MIN,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    JOYPLOT_PURE_ST_POU,
    MAX_OVERLAP_RATIO,
    MAX_RIDGE_COUNT,
    MIN_OVERLAP_RATIO,
    MIN_RIDGE_COUNT,
    PLOT_HEIGHT,
    PLOT_WIDTH,
    PLOT_X_LEFT,
    PLOT_X_RIGHT,
    PLOT_Y_BOTTOM,
    PLOT_Y_TOP,
    RIDGE_CYAN_GRAPHICAL_CONTRAST_RATIO,
    RIDGE_ERR_ANOMALY,
    RIDGE_ERR_DISTRIBUTION_EXCURSION,
    RIDGE_ERR_INVALID_COUNT,
    RIDGE_ERR_INVALID_RIDGE_COUNT,
    RIDGE_ERR_RENDER_FAULT,
    RIDGE_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    DiagnosticCode,
    JoyplotCanvas,
    JoyplotEngine,
    JoyplotHmiSync,
    PainterOrder,
    ProcessDistribution,
    ProcessRidge,
    RidgeCanvas,
    RidgeCanvasStatusBits,
    RidgeCanvasSync,
    RidgeDistribution,
    RidgeEngine,
    RidgePlotCanvas,
    RidgeStatusBits,
    calculate_contrast_ratio,
    compute_gaussian_kde,
    compute_gaussian_kernel,
    compute_silverman_bandwidth,
    create_canonical_joyplot_canvas,
    create_canonical_ridge_canvas,
    create_canonical_ridge_channels,
    create_mock_scan_context,
    generate_joyplot_svg,
    generate_ridge_canvas_svg,
    generate_ridge_plot_svg,
    generate_smooth_cubic_bezier_path,
    hex_to_relative_luminance,
    run_ridge_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_joyplot_pure_st,
    verify_ridge_canvas_pure_st,
    verify_ridge_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1 Check: Verify RidgeCanvasSync POU conforms to IEC 61131-3 Pure ST grammar."""
    SecurityGuard.assert_pure_st_content(RIDGE_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(RIDGE_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "RidgeCanvasSync"
    assert pou.pou_type == POUType.PROGRAM

    var_dict = {v.name: v for v in pou.variables}

    # Verify Word Registers %R1080..%R1087
    assert "ActiveRidgeCount" in var_dict
    assert var_dict["ActiveRidgeCount"].address_binding == "%R1080"
    assert var_dict["ActiveRidgeCount"].data_type == "INT"

    assert "PeakElevationScaled" in var_dict
    assert var_dict["PeakElevationScaled"].address_binding == "%R1081"

    assert "OverlapRatioScaled" in var_dict
    assert var_dict["OverlapRatioScaled"].address_binding == "%R1082"

    assert "SelectedRidgeIndex" in var_dict
    assert var_dict["SelectedRidgeIndex"].address_binding == "%R1083"

    assert "Channel1MeanScaled" in var_dict
    assert var_dict["Channel1MeanScaled"].address_binding == "%R1084"

    assert "Channel2MeanScaled" in var_dict
    assert var_dict["Channel2MeanScaled"].address_binding == "%R1085"

    assert "Channel3MeanScaled" in var_dict
    assert var_dict["Channel3MeanScaled"].address_binding == "%R1086"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1087"

    # Verify Discrete Coils %M252..%M253
    assert "DistributionAnomalyTrip" in var_dict
    assert var_dict["DistributionAnomalyTrip"].address_binding == "%M252"
    assert var_dict["DistributionAnomalyTrip"].data_type == "BOOL"

    assert "RidgeCanvasActive" in var_dict
    assert var_dict["RidgeCanvasActive"].address_binding == "%M253"
    assert var_dict["RidgeCanvasActive"].data_type == "BOOL"

    assert verify_ridge_canvas_pure_st() is True
    assert verify_ridge_pure_st() is True
    assert verify_joyplot_pure_st() is True


def test_ladder_construct_rejection() -> None:
    """Security Guard: Verify aggressive rejection of ladder logic constructs with LadderForbiddenError."""
    ladder_samples = [
        "PROGRAM BadContact\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM",
        "PROGRAM BadCoil\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM",
        "PROGRAM BadRung\nVAR x: BOOL; END_VAR\nRUNG 1:\nEND_PROGRAM",
        "PROGRAM BadNetwork\nVAR x: BOOL; END_VAR\nNETWORK\nEND_PROGRAM",
        "PROGRAM BadMnemonic\nVAR x: BOOL; END_VAR\nXIC(StartBtn);\nEND_PROGRAM",
        "PROGRAM BadCoilMnemonic\nVAR x: BOOL; END_VAR\nOTE(RunLamp);\nEND_PROGRAM",
    ]

    for sample in ladder_samples:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)
        # verified == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 2: Ridge Distribution Topology & Statistical Moments
# ============================================================================

def test_canonical_ridge_channels_topology() -> None:
    """Stage 3 Check: Verify canonical process channels and mean values conforming to %R1084..%R1086."""
    ridges = create_canonical_ridge_channels(ridge_count=5)
    assert len(ridges) == 5

    # Channel 1: Feed Inflow (Mean 52.0 -> scaled 520)
    assert ridges[0].name == "Stage 1: Feed Inflow"
    assert ridges[0].tag == "FPM-101"
    assert ridges[0].unit == "°C"
    assert ridges[0].mean_scaled == 520
    assert abs(ridges[0].mean - 52.0) < 0.1

    # Channel 2: Reactor Core (Mean 74.0 -> scaled 740)
    assert ridges[1].name == "Stage 2: Reactor Core"
    assert ridges[1].tag == "RXC-201"
    assert ridges[1].unit == "bar"
    assert ridges[1].mean_scaled == 740
    assert abs(ridges[1].mean - 74.0) < 0.1

    # Channel 3: Catalytic Reformer (Mean 91.0 -> scaled 910)
    assert ridges[2].name == "Stage 3: Catalytic Reformer"
    assert ridges[2].tag == "CAT-301"
    assert ridges[2].unit == "ppm"
    assert ridges[2].mean_scaled == 910
    assert abs(ridges[2].mean - 91.0) < 0.1

    # Channel 4: Flash Fractionator (Mean 68.0 -> scaled 680)
    assert ridges[3].name == "Stage 4: Flash Fractionator"
    assert ridges[3].tag == "FLF-401"
    assert ridges[3].mean_scaled == 680

    # Channel 5: Polishing Effluent (Mean 45.0 -> scaled 450)
    assert ridges[4].name == "Stage 5: Polishing Effluent"
    assert ridges[4].tag == "PLE-501"
    assert ridges[4].mean_scaled == 450

    # Verify Quantiles Q25 <= Q50 <= Q75
    for r in ridges:
        assert r.q25 <= r.q50 <= r.q75
        assert r.peak_density > 0.0
        assert r.peak_density_scaled > 0
        assert len(r.samples) == 48


# ============================================================================
# Section 3: Gaussian KDE & Elevation Geometry
# ============================================================================

def test_gaussian_kde_and_bandwidth_algorithms() -> None:
    """Stage 2 Check: Verify Gaussian kernel, Silverman bandwidth, and KDE grid evaluation."""
    assert abs(compute_gaussian_kernel(0.0) - (1.0 / math.sqrt(2.0 * math.pi))) < 1e-4

    test_samples = [50.0, 51.0, 52.0, 52.0, 53.0, 54.0]
    h = compute_silverman_bandwidth(test_samples)
    assert 1.0 <= h <= 20.0

    dens_center = compute_gaussian_kde(test_samples, 52.0, h)
    dens_tail = compute_gaussian_kde(test_samples, 100.0, h)
    assert dens_center > dens_tail
    assert dens_tail < 1e-5

    # Empty samples safety
    assert compute_gaussian_kde([], 50.0, 4.0) == 0.0
    assert compute_gaussian_kde(test_samples, 50.0, -1.0) == 0.0


def test_smooth_cubic_bezier_path_generation() -> None:
    """Verify smooth Catmull-Rom to Cubic Bezier elevation ribbon and crest outline paths."""
    baseline = 350.0
    points = [
        (220.0, baseline),
        (300.0, baseline - 40.0),
        (400.0, baseline - 120.0),
        (500.0, baseline - 30.0),
        (600.0, baseline),
    ]

    fill_d, crest_d = generate_smooth_cubic_bezier_path(points, baseline)
    assert fill_d.startswith(f"M 220.0,{baseline:.1f} L 220.0,{baseline:.1f}")
    assert fill_d.endswith(f"L 600.0,{baseline:.1f} Z")
    assert " C " in fill_d
    assert crest_d.startswith("M 220.0,")
    assert " C " in crest_d
    assert " Z" not in crest_d

    # Edge cases
    empty_fill, empty_crest = generate_smooth_cubic_bezier_path([], baseline)
    assert empty_fill == "" and empty_crest == ""
    single_fill, single_crest = generate_smooth_cubic_bezier_path([(220.0, 300.0)], baseline)
    assert single_fill == "" and single_crest == ""


def test_painter_ordering_and_overlap_occlusion() -> None:
    """Stage 2 Check: Verify painter's ordering and overlap ratios from 1.0x to 2.5x."""
    canvas_default = create_canonical_ridge_canvas(active_ridges=5, overlap_ratio=1.5)
    assert canvas_default.painter_order == PainterOrder.UPPER_OCCLUDES_LOWER
    svg_upper_occludes = canvas_default.render_svg()

    # In UPPER_OCCLUDES_LOWER, lane-4 is drawn earlier, lane-0 is drawn later in DOM
    idx_lane_4 = svg_upper_occludes.find('id="ridge-lane-4"')
    idx_lane_0 = svg_upper_occludes.find('id="ridge-lane-0"')
    assert idx_lane_4 != -1 and idx_lane_0 != -1
    assert idx_lane_4 < idx_lane_0, "Upper ridge (lane-0) should be rendered later in DOM to occlude lower ridge (lane-4)"

    canvas_lower_occludes = create_canonical_ridge_canvas(active_ridges=5, overlap_ratio=1.5)
    canvas_lower_occludes.painter_order = PainterOrder.LOWER_OCCLUDES_UPPER
    svg_lower_occludes = canvas_lower_occludes.render_svg()
    idx2_lane_0 = svg_lower_occludes.find('id="ridge-lane-0"')
    idx2_lane_4 = svg_lower_occludes.find('id="ridge-lane-4"')
    assert idx2_lane_0 < idx2_lane_4, "In lower_occludes_upper, lane-0 should be drawn before lane-4"

    # Test overlap ratio bounds
    canvas_default.set_overlap_ratio(0.5)
    assert canvas_default.overlap_ratio == MIN_OVERLAP_RATIO
    assert canvas_default.overlap_ratio_scaled == 100

    canvas_default.set_overlap_ratio(3.5)
    assert canvas_default.overlap_ratio == MAX_OVERLAP_RATIO
    assert canvas_default.overlap_ratio_scaled == 250


# ============================================================================
# Section 4: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def test_standalone_w3c_svg_rendering_and_xml_validation() -> None:
    """Stage 6 Check: Verify standalone W3C SVG 1.1 XML conformance, gradient fills, and elements."""
    canvas = create_canonical_ridge_canvas(active_ridges=5, overlap_ratio=1.5)
    svg_str = canvas.render_svg()

    # Valid XML test
    root = ET.fromstring(svg_str)
    assert root.tag == "{http://www.w3.org/2000/svg}svg" or root.tag == "svg"
    assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)
    assert root.attrib["version"] == "1.1"

    # SVG Structure Checks
    assert COLOR_DARK_THEME_BACKING in svg_str
    assert 'id="canvas-header"' in svg_str
    assert 'id="ridge-plot-container"' in svg_str
    assert 'id="plot-graduation-grid"' in svg_str
    assert 'id="ridge-lanes"' in svg_str
    assert 'id="telemetry-hud"' in svg_str

    # Gradient checks (Deep Indigo #1E1B4B to Cyan #06B6D4)
    assert COLOR_RIDGE_DEEP_INDIGO in svg_str
    assert COLOR_RIDGE_CYAN in svg_str
    assert '<linearGradient id="ridge-grad-0"' in svg_str

    # Ridge crest outline and baseline axes
    assert 'class="ridge-baseline-axis"' in svg_str
    assert 'class="ridge-elevation-ribbon"' in svg_str
    assert 'class="ridge-crest-outline"' in svg_str

    # Value graduation ticks (0..120)
    assert 'class="axis-graduation-tick"' in svg_str
    assert 'PROCESS VARIABLE VALUE DOMAIN [0.0 .. 120.0]' in svg_str


# ============================================================================
# Section 5: WCAG 2.1 AAA Accessibility & Decoupled Badges
# ============================================================================

def test_wcag_21_aaa_contrast_metrics() -> None:
    """Stage 7 Check: Validate WCAG 2.1 AAA contrast targets for text, graphics, and badges."""
    badge_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    theme_text_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    green_contrast = calculate_contrast_ratio(COLOR_NOMINAL_GREEN, COLOR_DARK_THEME_BACKING)
    amber_contrast = calculate_contrast_ratio(COLOR_ADVISORY_AMBER, COLOR_DARK_THEME_BACKING)
    red_contrast = calculate_contrast_ratio(COLOR_DISTRESS_RED, COLOR_DARK_THEME_BACKING)
    cyan_contrast = calculate_contrast_ratio(COLOR_RIDGE_CYAN, COLOR_DARK_THEME_BACKING)

    assert badge_contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert badge_contrast > 18.0
    assert theme_text_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert theme_text_contrast > 7.0
    assert green_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert amber_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert red_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert cyan_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET

    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, 7.0) is True


# ============================================================================
# Section 6: Process Safety Interlocks & Diagnostics
# ============================================================================

def test_process_safety_distribution_anomaly_trip_0xac01() -> None:
    """Stage 4 Check: Verify 0xAC01 distribution variance/skewness anomaly trip and %M252 assertion."""
    canvas = create_canonical_ridge_canvas(active_ridges=5)
    assert canvas.distribution_anomaly_trip is False
    assert canvas.reg_table.read_bit("%M252") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    canvas.trigger_distribution_excursion(ridge_index=2, injected_variance=950.0, injected_skewness=2.5)

    assert canvas.distribution_anomaly_trip is True
    assert canvas.reg_table.read_bit("%M252") is True
    assert canvas.diagnostic_code == RIDGE_ERR_DISTRIBUTION_EXCURSION
    assert canvas.diagnostic_code == 0xAC01
    assert canvas.diagnostic_code == -21503
    assert DiagnosticCode(canvas.reg_table.read_word("%R1087")) == 0xAC01
    assert canvas.selected_ridge_index == 2
    assert bool(canvas.status_bits & RidgeStatusBits.DISTRIBUTION_EXCURSION_TRIP)

    # Check SVG renders trip banner and alert halo
    svg_trip = canvas.render_svg()
    assert "0xAC01 TRIP" in svg_trip
    assert "ANOMALY TRIP (%M252)" in svg_trip
    assert 'class="excursion-alert-halo"' in svg_trip


def test_invalid_ridge_count_trip_0xac02() -> None:
    """Stage 5 Check: Verify 0xAC02 invalid ridge count (<2 or >10)."""
    canvas = create_canonical_ridge_canvas()

    # Under-range test (count = 1)
    canvas.trigger_invalid_ridge_count(1)
    assert canvas.diagnostic_code == RIDGE_ERR_INVALID_RIDGE_COUNT
    assert canvas.diagnostic_code == 0xAC02
    assert canvas.diagnostic_code == -21502
    assert DiagnosticCode(canvas.reg_table.read_word("%R1087")) == 0xAC02
    assert bool(canvas.status_bits & RidgeStatusBits.INVALID_RIDGE_COUNT)

    svg_bad = canvas.render_svg()
    assert "0xAC02 BAD RIDGES" in svg_bad

    # Over-range test (count = 12)
    canvas.trigger_invalid_ridge_count(12)
    assert canvas.diagnostic_code == RIDGE_ERR_INVALID_RIDGE_COUNT
    assert canvas.diagnostic_code == 0xAC02


def test_render_fault_0xac03_and_nominal_reset() -> None:
    """Stage 5 Check: Verify 0xAC03 render fault and reset_nominal restoration."""
    canvas = create_canonical_ridge_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == RIDGE_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xAC03
    assert canvas.diagnostic_code == -21501
    assert DiagnosticCode(canvas.reg_table.read_word("%R1087")) == 0xAC03

    svg_fault = canvas.render_svg()
    assert "0xAC03 FAULT" in svg_fault

    # Nominal reset restoration
    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.distribution_anomaly_trip is False
    assert canvas.reg_table.read_bit("%M252") is False
    assert canvas.reg_table.read_bit("%M253") is True
    assert canvas.reg_table.read_word("%R1087") == 0x0000
    assert bool(canvas.status_bits & RidgeStatusBits.NOMINAL_OPERATION)


# ============================================================================
# Section 7: Horner OCS Memory Space Integration & Scan Context
# ============================================================================

def test_horner_ocs_register_space_synchronization() -> None:
    """Stage 9 Check: Validate synchronous register reflection of %R1080..%R1087 and %M252..%M253."""
    canvas = create_canonical_ridge_canvas(active_ridges=5, overlap_ratio=1.5)
    canvas.set_selected_ridge_index(2)

    reg = canvas.reg_table
    assert reg.read_word("%R1080") == 5           # ActiveRidgeCount
    assert reg.read_word("%R1081") == 850         # PeakElevationScaled
    assert reg.read_word("%R1082") == 150         # OverlapRatioScaled (1.50x -> 150)
    assert reg.read_word("%R1083") == 2           # SelectedRidgeIndex
    assert reg.read_word("%R1084") == 520         # CH1 Mean Scaled
    assert reg.read_word("%R1085") == 740         # CH2 Mean Scaled
    assert reg.read_word("%R1086") == 910         # CH3 Mean Scaled
    assert reg.read_word("%R1087") == 0           # DiagnosticStatusCode
    assert reg.read_bit("%M252") is False         # DistributionAnomalyTrip
    assert reg.read_bit("%M253") is True          # RidgeCanvasActive


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface execution within simulated Horner PLC scan cycle."""
    canvas = create_canonical_ridge_canvas(active_ridges=5)
    assert canvas.name == "RidgeCanvasSync"
    assert canvas.priority == 88
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)
    canvas.execute(ctx)
    assert canvas.reg_table.read_bit("%M253") is True

    canvas.step()
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK


def test_quantile_markers_and_alert_halos_in_svg() -> None:
    """Stage 8 Check: Verify distribution quantiles (Q25, Q50, Q75) and alert halos in SVG."""
    canvas = create_canonical_ridge_canvas(active_ridges=5)
    svg_out = canvas.render_svg()

    assert 'class="quantile-q50"' in svg_out
    assert 'class="quantile-q25"' in svg_out
    assert 'class="quantile-q75"' in svg_out

    # Highlight selected ridge
    canvas.set_selected_ridge_index(1)
    svg_focused = canvas.render_svg()
    assert f'stroke="{COLOR_RIDGE_CREST_WHITE}"' in svg_focused


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration
# ============================================================================

def test_deterministic_9_stage_verification_suite(tmp_path: Path) -> None:
    """Execute complete deterministic 9-stage verification suite writing evidence JSON and sample SVG."""
    ev_path = tmp_path / "ridge_evidence.json"
    svg_path = tmp_path / "ridge_sample.svg"

    evidence = run_ridge_canvas_verification(
        output_path=ev_path,
        sample_svg_path=svg_path,
    )

    assert evidence["status"] == "success"
    assert evidence["error_code"] is None
    assert evidence["data"]["work_package"] == "W147"
    assert evidence["data"]["gate"] == "Gate G9 / G2"
    assert evidence["data"]["checks_passed"] == 9
    assert evidence["data"]["total_checks"] == 9
    assert len(evidence["data"]["tests"]) == 9

    # Verify disk files
    assert ev_path.exists()
    assert svg_path.exists()

    with open(ev_path, "r", encoding="utf-8") as f:
        loaded_ev = json.load(f)
    assert loaded_ev["status"] == "success"
    assert loaded_ev["data"]["checks_passed"] == 9

    with open(svg_path, "r", encoding="utf-8") as f:
        svg_content = f.read()
    assert '<svg xmlns="http://www.w3.org/2000/svg"' in svg_content
    ET.fromstring(svg_content)


# ============================================================================
# Section 9: DiagnosticCode & Edge Cases
# ============================================================================

def test_diagnostic_code_edge_cases() -> None:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and hash consistency."""
    code_trip = DiagnosticCode(0xAC01)
    assert code_trip == 0xAC01
    assert code_trip == -21503
    assert code_trip == 44033
    assert int(code_trip) == 44033
    assert hash(code_trip) == hash(44033)
    assert code_trip != "not_an_int"
    assert code_trip != 0x0000

    code_count = DiagnosticCode(0xAC02)
    assert code_count == 0xAC02
    assert code_count == -21502
    assert code_count == 44034

    code_fault = DiagnosticCode(0xAC03)
    assert code_fault == 0xAC03
    assert code_fault == -21501
    assert code_fault == 44035


def test_color_and_wcag_math_branches() -> None:
    """Verify sRGB channel linear conversion and hex luminance for 3-char and 6-char hex."""
    assert abs(srgb_channel_to_linear(0.02) - (0.02 / 12.92)) < 1e-6
    assert abs(srgb_channel_to_linear(0.5) - (((0.5 + 0.055) / 1.055) ** 2.4)) < 1e-6

    # 3-char hex #FFF
    lum_white_3 = hex_to_relative_luminance("#FFF")
    lum_white_6 = hex_to_relative_luminance("#FFFFFF")
    assert abs(lum_white_3 - lum_white_6) < 1e-4

    # 3-char hex #000
    lum_black_3 = hex_to_relative_luminance("#000")
    lum_black_6 = hex_to_relative_luminance("#000000")
    assert abs(lum_black_3 - lum_black_6) < 1e-4


def test_aliases_and_boundary_branches() -> None:
    """Verify class aliases, helper functions, and boundary configurations."""
    c1 = RidgeCanvasSync()
    c2 = JoyplotHmiSync()
    c3 = RidgePlotCanvas()
    c4 = JoyplotCanvas()
    c5 = RidgeEngine()
    c6 = JoyplotEngine()
    c7 = create_canonical_joyplot_canvas()

    for c in (c1, c2, c3, c4, c5, c6, c7):
        assert isinstance(c, RidgeCanvas)

    svg1 = generate_joyplot_svg(create_canonical_ridge_channels(5))
    svg2 = generate_ridge_plot_svg(create_canonical_ridge_channels(5))
    assert '<svg ' in svg1 and '<svg ' in svg2

    # RidgeDistribution with empty samples
    empty_dist = RidgeDistribution(ridge_id=0, name="Empty", tag="EMP", unit="u", samples=[])
    assert empty_dist.mean == 0.0
    assert empty_dist.mean_scaled == 0
    assert empty_dist.variance == 0.0
    assert empty_dist.q50 == 0.0

    # RidgeDistribution with 1 sample
    single_dist = RidgeDistribution(ridge_id=1, name="Single", tag="SGL", unit="u", samples=[42.0])
    assert single_dist.mean == 42.0
    assert single_dist.variance == 0.0
    assert single_dist.skewness == 0.0
    assert single_dist.q50 == 42.0

    # Boundary ridge counts
    c_min = create_canonical_ridge_canvas(active_ridges=MIN_RIDGE_COUNT)
    assert c_min.active_ridge_count == MIN_RIDGE_COUNT
    assert len(c_min.ridges) == MIN_RIDGE_COUNT

    c_max = create_canonical_ridge_canvas(active_ridges=MAX_RIDGE_COUNT)
    assert c_max.active_ridge_count == MAX_RIDGE_COUNT
    assert len(c_max.ridges) == MAX_RIDGE_COUNT
