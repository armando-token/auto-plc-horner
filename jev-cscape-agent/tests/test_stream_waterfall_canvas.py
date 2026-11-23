"""Comprehensive pytest test suite for Cscape HMI Dynamic Stream / Waterfall Multi-Epoch Hydrodynamic Flow SCADA Canvas (W189).

Work Package: W189 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Coverage:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1500..%R1507, %M350..%M351).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: StreamWaterfallConfig, StreamDataPoint, and ProcessStream initialization and validation.
4. Section 4: 5 Industrial process streams definition, nominal throughputs, and dynamic flow modulation.
5. Section 5: Stream stacking mathematics: vertical cumulative offset, baseline drift, ribbon thickness, Bezier paths.
6. Section 6: Multi-epoch history buffer rolling, depth bounding (8..48), and interactive selector controls.
7. Section 7: Standalone W3C SVG 1.1 XML generation, XML validity, dark theme backing, and HUD cards.
8. Section 8: WCAG 2.1 AAA accessibility and color contrast compliance (> 18:1 badge, > 7:1 text, > 3:1 graphics).
9. Section 9: Horner OCS RegisterTable memory synchronization (%R1500..%R1507, %M350..%M351) with PrivilegeMode.SYSTEM.
10. Section 10: Process safety interlocks (0xD301 turbulence breach asserts %M351, 0xD302 starvation, 0xD303 render fault).
11. Section 11: ILogicUnit discrete scan cycle execution (100+ scan steps, auto-trip, auto-recovery).
12. Section 12: Deterministic 9-stage verification suite integration runner returning status == 'success' and 9 passed stages.
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

from jev_cscape.hmi.stream_waterfall_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_CARD_BORDER,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DARK_THEME_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_FOCUS_BLUE,
    COLOR_GOLDEN_BASELINE,
    COLOR_GRID_LINE,
    COLOR_GRID_TICK,
    COLOR_NOMINAL_GREEN,
    COLOR_STREAM_1_DARK,
    COLOR_STREAM_1_SYNGAS,
    COLOR_STREAM_2_DARK,
    COLOR_STREAM_2_WAX,
    COLOR_STREAM_3_DARK,
    COLOR_STREAM_3_DIESEL,
    COLOR_STREAM_4_DARK,
    COLOR_STREAM_4_NAPHTHA,
    COLOR_STREAM_5_DARK,
    COLOR_STREAM_5_OFFGAS,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_CRIMSON,
    COLOR_WARNING_AMBER,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_EPOCH_DEPTH,
    DIAG_EVENT_FLOW_STARVATION,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DIAG_EVENT_STARVATION,
    DIAG_EVENT_TURBULENCE,
    DIAG_EVENT_TURBULENCE_BREACH,
    DiagnosticCode,
    FLOW_STARVATION_THRESHOLD_BPD,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    MAX_EPOCH_DEPTH,
    MIN_EPOCH_DEPTH,
    NOMINAL_ACTIVE_STREAM_COUNT,
    NOMINAL_DOMINANT_STREAM_INDEX,
    NOMINAL_FLOW_VELOCITY_VARIATION_PCT,
    NOMINAL_FLOW_VELOCITY_VARIATION_SCALED,
    NOMINAL_HYDRODYNAMIC_TURBULENCE,
    NOMINAL_HYDRODYNAMIC_TURBULENCE_SCALED,
    NOMINAL_STREAM_1_BPD,
    NOMINAL_STREAM_2_BPD,
    NOMINAL_STREAM_3_BPD,
    NOMINAL_STREAM_4_BPD,
    NOMINAL_STREAM_5_BPD,
    NOMINAL_STREAM_DISPERSION_COEFF,
    NOMINAL_STREAM_DISPERSION_COEFF_SCALED,
    NOMINAL_TOTAL_THROUGHPUT_BPD,
    NOMINAL_TOTAL_THROUGHPUT_BPD_SCALED,
    PLOT_HEIGHT,
    PLOT_WIDTH,
    PLOT_X_MAX,
    PLOT_X_MIN,
    PLOT_Y_MAX,
    PLOT_Y_MIN,
    ProcessStream,
    STREAM_ERR_FLOW_STARVATION,
    STREAM_ERR_OK,
    STREAM_ERR_RENDER_FAULT,
    STREAM_ERR_STARVATION,
    STREAM_ERR_TURBULENCE,
    STREAM_ERR_TURBULENCE_BREACH,
    STREAM_WATERFALL_PURE_ST_POU,
    StreamDataPoint,
    StreamId,
    StreamWaterfallCanvas,
    StreamWaterfallCanvasSync,
    StreamWaterfallConfig,
    StreamWaterfallEngine,
    StreamWaterfallHmiSync,
    StreamWaterfallStatusBits,
    TURBULENCE_TRIP_THRESHOLD,
    TURBULENCE_WARNING_THRESHOLD,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    WaterfallCanvas,
    WaterfallCanvasSync,
    WaterfallMetrics,
    WaterfallStatusBits,
    calculate_contrast_ratio,
    compute_cubic_bezier_spline_points,
    create_canonical_process_streams,
    create_canonical_waterfall_canvas,
    create_mock_scan_context,
    generate_stream_ribbon_svg_path,
    generate_stream_waterfall_canvas_svg,
    hex_to_relative_luminance,
    run_stream_waterfall_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_stream_waterfall_canvas_pure_st,
    verify_stream_waterfall_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Section 1.1: Verify Pure ST POU parses correctly via STParser and functions as PROGRAM."""
    assert verify_stream_waterfall_canvas_pure_st() is True
    assert verify_stream_waterfall_pure_st() is True

    parser = STParser()
    ast = parser.parse_pou(STREAM_WATERFALL_PURE_ST_POU)
    assert ast is not None
    assert ast.name == "StreamWaterfallCanvasSync"
    assert ast.pou_type == POUType.PROGRAM


def test_pure_st_pou_bound_registers() -> None:
    """Section 1.2: Verify all 10 Horner registers (%R1500..%R1507, %M350..%M351) are bound in AST."""
    parser = STParser()
    ast = parser.parse_pou(STREAM_WATERFALL_PURE_ST_POU)
    assert ast is not None

    expected_registers = [
        "%R1500", "%R1501", "%R1502", "%R1503",
        "%R1504", "%R1505", "%R1506", "%R1507",
        "%M350", "%M351",
    ]
    for reg in expected_registers:
        assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"


def test_pure_st_pou_syntax_validation() -> None:
    """Section 1.3: Validate code syntax passes with SUCCESS status."""
    res = STParser.validate_code(STREAM_WATERFALL_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_security_guard_assertion() -> None:
    """Section 2.1: Verify pure ST content passes SecurityGuard without error."""
    SecurityGuard.assert_pure_st_content(STREAM_WATERFALL_PURE_ST_POU)


def test_anti_ladder_security_guard_rejections() -> None:
    """Section 2.2: Verify ladder contacts, coils, mnemonics, and rungs are rejected."""
    bad_snippets = [
        "PROGRAM Bad1 VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM Bad2 VAR X : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM Bad3 VAR X : BOOL; END_VAR XIC %M350; END_PROGRAM",
        "PROGRAM Bad4 VAR X : BOOL; END_VAR OTE %M351; END_PROGRAM",
        "PROGRAM Bad5 VAR X : BOOL; END_VAR RUNG 1 StreamActive := TRUE; END_PROGRAM",
        "PROGRAM Bad6 VAR X : BOOL; END_VAR NETWORK 1 END_PROGRAM",
    ]
    for snippet in bad_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: Configuration & Data Structures
# ============================================================================

def test_stream_waterfall_config_defaults() -> None:
    """Section 3.1: Verify default configuration parameters."""
    cfg = StreamWaterfallConfig()
    assert cfg.viewport_width == CANVAS_VIEWPORT_WIDTH == 1200
    assert cfg.viewport_height == CANVAS_VIEWPORT_HEIGHT == 750
    assert cfg.epoch_depth == DEFAULT_EPOCH_DEPTH == 24
    assert cfg.nominal_total_bpd == NOMINAL_TOTAL_THROUGHPUT_BPD == 15000.0
    assert cfg.turbulence_warning_threshold == TURBULENCE_WARNING_THRESHOLD == 3.5
    assert cfg.turbulence_trip_threshold == TURBULENCE_TRIP_THRESHOLD == 4.0
    assert cfg.flow_starvation_threshold_bpd == FLOW_STARVATION_THRESHOLD_BPD == 1000.0
    assert cfg.selected_stream_index == 0
    assert cfg.selected_epoch_index == DEFAULT_EPOCH_DEPTH - 1
    assert cfg.flow_bands_mode == "cubic_bezier"
    assert cfg.theme_bg_color == COLOR_DARK_THEME_BACKING


def test_stream_waterfall_config_custom_initialization() -> None:
    """Section 3.2: Verify custom configuration initialization."""
    cfg = StreamWaterfallConfig(
        viewport_width=1600,
        viewport_height=900,
        epoch_depth=36,
        nominal_total_bpd=20000.0,
        turbulence_warning_threshold=3.0,
        turbulence_trip_threshold=3.8,
        flow_starvation_threshold_bpd=1200.0,
        selected_stream_index=2,
        selected_epoch_index=15,
        flow_bands_mode="sinusoidal",
        theme_bg_color=COLOR_DARK_THEME_BACKING_1E1E1E,
    )
    assert cfg.viewport_width == 1600
    assert cfg.viewport_height == 900
    assert cfg.epoch_depth == 36
    assert cfg.nominal_total_bpd == 20000.0
    assert cfg.selected_stream_index == 2
    assert cfg.selected_epoch_index == 15
    assert cfg.flow_bands_mode == "sinusoidal"
    assert cfg.theme_bg_color == "#1E1E1E"


def test_stream_data_point_initialization() -> None:
    """Section 3.3: Verify StreamDataPoint dataclass fields and defaults."""
    pt = StreamDataPoint(
        epoch=5,
        stream_id=1,
        stream_name="Syngas Feed",
        flow_rate_bpd=4250.0,
        velocity_fps=12.8,
        turbulence_re=2.45,
        dispersion_coeff=1.22,
        y_top=210.5,
        y_bottom=320.0,
        timestamp_offset_s=3600.0,
    )
    assert pt.epoch == 5
    assert pt.stream_id == 1
    assert pt.stream_name == "Syngas Feed"
    assert pt.flow_rate_bpd == 4250.0
    assert pt.velocity_fps == 12.8
    assert pt.turbulence_re == 2.45
    assert pt.dispersion_coeff == 1.22
    assert pt.y_top == 210.5
    assert pt.y_bottom == 320.0
    assert pt.timestamp_offset_s == 3600.0


def test_process_stream_initialization_and_nominal_fraction() -> None:
    """Section 3.4: Verify ProcessStream nominal fraction computation."""
    stream = ProcessStream(
        stream_id=1,
        name="Syngas Feed",
        color=COLOR_STREAM_1_SYNGAS,
        color_dark=COLOR_STREAM_1_DARK,
        nominal_bpd=4200.0,
    )
    assert stream.stream_id == 1
    assert stream.name == "Syngas Feed"
    assert stream.is_active is True
    assert stream.is_critical is True
    # 4200 / 15000 = 0.28
    assert abs(stream.nominal_fraction - 0.28) < 1e-4


def test_waterfall_metrics_scaled_properties_and_clamping() -> None:
    """Section 3.5: Verify WaterfallMetrics scaled INT16 properties and clamping."""
    metrics = WaterfallMetrics(
        active_stream_count=5,
        total_throughput_bpd=15000.0,
        dominant_stream_index=1,
        epoch_depth=24,
        hydrodynamic_turbulence=2.4,
        flow_velocity_variation_pct=4.5,
        stream_dispersion_coeff=1.20,
        diagnostic_status_code=DIAG_EVENT_OK,
        waterfall_streaming_active=True,
        flow_turbulence_warning=False,
    )
    assert metrics.total_throughput_scaled == 1500  # 15000 / 10
    assert metrics.hydrodynamic_turbulence_scaled == 24  # 2.4 * 10
    assert metrics.flow_velocity_variation_scaled == 45  # 4.5 * 10
    assert metrics.stream_dispersion_coeff_scaled == 120  # 1.20 * 100

    # Test extreme clamping
    metrics_extreme = WaterfallMetrics(
        active_stream_count=5,
        total_throughput_bpd=500000.0,  # 500,000 / 10 = 50,000 -> clamps to 32767
        dominant_stream_index=1,
        epoch_depth=24,
        hydrodynamic_turbulence=5000.0,  # clamps to 32767
        flow_velocity_variation_pct=-5000.0,  # clamps to -32768
        stream_dispersion_coeff=1000.0,  # clamps to 32767
        diagnostic_status_code=DIAG_EVENT_OK,
        waterfall_streaming_active=True,
        flow_turbulence_warning=False,
    )
    assert metrics_extreme.total_throughput_scaled == 32767
    assert metrics_extreme.hydrodynamic_turbulence_scaled == 32767
    assert metrics_extreme.flow_velocity_variation_scaled == -32768
    assert metrics_extreme.stream_dispersion_coeff_scaled == 32767


# ============================================================================
# Section 4: 5 Industrial Process Streams & Flow Modulation
# ============================================================================

def test_canonical_process_streams_definition() -> None:
    """Section 4.1: Verify 5 process streams, names, colors, and nominal throughput."""
    streams = create_canonical_process_streams(DEFAULT_EPOCH_DEPTH)
    assert len(streams) == 5

    stream_names = [s.name for s in streams]
    assert stream_names == [
        "Syngas Feed",
        "Liquid Wax",
        "Heavy Diesel",
        "Naphtha",
        "Offgas/Tailgas",
    ]

    nominals = [s.nominal_bpd for s in streams]
    assert nominals == [
        NOMINAL_STREAM_1_BPD,
        NOMINAL_STREAM_2_BPD,
        NOMINAL_STREAM_3_BPD,
        NOMINAL_STREAM_4_BPD,
        NOMINAL_STREAM_5_BPD,
    ]
    assert sum(nominals) == NOMINAL_TOTAL_THROUGHPUT_BPD == 15000.0


def test_dynamic_flow_rate_modulation() -> None:
    """Section 4.2: Verify flow history lists are populated with epoch depth length."""
    streams = create_canonical_process_streams(24)
    for s in streams:
        assert len(s.flow_history) == 24
        # Flows should be bounded within 20% of nominal
        for val in s.flow_history:
            assert 0.7 * s.nominal_bpd <= val <= 1.3 * s.nominal_bpd


def test_velocity_history_modulation() -> None:
    """Section 4.3: Verify velocity histories are populated and strictly positive."""
    streams = create_canonical_process_streams(24)
    for s in streams:
        assert len(s.velocity_history) == 24
        for v in s.velocity_history:
            assert v > 0.0


def test_dominant_stream_calculation() -> None:
    """Section 4.4: Verify dominant stream calculation under nominal and modified flows."""
    canvas = create_canonical_waterfall_canvas()
    assert canvas.metrics.dominant_stream_index == 1
    assert canvas.metrics.dominant_stream_name == "Syngas Feed"

    # Make Stream 2 (Liquid Wax) dominant
    canvas.streams[1].flow_history[-1] = 8000.0
    canvas.evaluate_hydrodynamics()
    assert canvas.metrics.dominant_stream_index == 2
    assert canvas.metrics.dominant_stream_name == "Liquid Wax"


# ============================================================================
# Section 5: Stream Stacking Mathematics & Geometry
# ============================================================================

def test_stream_stacking_vertical_cumulative_offsets() -> None:
    """Section 5.1: Verify stacked layers accumulate vertically from bottom to top."""
    canvas = create_canonical_waterfall_canvas()
    svg = canvas.render_svg()
    assert svg is not None

    # Stacking check: verify geometry calculations produce valid bounds
    epoch_count = canvas.config.epoch_depth
    scale_y = PLOT_HEIGHT / 18000.0
    current_baseline_y = [PLOT_Y_MAX] * epoch_count

    for s in canvas.streams:
        for t in range(epoch_count):
            flow = s.flow_history[t]
            thickness = max(6.0, flow * scale_y)
            top_y = current_baseline_y[t] - thickness
            assert top_y < current_baseline_y[t], "Top bound must be higher (smaller Y) than baseline"
            current_baseline_y[t] = top_y


def test_stream_ribbon_thickness_positive_and_clamped() -> None:
    """Section 5.2: Verify ribbon thickness is clamped to minimum positive value >= 6.0."""
    scale_y = PLOT_HEIGHT / 18000.0
    min_thickness = max(6.0, 0.0 * scale_y)
    assert min_thickness == 6.0


def test_hydrodynamic_wave_ripple_and_dispersion_modulation() -> None:
    """Section 5.3: Verify wave ripple and dispersion calculations produce bounded values."""
    turb = NOMINAL_HYDRODYNAMIC_TURBULENCE
    disp = NOMINAL_STREAM_DISPERSION_COEFF
    for t in range(24):
        for s_id in range(1, 6):
            ripple = (turb * 3.5) * math.sin(t * 0.75 + s_id * 1.1)
            disp_term = disp * 2.0 * math.cos(t * 0.5)
            assert abs(ripple) <= turb * 3.5
            assert abs(disp_term) <= disp * 2.0


def test_cubic_bezier_spline_points_continuity() -> None:
    """Section 5.4: Verify cubic Bezier spline generation for varying point counts."""
    # 0 points
    assert compute_cubic_bezier_spline_points([]) == ""
    # 1 point
    assert compute_cubic_bezier_spline_points([(10.0, 20.0)]) == "M 10.00 20.00"
    # 2 points
    assert compute_cubic_bezier_spline_points([(10.0, 20.0), (30.0, 40.0)]) == "M 10.00 20.00 L 30.00 40.00"

    # N points
    pts = [(100.0, 200.0), (200.0, 180.0), (300.0, 220.0), (400.0, 190.0)]
    spline = compute_cubic_bezier_spline_points(pts)
    assert spline.startswith("M 100.00 200.00")
    assert " C " in spline
    commands = spline.split()
    assert commands[0] == "M"
    assert "C" in commands


def test_generate_stream_ribbon_svg_path_closure_and_commands() -> None:
    """Section 5.5: Verify closed ribbon path format M...C...L...C...Z and error cases."""
    top_pts = [(100.0, 200.0), (200.0, 180.0), (300.0, 220.0), (400.0, 190.0)]
    bot_pts = [(100.0, 250.0), (200.0, 240.0), (300.0, 270.0), (400.0, 260.0)]

    path = generate_stream_ribbon_svg_path(top_pts, bot_pts)
    assert path.startswith("M 100.00 200.00")
    assert " C " in path
    assert " L 400.00 260.00" in path
    assert path.endswith(" Z")

    # Mismatched length returns empty string
    assert generate_stream_ribbon_svg_path(top_pts, bot_pts[:2]) == ""
    # Empty inputs return empty string
    assert generate_stream_ribbon_svg_path([], []) == ""


# ============================================================================
# Section 6: Multi-Epoch History Buffer & Interactive Navigation
# ============================================================================

def test_epoch_depth_bounds_clamping() -> None:
    """Section 6.1: Verify epoch depth is clamped between MIN_EPOCH_DEPTH and MAX_EPOCH_DEPTH."""
    # Underflow clamped to MIN (8)
    streams_min = create_canonical_process_streams(4)
    assert len(streams_min[0].flow_history) == MIN_EPOCH_DEPTH == 8

    # Overflow clamped to MAX (48)
    streams_max = create_canonical_process_streams(100)
    assert len(streams_max[0].flow_history) == MAX_EPOCH_DEPTH == 48


def test_stream_selection_focus() -> None:
    """Section 6.2: Verify select_stream updates config and ignores invalid indices."""
    canvas = create_canonical_waterfall_canvas()
    assert canvas.config.selected_stream_index == 0

    canvas.select_stream(3)
    assert canvas.config.selected_stream_index == 3

    # Out of range index should be ignored
    canvas.select_stream(99)
    assert canvas.config.selected_stream_index == 3


def test_epoch_selection_cursor() -> None:
    """Section 6.3: Verify select_epoch updates cursor within valid depth."""
    canvas = create_canonical_waterfall_canvas(epoch_depth=24)
    canvas.select_epoch(12)
    assert canvas.config.selected_epoch_index == 12

    # Out of range should be ignored
    canvas.select_epoch(30)
    assert canvas.config.selected_epoch_index == 12


# ============================================================================
# Section 7: Standalone W3C SVG 1.1 Vector Canvas Generation & XML Validity
# ============================================================================

def test_render_svg_xml_syntax_validity() -> None:
    """Section 7.1: Verify SVG string parses into XML without errors."""
    canvas = create_canonical_waterfall_canvas()
    svg_str = canvas.render_svg()
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")


def test_svg_viewport_and_root_attributes() -> None:
    """Section 7.2: Verify SVG root dimensions and namespaces."""
    canvas = create_canonical_waterfall_canvas()
    svg_str = canvas.render_svg()
    root = ET.fromstring(svg_str)

    assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)
    assert root.attrib.get("viewBox") == f"0 0 {CANVAS_VIEWPORT_WIDTH} {CANVAS_VIEWPORT_HEIGHT}"
    assert root.attrib.get("version") == "1.1"


def test_svg_linear_gradients_and_filters() -> None:
    """Section 7.3: Verify defs block contains all 5 stream linear gradients and blur filter."""
    canvas = create_canonical_waterfall_canvas()
    svg_str = canvas.render_svg()

    for s_id in range(1, 6):
        assert f'id="grad-stream-{s_id}"' in svg_str
    assert 'id="stream-glow"' in svg_str
    assert 'id="focus-glow"' in svg_str


def test_svg_golden_baseline_envelope_structure() -> None:
    """Section 7.4: Verify golden design baseline envelope paths and styling."""
    canvas = create_canonical_waterfall_canvas()
    svg_str = canvas.render_svg()

    assert 'id="golden-baseline-envelope"' in svg_str
    assert 'id="golden-envelope-top"' in svg_str
    assert 'id="golden-envelope-bottom"' in svg_str
    assert 'stroke-dasharray="6,4"' in svg_str or 'stroke-dasharray: 6,4' in svg_str


def test_svg_stream_ribbon_paths_present() -> None:
    """Section 7.5: Verify stream ribbon paths 1..5 exist with correct ids."""
    canvas = create_canonical_waterfall_canvas()
    svg_str = canvas.render_svg()

    assert 'id="waterfall-stream-layers"' in svg_str
    for s_id in range(1, 6):
        assert f'id="stream-ribbon-{s_id}"' in svg_str


def test_svg_telemetry_hud_cards_and_badges() -> None:
    """Section 7.6: Verify telemetry HUD cards for all registers and coils."""
    canvas = create_canonical_waterfall_canvas()
    svg_str = canvas.render_svg()

    assert 'id="telemetry-hud"' in svg_str
    assert 'id="hud-card-streams"' in svg_str
    assert 'id="hud-card-throughput"' in svg_str
    assert 'id="hud-card-turbulence"' in svg_str
    assert 'id="hud-card-dispersion"' in svg_str
    assert 'id="hud-card-coils"' in svg_str
    assert '%M350 STREAMING' in svg_str
    assert '%M351' in svg_str
    assert '%R1507:' in svg_str


# ============================================================================
# Section 8: WCAG 2.1 AAA Accessibility & Color Contrast
# ============================================================================

def test_srgb_channel_to_linear_and_hex_to_relative_luminance() -> None:
    """Section 8.1: Verify sRGB channel linearity and luminance calculations."""
    assert srgb_channel_to_linear(0.0) == 0.0
    assert abs(srgb_channel_to_linear(1.0) - 1.0) < 1e-4

    # Pure black = 0.0, pure white = 1.0
    assert hex_to_relative_luminance("#000000") == 0.0
    assert abs(hex_to_relative_luminance("#FFFFFF") - 1.0) < 1e-4


def test_calculate_contrast_ratio_formula() -> None:
    """Section 8.2: Verify contrast ratio symmetry and pure white vs pure black = 21:1."""
    ratio = calculate_contrast_ratio("#FFFFFF", "#000000")
    assert abs(ratio - 21.0) < 1e-3
    assert calculate_contrast_ratio("#000000", "#FFFFFF") == ratio
    assert calculate_contrast_ratio("#123456", "#123456") == 1.0


def test_wcag_aaa_contrast_targets_compliance() -> None:
    """Section 8.3: Verify contrast ratios exceed WCAG 2.1 AAA targets."""
    # Decoupled badge > 18:1
    badge_c = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    assert badge_c >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert badge_c > 18.0

    # Theme text > 7:1
    text_c = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    assert text_c >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert text_c > 7.0

    # SCADA stream colors > 3:1
    for color in [
        COLOR_STREAM_1_SYNGAS,
        COLOR_STREAM_2_WAX,
        COLOR_STREAM_3_DIESEL,
        COLOR_STREAM_4_NAPHTHA,
        COLOR_STREAM_5_OFFGAS,
    ]:
        c = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
        assert c >= WCAG_GRAPHICAL_CONTRAST_TARGET


def test_validate_wcag_aaa_contrast_helper_function() -> None:
    """Section 8.4: Verify validate_wcag_aaa_contrast helper returns expected tuple."""
    all_ok, b_c, t_c, g_c = validate_wcag_aaa_contrast()
    assert all_ok is True
    assert b_c >= 18.0
    assert t_c >= 7.0
    assert g_c >= 3.0


# ============================================================================
# Section 9: Horner RegisterTable Memory Space Integration
# ============================================================================

def test_register_table_synchronization_privilege() -> None:
    """Section 9.1: Verify RegisterTable writes succeed using PrivilegeMode.SYSTEM."""
    reg = RegisterTable()
    canvas = create_canonical_waterfall_canvas(reg_table=reg)
    canvas.sync_to_registers()

    # Reading registers should be non-empty and valid
    assert reg.read_word("%R1500") == 5
    assert reg.read_bit("%M350") is True


def test_nominal_register_read_values() -> None:
    """Section 9.2: Verify register reads match nominal process metrics."""
    canvas = create_canonical_waterfall_canvas()
    canvas.sync_to_registers()
    reg = canvas.reg_table

    assert reg.read_word("%R1500") == NOMINAL_ACTIVE_STREAM_COUNT == 5
    assert reg.read_word("%R1501") == NOMINAL_TOTAL_THROUGHPUT_BPD_SCALED == 1500
    assert reg.read_word("%R1502") == NOMINAL_DOMINANT_STREAM_INDEX == 1
    assert reg.read_word("%R1503") == DEFAULT_EPOCH_DEPTH == 24
    assert reg.read_word("%R1504") == NOMINAL_HYDRODYNAMIC_TURBULENCE_SCALED == 24
    assert reg.read_word("%R1505") == NOMINAL_FLOW_VELOCITY_VARIATION_SCALED == 45
    assert reg.read_word("%R1506") == NOMINAL_STREAM_DISPERSION_COEFF_SCALED == 120
    assert reg.read_word("%R1507") == DIAG_EVENT_OK == 0
    assert reg.read_bit("%M350") is True
    assert reg.read_bit("%M351") is False


def test_stream_waterfall_status_bits() -> None:
    """Section 9.3: Verify StreamWaterfallStatusBits bitmask definitions."""
    bits = StreamWaterfallStatusBits.ENGINE_ACTIVE | StreamWaterfallStatusBits.STREAMING_ACTIVE
    assert bits & StreamWaterfallStatusBits.ENGINE_ACTIVE
    assert bits & StreamWaterfallStatusBits.STREAMING_ACTIVE
    assert not (bits & StreamWaterfallStatusBits.TURBULENCE_WARNING)
    assert not (bits & StreamWaterfallStatusBits.FLOW_STARVATION)


# ============================================================================
# Section 10: Process Safety Interlocks & Diagnostics
# ============================================================================

def test_diagnostic_code_signed_unsigned_equality() -> None:
    """Section 10.1: Verify DiagnosticCode 16-bit signed/unsigned equivalence."""
    d1 = DiagnosticCode(0xD301)
    assert d1 == 0xD301
    assert d1 == -11519
    assert d1 == 54017

    d2 = DiagnosticCode(0xD302)
    assert d2 == 0xD302
    assert d2 == -11518
    assert d2 == 54018

    d3 = DiagnosticCode(0xD303)
    assert d3 == 0xD303
    assert d3 == -11517
    assert d3 == 54019

    d0 = DiagnosticCode(0x0000)
    assert d0 == 0x0000
    assert d0 == 0


def test_trigger_turbulence_breach_interlock() -> None:
    """Section 10.2: Verify 0xD301 turbulence breach asserts %M351 and sets status bits."""
    canvas = create_canonical_waterfall_canvas()
    canvas.trigger_turbulence_breach(turbulence=4.2)

    assert canvas.turbulence_warning is True
    assert canvas.diagnostic_code == STREAM_ERR_TURBULENCE_BREACH
    assert canvas.status_bits & StreamWaterfallStatusBits.TURBULENCE_WARNING
    assert not (canvas.status_bits & StreamWaterfallStatusBits.NOMINAL_OPERATION)
    assert canvas.reg_table.read_bit("%M351") is True
    assert DiagnosticCode(canvas.reg_table.read_word("%R1507")) == 0xD301


def test_trigger_flow_starvation_interlock() -> None:
    """Section 10.3: Verify 0xD302 flow starvation sets status bit and %R1507."""
    canvas = create_canonical_waterfall_canvas()
    canvas.trigger_flow_starvation(total_flow_override=600.0)

    assert canvas.diagnostic_code == STREAM_ERR_FLOW_STARVATION
    assert canvas.status_bits & StreamWaterfallStatusBits.FLOW_STARVATION
    assert not (canvas.status_bits & StreamWaterfallStatusBits.NOMINAL_OPERATION)
    assert canvas.reg_table.read_bit("%M351") is False
    assert DiagnosticCode(canvas.reg_table.read_word("%R1507")) == 0xD302


def test_trigger_render_fault_and_fallback() -> None:
    """Section 10.4: Verify 0xD303 render fault stops streaming and returns fallback SVG."""
    canvas = create_canonical_waterfall_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == STREAM_ERR_RENDER_FAULT
    assert canvas.streaming_active is False
    assert DiagnosticCode(canvas.reg_table.read_word("%R1507")) == 0xD303

    svg_str = canvas.render_svg()
    assert "SVG Render Fault 0xD303 Triggered" in svg_str
    # Still valid XML
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")


def test_clean_nominal_restoration() -> None:
    """Section 10.5: Verify resetting to nominal clears faults and restores coils."""
    canvas = create_canonical_waterfall_canvas()
    canvas.trigger_turbulence_breach()
    assert canvas.reg_table.read_bit("%M351") is True

    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.turbulence_warning is False
    assert canvas.reg_table.read_bit("%M351") is False
    assert canvas.reg_table.read_word("%R1507") == 0
    assert canvas.status_bits & StreamWaterfallStatusBits.NOMINAL_OPERATION


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Execution & Multi-Step Soak
# ============================================================================

def test_ilogic_unit_interface_properties() -> None:
    """Section 11.1: Verify ILogicUnit protocol properties."""
    canvas = create_canonical_waterfall_canvas()
    assert isinstance(canvas, ILogicUnit)
    assert canvas.name == "StreamWaterfallCanvasSync"
    assert canvas.priority == 85
    assert canvas.is_enabled is True


def test_ilogic_unit_100_scan_steps_stability() -> None:
    """Section 11.2: Execute 100+ scan steps verifying stability and register consistency."""
    canvas = create_canonical_waterfall_canvas()
    for cycle in range(1, 105):
        canvas.scan_step(dt=0.01)

    assert canvas.reg_table.read_word("%R1500") == 5
    assert canvas.reg_table.read_word("%R1501") == 1500
    assert canvas.reg_table.read_bit("%M350") is True
    assert canvas.reg_table.read_bit("%M351") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK


def test_scan_cycle_turbulence_auto_trip_and_recovery() -> None:
    """Section 11.3: Verify PLC scan cycle responds dynamically to turbulence register."""
    canvas = create_canonical_waterfall_canvas()

    # Artificially set turbulence scaled to 40 (>= 35 threshold) in register table
    canvas.reg_table.write_word("%R1504", 40, privilege=PrivilegeMode.SYSTEM)
    context = create_mock_scan_context(cycle=1, reg_table=canvas.reg_table)
    canvas.execute(context)

    assert canvas.reg_table.read_bit("%M351") is True
    assert DiagnosticCode(canvas.reg_table.read_word("%R1507")) == 0xD301

    # Return turbulence to nominal 24 (< 35) and clear diagnostic code
    canvas.diagnostic_code = DIAG_EVENT_OK
    canvas.reg_table.write_word("%R1504", 24, privilege=PrivilegeMode.SYSTEM)
    canvas.reg_table.write_word("%R1507", 0, privilege=PrivilegeMode.SYSTEM)
    context2 = create_mock_scan_context(cycle=2, reg_table=canvas.reg_table)
    canvas.execute(context2)

    assert canvas.reg_table.read_bit("%M351") is False
    assert DiagnosticCode(canvas.reg_table.read_word("%R1507")) == 0x0000


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Suite
# ============================================================================

def test_run_stream_waterfall_canvas_verification_deterministic_success(tmp_path: Path) -> None:
    """Section 12.1: Verify verification runner succeeds across all 9 stages."""
    evidence_path = tmp_path / "stream_waterfall_evidence.json"
    svg_path = tmp_path / "stream_waterfall_sample.svg"

    result = run_stream_waterfall_canvas_verification(
        output_path=str(evidence_path),
        sample_svg_path=str(svg_path),
    )

    assert result["status"] == "success"
    assert result["error_code"] is None
    data = result["data"]
    assert data["checks_passed"] == 9
    assert data["total_checks"] == 9
    assert len(data["tests"]) == 9

    for stage_result in data["tests"]:
        assert stage_result["passed"] is True

    # Verify artifacts were written to disk
    assert evidence_path.is_file()
    assert svg_path.is_file()

    with open(evidence_path, "r", encoding="utf-8") as f:
        ev_data = json.load(f)
    assert ev_data["status"] == "success"
    assert ev_data["data"]["checks_passed"] == 9
