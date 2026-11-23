"""Comprehensive pytest test suite for Cscape HMI Dynamic Horizon Chart Multi-Band Offset Density Canvas (W144).

Work Package: W144 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_upset_canvas.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1050..%R1057, %M245..%M246).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Horizon chart band calculation (folding, layering, and negative inversion algorithms).
4. Section 4: Standalone W3C SVG 1.1 XML generation, multi-channel track layout, and folded path ribbons.
5. Section 5: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
6. Section 6: Process safety trips (band excursion 0xA901, invalid band count 0xA902) and Horner coil assertion (%M245, %M246).
7. Section 7: Horner OCS register space synchronization (%R1050..%R1057, %M245..%M246).
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
from jev_cscape.hmi.horizon_canvas import (
    BAND_EXCURSION_LIMIT_SCALED,
    CANVAS_TRACK_LEFT,
    CANVAS_TRACK_RIGHT,
    CANVAS_TRACK_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ADVISORY_AMBER,
    COLOR_ADVISORY_AMBER_DARK,
    COLOR_BASELINE_MARKER,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_DISTRESS_RED,
    COLOR_DISTRESS_RED_DARK,
    COLOR_FOCUS_BLUE,
    COLOR_FOCUS_OUTLINE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_DARK,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRACK_BG,
    COLOR_TRIP_RED,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_BAND_COUNT,
    DEFAULT_BAND_HEIGHT_PIXELS,
    DEFAULT_BANDS,
    DEFAULT_NEGATIVE_PALETTE,
    DEFAULT_POSITIVE_PALETTE,
    DIAG_EVENT_BAND_EXCURSION,
    DIAG_EVENT_INVALID_BAND_COUNT,
    DIAG_EVENT_INVALID_BANDS,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    HORIZON_ERR_BAND_EXCURSION,
    HORIZON_ERR_INVALID_BAND_COUNT,
    HORIZON_ERR_INVALID_BANDS,
    HORIZON_ERR_RENDER_FAULT,
    HORIZON_PURE_ST_POU,
    MAX_BAND_COUNT,
    MAX_BANDS_LIMIT,
    MIN_BAND_COUNT,
    MIN_BANDS_LIMIT,
    NEGATIVE_BAND_PALETTES,
    NUM_PROCESS_CHANNELS,
    POSITIVE_BAND_PALETTES,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    DiagnosticCode,
    HorizonCanvas,
    HorizonCanvasStatusBits,
    HorizonCanvasSync,
    HorizonChannel,
    HorizonChartCanvas,
    HorizonChartHmiSync,
    HorizonEngine,
    HorizonHmiSync,
    HorizonStatusBits,
    ProcessChannel,
    calculate_contrast_ratio,
    compute_band_height,
    compute_band_heights,
    compute_horizon_band_paths,
    create_canonical_channels,
    create_canonical_horizon_canvas,
    create_mock_scan_context,
    generate_horizon_canvas_svg,
    generate_horizon_chart_svg,
    hex_to_relative_luminance,
    run_horizon_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_horizon_canvas_pure_st,
    verify_horizon_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Verify Pure ST POU AST parsing, symbol binding, and Horner register bindings (%R1050..%R1057, %M245..%M246)."""
    assert verify_horizon_canvas_pure_st() is True
    assert verify_horizon_pure_st() is True

    # Validate with SecurityGuard directly
    SecurityGuard.assert_pure_st_content(HORIZON_PURE_ST_POU)

    # Parse with STParser
    parser = STParser()
    ast = parser.parse_pou(HORIZON_PURE_ST_POU)

    assert ast is not None
    assert ast.name == "HorizonCanvasSync"
    assert ast.pou_type == POUType.PROGRAM

    # Verify bound registers in AST (%R1050..%R1057, %M245..%M246)
    expected_registers = {
        "%R1050", "%R1051", "%R1052", "%R1053",
        "%R1054", "%R1055", "%R1056", "%R1057",
        "%M245", "%M246",
    }
    ast_registers = set(ast.bound_registers)
    for reg in expected_registers:
        assert reg in ast_registers, f"Expected register {reg} not found in parsed AST bound registers."

    # Verify variable names and types
    var_dict = {v.name: v for v in ast.variables}
    assert "Channel1CurrentValueScaled" in var_dict
    assert var_dict["Channel1CurrentValueScaled"].data_type == "INT"
    assert var_dict["Channel1CurrentValueScaled"].address_binding == "%R1050"

    assert "Channel2CurrentValueScaled" in var_dict
    assert var_dict["Channel2CurrentValueScaled"].data_type == "INT"
    assert var_dict["Channel2CurrentValueScaled"].address_binding == "%R1051"

    assert "Channel3CurrentValueScaled" in var_dict
    assert var_dict["Channel3CurrentValueScaled"].data_type == "INT"
    assert var_dict["Channel3CurrentValueScaled"].address_binding == "%R1052"

    assert "Channel4CurrentValueScaled" in var_dict
    assert var_dict["Channel4CurrentValueScaled"].data_type == "INT"
    assert var_dict["Channel4CurrentValueScaled"].address_binding == "%R1053"

    assert "ActiveBandCount" in var_dict
    assert var_dict["ActiveBandCount"].data_type == "INT"
    assert var_dict["ActiveBandCount"].address_binding == "%R1054"

    assert "BandHeightPixels" in var_dict
    assert var_dict["BandHeightPixels"].data_type == "INT"
    assert var_dict["BandHeightPixels"].address_binding == "%R1055"

    assert "PeakExcursionChannel" in var_dict
    assert var_dict["PeakExcursionChannel"].data_type == "INT"
    assert var_dict["PeakExcursionChannel"].address_binding == "%R1056"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1057"

    assert "HorizonExcursionTrip" in var_dict
    assert var_dict["HorizonExcursionTrip"].data_type == "BOOL"
    assert var_dict["HorizonExcursionTrip"].address_binding == "%M245"

    assert "HorizonCanvasActive" in var_dict
    assert var_dict["HorizonCanvasActive"].data_type == "BOOL"
    assert var_dict["HorizonCanvasActive"].address_binding == "%M246"

    # Validate source code
    val_res = STParser.validate_code(HORIZON_PURE_ST_POU)
    assert val_res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 2: Anti-Ladder Security Guard Asserting LadderForbiddenError
# ============================================================================

def test_ladder_construct_rejection() -> None:
    """Verify aggressive rejection of ladder logic contacts, coils, rungs, mnemonics with LadderForbiddenError."""
    forbidden_snippets = [
        "PROGRAM BadHorizon VAR Active : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM BadHorizon VAR Active : BOOL; END_VAR ---[/]--- END_PROGRAM",
        "PROGRAM BadHorizon VAR Active : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM BadHorizon VAR Active : BOOL; END_VAR ---(S)--- END_PROGRAM",
        "PROGRAM BadHorizon VAR Active : BOOL; END_VAR ---(R)--- END_PROGRAM",
        "PROGRAM BadHorizon RUNG 1: XIC %M246 OTE %M245; END_RUNG END_PROGRAM",
        "PROGRAM BadHorizon NETWORK 1: LD %M246 ST %M245; END_PROGRAM",
    ]

    for snippet in forbidden_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

        val_res = STParser.validate_code(snippet)
        assert val_res.status == AgentStatus.FAILED
        assert val_res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: Horizon Chart Band Calculation, Folding & Negative Inversion
# ============================================================================

def test_canonical_channels_topology() -> None:
    """Verify canonical industrial plant sensor streams (4 channels) topology and properties."""
    channels = create_canonical_channels(band_count=3)
    assert len(channels) == 4
    assert NUM_PROCESS_CHANNELS == 4

    expected_names = [
        "Core Temp",
        "Loop Pressure",
        "Coolant Flow",
        "Vibration RMS",
    ]
    expected_tags = ["TIC-101", "PIC-102", "FIC-103", "VIB-104"]
    expected_units = ["°C", "bar", "L/min", "mm/s"]
    expected_spans = [40.0, 10.0, 50.0, 5.0]

    for i, ch in enumerate(channels):
        assert ch.channel_id == i
        assert ch.name == expected_names[i]
        assert ch.tag == expected_tags[i]
        assert ch.unit == expected_units[i]
        assert ch.band_span == expected_spans[i]
        assert ch.nominal_baseline == 0.0
        assert ch.baseline == 0.0
        assert len(ch.history) >= 40
        assert len(ch.data_points) == len(ch.history)
        assert ch.bands == 3

    # Scaled value conversions
    assert channels[0].current_value_scaled == 825
    assert channels[1].current_value_scaled == 185
    assert channels[2].current_value_scaled == 950
    assert channels[3].current_value_scaled == 42


def test_horizon_band_calculation_folding_and_layering() -> None:
    """Verify horizon chart band calculation, folding modulo span, and layering order."""
    span = 40.0
    h_track = 120.0

    # 1. Point at v = 20.0 (in Band 1 [0, 40])
    h1 = compute_band_height(20.0, 1, span, h_track, is_negative=False)
    h2 = compute_band_height(20.0, 2, span, h_track, is_negative=False)
    h3 = compute_band_height(20.0, 3, span, h_track, is_negative=False)
    assert math.isclose(h1, 60.0, abs_tol=1e-4)  # 20/40 * 120 = 60px
    assert h2 == 0.0
    assert h3 == 0.0

    # 2. Point at v = 60.0 (in Band 2 [40, 80])
    h1_sat = compute_band_height(60.0, 1, span, h_track, is_negative=False)
    h2_mid = compute_band_height(60.0, 2, span, h_track, is_negative=False)
    h3_zero = compute_band_height(60.0, 3, span, h_track, is_negative=False)
    assert math.isclose(h1_sat, 120.0, abs_tol=1e-4)  # Band 1 fully saturated
    assert math.isclose(h2_mid, 60.0, abs_tol=1e-4)   # (60-40)/40 * 120 = 60px
    assert h3_zero == 0.0

    # 3. Point at v = 100.0 (in Band 3 [80, 120])
    h1_full = compute_band_height(100.0, 1, span, h_track, is_negative=False)
    h2_full = compute_band_height(100.0, 2, span, h_track, is_negative=False)
    h3_mid = compute_band_height(100.0, 3, span, h_track, is_negative=False)
    assert math.isclose(h1_full, 120.0, abs_tol=1e-4)
    assert math.isclose(h2_full, 120.0, abs_tol=1e-4)
    assert math.isclose(h3_mid, 60.0, abs_tol=1e-4)

    # 4. Point at v = 135.0 (excursion > 3 * 40 = 120)
    h3_sat = compute_band_height(135.0, 3, span, h_track, is_negative=False)
    assert math.isclose(h3_sat, 120.0, abs_tol=1e-4)

    # Helper compute_band_heights returning (is_neg, heights)
    is_neg, heights = compute_band_heights(60.0, bands=3, band_span=span, track_height=h_track)
    assert is_neg is False
    assert len(heights) == 3
    assert math.isclose(heights[0], 120.0, abs_tol=1e-4)
    assert math.isclose(heights[1], 60.0, abs_tol=1e-4)
    assert heights[2] == 0.0


def test_negative_inversion_algorithm() -> None:
    """Verify negative value inversion (mirrored upwards) with distinct negative warning bands."""
    span = 40.0
    h_track = 120.0

    # Positive band height for negative input should be 0.0
    assert compute_band_height(-20.0, 1, span, h_track, is_negative=False) == 0.0

    # Point at v = -20.0 (in Negative Band 1 [0, 40])
    n1 = compute_band_height(-20.0, 1, span, h_track, is_negative=True)
    n2 = compute_band_height(-20.0, 2, span, h_track, is_negative=True)
    n3 = compute_band_height(-20.0, 3, span, h_track, is_negative=True)
    assert math.isclose(n1, 60.0, abs_tol=1e-4)  # |-20|/40 * 120 = 60px
    assert n2 == 0.0
    assert n3 == 0.0

    # Point at v = -60.0 (in Negative Band 2 [40, 80])
    n1_sat = compute_band_height(-60.0, 1, span, h_track, is_negative=True)
    n2_mid = compute_band_height(-60.0, 2, span, h_track, is_negative=True)
    n3_zero = compute_band_height(-60.0, 3, span, h_track, is_negative=True)
    assert math.isclose(n1_sat, 120.0, abs_tol=1e-4)
    assert math.isclose(n2_mid, 60.0, abs_tol=1e-4)
    assert n3_zero == 0.0

    # Helper compute_band_heights with negative input
    is_neg, heights = compute_band_heights(-60.0, bands=3, band_span=span, track_height=h_track)
    assert is_neg is True
    assert len(heights) == 3
    assert math.isclose(heights[0], 120.0, abs_tol=1e-4)
    assert math.isclose(heights[1], 60.0, abs_tol=1e-4)
    assert heights[2] == 0.0

    # Verify palettes match specification
    assert len(POSITIVE_BAND_PALETTES[3]) == 3
    assert len(NEGATIVE_BAND_PALETTES[3]) == 3
    assert POSITIVE_BAND_PALETTES[3] == ["#00B4D8", "#0077B6", "#023E8A"]
    assert NEGATIVE_BAND_PALETTES[3] == ["#F39C12", "#E74C3C", "#900C3F"]


def test_channel_metrics_and_excursion_evaluation() -> None:
    """Verify channel current_value, peak_excursion, scaled conversions, and capacity evaluation."""
    ch = ProcessChannel(
        channel_id=0,
        name="Core Temp",
        tag="TIC-101",
        unit="°C",
        band_span=40.0,
        nominal_baseline=0.0,
        current_value=82.5,
        history=[60.0, 82.5, 75.0],
        bands=3,
    )

    assert ch.current_value == 82.5
    assert ch.current_value_scaled == 825
    assert ch.band_span == 40.0

    # Capacity with B=3 is 3 * 40.0 = 120.0
    is_exc = ch.evaluate_excursion(active_band_count=3)
    assert is_exc is False
    assert ch.is_excursion is False

    # Introduce value exceeding 120.0
    ch.history.append(135.0)
    ch.current_value = 135.0
    is_exc2 = ch.evaluate_excursion(active_band_count=3)
    assert is_exc2 is True
    assert ch.is_excursion is True
    assert ch.peak_excursion_val == 135.0
    assert ch.peak_excursion_scaled == 1350


# ============================================================================
# Section 4: Standalone W3C SVG 1.1 XML Generation, Multi-Channel Tracks & Ribbons
# ============================================================================

def test_standalone_w3c_svg_rendering_and_track_ribbons(tmp_path: Path) -> None:
    """Verify standalone W3C SVG 1.1 rendering, XML well-formedness, multi-channel tracks, and folded path ribbons."""
    canvas = create_canonical_horizon_canvas(active_bands=3)
    svg_code = canvas.render_svg()

    # XML well-formedness
    root = ET.fromstring(svg_code)
    assert root.tag.endswith("svg")
    assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)

    # Structural components
    assert f'fill="{COLOR_DARK_THEME_BACKING}"' in svg_code
    assert 'id="canvas-header"' in svg_code
    assert 'id="horizon-tracks"' in svg_code
    assert 'id="telemetry-hud"' in svg_code
    assert 'id="time-scrub-cursor"' in svg_code

    # Multi-channel tracks layout verification:
    for i in range(4):
        assert f'id="track-channel-{i}"' in svg_code
        assert f'id="baseline-marker-ch{i}"' in svg_code

    # Path ribbons and geometry elements
    assert '<path ' in svg_code
    assert '<line ' in svg_code
    assert '<text ' in svg_code

    # Test compute_horizon_band_paths directly
    pos_paths, neg_paths = compute_horizon_band_paths(canvas.channels[0], active_bands=3)
    assert len(pos_paths) == 3
    assert len(neg_paths) == 3
    assert all(p.startswith("M") and p.endswith("Z") for p in pos_paths if p)

    # Alternative dark theme (#1E1E1E)
    svg_1e1e1e = canvas.render_svg(dark_theme_bg=COLOR_DARK_THEME_BACKING_1E1E1E)
    assert COLOR_DARK_THEME_BACKING_1E1E1E in svg_1e1e1e

    # SVG export to file
    out_svg = tmp_path / "test_horizon.svg"
    with open(out_svg, "w", encoding="utf-8") as f:
        f.write(svg_code)
    assert out_svg.exists()
    assert out_svg.stat().st_size > 5000


# ============================================================================
# Section 5: WCAG 2.1 AAA Contrast Ratio Checks (> 7.0:1 text, > 3.0:1 graphics, > 18:1 badge)
# ============================================================================

def test_wcag_21_aaa_contrast_metrics() -> None:
    """Verify WCAG 2.1 AAA contrast guidelines (> 7.0:1 text, > 3.0:1 graphics, > 18:1 badge)."""
    # 1. Decoupled dark backing badge contrast (> 18:1)
    badge_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    assert badge_contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert badge_contrast > 18.0
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0) is True

    # 2. Primary text on canvas backdrop (> 7.0:1)
    text_canvas_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    assert text_canvas_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert text_canvas_contrast > 7.0
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, min_contrast=7.0) is True

    # 3. Muted text on badge (> 7.0:1)
    muted_badge_contrast = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
    assert muted_badge_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert validate_wcag_aaa_contrast(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE, min_contrast=7.0) is True

    # 4. SCADA condition colors on canvas backdrop (> 3.0:1)
    green_contrast = calculate_contrast_ratio(COLOR_NOMINAL_GREEN, COLOR_DARK_THEME_BACKING)
    amber_contrast = calculate_contrast_ratio(COLOR_ADVISORY_AMBER, COLOR_DARK_THEME_BACKING)
    red_contrast = calculate_contrast_ratio(COLOR_DISTRESS_RED, COLOR_DARK_THEME_BACKING)
    focus_contrast = calculate_contrast_ratio(COLOR_FOCUS_BLUE, COLOR_DARK_THEME_BACKING)

    assert green_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert amber_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert red_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert focus_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET

    assert validate_wcag_aaa_contrast(COLOR_NOMINAL_GREEN, COLOR_DARK_THEME_BACKING, min_contrast=3.0) is True
    assert validate_wcag_aaa_contrast(COLOR_ADVISORY_AMBER, COLOR_DARK_THEME_BACKING, min_contrast=3.0) is True
    assert validate_wcag_aaa_contrast(COLOR_DISTRESS_RED, COLOR_DARK_THEME_BACKING, min_contrast=3.0) is True
    assert validate_wcag_aaa_contrast(COLOR_FOCUS_BLUE, COLOR_DARK_THEME_BACKING, min_contrast=3.0) is True


# ============================================================================
# Section 6: Process Safety Trips & Horner Coil Assertion (%M245, %M246)
# ============================================================================

def test_band_excursion_trip_0xa901() -> None:
    """Verify 0xA901 band excursion trip asserts %M245 when value exceeds folded band capacity."""
    canvas = create_canonical_horizon_canvas(active_bands=3)

    # Nominal check
    assert canvas.alarm_excursion_trip is False
    assert canvas.reg_table.read_bit("%M245") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # Trigger band excursion on Channel 1
    canvas.trigger_band_excursion(channel_idx=1, excursion_value=35.0)
    assert canvas.alarm_excursion_trip is True
    assert canvas.reg_table.read_bit("%M245") is True
    assert canvas.diagnostic_code == HORIZON_ERR_BAND_EXCURSION
    assert canvas.diagnostic_code == 0xA901
    assert canvas.diagnostic_code == -22271  # Signed 16-bit match
    assert canvas.peak_excursion_channel == 1
    assert canvas.reg_table.read_word("%R1056") == 1
    assert bool(canvas.status_bits & HorizonStatusBits.BAND_EXCURSION_TRIP)


def test_invalid_bands_trip_0xa902() -> None:
    """Verify 0xA902 invalid band count trip and 0xA903 render fault."""
    canvas = create_canonical_horizon_canvas()

    # 1. Trigger invalid band count (0xA902) with band_count=1
    canvas.trigger_invalid_band_count(band_count=1)
    assert canvas.diagnostic_code == HORIZON_ERR_INVALID_BAND_COUNT
    assert canvas.diagnostic_code == 0xA902
    assert canvas.diagnostic_code == -22270
    assert bool(canvas.status_bits & HorizonStatusBits.INVALID_BAND_COUNT)

    # 2. Trigger render fault (0xA903)
    canvas.reset_nominal()
    canvas.trigger_render_fault()
    assert canvas.diagnostic_code == HORIZON_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xA903
    assert canvas.diagnostic_code == -22269


def test_nominal_reset_clears_trips() -> None:
    """Verify nominal reset restores clean operating state and deasserts %M245."""
    canvas = create_canonical_horizon_canvas()
    canvas.trigger_band_excursion(channel_idx=0, excursion_value=140.0)
    assert canvas.alarm_excursion_trip is True

    canvas.reset_nominal()
    assert canvas.alarm_excursion_trip is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.reg_table.read_bit("%M245") is False
    assert canvas.reg_table.read_bit("%M246") is True


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1050..%R1057, %M245..%M246)
# ============================================================================

def test_horner_ocs_register_space_synchronization() -> None:
    """Verify full Horner OCS memory map bindings (%R1050..%R1057, %M245..%M246) and scan cycle execution."""
    canvas = create_canonical_horizon_canvas(active_bands=3)
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)

    canvas.execute(ctx)
    canvas.step()

    reg = canvas.reg_table
    assert reg.read_word("%R1050") == 825  # CH1 Core Temp Scaled (82.5 x10)
    assert reg.read_word("%R1051") == 185  # CH2 Loop Press Scaled (18.5 x10)
    assert reg.read_word("%R1052") == 950  # CH3 Coolant Flow Scaled (95.0 x10)
    assert reg.read_word("%R1053") == 42   # CH4 Vibration Scaled (4.2 x10)
    assert reg.read_word("%R1054") == 3    # Active Band Count
    assert reg.read_word("%R1055") == 120  # Band Height Pixels
    assert reg.read_word("%R1056") == 0    # Peak Excursion Channel
    assert reg.read_word("%R1057") == 0    # 0x0000 OK
    assert reg.read_bit("%M245") is False  # Alarm excursion trip inactive
    assert reg.read_bit("%M246") is True   # Horizon canvas active


def test_interactive_scrub_and_focus_switching() -> None:
    """Verify interactive time scrub cursor updates and status bit setting."""
    canvas = create_canonical_horizon_canvas()

    assert canvas.scrub_sample_index == 24
    canvas.set_scrub_sample_index(32)
    assert canvas.scrub_sample_index == 32
    assert bool(canvas.status_bits & HorizonStatusBits.SCRUB_ACTIVE)

    # Render with scrub line and excursion badge
    canvas.trigger_band_excursion(channel_idx=0, excursion_value=145.0)
    svg = canvas.render_svg()
    assert 'class="time-scrub-line"' in svg
    assert 'T = 32m' in svg
    assert 'EXCURSION TRIP (%M245)' in svg


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface properties and scan lifecycle methods."""
    canvas = create_canonical_horizon_canvas()
    assert canvas.name == "HorizonCanvasSync"
    assert canvas.priority == 85
    assert canvas.is_enabled is True

    canvas.step()
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

def test_deterministic_9_stage_verification_suite(tmp_path: Path) -> None:
    """Verify run_horizon_canvas_verification executes cleanly across all 9 stages writing evidence JSON and SVG."""
    ev_path = tmp_path / "horizon_evidence.json"
    svg_path = tmp_path / "horizon_sample.svg"

    res = run_horizon_canvas_verification(
        output_path=ev_path,
        sample_svg_path=svg_path,
    )

    assert res["status"] == "success"
    assert res["error_code"] is None
    assert res["data"]["checks_passed"] == 9
    assert res["data"]["total_checks"] == 9
    assert len(res["data"]["tests"]) == 9
    assert all(t["passed"] for t in res["data"]["tests"])

    # Verify evidence file written to disk
    assert ev_path.exists()
    assert ev_path.stat().st_size > 0
    with open(ev_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert loaded["data"]["work_package"] == "W144"
    assert loaded["data"]["gate"] == "Gate G9 / G2"

    # Verify sample SVG written to disk and valid
    assert svg_path.exists()
    assert svg_path.stat().st_size > 0
    with open(svg_path, "r", encoding="utf-8") as f:
        svg_content = f.read()
    root = ET.fromstring(svg_content)
    assert root.tag.endswith("svg")


# ============================================================================
# Supplementary Edge Cases, Diagnostic Code & Branch Coverage Tests
# ============================================================================

def test_diagnostic_code_edge_cases() -> None:
    """Verify DiagnosticCode comparisons, hashing, signed 16-bit handling, and non-int comparisons."""
    code = DiagnosticCode(0xA901)
    assert code == 0xA901
    assert code == -22271
    assert code == 43265
    assert code != 0x0000
    assert code != "invalid_type"
    assert isinstance(hash(code), int)

    ok_code = DiagnosticCode(0x0000)
    assert ok_code == 0
    assert ok_code != 0xA901


def test_color_and_wcag_math_branches() -> None:
    """Verify sRGB channel linear conversion, 3-char hex expansion, and relative luminance math."""
    # Low channel value <= 0.03928
    assert srgb_channel_to_linear(0.01) == 0.01 / 12.92
    assert srgb_channel_to_linear(0.5) > 0.0

    # 3-char hex string
    lum_white_short = hex_to_relative_luminance("#FFF")
    lum_white_long = hex_to_relative_luminance("#FFFFFF")
    assert math.isclose(lum_white_short, lum_white_long, abs_tol=1e-5)


def test_horizon_empty_and_boundary_branches() -> None:
    """Verify boundary conditions, zero band span, clamp logic, and empty history paths."""
    # compute_band_height with zero band_span or zero track_height
    assert compute_band_height(10.0, 1, band_span=0.0, track_height=100.0) == 0.0
    assert compute_band_height(10.0, 1, band_span=50.0, track_height=0.0) == 0.0

    # compute_horizon_band_paths with empty history or zero bands
    ch_empty = ProcessChannel(
        channel_id=0,
        name="Empty",
        tag="EMP-01",
        unit="V",
        band_span=10.0,
        nominal_baseline=0.0,
        current_value=0.0,
        history=[],
    )
    pos_p, neg_p = compute_horizon_band_paths(ch_empty, active_bands=3)
    assert pos_p == []
    assert neg_p == []

    # Single point history
    ch_single = ProcessChannel(
        channel_id=0,
        name="Single",
        tag="SNG-01",
        unit="V",
        band_span=10.0,
        nominal_baseline=0.0,
        current_value=5.0,
        history=[5.0],
    )
    pos_p1, neg_p1 = compute_horizon_band_paths(ch_single, active_bands=3)
    assert pos_p1 == []
    assert neg_p1 == []


def test_horizon_aliases_and_verification_kwargs(tmp_path: Path) -> None:
    """Verify module-level aliases and verification suite keyword arguments."""
    assert HorizonCanvasSync is HorizonCanvas
    assert HorizonHmiSync is HorizonCanvas
    assert HorizonEngine is HorizonCanvas
    assert HorizonChartCanvas is HorizonCanvas
    assert HorizonChartHmiSync is HorizonCanvas
    assert HorizonCanvasStatusBits is HorizonStatusBits
    assert generate_horizon_chart_svg is generate_horizon_canvas_svg

    ev_path = tmp_path / "kwargs_evidence.json"
    svg_path = tmp_path / "kwargs_sample.svg"
    res = run_horizon_canvas_verification(
        evidence_path=ev_path,
        svg_path=svg_path,
    )
    assert res["status"] == "success"
    assert ev_path.exists()
    assert svg_path.exists()
