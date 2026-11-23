"""Comprehensive pytest test suite for Cscape HMI Dynamic Box-and-Whisker Distribution Canvas (W168).

Work Package: W168 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1290..%R1297, %M301..%M302).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: 5 process batch streams statistical distribution geometry and Tukey five-number summary.
4. Section 4: Dual rendering geometry synthesis (Golden Baseline cyan contour vs Real-Time emerald green filled box).
5. Section 5: Standalone W3C SVG 1.1 XML generation, pulsing outlier circles, and quartile HUD metrics card.
6. Section 6: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
7. Section 7: Process safety trips (0xC101 extreme outlier breach, 0xC102 IQR expansion, 0xC103 render fault) and coil assertion (%M301, %M302).
8. Section 8: Horner OCS register space synchronization (%R1290..%R1297, %M301..%M302) with PrivilegeMode.SYSTEM.
9. Section 9: ILogicUnit discrete scan cycle execution and scan_step(dt).
10. Section 10: 9-stage verification suite integration test writing evidence JSON and sample SVG.
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

from jev_cscape.hmi.box_whisker_canvas import (
    BOX_ERR_EXTREME_OUTLIER_BREACH,
    BOX_ERR_IQR_EXPANSION_FAULT,
    BOX_ERR_OK,
    BOX_ERR_OUTLIER_TRIP,
    BOX_ERR_RENDER_FAULT,
    BOX_WHISKER_CANVAS_PURE_ST_POU,
    BOX_WHISKER_PURE_ST_POU,
    BOX_WIDTH,
    CANONICAL_STREAM_COUNT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CAP_WIDTH,
    COLOR_ALERT_HALO,
    COLOR_AMBER,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CRIMSON,
    COLOR_CYAN,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_EMERALD,
    COLOR_FOCUS_BLUE,
    COLOR_GRID_AXIS,
    COLOR_GRID_TICK,
    COLOR_INDIGO,
    COLOR_PURPLE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_EXTREME_OUTLIER_BREACH,
    DIAG_EVENT_IQR_EXPANSION_FAULT,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DiagnosticCode,
    FiveNumberSummary,
    OutlierPoint,
    PROCESS_QUARTILE_DISTRIBUTION_PURE_ST_POU,
    PROCESS_QUARTILE_PURE_ST_POU,
    ProcessQuartileDistributionCanvas,
    ProcessQuartileDistributionHmiSync,
    ProcessStream,
    StreamAlarmState,
    BoxCanvasStatusBits,
    BoxStatusBits,
    BoxWhiskerCanvas,
    BoxWhiskerCanvasEngine,
    BoxWhiskerCanvasSync,
    BoxWhiskerMetrics,
    BoxWhiskerStatusBits,
    calculate_contrast_ratio,
    compute_five_number_summary,
    create_canonical_box_whisker_canvas,
    create_canonical_process_streams,
    create_mock_scan_context,
    detect_outliers_in_data,
    hex_to_relative_luminance,
    map_value_to_screen_y,
    run_box_whisker_canvas_verification,
    validate_wcag_aaa_contrast,
    verify_box_whisker_canvas_pure_st,
    verify_box_whisker_pure_st,
    verify_process_quartile_distribution_pure_st,
    verify_process_quartile_pure_st,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
)


# ============================================================================
# Section 1: Pure ST POU Grammar & Variable AST Validation
# ============================================================================

class TestPureSTValidation:
    """Validate compliance with IEC 61131-3 Pure Structured Text standards."""

    def test_pure_st_pou_syntax_and_ast_parsing(self):
        """Verify BoxWhiskerCanvasSync parses without error and matches expected bindings."""
        SecurityGuard.assert_pure_st_content(BOX_WHISKER_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(BOX_WHISKER_CANVAS_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "BoxWhiskerCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        expected_bindings = {
            "SelectedStreamMedianScaled": "%R1290",
            "SelectedStreamIqrScaled": "%R1291",
            "OutlierCount": "%R1292",
            "Stream1MedianScaled": "%R1293",
            "Stream2MedianScaled": "%R1294",
            "Stream3MedianScaled": "%R1295",
            "SelectedStreamIndex": "%R1296",
            "DiagnosticStatusCode": "%R1297",
            "BoxOutlierTrip": "%M301",
            "BoxCanvasActive": "%M302",
        }

        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict
            assert var_dict[name] == addr

    def test_process_quartile_distribution_alias_pou(self):
        """Verify ProcessQuartileDistributionHmiSync alias POU parses cleanly."""
        SecurityGuard.assert_pure_st_content(PROCESS_QUARTILE_DISTRIBUTION_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(PROCESS_QUARTILE_DISTRIBUTION_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "ProcessQuartileDistributionHmiSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

    def test_helper_verification_functions(self):
        """Verify verification helper functions return True."""
        assert verify_box_whisker_canvas_pure_st() is True
        assert verify_box_whisker_pure_st() is True
        assert verify_process_quartile_distribution_pure_st() is True
        assert verify_process_quartile_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Construct Security Interception
# ============================================================================

class TestLadderConstructInterception:
    """Verify security guard intercepts forbidden ladder logic constructs."""

    @pytest.mark.parametrize(
        "label,snippet",
        [
            ("Contacts", "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"),
            ("Coils", "PROGRAM Bad\nVAR y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"),
            ("Rung", "PROGRAM Bad\nRUNG 1:\nEND_PROGRAM"),
            ("Network", "PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM"),
            ("XIC", "PROGRAM Bad\nXIC B3:0/0;\nEND_PROGRAM"),
            ("OTE", "PROGRAM Bad\nOTE B3:0/1;\nEND_PROGRAM"),
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden(self, label: str, snippet: str):
        """Verify that forbidden ladder logic constructs fail closed with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: Tukey Five-Number Summary & Outlier Calculations
# ============================================================================

class TestTukeyStatisticalCalculations:
    """Verify Tukey five-number summary, IQR, and outlier fences calculations."""

    def test_five_number_summary_odd_length(self):
        """Verify quantile computation on odd-length sequence."""
        data = [10.0, 20.0, 30.0, 40.0, 50.0]
        s = compute_five_number_summary(data)
        assert s.min_val == 10.0
        assert s.median == 30.0
        assert s.max_val == 50.0
        assert s.q1 == 20.0
        assert s.q3 == 40.0
        assert s.iqr == 20.0
        assert s.lower_inner_fence == 20.0 - 1.5 * 20.0  # -10.0
        assert s.upper_inner_fence == 40.0 + 1.5 * 20.0  # 70.0
        assert s.lower_extreme_fence == 20.0 - 3.0 * 20.0  # -40.0
        assert s.upper_extreme_fence == 40.0 + 3.0 * 20.0  # 100.0

    def test_five_number_summary_single_value(self):
        """Verify quantile computation on single value."""
        data = [42.0]
        s = compute_five_number_summary(data)
        assert s.min_val == 42.0
        assert s.median == 42.0
        assert s.max_val == 42.0
        assert s.q1 == 42.0
        assert s.q3 == 42.0
        assert s.iqr == 0.0

    def test_five_number_summary_empty_raises(self):
        """Verify empty sequence raises ValueError."""
        with pytest.raises(ValueError):
            compute_five_number_summary([])

    def test_detect_outliers_mild_and_extreme(self):
        """Verify outlier classification into mild vs extreme."""
        summary = FiveNumberSummary(min_val=10.0, q1=20.0, median=30.0, q3=40.0, max_val=50.0)
        # Inner fence: [-10.0 .. 70.0], Extreme fence: [-40.0 .. 100.0]
        sample_data = [30.0, 75.0, 110.0, -20.0, -50.0]
        outliers = detect_outliers_in_data(summary, sample_data, stream_index=0)

        assert len(outliers) == 4
        # 75.0 is mild upper outlier
        o_75 = [o for o in outliers if math.isclose(o.value, 75.0)][0]
        assert o_75.is_extreme is False
        assert o_75.fence_type == "upper"

        # 110.0 is extreme upper outlier
        o_110 = [o for o in outliers if math.isclose(o.value, 110.0)][0]
        assert o_110.is_extreme is True
        assert o_110.fence_type == "upper"

        # -20.0 is mild lower outlier
        o_m20 = [o for o in outliers if math.isclose(o.value, -20.0)][0]
        assert o_m20.is_extreme is False
        assert o_m20.fence_type == "lower"

        # -50.0 is extreme lower outlier
        o_m50 = [o for o in outliers if math.isclose(o.value, -50.0)][0]
        assert o_m50.is_extreme is True
        assert o_m50.fence_type == "lower"


# ============================================================================
# Section 4: 5 Canonical Process Batch Streams
# ============================================================================

class TestCanonicalStreams:
    """Verify the 5 canonical refinery / petrochemical process streams."""

    def test_stream_count_and_specifications(self):
        """Verify 5 canonical streams have correct physical ranges and tags."""
        streams = create_canonical_process_streams()
        assert len(streams) == 5

        # 1. Crude Distillation Feed Temp (340..390 °C)
        assert streams[0].name == "Crude Distillation Feed Temp"
        assert streams[0].min_range == 340.0
        assert streams[0].max_range == 390.0
        assert streams[0].unit == "°C"
        assert streams[0].median_scaled == 3650  # 365.0 * 10

        # 2. FCC Riser Reactor Exit Temp (490..540 °C)
        assert streams[1].name == "FCC Riser Reactor Exit Temp"
        assert streams[1].min_range == 490.0
        assert streams[1].max_range == 540.0
        assert streams[1].unit == "°C"
        assert streams[1].median_scaled == 5120  # 512.0 * 10
        assert streams[1].iqr_scaled == 140     # 14.0 * 10

        # 3. Hydrocracker Reaction Pressure (140..190 bar)
        assert streams[2].name == "Hydrocracker Reaction Pressure"
        assert streams[2].min_range == 140.0
        assert streams[2].max_range == 190.0
        assert streams[2].unit == "bar"
        assert streams[2].median_scaled == 1650  # 165.0 * 10

        # 4. CCR Reformer Aromatics Octane RON (92..104 RON)
        assert streams[3].name == "CCR Reformer Aromatics Octane RON"
        assert streams[3].min_range == 92.0
        assert streams[3].max_range == 104.0
        assert streams[3].unit == "RON"

        # 5. Delayed Coker Vapor Exit (410..460 °C)
        assert streams[4].name == "Delayed Coker Vapor Exit"
        assert streams[4].min_range == 410.0
        assert streams[4].max_range == 460.0
        assert streams[4].unit == "°C"

    def test_affine_coordinate_mapping(self):
        """Verify map_value_to_screen_y correctly projects values to screen pixels."""
        # For FCC Riser (490..540 °C)
        y_top = 140.0
        y_bottom = 620.0
        y_min = map_value_to_screen_y(490.0, 490.0, 540.0, y_top, y_bottom)
        y_max = map_value_to_screen_y(540.0, 490.0, 540.0, y_top, y_bottom)
        y_mid = map_value_to_screen_y(515.0, 490.0, 540.0, y_top, y_bottom)

        assert math.isclose(y_min, y_bottom, abs_tol=1e-3)
        assert math.isclose(y_max, y_top, abs_tol=1e-3)
        assert math.isclose(y_mid, (y_top + y_bottom) / 2.0, abs_tol=1e-3)


# ============================================================================
# Section 5: BoxWhiskerCanvas Operations & Stream Selection
# ============================================================================

class TestBoxWhiskerCanvasOperations:
    """Verify interactive stream selection and nominal telemetry state."""

    def test_default_initialization_nominal(self):
        """Verify default canvas initialization selects Stream 1 and registers are aligned."""
        canvas = create_canonical_box_whisker_canvas()
        assert canvas.selected_stream_index == 1
        assert canvas.diagnostic_code == BOX_ERR_OK
        assert canvas.outlier_trip is False
        assert canvas.reg_table.read_bit("%M301") is False
        assert canvas.reg_table.read_bit("%M302") is True
        assert canvas.reg_table.read_word("%R1290") == 5120
        assert canvas.reg_table.read_word("%R1291") == 140
        assert canvas.reg_table.read_word("%R1292") == 0
        assert canvas.reg_table.read_word("%R1293") == 3650
        assert canvas.reg_table.read_word("%R1294") == 5120
        assert canvas.reg_table.read_word("%R1295") == 1650
        assert canvas.reg_table.read_word("%R1296") == 1
        assert canvas.reg_table.read_word("%R1297") == 0

    def test_select_stream_updates_registers(self):
        """Verify select_stream updates %R1290, %R1291, and %R1296."""
        canvas = create_canonical_box_whisker_canvas()

        # Select Stream 0 (CDU Feed Temp, median 365.0, IQR 8.0)
        canvas.select_stream(0)
        assert canvas.selected_stream_index == 0
        assert canvas.reg_table.read_word("%R1290") == 3650
        assert canvas.reg_table.read_word("%R1291") == 80
        assert canvas.reg_table.read_word("%R1296") == 0

        # Select Stream 2 (Hydrocracker Reaction Pressure, median 165.0, IQR 8.0)
        canvas.select_stream(2)
        assert canvas.selected_stream_index == 2
        assert canvas.reg_table.read_word("%R1290") == 1650
        assert canvas.reg_table.read_word("%R1291") == 80
        assert canvas.reg_table.read_word("%R1296") == 2


# ============================================================================
# Section 6: Process Safety Interlocks & Diagnostic Faults
# ============================================================================

class TestSafetyInterlocksAndFaults:
    """Verify 0xC101, 0xC102, 0xC103 diagnostic event codes and interlocks."""

    def test_extreme_outlier_breach_trip_0xC101(self):
        """Verify 0xC101 extreme outlier breach asserts %M301 and latches diagnostic code."""
        canvas = create_canonical_box_whisker_canvas()
        assert canvas.outlier_trip is False
        assert canvas.reg_table.read_bit("%M301") is False

        # Inject extreme outlier on Stream 1
        canvas.trigger_extreme_outlier_trip(stream_index=1, injected_val=575.0)

        assert canvas.outlier_trip is True
        assert canvas.reg_table.read_bit("%M301") is True
        assert canvas.diagnostic_code == BOX_ERR_EXTREME_OUTLIER_BREACH
        assert canvas.diagnostic_code == 0xC101
        assert canvas.diagnostic_code == -16127
        assert DiagnosticCode(canvas.reg_table.read_word("%R1297")) == 0xC101
        assert canvas.reg_table.read_word("%R1292") >= 1
        assert bool(canvas.status_bits & BoxWhiskerStatusBits.EXTREME_OUTLIER_TRIP)
        assert bool(canvas.status_bits & BoxWhiskerStatusBits.OUTLIERS_DETECTED)
        assert not bool(canvas.status_bits & BoxWhiskerStatusBits.NOMINAL_OPERATION)

    def test_iqr_expansion_fault_0xC102(self):
        """Verify 0xC102 IQR expansion fault when IQR span expands > 200% of baseline."""
        canvas = create_canonical_box_whisker_canvas()
        canvas.trigger_iqr_expansion_fault(stream_index=1, expansion_factor=2.5)

        assert canvas.diagnostic_code == BOX_ERR_IQR_EXPANSION_FAULT
        assert canvas.diagnostic_code == 0xC102
        assert canvas.diagnostic_code == -16126
        assert DiagnosticCode(canvas.reg_table.read_word("%R1297")) == 0xC102
        assert bool(canvas.status_bits & BoxWhiskerStatusBits.IQR_EXPANSION_FAULT)
        assert not bool(canvas.status_bits & BoxWhiskerStatusBits.NOMINAL_OPERATION)

    def test_render_fault_0xC103_and_reset(self):
        """Verify 0xC103 render fault and reset_nominal restore clean state."""
        canvas = create_canonical_box_whisker_canvas()
        canvas.trigger_render_fault()

        assert canvas.diagnostic_code == BOX_ERR_RENDER_FAULT
        assert canvas.diagnostic_code == 0xC103
        assert canvas.diagnostic_code == -16125
        assert DiagnosticCode(canvas.reg_table.read_word("%R1297")) == 0xC103
        assert bool(canvas.status_bits & BoxWhiskerStatusBits.RENDER_FAULT)

        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.outlier_trip is False
        assert canvas.reg_table.read_bit("%M301") is False
        assert canvas.reg_table.read_word("%R1297") == 0
        assert bool(canvas.status_bits & BoxWhiskerStatusBits.NOMINAL_OPERATION)


# ============================================================================
# Section 7: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

class TestSVGRenderer:
    """Verify SVG generation, XML schema validity, elements, and styles."""

    def test_svg_is_valid_xml(self):
        """Verify render_svg outputs well-formed XML parseable by ElementTree."""
        canvas = create_canonical_box_whisker_canvas()
        svg_str = canvas.render_svg()

        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)

    def test_svg_contains_required_elements(self):
        """Verify SVG contains 5 streams, baseline contour, real-time boxes, and HUD card."""
        canvas = create_canonical_box_whisker_canvas()
        canvas.streams[1].outliers.append(
            OutlierPoint(value=535.0, stream_index=1, is_extreme=False, fence_type="upper")
        )
        svg_str = canvas.render_svg()

        assert 'id="canvas-header"' in svg_str
        assert 'id="box-plot-area"' in svg_str
        assert 'id="stream-box-plots"' in svg_str
        assert 'id="quartile-hud-card"' in svg_str
        assert 'id="stream-column-0"' in svg_str
        assert 'id="stream-column-1"' in svg_str
        assert 'id="stream-column-2"' in svg_str
        assert 'id="stream-column-3"' in svg_str
        assert 'id="stream-column-4"' in svg_str
        assert 'id="baseline-stream-0"' in svg_str
        assert 'id="realtime-stream-0"' in svg_str
        assert 'class="outlier-pulse"' in svg_str
        assert COLOR_DARK_THEME_BACKING in svg_str
        assert COLOR_CYAN in svg_str
        assert COLOR_EMERALD in svg_str


# ============================================================================
# Section 8: WCAG 2.1 AAA Accessibility & Contrast Ratios
# ============================================================================

class TestWCAGAccessibility:
    """Verify color palette meets WCAG 2.1 AAA accessibility targets."""

    def test_relative_luminance_and_contrast_helpers(self):
        """Verify relative luminance and contrast calculation."""
        lum_white = hex_to_relative_luminance("#FFFFFF")
        lum_black = hex_to_relative_luminance("#000000")
        assert math.isclose(lum_white, 1.0, abs_tol=1e-3)
        assert math.isclose(lum_black, 0.0, abs_tol=1e-3)

        cr = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert math.isclose(cr, 21.0, abs_tol=1e-1)

    def test_decoupled_badge_contrast_exceeds_18_to_1(self):
        """Verify decoupled dark badge contrast > 18.0:1."""
        cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert cr > 18.0

    def test_text_and_graphics_contrast_ratios(self):
        """Verify text > 7.0:1 and SCADA graphics > 3.0:1."""
        cr_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert cr_text >= WCAG_AAA_TEXT_CONTRAST_TARGET

        cr_emerald = calculate_contrast_ratio(COLOR_EMERALD, COLOR_DARK_THEME_BACKING)
        cr_cyan = calculate_contrast_ratio(COLOR_CYAN, COLOR_DARK_THEME_BACKING)
        cr_amber = calculate_contrast_ratio(COLOR_AMBER, COLOR_DARK_THEME_BACKING)
        cr_crimson = calculate_contrast_ratio(COLOR_CRIMSON, COLOR_DARK_THEME_BACKING)

        assert cr_emerald >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert cr_cyan >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert cr_amber >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert cr_crimson >= WCAG_GRAPHICAL_CONTRAST_TARGET


# ============================================================================
# Section 9: ILogicUnit Discrete Scan Cycle Execution
# ============================================================================

class TestScanCycleExecution:
    """Verify ILogicUnit interface compliance and scan cycle behavior."""

    def test_ilogicunit_interface_methods(self):
        """Verify BoxWhiskerCanvas implements ILogicUnit properties and methods."""
        canvas = create_canonical_box_whisker_canvas()
        assert isinstance(canvas, ILogicUnit)
        assert canvas.name == "BoxWhiskerCanvasSync"
        assert canvas.priority == 88
        assert canvas.is_enabled is True

    def test_scan_step_advances_telemetry(self):
        """Verify scan_step and execute run without error and sync registers."""
        canvas = create_canonical_box_whisker_canvas()
        canvas.scan_step(dt=0.01)

        ctx = create_mock_scan_context(cycle=1, reg_table=canvas.reg_table)
        canvas.execute(ctx)
        assert canvas.reg_table.read_word("%R1290") == 5120
        assert canvas.reg_table.read_bit("%M302") is True

    def test_scan_cycle_detects_injected_register_trip(self):
        """Verify scan cycle trip when %R1297 is written with 0xC101 (-16127)."""
        canvas = create_canonical_box_whisker_canvas()
        reg = canvas.reg_table
        ctx = create_mock_scan_context(cycle=2, reg_table=reg)

        reg.write_word("%R1297", -16127, privilege=PrivilegeMode.SYSTEM)
        canvas.diagnostic_code = BOX_ERR_EXTREME_OUTLIER_BREACH
        canvas.execute(ctx)

        assert reg.read_bit("%M301") is True
        assert DiagnosticCode(reg.read_word("%R1297")) == BOX_ERR_EXTREME_OUTLIER_BREACH


# ============================================================================
# Section 10: 9-Stage Verification Suite Integration
# ============================================================================

class TestVerificationSuiteIntegration:
    """Verify run_box_whisker_canvas_verification executes all 9 stages successfully."""

    def test_verification_suite_9_stages(self, tmp_path: Path):
        """Verify full 9-stage verification suite produces success and valid evidence."""
        out_ev = str(tmp_path / "box_whisker_canvas_evidence.json")
        out_svg = str(tmp_path / "box_whisker_canvas_sample.svg")

        result = run_box_whisker_canvas_verification(output_path=out_ev, sample_svg_path=out_svg)

        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9

        # Verify output files exist and are populated
        assert Path(out_ev).exists()
        assert Path(out_svg).exists()

        with open(out_ev, "r", encoding="utf-8") as f:
            ev_data = json.load(f)
            assert ev_data["status"] == "success"
            assert ev_data["data"]["work_package"] == "W168"
            assert len(ev_data["data"]["tests"]) == 9

        with open(out_svg, "r", encoding="utf-8") as f:
            svg_text = f.read()
            assert "<svg" in svg_text
            assert "</svg>" in svg_text
            assert 'id="quartile-hud-card"' in svg_text
