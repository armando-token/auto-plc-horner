"""Unit tests for Cscape HMI Dynamic Streamgraph Stacked Continuous Flow & Resource Allocation Canvas (W132).

Work Package: W132 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.streamgraph_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ADVISORY_AMBER,
    COLOR_ADVISORY_AMBER_LIGHT,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_LIGHT,
    COLOR_STREAM_1_CYAN,
    COLOR_STREAM_2_AMBER,
    COLOR_STREAM_3_EMERALD,
    COLOR_STREAM_4_VIOLET,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_RED,
    COLOR_TRIP_RED_LIGHT,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_HORIZON_SAMPLES,
    DEFAULT_PEAK_CAPACITY_LIMIT,
    DIAG_EVENT_BUFFER_OVERFLOW,
    DIAG_EVENT_OK,
    DIAG_EVENT_RESOURCE_DEFICIT,
    DIAG_EVENT_STARVATION,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    MAX_HORIZON_SAMPLES,
    MIN_HORIZON_SAMPLES,
    PLOT_HEIGHT,
    PLOT_WIDTH,
    PLOT_X_MAX,
    PLOT_X_MIN,
    PLOT_Y_MAX,
    PLOT_Y_MID,
    PLOT_Y_MIN,
    STARVATION_NOMINAL_RATIO_LIMIT,
    STREAM_ERR_BUFFER_OVERFLOW,
    STREAM_ERR_RESOURCE_DEFICIT,
    STREAM_ERR_STARVATION,
    STREAMGRAPH_PURE_ST_POU,
    BaselineMode,
    BaselineOffsetMode,
    DiagnosticCode,
    StreamDefinition,
    StreamgraphCanvas,
    StreamgraphCanvasSync,
    StreamgraphEngine,
    StreamgraphHmiSync,
    StreamgraphMetrics,
    StreamgraphStatusBits,
    StreamgraphSystem,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    compute_cubic_bezier_spline_points,
    compute_layer_boundaries,
    compute_streamgraph_baseline,
    compute_streamgraph_metrics,
    create_canonical_streamgraph_system,
    create_mock_scan_context,
    generate_stream_ribbon_svg_path,
    generate_streamgraph_canvas_svg,
    hex_to_relative_luminance,
    run_streamgraph_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_streamgraph_canvas_pure_st,
    verify_streamgraph_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Section 1: Verify Pure ST POU AST parsing, symbol binding, and Horner register bindings (%R930..%R937, %M217..%M218)."""
    assert verify_streamgraph_canvas_pure_st() is True
    assert verify_streamgraph_pure_st() is True

    # SecurityGuard assertion against ladder logic
    SecurityGuard.assert_pure_st_content(STREAMGRAPH_PURE_ST_POU)

    # Syntax validation via STParser
    res = STParser.validate_code(STREAMGRAPH_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS

    # AST structure and bound registers verification
    parser = STParser()
    ast = parser.parse_pou(STREAMGRAPH_PURE_ST_POU)
    assert ast is not None
    assert ast.name == "StreamgraphCanvasSync"
    assert ast.pou_type == POUType.PROGRAM

    expected_registers = [
        "%R930", "%R931", "%R932", "%R933",
        "%R934", "%R935", "%R936", "%R937",
        "%M217", "%M218",
    ]
    for reg in expected_registers:
        assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Assertion
# ============================================================================

def test_anti_ladder_security_guard_rejection() -> None:
    """Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, and rungs."""
    bad_snippets = [
        "PROGRAM BadStream1 VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM BadStream2 VAR X : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM BadStream3 VAR X : BOOL; END_VAR XIC %M217; END_PROGRAM",
        "PROGRAM BadStream4 VAR X : BOOL; END_VAR OTE %M218; END_PROGRAM",
        "PROGRAM BadStream5 VAR X : BOOL; END_VAR RUNG 1 StreamActive := TRUE; END_PROGRAM",
        "PROGRAM BadStream6 VAR X : BOOL; END_VAR NETWORK 1 END_PROGRAM",
    ]
    for snip in bad_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snip)


# ============================================================================
# 3. Section 3: Byron & Wattenberg Baseline Offset Algorithms
# ============================================================================

def test_byron_wattenberg_baseline_offset_algorithms() -> None:
    """Section 3: Byron & Wattenberg baseline offset algorithms (Zero, Silhouette, Wiggle minimization)."""
    t_samples = 24
    test_flows = [
        [50.0 + 10.0 * math.sin(t * 0.45) for t in range(t_samples)],
        [70.0 + 14.0 * math.cos(t * 0.38) for t in range(t_samples)],
        [60.0 + 8.0 * math.sin(t * 0.32 + 1.2) for t in range(t_samples)],
        [40.0 + 6.0 * math.cos(t * 0.55 + 2.1) for t in range(t_samples)],
    ]

    # 1. Mode 0: Zero Baseline (Flat-bottom traditional stacked area)
    g_zero, energy_zero = compute_streamgraph_baseline(test_flows, BaselineMode.ZERO)
    assert len(g_zero) == t_samples
    assert all(val == 0.0 for val in g_zero), "Zero baseline offsets must all strictly be 0.0"
    assert energy_zero > 0.0

    # 2. Mode 1: Silhouette / Centered Baseline: g(t) = -0.5 * sum_i(f_i(t))
    g_silh, energy_silh = compute_streamgraph_baseline(test_flows, BaselineMode.SILHOUETTE)
    assert len(g_silh) == t_samples
    for t in range(t_samples):
        expected_g = -0.5 * sum(test_flows[i][t] for i in range(4))
        assert math.isclose(g_silh[t], expected_g, rel_tol=1e-5), f"Silhouette baseline mismatch at step {t}"

    # 3. Mode 2: Byron & Wattenberg Wiggle Minimization Baseline
    g_wiggle, energy_wiggle = compute_streamgraph_baseline(test_flows, BaselineMode.WIGGLE)
    assert len(g_wiggle) == t_samples

    # Byron & Wattenberg energy minimization theorem:
    # Wiggle energy must be lower than or equal to both Silhouette energy and Zero baseline energy
    assert energy_wiggle <= energy_silh, f"Wiggle energy {energy_wiggle:.2f} must be <= Silhouette energy {energy_silh:.2f}"
    assert energy_wiggle <= energy_zero, f"Wiggle energy {energy_wiggle:.2f} must be <= Zero energy {energy_zero:.2f}"

    # 4. Layer Boundary Calculations
    layers_bot, layers_top = compute_layer_boundaries(test_flows, g_silh)
    assert len(layers_bot) == 4
    assert len(layers_top) == 4

    for t in range(t_samples):
        # Bottom of layer 0 is the baseline offset
        assert math.isclose(layers_bot[0][t], g_silh[t], rel_tol=1e-5)
        for i in range(4):
            thickness = layers_top[i][t] - layers_bot[i][t]
            assert math.isclose(thickness, test_flows[i][t], rel_tol=1e-5), f"Layer {i} thickness mismatch at step {t}"
            if i > 0:
                # Contiguity: bottom of layer i equals top of layer i-1
                assert math.isclose(layers_bot[i][t], layers_top[i - 1][t], rel_tol=1e-5)

    # 5. Degenerate and edge-case handling
    g_empty, e_empty = compute_streamgraph_baseline([], BaselineMode.WIGGLE)
    assert g_empty == []
    assert e_empty == 0.0

    g_single, e_single = compute_streamgraph_baseline([[25.0]], BaselineMode.WIGGLE)
    assert len(g_single) == 1
    assert math.isclose(g_single[0], -12.5, rel_tol=1e-5)

    # Enum and alias checks
    assert BaselineMode.ZERO == 0
    assert BaselineMode.SILHOUETTE == 1
    assert BaselineMode.WIGGLE == 2
    assert BaselineOffsetMode == BaselineMode


# ============================================================================
# 4. Section 4: Cubic Bezier Spline Interpolation & SVG Area Polygon Generation
# ============================================================================

def test_cubic_bezier_spline_interpolation_and_area_polygon_path() -> None:
    """Section 4: Cubic Bezier spline interpolation and area polygon SVG path generation ('M ... C ... L ... C ... Z')."""
    # 1. Cubic Bezier spline control point generation
    points = [
        (80.0, 300.0),
        (200.0, 350.0),
        (350.0, 280.0),
        (500.0, 320.0),
        (650.0, 260.0),
    ]
    control_points = compute_cubic_bezier_spline_points(points)
    assert len(control_points) == len(points) - 1

    # Verify C^1 continuity across interior knots
    for k in range(1, len(points) - 1):
        (cp1_prev_x, cp1_prev_y), (cp2_prev_x, cp2_prev_y) = control_points[k - 1]
        (cp1_curr_x, cp1_curr_y), (cp2_curr_x, cp2_curr_y) = control_points[k]

        dx_in = points[k][0] - cp2_prev_x
        dy_in = points[k][1] - cp2_prev_y
        slope_in = dy_in / dx_in

        dx_out = cp1_curr_x - points[k][0]
        dy_out = cp1_curr_y - points[k][1]
        slope_out = dy_out / dx_out

        assert math.isclose(slope_in, slope_out, rel_tol=1e-3, abs_tol=1e-3), (
            f"Knot {k} must have C^1 continuous tangent slope (in={slope_in:.4f}, out={slope_out:.4f})"
        )

    # 2. Area polygon SVG path generation
    top_pts = [(80.0 + t * 40.0, 200.0 + 10.0 * math.sin(t * 0.4)) for t in range(24)]
    bot_pts = [(80.0 + t * 40.0, 320.0 + 12.0 * math.cos(t * 0.3)) for t in range(24)]
    path_d = generate_stream_ribbon_svg_path(top_pts, bot_pts)

    # Syntax and grammar verification: 'M ... C ... L ... C ... Z'
    assert path_d.startswith("M "), "Path must begin with absolute moveto 'M '"
    assert " C " in path_d, "Path must contain forward cubic curveto segments ' C '"
    assert " L " in path_d, "Path must contain connecting lineto ' L '"
    assert path_d.endswith(" Z"), "Path must close with ' Z'"

    # 3. Standalone W3C SVG 1.1 Vector Canvas XML validation
    canvas = StreamgraphCanvas()
    svg_str = canvas.render_svg()

    parsed_tree = ET.fromstring(svg_str)
    assert parsed_tree.tag == "{http://www.w3.org/2000/svg}svg"
    assert parsed_tree.attrib["width"] == "1200"
    assert parsed_tree.attrib["height"] == "750"

    # Semantic SVG elements and IDs
    assert COLOR_DARK_THEME_BACKING in svg_str
    assert 'id="diagnostic-hud"' in svg_str
    assert 'id="streamgraph-grid"' in svg_str
    assert 'id="streamgraph-ribbons"' in svg_str
    assert 'id="operating-cursor"' in svg_str
    assert 'id="stream-legends"' in svg_str
    # Peak threshold line is rendered when within viewport (e.g. in Zero baseline mode)
    canvas_zero = StreamgraphCanvas(system=create_canonical_streamgraph_system(mode=BaselineMode.ZERO))
    svg_zero = canvas_zero.render_svg()
    assert 'id="peak-threshold-line"' in svg_zero
    assert 'HORNER OCS REGISTER SPACE' in svg_str

    # Degenerate path fallback
    assert generate_stream_ribbon_svg_path([], []) == "M 0 0 Z"
    assert compute_cubic_bezier_spline_points([(10.0, 10.0)]) == []


# ============================================================================
# 5. Section 5: WCAG 2.1 AAA Contrast Ratio Checks (> 7.0:1 Text, > 3.0:1 Graphical)
# ============================================================================

def test_wcag_21_aaa_contrast_ratio_checks() -> None:
    """Section 5: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge)."""
    # Palette definition checks
    assert COLOR_NOMINAL_GREEN == "#107C41"
    assert COLOR_NOMINAL_GREEN_LIGHT == "#27AE60"
    assert COLOR_ADVISORY_AMBER == "#D83B01"
    assert COLOR_ADVISORY_AMBER_LIGHT == "#F39C12"
    assert COLOR_TRIP_RED == "#A80000"
    assert COLOR_TRIP_RED_LIGHT == "#E74C3C"
    assert COLOR_DARK_THEME_BACKING == "#0F172A"
    assert COLOR_DARK_THEME_BACKING_1E1E1E == "#1E1E1E"
    assert COLOR_DECOUPLED_BADGE == "#0B0F19"
    assert COLOR_TEXT_PRIMARY == "#F8FAFC"
    assert COLOR_STREAM_1_CYAN == "#00B4D8"
    assert COLOR_STREAM_2_AMBER == "#F39C12"
    assert COLOR_STREAM_3_EMERALD == "#2ECC71"
    assert COLOR_STREAM_4_VIOLET == "#9B59B6"

    # Contrast ratio calculations
    contrast_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    contrast_dark_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    contrast_1e1e1e_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING_1E1E1E)
    contrast_s1 = calculate_contrast_ratio(COLOR_STREAM_1_CYAN, COLOR_DARK_THEME_BACKING)
    contrast_s2 = calculate_contrast_ratio(COLOR_STREAM_2_AMBER, COLOR_DARK_THEME_BACKING)
    contrast_s3 = calculate_contrast_ratio(COLOR_STREAM_3_EMERALD, COLOR_DARK_THEME_BACKING)
    contrast_s4 = calculate_contrast_ratio(COLOR_STREAM_4_VIOLET, COLOR_DARK_THEME_BACKING)
    contrast_green = calculate_contrast_ratio(COLOR_NOMINAL_GREEN_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_amber = calculate_contrast_ratio(COLOR_ADVISORY_AMBER_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_red = calculate_contrast_ratio(COLOR_TRIP_RED_LIGHT, COLOR_DARK_THEME_BACKING)

    # Assert WCAG 2.1 AAA targets
    assert contrast_badge >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_badge > 18.0, "Decoupled badge contrast must exceed 18:1"
    assert contrast_dark_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_1e1e1e_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_s1 >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_s2 >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_s3 >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_s4 >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_green >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_amber >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_red >= WCAG_GRAPHICAL_CONTRAST_TARGET

    # validate_wcag_aaa_contrast function
    ok, t_cr, g_cr = validate_wcag_aaa_contrast()
    assert ok is True
    assert t_cr >= 7.0
    assert g_cr >= 3.0

    # sRGB channel and luminance helper checks
    assert srgb_channel_to_linear(0.0) == 0.0
    assert srgb_channel_to_linear(1.0) == 1.0
    assert hex_to_relative_luminance("#000000") == 0.0
    assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, rel_tol=1e-5)


# ============================================================================
# 6. Section 6: Process Safety Trips & Horner Coil Assertion (%M217, %M218)
# ============================================================================

def test_process_safety_trips_and_horner_coils() -> None:
    """Section 6: Process safety trips (resource deficit 0x9D01, starvation 0x9D02) and Horner coil assertion (%M217, %M218)."""
    # 1. Nominal baseline operation
    canvas = StreamgraphCanvas(system=create_canonical_streamgraph_system(mode=BaselineMode.SILHOUETTE))
    assert canvas.metrics.resource_deficit is False
    assert canvas.metrics.starvation_detected is False
    assert canvas.reg_table.read_bit("%M217") is False
    assert canvas.reg_table.read_bit("%M218") is True  # Mode 1 active
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # 2. Resource Deficit Trip (%M217, code 0x9D01)
    canvas_deficit = StreamgraphCanvas(system=create_canonical_streamgraph_system(deficit=True))
    assert canvas_deficit.metrics.resource_deficit is True
    assert canvas_deficit.reg_table.read_bit("%M217") is True
    assert canvas_deficit.diagnostic_code == STREAM_ERR_RESOURCE_DEFICIT
    assert canvas_deficit.diagnostic_code == DIAG_EVENT_RESOURCE_DEFICIT
    assert canvas_deficit.diagnostic_code == 0x9D01
    assert canvas_deficit.diagnostic_code == -25343  # Signed 16-bit
    assert bool(canvas_deficit.status_bits & StreamgraphStatusBits.RESOURCE_DEFICIT_TRIP) is True

    # 3. Critical Stream Starvation Trip (code 0x9D02)
    canvas_starv = StreamgraphCanvas(system=create_canonical_streamgraph_system(starvation=True))
    assert canvas_starv.metrics.starvation_detected is True
    assert canvas_starv.diagnostic_code == STREAM_ERR_STARVATION
    assert canvas_starv.diagnostic_code == DIAG_EVENT_STARVATION
    assert canvas_starv.diagnostic_code == 0x9D02
    assert canvas_starv.diagnostic_code == -25342  # Signed 16-bit
    assert bool(canvas_starv.status_bits & StreamgraphStatusBits.STARVATION_ALARM) is True

    # 4. Injected triggers and reset
    canvas_inj = StreamgraphCanvas()
    canvas_inj.trigger_deficit(350.0)
    assert canvas_inj.metrics.resource_deficit is True
    assert canvas_inj.reg_table.read_bit("%M217") is True
    assert canvas_inj.diagnostic_code == 0x9D01

    canvas_inj.reset()
    assert canvas_inj.metrics.resource_deficit is False
    assert canvas_inj.reg_table.read_bit("%M217") is False
    assert canvas_inj.diagnostic_code == DIAG_EVENT_OK

    canvas_inj.trigger_starvation(0)
    assert canvas_inj.metrics.starvation_detected is True
    assert canvas_inj.diagnostic_code == 0x9D02

    # 5. Buffer Overflow Diagnostic (0x9D03)
    canvas_inj.set_time_horizon(75)
    assert canvas_inj.diagnostic_code == STREAM_ERR_BUFFER_OVERFLOW
    assert canvas_inj.diagnostic_code == 0x9D03
    assert canvas_inj.diagnostic_code == -25341
    assert bool(canvas_inj.status_bits & StreamgraphStatusBits.BUFFER_OVERFLOW) is True

    # DiagnosticCode equality and hash checks
    assert DIAG_EVENT_RESOURCE_DEFICIT == 0x9D01
    assert DIAG_EVENT_RESOURCE_DEFICIT == -25343
    assert DIAG_EVENT_STARVATION == 0x9D02
    assert DIAG_EVENT_STARVATION == -25342
    assert hash(DIAG_EVENT_RESOURCE_DEFICIT) == hash(0x9D01)


# ============================================================================
# 7. Section 7: Horner OCS Register Space Synchronization (%R930..%R937, %M217..%M218)
# ============================================================================

def test_horner_ocs_register_space_synchronization() -> None:
    """Section 7: Horner OCS register space synchronization (%R930..%R937, %M217..%M218) and scan cycle execution."""
    canvas = StreamgraphCanvas(system=create_canonical_streamgraph_system(mode=BaselineMode.SILHOUETTE, samples=24))
    reg = canvas.reg_table

    r930 = reg.read_word("%R930")
    r931 = reg.read_word("%R931")
    r932 = reg.read_word("%R932")
    r933 = reg.read_word("%R933")
    r934 = reg.read_word("%R934")
    r935 = reg.read_word("%R935")
    r936 = reg.read_word("%R936")
    r937 = reg.read_word("%R937")
    m217 = reg.read_bit("%M217")
    m218 = reg.read_bit("%M218")

    # Status word bit checks
    assert bool(canvas.status_bits & StreamgraphStatusBits.CANVAS_ACTIVE) is True
    assert bool(canvas.status_bits & StreamgraphStatusBits.FLOW_COMPUTED) is True
    assert bool(canvas.status_bits & StreamgraphStatusBits.BASELINE_CENTERED) is True
    assert bool(canvas.status_bits & StreamgraphStatusBits.WCAG_AAA) is True

    # Register values
    assert r930 == canvas.metrics.stream1_scaled
    assert r931 == canvas.metrics.stream2_scaled
    assert r932 == canvas.metrics.stream3_scaled
    assert r933 == canvas.metrics.stream4_scaled
    assert r934 == canvas.metrics.aggregate_scaled
    assert r935 == 1   # BaselineMode.SILHOUETTE
    assert r936 == 24  # Time horizon samples
    assert r937 == DIAG_EVENT_OK
    assert m217 is False
    assert m218 is True

    # Mode switching and register reflection
    # Switch to Zero Mode: %R935 becomes 0, %M218 is cleared
    canvas.set_baseline_mode(BaselineMode.ZERO)
    assert canvas.reg_table.read_word("%R935") == 0
    assert canvas.reg_table.read_bit("%M218") is False

    # Switch to Wiggle Mode: %R935 becomes 2, %M218 is asserted
    canvas.set_baseline_mode(BaselineMode.WIGGLE)
    assert canvas.reg_table.read_word("%R935") == 2
    assert canvas.reg_table.read_bit("%M218") is True

    # Switch back to Silhouette Mode
    canvas.set_baseline_mode(BaselineMode.SILHOUETTE)
    assert canvas.reg_table.read_word("%R935") == 1
    assert canvas.reg_table.read_bit("%M218") is True

    # ILogicUnit interface & Scan cycle execution
    assert canvas.name == "StreamgraphCanvasSync"
    assert canvas.priority == 78
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg)
    canvas.execute(ctx)
    canvas.step()
    canvas.execute_logic(ctx)

    # Class aliases
    assert StreamgraphCanvasSync == StreamgraphCanvas
    assert StreamgraphHmiSync == StreamgraphCanvas
    assert StreamgraphEngine == StreamgraphCanvas


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

def test_run_streamgraph_canvas_verification_suite(tmp_path: Path) -> None:
    """Section 8: 9-stage verification suite integration test writing evidence JSON and SVG."""
    evidence_file = tmp_path / "streamgraph_canvas_evidence.json"
    svg_file = tmp_path / "streamgraph_canvas_sample.svg"

    result = run_streamgraph_canvas_verification(
        output_path=evidence_file,
        sample_svg_path=svg_file,
    )

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["checks_passed"] == 9
    assert result["data"]["total_checks"] == 9
    assert len(result["data"]["tests"]) == 9
    assert evidence_file.exists()
    assert svg_file.exists()

    # Verify JSON content structure
    with open(evidence_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "success"
    assert data["data"]["work_package"] == "W132"
    assert data["data"]["gate"] == "Gate G9 / G2"
    assert data["data"]["register_map"]["analog_registers"] == "%R930..%R937"
    assert data["data"]["register_map"]["discrete_coils"] == "%M217..%M218"

    # Verify SVG file XML validity
    svg_tree = ET.parse(svg_file)
    root = svg_tree.getroot()
    assert root.attrib["width"] == "1200"
    assert root.attrib["height"] == "750"
