"""Comprehensive pytest test suite for Cscape HMI Dynamic Funnel / Pipeline Multi-Stage Yield Canvas (W150).

Work Package: W150 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1110..%R1117, %M259..%M260).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Industrial funnel/pipeline conversion geometry and mass balance calculations.
4. Section 4: Standalone W3C SVG 1.1 XML generation, stage walls, neck transitions, and fluid body.
5. Section 5: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
6. Section 6: Process safety trips (yield deficit 0xAF01, stage inversion 0xAF02, render fault 0xAF03)
   and Horner coil assertions (%M259, %M260).
7. Section 7: Horner OCS register space synchronization (%R1110..%R1117, %M259..%M260).
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
from jev_cscape.hmi.funnel_canvas import (
    AMBER_GRAPHICAL_CONTRAST_RATIO,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ADVISORY_AMBER,
    COLOR_ADVISORY_AMBER_DARK,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_DISTRESS_RED,
    COLOR_DISTRESS_RED_DARK,
    COLOR_FOCUS_BLUE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_DARK,
    COLOR_PIPE_FLANGE,
    COLOR_PIPE_WALL,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_RED,
    CRIMSON_GRAPHICAL_CONTRAST_RATIO,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_FEED_FLOW,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DIAG_EVENT_STAGE_INVERSION,
    DIAG_EVENT_YIELD_DEFICIT,
    FUNNEL_CENTER_Y,
    FUNNEL_ERR_DEFICIT,
    FUNNEL_ERR_INVERSION,
    FUNNEL_ERR_OK,
    FUNNEL_ERR_RENDER_FAULT,
    FUNNEL_ERR_STAGE_INVERSION,
    FUNNEL_ERR_YIELD_DEFICIT,
    FUNNEL_MAX_HALF_HEIGHT,
    FUNNEL_PURE_ST_POU,
    FUNNEL_X_END,
    FUNNEL_X_START,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    PIPELINE_YIELD_PURE_ST_POU,
    STAGE_LOSS_EXCURSION_THRESHOLD_PCT,
    STAGE_WIDTH,
    TRANSITION_WIDTH,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    YIELD_DEFICIT_THRESHOLD_PCT,
    DiagnosticCode,
    FunnelCanvas,
    FunnelCanvasStatusBits,
    FunnelCanvasSync,
    FunnelEngine,
    FunnelStage,
    FunnelStatusBits,
    FunnelTransitionMode,
    PipelineCanvas,
    PipelineStage,
    PipelineYieldCanvas,
    PipelineYieldEngine,
    PipelineYieldHmiSync,
    ProcessStage,
    StageGeometry,
    TransitionGeometry,
    calculate_contrast_ratio,
    compute_funnel_layout,
    create_canonical_funnel_canvas,
    create_canonical_funnel_stages,
    create_canonical_pipeline_yield_canvas,
    create_mock_scan_context,
    generate_funnel_body_path,
    generate_funnel_canvas_svg,
    generate_funnel_svg,
    generate_pipeline_yield_svg,
    hex_to_relative_luminance,
    run_funnel_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_funnel_canvas_pure_st,
    verify_funnel_pure_st,
    verify_pipeline_yield_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1 Check: Verify FunnelCanvasSync POU conforms to IEC 61131-3 Pure ST grammar."""
    SecurityGuard.assert_pure_st_content(FUNNEL_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(FUNNEL_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "FunnelCanvasSync"
    assert pou.pou_type == POUType.PROGRAM

    var_dict = {v.name: v for v in pou.variables}

    # Verify Word Registers %R1110..%R1117
    assert "Stage1FeedFlowScaled" in var_dict
    assert var_dict["Stage1FeedFlowScaled"].address_binding == "%R1110"
    assert var_dict["Stage1FeedFlowScaled"].data_type == "INT"

    assert "Stage2ReactionEffluentScaled" in var_dict
    assert var_dict["Stage2ReactionEffluentScaled"].address_binding == "%R1111"
    assert var_dict["Stage2ReactionEffluentScaled"].data_type == "INT"

    assert "Stage3FractionationProductScaled" in var_dict
    assert var_dict["Stage3FractionationProductScaled"].address_binding == "%R1112"
    assert var_dict["Stage3FractionationProductScaled"].data_type == "INT"

    assert "Stage4PolishedYieldScaled" in var_dict
    assert var_dict["Stage4PolishedYieldScaled"].address_binding == "%R1113"
    assert var_dict["Stage4PolishedYieldScaled"].data_type == "INT"

    assert "OverallYieldPct" in var_dict
    assert var_dict["OverallYieldPct"].address_binding == "%R1114"
    assert var_dict["OverallYieldPct"].data_type == "INT"

    assert "MaxStageLossPct" in var_dict
    assert var_dict["MaxStageLossPct"].address_binding == "%R1115"
    assert var_dict["MaxStageLossPct"].data_type == "INT"

    assert "BottleneckStageIndex" in var_dict
    assert var_dict["BottleneckStageIndex"].address_binding == "%R1116"
    assert var_dict["BottleneckStageIndex"].data_type == "INT"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1117"
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"

    # Verify Discrete Coils %M259..%M260
    assert "YieldExcursionTrip" in var_dict
    assert var_dict["YieldExcursionTrip"].address_binding == "%M259"
    assert var_dict["YieldExcursionTrip"].data_type == "BOOL"

    assert "FunnelCanvasActive" in var_dict
    assert var_dict["FunnelCanvasActive"].address_binding == "%M260"
    assert var_dict["FunnelCanvasActive"].data_type == "BOOL"


def test_pipeline_yield_st_pou_alias_validation() -> None:
    """Verify PipelineYieldHmiSync POU alias parses cleanly."""
    SecurityGuard.assert_pure_st_content(PIPELINE_YIELD_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(PIPELINE_YIELD_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "PipelineYieldHmiSync"
    assert pou.pou_type == POUType.PROGRAM
    assert verify_pipeline_yield_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_contacts_rejection() -> None:
    """Verify ladder logic contacts ---[ ]--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadFunnelContacts
    VAR Stage1Feed : INT; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_rung_delimiters_rejection() -> None:
    """Verify ladder logic RUNG / NETWORK delimiters trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadFunnelNetwork
    RUNG 1:
        FunnelActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_mnemonics_rejection() -> None:
    """Verify ladder logic mnemonics XIC / OTE trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadFunnelMnemonics
    VAR Stage1Feed : INT; END_VAR
    XIC %M260 OTE %M259;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


# ============================================================================
# Section 3: Industrial Funnel Conversion Geometry & Mass Balance
# ============================================================================

def test_canonical_funnel_stages() -> None:
    """Verify 4 canonical stages conform to mass balance specifications."""
    stages = create_canonical_funnel_stages()
    assert len(stages) == 4

    # Stage 1: Feedstock
    assert stages[0].stage_index == 1
    assert stages[0].name == "Raw Feedstock"
    assert stages[0].tag == "FDS-101"
    assert stages[0].flow_rate == 100.0
    assert stages[0].flow_scaled == 1000
    assert stages[0].loss_mass_rate == 0.0

    # Stage 2: Reactor Effluent (7.5% light off-gas)
    assert stages[1].stage_index == 2
    assert stages[1].name == "Reactor Effluent"
    assert stages[1].tag == "RXC-201"
    assert stages[1].flow_rate == 92.5
    assert stages[1].flow_scaled == 925
    assert stages[1].loss_mass_rate == 7.5
    assert stages[1].loss_pct == 7.5
    assert stages[1].loss_name == "Light Off-Gas"

    # Stage 3: Fractionation Distillates (7.5% heavy residue)
    assert stages[2].stage_index == 3
    assert stages[2].name == "Fractionation Distillates"
    assert stages[2].tag == "FRD-301"
    assert stages[2].flow_rate == 85.0
    assert stages[2].flow_scaled == 850
    assert stages[2].loss_mass_rate == 7.5
    assert stages[2].loss_pct == 7.5
    assert stages[2].loss_name == "Heavy Residue"

    # Stage 4: Polished Final Product (3.0% finishing loss)
    assert stages[3].stage_index == 4
    assert stages[3].name == "Polished Final Product"
    assert stages[3].tag == "PFP-401"
    assert stages[3].flow_rate == 82.0
    assert stages[3].flow_scaled == 820
    assert stages[3].loss_mass_rate == 3.0
    assert stages[3].loss_pct == 3.0
    assert stages[3].loss_name == "Finishing Loss"


def test_funnel_geometry_layout() -> None:
    """Verify funnel layout calculation generates valid coordinates and paths."""
    stages = create_canonical_funnel_stages()
    stage_geoms, trans_geoms = compute_funnel_layout(stages, mode=FunnelTransitionMode.CURVED)

    assert len(stage_geoms) == 4
    assert len(trans_geoms) == 3

    # Check heights are strictly narrowing
    for i in range(len(stage_geoms) - 1):
        assert stage_geoms[i].height > stage_geoms[i + 1].height
        assert stage_geoms[i].x_end < stage_geoms[i + 1].x_start

    fluid_d, top_d, btm_d = generate_funnel_body_path(stage_geoms, trans_geoms)
    assert fluid_d.startswith("M")
    assert fluid_d.endswith("Z")
    assert "C" in top_d  # Cubic bezier curves present
    assert "C" in btm_d

    # Test trapezoidal straight mode
    _, trans_trap = compute_funnel_layout(stages, mode=FunnelTransitionMode.TRAPEZOIDAL)
    _, top_trap, _ = generate_funnel_body_path(stage_geoms, trans_trap)
    assert "L" in top_trap


# ============================================================================
# Section 4: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def test_standalone_svg_xml_validation() -> None:
    """Verify SVG output is well-formed XML and contains required industrial elements."""
    canvas = create_canonical_funnel_canvas()
    svg_str = canvas.render_svg()

    # Parse with standard XML parser to verify strictly valid XML
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)

    # Check required SVG structure
    assert 'id="canvas-header"' in svg_str
    assert 'id="funnel-container"' in svg_str
    assert 'class="funnel-fluid-body"' in svg_str
    assert 'class="funnel-top-wall"' in svg_str
    assert 'class="funnel-bottom-wall"' in svg_str
    assert 'id="drop-off-losses"' in svg_str
    assert 'id="analytics-panel"' in svg_str
    assert 'id="efficiency-ring-gauge"' in svg_str
    assert 'id="bottleneck-stage"' in svg_str
    assert 'id="stage-selector-container"' in svg_str
    assert 'id="telemetry-hud"' in svg_str


def test_svg_drop_off_badges_content() -> None:
    """Verify stage drop-off loss callout badges render accurate loss rate and percentage."""
    canvas = create_canonical_funnel_canvas()
    svg_str = canvas.render_svg()

    assert "-7.5 kg/s (-7.5%)" in svg_str
    assert "-3.0 kg/s (-3.0%)" in svg_str
    assert "Light Off-Gas" in svg_str
    assert "Heavy Residue" in svg_str
    assert "Finishing Loss" in svg_str


# ============================================================================
# Section 5: WCAG 2.1 AAA Accessibility & Contrast Targets
# ============================================================================

def test_wcag_aaa_contrast_compliance() -> None:
    """Verify contrast ratios satisfy WCAG 2.1 AAA targets."""
    # Badge contrast (> 18:1)
    contrast_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    assert contrast_badge >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert contrast_badge > 18.0

    # Primary text on theme backing (> 7:1)
    contrast_theme = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    assert contrast_theme >= WCAG_AAA_TEXT_CONTRAST_TARGET

    # Graphical indicators on theme backing (> 3:1)
    contrast_green = calculate_contrast_ratio(COLOR_NOMINAL_GREEN, COLOR_DARK_THEME_BACKING)
    assert contrast_green >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_amber = calculate_contrast_ratio(COLOR_ADVISORY_AMBER, COLOR_DARK_THEME_BACKING)
    assert contrast_amber >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_red = calculate_contrast_ratio(COLOR_DISTRESS_RED, COLOR_DARK_THEME_BACKING)
    assert contrast_red >= WCAG_GRAPHICAL_CONTRAST_TARGET

    contrast_blue = calculate_contrast_ratio(COLOR_FOCUS_BLUE, COLOR_DARK_THEME_BACKING)
    assert contrast_blue >= WCAG_GRAPHICAL_CONTRAST_TARGET


# ============================================================================
# Section 6: Process Safety Interlocks & Diagnostics
# ============================================================================

def test_yield_deficit_trip_interlock_overall_yield() -> None:
    """Verify 0xAF01 trip when overall yield drops below 60%."""
    canvas = create_canonical_funnel_canvas()
    assert canvas.yield_excursion_trip is False
    assert canvas.reg_table.read_bit("%M259") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # Trigger overall yield deficit (55.0% < 60%)
    canvas.trigger_yield_deficit(overall_yield=55.0, injected_stage_index=2, injected_stage_loss_pct=15.0)

    assert canvas.yield_excursion_trip is True
    assert canvas.reg_table.read_bit("%M259") is True
    assert canvas.diagnostic_code == FUNNEL_ERR_YIELD_DEFICIT
    assert canvas.diagnostic_code == 0xAF01
    assert canvas.diagnostic_code == -20735
    assert (DiagnosticCode(canvas_trip_code := canvas.reg_table.read_word("%R1117")) == 0xAF01)
    assert bool(canvas.status_bits & FunnelStatusBits.YIELD_EXCURSION_TRIP)

    # Verify alert halo in SVG
    svg_trip = canvas.render_svg()
    assert "class=\"excursion-alert-halo\"" in svg_trip
    assert "PROCESS TRIP: YIELD DEFICIT EXCURSION ACTIVE (%M259)" in svg_trip


def test_yield_deficit_trip_interlock_single_stage_loss() -> None:
    """Verify 0xAF01 trip when single stage loss exceeds 25%."""
    canvas = create_canonical_funnel_canvas()
    canvas.trigger_yield_deficit(overall_yield=70.0, injected_stage_index=2, injected_stage_loss_pct=28.0)

    assert canvas.yield_excursion_trip is True
    assert canvas.reg_table.read_bit("%M259") is True
    assert canvas.diagnostic_code == FUNNEL_ERR_YIELD_DEFICIT


def test_stage_inversion_interlock() -> None:
    """Verify 0xAF02 stage inversion trip when downstream flow exceeds upstream flow."""
    canvas = create_canonical_funnel_canvas()
    # Downstream Stage 3 flow (96.0 kg/s) exceeds Stage 2 flow (92.5 kg/s)
    canvas.trigger_stage_inversion(stage_index=3, injected_flow=96.0)

    assert canvas.diagnostic_code == FUNNEL_ERR_STAGE_INVERSION
    assert canvas.diagnostic_code == 0xAF02
    assert canvas.diagnostic_code == -20734
    assert bool(canvas.status_bits & FunnelStatusBits.STAGE_INVERSION_FAULT)
    assert not bool(canvas.status_bits & FunnelStatusBits.NOMINAL_OPERATION)


def test_render_fault_diagnostic() -> None:
    """Verify 0xAF03 render fault condition."""
    canvas = create_canonical_funnel_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == FUNNEL_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xAF03
    assert canvas.diagnostic_code == -20733

    # Reset nominal state
    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.yield_excursion_trip is False
    assert canvas.reg_table.read_bit("%M259") is False


# ============================================================================
# Section 7: Horner OCS Memory Space Integration & Scan Cycle
# ============================================================================

def test_horner_register_space_synchronization() -> None:
    """Verify register table synchronization conforms to %R1110..%R1117, %M259..%M260."""
    canvas = create_canonical_funnel_canvas()
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute(ctx)

    reg = canvas.reg_table
    assert reg.read_word("%R1110") == 1000  # Stage 1: 100.0 kg/s
    assert reg.read_word("%R1111") == 925   # Stage 2: 92.5 kg/s
    assert reg.read_word("%R1112") == 850   # Stage 3: 85.0 kg/s
    assert reg.read_word("%R1113") == 820   # Stage 4: 82.0 kg/s
    assert reg.read_word("%R1114") == 820   # Overall Yield: 82.0%
    assert reg.read_word("%R1115") == 75    # Max Stage Loss: 7.5%
    assert reg.read_word("%R1116") == 2     # Bottleneck Stage: 2
    assert reg.read_word("%R1117") == 0     # Diag OK

    assert reg.read_bit("%M259") is False   # YieldExcursionTrip = False
    assert reg.read_bit("%M260") is True    # FunnelCanvasActive = True


def test_interactive_stage_selection() -> None:
    """Verify stage selection updates focus bits and SVG styling."""
    canvas = create_canonical_funnel_canvas()
    canvas.set_selected_stage_index(3)
    assert canvas.selected_stage_index == 3
    assert bool(canvas.status_bits & FunnelStatusBits.STAGE_FOCUSED)

    svg = canvas.render_svg()
    assert 'class="stage-focus-box"' in svg
    assert 'id="selector-stage-3"' in svg


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration
# ============================================================================

def test_run_funnel_canvas_verification_suite(tmp_path: Path) -> None:
    """Execute complete deterministic 9-stage verification suite."""
    ev_path = tmp_path / "funnel_evidence.json"
    svg_path = tmp_path / "funnel_sample.svg"

    report = run_funnel_canvas_verification(
        output_path=ev_path,
        sample_svg_path=svg_path,
    )

    assert report["status"] == "success"
    assert report["error_code"] is None
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

    with open(svg_path, "r", encoding="utf-8") as f:
        saved_svg = f.read()
    assert "<svg" in saved_svg
    assert "</svg>" in saved_svg


# ============================================================================
# Section 9: DiagnosticCode, Edge Cases & Scan Lifecycle
# ============================================================================

def test_diagnostic_code_edge_cases() -> None:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and hash consistency."""
    code_trip = DiagnosticCode(0xAF01)
    assert code_trip == 0xAF01
    assert code_trip == -20735
    assert code_trip == 44801
    assert int(code_trip) == 44801
    assert hash(code_trip) == hash(44801)
    assert code_trip != "not_an_int"
    assert code_trip != 0x0000

    code_inv = DiagnosticCode(0xAF02)
    assert code_inv == 0xAF02
    assert code_inv == -20734
    assert code_inv == 44802

    code_fault = DiagnosticCode(0xAF03)
    assert code_fault == 0xAF03
    assert code_fault == -20733
    assert code_fault == 44803


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
    c1 = FunnelCanvasSync()
    c2 = FunnelEngine()
    c3 = PipelineYieldCanvas()
    c4 = PipelineYieldEngine()
    c5 = PipelineCanvas()
    c6 = create_canonical_pipeline_yield_canvas()

    for c in (c1, c2, c3, c4, c5, c6):
        assert isinstance(c, FunnelCanvas)

    stages = create_canonical_funnel_stages()
    svg1 = generate_funnel_svg(stages)
    svg2 = generate_pipeline_yield_svg(stages)
    assert '<svg ' in svg1 and '<svg ' in svg2


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface execution within simulated Horner PLC scan cycle."""
    canvas = create_canonical_funnel_canvas()
    assert canvas.name == "FunnelCanvasSync"
    assert canvas.priority == 88
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)
    canvas.execute(ctx)
    assert canvas.reg_table.read_bit("%M260") is True

    canvas.step()
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK

