"""Comprehensive pytest test suite for Cscape HMI Dynamic Sankey Energy & Mass Flow Diagram Vector Canvas (W159).

Work Package: W159 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1200..%R1207, %M280..%M281).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Sankey flow network topology, nodal mass conservation, and Kirchhoff balance checks.
4. Section 4: Horizontal cubic Bézier ribbon geometry calculation, entry/exit coordinate alignment, and width scaling.
5. Section 5: Standalone W3C SVG 1.1 XML generation, gradient ribbon paths, and stream metric HUD badges.
6. Section 6: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
7. Section 7: Process safety trips (0xB801 flow imbalance, 0xB802 energy inversion) and Horner coil assertion (%M280, %M281).
8. Section 8: Horner OCS register space synchronization (%R1200..%R1207, %M280..%M281).
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
from jev_cscape.hmi.sankey_canvas import (
    AMBER_GRAPHICAL_CONTRAST_RATIO,
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
    COLOR_INDIGO,
    COLOR_NOMINAL_GREEN,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    CRIMSON_GRAPHICAL_CONTRAST_RATIO,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_ENERGY_INVERSION,
    DIAG_EVENT_FLOW_IMBALANCE,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DiagnosticCode,
    FLOW_IMBALANCE_THRESHOLD_PCT,
    MAX_ALLOWED_NODES,
    MIN_ALLOWED_NODES,
    PROCESS_FLOW_SANKEY_PURE_ST_POU,
    ProcessFlowSankeyCanvas,
    ProcessFlowSankeyHmiSync,
    SANKEY_CANVAS_PURE_ST_POU,
    SANKEY_ERR_ENERGY_INVERSION,
    SANKEY_ERR_FLOW_IMBALANCE,
    SANKEY_ERR_OK,
    SANKEY_ERR_RENDER_FAULT,
    SANKEY_PURE_ST_POU,
    SCADA_PALETTE,
    SankeyCanvas,
    SankeyCanvasEngine,
    SankeyCanvasStatusBits,
    SankeyCanvasSync,
    SankeyMetrics,
    SankeyNode,
    SankeyStatusBits,
    SankeyStream,
    calculate_contrast_ratio,
    compute_sankey_metrics,
    create_canonical_sankey_canvas,
    create_canonical_sankey_links,
    create_canonical_sankey_network,
    create_canonical_sankey_nodes,
    create_canonical_sankey_streams,
    create_mock_scan_context,
    generate_horizontal_bezier_ribbon_path,
    generate_sankey_canvas_svg,
    hex_to_relative_luminance,
    layout_sankey_diagram,
    run_sankey_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_process_flow_sankey_pure_st,
    verify_sankey_canvas_pure_st,
    verify_sankey_pure_st,
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
# Section 1: Pure ST POU AST Parsing & Validation (%R1200..%R1207, %M280..%M281)
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1 Check: Verify SankeyCanvasSync POU conforms to IEC 61131-3 Pure ST grammar (%R1200..%R1207, %M280..%M281)."""
    SecurityGuard.assert_pure_st_content(SANKEY_CANVAS_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(SANKEY_CANVAS_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "SankeyCanvasSync"
    assert pou.pou_type == POUType.PROGRAM

    var_dict = {v.name: v for v in pou.variables}

    # Verify Word Registers %R1200..%R1207
    assert "TotalFeedRateScaled" in var_dict
    assert var_dict["TotalFeedRateScaled"].address_binding == "%R1200"
    assert var_dict["TotalFeedRateScaled"].data_type == "INT"

    assert "ActiveNodeStagesCount" in var_dict
    assert var_dict["ActiveNodeStagesCount"].address_binding == "%R1201"
    assert var_dict["ActiveNodeStagesCount"].data_type == "INT"

    assert "RecycleStreamFlowScaled" in var_dict
    assert var_dict["RecycleStreamFlowScaled"].address_binding == "%R1202"
    assert var_dict["RecycleStreamFlowScaled"].data_type == "INT"

    assert "ProductYieldFlowScaled" in var_dict
    assert var_dict["ProductYieldFlowScaled"].address_binding == "%R1203"
    assert var_dict["ProductYieldFlowScaled"].data_type == "INT"

    assert "PurgeLossFlowScaled" in var_dict
    assert var_dict["PurgeLossFlowScaled"].address_binding == "%R1204"
    assert var_dict["PurgeLossFlowScaled"].data_type == "INT"

    assert "MaxStageImbalanceScaled" in var_dict
    assert var_dict["MaxStageImbalanceScaled"].address_binding == "%R1205"
    assert var_dict["MaxStageImbalanceScaled"].data_type == "INT"

    assert "SelectedStreamIndex" in var_dict
    assert var_dict["SelectedStreamIndex"].address_binding == "%R1206"
    assert var_dict["SelectedStreamIndex"].data_type == "INT"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1207"
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"

    # Verify Discrete Coils %M280..%M281
    assert "SankeyImbalanceTrip" in var_dict
    assert var_dict["SankeyImbalanceTrip"].address_binding == "%M280"
    assert var_dict["SankeyImbalanceTrip"].data_type == "BOOL"

    assert "SankeyCanvasActive" in var_dict
    assert var_dict["SankeyCanvasActive"].address_binding == "%M281"
    assert var_dict["SankeyCanvasActive"].data_type == "BOOL"

    # Verify pure ST helper functions
    assert verify_sankey_canvas_pure_st() is True
    assert verify_sankey_pure_st() is True


def test_process_flow_sankey_st_pou_alias_validation() -> None:
    """Verify ProcessFlowSankeyHmiSync POU alias parses cleanly with STParser."""
    SecurityGuard.assert_pure_st_content(PROCESS_FLOW_SANKEY_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(PROCESS_FLOW_SANKEY_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "ProcessFlowSankeyHmiSync"
    assert pou.pou_type == POUType.PROGRAM
    assert verify_process_flow_sankey_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_contacts_rejection() -> None:
    """Verify ladder logic contacts ---[ ]--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadSankeyContacts
    VAR SankeyCanvasActive : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_coils_rejection() -> None:
    """Verify ladder logic coils ---( )--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadSankeyCoils
    VAR SankeyImbalanceTrip : BOOL; END_VAR
    ---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_rung_delimiters_rejection() -> None:
    """Verify ladder logic RUNG / NETWORK delimiters trigger LadderForbiddenError."""
    ladder_text1 = """
    PROGRAM BadSankeyRung
    RUNG 1:
        SankeyCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text1)

    ladder_text2 = """
    PROGRAM BadSankeyNetwork
    NETWORK 1:
        SankeyCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text2)


def test_anti_ladder_mnemonics_rejection() -> None:
    """Verify ladder logic mnemonics XIC / OTE trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadSankeyMnemonics
    VAR TotalFeedRate : INT; END_VAR
    XIC %M281 OTE %M280;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


# ============================================================================
# Section 3: Sankey Flow Network Topology & Nodal Mass Conservation
# ============================================================================

def test_canonical_sankey_network_topology() -> None:
    """Verify 5 canonical process nodes and 9 transfer streams conform to specifications."""
    nodes, streams = create_canonical_sankey_network()
    assert len(nodes) == 5
    assert len(streams) == 9

    # Node 0: Feed Preparation (100.0 kg/s, Emerald #10B981)
    assert nodes[0].node_id == "NODE_FEED"
    assert nodes[0].name == "Feed Preparation"
    assert nodes[0].stage_index == 0
    assert nodes[0].color == COLOR_EMERALD

    # Node 1: Reaction Section (135.0 kg/s, Cyan #06B6D4)
    assert nodes[1].node_id == "NODE_REACTION"
    assert nodes[1].name == "Reaction Section"
    assert nodes[1].stage_index == 1
    assert nodes[1].color == COLOR_CYAN

    # Node 2: Separation Train (135.0 kg/s, Indigo #6366F1)
    assert nodes[2].node_id == "NODE_SEPARATION"
    assert nodes[2].name == "Separation Train"
    assert nodes[2].stage_index == 2
    assert nodes[2].color == COLOR_INDIGO

    # Node 3: Recycle System (35.0 kg/s, Amber #F59E0B)
    assert nodes[3].node_id == "NODE_RECYCLE"
    assert nodes[3].name == "Recycle System"
    assert nodes[3].stage_index == 3
    assert nodes[3].color == COLOR_AMBER

    # Node 4: Final Product & Purge (65.0 kg/s, Crimson #EF4444)
    assert nodes[4].node_id == "NODE_PRODUCT"
    assert nodes[4].name == "Final Product & Purge"
    assert nodes[4].stage_index == 4
    assert nodes[4].color == COLOR_CRIMSON

    # Recycle stream check
    recycle_stream = next(s for s in streams if s.is_recycle)
    assert recycle_stream.stream_id == "STR_RECYCLE_RETURN"
    assert recycle_stream.source_node_id == "NODE_RECYCLE"
    assert recycle_stream.target_node_id == "NODE_REACTION"
    assert math.isclose(recycle_stream.flow_kg_s, 35.0, abs_tol=1e-3)


def test_nodal_mass_conservation_and_kirchhoff_balance() -> None:
    """Verify exact nodal mass conservation and overall plant mass balance."""
    nodes, streams = create_canonical_sankey_network()
    layout_sankey_diagram(nodes, streams)

    # Node 0: Feed Preparation: 100 in, 100 out
    assert math.isclose(nodes[0].total_inflow_kg_s, 100.0, abs_tol=1e-3)
    assert math.isclose(nodes[0].total_outflow_kg_s, 100.0, abs_tol=1e-3)
    assert math.isclose(nodes[0].imbalance_pct, 0.0, abs_tol=1e-3)

    # Node 1: Reaction Section: 100 + 35 = 135 in, 135 out
    assert math.isclose(nodes[1].total_inflow_kg_s, 135.0, abs_tol=1e-3)
    assert math.isclose(nodes[1].total_outflow_kg_s, 135.0, abs_tol=1e-3)
    assert math.isclose(nodes[1].imbalance_pct, 0.0, abs_tol=1e-3)

    # Node 2: Separation Train: 135 in, 35 + 65 + 35 = 135 out
    assert math.isclose(nodes[2].total_inflow_kg_s, 135.0, abs_tol=1e-3)
    assert math.isclose(nodes[2].total_outflow_kg_s, 135.0, abs_tol=1e-3)
    assert math.isclose(nodes[2].imbalance_pct, 0.0, abs_tol=1e-3)

    # Node 3: Recycle System: 35 in, 35 out
    assert math.isclose(nodes[3].total_inflow_kg_s, 35.0, abs_tol=1e-3)
    assert math.isclose(nodes[3].total_outflow_kg_s, 35.0, abs_tol=1e-3)
    assert math.isclose(nodes[3].imbalance_pct, 0.0, abs_tol=1e-3)

    # Node 4: Final Product & Purge: 65 in, 62 + 3 = 65 out
    assert math.isclose(nodes[4].total_inflow_kg_s, 65.0, abs_tol=1e-3)
    assert math.isclose(nodes[4].total_outflow_kg_s, 65.0, abs_tol=1e-3)
    assert math.isclose(nodes[4].imbalance_pct, 0.0, abs_tol=1e-3)

    # Overall Kirchhoff balance: Intake 100 = Product 62 + Byproduct 35 + Purge 3
    raw_intake = sum(s.flow_kg_s for s in streams if s.source_node_id is None)
    terminals = sum(s.flow_kg_s for s in streams if s.target_node_id is None)
    assert math.isclose(raw_intake, 100.0, abs_tol=1e-3)
    assert math.isclose(terminals, 100.0, abs_tol=1e-3)
    assert math.isclose(raw_intake, terminals, abs_tol=1e-3)


def test_node_throughput_and_flow_properties() -> None:
    """Verify node throughput computation and stream flow accessors."""
    node = SankeyNode(
        node_id="TEST_UNIT",
        name="Test Unit",
        stage_index=1,
        color=COLOR_CYAN,
        total_inflow_kg_s=135.0,
        total_outflow_kg_s=130.0,
    )
    assert node.throughput == 135.0
    assert math.isclose(node.flow_balance_diff, 5.0, abs_tol=1e-3)

    stream = SankeyStream(
        stream_id="TEST_STR",
        name="Test Stream",
        source_node_id="A",
        target_node_id="B",
        flow_kg_s=42.5,
    )
    assert stream.flow == 42.5


# ============================================================================
# Section 4: Horizontal Cubic Bézier Ribbon Geometry Calculation
# ============================================================================

def test_horizontal_bezier_ribbon_path_geometry_and_tangents() -> None:
    """Verify horizontal cubic Bézier ribbon geometry with C^1 tangent continuity."""
    nodes, streams = create_canonical_sankey_network()
    layout_sankey_diagram(nodes, streams)

    forward_stream = streams[1]  # STR_PREP_FEED (Feed to Reaction)
    path_forward = generate_horizontal_bezier_ribbon_path(forward_stream)

    # Verify SVG grammar: M ... C ... L ... C ... Z
    assert path_forward.startswith("M ")
    assert " C " in path_forward
    assert " L " in path_forward
    assert path_forward.endswith(" Z")
    assert path_forward.count(" C ") == 2

    # Verify horizontal tangent continuity (dy/dx = 0 at ports):
    # Upper curve cp1 has same y as source_y_top; cp2 has same y as target_y_top
    dx = forward_stream.target_x - forward_stream.source_x
    cp1_x = forward_stream.source_x + dx * 0.5
    cp2_x = forward_stream.target_x - dx * 0.5
    y1_top = forward_stream.source_y
    assert (
        f"C {cp1_x:.2f},{forward_stream.source_y:.2f} {cp2_x:.2f},{forward_stream.target_y:.2f}" in path_forward
        or f"C {cp1_x:.2f} {forward_stream.source_y:.2f}, {cp2_x:.2f} {forward_stream.target_y:.2f}" in path_forward
        or f"C {cp1_x:.2f},{y1_top:.2f} {cp2_x:.2f},{y2_top:.2f}" in path_forward
    )




    # Backward recycle stream check
    recycle_stream = next(s for s in streams if s.is_recycle)
    path_recycle = generate_horizontal_bezier_ribbon_path(recycle_stream)
    assert path_recycle.startswith("M ")
    assert " C " in path_recycle
    assert " L " in path_recycle
    assert path_recycle.endswith(" Z")


def test_entry_exit_coordinate_alignment_and_width_scaling() -> None:
    """Verify entry and exit coordinates align with node ports and ribbon width scales with flow."""
    nodes, streams = create_canonical_sankey_network()
    layout_sankey_diagram(nodes, streams)

    # Every stream must have valid entry and exit coordinates
    for s in streams:
        assert s.ribbon_width > 0.0
        assert s.source_x > 0.0
        assert s.target_x > 0.0
        assert s.source_y > 0.0
        assert s.target_y > 0.0

    # Width scaling check: STR_PREP_FEED (100 kg/s) vs STR_OFFGAS_PURGE (3 kg/s)
    s_100 = next(s for s in streams if s.stream_id == "STR_PREP_FEED")
    s_3 = next(s for s in streams if s.stream_id == "STR_OFFGAS_PURGE")
    assert s_100.ribbon_width > s_3.ribbon_width
    assert math.isclose(s_100.ribbon_width / s_3.ribbon_width, 100.0 / 3.0, rel_tol=1e-3)


# ============================================================================
# Section 5: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def test_standalone_svg_xml_validation() -> None:
    """Verify SVG output is well-formed XML and contains required industrial SVG elements."""
    canvas = create_canonical_sankey_canvas()
    svg_str = canvas.render_svg()

    # Parse with standard XML parser to verify strictly valid XML
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)

    # Check required SVG structure
    assert 'id="canvas-header"' in svg_str
    assert 'id="sankey-diagram"' in svg_str
    assert 'id="flow-ribbons"' in svg_str
    assert 'id="node-bars"' in svg_str
    assert 'id="node-badges"' in svg_str
    assert 'id="stream-badges"' in svg_str
    assert 'id="flow-balance-metrics-card"' in svg_str


def test_gradient_ribbon_paths_and_stream_badges() -> None:
    """Verify gradient definitions, ribbon paths, and stream flow rate badges."""
    canvas = create_canonical_sankey_canvas(selected_stream_index=2)
    svg_str = canvas.render_svg()

    # Linear gradient definitions
    assert "<linearGradient" in svg_str
    assert 'id="ribbon-grad-' in svg_str
    assert 'stop-color="' in svg_str

    # Node bar elements
    assert 'id="node-bar-NODE_FEED"' in svg_str
    assert 'id="node-bar-NODE_REACTION"' in svg_str
    assert 'id="node-bar-NODE_SEPARATION"' in svg_str
    assert 'id="node-bar-NODE_RECYCLE"' in svg_str
    assert 'id="node-bar-NODE_PRODUCT"' in svg_str

    # Stream badges
    assert 'id="stream-badge-STR_RAW_FEED"' in svg_str
    assert 'id="stream-badge-STR_REACTOR_EFFLUENT"' in svg_str
    assert 'id="stream-badge-STR_PURIFIED_PRODUCT"' in svg_str

    # Metrics card text
    assert "PROCESS FLOW BALANCE METRICS" in svg_str
    assert "TOTAL FEED RATE (%R1200)" in svg_str
    assert "ACTIVE PROCESS STAGES (%R1201)" in svg_str
    assert "RECYCLE STREAM FLOW (%R1202)" in svg_str
    assert "PRODUCT YIELD FLOW (%R1203)" in svg_str
    assert "100.0% CONSERVED" in svg_str


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

    # Graphical indicators on theme backing (> 3:1)
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

    contrast_blue = calculate_contrast_ratio(COLOR_FOCUS_BLUE, COLOR_DARK_THEME_BACKING)
    assert contrast_blue >= WCAG_GRAPHICAL_CONTRAST_TARGET

    # Helper function validation
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0) is True
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, min_contrast=7.0) is True


# ============================================================================
# Section 7: Process Safety Trips & Horner Coil Assertion
# ============================================================================

def test_flow_imbalance_trip_0xb801_and_coil_assertion() -> None:
    """Verify 0xB801 trip when nodal mass flow imbalance exceeds 2.0%, asserting coil %M280."""
    canvas = create_canonical_sankey_canvas()
    assert canvas.imbalance_trip is False
    assert canvas.reg_table.read_bit("%M280") is False
    assert canvas.reg_table.read_bit("%M281") is True
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # Trigger flow imbalance trip (> 2.0% threshold, e.g. 2.50%)
    canvas.trigger_flow_imbalance(injected_imbalance_pct=2.5)

    assert canvas.imbalance_trip is True
    assert canvas.reg_table.read_bit("%M280") is True
    assert canvas.reg_table.read_bit("%M281") is True
    assert canvas.diagnostic_code == SANKEY_ERR_FLOW_IMBALANCE
    assert canvas.diagnostic_code == 0xB801
    assert canvas.diagnostic_code == -18431
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1207")) == 0xB801)
    assert canvas.reg_table.read_word("%R1205") == 250  # 2.50% scaled x100
    assert bool(canvas.status_bits & SankeyStatusBits.FLOW_IMBALANCE_TRIP)

    # Verify trip status in rendered SVG
    svg_trip = canvas.render_svg()
    assert "SAFETY INTERLOCK TRIP: 0xB801" in svg_trip
    assert 'id="anomaly-halos"' in svg_trip


def test_energy_inversion_fault_0xb802() -> None:
    """Verify 0xB802 diagnostic trip on energy inversion."""
    canvas = create_canonical_sankey_canvas()
    canvas.trigger_energy_inversion()

    assert canvas.diagnostic_code == SANKEY_ERR_ENERGY_INVERSION
    assert canvas.diagnostic_code == 0xB802
    assert canvas.diagnostic_code == -18430
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1207")) == 0xB802)
    assert bool(canvas.status_bits & SankeyStatusBits.ENERGY_INVERSION_FAULT)


def test_render_fault_0xb803_and_nominal_reset() -> None:
    """Verify 0xB803 render fault condition and clean nominal reset."""
    canvas = create_canonical_sankey_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == SANKEY_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xB803
    assert canvas.diagnostic_code == -18429
    assert bool(canvas.status_bits & SankeyStatusBits.RENDER_FAULT)

    # Reset nominal state
    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.imbalance_trip is False
    assert canvas.reg_table.read_bit("%M280") is False
    assert canvas.reg_table.read_bit("%M281") is True
    assert canvas.reg_table.read_word("%R1207") == 0


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization & Scan Cycle
# ============================================================================

def test_horner_register_space_synchronization() -> None:
    """Verify register table synchronization conforms to %R1200..%R1207, %M280..%M281."""
    canvas = create_canonical_sankey_canvas()
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute(ctx)

    reg = canvas.reg_table
    assert reg.read_word("%R1200") == 1000  # 100.0 kg/s feed rate scaled x10
    assert reg.read_word("%R1201") == 5     # 5 active node stages
    assert reg.read_word("%R1202") == 350   # 35.0 kg/s recycle flow scaled x10
    assert reg.read_word("%R1203") == 620   # 62.0 kg/s product yield scaled x10
    assert reg.read_word("%R1204") == 30    # 3.0 kg/s purge loss scaled x10
    assert reg.read_word("%R1205") == 0     # 0.00% max imbalance scaled x100
    assert reg.read_word("%R1206") == 0     # Selected stream 0
    assert reg.read_word("%R1207") == 0     # Diag OK

    assert reg.read_bit("%M280") is False   # SankeyImbalanceTrip = False
    assert reg.read_bit("%M281") is True    # SankeyCanvasActive = True


def test_interactive_stream_selection_and_scan_cycle() -> None:
    """Verify stream selection and scan cycle trip on elevated imbalance in %R1205."""
    canvas = create_canonical_sankey_canvas()

    # Select Stream 2 (STR_REACTOR_EFFLUENT)
    canvas.selected_stream_index = 2
    canvas.update_telemetry()
    canvas.sync_to_registers()

    assert canvas.selected_stream_index == 2
    assert canvas.reg_table.read_word("%R1206") == 2
    assert bool(canvas.status_bits & SankeyStatusBits.STREAM_SELECTED)

    # Scan cycle execution: Nominal
    ctx = create_mock_scan_context(cycle=1, reg_table=canvas.reg_table)
    canvas.execute_scan(ctx)
    assert canvas.reg_table.read_bit("%M280") is False
    assert canvas.reg_table.read_word("%R1207") == 0

    # Scan cycle execution: High imbalance injected into %R1205
    canvas.reg_table.write_word("%R1205", 250, privilege=PrivilegeMode.SYSTEM)  # 2.50% > 2.00%
    canvas.execute_scan(ctx)
    assert canvas.reg_table.read_bit("%M280") is True
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1207")) == SANKEY_ERR_FLOW_IMBALANCE)


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration
# ============================================================================

def test_run_sankey_canvas_verification_suite(tmp_path: Path) -> None:
    """Execute complete deterministic 9-stage verification suite."""
    ev_path = tmp_path / "sankey_evidence.json"
    svg_path = tmp_path / "sankey_sample.svg"

    report = run_sankey_canvas_verification(
        output_path=ev_path,
        sample_svg_path=svg_path,
    )

    assert report["status"] == "success"
    assert report["error_code"] is None
    assert report["data"]["work_package"] == "W159"
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
    assert saved_ev["data"]["work_package"] == "W159"

    with open(svg_path, "r", encoding="utf-8") as f:
        saved_svg = f.read()
    assert "<svg" in saved_svg
    assert "</svg>" in saved_svg


# ============================================================================
# DiagnosticCode, Edge Cases & Scan Lifecycle
# ============================================================================

def test_diagnostic_code_edge_cases() -> None:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and hash consistency."""
    code_imb = DiagnosticCode(0xB801)
    assert code_imb == 0xB801
    assert code_imb == -18431
    assert code_imb == 47105
    assert int(code_imb) == 47105
    assert hash(code_imb) == hash(47105)
    assert code_imb != "not_an_int"
    assert code_imb != 0x0000

    code_inv = DiagnosticCode(0xB802)
    assert code_inv == 0xB802
    assert code_inv == -18430
    assert code_inv == 47106

    code_fault = DiagnosticCode(0xB803)
    assert code_fault == 0xB803
    assert code_fault == -18429
    assert code_fault == 47107


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
    c1 = SankeyCanvasSync()
    c2 = SankeyCanvasEngine()
    c3 = ProcessFlowSankeyHmiSync()
    c4 = ProcessFlowSankeyCanvas()
    c5 = create_canonical_sankey_canvas()

    for c in (c1, c2, c3, c4, c5):
        assert isinstance(c, SankeyCanvas)

    nodes = create_canonical_sankey_nodes()
    streams = create_canonical_sankey_streams()
    links = create_canonical_sankey_links()
    assert len(nodes) == 5
    assert len(streams) == 9
    assert len(links) == 9

    assert MIN_ALLOWED_NODES == 3
    assert MAX_ALLOWED_NODES == 12
    assert FLOW_IMBALANCE_THRESHOLD_PCT == 2.0


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface execution within simulated Horner PLC scan cycle."""
    canvas = create_canonical_sankey_canvas()
    assert canvas.name == "SankeyCanvasSync"
    assert canvas.priority == 90
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)
    canvas.execute(ctx)
    assert canvas.reg_table.read_bit("%M281") is True

    canvas.step()
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
