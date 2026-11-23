"""Comprehensive pytest test suite for Cscape HMI Dynamic Circular Chord / Interconnection Flow Canvas (W153).

Work Package: W153 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1140..%R1147, %M266..%M267).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Chord circular geometry calculations (outer ring arcs, inner Bézier ribbon coordinates, matrix flow routing).
4. Section 4: Standalone W3C SVG 1.1 XML generation, ribbon gradient rendering, and capacity badges.
5. Section 5: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
6. Section 6: Process safety trips (flow imbalance 0xB201, invalid node count 0xB202) and Horner coil assertion (%M266, %M267).
7. Section 7: Horner OCS register space synchronization (%R1140..%R1147, %M266..%M267).
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
from jev_cscape.hmi.chord_canvas import (
    AMBER_GRAPHICAL_CONTRAST_RATIO,
    BOTTLENECK_UTILIZATION_PCT,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CHORD_CANVAS_PURE_ST_POU,
    CHORD_ERR_FLOW_IMBALANCE,
    CHORD_ERR_INVALID_NODE_COUNT,
    CHORD_ERR_OK,
    CHORD_ERR_RENDER_FAULT,
    CHORD_INNER_RADIUS,
    CHORD_OUTER_RADIUS,
    CHORD_PURE_ST_POU,
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
    DEFAULT_NODE_GAP_DEG,
    DIAG_EVENT_CONDUIT_OVERLOAD,
    DIAG_EVENT_FLOW_IMBALANCE,
    DIAG_EVENT_FLUX_IMBALANCE,
    DIAG_EVENT_INVALID_NODE_COUNT,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    FLOW_IMBALANCE_THRESHOLD_PCT,
    FLUX_IMBALANCE_TOLERANCE_KW,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    INTERCONNECTION_FLOW_PURE_ST_POU,
    MAX_ALLOWED_NODES,
    MIN_ALLOWED_NODES,
    OVERLOAD_UTILIZATION_PCT,
    SCADA_PALETTE,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    BezierCurveMode,
    ChordCanvas,
    ChordCanvasEngine,
    ChordCanvasStatusBits,
    ChordCanvasSync,
    ChordConduit,
    ChordMetrics,
    ChordRibbon,
    ChordStatusBits,
    CircularChordCanvas,
    DiagnosticCode,
    InterconnectionFlowHmiSync,
    PlantNode,
    calculate_contrast_ratio,
    compute_chord_metrics,
    create_canonical_chord_canvas,
    create_canonical_chord_conduits,
    create_canonical_chord_network,
    create_canonical_chord_nodes,
    create_canonical_refinery_energy_network,
    create_mock_scan_context,
    generate_chord_canvas_svg,
    generate_chord_ribbon_path,
    generate_node_arc_path,
    hex_to_relative_luminance,
    layout_chord_diagram,
    run_chord_canvas_verification,
    srgb_channel_to_linear,
    validate_kirchhoff_flux_continuity,
    validate_nodal_flow_imbalance,
    validate_wcag_aaa_contrast,
    verify_chord_canvas_pure_st,
    verify_chord_pure_st,
    verify_interconnection_flow_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Validation (%R1140..%R1147, %M266..%M267)
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1 Check: Verify ChordCanvasSync POU conforms to IEC 61131-3 Pure ST grammar (%R1140..%R1147, %M266..%M267)."""
    SecurityGuard.assert_pure_st_content(CHORD_CANVAS_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(CHORD_CANVAS_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "ChordCanvasSync"
    assert pou.pou_type == POUType.PROGRAM

    var_dict = {v.name: v for v in pou.variables}

    # Verify Word Registers %R1140..%R1147
    assert "NodeCount" in var_dict
    assert var_dict["NodeCount"].address_binding == "%R1140"
    assert var_dict["NodeCount"].data_type == "INT"

    assert "TotalFlowScaled" in var_dict
    assert var_dict["TotalFlowScaled"].address_binding == "%R1141"
    assert var_dict["TotalFlowScaled"].data_type == "INT"

    assert "SelectedNodeIndex" in var_dict
    assert var_dict["SelectedNodeIndex"].address_binding == "%R1142"
    assert var_dict["SelectedNodeIndex"].data_type == "INT"

    assert "TopFlowScaled" in var_dict
    assert var_dict["TopFlowScaled"].address_binding == "%R1143"
    assert var_dict["TopFlowScaled"].data_type == "INT"

    assert "SourceNodeIndex" in var_dict
    assert var_dict["SourceNodeIndex"].address_binding == "%R1144"
    assert var_dict["SourceNodeIndex"].data_type == "INT"

    assert "TargetNodeIndex" in var_dict
    assert var_dict["TargetNodeIndex"].address_binding == "%R1145"
    assert var_dict["TargetNodeIndex"].data_type == "INT"

    assert "FlowImbalanceScaled" in var_dict
    assert var_dict["FlowImbalanceScaled"].address_binding == "%R1146"
    assert var_dict["FlowImbalanceScaled"].data_type == "INT"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1147"
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"

    # Verify Discrete Coils %M266..%M267
    assert "InterconnectionImbalanceTrip" in var_dict
    assert var_dict["InterconnectionImbalanceTrip"].address_binding == "%M266"
    assert var_dict["InterconnectionImbalanceTrip"].data_type == "BOOL"

    assert "ChordCanvasActive" in var_dict
    assert var_dict["ChordCanvasActive"].address_binding == "%M267"
    assert var_dict["ChordCanvasActive"].data_type == "BOOL"

    # Verify pure ST helper functions
    assert verify_chord_canvas_pure_st() is True
    assert verify_chord_pure_st() is True


def test_interconnection_flow_st_pou_alias_validation() -> None:
    """Verify InterconnectionFlowHmiSync POU alias parses cleanly with STParser."""
    SecurityGuard.assert_pure_st_content(INTERCONNECTION_FLOW_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(INTERCONNECTION_FLOW_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "InterconnectionFlowHmiSync"
    assert pou.pou_type == POUType.PROGRAM
    assert verify_interconnection_flow_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_contacts_rejection() -> None:
    """Verify ladder logic contacts ---[ ]--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadChordContacts
    VAR ChordCanvasActive : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_coils_rejection() -> None:
    """Verify ladder logic coils ---( )--- trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadChordCoils
    VAR InterconnectionImbalanceTrip : BOOL; END_VAR
    ---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


def test_anti_ladder_rung_delimiters_rejection() -> None:
    """Verify ladder logic RUNG / NETWORK delimiters trigger LadderForbiddenError."""
    ladder_text1 = """
    PROGRAM BadChordRung
    RUNG 1:
        ChordCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text1)

    ladder_text2 = """
    PROGRAM BadChordNetwork
    NETWORK 1:
        ChordCanvasActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text2)


def test_anti_ladder_mnemonics_rejection() -> None:
    """Verify ladder logic mnemonics XIC / OTE trigger LadderForbiddenError."""
    ladder_text = """
    PROGRAM BadChordMnemonics
    VAR TotalFlow : INT; END_VAR
    XIC %M267 OTE %M266;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(ladder_text)


# ============================================================================
# Section 3: Chord Circular Geometry Calculations & Flow Routing
# ============================================================================

def test_canonical_chord_network_topology() -> None:
    """Verify 5 canonical plant units and 9 transfer ribbons conform to specifications."""
    nodes, ribbons = create_canonical_chord_network()
    assert len(nodes) == 5
    assert len(ribbons) == 9

    # Node 0: Steam Gen (120.0 kg/s capacity, Emerald #10B981)
    assert nodes[0].node_id == "STEAM_GEN"
    assert nodes[0].name == "Steam Gen"
    assert nodes[0].capacity_kg_s == 120.0
    assert nodes[0].color == COLOR_EMERALD

    # Node 1: Cracker (150.0 kg/s capacity, Cyan #06B6D4)
    assert nodes[1].node_id == "CRACKER"
    assert nodes[1].name == "Cracker"
    assert nodes[1].capacity_kg_s == 150.0
    assert nodes[1].color == COLOR_CYAN

    # Node 2: Hydrotreater (110.0 kg/s capacity, Indigo #6366F1)
    assert nodes[2].node_id == "HYDROTREATER"
    assert nodes[2].name == "Hydrotreater"
    assert nodes[2].capacity_kg_s == 110.0
    assert nodes[2].color == COLOR_INDIGO

    # Node 3: Fractionator (130.0 kg/s capacity, Amber #F59E0B)
    assert nodes[3].node_id == "FRACTIONATOR"
    assert nodes[3].name == "Fractionator"
    assert nodes[3].capacity_kg_s == 130.0
    assert nodes[3].color == COLOR_AMBER

    # Node 4: Tank Farm (90.0 kg/s capacity, Crimson #EF4444)
    assert nodes[4].node_id == "TANK_FARM"
    assert nodes[4].name == "Tank Farm"
    assert nodes[4].capacity_kg_s == 90.0
    assert nodes[4].color == COLOR_CRIMSON

    # Total network flow check: 46+20+40+55+60+50+49+16+50 = 386.0 kg/s
    total_flow = sum(r.flow_kg_s for r in ribbons)
    assert math.isclose(total_flow, 386.0, abs_tol=1e-3)


def test_circular_chord_geometry_and_perimeter_partitioning() -> None:
    """Verify circular perimeter partitioning into 5 annular outer ring arcs with angular gaps."""
    nodes, ribbons = create_canonical_chord_network()
    layout_chord_diagram(nodes, ribbons, gap_deg=DEFAULT_NODE_GAP_DEG)

    total_gap_rad = len(nodes) * math.radians(DEFAULT_NODE_GAP_DEG)
    sum_node_arcs = sum(n.angular_span_rad for n in nodes)
    full_circle_sum = sum_node_arcs + total_gap_rad

    assert math.isclose(full_circle_sum, 2.0 * math.pi, rel_tol=1e-5)
    for n in nodes:
        assert n.angular_span_rad > 0.0
        assert n.theta_end_rad > n.theta_start_rad

    # Verify non-overlapping adjacent arcs
    for i in range(len(nodes) - 1):
        assert nodes[i].theta_end_rad <= nodes[i + 1].theta_start_rad + 1e-6

    # Verify annular sector path generation
    arc_path = generate_node_arc_path(nodes[0], center_x=CANVAS_CENTER_X, center_y=CANVAS_CENTER_Y)
    assert arc_path.startswith("M ")
    assert f"A {CHORD_OUTER_RADIUS:.2f} {CHORD_OUTER_RADIUS:.2f}" in arc_path
    assert f"A {CHORD_INNER_RADIUS:.2f} {CHORD_INNER_RADIUS:.2f}" in arc_path
    assert arc_path.endswith(" Z")


def test_smooth_cubic_bezier_ribbon_synthesis() -> None:
    """Verify inner cubic Bézier ribbon coordinates and quadratic fallback paths."""
    nodes, ribbons = create_canonical_chord_network()
    layout_chord_diagram(nodes, ribbons)

    ribbon = ribbons[0]
    # Smooth cubic Bézier ribbon with radial tension control points
    path_cubic = generate_chord_ribbon_path(ribbon, curve_mode=BezierCurveMode.CUBIC)
    assert path_cubic.startswith("M ")
    assert " C " in path_cubic
    assert path_cubic.endswith(" Z")

    # Center-convergent quadratic Bézier ribbon
    path_quad = generate_chord_ribbon_path(ribbon, curve_mode=BezierCurveMode.QUADRATIC)
    assert path_quad.startswith("M ")
    assert f"Q {CANVAS_CENTER_X:.2f} {CANVAS_CENTER_Y:.2f}" in path_quad
    assert path_quad.endswith(" Z")


def test_matrix_flow_routing_and_proportionality() -> None:
    """Verify capacity and flow proportionality across annular arcs and transfer ribbons."""
    nodes, ribbons = create_canonical_chord_network()
    layout_chord_diagram(nodes, ribbons)

    total_capacity = sum(n.capacity_kg_s for n in nodes)
    available_rad = (2.0 * math.pi) - (len(nodes) * math.radians(DEFAULT_NODE_GAP_DEG))

    # Node arc span strictly proportional to node capacity
    for n in nodes:
        expected_span = (n.capacity_kg_s / total_capacity) * available_rad
        assert math.isclose(n.angular_span_rad, expected_span, rel_tol=1e-5)

    # Nodal flow balance evaluation
    nodal_res = validate_nodal_flow_imbalance(nodes, ribbons)
    assert nodal_res["trip_active"] is False
    assert nodal_res["max_imbalance_pct"] < FLOW_IMBALANCE_THRESHOLD_PCT

    # Kirchhoff continuity
    kirchhoff = validate_kirchhoff_flux_continuity(nodes, ribbons)
    assert kirchhoff["conserved"] is True


# ============================================================================
# Section 4: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def test_standalone_svg_xml_validation() -> None:
    """Verify SVG output is well-formed XML and contains required industrial SVG elements."""
    canvas = create_canonical_chord_canvas()
    svg_str = canvas.render_svg()

    # Parse with standard XML parser to verify strictly valid XML
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)

    # Check required SVG structure
    assert 'id="canvas-header"' in svg_str
    assert 'id="chord-diagram"' in svg_str
    assert 'id="chord-ribbons"' in svg_str
    assert 'id="node-arcs"' in svg_str
    assert 'id="node-badges"' in svg_str
    assert 'id="network-metrics-card"' in svg_str
    assert 'id="telemetry-hud"' in svg_str


def test_ribbon_gradient_rendering_and_capacity_badges() -> None:
    """Verify ribbon gradient rendering in <defs> and capacity badges for plant nodes."""
    canvas = create_canonical_chord_canvas()
    svg_str = canvas.render_svg()

    # Gradient rendering in defs
    assert "<linearGradient" in svg_str
    assert 'id="ribbon-grad-' in svg_str
    assert 'stop-color="' in svg_str

    # Capacity badges
    assert 'class="node-badge capacity-badge"' in svg_str
    assert 'id="badge-STEAM_GEN"' in svg_str
    assert 'id="badge-CRACKER"' in svg_str
    assert 'id="badge-HYDROTREATER"' in svg_str
    assert 'id="badge-FRACTIONATOR"' in svg_str
    assert 'id="badge-TANK_FARM"' in svg_str

    # Capacity callout values
    assert "120.0 kg/s" in svg_str
    assert "150.0 kg/s" in svg_str
    assert "110.0 kg/s" in svg_str
    assert "130.0 kg/s" in svg_str
    assert "90.0 kg/s" in svg_str


# ============================================================================
# Section 5: WCAG 2.1 AAA Accessibility & Contrast Targets
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
# Section 6: Process Safety Trips & Horner Coil Assertion
# ============================================================================

def test_flow_imbalance_trip_interlock_0xb201() -> None:
    """Verify 0xB201 trip when nodal mass flow imbalance exceeds 15%, asserting coil %M266."""
    canvas = create_canonical_chord_canvas()
    assert canvas.imbalance_trip is False
    assert canvas.reg_table.read_bit("%M266") is False
    assert canvas.reg_table.read_bit("%M267") is True
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # Trigger flow imbalance trip (> 15% threshold, e.g. 18.5%)
    canvas.trigger_flow_imbalance(injected_imbalance_pct=18.5)

    assert canvas.imbalance_trip is True
    assert canvas.reg_table.read_bit("%M266") is True
    assert canvas.reg_table.read_bit("%M267") is True
    assert canvas.diagnostic_code == CHORD_ERR_FLOW_IMBALANCE
    assert canvas.diagnostic_code == 0xB201
    assert canvas.diagnostic_code == -19967
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1147")) == 0xB201)
    assert canvas.reg_table.read_word("%R1146") == 185  # 18.5% scaled x10
    assert bool(canvas.status_bits & ChordStatusBits.FLOW_IMBALANCE_TRIP)

    # Verify alert halo in SVG
    svg_trip = canvas.render_svg()
    assert 'PROCESS TRIP: %M266 ACTIVE' in svg_trip
    assert 'class="chord-node node-arc-alert"' in svg_trip


def test_invalid_node_count_fault_0xb202() -> None:
    """Verify 0xB202 diagnostic trip when plant node count is invalid (<3 or >12 nodes)."""
    canvas = create_canonical_chord_canvas()
    canvas.trigger_invalid_node_count(count=2)

    assert canvas.diagnostic_code == CHORD_ERR_INVALID_NODE_COUNT
    assert canvas.diagnostic_code == 0xB202
    assert canvas.diagnostic_code == -19966
    assert (DiagnosticCode(canvas.reg_table.read_word("%R1147")) == 0xB202)
    assert bool(canvas.status_bits & ChordStatusBits.INVALID_NODE_COUNT)
    assert not bool(canvas.status_bits & ChordStatusBits.NOMINAL_OPERATION)


def test_render_fault_diagnostic_0xb203() -> None:
    """Verify 0xB203 render fault condition and clean nominal reset."""
    canvas = create_canonical_chord_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == CHORD_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xB203
    assert canvas.diagnostic_code == -19965
    assert bool(canvas.status_bits & ChordStatusBits.RENDER_FAULT)

    # Reset nominal state
    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.imbalance_trip is False
    assert canvas.reg_table.read_bit("%M266") is False
    assert canvas.reg_table.read_bit("%M267") is True
    assert canvas.reg_table.read_word("%R1147") == 0


# ============================================================================
# Section 7: Horner OCS Memory Space Integration & Scan Cycle
# ============================================================================

def test_horner_register_space_synchronization() -> None:
    """Verify register table synchronization conforms to %R1140..%R1147, %M266..%M267."""
    canvas = create_canonical_chord_canvas()
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute(ctx)

    reg = canvas.reg_table
    assert reg.read_word("%R1140") == 5     # 5 plant nodes
    assert reg.read_word("%R1141") == 3860  # 386.0 kg/s total flow scaled x10
    assert reg.read_word("%R1142") == 0     # Selected node 0
    assert reg.read_word("%R1143") == 600   # 60.0 kg/s top transfer flow scaled x10
    assert reg.read_word("%R1144") == 2     # Source index 2 (Hydrotreater)
    assert reg.read_word("%R1145") == 3     # Target index 3 (Fractionator)
    assert reg.read_word("%R1146") == 0     # 0.0% flow imbalance
    assert reg.read_word("%R1147") == 0     # Diag OK

    assert reg.read_bit("%M266") is False   # InterconnectionImbalanceTrip = False
    assert reg.read_bit("%M267") is True    # ChordCanvasActive = True


def test_interactive_node_selection() -> None:
    """Verify interactive node selection updates focus bits and register %R1142."""
    canvas = create_canonical_chord_canvas()
    canvas.selected_node_index = 2
    canvas.update_telemetry()
    canvas.sync_to_registers()

    assert canvas.selected_node_index == 2
    assert canvas.reg_table.read_word("%R1142") == 2
    assert bool(canvas.status_bits & ChordStatusBits.NODE_FOCUSED)

    svg = canvas.render_svg()
    assert 'class="chord-node active-focus"' in svg


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration
# ============================================================================

def test_run_chord_canvas_verification_suite(tmp_path: Path) -> None:
    """Execute complete deterministic 9-stage verification suite."""
    ev_path = tmp_path / "chord_evidence.json"
    svg_path = tmp_path / "chord_sample.svg"

    report = run_chord_canvas_verification(
        output_path=ev_path,
        sample_svg_path=svg_path,
    )

    assert report["status"] == "success"
    assert report["error_code"] is None
    assert report["data"]["work_package"] == "W153"
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
    assert saved_ev["data"]["work_package"] == "W153"

    with open(svg_path, "r", encoding="utf-8") as f:
        saved_svg = f.read()
    assert "<svg" in saved_svg
    assert "</svg>" in saved_svg


# ============================================================================
# Section 9: DiagnosticCode, Edge Cases & Scan Lifecycle
# ============================================================================

def test_diagnostic_code_edge_cases() -> None:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and hash consistency."""
    code_imb = DiagnosticCode(0xB201)
    assert code_imb == 0xB201
    assert code_imb == -19967
    assert code_imb == 45569
    assert int(code_imb) == 45569
    assert hash(code_imb) == hash(45569)
    assert code_imb != "not_an_int"
    assert code_imb != 0x0000

    code_inv = DiagnosticCode(0xB202)
    assert code_inv == 0xB202
    assert code_inv == -19966
    assert code_inv == 45570

    code_fault = DiagnosticCode(0xB203)
    assert code_fault == 0xB203
    assert code_fault == -19965
    assert code_fault == 45571


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
    c1 = ChordCanvasSync()
    c2 = ChordCanvasEngine()
    c3 = CircularChordCanvas()
    c4 = InterconnectionFlowHmiSync()
    c5 = create_canonical_chord_canvas()

    for c in (c1, c2, c3, c4, c5):
        assert isinstance(c, ChordCanvas)

    nodes = create_canonical_chord_nodes()
    conduits = create_canonical_chord_conduits()
    assert len(nodes) == 5
    assert len(conduits) == 9


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface execution within simulated Horner PLC scan cycle."""
    canvas = create_canonical_chord_canvas()
    assert canvas.name == "ChordCanvasSync"
    assert canvas.priority == 88
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)
    canvas.execute(ctx)
    assert canvas.reg_table.read_bit("%M267") is True

    canvas.step()
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
