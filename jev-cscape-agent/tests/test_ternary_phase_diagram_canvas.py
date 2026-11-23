"""Comprehensive pytest test suite for Cscape HMI Dynamic Ternary Phase Diagram & Multi-Component Equilibrium Canvas (W183).

Work Package: W183 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1440..%R1447, %M336..%M337).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Equilateral ternary triangle geometry, barycentric forward & inverse mapping, closure checking.
4. Section 4: Binodal miscibility gap envelope, plait critical point, and smooth Bézier spline synthesis (M...C...Z).
5. Section 5: Equilibrium tie-lines, lever-rule phase split calculation, and distance to critical point.
6. Section 6: Dual-state representation (golden baseline binodal vs live operating point with halo filter).
7. Section 7: Process safety interlocks (0xD001 emulsion trip -> %M336, 0xD002 closure breach, 0xD003 render fault, clean reset).
8. Section 8: Standalone W3C SVG 1.1 XML generation, equilateral triangle, grid lines, and right-hand HUD card.
9. Section 9: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
10. Section 10: Horner OCS register space synchronization (%R1440..%R1447, %M336..%M337) with PrivilegeMode.SYSTEM.
11. Section 11: 9-stage verification suite integration test writing evidence JSON and sample SVG.
12. Section 12: DiagnosticCode signed/unsigned 16-bit math and edge cases.
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

from jev_cscape.hmi.ternary_phase_diagram_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CLOSURE_TOLERANCE,
    COLOR_AMBER,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_COMPONENT_A,
    COLOR_COMPONENT_B,
    COLOR_COMPONENT_C,
    COLOR_CRIMSON,
    COLOR_CYAN,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_EMERALD,
    COLOR_GOLDEN_BASELINE,
    COLOR_GOLDEN_DESIGN,
    COLOR_GRID_LINE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_COORDINATE_CLOSURE_BREACH,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DIAG_EVENT_TWO_PHASE_EMULSION_TRIP,
    NOMINAL_ACTIVE_TIE_LINES_COUNT,
    NOMINAL_BINODAL_DIST_CRITICAL_PCT,
    NOMINAL_COMP_A_PCT,
    NOMINAL_COMP_B_PCT,
    NOMINAL_COMP_C_PCT,
    NOMINAL_EQUILIBRIUM_EFFICIENCY_PCT,
    NOMINAL_LEVER_RULE_SPLIT_PCT,
    STANDARD_TRIANGLE_VERTICES,
    TERNARY_EQUILIBRIUM_PURE_ST_POU,
    TERNARY_ERR_COORDINATE_CLOSURE_BREACH,
    TERNARY_ERR_OK,
    TERNARY_ERR_RENDER_FAULT,
    TERNARY_ERR_TWO_PHASE_EMULSION_TRIP,
    TERNARY_PHASE_DIAGRAM_PURE_ST_POU,
    TRIANGLE_HEIGHT,
    TRIANGLE_SIDE_LENGTH,
    VERTEX_A,
    VERTEX_B,
    VERTEX_C,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    BinodalEnvelope,
    BinodalNode,
    DiagnosticCode,
    OperationalState,
    PhaseState,
    SystemMode,
    TernaryCanvasStatusBits,
    TernaryEquilibriumCanvas,
    TernaryEquilibriumHmiSync,
    TernaryPhaseDiagramCanvas,
    TernaryPhaseDiagramCanvasSync,
    TernaryStatusBits,
    TieLine,
    build_canonical_binodal_envelope,
    calculate_contrast_ratio,
    calculate_distance_to_critical_point,
    calculate_lever_rule_phase_split,
    cartesian_2d_to_ternary,
    check_coordinate_closure,
    create_canonical_ternary_canvas,
    create_canonical_ternary_phase_diagram_canvas,
    generate_smooth_bezier_spline_path,
    generate_ternary_phase_diagram_canvas_svg,
    hex_to_relative_luminance,
    normalize_composition,
    run_ternary_phase_diagram_canvas_verification,
    srgb_channel_to_linear,
    ternary_to_cartesian_2d,
    validate_wcag_aaa_contrast,
    verify_ternary_phase_diagram_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestPureSTValidation:
    """Validate compliance with IEC 61131-3 Pure Structured Text standards (%R1440..%R1447, %M336..%M337)."""

    def test_pure_st_pou_ast_parsing_and_symbol_binding(self) -> None:
        """Stage 1 Check: Verify TernaryPhaseDiagramCanvasSync POU conforms to IEC 61131-3 grammar (%R1440..%R1447, %M336..%M337)."""
        SecurityGuard.assert_pure_st_content(TERNARY_PHASE_DIAGRAM_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(TERNARY_PHASE_DIAGRAM_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "TernaryPhaseDiagramCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        expected_bindings = {
            "CompAWeightPctScaled": "%R1440",
            "CompBWeightPctScaled": "%R1441",
            "CompCWeightPctScaled": "%R1442",
            "LeverRulePhaseSplitPctScaled": "%R1443",
            "BinodalDistanceToCriticalScaled": "%R1444",
            "ActiveTieLinesCount": "%R1445",
            "EquilibriumEfficiencyScoreScaled": "%R1446",
            "DiagnosticStatusCode": "%R1447",
            "PhaseSeparationTrip": "%M336",
            "TernaryCanvasActive": "%M337",
        }

        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict, f"Missing variable binding: {name}"
            assert var_dict[name] == addr, f"Binding mismatch for {name}: {var_dict[name]} != {addr}"

        type_dict = {v.name: v.data_type for v in pou.variables}
        for name in [
            "CompAWeightPctScaled", "CompBWeightPctScaled", "CompCWeightPctScaled",
            "LeverRulePhaseSplitPctScaled", "BinodalDistanceToCriticalScaled",
            "ActiveTieLinesCount", "EquilibriumEfficiencyScoreScaled", "DiagnosticStatusCode",
        ]:
            assert type_dict[name] == "INT", f"Expected INT for {name}, got {type_dict[name]}"

        for name in ["PhaseSeparationTrip", "TernaryCanvasActive"]:
            assert type_dict[name] == "BOOL", f"Expected BOOL for {name}, got {type_dict[name]}"

    def test_ternary_equilibrium_alias_pou(self) -> None:
        """Verify TernaryEquilibriumHmiSync alias POU parses cleanly with STParser."""
        SecurityGuard.assert_pure_st_content(TERNARY_EQUILIBRIUM_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(TERNARY_EQUILIBRIUM_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "TernaryEquilibriumHmiSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        expected_bindings = {
            "CompAWeightPctScaled": "%R1440",
            "CompBWeightPctScaled": "%R1441",
            "CompCWeightPctScaled": "%R1442",
            "LeverRulePhaseSplitPctScaled": "%R1443",
            "BinodalDistanceToCriticalScaled": "%R1444",
            "ActiveTieLinesCount": "%R1445",
            "EquilibriumEfficiencyScoreScaled": "%R1446",
            "DiagnosticStatusCode": "%R1447",
            "PhaseSeparationTrip": "%M336",
            "TernaryCanvasActive": "%M337",
        }
        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict
            assert var_dict[name] == addr

    def test_helper_verification_functions(self) -> None:
        """Verify Pure ST helper verification function returns True."""
        assert verify_ternary_phase_diagram_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

class TestLadderConstructInterception:
    """Verify security guard intercepts forbidden ladder logic constructs."""

    @pytest.mark.parametrize(
        "label,snippet",
        [
            ("Contacts", "PROGRAM BadTernaryContacts\nVAR Active : BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"),
            ("Coils", "PROGRAM BadTernaryCoils\nVAR Trip : BOOL; END_VAR\n---( )---\nEND_PROGRAM"),
            ("ContactsSlash", "PROGRAM BadTernaryContactsSlash\nVAR Active : BOOL; END_VAR\n---[/]---\nEND_PROGRAM"),
            ("Rung", "PROGRAM BadTernaryRung\nRUNG 1:\n    Active := TRUE;\nEND_PROGRAM"),
            ("Network", "PROGRAM BadTernaryNetwork\nNETWORK 1:\n    Active := TRUE;\nEND_PROGRAM"),
            ("XIC", "PROGRAM BadTernaryMnemonicXIC\nVAR Reg : INT; END_VAR\nXIC %M337;\nEND_PROGRAM"),
            ("OTE", "PROGRAM BadTernaryMnemonicOTE\nVAR Reg : INT; END_VAR\nOTE %M336;\nEND_PROGRAM"),
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden(self, label: str, snippet: str) -> None:
        """Verify that forbidden ladder logic constructs fail closed with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: Equilateral Ternary Triangle Geometry & Barycentric Transformation
# ============================================================================

class TestEquilateralTernaryGeometry:
    """Verify equilateral triangle geometry, forward & inverse barycentric mapping, and closure checking."""

    def test_triangle_geometry_dimensions(self) -> None:
        """Verify equilateral side lengths and height."""
        side_ab = math.hypot(VERTEX_A[0] - VERTEX_B[0], VERTEX_A[1] - VERTEX_B[1])
        side_bc = math.hypot(VERTEX_B[0] - VERTEX_C[0], VERTEX_B[1] - VERTEX_C[1])
        side_ca = math.hypot(VERTEX_C[0] - VERTEX_A[0], VERTEX_C[1] - VERTEX_A[1])

        assert math.isclose(side_ab, TRIANGLE_SIDE_LENGTH, rel_tol=1e-5)
        assert math.isclose(side_bc, TRIANGLE_SIDE_LENGTH, rel_tol=1e-5)
        assert math.isclose(side_ca, TRIANGLE_SIDE_LENGTH, rel_tol=1e-5)
        assert math.isclose(side_ab, 520.0, rel_tol=1e-5)

        h_calc = TRIANGLE_SIDE_LENGTH * math.sqrt(3.0) / 2.0
        assert math.isclose(h_calc, TRIANGLE_HEIGHT, rel_tol=1e-5)

    def test_vertex_coordinate_transformations(self) -> None:
        """Verify vertex positions map exactly to pure component compositions."""
        pa = ternary_to_cartesian_2d(1.0, 0.0, 0.0)
        pb = ternary_to_cartesian_2d(0.0, 1.0, 0.0)
        pc = ternary_to_cartesian_2d(0.0, 0.0, 1.0)

        assert math.isclose(pa[0], VERTEX_A[0], abs_tol=1e-6)
        assert math.isclose(pa[1], VERTEX_A[1], abs_tol=1e-6)

        assert math.isclose(pb[0], VERTEX_B[0], abs_tol=1e-6)
        assert math.isclose(pb[1], VERTEX_B[1], abs_tol=1e-6)

        assert math.isclose(pc[0], VERTEX_C[0], abs_tol=1e-6)
        assert math.isclose(pc[1], VERTEX_C[1], abs_tol=1e-6)

    def test_round_trip_barycentric_mapping(self) -> None:
        """Verify round-trip mapping (ternary -> cartesian -> ternary) is exact."""
        test_points = [
            (0.45, 0.35, 0.20),
            (0.333333, 0.333333, 0.333334),
            (0.10, 0.80, 0.10),
            (0.60, 0.20, 0.20),
            (0.05, 0.05, 0.90),
        ]
        for a, b, c in test_points:
            x, y = ternary_to_cartesian_2d(a, b, c)
            ra, rb, rc = cartesian_2d_to_ternary(x, y)
            assert math.isclose(a, ra, abs_tol=1e-6)
            assert math.isclose(b, rb, abs_tol=1e-6)
            assert math.isclose(c, rc, abs_tol=1e-6)

    def test_closure_checking(self) -> None:
        """Verify check_coordinate_closure accepts tolerance <= 0.02 and rejects breach."""
        assert check_coordinate_closure(0.45, 0.35, 0.20, tolerance=CLOSURE_TOLERANCE) is True
        assert check_coordinate_closure(0.45, 0.35, 0.21, tolerance=CLOSURE_TOLERANCE) is True
        assert check_coordinate_closure(0.45, 0.35, 0.23, tolerance=CLOSURE_TOLERANCE) is False
        assert check_coordinate_closure(0.40, 0.30, 0.20, tolerance=CLOSURE_TOLERANCE) is False


# ============================================================================
# Section 4: Binodal Envelope & Bézier Splines Engine
# ============================================================================

class TestBinodalEnvelopeAndSplines:
    """Verify binodal curve miscibility gap envelope and cubic Bézier splines synthesis."""

    def test_binodal_envelope_structure(self) -> None:
        """Verify binodal envelope contains 13 nodes, plait critical point, and 5 tie-lines."""
        env = build_canonical_binodal_envelope()
        assert len(env.nodes) == 13
        assert env.critical_node.is_critical is True
        assert math.isclose(env.critical_node.x_c, 0.3085, abs_tol=1e-3)
        assert len(env.tie_lines) == 5

    def test_smooth_bezier_spline_path_syntax(self) -> None:
        """Verify smooth Bézier spline generator emits M...C...Z format."""
        pts = [(100.0, 100.0), (200.0, 300.0), (400.0, 250.0), (300.0, 50.0)]
        path_d = generate_smooth_bezier_spline_path(pts, closed=True)
        assert path_d.startswith("M")
        assert " C " in path_d
        assert path_d.endswith("Z")

        # Open curve
        open_d = generate_smooth_bezier_spline_path(pts, closed=False)
        assert open_d.startswith("M")
        assert " C " in open_d
        assert not open_d.endswith("Z")


# ============================================================================
# Section 5: Equilibrium Tie-Lines & Lever Rule Calculations
# ============================================================================

class TestEquilibriumCalculations:
    """Verify tie-line lever-rule phase split and distance to critical point."""

    def test_nominal_lever_rule_phase_split(self) -> None:
        """Verify nominal operating point (45% A, 35% B, 20% C) calculates 62.0% phase split."""
        env = build_canonical_binodal_envelope()
        split = calculate_lever_rule_phase_split(0.45, 0.35, 0.20, env)
        assert math.isclose(split, NOMINAL_LEVER_RULE_SPLIT_PCT, abs_tol=0.2)

    def test_distance_to_critical_point(self) -> None:
        """Verify nominal distance to plait point is 14.5%."""
        env = build_canonical_binodal_envelope()
        dist = calculate_distance_to_critical_point(0.45, 0.35, 0.20, env.critical_node)
        assert math.isclose(dist, NOMINAL_BINODAL_DIST_CRITICAL_PCT, abs_tol=0.2)


# ============================================================================
# Section 6: Dual-State Representation
# ============================================================================

class TestDualStateRepresentation:
    """Verify dual-state representation (golden baseline vs live operating point)."""

    def test_dual_state_elements_in_svg(self) -> None:
        """Verify SVG contains golden baseline binodal, tie-lines, and live operating point."""
        svg = generate_ternary_phase_diagram_canvas_svg()
        assert 'id="golden-baseline-binodal"' in svg
        assert 'id="golden-design-tie-lines"' in svg
        assert COLOR_GOLDEN_BASELINE in svg
        assert 'stroke-dasharray="6,4"' in svg
        assert 'id="live-operating-point"' in svg
        assert 'filter="url(#op-halo)"' in svg


# ============================================================================
# Section 7: Process Safety Interlocks & Diagnostics
# ============================================================================

class TestProcessSafetyInterlocks:
    """Verify process safety interlocks (0xD001, 0xD002, 0xD003) and coil assertion."""

    def test_two_phase_emulsion_trip(self) -> None:
        """Verify 0xD001 emulsion trip asserts %M336 and updates diagnostic status."""
        canvas = create_canonical_ternary_phase_diagram_canvas()
        canvas.trigger_two_phase_emulsion_trip()

        assert canvas.phase_separation_trip is True
        assert canvas.reg_table.read_bit("%M336") is True
        assert canvas.diagnostic_status_code == TERNARY_ERR_TWO_PHASE_EMULSION_TRIP
        assert canvas.diagnostic_status_code == 0xD001
        assert canvas.diagnostic_status_code == -12287
        assert DiagnosticCode(canvas.reg_table.read_word("%R1447")) == 0xD001

    def test_coordinate_closure_breach(self) -> None:
        """Verify 0xD002 closure breach is asserted on sum(x) imbalance > 0.02."""
        canvas = create_canonical_ternary_phase_diagram_canvas()
        canvas.trigger_coordinate_closure_breach(delta=0.05)

        assert canvas.diagnostic_status_code == TERNARY_ERR_COORDINATE_CLOSURE_BREACH
        assert canvas.diagnostic_status_code == 0xD002
        assert canvas.diagnostic_status_code == -12286
        assert DiagnosticCode(canvas.reg_table.read_word("%R1447")) == 0xD002

    def test_render_fault_and_nominal_reset(self) -> None:
        """Verify 0xD003 render fault and clean nominal reset to 0x0000."""
        canvas = create_canonical_ternary_phase_diagram_canvas()
        canvas.trigger_render_fault()

        assert canvas.diagnostic_status_code == TERNARY_ERR_RENDER_FAULT
        assert canvas.diagnostic_status_code == 0xD003
        assert DiagnosticCode(canvas.reg_table.read_word("%R1447")) == 0xD003

        canvas.reset_nominal()
        assert canvas.diagnostic_status_code == DIAG_EVENT_OK
        assert canvas.phase_separation_trip is False
        assert canvas.reg_table.read_bit("%M336") is False


# ============================================================================
# Section 8: Standalone W3C SVG 1.1 Canvas Renderer
# ============================================================================

class TestSVGCanvasRenderer:
    """Verify standalone W3C SVG 1.1 canvas rendering and XML schema."""

    def test_svg_xml_validity_and_structure(self) -> None:
        """Verify rendered SVG parses as valid XML and contains essential components."""
        svg = generate_ternary_phase_diagram_canvas_svg()
        root = ET.fromstring(svg)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)

        assert 'id="canvas-header"' in svg
        assert 'id="ternary-diagram-grid"' in svg
        assert 'id="operating-point-focus"' in svg
        assert 'id="component-balance-hud"' in svg


# ============================================================================
# Section 9: WCAG 2.1 AAA Accessibility
# ============================================================================

class TestWCAGAccessibility:
    """Verify WCAG 2.1 AAA contrast compliance."""

    def test_contrast_ratios(self) -> None:
        """Verify decoupled badges, theme text, and graphical colors meet AAA targets."""
        badge_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        theme_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        cyan_contrast = calculate_contrast_ratio(COLOR_CYAN, COLOR_DARK_THEME_BACKING)
        emerald_contrast = calculate_contrast_ratio(COLOR_EMERALD, COLOR_DARK_THEME_BACKING)
        amber_contrast = calculate_contrast_ratio(COLOR_AMBER, COLOR_DARK_THEME_BACKING)

        assert badge_contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert badge_contrast > 18.0
        assert theme_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cyan_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert emerald_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert amber_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """Verify validate_wcag_aaa_contrast helper returns True."""
        ok, text_c, min_g = validate_wcag_aaa_contrast()
        assert ok is True
        assert text_c >= 7.0
        assert min_g >= 3.0


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & Scan Cycle
# ============================================================================

class TestHornerMemoryIntegration:
    """Verify register synchronization (%R1440..%R1447, %M336..%M337) and scan step."""

    def test_register_space_synchronization(self) -> None:
        """Verify register values in nominal state with PrivilegeMode.SYSTEM."""
        canvas = create_canonical_ternary_phase_diagram_canvas()
        canvas.scan_step(0.01)
        reg = canvas.reg_table

        assert reg.read_word("%R1440") == 450
        assert reg.read_word("%R1441") == 350
        assert reg.read_word("%R1442") == 200
        assert reg.read_word("%R1443") == 620
        assert reg.read_word("%R1444") == 145
        assert reg.read_word("%R1445") == 5
        assert reg.read_word("%R1446") == 962
        assert reg.read_word("%R1447") == 0
        assert reg.read_bit("%M336") is False
        assert reg.read_bit("%M337") is True

    def test_ilogic_unit_interface(self) -> None:
        """Verify ILogicUnit contract properties and execution."""
        canvas = create_canonical_ternary_phase_diagram_canvas()
        assert canvas.name == "TernaryPhaseDiagramCanvasSync"
        assert canvas.priority == 85
        assert canvas.is_enabled is True

        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=canvas.reg_table.read_register,
            set_register=lambda a, v: canvas.reg_table.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )
        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M337") is True


# ============================================================================
# Section 11: 9-Stage Verification Suite Integration
# ============================================================================

class TestVerificationSuite:
    """Verify deterministic 9-stage verification suite executes and reports SUCCESS."""

    def test_run_verification_suite(self, tmp_path: Path) -> None:
        """Execute run_ternary_phase_diagram_canvas_verification and verify output payload."""
        ev_file = tmp_path / "evidence.json"
        svg_file = tmp_path / "sample.svg"

        res = run_ternary_phase_diagram_canvas_verification(
            output_path=str(ev_file),
            sample_svg_path=str(svg_file),
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        data = res["data"]
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9
        assert ev_file.exists()
        assert svg_file.exists()


# ============================================================================
# Section 12: DiagnosticCode Signed/Unsigned Math
# ============================================================================

class TestDiagnosticCodeMath:
    """Verify DiagnosticCode handles 16-bit signed/unsigned equivalence."""

    def test_diagnostic_code_equality(self) -> None:
        """Verify 0xD001 equals -12287 and 53249."""
        code = DiagnosticCode(0xD001)
        assert code == 0xD001
        assert code == 53249
        assert code == -12287

        code2 = DiagnosticCode(0xD002)
        assert code2 == 0xD002
        assert code2 == 53250
        assert code2 == -12286

        code3 = DiagnosticCode(0xD003)
        assert code3 == 0xD003
        assert code3 == 53251
        assert code3 == -12285
