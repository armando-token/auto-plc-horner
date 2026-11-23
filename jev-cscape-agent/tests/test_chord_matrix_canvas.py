"""Comprehensive pytest test suite for Cscape HMI Dynamic Chord Diagram & Inter-Unit Material / Energy Flux Matrix Canvas (W177).

Work Package: W177 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1380..%R1387, %M322..%M323).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Circular chord geometry, 5 outer unit arcs, and angular span calculation.
4. Section 4: 5x5 flux matrix, directed flow calculation, and Bézier ribbon generation.
5. Section 5: Standalone W3C SVG 1.1 XML generation, ribbon paths, node arcs, labels, and HUD card.
6. Section 6: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
7. Section 7: Process safety trips (0xCA01 flux conservation breach, 0xCA02 matrix singularity) and Horner coil assertion (%M322, %M323).
8. Section 8: Horner OCS register space synchronization (%R1380..%R1387, %M322..%M323) with PrivilegeMode.SYSTEM.
9. Section 9: 9-stage verification suite integration test writing evidence JSON and sample SVG.
10. Section 10: DiagnosticCode signed/unsigned 16-bit math and edge cases.
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

from jev_cscape.hmi.chord_matrix_canvas import (
    ALK_GRAPHICAL_CONTRAST_RATIO,
    CANONICAL_BASELINE_FLUX_MATRIX,
    CANONICAL_UNIT_COUNT,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CDU_GRAPHICAL_CONTRAST_RATIO,
    CHORD_ERR_CIRCULAR_MATRIX_SINGULARITY,
    CHORD_ERR_FLUX_BREACH,
    CHORD_ERR_FLUX_CONSERVATION_BREACH,
    CHORD_ERR_MATRIX_SINGULARITY,
    CHORD_ERR_OK,
    CHORD_ERR_RENDER_FAULT,
    CHORD_FLUX_MATRIX_PURE_ST_POU,
    CHORD_INNER_RADIUS,
    CHORD_OUTER_RADIUS,
    CHORD_PURE_ST_POU,
    COLOR_ALERT_CRIMSON,
    COLOR_ALK,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CDU,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_FCC,
    COLOR_FOCUS_BLUE,
    COLOR_GOLDEN_BASELINE,
    COLOR_HCU,
    COLOR_LIVE_RIBBON,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_VDU,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_UNIT_GAP_DEG,
    DIAG_EVENT_CIRCULAR_MATRIX_SINGULARITY,
    DIAG_EVENT_FLUX_CONSERVATION_BREACH,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    FCC_GRAPHICAL_CONTRAST_RATIO,
    FLUX_CONSERVATION_TOLERANCE_T_H,
    HCU_GRAPHICAL_CONTRAST_RATIO,
    INTER_UNIT_PROCESS_FLUX_PURE_ST_POU,
    MAX_FLUX_IMBALANCE_THRESHOLD_PCT,
    MAX_PERMITTED_UNITS,
    MIN_PERMITTED_UNITS,
    RECIRCULATION_CHORD_PAIRS,
    REFINERY_PALETTE,
    VDU_GRAPHICAL_CONTRAST_RATIO,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    BezierCurveMode,
    ChordFluxMatrixCanvas,
    ChordFluxMatrixCanvasSync,
    ChordFluxMatrixEngine,
    ChordMatrixCanvas,
    ChordMatrixMetrics,
    ChordMatrixStatusBits,
    ChordStatusBits,
    DiagnosticCode,
    InterUnitChord,
    InterUnitProcessFluxHmiSync,
    RefineryChordMatrixCanvas,
    RefineryUnit,
    calculate_contrast_ratio,
    check_matrix_singularity,
    compute_chord_matrix_metrics,
    create_canonical_chord_matrix,
    create_canonical_chord_matrix_canvas,
    create_canonical_refinery_units,
    create_mock_scan_context,
    generate_chord_matrix_canvas_svg,
    generate_chord_ribbon_path,
    generate_unit_arc_path,
    hex_to_relative_luminance,
    layout_chord_matrix_diagram,
    run_chord_matrix_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_chord_flux_matrix_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Validation (%R1380..%R1387, %M322..%M323)
# ============================================================================

class TestPureSTValidation:
    """Validate compliance with IEC 61131-3 Pure Structured Text standards (%R1380..%R1387, %M322..%M323)."""

    def test_pure_st_pou_ast_parsing_and_symbol_binding(self) -> None:
        """Stage 1 Check: Verify ChordFluxMatrixCanvasSync POU conforms to IEC 61131-3 Pure ST grammar (%R1380..%R1387, %M322..%M323)."""
        SecurityGuard.assert_pure_st_content(CHORD_FLUX_MATRIX_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(CHORD_FLUX_MATRIX_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "ChordFluxMatrixCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        expected_bindings = {
            "GlobalFluxEfficiencyScoreScaled": "%R1380",
            "ActiveNodesCount": "%R1381",
            "SelectedSourceNodeIndex": "%R1382",
            "SelectedTargetNodeIndex": "%R1383",
            "SelectedChordFluxRateScaled": "%R1384",
            "RecirculationRatioScaled": "%R1385",
            "MaxFluxImbalanceScaled": "%R1386",
            "DiagnosticStatusCode": "%R1387",
            "ChordFluxTrip": "%M322",
            "ChordCanvasActive": "%M323",
        }

        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict, f"Missing variable binding: {name}"
            assert var_dict[name] == addr, f"Binding mismatch for {name}: {var_dict[name]} != {addr}"

        type_dict = {v.name: v.data_type for v in pou.variables}
        for name in [
            "GlobalFluxEfficiencyScoreScaled", "ActiveNodesCount", "SelectedSourceNodeIndex",
            "SelectedTargetNodeIndex", "SelectedChordFluxRateScaled", "RecirculationRatioScaled",
            "MaxFluxImbalanceScaled", "DiagnosticStatusCode",
        ]:
            assert type_dict[name] == "INT", f"Expected INT for {name}, got {type_dict[name]}"

        for name in ["ChordFluxTrip", "ChordCanvasActive"]:
            assert type_dict[name] == "BOOL", f"Expected BOOL for {name}, got {type_dict[name]}"

    def test_inter_unit_process_flux_alias_pou(self) -> None:
        """Verify InterUnitProcessFluxHmiSync alias POU parses cleanly with STParser."""
        SecurityGuard.assert_pure_st_content(INTER_UNIT_PROCESS_FLUX_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(INTER_UNIT_PROCESS_FLUX_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "InterUnitProcessFluxHmiSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_bindings = {
            "GlobalFluxEfficiencyScoreScaled": "%R1380",
            "ActiveNodesCount": "%R1381",
            "SelectedSourceNodeIndex": "%R1382",
            "SelectedTargetNodeIndex": "%R1383",
            "SelectedChordFluxRateScaled": "%R1384",
            "RecirculationRatioScaled": "%R1385",
            "MaxFluxImbalanceScaled": "%R1386",
            "DiagnosticStatusCode": "%R1387",
            "ChordFluxTrip": "%M322",
            "ChordCanvasActive": "%M323",
        }
        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict
            assert var_dict[name] == addr

    def test_helper_verification_functions(self) -> None:
        """Verify Pure ST helper verification functions return True."""
        assert verify_chord_flux_matrix_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Construct Security Interception
# ============================================================================

class TestLadderConstructInterception:
    """Verify security guard intercepts forbidden ladder logic constructs."""

    @pytest.mark.parametrize(
        "label,snippet",
        [
            ("Contacts", "PROGRAM BadChordContacts\nVAR Active : BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"),
            ("Coils", "PROGRAM BadChordCoils\nVAR Trip : BOOL; END_VAR\n---( )---\nEND_PROGRAM"),
            ("Rung", "PROGRAM BadChordRung\nRUNG 1:\n    Active := TRUE;\nEND_PROGRAM"),
            ("Network", "PROGRAM BadChordNetwork\nNETWORK 1:\n    Active := TRUE;\nEND_PROGRAM"),
            ("XIC", "PROGRAM BadChordMnemonicXIC\nVAR Reg : INT; END_VAR\nXIC %M323;\nEND_PROGRAM"),
            ("OTE", "PROGRAM BadChordMnemonicOTE\nVAR Reg : INT; END_VAR\nOTE %M322;\nEND_PROGRAM"),
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden(self, label: str, snippet: str) -> None:
        """Verify that forbidden ladder logic constructs fail closed with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: Circular Chord Geometry & 5 Outer Unit Arcs
# ============================================================================

class TestCircularChordGeometry:
    """Verify circular chord geometry, 5 outer unit arcs, and angular span calculation."""

    def test_5_canonical_units_topology_and_attributes(self) -> None:
        """Verify 5 canonical refinery units conform to specifications."""
        units = create_canonical_refinery_units()
        assert len(units) == 5

        # Unit 0: CDU (Crude Distillation Unit, 350.0 t/h, Emerald #10B981)
        assert units[0].unit_id == "CDU"
        assert units[0].name == "Crude Distillation Unit"
        assert units[0].capacity_t_h == 350.0
        assert units[0].color == COLOR_CDU

        # Unit 1: VDU (Vacuum Distillation Unit, 220.0 t/h, Cyan #06B6D4)
        assert units[1].unit_id == "VDU"
        assert units[1].name == "Vacuum Distillation Unit"
        assert units[1].capacity_t_h == 220.0
        assert units[1].color == COLOR_VDU

        # Unit 2: FCC (Fluid Catalytic Cracker, 260.0 t/h, Amber #F59E0B)
        assert units[2].unit_id == "FCC"
        assert units[2].name == "Fluid Catalytic Cracker"
        assert units[2].capacity_t_h == 260.0
        assert units[2].color == COLOR_FCC

        # Unit 3: HCU (Hydrocracker Unit, 240.0 t/h, Indigo-Lavender #818CF8)
        assert units[3].unit_id == "HCU"
        assert units[3].name == "Hydrocracker Unit"
        assert units[3].capacity_t_h == 240.0
        assert units[3].color == COLOR_HCU

        # Unit 4: ALK (Alkylation Plant, 150.0 t/h, Rose #F43F5E)
        assert units[4].unit_id == "ALK"
        assert units[4].name == "Alkylation Plant"
        assert units[4].capacity_t_h == 150.0
        assert units[4].color == COLOR_ALK

    def test_circular_perimeter_partitioning_into_5_unit_arcs(self) -> None:
        """Verify circular perimeter partitioning into 5 annular outer ring arcs with angular gaps."""
        units = create_canonical_refinery_units()
        base_matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        chords = layout_chord_matrix_diagram(units, base_matrix, base_matrix, gap_deg=DEFAULT_UNIT_GAP_DEG)

        total_gap_rad = len(units) * math.radians(DEFAULT_UNIT_GAP_DEG)
        sum_unit_arcs = sum(u.angular_span_rad for u in units)
        full_circle_sum = sum_unit_arcs + total_gap_rad

        assert math.isclose(full_circle_sum, 2.0 * math.pi, rel_tol=1e-5)
        for u in units:
            assert u.angular_span_rad > 0.0
            assert u.theta_end_rad > u.theta_start_rad

        # Verify non-overlapping adjacent arcs
        for i in range(len(units) - 1):
            assert units[i].theta_end_rad <= units[i + 1].theta_start_rad + 1e-6

    def test_unit_arc_svg_path_generation(self) -> None:
        """Verify annular sector path generation for refinery unit arcs."""
        units = create_canonical_refinery_units()
        base_matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        layout_chord_matrix_diagram(units, base_matrix, base_matrix)

        arc_path = generate_unit_arc_path(units[0], center_x=CANVAS_CENTER_X, center_y=CANVAS_CENTER_Y)
        assert arc_path.startswith("M ")
        assert f"A {CHORD_OUTER_RADIUS:.2f} {CHORD_OUTER_RADIUS:.2f}" in arc_path
        assert f"A {CHORD_INNER_RADIUS:.2f} {CHORD_INNER_RADIUS:.2f}" in arc_path
        assert " L " in arc_path
        assert arc_path.endswith(" Z")

    def test_proportional_angular_span_allocation(self) -> None:
        """Verify unit arc angular spans are strictly proportional to refinery unit capacity."""
        units = create_canonical_refinery_units()
        base_matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        layout_chord_matrix_diagram(units, base_matrix, base_matrix)

        total_capacity = sum(u.capacity_t_h for u in units)
        available_rad = (2.0 * math.pi) - (len(units) * math.radians(DEFAULT_UNIT_GAP_DEG))

        for u in units:
            expected_span = (u.capacity_t_h / total_capacity) * available_rad
            assert math.isclose(u.angular_span_rad, expected_span, rel_tol=1e-5)


# ============================================================================
# Section 4: 5x5 Flux Matrix, Directed Flow & Bézier Ribbons
# ============================================================================

class TestFluxMatrixAndDirectedFlow:
    """Verify 5x5 flux matrix, directed flow calculation, and Bézier ribbon generation."""

    def test_5x5_flux_matrix_structure_and_total_flow(self) -> None:
        """Verify canonical 5x5 flux matrix structure and total mass flux summation."""
        matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        assert len(matrix) == 5
        assert all(len(row) == 5 for row in matrix)

        # Check diagonal is zero (no self-loops)
        for i in range(5):
            assert matrix[i][i] == 0.0

        # Total matrix flux in baseline: 245 + 160 + 180 + 190 + 152 = 927.0 t/h
        total_flux = sum(sum(row) for row in matrix)
        assert math.isclose(total_flux, 927.0, abs_tol=1e-3)

        # Peak transfer: CDU -> VDU = 142.0 t/h
        assert matrix[0][1] == 142.0
        peak_val = max(max(row) for row in matrix)
        assert peak_val == 142.0

    def test_directed_flow_conservation_and_kirchhoff_balance(self) -> None:
        """Verify directed flow calculation preserves mass conservation across all 5 units in baseline."""
        units = create_canonical_refinery_units()
        base_matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        chords = layout_chord_matrix_diagram(units, base_matrix, base_matrix)

        # All units should have residuals within tolerance
        for u in units:
            assert abs(u.residual_t_h) <= FLUX_CONSERVATION_TOLERANCE_T_H
            assert u.imbalance_pct <= MAX_FLUX_IMBALANCE_THRESHOLD_PCT
            assert u.is_imbalanced is False

    def test_recirculation_ratio_and_chords_synthesis(self) -> None:
        """Verify recirculation loop streams and total synthesized chords."""
        units = create_canonical_refinery_units()
        base_matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        chords = layout_chord_matrix_diagram(units, base_matrix, base_matrix)

        # Total active chords
        assert len(chords) == 13
        metrics = compute_chord_matrix_metrics(units, chords)
        assert metrics.recirculation_ratio_pct > 15.0
        assert metrics.recirculation_ratio_scaled == 185  # ~18.5% scaled x10

    def test_smooth_cubic_and_quadratic_bezier_ribbon_generation(self) -> None:
        """Verify quadratic and cubic Bézier ribbon path generation."""
        units = create_canonical_refinery_units()
        base_matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        chords = layout_chord_matrix_diagram(units, base_matrix, base_matrix)

        chord = chords[0]
        # Center-convergent quadratic Bézier ribbon (M...Q...Z)
        path_quad = generate_chord_ribbon_path(chord, is_baseline=False, curve_mode=BezierCurveMode.QUADRATIC)
        assert path_quad.startswith("M ")
        assert f"Q {CANVAS_CENTER_X:.2f} {CANVAS_CENTER_Y:.2f}" in path_quad
        assert path_quad.endswith(" Z")

        # Smooth cubic Bézier ribbon (M...C...Z)
        path_cubic = generate_chord_ribbon_path(chord, is_baseline=False, curve_mode=BezierCurveMode.CUBIC)
        assert path_cubic.startswith("M ")
        assert " C " in path_cubic
        assert path_cubic.endswith(" Z")

    def test_matrix_singularity_detection(self) -> None:
        """Verify check_matrix_singularity detects zero-flow deadlock and disconnected node singularities."""
        # Nominal matrix is non-singular
        nom_matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        is_sing_nom, msg_nom = check_matrix_singularity(nom_matrix, 5)
        assert is_sing_nom is False
        assert msg_nom == ""

        # Zero-flow matrix
        zero_matrix = [[0.0] * 5 for _ in range(5)]
        is_sing_zero, msg_zero = check_matrix_singularity(zero_matrix, 5)
        assert is_sing_zero is True
        assert "Zero-flow deadlock" in msg_zero

        # Disconnected unit 4
        disc_matrix = [row[:] for row in CANONICAL_BASELINE_FLUX_MATRIX]
        for j in range(5):
            disc_matrix[4][j] = 0.0
            disc_matrix[j][4] = 0.0
        is_sing_disc, msg_disc = check_matrix_singularity(disc_matrix, 5)
        assert is_sing_disc is True
        assert "Unit 4" in msg_disc


# ============================================================================
# Section 5: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

class TestSVGCanvasRendering:
    """Verify standalone W3C SVG 1.1 XML generation, ribbon paths, node arcs, labels, and HUD card."""

    def test_svg_generation_and_xml_parsing(self) -> None:
        """Verify SVG output is well-formed XML and conforms to W3C SVG 1.1 specifications."""
        canvas = create_canonical_chord_matrix_canvas()
        svg_str = canvas.render_svg()

        assert svg_str.startswith('<?xml version="1.0" encoding="UTF-8"?>')
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)

    def test_svg_contains_all_structural_components(self) -> None:
        """Verify SVG contains all essential groups, ribbons, arcs, badges, and telemetry HUD."""
        canvas = create_canonical_chord_matrix_canvas()
        svg_str = canvas.render_svg()

        assert 'id="canvas-header"' in svg_str
        assert 'id="chord-diagram"' in svg_str
        assert 'id="golden-baseline-contours"' in svg_str
        assert 'id="live-flow-ribbons"' in svg_str
        assert 'id="flux-direction-arrows"' in svg_str
        assert 'id="unit-arcs"' in svg_str
        assert 'id="telemetry-hud"' in svg_str

    def test_unit_arcs_and_labels_rendered(self) -> None:
        """Verify all 5 refinery units are rendered with arc paths and capacity labels."""
        canvas = create_canonical_chord_matrix_canvas()
        svg_str = canvas.render_svg()

        # Unit arcs
        assert 'id="arc-CDU"' in svg_str
        assert 'id="arc-VDU"' in svg_str
        assert 'id="arc-FCC"' in svg_str
        assert 'id="arc-HCU"' in svg_str
        assert 'id="arc-ALK"' in svg_str

        # Capacity callouts
        assert "350 t/h" in svg_str
        assert "220 t/h" in svg_str
        assert "260 t/h" in svg_str
        assert "240 t/h" in svg_str
        assert "150 t/h" in svg_str

    def test_dual_state_representation_in_svg(self) -> None:
        """Verify dual-state representation: golden baseline contours and real-time live ribbons."""
        canvas = create_canonical_chord_matrix_canvas()
        svg_str = canvas.render_svg()

        assert 'id="base-CDU->VDU"' in svg_str
        assert 'id="live-CDU->VDU"' in svg_str
        assert COLOR_GOLDEN_BASELINE in svg_str
        assert COLOR_LIVE_RIBBON in svg_str

    def test_interactive_chord_selection_and_highlighting(self) -> None:
        """Verify selecting a chord highlights it and updates HUD card."""
        canvas = create_canonical_chord_matrix_canvas()
        canvas.select_chord(0, 1)
        svg_str = canvas.render_svg()

        assert 'class="chord-live chord-selected"' in svg_str
        assert 'CDU → VDU' in svg_str


# ============================================================================
# Section 6: WCAG 2.1 AAA Accessibility & Contrast Targets
# ============================================================================

class TestWCAGContrastCompliance:
    """Verify contrast ratios for SCADA display meet WCAG 2.1 AAA specifications."""

    def test_decoupled_badge_contrast_ratio(self) -> None:
        """Verify decoupled badge contrast ratio exceeds 18:1."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert ratio > 18.0

    def test_dark_theme_text_contrast_ratio(self) -> None:
        """Verify primary text on dark theme backing exceeds 7.0:1 AAA target."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert ratio >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert ratio > 7.0

    def test_scada_graphical_contrast_ratios(self) -> None:
        """Verify SCADA graphical colors on dark backing exceed 3.0:1 target."""
        for color, name in [
            (COLOR_CDU, "CDU Emerald"),
            (COLOR_VDU, "VDU Cyan"),
            (COLOR_FCC, "FCC Amber"),
            (COLOR_HCU, "HCU Lavender"),
            (COLOR_ALK, "ALK Rose"),
            (COLOR_FOCUS_BLUE, "Focus Blue"),
        ]:
            ratio = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
            assert ratio >= WCAG_GRAPHICAL_CONTRAST_TARGET, f"{name} contrast {ratio:.2f} < 3.0"

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """Verify validate_wcag_aaa_contrast helper returns True."""
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0) is True
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, min_contrast=7.0) is True


# ============================================================================
# Section 7: Process Safety Trips & Diagnostics
# ============================================================================

class TestProcessSafetyTrips:
    """Verify process safety trips (0xCA01, 0xCA02, 0xCA03) and coil assertion (%M322, %M323)."""

    def test_nominal_operational_state(self) -> None:
        """Verify nominal canvas state has no safety trips and status code 0x0000."""
        canvas = create_canonical_chord_matrix_canvas()
        assert canvas.flux_trip is False
        assert canvas.reg_table.read_bit("%M322") is False
        assert canvas.reg_table.read_bit("%M323") is True
        assert canvas.diagnostic_code == CHORD_ERR_OK
        assert canvas.diagnostic_code == 0x0000
        assert canvas.reg_table.read_word("%R1387") == 0

    def test_flux_conservation_breach_0xca01(self) -> None:
        """Verify 0xCA01 trip when nodal flux imbalance exceeds 5.0%, asserting coil %M322."""
        canvas = create_canonical_chord_matrix_canvas()
        canvas.trigger_flux_conservation_breach(unit_index=1, delta_t_h=25.0)

        assert canvas.flux_trip is True
        assert canvas.reg_table.read_bit("%M322") is True
        assert canvas.reg_table.read_bit("%M323") is True
        assert canvas.diagnostic_code == CHORD_ERR_FLUX_CONSERVATION_BREACH
        assert canvas.diagnostic_code == 0xCA01
        assert canvas.diagnostic_code == -13823
        assert (DiagnosticCode(canvas.reg_table.read_word("%R1387")) == 0xCA01)
        assert canvas.reg_table.read_word("%R1386") > 50  # Imbalance scaled > 5.0%
        assert bool(canvas.status_bits & ChordMatrixStatusBits.FLUX_CONSERVATION_TRIP)

        # Verify alert badge rendered in SVG
        svg_trip = canvas.render_svg()
        assert 'TRIP ACTIVE [0xCA01]' in svg_trip
        assert 'filter="url(#alert-halo)"' in svg_trip

    def test_matrix_singularity_0xca02(self) -> None:
        """Verify 0xCA02 trip when matrix singularity occurs, asserting %M322."""
        canvas = create_canonical_chord_matrix_canvas()
        canvas.trigger_matrix_singularity()

        assert canvas.flux_trip is True
        assert canvas.reg_table.read_bit("%M322") is True
        assert canvas.diagnostic_code == CHORD_ERR_CIRCULAR_MATRIX_SINGULARITY
        assert canvas.diagnostic_code == 0xCA02
        assert canvas.diagnostic_code == -13822
        assert (DiagnosticCode(canvas.reg_table.read_word("%R1387")) == 0xCA02)
        assert bool(canvas.status_bits & ChordMatrixStatusBits.MATRIX_SINGULARITY_FAULT)

    def test_render_fault_0xca03(self) -> None:
        """Verify 0xCA03 render fault condition latches diagnostic into %R1387."""
        canvas = create_canonical_chord_matrix_canvas()
        canvas.trigger_render_fault()

        assert canvas.diagnostic_code == CHORD_ERR_RENDER_FAULT
        assert canvas.diagnostic_code == 0xCA03
        assert canvas.diagnostic_code == -13821
        assert (DiagnosticCode(canvas.reg_table.read_word("%R1387")) == 0xCA03)
        assert bool(canvas.status_bits & ChordMatrixStatusBits.RENDER_FAULT)

    def test_reset_nominal_restores_clean_state(self) -> None:
        """Verify reset_nominal cleanly restores nominal operational state and clears trips."""
        canvas = create_canonical_chord_matrix_canvas()
        canvas.trigger_flux_conservation_breach()
        assert canvas.flux_trip is True

        canvas.reset_nominal()
        assert canvas.flux_trip is False
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_bit("%M322") is False
        assert canvas.reg_table.read_bit("%M323") is True
        assert canvas.reg_table.read_word("%R1387") == 0


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization & Scan Cycle
# ============================================================================

class TestHornerRegisterSynchronization:
    """Verify memory synchronization for %R1380..%R1387 and %M322..%M323."""

    def test_initial_register_bindings_values(self) -> None:
        """Verify initial register values match W177 specification."""
        canvas = create_canonical_chord_matrix_canvas()
        ctx = create_mock_scan_context(reg_table=canvas.reg_table)
        canvas.execute(ctx)

        reg = canvas.reg_table
        # %R1380: GlobalFluxEfficiencyScoreScaled (>= 950)
        assert reg.read_word("%R1380") >= 950
        # %R1381: ActiveNodesCount (5)
        assert reg.read_word("%R1381") == 5
        # %R1382: SelectedSourceNodeIndex (0)
        assert reg.read_word("%R1382") == 0
        # %R1383: SelectedTargetNodeIndex (1)
        assert reg.read_word("%R1383") == 1
        # %R1384: SelectedChordFluxRateScaled (1420)
        assert reg.read_word("%R1384") == 1420
        # %R1385: RecirculationRatioScaled (185)
        assert reg.read_word("%R1385") == 185
        # %R1386: MaxFluxImbalanceScaled (<= 50)
        assert reg.read_word("%R1386") <= 50
        # %R1387: DiagnosticStatusCode (0)
        assert reg.read_word("%R1387") == 0
        # %M322: ChordFluxTrip (False)
        assert reg.read_bit("%M322") is False
        # %M323: ChordCanvasActive (True)
        assert reg.read_bit("%M323") is True

    def test_privilege_mode_system_on_writes(self) -> None:
        """Verify writes are performed with PrivilegeMode.SYSTEM without raising permission errors."""
        reg_table = RegisterTable()
        canvas = ChordMatrixCanvas(reg_table=reg_table)
        canvas.sync_to_registers()

        assert reg_table.read_word("%R1381") == 5
        assert reg_table.read_bit("%M323") is True

    def test_ilogicunit_protocol_compliance(self) -> None:
        """Verify ILogicUnit contract properties and methods."""
        canvas = create_canonical_chord_matrix_canvas()
        assert isinstance(canvas, ILogicUnit)
        assert canvas.name == "ChordFluxMatrixCanvasSync"
        assert canvas.priority == 88
        assert canvas.is_enabled is True

    def test_discrete_scan_cycle_execution(self) -> None:
        """Verify discrete scan cycle updates registers cleanly."""
        canvas = create_canonical_chord_matrix_canvas()
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)

        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M323") is True

        canvas.step()
        canvas.execute_logic(ctx)
        canvas.reset()
        assert canvas.diagnostic_code == DIAG_EVENT_OK


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestVerificationSuiteIntegration:
    """Verify 9-stage verification suite produces deterministic contract JSON and SVG deliverable."""

    def test_complete_9_stage_verification_suite(self, tmp_path: Path) -> None:
        """Verify run_chord_matrix_canvas_verification runs all 9 stages cleanly."""
        ev_file = tmp_path / "chord_matrix_evidence.json"
        svg_file = tmp_path / "chord_matrix_sample.svg"

        result = run_chord_matrix_canvas_verification(
            output_path=str(ev_file),
            sample_svg_path=str(svg_file),
        )

        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

        # Verify all 9 stages passed
        for t in result["data"]["tests"]:
            assert t["passed"] is True, f"Failed stage {t['stage']}: {t['check']}"

        # Verify deliverables were written
        assert ev_file.exists()
        assert svg_file.exists()
        assert ev_file.stat().st_size > 0
        assert svg_file.stat().st_size > 0

        # Verify JSON content
        with open(ev_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["status"] == "success"
            assert data["data"]["work_package"] == "W177"
            assert data["data"]["gate"] == "Gate G9 / G2"
            assert data["data"]["metrics"]["active_nodes_count"] == 5
            assert data["data"]["metrics"]["active_chords_count"] == 13
            assert data["data"]["metrics"]["recirculation_ratio_pct"] == 18.5
            assert data["data"]["metrics"]["selected_flux_t_h"] == 142.0


# ============================================================================
# Section 10: DiagnosticCode, Math & Edge Cases
# ============================================================================

class TestDiagnosticCodeAndEdgeCases:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and helper branches."""

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        """Verify 16-bit signed vs unsigned equality for DiagnosticCode."""
        code_flux = DiagnosticCode(0xCA01)
        assert code_flux == 0xCA01
        assert code_flux == 51713
        assert code_flux == -13823
        assert int(code_flux) == 51713
        assert hash(code_flux) == hash(51713)
        assert code_flux != "not_an_int"
        assert code_flux != 0x0000

        code_sing = DiagnosticCode(0xCA02)
        assert code_sing == 0xCA02
        assert code_sing == 51714
        assert code_sing == -13822

        code_rend = DiagnosticCode(0xCA03)
        assert code_rend == 0xCA03
        assert code_rend == 51715
        assert code_rend == -13821

    def test_srgb_and_hex_luminance_math(self) -> None:
        """Verify sRGB channel linear conversion and hex luminance."""
        assert abs(srgb_channel_to_linear(0.02) - (0.02 / 12.92)) < 1e-6
        assert abs(srgb_channel_to_linear(0.5) - (((0.5 + 0.055) / 1.055) ** 2.4)) < 1e-6

        # 3-char vs 6-char hex
        lum3 = hex_to_relative_luminance("#FFF")
        lum6 = hex_to_relative_luminance("#FFFFFF")
        assert abs(lum3 - lum6) < 1e-4

        lum_blk3 = hex_to_relative_luminance("#000")
        lum_blk6 = hex_to_relative_luminance("#000000")
        assert abs(lum_blk3 - lum_blk6) < 1e-4

    def test_aliases_and_factory_functions(self) -> None:
        """Verify class aliases and factory functions instantiate properly."""
        c1 = ChordFluxMatrixCanvasSync()
        c2 = InterUnitProcessFluxHmiSync()
        c3 = ChordFluxMatrixEngine()
        c4 = RefineryChordMatrixCanvas()
        c5 = create_canonical_chord_matrix_canvas()
        c6 = create_canonical_chord_matrix()

        for c in (c1, c2, c3, c4, c5, c6):
            assert isinstance(c, ChordMatrixCanvas)

        units = create_canonical_refinery_units()
        assert len(units) == 5
