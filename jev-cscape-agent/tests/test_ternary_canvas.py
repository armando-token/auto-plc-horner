"""Unit tests for Cscape HMI Dynamic Ternary / Gibbs Triangle Phase Equilibrium Canvas (W129).

Work Package: W129 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.ternary_canvas import (
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ADVISORY_AMBER,
    COLOR_ADVISORY_AMBER_LIGHT,
    COLOR_COMPONENT_A,
    COLOR_COMPONENT_B,
    COLOR_COMPONENT_C,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_LIGHT,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_RED,
    COLOR_TRIP_RED_LIGHT,
    COLOR_TWO_PHASE_FILL,
    COLOR_TWO_PHASE_STROKE,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_BOUNDARY_EXCURSION,
    DIAG_EVENT_COMPOSITION_FAULT,
    DIAG_EVENT_GEOMETRY_DEGENERACY,
    DIAG_EVENT_OK,
    DIAG_EVENT_PHASE_BOUNDARY_TRIP,
    DIAG_EVENT_PHASE_EXCURSION,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    OperationalState,
    PhaseState,
    STANDARD_TRIANGLE_VERTICES,
    SystemMode,
    TERNARY_PURE_ST_POU,
    TernaryCanvas,
    TernaryComposition,
    TernaryEngine,
    TernaryMetrics,
    TernaryStatusBits,
    TernarySystem,
    TRIANGLE_HEIGHT,
    TRIANGLE_SIDE_LENGTH,
    VERTEX_A,
    VERTEX_B,
    VERTEX_C,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    cartesian_2d_to_gibbs,
    cartesian_to_ternary,
    compute_binodal_curve,
    compute_distance_to_envelope,
    compute_ternary_metrics,
    create_canonical_azeotrope_system,
    create_canonical_eutectic_system,
    create_canonical_extraction_system,
    create_mock_scan_context,
    generate_binodal_svg_path,
    generate_ternary_canvas_svg,
    generate_tie_lines,
    generate_triangle_path,
    gibbs_to_cartesian_2d,
    is_inside_binodal,
    normalize_composition,
    run_ternary_canvas_verification,
    ternary_to_cartesian,
    validate_wcag_aaa_contrast,
    verify_ternary_canvas_pure_st,
    verify_ternary_pure_st,
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
    """Section 1: Verify Pure ST POU AST parsing, symbol binding, and Horner register bindings (%R900..%R907, %M210..%M211)."""
    assert verify_ternary_canvas_pure_st() is True
    assert verify_ternary_pure_st() is True

    # SecurityGuard assertion against ladder logic
    SecurityGuard.assert_pure_st_content(TERNARY_PURE_ST_POU)

    # Syntax validation via STParser
    res = STParser.validate_code(TERNARY_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS

    # AST structure and bound registers verification
    parser = STParser()
    ast = parser.parse_pou(TERNARY_PURE_ST_POU)
    assert ast is not None
    assert ast.name == "TernaryCanvasSync"
    assert ast.pou_type == POUType.PROGRAM

    expected_registers = [
        "%R900", "%R901", "%R902", "%R903",
        "%R904", "%R905", "%R906", "%R907",
        "%M210", "%M211",
    ]
    for reg in expected_registers:
        assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Assertion
# ============================================================================

def test_anti_ladder_security_guard_rejection() -> None:
    """Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, and rungs."""
    bad_snippets = [
        "PROGRAM BadTernary1 VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM BadTernary2 VAR X : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM BadTernary3 VAR X : BOOL; END_VAR XIC %M210; END_PROGRAM",
        "PROGRAM BadTernary4 VAR X : BOOL; END_VAR OTE %M211; END_PROGRAM",
        "PROGRAM BadTernary5 VAR X : BOOL; END_VAR RUNG 1 TernaryActive := TRUE; END_PROGRAM",
        "PROGRAM BadTernary6 VAR X : BOOL; END_VAR NETWORK 1 END_PROGRAM",
    ]
    for snip in bad_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snip)


# ============================================================================
# 3. Section 3: Gibbs Triangular Coordinate Transformation & Sum-to-1 Normalization
# ============================================================================

def test_gibbs_triangular_coordinate_transformation_and_normalization() -> None:
    """Section 3: Verify Gibbs triangular coordinate transformation (a, b, c -> x, y) and sum-to-1 normalization."""
    # 1. Normalization tests
    a_norm, b_norm, c_norm = normalize_composition(0.2, 0.3, 0.5)
    assert math.isclose(a_norm, 0.2, rel_tol=1e-5)
    assert math.isclose(b_norm, 0.3, rel_tol=1e-5)
    assert math.isclose(c_norm, 0.5, rel_tol=1e-5)
    assert math.isclose(a_norm + b_norm + c_norm, 1.0, rel_tol=1e-5)

    # Scaled inputs (e.g. percentages or raw kg)
    a2, b2, c2 = normalize_composition(25.0, 25.0, 50.0)
    assert math.isclose(a2, 0.25, rel_tol=1e-5)
    assert math.isclose(b2, 0.25, rel_tol=1e-5)
    assert math.isclose(c2, 0.50, rel_tol=1e-5)
    assert math.isclose(a2 + b2 + c2, 1.0, rel_tol=1e-5)

    # Degenerate zero input fallback to centroid
    az, bz, cz = normalize_composition(0.0, 0.0, 0.0)
    assert math.isclose(az, 1.0 / 3.0, rel_tol=1e-5)
    assert math.isclose(bz, 1.0 / 3.0, rel_tol=1e-5)
    assert math.isclose(cz, 1.0 / 3.0, rel_tol=1e-5)

    # Negative value clamping
    an, bn, cn = normalize_composition(-5.0, 30.0, 70.0)
    assert math.isclose(an, 0.0, abs_tol=1e-5)
    assert math.isclose(bn, 0.30, rel_tol=1e-5)
    assert math.isclose(cn, 0.70, rel_tol=1e-5)

    # 2. Equilateral triangle geometry checks
    va, vb, vc = STANDARD_TRIANGLE_VERTICES
    # Side lengths must all equal TRIANGLE_SIDE_LENGTH (500.0)
    side_ab = math.hypot(vb[0] - va[0], vb[1] - va[1])
    side_bc = math.hypot(vc[0] - vb[0], vc[1] - vb[1])
    side_ca = math.hypot(va[0] - vc[0], va[1] - vc[1])
    assert math.isclose(side_ab, TRIANGLE_SIDE_LENGTH, rel_tol=1e-5)
    assert math.isclose(side_bc, TRIANGLE_SIDE_LENGTH, rel_tol=1e-5)
    assert math.isclose(side_ca, TRIANGLE_SIDE_LENGTH, rel_tol=1e-5)

    # 3. Barycentric forward transformations at vertices and centroid
    pa = ternary_to_cartesian(1.0, 0.0, 0.0)
    pb = ternary_to_cartesian(0.0, 1.0, 0.0)
    pc = ternary_to_cartesian(0.0, 0.0, 1.0)
    p_cent = ternary_to_cartesian(1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0)

    assert math.isclose(pa[0], va[0], rel_tol=1e-4)
    assert math.isclose(pa[1], va[1], rel_tol=1e-4)
    assert math.isclose(pb[0], vb[0], rel_tol=1e-4)
    assert math.isclose(pb[1], vb[1], rel_tol=1e-4)
    assert math.isclose(pc[0], vc[0], rel_tol=1e-4)
    assert math.isclose(pc[1], vc[1], rel_tol=1e-4)
    assert math.isclose(p_cent[0], CANVAS_CENTER_X, rel_tol=1e-4)
    assert math.isclose(p_cent[1], CANVAS_CENTER_Y, rel_tol=1e-4)

    # 4. Inverse mapping: cartesian_to_ternary
    inv_a = cartesian_to_ternary(va[0], va[1])
    inv_b = cartesian_to_ternary(vb[0], vb[1])
    inv_c = cartesian_to_ternary(vc[0], vc[1])
    inv_cent = cartesian_to_ternary(CANVAS_CENTER_X, CANVAS_CENTER_Y)

    assert math.isclose(inv_a[0], 1.0, abs_tol=1e-4)
    assert math.isclose(inv_a[1], 0.0, abs_tol=1e-4)
    assert math.isclose(inv_a[2], 0.0, abs_tol=1e-4)

    assert math.isclose(inv_b[0], 0.0, abs_tol=1e-4)
    assert math.isclose(inv_b[1], 1.0, abs_tol=1e-4)
    assert math.isclose(inv_b[2], 0.0, abs_tol=1e-4)

    assert math.isclose(inv_c[0], 0.0, abs_tol=1e-4)
    assert math.isclose(inv_c[1], 0.0, abs_tol=1e-4)
    assert math.isclose(inv_c[2], 1.0, abs_tol=1e-4)

    assert math.isclose(inv_cent[0], 1.0 / 3.0, rel_tol=1e-4)
    assert math.isclose(inv_cent[1], 1.0 / 3.0, rel_tol=1e-4)
    assert math.isclose(inv_cent[2], 1.0 / 3.0, rel_tol=1e-4)

    # Arbitrary composition roundtrip
    test_points = [
        (0.60, 0.20, 0.20),
        (0.15, 0.45, 0.40),
        (0.42, 0.38, 0.20),
        (0.10, 0.80, 0.10),
    ]
    for orig_a, orig_b, orig_c in test_points:
        x, y = ternary_to_cartesian(orig_a, orig_b, orig_c)
        ra, rb, rc = cartesian_to_ternary(x, y)
        assert math.isclose(ra, orig_a, abs_tol=1e-4)
        assert math.isclose(rb, orig_b, abs_tol=1e-4)
        assert math.isclose(rc, orig_c, abs_tol=1e-4)

    # 5. Gibbs equilateral coordinate transformation formula (W129 Specification 2):
    # x = 0.5 * (2*b + c) / (a + b + c), y = (sqrt(3)/2) * c / (a + b + c)
    sqrt3_2 = math.sqrt(3.0) / 2.0
    gx_a, gy_a = gibbs_to_cartesian_2d(1.0, 0.0, 0.0)
    assert math.isclose(gx_a, 0.0, abs_tol=1e-6)
    assert math.isclose(gy_a, 0.0, abs_tol=1e-6)

    gx_b, gy_b = gibbs_to_cartesian_2d(0.0, 1.0, 0.0)
    assert math.isclose(gx_b, 1.0, abs_tol=1e-6)
    assert math.isclose(gy_b, 0.0, abs_tol=1e-6)

    gx_c, gy_c = gibbs_to_cartesian_2d(0.0, 0.0, 1.0)
    assert math.isclose(gx_c, 0.5, abs_tol=1e-6)
    assert math.isclose(gy_c, sqrt3_2, abs_tol=1e-6)

    # Roundtrip with cartesian_2d_to_gibbs
    for orig_a, orig_b, orig_c in test_points:
        gx, gy = gibbs_to_cartesian_2d(orig_a, orig_b, orig_c)
        r_a, r_b, r_c = cartesian_2d_to_gibbs(gx, gy)
        assert math.isclose(r_a, orig_a, abs_tol=1e-5)
        assert math.isclose(r_b, orig_b, abs_tol=1e-5)
        assert math.isclose(r_c, orig_c, abs_tol=1e-5)


# ============================================================================
# 4. Section 4: Binodal Curve Calculation, Tie-Line Generation & SVG Rendering
# ============================================================================

def test_binodal_curve_tie_lines_and_svg_path_rendering() -> None:
    """Section 4: Binodal curve calculation, tie-line generation, and SVG path rendering."""
    # 1. Binodal curve calculation
    curve = compute_binodal_curve(num_points=61)
    assert len(curve) == 61

    # Every point strictly conserves sum-to-1
    for pa, pb, pc in curve:
        assert math.isclose(pa + pb + pc, 1.0, rel_tol=1e-5), "Binodal point must strictly sum to 1.0"
        assert pa >= 0.0
        assert pb >= 0.0
        assert pc >= 0.0

    # Apex plait point occurs near the center of the parameter space
    plait_pt = max(curve, key=lambda p: p[0])
    assert math.isclose(plait_pt[0], 0.42, rel_tol=1e-3)
    assert math.isclose(plait_pt[1], 0.38, rel_tol=1e-3)
    assert math.isclose(plait_pt[2], 0.20, rel_tol=1e-3)

    # Endpoints on base
    left_base = curve[0]
    right_base = curve[-1]
    assert math.isclose(left_base[0], 0.02, abs_tol=1e-3)
    assert math.isclose(left_base[1], 0.08, abs_tol=1e-3)
    assert math.isclose(right_base[0], 0.02, abs_tol=1e-3)
    assert math.isclose(right_base[1], 0.82, abs_tol=1e-3)

    # 2. Tie-lines generation
    tie_lines = generate_tie_lines(count=5)
    assert len(tie_lines) == 5
    tlines_custom = generate_tie_lines(count=3)
    assert len(tlines_custom) == 3

    for tl in tie_lines:
        ra, rb, rc = tl.raffinate
        ea, eb, ec = tl.extract
        assert math.isclose(ra + rb + rc, 1.0, rel_tol=1e-5)
        assert math.isclose(ea + eb + ec, 1.0, rel_tol=1e-5)
        # Extract is solute rich, raffinate is carrier rich
        assert eb > rb, "Extract phase must have higher solute B concentration than raffinate"
        assert rc > ec, "Raffinate phase must have higher carrier C concentration than extract"
        assert tl.k_factor > 1.0, "Solute distribution coefficient K must exceed 1.0"

    # 3. SVG path syntax and grammar
    tri_path = generate_triangle_path()
    assert tri_path.startswith("M ")
    assert " L " in tri_path
    assert tri_path.endswith(" Z")
    assert tri_path.count(" L ") == 2

    bin_path = generate_binodal_svg_path(curve)
    assert bin_path.startswith("M ")
    assert " L " in bin_path
    assert bin_path.endswith(" Z")
    assert bin_path.count(" L ") == 60

    # 4. Complete SVG Canvas XML validation
    canvas = TernaryCanvas()
    svg_content = canvas.render_svg()

    parsed_tree = ET.fromstring(svg_content)
    assert parsed_tree.tag == "{http://www.w3.org/2000/svg}svg"
    assert parsed_tree.attrib["width"] == "1200"
    assert parsed_tree.attrib["height"] == "750"

    # Required semantic SVG groups and IDs
    assert COLOR_DARK_THEME_BACKING in svg_content
    assert 'id="diagnostic-hud"' in svg_content
    assert 'id="ternary-triangle-frame"' in svg_content
    assert 'id="ternary-grid-lines"' in svg_content
    assert 'id="binodal-envelope"' in svg_content
    assert 'id="tie-lines"' in svg_content
    assert 'id="operating-point"' in svg_content
    assert 'id="horner-register-space"' in svg_content
    assert 'HORNER OCS REGISTER SPACE' in svg_content


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

    # Contrast ratios
    contrast_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    contrast_dark_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    contrast_1e1e1e_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING_1E1E1E)
    assert contrast_1e1e1e_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
    contrast_1e1e1e_green = calculate_contrast_ratio(COLOR_NOMINAL_GREEN_LIGHT, COLOR_DARK_THEME_BACKING_1E1E1E)
    assert contrast_1e1e1e_green >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert calculate_contrast_ratio("#FFF", "#000") > 20.0
    contrast_green = calculate_contrast_ratio(COLOR_NOMINAL_GREEN_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_amber = calculate_contrast_ratio(COLOR_ADVISORY_AMBER_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_red = calculate_contrast_ratio(COLOR_TRIP_RED_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_comp_a = calculate_contrast_ratio(COLOR_COMPONENT_A, COLOR_DARK_THEME_BACKING)
    contrast_comp_b = calculate_contrast_ratio(COLOR_COMPONENT_B, COLOR_DARK_THEME_BACKING)
    contrast_comp_c = calculate_contrast_ratio(COLOR_COMPONENT_C, COLOR_DARK_THEME_BACKING)

    # Assert WCAG 2.1 AAA targets
    assert contrast_badge >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_badge > 18.0  # Decoupled badge > 18:1
    assert contrast_dark_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_green >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_amber >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_red >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_comp_a >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_comp_b >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_comp_c >= WCAG_GRAPHICAL_CONTRAST_TARGET

    # validate_wcag_aaa_contrast function
    ok, t_cr, g_cr = validate_wcag_aaa_contrast()
    assert ok is True
    assert t_cr >= 7.0
    assert g_cr >= 3.0


# ============================================================================
# 6. Section 6: Phase Boundary Excursion Detection & Distance Calculation
# ============================================================================

def test_phase_boundary_excursion_detection_and_distance_calculation() -> None:
    """Section 6: Phase boundary excursion detection (%M210, code 0x9A01) and distance-to-envelope calculation."""
    # 1. State machine and system mode transitions
    canvas = TernaryCanvas()
    assert canvas.current_mode == SystemMode.LIQUID_LIQUID
    assert canvas.system.components[0] == "Water"
    assert canvas.system.components[1] == "Ethanol"
    assert canvas.system.components[2] == "Toluene"

    # Switch to Solid-Liquid (Crystallization / Eutectic)
    canvas.set_system_mode(SystemMode.SOLID_LIQUID)
    assert canvas.current_mode == SystemMode.SOLID_LIQUID
    assert canvas.system.components[1] == "NaCl"

    # Switch to Vapor-Liquid (Azeotropic Distillation)
    canvas.set_system_mode(SystemMode.VAPOR_LIQUID)
    assert canvas.current_mode == SystemMode.VAPOR_LIQUID
    assert canvas.system.components[0] == "Acetone"

    # Switch back to Liquid-Liquid
    canvas.set_system_mode(SystemMode.LIQUID_LIQUID)
    assert canvas.current_mode == SystemMode.LIQUID_LIQUID

    # 2. Nominal baseline (outside binodal envelope, single phase homogeneous)
    assert canvas.metrics.is_excursion is False
    assert canvas.metrics.phase_state == PhaseState.HOMOGENEOUS
    assert canvas.metrics.distance_to_envelope_px > 0.0
    assert canvas.reg_table.read_bit("%M210") is False
    assert canvas.reg_table.read_bit("%M211") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # 3. Two-phase emulsion excursion detection (%M210, code 0x9A01)
    sys_excursion = create_canonical_extraction_system(excursion=True)
    canvas_excur = TernaryCanvas(system=sys_excursion)

    assert canvas_excur.metrics.is_excursion is True
    assert canvas_excur.metrics.phase_state == PhaseState.TWO_PHASE
    assert canvas_excur.metrics.distance_to_envelope_px < 0.0
    assert canvas_excur.metrics.active_phase_count == 2
    assert canvas_excur.reg_table.read_bit("%M210") is True
    assert canvas_excur.reg_table.read_bit("%M211") is True
    assert canvas_excur.diagnostic_code == DIAG_EVENT_PHASE_EXCURSION
    assert canvas_excur.diagnostic_code == DIAG_EVENT_PHASE_BOUNDARY_TRIP
    assert canvas_excur.diagnostic_code == 0x9A01
    assert bool(canvas_excur.status_bits & TernaryStatusBits.PHASE_EXCURSION_ALARM) is True
    assert bool(canvas_excur.status_bits & TernaryStatusBits.EXCURSION_HIGHLIGHTED) is True
    assert bool(canvas_excur.status_bits & TernaryStatusBits.COMPOSITION_LIMIT_TRIP) is True

    # Check helper functions directly
    assert is_inside_binodal(0.15, 0.45, 0.40) is True
    assert is_inside_binodal(0.60, 0.20, 0.20) is False
    dist_inside = compute_distance_to_envelope(0.15, 0.45, 0.40)
    dist_outside = compute_distance_to_envelope(0.60, 0.20, 0.20)
    assert dist_inside < 0.0, "Inside envelope must produce negative signed distance"
    assert dist_outside > 0.0, "Outside envelope must produce positive signed distance"

    # DiagnosticCode equality and hash checks
    assert DIAG_EVENT_PHASE_EXCURSION == 0x9A01
    assert DIAG_EVENT_PHASE_EXCURSION == -26111  # Signed 16-bit
    assert DIAG_EVENT_COMPOSITION_FAULT == -26110
    assert hash(DIAG_EVENT_PHASE_EXCURSION) == hash(0x9A01)

    # Excursion factories for alternate system modes
    azeo_excur = create_canonical_azeotrope_system(excursion=True)
    assert azeo_excur.operating_point.a == 0.12
    eut_excur = create_canonical_eutectic_system(excursion=True)
    assert eut_excur.operating_point.a == 0.18

    # Operating point update with label and critical distance threshold
    canvas.set_operating_point(0.45, 0.35, 0.20, label="Near Critical")
    assert canvas.system.operating_point.label == "Near Critical"
    canvas.system.critical_distance_px = 50.0  # Threshold exceeds distance to envelope
    canvas.evaluate_equilibrium()
    assert canvas.metrics.phase_state == PhaseState.CRITICAL


# ============================================================================
# 7. Section 7: Horner OCS Register Space Synchronization (%R900..%R907, %M210..%M211)
# ============================================================================

def test_horner_ocs_register_space_synchronization() -> None:
    """Section 7: Horner OCS register space synchronization (%R900..%R907, %M210..%M211) and scan cycle execution."""
    canvas = TernaryCanvas()
    reg = canvas.reg_table

    r900 = reg.read_uword("%R900")
    r901 = reg.read_word("%R901")
    r902 = reg.read_word("%R902")
    r903 = reg.read_word("%R903")
    r904 = reg.read_word("%R904")
    r905 = reg.read_word("%R905")
    r906 = reg.read_word("%R906")
    r907 = reg.read_word("%R907")
    m210 = reg.read_bit("%M210")
    m211 = reg.read_bit("%M211")

    # Status word bit checks
    assert bool(r900 & int(TernaryStatusBits.CANVAS_ACTIVE)) is True
    assert bool(r900 & int(TernaryStatusBits.TERNARY_COMPUTED)) is True
    assert bool(r900 & int(TernaryStatusBits.COMPOSITION_NORMALIZED)) is True
    assert bool(r900 & int(TernaryStatusBits.WCAG_AAA)) is True

    # Register values
    assert r901 == 600      # 60.0% Component A scaled x1000
    assert r902 == 200      # 20.0% Component B scaled x1000
    assert r903 == 200      # 20.0% Component C scaled x1000
    assert r901 + r902 + r903 == 1000  # Strictly sums to 1000 (100.0%)
    assert r904 > 0         # Positive distance margin
    assert r905 == 1        # Single phase homogeneous
    assert r906 == 0        # Mode: 0=LIQUID_LIQUID
    assert r907 == DIAG_EVENT_OK
    assert m210 is False
    assert m211 is False

    # ILogicUnit interface & Scan cycle execution
    assert canvas.name == "TernaryCanvasSync"
    assert canvas.priority == 75
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg)
    canvas.execute(ctx)
    canvas.step()
    canvas.execute_logic(ctx)

    # Injected composition fault trip test (%M211 trip)
    canvas_fault = TernaryCanvas()
    canvas_fault.trigger_fault(DIAG_EVENT_COMPOSITION_FAULT)

    assert canvas_fault.reg_table.read_bit("%M211") is True
    assert canvas_fault.reg_table.read_word("%R907") == DIAG_EVENT_COMPOSITION_FAULT

    # Reset test
    canvas_fault.reset()
    assert canvas_fault.current_mode == SystemMode.LIQUID_LIQUID
    assert canvas_fault.diagnostic_code == DIAG_EVENT_OK
    assert canvas_fault.reg_table.read_bit("%M210") is False
    assert canvas_fault.reg_table.read_bit("%M211") is False


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

def test_run_ternary_canvas_verification_suite(tmp_path: Path) -> None:
    """Section 8: 9-stage verification suite integration test writing evidence JSON and SVG."""
    evidence_file = tmp_path / "ternary_canvas_evidence.json"
    svg_file = tmp_path / "ternary_canvas_sample.svg"

    result = run_ternary_canvas_verification(
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
    assert data["data"]["work_package"] == "W129"
    assert data["data"]["gate"] == "Gate G9 / G2"
    assert data["data"]["register_map"]["analog_registers"] == "%R900..%R907"
    assert data["data"]["register_map"]["discrete_coils"] == "%M210..%M211"

    # Verify SVG file XML validity
    svg_tree = ET.parse(svg_file)
    root = svg_tree.getroot()
    assert root.attrib["width"] == "1200"
    assert root.attrib["height"] == "750"
