"""Comprehensive pytest test suite for Cscape HMI Dynamic Ternary Phase Diagram SCADA Canvas (W243).

Work Package: Wave W243 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Ternary Phase Diagram Canvas]

Covers 130 deterministic unit tests across 13 Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2. TestTernaryCoordinateTransformation: Gibbs coordinate transformation, A+B+C = 1.0 normalization, Cartesian (X,Y) mapping, inverse mapping.
3. TestBinodalCurveAndTieLines: Binodal curve spline points, tie line calculations, lever rule phase split fractions.
4. TestTwoPhaseEnvelopeDetection: Inside vs outside binodal region classification, %M477 two-phase split alarm assertion.
5. TestOperatingPointValidation: Component sum violation 0xF701 detection, non-negative fractions.
6. TestCanvasGeometryAndLayout: Equilateral triangle dimensions, 1200x750 viewport, gridlines.
7. TestSVGGenerationAndXMLSyntax: Standalone W3C SVG 1.1 generation, ElementTree XML validation, <polygon>, <path>, <line> tags.
8. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1.
9. TestHornerOCSSynchronizationAndRegisters: %R2040..%R2047 and %M476..%M477 bit-exact synchronization, PrivilegeMode.SYSTEM.
10. TestPureSTAndSecurity: STParser & SecurityGuard verification of TernaryPhaseCanvasSync POU.
11. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
12. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
13. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.ternary_phase_canvas import (
    BINODAL_INTERPOLATION_ERROR,
    BINODAL_INTERPOLATION_FAULT,
    CANVAS_OVERFLOW,
    CANVAS_OVERFLOW_FAULT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CLOSURE_TOLERANCE_PCT,
    COIL_ALARM_ACTIVE,
    COIL_CANVAS_ACTIVE,
    COIL_SPLIT_ALARM,
    COIL_TERNARY_ACTIVE,
    COIL_TERNARY_CANVAS_ACTIVE,
    COIL_TWO_PHASE_ALARM,
    COIL_TWO_PHASE_SPLIT_ALARM,
    COLOR_AMBER,
    COLOR_BORDER,
    COLOR_COMPONENT_A,
    COLOR_COMPONENT_B,
    COLOR_COMPONENT_C,
    COLOR_CRIMSON,
    COLOR_CYAN,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_EMERALD,
    COLOR_FRAME_LINE,
    COLOR_GRID_LINE,
    COLOR_PANEL_BG,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COMPONENT_SUM_VIOLATION,
    COMPONENT_SUM_VIOLATION_FAULT,
    DIAG_ERR_BINODAL_INTERPOLATION_ERROR,
    DIAG_ERR_CANVAS_OVERFLOW,
    DIAG_ERR_COMPONENT_SUM_VIOLATION,
    DIAG_ERR_GEOMETRY_DEGENERACY,
    DIAG_EVENT_OK,
    DIAG_OK,
    GEOMETRY_DEGENERACY,
    GEOMETRY_DEGENERACY_FAULT,
    NOMINAL_COMP_A_PCT,
    NOMINAL_COMP_B_PCT,
    NOMINAL_COMP_C_PCT,
    NOMINAL_DIAGNOSTIC_CODE,
    NOMINAL_DISTRIBUTION_COEFF,
    NOMINAL_DISTRIBUTION_COEFF_SCALED,
    NOMINAL_OPERATING_POINT_X_SCALED,
    NOMINAL_OPERATING_POINT_Y_SCALED,
    NOMINAL_OPERATING_POINT_Z_SCALED,
    NOMINAL_PHASE_EQUILIBRIUM_STATE,
    NOMINAL_TIE_LINE_SLOPE,
    NOMINAL_TIE_LINE_SLOPE_SCALED,
    NOMINAL_TWO_PHASE_ENVELOPE_TIE_LINES,
    REG_ACTIVE_TIE_LINES,
    REG_COMP_A_SCALED,
    REG_COMP_B_SCALED,
    REG_COMP_C_SCALED,
    REG_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DIAG_CODE,
    REG_DISTRIBUTION_COEFF_SCALED,
    REG_EQUILIBRIUM_STATE,
    REG_K_D_SCALED,
    REG_OPERATING_POINT_X_SCALED,
    REG_OPERATING_POINT_Y_SCALED,
    REG_OPERATING_POINT_Z_SCALED,
    REG_OP_POINT_X_SCALED,
    REG_OP_POINT_Y_SCALED,
    REG_OP_POINT_Z_SCALED,
    REG_PHASE_EQUILIBRIUM_STATE,
    REG_SLOPE_SCALED,
    REG_TIE_LINES_COUNT,
    REG_TIE_LINE_SLOPE_SCALED,
    REG_TWO_PHASE_ENVELOPE_TIE_LINES,
    STANDARD_TRIANGLE_VERTICES,
    TERNARY_OK,
    TERNARY_PHASE_CANVAS_PURE_ST_POU,
    TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU,
    TERNARY_PHASE_OK,
    TRIANGLE_BASE_WIDTH,
    TRIANGLE_HEIGHT,
    VERTEX_A,
    VERTEX_B,
    VERTEX_C,
    W243_TERNARY_PHASE_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    BinodalEnvelope,
    BinodalInterpolationError,
    BinodalNode,
    CanvasOverflowError,
    ComponentSumViolationError,
    DiagnosticCode,
    GeometryDegeneracyError,
    PhaseEquilibriumState,
    PhaseState,
    TernaryDiagnosticCode,
    TernaryPhaseCanvas,
    TernaryPhaseCanvasDiagnosticCode,
    TernaryPhaseCanvasEngine,
    TernaryPhaseCanvasError,
    TernaryPhaseCanvasStatusBits,
    TernaryPhaseCanvasSync,
    TernaryPhaseDiagnosticCode,
    TernaryPhaseMetrics,
    TernaryPhaseStatusBits,
    TernaryStatusBits,
    TieLine,
    build_canonical_binodal_envelope,
    calculate_contrast_ratio,
    cartesian_2d_to_ternary,
    check_coordinate_closure,
    create_canonical_ternary_phase_canvas,
    generate_smooth_bezier_spline_path,
    generate_ternary_phase_canvas_svg,
    is_point_in_triangle,
    is_point_inside_polygon,
    normalize_composition,
    relative_luminance,
    run_ternary_phase_canvas_verification,
    srgb_channel_to_linear,
    ternary_to_cartesian_2d,
    validate_wcag_aaa_contrast,
    verify_ternary_phase_canvas_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, registers, and coils."""

    def test_diagnostic_code_signed_unsigned_equality_ok(self) -> None:
        diag = DiagnosticCode(0x0000)
        assert diag == 0
        assert diag == 0x0000
        assert diag == DIAG_EVENT_OK
        assert diag == DIAG_OK
        assert diag == TERNARY_OK
        assert diag == TERNARY_PHASE_OK

    def test_diagnostic_code_signed_unsigned_equality_0xf701(self) -> None:
        diag = DiagnosticCode(0xF701)
        assert diag == 0xF701
        assert diag == -2303  # 0xF701 as signed int16
        assert diag == DIAG_ERR_COMPONENT_SUM_VIOLATION
        assert diag == COMPONENT_SUM_VIOLATION
        assert diag == COMPONENT_SUM_VIOLATION_FAULT

    def test_diagnostic_code_signed_unsigned_equality_0xf702(self) -> None:
        diag = DiagnosticCode(0xF702)
        assert diag == 0xF702
        assert diag == -2302  # 0xF702 as signed int16
        assert diag == DIAG_ERR_GEOMETRY_DEGENERACY
        assert diag == GEOMETRY_DEGENERACY
        assert diag == GEOMETRY_DEGENERACY_FAULT

    def test_diagnostic_code_signed_unsigned_equality_0xf703(self) -> None:
        diag = DiagnosticCode(0xF703)
        assert diag == 0xF703
        assert diag == -2301  # 0xF703 as signed int16
        assert diag == DIAG_ERR_BINODAL_INTERPOLATION_ERROR
        assert diag == BINODAL_INTERPOLATION_ERROR
        assert diag == BINODAL_INTERPOLATION_FAULT

    def test_diagnostic_code_signed_unsigned_equality_0xf704(self) -> None:
        diag = DiagnosticCode(0xF704)
        assert diag == 0xF704
        assert diag == -2300  # 0xF704 as signed int16
        assert diag == DIAG_ERR_CANVAS_OVERFLOW
        assert diag == CANVAS_OVERFLOW
        assert diag == CANVAS_OVERFLOW_FAULT

    def test_diagnostic_code_hashing(self) -> None:
        d1 = DiagnosticCode(0xF701)
        d2 = DiagnosticCode(0xF701)
        assert hash(d1) == hash(d2)
        diag_map = {d1: "sum_violation"}
        assert diag_map[d2] == "sum_violation"

    def test_diagnostic_code_non_int_comparison(self) -> None:
        diag = DiagnosticCode(0xF701)
        assert diag != "0xF701"
        assert diag is not None

    def test_phase_equilibrium_state_enum(self) -> None:
        assert PhaseEquilibriumState.SINGLE_PHASE == 1
        assert PhaseEquilibriumState.TWO_PHASE_SPLIT == 2
        assert PhaseEquilibriumState.PLAIT_POINT == 3

    def test_phase_state_enum(self) -> None:
        assert PhaseState.SINGLE_PHASE == 1
        assert PhaseState.TWO_PHASE_SPLIT == 2
        assert PhaseState.PLAIT_POINT == 3

    def test_status_bits_values(self) -> None:
        assert TernaryPhaseStatusBits.NOMINAL_OPERATION == 1
        assert TernaryPhaseStatusBits.CANVAS_ACTIVE == 2
        assert TernaryPhaseStatusBits.TWO_PHASE_SPLIT_ALARM == 4
        assert TernaryPhaseStatusBits.SINGLE_PHASE_STATE == 8
        assert TernaryPhaseStatusBits.TWO_PHASE_STATE == 16
        assert TernaryPhaseStatusBits.PLAIT_POINT_STATE == 32
        assert TernaryPhaseStatusBits.COMPONENT_SUM_FAULT == 64
        assert TernaryPhaseStatusBits.GEOMETRY_DEGENERACY_FAULT == 128
        assert TernaryPhaseStatusBits.BINODAL_INTERPOLATION_FAULT == 256
        assert TernaryPhaseStatusBits.CANVAS_OVERFLOW_FAULT == 512
        assert TernaryPhaseStatusBits.SPLINE_COMPUTED == 1024
        assert TernaryPhaseStatusBits.SVG_VALID == 2048
        assert TernaryPhaseStatusBits.WCAG_AAA_VERIFIED == 4096
        assert TernaryStatusBits == TernaryPhaseStatusBits
        assert TernaryPhaseCanvasStatusBits == TernaryPhaseStatusBits

    def test_register_address_constants(self) -> None:
        assert REG_OPERATING_POINT_X_SCALED == "%R2040"
        assert REG_OPERATING_POINT_Y_SCALED == "%R2041"
        assert REG_OPERATING_POINT_Z_SCALED == "%R2042"
        assert REG_TWO_PHASE_ENVELOPE_TIE_LINES == "%R2043"
        assert REG_PHASE_EQUILIBRIUM_STATE == "%R2044"
        assert REG_TIE_LINE_SLOPE_SCALED == "%R2045"
        assert REG_DISTRIBUTION_COEFF_SCALED == "%R2046"
        assert REG_DIAGNOSTIC_CODE == "%R2047"
        assert REG_OP_POINT_X_SCALED == "%R2040"
        assert REG_COMP_A_SCALED == "%R2040"
        assert REG_TIE_LINES_COUNT == "%R2043"
        assert REG_EQUILIBRIUM_STATE == "%R2044"
        assert REG_SLOPE_SCALED == "%R2045"
        assert REG_K_D_SCALED == "%R2046"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2047"

    def test_coil_address_constants(self) -> None:
        assert COIL_TERNARY_CANVAS_ACTIVE == "%M476"
        assert COIL_TWO_PHASE_SPLIT_ALARM == "%M477"
        assert COIL_CANVAS_ACTIVE == "%M476"
        assert COIL_TERNARY_ACTIVE == "%M476"
        assert COIL_SPLIT_ALARM == "%M477"
        assert COIL_TWO_PHASE_ALARM == "%M477"
        assert COIL_ALARM_ACTIVE == "%M477"

    def test_exception_hierarchy(self) -> None:
        assert issubclass(ComponentSumViolationError, TernaryPhaseCanvasError)
        assert issubclass(GeometryDegeneracyError, TernaryPhaseCanvasError)
        assert issubclass(BinodalInterpolationError, TernaryPhaseCanvasError)
        assert issubclass(CanvasOverflowError, TernaryPhaseCanvasError)
        assert issubclass(TernaryPhaseCanvasError, Exception)

    def test_nominal_constant_values(self) -> None:
        assert NOMINAL_COMP_A_PCT == 45.00
        assert NOMINAL_COMP_B_PCT == 35.00
        assert NOMINAL_COMP_C_PCT == 20.00
        assert NOMINAL_OPERATING_POINT_X_SCALED == 4500
        assert NOMINAL_OPERATING_POINT_Y_SCALED == 3500
        assert NOMINAL_OPERATING_POINT_Z_SCALED == 2000
        assert NOMINAL_TWO_PHASE_ENVELOPE_TIE_LINES == 5
        assert NOMINAL_PHASE_EQUILIBRIUM_STATE == 1
        assert NOMINAL_TIE_LINE_SLOPE_SCALED == -125
        assert NOMINAL_DISTRIBUTION_COEFF_SCALED == 1450
        assert CLOSURE_TOLERANCE_PCT == 0.05


# ============================================================================
# 2. TestTernaryCoordinateTransformation
# ============================================================================

class TestTernaryCoordinateTransformation:
    """Validate Gibbs coordinate transformation, A+B+C = 1.0 normalization, Cartesian (X,Y) and inverse mapping."""

    def test_normalize_composition_nominal(self) -> None:
        na, nb, nc = normalize_composition(45.0, 35.0, 20.0)
        assert pytest.approx(na, 1e-4) == 45.0
        assert pytest.approx(nb, 1e-4) == 35.0
        assert pytest.approx(nc, 1e-4) == 20.0
        assert pytest.approx(na + nb + nc, 1e-4) == 100.0

    def test_normalize_composition_scaling_100(self) -> None:
        na, nb, nc = normalize_composition(4500.0, 3500.0, 2000.0)
        assert pytest.approx(na, 1e-4) == 45.0
        assert pytest.approx(nb, 1e-4) == 35.0
        assert pytest.approx(nc, 1e-4) == 20.0

    def test_normalize_composition_clamp_negatives(self) -> None:
        na, nb, nc = normalize_composition(-10.0, 40.0, 60.0)
        assert pytest.approx(na, 1e-4) == 0.0
        assert pytest.approx(nb, 1e-4) == 40.0
        assert pytest.approx(nc, 1e-4) == 60.0

    def test_normalize_composition_zero_sum(self) -> None:
        na, nb, nc = normalize_composition(0.0, 0.0, 0.0)
        assert pytest.approx(na, 1e-4) == 100.0 / 3.0
        assert pytest.approx(nb, 1e-4) == 100.0 / 3.0
        assert pytest.approx(nc, 1e-4) == 100.0 / 3.0

    def test_check_coordinate_closure_exact(self) -> None:
        assert check_coordinate_closure(45.0, 35.0, 20.0) is True

    def test_check_coordinate_closure_within_tolerance(self) -> None:
        assert check_coordinate_closure(45.02, 35.0, 20.0, tolerance_pct=0.05) is True
        assert check_coordinate_closure(44.98, 35.0, 20.0, tolerance_pct=0.05) is True

    def test_check_coordinate_closure_breach(self) -> None:
        assert check_coordinate_closure(45.10, 35.0, 20.0, tolerance_pct=0.05) is False

    def test_ternary_to_cartesian_vertices(self) -> None:
        pa = ternary_to_cartesian_2d(100.0, 0.0, 0.0)
        pb = ternary_to_cartesian_2d(0.0, 100.0, 0.0)
        pc = ternary_to_cartesian_2d(0.0, 0.0, 100.0)
        assert math.hypot(pa[0] - VERTEX_A[0], pa[1] - VERTEX_A[1]) < 1e-4
        assert math.hypot(pb[0] - VERTEX_B[0], pb[1] - VERTEX_B[1]) < 1e-4
        assert math.hypot(pc[0] - VERTEX_C[0], pc[1] - VERTEX_C[1]) < 1e-4

    def test_cartesian_to_ternary_vertices(self) -> None:
        ta = cartesian_2d_to_ternary(VERTEX_A[0], VERTEX_A[1])
        tb = cartesian_2d_to_ternary(VERTEX_B[0], VERTEX_B[1])
        tc = cartesian_2d_to_ternary(VERTEX_C[0], VERTEX_C[1])
        assert pytest.approx(ta[0], 1e-4) == 100.0
        assert pytest.approx(ta[1], 1e-4) == 0.0
        assert pytest.approx(ta[2], 1e-4) == 0.0
        assert pytest.approx(tb[0], 1e-4) == 0.0
        assert pytest.approx(tb[1], 1e-4) == 100.0
        assert pytest.approx(tb[2], 1e-4) == 0.0
        assert pytest.approx(tc[0], 1e-4) == 0.0
        assert pytest.approx(tc[1], 1e-4) == 0.0
        assert pytest.approx(tc[2], 1e-4) == 100.0

    def test_round_trip_transformation_multiple_points(self) -> None:
        test_points = [
            (45.0, 35.0, 20.0),
            (30.0, 20.0, 50.0),
            (10.0, 70.0, 20.0),
            (42.0, 40.0, 18.0),
            (33.333, 33.333, 33.334),
            (10.0, 10.0, 80.0),
            (80.0, 10.0, 10.0),
        ]
        for a, b, c in test_points:
            x, y = ternary_to_cartesian_2d(a, b, c)
            ra, rb, rc = cartesian_2d_to_ternary(x, y)
            assert pytest.approx(ra, 1e-3) == a
            assert pytest.approx(rb, 1e-3) == b
            assert pytest.approx(rc, 1e-3) == c


# ============================================================================
# 3. TestBinodalCurveAndTieLines
# ============================================================================

class TestBinodalCurveAndTieLines:
    """Validate binodal curve spline points, tie line calculations, and lever rule phase split fractions."""

    def test_canonical_binodal_envelope_structure(self) -> None:
        env = build_canonical_binodal_envelope()
        assert isinstance(env, BinodalEnvelope)
        assert len(env.nodes) == 13
        assert len(env.tie_lines) == 5
        assert env.critical_node.is_critical is True
        assert len(env.path_d) > 0

    def test_binodal_nodes_count_and_order(self) -> None:
        env = build_canonical_binodal_envelope()
        names = [n.name for n in env.nodes]
        assert names[0] == "R0"
        assert names[5] == "R5"
        assert names[6] == "PlaitPoint_Crit"
        assert names[7] == "E5"
        assert names[12] == "E0"

    def test_plait_critical_point_properties(self) -> None:
        env = build_canonical_binodal_envelope()
        cp = env.critical_node
        assert pytest.approx(cp.comp_a_pct, 1e-4) == 42.0
        assert pytest.approx(cp.comp_b_pct, 1e-4) == 40.0
        assert pytest.approx(cp.comp_c_pct, 1e-4) == 18.0
        assert pytest.approx(cp.comp_a_pct + cp.comp_b_pct + cp.comp_c_pct, 1e-4) == 100.0

    def test_tie_lines_count_and_indices(self) -> None:
        env = build_canonical_binodal_envelope()
        indices = [tl.index for tl in env.tie_lines]
        assert indices == [1, 2, 3, 4, 5]

    def test_tie_lines_geometry_lengths(self) -> None:
        env = build_canonical_binodal_envelope()
        for tl in env.tie_lines:
            length = math.hypot(tl.extract.x_px - tl.raffinate.x_px, tl.extract.y_px - tl.raffinate.y_px)
            assert length > 50.0

    def test_tie_line_slopes_negative(self) -> None:
        env = build_canonical_binodal_envelope()
        for tl in env.tie_lines:
            assert tl.slope < 0.0

    def test_tie_line_3_nominal_properties(self) -> None:
        env = build_canonical_binodal_envelope()
        tl3 = env.tie_lines[2]  # Index 3
        assert tl3.index == 3
        assert pytest.approx(tl3.slope, 1e-2) == -1.25
        assert tl3.slope_scaled == -125
        assert pytest.approx(tl3.distribution_coeff, 1e-2) == 1.450
        assert tl3.distribution_coeff_scaled == 1450

    def test_smooth_bezier_spline_path_format(self) -> None:
        env = build_canonical_binodal_envelope()
        assert env.path_d.startswith("M ")
        assert " C " in env.path_d
        assert env.path_d.endswith(" Z")

    def test_smooth_bezier_spline_short_points(self) -> None:
        assert generate_smooth_bezier_spline_path([]) == ""
        assert generate_smooth_bezier_spline_path([(0.0, 0.0)]) == ""
        p2 = generate_smooth_bezier_spline_path([(0.0, 0.0), (10.0, 10.0)])
        assert p2 == "M 0.00,0.00 L 10.00,10.00"

    def test_tie_lines_raffinate_and_extract_endpoints(self) -> None:
        env = build_canonical_binodal_envelope()
        for tl in env.tie_lines:
            assert tl.raffinate.x_px < tl.extract.x_px


# ============================================================================
# 4. TestTwoPhaseEnvelopeDetection
# ============================================================================

class TestTwoPhaseEnvelopeDetection:
    """Validate inside vs outside binodal region classification and %M477 two-phase split alarm."""

    def test_nominal_point_outside_envelope(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        assert canvas.two_phase_split_alarm is False
        assert canvas.phase_equilibrium_state == PhaseEquilibriumState.SINGLE_PHASE

    def test_point_above_plait_point_outside(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.set_compositions(45.0, 30.0, 25.0)  # C=25% > 18% plait point
        assert canvas.two_phase_split_alarm is False
        assert canvas.phase_equilibrium_state == PhaseEquilibriumState.SINGLE_PHASE

    def test_two_phase_point_inside_envelope(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.set_compositions(35.0, 55.0, 10.0)
        assert canvas.two_phase_split_alarm is True
        assert canvas.phase_equilibrium_state == PhaseEquilibriumState.TWO_PHASE_SPLIT

    def test_canvas_trigger_two_phase_split_sets_alarm(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        assert canvas.two_phase_split_alarm is False
        canvas.trigger_two_phase_split()
        assert canvas.two_phase_split_alarm is True

    def test_canvas_two_phase_split_sets_m477_coil(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_two_phase_split()
        assert canvas.reg_table.read_bit(COIL_TWO_PHASE_SPLIT_ALARM) is True

    def test_canvas_two_phase_split_sets_state_2(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_two_phase_split()
        assert canvas.phase_equilibrium_state == PhaseEquilibriumState.TWO_PHASE_SPLIT
        assert canvas.phase_equilibrium_state == 2

    def test_canvas_two_phase_split_sets_r2044(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_two_phase_split()
        r2044 = canvas.reg_table.read_word(REG_PHASE_EQUILIBRIUM_STATE)
        assert r2044 == 2

    def test_canvas_recovery_reset_clears_m477(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_two_phase_split()
        assert canvas.reg_table.read_bit(COIL_TWO_PHASE_SPLIT_ALARM) is True
        canvas.reset_nominal()
        assert canvas.reg_table.read_bit(COIL_TWO_PHASE_SPLIT_ALARM) is False

    def test_canvas_recovery_restores_state_1(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_two_phase_split()
        assert canvas.reg_table.read_word(REG_PHASE_EQUILIBRIUM_STATE) == 2
        canvas.reset_nominal()
        assert canvas.reg_table.read_word(REG_PHASE_EQUILIBRIUM_STATE) == 1

    def test_is_point_inside_polygon_ray_casting(self) -> None:
        diamond = [(5.0, 0.0), (10.0, 5.0), (5.0, 10.0), (0.0, 5.0)]
        assert is_point_inside_polygon(5.0, 5.0, diamond) is True
        assert is_point_inside_polygon(15.0, 5.0, diamond) is False
        assert is_point_inside_polygon(-1.0, 5.0, diamond) is False


# ============================================================================
# 5. TestOperatingPointValidation
# ============================================================================

class TestOperatingPointValidation:
    """Validate component sum violation 0xF701 detection, non-negative fractions, and fault handling."""

    def test_component_sum_violation_trigger(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_component_sum_violation()
        assert canvas.diagnostic_code == DIAG_ERR_COMPONENT_SUM_VIOLATION
        assert canvas.diagnostic_code == 0xF701

    def test_sum_violation_updates_r2047(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_component_sum_violation()
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF
        assert reg_val == 0xF701

    def test_sum_violation_clears_two_phase_alarm(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_component_sum_violation()
        # DiagnosticCode is 0xF701, so two_phase_split_alarm is active due to fault
        assert canvas.diagnostic_code == DIAG_ERR_COMPONENT_SUM_VIOLATION
        # When resetting nominal, alarm and diagnostic clear cleanly
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.two_phase_split_alarm is False
        assert canvas.reg_table.read_bit(COIL_TWO_PHASE_SPLIT_ALARM) is False

    def test_geometry_degeneracy_trigger(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_geometry_degeneracy()
        assert canvas.diagnostic_code == DIAG_ERR_GEOMETRY_DEGENERACY
        assert canvas.diagnostic_code == 0xF702

    def test_geometry_degeneracy_updates_r2047(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_geometry_degeneracy()
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF
        assert reg_val == 0xF702

    def test_binodal_interpolation_error_trigger(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_binodal_interpolation_error()
        assert canvas.diagnostic_code == DIAG_ERR_BINODAL_INTERPOLATION_ERROR
        assert canvas.diagnostic_code == 0xF703

    def test_binodal_interpolation_error_updates_r2047(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_binodal_interpolation_error()
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF
        assert reg_val == 0xF703

    def test_canvas_overflow_trigger(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_canvas_overflow()
        assert canvas.diagnostic_code == DIAG_ERR_CANVAS_OVERFLOW
        assert canvas.diagnostic_code == 0xF704

    def test_canvas_overflow_updates_r2047(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_canvas_overflow()
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF
        assert reg_val == 0xF704

    def test_reset_nominal_restores_ok_diagnostic(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_component_sum_violation()
        assert canvas.diagnostic_code != DIAG_EVENT_OK
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000


# ============================================================================
# 6. TestCanvasGeometryAndLayout
# ============================================================================

class TestCanvasGeometryAndLayout:
    """Validate equilateral triangle dimensions, 1200x750 viewport, and gridlines."""

    def test_viewport_dimensions(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 1200
        assert CANVAS_VIEWPORT_HEIGHT == 750

    def test_triangle_base_width_and_height(self) -> None:
        assert TRIANGLE_BASE_WIDTH == 800.0
        assert TRIANGLE_HEIGHT == 580.0

    def test_triangle_vertices(self) -> None:
        assert VERTEX_A == (600.0, 100.0)
        assert VERTEX_B == (200.0, 680.0)
        assert VERTEX_C == (1000.0, 680.0)
        assert STANDARD_TRIANGLE_VERTICES == (VERTEX_A, VERTEX_B, VERTEX_C)

    def test_apex_centered_over_base(self) -> None:
        assert VERTEX_A[0] == (VERTEX_B[0] + VERTEX_C[0]) / 2.0 == 600.0

    def test_base_horizontal(self) -> None:
        assert VERTEX_B[1] == VERTEX_C[1] == 680.0

    def test_is_point_in_triangle_inside_and_outside(self) -> None:
        # Centroid of triangle
        cx = (VERTEX_A[0] + VERTEX_B[0] + VERTEX_C[0]) / 3.0
        cy = (VERTEX_A[1] + VERTEX_B[1] + VERTEX_C[1]) / 3.0
        assert is_point_in_triangle(cx, cy) is True
        assert is_point_in_triangle(100.0, 100.0) is False
        assert is_point_in_triangle(1100.0, 700.0) is False

    def test_scada_color_constants(self) -> None:
        assert COLOR_DARK_THEME_BACKING == "#0B0F19"
        assert COLOR_PANEL_BG == "#161B22"
        assert COLOR_BORDER == "#21262D"
        assert COLOR_DECOUPLED_BADGE == "#050811"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_TEXT_MUTED == "#8B949E"
        assert COLOR_GRID_LINE == "#21262D"
        assert COLOR_FRAME_LINE == "#475569"

    def test_component_colors(self) -> None:
        assert COLOR_COMPONENT_A == "#3B82F6"  # Water Sky Blue
        assert COLOR_COMPONENT_B == "#8B5CF6"  # Carrier Solvent Mint
        assert COLOR_COMPONENT_C == "#EAB308"  # Solute Warm Amber

    def test_gridline_fractions(self) -> None:
        fractions = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
        assert len(fractions) == 9
        for f in fractions:
            p = ternary_to_cartesian_2d(f * 100.0, (1.0 - f) * 100.0, 0.0)
            assert 200.0 <= p[0] <= 1000.0
            assert 100.0 <= p[1] <= 680.0

    def test_status_palette_colors(self) -> None:
        assert COLOR_EMERALD == "#10B981"
        assert COLOR_AMBER == "#F59E0B"
        assert COLOR_CRIMSON == "#EF4444"
        assert COLOR_CYAN == "#06B6D4"


# ============================================================================
# 7. TestSVGGenerationAndXMLSyntax
# ============================================================================

class TestSVGGenerationAndXMLSyntax:
    """Validate standalone W3C SVG 1.1 generation, ElementTree XML validation, <polygon>, <path>, <line> tags."""

    def test_svg_xml_well_formed_elementtree(self) -> None:
        svg_xml = generate_ternary_phase_canvas_svg()
        root = ET.fromstring(svg_xml)
        assert root is not None

    def test_svg_root_tag_and_dimensions(self) -> None:
        svg_xml = generate_ternary_phase_canvas_svg()
        root = ET.fromstring(svg_xml)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"
        assert root.attrib["viewBox"] == "0 0 1200 750"

    def test_svg_contains_polygon_frame(self) -> None:
        svg_xml = generate_ternary_phase_canvas_svg()
        root = ET.fromstring(svg_xml)
        polygons = root.findall(".//{http://www.w3.org/2000/svg}polygon")
        assert len(polygons) == 1
        points = polygons[0].attrib.get("points", "")
        assert "600.0,100.0" in points

    def test_svg_contains_binodal_envelope_path(self) -> None:
        svg_xml = generate_ternary_phase_canvas_svg()
        root = ET.fromstring(svg_xml)
        paths = root.findall(".//{http://www.w3.org/2000/svg}path")
        assert len(paths) >= 1
        assert any("M" in p.attrib.get("d", "") and "Z" in p.attrib.get("d", "") for p in paths)

    def test_svg_contains_5_tie_lines(self) -> None:
        svg_xml = generate_ternary_phase_canvas_svg()
        root = ET.fromstring(svg_xml)
        lines = root.findall(".//{http://www.w3.org/2000/svg}line")
        assert len(lines) >= 5
        assert 'id="equilibrium-tie-lines"' in svg_xml

    def test_svg_contains_operating_point_marker(self) -> None:
        svg_xml = generate_ternary_phase_canvas_svg()
        assert 'id="operating-point-marker"' in svg_xml

    def test_svg_contains_hud_card(self) -> None:
        svg_xml = generate_ternary_phase_canvas_svg()
        assert 'id="scada-telemetry-hud"' in svg_xml

    def test_svg_reflects_alarm_state_color(self) -> None:
        svg_alarm = generate_ternary_phase_canvas_svg(two_phase_split_alarm=True)
        assert COLOR_CRIMSON in svg_alarm
        assert "ALARM" in svg_alarm

    def test_svg_reflects_diagnostic_fault_color(self) -> None:
        svg_fault = generate_ternary_phase_canvas_svg(diagnostic_code=DIAG_ERR_COMPONENT_SUM_VIOLATION)
        assert "0xF701" in svg_fault

    def test_svg_reflects_nominal_state_color(self) -> None:
        svg_nom = generate_ternary_phase_canvas_svg(
            comp_a_pct=45.0,
            comp_b_pct=35.0,
            comp_c_pct=20.0,
            two_phase_split_alarm=False,
            diagnostic_code=DIAG_EVENT_OK,
        )
        assert COLOR_EMERALD in svg_nom
        assert "SINGLE-PHASE" in svg_nom or "NOMINAL" in svg_nom


# ============================================================================
# 8. TestWCAG21AAAContrastAndVisualLegibility
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Validate WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1."""

    def test_srgb_channel_to_linear_low_and_high(self) -> None:
        assert srgb_channel_to_linear(0) == 0.0
        assert srgb_channel_to_linear(10) == pytest.approx((10.0 / 255.0) / 12.92, 1e-6)
        assert srgb_channel_to_linear(255) == 1.0

    def test_relative_luminance_black_and_white(self) -> None:
        assert relative_luminance("#000000") == pytest.approx(0.0, 1e-6)
        assert relative_luminance("#FFFFFF") == pytest.approx(1.0, 1e-6)

    def test_contrast_ratio_black_white_is_21(self) -> None:
        cr = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert pytest.approx(cr, 1e-3) == 21.0

    def test_contrast_ratio_identical_colors_is_1(self) -> None:
        cr = calculate_contrast_ratio("#123456", "#123456")
        assert pytest.approx(cr, 1e-4) == 1.0

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        badge_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert badge_cr >= 18.0
        assert badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET

    def test_text_contrast_on_dark_backing_exceeds_7_to_1(self) -> None:
        text_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert text_cr >= 7.0
        assert text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET

    def test_panel_bg_contrast_ratio(self) -> None:
        panel_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_PANEL_BG)
        assert panel_cr >= 7.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        is_compliant, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_compliant is True
        assert text_cr >= 7.0
        assert badge_cr >= 18.0

    def test_wcag_targets_constants(self) -> None:
        assert WCAG_AAA_BADGE_CONTRAST_TARGET == 18.0
        assert WCAG_AAA_TEXT_CONTRAST_TARGET == 7.0
        assert WCAG_GRAPHICAL_CONTRAST_TARGET == 3.0

    def test_3_digit_hex_expansion(self) -> None:
        lum_short = relative_luminance("#FFF")
        lum_full = relative_luminance("#FFFFFF")
        assert pytest.approx(lum_short, 1e-6) == lum_full


# ============================================================================
# 9. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate %R2040..%R2047 and %M476..%M477 bit-exact synchronization, PrivilegeMode.SYSTEM."""

    def test_initial_register_synchronization(self) -> None:
        reg_table = RegisterTable()
        canvas = TernaryPhaseCanvas(reg_table=reg_table)
        assert (reg_table.read_word(REG_OPERATING_POINT_X_SCALED) & 0xFFFF) == 4500
        assert (reg_table.read_word(REG_OPERATING_POINT_Y_SCALED) & 0xFFFF) == 3500
        assert (reg_table.read_word(REG_OPERATING_POINT_Z_SCALED) & 0xFFFF) == 2000
        assert (reg_table.read_word(REG_TWO_PHASE_ENVELOPE_TIE_LINES) & 0xFFFF) == 5
        assert (reg_table.read_word(REG_PHASE_EQUILIBRIUM_STATE) & 0xFFFF) == 1
        assert reg_table.read_word(REG_TIE_LINE_SLOPE_SCALED) == -125
        assert (reg_table.read_word(REG_DISTRIBUTION_COEFF_SCALED) & 0xFFFF) == 1450
        assert (reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0
        assert reg_table.read_bit(COIL_TERNARY_CANVAS_ACTIVE) is True
        assert reg_table.read_bit(COIL_TWO_PHASE_SPLIT_ALARM) is False

    def test_r2040_comp_a_scaled(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.set_compositions(50.0, 30.0, 20.0)
        assert canvas.reg_table.read_word(REG_OPERATING_POINT_X_SCALED) == 5000

    def test_r2041_comp_b_scaled(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.set_compositions(50.0, 30.0, 20.0)
        assert canvas.reg_table.read_word(REG_OPERATING_POINT_Y_SCALED) == 3000

    def test_r2042_comp_c_scaled(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.set_compositions(50.0, 30.0, 20.0)
        assert canvas.reg_table.read_word(REG_OPERATING_POINT_Z_SCALED) == 2000

    def test_r2043_tie_lines_count(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        r2043 = canvas.reg_table.read_word(REG_TWO_PHASE_ENVELOPE_TIE_LINES)
        assert r2043 == 5

    def test_r2044_phase_state_scaled(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        r2044 = canvas.reg_table.read_word(REG_PHASE_EQUILIBRIUM_STATE)
        assert r2044 == 1

    def test_r2045_slope_scaled(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        assert canvas.reg_table.read_word(REG_TIE_LINE_SLOPE_SCALED) == -125

    def test_r2046_distribution_coeff_scaled(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        assert canvas.reg_table.read_word(REG_DISTRIBUTION_COEFF_SCALED) == 1450

    def test_r2047_diagnostic_code_signed_handling(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_component_sum_violation()
        raw_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE)
        assert (raw_val & 0xFFFF) == 0xF701

    def test_coils_m476_m477_states(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        assert canvas.reg_table.read_bit(COIL_TERNARY_CANVAS_ACTIVE) is True
        assert canvas.reg_table.read_bit(COIL_TWO_PHASE_SPLIT_ALARM) is False
        canvas.trigger_two_phase_split()
        assert canvas.reg_table.read_bit(COIL_TWO_PHASE_SPLIT_ALARM) is True


# ============================================================================
# 10. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate STParser & SecurityGuard verification of TernaryPhaseCanvasSync POU."""

    def test_pure_st_content_passes_security_guard(self) -> None:
        SecurityGuard.assert_pure_st_content(TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU)

    def test_st_parser_validates_pou_structure(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "TernaryPhaseCanvasSync"

    def test_pou_name_is_ternary_phase_canvas_sync(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU)
        assert pou.name == "TernaryPhaseCanvasSync"

    def test_pou_type_is_program(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU)
        assert pou.pou_type == POUType.PROGRAM

    def test_pou_has_10_variables(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU)
        assert len(pou.variables) == 10

    def test_pou_variable_address_bindings_all_exact(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU)
        expected = {
            "OperatingPointXScaled": "%R2040",
            "OperatingPointYScaled": "%R2041",
            "OperatingPointZScaled": "%R2042",
            "TwoPhaseEnvelopeTieLines": "%R2043",
            "PhaseEquilibriumState": "%R2044",
            "TieLineSlopeScaled": "%R2045",
            "DistributionCoeffScaled": "%R2046",
            "DiagnosticCode": "%R2047",
            "TernaryCanvasActive": "%M476",
            "TwoPhaseSplitAlarm": "%M477",
        }
        actual = {v.name: v.address_binding for v in pou.variables}
        for k, v in expected.items():
            assert actual[k] == v

    def test_pou_variable_data_types(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU)
        vtypes = {v.name: v.data_type for v in pou.variables}
        for k, dt in vtypes.items():
            if k in ("TernaryCanvasActive", "TwoPhaseSplitAlarm"):
                assert dt == "BOOL"
            else:
                assert dt == "INT"

    def test_pou_st_logic_branching(self) -> None:
        assert "IF TernaryCanvasActive THEN" in TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU
        assert "IF PhaseEquilibriumState = 2 OR DiagnosticCode <> 0 THEN" in TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU
        assert "END_PROGRAM" in TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU

    def test_verify_ternary_phase_canvas_pure_st_function(self) -> None:
        assert verify_ternary_phase_canvas_pure_st() is True

    def test_pure_st_pou_string_constants_aliases(self) -> None:
        assert TERNARY_PHASE_CANVAS_PURE_ST_POU == TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU
        assert W243_TERNARY_PHASE_PURE_ST_POU == TERNARY_PHASE_CANVAS_SYNC_PURE_ST_POU


# ============================================================================
# 11. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate rejection of 6+ ladder constructs with LadderForbiddenError."""

    def test_reject_normally_open_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---[ ]---")

    def test_reject_normally_closed_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---[/]---")

    def test_reject_normal_coil(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---( )---")

    def test_reject_negated_coil(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---(/)---")

    def test_reject_rung_keyword(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: XIC %M476 OTE %M477")

    def test_reject_network_keyword(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 10: LD %R2040")

    def test_reject_mnemonic_xic(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC StartBit")

    def test_reject_mnemonic_ote(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("OTE SplitAlarm")


# ============================================================================
# 12. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate scan_step, step, execute, reset, and 100-cycle soak stability."""

    def test_ilogicunit_interface_properties(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        assert isinstance(canvas, ILogicUnit)
        assert canvas.name == "TernaryPhaseCanvas"
        assert canvas.priority == 10
        assert canvas.is_enabled is True

    def test_scan_step_recomputes_and_syncs(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.scan_step(dt=0.01)
        assert canvas.reg_table.read_bit(COIL_TERNARY_CANVAS_ACTIVE) is True

    def test_step_alias_invokes_scan_step(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.step()
        assert canvas.is_enabled is True

    def test_execute_logic_with_scan_context(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        canvas.execute(ctx)
        assert canvas.ternary_canvas_active is True

    def test_reset_restores_nominal(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.trigger_component_sum_violation()
        assert canvas.diagnostic_code != DIAG_EVENT_OK
        canvas.reset()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.comp_a_pct == NOMINAL_COMP_A_PCT

    def test_canvas_inactive_when_m476_false(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        canvas.reg_table.write_bit(COIL_TERNARY_CANVAS_ACTIVE, False, privilege=PrivilegeMode.SYSTEM)
        canvas.sync_from_registers()
        assert canvas.ternary_canvas_active is False

    def test_100_cycle_soak_stability(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        init_a = canvas.comp_a_pct
        init_b = canvas.comp_b_pct
        init_c = canvas.comp_c_pct
        init_ties = canvas.two_phase_envelope_tie_lines

        for _ in range(100):
            canvas.scan_step(dt=0.01)

        assert canvas.comp_a_pct == init_a
        assert canvas.comp_b_pct == init_b
        assert canvas.comp_c_pct == init_c
        assert canvas.two_phase_envelope_tie_lines == init_ties
        assert not math.isnan(canvas.comp_a_pct)
        assert not math.isnan(canvas.comp_b_pct)
        assert not math.isnan(canvas.comp_c_pct)

    def test_metrics_property_snapshot(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        metrics = canvas.metrics
        assert isinstance(metrics, TernaryPhaseMetrics)
        assert metrics.comp_a_pct == NOMINAL_COMP_A_PCT
        assert metrics.two_phase_envelope_tie_lines == 5

    def test_factory_create_canonical_instance(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        assert isinstance(canvas, TernaryPhaseCanvas)
        assert canvas.name == "TernaryPhaseCanvas"

    def test_render_svg_method_on_instance(self) -> None:
        canvas = create_canonical_ternary_phase_canvas()
        svg_xml = canvas.render_svg()
        assert svg_xml.startswith("<svg")
        assert svg_xml.endswith("</svg>")


# ============================================================================
# 13. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage runner export and strict 4-state contract validation."""

    def test_runner_returns_strict_4_state_contract(self) -> None:
        result = run_ternary_phase_canvas_verification()
        assert "status" in result
        assert "error_code" in result
        assert "details" in result
        assert "data" in result
        assert result["status"] in ("success", "failed", "blocked", "inconclusive")

    def test_runner_success_status(self) -> None:
        result = run_ternary_phase_canvas_verification()
        assert result["status"] == "success"

    def test_runner_error_code_is_none_on_success(self) -> None:
        result = run_ternary_phase_canvas_verification()
        assert result["error_code"] is None

    def test_runner_details_string_contains_stages(self) -> None:
        result = run_ternary_phase_canvas_verification()
        assert "9/9 stages passed" in result["details"]

    def test_runner_data_contains_expected_fields(self) -> None:
        result = run_ternary_phase_canvas_verification()
        data = result["data"]
        assert data["work_package"] == "W243"
        assert data["gate"] in ("Gate G9 / G2", "Gate G9 / Gate G2")
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9

    def test_runner_all_9_stages_pass(self) -> None:
        result = run_ternary_phase_canvas_verification()
        tests = result["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True, f"Stage {t['stage']} failed: {t['check']}"

    def test_runner_evidence_file_exported(self) -> None:
        result = run_ternary_phase_canvas_verification()
        evidence_file = Path("artifacts/HMI/ternary_phase_canvas_evidence.json")
        assert evidence_file.exists()
        evidence_data = json.loads(evidence_file.read_text(encoding="utf-8"))
        assert evidence_data["status"] == "success"

    def test_runner_sample_svg_file_exported(self) -> None:
        result = run_ternary_phase_canvas_verification()
        svg_file = Path("artifacts/HMI/ternary_phase_canvas_sample.svg")
        assert svg_file.exists()
        svg_content = svg_file.read_text(encoding="utf-8")
        assert svg_content.startswith("<svg")

    def test_runner_custom_output_paths(self, tmp_path: Path) -> None:
        custom_ev = tmp_path / "custom_evidence.json"
        custom_svg = tmp_path / "custom_sample.svg"
        result = run_ternary_phase_canvas_verification(
            output_path=custom_ev,
            sample_svg_path=custom_svg,
            work_package="W243_TEST",
        )
        assert result["status"] == "success"
        assert custom_ev.exists()
        assert custom_svg.exists()

    def test_runner_metrics_reported(self) -> None:
        result = run_ternary_phase_canvas_verification()
        metrics = result["data"]["metrics"]
        assert metrics["operating_point_x_scaled"] == 4500
        assert metrics["operating_point_y_scaled"] == 3500
        assert metrics["operating_point_z_scaled"] == 2000
        assert metrics["two_phase_envelope_tie_lines"] == 5
        assert metrics["wcag_badge_contrast"] >= 18.0
        assert metrics["wcag_text_contrast"] >= 7.0
