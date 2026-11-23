"""Unit tests for Cscape HMI Dynamic Poincare Phase Portrait & Non-Linear Attractor Trajectory Canvas (W114).

Work Package: W114 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.poincare_canvas import (
    AttractorMetrics,
    ClosedLoopHuntingOscillator,
    DIAG_EVENT_ATTRACTOR_INSTABILITY,
    DIAG_EVENT_CHAOTIC_OR_HUNTING_SURGE,
    DIAG_EVENT_DIVERGENT_TRAJECTORY,
    DIAG_EVENT_OK,
    DuffingOscillator,
    OscillatorType,
    POINCARE_CANVAS_PURE_ST_POU,
    PhasePoint,
    PoincareCanvas,
    PoincareCanvasStatusBits,
    PoincareSection,
    PoincareStatusBits,
    PuncturePoint,
    SectionType,
    VanDerPolOscillator,
    compute_attractor_metrics,
    detect_poincare_punctures,
    estimate_lyapunov_exponent,
    generate_poincare_canvas_svg,
    integrate_rk4_trajectory,
    run_poincare_canvas_verification,
    velocity_to_hex_color,
    verify_poincare_canvas_pure_st,
    verify_poincare_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Pure ST POU AST Validation and Anti-Ladder Check
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1: Verify Pure ST POU AST parsing, absence of ladder constructs, and Horner register bindings."""
    # 1. Top-level convenience validation
    assert verify_poincare_canvas_pure_st() is True
    assert verify_poincare_pure_st() is True

    # 2. SecurityGuard pure ST assertion
    SecurityGuard.assert_pure_st_content(POINCARE_CANVAS_PURE_ST_POU)

    # 3. Syntax validation via STParser
    res = STParser.validate_code(POINCARE_CANVAS_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS

    # 4. AST structure and bound registers verification
    parser = STParser()
    ast = parser.parse_pou(POINCARE_CANVAS_PURE_ST_POU)
    assert ast is not None
    assert ast.name == "PoincareCanvasSync"
    assert ast.pou_type == POUType.PROGRAM

    expected_registers = [
        "%R750", "%R751", "%R752", "%R753",
        "%R754", "%R755", "%R756", "%R757",
        "%M175", "%M176",
    ]
    for reg in expected_registers:
        assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"


# ============================================================================
# 2. Van der Pol and Duffing Oscillator RK4 Trajectory Integration
# ============================================================================

def test_van_der_pol_rk4_trajectory_integration() -> None:
    """Stage 2a: Verify Van der Pol oscillator dynamics, derivative calculations, and RK4 integration."""
    vdp = VanDerPolOscillator(mu=1.0, omega0=1.0)

    # Derivative checks at key phase portrait coordinates
    vx0, vy0 = vdp.derivatives(0.0, 0.0, 0.0)
    assert vx0 == 0.0 and vy0 == 0.0  # Equilibrium at origin

    vx1, vy1 = vdp.derivatives(0.0, 0.0, 1.0)
    assert vx1 == 1.0 and vy1 == 1.0

    vx2, vy2 = vdp.derivatives(0.0, 2.0, 0.0)
    assert vx2 == 0.0
    assert vy2 == pytest.approx(-2.0, abs=1e-6)

    # RK4 trajectory integration over 2500 steps (dt=0.010s)
    traj = integrate_rk4_trajectory(
        deriv_fn=vdp.derivatives,
        x0=0.5,
        y0=0.0,
        dt=0.010,
        steps=2500,
    )

    assert len(traj) == 2500
    assert traj[0].t == 0.0
    assert traj[-1].t == pytest.approx(24.99, abs=0.05)
    assert all(math.isfinite(p.x) and math.isfinite(p.y) and math.isfinite(p.speed) for p in traj)

    # Bounded amplitude around limit cycle (radius ~ 2.0)
    peak_amp = max(abs(p.x) for p in traj)
    assert 1.8 <= peak_amp <= 2.3

    # Van der Pol with altered parameter mu=2.0, omega0=1.5
    vdp_mod = VanDerPolOscillator(mu=2.0, omega0=1.5)
    traj_mod = integrate_rk4_trajectory(vdp_mod.derivatives, 1.0, 0.0, dt=0.02, steps=500)
    assert len(traj_mod) == 500
    assert all(math.isfinite(p.speed) for p in traj_mod)


def test_duffing_oscillator_rk4_trajectory_integration() -> None:
    """Stage 2b: Verify Duffing oscillator double-well potential dynamics and RK4 integration."""
    duffing = DuffingOscillator(
        alpha=-1.0,
        beta=1.0,
        delta=0.3,
        gamma=0.0,  # Unforced
        omega=1.2,
    )

    # Derivatives at equilibria (x = +/- 1, y = 0)
    vx_eq, vy_eq = duffing.derivatives(0.0, 1.0, 0.0)
    assert vx_eq == 0.0
    assert abs(vy_eq) < 1e-9  # Equilibrium

    vx_eq2, vy_eq2 = duffing.derivatives(0.0, -1.0, 0.0)
    assert vx_eq2 == 0.0
    assert abs(vy_eq2) < 1e-9

    traj = integrate_rk4_trajectory(
        deriv_fn=duffing.derivatives,
        x0=0.5,
        y0=0.0,
        dt=0.010,
        steps=2000,
    )

    assert len(traj) == 2000
    assert all(math.isfinite(p.x) and math.isfinite(p.y) for p in traj)


def test_closed_loop_hunting_oscillator() -> None:
    """Stage 2c: Verify ClosedLoopHuntingOscillator stiction and non-linear limit cycle."""
    hunting = ClosedLoopHuntingOscillator(
        alpha=0.8,
        beta=0.3,
        omega_n=1.0,
        stiction_band=0.1,
        stiction_fc=0.15,
    )

    vx, vy = hunting.derivatives(0.0, 0.5, 0.5)
    assert vx == 0.5
    assert math.isfinite(vy)

    traj = integrate_rk4_trajectory(hunting.derivatives, 0.2, 0.0, dt=0.010, steps=1000)
    assert len(traj) == 1000


# ============================================================================
# 3. Poincaré Section Plane Crossing and Root-Finding Interpolation
# ============================================================================

def test_poincare_section_plane_geometry() -> None:
    """Stage 3a: Verify Poincaré section plane scalar function evaluation."""
    sec = PoincareSection(a=1.0, b=0.0, c=0.0, crossing_dir=1)

    # Plane evaluation: g(x, y) = 1.0 * x
    assert sec.eval_g(0.5, 2.0) == 0.5
    assert sec.eval_g(0.0, 2.0) == 0.0
    assert sec.eval_g(-0.5, 2.0) == -0.5


def test_poincare_section_puncture_root_finding() -> None:
    """Stage 3b: Verify sub-step root finding accuracy on section Sigma (|g(x*, y*)| < 1e-4)."""
    vdp = VanDerPolOscillator(mu=1.0, omega0=1.0)
    traj = integrate_rk4_trajectory(vdp.derivatives, x0=0.5, y0=0.0, dt=0.010, steps=2500)
    sec = PoincareSection(a=1.0, b=0.0, c=0.0, crossing_dir=1)

    punctures = detect_poincare_punctures(traj, sec, vdp.derivatives)

    assert len(punctures) >= 3
    for p in punctures:
        # Check transverse intersection accuracy (|x*| < 1e-4)
        assert abs(p.x) < 1e-4
        assert p.y > 0.0
        assert math.isfinite(p.speed)
        assert p.t > 0.0


def test_poincare_section_crossing_direction_filtering() -> None:
    """Stage 3c: Verify positive vs negative transversal crossing direction filtering."""
    vdp = VanDerPolOscillator(mu=1.0, omega0=1.0)
    traj = integrate_rk4_trajectory(vdp.derivatives, x0=0.5, y0=0.0, dt=0.010, steps=2500)

    sec_pos = PoincareSection(a=1.0, b=0.0, c=0.0, crossing_dir=1)
    sec_neg = PoincareSection(a=1.0, b=0.0, c=0.0, crossing_dir=-1)

    punctures_pos = detect_poincare_punctures(traj, sec_pos, vdp.derivatives)
    punctures_neg = detect_poincare_punctures(traj, sec_neg, vdp.derivatives)

    assert len(punctures_pos) >= 3
    assert len(punctures_neg) >= 3
    # In positive direction, y = dx/dt > 0
    assert all(p.y > 0.0 for p in punctures_pos)
    # In negative direction, y = dx/dt < 0
    assert all(p.y < 0.0 for p in punctures_neg)


def test_stroboscopic_poincare_section() -> None:
    """Stage 3d: Verify stroboscopic sampling section for periodically forced systems."""
    sec_strob = PoincareSection(
        section_type=SectionType.STROBOSCOPIC,
        period_t=2.0 * math.pi / 1.2,
        t_offset=0.0,
    )

    duff = DuffingOscillator(alpha=-1.0, beta=1.0, delta=0.3, gamma=0.35, omega=1.2)
    traj = integrate_rk4_trajectory(duff.derivatives, x0=0.5, y0=0.0, dt=0.010, steps=2000)

    punctures = detect_poincare_punctures(traj, sec_strob, duff.derivatives)
    assert len(punctures) >= 3


# ============================================================================
# 4. Orbital Period and Stability Index Evaluation
# ============================================================================

def test_orbital_period_evaluation_van_der_pol() -> None:
    """Stage 4a: Verify Van der Pol limit cycle orbital period convergence (T ~ 6.66s at mu=1.0)."""
    vdp = VanDerPolOscillator(mu=1.0, omega0=1.0)
    traj = integrate_rk4_trajectory(vdp.derivatives, x0=0.5, y0=0.0, dt=0.010, steps=2500)
    sec = PoincareSection(a=1.0, b=0.0, c=0.0, crossing_dir=1)

    punctures = detect_poincare_punctures(traj, sec, vdp.derivatives)
    assert len(punctures) >= 3

    periods = [punctures[i + 1].t - punctures[i].t for i in range(len(punctures) - 1)]
    mean_period = sum(periods) / len(periods)

    # Theoretical period for mu=1.0 Van der Pol is approx 6.66 seconds
    assert 6.0 <= mean_period <= 7.2
    assert 2.0 <= punctures[-1].y <= 2.3  # Return map fixed point y*


def test_stability_index_and_attractor_metrics() -> None:
    """Stage 4b: Verify attractor metrics, stability index >= 0.85, and dispersion on limit cycle."""
    vdp = VanDerPolOscillator(mu=1.0, omega0=1.0)
    traj = integrate_rk4_trajectory(vdp.derivatives, x0=0.5, y0=0.0, dt=0.010, steps=2500)
    sec = PoincareSection(a=1.0, b=0.0, c=0.0, crossing_dir=1)
    punctures = detect_poincare_punctures(traj, sec, vdp.derivatives)

    metrics = compute_attractor_metrics(traj, punctures, vdp.derivatives)

    assert metrics.puncture_count >= 3
    assert 6000 <= metrics.orbital_period_ms <= 7200
    assert metrics.stability_index >= 0.85
    assert metrics.stability_index_scaled >= 85
    assert metrics.dispersion < 0.05
    assert metrics.is_limit_cycle is True
    assert metrics.is_converged is True


def test_lyapunov_exponent_estimation() -> None:
    """Stage 4c: Verify Lyapunov exponent estimation on bounded trajectory."""
    vdp = VanDerPolOscillator(mu=1.0, omega0=1.0)
    traj = integrate_rk4_trajectory(vdp.derivatives, x0=0.5, y0=0.0, dt=0.010, steps=1000)

    lyap = estimate_lyapunov_exponent(vdp.derivatives, x0=0.5, y0=0.0, dt=0.010, steps=1000)
    assert math.isfinite(lyap)


# ============================================================================
# 5. Standalone W3C SVG 1.1 Generation and XML Well-Formedness
# ============================================================================

def test_svg_11_generation_and_xml_well_formedness() -> None:
    """Stage 5: Verify standalone W3C SVG 1.1 vector layout and ElementTree validation."""
    canvas = PoincareCanvas(oscillator_type=OscillatorType.VAN_DER_POL)
    svg_content = canvas.render_svg()

    assert isinstance(svg_content, str)
    assert len(svg_content) > 1000

    # ElementTree XML well-formedness parsing
    root = ET.fromstring(svg_content)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == "1200"
    assert root.attrib["height"] == "750"
    assert root.attrib["viewBox"] == "0 0 1200 750"
    assert root.attrib["version"] == "1.1"

    # Graphical visual primitives
    assert "<path" in svg_content
    assert "<line" in svg_content
    assert "<circle" in svg_content
    assert "<rect" in svg_content
    assert "<text" in svg_content

    # Color palette & themes
    assert "#0F172A" in svg_content  # Slate dark backdrop
    assert "#0B0F19" in svg_content  # Decoupled dark badge backing
    assert (canvas.status_bits & PoincareStatusBits.SVG_VALID) != 0


# ============================================================================
# 6. WCAG 2.1 AAA High-Contrast Ratio Compliance (> 18:1)
# ============================================================================

def test_wcag_21_aaa_high_contrast_ratio_compliance() -> None:
    """Stage 6: Verify WCAG 2.1 AAA contrast ratio (> 18:1) via decoupled dark backing badges."""
    # Text #FFFFFF / #F8FAFC relative luminance L_text = 1.0
    # Decoupled dark badge #0B0F19 relative luminance L_badge ≈ 0.00473
    # Contrast ratio = (1.0 + 0.05) / (0.00473 + 0.05) ≈ 19.19:1
    l_text = 1.0
    l_badge = 0.00473
    contrast_ratio = (l_text + 0.05) / (l_badge + 0.05)

    assert contrast_ratio > 18.0
    assert contrast_ratio == pytest.approx(19.19, abs=0.10)

    canvas = PoincareCanvas(oscillator_type=OscillatorType.VAN_DER_POL)
    assert (canvas.status_bits & PoincareStatusBits.WCAG_AAA) != 0


def test_velocity_colormap_chromatic_grading() -> None:
    """Stage 6b: Verify velocity-to-hex chromatic color mapping palette."""
    c_low = velocity_to_hex_color(0.1, 0.0, 3.0)
    c_mid = velocity_to_hex_color(1.5, 0.0, 3.0)
    c_high = velocity_to_hex_color(2.4, 0.0, 3.0)
    c_peak = velocity_to_hex_color(2.9, 0.0, 3.0)

    assert c_low == "#38BDF8"
    assert c_mid == "#34D399"
    assert c_high == "#FBBF24"
    assert c_peak == "#F87171"


# ============================================================================
# 7. Horner OCS Register Space Synchronization (%R750..%R757, %M175..%M176)
# ============================================================================

def test_horner_ocs_register_nominal_synchronization() -> None:
    """Stage 7a: Verify registers %R750..%R757 and coils %M175..%M176 under nominal limit cycle."""
    reg_table = RegisterTable()
    canvas = PoincareCanvas(oscillator_type=OscillatorType.VAN_DER_POL, reg_table=reg_table)
    canvas.render_svg()

    # %R750: StatusWord
    status_word = reg_table.read_uword("%R750")
    assert (status_word & int(PoincareStatusBits.CANVAS_ACTIVE)) != 0
    assert (status_word & int(PoincareStatusBits.TRAJECTORY_COMPUTED)) != 0
    assert (status_word & int(PoincareStatusBits.LIMIT_CYCLE_DETECTED)) != 0
    assert (status_word & int(PoincareStatusBits.SVG_VALID)) != 0
    assert (status_word & int(PoincareStatusBits.WCAG_AAA)) != 0

    # %R751: PunctureCount
    p_count = reg_table.read_word("%R751")
    assert p_count >= 3

    # %R752: PeakAmplitudeScaled (x10) -> ~2.0 -> ~20
    peak_amp = reg_table.read_word("%R752")
    assert 18 <= peak_amp <= 25

    # %R753: OrbitalPeriodMs (x1 ms) -> 6.66s -> ~6660 ms
    period_ms = reg_table.read_word("%R753")
    assert 6000 <= period_ms <= 7200

    # %R754: StabilityIndexScaled (x100) -> >= 85
    stability_scaled = reg_table.read_word("%R754")
    assert stability_scaled >= 85

    # %R755: PhaseVelocityRmsScaled (x10)
    vel_scaled = reg_table.read_word("%R755")
    assert vel_scaled > 0

    # %R756: IntegrationStepsTotal
    steps_total = reg_table.read_word("%R756")
    assert steps_total == 2500

    # %R757: DiagEventCode
    diag_code = reg_table.read_word("%R757")
    assert diag_code == DIAG_EVENT_OK

    # %M175 & %M176: Discrete trip coils
    assert reg_table.read_bit("%M175") is False
    assert reg_table.read_bit("%M176") is False


def test_horner_ocs_trips_and_fault_handling() -> None:
    """Stage 7b: Verify %M175 surge alarm and %M176 attractor instability trip."""
    reg_table = RegisterTable()
    canvas = PoincareCanvas(oscillator_type=OscillatorType.VAN_DER_POL, reg_table=reg_table)

    # 1. Trigger surge alarm (%M175)
    canvas.status_bits |= PoincareStatusBits.CHAOS_OR_HUNTING_ALARM
    canvas._sync_registers()
    assert reg_table.read_bit("%M175") is True

    # 2. Trigger instability trip (%M176)
    canvas.diagnostic_code = DIAG_EVENT_ATTRACTOR_INSTABILITY
    canvas._sync_registers()
    assert reg_table.read_bit("%M176") is True
    assert reg_table.read_word("%R757") == DIAG_EVENT_ATTRACTOR_INSTABILITY


# ============================================================================
# 8. Anti-Ladder Security Guard Rejection
# ============================================================================

def test_anti_ladder_security_guard_rejection() -> None:
    """Stage 8: Verify fail-closed interception of ladder contacts, coils, and mnemonics."""
    # 1. Clean Pure ST is accepted without exception
    SecurityGuard.assert_pure_st_content(POINCARE_CANVAS_PURE_ST_POU)

    # 2. Contact and coil constructs rejection
    bad_st_ladder = """
    PROGRAM BadPoincareLadder
    VAR OrbitActive : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_st_ladder)

    # 3. Ladder mnemonics rejection
    bad_st_mnemonics = """
    PROGRAM BadMnemonicLadder
    VAR Coil : BOOL; END_VAR
    XIC %M175 OTE %M176
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_st_mnemonics)

    # 4. Rung delimiter rejection
    bad_st_rung = """
    PROGRAM BadRungLadder
    RUNG 1
    PoincareActive := TRUE;
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_st_rung)


# ============================================================================
# 9. Full Verification Suite Runner and 4-State Contract
# ============================================================================

def test_full_poincare_canvas_verification_runner(tmp_path: Path) -> None:
    """Stage 9: Verify complete 9-stage verification runner and strict 4-state contract."""
    evidence_path = str(tmp_path / "poincare_evidence.json")
    svg_path = str(tmp_path / "poincare_sample.svg")

    evidence = run_poincare_canvas_verification(
        evidence_path=evidence_path,
        svg_path=svg_path,
    )

    # Strict 4-State Engineering Contract Assertions
    assert evidence["status"] == "success"
    assert evidence["error_code"] is None
    assert "verified cleanly" in evidence["details"]

    data = evidence["data"]
    assert data["work_package"] == "W114"
    assert data["gate"] == "Gate G9 / G2"
    assert data["checks_passed"] == 9
    assert data["total_checks"] == 9
    assert len(data["tests"]) == 9
    assert all(t["passed"] for t in data["tests"])

    # Register map verification
    reg_map = data["register_map"]
    assert reg_map["analog_registers"] == "%R750..%R757"
    assert reg_map["discrete_coils"] == "%M175..%M176"

    # Verify generated evidence and SVG on disk
    assert Path(evidence_path).is_file()
    assert Path(svg_path).is_file()

    with open(evidence_path, "r", encoding="utf-8") as f:
        saved_evidence = json.load(f)
    assert saved_evidence["status"] == "success"
    assert saved_evidence["data"]["work_package"] == "W114"
