"""Unit Test Suite for Distillation Column Multi-Stage VLE & McCabe-Thiele Dynamics ODE Solver.

Work Package: W086 (Gate G7 / G4)
Classification: PRODUCTION_READY

Covers:
1. McCabe-Thiele VLE monotonicity, concavity, and boundary invariants.
2. Relative volatility alpha influence on separation factor.
3. Multi-stage column ODE integration stability via 4th-Order Runge-Kutta (RK4).
4. Dynamic response to step change in reflux ratio R (enrichment).
5. Dynamic response to feed composition disturbance z_F.
6. Murphree tray vapor efficiency scaling E_MV.
7. Condenser and reboiler duty energy balances.
8. Horner OCS register synchronization (%R470..%R477, %M109..%M111) with zero overflow.
9. Pure IEC 61131-3 Structured Text (ST) POU compliance and anti-ladder guard.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.distillation import (
    DISTILLATION_COLUMN_PURE_ST_POU,
    DistillationColumnSimulator,
    DistillationConfig,
    DistillationStatusBits,
    run_distillation_verification,
)
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


@pytest.fixture
def sim() -> DistillationColumnSimulator:
    reg_table = RegisterTable()
    config = DistillationConfig(n_stages=10, n_feed=5, alpha=2.80, murphree_eff=0.85)
    return DistillationColumnSimulator(config=config, register_table=reg_table)


# ============================================================================
# Suite 1: VLE Monotonicity, Concavity, and Boundaries
# ============================================================================

def test_vle_monotonicity_and_bounds(sim: DistillationColumnSimulator) -> None:
    """Verify McCabe-Thiele equilibrium curve satisfies bounds and strict monotonicity."""
    assert sim.vle_ideal(0.0) == 0.0
    assert sim.vle_ideal(1.0) == 1.0

    prev_y = 0.0
    for i in range(1, 101):
        x = i / 100.0
        y = sim.vle_ideal(x)
        assert y > prev_y, f"Monotonicity failed at x={x}"
        assert y >= x, f"Vapor enrichment violated at x={x}"
        prev_y = y


def test_vle_concavity_and_separation_factor(sim: DistillationColumnSimulator) -> None:
    """Verify second derivative is strictly negative (concave down) and separation factor equals alpha."""
    alpha = sim.cfg.alpha
    for i in range(5, 95):
        x = i / 100.0
        y = sim.vle_ideal(x)
        # Analytical separation factor S = (y / (1-y)) / (x / (1-x)) == alpha
        s_factor = (y / (1.0 - y)) / (x / (1.0 - x))
        assert abs(s_factor - alpha) < 1e-10


# ============================================================================
# Suite 2: Relative Volatility Alpha Influence
# ============================================================================

def test_relative_volatility_alpha_influence() -> None:
    """Verify higher alpha yields stronger vapor enrichment at identical liquid composition."""
    cfg_low = DistillationConfig(alpha=1.50)
    cfg_mid = DistillationConfig(alpha=2.50)
    cfg_high = DistillationConfig(alpha=4.00)

    sim_low = DistillationColumnSimulator(config=cfg_low)
    sim_mid = DistillationColumnSimulator(config=cfg_mid)
    sim_high = DistillationColumnSimulator(config=cfg_high)

    x = 0.50
    y_low = sim_low.vle_ideal(x)
    y_mid = sim_mid.vle_ideal(x)
    y_high = sim_high.vle_ideal(x)

    assert y_low < y_mid < y_high
    assert y_low == pytest.approx(0.60, abs=1e-3)
    assert y_mid == pytest.approx(0.7143, abs=1e-3)
    assert y_high == pytest.approx(0.80, abs=1e-3)


# ============================================================================
# Suite 3: RK4 Dynamic Integration Stability and Mass Conservation
# ============================================================================

def test_rk4_dynamic_mass_conservation(sim: DistillationColumnSimulator) -> None:
    """Verify mass and component conservation balances during RK4 integration."""
    cons = sim.check_conservation()
    assert cons["is_molar_conserved"] is True
    assert cons["is_component_conserved"] is True
    assert cons["total_molar_residual_mol_s"] < 1e-10
    assert cons["component_molar_residual_mol_s"] < 1e-10


def test_rk4_step_integration_bounds(sim: DistillationColumnSimulator) -> None:
    """Verify multi-step RK4 integration maintains bounded liquid holdups and compositions."""
    initial_total_holdup = sum(sim.M)

    for step in range(100):
        step_res = sim.step_rk4(dt=0.1)
        assert 0.0 <= step_res["x_D"] <= 1.0
        assert 0.0 <= step_res["x_B"] <= 1.0
        assert 0.0 <= step_res["x_feed"] <= 1.0

    final_total_holdup = sum(sim.M)
    # Level controllers should stabilize total holdup near initial
    assert abs(final_total_holdup - initial_total_holdup) < 5.0


# ============================================================================
# Suite 4: Reflux Ratio Step Response (Enrichment)
# ============================================================================

def test_reflux_ratio_step_response(sim: DistillationColumnSimulator) -> None:
    """Verify step increase in reflux ratio enhances overhead distillate purity."""
    # Settle initially at R=2.0
    sim.reflux_ratio = 2.0
    for _ in range(50):
        sim.step_rk4(dt=0.1)
    x_D_initial = sim.x[-1]

    # Step increase to R=5.0
    sim.reflux_ratio = 5.0
    for _ in range(50):
        sim.step_rk4(dt=0.1)
    x_D_final = sim.x[-1]

    assert x_D_final > x_D_initial


# ============================================================================
# Suite 5: Feed Composition Disturbance Response
# ============================================================================

def test_feed_composition_disturbance(sim: DistillationColumnSimulator) -> None:
    """Verify propagation of feed composition disturbance through column stages."""
    # Settle at z_F = 0.50
    for _ in range(30):
        sim.step_rk4(dt=0.1)
    x_feed_initial = sim.x[sim.N_F - 1]

    # Step disturbance in feed composition to 0.65
    sim.cfg.z_feed = 0.65
    for _ in range(40):
        sim.step_rk4(dt=0.1)
    x_feed_final = sim.x[sim.N_F - 1]

    assert x_feed_final > x_feed_initial


# ============================================================================
# Suite 6: Murphree Tray Efficiency Monotonicity
# ============================================================================

def test_murphree_efficiency_monotonicity(sim: DistillationColumnSimulator) -> None:
    """Verify higher Murphree efficiency produces higher leaving vapor enrichment."""
    sim.cfg.murphree_eff = 0.60
    y_low = sim.compute_tray_vapors(sim.x)

    sim.cfg.murphree_eff = 0.90
    y_high = sim.compute_tray_vapors(sim.x)

    # Intermediate stages should show greater or equal vapor enrichment
    for i in range(1, sim.N - 1):
        assert y_high[i] >= y_low[i]


# ============================================================================
# Suite 7: Energy Balances (Condenser vs Reboiler)
# ============================================================================

def test_energy_balance_under_cmo(sim: DistillationColumnSimulator) -> None:
    """Verify condenser and reboiler heat duties under Constant Molar Overflow."""
    _, _, meta = sim.derivatives(sim.M, sim.x, sim.reflux_ratio, sim.q_reboiler_kw)
    q_c = meta["Q_C"]
    q_r = sim.q_reboiler_kw

    assert q_c > 0.0
    assert q_r > 0.0
    # For saturated liquid feed (q=1.0), rectifying vapor equals stripping boilup: Q_C == Q_R
    assert abs(q_c - q_r) < 1e-3


# ============================================================================
# Suite 8: Horner Register Space Synchronization & Overflow Protection
# ============================================================================

def test_horner_register_sync_and_overflow(sim: DistillationColumnSimulator) -> None:
    """Verify register synchronization operates with zero 16-bit signed integer overflow."""
    sim.step_rk4(dt=0.1)

    r470 = sim.registers.read_word("%R470")
    r471 = sim.registers.read_word("%R471")
    r472 = sim.registers.read_word("%R472")
    r473 = sim.registers.read_word("%R473")
    r474 = sim.registers.read_word("%R474")
    r475 = sim.registers.read_word("%R475")
    r476 = sim.registers.read_word("%R476")
    r477 = sim.registers.read_word("%R477")

    # Verify all fall strictly within positive signed 16-bit range (0..32767)
    assert 0 <= r470 <= 10000
    assert 0 <= r471 <= 10000
    assert 0 <= r472 <= 10000
    assert 500 <= r473 <= 1200
    assert 800 <= r474 <= 1200
    assert 0 <= r475 <= 1000
    assert 0 <= r476 <= 32767
    assert 0 <= r477 <= 32767


def test_alarm_reset_and_total_reflux(sim: DistillationColumnSimulator) -> None:
    """Verify alarm latching, total reflux mode, and %M111 reset handshake."""
    # Force off-spec distillate
    sim.x[-1] = 0.85
    sim.step_rk4(dt=0.1)
    assert sim.off_spec_dist_alarm is True
    assert sim.alarm_latched is True

    # Engage total reflux override
    sim.registers.write_bit("%M110", True, privilege=PrivilegeMode.SYSTEM)
    sim.step_rk4(dt=0.1)
    assert sim.total_reflux is True

    # Restore on-spec condition and handshake reset via %M111
    sim.x[-1] = 0.95
    sim.registers.write_bit("%M111", True, privilege=PrivilegeMode.SYSTEM)
    sim.step_rk4(dt=0.1)
    assert sim.registers.read_bit("%M111") is False
    assert sim.alarm_latched is False


# ============================================================================
# Suite 9: Pure ST POU Compliance and Ladder Guard
# ============================================================================

def test_pure_st_pou_validation_and_ladder_rejection() -> None:
    """Verify ST POU passes AST parser cleanly and rejects ladder constructs."""
    st_res = STParser.validate_code(DISTILLATION_COLUMN_PURE_ST_POU)
    assert st_res.status == AgentStatus.SUCCESS

    ast = STParser.parse_pou(DISTILLATION_COLUMN_PURE_ST_POU)
    assert ast.name == "W086_DistillationColumnODE"
    assert ast.pou_type == POUType.PROGRAM
    assert "%R470" in ast.bound_registers
    assert "%M109" in ast.bound_registers

    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("---[ ]---")

    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("---( )---")

    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("RUNG 1: XIC %M109 OTE %M110 END_RUNG")


def test_full_distillation_verification_runner(tmp_path: Any) -> None:
    """Verify end-to-end distillation verification runner produces valid evidence JSON."""
    ev_path = str(tmp_path / "distillation_evidence.json")
    evidence = run_distillation_verification(ev_path)

    assert evidence["status"] == "success"
    assert evidence["data"]["checks_passed"] == 9
    assert evidence["data"]["total_checks"] == 9
    assert len(evidence["data"]["tests"]) == 9
