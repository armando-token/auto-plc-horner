"""Unit tests for Industrial Multiple-Effect Evaporator & MVR Dynamics ODE Simulation (W104)."""

from __future__ import annotations

import math
import pytest

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.evaporator import (
    EvaporatorDiagnosticCode,
    EvaporatorParams,
    EvaporatorSimulator,
    EvaporatorStatusBits,
    compute_bpe,
    compute_heat_transfer_coeff,
    compute_latent_heat,
    compute_p_sat_water,
    compute_solution_cp,
    compute_solution_density,
    compute_t_sat_water,
    verify_evaporator_pure_st,
)


def test_pure_st_pou_ast() -> None:
    """Stage 1: Verify Pure ST POU AST parsing and absence of ladder constructs."""
    assert verify_evaporator_pure_st() is True


def test_thermodynamic_flash_and_bpe() -> None:
    """Stage 2: Verify BPE and Antoine saturation relations."""
    # BPE at 0% is 0 K
    assert compute_bpe(0.0) == 0.0

    # BPE at 10%: 8.5 * 0.1 + 24.0 * 0.01 = 0.85 + 0.24 = 1.09 K
    assert compute_bpe(0.10) == pytest.approx(1.09, abs=1e-3)

    # BPE at 40%: 8.5 * 0.4 + 24.0 * 0.16 = 3.40 + 3.84 = 7.24 K
    assert compute_bpe(0.40) == pytest.approx(7.24, abs=1e-3)

    # Saturation temperature at atmospheric pressure (101.325 kPa)
    t_sat_101kpa = compute_t_sat_water(101325.0)
    # Should be close to 373.15 K (100 degC)
    assert 372.0 <= t_sat_101kpa <= 374.0

    # Inverse relation: P_sat(T_sat) approx 101325 Pa
    p_rec = compute_p_sat_water(t_sat_101kpa)
    assert p_rec == pytest.approx(101325.0, rel=0.02)


def test_heat_transfer_degradation() -> None:
    """Stage 3: Verify heat transfer coefficient degradation with concentration."""
    u_0 = compute_heat_transfer_coeff(0.0)
    assert u_0 == 2400.0

    u_20 = compute_heat_transfer_coeff(0.20)
    u_40 = compute_heat_transfer_coeff(0.40)

    # U must monotonically decrease with concentration
    assert u_0 > u_20 > u_40 > 500.0


def test_mvr_isentropic_compression() -> None:
    """Stage 4: Verify MVR compressor power and specific energy calculations."""
    sim = EvaporatorSimulator()
    sim.step_rk4(dt=0.01)

    assert sim.compressor_power_w > 0.0
    assert 5.0 <= sim.specific_energy_kwh_per_ton <= 90.0
    assert sim.economy_ratio > 0.0


def test_rk4_dynamic_integration() -> None:
    """Stage 5: Verify RK4 12-state dynamic ODE solver numerical stability."""
    sim = EvaporatorSimulator()
    y_init = sim.get_state_vector()
    assert len(y_init) == 12

    for _ in range(50):
        sim.step_rk4(dt=0.01)

    y_final = sim.get_state_vector()
    assert len(y_final) == 12

    # Check finite physical values
    for val in y_final:
        assert not math.isnan(val)
        assert not math.isinf(val)


def test_thermal_collapse_alarm() -> None:
    """Stage 6: Verify low delta-T thermal collapse alarm tripping (%M152)."""
    sim = EvaporatorSimulator()
    # Normal state: delta-T is healthy
    assert sim.reg_table.read_bit("%M152") is False

    # Force low driving force in Effect 1
    sim.effects[0].temperature = sim.t_steam1 - 1.5  # Delta-T = 1.5 K < 3.0 K
    sim._evaluate_diagnostics_and_sync()

    assert sim.reg_table.read_bit("%M152") is True
    assert bool(sim.status_bits & EvaporatorStatusBits.THERMAL_COLLAPSE_ALARM) is True


def test_salting_risk_trip() -> None:
    """Stage 7: Verify salting crystallization trip (%M151) at high concentration."""
    sim = EvaporatorSimulator()
    assert sim.reg_table.read_bit("%M151") is False

    # Set Effect 3 concentration to 49.0 wt% >= 48.0 wt% limit
    sim.effects[2].conc = 0.49
    sim._evaluate_diagnostics_and_sync()

    assert sim.reg_table.read_bit("%M151") is True
    assert bool(sim.status_bits & EvaporatorStatusBits.SALTING_RISK_TRIP) is True
    assert sim.diagnostic_code == EvaporatorDiagnosticCode.ERR_SALTING_OVER_CONC


def test_level_high_alarm() -> None:
    """Stage 8: Verify liquid level overfill trip (%M153)."""
    sim = EvaporatorSimulator()
    assert sim.reg_table.read_bit("%M153") is False

    # Overfill Effect 2: 2.40 m^3 in 2.50 m^3 vessel = 96.0% >= 92%
    sim.effects[1].volume = 2.40
    sim._evaluate_diagnostics_and_sync()

    assert sim.reg_table.read_bit("%M153") is True
    assert bool(sim.status_bits & EvaporatorStatusBits.LEVEL_HIGH_TRIP) is True


def test_horner_register_sync() -> None:
    """Stage 8: Verify Horner OCS register space synchronization (%R650..%R657)."""
    sim = EvaporatorSimulator()
    sim.step_rk4(dt=0.01)

    st_word = sim.reg_table.read_uword("%R650")
    conc_val = sim.reg_table.read_word("%R651")
    evap_val = sim.reg_table.read_word("%R652")
    t_vap1 = sim.reg_table.read_word("%R653")
    t_vap3 = sim.reg_table.read_word("%R654")
    pwr_val = sim.reg_table.read_word("%R655")

    assert (st_word & int(EvaporatorStatusBits.SYSTEM_RUNNING)) != 0
    assert 3000 <= conc_val <= 5500
    assert evap_val >= 0
    assert t_vap1 > t_vap3 > 0
    assert pwr_val >= 0


def test_anti_ladder_guard() -> None:
    """Stage 9: Verify anti-ladder security guard assertion with ERR_LADDER_FORBIDDEN."""
    bad_st = """
    PROGRAM BadEvapLadderLogic
    VAR V : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_st)
