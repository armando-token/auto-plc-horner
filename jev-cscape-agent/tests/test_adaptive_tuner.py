"""Unit tests for Adaptive Gain PID Self-Tuner & Loop Decoupler Engine (W059).

Tests:
1. RLSIdentifier parameter tracking and mathematical convergence.
2. Covariance trace clamping preventing estimator windup.
3. Persistent excitation (PE) gating logic.
4. Cohen-Coon and AMIGO tuning rule calculations.
5. Parameter safety clamping within industrial limits.
6. 2D Bilinear Gain Scheduling Matrix interpolation across level and temperature.
7. Feedforward Decoupler cross-channel interaction offsets (D21 and D12).
8. Horner OCS register space synchronization (%R160..%R169, %M48..%M50).
9. ILogicUnit scan cycle execution, ScanContext compatibility, and reset behavior.
10. Canonical verification runner and artifact JSON generation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest

from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.adaptive_tuner import (
    AdaptivePIDTunerManager,
    FeedforwardDecoupler,
    GainSchedulingMatrix,
    PIDParameters,
    RLSIdentifier,
    TunerStatusFlag,
    TuningMethod,
    TuningRuleEngine,
    verify_adaptive_tuner_and_export_evidence,
)


def test_rls_identifier_convergence() -> None:
    """Verify RLS identifier converges toward true process gain and time constant."""
    dt = 0.010
    rls = RLSIdentifier(forgetting_factor=0.99, dt_s=dt)

    # True process: dy/dt = (K_true * u - y) / tau_true
    # Discrete equivalent: y(k) = a1 * y(k-1) + b1 * u(k-1)
    k_true = 1.50
    tau_true = 3.0
    a1_true = math.exp(-dt / tau_true)
    b1_true = k_true * (1.0 - a1_true)

    y = 0.0
    u_prev = 0.0
    for i in range(1200):
        # Persistent excitation: square wave input u with continuous dither
        u = 40.0 + (20.0 if (i % 100 < 50) else -20.0) + 2.0 * math.sin(i)
        y = a1_true * y + b1_true * u_prev
        u_prev = u
        k_est, tau_est = rls.update(y, u)

    # Verify identified parameters are within 10% of true values
    assert abs(k_est - k_true) / k_true < 0.10
    assert abs(tau_est - tau_true) / tau_true < 0.10
    assert rls.pe_active is True


def test_rls_trace_clamping() -> None:
    """Verify covariance matrix trace is strictly clamped to prevent numerical blowup."""
    rls = RLSIdentifier(max_trace=500.0, forgetting_factor=0.90)

    # Feed steady non-exciting input
    for _ in range(50):
        rls.update(y=10.0, u=10.0)

    assert rls.trace <= 500.01


def test_persistent_excitation_gating() -> None:
    """Verify estimator detects lack of excitation and pauses adaptation."""
    rls = RLSIdentifier(pe_threshold=0.50)

    # Flat constant input -> variance = 0
    for _ in range(20):
        rls.update(y=5.0, u=50.0)
    assert rls.pe_active is False

    # Highly oscillating input -> variance high
    for i in range(20):
        u = 20.0 if i % 2 == 0 else 80.0
        rls.update(y=5.0, u=u)
    assert rls.pe_active is True


def test_tuning_rule_cohen_coon_and_amigo() -> None:
    """Verify Cohen-Coon and AMIGO tuning rule equations."""
    k = 1.2
    tau = 4.0
    theta = 0.5

    p_cc = TuningRuleEngine.calculate_cohen_coon(k=k, tau=tau, theta_dt=theta)
    assert p_cc.kp > 0.0
    assert p_cc.ti > 0.0
    assert p_cc.td > 0.0

    p_amigo = TuningRuleEngine.calculate_amigo(k=k, tau=tau, theta_dt=theta)
    assert p_amigo.kp > 0.0
    assert p_amigo.ti > 0.0
    assert p_amigo.td > 0.0

    # Ensure parameters differ based on tuning method
    assert p_cc.kp != p_amigo.kp


def test_pid_safety_bounds_clamping() -> None:
    """Verify aggressive or degenerate tuning outputs are clamped to safe plant limits."""
    # Degenerate case: tiny gain, huge delay
    params = TuningRuleEngine.calculate_cohen_coon(k=1e-8, tau=1000.0, theta_dt=0.001)
    assert 0.05 <= params.kp <= 25.0
    assert 0.20 <= params.ti <= 600.0
    assert 0.0 <= params.td <= 60.0


def test_gain_scheduling_matrix() -> None:
    """Verify bilinear interpolation across level and temperature."""
    sched = GainSchedulingMatrix()

    # Exact grid corners
    p_c1 = sched.interpolate(0.5, 25.0)
    assert math.isclose(p_c1.kp, 2.8, rel_tol=1e-3)

    p_c2 = sched.interpolate(1.5, 75.0)
    assert math.isclose(p_c2.kp, 2.3, rel_tol=1e-3)

    # Intermediate midpoint (1.0m, 50C)
    p_mid = sched.interpolate(1.0, 50.0)
    expected_kp = (2.8 + 3.2 + 1.9 + 2.3) / 4.0
    assert math.isclose(p_mid.kp, expected_kp, rel_tol=1e-2)


def test_feedforward_decoupler() -> None:
    """Verify cross-channel disturbance decoupling offsets."""
    decoupler = FeedforwardDecoupler(d21_gain=0.40, d12_gain=-0.02)

    # Initial state
    ff_v, ff_h = decoupler.compute_offsets(u_valve=50.0, u_heater=30.0, enabled=True)
    assert ff_h > 0.0  # Cold inflow offset boosts heater
    assert ff_v < 0.0  # Heater offset slightly trims valve

    # Disabled mode returns zero
    ff_v_dis, ff_h_dis = decoupler.compute_offsets(u_valve=50.0, u_heater=30.0, enabled=False)
    assert ff_v_dis == 0.0
    assert ff_h_dis == 0.0


def test_horner_register_synchronization() -> None:
    """Verify OCS register table synchronization (%R160..%R169, %M48..%M50)."""
    reg = RegisterTable()
    tuner = AdaptivePIDTunerManager(register_table=reg, dt_s=0.010)

    # Step to initialize
    tuner.step(0.010)

    # Check initial values written to register space
    kp_val = reg.read_word("%R160")
    assert kp_val > 0
    assert reg.read_word("%R161") > 0  # Ti
    status = reg.read_word("%R165")
    assert status & TunerStatusFlag.RLS_ACTIVE
    assert status & TunerStatusFlag.ADAPTATION_ON

    # Test operator control coil %M48 (disable adaptation)
    reg.write_bit("%M48", False, privilege=PrivilegeMode.SYSTEM)
    tuner.step(0.010)
    assert tuner.adaptation_enabled is False
    assert not (reg.read_word("%R165") & TunerStatusFlag.ADAPTATION_ON)

    # Test reset coil %M50
    reg.write_bit("%M50", True, privilege=PrivilegeMode.SYSTEM)
    tuner.step(0.010)
    assert tuner.identifier.samples_processed == 0


def test_ilogicunit_interface() -> None:
    """Verify compliance with ILogicUnit scan cycle execution."""
    tuner = AdaptivePIDTunerManager()
    assert tuner.name == "AdaptivePIDTunerUnit"
    assert tuner.priority == 45
    assert tuner.is_enabled is True

    ctx = ScanContext(
        cycle=1,
        dt_ms=10.0,
        elapsed_time_ms=10.0,
        get_register=lambda addr: 0,
        set_register=lambda addr, val: None,
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )
    tuner.execute(ctx)
    assert tuner.identifier.samples_processed == 1


def test_verify_adaptive_tuner_evidence(tmp_path: Path) -> None:
    """Verify canonical evidence generation function."""
    out_evidence = tmp_path / "adaptive_tuner_evidence.json"
    result = verify_adaptive_tuner_and_export_evidence(str(out_evidence))
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert out_evidence.exists()

    with open(out_evidence, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["data"]["work_package"] == "W059"
    assert loaded["data"]["gate"] == "G7"
    assert "horner_ocs_register_map" in loaded["data"]
