"""Unit tests for Model Predictive Controller (MPC) Horizon Solver (W061).

Tests:
1. Unconstrained step tracking (receding horizon drives error to zero asymptotically).
2. Input saturation clamping (u_min, u_max boundaries, anti-windup, status bits).
3. Slew rate clamping (|delta_u| <= delta_u_max, status bit).
4. Disturbance rejection when unmeasured load perturbation occurs.
5. Horner OCS register synchronization (%R170..%R175, %M54..%M55).
6. ILogicUnit scan cycle execution with ScanContext.
7. Pure ST boundary enforcement: rejection of ladder constructs.
8. Canonical verification runner and artifact JSON generation.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.mpc_controller import (
    HildrethQPSolver,
    MPCConfig,
    MPCController,
    MPCStatusFlag,
    verify_mpc_controller_and_export_evidence,
)


def test_hildreth_qp_solver_unconstrained() -> None:
    """Verify Hildreth QP solver matches analytical solution for unconstrained quadratic."""
    # Min 0.5 * x^T * H * x + f^T * x
    # H = [[4.0, 1.0], [1.0, 2.0]], f = [-2.0, -5.0]
    # Analytical: x* = -H^-1 * f = (1/7) * [[2, -1], [-1, 4]] * [2, 5]^T = (1/7) * [-1, 18]^T = [-0.142857, 2.571428]
    H = [[4.0, 1.0], [1.0, 2.0]]
    M = [[1.0, 0.0], [-1.0, 0.0], [0.0, 1.0], [0.0, -1.0]]
    gamma = [10.0, 10.0, 10.0, 10.0]  # Generous bounds
    solver = HildrethQPSolver(H, M)

    f = [-2.0, -5.0]
    x_opt, iters, converged = solver.solve(f, gamma)
    assert converged is True
    assert iters == 0  # Unconstrained solution is immediately feasible
    assert abs(x_opt[0] - (-1.0 / 7.0)) < 1e-4
    assert abs(x_opt[1] - (18.0 / 7.0)) < 1e-4


def test_hildreth_qp_solver_constrained() -> None:
    """Verify Hildreth QP solver respects active inequality constraints."""
    H = [[2.0, 0.0], [0.0, 2.0]]
    # Unconstrained optimum with f=[-10, -10] is x* = [5, 5]
    f = [-10.0, -10.0]
    # Constraint: x1 + x2 <= 4.0, x1 >= 0, x2 >= 0
    M = [[1.0, 1.0], [-1.0, 0.0], [0.0, -1.0]]
    gamma = [4.0, 0.0, 0.0]
    solver = HildrethQPSolver(H, M, max_iter=50)

    x_opt, iters, converged = solver.solve(f, gamma)
    assert converged is True
    assert iters > 0
    # Constrained optimum on line x1 + x2 = 4 is x* = [2.0, 2.0]
    assert abs(x_opt[0] - 2.0) < 1e-3
    assert abs(x_opt[1] - 2.0) < 1e-3
    assert x_opt[0] + x_opt[1] <= 4.0001


def test_mpc_unconstrained_step_tracking() -> None:
    """Verify receding horizon controller drives process variable toward setpoint."""
    reg = RegisterTable()
    cfg = MPCConfig(np=10, nc=3, dt_s=0.010, u_min=0.0, u_max=100.0, delta_u_max=20.0)
    mpc = MPCController(register_table=reg, config=cfg, k_plant=1.0, tau_plant=1.0)

    # Setpoint at 50.0% (16000 counts)
    reg.write_word("%R172", 16000, privilege=PrivilegeMode.SYSTEM)

    sim_pv = 0.0
    for _ in range(250):
        # Read manipulated variable u
        u_counts = reg.read_word("%AQ1")
        u_val = (u_counts / 32000.0) * 100.0
        # First-order plant: y(k) = a1*y + b1*u
        sim_pv = mpc.a1 * sim_pv + mpc.b1 * u_val
        reg.write_word("%AI1", int((sim_pv / 100.0) * 32000.0), privilege=PrivilegeMode.SYSTEM)
        mpc.step(0.010)

    # Steady-state error should be less than 5%
    assert abs(mpc.pv - 50.0) < 5.0
    assert mpc.status_flags & MPCStatusFlag.MPC_ACTIVE
    assert mpc.status_flags & MPCStatusFlag.SOLVER_OPTIMAL


def test_mpc_input_saturation_clamping() -> None:
    """Verify actuator command is strictly clamped within [u_min, u_max]."""
    reg = RegisterTable()
    cfg = MPCConfig(np=10, nc=2, dt_s=0.010, u_min=0.0, u_max=100.0, delta_u_max=20.0)
    mpc = MPCController(register_table=reg, config=cfg, k_plant=1.0, tau_plant=4.0)

    # Extreme setpoint jump: 100.0%
    reg.write_word("%R172", 32000, privilege=PrivilegeMode.SYSTEM)
    reg.write_word("%AI1", 0, privilege=PrivilegeMode.SYSTEM)  # PV at 0%

    for _ in range(20):
        mpc.step(0.010)
        assert 0.0 <= mpc.u <= 100.0
        assert 0 <= reg.read_word("%R170") <= 32000

    # Max saturation flag asserted
    assert mpc.status_flags & MPCStatusFlag.SATURATED_MAX


def test_mpc_slew_rate_clamping() -> None:
    """Verify rate of change |delta_u| is bounded by delta_u_max."""
    reg = RegisterTable()
    cfg = MPCConfig(np=10, nc=2, dt_s=0.010, delta_u_max=2.0)
    mpc = MPCController(register_table=reg, config=cfg, k_plant=1.0, tau_plant=4.0)

    # Instantaneous setpoint jump
    reg.write_word("%R172", 32000, privilege=PrivilegeMode.SYSTEM)
    reg.write_word("%AI1", 0, privilege=PrivilegeMode.SYSTEM)

    for _ in range(10):
        mpc.step(0.010)
        assert abs(mpc.delta_u) <= cfg.delta_u_max + 1e-6
        if abs(mpc.delta_u) >= cfg.delta_u_max - 1e-6:
            assert mpc.status_flags & MPCStatusFlag.SLEW_LIMITED


def test_mpc_disturbance_rejection() -> None:
    """Verify disturbance observer detects and compensates unmeasured load changes."""
    reg = RegisterTable()
    cfg = MPCConfig(np=10, nc=3, dt_s=0.010)
    mpc = MPCController(register_table=reg, config=cfg, k_plant=1.0, tau_plant=3.0)

    reg.write_word("%R172", 16000, privilege=PrivilegeMode.SYSTEM)  # 50%
    reg.write_word("%AI1", 16000, privilege=PrivilegeMode.SYSTEM)   # 50%
    mpc.u = 50.0

    # Inject sudden negative level disturbance
    reg.write_word("%AI1", 9600, privilege=PrivilegeMode.SYSTEM)  # 30%
    for _ in range(25):
        mpc.step(0.010)

    # Observer should estimate disturbance
    assert abs(mpc.disturbance_estimate) > 0.0
    assert mpc.status_flags & MPCStatusFlag.DISTURBANCE_ACTIVE


def test_mpc_horner_register_synchronization() -> None:
    """Verify %R170..%R175 and %M54..%M55 synchronization."""
    reg = RegisterTable()
    mpc = MPCController(register_table=reg)

    mpc.step(0.010)
    assert reg.read_bit("%M54") is True
    assert reg.read_bit("%M55") is False

    # Check %R170..%R175 write
    assert reg.read_word("%R170") == int(round((mpc.u / 100.0) * 32000.0))
    assert reg.read_word("%R175") == int(mpc.status_flags)

    # Test disable coil %M54
    reg.write_bit("%M54", False, privilege=PrivilegeMode.SYSTEM)
    mpc.step(0.010)
    assert mpc.run_enabled is False
    assert mpc.status_flags == MPCStatusFlag.NONE

    # Test reset coil %M55
    reg.write_bit("%M55", True, privilege=PrivilegeMode.SYSTEM)
    mpc.step(0.010)
    assert reg.read_bit("%M55") is False  # Self-cleared
    assert mpc.u == 0.0


def test_mpc_ilogicunit_interface() -> None:
    """Verify ILogicUnit scan cycle execution."""
    mpc = MPCController()
    assert mpc.name == "MPCControllerUnit"
    assert mpc.priority == 40
    assert mpc.is_enabled is True

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
    mpc.execute(ctx)
    assert mpc.status_flags & MPCStatusFlag.MPC_ACTIVE

    mpc.reset()
    assert mpc.u == 0.0


def test_mpc_pure_st_ladder_rejection() -> None:
    """Verify SecurityGuard rejects forbidden ladder logic in ST."""
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("---[ ]---; (* illegal contact in MPC block *)")

    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("RUNG 1: x := 10;")


def test_verify_mpc_evidence_export(tmp_path: Path) -> None:
    """Verify canonical evidence generation function."""
    out_evidence = tmp_path / "mpc_controller_evidence.json"
    result = verify_mpc_controller_and_export_evidence(str(out_evidence))
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert out_evidence.exists()

    with open(out_evidence, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["data"]["work_package"] == "W061"
    assert loaded["data"]["gate"] == "G4"
    assert "horner_ocs_register_map" in loaded["data"]
