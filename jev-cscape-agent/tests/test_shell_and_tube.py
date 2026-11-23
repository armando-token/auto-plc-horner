"""Unit Tests for Multi-Pass Shell-and-Tube Exchanger Dynamics ODE Solver (W095).

Gate G7 Advanced Process Dynamics / Gate G4 Simulation.
"""

from __future__ import annotations

import math
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.shell_and_tube import (
    ExchangerStatusBits,
    ShellAndTubeConfig,
    ShellAndTubeExchangerSimulator,
    SHELL_AND_TUBE_PURE_ST_POU,
    run_shell_and_tube_verification,
)


class TestShellAndTubeExchanger:
    """Test suite for W095 Shell-and-Tube Exchanger Simulator."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Pure ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(SHELL_AND_TUBE_PURE_ST_POU)
        res = STParser.validate_code(SHELL_AND_TUBE_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SHELL_AND_TUBE_PURE_ST_POU)
        assert ast.name == "W095_ShellAndTubeExchanger"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R560" in ast.bound_registers
        assert "%R567" in ast.bound_registers
        assert "%M130" in ast.bound_registers
        assert "%M132" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM LadderExchanger
        VAR Coil1 : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_lmtd_and_f_correction_factor(self) -> None:
        """Test analytical LMTD, F-factor, and effective delta Tm."""
        sim = ShellAndTubeExchangerSimulator()

        # Normal condition: Th_out = 75 C (348.15 K), Tc_out = 35 C (308.15 K)
        lmtd, f, dtm = sim.compute_lmtd_and_f(t_h_out=348.15, t_c_out=308.15)
        assert lmtd > 25.0
        assert 0.75 <= f <= 1.0
        assert dtm > 20.0
        assert abs(dtm - f * lmtd) < 1e-4

    def test_f_factor_singularity_at_r_one(self) -> None:
        """Test L'Hopital evaluation when capacity ratio R approaches 1.0."""
        sim = ShellAndTubeExchangerSimulator()

        # Create conditions where R = 1.0: delta T_hot == delta T_cold
        # Inlet Th = 95 C (368.15 K), Inlet Tc = 20 C (293.15 K)
        # If Th_out = 70 C, delta Th = 25 C. If Tc_out = 45 C, delta Tc = 25 C -> R = 1.0
        lmtd, f, dtm = sim.compute_lmtd_and_f(t_h_out=343.15, t_c_out=318.15)
        assert not math.isnan(f)
        assert not math.isinf(f)
        assert 0.50 <= f <= 1.0

    def test_coupled_ode_energy_conservation(self) -> None:
        """Test exact thermal energy conservation residual < 1e-10 W."""
        sim = ShellAndTubeExchangerSimulator()
        y = [sim.t_h, sim.t_c, sim.t_wall, sim.r_f]
        dydt, flows = sim.evaluate_derivatives(y)

        cons = sim.check_energy_conservation(dydt, y)
        assert cons["is_conserved"] is True
        assert cons["residual_w"] < 1e-10

    def test_kern_seaton_asymptotic_fouling_ode(self) -> None:
        """Test Kern-Seaton dynamic fouling deposition and removal rate."""
        sim = ShellAndTubeExchangerSimulator()

        # Clean surface (R_f = 0): dRf/dt equals phi_dep
        dydt_clean, _ = sim.evaluate_derivatives([sim.t_h, sim.t_c, sim.t_wall, 0.0])
        assert abs(dydt_clean[3] - sim.cfg.deposition_flux_w_m2_k_s) < 1e-12

        # Asymptotic steady-state ceiling: dRf/dt = 0
        r_f_inf = sim.cfg.deposition_flux_w_m2_k_s / sim.cfg.removal_rate_s_inv
        dydt_inf, _ = sim.evaluate_derivatives([sim.t_h, sim.t_c, sim.t_wall, r_f_inf])
        assert abs(dydt_inf[3]) < 1e-12
        assert abs(r_f_inf - 3.494e-4) < 1e-5

    def test_tube_bore_constriction_and_dp_surge(self) -> None:
        """Test hydraulic diameter shrinkage and non-linear 5th power dP surge."""
        sim = ShellAndTubeExchangerSimulator()

        d_clean, dp_clean = sim.compute_hydraulics(0.0)
        assert abs(d_clean - sim.cfg.tube_inner_diameter_m) < 1e-5
        assert abs(dp_clean - sim.cfg.clean_dp_mbar) < 1e-2

        # Fouled condition: R_f = 400 um^2*K/W
        d_fouled, dp_fouled = sim.compute_hydraulics(400e-6)
        assert d_fouled < d_clean
        # dP should surge by > 3x
        assert dp_fouled > 3.0 * dp_clean

    def test_rk4_simulation_stepping(self) -> None:
        """Test deterministic RK4 simulation stepping over scan cycles."""
        reg_table = RegisterTable()
        sim = ShellAndTubeExchangerSimulator(register_table=reg_table)

        t_initial = sim.time_s
        for _ in range(10):
            step_data = sim.step(dt=0.1)
            assert step_data["conservation"]["is_conserved"] is True

        assert abs(sim.time_s - (t_initial + 1.0)) < 1e-4

    def test_high_fouling_alarm_actuation(self) -> None:
        """Test high fouling alarm trip (%M130 and %R567 bit 5)."""
        reg_table = RegisterTable()
        sim = ShellAndTubeExchangerSimulator(register_table=reg_table)

        sim.r_f = 450e-6
        sim.step(dt=0.1)

        assert reg_table.read_bit("%M130") is True
        assert bool(reg_table.read_word("%R567") & ExchangerStatusBits.HIGH_FOULING_ALARM)

    def test_low_duty_thermal_trip(self) -> None:
        """Test thermal duty collapse trip (%M131 and %R567 bit 6)."""
        reg_table = RegisterTable()
        sim = ShellAndTubeExchangerSimulator(register_table=reg_table)

        # Cut hot mass flow
        sim.cfg.hot_mass_flow_kg_s = 0.40
        sim.step(dt=0.1)

        assert reg_table.read_bit("%M131") is True
        assert bool(reg_table.read_word("%R567") & ExchangerStatusBits.LOW_DUTY_TRIP)

    def test_clean_status_baseline(self) -> None:
        """Test clean exchanger status indicator (%M132 and %R567 bit 7)."""
        reg_table = RegisterTable()
        sim = ShellAndTubeExchangerSimulator(register_table=reg_table)

        sim.r_f = 40e-6
        sim.step(dt=0.1)

        assert reg_table.read_bit("%M132") is True
        assert bool(reg_table.read_word("%R567") & ExchangerStatusBits.CLEAN_BASELINE_STATUS)
        assert reg_table.read_bit("%M130") is False
        assert reg_table.read_bit("%M131") is False

    def test_horner_ocs_register_scaling(self) -> None:
        """Test Horner analog registers %R560..%R566 scaling."""
        reg_table = RegisterTable()
        sim = ShellAndTubeExchangerSimulator(register_table=reg_table)

        sim.t_h = 353.15      # 80.0 °C
        sim.t_c = 313.15      # 40.0 °C
        sim.r_f = 150e-6      # 150 um^2*K/W
        sim.sync_registers(duty_kw=235.4, dp_mbar=320.0)

        assert reg_table.read_word("%R560") == 950   # 95.0 °C
        assert reg_table.read_word("%R561") == 800   # 80.0 °C
        assert reg_table.read_word("%R562") == 200   # 20.0 °C
        assert reg_table.read_word("%R563") == 400   # 40.0 °C
        assert reg_table.read_word("%R564") == 2354  # 235.4 kW * 10
        assert reg_table.read_word("%R565") == 150   # 150 count
        assert reg_table.read_word("%R566") == 320   # 320 mbar

    def test_run_verification_runner_end_to_end(self, tmp_path) -> None:
        """Test end-to-end 9-stage verification runner function."""
        ev_file = tmp_path / "exchanger_evidence.json"
        res = run_shell_and_tube_verification(evidence_path=str(ev_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert ev_file.exists()
