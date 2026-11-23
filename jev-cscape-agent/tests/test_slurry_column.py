"""Unit Tests for Continuous Multi-Stage Slurry Bubble Column Reactor ODE Solver (W101).

Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation.
"""

from __future__ import annotations

import math
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.slurry_column import (
    SlurryColumnStatusBits,
    SlurryColumnParams,
    StageState,
    SlurryBubbleColumnEngine,
    SLURRY_COLUMN_PURE_ST_POU,
    run_slurry_column_verification,
)


class TestSlurryBubbleColumnEngine:
    """Test suite for W101 Slurry Column ODE Solver."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Pure ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(SLURRY_COLUMN_PURE_ST_POU)
        res = STParser.validate_code(SLURRY_COLUMN_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SLURRY_COLUMN_PURE_ST_POU)
        assert ast.name == "SlurryBubbleColumnSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R620" in ast.bound_registers
        assert "%R621" in ast.bound_registers
        assert "%R622" in ast.bound_registers
        assert "%R623" in ast.bound_registers
        assert "%R624" in ast.bound_registers
        assert "%R625" in ast.bound_registers
        assert "%R626" in ast.bound_registers
        assert "%R627" in ast.bound_registers
        assert "%M144" in ast.bound_registers
        assert "%M145" in ast.bound_registers
        assert "%M146" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM BadSlurryLadder
        VAR Valve : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_hydrodynamic_drift_flux_and_holdup(self) -> None:
        """Verify Zuber-Findlay drift flux calculation across gas velocities."""
        sim = SlurryBubbleColumnEngine()
        holdup_02 = sim.compute_steady_gas_holdup(0.02, 0.015)
        holdup_08 = sim.compute_steady_gas_holdup(0.08, 0.015)
        holdup_20 = sim.compute_steady_gas_holdup(0.20, 0.015)

        assert 0.05 < holdup_02 < 0.15
        assert 0.15 < holdup_08 < 0.28
        assert 0.28 < holdup_20 < 0.45
        assert holdup_02 < holdup_08 < holdup_20

    def test_solids_suspension_threshold(self) -> None:
        """Verify Roy/Joshi critical suspension velocity and warning coil."""
        reg_table = RegisterTable()
        sim = SlurryBubbleColumnEngine(register_table=reg_table)

        # Gas velocity below threshold (0.05 < 0.08 m/s)
        sim.U_g = 0.05
        sim._sync_registers()
        assert sim.is_solids_suspended() is False
        assert reg_table.read_bit("%M146") is True
        assert reg_table.read_word("%R627") == 0
        assert (reg_table.read_word("%R620") & int(SlurryColumnStatusBits.SOLIDS_SETTLING_WARNING)) != 0

        # Gas velocity above threshold (0.12 >= 0.08 m/s)
        sim.U_g = 0.12
        sim._sync_registers()
        assert sim.is_solids_suspended() is True
        assert reg_table.read_bit("%M146") is False
        assert reg_table.read_word("%R627") == 1

    def test_three_stage_axial_profiles_and_rk4(self) -> None:
        """Verify RK4 integration, reactant consumption, and axial exotherm."""
        sim = SlurryBubbleColumnEngine()
        res = sim.advance_time(duration_s=1.5, dt=0.01)
        assert res.status == AgentStatus.SUCCESS
        assert sim.sim_time == pytest.approx(1.5, abs=1e-5)

        # Check axial concentration gradient (C_B decreases up the stages)
        c_b_1 = sim.stages[0].C_B
        c_b_2 = sim.stages[1].C_B
        c_b_3 = sim.stages[2].C_B
        assert c_b_1 > c_b_2 > c_b_3

        # Check axial temperature gradient (temperature rises due to exotherm)
        t_1 = sim.stages[0].T_sl
        t_2 = sim.stages[1].T_sl
        t_3 = sim.stages[2].T_sl
        assert t_1 < t_2 < t_3
        assert sim.get_product_conversion() > 0.10

    def test_cooling_jacket_heat_balance_and_failure(self) -> None:
        """Verify cooling jacket duty and thermal response under cooling failure."""
        sim = SlurryBubbleColumnEngine()
        sim.advance_time(duration_s=1.0, dt=0.01)
        duty_normal = sim.get_total_heat_duty_kw()
        assert duty_normal > 0.0

        # Simulate cooling jacket pump failure
        sim.cooling_enabled = False
        sim.advance_time(duration_s=1.5, dt=0.01)
        assert sim.get_total_heat_duty_kw() == 0.0
        assert (sim.reg_table.read_word("%R620") & int(SlurryColumnStatusBits.COOLING_JACKET_FAULT)) != 0

    def test_critical_holdup_and_foaming_trip(self) -> None:
        """Verify foaming condition and critical holdup trip assertion."""
        reg_table = RegisterTable()
        sim = SlurryBubbleColumnEngine(register_table=reg_table)
        sim.U_g = 0.40  # Excess gas velocity
        sim.advance_time(duration_s=2.0, dt=0.01)

        avg_holdup = sim.get_average_gas_holdup()
        assert avg_holdup >= 0.38
        assert reg_table.read_bit("%M144") is True
        assert (reg_table.read_word("%R620") & int(SlurryColumnStatusBits.CRITICAL_HOLDUP_TRIP)) != 0

    def test_sparger_orifice_pressure_drop(self) -> None:
        """Verify orifice pressure drop correlation."""
        sim = SlurryBubbleColumnEngine()
        dp_pa_08 = sim.compute_sparger_pressure_drop(0.08)
        dp_pa_16 = sim.compute_sparger_pressure_drop(0.16)

        # Quadratic scaling: doubling velocity should quadruple pressure drop
        assert dp_pa_16 == pytest.approx(4.0 * dp_pa_08, rel=1e-3)
        assert 1000.0 < dp_pa_08 < 5000.0

    def test_horner_register_sync(self) -> None:
        """Verify registers %R620..%R627 and %M144..%M146 mapping."""
        reg_table = RegisterTable()
        sim = SlurryBubbleColumnEngine(register_table=reg_table)
        sim.advance_time(duration_s=0.5, dt=0.01)

        r620 = reg_table.read_word("%R620")
        r621 = reg_table.read_word("%R621")
        r622 = reg_table.read_word("%R622")
        r623 = reg_table.read_word("%R623")
        r624 = reg_table.read_word("%R624")
        r625 = reg_table.read_word("%R625")
        r626 = reg_table.read_word("%R626")
        r627 = reg_table.read_word("%R627")

        assert (r620 & int(SlurryColumnStatusBits.SYSTEM_ACTIVE)) != 0
        assert r621 > 0
        assert r622 == 8
        assert r623 > 300
        assert r627 == 1

    def test_full_verification_runner_9_stages(self) -> None:
        """Verify 9-stage verification suite executes cleanly."""
        evidence = run_slurry_column_verification()
        assert evidence["status"] == "success"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
