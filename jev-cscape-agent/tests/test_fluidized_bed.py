"""Unit tests for Fluidized Bed Reactor (FBR) Two-Phase Hydrodynamics & Catalytic Gasification ODE Solver.

Work Package: W089 (Gate G7 Advanced Process Dynamics / Gate G4 Simulation)
Classification: PRODUCTION_READY
"""

import math
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.fluidized_bed import (
    FBRConfig,
    FBRStatusBits,
    FluidizedBedReactorSimulator,
    FLUIDIZED_BED_PURE_ST_POU,
    run_fluidized_bed_verification,
)


class TestFluidizedBedPureST:
    """Tests for IEC 61131-3 Pure ST compliance and anti-ladder security."""

    def test_pure_st_security_guard(self) -> None:
        """Verify Pure ST POU passes security guard assertion."""
        SecurityGuard.assert_pure_st_content(FLUIDIZED_BED_PURE_ST_POU)

    def test_ladder_constructs_rejected(self) -> None:
        """Verify ladder contacts, coils, and rungs trigger LadderForbiddenError."""
        ladder_snippets = [
            FLUIDIZED_BED_PURE_ST_POU + "\n---[ ]---",
            FLUIDIZED_BED_PURE_ST_POU + "\n---( )---",
            FLUIDIZED_BED_PURE_ST_POU + "\nRUNG 1",
            FLUIDIZED_BED_PURE_ST_POU + "\nNETWORK 1",
            FLUIDIZED_BED_PURE_ST_POU + "\nOTE MyCoil",
        ]
        for snip in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)

    def test_st_parser_validation_and_ast(self) -> None:
        """Verify ST parser validates syntax and extracts AST properly."""
        val = STParser.validate_code(FLUIDIZED_BED_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(FLUIDIZED_BED_PURE_ST_POU)
        assert ast.name == "W089_FluidizedBedReactor"
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = ["%R500", "%R501", "%R502", "%R503", "%R504", "%R505", "%R506", "%R507"]
        for reg in expected_regs:
            assert reg in ast.bound_registers
        expected_coils = ["%M116", "%M117", "%M118"]
        for coil in expected_coils:
            assert coil in ast.bound_registers


class TestFluidizedBedHydrodynamics:
    """Tests for two-phase fluidization hydrodynamics, bubble dynamics, and expansion."""

    def test_ergun_umf_calculation(self) -> None:
        """Verify Ergun equation solution yields realistic U_mf in 0.005..0.05 m/s."""
        sim = FluidizedBedReactorSimulator()
        umf = sim.compute_umf(sim.t_em_k)
        assert 0.005 <= umf <= 0.05

        # Increasing temperature increases gas viscosity, decreasing U_mf
        umf_cold = sim.compute_umf(300.0)
        umf_hot = sim.compute_umf(1100.0)
        assert umf_cold > umf_hot

    def test_darton_bubble_growth(self) -> None:
        """Verify Darton bubble diameter growth with height and excess velocity."""
        sim = FluidizedBedReactorSimulator()
        umf = sim.compute_umf(sim.t_em_k)
        u0 = 0.65
        d_b_bottom = sim.compute_bubble_diameter(u0, umf, 0.1)
        d_b_top = sim.compute_bubble_diameter(u0, umf, 1.5)
        assert d_b_top > d_b_bottom
        assert d_b_top <= 0.40 * sim.cfg.diameter_m

    def test_bed_expansion_and_voidage(self) -> None:
        """Verify bed expansion and gas holdup voidage under fluidizing conditions."""
        sim = FluidizedBedReactorSimulator()
        umf = sim.compute_umf(sim.t_em_k)
        hydro = sim.compute_hydrodynamics(0.65, umf, sim.t_em_k)
        assert hydro["L_f"] > sim.cfg.settled_height_m
        assert 0.05 < hydro["delta_b"] < 0.60
        assert hydro["total_delta_p"] > hydro["delta_p_bed"]

    def test_kunii_levenspiel_transfer_coefficients(self) -> None:
        """Verify interphase exchange coefficients K_be and H_be."""
        sim = FluidizedBedReactorSimulator()
        umf = sim.compute_umf(sim.t_em_k)
        hydro = sim.compute_hydrodynamics(0.65, umf, sim.t_em_k)
        assert hydro["k_be"] > 0.25
        assert hydro["h_be"] > 100.0


class TestFluidizedBedReactionKineticsAndConservation:
    """Tests for reaction kinetics, coupled ODE derivatives, and conservation laws."""

    def test_arrhenius_kinetics(self) -> None:
        """Verify 1st-order Arrhenius catalytic rate law."""
        sim = FluidizedBedReactorSimulator()
        r1 = sim.reaction_rate(10.0, 700.0 + 273.15)
        r2 = sim.reaction_rate(10.0, 800.0 + 273.15)
        assert r2 > r1
        assert sim.reaction_rate(0.0, 750.0 + 273.15) == 0.0

    def test_coupled_derivatives_and_conservation(self) -> None:
        """Verify mass and energy balance residuals are < 1e-10."""
        sim = FluidizedBedReactorSimulator()
        umf = sim.compute_umf(sim.t_em_k)
        hydro = sim.compute_hydrodynamics(sim.u0_m_s, umf, sim.t_em_k)
        state = [sim.c_a_b, sim.c_a_em, sim.t_b_k, sim.t_em_k]
        d_state, r_a = sim.evaluate_derivatives(state, sim.u0_m_s, umf, hydro)

        conservation = sim.check_conservation(state, d_state, r_a, sim.u0_m_s, umf, hydro)
        assert conservation["is_mass_conserved"]
        assert conservation["is_energy_conserved"]
        assert conservation["mass_residual_mol_s"] < 1e-10
        assert conservation["energy_residual_w"] < 1e-10

    def test_rk4_time_stepping(self) -> None:
        """Verify RK4 integration step maintains stability and state bounds."""
        sim = FluidizedBedReactorSimulator()
        initial_t_em = sim.t_em_k
        sim.step(dt=0.05)
        assert sim.t_em_k >= 293.15
        assert sim.c_a_b >= 0.0
        assert sim.c_a_em >= 0.0
        assert sim.time_s == pytest.approx(0.05)


class TestFluidizedBedCycloneAndSolidsReturn:
    """Tests for elutriation and cyclone separation return loop."""

    def test_cyclone_separation_efficiency(self) -> None:
        """Verify 99.2% cyclone separation and solids return rate."""
        sim = FluidizedBedReactorSimulator()
        umf = sim.compute_umf(sim.t_em_k)
        hydro = sim.compute_hydrodynamics(sim.u0_m_s, umf, sim.t_em_k)
        assert hydro["F_ent"] > 0.0
        assert hydro["F_return"] == pytest.approx(0.992 * hydro["F_ent"], rel=1e-4)
        assert hydro["F_loss"] == pytest.approx(0.008 * hydro["F_ent"], rel=1e-4)
        assert hydro["TDH"] > 0.35


class TestFluidizedBedControlsAndAlarms:
    """Tests for safety shutdowns, N2 quench, and Horner OCS register space."""

    def test_hotspot_automatic_quench(self) -> None:
        """Verify automatic quench trip on emulsion temperature runaway >= 850 C."""
        reg_table = RegisterTable()
        sim = FluidizedBedReactorSimulator(register_table=reg_table)
        sim.t_em_k = 860.0 + 273.15  # Hotspot trip condition
        sim.step(dt=0.1)

        assert sim.hot_spot_alarm
        assert sim.alarm_latched
        assert sim.quench_active
        r500 = reg_table.read_word("%R500")
        assert bool(r500 & FBRStatusBits.HOT_SPOT_ALARM)
        assert bool(r500 & FBRStatusBits.PURGE_ACTIVE)
        assert bool(r500 & FBRStatusBits.DEFLUIDIZED)

    def test_emergency_quench_override_coil(self) -> None:
        """Verify manual coil %M117 engages emergency cold N2 purge and slumps bed."""
        reg_table = RegisterTable()
        sim = FluidizedBedReactorSimulator(register_table=reg_table)
        reg_table.write_bit("%M117", True, privilege=PrivilegeMode.SYSTEM)
        t_before = sim.t_em_k
        sim.step(dt=0.1)

        assert sim.quench_active
        assert sim.t_em_k < t_before
        assert sim.c_a_em == 0.0

    def test_alarm_reset_handshake(self) -> None:
        """Verify %M118 clears latched alarms and resets itself."""
        reg_table = RegisterTable()
        sim = FluidizedBedReactorSimulator(register_table=reg_table)
        sim.hot_spot_alarm = True
        sim.alarm_latched = True
        sim.sync_registers()

        assert bool(reg_table.read_word("%R500") & FBRStatusBits.ALARM_LATCHED)

        # Trigger reset
        reg_table.write_bit("%M118", True, privilege=PrivilegeMode.SYSTEM)
        sim.t_em_k = 750.0 + 273.15
        sim.step(dt=0.1)

        assert not sim.alarm_latched
        assert not sim.hot_spot_alarm
        assert not reg_table.read_bit("%M118")

    def test_register_scaling_ranges(self) -> None:
        """Verify scaled registers %R500..%R507 are within valid 16-bit ranges."""
        reg_table = RegisterTable()
        sim = FluidizedBedReactorSimulator(register_table=reg_table)
        sim.step(dt=0.1)

        r500 = reg_table.read_word("%R500")
        r501 = reg_table.read_word("%R501")
        r502 = reg_table.read_word("%R502")
        r503 = reg_table.read_word("%R503")
        r504 = reg_table.read_word("%R504")
        r505 = reg_table.read_word("%R505")
        r506 = reg_table.read_word("%R506")
        r507 = reg_table.read_word("%R507")

        for r_val, name in [
            (r500, "%R500"), (r501, "%R501"), (r502, "%R502"), (r503, "%R503"),
            (r504, "%R504"), (r505, "%R505"), (r506, "%R506"), (r507, "%R507")
        ]:
            assert -32768 <= r_val <= 32767, f"{name} out of signed 16-bit range"

        assert r501 == 65
        assert r504 > 7000


class TestFluidizedBedVerificationRunner:
    """Tests for the end-to-end 9-stage verification runner."""

    def test_run_verification(self, tmp_path) -> None:
        """Verify the full 9-stage verification function passes and writes evidence."""
        out_file = tmp_path / "fbr_evidence.json"
        res = run_fluidized_bed_verification(str(out_file))
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert out_file.exists()
