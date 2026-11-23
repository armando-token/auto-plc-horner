"""Unit and Integration Tests for Industrial Fluidized Bed Catalytic Cracking (FCC) Regenerator Simulation.

Work Package: W146 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1070..%R1077, %M249..%M251).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Two-phase bubbling bed fluidization mechanics and catalyst residence time distributions.
4. Section 4: Heterogeneous coke combustion and freeboard homogeneous CO afterburning reaction kinetics.
5. Section 5: Coupled ODE RK4 integration stability and dual carbon/oxygen mass and enthalpy conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xAB01, 0xAB02, 0xAB03, 0xAB04) and Horner coil assertion (%M249, %M250, %M251).
7. Section 7: Horner OCS register space synchronization (%R1070..%R1077, %M249..%M251).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.fcc_regenerator import (
    DELTA_H_R1_J_MOL,
    DELTA_H_R2_J_MOL,
    DELTA_H_R3_J_MOL,
    FCC_PURE_ST_POU,
    FCC_REGENERATOR_DYNAMICS_SYNC_POU,
    FCC_REGENERATOR_PURE_ST_POU,
    FCC_REGENERATOR_SYNC_POU,
    FCC_SYNC_POU,
    FLUIDIZED_BED_REGENERATOR_PURE_ST_POU,
    FLUIDIZED_BED_REGENERATOR_SYNC_POU,
    MW_AIR,
    MW_CARBON,
    MW_CO,
    MW_CO2,
    MW_O2,
    T_ZERO_CELSIUS,
    FccConfig,
    FccDiagCode,
    FccDiagnosticCode,
    FccEngine,
    FccParameters,
    FccRegeneratorConfig,
    FccRegeneratorDiagnosticCode,
    FccRegeneratorEngine,
    FccRegeneratorModel,
    FccRegeneratorParameters,
    FccRegeneratorPlantModel,
    FccRegeneratorSimulationEngine,
    FccRegeneratorSimulator,
    FccRegeneratorState,
    FccRegeneratorStatusBits,
    FccRegeneratorStatusWord,
    FccSimulator,
    FccState,
    FccStatusBits,
    FccStatusWord,
    FluidizedBedRegeneratorConfig,
    FluidizedBedRegeneratorDiagnosticCode,
    FluidizedBedRegeneratorEngine,
    FluidizedBedRegeneratorModel,
    FluidizedBedRegeneratorParameters,
    FluidizedBedRegeneratorPlantModel,
    FluidizedBedRegeneratorSimulationEngine,
    FluidizedBedRegeneratorSimulator,
    FluidizedBedRegeneratorState,
    FluidizedBedRegeneratorStatusBits,
    FluidizedBedRegeneratorStatusWord,
    run_fcc_regenerator_verification,
    run_fcc_verification,
    run_fluidized_bed_regenerator_verification,
    run_regenerator_verification,
    verify_fcc_pure_st,
    verify_fcc_regenerator_pure_st,
    verify_fluidized_bed_pure_st,
    verify_fluidized_bed_regenerator_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1070..%R1077, %M249..%M251)."""

    def test_verify_fcc_regenerator_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_fcc_regenerator_pure_st() is True
        assert verify_fcc_pure_st() is True
        assert verify_fluidized_bed_pure_st() is True
        assert verify_fluidized_bed_regenerator_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1070..%R1077, %M249..%M251)."""
        SecurityGuard.assert_pure_st_content(FCC_REGENERATOR_PURE_ST_POU)
        val = STParser.validate_code(FCC_REGENERATOR_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(FCC_REGENERATOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "FccRegeneratorSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1070", "%R1071", "%R1072", "%R1073",
            "%R1074", "%R1075", "%R1076", "%R1077",
            "%M249", "%M250", "%M251",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Verify FccRegeneratorSync aliases parse cleanly."""
        for pou_text in [
            FCC_PURE_ST_POU,
            FCC_SYNC_POU,
            FCC_REGENERATOR_SYNC_POU,
            FCC_REGENERATOR_DYNAMICS_SYNC_POU,
        ]:
            SecurityGuard.assert_pure_st_content(pou_text)
            ast = STParser.parse_pou(pou_text)
            assert ast is not None
            assert ast.pou_type == POUType.PROGRAM
            for reg in [
                "%R1070", "%R1071", "%R1072", "%R1073",
                "%R1074", "%R1075", "%R1076", "%R1077",
                "%M249", "%M250", "%M251",
            ]:
                assert reg in ast.bound_registers

    def test_fluidized_bed_regenerator_alias(self) -> None:
        """Requirement 1: Verify FluidizedBedRegeneratorSync alias AST parsing."""
        SecurityGuard.assert_pure_st_content(FLUIDIZED_BED_REGENERATOR_PURE_ST_POU)
        ast = STParser.parse_pou(FLUIDIZED_BED_REGENERATOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "FluidizedBedRegeneratorSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R1070" in ast.bound_registers
        assert "%M249" in ast.bound_registers


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests for interception and rejection of ladder logic constructs with ERR_LADDER_FORBIDDEN."""

    @pytest.mark.parametrize(
        "ladder_snippet",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 1",
            "END_RUNG",
            "NETWORK 1",
            "XIC AirBlowerPermissive",
            "XIO AfterburningThermalRunawayTrip",
            "OTE DenseBedHighTempAlarm",
            "OTL CombustionAirBlowerRunning",
            "OTU EmergencySteamQuenchActive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: All ladder constructs must trigger LadderForbiddenError."""
        invalid_st = f"""
        PROGRAM BadLadderFcc
        VAR
            TestVar : BOOL;
        END_VAR
        {ladder_snippet}
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(invalid_st)


# ============================================================================
# 3. Section 3: Two-Phase Bubbling Bed Fluidization Mechanics & RTD
# ============================================================================

class TestSection3FluidizationMechanicsAndRTD:
    """Tests for two-phase fluidization hydrodynamics, Kunii-Levenspiel mechanics, and catalyst RTD."""

    def test_catalyst_and_vessel_parameters(self) -> None:
        """Requirement 3: Verify FCC Geldart Group A catalyst properties and vessel dimensions."""
        cfg = FccRegeneratorConfig()
        assert cfg.particle_diameter_m == 70e-6
        assert cfg.particle_density_kg_m3 == 1500.0
        assert cfg.settled_bulk_density_kg_m3 == 780.0
        assert cfg.emulsion_voidage_mf == 0.48
        assert cfg.catalyst_inventory_kg == 220000.0
        assert cfg.regenerator_diameter_m == 8.0
        assert cfg.dense_bed_height_m == 6.0
        assert cfg.freeboard_height_m == 24.0
        assert cfg.operating_pressure_kpa == 250.0

    def test_minimum_fluidization_velocity(self) -> None:
        """Requirement 3: Minimum fluidization velocity U_mf via Wen & Yu Archimedes correlation."""
        sim = FccRegeneratorSimulator()
        hydro = sim.compute_hydrodynamics(t_bed_k=710.0 + T_ZERO_CELSIUS, p_dense_pa=250000.0)

        u_mf = hydro["u_mf"]
        u0 = hydro["u0"]

        assert 0.0005 <= u_mf <= 0.010, f"U_mf={u_mf} m/s must be in Geldart A range (0.5..10 mm/s)"
        assert u0 > u_mf * 10.0, f"U_0={u0} m/s must exceed 10x U_mf for vigorous bubbling fluidization"
        assert abs(u0 - 3.03) < 0.2

    def test_bubble_diameter_growth_and_rise_velocity(self) -> None:
        """Requirement 3: Darton bubble diameter growth d_b(z) and Davidson-Harrison rise velocity u_b."""
        sim = FccRegeneratorSimulator()
        hydro = sim.compute_hydrodynamics()

        db = hydro["bubble_diameter_m"]
        ub = hydro["bubble_velocity_m_s"]
        u0 = hydro["u0"]

        assert 0.10 <= db <= 0.50, f"Mean bubble diameter {db} m must be in stable Geldart A range"
        assert ub > u0, f"Bubble velocity {ub} m/s must exceed superficial gas velocity {u0} m/s"
        assert ub > 3.5

    def test_phase_volume_fractions_and_interphase_transfer(self) -> None:
        """Requirement 3: Bubble/emulsion volume fractions and Kunii-Levenspiel K_be interchange."""
        sim = FccRegeneratorSimulator()
        hydro = sim.compute_hydrodynamics()

        delta_b = hydro["delta_b"]
        delta_e = hydro["delta_e"]
        k_be = hydro["k_be"]

        assert 0.10 <= delta_b <= 0.60
        assert 0.40 <= delta_e <= 0.90
        assert abs((delta_b + delta_e) - 1.0) < 1e-9
        assert k_be > 0.1, f"K_be interchange coefficient {k_be} 1/s must be > 0.1"

    def test_catalyst_mean_residence_time(self) -> None:
        """Requirement 3: Catalyst mean residence time tau = M_bed / m_spent (~258.8 s, ~4.31 min)."""
        sim = FccRegeneratorSimulator()
        tau = sim.mean_residence_time_s
        expected_tau = 220000.0 / 850.0  # 258.8235 s

        assert abs(tau - expected_tau) < 1e-4
        assert abs(sim.config.catalyst_mean_residence_time_s - expected_tau) < 1e-4
        assert 240.0 <= tau <= 280.0

    def test_catalyst_residence_time_distribution_e_and_f(self) -> None:
        """Requirement 3: Ideal CSTR RTD functions E(t) = (1/tau)*exp(-t/tau) and F(t) = 1 - exp(-t/tau)."""
        sim = FccRegeneratorSimulator()
        tau = sim.mean_residence_time_s

        # At t = 0
        rtd_0 = sim.compute_catalyst_rtd(0.0)
        assert abs(rtd_0["e_t"] - (1.0 / tau)) < 1e-6
        assert rtd_0["f_t"] == 0.0

        # At t = tau
        f_tau = sim.catalyst_rtd_f(tau)
        expected_f_tau = 1.0 - math.exp(-1.0)  # ~0.6321
        assert abs(f_tau - expected_f_tau) < 1e-4

        # At t = 5*tau
        f_5tau = sim.catalyst_rtd_f(5.0 * tau)
        assert f_5tau > 0.99  # > 99% of catalyst has resided within 5 mean residence times

        # Numerical integration of E(t) over [0, 10*tau] must approximate 1.0
        n_steps = 1000
        dt = (10.0 * tau) / float(n_steps)
        integral = sum(sim.catalyst_rtd_e((i + 0.5) * dt) * dt for i in range(n_steps))
        assert abs(integral - 1.0) < 0.001

    def test_cyclone_system_dp_and_efficiency(self) -> None:
        """Requirement 3: Two-stage primary/secondary cyclones differential pressure and recovery."""
        sim = FccRegeneratorSimulator()
        assert sim.config.cyclone_overall_efficiency == 0.9998  # 99.98%
        assert sim.config.cyclone_dp_nominal_kpa == 45.0
        assert sim.config.cyclone_dp_trip_kpa == 80.0
        assert 20.0 <= sim.state.cyclone_dp_kpa <= 75.0


# ============================================================================
# 4. Section 4: Heterogeneous Coke Combustion & CO Afterburning Reaction Kinetics
# ============================================================================

class TestSection4CokeCombustionAndAfterburningKinetics:
    """Tests for surface coke combustion reactions (r1, r2) and freeboard CO afterburning (r3)."""

    def test_reaction_stoichiometry_and_enthalpies(self) -> None:
        """Requirement 4: Verify exothermic standard heats of reaction."""
        # r1: C + 0.5 O2 -> CO (-110.53 kJ/mol)
        assert DELTA_H_R1_J_MOL == -110530.0
        # r2: C + O2 -> CO2 (-393.51 kJ/mol)
        assert DELTA_H_R2_J_MOL == -393510.0
        # r3: CO + 0.5 O2 -> CO2 (-282.98 kJ/mol)
        assert DELTA_H_R3_J_MOL == -282980.0

        # Enthalpy of complete combustion equals sum of partial + afterburning
        assert abs((DELTA_H_R1_J_MOL + DELTA_H_R3_J_MOL) - DELTA_H_R2_J_MOL) < 1.0

    def test_arrhenius_temperature_monotonicity(self) -> None:
        """Requirement 4: Arrhenius reaction rate constants increase monotonically with temperature."""
        sim = FccRegeneratorSimulator()

        rx_680 = sim.compute_reaction_rates(680.0 + T_ZERO_CELSIUS, 705.0 + T_ZERO_CELSIUS, 0.035, 250000.0, 1.5, 450.0)
        rx_710 = sim.compute_reaction_rates(710.0 + T_ZERO_CELSIUS, 735.0 + T_ZERO_CELSIUS, 0.035, 250000.0, 1.5, 450.0)
        rx_740 = sim.compute_reaction_rates(740.0 + T_ZERO_CELSIUS, 765.0 + T_ZERO_CELSIUS, 0.035, 250000.0, 1.5, 450.0)

        assert rx_680["k1"] < rx_710["k1"] < rx_740["k1"]
        assert rx_680["k2"] < rx_710["k2"] < rx_740["k2"]
        assert rx_680["k3"] < rx_710["k3"] < rx_740["k3"]

    def test_catalyst_coke_reduction_efficiency(self) -> None:
        """Requirement 4: Spent catalyst coke reduced from ~1.2 wt% to < 0.05 wt% (> 95% removal)."""
        sim = FccRegeneratorSimulator()
        spent_coke = sim.config.spent_coke_wt_pct
        regen_coke = sim.state.c_coke_wt_pct
        removal_ratio = (spent_coke - regen_coke) / spent_coke

        assert spent_coke == 1.20
        assert regen_coke < 0.05
        assert removal_ratio > 0.95

    def test_nominal_coke_combustion_mass_rate(self) -> None:
        """Requirement 4: Instantaneous coke combustion mass rate matches nominal ~12.5 kg/s (%R1074)."""
        sim = FccRegeneratorSimulator()
        rx = sim.compute_reaction_rates(710.0 + T_ZERO_CELSIUS, 735.0 + T_ZERO_CELSIUS, 0.035, 250000.0, 1.5, 450.0)

        assert abs(rx["coke_burn_rate_kg_s"] - 12.5) < 0.5
        assert rx["coke_burn_rate_kg_s"] > 5.0

    def test_freeboard_co_afterburning_kinetics_and_exothermicity(self) -> None:
        """Requirement 4: Freeboard homogeneous CO afterburning produces positive exothermic heat scaling with CO slip."""
        sim = FccRegeneratorSimulator()

        # Low CO slip (200 ppm, 720 °C) vs High CO slip (800 ppm, 760 °C)
        rx_low = sim.compute_reaction_rates(710.0 + T_ZERO_CELSIUS, 720.0 + T_ZERO_CELSIUS, 0.035, 250000.0, 1.5, 200.0)
        rx_high = sim.compute_reaction_rates(710.0 + T_ZERO_CELSIUS, 760.0 + T_ZERO_CELSIUS, 0.035, 250000.0, 1.5, 800.0)

        assert rx_low["q_afterburn_kw"] > 0.0
        assert rx_high["q_afterburn_kw"] > rx_low["q_afterburn_kw"]
        assert rx_high["k3"] > rx_low["k3"]
        assert rx_high["r3_mol_s"] > 0.0
        assert rx_high["q_afterburn_kw"] > 5000.0

    def test_thermal_powers_in_dense_bed_and_freeboard(self) -> None:
        """Requirement 4: Dense bed and freeboard thermal power releases."""
        sim = FccRegeneratorSimulator()
        rx = sim.compute_reaction_rates(710.0 + T_ZERO_CELSIUS, 735.0 + T_ZERO_CELSIUS, 0.035, 250000.0, 1.5, 450.0)

        assert rx["q_dense_kw"] > 100000.0  # Massive combustion in bed (~350 MW)
        assert rx["q_afterburn_kw"] > 1000.0  # CO afterburning in freeboard (~5 MW)


# ============================================================================
# 5. Section 5: Coupled 6-State ODE RK4 Solver & Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection5CoupledODESystemAndRK4Solver:
    """Tests for 6-state ODE integration stability and dual carbon/oxygen mass and enthalpy conservation residuals."""

    def test_compute_derivatives_finite_and_stable(self) -> None:
        """Requirement 5: Compute derivatives produces finite values for all 6 state variables."""
        sim = FccRegeneratorSimulator()
        y = [
            sim.state.t_bed_c,
            sim.state.t_freeboard_c,
            sim.state.c_coke_wt_pct,
            sim.state.p_dense_kpa,
            sim.state.y_o2_vol_pct,
            sim.state.y_co_ppm,
        ]
        derivs = sim.compute_derivatives(0.0, y)

        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d) and not math.isinf(d)

    def test_rk4_step_integration(self) -> None:
        """Requirement 5: Single RK4 step increments time and preserves physical consistency."""
        sim = FccRegeneratorSimulator()
        t0 = sim.state.time_s
        sim.rk4_step(dt=0.05)

        assert abs(sim.state.time_s - (t0 + 0.05)) < 1e-9
        assert not math.isnan(sim.state.t_bed_c)
        assert not math.isnan(sim.state.t_freeboard_c)
        assert sim.state.c_coke_wt_pct > 0.0

    def test_rk4_multi_second_integration_stability(self) -> None:
        """Requirement 5: 5.0 seconds of RK4 integration maintains stable temperatures and concentrations."""
        sim = FccRegeneratorSimulator()
        res = sim.advance_time(duration_s=5.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 650.0 <= sim.state.t_bed_c <= 780.0
        assert 650.0 <= sim.state.t_freeboard_c <= 820.0
        assert 0.001 <= sim.state.c_coke_wt_pct <= 0.20
        assert 200.0 <= sim.state.p_dense_kpa <= 300.0
        assert 0.1 <= sim.state.y_o2_vol_pct <= 5.0
        assert sim.state.y_co_ppm >= 0.0

    def test_dual_stoichiometric_mass_conservation_residuals(self) -> None:
        """Requirement 5: Carbon, oxygen, and total mass balance residuals strictly < 1e-10 kg/s."""
        sim = FccRegeneratorSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.carbon_mass_balance_residual_kg_s < 1e-10
        assert sim.state.oxygen_mass_balance_residual_kg_s < 1e-10
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10

    def test_first_law_thermal_enthalpy_conservation_residual(self) -> None:
        """Requirement 5: Thermal enthalpy energy balance residual strictly < 1e-10 kW."""
        sim = FccRegeneratorSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Non-positive duration or dt fails closed with INVALID_TIMESTEP."""
        sim = FccRegeneratorSimulator()
        res_neg = sim.advance_time(duration_s=-1.0, dt=0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

        res_zero_dt = sim.advance_time(duration_s=1.0, dt=0.0)
        assert res_zero_dt.status == AgentStatus.FAILED
        assert res_zero_dt.error_code == "INVALID_TIMESTEP"


# ============================================================================
# 6. Section 6: Process Safety Interlocks & Diagnostics (0xAB01..0xAB04)
# ============================================================================

class TestSection6ProcessSafetyInterlocks:
    """Tests for process safety trips (0xAB01, 0xAB02, 0xAB03, 0xAB04) and priority hierarchy."""

    def test_afterburning_runaway_trip_delta_t_0xab01(self) -> None:
        """Requirement 6: (T_fb - T_bed > 40 C) asserts %M250 (AfterburningThermalRunawayTrip) and clears %M249."""
        sim = FccRegeneratorSimulator()
        sim.state.t_bed_c = 710.0
        sim.state.t_freeboard_c = 755.0  # Delta T = 45 C > 40 C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorDiagnosticCode.FCC_ERR_AFTERBURNING_RUNAWAY
        assert sim.state.afterburning_runaway_trip is True
        assert sim.state.air_blower_permissive is False
        assert sim.reg_table.read_bit("%M250") is True
        assert sim.reg_table.read_bit("%M249") is False
        assert (sim.reg_table.read_word("%R1077") & 0xFFFF) == 0xAB01

    def test_afterburning_runaway_trip_absolute_t_0xab01(self) -> None:
        """Requirement 6: T_fb > 780 C asserts %M250 and clears %M249 even if Delta T <= 40 C."""
        sim = FccRegeneratorSimulator()
        sim.state.t_bed_c = 750.0
        sim.state.t_freeboard_c = 785.0  # Delta T = 35 C, but T_fb > 780 C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xAB01
        assert sim.state.afterburning_runaway_trip is True
        assert sim.state.air_blower_permissive is False
        assert sim.reg_table.read_bit("%M250") is True
        assert sim.reg_table.read_bit("%M249") is False
        assert (sim.reg_table.read_word("%R1077") & 0xFFFF) == 0xAB01

    def test_dense_bed_high_temp_alarm_0xab02(self) -> None:
        """Requirement 6: T_bed > 760 C asserts %M251 (DenseBedHighTempAlarm), blower permissive stays True."""
        sim = FccRegeneratorSimulator()
        sim.state.t_bed_c = 765.0
        sim.state.t_freeboard_c = 770.0  # Delta T = 5 C, T_fb <= 780 C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorDiagnosticCode.FCC_ERR_DENSE_BED_OVERTEMP
        assert sim.state.dense_bed_high_temp_alarm is True
        assert sim.state.air_blower_permissive is True
        assert sim.reg_table.read_bit("%M251") is True
        assert sim.reg_table.read_bit("%M249") is True
        assert (sim.reg_table.read_word("%R1077") & 0xFFFF) == 0xAB02

    def test_cyclone_dipleg_flooding_fault_0xab03(self) -> None:
        """Requirement 6: Cyclone dP > 80 kPa triggers 0xAB03 fault."""
        sim = FccRegeneratorSimulator()
        sim.state.cyclone_dp_kpa = 85.0  # > 80.0 kPa
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorDiagnosticCode.FCC_ERR_CYCLONE_DIPLEG_FLOODING
        assert sim.state.cyclone_flooding_fault is True
        assert (sim.reg_table.read_word("%R1077") & 0xFFFF) == 0xAB03

    def test_o2_deficiency_fault_0xab04(self) -> None:
        """Requirement 6: Flue gas O2 < 0.20 vol% triggers 0xAB04 fault."""
        sim = FccRegeneratorSimulator()
        sim.state.y_o2_vol_pct = 0.15  # < 0.20%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorDiagnosticCode.FCC_ERR_O2_DEFICIENCY
        assert sim.state.o2_deficiency_fault is True
        assert (sim.reg_table.read_word("%R1077") & 0xFFFF) == 0xAB04

    def test_safety_priority_hierarchy(self) -> None:
        """Requirement 6: Priority hierarchy: Afterburning Runaway (0xAB01) > Bed Overtemp (0xAB02) > Cyclone (0xAB03) > O2 Deficiency (0xAB04)."""
        sim = FccRegeneratorSimulator()

        # All four fault conditions active
        sim.state.t_bed_c = 765.0       # 0xAB02
        sim.state.t_freeboard_c = 810.0 # 0xAB01 (Delta T = 45 C, T_fb > 780 C)
        sim.state.cyclone_dp_kpa = 85.0 # 0xAB03
        sim.state.y_o2_vol_pct = 0.15   # 0xAB04

        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0xAB01
        assert sim.state.air_blower_permissive is False

        # Clear afterburn runaway -> next is bed overtemp 0xAB02
        sim.state.t_freeboard_c = 770.0  # Delta T = 5 C, T_fb <= 780 C
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0xAB02
        assert sim.state.air_blower_permissive is True

        # Clear bed overtemp -> next is cyclone flooding 0xAB03
        sim.state.t_bed_c = 710.0
        sim.state.t_freeboard_c = 735.0  # Delta T = 25 C <= 40 C
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0xAB03

        # Clear cyclone flooding -> next is O2 deficiency 0xAB04
        sim.state.cyclone_dp_kpa = 45.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0xAB04

        # Clear O2 deficiency -> healthy normal 0x0000
        sim.state.y_o2_vol_pct = 1.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0x0000
        assert sim.state.air_blower_permissive is True
        assert sim.state.afterburning_runaway_trip is False
        assert sim.state.dense_bed_high_temp_alarm is False


# ============================================================================
# 7. Section 7: Horner OCS Register Space Synchronization (%R1070..%R1077, %M249..%M251)
# ============================================================================

class TestSection7HornerOCSSync:
    """Tests for Horner OCS memory register bindings (%R1070..%R1077, %M249..%M251) and class compatibility aliases."""

    def test_nominal_register_sync(self) -> None:
        """Requirement 7: Verify analog registers %R1070..%R1077 and discrete coils %M249..%M251."""
        sim = FccRegeneratorSimulator()
        reg = sim.reg_table

        # %R1070: DenseBedTempCelsius (scaled x10 C, e.g. 7100 = 710.0 C)
        assert reg.read_word("%R1070") == 7100

        # %R1071: FreeboardTempCelsius (scaled x10 C, e.g. 7350 = 735.0 C)
        assert reg.read_word("%R1071") == 7350

        # %R1072: FlueGasCoPpm (scaled x1 ppm, e.g. 450 = 450 ppm)
        assert reg.read_word("%R1072") == 450

        # %R1073: FlueGasO2VolPct (scaled x10 %, e.g. 15 = 1.5% O2)
        assert reg.read_word("%R1073") == 15

        # %R1074: CokeCombustionRateKgs (scaled x10 kg/s, e.g. 125 = 12.5 kg/s)
        assert reg.read_word("%R1074") == 125

        # %R1075: SpentCatalystFlowRateKgs (scaled x10 kg/s, e.g. 8500 = 850.0 kg/s)
        assert reg.read_word("%R1075") == 8500

        # %R1076: CycloneDifferentialPressureKpa (scaled x10 kPa, e.g. 450 = 45.0 kPa)
        assert reg.read_word("%R1076") == 450

        # %R1077: DiagnosticStatusCode (0x0000 = OK)
        assert (reg.read_word("%R1077") & 0xFFFF) == 0x0000

        # %M249: RegeneratorAirBlowerPermissive (BOOL)
        assert reg.read_bit("%M249") is True

        # %M250: AfterburningThermalRunawayTrip (BOOL)
        assert reg.read_bit("%M250") is False

        # %M251: DenseBedHighTempAlarm (BOOL)
        assert reg.read_bit("%M251") is False

    def test_class_compatibility_aliases(self) -> None:
        """Requirement 7: Verify all required class and module aliases exist."""
        assert FccSimulator is FccRegeneratorSimulator
        assert FluidizedBedRegeneratorSimulator is FccRegeneratorSimulator
        assert FccRegeneratorSimulationEngine is FccRegeneratorSimulator
        assert FccRegeneratorModel is FccRegeneratorSimulator
        assert FccRegeneratorPlantModel is FccRegeneratorSimulator
        assert FccEngine is FccRegeneratorSimulator
        assert FccRegeneratorEngine is FccRegeneratorSimulator
        assert FluidizedBedRegeneratorEngine is FccRegeneratorSimulator
        assert FluidizedBedRegeneratorModel is FccRegeneratorSimulator
        assert FluidizedBedRegeneratorSimulationEngine is FccRegeneratorSimulator
        assert FluidizedBedRegeneratorPlantModel is FccRegeneratorSimulator

        assert FccConfig is FccRegeneratorConfig
        assert FluidizedBedRegeneratorConfig is FccRegeneratorConfig
        assert FccParameters is FccRegeneratorConfig
        assert FccRegeneratorParameters is FccRegeneratorConfig
        assert FluidizedBedRegeneratorParameters is FccRegeneratorConfig

        assert FccState is FccRegeneratorState
        assert FluidizedBedRegeneratorState is FccRegeneratorState

        assert FccStatusBits is FccRegeneratorStatusBits
        assert FluidizedBedRegeneratorStatusBits is FccRegeneratorStatusBits
        assert FccRegeneratorStatusWord is FccRegeneratorStatusBits
        assert FccStatusWord is FccRegeneratorStatusBits
        assert FluidizedBedRegeneratorStatusWord is FccRegeneratorStatusBits

        assert FccDiagnosticCode is FccRegeneratorDiagnosticCode
        assert FluidizedBedRegeneratorDiagnosticCode is FccRegeneratorDiagnosticCode
        assert FccDiagCode is FccRegeneratorDiagnosticCode


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Test & Evidence JSON
# ============================================================================

class TestSection8FccVerificationRunner:
    """Tests for run_fcc_regenerator_verification function and evidence artifact generation."""

    def test_run_fcc_regenerator_verification_suite_all_9_stages(self, tmp_path: Path) -> None:
        """Requirement 8: Execute full 9-stage verification suite and assert strict success."""
        out_file = str(tmp_path / "w146_fcc_regenerator_evidence.json")
        res = run_fcc_regenerator_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "Industrial FCC Regenerator Two-Phase Hydrodynamics & Coke Combustion ODE Simulation verified cleanly (9/9 checks passed)" in res["details"]

        data = res["data"]
        assert data["work_package"] == "W146"
        assert data["gate"] == "Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation"
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9

        tests = data["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True, f"Stage {t['stage']} ({t['check']}) failed: {t['details']}"

        # Verify evidence JSON file written to disk
        evidence_file = Path(out_file)
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
        assert saved_data["status"] == "success"
        assert saved_data["data"]["checks_passed"] == 9

    def test_run_fcc_regenerator_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 8: Test evidence_path compatibility alias parameter."""
        ev_file = tmp_path / "fcc_alias_evidence.json"
        res = run_fcc_regenerator_verification(evidence_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_fluidized_bed_regenerator_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Test run_fluidized_bed_regenerator_verification function alias."""
        ev_file = tmp_path / "fluid_bed_alias_evidence.json"
        res = run_fluidized_bed_regenerator_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_fcc_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Test run_fcc_verification function alias."""
        ev_file = tmp_path / "fcc_func_alias_evidence.json"
        res = run_fcc_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_regenerator_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Test run_regenerator_verification function alias."""
        ev_file = tmp_path / "regen_alias_evidence.json"
        res = run_regenerator_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()
