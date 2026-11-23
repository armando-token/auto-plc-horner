"""Unit and Integration Tests for Industrial Hydrocracking High-Pressure Trickle-Bed Reactor Simulation.

Work Package: W149 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1100..%R1107, %M256..%M258).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: High-pressure trickle-bed multi-phase hydrodynamics, liquid holdup, two-phase dP, and kLa mass transfer.
4. Section 4: Exothermic hydrotreating (HDS) & hydrocracking reaction kinetics, Arrhenius monotonicity, -180 kJ/mol exotherm, and quench mixing.
5. Section 5: Coupled ODE RK4 integration stability and dual conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xAE01, 0xAE02, 0xAE03, 0xAE04) and Horner coil assertion (%M256, %M257, %M258).
7. Section 7: Horner OCS register space synchronization (%R1100..%R1107, %M256..%M258).
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
from jev_cscape.simulation.hydrocracker_tbr import (
    DELTA_H_CRACK_J_MOL_H2,
    DELTA_H_HCK_J_MOL,
    DELTA_H_HDS_J_MOL,
    DELTA_H_HDS_J_MOL_H2,
    DELTA_H_HYDROPROCESSING_J_MOL_H2,
    HYDROCRACKER_DYNAMICS_SYNC_POU,
    HYDROCRACKER_PURE_ST_POU,
    HYDROCRACKER_SYNC_POU,
    HYDROCRACKER_TBR_DYNAMICS_SYNC_POU,
    HYDROCRACKER_TBR_PURE_ST_POU,
    HYDROCRACKER_TBR_SYNC_POU,
    MW_DIESEL,
    MW_FEED_OIL,
    MW_H2,
    MW_H2S,
    MW_HEAVY,
    MW_LIGHT,
    MW_OIL,
    MW_SULFUR,
    R_GAS_CONST,
    TBR_PURE_ST_POU,
    TBR_SYNC_POU,
    TRICKLE_BED_REACTOR_PURE_ST_POU,
    TRICKLE_BED_REACTOR_SYNC_POU,
    T_ZERO_CELSIUS,
    HydrocrackerConfig,
    HydrocrackerDiagCode,
    HydrocrackerDiagnosticCode,
    HydrocrackerEngine,
    HydrocrackerParameters,
    HydrocrackerSimulator,
    HydrocrackerState,
    HydrocrackerStatusBits,
    HydrocrackerStatusWord,
    HydrocrackerTbrConfig,
    HydrocrackerTbrDiagnosticCode,
    HydrocrackerTbrEngine,
    HydrocrackerTbrModel,
    HydrocrackerTbrParameters,
    HydrocrackerTbrPlantModel,
    HydrocrackerTbrSimulationEngine,
    HydrocrackerTbrSimulator,
    HydrocrackerTbrState,
    HydrocrackerTbrStatusBits,
    HydrocrackerTbrStatusWord,
    TbrConfig,
    TbrDiagCode,
    TbrDiagnosticCode,
    TbrEngine,
    TbrModel,
    TbrParameters,
    TbrSimulator,
    TbrState,
    TbrStatusBits,
    TbrStatusWord,
    TrickleBedReactorConfig,
    TrickleBedReactorDiagnosticCode,
    TrickleBedReactorEngine,
    TrickleBedReactorModel,
    TrickleBedReactorParameters,
    TrickleBedReactorPlantModel,
    TrickleBedReactorSimulationEngine,
    TrickleBedReactorSimulator,
    TrickleBedReactorState,
    TrickleBedReactorStatusBits,
    run_hydrocracker_tbr_verification,
    run_hydrocracker_verification,
    run_tbr_verification,
    run_trickle_bed_reactor_verification,
    verify_hydrocracker_pure_st,
    verify_hydrocracker_tbr_pure_st,
    verify_tbr_pure_st,
    verify_trickle_bed_pure_st,
    verify_trickle_bed_reactor_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1100..%R1107, %M256..%M258)."""

    def test_verify_hydrocracker_tbr_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_hydrocracker_tbr_pure_st() is True
        assert verify_hydrocracker_pure_st() is True
        assert verify_trickle_bed_pure_st() is True
        assert verify_trickle_bed_reactor_pure_st() is True
        assert verify_tbr_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1100..%R1107, %M256..%M258)."""
        SecurityGuard.assert_pure_st_content(HYDROCRACKER_TBR_PURE_ST_POU)
        val = STParser.validate_code(HYDROCRACKER_TBR_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(HYDROCRACKER_TBR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "HydrocrackerTbrSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1100", "%R1101", "%R1102", "%R1103",
            "%R1104", "%R1105", "%R1106", "%R1107",
            "%M256", "%M257", "%M258",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Verify HydrocrackerTbrSync aliases parse cleanly."""
        for pou_text in [
            HYDROCRACKER_PURE_ST_POU,
            HYDROCRACKER_SYNC_POU,
            HYDROCRACKER_TBR_SYNC_POU,
            HYDROCRACKER_DYNAMICS_SYNC_POU,
            HYDROCRACKER_TBR_DYNAMICS_SYNC_POU,
        ]:
            SecurityGuard.assert_pure_st_content(pou_text)
            ast = STParser.parse_pou(pou_text)
            assert ast is not None
            assert ast.pou_type == POUType.PROGRAM
            for reg in [
                "%R1100", "%R1101", "%R1102", "%R1103",
                "%R1104", "%R1105", "%R1106", "%R1107",
                "%M256", "%M257", "%M258",
            ]:
                assert reg in ast.bound_registers

    def test_trickle_bed_reactor_aliases(self) -> None:
        """Requirement 1: Verify TrickleBedReactorSync and TbrSync aliases AST parsing."""
        for pou_text, expected_name in [
            (TRICKLE_BED_REACTOR_PURE_ST_POU, "TrickleBedReactorSync"),
            (TRICKLE_BED_REACTOR_SYNC_POU, "TrickleBedReactorSync"),
            (TBR_PURE_ST_POU, "TbrSync"),
            (TBR_SYNC_POU, "TbrSync"),
        ]:
            SecurityGuard.assert_pure_st_content(pou_text)
            ast = STParser.parse_pou(pou_text)
            assert ast is not None
            assert ast.name == expected_name
            assert ast.pou_type == POUType.PROGRAM
            assert "%R1100" in ast.bound_registers
            assert "%M256" in ast.bound_registers


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
            "XIC HydrocrackerPermissive",
            "XIO ExothermicThermalRunawayTrip",
            "OTE InterbedQuenchValveActive",
            "OTL FeedPumpRunning",
            "OTU EmergencyDepressurizationActive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: All ladder constructs must trigger LadderForbiddenError."""
        invalid_st = f"""
        PROGRAM BadLadderHydrocracker
        VAR
            TestVar : BOOL;
        END_VAR
        {ladder_snippet}
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(invalid_st)


# ============================================================================
# 3. Section 3: Trickle-Bed Hydrodynamics & Gas-Liquid Mechanics
# ============================================================================

class TestSection3TrickleBedHydrodynamicsAndMassTransfer:
    """Tests for two-phase trickle bed hydrodynamics, holdup, pressure drop, and kLa mass transfer."""

    def test_reactor_and_bed_dimensions(self) -> None:
        """Requirement 3: Verify reactor geometry and catalyst bed inventory parameters."""
        cfg = HydrocrackerTbrConfig()
        assert cfg.reactor_diameter_m == 3.2
        assert cfg.bed1_height_m == 10.0
        assert cfg.bed2_height_m == 12.0
        assert cfg.catalyst_particle_diameter_m == 0.0015
        assert cfg.catalyst_bulk_density_kg_m3 == 900.0
        assert cfg.catalyst_particle_density_kg_m3 == 1450.0
        assert cfg.total_catalyst_inventory_kg == 158000.0
        assert cfg.bed_voidage_fraction == 0.38

        # Derived properties
        assert abs(cfg.bed_cross_section_area_m2 - (math.pi * 1.6 ** 2)) < 1e-4
        assert cfg.bed1_thermal_capacitance_j_k > 0.0
        assert cfg.bed2_thermal_capacitance_j_k > 0.0

    def test_gas_liquid_superficial_velocities(self) -> None:
        """Requirement 3: Gas and liquid superficial velocities in high-pressure trickle bed."""
        sim = HydrocrackerTbrSimulator()
        hydro = sim.compute_hydrodynamics(
            t_bed1_k=395.0 + T_ZERO_CELSIUS,
            t_bed2_k=410.0 + T_ZERO_CELSIUS,
            p_react_bar=165.0,
            m_quench_kg_s=8.5,
        )

        u_l = hydro["u_l_m_s"]
        u_g = hydro["u_g_m_s"]

        assert 0.005 <= u_l <= 0.050, f"u_L={u_l} m/s must be in typical trickle range (5..50 mm/s)"
        assert 0.05 <= u_g <= 0.45, f"u_G={u_g} m/s must be in typical high-pressure gas range (0.05..0.45 m/s)"

    def test_liquid_holdup_fraction(self) -> None:
        """Requirement 3: Verify dynamic liquid holdup is in physical range for high-pressure trickle bed."""
        sim = HydrocrackerTbrSimulator()
        hydro = sim.compute_hydrodynamics(
            t_bed1_k=395.0 + T_ZERO_CELSIUS,
            t_bed2_k=410.0 + T_ZERO_CELSIUS,
            p_react_bar=165.0,
            m_quench_kg_s=8.5,
        )
        eps_l = hydro["liquid_holdup_fraction"]
        assert 0.10 <= eps_l <= 0.40

    def test_two_phase_pressure_drop(self) -> None:
        """Requirement 3: Two-phase pressure drop across catalyst beds."""
        sim = HydrocrackerTbrSimulator()
        hydro = sim.compute_hydrodynamics(
            t_bed1_k=395.0 + T_ZERO_CELSIUS,
            t_bed2_k=410.0 + T_ZERO_CELSIUS,
            p_react_bar=165.0,
        )
        dp = hydro["two_phase_dp_bar"]
        assert 5.0 <= dp <= 25.0

    def test_volumetric_mass_transfer_kla(self) -> None:
        """Requirement 3: Gas-liquid volumetric mass transfer coefficient k_L a."""
        sim = HydrocrackerTbrSimulator()
        hydro = sim.compute_hydrodynamics(
            t_bed1_k=395.0 + T_ZERO_CELSIUS,
            t_bed2_k=410.0 + T_ZERO_CELSIUS,
            p_react_bar=165.0,
        )
        kla = hydro["kla_mass_transfer_s_inv"]
        assert 0.02 <= kla <= 0.30


# ============================================================================
# 4. Section 4: Exothermic Reactions & Interbed Quench Kinetics
# ============================================================================

class TestSection4ExothermicReactionsAndQuenchKinetics:
    """Tests for HDS and hydrocracking reaction kinetics, Arrhenius monotonicity, and interbed quench mixing."""

    def test_reaction_stoichiometry_and_enthalpy(self) -> None:
        """Requirement 4: Verify reaction network exothermicity (-180 kJ/mol H2)."""
        assert DELTA_H_HYDROPROCESSING_J_MOL_H2 == -180000.0
        assert DELTA_H_HDS_J_MOL_H2 == -180000.0
        assert DELTA_H_CRACK_J_MOL_H2 == -180000.0

    def test_arrhenius_temperature_monotonicity(self) -> None:
        """Requirement 4: Reaction rate constants must increase monotonically with temperature."""
        sim = HydrocrackerTbrSimulator()
        rx_380 = sim.compute_reaction_rates(380.0 + T_ZERO_CELSIUS, 395.0 + T_ZERO_CELSIUS, 165.0, 144.48, 15.0)
        rx_400 = sim.compute_reaction_rates(400.0 + T_ZERO_CELSIUS, 415.0 + T_ZERO_CELSIUS, 165.0, 144.48, 15.0)
        rx_420 = sim.compute_reaction_rates(420.0 + T_ZERO_CELSIUS, 435.0 + T_ZERO_CELSIUS, 165.0, 144.48, 15.0)

        assert rx_380["k_hds_b1"] < rx_400["k_hds_b1"] < rx_420["k_hds_b1"]
        assert rx_380["k_crack_b1"] < rx_400["k_crack_b1"] < rx_420["k_crack_b1"]

    def test_conversion_yield_and_sulfur_removal(self) -> None:
        """Requirement 4: Cracking conversion yield and sulfur removal performance."""
        sim = HydrocrackerTbrSimulator()
        assert 70.0 <= sim.state.conversion_yield_pct <= 90.0
        assert sim.state.c_sulfur_ppm <= 20.0
        # HDS conversion > 99%
        s_feed = sim.config.feed_sulfur_ppm
        s_eff = sim.state.c_sulfur_ppm
        assert ((s_feed - s_eff) / s_feed) * 100.0 > 99.0

    def test_interbed_quench_cooling_dynamics(self) -> None:
        """Requirement 4: Interbed cold hydrogen quench gas cooling effectiveness."""
        sim = HydrocrackerTbrSimulator()
        t_mix_no_quench = sim.compute_interbed_quench_mixing(t_bed1_c=395.0, m_quench_kg_s=0.0)
        t_mix_nom_quench = sim.compute_interbed_quench_mixing(t_bed1_c=395.0, m_quench_kg_s=8.5)
        t_mix_high_quench = sim.compute_interbed_quench_mixing(t_bed1_c=395.0, m_quench_kg_s=15.0)

        assert abs(t_mix_no_quench - 395.0) < 1e-5
        assert t_mix_nom_quench < t_mix_no_quench
        assert t_mix_high_quench < t_mix_nom_quench
        delta_t = t_mix_no_quench - t_mix_nom_quench
        assert 5.0 <= delta_t <= 18.0


# ============================================================================
# 5. Section 5: Coupled 6-State ODE System & RK4 Solver
# ============================================================================

class TestSection5CoupledODESystemAndRK4Solver:
    """Tests for RK4 numerical integration, derivatives, and conservation residuals (< 1e-10)."""

    def test_compute_derivatives_finite_and_stable(self) -> None:
        """Requirement 5: All 6 dynamic state derivatives must be finite and well-conditioned."""
        sim = HydrocrackerTbrSimulator()
        y = [
            sim.state.t_bed1_c,
            sim.state.t_bed2_c,
            sim.state.p_react_bar,
            sim.state.c_heavy_kg_m3,
            sim.state.c_sulfur_ppm,
            sim.state.m_quench_kg_s,
        ]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6
        assert all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    def test_rk4_step_integration(self) -> None:
        """Requirement 5: Single RK4 integration step advances time and updates states."""
        sim = HydrocrackerTbrSimulator()
        t0 = sim.state.time_s
        sim.rk4_step(dt=0.05)
        assert abs(sim.state.time_s - (t0 + 0.05)) < 1e-9
        assert 370.0 <= sim.state.t_bed1_c <= 425.0
        assert 380.0 <= sim.state.t_bed2_c <= 430.0

    def test_rk4_multi_second_integration_stability(self) -> None:
        """Requirement 5: 5-second dynamic integration maintains physical stability."""
        sim = HydrocrackerTbrSimulator()
        res = sim.advance_time(duration_s=5.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert 370.0 <= sim.state.t_bed1_c <= 425.0
        assert 380.0 <= sim.state.t_bed2_c <= 430.0
        assert 150.0 <= sim.state.p_react_bar <= 180.0
        assert 50.0 <= sim.state.c_heavy_kg_m3 <= 300.0
        assert 0.1 <= sim.state.c_sulfur_ppm <= 50.0
        assert 2.0 <= sim.state.m_quench_kg_s <= 20.0

    def test_dual_stoichiometric_mass_conservation_residuals(self) -> None:
        """Requirement 5: Stoichiometric mass conservation residual must be strictly < 1e-10 kg/s."""
        sim = HydrocrackerTbrSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.hydrocarbon_mass_balance_residual_kg_s < 1.0e-10

    def test_first_law_thermal_enthalpy_conservation_residual(self) -> None:
        """Requirement 5: First-law thermal enthalpy energy conservation residual must be strictly < 1e-10 kW."""
        sim = HydrocrackerTbrSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Non-positive timesteps must fail closed."""
        sim = HydrocrackerTbrSimulator()
        res_zero = sim.advance_time(duration_s=0.0, dt=0.05)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=-5.0, dt=0.05)
        assert res_neg.status == AgentStatus.FAILED


# ============================================================================
# 6. Section 6: Process Safety Interlocks & Diagnostics
# ============================================================================

class TestSection6ProcessSafetyInterlocks:
    """Tests for safety diagnostics (0xAE01..0xAE04) and Horner coil assertions (%M256..%M258)."""

    def test_thermal_runaway_trip_temperature_0xae01(self) -> None:
        """Requirement 6: 0xAE01 asserted on high bed temperature (> 430 °C)."""
        sim = HydrocrackerTbrSimulator()
        sim.state.t_bed1_c = 432.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xAE01
        assert sim.state.exothermic_thermal_runaway_trip is True
        assert sim.state.hydrocracker_permissive is False
        assert sim.state.interbed_quench_valve_active is True

    def test_thermal_runaway_trip_heating_rate_0xae01(self) -> None:
        """Requirement 6: 0xAE01 asserted on high heating rate (> 5.0 °C/min)."""
        sim = HydrocrackerTbrSimulator()
        sim.state.t_bed1_c = 410.0
        sim.state.t_bed2_c = 415.0
        sim.state.dt_bed2_dt_c_min = 6.2  # > 5.0 °C/min
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xAE01
        assert sim.state.exothermic_thermal_runaway_trip is True
        assert sim.state.hydrocracker_permissive is False

    def test_quench_failure_deficit_0xae02(self) -> None:
        """Requirement 6: 0xAE02 asserted on quench gas deficit (< 4.0 kg/s)."""
        sim = HydrocrackerTbrSimulator()
        sim.state.t_bed1_c = 395.0
        sim.state.t_bed2_c = 410.0
        sim.state.dt_bed1_dt_c_min = 0.0
        sim.state.dt_bed2_dt_c_min = 0.0
        sim.state.m_quench_kg_s = 2.5  # < 4.0 kg/s
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xAE02
        assert sim.state.interbed_quench_valve_active is True
        assert sim.state.hydrocracker_permissive is True

    def test_overpressure_trip_0xae03(self) -> None:
        """Requirement 6: 0xAE03 asserted on reactor overpressure (> 190.0 bar)."""
        sim = HydrocrackerTbrSimulator()
        sim.state.m_quench_kg_s = 8.5
        sim.state.p_react_bar = 194.5  # > 190.0 bar
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xAE03
        assert sim.state.hydrocracker_permissive is False

    def test_h2_oil_ratio_low_fault_0xae04(self) -> None:
        """Requirement 6: 0xAE04 asserted on low H2-to-oil treat gas ratio (< 800 Nm3/m3)."""
        sim = HydrocrackerTbrSimulator()
        sim.state.p_react_bar = 165.0
        sim.state.h2_oil_ratio_nm3_m3 = 750.0  # < 800 Nm3/m3
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xAE04
        assert sim.state.h2_oil_ratio_low_fault is True

    def test_safety_priority_hierarchy(self) -> None:
        """Requirement 6: Safety hierarchy priority (0xAE01 > 0xAE02 > 0xAE03 > 0xAE04)."""
        sim = HydrocrackerTbrSimulator()
        sim.state.t_bed1_c = 435.0             # 0xAE01
        sim.state.m_quench_kg_s = 2.0          # 0xAE02
        sim.state.p_react_bar = 195.0          # 0xAE03
        sim.state.h2_oil_ratio_nm3_m3 = 600.0  # 0xAE04
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xAE01


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration
# ============================================================================

class TestSection7HornerOCSSync:
    """Tests for Horner OCS memory register bindings (%R1100..%R1107, %M256..%M258)."""

    def test_nominal_register_sync(self) -> None:
        """Requirement 7: Verify all registers synchronize to RegisterTable accurately."""
        reg = RegisterTable()
        sim = HydrocrackerTbrSimulator(register_table=reg)

        sim.state.t_bed1_c = 395.0
        sim.state.t_bed2_c = 410.0
        sim.state.p_react_bar = 165.0
        sim.state.h2_oil_ratio_nm3_m3 = 1200.0
        sim.state.m_quench_kg_s = 8.5
        sim.state.conversion_yield_pct = 78.5
        sim.state.c_sulfur_ppm = 15.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1100") == 3950
        assert reg.read_word("%R1101") == 4100
        assert reg.read_word("%R1102") == 1650
        assert reg.read_word("%R1103") == 1200
        assert reg.read_word("%R1104") == 85
        assert reg.read_word("%R1105") == 785
        assert reg.read_word("%R1106") == 15
        assert reg.read_word("%R1107") & 0xFFFF == 0x0000

        assert reg.read_bit("%M256") is True
        assert reg.read_bit("%M257") is False
        assert reg.read_bit("%M258") is False

    def test_class_compatibility_aliases(self) -> None:
        """Requirement 7: Verify class and type compatibility aliases instantiate identically."""
        sim1 = HydrocrackerTbrSimulator()
        sim2 = HydrocrackerSimulator()
        sim3 = TrickleBedReactorSimulator()
        sim4 = TbrSimulator()
        sim5 = HydrocrackerTbrSimulationEngine()
        sim6 = HydrocrackerTbrModel()

        assert isinstance(sim1, HydrocrackerTbrSimulator)
        assert isinstance(sim2, HydrocrackerTbrSimulator)
        assert isinstance(sim3, HydrocrackerTbrSimulator)
        assert isinstance(sim4, HydrocrackerTbrSimulator)
        assert isinstance(sim5, HydrocrackerTbrSimulator)
        assert isinstance(sim6, HydrocrackerTbrSimulator)


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Runner
# ============================================================================

class TestSection8HydrocrackerVerificationRunner:
    """Tests for complete 9-stage verification suite runner and evidence JSON generation."""

    def test_run_hydrocracker_tbr_verification_suite_all_9_stages(self, tmp_path: Path) -> None:
        """Requirement 8: Run complete 9-stage verification suite and assert strict 4-state contract success."""
        evidence_file = tmp_path / "hydrocracker_tbr_evidence.json"
        res = run_hydrocracker_tbr_verification(output_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W149"
        assert res["data"]["gate"] == "Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["tests"]) == 9
        assert all(t["passed"] for t in res["data"]["tests"])

        # Check evidence file wrote correctly
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_run_hydrocracker_tbr_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 8: Verify evidence_path kwarg compatibility."""
        evidence_file = tmp_path / "evidence_kwarg.json"
        res = run_hydrocracker_tbr_verification(evidence_path=str(evidence_file))
        assert res["status"] == "success"
        assert evidence_file.exists()

    def test_run_trickle_bed_reactor_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Verify run_trickle_bed_reactor_verification alias."""
        evidence_file = tmp_path / "tbr_alias.json"
        res = run_trickle_bed_reactor_verification(output_path=str(evidence_file))
        assert res["status"] == "success"

    def test_run_hydrocracker_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Verify run_hydrocracker_verification alias."""
        evidence_file = tmp_path / "hck_alias.json"
        res = run_hydrocracker_verification(output_path=str(evidence_file))
        assert res["status"] == "success"

    def test_run_tbr_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Verify run_tbr_verification alias."""
        evidence_file = tmp_path / "tbr_short_alias.json"
        res = run_tbr_verification(output_path=str(evidence_file))
        assert res["status"] == "success"
