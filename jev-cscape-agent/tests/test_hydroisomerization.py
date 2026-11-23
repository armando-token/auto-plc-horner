"""Unit and Integration Tests for Industrial Hydroisomerization Dewaxing Trickle-Bed ODE Simulation.

Work Package: W170 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1310..%R1317, %M305..%M307).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Trickle-bed hydrodynamics, high-pressure hydrogen solubility, and liquid hourly space velocity (LHSV).
4. Section 4: Dual isomerization vs cracking kinetics, pour point depression curve, and Viscosity Index retention.
5. Section 5: Coupled ODE RK4 integration stability and dual elemental mass and thermal enthalpy conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xC301, 0xC302, 0xC303, 0xC304) and Horner coil assertion (%M305, %M306, %M307).
7. Section 7: Horner OCS register space synchronization (%R1310..%R1317, %M305..%M307) with signed INT16 pour point support and PrivilegeMode.SYSTEM.
8. Section 8: Dynamic disturbance response and settling stability.
9. Section 9: 9-stage verification suite integration test writing evidence JSON with strict 4-state contract.
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
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.hydroisomerization import (
    DELTA_H_CRACKING_J_MOL,
    DELTA_H_CRACKING_KJ_MOL,
    DELTA_H_CRACK_J_MOL,
    DELTA_H_CRACK_KJ_MOL,
    DELTA_H_ISOMERIZATION_J_MOL,
    DELTA_H_ISOMERIZATION_KJ_MOL,
    DELTA_H_ISOM_J_MOL,
    DELTA_H_ISOM_KJ_MOL,
    G_ACCEL,
    HYDROISOMERIZATION_DEWAXING_PURE_ST_POU,
    HYDROISOMERIZATION_DEWAXING_SYNC_POU,
    HYDROISOMERIZATION_PURE_ST_POU,
    HYDROISOMERIZATION_SYNC_POU,
    LUBE_DEWAXING_PURE_ST_POU,
    LUBE_DEWAXING_SYNC_POU,
    LUBE_DEWAXING_TRICKLE_BED_PURE_ST_POU,
    LUBE_DEWAXING_TRICKLE_BED_SYNC_POU,
    MW_FEED_OIL,
    MW_H2,
    MW_H2S,
    MW_ISO_PARAFFIN,
    MW_LIGHT_CRACKED,
    MW_LUBE_OIL,
    MW_N_PARAFFIN,
    MW_OIL,
    MW_SULFUR,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    HydroisomerizationConfig,
    HydroisomerizationDewaxingConfig,
    HydroisomerizationDewaxingDiagnosticCode,
    HydroisomerizationDewaxingLogicUnit,
    HydroisomerizationDewaxingSimulator,
    HydroisomerizationDewaxingState,
    HydroisomerizationDewaxingStatusBits,
    HydroisomerizationDiagCode,
    HydroisomerizationDiagnosticCode,
    HydroisomerizationEngine,
    HydroisomerizationLogicUnit,
    HydroisomerizationModel,
    HydroisomerizationParameters,
    HydroisomerizationPlantModel,
    HydroisomerizationSimulationEngine,
    HydroisomerizationSimulator,
    HydroisomerizationState,
    HydroisomerizationStatusBits,
    HydroisomerizationStatusWord,
    LubeDewaxingConfig,
    LubeDewaxingDiagCode,
    LubeDewaxingDiagnosticCode,
    LubeDewaxingEngine,
    LubeDewaxingLogicUnit,
    LubeDewaxingParameters,
    LubeDewaxingSimulator,
    LubeDewaxingState,
    LubeDewaxingStatusBits,
    LubeDewaxingStatusWord,
    LubeDewaxingTrickleBedConfig,
    LubeDewaxingTrickleBedDiagnosticCode,
    LubeDewaxingTrickleBedLogicUnit,
    LubeDewaxingTrickleBedSimulator,
    LubeDewaxingTrickleBedState,
    LubeDewaxingTrickleBedStatusBits,
    run_dewaxing_verification,
    run_hydroisomerization_dewaxing_verification,
    run_hydroisomerization_verification,
    run_lube_dewaxing_trickle_bed_verification,
    run_lube_dewaxing_verification,
    verify_hydroisomerization_dewaxing_pure_st,
    verify_hydroisomerization_pure_st,
    verify_lube_dewaxing_pure_st,
    verify_lube_dewaxing_trickle_bed_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1310..%R1317, %M305..%M307)."""

    def test_verify_hydroisomerization_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_hydroisomerization_pure_st() is True
        assert verify_hydroisomerization_dewaxing_pure_st() is True
        assert verify_lube_dewaxing_pure_st() is True
        assert verify_lube_dewaxing_trickle_bed_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1310..%R1317, %M305..%M307)."""
        SecurityGuard.assert_pure_st_content(HYDROISOMERIZATION_DEWAXING_PURE_ST_POU)
        val = STParser.validate_code(HYDROISOMERIZATION_DEWAXING_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(HYDROISOMERIZATION_DEWAXING_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "HydroisomerizationDewaxingSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1310", "%R1311", "%R1312", "%R1313",
            "%R1314", "%R1315", "%R1316", "%R1317",
            "%M305", "%M306", "%M307",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from HydroisomerizationDewaxingSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate LubeDewaxingTrickleBedSync alias POU AST."""
        ast_alias = STParser.parse_pou(LUBE_DEWAXING_TRICKLE_BED_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "LubeDewaxingTrickleBedSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1310", "%R1311", "%R1312", "%R1313",
            "%R1314", "%R1315", "%R1316", "%R1317",
            "%M305", "%M306", "%M307",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers, (
                f"Register {reg} missing from LubeDewaxingTrickleBedSync AST bindings"
            )


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests for rejection of ladder logic contacts, coils, rungs, and mnemonics with ERR_LADDER_FORBIDDEN."""

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
            "XIC HydroisomerizationPermissive",
            "XIO IsomThermalTrip",
            "OTE LubeOilOffspecAlarm",
            "OTL IsomThermalTrip",
            "OTU HydroisomerizationPermissive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Enforce pure ST by aggressively rejecting ladder constructs."""
        bad_code = f"""
        PROGRAM BadIsomLadder
        VAR
            Permissive AT %M305 : BOOL;
        END_VAR
        {ladder_snippet}
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 3. Section 3: Trickle-Bed Hydrodynamics & Hydrogen Solubility
# ============================================================================

class TestSection3TrickleBedHydrodynamicsAndHydraulics:
    """Tests for trickle-bed hydrodynamics, high-pressure hydrogen solubility, and liquid hourly space velocity (LHSV)."""

    def test_hydrodynamics_nominal_conditions(self) -> None:
        """Requirement 3: Verify superficial velocities, liquid holdup, two-phase pressure drop, and kla."""
        sim = HydroisomerizationSimulator()
        hydro = sim.compute_hydrodynamics(t_bed_c=335.0, p_bar=120.0)

        assert 0.005 <= hydro["u_l_m_s"] <= 0.025
        assert 0.05 <= hydro["u_g_m_s"] <= 0.35
        assert 0.15 <= hydro["liquid_holdup_fraction"] <= 0.35
        assert 1.5 <= hydro["two_phase_dp_bar"] <= 4.0
        assert 0.03 <= hydro["kla_mass_transfer_s_inv"] <= 0.15
        assert sim.config.operating_pressure_bar == 120.0

    def test_high_pressure_hydrogen_density_scaling(self) -> None:
        """Requirement 3: Verify high-pressure gas density scales linearly with reactor pressure."""
        sim = HydroisomerizationSimulator()
        hydro_110 = sim.compute_hydrodynamics(t_bed_c=335.0, p_bar=110.0)
        hydro_140 = sim.compute_hydrodynamics(t_bed_c=335.0, p_bar=140.0)

        assert hydro_110["rho_gas_kg_m3"] < hydro_140["rho_gas_kg_m3"]
        assert hydro_140["rho_gas_kg_m3"] == pytest.approx(
            hydro_110["rho_gas_kg_m3"] * (140.0 / 110.0), rel=1e-3
        )
        assert 4.0 <= hydro_110["rho_gas_kg_m3"] <= 6.0
        assert 600.0 <= hydro_110["rho_liq_kg_m3"] <= 800.0

    def test_liquid_hourly_space_velocity_and_residence_time(self) -> None:
        """Requirement 3: Verify liquid hourly space velocity (LHSV) and mean residence time."""
        sim = HydroisomerizationSimulator()
        vol_oil_m3_h = (sim.config.feed_oil_mass_flow_kg_s / sim.config.feed_oil_density_kg_m3) * 3600.0
        lhsv = vol_oil_m3_h / sim.config.bed_volume_m3

        assert 1.5 <= lhsv <= 4.5
        assert 200.0 <= sim.config.liquid_mean_residence_time_s <= 400.0
        assert 40.0 <= sim.config.bed_volume_m3 <= 70.0


# ============================================================================
# 4. Section 4: Dual Isomerization vs Cracking Kinetics & Thermodynamics
# ============================================================================

class TestSection4HydroisomerizationKineticsAndThermodynamics:
    """Tests for dual kinetics, reaction enthalpies (-45 and -65 kJ/mol), pour point depression, and VI retention."""

    def test_reaction_enthalpy_values(self) -> None:
        """Requirement 4: Verify reaction enthalpies for isomerization (-45 kJ/mol) and cracking (-65 kJ/mol)."""
        assert DELTA_H_ISOM_J_MOL == -45000.0
        assert DELTA_H_ISOM_KJ_MOL == -45.0
        assert DELTA_H_ISOMERIZATION_J_MOL == -45000.0
        assert DELTA_H_ISOMERIZATION_KJ_MOL == -45.0

        assert DELTA_H_CRACK_J_MOL == -65000.0
        assert DELTA_H_CRACK_KJ_MOL == -65.0
        assert DELTA_H_CRACKING_J_MOL == -65000.0
        assert DELTA_H_CRACKING_KJ_MOL == -65.0

    def test_arrhenius_monotonicity(self) -> None:
        """Requirement 4: Verify Arrhenius rate constants increase monotonically with temperature."""
        sim = HydroisomerizationSimulator()
        rx_320 = sim.compute_reaction_rates(320.0, 0.035, 0.700, 96.5)
        rx_335 = sim.compute_reaction_rates(335.0, 0.035, 0.700, 96.5)
        rx_350 = sim.compute_reaction_rates(350.0, 0.035, 0.700, 96.5)

        assert rx_320["k_isom"] < rx_335["k_isom"] < rx_350["k_isom"]
        assert rx_320["k_crack"] < rx_335["k_crack"] < rx_350["k_crack"]
        assert rx_335["q_isom_kw"] > 0.0
        assert rx_335["q_crack_kw"] > 0.0
        assert rx_335["q_rxn_total_kw"] == pytest.approx(
            rx_335["q_isom_kw"] + rx_335["q_crack_kw"], rel=1e-4
        )

    def test_activation_energy_selectivity_shift(self) -> None:
        """Requirement 4: Verify higher activation energy of cracking shifts selectivity unfavorably at elevated T."""
        sim = HydroisomerizationSimulator()
        rx_320 = sim.compute_reaction_rates(320.0, 0.035, 0.700, 96.5)
        rx_350 = sim.compute_reaction_rates(350.0, 0.035, 0.700, 96.5)

        ratio_320 = rx_320["k_crack"] / rx_320["k_isom"]
        ratio_350 = rx_350["k_crack"] / rx_350["k_isom"]
        assert ratio_350 > ratio_320

    def test_pour_point_depression_curve_and_viscosity_index_retention(self) -> None:
        """Requirement 4: Verify feed pour point (+35 °C) depression down to -18 °C while maintaining VI >= 130."""
        sim = HydroisomerizationSimulator()

        assert sim.config.feed_pour_point_c == 35.0
        assert sim.state.pour_point_celsius == -18.0
        assert sim.state.viscosity_index == 132.0
        assert sim.state.viscosity_index >= 130.0
        assert sim.state.y_lube_yield == 0.845
        assert sim.config.feed_viscosity_index == 105.0


# ============================================================================
# 5. Section 5: Coupled ODE RK4 Integration & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual elemental mass and thermal enthalpy conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states(self) -> None:
        """Requirement 5: Verify RK4 integration steps remain stable and bounded within physical limits."""
        sim = HydroisomerizationSimulator()
        for _ in range(100):
            res = sim.step(dt=0.05)
            assert res.status == AgentStatus.SUCCESS

        assert 330.0 <= sim.state.t_bed_celsius <= 340.0
        assert 0.01 <= sim.state.y_nparaffin <= 0.06
        assert 0.60 <= sim.state.y_isoparaffin <= 0.80
        assert 0.80 <= sim.state.y_lube_yield <= 0.90
        assert -22.0 <= sim.state.pour_point_celsius <= -14.0
        assert 130.0 <= sim.state.viscosity_index <= 138.0
        assert not math.isnan(sim.state.t_bed_celsius)
        assert not math.isnan(sim.state.y_isoparaffin)
        assert not math.isnan(sim.state.pour_point_celsius)
        assert not math.isnan(sim.state.viscosity_index)

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 5: Verify dual elemental mass and thermal enthalpy residuals < 1e-10."""
        sim = HydroisomerizationSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_derivative_computations_finite(self) -> None:
        """Requirement 5: Verify compute_derivatives produces 6 finite derivatives."""
        sim = HydroisomerizationSimulator()
        derivs = sim.compute_derivatives(
            0.0,
            [
                sim.state.t_bed_celsius,
                sim.state.y_nparaffin,
                sim.state.y_isoparaffin,
                sim.state.y_lube_yield,
                sim.state.pour_point_celsius,
                sim.state.viscosity_index,
            ],
        )
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_invalid_timestep_handling(self) -> None:
        """Requirement 5: Verify non-positive timestep rejection."""
        sim = HydroisomerizationSimulator()
        res1 = sim.advance_time(duration_s=-1.0, dt=0.05)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "INVALID_TIMESTEP"

        res2 = sim.advance_time(duration_s=1.0, dt=-0.05)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "INVALID_TIMESTEP"


# ============================================================================
# 6. Section 6: Process Safety Trips & Priority Hierarchy
# ============================================================================

class TestSection6ProcessSafetyInterlocksAndTrips:
    """Tests for safety trips (0xC301, 0xC302, 0xC303, 0xC304) and Horner coil assertions (%M305..%M307)."""

    def test_trip_0xc301_bed_exotherm_runaway(self) -> None:
        """Requirement 6: Verify 0xC301 trip on bed temp > 355 °C -> asserts %M306, clears %M305."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)

        sim.state.t_bed_celsius = 358.5  # > 355.0 °C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1317") & 0xFFFF == 0xC301
        assert reg.read_bit("%M306") is True
        assert reg.read_bit("%M305") is False

    def test_fault_0xc302_pour_point_offspec(self) -> None:
        """Requirement 6: Verify 0xC302 on pour point > -10 °C -> asserts %M307, maintains %M305."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)

        sim.state.t_bed_celsius = 335.0
        sim.state.pour_point_celsius = -8.5  # > -10.0 °C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1317") & 0xFFFF == 0xC302
        assert reg.read_bit("%M307") is True
        assert reg.read_bit("%M305") is True
        assert reg.read_bit("%M306") is False

    def test_fault_0xc303_high_hydrogen_consumption(self) -> None:
        """Requirement 6: Verify 0xC303 on excessive hydrogen consumption (> 0.065 kg/s)."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)

        sim.state.t_bed_celsius = 335.0
        sim.state.pour_point_celsius = -18.0
        sim.state.h2_consumption_kg_s = 0.082  # > 0.065 kg/s
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1317") & 0xFFFF == 0xC303
        assert sim.state.high_h2_consumption_fault is True
        assert reg.read_bit("%M305") is True
        assert reg.read_bit("%M306") is False

    def test_fault_0xc304_catalyst_poisoning_and_sulfur_breakthrough(self) -> None:
        """Requirement 6: Verify 0xC304 on sulfur breakthrough (> 5.0 ppm) or low catalyst activity (< 70%)."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)

        # 1. Sulfur breakthrough
        sim.state.t_bed_celsius = 335.0
        sim.state.pour_point_celsius = -18.0
        sim.state.h2_consumption_kg_s = 0.0278
        sim.state.feed_sulfur_ppm = 8.5  # > 5.0 ppm
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1317") & 0xFFFF == 0xC304
        assert sim.state.catalyst_poisoning_fault is True

        # 2. Catalyst activity decay
        sim.state.feed_sulfur_ppm = 0.5
        sim.state.catalyst_activity_pct = 65.0  # < 70.0%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1317") & 0xFFFF == 0xC304
        assert sim.state.catalyst_poisoning_fault is True

    def test_priority_hierarchy(self) -> None:
        """Requirement 6: Verify 0xC301 (thermal runaway) dominates over all other faults."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)

        sim.state.t_bed_celsius = 360.0       # 0xC301
        sim.state.pour_point_celsius = -5.0   # 0xC302
        sim.state.h2_consumption_kg_s = 0.090 # 0xC303
        sim.state.feed_sulfur_ppm = 12.0      # 0xC304
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1317") & 0xFFFF == 0xC301
        assert reg.read_bit("%M306") is True
        assert reg.read_bit("%M305") is False
        assert reg.read_bit("%M307") is True


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration
# ============================================================================

class TestSection7HornerOCSMemorySpaceIntegration:
    """Tests for Horner OCS memory space bindings (%R1310..%R1317, %M305..%M307) with signed INT16 pour point and PrivilegeMode.SYSTEM."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 7: Verify analog register values and discrete coil states with PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)

        sim.state.t_bed_celsius = 335.0
        sim.state.p_react_bar = 120.0
        sim.state.h2_oil_ratio_nm3_m3 = 600.0
        sim.state.y_lube_yield = 0.845
        sim.state.pour_point_celsius = -18.0
        sim.state.viscosity_index = 132.0
        sim.state.catalyst_activity_pct = 96.5

        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1310") == 3350
        assert reg.read_word("%R1311") == 1200
        assert reg.read_word("%R1312") == 600
        assert reg.read_word("%R1313") == 845
        assert reg.read_word("%R1314") == -180
        assert reg.read_word("%R1315") == 132
        assert reg.read_word("%R1316") == 965
        assert reg.read_word("%R1317") & 0xFFFF == 0x0000
        assert reg.read_bit("%M305") is True
        assert reg.read_bit("%M306") is False
        assert reg.read_bit("%M307") is False

    def test_signed_int16_pour_point_negative_values(self) -> None:
        """Requirement 7: Verify %R1314 supports negative temperatures as signed INT16 without overflow."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)

        test_temperatures = [-18.0, -25.5, -30.0, 0.0, 15.0]
        expected_scaled = [-180, -255, -300, 0, 150]

        for temp_c, expected in zip(test_temperatures, expected_scaled):
            sim.state.pour_point_celsius = temp_c
            sim._sync_registers()
            assert reg.read_word("%R1314") == expected

    def test_system_privilege_enforced_for_internal_writes(self) -> None:
        """Requirement 7: Ensure writes use PrivilegeMode.SYSTEM without throwing privilege errors."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1310") == 3350


# ============================================================================
# 8. Section 8: ILogicUnit Compliance & Dynamic Disturbance Response
# ============================================================================

class TestSection8ILogicUnitAndDisturbanceResponse:
    """Tests for ILogicUnit interface, scan_step, transient disturbance response, and settling stability."""

    def test_ilogicunit_interface_and_scan_step(self) -> None:
        """Requirement 8: Verify ILogicUnit protocol compliance and scan_step return dictionary."""
        sim = HydroisomerizationSimulator()
        assert sim.name == "HydroisomerizationDewaxingSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

        res = sim.scan_step(dt_s=0.05)
        assert "status" in res
        assert "t_bed_celsius" in res
        assert "y_nparaffin" in res
        assert "y_isoparaffin" in res
        assert "y_lube_yield" in res
        assert "pour_point_celsius" in res
        assert "viscosity_index" in res
        assert "hydroisomerization_permissive" in res
        assert res["hydroisomerization_permissive"] is True

    def test_hydroisomerization_logic_unit_adapter(self) -> None:
        """Requirement 8: Verify HydroisomerizationLogicUnit adapter couples correctly into ScanContext."""
        reg = RegisterTable()
        sim = HydroisomerizationSimulator(register_table=reg)
        unit = HydroisomerizationLogicUnit(simulator=sim)
        ctx = ScanContext(
            cycle=1,
            dt_ms=50.0,
            elapsed_time_ms=50.0,
            get_register=lambda addr: reg.read_word(addr),
            set_register=lambda addr, val: reg.write_word(addr, val, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda name, default=None: default,
            set_variable=lambda name, val: None,
            record_fault=lambda fault: None,
        )
        ctx.registers = reg

        unit.execute(ctx)
        assert reg.read_word("%R1310") == 3350
        assert reg.read_word("%R1311") == 1200
        assert reg.read_bit("%M305") is True

        unit.reset()
        assert unit.simulator.state.time_s == 0.0

    def test_temperature_disturbance_settling(self) -> None:
        """Requirement 8: Verify closed-loop settling response to +2.5 °C bed temperature disturbance."""
        sim = HydroisomerizationSimulator()
        sim.state.t_bed_celsius = 337.5  # +2.5 °C bed disturbance
        res = sim.advance_time(duration_s=8.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 333.0 <= sim.state.t_bed_celsius <= 340.0
        assert sim.state.pour_point_celsius <= -14.0
        assert sim.state.viscosity_index >= 130.0
        assert sim.state.hydroisomerization_permissive is True
        assert not math.isnan(sim.state.t_bed_celsius)


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_hydroisomerization_verification execution and strict 4-state contract validation."""

    def test_run_hydroisomerization_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 9: Execute verification suite, write evidence JSON, assert success contract."""
        out_file = tmp_path / "hydroisomerization_evidence.json"
        evidence = run_hydroisomerization_verification(str(out_file))

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["data"]["work_package"] == "W170"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_suite_aliases(self) -> None:
        """Requirement 9: Verify alias functions execute cleanly."""
        res1 = run_hydroisomerization_dewaxing_verification()
        assert res1["status"] == "success"
        assert res1["data"]["checks_passed"] == 9

        res2 = run_lube_dewaxing_trickle_bed_verification()
        assert res2["status"] == "success"
        assert res2["data"]["checks_passed"] == 9

        res3 = run_lube_dewaxing_verification()
        assert res3["status"] == "success"
        assert res3["data"]["checks_passed"] == 9

        res4 = run_dewaxing_verification()
        assert res4["status"] == "success"
        assert res4["data"]["checks_passed"] == 9
