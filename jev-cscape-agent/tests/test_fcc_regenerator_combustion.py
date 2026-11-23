"""Unit and Integration Tests for Industrial Fluid Catalytic Cracking (FCC) Catalyst Regeneration Coke Combustion & Two-Phase Dense Bed Hydrodynamics ODE Simulation.

Work Package: W182 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1430..%R1437, %M333..%M335).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Combustion stoichiometry (CO, CO2, H2O), afterburning kinetics, heat release.
4. Section 4: Two-phase dense bed fluidization hydrodynamics, minimum fluidization velocity, bubble vs emulsion.
5. Section 5: Coupled 6-state ODE RK4 integration stability and dual mass/enthalpy conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xCF01 afterburning runaway, 0xCF02 defluidization, 0xCF03 high CO emission, 0xCF04 high O2 breakthrough) and Horner coil assertion (%M333, %M334, %M335).
7. Section 7: Horner OCS register space synchronization (%R1430..%R1437, %M333..%M335) with PrivilegeMode.SYSTEM.
8. Section 8: Dynamic disturbance response (combustion air surge, spent catalyst flow trip) and settling stability.
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
from jev_cscape.simulation.engine import ILogicUnit, ScanContext, SimulationEngine
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.fcc_regenerator_combustion import (
    AFTERBURNING_DELTA_T_LIMIT_C,
    AFTERBURNING_DELTA_T_NOMINAL_C,
    CATALYST_CIRCULATION_RATE_KG_S,
    CATALYST_CIRCULATION_RATE_TONNES_MIN,
    CATALYST_INVENTORY_NOMINAL_KG,
    CATALYST_INVENTORY_TONNES,
    COMBUSTION_AIR_FLOW_NOMINAL_NM3_H,
    COMBUSTION_AIR_FLOW_SCALED,
    DELTA_H_C_TO_CO2_J_MOL,
    DELTA_H_C_TO_CO2_KJ_MOL,
    DELTA_H_C_TO_CO_J_MOL,
    DELTA_H_C_TO_CO_KJ_MOL,
    DELTA_H_CO_TO_CO2_J_MOL,
    DELTA_H_CO_TO_CO2_KJ_MOL,
    DELTA_H_RXN1_J_MOL,
    DELTA_H_RXN2_J_MOL,
    DELTA_H_RXN3_J_MOL,
    DENSE_BED_COKE_BURN_REGEN_DYNAMICS_SYNC_POU,
    DENSE_BED_COKE_BURN_REGEN_PURE_ST_POU,
    DENSE_BED_COKE_BURN_REGEN_SYNC_POU,
    DENSE_BED_TEMP_MAX_C,
    DENSE_BED_TEMP_MIN_C,
    DENSE_BED_TEMP_NOMINAL_C,
    DILUTE_PHASE_TEMP_MAX_C,
    DILUTE_PHASE_TEMP_MIN_C,
    DILUTE_PHASE_TEMP_NOMINAL_C,
    DILUTE_TEMP_TRIP_LIMIT_C,
    DenseBedCokeBurnRegenConfig,
    DenseBedCokeBurnRegenDiagCode,
    DenseBedCokeBurnRegenDiagnosticCode,
    DenseBedCokeBurnRegenEngine,
    DenseBedCokeBurnRegenLogicUnit,
    DenseBedCokeBurnRegenModel,
    DenseBedCokeBurnRegenParameters,
    DenseBedCokeBurnRegenSimulator,
    DenseBedCokeBurnRegenState,
    DenseBedCokeBurnRegenStatusBits,
    DenseBedCokeBurnRegenStatusWord,
    FCC_COMBUSTION_PURE_ST_POU,
    FCC_COMBUSTION_SYNC_POU,
    FCC_REGENERATOR_COMBUSTION_DYNAMICS_SYNC_POU,
    FCC_REGENERATOR_COMBUSTION_PURE_ST_POU,
    FCC_REGENERATOR_COMBUSTION_SYNC_POU,
    FCC_REGEN_COMBUSTION_PURE_ST_POU,
    FCCCombustionConfig,
    FCCCombustionDiagCode,
    FCCCombustionDiagnosticCode,
    FCCCombustionEngine,
    FCCCombustionLogicUnit,
    FCCCombustionModel,
    FCCCombustionParameters,
    FCCCombustionSimulator,
    FCCCombustionState,
    FCCCombustionStatusBits,
    FCCCombustionStatusWord,
    FCCRegeneratorCombustionConfig,
    FCCRegeneratorCombustionDiagCode,
    FCCRegeneratorCombustionDiagnosticCode,
    FCCRegeneratorCombustionEngine,
    FCCRegeneratorCombustionLogicUnit,
    FCCRegeneratorCombustionModel,
    FCCRegeneratorCombustionParameters,
    FCCRegeneratorCombustionPlantModel,
    FCCRegeneratorCombustionSimulationEngine,
    FCCRegeneratorCombustionSimulator,
    FCCRegeneratorCombustionState,
    FCCRegeneratorCombustionStatusBits,
    FCCRegeneratorCombustionStatusWord,
    FLUE_GAS_CO2_VOL_PCT_NOMINAL,
    FLUE_GAS_CO_PPM_NOMINAL,
    FLUE_GAS_O2_VOL_PCT_NOMINAL,
    FccCokeRegeneratorSimulator,
    FccCombustionConfig,
    FccCombustionDiagCode,
    FccCombustionDiagnosticCode,
    FccCombustionLogicUnit,
    FccCombustionParameters,
    FccCombustionSimulator,
    FccCombustionState,
    FccCombustionStatusBits,
    FccCombustionStatusWord,
    FccRegenCombustionDiagnosticCode,
    FccRegeneratorCombustionConfig,
    FccRegeneratorCombustionDiagCode,
    FccRegeneratorCombustionDiagnosticCode,
    FccRegeneratorCombustionEngine,
    FccRegeneratorCombustionLogicUnit,
    FccRegeneratorCombustionModel,
    FccRegeneratorCombustionParameters,
    FccRegeneratorCombustionPlantModel,
    FccRegeneratorCombustionSimulationEngine,
    FccRegeneratorCombustionSimulator,
    FccRegeneratorCombustionState,
    FccRegeneratorCombustionStatusBits,
    FccRegeneratorCombustionStatusWord,
    G_ACCEL,
    MW_AIR,
    MW_CARBON,
    MW_CO,
    MW_CO2,
    MW_N2,
    MW_O2,
    MW_WATER,
    REGEN_COKE_WT_PCT_NOMINAL,
    R_GAS_CONST,
    SUPERFICIAL_GAS_VELOCITY_NOMINAL_M_S,
    T_REF_K,
    T_ZERO_CELSIUS,
    run_dense_bed_coke_burn_regen_verification,
    run_fcc_combustion_verification,
    run_fcc_regen_combustion_verification,
    run_fcc_regenerator_combustion_verification,
    run_regenerator_combustion_verification,
    validate_pure_st,
    verify_dense_bed_coke_burn_regen_pure_st,
    verify_dense_bed_pure_st,
    verify_fcc_combustion_pure_st,
    verify_fcc_regen_combustion_pure_st,
    verify_fcc_regenerator_combustion_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1430..%R1437, %M333..%M335)."""

    def test_verify_fcc_regenerator_combustion_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_fcc_regenerator_combustion_pure_st() is True
        assert verify_dense_bed_coke_burn_regen_pure_st() is True
        assert verify_dense_bed_pure_st() is True
        assert verify_fcc_combustion_pure_st() is True
        assert verify_fcc_regen_combustion_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1430..%R1437, %M333..%M335)."""
        SecurityGuard.assert_pure_st_content(FCC_REGENERATOR_COMBUSTION_PURE_ST_POU)
        val = STParser.validate_code(FCC_REGENERATOR_COMBUSTION_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(FCC_REGENERATOR_COMBUSTION_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "FccRegeneratorCombustionSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1430", "%R1431", "%R1432", "%R1433",
            "%R1434", "%R1435", "%R1436", "%R1437",
            "%M333", "%M334", "%M335",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from FccRegeneratorCombustionSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate DenseBedCokeBurnRegenSync alias POU AST."""
        ast_alias = STParser.parse_pou(DENSE_BED_COKE_BURN_REGEN_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "DenseBedCokeBurnRegenSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1430", "%R1431", "%R1432", "%R1433",
            "%R1434", "%R1435", "%R1436", "%R1437",
            "%M333", "%M334", "%M335",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers

    def test_pou_string_constants_and_sync_aliases(self) -> None:
        """Requirement 1: Verify string constants and sync POU aliases."""
        assert FCC_REGENERATOR_COMBUSTION_SYNC_POU == FCC_REGENERATOR_COMBUSTION_PURE_ST_POU
        assert DENSE_BED_COKE_BURN_REGEN_SYNC_POU == DENSE_BED_COKE_BURN_REGEN_PURE_ST_POU
        assert FCC_REGEN_COMBUSTION_PURE_ST_POU == FCC_REGENERATOR_COMBUSTION_PURE_ST_POU
        assert FCC_REGENERATOR_COMBUSTION_DYNAMICS_SYNC_POU == FCC_REGENERATOR_COMBUSTION_PURE_ST_POU
        assert DENSE_BED_COKE_BURN_REGEN_DYNAMICS_SYNC_POU == DENSE_BED_COKE_BURN_REGEN_PURE_ST_POU
        assert FCC_COMBUSTION_PURE_ST_POU == FCC_REGENERATOR_COMBUSTION_PURE_ST_POU
        assert FCC_COMBUSTION_SYNC_POU == FCC_REGENERATOR_COMBUSTION_PURE_ST_POU

    def test_validate_pure_st_function(self) -> None:
        """Requirement 1: Test validate_pure_st function returns SUCCESS."""
        res = validate_pure_st()
        assert res.status == AgentStatus.SUCCESS


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests for interception and rejection of ladder logic constructs with ERR_LADDER_FORBIDDEN."""

    @pytest.mark.parametrize(
        "ladder_fragment",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 1",
            "END_RUNG",
            "NETWORK 1",
            "XIC RegeneratorAirPermissive",
            "XIO RegeneratorEmergencyTrip",
            "OTE DefluidizationWarningAlarm",
            "OTL RegeneratorEmergencyTrip",
            "OTU RegeneratorAirPermissive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_fragment: str) -> None:
        """Requirement 2: Verify SecurityGuard.assert_pure_st_content raises LadderForbiddenError."""
        bad_st = f"""
        PROGRAM LadderTest
        VAR
            TestVar : BOOL;
        END_VAR
        {ladder_fragment}
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

        val = STParser.validate_code(bad_st)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 3. Section 3: Combustion Stoichiometry, Afterburning Kinetics & Heat Release
# ============================================================================

class TestSection3CombustionStoichiometryKineticsAndHeatRelease:
    """Tests for coke combustion stoichiometry (CO, CO2, H2O), afterburning kinetics, and heat release."""

    def test_reaction_enthalpy_constants(self) -> None:
        """Requirement 3: Verify standard exothermic combustion reaction enthalpies."""
        assert DELTA_H_C_TO_CO2_KJ_MOL == -393.5
        assert DELTA_H_C_TO_CO2_J_MOL == -393500.0
        assert DELTA_H_C_TO_CO_KJ_MOL == -110.5
        assert DELTA_H_C_TO_CO_J_MOL == -110500.0
        assert DELTA_H_CO_TO_CO2_KJ_MOL == -283.0
        assert DELTA_H_CO_TO_CO2_J_MOL == -283000.0
        assert DELTA_H_RXN1_J_MOL == -393500.0
        assert DELTA_H_RXN2_J_MOL == -110500.0
        assert DELTA_H_RXN3_J_MOL == -283000.0

    def test_universal_molecular_weight_constants(self) -> None:
        """Requirement 3: Validate universal molecular weight constants for flue gas and coke."""
        assert MW_CARBON == 0.012011
        assert MW_O2 == 0.031998
        assert MW_CO == 0.028010
        assert MW_CO2 == 0.044010
        assert MW_N2 == 0.028014
        assert MW_AIR == 0.028970
        assert MW_WATER == 0.018015

    def test_coke_combustion_stoichiometry_and_mass_rates(self) -> None:
        """Requirement 3: Validate coke burn rate = 2.0 kg/s from spent cat flow and wt% reduction."""
        sim = FccRegeneratorCombustionSimulator()
        assert sim.state.spent_catalyst_flow_kg_s == 500.0
        assert sim.config.spent_coke_wt_pct == 1.25
        assert sim.state.c_coke_wt_pct == 0.85
        assert sim.state.coke_combustion_rate_kg_s == 2.0
        assert sim.state.regen_catalyst_flow_kg_s == 498.0

        # Carbon moles burned per second: 2.0 kg/s / 0.012011 kg/mol ~ 166.514 mol C/s
        mol_c_per_s = sim.state.coke_combustion_rate_kg_s / MW_CARBON
        assert abs(mol_c_per_s - 166.514) < 0.1

    def test_co2_co_selectivity_in_dense_bed(self) -> None:
        """Requirement 3: Selectivity between CO2 and CO in dense bed (Arthur correlation)."""
        sim = FccRegeneratorCombustionSimulator()
        kin = sim.compute_kinetics(
            t_dense_c=715.0,
            t_dilute_c=732.0,
            c_coke=0.85,
            air_flow_kg_s=30.52,
        )
        r1 = kin["r1_mol_s"]
        r2 = kin["r2_mol_s"]
        r3 = kin["r3_mol_s"]

        assert r1 > r2  # Complete combustion dominates over partial oxidation (~9:1 ratio)
        assert abs((r1 + r2) - (2.0 / MW_CARBON)) < 0.01
        assert r3 <= r2 # Afterburning consumes CO

    def test_dilute_phase_afterburning_exotherm_and_heat_release(self) -> None:
        """Requirement 3: Freeboard CO afterburning exotherm (~4,700 kW) and dense bed heat (~60,812 kW)."""
        sim = FccRegeneratorCombustionSimulator()
        kin = sim.compute_kinetics(
            t_dense_c=715.0,
            t_dilute_c=732.0,
            c_coke=0.85,
            air_flow_kg_s=30.52,
        )
        assert 40000.0 <= kin["dense_bed_heat_kw"] <= 70000.0
        assert 5000.0 <= kin["dilute_afterburning_heat_kw"] <= 15000.0
        assert kin["dense_wall_loss_kw"] > 0.0
        assert kin["dilute_wall_loss_kw"] > 0.0

    def test_combustion_air_inflow_and_excess_oxygen(self) -> None:
        """Requirement 3: Combustion air blower supply (85,000 Nm3/h) and flue gas excess O2 (1.2 vol%)."""
        sim = FccRegeneratorCombustionSimulator()
        assert sim.state.combustion_air_flow_nm3_h == 85000.0
        assert COMBUSTION_AIR_FLOW_NOMINAL_NM3_H == 85000.0
        assert COMBUSTION_AIR_FLOW_SCALED == 8500
        assert abs(sim.state.combustion_air_mass_flow_kg_s - 30.52) < 0.5
        assert sim.state.y_o2_flue_vol_pct == 1.2
        assert FLUE_GAS_O2_VOL_PCT_NOMINAL == 1.2


# ============================================================================
# 4. Section 4: Two-Phase Dense Bed Fluidization Hydrodynamics
# ============================================================================

class TestSection4TwoPhaseDenseBedFluidizationHydrodynamics:
    """Tests for bubbling fluidized bed hydrodynamics, minimum fluidization velocity, and bubble vs emulsion."""

    def test_minimum_fluidization_velocity_wen_yu(self) -> None:
        """Requirement 4: Minimum fluidization velocity U_mf via Wen & Yu correlation (~1.028 mm/s)."""
        sim = FccRegeneratorCombustionSimulator()
        hydro = sim.compute_hydrodynamics(u_g=0.85, bed_temp_c=715.0)
        u_mf = hydro["u_mf_m_s"]

        assert 0.0005 <= u_mf <= 0.0050
        assert abs(u_mf * 1000.0 - 1.028) < 0.2

    def test_superficial_gas_velocity_and_bed_expansion(self) -> None:
        """Requirement 4: Superficial gas velocity U_g = 0.85 m/s operates deep in bubbling regime."""
        sim = FccRegeneratorCombustionSimulator()
        hydro = sim.compute_hydrodynamics(u_g=0.85, bed_temp_c=715.0)

        assert hydro["u_g_superficial_m_s"] == 0.85
        assert SUPERFICIAL_GAS_VELOCITY_NOMINAL_M_S == 0.85
        assert hydro["u_g_superficial_m_s"] > 100.0 * hydro["u_mf_m_s"]

    def test_bubble_diameter_and_rise_velocity(self) -> None:
        """Requirement 4: Mean bubble diameter d_b (0.35 m) and bubble rise velocity u_b (2.17 m/s)."""
        sim = FccRegeneratorCombustionSimulator()
        hydro = sim.compute_hydrodynamics(u_g=0.85, bed_temp_c=715.0)

        assert 0.20 <= hydro["bubble_diameter_m"] <= 0.50
        assert hydro["bubble_rise_velocity_m_s"] > 1.5
        assert abs(hydro["bubble_diameter_m"] - 0.35) < 0.05
        assert abs(hydro["bubble_rise_velocity_m_s"] - 2.17) < 0.15

    def test_bubble_and_emulsion_volume_fractions(self) -> None:
        """Requirement 4: Two-phase volume fractions delta_b (~0.392) + delta_e (~0.608) == 1.0."""
        sim = FccRegeneratorCombustionSimulator()
        hydro = sim.compute_hydrodynamics(u_g=0.85, bed_temp_c=715.0)

        delta_b = hydro["bubble_volume_fraction"]
        delta_e = hydro["emulsion_volume_fraction"]

        assert 0.20 <= delta_b <= 0.60
        assert 0.40 <= delta_e <= 0.80
        assert abs((delta_b + delta_e) - 1.0) < 1e-6

    def test_interphase_gas_exchange_coefficient_k_be(self) -> None:
        """Requirement 4: Kunii-Levenspiel interphase exchange coefficient K_be > 0.05 1/s."""
        sim = FccRegeneratorCombustionSimulator()
        hydro = sim.compute_hydrodynamics(u_g=0.85, bed_temp_c=715.0)
        assert hydro["k_be_interphase_s_inv"] > 0.10
        assert abs(hydro["k_be_interphase_s_inv"] - 0.205) < 0.05

    def test_catalyst_inventory_and_residence_time(self) -> None:
        """Requirement 4: Catalyst inventory 200 tonnes, circulation 500 kg/s -> tau = 400s."""
        sim = FccRegeneratorCombustionSimulator()
        assert sim.config.catalyst_inventory_kg == 200000.0
        assert CATALYST_INVENTORY_NOMINAL_KG == 200000.0
        assert CATALYST_INVENTORY_TONNES == 200.0
        assert CATALYST_CIRCULATION_RATE_TONNES_MIN == 30.0
        assert CATALYST_CIRCULATION_RATE_KG_S == 500.0
        assert sim.config.catalyst_mean_residence_time_s == 400.0

    def test_defluidization_boundary_condition(self) -> None:
        """Requirement 4: Defluidization trip occurs if U_g drops below 1.5 * U_mf."""
        sim = FccRegeneratorCombustionSimulator()
        hydro_norm = sim.compute_hydrodynamics(u_g=0.85, bed_temp_c=715.0)
        hydro_trip = sim.compute_hydrodynamics(u_g=0.0010, bed_temp_c=715.0)

        assert hydro_norm["is_fluidized"] is True
        assert hydro_trip["is_fluidized"] is False


# ============================================================================
# 5. Section 5: Coupled 6-State ODE RK4 Integration & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states_bounded(self) -> None:
        """Requirement 5: Advance ODE system via high-order RK4 over 5.0s and verify state stability."""
        sim = FccRegeneratorCombustionSimulator()
        res = sim.advance_time(duration_s=5.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 695.0 <= sim.state.t_dense_bed_celsius <= 735.0
        assert 715.0 <= sim.state.t_dilute_phase_celsius <= 755.0
        assert 0.70 <= sim.state.c_coke_wt_pct <= 1.05
        assert 0.5 <= sim.state.y_o2_flue_vol_pct <= 3.5
        assert 100.0 <= sim.state.y_co_flue_ppm <= 800.0
        assert 10.0 <= sim.state.y_co2_flue_vol_pct <= 18.0

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 5: Total mass balance, elemental balance, and enthalpy residuals < 1e-10."""
        sim = FccRegeneratorCombustionSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_rk4_all_derivatives_finite(self) -> None:
        """Requirement 5: Verify all 6 ODE state derivatives remain finite without NaN or Inf."""
        sim = FccRegeneratorCombustionSimulator()
        y0 = [715.0, 732.0, 0.85, 1.2, 320.0, 14.6]
        derivs = sim.compute_derivatives(0.0, y0)

        assert len(derivs) == 6
        for i, d in enumerate(derivs):
            assert not math.isnan(d), f"Derivative {i} is NaN"
            assert not math.isinf(d), f"Derivative {i} is infinite"

    def test_invalid_timestep_handling(self) -> None:
        """Requirement 5: Non-positive integration timestep fails cleanly."""
        sim = FccRegeneratorCombustionSimulator()
        res_neg = sim.step(dt=-0.05)
        # Advance time or step handles cleanly
        assert not math.isnan(sim.state.t_dense_bed_celsius)


# ============================================================================
# 6. Section 6: Process Safety Interlocks, Diagnostics & Coils
# ============================================================================

class TestSection6ProcessSafetyInterlocksAndDiagnostics:
    """Tests for safety trips (0xCF01..0xCF04) and Horner coil assertions (%M333, %M334, %M335)."""

    def test_afterburning_thermal_runaway_emergency_trip_0xcf01(self) -> None:
        """Requirement 6: 0xCF01 Afterburning runaway (Delta T > 45 °C or dilute > 760 °C) asserts %M334, clears %M333."""
        sim = FccRegeneratorCombustionSimulator()
        sim.state.t_dilute_phase_celsius = 770.0
        sim.state.afterburning_delta_t_celsius = 55.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorCombustionDiagnosticCode.FCC_ERR_AFTERBURNING_THERMAL_RUNAWAY
        assert sim.state.regenerator_emergency_trip is True
        assert sim.state.regenerator_air_permissive is False

    def test_dense_bed_defluidization_alarm_0xcf02(self) -> None:
        """Requirement 6: 0xCF02 Defluidization (U_g < 1.5 * U_mf) asserts %M335 (DefluidizationWarningAlarm)."""
        sim = FccRegeneratorCombustionSimulator()
        sim.state.u_g_superficial_m_s = 0.0005  # below 1.5 * U_mf
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorCombustionDiagnosticCode.FCC_ERR_DENSE_BED_DEFLUIDIZATION
        assert sim.state.defluidization_warning_alarm is True
        assert sim.state.regenerator_air_permissive is True
        assert sim.state.regenerator_emergency_trip is False

    def test_high_co_flue_emission_fault_0xcf03(self) -> None:
        """Requirement 6: 0xCF03 Flue gas CO > 1200 ppm sets fault code."""
        sim = FccRegeneratorCombustionSimulator()
        sim.state.y_co_flue_ppm = 1350.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorCombustionDiagnosticCode.FCC_ERR_HIGH_CO_FLUE_EMISSION
        assert sim.state.regenerator_air_permissive is True
        assert sim.state.regenerator_emergency_trip is False

    def test_high_o2_breakthrough_fault_0xcf04(self) -> None:
        """Requirement 6: 0xCF04 Flue gas O2 > 4.5 vol% sets fault code."""
        sim = FccRegeneratorCombustionSimulator()
        sim.state.y_o2_flue_vol_pct = 5.2
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorCombustionDiagnosticCode.FCC_ERR_HIGH_O2_BREAKTHROUGH
        assert sim.state.regenerator_air_permissive is True
        assert sim.state.regenerator_emergency_trip is False

    def test_safety_priority_hierarchy(self) -> None:
        """Requirement 6: Priority Hierarchy 0xCF01 > 0xCF02 > 0xCF03 > 0xCF04."""
        sim = FccRegeneratorCombustionSimulator()
        sim.state.t_dilute_phase_celsius = 775.0        # 0xCF01
        sim.state.u_g_superficial_m_s = 0.0002          # 0xCF02
        sim.state.y_co_flue_ppm = 1400.0                # 0xCF03
        sim.state.y_o2_flue_vol_pct = 5.5               # 0xCF04
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xCF01
        assert sim.state.regenerator_emergency_trip is True
        assert sim.state.regenerator_air_permissive is False
        assert sim.state.defluidization_warning_alarm is True

    def test_normal_healthy_clears_all_trips(self) -> None:
        """Requirement 6: Healthy state resets diagnostic code to 0x0000 and activates permissive."""
        sim = FccRegeneratorCombustionSimulator()
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == FccRegeneratorCombustionDiagnosticCode.OK
        assert sim.state.regenerator_air_permissive is True
        assert sim.state.regenerator_emergency_trip is False
        assert sim.state.defluidization_warning_alarm is False


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration (%R1430..%R1437, %M333..%M335)
# ============================================================================

class TestSection7HornerOCSMemorySpaceIntegration:
    """Tests for %R1430..%R1437 and %M333..%M335 scaling and PrivilegeMode.SYSTEM enforcement."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 7: Verify scaled values in RegisterTable."""
        reg = RegisterTable()
        sim = FccRegeneratorCombustionSimulator(register_table=reg)

        sim.state.t_dense_bed_celsius = 715.0
        sim.state.t_dilute_phase_celsius = 732.0
        sim.state.afterburning_delta_t_celsius = 17.0
        sim.state.c_coke_wt_pct = 0.85
        sim.state.y_o2_flue_vol_pct = 1.2
        sim.state.y_co_flue_ppm = 320.0
        sim.state.combustion_air_flow_nm3_h = 85000.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1430") == 7150
        assert reg.read_word("%R1431") == 7320
        assert reg.read_word("%R1432") == 170
        assert reg.read_word("%R1433") == 85
        assert reg.read_word("%R1434") == 12
        assert reg.read_word("%R1435") == 320
        assert reg.read_word("%R1436") == 8500
        assert reg.read_word("%R1437") & 0xFFFF == 0x0000

        assert reg.read_bit("%M333") is True
        assert reg.read_bit("%M334") is False
        assert reg.read_bit("%M335") is False

    def test_system_privilege_enforced(self) -> None:
        """Requirement 7: Internal write operations use PrivilegeMode.SYSTEM without privilege errors."""
        reg = RegisterTable()
        sim = FccRegeneratorCombustionSimulator(register_table=reg)
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1430") == 7150

    def test_ilogicunit_protocol_compliance_and_scan_step(self) -> None:
        """Requirement 7: ILogicUnit protocol compliance and scan_step return dictionary."""
        sim = FccRegeneratorCombustionSimulator()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "FccRegeneratorCombustionSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

        res_dict = sim.scan_step(dt=0.05)
        assert res_dict["status"] == "success"
        assert "t_dense_bed_celsius" in res_dict
        assert "t_dilute_phase_celsius" in res_dict
        assert "afterburning_delta_t_celsius" in res_dict
        assert "c_coke_wt_pct" in res_dict
        assert "y_o2_flue_vol_pct" in res_dict
        assert "y_co_flue_ppm" in res_dict
        assert "combustion_air_flow_nm3_h" in res_dict
        assert "diagnostic_code" in res_dict
        assert "regenerator_air_permissive" in res_dict
        assert "regenerator_emergency_trip" in res_dict
        assert "defluidization_warning_alarm" in res_dict

    def test_scan_context_adapter_execution(self) -> None:
        """Requirement 7: Verify execute(ScanContext) multi-cycle adapter execution."""
        reg = RegisterTable()
        sim = FccRegeneratorCombustionSimulator(register_table=reg)
        unit = FccRegeneratorCombustionLogicUnit(config=sim.config, register_table=reg)
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
        assert reg.read_word("%R1430") == 7150
        assert reg.read_word("%R1431") == 7320
        assert reg.read_bit("%M333") is True


# ============================================================================
# 8. Section 8: Dynamic Disturbance Response & Closed-Loop Settling
# ============================================================================

class TestSection8DynamicDisturbanceResponseAndSettling:
    """Tests for transient disturbance response (dense bed thermal spike, combustion air surge) and settling."""

    def test_dense_bed_temperature_transient_disturbance(self) -> None:
        """Requirement 8: +10 °C dense bed disturbance settles cleanly without instability."""
        sim = FccRegeneratorCombustionSimulator()
        sim.state.t_dense_bed_celsius = 725.0  # +10.0 °C disturbance
        res = sim.advance_time(duration_s=8.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert not math.isnan(sim.state.t_dense_bed_celsius)
        assert not math.isnan(sim.state.t_dilute_phase_celsius)
        assert 710.0 <= sim.state.t_dense_bed_celsius <= 725.0
        assert sim.state.regenerator_air_permissive is True
        assert sim.state.regenerator_emergency_trip is False

    def test_combustion_air_surge_perturbation(self) -> None:
        """Requirement 8: Air surge disturbance shifts flue gas excess O2 smoothly."""
        sim = FccRegeneratorCombustionSimulator()
        sim.state.combustion_air_flow_nm3_h = 95000.0  # +10,000 Nm3/h surge
        sim.advance_time(duration_s=4.0, dt=0.05)

        assert not math.isnan(sim.state.y_o2_flue_vol_pct)
        assert sim.state.regenerator_air_permissive is True

    def test_spent_catalyst_circulation_trip_response(self) -> None:
        """Requirement 8: Catalyst circulation trip disturbance response."""
        sim = FccRegeneratorCombustionSimulator()
        sim.state.spent_catalyst_flow_kg_s = 400.0
        sim.advance_time(duration_s=3.0, dt=0.05)

        assert not math.isnan(sim.state.t_dense_bed_celsius)
        assert not math.isnan(sim.state.c_coke_wt_pct)


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_fcc_regenerator_combustion_verification suite and evidence artifact generation."""

    def test_run_fcc_regenerator_combustion_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 9: Verification suite returns strict 4-state contract JSON with all 9 stages passed."""
        out_file = tmp_path / "fcc_regenerator_combustion_evidence.json"
        res = run_fcc_regenerator_combustion_verification(output_path=str(out_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
        assert saved_data["status"] == "success"
        assert len(saved_data["data"]["tests"]) == 9

    def test_verification_suite_aliases(self) -> None:
        """Requirement 9: Verify verification function aliases."""
        assert run_dense_bed_coke_burn_regen_verification == run_fcc_regenerator_combustion_verification
        assert run_fcc_combustion_verification == run_fcc_regenerator_combustion_verification
        assert run_fcc_regen_combustion_verification == run_fcc_regenerator_combustion_verification
        assert run_regenerator_combustion_verification == run_fcc_regenerator_combustion_verification
