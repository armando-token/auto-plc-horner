"""Unit and Integration Tests for Industrial Steam Cracker Pyrolysis Furnace Tube Coking & Thermal Quench ODE Simulation.

Work Package: W179 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1400..%R1407, %M326..%M328).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Cracking kinetics, ethylene and propylene yield splits, endothermic heat of cracking.
4. Section 4: Asymptotic tube coking model, pressure drop delta_P rise, TMT elevation.
5. Section 5: Coupled 6-state ODE RK4 integration stability and dual conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xCC01 TMT overtemp, 0xCC02 coke dP high, 0xCC03 quench high temp, 0xCC04 low steam ratio) and Horner coil assertions (%M326, %M327, %M328).
7. Section 7: Horner OCS register space synchronization (%R1400..%R1407, %M326..%M328) with PrivilegeMode.SYSTEM.
8. Section 8: Dynamic disturbance response (quench trip perturbation, feed steam loss) and settling stability.
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
from jev_cscape.simulation.steam_cracker_furnace import (
    COIL_DP_CLEAN_BAR,
    COIL_DP_MAX_ALARM_BAR,
    COIL_DP_NOMINAL_BAR,
    COKE_THICKNESS_MAX_ALARM_MICRONS,
    COKE_THICKNESS_NOMINAL_MICRONS,
    COT_NOMINAL_C,
    DELTA_H_CRACKING_J_KG,
    DELTA_H_CRACKING_KJ_KG,
    DELTA_H_RXN_J_KG,
    DELTA_H_RXN_KJ_KG,
    ETHYLENE_YIELD_NOMINAL_PCT,
    G_ACCEL,
    MW_ETHYLENE,
    MW_HYDROGEN,
    MW_METHANE,
    MW_NAPHTHA_MEAN,
    MW_PROPYLENE,
    MW_WATER,
    NOMINAL_STEAM_TO_OIL_RATIO,
    PROPYLENE_YIELD_NOMINAL_PCT,
    PYROLYSIS_TUBE_COKING_QUENCH_PURE_ST_POU,
    PYROLYSIS_TUBE_COKING_QUENCH_SYNC_POU,
    R_GAS_CONST,
    STEAM_CRACKER_FURNACE_DYNAMICS_SYNC_POU,
    STEAM_CRACKER_FURNACE_PURE_ST_POU,
    STEAM_CRACKER_FURNACE_SYNC_POU,
    STEAM_OIL_RATIO_MIN,
    TLE_QUENCH_MAX_TRIP_C,
    TLE_QUENCH_NOMINAL_C,
    TMT_MAX_TRIP_C,
    TMT_NOMINAL_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    FurnaceConfig,
    FurnaceDiagnosticCode,
    FurnaceSimulator,
    FurnaceState,
    FurnaceStatusBits,
    PyrolysisTubeCokingQuenchConfig,
    PyrolysisTubeCokingQuenchDiagCode,
    PyrolysisTubeCokingQuenchDiagnosticCode,
    PyrolysisTubeCokingQuenchLogicUnit,
    PyrolysisTubeCokingQuenchSimulator,
    PyrolysisTubeCokingQuenchState,
    PyrolysisTubeCokingQuenchStatusBits,
    PyrolysisTubeCokingQuenchStatusWord,
    SteamCrackerConfig,
    SteamCrackerDiagnosticCode,
    SteamCrackerFurnaceConfig,
    SteamCrackerFurnaceDiagCode,
    SteamCrackerFurnaceDiagnosticCode,
    SteamCrackerFurnaceEngine,
    SteamCrackerFurnaceLogicUnit,
    SteamCrackerFurnaceModel,
    SteamCrackerFurnaceParameters,
    SteamCrackerFurnacePlantModel,
    SteamCrackerFurnaceSimulationEngine,
    SteamCrackerFurnaceSimulator,
    SteamCrackerFurnaceState,
    SteamCrackerFurnaceStatusBits,
    SteamCrackerFurnaceStatusWord,
    SteamCrackerSimulator,
    SteamCrackerState,
    SteamCrackerStatusBits,
    run_pyrolysis_tube_coking_quench_verification,
    run_steam_cracker_furnace_verification,
    run_steam_cracker_verification,
    validate_pure_st,
    verify_pyrolysis_tube_coking_quench_pure_st,
    verify_steam_cracker_furnace_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1400..%R1407, %M326..%M328)."""

    def test_verify_steam_cracker_furnace_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_steam_cracker_furnace_pure_st() is True
        assert verify_pyrolysis_tube_coking_quench_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1400..%R1407, %M326..%M328)."""
        SecurityGuard.assert_pure_st_content(STEAM_CRACKER_FURNACE_PURE_ST_POU)
        val = STParser.validate_code(STEAM_CRACKER_FURNACE_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(STEAM_CRACKER_FURNACE_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "SteamCrackerFurnaceSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1400", "%R1401", "%R1402", "%R1403",
            "%R1404", "%R1405", "%R1406", "%R1407",
            "%M326", "%M327", "%M328",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from SteamCrackerFurnaceSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate PyrolysisTubeCokingQuenchSync alias POU AST."""
        ast_alias = STParser.parse_pou(PYROLYSIS_TUBE_COKING_QUENCH_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "PyrolysisTubeCokingQuenchSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1400", "%R1401", "%R1402", "%R1403",
            "%R1404", "%R1405", "%R1406", "%R1407",
            "%M326", "%M327", "%M328",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers

    def test_pou_string_constants_and_sync_aliases(self) -> None:
        """Requirement 1: Verify string constants and sync POU aliases."""
        assert STEAM_CRACKER_FURNACE_SYNC_POU == STEAM_CRACKER_FURNACE_PURE_ST_POU
        assert PYROLYSIS_TUBE_COKING_QUENCH_SYNC_POU == PYROLYSIS_TUBE_COKING_QUENCH_PURE_ST_POU
        assert STEAM_CRACKER_FURNACE_DYNAMICS_SYNC_POU == STEAM_CRACKER_FURNACE_PURE_ST_POU

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
            "XIC FurnaceFiringPermissive",
            "XIO FurnaceEmergencyShutdownTrip",
            "OTE DecokingRequiredAlarm",
            "OTL FurnaceEmergencyShutdownTrip",
            "OTU FurnaceFiringPermissive",
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
# 3. Section 3: Cracking Kinetics, Product Yield Splits & Endothermic Heat
# ============================================================================

class TestSection3CrackingKineticsAndYieldSplits:
    """Tests for naphtha cracking reaction kinetics, endothermic enthalpy (+1650 kJ/kg feed), and olefin splits."""

    def test_reaction_enthalpy_constants(self) -> None:
        """Requirement 3: Delta H_rxn = +1650 kJ/kg feed (endothermic heat of cracking)."""
        assert DELTA_H_CRACKING_KJ_KG == 1650.0
        assert DELTA_H_CRACKING_J_KG == 1650000.0
        assert DELTA_H_RXN_KJ_KG == 1650.0
        assert DELTA_H_RXN_J_KG == 1650000.0

    def test_olefin_nominal_yield_distributions(self) -> None:
        """Requirement 3: Ethylene (33.5%), Propylene (14.8%), and complete stoichiometric split summing to 100%."""
        sim = SteamCrackerFurnaceSimulator()
        assert sim.state.ethylene_yield_pct == 33.5
        assert sim.state.propylene_yield_pct == 14.8
        assert sim.state.y_ethylene == 0.335
        assert sim.state.y_propylene == 0.148
        assert sim.state.methane_yield_pct == 15.2
        assert sim.state.pygas_yield_pct == 18.5
        assert sim.state.hydrogen_yield_pct == 1.5
        assert sim.state.fuel_oil_yield_pct == 3.5
        assert sim.state.uncracked_naphtha_yield_pct == 13.0

        total_yield = (
            sim.state.ethylene_yield_pct
            + sim.state.propylene_yield_pct
            + sim.state.methane_yield_pct
            + sim.state.pygas_yield_pct
            + sim.state.hydrogen_yield_pct
            + sim.state.fuel_oil_yield_pct
            + sim.state.uncracked_naphtha_yield_pct
        )
        assert abs(total_yield - 100.0) < 1e-6

    def test_cracking_severity_monotonicity_with_cot(self) -> None:
        """Requirement 3: Higher Coil Outlet Temperature (COT) increases cracking severity and ethylene yield."""
        sim_nom = SteamCrackerFurnaceSimulator()
        sim_high = SteamCrackerFurnaceSimulator()
        sim_high.state.t_gas_cot_celsius = 855.0  # Elevated severity
        sim_high.step(dt=0.20)

        assert sim_high.state.ethylene_yield_pct > sim_nom.state.ethylene_yield_pct

    def test_feed_naphtha_and_dilution_steam_conditions(self) -> None:
        """Requirement 3: Verify nominal feed rates and steam-to-oil dilution ratio 0.50 kg/kg."""
        sim = SteamCrackerFurnaceSimulator()
        assert sim.state.feed_naphtha_flow_kg_s == 15.0
        assert sim.state.dilution_steam_flow_kg_s == 7.5
        assert sim.state.steam_hydrocarbon_ratio == 0.50
        assert NOMINAL_STEAM_TO_OIL_RATIO == 0.50
        assert STEAM_OIL_RATIO_MIN == 0.35

    def test_molecular_weight_constants(self) -> None:
        """Requirement 3: Validate universal molecular weight constants."""
        assert MW_ETHYLENE == 0.028054
        assert MW_PROPYLENE == 0.042081
        assert MW_METHANE == 0.016043
        assert MW_HYDROGEN == 0.00201588
        assert MW_WATER == 0.01801528
        assert MW_NAPHTHA_MEAN == 0.100000


# ============================================================================
# 4. Section 4: Asymptotic Tube Coking Model, Pressure Drop & TMT Elevation
# ============================================================================

class TestSection4AsymptoticCokingPressureDropAndTMT:
    """Tests for asymptotic coke growth, radiant coil pressure drop rise, and TMT profile."""

    def test_coke_layer_thickness_nominal_and_limits(self) -> None:
        """Requirement 4: Nominal coke thickness 2400 microns (2.4 mm) and alarm threshold 8000 microns."""
        sim = SteamCrackerFurnaceSimulator()
        assert sim.state.coke_layer_thickness_microns == 2400.0
        assert COKE_THICKNESS_NOMINAL_MICRONS == 2400.0
        assert COKE_THICKNESS_MAX_ALARM_MICRONS == 8000.0

    def test_radiant_coil_pressure_drop_clean_nominal_fouled(self) -> None:
        """Requirement 4: Clean coil dP 1.80 bar, nominal 2.10 bar, fouled > 3.50 bar."""
        sim = SteamCrackerFurnaceSimulator()
        dp_clean = sim.compute_pressure_drop(coke_microns=0.0)
        dp_nom = sim.compute_pressure_drop(coke_microns=2400.0)
        dp_fouled = sim.compute_pressure_drop(coke_microns=8500.0)

        assert abs(dp_clean - 1.80) < 1e-3
        assert abs(dp_nom - 2.10) < 1e-3
        assert dp_fouled > 3.50
        assert COIL_DP_CLEAN_BAR == 1.80
        assert COIL_DP_NOMINAL_BAR == 2.10
        assert COIL_DP_MAX_ALARM_BAR == 3.50
        assert dp_clean < dp_nom < dp_fouled

    def test_tmt_elevation_and_furnace_temperature_profile(self) -> None:
        """Requirement 4: COT 840 °C, TMT 1020 °C (limit 1080 °C), TLE quench 405 °C (limit 460 °C)."""
        sim = SteamCrackerFurnaceSimulator()
        assert sim.state.t_gas_cot_celsius == 840.0
        assert sim.state.t_tube_metal_celsius == 1020.0
        assert sim.state.t_quench_outlet_celsius == 405.0
        assert COT_NOMINAL_C == 840.0
        assert TMT_NOMINAL_C == 1020.0
        assert TMT_MAX_TRIP_C == 1080.0
        assert TLE_QUENCH_NOMINAL_C == 405.0
        assert TLE_QUENCH_MAX_TRIP_C == 460.0

        # Tube metal temperature is strictly greater than gas temperature
        assert sim.state.t_tube_metal_celsius > sim.state.t_gas_cot_celsius
        assert sim.state.t_tube_metal_celsius - sim.state.t_gas_cot_celsius == 180.0

    def test_hydrodynamics_gas_superficial_velocity_and_quench_delta_t(self) -> None:
        """Requirement 4: Radiant coil superficial velocity (15..35 m/s) and TLE rapid quench Delta T."""
        sim = SteamCrackerFurnaceSimulator()
        hydro = sim.compute_hydrodynamics()
        u_gas = hydro["gas_superficial_velocity_m_s"]
        quench_dt = hydro["quench_cooling_delta_t"]

        assert 15.0 <= u_gas <= 35.0
        assert abs(quench_dt - 435.0) < 1e-2  # 840.0 - 405.0 = 435.0 °C
        assert hydro["ua_eff_kw_k"] > 150.0


# ============================================================================
# 5. Section 5: Coupled 6-State ODE RK4 Integration & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states_bounded(self) -> None:
        """Requirement 5: Advance ODE system via high-order RK4 over 5.0s and verify state stability."""
        sim = SteamCrackerFurnaceSimulator()
        res = sim.advance_time(duration_s=5.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 820.0 <= sim.state.t_gas_cot_celsius <= 860.0
        assert 1000.0 <= sim.state.t_tube_metal_celsius <= 1040.0
        assert 0.30 <= sim.state.y_ethylene <= 0.38
        assert 0.12 <= sim.state.y_propylene <= 0.18
        assert 2000.0 <= sim.state.coke_layer_thickness_microns <= 3000.0
        assert 395.0 <= sim.state.t_quench_outlet_celsius <= 425.0

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 5: Mass balance, elemental balance, and enthalpy residuals < 1e-10."""
        sim = SteamCrackerFurnaceSimulator()
        sim.advance_time(duration_s=3.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_rk4_all_derivatives_finite(self) -> None:
        """Requirement 5: Verify all 6 ODE state derivatives remain finite without NaN or Inf."""
        sim = SteamCrackerFurnaceSimulator()
        y0 = [840.0, 1020.0, 0.335, 0.148, 2400.0, 405.0]
        derivs = sim.compute_derivatives(0.0, y0)

        assert len(derivs) == 6
        for i, d in enumerate(derivs):
            assert not math.isnan(d), f"Derivative {i} is NaN"
            assert not math.isinf(d), f"Derivative {i} is infinite"

    def test_invalid_timestep_handling(self) -> None:
        """Requirement 5: Non-positive integration timestep fails cleanly."""
        sim = SteamCrackerFurnaceSimulator()
        res_neg = sim.step(dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

        res_zero = sim.advance_time(duration_s=0.0, dt=0.05)
        assert res_zero.status == AgentStatus.FAILED


# ============================================================================
# 6. Section 6: Process Safety Interlocks, Diagnostics & Coils
# ============================================================================

class TestSection6ProcessSafetyInterlocksAndDiagnostics:
    """Tests for safety trips (0xCC01..0xCC04) and Horner coil assertions (%M326, %M327, %M328)."""

    def test_tmt_overtemperature_emergency_trip_0xcc01(self) -> None:
        """Requirement 6: 0xCC01 TMT overtemperature (> 1080 °C) asserts %M327, clears %M326."""
        sim = SteamCrackerFurnaceSimulator()
        sim.state.t_tube_metal_celsius = 1085.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == SteamCrackerFurnaceDiagnosticCode.FURNACE_ERR_TMT_OVERTEMPERATURE
        assert sim.state.furnace_emergency_shutdown_trip is True
        assert sim.state.furnace_firing_permissive is False

    def test_coke_pressure_drop_high_alarm_0xcc02(self) -> None:
        """Requirement 6: 0xCC02 Coke dP > 3.5 bar asserts %M328 (DecokingRequiredAlarm)."""
        sim = SteamCrackerFurnaceSimulator()
        sim.state.radiant_coil_pressure_drop_bar = 3.65
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == SteamCrackerFurnaceDiagnosticCode.FURNACE_ERR_COKE_PRESSURE_DROP_HIGH
        assert sim.state.decoking_required_alarm is True
        assert sim.state.furnace_firing_permissive is True
        assert sim.state.furnace_emergency_shutdown_trip is False

    def test_coke_thickness_high_alarm_0xcc02(self) -> None:
        """Requirement 6: 0xCC02 Coke thickness > 8000 um asserts %M328."""
        sim = SteamCrackerFurnaceSimulator()
        sim.state.radiant_coil_pressure_drop_bar = 2.10
        sim.state.coke_layer_thickness_microns = 8200.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == SteamCrackerFurnaceDiagnosticCode.FURNACE_ERR_COKE_PRESSURE_DROP_HIGH
        assert sim.state.decoking_required_alarm is True

    def test_tle_quench_high_temp_fault_0xcc03(self) -> None:
        """Requirement 6: 0xCC03 TLE quench outlet temperature > 460 °C sets fault code."""
        sim = SteamCrackerFurnaceSimulator()
        sim.state.radiant_coil_pressure_drop_bar = 2.10
        sim.state.coke_layer_thickness_microns = 2400.0
        sim.state.t_quench_outlet_celsius = 468.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == SteamCrackerFurnaceDiagnosticCode.FURNACE_ERR_TLE_QUENCH_HIGH_TEMP
        assert sim.state.tle_quench_high_temp_fault is True
        assert sim.state.furnace_firing_permissive is True

    def test_steam_hydrocarbon_ratio_low_fault_0xcc04(self) -> None:
        """Requirement 6: 0xCC04 Steam-to-oil dilution ratio < 0.35 kg/kg sets fault code."""
        sim = SteamCrackerFurnaceSimulator()
        sim.state.t_quench_outlet_celsius = 405.0
        sim.state.steam_hydrocarbon_ratio = 0.28
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == SteamCrackerFurnaceDiagnosticCode.FURNACE_ERR_STEAM_HYDROCARBON_RATIO_LOW
        assert sim.state.steam_hc_ratio_low_fault is True
        assert sim.state.furnace_firing_permissive is True

    def test_safety_priority_hierarchy(self) -> None:
        """Requirement 6: Priority Hierarchy 0xCC01 > 0xCC02 > 0xCC03 > 0xCC04."""
        sim = SteamCrackerFurnaceSimulator()
        sim.state.t_tube_metal_celsius = 1092.0          # 0xCC01
        sim.state.radiant_coil_pressure_drop_bar = 3.80  # 0xCC02
        sim.state.t_quench_outlet_celsius = 475.0        # 0xCC03
        sim.state.steam_hydrocarbon_ratio = 0.25         # 0xCC04
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xCC01
        assert sim.state.furnace_emergency_shutdown_trip is True
        assert sim.state.furnace_firing_permissive is False
        assert sim.state.decoking_required_alarm is True

    def test_normal_healthy_clears_all_trips(self) -> None:
        """Requirement 6: Healthy state resets diagnostic code to 0x0000 and activates permissive."""
        sim = SteamCrackerFurnaceSimulator()
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == SteamCrackerFurnaceDiagnosticCode.OK
        assert sim.state.furnace_firing_permissive is True
        assert sim.state.furnace_emergency_shutdown_trip is False
        assert sim.state.decoking_required_alarm is False


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration (%R1400..%R1407, %M326..%M328)
# ============================================================================

class TestSection7HornerOCSMemorySpaceIntegration:
    """Tests for %R1400..%R1407 and %M326..%M328 scaling and PrivilegeMode.SYSTEM enforcement."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 7: Verify scaled values in RegisterTable."""
        reg = RegisterTable()
        sim = SteamCrackerFurnaceSimulator(register_table=reg)

        sim.state.t_gas_cot_celsius = 840.0
        sim.state.t_tube_metal_celsius = 1020.0
        sim.state.radiant_coil_pressure_drop_bar = 2.10
        sim.state.coke_layer_thickness_microns = 2400.0
        sim.state.ethylene_yield_pct = 33.5
        sim.state.propylene_yield_pct = 14.8
        sim.state.t_quench_outlet_celsius = 405.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1400") == 8400
        assert reg.read_word("%R1401") == 10200
        assert reg.read_word("%R1402") == 210
        assert reg.read_word("%R1403") == 2400
        assert reg.read_word("%R1404") == 335
        assert reg.read_word("%R1405") == 148
        assert reg.read_word("%R1406") == 4050
        assert reg.read_word("%R1407") & 0xFFFF == 0x0000

        assert reg.read_bit("%M326") is True
        assert reg.read_bit("%M327") is False
        assert reg.read_bit("%M328") is False

    def test_system_privilege_enforced(self) -> None:
        """Requirement 7: Internal write operations use PrivilegeMode.SYSTEM without privilege errors."""
        reg = RegisterTable()
        sim = SteamCrackerFurnaceSimulator(register_table=reg)
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1400") == 8400

    def test_ilogicunit_protocol_compliance_and_scan_step(self) -> None:
        """Requirement 7: ILogicUnit protocol compliance and scan_step return dictionary."""
        sim = SteamCrackerFurnaceSimulator()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "SteamCrackerFurnaceSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

        res_dict = sim.scan_step(dt=0.05)
        assert res_dict["status"] == "success"
        assert "t_gas_cot_celsius" in res_dict
        assert "t_tube_metal_celsius" in res_dict
        assert "radiant_coil_pressure_drop_bar" in res_dict
        assert "coke_layer_thickness_microns" in res_dict
        assert "ethylene_yield_pct" in res_dict
        assert "propylene_yield_pct" in res_dict
        assert "t_quench_outlet_celsius" in res_dict
        assert "diagnostic_code" in res_dict
        assert "furnace_firing_permissive" in res_dict
        assert "furnace_emergency_shutdown_trip" in res_dict
        assert "decoking_required_alarm" in res_dict

    def test_scan_context_adapter_execution(self) -> None:
        """Requirement 7: Verify execute(ScanContext) multi-cycle adapter execution."""
        reg = RegisterTable()
        sim = SteamCrackerFurnaceSimulator(register_table=reg)
        unit = SteamCrackerFurnaceLogicUnit(config=sim.config, register_table=reg)
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
        assert reg.read_word("%R1400") == 8400
        assert reg.read_word("%R1401") == 10200
        assert reg.read_bit("%M326") is True


# ============================================================================
# 8. Section 8: Dynamic Disturbance Response & Closed-Loop Settling
# ============================================================================

class TestSection8DynamicDisturbanceResponseAndSettling:
    """Tests for transient disturbance response (COT spike, feed steam loss) and settling stability."""

    def test_cot_transient_disturbance_response(self) -> None:
        """Requirement 8: +10 °C COT disturbance settles cleanly without instability."""
        sim = SteamCrackerFurnaceSimulator()
        sim.state.t_gas_cot_celsius = 850.0  # +10.0 °C disturbance
        res = sim.advance_time(duration_s=8.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert not math.isnan(sim.state.t_gas_cot_celsius)
        assert not math.isnan(sim.state.t_tube_metal_celsius)
        assert 830.0 <= sim.state.t_gas_cot_celsius <= 855.0
        assert sim.state.furnace_firing_permissive is True
        assert sim.state.furnace_emergency_shutdown_trip is False

    def test_feed_steam_loss_disturbance_and_recovery(self) -> None:
        """Requirement 8: Loss of dilution steam trips fault 0xCC04; restoration recovers permissive."""
        sim = SteamCrackerFurnaceSimulator()

        # Disturbance: Steam cut to 3.0 kg/s (ratio = 0.20 kg/kg < 0.35)
        sim.state.dilution_steam_flow_kg_s = 3.0
        sim.state.steam_hydrocarbon_ratio = 3.0 / 15.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == SteamCrackerFurnaceDiagnosticCode.FURNACE_ERR_STEAM_HYDROCARBON_RATIO_LOW
        assert sim.state.steam_hc_ratio_low_fault is True

        # Recovery: Restore steam flow to 7.5 kg/s (ratio = 0.50 kg/kg)
        sim.state.dilution_steam_flow_kg_s = 7.5
        sim.state.steam_hydrocarbon_ratio = 0.50
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == SteamCrackerFurnaceDiagnosticCode.OK
        assert sim.state.steam_hc_ratio_low_fault is False
        assert sim.state.furnace_firing_permissive is True

    def test_tle_quench_cooling_temperature_tracking(self) -> None:
        """Requirement 8: TLE rapid quench outlet dynamically follows COT changes."""
        sim = SteamCrackerFurnaceSimulator()
        sim.state.t_gas_cot_celsius = 848.0
        sim.advance_time(duration_s=2.0, dt=0.05)

        # Quench outlet temperature adjusts smoothly
        assert 400.0 <= sim.state.t_quench_outlet_celsius <= 415.0
        assert not math.isnan(sim.state.t_quench_outlet_celsius)


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_steam_cracker_furnace_verification suite and evidence artifact generation."""

    def test_run_steam_cracker_furnace_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 9: Verification suite returns strict 4-state contract JSON with all 9 stages passed."""
        out_file = tmp_path / "steam_cracker_furnace_evidence.json"
        res = run_steam_cracker_furnace_verification(output_path=str(out_file))

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
        assert run_pyrolysis_tube_coking_quench_verification == run_steam_cracker_furnace_verification
        assert run_steam_cracker_verification == run_steam_cracker_furnace_verification
