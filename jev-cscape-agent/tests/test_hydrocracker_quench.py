"""Unit and Integration Tests for Industrial Hydrocracking Heavy Gas Oil Trickle-Bed Hydrodynamics & Cracking Quench ODE Simulation.

Work Package: W176 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1370..%R1377, %M319..%M321).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Trickle-bed hydrodynamics, multi-phase pressure drop, and inter-bed quench injection mechanics.
4. Section 4: Hydrocracking reaction kinetics, exothermic reaction heat (-42 kJ/mol H2), and yield splits.
5. Section 5: Coupled 6-state ODE RK4 integration stability and dual conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xC901, 0xC902, 0xC903, 0xC904) and Horner coil assertions (%M319, %M320, %M321).
7. Section 7: Horner OCS register space synchronization (%R1370..%R1377, %M319..%M321) with PrivilegeMode.SYSTEM.
8. Section 8: Dynamic disturbance response and closed-loop settling stability.
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
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.hydrocracker_quench import (
    DELTA_H_CRACKING_J_MOL,
    DELTA_H_CRACKING_KJ_MOL,
    DELTA_H_CRACK_J_MOL,
    DELTA_H_CRACK_KJ_MOL,
    DELTA_H_HC_J_MOL,
    DELTA_H_HC_J_MOL_H2,
    DELTA_H_HC_KJ_MOL,
    DELTA_H_HC_KJ_MOL_H2,
    DELTA_H_HYDROCRACKING_J_MOL,
    DELTA_H_HYDROCRACKING_KJ_MOL,
    G_ACCEL,
    HEAVY_GAS_OIL_CRACKING_QUENCH_PURE_ST_POU,
    HEAVY_GAS_OIL_CRACKING_QUENCH_SYNC_POU,
    HYDROCRACKER_BED_QUENCH_PURE_ST_POU,
    HYDROCRACKER_BED_QUENCH_SYNC_POU,
    HYDROCRACKER_QUENCH_DYNAMICS_SYNC_POU,
    HYDROCRACKER_QUENCH_PURE_ST_POU,
    HYDROCRACKER_QUENCH_SYNC_POU,
    HeavyGasOilCrackingDiagCode,
    HeavyGasOilCrackingQuenchConfig,
    HeavyGasOilCrackingQuenchDiagnosticCode,
    HeavyGasOilCrackingQuenchLogicUnit,
    HeavyGasOilCrackingQuenchSimulator,
    HeavyGasOilCrackingQuenchState,
    HeavyGasOilCrackingQuenchStatusBits,
    HeavyGasOilCrackingQuenchStatusWord,
    HydrocrackerBedQuenchConfig,
    HydrocrackerBedQuenchDiagCode,
    HydrocrackerBedQuenchDiagnosticCode,
    HydrocrackerBedQuenchLogicUnit,
    HydrocrackerBedQuenchParameters,
    HydrocrackerBedQuenchSimulator,
    HydrocrackerBedQuenchState,
    HydrocrackerBedQuenchStatusBits,
    HydrocrackerBedQuenchStatusWord,
    HydrocrackerDiagCode,
    HydrocrackerDiagnosticCode,
    HydrocrackerQuenchConfig,
    HydrocrackerQuenchDiagCode,
    HydrocrackerQuenchDiagnosticCode,
    HydrocrackerQuenchEngine,
    HydrocrackerQuenchLogicUnit,
    HydrocrackerQuenchModel,
    HydrocrackerQuenchParameters,
    HydrocrackerQuenchPlantModel,
    HydrocrackerQuenchSimulationEngine,
    HydrocrackerQuenchSimulator,
    HydrocrackerQuenchState,
    HydrocrackerQuenchStatusBits,
    HydrocrackerQuenchStatusWord,
    HydrocrackerStatusBits,
    HydrocrackerStatusWord,
    MW_DIESEL,
    MW_FEED_OIL,
    MW_H2,
    MW_HEAVY_GAS_OIL,
    MW_HGO,
    MW_JET_FUEL,
    MW_KEROSENE,
    MW_LIGHT_NAPHTHA,
    MW_NAPHTHA,
    MW_OIL,
    MW_ULSD,
    QuenchBedConfig,
    QuenchBedDynamics,
    QuenchBedLogicUnit,
    QuenchBedParameters,
    QuenchBedSimulator,
    QuenchBedState,
    QuenchDiagnosticCode,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    run_heavy_gas_oil_cracking_quench_verification,
    run_hydrocracker_bed_quench_verification,
    run_hydrocracker_quench_verification,
    run_hydrocracking_quench_verification,
    validate_pure_st,
    verify_heavy_gas_oil_cracking_quench_pure_st,
    verify_hydrocracker_bed_quench_pure_st,
    verify_hydrocracker_quench_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1370..%R1377, %M319..%M321)."""

    def test_verify_hydrocracker_quench_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_hydrocracker_quench_pure_st() is True
        assert verify_hydrocracker_bed_quench_pure_st() is True
        assert verify_heavy_gas_oil_cracking_quench_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1370..%R1377, %M319..%M321)."""
        SecurityGuard.assert_pure_st_content(HYDROCRACKER_BED_QUENCH_PURE_ST_POU)
        val = STParser.validate_code(HYDROCRACKER_BED_QUENCH_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(HYDROCRACKER_BED_QUENCH_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "HydrocrackerBedQuenchSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1370", "%R1371", "%R1372", "%R1373",
            "%R1374", "%R1375", "%R1376", "%R1377",
            "%M319", "%M320", "%M321",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from HydrocrackerBedQuenchSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate HeavyGasOilCrackingQuenchSync alias POU AST."""
        ast_alias = STParser.parse_pou(HEAVY_GAS_OIL_CRACKING_QUENCH_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "HeavyGasOilCrackingQuenchSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1370", "%R1371", "%R1372", "%R1373",
            "%R1374", "%R1375", "%R1376", "%R1377",
            "%M319", "%M320", "%M321",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers

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
            "XIC HydrocrackerPermissive",
            "XIO HydrocrackerThermalTrip",
            "OTE QuenchValveAnomalyAlarm",
            "OTL HydrocrackerThermalTrip",
            "OTU HydrocrackerPermissive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_fragment: str) -> None:
        """Requirement 1: Verify SecurityGuard.assert_pure_st_content raises LadderForbiddenError."""
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
# 3. Section 3: High-Pressure Trickle-Bed Hydrodynamics & Quench Mechanics
# ============================================================================

class TestSection3TrickleBedHydrodynamicsAndQuench:
    """Tests for two-phase trickle bed hydrodynamics and cold hydrogen quench enthalpy mixing."""

    def test_hydrodynamics_nominal_conditions(self) -> None:
        """Requirement 2: Verify liquid superficial velocity, gas superficial velocity, and liquid holdup."""
        sim = HydrocrackerQuenchSimulator()
        hydro = sim.compute_hydrodynamics()

        assert 0.005 <= hydro["u_l_m_s"] <= 0.030
        assert 0.040 <= hydro["u_g_m_s"] <= 0.200
        assert 0.10 <= hydro["liquid_holdup_fraction"] <= 0.35
        assert hydro["two_phase_dp_bar"] > 0.0
        assert hydro["kla_mass_transfer_s_inv"] > 0.0

    def test_quench_enthalpy_mixing_cooling(self) -> None:
        """Requirement 2: Inter-bed quench injection (4.5 kg/s at 45 °C) cools Bed 1 effluent before Bed 2."""
        sim = HydrocrackerQuenchSimulator()
        hydro = sim.compute_hydrodynamics(
            t_bed1_c=413.0,
            t_bed2_c=403.0,
            p_bar=160.0,
            m_quench_kg_s=4.5,
        )
        assert 385.0 <= hydro["t_quench_mix_calc_c"] <= 390.0
        assert abs(hydro["t_quench_mix_calc_c"] - 388.0) < 0.1
        assert 20.0 <= hydro["quench_cooling_delta_t"] <= 30.0
        assert abs(hydro["quench_cooling_delta_t"] - 25.0) < 0.1

    def test_quench_cooling_scales_with_flow(self) -> None:
        """Requirement 2: Higher quench flow increases cooling and lowers mixed temperature."""
        sim = HydrocrackerQuenchSimulator()
        h_low_q = sim.compute_hydrodynamics(t_bed1_c=413.0, m_quench_kg_s=3.0)
        h_nom_q = sim.compute_hydrodynamics(t_bed1_c=413.0, m_quench_kg_s=4.5)
        h_high_q = sim.compute_hydrodynamics(t_bed1_c=413.0, m_quench_kg_s=6.0)

        assert h_low_q["t_quench_mix_calc_c"] > h_nom_q["t_quench_mix_calc_c"] > h_high_q["t_quench_mix_calc_c"]
        assert h_low_q["quench_cooling_delta_t"] < h_nom_q["quench_cooling_delta_t"] < h_high_q["quench_cooling_delta_t"]


# ============================================================================
# 4. Section 4: Hydrocracking Reaction Kinetics & Exothermic Heat Generation
# ============================================================================

class TestSection4HydrocrackingKineticsAndExothermicHeat:
    """Tests for reaction kinetics, reaction enthalpy (-42 kJ/mol H2), and yield distributions."""

    def test_reaction_enthalpy_constants(self) -> None:
        """Requirement 2: delta H_hc = -42 kJ/mol H2 consumed."""
        assert DELTA_H_HC_KJ_MOL_H2 == -42.0
        assert DELTA_H_HC_J_MOL_H2 == -42000.0
        assert DELTA_H_HYDROCRACKING_KJ_MOL == -42.0
        assert DELTA_H_HYDROCRACKING_J_MOL == -42000.0

    def test_arrhenius_kinetics_monotonicity_with_temperature(self) -> None:
        """Requirement 2: Cracking reaction rate increases monotonically with bed temperature."""
        sim = HydrocrackerQuenchSimulator()
        rx_380 = sim.compute_reaction_rates(380.0, 375.0, 0.050, 160.0)
        rx_413 = sim.compute_reaction_rates(413.0, 403.0, 0.050, 160.0)
        rx_430 = sim.compute_reaction_rates(430.0, 420.0, 0.050, 160.0)

        assert rx_380["k_crack1"] < rx_413["k_crack1"] < rx_430["k_crack1"]
        assert rx_380["q_rxn_total_kw"] < rx_413["q_rxn_total_kw"] < rx_430["q_rxn_total_kw"]

    def test_bed1_axial_exotherm_range(self) -> None:
        """Requirement 2: Bed 1 axial exotherm delta T = 15..25 °C across Bed 1."""
        sim = HydrocrackerQuenchSimulator()
        delta_t_b1 = sim.state.t_bed1_celsius - sim.state.t_bed1_inlet_celsius
        assert 15.0 <= delta_t_b1 <= 25.0
        assert delta_t_b1 == 18.0

    def test_middle_distillates_yields(self) -> None:
        """Requirement 2: Middle distillates ULSD Diesel (61.5%) + Jet Fuel / Kerosene (24.5%)."""
        sim = HydrocrackerQuenchSimulator()
        assert sim.state.diesel_yield_pct == 61.5
        assert sim.state.kerosene_jet_yield_pct == 24.5
        assert sim.state.y_diesel == 0.615
        assert sim.state.y_kerosene == 0.245
        assert sim.state.diesel_yield_pct + sim.state.kerosene_jet_yield_pct == 86.0

    def test_molecular_weight_constants(self) -> None:
        """Requirement 2: Validate molecular weight constants."""
        assert MW_H2 == 0.00201588
        assert MW_HGO == 0.380
        assert MW_DIESEL == 0.220
        assert MW_KEROSENE == 0.160
        assert MW_NAPHTHA == 0.090


# ============================================================================
# 5. Section 5: Coupled 6-State ODE System & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states_bounded(self) -> None:
        """Requirement 2: Advance ODE system via high-order RK4 over 5.0s and verify state stability."""
        sim = HydrocrackerQuenchSimulator()
        res = sim.advance_time(duration_s=5.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 400.0 <= sim.state.t_bed1_celsius <= 420.0
        assert 395.0 <= sim.state.t_bed2_celsius <= 415.0
        assert 0.02 <= sim.state.y_hgo_feed <= 0.10
        assert 0.55 <= sim.state.y_diesel <= 0.70
        assert 0.20 <= sim.state.y_kerosene <= 0.30
        assert 380.0 <= sim.state.t_quench_mix_celsius <= 395.0

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 2: Elemental mass balance and enthalpy residuals < 1e-10."""
        sim = HydrocrackerQuenchSimulator()
        sim.advance_time(duration_s=3.0, dt=0.05)

        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_derivative_computations_finite(self) -> None:
        """Requirement 2: Ensure derivatives are finite and non-NaN."""
        sim = HydrocrackerQuenchSimulator()
        derivs = sim.compute_derivatives(0.0, [413.0, 403.0, 0.050, 0.615, 0.245, 388.0])
        assert len(derivs) == 6
        assert all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    def test_invalid_timestep_handling(self) -> None:
        """Requirement 2: Verify error handling on non-positive duration or dt."""
        sim = HydrocrackerQuenchSimulator()
        res_neg = sim.advance_time(duration_s=-1.0, dt=0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

        res_zero = sim.advance_time(duration_s=1.0, dt=0.0)
        assert res_zero.status == AgentStatus.FAILED


# ============================================================================
# 6. Section 6: Process Safety Interlocks & Diagnostics
# ============================================================================

class TestSection6ProcessSafetyInterlocksAndTrips:
    """Tests for process safety trips (0xC901..0xC904), priority hierarchy, and coil assertions (%M319..%M321)."""

    def test_trip_0xc901_bed_thermal_runaway(self) -> None:
        """Requirement 3: 0xC901 HC_ERR_BED_THERMAL_RUNAWAY (Bed temp > 425 °C) -> asserts %M320, clears %M319."""
        sim = HydrocrackerQuenchSimulator()
        sim.state.t_bed1_celsius = 428.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xC901
        assert sim.state.hydrocracker_thermal_trip is True
        assert sim.state.hydrocracker_permissive is False

    def test_alarm_0xc902_quench_valve_fail(self) -> None:
        """Requirement 3: 0xC902 HC_ERR_QUENCH_VALVE_FAIL (Quench flow deviation > 30% from demand) -> asserts %M321."""
        sim = HydrocrackerQuenchSimulator()
        # demand is 4.5 kg/s. 30% dev is 1.35 kg/s. Flow 2.5 kg/s -> deviation = 2.0 / 4.5 = 44.4% > 30%
        sim.state.cold_hydrogen_quench_flow_kg_s = 2.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xC902
        assert sim.state.quench_valve_anomaly_alarm is True
        assert sim.state.hydrocracker_permissive is True
        assert sim.state.hydrocracker_thermal_trip is False

    def test_alarm_0xc902_quench_valve_jammed(self) -> None:
        """Requirement 3: 0xC902 HC_ERR_QUENCH_VALVE_FAIL when valve jammed."""
        sim = HydrocrackerQuenchSimulator()
        sim.state.quench_valve_jammed = True
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xC902
        assert sim.state.quench_valve_anomaly_alarm is True

    def test_fault_0xc903_high_pressure_surge(self) -> None:
        """Requirement 3: 0xC903 HC_ERR_HIGH_PRESSURE_SURGE (Reactor pressure > 185 bar)."""
        sim = HydrocrackerQuenchSimulator()
        sim.state.reactor_pressure_bar = 188.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xC903
        assert sim.state.high_pressure_surge_fault is True
        assert sim.state.hydrocracker_permissive is True

    def test_fault_0xc904_maldistribution_hotspot(self) -> None:
        """Requirement 3: 0xC904 HC_ERR_MALDISTRIBUTION_HOTSPOT (exotherm gradient > 28 °C)."""
        sim = HydrocrackerQuenchSimulator()
        sim.state.catalyst_bed_max_exotherm_delta_t = 30.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xC904
        assert sim.state.maldistribution_hotspot_fault is True
        assert sim.state.hydrocracker_permissive is True

    def test_priority_hierarchy(self) -> None:
        """Requirement 3: Priority Hierarchy 0xC901 > 0xC902 > 0xC903 > 0xC904."""
        sim = HydrocrackerQuenchSimulator()
        sim.state.t_bed1_celsius = 432.0                      # 0xC901
        sim.state.cold_hydrogen_quench_flow_kg_s = 2.0        # 0xC902
        sim.state.reactor_pressure_bar = 190.0                # 0xC903
        sim.state.catalyst_bed_max_exotherm_delta_t = 32.0    # 0xC904
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xC901
        assert sim.state.hydrocracker_thermal_trip is True
        assert sim.state.hydrocracker_permissive is False
        assert sim.state.quench_valve_anomaly_alarm is True


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration
# ============================================================================

class TestSection7HornerOCSMemorySpaceIntegration:
    """Tests for %R1370..%R1377 and %M319..%M321 scaling and PrivilegeMode.SYSTEM enforcement."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 4: Verify scaled values in RegisterTable."""
        reg = RegisterTable()
        sim = HydrocrackerQuenchSimulator(register_table=reg)

        sim.state.t_bed1_inlet_celsius = 395.0
        sim.state.t_bed2_inlet_celsius = 388.0
        sim.state.reactor_pressure_bar = 160.0
        sim.state.cold_hydrogen_quench_flow_kg_s = 4.5
        sim.state.diesel_yield_pct = 61.5
        sim.state.kerosene_jet_yield_pct = 24.5
        sim.state.catalyst_bed_max_exotherm_delta_t = 18.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1370") == 3950
        assert reg.read_word("%R1371") == 3880
        assert reg.read_word("%R1372") == 1600
        assert reg.read_word("%R1373") == 45
        assert reg.read_word("%R1374") == 615
        assert reg.read_word("%R1375") == 245
        assert reg.read_word("%R1376") == 180
        assert reg.read_word("%R1377") & 0xFFFF == 0x0000

        assert reg.read_bit("%M319") is True
        assert reg.read_bit("%M320") is False
        assert reg.read_bit("%M321") is False

    def test_system_privilege_enforced(self) -> None:
        """Requirement 4: Internal write operations use PrivilegeMode.SYSTEM without privilege errors."""
        reg = RegisterTable()
        sim = HydrocrackerQuenchSimulator(register_table=reg)
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1370") == 3950

    def test_ilogicunit_protocol_compliance_and_scan_step(self) -> None:
        """Requirement 2: ILogicUnit protocol compliance and scan_step return dictionary."""
        sim = HydrocrackerQuenchSimulator()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "HydrocrackerBedQuenchSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

        res_dict = sim.scan_step(dt=0.05)
        assert res_dict["status"] == "success"
        assert "t_bed1_celsius" in res_dict
        assert "diesel_yield_pct" in res_dict
        assert res_dict["hydrocracker_permissive"] is True

    def test_scan_context_adapter_execution(self) -> None:
        """Requirement 2: Verify execute(ScanContext)."""
        reg = RegisterTable()
        sim = HydrocrackerQuenchSimulator(register_table=reg)
        unit = HydrocrackerQuenchLogicUnit(config=sim.config, register_table=reg)
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
        assert reg.read_word("%R1370") == 3950


# ============================================================================
# 8. Section 8: Dynamic Disturbance Response & Closed-Loop Settling
# ============================================================================

class TestSection8DynamicDisturbanceResponse:
    """Tests for disturbance response and closed-loop settling."""

    def test_temperature_disturbance_settling(self) -> None:
        """Requirement 2: Transient response to +5.0 °C disturbance settles stably without NaNs."""
        sim = HydrocrackerQuenchSimulator()
        sim.state.t_bed1_celsius = 418.0
        res = sim.advance_time(duration_s=8.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert not math.isnan(sim.state.t_bed1_celsius)
        assert not math.isinf(sim.state.t_bed1_celsius)
        assert 405.0 <= sim.state.t_bed1_celsius <= 420.0
        assert sim.state.hydrocracker_permissive is True
        assert sim.state.hydrocracker_thermal_trip is False

    def test_quench_step_disturbance(self) -> None:
        """Requirement 2: Transient response to quench flow step from 4.5 to 5.2 kg/s."""
        sim = HydrocrackerQuenchSimulator()
        sim.state.cold_hydrogen_quench_flow_kg_s = 5.2
        res = sim.advance_time(duration_s=5.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        # Higher quench flow causes cooling of quench mix
        assert sim.state.t_quench_mix_celsius < 388.0
        assert sim.state.hydrocracker_permissive is True


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_hydrocracker_quench_verification suite and evidence artifact generation."""

    def test_run_hydrocracker_quench_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 5: Verification suite returns strict 4-state contract JSON with all 9 stages passed."""
        out_file = tmp_path / "hydrocracker_quench_evidence.json"
        res = run_hydrocracker_quench_verification(output_path=str(out_file))

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
        """Requirement 5: Verify verification function aliases."""
        assert run_hydrocracker_bed_quench_verification == run_hydrocracker_quench_verification
        assert run_heavy_gas_oil_cracking_quench_verification == run_hydrocracker_quench_verification
        assert run_hydrocracking_quench_verification == run_hydrocracker_quench_verification
