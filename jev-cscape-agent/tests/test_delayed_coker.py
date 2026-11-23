"""Unit and Integration Tests for Industrial Delayed Coking Thermal Cracking Drum Simulation.

Work Package: W167 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1280..%R1287, %M298..%M300).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Delayed coking drum hydrodynamics, vapor velocity, level swell, foam height tracking, bed growth (~0.85 m/h).
4. Section 4: High-temperature residue thermal cracking kinetics, reaction enthalpy (+210 kJ/kg feed), Arrhenius monotonicity.
5. Section 5: Coupled 6-state ODE RK4 integration stability and dual stoichiometric conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xC001..0xC004), priority hierarchy, and Horner coil assertions (%M298..%M300).
7. Section 7: Horner OCS register space synchronization (%R1280..%R1287, %M298..%M300) with PrivilegeMode.SYSTEM.
8. Section 8: ILogicUnit scan cycle execution, dynamic disturbance response, and closed-loop settling stability.
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
from jev_cscape.simulation.delayed_coker import (
    CokerConfig,
    CokerDiagnosticCode,
    CokerState,
    CokerStatusBits,
    DELAYED_COKER_DRUM_PURE_ST_POU,
    DELAYED_COKER_DRUM_SYNC_POU,
    DELAYED_COKER_DYNAMICS_SYNC_POU,
    DELAYED_COKER_PURE_ST_POU,
    DELAYED_COKER_SYNC_POU,
    DELAYED_COKING_DRUM_PURE_ST_POU,
    DELAYED_COKING_DRUM_SYNC_POU,
    DELAYED_COKING_PURE_ST_POU,
    DELAYED_COKING_THERMAL_CRACKING_PURE_ST_POU,
    DELAYED_COKING_THERMAL_CRACKING_SYNC_POU,
    DELTA_H_COKE_J_KG,
    DELTA_H_COKE_KJ_KG,
    DELTA_H_CRACK_J_KG,
    DELTA_H_CRACK_KJ_KG,
    DELTA_H_CRACKING_J_KG,
    DELTA_H_CRACKING_KJ_KG,
    DELTA_H_THERMAL_CRACKING_J_KG,
    DELTA_H_THERMAL_CRACKING_KJ_KG,
    DelayedCokerConfig,
    DelayedCokerDiagCode,
    DelayedCokerDiagnosticCode,
    DelayedCokerDrumConfig,
    DelayedCokerDrumDiagnosticCode,
    DelayedCokerDrumEngine,
    DelayedCokerDrumModel,
    DelayedCokerDrumParameters,
    DelayedCokerDrumSimulator,
    DelayedCokerDrumState,
    DelayedCokerDrumStatusBits,
    DelayedCokerDrumStatusWord,
    DelayedCokerEngine,
    DelayedCokerLogicUnit,
    DelayedCokerModel,
    DelayedCokerParameters,
    DelayedCokerPlantModel,
    DelayedCokerSimulationEngine,
    DelayedCokerSimulator,
    DelayedCokerState,
    DelayedCokerStatusBits,
    DelayedCokerStatusWord,
    DelayedCokingDiagnosticCode,
    DelayedCokingEngine,
    DelayedCokingState,
    DelayedCokingStatusBits,
    DelayedCokingThermalCrackingConfig,
    DelayedCokingThermalCrackingDiagnosticCode,
    DelayedCokingThermalCrackingSimulator,
    DelayedCokingThermalCrackingState,
    DelayedCokingThermalCrackingStatusBits,
    MW_C,
    MW_CARBON,
    MW_COKE,
    MW_COKER_GAS,
    MW_COKER_GASOIL,
    MW_COKER_NAPHTHA,
    MW_FEED,
    MW_GAS,
    MW_GASOIL,
    MW_HCGO,
    MW_LCGO,
    MW_LIGHT_GAS,
    MW_NAPHTHA,
    MW_OFFGAS,
    MW_OIL,
    MW_RESIDUE,
    MW_STEAM,
    MW_VR,
    MW_WET_GAS,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    run_coker_verification,
    run_delayed_coker_drum_verification,
    run_delayed_coker_verification,
    run_delayed_coking_thermal_cracking_verification,
    verify_delayed_coker_drum_pure_st,
    verify_delayed_coker_pure_st,
    verify_delayed_coking_thermal_cracking_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1280..%R1287, %M298..%M300)."""

    def test_verify_delayed_coker_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_delayed_coker_pure_st() is True
        assert verify_delayed_coking_thermal_cracking_pure_st() is True
        assert verify_delayed_coker_drum_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1280..%R1287, %M298..%M300)."""
        SecurityGuard.assert_pure_st_content(DELAYED_COKER_DRUM_PURE_ST_POU)
        val = STParser.validate_code(DELAYED_COKER_DRUM_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(DELAYED_COKER_DRUM_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "DelayedCokerDrumSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1280", "%R1281", "%R1282", "%R1283",
            "%R1284", "%R1285", "%R1286", "%R1287",
            "%M298", "%M299", "%M300",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from DelayedCokerDrumSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate DelayedCokingThermalCrackingSync alias POU AST."""
        ast_alias = STParser.parse_pou(DELAYED_COKING_THERMAL_CRACKING_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "DelayedCokingThermalCrackingSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1280", "%R1281", "%R1282", "%R1283",
            "%R1284", "%R1285", "%R1286", "%R1287",
            "%M298", "%M299", "%M300",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers, (
                f"Register {reg} missing from DelayedCokingThermalCrackingSync AST bindings"
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
            "XIC DelayedCokerPermissive",
            "XIO CokerThermalTrip",
            "OTE FoamoverAlarm",
            "OTL CokerThermalTrip",
            "OTU DelayedCokerPermissive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Enforce pure ST by aggressively rejecting ladder constructs."""
        bad_code = f"""
        PROGRAM BadCokerLadder
        VAR
            Permissive AT %M298 : BOOL;
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
# 3. Section 3: Delayed Coking Drum Hydrodynamics & Foam Swell Mechanics
# ============================================================================

class TestSection3DelayedCokingDrumHydrodynamics:
    """Tests for delayed coking drum hydrodynamics, vapor velocity, level swell, foam height, bed growth (~0.85 m/h)."""

    def test_hydrodynamics_nominal_conditions(self) -> None:
        """Requirement 3: Verify superficial vapor velocity, swell factor, foam height, and bed growth rate."""
        sim = DelayedCokerSimulator()
        hydro = sim.compute_hydrodynamics(
            p_bar=2.8,
            temp_k=435.0 + T_ZERO_CELSIUS,
            feed_flow_kg_s=50.0,
            recycle_ratio=1.1,
            h_bed_m=18.5,
        )

        assert 0.08 <= hydro["u_vapor_m_s"] <= 0.40
        assert 1.10 <= hydro["swell_factor"] <= 2.20
        assert 20.0 <= hydro["foam_layer_height_m"] <= 26.0
        assert hydro["foam_level_pct"] < 90.0
        assert 0.70 <= hydro["bed_growth_rate_m_h"] <= 1.05

    def test_coke_bed_growth_rate_scaling(self) -> None:
        """Requirement 3: Verify coke bed growth rate scales linearly with feed rate."""
        sim = DelayedCokerSimulator()
        hydro_base = sim.compute_hydrodynamics(
            p_bar=2.8,
            temp_k=435.0 + T_ZERO_CELSIUS,
            feed_flow_kg_s=50.0,
            recycle_ratio=1.1,
            h_bed_m=18.5,
        )
        hydro_double = sim.compute_hydrodynamics(
            p_bar=2.8,
            temp_k=435.0 + T_ZERO_CELSIUS,
            feed_flow_kg_s=100.0,
            recycle_ratio=1.1,
            h_bed_m=18.5,
        )

        assert hydro_double["bed_growth_rate_m_h"] == pytest.approx(
            hydro_base["bed_growth_rate_m_h"] * 2.0, rel=1e-3
        )


# ============================================================================
# 4. Section 4: High-Temperature Residue Thermal Cracking Kinetics & Thermodynamics
# ============================================================================

class TestSection4DelayedCokingReactionKinetics:
    """Tests for residue thermal cracking kinetics, reaction enthalpy (+210 kJ/kg feed), Arrhenius monotonicity."""

    def test_reaction_enthalpy_values(self) -> None:
        """Requirement 4: Verify specified reaction enthalpy (+210 kJ/kg feed)."""
        assert DELTA_H_COKE_J_KG == 210000.0
        assert DELTA_H_COKE_KJ_KG == 210.0
        assert DELTA_H_CRACK_J_KG == 210000.0
        assert DELTA_H_CRACK_KJ_KG == 210.0
        assert DELTA_H_CRACKING_J_KG == 210000.0
        assert DELTA_H_CRACKING_KJ_KG == 210.0
        assert DELTA_H_THERMAL_CRACKING_J_KG == 210000.0
        assert DELTA_H_THERMAL_CRACKING_KJ_KG == 210.0

    def test_arrhenius_monotonicity(self) -> None:
        """Requirement 4: Verify Arrhenius cracking rate constants increase monotonically with temperature."""
        sim = DelayedCokerSimulator()
        rx_480 = sim.compute_reaction_rates(480.0 + T_ZERO_CELSIUS, 0.0, 0.52, 0.13, 0.065)
        rx_495 = sim.compute_reaction_rates(495.0 + T_ZERO_CELSIUS, 0.0, 0.52, 0.13, 0.065)
        rx_510 = sim.compute_reaction_rates(510.0 + T_ZERO_CELSIUS, 0.0, 0.52, 0.13, 0.065)

        assert rx_480["k_crack"] < rx_495["k_crack"] < rx_510["k_crack"]
        assert rx_480["k_cgo"] < rx_495["k_cgo"] < rx_510["k_cgo"]
        assert rx_480["k_naphtha"] < rx_495["k_naphtha"] < rx_510["k_naphtha"]
        assert rx_480["k_gas"] < rx_495["k_gas"] < rx_510["k_gas"]

    def test_endothermic_temperature_drop(self) -> None:
        """Requirement 4: Verify net endothermic heat absorption and axial temperature drop (495 C inlet -> ~435 C exit)."""
        sim = DelayedCokerSimulator()
        derivs = sim.compute_derivatives(
            0.0,
            [sim.state.t_drum_vapor_c, sim.state.y_residue, sim.state.y_coker_gasoil,
             sim.state.y_coker_naphtha, sim.state.y_coker_gas, sim.state.h_coke_bed_m],
        )
        assert len(derivs) == 6
        assert 9500.0 <= sim.state.endothermic_reaction_heat_kw <= 11500.0
        assert 55.0 <= sim.state.axial_temperature_drop_c <= 65.0


# ============================================================================
# 5. Section 5: Coupled ODE RK4 Integration & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual stoichiometric conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states(self) -> None:
        """Requirement 5: Verify RK4 integration steps remain stable and bounded within physical limits."""
        sim = DelayedCokerSimulator()
        for _ in range(100):
            res = sim.step(dt=0.05)
            assert res.status == AgentStatus.SUCCESS

        assert 425.0 <= sim.state.t_drum_vapor_c <= 445.0
        assert 0.00 <= sim.state.y_residue <= 0.05
        assert 0.45 <= sim.state.y_coker_gasoil <= 0.58
        assert 0.10 <= sim.state.y_coker_naphtha <= 0.18
        assert 0.04 <= sim.state.y_coker_gas <= 0.10
        assert 25.0 <= sim.state.coke_yield_pct <= 32.0
        assert 18.0 <= sim.state.h_coke_bed_m <= 19.0
        assert not math.isnan(sim.state.t_drum_vapor_c)
        assert not math.isnan(sim.state.y_coker_gasoil)
        assert not math.isnan(sim.state.h_coke_bed_m)

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 5: Verify dual elemental mass and thermal enthalpy residuals < 1e-10."""
        sim = DelayedCokerSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_derivative_computations_finite(self) -> None:
        """Requirement 5: Verify compute_derivatives produces 6 finite derivatives."""
        sim = DelayedCokerSimulator()
        derivs = sim.compute_derivatives(
            0.0,
            [sim.state.t_drum_vapor_c, sim.state.y_residue, sim.state.y_coker_gasoil,
             sim.state.y_coker_naphtha, sim.state.y_coker_gas, sim.state.h_coke_bed_m],
        )
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)


# ============================================================================
# 6. Section 6: Process Safety Trips & Priority Hierarchy
# ============================================================================

class TestSection6ProcessSafetyInterlocksAndTrips:
    """Tests for safety trips (0xC001..0xC004), priority hierarchy, and Horner coil assertions (%M298..%M300)."""

    def test_trip_0xc001_drum_overtemp(self) -> None:
        """Requirement 6: Verify 0xC001 trip on vapor outlet temp > 460 C -> asserts %M299, clears %M298."""
        reg = RegisterTable()
        sim = DelayedCokerSimulator(register_table=reg)

        sim.state.t_drum_vapor_c = 465.0  # > 460 C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1287") & 0xFFFF == 0xC001
        assert reg.read_bit("%M299") is True
        assert reg.read_bit("%M298") is False

    def test_fault_0xc002_drum_foamover_surge(self) -> None:
        """Requirement 6: Verify 0xC002 on foam layer height > 90% drum level -> asserts %M300."""
        reg = RegisterTable()
        sim = DelayedCokerSimulator(register_table=reg)

        sim.state.t_drum_vapor_c = 435.0
        sim.state.foam_level_pct = 92.5  # > 90%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1287") & 0xFFFF == 0xC002
        assert reg.read_bit("%M300") is True
        assert reg.read_bit("%M298") is True
        assert reg.read_bit("%M299") is False

    def test_trip_0xc003_furnace_transfer_pressure_high(self) -> None:
        """Requirement 6: Verify 0xC003 on transfer pressure > 4.5 bar -> asserts %M299, clears %M298."""
        reg = RegisterTable()
        sim = DelayedCokerSimulator(register_table=reg)

        sim.state.t_drum_vapor_c = 435.0
        sim.state.foam_level_pct = 73.3
        sim.state.transfer_line_pressure_bar = 4.8  # > 4.5 bar
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1287") & 0xFFFF == 0xC003
        assert reg.read_bit("%M299") is True
        assert reg.read_bit("%M298") is False

    def test_fault_0xc004_bed_level_collapse(self) -> None:
        """Requirement 6: Verify 0xC004 on abnormal coke level sensor anomaly."""
        reg = RegisterTable()
        sim = DelayedCokerSimulator(register_table=reg)

        sim.state.t_drum_vapor_c = 435.0
        sim.state.foam_level_pct = 73.3
        sim.state.transfer_line_pressure_bar = 3.8
        sim.state.h_coke_bed_m = -1.0  # abnormal negative level
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1287") & 0xFFFF == 0xC004
        assert reg.read_bit("%M298") is True
        assert reg.read_bit("%M299") is False

    def test_priority_hierarchy(self) -> None:
        """Requirement 6: Verify 0xC001 (drum overtemp) dominates all other faults."""
        reg = RegisterTable()
        sim = DelayedCokerSimulator(register_table=reg)

        sim.state.t_drum_vapor_c = 470.0  # 0xC001
        sim.state.foam_level_pct = 95.0   # 0xC002
        sim.state.transfer_line_pressure_bar = 5.0 # 0xC003
        sim.state.h_coke_bed_m = -2.0     # 0xC004
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1287") & 0xFFFF == 0xC001
        assert reg.read_bit("%M299") is True
        assert reg.read_bit("%M298") is False
        assert reg.read_bit("%M300") is True


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration
# ============================================================================

class TestSection7HornerOCSMemorySpaceIntegration:
    """Tests for Horner OCS memory space bindings (%R1280..%R1287, %M298..%M300) with PrivilegeMode.SYSTEM."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 7: Verify analog register values and discrete coil states with PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = DelayedCokerSimulator(register_table=reg)

        sim.state.t_drum_inlet_c = 495.0
        sim.state.t_drum_vapor_c = 435.0
        sim.state.drum_pressure_bar = 2.8
        sim.state.recycle_ratio = 1.1
        sim.state.y_coker_gasoil = 0.520
        sim.state.coke_yield_pct = 28.5
        sim.state.h_coke_bed_m = 18.5
        sim.state.transfer_line_pressure_bar = 3.8
        sim.state.foam_level_pct = 73.3

        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1280") == 4950
        assert reg.read_word("%R1281") == 4350
        assert reg.read_word("%R1282") == 28
        assert reg.read_word("%R1283") == 11
        assert reg.read_word("%R1284") == 520
        assert reg.read_word("%R1285") == 285
        assert reg.read_word("%R1286") == 185
        assert reg.read_word("%R1287") & 0xFFFF == 0x0000
        assert reg.read_bit("%M298") is True
        assert reg.read_bit("%M299") is False
        assert reg.read_bit("%M300") is False

    def test_system_privilege_enforced_for_internal_writes(self) -> None:
        """Requirement 7: Ensure writes use PrivilegeMode.SYSTEM without throwing privilege errors."""
        reg = RegisterTable()
        sim = DelayedCokerSimulator(register_table=reg)
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1280") == 4950


# ============================================================================
# 8. Section 8: ILogicUnit Compliance & Dynamic Disturbance Response
# ============================================================================

class TestSection8ILogicUnitAndDisturbanceResponse:
    """Tests for ILogicUnit interface, scan_step, transient disturbance response, and settling stability."""

    def test_ilogicunit_interface_and_scan_step(self) -> None:
        """Requirement 8: Verify ILogicUnit protocol compliance and scan_step return dictionary."""
        sim = DelayedCokerSimulator()
        assert sim.name == "DelayedCokerDrumSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

        res = sim.scan_step(dt_s=0.05)
        assert "status" in res
        assert "t_drum_vapor_c" in res
        assert "y_coker_gasoil" in res
        assert "delayed_coker_permissive" in res
        assert res["delayed_coker_permissive"] is True

    def test_delayed_coker_logic_unit_adapter(self) -> None:
        """Requirement 8: Verify DelayedCokerLogicUnit adapter couples correctly into ScanContext."""
        reg = RegisterTable()
        sim = DelayedCokerSimulator(register_table=reg)
        unit = DelayedCokerLogicUnit(simulator=sim)
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
        assert reg.read_word("%R1280") == 4950
        assert reg.read_word("%R1281") == 4350
        assert reg.read_bit("%M298") is True

        unit.reset()
        assert unit.simulator.state.time_s == 0.0

    def test_inlet_temp_disturbance_settling(self) -> None:
        """Requirement 8: Verify closed-loop settling response to +3 °C inlet temperature disturbance."""
        sim = DelayedCokerSimulator()
        sim.state.t_drum_inlet_c = 498.0  # +3 C inlet disturbance
        res = sim.advance_time(duration_s=8.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 433.0 <= sim.state.t_drum_vapor_c <= 442.0
        assert sim.state.delayed_coker_permissive is True
        assert not math.isnan(sim.state.t_drum_vapor_c)


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_delayed_coker_verification execution and 4-state contract validation."""

    def test_run_delayed_coker_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 9: Execute verification suite, write evidence JSON, assert success contract."""
        out_file = tmp_path / "delayed_coker_evidence.json"
        evidence = run_delayed_coker_verification(str(out_file))

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["data"]["work_package"] == "W167"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_suite_aliases(self) -> None:
        """Requirement 9: Verify alias functions execute cleanly."""
        res1 = run_delayed_coker_drum_verification()
        assert res1["status"] == "success"
        assert res1["data"]["checks_passed"] == 9

        res2 = run_delayed_coking_thermal_cracking_verification()
        assert res2["status"] == "success"
        assert res2["data"]["checks_passed"] == 9

        res3 = run_coker_verification()
        assert res3["status"] == "success"
        assert res3["data"]["checks_passed"] == 9
