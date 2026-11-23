"""Unit and Integration Tests for Industrial Continuous Catalytic Reforming (CCR) Multi-Bed Simulation.

Work Package: W161 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1220..%R1227, %M284..%M286).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: CCR multi-bed aromatization kinetics, dehydrocyclization, dehydrogenation, and hydrocracking thermodynamics.
4. Section 4: 3-stage radial-flow moving-bed hydrodynamics, inter-stage furnace reheaters, and thermal endotherm profiles.
5. Section 5: Coupled 6-state ODE RK4 integration stability and dual stoichiometric conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xBA01, 0xBA02, 0xBA03, 0xBA04), priority hierarchy, and Horner coil assertions (%M284, %M285, %M286).
7. Section 7: Horner OCS register space synchronization (%R1220..%R1227, %M284..%M286).
8. Section 8: Dynamic disturbance response and closed-loop settling stability.
9. Section 9: 9-stage verification suite integration test writing evidence JSON.
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
from jev_cscape.simulation.ccr_reformer import (
    CCR_DYNAMICS_SYNC_POU,
    CCR_PURE_ST_POU,
    CCR_REFORMER_DYNAMICS_SYNC_POU,
    CCR_REFORMER_PURE_ST_POU,
    CCR_REFORMER_SYNC_POU,
    CCR_SYNC_POU,
    CONTINUOUS_CATALYTIC_REFORMER_PURE_ST_POU,
    CONTINUOUS_CATALYTIC_REFORMER_SYNC_POU,
    CONTINUOUS_CATALYTIC_REFORMING_PURE_ST_POU,
    CONTINUOUS_CATALYTIC_REFORMING_SYNC_POU,
    CcrConfig,
    CcrDiagCode,
    CcrDiagnosticCode,
    CcrEngine,
    CcrModel,
    CcrParameters,
    CcrPlantModel,
    CcrReformerConfig,
    CcrReformerDiagnosticCode,
    CcrReformerEngine,
    CcrReformerModel,
    CcrReformerParameters,
    CcrReformerPlantModel,
    CcrReformerSimulationEngine,
    CcrReformerSimulator,
    CcrReformerState,
    CcrReformerStatusBits,
    CcrReformerStatusWord,
    CcrSimulator,
    CcrState,
    CcrStatusBits,
    CcrStatusWord,
    ContinuousCatalyticReformerConfig,
    ContinuousCatalyticReformerDiagnosticCode,
    ContinuousCatalyticReformerEngine,
    ContinuousCatalyticReformerModel,
    ContinuousCatalyticReformerPlantModel,
    ContinuousCatalyticReformerSimulationEngine,
    ContinuousCatalyticReformerSimulator,
    ContinuousCatalyticReformerState,
    ContinuousCatalyticReformerStatusBits,
    ContinuousCatalyticReformingConfig,
    ContinuousCatalyticReformingDiagnosticCode,
    ContinuousCatalyticReformingSimulator,
    ContinuousCatalyticReformingState,
    ContinuousCatalyticReformingStatusBits,
    DELTA_H_DEHYDROCYCLIZATION_J_MOL,
    DELTA_H_DEHYDROGENATION_J_MOL,
    DELTA_H_HYDROCRACKING_J_MOL,
    MW_AROMATIC,
    MW_C,
    MW_H,
    MW_H2,
    MW_NAPHTHA,
    MW_NAPHTHENE,
    MW_PARAFFIN,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    run_ccr_reformer_verification,
    run_ccr_verification,
    run_continuous_catalytic_reformer_verification,
    run_continuous_catalytic_reforming_verification,
    verify_ccr_pure_st,
    verify_ccr_reformer_pure_st,
    verify_continuous_catalytic_reformer_pure_st,
    verify_continuous_catalytic_reforming_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1220..%R1227, %M284..%M286)."""

    def test_verify_ccr_reformer_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_ccr_reformer_pure_st() is True
        assert verify_ccr_pure_st() is True
        assert verify_continuous_catalytic_reforming_pure_st() is True
        assert verify_continuous_catalytic_reformer_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1220..%R1227, %M284..%M286)."""
        SecurityGuard.assert_pure_st_content(CCR_REFORMER_PURE_ST_POU)
        val = STParser.validate_code(CCR_REFORMER_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CCR_REFORMER_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "CcrReformerSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1220", "%R1221", "%R1222", "%R1223",
            "%R1224", "%R1225", "%R1226", "%R1227",
            "%M284", "%M285", "%M286",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from CcrReformerSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate ContinuousCatalyticReformingSync alias POU AST."""
        ast_alias = STParser.parse_pou(CONTINUOUS_CATALYTIC_REFORMING_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "ContinuousCatalyticReformingSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1220", "%R1221", "%R1222", "%R1223",
            "%R1224", "%R1225", "%R1226", "%R1227",
            "%M284", "%M285", "%M286",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers, f"Register {reg} missing from ContinuousCatalyticReformingSync AST bindings"


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
            "XIC CcrReformerPermissive",
            "XIO FurnaceOvertempTrip",
            "OTE CatalystRegenActive",
            "OTL FurnaceOvertempTrip",
            "OTU CcrReformerPermissive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Enforce pure ST by aggressively rejecting ladder constructs."""
        bad_code = f"""
        PROGRAM BadCcrLadder
        VAR
            Permissive AT %M284 : BOOL;
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
# 3. Section 3: CCR Multi-Bed Kinetics & Thermodynamics
# ============================================================================

class TestSection3AromatizationKineticsAndEndotherms:
    """Tests for CCR aromatization kinetics, dehydrogenation, and dehydrocyclization endotherms."""

    def test_reaction_enthalpies_values(self) -> None:
        """Requirement 3: Verify exact specified reaction enthalpies."""
        assert DELTA_H_DEHYDROCYCLIZATION_J_MOL == 220000.0  # +220 kJ/mol endothermic
        assert DELTA_H_DEHYDROGENATION_J_MOL == 210000.0     # +210 kJ/mol endothermic
        assert DELTA_H_HYDROCRACKING_J_MOL == -50000.0       # -50 kJ/mol exothermic

    def test_arrhenius_monotonicity(self) -> None:
        """Requirement 3: Verify Arrhenius rate constants increase monotonically with temperature."""
        sim = CcrReformerSimulator()
        rx_490 = sim.compute_reaction_rates(490.0 + T_ZERO_CELSIUS, 5.0, 0.22, 0.03, 0.72)
        rx_510 = sim.compute_reaction_rates(510.0 + T_ZERO_CELSIUS, 5.0, 0.22, 0.03, 0.72)
        rx_530 = sim.compute_reaction_rates(530.0 + T_ZERO_CELSIUS, 5.0, 0.22, 0.03, 0.72)

        assert rx_490["k_dhc"] < rx_510["k_dhc"] < rx_530["k_dhc"]
        assert rx_490["k_dhn"] < rx_510["k_dhn"] < rx_530["k_dhn"]
        assert rx_490["k_hck"] < rx_510["k_hck"] < rx_530["k_hck"]

    def test_endothermic_heat_absorption(self) -> None:
        """Requirement 3: Verify net endothermic heat absorption at nominal reforming conditions."""
        sim = CcrReformerSimulator()
        rx = sim.compute_reaction_rates(510.0 + T_ZERO_CELSIUS, 5.0, 0.22, 0.03, 0.72)
        assert rx["q_dhc_kw"] > 0.0
        assert rx["q_dhn_kw"] > 0.0
        assert rx["q_hck_kw"] > 0.0
        assert rx["q_net_endotherm_kw"] > 1000.0


# ============================================================================
# 4. Section 4: Radial Flow Hydrodynamics & Furnace Reheaters
# ============================================================================

class TestSection4RadialFlowHydrodynamicsAndFurnaces:
    """Tests for 3-stage radial-flow moving-bed hydrodynamics, pressure drops, and furnace reheaters."""

    def test_radial_bed_pressure_drops(self) -> None:
        """Requirement 4: Verify radial Ergun pressure drop across each bed and catalyst moving bed velocity."""
        sim = CcrReformerSimulator()
        hydro = sim.compute_hydrodynamics(
            p_bar=5.0,
            temp1_k=465.0 + T_ZERO_CELSIUS,
            temp2_k=480.0 + T_ZERO_CELSIUS,
            temp3_k=485.0 + T_ZERO_CELSIUS,
        )
        assert 0.02 <= hydro["bed1_dp_bar"] <= 0.80
        assert 0.02 <= hydro["bed2_dp_bar"] <= 0.80
        assert 0.02 <= hydro["bed3_dp_bar"] <= 0.80
        assert 0.10 <= hydro["total_dp_bar"] <= 2.20
        assert 0.20 <= hydro["catalyst_bed_velocity_m_h"] <= 2.50

    def test_multi_bed_temperature_drops(self) -> None:
        """Requirement 4: Verify monotonic temperature drop profile: Bed 1 > Bed 2 > Bed 3."""
        sim = CcrReformerSimulator()
        sim.compute_derivatives(
            0.0,
            [sim.state.t_bed1_c, sim.state.t_bed2_c, sim.state.t_bed3_c,
             sim.state.y_paraffins, sim.state.y_naphthenes, sim.state.y_aromatics],
        )
        dt1 = sim.state.delta_t_bed1_c
        dt2 = sim.state.delta_t_bed2_c
        dt3 = sim.state.delta_t_bed3_c

        assert dt1 > dt2 > dt3 > 0.0
        assert 35.0 <= dt1 <= 60.0
        assert 15.0 <= dt3 <= 35.0

    def test_furnace_reheater_heat_duties(self) -> None:
        """Requirement 4: Verify furnace reheaters deliver necessary sensible heat input."""
        sim = CcrReformerSimulator()
        sim.compute_derivatives(
            0.0,
            [sim.state.t_bed1_c, sim.state.t_bed2_c, sim.state.t_bed3_c,
             sim.state.y_paraffins, sim.state.y_naphthenes, sim.state.y_aromatics],
        )
        assert sim.state.furnace1_heat_duty_kw > 1000.0
        assert sim.state.furnace2_heat_duty_kw > 1000.0
        assert sim.state.furnace3_heat_duty_kw > 1000.0
        assert sim.state.total_furnace_duty_kw > 5000.0

    def test_catalyst_circulation_dynamics(self) -> None:
        """Requirement 4: Verify catalyst circulation dynamics and deactivation by coke."""
        sim = CcrReformerSimulator()
        coke_low, act_low = sim.compute_catalyst_activity(600.0)
        coke_nom, act_nom = sim.compute_catalyst_activity(1200.0)
        coke_high, act_high = sim.compute_catalyst_activity(2400.0)

        assert coke_low > coke_nom > coke_high
        assert act_high > act_nom > act_low
        assert 0.80 <= act_nom <= 1.0


# ============================================================================
# 5. Section 5: Coupled 6-State ODE RK4 Integration & Conservation
# ============================================================================

class TestSection5CoupledODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual stoichiometric conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states(self) -> None:
        """Requirement 5: Verify RK4 integration steps remain stable and bounded."""
        sim = CcrReformerSimulator()
        for _ in range(100):
            res = sim.step(dt=0.05)
            assert res.status == AgentStatus.SUCCESS

        assert 440.0 <= sim.state.t_bed1_c <= 500.0
        assert 450.0 <= sim.state.t_bed2_c <= 510.0
        assert 460.0 <= sim.state.t_bed3_c <= 510.0
        assert 0.10 <= sim.state.y_paraffins <= 0.40
        assert 0.005 <= sim.state.y_naphthenes <= 0.10
        assert 0.60 <= sim.state.y_aromatics <= 0.85
        assert 98.0 <= sim.state.research_octane_number_ron <= 106.0
        assert not math.isnan(sim.state.t_bed1_c)
        assert not math.isnan(sim.state.research_octane_number_ron)

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 5: Verify dual stoichiometric mass and enthalpy residuals < 1e-10."""
        sim = CcrReformerSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# 6. Section 6: Process Safety Trips & Priority Hierarchy
# ============================================================================

class TestSection6ProcessSafetyInterlocksAndTrips:
    """Tests for safety trips (0xBA01..0xBA04), priority hierarchy, and Horner coil assertions (%M284..%M286)."""

    def test_trip_0xba01_furnace_overtemp(self) -> None:
        """Requirement 6: Verify 0xBA01 trip on furnace temp > 550 C."""
        reg = RegisterTable()
        sim = CcrReformerSimulator(register_table=reg)

        sim.state.t_furnace1_c = 554.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1227") & 0xFFFF == 0xBA01
        assert reg.read_bit("%M285") is True
        assert reg.read_bit("%M284") is False

    def test_fault_0xba02_catalyst_circulation_pinch(self) -> None:
        """Requirement 6: Verify 0xBA02 on catalyst circulation rate < 800 kg/h."""
        reg = RegisterTable()
        sim = CcrReformerSimulator(register_table=reg)

        sim.state.catalyst_circulation_rate_kg_h = 750.0  # < 800 kg/h
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1227") & 0xFFFF == 0xBA02
        assert reg.read_bit("%M284") is True

    def test_trip_0xba03_high_hydrocracking_exotherm(self) -> None:
        """Requirement 6: Verify 0xBA03 on hydrocracking runaway dT/dt > 4.0 C/min."""
        reg = RegisterTable()
        sim = CcrReformerSimulator(register_table=reg)

        sim.state.dt_bed3_dt_c_min = 4.8  # > 4.0 C/min
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1227") & 0xFFFF == 0xBA03
        assert reg.read_bit("%M285") is True

    def test_alarm_0xba04_octane_barrel_collapse(self) -> None:
        """Requirement 6: Verify 0xBA04 on research octane number < 95.0 RON."""
        reg = RegisterTable()
        sim = CcrReformerSimulator(register_table=reg)

        sim.state.research_octane_number_ron = 92.5  # < 95.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1227") & 0xFFFF == 0xBA04
        assert reg.read_bit("%M284") is True

    def test_priority_hierarchy(self) -> None:
        """Requirement 6: Verify 0xBA01 furnace overtemp dominates all other trips."""
        reg = RegisterTable()
        sim = CcrReformerSimulator(register_table=reg)

        sim.state.t_furnace1_c = 555.0
        sim.state.catalyst_circulation_rate_kg_h = 600.0
        sim.state.dt_bed3_dt_c_min = 6.0
        sim.state.research_octane_number_ron = 88.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1227") & 0xFFFF == 0xBA01
        assert reg.read_bit("%M285") is True
        assert reg.read_bit("%M284") is False


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration
# ============================================================================

class TestSection7HornerOCSMemorySpaceIntegration:
    """Tests for Horner OCS memory space bindings (%R1220..%R1227, %M284..%M286)."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 7: Verify analog register values and discrete coil states."""
        reg = RegisterTable()
        sim = CcrReformerSimulator(register_table=reg)

        sim.state.t_bed1_inlet_c = 510.0
        sim.state.t_bed3_c = 485.0
        sim.state.operating_pressure_bar = 5.0
        sim.state.h2_hc_molar_ratio = 3.0
        sim.state.y_aromatics = 0.720
        sim.state.research_octane_number_ron = 102.0
        sim.state.catalyst_circulation_rate_kg_h = 1200.0
        sim.state.t_furnace1_c = 510.0
        sim.state.t_furnace2_c = 510.0
        sim.state.t_furnace3_c = 510.0
        sim.state.dt_bed1_dt_c_min = 0.0
        sim.state.dt_bed2_dt_c_min = 0.0
        sim.state.dt_bed3_dt_c_min = 0.0

        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1220") == 5100
        assert reg.read_word("%R1221") == 4850
        assert reg.read_word("%R1222") == 50
        assert reg.read_word("%R1223") == 30
        assert reg.read_word("%R1224") == 720
        assert reg.read_word("%R1225") == 1020
        assert reg.read_word("%R1226") == 1200
        assert reg.read_word("%R1227") & 0xFFFF == 0x0000
        assert reg.read_bit("%M284") is True
        assert reg.read_bit("%M285") is False
        assert reg.read_bit("%M286") is True


# ============================================================================
# 8. Section 8: Dynamic Disturbance Response
# ============================================================================

class TestSection8DynamicDisturbanceResponse:
    """Tests for transient response to process disturbances and settling stability."""

    def test_furnace_temp_disturbance_settling(self) -> None:
        """Requirement 8: Verify closed-loop settling response to furnace temperature step disturbance."""
        sim = CcrReformerSimulator()
        sim.state.t_furnace1_c = 513.0  # +3 C disturbance
        res = sim.advance_time(duration_s=10.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 450.0 <= sim.state.t_bed1_c <= 510.0
        assert 470.0 <= sim.state.t_bed3_c <= 510.0
        assert sim.state.ccr_reformer_permissive is True
        assert not math.isnan(sim.state.t_bed1_c)


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_ccr_reformer_verification execution and 4-state contract validation."""

    def test_run_ccr_reformer_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 9: Execute verification suite, write evidence JSON, assert success contract."""
        out_file = tmp_path / "ccr_evidence.json"
        evidence = run_ccr_reformer_verification(str(out_file))

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["data"]["work_package"] == "W161"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"

    def test_verification_suite_aliases(self) -> None:
        """Requirement 9: Verify alias functions execute cleanly."""
        res = run_ccr_verification()
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9

        res2 = run_continuous_catalytic_reformer_verification()
        assert res2["status"] == "success"
        assert res2["data"]["checks_passed"] == 9

        res3 = run_continuous_catalytic_reforming_verification()
        assert res3["status"] == "success"
        assert res3["data"]["checks_passed"] == 9
