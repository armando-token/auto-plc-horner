"""Unit and Integration Tests for Industrial Alkylation Acid Reaction & Settler ODE Simulation.

Work Package: W173 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1340..%R1347, %M312..%M314).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Alkylation kinetics, I/O ratio impact on alkylate RON, and exothermic heat generation (-85 kJ/mol).
4. Section 4: Acid dilution kinetics, fresh make-up acid balance, and ASO polymer accumulation.
5. Section 5: Gravity acid settler Stokes settling dynamics, interface level tracking, and carryover surveillance.
6. Section 6: Coupled 6-state ODE RK4 integration stability and dual elemental mass and thermal enthalpy conservation residuals (< 1e-10).
7. Section 7: Process safety trips (0xC601, 0xC602, 0xC603, 0xC604) and Horner coil assertion (%M312, %M313, %M314).
8. Section 8: Horner OCS register space synchronization (%R1340..%R1347, %M312..%M314) with PrivilegeMode.SYSTEM.
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
from jev_cscape.simulation.alkylation_acid import (
    DELTA_H_ALKYLATION_J_MOL,
    DELTA_H_ALKYLATION_KJ_MOL,
    DELTA_H_ALK_J_MOL,
    DELTA_H_ALK_KJ_MOL,
    DELTA_H_SECONDARY_J_MOL,
    DELTA_H_SECONDARY_KJ_MOL,
    DELTA_H_SEC_J_MOL,
    DELTA_H_SEC_KJ_MOL,
    G_ACCEL,
    MW_ASO,
    MW_DMH,
    MW_H2SO4,
    MW_HF,
    MW_ISOBUTANE,
    MW_OLEFIN,
    MW_TMP,
    MW_WATER,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    ALKYLATION_ACID_PURE_ST_POU,
    ALKYLATION_ACID_REACTION_PURE_ST_POU,
    ALKYLATION_ACID_SYNC_POU,
    ALKYLATION_PURE_ST_POU,
    ALKYLATION_SYNC_POU,
    SULFURIC_ACID_ALKYLATION_PURE_ST_POU,
    SULFURIC_ACID_ALKYLATION_SYNC_POU,
    AlkylationAcidConfig,
    AlkylationAcidDiagCode,
    AlkylationAcidDiagnosticCode,
    AlkylationAcidEngine,
    AlkylationAcidLogicUnit,
    AlkylationAcidModel,
    AlkylationAcidParameters,
    AlkylationAcidPlantModel,
    AlkylationAcidReactionConfig,
    AlkylationAcidReactionLogicUnit,
    AlkylationAcidReactionSimulator,
    AlkylationAcidReactionState,
    AlkylationAcidSimulationEngine,
    AlkylationAcidSimulator,
    AlkylationAcidState,
    AlkylationAcidStatusBits,
    AlkylationAcidStatusWord,
    AlkylationConfig,
    AlkylationDiagCode,
    AlkylationDiagnosticCode,
    AlkylationEngine,
    AlkylationLogicUnit,
    AlkylationModel,
    AlkylationParameters,
    AlkylationPlantModel,
    AlkylationSimulationEngine,
    AlkylationSimulator,
    AlkylationState,
    AlkylationStatusBits,
    AlkylationStatusWord,
    SulfuricAcidAlkylationConfig,
    SulfuricAcidAlkylationDiagCode,
    SulfuricAcidAlkylationDiagnosticCode,
    SulfuricAcidAlkylationLogicUnit,
    SulfuricAcidAlkylationSimulator,
    SulfuricAcidAlkylationState,
    SulfuricAcidAlkylationStatusBits,
    SulfuricAcidAlkylationStatusWord,
    run_alkylation_acid_reaction_verification,
    run_alkylation_acid_verification,
    run_alkylation_verification,
    run_sulfuric_acid_alkylation_verification,
    validate_pure_st,
    verify_alkylation_acid_pure_st,
    verify_alkylation_acid_reaction_pure_st,
    verify_alkylation_pure_st,
    verify_sulfuric_acid_alkylation_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1340..%R1347, %M312..%M314)."""

    def test_verify_alkylation_acid_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_alkylation_acid_pure_st() is True
        assert verify_alkylation_acid_reaction_pure_st() is True
        assert verify_sulfuric_acid_alkylation_pure_st() is True
        assert verify_alkylation_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1340..%R1347, %M312..%M314)."""
        SecurityGuard.assert_pure_st_content(ALKYLATION_ACID_REACTION_PURE_ST_POU)
        val = STParser.validate_code(ALKYLATION_ACID_REACTION_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ALKYLATION_ACID_REACTION_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "AlkylationAcidReactionSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1340", "%R1341", "%R1342", "%R1343",
            "%R1344", "%R1345", "%R1346", "%R1347",
            "%M312", "%M313", "%M314",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from AlkylationAcidReactionSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate SulfuricAcidAlkylationSync alias POU AST."""
        ast_alias = STParser.parse_pou(SULFURIC_ACID_ALKYLATION_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "SulfuricAcidAlkylationSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1340", "%R1341", "%R1342", "%R1343",
            "%R1344", "%R1345", "%R1346", "%R1347",
            "%M312", "%M313", "%M314",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers, (
                f"Register {reg} missing from SulfuricAcidAlkylationSync AST bindings"
            )

    def test_validate_pure_st_function(self) -> None:
        """Requirement 1: Validate validate_pure_st helper returns success ExecutionResult."""
        res = validate_pure_st()
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None


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
            "XIC AlkylationPermissive",
            "XIO AlkylationThermalTrip",
            "OTE AcidCarryoverAlarm",
            "OTL AlkylationThermalTrip",
            "OTU AlkylationPermissive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Enforce pure ST by aggressively rejecting ladder constructs."""
        bad_code = f"""
        PROGRAM BadAlkylationLadder
        VAR
            Permissive AT %M312 : BOOL;
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
# 3. Section 3: Alkylation Kinetics & Exothermic Heat Generation (-85 kJ/mol)
# ============================================================================

class TestSection3AlkylationKineticsAndExothermicHeat:
    """Tests for alkylation kinetics, I/O ratio impact on alkylate RON, and exothermic heat generation (-85 kJ/mol)."""

    def test_reaction_enthalpy_constants(self) -> None:
        """Requirement 3: Verify exothermic primary alkylation enthalpy (-85 kJ/mol) and secondary oligomerization (-92 kJ/mol)."""
        assert DELTA_H_ALK_J_MOL == -85000.0
        assert DELTA_H_ALK_KJ_MOL == -85.0
        assert DELTA_H_ALKYLATION_J_MOL == -85000.0
        assert DELTA_H_ALKYLATION_KJ_MOL == -85.0

        assert DELTA_H_SEC_J_MOL == -92000.0
        assert DELTA_H_SEC_KJ_MOL == -92.0
        assert DELTA_H_SECONDARY_J_MOL == -92000.0
        assert DELTA_H_SECONDARY_KJ_MOL == -92.0

    def test_arrhenius_kinetics_monotonicity_with_temperature(self) -> None:
        """Requirement 3: Verify Arrhenius rate constants increase monotonically with contactor temperature."""
        sim = AlkylationAcidSimulator()
        rx_2 = sim.compute_reaction_rates(t_contactor_c=2.0, y_iso=0.785, y_olef=0.012, acid_strength_wt=91.5, io_ratio=11.5)
        rx_4 = sim.compute_reaction_rates(t_contactor_c=4.5, y_iso=0.785, y_olef=0.012, acid_strength_wt=91.5, io_ratio=11.5)
        rx_8 = sim.compute_reaction_rates(t_contactor_c=8.0, y_iso=0.785, y_olef=0.012, acid_strength_wt=91.5, io_ratio=11.5)

        assert rx_2["k_alk"] < rx_4["k_alk"] < rx_8["k_alk"]
        assert rx_2["k_sec"] < rx_4["k_sec"] < rx_8["k_sec"]
        assert rx_4["q_alk_kw"] > 0.0
        assert rx_4["q_sec_kw"] > 0.0
        assert rx_4["q_rxn_total_kw"] == pytest.approx(
            rx_4["q_alk_kw"] + rx_4["q_sec_kw"], rel=1e-4
        )

    def test_isobutane_to_olefin_ratio_impact_on_alkylate_ron(self) -> None:
        """Requirement 3: Verify higher I/O ratio suppresses secondary oligomerization and boosts alkylate RON."""
        sim = AlkylationAcidSimulator()
        rx_low_io = sim.compute_reaction_rates(t_contactor_c=4.5, y_iso=0.785, y_olef=0.012, acid_strength_wt=91.5, io_ratio=8.5)
        rx_nom_io = sim.compute_reaction_rates(t_contactor_c=4.5, y_iso=0.785, y_olef=0.012, acid_strength_wt=91.5, io_ratio=11.5)
        rx_high_io = sim.compute_reaction_rates(t_contactor_c=4.5, y_iso=0.785, y_olef=0.012, acid_strength_wt=91.5, io_ratio=14.0)

        # Higher I/O increases TMP selectivity and raises composite RON
        assert rx_low_io["tmp_selectivity"] < rx_nom_io["tmp_selectivity"] <= rx_high_io["tmp_selectivity"]
        assert rx_low_io["alkylate_ron"] < rx_nom_io["alkylate_ron"] <= rx_high_io["alkylate_ron"]
        assert 90.0 <= rx_low_io["alkylate_ron"] <= 100.0
        assert 90.0 <= rx_nom_io["alkylate_ron"] <= 100.0
        assert sim.config.target_alkylate_ron == 96.5

    def test_molecular_weight_constants(self) -> None:
        """Requirement 3: Verify stoichiometric molecular weights for isobutane, olefin, TMP, DMH, ASO, and acids."""
        assert MW_ISOBUTANE == pytest.approx(0.05812, rel=1e-4)
        assert MW_OLEFIN == pytest.approx(0.05611, rel=1e-4)
        assert MW_TMP == pytest.approx(0.11423, rel=1e-4)
        assert MW_DMH == pytest.approx(0.11423, rel=1e-4)
        assert MW_ASO == pytest.approx(0.28000, rel=1e-4)
        assert MW_H2SO4 == pytest.approx(0.09808, rel=1e-4)
        assert MW_HF == pytest.approx(0.02001, rel=1e-4)
        assert MW_WATER == pytest.approx(0.018015, rel=1e-4)


# ============================================================================
# 4. Section 4: Acid Dilution Kinetics & Fresh Make-up Balance
# ============================================================================

class TestSection4AcidDilutionKineticsAndMakeUpBalance:
    """Tests for acid dilution kinetics, fresh make-up acid balance, and ASO polymer accumulation."""

    def test_acid_management_configuration_parameters(self) -> None:
        """Requirement 4: Verify target acid strength (91.5 wt%), fresh acid (98.0 wt%), and spent acid threshold (88.0 wt%)."""
        sim = AlkylationAcidSimulator()
        assert sim.config.target_acid_strength_wt == 91.5
        assert sim.config.fresh_acid_strength_wt == 98.0
        assert sim.config.spent_acid_threshold_wt == 88.0
        assert sim.config.fresh_acid_makeup_rate_kg_h == 15.0
        assert sim.config.aso_sludge_nominal_wt_pct == 4.5
        assert sim.config.acid_holdup_mass_kg == 35000.0

    def test_acid_activity_factor_decay_on_dilution(self) -> None:
        """Requirement 4: Verify acid activity decreases significantly below 88.0 wt% acid strength."""
        sim = AlkylationAcidSimulator()
        rx_target = sim.compute_reaction_rates(4.5, 0.785, 0.012, acid_strength_wt=91.5, io_ratio=11.5)
        rx_dilute = sim.compute_reaction_rates(4.5, 0.785, 0.012, acid_strength_wt=87.5, io_ratio=11.5)

        assert rx_dilute["k_alk"] < rx_target["k_alk"]
        assert rx_dilute["r_alk_mol_s"] < rx_target["r_alk_mol_s"]
        # Dilution shifts reaction towards secondary oligomers and ASO formation
        assert rx_dilute["aso_formation_rate_kg_h"] > 0.0

    def test_aso_polymer_accumulation_rate(self) -> None:
        """Requirement 4: Verify ASO sludge formation rate is positive and scales with secondary reactions."""
        sim = AlkylationAcidSimulator()
        rx = sim.compute_reaction_rates(4.5, 0.785, 0.012, acid_strength_wt=91.5, io_ratio=11.5)
        assert rx["aso_formation_rate_kg_h"] > 0.0
        assert 0.01 <= rx["aso_formation_rate_kg_h"] <= 5.0

    def test_state_convenience_properties_and_status_bits(self) -> None:
        """Requirement 4: Verify AlkylationAcidState convenience getters, setters, and status bits."""
        state = AlkylationAcidState()
        state.temp_c = 5.2
        assert state.temp_c == 5.2
        assert state.t_contactor_celsius == 5.2

        state.t_contactor_c = 6.1
        assert state.t_contactor_c == 6.1
        assert state.t_contactor_celsius == 6.1

        state.io_ratio = 12.3
        assert state.io_ratio == 12.3
        assert state.isobutane_to_olefin_ratio == 12.3

        state.acid_wt_pct = 92.4
        assert state.acid_wt_pct == 92.4
        assert state.acid_strength_wt == 92.4

        state.ron = 97.2
        assert state.ron == 97.2
        assert state.alkylate_octane_ron == 97.2

        state.settler_level_pct = 54.5
        assert state.settler_level_pct == 54.5
        assert state.h_settler_interface_pct == 54.5

        # Check status bits flags
        assert AlkylationAcidStatusBits.RUNNING == 0x0001
        assert AlkylationAcidStatusBits.ALKYLATION_PERMISSIVE == 0x0002
        assert AlkylationAcidStatusBits.ALKYLATION_THERMAL_TRIP == 0x0004
        assert AlkylationAcidStatusBits.ACID_CARRYOVER_ALARM == 0x0008
        assert AlkylationAcidStatusBits.ACID_DILUTION_FAULT == 0x0010
        assert AlkylationAcidStatusBits.LOW_IO_RATIO_FAULT == 0x0020
        assert AlkylationAcidStatusBits.HIGH_OCTANE_MODE == 0x0040
        assert AlkylationAcidStatusBits.EMULSION_STABLE == 0x0080


# ============================================================================
# 5. Section 5: Gravity Acid Settler Stokes Settling Dynamics
# ============================================================================

class TestSection5GravityAcidSettlerStokesSettlingDynamics:
    """Tests for gravity acid settler Stokes settling dynamics, interface level tracking, and carryover surveillance."""

    def test_stokes_droplet_settling_velocity_nominal_conditions(self) -> None:
        """Requirement 5: Verify terminal settling velocity via Stokes Law under nominal physical properties."""
        sim = AlkylationAcidSimulator()
        hydro = sim.compute_settler_hydrodynamics()

        # v_t = (g * delta_rho * d_p^2) / (18 * mu_c)
        expected_delta_rho = sim.config.rho_acid_kg_m3 - sim.config.rho_hc_kg_m3
        assert hydro["delta_rho_kg_m3"] == pytest.approx(expected_delta_rho, rel=1e-3)
        assert hydro["delta_rho_kg_m3"] == pytest.approx(1115.0, abs=1.0)

        # Terminal velocity for 120 um droplet in 0.25 cP hydrocarbon
        # v_t = (9.80665 * 1115.0 * (1.2e-4)^2) / (18 * 2.5e-4) = 0.0350 m/s
        assert 0.020 <= hydro["droplet_settling_velocity_m_s"] <= 0.050
        assert hydro["droplet_settling_velocity_m_s"] == pytest.approx(0.0350, abs=0.005)
        assert hydro["settling_capacity_m3_s"] > 0.10
        assert hydro["a_settler_m2"] > 4.0

    def test_settler_geometry_and_interface_level_parameters(self) -> None:
        """Requirement 5: Verify settler dimensions, nominal interface level (52.0%), and high alarm threshold (75.0%)."""
        sim = AlkylationAcidSimulator()
        assert sim.config.settler_volume_m3 == 65.0
        assert sim.config.settler_diameter_m == 2.8
        assert sim.config.settler_length_m == 10.5
        assert sim.config.nominal_settler_interface_pct == 52.0
        assert sim.config.settler_interface_high_pct == 75.0
        assert sim.state.h_settler_interface_pct == 52.0

    def test_stokes_velocity_scales_with_droplet_diameter_squared(self) -> None:
        """Requirement 5: Verify terminal velocity scales quadratically with droplet diameter."""
        sim = AlkylationAcidSimulator()
        hydro_120 = sim.compute_settler_hydrodynamics(dp_m=1.2e-4)
        hydro_240 = sim.compute_settler_hydrodynamics(dp_m=2.4e-4)

        ratio = hydro_240["droplet_settling_velocity_m_s"] / hydro_120["droplet_settling_velocity_m_s"]
        assert ratio == pytest.approx(4.0, rel=1e-3)


# ============================================================================
# 6. Section 6: Coupled 6-State ODE RK4 Integration & Conservation Residuals
# ============================================================================

class TestSection6CoupledODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual elemental mass and thermal enthalpy conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states_bounded(self) -> None:
        """Requirement 6: Verify RK4 numerical integration remains stable, bounded, and produces no NaNs/Infs."""
        sim = AlkylationAcidSimulator()
        for _ in range(100):
            res = sim.step(dt=0.05)
            assert res.status == AgentStatus.SUCCESS

        assert 3.0 <= sim.state.t_contactor_celsius <= 7.0
        assert 0.70 <= sim.state.y_isobutane <= 0.85
        assert 0.005 <= sim.state.y_olefin <= 0.025
        assert 0.12 <= sim.state.y_alkylate_tmp <= 0.25
        assert 89.0 <= sim.state.acid_strength_wt <= 93.0
        assert 48.0 <= sim.state.h_settler_interface_pct <= 56.0

        assert not math.isnan(sim.state.t_contactor_celsius)
        assert not math.isnan(sim.state.y_isobutane)
        assert not math.isnan(sim.state.y_olefin)
        assert not math.isnan(sim.state.y_alkylate_tmp)
        assert not math.isnan(sim.state.acid_strength_wt)
        assert not math.isnan(sim.state.h_settler_interface_pct)

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 6: Verify dual elemental mass balance and thermal enthalpy residuals < 1e-10."""
        sim = AlkylationAcidSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_derivative_computations_finite(self) -> None:
        """Requirement 6: Verify compute_derivatives produces 6 finite, real derivatives."""
        sim = AlkylationAcidSimulator()
        derivs = sim.compute_derivatives(
            0.0,
            [
                sim.state.t_contactor_celsius,
                sim.state.y_isobutane,
                sim.state.y_olefin,
                sim.state.y_alkylate_tmp,
                sim.state.acid_strength_wt,
                sim.state.h_settler_interface_pct,
            ],
        )
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_invalid_timestep_handling(self) -> None:
        """Requirement 6: Verify non-positive timestep rejection with INVALID_TIMESTEP error code."""
        sim = AlkylationAcidSimulator()
        res1 = sim.advance_time(duration_s=-1.0, dt=0.05)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "INVALID_TIMESTEP"

        res2 = sim.advance_time(duration_s=1.0, dt=-0.05)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "INVALID_TIMESTEP"


# ============================================================================
# 7. Section 7: Process Safety Interlocks & Trips
# ============================================================================

class TestSection7ProcessSafetyInterlocksAndTrips:
    """Tests for safety trips (0xC601, 0xC602, 0xC603, 0xC604) and Horner coil assertions (%M312..%M314)."""

    def test_trip_0xc601_acid_runaway_exotherm(self) -> None:
        """Requirement 7: Verify 0xC601 trip on contactor temp > 12.0 °C -> asserts %M313, clears %M312."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)

        sim.state.t_contactor_celsius = 13.5  # > 12.0 °C trip limit
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1347") & 0xFFFF == 0xC601
        assert reg.read_bit("%M313") is True   # AlkylationThermalTrip active
        assert reg.read_bit("%M312") is False  # AlkylationPermissive tripped

    def test_fault_0xc602_acid_dilution_spent(self) -> None:
        """Requirement 7: Verify 0xC602 fault on acid strength < 88.0 wt%."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)

        sim.state.t_contactor_celsius = 4.5
        sim.state.acid_strength_wt = 86.5  # < 88.0 wt% spent acid threshold
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1347") & 0xFFFF == 0xC602
        assert sim.state.acid_dilution_fault is True
        assert reg.read_bit("%M312") is True
        assert reg.read_bit("%M313") is False

    def test_fault_0xc603_acid_settler_carryover(self) -> None:
        """Requirement 7: Verify 0xC603 on interface level > 75.0% or carryover detected -> asserts %M314."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)

        # Case A: Interface level surge > 75.0%
        sim.state.t_contactor_celsius = 4.5
        sim.state.acid_strength_wt = 91.5
        sim.state.h_settler_interface_pct = 78.5  # > 75.0%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1347") & 0xFFFF == 0xC603
        assert reg.read_bit("%M314") is True   # AcidCarryoverAlarm active
        assert reg.read_bit("%M312") is True
        assert reg.read_bit("%M313") is False

        # Case B: Entrainment carryover detector flag
        sim.state.h_settler_interface_pct = 52.0
        sim.state.acid_carryover_detected = True
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1347") & 0xFFFF == 0xC603
        assert reg.read_bit("%M314") is True

    def test_fault_0xc604_low_isobutane_olefin_ratio(self) -> None:
        """Requirement 7: Verify 0xC604 on I/O ratio < 8.0."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)

        sim.state.t_contactor_celsius = 4.5
        sim.state.acid_strength_wt = 91.5
        sim.state.h_settler_interface_pct = 52.0
        sim.state.acid_carryover_detected = False
        sim.state.isobutane_to_olefin_ratio = 7.2  # < 8.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1347") & 0xFFFF == 0xC604
        assert sim.state.low_io_ratio_fault is True
        assert reg.read_bit("%M312") is True
        assert reg.read_bit("%M313") is False

    def test_priority_hierarchy(self) -> None:
        """Requirement 7: Verify 0xC601 (thermal runaway) dominates over 0xC602, 0xC603, and 0xC604."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)

        # Trigger all 4 fault conditions simultaneously
        sim.state.t_contactor_celsius = 15.0       # 0xC601
        sim.state.acid_strength_wt = 85.0          # 0xC602
        sim.state.h_settler_interface_pct = 82.0   # 0xC603
        sim.state.isobutane_to_olefin_ratio = 6.5  # 0xC604
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        # Highest priority 0xC601 must be reported in %R1347
        assert reg.read_word("%R1347") & 0xFFFF == 0xC601
        assert reg.read_bit("%M313") is True   # Thermal trip asserted
        assert reg.read_bit("%M312") is False  # Permissive cleared
        assert reg.read_bit("%M314") is True   # Carryover coil still asserted concurrently


# ============================================================================
# 8. Section 8: Horner OCS Memory Space Integration
# ============================================================================

class TestSection8HornerOCSMemorySpaceIntegration:
    """Tests for Horner OCS memory space bindings (%R1340..%R1347, %M312..%M314) with PrivilegeMode.SYSTEM."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 8: Verify analog register values and discrete coil states with PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)

        sim.state.t_contactor_celsius = 4.5
        sim.state.isobutane_to_olefin_ratio = 11.5
        sim.state.acid_strength_wt = 91.5
        sim.state.alkylate_octane_ron = 96.5
        sim.state.h_settler_interface_pct = 52.0
        sim.state.acid_soluble_oil_pct = 4.5
        sim.state.fresh_acid_makeup_rate_kg_h = 15.0

        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1340") == 45   # 4.5 °C * 10
        assert reg.read_word("%R1341") == 115  # 11.5 * 10
        assert reg.read_word("%R1342") == 915  # 91.5 % * 10
        assert reg.read_word("%R1343") == 965  # 96.5 RON * 10
        assert reg.read_word("%R1344") == 520  # 52.0 % * 10
        assert reg.read_word("%R1345") == 45   # 4.5 % * 10
        assert reg.read_word("%R1346") == 150  # 15.0 kg/h * 10
        assert reg.read_word("%R1347") & 0xFFFF == 0x0000
        assert reg.read_bit("%M312") is True
        assert reg.read_bit("%M313") is False
        assert reg.read_bit("%M314") is False

    def test_analog_register_scaling_ranges(self) -> None:
        """Requirement 8: Verify safe INT16 scaling across operational range."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)

        test_cases = [
            (3.0, 10.0, 90.0, 95.0, 50.0, 4.0, 10.0, [30, 100, 900, 950, 500, 40, 100]),
            (6.5, 13.0, 93.5, 98.0, 55.0, 5.0, 20.0, [65, 130, 935, 980, 550, 50, 200]),
        ]

        for temp_c, io_r, acid_wt, ron, sett_pct, aso_pct, mkup, expected in test_cases:
            sim.state.t_contactor_celsius = temp_c
            sim.state.isobutane_to_olefin_ratio = io_r
            sim.state.acid_strength_wt = acid_wt
            sim.state.alkylate_octane_ron = ron
            sim.state.h_settler_interface_pct = sett_pct
            sim.state.acid_soluble_oil_pct = aso_pct
            sim.state.fresh_acid_makeup_rate_kg_h = mkup
            sim._sync_registers()

            assert reg.read_word("%R1340") == expected[0]
            assert reg.read_word("%R1341") == expected[1]
            assert reg.read_word("%R1342") == expected[2]
            assert reg.read_word("%R1343") == expected[3]
            assert reg.read_word("%R1344") == expected[4]
            assert reg.read_word("%R1345") == expected[5]
            assert reg.read_word("%R1346") == expected[6]

    def test_system_privilege_enforced_for_internal_writes(self) -> None:
        """Requirement 8: Ensure writes use PrivilegeMode.SYSTEM without throwing privilege errors."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1340") == 45

    def test_ilogicunit_protocol_compliance_and_scan_step(self) -> None:
        """Requirement 8: Verify ILogicUnit protocol compliance and scan_step return dictionary."""
        sim = AlkylationAcidSimulator()
        assert sim.name == "AlkylationAcidReactionSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

        res = sim.scan_step(dt_s=0.05)
        assert "status" in res
        assert "t_contactor_celsius" in res
        assert "y_isobutane" in res
        assert "y_olefin" in res
        assert "y_alkylate_tmp" in res
        assert "acid_strength_wt" in res
        assert "h_settler_interface_pct" in res
        assert "isobutane_to_olefin_ratio" in res
        assert "alkylate_octane_ron" in res
        assert "acid_soluble_oil_pct" in res
        assert "fresh_acid_makeup_rate_kg_h" in res
        assert "diagnostic_code" in res
        assert "alkylation_permissive" in res
        assert "alkylation_thermal_trip" in res
        assert "acid_carryover_alarm" in res
        assert res["alkylation_permissive"] is True

    def test_scan_context_adapter_execution(self) -> None:
        """Requirement 8: Verify AlkylationAcidLogicUnit adapter couples correctly into ScanContext."""
        reg = RegisterTable()
        sim = AlkylationAcidSimulator(register_table=reg)
        unit = AlkylationAcidLogicUnit(config=sim.config, register_table=reg)
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
        assert reg.read_word("%R1340") == 45
        assert reg.read_word("%R1341") == 115
        assert reg.read_bit("%M312") is True

        unit.reset()
        assert unit.state.time_s == 0.0

    def test_transient_disturbance_settling_response(self) -> None:
        """Requirement 8: Verify closed-loop settling response to +3.0 °C contactor temperature disturbance."""
        sim = AlkylationAcidSimulator()
        sim.state.t_contactor_celsius = 7.5  # +3.0 °C disturbance
        res = sim.advance_time(duration_s=8.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 3.5 <= sim.state.t_contactor_celsius <= 8.5
        assert sim.state.alkylation_permissive is True
        assert sim.state.alkylation_thermal_trip is False
        assert not math.isnan(sim.state.t_contactor_celsius)


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_alkylation_acid_verification execution and strict 4-state contract validation."""

    def test_run_alkylation_acid_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 9: Execute verification suite, write evidence JSON, assert success contract."""
        out_file = tmp_path / "alkylation_acid_evidence.json"
        evidence = run_alkylation_acid_verification(str(out_file))

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["data"]["work_package"] == "W173"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_suite_aliases(self) -> None:
        """Requirement 9: Verify alias functions execute cleanly."""
        res1 = run_sulfuric_acid_alkylation_verification()
        assert res1["status"] == "success"
        assert res1["data"]["checks_passed"] == 9

        res2 = run_alkylation_verification()
        assert res2["status"] == "success"
        assert res2["data"]["checks_passed"] == 9

        res3 = run_alkylation_acid_reaction_verification()
        assert res3["status"] == "success"
        assert res3["data"]["checks_passed"] == 9
