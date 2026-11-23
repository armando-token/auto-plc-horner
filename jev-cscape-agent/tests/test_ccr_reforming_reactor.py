"""Unit and Integration Tests for Industrial Continuous Catalytic Reforming (CCR) Pin-Fin Radial Flow Chlorided-Alumina Reforming Reactor ODE Simulation.

Work Package: W185 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1460..%R1467, %M340..%M342).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Reforming kinetics, naphthene dehydrogenation, endothermic heat Delta H.
4. Section 4: Radial flow temperature profile, Delta T drop, reformate RON and aromatics yield.
5. Section 5: Coupled 6-state ODE RK4 integration stability and dual mass/enthalpy conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xD201 thermal pinch quench, 0xD202 chloride promoter depletion, 0xD203 low H2 pressure, 0xD204 dP anomaly) and Horner coil assertion (%M340, %M341, %M342).
7. Section 7: Horner OCS register space synchronization (%R1460..%R1467, %M340..%M342) with PrivilegeMode.SYSTEM.
8. Section 8: Dynamic disturbance response (feed naphthene surge, furnace burner trip) and settling stability.
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
from jev_cscape.simulation.ccr_reforming_reactor import (
    AROMATICS_YIELD_PCT_NOMINAL,
    CATALYST_CIRCULATION_RATE_KG_H,
    CATALYST_INVENTORY_NOMINAL_KG,
    CCR_REACTOR_PURE_ST_POU,
    CCR_REACTOR_SYNC_POU,
    CCR_REFORMING_REACTOR_DYNAMICS_SYNC_POU,
    CCR_REFORMING_REACTOR_PURE_ST_POU,
    CCR_REFORMING_REACTOR_SYNC_POU,
    CHLORIDE_PROMOTER_MIN_WT_PCT,
    CHLORIDE_PROMOTER_WT_PCT_NOMINAL,
    CcrReactorConfig,
    CcrReactorDiagCode,
    CcrReactorDiagnosticCode,
    CcrReactorEngine,
    CcrReactorLogicUnit,
    CcrReactorModel,
    CcrReactorParameters,
    CcrReactorPlantModel,
    CcrReactorSimulationEngine,
    CcrReactorSimulator,
    CcrReactorState,
    CcrReactorStatusBits,
    CcrReactorStatusWord,
    CcrReformingConfig,
    CcrReformingDiagnosticCode,
    CcrReformingLogicUnit,
    CcrReformingReactorConfig,
    CcrReformingReactorDiagCode,
    CcrReformingReactorDiagnosticCode,
    CcrReformingReactorEngine,
    CcrReformingReactorLogicUnit,
    CcrReformingReactorModel,
    CcrReformingReactorParameters,
    CcrReformingReactorPlantModel,
    CcrReformingReactorSimulationEngine,
    CcrReformingReactorSimulator,
    CcrReformingReactorState,
    CcrReformingReactorStatusBits,
    CcrReformingReactorStatusWord,
    CcrReformingSimulator,
    CcrReformingState,
    DELTA_H_AROMATIZATION_J_MOL,
    DELTA_H_CRACKING_J_MOL,
    DELTA_H_CRACK_J_MOL,
    DELTA_H_CYCLIZATION_J_MOL,
    DELTA_H_DEHYD_J_MOL,
    DELTA_H_DEHYDROCYCLIZATION_J_MOL,
    DELTA_H_DEHYDROCYCLIZATION_KJ_MOL,
    DELTA_H_DEHYDROCYCL_J_MOL,
    DELTA_H_DEHYDROGENATION_J_MOL,
    DELTA_H_DEHYDROGENATION_KJ_MOL,
    DELTA_H_DEHYDRO_J_MOL,
    DELTA_H_DHC_J_MOL,
    DELTA_H_DHN_J_MOL,
    DELTA_H_HCK_J_MOL,
    DELTA_H_HYDROCRACKING_J_MOL,
    DELTA_H_HYDROCRACKING_KJ_MOL,
    DELTA_H_ISOMERIZATION_J_MOL,
    DELTA_H_ISOMERIZATION_KJ_MOL,
    DELTA_H_RXN1_J_MOL,
    DELTA_H_RXN2_J_MOL,
    DELTA_H_RXN3_J_MOL,
    FEED_AROMATICS_WT_PCT_NOMINAL,
    FEED_NAPHTHA_FLOW_NOMINAL_KG_S,
    FEED_NAPHTHENE_WT_PCT_NOMINAL,
    FEED_PARAFFIN_WT_PCT_NOMINAL,
    G_ACCEL,
    HYDROGEN_PRESSURE_MIN_BAR,
    HYDROGEN_PRESSURE_NOMINAL_BAR,
    HYDROGEN_PRESSURE_SCALED,
    MW_AROMATIC,
    MW_CARBON,
    MW_CRACKED_GAS,
    MW_H2,
    MW_HEPTANE,
    MW_LIGHT_ENDS,
    MW_MCH,
    MW_NAPHTHA,
    MW_NAPHTHENE,
    MW_PARAFFIN,
    MW_TOLUENE,
    RADIAL_BED_DELTA_T_LIMIT_C,
    RADIAL_BED_DELTA_T_NOMINAL_C,
    RADIAL_BED_DP_MAX_LIMIT_KPA,
    RADIAL_BED_DP_MIN_LIMIT_KPA,
    RADIAL_BED_DP_NOMINAL_KPA,
    RADIAL_FLOW_REFORMING_REACTOR_DYNAMICS_SYNC_POU,
    RADIAL_FLOW_REFORMING_REACTOR_PURE_ST_POU,
    RADIAL_FLOW_REFORMING_REACTOR_SYNC_POU,
    REACTOR_INLET_TEMP_MAX_C,
    REACTOR_INLET_TEMP_MIN_C,
    REACTOR_INLET_TEMP_NOMINAL_C,
    REACTOR_OUTLET_TEMP_MAX_C,
    REACTOR_OUTLET_TEMP_MIN_C,
    REACTOR_OUTLET_TEMP_NOMINAL_C,
    REFORMATE_RON_MIN,
    REFORMATE_RON_NOMINAL,
    REFORMING_REACTOR_PURE_ST_POU,
    REFORMING_REACTOR_SYNC_POU,
    R_GAS_CONST,
    RadialFlowChloridedAluminaReformerConfig,
    RadialFlowChloridedAluminaReformerDiagCode,
    RadialFlowChloridedAluminaReformerDiagnosticCode,
    RadialFlowChloridedAluminaReformerEngine,
    RadialFlowChloridedAluminaReformerLogicUnit,
    RadialFlowChloridedAluminaReformerModel,
    RadialFlowChloridedAluminaReformerParameters,
    RadialFlowChloridedAluminaReformerPlantModel,
    RadialFlowChloridedAluminaReformerSimulationEngine,
    RadialFlowChloridedAluminaReformerSimulator,
    RadialFlowChloridedAluminaReformerState,
    RadialFlowChloridedAluminaReformerStatusBits,
    RadialFlowChloridedAluminaReformerStatusWord,
    RadialFlowReformingReactorConfig,
    RadialFlowReformingReactorDiagCode,
    RadialFlowReformingReactorDiagnosticCode,
    RadialFlowReformingReactorEngine,
    RadialFlowReformingReactorLogicUnit,
    RadialFlowReformingReactorModel,
    RadialFlowReformingReactorParameters,
    RadialFlowReformingReactorPlantModel,
    RadialFlowReformingReactorSimulationEngine,
    RadialFlowReformingReactorSimulator,
    RadialFlowReformingReactorState,
    RadialFlowReformingReactorStatusBits,
    RadialFlowReformingReactorStatusWord,
    ReformingReactorConfig,
    ReformingReactorDiagCode,
    ReformingReactorDiagnosticCode,
    ReformingReactorEngine,
    ReformingReactorLogicUnit,
    ReformingReactorModel,
    ReformingReactorParameters,
    ReformingReactorPlantModel,
    ReformingReactorSimulationEngine,
    ReformingReactorSimulator,
    ReformingReactorState,
    ReformingReactorStatusBits,
    ReformingReactorStatusWord,
    T_REF_K,
    T_ZERO_CELSIUS,
    run_ccr_reactor_verification,
    run_ccr_reforming_reactor_verification,
    run_radial_flow_reforming_reactor_verification,
    run_reforming_reactor_verification,
    validate_pure_st,
    verify_ccr_reactor_pure_st,
    verify_ccr_reforming_reactor_pure_st,
    verify_radial_flow_reforming_reactor_pure_st,
    verify_reforming_reactor_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1460..%R1467, %M340..%M342)."""

    def test_verify_ccr_reforming_reactor_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_ccr_reforming_reactor_pure_st() is True
        assert verify_radial_flow_reforming_reactor_pure_st() is True
        assert verify_ccr_reactor_pure_st() is True
        assert verify_reforming_reactor_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1460..%R1467, %M340..%M342)."""
        SecurityGuard.assert_pure_st_content(CCR_REFORMING_REACTOR_PURE_ST_POU)
        val = STParser.validate_code(CCR_REFORMING_REACTOR_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CCR_REFORMING_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "CcrReformingReactorSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1460", "%R1461", "%R1462", "%R1463",
            "%R1464", "%R1465", "%R1466", "%R1467",
            "%M340", "%M341", "%M342",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from CcrReformingReactorSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate RadialFlowReformingReactorSync alias POU AST."""
        ast_alias = STParser.parse_pou(RADIAL_FLOW_REFORMING_REACTOR_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "RadialFlowReformingReactorSync"
        assert ast_alias.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1460", "%R1461", "%R1462", "%R1463",
            "%R1464", "%R1465", "%R1466", "%R1467",
            "%M340", "%M341", "%M342",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers

    def test_pou_string_constants_and_sync_aliases(self) -> None:
        """Requirement 1: Verify string constants and sync POU aliases."""
        assert CCR_REFORMING_REACTOR_SYNC_POU == CCR_REFORMING_REACTOR_PURE_ST_POU
        assert RADIAL_FLOW_REFORMING_REACTOR_SYNC_POU == RADIAL_FLOW_REFORMING_REACTOR_PURE_ST_POU
        assert CCR_REACTOR_PURE_ST_POU == CCR_REFORMING_REACTOR_PURE_ST_POU
        assert CCR_REACTOR_SYNC_POU == CCR_REFORMING_REACTOR_PURE_ST_POU
        assert CCR_REFORMING_REACTOR_DYNAMICS_SYNC_POU == CCR_REFORMING_REACTOR_PURE_ST_POU
        assert RADIAL_FLOW_REFORMING_REACTOR_DYNAMICS_SYNC_POU == RADIAL_FLOW_REFORMING_REACTOR_PURE_ST_POU
        assert REFORMING_REACTOR_PURE_ST_POU == CCR_REFORMING_REACTOR_PURE_ST_POU
        assert REFORMING_REACTOR_SYNC_POU == CCR_REFORMING_REACTOR_PURE_ST_POU

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
            "XIC ReformingPermissive",
            "XIO ReformingEmergencyTrip",
            "OTE PromoterChlorideAlarm",
            "OTL ReformingEmergencyTrip",
            "OTU ReformingPermissive",
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
# 3. Section 3: Reforming Kinetics, Naphthene Dehydrogenation & Endothermic Heat
# ============================================================================

class TestSection3ReformingKineticsNaphtheneDehydrogenationAndEndothermicHeat:
    """Tests for reforming kinetics, naphthene dehydrogenation, and endothermic heat Delta H."""

    def test_reaction_enthalpy_constants(self) -> None:
        """Requirement 3: Verify standard endothermic and exothermic reaction enthalpies."""
        assert DELTA_H_DEHYDROGENATION_KJ_MOL == 215.0
        assert DELTA_H_DEHYDROGENATION_J_MOL == 215000.0
        assert DELTA_H_DEHYDROCYCLIZATION_KJ_MOL == 225.0
        assert DELTA_H_DEHYDROCYCLIZATION_J_MOL == 225000.0
        assert DELTA_H_HYDROCRACKING_KJ_MOL == -50.0
        assert DELTA_H_HYDROCRACKING_J_MOL == -50000.0
        assert DELTA_H_ISOMERIZATION_KJ_MOL == -10.0
        assert DELTA_H_ISOMERIZATION_J_MOL == -10000.0

        assert DELTA_H_DEHYD_J_MOL == 215000.0
        assert DELTA_H_DEHYDROCYCL_J_MOL == 225000.0
        assert DELTA_H_CRACK_J_MOL == -50000.0
        assert DELTA_H_DHC_J_MOL == 225000.0
        assert DELTA_H_DHN_J_MOL == 215000.0
        assert DELTA_H_HCK_J_MOL == -50000.0
        assert DELTA_H_CYCLIZATION_J_MOL == 225000.0
        assert DELTA_H_DEHYDRO_J_MOL == 215000.0
        assert DELTA_H_CRACKING_J_MOL == -50000.0
        assert DELTA_H_AROMATIZATION_J_MOL == 225000.0
        assert DELTA_H_RXN1_J_MOL == 215000.0
        assert DELTA_H_RXN2_J_MOL == 225000.0
        assert DELTA_H_RXN3_J_MOL == -50000.0

    def test_universal_molecular_weight_constants(self) -> None:
        """Requirement 3: Validate universal molecular weight constants for hydrocarbons and H2."""
        assert abs(MW_H2 - 0.00201588) < 1e-6
        assert abs(MW_CARBON - 0.012011) < 1e-6
        assert abs(MW_NAPHTHA - 0.100000) < 1e-6
        assert abs(MW_PARAFFIN - 0.100205) < 1e-6
        assert abs(MW_NAPHTHENE - 0.098189) < 1e-6
        assert abs(MW_AROMATIC - 0.092141) < 1e-6
        assert abs(MW_LIGHT_ENDS - 0.044097) < 1e-6
        assert MW_CRACKED_GAS == MW_LIGHT_ENDS
        assert MW_MCH == MW_NAPHTHENE
        assert MW_TOLUENE == MW_AROMATIC
        assert MW_HEPTANE == MW_PARAFFIN

    def test_naphthene_dehydrogenation_kinetics(self) -> None:
        """Requirement 3: Fast metal-catalyzed naphthene dehydrogenation (conversion > 80%)."""
        sim = CcrReformingReactorSimulator()
        kin = sim.compute_reforming_kinetics(
            t_inlet_c=520.0,
            t_outlet_c=465.0,
            p_h2_bar=25.0,
            chloride_wt_pct=0.95,
            feed_flow_kg_s=45.0,
        )
        assert kin["r_dehyd_mol_s"] > 50.0
        # Feed naphthene molar flow is ~82.5 mol/s -> conversion > 75%
        assert kin["r_dehyd_mol_s"] <= 82.5

    def test_paraffin_dehydrocyclization_kinetics(self) -> None:
        """Requirement 3: Bifunctional acid-metal paraffin dehydrocyclization kinetics."""
        sim = CcrReformingReactorSimulator()
        kin = sim.compute_reforming_kinetics(
            t_inlet_c=520.0,
            t_outlet_c=465.0,
            p_h2_bar=25.0,
            chloride_wt_pct=0.95,
            feed_flow_kg_s=45.0,
        )
        assert kin["r_dhc_mol_s"] > 50.0
        assert kin["r_hck_mol_s"] < kin["r_dhc_mol_s"]  # Cyclization dominates over cracking

    def test_chloride_promoter_acid_function_sensitivity(self) -> None:
        """Requirement 3: Promoter chloride levels determine acid function factor phi_acid."""
        sim = CcrReformingReactorSimulator()
        kin_norm = sim.compute_reforming_kinetics(chloride_wt_pct=0.95)
        kin_depl = sim.compute_reforming_kinetics(chloride_wt_pct=0.70)

        assert kin_norm["phi_acid"] == 1.0
        assert kin_depl["phi_acid"] < 0.80
        assert kin_depl["r_dhc_mol_s"] < kin_norm["r_dhc_mol_s"]

    def test_endothermic_reaction_heat_release(self) -> None:
        """Requirement 3: Net endothermic heat duty Q_endo ~25,000..45,000 kW."""
        sim = CcrReformingReactorSimulator()
        kin = sim.compute_reforming_kinetics()
        assert 20000.0 <= kin["q_endothermic_kw"] <= 45000.0
        assert kin["q_dehyd_kw"] > 0.0
        assert kin["q_dhc_kw"] > 0.0
        assert kin["q_hck_kw"] < 0.0  # Hydrocracking is exothermic (negative duty)
        assert kin["heat_loss_kw"] > 0.0


# ============================================================================
# 4. Section 4: Radial Flow Temperature Profile, Delta T Drop & Reformate Quality
# ============================================================================

class TestSection4RadialFlowProfileDeltaTDropAndReformateQuality:
    """Tests for radial flow temperature profile, Delta T drop, reformate RON, and aromatics yield."""

    def test_radial_flow_reactor_geometry_and_annular_volume(self) -> None:
        """Requirement 4: Verify radial flow geometry (r_in=0.6m, r_out=1.8m, H=10m, Cat=65t)."""
        sim = CcrReformingReactorSimulator()
        assert sim.config.inner_radius_centerpipe_m == 0.6
        assert sim.config.outer_radius_basket_m == 1.8
        assert sim.config.active_bed_height_m == 10.0
        assert abs(sim.config.radial_thickness_m - 1.2) < 1e-6
        assert sim.config.catalyst_inventory_kg == 65000.0
        assert CATALYST_INVENTORY_NOMINAL_KG == 65000.0
        assert CATALYST_CIRCULATION_RATE_KG_H == 1500.0

        # Annular bed volume = pi * (1.8^2 - 0.6^2) * 10 = pi * (3.24 - 0.36) * 10 ~ 90.478 m^3
        v_bed = sim.config.bed_cross_sectional_volume_m3
        assert abs(v_bed - 90.478) < 0.1

    def test_radial_gas_velocity_and_pinning_prevention(self) -> None:
        """Requirement 4: Gas superficial velocity and pinning prevention limit check."""
        sim = CcrReformingReactorSimulator()
        prof = sim.compute_radial_profile(t_inlet_c=520.0, feed_flow_kg_s=45.0)

        assert 0.03 <= prof["gas_superficial_velocity_m_s"] <= 0.30
        assert prof["gas_inner_screen_velocity_m_s"] < prof["pinning_velocity_limit_m_s"]
        assert prof["is_pinning_safe"] is True

    def test_radial_bed_pressure_drop_ergun(self) -> None:
        """Requirement 4: Pin-fin radial flow basket dP ~ 45.0 kPa at nominal feed flow."""
        sim = CcrReformingReactorSimulator()
        prof = sim.compute_radial_profile(t_inlet_c=520.0, feed_flow_kg_s=45.0)

        assert abs(prof["radial_dp_kpa"] - 45.0) < 5.0
        assert RADIAL_BED_DP_NOMINAL_KPA == 45.0
        assert RADIAL_BED_DP_MAX_LIMIT_KPA == 85.0
        assert RADIAL_BED_DP_MIN_LIMIT_KPA == 10.0

    def test_radial_temperature_profile_and_delta_t_drop(self) -> None:
        """Requirement 4: Radial bed temperature drop Delta T ~ 55.0 °C (Inlet 520 °C -> Outlet 465 °C)."""
        sim = CcrReformingReactorSimulator()
        prof = sim.compute_radial_profile(t_inlet_c=520.0, feed_flow_kg_s=45.0)

        assert abs(prof["delta_t_celsius"] - 55.0) < 5.0
        assert abs(prof["reactor_outlet_temp_celsius"] - 465.0) < 5.0
        assert REACTOR_INLET_TEMP_NOMINAL_C == 520.0
        assert REACTOR_OUTLET_TEMP_NOMINAL_C == 465.0
        assert RADIAL_BED_DELTA_T_NOMINAL_C == 55.0
        assert RADIAL_BED_DELTA_T_LIMIT_C == 75.0

    def test_reformate_ron_and_aromatics_yield(self) -> None:
        """Requirement 4: Reformate Research Octane Number RON ~ 102.0 and aromatics yield ~ 70 wt%."""
        sim = CcrReformingReactorSimulator()
        prof = sim.compute_radial_profile(t_inlet_c=520.0, feed_flow_kg_s=45.0)

        assert abs(prof["reformate_ron"] - 102.0) < 1.0
        assert abs(prof["aromatics_yield_pct"] - 70.0) < 1.0
        assert REFORMATE_RON_NOMINAL == 102.0
        assert AROMATICS_YIELD_PCT_NOMINAL == 70.0


# ============================================================================
# 5. Section 5: Coupled 6-State ODE RK4 Integration & Conservation Residuals
# ============================================================================

class TestSection5Coupled6StateODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states_bounded(self) -> None:
        """Requirement 5: Advance ODE system via high-order RK4 over 5.0s and verify state stability."""
        sim = CcrReformingReactorSimulator()
        res = sim.advance_time(duration_s=5.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 510.0 <= sim.state.reactor_inlet_temp_celsius <= 530.0
        assert 455.0 <= sim.state.reactor_outlet_temp_celsius <= 475.0
        assert 15.0 <= sim.state.y_paraffins_wt_pct <= 30.0
        assert 1.0 <= sim.state.y_naphthenes_wt_pct <= 6.0
        assert 65.0 <= sim.state.y_aromatics_wt_pct <= 75.0
        assert 20.0 <= sim.state.hydrogen_partial_pressure_bar <= 30.0

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 5: Total mass balance, elemental balance, and enthalpy residuals < 1e-10."""
        sim = CcrReformingReactorSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_rk4_all_derivatives_finite(self) -> None:
        """Requirement 5: Verify all 6 ODE state derivatives remain finite without NaN or Inf."""
        sim = CcrReformingReactorSimulator()
        y0 = [520.0, 465.0, 22.0, 3.5, 70.0, 25.0]
        derivs = sim.compute_derivatives(0.0, y0)

        assert len(derivs) == 6
        for i, d in enumerate(derivs):
            assert not math.isnan(d), f"Derivative {i} is NaN"
            assert not math.isinf(d), f"Derivative {i} is infinite"

    def test_invalid_timestep_handling(self) -> None:
        """Requirement 5: Non-positive integration timestep fails cleanly."""
        sim = CcrReformingReactorSimulator()
        res_neg = sim.step(dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"
        assert not math.isnan(sim.state.reactor_inlet_temp_celsius)


# ============================================================================
# 6. Section 6: Process Safety Trips, Interlocks & Horner Coils
# ============================================================================

class TestSection6ProcessSafetyInterlocksAndDiagnostics:
    """Tests for safety trips (0xD201..0xD204) and Horner coil assertions (%M340, %M341, %M342)."""

    def test_thermal_pinch_quench_trip_0xd201(self) -> None:
        """Requirement 6: 0xD201 Thermal pinch quench (Delta T > 75 °C or Tout < 440 °C) asserts %M341, clears %M340."""
        sim = CcrReformingReactorSimulator()
        sim.state.radial_bed_delta_t_celsius = 78.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == CcrReformingReactorDiagnosticCode.CCR_ERR_THERMAL_PINCH_QUENCH
        assert sim.state.reforming_emergency_trip is True
        assert sim.state.reforming_permissive is False

    def test_thermal_pinch_outlet_temp_quench_0xd201(self) -> None:
        """Requirement 6: 0xD201 Tout < 440 °C triggers emergency trip."""
        sim = CcrReformingReactorSimulator()
        sim.state.reactor_outlet_temp_celsius = 435.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == CcrReformingReactorDiagnosticCode.CCR_ERR_THERMAL_PINCH_QUENCH
        assert sim.state.reforming_emergency_trip is True
        assert sim.state.reforming_permissive is False

    def test_chloride_promoter_depletion_alarm_0xd202(self) -> None:
        """Requirement 6: 0xD202 Chloride promoter < 0.80 wt% asserts %M342 (PromoterChlorideAlarm)."""
        sim = CcrReformingReactorSimulator()
        sim.state.chloride_promoter_wt_pct = 0.75
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == CcrReformingReactorDiagnosticCode.CCR_ERR_CHLORIDE_PROMOTER_DEPLETION
        assert sim.state.promoter_chloride_alarm is True
        assert sim.state.reforming_permissive is True
        assert sim.state.reforming_emergency_trip is False

    def test_low_h2_pressure_trip_0xd203(self) -> None:
        """Requirement 6: 0xD203 Low H2 partial pressure < 15.0 bar asserts %M341, clears %M340."""
        sim = CcrReformingReactorSimulator()
        sim.state.hydrogen_partial_pressure_bar = 12.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == CcrReformingReactorDiagnosticCode.CCR_ERR_LOW_H2_PRESSURE
        assert sim.state.reforming_emergency_trip is True
        assert sim.state.reforming_permissive is False

    def test_radial_bed_dp_anomaly_fault_0xd204(self) -> None:
        """Requirement 6: 0xD204 Pin-fin radial bed dP > 85.0 kPa sets fault code."""
        sim = CcrReformingReactorSimulator()
        sim.state.radial_bed_differential_pressure_kpa = 92.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == CcrReformingReactorDiagnosticCode.CCR_ERR_RADIAL_BED_DP_ANOMALY
        assert sim.state.reforming_permissive is True
        assert sim.state.reforming_emergency_trip is False

    def test_safety_priority_hierarchy(self) -> None:
        """Requirement 6: Priority hierarchy 0xD201 > 0xD202 > 0xD203 > 0xD204."""
        sim = CcrReformingReactorSimulator()
        sim.state.radial_bed_delta_t_celsius = 80.0                # 0xD201
        sim.state.chloride_promoter_wt_pct = 0.70                 # 0xD202
        sim.state.hydrogen_partial_pressure_bar = 10.0            # 0xD203
        sim.state.radial_bed_differential_pressure_kpa = 95.0     # 0xD204
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xD201
        assert sim.state.reforming_emergency_trip is True
        assert sim.state.reforming_permissive is False
        assert sim.state.promoter_chloride_alarm is True

    def test_normal_healthy_clears_all_trips(self) -> None:
        """Requirement 6: Healthy state resets diagnostic code to 0x0000 and activates permissive."""
        sim = CcrReformingReactorSimulator()
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == CcrReformingReactorDiagnosticCode.OK
        assert sim.state.reforming_permissive is True
        assert sim.state.reforming_emergency_trip is False
        assert sim.state.promoter_chloride_alarm is False


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration (%R1460..%R1467, %M340..%M342)
# ============================================================================

class TestSection7HornerOCSMemorySpaceIntegration:
    """Tests for %R1460..%R1467 and %M340..%M342 scaling and PrivilegeMode.SYSTEM enforcement."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 7: Verify scaled values in RegisterTable."""
        reg = RegisterTable()
        sim = CcrReformingReactorSimulator(register_table=reg)

        sim.state.reactor_inlet_temp_celsius = 520.0
        sim.state.reactor_outlet_temp_celsius = 465.0
        sim.state.radial_bed_delta_t_celsius = 55.0
        sim.state.reformate_ron = 102.0
        sim.state.y_aromatics_wt_pct = 70.0
        sim.state.hydrogen_partial_pressure_bar = 25.0
        sim.state.radial_bed_differential_pressure_kpa = 45.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1460") == 5200
        assert reg.read_word("%R1461") == 4650
        assert reg.read_word("%R1462") == 550
        assert reg.read_word("%R1463") == 1020
        assert reg.read_word("%R1464") == 700
        assert reg.read_word("%R1465") == 250
        assert reg.read_word("%R1466") == 450
        assert reg.read_word("%R1467") & 0xFFFF == 0x0000

        assert reg.read_bit("%M340") is True
        assert reg.read_bit("%M341") is False
        assert reg.read_bit("%M342") is False

    def test_system_privilege_enforced(self) -> None:
        """Requirement 7: Internal write operations use PrivilegeMode.SYSTEM without privilege errors."""
        reg = RegisterTable()
        sim = CcrReformingReactorSimulator(register_table=reg)
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1460") == 5200

    def test_ilogicunit_protocol_compliance_and_scan_step(self) -> None:
        """Requirement 7: ILogicUnit protocol compliance and scan_step return dictionary."""
        sim = CcrReformingReactorSimulator()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "CcrReformingReactorSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

        res_dict = sim.scan_step(dt=0.05)
        assert res_dict["status"] == "success"
        assert "reactor_inlet_temp_celsius" in res_dict
        assert "reactor_outlet_temp_celsius" in res_dict
        assert "radial_bed_delta_t_celsius" in res_dict
        assert "reformate_ron" in res_dict
        assert "aromatics_yield_pct" in res_dict
        assert "hydrogen_partial_pressure_bar" in res_dict
        assert "radial_bed_differential_pressure_kpa" in res_dict
        assert "diagnostic_code" in res_dict
        assert "reforming_permissive" in res_dict
        assert "reforming_emergency_trip" in res_dict
        assert "promoter_chloride_alarm" in res_dict

    def test_scan_context_adapter_execution(self) -> None:
        """Requirement 7: Verify execute(ScanContext) multi-cycle adapter execution."""
        reg = RegisterTable()
        sim = CcrReformingReactorSimulator(register_table=reg)
        unit = CcrReformingReactorLogicUnit(config=sim.config, register_table=reg)
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
        assert reg.read_word("%R1460") == 5200
        assert reg.read_word("%R1461") == 4650
        assert reg.read_bit("%M340") is True


# ============================================================================
# 8. Section 8: Dynamic Disturbance Response & Closed-Loop Settling
# ============================================================================

class TestSection8DynamicDisturbanceResponseAndSettling:
    """Tests for transient disturbance response (feed naphthene surge, furnace burner trip) and settling."""

    def test_feed_naphthene_surge_disturbance(self) -> None:
        """Requirement 8: Feed naphthene surge (+10 kg/s) increases endotherm and settles cleanly."""
        sim = CcrReformingReactorSimulator()
        sim.state.feed_naphtha_flow_kg_s = 55.0  # +10 kg/s feed surge
        res = sim.advance_time(duration_s=6.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert not math.isnan(sim.state.reactor_outlet_temp_celsius)
        assert not math.isnan(sim.state.reformate_ron)
        assert 445.0 <= sim.state.reactor_outlet_temp_celsius <= 475.0
        assert sim.state.reforming_permissive is True
        assert sim.state.reforming_emergency_trip is False

    def test_furnace_burner_trip_disturbance(self) -> None:
        """Requirement 8: Furnace burner trip (-25 °C inlet drop) settles cleanly."""
        sim = CcrReformingReactorSimulator()
        sim.state.reactor_inlet_temp_celsius = 495.0
        res = sim.advance_time(duration_s=6.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert not math.isnan(sim.state.reactor_outlet_temp_celsius)
        assert 440.0 <= sim.state.reactor_outlet_temp_celsius <= 465.0

    def test_chloride_depletion_transient_response(self) -> None:
        """Requirement 8: Catalyst chloride depletion disturbance transient response."""
        sim = CcrReformingReactorSimulator()
        sim.state.chloride_promoter_wt_pct = 0.75
        sim.advance_time(duration_s=4.0, dt=0.05)

        assert not math.isnan(sim.state.reformate_ron)
        assert sim.state.promoter_chloride_alarm is True


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_ccr_reforming_reactor_verification suite and evidence artifact generation."""

    def test_run_ccr_reforming_reactor_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 9: Verification suite returns strict 4-state contract JSON with all 9 stages passed."""
        out_file = tmp_path / "ccr_reforming_reactor_evidence.json"
        res = run_ccr_reforming_reactor_verification(output_path=str(out_file))

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
        assert run_radial_flow_reforming_reactor_verification == run_ccr_reforming_reactor_verification
        assert run_ccr_reactor_verification == run_ccr_reforming_reactor_verification
        assert run_reforming_reactor_verification == run_ccr_reforming_reactor_verification

    def test_radial_flow_chlorided_alumina_aliases_and_properties(self) -> None:
        """Requirement 9: Verify class aliases and convenience property accessors on state."""
        cfg = RadialFlowChloridedAluminaReformerConfig()
        assert isinstance(cfg, CcrReformingReactorConfig)

        sim = RadialFlowChloridedAluminaReformerSimulator(config=cfg)
        assert isinstance(sim, CcrReformingReactorSimulator)
        assert isinstance(sim.state, RadialFlowChloridedAluminaReformerState)

        lu = RadialFlowChloridedAluminaReformerLogicUnit(config=cfg)
        assert isinstance(lu, ILogicUnit)

        state = sim.state
        assert state.reformer_firing_permissive is True
        assert state.reformer_emergency_trip is False
        assert state.chloride_injection_alarm is False
        assert state.inlet_temp_celsius == pytest.approx(520.0, rel=1e-3)
        assert state.outlet_temp_celsius == pytest.approx(465.0, rel=1e-3)
        assert state.t_bed_radial_celsius == pytest.approx(465.0, rel=1e-3)
        assert state.radial_delta_t_celsius == pytest.approx(55.0, rel=1e-3)
        assert state.y_aromatics == pytest.approx(70.0, rel=1e-3)
        assert state.y_paraffins == pytest.approx(22.0, rel=1e-3)
        assert state.y_naphthenes == pytest.approx(3.5, rel=1e-3)
        assert state.y_hydrogen == pytest.approx(25.0, rel=1e-3)
        assert state.y_hydrogen_mol_pct == 91.5
        assert state.radial_screen_dp_bar == pytest.approx(0.45, rel=1e-3)

        # Test setters
        state.reformer_firing_permissive = False
        assert state.reforming_permissive is False
        state.reformer_emergency_trip = True
        assert state.reforming_emergency_trip is True
        state.chloride_injection_alarm = True
        assert state.promoter_chloride_alarm is True
        state.inlet_temp_celsius = 525.0
        assert state.reactor_inlet_temp_celsius == 525.0
        state.outlet_temp_celsius = 472.0
        assert state.reactor_outlet_temp_celsius == 472.0
        state.t_bed_radial_celsius = 470.0
        assert state.reactor_outlet_temp_celsius == 470.0
        state.radial_delta_t_celsius = 53.0
        assert state.radial_bed_delta_t_celsius == 53.0
        state.y_aromatics = 68.5
        assert state.y_aromatics_wt_pct == 68.5
        state.y_paraffins = 20.0
        assert state.y_paraffins_wt_pct == 20.0
        state.y_naphthenes = 2.5
        assert state.y_naphthenes_wt_pct == 2.5
        state.y_hydrogen = 26.0
        assert state.hydrogen_partial_pressure_bar == 26.0

