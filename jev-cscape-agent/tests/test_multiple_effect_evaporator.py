"""Unit and Integration Tests for Industrial Multiple-Effect Evaporator (MEE) ODE Simulation.

Work Package: W134 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R950..%R957, %M221..%M223).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Antoine vapor pressure equations, Duhring's rule BPE calculation, and latent heat of vaporization.
4. Section 4: Triple-effect heat transfer, inter-effect vapor coupling, and steam economy formulation (2.7..2.9).
5. Section 5: Coupled ODE RK4 integration stability and dual mass and solute conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0x9F01, 0x9F02, 0x9F03, 0x9F04) and Horner coil assertion (%M221, %M222, %M223).
7. Section 7: Horner OCS register space synchronization (%R950..%R957, %M221..%M223).
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
from jev_cscape.simulation.multiple_effect_evaporator import (
    MEE_EVAPORATOR_DYNAMICS_SYNC_POU,
    MEE_EVAPORATOR_PURE_ST_POU,
    MEE_PURE_ST_POU,
    MEE_SYNC_POU,
    MEE_VAPOR_RECOMPRESSION_SYNC_POU,
    MULTIPLE_EFFECT_EVAPORATOR_PURE_ST_POU,
    MULTIPLE_EFFECT_EVAPORATOR_SYNC_POU,
    MEEConfig,
    MEEDiagnosticCode,
    MEESimulator,
    MEEState,
    MEEStatusBits,
    MEEStatusWord,
    MeeConfig,
    MeeDiagnosticCode,
    MeeEvaporatorConfig,
    MeeEvaporatorModel,
    MeeEvaporatorSimulator,
    MeeEvaporatorState,
    MeeParameters,
    MeePlantModel,
    MeeSimulator,
    MeeState,
    MeeStatusBits,
    MeeStatusWord,
    MultipleEffectEvaporatorConfig,
    MultipleEffectEvaporatorDiagnosticCode,
    MultipleEffectEvaporatorEngine,
    MultipleEffectEvaporatorModel,
    MultipleEffectEvaporatorParameters,
    MultipleEffectEvaporatorPlantModel,
    MultipleEffectEvaporatorSimulationEngine,
    MultipleEffectEvaporatorSimulator,
    MultipleEffectEvaporatorState,
    MultipleEffectEvaporatorStatusBits,
    MultipleEffectEvaporatorStatusWord,
    run_mee_evaporator_verification,
    run_multiple_effect_evaporator_verification,
    verify_mee_evaporator_pure_st,
    verify_multiple_effect_evaporator_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R950..%R957, %M221..%M223)."""

    def test_verify_multiple_effect_evaporator_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_mee_evaporator_pure_st() is True
        assert verify_multiple_effect_evaporator_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R950..%R957, %M221..%M223)."""
        SecurityGuard.assert_pure_st_content(MEE_EVAPORATOR_PURE_ST_POU)
        val = STParser.validate_code(MEE_EVAPORATOR_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(MEE_EVAPORATOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "MeeEvaporatorSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R950", "%R951", "%R952", "%R953",
            "%R954", "%R955", "%R956", "%R957",
            "%M221", "%M222", "%M223",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_dynamics_alias_ast(self) -> None:
        """Requirement 1: Verify MeeEvaporatorDynamicsSync alias parses cleanly."""
        SecurityGuard.assert_pure_st_content(MEE_EVAPORATOR_DYNAMICS_SYNC_POU)
        ast = STParser.parse_pou(MEE_EVAPORATOR_DYNAMICS_SYNC_POU)
        assert ast is not None
        assert ast.name == "MeeEvaporatorDynamicsSync"
        assert ast.pou_type == POUType.PROGRAM
        for reg in ["%R950", "%R951", "%R952", "%R953", "%R954", "%R955", "%R956", "%R957", "%M221", "%M222", "%M223"]:
            assert reg in ast.bound_registers

    def test_pure_st_pou_vapor_recompression_alias_ast(self) -> None:
        """Requirement 1: Verify MEEVaporRecompressionSync alias parses cleanly."""
        SecurityGuard.assert_pure_st_content(MEE_VAPOR_RECOMPRESSION_SYNC_POU)
        ast = STParser.parse_pou(MEE_VAPOR_RECOMPRESSION_SYNC_POU)
        assert ast is not None
        assert ast.name == "MEEVaporRecompressionSync"
        assert ast.pou_type == POUType.PROGRAM
        for reg in ["%R950", "%R951", "%R952", "%R953", "%R954", "%R955", "%R956", "%R957", "%M221", "%M222", "%M223"]:
            assert reg in ast.bound_registers

    def test_pure_st_pou_alias_equivalence(self) -> None:
        """Requirement 1: Verify POU aliases are defined and consistent."""
        assert MEE_PURE_ST_POU == MEE_EVAPORATOR_PURE_ST_POU
        assert MEE_SYNC_POU == MEE_EVAPORATOR_PURE_ST_POU
        assert MULTIPLE_EFFECT_EVAPORATOR_PURE_ST_POU == MEE_EVAPORATOR_PURE_ST_POU
        assert MULTIPLE_EFFECT_EVAPORATOR_SYNC_POU == MEE_EVAPORATOR_PURE_ST_POU

    def test_pure_st_pou_internal_variables_and_control_logic(self) -> None:
        """Requirement 1: Verify internal boolean variables and interlock IF-branches."""
        ast = STParser.parse_pou(MEE_EVAPORATOR_PURE_ST_POU)
        assert ast is not None
        var_names = [v.name for v in ast.variables]
        assert "SteamInletValveOpen" in var_names
        assert "VacuumSystemPermissive" in var_names
        assert "EvaporatorFeedPumpPermissive" in var_names
        assert "OverpressureVaporTrip" in var_names
        assert "BoilingPointElevationAlarm" in var_names

        stmts = "\n".join(ast.raw_statements)
        assert "IF DiagnosticStatusCode = 40705 THEN" in stmts
        assert "IF (ProductConcentrationBrix > 720) OR (DiagnosticStatusCode = 40706) THEN" in stmts
        assert "IF DiagnosticStatusCode = 40707 THEN" in stmts
        assert "IF DiagnosticStatusCode = 40708 THEN" in stmts


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests for SecurityGuard fail-closed rejection of ladder logic constructs."""

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
            "XIC EvaporatorFeedPumpPermissive",
            "XIO OverpressureVaporTrip",
            "OTE BoilingPointElevationAlarm",
            "OTL SteamInletValveOpen",
            "OTU VacuumSystemPermissive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{MEE_EVAPORATOR_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 3. Section 3: Antoine Vapor Pressure Equations, Dühring's BPE & Latent Heat
# ============================================================================

class TestSection3AntoineVaporPressureDuhringBPEAndLatentHeat:
    """Tests for Antoine saturation formulation, Dühring's BPE rule, and latent heat of vaporization."""

    def test_antoine_saturation_and_inversion(self) -> None:
        """Requirement 3: Verify Antoine formulation and exact invertible consistency."""
        sim = MultipleEffectEvaporatorSimulator()
        test_temps = [50.0, 62.1, 84.2, 100.0, 102.5, 138.87]
        for t in test_temps:
            p = sim.antoine_saturation_pressure(t)
            t_inv = sim.antoine_saturation_temperature(p)
            assert math.isclose(t, t_inv, abs_tol=0.05), f"Failed inverse consistency at T={t} C"

    def test_stage_pressure_gradient(self) -> None:
        """Requirement 3: Verify decreasing pressure stages: Steam > Effect 1 > Effect 2 > Effect 3."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state
        assert st.p_steam_kpa > st.p_vap_1_kpa > st.p_vap_2_kpa > st.p_vap_3_kpa
        assert math.isclose(st.p_steam_kpa, 350.0, abs_tol=1.0)
        assert math.isclose(st.p_vap_1_kpa, 110.2, abs_tol=1.0)
        assert math.isclose(st.p_vap_2_kpa, 55.4, abs_tol=1.0)
        assert math.isclose(st.p_vap_3_kpa, 19.5, abs_tol=1.0)

    def test_saturation_temperatures_across_stages(self) -> None:
        """Requirement 3: Verify saturation temperatures follow pressure gradient."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state
        assert st.t_sat_steam_c > st.t_sat_v1_c > st.t_sat_v2_c > st.t_sat_v3_c
        assert math.isclose(st.t_sat_steam_c, 138.58, abs_tol=1.5)
        assert math.isclose(st.t_sat_v1_c, 102.37, abs_tol=1.5)
        assert math.isclose(st.t_sat_v2_c, 83.93, abs_tol=1.5)
        assert math.isclose(st.t_sat_v3_c, 59.58, abs_tol=1.5)

    def test_bpe_monotonic_increase_with_solute(self) -> None:
        """Requirement 3: Verify BPE rises monotonically with solute concentration via Dühring's rule."""
        sim = MultipleEffectEvaporatorSimulator()
        bpe_10 = sim.compute_boiling_point_elevation(10.0)
        bpe_16 = sim.compute_boiling_point_elevation(16.6)
        bpe_26 = sim.compute_boiling_point_elevation(26.5)
        bpe_65 = sim.compute_boiling_point_elevation(65.0)
        bpe_72 = sim.compute_boiling_point_elevation(72.0)

        assert 0.0 < bpe_10 < bpe_16 < bpe_26 < bpe_65 < bpe_72
        assert math.isclose(bpe_16, 0.13, abs_tol=0.10)
        assert math.isclose(bpe_26, 0.26, abs_tol=0.15)
        assert math.isclose(bpe_65, 2.52, abs_tol=0.25)

    def test_bpe_crystallization_threshold(self) -> None:
        """Requirement 3: Verify severe over-concentration triggers high BPE (> 15.0 C)."""
        sim = MultipleEffectEvaporatorSimulator()
        bpe_85 = sim.compute_boiling_point_elevation(85.0)
        assert bpe_85 > 15.0

    def test_boiling_temperatures_elevated_above_saturation(self) -> None:
        """Requirement 3: Verify T_boil = T_sat + Delta_T_bpe in all effects."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state
        assert st.t1_c >= st.t_sat_v1_c
        assert st.t2_c >= st.t_sat_v2_c
        assert st.t3_c >= st.t_sat_v3_c

    def test_latent_heat_temperature_dependency(self) -> None:
        """Requirement 3: Verify latent heat lambda decreases with temperature."""
        sim = MultipleEffectEvaporatorSimulator()
        lh_50 = sim.compute_latent_heat(50.0)
        lh_100 = sim.compute_latent_heat(100.0)
        lh_140 = sim.compute_latent_heat(140.0)

        assert lh_50 > lh_100 > lh_140
        assert math.isclose(lh_100, 2.265e6, rel_tol=0.01)


# ============================================================================
# 4. Section 4: Triple-Effect Heat Transfer, Vapor Coupling & Steam Economy
# ============================================================================

class TestSection4TripleEffectHeatTransferAndSteamEconomy:
    """Tests for triple-effect heat transfer, inter-effect vapor coupling, and steam economy formulation (2.7..2.9)."""

    def test_calandria_driving_forces_positive(self) -> None:
        """Requirement 4: Verify positive heat transfer driving force across calandrias."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state
        delta_t_1 = st.t_sat_steam_c - st.t1_c
        delta_t_2 = st.t_sat_v1_c - st.t2_c
        delta_t_3 = st.t_sat_v2_c - st.t3_c

        assert delta_t_1 > 0.0
        assert delta_t_2 > 0.0
        assert delta_t_3 > 0.0

        assert st.q1_heat_transfer_w > 0.0
        assert st.q2_heat_transfer_w > 0.0
        assert st.q3_heat_transfer_w > 0.0

    def test_inter_effect_vapor_coupling(self) -> None:
        """Requirement 4: Verify inter-effect vapor coupling where Effect (i) vapor provides heat to Effect (i+1)."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state

        # Effect 1 vapor generation rate
        lambda_1 = sim.compute_latent_heat(st.t1_c)
        q_vap_1 = st.v1_kg_s * lambda_1

        # Effect 2 calandria heat transfer is directly coupled to Effect 1 condensing vapor (within 10% thermal dissipation)
        assert math.isclose(st.q2_heat_transfer_w, q_vap_1, rel_tol=0.10)

        # Effect 2 vapor generation rate
        lambda_2 = sim.compute_latent_heat(st.t2_c)
        q_vap_2 = st.v2_kg_s * lambda_2

        # Effect 3 calandria heat transfer is directly coupled to Effect 2 condensing vapor
        assert math.isclose(st.q3_heat_transfer_w, q_vap_2, rel_tol=0.10)

    def test_solute_concentration_progression(self) -> None:
        """Requirement 4: Verify solute concentration increases progressively from Effect 1 to Effect 3."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state
        cfg = sim.config

        assert cfg.feed_concentration_brix < st.c1_brix < st.c2_brix < st.c3_brix
        assert math.isclose(st.c1_brix, 16.6, abs_tol=0.5)
        assert math.isclose(st.c2_brix, 26.5, abs_tol=0.5)
        assert math.isclose(st.c3_brix, 65.0, abs_tol=0.5)

    def test_forward_feed_liquid_flow_cascade(self) -> None:
        """Requirement 4: Verify forward-feed liquid flows decrease as vapor is released."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state

        assert st.feed_flow_kg_s > st.l1_kg_s > st.l2_kg_s > st.l3_product_kg_s
        assert math.isclose(st.l1_kg_s, st.feed_flow_kg_s - st.v1_kg_s, rel_tol=1e-5)
        assert math.isclose(st.l2_kg_s, st.l1_kg_s - st.v2_kg_s, rel_tol=1e-5)
        assert math.isclose(st.l3_product_kg_s, st.l2_kg_s - st.v3_kg_s, rel_tol=1e-5)

    def test_steam_economy_nominal_band(self) -> None:
        """Requirement 4: Verify steam economy falls within nominal 2.7..2.9 for triple-effect MEE."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state
        assert 2.70 <= st.steam_economy <= 2.95
        assert math.isclose(st.steam_economy, 2.85, rel_tol=0.05)

    def test_total_evaporation_rate(self) -> None:
        """Requirement 4: Verify total evaporation rate is around nominal 1250 kg/h."""
        sim = MultipleEffectEvaporatorSimulator()
        st = sim.state
        assert math.isclose(st.total_evap_rate_kg_h, 1250.0, rel_tol=0.05)
        assert math.isclose(
            st.total_evap_rate_kg_s,
            st.v1_kg_s + st.v2_kg_s + st.v3_kg_s,
            rel_tol=1e-6,
        )


# ============================================================================
# 5. Section 5: Coupled ODE RK4 Integration Stability & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEAndRK4Solver:
    """Tests for coupled ODE RK4 integration stability and dual stoichiometric conservation residuals (< 1e-10)."""

    def test_rk4_advance_time_stability(self) -> None:
        """Requirement 5: Verify RK4 numerical integration produces smooth, stable trajectories."""
        sim = MultipleEffectEvaporatorSimulator()
        res = sim.advance_time(duration_s=3.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS

        st = sim.state
        assert st.t1_c > st.t2_c > st.t3_c > 0.0
        assert 10.0 <= st.c1_brix <= 25.0
        assert 20.0 <= st.c2_brix <= 40.0
        assert 50.0 <= st.c3_brix <= 70.0
        assert st.total_evap_rate_kg_s > 0.0

    def test_dual_stoichiometric_mass_conservation_residuals(self) -> None:
        """Requirement 5: Verify dual stoichiometric mass conservation residuals < 1e-10 kg/s."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        total_res = sim.state.total_mass_balance_residual_kg_s
        solute_res = sim.state.solute_mass_balance_residual_kg_s

        assert total_res < 1e-10, f"Total mass residual {total_res:.3e} exceeds 1e-10"
        assert solute_res < 1e-10, f"Solute mass residual {solute_res:.3e} exceeds 1e-10"

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Verify negative or zero duration or dt fails closed."""
        sim = MultipleEffectEvaporatorSimulator()
        res_zero = sim.advance_time(duration_s=0.0, dt=0.05)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

    def test_pump_off_evaporation_decay(self) -> None:
        """Requirement 5: Verify feed flow and evaporation cease when feed pump permissive is disabled."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.state.feed_pump_permissive = False
        sim.advance_time(duration_s=1.0, dt=0.05)

        assert sim.state.feed_flow_kg_s == 0.0
        assert sim.state.v1_kg_s == 0.0
        assert sim.state.total_evap_rate_kg_s == 0.0
        assert sim.state.steam_economy == 0.0


# ============================================================================
# 6. Section 6: Process Safety Trips & Horner Coil Assertion (%M221..%M223)
# ============================================================================

class TestSection6ProcessSafetyInterlocks:
    """Tests for process safety trips (0x9F01, 0x9F02, 0x9F03, 0x9F04) and Horner coils (%M221, %M222, %M223)."""

    def test_vapor_overpressure_trip_0x9f01(self) -> None:
        """Requirement 6: Effect 1 vapor pressure > 250 kPa asserts %M222, clears %M221, sets code 0x9F01."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.state.p_vap_1_kpa = 260.0  # > 250.0 kPa
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M222") is True
        assert sim.reg_table.read_bit("%M221") is False
        assert (sim.reg_table.read_word("%R957") & 0xFFFF) == int(MeeDiagnosticCode.MEE_ERR_VAPOR_OVERPRESSURE)

    def test_bpe_crystallization_alarm_0x9f02(self) -> None:
        """Requirement 6: Product Brix > 72 asserts %M223 and flags 0x9F02."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.state.c3_brix = 75.0  # > 72.0 Brix
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M223") is True
        assert (sim.reg_table.read_word("%R957") & 0xFFFF) == int(MeeDiagnosticCode.MEE_ERR_BPE_CRYSTALLIZATION)

    def test_bpe_crystallization_alarm_by_delta_t_0x9f02(self) -> None:
        """Requirement 6: BPE > 15.0 C asserts %M223 and flags 0x9F02."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.state.bpe_3_c = 16.5  # > 15.0 C
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M223") is True
        assert (sim.reg_table.read_word("%R957") & 0xFFFF) == int(MeeDiagnosticCode.MEE_ERR_BPE_CRYSTALLIZATION)

    def test_vacuum_collapse_trip_0x9f03(self) -> None:
        """Requirement 6: Effect 3 pressure > 40 kPa flags 0x9F03."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.state.p_vap_3_kpa = 45.0  # > 40.0 kPa
        sim._sync_registers()

        assert (sim.reg_table.read_word("%R957") & 0xFFFF) == int(MeeDiagnosticCode.MEE_ERR_VACUUM_COLLAPSE)

    def test_dry_boiling_trip_0x9f04(self) -> None:
        """Requirement 6: Liquid inventory below minimum clears %M221 and flags 0x9F04."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.state.m1_liquid_kg = 150.0  # < 200.0 kg
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M221") is False
        assert (sim.reg_table.read_word("%R957") & 0xFFFF) == int(MeeDiagnosticCode.MEE_ERR_DRY_BOILING)

    def test_diagnostic_code_priority_hierarchy(self) -> None:
        """Requirement 6: Priority hierarchy: Overpressure (0x9F01) > Dry Boiling (0x9F04) > Vacuum (0x9F03) > BPE (0x9F02)."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.state.p_vap_1_kpa = 260.0  # 0x9F01
        sim.state.m1_liquid_kg = 150.0  # 0x9F04
        sim.state.p_vap_3_kpa = 45.0   # 0x9F03
        sim.state.c3_brix = 75.0       # 0x9F02
        sim._sync_registers()

        # Highest priority (0x9F01) must take precedence
        assert (sim.reg_table.read_word("%R957") & 0xFFFF) == int(MeeDiagnosticCode.MEE_ERR_VAPOR_OVERPRESSURE)


# ============================================================================
# 7. Section 7: Horner OCS Register Space Synchronization (%R950..%R957, %M221..%M223)
# ============================================================================

class TestSection7HornerOCSSync:
    """Tests for Horner OCS memory register bindings (%R950..%R957, %M221..%M223) and class compatibility aliases."""

    def test_nominal_register_sync(self) -> None:
        """Requirement 7: Verify analog registers %R950..%R957 and discrete coils %M221..%M223."""
        sim = MultipleEffectEvaporatorSimulator()
        sim.advance_time(duration_s=0.5, dt=0.05)
        reg = sim.reg_table

        # %R950: LiveSteamPressureKpa (INT16, scaled x10 kPa, e.g. 3500 = 350.0 kPa)
        assert 3400 <= reg.read_word("%R950") <= 3600

        # %R951: Effect1TempCelsius (INT16, scaled x10 C, e.g. 1025 = 102.5 C)
        assert 1000 <= reg.read_word("%R951") <= 1050

        # %R952: Effect2TempCelsius (INT16, scaled x10 C, e.g. 842 = 84.2 C)
        assert 820 <= reg.read_word("%R952") <= 860

        # %R953: Effect3TempCelsius (INT16, scaled x10 C, e.g. 621 = 62.1 C)
        assert 600 <= reg.read_word("%R953") <= 640

        # %R954: ProductConcentrationBrix (INT16, scaled x10 Brix, e.g. 650 = 65.0 Brix)
        assert 630 <= reg.read_word("%R954") <= 670

        # %R955: TotalEvaporationRateKgh (INT16, scaled x10 kg/h, e.g. 12500 = 1250.0 kg/h)
        assert 12000 <= reg.read_word("%R955") <= 13500

        # %R956: SteamEconomyScaled (INT16, scaled x100, e.g. 285 = 2.85)
        assert 270 <= reg.read_word("%R956") <= 295

        # %R957: DiagnosticStatusCode (0x0000 = OK)
        assert (reg.read_word("%R957") & 0xFFFF) == 0x0000

        # %M221: EvaporatorFeedPumpPermissive (BOOL)
        assert reg.read_bit("%M221") is True

        # %M222: OverpressureVaporTrip (BOOL)
        assert reg.read_bit("%M222") is False

        # %M223: BoilingPointElevationAlarm (BOOL)
        assert reg.read_bit("%M223") is False

    def test_class_compatibility_aliases(self) -> None:
        """Requirement 7: Verify all required class and module aliases exist."""
        assert MEESimulator is MultipleEffectEvaporatorSimulator
        assert MeeSimulator is MultipleEffectEvaporatorSimulator
        assert MeeEvaporatorSimulator is MultipleEffectEvaporatorSimulator
        assert MeeEvaporatorModel is MultipleEffectEvaporatorSimulator
        assert MultipleEffectEvaporatorEngine is MultipleEffectEvaporatorSimulator
        assert MultipleEffectEvaporatorSimulationEngine is MultipleEffectEvaporatorSimulator
        assert MultipleEffectEvaporatorModel is MultipleEffectEvaporatorSimulator
        assert MultipleEffectEvaporatorPlantModel is MultipleEffectEvaporatorSimulator
        assert MeePlantModel is MultipleEffectEvaporatorSimulator

        assert MEEConfig is MultipleEffectEvaporatorConfig
        assert MeeConfig is MultipleEffectEvaporatorConfig
        assert MeeEvaporatorConfig is MultipleEffectEvaporatorConfig
        assert MultipleEffectEvaporatorParameters is MultipleEffectEvaporatorConfig
        assert MeeParameters is MultipleEffectEvaporatorConfig

        assert MEEState is MultipleEffectEvaporatorState
        assert MeeState is MultipleEffectEvaporatorState
        assert MeeEvaporatorState is MultipleEffectEvaporatorState

        assert MEEStatusBits is MultipleEffectEvaporatorStatusBits
        assert MeeStatusBits is MultipleEffectEvaporatorStatusBits
        assert MeeStatusWord is MultipleEffectEvaporatorStatusBits
        assert MEEStatusWord is MultipleEffectEvaporatorStatusBits
        assert MultipleEffectEvaporatorStatusWord is MultipleEffectEvaporatorStatusBits

        assert MEEDiagnosticCode is MultipleEffectEvaporatorDiagnosticCode
        assert MeeDiagnosticCode is MultipleEffectEvaporatorDiagnosticCode


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Test & Evidence JSON
# ============================================================================

class TestSection8MultipleEffectEvaporatorVerificationRunner:
    """Tests for run_multiple_effect_evaporator_verification function and evidence artifact generation."""

    def test_run_multiple_effect_evaporator_verification_suite_all_9_stages(self, tmp_path: Path) -> None:
        """Requirement 8: Execute full 9-stage verification suite and assert strict success."""
        out_file = str(tmp_path / "w134_mee_verification_evidence.json")
        res = run_multiple_effect_evaporator_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "Industrial Multiple-Effect Evaporation (MEE) Dynamics ODE Simulation verified cleanly (9/9 checks passed)" in res["details"]

        data = res["data"]
        assert data["work_package"] == "W134"
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

    def test_run_multiple_effect_evaporator_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 8: Test evidence_path compatibility alias parameter."""
        ev_file = tmp_path / "mee_alias_evidence.json"
        res = run_multiple_effect_evaporator_verification(evidence_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_mee_evaporator_verification_function_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Test run_mee_evaporator_verification function alias."""
        ev_file = tmp_path / "mee_func_alias_evidence.json"
        res = run_mee_evaporator_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()
