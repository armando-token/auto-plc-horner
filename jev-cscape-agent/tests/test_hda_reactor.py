"""Unit and Integration Tests for Industrial Hydrodealkylation (HDA) Thermal Reactor Simulation.

Work Package: W158 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1190..%R1197, %M277..%M279).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Non-catalytic thermal hydrodealkylation kinetics (r1 ~ k1 * [C7H8] * [H2]^0.5) and biphenyl equilibrium.
4. Section 4: Reaction thermodynamics, exothermic heats (-42 kJ/mol, -8 kJ/mol), and first-law enthalpy balances.
5. Section 5: Interbed cold hydrogen quench gas injection and quench mixing dynamics.
6. Section 6: Coupled 6-state ODE RK4 numerical integration and dual stoichiometric conservation residuals (< 1e-10).
7. Section 7: Process safety interlocks (0xB701, 0xB702, 0xB703, 0xB704) and Horner coil assertions (%M277, %M278, %M279).
8. Section 8: Horner OCS register space synchronization (%R1190..%R1197, %M277..%M279) and benzene selectivity metrics.
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
from jev_cscape.simulation.hda_reactor import (
    DELTA_H_BIPHENYL_J_MOL,
    DELTA_H_HDA_J_MOL,
    DELTA_H_PRIMARY_J_MOL,
    DELTA_H_SECONDARY_J_MOL,
    HDA_PURE_ST_POU,
    HDA_REACTOR_PURE_ST_POU,
    HDA_REACTOR_SYNC_POU,
    HDA_SYNC_POU,
    HdaConfig,
    HdaDiagCode,
    HdaDiagnosticCode,
    HdaReactorConfig,
    HdaReactorDiagnosticCode,
    HdaReactorEngine,
    HdaReactorModel,
    HdaReactorParameters,
    HdaReactorPlantModel,
    HdaReactorSimulationEngine,
    HdaReactorSimulator,
    HdaReactorState,
    HdaReactorStatusBits,
    HdaReactorStatusWord,
    HdaSimulator,
    HdaState,
    HdaStatusBits,
    MW_BENZENE,
    MW_BIPHENYL,
    MW_METHANE,
    MW_TOLUENE,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    TOLUENE_HDA_PURE_ST_POU,
    TOLUENE_HDA_SYNC_POU,
    TOLUENE_HYDRODEALKYLATION_PURE_ST_POU,
    TOLUENE_HYDRODEALKYLATION_SYNC_POU,
    TolueneHdaConfig,
    TolueneHdaDiagnosticCode,
    TolueneHdaSimulator,
    TolueneHdaState,
    TolueneHydrodealkylationConfig,
    TolueneHydrodealkylationDiagnosticCode,
    TolueneHydrodealkylationSimulator,
    TolueneHydrodealkylationState,
    run_hda_reactor_verification,
    run_hda_verification,
    run_toluene_hda_verification,
    run_toluene_hydrodealkylation_verification,
    verify_hda_pure_st,
    verify_hda_reactor_pure_st,
    verify_toluene_hda_pure_st,
    verify_toluene_hydrodealkylation_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1190..%R1197, %M277..%M279)."""

    def test_verify_hda_reactor_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_hda_reactor_pure_st() is True
        assert verify_hda_pure_st() is True
        assert verify_toluene_hydrodealkylation_pure_st() is True
        assert verify_toluene_hda_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1190..%R1197, %M277..%M279)."""
        SecurityGuard.assert_pure_st_content(HDA_REACTOR_PURE_ST_POU)
        val = STParser.validate_code(HDA_REACTOR_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(HDA_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "HdaReactorSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1190", "%R1191", "%R1192", "%R1193",
            "%R1194", "%R1195", "%R1196", "%R1197",
            "%M277", "%M278", "%M279",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from HdaReactorSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate TolueneHydrodealkylationSync alias POU AST."""
        ast_alias = STParser.parse_pou(TOLUENE_HYDRODEALKYLATION_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "TolueneHydrodealkylationSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1190", "%R1191", "%R1192", "%R1193",
            "%R1194", "%R1195", "%R1196", "%R1197",
            "%M277", "%M278", "%M279",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers, f"Register {reg} missing from TolueneHydrodealkylationSync AST bindings"


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
            "XIC HdaReactorPermissive",
            "XIO ThermalRunawayQuenchTrip",
            "OTE QuenchValveActive",
            "OTL EmergencyQuenchTrip",
            "OTU QuenchActive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 1: Enforce pure ST by aggressively rejecting ladder constructs."""
        bad_code = f"""
        PROGRAM BadHdaLadder
        VAR
            Permissive AT %M277 : BOOL;
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
# 3. Section 3: Non-Catalytic Thermal Kinetics & Arrhenius Monotonicity
# ============================================================================

class TestSection3ReactionKineticsAndThermodynamics:
    """Tests for primary non-catalytic HDA kinetics (r1 ~ k1 * [C7H8] * [H2]^0.5) and secondary biphenyl equilibrium."""

    def test_arrhenius_monotonicity_and_ea_recovery(self) -> None:
        """Requirement 2: Verify Arrhenius rate constant increases with temperature and recovers Ea."""
        sim = HdaReactorSimulator()
        k_600 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, 600.0 + T_ZERO_CELSIUS)
        k_630 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, 630.0 + T_ZERO_CELSIUS)
        k_660 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, 660.0 + T_ZERO_CELSIUS)

        assert k_660 > k_630 > k_600 > 0.0

        t1 = 600.0 + T_ZERO_CELSIUS
        t2 = 660.0 + T_ZERO_CELSIUS
        ea_recovered = -R_GAS_CONST * math.log(k_660 / k_600) / ((1.0 / t2) - (1.0 / t1))
        assert abs(ea_recovered - sim.config.activation_e1_j_mol) < 1.0e-5

    def test_half_order_hydrogen_dependence(self) -> None:
        """Requirement 2: Verify primary HDA rate is half-order in hydrogen: r1 ~ [H2]^0.5."""
        sim = HdaReactorSimulator()
        kin_low = sim.compute_kinetics(630.0 + T_ZERO_CELSIUS, 35.0, 0.10, 0.10, 0.10, 0.002, y_h2=0.40)
        kin_high = sim.compute_kinetics(630.0 + T_ZERO_CELSIUS, 35.0, 0.10, 0.10, 0.10, 0.002, y_h2=0.80)

        rate_ratio = kin_high["r1_mol_m3_s"] / kin_low["r1_mol_m3_s"]
        expected_ratio = math.sqrt(0.80 / 0.40)  # sqrt(2) ~ 1.41421356
        assert abs(rate_ratio - expected_ratio) < 1.0e-5

    def test_secondary_biphenyl_equilibrium(self) -> None:
        """Requirement 2: Verify reversible biphenyl equilibrium 2 C6H6 <-> C12H10 + H2."""
        sim = HdaReactorSimulator()
        keq = sim.compute_biphenyl_equilibrium_constant(640.0 + T_ZERO_CELSIUS)
        assert keq > 0.0

        kin = sim.compute_kinetics(640.0 + T_ZERO_CELSIUS, 35.0, 0.10, 0.10, 0.10, 0.002, y_h2=0.70)
        assert kin["k2_f"] > 0.0
        assert kin["k2_r"] > 0.0
        assert kin["q_rxn2_kw"] > 0.0


# ============================================================================
# 4. Section 4: Reaction Thermodynamics & Enthalpies
# ============================================================================

class TestSection4ReactionThermodynamicsAndEnthalpies:
    """Tests for reaction enthalpies (-42 kJ/mol, -8 kJ/mol) and first-law enthalpy balances."""

    def test_exothermic_enthalpies_values(self) -> None:
        """Requirement 2: Verify exact specified reaction enthalpies."""
        assert DELTA_H_PRIMARY_J_MOL == -42000.0  # -42 kJ/mol
        assert DELTA_H_SECONDARY_J_MOL == -8000.0 # -8 kJ/mol
        assert DELTA_H_HDA_J_MOL == -42000.0
        assert DELTA_H_BIPHENYL_J_MOL == -8000.0

    def test_heat_release_positive_and_temperature_rise(self) -> None:
        """Requirement 2 & 3: Verify positive exothermic heat generation and heating rate."""
        sim = HdaReactorSimulator()
        kin = sim.compute_kinetics(640.0 + T_ZERO_CELSIUS, 35.0, 0.10, 0.10, 0.10, 0.002, y_h2=0.698)
        assert kin["q_rxn1_kw"] > 1000.0
        assert kin["q_rxn2_kw"] > 0.0
        assert kin["q_total_rxn_kw"] > 1000.0

        derivs = sim.compute_derivatives(0.0, [600.0, 35.0, 0.1667, 0.001, 0.001, 0.0001])
        dt_react_dt = derivs[0]
        assert dt_react_dt > 0.0


# ============================================================================
# 5. Section 5: Cold Hydrogen Quench Gas Mixing Dynamics
# ============================================================================

class TestSection5ColdHydrogenQuenchMixing:
    """Tests for interbed cold hydrogen quench gas injection and quench mixing dynamics."""

    def test_quench_mixing_temperatures_and_cooling(self) -> None:
        """Requirement 2: Verify cold hydrogen quench mixing lowers gas temperature."""
        sim = HdaReactorSimulator()
        t_hotspot = 655.0

        t_mix_0 = sim.compute_interbed_quench_mixing(t_hotspot_c=t_hotspot, m_quench_kg_s=0.0)
        t_mix_45 = sim.compute_interbed_quench_mixing(t_hotspot_c=t_hotspot, m_quench_kg_s=4.5)
        t_mix_10 = sim.compute_interbed_quench_mixing(t_hotspot_c=t_hotspot, m_quench_kg_s=10.0)

        assert abs(t_mix_0 - t_hotspot) < 1.0e-6
        assert t_mix_45 < t_mix_0
        assert t_mix_10 < t_mix_45

        delta_t_45 = t_hotspot - t_mix_45
        assert 10.0 <= delta_t_45 <= 35.0

    def test_quench_flow_scaling(self) -> None:
        """Requirement 2: Verify multi-stage quench helper returns consistent powers."""
        sim = HdaReactorSimulator()
        res = sim.compute_quench_mixing(t_stage1_c=655.0, m_quench_kg_s=4.5)
        assert res["quench_cooling_power_kw"] > 0.0
        assert res["delta_t_cooling_c"] > 10.0


# ============================================================================
# 6. Section 6: Coupled 6-State ODE RK4 Integration & Conservation Residuals
# ============================================================================

class TestSection6ODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual stoichiometric conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states(self) -> None:
        """Requirement 3: Verify 200 RK4 integration steps remain stable and bounded."""
        sim = HdaReactorSimulator()
        for _ in range(200):
            res = sim.step(dt=0.01)
            assert res.status == AgentStatus.SUCCESS

        assert 600.0 <= sim.state.t_react_c <= 675.0
        assert 30.0 <= sim.state.p_hda_bar <= 40.0
        assert 0.01 <= sim.state.y_toluene <= 0.40
        assert 0.05 <= sim.state.y_benzene <= 0.60
        assert 0.05 <= sim.state.y_methane <= 0.60
        assert 0.0001 <= sim.state.y_biphenyl <= 0.05
        assert not math.isnan(sim.state.t_react_c)
        assert not math.isnan(sim.state.y_benzene)

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 3: Verify dual stoichiometric mass and enthalpy residuals < 1e-10."""
        sim = HdaReactorSimulator()
        sim.advance_time(duration_s=2.0, dt=0.01)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.carbon_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.hydrogen_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# 7. Section 7: Process Safety Interlocks & Diagnostics
# ============================================================================

class TestSection7ProcessSafetyInterlocks:
    """Tests for safety trips (0xB701..0xB704) and priority hierarchy."""

    def test_trip_0xb701_thermal_runaway_temp(self) -> None:
        """Requirement 4: Verify 0xB701 trip on reactor temp > 680 °C."""
        reg = RegisterTable()
        sim = HdaReactorSimulator(register_table=reg)

        sim.state.t_react_c = 685.0
        sim.state.t_hotspot_c = 685.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1197") & 0xFFFF == 0xB701
        assert reg.read_bit("%M278") is True
        assert reg.read_bit("%M277") is False
        assert reg.read_bit("%M279") is True

    def test_trip_0xb701_thermal_runaway_rate(self) -> None:
        """Requirement 4: Verify 0xB701 trip on heating rate dT/dt > 5.0 °C/min."""
        reg = RegisterTable()
        sim = HdaReactorSimulator(register_table=reg)

        sim.state.t_hotspot_c = 655.0
        sim.state.t_react_c = 650.0
        sim.state.dt_react_dt_c_min = 6.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1197") & 0xFFFF == 0xB701
        assert reg.read_bit("%M278") is True
        assert reg.read_bit("%M277") is False

    def test_fault_0xb703_overpressure(self) -> None:
        """Requirement 4: Verify 0xB703 on operating pressure > 42.0 bar."""
        reg = RegisterTable()
        sim = HdaReactorSimulator(register_table=reg)

        sim.state.p_hda_bar = 44.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1197") & 0xFFFF == 0xB703
        assert reg.read_bit("%M277") is False

    def test_fault_0xb702_low_h2_aromatics_ratio(self) -> None:
        """Requirement 4: Verify 0xB702 on H2/aromatics ratio < 4.0."""
        reg = RegisterTable()
        sim = HdaReactorSimulator(register_table=reg)

        sim.state.h2_aromatics_ratio = 3.2
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1197") & 0xFFFF == 0xB702

    def test_alarm_0xb704_selectivity_collapse(self) -> None:
        """Requirement 4: Verify 0xB704 on benzene selectivity < 92.0%."""
        reg = RegisterTable()
        sim = HdaReactorSimulator(register_table=reg)

        sim.state.benzene_selectivity_pct = 89.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1197") & 0xFFFF == 0xB704

    def test_priority_hierarchy(self) -> None:
        """Requirement 4: Verify 0xB701 thermal runaway dominates all other faults."""
        reg = RegisterTable()
        sim = HdaReactorSimulator(register_table=reg)

        sim.state.t_hotspot_c = 690.0
        sim.state.p_hda_bar = 45.0
        sim.state.h2_aromatics_ratio = 3.0
        sim.state.benzene_selectivity_pct = 85.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1197") & 0xFFFF == 0xB701


# ============================================================================
# 8. Section 8: Horner OCS Register Space Integration
# ============================================================================

class TestSection8HornerRegistersAndMetrics:
    """Tests for Horner OCS memory map (%R1190..%R1197, %M277..%M279) and scaling."""

    def test_horner_registers_synchronization(self) -> None:
        """Requirement 5: Verify exact register addresses and scaled INT16 representations."""
        reg = RegisterTable()
        sim = HdaReactorSimulator(register_table=reg)

        sim.state.t_inlet_c = 600.0
        sim.state.t_hotspot_c = 655.0
        sim.state.p_hda_bar = 35.0
        sim.state.h2_aromatics_ratio = 5.0
        sim.state.toluene_conversion_pct = 75.0
        sim.state.benzene_selectivity_pct = 96.0
        sim.state.quench_hydrogen_flow_rate_kg_s = 4.5
        sim.state.dt_react_dt_c_min = 0.0
        sim._sync_registers()

        assert reg.read_word("%R1190") == 6000
        assert reg.read_word("%R1191") == 6550
        assert reg.read_word("%R1192") == 350
        assert reg.read_word("%R1193") == 50
        assert reg.read_word("%R1194") == 750
        assert reg.read_word("%R1195") == 960
        assert reg.read_word("%R1196") == 45
        assert reg.read_word("%R1197") & 0xFFFF == 0x0000

        assert reg.read_bit("%M277") is True
        assert reg.read_bit("%M278") is False
        assert reg.read_bit("%M279") is True


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration
# ============================================================================

class TestSection9VerificationSuite:
    """Tests for deterministic 9-stage verification suite returning strict 4-state contract JSON."""

    def test_run_hda_reactor_verification(self, tmp_path: Path) -> None:
        """Requirement 6: Verify 9-stage verification suite passes and writes valid JSON evidence."""
        out_file = tmp_path / "hda_reactor_evidence.json"
        res = run_hda_reactor_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["tests"]) == 9
        assert all(t["passed"] for t in res["data"]["tests"])

        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            evidence = json.load(f)
        assert evidence["status"] == "success"
        assert evidence["data"]["work_package"] == "W158"
        assert evidence["data"]["gate"] == "Gate G7 / G4"

    def test_verification_suite_aliases(self) -> None:
        """Requirement 6: Verify alias functions execute cleanly."""
        res = run_hda_verification()
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9

        res2 = run_toluene_hydrodealkylation_verification()
        assert res2["status"] == "success"
        assert res2["data"]["checks_passed"] == 9
