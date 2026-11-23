"""Unit and Integration Tests for Industrial Hydrotreating Fixed-Bed Naphtha Hydrodesulfurization (HDS) Simulation.

Work Package: W155 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1160..%R1167, %M270..%M272).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Langmuir-Hinshelwood HDS multi-reaction kinetics, Arrhenius monotonicity, and H2S competitive inhibition.
4. Section 4: Exothermic heat of desulfurization (-65 kJ/mol H2) and olefin saturation (-125 kJ/mol H2).
5. Section 5: Fixed-bed hydrodynamics, Ergun pressure drop Delta P scaling (~650 mbar nominal).
6. Section 6: Coupled 6-state ODE RK4 numerical integration and dual stoichiometric conservation residuals (< 1e-10).
7. Section 7: Process safety interlocks (0xB401, 0xB402, 0xB403, 0xB404) and Horner coil assertions (%M270, %M271, %M272).
8. Section 8: Horner OCS register space synchronization (%R1160..%R1167, %M270..%M272) and ULSN output (< 1.0 ppm S).
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
from jev_cscape.simulation.naphtha_hds import (
    DELTA_H_DESULFURIZATION_J_MOL_H2,
    DELTA_H_HDS_J_MOL,
    DELTA_H_HDS_J_MOL_H2,
    DELTA_H_OLEFIN_J_MOL,
    DELTA_H_OLEFIN_J_MOL_H2,
    DELTA_H_OLEFIN_SATURATION_J_MOL_H2,
    HDS_PURE_ST_POU,
    HDS_SYNC_POU,
    HYDROTREATER_PURE_ST_POU,
    HYDROTREATER_REACTOR_PURE_ST_POU,
    HYDROTREATER_SYNC_POU,
    HdsConfig,
    HdsDiagCode,
    HdsDiagnosticCode,
    HdsSimulator,
    HdsState,
    HdsStatusBits,
    HydrotreaterConfig,
    HydrotreaterDiagnosticCode,
    HydrotreaterEngine,
    HydrotreaterParameters,
    HydrotreaterSimulator,
    HydrotreaterState,
    HydrotreaterStatusBits,
    HydrotreaterStatusWord,
    MW_H2,
    MW_H2S,
    MW_MERC,
    MW_MERCAPTAN,
    MW_NAPHTHA_MEAN,
    MW_OLEFIN_MEAN,
    MW_SULFUR,
    MW_TH,
    MW_THIOPHENE,
    NAPHTHA_HDS_PURE_ST_POU,
    NAPHTHA_HDS_SYNC_POU,
    NaphthaHdsConfig,
    NaphthaHdsDiagnosticCode,
    NaphthaHdsEngine,
    NaphthaHdsParameters,
    NaphthaHdsSimulationEngine,
    NaphthaHdsSimulator,
    NaphthaHdsState,
    NaphthaHdsStatusBits,
    NaphthaHdsStatusWord,
    NaphthaHydrotreaterConfig,
    NaphthaHydrotreaterDiagnosticCode,
    NaphthaHydrotreaterSimulator,
    NaphthaHydrotreaterState,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    run_hds_verification,
    run_hydrotreater_verification,
    run_naphtha_hds_verification,
    run_naphtha_hydrotreater_verification,
    verify_hds_pure_st,
    verify_hydrotreater_pure_st,
    verify_naphtha_hds_pure_st,
    verify_naphtha_hydrotreater_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1160..%R1167, %M270..%M272)."""

    def test_verify_naphtha_hds_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_naphtha_hds_pure_st() is True
        assert verify_hydrotreater_pure_st() is True
        assert verify_hds_pure_st() is True
        assert verify_naphtha_hydrotreater_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1160..%R1167, %M270..%M272)."""
        SecurityGuard.assert_pure_st_content(NAPHTHA_HDS_PURE_ST_POU)
        val = STParser.validate_code(NAPHTHA_HDS_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(NAPHTHA_HDS_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "NaphthaHdsSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1160", "%R1161", "%R1162", "%R1163",
            "%R1164", "%R1165", "%R1166", "%R1167",
            "%M270", "%M271", "%M272",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Verify HydrotreaterReactorSync aliases parse cleanly."""
        for pou_text in [
            HYDROTREATER_REACTOR_PURE_ST_POU,
            HYDROTREATER_PURE_ST_POU,
            HYDROTREATER_SYNC_POU,
            NAPHTHA_HDS_SYNC_POU,
            HDS_PURE_ST_POU,
            HDS_SYNC_POU,
        ]:
            SecurityGuard.assert_pure_st_content(pou_text)
            ast = STParser.parse_pou(pou_text)
            assert ast is not None
            assert ast.pou_type == POUType.PROGRAM
            for reg in [
                "%R1160", "%R1161", "%R1162", "%R1163",
                "%R1164", "%R1165", "%R1166", "%R1167",
                "%M270", "%M271", "%M272",
            ]:
                assert reg in ast.bound_registers


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests for interception and rejection of ladder logic constructs with ERR_LADDER_FORBIDDEN."""

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
            "XIC HydrotreaterPermissive",
            "XIO ExothermicThermalRunawayTrip",
            "OTE RecycleCompressorValveActive",
            "OTL FeedPumpRunning",
            "OTU EmergencyDepressurizationActive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: All ladder constructs must trigger LadderForbiddenError."""
        invalid_st = f"""
        PROGRAM BadLadderNaphthaHds
        VAR
            TestVar : BOOL;
        END_VAR
        {ladder_snippet}
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(invalid_st)


# ============================================================================
# 3. Section 3: Langmuir-Hinshelwood Reaction Kinetics & H2S Inhibition
# ============================================================================

class TestSection3LangmuirHinshelwoodKinetics:
    """Tests for Langmuir-Hinshelwood multi-reaction kinetics, Arrhenius monotonicity, and H2S inhibition."""

    def test_arrhenius_monotonicity_and_ea_recovery(self) -> None:
        """Requirement 3: Verify Arrhenius rate constants increase monotonically and Ea is recovered."""
        sim = NaphthaHdsSimulator()
        temps_c = [320.0, 330.0, 340.0, 350.0, 360.0]
        k_vals = [
            sim.arrhenius_rate_constant(sim.config.arrhenius_a_thiophene, sim.config.activation_e_thiophene_j_mol, tc + T_ZERO_CELSIUS)
            for tc in temps_c
        ]

        # Monotonicity
        for i in range(len(k_vals) - 1):
            assert k_vals[i + 1] > k_vals[i] > 0.0

        # Ea recovery
        t1 = temps_c[0] + T_ZERO_CELSIUS
        t2 = temps_c[-1] + T_ZERO_CELSIUS
        k1 = k_vals[0]
        k2 = k_vals[-1]
        ea_recovered = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2) - (1.0 / t1))
        assert abs(ea_recovered - sim.config.activation_e_thiophene_j_mol) < 1e-6

    def test_h2s_competitive_inhibition(self) -> None:
        """Requirement 3: High H2S concentration competitively inhibits HDS reaction rate."""
        sim = NaphthaHdsSimulator()
        tb_k = 340.0 + T_ZERO_CELSIUS
        kin_low_h2s = sim.compute_kinetics(tb_k, 45.0, 450.0, 150.0, c_h2s_gas_mol_pct=0.1)
        kin_high_h2s = sim.compute_kinetics(tb_k, 45.0, 450.0, 150.0, c_h2s_gas_mol_pct=4.0)

        # Rate must decrease as H2S competitive inhibition increases
        assert kin_low_h2s["r_thiophene_s_inv"] > kin_high_h2s["r_thiophene_s_inv"]
        assert kin_low_h2s["r_mercaptan_s_inv"] > kin_high_h2s["r_mercaptan_s_inv"]

    def test_mercaptan_reactivity_vs_thiophene(self) -> None:
        """Requirement 3: Aliphatic mercaptans react significantly faster than thiophenes."""
        sim = NaphthaHdsSimulator()
        kin = sim.compute_kinetics(340.0 + T_ZERO_CELSIUS, 45.0, 450.0, 150.0)
        assert kin["r_mercaptan_s_inv"] > kin["r_thiophene_s_inv"]


# ============================================================================
# 4. Section 4: Exothermic Reaction Enthalpies & Energy Balances
# ============================================================================

class TestSection4ReactionThermodynamicsAndEnthalpies:
    """Tests for exothermic reaction enthalpies (-65 kJ/mol H2 for HDS, -125 kJ/mol H2 for olefins)."""

    def test_exothermic_enthalpies_values(self) -> None:
        """Requirement 4: Verify specified reaction enthalpy constants."""
        assert DELTA_H_DESULFURIZATION_J_MOL_H2 == -65000.0
        assert DELTA_H_HDS_J_MOL_H2 == -65000.0
        assert DELTA_H_OLEFIN_SATURATION_J_MOL_H2 == -125000.0
        assert DELTA_H_OLEFIN_J_MOL_H2 == -125000.0

    def test_heat_release_positive_and_temperature_rise(self) -> None:
        """Requirement 4: Reaction exotherm releases positive thermal power and increases bed heating."""
        sim = NaphthaHdsSimulator()
        kin = sim.compute_kinetics(355.0 + T_ZERO_CELSIUS, 45.0, 450.0, 150.0)
        assert kin["q_hds_kw"] > 0.0
        assert kin["q_ole_kw"] > 0.0
        assert kin["q_total_kw"] > 0.0

        # Heating rate at isothermal condition (T_inlet = T_bed)
        derivs = sim.compute_derivatives(0.0, [340.0, 340.0, 45.0, 450.0, 150.0, 650.0])
        dt_bed_dt = derivs[1]
        assert dt_bed_dt > 0.0  # Reaction drives temperature rise


# ============================================================================
# 5. Section 5: Fixed-Bed Hydrodynamics & Ergun Pressure Drop
# ============================================================================

class TestSection5FixedBedHydrodynamics:
    """Tests for fixed-bed hydrodynamics, superficial velocities, and Ergun Delta P."""

    def test_nominal_differential_pressure(self) -> None:
        """Requirement 5: Bed differential pressure is nominal 650 mbar at design conditions."""
        sim = NaphthaHdsSimulator()
        hydro = sim.compute_hydrodynamics(355.0 + T_ZERO_CELSIUS, 45.0)
        assert abs(hydro["dp_bed_mbar"] - 650.0) < 1.0
        assert abs(hydro["dp_bed_bar"] - 0.65) < 0.01

    def test_flow_rate_scaling(self) -> None:
        """Requirement 5: Higher naphtha flow rate increases differential pressure."""
        sim = NaphthaHdsSimulator()
        hydro_nom = sim.compute_hydrodynamics(355.0 + T_ZERO_CELSIUS, 45.0, naphtha_flow_kg_s=45.0)
        hydro_high = sim.compute_hydrodynamics(355.0 + T_ZERO_CELSIUS, 45.0, naphtha_flow_kg_s=60.0)
        assert hydro_high["dp_bed_mbar"] > hydro_nom["dp_bed_mbar"]
        assert hydro_nom["u_liq_m_s"] > 0.0
        assert hydro_nom["u_gas_m_s"] > 0.0


# ============================================================================
# 6. Section 6: Coupled 6-State ODE RK4 Integration & Dual Conservation
# ============================================================================

class TestSection6ODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 solver and dual conservation residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states(self) -> None:
        """Requirement 6: Advance ODE system by multiple RK4 steps without numerical instability."""
        sim = NaphthaHdsSimulator()
        for _ in range(100):
            res = sim.step(dt=0.01)
            assert res.status == AgentStatus.SUCCESS

        assert 320.0 <= sim.state.t_bed_c <= 375.0
        assert 300.0 <= sim.state.t_inlet_c <= 360.0
        assert 30.0 <= sim.state.p_hds_bar <= 60.0
        assert not math.isnan(sim.state.t_bed_c)
        assert not math.isinf(sim.state.t_bed_c)

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 6: Total mass and first-law enthalpy residuals must be strictly < 1e-10."""
        sim = NaphthaHdsSimulator()
        sim.step(dt=0.05)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# 7. Section 7: Process Safety Interlocks & Diagnostics (0xB401..0xB404)
# ============================================================================

class TestSection7ProcessSafetyInterlocks:
    """Tests for process safety trips (0xB401, 0xB402, 0xB403, 0xB404) and Horner coils."""

    def test_trip_0xb401_thermal_runaway(self) -> None:
        """Requirement 7: T_bed > 375 °C trips 0xB401, asserts %M271, clears %M270."""
        reg = RegisterTable()
        sim = NaphthaHdsSimulator(register_table=reg)

        # Healthy operation
        sim.state.t_bed_c = 355.0
        sim.step(0.01)
        assert reg.read_bit("%M271") is False
        assert reg.read_bit("%M270") is True
        assert reg.read_word("%R1167") == 0x0000

        # Thermal runaway condition
        sim.state.t_bed_c = 378.0
        sim.step(0.01)
        assert reg.read_bit("%M271") is True
        assert reg.read_bit("%M270") is False
        assert reg.read_word("%R1167") & 0xFFFF == 0xB401

    def test_fault_0xb402_low_h2_ratio(self) -> None:
        """Requirement 7: H2/oil < 150 Nm3/m3 sets 0xB402."""
        reg = RegisterTable()
        sim = NaphthaHdsSimulator(register_table=reg)
        sim.state.h2_oil_ratio_nm3_m3 = 130.0
        sim.step(0.01)
        assert reg.read_word("%R1167") & 0xFFFF == 0xB402

    def test_trip_0xb403_bed_high_dp(self) -> None:
        """Requirement 7: Bed Delta P > 1.8 bar (1800 mbar) sets 0xB403."""
        reg = RegisterTable()
        sim = NaphthaHdsSimulator(register_table=reg)
        sim.state.delta_p_bed_mbar = 1950.0
        sim.step(0.01)
        assert reg.read_word("%R1167") & 0xFFFF == 0xB403

    def test_alarm_0xb404_offspec_sulfur(self) -> None:
        """Requirement 7: Product sulfur > 10.0 ppm sets 0xB404."""
        reg = RegisterTable()
        sim = NaphthaHdsSimulator(register_table=reg)
        sim.state.c_thiophene_ppm = 9.0
        sim.state.c_mercaptan_ppm = 2.5
        sim.step(0.01)
        assert reg.read_word("%R1167") & 0xFFFF == 0xB404


# ============================================================================
# 8. Section 8: Horner OCS Registers & Ultra-Low Sulfur Output
# ============================================================================

class TestSection8HornerRegistersAndULSNOutput:
    """Tests for Horner OCS memory space scaling and ULSN compliance (< 1.0 ppm S)."""

    def test_ulsn_product_compliance(self) -> None:
        """Requirement 8: Normal operating product sulfur is < 1.0 ppm S (ULSN specification)."""
        sim = NaphthaHdsSimulator()
        sim.advance_time(duration_s=2.0, dt=0.01)
        assert sim.state.product_sulfur_ppm < 1.0
        assert sim.state.sulfur_removal_conversion_pct > 99.0

    def test_horner_registers_synchronization(self) -> None:
        """Requirement 8: Verify exact scaled values in %R1160..%R1167 and %M270..%M272."""
        reg = RegisterTable()
        sim = NaphthaHdsSimulator(register_table=reg)
        sim.state.t_inlet_c = 330.0
        sim.state.t_bed_c = 355.0
        sim.state.p_hds_bar = 45.0
        sim.state.h2_oil_ratio_nm3_m3 = 250.0
        sim.state.sulfur_removal_conversion_pct = 98.5
        sim.state.c_thiophene_ppm = 0.40
        sim.state.c_mercaptan_ppm = 0.10
        sim.state.product_sulfur_ppm = 0.50
        sim.state.delta_p_bed_mbar = 650.0
        sim._sync_registers()

        assert reg.read_word("%R1160") == 3300  # 330.0 °C x10
        assert reg.read_word("%R1161") == 3550  # 355.0 °C x10
        assert reg.read_word("%R1162") == 450   # 45.0 bar x10
        assert reg.read_word("%R1163") == 250   # 250 Nm3/m3
        assert reg.read_word("%R1164") == 985   # 98.5 % x10
        assert reg.read_word("%R1165") == 5     # 0.5 ppm x10
        assert reg.read_word("%R1166") == 650   # 650 mbar
        assert reg.read_word("%R1167") == 0     # 0x0000 OK
        assert reg.read_bit("%M270") is True
        assert reg.read_bit("%M271") is False
        assert reg.read_bit("%M272") is True


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection9VerificationSuite:
    """Integration test executing the 9-stage verification suite and confirming evidence emission."""

    def test_run_naphtha_hds_verification(self, tmp_path: Path) -> None:
        """Requirement 9: Execute full 9-stage suite, verify SUCCESS status and JSON emission."""
        evidence_file = tmp_path / "naphtha_hds_test_evidence.json"
        res = run_naphtha_hds_verification(output_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["tests"]) == 9
        for test in res["data"]["tests"]:
            assert test["passed"] is True, f"Stage {test['stage']} ({test['check']}) must pass"

        assert evidence_file.exists()
        loaded = json.loads(evidence_file.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
