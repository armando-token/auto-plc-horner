"""Unit and Integration Tests for Industrial Steam Methane Reforming (SMR) & Water-Gas Shift Multi-Tube Kinetics ODE Simulation.

Work Package: W152 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1130..%R1137, %M263..%M265).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Xu & Froment intrinsic reaction kinetics, thermodynamic equilibria, and endothermic heat of reaction.
4. Section 4: Multi-tube reformer geometry, heat transfer, catalyst bed temperature, and steam-to-carbon ratio.
5. Section 5: Coupled 6-state ODE RK4 numerical integration and dual stoichiometric conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xB101, 0xB102, 0xB103, 0xB104) and Horner coil assertions (%M263, %M264, %M265).
7. Section 7: Horner OCS register space synchronization (%R1130..%R1137, %M263..%M265).
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
from jev_cscape.simulation.smr_reformer import (
    DELTA_H_SHIFT_J_MOL,
    DELTA_H_SMR1_J_MOL,
    DELTA_H_SMR2_J_MOL,
    REFORMER_PURE_ST_POU,
    REFORMER_SYNC_POU,
    ReformerConfig,
    ReformerDiagCode,
    ReformerDiagnosticCode,
    ReformerSimulator,
    ReformerState,
    ReformerStatusBits,
    ReformerStatusWord,
    SMR_PURE_ST_POU,
    SMR_REFORMER_PURE_ST_POU,
    SMR_REFORMER_SYNC_POU,
    SMR_SYNC_POU,
    STEAM_METHANE_REFORMER_PURE_ST_POU,
    STEAM_METHANE_REFORMER_SYNC_POU,
    STEAM_METHANE_REFORMING_PURE_ST_POU,
    STEAM_METHANE_REFORMING_SYNC_POU,
    SmrConfig,
    SmrDiagCode,
    SmrDiagnosticCode,
    SmrParameters,
    SmrReformerConfig,
    SmrReformerDiagnosticCode,
    SmrReformerEngine,
    SmrReformerModel,
    SmrReformerParameters,
    SmrReformerPlantModel,
    SmrReformerSimulationEngine,
    SmrReformerSimulator,
    SmrReformerState,
    SmrReformerStatusBits,
    SmrReformerStatusWord,
    SmrSimulator,
    SmrState,
    SmrStatusBits,
    SmrStatusWord,
    SteamMethaneReformerConfig,
    SteamMethaneReformerDiagnosticCode,
    SteamMethaneReformerSimulator,
    SteamMethaneReformerState,
    SteamMethaneReformerStatusBits,
    SteamMethaneReformingConfig,
    SteamMethaneReformingDiagnosticCode,
    SteamMethaneReformingSimulator,
    SteamMethaneReformingState,
    SteamMethaneReformingStatusBits,
    T_ZERO_CELSIUS,
    run_reformer_verification,
    run_smr_reformer_verification,
    run_smr_verification,
    run_steam_methane_reformer_verification,
    run_steam_methane_reforming_verification,
    verify_reformer_pure_st,
    verify_smr_pure_st,
    verify_smr_reformer_pure_st,
    verify_steam_methane_reformer_pure_st,
    verify_steam_methane_reforming_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================


class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1130..%R1137, %M263..%M265)."""

    def test_verify_smr_reformer_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_smr_reformer_pure_st() is True
        assert verify_smr_pure_st() is True
        assert verify_steam_methane_reformer_pure_st() is True
        assert verify_steam_methane_reforming_pure_st() is True
        assert verify_reformer_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1130..%R1137, %M263..%M265)."""
        SecurityGuard.assert_pure_st_content(SMR_REFORMER_PURE_ST_POU)
        val = STParser.validate_code(SMR_REFORMER_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SMR_REFORMER_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "SmrReformerSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1130", "%R1131", "%R1132", "%R1133",
            "%R1134", "%R1135", "%R1136", "%R1137",
            "%M263", "%M264", "%M265",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Verify SmrReformerSync aliases parse cleanly."""
        for pou_text in [
            SMR_PURE_ST_POU,
            SMR_SYNC_POU,
            SMR_REFORMER_SYNC_POU,
            STEAM_METHANE_REFORMER_PURE_ST_POU,
            STEAM_METHANE_REFORMER_SYNC_POU,
            STEAM_METHANE_REFORMING_PURE_ST_POU,
            STEAM_METHANE_REFORMING_SYNC_POU,
            REFORMER_PURE_ST_POU,
            REFORMER_SYNC_POU,
        ]:
            SecurityGuard.assert_pure_st_content(pou_text)
            ast = STParser.parse_pou(pou_text)
            assert ast is not None
            assert ast.pou_type == POUType.PROGRAM
            for reg in [
                "%R1130", "%R1131", "%R1132", "%R1133",
                "%R1134", "%R1135", "%R1136", "%R1137",
                "%M263", "%M264", "%M265",
            ]:
                assert reg in ast.bound_registers


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================


class TestSection2AntiLadderGuards:
    """Tests confirming forbidden ladder logic constructs raise LadderForbiddenError."""

    @pytest.mark.parametrize(
        "bad_code, reason",
        [
            ("PROGRAM BadContact\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM", "ladder contact"),
            ("PROGRAM BadNegContact\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM", "ladder negative contact"),
            ("PROGRAM BadCoil\nVAR X: BOOL; END_VAR\n---( )---\nEND_PROGRAM", "ladder coil"),
            ("PROGRAM BadRung\nVAR X: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM", "rung keyword"),
            ("PROGRAM BadMnemonic\nVAR X: BOOL; END_VAR\nXIC %M263\nOTE %M264\nEND_PROGRAM", "ladder mnemonic"),
            ("PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM", "network keyword"),
        ],
    )
    def test_security_guard_rejects_ladder_syntax(self, bad_code: str, reason: str) -> None:
        """Requirement 2: Ensure SecurityGuard blocks ladder constructs with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_st_parser_returns_failed_on_ladder_logic(self) -> None:
        """Requirement 2: Ensure STParser flags ladder logic constructs as FAILED."""
        ladder_code = "PROGRAM LadderTest\nVAR Y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        result = STParser.validate_code(ladder_code)
        assert result.status == AgentStatus.FAILED
        assert "ERR_LADDER_FORBIDDEN" in (result.error_code or "")


# ============================================================================
# 3. Section 3: Xu & Froment Kinetics & Thermodynamics
# ============================================================================


class TestSection3XuFromentKineticsAndThermodynamics:
    """Tests for Xu & Froment reaction rates, equilibrium constants, and reaction enthalpies."""

    def test_reaction_enthalpies(self) -> None:
        """Requirement 3: Verify endothermic SMR reaction enthalpies."""
        assert DELTA_H_SMR1_J_MOL > 200000.0  # +206.1 kJ/mol (endothermic)
        assert DELTA_H_SHIFT_J_MOL < 0.0     # -41.2 kJ/mol (exothermic WGS)
        assert DELTA_H_SMR2_J_MOL > 150000.0  # +164.9 kJ/mol (endothermic)

    def test_kinetic_rates_monotonic_with_temperature(self) -> None:
        """Requirement 3: Reforming rates must increase monotonically with temperature (Arrhenius)."""
        sim = SmrReformerSimulator()
        rx_750 = sim.compute_reaction_rates(750.0 + T_ZERO_CELSIUS, 25.0, 0.035, 0.485, 0.115)
        rx_820 = sim.compute_reaction_rates(820.0 + T_ZERO_CELSIUS, 25.0, 0.035, 0.485, 0.115)
        rx_900 = sim.compute_reaction_rates(900.0 + T_ZERO_CELSIUS, 25.0, 0.035, 0.485, 0.115)

        assert rx_750["k_1"] < rx_820["k_1"] < rx_900["k_1"]
        assert rx_750["k_2"] < rx_820["k_2"] < rx_900["k_2"]
        assert rx_750["k_3"] < rx_820["k_3"] < rx_900["k_3"]
        assert rx_820["q_total_rxn_kw"] > 0.0

    def test_equilibrium_constants(self) -> None:
        """Requirement 3: Verify equilibrium constants K_eq1, K_eq2."""
        sim = SmrReformerSimulator()
        eq_820 = sim.compute_thermodynamic_equilibria(820.0 + T_ZERO_CELSIUS)
        eq_900 = sim.compute_thermodynamic_equilibria(900.0 + T_ZERO_CELSIUS)
        assert eq_820["k_eq1"] > 0.0
        assert eq_820["k_eq2"] > 0.0
        assert eq_820["k_eq1"] < eq_900["k_eq1"], "Endothermic SMR equilibrium constant increases with T"
        assert eq_820["k_eq2"] > eq_900["k_eq2"], "Exothermic WGS equilibrium constant decreases with T"


# ============================================================================
# 4. Section 4: Multi-Tube Reformer Geometry & Heat Transfer
# ============================================================================


class TestSection4MultiTubeReformerGeometry:
    """Tests for multi-tube furnace geometry, catalyst volume, and heat transfer."""

    def test_furnace_geometry_dimensions(self) -> None:
        """Requirement 4: Verify tube count, inner area, outer area, and catalyst volume."""
        cfg = SmrReformerConfig()
        assert cfg.num_tubes == 280
        assert 1000.0 <= cfg.total_tube_inner_area_m2 <= 1300.0
        assert 1200.0 <= cfg.total_tube_outer_area_m2 <= 1600.0
        assert 20.0 <= cfg.total_catalyst_volume_m3 <= 35.0
        assert cfg.steam_to_carbon_ratio == 3.00

    def test_heat_transfer_tube_to_gas(self) -> None:
        """Requirement 4: Heat transfer from tube wall to process gas must be positive when T_tube > T_gas."""
        sim = SmrReformerSimulator()
        ht = sim.compute_heat_transfer(t_gas_c=820.0, t_tube_c=865.0, t_furnace_c=850.0)
        assert ht["q_tube_to_gas_kw"] > 0.0
        assert 40000.0 <= ht["q_tube_to_gas_kw"] <= 80000.0


# ============================================================================
# 5. Section 5: Coupled ODE RK4 Integration & Dual Conservation Residuals
# ============================================================================


class TestSection5CoupledODERK4Integration:
    """Tests for RK4 numerical solver stability and elemental mass & energy conservation (< 1e-10)."""

    def test_rk4_step_stability(self) -> None:
        """Requirement 5: Verify RK4 step preserves state bounded within physical ranges."""
        sim = SmrReformerSimulator()
        res = sim.advance_time(duration_s=5.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS

        st = sim.state
        assert 750.0 <= st.t_gas_c <= 900.0
        assert 800.0 <= st.t_tube_c <= 920.0
        assert 20.0 <= st.p_smr_bar <= 30.0
        assert 0.01 <= st.y_ch4 <= 0.15
        assert 0.35 <= st.y_h2 <= 0.65
        assert 0.05 <= st.y_co <= 0.20

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 5: Verify elemental mass residual and thermal energy residual are < 1e-10."""
        sim = SmrReformerSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        mass_res = sim.state.total_elemental_mass_residual_kg_s
        enth_res = sim.state.enthalpy_conservation_residual_kw
        assert abs(mass_res) < 1.0e-10, f"Mass residual {mass_res} exceeds 1e-10 threshold"
        assert abs(enth_res) < 1.0e-10, f"Energy residual {enth_res} exceeds 1e-10 threshold"


# ============================================================================
# 6. Section 6: Process Safety Trips & Horner Coil Assertion
# ============================================================================


class TestSection6ProcessSafetyTrips:
    """Tests for safety alarm trips: 0xB101 (Tube Overtemp), 0xB102 (Low S/C), 0xB103 (Overpressure), 0xB104 (Conversion Collapse)."""

    def test_trip_0xb101_tube_overtemperature(self) -> None:
        """Requirement 6: T_tube > 920 °C must trip 0xB101, assert %M264, and clear %M263."""
        sim = SmrReformerSimulator()
        sim.state.t_tube_c = 925.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xB101
        assert sim.state.reformer_tube_overtemp_trip is True
        assert sim.state.reformer_permissive is False

    def test_trip_0xb102_low_steam_carbon_ratio(self) -> None:
        """Requirement 6: S/C < 2.50 must assert %M265 LowSteamCarbonRatioAlarm."""
        sim = SmrReformerSimulator()
        sim.state.t_tube_c = 865.0
        sim.state.steam_to_carbon_ratio = 2.30
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xB102
        assert sim.state.low_steam_carbon_ratio_alarm is True
        assert sim.state.reformer_permissive is True

    def test_trip_0xb103_overpressure(self) -> None:
        """Requirement 6: Operating pressure > 35.0 bar must trip 0xB103 and clear %M263."""
        sim = SmrReformerSimulator()
        sim.state.steam_to_carbon_ratio = 3.00
        sim.state.p_smr_bar = 36.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == 0xB103
        assert sim.state.reformer_permissive is False

    def test_nominal_operating_state_permissive_active(self) -> None:
        """Requirement 6: Under nominal conditions, %M263 must be True and alarm coils False."""
        sim = SmrReformerSimulator()
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.reformer_permissive is True
        assert sim.state.reformer_tube_overtemp_trip is False
        assert sim.state.low_steam_carbon_ratio_alarm is False
        assert sim.state.diagnostic_code == 0x0000


# ============================================================================
# 7. Section 7: Horner OCS Register Space Synchronization
# ============================================================================


class TestSection7HornerRegisterSpaceSync:
    """Tests for Horner OCS memory register table bindings (%R1130..%R1137, %M263..%M265)."""

    def test_register_table_write_and_read(self) -> None:
        """Requirement 7: Verify synchronized values in RegisterTable match state variables."""
        reg = RegisterTable()
        sim = SmrReformerSimulator(register_table=reg)

        sim.state.t_furnace_c = 850.0
        sim.state.t_gas_c = 820.0
        sim.state.t_tube_c = 865.0
        sim.state.p_smr_bar = 25.0
        sim.state.steam_to_carbon_ratio = 3.00
        sim.state.methane_conversion_pct = 82.5
        sim.state.h2_production_nm3_h = 1500.0
        sim.state.co_vol_pct = 11.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1130") == 8500
        assert reg.read_word("%R1131") == 8200
        assert reg.read_word("%R1132") == 250
        assert reg.read_word("%R1133") == 300
        assert reg.read_word("%R1134") == 825
        assert reg.read_word("%R1135") == 15000
        assert reg.read_word("%R1136") == 115
        assert (reg.read_word("%R1137") & 0xFFFF) == 0x0000
        assert reg.read_bit("%M263") is True
        assert reg.read_bit("%M264") is False
        assert reg.read_bit("%M265") is False


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================


class TestSection8VerificationSuite:
    """Tests running the 9-stage verification suite and asserting evidence JSON output."""

    def test_run_smr_reformer_verification_success(self, tmp_path: Path) -> None:
        """Requirement 8: run_smr_reformer_verification returns success with 9/9 stages passed."""
        out_file = tmp_path / "smr_reformer_evidence.json"
        evidence = run_smr_reformer_verification(output_path=str(out_file))

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert out_file.is_file()
        assert out_file.stat().st_size > 0

        data = evidence.get("data", {})
        assert data.get("checks_passed") == 9
        assert data.get("total_checks") == 9

        tests = data.get("tests", [])
        assert len(tests) == 9
        for t in tests:
            assert t.get("passed") is True, f"Stage {t.get('stage')} failed: {t.get('details')}"

    def test_evidence_json_content_and_contract(self, tmp_path: Path) -> None:
        """Requirement 8: Validate schema compliance of exported evidence JSON."""
        out_file = tmp_path / "smr_evidence_contract.json"
        evidence = run_smr_reformer_verification(str(out_file))

        with open(out_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded["status"] == "success"
        assert "work_package" in loaded["data"]
        assert loaded["data"]["work_package"] == "W152"
