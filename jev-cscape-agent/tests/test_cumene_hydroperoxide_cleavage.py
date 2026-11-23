"""Comprehensive Unit and Integration Test Suite for Wave W251:
Industrial Phenol-Acetone Cumene Hydroperoxide (CHP) Acid-Catalyzed Cleavage Reaction ODE Simulation.

Work Package: W251 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS (100+ Deterministic Assertions across 15 Test Classes)
Status Contract: Strict 4-State JSON output & evidence emission.

Covers 15 Engineering Test Classes:
1.  TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2.  TestCleavagePhysicsAndKinetics: Reaction enthalpies (-252.0 kJ/mol, -120.0 kJ/mol, +45.0 kJ/mol), kinetics, molar masses.
3.  TestRK4NumericalSolver: RK4 state transitions, dt stability, convergence, non-negative concentrations.
4.  TestNominalSteadyStateConvergence: Conversion >= 99.8%, Selectivity >= 99.0%, Temp 68.5 °C, Pressure 1.25 bar, Production ~8950 kg/h.
5.  TestConservationLawsAndThermodynamics: Mass conservation error < 1e-10 kg/s, elemental mass balance, enthalpy conservation < 1e-10 kW.
6.  TestThermalRunawayExotherm0xF401: Temp > 85.0 °C trips 0xF401, asserts %M496 emergency quench trip.
7.  TestChpAccumulationHazard0xF402: Unreacted CHP > 0.8 wt% trips %M495 pre-alarm, severe accumulation trips 0xF402.
8.  TestCatalystAcidityStarvation0xF403: Acid catalyst < 80 ppm trips 0xF403.
9.  TestCoolingHeatRemovalFault0xF404: Cooling jacket heat removal failure trips 0xF404.
10. TestProcessSafetyStrictPriorityHierarchy: Strict priority resolution (0xF401 > 0xF402 > 0xF403 > 0xF404 > 0x0000).
11. TestHornerOCSSynchronizationAndRegisters: %R2120..%R2127, %M494..%M496 bit-exact synchronization, PrivilegeMode.SYSTEM.
12. TestPureSTAndSecurity: STParser & SecurityGuard verification of CumeneCleavageSync POU.
13. TestAntiLadderRejection: Rejection of 6+ ladder constructs with LadderForbiddenError.
14. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
15. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.cumene_hydroperoxide_cleavage import (
    ACETONE_PROD_NOMINAL_KG_H,
    ACID_CATALYST_NOMINAL_PPM,
    ACID_CATALYST_STARVATION_PPM,
    ACID_PRE_ALARM_PPM,
    CHP_ACCUMULATION_TRIP_CONC_MOL_L,
    CHP_CLEAVAGE_PURE_ST_POU,
    CHP_CLEAVAGE_SYNC_POU,
    CHP_CONVERSION_MIN_TRIP_PCT,
    CHP_CONV_NOMINAL_PCT,
    CHP_PRE_ALARM_CONC_MOL_L,
    COIL_EMERGENCY_QUENCH_OPEN,
    COIL_HIGH_CHP_PREALARM,
    COIL_REACTOR_ACTIVE,
    CUMENE_HYDROPEROXIDE_CLEAVAGE_PURE_ST_POU,
    CUMENE_HYDROPEROXIDE_CLEAVAGE_SYNC_POU,
    CumeneHydroperoxideCleavage,
    CumeneHydroperoxideCleavageConfig,
    DiagnosticCode,
    REG_ACID_CATALYST_SCALED,
    REG_CHP_CONVERSION_SCALED,
    REG_DIAGNOSTIC_CODE,
    REG_PHENOL_PROD_RATE_SCALED,
    REG_PHENOL_SELECTIVITY_SCALED,
    REG_REACTOR_PRESSURE_SCALED,
    REG_REACTOR_TEMP_SCALED,
    REG_RESIDUAL_CHP_SCALED,
    run_cumene_hydroperoxide_cleavage_verification,
    verify_cumene_hydroperoxide_cleavage_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate DiagnosticCode signed/unsigned 16-bit representations, hashing, register mappings."""

    def test_diagnostic_code_signed_unsigned_values(self) -> None:
        assert DiagnosticCode.OK == 0x0000
        assert int(DiagnosticCode.OK) == 0

        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION == 0xF401
        assert (DiagnosticCode.THERMAL_RUNAWAY_EXCURSION & 0xFFFF) == 0xF401
        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION == -3071

        assert DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP == 0xF402
        assert (DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP & 0xFFFF) == 0xF402
        assert DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP == -3070

        assert DiagnosticCode.ACID_CATALYST_STARVATION_FAULT == 0xF403
        assert (DiagnosticCode.ACID_CATALYST_STARVATION_FAULT & 0xFFFF) == 0xF403
        assert DiagnosticCode.ACID_CATALYST_STARVATION_FAULT == -3069

        assert DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT == 0xF404
        assert (DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT & 0xFFFF) == 0xF404
        assert DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT == -3068

    def test_diagnostic_code_hashing(self) -> None:
        s = {
            DiagnosticCode.OK,
            DiagnosticCode.THERMAL_RUNAWAY_EXCURSION,
            DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP,
            DiagnosticCode.ACID_CATALYST_STARVATION_FAULT,
            DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT,
        }
        assert len(s) == 5
        assert DiagnosticCode.OK in s
        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION in s

    def test_diagnostic_code_str_representation(self) -> None:
        s_ok = str(DiagnosticCode.OK)
        assert "0x0000" in s_ok or "OK" in s_ok
        s_trip = str(DiagnosticCode.THERMAL_RUNAWAY_EXCURSION)
        assert "F401" in s_trip or "THERMAL" in s_trip

    def test_register_and_coil_addresses(self) -> None:
        assert REG_REACTOR_TEMP_SCALED == "%R2120"
        assert REG_REACTOR_PRESSURE_SCALED == "%R2121"
        assert REG_CHP_CONVERSION_SCALED == "%R2122"
        assert REG_PHENOL_SELECTIVITY_SCALED == "%R2123"
        assert REG_RESIDUAL_CHP_SCALED == "%R2124"
        assert REG_PHENOL_PROD_RATE_SCALED == "%R2125"
        assert REG_ACID_CATALYST_SCALED == "%R2126"
        assert REG_DIAGNOSTIC_CODE == "%R2127"

        assert COIL_REACTOR_ACTIVE == "%M494"
        assert COIL_HIGH_CHP_PREALARM == "%M495"
        assert COIL_EMERGENCY_QUENCH_OPEN == "%M496"

    def test_nominal_operating_constants(self) -> None:
        assert CHP_CONV_NOMINAL_PCT >= 99.8
        assert ACID_CATALYST_NOMINAL_PPM == 250
        assert ACID_CATALYST_STARVATION_PPM < 100
        assert ACID_PRE_ALARM_PPM > ACID_CATALYST_STARVATION_PPM
        assert CHP_PRE_ALARM_CONC_MOL_L < CHP_ACCUMULATION_TRIP_CONC_MOL_L


# ============================================================================
# 2. TestCleavagePhysicsAndKinetics
# ============================================================================

class TestCleavagePhysicsAndKinetics:
    """Validate reaction enthalpies, thermodynamics, and kinetics."""

    def test_reaction_enthalpies(self) -> None:
        from jev_cscape.simulation.cumene_hydroperoxide_cleavage import (
            DELTA_H1_J_MOL,
            DELTA_H2_J_MOL,
            DELTA_H3_J_MOL,
        )
        assert DELTA_H1_J_MOL == -252000.0  # Highly exothermic -252 kJ/mol
        assert DELTA_H2_J_MOL == -120000.0  # Side condensation -120 kJ/mol
        assert DELTA_H3_J_MOL == 45000.0    # Endothermic side decomposition +45 kJ/mol

    def test_molar_masses(self) -> None:
        from jev_cscape.simulation.cumene_hydroperoxide_cleavage import (
            MW_CHP,
            MW_PHENOL,
            MW_ACETONE,
        )
        assert abs(MW_CHP * 1000.0 - 152.19) < 0.1
        assert abs(MW_PHENOL * 1000.0 - 94.11) < 0.1
        assert abs(MW_ACETONE * 1000.0 - 58.08) < 0.1
        # Mass conservation: MW_CHP = MW_PHENOL + MW_ACETONE
        assert abs((MW_CHP - (MW_PHENOL + MW_ACETONE)) * 1000.0) < 0.1

    def test_arrhenius_rate_computation(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        k1 = sim.compute_k1(68.5, 250.0)
        assert k1 > 0.0
        # Rate increases with acid catalyst
        k1_high_acid = sim.compute_k1(68.5, 500.0)
        assert k1_high_acid > k1
        # Rate increases with temperature
        k1_high_temp = sim.compute_k1(75.0, 250.0)
        assert k1_high_temp > k1


# ============================================================================
# 3. TestRK4NumericalSolver
# ============================================================================

class TestRK4NumericalSolver:
    """Validate 4th-Order Runge-Kutta numerical integration stability and bounds."""

    def test_rk4_single_step_advancement(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        t0 = sim.time_s
        sim.scan_step(0.020)
        assert sim.time_s > t0
        assert abs(sim.time_s - (t0 + 0.020)) < 1e-6

    def test_rk4_state_non_negativity(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        for _ in range(50):
            sim.scan_step(0.020)
            assert sim.state.c_chp >= 0.0
            assert sim.state.c_phenol >= 0.0
            assert sim.state.c_acetone >= 0.0
            assert sim.state.t_reactor_c > 0.0
            assert sim.state.p_reactor_bar > 0.0

    def test_rk4_stability_under_varying_dt(self) -> None:
        for dt in [0.005, 0.010, 0.020, 0.040]:
            sim = CumeneHydroperoxideCleavage()
            sim.reset()
            sim.scan_step(dt)
            assert not math.isnan(sim.state.t_reactor_c)
            assert not math.isinf(sim.state.t_reactor_c)
            assert abs(sim.state.t_reactor_c - 68.5) < 2.0


# ============================================================================
# 4. TestNominalSteadyStateConvergence
# ============================================================================

class TestNominalSteadyStateConvergence:
    """Validate nominal steady-state operating point KPIs."""

    def test_nominal_kpis(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        assert sim.state.chp_conversion_pct >= 99.80
        assert sim.state.phenol_selectivity_pct >= 99.00
        assert abs(sim.state.phenol_production_rate_kg_h - 8950.0) < 50.0
        assert abs(sim.state.t_reactor_c - 68.5) < 0.5
        assert abs(sim.state.p_reactor_bar - 1.25) < 0.1
        assert sim.state.c_chp <= 0.05

    def test_nominal_coils_and_state(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        assert sim.is_running is True
        assert sim.emergency_quench_open is False
        assert sim.high_chp_prealarm is False
        assert sim.diagnostic_code == DiagnosticCode.OK


# ============================================================================
# 5. TestConservationLawsAndThermodynamics
# ============================================================================

class TestConservationLawsAndThermodynamics:
    """Validate conservation residuals (mass and enthalpy errors < 1e-10)."""

    def test_stoichiometric_mass_balance_error(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        res = sim.verify_conservation_laws()
        assert res["stoichiometric_mass_error_kg_s"] < 1e-10
        assert res["elemental_mass_error_kg_s"] < 1e-10
        assert res["enthalpy_error_kw"] < 1e-10

    def test_conservation_laws_over_multiple_steps(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        for _ in range(25):
            sim.scan_step(0.020)
            res = sim.verify_conservation_laws()
            assert res["stoichiometric_mass_error_kg_s"] < 1e-10


# ============================================================================
# 6. TestThermalRunawayExotherm0xF401
# ============================================================================

class TestThermalRunawayExotherm0xF401:
    """Validate thermal runaway exotherm injection and emergency quench trip."""

    def test_thermal_runaway_trip(self) -> None:
        rt = RegisterTable()
        sim = CumeneHydroperoxideCleavage(register_table=rt)
        sim.reset()
        assert sim.emergency_quench_open is False

        sim.inject_thermal_runaway(temp_c=88.0)
        assert sim.emergency_quench_open is True
        assert sim.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert sim.is_running is False

        assert rt.read_bit("%M496") is True  # Emergency quench open
        assert rt.read_bit("%M494") is False # Reactor active cleared
        assert rt.read_uword("%R2127") == 0xF401

    def test_thermal_runaway_quench_cooling(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        sim.inject_thermal_runaway(temp_c=88.0)
        assert sim.emergency_quench_open is True
        # Quench agent removes heat rapidly
        sim.scan_step(0.020)
        assert sim.state.t_reactor_c < 88.0


# ============================================================================
# 7. TestChpAccumulationHazard0xF402
# ============================================================================

class TestChpAccumulationHazard0xF402:
    """Validate unreacted CHP accumulation pre-alarm and hazard trip."""

    def test_chp_accumulation_prealarm(self) -> None:
        rt = RegisterTable()
        sim = CumeneHydroperoxideCleavage(register_table=rt)
        sim.reset()
        sim.inject_chp_accumulation(c_chp=0.20)  # Above pre-alarm (0.15), below trip (0.35)
        assert sim.high_chp_prealarm is True
        assert sim.emergency_quench_open is False
        assert rt.read_bit("%M495") is True

    def test_chp_accumulation_trip(self) -> None:
        rt = RegisterTable()
        sim = CumeneHydroperoxideCleavage(register_table=rt)
        sim.reset()
        sim.inject_chp_accumulation(c_chp=0.45)  # Above trip threshold
        assert sim.diagnostic_code == DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP
        assert sim.emergency_quench_open is True
        assert rt.read_uword("%R2127") == 0xF402
        assert rt.read_bit("%M496") is True


# ============================================================================
# 8. TestCatalystAcidityStarvation0xF403
# ============================================================================

class TestCatalystAcidityStarvation0xF403:
    """Validate acid catalyst starvation fault injection."""

    def test_acid_starvation_fault(self) -> None:
        rt = RegisterTable()
        sim = CumeneHydroperoxideCleavage(register_table=rt)
        sim.reset()
        sim.inject_acid_starvation(acid_ppm=40.0)
        assert sim.diagnostic_code == DiagnosticCode.ACID_CATALYST_STARVATION_FAULT
        assert rt.read_uword("%R2127") == 0xF403


# ============================================================================
# 9. TestCoolingHeatRemovalFault0xF404
# ============================================================================

class TestCoolingHeatRemovalFault0xF404:
    """Validate cooling jacket heat removal fault injection."""

    def test_cooling_jacket_fault(self) -> None:
        rt = RegisterTable()
        sim = CumeneHydroperoxideCleavage(register_table=rt)
        sim.reset()
        sim.inject_cooling_failure(ua_degradation_pct=60.0)
        assert sim.diagnostic_code == DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT
        assert rt.read_uword("%R2127") == 0xF404


# ============================================================================
# 10. TestProcessSafetyStrictPriorityHierarchy
# ============================================================================

class TestProcessSafetyStrictPriorityHierarchy:
    """Validate priority resolution: 0xF401 > 0xF402 > 0xF403 > 0xF404."""

    def test_thermal_runaway_overrides_accumulation(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        sim.inject_chp_accumulation(c_chp=0.45)
        sim.inject_thermal_runaway(temp_c=88.0)
        assert sim.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION

    def test_accumulation_overrides_starvation(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        sim.inject_acid_starvation(acid_ppm=40.0)
        sim.inject_chp_accumulation(c_chp=0.45)
        assert sim.diagnostic_code == DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP


# ============================================================================
# 11. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate %R2120..%R2127 and %M494..%M496 bit-exact synchronization."""

    def test_nominal_registers_bit_exact(self) -> None:
        rt = RegisterTable()
        sim = CumeneHydroperoxideCleavage(register_table=rt)
        sim.reset()
        assert rt.read_word("%R2120") == 685   # 68.5 °C scaled by 10
        assert rt.read_word("%R2121") == 125   # 1.25 bar scaled by 100
        assert rt.read_word("%R2122") == 9985  # 99.85% conversion scaled by 100
        assert rt.read_word("%R2123") == 9920  # 99.20% selectivity scaled by 100
        assert rt.read_word("%R2124") == 25    # 0.025 mol/L residual CHP scaled by 1000
        assert rt.read_word("%R2125") == 8950  # 8950 kg/h production rate
        assert rt.read_word("%R2126") == 250   # 250 ppm acid catalyst
        assert rt.read_uword("%R2127") == 0x0000

        assert rt.read_bit("%M494") is True
        assert rt.read_bit("%M495") is False
        assert rt.read_bit("%M496") is False

    def test_operator_reset_restores_registers(self) -> None:
        rt = RegisterTable()
        sim = CumeneHydroperoxideCleavage(register_table=rt)
        sim.reset()
        sim.inject_thermal_runaway(temp_c=88.0)
        assert rt.read_bit("%M496") is True
        assert rt.read_uword("%R2127") == 0xF401

        sim.reset()
        assert rt.read_bit("%M496") is False
        assert rt.read_bit("%M494") is True
        assert rt.read_uword("%R2127") == 0x0000


# ============================================================================
# 12. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 ST POU syntax and register bindings."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cumene_hydroperoxide_cleavage_pure_st() is True

    def test_st_parser_ast_properties(self) -> None:
        ast = STParser.parse_pou(CUMENE_HYDROPEROXIDE_CLEAVAGE_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2120", "%R2121", "%R2122", "%R2123",
            "%R2124", "%R2125", "%R2126", "%R2127",
            "%M494", "%M495", "%M496",
        }
        assert expected_regs.issubset(set(ast.bound_registers))


# ============================================================================
# 13. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate strict rejection of forbidden ladder logic constructs."""

    def test_reject_normally_open_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM")

    def test_reject_normally_closed_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM")

    def test_reject_standard_coil(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR x := ---( )---; END_PROGRAM")

    def test_reject_set_coil(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---(S)--- x; END_PROGRAM")

    def test_reject_reset_coil(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---(R)--- x; END_PROGRAM")

    def test_reject_rung_delimiter(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test RUNG 1: x := 1; END_PROGRAM")

    def test_reject_network_delimiter(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test NETWORK 1: x := 1; END_PROGRAM")

    def test_reject_mnemonics(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test XIC(Contact1); OTE(Coil1); END_PROGRAM")


# ============================================================================
# 14. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface contract and 100-cycle soak stability."""

    def test_ilogic_unit_properties(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        assert isinstance(sim, ILogicUnit)
        assert isinstance(sim.name, str)
        assert sim.name in ("CumeneHydroperoxideCleavage", "CumeneHydroperoxideCleavageSync")
        assert sim.priority in (10, 100)
        assert sim.is_enabled is True

    def test_step_and_execute_methods(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        t0 = sim.time_s
        sim.step()
        assert sim.time_s > t0

        ctx = ScanContext(cycle=1, dt=0.010, timestamp=time.time())
        sim.execute(ctx)
        assert sim.cycles_count >= 2

    def test_100_cycle_soak_stability(self) -> None:
        sim = CumeneHydroperoxideCleavage()
        sim.reset()
        tracemalloc.start()
        snapshot1 = tracemalloc.take_snapshot()

        for _ in range(100):
            sim.scan_step(0.020)

        snapshot2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snapshot2.compare_to(snapshot1, "lineno")
        total_growth_kb = sum(s.size_diff for s in stats if s.size_diff > 0) / 1024.0

        assert total_growth_kb < 100.0  # Under 100 KB limit
        assert sim.is_running is True
        assert sim.emergency_quench_open is False
        assert not math.isnan(sim.state.t_reactor_c)
        assert not math.isnan(sim.state.chp_conversion_pct)


# ============================================================================
# 15. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage runner export and strict 4-state contract."""

    def test_runner_execution_and_stages(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = Path(tf.name)
        try:
            result = run_cumene_hydroperoxide_cleavage_verification(output_path=temp_path)
            assert isinstance(result, dict)
            assert result.get("status") == "success"
            assert result.get("error_code") is None
            assert "details" in result
            data = result.get("data", {})
            stages = data.get("stages", [])
            assert len(stages) == 9
            assert all(s.get("passed", False) for s in stages)
            assert temp_path.exists()
            assert temp_path.stat().st_size > 0
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_cli_verification_script_execution(self) -> None:
        cli_script = Path(__file__).resolve().parent.parent / "scripts" / "run_cumene_hydroperoxide_cleavage_verification.py"
        assert cli_script.exists()
        res = subprocess.run(
            [sys.executable, str(cli_script), "--json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert res.returncode == 0
        payload = json.loads(res.stdout)
        assert payload.get("status") == "success"
        assert payload.get("data", {}).get("checks_passed") == 9
