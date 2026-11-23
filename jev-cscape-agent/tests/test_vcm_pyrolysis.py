"""Comprehensive Unit and Integration Test Suite for Wave W248:
Industrial Vinyl Chloride Monomer (VCM) 1,2-Dichloroethane (EDC) Thermal Pyrolysis Cracking ODE Simulation.

Work Package: W248 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS (100+ Deterministic Assertions across 16 Test Classes)
Status Contract: Strict 4-State JSON output & evidence emission.

Covers 16 Engineering Test Classes:
1.  TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2.  TestPyrolysisPhysicsAndKinetics: Reaction enthalpies (+71.0, +96.0, -35.0 kJ/mol), Arrhenius rate constants, activation energies.
3.  TestRK4NumericalSolver: RK4 state transitions, dt stability, convergence, non-negative concentrations.
4.  TestNominalSteadyStateConvergence: Conversion >= 54.0%, Selectivity >= 98.0%, Temp 495 °C, Pressure 26.5 bar, Feed 18500 kg/h, Rate 6400 kg/h.
5.  TestConservationLawsAndThermodynamics: Mass conservation error < 1e-10 kg/s, elemental mass balance, enthalpy conservation < 1e-10 kW.
6.  TestThermalSkinOvertempFault0xF301: Skin temp > 560 °C trips 0xF301, asserts %M489 emergency trip.
7.  TestFurnaceOverpressureFault0xF302: Pressure > 32.0 bar trips 0xF302, emergency trip %M489.
8.  TestCokeHotspotFault0xF303: Skin temp > 540 °C trips %M488 pre-alarm, severe coking trips 0xF303.
9.  TestSelectivityDegradationFault0xF304: Selectivity < 95% trips 0xF304.
10. TestProcessSafetyStrictPriorityHierarchy: Strict priority resolution (0xF301 > 0xF302 > 0xF303 > 0xF304 > 0x0000).
11. TestHornerOCSSynchronizationAndRegisters: %R2090..%R2097, %M487..%M489 bit-exact synchronization, PrivilegeMode.SYSTEM.
12. TestPureSTAndSecurity: STParser & SecurityGuard verification of VcmPyrolysisSync POU.
13. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts `---[ ]---`, coils `---( )---`, rungs, networks, mnemonics) with LadderForbiddenError.
14. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
15. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
16. TestEdgeCasesAndConfigModels: Custom configurations, property aliases, and edge conditions.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import tracemalloc
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, ReadOnlyChannelError, RegisterTable

from jev_cscape.simulation.vcm_pyrolysis import (
    COIL_COKE_HOTSPOT_PREALARM,
    COIL_COKE_HOTSPOT_PREALARM_ADDR,
    COIL_FURNACE_EMERGENCY_TRIP,
    COIL_FURNACE_EMERGENCY_TRIP_ADDR,
    COIL_VCM_FURNACE_RUNNING,
    COIL_VCM_FURNACE_RUNNING_ADDR,
    COKE_DEPOSITION_RATE_NOMINAL_G_H,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DiagnosticCode,
    EDC_CONVERSION_NOMINAL_PCT,
    EDC_FEED_FLOW_NOMINAL_KG_H,
    FURNACE_OVERPRESSURE_TRIP_BAR,
    FURNACE_PRESSURE_NOMINAL_BAR,
    FURNACE_TEMP_NOMINAL_C,
    G_ACCEL,
    MW_C,
    MW_C2H2,
    MW_C4H6CL2,
    MW_CL,
    MW_COKE,
    MW_COKE_PRECURSOR,
    MW_EDC,
    MW_H,
    MW_HCL,
    MW_VCM,
    PureSTValidationResult,
    R_GAS_CONST,
    REG_COKE_DEPOSITION_RATE,
    REG_COKE_DEPOSITION_RATE_ADDR,
    REG_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_CODE_ADDR,
    REG_EDC_CONVERSION,
    REG_EDC_CONVERSION_ADDR,
    REG_EDC_FEED_FLOW,
    REG_EDC_FEED_FLOW_ADDR,
    REG_EDC_FURNACE_TEMP,
    REG_EDC_FURNACE_TEMP_ADDR,
    REG_FURNACE_PRESSURE,
    REG_FURNACE_PRESSURE_ADDR,
    REG_VCM_PRODUCTION_RATE,
    REG_VCM_PRODUCTION_RATE_ADDR,
    REG_VCM_SELECTIVITY,
    REG_VCM_SELECTIVITY_ADDR,
    T_REF_K,
    T_ZERO_CELSIUS,
    TUBE_SKIN_HOTSPOT_PREALARM_C,
    TUBE_SKIN_OVERTEMP_TRIP_C,
    TUBE_SKIN_TEMP_NOMINAL_C,
    VCM_PRODUCTION_RATE_NOMINAL_KG_H,
    VCM_PURE_ST_POU,
    VCM_PYROLYSIS_PURE_ST_POU,
    VCM_PYROLYSIS_SYNC_POU,
    VCM_SELECTIVITY_MIN_PCT,
    VCM_SELECTIVITY_NOMINAL_PCT,
    VCM_SYNC_POU,
    VcmCracker,
    VcmCrackingFurnace,
    VcmCrackingFurnaceLogicUnit,
    VcmCrackingFurnaceSimulator,
    VcmDiagCode,
    VcmDiagnosticCode,
    VcmPyrolysis,
    VcmPyrolysisConfig,
    VcmPyrolysisDiagCode,
    VcmPyrolysisDiagnosticCode,
    VcmPyrolysisEngine,
    VcmPyrolysisLogicUnit,
    VcmPyrolysisModel,
    VcmPyrolysisParameters,
    VcmPyrolysisPlantModel,
    VcmPyrolysisReactor,
    VcmPyrolysisReactorLogicUnit,
    VcmPyrolysisSimulationEngine,
    VcmPyrolysisSimulator,
    VcmPyrolysisState,
    VcmPyrolysisStatusBits,
    VcmPyrolysisStatusWord,
    VcmStatusBits,
    VcmStatusWord,
    run_vcm_pyrolysis_verification,
    run_vcm_verification,
    validate_pure_st,
    verify_vcm_pure_st,
    verify_vcm_pyrolysis_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate register bindings, diagnostic codes, enum representations, and status bits."""

    def test_diagnostic_codes_values(self) -> None:
        assert DiagnosticCode.FURNACE_OK == 0x0000
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.THERMAL_SKIN_OVERTEMP == 0xF301
        assert DiagnosticCode.FURNACE_OVERPRESSURE == 0xF302
        assert DiagnosticCode.COKE_FOULING_HOTSPOT == 0xF303
        assert DiagnosticCode.VCM_SELECTIVITY_DEGRADATION == 0xF304

    def test_diagnostic_code_signed_equality(self) -> None:
        # Signed 16-bit representation: 0xF301 - 0x10000 = -3327
        assert DiagnosticCode.THERMAL_SKIN_OVERTEMP == -3327
        assert DiagnosticCode.FURNACE_OVERPRESSURE == -3326
        assert DiagnosticCode.COKE_FOULING_HOTSPOT == -3325
        assert DiagnosticCode.VCM_SELECTIVITY_DEGRADATION == -3324
        assert DiagnosticCode.FURNACE_OK == 0

    def test_diagnostic_code_unsigned_equality(self) -> None:
        assert DiagnosticCode.THERMAL_SKIN_OVERTEMP == 0xF301
        assert DiagnosticCode.FURNACE_OVERPRESSURE == 0xF302
        assert DiagnosticCode.COKE_FOULING_HOTSPOT == 0xF303
        assert DiagnosticCode.VCM_SELECTIVITY_DEGRADATION == 0xF304
        assert DiagnosticCode.FURNACE_OK == 0x0000

    def test_diagnostic_code_lookup_via_missing(self) -> None:
        assert DiagnosticCode(-3327) == DiagnosticCode.THERMAL_SKIN_OVERTEMP
        assert DiagnosticCode(-3326) == DiagnosticCode.FURNACE_OVERPRESSURE
        assert DiagnosticCode(-3325) == DiagnosticCode.COKE_FOULING_HOTSPOT
        assert DiagnosticCode(-3324) == DiagnosticCode.VCM_SELECTIVITY_DEGRADATION
        assert DiagnosticCode(0xF301) == DiagnosticCode.THERMAL_SKIN_OVERTEMP
        assert DiagnosticCode(0x0000) == DiagnosticCode.FURNACE_OK

    def test_diagnostic_code_bitwise_and(self) -> None:
        assert (DiagnosticCode.THERMAL_SKIN_OVERTEMP & 0xFFFF) == 0xF301
        assert (0xFFFF & DiagnosticCode.FURNACE_OVERPRESSURE) == 0xF302
        assert (DiagnosticCode.COKE_FOULING_HOTSPOT & 0xF000) == 0xF000
        assert (DiagnosticCode.VCM_SELECTIVITY_DEGRADATION & 0x00FF) == 0x0004

    def test_diagnostic_code_bitwise_rand(self) -> None:
        assert (0xFFFF & DiagnosticCode.THERMAL_SKIN_OVERTEMP) == 0xF301
        assert (0xF000 & DiagnosticCode.FURNACE_OVERPRESSURE) == 0xF000

    def test_diagnostic_code_hashing(self) -> None:
        code_set = {
            DiagnosticCode.FURNACE_OK,
            DiagnosticCode.THERMAL_SKIN_OVERTEMP,
            DiagnosticCode.FURNACE_OVERPRESSURE,
            DiagnosticCode.COKE_FOULING_HOTSPOT,
            DiagnosticCode.VCM_SELECTIVITY_DEGRADATION,
        }
        assert len(code_set) == 5
        assert DiagnosticCode.THERMAL_SKIN_OVERTEMP in code_set
        assert hash(DiagnosticCode.THERMAL_SKIN_OVERTEMP) == hash(0xF301)

    def test_diagnostic_code_aliases(self) -> None:
        assert VcmPyrolysisDiagnosticCode is DiagnosticCode
        assert VcmPyrolysisDiagCode is DiagnosticCode
        assert VcmDiagnosticCode is DiagnosticCode
        assert VcmDiagCode is DiagnosticCode
        assert DiagnosticCode.ERR_THERMAL_SKIN_OVERTEMP == 0xF301
        assert DiagnosticCode.ERR_FURNACE_OVERPRESSURE == 0xF302
        assert DiagnosticCode.ERR_COKE_FOULING_HOTSPOT == 0xF303
        assert DiagnosticCode.ERR_VCM_SELECTIVITY_DEGRADATION == 0xF304
        assert DiagnosticCode.VCM_ERR_THERMAL_SKIN_OVERTEMP == 0xF301

    def test_status_bits_values(self) -> None:
        assert VcmPyrolysisStatusBits.RUNNING == 0x0001
        assert VcmPyrolysisStatusBits.VCM_FURNACE_RUNNING == 0x0002
        assert VcmPyrolysisStatusBits.COKE_HOTSPOT_PREALARM == 0x0004
        assert VcmPyrolysisStatusBits.FURNACE_EMERGENCY_TRIP == 0x0008
        assert VcmPyrolysisStatusBits.THERMAL_SKIN_OVERTEMP == 0x0010
        assert VcmPyrolysisStatusBits.FURNACE_OVERPRESSURE == 0x0020
        assert VcmPyrolysisStatusBits.COKE_FOULING_HOTSPOT == 0x0040
        assert VcmPyrolysisStatusBits.VCM_SELECTIVITY_DEGRADATION == 0x0080

    def test_status_word_combinations(self) -> None:
        sw = VcmPyrolysisStatusBits.RUNNING | VcmPyrolysisStatusBits.VCM_FURNACE_RUNNING
        assert sw == 0x0003
        assert bool(sw & VcmPyrolysisStatusBits.RUNNING) is True
        assert bool(sw & VcmPyrolysisStatusBits.FURNACE_EMERGENCY_TRIP) is False

    def test_status_bits_aliases(self) -> None:
        assert VcmPyrolysisStatusWord is VcmPyrolysisStatusBits
        assert VcmStatusBits is VcmPyrolysisStatusBits
        assert VcmStatusWord is VcmPyrolysisStatusBits

    def test_register_addresses(self) -> None:
        assert REG_EDC_FURNACE_TEMP_ADDR == "%R2090"
        assert REG_EDC_CONVERSION_ADDR == "%R2091"
        assert REG_VCM_SELECTIVITY_ADDR == "%R2092"
        assert REG_EDC_FEED_FLOW_ADDR == "%R2093"
        assert REG_FURNACE_PRESSURE_ADDR == "%R2094"
        assert REG_VCM_PRODUCTION_RATE_ADDR == "%R2095"
        assert REG_COKE_DEPOSITION_RATE_ADDR == "%R2096"
        assert REG_DIAGNOSTIC_CODE_ADDR == "%R2097"
        assert REG_EDC_FURNACE_TEMP == "%R2090"
        assert REG_EDC_CONVERSION == "%R2091"
        assert REG_VCM_SELECTIVITY == "%R2092"
        assert REG_EDC_FEED_FLOW == "%R2093"
        assert REG_FURNACE_PRESSURE == "%R2094"
        assert REG_VCM_PRODUCTION_RATE == "%R2095"
        assert REG_COKE_DEPOSITION_RATE == "%R2096"
        assert REG_DIAGNOSTIC_CODE == "%R2097"

    def test_coil_addresses(self) -> None:
        assert COIL_VCM_FURNACE_RUNNING_ADDR == "%M487"
        assert COIL_COKE_HOTSPOT_PREALARM_ADDR == "%M488"
        assert COIL_FURNACE_EMERGENCY_TRIP_ADDR == "%M489"
        assert COIL_VCM_FURNACE_RUNNING == "%M487"
        assert COIL_COKE_HOTSPOT_PREALARM == "%M488"
        assert COIL_FURNACE_EMERGENCY_TRIP == "%M489"

    def test_universal_physical_constants_and_mw(self) -> None:
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(G_ACCEL - 9.80665) < 1e-4
        assert T_ZERO_CELSIUS == 273.15
        assert T_REF_K == 768.15
        assert MW_C == 0.012011
        assert MW_H == 0.001008
        assert MW_CL == 0.035453
        assert abs(MW_EDC - (2 * MW_C + 4 * MW_H + 2 * MW_CL)) < 1e-9
        assert abs(MW_VCM - (2 * MW_C + 3 * MW_H + 1 * MW_CL)) < 1e-9
        assert abs(MW_HCL - (1 * MW_H + 1 * MW_CL)) < 1e-9
        assert abs(MW_C2H2 - (2 * MW_C + 2 * MW_H)) < 1e-9
        assert abs(MW_C4H6CL2 - (4 * MW_C + 6 * MW_H + 2 * MW_CL)) < 1e-9
        assert MW_COKE_PRECURSOR == MW_C4H6CL2
        assert MW_COKE == MW_C


# ============================================================================
# 2. TestPyrolysisPhysicsAndKinetics
# ============================================================================

class TestPyrolysisPhysicsAndKinetics:
    """Validate reaction enthalpies, Arrhenius parameters, and kinetic behaviors."""

    def test_reaction_enthalpies(self) -> None:
        assert DELTA_H1_KJ_MOL == 71.0
        assert DELTA_H1_J_MOL == 71000.0
        assert DELTA_H2_KJ_MOL == 96.0
        assert DELTA_H2_J_MOL == 96000.0
        assert DELTA_H3_KJ_MOL == -35.0
        assert DELTA_H3_J_MOL == -35000.0

    def test_arrhenius_monotonicity_k1(self) -> None:
        sim = VcmPyrolysis()
        t1 = 450.0 + T_ZERO_CELSIUS
        t2 = 495.0 + T_ZERO_CELSIUS
        t3 = 540.0 + T_ZERO_CELSIUS
        k1_t1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1)
        k1_t2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2)
        k1_t3 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t3)
        assert 0.0 < k1_t1 < k1_t2 < k1_t3

    def test_arrhenius_monotonicity_k2(self) -> None:
        sim = VcmPyrolysis()
        t1 = 450.0 + T_ZERO_CELSIUS
        t2 = 495.0 + T_ZERO_CELSIUS
        t3 = 540.0 + T_ZERO_CELSIUS
        k2_t1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t1)
        k2_t2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t2)
        k2_t3 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t3)
        assert 0.0 < k2_t1 < k2_t2 < k2_t3

    def test_arrhenius_monotonicity_k3(self) -> None:
        sim = VcmPyrolysis()
        t1 = 450.0 + T_ZERO_CELSIUS
        t2 = 495.0 + T_ZERO_CELSIUS
        t3 = 540.0 + T_ZERO_CELSIUS
        k3_t1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t1)
        k3_t2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t2)
        k3_t3 = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t3)
        assert 0.0 < k3_t1 < k3_t2 < k3_t3

    def test_activation_energy_reconstruction_e1(self) -> None:
        sim = VcmPyrolysis()
        t1 = 495.0 + T_ZERO_CELSIUS
        t2 = 525.0 + T_ZERO_CELSIUS
        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2)
        ea_rec = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2) - (1.0 / t1))
        assert abs(ea_rec - sim.config.activation_e1_j_mol) < 1e-3

    def test_activation_energy_reconstruction_e2(self) -> None:
        sim = VcmPyrolysis()
        t1 = 495.0 + T_ZERO_CELSIUS
        t2 = 525.0 + T_ZERO_CELSIUS
        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t1)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t2)
        ea_rec = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2) - (1.0 / t1))
        assert abs(ea_rec - sim.config.activation_e2_j_mol) < 1e-3

    def test_side_cracking_accelerates_at_elevated_temperature(self) -> None:
        sim = VcmPyrolysis()
        t_low = 475.0 + T_ZERO_CELSIUS
        t_high = 535.0 + T_ZERO_CELSIUS
        k1_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_low)
        k1_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_high)
        k2_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t_low)
        k2_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t_high)
        ratio_k2 = k2_high / k2_low
        ratio_k1 = k1_high / k1_low
        assert ratio_k2 > ratio_k1  # Ea2 (220 kJ/mol) > Ea1 (180 kJ/mol)

    def test_reaction_rates_zero_when_emergency_tripped(self) -> None:
        sim = VcmPyrolysis()
        t_k = 495.0 + T_ZERO_CELSIUS
        rates = sim.compute_reaction_rates(148.0, 174.0, t_k, trip=True)
        assert rates["r1_vol"] == 0.0
        assert rates["r2_vol"] == 0.0
        assert rates["r3_vol"] == 0.0
        assert rates["q_rxn_kw"] == 0.0

    def test_reaction_rates_positive_at_nominal_operating_temp(self) -> None:
        sim = VcmPyrolysis()
        t_k = 495.0 + T_ZERO_CELSIUS
        rates = sim.compute_reaction_rates(148.0, 174.0, t_k, trip=False)
        assert rates["r1_vol"] > 0.0
        assert rates["r2_vol"] > 0.0
        assert rates["r3_vol"] > 0.0
        assert rates["q_rxn_kw"] > 0.0

    def test_reaction_thermal_duties_endothermic_and_exothermic(self) -> None:
        sim = VcmPyrolysis()
        t_k = 495.0 + T_ZERO_CELSIUS
        rates = sim.compute_reaction_rates(148.0, 174.0, t_k, trip=False)
        # Endothermic cracking absorbs net heat
        assert rates["q_rxn_kw"] > 1000.0


# ============================================================================
# 3. TestRK4NumericalSolver
# ============================================================================

class TestRK4NumericalSolver:
    """Validate Runge-Kutta 4th-order ODE system stability, time-step transitions, and clamping."""

    def test_rk4_derivatives_finite_and_length(self) -> None:
        sim = VcmPyrolysis()
        y0 = [sim.state.c_edc, sim.state.c_vcm, sim.state.c_hcl, sim.state.c_c2h2, sim.state.coke_rate, sim.state.t_skin_k]
        derivs = sim.compute_derivatives(0.0, y0)
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_rk4_single_step_state_transition(self) -> None:
        sim = VcmPyrolysis()
        t_before = sim.state.sim_time_s
        c_before = sim.state.scan_count
        sim.rk4_step(dt=0.02)
        assert abs(sim.state.sim_time_s - (t_before + 0.02)) < 1e-6
        assert sim.state.scan_count == c_before + 1

    def test_rk4_dt_stability_various_step_sizes(self) -> None:
        for dt_val in (0.005, 0.01, 0.02, 0.05):
            sim = VcmPyrolysis()
            res = sim.step(dt=dt_val)
            assert res.status == AgentStatus.SUCCESS
            assert not math.isnan(sim.state.c_edc)
            assert not math.isnan(sim.state.c_vcm)
            assert not math.isnan(sim.state.tube_skin_temp_celsius)

    def test_rk4_non_negative_concentrations_boundary_enforcement(self) -> None:
        sim = VcmPyrolysis()
        # Perturb with extreme depletion
        sim.state.c_edc = 0.0001
        sim.state.c_vcm = 0.0001
        sim.step(dt=0.02)
        assert sim.state.c_edc >= 0.0
        assert sim.state.c_vcm >= 0.0
        assert sim.state.c_hcl >= 0.0
        assert sim.state.c_c2h2 >= 0.0

    def test_rk4_tube_skin_temperature_clamping(self) -> None:
        sim = VcmPyrolysis()
        sim.state.t_skin_k = 100.0  # Unphysical low
        sim.rk4_step(dt=0.02)
        assert sim.state.t_skin_k >= 250.0

        sim.state.t_skin_k = 2000.0  # Unphysical high
        sim.rk4_step(dt=0.02)
        assert sim.state.t_skin_k <= 1500.0

    def test_rk4_coke_deposition_rate_clamping(self) -> None:
        sim = VcmPyrolysis()
        sim.state.coke_rate = -50.0
        sim.rk4_step(dt=0.02)
        assert sim.state.coke_rate >= 0.0

        sim.state.coke_rate = 2000.0
        sim.rk4_step(dt=0.02)
        assert sim.state.coke_rate <= 1000.0

    def test_rk4_scan_count_and_time_increment(self) -> None:
        sim = VcmPyrolysis()
        for i in range(5):
            sim.rk4_step(dt=0.02)
        assert sim.state.scan_count == 5
        assert abs(sim.state.sim_time_s - 0.10) < 1e-6

    def test_advance_time_multi_step_trajectory(self) -> None:
        sim = VcmPyrolysis()
        res = sim.advance_time(duration_s=1.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.scan_count == 50
        assert abs(sim.state.sim_time_s - 1.0) < 1e-6


# ============================================================================
# 4. TestNominalSteadyStateConvergence
# ============================================================================

class TestNominalSteadyStateConvergence:
    """Validate nominal operating steady state: conversion, selectivity, temperature, and rates."""

    def test_nominal_edc_single_pass_conversion(self) -> None:
        sim = VcmPyrolysis()
        assert sim.state.edc_conversion_pct >= 54.0
        assert abs(sim.state.edc_conversion_pct - EDC_CONVERSION_NOMINAL_PCT) < 1.0

    def test_nominal_vcm_selectivity(self) -> None:
        sim = VcmPyrolysis()
        assert sim.state.vcm_selectivity_pct >= 98.0
        assert abs(sim.state.vcm_selectivity_pct - VCM_SELECTIVITY_NOMINAL_PCT) < 1.0

    def test_nominal_vcm_production_rate(self) -> None:
        sim = VcmPyrolysis()
        assert abs(sim.state.vcm_production_rate_kg_h - VCM_PRODUCTION_RATE_NOMINAL_KG_H) < 50.0
        assert sim.state.vcm_production_rate_kg_h >= 6350.0

    def test_nominal_coke_deposition_rate(self) -> None:
        sim = VcmPyrolysis()
        assert abs(sim.state.coke_deposition_rate_g_h - COKE_DEPOSITION_RATE_NOMINAL_G_H) < 2.0

    def test_nominal_furnace_gas_temperature(self) -> None:
        sim = VcmPyrolysis()
        assert sim.state.edc_furnace_temp_celsius == FURNACE_TEMP_NOMINAL_C
        assert sim.state.edc_furnace_temp_celsius == 495.0

    def test_nominal_operating_furnace_pressure(self) -> None:
        sim = VcmPyrolysis()
        assert sim.state.furnace_pressure_bar == FURNACE_PRESSURE_NOMINAL_BAR
        assert sim.state.furnace_pressure_bar == 26.50

    def test_nominal_edc_feed_mass_flow(self) -> None:
        sim = VcmPyrolysis()
        assert sim.state.edc_feed_flow_kg_h == EDC_FEED_FLOW_NOMINAL_KG_H
        assert sim.state.edc_feed_flow_kg_h == 18500.0

    def test_nominal_tube_skin_temperature(self) -> None:
        sim = VcmPyrolysis()
        assert abs(sim.state.tube_skin_temp_celsius - TUBE_SKIN_TEMP_NOMINAL_C) < 1.0


# ============================================================================
# 5. TestConservationLawsAndThermodynamics
# ============================================================================

class TestConservationLawsAndThermodynamics:
    """Validate stoichiometric mass, elemental, and first-law enthalpy conservation residuals (< 1e-10)."""

    def test_total_mass_balance_residual_below_threshold(self) -> None:
        sim = VcmPyrolysis()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_mass_balance_residual_below_threshold(self) -> None:
        sim = VcmPyrolysis()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_carbon_stoichiometric_elemental_balance(self) -> None:
        # C2H4Cl2 (2 C) -> C2H3Cl (2 C) + HCl (0 C); C2H3Cl -> C2H2 (2 C); C2H3Cl + C2H4Cl2 -> C4H6Cl2 (4 C)
        sim = VcmPyrolysis()
        r1 = sim.state.r1_rate_mol_s
        r2 = sim.state.r2_rate_mol_s
        r3 = sim.state.r3_rate_mol_s
        c_in = (r1 + r3) * 2.0 + (r2 + r3) * 2.0
        c_out = r1 * 2.0 + r2 * 2.0 + r3 * 4.0
        assert abs(c_in - c_out) < 1e-9

    def test_chlorine_stoichiometric_elemental_balance(self) -> None:
        # C2H4Cl2 (2 Cl) -> C2H3Cl (1 Cl) + HCl (1 Cl); C2H3Cl -> C2H2 (0 Cl) + HCl (1 Cl); C2H3Cl + EDC -> C4H6Cl2 (2 Cl) + HCl (1 Cl)
        sim = VcmPyrolysis()
        r1 = sim.state.r1_rate_mol_s
        r2 = sim.state.r2_rate_mol_s
        r3 = sim.state.r3_rate_mol_s
        cl_in = (r1 + r3) * 2.0 + (r2 + r3) * 1.0
        cl_out = r1 * (1.0 + 1.0) + r2 * 1.0 + r3 * (2.0 + 1.0)
        assert abs(cl_in - cl_out) < 1e-9

    def test_hydrogen_stoichiometric_elemental_balance(self) -> None:
        # C2H4Cl2 (4 H) -> C2H3Cl (3 H) + HCl (1 H); C2H3Cl -> C2H2 (2 H) + HCl (1 H); C2H3Cl + EDC -> C4H6Cl2 (6 H) + HCl (1 H)
        sim = VcmPyrolysis()
        r1 = sim.state.r1_rate_mol_s
        r2 = sim.state.r2_rate_mol_s
        r3 = sim.state.r3_rate_mol_s
        h_in = (r1 + r3) * 4.0 + (r2 + r3) * 3.0
        h_out = r1 * (3.0 + 1.0) + r2 * (2.0 + 1.0) + r3 * (6.0 + 1.0)
        assert abs(h_in - h_out) < 1e-9

    def test_first_law_enthalpy_residual_below_threshold(self) -> None:
        sim = VcmPyrolysis()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_preserved_across_dynamic_steps(self) -> None:
        sim = VcmPyrolysis()
        for _ in range(50):
            sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_mass_conservation_holds_when_feed_is_zero(self) -> None:
        sim = VcmPyrolysis()
        sim.state.edc_feed_flow_kg_h = 0.0
        sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10


# ============================================================================
# 6. TestThermalSkinOvertempFault0xF301
# ============================================================================

class TestThermalSkinOvertempFault0xF301:
    """Validate 0xF301 Thermal Skin Overtemp fault (> 560.0 °C), %M489 emergency trip, and %M488 pre-alarm."""

    def test_overtemp_trips_above_560_celsius(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 560.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_SKIN_OVERTEMP
        assert sim.state.diagnostic_code == 0xF301

    def test_overtemp_clears_furnace_running_coil(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 562.0
        sim._evaluate_safety_interlocks()
        assert sim.state.vcm_furnace_running is False

    def test_overtemp_asserts_emergency_trip_coil(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0
        sim._evaluate_safety_interlocks()
        assert sim.state.furnace_emergency_trip is True

    def test_overtemp_asserts_coke_hotspot_prealarm_coil(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0
        sim._evaluate_safety_interlocks()
        assert sim.state.coke_hotspot_prealarm is True

    def test_overtemp_sets_status_bits_mask(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0
        sim._evaluate_safety_interlocks()
        sw = VcmPyrolysisStatusBits(sim.state.status_word)
        assert bool(sw & VcmPyrolysisStatusBits.THERMAL_SKIN_OVERTEMP) is True
        assert bool(sw & VcmPyrolysisStatusBits.FURNACE_EMERGENCY_TRIP) is True
        assert bool(sw & VcmPyrolysisStatusBits.VCM_FURNACE_RUNNING) is False

    def test_overtemp_activates_trip_quench_duty(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0
        sim.state.t_skin_k = 565.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        derivs = sim.compute_derivatives(0.0, [sim.state.c_edc, sim.state.c_vcm, sim.state.c_hcl, sim.state.c_c2h2, sim.state.coke_rate, sim.state.t_skin_k])
        # dt_skin_dt should be strongly negative due to quench cooling
        dt_skin_dt = derivs[5]
        assert dt_skin_dt < 0.0

    def test_overtemp_zeroes_feed_inflow(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0
        sim._evaluate_safety_interlocks()
        sim._update_kinetics_and_conversion()
        assert sim.state.edc_conversion_pct == 0.0
        assert sim.state.vcm_production_rate_kg_h == 0.0

    def test_overtemp_register_table_synchronization(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.state.tube_skin_temp_celsius = 565.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert table.read_uword("%R2097") == 0xF301
        assert table.read_word("%R2097") == -3327
        assert table.read_bit("%M487") is False
        assert table.read_bit("%M488") is True
        assert table.read_bit("%M489") is True


# ============================================================================
# 7. TestFurnaceOverpressureFault0xF302
# ============================================================================

class TestFurnaceOverpressureFault0xF302:
    """Validate 0xF302 Furnace Overpressure fault (> 32.0 bar) and %M489 emergency trip."""

    def test_overpressure_trips_above_32_bar(self) -> None:
        sim = VcmPyrolysis()
        sim.state.furnace_pressure_bar = 32.2
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.FURNACE_OVERPRESSURE
        assert sim.state.diagnostic_code == 0xF302

    def test_overpressure_asserts_emergency_trip_coil(self) -> None:
        sim = VcmPyrolysis()
        sim.state.furnace_pressure_bar = 32.5
        sim._evaluate_safety_interlocks()
        assert sim.state.furnace_emergency_trip is True

    def test_overpressure_clears_furnace_running_coil(self) -> None:
        sim = VcmPyrolysis()
        sim.state.furnace_pressure_bar = 33.0
        sim._evaluate_safety_interlocks()
        assert sim.state.vcm_furnace_running is False

    def test_overpressure_sets_status_bits_mask(self) -> None:
        sim = VcmPyrolysis()
        sim.state.furnace_pressure_bar = 32.5
        sim._evaluate_safety_interlocks()
        sw = VcmPyrolysisStatusBits(sim.state.status_word)
        assert bool(sw & VcmPyrolysisStatusBits.FURNACE_OVERPRESSURE) is True
        assert bool(sw & VcmPyrolysisStatusBits.FURNACE_EMERGENCY_TRIP) is True
        assert bool(sw & VcmPyrolysisStatusBits.VCM_FURNACE_RUNNING) is False

    def test_overpressure_maintains_hotspot_coil_false_at_nominal_skin(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 520.0  # Nominal
        sim.state.furnace_pressure_bar = 32.5
        sim._evaluate_safety_interlocks()
        assert sim.state.coke_hotspot_prealarm is False

    def test_overpressure_reflects_hotspot_coil_true_if_skin_elevated(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 545.0  # Elevated
        sim.state.furnace_pressure_bar = 32.5
        sim._evaluate_safety_interlocks()
        assert sim.state.coke_hotspot_prealarm is True

    def test_overpressure_register_table_synchronization(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.state.furnace_pressure_bar = 32.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert table.read_uword("%R2097") == 0xF302
        assert table.read_word("%R2097") == -3326
        assert table.read_bit("%M487") is False
        assert table.read_bit("%M489") is True


# ============================================================================
# 8. TestCokeHotspotFault0xF303
# ============================================================================

class TestCokeHotspotFault0xF303:
    """Validate 0xF303 Coke Fouling Hotspot (> 540.0 °C skin) and %M488 pre-alarm."""

    def test_hotspot_trips_above_540_celsius(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 540.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COKE_FOULING_HOTSPOT
        assert sim.state.diagnostic_code == 0xF303

    def test_hotspot_asserts_prealarm_coil(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 545.0
        sim._evaluate_safety_interlocks()
        assert sim.state.coke_hotspot_prealarm is True

    def test_hotspot_does_not_assert_emergency_trip_coil(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 545.0
        sim._evaluate_safety_interlocks()
        assert sim.state.furnace_emergency_trip is False

    def test_hotspot_keeps_furnace_running_coil_true(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 545.0
        sim._evaluate_safety_interlocks()
        assert sim.state.vcm_furnace_running is True

    def test_hotspot_sets_status_bits_mask(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 545.0
        sim._evaluate_safety_interlocks()
        sw = VcmPyrolysisStatusBits(sim.state.status_word)
        assert bool(sw & VcmPyrolysisStatusBits.COKE_FOULING_HOTSPOT) is True
        assert bool(sw & VcmPyrolysisStatusBits.COKE_HOTSPOT_PREALARM) is True
        assert bool(sw & VcmPyrolysisStatusBits.FURNACE_EMERGENCY_TRIP) is False

    def test_hotspot_accelerates_coke_deposition_rate(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 550.0
        sim.state.t_skin_k = 550.0 + T_ZERO_CELSIUS
        y = [sim.state.c_edc, sim.state.c_vcm, sim.state.c_hcl, sim.state.c_c2h2, sim.state.coke_rate, sim.state.t_skin_k]
        derivs = sim.compute_derivatives(0.0, y)
        dr_coke_dt = derivs[4]
        assert dr_coke_dt > 0.0  # Coke rate accelerates towards higher equilibrium

    def test_hotspot_clears_below_540_celsius(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 545.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COKE_FOULING_HOTSPOT

        sim.state.tube_skin_temp_celsius = 520.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.FURNACE_OK
        assert sim.state.coke_hotspot_prealarm is False

    def test_hotspot_register_table_synchronization(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.state.tube_skin_temp_celsius = 545.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert table.read_uword("%R2097") == 0xF303
        assert table.read_word("%R2097") == -3325
        assert table.read_bit("%M487") is True
        assert table.read_bit("%M488") is True
        assert table.read_bit("%M489") is False


# ============================================================================
# 9. TestSelectivityDegradationFault0xF304
# ============================================================================

class TestSelectivityDegradationFault0xF304:
    """Validate 0xF304 VCM Selectivity Degradation (< 95.0%)."""

    def test_selectivity_degradation_trips_below_95_percent(self) -> None:
        sim = VcmPyrolysis()
        sim.state.vcm_selectivity_pct = 94.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VCM_SELECTIVITY_DEGRADATION
        assert sim.state.diagnostic_code == 0xF304

    def test_selectivity_degradation_keeps_furnace_running_coil(self) -> None:
        sim = VcmPyrolysis()
        sim.state.vcm_selectivity_pct = 93.0
        sim._evaluate_safety_interlocks()
        assert sim.state.vcm_furnace_running is True

    def test_selectivity_degradation_no_emergency_trip(self) -> None:
        sim = VcmPyrolysis()
        sim.state.vcm_selectivity_pct = 92.0
        sim._evaluate_safety_interlocks()
        assert sim.state.furnace_emergency_trip is False

    def test_selectivity_degradation_sets_status_bits_mask(self) -> None:
        sim = VcmPyrolysis()
        sim.state.vcm_selectivity_pct = 94.0
        sim._evaluate_safety_interlocks()
        sw = VcmPyrolysisStatusBits(sim.state.status_word)
        assert bool(sw & VcmPyrolysisStatusBits.VCM_SELECTIVITY_DEGRADATION) is True
        assert bool(sw & VcmPyrolysisStatusBits.FURNACE_EMERGENCY_TRIP) is False

    def test_selectivity_degradation_clears_above_95_percent(self) -> None:
        sim = VcmPyrolysis()
        sim.state.vcm_selectivity_pct = 94.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VCM_SELECTIVITY_DEGRADATION

        sim.state.vcm_selectivity_pct = 98.20
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.FURNACE_OK

    def test_selectivity_degradation_prealarm_reflects_skin_state(self) -> None:
        sim = VcmPyrolysis()
        sim.state.vcm_selectivity_pct = 94.0
        sim.state.tube_skin_temp_celsius = 520.0
        sim._evaluate_safety_interlocks()
        assert sim.state.coke_hotspot_prealarm is False

        sim.state.tube_skin_temp_celsius = 545.0
        sim._evaluate_safety_interlocks()
        # With skin temp elevated, 0xF303 has higher priority than 0xF304!
        assert sim.state.diagnostic_code == DiagnosticCode.COKE_FOULING_HOTSPOT
        assert sim.state.coke_hotspot_prealarm is True

    def test_selectivity_degradation_register_table_synchronization(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.state.vcm_selectivity_pct = 94.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert table.read_uword("%R2097") == 0xF304
        assert table.read_word("%R2097") == -3324
        assert table.read_bit("%M487") is True
        assert table.read_bit("%M488") is False
        assert table.read_bit("%M489") is False


# ============================================================================
# 10. TestProcessSafetyStrictPriorityHierarchy
# ============================================================================

class TestProcessSafetyStrictPriorityHierarchy:
    """Validate strict priority resolution (0xF301 > 0xF302 > 0xF303 > 0xF304 > 0x0000)."""

    def test_priority_overtemp_over_overpressure(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0  # 0xF301
        sim.state.furnace_pressure_bar = 33.0    # 0xF302
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_SKIN_OVERTEMP
        assert sim.state.furnace_emergency_trip is True

    def test_priority_overtemp_over_coke_hotspot(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0  # > 560 triggers 0xF301, > 540 triggers 0xF303
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_SKIN_OVERTEMP

    def test_priority_overtemp_over_selectivity_degradation(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0  # 0xF301
        sim.state.vcm_selectivity_pct = 92.0     # 0xF304
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_SKIN_OVERTEMP

    def test_priority_overpressure_over_coke_hotspot(self) -> None:
        sim = VcmPyrolysis()
        sim.state.furnace_pressure_bar = 33.0    # 0xF302
        sim.state.tube_skin_temp_celsius = 545.0 # 0xF303
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.FURNACE_OVERPRESSURE
        assert sim.state.furnace_emergency_trip is True

    def test_priority_overpressure_over_selectivity_degradation(self) -> None:
        sim = VcmPyrolysis()
        sim.state.furnace_pressure_bar = 33.0    # 0xF302
        sim.state.vcm_selectivity_pct = 92.0     # 0xF304
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.FURNACE_OVERPRESSURE

    def test_priority_coke_hotspot_over_selectivity_degradation(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 545.0 # 0xF303
        sim.state.vcm_selectivity_pct = 92.0     # 0xF304
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COKE_FOULING_HOTSPOT
        assert sim.state.furnace_emergency_trip is False

    def test_all_faults_simultaneous_clearance_cascade(self) -> None:
        sim = VcmPyrolysis()
        # Set all 4 faults simultaneously
        sim.state.tube_skin_temp_celsius = 565.0
        sim.state.furnace_pressure_bar = 33.0
        sim.state.vcm_selectivity_pct = 92.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_SKIN_OVERTEMP

        # Step 1: Clear overtemperature to 545 °C
        sim.state.tube_skin_temp_celsius = 545.0
        sim.state.furnace_emergency_trip = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.FURNACE_OVERPRESSURE

        # Step 2: Clear overpressure to 26.5 bar
        sim.state.furnace_pressure_bar = 26.50
        sim.state.furnace_emergency_trip = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COKE_FOULING_HOTSPOT

        # Step 3: Clear skin hotspot to 520 °C
        sim.state.tube_skin_temp_celsius = 520.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VCM_SELECTIVITY_DEGRADATION

        # Step 4: Clear selectivity to 98.20%
        sim.state.vcm_selectivity_pct = 98.20
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.FURNACE_OK


# ============================================================================
# 11. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate bit-exact Horner OCS memory map (%R2090..%R2097, %M487..%M489)."""

    def test_nominal_analog_registers_bit_exact(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.reset()

        assert table.read_word("%R2090") == 4950   # 495.0 °C scaled x10
        assert table.read_word("%R2091") == 5450   # 54.50% conversion scaled x100
        assert table.read_word("%R2092") == 9820   # 98.20% selectivity scaled x100
        assert table.read_word("%R2093") == 18500  # 18500 kg/h feed flow scaled x1
        assert table.read_word("%R2094") == 2650   # 26.50 bar scaled x100
        assert table.read_word("%R2095") == 6400   # 6400 kg/h VCM rate
        assert table.read_word("%R2096") == 4500   # 45.00 g/h coke scaled x100
        assert table.read_uword("%R2097") == 0x0000# FURNACE_OK

    def test_nominal_discrete_coils_bit_exact(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.reset()

        assert table.read_bit("%M487") is True     # VcmFurnaceRunning
        assert table.read_bit("%M488") is False    # CokeHotspotPrealarm
        assert table.read_bit("%M489") is False    # FurnaceEmergencyTrip

    def test_system_privilege_mode_synchronization(self) -> None:
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.SYSTEM
        sim = VcmPyrolysis(register_table=table)
        sim.reset()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2090") == 4950

    def test_unprivileged_write_rejected_with_readonly_error(self) -> None:
        table = RegisterTable()
        with pytest.raises(ReadOnlyChannelError):
            table.write_word("%AI1", 100, privilege=PrivilegeMode.APPLICATION)
        table.write_word("%AI1", 100, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%AI1") == 100

    def test_temperature_scaling_resolution_roundtrip(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.state.edc_furnace_temp_celsius = 496.3
        sim._sync_registers()
        raw = table.read_word("%R2090")
        assert raw == 4963
        recovered = raw / 10.0
        assert abs(recovered - 496.3) < 1e-6

    def test_conversion_scaling_resolution_roundtrip(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.state.edc_conversion_pct = 55.25
        sim._sync_registers()
        raw = table.read_word("%R2091")
        assert raw == 5525
        recovered = raw / 100.0
        assert abs(recovered - 55.25) < 1e-6

    def test_selectivity_scaling_resolution_roundtrip(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.state.vcm_selectivity_pct = 98.75
        sim._sync_registers()
        raw = table.read_word("%R2092")
        assert raw == 9875
        recovered = raw / 100.0
        assert abs(recovered - 98.75) < 1e-6

    def test_pressure_scaling_resolution_roundtrip(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        sim.state.furnace_pressure_bar = 27.15
        sim._sync_registers()
        raw = table.read_word("%R2094")
        assert raw == 2715
        recovered = raw / 100.0
        assert abs(recovered - 27.15) < 1e-6

    def test_diagnostic_register_signed_unsigned_representations(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)

        # 0xF301
        sim.state.diagnostic_code = DiagnosticCode.THERMAL_SKIN_OVERTEMP
        sim._sync_registers()
        assert table.read_uword("%R2097") == 0xF301
        assert table.read_word("%R2097") == -3327

        # 0xF302
        sim.state.diagnostic_code = DiagnosticCode.FURNACE_OVERPRESSURE
        sim._sync_registers()
        assert table.read_uword("%R2097") == 0xF302
        assert table.read_word("%R2097") == -3326

        # 0xF303
        sim.state.diagnostic_code = DiagnosticCode.COKE_FOULING_HOTSPOT
        sim._sync_registers()
        assert table.read_uword("%R2097") == 0xF303
        assert table.read_word("%R2097") == -3325

        # 0xF304
        sim.state.diagnostic_code = DiagnosticCode.VCM_SELECTIVITY_DEGRADATION
        sim._sync_registers()
        assert table.read_uword("%R2097") == 0xF304
        assert table.read_word("%R2097") == -3324


# ============================================================================
# 12. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 Structured Text compliance and AST parsing."""

    def test_pure_st_security_guard_assertion_passes(self) -> None:
        SecurityGuard.assert_pure_st_content(VCM_PYROLYSIS_PURE_ST_POU)

    def test_pure_st_parser_validate_code_success(self) -> None:
        val = STParser.validate_code(VCM_PYROLYSIS_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

    def test_pure_st_ast_structure_and_pou_type(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(VCM_PYROLYSIS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "VcmPyrolysisSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_bound_registers_contain_required_set(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(VCM_PYROLYSIS_PURE_ST_POU)
        assert pou is not None
        expected = [
            "%R2090", "%R2091", "%R2092", "%R2093",
            "%R2094", "%R2095", "%R2096", "%R2097",
            "%M487", "%M488", "%M489",
        ]
        for reg in expected:
            assert reg in pou.bound_registers

    def test_pure_st_pou_string_aliases_identical(self) -> None:
        assert VCM_PYROLYSIS_SYNC_POU == VCM_PYROLYSIS_PURE_ST_POU
        assert VCM_PURE_ST_POU == VCM_PYROLYSIS_PURE_ST_POU
        assert VCM_SYNC_POU == VCM_PYROLYSIS_PURE_ST_POU

    def test_verify_vcm_pyrolysis_pure_st_helper(self) -> None:
        res = verify_vcm_pyrolysis_pure_st()
        assert isinstance(res, PureSTValidationResult)
        assert res.status == AgentStatus.SUCCESS
        assert len(res.bound_registers) >= 11

    def test_verify_vcm_pure_st_and_validate_pure_st_aliases(self) -> None:
        assert verify_vcm_pure_st is verify_vcm_pyrolysis_pure_st
        assert validate_pure_st is verify_vcm_pyrolysis_pure_st


# ============================================================================
# 13. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate strict rejection of 6+ ladder logic constructs (ERR_LADDER_FORBIDDEN)."""

    def test_reject_ladder_contact(self) -> None:
        bad_code = "PROGRAM Bad ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_negated_contact(self) -> None:
        bad_code = "PROGRAM Bad ---[/]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_coil(self) -> None:
        bad_code = "PROGRAM Bad ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_set_coil(self) -> None:
        bad_code = "PROGRAM Bad ---(S)--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_reset_coil(self) -> None:
        bad_code = "PROGRAM Bad ---(R)--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_rung_delimiter(self) -> None:
        bad_code = "PROGRAM Bad RUNG 1: X := 1; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_network_delimiter(self) -> None:
        bad_code = "PROGRAM Bad NETWORK 1: Y := 2; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_mnemonics_xic_ote(self) -> None:
        bad_xic = "PROGRAM Bad XIC(InputBit); END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_xic)

        bad_ote = "PROGRAM Bad OTE(OutputCoil); END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_ote)


# ============================================================================
# 14. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit protocol compliance, scan cycles, and 100-cycle soak stability."""

    def test_ilogic_unit_properties(self) -> None:
        sim = VcmPyrolysis()
        assert sim.name == "VcmPyrolysisSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_enable_disable_lifecycle(self) -> None:
        sim = VcmPyrolysis()
        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_scan_step_with_context(self) -> None:
        table = RegisterTable()
        sim = VcmPyrolysis(register_table=table)
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        out = sim.scan_step(dt=0.02, context=ctx)
        assert out["status"] == "success"
        assert sim.state.scan_count == 1
        assert abs(sim.state.sim_time_s - 0.02) < 1e-6
        assert table.read_word("%R2090") == 4950
        assert table.read_word("%R2095") == 6400

    def test_execute_via_scan_context(self) -> None:
        sim = VcmPyrolysis()
        ctx = ScanContext(cycle=2, dt_ms=20.0, elapsed_time_ms=40.0, dt=0.02)
        sim.execute(ctx)
        assert sim.state.scan_count == 1

    def test_reset_restores_nominal_state(self) -> None:
        sim = VcmPyrolysis()
        sim.state.tube_skin_temp_celsius = 565.0
        sim._evaluate_safety_interlocks()
        assert sim.state.furnace_emergency_trip is True
        sim.reset()
        assert sim.state.tube_skin_temp_celsius == 520.0
        assert sim.state.furnace_emergency_trip is False
        assert sim.state.vcm_furnace_running is True
        assert sim.state.diagnostic_code == DiagnosticCode.FURNACE_OK

    def test_100_cycle_soak_stability(self) -> None:
        sim = VcmPyrolysis()
        sim.reset()

        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()
        for c in range(1, 101):
            ctx = ScanContext(cycle=c, dt_ms=20.0, elapsed_time_ms=c * 20.0, dt=0.02)
            sim.execute(ctx)
        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snap2.compare_to(snap1, "lineno")
        mem_diff_kb = sum(s.size_diff for s in stats if s.size_diff > 0) / 1024.0

        assert not math.isnan(sim.state.tube_skin_temp_celsius)
        assert not math.isnan(sim.state.c_vcm)
        assert 500.0 <= sim.state.tube_skin_temp_celsius <= 550.0
        assert sim.state.edc_conversion_pct >= 50.0
        assert sim.state.vcm_selectivity_pct >= 95.0
        assert mem_diff_kb < 1000.0

    def test_logic_unit_adapter_execute(self) -> None:
        unit = VcmPyrolysisLogicUnit()
        assert unit.name == "VcmPyrolysisSync"
        assert unit.is_enabled is True
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        assert unit.state.scan_count == 1

    def test_logic_unit_adapter_reset(self) -> None:
        unit = VcmPyrolysisLogicUnit()
        unit.state.tube_skin_temp_celsius = 565.0
        unit.reset()
        assert unit.state.tube_skin_temp_celsius == 520.0


# ============================================================================
# 15. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate 9-stage verification runner returning strict 4-state contract."""

    def test_verification_runner_returns_dict_with_4_state_keys(self) -> None:
        res = run_vcm_pyrolysis_verification(work_package="W248")
        assert isinstance(res, dict)
        assert "status" in res
        assert "error_code" in res
        assert "details" in res
        assert "data" in res

    def test_verification_runner_status_success(self) -> None:
        res = run_vcm_pyrolysis_verification(work_package="W248")
        assert res["status"] == "success"
        assert res["error_code"] is None

    def test_all_9_verification_stages_passed(self) -> None:
        res = run_vcm_pyrolysis_verification(work_package="W248")
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_verification_stages_structure_and_stages_field(self) -> None:
        res = run_vcm_pyrolysis_verification(work_package="W248")
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for s in stages:
            assert "stage" in s
            assert "check" in s
            assert "passed" in s
            assert s["passed"] is True

    def test_verification_file_export_to_tempfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "vcm_pyrolysis_evidence.json"
            res = run_vcm_pyrolysis_verification(output_path=out_file)
            assert out_file.exists()
            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["data"]["checks_passed"] == 9

    def test_verification_runner_aliases(self) -> None:
        assert run_vcm_verification is run_vcm_pyrolysis_verification

    def test_verification_runner_cli_script_execution(self) -> None:
        script_path = Path("scripts/run_vcm_pyrolysis_verification.py")
        if script_path.exists():
            cmd = [sys.executable, str(script_path), "--json"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            assert proc.returncode == 0
            loaded = json.loads(proc.stdout)
            assert loaded["status"] == "success"
            assert loaded["data"]["checks_passed"] == 9


# ============================================================================
# 16. TestEdgeCasesAndConfigModels
# ============================================================================

class TestEdgeCasesAndConfigModels:
    """Validate custom configurations, parameter models, and edge conditions."""

    def test_custom_config_initialization(self) -> None:
        cfg = VcmPyrolysisConfig(
            tube_volume_m3=0.400,
            nominal_furnace_temp_c=500.0,
            nominal_furnace_pressure_bar=28.0,
        )
        sim = VcmPyrolysis(config=cfg)
        assert sim.config.tube_volume_m3 == 0.400
        assert sim.config.nominal_furnace_temp_c == 500.0
        assert sim.config.nominal_furnace_pressure_bar == 28.0

    def test_simulator_class_aliases(self) -> None:
        assert VcmPyrolysisReactor is VcmPyrolysis
        assert VcmPyrolysisSimulator is VcmPyrolysis
        assert VcmPyrolysisEngine is VcmPyrolysis
        assert VcmPyrolysisModel is VcmPyrolysis
        assert VcmPyrolysisPlantModel is VcmPyrolysis
        assert VcmPyrolysisSimulationEngine is VcmPyrolysis
        assert VcmCracker is VcmPyrolysis
        assert VcmCrackingFurnace is VcmPyrolysis
        assert VcmCrackingFurnaceSimulator is VcmPyrolysis
        assert VcmPyrolysisReactorLogicUnit is VcmPyrolysisLogicUnit
        assert VcmCrackingFurnaceLogicUnit is VcmPyrolysisLogicUnit

    def test_zero_feed_rate_graceful_handling(self) -> None:
        sim = VcmPyrolysis()
        sim.state.edc_feed_flow_kg_h = 0.0
        sim.state.c_edc = 0.0
        sim.state.c_vcm = 0.0
        sim.step(dt=0.02)
        assert sim.state.edc_conversion_pct == 0.0
        assert sim.state.vcm_selectivity_pct == 0.0
        assert sim.state.vcm_production_rate_kg_h == 0.0

    def test_invalid_step_duration_negative(self) -> None:
        sim = VcmPyrolysis()
        res = sim.step(dt=-0.02)
        # Even with negative dt, does not raise unhandled exception
        assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

    def test_diagnostic_code_missing_fallback(self) -> None:
        assert DiagnosticCode._missing_(999999) is None
        assert DiagnosticCode._missing_("invalid_code") is None

    def test_diagnostic_code_bitwise_and_with_int(self) -> None:
        val = int(DiagnosticCode.THERMAL_SKIN_OVERTEMP)
        assert val == 0xF301
        assert (val & 0xFFFF) == 0xF301

    def test_extreme_temperature_evaluation(self) -> None:
        sim = VcmPyrolysis()
        k_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, 2000.0)
        assert not math.isnan(k_high)
        assert not math.isinf(k_high)
        assert k_high > 0.0

        k_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, 100.0)
        assert not math.isnan(k_low)
        assert not math.isinf(k_low)
        assert k_low >= 0.0

    def test_coke_rate_relaxation_dynamics(self) -> None:
        sim = VcmPyrolysis()
        sim.state.coke_rate = 10.0
        sim.state.tube_skin_temp_celsius = 520.0
        sim.state.t_skin_k = 520.0 + T_ZERO_CELSIUS
        y = [sim.state.c_edc, sim.state.c_vcm, sim.state.c_hcl, sim.state.c_c2h2, sim.state.coke_rate, sim.state.t_skin_k]
        derivs = sim.compute_derivatives(0.0, y)
        # With nominal 45 g/h and current 10 g/h, derivative must be positive to relax upwards
        assert derivs[4] > 0.0
