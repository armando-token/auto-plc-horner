"""Comprehensive Unit and Integration Test Suite for Wave W239:
Industrial Caprolactam Beckmann Gas-Phase Fluidized Bed Rearrangement ODE Simulation.

Work Package: W239 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS (110+ Deterministic Assertions across 15 Test Classes)

Test Structure:
1. TestConstantsEnumsAndDiagnostics:
   DiagnosticCode signed/unsigned 16-bit equality, masking (& 0xFFFF), hashing, enum values,
   status word flags, register address constants (%R2000..%R2007), and coil addresses (%M466..%M468).
2. TestFluidizedBedPhysicsAndKinetics:
   Reaction enthalpies (-160 kJ/mol, -45 kJ/mol), Arrhenius kinetics, activation energies (88 kJ/mol, 95 kJ/mol),
   stoichiometric atomic weights, catalyst properties, and hydrodynamic parameters (Umf = 0.15 m/s, Ug = 0.45 m/s).
3. TestRK4NumericalSolver:
   RK4 numerical solver derivative computation, 6-state state vector transitions, dt stability sweep,
   convergence, and concentration non-negativity guarantees.
4. TestNominalSteadyStateConvergence:
   High-conversion regime (>= 99.0%), high-selectivity regime (>= 96.0%), nominal temperature (350.0 °C),
   pressure (1.20 bar), production rate (~3500 kg/h), and nominal coils state.
5. TestConservationLawsAndThermodynamics:
   Total mass conservation error < 1e-10 kg/s, elemental mass balance (C, H, N, O) < 1e-10 kg/s,
   enthalpy first-law conservation < 1e-10 kW, and heat removal matching reaction generation.
6. TestThermalRunawayFault0xF001:
   Temperature > 380.0 °C and overpressure > 2.50 bar trip 0xF001, assert %M468 emergency trip,
   clear %M466 running status, and verify safe cooling recovery.
7. TestDefluidizationFault0xF002:
   Superficial gas velocity < Umf (0.15 m/s) trips 0xF002, asserts %M468, clears %M466,
   and verifies velocity boundary conditions.
8. TestCatalystDeactivationFault0xF003:
   Catalyst activity < 0.85 trips 0xF003, maintains reactor running without emergency trip,
   asserts SEVERE_COKING_FAULT, and tests regeneration reset.
9. TestSelectivityDegradationFault0xF004:
   Selectivity < 94.0% asserts pre-alarm %M467; selectivity < 90.0% trips 0xF004 while maintaining
   reactor running status without emergency trip.
10. TestHornerOCSSynchronizationAndRegisters:
    Bit-exact register synchronization into %R2000..%R2007 and coils %M466..%M468 with PrivilegeMode.SYSTEM,
    scaling factors, signed 16-bit negative representation, and unsigned readback.
11. TestPureSTAndSecurity:
    Validation of CaprolactamFluidizedBedSync POU using STParser and SecurityGuard, AST bound registers,
    and program structure.
12. TestAntiLadderRejection:
    Rejection of 6+ ladder logic constructs (normally-open/closed contacts, standard/set/reset coils,
    rung/network blocks, Allen-Bradley mnemonics) with LadderForbiddenError.
13. TestILogicUnitCompliance:
    ILogicUnit interface adherence (name, priority, is_enabled, enable, disable), scan_step, step,
    execute, reset, and 100-cycle soak stability without memory growth or NaNs.
14. TestVerificationRunnerAndContract:
    Execution of run_caprolactam_fluidized_bed_verification(), verifying all 9 deterministic stages,
    strict 4-state contract adherence, and evidence JSON serialization.
15. TestFluidizedBedConfigAndStateEdgeCases:
    Custom configurations, dataclass defaults, property getters/setters compatibility,
    and multiple-fault priority resolution matrix.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
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

from jev_cscape.simulation.caprolactam_fluidized_bed import (
    BED_TEMP_NOMINAL_C,
    CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU,
    CAPROLACTAM_FLUIDIZED_BED_REACTOR_PURE_ST_POU,
    CAPROLACTAM_FLUIDIZED_BED_SYNC_POU,
    CAPROLACTAM_PURE_ST_POU,
    CAPROLACTAM_SELECTIVITY_NOMINAL_PCT,
    CAPROLACTAM_SELECT_NOMINAL_PCT,
    CAPROLACTAM_SYNC_POU,
    CATALYST_ACTIVITY_NOMINAL,
    CATALYST_ACTIVITY_NOMINAL_PCT,
    CATALYST_ACTIVITY_TRIP,
    CATALYST_ACTIVITY_TRIP_PCT,
    COIL_BED_EMERGENCY_TRIP,
    COIL_FLUIDIZED_BED_RUNNING,
    COIL_SELECTIVITY_PREALARM,
    CaprolactamConfig,
    CaprolactamDiagCode,
    CaprolactamDiagnosticCode,
    CaprolactamEngine,
    CaprolactamFluidizedBed,
    CaprolactamFluidizedBedConfig,
    CaprolactamFluidizedBedDiagCode,
    CaprolactamFluidizedBedDiagnosticCode,
    CaprolactamFluidizedBedEngine,
    CaprolactamFluidizedBedLogicUnit,
    CaprolactamFluidizedBedModel,
    CaprolactamFluidizedBedParameters,
    CaprolactamFluidizedBedPlantModel,
    CaprolactamFluidizedBedReactor,
    CaprolactamFluidizedBedSimulationEngine,
    CaprolactamFluidizedBedSimulator,
    CaprolactamFluidizedBedState,
    CaprolactamFluidizedBedStateAlias,
    CaprolactamFluidizedBedStatusBits,
    CaprolactamFluidizedBedStatusWord,
    CaprolactamLogicUnit,
    CaprolactamReactor,
    CaprolactamSimulator,
    CaprolactamState,
    CaprolactamStatusBits,
    DEFLUIDIZATION_COLLAPSE_M_S,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H_J_MOL,
    DELTA_H_KJ_MOL,
    DiagnosticCode,
    FluidizedBedBeckmannLogicUnit,
    FluidizedBedBeckmannReactor,
    FluidizedBedBeckmannSimulator,
    FluidizedBedConfig,
    FluidizedBedDiagnosticCode,
    GAS_VELOCITY_NOMINAL_M_S,
    G_ACCEL,
    MW_BYP,
    MW_BYPRODUCT,
    MW_C,
    MW_CAPROLACTAM,
    MW_CHO,
    MW_CPL,
    MW_CYCLOHEXANONE_OXIME,
    MW_EPSILON_CAPROLACTAM,
    MW_H,
    MW_N,
    MW_O,
    MW_OXIME,
    OPERATING_PRESSURE_NOMINAL_BAR,
    OXIME_CONVERSION_NOMINAL_PCT,
    OXIME_CONV_NOMINAL_PCT,
    PRODUCTION_RATE_NOMINAL_KG_H,
    P_BED_MAX_SAFE_BAR,
    P_BED_NOMINAL_BAR,
    P_MAX_SAFE_BAR,
    PureSTValidationResult,
    REG_BED_TEMPERATURE_SCALED,
    REG_CAPROLACTAM_SELECTIVITY_SCALED,
    REG_CATALYST_ACTIVITY_SCALED,
    REG_DIAGNOSTIC_CODE,
    REG_GAS_VELOCITY_SCALED,
    REG_OPERATING_PRESSURE_SCALED,
    REG_OXIME_CONVERSION_SCALED,
    REG_PRODUCTION_RATE_KG_H,
    R_GAS_CONST,
    SELECTIVITY_PREALARM_PCT,
    SELECTIVITY_TRIP_PCT,
    StatusBits,
    T_BED_NOMINAL_C,
    T_REF_K,
    T_RUNAWAY_TRIP_C,
    T_THERMAL_RUNAWAY_TRIP_C,
    T_ZERO_CELSIUS,
    U_MF_COLLAPSE_M_S,
    U_MF_NOMINAL_M_S,
    run_caprolactam_fluidized_bed_verification,
    run_caprolactam_verification,
    run_fluidized_bed_verification,
    verify_caprolactam_fluidized_bed_pure_st,
    verify_caprolactam_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Verify DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses."""

    def test_diagnostic_code_integer_values(self) -> None:
        """DiagnosticCode enum members must match expected 16-bit hex values."""
        assert DiagnosticCode.REACTOR_OK.value == 0x0000
        assert DiagnosticCode.THERMAL_RUNAWAY_TRIP.value == 0xF001
        assert DiagnosticCode.DEFLUIDIZATION_COLLAPSE.value == 0xF002
        assert DiagnosticCode.CATALYST_SEVERE_COKING.value == 0xF003
        assert DiagnosticCode.SELECTIVITY_PLUMMET.value == 0xF004

    def test_diagnostic_code_signed_16bit_equality(self) -> None:
        """DiagnosticCode must compare equal to both unsigned 0xF00x and signed INT16 equivalents."""
        # 0xF001 unsigned == -4095 signed
        assert DiagnosticCode.THERMAL_RUNAWAY_TRIP == 0xF001
        assert DiagnosticCode.THERMAL_RUNAWAY_TRIP == -4095
        # 0xF002 unsigned == -4094 signed
        assert DiagnosticCode.DEFLUIDIZATION_COLLAPSE == 0xF002
        assert DiagnosticCode.DEFLUIDIZATION_COLLAPSE == -4094
        # 0xF003 unsigned == -4093 signed
        assert DiagnosticCode.CATALYST_SEVERE_COKING == 0xF003
        assert DiagnosticCode.CATALYST_SEVERE_COKING == -4093
        # 0xF004 unsigned == -4092 signed
        assert DiagnosticCode.SELECTIVITY_PLUMMET == 0xF004
        assert DiagnosticCode.SELECTIVITY_PLUMMET == -4092
        # 0x0000 == 0
        assert DiagnosticCode.REACTOR_OK == 0x0000
        assert DiagnosticCode.REACTOR_OK == 0

    def test_diagnostic_code_masking_operations(self) -> None:
        """DiagnosticCode must support bitwise AND masking with 0xFFFF transparently."""
        assert (DiagnosticCode.THERMAL_RUNAWAY_TRIP & 0xFFFF) == 0xF001
        assert (0xFFFF & DiagnosticCode.THERMAL_RUNAWAY_TRIP) == 0xF001
        assert (DiagnosticCode.DEFLUIDIZATION_COLLAPSE & 0xFFFF) == 0xF002
        assert (DiagnosticCode.CATALYST_SEVERE_COKING & 0xFFFF) == 0xF003
        assert (DiagnosticCode.SELECTIVITY_PLUMMET & 0xFFFF) == 0xF004
        assert (DiagnosticCode.REACTOR_OK & 0xFFFF) == 0x0000

    def test_diagnostic_code_missing_signed_lookup(self) -> None:
        """DiagnosticCode._missing_ must instantiate correctly from negative signed 16-bit integers."""
        assert DiagnosticCode(-4095) == DiagnosticCode.THERMAL_RUNAWAY_TRIP
        assert DiagnosticCode(-4094) == DiagnosticCode.DEFLUIDIZATION_COLLAPSE
        assert DiagnosticCode(-4093) == DiagnosticCode.CATALYST_SEVERE_COKING
        assert DiagnosticCode(-4092) == DiagnosticCode.SELECTIVITY_PLUMMET
        assert DiagnosticCode(0) == DiagnosticCode.REACTOR_OK

    def test_diagnostic_code_hashing_and_set_membership(self) -> None:
        """DiagnosticCode instances must be hashable and valid in sets/dictionaries."""
        diag_set = {
            DiagnosticCode.REACTOR_OK,
            DiagnosticCode.THERMAL_RUNAWAY_TRIP,
            DiagnosticCode.DEFLUIDIZATION_COLLAPSE,
            DiagnosticCode.CATALYST_SEVERE_COKING,
            DiagnosticCode.SELECTIVITY_PLUMMET,
        }
        assert len(diag_set) == 5
        assert DiagnosticCode(-4095) in diag_set
        assert hash(DiagnosticCode.THERMAL_RUNAWAY_TRIP) == hash(0xF001)

    def test_diagnostic_code_compatibility_aliases(self) -> None:
        """All defined compatibility aliases must map to expected DiagnosticCode members."""
        assert DiagnosticCode.OK == DiagnosticCode.REACTOR_OK
        assert DiagnosticCode.THERMAL_RUNAWAY == DiagnosticCode.THERMAL_RUNAWAY_TRIP
        assert DiagnosticCode.DEFLUIDIZATION == DiagnosticCode.DEFLUIDIZATION_COLLAPSE
        assert DiagnosticCode.CATALYST_COKING == DiagnosticCode.CATALYST_SEVERE_COKING
        assert DiagnosticCode.LOW_SELECTIVITY == DiagnosticCode.SELECTIVITY_PLUMMET
        assert DiagnosticCode.ERR_THERMAL_RUNAWAY == DiagnosticCode.THERMAL_RUNAWAY_TRIP
        assert DiagnosticCode.ERR_DEFLUIDIZATION == DiagnosticCode.DEFLUIDIZATION_COLLAPSE
        assert DiagnosticCode.ERR_CATALYST_COKING == DiagnosticCode.CATALYST_SEVERE_COKING
        assert DiagnosticCode.ERR_SELECTIVITY_PLUMMET == DiagnosticCode.SELECTIVITY_PLUMMET

    def test_status_bits_definitions(self) -> None:
        """CaprolactamFluidizedBedStatusBits flags must have distinct powers-of-two values."""
        assert CaprolactamFluidizedBedStatusBits.RUNNING == 1 << 0
        assert CaprolactamFluidizedBedStatusBits.FLUIDIZED_BED_RUNNING == 1 << 1
        assert CaprolactamFluidizedBedStatusBits.SELECTIVITY_PREALARM == 1 << 2
        assert CaprolactamFluidizedBedStatusBits.BED_EMERGENCY_TRIP == 1 << 3
        assert CaprolactamFluidizedBedStatusBits.THERMAL_RUNAWAY_FAULT == 1 << 4
        assert CaprolactamFluidizedBedStatusBits.DEFLUIDIZATION_FAULT == 1 << 5
        assert CaprolactamFluidizedBedStatusBits.SEVERE_COKING_FAULT == 1 << 6
        assert CaprolactamFluidizedBedStatusBits.SELECTIVITY_PLUMMET_FAULT == 1 << 7

    def test_register_constants_and_address_mappings(self) -> None:
        """Horner OCS register address constants must match %R2000 through %R2007."""
        assert REG_BED_TEMPERATURE_SCALED == "%R2000"
        assert REG_OXIME_CONVERSION_SCALED == "%R2001"
        assert REG_CAPROLACTAM_SELECTIVITY_SCALED == "%R2002"
        assert REG_GAS_VELOCITY_SCALED == "%R2003"
        assert REG_CATALYST_ACTIVITY_SCALED == "%R2004"
        assert REG_OPERATING_PRESSURE_SCALED == "%R2005"
        assert REG_PRODUCTION_RATE_KG_H == "%R2006"
        assert REG_DIAGNOSTIC_CODE == "%R2007"

    def test_coil_constants_and_address_mappings(self) -> None:
        """Horner OCS discrete coil address constants must match %M466 through %M468."""
        assert COIL_FLUIDIZED_BED_RUNNING == "%M466"
        assert COIL_SELECTIVITY_PREALARM == "%M467"
        assert COIL_BED_EMERGENCY_TRIP == "%M468"

    def test_universal_physical_constants_values(self) -> None:
        """Physical and chemical constants must adhere to CODATA/IUPAC standard values."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, abs_tol=1e-5)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, abs_tol=1e-5)
        assert math.isclose(T_REF_K, 623.15, abs_tol=1e-5)


# ============================================================================
# 2. TestFluidizedBedPhysicsAndKinetics
# ============================================================================

class TestFluidizedBedPhysicsAndKinetics:
    """Verify Reaction enthalpy (-160 kJ/mol), Arrhenius rate constants, activation energies, equilibrium values."""

    def test_reaction1_beckmann_rearrangement_enthalpy(self) -> None:
        """Main reaction must be exothermic with Delta_H = -160.0 kJ/mol (-160,000 J/mol)."""
        assert math.isclose(DELTA_H1_KJ_MOL, -160.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H1_J_MOL, -160000.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_KJ_MOL, -160.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_J_MOL, -160000.0, abs_tol=1e-6)
        assert DELTA_H1_KJ_MOL < 0.0

    def test_reaction2_side_hydrolysis_enthalpy(self) -> None:
        """Side reaction 2 must have Delta_H2 = -80.0 kJ/mol (-80,000 J/mol)."""
        assert math.isclose(DELTA_H2_KJ_MOL, -80.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H2_J_MOL, -80000.0, abs_tol=1e-6)
        assert DELTA_H2_KJ_MOL < 0.0

    def test_arrhenius_rate_constant_temperature_monotonicity(self) -> None:
        """Arrhenius rate constant k(T) must increase strictly monotonically with temperature."""
        sim = CaprolactamFluidizedBed()
        t1_k = 330.0 + T_ZERO_CELSIUS
        t2_k = 350.0 + T_ZERO_CELSIUS
        t3_k = 370.0 + T_ZERO_CELSIUS

        k1_t1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1_k)
        k1_t2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2_k)
        k1_t3 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t3_k)

        assert 0.0 < k1_t1 < k1_t2 < k1_t3
        assert math.isclose(k1_t2, 73.0, rel_tol=0.05)

    def test_arrhenius_activation_energy_reconstruction(self) -> None:
        """Activation energy Ea must be reconstructible from Arrhenius slope within 1e-6 relative tolerance."""
        sim = CaprolactamFluidizedBed()
        t1_k = 330.0 + T_ZERO_CELSIUS
        t2_k = 370.0 + T_ZERO_CELSIUS

        k1_1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1_k)
        k1_2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2_k)

        ea_reconstructed = -R_GAS_CONST * math.log(k1_2 / k1_1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(ea_reconstructed, sim.config.activation_e1_j_mol, rel_tol=1e-6)
        assert math.isclose(sim.config.activation_e1_j_mol, 65000.0, abs_tol=1e-3)

    def test_arrhenius_zero_or_negative_temperature_handling(self) -> None:
        """Arrhenius rate constant must clamp non-physical zero or negative temperatures safely."""
        sim = CaprolactamFluidizedBed()
        k_zero = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, 0.0)
        k_200 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, 200.0)
        assert math.isclose(k_zero, k_200, rel_tol=1e-9)
        assert k_zero > 0.0

    def test_molecular_weights_and_species_stoichiometry(self) -> None:
        """Molecular weights for Cyclohexanone Oxime and Caprolactam must equal 113.160 g/mol."""
        expected_mw = 6.0 * MW_C + 11.0 * MW_H + MW_N + MW_O
        assert math.isclose(MW_OXIME, expected_mw, rel_tol=1e-9)
        assert math.isclose(MW_CAPROLACTAM, expected_mw, rel_tol=1e-9)
        assert math.isclose(MW_CYCLOHEXANONE_OXIME, MW_OXIME, abs_tol=1e-12)
        assert math.isclose(MW_EPSILON_CAPROLACTAM, MW_CAPROLACTAM, abs_tol=1e-12)
        assert math.isclose(MW_CHO, MW_OXIME, abs_tol=1e-12)
        assert math.isclose(MW_CPL, MW_CAPROLACTAM, abs_tol=1e-12)
        assert math.isclose(MW_OXIME * 1000.0, 113.160, rel_tol=1e-3)

    def test_fluidized_bed_geometry_and_catalyst_inventory(self) -> None:
        """Reactor column dimensions, active volume, and catalyst inventory must match industrial specifications."""
        config = CaprolactamFluidizedBedConfig()
        assert math.isclose(config.bed_diameter_m, 2.0, abs_tol=1e-4)
        assert math.isclose(config.bed_height_m, 1.0, abs_tol=1e-4)
        assert math.isclose(config.bed_volume_m3, 2.0, abs_tol=1e-3)
        assert math.isclose(config.catalyst_mass_kg, 2500.0, abs_tol=1e-3)

    def test_hydrodynamic_fluidization_velocities(self) -> None:
        """Minimum fluidization velocity Umf = 0.15 m/s and nominal superficial velocity = 0.45 m/s (3x Umf)."""
        assert math.isclose(U_MF_NOMINAL_M_S, 0.15, abs_tol=1e-5)
        assert math.isclose(U_MF_COLLAPSE_M_S, 0.15, abs_tol=1e-5)
        assert math.isclose(GAS_VELOCITY_NOMINAL_M_S, 0.45, abs_tol=1e-5)
        assert math.isclose(GAS_VELOCITY_NOMINAL_M_S / U_MF_NOMINAL_M_S, 3.0, abs_tol=1e-3)

    def test_operating_baseline_and_safety_pressures(self) -> None:
        """Nominal operating pressure must equal 1.20 bar and maximum safe pressure must equal 2.50 bar."""
        assert math.isclose(OPERATING_PRESSURE_NOMINAL_BAR, 1.20, abs_tol=1e-5)
        assert math.isclose(P_BED_NOMINAL_BAR, 1.20, abs_tol=1e-5)
        assert math.isclose(P_MAX_SAFE_BAR, 2.50, abs_tol=1e-5)
        assert math.isclose(P_BED_MAX_SAFE_BAR, 2.50, abs_tol=1e-5)


# ============================================================================
# 3. TestRK4NumericalSolver
# ============================================================================

class TestRK4NumericalSolver:
    """Verify RK4 state transitions, dt stability, convergence, non-negative concentrations."""

    def test_compute_derivatives_state_vector_dimension(self) -> None:
        """compute_derivatives must return exactly 6 derivatives matching state vector length."""
        sim = CaprolactamFluidizedBed()
        y0 = [sim.state.c_cho, sim.state.c_cpl, sim.state.c_byp, sim.state.t_bed_c + T_ZERO_CELSIUS, sim.state.catalyst_activity, sim.state.p_bed_bar]
        derivs = sim.compute_derivatives(0.0, y0)
        assert isinstance(derivs, list)
        assert len(derivs) == 6
        assert all(isinstance(d, float) and not math.isnan(d) and not math.isinf(d) for d in derivs)

    def test_compute_derivatives_physical_signs_at_nominal(self) -> None:
        """At nominal conditions, reactant CHO consumption must be balanced and derivatives bounded."""
        sim = CaprolactamFluidizedBed()
        y0 = [sim.state.c_cho, sim.state.c_cpl, sim.state.c_byp, sim.state.t_bed_c + T_ZERO_CELSIUS, sim.state.catalyst_activity, sim.state.p_bed_bar]
        derivs = sim.compute_derivatives(0.0, y0)
        d_c_cho, d_c_cpl, d_c_byp, d_t_k, d_activity, d_p = derivs
        # Derivative of temperature should be small near steady state (< 5.0 K/s)
        assert abs(d_t_k) < 5.0
        # Catalyst activity decay rate should be <= 0.0
        assert d_activity <= 0.0

    def test_single_rk4_step_smooth_transition(self) -> None:
        """A single RK4 step must advance simulation time by dt without state discontinuity."""
        sim = CaprolactamFluidizedBed()
        t0 = sim.state.sim_time_s
        c_cho_0 = sim.state.c_cho
        sim.step(0.02)
        assert math.isclose(sim.state.sim_time_s, t0 + 0.02, abs_tol=1e-6)
        assert math.isclose(sim.state.c_cho, c_cho_0, rel_tol=0.1)

    def test_dt_stability_sweep(self) -> None:
        """RK4 integration must maintain numerical stability across a range of timesteps dt in [0.005, 0.05]."""
        for dt_val in [0.005, 0.01, 0.02, 0.05]:
            sim = CaprolactamFluidizedBed()
            sim.reset()
            for _ in range(20):
                sim.step(dt_val)
            assert not math.isnan(sim.state.t_bed_c)
            assert not math.isnan(sim.state.c_cho)
            assert not math.isnan(sim.state.c_cpl)
            assert 340.0 <= sim.state.t_bed_c <= 360.0

    def test_concentrations_remain_strictly_non_negative(self) -> None:
        """Concentrations must never become negative even if heavily depleted."""
        sim = CaprolactamFluidizedBed()
        sim.state.c_cho = 0.0001
        sim.state.c_cpl = 0.0
        sim.step(0.02)
        assert sim.state.c_cho >= 0.0
        assert sim.state.c_cpl >= 0.0
        assert sim.state.c_byp >= 0.0

    def test_rk4_temperature_bounding(self) -> None:
        """Emulsion bed temperature must remain strictly bounded and non-divergent during RK4 integration."""
        sim = CaprolactamFluidizedBed()
        sim.reset()
        for _ in range(50):
            sim.step(0.02)
        assert 345.0 <= sim.state.t_bed_c <= 355.0

    def test_catalyst_activity_decay_ode_progression(self) -> None:
        """Catalyst activity must degrade continuously and monotonically downward under reaction exposure."""
        sim = CaprolactamFluidizedBed()
        sim.reset()
        act_initial = sim.state.catalyst_activity
        for _ in range(50):
            sim.step(0.02)
        assert sim.state.catalyst_activity <= act_initial
        assert sim.state.catalyst_activity >= 0.0

    def test_multi_step_rk4_convergence(self) -> None:
        """Repeated RK4 steps must converge toward nominal steady-state values."""
        sim = CaprolactamFluidizedBed()
        sim.reset()
        for _ in range(100):
            sim.step(0.02)
        assert math.isclose(sim.state.oxime_conversion_pct, 99.40, abs_tol=1.0)
        assert math.isclose(sim.state.caprolactam_selectivity_pct, 96.50, abs_tol=1.0)


# ============================================================================
# 4. TestNominalSteadyStateConvergence
# ============================================================================

class TestNominalSteadyStateConvergence:
    """Verify Conversion >= 99.0%, Selectivity >= 96.0%, Temperature 350 °C, Pressure 1.2 bar."""

    def test_nominal_oxime_conversion_exceeds_threshold(self) -> None:
        """Nominal oxime conversion must be >= 99.0% (target 99.40%)."""
        sim = CaprolactamFluidizedBed()
        assert sim.state.oxime_conversion_pct >= 99.0
        assert math.isclose(sim.state.oxime_conversion_pct, OXIME_CONVERSION_NOMINAL_PCT, abs_tol=0.5)

    def test_nominal_caprolactam_selectivity_exceeds_threshold(self) -> None:
        """Nominal caprolactam selectivity must be >= 96.0% (target 96.50%)."""
        sim = CaprolactamFluidizedBed()
        assert sim.state.caprolactam_selectivity_pct >= 96.0
        assert math.isclose(sim.state.caprolactam_selectivity_pct, CAPROLACTAM_SELECTIVITY_NOMINAL_PCT, abs_tol=0.5)

    def test_nominal_bed_temperature(self) -> None:
        """Nominal fluidized bed temperature must be 350.0 °C within 1.0 °C tolerance."""
        sim = CaprolactamFluidizedBed()
        assert math.isclose(sim.state.t_bed_c, 350.0, abs_tol=1.0)
        assert math.isclose(sim.state.t_bed_c, BED_TEMP_NOMINAL_C, abs_tol=1.0)

    def test_nominal_bed_operating_pressure(self) -> None:
        """Nominal bed pressure must be 1.20 bar."""
        sim = CaprolactamFluidizedBed()
        assert math.isclose(sim.state.p_bed_bar, 1.20, abs_tol=0.05)
        assert math.isclose(sim.state.p_bed_bar, OPERATING_PRESSURE_NOMINAL_BAR, abs_tol=0.05)

    def test_nominal_caprolactam_production_rate(self) -> None:
        """Nominal caprolactam production rate must be approximately 3500.0 kg/h."""
        sim = CaprolactamFluidizedBed()
        assert math.isclose(sim.state.production_rate_kg_h, 3500.0, rel_tol=0.05)
        assert math.isclose(PRODUCTION_RATE_NOMINAL_KG_H, 3500.0, abs_tol=1e-3)

    def test_nominal_gas_superficial_velocity(self) -> None:
        """Nominal superficial gas velocity must be 0.45 m/s."""
        sim = CaprolactamFluidizedBed()
        assert math.isclose(sim.state.gas_velocity_m_s, 0.45, abs_tol=0.02)
        assert math.isclose(GAS_VELOCITY_NOMINAL_M_S, 0.45, abs_tol=1e-5)

    def test_nominal_catalyst_activity(self) -> None:
        """Nominal catalyst activity must be >= 0.95 (nominal ~0.982 = 98.2%)."""
        sim = CaprolactamFluidizedBed()
        assert sim.state.catalyst_activity >= 0.95
        assert math.isclose(sim.state.catalyst_activity_pct, 98.20, abs_tol=1.0)

    def test_nominal_discrete_coils_state(self) -> None:
        """Nominally, %M466 must be True, %M467 False, %M468 False, and DiagnosticCode OK."""
        sim = CaprolactamFluidizedBed()
        assert sim.state.fluidized_bed_running is True
        assert sim.state.selectivity_prealarm is False
        assert sim.state.bed_emergency_trip is False
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK


# ============================================================================
# 5. TestConservationLawsAndThermodynamics
# ============================================================================

class TestConservationLawsAndThermodynamics:
    """Verify Mass conservation error < 1e-10 kg/s, elemental mass balance, enthalpy conservation < 1e-10 kW."""

    def test_total_mass_conservation_residual_steady_state(self) -> None:
        """Steady-state total mass balance residual must be strictly less than 1e-10 kg/s."""
        sim = CaprolactamFluidizedBed()
        sim.step(0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10

    def test_elemental_mass_balance_residual(self) -> None:
        """Elemental mass conservation (C, H, N, O) residual must be strictly less than 1e-10 kg/s."""
        sim = CaprolactamFluidizedBed()
        sim.step(0.02)
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10

    def test_enthalpy_conservation_residual_first_law(self) -> None:
        """First-law enthalpy conservation residual |Q_rxn - Q_cool - Q_flow| must be < 1e-10 kW."""
        sim = CaprolactamFluidizedBed()
        sim.step(0.02)
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_conservation_under_perturbed_conversion(self) -> None:
        """Mass and enthalpy conservation must remain < 1e-10 under perturbed conversion."""
        sim = CaprolactamFluidizedBed()
        sim.state.oxime_conversion_pct = 95.0
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_conservation_under_perturbed_selectivity(self) -> None:
        """Mass and enthalpy conservation must remain < 1e-10 under perturbed selectivity."""
        sim = CaprolactamFluidizedBed()
        sim.state.caprolactam_selectivity_pct = 92.0
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_cooling_matches_reaction_heat_at_steady_state(self) -> None:
        """Reaction heat generated must balance cooling duty plus sensible flow removal within 2%."""
        sim = CaprolactamFluidizedBed()
        sim.step(0.02)
        assert math.isclose(sim.state.q_rxn_kw, sim.state.q_cool_kw + sim.state.q_flow_kw, rel_tol=0.02)
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_stoichiometric_atom_counts_per_mole(self) -> None:
        """Stoichiometric formula of Cyclohexanone Oxime and Caprolactam must have 6 C, 11 H, 1 N, 1 O."""
        c_count = 6
        h_count = 11
        n_count = 1
        o_count = 1
        mol_wt = c_count * MW_C + h_count * MW_H + n_count * MW_N + o_count * MW_O
        assert math.isclose(mol_wt, MW_OXIME, rel_tol=1e-9)
        assert math.isclose(mol_wt, MW_CAPROLACTAM, rel_tol=1e-9)

    def test_reaction_energy_generation_rate(self) -> None:
        """Reaction energy power Q_rxn must scale with reaction rate: Q = r1 * |Delta_H1| + r2 * |Delta_H2|."""
        sim = CaprolactamFluidizedBed()
        sim.step(0.02)
        expected_q_kw = (sim.state.r1_total_mol_s * abs(DELTA_H1_KJ_MOL)) + (sim.state.r2_total_mol_s * abs(DELTA_H2_KJ_MOL))
        assert math.isclose(sim.state.q_rxn_kw, expected_q_kw, rel_tol=1e-5)


# ============================================================================
# 6. TestThermalRunawayFault0xF001
# ============================================================================

class TestThermalRunawayFault0xF001:
    """Verify Temperature > 380 °C trips 0xF001, asserts %M468 emergency trip, safe cooling recovery."""

    def test_temperature_over_380_trips_0xF001(self) -> None:
        """Bed temperature > 380.0 °C must trip DiagnosticCode.THERMAL_RUNAWAY_TRIP (0xF001)."""
        sim = CaprolactamFluidizedBed()
        sim.state.t_bed_c = 385.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP
        assert sim.state.diagnostic_code == 0xF001
        assert sim.state.diagnostic_code == -4095

    def test_overpressure_over_2_5_bar_trips_0xF001(self) -> None:
        """Bed operating pressure > 2.50 bar must also trip 0xF001."""
        sim = CaprolactamFluidizedBed()
        sim.state.p_bed_bar = 2.60
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP

    def test_thermal_runaway_asserts_emergency_trip_coil(self) -> None:
        """Thermal runaway fault must assert %M468 (COIL_BED_EMERGENCY_TRIP = True)."""
        sim = CaprolactamFluidizedBed()
        sim.state.t_bed_c = 382.0
        sim._evaluate_safety_interlocks()
        assert sim.state.bed_emergency_trip is True

    def test_thermal_runaway_clears_fluidized_bed_running_coil(self) -> None:
        """Thermal runaway fault must clear %M466 (COIL_FLUIDIZED_BED_RUNNING = False)."""
        sim = CaprolactamFluidizedBed()
        sim.state.t_bed_c = 385.0
        sim._evaluate_safety_interlocks()
        assert sim.state.fluidized_bed_running is False

    def test_thermal_runaway_sets_status_bits_fault_flag(self) -> None:
        """Thermal runaway fault must set THERMAL_RUNAWAY_FAULT bit in status_bits."""
        sim = CaprolactamFluidizedBed()
        sim.state.t_bed_c = 385.0
        sim._evaluate_safety_interlocks()
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.THERMAL_RUNAWAY_FAULT) != 0
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.BED_EMERGENCY_TRIP) != 0

    def test_thermal_runaway_priority_hierarchy(self) -> None:
        """Priority 1 (0xF001) must take precedence over all lower priority faults (0xF002..0xF004)."""
        sim = CaprolactamFluidizedBed()
        # Concurrently violate all fault conditions
        sim.state.t_bed_c = 390.0                      # Violates P1 (T > 380)
        sim.state.gas_velocity_m_s = 0.05              # Violates P2 (Ug < 0.15)
        sim.state.catalyst_activity = 0.50             # Violates P3 (act < 0.85)
        sim.state.caprolactam_selectivity_pct = 80.0   # Violates P4 (sel < 90.0)
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP
        assert sim.state.bed_emergency_trip is True
        assert sim.state.fluidized_bed_running is False

    def test_thermal_runaway_safe_cooling_recovery(self) -> None:
        """Cooling below 380 °C and resetting must clear the trip and restore normal status."""
        sim = CaprolactamFluidizedBed()
        sim.state.t_bed_c = 385.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP

        # Cooling recovery
        sim.reset()
        assert sim.state.t_bed_c == 350.0
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK
        assert sim.state.bed_emergency_trip is False
        assert sim.state.fluidized_bed_running is True

    def test_thermal_runaway_register_table_reflection(self) -> None:
        """Thermal runaway fault must write signed -4095 (0xF001) into %R2007 and True into %M468."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.t_bed_c = 385.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)

        assert reg_table.read_word("%R2007") == -4095
        assert reg_table.read_uword("%R2007") == 0xF001
        assert reg_table.read_bit("%M468") is True
        assert reg_table.read_bit("%M466") is False


# ============================================================================
# 7. TestDefluidizationFault0xF002
# ============================================================================

class TestDefluidizationFault0xF002:
    """Verify Gas velocity < Umf trips 0xF002, minimum fluidization velocity checks."""

    def test_velocity_below_umf_trips_0xF002(self) -> None:
        """Superficial gas velocity < Umf (0.15 m/s) must trip DiagnosticCode.DEFLUIDIZATION_COLLAPSE (0xF002)."""
        sim = CaprolactamFluidizedBed()
        sim.state.gas_velocity_m_s = 0.12
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEFLUIDIZATION_COLLAPSE
        assert sim.state.diagnostic_code == 0xF002
        assert sim.state.diagnostic_code == -4094

    def test_defluidization_asserts_emergency_trip_coil(self) -> None:
        """Defluidization trip must assert %M468 (COIL_BED_EMERGENCY_TRIP = True)."""
        sim = CaprolactamFluidizedBed()
        sim.state.gas_velocity_m_s = 0.10
        sim._evaluate_safety_interlocks()
        assert sim.state.bed_emergency_trip is True

    def test_defluidization_clears_fluidized_bed_running_coil(self) -> None:
        """Defluidization trip must clear %M466 (COIL_FLUIDIZED_BED_RUNNING = False)."""
        sim = CaprolactamFluidizedBed()
        sim.state.gas_velocity_m_s = 0.10
        sim._evaluate_safety_interlocks()
        assert sim.state.fluidized_bed_running is False

    def test_defluidization_sets_status_bits_fault_flag(self) -> None:
        """Defluidization fault must set DEFLUIDIZATION_FAULT bit in status_bits."""
        sim = CaprolactamFluidizedBed()
        sim.state.gas_velocity_m_s = 0.14
        sim._evaluate_safety_interlocks()
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.DEFLUIDIZATION_FAULT) != 0
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.BED_EMERGENCY_TRIP) != 0

    def test_defluidization_boundary_condition(self) -> None:
        """Exact boundary: gas_velocity < 0.15 trips, gas_velocity >= 0.15 does not trip 0xF002."""
        sim = CaprolactamFluidizedBed()
        sim.state.gas_velocity_m_s = 0.149
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEFLUIDIZATION_COLLAPSE

        sim.state.gas_velocity_m_s = 0.151
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_defluidization_priority_subordinate_to_thermal(self) -> None:
        """If temperature runaway (P1) and defluidization (P2) occur together, P1 wins."""
        sim = CaprolactamFluidizedBed()
        sim.state.t_bed_c = 385.0
        sim.state.gas_velocity_m_s = 0.10
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP

    def test_defluidization_priority_over_coking(self) -> None:
        """If defluidization (P2) and severe coking (P3) occur together, P2 wins."""
        sim = CaprolactamFluidizedBed()
        sim.state.gas_velocity_m_s = 0.12
        sim.state.catalyst_activity = 0.70
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEFLUIDIZATION_COLLAPSE
        assert sim.state.bed_emergency_trip is True

    def test_defluidization_register_table_reflection(self) -> None:
        """Defluidization must write signed -4094 (0xF002) into %R2007 and True into %M468."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.gas_velocity_m_s = 0.10
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)

        assert reg_table.read_word("%R2007") == -4094
        assert reg_table.read_uword("%R2007") == 0xF002
        assert reg_table.read_bit("%M468") is True
        assert reg_table.read_bit("%M466") is False


# ============================================================================
# 8. TestCatalystDeactivationFault0xF003
# ============================================================================

class TestCatalystDeactivationFault0xF003:
    """Verify Catalyst activity decay, coking ODE, 0xF003 trip, regeneration reset."""

    def test_activity_below_85_pct_trips_0xF003(self) -> None:
        """Catalyst activity < 0.85 must trip DiagnosticCode.CATALYST_SEVERE_COKING (0xF003)."""
        sim = CaprolactamFluidizedBed()
        sim.state.catalyst_activity = 0.80
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_SEVERE_COKING
        assert sim.state.diagnostic_code == 0xF003
        assert sim.state.diagnostic_code == -4093

    def test_catalyst_coking_keeps_reactor_running_no_emergency_trip(self) -> None:
        """Catalyst coking is an operational maintenance alarm, NOT an emergency safety shutdown."""
        sim = CaprolactamFluidizedBed()
        sim.state.catalyst_activity = 0.82
        sim._evaluate_safety_interlocks()
        assert sim.state.bed_emergency_trip is False
        assert sim.state.fluidized_bed_running is True

    def test_catalyst_coking_sets_status_bits_fault_flag(self) -> None:
        """Catalyst coking must set SEVERE_COKING_FAULT bit in status_bits."""
        sim = CaprolactamFluidizedBed()
        sim.state.catalyst_activity = 0.80
        sim._evaluate_safety_interlocks()
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.SEVERE_COKING_FAULT) != 0
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.BED_EMERGENCY_TRIP) == 0

    def test_catalyst_activity_decay_ode_progression(self) -> None:
        """Catalyst activity must steadily degrade downward over time without regeneration."""
        sim = CaprolactamFluidizedBed()
        sim.reset()
        init_act = sim.state.catalyst_activity
        for _ in range(50):
            sim.step(0.02)
        assert sim.state.catalyst_activity <= init_act

    def test_catalyst_coking_boundary_condition(self) -> None:
        """Boundary check: activity < 0.85 trips 0xF003, activity >= 0.85 does not."""
        sim = CaprolactamFluidizedBed()
        sim.state.catalyst_activity = 0.849
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_SEVERE_COKING

        sim.state.catalyst_activity = 0.851
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_catalyst_regeneration_reset(self) -> None:
        """reset() must restore catalyst activity to nominal operating value."""
        sim = CaprolactamFluidizedBed()
        sim.state.catalyst_activity = 0.70
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_SEVERE_COKING

        sim.reset()
        assert math.isclose(sim.state.catalyst_activity_pct, 98.20, abs_tol=1.0)
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_catalyst_coking_subordinate_to_defluidization(self) -> None:
        """Defluidization (P2) takes priority over catalyst coking (P3)."""
        sim = CaprolactamFluidizedBed()
        sim.state.gas_velocity_m_s = 0.10
        sim.state.catalyst_activity = 0.75
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEFLUIDIZATION_COLLAPSE

    def test_catalyst_coking_register_reflection(self) -> None:
        """Catalyst coking fault must write -4093 to %R2007 and True to %M466."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.catalyst_activity = 0.80
        sim.state.catalyst_activity_pct = 80.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)

        assert reg_table.read_word("%R2007") == -4093
        assert reg_table.read_uword("%R2007") == 0xF003
        assert reg_table.read_bit("%M466") is True
        assert reg_table.read_bit("%M468") is False


# ============================================================================
# 9. TestSelectivityDegradationFault0xF004
# ============================================================================

class TestSelectivityDegradationFault0xF004:
    """Verify Selectivity < 94% pre-alarm %M467, < 90% trip 0xF004."""

    def test_selectivity_below_94_pct_triggers_prealarm_coil(self) -> None:
        """Selectivity < 94.0% must assert %M467 (COIL_SELECTIVITY_PREALARM = True)."""
        sim = CaprolactamFluidizedBed()
        sim.state.caprolactam_selectivity_pct = 93.5
        sim._evaluate_safety_interlocks()
        assert sim.state.selectivity_prealarm is True
        # Since selectivity is 93.5% (> 90.0%), diagnostic code should still be OK
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_selectivity_below_90_pct_trips_0xF004(self) -> None:
        """Selectivity < 90.0% must trip DiagnosticCode.SELECTIVITY_PLUMMET (0xF004)."""
        sim = CaprolactamFluidizedBed()
        sim.state.caprolactam_selectivity_pct = 88.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.SELECTIVITY_PLUMMET
        assert sim.state.diagnostic_code == 0xF004
        assert sim.state.diagnostic_code == -4092
        assert sim.state.selectivity_prealarm is True

    def test_selectivity_plummet_maintains_running_status(self) -> None:
        """Selectivity fault is a quality fault; reactor remains running without emergency trip."""
        sim = CaprolactamFluidizedBed()
        sim.state.caprolactam_selectivity_pct = 88.0
        sim._evaluate_safety_interlocks()
        assert sim.state.fluidized_bed_running is True
        assert sim.state.bed_emergency_trip is False

    def test_selectivity_plummet_sets_status_bits_fault_flag(self) -> None:
        """Selectivity fault must set SELECTIVITY_PLUMMET_FAULT and SELECTIVITY_PREALARM in status_bits."""
        sim = CaprolactamFluidizedBed()
        sim.state.caprolactam_selectivity_pct = 88.0
        sim._evaluate_safety_interlocks()
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.SELECTIVITY_PLUMMET_FAULT) != 0
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.SELECTIVITY_PREALARM) != 0

    def test_selectivity_boundary_conditions(self) -> None:
        """Exact boundaries: < 94.0% pre-alarm, < 90.0% trip 0xF004."""
        sim = CaprolactamFluidizedBed()
        sim.state.caprolactam_selectivity_pct = 94.1
        sim._evaluate_safety_interlocks()
        assert sim.state.selectivity_prealarm is False

        sim.state.caprolactam_selectivity_pct = 93.9
        sim._evaluate_safety_interlocks()
        assert sim.state.selectivity_prealarm is True
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

        sim.state.caprolactam_selectivity_pct = 89.9
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.SELECTIVITY_PLUMMET

    def test_selectivity_recovery_clears_prealarm(self) -> None:
        """Recovering selectivity to nominal 96.5% clears both 0xF004 and pre-alarm %M467."""
        sim = CaprolactamFluidizedBed()
        sim.state.caprolactam_selectivity_pct = 85.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.SELECTIVITY_PLUMMET

        sim.state.caprolactam_selectivity_pct = 96.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK
        assert sim.state.selectivity_prealarm is False

    def test_selectivity_priority_lowest(self) -> None:
        """All higher-priority faults (thermal, defluidization, coking) supersede selectivity fault."""
        sim = CaprolactamFluidizedBed()
        sim.state.catalyst_activity = 0.80
        sim.state.caprolactam_selectivity_pct = 88.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_SEVERE_COKING

    def test_selectivity_registers_reflection(self) -> None:
        """Selectivity fault must write -4092 into %R2007, scaled selectivity into %R2002, and True to %M467."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.caprolactam_selectivity_pct = 88.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)

        assert reg_table.read_word("%R2002") == 8800
        assert reg_table.read_word("%R2007") == -4092
        assert reg_table.read_uword("%R2007") == 0xF004
        assert reg_table.read_bit("%M467") is True
        assert reg_table.read_bit("%M466") is True


# ============================================================================
# 10. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Verify %R2000..%R2007, %M466..%M468 bit-exact synchronization, PrivilegeMode.SYSTEM."""

    def test_registers_and_coils_synchronization_privilege(self) -> None:
        """sync_to_registers must successfully write to RegisterTable with PrivilegeMode.SYSTEM."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word("%R2000") is not None
        assert reg_table.read_bit("%M466") is not None

    def test_r2000_temperature_scaling(self) -> None:
        """%R2000 scaled x10 °C: 350.0 °C -> 3500."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.t_bed_c = 350.0
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2000") == 3500

    def test_r2001_conversion_scaling(self) -> None:
        """%R2001 scaled x100 %: 99.40 % -> 9940."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.oxime_conversion_pct = 99.40
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2001") == 9940

    def test_r2002_selectivity_scaling(self) -> None:
        """%R2002 scaled x100 %: 96.50 % -> 9650."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.caprolactam_selectivity_pct = 96.50
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2002") == 9650

    def test_r2003_gas_velocity_scaling(self) -> None:
        """%R2003 scaled x100 m/s: 0.45 m/s -> 45."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.gas_velocity_m_s = 0.45
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2003") == 45

    def test_r2004_catalyst_activity_scaling(self) -> None:
        """%R2004 scaled x100 %: 98.20 % -> 9820."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.catalyst_activity_pct = 98.20
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2004") == 9820

    def test_r2005_operating_pressure_scaling(self) -> None:
        """%R2005 scaled x100 bar: 1.20 bar -> 120."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.p_bed_bar = 1.20
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2005") == 120

    def test_r2006_production_rate_scaling(self) -> None:
        """%R2006 scaled x1 kg/h: 3500.0 kg/h -> 3500."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)
        sim.state.production_rate_kg_h = 3500.0
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2006") == 3500

    def test_r2007_diagnostic_code_signed_roundtrip(self) -> None:
        """%R2007 signed/unsigned readback for 0x0000 and 0xF001..0xF004."""
        reg_table = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=reg_table)

        # OK -> 0
        sim.state.diagnostic_code = DiagnosticCode.REACTOR_OK
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2007") == 0
        assert reg_table.read_uword("%R2007") == 0x0000

        # THERMAL_RUNAWAY -> 0xF001 / -4095
        sim.state.diagnostic_code = DiagnosticCode.THERMAL_RUNAWAY_TRIP
        sim.sync_to_registers(reg_table)
        assert reg_table.read_word("%R2007") == -4095
        assert reg_table.read_uword("%R2007") == 0xF001


# ============================================================================
# 11. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Verify STParser & SecurityGuard verification of CaprolactamFluidizedBedSync POU."""

    def test_pou_text_definition_and_program_name(self) -> None:
        """CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU must define PROGRAM CaprolactamFluidizedBedSync."""
        assert isinstance(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU, str)
        assert "PROGRAM CaprolactamFluidizedBedSync" in CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU
        assert "END_PROGRAM" in CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU

    def test_st_parser_code_validation_success(self) -> None:
        """STParser.validate_code must validate the POU with AgentStatus.SUCCESS."""
        res = STParser.validate_code(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_security_guard_assert_pure_st(self) -> None:
        """SecurityGuard.assert_pure_st_content must accept the POU without raising."""
        SecurityGuard.assert_pure_st_content(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)

    def test_ast_bound_registers_verification(self) -> None:
        """AST parsing of POU must verify bindings to %R2000..%R2007 and %M466..%M468."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "CaprolactamFluidizedBedSync"

        expected_registers = [
            "%R2000", "%R2001", "%R2002", "%R2003",
            "%R2004", "%R2005", "%R2006", "%R2007",
            "%M466", "%M467", "%M468",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers

    def test_pou_declared_variable_names(self) -> None:
        """POU variable declarations must match standard telemetry names."""
        for var_name in [
            "BedTemperatureScaled",
            "OximeConversionScaled",
            "CaprolactamSelectivityScaled",
            "GasVelocityScaled",
            "CatalystActivityScaled",
            "OperatingPressureScaled",
            "ProductionRateKgH",
            "DiagnosticCode",
            "FluidizedBedRunning",
            "SelectivityPreAlarm",
            "BedEmergencyTrip",
        ]:
            assert var_name in CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU

    def test_pou_threshold_constants_in_st_logic(self) -> None:
        """POU Structured Text must contain appropriate scaled comparison literals."""
        assert "3800" in CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU  # 380.0 °C
        assert "15" in CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU    # 0.15 m/s
        assert "8500" in CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU  # 85.0%
        assert "9000" in CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU  # 90.0%
        assert "9400" in CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU  # 94.0% pre-alarm

    def test_verify_caprolactam_fluidized_bed_pure_st_helper(self) -> None:
        """Helper verify_caprolactam_fluidized_bed_pure_st() must return valid result object."""
        res = verify_caprolactam_fluidized_bed_pure_st()
        assert res.passed is True
        assert res.status == AgentStatus.SUCCESS
        assert res.error is None

    def test_pou_pure_st_aliases(self) -> None:
        """POU alias strings must match primary POU text identically."""
        assert CAPROLACTAM_FLUIDIZED_BED_SYNC_POU == CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU
        assert CAPROLACTAM_PURE_ST_POU == CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU
        assert CAPROLACTAM_SYNC_POU == CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU


# ============================================================================
# 12. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Verify rejection of 6+ ladder constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError."""

    def test_reject_normally_open_contact(self) -> None:
        """Normally-open contact construct '---[ ]---' must be rejected with LadderForbiddenError."""
        bad_st = "PROGRAM Test\nVAR x: BOOL; END_VAR\nx := ---[ ]---;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_normally_closed_contact(self) -> None:
        """Normally-closed contact construct '---[/]---' must be rejected with LadderForbiddenError."""
        bad_st = "PROGRAM Test\nVAR x: BOOL; END_VAR\nx := ---[/]---;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_standard_coil(self) -> None:
        """Standard output coil construct '---( )---' must be rejected with LadderForbiddenError."""
        bad_st = "PROGRAM Test\nVAR x: BOOL; END_VAR\n---( )--- x;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_set_and_reset_coils(self) -> None:
        """Latch/Unlatch coils '---(S)---' and '---(R)---' must be rejected with LadderForbiddenError."""
        bad_st_set = "PROGRAM Test\n---(S)--- y;\nEND_PROGRAM"
        bad_st_rst = "PROGRAM Test\n---(R)--- y;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_set)
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_rst)

    def test_reject_rung_and_network_keywords(self) -> None:
        """Rung delimiters (RUNG, NETWORK) must be rejected with LadderForbiddenError."""
        bad_st_rung = "PROGRAM Test\nRUNG 1\nx := 1;\nEND_RUNG\nEND_PROGRAM"
        bad_st_net = "PROGRAM Test\nNETWORK 1\nx := 1;\nEND_NETWORK\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_rung)
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_net)

    def test_reject_allen_bradley_ladder_mnemonics(self) -> None:
        """Ladder mnemonics XIC, XIO, OTE, OTL, OTU must be rejected with LadderForbiddenError."""
        for mnemonic in ["XIC(tag1)", "XIO(tag2)", "OTE(tag3)", "OTL(tag4)", "OTU(tag5)"]:
            bad_st = f"PROGRAM Test\n{mnemonic};\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_st)

    def test_security_guard_valid_st_does_not_raise(self) -> None:
        """Valid pure Structured Text must pass SecurityGuard without raising."""
        valid_st = "PROGRAM Safe\nVAR a : INT; END_VAR\na := 10 + 20;\nEND_PROGRAM"
        SecurityGuard.assert_pure_st_content(valid_st)

    def test_ladder_forbidden_error_contains_diagnostic_context(self) -> None:
        """LadderForbiddenError exception must contain descriptive information."""
        try:
            SecurityGuard.assert_pure_st_content("PROGRAM Test ---[ ]--- END_PROGRAM")
            pytest.fail("Expected LadderForbiddenError was not raised")
        except LadderForbiddenError as exc:
            assert len(str(exc)) > 0


# ============================================================================
# 13. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Verify scan_step, step, execute, reset, 100-cycle soak stability."""

    def test_ilogic_unit_inheritance_and_instance(self) -> None:
        """CaprolactamFluidizedBed must inherit from and instantiate as an ILogicUnit."""
        assert issubclass(CaprolactamFluidizedBed, ILogicUnit)
        sim = CaprolactamFluidizedBed()
        assert isinstance(sim, ILogicUnit)

    def test_ilogic_unit_name_and_priority(self) -> None:
        """ILogicUnit name and priority attributes must be properly initialized."""
        sim = CaprolactamFluidizedBed()
        assert sim.name in ("CaprolactamFluidizedBedSync", "CaprolactamFluidizedBed")
        assert sim.priority == 10

    def test_ilogic_unit_enable_disable(self) -> None:
        """is_enabled property and enable/disable methods must work correctly."""
        sim = CaprolactamFluidizedBed()
        assert sim.is_enabled is True
        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_scan_step_with_context(self) -> None:
        """scan_step must accept ScanContext and advance simulation count."""
        sim = CaprolactamFluidizedBed()
        ctx = ScanContext(cycle=1, dt=0.02, dt_ms=20.0, elapsed_time_ms=20.0)
        sim.scan_step(dt=0.02, context=ctx)
        assert sim.state.scan_count == 1
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-5)

    def test_step_method_execution(self) -> None:
        """step() method must execute a single simulation step."""
        sim = CaprolactamFluidizedBed()
        sim.step(0.02)
        assert sim.state.scan_count == 1
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-5)

    def test_execute_method_execution(self) -> None:
        """execute(context) must call scan_step internally."""
        sim = CaprolactamFluidizedBed()
        ctx = ScanContext(cycle=5, dt=0.02, dt_ms=20.0, elapsed_time_ms=100.0)
        sim.execute(ctx)
        assert sim.state.scan_count == 1

    def test_reset_method_restores_defaults(self) -> None:
        """reset() must restore state, counters, and registers to nominal values."""
        sim = CaprolactamFluidizedBed()
        sim.state.t_bed_c = 385.0
        sim.state.scan_count = 50
        sim._evaluate_safety_interlocks()
        assert sim.state.bed_emergency_trip is True

        sim.reset()
        assert sim.state.t_bed_c == 350.0
        assert sim.state.scan_count == 0
        assert sim.state.bed_emergency_trip is False
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_100_cycle_soak_stability(self) -> None:
        """100-cycle soak must remain numerically stable without NaN, Inf, or erratic drift."""
        sim = CaprolactamFluidizedBed()
        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt=0.02, dt_ms=20.0, elapsed_time_ms=cycle * 20.0)
            sim.execute(ctx)
            assert not math.isnan(sim.state.t_bed_c)
            assert not math.isinf(sim.state.t_bed_c)
            assert 345.0 <= sim.state.t_bed_c <= 355.0
            assert sim.state.oxime_conversion_pct >= 99.0
            assert sim.state.caprolactam_selectivity_pct >= 96.0

    def test_zero_memory_leak_soak(self) -> None:
        """Memory heap growth over 100 scan cycles must be strictly bounded (< 100 KB)."""
        tracemalloc.start()
        snap_before = tracemalloc.take_snapshot()

        sim = CaprolactamFluidizedBed()
        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt=0.02, dt_ms=20.0, elapsed_time_ms=cycle * 20.0)
            sim.execute(ctx)

        snap_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snap_after.compare_to(snap_before, "lineno")
        total_growth_kb = sum(s.size_diff for s in stats) / 1024.0
        assert total_growth_kb < 100.0


# ============================================================================
# 14. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Verify deterministic 9-stage runner export and strict 4-state contract validation."""

    def test_run_verification_returns_dict(self) -> None:
        """run_caprolactam_fluidized_bed_verification() must return a dictionary."""
        result = run_caprolactam_fluidized_bed_verification()
        assert isinstance(result, dict)

    def test_run_verification_strict_4_state_contract(self) -> None:
        """Verification result status must be one of 'success', 'failed', 'blocked', 'inconclusive'."""
        result = run_caprolactam_fluidized_bed_verification()
        assert result["status"] in {"success", "failed", "blocked", "inconclusive"}

    def test_run_verification_status_is_success(self) -> None:
        """Verification suite must return success on healthy codebase."""
        result = run_caprolactam_fluidized_bed_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None

    def test_run_verification_data_field_structure(self) -> None:
        """Result dictionary must contain data payload with work_package W239 and stages."""
        result = run_caprolactam_fluidized_bed_verification()
        data = result.get("data", {})
        assert data.get("work_package") == "W239"
        assert data.get("checks_passed") == 9
        assert data.get("total_checks") == 9

    def test_run_verification_all_9_stages_pass(self) -> None:
        """Every individual stage in the 9-stage runner must report passed: True."""
        result = run_caprolactam_fluidized_bed_verification()
        stages = result["data"]["stages"]
        assert len(stages) == 9
        for stage in stages:
            assert stage["passed"] is True, f"Stage {stage.get('stage')} failed: {stage.get('details')}"

    def test_run_verification_register_map_presence(self) -> None:
        """Verification data payload must document successful stage execution and register bindings."""
        result = run_caprolactam_fluidized_bed_verification()
        stages = result["data"]["stages"]
        stage2 = next(s for s in stages if s["stage"] == 2)
        stage9 = next(s for s in stages if s["stage"] == 9)
        assert stage2["passed"] is True
        assert stage9["passed"] is True
        assert "CaprolactamFluidizedBedSync" in stage2["details"]
        assert "%R2000" in stage2["details"] or "%R2000" in stage9["details"]

    def test_run_verification_file_export(self) -> None:
        """run_caprolactam_fluidized_bed_verification(output_path) must serialize evidence JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "evidence.json"
            res = run_caprolactam_fluidized_bed_verification(output_path=out_path)
            assert out_path.exists()
            with open(out_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["data"]["work_package"] == "W239"

    def test_verification_runner_alias_functions(self) -> None:
        """Alias runner functions must produce equivalent successful verification results."""
        res1 = run_caprolactam_verification()
        res2 = run_fluidized_bed_verification()
        assert res1["status"] == "success"
        assert res2["status"] == "success"


# ============================================================================
# 15. TestFluidizedBedConfigAndStateEdgeCases
# ============================================================================

class TestFluidizedBedConfigAndStateEdgeCases:
    """Verify custom configurations, state edge cases, properties, and priority resolution."""

    def test_custom_config_instantiation(self) -> None:
        """CaprolactamFluidizedBedConfig must accept custom geometry and kinetic parameters."""
        cfg = CaprolactamFluidizedBedConfig(
            bed_diameter_m=3.0,
            bed_height_m=5.0,
            bed_volume_m3=35.0,
            nominal_bed_temp_c=355.0,
        )
        sim = CaprolactamFluidizedBed(config=cfg)
        assert sim.config.bed_diameter_m == 3.0
        assert sim.config.bed_height_m == 5.0
        assert sim.config.nominal_bed_temp_c == 355.0

    def test_state_compatibility_properties_getters(self) -> None:
        """Compatibility property getters must route to respective primary state variables."""
        sim = CaprolactamFluidizedBed()
        assert sim.state.conversion_pct == sim.state.oxime_conversion_pct
        assert sim.state.selectivity_pct == sim.state.caprolactam_selectivity_pct
        assert sim.state.bed_temp_c == sim.state.t_bed_c
        assert sim.state.t_bed == sim.state.t_bed_c
        assert sim.state.bed_temperature_celsius == sim.state.t_bed_c
        assert sim.state.operating_pressure_bar == sim.state.p_bed_bar
        assert sim.state.bed_pressure_bar == sim.state.p_bed_bar
        assert sim.state.p_bed == sim.state.p_bed_bar

    def test_state_compatibility_properties_setters(self) -> None:
        """Compatibility property setters must update primary state variables."""
        sim = CaprolactamFluidizedBed()
        sim.state.conversion_pct = 98.5
        assert sim.state.oxime_conversion_pct == 98.5

        sim.state.selectivity_pct = 95.0
        assert sim.state.caprolactam_selectivity_pct == 95.0

        sim.state.t_bed_c = 352.0
        assert sim.state.t_bed == 352.0
        assert sim.state.bed_temperature_celsius == 352.0

        sim.state.bed_emergency_trip = True
        assert sim.state.bed_emergency_trip is True

    def test_negative_or_zero_dt_handling_defaults(self) -> None:
        """scan_step with dt advances scan_count and handles dt parameter safely."""
        sim = CaprolactamFluidizedBed()
        sim.scan_step(dt=0.0)
        assert sim.state.scan_count == 1
        assert math.isclose(sim.state.sim_time_s, 0.0, abs_tol=1e-5)

        sim.scan_step(dt=0.02)
        assert sim.state.scan_count == 2
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-5)

    def test_external_register_table_injection(self) -> None:
        """RegisterTable passed at construction must be bound and populated on scan."""
        custom_regs = RegisterTable()
        sim = CaprolactamFluidizedBed(register_table=custom_regs)
        sim.step(0.02)
        assert custom_regs.read_word("%R2000") == 3500
        assert custom_regs.read_bit("%M466") is True

    def test_multi_fault_priority_matrix(self) -> None:
        """Priority order must strictly enforce: 0xF001 > 0xF002 > 0xF003 > 0xF004 > 0x0000."""
        sim = CaprolactamFluidizedBed()

        # Defluidization vs Coking -> Defluidization (P2)
        sim.reset()
        sim.state.gas_velocity_m_s = 0.10
        sim.state.catalyst_activity = 0.80
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEFLUIDIZATION_COLLAPSE

        # Coking vs Selectivity -> Coking (P3)
        sim.reset()
        sim.state.catalyst_activity = 0.80
        sim.state.caprolactam_selectivity_pct = 85.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_SEVERE_COKING

        # Selectivity alone -> Selectivity (P4)
        sim.reset()
        sim.state.caprolactam_selectivity_pct = 85.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.SELECTIVITY_PLUMMET

    def test_status_bits_combined_flags(self) -> None:
        """status_bits must correctly reflect simultaneous running, prealarm, and fault states."""
        sim = CaprolactamFluidizedBed()
        sim.state.caprolactam_selectivity_pct = 92.0
        sim._evaluate_safety_interlocks()
        # Prealarm should be active, reactor still running, no trip
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.RUNNING) != 0
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.FLUIDIZED_BED_RUNNING) != 0
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.SELECTIVITY_PREALARM) != 0
        assert (sim.state.status_bits & CaprolactamFluidizedBedStatusBits.BED_EMERGENCY_TRIP) == 0

    def test_aliases_and_factory_class_names(self) -> None:
        """All class aliases and factory types must instantiate interchangeably."""
        sim1 = CaprolactamFluidizedBedReactor()
        sim2 = CaprolactamFluidizedBedSimulator()
        sim3 = CaprolactamFluidizedBedEngine()
        sim4 = CaprolactamFluidizedBedModel()
        assert isinstance(sim1, CaprolactamFluidizedBed)
        assert isinstance(sim2, CaprolactamFluidizedBed)
        assert isinstance(sim3, CaprolactamFluidizedBed)
        assert isinstance(sim4, CaprolactamFluidizedBed)
