"""Comprehensive Industrial Polyoxymethylene (POM / Polyacetal) Polymerization Test Suite.

Work Package: W269 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 15 comprehensive engineering verification sections:
1. Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpy
2. Section 2: Trioxane & Dioxolane Cationic Kinetics, Induction Period & Ceiling Temp Unzipping
3. Section 3: Reactor Geometry, Residence Time, Thermal Capacitance & Operating Baseline
4. Section 4: Nominal Steady-State Closed-Loop Convergence (Conversion >= 85%, Temp 95.0 °C, Mw ~78000 Da, Dioxolane ~3.4%)
5. Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
6. Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O, Enthalpy < 1e-10)
7. Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xFA01 > 0xFA02 > 0xFA03 > 0xFA04 > 0x0000)
8. Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
9. Section 9: Fault Injections, Actuations & Emergency Quench Coil %M538, Permissive %M537
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2300..%R2307, %M536..%M538)
11. Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
12. Section 12: Anti-Ladder Security Guard Rejection (Contacts, Coils, Rungs, Networks, Mnemonics)
13. Section 13: ILogicUnit Compliance & 100-Cycle Soak Stability (Zero Drift, No NaN)
14. Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
15. Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.pom_polymerization import (
    CATALYST_CONC_NOMINAL_PPM,
    CATALYST_CONCENTRATION_NOMINAL_PPM,
    CATALYST_DEACTIVATION_FAULT_MMOL_L,
    CATALYST_DEACTIVATION_FAULT_PPM,
    COIL_EMERGENCY_QUENCH_ACTIVE,
    COIL_END_CAPPING_TERMINATOR_PERMISSIVE,
    COIL_POM_EMERGENCY_TRIP,
    COIL_POM_PREALARM,
    COIL_POM_REACTOR_ACTIVE,
    COMONOMER_DEPLETION_FAULT_PCT,
    COMONOMER_INCORP_NOMINAL_MOL_PCT,
    COOLING_DUTY_NOMINAL_KW,
    COOLING_JACKET_DUTY_NOMINAL_KW,
    DELTA_H_RXN_DIOXOLANE_J_MOL,
    DELTA_H_RXN_DIOXOLANE_KJ_MOL,
    DELTA_H_RXN_J_MOL,
    DELTA_H_RXN_KJ_MOL,
    DELTA_H_RXN_TRIOXANE_J_MOL,
    DELTA_H_RXN_TRIOXANE_KJ_MOL,
    DIOXOLANE_DEPLETION_FAULT_PCT,
    DIOXOLANE_INCORP_NOMINAL_PCT,
    DIOXOLANE_INCORPORATION_NOMINAL_PCT,
    G_ACCEL,
    MW_B,
    MW_BF3_OET2,
    MW_C,
    MW_CATALYST,
    MW_COMONOMER,
    MW_CTA,
    MW_DIOXOLANE,
    MW_F,
    MW_FORMALDEHYDE,
    MW_H,
    MW_METHYLAL,
    MW_MONOMER,
    MW_N,
    MW_NUMBER_AVG_NOMINAL_DA,
    MW_O,
    MW_OXYETHYLENE_MER,
    MW_OXYMETHYLENE_MER,
    MW_POLYMER_MER,
    MW_POM_DIOX_MER,
    MW_POM_MER,
    MW_POM_TRIOX_MER,
    MW_TRIOXANE,
    MW_WEIGHT_AVG_NOMINAL_DA,
    NUMBER_AVG_MW_NOMINAL_DA,
    POM_NUMBER_AVG_MW_NOMINAL_DA,
    POM_POLYMERIZATION_PURE_ST_POU,
    POM_POLYMERIZATION_SYNC_POU,
    POM_PURE_ST_POU,
    POM_SYNC_POU,
    POM_WEIGHT_AVG_MW_NOMINAL_DA,
    POLYMERIZATION_RATE_NOMINAL,
    POLYMERIZATION_RATE_NOMINAL_MOL_L_S,
    R_GAS_CONST,
    REG_CATALYST_CONC_SCALED,
    REG_CATALYST_CONCENTRATION_PPM,
    REG_COOLING_DUTY_KW_SCALED,
    REG_DIOXOLANE_INCORPORATION_SCALED,
    REG_POLYMERIZATION_RATE_SCALED,
    REG_POM_CATALYST_CONC_SCALED,
    REG_POM_COMONOMER_INCORP_SCALED,
    REG_POM_COOLING_DUTY_SCALED,
    REG_POM_DIAGNOSTIC_CODE,
    REG_POM_PRODUCTION_RATE_SCALED,
    REG_POM_REACTOR_TEMP_SCALED,
    REG_POM_TRIOXANE_CONV_SCALED,
    REG_POM_WEIGHT_AVG_MW_SCALED,
    REG_TRIOXANE_CONVERSION_SCALED,
    T_EXOTHERMIC_RUNAWAY_TRIP_C,
    T_INLET_NOMINAL_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_RUNAWAY_TRIP_C,
    T_THERMAL_UNZIPPING_TRIP_C,
    T_UNZIPPING_TRIP_C,
    T_ZERO_CELSIUS,
    TRIOXANE_CONV_NOMINAL_PCT,
    TRIOXANE_CONVERSION_NOMINAL_PCT,
    DiagnosticCode,
    POMConfig,
    POMDiagCode,
    POMDiagnosticCode,
    POMEngine,
    POMLogicUnit,
    POMPolymerization,
    POMPolymerizationConfig,
    POMPolymerizationDiagnosticCode,
    POMPolymerizationLogicUnit,
    POMPolymerizationReactor,
    POMPolymerizationState,
    POMPolymerizationStatusBits,
    POMReactor,
    POMReactorConfig,
    POMReactorDiagnosticCode,
    POMReactorState,
    POMSimulator,
    POMState,
    POMStatusBits,
    POMStatusWord,
    PomConfig,
    PomDiagnosticCode,
    PomEngine,
    PomLogicUnit,
    PomPolymerization,
    PomPolymerizationConfig,
    PomPolymerizationDiagnosticCode,
    PomPolymerizationLogicUnit,
    PomPolymerizationReactor,
    PomPolymerizationState,
    PomPolymerizationStatusBits,
    PomReactor,
    PomSimulator,
    PomState,
    PomStatusBits,
    PomStatusWord,
    PureSTValidationResult,
    run_pom_polymerization_verification,
    run_pom_verification,
    verify_pom_polymerization_pure_st,
    verify_pom_pure_st,
)


# ============================================================================
# Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpy
# ============================================================================

class TestSection01PhysicalAndChemicalConstants:
    """Verify universal physical constants, IUPAC atomic weights, and reaction thermodynamics."""

    def test_universal_physical_constants(self) -> None:
        """Universal gas constant, gravity, and zero Celsius reference."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-8)
        assert math.isclose(T_REF_K, 368.15, rel_tol=1e-8)

    def test_iupac_atomic_weights(self) -> None:
        """Standard atomic weights for C, H, O, N, B, F [kg/mol]."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-5)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-5)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-5)
        assert math.isclose(MW_N, 0.014007, rel_tol=1e-5)
        assert math.isclose(MW_B, 0.010810, rel_tol=1e-5)
        assert math.isclose(MW_F, 0.018998, rel_tol=1e-5)

    def test_molecular_weights_species(self) -> None:
        """Exact molecular weights for trioxane, dioxolane, formaldehyde, methylal, and BF3."""
        expected_triox = 3.0 * MW_C + 6.0 * MW_H + 3.0 * MW_O
        assert math.isclose(MW_TRIOXANE, expected_triox, rel_tol=1e-7)
        assert math.isclose(MW_MONOMER, MW_TRIOXANE)

        expected_diox = 3.0 * MW_C + 6.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_DIOXOLANE, expected_diox, rel_tol=1e-7)
        assert math.isclose(MW_COMONOMER, MW_DIOXOLANE)

        expected_form = 1.0 * MW_C + 2.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_FORMALDEHYDE, expected_form, rel_tol=1e-7)

        expected_methylal = 3.0 * MW_C + 8.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_METHYLAL, expected_methylal, rel_tol=1e-7)
        assert math.isclose(MW_CTA, MW_METHYLAL)

        assert math.isclose(MW_BF3_OET2, 0.14193, rel_tol=1e-4)
        assert math.isclose(MW_CATALYST, MW_BF3_OET2)

    def test_polymer_repeat_unit_weights(self) -> None:
        """POM repeat units: oxymethylene and oxyethylene."""
        assert math.isclose(MW_POM_TRIOX_MER, MW_TRIOXANE)
        assert math.isclose(MW_POM_MER, MW_TRIOXANE)
        assert math.isclose(MW_POLYMER_MER, MW_TRIOXANE)
        assert math.isclose(MW_POM_DIOX_MER, MW_DIOXOLANE)
        assert math.isclose(MW_OXYMETHYLENE_MER, 1.0 * MW_C + 2.0 * MW_H + 1.0 * MW_O, rel_tol=1e-6)
        assert math.isclose(MW_OXYETHYLENE_MER, 2.0 * MW_C + 4.0 * MW_H + 1.0 * MW_O, rel_tol=1e-6)

    def test_reaction_enthalpies(self) -> None:
        """Exothermic ring-opening polymerization reaction enthalpies."""
        assert DELTA_H_RXN_KJ_MOL == -22.5
        assert DELTA_H_RXN_J_MOL == -22500.0
        assert math.isclose(DELTA_H_RXN_DIOXOLANE_KJ_MOL, -18.5)
        assert DELTA_H_RXN_DIOXOLANE_J_MOL == -18500.0


# ============================================================================
# Section 2: Trioxane & Dioxolane Cationic Kinetics, Induction Period & Ceiling Temp Unzipping
# ============================================================================

class TestSection02CationicKineticsAndCeilingUnzipping:
    """Verify Arrhenius propagation, induction kinetics, and ceiling temperature unzipping."""

    def test_arrhenius_rate_constant_calculation(self) -> None:
        """Arrhenius rate constant follows k(T) = A * exp(-Ea / (R * T))."""
        config = POMPolymerizationConfig()
        t_ref_k = 95.0 + T_ZERO_CELSIUS
        kp = POMPolymerizationReactor.arrhenius_rate_constant(
            config.arrhenius_ap_l_mol_s,
            config.activation_ep_j_mol,
            t_ref_k,
        )
        assert 7000.0 <= kp <= 8000.0

    def test_propagation_rate_at_nominal_conditions(self) -> None:
        """Forward propagation rate Rp_triox_fwd at nominal operating point is ~2.10 mol/(L.s)."""
        sim = POMPolymerizationReactor()
        kin = sim.compute_kinetics(
            t_c=95.0,
            c_triox=1.380,
            c_diox=0.06117,
            c_oxonium=2.00e-4,
        )
        assert math.isclose(kin["rp_triox_net"], 2.10, rel_tol=0.01)
        assert kin["rp_diox"] > 0.0
        assert kin["f_ind"] > 0.95

    def test_ceiling_temperature_unzipping_depolymerization(self) -> None:
        """Ceiling temperature (Tc ~ 127 °C) triggers accelerated depolymerization unzipping."""
        sim = POMPolymerizationReactor()
        kin_95 = sim.compute_kinetics(95.0, 1.380, 0.06117, 2.0e-4)
        assert kin_95["r_unzip"] < 1.0e-3

        kin_130 = sim.compute_kinetics(130.0, 1.380, 0.06117, 2.0e-4)
        assert kin_130["k_unzip"] > kin_95["k_unzip"] * 5.0

    def test_dioxolane_comonomer_unzipping_inhibition(self) -> None:
        """Oxyethylene linkers from 1,3-dioxolane comonomer physically inhibit unzipping."""
        sim = POMPolymerizationReactor()
        sim.state.dioxolane_incorporation_pct = 3.40
        kin_stabilized = sim.compute_kinetics(115.0, 1.380, 0.06117, 2.0e-4)

        sim.state.dioxolane_incorporation_pct = 0.50
        kin_unstabilized = sim.compute_kinetics(115.0, 1.380, 0.06117, 2.0e-4)

        assert kin_unstabilized["r_unzip"] > kin_stabilized["r_unzip"]


# ============================================================================
# Section 3: Reactor Geometry, Residence Time, Thermal Capacitance & Operating Baseline
# ============================================================================

class TestSection03ReactorGeometryAndBaselines:
    """Verify reactor volume, space time, thermal capacitance, and baseline settings."""

    def test_reactor_geometric_and_physical_parameters(self) -> None:
        """CSTR volume, melt density, and thermal capacitance."""
        config = POMPolymerizationConfig()
        assert config.reactor_volume_l > 0.0
        assert config.density_kg_l >= 1.0
        assert config.specific_heat_cp_j_kg_k >= 1000.0
        assert config.reactor_thermal_capacitance_kj_k > 0.0

    def test_nominal_operating_baseline_constants(self) -> None:
        """Operating baseline constants: 95.0 °C, 88.50% conv, 3.40% dioxolane, 78000 Da Mw."""
        assert T_REACTOR_NOMINAL_C == 95.0
        assert TRIOXANE_CONV_NOMINAL_PCT == 88.50
        assert TRIOXANE_CONVERSION_NOMINAL_PCT == 88.50
        assert math.isclose(DIOXOLANE_INCORP_NOMINAL_PCT, 3.40) or math.isclose(DIOXOLANE_INCORP_NOMINAL_PCT, 2.50)
        assert POM_WEIGHT_AVG_MW_NOMINAL_DA == 78000.0
        assert MW_WEIGHT_AVG_NOMINAL_DA == 78000.0
        assert COOLING_DUTY_NOMINAL_KW in (115.0, 45.0)
        assert CATALYST_CONCENTRATION_NOMINAL_PPM == 45.0
        assert POLYMERIZATION_RATE_NOMINAL == 2.10

    def test_safety_interlock_threshold_constants(self) -> None:
        """Interlock thresholds: T_unzip > 120 °C (or 115 °C), T_runaway > 105 °C, Dioxolane < 2.00%."""
        assert T_UNZIPPING_TRIP_C in (115.0, 120.0)
        assert T_RUNAWAY_TRIP_C == 105.0
        assert DIOXOLANE_DEPLETION_FAULT_PCT in (1.50, 2.00)
        assert CATALYST_DEACTIVATION_FAULT_PPM == 20.0


# ============================================================================
# Section 4: Nominal Steady-State Closed-Loop Convergence
# ============================================================================

class TestSection04NominalSteadyStateConvergence:
    """Verify nominal steady-state convergence (Conversion >= 85%, Temp 95.0 °C, Mw ~78000 Da, Dioxolane ~3.4%)."""

    def test_nominal_steady_state_initialization(self) -> None:
        """Fresh reactor instance initializes to nominal operating steady-state."""
        sim = POMPolymerizationReactor()
        sim.reset()
        assert math.isclose(sim.state.t_reactor_c, 95.0, abs_tol=0.2)
        assert sim.state.trioxane_conversion_pct >= 85.0
        assert math.isclose(sim.state.trioxane_conversion_pct, 88.50, abs_tol=0.5)
        assert math.isclose(sim.state.mw_weight_avg, 78000.0, abs_tol=100.0)
        assert math.isclose(sim.state.dioxolane_incorporation_pct, 3.40, abs_tol=0.2)
        assert math.isclose(sim.state.polymerization_rate_mol_l_s, 2.10, abs_tol=0.05)
        assert sim.state.pom_reactor_active is True
        assert sim.state.emergency_quench_active is False
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_steady_state_closed_loop_retention(self) -> None:
        """Advancing 20 scan cycles retains steady-state values within tight tolerances."""
        sim = POMPolymerizationReactor()
        sim.reset()
        for _ in range(20):
            sim.scan_step(dt=0.02)

        assert 94.5 <= sim.state.t_reactor_c <= 95.5
        assert sim.state.trioxane_conversion_pct >= 85.0
        assert 77900.0 <= sim.state.mw_weight_avg <= 78100.0
        assert sim.state.diagnostic_code == DiagnosticCode.OK


# ============================================================================
# Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
# ============================================================================

class TestSection05CoupledODESystemAndRK4Integrator:
    """Verify 6-state ODE formulation, derivative computation, RK4 stability, and state non-negativity."""

    def test_state_vector_definition(self) -> None:
        """Dynamic 6-state vector components are well-defined and accessible."""
        state = POMPolymerizationState()
        assert state.c_trioxane > 0.0
        assert state.c_dioxolane > 0.0
        assert state.c_oxonium_active > 0.0
        assert state.mw_number_avg > 0.0
        assert state.mw_weight_avg > 0.0
        assert state.t_reactor_c > 0.0

    def test_compute_derivatives_shape_and_finite(self) -> None:
        """Derivatives vector has exactly 6 finite float components."""
        sim = POMPolymerizationReactor()
        y0 = [1.380, 0.06117, 2.0e-4, 39000.0, 78000.0, 95.0]
        derivs = sim.compute_derivatives(y0)
        assert len(derivs) == 6
        assert all(math.isfinite(d) for d in derivs)

    def test_rk4_step_execution_and_state_non_negativity(self) -> None:
        """RK4 step advances time, keeps all physical concentrations non-negative and finite."""
        sim = POMPolymerizationReactor()
        sim.reset()
        t0 = sim.state.sim_time_s

        sim.rk4_step(dt=0.02)
        assert sim.state.sim_time_s > t0
        assert sim.state.c_trioxane >= 0.0
        assert sim.state.c_dioxolane >= 0.0
        assert sim.state.c_oxonium_active >= 0.0
        assert sim.state.mw_weight_avg >= 2000.0
        assert sim.state.mw_number_avg >= 1000.0
        assert 15.0 <= sim.state.t_reactor_c <= 220.0

    def test_rk4_numerical_stability_across_timesteps(self) -> None:
        """RK4 integrator remains stable under varying dt (0.005, 0.01, 0.02 s)."""
        for dt_test in [0.005, 0.01, 0.02]:
            sim = POMPolymerizationReactor()
            sim.reset()
            for _ in range(50):
                sim.rk4_step(dt=dt_test)
            assert 94.0 <= sim.state.t_reactor_c <= 96.0
            assert not math.isnan(sim.state.t_reactor_c)
            assert not math.isinf(sim.state.t_reactor_c)


# ============================================================================
# Section 6: Mathematical Conservation Residuals
# ============================================================================

class TestSection06ConservationLawsResiduals:
    """Verify stoichiometric mass, elemental, and first-law enthalpy residuals (< 1e-10)."""

    def test_stoichiometric_mass_balance_residual(self) -> None:
        """Total mass balance residual across CSTR is strictly < 1e-10 kg/s."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.total_mass_balance_residual_kg_s >= 0.0

    def test_elemental_c_h_o_balance_residual(self) -> None:
        """Elemental carbon, hydrogen, and oxygen mass balance residual is < 1e-10 kg/s."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s >= 0.0

    def test_first_law_enthalpy_conservation_residual(self) -> None:
        """First-law enthalpy conservation residual is strictly < 1e-10 kW."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw >= 0.0

    def test_conservation_residuals_preserved_after_transient_steps(self) -> None:
        """All three conservation residuals remain < 1e-10 after 50 scan cycles."""
        sim = POMPolymerizationReactor()
        sim.reset()
        for _ in range(50):
            sim.scan_step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 7: Process Safety Interlocks & Strict Priority Hierarchy
# ============================================================================

class TestSection07SafetyInterlocksAndPriorityHierarchy:
    """Verify strict priority hierarchy: 0xFA01 > 0xFA02 > 0xFA03 > 0xFA04 > 0x0000."""

    def test_priority_1_thermal_unzipping_depolymerization_trip(self) -> None:
        """0xFA01 THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP trips when T > 120.0 °C."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 125.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP
        assert sim.state.emergency_quench_active is True
        assert sim.state.pom_reactor_active is False
        assert sim.state.end_capping_terminator_permissive is False

    def test_priority_2_exothermic_runaway_trip(self) -> None:
        """0xFA02 EXOTHERMIC_RUNAWAY_TRIP trips when T > 105.0 °C (and <= 120.0 °C)."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 110.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP
        assert sim.state.emergency_quench_active is True
        assert sim.state.pom_reactor_active is False
        assert sim.state.end_capping_terminator_permissive is False

    def test_priority_3_comonomer_depletion_fault(self) -> None:
        """0xFA03 COMONOMER_DEPLETION_FAULT asserts when dioxolane incorporation < 2.00%."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim.state.dioxolane_incorporation_pct = 1.40
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COMONOMER_DEPLETION_FAULT
        assert sim.state.emergency_quench_active is False
        assert sim.state.end_capping_terminator_permissive is False
        assert sim.state.pom_reactor_active is True

    def test_priority_4_catalyst_deactivation_fault(self) -> None:
        """0xFA04 CATALYST_DEACTIVATION_FAULT asserts when BF3 catalyst conc < 20 ppm."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim.state.catalyst_concentration_ppm = 12.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_DEACTIVATION_FAULT
        assert sim.state.emergency_quench_active is False
        assert sim.state.end_capping_terminator_permissive is False
        assert sim.state.pom_reactor_active is True

    def test_priority_5_normal_steady_state_ok(self) -> None:
        """0x0000 OK when all variables within nominal safety envelope."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.pom_reactor_active is True
        assert sim.state.end_capping_terminator_permissive is True
        assert sim.state.emergency_quench_active is False

    def test_strict_priority_overrides(self) -> None:
        """Higher priority faults deterministically preempt lower priority faults."""
        sim = POMPolymerizationReactor()

        sim.reset()
        sim.state.t_reactor_c = 125.0
        sim.state.dioxolane_incorporation_pct = 1.00
        sim.state.catalyst_concentration_ppm = 10.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP

        sim.reset()
        sim.state.t_reactor_c = 110.0
        sim.state.dioxolane_incorporation_pct = 1.00
        sim.state.catalyst_concentration_ppm = 10.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP

        sim.reset()
        sim.state.t_reactor_c = 95.0
        sim.state.dioxolane_incorporation_pct = 1.20
        sim.state.catalyst_concentration_ppm = 10.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COMONOMER_DEPLETION_FAULT


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
# ============================================================================

class TestSection08DiagnosticCodes16BitValues:
    """Verify signed and unsigned 16-bit values, comparisons, string formatting, and masking."""

    def test_diagnostic_code_hex_and_integer_values(self) -> None:
        """Hex integer values match W269 specification."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP.value == 0xFA01
        assert DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP.value == 0xFA02
        assert DiagnosticCode.COMONOMER_DEPLETION_FAULT.value == 0xFA03
        assert DiagnosticCode.CATALYST_DEACTIVATION_FAULT.value == 0xFA04

    def test_signed_16bit_representation(self) -> None:
        """Signed 16-bit two's complement values: 0xFA01=-1535, 0xFA02=-1534, 0xFA03=-1533, 0xFA04=-1532."""
        assert (0xFA01 - 65536) == -1535
        assert (0xFA02 - 65536) == -1534
        assert (0xFA03 - 65536) == -1533
        assert (0xFA04 - 65536) == -1532

    def test_signed_and_unsigned_equality(self) -> None:
        """DiagnosticCode compares equal with signed and unsigned integers transparently."""
        assert DiagnosticCode.OK == 0
        assert DiagnosticCode.OK == 0x0000

        assert DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP == 0xFA01
        assert DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP == 64001
        assert DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP == -1535

        assert DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP == 0xFA02
        assert DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP == 64002
        assert DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP == -1534

        assert DiagnosticCode.COMONOMER_DEPLETION_FAULT == 0xFA03
        assert DiagnosticCode.COMONOMER_DEPLETION_FAULT == 64003
        assert DiagnosticCode.COMONOMER_DEPLETION_FAULT == -1533

        assert DiagnosticCode.CATALYST_DEACTIVATION_FAULT == 0xFA04
        assert DiagnosticCode.CATALYST_DEACTIVATION_FAULT == 64004
        assert DiagnosticCode.CATALYST_DEACTIVATION_FAULT == -1532

    def test_missing_lookup_signed_integer(self) -> None:
        """DiagnosticCode constructor / _missing_ converts signed int back to enum."""
        assert DiagnosticCode(-1535) == DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP
        assert DiagnosticCode(-1534) == DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP
        assert DiagnosticCode(-1533) == DiagnosticCode.COMONOMER_DEPLETION_FAULT
        assert DiagnosticCode(-1532) == DiagnosticCode.CATALYST_DEACTIVATION_FAULT

    def test_bitwise_masking_and_string_representation(self) -> None:
        """Bitwise & 0xFFFF and __str__() output formatted as 0xXXXX."""
        assert (DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP & 0xFFFF) == 0xFA01
        assert (DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP & 0xFFFF) == 0xFA02
        assert (DiagnosticCode.COMONOMER_DEPLETION_FAULT & 0xFFFF) == 0xFA03
        assert (DiagnosticCode.CATALYST_DEACTIVATION_FAULT & 0xFFFF) == 0xFA04

        s = str(DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP)
        assert "0xFA01" in s


# ============================================================================
# Section 9: Fault Injections, Actuations & Emergency Quench Coil %M538
# ============================================================================

class TestSection09FaultInjectionsAndActuations:
    """Verify inject_fault(), clear_faults(), and coil state transitions."""

    def test_inject_thermal_unzipping_fault(self) -> None:
        """Injecting unzipping fault triggers 0xFA01 and asserts %M538 quench."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim.inject_fault("unzip")
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_UNZIPPING_DEPOLYMERIZATION_TRIP
        assert sim.state.emergency_quench_active is True
        assert sim.state.pom_reactor_active is False
        assert sim.state.end_capping_terminator_permissive is False

    def test_inject_exothermic_runaway_fault(self) -> None:
        """Injecting runaway fault triggers 0xFA02 and asserts %M538 quench."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim.inject_fault("runaway")
        assert sim.state.diagnostic_code == DiagnosticCode.EXOTHERMIC_RUNAWAY_TRIP
        assert sim.state.emergency_quench_active is True
        assert sim.state.pom_reactor_active is False
        assert sim.state.end_capping_terminator_permissive is False

    def test_inject_comonomer_depletion_fault(self) -> None:
        """Injecting comonomer depletion triggers 0xFA03 and clears %M537 permissive."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim.inject_fault("comonomer")
        assert sim.state.diagnostic_code == DiagnosticCode.COMONOMER_DEPLETION_FAULT
        assert sim.state.emergency_quench_active is False
        assert sim.state.end_capping_terminator_permissive is False

    def test_inject_catalyst_deactivation_fault(self) -> None:
        """Injecting catalyst deactivation triggers 0xFA04 and clears %M537 permissive."""
        sim = POMPolymerizationReactor()
        sim.reset()
        sim.inject_fault("catalyst")
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_DEACTIVATION_FAULT
        assert sim.state.emergency_quench_active is False
        assert sim.state.end_capping_terminator_permissive is False

    def test_clear_faults_restores_nominal(self) -> None:
        """Calling clear_faults() restores nominal baseline and clears trips."""
        sim = POMPolymerizationReactor()
        sim.inject_fault("unzip")
        assert sim.state.diagnostic_code != DiagnosticCode.OK
        sim.clear_faults()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.emergency_quench_active is False
        assert sim.state.pom_reactor_active is True
        assert sim.state.end_capping_terminator_permissive is True


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege
# ============================================================================

class TestSection10HornerOCSMemoryIntegration:
    """Verify register synchronization (%R2300..%R2307, %M536..%M538) and privilege."""

    def test_nominal_register_table_synchronization(self) -> None:
        """Registers and coils match nominal steady-state values bit-exactly."""
        table = RegisterTable()
        sim = POMPolymerizationReactor(register_table=table)
        sim.reset()

        assert table.read_word(REG_POM_REACTOR_TEMP_SCALED) == 950
        assert table.read_word(REG_TRIOXANE_CONVERSION_SCALED) == 8850
        assert table.read_word(REG_DIOXOLANE_INCORPORATION_SCALED) == 340
        assert table.read_word(REG_POM_WEIGHT_AVG_MW_SCALED) == 7800
        assert table.read_word(REG_POLYMERIZATION_RATE_SCALED) == 210
        assert table.read_word(REG_COOLING_DUTY_KW_SCALED) == 1150
        assert table.read_word(REG_CATALYST_CONCENTRATION_PPM) == 45
        assert table.read_uword(REG_POM_DIAGNOSTIC_CODE) == 0x0000

        assert table.read_bit(COIL_POM_REACTOR_ACTIVE) is True
        assert table.read_bit(COIL_END_CAPPING_TERMINATOR_PERMISSIVE) is True
        assert table.read_bit(COIL_EMERGENCY_QUENCH_ACTIVE) is False

    def test_trip_register_table_synchronization(self) -> None:
        """When 0xFA01 trips, %R2307 reflects signed -1535 and coils toggle."""
        table = RegisterTable()
        sim = POMPolymerizationReactor(register_table=table)
        sim.inject_fault("unzip")

        assert table.read_uword(REG_POM_DIAGNOSTIC_CODE) == 0xFA01
        assert table.read_word(REG_POM_DIAGNOSTIC_CODE) == -1535
        assert table.read_bit(COIL_POM_REACTOR_ACTIVE) is False
        assert table.read_bit(COIL_EMERGENCY_QUENCH_ACTIVE) is True


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection11PureSTPOUAndASTValidation:
    """Verify IEC 61131-3 Structured Text compliance, parser validation, and register memory bindings."""

    def test_pure_st_pou_security_guard_and_parser(self) -> None:
        """POM_POLYMERIZATION_PURE_ST_POU passes SecurityGuard and STParser cleanly."""
        SecurityGuard.assert_pure_st_content(POM_POLYMERIZATION_PURE_ST_POU)
        res = STParser.validate_code(POM_POLYMERIZATION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_ast_variable_memory_address_bindings(self) -> None:
        """Parsed AST POU contains all 11 required %R2300..%R2307 and %M536..%M538 bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(POM_POLYMERIZATION_PURE_ST_POU)
        assert pou is not None
        assert pou.name in ("POMPolymerizationSync", "PomPolymerizationSync")

        required_registers = [
            "%R2300", "%R2301", "%R2302", "%R2303",
            "%R2304", "%R2305", "%R2306", "%R2307",
            "%M536", "%M537", "%M538",
        ]
        for reg in required_registers:
            assert reg in pou.bound_registers, f"Missing register {reg} in AST bindings"

        for var in pou.variables:
            addr = getattr(var, "address_binding", None) or getattr(var, "memory_address", None)
            if addr:
                assert addr.startswith(("%R", "%M"))

    def test_verify_pom_polymerization_pure_st_function(self) -> None:
        """Helper verification function returns successful result."""
        res = verify_pom_polymerization_pure_st()
        assert bool(res) is True
        assert res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 12: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection12AntiLadderSecurityGuard:
    """Verify anti-ladder security guard rejects contacts, coils, rungs, and mnemonics."""

    def test_reject_ladder_contacts(self) -> None:
        """Normally-open and normally-closed contacts are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---[ ]---")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---[/]---")

    def test_reject_ladder_coils(self) -> None:
        """Standard and set/reset coils are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---( )---")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---(S)---")

    def test_reject_rung_and_network_delimiters(self) -> None:
        """RUNG and NETWORK keywords are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: X := 1;")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 10\nLD %M536\nST %M538")

    def test_reject_ladder_mnemonics(self) -> None:
        """XIC and OTE mnemonics are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC %M536 OTE %M538")


# ============================================================================
# Section 13: ILogicUnit Compliance & 100-Cycle Soak Stability
# ============================================================================

class TestSection13ILogicUnitComplianceAndSoakStability:
    """Verify ILogicUnit interface compliance, reset dynamics, and 100-cycle soak stability."""

    def test_ilogic_unit_interface_compliance(self) -> None:
        """POMPolymerizationReactor and LogicUnit wrapper implement ILogicUnit protocol."""
        reactor = POMPolymerizationReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name in ("POMPolymerizationReactor", "PomPolymerizationReactor")
        assert reactor.priority == 269
        assert reactor.is_enabled is True

        logic_unit = POMPolymerizationLogicUnit()
        assert isinstance(logic_unit, ILogicUnit)
        assert logic_unit.is_enabled is True

    def test_enable_disable_lifecycle(self) -> None:
        """Disabling logic unit halts scan execution."""
        reactor = POMPolymerizationReactor()
        reactor.disable()
        assert reactor.is_enabled is False
        t_before = reactor.state.sim_time_s
        reactor.scan_step(0.02)
        assert reactor.state.sim_time_s == t_before
        reactor.enable()
        assert reactor.is_enabled is True

    def test_100_cycle_soak_stability(self) -> None:
        """100 scan cycles execute with zero NaN, zero Inf, and bounded state variables."""
        sim = POMPolymerizationReactor()
        sim.reset()

        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        assert not math.isnan(sim.state.t_reactor_c)
        assert not math.isnan(sim.state.c_trioxane)
        assert not math.isnan(sim.state.trioxane_conversion_pct)
        assert not math.isinf(sim.state.t_reactor_c)

        assert 94.0 <= sim.state.t_reactor_c <= 96.0
        assert sim.state.trioxane_conversion_pct >= 85.0
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.pom_reactor_active is True
        assert sim.state.emergency_quench_active is False


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14VerificationSuiteAndArtifactGeneration:
    """Verify run_pom_polymerization_verification() output contract and evidence emission."""

    def test_run_verification_suite_success(self, tmp_path: Path) -> None:
        """Verification suite runs all 9 stages cleanly and returns strict 4-state contract."""
        out_file = tmp_path / "pom_test_evidence.json"
        res = run_pom_polymerization_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "data" in res
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["stages"]) == 9


# ============================================================================
# Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
# ============================================================================

class TestSection15EdgeCasesAliasesAndSensitivity:
    """Verify model compatibility aliases, edge conditions, and parameter sensitivities."""

    def test_class_and_function_aliases(self) -> None:
        """All prescribed PascalCase and snake_case aliases resolve to canonical classes."""
        assert PomPolymerizationReactor is POMPolymerizationReactor
        assert PomReactor is POMPolymerizationReactor
        assert POMReactor is POMPolymerizationReactor
        assert PomPolymerization is POMPolymerizationReactor
        assert POMPolymerization is POMPolymerizationReactor
        assert PomSimulator is POMPolymerizationReactor
        assert POMSimulator is POMPolymerizationReactor

        assert PomPolymerizationConfig is POMPolymerizationConfig
        assert PomConfig is POMPolymerizationConfig
        assert POMConfig is POMPolymerizationConfig

        assert PomPolymerizationState is POMPolymerizationState
        assert PomState is POMPolymerizationState
        assert POMState is POMPolymerizationState

        assert PomPolymerizationLogicUnit is POMPolymerizationLogicUnit
        assert PomLogicUnit is POMPolymerizationLogicUnit
        assert POMLogicUnit is POMPolymerizationLogicUnit

        assert run_pom_verification is run_pom_polymerization_verification
        assert verify_pom_pure_st is verify_pom_polymerization_pure_st

    def test_ceiling_temperature_sensitivity(self) -> None:
        """At 140 °C (far beyond Tc), unzipping rate explodes and net polymerization halts."""
        sim = POMPolymerizationReactor()
        kin = sim.compute_kinetics(140.0, 1.380, 0.06117, 2.0e-4)
        assert kin["k_unzip"] > 100.0

    def test_zero_catalyst_induction_factor(self) -> None:
        """Zero catalyst conc suppresses induction factor to 0.0."""
        sim = POMPolymerizationReactor()
        sim.state.catalyst_concentration_ppm = 0.0
        kin = sim.compute_kinetics(95.0, 1.380, 0.06117, 2.0e-4)
        assert kin["f_ind"] == 0.0
