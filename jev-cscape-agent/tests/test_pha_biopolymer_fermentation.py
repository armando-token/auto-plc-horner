"""Comprehensive Industrial Polyhydroxyalkanoates (PHA) Biopolymer Fermentation Test Suite.

Work Package: W272 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 15 comprehensive engineering verification sections:
1. Section 1: Universal Physical & Biochemical Constants, Molecular Weights & Reaction Enthalpy
2. Section 2: Microbial Growth, PHA Synthesis Monod Kinetics & Nitrogen Inhibition Switch
3. Section 3: Fermenter Geometry, Broth Volume, Aeration, and Operating Baseline
4. Section 4: Nominal Steady-State Closed-Loop Convergence (X=42.5 g/L, P=68.0 g/L, S=12.0 g/L, N=0.15 g/L, DO=35.0%)
5. Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
6. Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O/N, Carbon < 1e-10)
7. Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xFB01 > 0xFB02 > 0xFB03 > 0xFB04 > 0x0000)
8. Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
9. Section 9: Fault Injections, Actuations & Emergency Nutrient Feed Stop Coil %M545, Permissive %M544
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2330..%R2337, %M543..%M545)
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

from jev_cscape.simulation.pha_biopolymer_fermentation import (
    ACCUMULATION_PHASE_SWITCH_N_G_L,
    BIOMASS_CONC_NOMINAL_G_L,
    COIL_PHA_ACCUMULATION_PHASE_ACTIVE,
    COIL_PHA_EMERGENCY_FEED_STOP,
    COIL_PHA_FERMENTER_ACTIVE,
    COIL_PHA_NUTRIENT_FEED_PERMISSIVE,
    COIL_PHA_OXYGEN_DEPLETION_TRIPPED,
    DELTA_H_METABOLISM_KJ_MOL,
    DISSOLVED_OXYGEN_NOMINAL_PCT,
    DO_DEPLETION_TRIP_PCT,
    G_ACCEL,
    MW_BIOMASS_CMOL,
    MW_C,
    MW_CO2,
    MW_GLUCOSE,
    MW_H,
    MW_H2O,
    MW_N,
    MW_NITROGEN_N,
    MW_O,
    MW_O2,
    MW_PHA_MER,
    MW_PHB_MER,
    MW_POLYMER_MER,
    MW_S,
    MW_SUBSTRATE,
    NITROGEN_CONC_NOMINAL_G_L,
    NITROGEN_OVERFEED_FAULT_G_L,
    PHA_BIOPOLYMER_FERMENTATION_PURE_ST_POU,
    PHA_BIOPOLYMER_FERMENTATION_SYNC_POU,
    PHA_PURE_ST_POU,
    PHA_SYNC_POU,
    POLYMER_ACCUMULATION_NOMINAL_G_L,
    R_GAS_CONST,
    REG_PHA_ACCUMULATION_PCT_SCALED,
    REG_PHA_BIOMASS_CONC_SCALED,
    REG_PHA_DIAGNOSTIC_CODE,
    REG_PHA_DISSOLVED_OXYGEN_SCALED,
    REG_PHA_FERMENTER_TEMP_SCALED,
    REG_PHA_KLA_TRANSFER_RATE_SCALED,
    REG_PHA_NITROGEN_CONC_SCALED,
    REG_PHA_POLYMER_ACCUMULATION_SCALED,
    REG_PHA_SPECIFIC_GROWTH_RATE_SCALED,
    REG_PHA_SUBSTRATE_CONC_SCALED,
    REG_PHA_SUBSTRATE_GLUCOSE_SCALED,
    REG_PHA_VESSEL_VOLUME_SCALED,
    SPECIFIC_GROWTH_RATE_NOMINAL_H1,
    SUBSTRATE_EXHAUSTION_FAULT_G_L,
    SUBSTRATE_GLUCOSE_NOMINAL_G_L,
    T_FERMENTER_NOMINAL_C,
    T_ZERO_CELSIUS,
    VESSEL_OVERFILL_FAULT_L,
    VESSEL_VOLUME_NOMINAL_L,
    DiagnosticCode,
    PHABiopolymerConfig,
    PHABiopolymerFermentationConfig,
    PHABiopolymerFermentationLogicUnit,
    PHABiopolymerFermentationReactor,
    PHABiopolymerFermentationState,
    PHABiopolymerFermentationStatusBits,
    PHABiopolymerState,
    PHADiagnosticCode,
    PHAEngine,
    PHAFeedConfig,
    PHAFermenter,
    PHAFermentation,
    PHAFermenterDiagnosticCode,
    PHAFermenterState,
    PHAFermenterStatusBits,
    PHAFermentationStatusBits,
    PHALogicUnit,
    PHAModel,
    PHAPlantModel,
    PHASimulator,
    PHAState,
    PHAStatusBits,
    PHAConfig,
    PhaBiopolymerConfig,
    PhaBiopolymerFermentationReactor,
    PhaBiopolymerLogicUnit,
    PhaBiopolymerReactor,
    PhaBiopolymerState,
    PhaConfig,
    PhaDiagnosticCode,
    PhaEngine,
    PhaFermenter,
    PhaFermenterDiagnosticCode,
    PhaFermenterState,
    PhaFermenterStatusBits,
    PhaFermentation,
    PhaLogicUnit,
    PhaSimulator,
    PhaState,
    PhaStatusBits,
    PureSTValidationResult,
    run_pha_biopolymer_fermentation_verification,
    run_pha_verification,
    verify_pha_biopolymer_fermentation_pure_st,
    verify_pha_pure_st,
)


# ============================================================================
# Section 1: Universal Physical & Biochemical Constants, Molecular Weights & Reaction Enthalpy
# ============================================================================

class TestSection01PhysicalAndBiochemicalConstants:
    """Verify universal physical constants, IUPAC atomic weights, and biochemical thermodynamics."""

    def test_universal_physical_constants(self) -> None:
        """Universal gas constant, standard gravity, and zero Celsius reference."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-8)
        assert math.isclose(T_FERMENTER_NOMINAL_C, 30.0, rel_tol=1e-8)

    def test_iupac_atomic_weights(self) -> None:
        """Standard atomic weights for C, H, O, N, S [g/mol]."""
        assert math.isclose(MW_C, 12.011, rel_tol=1e-5)
        assert math.isclose(MW_H, 1.008, rel_tol=1e-5)
        assert math.isclose(MW_O, 15.999, rel_tol=1e-5)
        assert math.isclose(MW_N, 14.007, rel_tol=1e-5)
        assert math.isclose(MW_S, 32.065, rel_tol=1e-5)
        assert math.isclose(MW_NITROGEN_N, MW_N)

    def test_molecular_weights_species(self) -> None:
        """Exact molecular weights for glucose, PHA monomer repeat unit, biomass, and respiratory gases."""
        expected_glucose = 6.0 * MW_C + 12.0 * MW_H + 6.0 * MW_O
        assert math.isclose(MW_GLUCOSE, expected_glucose, rel_tol=1e-6)
        assert math.isclose(MW_SUBSTRATE, MW_GLUCOSE)

        expected_phb = 4.0 * MW_C + 6.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_PHB_MER, expected_phb, rel_tol=1e-6)
        assert math.isclose(MW_PHA_MER, MW_PHB_MER)
        assert math.isclose(MW_POLYMER_MER, MW_PHB_MER)

        expected_biomass = 1.0 * MW_C + 1.8 * MW_H + 0.5 * MW_O + 0.2 * MW_N
        assert math.isclose(MW_BIOMASS_CMOL, expected_biomass, rel_tol=1e-6)

        assert math.isclose(MW_O2, 2.0 * MW_O, rel_tol=1e-6)
        assert math.isclose(MW_CO2, 1.0 * MW_C + 2.0 * MW_O, rel_tol=1e-6)
        assert math.isclose(MW_H2O, 2.0 * MW_H + 1.0 * MW_O, rel_tol=1e-6)

    def test_metabolic_reaction_enthalpy(self) -> None:
        """Exothermic aerobic metabolic heat of combustion enthalpy."""
        assert DELTA_H_METABOLISM_KJ_MOL == -2808.0


# ============================================================================
# Section 2: Microbial Growth, PHA Synthesis Monod Kinetics & Nitrogen Inhibition Switch
# ============================================================================

class TestSection02MonodKineticsAndNitrogenSwitch:
    """Verify dual Monod growth kinetics and nitrogen exhaustion regulatory switch."""

    def test_default_kinetic_parameters(self) -> None:
        """Default maximum growth rate, accumulation rate, and affinity saturation constants."""
        config = PHABiopolymerFermentationConfig()
        assert config.mu_max_h1 > 0.30
        assert config.q_p_max_h1 > 1.0
        assert config.k_s_glucose_g_l == 1.5
        assert config.k_n_nitrogen_g_l == 0.08
        assert config.k_do_oxygen_pct == 5.0
        assert config.k_sp_glucose_g_l == 1.0
        assert config.k_in_nitrogen_g_l == 0.10
        assert config.k_dop_oxygen_pct == 5.0
        assert config.p_max_capacity_g_l == 170.0

    def test_nominal_kinetics_evaluation(self) -> None:
        """Nominal conditions produce mu = 0.180 1/h and q_p = 0.288 1/h."""
        sim = PHABiopolymerFermentationReactor()
        mu, q_p, kla, our = sim.compute_kinetics(
            x=BIOMASS_CONC_NOMINAL_G_L,
            s=SUBSTRATE_GLUCOSE_NOMINAL_G_L,
            n=NITROGEN_CONC_NOMINAL_G_L,
            p=POLYMER_ACCUMULATION_NOMINAL_G_L,
            do=DISSOLVED_OXYGEN_NOMINAL_PCT,
            v=VESSEL_VOLUME_NOMINAL_L,
        )
        assert math.isclose(mu, 0.180, abs_tol=0.005)
        assert math.isclose(q_p, 0.288, abs_tol=0.005)
        assert math.isclose(kla, 150.0, abs_tol=0.1)
        assert our > 0.0

    def test_growth_phase_under_excess_nitrogen(self) -> None:
        """Under high nitrogen (N = 1.00 g/L), catalytic cell growth is rapid and dominant."""
        sim = PHABiopolymerFermentationReactor()
        mu_high, q_p_high, _, _ = sim.compute_kinetics(
            x=42.5,
            s=12.0,
            n=1.00,
            p=10.0,
            do=35.0,
            v=105.0,
        )
        assert mu_high > 0.25
        assert mu_high > q_p_high

    def test_accumulation_phase_triggered_on_nitrogen_exhaustion(self) -> None:
        """When nitrogen is exhausted (N -> 0), cell growth halts and PHA accumulation accelerates."""
        sim = PHABiopolymerFermentationReactor()
        mu_low, q_p_low, _, _ = sim.compute_kinetics(
            x=42.5,
            s=12.0,
            n=0.005,
            p=10.0,
            do=35.0,
            v=105.0,
        )
        assert mu_low < 0.05
        assert q_p_low > 0.50
        assert q_p_low > mu_low * 5.0

    def test_intracellular_saturation_headroom(self) -> None:
        """When intracellular PHA reaches capacity limit (170.0 g/L), accumulation rate halts."""
        sim = PHABiopolymerFermentationReactor()
        mu, q_p_saturated, _, _ = sim.compute_kinetics(
            x=42.5,
            s=12.0,
            n=0.05,
            p=170.0,
            do=35.0,
            v=105.0,
        )
        assert math.isclose(q_p_saturated, 0.0, abs_tol=1e-6)


# ============================================================================
# Section 3: Fermenter Geometry, Broth Volume, Aeration, and Operating Baseline
# ============================================================================

class TestSection03FermenterGeometryAndAeration:
    """Verify fermenter volume, broth density, Kla oxygen mass transfer, and baseline constants."""

    def test_fermenter_geometric_and_physical_parameters(self) -> None:
        """Broth volume, working volume limit, and liquid density."""
        config = PHABiopolymerFermentationConfig()
        assert config.nominal_volume_l == 105.0
        assert config.maximum_working_volume_l == 140.0
        assert config.broth_density_kg_l == 1.035
        assert config.temperature_c == 30.0

    def test_kla_and_oxygen_mass_transfer(self) -> None:
        """Volumetric mass transfer coefficient Kla and driving force OTR."""
        config = PHABiopolymerFermentationConfig()
        assert config.kla_volumetric_mass_transfer_h1 == 150.0
        assert config.do_sat_pct == 100.0

        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        assert math.isclose(sim.state.oxygen_transfer_rate_pct_h, 9750.0, abs_tol=1.0)
        assert math.isclose(sim.state.oxygen_uptake_rate_pct_h, 9743.70, abs_tol=5.0)

    def test_nominal_operating_baseline_constants(self) -> None:
        """Operating baseline constants: X=42.5, P=68.0, S=12.0, N=0.15, DO=35.0%, V=105.0 L, mu=0.180."""
        assert BIOMASS_CONC_NOMINAL_G_L == 42.5
        assert POLYMER_ACCUMULATION_NOMINAL_G_L == 68.0
        assert SUBSTRATE_GLUCOSE_NOMINAL_G_L == 12.0
        assert NITROGEN_CONC_NOMINAL_G_L == 0.15
        assert DISSOLVED_OXYGEN_NOMINAL_PCT == 35.0
        assert VESSEL_VOLUME_NOMINAL_L == 105.0
        assert SPECIFIC_GROWTH_RATE_NOMINAL_H1 == 0.180

    def test_safety_interlock_threshold_constants(self) -> None:
        """Threshold limits: DO_trip < 10.0%, S_trip < 2.0 g/L, V_trip > 140.0 L, N_overfeed > 1.00 g/L."""
        assert DO_DEPLETION_TRIP_PCT == 10.0
        assert SUBSTRATE_EXHAUSTION_FAULT_G_L == 2.0
        assert VESSEL_OVERFILL_FAULT_L == 140.0
        assert NITROGEN_OVERFEED_FAULT_G_L == 1.00
        assert ACCUMULATION_PHASE_SWITCH_N_G_L == 0.20


# ============================================================================
# Section 4: Nominal Steady-State Closed-Loop Convergence
# ============================================================================

class TestSection04NominalSteadyStateConvergence:
    """Verify nominal steady-state convergence (X=42.5 g/L, P=68.0 g/L, S=12.0 g/L, N=0.15 g/L, DO=35.0%)."""

    def test_nominal_steady_state_initialization(self) -> None:
        """Fresh fermenter instance initializes to nominal operating steady-state."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        assert math.isclose(sim.state.biomass_conc_g_l, 42.5, abs_tol=0.2)
        assert math.isclose(sim.state.polymer_accumulation_g_l, 68.0, abs_tol=0.2)
        assert math.isclose(sim.state.substrate_glucose_g_l, 12.0, abs_tol=0.2)
        assert math.isclose(sim.state.nitrogen_conc_g_l, 0.15, abs_tol=0.02)
        assert math.isclose(sim.state.dissolved_oxygen_pct, 35.0, abs_tol=0.2)
        assert math.isclose(sim.state.vessel_volume_l, 105.0, abs_tol=0.5)
        assert math.isclose(sim.state.specific_growth_rate_h1, 0.180, abs_tol=0.005)
        assert math.isclose(sim.state.total_biomass_dcw_g_l, 110.5, abs_tol=0.5)
        assert math.isclose(sim.state.pha_mass_fraction_pct, 61.54, abs_tol=0.5)
        assert sim.state.fermenter_active is True
        assert sim.state.accumulation_phase_active is True
        assert sim.state.oxygen_depletion_tripped is False
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_steady_state_closed_loop_retention(self) -> None:
        """Advancing 20 scan cycles retains steady-state values within tight tolerances."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        for _ in range(20):
            sim.scan_step(dt=0.02)

        assert 42.0 <= sim.state.biomass_conc_g_l <= 43.0
        assert 67.5 <= sim.state.polymer_accumulation_g_l <= 68.5
        assert 11.5 <= sim.state.substrate_glucose_g_l <= 12.5
        assert 0.14 <= sim.state.nitrogen_conc_g_l <= 0.16
        assert 34.5 <= sim.state.dissolved_oxygen_pct <= 35.5
        assert 104.5 <= sim.state.vessel_volume_l <= 105.5
        assert sim.state.diagnostic_code == DiagnosticCode.OK


# ============================================================================
# Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
# ============================================================================

class TestSection05CoupledODESystemAndRK4Integrator:
    """Verify 6-state ODE formulation, derivative computation, RK4 stability, and state non-negativity."""

    def test_state_vector_definition(self) -> None:
        """Dynamic 6-state vector components are well-defined and accessible."""
        state = PHABiopolymerFermentationState()
        assert state.biomass_conc_g_l > 0.0
        assert state.polymer_accumulation_g_l > 0.0
        assert state.substrate_glucose_g_l > 0.0
        assert state.nitrogen_conc_g_l > 0.0
        assert state.dissolved_oxygen_pct > 0.0
        assert state.vessel_volume_l > 0.0

    def test_ode_system_shape_and_finite(self) -> None:
        """ODE system returns exactly 6 finite float components."""
        sim = PHABiopolymerFermentationReactor()
        y0 = [42.5, 12.0, 0.15, 68.0, 35.0, 105.0]
        derivs = sim.ode_system(y0)
        assert len(derivs) == 6
        assert all(math.isfinite(d) for d in derivs)

    def test_rk4_step_execution_and_state_non_negativity(self) -> None:
        """RK4 step advances time and maintains non-negative finite state variables."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        t0 = sim.state.sim_time_s

        sim.rk4_step(dt=0.02)
        assert sim.state.sim_time_s > t0
        assert sim.state.biomass_conc_g_l >= 0.0
        assert sim.state.polymer_accumulation_g_l >= 0.0
        assert sim.state.substrate_glucose_g_l >= 0.0
        assert sim.state.nitrogen_conc_g_l >= 0.0
        assert 0.0 <= sim.state.dissolved_oxygen_pct <= 100.0
        assert sim.state.vessel_volume_l >= 1.0

    def test_rk4_numerical_stability_across_timesteps(self) -> None:
        """RK4 integrator remains stable under varying dt (0.005, 0.01, 0.02 s)."""
        for dt_test in [0.005, 0.01, 0.02]:
            sim = PHABiopolymerFermentationReactor()
            sim.reset()
            for _ in range(50):
                sim.rk4_step(dt=dt_test)
            assert 42.0 <= sim.state.biomass_conc_g_l <= 43.0
            assert not math.isnan(sim.state.biomass_conc_g_l)
            assert not math.isinf(sim.state.biomass_conc_g_l)


# ============================================================================
# Section 6: Mathematical Conservation Residuals
# ============================================================================

class TestSection06ConservationLawsResiduals:
    """Verify stoichiometric mass, elemental, and carbon conservation residuals (< 1e-10)."""

    def test_total_mass_balance_residual(self) -> None:
        """Total mass balance residual across fed-batch vessel is strictly < 1e-10 kg/s."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.total_mass_balance_residual_kg_s >= 0.0

    def test_elemental_balance_residual(self) -> None:
        """Elemental mass balance residual is < 1e-10 kg/s."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s >= 0.0

    def test_carbon_mass_balance_residual(self) -> None:
        """Carbon mass conservation residual is strictly < 1e-10 kg/s."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.carbon_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.carbon_mass_balance_residual_kg_s >= 0.0

    def test_conservation_residuals_preserved_after_transient_steps(self) -> None:
        """All three conservation residuals remain < 1e-10 after 50 scan cycles."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        for _ in range(50):
            sim.scan_step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.carbon_mass_balance_residual_kg_s < 1.0e-10


# ============================================================================
# Section 7: Process Safety Interlocks & Strict Priority Hierarchy
# ============================================================================

class TestSection07SafetyInterlocksAndPriorityHierarchy:
    """Verify strict priority hierarchy: 0xFB01 > 0xFB02 > 0xFB03 > 0xFB04 > 0x0000."""

    def test_priority_1_oxygen_depletion_trip(self) -> None:
        """0xFB01 DISSOLVED_OXYGEN_DEPLETION_TRIP trips when DO < 10.0% sat."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.state.dissolved_oxygen_pct = 7.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP
        assert sim.state.oxygen_depletion_tripped is True
        assert sim.state.fermenter_active is False
        assert sim.state.accumulation_phase_active is False

    def test_priority_2_substrate_exhaustion_fault(self) -> None:
        """0xFB02 SUBSTRATE_EXHAUSTION_FAULT trips when glucose < 2.0 g/L."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.state.substrate_glucose_g_l = 1.2
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT
        assert sim.state.oxygen_depletion_tripped is False
        assert sim.state.fermenter_active is False
        assert sim.state.accumulation_phase_active is False

    def test_priority_3_vessel_overfill_fault(self) -> None:
        """0xFB03 VESSEL_OVERFILL_FAULT trips when broth volume > 140.0 L."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.state.vessel_volume_l = 145.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VESSEL_OVERFILL_FAULT
        assert sim.state.oxygen_depletion_tripped is False
        assert sim.state.fermenter_active is False
        assert sim.state.accumulation_phase_active is False

    def test_priority_4_nitrogen_overfeed_fault(self) -> None:
        """0xFB04 NITROGEN_OVERFEED_ACCUMULATION_FAULT asserts when N > 1.00 g/L."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.state.nitrogen_conc_g_l = 1.35
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.NITROGEN_OVERFEED_ACCUMULATION_FAULT
        assert sim.state.oxygen_depletion_tripped is False
        assert sim.state.fermenter_active is True
        assert sim.state.accumulation_phase_active is False

    def test_priority_5_normal_steady_state_ok(self) -> None:
        """0x0000 OK when all variables within nominal safety envelope."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.fermenter_active is True
        assert sim.state.accumulation_phase_active is True
        assert sim.state.oxygen_depletion_tripped is False

    def test_strict_priority_overrides(self) -> None:
        """Higher priority faults deterministically preempt lower priority faults."""
        sim = PHABiopolymerFermentationReactor()

        # Oxygen depletion (0xFB01) preempts substrate (0xFB02) and overfill (0xFB03)
        sim.reset()
        sim.state.dissolved_oxygen_pct = 5.0
        sim.state.substrate_glucose_g_l = 1.0
        sim.state.vessel_volume_l = 150.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP

        # Substrate exhaustion (0xFB02) preempts overfill (0xFB03)
        sim.reset()
        sim.state.dissolved_oxygen_pct = 35.0
        sim.state.substrate_glucose_g_l = 1.0
        sim.state.vessel_volume_l = 150.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT

        # Overfill (0xFB03) preempts nitrogen overfeed (0xFB04)
        sim.reset()
        sim.state.dissolved_oxygen_pct = 35.0
        sim.state.substrate_glucose_g_l = 12.0
        sim.state.vessel_volume_l = 150.0
        sim.state.nitrogen_conc_g_l = 1.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VESSEL_OVERFILL_FAULT


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
# ============================================================================

class TestSection08DiagnosticCodes16BitValues:
    """Verify signed and unsigned 16-bit values, comparisons, string formatting, and masking."""

    def test_diagnostic_code_hex_and_integer_values(self) -> None:
        """Hex integer values match W272 specification."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP.value == 0xFB01
        assert DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT.value == 0xFB02
        assert DiagnosticCode.VESSEL_OVERFILL_FAULT.value == 0xFB03
        assert DiagnosticCode.NITROGEN_OVERFEED_ACCUMULATION_FAULT.value == 0xFB04

    def test_signed_16bit_representation(self) -> None:
        """Signed 16-bit two's complement values: 0xFB01=-1279, 0xFB02=-1278, 0xFB03=-1277, 0xFB04=-1276."""
        assert (0xFB01 - 65536) == -1279
        assert (0xFB02 - 65536) == -1278
        assert (0xFB03 - 65536) == -1277
        assert (0xFB04 - 65536) == -1276

    def test_signed_and_unsigned_equality(self) -> None:
        """DiagnosticCode compares equal with signed and unsigned integers transparently."""
        assert DiagnosticCode.OK == 0
        assert DiagnosticCode.OK == 0x0000

        assert DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP == 0xFB01
        assert DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP == 64257
        assert DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP == -1279

        assert DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT == 0xFB02
        assert DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT == 64258
        assert DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT == -1278

        assert DiagnosticCode.VESSEL_OVERFILL_FAULT == 0xFB03
        assert DiagnosticCode.VESSEL_OVERFILL_FAULT == 64259
        assert DiagnosticCode.VESSEL_OVERFILL_FAULT == -1277

        assert DiagnosticCode.NITROGEN_OVERFEED_ACCUMULATION_FAULT == 0xFB04
        assert DiagnosticCode.NITROGEN_OVERFEED_ACCUMULATION_FAULT == 64260
        assert DiagnosticCode.NITROGEN_OVERFEED_ACCUMULATION_FAULT == -1276

    def test_missing_lookup_signed_integer(self) -> None:
        """DiagnosticCode constructor / _missing_ converts signed int back to enum."""
        assert DiagnosticCode(-1279) == DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP
        assert DiagnosticCode(-1278) == DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT
        assert DiagnosticCode(-1277) == DiagnosticCode.VESSEL_OVERFILL_FAULT
        assert DiagnosticCode(-1276) == DiagnosticCode.NITROGEN_OVERFEED_ACCUMULATION_FAULT

    def test_bitwise_masking_and_string_representation(self) -> None:
        """Bitwise & 0xFFFF and __str__() output formatted as 0xXXXX."""
        assert (DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP & 0xFFFF) == 0xFB01
        assert (DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT & 0xFFFF) == 0xFB02
        assert (DiagnosticCode.VESSEL_OVERFILL_FAULT & 0xFFFF) == 0xFB03
        assert (DiagnosticCode.NITROGEN_OVERFEED_ACCUMULATION_FAULT & 0xFFFF) == 0xFB04

        s = str(DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP)
        assert "0xFB01" in s


# ============================================================================
# Section 9: Fault Injections, Actuations & Emergency Nutrient Feed Stop Coil %M545
# ============================================================================

class TestSection09FaultInjectionsAndActuations:
    """Verify inject_fault(), clear_faults(), and coil state transitions."""

    def test_inject_oxygen_depletion_fault(self) -> None:
        """Injecting oxygen depletion triggers 0xFB01 and asserts %M545 emergency trip."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.inject_fault("oxygen")
        assert sim.state.diagnostic_code == DiagnosticCode.DISSOLVED_OXYGEN_DEPLETION_TRIP
        assert sim.state.oxygen_depletion_tripped is True
        assert sim.state.fermenter_active is False
        assert sim.state.accumulation_phase_active is False

    def test_inject_substrate_exhaustion_fault(self) -> None:
        """Injecting substrate exhaustion triggers 0xFB02 and halts active feeding."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.inject_fault("substrate")
        assert sim.state.diagnostic_code == DiagnosticCode.SUBSTRATE_EXHAUSTION_FAULT
        assert sim.state.oxygen_depletion_tripped is False
        assert sim.state.fermenter_active is False
        assert sim.state.accumulation_phase_active is False

    def test_inject_vessel_overfill_fault(self) -> None:
        """Injecting overfill triggers 0xFB03 and stops feed."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.inject_fault("volume")
        assert sim.state.diagnostic_code == DiagnosticCode.VESSEL_OVERFILL_FAULT
        assert sim.state.oxygen_depletion_tripped is False
        assert sim.state.fermenter_active is False
        assert sim.state.accumulation_phase_active is False

    def test_inject_nitrogen_overfeed_fault(self) -> None:
        """Injecting nitrogen overfeed triggers 0xFB04 and clears %M544 accumulation permissive."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.inject_fault("nitrogen")
        assert sim.state.diagnostic_code == DiagnosticCode.NITROGEN_OVERFEED_ACCUMULATION_FAULT
        assert sim.state.oxygen_depletion_tripped is False
        assert sim.state.fermenter_active is True
        assert sim.state.accumulation_phase_active is False

    def test_clear_faults_restores_nominal(self) -> None:
        """Calling clear_faults() restores nominal baseline and clears trips."""
        sim = PHABiopolymerFermentationReactor()
        sim.inject_fault("oxygen")
        assert sim.state.diagnostic_code != DiagnosticCode.OK
        sim.clear_faults()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.oxygen_depletion_tripped is False
        assert sim.state.fermenter_active is True
        assert sim.state.accumulation_phase_active is True


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege
# ============================================================================

class TestSection10HornerOCSMemoryIntegration:
    """Verify register synchronization (%R2330..%R2337, %M543..%M545) and privilege."""

    def test_nominal_register_table_synchronization(self) -> None:
        """Registers and coils match nominal steady-state values bit-exactly."""
        table = RegisterTable()
        sim = PHABiopolymerFermentationReactor(register_table=table)
        sim.reset()

        assert table.read_word(REG_PHA_BIOMASS_CONC_SCALED) == 425
        assert table.read_word(REG_PHA_POLYMER_ACCUMULATION_SCALED) == 680
        assert table.read_word(REG_PHA_SUBSTRATE_GLUCOSE_SCALED) == 120
        assert table.read_word(REG_PHA_NITROGEN_CONC_SCALED) == 15
        assert table.read_word(REG_PHA_DISSOLVED_OXYGEN_SCALED) == 350
        assert table.read_word(REG_PHA_VESSEL_VOLUME_SCALED) == 1050
        assert table.read_word(REG_PHA_SPECIFIC_GROWTH_RATE_SCALED) == 180
        assert table.read_uword(REG_PHA_DIAGNOSTIC_CODE) == 0x0000

        assert table.read_bit(COIL_PHA_FERMENTER_ACTIVE) is True
        assert table.read_bit(COIL_PHA_ACCUMULATION_PHASE_ACTIVE) is True
        assert table.read_bit(COIL_PHA_OXYGEN_DEPLETION_TRIPPED) is False

    def test_trip_register_table_synchronization(self) -> None:
        """When 0xFB01 trips, %R2337 reflects signed -1279 and %M545 emergency trip asserts."""
        table = RegisterTable()
        sim = PHABiopolymerFermentationReactor(register_table=table)
        sim.inject_fault("oxygen")

        assert table.read_uword(REG_PHA_DIAGNOSTIC_CODE) == 0xFB01
        assert table.read_word(REG_PHA_DIAGNOSTIC_CODE) == -1279
        assert table.read_bit(COIL_PHA_FERMENTER_ACTIVE) is False
        assert table.read_bit(COIL_PHA_OXYGEN_DEPLETION_TRIPPED) is True

    def test_system_privilege_sync(self) -> None:
        """Registers synchronized with SYSTEM privilege overwrite protected memory channels."""
        table = RegisterTable()
        sim = PHABiopolymerFermentationReactor()
        sim.reset()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2330") == 425


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection11PureSTPOUAndASTValidation:
    """Verify IEC 61131-3 Structured Text compliance, parser validation, and register memory bindings."""

    def test_pure_st_pou_security_guard_and_parser(self) -> None:
        """PHA_BIOPOLYMER_FERMENTATION_PURE_ST_POU passes SecurityGuard and STParser cleanly."""
        SecurityGuard.assert_pure_st_content(PHA_BIOPOLYMER_FERMENTATION_PURE_ST_POU)
        res = STParser.validate_code(PHA_BIOPOLYMER_FERMENTATION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_ast_variable_memory_address_bindings(self) -> None:
        """Parsed AST POU contains all 11 required %R2330..%R2337 and %M543..%M545 bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(PHA_BIOPOLYMER_FERMENTATION_PURE_ST_POU)
        assert pou is not None
        assert pou.name in ("PhaBiopolymerFermentationSync", "PHABiopolymerFermentationSync")

        required_registers = [
            "%R2330", "%R2331", "%R2332", "%R2333",
            "%R2334", "%R2335", "%R2336", "%R2337",
            "%M543", "%M544", "%M545",
        ]
        for reg in required_registers:
            assert reg in pou.bound_registers, f"Missing register {reg} in AST bindings"

        for var in pou.variables:
            addr = getattr(var, "address_binding", None) or getattr(var, "memory_address", None)
            if addr:
                assert addr.startswith(("%R", "%M"))

    def test_verify_pha_biopolymer_fermentation_pure_st_function(self) -> None:
        """Helper verification function returns successful result."""
        res = verify_pha_biopolymer_fermentation_pure_st()
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
            SecurityGuard.assert_pure_st_content("NETWORK 10\nLD %M543\nST %M545")

    def test_reject_ladder_mnemonics(self) -> None:
        """XIC and OTE mnemonics are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC %M543 OTE %M545")


# ============================================================================
# Section 13: ILogicUnit Compliance & 100-Cycle Soak Stability
# ============================================================================

class TestSection13ILogicUnitComplianceAndSoakStability:
    """Verify ILogicUnit interface compliance, reset dynamics, and 100-cycle soak stability."""

    def test_ilogic_unit_interface_compliance(self) -> None:
        """PHABiopolymerFermentationReactor and LogicUnit wrapper implement ILogicUnit protocol."""
        reactor = PHABiopolymerFermentationReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name in ("PHABiopolymerFermentationReactor", "PhaBiopolymerFermentationReactor")
        assert reactor.priority == 272
        assert reactor.is_enabled is True

        logic_unit = PHABiopolymerFermentationLogicUnit()
        assert isinstance(logic_unit, ILogicUnit)
        assert logic_unit.is_enabled is True

    def test_enable_disable_lifecycle(self) -> None:
        """Disabling logic unit halts scan execution."""
        reactor = PHABiopolymerFermentationReactor()
        reactor.disable()
        assert reactor.is_enabled is False
        t_before = reactor.state.sim_time_s
        reactor.scan_step(0.02)
        assert reactor.state.sim_time_s == t_before
        reactor.enable()
        assert reactor.is_enabled is True

    def test_100_cycle_soak_stability(self) -> None:
        """100 scan cycles execute with zero NaN, zero Inf, and bounded state variables."""
        sim = PHABiopolymerFermentationReactor()
        sim.reset()

        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        assert not math.isnan(sim.state.biomass_conc_g_l)
        assert not math.isnan(sim.state.polymer_accumulation_g_l)
        assert not math.isnan(sim.state.vessel_volume_l)
        assert not math.isnan(sim.state.dissolved_oxygen_pct)
        assert not math.isinf(sim.state.biomass_conc_g_l)

        assert 42.0 <= sim.state.biomass_conc_g_l <= 43.0
        assert 67.0 <= sim.state.polymer_accumulation_g_l <= 69.0
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.fermenter_active is True
        assert sim.state.oxygen_depletion_tripped is False


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14VerificationSuiteAndArtifactGeneration:
    """Verify run_pha_biopolymer_fermentation_verification() output contract and evidence emission."""

    def test_run_verification_suite_success(self, tmp_path: Path) -> None:
        """Verification suite runs all 9 stages cleanly and returns strict 4-state contract."""
        out_file = tmp_path / "pha_test_evidence.json"
        res = run_pha_biopolymer_fermentation_verification(output_path=out_file)

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
        assert PhaBiopolymerReactor is PHABiopolymerFermentationReactor
        assert PhaFermenter is PHABiopolymerFermentationReactor
        assert PHAFermenter is PHABiopolymerFermentationReactor
        assert PhaFermentation is PHABiopolymerFermentationReactor
        assert PHAFermentation is PHABiopolymerFermentationReactor
        assert PhaSimulator is PHABiopolymerFermentationReactor
        assert PHASimulator is PHABiopolymerFermentationReactor
        assert PhaEngine is PHABiopolymerFermentationReactor
        assert PHAEngine is PHABiopolymerFermentationReactor

        assert PhaBiopolymerConfig is PHABiopolymerFermentationConfig
        assert PhaConfig is PHABiopolymerFermentationConfig
        assert PHAConfig is PHABiopolymerFermentationConfig
        assert PHABiopolymerConfig is PHABiopolymerFermentationConfig
        assert PHAFeedConfig is PHABiopolymerFermentationConfig

        assert PhaBiopolymerState is PHABiopolymerFermentationState
        assert PhaState is PHABiopolymerFermentationState
        assert PHAState is PHABiopolymerFermentationState
        assert PHAFermenterState is PHABiopolymerFermentationState
        assert PhaFermenterState is PHABiopolymerFermentationState

        assert PhaBiopolymerLogicUnit is PHABiopolymerFermentationLogicUnit
        assert PhaLogicUnit is PHABiopolymerFermentationLogicUnit
        assert PHALogicUnit is PHABiopolymerFermentationLogicUnit

        assert run_pha_verification is run_pha_biopolymer_fermentation_verification
        assert verify_pha_pure_st is verify_pha_biopolymer_fermentation_pure_st

    def test_zero_glucose_suppression(self) -> None:
        """Zero glucose completely halts cell growth and PHA synthesis."""
        sim = PHABiopolymerFermentationReactor()
        mu, q_p, _, _ = sim.compute_kinetics(42.5, 0.0, 0.15, 68.0, 35.0, 105.0)
        assert mu == 0.0
        assert q_p == 0.0

    def test_anoxic_zero_oxygen_suppression(self) -> None:
        """Zero dissolved oxygen completely halts aerobic growth and PHA synthesis."""
        sim = PHABiopolymerFermentationReactor()
        mu, q_p, _, _ = sim.compute_kinetics(42.5, 12.0, 0.15, 68.0, 0.0, 105.0)
        assert mu == 0.0
        assert q_p == 0.0
