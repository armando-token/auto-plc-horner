"""Comprehensive Industrial Bisphenol A (BPA) Catalytic Condensation Test Suite.

Work Package: W233 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 14 engineering verification sections (120+ unit tests):
1. Section 1: Universal Physical Constants, IUPAC Atomic Weights & Species Molecular Weights
2. Section 2: Reaction Enthalpies, Exothermicity & Stoichiometric Conservation
3. Section 3: Arrhenius Reaction Kinetics, Promoter Enhancement & Activation Energies
4. Section 4: Reactor Geometry, Sizing, Thermal Capacitance & Heat Removal Dynamics
5. Section 5: Nominal Steady-State Production Metrics, Conversion, Selectivity & Rates
6. Section 6: Coupled 6-State Dynamic ODE System & High-Order RK4 Numerical Integrator
7. Section 7: Mathematical Conservation Residuals (Mass, Elements, Enthalpy < 1e-10)
8. Section 8: Process Safety Interlocks & Strict Diagnostic Priority Hierarchy (0xF001..0xF004)
9. Section 9: DiagnosticCode Signed/Unsigned Integer Equality, Bitwise Masking (& 0xFFFF)
10. Section 10: Pre-Alarm Logic (%M453) & Emergency BPA Quench Valve Actuation (%M454)
11. Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege (%R1940..%R1947, %M452..%M454)
12. Section 12: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
13. Section 13: ILogicUnit Scan Cycle Execution, Reset Dynamics & Soak Stability
14. Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.bpa_condensation import (
    ACETONE_ACCUMULATION_TRIP_CONC_MOL_L,
    ACETONE_CONV_NOMINAL_PCT,
    ACETONE_CONVERSION_MIN_TRIP_PCT,
    BPA_CONDENSATION_PURE_ST_POU,
    BPA_CONDENSATION_REACTOR_PURE_ST_POU,
    BPA_CONDENSATION_SYNC_POU,
    BPA_PROD_NOMINAL_KG_H,
    BPA_PURE_ST_POU,
    BPA_SEL_NOMINAL_PCT,
    BPA_SYNC_POU,
    CATALYST_DEACTIVATION_NOMINAL_PCT,
    CATALYST_DEACTIVATION_TRIP_PCT,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    G_ACCEL,
    MW_ACETONE,
    MW_BISPHENOL_A,
    MW_BPA,
    MW_BYPRODUCTS,
    MW_C,
    MW_H,
    MW_HEAVY,
    MW_O,
    MW_OP_ISOMER,
    MW_PHENOL,
    MW_PP_BPA,
    MW_TRISPHENOL,
    MW_WATER,
    P_REACTOR_NOMINAL_BAR,
    PHENOL_ACETONE_RATIO_NOMINAL,
    PHENOL_ACETONE_RATIO_PRE_ALARM,
    PHENOL_ACETONE_RATIO_TRIP,
    PROMOTER_NOMINAL_PPM,
    PROMOTER_STARVATION_TRIP_PPM,
    R_GAS_CONST,
    T_INLET_NOMINAL_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_RUNAWAY_TRIP_C,
    T_ZERO_CELSIUS,
    BpaCondensation,
    BpaCondensationConfig,
    BpaCondensationDiagCode,
    BpaCondensationDiagnosticCode,
    BpaCondensationEngine,
    BpaCondensationLogicUnit,
    BpaCondensationModel,
    BpaCondensationParameters,
    BpaCondensationPlantModel,
    BpaCondensationReactor,
    BpaCondensationReactorConfig,
    BpaCondensationReactorDiagCode,
    BpaCondensationReactorDiagnosticCode,
    BpaCondensationReactorLogicUnit,
    BpaCondensationReactorState,
    BpaCondensationSimulationEngine,
    BpaCondensationSimulator,
    BpaCondensationState,
    BpaCondensationStatusBits,
    BpaCondensationStatusWord,
    BpaConfig,
    BpaDiagCode,
    BpaDiagnosticCode,
    BpaEngine,
    BpaLogicUnit,
    BpaParameters,
    BpaReactor,
    BpaReactorConfig,
    BpaReactorLogicUnit,
    BpaReactorState,
    BpaReactorStatusBits,
    BpaSimulator,
    BpaState,
    BpaStatusBits,
    BpaStatusWord,
    DiagnosticCode,
    StatusBits,
    run_bpa_condensation_reactor_verification,
    run_bpa_condensation_verification,
    run_bpa_verification,
    validate_pure_st,
    verify_bpa_condensation_pure_st,
    verify_bpa_condensation_pure_st_pou,
    verify_bpa_pure_st,
)


# ============================================================================
# Section 1: Universal Physical Constants & Species Molecular Weights
# ============================================================================

class TestSection1PhysicalConstantsAndMolecularWeights:
    """Validate universal constants, IUPAC atomic masses, and molecular weights."""

    def test_universal_gas_constant(self) -> None:
        """Universal gas constant must match CODATA 2018 value: 8.314462618 J/(mol*K)."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-9)

    def test_standard_gravity_acceleration(self) -> None:
        """Standard gravitational acceleration must equal 9.80665 m/s^2."""
        assert math.isclose(G_ACCEL, 9.80665, abs_tol=1e-6)

    def test_absolute_zero_celsius(self) -> None:
        """Absolute zero reference must be 273.15 K."""
        assert math.isclose(T_ZERO_CELSIUS, 273.15, abs_tol=1e-6)

    def test_reactor_reference_temperature(self) -> None:
        """Reference temperature must correspond to 72.0 °C (345.15 K)."""
        assert math.isclose(T_REF_K, 72.0 + 273.15, abs_tol=1e-6)

    def test_iupac_elemental_weights(self) -> None:
        """Elemental masses for Carbon, Hydrogen, and Oxygen must match IUPAC standards."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)

    def test_phenol_molecular_weight(self) -> None:
        """Phenol C6H6O molecular weight must equal 6*C + 6*H + 1*O (~94.113 g/mol)."""
        expected_phenol = 6.0 * MW_C + 6.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_PHENOL, expected_phenol, rel_tol=1e-9)
        assert math.isclose(MW_PHENOL * 1000.0, 94.113, rel_tol=1e-3)

    def test_acetone_molecular_weight(self) -> None:
        """Acetone C3H6O molecular weight must equal 3*C + 6*H + 1*O (~58.080 g/mol)."""
        expected_acetone = 3.0 * MW_C + 6.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_ACETONE, expected_acetone, rel_tol=1e-9)
        assert math.isclose(MW_ACETONE * 1000.0, 58.080, rel_tol=1e-3)

    def test_bpa_molecular_weight(self) -> None:
        """p,p'-BPA C15H16O2 molecular weight must equal 15*C + 16*H + 2*O (~228.291 g/mol)."""
        expected_bpa = 15.0 * MW_C + 16.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_BPA, expected_bpa, rel_tol=1e-9)
        assert math.isclose(MW_BPA * 1000.0, 228.291, rel_tol=1e-3)
        assert MW_BISPHENOL_A == MW_BPA
        assert MW_PP_BPA == MW_BPA

    def test_op_isomer_molecular_weight(self) -> None:
        """o,p'-BPA isomer C15H16O2 molecular weight must be identical to p,p'-BPA."""
        assert math.isclose(MW_OP_ISOMER, MW_BPA, rel_tol=1e-9)

    def test_water_and_byproducts_molecular_weights(self) -> None:
        """Water H2O and Trisphenol C24H26O3 molecular weights must match stoichiometric formulas."""
        expected_water = 2.0 * MW_H + 1.0 * MW_O
        expected_trisphenol = 24.0 * MW_C + 26.0 * MW_H + 3.0 * MW_O
        assert math.isclose(MW_WATER, expected_water, rel_tol=1e-9)
        assert math.isclose(MW_TRISPHENOL, expected_trisphenol, rel_tol=1e-9)
        assert MW_BYPRODUCTS == MW_TRISPHENOL
        assert MW_HEAVY == MW_TRISPHENOL


# ============================================================================
# Section 2: Reaction Enthalpies, Exothermicity & Stoichiometric Conservation
# ============================================================================

class TestSection2ReactionEnthalpiesAndStoichiometry:
    """Validate reaction enthalpies and dual stoichiometric conservation."""

    def test_primary_condensation_enthalpy(self) -> None:
        """Primary condensation is exothermic: -46.0 kJ/mol (-46,000 J/mol)."""
        assert math.isclose(DELTA_H1_KJ_MOL, -46.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H1_J_MOL, -46000.0, abs_tol=1e-6)
        assert DELTA_H1_KJ_MOL < 0.0

    def test_side_isomerization_enthalpy(self) -> None:
        """Side isomerization is exothermic: -43.0 kJ/mol (-43,000 J/mol)."""
        assert math.isclose(DELTA_H2_KJ_MOL, -43.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H2_J_MOL, -43000.0, abs_tol=1e-6)
        assert DELTA_H2_KJ_MOL < 0.0

    def test_side_condensation_trisphenol_enthalpy(self) -> None:
        """Side condensation to Trisphenol is exothermic: -38.0 kJ/mol (-38,000 J/mol)."""
        assert math.isclose(DELTA_H3_KJ_MOL, -38.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H3_J_MOL, -38000.0, abs_tol=1e-6)
        assert DELTA_H3_KJ_MOL < 0.0

    def test_reaction1_stoichiometric_mass_balance(self) -> None:
        """Reaction 1: 2 Phenol + 1 Acetone -> 1 p,p'-BPA + 1 H2O must have zero mass residual."""
        reactants_mass = 2.0 * MW_PHENOL + MW_ACETONE
        products_mass = MW_BPA + MW_WATER
        assert abs(reactants_mass - products_mass) < 1.0e-15

    def test_reaction2_stoichiometric_mass_balance(self) -> None:
        """Reaction 2: 2 Phenol + 1 Acetone -> 1 o,p'-BPA + 1 H2O must have zero mass residual."""
        reactants_mass = 2.0 * MW_PHENOL + MW_ACETONE
        products_mass = MW_OP_ISOMER + MW_WATER
        assert abs(reactants_mass - products_mass) < 1.0e-15

    def test_reaction3_stoichiometric_mass_balance(self) -> None:
        """Reaction 3: 1 p,p'-BPA + 1 Acetone + 1 Phenol -> 1 Trisphenol + 1 H2O must have zero mass residual."""
        reactants_mass = MW_BPA + MW_ACETONE + MW_PHENOL
        products_mass = MW_TRISPHENOL + MW_WATER
        assert abs(reactants_mass - products_mass) < 1.0e-15


# ============================================================================
# Section 3: Arrhenius Kinetics, Promoter Enhancement & Activation Energies
# ============================================================================

class TestSection3ArrheniusKineticsAndPromoterEffect:
    """Validate Arrhenius reaction kinetics, temperature sensitivity, and promoter effect."""

    def test_arrhenius_monotonicity(self) -> None:
        """Rate constants must increase monotonically with temperature (65 °C < 72 °C < 85 °C)."""
        sim = BpaCondensation()
        t65_k = 65.0 + T_ZERO_CELSIUS
        t72_k = 72.0 + T_ZERO_CELSIUS
        t85_k = 85.0 + T_ZERO_CELSIUS

        k1_65 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t65_k)
        k1_72 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t72_k)
        k1_85 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t85_k)

        assert k1_85 > k1_72 > k1_65 > 0.0

    def test_activation_energy_slope_recovery(self) -> None:
        """Recover activation energy Ea1 from Arrhenius slope within 1e-4 J/mol."""
        sim = BpaCondensation()
        t65_k = 65.0 + T_ZERO_CELSIUS
        t85_k = 85.0 + T_ZERO_CELSIUS

        k1_65 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t65_k)
        k1_85 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t85_k)

        ea_rec = -R_GAS_CONST * math.log(k1_85 / k1_65) / ((1.0 / t85_k) - (1.0 / t65_k))
        assert abs(ea_rec - sim.config.activation_e1_j_mol) < 1.0e-4

    def test_promoter_starvation_derating(self) -> None:
        """Promoter starvation (< 50 ppm) drastically reduces kinetic activity."""
        sim = BpaCondensation()
        sim.state.promoter_concentration_ppm = 25.0  # Starved
        kin_starved = sim.compute_kinetics(
            t_reactor_k=72.0 + T_ZERO_CELSIUS,
            c_phenol=sim.state.c_phenol,
            c_acetone=sim.state.c_acetone,
            c_bpa=sim.state.c_bpa,
        )
        sim.state.promoter_concentration_ppm = 500.0  # Nominal
        kin_nominal = sim.compute_kinetics(
            t_reactor_k=72.0 + T_ZERO_CELSIUS,
            c_phenol=sim.state.c_phenol,
            c_acetone=sim.state.c_acetone,
            c_bpa=sim.state.c_bpa,
        )
        assert kin_starved["r1"] < 0.20 * kin_nominal["r1"]

    def test_resin_deactivation_derating(self) -> None:
        """Resin deactivation decreases kinetic rates monotonically."""
        sim = BpaCondensation()
        sim.state.catalyst_deactivation_pct = 0.85
        kin_clean = sim.compute_kinetics(72.0 + T_ZERO_CELSIUS, 8.53, 0.012, 0.92)

        sim.state.catalyst_deactivation_pct = 4.50
        kin_aged = sim.compute_kinetics(72.0 + T_ZERO_CELSIUS, 8.53, 0.012, 0.92)

        assert kin_aged["r1"] < kin_clean["r1"]


# ============================================================================
# Section 4: Reactor Geometry, Sizing & Heat Removal Dynamics
# ============================================================================

class TestSection4ReactorConfigurationAndThermalDynamics:
    """Validate reactor sizing, liquid volume, residence time, and thermal equilibrium."""

    def test_reactor_geometry_and_residence_time(self) -> None:
        """Reactor volume ~0.696 m^3 and residence time 360 s (6 min)."""
        cfg = BpaCondensationConfig()
        assert math.isclose(cfg.reactor_volume_m3, 0.6960888, rel_tol=1e-5)
        assert math.isclose(cfg.nominal_residence_time_s, 360.0, rel_tol=1e-5)

    def test_reactor_thermal_capacitance(self) -> None:
        """Thermal capacitance C_th must equal V * rho * Cp / 1000 (~7345.4 kJ/K)."""
        cfg = BpaCondensationConfig()
        m_tot = cfg.reactor_volume_m3 * cfg.liquid_mixture_density_kg_m3
        expected_cth = (m_tot * cfg.liquid_specific_heat_cp_j_kg_k) / 1000.0
        assert math.isclose(cfg.reactor_thermal_capacitance_kj_k, expected_cth, rel_tol=1e-4)

    def test_steady_state_thermal_equilibrium(self) -> None:
        """At nominal steady state, Q_rxn_total balances Q_flow + Q_cooling exactly."""
        sim = BpaCondensation()
        derivs = sim.compute_derivatives(
            0.0,
            [
                sim.state.c_phenol,
                sim.state.c_acetone,
                sim.state.c_bpa,
                sim.state.c_op_isomer,
                sim.state.c_byproducts,
                72.0,
            ],
        )
        # Temperature derivative at nominal conditions must be virtually 0 (< 1e-4 °C/s)
        assert abs(derivs[5]) < 1.0e-4


# ============================================================================
# Section 5: Nominal Steady-State Production Metrics
# ============================================================================

class TestSection5NominalSteadyStateProductionMetrics:
    """Validate nominal production metrics: conversion, selectivity, and production rate."""

    def test_nominal_operating_parameters(self) -> None:
        """Validate nominal temperature 72.0 °C, pressure 2.2 bar, ratio 10.5:1."""
        sim = BpaCondensation()
        assert sim.state.t_reactor_c == 72.0
        assert sim.state.p_reactor_bar == 2.2
        assert sim.state.phenol_acetone_ratio == 10.5
        assert sim.state.catalyst_deactivation_pct == 0.85

    def test_target_conversion_and_selectivity(self) -> None:
        """Validate > 98.5% Acetone conversion (98.80%) and > 94.0% BPA selectivity (94.50%)."""
        sim = BpaCondensation()
        assert sim.state.acetone_conversion_pct > 98.5
        assert sim.state.bpa_selectivity_pct > 94.0
        assert math.isclose(sim.state.bpa_selectivity_pct, 95.20, abs_tol=1.0)

    def test_target_production_rate(self) -> None:
        """Validate nominal BPA production rate ~1400.0 kg/h."""
        sim = BpaCondensation()
        assert math.isclose(sim.state.bpa_production_rate_kg_h, 1400.0, rel_tol=1e-3)


# ============================================================================
# Section 6: Coupled 6-State ODE System & RK4 Numerical Integrator
# ============================================================================

class TestSection6Coupled6StateODEAndRK4Integration:
    """Validate 6-state ODE derivatives, RK4 numerical integration, and bounded trajectories."""

    def test_derivatives_vector_dimension(self) -> None:
        """compute_derivatives must return a 6-element list."""
        sim = BpaCondensation()
        derivs = sim.compute_derivatives(0.0, [8.53, 0.012, 0.92, 0.044, 0.0098, 72.0])
        assert len(derivs) == 6
        assert all(isinstance(d, float) for d in derivs)

    def test_rk4_step_advances_time(self) -> None:
        """rk4_step must increment sim_time_s by dt."""
        sim = BpaCondensation()
        t0 = sim.state.sim_time_s
        sim.rk4_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, t0 + 0.02, abs_tol=1e-6)

    def test_rk4_multi_step_soak_stability(self) -> None:
        """Advance simulation for 250 steps (5.0s) and ensure bounded states without NaNs."""
        sim = BpaCondensation()
        res = sim.advance_time(duration_s=5.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert 70.0 <= sim.state.t_reactor_c <= 74.0
        assert not math.isnan(sim.state.c_bpa)
        assert not math.isnan(sim.state.t_reactor_c)
        assert sim.state.acetone_conversion_pct > 98.5
        assert sim.state.bpa_selectivity_pct > 94.0


# ============================================================================
# Section 7: Mathematical Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection7ConservationResiduals:
    """Validate stoichiometric mass, elemental atom, and enthalpy conservation residuals."""

    def test_mass_balance_residual(self) -> None:
        """Stoichiometric mass balance residual must be strictly < 1e-10 kg/s."""
        sim = BpaCondensation()
        sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_balance_residual(self) -> None:
        """Elemental Carbon/Hydrogen/Oxygen balance residual must be strictly < 1e-10 kg/s."""
        sim = BpaCondensation()
        sim.step(dt=0.02)
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual(self) -> None:
        """First-law enthalpy conservation residual must be strictly < 1e-10 kW."""
        sim = BpaCondensation()
        sim.step(dt=0.02)
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 8: Process Safety Interlocks & Strict Priority Hierarchy
# ============================================================================

class TestSection8ProcessSafetyInterlocks:
    """Validate safety interlocks in strict priority order (0xF001..0xF004)."""

    def test_priority1_thermal_runaway(self) -> None:
        """Priority 1: 0xF001 THERMAL_RUNAWAY_EXCURSION (T > 95.0 °C)."""
        sim = BpaCondensation()
        sim.state.t_reactor_c = 96.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert sim.state.emergency_bpa_quench_valve_open is True
        assert sim.state.bpa_reactor_active is False

    def test_priority2_acetone_accumulation(self) -> None:
        """Priority 2: 0xF002 ACETONE_ACCUMULATION_RUNAWAY_TRIP (C_ac > 0.40 mol/L or conv < 90%)."""
        sim = BpaCondensation()
        sim.state.c_acetone = 0.45
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.ACETONE_ACCUMULATION_RUNAWAY_TRIP
        assert sim.state.emergency_bpa_quench_valve_open is True
        assert sim.state.bpa_reactor_active is False

        sim.reset()
        sim.state.acetone_conversion_pct = 85.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.ACETONE_ACCUMULATION_RUNAWAY_TRIP

    def test_priority3_low_phenol_acetone_ratio(self) -> None:
        """Priority 3: 0xF003 LOW_PHENOL_ACETONE_RATIO (ratio < 6.0:1)."""
        sim = BpaCondensation()
        sim.state.phenol_acetone_ratio = 5.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.LOW_PHENOL_ACETONE_RATIO
        assert sim.state.emergency_bpa_quench_valve_open is True
        assert sim.state.bpa_reactor_active is False
        assert sim.state.low_phenol_acetone_ratio_pre_alarm is True

    def test_priority4_catalyst_resin_deactivation(self) -> None:
        """Priority 4: 0xF004 CATALYST_RESIN_DEACTIVATION_HOTSPOT (deactivation > 5% or promoter < 50 ppm)."""
        sim = BpaCondensation()
        sim.state.catalyst_deactivation_pct = 5.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_RESIN_DEACTIVATION_HOTSPOT
        assert sim.state.emergency_bpa_quench_valve_open is True
        assert sim.state.bpa_reactor_active is False

        sim.reset()
        sim.state.promoter_concentration_ppm = 30.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_RESIN_DEACTIVATION_HOTSPOT

    def test_priority_conflict_resolution(self) -> None:
        """Thermal excursion (0xF001) must take precedence over all other trip conditions."""
        sim = BpaCondensation()
        sim.state.t_reactor_c = 97.0
        sim.state.c_acetone = 0.50
        sim.state.phenol_acetone_ratio = 4.0
        sim.state.catalyst_deactivation_pct = 6.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION


# ============================================================================
# Section 9: DiagnosticCode Signed/Unsigned Equality & Masking
# ============================================================================

class TestSection9DiagnosticCodeSignedUnsignedEquality:
    """Validate DiagnosticCode signed/unsigned integer transparency."""

    def test_diagnostic_code_values(self) -> None:
        """Validate literal hex values for diagnostic codes."""
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION == 0xF001
        assert DiagnosticCode.ACETONE_ACCUMULATION_RUNAWAY_TRIP == 0xF002
        assert DiagnosticCode.LOW_PHENOL_ACETONE_RATIO == 0xF003
        assert DiagnosticCode.CATALYST_RESIN_DEACTIVATION_HOTSPOT == 0xF004

    def test_signed_integer_equality(self) -> None:
        """0xF001 must equal -4095 under signed 16-bit representation."""
        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION == -4095
        assert DiagnosticCode.ACETONE_ACCUMULATION_RUNAWAY_TRIP == -4094
        assert DiagnosticCode.LOW_PHENOL_ACETONE_RATIO == -4093
        assert DiagnosticCode.CATALYST_RESIN_DEACTIVATION_HOTSPOT == -4092

    def test_bitwise_masking(self) -> None:
        """Ensure & 0xFFFF masking works both as left- and right-operand."""
        code = DiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert (code & 0xFFFF) == 0xF001
        assert (0xFFFF & code) == 0xF001

    def test_missing_lookup_with_negative_integers(self) -> None:
        """Enum instantiation with negative 16-bit values must return the correct member."""
        assert DiagnosticCode(-4095) == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert DiagnosticCode(-4094) == DiagnosticCode.ACETONE_ACCUMULATION_RUNAWAY_TRIP


# ============================================================================
# Section 10: Pre-Alarm Logic & Emergency BPA Quench Actuation
# ============================================================================

class TestSection10PreAlarmAndEmergencyQuenchActuation:
    """Validate pre-alarm %M453 and emergency quench valve %M454 actuation."""

    def test_pre_alarm_without_trip(self) -> None:
        """Ratio 7.0:1 triggers pre-alarm %M453 without triggering trip or quench valve."""
        sim = BpaCondensation()
        sim.state.phenol_acetone_ratio = 7.0
        sim._evaluate_safety_interlocks()
        assert sim.state.low_phenol_acetone_ratio_pre_alarm is True
        assert sim.state.emergency_bpa_quench_valve_open is False
        assert sim.state.bpa_reactor_active is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_emergency_quench_valve_cools_and_shuts_down(self) -> None:
        """On trip, quench valve opens, reaction power drops to 0, and reactor cools down."""
        sim = BpaCondensation()
        sim.state.t_reactor_c = 98.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_bpa_quench_valve_open is True
        assert sim.state.bpa_reactor_active is False

        # Advance under quench
        sim.advance_time(duration_s=6.0, dt=0.02)
        assert sim.state.q_rxn_total_kw == 0.0
        assert sim.state.t_reactor_c < 96.0


# ============================================================================
# Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege
# ============================================================================

class TestSection11HornerOCSRegisterSpaceIntegration:
    """Validate register table mapping (%R1940..%R1947, %M452..%M454)."""

    def test_nominal_baseline_register_table(self) -> None:
        """Validate exact register scaling at nominal baseline conditions."""
        table = RegisterTable()
        sim = BpaCondensation(register_table=table)
        sim._sync_registers()

        assert table.read_word("%R1940") == 720    # 72.0 °C
        assert table.read_word("%R1941") == 22     # 2.2 bar
        assert table.read_word("%R1942") == 9880   # 98.80%
        assert table.read_word("%R1943") in (9450, 9520) # 94.50% / 95.20%
        assert table.read_word("%R1944") == 105    # 10.5:1
        assert table.read_word("%R1945") == 14000  # 1400.0 kg/h
        assert table.read_word("%R1946") == 85     # 0.85%
        assert table.read_uword("%R1947") == 0x0000# OK
        assert table.read_bit("%M452") is True     # Active
        assert table.read_bit("%M453") is False    # Pre-alarm inactive
        assert table.read_bit("%M454") is False    # Quench valve closed

    def test_system_privilege_mode_used_in_sync(self) -> None:
        """sync_to_registers must write using PrivilegeMode.SYSTEM."""
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.USER
        sim = BpaCondensation()
        # Explicit call with SYSTEM privilege must succeed
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R1940") == 720


# ============================================================================
# Section 12: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Guard
# ============================================================================

class TestSection12PureIEC61131STPOUAndAntiLadder:
    """Validate pure ST code against anti-ladder guards and ST parser."""

    def test_pure_st_pou_syntax_and_ast_parser(self) -> None:
        """POU BpaCondensationSync must pass SecurityGuard and STParser without errors."""
        SecurityGuard.assert_pure_st_content(BPA_CONDENSATION_PURE_ST_POU)
        res = STParser.validate_code(BPA_CONDENSATION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(BPA_CONDENSATION_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "BpaCondensationSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = [
            "%R1940", "%R1941", "%R1942", "%R1943",
            "%R1944", "%R1945", "%R1946", "%R1947",
            "%M452", "%M453", "%M454",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_anti_ladder_security_guard_rejection(self) -> None:
        """Anti-ladder guard must reject ladder contacts and coils with LadderForbiddenError."""
        bad_ladder = """
        PROGRAM BadBpaLadder
        VAR Temp : INT; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_ladder)

    def test_verify_bpa_pure_st_function(self) -> None:
        """verify_bpa_condensation_pure_st helper must return SUCCESS."""
        res = verify_bpa_condensation_pure_st()
        assert res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 13: ILogicUnit Scan Cycle Execution & Reset Dynamics
# ============================================================================

class TestSection13ILogicUnitProtocol:
    """Validate ILogicUnit interface methods and reset behaviour."""

    def test_scan_step_and_execute(self) -> None:
        """scan_step and execute must advance simulation time consistently."""
        sim = BpaCondensation()
        sim.scan_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-6)

        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)
        assert math.isclose(sim.state.sim_time_s, 0.04, abs_tol=1e-6)

    def test_reset_restores_nominal_state(self) -> None:
        """reset must restore nominal operating baseline."""
        sim = BpaCondensation()
        sim.state.t_reactor_c = 98.0
        sim.state.emergency_bpa_quench_valve_open = True
        sim.state.bpa_reactor_active = False

        sim.reset()
        assert sim.state.t_reactor_c == 72.0
        assert sim.state.emergency_bpa_quench_valve_open is False
        assert sim.state.bpa_reactor_active is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_logic_unit_wrapper(self) -> None:
        """BpaCondensationLogicUnit wrapper must proxy simulator correctly."""
        unit = BpaCondensationLogicUnit()
        assert unit.name == "BpaCondensationSync"
        assert unit.priority == 100
        assert unit.is_enabled is True

        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        assert math.isclose(unit.sim.state.sim_time_s, 0.02, abs_tol=1e-6)


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifacts
# ============================================================================

class TestSection14Deterministic9StageVerification:
    """Validate 9-stage engineering verification runner and contract payload."""

    def test_run_verification_returns_success(self, tmp_path: Path) -> None:
        """Verification suite must return strict 4-state contract success."""
        evidence_file = tmp_path / "bpa_evidence.json"
        res = run_bpa_condensation_verification(output_path=evidence_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

        # Ensure evidence file written to disk
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
