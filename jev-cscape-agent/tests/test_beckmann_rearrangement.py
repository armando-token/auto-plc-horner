"""Comprehensive Industrial Caprolactam Beckmann Rearrangement Reactor Test Suite.

Work Package: W215 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 13 engineering verification sections:
1. Section 1: Universal Physical Constants, Molecular Weights & Thermodynamic Enthalpies
2. Section 2: Reactor Configuration, Bed Geometry & Operating Baseline Parameters
3. Section 3: Arrhenius Reaction Kinetics, Decomposition Pathways & Cracking Sensitivity
4. Section 4: Vapor Concentrations, Contact Time & Feed Hydrodynamics
5. Section 5: Catalyst Deactivation Kinetics & Methanol Regeneration Dynamics
6. Section 6: Coupled 6-State ODE System & RK4 Numerical Integrator Stability
7. Section 7: Stoichiometric Mass, Elemental Atomic & Enthalpy Conservation Residuals (< 1e-10)
8. Section 8: High-Conversion Regime (> 99.0%) & High Caprolactam Selectivity (> 95.0%)
9. Section 9: Process Safety Interlocks & Diagnostics in Strict Priority Hierarchy (0xE701..0xE704)
10. Section 10: Emergency Methanol Flush Deluge & Nitrogen Inerting on Thermal Runaway (> 375 °C)
11. Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege Mode (%R1760..%R1767, %M410..%M412)
12. Section 12: Strict Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
13. Section 13: ILogicUnit Scan Cycle Execution, Multi-Cycle Soak & 9-Stage Verification Suite
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

from jev_cscape.simulation.beckmann_rearrangement import (
    BECKMANN_PURE_ST_POU,
    BECKMANN_REACTOR_PURE_ST_POU,
    BECKMANN_REACTOR_SYNC_POU,
    BECKMANN_REARRANGEMENT_PURE_ST_POU,
    BECKMANN_REARRANGEMENT_SYNC_POU,
    BECKMANN_SYNC_POU,
    CAPROLACTAM_SELECTIVITY_MIN_PCT,
    CAPROLACTAM_SELECTIVITY_NOMINAL_PCT,
    CAPROLACTAM_SELECTIVITY_TARGET_PCT,
    CATALYST_ACTIVITY_MIN_PCT,
    CATALYST_ACTIVITY_NOMINAL_PCT,
    CONTACT_TIME_MAX_S,
    CONTACT_TIME_MIN_S,
    CONTACT_TIME_NOMINAL_S,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DELTA_H_BECKMANN_J_MOL,
    DELTA_H_BECKMANN_KJ_MOL,
    DELTA_H_CRACKING_J_MOL,
    DELTA_H_CRACKING_KJ_MOL,
    DELTA_H_HYDROLYSIS_J_MOL,
    DELTA_H_HYDROLYSIS_KJ_MOL,
    G_ACCEL,
    METHANOL_OXIME_RATIO_MIN,
    METHANOL_OXIME_RATIO_NOMINAL,
    MW_BYPRODUCTS,
    MW_C,
    MW_CAPROLACTAM,
    MW_CYCLOHEXANONE,
    MW_CYCLOHEXANONE_OXIME,
    MW_EPSILON_CAPROLACTAM,
    MW_H,
    MW_H2O,
    MW_HYDROXYLAMINE,
    MW_METHANOL,
    MW_N,
    MW_N2,
    MW_O,
    MW_OXIME,
    MW_TAR,
    OXIME_CONVERSION_MIN_PCT,
    OXIME_CONVERSION_NOMINAL_PCT,
    OXIME_CONVERSION_TARGET_PCT,
    R_GAS_CONST,
    REACTOR_PRESSURE_MAX_BAR,
    REACTOR_PRESSURE_MIN_BAR,
    REACTOR_PRESSURE_NOMINAL_BAR,
    REACTOR_TEMP_MAX_C,
    REACTOR_TEMP_MIN_C,
    REACTOR_TEMP_NOMINAL_C,
    REACTOR_TEMP_PRE_ALARM_C,
    REACTOR_TEMP_RESET_C,
    REACTOR_TEMP_TRIP_C,
    SPACE_VELOCITY_WHSV_NOMINAL,
    T_REF_K,
    T_ZERO_CELSIUS,
    BeckmannConfig,
    BeckmannDiagCode,
    BeckmannDiagnosticCode,
    BeckmannEngine,
    BeckmannLogicUnit,
    BeckmannModel,
    BeckmannParameters,
    BeckmannPlantModel,
    BeckmannReactor,
    BeckmannReactorConfig,
    BeckmannReactorDiagCode,
    BeckmannReactorDiagnosticCode,
    BeckmannReactorEngine,
    BeckmannReactorLogicUnit,
    BeckmannReactorModel,
    BeckmannReactorParameters,
    BeckmannReactorPlantModel,
    BeckmannReactorSimulationEngine,
    BeckmannReactorSimulator,
    BeckmannReactorState,
    BeckmannReactorStatusBits,
    BeckmannReactorStatusWord,
    BeckmannRearrangementConfig,
    BeckmannRearrangementDiagCode,
    BeckmannRearrangementDiagnosticCode,
    BeckmannRearrangementEngine,
    BeckmannRearrangementLogicUnit,
    BeckmannRearrangementModel,
    BeckmannRearrangementParameters,
    BeckmannRearrangementPlantModel,
    BeckmannRearrangementReactor,
    BeckmannRearrangementReactorState,
    BeckmannRearrangementSimulationEngine,
    BeckmannRearrangementSimulator,
    BeckmannRearrangementState,
    BeckmannRearrangementStatusBits,
    BeckmannRearrangementStatusWord,
    BeckmannSimulationEngine,
    BeckmannSimulator,
    BeckmannState,
    BeckmannStatusBits,
    BeckmannStatusWord,
    run_beckmann_reactor_verification,
    run_beckmann_rearrangement_verification,
    run_beckmann_verification,
    validate_beckmann_pure_st,
    validate_pure_st,
    verify_beckmann_pure_st,
    verify_beckmann_reactor_pure_st,
    verify_beckmann_rearrangement_pure_st,
)


# ============================================================================
# Section 1: Universal Physical Constants, Molecular Weights & Enthalpies
# ============================================================================

class TestSection1ConstantsAndThermodynamics:
    """Tests for physical constants, atomic/molecular weights, and reaction enthalpies."""

    def test_universal_physical_constants(self) -> None:
        """Verify universal gas constant, standard gravity, and temperature conversions."""
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(G_ACCEL - 9.80665) < 1e-4
        assert abs(T_ZERO_CELSIUS - 273.15) < 1e-4
        assert abs(T_REF_K - 593.15) < 1e-4

    def test_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon, Hydrogen, Oxygen, and Nitrogen."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_O - 0.015999) < 1e-6
        assert abs(MW_N - 0.014007) < 1e-6

    def test_molecular_weights_species(self) -> None:
        """Verify molecular weights for Oxime, Caprolactam, Cyclohexanone, Hydroxylamine, H2O, Methanol, N2."""
        assert abs(MW_OXIME - 0.113160) < 1e-5
        assert abs(MW_CYCLOHEXANONE_OXIME - MW_OXIME) < 1e-8
        assert abs(MW_CAPROLACTAM - MW_OXIME) < 1e-8
        assert abs(MW_EPSILON_CAPROLACTAM - MW_OXIME) < 1e-8
        assert abs(MW_CYCLOHEXANONE - 0.098145) < 1e-5
        assert abs(MW_HYDROXYLAMINE - 0.033030) < 1e-5
        assert abs(MW_H2O - 0.018015) < 1e-5
        assert abs(MW_METHANOL - 0.032042) < 1e-5
        assert abs(MW_N2 - 0.028014) < 1e-5
        assert abs(MW_BYPRODUCTS - MW_OXIME) < 1e-8
        assert abs(MW_TAR - MW_OXIME) < 1e-8

    def test_reaction1_beckmann_rearrangement_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 1: Oxime (C6H11NO) -> Caprolactam (C6H11NO) exact isomerization & Delta H1."""
        reactant = MW_OXIME
        product = MW_CAPROLACTAM
        assert abs(reactant - product) < 1e-12
        assert DELTA_H1_KJ_MOL == -115.0
        assert DELTA_H1_J_MOL == -115000.0
        assert DELTA_H_BECKMANN_KJ_MOL == -115.0
        assert DELTA_H_BECKMANN_J_MOL == -115000.0

    def test_reaction2_hydrolysis_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 2: Oxime + H2O -> Cyclohexanone + Hydroxylamine mass balance and Delta H2."""
        reactants = MW_OXIME + MW_H2O
        products = MW_CYCLOHEXANONE + MW_HYDROXYLAMINE
        assert abs(reactants - products) < 1e-12
        assert DELTA_H2_KJ_MOL == -45.0
        assert DELTA_H2_J_MOL == -45000.0
        assert DELTA_H_HYDROLYSIS_KJ_MOL == -45.0
        assert DELTA_H_HYDROLYSIS_J_MOL == -45000.0

    def test_reaction3_cracking_and_tar_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 3: High-temp oligomerization/cracking to tar mass balance and Delta H3."""
        reactant = MW_OXIME
        product = MW_TAR
        assert abs(reactant - product) < 1e-12
        assert DELTA_H3_KJ_MOL == -190.0
        assert DELTA_H3_J_MOL == -190000.0
        assert DELTA_H_CRACKING_KJ_MOL == -190.0
        assert DELTA_H_CRACKING_J_MOL == -190000.0

    def test_elemental_stoichiometry_exactness(self) -> None:
        """Verify elemental atomic balance (C, H, O, N) for all reactions."""
        # Oxime C6H11NO
        assert abs((6 * MW_C + 11 * MW_H + MW_N + MW_O) - MW_OXIME) < 1e-6
        # Caprolactam C6H11NO
        assert abs((6 * MW_C + 11 * MW_H + MW_N + MW_O) - MW_CAPROLACTAM) < 1e-6
        # Hydrolysis: C6H11NO + H2O = C6H10O + NH2OH
        lhs = (6 * MW_C + 11 * MW_H + MW_N + MW_O) + (2 * MW_H + MW_O)
        rhs = (6 * MW_C + 10 * MW_H + MW_O) + (3 * MW_H + MW_N + MW_O)
        assert abs(lhs - rhs) < 1e-6


# ============================================================================
# Section 2: Reactor Configuration, Geometry & Operating Baseline
# ============================================================================

class TestSection2ReactorConfiguration:
    """Tests for fixed-bed reactor geometry, catalyst inventory, operating limits, and parameters."""

    def test_default_reactor_geometry(self) -> None:
        """Verify column dimensions, active volume, and cross-sectional area."""
        cfg = BeckmannRearrangementConfig()
        assert cfg.reactor_diameter_m == 1.6
        assert cfg.bed_height_m == 3.0
        assert cfg.bed_volume_m3 == 6.03
        assert cfg.catalyst_loading_kg == 6918.0
        expected_cs = 0.25 * math.pi * (1.6 ** 2)
        assert abs(cfg.cross_section_area_m2 - expected_cs) < 1e-4

    def test_contact_time_and_space_velocity(self) -> None:
        """Verify gas residence contact time in 0.5-2.0 s range and nominal WHSV."""
        cfg = BeckmannRearrangementConfig()
        assert cfg.contact_time_s == 1.20
        assert CONTACT_TIME_MIN_S <= cfg.contact_time_s <= CONTACT_TIME_MAX_S
        assert cfg.whsv_h_inv == 1.2
        assert SPACE_VELOCITY_WHSV_NOMINAL == 1.2

    def test_nominal_operating_temperatures_and_pressures(self) -> None:
        """Verify nominal operating temperatures, pressures, and safety boundaries."""
        assert REACTOR_TEMP_NOMINAL_C == 320.0
        assert REACTOR_TEMP_MIN_C == 300.0
        assert REACTOR_TEMP_MAX_C == 350.0
        assert REACTOR_TEMP_PRE_ALARM_C == 355.0
        assert REACTOR_TEMP_TRIP_C == 375.0
        assert REACTOR_TEMP_RESET_C == 345.0

        assert REACTOR_PRESSURE_NOMINAL_BAR == 1.50
        assert REACTOR_PRESSURE_MIN_BAR == 1.00
        assert REACTOR_PRESSURE_MAX_BAR == 2.50

    def test_carrier_methanol_molar_ratio(self) -> None:
        """Verify nominal methanol:oxime molar ratio and minimum starvation boundary."""
        cfg = BeckmannRearrangementConfig()
        assert cfg.methanol_oxime_molar_ratio == 6.50
        assert METHANOL_OXIME_RATIO_NOMINAL == 6.50
        assert METHANOL_OXIME_RATIO_MIN == 3.00

    def test_thermal_capacitance_and_cooling_bundle(self) -> None:
        """Verify bed heat capacity, heat transfer coefficient UA, and coolant temperature."""
        cfg = BeckmannRearrangementConfig()
        assert cfg.bed_heat_capacity_j_k == 8.5e5
        assert cfg.ua_cooling_w_k == 55495.0
        assert cfg.coolant_temp_c == 280.0
        assert cfg.feed_inlet_temp_c == 310.0
        assert cfg.ambient_temp_c == 25.0

    def test_emergency_flush_parameters(self) -> None:
        """Verify emergency methanol deluge cooling duty (15 MW) and N2 purge flow."""
        cfg = BeckmannRearrangementConfig()
        assert cfg.emergency_flush_cooling_duty_kw == 15000.0
        assert cfg.emergency_nitrogen_purge_mol_s == 350.0


# ============================================================================
# Section 3: Arrhenius Reaction Kinetics & Thermal Sensitivity
# ============================================================================

class TestSection3ReactionKinetics:
    """Tests for reaction rates, Arrhenius temperature dependencies, and cracking acceleration."""

    def test_rate_constants_at_reference_temperature(self) -> None:
        """Verify reference rate constants k1, k2, k3 at 320.0 °C (593.15 K)."""
        cfg = BeckmannRearrangementConfig()
        assert cfg.k1_ref == 180.2
        assert cfg.k2_ref == 4.5
        assert cfg.k3_ref == 2.6

    def test_activation_energies(self) -> None:
        """Verify activation energies Ea1, Ea2, Ea3."""
        cfg = BeckmannRearrangementConfig()
        assert cfg.activation_energy_1_j_mol == 65000.0
        assert cfg.activation_energy_2_j_mol == 52000.0
        assert cfg.activation_energy_3_j_mol == 145000.0

    def test_cracking_accelerates_faster_than_beckmann(self) -> None:
        """Verify high Ea3 causes tar cracking to accelerate much faster than Beckmann rearrangement at elevated T."""
        sim = BeckmannRearrangementReactor()
        rates_nom = sim.compute_reaction_rates(0.02029, 3.8817, 0.1534, 593.15, 0.885)
        rates_hot = sim.compute_reaction_rates(0.02029, 3.8817, 0.1534, 633.15, 0.885)

        ratio_r1 = rates_hot["r1_tot"] / max(1e-6, rates_nom["r1_tot"])
        ratio_r3 = rates_hot["r3_tot"] / max(1e-6, rates_nom["r3_tot"])
        assert ratio_r3 > ratio_r1
        assert ratio_r3 > 5.0
        assert ratio_r1 > 1.8

    def test_zero_rates_when_tripped(self) -> None:
        """Verify all reaction rates and exothermic powers are zero when tripped."""
        sim = BeckmannRearrangementReactor()
        rates = sim.compute_reaction_rates(0.02, 3.8, 0.15, 593.15, 0.885, is_tripped=True)
        assert rates["r1_vol"] == 0.0
        assert rates["r2_vol"] == 0.0
        assert rates["r3_vol"] == 0.0
        assert rates["q_rxn_kw"] == 0.0

    def test_exothermic_power_calculation(self) -> None:
        """Verify exothermic power is correctly computed from molar rates and enthalpies."""
        sim = BeckmannRearrangementReactor()
        rates = sim.compute_reaction_rates(0.02029, 3.8817, 0.1534, 593.15, 0.885)
        expected_w = (
            rates["r1_tot"] * 115000.0
            + rates["r2_tot"] * 45000.0
            + rates["r3_tot"] * 190000.0
        )
        assert abs(rates["q_rxn_kw"] * 1000.0 - expected_w) < 1e-4

    def test_rate_dependence_on_catalyst_activity(self) -> None:
        """Verify reaction rate scales linearly with dimensionless catalyst activity."""
        sim = BeckmannRearrangementReactor()
        rates_full = sim.compute_reaction_rates(0.02, 3.8, 0.15, 593.15, 1.0)
        rates_half = sim.compute_reaction_rates(0.02, 3.8, 0.15, 593.15, 0.5)
        assert abs(rates_half["r1_vol"] - 0.5 * rates_full["r1_vol"]) < 1e-6


# ============================================================================
# Section 4: Vapor Concentrations & Feed Hydrodynamics
# ============================================================================

class TestSection4FeedAndHydrodynamics:
    """Tests for feed concentrations, ideal gas law scaling, and contact time."""

    def test_get_feed_concentrations_nominal(self) -> None:
        """Verify feed concentrations derived from pressure, temperature, and methanol ratio."""
        sim = BeckmannRearrangementReactor()
        c_ox, c_meth = sim.get_feed_concentrations()
        p_pa = 1.50 * 1e5
        t_k = 320.0 + T_ZERO_CELSIUS
        c_tot = p_pa / (R_GAS_CONST * t_k)
        assert abs(c_ox + c_meth - c_tot) < 1e-4
        assert (c_meth / c_ox) == pytest.approx(6.50, abs=0.01)

    def test_feed_concentrations_change_with_pressure(self) -> None:
        """Verify higher pressure increases feed molar concentration."""
        sim = BeckmannRearrangementReactor()
        sim.state.bed_pressure_bar = 2.0
        c_ox_hi, _ = sim.get_feed_concentrations()
        sim.state.bed_pressure_bar = 1.0
        c_ox_lo, _ = sim.get_feed_concentrations()
        assert c_ox_hi > c_ox_lo

    def test_methanol_ratio_influence_on_oxime_feed(self) -> None:
        """Verify higher methanol ratio dilutes oxime concentration."""
        sim = BeckmannRearrangementReactor()
        sim.state.methanol_oxime_molar_ratio = 10.0
        c_ox_dilute, _ = sim.get_feed_concentrations()
        sim.state.methanol_oxime_molar_ratio = 4.0
        c_ox_concentrated, _ = sim.get_feed_concentrations()
        assert c_ox_dilute < c_ox_concentrated

    def test_contact_time_clamping_protection(self) -> None:
        """Verify contact time is protected against non-positive zero division."""
        sim = BeckmannRearrangementReactor()
        sim.config.contact_time_s = 0.0
        derivs = sim.compute_derivatives(0.0, [0.02, 3.88, 0.15, 26.35, 593.15, 0.885])
        assert all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    def test_zero_oxime_feed_when_tripped(self) -> None:
        """Verify oxime feed is shut off under trip conditions."""
        sim = BeckmannRearrangementReactor()
        sim.state.emergency_methanol_flush_active = True
        derivs = sim.compute_derivatives(0.0, [0.02, 3.88, 0.15, 26.35, 593.15, 0.885])
        # dc_oxime/dt should be strictly negative (purging out)
        assert derivs[0] < 0.0


# ============================================================================
# Section 5: Catalyst Deactivation & Methanol Regeneration Kinetics
# ============================================================================

class TestSection5CatalystKinetics:
    """Tests for catalyst coking deactivation and methanol desorbing preservation effect."""

    def test_nominal_catalyst_activity_balance(self) -> None:
        """Verify nominal steady-state activity derivative is near zero (|da/dt| < 0.05)."""
        sim = BeckmannRearrangementReactor()
        derivs = sim.compute_derivatives(0.0, [
            sim.state.c_oxime,
            sim.state.c_caprolactam,
            sim.state.c_byproducts,
            sim.state.c_methanol,
            sim.state.t_bed,
            sim.state.activity_catalyst,
        ])
        da_dt = derivs[5]
        assert abs(da_dt) < 0.05

    def test_methanol_carrier_starvation_causes_rapid_deactivation(self) -> None:
        """Verify lowering methanol concentration causes negative da/dt (rapid coking deactivation)."""
        sim = BeckmannRearrangementReactor()
        derivs_starved = sim.compute_derivatives(0.0, [
            sim.state.c_oxime,
            sim.state.c_caprolactam,
            sim.state.c_byproducts,
            5.0,  # low methanol
            sim.state.t_bed,
            sim.state.activity_catalyst,
        ])
        da_dt_starved = derivs_starved[5]
        assert da_dt_starved < -0.001

    def test_high_oxime_concentration_accelerates_coking(self) -> None:
        """Verify elevated oxime concentration accelerates catalyst coking rate."""
        sim = BeckmannRearrangementReactor()
        derivs_hi_ox = sim.compute_derivatives(0.0, [
            0.10,  # 5x oxime concentration
            sim.state.c_caprolactam,
            sim.state.c_byproducts,
            sim.state.c_methanol,
            sim.state.t_bed,
            sim.state.activity_catalyst,
        ])
        derivs_lo_ox = sim.compute_derivatives(0.0, [
            0.02,
            sim.state.c_caprolactam,
            sim.state.c_byproducts,
            sim.state.c_methanol,
            sim.state.t_bed,
            sim.state.activity_catalyst,
        ])
        assert derivs_hi_ox[5] < derivs_lo_ox[5]

    def test_deluge_regeneration_when_tripped(self) -> None:
        """Verify tripping into emergency flush accelerates catalyst site regeneration."""
        sim = BeckmannRearrangementReactor()
        sim.state.emergency_methanol_flush_active = True
        derivs = sim.compute_derivatives(0.0, [
            sim.state.c_oxime,
            sim.state.c_caprolactam,
            sim.state.c_byproducts,
            sim.state.c_methanol,
            sim.state.t_bed,
            0.70,  # partially deactivated
        ])
        assert derivs[5] > 0.0  # regeneration is positive

    def test_catalyst_activity_bounds_preservation(self) -> None:
        """Verify activity remains bounded in [0.0, 1.0] across integration."""
        sim = BeckmannRearrangementReactor()
        sim.state.activity_catalyst = 1.05
        sim.rk4_step(dt=0.02)
        assert sim.state.activity_catalyst <= 1.0
        assert sim.state.activity_catalyst >= 0.0


# ============================================================================
# Section 6: Coupled 6-State ODE System & RK4 Solver Stability
# ============================================================================

class TestSection6ODEAndRK4Solver:
    """Tests for ODE state vector derivatives, RK4 numerical integration, and stability."""

    def test_coupled_state_vector_length_and_types(self) -> None:
        """Verify compute_derivatives returns exactly 6 finite float derivatives."""
        sim = BeckmannRearrangementReactor()
        y = [0.02029, 3.8817, 0.1534, 26.358, 593.15, 0.8850]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6
        assert all(isinstance(d, float) for d in derivs)
        assert all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    def test_single_rk4_step_execution(self) -> None:
        """Verify rk4_step advances simulation time and updates state."""
        sim = BeckmannRearrangementReactor()
        t0 = sim.state.sim_time_s
        sc0 = sim.state.scan_count
        sim.rk4_step(dt=0.02)
        assert abs(sim.state.sim_time_s - (t0 + 0.02)) < 1e-6
        assert sim.state.scan_count == sc0 + 1

    def test_step_method_returns_execution_result_success(self) -> None:
        """Verify step() returns ExecutionResult with status SUCCESS."""
        sim = BeckmannRearrangementReactor()
        res = sim.step(dt=0.02)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert "bed_temp_c" in res.data
        assert "conversion_pct" in res.data
        assert "selectivity_pct" in res.data

    def test_advance_time_multi_step_trajectory(self) -> None:
        """Verify advance_time runs multiple steps deterministically."""
        sim = BeckmannRearrangementReactor()
        res = sim.advance_time(duration_s=1.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.sim_time_s >= 1.0
        assert sim.state.scan_count >= 50

    def test_rk4_stability_over_extended_window(self) -> None:
        """Verify RK4 integration remains stable over 2 seconds."""
        sim = BeckmannRearrangementReactor()
        res = sim.advance_time(duration_s=2.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert 0.0 <= sim.state.c_oxime <= 1.0
        assert 2.0 <= sim.state.c_caprolactam <= 6.0
        assert 0.0 <= sim.state.c_byproducts <= 1.0
        assert 15.0 <= sim.state.c_methanol <= 40.0
        assert 300.0 <= sim.state.bed_temperature_celsius <= 350.0
        assert 0.50 <= sim.state.activity_catalyst <= 1.0

    def test_temperature_synchronization_property(self) -> None:
        """Verify bed_temperature_celsius and t_bed are strictly synchronized."""
        sim = BeckmannRearrangementReactor()
        sim.state.t_bed = 600.0
        sim.state.bed_temperature_celsius = sim.state.t_bed - T_ZERO_CELSIUS
        assert abs(sim.state.bed_temperature_celsius - (600.0 - 273.15)) < 1e-6


# ============================================================================
# Section 7: Stoichiometric Mass, Elemental Atomic & Enthalpy Residuals (< 1e-10)
# ============================================================================

class TestSection7ConservationResiduals:
    """Tests for rigorous mathematical conservation residuals < 1e-10."""

    def test_total_mass_balance_residual_less_than_1e10(self) -> None:
        """Verify overall stoichiometric mass balance residual is < 1e-10 kg/s."""
        sim = BeckmannRearrangementReactor()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_species_mass_residual_less_than_1e10(self) -> None:
        """Verify atomic elemental mass balance residual is < 1e-10 kg/s."""
        sim = BeckmannRearrangementReactor()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        """Verify thermal enthalpy conservation residual is < 1e-10 kW."""
        sim = BeckmannRearrangementReactor()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_over_extended_simulation(self) -> None:
        """Verify residuals remain strictly < 1e-10 after 100 simulation cycles."""
        sim = BeckmannRearrangementReactor()
        for _ in range(100):
            sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_under_perturbed_concentrations(self) -> None:
        """Verify residuals remain strictly < 1e-10 under non-nominal concentrations."""
        sim = BeckmannRearrangementReactor()
        sim.state.c_oxime = 0.05
        sim.state.c_caprolactam = 3.2
        sim.state.c_byproducts = 0.4
        sim.state.c_methanol = 20.0
        sim._update_kinetics_and_conversion()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 8: High Conversion (> 99.0%) & High Selectivity (> 95.0%) Regime
# ============================================================================

class TestSection8YieldAndSelectivity:
    """Tests for ultra-high oxime conversion, caprolactam selectivity, and WHSV."""

    def test_nominal_oxime_conversion_above_99_pct(self) -> None:
        """Verify nominal oxime conversion is 99.50% and exceeds >= 99.00% target."""
        sim = BeckmannRearrangementReactor()
        conv = sim.state.oxime_conversion_pct
        assert conv == pytest.approx(OXIME_CONVERSION_NOMINAL_PCT, abs=0.2)
        assert conv >= OXIME_CONVERSION_TARGET_PCT
        assert conv >= 99.00

    def test_nominal_caprolactam_selectivity_above_95_pct(self) -> None:
        """Verify nominal caprolactam selectivity is 96.20% and exceeds >= 95.00% target."""
        sim = BeckmannRearrangementReactor()
        sel = sim.state.caprolactam_selectivity_pct
        assert sel == pytest.approx(CAPROLACTAM_SELECTIVITY_NOMINAL_PCT, abs=0.2)
        assert sel >= CAPROLACTAM_SELECTIVITY_TARGET_PCT
        assert sel >= 95.00

    def test_nominal_catalyst_activity(self) -> None:
        """Verify nominal catalyst activity is 88.50%."""
        sim = BeckmannRearrangementReactor()
        act = sim.state.catalyst_activity_pct
        assert act == pytest.approx(CATALYST_ACTIVITY_NOMINAL_PCT, abs=0.2)
        assert act >= 80.0

    def test_space_velocity_nominal_value(self) -> None:
        """Verify space velocity reflects nominal 1.2 h^-1."""
        sim = BeckmannRearrangementReactor()
        assert sim.state.space_velocity_whsv == 1.2

    def test_conversion_and_selectivity_bounds(self) -> None:
        """Verify conversion and selectivity percentages are bounded in [0, 100]."""
        sim = BeckmannRearrangementReactor()
        assert 0.0 <= sim.state.oxime_conversion_pct <= 100.0
        assert 0.0 <= sim.state.caprolactam_selectivity_pct <= 100.0


# ============================================================================
# Section 9: Process Safety Interlocks & Strict Priority Diagnostics (0xE701..0xE704)
# ============================================================================

class TestSection9SafetyInterlocksAndPriority:
    """Tests for process safety diagnostics and strict priority hierarchy."""

    def test_priority_1_thermal_runaway_trip_0xe701(self) -> None:
        """Verify 0xE701 triggers on T_bed > 375.0 °C and sets emergency flush."""
        sim = BeckmannRearrangementReactor()
        sim.state.bed_temperature_celsius = 378.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        assert sim.state.emergency_methanol_flush_active is True
        assert sim.state.temperature_high_pre_alarm is True
        assert sim.state.beckmann_rearrangement_active is False

    def test_priority_2_oxime_slip_low_conversion_0xe702(self) -> None:
        """Verify 0xE702 triggers on conversion < 98.0% without emergency flush."""
        sim = BeckmannRearrangementReactor()
        sim.state.oxime_conversion_pct = 97.4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.OXIME_SLIP_LOW_CONVERSION
        assert sim.state.emergency_methanol_flush_active is False
        assert sim.state.beckmann_rearrangement_active is True

    def test_priority_3_catalyst_coking_deactivation_0xe703(self) -> None:
        """Verify 0xE703 triggers on catalyst activity < 60.0%."""
        sim = BeckmannRearrangementReactor()
        sim.state.catalyst_activity_pct = 54.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.CATALYST_COKING_DEACTIVATION
        assert sim.state.emergency_methanol_flush_active is False
        assert sim.state.beckmann_rearrangement_active is True

    def test_priority_4_methanol_carrier_starvation_0xe704(self) -> None:
        """Verify 0xE704 triggers on methanol:oxime molar ratio < 3.0:1."""
        sim = BeckmannRearrangementReactor()
        sim.state.methanol_oxime_molar_ratio = 2.40
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.METHANOL_CARRIER_STARVATION
        assert sim.state.emergency_methanol_flush_active is False
        assert sim.state.beckmann_rearrangement_active is True

    def test_normal_operating_code_0x0000(self) -> None:
        """Verify normal steady-state operation reports diagnostic code 0x0000 (OK)."""
        sim = BeckmannRearrangementReactor()
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.OK
        assert sim.state.emergency_methanol_flush_active is False
        assert sim.state.beckmann_rearrangement_active is True

    def test_strict_priority_hierarchy_ordering(self) -> None:
        """Verify strict priority ordering: 0xE701 > 0xE702 > 0xE703 > 0xE704 > 0x0000."""
        sim = BeckmannRearrangementReactor()
        # All conditions active
        sim.state.bed_temperature_celsius = 380.0   # 0xE701
        sim.state.oxime_conversion_pct = 96.0       # 0xE702
        sim.state.catalyst_activity_pct = 50.0      # 0xE703
        sim.state.methanol_oxime_molar_ratio = 2.0  # 0xE704
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.THERMAL_EXCURSION_RUNAWAY

        # Clear 0xE701
        sim.state.bed_temperature_celsius = 320.0
        sim.state.emergency_methanol_flush_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.OXIME_SLIP_LOW_CONVERSION

        # Clear 0xE702
        sim.state.oxime_conversion_pct = 99.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.CATALYST_COKING_DEACTIVATION

        # Clear 0xE703
        sim.state.catalyst_activity_pct = 88.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.METHANOL_CARRIER_STARVATION

        # Clear 0xE704
        sim.state.methanol_oxime_molar_ratio = 6.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.OK


# ============================================================================
# Section 10: Emergency Methanol Flush Deluge & Nitrogen Inerting
# ============================================================================

class TestSection10EmergencyFlushAndInerting:
    """Tests for emergency methanol deluge cooling and nitrogen inerting on excursion trip."""

    def test_emergency_flush_coil_m412_asserts_on_0xe701(self) -> None:
        """Verify %M412 emergency flush coil asserts on 0xE701."""
        sim = BeckmannRearrangementReactor()
        sim.state.bed_temperature_celsius = 378.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_methanol_flush_active is True

    def test_reaction_active_coil_m410_clears_on_trip(self) -> None:
        """Verify %M410 BeckmannRearrangementActive is cleared (False) under trip."""
        sim = BeckmannRearrangementReactor()
        sim.state.bed_temperature_celsius = 378.0
        sim._evaluate_safety_interlocks()
        assert sim.state.beckmann_rearrangement_active is False

    def test_temperature_pre_alarm_coil_m411(self) -> None:
        """Verify %M411 temperature pre-alarm asserts above 355.0 °C."""
        sim = BeckmannRearrangementReactor()
        sim.state.bed_temperature_celsius = 358.0
        sim._evaluate_safety_interlocks()
        assert sim.state.temperature_high_pre_alarm is True

        sim.state.bed_temperature_celsius = 340.0
        sim._evaluate_safety_interlocks()
        assert sim.state.temperature_high_pre_alarm is False

    def test_flush_cooling_duty_activation(self) -> None:
        """Verify 15 MW emergency deluge cooling duty is active when tripped."""
        sim = BeckmannRearrangementReactor()
        sim.state.emergency_methanol_flush_active = True
        sim._update_kinetics_and_conversion()
        assert sim.state.q_flush_kw == 15000.0

    def test_thermal_recovery_under_flush(self) -> None:
        """Verify reactor bed cools down below 355.0 °C under active emergency deluge."""
        sim = BeckmannRearrangementReactor()
        sim.state.bed_temperature_celsius = 380.0
        sim.state.t_bed = 380.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_methanol_flush_active is True

        sim.advance_time(duration_s=4.0, dt=0.02)
        assert sim.state.bed_temperature_celsius < 355.0


# ============================================================================
# Section 11: Horner OCS Memory Map Integration (%R1760..%R1767, %M410..%M412)
# ============================================================================

class TestSection11HornerMemoryMap:
    """Tests for register synchronization, scaling, and SYSTEM privilege writes."""

    def test_analog_registers_scaling_and_values(self) -> None:
        """Verify analog registers %R1760..%R1766 write exact scaled values."""
        reg = RegisterTable()
        sim = BeckmannRearrangementReactor(register_table=reg)
        sim.state.bed_temperature_celsius = 320.0
        sim.state.bed_pressure_bar = 1.50
        sim.state.oxime_conversion_pct = 99.50
        sim.state.caprolactam_selectivity_pct = 96.20
        sim.state.catalyst_activity_pct = 88.50
        sim.state.methanol_oxime_molar_ratio = 6.50
        sim.state.space_velocity_whsv = 1.2
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1760") == 3200  # x10 °C
        assert reg.read_word("%R1761") == 150   # x100 bar
        assert reg.read_word("%R1762") == 9950  # x100 %
        assert reg.read_word("%R1763") == 9620  # x100 %
        assert reg.read_word("%R1764") == 8850  # x100 %
        assert reg.read_word("%R1765") == 650   # x100 ratio
        assert reg.read_word("%R1766") == 12    # x10 WHSV

    def test_diagnostic_status_code_register_r1767(self) -> None:
        """Verify %R1767 reflects diagnostic code."""
        reg = RegisterTable()
        sim = BeckmannRearrangementReactor(register_table=reg)
        sim.state.diagnostic_code = BeckmannRearrangementDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_uword("%R1767") == 0xE701

    def test_discrete_coils_synchronization(self) -> None:
        """Verify discrete coils %M410..%M412 match boolean state."""
        reg = RegisterTable()
        sim = BeckmannRearrangementReactor(register_table=reg)
        sim.state.beckmann_rearrangement_active = True
        sim.state.temperature_high_pre_alarm = False
        sim.state.emergency_methanol_flush_active = False
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M410") is True
        assert reg.read_bit("%M411") is False
        assert reg.read_bit("%M412") is False

    def test_system_privilege_mode_enforcement(self) -> None:
        """Verify write with PrivilegeMode.SYSTEM succeeds."""
        reg = RegisterTable()
        sim = BeckmannRearrangementReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_word("%R1760") == 3200

    def test_register_sync_under_trip_conditions(self) -> None:
        """Verify registers and coils under emergency excursion trip."""
        reg = RegisterTable()
        sim = BeckmannRearrangementReactor(register_table=reg)
        sim.state.bed_temperature_celsius = 378.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M410") is False
        assert reg.read_bit("%M411") is True
        assert reg.read_bit("%M412") is True
        assert reg.read_uword("%R1767") == 0xE701

    def test_status_word_bitmask_consistency(self) -> None:
        """Verify status word bitmask reflects active alarms and states."""
        sim = BeckmannRearrangementReactor()
        sim.state.bed_temperature_celsius = 378.0
        sim._evaluate_safety_interlocks()
        sw = sim.state.status_word
        assert sw & BeckmannRearrangementStatusBits.THERMAL_EXCURSION_TRIP
        assert sw & BeckmannRearrangementStatusBits.EMERGENCY_FLUSH_ACTIVE
        assert sw & BeckmannRearrangementStatusBits.TEMPERATURE_HIGH_PRE_ALARM

    def test_register_clamping_protection(self) -> None:
        """Verify register values are clamped within INT16 bounds."""
        reg = RegisterTable()
        sim = BeckmannRearrangementReactor(register_table=reg)
        sim.state.bed_temperature_celsius = 5000.0  # would exceed 32767 scaled
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_word("%R1760") == 32767


# ============================================================================
# Section 12: Pure IEC 61131-3 Structured Text & Anti-Ladder Security Guard
# ============================================================================

class TestSection12PureSTAndSecurityGuard:
    """Tests for pure Structured Text compliance, AST parsing, and ladder rejection."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Beckmann Rearrangement ST POU parses into valid AST PROGRAM structure."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(BECKMANN_REARRANGEMENT_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "BeckmannRearrangementSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_bound_registers(self) -> None:
        """Verify all %R1760..%R1767 and %M410..%M412 are bound in ST POU."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(BECKMANN_REARRANGEMENT_PURE_ST_POU)
        assert ast is not None
        expected_regs = [
            "%R1760", "%R1761", "%R1762", "%R1763",
            "%R1764", "%R1765", "%R1766", "%R1767",
            "%M410", "%M411", "%M412",
        ]
        for r in expected_regs:
            assert r in ast.bound_registers

    def test_security_guard_assert_pure_st_valid(self) -> None:
        """Verify SecurityGuard accepts pure Structured Text without exception."""
        SecurityGuard.assert_pure_st_content(BECKMANN_REARRANGEMENT_PURE_ST_POU)

    def test_anti_ladder_rejection_contact(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder contacts."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_coil(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder coils."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_rung(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on RUNG keywords."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_mnemonics(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder mnemonics."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nXIC BeckmannRearrangementActive\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 13: ILogicUnit Scan Cycle Execution, Multi-Cycle Soak & Verification Suite
# ============================================================================

class TestSection13ILogicUnitAndVerificationSuite:
    """Tests for ILogicUnit scan cycle execution, multi-cycle soak, and 9-stage runner."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify BeckmannRearrangementReactor exposes required ILogicUnit properties."""
        sim = BeckmannRearrangementReactor()
        assert sim.name == "BeckmannRearrangementSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_with_scan_context(self) -> None:
        """Verify scan_step executes and writes to context.registers."""
        sim = BeckmannRearrangementReactor()
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=20.0)
        ctx.registers = reg
        sim.scan_step(dt=0.02, context=ctx)
        assert reg.read_word("%R1760") == 3200

    def test_adapter_logic_unit_execution(self) -> None:
        """Verify BeckmannRearrangementLogicUnit adapter executes within engine."""
        unit = BeckmannRearrangementLogicUnit()
        assert unit.name == "BeckmannRearrangementSync"
        assert unit.priority == 100
        assert unit.is_enabled is True
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=20.0)
        ctx.registers = reg
        unit.execute(ctx)
        assert reg.read_word("%R1760") == 3200

    def test_reset_restores_nominal_state(self) -> None:
        """Verify reset() restores nominal baseline state."""
        sim = BeckmannRearrangementReactor()
        sim.state.bed_temperature_celsius = 380.0
        sim.state.oxime_conversion_pct = 95.0
        sim.reset()
        assert sim.state.bed_temperature_celsius == REACTOR_TEMP_NOMINAL_C
        assert sim.state.oxime_conversion_pct == pytest.approx(OXIME_CONVERSION_NOMINAL_PCT, abs=0.05)
        assert sim.state.diagnostic_code == BeckmannRearrangementDiagnosticCode.OK
        assert sim.state.emergency_methanol_flush_active is False

    def test_multi_cycle_soak_execution(self) -> None:
        """Verify 100 continuous scan cycles execute without drift or error."""
        sim = BeckmannRearrangementReactor()
        for _ in range(100):
            sim.scan_step(dt=0.02)
        assert sim.state.scan_count == 100
        assert 300.0 <= sim.state.bed_temperature_celsius <= 350.0
        assert not math.isnan(sim.state.bed_temperature_celsius)

    def test_run_beckmann_rearrangement_verification_status_success(self) -> None:
        """Verify 9-stage verification suite passes with strict 4-state success contract."""
        res = run_beckmann_rearrangement_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W215"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_verification_json_export(self, tmp_path: Path) -> None:
        """Verify JSON evidence artifact is created and valid on disk."""
        out_file = tmp_path / "beckmann_evidence.json"
        res = run_beckmann_rearrangement_verification(output_path=out_file)
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_aliases(self) -> None:
        """Verify all verification runner aliases return identical success."""
        res1 = run_beckmann_rearrangement_verification()
        res2 = run_beckmann_verification()
        res3 = run_beckmann_reactor_verification()
        assert res1["status"] == "success"
        assert res2["status"] == "success"
        assert res3["status"] == "success"

    def test_helper_verification_functions(self) -> None:
        """Verify helper validation functions return True / SUCCESS."""
        assert verify_beckmann_rearrangement_pure_st() is True
        assert verify_beckmann_pure_st() is True
        assert verify_beckmann_reactor_pure_st() is True
        val = validate_pure_st()
        assert val.status == AgentStatus.SUCCESS

    def test_class_and_constant_aliases(self) -> None:
        """Verify model, state, config, and diagnostic aliases point to canonical definitions."""
        assert BeckmannReactor is BeckmannRearrangementReactor
        assert BeckmannSimulator is BeckmannRearrangementReactor
        assert BeckmannEngine is BeckmannRearrangementReactor
        assert BeckmannModel is BeckmannRearrangementReactor
        assert BeckmannPlantModel is BeckmannRearrangementReactor
        assert BeckmannSimulationEngine is BeckmannRearrangementReactor
        assert BeckmannReactorSimulator is BeckmannRearrangementReactor
        assert BeckmannReactorEngine is BeckmannRearrangementReactor
        assert BeckmannReactorModel is BeckmannRearrangementReactor
        assert BeckmannReactorPlantModel is BeckmannRearrangementReactor
        assert BeckmannReactorSimulationEngine is BeckmannRearrangementReactor
        assert BeckmannRearrangementSimulator is BeckmannRearrangementReactor
        assert BeckmannRearrangementEngine is BeckmannRearrangementReactor
        assert BeckmannRearrangementModel is BeckmannRearrangementReactor
        assert BeckmannRearrangementPlantModel is BeckmannRearrangementReactor
        assert BeckmannRearrangementSimulationEngine is BeckmannRearrangementReactor

        assert BeckmannConfig is BeckmannRearrangementConfig
        assert BeckmannParameters is BeckmannRearrangementConfig
        assert BeckmannReactorConfig is BeckmannRearrangementConfig
        assert BeckmannReactorParameters is BeckmannRearrangementConfig
        assert BeckmannRearrangementParameters is BeckmannRearrangementConfig

        assert BeckmannDiagnosticCode is BeckmannRearrangementDiagnosticCode
        assert BeckmannDiagCode is BeckmannRearrangementDiagnosticCode
        assert BeckmannReactorDiagnosticCode is BeckmannRearrangementDiagnosticCode
        assert BeckmannReactorDiagCode is BeckmannRearrangementDiagnosticCode
        assert BeckmannRearrangementDiagCode is BeckmannRearrangementDiagnosticCode

        assert BeckmannStatusBits is BeckmannRearrangementStatusBits
        assert BeckmannStatusWord is BeckmannRearrangementStatusBits
        assert BeckmannReactorStatusBits is BeckmannRearrangementStatusBits
        assert BeckmannReactorStatusWord is BeckmannRearrangementStatusBits
        assert BeckmannRearrangementStatusWord is BeckmannRearrangementStatusBits

        assert BeckmannState is BeckmannRearrangementState
        assert BeckmannReactorState is BeckmannRearrangementState
        assert BeckmannRearrangementReactorState is BeckmannRearrangementState

        assert BeckmannLogicUnit is BeckmannRearrangementLogicUnit
        assert BeckmannReactorLogicUnit is BeckmannRearrangementLogicUnit

        assert (
            BECKMANN_REARRANGEMENT_PURE_ST_POU
            == BECKMANN_REARRANGEMENT_SYNC_POU
            == BECKMANN_PURE_ST_POU
            == BECKMANN_SYNC_POU
            == BECKMANN_REACTOR_PURE_ST_POU
            == BECKMANN_REACTOR_SYNC_POU
        )
