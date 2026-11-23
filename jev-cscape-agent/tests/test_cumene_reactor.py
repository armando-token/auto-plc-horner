"""Comprehensive Industrial Cumene Zeolite Alkylation & Transalkylation Reactor Test Suite.

Work Package: W197 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 12 engineering verification sections:
1. Section 1: Universal Physical Constants, Molecular Weights & Thermodynamic Enthalpies
2. Section 2: Fixed-Bed Reactor Configuration, Geometry & Operating Parameters
3. Section 3: Zeolite Alkylation, Polyalkylation & Transalkylation Kinetics & Arrhenius Energies
4. Section 4: Inter-Bed Cold Benzene Quench Dynamic Cooling & Runaway Prevention
5. Section 5: Coupled 6-State ODE System & High-Order RK4 Numerical Integration
6. Section 6: Stoichiometric Mass, Elemental & Enthalpy Conservation Residuals (< 1e-10)
7. Section 7: Derived Operational Metrics, Yield & Transalkylation Performance
8. Section 8: Process Safety Interlocks & Diagnostics in Strict Priority Hierarchy (0xD501..0xD504)
9. Section 9: Horner OCS Memory Space Integration & SYSTEM Privilege Mode
10. Section 10: Strict Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
11. Section 11: ILogicUnit Scan Cycle Execution & Simulation Engine Integration
12. Section 12: Deterministic 9-Stage Verification Suite & Runner Integration
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.cumene_reactor import (
    BED_OVERHEAT_WARNING_C,
    BENZENE_PROPYLENE_RATIO_NOMINAL,
    BENZENE_STARVATION_RATIO_MIN,
    CUMENE_PURE_ST_POU,
    CUMENE_REACTOR_PURE_ST_POU,
    CUMENE_REACTOR_SYNC_POU,
    CUMENE_SELECTIVITY_NOMINAL_PCT,
    CUMENE_SYNC_POU,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DIPB_FRACTION_NOMINAL_PCT,
    G_ACCEL,
    INLET_TEMP_NOMINAL_C,
    MW_BENZENE,
    MW_C,
    MW_CUMENE,
    MW_DIPB,
    MW_H,
    MW_PROPYLENE,
    PEAK_TEMP_NOMINAL_C,
    PROPYLENE_CONV_NOMINAL_PCT,
    QUENCH_SHUTOFF_TEMP_C,
    QUENCH_TRIGGER_TEMP_C,
    REACTOR_PRESSURE_MAX_BAR,
    REACTOR_PRESSURE_MIN_BAR,
    REACTOR_PRESSURE_NOMINAL_BAR,
    R_GAS_CONST,
    TRANSALKYLATION_CONV_MIN_PCT,
    TRANSALKYLATION_CONV_NOMINAL_PCT,
    T_REF_K,
    T_ZERO_CELSIUS,
    CumeneConfig,
    CumeneDiagCode,
    CumeneDiagnosticCode,
    CumeneLogicUnit,
    CumeneParameters,
    CumeneReactor,
    CumeneReactorConfig,
    CumeneReactorDiagCode,
    CumeneReactorDiagnosticCode,
    CumeneReactorEngine,
    CumeneReactorLogicUnit,
    CumeneReactorModel,
    CumeneReactorParameters,
    CumeneReactorPlantModel,
    CumeneReactorSimulationEngine,
    CumeneReactorSimulator,
    CumeneReactorState,
    CumeneReactorStatusBits,
    CumeneReactorStatusWord,
    CumeneSimulator,
    CumeneState,
    CumeneStatusBits,
    CumeneStatusWord,
    run_cumene_reactor_verification,
    run_cumene_verification,
    validate_pure_st,
    verify_cumene_pure_st,
    verify_cumene_reactor_pure_st,
)
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


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
        assert abs(T_REF_K - 493.15) < 1e-4

    def test_elemental_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon and Hydrogen."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6

    def test_reactant_molecular_weights(self) -> None:
        """Verify reactant molecular weights for benzene (C6H6) and propylene (C3H6)."""
        expected_benzene = 6.0 * MW_C + 6.0 * MW_H
        expected_propylene = 3.0 * MW_C + 6.0 * MW_H
        assert abs(MW_BENZENE - expected_benzene) < 1e-8
        assert abs(MW_PROPYLENE - expected_propylene) < 1e-8
        assert abs(MW_BENZENE - 0.078114) < 1e-5
        assert abs(MW_PROPYLENE - 0.042081) < 1e-5

    def test_product_molecular_weights(self) -> None:
        """Verify product molecular weights for cumene (C9H12) and DIPB (C12H18)."""
        expected_cumene = 9.0 * MW_C + 12.0 * MW_H
        expected_dipb = 12.0 * MW_C + 18.0 * MW_H
        assert abs(MW_CUMENE - expected_cumene) < 1e-8
        assert abs(MW_DIPB - expected_dipb) < 1e-8
        assert abs(MW_CUMENE - 0.120195) < 1e-5
        assert abs(MW_DIPB - 0.162276) < 1e-5

    def test_stoichiometric_mass_balance_relations(self) -> None:
        """Verify stoichiometric relations between reactants and products."""
        # Alkylation: Benzene + Propylene -> Cumene
        assert abs((MW_BENZENE + MW_PROPYLENE) - MW_CUMENE) < 1e-12
        # Polyalkylation: Cumene + Propylene -> DIPB
        assert abs((MW_CUMENE + MW_PROPYLENE) - MW_DIPB) < 1e-12
        # Transalkylation: DIPB + Benzene <-> 2 Cumene
        assert abs((MW_DIPB + MW_BENZENE) - (2.0 * MW_CUMENE)) < 1e-12

    def test_reaction_enthalpies(self) -> None:
        """Verify reaction enthalpies for alkylation, polyalkylation, and transalkylation."""
        assert DELTA_H1_KJ_MOL == -105.0
        assert DELTA_H1_J_MOL == -105000.0
        assert DELTA_H2_KJ_MOL == -102.0
        assert DELTA_H2_J_MOL == -102000.0
        assert DELTA_H3_KJ_MOL == -3.0
        assert DELTA_H3_J_MOL == -3000.0

    def test_hess_law_thermochemical_consistency(self) -> None:
        """Verify Hess's Law thermochemical consistency: Delta H1 - Delta H2 == Delta H3."""
        # (Benzene + Propylene -> Cumene) minus (Cumene + Propylene -> DIPB)
        # = Benzene - Cumene -> Cumene - DIPB <=> Benzene + DIPB -> 2 Cumene
        assert abs((DELTA_H1_KJ_MOL - DELTA_H2_KJ_MOL) - DELTA_H3_KJ_MOL) < 1e-9


# ============================================================================
# Section 2: Fixed-Bed Reactor Configuration & Operating Parameters
# ============================================================================

class TestSection2ReactorConfiguration:
    """Tests for CumeneConfig geometry, dimensions, catalyst, and parameters."""

    def test_default_geometric_properties(self) -> None:
        """Verify default column diameter, bed length, cross-section and volume."""
        cfg = CumeneConfig()
        assert cfg.reactor_diameter_m == 2.6
        assert cfg.bed_length_m == 10.0
        expected_cross_section = 0.25 * math.pi * (2.6 ** 2)
        assert abs(cfg.bed_cross_section_m2 - expected_cross_section) < 1e-4
        expected_volume = expected_cross_section * 10.0
        assert abs(cfg.bed_volume_m3 - expected_volume) < 1e-4
        expected_surface = math.pi * 2.6 * 10.0
        assert abs(cfg.vessel_surface_area_m2 - expected_surface) < 1e-4

    def test_catalyst_particle_and_bed_properties(self) -> None:
        """Verify zeolite catalyst extrudate properties and bed voidage."""
        cfg = CumeneConfig()
        assert cfg.particle_diameter_m == 0.0016
        assert cfg.bed_voidage_fraction == 0.40
        assert cfg.catalyst_bulk_density_kg_m3 == 700.0
        assert cfg.catalyst_heat_capacity_j_kg_k == 1100.0
        assert cfg.bed_heat_capacity_j_k > 0.0

    def test_nominal_operating_baseline_parameters(self) -> None:
        """Verify baseline operating conditions: inlet 210 °C, peak 245 °C, 35 bar, B/P 3.50."""
        cfg = CumeneConfig()
        assert cfg.nominal_bed_inlet_temp_c == INLET_TEMP_NOMINAL_C == 210.0
        assert cfg.nominal_bed_peak_temp_c == PEAK_TEMP_NOMINAL_C == 245.0
        assert cfg.nominal_reactor_pressure_bar == REACTOR_PRESSURE_NOMINAL_BAR == 35.0
        assert cfg.nominal_benzene_propylene_ratio == BENZENE_PROPYLENE_RATIO_NOMINAL == 3.50
        assert cfg.nominal_propylene_feed_kg_h == 10000.0

    def test_nominal_conversions_and_selectivities(self) -> None:
        """Verify baseline conversion and selectivity targets."""
        assert PROPYLENE_CONV_NOMINAL_PCT == 99.8
        assert CUMENE_SELECTIVITY_NOMINAL_PCT == 92.5
        assert DIPB_FRACTION_NOMINAL_PCT == 6.8
        assert TRANSALKYLATION_CONV_NOMINAL_PCT == 85.0

    def test_cold_quench_design_parameters(self) -> None:
        """Verify cold benzene quench parameters: 60 °C, 25 kg/s, trigger 248 °C, shutoff 246 °C."""
        cfg = CumeneConfig()
        assert cfg.quench_temp_c == 60.0
        assert cfg.quench_flow_kg_s == 25.0
        assert cfg.quench_trigger_temp_c == QUENCH_TRIGGER_TEMP_C == 248.0
        assert cfg.quench_shutoff_temp_c == QUENCH_SHUTOFF_TEMP_C == 246.0

    def test_config_type_aliases(self) -> None:
        """Verify configuration type aliases."""
        assert CumeneReactorConfig is CumeneConfig
        assert CumeneParameters is CumeneConfig
        assert CumeneReactorParameters is CumeneConfig


# ============================================================================
# Section 3: Zeolite Alkylation, Polyalkylation & Transalkylation Kinetics
# ============================================================================

class TestSection3ReactionKinetics:
    """Tests for reaction rates, Arrhenius acceleration, and activation energies."""

    @pytest.fixture
    def reactor(self) -> CumeneReactor:
        return CumeneReactor()

    def test_activation_energies_ordering(self) -> None:
        """Verify activation energies: polyalkylation (72 kJ) > alkylation (65 kJ) > transalkylation (45 kJ)."""
        cfg = CumeneConfig()
        assert cfg.activation_energy_2_j_mol > cfg.activation_energy_1_j_mol
        assert cfg.activation_energy_1_j_mol > cfg.activation_energy_3_j_mol
        assert cfg.activation_energy_1_j_mol == 65000.0
        assert cfg.activation_energy_2_j_mol == 72000.0
        assert cfg.activation_energy_3_j_mol == 45000.0

    def test_nominal_reaction_rates_positive(self, reactor: CumeneReactor) -> None:
        """Verify all reaction rates and exothermic duty are positive at nominal conditions."""
        rates = reactor.compute_reaction_rates(5500.0, 8.5, 1650.0, 120.0, 518.15)
        assert rates["r1_mol_s"] > 0.0
        assert rates["r2_mol_s"] > 0.0
        assert rates["r3f_mol_s"] > 0.0
        assert rates["r3r_mol_s"] > 0.0
        assert rates["r3_net_mol_s"] > 0.0
        assert rates["q_rxn_kw"] > 0.0

    def test_arrhenius_temperature_acceleration(self, reactor: CumeneReactor) -> None:
        """Verify that reaction rates accelerate with increasing temperature."""
        rates_nom = reactor.compute_reaction_rates(5500.0, 8.5, 1650.0, 120.0, 518.15)
        rates_hot = reactor.compute_reaction_rates(5500.0, 8.5, 1650.0, 120.0, 528.15)
        assert rates_hot["r1_mol_s"] > rates_nom["r1_mol_s"]
        assert rates_hot["r2_mol_s"] > rates_nom["r2_mol_s"]
        assert rates_hot["q_rxn_kw"] > rates_nom["q_rxn_kw"]

    def test_polyalkylation_acceleration_ratio(self, reactor: CumeneReactor) -> None:
        """Verify that polyalkylation (Ea=72k) accelerates faster than alkylation (Ea=65k)."""
        rates_nom = reactor.compute_reaction_rates(5500.0, 8.5, 1650.0, 120.0, 518.15)
        rates_hot = reactor.compute_reaction_rates(5500.0, 8.5, 1650.0, 120.0, 538.15)
        ratio_r1 = rates_hot["r1_mol_s"] / rates_nom["r1_mol_s"]
        ratio_r2 = rates_hot["r2_mol_s"] / rates_nom["r2_mol_s"]
        assert ratio_r2 > ratio_r1

    def test_transalkylation_equilibrium_and_net_forward_rate(self, reactor: CumeneReactor) -> None:
        """Verify that transalkylation forward rate exceeds reverse under rich benzene/DIPB conditions."""
        rates = reactor.compute_reaction_rates(5500.0, 8.5, 1650.0, 120.0, 518.15)
        assert rates["r3f_mol_s"] > rates["r3r_mol_s"]
        assert rates["r3_net_mol_s"] > 0.0

    def test_kinetic_rate_constants_at_reference_temp(self, reactor: CumeneReactor) -> None:
        """Verify rate constants evaluated at reference temperature match configured values."""
        rates_ref = reactor.compute_reaction_rates(5500.0, 8.5, 1650.0, 120.0, T_REF_K)
        assert abs(rates_ref["k1"] - reactor.config.k1_ref) < 1e-6
        assert abs(rates_ref["k2"] - reactor.config.k2_ref) < 1e-6
        assert abs(rates_ref["k3f"] - reactor.config.k3f_ref) < 1e-6
        assert abs(rates_ref["k3r"] - reactor.config.k3r_ref) < 1e-6


# ============================================================================
# Section 4: Inter-Bed Cold Benzene Quench Dynamic Cooling & Runaway Prevention
# ============================================================================

class TestSection4QuenchDynamics:
    """Tests for cold benzene quench injection, hysteresis, and runaway prevention."""

    def test_quench_inactive_at_nominal_temperature(self) -> None:
        """Verify quench valve remains closed at nominal 245 °C."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 245.0
        sim._evaluate_safety_interlocks()
        assert sim.state.quench_shot_active is False
        assert sim.state.bed_overheat_warning is False

    def test_quench_triggers_above_248c(self) -> None:
        """Verify quench valve opens when bed peak temperature exceeds 248.0 °C."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 248.5
        sim._evaluate_safety_interlocks()
        assert sim.state.quench_shot_active is True

    def test_quench_hysteresis_shutoff(self) -> None:
        """Verify quench valve stays open between 246 °C and 248 °C until cooled below 246 °C."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 250.0
        sim._evaluate_safety_interlocks()
        assert sim.state.quench_shot_active is True

        # Drop to 247.0 °C (in hysteresis zone)
        sim.state.bed_peak_temp_celsius = 247.0
        sim._evaluate_safety_interlocks()
        assert sim.state.quench_shot_active is True

        # Drop below 246.0 °C
        sim.state.bed_peak_temp_celsius = 245.5
        sim._evaluate_safety_interlocks()
        assert sim.state.quench_shot_active is False

    def test_quench_cooling_duty_calculation(self) -> None:
        """Verify quench cooling duty calculation when quench valve is active."""
        sim = CumeneReactor()
        sim.state.quench_shot_active = True
        sim.state.bed_peak_temp_celsius = 260.0
        sim.state.t_bed = 260.0 + T_ZERO_CELSIUS
        sim._update_kinetics_and_conversion()
        # Q = 25.0 kg/s * 2200 J/(kg*K) * (260 - 60) K = 11,000,000 W = 11,000 kW
        expected_duty = 25.0 * 2200.0 * (260.0 - 60.0) / 1000.0
        assert abs(sim.state.q_quench_kw - expected_duty) < 1.0

    def test_emergency_quench_thermal_runaway_arrest(self) -> None:
        """Verify emergency quench arrests runaway excursion from 265 °C to < 250 °C within 8s."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 265.0
        sim.state.t_bed = 265.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.quench_shot_active is True
        assert sim.state.bed_overheat_warning is True

        res = sim.advance_time(duration_s=8.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.bed_peak_temp_celsius < 250.0

    def test_quench_adds_diluent_benzene_moles(self) -> None:
        """Verify that quench injection adds cold benzene into the reactor derivatives."""
        sim = CumeneReactor()
        y0 = [sim.state.c_benzene, sim.state.c_propylene, sim.state.c_cumene, sim.state.c_dipb, sim.state.t_bed, sim.state.p_reactor]
        # Derivative with quench inactive
        sim.state.quench_shot_active = False
        d_no_quench = sim.compute_derivatives(0.0, y0)

        # Derivative with quench active
        sim.state.quench_shot_active = True
        d_quench = sim.compute_derivatives(0.0, y0)

        # Benzene concentration derivative is higher (more benzene added)
        assert d_quench[0] > d_no_quench[0]
        # Temperature derivative is significantly lower (more cooling)
        assert d_quench[4] < d_no_quench[4]


# ============================================================================
# Section 5: Coupled 6-State ODE System & High-Order RK4 Integration
# ============================================================================

class TestSection5RK4Integration:
    """Tests for coupled 6-state ODE system and RK4 integration stability."""

    def test_derivative_vector_length_and_finiteness(self) -> None:
        """Verify compute_derivatives returns exactly 6 finite values."""
        sim = CumeneReactor()
        y = [sim.state.c_benzene, sim.state.c_propylene, sim.state.c_cumene, sim.state.c_dipb, sim.state.t_bed, sim.state.p_reactor]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6
        assert all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    def test_state_vector_names_and_physical_bounds(self) -> None:
        """Verify that state attributes are present and within valid ranges."""
        sim = CumeneReactor()
        assert sim.state.c_benzene > 0.0
        assert sim.state.c_propylene >= 0.0
        assert sim.state.c_cumene > 0.0
        assert sim.state.c_dipb >= 0.0
        assert 200.0 <= sim.state.bed_peak_temp_celsius <= 300.0
        assert 20.0 <= sim.state.reactor_pressure_bar <= 50.0

    def test_rk4_single_step_advancement(self) -> None:
        """Verify single rk4_step advances simulation time by dt and increments scan count."""
        sim = CumeneReactor()
        initial_time = sim.state.sim_time_s
        initial_scans = sim.state.scan_count
        res = sim.step(dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert abs(sim.state.sim_time_s - (initial_time + 0.05)) < 1e-6
        assert sim.state.scan_count == initial_scans + 1

    def test_rk4_multi_step_stability_and_convergence(self) -> None:
        """Verify advance_time(5.0 s) remains dynamically stable within physical bounds."""
        sim = CumeneReactor()
        res = sim.advance_time(duration_s=5.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.c_benzene > 3000.0
        assert sim.state.c_propylene >= 0.0
        assert sim.state.c_cumene > 1000.0
        assert sim.state.c_dipb > 50.0
        assert 210.0 <= sim.state.bed_peak_temp_celsius <= 260.0
        assert 30.0 <= sim.state.reactor_pressure_bar <= 40.0

    def test_pressure_dynamics_and_thermal_coupling(self) -> None:
        """Verify pressure dynamics relaxation toward target with thermal coupling."""
        sim = CumeneReactor()
        # Set off-target pressure
        sim.state.p_reactor = 30.0 * 1.0e5
        y = [sim.state.c_benzene, sim.state.c_propylene, sim.state.c_cumene, sim.state.c_dipb, sim.state.t_bed, sim.state.p_reactor]
        d = sim.compute_derivatives(0.0, y)
        # Pressure derivative should be positive (driving back to 35 bar)
        assert d[5] > 0.0

    def test_reset_functionality(self) -> None:
        """Verify reset() restores simulator state to nominal conditions."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 280.0
        sim.state.quench_shot_active = True
        sim.reset()
        assert sim.state.bed_peak_temp_celsius == PEAK_TEMP_NOMINAL_C
        assert sim.state.quench_shot_active is False
        assert sim.state.sim_time_s == 0.0


# ============================================================================
# Section 6: Stoichiometric Mass, Elemental & Enthalpy Residuals (< 1e-10)
# ============================================================================

class TestSection6ConservationResiduals:
    """Tests for stoichiometric mass balance, elemental, and enthalpy residuals."""

    def test_total_mass_balance_residual_under_1e10(self) -> None:
        """Verify total mass balance residual is strictly < 1e-10 kg/s at baseline."""
        sim = CumeneReactor()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_mass_balance_residual_under_1e10(self) -> None:
        """Verify elemental mass balance residual is strictly < 1e-10 kg/s."""
        sim = CumeneReactor()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_under_1e10(self) -> None:
        """Verify enthalpy conservation residual is strictly < 1e-10 kW."""
        sim = CumeneReactor()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_maintained_during_rk4_dynamic_integration(self) -> None:
        """Verify all 3 conservation residuals remain < 1e-10 during dynamic RK4 integration."""
        sim = CumeneReactor()
        sim.advance_time(duration_s=2.0, dt=0.05)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_under_high_temperature_excursion(self) -> None:
        """Verify conservation residuals remain < 1e-10 even under thermal excursion at 270 °C."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 270.0
        sim.state.t_bed = 270.0 + T_ZERO_CELSIUS
        sim._update_kinetics_and_conversion()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_exact_species_mass_stoichiometry(self) -> None:
        """Verify exact closed-form algebraic stoichiometry for alkylation and transalkylation."""
        r1, r2, r3 = 50.0, 5.0, 3.0
        # Reactants mass
        mass_in = (r1 + r3) * MW_BENZENE + (r1 + r2) * MW_PROPYLENE + r2 * MW_CUMENE + r3 * MW_DIPB
        # Products mass
        mass_out = (r1 + 2.0 * r3) * MW_CUMENE + r2 * MW_DIPB
        assert abs(mass_in - mass_out) < 1e-14


# ============================================================================
# Section 7: Derived Operational Metrics, Yield & Transalkylation Performance
# ============================================================================

class TestSection7OperationalMetrics:
    """Tests for propylene conversion, cumene selectivity, DIPB fraction, and in-spec logic."""

    def test_propylene_conversion_calculation(self) -> None:
        """Verify propylene conversion percentage tracks consumed propylene."""
        sim = CumeneReactor()
        sim.state.c_propylene = 8.5
        sim._update_kinetics_and_conversion()
        assert 95.0 <= sim.state.propylene_conversion_pct <= 100.0

    def test_cumene_selectivity_calculation(self) -> None:
        """Verify cumene selectivity percentage calculation."""
        sim = CumeneReactor()
        assert abs(sim.state.cumene_selectivity_pct - CUMENE_SELECTIVITY_NOMINAL_PCT) < 0.1
        # Off-nominal high byproduct state
        sim.state.c_cumene = 1000.0
        sim.state.c_dipb = 400.0
        sim._update_kinetics_and_conversion()
        expected = (1000.0 / (1000.0 + 2.0 * 400.0)) * 100.0
        assert abs(sim.state.cumene_selectivity_pct - expected) < 1.0

    def test_dipb_fraction_calculation(self) -> None:
        """Verify DIPB byproduct fraction percentage calculation."""
        sim = CumeneReactor()
        sim.state.c_cumene = 1650.0
        sim.state.c_dipb = 120.0
        sim._update_kinetics_and_conversion()
        expected = (120.0 / (1650.0 + 120.0)) * 100.0
        assert abs(sim.state.dipb_fraction_pct - expected) < 1.0

    def test_transalkylation_conversion_calculation(self) -> None:
        """Verify transalkylation conversion tracks net DIPB consumption."""
        sim = CumeneReactor()
        sim._update_kinetics_and_conversion()
        assert 50.0 <= sim.state.transalkylation_conversion_pct <= 100.0

    def test_transalkylation_in_spec_logic(self) -> None:
        """Verify %M370 is True when selectivity > 90% and conversion > 95%."""
        sim = CumeneReactor()
        sim.state.cumene_selectivity_pct = 92.5
        sim.state.propylene_conversion_pct = 99.8
        sim._evaluate_safety_interlocks()
        assert sim.state.transalkylation_in_spec is True

    def test_transalkylation_off_spec_on_low_selectivity(self) -> None:
        """Verify %M370 drops to False when cumene selectivity drops below 90%."""
        sim = CumeneReactor()
        sim.state.cumene_selectivity_pct = 88.0
        sim.state.propylene_conversion_pct = 99.8
        sim._evaluate_safety_interlocks()
        assert sim.state.transalkylation_in_spec is False

    def test_transalkylation_off_spec_on_low_conversion(self) -> None:
        """Verify %M370 drops to False when propylene conversion drops below 95%."""
        sim = CumeneReactor()
        sim.state.cumene_selectivity_pct = 92.5
        sim.state.propylene_conversion_pct = 94.0
        sim._evaluate_safety_interlocks()
        assert sim.state.transalkylation_in_spec is False


# ============================================================================
# Section 8: Process Safety Interlocks & Diagnostics in Strict Priority
# ============================================================================

class TestSection8SafetyInterlocks:
    """Tests for safety alarms 0xD501..0xD504 and strict priority hierarchy."""

    def test_nominal_healthy_diagnostic_code(self) -> None:
        """Verify diagnostic code is 0x0000 (OK) during normal operation."""
        sim = CumeneReactor()
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.OK

    def test_priority_1_thermal_runaway_risk(self) -> None:
        """Verify 0xD501 is asserted when bed peak temp > 260 °C, sets %M368 and %M369."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 265.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.THERMAL_RUNAWAY_RISK
        assert sim.state.diagnostic_code == 0xD501
        assert sim.state.bed_overheat_warning is True
        assert sim.state.quench_shot_active is True

    def test_priority_2_benzene_starvation(self) -> None:
        """Verify 0xD502 is asserted when Benzene/Propylene ratio < 2.50."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 245.0
        sim.state.benzene_propylene_ratio = 2.20
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.BENZENE_STARVATION
        assert sim.state.diagnostic_code == 0xD502
        assert sim.state.bed_overheat_warning is False

    def test_priority_3_catalyst_coking_degradation(self) -> None:
        """Verify 0xD503 is asserted when transalkylation conversion < 75.0%."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 245.0
        sim.state.benzene_propylene_ratio = 3.50
        sim.state.transalkylation_conversion_pct = 70.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.CATALYST_COKING_DEGRADATION
        assert sim.state.diagnostic_code == 0xD503

    def test_priority_4_pressure_drop_anomaly(self) -> None:
        """Verify 0xD504 is asserted when pressure < 28 bar or > 42 bar."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 245.0
        sim.state.benzene_propylene_ratio = 3.50
        sim.state.transalkylation_conversion_pct = 85.0
        # Pressure low
        sim.state.reactor_pressure_bar = 25.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.PRESSURE_DROP_ANOMALY
        assert sim.state.diagnostic_code == 0xD504

        # Pressure high
        sim.state.reactor_pressure_bar = 45.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.PRESSURE_DROP_ANOMALY

    def test_strict_priority_hierarchy_ordering(self) -> None:
        """Verify strict priority ordering: 0xD501 > 0xD502 > 0xD503 > 0xD504 > 0x0000."""
        sim = CumeneReactor()
        # All 4 faults active simultaneously
        sim.state.bed_peak_temp_celsius = 265.0   # 0xD501
        sim.state.benzene_propylene_ratio = 2.10  # 0xD502
        sim.state.transalkylation_conversion_pct = 68.0 # 0xD503
        sim.state.reactor_pressure_bar = 24.0     # 0xD504
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.THERMAL_RUNAWAY_RISK

        # Clear 0xD501 -> 0xD502 active
        sim.state.bed_peak_temp_celsius = 245.0
        sim.state.quench_shot_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.BENZENE_STARVATION

        # Clear 0xD502 -> 0xD503 active
        sim.state.benzene_propylene_ratio = 3.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.CATALYST_COKING_DEGRADATION

        # Clear 0xD503 -> 0xD504 active
        sim.state.transalkylation_conversion_pct = 85.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.PRESSURE_DROP_ANOMALY

        # Clear 0xD504 -> 0x0000 OK
        sim.state.reactor_pressure_bar = 35.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneDiagnosticCode.OK

    def test_status_word_bitmask_consistency(self) -> None:
        """Verify status word correctly encodes bit flags."""
        sim = CumeneReactor()
        sim.state.bed_peak_temp_celsius = 265.0
        sim._evaluate_safety_interlocks()
        assert bool(sim.state.status_word & CumeneStatusBits.RUNNING)
        assert bool(sim.state.status_word & CumeneStatusBits.BED_OVERHEAT_WARNING)
        assert bool(sim.state.status_word & CumeneStatusBits.QUENCH_SHOT_ACTIVE)
        assert bool(sim.state.status_word & CumeneStatusBits.THERMAL_RUNAWAY_ALARM)


# ============================================================================
# Section 9: Horner OCS Memory Space Integration & SYSTEM Privilege
# ============================================================================

class TestSection9HornerMemorySpace:
    """Tests for Horner OCS RegisterTable synchronization with PrivilegeMode.SYSTEM."""

    def test_register_table_write_with_system_privilege(self) -> None:
        """Verify sync_to_registers writes all registers with SYSTEM privilege."""
        reg = RegisterTable()
        sim = CumeneReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        # Check that analog and discrete registers are written
        assert reg.read_word("%R1580") > 0
        assert reg.read_word("%R1581") > 0

    def test_analog_register_scaling_factors(self) -> None:
        """Verify scaling factors for %R1580..%R1587."""
        reg = RegisterTable()
        sim = CumeneReactor(register_table=reg)
        sim.state.bed_inlet_temp_celsius = 210.0
        sim.state.bed_peak_temp_celsius = 245.0
        sim.state.benzene_propylene_ratio = 3.50
        sim.state.propylene_conversion_pct = 99.8
        sim.state.cumene_selectivity_pct = 92.5
        sim.state.dipb_fraction_pct = 6.8
        sim.state.transalkylation_conversion_pct = 85.0
        sim.state.reactor_pressure_bar = 35.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1580") == 2100  # x10 °C
        assert reg.read_word("%R1581") == 2450  # x10 °C
        assert reg.read_word("%R1582") == 350   # x100 ratio
        assert reg.read_word("%R1583") == 998   # x10 %
        assert reg.read_word("%R1584") == 925   # x10 %
        assert reg.read_word("%R1585") == 68    # x10 %
        assert reg.read_word("%R1586") == 850   # x10 %
        assert reg.read_word("%R1587") == 350   # x10 bar

    def test_discrete_coil_states(self) -> None:
        """Verify discrete coils %M368..%M370 mapping."""
        reg = RegisterTable()
        sim = CumeneReactor(register_table=reg)
        sim.state.bed_overheat_warning = False
        sim.state.quench_shot_active = True
        sim.state.transalkylation_in_spec = True
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M368") is False
        assert reg.read_bit("%M369") is True
        assert reg.read_bit("%M370") is True

    def test_register_table_read_roundtrip_fidelity(self) -> None:
        """Verify registers can be read back and decoded to within 0.1% of true float values."""
        reg = RegisterTable()
        sim = CumeneReactor(register_table=reg)
        sim.state.bed_peak_temp_celsius = 243.6
        sim.state.benzene_propylene_ratio = 3.42
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        decoded_temp = reg.read_word("%R1581") / 10.0
        decoded_ratio = reg.read_word("%R1582") / 100.0
        assert abs(decoded_temp - 243.6) < 0.15
        assert abs(decoded_ratio - 3.42) < 0.02

    def test_default_register_table_creation(self) -> None:
        """Verify simulator initializes with a default RegisterTable if none is provided."""
        sim = CumeneReactor()
        assert isinstance(sim.registers, RegisterTable)
        assert sim.registers.read_word("%R1580") > 0


# ============================================================================
# Section 10: Strict Pure IEC 61131-3 Structured Text POU & Anti-Ladder Guard
# ============================================================================

class TestSection10PureSTAndSecurityGuard:
    """Tests for pure Structured Text POU parsing and anti-ladder security interception."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify STParser parses POU 'CumeneReactorSync' with POUType.PROGRAM."""
        ast = STParser.parse_pou(CUMENE_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "CumeneReactorSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_pou_register_symbol_bindings(self) -> None:
        """Verify POU binds all 11 registers: %R1580..%R1587 and %M368..%M370."""
        ast = STParser.parse_pou(CUMENE_REACTOR_PURE_ST_POU)
        assert ast is not None
        expected_regs = [
            "%R1580", "%R1581", "%R1582", "%R1583",
            "%R1584", "%R1585", "%R1586", "%R1587",
            "%M368", "%M369", "%M370",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_anti_ladder_security_guard_normal_content(self) -> None:
        """Verify SecurityGuard.assert_pure_st_content accepts clean ST POU without exception."""
        SecurityGuard.assert_pure_st_content(CUMENE_REACTOR_PURE_ST_POU)

    def test_anti_ladder_rejection_contact(self) -> None:
        """Verify SecurityGuard rejects ladder contact construct '---[ ]---'."""
        bad_code = f"PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_coil(self) -> None:
        """Verify SecurityGuard rejects ladder coil construct '---( )---'."""
        bad_code = f"PROGRAM Bad\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_rung(self) -> None:
        """Verify SecurityGuard rejects ladder rung delimiter 'RUNG 1'."""
        bad_code = f"PROGRAM Bad\nVAR x: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_mnemonics(self) -> None:
        """Verify SecurityGuard rejects ladder mnemonics 'XIC' and 'OTE'."""
        bad_xic = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nXIC BedOverheatWarning\nEND_PROGRAM"
        bad_ote = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nOTE QuenchShotActive\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_xic)
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_ote)

    def test_verify_cumene_reactor_pure_st_helpers(self) -> None:
        """Verify helper validation functions return True and success."""
        assert verify_cumene_reactor_pure_st() is True
        assert verify_cumene_pure_st() is True
        val = validate_pure_st()
        assert val.status == AgentStatus.SUCCESS

    def test_pou_string_constants_aliases(self) -> None:
        """Verify POU string constants and aliases."""
        assert CUMENE_REACTOR_SYNC_POU == CUMENE_REACTOR_PURE_ST_POU
        assert CUMENE_PURE_ST_POU == CUMENE_REACTOR_PURE_ST_POU
        assert CUMENE_SYNC_POU == CUMENE_REACTOR_PURE_ST_POU


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Execution & Simulation Engine Integration
# ============================================================================

class TestSection11ILogicUnitIntegration:
    """Tests for ILogicUnit scan cycle execution and ScanContext integration."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify ILogicUnit interface properties: name, priority, is_enabled."""
        sim = CumeneReactor()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "CumeneReactorSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_return_dictionary(self) -> None:
        """Verify scan_step(0.05) returns dictionary with all telemetry keys."""
        sim = CumeneReactor()
        out = sim.scan_step(dt=0.05)
        assert isinstance(out, dict)
        assert out["status"] == "success"
        assert "bed_inlet_temp_celsius" in out
        assert "bed_peak_temp_celsius" in out
        assert "benzene_propylene_ratio" in out
        assert "propylene_conversion_pct" in out
        assert "cumene_selectivity_pct" in out
        assert "dipb_fraction_pct" in out
        assert "transalkylation_conversion_pct" in out
        assert "reactor_pressure_bar" in out
        assert "diagnostic_code" in out
        assert "bed_overheat_warning" in out
        assert "quench_shot_active" in out
        assert "transalkylation_in_spec" in out

    def test_execute_via_scan_context(self) -> None:
        """Verify execute() method updates state and registers using ScanContext."""
        reg = RegisterTable()
        sim = CumeneReactor(register_table=reg)
        ctx = ScanContext(
            cycle=1,
            dt_ms=50.0,
            elapsed_time_ms=50.0,
            get_register=lambda a: reg.read_word(a),
            set_register=lambda a, v: reg.write_word(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda n, d=None: d,
            set_variable=lambda n, v: None,
            record_fault=lambda f: None,
        )
        ctx.registers = reg
        sim.execute(ctx)
        assert reg.read_word("%R1580") > 0
        assert sim.state.scan_count == 1

    def test_adapter_logic_unit_cumene_logic_unit(self) -> None:
        """Verify CumeneReactorLogicUnit adapter class implements ILogicUnit."""
        reg = RegisterTable()
        unit = CumeneReactorLogicUnit(register_table=reg)
        assert isinstance(unit, ILogicUnit)
        assert unit.name == "CumeneReactorSync"
        assert unit.priority == 100
        assert unit.is_enabled is True
        ctx = ScanContext(
            cycle=1,
            dt_ms=50.0,
            elapsed_time_ms=50.0,
            get_register=lambda a: reg.read_word(a),
            set_register=lambda a, v: reg.write_word(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda n, d=None: d,
            set_variable=lambda n, v: None,
            record_fault=lambda f: None,
        )
        ctx.registers = reg
        unit.execute(ctx)
        assert reg.read_word("%R1581") > 0
        unit.reset()
        assert unit.simulator.state.sim_time_s == 0.0

    def test_100_continuous_scan_cycles(self) -> None:
        """Verify 100 consecutive scan steps execute deterministically without errors."""
        sim = CumeneReactor()
        for i in range(100):
            res = sim.scan_step(dt=0.05)
            assert res["status"] == "success"
        assert sim.state.scan_count == 100
        assert abs(sim.state.sim_time_s - 5.0) < 1e-4
        assert 210.0 <= sim.state.bed_peak_temp_celsius <= 260.0


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Suite & Runner Integration
# ============================================================================

class TestSection12VerificationSuite:
    """Tests for run_cumene_reactor_verification runner and 4-state contract."""

    def test_run_cumene_reactor_verification_deterministic_pass(self) -> None:
        """Verify that all 9 stages in run_cumene_reactor_verification pass cleanly."""
        res = run_cumene_reactor_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        data = res["data"]
        assert data["work_package"] == "W197"
        assert data["module"] == "cumene_reactor"
        assert data["total_checks"] == 9
        assert data["checks_passed"] == 9

        tests = data["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True

    def test_run_cumene_reactor_verification_stage_names(self) -> None:
        """Verify each of the 9 stages has expected descriptive checks."""
        res = run_cumene_reactor_verification()
        tests = res["data"]["tests"]
        expected_checks = [
            "Pure_ST_POU_AST_Parsing_And_Horner_Symbol_Bindings",
            "Anti_Ladder_Security_Guard_Interception",
            "Cumene_Alkylation_And_Transalkylation_Kinetics_And_Enthalpies",
            "Inter_Bed_Cold_Benzene_Quench_Dynamic_Cooling",
            "Coupled_6_State_ODE_System_RK4_Integration_Stability",
            "Stoichiometric_Mass_And_Enthalpy_Conservation_Residuals",
            "Process_Safety_Interlocks_And_Strict_Priority_Hierarchy",
            "Horner_OCS_Memory_Space_Integration",
            "Transalkylation_In_Spec_Logic_And_Disturbance_Recovery",
        ]
        for i, check in enumerate(expected_checks):
            assert tests[i]["check"] == check
            assert tests[i]["stage"] == i + 1

    def test_run_cumene_reactor_verification_json_export(self, tmp_path: Path) -> None:
        """Verify JSON export creates a valid evidence artifact matching output payload."""
        out_file = tmp_path / "cumene_evidence.json"
        res = run_cumene_reactor_verification(output_path=str(out_file))
        assert out_file.exists()
        assert out_file.stat().st_size > 0

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W197"
        assert data["data"]["checks_passed"] == 9

    def test_verification_aliases(self) -> None:
        """Verify function aliases for verification runner."""
        assert run_cumene_verification is run_cumene_reactor_verification

    def test_simulator_class_aliases(self) -> None:
        """Verify simulator class aliases."""
        assert CumeneSimulator is CumeneReactor
        assert CumeneReactorSimulator is CumeneReactor
        assert CumeneReactorEngine is CumeneReactor
        assert CumeneReactorModel is CumeneReactor
        assert CumeneReactorPlantModel is CumeneReactor
        assert CumeneReactorSimulationEngine is CumeneReactor
        assert CumeneLogicUnit is CumeneReactorLogicUnit
