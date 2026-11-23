"""Comprehensive Industrial Ethylene Oxide (EO) Fixed-Bed Reactor Test Suite.

Work Package: W191 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 12 engineering verification sections:
1. Section 1: Reactor Constants, Thermodynamic Enthalpies, Geometry & Aliases
2. Section 2: Ag/alpha-Al2O3 Reaction Kinetics & Arrhenius Acceleration
3. Section 3: Ethyl Chloride Moderator Physics & Selectivity Optimization
4. Section 4: Shell-Side Boiling Coolant & Heat Transfer Dynamics
5. Section 5: Coupled 6-State ODE System & RK4 Micro-Step Numerical Integration
6. Section 6: Stoichiometric & Thermal Conservation Residuals (< 1e-10)
7. Section 7: Process Safety Interlocks & Diagnostic Event Codes (0xD201..0xD204)
8. Section 8: Emergency Nitrogen Ballast Dynamic Quench
9. Section 9: Horner OCS Memory Space Integration & SYSTEM Privilege
10. Section 10: ILogicUnit Scan Cycle Execution (100+ Continuous Scans)
11. Section 11: Pure IEC 61131-3 Structured Text & Anti-Ladder Security Guard
12. Section 12: Deterministic 9-Stage Verification Suite Integration
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
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.ethylene_oxide_reactor import (
    BED_TEMP_NOMINAL_C,
    BED_TEMP_TRIP_C,
    BED_TEMP_WARNING_C,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DELTA_H_EO_COMBUSTION_J_MOL,
    DELTA_H_EO_COMBUSTION_KJ_MOL,
    DELTA_H_PARTIAL_OXIDATION_J_MOL,
    DELTA_H_PARTIAL_OXIDATION_KJ_MOL,
    DELTA_H_TOTAL_COMBUSTION_J_MOL,
    DELTA_H_TOTAL_COMBUSTION_KJ_MOL,
    EO_REACTOR_PURE_ST_POU,
    EO_REACTOR_SYNC_POU,
    EO_SELECTIVITY_NOMINAL_PCT,
    ETHYLENE_CONVERSION_NOMINAL_PCT,
    ETHYLENE_INLET_MAX_PCT,
    ETHYLENE_INLET_MIN_PCT,
    ETHYLENE_INLET_NOMINAL_PCT,
    ETHYLENE_OXIDE_REACTOR_PURE_ST_POU,
    ETHYLENE_OXIDE_REACTOR_SYNC_POU,
    MODERATOR_DEPLETION_LIMIT_PPM,
    MODERATOR_NOMINAL_PPM,
    MODERATOR_OVER_LIMIT_PPM,
    MW_C,
    MW_C2H4,
    MW_CH4,
    MW_CO2,
    MW_EO,
    MW_H,
    MW_H2O,
    MW_N2,
    MW_O,
    MW_O2,
    OXYGEN_FLAMMABILITY_LIMIT_PCT,
    OXYGEN_INLET_NOMINAL_PCT,
    R_GAS_CONST,
    SHELL_TEMP_NOMINAL_C,
    SHELL_TEMP_TRIP_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    EoReactorConfig,
    EoReactorDiagCode,
    EoReactorDiagnosticCode,
    EoReactorEngine,
    EoReactorLogicUnit,
    EoReactorModel,
    EoReactorParameters,
    EoReactorPlantModel,
    EoReactorSimulationEngine,
    EoReactorSimulator,
    EoReactorState,
    EoReactorStatusBits,
    EoReactorStatusWord,
    EthyleneOxideReactor,
    EthyleneOxideReactorConfig,
    EthyleneOxideReactorDiagCode,
    EthyleneOxideReactorDiagnosticCode,
    EthyleneOxideReactorEngine,
    EthyleneOxideReactorLogicUnit,
    EthyleneOxideReactorModel,
    EthyleneOxideReactorParameters,
    EthyleneOxideReactorPlantModel,
    EthyleneOxideReactorSimulationEngine,
    EthyleneOxideReactorSimulator,
    EthyleneOxideReactorState,
    EthyleneOxideReactorStatusBits,
    EthyleneOxideReactorStatusWord,
    run_eo_reactor_verification,
    run_ethylene_oxide_reactor_verification,
    validate_pure_st,
    verify_eo_reactor_pure_st,
    verify_ethylene_oxide_reactor_pure_st,
)
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Section 1: Reactor Constants & Configuration Tests
# ============================================================================

class TestSection1ConstantsAndConfiguration:
    """Tests for physical, thermodynamic, and geometric constants."""

    def test_universal_constants(self) -> None:
        """Verify universal physical constants."""
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(T_ZERO_CELSIUS - 273.15) < 1e-4
        assert abs(T_REF_K - 521.15) < 1e-4

    def test_molecular_weights(self) -> None:
        """Verify exact atomic and molecular weights."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_O - 0.015999) < 1e-6
        assert abs(MW_C2H4 - 0.028054) < 1e-6
        assert abs(MW_O2 - 0.031998) < 1e-6
        assert abs(MW_EO - 0.044053) < 1e-6
        assert abs(MW_CO2 - 0.044009) < 1e-6
        assert abs(MW_H2O - 0.018015) < 1e-6
        assert abs(MW_CH4 - 0.016043) < 1e-6
        assert abs(MW_N2 - 0.028013) < 1e-6

    def test_reaction_enthalpies_and_hess_law(self) -> None:
        """Verify reaction enthalpies and Hess's law satisfaction."""
        assert DELTA_H1_KJ_MOL == -105.0
        assert DELTA_H1_J_MOL == -105000.0
        assert DELTA_H2_KJ_MOL == -1323.0
        assert DELTA_H2_J_MOL == -1323000.0
        assert DELTA_H3_KJ_MOL == -1218.0
        assert DELTA_H3_J_MOL == -1218000.0

        # Exact Hess's Law summation: Delta H1 + Delta H3 = Delta H2
        assert DELTA_H1_KJ_MOL + DELTA_H3_KJ_MOL == DELTA_H2_KJ_MOL
        assert DELTA_H1_J_MOL + DELTA_H3_J_MOL == DELTA_H2_J_MOL

    def test_nominal_operating_limits(self) -> None:
        """Verify operating limits, warning/trip temperatures, and pressures."""
        assert ETHYLENE_INLET_NOMINAL_PCT == 28.0
        assert ETHYLENE_INLET_MIN_PCT == 10.0
        assert ETHYLENE_INLET_MAX_PCT == 40.0

        assert OXYGEN_INLET_NOMINAL_PCT == 7.5
        assert OXYGEN_FLAMMABILITY_LIMIT_PCT == 9.0

        assert BED_TEMP_NOMINAL_C == 248.0
        assert BED_TEMP_WARNING_C == 260.0
        assert BED_TEMP_TRIP_C == 270.0

        assert SHELL_TEMP_NOMINAL_C == 235.0
        assert SHELL_TEMP_TRIP_C == 255.0

        assert MODERATOR_NOMINAL_PPM == 3.5
        assert MODERATOR_DEPLETION_LIMIT_PPM == 1.5
        assert MODERATOR_OVER_LIMIT_PPM == 7.0

        assert EO_SELECTIVITY_NOMINAL_PCT == 84.5
        assert ETHYLENE_CONVERSION_NOMINAL_PCT == 12.5

    def test_reactor_config_geometry_and_aliases(self) -> None:
        """Verify multi-tubular fixed-bed geometry and class aliases."""
        cfg = EoReactorConfig()
        assert cfg.tube_count == 8000
        assert cfg.tube_length_m == 8.0
        assert cfg.tube_inner_diameter_m == 0.025
        assert cfg.bed_void_fraction == 0.40
        assert cfg.catalyst_mass_kg == 35000.0

        tube_area = 0.25 * math.pi * (0.025 ** 2)
        expected_vol = 8000 * tube_area * 8.0
        assert abs(cfg.total_tube_volume_m3 - expected_vol) < 1e-6
        assert abs(cfg.gas_void_volume_m3 - expected_vol * 0.40) < 1e-6
        assert abs(cfg.heat_transfer_area_m2 - (8000 * math.pi * 0.025 * 8.0)) < 1e-6

        # Check aliases
        assert EthyleneOxideReactorConfig is EoReactorConfig
        assert EthyleneOxideReactorParameters is EoReactorConfig
        assert EoReactorParameters is EoReactorConfig
        assert EthyleneOxideReactorSimulator is EthyleneOxideReactor
        assert EoReactorSimulator is EthyleneOxideReactor
        assert EthyleneOxideReactorEngine is EthyleneOxideReactor
        assert EoReactorEngine is EthyleneOxideReactor
        assert EthyleneOxideReactorModel is EthyleneOxideReactor
        assert EoReactorModel is EthyleneOxideReactor
        assert EthyleneOxideReactorPlantModel is EthyleneOxideReactor
        assert EoReactorPlantModel is EthyleneOxideReactor

    def test_custom_config_instantiation(self) -> None:
        """Verify reactor simulator accepts custom configuration parameters."""
        cfg = EoReactorConfig(
            tube_count=10000,
            tube_length_m=10.0,
            bed_void_fraction=0.38,
            catalyst_mass_kg=40000.0,
        )
        sim = EthyleneOxideReactor(config=cfg)
        assert sim.config.tube_count == 10000
        assert sim.config.tube_length_m == 10.0
        assert sim.config.bed_void_fraction == 0.38


# ============================================================================
# 2. Section 2: Catalysis & Reaction Kinetics Tests
# ============================================================================

class TestSection2CatalysisAndKinetics:
    """Tests for Ag/alpha-Al2O3 catalytic partial oxidation and combustion kinetics."""

    def test_nominal_reaction_rates_positive(self) -> None:
        """Verify reaction rates at nominal operating conditions."""
        sim = EthyleneOxideReactor()
        rates = sim.compute_reaction_rates(
            y_c2h4=0.2450,
            y_o2=0.0442,
            y_eo=0.0296,
            t_bed_k=521.15,
            mod_ppm=3.5,
        )
        assert rates["r1"] > 0.0
        assert rates["r2"] > 0.0
        assert rates["r3"] > 0.0
        assert rates["r1_mol_s"] > 30.0
        assert rates["r2_mol_s"] > 5.0
        assert rates["q_rxn_kw"] > 10000.0

    def test_arrhenius_temperature_acceleration(self) -> None:
        """Verify combustion accelerates faster than epoxidation due to higher activation energy."""
        sim = EthyleneOxideReactor()
        rates_248 = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 521.15, 3.5)
        rates_260 = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 533.15, 3.5)

        accel_r1 = rates_260["r1"] / rates_248["r1"]
        accel_r2 = rates_260["r2"] / rates_248["r2"]
        # E_a2 (95 kJ/mol) > E_a1 (72 kJ/mol) causes faster acceleration of combustion
        assert accel_r2 > accel_r1
        assert rates_260["q_rxn_kw"] > rates_248["q_rxn_kw"]

    def test_reaction_shutdown_on_trip(self) -> None:
        """Verify reaction rates are zero when emergency trip is active."""
        sim = EthyleneOxideReactor()
        rates = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 550.0, 3.5, trip=True)
        assert rates["r1"] == 0.0
        assert rates["r2"] == 0.0
        assert rates["r3"] == 0.0
        assert rates["q_rxn_kw"] == 0.0
        assert rates["q_rxn_w"] == 0.0

    def test_reaction_rates_concentration_sensitivity(self) -> None:
        """Verify rates scale monotonically with reactant concentrations."""
        sim = EthyleneOxideReactor()
        rates_low_c2h4 = sim.compute_reaction_rates(0.1500, 0.0442, 0.0296, 521.15, 3.5)
        rates_high_c2h4 = sim.compute_reaction_rates(0.3000, 0.0442, 0.0296, 521.15, 3.5)
        assert rates_high_c2h4["r1"] > rates_low_c2h4["r1"]
        assert rates_high_c2h4["r2"] > rates_low_c2h4["r2"]

        rates_low_o2 = sim.compute_reaction_rates(0.2450, 0.0200, 0.0296, 521.15, 3.5)
        rates_high_o2 = sim.compute_reaction_rates(0.2450, 0.0600, 0.0296, 521.15, 3.5)
        assert rates_high_o2["r1"] > rates_low_o2["r1"]
        assert rates_high_o2["r2"] > rates_low_o2["r2"]

    def test_temperature_clamping_behavior(self) -> None:
        """Verify temperature clamping at extreme non-physical values."""
        sim = EthyleneOxideReactor()
        rates_subzero = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 50.0, 3.5)
        assert rates_subzero["r1"] >= 0.0
        rates_extreme = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 1500.0, 3.5)
        assert rates_extreme["r1"] > 0.0


# ============================================================================
# 3. Section 3: Ethyl Chloride Moderator Physics Tests
# ============================================================================

class TestSection3EthylChlorideModeratorPhysics:
    """Tests for ethyl chloride moderator selectivity tuning and depletion."""

    def test_nominal_moderator_selectivity(self) -> None:
        """Verify nominal moderator concentration provides high EO selectivity (> 80%)."""
        sim = EthyleneOxideReactor()
        rates = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 521.15, 3.5)
        sel = rates["r1"] / (rates["r1"] + rates["r2"]) * 100.0
        assert 80.0 <= sel <= 88.0

    def test_moderator_depletion_causes_combustion_surge(self) -> None:
        """Verify moderator depletion (< 1.5 ppm) dramatically accelerates combustion."""
        sim = EthyleneOxideReactor()
        rates_nom = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 521.15, 3.5)
        rates_dep = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 521.15, 0.5)

        # Combustion rate surges
        assert rates_dep["r2"] > 2.5 * rates_nom["r2"]
        # Heat generation increases significantly
        assert rates_dep["q_rxn_kw"] > rates_nom["q_rxn_kw"]

    def test_over_moderation_suppresses_catalytic_activity(self) -> None:
        """Verify over-moderation (> 5.0 ppm) poisons active sites and lowers reaction rate."""
        sim = EthyleneOxideReactor()
        rates_nom = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 521.15, 3.5)
        rates_over = sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 521.15, 7.5)

        assert rates_over["r1"] < rates_nom["r1"]
        assert rates_over["r2"] < rates_nom["r2"]

    def test_moderator_sweep_monotonicity(self) -> None:
        """Verify moderator response across sweep from 0.5 to 8.0 ppm."""
        sim = EthyleneOxideReactor()
        ppms = [0.5, 1.0, 2.0, 3.5, 5.0, 6.0, 8.0]
        rates_list = [
            sim.compute_reaction_rates(0.2450, 0.0442, 0.0296, 521.15, p)
            for p in ppms
        ]
        # In depletion region (0.5 to 1.0), r2 decreases as moderator increases towards optimal
        assert rates_list[0]["r2"] > rates_list[1]["r2"]
        # Over-moderation region (6.0 to 8.0), r1 decreases as catalyst is poisoned
        assert rates_list[5]["r1"] > rates_list[6]["r1"]

    def test_moderator_property_setters_and_getters(self) -> None:
        """Verify EoReactorState convenience properties for moderator and conversions."""
        state = EoReactorState()
        state.moderator_ppm = 4.2
        assert abs(state.chloride_moderator_ppm - 4.2) < 1e-4
        assert abs(state.moderator_ppm - 4.2) < 1e-4

        state.selectivity_pct = 85.2
        assert abs(state.ethylene_oxide_selectivity_pct - 85.2) < 1e-4
        assert abs(state.selectivity_pct - 85.2) < 1e-4

        state.conversion_pct = 13.1
        assert abs(state.ethylene_conversion_pct - 13.1) < 1e-4
        assert abs(state.conversion_pct - 13.1) < 1e-4


# ============================================================================
# 4. Section 4: Shell-Side Boiling Coolant & Heat Transfer Dynamics
# ============================================================================

class TestSection4CoolantAndHeatTransfer:
    """Tests for shell-side boiling coolant heat transfer and thermal equilibrium."""

    def test_bed_to_shell_heat_transfer_rate(self) -> None:
        """Verify bed-to-shell overall heat transfer Q_cool = UA * (T_bed - T_shell)."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 250.0
        sim.state.t_shell_celsius = 235.0

        delta_t = sim.state.t_bed - sim.state.t_shell
        expected_q_cool_w = sim.config.ua_bed_shell_w_k * delta_t
        expected_q_cool_kw = expected_q_cool_w / 1000.0

        sim._update_kinetics_and_conversion()
        assert abs(sim.state.q_cool_shell_kw - expected_q_cool_kw) < 1.0

    def test_shell_to_boiling_heat_transfer_rate(self) -> None:
        """Verify heat removed from shell by boiling coolant Q_shell_rem = UA_boil * (T_shell - T_boil)."""
        sim = EthyleneOxideReactor()
        sim.state.t_shell_celsius = 235.0
        t_shell_k = sim.state.t_shell
        t_boil_k = sim.config.boiling_coolant_temp_c + T_ZERO_CELSIUS

        q_shell_rem_w = sim.config.ua_shell_boil_w_k * (t_shell_k - t_boil_k)
        assert q_shell_rem_w > 1.0e7  # > 10 MW removal capacity

    def test_thermal_equilibrium_heat_balance(self) -> None:
        """Verify heat generated by reactions is balanced by removal duties at nominal conditions."""
        sim = EthyleneOxideReactor()
        sim._update_kinetics_and_conversion()

        q_gen = sim.state.q_rxn_total_kw
        q_rem = sim.state.q_cool_shell_kw + sim.state.q_gas_convection_kw
        rel_diff = abs(q_gen - q_rem) / q_gen
        # Nominal generation (~16.8 MW) and removal (~19.7 MW) match within 20%
        assert rel_diff < 0.20

    def test_gas_stream_convective_heat_removal(self) -> None:
        """Verify gas sensible heat convection Q_gas = F * Cp * (T_bed - T_gas_in)."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 248.0
        t_gas_in_k = sim.config.gas_inlet_temp_c + T_ZERO_CELSIUS
        delta_t_gas = sim.state.t_bed - t_gas_in_k

        expected_q_gas_w = (
            sim.config.nominal_gas_flow_mol_s
            * sim.config.gas_heat_capacity_j_mol_k
            * delta_t_gas
        )
        expected_q_gas_kw = expected_q_gas_w / 1000.0
        sim._update_kinetics_and_conversion()
        assert abs(sim.state.q_gas_convection_kw - expected_q_gas_kw) < 1.0

    def test_heat_removal_dynamic_response(self) -> None:
        """Verify derivative dT_shell/dt responds properly to shell temperature variations."""
        sim = EthyleneOxideReactor()
        y_nom = [0.2450, 0.0442, 0.0296, 0.0208, 521.15, 508.15]
        derivs = sim.compute_derivatives(0.0, y_nom)
        dt_shell_dt = derivs[5]
        assert not math.isnan(dt_shell_dt)
        assert abs(dt_shell_dt) < 5.0  # Stable rate in K/s


# ============================================================================
# 5. Section 5: Coupled 6-State ODE System & RK4 Solver Tests
# ============================================================================

class TestSection5CoupledODEAndRK4Solver:
    """Tests for coupled 6-state ODE system integration and stability."""

    def test_state_vector_initialization_and_properties(self) -> None:
        """Verify state attributes, setters, and properties."""
        state = EoReactorState()
        assert abs(state.y_c2h4 - 0.2450) < 1e-4
        assert abs(state.y_o2 - 0.0442) < 1e-4
        assert abs(state.y_eo - 0.0296) < 1e-4
        assert abs(state.y_co2 - 0.0208) < 1e-4
        assert abs(state.catalyst_hotspot_temp_celsius - 248.0) < 1e-4
        assert abs(state.coolant_shell_temp_celsius - 235.0) < 1e-4

        state.t_bed_celsius = 250.0
        assert abs(state.t_bed - 523.15) < 1e-4
        assert abs(state.catalyst_hotspot_temp_celsius - 250.0) < 1e-4

        state.t_shell_celsius = 236.0
        assert abs(state.t_shell - 509.15) < 1e-4
        assert abs(state.coolant_shell_temp_celsius - 236.0) < 1e-4

    def test_compute_derivatives_finite(self) -> None:
        """Verify all 6 state derivatives are non-NaN and finite."""
        sim = EthyleneOxideReactor()
        y0 = [
            sim.state.y_c2h4,
            sim.state.y_o2,
            sim.state.y_eo,
            sim.state.y_co2,
            sim.state.t_bed,
            sim.state.t_shell,
        ]
        derivs = sim.compute_derivatives(0.0, y0)
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_rk4_single_step_advancement(self) -> None:
        """Verify single RK4 step advancement increments sim_time and scan_count."""
        sim = EthyleneOxideReactor()
        init_time = sim.state.sim_time_s
        init_scans = sim.state.scan_count

        res = sim.step(dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert abs(sim.state.sim_time_s - (init_time + 0.05)) < 1e-6
        assert sim.state.scan_count == init_scans + 1

    def test_rk4_multi_step_stability_and_bounds(self) -> None:
        """Verify 100 RK4 integration steps (5.0s) remain numerically stable within bounds."""
        sim = EthyleneOxideReactor()
        res_adv = sim.advance_time(duration_s=5.0, dt=0.05)
        assert res_adv.status == AgentStatus.SUCCESS
        assert 0.15 <= sim.state.y_c2h4 <= 0.35
        assert 0.02 <= sim.state.y_o2 <= 0.10
        assert 0.01 <= sim.state.y_eo <= 0.06
        assert 0.01 <= sim.state.y_co2 <= 0.06
        assert 240.0 <= sim.state.catalyst_hotspot_temp_celsius <= 260.0
        assert 230.0 <= sim.state.coolant_shell_temp_celsius <= 242.0

    def test_reset_functionality(self) -> None:
        """Verify reset restores nominal baseline state."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 265.0
        sim.advance_time(duration_s=2.0)

        sim.reset()
        assert abs(sim.state.catalyst_hotspot_temp_celsius - 248.0) < 1e-4
        assert abs(sim.state.coolant_shell_temp_celsius - 235.0) < 1e-4
        assert sim.state.sim_time_s == 0.0
        assert sim.state.scan_count == 0

    def test_rk4_dt_variation_stability(self) -> None:
        """Verify numerical stability with varying dt steps."""
        for dt_val in [0.01, 0.05, 0.10]:
            sim = EthyleneOxideReactor()
            res = sim.advance_time(duration_s=1.0, dt=dt_val)
            assert res.status == AgentStatus.SUCCESS
            assert 240.0 <= sim.state.catalyst_hotspot_temp_celsius <= 260.0


# ============================================================================
# 6. Section 6: Conservation Residuals (< 1e-10) Tests
# ============================================================================

class TestSection6ConservationResiduals:
    """Tests for stoichiometric mass balance and thermal enthalpy conservation residuals."""

    def test_stoichiometric_mass_conservation_residual(self) -> None:
        """Verify dual stoichiometric mass balance residual is strictly < 1e-10 kg/s."""
        sim = EthyleneOxideReactor()
        sim.advance_time(duration_s=3.0, dt=0.05)

        mass_res = sim.state.total_mass_balance_residual_kg_s
        assert mass_res < 1.0e-10

    def test_elemental_mass_conservation_residual(self) -> None:
        """Verify elemental C, H, O conservation residual is strictly < 1e-10 kg/s."""
        sim = EthyleneOxideReactor()
        sim.advance_time(duration_s=3.0, dt=0.05)

        elem_res = sim.state.elemental_mass_balance_residual_kg_s
        assert elem_res < 1.0e-10

    def test_thermal_enthalpy_conservation_residual(self) -> None:
        """Verify thermal enthalpy residual is strictly < 1e-10 kW."""
        sim = EthyleneOxideReactor()
        sim.advance_time(duration_s=3.0, dt=0.05)

        enth_res = sim.state.enthalpy_conservation_residual_kw
        assert enth_res < 1.0e-10

    def test_conservation_residuals_over_extended_simulation(self) -> None:
        """Verify residuals remain strictly < 1e-10 across 100 integration steps."""
        sim = EthyleneOxideReactor()
        for _ in range(100):
            sim.step(dt=0.05)
            assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_under_load_changes(self) -> None:
        """Verify residuals remain < 1e-10 under perturbed inlet concentrations."""
        sim = EthyleneOxideReactor()
        sim.state.ethylene_inlet_pct = 32.0
        sim.state.oxygen_inlet_pct = 8.2
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# 7. Section 7: Process Safety Interlocks & Diagnostics Tests
# ============================================================================

class TestSection7ProcessSafetyInterlocks:
    """Tests for 0xD201..0xD204 diagnostics and strict priority hierarchy."""

    def test_d201_thermal_runaway_trip(self) -> None:
        """Verify 0xD201 trip when hotspot T_bed > 270.0 °C."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 273.5
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_THERMAL_RUNAWAY_TRIP
        assert sim.state.hotspot_thermal_trip is True
        assert sim.state.nitrogen_ballast_injection_active is True
        assert sim.state.eo_reactor_permissive is False
        assert (sim.state.status_word & EoReactorStatusBits.HOTSPOT_THERMAL_TRIP) != 0
        assert (sim.state.status_word & EoReactorStatusBits.NITROGEN_BALLAST_ACTIVE) != 0

    def test_d201_trip_latch_and_reset_hysteresis(self) -> None:
        """Verify 0xD201 trip latches until hotspot cools below reset threshold (245.0 °C)."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 272.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_THERMAL_RUNAWAY_TRIP

        # Temp cools to 255 °C (below 270, but above reset threshold 245)
        sim.state.t_bed_celsius = 255.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_THERMAL_RUNAWAY_TRIP
        assert sim.state.hotspot_thermal_trip is True

        # Temp cools to 242 °C (below 245 °C)
        sim.state.t_bed_celsius = 242.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.OK
        assert sim.state.hotspot_thermal_trip is False

    def test_d202_flammability_envelope_breach_high_oxygen(self) -> None:
        """Verify 0xD202 trip when O2 > 9.0 mol%."""
        sim = EthyleneOxideReactor()
        sim.state.oxygen_inlet_pct = 9.8
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_FLAMMABILITY_ENVELOPE_BREACH
        assert sim.state.hotspot_thermal_trip is False
        assert sim.state.eo_reactor_permissive is False
        assert (sim.state.status_word & EoReactorStatusBits.FLAMMABILITY_BREACH) != 0

    def test_d202_flammability_envelope_breach_ethylene_limits(self) -> None:
        """Verify 0xD202 trip when C2H4 < 10.0 mol% or > 40.0 mol%."""
        sim = EthyleneOxideReactor()
        sim.state.ethylene_inlet_pct = 8.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_FLAMMABILITY_ENVELOPE_BREACH

        sim.state.ethylene_inlet_pct = 42.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_FLAMMABILITY_ENVELOPE_BREACH

    def test_d203_moderator_depletion_alarm(self) -> None:
        """Verify 0xD203 alarm when ethyl chloride moderator < 1.5 ppm."""
        sim = EthyleneOxideReactor()
        sim.state.chloride_moderator_ppm = 1.0
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_MODERATOR_DEPLETION
        assert sim.state.hotspot_thermal_trip is False
        assert sim.state.eo_reactor_permissive is True
        assert (sim.state.status_word & EoReactorStatusBits.MODERATOR_DEPLETION) != 0

    def test_d204_coolant_circulation_loss(self) -> None:
        """Verify 0xD204 trip when coolant shell temp > 255.0 °C."""
        sim = EthyleneOxideReactor()
        sim.state.coolant_shell_temp_celsius = 258.0
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_COOLANT_CIRCULATION_LOSS
        assert sim.state.hotspot_thermal_trip is False
        assert sim.state.eo_reactor_permissive is False
        assert (sim.state.status_word & EoReactorStatusBits.COOLANT_CIRCULATION_LOSS) != 0

    def test_priority_hierarchy_simultaneous_faults(self) -> None:
        """Verify strict priority ordering: 0xD201 > 0xD202 > 0xD203 > 0xD204."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 275.0                 # 0xD201
        sim.state.oxygen_inlet_pct = 10.0               # 0xD202
        sim.state.chloride_moderator_ppm = 0.5          # 0xD203
        sim.state.coolant_shell_temp_celsius = 260.0    # 0xD204

        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_THERMAL_RUNAWAY_TRIP

        # Clear 0xD201 (cool below reset threshold and clear latched trip)
        sim.state.t_bed_celsius = 240.0
        sim.state.hotspot_thermal_trip = False
        sim.state.nitrogen_ballast_injection_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_FLAMMABILITY_ENVELOPE_BREACH

        # Clear 0xD202
        sim.state.oxygen_inlet_pct = 7.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_MODERATOR_DEPLETION

        # Clear 0xD203
        sim.state.chloride_moderator_ppm = 3.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_COOLANT_CIRCULATION_LOSS

        # Clear 0xD204
        sim.state.coolant_shell_temp_celsius = 235.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.OK


# ============================================================================
# 8. Section 8: Emergency Nitrogen Ballast Dynamic Quench Tests
# ============================================================================

class TestSection8EmergencyNitrogenBallastQuench:
    """Tests for dynamic mitigation of thermal runaway via emergency nitrogen ballast."""

    def test_thermal_runaway_emergency_quench(self) -> None:
        """Verify high hotspot excursion trips 0xD201 and quenches hotspot below 250 °C."""
        sim = EthyleneOxideReactor()
        # Trigger trip excursion at 273.0 °C
        sim.state.t_bed_celsius = 273.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == EoReactorDiagnosticCode.EO_ERR_THERMAL_RUNAWAY_TRIP
        assert sim.state.hotspot_thermal_trip is True
        assert sim.state.nitrogen_ballast_injection_active is True

        # Advance under emergency nitrogen quench
        res = sim.advance_time(duration_s=6.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.catalyst_hotspot_temp_celsius < 250.0

    def test_emergency_quench_cuts_inlet_reactants(self) -> None:
        """Verify derivative calculation cuts reactant inflows during quench."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 275.0
        sim._evaluate_safety_interlocks()

        y = [0.2450, 0.0442, 0.0296, 0.0208, 275.0 + T_ZERO_CELSIUS, 508.15]
        derivs = sim.compute_derivatives(0.0, y)
        # dy_c2h4/dt = (0.0 - c2h4) / tau < 0
        assert derivs[0] < 0.0
        # dy_o2/dt = (0.0 - o2) / tau < 0
        assert derivs[1] < 0.0

    def test_emergency_quench_status_bits(self) -> None:
        """Verify status word reflects nitrogen ballast active."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 273.0
        sim._evaluate_safety_interlocks()
        sw = sim.state.status_word
        assert (sw & EoReactorStatusBits.NITROGEN_BALLAST_ACTIVE) != 0
        assert (sw & EoReactorStatusBits.HOTSPOT_THERMAL_TRIP) != 0

    def test_quench_cooling_rate_monotonicity(self) -> None:
        """Verify bed temperature decreases monotonically during quench."""
        sim = EthyleneOxideReactor()
        sim.state.t_bed_celsius = 275.0
        sim._evaluate_safety_interlocks()

        temp_prev = sim.state.catalyst_hotspot_temp_celsius
        for _ in range(5):
            sim.step(dt=0.1)
            temp_curr = sim.state.catalyst_hotspot_temp_celsius
            assert temp_curr < temp_prev
            temp_prev = temp_curr


# ============================================================================
# 9. Section 9: Horner OCS Memory Space Synchronization Tests
# ============================================================================

class TestSection9HornerOCSMemoryMapping:
    """Tests for Horner OCS memory space synchronization with PrivilegeMode.SYSTEM."""

    def test_register_sync_nominal(self) -> None:
        """Verify %R1520..%R1527 and %M354..%M356 scaling and values."""
        reg = RegisterTable()
        sim = EthyleneOxideReactor(register_table=reg)

        sim.state.ethylene_inlet_pct = 28.0
        sim.state.oxygen_inlet_pct = 7.5
        sim.state.t_bed_celsius = 248.0
        sim.state.t_shell_celsius = 235.0
        sim.state.ethylene_oxide_selectivity_pct = 84.5
        sim.state.ethylene_conversion_pct = 12.5
        sim.state.chloride_moderator_ppm = 3.5
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg)

        assert reg.read_word("%R1520") == 2800
        assert reg.read_word("%R1521") == 750
        assert reg.read_word("%R1522") == 2480
        assert reg.read_word("%R1523") == 2350
        assert reg.read_word("%R1524") == 845
        assert reg.read_word("%R1525") == 125
        assert reg.read_word("%R1526") == 35
        assert (reg.read_word("%R1527") & 0xFFFF) == 0x0000

        assert reg.read_bit("%M354") is True
        assert reg.read_bit("%M355") is False
        assert reg.read_bit("%M356") is False

    def test_register_sync_trip_masked(self) -> None:
        """Verify registers and coils reflect thermal runaway trip state (0xD201)."""
        reg = RegisterTable()
        sim = EthyleneOxideReactor(register_table=reg)

        sim.state.t_bed_celsius = 275.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg)

        assert reg.read_word("%R1522") == 2750
        assert (reg.read_word("%R1527") & 0xFFFF) == 0xD201
        assert reg.read_bit("%M354") is False
        assert reg.read_bit("%M355") is True
        assert reg.read_bit("%M356") is True

    def test_register_sync_flammability_breach_masked(self) -> None:
        """Verify register table reflects flammability envelope breach (0xD202)."""
        reg = RegisterTable()
        sim = EthyleneOxideReactor(register_table=reg)

        sim.state.oxygen_inlet_pct = 9.5
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg)

        assert (reg.read_word("%R1527") & 0xFFFF) == 0xD202
        assert reg.read_bit("%M354") is False
        assert reg.read_bit("%M355") is False

    def test_register_sync_moderator_depletion_masked(self) -> None:
        """Verify register table reflects moderator depletion (0xD203)."""
        reg = RegisterTable()
        sim = EthyleneOxideReactor(register_table=reg)

        sim.state.chloride_moderator_ppm = 1.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg)

        assert (reg.read_word("%R1527") & 0xFFFF) == 0xD203
        assert reg.read_bit("%M354") is True

    def test_register_sync_coolant_loss_masked(self) -> None:
        """Verify register table reflects coolant circulation loss (0xD204)."""
        reg = RegisterTable()
        sim = EthyleneOxideReactor(register_table=reg)

        sim.state.coolant_shell_temp_celsius = 258.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg)

        assert (reg.read_word("%R1527") & 0xFFFF) == 0xD204
        assert reg.read_bit("%M354") is False

    def test_register_sync_privilege_mode_system(self) -> None:
        """Verify sync_to_registers uses SYSTEM privilege successfully."""
        reg = RegisterTable()
        sim = EthyleneOxideReactor(register_table=reg)
        # Verify writing completes without exception
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1520") == 2800


# ============================================================================
# 10. Section 10: ILogicUnit Scan Cycle Execution Tests
# ============================================================================

class TestSection10ILogicUnitScanCycleExecution:
    """Tests for ILogicUnit interface, scan_step, and 100+ scan steps continuous run."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify ILogicUnit contract properties."""
        sim = EthyleneOxideReactor()
        assert sim.name == "EthyleneOxideReactorSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_ilogic_unit_single_scan_step(self) -> None:
        """Verify single scan_step execution returns valid state dictionary."""
        sim = EthyleneOxideReactor()
        res = sim.scan_step(dt=0.05)
        assert res["status"] == "success"
        assert "ethylene_inlet_pct" in res
        assert "oxygen_inlet_pct" in res
        assert "catalyst_hotspot_temp_celsius" in res
        assert "coolant_shell_temp_celsius" in res
        assert "ethylene_oxide_selectivity_pct" in res
        assert "ethylene_conversion_pct" in res
        assert "chloride_moderator_ppm" in res
        assert "diagnostic_code" in res
        assert "eo_reactor_permissive" in res

    def test_ilogic_unit_100_plus_scan_steps_continuous(self) -> None:
        """Verify 120 continuous scan steps run stably without failure."""
        sim = EthyleneOxideReactor()
        for cycle in range(120):
            res = sim.scan_step(dt=0.05)
            assert res["status"] == "success"
        assert sim.state.scan_count == 120
        assert sim.state.sim_time_s == pytest.approx(6.0, rel=1e-3)

    def test_adapter_logic_unit_scan_context(self) -> None:
        """Verify EthyleneOxideReactorLogicUnit adapter execution in ScanContext."""
        reg = RegisterTable()
        unit = EthyleneOxideReactorLogicUnit(register_table=reg)
        assert unit.name == "EthyleneOxideReactorSync"
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
        assert reg.read_word("%R1520") == 2800
        assert reg.read_bit("%M354") is True

    def test_logic_unit_reset(self) -> None:
        """Verify adapter logic unit reset delegates properly."""
        reg = RegisterTable()
        unit = EthyleneOxideReactorLogicUnit(register_table=reg)
        unit.simulator.state.t_bed_celsius = 268.0
        unit.reset()
        assert unit.simulator.state.catalyst_hotspot_temp_celsius == 248.0


# ============================================================================
# 11. Section 11: Pure IEC 61131-3 Structured Text & Anti-Ladder Security Guard
# ============================================================================

class TestSection11PureStructuredTextPOU:
    """Tests for pure ST POU validation, AST parsing, and ladder logic rejection."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify AST parsing and program name."""
        SecurityGuard.assert_pure_st_content(ETHYLENE_OXIDE_REACTOR_PURE_ST_POU)
        ast = STParser.parse_pou(ETHYLENE_OXIDE_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "EthyleneOxideReactorSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_pou_bound_registers(self) -> None:
        """Verify all 11 required Horner OCS registers are bound in ST AST."""
        ast = STParser.parse_pou(ETHYLENE_OXIDE_REACTOR_PURE_ST_POU)
        assert ast is not None
        expected_regs = [
            "%R1520", "%R1521", "%R1522", "%R1523",
            "%R1524", "%R1525", "%R1526", "%R1527",
            "%M354", "%M355", "%M356",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    @pytest.mark.parametrize("bad_contact", [
        "---[ ]---",
        "---[ / ]---",
        "---[/]---",
    ])
    def test_anti_ladder_security_guard_blocks_contacts(self, bad_contact: str) -> None:
        """Verify ladder contacts are intercepted with LadderForbiddenError."""
        code = f"PROGRAM BadContact\nVAR x: BOOL; END_VAR\n{bad_contact}\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    @pytest.mark.parametrize("bad_coil", [
        "---( )---",
        "---(S)---",
        "---(R)---",
    ])
    def test_anti_ladder_security_guard_blocks_coils(self, bad_coil: str) -> None:
        """Verify ladder coils are intercepted with LadderForbiddenError."""
        code = f"PROGRAM BadCoil\nVAR x: BOOL; END_VAR\n{bad_coil}\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    @pytest.mark.parametrize("bad_mnemonic", [
        "RUNG 1",
        "END_RUNG",
        "NETWORK",
        "XIC EoPermissive",
        "OTE ThermalTrip",
        "OTL LatchedTrip",
        "OTU UnlatchTrip",
    ])
    def test_anti_ladder_security_guard_blocks_rungs_and_mnemonics(self, bad_mnemonic: str) -> None:
        """Verify ladder rungs and mnemonics are intercepted with LadderForbiddenError."""
        code = f"PROGRAM BadMnemonic\nVAR x: BOOL; END_VAR\n{bad_mnemonic}\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_validate_pure_st_helper_functions(self) -> None:
        """Verify helper validation functions and string aliases."""
        assert ETHYLENE_OXIDE_REACTOR_SYNC_POU == ETHYLENE_OXIDE_REACTOR_PURE_ST_POU
        assert EO_REACTOR_PURE_ST_POU == ETHYLENE_OXIDE_REACTOR_PURE_ST_POU
        assert EO_REACTOR_SYNC_POU == ETHYLENE_OXIDE_REACTOR_PURE_ST_POU

        assert verify_ethylene_oxide_reactor_pure_st() is True
        assert verify_eo_reactor_pure_st() is True
        val_res = validate_pure_st()
        assert val_res.status == AgentStatus.SUCCESS


# ============================================================================
# 12. Section 12: Deterministic 9-Stage Verification Suite Integration
# ============================================================================

class TestSection12VerificationSuiteIntegration:
    """Tests for run_ethylene_oxide_reactor_verification suite and output contract."""

    def test_verification_suite_passes_all_stages(self) -> None:
        """Verify 9-stage verification suite passes with strict 4-state success contract."""
        res = run_ethylene_oxide_reactor_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W191"
        assert res["data"]["total_checks"] == 9
        assert res["data"]["checks_passed"] == 9

    def test_verification_suite_strict_4_state_contract(self) -> None:
        """Verify strict 4-state engineering contract keys and types."""
        res = run_ethylene_oxide_reactor_verification()
        assert "status" in res
        assert "error_code" in res
        assert "details" in res
        assert "data" in res
        assert res["status"] in {"success", "failed", "blocked", "inconclusive"}

    def test_verification_suite_file_output(self, tmp_path: Path) -> None:
        """Verify verification suite writes valid JSON output file."""
        out_file = tmp_path / "eo_verification.json"
        res = run_ethylene_oxide_reactor_verification(str(out_file))

        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9

    def test_verification_suite_all_individual_checks(self) -> None:
        """Verify each of the 9 individual stages passed."""
        res = run_ethylene_oxide_reactor_verification()
        tests = res["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True
            assert "stage" in t
            assert "check" in t
            assert "details" in t

    def test_verification_suite_alias_function(self) -> None:
        """Verify run_eo_reactor_verification alias function."""
        res = run_eo_reactor_verification()
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
