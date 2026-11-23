"""Comprehensive Industrial Ethylene Glycol (EG) Hydration Reactor Test Suite.

Work Package: W221 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 13 engineering verification sections (65+ tests):
1. Section 1: Physical Constants, IUPAC Atomic Weights & Species Molecular Weights
2. Section 2: Reaction Enthalpies, Exothermicity & Hess's Law Stoichiometry
3. Section 3: Arrhenius Reaction Kinetics, Activation Energies & Temperature Acceleration
4. Section 4: Reactor Vessel Configuration, Geometry & Operating Envelope
5. Section 5: Water-to-EO Ratio Dynamics, MEG Selectivity (> 91.5%) & Byproducts
6. Section 6: Coupled 6-State ODE System & High-Order RK4 Numerical Integrator
7. Section 7: Mathematical Conservation Residuals (Mass, Elements, Enthalpy < 1e-10)
8. Section 8: Process Safety Interlocks & Strict Diagnostic Priority (0xED01..0xED04)
9. Section 9: Emergency Cold Water Deluge Dynamic Quench (> 220 °C or > 28 bar)
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R1820..%R1827, %M424..%M426)
11. Section 11: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
12. Section 12: ILogicUnit Scan Cycle Execution, Reset Dynamics & Soak Stability
13. Section 13: Deterministic 9-Stage Verification Suite & Artifact Generation
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

from jev_cscape.simulation.eg_hydration_reactor import (
    DEG_BYPRODUCT_NOMINAL_PCT,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    EG_HYDRATION_PURE_ST_POU,
    EG_HYDRATION_REACTOR_PURE_ST_POU,
    EG_HYDRATION_REACTOR_SYNC_POU,
    EG_HYDRATION_SYNC_POU,
    EO_CONVERSION_MIN_PCT,
    EO_CONVERSION_NOMINAL_PCT,
    MEG_PRODUCTION_NOMINAL_KG_H,
    MEG_SELECTIVITY_MIN_PCT,
    MEG_SELECTIVITY_NOMINAL_PCT,
    MW_C,
    MW_DEG,
    MW_DIETHYLENE_GLYCOL,
    MW_EO,
    MW_ETHYLENE_OXIDE,
    MW_H,
    MW_H2O,
    MW_MEG,
    MW_MONOETHYLENE_GLYCOL,
    MW_O,
    MW_TEG,
    MW_TRIETHYLENE_GLYCOL,
    MW_WATER,
    R_GAS_CONST,
    REACTOR_PRESSURE_MAX_BAR,
    REACTOR_PRESSURE_MIN_BAR,
    REACTOR_PRESSURE_NOMINAL_BAR,
    REACTOR_PRESSURE_TRIP_BAR,
    REACTOR_TEMP_MAX_C,
    REACTOR_TEMP_MIN_C,
    REACTOR_TEMP_NOMINAL_C,
    REACTOR_TEMP_TRIP_C,
    TEG_BYPRODUCT_NOMINAL_PCT,
    T_REF_K,
    T_ZERO_CELSIUS,
    WATER_EO_RATIO_MAX,
    WATER_EO_RATIO_MIN,
    WATER_EO_RATIO_NOMINAL,
    WATER_EO_RATIO_PREALARM,
    EgHydrationConfig,
    EgHydrationDiagCode,
    EgHydrationDiagnosticCode,
    EgHydrationEngine,
    EgHydrationLogicUnit,
    EgHydrationModel,
    EgHydrationParameters,
    EgHydrationPlantModel,
    EgHydrationReactor,
    EgHydrationReactorConfig,
    EgHydrationReactorDiagCode,
    EgHydrationReactorDiagnosticCode,
    EgHydrationReactorEngine,
    EgHydrationReactorLogicUnit,
    EgHydrationReactorModel,
    EgHydrationReactorParameters,
    EgHydrationReactorPlantModel,
    EgHydrationReactorSimulationEngine,
    EgHydrationReactorSimulator,
    EgHydrationReactorState,
    EgHydrationReactorStatusBits,
    EgHydrationReactorStatusWord,
    EgHydrationSimulationEngine,
    EgHydrationSimulator,
    EgHydrationState,
    EgHydrationStatusBits,
    EgHydrationStatusWord,
    run_eg_hydration_reactor_verification,
    run_eg_hydration_verification,
    validate_pure_st,
    verify_eg_hydration_pure_st,
    verify_eg_hydration_reactor_pure_st,
)


# ============================================================================
# Section 1: Physical Constants, IUPAC Atomic Weights & Molecular Weights
# ============================================================================

class TestSection1PhysicalConstantsAndMolecularWeights:
    """Tests for physical constants, atomic weights, and reactant/product molecular weights."""

    def test_gas_constant_and_reference_temperatures(self) -> None:
        """Verify universal gas constant and temperature conversion references."""
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(T_ZERO_CELSIUS - 273.15) < 1e-4
        assert abs(T_REF_K - 465.15) < 1e-4  # 192.0 °C nominal
        assert abs((REACTOR_TEMP_NOMINAL_C + T_ZERO_CELSIUS) - T_REF_K) < 1e-4

    def test_atomic_weights_iupac(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon, Hydrogen, and Oxygen."""
        assert abs(MW_C - 0.012011) < 1e-6  # 12.011 g/mol
        assert abs(MW_H - 0.001008) < 1e-6  # 1.008 g/mol
        assert abs(MW_O - 0.015999) < 1e-6  # 15.999 g/mol

    def test_ethylene_oxide_molecular_weight(self) -> None:
        """Verify molecular weight of Ethylene Oxide (EO, C2H4O): 44.053 g/mol (0.044053 kg/mol)."""
        expected = 2.0 * MW_C + 4.0 * MW_H + MW_O
        assert abs(MW_EO - expected) < 1e-8
        assert abs(MW_EO - 0.04405) < 1e-4
        assert abs(MW_ETHYLENE_OXIDE - MW_EO) < 1e-8

    def test_water_molecular_weight(self) -> None:
        """Verify molecular weight of Water (H2O): 18.015 g/mol (0.018015 kg/mol)."""
        expected = 2.0 * MW_H + MW_O
        assert abs(MW_H2O - expected) < 1e-8
        assert abs(MW_H2O - 0.01802) < 1e-4
        assert abs(MW_WATER - MW_H2O) < 1e-8

    def test_monoethylene_glycol_molecular_weight(self) -> None:
        """Verify molecular weight of MEG (C2H6O2): 62.068 g/mol (0.062068 kg/mol)."""
        expected = 2.0 * MW_C + 6.0 * MW_H + 2.0 * MW_O
        assert abs(MW_MEG - expected) < 1e-8
        assert abs(MW_MEG - 0.06207) < 1e-4
        assert abs(MW_MONOETHYLENE_GLYCOL - MW_MEG) < 1e-8

    def test_diethylene_glycol_molecular_weight(self) -> None:
        """Verify molecular weight of DEG (C4H10O3): 106.121 g/mol (0.106121 kg/mol)."""
        expected = 4.0 * MW_C + 10.0 * MW_H + 3.0 * MW_O
        assert abs(MW_DEG - expected) < 1e-8
        assert abs(MW_DEG - 0.10612) < 1e-4
        assert abs(MW_DIETHYLENE_GLYCOL - MW_DEG) < 1e-8

    def test_triethylene_glycol_molecular_weight(self) -> None:
        """Verify molecular weight of TEG (C6H14O4): 150.174 g/mol (0.150174 kg/mol)."""
        expected = 6.0 * MW_C + 14.0 * MW_H + 4.0 * MW_O
        assert abs(MW_TEG - expected) < 1e-8
        assert abs(MW_TEG - 0.15017) < 1e-4
        assert abs(MW_TRIETHYLENE_GLYCOL - MW_TEG) < 1e-8

    def test_molecular_weight_additive_relationships(self) -> None:
        """Verify additive relationships: MEG = EO + H2O, DEG = MEG + EO, TEG = DEG + EO."""
        assert abs((MW_EO + MW_H2O) - MW_MEG) < 1e-12
        assert abs((MW_MEG + MW_EO) - MW_DEG) < 1e-12
        assert abs((MW_DEG + MW_EO) - MW_TEG) < 1e-12


# ============================================================================
# Section 2: Reaction Enthalpies, Exothermicity & Hess's Law Stoichiometry
# ============================================================================

class TestSection2ThermodynamicEnthalpiesAndHessLaw:
    """Tests for reaction enthalpies, exothermicity, and exact stoichiometric mass balances."""

    def test_primary_hydration_enthalpy_delta_h1(self) -> None:
        """Verify primary hydration enthalpy Delta H1: -80.0 kJ/mol (-80,000 J/mol)."""
        assert DELTA_H1_KJ_MOL == -80.0
        assert DELTA_H1_J_MOL == -80000.0

    def test_secondary_etherification_enthalpy_delta_h2(self) -> None:
        """Verify secondary etherification enthalpy Delta H2: -78.0 kJ/mol (-78,000 J/mol)."""
        assert DELTA_H2_KJ_MOL == -78.0
        assert DELTA_H2_J_MOL == -78000.0

    def test_tertiary_etherification_enthalpy_delta_h3(self) -> None:
        """Verify tertiary etherification enthalpy Delta H3: -75.0 kJ/mol (-75,000 J/mol)."""
        assert DELTA_H3_KJ_MOL == -75.0
        assert DELTA_H3_J_MOL == -75000.0

    def test_exothermic_heat_release_all_negative(self) -> None:
        """Verify all three hydration/etherification reactions are exothermic (Delta H < 0)."""
        assert DELTA_H1_J_MOL < 0.0
        assert DELTA_H2_J_MOL < 0.0
        assert DELTA_H3_J_MOL < 0.0

    def test_stoichiometric_mass_balance_per_reaction(self) -> None:
        """Verify mass conservation across individual reaction stoichiometries."""
        # Reaction 1: EO + H2O -> MEG
        assert abs((MW_EO + MW_H2O) - MW_MEG) < 1e-12
        # Reaction 2: MEG + EO -> DEG
        assert abs((MW_MEG + MW_EO) - MW_DEG) < 1e-12
        # Reaction 3: DEG + EO -> TEG
        assert abs((MW_DEG + MW_EO) - MW_TEG) < 1e-12


# ============================================================================
# Section 3: Arrhenius Reaction Kinetics, Activation Energies & Rates
# ============================================================================

class TestSection3ArrheniusKinetics:
    """Tests for kinetic rate constants, activation energies, and temperature acceleration."""

    def test_arrhenius_activation_energies(self) -> None:
        """Verify activation energies: Ea1=75 kJ/mol, Ea2=80 kJ/mol, Ea3=85 kJ/mol."""
        cfg = EgHydrationConfig()
        assert cfg.activation_energy_1_j_mol == 75000.0
        assert cfg.activation_energy_2_j_mol == 80000.0
        assert cfg.activation_energy_3_j_mol == 85000.0

    def test_reference_rate_constants(self) -> None:
        """Verify rate constants at reference temperature (192.0 °C / 465.15 K)."""
        cfg = EgHydrationConfig()
        assert cfg.k1_ref == 7.53e-6
        assert cfg.k2_ref == 5.66e-6
        assert cfg.k3_ref == 1.49e-5

    def test_nominal_reaction_rates_positive(self) -> None:
        """Verify reaction rates and exotherm are strictly positive under nominal feed."""
        sim = EgHydrationReactor()
        rates = sim.compute_reaction_rates(
            c_eo=4.770,
            c_water=41933.44,
            c_meg=2192.36,
            c_deg=80.93,
            t_reactor_k=465.15,
        )
        assert rates["r1"] > 0.0
        assert rates["r2"] > 0.0
        assert rates["r3"] > 0.0
        assert rates["q_rxn_w"] > 0.0
        assert rates["q_rxn_kw"] > 0.0

    def test_reaction_rate_acceleration_with_temperature(self) -> None:
        """Verify reaction rates accelerate with increasing temperature."""
        sim = EgHydrationReactor()
        r_nominal = sim.compute_reaction_rates(4.770, 41933.44, 2192.36, 80.93, 465.15)
        r_elevated = sim.compute_reaction_rates(4.770, 41933.44, 2192.36, 80.93, 480.15)
        assert r_elevated["r1"] > r_nominal["r1"]
        assert r_elevated["r2"] > r_nominal["r2"]
        assert r_elevated["r3"] > r_nominal["r3"]
        assert r_elevated["q_rxn_kw"] > r_nominal["q_rxn_kw"]

    def test_side_etherification_accelerates_faster_than_primary_hydration(self) -> None:
        """Verify higher Ea of side reactions causes faster acceleration at high temp."""
        sim = EgHydrationReactor()
        r_nom = sim.compute_reaction_rates(4.770, 41933.44, 2192.36, 80.93, 465.15)
        r_hot = sim.compute_reaction_rates(4.770, 41933.44, 2192.36, 80.93, 485.15)
        ratio_r1 = r_hot["r1"] / r_nom["r1"]
        ratio_r2 = r_hot["r2"] / r_nom["r2"]
        ratio_r3 = r_hot["r3"] / r_nom["r3"]
        assert ratio_r2 > ratio_r1
        assert ratio_r3 > ratio_r1

    def test_reaction_rates_zero_when_tripped(self) -> None:
        """Verify reaction rates and heat release collapse to zero when is_tripped=True."""
        sim = EgHydrationReactor()
        rates = sim.compute_reaction_rates(4.770, 41933.44, 2192.36, 80.93, 465.15, is_tripped=True)
        assert rates["r1"] == 0.0
        assert rates["r2"] == 0.0
        assert rates["r3"] == 0.0
        assert rates["q_rxn_w"] == 0.0
        assert rates["q_rxn_kw"] == 0.0

    def test_reaction_rates_zero_at_zero_eo_concentration(self) -> None:
        """Verify reaction rates are zero when EO reactant concentration is zero."""
        sim = EgHydrationReactor()
        rates = sim.compute_reaction_rates(0.0, 41933.44, 2192.36, 80.93, 465.15)
        assert rates["r1"] == 0.0
        assert rates["r2"] == 0.0
        assert rates["r3"] == 0.0
        assert rates["q_rxn_kw"] == 0.0


# ============================================================================
# Section 4: Reactor Vessel Configuration, Geometry & Operating Envelope
# ============================================================================

class TestSection4ReactorConfigAndGeometry:
    """Tests for tubular reactor vessel dimensions, thermal properties, and operational envelope."""

    def test_default_config_geometry(self) -> None:
        """Verify tubular reactor geometry and volume."""
        cfg = EgHydrationConfig()
        assert cfg.reactor_volume_m3 == 1.50
        assert cfg.tube_length_m == 120.0
        assert cfg.tube_diameter_m == 0.126
        assert cfg.reactor_metal_mass_kg == 8500.0
        assert cfg.liquid_density_kg_m3 == 900.0
        assert cfg.total_fluid_mass_kg == 1.50 * 900.0  # 1350 kg

    def test_thermal_capacitance_liquid_and_metal(self) -> None:
        """Verify total thermal capacitance includes fluid and metal mass."""
        cfg = EgHydrationConfig()
        fluid_cap = cfg.total_fluid_mass_kg * cfg.liquid_heat_capacity_j_kg_k
        metal_cap = cfg.reactor_metal_mass_kg * cfg.metal_heat_capacity_j_kg_k
        expected = fluid_cap + metal_cap
        assert abs(cfg.total_thermal_capacitance_j_k - expected) < 1e-4

    def test_volumetric_flow_and_residence_time(self) -> None:
        """Verify nominal volumetric flow rate and mean liquid residence time."""
        cfg = EgHydrationConfig()
        assert cfg.nominal_total_feed_mass_flow_kg_s > 0.0
        assert cfg.nominal_volumetric_flow_m3_s > 0.0
        assert 1000.0 <= cfg.nominal_residence_time_s <= 2000.0

    def test_operating_temperature_and_pressure_boundaries(self) -> None:
        """Verify operating temperature and pressure envelope constants."""
        assert REACTOR_TEMP_NOMINAL_C == 192.0
        assert REACTOR_TEMP_MIN_C == 160.0
        assert REACTOR_TEMP_MAX_C == 200.0
        assert REACTOR_TEMP_TRIP_C == 220.0

        assert REACTOR_PRESSURE_NOMINAL_BAR == 22.00
        assert REACTOR_PRESSURE_MIN_BAR == 18.00
        assert REACTOR_PRESSURE_MAX_BAR == 25.00
        assert REACTOR_PRESSURE_TRIP_BAR == 28.00

    def test_config_and_parameters_aliases(self) -> None:
        """Verify class aliases point to canonical configuration."""
        assert EgHydrationReactorConfig is EgHydrationConfig
        assert EgHydrationParameters is EgHydrationConfig
        assert EgHydrationReactorParameters is EgHydrationConfig


# ============================================================================
# Section 5: Water-to-EO Ratio Dynamics, MEG Selectivity (> 91.5%) & Byproducts
# ============================================================================

class TestSection5WaterToEoRatioAndSelectivity:
    """Tests for water-to-EO molar ratio dynamics, MEG selectivity, and byproduct formation."""

    def test_nominal_water_eo_ratio_and_selectivity(self) -> None:
        """Verify nominal water:EO ratio is 18.5 and nominal MEG selectivity is 92.10% (> 91.5%)."""
        sim = EgHydrationReactor()
        assert sim.state.water_to_eo_feed_ratio == 18.5
        assert abs(sim.state.meg_selectivity_pct - 92.10) < 0.1
        assert sim.state.meg_selectivity_pct >= MEG_SELECTIVITY_MIN_PCT
        assert MEG_SELECTIVITY_MIN_PCT == 91.50

    def test_water_ratio_operational_envelope(self) -> None:
        """Verify water-to-EO ratio envelope is 15.0 to 22.0."""
        assert WATER_EO_RATIO_MIN == 15.0
        assert WATER_EO_RATIO_NOMINAL == 18.5
        assert WATER_EO_RATIO_MAX == 22.0
        assert WATER_EO_RATIO_PREALARM == 14.0

    def test_water_starvation_reduces_meg_selectivity(self) -> None:
        """Verify low water-to-EO ratio reduces MEG selectivity and increases DEG/TEG."""
        sim = EgHydrationReactor()
        sim.state.water_to_eo_feed_ratio = 8.0
        sim.state.c_water = 18000.0
        sim.state.c_meg = 1800.0
        sim.state.c_deg = 280.0
        sim.state.c_teg = 45.0
        sim._update_kinetics_and_conversion()
        assert sim.state.meg_selectivity_pct < MEG_SELECTIVITY_MIN_PCT

    def test_deg_and_teg_byproduct_fractions(self) -> None:
        """Verify nominal DEG byproduct is 6.80% and TEG byproduct is 1.10%."""
        sim = EgHydrationReactor()
        assert DEG_BYPRODUCT_NOMINAL_PCT == 6.80
        assert TEG_BYPRODUCT_NOMINAL_PCT == 1.10
        assert abs(sim.state.deg_byproduct_pct - 6.80) < 0.1
        assert abs(sim.state.teg_byproduct_pct - 1.10) < 0.1
        total_selectivity = (
            sim.state.meg_selectivity_pct
            + sim.state.deg_byproduct_pct
            + sim.state.teg_byproduct_pct
        )
        assert abs(total_selectivity - 100.0) < 0.1

    def test_eo_conversion_exceeds_99_5_pct(self) -> None:
        """Verify EO conversion is 99.80%, strictly exceeding 99.50% minimum threshold."""
        sim = EgHydrationReactor()
        assert abs(sim.state.eo_conversion_pct - 99.80) < 0.1
        assert sim.state.eo_conversion_pct >= EO_CONVERSION_MIN_PCT
        assert EO_CONVERSION_MIN_PCT == 99.50

    def test_meg_production_rate_nominal(self) -> None:
        """Verify nominal MEG production rate is 485.0 kg/h."""
        sim = EgHydrationReactor()
        assert MEG_PRODUCTION_NOMINAL_KG_H == 485.0
        assert abs(sim.state.meg_production_rate_kg_h - 485.0) < 0.5


# ============================================================================
# Section 6: Coupled 6-State ODE System & High-Order RK4 Numerical Integrator
# ============================================================================

class TestSection6Coupled6StateODEAndRK4:
    """Tests for 6-state ODE formulation, time derivatives, and RK4 integrator stability."""

    def test_dynamic_state_vector_elements(self) -> None:
        """Verify state vector comprises 6 variables: C_eo, C_water, C_meg, C_deg, C_teg, T_reactor."""
        state = EgHydrationState()
        assert hasattr(state, "c_eo")
        assert hasattr(state, "c_water")
        assert hasattr(state, "c_meg")
        assert hasattr(state, "c_deg")
        assert hasattr(state, "c_teg")
        assert hasattr(state, "t_reactor")

    def test_state_initial_defaults(self) -> None:
        """Verify nominal steady-state values of the 6 dynamic states."""
        state = EgHydrationState()
        assert abs(state.c_eo - 4.770) < 1e-2
        assert abs(state.c_water - 41933.44) < 1e-1
        assert abs(state.c_meg - 2192.36) < 1e-1
        assert abs(state.c_deg - 80.93) < 1e-1
        assert abs(state.c_teg - 8.73) < 1e-1
        assert abs(state.t_reactor - (192.0 + T_ZERO_CELSIUS)) < 1e-2
        assert state.eg_hydration_active is True
        assert state.emergency_cold_deluge_active is False
        assert state.low_water_eo_ratio_pre_alarm is False
        assert state.diagnostic_code == EgHydrationDiagnosticCode.OK

    def test_compute_derivatives_shape_and_finiteness(self) -> None:
        """Verify compute_derivatives returns 6 finite floating point numbers."""
        sim = EgHydrationReactor()
        y0 = [
            sim.state.c_eo,
            sim.state.c_water,
            sim.state.c_meg,
            sim.state.c_deg,
            sim.state.c_teg,
            sim.state.t_reactor,
        ]
        derivs = sim.compute_derivatives(0.0, y0)
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_single_rk4_step_advances_time(self) -> None:
        """Verify single rk4_step increments simulation time and scan count."""
        sim = EgHydrationReactor()
        t0 = sim.state.sim_time_s
        c0 = sim.state.scan_count
        sim.rk4_step(0.02)
        assert abs(sim.state.sim_time_s - (t0 + 0.02)) < 1e-6
        assert sim.state.scan_count == c0 + 1

    def test_advance_time_multi_step_execution(self) -> None:
        """Verify advance_time executes multiple RK4 micro-steps cleanly."""
        sim = EgHydrationReactor()
        res = sim.advance_time(duration_s=2.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert abs(sim.state.sim_time_s - 2.0) < 1e-4
        assert sim.state.scan_count == 100

    def test_step_returns_execution_result_payload(self) -> None:
        """Verify step() returns AgentStatus.SUCCESS with telemetry details."""
        sim = EgHydrationReactor()
        res = sim.step(0.02)
        assert res.status == AgentStatus.SUCCESS
        assert "Step completed" in res.details
        assert abs(sim.state.sim_time_s - 0.02) < 1e-6

    def test_rk4_state_clamping_and_non_negativity(self) -> None:
        """Verify state concentrations remain strictly non-negative after RK4 step."""
        sim = EgHydrationReactor()
        sim.rk4_step(0.05)
        assert sim.state.c_eo >= 0.0
        assert sim.state.c_water >= 0.0
        assert sim.state.c_meg >= 0.0
        assert sim.state.c_deg >= 0.0
        assert sim.state.c_teg >= 0.0
        assert sim.state.t_reactor >= 273.15


# ============================================================================
# Section 7: Mathematical Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection7MathematicalConservationResiduals:
    """Tests for rigorous mass, elemental, and enthalpy conservation residuals < 1e-10."""

    def test_total_mass_balance_residual_less_than_1e10(self) -> None:
        """Verify total mass balance residual is strictly < 1e-10 kg/s."""
        sim = EgHydrationReactor()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_species_mass_residual_less_than_1e10(self) -> None:
        """Verify atomic elemental mass balance residual is strictly < 1e-10 kg/s."""
        sim = EgHydrationReactor()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        """Verify thermal enthalpy conservation residual is strictly < 1e-10 kW."""
        sim = EgHydrationReactor()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_residuals_conserved_over_extended_simulation(self) -> None:
        """Verify conservation residuals remain < 1e-10 across 100 simulation cycles."""
        sim = EgHydrationReactor()
        sim.advance_time(duration_s=2.0, dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_residuals_under_perturbed_concentrations(self) -> None:
        """Verify residuals remain < 1e-10 under perturbed process conditions."""
        sim = EgHydrationReactor()
        sim.state.c_eo = 12.0
        sim.state.c_meg = 2000.0
        sim.state.c_deg = 150.0
        sim.state.c_teg = 20.0
        sim._update_kinetics_and_conversion()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 8: Process Safety Interlocks & Strict Diagnostic Priority
# ============================================================================

class TestSection8ProcessSafetyInterlocks:
    """Tests for safety alarms, trips, and strict diagnostic priority (0xED01..0xED04)."""

    def test_normal_steady_state_diagnostic_code_ok(self) -> None:
        """Verify diagnostic code is 0x0000 (OK) at nominal steady-state."""
        sim = EgHydrationReactor()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.OK
        assert sim.state.eg_hydration_active is True
        assert sim.state.emergency_cold_deluge_active is False
        assert sim.state.low_water_eo_ratio_pre_alarm is False

    def test_priority_1_thermal_runaway_trip_above_220c(self) -> None:
        """Verify 0xED01 asserts when reactor temp > 220.0 °C (Priority 1)."""
        sim = EgHydrationReactor()
        sim.state.reactor_temperature_celsius = 222.5
        sim.state.t_reactor = 222.5 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        assert sim.state.emergency_cold_deluge_active is True
        assert sim.state.eg_hydration_active is False

    def test_priority_2_pressure_surge_trip_above_28bar(self) -> None:
        """Verify 0xED02 asserts when reactor pressure > 28.0 bar (Priority 2)."""
        sim = EgHydrationReactor()
        sim.state.reactor_pressure_bar = 29.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.EXCESSIVE_PRESSURE_SURGE
        assert sim.state.emergency_cold_deluge_active is True
        assert sim.state.eg_hydration_active is False

    def test_priority_3_meg_selectivity_below_target(self) -> None:
        """Verify 0xED03 asserts when MEG selectivity < 91.50 % (Priority 3)."""
        sim = EgHydrationReactor()
        sim.state.meg_selectivity_pct = 90.00
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.MEG_SELECTIVITY_BELOW_TARGET
        assert sim.state.emergency_cold_deluge_active is False
        assert sim.state.eg_hydration_active is True

    def test_priority_4_water_eo_ratio_starvation(self) -> None:
        """Verify 0xED04 asserts when water-to-EO ratio < 15.0:1 (Priority 4)."""
        sim = EgHydrationReactor()
        sim.state.water_to_eo_feed_ratio = 14.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.WATER_EO_RATIO_STARVATION
        assert sim.state.emergency_cold_deluge_active is False
        assert sim.state.eg_hydration_active is True

    def test_low_water_ratio_prealarm_coil_m425(self) -> None:
        """Verify pre-alarm %M425 asserts when water-to-EO ratio < 14.0:1."""
        sim = EgHydrationReactor()
        sim.state.water_to_eo_feed_ratio = 13.5
        sim._evaluate_safety_interlocks()
        assert sim.state.low_water_eo_ratio_pre_alarm is True
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.WATER_EO_RATIO_STARVATION

    def test_strict_priority_hierarchy_ordering(self) -> None:
        """Verify strict priority ordering: 0xED01 > 0xED02 > 0xED03 > 0xED04 > 0x0000."""
        sim = EgHydrationReactor()
        # Activate all fault conditions simultaneously
        sim.state.reactor_temperature_celsius = 225.0  # 0xED01
        sim.state.t_reactor = 225.0 + T_ZERO_CELSIUS
        sim.state.reactor_pressure_bar = 30.0         # 0xED02
        sim.state.meg_selectivity_pct = 89.0          # 0xED03
        sim.state.water_to_eo_feed_ratio = 12.0       # 0xED04
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY

        # Clear 0xED01 -> Priority 2 (0xED02) must take precedence
        sim.state.reactor_temperature_celsius = 192.0
        sim.state.t_reactor = 192.0 + T_ZERO_CELSIUS
        sim.state.emergency_cold_deluge_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.EXCESSIVE_PRESSURE_SURGE

        # Clear 0xED02 -> Priority 3 (0xED03) must take precedence
        sim.state.reactor_pressure_bar = 22.0
        sim.state.emergency_cold_deluge_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.MEG_SELECTIVITY_BELOW_TARGET

        # Clear 0xED03 -> Priority 4 (0xED04) must take precedence
        sim.state.meg_selectivity_pct = 92.10
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.WATER_EO_RATIO_STARVATION

        # Clear 0xED04 -> Normal OK (0x0000)
        sim.state.water_to_eo_feed_ratio = 18.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.OK

    def test_diagnostic_code_enum_values_and_aliases(self) -> None:
        """Verify diagnostic code hex numbers and compatibility aliases."""
        assert EgHydrationDiagnosticCode.OK == 0x0000
        assert EgHydrationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY == 0xED01
        assert EgHydrationDiagnosticCode.EXCESSIVE_PRESSURE_SURGE == 0xED02
        assert EgHydrationDiagnosticCode.MEG_SELECTIVITY_BELOW_TARGET == 0xED03
        assert EgHydrationDiagnosticCode.WATER_EO_RATIO_STARVATION == 0xED04
        assert EgHydrationDiagCode is EgHydrationDiagnosticCode
        assert EgHydrationReactorDiagnosticCode is EgHydrationDiagnosticCode
        assert EgHydrationReactorDiagCode is EgHydrationDiagnosticCode


# ============================================================================
# Section 9: Emergency Cold Water Deluge Dynamic Quench (> 220 °C or > 28 bar)
# ============================================================================

class TestSection9EmergencyColdWaterDeluge:
    """Tests for emergency cold water deluge cooling and thermal recovery dynamics."""

    def test_deluge_coil_m426_asserts_on_thermal_runaway(self) -> None:
        """Verify %M426 EmergencyColdDelugeActive asserts on 0xED01 (> 220 °C)."""
        sim = EgHydrationReactor()
        sim.state.reactor_temperature_celsius = 221.0
        sim.state.t_reactor = 221.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cold_deluge_active is True

    def test_deluge_coil_m426_asserts_on_pressure_surge(self) -> None:
        """Verify %M426 EmergencyColdDelugeActive asserts on 0xED02 (> 28 bar)."""
        sim = EgHydrationReactor()
        sim.state.reactor_pressure_bar = 28.5
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cold_deluge_active is True

    def test_active_coil_m424_cleared_on_trip(self) -> None:
        """Verify %M424 EgHydrationActive is cleared (False) when reactor trips."""
        sim = EgHydrationReactor()
        sim.state.reactor_temperature_celsius = 223.0
        sim.state.t_reactor = 223.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.eg_hydration_active is False

    def test_deluge_heat_removal_duty_active(self) -> None:
        """Verify emergency cold water deluge removes substantial heat during trip."""
        sim = EgHydrationReactor()
        sim.state.reactor_temperature_celsius = 225.0
        sim.state.t_reactor = 225.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cold_deluge_active is True

        y_trip = [
            sim.state.c_eo,
            sim.state.c_water,
            sim.state.c_meg,
            sim.state.c_deg,
            sim.state.c_teg,
            sim.state.t_reactor,
        ]
        d_trip = sim.compute_derivatives(0.0, y_trip)
        # Under cold deluge, dT/dt (index 5) is strongly negative (< -1.0 K/s)
        assert d_trip[5] < -1.0

    def test_dynamic_thermal_recovery_under_cold_deluge(self) -> None:
        """Verify reactor temperature cools rapidly below reset threshold under active deluge."""
        sim = EgHydrationReactor()
        sim.state.reactor_temperature_celsius = 225.0
        sim.state.t_reactor = 225.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cold_deluge_active is True

        sim.advance_time(duration_s=8.0, dt=0.02)
        assert sim.state.reactor_temperature_celsius <= sim.config.deluge_reset_temp_c

    def test_pressure_recovery_under_quench(self) -> None:
        """Verify reactor pressure decreases toward baseline under cooling quench."""
        sim = EgHydrationReactor()
        sim.state.reactor_pressure_bar = 29.0
        sim._evaluate_safety_interlocks()
        sim.advance_time(duration_s=5.0, dt=0.02)
        assert sim.state.reactor_pressure_bar <= 25.0


# ============================================================================
# Section 10: Horner OCS Memory Space Integration (%R1820..%R1827, %M424..%M426)
# ============================================================================

class TestSection10HornerOCSMiniMemorySpace:
    """Tests for Horner OCS register table synchronization, signed 16-bit masking, and SYSTEM privilege."""

    def test_analog_registers_scaling_r1820_to_r1826(self) -> None:
        """Verify scaled integer values in analog registers %R1820..%R1826."""
        reg = RegisterTable()
        sim = EgHydrationReactor(register_table=reg)

        sim.state.reactor_temperature_celsius = 192.0
        sim.state.reactor_pressure_bar = 22.00
        sim.state.eo_conversion_pct = 99.80
        sim.state.meg_selectivity_pct = 92.10
        sim.state.deg_byproduct_pct = 6.80
        sim.state.water_to_eo_feed_ratio = 18.5
        sim.state.meg_production_rate_kg_h = 485.0
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1820") == 1920
        assert reg.read_word("%R1821") == 2200
        assert reg.read_word("%R1822") == 9980
        assert reg.read_word("%R1823") == 9210
        assert reg.read_word("%R1824") == 680
        assert reg.read_word("%R1825") == 185
        assert reg.read_word("%R1826") == 4850

    def test_diagnostic_status_code_register_r1827_hex_masking(self) -> None:
        """Verify %R1827 diagnostic code with unsigned 16-bit hex masking (& 0xFFFF)."""
        reg = RegisterTable()
        sim = EgHydrationReactor(register_table=reg)

        # 0xED01: THERMAL_EXCURSION_RUNAWAY
        sim.state.diagnostic_code = EgHydrationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        raw_signed = reg.read_word("%R1827")
        assert (raw_signed & 0xFFFF) == 0xED01
        assert reg.read_uword("%R1827") == 0xED01

        # 0xED02: EXCESSIVE_PRESSURE_SURGE
        sim.state.diagnostic_code = EgHydrationDiagnosticCode.EXCESSIVE_PRESSURE_SURGE
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert (reg.read_word("%R1827") & 0xFFFF) == 0xED02

        # 0xED03: MEG_SELECTIVITY_BELOW_TARGET
        sim.state.diagnostic_code = EgHydrationDiagnosticCode.MEG_SELECTIVITY_BELOW_TARGET
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert (reg.read_word("%R1827") & 0xFFFF) == 0xED03

        # 0xED04: WATER_EO_RATIO_STARVATION
        sim.state.diagnostic_code = EgHydrationDiagnosticCode.WATER_EO_RATIO_STARVATION
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert (reg.read_word("%R1827") & 0xFFFF) == 0xED04

        # 0x0000: OK
        sim.state.diagnostic_code = EgHydrationDiagnosticCode.OK
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert (reg.read_word("%R1827") & 0xFFFF) == 0x0000

    def test_discrete_coils_m424_to_m426(self) -> None:
        """Verify discrete coils %M424, %M425, %M426 reflect system state."""
        reg = RegisterTable()
        sim = EgHydrationReactor(register_table=reg)

        sim.state.eg_hydration_active = True
        sim.state.low_water_eo_ratio_pre_alarm = False
        sim.state.emergency_cold_deluge_active = False
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M424") is True
        assert reg.read_bit("%M425") is False
        assert reg.read_bit("%M426") is False

    def test_system_privilege_mode_enforcement(self) -> None:
        """Verify synchronization operates cleanly under PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = EgHydrationReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_word("%R1820") == 1920

    def test_register_sync_under_thermal_trip(self) -> None:
        """Verify register table reflection under thermal runaway trip."""
        reg = RegisterTable()
        sim = EgHydrationReactor(register_table=reg)
        sim.state.reactor_temperature_celsius = 226.0
        sim.state.t_reactor = 226.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert (reg.read_word("%R1827") & 0xFFFF) == 0xED01
        assert reg.read_bit("%M424") is False
        assert reg.read_bit("%M426") is True

    def test_register_sync_under_pressure_trip(self) -> None:
        """Verify register table reflection under overpressure surge trip."""
        reg = RegisterTable()
        sim = EgHydrationReactor(register_table=reg)
        sim.state.reactor_pressure_bar = 29.8
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert (reg.read_word("%R1827") & 0xFFFF) == 0xED02
        assert reg.read_bit("%M424") is False
        assert reg.read_bit("%M426") is True

    def test_status_word_bitmask_consistency(self) -> None:
        """Verify status word bitmask matches active alarms and states."""
        sim = EgHydrationReactor()
        sim.state.reactor_temperature_celsius = 225.0
        sim.state.t_reactor = 225.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.status_word & EgHydrationStatusBits.EMERGENCY_COLD_DELUGE_ACTIVE
        assert sim.state.status_word & EgHydrationStatusBits.THERMAL_EXCURSION_ALARM
        assert not (sim.state.status_word & EgHydrationStatusBits.EG_HYDRATION_ACTIVE)


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text & Anti-Ladder Security Guard
# ============================================================================

class TestSection11PureIEC61131StructuredText:
    """Tests for pure Structured Text compliance, AST parsing, and ladder rejection."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify EG Hydration ST POU parses into a valid AST PROGRAM structure."""
        SecurityGuard.assert_pure_st_content(EG_HYDRATION_REACTOR_PURE_ST_POU)
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(EG_HYDRATION_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "EgHydrationSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_pou_name_and_type(self) -> None:
        """Verify program name 'EgHydrationSync' and POUType.PROGRAM."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(EG_HYDRATION_REACTOR_PURE_ST_POU)
        assert ast.name == "EgHydrationSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_bound_registers(self) -> None:
        """Verify all %R1820..%R1827 and %M424..%M426 are bound in the ST POU."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(EG_HYDRATION_REACTOR_PURE_ST_POU)
        expected_regs = [
            "%R1820", "%R1821", "%R1822", "%R1823",
            "%R1824", "%R1825", "%R1826", "%R1827",
            "%M424", "%M425", "%M426",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_security_guard_assert_pure_st_valid(self) -> None:
        """Verify SecurityGuard accepts pure Structured Text without raising exceptions."""
        SecurityGuard.assert_pure_st_content(EG_HYDRATION_REACTOR_PURE_ST_POU)
        assert verify_eg_hydration_reactor_pure_st() is True
        assert verify_eg_hydration_pure_st() is True

    def test_anti_ladder_rejection_contact(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder contacts ---[ ]---."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_coil(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder coils ---( )---."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_rung(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on RUNG keywords."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_mnemonics_xic(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder mnemonic XIC."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nXIC EgHydrationActive\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_mnemonics_ote(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder mnemonic OTE."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nOTE EmergencyColdDelugeActive\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 12: ILogicUnit Scan Cycle Execution, Reset & Soak Stability
# ============================================================================

class TestSection12ILogicUnitScanCycleIntegration:
    """Tests for ILogicUnit scan cycle execution, reset dynamics, and soak stability."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify EgHydrationReactor exposes required ILogicUnit properties."""
        sim = EgHydrationReactor()
        assert sim.name == "EgHydrationSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_with_scan_context(self) -> None:
        """Verify scan_step executes and syncs with ScanContext register table."""
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=20.0)
        setattr(ctx, "registers", reg)
        sim = EgHydrationReactor()
        sim.scan_step(dt=0.02, context=ctx)
        assert reg.read_word("%R1820") == 1920

    def test_execute_via_scan_context(self) -> None:
        """Verify execute(ctx) executes one scan cycle."""
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=20.0)
        setattr(ctx, "registers", reg)
        sim = EgHydrationReactor(register_table=reg)
        sim.execute(ctx)
        assert sim.state.scan_count == 1

    def test_adapter_logic_unit_execution(self) -> None:
        """Verify EgHydrationReactorLogicUnit adapter executes cleanly."""
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=20.0)
        setattr(ctx, "registers", reg)
        unit = EgHydrationReactorLogicUnit(register_table=reg)
        unit.execute(ctx)
        assert reg.read_word("%R1820") == 1920
        assert unit.name == "EgHydrationSync"
        assert unit.priority == 100
        assert unit.is_enabled is True

    def test_reset_restores_nominal_state(self) -> None:
        """Verify reset() restores nominal baseline state after trips."""
        sim = EgHydrationReactor()
        sim.state.reactor_temperature_celsius = 228.0
        sim.state.emergency_cold_deluge_active = True
        sim.state.diagnostic_code = EgHydrationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        sim.reset()
        assert abs(sim.state.reactor_temperature_celsius - 192.0) < 1e-2
        assert sim.state.emergency_cold_deluge_active is False
        assert sim.state.diagnostic_code == EgHydrationDiagnosticCode.OK

    def test_continuous_multi_cycle_soak_execution(self) -> None:
        """Verify 100 continuous scan cycles execute without drift or error."""
        sim = EgHydrationReactor()
        for _ in range(100):
            sim.scan_step(dt=0.02)
        assert sim.state.scan_count == 100
        assert abs(sim.state.sim_time_s - 2.0) < 1e-4
        assert 160.0 <= sim.state.reactor_temperature_celsius <= 200.0


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection13VerificationSuiteAndArtifacts:
    """Tests for 9-stage verification runner, JSON export, and component aliases."""

    def test_run_eg_hydration_reactor_verification_status_success(self) -> None:
        """Verify 9-stage verification suite passes with strict 4-state success contract."""
        res = run_eg_hydration_reactor_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W221"
        assert res["data"]["module"] == "eg_hydration_reactor"
        assert res["data"]["total_checks"] == 9
        assert res["data"]["checks_passed"] == 9

    def test_all_9_verification_stages_passed(self) -> None:
        """Verify all 9 stages passed deterministically."""
        res = run_eg_hydration_reactor_verification()
        tests = res["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True

    def test_verification_json_export(self, tmp_path: Path) -> None:
        """Verify JSON evidence artifact is created and valid on disk."""
        out_file = tmp_path / "eg_evidence.json"
        res = run_eg_hydration_reactor_verification(output_path=out_file)
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_aliases(self) -> None:
        """Verify run_eg_hydration_verification alias returns success."""
        res = run_eg_hydration_verification()
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9

    def test_helper_verification_functions(self) -> None:
        """Verify helper validation functions return True / SUCCESS."""
        assert verify_eg_hydration_reactor_pure_st() is True
        assert verify_eg_hydration_pure_st() is True
        res = validate_pure_st()
        assert res.status == AgentStatus.SUCCESS

    def test_simulator_and_config_aliases(self) -> None:
        """Verify all model, engine, simulator, and logic unit aliases point to canonical definitions."""
        assert EgHydrationSimulator is EgHydrationReactor
        assert EgHydrationEngine is EgHydrationReactor
        assert EgHydrationModel is EgHydrationReactor
        assert EgHydrationPlantModel is EgHydrationReactor
        assert EgHydrationSimulationEngine is EgHydrationReactor
        assert EgHydrationReactorSimulator is EgHydrationReactor
        assert EgHydrationReactorEngine is EgHydrationReactor
        assert EgHydrationReactorModel is EgHydrationReactor
        assert EgHydrationReactorPlantModel is EgHydrationReactor
        assert EgHydrationReactorSimulationEngine is EgHydrationReactor
        assert EgHydrationLogicUnit is EgHydrationReactorLogicUnit
        assert EG_HYDRATION_SYNC_POU == EG_HYDRATION_REACTOR_PURE_ST_POU
        assert EG_HYDRATION_PURE_ST_POU == EG_HYDRATION_REACTOR_PURE_ST_POU
        assert EG_HYDRATION_REACTOR_SYNC_POU == EG_HYDRATION_REACTOR_PURE_ST_POU
