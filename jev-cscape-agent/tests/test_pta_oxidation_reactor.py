"""Comprehensive Industrial PTA Oxidation Reactor Test Suite.

Work Package: W218 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 13 engineering verification sections:
1. Section 1: Universal Physical Constants, Molecular Weights & Thermodynamic Enthalpies
2. Section 2: Reactor Configuration, Vessel Geometry & Baseline Operating Parameters
3. Section 3: Arrhenius Reaction Kinetics, Intermediate Pathways & Solvent Combustion
4. Section 4: Gas-Liquid Mass Transfer, Henry's Law Oxygen Absorption & Off-Gas Vol%
5. Section 5: Coupled 6-State ODE System & High-Order RK4 Numerical Integrator
6. Section 6: Stoichiometric Mass, Elemental Atomic & Enthalpy Conservation Residuals (< 1e-10)
7. Section 7: High PX Conversion (> 99.0%), PTA Yield (> 95.0%) & 4-CBA Impurity (< 25 ppm)
8. Section 8: Process Safety Interlocks & Diagnostics in Strict Priority Hierarchy (0xEA01..0xEA04)
9. Section 9: Emergency Cold Acetic Acid Quench & Nitrogen Deluge on Runaway (> 225 °C)
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege Mode (%R1790..%R1797, %M417..%M419)
11. Section 11: Strict Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
12. Section 12: ILogicUnit Scan Cycle Execution, Reset Dynamics & Multi-Cycle Soak
13. Section 13: Deterministic 9-Stage Verification Suite & Runner Integration
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

from jev_cscape.simulation.pta_oxidation_reactor import (
    CBA_IMPURITY_ALARM_PPM,
    CBA_IMPURITY_MAX_PPM,
    CBA_IMPURITY_NOMINAL_PPM,
    CONVERSION_MIN_PCT,
    CONVERSION_NOMINAL_PCT,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DELTA_H4_J_MOL,
    DELTA_H4_KJ_MOL,
    DELTA_H_4CBA_OXIDATION_J_MOL,
    DELTA_H_4CBA_OXIDATION_KJ_MOL,
    DELTA_H_PX_OXIDATION_J_MOL,
    DELTA_H_PX_OXIDATION_KJ_MOL,
    DELTA_H_SOLVENT_BURNING_J_MOL,
    DELTA_H_SOLVENT_BURNING_KJ_MOL,
    DELTA_H_SOLVENT_BURNOFF_J_MOL,
    DELTA_H_SOLVENT_BURNOFF_KJ_MOL,
    DELTA_H_TOLUIC_OXIDATION_J_MOL,
    DELTA_H_TOLUIC_OXIDATION_KJ_MOL,
    DISSOLVED_O2_LOW_ANOXIA_PPM,
    DISSOLVED_O2_LOW_PPM,
    DISSOLVED_O2_NOMINAL_PPM,
    FOUR_CBA_ALARM_PPM,
    FOUR_CBA_NOMINAL_PPM,
    FOUR_CBA_TARGET_MAX_PPM,
    G_ACCEL,
    MW_4CBA,
    MW_ACETIC_ACID,
    MW_C,
    MW_CBA,
    MW_CO,
    MW_CO2,
    MW_FOUR_CBA,
    MW_H,
    MW_H2O,
    MW_HAC,
    MW_N,
    MW_N2,
    MW_O,
    MW_O2,
    MW_P_TOLUIC_ACID,
    MW_P_XYLENE,
    MW_PTAC,
    MW_PTA,
    MW_PX,
    MW_TEREPHTHALIC_ACID,
    MW_TOLUIC,
    MW_TPA,
    MW_WATER,
    OFFGAS_O2_ALARM_PCT,
    OFFGAS_O2_ENVELOPE_MAX_VOL_PCT,
    OFFGAS_O2_HIGH_ALARM_VOL_PCT,
    OFFGAS_O2_NOMINAL_PCT,
    OFFGAS_O2_NOMINAL_VOL_PCT,
    OFFGAS_O2_RESET_VOL_PCT,
    OFFGAS_O2_TRIP_PCT,
    OFFGAS_O2_TRIP_VOL_PCT,
    PTA_OXIDATION_PURE_ST_POU,
    PTA_OXIDATION_REACTOR_PURE_ST_POU,
    PTA_OXIDATION_REACTOR_SYNC_POU,
    PTA_OXIDATION_SYNC_POU,
    PTA_PURE_ST_POU,
    PTA_REACTOR_PURE_ST_POU,
    PTA_REACTOR_SYNC_POU,
    PTA_SYNC_POU,
    PTA_YIELD_MIN_PCT,
    PTA_YIELD_NOMINAL_PCT,
    PTA_YIELD_TARGET_MIN,
    PX_CONVERSION_MIN_PCT,
    PX_CONVERSION_NOMINAL_PCT,
    PX_CONVERSION_TARGET_MIN,
    PX_FEED_RATE_NOMINAL_KG_H,
    QUENCH_FLOW_KG_S,
    QUENCH_SHUTOFF_TEMP_C,
    QUENCH_TEMP_C,
    R_GAS_CONST,
    REACTOR_PRESSURE_MAX_BAR,
    REACTOR_PRESSURE_MIN_BAR,
    REACTOR_PRESSURE_NOMINAL_BAR,
    REACTOR_TEMP_MAX_C,
    REACTOR_TEMP_MIN_C,
    REACTOR_TEMP_NOMINAL_C,
    REACTOR_TEMP_RESET_C,
    REACTOR_TEMP_TRIP_C,
    REACTOR_TEMP_WARNING_C,
    RUNAWAY_TRIP_TEMP_C,
    SOLVENT_BURN_RATE_MAX_KG_T,
    SOLVENT_BURN_RATE_NOMINAL_KG_T,
    SOLVENT_PX_MASS_RATIO_NOMINAL,
    T_REF_K,
    T_ZERO_CELSIUS,
    YIELD_MIN_PCT,
    YIELD_NOMINAL_PCT,
    PtaConfig,
    PtaDiagCode,
    PtaDiagnosticCode,
    PtaLogicUnit,
    PtaOxidationConfig,
    PtaOxidationDiagCode,
    PtaOxidationDiagnosticCode,
    PtaOxidationLogicUnit,
    PtaOxidationParameters,
    PtaOxidationReactor,
    PtaOxidationReactorConfig,
    PtaOxidationReactorDiagCode,
    PtaOxidationReactorDiagnosticCode,
    PtaOxidationReactorEngine,
    PtaOxidationReactorLogicUnit,
    PtaOxidationReactorModel,
    PtaOxidationReactorParameters,
    PtaOxidationReactorPlantModel,
    PtaOxidationReactorSimulationEngine,
    PtaOxidationReactorSimulator,
    PtaOxidationReactorState,
    PtaOxidationSimulator,
    PtaOxidationState,
    PtaOxidationStatusBits,
    PtaOxidationStatusWord,
    PtaParameters,
    PtaReactor,
    PtaReactorConfig,
    PtaReactorDiagCode,
    PtaReactorDiagnosticCode,
    PtaReactorEngine,
    PtaReactorLogicUnit,
    PtaReactorModel,
    PtaReactorParameters,
    PtaReactorPlantModel,
    PtaReactorSimulationEngine,
    PtaReactorSimulator,
    PtaReactorState,
    PtaReactorStatusBits,
    PtaReactorStatusWord,
    PtaSimulator,
    PtaState,
    PtaStatusBits,
    PtaStatusWord,
    run_pta_oxidation_reactor_verification,
    run_pta_oxidation_verification,
    run_pta_reactor_verification,
    run_pta_verification,
    validate_pta_oxidation_pure_st,
    validate_pta_pure_st,
    validate_pure_st,
    verify_pta_oxidation_pure_st,
    verify_pta_oxidation_reactor_pure_st,
    verify_pta_pure_st,
    verify_pta_reactor_pure_st,
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
        assert abs(T_REF_K - 473.15) < 1e-4

    def test_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon, Hydrogen, Oxygen, and Nitrogen."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_O - 0.015999) < 1e-6
        assert abs(MW_N - 0.014007) < 1e-6

    def test_molecular_weights_species(self) -> None:
        """Verify molecular weights for PX, PTAC, 4-CBA, PTA, Acetic acid, H2O, O2, N2, CO2."""
        assert abs(MW_PX - 0.106168) < 1e-5
        assert abs(MW_P_XYLENE - MW_PX) < 1e-8
        assert abs(MW_TOLUIC - 0.136150) < 1e-5
        assert abs(MW_P_TOLUIC_ACID - MW_TOLUIC) < 1e-8
        assert abs(MW_PTAC - MW_TOLUIC) < 1e-8
        assert abs(MW_4CBA - 0.150133) < 1e-5
        assert abs(MW_FOUR_CBA - MW_4CBA) < 1e-8
        assert abs(MW_CBA - MW_4CBA) < 1e-8
        assert abs(MW_PTA - 0.166132) < 1e-5
        assert abs(MW_TPA - MW_PTA) < 1e-8
        assert abs(MW_TEREPHTHALIC_ACID - MW_PTA) < 1e-8
        assert abs(MW_HAC - 0.060052) < 1e-5
        assert abs(MW_ACETIC_ACID - MW_HAC) < 1e-8
        assert abs(MW_H2O - 0.018015) < 1e-5
        assert abs(MW_WATER - MW_H2O) < 1e-8
        assert abs(MW_O2 - 0.031998) < 1e-5
        assert abs(MW_N2 - 0.028014) < 1e-5
        assert abs(MW_CO2 - 0.044009) < 1e-5
        assert abs(MW_CO - 0.028010) < 1e-5

    def test_reaction1_px_oxidation_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 1: PX + 1.5 O2 -> PTAC + H2O exact mass balance and Delta H1."""
        reactants = MW_PX + 1.5 * MW_O2
        products = MW_TOLUIC + MW_H2O
        assert abs(reactants - products) < 1e-12
        assert DELTA_H1_KJ_MOL == -420.0
        assert DELTA_H1_J_MOL == -420000.0
        assert DELTA_H_PX_OXIDATION_KJ_MOL == -420.0
        assert DELTA_H_PX_OXIDATION_J_MOL == -420000.0

    def test_reaction2_ptac_oxidation_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 2: PTAC + O2 -> 4-CBA + H2O exact mass balance and Delta H2."""
        reactants = MW_TOLUIC + 1.0 * MW_O2
        products = MW_4CBA + MW_H2O
        assert abs(reactants - products) < 1e-12
        assert DELTA_H2_KJ_MOL == -380.0
        assert DELTA_H2_J_MOL == -380000.0
        assert DELTA_H_TOLUIC_OXIDATION_KJ_MOL == -380.0
        assert DELTA_H_TOLUIC_OXIDATION_J_MOL == -380000.0

    def test_reaction3_4cba_oxidation_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 3: 4-CBA + 0.5 O2 -> PTA exact mass balance and Delta H3."""
        reactants = MW_4CBA + 0.5 * MW_O2
        products = MW_PTA
        assert abs(reactants - products) < 1e-12
        assert DELTA_H3_KJ_MOL == -550.0
        assert DELTA_H3_J_MOL == -550000.0
        assert DELTA_H_4CBA_OXIDATION_KJ_MOL == -550.0
        assert DELTA_H_4CBA_OXIDATION_J_MOL == -550000.0

    def test_reaction4_solvent_combustion_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 4: CH3COOH + 2 O2 -> 2 CO2 + 2 H2O exact mass balance and Delta H4."""
        reactants = MW_HAC + 2.0 * MW_O2
        products = 2.0 * MW_CO2 + 2.0 * MW_H2O
        assert abs(reactants - products) < 1e-12
        assert DELTA_H4_KJ_MOL == -874.0
        assert DELTA_H4_J_MOL == -874000.0
        assert DELTA_H_SOLVENT_BURNING_KJ_MOL == -874.0
        assert DELTA_H_SOLVENT_BURNING_J_MOL == -874000.0
        assert DELTA_H_SOLVENT_BURNOFF_KJ_MOL == -874.0
        assert DELTA_H_SOLVENT_BURNOFF_J_MOL == -874000.0


# ============================================================================
# Section 2: Reactor Configuration, Vessel Geometry & Baseline Parameters
# ============================================================================

class TestSection2ReactorConfigAndBaseline:
    """Tests for vessel geometry, process parameters, and initial states."""

    def test_default_config_parameters(self) -> None:
        """Verify default configuration dimensions and hydrodynamic baselines."""
        cfg = PtaOxidationConfig()
        assert cfg.reactor_diameter_m == 4.5
        assert cfg.reactor_height_m == 24.0
        assert cfg.liquid_volume_m3 == 120.0
        assert cfg.residence_time_s == 2400.0
        assert cfg.operating_pressure_bar == 18.00
        assert cfg.liquid_density_kg_m3 == 880.0
        assert cfg.liquid_cp_j_kg_k == 2500.0

    def test_geometric_properties(self) -> None:
        """Verify cross-sectional area and vessel outer heat loss surface area."""
        cfg = PtaOxidationConfig()
        expected_area = 0.25 * math.pi * (4.5 ** 2)
        assert abs(cfg.cross_section_area_m2 - expected_area) < 1e-4
        assert abs(cfg.reactor_cross_section_m2 - expected_area) < 1e-4
        expected_surface = math.pi * 4.5 * 24.0
        assert abs(cfg.vessel_surface_area_m2 - expected_surface) < 1e-4

    def test_operating_temperature_and_pressure_boundaries(self) -> None:
        """Verify operational limits for temperature and pressure."""
        assert REACTOR_TEMP_NOMINAL_C == 200.0
        assert REACTOR_TEMP_MIN_C == 190.0
        assert REACTOR_TEMP_MAX_C == 210.0
        assert REACTOR_TEMP_WARNING_C == 215.0
        assert REACTOR_TEMP_TRIP_C == 225.0
        assert REACTOR_TEMP_RESET_C == 210.0
        assert RUNAWAY_TRIP_TEMP_C == 225.0

        assert REACTOR_PRESSURE_NOMINAL_BAR == 18.00
        assert REACTOR_PRESSURE_MIN_BAR == 15.00
        assert REACTOR_PRESSURE_MAX_BAR == 22.00

    def test_initial_state_defaults(self) -> None:
        """Verify initial dynamic state vector matches nominal operation."""
        state = PtaOxidationState()
        assert abs(state.reactor_temp_celsius - 200.0) < 1e-2
        assert abs(state.reactor_pressure_bar - 18.00) < 1e-2
        assert abs(state.px_conversion_pct - 99.20) < 1e-2
        assert abs(state.pta_yield_pct - 96.50) < 1e-2
        assert abs(state.four_cba_impurity_ppm - 22.0) < 1e-2
        assert abs(state.cba_impurity_ppm - 22.0) < 1e-2
        assert abs(state.offgas_oxygen_vol_pct - 2.80) < 1e-2
        assert abs(state.solvent_burn_rate_kg_t - 0.45) < 1e-2
        assert state.pta_oxidation_active is True
        assert state.emergency_nitrogen_quench_active is False
        assert state.emergency_quench_active is False
        assert state.diagnostic_code == PtaOxidationDiagnosticCode.OK

    def test_state_temperature_property_coupling(self) -> None:
        """Verify property setters for t_reactor_celsius and t_reactor_k synchronize."""
        state = PtaOxidationState()
        state.t_reactor_celsius = 210.0
        assert abs(state.t_reactor - (210.0 + T_ZERO_CELSIUS)) < 1e-4
        state.t_reactor_k = 480.0
        assert abs(state.reactor_temp_celsius - (480.0 - T_ZERO_CELSIUS)) < 1e-4

    def test_state_aliased_properties(self) -> None:
        """Verify c_ptac, c_o2_dissolved, and cba_impurity_ppm property bindings."""
        state = PtaOxidationState()
        state.c_ptac = 40.0
        assert abs(state.c_toluic - 40.0) < 1e-6
        state.c_o2_dissolved = 0.50
        assert abs(state.c_dissolved_o2 - 0.50) < 1e-6
        state.cba_impurity_ppm = 18.0
        assert abs(state.four_cba_impurity_ppm - 18.0) < 1e-6


# ============================================================================
# Section 3: Arrhenius Reaction Kinetics & Solvent Combustion Sensitivity
# ============================================================================

class TestSection3ArrheniusKinetics:
    """Tests for reaction rates, Arrhenius temperature factors, and combustion acceleration."""

    def test_nominal_reaction_rates_positive(self) -> None:
        """Verify computed volumetric and total reaction rates are positive under nominal feed."""
        sim = PtaOxidationReactor()
        rates = sim.compute_reaction_rates(15.248, 35.80, 0.044776, 1839.29, 473.15, 0.352)
        assert rates["r1_tot"] > 0.0
        assert rates["r2_tot"] > 0.0
        assert rates["r3_tot"] > 0.0
        assert rates["r4_tot"] > 0.0
        assert rates["q_rxn_kw"] > 0.0

    def test_temperature_dependence_arrhenius_acceleration(self) -> None:
        """Verify reaction rates accelerate with increasing temperature."""
        sim = PtaOxidationReactor()
        rates_200 = sim.compute_reaction_rates(15.248, 35.80, 0.044776, 1839.29, 473.15, 0.352)
        rates_215 = sim.compute_reaction_rates(15.248, 35.80, 0.044776, 1839.29, 488.15, 0.352)
        assert rates_215["r1_tot"] > rates_200["r1_tot"]
        assert rates_215["r2_tot"] > rates_200["r2_tot"]
        assert rates_215["r3_tot"] > rates_200["r3_tot"]
        assert rates_215["r4_tot"] > rates_200["r4_tot"]
        assert rates_215["q_rxn_kw"] > rates_200["q_rxn_kw"]

    def test_solvent_combustion_accelerates_faster_than_oxidation(self) -> None:
        """Verify solvent combustion (Ea4=125 kJ/mol) accelerates faster than PX oxidation (Ea1=92 kJ/mol)."""
        sim = PtaOxidationReactor()
        rates_200 = sim.compute_reaction_rates(15.248, 35.80, 0.044776, 1839.29, 473.15, 0.352)
        rates_220 = sim.compute_reaction_rates(15.248, 35.80, 0.044776, 1839.29, 493.15, 0.352)
        ratio_r1 = rates_220["r1_tot"] / rates_200["r1_tot"]
        ratio_r4 = rates_220["r4_tot"] / rates_200["r4_tot"]
        assert ratio_r4 > ratio_r1

    def test_tripped_state_kills_all_reaction_rates(self) -> None:
        """Verify all reaction rates and heat release collapse to zero when tripped."""
        sim = PtaOxidationReactor()
        rates = sim.compute_reaction_rates(15.248, 35.80, 0.044776, 1839.29, 473.15, 0.352, is_tripped=True)
        assert rates["r1_tot"] == 0.0
        assert rates["r2_tot"] == 0.0
        assert rates["r3_tot"] == 0.0
        assert rates["r4_tot"] == 0.0
        assert rates["q_rxn_kw"] == 0.0

    def test_zero_reactant_concentrations_yield_zero_rates(self) -> None:
        """Verify zero concentrations result in zero rates."""
        sim = PtaOxidationReactor()
        rates = sim.compute_reaction_rates(0.0, 0.0, 0.0, 0.0, 473.15, 0.0)
        assert rates["r1_tot"] == 0.0
        assert rates["r2_tot"] == 0.0
        assert rates["r3_tot"] == 0.0
        assert rates["r4_tot"] == 0.0


# ============================================================================
# Section 4: Gas-Liquid Mass Transfer & Off-Gas Oxygen Boundary (< 4.0 vol%)
# ============================================================================

class TestSection4MassTransferAndOffgas:
    """Tests for Henry's law oxygen absorption, dissolved O2, and off-gas flammability safety."""

    def test_nominal_oxygen_absorption_efficiency(self) -> None:
        """Verify oxygen mass transfer absorption rate is positive and high efficiency (> 85%)."""
        sim = PtaOxidationReactor()
        mt = sim.compute_mass_transfer(0.352, 473.15, 18.0)
        assert mt["r_o2_mt_tot"] > 0.0
        eff = mt["r_o2_mt_tot"] / mt["o2_feed_mol_s"]
        assert eff > 0.85

    def test_nominal_offgas_oxygen_below_flammability_envelope(self) -> None:
        """Verify nominal offgas O2 concentration is ~2.80 vol%, strictly < 4.00 vol% envelope."""
        sim = PtaOxidationReactor()
        mt = sim.compute_mass_transfer(0.352, 473.15, 18.0)
        assert 2.00 <= mt["offgas_o2_vol_pct"] <= 3.50
        assert mt["offgas_o2_vol_pct"] < OFFGAS_O2_ENVELOPE_MAX_VOL_PCT

    def test_flammability_safety_thresholds(self) -> None:
        """Verify off-gas pre-alarm, envelope limit, and trip thresholds."""
        assert OFFGAS_O2_ENVELOPE_MAX_VOL_PCT == 4.00
        assert OFFGAS_O2_HIGH_ALARM_VOL_PCT == 3.80
        assert OFFGAS_O2_TRIP_VOL_PCT == 4.50
        assert OFFGAS_O2_RESET_VOL_PCT == 3.50

    def test_tripped_emergency_nitrogen_sweep_dilutes_offgas(self) -> None:
        """Verify emergency nitrogen deluge purge reduces offgas oxygen to trace levels."""
        sim = PtaOxidationReactor()
        mt = sim.compute_mass_transfer(0.352, 473.15, 18.0, is_tripped=True)
        assert mt["o2_feed_mol_s"] == 0.0
        assert mt["n2_feed_mol_s"] == sim.config.nitrogen_purge_flow_mol_s
        assert mt["offgas_o2_vol_pct"] < 0.20

    def test_dissolved_oxygen_saturation(self) -> None:
        """Verify dissolved oxygen saturation concentration computation via Henry's Law."""
        sim = PtaOxidationReactor()
        mt = sim.compute_mass_transfer(0.352, 473.15, 18.0)
        assert mt["c_o2_sat"] > 0.50


# ============================================================================
# Section 5: Coupled 6-State ODE System & High-Order RK4 Numerical Integrator
# ============================================================================

class TestSection5CoupledODESystemAndRK4:
    """Tests for ODE derivatives vector and 4th-order Runge-Kutta stability."""

    def test_derivatives_vector_length_and_finiteness(self) -> None:
        """Verify compute_derivatives returns 6 finite floating point numbers."""
        sim = PtaOxidationReactor()
        y = [
            sim.state.c_px,
            sim.state.c_toluic,
            sim.state.c_4cba,
            sim.state.c_pta,
            sim.state.t_reactor,
            sim.state.c_dissolved_o2,
        ]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_single_rk4_step_execution(self) -> None:
        """Verify single rk4_step advances simulation time and scan count."""
        sim = PtaOxidationReactor()
        t0 = sim.state.sim_time_s
        c0 = sim.state.scan_count
        sim.rk4_step(0.02)
        assert abs(sim.state.sim_time_s - (t0 + 0.02)) < 1e-6
        assert sim.state.scan_count == c0 + 1

    def test_rk4_state_clamping_and_physical_bounds(self) -> None:
        """Verify state variables stay within physical bounds after RK4 step."""
        sim = PtaOxidationReactor()
        sim.rk4_step(0.05)
        assert sim.state.c_px >= 0.0
        assert sim.state.c_toluic >= 0.0
        assert sim.state.c_4cba >= 0.0
        assert sim.state.c_pta >= 0.0
        assert 290.0 <= sim.state.t_reactor <= 600.0
        assert sim.state.c_dissolved_o2 >= 0.001

    def test_advance_time_multi_step(self) -> None:
        """Verify advance_time runs multiple steps successfully."""
        sim = PtaOxidationReactor()
        res = sim.advance_time(duration_s=2.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert abs(sim.state.sim_time_s - 2.0) < 1e-4
        assert sim.state.scan_count == 100

    def test_step_returns_execution_result_payload(self) -> None:
        """Verify step() returns standard ExecutionResult with telemetry data."""
        sim = PtaOxidationReactor()
        res = sim.step(0.02)
        assert res.status == AgentStatus.SUCCESS
        assert "sim_time_s" in res.data
        assert "conversion_pct" in res.data or "px_conversion_pct" in res.data
        assert "pta_yield_pct" in res.data
        assert "four_cba_ppm" in res.data or "cba_impurity_ppm" in res.data
        assert "offgas_o2_pct" in res.data


# ============================================================================
# Section 6: Stoichiometric Mass, Elemental & Enthalpy Residuals (< 1e-10)
# ============================================================================

class TestSection6ConservationResiduals:
    """Tests for rigorous mathematical conservation residuals < 1e-10."""

    def test_total_mass_balance_residual_less_than_1e10(self) -> None:
        """Verify overall stoichiometric mass balance residual is < 1e-10 kg/s."""
        sim = PtaOxidationReactor()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_species_mass_residual_less_than_1e10(self) -> None:
        """Verify atomic elemental mass balance residual is < 1e-10 kg/s."""
        sim = PtaOxidationReactor()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        """Verify thermal enthalpy conservation residual is < 1e-10 kW."""
        sim = PtaOxidationReactor()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_over_extended_simulation(self) -> None:
        """Verify residuals remain < 1e-10 after 100 simulation cycles."""
        sim = PtaOxidationReactor()
        sim.advance_time(duration_s=2.0, dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_under_perturbed_concentrations(self) -> None:
        """Verify residuals remain strictly < 1e-10 under non-nominal concentrations."""
        sim = PtaOxidationReactor()
        sim.state.c_px = 35.0
        sim.state.c_toluic = 20.0
        sim.state.c_4cba = 0.15
        sim.state.c_pta = 1750.0
        sim._update_kinetics_and_conversion()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 7: High PX Conversion (> 99.0%), PTA Yield (> 95.0%) & 4-CBA (< 25 ppm)
# ============================================================================

class TestSection7PerformanceRegime:
    """Tests for p-Xylene conversion (> 99.0%), PTA yield (> 95.0%), and 4-CBA (< 25 ppm)."""

    def test_nominal_px_conversion_exceeds_99_pct(self) -> None:
        """Verify nominal p-xylene conversion is 99.20%, strictly exceeding 99.0% target floor."""
        sim = PtaOxidationReactor()
        assert sim.state.px_conversion_pct > 99.00
        assert abs(sim.state.px_conversion_pct - 99.20) < 0.1
        assert PX_CONVERSION_TARGET_MIN == 99.00

    def test_nominal_pta_yield_exceeds_95_pct(self) -> None:
        """Verify nominal PTA yield is 96.50%, strictly exceeding 95.0% target floor."""
        sim = PtaOxidationReactor()
        assert sim.state.pta_yield_pct > 95.00
        assert abs(sim.state.pta_yield_pct - 96.50) < 0.1
        assert PTA_YIELD_TARGET_MIN == 95.00

    def test_nominal_4cba_impurity_below_25_ppm(self) -> None:
        """Verify nominal 4-CBA impurity concentration is 22.0 ppm, strictly < 25.0 ppm."""
        sim = PtaOxidationReactor()
        assert sim.state.four_cba_impurity_ppm < 25.0
        assert abs(sim.state.four_cba_impurity_ppm - 22.0) < 0.5
        assert FOUR_CBA_TARGET_MAX_PPM == 25.0
        assert CBA_IMPURITY_MAX_PPM == 25.0

    def test_solvent_burn_rate_within_specification(self) -> None:
        """Verify nominal solvent burn rate is 0.45 kg/t PTA, within industrial 0.2-1.0 range."""
        sim = PtaOxidationReactor()
        assert abs(sim.state.solvent_burn_rate_kg_t - 0.45) < 0.1
        assert sim.state.solvent_burn_rate_kg_t <= SOLVENT_BURN_RATE_MAX_KG_T

    def test_higher_unreacted_px_lowers_conversion(self) -> None:
        """Verify unreacted PX accumulation lowers conversion."""
        sim = PtaOxidationReactor()
        sim.state.c_px = 38.12  # 38.12 / 1906 = 2.0% unreacted -> 98.0% conversion
        sim._update_kinetics_and_conversion()
        assert abs(sim.state.px_conversion_pct - 98.00) < 0.1


# ============================================================================
# Section 8: Process Safety Interlocks & Diagnostics in Strict Priority
# ============================================================================

class TestSection8SafetyInterlocksAndPriority:
    """Tests for safety alarms, flammability trips, and strict priority hierarchy (0xEA01..0xEA04)."""

    def test_normal_steady_state_diagnostic_code_ok(self) -> None:
        """Verify diagnostic code is 0x0000 (OK) at nominal steady-state."""
        sim = PtaOxidationReactor()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.OK
        assert sim.state.pta_oxidation_active is True
        assert sim.state.emergency_nitrogen_quench_active is False
        assert sim.state.offgas_oxygen_high_prealarm is False

    def test_priority_1_thermal_runaway_excursion(self) -> None:
        """Verify 0xEA01 asserts when reactor temperature > 225.0 °C (Priority 1)."""
        sim = PtaOxidationReactor()
        sim.state.reactor_temp_celsius = 227.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        assert sim.state.emergency_nitrogen_quench_active is True
        assert sim.state.pta_oxidation_active is False

    def test_priority_2_offgas_o2_explosion_hazard(self) -> None:
        """Verify 0xEA02 asserts when offgas O2 > 4.50 vol% (Priority 2)."""
        sim = PtaOxidationReactor()
        sim.state.offgas_oxygen_vol_pct = 4.65
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.OFFGAS_OXYGEN_EXPLOSION_HAZARD
        assert sim.state.emergency_nitrogen_quench_active is True
        assert sim.state.pta_oxidation_active is False
        assert sim.state.offgas_oxygen_high_prealarm is True

    def test_priority_3_four_cba_impurity_exceeded(self) -> None:
        """Verify 0xEA03 asserts when 4-CBA impurity > 25.0 ppm (Priority 3)."""
        sim = PtaOxidationReactor()
        sim.state.four_cba_impurity_ppm = 26.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.FOUR_CBA_IMPURITY_EXCEEDED
        assert sim.state.emergency_nitrogen_quench_active is False
        assert sim.state.pta_oxidation_active is True

    def test_priority_4_catalyst_precipitation_fault(self) -> None:
        """Verify 0xEA04 asserts when PTA yield < 90.0% (Priority 4)."""
        sim = PtaOxidationReactor()
        sim.state.pta_yield_pct = 88.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.CATALYST_PRECIPITATION_FAULT
        assert sim.state.emergency_nitrogen_quench_active is False
        assert sim.state.pta_oxidation_active is True

    def test_strict_priority_hierarchy_ordering(self) -> None:
        """Verify strict priority ordering: 0xEA01 > 0xEA02 > 0xEA03 > 0xEA04 > 0x0000."""
        sim = PtaOxidationReactor()
        # Activate all fault conditions simultaneously
        sim.state.reactor_temp_celsius = 228.0    # 0xEA01
        sim.state.offgas_oxygen_vol_pct = 4.80   # 0xEA02
        sim.state.four_cba_impurity_ppm = 28.0   # 0xEA03
        sim.state.pta_yield_pct = 85.0           # 0xEA04
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY

        # Clear 0xEA01 -> Priority 2 (0xEA02) must take precedence
        sim.state.reactor_temp_celsius = 200.0
        sim.state.emergency_nitrogen_quench_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.OFFGAS_OXYGEN_EXPLOSION_HAZARD

        # Clear 0xEA02 -> Priority 3 (0xEA03) must take precedence
        sim.state.offgas_oxygen_vol_pct = 2.80
        sim.state.emergency_nitrogen_quench_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.FOUR_CBA_IMPURITY_EXCEEDED

        # Clear 0xEA03 -> Priority 4 (0xEA04) must take precedence
        sim.state.four_cba_impurity_ppm = 22.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.CATALYST_PRECIPITATION_FAULT

        # Clear 0xEA04 -> Normal OK (0x0000)
        sim.state.pta_yield_pct = 96.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.OK

    def test_pre_trip_alarm_coil_m418(self) -> None:
        """Verify %M418 asserts when offgas O2 > 3.80 vol% even before trip at 4.50 vol%."""
        sim = PtaOxidationReactor()
        sim.state.offgas_oxygen_vol_pct = 3.90
        sim._evaluate_safety_interlocks()
        assert sim.state.offgas_oxygen_high_prealarm is True
        assert sim.state.emergency_nitrogen_quench_active is False
        assert sim.state.pta_oxidation_active is True


# ============================================================================
# Section 9: Emergency Cold Acetic Acid Quench & Nitrogen Deluge (> 225 °C)
# ============================================================================

class TestSection9EmergencyQuenchAndDeluge:
    """Tests for emergency cold quench cooling and nitrogen deluge on runaway (> 225 °C)."""

    def test_emergency_quench_coil_m419_asserts_on_0xea01(self) -> None:
        """Verify %M419 asserts on 0xEA01 (> 225 °C)."""
        sim = PtaOxidationReactor()
        sim.state.reactor_temp_celsius = 226.5
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_nitrogen_quench_active is True
        assert sim.state.emergency_quench_active is True

    def test_emergency_quench_coil_m419_asserts_on_0xea02(self) -> None:
        """Verify %M419 asserts on 0xEA02."""
        sim = PtaOxidationReactor()
        sim.state.offgas_oxygen_vol_pct = 4.60
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_nitrogen_quench_active is True

    def test_reaction_active_coil_m417_clears_on_trip(self) -> None:
        """Verify %M417 PtaOxidationActive is cleared (False) under trip."""
        sim = PtaOxidationReactor()
        sim.state.reactor_temp_celsius = 227.0
        sim._evaluate_safety_interlocks()
        assert sim.state.pta_oxidation_active is False

    def test_quench_cooling_duty_activation(self) -> None:
        """Verify quench cooling duty (85 MW) activates when quench is triggered."""
        sim = PtaOxidationReactor()
        sim.state.emergency_nitrogen_quench_active = True
        sim._update_kinetics_and_conversion()
        assert sim.state.q_quench_kw == sim.config.quench_cooling_duty_kw

    def test_emergency_nitrogen_purge_flow(self) -> None:
        """Verify emergency N2 deluge purge flow sweeps reactor vapor space."""
        sim = PtaOxidationReactor()
        mt = sim.compute_mass_transfer(0.352, 473.15, 18.0, is_tripped=True)
        assert mt["n2_feed_mol_s"] == sim.config.nitrogen_purge_flow_mol_s

    def test_thermal_recovery_under_cold_quench(self) -> None:
        """Verify reactor temperature drops rapidly below reset threshold under active quench."""
        sim = PtaOxidationReactor()
        sim.state.reactor_temp_celsius = 230.0
        sim.state.t_reactor = 230.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_nitrogen_quench_active is True

        sim.advance_time(duration_s=8.0, dt=0.02)
        assert sim.state.reactor_temp_celsius < 220.0


# ============================================================================
# Section 10: Horner OCS Memory Space Integration (%R1790..%R1797, %M417..%M419)
# ============================================================================

class TestSection10HornerMemoryMap:
    """Tests for register synchronization, scaling, and SYSTEM privilege writes."""

    def test_analog_registers_scaling_and_values(self) -> None:
        """Verify analog registers %R1790..%R1796 write exact scaled values."""
        reg = RegisterTable()
        sim = PtaOxidationReactor(register_table=reg)

        sim.state.reactor_temp_celsius = 200.0
        sim.state.reactor_pressure_bar = 18.00
        sim.state.px_conversion_pct = 99.20
        sim.state.pta_yield_pct = 96.50
        sim.state.four_cba_impurity_ppm = 22.0
        sim.state.offgas_oxygen_vol_pct = 2.80
        sim.state.solvent_burn_rate_kg_t = 0.45
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1790") == 2000
        assert reg.read_word("%R1791") == 1800
        assert reg.read_word("%R1792") == 9920
        assert reg.read_word("%R1793") == 9650
        assert reg.read_word("%R1794") == 22
        assert reg.read_word("%R1795") == 280
        assert reg.read_word("%R1796") == 45

    def test_diagnostic_status_code_register_r1797(self) -> None:
        """Verify %R1797 reflects diagnostic code."""
        reg = RegisterTable()
        sim = PtaOxidationReactor(register_table=reg)

        sim.state.diagnostic_code = PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_uword("%R1797") == 0xEA01

    def test_discrete_coils_synchronization(self) -> None:
        """Verify discrete coils %M417..%M419 match boolean state."""
        reg = RegisterTable()
        sim = PtaOxidationReactor(register_table=reg)

        sim.state.pta_oxidation_active = True
        sim.state.offgas_oxygen_high_prealarm = False
        sim.state.emergency_nitrogen_quench_active = False
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M417") is True
        assert reg.read_bit("%M418") is False
        assert reg.read_bit("%M419") is False

    def test_system_privilege_mode_enforcement(self) -> None:
        """Verify write with PrivilegeMode.SYSTEM succeeds."""
        reg = RegisterTable()
        sim = PtaOxidationReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_word("%R1790") == 2000

    def test_register_sync_under_trip_conditions(self) -> None:
        """Verify registers and coils under emergency trip."""
        reg = RegisterTable()
        sim = PtaOxidationReactor(register_table=reg)
        sim.state.reactor_temp_celsius = 228.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_uword("%R1797") == 0xEA01
        assert reg.read_bit("%M417") is False
        assert reg.read_bit("%M419") is True

    def test_status_word_bitmask_consistency(self) -> None:
        """Verify status word bitmask reflects active alarms and states."""
        sim = PtaOxidationReactor()
        sim.state.reactor_temp_celsius = 228.0
        sim._evaluate_safety_interlocks()
        assert sim.state.status_word & PtaOxidationStatusBits.THERMAL_RUNAWAY_TRIP
        assert sim.state.status_word & PtaOxidationStatusBits.EMERGENCY_QUENCH_ACTIVE
        assert not (sim.state.status_word & PtaOxidationStatusBits.PTA_OXIDATION_ACTIVE)


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text & Anti-Ladder Security Guard
# ============================================================================

class TestSection11PureSTAndSecurityGuard:
    """Tests for pure Structured Text compliance, AST parsing, and ladder rejection."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify PTA Oxidation ST POU parses into valid AST PROGRAM structure."""
        SecurityGuard.assert_pure_st_content(PTA_OXIDATION_REACTOR_PURE_ST_POU)
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(PTA_OXIDATION_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "PtaOxidationSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_pou_name_and_type(self) -> None:
        """Verify program name and type match IEC standards."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(PTA_OXIDATION_REACTOR_PURE_ST_POU)
        assert ast.name == "PtaOxidationSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_bound_registers(self) -> None:
        """Verify all %R1790..%R1797 and %M417..%M419 are bound in ST POU."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(PTA_OXIDATION_REACTOR_PURE_ST_POU)
        expected_regs = [
            "%R1790", "%R1791", "%R1792", "%R1793",
            "%R1794", "%R1795", "%R1796", "%R1797",
            "%M417", "%M418", "%M419",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_security_guard_assert_pure_st_valid(self) -> None:
        """Verify SecurityGuard accepts pure Structured Text without exception."""
        SecurityGuard.assert_pure_st_content(PTA_OXIDATION_REACTOR_PURE_ST_POU)

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
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nXIC PtaOxidationActive\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 12: ILogicUnit Scan Cycle Execution, Reset & Soak Stability
# ============================================================================

class TestSection12ILogicUnitIntegration:
    """Tests for ILogicUnit scan cycle execution, reset dynamics, and soak stability."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify PtaOxidationReactor exposes required ILogicUnit properties."""
        sim = PtaOxidationReactor()
        assert sim.name == "PtaOxidationSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_with_scan_context(self) -> None:
        """Verify scan_step executes and writes to context.registers."""
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=20.0)
        setattr(ctx, "registers", reg)
        sim = PtaOxidationReactor()
        sim.scan_step(dt=0.02, context=ctx)
        assert reg.read_word("%R1790") == 2000

    def test_adapter_logic_unit_execution(self) -> None:
        """Verify PtaOxidationReactorLogicUnit adapter executes within engine."""
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=20.0)
        setattr(ctx, "registers", reg)
        unit = PtaOxidationReactorLogicUnit(register_table=reg)
        unit.execute(ctx)
        assert reg.read_word("%R1790") == 2000

    def test_reset_restores_nominal_state(self) -> None:
        """Verify reset() restores nominal baseline state."""
        sim = PtaOxidationReactor()
        sim.state.reactor_temp_celsius = 228.0
        sim.state.emergency_nitrogen_quench_active = True
        sim.reset()
        assert abs(sim.state.reactor_temp_celsius - 200.0) < 1e-2
        assert sim.state.emergency_nitrogen_quench_active is False
        assert sim.state.diagnostic_code == PtaOxidationDiagnosticCode.OK

    def test_multi_cycle_soak_execution(self) -> None:
        """Verify 100 continuous scan cycles execute without drift or error."""
        sim = PtaOxidationReactor()
        for _ in range(100):
            sim.scan_step(dt=0.02)
        assert sim.state.scan_count == 100
        assert abs(sim.state.sim_time_s - 2.0) < 1e-4
        assert 190.0 <= sim.state.reactor_temp_celsius <= 210.0


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite & Runner Integration
# ============================================================================

class TestSection13VerificationSuiteAndArtifacts:
    """Tests for 9-stage verification runner, JSON export, and component aliases."""

    def test_run_pta_oxidation_reactor_verification_status_success(self) -> None:
        """Verify 9-stage verification suite passes with strict 4-state success contract."""
        res = run_pta_oxidation_reactor_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W218"
        assert res["data"]["module"] == "pta_oxidation_reactor"
        assert res["data"]["total_checks"] == 9
        assert res["data"]["checks_passed"] == 9

    def test_all_9_verification_stages_passed(self) -> None:
        """Verify all 9 stages passed deterministically."""
        res = run_pta_oxidation_reactor_verification()
        tests = res["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True

    def test_verification_json_export(self, tmp_path: Path) -> None:
        """Verify JSON evidence artifact is created and valid on disk."""
        out_file = tmp_path / "pta_evidence.json"
        res = run_pta_oxidation_reactor_verification(output_path=out_file)
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_aliases(self) -> None:
        """Verify all verification runner aliases return identical success."""
        r1 = run_pta_oxidation_verification()
        r2 = run_pta_reactor_verification()
        r3 = run_pta_verification()
        assert r1["status"] == "success"
        assert r2["status"] == "success"
        assert r3["status"] == "success"

    def test_helper_verification_functions(self) -> None:
        """Verify helper validation functions return True / SUCCESS."""
        assert verify_pta_oxidation_reactor_pure_st() is True
        assert verify_pta_oxidation_pure_st() is True
        assert verify_pta_reactor_pure_st() is True
        assert verify_pta_pure_st() is True
        res = validate_pure_st()
        assert res.status == AgentStatus.SUCCESS
        assert validate_pta_pure_st().status == AgentStatus.SUCCESS

    def test_class_and_constant_aliases(self) -> None:
        """Verify model, state, config, and diagnostic aliases point to canonical definitions."""
        assert PtaReactor is PtaOxidationReactor
        assert PtaSimulator is PtaOxidationReactor
        assert PtaOxidationReactorEngine is PtaOxidationReactor
        assert PtaConfig is PtaOxidationConfig
        assert PtaParameters is PtaOxidationConfig
        assert PtaState is PtaOxidationState
        assert PtaDiagCode is PtaOxidationDiagnosticCode
        assert PtaStatusBits is PtaOxidationStatusBits
        assert PtaLogicUnit is PtaOxidationReactorLogicUnit
        assert PTA_PURE_ST_POU == PTA_OXIDATION_REACTOR_PURE_ST_POU
        assert PTA_SYNC_POU == PTA_OXIDATION_REACTOR_PURE_ST_POU
        assert PTA_REACTOR_PURE_ST_POU == PTA_OXIDATION_REACTOR_PURE_ST_POU
        assert PTA_REACTOR_SYNC_POU == PTA_OXIDATION_REACTOR_PURE_ST_POU
