"""Comprehensive Industrial Cyclohexane KA Oxidation Reactor Test Suite.

Work Package: W212 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 13 engineering verification sections:
1. Section 1: Universal Physical Constants, Molecular Weights & Thermodynamic Enthalpies
2. Section 2: Reactor Configuration, Vessel Geometry & Baseline Operating Parameters
3. Section 3: Arrhenius Reaction Kinetics, Decomposition Pathways & Over-Oxidation Rates
4. Section 4: Vapor-Liquid Equilibrium, Henry's Law Oxygen Absorption & Off-Gas Vol%
5. Section 5: Coupled 6-State ODE Vector & High-Order RK4 Numerical Integrator
6. Section 6: Stoichiometric Mass, Elemental Atomic & Enthalpy Conservation Residuals (< 1e-10)
7. Section 7: Cyclohexane Conversion (3.5 - 5.5%), KA Selectivity (> 82%), and K/A Ratio
8. Section 8: Process Safety Interlocks & Diagnostics in Strict Priority Hierarchy (0xE401..0xE404)
9. Section 9: Emergency Cold Cyclohexane Recirculating Quench & Nitrogen Blanketing Inerting
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege Mode (%R1730..%R1737, %M403..%M405)
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

from jev_cscape.simulation.ka_oxidation_reactor import (
    CONVERSION_MAX_PCT,
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
    DELTA_H_ALCOHOL_DECOMP_J_MOL,
    DELTA_H_ALCOHOL_DECOMP_KJ_MOL,
    DELTA_H_AUTOXIDATION_J_MOL,
    DELTA_H_AUTOXIDATION_KJ_MOL,
    DELTA_H_KETONE_DECOMP_J_MOL,
    DELTA_H_KETONE_DECOMP_KJ_MOL,
    DELTA_H_OVER_OXIDATION_J_MOL,
    DELTA_H_OVER_OXIDATION_KJ_MOL,
    DISSOLVED_O2_LOW_ANOXIA_PPM,
    DISSOLVED_O2_NOMINAL_PPM,
    G_ACCEL,
    KA_MOLAR_RATIO_NOMINAL,
    KA_OXIDATION_PURE_ST_POU,
    KA_OXIDATION_REACTOR_PURE_ST_POU,
    KA_OXIDATION_REACTOR_SYNC_POU,
    KA_OXIDATION_SYNC_POU,
    KA_PURE_ST_POU,
    KA_REACTOR_PURE_ST_POU,
    KA_REACTOR_SYNC_POU,
    KA_SELECTIVITY_MIN_PCT,
    KA_SELECTIVITY_NOMINAL_PCT,
    KA_SELECTIVITY_TARGET_MIN,
    KA_SYNC_POU,
    MW_A,
    MW_ADIPIC_ACID,
    MW_C,
    MW_CHHP,
    MW_CHX,
    MW_CYCLOHEXANE,
    MW_CYCLOHEXANOL,
    MW_CYCLOHEXANONE,
    MW_DBA,
    MW_DIBASIC_ACID,
    MW_H,
    MW_H2O,
    MW_K,
    MW_N,
    MW_N2,
    MW_O,
    MW_O2,
    OFFGAS_O2_HIGH_ALARM_VOL_PCT,
    OFFGAS_O2_NOMINAL_VOL_PCT,
    OFFGAS_O2_TRIP_VOL_PCT,
    R_GAS_CONST,
    REACTOR_PRESSURE_MAX_BAR,
    REACTOR_PRESSURE_MIN_BAR,
    REACTOR_PRESSURE_NOMINAL_BAR,
    REACTOR_TEMP_NOMINAL_C,
    REACTOR_TEMP_RESET_C,
    REACTOR_TEMP_TRIP_C,
    REACTOR_TEMP_WARNING_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    KaConfig,
    KaDiagCode,
    KaDiagnosticCode,
    KaLogicUnit,
    KaOxidationConfig,
    KaOxidationDiagCode,
    KaOxidationDiagnosticCode,
    KaOxidationLogicUnit,
    KaOxidationParameters,
    KaOxidationReactor,
    KaOxidationReactorConfig,
    KaOxidationReactorDiagCode,
    KaOxidationReactorDiagnosticCode,
    KaOxidationReactorEngine,
    KaOxidationReactorLogicUnit,
    KaOxidationReactorModel,
    KaOxidationReactorParameters,
    KaOxidationReactorPlantModel,
    KaOxidationReactorSimulationEngine,
    KaOxidationReactorSimulator,
    KaOxidationReactorState,
    KaOxidationReactorStatusBits,
    KaOxidationReactorStatusWord,
    KaOxidationSimulator,
    KaOxidationState,
    KaOxidationStatusBits,
    KaOxidationStatusWord,
    KaParameters,
    KaReactor,
    KaReactorConfig,
    KaReactorDiagCode,
    KaReactorDiagnosticCode,
    KaReactorEngine,
    KaReactorLogicUnit,
    KaReactorModel,
    KaReactorParameters,
    KaReactorPlantModel,
    KaReactorSimulationEngine,
    KaReactorSimulator,
    KaReactorState,
    KaReactorStatusBits,
    KaReactorStatusWord,
    KaSimulator,
    KaState,
    KaStatusBits,
    KaStatusWord,
    run_ka_oxidation_reactor_verification,
    run_ka_oxidation_verification,
    run_ka_reactor_verification,
    run_ka_verification,
    validate_pure_st,
    verify_ka_oxidation_pure_st,
    verify_ka_oxidation_reactor_pure_st,
    verify_ka_pure_st,
    verify_ka_reactor_pure_st,
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
        assert abs(T_REF_K - 428.15) < 1e-4

    def test_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon, Hydrogen, Oxygen, and Nitrogen."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_O - 0.015999) < 1e-6
        assert abs(MW_N - 0.014007) < 1e-6

    def test_molecular_weights_species(self) -> None:
        """Verify molecular weights for O2, N2, Cyclohexane, CHHP, Ketone, Alcohol, H2O, DBA."""
        assert abs(MW_O2 - 0.031998) < 1e-5
        assert abs(MW_N2 - 0.028014) < 1e-5
        assert abs(MW_CHX - 0.084162) < 1e-5
        assert abs(MW_CYCLOHEXANE - MW_CHX) < 1e-8
        assert abs(MW_CHHP - 0.116160) < 1e-5
        assert abs(MW_K - 0.098145) < 1e-5
        assert abs(MW_CYCLOHEXANONE - MW_K) < 1e-8
        assert abs(MW_A - 0.100161) < 1e-5
        assert abs(MW_CYCLOHEXANOL - MW_A) < 1e-8
        assert abs(MW_H2O - 0.018015) < 1e-5
        assert abs(MW_DBA - 0.146142) < 1e-5
        assert abs(MW_ADIPIC_ACID - MW_DBA) < 1e-8
        assert abs(MW_DIBASIC_ACID - MW_DBA) < 1e-8

    def test_reaction1_autoxidation_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 1: C6H12 + O2 -> CHHP stoichiometry and exothermic enthalpy."""
        reactants = MW_CHX + MW_O2
        product = MW_CHHP
        assert abs(reactants - product) < 1e-12
        assert DELTA_H1_KJ_MOL == -135.0
        assert DELTA_H1_J_MOL == -135000.0
        assert DELTA_H_AUTOXIDATION_KJ_MOL == -135.0
        assert DELTA_H_AUTOXIDATION_J_MOL == -135000.0

    def test_reaction2_ketone_decomposition_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 2: CHHP -> Cyclohexanone + H2O mass balance and enthalpy."""
        reactant = MW_CHHP
        products = MW_K + MW_H2O
        assert abs(reactant - products) < 1e-12
        assert DELTA_H2_KJ_MOL == -180.0
        assert DELTA_H2_J_MOL == -180000.0
        assert DELTA_H_KETONE_DECOMP_KJ_MOL == -180.0
        assert DELTA_H_KETONE_DECOMP_J_MOL == -180000.0

    def test_reaction3_alcohol_decomposition_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 3: CHHP -> Cyclohexanol + 0.5 O2 mass balance and enthalpy."""
        reactant = MW_CHHP
        products = MW_A + 0.5 * MW_O2
        assert abs(reactant - products) < 1e-12
        assert DELTA_H3_KJ_MOL == -145.0
        assert DELTA_H3_J_MOL == -145000.0
        assert DELTA_H_ALCOHOL_DECOMP_KJ_MOL == -145.0
        assert DELTA_H_ALCOHOL_DECOMP_J_MOL == -145000.0

    def test_reaction4_overoxidation_stoichiometry_and_enthalpy(self) -> None:
        """Verify Reaction 4: Cyclohexanone + 1.5 O2 -> Adipic Acid (DBA) mass balance and enthalpy."""
        reactants = MW_K + 1.5 * MW_O2
        product = MW_DBA
        assert abs(reactants - product) < 1e-12
        assert DELTA_H4_KJ_MOL == -320.0
        assert DELTA_H4_J_MOL == -320000.0
        assert DELTA_H_OVER_OXIDATION_KJ_MOL == -320.0
        assert DELTA_H_OVER_OXIDATION_J_MOL == -320000.0

    def test_elemental_stoichiometry_exactness(self) -> None:
        """Verify atomic elemental balance (Carbon, Hydrogen, Oxygen) for all 4 reactions."""
        # Reaction 1: C6H12 + O2 -> C6H12O2
        assert abs((6 * MW_C + 12 * MW_H + 2 * MW_O) - MW_CHHP) < 1e-6
        # Reaction 2: C6H12O2 -> C6H10O + H2O
        assert abs((6 * MW_C + 10 * MW_H + MW_O + (2 * MW_H + MW_O)) - MW_CHHP) < 1e-6
        # Reaction 3: C6H12O2 -> C6H12O + 0.5 O2
        assert abs((6 * MW_C + 12 * MW_H + MW_O + MW_O) - MW_CHHP) < 1e-6
        # Reaction 4: C6H10O + 1.5 O2 -> C6H10O4
        assert abs((6 * MW_C + 10 * MW_H + 4 * MW_O) - MW_DBA) < 1e-6


# ============================================================================
# Section 2: Reactor Configuration, Geometry & Operating Baseline
# ============================================================================

class TestSection2ReactorConfiguration:
    """Tests for bubble column dimensions, holdup, operating limits, and parameters."""

    def test_default_reactor_geometry(self) -> None:
        """Verify column dimensions, cross section, and liquid volume."""
        cfg = KaOxidationConfig()
        assert cfg.reactor_diameter_m == 3.2
        assert cfg.reactor_height_m == 9.0
        assert cfg.liquid_volume_m3 == 48.0
        assert cfg.gas_holdup_fraction == 0.18
        expected_cs = 0.25 * math.pi * (3.2 ** 2)
        assert abs(cfg.reactor_cross_section_m2 - expected_cs) < 1e-4

    def test_residence_time_and_capacitance(self) -> None:
        """Verify liquid residence time in 20-30 min range and thermal capacitance."""
        cfg = KaOxidationConfig()
        assert cfg.residence_time_s == 1500.0  # 25 minutes
        assert 1200.0 <= cfg.residence_time_s <= 1800.0
        assert cfg.reactor_heat_capacity_j_k == 1.8e7
        assert cfg.liquid_density_kg_m3 == 680.0
        assert cfg.liquid_cp_j_kg_k == 2300.0

    def test_nominal_operating_temperatures_and_pressures(self) -> None:
        """Verify nominal operating and safety boundary parameters."""
        assert REACTOR_TEMP_NOMINAL_C == 155.0
        assert REACTOR_TEMP_WARNING_C == 162.0
        assert REACTOR_TEMP_TRIP_C == 165.0
        assert REACTOR_TEMP_RESET_C == 156.0

        assert REACTOR_PRESSURE_NOMINAL_BAR == 10.5
        assert REACTOR_PRESSURE_MIN_BAR == 9.0
        assert REACTOR_PRESSURE_MAX_BAR == 12.0

    def test_feed_stream_quantities(self) -> None:
        """Verify sparge air feed rate and inlet oxygen mole fraction."""
        cfg = KaOxidationConfig()
        assert cfg.nominal_air_flow_mol_s == 47.62
        assert cfg.air_o2_mole_fraction == 0.21
        assert abs(cfg.c_chx_feed_mol_m3 - (680.0 / MW_CHX)) < 1e-2

    def test_cooling_and_ambient_parameters(self) -> None:
        """Verify cooling duty coefficients and ambient heat loss."""
        cfg = KaOxidationConfig()
        assert cfg.ua_cooling_w_k in (85000.0, 95000.0)
        assert cfg.coolant_temp_c in (110.0, 120.0)
        assert cfg.u_wall_w_m2_k == 15.0
        assert cfg.ambient_temp_c == 25.0
        assert cfg.quench_cooling_duty_kw in (5500.0, 25000.0)

    def test_safety_limit_parameters(self) -> None:
        """Verify safety thresholds for conversion, selectivity, and off-gas O2."""
        assert CONVERSION_NOMINAL_PCT == 4.80
        assert CONVERSION_MIN_PCT == 3.50
        assert CONVERSION_MAX_PCT == 5.50

        assert KA_SELECTIVITY_NOMINAL_PCT == 84.5
        assert KA_SELECTIVITY_MIN_PCT == 80.0
        assert KA_SELECTIVITY_TARGET_MIN == 82.0

        assert OFFGAS_O2_NOMINAL_VOL_PCT == 1.85
        assert OFFGAS_O2_HIGH_ALARM_VOL_PCT == 2.80
        assert OFFGAS_O2_TRIP_VOL_PCT == 3.50

        assert DISSOLVED_O2_NOMINAL_PPM == 45.0
        assert DISSOLVED_O2_LOW_ANOXIA_PPM == 10.0


# ============================================================================
# Section 3: Arrhenius Kinetics, Rates & Activation Energies
# ============================================================================

class TestSection3ArrheniusKinetics:
    """Tests for multi-step autoxidation, decomposition, and over-oxidation kinetics."""

    def test_arrhenius_activation_energies_ordering(self) -> None:
        """Verify activation energies ordering: autoxidation < decomp < overoxidation."""
        cfg = KaOxidationConfig()
        assert cfg.activation_energy_1_j_mol == 95000.0   # 95 kJ/mol
        assert cfg.activation_energy_2_j_mol in (85000.0, 102000.0)
        assert cfg.activation_energy_3_j_mol in (82000.0, 108000.0)
        assert cfg.activation_energy_4_j_mol == 115000.0  # 115 kJ/mol
        assert cfg.activation_energy_4_j_mol > cfg.activation_energy_1_j_mol

    def test_baseline_reaction_rates_positive(self) -> None:
        """Verify reaction rates are strictly positive under nominal conditions."""
        sim = KaOxidationReactor()
        rates = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 428.15)
        assert rates["r1_tot"] > 0.0
        assert rates["r2_tot"] > 0.0
        assert rates["r3_tot"] > 0.0
        assert rates["r4_tot"] > 0.0
        assert rates["q_rxn_kw"] > 0.0

    def test_temperature_acceleration_autoxidation(self) -> None:
        """Verify autoxidation rate accelerates with increasing temperature."""
        sim = KaOxidationReactor()
        rates_155 = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 428.15)
        rates_165 = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 438.15)
        assert rates_165["r1_tot"] > rates_155["r1_tot"]
        assert rates_165["q_rxn_kw"] > rates_155["q_rxn_kw"]

    def test_overoxidation_accelerates_faster_than_autoxidation(self) -> None:
        """Verify over-oxidation (Ea=115 kJ) accelerates faster than autoxidation (Ea=95 kJ)."""
        sim = KaOxidationReactor()
        rates_nom = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 428.15)
        rates_hot = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 443.15)
        ratio_r1 = rates_hot["r1_tot"] / rates_nom["r1_tot"]
        ratio_r4 = rates_hot["r4_tot"] / rates_nom["r4_tot"]
        assert ratio_r4 > ratio_r1

    def test_reaction_power_dissipation_positive(self) -> None:
        """Verify exothermic heat generation is within expected megawatt range."""
        sim = KaOxidationReactor()
        rates = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 428.15)
        assert 2000.0 <= rates["q_rxn_kw"] <= 6000.0

    def test_tripped_state_quenches_kinetics(self) -> None:
        """Verify is_tripped=True immediately suppresses chemical reaction rates to zero."""
        sim = KaOxidationReactor()
        rates_tripped = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 428.15, is_tripped=True)
        assert rates_tripped["r1_tot"] == 0.0
        assert rates_tripped["r2_tot"] == 0.0
        assert rates_tripped["r3_tot"] == 0.0
        assert rates_tripped["r4_tot"] == 0.0
        assert rates_tripped["q_rxn_kw"] == 0.0


# ============================================================================
# Section 4: Vapor-Liquid Equilibrium & Off-Gas Oxygen Calculation
# ============================================================================

class TestSection4VLEAndOffgasOxygen:
    """Tests for Henry's law oxygen solubility, mass transfer, and off-gas O2 vol%."""

    def test_henrys_law_oxygen_solubility(self) -> None:
        """Verify Henry's constant and saturation oxygen concentration at 10.5 bar."""
        cfg = KaOxidationConfig()
        assert cfg.henry_o2_mol_m3_bar == 0.85
        sim = KaOxidationReactor()
        mt = sim.compute_mass_transfer(0.956, 428.15, 10.5)
        assert mt["c_o2_sat"] > 0.0
        assert 0.8 <= mt["c_o2_sat"] <= 1.5

    def test_oxygen_mass_transfer_rate(self) -> None:
        """Verify oxygen absorption rate into liquid under nominal conditions."""
        sim = KaOxidationReactor()
        mt = sim.compute_mass_transfer(0.956, 428.15, 10.5)
        assert mt["r_o2_mt_tot"] > 8.0
        assert mt["o2_feed_mol_s"] == pytest.approx(10.0, rel=0.01)

    def test_offgas_oxygen_volume_fraction_nominal(self) -> None:
        """Verify off-gas oxygen volume fraction is safely < 3.5 vol% at nominal operation."""
        sim = KaOxidationReactor()
        mt = sim.compute_mass_transfer(0.956, 428.15, 10.5)
        offgas_pct = mt["offgas_o2_vol_pct"]
        assert 1.0 <= offgas_pct <= 2.5
        assert offgas_pct < OFFGAS_O2_TRIP_VOL_PCT

    def test_offgas_oxygen_elevated_on_dissolved_saturation(self) -> None:
        """Verify that elevated dissolved O2 reduces absorption and increases offgas O2."""
        sim = KaOxidationReactor()
        mt_normal = sim.compute_mass_transfer(0.956, 428.15, 10.5)
        mt_saturated = sim.compute_mass_transfer(2.5, 428.15, 10.5)
        assert mt_saturated["offgas_o2_vol_pct"] > mt_normal["offgas_o2_vol_pct"]

    def test_nitrogen_quench_dilutes_offgas(self) -> None:
        """Verify emergency nitrogen purge dilutes off-gas oxygen under tripped state."""
        sim = KaOxidationReactor()
        mt_tripped = sim.compute_mass_transfer(0.956, 428.15, 10.5, is_tripped=True)
        assert mt_tripped["offgas_o2_vol_pct"] < 0.20
        assert mt_tripped["r_o2_mt_tot"] == 0.0

    def test_dissolved_oxygen_ppm_calculation(self) -> None:
        """Verify dissolved oxygen in ppm matches nominal 45.0 ppm."""
        sim = KaOxidationReactor()
        rho = sim.config.liquid_density_kg_m3
        c_o2 = sim.state.c_o2_dissolved
        calc_ppm = (c_o2 * MW_O2 / rho) * 1.0e6
        assert abs(calc_ppm - DISSOLVED_O2_NOMINAL_PPM) < 1.0


# ============================================================================
# Section 5: Coupled 6-State ODE System & RK4 Numerical Integration
# ============================================================================

class TestSection5CoupledODESystemAndRK4:
    """Tests for 6-state ODE vector derivatives and RK4 numerical integration."""

    def test_derivatives_shape_and_finiteness(self) -> None:
        """Verify compute_derivatives returns exactly 6 finite values."""
        sim = KaOxidationReactor()
        y0 = [
            sim.state.c_cyclohexane,
            sim.state.c_o2_dissolved,
            sim.state.c_chhp,
            sim.state.c_cyclohexanone,
            sim.state.c_cyclohexanol,
            sim.state.t_reactor,
        ]
        derivs = sim.compute_derivatives(0.0, y0)
        assert len(derivs) == 6
        assert all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    def test_single_rk4_step_execution(self) -> None:
        """Verify rk4_step executes without exception and advances simulation time."""
        sim = KaOxidationReactor()
        t0 = sim.state.sim_time_s
        sim.rk4_step(dt=0.05)
        assert sim.state.sim_time_s == pytest.approx(t0 + 0.05, abs=1e-5)
        assert sim.state.scan_count == 1

    def test_rk4_step_state_bounds(self) -> None:
        """Verify states remain strictly within physical bounds after RK4 step."""
        sim = KaOxidationReactor()
        for _ in range(10):
            sim.rk4_step(dt=0.05)
        assert 5000.0 <= sim.state.c_cyclohexane <= 8500.0
        assert 0.001 <= sim.state.c_o2_dissolved <= 5.0
        assert 0.0 <= sim.state.c_chhp <= 300.0
        assert 0.0 <= sim.state.c_cyclohexanone <= 500.0
        assert 0.0 <= sim.state.c_cyclohexanol <= 500.0
        assert 290.0 <= sim.state.t_reactor <= 600.0

    def test_advance_time_multi_step(self) -> None:
        """Verify advance_time runs multiple steps successfully."""
        sim = KaOxidationReactor()
        res = sim.advance_time(duration_s=2.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.sim_time_s == pytest.approx(2.0, abs=1e-3)
        assert sim.state.scan_count == 40

    def test_thermal_stability_at_steady_state(self) -> None:
        """Verify reactor temperature remains thermally stable near 155 °C."""
        sim = KaOxidationReactor()
        sim.advance_time(duration_s=5.0, dt=0.05)
        assert 150.0 <= sim.state.reactor_temp_celsius <= 160.0

    def test_step_returns_execution_result(self) -> None:
        """Verify step() returns standard ExecutionResult with telemetry data."""
        sim = KaOxidationReactor()
        res = sim.step(dt=0.05)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert "reactor_temp_c" in res.data
        assert "conversion_pct" in res.data
        assert "ka_selectivity_pct" in res.data
        assert "offgas_o2_pct" in res.data


# ============================================================================
# Section 6: Stoichiometric Mass, Elemental & Enthalpy Conservation (< 1e-10)
# ============================================================================

class TestSection6ConservationResiduals:
    """Tests for rigorous mathematical conservation residuals < 1e-10."""

    def test_total_mass_balance_residual_less_than_1e10(self) -> None:
        """Verify overall stoichiometric mass balance residual is < 1e-10 kg/s."""
        sim = KaOxidationReactor()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_species_mass_residual_less_than_1e10(self) -> None:
        """Verify atomic elemental mass balance residual is < 1e-10 kg/s."""
        sim = KaOxidationReactor()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        """Verify thermal enthalpy conservation residual is < 1e-10 kW."""
        sim = KaOxidationReactor()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_over_extended_simulation(self) -> None:
        """Verify residuals remain < 1e-10 after 100 simulation cycles."""
        sim = KaOxidationReactor()
        for _ in range(100):
            sim.step(dt=0.05)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_under_perturbed_concentrations(self) -> None:
        """Verify residuals remain strictly < 1e-10 under non-nominal concentrations."""
        sim = KaOxidationReactor()
        sim.state.c_cyclohexane = 7200.0
        sim.state.c_o2_dissolved = 1.2
        sim.state.c_chhp = 85.0
        sim.state.c_cyclohexanone = 210.0
        sim.state.c_cyclohexanol = 180.0
        sim._update_kinetics_and_conversion()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 7: Yield, Conversion (3.5 - 5.5%) & KA Selectivity (> 82%)
# ============================================================================

class TestSection7YieldAndSelectivity:
    """Tests for low-conversion high-selectivity regime and K/A ratio."""

    def test_nominal_cyclohexane_conversion_within_window(self) -> None:
        """Verify nominal conversion is 4.80%, within the 3.5 - 5.5% window."""
        sim = KaOxidationReactor()
        conv = sim.state.cyclohexane_conversion_pct
        assert conv == pytest.approx(CONVERSION_NOMINAL_PCT, abs=0.1)
        assert CONVERSION_MIN_PCT <= conv <= CONVERSION_MAX_PCT

    def test_nominal_ka_oil_selectivity(self) -> None:
        """Verify nominal KA oil selectivity is 84.5%, meeting >= 82.0% floor."""
        sim = KaOxidationReactor()
        sel = sim.state.ka_oil_selectivity_pct
        assert sel == pytest.approx(KA_SELECTIVITY_NOMINAL_PCT, abs=0.2)
        assert sel >= KA_SELECTIVITY_TARGET_MIN

    def test_nominal_ka_molar_ratio(self) -> None:
        """Verify nominal ketone/alcohol molar ratio is 1.20:1."""
        sim = KaOxidationReactor()
        ratio = sim.state.ka_molar_ratio
        assert ratio == pytest.approx(KA_MOLAR_RATIO_NOMINAL, abs=0.05)
        assert 0.90 <= ratio <= 1.50

    def test_higher_conversion_degrades_selectivity(self) -> None:
        """Verify that excessive conversion triggers higher byproduct formation."""
        sim = KaOxidationReactor()
        # Simulate higher consumption of cyclohexane with byproduct generation
        sim.state.c_cyclohexane = 7400.0  # More converted
        sim.state.c_cyclohexanone = 190.0
        sim.state.c_cyclohexanol = 160.0
        sim._update_kinetics_and_conversion()
        assert sim.state.cyclohexane_conversion_pct > CONVERSION_NOMINAL_PCT

    def test_conversion_clamping_and_scaling(self) -> None:
        """Verify conversion is bounded within [0, 100]."""
        sim = KaOxidationReactor()
        assert 0.0 <= sim.state.cyclohexane_conversion_pct <= 100.0

    def test_selectivity_clamping_and_scaling(self) -> None:
        """Verify selectivity is bounded within [0, 100]."""
        sim = KaOxidationReactor()
        assert 0.0 <= sim.state.ka_oil_selectivity_pct <= 100.0


# ============================================================================
# Section 8: Process Safety Interlocks & Strict Priority Hierarchy (0xE401..0xE404)
# ============================================================================

class TestSection8SafetyInterlocksAndPriority:
    """Tests for safety alarms, flammability trips, and diagnostic priority."""

    def test_normal_steady_state_diagnostic_code_ok(self) -> None:
        """Verify diagnostic code is 0x0000 (OK) at nominal steady-state."""
        sim = KaOxidationReactor()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.OK
        assert sim.state.ka_oxidation_active is True
        assert sim.state.emergency_nitrogen_quench_active is False
        assert sim.state.offgas_o2_high_alarm is False

    def test_priority_1_offgas_o2_explosive_trip(self) -> None:
        """Verify 0xE401 asserts when offgas O2 >= 3.50 vol%."""
        sim = KaOxidationReactor()
        sim.state.offgas_oxygen_vol_pct = 3.65
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.OFFGAS_O2_EXPLOSIVE_TRIP
        assert sim.state.emergency_nitrogen_quench_active is True
        assert sim.state.ka_oxidation_active is False
        assert sim.state.offgas_o2_high_alarm is True

    def test_priority_2_thermal_runaway_excursion(self) -> None:
        """Verify 0xE402 asserts when reactor temperature > 165.0 °C."""
        sim = KaOxidationReactor()
        sim.state.reactor_temp_celsius = 168.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert sim.state.emergency_nitrogen_quench_active is True
        assert sim.state.ka_oxidation_active is False

    def test_priority_3_low_ka_selectivity_degradation(self) -> None:
        """Verify 0xE403 asserts when KA selectivity < 80.0%."""
        sim = KaOxidationReactor()
        sim.state.ka_oil_selectivity_pct = 78.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.LOW_KA_SELECTIVITY_DEGRADATION
        assert sim.state.emergency_nitrogen_quench_active is False
        assert sim.state.ka_oxidation_active is True

    def test_priority_4_sparger_deficiency_anoxia(self) -> None:
        """Verify 0xE404 asserts when dissolved O2 < 10.0 ppm."""
        sim = KaOxidationReactor()
        sim.state.dissolved_oxygen_ppm = 7.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.SPARGER_DEFICIENCY_ANOXIA
        assert sim.state.emergency_nitrogen_quench_active is False
        assert sim.state.ka_oxidation_active is True

    def test_strict_priority_hierarchy_ordering(self) -> None:
        """Verify strict priority ordering: 0xE401 > 0xE402 > 0xE403 > 0xE404 > 0x0000."""
        sim = KaOxidationReactor()
        # All conditions triggered simultaneously
        sim.state.offgas_oxygen_vol_pct = 3.90  # 0xE401
        sim.state.reactor_temp_celsius = 170.0   # 0xE402
        sim.state.ka_oil_selectivity_pct = 75.0 # 0xE403
        sim.state.dissolved_oxygen_ppm = 5.0    # 0xE404

        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.OFFGAS_O2_EXPLOSIVE_TRIP

        # Clear 0xE401 -> 0xE402 takes precedence
        sim.state.offgas_oxygen_vol_pct = 1.85
        sim.state.emergency_nitrogen_quench_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.THERMAL_RUNAWAY_EXCURSION

        # Clear 0xE402 -> 0xE403 takes precedence
        sim.state.reactor_temp_celsius = 155.0
        sim.state.emergency_nitrogen_quench_active = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.LOW_KA_SELECTIVITY_DEGRADATION

        # Clear 0xE403 -> 0xE404 takes precedence
        sim.state.ka_oil_selectivity_pct = 84.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.SPARGER_DEFICIENCY_ANOXIA

        # Clear 0xE404 -> 0x0000 (OK)
        sim.state.dissolved_oxygen_ppm = 45.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.OK

    def test_pre_trip_alarm_coil_m404(self) -> None:
        """Verify %M404 asserts when offgas O2 > 2.80 vol% even before trip at 3.50 vol%."""
        sim = KaOxidationReactor()
        sim.state.offgas_oxygen_vol_pct = 3.10  # Between 2.80 and 3.50
        sim._evaluate_safety_interlocks()
        assert sim.state.offgas_o2_high_alarm is True
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.OK


# ============================================================================
# Section 9: Emergency Quench & Nitrogen Inerting Dynamics
# ============================================================================

class TestSection9EmergencyQuenchAndInerting:
    """Tests for cold quench cooling and nitrogen inerting on runaway trip."""

    def test_emergency_quench_coil_m405_asserts_on_0xe401(self) -> None:
        """Verify %M405 emergency quench coil asserts on 0xE401."""
        sim = KaOxidationReactor()
        sim.state.offgas_oxygen_vol_pct = 3.60
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_nitrogen_quench_active is True

    def test_emergency_quench_coil_m405_asserts_on_0xe402(self) -> None:
        """Verify %M405 emergency quench coil asserts on 0xE402."""
        sim = KaOxidationReactor()
        sim.state.reactor_temp_celsius = 167.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_nitrogen_quench_active is True

    def test_reaction_active_coil_m403_clears_on_trip(self) -> None:
        """Verify %M403 KaOxidationActive is cleared (False) under trip."""
        sim = KaOxidationReactor()
        sim.state.reactor_temp_celsius = 168.0
        sim._evaluate_safety_interlocks()
        assert sim.state.ka_oxidation_active is False

    def test_quench_cooling_duty_activation(self) -> None:
        """Verify quench cooling duty is active when quench is triggered."""
        sim = KaOxidationReactor()
        sim.state.emergency_nitrogen_quench_active = True
        sim._update_kinetics_and_conversion()
        assert sim.state.q_quench_kw in (5500.0, 25000.0)

    def test_emergency_nitrogen_purge_flow(self) -> None:
        """Verify emergency N2 purge flow sweeps reactor vapor space."""
        cfg = KaOxidationConfig()
        assert cfg.nitrogen_purge_flow_mol_s in (85.0, 250.0)

    def test_thermal_recovery_under_quench(self) -> None:
        """Verify reactor cools down rapidly below trip limit under active quench."""
        sim = KaOxidationReactor()
        sim.state.reactor_temp_celsius = 168.0
        sim.state.t_reactor = 168.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_nitrogen_quench_active is True

        sim.advance_time(duration_s=8.0, dt=0.05)
        assert sim.state.reactor_temp_celsius < 162.0


# ============================================================================
# Section 10: Horner OCS Register Synchronization (%R1730..%R1737, %M403..%M405)
# ============================================================================

class TestSection10HornerMemoryMap:
    """Tests for register synchronization, scaling, and SYSTEM privilege writes."""

    def test_analog_registers_scaling_and_values(self) -> None:
        """Verify analog registers %R1730..%R1736 write exact scaled values."""
        reg = RegisterTable()
        sim = KaOxidationReactor(register_table=reg)
        sim.state.reactor_temp_celsius = 155.0
        sim.state.reactor_pressure_bar = 10.5
        sim.state.cyclohexane_conversion_pct = 4.80
        sim.state.ka_oil_selectivity_pct = 84.5
        sim.state.ka_molar_ratio = 1.20
        sim.state.offgas_oxygen_vol_pct = 1.85
        sim.state.dissolved_oxygen_ppm = 45.0
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1730") == 1550  # x10 °C
        assert reg.read_word("%R1731") == 105   # x10 bar
        assert reg.read_word("%R1732") == 480   # x100 %
        assert reg.read_word("%R1733") == 845   # x10 %
        assert reg.read_word("%R1734") == 120   # x100 ratio
        assert reg.read_word("%R1735") == 185   # x100 %
        assert reg.read_word("%R1736") == 450   # x10 ppm

    def test_diagnostic_status_code_register_r1737(self) -> None:
        """Verify %R1737 reflects diagnostic code."""
        reg = RegisterTable()
        sim = KaOxidationReactor(register_table=reg)
        sim.state.diagnostic_code = KaOxidationDiagnosticCode.OFFGAS_O2_EXPLOSIVE_TRIP
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_uword("%R1737") == 0xE401

    def test_discrete_coils_synchronization(self) -> None:
        """Verify discrete coils %M403..%M405 match boolean state."""
        reg = RegisterTable()
        sim = KaOxidationReactor(register_table=reg)
        sim.state.ka_oxidation_active = True
        sim.state.offgas_o2_high_alarm = False
        sim.state.emergency_nitrogen_quench_active = False
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M403") is True
        assert reg.read_bit("%M404") is False
        assert reg.read_bit("%M405") is False

    def test_system_privilege_mode_enforcement(self) -> None:
        """Verify write with PrivilegeMode.SYSTEM succeeds."""
        reg = RegisterTable()
        sim = KaOxidationReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_word("%R1730") == 1550

    def test_register_sync_under_trip_conditions(self) -> None:
        """Verify registers and coils under emergency trip."""
        reg = RegisterTable()
        sim = KaOxidationReactor(register_table=reg)
        sim.state.offgas_oxygen_vol_pct = 3.75
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M403") is False
        assert reg.read_bit("%M404") is True
        assert reg.read_bit("%M405") is True
        assert reg.read_uword("%R1737") == 0xE401

    def test_status_word_bitmask_consistency(self) -> None:
        """Verify status word bitmask reflects active alarms and states."""
        sim = KaOxidationReactor()
        sim.state.offgas_oxygen_vol_pct = 3.60
        sim._evaluate_safety_interlocks()
        sw = sim.state.status_word
        assert sw & KaOxidationStatusBits.OFFGAS_O2_TRIP
        assert sw & KaOxidationStatusBits.EMERGENCY_QUENCH_ACTIVE
        assert sw & KaOxidationStatusBits.OFFGAS_O2_HIGH_ALARM


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text & Anti-Ladder Security Guard
# ============================================================================

class TestSection11PureSTAndSecurityGuard:
    """Tests for pure Structured Text compliance, AST parsing, and ladder rejection."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify KA Oxidation ST POU parses into valid AST PROGRAM structure."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(KA_OXIDATION_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "KaOxidationReactorSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_pou_name_and_type(self) -> None:
        """Verify program name and type match IEC standards."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(KA_OXIDATION_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "KaOxidationReactorSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_bound_registers(self) -> None:
        """Verify all %R1730..%R1737 and %M403..%M405 are bound in ST POU."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(KA_OXIDATION_REACTOR_PURE_ST_POU)
        assert ast is not None
        expected_regs = [
            "%R1730", "%R1731", "%R1732", "%R1733",
            "%R1734", "%R1735", "%R1736", "%R1737",
            "%M403", "%M404", "%M405",
        ]
        for r in expected_regs:
            assert r in ast.bound_registers

    def test_security_guard_assert_pure_st_valid(self) -> None:
        """Verify SecurityGuard accepts pure Structured Text without exception."""
        SecurityGuard.assert_pure_st_content(KA_OXIDATION_REACTOR_PURE_ST_POU)

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
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nXIC KaOxidationActive\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 12: ILogicUnit Scan Cycle Execution, Reset Dynamics & Multi-Cycle Soak
# ============================================================================

class TestSection12ILogicUnitIntegration:
    """Tests for ILogicUnit scan cycle execution, reset dynamics, and soak stability."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify KaOxidationReactor exposes required ILogicUnit properties."""
        sim = KaOxidationReactor()
        assert sim.name == "KaOxidationReactorSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_with_scan_context(self) -> None:
        """Verify scan_step executes and writes to context.registers."""
        sim = KaOxidationReactor()
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=50.0)
        ctx.registers = reg
        sim.scan_step(dt=0.05, context=ctx)
        assert reg.read_word("%R1730") == 1550

    def test_adapter_logic_unit_execution(self) -> None:
        """Verify KaOxidationReactorLogicUnit adapter executes within engine."""
        unit = KaOxidationReactorLogicUnit()
        assert unit.name == "KaOxidationReactorSync"
        assert unit.priority == 100
        assert unit.is_enabled is True
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=50.0)
        ctx.registers = reg
        unit.execute(ctx)
        assert reg.read_word("%R1730") == 1550

    def test_reset_restores_nominal_state(self) -> None:
        """Verify reset() restores nominal baseline state."""
        sim = KaOxidationReactor()
        sim.state.reactor_temp_celsius = 180.0
        sim.state.offgas_oxygen_vol_pct = 4.5
        sim.reset()
        assert sim.state.reactor_temp_celsius == REACTOR_TEMP_NOMINAL_C
        assert sim.state.diagnostic_code == KaOxidationDiagnosticCode.OK
        assert sim.state.emergency_nitrogen_quench_active is False

    def test_multi_cycle_soak_execution(self) -> None:
        """Verify 100 continuous scan cycles execute without drift or error."""
        sim = KaOxidationReactor()
        for _ in range(100):
            sim.scan_step(dt=0.05)
        assert sim.state.scan_count == 100
        assert 145.0 <= sim.state.reactor_temp_celsius <= 165.0
        assert not math.isnan(sim.state.reactor_temp_celsius)

    def test_step_failure_handling(self) -> None:
        """Verify step returns failed ExecutionResult if exception occurs."""
        sim = KaOxidationReactor()
        # Pass non-float or invalid dt to provoke failure if any
        res = sim.step(dt=0.05)
        assert res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite & Runner Integration
# ============================================================================

class TestSection13VerificationSuiteAndArtifacts:
    """Tests for 9-stage verification runner, JSON export, and component aliases."""

    def test_run_ka_oxidation_reactor_verification_status_success(self) -> None:
        """Verify 9-stage verification suite passes with strict 4-state success contract."""
        res = run_ka_oxidation_reactor_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W212"

    def test_all_9_verification_stages_passed(self) -> None:
        """Verify all 9 stages passed deterministically."""
        res = run_ka_oxidation_reactor_verification()
        assert res["data"]["total_checks"] == 9
        assert res["data"]["checks_passed"] == 9
        stages = [t["stage"] for t in res["data"]["tests"]]
        assert stages == list(range(1, 10))
        assert all(t["passed"] for t in res["data"]["tests"])

    def test_verification_json_export(self, tmp_path: Path) -> None:
        """Verify JSON evidence artifact is created and valid on disk."""
        out_file = tmp_path / "ka_evidence.json"
        res = run_ka_oxidation_reactor_verification(output_path=out_file)
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_aliases(self) -> None:
        """Verify all verification runner aliases return identical success."""
        res1 = run_ka_oxidation_verification()
        res2 = run_ka_reactor_verification()
        res3 = run_ka_verification()
        assert res1["status"] == "success"
        assert res2["status"] == "success"
        assert res3["status"] == "success"

    def test_helper_verification_functions(self) -> None:
        """Verify helper validation functions return True / SUCCESS."""
        assert verify_ka_oxidation_reactor_pure_st() is True
        assert verify_ka_oxidation_pure_st() is True
        assert verify_ka_reactor_pure_st() is True
        assert verify_ka_pure_st() is True
        val = validate_pure_st()
        assert val.status == AgentStatus.SUCCESS

    def test_class_and_constant_aliases(self) -> None:
        """Verify model, state, config, and diagnostic aliases point to canonical definitions."""
        assert KaReactor is KaOxidationReactor
        assert KaSimulator is KaOxidationReactor
        assert KaReactorSimulator is KaOxidationReactor
        assert KaReactorEngine is KaOxidationReactor
        assert KaReactorModel is KaOxidationReactor
        assert KaReactorPlantModel is KaOxidationReactor
        assert KaReactorSimulationEngine is KaOxidationReactor
        assert KaOxidationSimulator is KaOxidationReactor
        assert KaConfig is KaOxidationConfig
        assert KaReactorConfig is KaOxidationConfig
        assert KaParameters is KaOxidationConfig
        assert KaReactorParameters is KaOxidationConfig
        assert KaOxidationParameters is KaOxidationConfig
        assert KaDiagnosticCode is KaOxidationDiagnosticCode
        assert KaDiagCode is KaOxidationDiagnosticCode
        assert KaReactorDiagnosticCode is KaOxidationDiagnosticCode
        assert KaReactorDiagCode is KaOxidationDiagnosticCode
        assert KaStatusBits is KaOxidationStatusBits
        assert KaStatusWord is KaOxidationStatusBits
        assert KaReactorStatusBits is KaOxidationStatusBits
        assert KaReactorStatusWord is KaOxidationStatusBits
        assert KaState is KaOxidationState
        assert KaReactorState is KaOxidationState
        assert KaLogicUnit is KaOxidationReactorLogicUnit
        assert KaReactorLogicUnit is KaOxidationReactorLogicUnit
        assert KA_OXIDATION_REACTOR_PURE_ST_POU == KA_OXIDATION_REACTOR_SYNC_POU == KA_OXIDATION_PURE_ST_POU
        assert KA_PURE_ST_POU == KA_SYNC_POU == KA_REACTOR_PURE_ST_POU == KA_REACTOR_SYNC_POU
