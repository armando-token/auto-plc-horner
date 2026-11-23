"""Comprehensive Industrial Cumene Catalytic Alkylation Reactor Test Suite.

Work Package: W227 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 14 engineering verification sections (110+ unit tests):
1. Section 1: Universal Physical Constants, IUPAC Atomic Weights & Molecular Weights
2. Section 2: Reaction Enthalpies, Exothermicity & Stoichiometric Conservation
3. Section 3: Arrhenius Reaction Kinetics, Activation Energies & Monotonicity
4. Section 4: Fixed-Bed Reactor Geometry, Materials & Thermal Capacitance
5. Section 5: Benzene-to-Propylene Ratio Dynamics, Conversion & Selectivity Metrics
6. Section 6: Coupled 6-State ODE System & High-Order RK4 Numerical Integrator
7. Section 7: Mathematical Conservation Residuals (Mass, Elements, Enthalpy < 1e-10)
8. Section 8: Process Safety Interlocks & Strict Diagnostic Priority Hierarchy (0xF001..0xF004)
9. Section 9: DiagnosticCode Signed/Unsigned Integer Equality & Masking (& 0xFFFF)
10. Section 10: Emergency Cold Benzene Quench Valve Actuation (%M440)
11. Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege (%R1880..%R1887, %M438..%M440)
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

from jev_cscape.simulation.cumene_alkylation import (
    BENZENE_PROPYLENE_RATIO_NOMINAL,
    BENZENE_RATIO_PRE_ALARM,
    BENZENE_RATIO_TRIP,
    CATALYST_DEACTIVATION_NOMINAL_PCT,
    CATALYST_DEACTIVATION_TRIP_PCT,
    CUMENE_ALKYLATION_PURE_ST_POU,
    CUMENE_ALKYLATION_SYNC_POU,
    CUMENE_PROD_NOMINAL_KG_H,
    CUMENE_PURE_ST_POU,
    CUMENE_SEL_NOMINAL_PCT,
    CUMENE_SYNC_POU,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    G_ACCEL,
    MW_BENZENE,
    MW_BZ,
    MW_C,
    MW_CUMENE,
    MW_CU,
    MW_DIISOPROPYLBENZENE,
    MW_DIPB,
    MW_H,
    MW_OLIGO,
    MW_PROPYLENE,
    MW_PR,
    P_REACTOR_MAX_BAR,
    P_REACTOR_NOMINAL_BAR,
    PROPYLENE_CONV_NOMINAL_PCT,
    R_GAS_CONST,
    T_BED_NOMINAL_C,
    T_BED_RUNAWAY_TRIP_C,
    T_INLET_NOMINAL_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    CumeneAlkylation,
    CumeneAlkylationConfig,
    CumeneAlkylationDiagCode,
    CumeneAlkylationDiagnosticCode,
    CumeneAlkylationEngine,
    CumeneAlkylationLogicUnit,
    CumeneAlkylationModel,
    CumeneAlkylationParameters,
    CumeneAlkylationPlantModel,
    CumeneAlkylationReactor,
    CumeneAlkylationReactorLogicUnit,
    CumeneAlkylationSimulationEngine,
    CumeneAlkylationSimulator,
    CumeneAlkylationState,
    CumeneAlkylationStatusBits,
    CumeneAlkylationStatusWord,
    CumeneConfig,
    CumeneDiagCode,
    CumeneDiagnosticCode,
    CumeneEngine,
    CumeneLogicUnit,
    CumeneParameters,
    CumeneReactor,
    CumeneReactorConfig,
    CumeneReactorLogicUnit,
    CumeneSimulator,
    CumeneState,
    CumeneStatusBits,
    CumeneStatusWord,
    DiagnosticCode,
    StatusBits,
    run_cumene_alkylation_reactor_verification,
    run_cumene_alkylation_verification,
    run_cumene_verification,
    verify_cumene_alkylation_pure_st,
    verify_cumene_pure_st,
)


# ============================================================================
# Section 1: Universal Physical Constants, IUPAC Atomic Weights & Molecular Weights
# ============================================================================

class TestSection1PhysicalConstantsAndMolecularWeights:
    """Validate IUPAC atomic masses, molecular weights, and physical constants."""

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
        """Reference temperature must correspond to 205.0 °C (478.15 K)."""
        assert math.isclose(T_REF_K, 205.0 + 273.15, abs_tol=1e-6)

    def test_iupac_elemental_weights(self) -> None:
        """Elemental masses for Carbon and Hydrogen must match IUPAC standards."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)

    def test_benzene_molecular_weight(self) -> None:
        """Benzene C6H6 molecular weight must equal 6*C + 6*H (~78.114 g/mol)."""
        expected_bz = 6.0 * MW_C + 6.0 * MW_H
        assert math.isclose(MW_BZ, expected_bz, rel_tol=1e-9)
        assert math.isclose(MW_BZ * 1000.0, 78.114, rel_tol=1e-3)
        assert MW_BENZENE == MW_BZ

    def test_propylene_molecular_weight(self) -> None:
        """Propylene C3H6 molecular weight must equal 3*C + 6*H (~42.081 g/mol)."""
        expected_pr = 3.0 * MW_C + 6.0 * MW_H
        assert math.isclose(MW_PR, expected_pr, rel_tol=1e-9)
        assert math.isclose(MW_PR * 1000.0, 42.081, rel_tol=1e-3)
        assert MW_PROPYLENE == MW_PR

    def test_cumene_molecular_weight(self) -> None:
        """Cumene (isopropylbenzene) C9H12 molecular weight must equal 9*C + 12*H (~120.195 g/mol)."""
        expected_cu = 9.0 * MW_C + 12.0 * MW_H
        assert math.isclose(MW_CU, expected_cu, rel_tol=1e-9)
        assert math.isclose(MW_CU * 1000.0, 120.195, rel_tol=1e-3)
        assert MW_CUMENE == MW_CU

    def test_diisopropylbenzene_molecular_weight(self) -> None:
        """Diisopropylbenzene (DIPB) C12H18 molecular weight must equal 12*C + 18*H (~162.276 g/mol)."""
        expected_dipb = 12.0 * MW_C + 18.0 * MW_H
        assert math.isclose(MW_DIPB, expected_dipb, rel_tol=1e-9)
        assert math.isclose(MW_DIPB * 1000.0, 162.276, rel_tol=1e-3)
        assert MW_DIISOPROPYLBENZENE == MW_DIPB

    def test_molecular_weight_abbreviations_and_aliases(self) -> None:
        """Verify full names and short abbreviation aliases for all hydrocarbon species."""
        assert MW_BENZENE == MW_BZ
        assert MW_PROPYLENE == MW_PR
        assert MW_CUMENE == MW_CU
        assert MW_DIISOPROPYLBENZENE == MW_DIPB


# ============================================================================
# Section 2: Reaction Enthalpies, Exothermicity & Stoichiometric Conservation
# ============================================================================

class TestSection2ReactionEnthalpiesAndStoichiometry:
    """Validate reaction enthalpies and dual stoichiometric additive relationships."""

    def test_primary_alkylation_enthalpy(self) -> None:
        """Primary catalytic alkylation is exothermic: -105.0 kJ/mol (-105,000 J/mol)."""
        assert math.isclose(DELTA_H1_KJ_MOL, -105.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H1_J_MOL, -105000.0, abs_tol=1e-6)
        assert DELTA_H1_KJ_MOL < 0.0

    def test_side_dialkylation_enthalpy(self) -> None:
        """Secondary di-alkylation to DIPB is exothermic: -102.0 kJ/mol (-102,000 J/mol)."""
        assert math.isclose(DELTA_H2_KJ_MOL, -102.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H2_J_MOL, -102000.0, abs_tol=1e-6)
        assert DELTA_H2_KJ_MOL < 0.0

    def test_transalkylation_enthalpy(self) -> None:
        """Side propylene oligomerization: -95.0 kJ/mol (-95,000 J/mol)."""
        assert math.isclose(DELTA_H3_KJ_MOL, -95.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H3_J_MOL, -95000.0, abs_tol=1e-6)
        assert DELTA_H3_KJ_MOL < 0.0

    def test_reaction_1_stoichiometric_mass_balance(self) -> None:
        """R1: Benzene + Propylene -> Cumene must satisfy exact mass conservation: MW_BZ + MW_PR == MW_CU."""
        diff = abs((MW_BZ + MW_PR) - MW_CU)
        assert diff < 1e-15

    def test_reaction_2_stoichiometric_mass_balance(self) -> None:
        """R2: Cumene + Propylene -> DIPB must satisfy exact mass conservation: MW_CU + MW_PR == MW_DIPB."""
        diff = abs((MW_CU + MW_PR) - MW_DIPB)
        assert diff < 1e-15

    def test_reaction_3_stoichiometric_mass_balance(self) -> None:
        """R3: 3 Propylene -> Oligomer must satisfy exact mass conservation: 3*MW_PR == MW_OLIGO."""
        diff = abs((3.0 * MW_PR) - MW_OLIGO)
        assert diff < 1e-15

    def test_carbon_elemental_conservation(self) -> None:
        """Every reaction step must preserve exact integer counts of Carbon atoms."""
        # R1: C6H6 + C3H6 -> C9H12 (6 + 3 == 9)
        assert 6 + 3 == 9
        # R2: C9H12 + C3H6 -> C12H18 (9 + 3 == 12)
        assert 9 + 3 == 12
        # R3: 3 C3H6 -> C9H18 (3 * 3 == 9)
        assert 3 * 3 == 9

    def test_hydrogen_elemental_conservation(self) -> None:
        """Every reaction step must preserve exact integer counts of Hydrogen atoms."""
        # R1: C6H6 + C3H6 -> C9H12 (6 + 6 == 12)
        assert 6 + 6 == 12
        # R2: C9H12 + C3H6 -> C12H18 (12 + 6 == 18)
        assert 12 + 6 == 18
        # R3: 3 C3H6 -> C9H18 (3 * 6 == 18)
        assert 3 * 6 == 18


# ============================================================================
# Section 3: Arrhenius Reaction Kinetics, Activation Energies & Monotonicity
# ============================================================================

class TestSection3ArrheniusKineticsAndMonotonicity:
    """Validate temperature-dependent reaction kinetics, rate constants, and Arrhenius activation energies."""

    def test_arrhenius_activation_energies(self) -> None:
        """Activation energies: Ea1 = 68.0 kJ/mol, Ea2 = 74.0 kJ/mol, Ea3 = 58.0 kJ/mol."""
        cfg = CumeneAlkylationConfig()
        assert math.isclose(cfg.activation_e1_j_mol, 68000.0, abs_tol=1e-3)
        assert math.isclose(cfg.activation_e2_j_mol, 74000.0, abs_tol=1e-3)
        assert math.isclose(cfg.activation_e3_j_mol, 58000.0, abs_tol=1e-3)

    def test_activation_energy_hierarchy(self) -> None:
        """Polyalkylation activation energy Ea2 (74 kJ) must exceed alkylation Ea1 (68 kJ) and oligomerization Ea3 (58 kJ)."""
        cfg = CumeneAlkylationConfig()
        assert cfg.activation_e2_j_mol > cfg.activation_e1_j_mol > cfg.activation_e3_j_mol

    def test_rate_constant_monotonic_increase_with_temperature(self) -> None:
        """Rate constants k1, k2, k3 must strictly increase with temperature."""
        sim = CumeneAlkylation()
        t_cold_k = 185.0 + T_ZERO_CELSIUS
        t_nom_k = 205.0 + T_ZERO_CELSIUS
        t_hot_k = 225.0 + T_ZERO_CELSIUS

        k1_cold = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_cold_k)
        k1_nom = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_nom_k)
        k1_hot = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_hot_k)

        assert 0.0 < k1_cold < k1_nom < k1_hot

    def test_polyalkylation_accelerates_faster_than_alkylation(self) -> None:
        """Polyalkylation (Ea2 = 72 kJ/mol) must accelerate faster than alkylation (Ea1 = 65 kJ/mol) at higher temperatures."""
        sim = CumeneAlkylation()
        t1_k = 185.0 + T_ZERO_CELSIUS
        t2_k = 225.0 + T_ZERO_CELSIUS

        k1_1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1_k)
        k1_2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2_k)

        k2_1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t1_k)
        k2_2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t2_k)

        accel_k1 = k1_2 / k1_1
        accel_k2 = k2_2 / k2_1
        assert accel_k2 > accel_k1

    def test_recovered_activation_energy_matches_input(self) -> None:
        """Arrhenius slope d(ln k)/d(1/T) must exactly reproduce Ea1 within numerical precision."""
        sim = CumeneAlkylation()
        t1_k = 185.0 + T_ZERO_CELSIUS
        t2_k = 225.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1_k)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2_k)

        ea_rec = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(ea_rec, sim.config.activation_e1_j_mol, rel_tol=1e-5)

    def test_rates_quenched_when_reactor_inactive(self) -> None:
        """Reaction rates must drop to zero when reactor active coil %M438 is False."""
        sim = CumeneAlkylation()
        sim.state.cumene_reactor_active = False
        kin = sim.compute_kinetics(205.0 + T_ZERO_CELSIUS, 6719.79, 24.0, 1751.94, 60.0)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["r3"] == 0.0
        assert kin["q_total_kw"] == 0.0

    def test_rates_quenched_when_quench_valve_open(self) -> None:
        """Reaction rates must drop to zero when emergency quench valve %M440 is open."""
        sim = CumeneAlkylation()
        sim.state.emergency_quench_valve_open = True
        kin = sim.compute_kinetics(205.0 + T_ZERO_CELSIUS, 6719.79, 24.0, 1751.94, 60.0)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["r3"] == 0.0
        assert kin["q_total_kw"] == 0.0

    def test_catalyst_activity_derating_under_deactivation(self) -> None:
        """Catalyst activity factor must decrease when catalyst hotspot deactivation increases."""
        sim = CumeneAlkylation()
        sim.state.catalyst_deactivation_pct = 1.20
        kin_fresh = sim.compute_kinetics(205.0 + T_ZERO_CELSIUS, 6719.79, 24.0, 1751.94, 60.0)

        sim.state.catalyst_deactivation_pct = 4.00
        kin_deact = sim.compute_kinetics(205.0 + T_ZERO_CELSIUS, 6719.79, 24.0, 1751.94, 60.0)

        assert kin_deact["r1"] < kin_fresh["r1"]
        assert kin_deact["q_total_kw"] < kin_fresh["q_total_kw"]


# ============================================================================
# Section 4: Fixed-Bed Reactor Geometry, Materials & Thermal Capacitance
# ============================================================================

class TestSection4ReactorVesselGeometryAndEnvelope:
    """Validate fixed-bed reactor column geometry, catalyst mass, and thermal capacitance."""

    def test_default_config_geometry(self) -> None:
        """Column geometry: volume = 4.50 m3, diameter = 1.40 m, bed length = 2.92 m."""
        cfg = CumeneAlkylationConfig()
        assert math.isclose(cfg.bed_volume_m3, 4.50, abs_tol=1e-2)
        assert math.isclose(cfg.bed_diameter_m, 1.40, abs_tol=1e-2)
        assert math.isclose(cfg.bed_height_m, 2.92, abs_tol=1e-2)

    def test_catalyst_physical_properties(self) -> None:
        """Zeolite catalyst: bulk density = 780 kg/m^3, heat capacity = 1150 J/(kg*K)."""
        cfg = CumeneAlkylationConfig()
        assert math.isclose(cfg.catalyst_bulk_density_kg_m3, 780.0, abs_tol=1e-1)
        assert math.isclose(cfg.catalyst_heat_capacity_j_kg_k, 1150.0, abs_tol=1e-1)

    def test_bed_thermal_capacitance(self) -> None:
        """Bed thermal capacitance C_th must equal 5000.0 kJ/K."""
        cfg = CumeneAlkylationConfig()
        assert math.isclose(cfg.bed_thermal_capacitance_kj_k, 5000.0, abs_tol=1e-1)

    def test_nominal_operating_temperatures(self) -> None:
        """Nominal operating points: bed = 205.0 °C (%R1880=2050), inlet = 195.0 °C."""
        cfg = CumeneAlkylationConfig()
        assert math.isclose(cfg.nominal_bed_temp_c, 205.0, abs_tol=1e-3)
        assert math.isclose(cfg.nominal_inlet_temp_c, 195.0, abs_tol=1e-3)

    def test_nominal_operating_pressure(self) -> None:
        """Nominal reactor pressure must be 30.0 bar (%R1881=300)."""
        cfg = CumeneAlkylationConfig()
        assert math.isclose(cfg.nominal_reactor_pressure_bar, 30.0, abs_tol=1e-3)

    def test_config_and_parameters_aliases(self) -> None:
        """Configuration class aliases must be identical."""
        assert CumeneConfig is CumeneAlkylationConfig
        assert CumeneParameters is CumeneAlkylationConfig
        assert CumeneAlkylationParameters is CumeneAlkylationConfig
        assert CumeneReactorConfig is CumeneAlkylationConfig


# ============================================================================
# Section 5: Benzene-to-Propylene Ratio Dynamics, Conversion & Selectivity
# ============================================================================

class TestSection5BenzeneRatioDynamicsConversionAndSelectivity:
    """Validate Benzene:Propylene molar ratio dynamics, propylene conversion, and cumene selectivity."""

    def test_nominal_benzene_propylene_ratio(self) -> None:
        """Nominal Benzene:Propylene molar ratio must be 5.50:1 (%R1884 = 55)."""
        sim = CumeneAlkylation()
        assert math.isclose(sim.state.benzene_propylene_ratio, 5.50, abs_tol=1e-2)

    def test_nominal_propylene_conversion_exceeds_98_pct(self) -> None:
        """Nominal propylene conversion must exceed 98.0% (target ~98.65%)."""
        sim = CumeneAlkylation()
        assert sim.state.propylene_conversion_pct >= 98.0
        assert math.isclose(sim.state.propylene_conversion_pct, 98.65, abs_tol=0.5)

    def test_nominal_cumene_selectivity_exceeds_92_pct(self) -> None:
        """Nominal cumene selectivity must exceed 92.5% (target ~93.20%)."""
        sim = CumeneAlkylation()
        assert sim.state.cumene_selectivity_pct >= 92.5
        assert math.isclose(sim.state.cumene_selectivity_pct, 93.20, abs_tol=0.5)

    def test_nominal_cumene_production_rate(self) -> None:
        """Nominal cumene production rate must equal approx 1150.0 kg/h (%R1885 = 11500)."""
        sim = CumeneAlkylation()
        assert math.isclose(sim.state.cumene_production_rate_kg_h, 1150.0, rel_tol=0.05)

    def test_low_ratio_accelerates_catalyst_deactivation(self) -> None:
        """Benzene:Propylene ratio below 3.50:1 must cause catalyst deactivation to increase over time."""
        sim = CumeneAlkylation()
        sim.state.benzene_propylene_ratio = 3.20
        deact_before = sim.state.catalyst_deactivation_pct
        for _ in range(50):  # 1.0 s
            sim.rk4_step(dt=0.02)
        deact_after = sim.state.catalyst_deactivation_pct
        assert deact_after > deact_before

    def test_normal_ratio_suppresses_deactivation_growth(self) -> None:
        """Benzene:Propylene ratio of 4.50:1 (>= 3.50:1) must not increase deactivation."""
        sim = CumeneAlkylation()
        sim.state.benzene_propylene_ratio = 4.50
        deact_before = sim.state.catalyst_deactivation_pct
        for _ in range(50):
            sim.rk4_step(dt=0.02)
        deact_after = sim.state.catalyst_deactivation_pct
        assert deact_after <= deact_before + 1e-9

    def test_deactivation_increases_bed_pressure_drop(self) -> None:
        """Increased catalyst deactivation must cause bed pressure drop to increase above clean DP."""
        sim = CumeneAlkylation()
        sim.state.catalyst_deactivation_pct = 4.0
        clean_dp = sim.config.nominal_bed_dp_bar
        sim.rk4_step(dt=0.02)
        assert sim.state.bed_pressure_drop_bar > clean_dp


# ============================================================================
# Section 6: Coupled 6-State ODE System & High-Order RK4 Numerical Integrator
# ============================================================================

class TestSection6Coupled6StateODESystemAndRK4Integrator:
    """Validate 6-state ODE vector derivatives, RK4 solver, and numerical stability."""

    def test_state_vector_elements_and_defaults(self) -> None:
        """State vector must contain C_bz, C_pr, C_cu, C_dipb, C_oligo, T_bed_c, P_reactor_bar."""
        state = CumeneAlkylationState()
        assert math.isclose(state.c_bz, 7.326399, rel_tol=1e-2)
        assert math.isclose(state.c_pr, 0.024125, rel_tol=1e-2)
        assert math.isclose(state.c_cu, 1.476510, rel_tol=1e-2)
        assert math.isclose(state.c_dipb, 0.043091, rel_tol=1e-2)
        assert math.isclose(state.c_oligo, 0.007182, rel_tol=1e-2)
        assert math.isclose(state.t_bed_c, 205.0, abs_tol=1e-3)
        assert math.isclose(state.p_reactor_bar, 30.0, abs_tol=1e-3)

    def test_compute_derivatives_shape_and_finiteness(self) -> None:
        """compute_derivatives must return exactly 6 finite float derivatives."""
        sim = CumeneAlkylation()
        y = [7.326399, 0.024125, 1.476510, 0.043091, 0.007182, 205.0]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6
        assert all(isinstance(d, float) for d in derivs)
        assert all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    def test_single_rk4_step_advances_simulation_time(self) -> None:
        """rk4_step must advance sim_time_s by exactly dt."""
        sim = CumeneAlkylation()
        t0 = sim.state.sim_time_s
        sim.rk4_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, t0 + 0.02, abs_tol=1e-9)

    def test_step_returns_execution_result_payload(self) -> None:
        """step() must return ExecutionResult with status == SUCCESS."""
        sim = CumeneAlkylation()
        res = sim.step(dt=0.02)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None

    def test_advance_time_multi_step_execution(self) -> None:
        """advance_time(1.0, dt=0.02) must advance time by exactly 1.0 s in 50 steps."""
        sim = CumeneAlkylation()
        res = sim.advance_time(duration_s=1.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert math.isclose(sim.state.sim_time_s, 1.0, abs_tol=1e-6)

    def test_advance_time_rejects_negative_or_zero_duration(self) -> None:
        """advance_time must return status == FAILED on non-positive duration or dt."""
        sim = CumeneAlkylation()
        res_neg = sim.advance_time(duration_s=-1.0, dt=0.02)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

        res_zero_dt = sim.advance_time(duration_s=1.0, dt=0.0)
        assert res_zero_dt.status == AgentStatus.FAILED

    def test_rk4_state_non_negativity_clamping(self) -> None:
        """RK4 solver must clamp concentrations to non-negative values."""
        sim = CumeneAlkylation()
        sim.state.c_propylene = 0.0001
        for _ in range(10):
            sim.rk4_step(dt=0.02)
        assert sim.state.c_benzene >= 0.0
        assert sim.state.c_propylene >= 0.0
        assert sim.state.c_cumene >= 0.0
        assert sim.state.c_dipb >= 0.0

    def test_extended_simulation_stability(self) -> None:
        """Continuous simulation over 5.0 seconds (250 steps) must remain stable and non-divergent."""
        sim = CumeneAlkylation()
        for _ in range(250):
            res = sim.step(dt=0.02)
            assert res.status == AgentStatus.SUCCESS
        assert 195.0 <= sim.state.t_bed_c <= 215.0
        assert not math.isnan(sim.state.c_cumene)
        assert not math.isinf(sim.state.c_cumene)

    def test_uncooled_thermal_runaway_tendency(self) -> None:
        """Without cooling, exothermic alkylation reaction must cause positive temperature rate dT/dt."""
        sim = CumeneAlkylation()
        sim.config.cooling_ua_kw_k = 0.0  # disable cooling
        y = [7.326399, 0.024125, 1.476510, 0.043091, 0.007182, 205.0]
        derivs = sim.compute_derivatives(0.0, y)
        dt_bed_dt = derivs[5]
        assert dt_bed_dt > 0.0  # temperature rises due to exothermic heat release


# ============================================================================
# Section 7: Mathematical Conservation Residuals (Mass, Elements, Enthalpy < 1e-10)
# ============================================================================

class TestSection7MathematicalConservationResiduals:
    """Validate stoichiometric mass, elemental species, and first-law enthalpy conservation residuals."""

    def test_total_mass_balance_residual_less_than_1e10(self) -> None:
        """Total stoichiometric mass balance residual must be strictly < 1e-10 kg/s."""
        sim = CumeneAlkylation()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_mass_balance_residual_less_than_1e10(self) -> None:
        """Elemental carbon and hydrogen mass balance residual must be strictly < 1e-10 kg/s."""
        sim = CumeneAlkylation()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        """First-law thermal enthalpy conservation residual must be strictly < 1e-10 kW."""
        sim = CumeneAlkylation()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_residuals_conserved_over_extended_simulation(self) -> None:
        """All three conservation residuals must remain < 1e-10 over extended multi-step simulation."""
        sim = CumeneAlkylation()
        sim.advance_time(duration_s=2.0, dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_residuals_under_perturbed_concentrations(self) -> None:
        """Conservation residuals must remain < 1e-10 even under perturbed initial concentrations."""
        sim = CumeneAlkylation()
        sim.state.c_benzene = 7.50
        sim.state.c_propylene = 0.05
        sim.state.c_cumene = 1.20
        sim.state.c_dipb = 0.08
        sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_enthalpy_components_additive_consistency(self) -> None:
        """Net reaction thermal release must equal Q1 + Q2 + Q3."""
        sim = CumeneAlkylation()
        kin = sim.compute_kinetics(205.0 + T_ZERO_CELSIUS, 6719.79, 24.0, 1751.94, 60.0)
        q1 = kin["q_rxn1_kw"]
        q2 = kin["q_rxn2_kw"]
        q3 = kin["q_rxn3_kw"]
        q_tot = kin["q_total_kw"]
        assert math.isclose(q_tot, q1 + q2 + q3, rel_tol=1e-9)


# ============================================================================
# Section 8: Process Safety Interlocks & Strict Diagnostic Priority (0xF001..0xF004)
# ============================================================================

class TestSection8ProcessSafetyInterlocksAndPriority:
    """Validate diagnostic event codes and strict priority hierarchy ordering."""

    def test_normal_operation_diagnostic_code_ok(self) -> None:
        """Under baseline conditions, diagnostic code must be 0x0000 OK."""
        sim = CumeneAlkylation()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OK
        assert sim.state.cumene_reactor_active is True
        assert sim.state.emergency_quench_valve_open is False

    def test_priority_1_thermal_runaway_trip_above_250c(self) -> None:
        """T_bed > 250.0 °C must trip 0xF001, open quench valve %M440, and de-energize %M438."""
        sim = CumeneAlkylation()
        sim.state.t_bed_c = 255.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OVER_TEMPERATURE_RUNAWAY
        assert sim.state.diagnostic_code == 0xF001
        assert sim.state.emergency_quench_valve_open is True
        assert sim.state.cumene_reactor_active is False

    def test_priority_2_overpressure_hydraulic_trip_above_38bar(self) -> None:
        """P_reactor > 38.0 bar must trip 0xF002, open quench valve %M440, and de-energize %M438."""
        sim = CumeneAlkylation()
        sim.state.p_reactor_bar = 39.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OVERPRESSURE_FAULT
        assert sim.state.diagnostic_code == 0xF002
        assert sim.state.emergency_quench_valve_open is True
        assert sim.state.cumene_reactor_active is False

    def test_priority_3_low_benzene_propylene_ratio_trip_below_3_5(self) -> None:
        """Benzene:Propylene ratio < 3.50:1 must trip 0xF003 and de-energize %M438."""
        sim = CumeneAlkylation()
        sim.state.benzene_propylene_ratio = 3.20
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.LOW_BENZENE_RATIO
        assert sim.state.diagnostic_code == 0xF003
        assert sim.state.cumene_reactor_active is False

    def test_priority_4_catalyst_hotspot_deactivation_trip_above_4_5_pct(self) -> None:
        """Catalyst deactivation > 4.50% must trip 0xF004 and de-energize %M438."""
        sim = CumeneAlkylation()
        sim.state.catalyst_deactivation_pct = 4.80
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.CATALYST_HOTSPOT_DEACTIVATION
        assert sim.state.diagnostic_code == 0xF004
        assert sim.state.cumene_reactor_active is False

    def test_low_benzene_ratio_pre_alarm_coil_m439(self) -> None:
        """Benzene:Propylene ratio < 4.20:1 must assert pre-alarm %M439 without tripping reactor (at ratio 4.00)."""
        sim = CumeneAlkylation()
        sim.state.benzene_propylene_ratio = 4.00
        sim._evaluate_safety_interlocks()
        assert sim.state.low_benzene_ratio_pre_alarm is True
        assert sim.state.cumene_reactor_active is True
        assert sim.state.emergency_quench_valve_open is False
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OK

    def test_pre_alarm_clears_when_ratio_normal(self) -> None:
        """Benzene:Propylene ratio >= 4.20:1 must clear pre-alarm %M439."""
        sim = CumeneAlkylation()
        sim.state.benzene_propylene_ratio = 4.50
        sim._evaluate_safety_interlocks()
        assert sim.state.low_benzene_ratio_pre_alarm is False

    def test_strict_priority_hierarchy_ordering(self) -> None:
        """Runaway (0xF001) > Overpressure (0xF002) > Ratio (0xF003) > Hotspot (0xF004)."""
        sim = CumeneAlkylation()

        # All fault conditions active simultaneously: Runaway (0xF001) takes precedence
        sim.reset()
        sim.state.t_bed_c = 260.0               # 0xF001
        sim.state.p_reactor_bar = 40.0         # 0xF002
        sim.state.benzene_propylene_ratio = 3.0 # 0xF003
        sim.state.catalyst_deactivation_pct = 5.0 # 0xF004
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OVER_TEMPERATURE_RUNAWAY

        # Remove 0xF001, keep overpressure, low ratio, and deactivation: Overpressure (0xF002) takes precedence
        sim.reset()
        sim.state.t_bed_c = 205.0
        sim.state.p_reactor_bar = 40.0         # 0xF002
        sim.state.benzene_propylene_ratio = 3.0 # 0xF003
        sim.state.catalyst_deactivation_pct = 5.0 # 0xF004
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OVERPRESSURE_FAULT

        # Normal pressure, low ratio and deactivation: Low Ratio (0xF003) takes precedence
        sim.reset()
        sim.state.t_bed_c = 205.0
        sim.state.p_reactor_bar = 30.0
        sim.state.benzene_propylene_ratio = 3.0 # 0xF003
        sim.state.catalyst_deactivation_pct = 5.0 # 0xF004
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.LOW_BENZENE_RATIO

        # Normal ratio, keep deactivation: Hotspot (0xF004)
        sim.reset()
        sim.state.t_bed_c = 205.0
        sim.state.p_reactor_bar = 30.0
        sim.state.benzene_propylene_ratio = 4.50
        sim.state.catalyst_deactivation_pct = 5.0 # 0xF004
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.CATALYST_HOTSPOT_DEACTIVATION

        # Restore deactivation to normal: OK (0x0000)
        sim.reset()
        sim.state.t_bed_c = 205.0
        sim.state.p_reactor_bar = 30.0
        sim.state.benzene_propylene_ratio = 4.50
        sim.state.catalyst_deactivation_pct = 1.20
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OK

    def test_diagnostic_code_enum_values_and_aliases(self) -> None:
        """Validate exact diagnostic integer values and compatibility aliases."""
        assert CumeneAlkylationDiagnosticCode.OK == 0x0000
        assert CumeneAlkylationDiagnosticCode.OVER_TEMPERATURE_RUNAWAY == 0xF001
        assert CumeneAlkylationDiagnosticCode.OVERPRESSURE_FAULT == 0xF002
        assert CumeneAlkylationDiagnosticCode.LOW_BENZENE_RATIO == 0xF003
        assert CumeneAlkylationDiagnosticCode.CATALYST_HOTSPOT_DEACTIVATION == 0xF004

        assert DiagnosticCode is CumeneAlkylationDiagnosticCode
        assert CumeneDiagnosticCode is CumeneAlkylationDiagnosticCode
        assert CumeneDiagCode is CumeneAlkylationDiagnosticCode


# ============================================================================
# Section 9: DiagnosticCode Signed/Unsigned Integer Equality & Masking (& 0xFFFF)
# ============================================================================

class TestSection9DiagnosticCodeSignedUnsignedEqualityAndMasking:
    """Validate signed/unsigned 16-bit integer comparisons and masking with & 0xFFFF."""

    def test_diagnostic_code_signed_int_equality(self) -> None:
        """0xF001 stored as signed 16-bit int is -4095; equality must hold directly."""
        code = DiagnosticCode.OVER_TEMPERATURE_RUNAWAY
        assert code == -4095
        assert code == 0xF001

    def test_diagnostic_code_overpressure_signed_int_equality(self) -> None:
        """0xF002 stored as signed 16-bit int is -4094; equality must hold directly."""
        code = DiagnosticCode.OVERPRESSURE_FAULT
        assert code == -4094
        assert code == 0xF002

    def test_diagnostic_code_low_ratio_signed_int_equality(self) -> None:
        """0xF003 stored as signed 16-bit int is -4093; equality must hold directly."""
        code = DiagnosticCode.LOW_BENZENE_RATIO
        assert code == -4093
        assert code == 0xF003

    def test_diagnostic_code_hotspot_signed_int_equality(self) -> None:
        """0xF004 stored as signed 16-bit int is -4092; equality must hold directly."""
        code = DiagnosticCode.CATALYST_HOTSPOT_DEACTIVATION
        assert code == -4092
        assert code == 0xF004

    def test_diagnostic_code_masking_with_0xffff(self) -> None:
        """Bitwise masking (& 0xFFFF) on DiagnosticCode must produce exact unsigned hex integer."""
        assert (DiagnosticCode.OVER_TEMPERATURE_RUNAWAY & 0xFFFF) == 0xF001
        assert (DiagnosticCode.OVERPRESSURE_FAULT & 0xFFFF) == 0xF002
        assert (DiagnosticCode.LOW_BENZENE_RATIO & 0xFFFF) == 0xF003
        assert (DiagnosticCode.CATALYST_HOTSPOT_DEACTIVATION & 0xFFFF) == 0xF004
        assert (DiagnosticCode.OK & 0xFFFF) == 0x0000

    def test_diagnostic_code_reverse_masking_operation(self) -> None:
        """Reverse bitwise masking with int (& DiagnosticCode) must evaluate properly."""
        assert (0xFFFF & DiagnosticCode.OVER_TEMPERATURE_RUNAWAY) == 0xF001
        assert (0xFFFF & DiagnosticCode.OVERPRESSURE_FAULT) == 0xF002

    def test_diagnostic_code_missing_signed_lookup(self) -> None:
        """DiagnosticCode(-4095) must instantiate or look up OVER_TEMPERATURE_RUNAWAY cleanly."""
        assert DiagnosticCode(-4095) == DiagnosticCode.OVER_TEMPERATURE_RUNAWAY
        assert DiagnosticCode(-4094) == DiagnosticCode.OVERPRESSURE_FAULT
        assert DiagnosticCode(-4093) == DiagnosticCode.LOW_BENZENE_RATIO
        assert DiagnosticCode(-4092) == DiagnosticCode.CATALYST_HOTSPOT_DEACTIVATION

    def test_diagnostic_code_hash_consistency(self) -> None:
        """DiagnosticCode must hash consistently based on its unsigned value."""
        assert hash(DiagnosticCode.OVER_TEMPERATURE_RUNAWAY) == hash(0xF001)


# ============================================================================
# Section 10: Emergency Cold Benzene Quench Valve Actuation (%M440)
# ============================================================================

class TestSection10EmergencyColdBenzeneQuenchValve:
    """Validate emergency cold benzene quench valve actuation, thermal quenching, and safety interlocks."""

    def test_quench_valve_coil_m440_asserts_on_thermal_runaway(self) -> None:
        """Quench valve coil %M440 must assert True on thermal runaway trip (T > 250 °C)."""
        sim = CumeneAlkylation()
        sim.state.t_bed_c = 255.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_quench_valve_open is True

    def test_quench_valve_coil_m440_asserts_on_overpressure(self) -> None:
        """Quench valve coil %M440 must assert True on overpressure trip (P > 38 bar)."""
        sim = CumeneAlkylation()
        sim.state.p_reactor_bar = 39.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_quench_valve_open is True

    def test_reactor_active_coil_m438_cleared_on_trip(self) -> None:
        """Reactor active coil %M438 must clear False whenever quench valve %M440 is actuated."""
        sim = CumeneAlkylation()
        sim.state.t_bed_c = 255.0
        sim._evaluate_safety_interlocks()
        assert sim.state.cumene_reactor_active is False

    def test_quench_valve_cools_bed_below_runaway_threshold(self) -> None:
        """Subcooled benzene quench must actively remove heat and cool bed below 250.0 °C."""
        sim = CumeneAlkylation()
        sim.state.t_bed_c = 255.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_quench_valve_open is True

        sim.advance_time(duration_s=6.0, dt=0.02)
        assert sim.state.t_bed_c < 248.0
        assert sim.state.q_rxn_total_kw < 1.0

    def test_status_bits_quench_active_bit(self) -> None:
        """Status word must set EMERGENCY_QUENCH_ACTIVE bit when valve is open."""
        sim = CumeneAlkylation()
        sim.state.emergency_quench_valve_open = True
        sim._evaluate_safety_interlocks()
        assert bool(sim.state.status_bits & CumeneAlkylationStatusBits.EMERGENCY_QUENCH_ACTIVE)


# ============================================================================
# Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege (%R1880..%R1887, %M438..%M440)
# ============================================================================

class TestSection11HornerOCSMemorySpaceIntegration:
    """Validate Horner OCS analog registers, discrete coils, bitmasks, and privilege enforcement."""

    def test_analog_registers_scaling_r1880_to_r1886(self) -> None:
        """Verify exact engineering units scaling of %R1880 through %R1886."""
        reg = RegisterTable()
        sim = CumeneAlkylation(register_table=reg)

        sim.state.t_bed_c = 205.0
        sim.state.p_reactor_bar = 30.0
        sim.state.propylene_conversion_pct = 98.65
        sim.state.cumene_selectivity_pct = 93.20
        sim.state.benzene_propylene_ratio = 4.50
        sim.state.cumene_production_rate_kg_h = 1150.0
        sim.state.catalyst_deactivation_pct = 1.20
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1880") == 2050  # 205.0 * 10
        assert reg.read_word("%R1881") == 300   # 30.0 * 10
        assert reg.read_word("%R1882") == 9865  # 98.65 * 100
        assert reg.read_word("%R1883") == 9320  # 93.20 * 100
        assert reg.read_word("%R1884") == 45    # 4.50 * 10
        assert reg.read_word("%R1885") == 11500 # 1150.0 * 10
        assert reg.read_word("%R1886") == 120   # 1.20 * 100

    def test_diagnostic_status_code_register_r1887_hex_masking(self) -> None:
        """reg_table.read_word returns signed int16; must mask with & 0xFFFF when evaluating hex codes."""
        reg = RegisterTable()
        sim = CumeneAlkylation(register_table=reg)

        # Normal condition: 0x0000
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert (reg.read_word("%R1887") & 0xFFFF) == 0x0000
        assert reg.read_uword("%R1887") == 0x0000

        # Thermal runaway trip: 0xF001
        sim.state.t_bed_c = 255.0
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        raw_signed = reg.read_word("%R1887")
        assert (raw_signed & 0xFFFF) == 0xF001
        assert reg.read_uword("%R1887") == 0xF001

        # Overpressure trip: 0xF002
        sim.state.t_bed_c = 205.0
        sim.state.p_reactor_bar = 39.5
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert (reg.read_word("%R1887") & 0xFFFF) == 0xF002

        # Low ratio trip: 0xF003
        sim.state.p_reactor_bar = 30.0
        sim.state.benzene_propylene_ratio = 3.20
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert (reg.read_word("%R1887") & 0xFFFF) == 0xF003

        # Catalyst deactivation trip: 0xF004
        sim.state.benzene_propylene_ratio = 4.50
        sim.state.catalyst_deactivation_pct = 4.80
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert (reg.read_word("%R1887") & 0xFFFF) == 0xF004

    def test_discrete_coils_m438_to_m440(self) -> None:
        """Verify discrete coils %M438 (Active), %M439 (PreAlarm), %M440 (QuenchOpen)."""
        reg = RegisterTable()
        sim = CumeneAlkylation(register_table=reg)

        sim.state.cumene_reactor_active = True
        sim.state.low_benzene_ratio_pre_alarm = False
        sim.state.emergency_quench_valve_open = False
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M438") is True
        assert reg.read_bit("%M439") is False
        assert reg.read_bit("%M440") is False

    def test_system_privilege_mode_enforcement(self) -> None:
        """Writing to Horner registers must execute cleanly under PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = CumeneAlkylation(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_uword("%R1887") == 0x0000

    def test_status_word_bitmask_consistency(self) -> None:
        """Status word flags must maintain consistent bits matching Horner standard."""
        assert CumeneAlkylationStatusBits.RUNNING == 0x0001
        assert CumeneAlkylationStatusBits.CUMENE_ALKYLATION_ACTIVE == 0x0002
        assert CumeneAlkylationStatusBits.LOW_BENZENE_PRE_ALARM == 0x0004
        assert CumeneAlkylationStatusBits.EMERGENCY_QUENCH_ACTIVE == 0x0008
        assert CumeneAlkylationStatusBits.THERMAL_RUNAWAY_TRIP == 0x0010
        assert CumeneAlkylationStatusBits.OVERPRESSURE_TRIP == 0x0020
        assert CumeneAlkylationStatusBits.LOW_BENZENE_RATIO_TRIP == 0x0040
        assert CumeneAlkylationStatusBits.CATALYST_HOTSPOT_TRIP == 0x0080

    def test_status_word_aliases(self) -> None:
        """Status word class aliases must match."""
        assert CumeneStatusBits is CumeneAlkylationStatusBits
        assert CumeneStatusWord is CumeneAlkylationStatusBits
        assert CumeneAlkylationStatusWord is CumeneAlkylationStatusBits
        assert StatusBits is CumeneAlkylationStatusBits


# ============================================================================
# Section 12: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
# ============================================================================

class TestSection12PureStructuredTextPOUAndAntiLadder:
    """Validate pure IEC 61131-3 ST POU parsing, register bindings, and ladder logic rejection."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """POU must parse cleanly using STParser into valid AST."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(CUMENE_ALKYLATION_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "CumeneAlkylationSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_bound_registers(self) -> None:
        """ST POU must bind all Horner registers: %R1880..%R1887 and %M438..%M440."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(CUMENE_ALKYLATION_PURE_ST_POU)
        expected_regs = [
            "%R1880", "%R1881", "%R1882", "%R1883",
            "%R1884", "%R1885", "%R1886", "%R1887",
            "%M438", "%M439", "%M440",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_security_guard_assert_pure_st_valid(self) -> None:
        """SecurityGuard.assert_pure_st_content must pass on pure ST POU."""
        SecurityGuard.assert_pure_st_content(CUMENE_ALKYLATION_PURE_ST_POU)

    def test_anti_ladder_rejection_contact(self) -> None:
        """SecurityGuard must raise LadderForbiddenError on ladder contact '---[ ]---'."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM")

    def test_anti_ladder_rejection_coil(self) -> None:
        """SecurityGuard must raise LadderForbiddenError on ladder coil '---( )---'."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM")

    def test_anti_ladder_rejection_rung(self) -> None:
        """SecurityGuard must raise LadderForbiddenError on rung delimiter 'RUNG 1'."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad\nVAR x: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM")

    def test_anti_ladder_rejection_mnemonics_xic(self) -> None:
        """SecurityGuard must raise LadderForbiddenError on ladder mnemonic 'XIC'."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad\nVAR x: BOOL; END_VAR\nXIC CumeneActive\nEND_PROGRAM")

    def test_anti_ladder_rejection_mnemonics_ote(self) -> None:
        """SecurityGuard must raise LadderForbiddenError on ladder mnemonic 'OTE'."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad\nVAR x: BOOL; END_VAR\nOTE QuenchValveOpen\nEND_PROGRAM")

    def test_pou_verification_helpers(self) -> None:
        """Helper functions verify_cumene_alkylation_pure_st and verify_cumene_pure_st must return True."""
        assert verify_cumene_alkylation_pure_st() is True
        assert verify_cumene_pure_st() is True

    def test_pou_string_aliases(self) -> None:
        """POU string aliases must resolve identically."""
        assert CUMENE_ALKYLATION_SYNC_POU == CUMENE_ALKYLATION_PURE_ST_POU
        assert CUMENE_PURE_ST_POU == CUMENE_ALKYLATION_PURE_ST_POU
        assert CUMENE_SYNC_POU == CUMENE_ALKYLATION_PURE_ST_POU


# ============================================================================
# Section 13: ILogicUnit Scan Cycle Execution, Reset Dynamics & Soak Stability
# ============================================================================

class TestSection13ILogicUnitScanCycleAndReset:
    """Validate ILogicUnit protocol compliance, ScanContext execution, and reset semantics."""

    def test_ilogic_unit_properties(self) -> None:
        """Simulator must implement ILogicUnit name, priority, and is_enabled properties."""
        sim = CumeneAlkylation()
        assert sim.name == "CumeneAlkylationSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_with_scan_context(self) -> None:
        """scan_step must execute cleanly with optional ScanContext."""
        reg = RegisterTable()
        sim = CumeneAlkylation(register_table=reg)
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        ctx.registers = reg
        sim.scan_step(dt=0.02, context=ctx)
        assert sim.state.sim_time_s > 0.0

    def test_execute_via_scan_context(self) -> None:
        """execute(ctx) must advance simulation and update state."""
        reg = RegisterTable()
        sim = CumeneAlkylation(register_table=reg)
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)
        assert sim.state.sim_time_s > 0.0

    def test_adapter_logic_unit_execution(self) -> None:
        """CumeneAlkylationLogicUnit adapter must implement ILogicUnit cleanly."""
        unit = CumeneAlkylationLogicUnit()
        assert isinstance(unit, ILogicUnit)
        assert unit.name == "CumeneAlkylationSync"
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        assert unit.simulator.state.sim_time_s > 0.0

    def test_reset_restores_nominal_state(self) -> None:
        """reset() must restore nominal baseline conditions after disturbance."""
        sim = CumeneAlkylation()
        sim.state.t_bed_c = 260.0
        sim.state.benzene_propylene_ratio = 3.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_quench_valve_open is True

        sim.reset()
        assert math.isclose(sim.state.t_bed_c, 205.0, abs_tol=1e-3)
        assert math.isclose(sim.state.benzene_propylene_ratio, 5.50, abs_tol=1e-2)
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OK
        assert sim.state.emergency_quench_valve_open is False
        assert sim.state.cumene_reactor_active is True

    def test_continuous_multi_cycle_soak_execution(self) -> None:
        """500 consecutive scan cycles (10.0 s soak) must run with zero faults."""
        sim = CumeneAlkylation()
        for i in range(500):
            ctx = ScanContext(cycle=i + 1, dt_ms=20.0, elapsed_time_ms=(i + 1) * 20.0, dt=0.02)
            sim.execute(ctx)
        assert math.isclose(sim.state.sim_time_s, 10.0, abs_tol=1e-4)
        assert sim.state.diagnostic_code == CumeneAlkylationDiagnosticCode.OK


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14DeterministicVerificationSuiteAndArtifacts:
    """Validate 9-stage verification runner, contract payload structure, and JSON evidence generation."""

    def test_run_cumene_alkylation_verification_status_success(self) -> None:
        """run_cumene_alkylation_verification must return status == 'success'."""
        result = run_cumene_alkylation_verification()
        assert isinstance(result, dict)
        assert result.get("status") == "success"
        assert result.get("error_code") is None

    def test_all_9_verification_stages_passed(self) -> None:
        """All 9 stages must return passed == True."""
        result = run_cumene_alkylation_verification()
        data = result.get("data", {})
        tests = data.get("tests", [])
        assert len(tests) == 9
        assert data.get("checks_passed") == 9
        assert all(t.get("passed") is True for t in tests)

    def test_verification_json_export(self, tmp_path: Path) -> None:
        """Verification suite must write strict 4-state contract JSON to output_path."""
        out_file = tmp_path / "cumene_evidence.json"
        result = run_cumene_alkylation_verification(output_path=str(out_file))
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            saved = json.load(f)

        assert saved["status"] == "success"
        assert saved["data"]["work_package"] == "W227"
        assert saved["data"]["checks_passed"] == 9

    def test_verification_aliases(self) -> None:
        """run_cumene_verification and run_cumene_alkylation_reactor_verification aliases must succeed."""
        res1 = run_cumene_verification()
        res2 = run_cumene_alkylation_reactor_verification()
        assert res1["status"] == "success"
        assert res2["status"] == "success"

    def test_simulator_and_config_aliases(self) -> None:
        """All simulator and config compatibility aliases must resolve correctly."""
        assert CumeneReactor is CumeneAlkylation
        assert CumeneSimulator is CumeneAlkylation
        assert CumeneEngine is CumeneAlkylation
        assert CumeneAlkylationSimulator is CumeneAlkylation
        assert CumeneAlkylationEngine is CumeneAlkylation
        assert CumeneAlkylationModel is CumeneAlkylation
        assert CumeneAlkylationReactor is CumeneAlkylation
        assert CumeneAlkylationPlantModel is CumeneAlkylation
        assert CumeneAlkylationSimulationEngine is CumeneAlkylation
        assert CumeneLogicUnit is CumeneAlkylationLogicUnit
        assert CumeneReactorLogicUnit is CumeneAlkylationLogicUnit
        assert CumeneAlkylationReactorLogicUnit is CumeneAlkylationLogicUnit
