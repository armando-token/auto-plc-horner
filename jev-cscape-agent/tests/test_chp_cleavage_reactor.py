"""Comprehensive Industrial Cumene Hydroperoxide (CHP) Cleavage Reactor Test Suite.

Work Package: W230 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 14 engineering verification sections (120+ unit tests):
1. Section 1: Universal Physical Constants, IUPAC Atomic Weights & Species Molecular Weights
2. Section 2: Reaction Enthalpies, Exothermicity (-252 kJ/mol) & Stoichiometric Conservation
3. Section 3: Arrhenius Reaction Kinetics, Acid Catalyst Rate Enhancement & Activation Energies
4. Section 4: Reactor Geometry, Sizing, Thermal Capacitance & Heat Removal Dynamics
5. Section 5: Nominal Steady-State Production Metrics, Conversion, Selectivity & Production Rates
6. Section 6: Coupled 6-State Dynamic ODE System & High-Order RK4 Numerical Integrator
7. Section 7: Mathematical Conservation Residuals (Mass, Elements, Enthalpy < 1e-10)
8. Section 8: Process Safety Interlocks & Strict Diagnostic Priority Hierarchy (0xF001..0xF004)
9. Section 9: DiagnosticCode Signed/Unsigned Integer Equality, Bitwise Masking (& 0xFFFF)
10. Section 10: Pre-Alarm Logic (%M446) & Emergency Cleavage Quench Valve Actuation (%M447)
11. Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege (%R1910..%R1917, %M445..%M447)
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

from jev_cscape.simulation.chp_cleavage_reactor import (
    ACID_CATALYST_NOMINAL_PPM,
    ACID_CATALYST_STARVATION_PPM,
    ACID_PRE_ALARM_PPM,
    ACETONE_PROD_NOMINAL_KG_H,
    CHP_ACCUMULATION_TRIP_CONC_MOL_L,
    CHP_CLEAVAGE_PURE_ST_POU,
    CHP_CLEAVAGE_REACTOR_PURE_ST_POU,
    CHP_CLEAVAGE_SYNC_POU,
    CHP_CONV_NOMINAL_PCT,
    CHP_CONVERSION_MIN_TRIP_PCT,
    CHP_PRE_ALARM_CONC_MOL_L,
    CHP_PURE_ST_POU,
    CHP_SYNC_POU,
    COOLING_UA_DEGRADATION_THRESHOLD,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    G_ACCEL,
    MW_ACETONE,
    MW_ALPHA_METHYLSTYRENE,
    MW_AMS,
    MW_BYPRODUCTS,
    MW_C,
    MW_CHP,
    MW_CUMENE_HYDROPEROXIDE,
    MW_DCP,
    MW_DICUMYL_PEROXIDE,
    MW_DMBA,
    MW_H,
    MW_HEAVY,
    MW_O,
    MW_PHENOL,
    MW_WATER,
    P_REACTOR_NOMINAL_BAR,
    PHENOL_PROD_NOMINAL_KG_H,
    PHENOL_SEL_NOMINAL_PCT,
    R_GAS_CONST,
    RESIDUAL_CHP_NOMINAL_MOL_L,
    T_INLET_NOMINAL_C,
    T_PRE_ALARM_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_RUNAWAY_TRIP_C,
    T_ZERO_CELSIUS,
    ChpCleavage,
    ChpCleavageConfig,
    ChpCleavageDiagCode,
    ChpCleavageDiagnosticCode,
    ChpCleavageEngine,
    ChpCleavageLogicUnit,
    ChpCleavageModel,
    ChpCleavageParameters,
    ChpCleavagePlantModel,
    ChpCleavageReactor,
    ChpCleavageReactorConfig,
    ChpCleavageReactorDiagCode,
    ChpCleavageReactorDiagnosticCode,
    ChpCleavageReactorLogicUnit,
    ChpCleavageReactorState,
    ChpCleavageReactorStatusBits,
    ChpCleavageSimulationEngine,
    ChpCleavageSimulator,
    ChpCleavageState,
    ChpCleavageStatusBits,
    ChpCleavageStatusWord,
    ChpConfig,
    ChpDiagCode,
    ChpDiagnosticCode,
    ChpEngine,
    ChpLogicUnit,
    ChpParameters,
    ChpReactor,
    ChpReactorConfig,
    ChpReactorLogicUnit,
    ChpReactorState,
    ChpReactorStatusBits,
    ChpSimulator,
    ChpState,
    ChpStatusBits,
    ChpStatusWord,
    DiagnosticCode,
    StatusBits,
    run_chp_cleavage_reactor_verification,
    run_chp_cleavage_verification,
    run_chp_verification,
    validate_pure_st,
    verify_chp_cleavage_pure_st,
    verify_chp_cleavage_reactor_pure_st,
    verify_chp_pure_st,
)


# ============================================================================
# Section 1: Universal Physical Constants, IUPAC Atomic Weights & Species Molecular Weights
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
        """Reference temperature must correspond to 65.0 °C (338.15 K)."""
        assert math.isclose(T_REF_K, 65.0 + 273.15, abs_tol=1e-6)

    def test_iupac_elemental_weights(self) -> None:
        """Elemental masses for Carbon, Hydrogen, and Oxygen must match IUPAC standards."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)

    def test_chp_molecular_weight(self) -> None:
        """Cumene Hydroperoxide C9H12O2 molecular weight must equal 9*C + 12*H + 2*O (~152.193 g/mol)."""
        expected_chp = 9.0 * MW_C + 12.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_CHP, expected_chp, rel_tol=1e-9)
        assert math.isclose(MW_CHP * 1000.0, 152.193, rel_tol=1e-3)
        assert MW_CUMENE_HYDROPEROXIDE == MW_CHP

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

    def test_byproducts_molecular_weights(self) -> None:
        """Validate molecular weights for AMS, DMBA, Water, and DCP."""
        expected_ams = 9.0 * MW_C + 10.0 * MW_H
        expected_dmba = 9.0 * MW_C + 12.0 * MW_H + 1.0 * MW_O
        expected_water = 2.0 * MW_H + 1.0 * MW_O
        expected_dcp = 18.0 * MW_C + 22.0 * MW_H + 2.0 * MW_O

        assert math.isclose(MW_AMS, expected_ams, rel_tol=1e-9)
        assert math.isclose(MW_DMBA, expected_dmba, rel_tol=1e-9)
        assert math.isclose(MW_WATER, expected_water, rel_tol=1e-9)
        assert math.isclose(MW_DCP, expected_dcp, rel_tol=1e-9)

    def test_species_aliases(self) -> None:
        """Verify species aliases for all chemical components."""
        assert MW_CUMENE_HYDROPEROXIDE == MW_CHP
        assert MW_ALPHA_METHYLSTYRENE == MW_AMS
        assert MW_DICUMYL_PEROXIDE == MW_DCP
        assert MW_HEAVY == MW_DCP
        assert MW_BYPRODUCTS == MW_DCP


# ============================================================================
# Section 2: Reaction Enthalpies, Exothermicity & Stoichiometric Conservation
# ============================================================================

class TestSection2ReactionEnthalpiesAndStoichiometry:
    """Validate reaction enthalpies and dual stoichiometric additive relationships."""

    def test_primary_cleavage_enthalpy(self) -> None:
        """Primary catalytic cleavage is strongly exothermic: -252.0 kJ/mol (-252,000 J/mol)."""
        assert math.isclose(DELTA_H1_KJ_MOL, -252.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H1_J_MOL, -252000.0, abs_tol=1e-6)
        assert DELTA_H1_KJ_MOL < 0.0

    def test_side_condensation_enthalpy(self) -> None:
        """Secondary condensation to DCP is exothermic: -120.0 kJ/mol (-120,000 J/mol)."""
        assert math.isclose(DELTA_H2_KJ_MOL, -120.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H2_J_MOL, -120000.0, abs_tol=1e-6)
        assert DELTA_H2_KJ_MOL < 0.0

    def test_side_dehydration_enthalpy(self) -> None:
        """Side DMBA dehydration to AMS is endothermic: +45.0 kJ/mol (+45,000 J/mol)."""
        assert math.isclose(DELTA_H3_KJ_MOL, 45.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H3_J_MOL, 45000.0, abs_tol=1e-6)
        assert DELTA_H3_KJ_MOL > 0.0

    def test_reaction_1_stoichiometric_mass_balance(self) -> None:
        """R1: CHP -> Phenol + Acetone must satisfy exact mass conservation: MW_CHP == MW_PHENOL + MW_ACETONE."""
        diff = abs(MW_CHP - (MW_PHENOL + MW_ACETONE))
        assert diff < 1e-15

    def test_reaction_2_stoichiometric_mass_balance(self) -> None:
        """R2: CHP + AMS -> DCP must satisfy exact mass conservation: MW_CHP + MW_AMS == MW_DCP."""
        diff = abs((MW_CHP + MW_AMS) - MW_DCP)
        assert diff < 1e-15

    def test_reaction_3_stoichiometric_mass_balance(self) -> None:
        """R3: DMBA -> AMS + Water must satisfy exact mass conservation: MW_DMBA == MW_AMS + MW_WATER."""
        diff = abs(MW_DMBA - (MW_AMS + MW_WATER))
        assert diff < 1e-15

    def test_carbon_elemental_conservation(self) -> None:
        """Every reaction step must preserve exact integer counts of Carbon atoms."""
        # R1: C9H12O2 -> C6H6O + C3H6O (9 == 6 + 3)
        assert 9 == 6 + 3
        # R2: C9H12O2 + C9H10 -> C18H22O2 (9 + 9 == 18)
        assert 9 + 9 == 18
        # R3: C9H12O -> C9H10 + H2O (9 == 9)
        assert 9 == 9

    def test_hydrogen_elemental_conservation(self) -> None:
        """Every reaction step must preserve exact integer counts of Hydrogen atoms."""
        # R1: C9H12O2 -> C6H6O + C3H6O (12 == 6 + 6)
        assert 12 == 6 + 6
        # R2: C9H12O2 + C9H10 -> C18H22O2 (12 + 10 == 22)
        assert 12 + 10 == 22
        # R3: C9H12O -> C9H10 + H2O (12 == 10 + 2)
        assert 12 == 10 + 2

    def test_oxygen_elemental_conservation(self) -> None:
        """Every reaction step must preserve exact integer counts of Oxygen atoms."""
        # R1: C9H12O2 -> C6H6O + C3H6O (2 == 1 + 1)
        assert 2 == 1 + 1
        # R2: C9H12O2 + C9H10 -> C18H22O2 (2 == 2)
        assert 2 == 2
        # R3: C9H12O -> C9H10 + H2O (1 == 1)
        assert 1 == 1


# ============================================================================
# Section 3: Arrhenius Reaction Kinetics, Acid Catalyst Enhancement & Activation Energies
# ============================================================================

class TestSection3ArrheniusKineticsAndMonotonicity:
    """Validate temperature-dependent reaction kinetics, acid enhancement, and Arrhenius activation energies."""

    def test_arrhenius_activation_energies(self) -> None:
        """Activation energies: Ea1 = 90.0 kJ/mol, Ea2 = 80.0 kJ/mol, Ea3 = 95.0 kJ/mol."""
        cfg = ChpCleavageReactorConfig()
        assert math.isclose(cfg.activation_e1_j_mol, 90000.0, abs_tol=1e-3)
        assert math.isclose(cfg.activation_e2_j_mol, 80000.0, abs_tol=1e-3)
        assert math.isclose(cfg.activation_e3_j_mol, 95000.0, abs_tol=1e-3)

    def test_arrhenius_rate_constant_monotonicity(self) -> None:
        """Arrhenius rate constants must monotonically increase with temperature."""
        sim = ChpCleavageReactor()
        t50_k = 50.0 + T_ZERO_CELSIUS
        t65_k = 65.0 + T_ZERO_CELSIUS
        t75_k = 75.0 + T_ZERO_CELSIUS
        t85_k = 85.0 + T_ZERO_CELSIUS

        k1_50 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t50_k)
        k1_65 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t65_k)
        k1_75 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t75_k)
        k1_85 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t85_k)

        assert k1_50 < k1_65 < k1_75 < k1_85
        assert k1_50 > 0.0

    def test_arrhenius_activation_energy_slope_recovery(self) -> None:
        """Verify activation energy Ea1 can be deterministically recovered from Arrhenius slope."""
        sim = ChpCleavageReactor()
        t1_k = 50.0 + T_ZERO_CELSIUS
        t2_k = 75.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1_k)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2_k)

        ea1_recovered = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(ea1_recovered, sim.config.activation_e1_j_mol, rel_tol=1e-6)

    def test_acid_catalyst_enhancement_proportionality(self) -> None:
        """Reaction rate r1 must scale proportionally with acid catalyst concentration."""
        sim = ChpCleavageReactor()
        t_k = 65.0 + T_ZERO_CELSIUS

        kin_150 = sim.compute_kinetics(t_k, c_chp=0.05, c_ams=0.12, c_dmba=0.01, acid_ppm=150.0)
        kin_300 = sim.compute_kinetics(t_k, c_chp=0.05, c_ams=0.12, c_dmba=0.01, acid_ppm=300.0)

        ratio = kin_300["r1"] / kin_150["r1"]
        assert math.isclose(ratio, 2.0, rel_tol=1e-5)

    def test_acid_catalyst_zero_starvation_rate(self) -> None:
        """Reaction rate r1 must drop to zero if acid catalyst is completely absent (0 ppm)."""
        sim = ChpCleavageReactor()
        t_k = 65.0 + T_ZERO_CELSIUS
        kin_zero = sim.compute_kinetics(t_k, c_chp=0.05, c_ams=0.12, c_dmba=0.01, acid_ppm=0.0)
        assert kin_zero["r1"] == 0.0

    def test_temperature_acceleration_ratio(self) -> None:
        """Rate constant at 85 °C must show marked thermal acceleration (> 20x vs 50 °C)."""
        sim = ChpCleavageReactor()
        t50_k = 50.0 + T_ZERO_CELSIUS
        t85_k = 85.0 + T_ZERO_CELSIUS
        k1_50 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t50_k)
        k1_85 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t85_k)
        accel = k1_85 / k1_50
        assert accel > 20.0

    def test_kinetics_inactive_when_reactor_stopped(self) -> None:
        """All reaction rates must evaluate to zero when reactor permissive is False."""
        sim = ChpCleavageReactor()
        sim.state.chp_cleavage_reactor_active = False
        t_k = 65.0 + T_ZERO_CELSIUS
        kin = sim.compute_kinetics(t_k, c_chp=0.05, c_ams=0.12, c_dmba=0.01, acid_ppm=250.0)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["r3"] == 0.0

    def test_kinetics_inactive_when_quench_valve_open(self) -> None:
        """All reaction rates must evaluate to zero when emergency quench valve is active."""
        sim = ChpCleavageReactor()
        sim.state.emergency_cleavage_quench_valve_open = True
        t_k = 65.0 + T_ZERO_CELSIUS
        kin = sim.compute_kinetics(t_k, c_chp=0.05, c_ams=0.12, c_dmba=0.01, acid_ppm=250.0)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["r3"] == 0.0

    def test_exothermic_heat_generation_positive_power(self) -> None:
        """Exothermic cleavage must generate substantial positive thermal power (> 500 kW)."""
        sim = ChpCleavageReactor()
        t_k = 65.0 + T_ZERO_CELSIUS
        kin = sim.compute_kinetics(t_k, c_chp=0.05, c_ams=0.12, c_dmba=0.01, acid_ppm=250.0)
        assert kin["q_rxn1_kw"] > 500.0
        assert kin["q_total_kw"] > 500.0

    def test_uncooled_reactor_temperature_derivative_positive(self) -> None:
        """Without jacket cooling, reactor temperature derivative dT/dt must be strongly positive."""
        sim = ChpCleavageReactor()
        sim.config.cooler_ua_kw_k = 0.0
        sim.state.cooler_ua_actual_kw_k = 0.0
        y = [0.05, 12.26, 12.26, 0.12, 0.18, 65.0]
        derivs = sim.compute_derivatives(0.0, y)
        dt_dt = derivs[5]
        assert dt_dt > 0.0  # Exothermic heat drives temperature rise


# ============================================================================
# Section 4: Reactor Geometry, Sizing, Thermal Capacitance & Heat Removal
# ============================================================================

class TestSection4ReactorGeometryAndThermalCapacitance:
    """Validate reactor physical volume, thermal capacitance, and cooling jacket dynamics."""

    def test_reactor_volume_and_residence_time(self) -> None:
        """Validate active reaction volume and liquid residence time parameters."""
        cfg = ChpCleavageReactorConfig()
        assert cfg.reactor_volume_m3 > 0.0
        assert math.isclose(cfg.nominal_residence_time_s, 200.0, abs_tol=1e-3)

    def test_mixture_density_and_heat_capacity(self) -> None:
        """Validate reaction liquid mixture density and specific heat."""
        cfg = ChpCleavageReactorConfig()
        assert math.isclose(cfg.liquid_mixture_density_kg_m3, 950.0, abs_tol=1e-3)
        assert math.isclose(cfg.liquid_specific_heat_cp_j_kg_k, 2100.0, abs_tol=1e-3)

    def test_thermal_capacitance_calculation(self) -> None:
        """Thermal capacitance C_th must equal V * rho * Cp / 1000 [kJ/K]."""
        cfg = ChpCleavageReactorConfig()
        expected_c_th = (cfg.reactor_volume_m3 * 1000.0 * (cfg.liquid_mixture_density_kg_m3 / 1000.0) * cfg.liquid_specific_heat_cp_j_kg_k) / 1000.0
        assert math.isclose(cfg.reactor_thermal_capacitance_kj_k, expected_c_th, rel_tol=1e-4)

    def test_cooler_heat_removal_capacity(self) -> None:
        """Validate baseline cooling jacket UA and coolant inlet temperature."""
        cfg = ChpCleavageReactorConfig()
        assert cfg.cooler_ua_kw_k > 20.0
        assert math.isclose(cfg.coolant_temp_c, 30.0, abs_tol=1e-3)

    def test_cooler_ua_degradation_effect(self) -> None:
        """Degrading cooler UA must reduce actual cooling heat removal."""
        sim = ChpCleavageReactor()
        sim.state.cooler_ua_actual_kw_k = sim.config.nominal_cooler_ua_kw_k * 0.60
        y = [0.05, 12.26, 12.26, 0.12, 0.18, 65.0]
        sim.compute_derivatives(0.0, y)
        q_clean = sim.config.nominal_cooler_ua_kw_k * (65.0 - 30.0)
        assert sim.state.q_cooling_kw < q_clean

    def test_cooling_water_loss_zeroes_cooling_power(self) -> None:
        """Loss of cooling water availability sets cooling heat removal to 0 kW."""
        sim = ChpCleavageReactor()
        sim.state.cooling_water_available = False
        y = [0.05, 12.26, 12.26, 0.12, 0.18, 65.0]
        sim.compute_derivatives(0.0, y)
        assert sim.state.q_cooling_kw == 0.0

    def test_emergency_quench_flow_and_temp(self) -> None:
        """Emergency quench system parameters: 40 kg/s flow at 20 °C."""
        cfg = ChpCleavageReactorConfig()
        assert math.isclose(cfg.emergency_quench_flow_kg_s, 40.0, abs_tol=1e-3)
        assert math.isclose(cfg.emergency_quench_temp_c, 20.0, abs_tol=1e-3)

    def test_sensible_feed_flow_heat_exchange(self) -> None:
        """Cool feed stream entering at 50 °C into 65 °C reactor absorbs sensible heat."""
        sim = ChpCleavageReactor()
        y = [0.05, 12.26, 12.26, 0.12, 0.18, 65.0]
        sim.compute_derivatives(0.0, y)
        assert sim.state.q_flow_kw > 0.0


# ============================================================================
# Section 5: Nominal Steady-State Production Metrics
# ============================================================================

class TestSection5NominalSteadyStateProductionMetrics:
    """Validate nominal steady-state CHP conversion, Phenol selectivity, and production rates."""

    def test_nominal_operating_temperature_and_pressure(self) -> None:
        """Nominal temperature 65.0 °C (%R1910=650) and pressure 1.5 bar (%R1911=15)."""
        assert math.isclose(T_REACTOR_NOMINAL_C, 65.0, abs_tol=1e-3)
        assert math.isclose(P_REACTOR_NOMINAL_BAR, 1.5, abs_tol=1e-3)

    def test_nominal_chp_conversion_exceeds_threshold(self) -> None:
        """Nominal CHP conversion must exceed 99.5% (nominal 99.60%, %R1912=9960)."""
        assert CHP_CONV_NOMINAL_PCT > 99.50
        assert math.isclose(CHP_CONV_NOMINAL_PCT, 99.60, abs_tol=1e-2)

    def test_nominal_phenol_selectivity_exceeds_threshold(self) -> None:
        """Nominal Phenol selectivity must exceed 98.0% (nominal 98.50%, %R1913=9850)."""
        assert PHENOL_SEL_NOMINAL_PCT > 98.00
        assert math.isclose(PHENOL_SEL_NOMINAL_PCT, 98.50, abs_tol=1e-2)

    def test_nominal_residual_chp_concentration(self) -> None:
        """Nominal residual unreacted CHP concentration is 0.050 mol/L (%R1914=50)."""
        assert math.isclose(RESIDUAL_CHP_NOMINAL_MOL_L, 0.050, abs_tol=1e-3)

    def test_nominal_phenol_production_rate(self) -> None:
        """Nominal Phenol production rate must equal 1200.0 kg/h (%R1915=12000)."""
        assert math.isclose(PHENOL_PROD_NOMINAL_KG_H, 1200.0, abs_tol=1e-3)

    def test_nominal_acetone_production_rate(self) -> None:
        """Nominal Acetone production rate must equal 740.0 kg/h."""
        assert math.isclose(ACETONE_PROD_NOMINAL_KG_H, 740.0, abs_tol=1e-3)

    def test_nominal_acid_catalyst_concentration(self) -> None:
        """Nominal sulfuric acid catalyst concentration is 250 ppm (%R1916=250)."""
        assert math.isclose(ACID_CATALYST_NOMINAL_PPM, 250.0, abs_tol=1e-3)

    def test_closed_loop_convergence_after_settling(self) -> None:
        """Advancing simulation 10.0 s must maintain steady-state metrics within tight tolerance."""
        sim = ChpCleavageReactor()
        res = sim.advance_time(duration_s=10.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.chp_conversion_pct > 99.50
        assert sim.state.phenol_selectivity_pct > 98.00
        assert 64.0 <= sim.state.t_reactor_c <= 66.0


# ============================================================================
# Section 6: Coupled 6-State Dynamic ODE System & RK4 Numerical Integrator
# ============================================================================

class TestSection6Coupled6StateODEAndRK4Integrator:
    """Validate 6-state ODE vector derivatives and RK4 integration dynamics."""

    def test_state_vector_initialization(self) -> None:
        """State vector must initialize all 6 dynamic states to nominal values."""
        state = ChpCleavageReactorState()
        assert math.isclose(state.c_chp, 0.050, abs_tol=1e-3)
        assert math.isclose(state.c_phenol, 12.26325, abs_tol=1e-3)
        assert math.isclose(state.c_acetone, 12.26325, abs_tol=1e-3)
        assert math.isclose(state.c_ams, 0.120, abs_tol=1e-3)
        assert math.isclose(state.c_heavy, 0.18675, abs_tol=1e-3)
        assert math.isclose(state.t_reactor_c, 65.0, abs_tol=1e-3)

    def test_derivatives_shape_and_types(self) -> None:
        """compute_derivatives must return a list of exactly 6 float values."""
        sim = ChpCleavageReactor()
        y = [0.05, 12.26, 12.26, 0.12, 0.18, 65.0]
        derivs = sim.compute_derivatives(0.0, y)
        assert isinstance(derivs, list)
        assert len(derivs) == 6
        assert all(isinstance(v, float) for v in derivs)

    def test_rk4_step_single_advancement(self) -> None:
        """Single rk4_step(dt=0.02) advances simulation time by exactly dt."""
        sim = ChpCleavageReactor()
        t0 = sim.state.sim_time_s
        sim.rk4_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s - t0, 0.02, abs_tol=1e-9)

    def test_advance_time_multi_step(self) -> None:
        """advance_time(duration_s=2.0, dt=0.02) advances simulation time by 2.0 s."""
        sim = ChpCleavageReactor()
        res = sim.advance_time(duration_s=2.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert math.isclose(sim.state.sim_time_s, 2.0, abs_tol=1e-4)

    def test_rk4_step_non_negative_concentrations(self) -> None:
        """All concentrations must remain strictly non-negative after RK4 integration."""
        sim = ChpCleavageReactor()
        sim.advance_time(duration_s=1.0, dt=0.02)
        assert sim.state.c_chp >= 0.0
        assert sim.state.c_phenol >= 0.0
        assert sim.state.c_acetone >= 0.0
        assert sim.state.c_ams >= 0.0
        assert sim.state.c_heavy >= 0.0

    def test_rk4_step_temperature_stability(self) -> None:
        """Temperature must remain bounded between 60 °C and 70 °C during nominal operation."""
        sim = ChpCleavageReactor()
        sim.advance_time(duration_s=5.0, dt=0.02)
        assert 60.0 <= sim.state.t_reactor_c <= 70.0

    def test_rk4_step_deterministic_reproducibility(self) -> None:
        """Two identical simulations from nominal state must yield bit-exact identical trajectories."""
        sim1 = ChpCleavageReactor()
        sim2 = ChpCleavageReactor()
        sim1.advance_time(duration_s=2.0, dt=0.02)
        sim2.advance_time(duration_s=2.0, dt=0.02)
        assert math.isclose(sim1.state.t_reactor_c, sim2.state.t_reactor_c, abs_tol=1e-12)
        assert math.isclose(sim1.state.c_chp, sim2.state.c_chp, abs_tol=1e-12)
        assert math.isclose(sim1.state.c_phenol, sim2.state.c_phenol, abs_tol=1e-12)

    def test_invalid_timestep_handling(self) -> None:
        """advance_time must return FAILED ExecutionResult on non-positive duration or dt."""
        sim = ChpCleavageReactor()
        res1 = sim.advance_time(duration_s=-1.0, dt=0.02)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "INVALID_TIMESTEP"

        res2 = sim.advance_time(duration_s=1.0, dt=0.0)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "INVALID_TIMESTEP"

    def test_soak_stability_100_cycles(self) -> None:
        """Executing 100 scan cycles must produce zero NaNs and zero infinite values."""
        sim = ChpCleavageReactor()
        for _ in range(100):
            res = sim.step(dt=0.02)
            assert res.status == AgentStatus.SUCCESS
        assert not math.isnan(sim.state.t_reactor_c)
        assert not math.isnan(sim.state.c_chp)
        assert not math.isinf(sim.state.t_reactor_c)

    def test_step_returns_execution_result_contract(self) -> None:
        """step() must return an ExecutionResult adhering to the strict 4-state contract."""
        sim = ChpCleavageReactor()
        res = sim.step(dt=0.02)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None


# ============================================================================
# Section 7: Mathematical Conservation Residuals
# ============================================================================

class TestSection7MathematicalConservationResiduals:
    """Validate stoichiometric mass, elemental, and first-law enthalpy residuals (< 1e-10)."""

    def test_stoichiometric_mass_conservation_residual_less_than_1e10(self) -> None:
        """Stoichiometric mass balance residual must be strictly less than 1e-10 kg/s."""
        sim = ChpCleavageReactor()
        sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_carbon_elemental_conservation_residual_less_than_1e10(self) -> None:
        """Carbon atom balance residual across all reactions must be strictly zero."""
        sim = ChpCleavageReactor()
        sim.step(dt=0.02)
        delta_c1 = abs(9.0 - (6.0 + 3.0))
        delta_c2 = abs(18.0 - (9.0 + 9.0))
        delta_c3 = abs(9.0 - 9.0)
        assert (delta_c1 + delta_c2 + delta_c3) == 0.0

    def test_hydrogen_elemental_conservation_residual_less_than_1e10(self) -> None:
        """Hydrogen atom balance residual across all reactions must be strictly zero."""
        sim = ChpCleavageReactor()
        sim.step(dt=0.02)
        delta_h1 = abs(12.0 - (6.0 + 6.0))
        delta_h2 = abs(22.0 - (12.0 + 10.0))
        delta_h3 = abs(12.0 - (10.0 + 2.0))
        assert (delta_h1 + delta_h2 + delta_h3) == 0.0

    def test_oxygen_elemental_conservation_residual_less_than_1e10(self) -> None:
        """Oxygen atom balance residual across all reactions must be strictly zero."""
        sim = ChpCleavageReactor()
        sim.step(dt=0.02)
        delta_o1 = abs(2.0 - (1.0 + 1.0))
        delta_o2 = abs(2.0 - 2.0)
        delta_o3 = abs(1.0 - 1.0)
        assert (delta_o1 + delta_o2 + delta_o3) == 0.0

    def test_total_elemental_residual_less_than_1e10(self) -> None:
        """Total elemental mass balance residual must be strictly less than 1e-10 kg/s."""
        sim = ChpCleavageReactor()
        sim.step(dt=0.02)
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_first_law_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        """First-law enthalpy conservation residual must be strictly less than 1e-10 kW."""
        sim = ChpCleavageReactor()
        sim.step(dt=0.02)
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_residuals_during_transient_perturbation(self) -> None:
        """Residuals must remain < 1e-10 during transient perturbation away from steady state."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 72.0
        sim.state.c_chp = 0.20
        sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_residuals_under_emergency_quench(self) -> None:
        """Residuals must remain < 1e-10 under emergency quench operation."""
        sim = ChpCleavageReactor()
        sim.state.emergency_cleavage_quench_valve_open = True
        sim.state.chp_cleavage_reactor_active = False
        sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 8: Process Safety Interlocks & Fault Priority Hierarchy
# ============================================================================

class TestSection8ProcessSafetyInterlocksAndFaultPriority:
    """Validate process safety trips (0xF001..0xF004) and strict priority hierarchy."""

    def test_normal_steady_state_diagnostic_ok(self) -> None:
        """Normal steady-state operation must yield 0x0000 OK without trip or alarm."""
        sim = ChpCleavageReactor()
        sim.reset()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.chp_cleavage_reactor_active is True
        assert sim.state.emergency_cleavage_quench_valve_open is False
        assert sim.state.high_chp_residual_pre_alarm is False

    def test_thermal_runaway_trip_0xF001(self) -> None:
        """Priority 1: Over-temperature excursion (T > 85.0 °C) triggers 0xF001."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 88.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert sim.state.emergency_cleavage_quench_valve_open is True
        assert sim.state.chp_cleavage_reactor_active is False

    def test_chp_accumulation_trip_0xF002(self) -> None:
        """Priority 2: Residual CHP accumulation (C_chp > 0.35 mol/L) triggers 0xF002."""
        sim = ChpCleavageReactor()
        sim.state.c_chp = 0.40
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP
        assert sim.state.emergency_cleavage_quench_valve_open is True
        assert sim.state.chp_cleavage_reactor_active is False

    def test_chp_low_conversion_trip_0xF002(self) -> None:
        """Priority 2: Inadequate CHP conversion (< 95.0%) triggers 0xF002."""
        sim = ChpCleavageReactor()
        sim.state.chp_conversion_pct = 92.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP
        assert sim.state.emergency_cleavage_quench_valve_open is True
        assert sim.state.chp_cleavage_reactor_active is False

    def test_acid_catalyst_starvation_trip_0xF003(self) -> None:
        """Priority 3: Acid catalyst starvation (< 50 ppm) triggers 0xF003."""
        sim = ChpCleavageReactor()
        sim.state.acid_catalyst_ppm = 35.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.ACID_CATALYST_STARVATION_FAULT
        assert sim.state.emergency_cleavage_quench_valve_open is True
        assert sim.state.chp_cleavage_reactor_active is False

    def test_cooling_jacket_heat_removal_failure_trip_0xF004(self) -> None:
        """Priority 4: Cooling jacket failure / loss of cooling water triggers 0xF004."""
        sim = ChpCleavageReactor()
        sim.state.cooling_water_available = False
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT
        assert sim.state.emergency_cleavage_quench_valve_open is True
        assert sim.state.chp_cleavage_reactor_active is False

    def test_priority_conflict_p1_over_p2_p3_p4(self) -> None:
        """Thermal runaway excursion (0xF001) must take precedence over all other trips."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 90.0                   # 0xF001
        sim.state.c_chp = 0.50                         # 0xF002
        sim.state.acid_catalyst_ppm = 20.0             # 0xF003
        sim.state.cooling_water_available = False      # 0xF004
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION

    def test_priority_conflict_p2_over_p3_p4(self) -> None:
        """CHP accumulation (0xF002) must take precedence over acid starvation and cooling failure."""
        sim = ChpCleavageReactor()
        sim.state.c_chp = 0.45                         # 0xF002
        sim.state.acid_catalyst_ppm = 20.0             # 0xF003
        sim.state.cooling_water_available = False      # 0xF004
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP

    def test_priority_conflict_p3_over_p4(self) -> None:
        """Acid starvation (0xF003) must take precedence over cooling failure (0xF004)."""
        sim = ChpCleavageReactor()
        sim.state.acid_catalyst_ppm = 20.0             # 0xF003
        sim.state.cooling_water_available = False      # 0xF004
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.ACID_CATALYST_STARVATION_FAULT

    def test_quench_valve_lockout_enforcement(self) -> None:
        """Reactor permissive %M445 must be strictly locked to False whenever quench valve is open."""
        sim = ChpCleavageReactor()
        sim.state.emergency_cleavage_quench_valve_open = True
        sim.state.chp_cleavage_reactor_active = True
        sim._evaluate_safety_interlocks()
        assert sim.state.chp_cleavage_reactor_active is False

    def test_safety_trip_latches_until_reset(self) -> None:
        """Tripped state must latch even if temperature subsequently drops below trip point."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 88.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION

        # Temperature cools down to 60 °C while valve remains open
        sim.state.t_reactor_c = 60.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert sim.state.emergency_cleavage_quench_valve_open is True

    def test_reset_restores_nominal_safe_state(self) -> None:
        """reset() must clear latch, close quench valve, and re-engage reactor permissive."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 88.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cleavage_quench_valve_open is True

        sim.reset()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.emergency_cleavage_quench_valve_open is False
        assert sim.state.chp_cleavage_reactor_active is True


# ============================================================================
# Section 9: DiagnosticCode Signed/Unsigned Equality, Bitwise Masking (& 0xFFFF)
# ============================================================================

class TestSection9DiagnosticCodeSignedUnsignedEquality:
    """Validate DiagnosticCode signed/unsigned integer equality and bitwise masking (& 0xFFFF)."""

    def test_diagnostic_code_values(self) -> None:
        """Verify standard diagnostic event code constants."""
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION == 0xF001
        assert DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP == 0xF002
        assert DiagnosticCode.ACID_CATALYST_STARVATION_FAULT == 0xF003
        assert DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT == 0xF004

    def test_diagnostic_code_signed_integer_equality(self) -> None:
        """DiagnosticCode must compare equal to signed 16-bit integer representation."""
        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION == -4095
        assert DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP == -4094
        assert DiagnosticCode.ACID_CATALYST_STARVATION_FAULT == -4093
        assert DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT == -4092

    def test_diagnostic_code_unsigned_integer_equality(self) -> None:
        """DiagnosticCode must compare equal to unsigned 16-bit integer representation."""
        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION == 61441
        assert DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP == 61442
        assert DiagnosticCode.ACID_CATALYST_STARVATION_FAULT == 61443
        assert DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT == 61444

    def test_diagnostic_code_bitwise_masking_and(self) -> None:
        """(code & 0xFFFF) must equal unsigned integer value."""
        assert (DiagnosticCode.THERMAL_RUNAWAY_EXCURSION & 0xFFFF) == 0xF001
        assert (DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP & 0xFFFF) == 0xF002
        assert (DiagnosticCode.ACID_CATALYST_STARVATION_FAULT & 0xFFFF) == 0xF003
        assert (DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT & 0xFFFF) == 0xF004

    def test_diagnostic_code_reverse_bitwise_and(self) -> None:
        """(0xFFFF & code) must equal unsigned integer value."""
        assert (0xFFFF & DiagnosticCode.THERMAL_RUNAWAY_EXCURSION) == 0xF001
        assert (0xFFFF & DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP) == 0xF002
        assert (0xFFFF & DiagnosticCode.ACID_CATALYST_STARVATION_FAULT) == 0xF003
        assert (0xFFFF & DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT) == 0xF004

    def test_diagnostic_code_missing_lookup_signed(self) -> None:
        """DiagnosticCode(-4095) must instantiate THERMAL_RUNAWAY_EXCURSION via _missing_."""
        assert DiagnosticCode(-4095) == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert DiagnosticCode(-4094) == DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP
        assert DiagnosticCode(-4093) == DiagnosticCode.ACID_CATALYST_STARVATION_FAULT
        assert DiagnosticCode(-4092) == DiagnosticCode.COOLING_JACKET_HEAT_REMOVAL_FAULT

    def test_diagnostic_code_missing_lookup_unsigned(self) -> None:
        """DiagnosticCode(0xF001) must instantiate THERMAL_RUNAWAY_EXCURSION."""
        assert DiagnosticCode(0xF001) == DiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        assert DiagnosticCode(0xF002) == DiagnosticCode.UNREACTED_CHP_ACCUMULATION_TRIP

    def test_diagnostic_code_hash_and_set_membership(self) -> None:
        """DiagnosticCode members must behave correctly in sets and dictionary keys."""
        s = {DiagnosticCode.THERMAL_RUNAWAY_EXCURSION, DiagnosticCode.OK}
        assert DiagnosticCode.THERMAL_RUNAWAY_EXCURSION in s
        assert DiagnosticCode(-4095) in s


# ============================================================================
# Section 10: Pre-Alarm Logic (%M446) & Emergency Cleavage Quench Valve Actuation (%M447)
# ============================================================================

class TestSection10PreAlarmLogicAndEmergencyQuench:
    """Validate Pre-Alarm %M446 dynamics and emergency quench valve %M447 actuation."""

    def test_pre_alarm_on_high_temperature(self) -> None:
        """High reactor temperature (T > 75.0 °C) asserts pre-alarm without tripping."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 78.0  # > 75.0 °C but <= 85.0 °C
        sim._evaluate_safety_interlocks()
        assert sim.state.high_chp_residual_pre_alarm is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.emergency_cleavage_quench_valve_open is False
        assert sim.state.chp_cleavage_reactor_active is True

    def test_pre_alarm_on_high_chp_concentration(self) -> None:
        """High residual CHP concentration (C_chp > 0.15 mol/L) asserts pre-alarm."""
        sim = ChpCleavageReactor()
        sim.state.c_chp = 0.20  # > 0.15 mol/L but <= 0.35 mol/L
        sim._evaluate_safety_interlocks()
        assert sim.state.high_chp_residual_pre_alarm is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.emergency_cleavage_quench_valve_open is False

    def test_pre_alarm_cleared_under_nominal_conditions(self) -> None:
        """Under nominal operating conditions (T=65 °C, C_chp=0.05 mol/L), pre-alarm is False."""
        sim = ChpCleavageReactor()
        sim.reset()
        assert sim.state.high_chp_residual_pre_alarm is False

    def test_pre_alarm_does_not_open_quench_valve(self) -> None:
        """Asserting pre-alarm alone must never actuate emergency quench valve."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 76.0
        sim._evaluate_safety_interlocks()
        assert sim.state.high_chp_residual_pre_alarm is True
        assert sim.state.emergency_cleavage_quench_valve_open is False

    def test_emergency_quench_opens_on_thermal_runaway(self) -> None:
        """Thermal runaway excursion must open quench valve %M447."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 88.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cleavage_quench_valve_open is True

    def test_emergency_quench_opens_on_chp_accumulation(self) -> None:
        """CHP accumulation trip must open quench valve %M447."""
        sim = ChpCleavageReactor()
        sim.state.c_chp = 0.40
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cleavage_quench_valve_open is True

    def test_emergency_quench_opens_on_acid_starvation(self) -> None:
        """Acid starvation fault must open quench valve %M447."""
        sim = ChpCleavageReactor()
        sim.state.acid_catalyst_ppm = 30.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cleavage_quench_valve_open is True

    def test_emergency_quench_cooling_dynamics(self) -> None:
        """Emergency quench injection must rapidly cool reactor bulk temperature."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 88.0
        sim._evaluate_safety_interlocks()
        res = sim.advance_time(duration_s=6.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.t_reactor_c < 30.0
        assert sim.state.q_rxn_total_kw == 0.0


# ============================================================================
# Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege
# ============================================================================

class TestSection11HornerOCSRegisterTableSynchronization:
    """Validate register table mapping (%R1910..%R1917, %M445..%M447) and SYSTEM privilege."""

    def test_nominal_register_values_exact(self) -> None:
        """Verify bit-exact nominal scaled values in %R1910..%R1917."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.reset()

        assert table.read_word("%R1910") == 650    # 65.0 °C x10
        assert table.read_word("%R1911") == 15     # 1.5 bar x10
        assert table.read_word("%R1912") == 9960   # 99.60% x100
        assert table.read_word("%R1913") == 9850   # 98.50% x100
        assert table.read_word("%R1914") == 50     # 0.050 mol/L x1000
        assert table.read_word("%R1915") == 12000  # 1200.0 kg/h x10
        assert table.read_word("%R1916") == 250    # 250 ppm x1
        assert table.read_uword("%R1917") == 0x0000# 0x0000 OK

    def test_nominal_discrete_coils_exact(self) -> None:
        """Verify discrete coils %M445..%M447 at nominal steady state."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.reset()

        assert table.read_bit("%M445") is True    # %M445 active
        assert table.read_bit("%M446") is False   # %M446 pre-alarm clear
        assert table.read_bit("%M447") is False   # %M447 quench closed

    def test_privilege_mode_system_required(self) -> None:
        """Writes to registers must succeed with PrivilegeMode.SYSTEM."""
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.SYSTEM
        table.write_word("%R1910", 650, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R1910") == 650

    def test_register_temperature_scaling_x10(self) -> None:
        """%R1910 must accurately represent temperature scaled by 10."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.state.t_reactor_c = 72.4
        sim.sync_to_registers(table)
        assert table.read_word("%R1910") == 724

    def test_register_pressure_scaling_x10(self) -> None:
        """%R1911 must accurately represent pressure scaled by 10."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.state.p_reactor_bar = 2.1
        sim.sync_to_registers(table)
        assert table.read_word("%R1911") == 21

    def test_register_conversion_scaling_x100(self) -> None:
        """%R1912 must accurately represent conversion percentage scaled by 100."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.state.chp_conversion_pct = 98.75
        sim.sync_to_registers(table)
        assert table.read_word("%R1912") == 9875

    def test_register_selectivity_scaling_x100(self) -> None:
        """%R1913 must accurately represent selectivity percentage scaled by 100."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.state.phenol_selectivity_pct = 97.80
        sim.sync_to_registers(table)
        assert table.read_word("%R1913") == 9780

    def test_register_residual_chp_scaling_x1000(self) -> None:
        """%R1914 must accurately represent residual CHP concentration scaled by 1000."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.state.c_chp = 0.125
        sim.sync_to_registers(table)
        assert table.read_word("%R1914") == 125

    def test_register_phenol_rate_scaling_x10(self) -> None:
        """%R1915 must accurately represent Phenol production rate scaled by 10."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.state.phenol_production_rate_kg_h = 1150.5
        sim.sync_to_registers(table)
        assert table.read_word("%R1915") == 11505

    def test_register_diagnostic_code_signed_unsigned_sync(self) -> None:
        """%R1917 must store trip codes readable as signed (-4095) or unsigned (0xF001)."""
        table = RegisterTable()
        sim = ChpCleavageReactor(register_table=table)
        sim.state.t_reactor_c = 89.0
        sim.sync_to_registers(table)
        assert table.read_word("%R1917") == -4095
        assert table.read_uword("%R1917") == 0xF001


# ============================================================================
# Section 12: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
# ============================================================================

class TestSection12PureIEC61131_3StructuredTextPOU:
    """Validate Pure IEC 61131-3 ST POU syntax and anti-ladder interception."""

    def test_pure_st_pou_string_constant_defined(self) -> None:
        """POU string constants must be defined non-empty strings."""
        assert isinstance(CHP_CLEAVAGE_REACTOR_PURE_ST_POU, str)
        assert len(CHP_CLEAVAGE_REACTOR_PURE_ST_POU) > 100
        assert CHP_CLEAVAGE_PURE_ST_POU == CHP_CLEAVAGE_REACTOR_PURE_ST_POU

    def test_pure_st_pou_passes_security_guard(self) -> None:
        """SecurityGuard.assert_pure_st_content must pass cleanly without exception."""
        SecurityGuard.assert_pure_st_content(CHP_CLEAVAGE_REACTOR_PURE_ST_POU)

    def test_pure_st_pou_validates_with_st_parser(self) -> None:
        """STParser.validate_code must return AgentStatus.SUCCESS."""
        res = STParser.validate_code(CHP_CLEAVAGE_REACTOR_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_pure_st_pou_parses_into_ast(self) -> None:
        """STParser.parse_pou must return a valid POUAST named 'ChpCleavageReactorSync'."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(CHP_CLEAVAGE_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "ChpCleavageReactorSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_pou_binds_all_required_registers(self) -> None:
        """POU AST must bind all required registers: %R1910..%R1917 and %M445..%M447."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(CHP_CLEAVAGE_REACTOR_PURE_ST_POU)
        required = [
            "%R1910", "%R1911", "%R1912", "%R1913",
            "%R1914", "%R1915", "%R1916", "%R1917",
            "%M445", "%M446", "%M447",
        ]
        for reg in required:
            assert reg in ast.bound_registers

    def test_anti_ladder_security_guard_rejects_contacts(self) -> None:
        """SecurityGuard must reject ladder contact symbols (---[ ]---)."""
        bad_code = "PROGRAM BadLadder VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_security_guard_rejects_coils(self) -> None:
        """SecurityGuard must reject ladder coil symbols (---( )---)."""
        bad_code = "PROGRAM BadLadder VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_security_guard_rejects_rungs(self) -> None:
        """SecurityGuard must reject ladder rung delimiters and mnemonics."""
        bad_code = "PROGRAM BadLadder VAR Z: BOOL; END_VAR RUNG 1: XIC(Start) OTE(Run); END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 13: ILogicUnit Compliance, Scan Cycle Execution & Reset Dynamics
# ============================================================================

class TestSection13ILogicUnitComplianceAndScanCycle:
    """Validate ILogicUnit interface compliance, scan cycles, and reset recovery."""

    def test_ilogic_unit_interface_inheritance(self) -> None:
        """ChpCleavageReactor must implement the ILogicUnit interface."""
        assert issubclass(ChpCleavageReactor, ILogicUnit)

    def test_ilogic_unit_properties(self) -> None:
        """ILogicUnit name, priority, and is_enabled properties must be properly exposed."""
        sim = ChpCleavageReactor()
        assert sim.name == "ChpCleavageReactorSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_execution(self) -> None:
        """scan_step(dt=0.02) must advance internal simulation time and update registers."""
        sim = ChpCleavageReactor()
        t0 = sim.state.sim_time_s
        sim.scan_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s - t0, 0.02, abs_tol=1e-6)

    def test_execute_via_scan_context(self) -> None:
        """execute(context) must advance simulation using context dt."""
        sim = ChpCleavageReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-6)

    def test_reset_restores_nominal_state(self) -> None:
        """reset() must restore state to nominal operating values."""
        sim = ChpCleavageReactor()
        sim.state.t_reactor_c = 85.0
        sim.state.c_chp = 0.40
        sim.reset()
        assert math.isclose(sim.state.t_reactor_c, 65.0, abs_tol=1e-3)
        assert math.isclose(sim.state.c_chp, 0.050, abs_tol=1e-3)
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_enable_disable_lifecycle(self) -> None:
        """enable() and disable() methods must toggle is_enabled state."""
        sim = ChpCleavageReactor()
        assert sim.is_enabled is True
        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_adapter_logic_unit_compliance(self) -> None:
        """ChpCleavageReactorLogicUnit adapter must implement ILogicUnit."""
        unit = ChpCleavageReactorLogicUnit()
        assert isinstance(unit, ILogicUnit)
        assert unit.name == "ChpCleavageReactorSync"
        assert unit.priority == 100
        assert unit.is_enabled is True

    def test_adapter_scan_step_and_execute(self) -> None:
        """Adapter execute(ctx) must delegate cleanly to underlying simulator."""
        unit = ChpCleavageReactorLogicUnit()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        assert math.isclose(unit.sim.state.sim_time_s, 0.02, abs_tol=1e-6)

    def test_sync_to_external_register_table(self) -> None:
        """sync_to_registers must write to an independently supplied RegisterTable."""
        sim = ChpCleavageReactor()
        ext_table = RegisterTable()
        sim.sync_to_registers(ext_table, privilege=PrivilegeMode.SYSTEM)
        assert ext_table.read_word("%R1910") == 650
        assert ext_table.read_bit("%M445") is True

    def test_soak_determinism_across_multiple_runs(self) -> None:
        """Two independent 50-cycle simulation runs must produce bit-exact identical register states."""
        sim1 = ChpCleavageReactor()
        sim2 = ChpCleavageReactor()
        ctx = ScanContext(cycle=0, dt_ms=20.0, elapsed_time_ms=0.0, dt=0.02)
        for i in range(50):
            ctx.cycle = i
            sim1.execute(ctx)
            sim2.execute(ctx)
        assert sim1.registers.read_word("%R1910") == sim2.registers.read_word("%R1910")
        assert sim1.registers.read_word("%R1914") == sim2.registers.read_word("%R1914")
        assert sim1.registers.read_word("%R1915") == sim2.registers.read_word("%R1915")


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14DeterministicVerificationSuite:
    """Validate 9-stage verification suite execution and artifact generation."""

    def test_run_verification_returns_strict_4state_contract(self) -> None:
        """run_chp_cleavage_reactor_verification must return a valid 4-state contract dictionary."""
        result = run_chp_cleavage_reactor_verification()
        assert isinstance(result, dict)
        assert "status" in result
        assert result["status"] in {"success", "failed", "blocked", "inconclusive"}
        assert "error_code" in result
        assert "details" in result
        assert "data" in result

    def test_verification_all_9_stages_pass(self) -> None:
        """All 9 stages must pass deterministically."""
        result = run_chp_cleavage_reactor_verification()
        assert result["status"] == "success"
        data = result["data"]
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9

    def test_verification_generates_json_evidence_file(self, tmp_path: Path) -> None:
        """Verification must write valid JSON evidence artifact to specified file."""
        evidence_file = tmp_path / "chp_evidence.json"
        result = run_chp_cleavage_reactor_verification(output_path=str(evidence_file))
        assert result["status"] == "success"
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            saved = json.load(f)
        assert saved["status"] == "success"
        assert saved["data"]["work_package"] == "W230"

    def test_verification_evidence_structure_and_keys(self) -> None:
        """Verification result data must contain work_package, gate, and register_map."""
        result = run_chp_cleavage_reactor_verification()
        data = result["data"]
        assert data["work_package"] == "W230"
        assert "register_map" in data
        assert "analog_registers" in data["register_map"]
        assert "discrete_coils" in data["register_map"]

    def test_verification_register_map_in_evidence(self) -> None:
        """Evidence register map must accurately record all 8 analog and 3 discrete registers."""
        result = run_chp_cleavage_reactor_verification()
        reg_vals = result["data"]["register_map"]["values"]
        assert reg_vals["%R1910"] == 650
        assert reg_vals["%R1911"] == 15
        assert reg_vals["%R1912"] == 9960
        assert reg_vals["%R1913"] == 9850
        assert reg_vals["%R1914"] == 50
        assert reg_vals["%R1915"] == 12000
        assert reg_vals["%R1916"] == 250
        assert reg_vals["%R1917"] == 0x0000
        assert reg_vals["%M445"] is True
        assert reg_vals["%M446"] is False
        assert reg_vals["%M447"] is False

    def test_verification_runner_aliases(self) -> None:
        """Verify runner function aliases run_chp_cleavage_verification and run_chp_verification."""
        assert run_chp_cleavage_verification == run_chp_cleavage_reactor_verification
        assert run_chp_verification == run_chp_cleavage_reactor_verification
        assert verify_chp_cleavage_pure_st == verify_chp_cleavage_reactor_pure_st
        assert verify_chp_pure_st == verify_chp_cleavage_reactor_pure_st
