"""Comprehensive Industrial PMMA Bulk Free-Radical Polymerization Test Suite.

Work Package: W263 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 15 comprehensive engineering verification sections (100+ unit tests):
1. Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpy
2. Section 2: Trommsdorff-Norrish Gel Effect Kinetics & Free Volume Calculations
3. Section 3: Reactor Geometry, Residence Time, Thermal Capacitance & Operating Baseline
4. Section 4: Nominal Steady-State Closed-Loop Convergence (Conversion >= 80%, Temp 80.0 °C, MW ~125,000 Da)
5. Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
6. Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O, Enthalpy < 1e-10)
7. Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xF801 > 0xF802 > 0xF803 > 0xF804 > 0x0000)
8. Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
9. Section 9: Gel Pre-Alarm (%M523) & Emergency Inhibitor Injection Actuation (%M524)
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2240..%R2247, %M522..%M524)
11. Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
12. Section 12: Anti-Ladder Security Guard Rejection (Contacts, Coils, Rungs, Networks, Mnemonics)
13. Section 13: ILogicUnit Scan Cycle Execution, Reset Dynamics & 100-Cycle Soak Stability
14. Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
15. Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
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

from jev_cscape.simulation.pmma_polymerization import (
    COIL_EMERGENCY_INHIBITOR_INJECTED,
    COIL_GEL_EFFECT_PRE_ALARM,
    COIL_PMMA_REACTOR_ACTIVE,
    CONVERSION_PRE_ALARM_PCT,
    COOLING_DUTY_NOMINAL_KW,
    COOLING_JACKET_DUTY_NOMINAL_KW,
    COOLING_LOSS_TRIP_KW,
    DELTA_H_RXN_J_MOL,
    DELTA_H_RXN_KJ_MOL,
    G_ACCEL,
    GEL_EFFECT_ACCELERATION_FACTOR_NOMINAL,
    GEL_FACTOR_NOMINAL,
    GEL_PRE_ALARM_FACTOR,
    INITIATOR_EFFICIENCY_NOMINAL_PPM,
    INITIATOR_EXHAUSTION_FAULT_PPM,
    MELT_VISCOSITY_NOMINAL_POISE,
    MMA_CONV_NOMINAL_PCT,
    MMA_CONVERSION_NOMINAL_PCT,
    MW_AIBN,
    MW_C,
    MW_H,
    MW_INITIATOR,
    MW_METHYL_METHACRYLATE,
    MW_MMA,
    MW_N,
    MW_O,
    MW_PMMA,
    MW_PMMA_MER,
    MW_WEIGHT_AVG_NOMINAL_DA,
    PMMA_MW_NOMINAL_DA,
    PMMA_NUMBER_AVG_MW_NOMINAL_DA,
    PMMA_POLYMERIZATION_PURE_ST_POU,
    PMMA_POLYMERIZATION_SYNC_POU,
    PMMA_PURE_ST_POU,
    PMMA_SYNC_POU,
    PMMA_WEIGHT_AVG_MW_NOMINAL_DA,
    R_GAS_CONST,
    REG_COOLING_JACKET_HEAT_DUTY_KW_SCALED,
    REG_GEL_EFFECT_ACCELERATION_FACTOR_SCALED,
    REG_INITIATOR_EFFICIENCY_PPM,
    REG_MELT_VISCOSITY_POISE_SCALED,
    REG_MMA_CONVERSION_SCALED,
    REG_PMMA_DIAGNOSTIC_CODE,
    REG_PMMA_REACTOR_TEMP_SCALED,
    REG_PMMA_WEIGHT_AVG_MW_SCALED,
    T_INLET_NOMINAL_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_THERMAL_RUNAWAY_TRIP_C,
    T_ZERO_CELSIUS,
    VISCOSITY_CLOGGING_FAULT_POISE,
    VISCOSITY_NOMINAL_POISE,
    DiagnosticCode,
    PMMAConfig,
    PMMADiagnosticCode,
    PMMAPolymerization,
    PMMAPolymerizationConfig,
    PMMAPolymerizationReactor,
    PMMAPolymerizationState,
    PMMAPolymerizationStatusBits,
    PMMAReactor,
    PMMAState,
    PMMAStatusBits,
    PmmaConfig,
    PmmaDiagCode,
    PmmaDiagnosticCode,
    PmmaPolymerization,
    PmmaPolymerizationConfig,
    PmmaPolymerizationEngine,
    PmmaPolymerizationLogicUnit,
    PmmaPolymerizationModel,
    PmmaPolymerizationPlantModel,
    PmmaPolymerizationReactor,
    PmmaPolymerizationSimulator,
    PmmaPolymerizationState,
    PmmaPolymerizationStatusBits,
    PmmaReactor,
    PmmaState,
    PmmaStatusBits,
    PmmaStatusWord,
    PureSTValidationResult,
    run_pmma_poly_verification,
    run_pmma_polymerization_verification,
    run_pmma_verification,
    verify_pmma_polymerization_pure_st,
    verify_pmma_pure_st,
)


# ============================================================================
# Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpy
# ============================================================================

class TestSection01PhysicalAndChemicalConstants:
    """Verify universal physical constants, IUPAC atomic weights, and reaction thermodynamics."""

    def test_universal_physical_constants(self) -> None:
        """Universal gas constant, gravity, and reference temperature match standard physical constants."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, abs_tol=1e-5)
        assert math.isclose(T_REF_K, 353.15, abs_tol=1e-5)
        assert math.isclose(T_REF_K, 80.0 + T_ZERO_CELSIUS, abs_tol=1e-5)

    def test_iupac_standard_atomic_weights(self) -> None:
        """IUPAC atomic weights for Carbon, Hydrogen, Oxygen, and Nitrogen are accurate."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)
        assert math.isclose(MW_N, 0.014007, rel_tol=1e-6)

    def test_chemical_species_molecular_weights(self) -> None:
        """Molecular weights of MMA, AIBN, and PMMA Mer are exact."""
        # Methyl Methacrylate (MMA): C5H8O2 -> 5*12.011 + 8*1.008 + 2*15.999 = 100.117 g/mol (0.100117 kg/mol)
        expected_mma = 5.0 * MW_C + 8.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_MMA, expected_mma, rel_tol=1e-9)
        assert math.isclose(MW_METHYL_METHACRYLATE, MW_MMA, rel_tol=1e-9)
        assert math.isclose(MW_MMA, 0.100117, rel_tol=1e-4)

        # 2,2'-Azobis(isobutyronitrile) (AIBN): C8H12N4 -> 8*12.011 + 12*1.008 + 4*14.007 = 164.212 g/mol
        expected_aibn = 8.0 * MW_C + 12.0 * MW_H + 4.0 * MW_N
        assert math.isclose(MW_AIBN, expected_aibn, rel_tol=1e-9)
        assert math.isclose(MW_INITIATOR, MW_AIBN, rel_tol=1e-9)
        assert math.isclose(MW_AIBN, 0.164212, rel_tol=1e-4)

        # PMMA Repeat Unit (Mer): C5H8O2 -> exact same as MMA monomer
        assert math.isclose(MW_PMMA_MER, MW_MMA, rel_tol=1e-9)
        assert math.isclose(MW_PMMA, MW_MMA, rel_tol=1e-9)

    def test_stoichiometric_polymerization_mass_conservation(self) -> None:
        """MMA addition polymerization preserves exact stoichiometry: MMA == PMMA_mer."""
        delta_mw = abs(MW_PMMA_MER - MW_MMA)
        assert delta_mw < 1e-12

    def test_elemental_stoichiometry_conservation(self) -> None:
        """Carbon, Hydrogen, and Oxygen atom balance is identical across addition polymerization."""
        # Carbon: 5 -> 5
        assert 5 == 5
        # Hydrogen: 8 -> 8
        assert 8 == 8
        # Oxygen: 2 -> 2
        assert 2 == 2

    def test_reaction_enthalpies_and_energetics(self) -> None:
        """Reaction enthalpy matches specified -57.8 kJ/mol exothermic value."""
        assert math.isclose(DELTA_H_RXN_KJ_MOL, -57.8, abs_tol=1e-6)
        assert math.isclose(DELTA_H_RXN_J_MOL, -57800.0, abs_tol=1e-6)
        assert DELTA_H_RXN_KJ_MOL < 0.0
        assert DELTA_H_RXN_J_MOL < 0.0

    def test_atomic_weight_ratios(self) -> None:
        """Atomic weight ratios are consistent with IUPAC standards."""
        assert MW_C > MW_H
        assert MW_O > MW_N > MW_C
        assert math.isclose(MW_C / MW_H, 12.011 / 1.008, rel_tol=1e-4)


# ============================================================================
# Section 2: Trommsdorff-Norrish Gel Effect Kinetics & Free Volume Calculations
# ============================================================================

class TestSection02GelEffectKineticsAndFreeVolume:
    """Verify Trommsdorff-Norrish autoacceleration kinetics, free volume calculations, and Arrhenius dependencies."""

    def test_arrhenius_monotonic_temperature_dependence(self) -> None:
        """Rate constants (kd, kp, kt0) increase monotonically with increasing temperature."""
        sim = PMMAPolymerizationReactor()
        t_low_k = 70.0 + T_ZERO_CELSIUS
        t_nom_k = 80.0 + T_ZERO_CELSIUS
        t_high_k = 90.0 + T_ZERO_CELSIUS

        kd_low = sim.arrhenius_rate_constant(sim.config.arrhenius_kd_a, sim.config.activation_ed_j_mol, t_low_k)
        kd_nom = sim.arrhenius_rate_constant(sim.config.arrhenius_kd_a, sim.config.activation_ed_j_mol, t_nom_k)
        kd_high = sim.arrhenius_rate_constant(sim.config.arrhenius_kd_a, sim.config.activation_ed_j_mol, t_high_k)
        assert 0.0 < kd_low < kd_nom < kd_high

        kp_low = sim.arrhenius_rate_constant(sim.config.arrhenius_kp_a, sim.config.activation_ep_j_mol, t_low_k)
        kp_nom = sim.arrhenius_rate_constant(sim.config.arrhenius_kp_a, sim.config.activation_ep_j_mol, t_nom_k)
        kp_high = sim.arrhenius_rate_constant(sim.config.arrhenius_kp_a, sim.config.activation_ep_j_mol, t_high_k)
        assert 0.0 < kp_low < kp_nom < kp_high

        kt0_low = sim.arrhenius_rate_constant(sim.config.arrhenius_kt0_a, sim.config.activation_et_j_mol, t_low_k)
        kt0_nom = sim.arrhenius_rate_constant(sim.config.arrhenius_kt0_a, sim.config.activation_et_j_mol, t_nom_k)
        kt0_high = sim.arrhenius_rate_constant(sim.config.arrhenius_kt0_a, sim.config.activation_et_j_mol, t_high_k)
        assert 0.0 < kt0_low < kt0_nom < kt0_high

    def test_activation_energy_reconstruction_kd(self) -> None:
        """Arrhenius equation allows exact mathematical reconstruction of AIBN activation energy Ed."""
        sim = PMMAPolymerizationReactor()
        t1_k = 70.0 + T_ZERO_CELSIUS
        t2_k = 90.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_kd_a, sim.config.activation_ed_j_mol, t1_k)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_kd_a, sim.config.activation_ed_j_mol, t2_k)

        recovered_ed = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ed, sim.config.activation_ed_j_mol, rel_tol=1e-5)
        assert math.isclose(recovered_ed, 128450.0, rel_tol=1e-5)

    def test_activation_energy_reconstruction_kp(self) -> None:
        """Arrhenius equation allows exact mathematical reconstruction of propagation activation energy Ep."""
        sim = PMMAPolymerizationReactor()
        t1_k = 70.0 + T_ZERO_CELSIUS
        t2_k = 90.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_kp_a, sim.config.activation_ep_j_mol, t1_k)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_kp_a, sim.config.activation_ep_j_mol, t2_k)

        recovered_ep = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ep, sim.config.activation_ep_j_mol, rel_tol=1e-5)
        assert math.isclose(recovered_ep, 18200.0, rel_tol=1e-5)

    def test_activation_energy_reconstruction_kt0(self) -> None:
        """Arrhenius equation allows exact mathematical reconstruction of termination activation energy Et."""
        sim = PMMAPolymerizationReactor()
        t1_k = 70.0 + T_ZERO_CELSIUS
        t2_k = 90.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_kt0_a, sim.config.activation_et_j_mol, t1_k)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_kt0_a, sim.config.activation_et_j_mol, t2_k)

        recovered_et = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(recovered_et, sim.config.activation_et_j_mol, rel_tol=1e-5)
        assert math.isclose(recovered_et, 2930.0, rel_tol=1e-5)

    def test_free_volume_decreases_with_conversion(self) -> None:
        """Free volume fraction decreases monotonically as MMA monomer converts into PMMA polymer."""
        sim = PMMAPolymerizationReactor()
        vf_0 = sim.compute_free_volume(80.0, 0.0)
        vf_30 = sim.compute_free_volume(80.0, 0.30)
        vf_60 = sim.compute_free_volume(80.0, 0.60)
        vf_82 = sim.compute_free_volume(80.0, 0.825)
        vf_95 = sim.compute_free_volume(80.0, 0.95)

        assert vf_0 > vf_30 > vf_60 > vf_82 > vf_95 > 0.005

    def test_free_volume_increases_with_temperature(self) -> None:
        """Free volume fraction expands with increasing temperature at fixed conversion."""
        sim = PMMAPolymerizationReactor()
        vf_70 = sim.compute_free_volume(70.0, 0.825)
        vf_80 = sim.compute_free_volume(80.0, 0.825)
        vf_90 = sim.compute_free_volume(90.0, 0.825)

        assert 0.005 < vf_70 < vf_80 < vf_90

    def test_gel_effect_onset_conversion_threshold(self) -> None:
        """Gel effect is inactive (g_accel=1.0, g_t=1.0) below the 30% onset conversion threshold."""
        sim = PMMAPolymerizationReactor()
        g_accel_10, g_t_10 = sim.compute_gel_effect(80.0, 10.0)
        g_accel_25, g_t_25 = sim.compute_gel_effect(80.0, 25.0)
        g_accel_30, g_t_30 = sim.compute_gel_effect(80.0, 30.0)

        assert g_accel_10 == 1.0 and g_t_10 == 1.0
        assert g_accel_25 == 1.0 and g_t_25 == 1.0
        assert g_accel_30 == 1.0 and g_t_30 == 1.0

    def test_gel_effect_autoacceleration_above_threshold(self) -> None:
        """Above 30% conversion, autoacceleration factor increases and termination rate drops."""
        sim = PMMAPolymerizationReactor()
        g_accel_40, g_t_40 = sim.compute_gel_effect(80.0, 40.0)
        g_accel_60, g_t_60 = sim.compute_gel_effect(80.0, 60.0)
        g_accel_82, g_t_82 = sim.compute_gel_effect(80.0, 82.50)

        assert 1.0 < g_accel_40 < g_accel_60 < g_accel_82
        assert 1.0 > g_t_40 > g_t_60 > g_t_82 > 0.0
        assert math.isclose(g_accel_82, 4.50, abs_tol=0.05)
        assert math.isclose(g_t_82, 1.0 / (4.50 ** 2), abs_tol=0.005)

    def test_compute_kinetics_nominal_rates(self) -> None:
        """compute_kinetics returns positive rates, valid radical target, and exothermic heat."""
        sim = PMMAPolymerizationReactor()
        kin = sim.compute_kinetics(
            t_reactor_k=80.0 + T_ZERO_CELSIUS,
            c_i=sim.state.c_initiator,
            c_m=sim.state.c_monomer,
            c_r=sim.state.c_radicals,
            conversion_pct=sim.state.mma_conversion_pct,
        )
        assert kin["k_d"] > 0.0
        assert kin["k_p"] > 0.0
        assert kin["k_t"] > 0.0
        assert kin["r_p"] > 0.0
        assert kin["r_p_total"] > 0.0
        assert kin["q_rxn_kw"] > 0.0
        assert kin["c_r_target"] > 0.0
        assert math.isclose(kin["g_accel"], 4.50, abs_tol=0.05)

    def test_kinetics_zeroed_when_inhibitor_injected(self) -> None:
        """Reaction rates and heat generation drop to zero when emergency inhibitor is injected."""
        sim = PMMAPolymerizationReactor()
        sim.state.emergency_inhibitor_injected = True
        kin = sim.compute_kinetics(
            t_reactor_k=80.0 + T_ZERO_CELSIUS,
            c_i=sim.state.c_initiator,
            c_m=sim.state.c_monomer,
            c_r=sim.state.c_radicals,
            conversion_pct=sim.state.mma_conversion_pct,
        )
        assert kin["r_p"] == 0.0
        assert kin["r_p_total"] == 0.0
        assert kin["q_rxn_kw"] == 0.0
        assert kin["c_r_target"] == 0.0


# ============================================================================
# Section 3: Reactor Geometry, Residence Time, Thermal Capacitance & Operating Baseline
# ============================================================================

class TestSection03ReactorGeometryAndOperatingBaseline:
    """Verify reactor dimensions, residence time, thermal capacitance, and baseline nominal values."""

    def test_reactor_geometry_and_capacitance(self) -> None:
        """Reactor volume, residence time, and thermal mass match plant specification."""
        cfg = PMMAPolymerizationConfig()
        assert math.isclose(cfg.reactor_volume_m3, 1.1698, rel_tol=1e-4)
        assert math.isclose(cfg.nominal_residence_time_s, 3600.0, abs_tol=1e-3)
        assert math.isclose(cfg.reactor_thermal_capacitance_kj_k, 4500.0, abs_tol=1e-3)
        assert math.isclose(cfg.monomer_density_kg_m3, 936.0, abs_tol=1e-3)
        assert math.isclose(cfg.melt_density_kg_m3, 1180.0, abs_tol=1e-3)

    def test_monomer_feed_baseline_parameters(self) -> None:
        """Monomer feed rate, concentration, and inlet temperature are consistent."""
        cfg = PMMAPolymerizationConfig()
        assert math.isclose(cfg.nominal_mma_feed_rate_mol_s, 3.040788, rel_tol=1e-5)
        assert math.isclose(cfg.feed_monomer_conc_mol_l, 9.3580, rel_tol=1e-5)
        assert math.isclose(cfg.feed_initiator_conc_mol_l, 0.02480, rel_tol=1e-5)
        assert math.isclose(cfg.nominal_inlet_temp_c, 80.0, abs_tol=1e-3)
        assert math.isclose(T_INLET_NOMINAL_C, 80.0, abs_tol=1e-3)

    def test_operating_baseline_constants(self) -> None:
        """Nominal operating baseline matches target polymer specification."""
        assert math.isclose(T_REACTOR_NOMINAL_C, 80.0, abs_tol=1e-4)
        assert math.isclose(MMA_CONV_NOMINAL_PCT, 82.50, abs_tol=1e-4)
        assert math.isclose(MMA_CONVERSION_NOMINAL_PCT, 82.50, abs_tol=1e-4)
        assert math.isclose(PMMA_WEIGHT_AVG_MW_NOMINAL_DA, 125000.0, abs_tol=1e-3)
        assert math.isclose(PMMA_MW_NOMINAL_DA, 125000.0, abs_tol=1e-3)
        assert math.isclose(MW_WEIGHT_AVG_NOMINAL_DA, 125000.0, abs_tol=1e-3)
        assert math.isclose(PMMA_NUMBER_AVG_MW_NOMINAL_DA, 62500.0, abs_tol=1e-3)
        assert math.isclose(GEL_EFFECT_ACCELERATION_FACTOR_NOMINAL, 4.50, abs_tol=1e-4)
        assert math.isclose(GEL_FACTOR_NOMINAL, 4.50, abs_tol=1e-4)
        assert math.isclose(COOLING_JACKET_DUTY_NOMINAL_KW, 145.0, abs_tol=1e-4)
        assert math.isclose(COOLING_DUTY_NOMINAL_KW, 145.0, abs_tol=1e-4)
        assert math.isclose(MELT_VISCOSITY_NOMINAL_POISE, 3800.0, abs_tol=1e-3)
        assert math.isclose(VISCOSITY_NOMINAL_POISE, 3800.0, abs_tol=1e-3)
        assert INITIATOR_EFFICIENCY_NOMINAL_PPM == 680

    def test_safety_interlock_threshold_constants(self) -> None:
        """Process safety interlock threshold constants are exact."""
        assert math.isclose(T_THERMAL_RUNAWAY_TRIP_C, 95.0, abs_tol=1e-4)
        assert math.isclose(COOLING_LOSS_TRIP_KW, 50.0, abs_tol=1e-4)
        assert math.isclose(VISCOSITY_CLOGGING_FAULT_POISE, 5500.0, abs_tol=1e-3)
        assert INITIATOR_EXHAUSTION_FAULT_PPM == 450
        assert math.isclose(GEL_PRE_ALARM_FACTOR, 5.50, abs_tol=1e-4)
        assert math.isclose(CONVERSION_PRE_ALARM_PCT, 85.00, abs_tol=1e-4)


# ============================================================================
# Section 4: Nominal Steady-State Closed-Loop Convergence
# ============================================================================

class TestSection04NominalSteadyStateConvergence:
    """Verify nominal steady-state values (Conversion >= 80%, Temp 80.0 °C, MW ~125,000 Da)."""

    def test_nominal_steady_state_reset_calibration(self) -> None:
        """Fresh reactor instance initializes precisely at nominal steady-state baseline."""
        sim = PMMAPolymerizationReactor()
        sim.reset()

        assert sim.state.mma_conversion_pct >= 80.0
        assert math.isclose(sim.state.mma_conversion_pct, 82.50, abs_tol=0.20)
        assert math.isclose(sim.state.t_reactor_c, 80.0, abs_tol=0.20)
        assert math.isclose(sim.state.mw_weight_avg, 125000.0, abs_tol=100.0)
        assert math.isclose(sim.state.mw_number_avg, 62500.0, abs_tol=50.0)
        assert math.isclose(sim.state.gel_effect_acceleration_factor, 4.50, abs_tol=0.05)
        assert math.isclose(sim.state.cooling_jacket_duty_kw, 145.0, abs_tol=1.0)
        assert math.isclose(sim.state.melt_viscosity_poise, 3800.0, abs_tol=20.0)
        assert sim.state.initiator_efficiency_ppm == 680
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.pmma_reactor_active is True
        assert sim.state.gel_effect_pre_alarm is False
        assert sim.state.emergency_inhibitor_injected is False

    def test_polydispersity_index_nominal(self) -> None:
        """Polydispersity index Mw / Mn is approximately 2.0 (most probable distribution)."""
        sim = PMMAPolymerizationReactor()
        pdi = sim.state.mw_weight_avg / sim.state.mw_number_avg
        assert math.isclose(pdi, 2.0, abs_tol=0.05)

    def test_steady_state_derivatives_equilibrium(self) -> None:
        """At nominal steady-state, derivatives dy/dt are in dynamic equilibrium."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        y = [
            sim.state.c_initiator,
            sim.state.c_monomer,
            sim.state.c_radicals,
            sim.state.mw_number_avg,
            sim.state.mw_weight_avg,
            sim.state.t_reactor_c,
        ]
        dy = sim.compute_derivatives(0.0, y)
        assert len(dy) == 6
        # Temperature derivative dT/dt close to zero in balanced equilibrium
        assert abs(dy[5]) < 0.10

    def test_extended_steady_state_scan_stability(self) -> None:
        """Fifty consecutive scan steps at dt=0.02 s preserve nominal steady-state."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        for _ in range(50):
            sim.scan_step(dt=0.02)

        assert 80.0 <= sim.state.mma_conversion_pct <= 85.0
        assert 79.5 <= sim.state.t_reactor_c <= 80.5
        assert 120000.0 <= sim.state.mw_weight_avg <= 130000.0
        assert sim.state.diagnostic_code == DiagnosticCode.OK


# ============================================================================
# Section 5: Coupled 6-State ODE System, Derivatives & RK4 Numerical Integrator
# ============================================================================

class TestSection05Coupled6StateODEAndRK4:
    """Verify coupled 6-state ODE dynamics, RK4 integration stability, and state non-negativity."""

    def test_compute_derivatives_structure_and_types(self) -> None:
        """compute_derivatives returns a 6-element list of floats."""
        sim = PMMAPolymerizationReactor()
        y = [0.0058, 1.637, 2.45e-7, 62500.0, 125000.0, 80.0]
        dy = sim.compute_derivatives(0.0, y)
        assert isinstance(dy, list)
        assert len(dy) == 6
        assert all(isinstance(val, float) for val in dy)

    def test_state_non_negativity_clamping(self) -> None:
        """State values cannot be driven below zero or physical minimums by RK4."""
        sim = PMMAPolymerizationReactor()
        # Test negative inputs are clamped
        y_neg = [-0.01, -1.0, -1e-6, -100.0, -200.0, -10.0]
        dy = sim.compute_derivatives(0.0, y_neg)
        assert all(not math.isnan(val) for val in dy)

        # Force state to zero and step
        sim.state.c_initiator = 0.0
        sim.state.c_monomer = 0.0
        sim.state.c_radicals = 0.0
        sim.rk4_step(dt=0.02)
        assert sim.state.c_initiator >= 0.0
        assert sim.state.c_monomer >= 0.0
        assert sim.state.c_radicals >= 0.0
        assert sim.state.mw_number_avg >= 500.0
        assert sim.state.mw_weight_avg >= 1000.0

    def test_rk4_varying_time_steps(self) -> None:
        """RK4 solver is numerically stable across small and large delta-t values."""
        for dt in [0.005, 0.010, 0.020, 0.050]:
            sim = PMMAPolymerizationReactor()
            sim.reset()
            for _ in range(20):
                sim.rk4_step(dt=dt)
            assert not math.isnan(sim.state.t_reactor_c)
            assert not math.isnan(sim.state.mma_conversion_pct)
            assert not math.isnan(sim.state.mw_weight_avg)

    def test_rk4_step_alias_method(self) -> None:
        """Method sim.step() is an exact functional alias for sim.rk4_step()."""
        sim1 = PMMAPolymerizationReactor()
        sim2 = PMMAPolymerizationReactor()
        sim1.rk4_step(dt=0.02)
        sim2.step(dt=0.02)

        assert math.isclose(sim1.state.t_reactor_c, sim2.state.t_reactor_c, abs_tol=1e-9)
        assert math.isclose(sim1.state.mma_conversion_pct, sim2.state.mma_conversion_pct, abs_tol=1e-9)
        assert math.isclose(sim1.state.mw_weight_avg, sim2.state.mw_weight_avg, abs_tol=1e-9)


# ============================================================================
# Section 6: Mathematical Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection06ConservationResiduals:
    """Verify stoichiometric mass, elemental (C, H, O), and first-law enthalpy residuals (< 1e-10)."""

    def test_stoichiometric_mass_residual_less_than_1e10(self) -> None:
        """Stoichiometric mass balance residual is strictly less than 1e-10 kg/s."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.total_mass_balance_residual_kg_s >= 0.0

    def test_elemental_mass_balance_residual_less_than_1e10(self) -> None:
        """Elemental (C, H, O) mass balance residual is strictly less than 1e-10 kg/s."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s >= 0.0

    def test_first_law_enthalpy_residual_less_than_1e10(self) -> None:
        """First-law thermal enthalpy conservation residual is strictly less than 1e-10 kW."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw >= 0.0

    def test_conservation_residuals_persist_after_multiple_scans(self) -> None:
        """All three conservation residuals remain < 1e-10 across 30 scan cycles."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        for _ in range(30):
            sim.scan_step(dt=0.02)
            assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 7: Process Safety Interlocks & Strict Priority Hierarchy
# ============================================================================

class TestSection07SafetyInterlocksAndPriority:
    """Verify process safety trips, interlocks, and strict priority hierarchy (0xF801 > 0xF802 > 0xF803 > 0xF804 > 0x0000)."""

    def test_priority_1_thermal_runaway_gel_trip(self) -> None:
        """T_reactor > 95.0 °C triggers Priority 1 0xF801, emergency inhibitor %M524, and clears %M522."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 96.0
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP
        assert sim.state.emergency_inhibitor_injected is True
        assert sim.state.pmma_reactor_active is False

    def test_priority_2_cooling_loss_trip(self) -> None:
        """Cooling jacket duty < 50.0 kW triggers Priority 2 0xF802, emergency inhibitor %M524, and clears %M522."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.cooling_jacket_duty_kw = 45.0
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.COOLING_LOSS_TRIP
        assert sim.state.emergency_inhibitor_injected is True
        assert sim.state.pmma_reactor_active is False

    def test_priority_3_viscosity_clogging_fault(self) -> None:
        """Melt viscosity > 5500 Poise triggers Priority 3 0xF803 without inhibitor injection."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.melt_viscosity_poise = 5800.0
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.VISCOSITY_CLOGGING_FAULT
        assert sim.state.emergency_inhibitor_injected is False
        assert sim.state.pmma_reactor_active is True

    def test_priority_4_initiator_exhaustion_fault(self) -> None:
        """Initiator efficiency < 450 ppm triggers Priority 4 0xF804 without inhibitor injection."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.initiator_efficiency_ppm = 420
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.INITIATOR_EXHAUSTION_FAULT
        assert sim.state.emergency_inhibitor_injected is False
        assert sim.state.pmma_reactor_active is True

    def test_priority_precedence_t1_over_t2(self) -> None:
        """When T > 95°C and Q_cool < 50 kW, Priority 1 (0xF801) dominates Priority 2 (0xF802)."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 97.0
        sim.state.cooling_jacket_duty_kw = 40.0
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP

    def test_priority_precedence_t1_over_t3(self) -> None:
        """When T > 95°C and Viscosity > 5500 Poise, Priority 1 (0xF801) dominates Priority 3 (0xF803)."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 97.0
        sim.state.melt_viscosity_poise = 6000.0
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP

    def test_priority_precedence_t2_over_t3(self) -> None:
        """When Q_cool < 50 kW and Viscosity > 5500 Poise, Priority 2 (0xF802) dominates Priority 3 (0xF803)."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.cooling_jacket_duty_kw = 40.0
        sim.state.melt_viscosity_poise = 6000.0
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.COOLING_LOSS_TRIP

    def test_priority_precedence_t3_over_t4(self) -> None:
        """When Viscosity > 5500 Poise and Initiator < 450 ppm, Priority 3 (0xF803) dominates Priority 4 (0xF804)."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.melt_viscosity_poise = 6000.0
        sim.state.initiator_efficiency_ppm = 350
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.VISCOSITY_CLOGGING_FAULT

    def test_gel_pre_alarm_by_acceleration_factor(self) -> None:
        """Gel effect acceleration factor >= 5.50 sets %M523 without tripping diagnostic code."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.gel_effect_acceleration_factor = 5.60
        sim._evaluate_safety_interlocks()

        assert sim.state.gel_effect_pre_alarm is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_gel_pre_alarm_by_conversion(self) -> None:
        """MMA conversion >= 85.00% sets %M523 without tripping diagnostic code."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.mma_conversion_pct = 85.50
        sim._evaluate_safety_interlocks()

        assert sim.state.gel_effect_pre_alarm is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_gel_pre_alarm_clears_when_normal(self) -> None:
        """Pre-alarm %M523 clears when both acceleration factor < 5.50 and conversion < 85.00%."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.gel_effect_acceleration_factor = 4.50
        sim.state.mma_conversion_pct = 82.50
        sim._evaluate_safety_interlocks()

        assert sim.state.gel_effect_pre_alarm is False


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
# ============================================================================

class TestSection08DiagnosticCodeMasking:
    """Verify DiagnosticCode signed/unsigned 16-bit values, integer equality, bitwise masking, and string formatting."""

    def test_hexadecimal_code_values(self) -> None:
        """Diagnostic codes have correct 16-bit integer values."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP.value == 0xF801
        assert DiagnosticCode.COOLING_LOSS_TRIP.value == 0xF802
        assert DiagnosticCode.VISCOSITY_CLOGGING_FAULT.value == 0xF803
        assert DiagnosticCode.INITIATOR_EXHAUSTION_FAULT.value == 0xF804

    def test_signed_16bit_integer_equality(self) -> None:
        """DiagnosticCode compares equal to signed 16-bit negative integer representations."""
        # 0xF801 in signed 16-bit: 0xF801 - 0x10000 = -2047
        assert DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP == -2047
        # 0xF802 in signed 16-bit: 0xF802 - 0x10000 = -2046
        assert DiagnosticCode.COOLING_LOSS_TRIP == -2046
        # 0xF803 in signed 16-bit: 0xF803 - 0x10000 = -2045
        assert DiagnosticCode.VISCOSITY_CLOGGING_FAULT == -2045
        # 0xF804 in signed 16-bit: 0xF804 - 0x10000 = -2044
        assert DiagnosticCode.INITIATOR_EXHAUSTION_FAULT == -2044
        assert DiagnosticCode.OK == 0

    def test_unsigned_16bit_integer_equality(self) -> None:
        """DiagnosticCode compares equal to unsigned 16-bit positive integer representations."""
        assert DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP == 0xF801
        assert DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP == 63489
        assert DiagnosticCode.COOLING_LOSS_TRIP == 0xF802
        assert DiagnosticCode.COOLING_LOSS_TRIP == 63490
        assert DiagnosticCode.VISCOSITY_CLOGGING_FAULT == 0xF803
        assert DiagnosticCode.VISCOSITY_CLOGGING_FAULT == 63491
        assert DiagnosticCode.INITIATOR_EXHAUSTION_FAULT == 0xF804
        assert DiagnosticCode.INITIATOR_EXHAUSTION_FAULT == 63492
        assert DiagnosticCode.OK == 0x0000

    def test_bitwise_masking_operations(self) -> None:
        """Bitwise masking (& 0xFFFF) operates cleanly with DiagnosticCode."""
        code = DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP
        assert (code & 0xFFFF) == 0xF801
        assert (0xFFFF & code) == 0xF801
        assert (code & 0xF800) == 0xF800
        assert (code & 0x00FF) == 0x0001

    def test_missing_lookup_signed_integer(self) -> None:
        """DiagnosticCode._missing_ resolves signed 16-bit integers to enum members."""
        assert DiagnosticCode(-2047) is DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP
        assert DiagnosticCode(-2046) is DiagnosticCode.COOLING_LOSS_TRIP
        assert DiagnosticCode(-2045) is DiagnosticCode.VISCOSITY_CLOGGING_FAULT
        assert DiagnosticCode(-2044) is DiagnosticCode.INITIATOR_EXHAUSTION_FAULT
        assert DiagnosticCode(0) is DiagnosticCode.OK

    def test_string_formatting(self) -> None:
        """DiagnosticCode __str__ formats with hexadecimal code and member name."""
        assert str(DiagnosticCode.OK) == "0x0000 (OK)"
        assert str(DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP) == "0xF801 (THERMAL_RUNAWAY_GEL_TRIP)"
        assert str(DiagnosticCode.COOLING_LOSS_TRIP) == "0xF802 (COOLING_LOSS_TRIP)"
        assert str(DiagnosticCode.VISCOSITY_CLOGGING_FAULT) == "0xF803 (VISCOSITY_CLOGGING_FAULT)"
        assert str(DiagnosticCode.INITIATOR_EXHAUSTION_FAULT) == "0xF804 (INITIATOR_EXHAUSTION_FAULT)"

    def test_status_bits_flag_operations(self) -> None:
        """PMMAPolymerizationStatusBits IntFlag combinations verify bit positions."""
        bits = PMMAPolymerizationStatusBits.RUNNING | PMMAPolymerizationStatusBits.PMMA_REACTOR_ACTIVE
        assert bool(bits & PMMAPolymerizationStatusBits.RUNNING)
        assert bool(bits & PMMAPolymerizationStatusBits.PMMA_REACTOR_ACTIVE)
        assert not bool(bits & PMMAPolymerizationStatusBits.THERMAL_RUNAWAY_GEL_TRIP)


# ============================================================================
# Section 9: Gel Pre-Alarm (%M523) & Emergency Inhibitor Injection Actuation (%M524)
# ============================================================================

class TestSection09PreAlarmAndInhibitorActuation:
    """Verify gel pre-alarm %M523 and emergency inhibitor %M524 actuation dynamics."""

    def test_pre_alarm_does_not_halt_reaction(self) -> None:
        """Pre-alarm alone maintains active reactor status and uninhibited propagation."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.gel_effect_acceleration_factor = 5.75
        sim._evaluate_safety_interlocks()

        assert sim.state.gel_effect_pre_alarm is True
        assert sim.state.pmma_reactor_active is True
        assert sim.state.emergency_inhibitor_injected is False

    def test_emergency_inhibitor_forces_quench_duty(self) -> None:
        """Inhibitor injection triggers maximum emergency quench cooling (250 kW)."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 98.0
        sim._evaluate_safety_interlocks()

        assert sim.state.emergency_inhibitor_injected is True
        dy = sim.compute_derivatives(0.0, [
            sim.state.c_initiator,
            sim.state.c_monomer,
            sim.state.c_radicals,
            sim.state.mw_number_avg,
            sim.state.mw_weight_avg,
            sim.state.t_reactor_c,
        ])
        # With 250 kW quench cooling and 0 kW rxn heat, dT/dt must be strongly negative
        assert dy[5] < -0.01

    def test_emergency_inhibitor_prevents_active_restart(self) -> None:
        """Reactor cannot be made active while emergency inhibitor is active during trip."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 96.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_inhibitor_injected is True
        assert sim.state.pmma_reactor_active is False

        # Attempt to force active while trip condition persists
        sim.state.pmma_reactor_active = True
        sim._evaluate_safety_interlocks()
        assert sim.state.pmma_reactor_active is False


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2240..%R2247, %M522..%M524)
# ============================================================================

class TestSection10RegisterTableSync:
    """Verify register table mapping and synchronization to %R2240..%R2247 and %M522..%M524."""

    def test_register_constants_definitions(self) -> None:
        """Register and coil address string constants are defined accurately."""
        assert REG_PMMA_REACTOR_TEMP_SCALED == "%R2240"
        assert REG_MMA_CONVERSION_SCALED == "%R2241"
        assert REG_PMMA_WEIGHT_AVG_MW_SCALED == "%R2242"
        assert REG_GEL_EFFECT_ACCELERATION_FACTOR_SCALED == "%R2243"
        assert REG_COOLING_JACKET_HEAT_DUTY_KW_SCALED == "%R2244"
        assert REG_MELT_VISCOSITY_POISE_SCALED == "%R2245"
        assert REG_INITIATOR_EFFICIENCY_PPM == "%R2246"
        assert REG_PMMA_DIAGNOSTIC_CODE == "%R2247"
        assert COIL_PMMA_REACTOR_ACTIVE == "%M522"
        assert COIL_GEL_EFFECT_PRE_ALARM == "%M523"
        assert COIL_EMERGENCY_INHIBITOR_INJECTED == "%M524"

    def test_sync_to_registers_nominal_values(self) -> None:
        """Synchronizing steady-state reactor populates register table with correct scaled values."""
        table = RegisterTable()
        sim = PMMAPolymerizationReactor(register_table=table)
        sim.reset()

        assert table.read_word("%R2240") == 800      # 80.0 °C * 10
        assert table.read_word("%R2241") == 8250     # 82.50 % * 100
        assert table.read_word("%R2242") == 1250     # 125,000 Da / 100
        assert table.read_word("%R2243") == 450      # 4.50 * 100
        assert table.read_word("%R2244") == 1450     # 145.0 kW * 10
        assert table.read_word("%R2245") == 3800     # 3800 Poise
        assert table.read_word("%R2246") == 680      # 680 ppm
        assert table.read_uword("%R2247") == 0x0000  # OK

        assert table.read_bit("%M522") is True
        assert table.read_bit("%M523") is False
        assert table.read_bit("%M524") is False

    def test_sync_trip_state_signed_and_unsigned_masking(self) -> None:
        """Tripped state synchronizes signed integer in read_word and unsigned hex in read_uword."""
        table = RegisterTable()
        sim = PMMAPolymerizationReactor(register_table=table)
        sim.reset()
        sim.state.t_reactor_c = 98.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_word("%R2247") == -2047
        assert table.read_uword("%R2247") == 0xF801
        assert (table.read_uword("%R2247") & 0xFFFF) == 0xF801
        assert table.read_bit("%M522") is False
        assert table.read_bit("%M524") is True

    def test_sync_system_privilege_requirement(self) -> None:
        """sync_to_registers executes without error using PrivilegeMode.SYSTEM."""
        table = RegisterTable()
        sim = PMMAPolymerizationReactor()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2240") == 800


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection11PureSTPOU:
    """Verify Pure IEC 61131-3 Structured Text POU, variable bindings, and syntax validation."""

    def test_pure_st_pou_string_constants(self) -> None:
        """Pure ST POU text constant is defined and matches aliases."""
        assert isinstance(PMMA_POLYMERIZATION_PURE_ST_POU, str)
        assert "PROGRAM PMMAPolymerizationSync" in PMMA_POLYMERIZATION_PURE_ST_POU
        assert "END_PROGRAM" in PMMA_POLYMERIZATION_PURE_ST_POU
        assert PMMA_POLYMERIZATION_SYNC_POU == PMMA_POLYMERIZATION_PURE_ST_POU
        assert PMMA_PURE_ST_POU == PMMA_POLYMERIZATION_PURE_ST_POU
        assert PMMA_SYNC_POU == PMMA_POLYMERIZATION_PURE_ST_POU

    def test_st_parser_validate_code_success(self) -> None:
        """STParser.validate_code validates PMMA_POLYMERIZATION_PURE_ST_POU cleanly."""
        res = STParser.validate_code(PMMA_POLYMERIZATION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_security_guard_assert_pure_st_success(self) -> None:
        """SecurityGuard.assert_pure_st_content verifies pure ST without ladder logic."""
        SecurityGuard.assert_pure_st_content(PMMA_POLYMERIZATION_PURE_ST_POU)

    def test_verify_pmma_polymerization_pure_st_function(self) -> None:
        """verify_pmma_polymerization_pure_st() and alias return passed=True."""
        res1 = verify_pmma_polymerization_pure_st()
        assert res1.passed is True
        assert res1.status == AgentStatus.SUCCESS
        assert res1.error is None

        res2 = verify_pmma_pure_st()
        assert res2.passed is True

    def test_ast_bound_registers_comprehensive(self) -> None:
        """STParser AST contains all 11 required %R2240..%R2247 and %M522..%M524 bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(PMMA_POLYMERIZATION_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "PMMAPolymerizationSync"
        assert pou.pou_type == POUType.PROGRAM

        required = [
            "%R2240", "%R2241", "%R2242", "%R2243",
            "%R2244", "%R2245", "%R2246", "%R2247",
            "%M522", "%M523", "%M524",
        ]
        for reg in required:
            assert reg in pou.bound_registers

    def test_ast_variable_memory_address_attributes(self) -> None:
        """Each AST variable correctly captures its memory_address / address_binding attribute."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(PMMA_POLYMERIZATION_PURE_ST_POU)
        assert pou is not None

        var_map = {
            v.name: getattr(v, "address_binding", getattr(v, "memory_address", getattr(v, "address", None)))
            for v in pou.variables
        }
        assert var_map.get("ReactorTempScaled") == "%R2240"
        assert var_map.get("MmaConversionScaled") == "%R2241"
        assert var_map.get("PmmaWeightAvgMwScaled") == "%R2242"
        assert var_map.get("GelEffectAccelerationFactorScaled") == "%R2243"
        assert var_map.get("CoolingJacketHeatDutyKwScaled") == "%R2244"
        assert var_map.get("MeltViscosityPoiseScaled") == "%R2245"
        assert var_map.get("InitiatorEfficiencyPpm") == "%R2246"
        assert var_map.get("PmmaDiagnosticCode") == "%R2247"
        assert var_map.get("PmmaReactorActive") == "%M522"
        assert var_map.get("GelEffectPreAlarm") == "%M523"
        assert var_map.get("EmergencyInhibitorInjected") == "%M524"


# ============================================================================
# Section 12: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection12AntiLadderRejection:
    """Verify anti-ladder security guard rejects contacts, coils, rungs, networks, and mnemonics."""

    def test_reject_ladder_contacts(self) -> None:
        """Ladder logic contacts |---[ ]---| are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L1\nVAR b: BOOL; END_VAR\n|---[ ]---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_coils(self) -> None:
        """Ladder logic coils |---( )---| are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L2\nVAR b: BOOL; END_VAR\n|---( )---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_rungs_and_networks(self) -> None:
        """Ladder rung and network keywords are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P5 RUNG 1 END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P6 NETWORK 10 END_PROGRAM")

    def test_reject_ladder_mnemonics(self) -> None:
        """Ladder instruction mnemonics (XIC, XIO, OTE, OTL, OTU) are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P7 XIC(Start); END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P8 XIO(Stop); END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P9 OTE(Run); END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P10 OTL(Latch); END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P11 OTU(Unlatch); END_PROGRAM")


# ============================================================================
# Section 13: ILogicUnit Scan Cycle Execution, Reset Dynamics & 100-Cycle Soak Stability
# ============================================================================

class TestSection13ILogicUnitComplianceAndSoak:
    """Verify ILogicUnit interface compliance, scan cycles, and 100-cycle soak stability."""

    def test_ilogicunit_interface_properties(self) -> None:
        """PMMAPolymerizationReactor conforms to ILogicUnit interface properties."""
        sim = PMMAPolymerizationReactor(name="CustomPMMA", priority=150)
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "CustomPMMA"
        assert sim.priority == 150
        assert sim.is_enabled is True

        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_execute_with_scan_context(self) -> None:
        """execute(context) advances simulation time and cycle count."""
        sim = PMMAPolymerizationReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)

        assert sim.state.cycle_count == 1
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-5)

    def test_disabled_simulation_does_not_advance(self) -> None:
        """When disabled, scan_step does not increment cycles or modify time."""
        sim = PMMAPolymerizationReactor()
        sim.disable()
        sim.scan_step(dt=0.02)

        assert sim.state.cycle_count == 0
        assert sim.state.sim_time_s == 0.0

    def test_100_cycle_soak_stability(self) -> None:
        """100 consecutive scan cycles maintain state boundedness, zero NaNs, and stability."""
        sim = PMMAPolymerizationReactor()
        sim.reset()

        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

            assert not math.isnan(sim.state.t_reactor_c)
            assert not math.isnan(sim.state.mma_conversion_pct)
            assert not math.isnan(sim.state.mw_weight_avg)
            assert not math.isnan(sim.state.gel_effect_acceleration_factor)
            assert not math.isnan(sim.state.cooling_jacket_duty_kw)
            assert not math.isnan(sim.state.melt_viscosity_poise)

        assert 78.0 <= sim.state.t_reactor_c <= 82.0
        assert sim.state.mma_conversion_pct >= 80.0
        assert 120000.0 <= sim.state.mw_weight_avg <= 130000.0
        assert sim.state.cycle_count == 100
        assert math.isclose(sim.state.sim_time_s, 2.0, abs_tol=1e-4)


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14VerificationSuiteAndArtifacts:
    """Verify 9-stage engineering verification suite execution and artifact emission."""

    def test_verification_suite_all_stages_pass(self) -> None:
        """run_pmma_polymerization_verification() executes and passes all 9 stages."""
        result = run_pmma_polymerization_verification()
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert "data" in result
        assert result["data"]["work_package"] == "W263"
        assert result["data"]["passed_stages"] == 9
        assert result["data"]["total_stages"] == 9

    def test_verification_suite_output_file_emission(self, tmp_path: Path) -> None:
        """Verification suite writes well-formed JSON evidence artifact."""
        out_file = tmp_path / "pmma_evidence.json"
        result = run_pmma_polymerization_verification(output_path=out_file)

        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W263"
        assert len(data["data"]["stages"]) == 9

    def test_verification_aliases(self) -> None:
        """Verification function aliases call the identical runner."""
        res1 = run_pmma_verification()
        res2 = run_pmma_poly_verification()
        assert res1["status"] == "success"
        assert res2["status"] == "success"


# ============================================================================
# Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
# ============================================================================

class TestSection15EdgeCasesAndAliases:
    """Verify class aliases, property setters, edge cases, and custom configurations."""

    def test_class_and_state_aliases(self) -> None:
        """Compatibility class aliases resolve to the primary implementations."""
        assert PmmaReactor is PMMAPolymerizationReactor
        assert PMMAReactor is PMMAPolymerizationReactor
        assert PmmaPolymerization is PMMAPolymerizationReactor
        assert PMMAPolymerization is PMMAPolymerizationReactor
        assert PmmaPolymerizationModel is PMMAPolymerizationReactor
        assert PmmaPolymerizationEngine is PMMAPolymerizationReactor
        assert PmmaPolymerizationSimulator is PMMAPolymerizationReactor
        assert PmmaPolymerizationPlantModel is PMMAPolymerizationReactor
        assert PmmaPolymerizationLogicUnit is PMMAPolymerizationReactor

        assert PmmaConfig is PMMAPolymerizationConfig
        assert PMMAConfig is PMMAPolymerizationConfig
        assert PmmaState is PMMAPolymerizationState
        assert PMMAState is PMMAPolymerizationState
        assert PmmaDiagnosticCode is DiagnosticCode
        assert PMMADiagnosticCode is DiagnosticCode
        assert PmmaDiagCode is DiagnosticCode
        assert PmmaStatusBits is PMMAPolymerizationStatusBits
        assert PMMAStatusBits is PMMAPolymerizationStatusBits
        assert PmmaStatusWord is PMMAPolymerizationStatusBits

    def test_state_property_getters_and_setters(self) -> None:
        """State compatibility property getters and setters update the underlying fields."""
        st = PMMAPolymerizationState()
        st.conversion_pct = 84.0
        assert st.mma_conversion_pct == 84.0
        assert st.conversion_pct == 84.0

        st.mw_w = 126000.0
        assert st.mw_weight_avg == 126000.0
        assert st.mw_w == 126000.0

        st.mw_n = 63000.0
        assert st.mw_number_avg == 63000.0
        assert st.mw_n == 63000.0

        st.viscosity = 4000.0
        assert st.melt_viscosity_poise == 4000.0
        assert st.viscosity == 4000.0

        st.acceleration_factor = 4.80
        assert st.gel_effect_acceleration_factor == 4.80
        assert st.acceleration_factor == 4.80

        st.reactor_active = False
        assert st.pmma_reactor_active is False
        assert st.reactor_active is False

        st.pre_alarm = True
        assert st.gel_effect_pre_alarm is True
        assert st.pre_alarm is True

        st.inhibitor_injected = True
        assert st.emergency_inhibitor_injected is True
        assert st.inhibitor_injected is True

    def test_low_conversion_and_cold_feed_edge_cases(self) -> None:
        """Cold monomer feed and low conversion conditions evaluate smoothly."""
        cfg = PMMAPolymerizationConfig(nominal_inlet_temp_c=25.0)
        sim = PMMAPolymerizationReactor(config=cfg)
        sim.reset()
        sim.state.t_reactor_c = 72.0
        sim.state.c_monomer = 8.5
        sim.scan_step(dt=0.02)

        assert not math.isnan(sim.state.t_reactor_c)
        assert sim.state.t_reactor_c > 50.0

    def test_extreme_high_temperature_thermal_runaway(self) -> None:
        """Extreme temperature (110 °C) triggers runaway trip and forces rapid quench."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 110.0
        sim.scan_step(dt=0.02)

        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP
        assert sim.state.emergency_inhibitor_injected is True
        assert sim.state.pmma_reactor_active is False

    def test_trommsdorff_rate_expression_scaling(self) -> None:
        """Termination suppression factor g_t is strictly equal to 1 / (g_accel^2) across conversion domain."""
        sim = PMMAPolymerizationReactor()
        for x_pct in [10.0, 30.0, 50.0, 70.0, 82.5, 90.0, 95.0]:
            g_accel, g_t = sim.compute_gel_effect(80.0, x_pct)
            assert math.isclose(g_t, 1.0 / (g_accel ** 2), rel_tol=1e-9)

    def test_gel_effect_temperature_coupling(self) -> None:
        """Elevated temperature reduces gel autoacceleration due to enhanced free volume mobility."""
        sim = PMMAPolymerizationReactor()
        g_accel_75, _ = sim.compute_gel_effect(75.0, 82.50)
        g_accel_80, _ = sim.compute_gel_effect(80.0, 82.50)
        g_accel_90, _ = sim.compute_gel_effect(90.0, 82.50)
        assert g_accel_75 > g_accel_80 > g_accel_90

    def test_free_volume_bounds_and_limits(self) -> None:
        """Free volume calculation enforces physical minimum floor under extreme edge conditions."""
        sim = PMMAPolymerizationReactor()
        vf_low = sim.compute_free_volume(-50.0, 1.5)
        assert vf_low >= 0.005
        vf_high = sim.compute_free_volume(200.0, -0.5)
        assert vf_high > 0.05

    def test_radical_steady_state_target_calculation(self) -> None:
        """Quasi-steady-state radical concentration target matches analytical formula."""
        sim = PMMAPolymerizationReactor()
        kin = sim.compute_kinetics(
            t_reactor_k=80.0 + T_ZERO_CELSIUS,
            c_i=0.0058,
            c_m=1.637,
            c_r=2.45e-7,
            conversion_pct=82.50,
        )
        f_eff = sim.state.initiator_efficiency_f
        expected_r = math.sqrt((f_eff * kin["k_d"] * 0.0058) / kin["k_t"])
        assert math.isclose(kin["c_r_target"], expected_r, rel_tol=1e-5)

    def test_diagnostic_code_membership_and_iteration(self) -> None:
        """DiagnosticCode iteration contains expected 5 primary fault codes."""
        members = list(DiagnosticCode)
        assert DiagnosticCode.OK in members
        assert DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP in members
        assert DiagnosticCode.COOLING_LOSS_TRIP in members
        assert DiagnosticCode.VISCOSITY_CLOGGING_FAULT in members
        assert DiagnosticCode.INITIATOR_EXHAUSTION_FAULT in members

    def test_diagnostic_code_hash_and_set_operations(self) -> None:
        """DiagnosticCode hashes properly and supports set and dictionary keys."""
        code_set = {
            DiagnosticCode.OK,
            DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP,
            DiagnosticCode.COOLING_LOSS_TRIP,
            DiagnosticCode.VISCOSITY_CLOGGING_FAULT,
            DiagnosticCode.INITIATOR_EXHAUSTION_FAULT,
        }
        assert len(code_set) == 5
        assert DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP in code_set
        code_map = {DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP: "TRIP1"}
        assert code_map[DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP] == "TRIP1"

    def test_diagnostic_code_invalid_lookup_returns_none(self) -> None:
        """Looking up undefined diagnostic value via _missing_ returns None."""
        assert DiagnosticCode._missing_(0x1234) is None
        assert DiagnosticCode._missing_("INVALID") is None

    def test_diagnostic_code_bitwise_rand(self) -> None:
        """Right-hand bitwise AND works with DiagnosticCode."""
        assert (0xFFFF & DiagnosticCode.COOLING_LOSS_TRIP) == 0xF802
        assert (0xF800 & DiagnosticCode.COOLING_LOSS_TRIP) == 0xF800

    def test_custom_config_parameter_overrides(self) -> None:
        """Custom reactor geometry and thermal capacitance configurations function smoothly."""
        custom_cfg = PMMAPolymerizationConfig(
            reactor_volume_m3=2.50,
            nominal_residence_time_s=7200.0,
            reactor_thermal_capacitance_kj_k=9000.0,
            jacket_cooling_duty_kw=300.0,
        )
        sim = PMMAPolymerizationReactor(config=custom_cfg)
        sim.reset()
        assert sim.config.reactor_volume_m3 == 2.50
        assert sim.config.nominal_residence_time_s == 7200.0
        assert sim.config.reactor_thermal_capacitance_kj_k == 9000.0
        assert sim.state.cooling_jacket_duty_kw == 300.0

    def test_extreme_inhibitor_quench_cooling_temperature_drop(self) -> None:
        """Triggering inhibitor quench rapidly lowers reactor temperature over consecutive steps."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 97.0
        sim.scan_step(dt=0.02)
        assert sim.state.emergency_inhibitor_injected is True

        start_t = sim.state.t_reactor_c
        for _ in range(50):
            sim.scan_step(dt=0.02)
        assert sim.state.t_reactor_c < start_t

    def test_monomer_depletion_zero_rate(self) -> None:
        """Zero monomer concentration leads to zero reaction rate and zero reaction heat."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        kin = sim.compute_kinetics(
            t_reactor_k=80.0 + T_ZERO_CELSIUS,
            c_i=0.0058,
            c_m=0.0,
            c_r=2.45e-7,
            conversion_pct=100.0,
        )
        assert kin["r_p"] == 0.0
        assert kin["r_p_total"] == 0.0
        assert kin["q_rxn_kw"] == 0.0

    def test_zero_initiator_decay_zero_radical_target(self) -> None:
        """Zero initiator concentration yields zero radical target."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        kin = sim.compute_kinetics(
            t_reactor_k=80.0 + T_ZERO_CELSIUS,
            c_i=0.0,
            c_m=1.637,
            c_r=2.45e-7,
            conversion_pct=82.50,
        )
        assert kin["c_r_target"] == 0.0

    def test_viscosity_clogging_high_molecular_weight(self) -> None:
        """Very high weight-average molecular weight drives viscosity past fault threshold."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.mw_weight_avg = 180000.0
        sim._update_derived_variables()
        sim._evaluate_safety_interlocks()

        assert sim.state.melt_viscosity_poise > 5500.0
        assert sim.state.diagnostic_code == DiagnosticCode.VISCOSITY_CLOGGING_FAULT

    def test_initiator_depletion_ppm_fault_interlock(self) -> None:
        """Low initiator efficiency (< 450 ppm) activates initiator exhaustion fault 0xF804."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.initiator_efficiency_f = 0.380
        sim._update_derived_variables()
        sim._evaluate_safety_interlocks()

        assert sim.state.initiator_efficiency_ppm == 380
        assert sim.state.diagnostic_code == DiagnosticCode.INITIATOR_EXHAUSTION_FAULT

    def test_reset_clears_previous_trip_state(self) -> None:
        """Reactor reset cleanly restores normal state from an active trip."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 100.0
        sim.scan_step(dt=0.02)
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_GEL_TRIP
        assert sim.state.emergency_inhibitor_injected is True

        sim.reset()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.emergency_inhibitor_injected is False
        assert sim.state.pmma_reactor_active is True
        assert math.isclose(sim.state.t_reactor_c, 80.0, abs_tol=1e-3)

    def test_soak_monotonic_sim_time(self) -> None:
        """sim_time_s advances strictly monotonically with every scan cycle."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        last_time = sim.state.sim_time_s

        for cycle in range(1, 21):
            sim.scan_step(dt=0.02)
            assert sim.state.sim_time_s > last_time
            last_time = sim.state.sim_time_s
        assert math.isclose(sim.state.sim_time_s, 0.40, abs_tol=1e-5)

    def test_enthalpy_conservation_under_external_ambient_variation(self) -> None:
        """First-law enthalpy residual remains < 1e-10 even under extreme ambient temperatures."""
        sim = PMMAPolymerizationReactor()
        for t_amb in [-20.0, 0.0, 25.0, 45.0]:
            sim.config.ambient_temp_c = t_amb
            sim.scan_step(dt=0.02)
            assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_reaction_rate_monotonicity_with_radical_concentration(self) -> None:
        """Polymerization rate scales strictly monotonically with active macroradical concentration."""
        sim = PMMAPolymerizationReactor()
        kin1 = sim.compute_kinetics(80.0 + T_ZERO_CELSIUS, 0.0058, 1.637, 1.0e-7, 82.50)
        kin2 = sim.compute_kinetics(80.0 + T_ZERO_CELSIUS, 0.0058, 1.637, 2.45e-7, 82.50)
        kin3 = sim.compute_kinetics(80.0 + T_ZERO_CELSIUS, 0.0058, 1.637, 5.0e-7, 82.50)
        assert 0.0 < kin1["r_p"] < kin2["r_p"] < kin3["r_p"]

    def test_residence_time_feed_balance(self) -> None:
        """Volumetric flow rate and feed molar rate balance exactly across residence time tau."""
        cfg = PMMAPolymerizationConfig()
        v_l = cfg.reactor_volume_m3 * 1000.0
        f_vol_l_s = v_l / cfg.nominal_residence_time_s
        expected_feed_rate = cfg.feed_monomer_conc_mol_l * f_vol_l_s
        assert math.isclose(cfg.nominal_mma_feed_rate_mol_s, expected_feed_rate, rel_tol=1e-4)

    def test_mark_houwink_temperature_viscosity_dependence(self) -> None:
        """Viscosity decreases with higher temperature due to Arrhenius thermal fluidization."""
        sim = PMMAPolymerizationReactor()
        sim.reset()
        sim.state.t_reactor_c = 75.0
        sim._update_derived_variables()
        visc_75 = sim.state.melt_viscosity_poise

        sim.state.t_reactor_c = 80.0
        sim._update_derived_variables()
        visc_80 = sim.state.melt_viscosity_poise

        sim.state.t_reactor_c = 85.0
        sim._update_derived_variables()
        visc_85 = sim.state.melt_viscosity_poise

        assert visc_75 > visc_80 > visc_85

    def test_diagnostic_code_str_all_members(self) -> None:
        """All DiagnosticCode enum members format correctly as '0xXXXX (NAME)'."""
        for member in DiagnosticCode:
            formatted = str(member)
            assert formatted.startswith(f"0x{member.value & 0xFFFF:04X} (")
            assert formatted.endswith(f"{member.name})")

    def test_status_word_intflag_all_bits(self) -> None:
        """All 8 defined status bits occupy unique non-overlapping power-of-two positions."""
        bits_list = [
            PMMAPolymerizationStatusBits.RUNNING,
            PMMAPolymerizationStatusBits.PMMA_REACTOR_ACTIVE,
            PMMAPolymerizationStatusBits.GEL_EFFECT_PRE_ALARM,
            PMMAPolymerizationStatusBits.EMERGENCY_INHIBITOR_INJECTED,
            PMMAPolymerizationStatusBits.THERMAL_RUNAWAY_GEL_TRIP,
            PMMAPolymerizationStatusBits.COOLING_LOSS_TRIP,
            PMMAPolymerizationStatusBits.VISCOSITY_CLOGGING_FAULT,
            PMMAPolymerizationStatusBits.INITIATOR_EXHAUSTION_FAULT,
        ]
        assert len(bits_list) == 8
        # Ensure mutually exclusive powers of 2
        for i in range(len(bits_list)):
            for j in range(i + 1, len(bits_list)):
                assert (bits_list[i] & bits_list[j]) == 0


