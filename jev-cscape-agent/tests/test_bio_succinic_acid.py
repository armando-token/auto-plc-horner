"""Industrial Bio-Succinic Acid Bacterial Fermentation Test Suite.

Work Package: W284 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Status Contract: Strict 4-State JSON output & evidence emission.

Structured into 17 comprehensive engineering verification sections:
1. Section 1: Universal Physical & Biochemical Constants, Molecular Weights & Stoichiometric Carbon Fractions
2. Section 2: Configuration Defaults and Biochemical Parameter Validation
3. Section 3: Model Initialization, Nominal Baseline and State Vector
4. Section 4: Biochemical Reaction Kinetics & Andrews/Haldane Uptake Dynamics
5. Section 5: Glucose & Dissolved CO2 Uptake Stoichiometry & Carboxylation Kinetics
6. Section 6: Product Inhibition & Neutralizing Base Titration Demand
7. Section 7: Coupled 6-State ODE System & RK4 Numerical Integrator Stability
8. Section 8: Mathematical Conservation Laws & Residuals (< 1e-10)
9. Section 9: Process Safety Interlocks & Strict Priority Hierarchy (0xF701 > 0xF702 > 0xF703 > 0xF704 > 0x0000)
10. Section 10: Diagnostic & Trip Code Properties (Signed/Unsigned 16-Bit, Masking, Hash, Enums)
11. Section 11: Fault Injections, Clear Faults & Actuator Coil Responses
12. Section 12: Horner OCS Register Space Synchronization (%R2450..%R2457, %M571..%M573)
13. Section 13: Pure IEC 61131-3 Structured Text Generation & AST Memory Address Bindings
14. Section 14: Anti-Ladder Security Guard Validation (Contacts, Coils, Rungs, Mnemonics)
15. Section 15: ILogicUnit Compliance & 100-Cycle Soak Stability (Zero Drift, No NaN)
16. Section 16: Deterministic 10-Stage Verification Suite & Artifact Emission
17. Section 17: Class and Compatibility Aliases & Sensitivity Edge Cases
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.bio_succinic_acid import (
    ACIDIFICATION_BYPRODUCT_TRIP_G_L,
    ACIDIFICATION_RUNAWAY_TRIP_PH,
    BIOMASS_NOMINAL_G_L,
    BIOSUCCINIC_ACID_PURE_ST_POU,
    BIOSUCCINIC_ACID_SYNC_POU,
    BIO_SUCCINIC_ACID_PURE_ST_POU,
    BIO_SUCCINIC_ACID_SYNC_POU,
    BYPRODUCT_ACID_NOMINAL_G_L,
    BYPRODUCT_LACTIC_NOMINAL_G_L,
    CO2_STARVATION_TRIP_MM,
    COIL_BIOSUCCINIC_ACIDIFICATION_RUNAWAY_ALARM,
    COIL_BIOSUCCINIC_ACIDIFICATION_TRIP_ALARM,
    COIL_BIOSUCCINIC_ANAEROBIC_CO2_SPARGING,
    COIL_BIOSUCCINIC_BASE_NEUTRALIZER_PUMP_ACTIVE,
    COIL_BIOSUCCINIC_BASE_PUMP_ACTIVE,
    COIL_BIOSUCCINIC_CARBOXYLATION_VALID,
    COIL_BIOSUCCINIC_CO2_SPARGING_ACTIVE,
    COIL_BIOSUCCINIC_PH_REGULATOR,
    COIL_BIOSUCCINIC_SUBSTRATE_INVERSION_ALARM,
    CONTAMINATION_LACTIC_TRIP_G_L,
    DISSOLVED_CO2_NOMINAL_MM,
    F_C_ACETIC,
    F_C_BIOMASS,
    F_C_BYPRODUCT_ACID,
    F_C_CO2,
    F_C_FORMIC,
    F_C_GLUCOSE,
    F_C_LACTIC,
    F_C_SUCCINIC,
    GLUCOSE_NOMINAL_G_L,
    G_ACCEL,
    METABOLIC_STATE_NOMINAL_CODE,
    MW_ACETIC_ACID,
    MW_BICARBONATE,
    MW_BIOMASS_CMOL,
    MW_BYPRODUCT1,
    MW_BYPRODUCT2,
    MW_BYPRODUCT_ACID,
    MW_C,
    MW_CA,
    MW_CO2,
    MW_FORMIC_ACID,
    MW_GLUCOSE,
    MW_H,
    MW_H2O,
    MW_LACTATE,
    MW_LACTIC_ACID,
    MW_MG,
    MW_MG_OH_2,
    MW_N,
    MW_NA,
    MW_NAOH,
    MW_O,
    MW_P,
    MW_PRIMARY_SUBSTRATE,
    MW_S,
    MW_SUCCINATE,
    MW_SUCCINIC_ACID,
    REG_BIOSUCCINIC_BIOMASS_CONC_SCALED,
    REG_BIOSUCCINIC_BIOMASS_SCALED,
    REG_BIOSUCCINIC_BYPRODUCT1_SCALED,
    REG_BIOSUCCINIC_BYPRODUCT2_SCALED,
    REG_BIOSUCCINIC_BYPRODUCT_ACID_SCALED,
    REG_BIOSUCCINIC_BYPRODUCT_LACTIC_SCALED,
    REG_BIOSUCCINIC_CO2_SCALED,
    REG_BIOSUCCINIC_C_CO2_SCALED,
    REG_BIOSUCCINIC_DISSOLVED_CO2_SCALED,
    REG_BIOSUCCINIC_FERMENTER_TEMP_SCALED,
    REG_BIOSUCCINIC_GLUCOSE_SCALED,
    REG_BIOSUCCINIC_METABOLIC_YIELD_SCALED,
    REG_BIOSUCCINIC_P_BY1_SCALED,
    REG_BIOSUCCINIC_P_BY2_SCALED,
    REG_BIOSUCCINIC_P_SUCC_SCALED,
    REG_BIOSUCCINIC_STATE_CODE_SCALED,
    REG_BIOSUCCINIC_SUBSTRATE_GLUCOSE_SCALED,
    REG_BIOSUCCINIC_SUCCINIC_ACID_SCALED,
    REG_BIOSUCCINIC_SUCCINIC_SCALED,
    REG_BIOSUCCINIC_S_SCALED,
    REG_BIOSUCCINIC_TEMPERATURE_SCALED,
    REG_BIOSUCCINIC_TEMP_SCALED,
    REG_BIOSUCCINIC_X_SCALED,
    REG_BIOSUCCINIC_YIELD_STATE_SCALED,
    R_GAS_CONST,
    ST_PROGRAM_BIO_SUCCINIC_ACID_SYNC,
    SUCCINATE_YIELD_NOMINAL_PCT,
    SUCCINIC_ACID_NOMINAL_G_L,
    TEMP_EXCURSION_TRIP_C,
    TEMP_NOMINAL_C,
    T_FERMENTER_NOMINAL_C,
    T_ZERO_CELSIUS,
    BioSuccinicAcidConfig,
    BioSuccinicAcidDiagnosticCode,
    BioSuccinicAcidEngine,
    BioSuccinicAcidLogicUnit,
    BioSuccinicAcidModel,
    BioSuccinicAcidParameters,
    BioSuccinicAcidPlantModel,
    BioSuccinicAcidReactor,
    BioSuccinicAcidSimulator,
    BioSuccinicAcidState,
    BioSuccinicAcidStatusBits,
    BioSuccinicAcidTripCode,
    BioSuccinicConfig,
    BioSuccinicDiagnosticCode,
    BioSuccinicEngine,
    BioSuccinicFermentationStatusBits,
    BioSuccinicLogicUnit,
    BioSuccinicMetabolicState,
    BioSuccinicModel,
    BioSuccinicParameters,
    BioSuccinicPlantModel,
    BioSuccinicReactor,
    BioSuccinicSimulator,
    BioSuccinicState,
    BioSuccinicStatusBits,
    BioSuccinicTripCode,
    PureSTValidationResult,
    run_bio_succinic_acid_verification,
    run_bio_succinic_verification,
    validate_pure_st,
    verify_bio_succinic_acid_pure_st,
    verify_bio_succinic_pure_st,
)


# ============================================================================
# Section 1: Universal Physical & Biochemical Constants, Molecular Weights & Carbon Fractions
# ============================================================================

class TestSection01PhysicalAndBiochemicalConstants:
    """Verify universal physical constants, IUPAC atomic weights, and carbon mass fractions."""

    def test_universal_physical_constants(self) -> None:
        """Universal gas constant, standard gravity, and zero Celsius reference."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-8)
        assert math.isclose(T_FERMENTER_NOMINAL_C, 37.0, rel_tol=1e-8)

    def test_iupac_elemental_atomic_weights(self) -> None:
        """Standard atomic weights for C, H, O, N, Na, Mg, Ca, P, S [g/mol]."""
        assert math.isclose(MW_C, 12.011, rel_tol=1e-5)
        assert math.isclose(MW_H, 1.008, rel_tol=1e-5)
        assert math.isclose(MW_O, 15.999, rel_tol=1e-5)
        assert math.isclose(MW_N, 14.007, rel_tol=1e-5)
        assert math.isclose(MW_NA, 22.990, rel_tol=1e-5)
        assert math.isclose(MW_MG, 24.305, rel_tol=1e-5)
        assert math.isclose(MW_CA, 40.078, rel_tol=1e-5)
        assert math.isclose(MW_P, 30.974, rel_tol=1e-5)
        assert math.isclose(MW_S, 32.065, rel_tol=1e-5)

    def test_molecular_weights_species(self) -> None:
        """Exact molecular weights for glucose, succinate, byproducts, and neutralizing bases."""
        expected_glucose = 6.0 * MW_C + 12.0 * MW_H + 6.0 * MW_O
        assert math.isclose(MW_GLUCOSE, expected_glucose, rel_tol=1e-6)
        assert math.isclose(MW_PRIMARY_SUBSTRATE, MW_GLUCOSE)

        expected_co2 = 1.0 * MW_C + 2.0 * MW_O
        assert math.isclose(MW_CO2, expected_co2, rel_tol=1e-6)
        expected_bicarbonate = 1.0 * MW_H + 1.0 * MW_C + 3.0 * MW_O
        assert math.isclose(MW_BICARBONATE, expected_bicarbonate, rel_tol=1e-6)
        assert math.isclose(MW_H2O, 2.0 * MW_H + 1.0 * MW_O, rel_tol=1e-6)

        expected_succ = 4.0 * MW_C + 6.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_SUCCINIC_ACID, expected_succ, rel_tol=1e-6)
        assert math.isclose(MW_SUCCINATE, MW_SUCCINIC_ACID)

        expected_acetic = 2.0 * MW_C + 4.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_ACETIC_ACID, expected_acetic, rel_tol=1e-6)
        expected_formic = 1.0 * MW_C + 2.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_FORMIC_ACID, expected_formic, rel_tol=1e-6)
        assert math.isclose(MW_BYPRODUCT_ACID, MW_ACETIC_ACID)
        assert math.isclose(MW_BYPRODUCT1, MW_ACETIC_ACID)

        expected_lactic = 3.0 * MW_C + 6.0 * MW_H + 3.0 * MW_O
        assert math.isclose(MW_LACTIC_ACID, expected_lactic, rel_tol=1e-6)
        assert math.isclose(MW_LACTATE, MW_LACTIC_ACID)
        assert math.isclose(MW_BYPRODUCT2, MW_LACTIC_ACID)

        expected_biomass = 1.0 * MW_C + 1.8 * MW_H + 0.5 * MW_O + 0.2 * MW_N
        assert math.isclose(MW_BIOMASS_CMOL, expected_biomass, rel_tol=1e-6)

        assert math.isclose(MW_NAOH, MW_NA + MW_O + MW_H, rel_tol=1e-6)
        assert math.isclose(MW_MG_OH_2, MW_MG + 2.0 * (MW_O + MW_H), rel_tol=1e-6)

    def test_stoichiometric_carbon_mass_fractions(self) -> None:
        """Elemental carbon mass fractions [g C / g molecule]."""
        assert math.isclose(F_C_GLUCOSE, (6.0 * MW_C) / MW_GLUCOSE, rel_tol=1e-6)
        assert math.isclose(F_C_CO2, MW_C / MW_CO2, rel_tol=1e-6)
        assert math.isclose(F_C_SUCCINIC, (4.0 * MW_C) / MW_SUCCINIC_ACID, rel_tol=1e-6)
        assert math.isclose(F_C_ACETIC, (2.0 * MW_C) / MW_ACETIC_ACID, rel_tol=1e-6)
        assert math.isclose(F_C_FORMIC, MW_C / MW_FORMIC_ACID, rel_tol=1e-6)
        assert math.isclose(F_C_BYPRODUCT_ACID, F_C_ACETIC)
        assert math.isclose(F_C_LACTIC, (3.0 * MW_C) / MW_LACTIC_ACID, rel_tol=1e-6)
        assert math.isclose(F_C_BIOMASS, MW_C / MW_BIOMASS_CMOL, rel_tol=1e-6)


# ============================================================================
# Section 2: Configuration Defaults and Biochemical Parameter Validation
# ============================================================================

class TestSection02ConfigDefaultsAndParameterValidation:
    """Verify default parameters, kinetic limits, and operating thresholds."""

    def test_default_geometric_and_physical_parameters(self) -> None:
        """Vessel volume, density, temperature, and neutral operating pH."""
        cfg = BioSuccinicConfig()
        assert cfg.nominal_volume_l == 500.0
        assert cfg.maximum_volume_l == 650.0
        assert cfg.broth_density_kg_l == 1.040
        assert cfg.temperature_c == 37.0
        assert cfg.ph_nominal == 6.8
        assert cfg.nominal_feed_rate_l_h == 5.0
        assert cfg.feed_glucose_conc_g_l == 400.0
        assert cfg.fed_batch_mode is True

    def test_default_kinetic_parameters(self) -> None:
        """Andrews/Haldane growth kinetics and inhibition constants."""
        cfg = BioSuccinicConfig()
        assert cfg.mu_max_growth_h1 == 0.350
        assert cfg.k_s_glucose_g_l == 2.0
        assert cfg.k_i_glucose_g_l == 80.0
        assert cfg.k_co2_affinity_mm == 10.0
        assert cfg.p_max_succinic_g_l == 90.0
        assert cfg.p_max_byproduct_g_l == 40.0

    def test_luedeking_piret_synthesis_parameters(self) -> None:
        """Succinate, byproduct 1, and lactic acid synthesis coefficients."""
        cfg = BioSuccinicConfig()
        assert cfg.alpha_succ_coef == 1.25
        assert cfg.beta_succ_coef_h1 == 0.080
        assert cfg.k_co2_succ_mm == 5.0
        assert cfg.alpha_by1_coef == 0.28
        assert cfg.beta_by1_coef_h1 == 0.025
        assert cfg.alpha_by2_coef == 0.050
        assert cfg.beta_by2_coef_h1 == 0.005

    def test_stoichiometric_yields_and_maintenance(self) -> None:
        """Biomass and product yields on glucose and maintenance requirement."""
        cfg = BioSuccinicConfig()
        assert cfg.yield_xs_g_g == 0.35
        assert cfg.yield_ps_succ_g_g == 0.85
        assert cfg.yield_ps_by1_g_g == 0.40
        assert cfg.yield_ps_by2_g_g == 0.90
        assert cfg.maintenance_glucose_g_g_h == 0.015

    def test_mass_transfer_and_safety_limits(self) -> None:
        """Kla, base concentration, and safety interlock trip limits."""
        cfg = BioSuccinicConfig()
        assert cfg.kla_co2_h1 == 60.0
        assert cfg.co2_sat_conc_mm == 120.0
        assert cfg.nominal_co2_sparge_l_min == 25.0
        assert cfg.base_molarity_mol_l == 5.0
        assert cfg.co2_starvation_trip_mm == 15.0
        assert cfg.ph_trip_min == 6.0
        assert cfg.acidification_byproduct_trip_g_l == 25.0
        assert cfg.temp_excursion_trip_c == 40.0
        assert cfg.contamination_lactic_trip_g_l == 10.0
        assert cfg.harvest_succinic_target_g_l == 75.0


# ============================================================================
# Section 3: Model Initialization, Nominal Baseline and State Vector
# ============================================================================

class TestSection03InitializationAndStateVector:
    """Verify nominal baseline state vector initialization, reset, and properties."""

    def test_nominal_operating_baseline_constants(self) -> None:
        """Nominal operating baseline constants match W284 specification."""
        assert TEMP_NOMINAL_C == 37.0
        assert BIOMASS_NOMINAL_G_L == 15.0
        assert GLUCOSE_NOMINAL_G_L == 45.0
        assert DISSOLVED_CO2_NOMINAL_MM == 80.0
        assert SUCCINIC_ACID_NOMINAL_G_L == 55.0
        assert BYPRODUCT_ACID_NOMINAL_G_L == 12.0
        assert BYPRODUCT_LACTIC_NOMINAL_G_L == 2.5
        assert SUCCINATE_YIELD_NOMINAL_PCT == 20.0
        assert METABOLIC_STATE_NOMINAL_CODE == 0x01

    def test_fresh_instance_initialization(self) -> None:
        """BioSuccinicAcidReactor initializes to nominal baseline state."""
        reactor = BioSuccinicAcidReactor()
        state = reactor.state
        assert state.biomass_conc_g_l == 15.0
        assert state.substrate_glucose_g_l == 45.0
        assert state.dissolved_co2_mm == 80.0
        assert state.succinic_acid_g_l == 55.0
        assert state.byproduct_acid_g_l == 12.0
        assert state.byproduct_lactic_g_l == 2.5
        assert state.temperature_c == 37.0
        assert state.ph_level == 6.8
        assert state.broth_volume_l == 500.0
        assert state.trip_code == BioSuccinicTripCode.NORMAL
        assert state.co2_sparging_active is True
        assert state.base_pump_active is True
        assert state.acidification_trip_alarm is False
        assert state.batch_harvest_complete is False

    def test_shorthand_properties_and_setters(self) -> None:
        """Shorthand state properties (x, s, c_co2, p_succ, p_by1, p_by2) get and set."""
        state = BioSuccinicState()
        assert state.x == state.biomass_conc_g_l
        assert state.s == state.substrate_glucose_g_l
        assert state.c_co2 == state.dissolved_co2_mm
        assert state.p_succ == state.succinic_acid_g_l
        assert state.p_by1 == state.byproduct_acid_g_l
        assert state.p_by2 == state.byproduct_lactic_g_l

        state.x = 22.0
        assert state.biomass_conc_g_l == 22.0
        state.s = 30.0
        assert state.substrate_glucose_g_l == 30.0
        state.c_co2 = 65.0
        assert state.dissolved_co2_mm == 65.0
        state.p_succ = 60.0
        assert state.succinic_acid_g_l == 60.0
        state.p_by1 = 15.0
        assert state.byproduct_acid_g_l == 15.0
        state.p_by2 = 4.0
        assert state.byproduct_lactic_g_l == 4.0

    def test_reactor_reset_restores_nominal(self) -> None:
        """Reset clears perturbations and returns to nominal operating point."""
        reactor = BioSuccinicAcidReactor()
        reactor.state.temperature_c = 43.0
        reactor.state.biomass_conc_g_l = 5.0
        reactor.state.trip_code = BioSuccinicTripCode.THERMAL_EXCURSION
        reactor.state.co2_sparging_active = False

        reactor.reset()
        assert reactor.state.temperature_c == 37.0
        assert reactor.state.biomass_conc_g_l == 15.0
        assert reactor.state.trip_code == BioSuccinicTripCode.NORMAL
        assert reactor.state.co2_sparging_active is True
        assert reactor.state.base_pump_active is True


# ============================================================================
# Section 4: Biochemical Reaction Kinetics & Andrews/Haldane Uptake Dynamics
# ============================================================================

class TestSection04BiochemicalReactionKinetics:
    """Verify Andrews/Haldane substrate kinetics, environmental modulations, and reaction rates."""

    def test_compute_kinetics_nominal_baseline(self) -> None:
        """Nominal state yields strictly positive specific growth and production rates."""
        reactor = BioSuccinicAcidReactor()
        kin = reactor.compute_kinetics(
            x=15.0, s=45.0, c_co2=80.0, p_succ=55.0, p_by1=12.0, p_by2=2.5, temp=37.0, ph=6.8
        )
        assert kin["mu"] > 0.0
        assert kin["r_succ"] > 0.0
        assert kin["r_by1"] > 0.0
        assert kin["r_by2"] > 0.0
        assert kin["q_s"] > 0.0
        assert kin["ctr"] > 0.0
        assert kin["q_co2_succ"] > 0.0
        assert kin["r_co2_gen"] > 0.0
        assert kin["r_h_total"] > 0.0

    def test_andrews_haldane_substrate_inhibition_curve(self) -> None:
        """Haldane kinetics shows optimum glucose concentration and inhibition at elevated glucose."""
        reactor = BioSuccinicAcidReactor()
        # Evaluate growth at low (2 g/L), optimal (~15-20 g/L), and excessive substrate (200 g/L)
        kin_low = reactor.compute_kinetics(15.0, 2.0, 80.0, 10.0, 2.0, 0.5)
        kin_opt = reactor.compute_kinetics(15.0, 15.0, 80.0, 10.0, 2.0, 0.5)
        kin_high = reactor.compute_kinetics(15.0, 200.0, 80.0, 10.0, 2.0, 0.5)

        assert kin_opt["mu"] > kin_low["mu"]
        assert kin_opt["mu"] > kin_high["mu"]  # Substrate inhibition verified

    def test_zero_substrate_halts_growth(self) -> None:
        """Zero glucose concentration halts cell growth."""
        reactor = BioSuccinicAcidReactor()
        kin_zero = reactor.compute_kinetics(15.0, 0.0, 80.0, 10.0, 2.0, 0.5)
        assert kin_zero["mu"] == 0.0

    def test_temperature_environmental_factor(self) -> None:
        """Bell-shaped temperature response peaks at nominal 37.0 °C."""
        reactor = BioSuccinicAcidReactor()
        kin_nom = reactor.compute_kinetics(15.0, 45.0, 80.0, 10.0, 2.0, 0.5, temp=37.0)
        kin_cold = reactor.compute_kinetics(15.0, 45.0, 80.0, 10.0, 2.0, 0.5, temp=30.0)
        kin_hot = reactor.compute_kinetics(15.0, 45.0, 80.0, 10.0, 2.0, 0.5, temp=42.0)

        assert kin_nom["mu"] > kin_cold["mu"]
        assert kin_nom["mu"] > kin_hot["mu"]

    def test_ph_environmental_factor(self) -> None:
        """Bell-shaped pH factor peaks around nominal 6.8."""
        reactor = BioSuccinicAcidReactor()
        kin_opt_ph = reactor.compute_kinetics(15.0, 45.0, 80.0, 10.0, 2.0, 0.5, ph=6.8)
        kin_acid_ph = reactor.compute_kinetics(15.0, 45.0, 80.0, 10.0, 2.0, 0.5, ph=5.8)
        kin_basic_ph = reactor.compute_kinetics(15.0, 45.0, 80.0, 10.0, 2.0, 0.5, ph=7.8)

        assert kin_opt_ph["mu"] > kin_acid_ph["mu"]
        assert kin_opt_ph["mu"] > kin_basic_ph["mu"]


# ============================================================================
# Section 5: Glucose & Dissolved CO2 Uptake Stoichiometry & Carboxylation Kinetics
# ============================================================================

class TestSection05UptakeStoichiometryAndCO2Fixation:
    """Verify stoichiometric glucose uptake, CO2 fixation, and lactate shunting."""

    def test_co2_fixation_stoichiometry(self) -> None:
        """1 mole of CO2 is fixed per mole of succinic acid formed."""
        reactor = BioSuccinicAcidReactor()
        kin = reactor.compute_kinetics(15.0, 45.0, 80.0, 55.0, 12.0, 2.5)
        expected_q_co2 = (kin["r_succ"] / MW_SUCCINIC_ACID) * 1000.0
        assert math.isclose(kin["q_co2_succ"], expected_q_co2, rel_tol=1e-8)

    def test_co2_limitation_and_lactate_shunting(self) -> None:
        """Under dissolved CO2 starvation, succinate synthesis decreases and lactate shunts upwards."""
        reactor = BioSuccinicAcidReactor()
        kin_high_co2 = reactor.compute_kinetics(15.0, 45.0, 80.0, 20.0, 5.0, 1.0)
        kin_low_co2 = reactor.compute_kinetics(15.0, 45.0, 5.0, 20.0, 5.0, 1.0)

        assert kin_high_co2["r_succ"] > kin_low_co2["r_succ"]
        assert kin_low_co2["r_by2"] > kin_high_co2["r_by2"]  # Lactate shunt verified
        assert kin_high_co2["q_co2_succ"] > kin_low_co2["q_co2_succ"]

    def test_ctr_gas_liquid_mass_transfer(self) -> None:
        """Gas-liquid CO2 transfer rate follows driving force CTR = Kla * (C_sat - C_CO2)."""
        reactor = BioSuccinicAcidReactor()
        reactor.state.co2_sparging_active = True
        kin_sparged = reactor.compute_kinetics(15.0, 45.0, 80.0, 20.0, 5.0, 1.0)
        expected_ctr = reactor.config.kla_co2_h1 * (reactor.config.co2_sat_conc_mm - 80.0)
        assert math.isclose(kin_sparged["ctr"], expected_ctr, rel_tol=1e-6)

        # When sparging disabled, CTR falls to zero
        reactor.state.co2_sparging_active = False
        kin_unsparged = reactor.compute_kinetics(15.0, 45.0, 80.0, 20.0, 5.0, 1.0)
        assert kin_unsparged["ctr"] == 0.0

    def test_glucose_uptake_composition(self) -> None:
        """Substrate uptake rate q_s accounts for biomass growth, succinate, byproducts, and maintenance."""
        reactor = BioSuccinicAcidReactor()
        cfg = reactor.config
        x = 15.0
        kin = reactor.compute_kinetics(x, 45.0, 80.0, 30.0, 5.0, 1.0)
        expected_q_s = (
            (kin["mu"] / cfg.yield_xs_g_g)
            + (kin["r_succ"] / (x * cfg.yield_ps_succ_g_g))
            + (kin["r_by1"] / (x * cfg.yield_ps_by1_g_g))
            + (kin["r_by2"] / (x * cfg.yield_ps_by2_g_g))
            + cfg.maintenance_glucose_g_g_h
        ) * x
        assert math.isclose(kin["q_s"], expected_q_s, rel_tol=1e-6)


# ============================================================================
# Section 6: Product Inhibition & Neutralizing Base Titration Demand
# ============================================================================

class TestSection06ProductInhibitionAndBaseNeutralization:
    """Verify organic acid product inhibition and neutralizing base demand."""

    def test_succinic_acid_product_inhibition(self) -> None:
        """Elevated succinic acid inhibits cell growth and synthesis rate."""
        reactor = BioSuccinicAcidReactor()
        kin_low_p = reactor.compute_kinetics(15.0, 45.0, 80.0, 10.0, 5.0, 1.0)
        kin_high_p = reactor.compute_kinetics(15.0, 45.0, 80.0, 80.0, 5.0, 1.0)
        kin_sat_p = reactor.compute_kinetics(15.0, 45.0, 80.0, 95.0, 5.0, 1.0)

        assert kin_low_p["mu"] > kin_high_p["mu"]
        assert kin_high_p["mu"] > kin_sat_p["mu"]
        assert kin_sat_p["mu"] == 0.0

    def test_byproduct_acid_product_inhibition(self) -> None:
        """Elevated acetic/formic byproduct inhibits growth."""
        reactor = BioSuccinicAcidReactor()
        kin_low_by1 = reactor.compute_kinetics(15.0, 45.0, 80.0, 20.0, 5.0, 1.0)
        kin_high_by1 = reactor.compute_kinetics(15.0, 45.0, 80.0, 20.0, 35.0, 1.0)
        kin_sat_by1 = reactor.compute_kinetics(15.0, 45.0, 80.0, 20.0, 45.0, 1.0)

        assert kin_low_by1["mu"] > kin_high_by1["mu"]
        assert kin_sat_by1["mu"] == 0.0

    def test_diprotic_and_monoprotic_proton_generation(self) -> None:
        """Succinic acid yields 2 H+/mol; acetic and lactic acids yield 1 H+/mol."""
        reactor = BioSuccinicAcidReactor()
        kin = reactor.compute_kinetics(15.0, 45.0, 80.0, 55.0, 12.0, 2.5)
        expected_r_h = (
            2.0 * (kin["r_succ"] / MW_SUCCINIC_ACID)
            + 1.0 * (kin["r_by1"] / MW_BYPRODUCT_ACID)
            + 1.0 * (kin["r_by2"] / MW_LACTIC_ACID)
        )
        assert math.isclose(kin["r_h_total"], expected_r_h, rel_tol=1e-6)

    def test_base_titration_rate_demand(self) -> None:
        """Base flow rate satisfies neutralization stoichiometric balance."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        expected_f_base = (
            reactor.state.broth_volume_l * reactor.state.proton_generation_rate_mol_l_h
        ) / reactor.config.base_molarity_mol_l
        assert math.isclose(reactor.state.base_titration_rate_l_h, expected_f_base, rel_tol=1e-5)

    def test_unneutralized_organic_acid_causes_ph_drop(self) -> None:
        """Disabling base pump causes broth pH to decline."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.state.base_pump_active = False
        initial_ph = reactor.state.ph_level

        for _ in range(30):
            reactor.rk4_step(dt=1.0)

        assert reactor.state.ph_level < initial_ph


# ============================================================================
# Section 7: Coupled 6-State ODE System & RK4 Numerical Integrator Stability
# ============================================================================

class TestSection07CoupledODESystemAndRK4Integrator:
    """Verify 6-state ODE derivative formulation, RK4 stability, and time scaling."""

    def test_ode_system_vector_size_and_finite(self) -> None:
        """Continuous derivative dy/dt evaluates exactly 6 finite float components."""
        reactor = BioSuccinicAcidReactor()
        y0 = [15.0, 45.0, 80.0, 55.0, 12.0, 2.5]
        derivs = reactor.ode_system(y0)
        assert len(derivs) == 6
        assert all(math.isfinite(d) for d in derivs)

    def test_rk4_step_advances_simulation_time(self) -> None:
        """Single RK4 step advances sim_time_s and increments cycle count."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        t0 = reactor.state.sim_time_s
        c0 = reactor.state.cycle_count

        reactor.rk4_step(dt=0.02)
        assert reactor.state.sim_time_s > t0
        assert math.isclose(reactor.state.sim_time_s, t0 + 0.02, abs_tol=1e-6)
        assert reactor.state.cycle_count == c0 + 1

    def test_rk4_step_hours_scaling(self) -> None:
        """rk4_step_hours() properly scales time step from hours to seconds."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        t0 = reactor.state.sim_time_s

        reactor.rk4_step_hours(dt_h=0.5)
        assert math.isclose(reactor.state.sim_time_s, t0 + 1800.0, abs_tol=1e-3)

    def test_rk4_state_non_negativity_clipping(self) -> None:
        """RK4 step enforces non-negative bounds on concentrations."""
        reactor = BioSuccinicAcidReactor()
        reactor.state.substrate_glucose_g_l = 0.0001
        reactor.rk4_step(dt=10.0)
        assert reactor.state.substrate_glucose_g_l >= 0.0
        assert reactor.state.biomass_conc_g_l >= 0.0
        assert reactor.state.succinic_acid_g_l >= 0.0

    def test_rk4_numerical_stability_across_dt(self) -> None:
        """Integrator remains numerically stable across multiple scan step sizes."""
        for dt_val in [0.005, 0.01, 0.02]:
            reactor = BioSuccinicAcidReactor()
            reactor.reset()
            for _ in range(50):
                reactor.rk4_step(dt=dt_val)
            assert not math.isnan(reactor.state.biomass_conc_g_l)
            assert not math.isnan(reactor.state.succinic_acid_g_l)
            assert not math.isnan(reactor.state.dissolved_co2_mm)
            assert not math.isinf(reactor.state.biomass_conc_g_l)


# ============================================================================
# Section 8: Mathematical Conservation Laws & Residuals (< 1e-10)
# ============================================================================

class TestSection08ConservationLawsAndResiduals:
    """Verify carbon, stoichiometric, and total liquid mass conservation residuals (< 1e-10)."""

    def test_carbon_mass_balance_residual_bound(self) -> None:
        """Carbon conservation residual is strictly < 1e-10 kg/s."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        assert reactor.state.carbon_mass_balance_residual < 1.0e-10
        assert reactor.state.carbon_mass_balance_residual >= 0.0

    def test_stoichiometric_mass_balance_residual_bound(self) -> None:
        """Stoichiometric mass conservation residual is strictly < 1e-10 kg/s."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        assert reactor.state.stoichiometric_mass_balance_residual < 1.0e-10
        assert reactor.state.stoichiometric_mass_balance_residual >= 0.0

    def test_total_mass_balance_residual_bound(self) -> None:
        """Total broth mass balance residual is strictly < 1e-10 kg/s."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        assert reactor.state.total_mass_balance_residual < 1.0e-10
        assert reactor.state.total_mass_balance_residual >= 0.0

    def test_conservation_residual_stability_under_scan_steps(self) -> None:
        """All conservation residuals remain < 1e-10 across 50 consecutive scan steps."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        for _ in range(50):
            reactor.scan_step(dt=0.02)
        assert reactor.state.carbon_mass_balance_residual < 1.0e-10
        assert reactor.state.stoichiometric_mass_balance_residual < 1.0e-10
        assert reactor.state.total_mass_balance_residual < 1.0e-10


# ============================================================================
# Section 9: Process Safety Interlocks & Strict Priority Hierarchy
# ============================================================================

class TestSection09SafetyInterlocksAndPriorityHierarchy:
    """Verify strict priority hierarchy: 0xF701 > 0xF702 > 0xF703 > 0xF704 > 0x0000."""

    def test_priority_1_co2_starvation_trip(self) -> None:
        """0xF701 CO2_STARVATION trips when dissolved CO2 < 15.0 mM."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.state.dissolved_co2_mm = 12.0
        reactor._evaluate_safety_interlocks()

        assert reactor.state.trip_code == BioSuccinicTripCode.CO2_STARVATION
        assert reactor.state.co2_sparging_active is False
        assert reactor.state.base_pump_active is False
        assert reactor.state.acidification_trip_alarm is True

    def test_priority_2_acidification_runaway_trip_ph(self) -> None:
        """0xF702 ACIDIFICATION_RUNAWAY trips when pH < 6.0."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.state.ph_level = 5.8
        reactor._evaluate_safety_interlocks()

        assert reactor.state.trip_code == BioSuccinicTripCode.ACIDIFICATION_RUNAWAY
        assert reactor.state.co2_sparging_active is False
        assert reactor.state.base_pump_active is False
        assert reactor.state.acidification_trip_alarm is True

    def test_priority_2_acidification_runaway_trip_byproduct(self) -> None:
        """0xF702 ACIDIFICATION_RUNAWAY trips when byproduct acid > 25.0 g/L."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.state.byproduct_acid_g_l = 28.0
        reactor._evaluate_safety_interlocks()

        assert reactor.state.trip_code == BioSuccinicTripCode.ACIDIFICATION_RUNAWAY
        assert reactor.state.co2_sparging_active is False
        assert reactor.state.base_pump_active is False
        assert reactor.state.acidification_trip_alarm is True

    def test_priority_3_thermal_excursion_trip(self) -> None:
        """0xF703 THERMAL_EXCURSION trips when temperature > 40.0 °C."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.state.temperature_c = 41.5
        reactor._evaluate_safety_interlocks()

        assert reactor.state.trip_code == BioSuccinicTripCode.THERMAL_EXCURSION
        assert reactor.state.co2_sparging_active is False
        assert reactor.state.base_pump_active is False
        assert reactor.state.acidification_trip_alarm is True

    def test_priority_4_contamination_lactic_spike(self) -> None:
        """0xF704 CONTAMINATION_LACTIC_SPIKE trips when lactic acid > 10.0 g/L."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.state.byproduct_lactic_g_l = 12.5
        reactor._evaluate_safety_interlocks()

        assert reactor.state.trip_code == BioSuccinicTripCode.CONTAMINATION_LACTIC_SPIKE
        assert reactor.state.co2_sparging_active is False
        assert reactor.state.base_pump_active is False
        assert reactor.state.acidification_trip_alarm is True

    def test_priority_5_normal_and_harvest(self) -> None:
        """0x0000 NORMAL when healthy; transitions to harvest code when succinate >= 75.0 g/L."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor._evaluate_safety_interlocks()
        assert reactor.state.trip_code == BioSuccinicTripCode.NORMAL
        assert reactor.state.metabolic_state_code == BioSuccinicMetabolicState.ANAEROBIC_FERMENTATION
        assert reactor.state.batch_harvest_complete is False

        # Target succinic acid reached
        reactor.state.succinic_acid_g_l = 76.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.trip_code == BioSuccinicTripCode.NORMAL
        assert reactor.state.metabolic_state_code == BioSuccinicMetabolicState.BATCH_HARVEST_COMPLETE
        assert reactor.state.batch_harvest_complete is True

    def test_strict_priority_hierarchy_preemption(self) -> None:
        """Higher priority faults deterministically preempt lower priority faults."""
        reactor = BioSuccinicAcidReactor()

        # CO2 starvation (0xF701) preempts acidification (0xF702), thermal (0xF703), and contamination (0xF704)
        reactor.reset()
        reactor.state.dissolved_co2_mm = 10.0
        reactor.state.ph_level = 5.5
        reactor.state.temperature_c = 42.0
        reactor.state.byproduct_lactic_g_l = 15.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.trip_code == BioSuccinicTripCode.CO2_STARVATION

        # Acidification (0xF702) preempts thermal (0xF703) and contamination (0xF704)
        reactor.reset()
        reactor.state.dissolved_co2_mm = 80.0
        reactor.state.ph_level = 5.5
        reactor.state.temperature_c = 42.0
        reactor.state.byproduct_lactic_g_l = 15.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.trip_code == BioSuccinicTripCode.ACIDIFICATION_RUNAWAY

        # Thermal (0xF703) preempts contamination (0xF704)
        reactor.reset()
        reactor.state.dissolved_co2_mm = 80.0
        reactor.state.ph_level = 6.8
        reactor.state.temperature_c = 42.0
        reactor.state.byproduct_lactic_g_l = 15.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.trip_code == BioSuccinicTripCode.THERMAL_EXCURSION


# ============================================================================
# Section 10: Diagnostic & Trip Code Properties
# ============================================================================

class TestSection10DiagnosticAndTripCodeProperties:
    """Verify signed and unsigned 16-bit values, comparisons, hashing, string formatting, and flags."""

    def test_trip_code_hex_and_integer_values(self) -> None:
        """Hex integer values match W284 specification."""
        assert BioSuccinicTripCode.NORMAL.value == 0x0000
        assert BioSuccinicTripCode.CO2_STARVATION.value == 0xF701
        assert BioSuccinicTripCode.ACIDIFICATION_RUNAWAY.value == 0xF702
        assert BioSuccinicTripCode.THERMAL_EXCURSION.value == 0xF703
        assert BioSuccinicTripCode.CONTAMINATION_LACTIC_SPIKE.value == 0xF704

    def test_trip_code_signed_two_complement(self) -> None:
        """Signed 16-bit representations: 0xF701=-2303, 0xF702=-2302, 0xF703=-2301, 0xF704=-2300."""
        assert (0xF701 - 65536) == -2303
        assert (0xF702 - 65536) == -2302
        assert (0xF703 - 65536) == -2301
        assert (0xF704 - 65536) == -2300

    def test_trip_code_equality_comparisons(self) -> None:
        """BioSuccinicTripCode transparently compares equal to signed and unsigned integers."""
        assert BioSuccinicTripCode.NORMAL == 0
        assert BioSuccinicTripCode.NORMAL == 0x0000

        assert BioSuccinicTripCode.CO2_STARVATION == 0xF701
        assert BioSuccinicTripCode.CO2_STARVATION == 63233
        assert BioSuccinicTripCode.CO2_STARVATION == -2303

        assert BioSuccinicTripCode.ACIDIFICATION_RUNAWAY == 0xF702
        assert BioSuccinicTripCode.ACIDIFICATION_RUNAWAY == 63234
        assert BioSuccinicTripCode.ACIDIFICATION_RUNAWAY == -2302

        assert BioSuccinicTripCode.THERMAL_EXCURSION == 0xF703
        assert BioSuccinicTripCode.THERMAL_EXCURSION == 63235
        assert BioSuccinicTripCode.THERMAL_EXCURSION == -2301

        assert BioSuccinicTripCode.CONTAMINATION_LACTIC_SPIKE == 0xF704
        assert BioSuccinicTripCode.CONTAMINATION_LACTIC_SPIKE == 63236
        assert BioSuccinicTripCode.CONTAMINATION_LACTIC_SPIKE == -2300

    def test_trip_code_missing_lookup(self) -> None:
        """Constructor converts signed and unsigned integers back to enum members."""
        assert BioSuccinicTripCode(-2303) == BioSuccinicTripCode.CO2_STARVATION
        assert BioSuccinicTripCode(0xF701) == BioSuccinicTripCode.CO2_STARVATION
        assert BioSuccinicTripCode(-2302) == BioSuccinicTripCode.ACIDIFICATION_RUNAWAY
        assert BioSuccinicTripCode(0xF702) == BioSuccinicTripCode.ACIDIFICATION_RUNAWAY
        assert BioSuccinicTripCode(-2301) == BioSuccinicTripCode.THERMAL_EXCURSION
        assert BioSuccinicTripCode(0xF703) == BioSuccinicTripCode.THERMAL_EXCURSION
        assert BioSuccinicTripCode(-2300) == BioSuccinicTripCode.CONTAMINATION_LACTIC_SPIKE
        assert BioSuccinicTripCode(0xF704) == BioSuccinicTripCode.CONTAMINATION_LACTIC_SPIKE

    def test_trip_code_hash_and_bitwise_masking(self) -> None:
        """__hash__ implementation masks to unsigned 16-bit integer."""
        c = BioSuccinicTripCode.CO2_STARVATION
        assert hash(c) == hash(int(c) & 0xFFFF)
        assert (c & 0xFFFF) == 0xF701
        assert (c & 0xFF) == 0x01
        assert (0xFF & c) == 0x01
        assert "0xF701" in str(c)

    def test_metabolic_state_enum(self) -> None:
        """BioSuccinicMetabolicState values match specifications."""
        assert BioSuccinicMetabolicState.IDLE == 0x00
        assert BioSuccinicMetabolicState.ANAEROBIC_FERMENTATION == 0x01
        assert BioSuccinicMetabolicState.BASE_TITRATION_REGULATION == 0x02
        assert BioSuccinicMetabolicState.BATCH_HARVEST_COMPLETE == 0x05
        assert BioSuccinicMetabolicState.TRIPPED == 0x0F

    def test_status_bits_flag(self) -> None:
        """BioSuccinicStatusBits bitmask flags."""
        assert BioSuccinicStatusBits.RUNNING == 1 << 0
        assert BioSuccinicStatusBits.CO2_SPARGING_ACTIVE == 1 << 1
        assert BioSuccinicStatusBits.BASE_PUMP_ACTIVE == 1 << 2
        assert BioSuccinicStatusBits.TRIP_ALARM_ACTIVE == 1 << 3
        assert BioSuccinicStatusBits.CO2_STARVATION_TRIP == 1 << 4
        assert BioSuccinicStatusBits.ACIDIFICATION_RUNAWAY_TRIP == 1 << 5
        assert BioSuccinicStatusBits.THERMAL_EXCURSION_TRIP == 1 << 6
        assert BioSuccinicStatusBits.CONTAMINATION_LACTIC_TRIP == 1 << 7
        assert BioSuccinicStatusBits.BATCH_HARVEST_COMPLETE == 1 << 8


# ============================================================================
# Section 11: Fault Injections, Clear Faults & Actuator Coil Responses
# ============================================================================

class TestSection11FaultInjectionsAndActuations:
    """Verify inject_fault(), clear_faults(), and actuator coil assertions."""

    def test_inject_fault_co2_starvation(self) -> None:
        """Injecting CO2 starvation asserts 0xF701 and triggers alarm."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.inject_fault("co2")

        assert reactor.state.trip_code == BioSuccinicTripCode.CO2_STARVATION
        assert reactor.state.co2_sparging_active is False
        assert reactor.state.base_pump_active is False
        assert reactor.state.acidification_trip_alarm is True

    def test_inject_fault_acidification(self) -> None:
        """Injecting acidification runaway asserts 0xF702."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.inject_fault("acidification")

        assert reactor.state.trip_code == BioSuccinicTripCode.ACIDIFICATION_RUNAWAY
        assert reactor.state.acidification_trip_alarm is True

    def test_inject_fault_thermal(self) -> None:
        """Injecting thermal excursion asserts 0xF703."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.inject_fault("thermal")

        assert reactor.state.trip_code == BioSuccinicTripCode.THERMAL_EXCURSION
        assert reactor.state.acidification_trip_alarm is True

    def test_inject_fault_contamination(self) -> None:
        """Injecting lactic spike asserts 0xF704."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.inject_fault("contamination")

        assert reactor.state.trip_code == BioSuccinicTripCode.CONTAMINATION_LACTIC_SPIKE
        assert reactor.state.acidification_trip_alarm is True

    def test_inject_fault_harvest(self) -> None:
        """Injecting harvest asserts harvest completion."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.inject_fault("harvest")

        assert reactor.state.batch_harvest_complete is True
        assert reactor.state.metabolic_state_code == BioSuccinicMetabolicState.BATCH_HARVEST_COMPLETE

    def test_clear_faults_restores_nominal(self) -> None:
        """clear_faults() resets reactor to healthy baseline."""
        reactor = BioSuccinicAcidReactor()
        reactor.inject_fault("co2")
        assert reactor.state.trip_code != BioSuccinicTripCode.NORMAL

        reactor.clear_faults()
        assert reactor.state.trip_code == BioSuccinicTripCode.NORMAL
        assert reactor.state.co2_sparging_active is True
        assert reactor.state.base_pump_active is True
        assert reactor.state.acidification_trip_alarm is False


# ============================================================================
# Section 12: Horner OCS Register Space Synchronization (%R2450..%R2457, %M571..%M573)
# ============================================================================

class TestSection12HornerOCSMemoryIntegration:
    """Verify register synchronization (%R2450..%R2457, %M571..%M573) and scaling."""

    def test_nominal_register_synchronization(self) -> None:
        """Registers and coils match nominal steady-state values bit-exactly."""
        table = RegisterTable()
        reactor = BioSuccinicAcidReactor(register_table=table)
        reactor.reset()

        assert table.read_word(REG_BIOSUCCINIC_TEMP_SCALED) == 370
        assert table.read_word(REG_BIOSUCCINIC_BIOMASS_SCALED) == 150
        assert table.read_word(REG_BIOSUCCINIC_GLUCOSE_SCALED) == 450
        assert table.read_word(REG_BIOSUCCINIC_CO2_SCALED) == 800
        assert table.read_word(REG_BIOSUCCINIC_SUCCINIC_SCALED) == 550
        assert table.read_word(REG_BIOSUCCINIC_BYPRODUCT1_SCALED) == 120
        assert table.read_word(REG_BIOSUCCINIC_BYPRODUCT2_SCALED) == 25

        # %R2457 packed word
        r2457_val = table.read_uword(REG_BIOSUCCINIC_YIELD_STATE_SCALED)
        yield_byte = (r2457_val >> 8) & 0xFF
        state_byte = r2457_val & 0xFF
        assert yield_byte == 200  # 20.0% * 10
        assert state_byte == 0x01  # Anaerobic fermentation active
        assert r2457_val == ((200 << 8) | 1)

        # Coils
        assert table.read_bit(COIL_BIOSUCCINIC_CO2_SPARGING_ACTIVE) is True
        assert table.read_bit(COIL_BIOSUCCINIC_BASE_PUMP_ACTIVE) is True
        assert table.read_bit(COIL_BIOSUCCINIC_ACIDIFICATION_TRIP_ALARM) is False

    def test_trip_register_and_coil_synchronization(self) -> None:
        """When 0xF701 trips, coils update and alarm asserts."""
        table = RegisterTable()
        reactor = BioSuccinicAcidReactor(register_table=table)
        reactor.inject_fault("co2")

        assert table.read_bit(COIL_BIOSUCCINIC_CO2_SPARGING_ACTIVE) is False
        assert table.read_bit(COIL_BIOSUCCINIC_BASE_PUMP_ACTIVE) is False
        assert table.read_bit(COIL_BIOSUCCINIC_ACIDIFICATION_TRIP_ALARM) is True

    def test_system_privilege_register_sync(self) -> None:
        """Explicit sync_to_registers call with PrivilegeMode.SYSTEM."""
        table = RegisterTable()
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        reactor.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_word("%R2450") == 370
        assert table.read_word("%R2451") == 150
        assert table.read_word("%R2452") == 450
        assert table.read_word("%R2453") == 800
        assert table.read_word("%R2454") == 550
        assert table.read_word("%R2455") == 120
        assert table.read_word("%R2456") == 25
        assert table.read_bit("%M571") is True
        assert table.read_bit("%M572") is True
        assert table.read_bit("%M573") is False

    def test_register_and_coil_address_aliases(self) -> None:
        """String constants for registers and coils resolve properly."""
        assert REG_BIOSUCCINIC_TEMPERATURE_SCALED == "%R2450"
        assert REG_BIOSUCCINIC_FERMENTER_TEMP_SCALED == "%R2450"
        assert REG_BIOSUCCINIC_BIOMASS_CONC_SCALED == "%R2451"
        assert REG_BIOSUCCINIC_X_SCALED == "%R2451"
        assert REG_BIOSUCCINIC_SUBSTRATE_GLUCOSE_SCALED == "%R2452"
        assert REG_BIOSUCCINIC_S_SCALED == "%R2452"
        assert REG_BIOSUCCINIC_DISSOLVED_CO2_SCALED == "%R2453"
        assert REG_BIOSUCCINIC_C_CO2_SCALED == "%R2453"
        assert REG_BIOSUCCINIC_SUCCINIC_ACID_SCALED == "%R2454"
        assert REG_BIOSUCCINIC_P_SUCC_SCALED == "%R2454"
        assert REG_BIOSUCCINIC_BYPRODUCT_ACID_SCALED == "%R2455"
        assert REG_BIOSUCCINIC_P_BY1_SCALED == "%R2455"
        assert REG_BIOSUCCINIC_BYPRODUCT_LACTIC_SCALED == "%R2456"
        assert REG_BIOSUCCINIC_P_BY2_SCALED == "%R2456"
        assert REG_BIOSUCCINIC_METABOLIC_YIELD_SCALED == "%R2457"
        assert REG_BIOSUCCINIC_STATE_CODE_SCALED == "%R2457"

        assert COIL_BIOSUCCINIC_ANAEROBIC_CO2_SPARGING == "%M571"
        assert COIL_BIOSUCCINIC_CARBOXYLATION_VALID == "%M571"
        assert COIL_BIOSUCCINIC_BASE_NEUTRALIZER_PUMP_ACTIVE == "%M572"
        assert COIL_BIOSUCCINIC_PH_REGULATOR == "%M572"
        assert COIL_BIOSUCCINIC_ACIDIFICATION_RUNAWAY_ALARM == "%M573"
        assert COIL_BIOSUCCINIC_SUBSTRATE_INVERSION_ALARM == "%M573"


# ============================================================================
# Section 13: Pure IEC 61131-3 Structured Text Generation & AST Bindings
# ============================================================================

class TestSection13PureSTPOUAndASTValidation:
    """Verify IEC 61131-3 Structured Text compliance, parser validation, and register bindings."""

    def test_pure_st_pou_security_guard(self) -> None:
        """BIOSUCCINIC_ACID_PURE_ST_POU passes SecurityGuard cleanly."""
        SecurityGuard.assert_pure_st_content(BIOSUCCINIC_ACID_PURE_ST_POU)

    def test_pure_st_pou_st_parser_validation(self) -> None:
        """STParser.validate_code validates POU with AgentStatus.SUCCESS."""
        res = STParser.validate_code(BIOSUCCINIC_ACID_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_ast_variable_memory_address_bindings(self) -> None:
        """Parsed AST POU contains all 11 required %R2450..%R2457 and %M571..%M573 bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(BIOSUCCINIC_ACID_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "BioSuccinicAcidSync"
        assert pou.pou_type == POUType.PROGRAM

        required_registers = [
            "%R2450", "%R2451", "%R2452", "%R2453",
            "%R2454", "%R2455", "%R2456", "%R2457",
            "%M571", "%M572", "%M573",
        ]
        for reg in required_registers:
            assert reg in pou.bound_registers, f"Missing register {reg} in bound registers"

        for var in pou.variables:
            addr = getattr(var, "address_binding", None) or getattr(var, "memory_address", None)
            if addr:
                assert addr.startswith(("%R", "%M"))

    def test_verify_bio_succinic_acid_pure_st_function(self) -> None:
        """Helper verification function returns successful result."""
        res = verify_bio_succinic_acid_pure_st()
        assert bool(res) is True
        assert res.status == AgentStatus.SUCCESS
        assert res.error is None

    def test_pou_string_constants_aliases(self) -> None:
        """Aliases for POU string match canonical definition."""
        assert BIOSUCCINIC_ACID_SYNC_POU == BIOSUCCINIC_ACID_PURE_ST_POU
        assert BIO_SUCCINIC_ACID_PURE_ST_POU == BIOSUCCINIC_ACID_PURE_ST_POU
        assert BIO_SUCCINIC_ACID_SYNC_POU == BIOSUCCINIC_ACID_PURE_ST_POU
        assert ST_PROGRAM_BIO_SUCCINIC_ACID_SYNC == BIOSUCCINIC_ACID_PURE_ST_POU


# ============================================================================
# Section 14: Anti-Ladder Security Guard Validation
# ============================================================================

class TestSection14AntiLadderSecurityGuard:
    """Verify anti-ladder security guard rejects contacts, coils, rungs, and mnemonics."""

    def test_reject_ladder_contacts(self) -> None:
        """Normally-open and normally-closed contacts are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---[ ]---")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---[/]---")

    def test_reject_ladder_coils(self) -> None:
        """Standard and set/reset coils are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---( )---")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---(S)---")

    def test_reject_rung_and_network_delimiters(self) -> None:
        """RUNG and NETWORK keywords are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: X := 1;")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 10\nLD %M571\nST %M573")

    def test_reject_ladder_mnemonics(self) -> None:
        """XIC and OTE mnemonics are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC %M571 OTE %M573")


# ============================================================================
# Section 15: ILogicUnit Compliance & 100-Cycle Soak Stability
# ============================================================================

class TestSection15ILogicUnitComplianceAndSoakStability:
    """Verify ILogicUnit interface compliance, lifecycle methods, and 100-cycle soak stability."""

    def test_ilogic_unit_interface_compliance(self) -> None:
        """BioSuccinicAcidReactor and LogicUnit wrapper implement ILogicUnit protocol."""
        reactor = BioSuccinicAcidReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "BioSuccinicAcidReactor"
        assert reactor.priority == 284
        assert reactor.is_enabled is True

        logic_unit = BioSuccinicAcidLogicUnit()
        assert isinstance(logic_unit, ILogicUnit)
        assert logic_unit.priority == 284
        assert logic_unit.is_enabled is True

    def test_enable_disable_lifecycle(self) -> None:
        """Disabling logic unit halts scan execution."""
        reactor = BioSuccinicAcidReactor()
        reactor.disable()
        assert reactor.is_enabled is False

        t0 = reactor.state.sim_time_s
        reactor.scan_step(0.02)
        assert reactor.state.sim_time_s == t0

        reactor.enable()
        assert reactor.is_enabled is True
        reactor.scan_step(0.02)
        assert reactor.state.sim_time_s > t0

    def test_step_and_scan_step_aliases(self) -> None:
        """step() delegates to scan_step()."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        t0 = reactor.state.sim_time_s
        reactor.step(0.02)
        assert reactor.state.sim_time_s > t0

    def test_execute_with_scan_context(self) -> None:
        """execute() method with ScanContext progresses time."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        reactor.execute(ctx)
        assert math.isclose(reactor.state.sim_time_s, 0.02, abs_tol=1e-5)

    def test_logic_unit_wrapper_methods(self) -> None:
        """BioSuccinicAcidLogicUnit wrapper delegates all ILogicUnit operations."""
        table = RegisterTable()
        lu = BioSuccinicAcidLogicUnit(register_table=table)
        lu.reset()
        assert lu.name == "BioSuccinicAcidLogicUnit"
        assert lu.priority == 284

        lu.scan_step(0.02)
        assert lu.simulator.state.sim_time_s > 0.0

        lu.step(0.02)
        ctx = ScanContext(cycle=3, dt_ms=20.0, elapsed_time_ms=60.0, dt=0.02)
        lu.execute(ctx)

        lu.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2450") == 370

        lu.disable()
        assert lu.is_enabled is False
        lu.enable()
        assert lu.is_enabled is True

    def test_100_cycle_soak_stability(self) -> None:
        """100 scan cycles execute with zero NaN, zero Inf, and bounded state variables."""
        reactor = BioSuccinicAcidReactor()
        reactor.reset()

        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            reactor.execute(ctx)

        assert not math.isnan(reactor.state.biomass_conc_g_l)
        assert not math.isnan(reactor.state.succinic_acid_g_l)
        assert not math.isnan(reactor.state.substrate_glucose_g_l)
        assert not math.isnan(reactor.state.dissolved_co2_mm)
        assert not math.isinf(reactor.state.biomass_conc_g_l)

        assert 14.5 <= reactor.state.biomass_conc_g_l <= 16.0
        assert 54.5 <= reactor.state.succinic_acid_g_l <= 56.5
        assert reactor.state.trip_code == BioSuccinicTripCode.NORMAL
        assert reactor.state.co2_sparging_active is True
        assert reactor.state.acidification_trip_alarm is False


# ============================================================================
# Section 16: Deterministic 10-Stage Verification Suite & Artifact Emission
# ============================================================================

class TestSection16VerificationSuiteAndArtifactEmission:
    """Verify run_bio_succinic_acid_verification() output contract and evidence emission."""

    def test_run_verification_suite_success(self, tmp_path: Path) -> None:
        """Verification suite runs all 10 stages cleanly and returns strict 4-state contract."""
        out_file = tmp_path / "bio_succinic_acid_evidence.json"
        res = run_bio_succinic_acid_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "data" in res
        assert res["data"]["checks_passed"] == 10
        assert res["data"]["total_checks"] == 10
        assert res["data"]["stages_passed"] == 10
        assert res["data"]["total_stages"] == 10
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["stages"]) == 10

    def test_verification_function_alias(self) -> None:
        """Alias run_bio_succinic_verification points to canonical runner."""
        assert run_bio_succinic_verification is run_bio_succinic_acid_verification
        assert verify_bio_succinic_pure_st is verify_bio_succinic_acid_pure_st
        assert validate_pure_st is verify_bio_succinic_acid_pure_st


# ============================================================================
# Section 17: Class and Compatibility Aliases & Sensitivity Edge Cases
# ============================================================================

class TestSection17AliasesAndSensitivityEdgeCases:
    """Verify class compatibility aliases and extreme edge parameter sensitivities."""

    def test_class_aliases(self) -> None:
        """All model and logic unit aliases resolve to canonical classes."""
        assert BioSuccinicReactor is BioSuccinicAcidReactor
        assert BioSuccinicSimulator is BioSuccinicAcidReactor
        assert BioSuccinicAcidSimulator is BioSuccinicAcidReactor
        assert BioSuccinicEngine is BioSuccinicAcidReactor
        assert BioSuccinicAcidEngine is BioSuccinicAcidReactor
        assert BioSuccinicModel is BioSuccinicAcidReactor
        assert BioSuccinicAcidModel is BioSuccinicAcidReactor
        assert BioSuccinicPlantModel is BioSuccinicAcidReactor
        assert BioSuccinicAcidPlantModel is BioSuccinicAcidReactor

        assert BioSuccinicConfig is BioSuccinicAcidConfig
        assert BioSuccinicParameters is BioSuccinicAcidConfig
        assert BioSuccinicAcidParameters is BioSuccinicAcidConfig

        assert BioSuccinicState is BioSuccinicAcidState

        assert BioSuccinicAcidTripCode is BioSuccinicTripCode
        assert BioSuccinicDiagnosticCode is BioSuccinicTripCode
        assert BioSuccinicAcidDiagnosticCode is BioSuccinicTripCode

        assert BioSuccinicAcidStatusBits is BioSuccinicStatusBits
        assert BioSuccinicFermentationStatusBits is BioSuccinicStatusBits

        assert BioSuccinicLogicUnit is BioSuccinicAcidLogicUnit

    def test_zero_glucose_suppression(self) -> None:
        """Zero glucose completely halts cell growth."""
        reactor = BioSuccinicAcidReactor()
        kin = reactor.compute_kinetics(15.0, 0.0, 80.0, 55.0, 12.0, 2.5)
        assert kin["mu"] == 0.0

    def test_zero_co2_suppression(self) -> None:
        """Zero dissolved CO2 completely halts cell growth and maximizes transfer gradient."""
        reactor = BioSuccinicAcidReactor()
        kin = reactor.compute_kinetics(15.0, 45.0, 0.0, 55.0, 12.0, 2.5)
        assert kin["mu"] == 0.0
        assert kin["ctr"] > 0.0

    def test_extreme_acid_inhibition(self) -> None:
        """Severe organic acid buildup halts bacterial cell growth."""
        reactor = BioSuccinicAcidReactor()
        kin = reactor.compute_kinetics(15.0, 45.0, 80.0, 95.0, 45.0, 15.0)
        assert kin["mu"] == 0.0
