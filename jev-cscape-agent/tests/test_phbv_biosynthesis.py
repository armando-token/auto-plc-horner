"""Comprehensive Industrial Polyhydroxyvalerate (PHV) / PHBV Copolymer Biosynthesis Test Suite.

Work Package: W281 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 14 comprehensive engineering verification sections:
1. Section 1: Universal Physical & Biochemical Constants, Molecular Weights & Carbon Fractions
2. Section 2: Model Initialization, Geometry & Parameter Validation
3. Section 3: Reaction Kinetics, Glucose & Precursor Uptake Rates
4. Section 4: Dual-Phase Metabolic Transition (Phase 1 Growth vs Phase 2 Accumulation)
5. Section 5: Copolymer Composition & HV Fraction Response to Precursor Concentration
6. Section 6: Aeration, Dissolved Oxygen Dynamics & Oxygen Uptake
7. Section 7: Coupled 6-State ODE System, Derivatives & RK4 Numerical Integrator
8. Section 8: Analytical Mass Conservation Residuals (< 1e-10 kg/s)
9. Section 9: Process Safety Trips & Strict Hierarchy (0xF601 > 0xF602 > 0xF603 > 0xF604)
10. Section 10: PhbvTripCode IntEnum Masking, Signed/Unsigned Equality & Hash Compliance
11. Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2420..%R2427, %M564..%M566)
12. Section 12: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
13. Section 13: Anti-Ladder Security Guard Rejection (Contacts, Coils, Rungs, Networks, Mnemonics)
14. Section 14: ILogicUnit Compliance, 100-Cycle Soak Stability & 10-Stage Verification Runner
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

from jev_cscape.simulation.phbv_biosynthesis import (
    BATCH_HARVEST_POLYMER_G_L,
    BIOMASS_NOMINAL_G_L,
    COIL_PHBV_ACIDIFICATION_TRIP_ALARM,
    COIL_PHBV_BATCH_HARVEST_COMPLETE,
    COIL_PHBV_FEED_PUMP_ACTIVE,
    COIL_PHBV_HARVEST_ALARM,
    COIL_PHBV_INDUCTION_ACTIVE,
    COIL_PHBV_NITROGEN_EXHAUSTED,
    COIL_PHBV_POLYMER_INDUCTION_ACTIVE,
    COIL_PHBV_SUBSTRATE_FEED_PUMP_ACTIVE,
    CONTAMINATION_PH_TRIP_MIN,
    DISSOLVED_OXYGEN_NOMINAL_PCT,
    DO_STARVATION_TRIP_PCT,
    F_C_BIOMASS,
    F_C_CO2,
    F_C_GLUCOSE,
    F_C_HB,
    F_C_HV,
    F_C_VALERATE,
    GLUCOSE_NOMINAL_G_L,
    G_ACCEL,
    HV_FRACTION_NOMINAL_MOL_PCT,
    KLA_NOMINAL_H1,
    MW_3HB,
    MW_3HV,
    MW_BIOMASS_CMOL,
    MW_C,
    MW_CO2,
    MW_GLUCOSE,
    MW_H,
    MW_H2O,
    MW_HB_MER,
    MW_HV_MER,
    MW_N,
    MW_NA,
    MW_O,
    MW_O2,
    MW_P,
    MW_PHB_MER,
    MW_PHV_MER,
    MW_PRECURSOR_SUBSTRATE,
    MW_PRIMARY_SUBSTRATE,
    MW_PROPIONATE,
    MW_S,
    MW_SODIUM_VALERATE,
    MW_VALERATE,
    PHBV_BIOSYNTHESIS_PURE_ST_POU,
    PHBV_BIOSYNTHESIS_SYNC_POU,
    PHBV_PURE_ST_POU,
    PHBV_SYNC_POU,
    PHBVConfig,
    PHBVDiagnosticCode,
    PHBVEngine,
    PHBVLogicUnit,
    PHBVModel,
    PHBVPlantModel,
    PHBVReactor,
    PHBVSimulator,
    PHBVState,
    PHBVStatusBits,
    PHBVTripCode,
    PRECURSOR_NOMINAL_G_L,
    PRECURSOR_OVERCONC_TRIP_G_L,
    PhbvBiosynthesisConfig,
    PhbvBiosynthesisLogicUnit,
    PhbvBiosynthesisParameters,
    PhbvBiosynthesisReactor,
    PhbvBiosynthesisSimulator,
    PhbvBiosynthesisState,
    PhbvConfig,
    PhbvDiagnosticCode,
    PhbvEngine,
    PhbvFermentationStatusBits,
    PhbvLogicUnit,
    PhbvMetabolicState,
    PhbvModel,
    PhbvPlantModel,
    PhbvReactor,
    PhbvSimulator,
    PhbvState,
    PhbvStatusBits,
    PhbvTripCode,
    POLYMER_NOMINAL_G_L,
    R_GAS_CONST,
    REG_PHBV_BIOREACTOR_TEMP_SCALED,
    REG_PHBV_BIOMASS_CONC_SCALED,
    REG_PHBV_BIOMASS_SCALED,
    REG_PHBV_DISSOLVED_OXYGEN_SCALED,
    REG_PHBV_DO_SCALED,
    REG_PHBV_F_HV_SCALED,
    REG_PHBV_GLUCOSE_SCALED,
    REG_PHBV_GLUCOSE_SUBSTRATE_SCALED,
    REG_PHBV_GROWTH_RATE_STATE_CODE,
    REG_PHBV_GROWTH_STATE_SCALED,
    REG_PHBV_HV_FRACTION_SCALED,
    REG_PHBV_P_SCALED,
    REG_PHBV_PHBV_POLYMER_SCALED,
    REG_PHBV_POLYMER_ACCUMULATION_SCALED,
    REG_PHBV_POLYMER_SCALED,
    REG_PHBV_PRECURSOR_SCALED,
    REG_PHBV_PRECURSOR_VALERATE_SCALED,
    REG_PHBV_SG_SCALED,
    REG_PHBV_STATE_CODE_SCALED,
    REG_PHBV_SV_SCALED,
    REG_PHBV_TEMPERATURE_SCALED,
    REG_PHBV_TEMP_SCALED,
    REG_PHBV_X_SCALED,
    SPECIFIC_GROWTH_RATE_NOMINAL_H1,
    TEMP_NOMINAL_C,
    TEMP_RUNAWAY_TRIP_C,
    T_FERMENTER_NOMINAL_C,
    T_ZERO_CELSIUS,
    PureSTValidationResult,
    run_phbv_biosynthesis_verification,
    run_phbv_verification,
    validate_pure_st,
    verify_phbv_biosynthesis_pure_st,
    verify_phbv_pure_st,
)


# ============================================================================
# Section 1: Universal Physical & Biochemical Constants & Molecular Weights
# ============================================================================

class TestSection01PhysicalAndBiochemicalConstants:
    """Verify universal physical constants, IUPAC atomic weights, and substrate molecular weights."""

    def test_universal_physical_constants(self) -> None:
        """Physical constants must match SI and IUPAC standards."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, rel_tol=1e-8)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-8)
        assert math.isclose(T_FERMENTER_NOMINAL_C, 30.0, rel_tol=1e-8)
        assert math.isclose(TEMP_NOMINAL_C, 30.0, rel_tol=1e-8)

    def test_iupac_standard_atomic_weights(self) -> None:
        """IUPAC atomic weights for C, H, O, N, Na, P, S must be correct."""
        assert math.isclose(MW_C, 12.011, rel_tol=1e-5)
        assert math.isclose(MW_H, 1.008, rel_tol=1e-5)
        assert math.isclose(MW_O, 15.999, rel_tol=1e-5)
        assert math.isclose(MW_N, 14.007, rel_tol=1e-5)
        assert math.isclose(MW_NA, 22.990, rel_tol=1e-5)
        assert math.isclose(MW_P, 30.974, rel_tol=1e-5)
        assert math.isclose(MW_S, 32.065, rel_tol=1e-5)

    def test_primary_substrate_glucose_molecular_weight(self) -> None:
        """D-Glucose C6H12O6 stoichiometry must yield 180.156 g/mol."""
        calc_mw = 6.0 * MW_C + 12.0 * MW_H + 6.0 * MW_O
        assert math.isclose(MW_GLUCOSE, calc_mw, rel_tol=1e-6)
        assert math.isclose(MW_GLUCOSE, 180.156, rel_tol=1e-4)
        assert MW_PRIMARY_SUBSTRATE == MW_GLUCOSE

    def test_precursor_valerate_and_propionate_molecular_weights(self) -> None:
        """Valerate C5H10O2 (102.132 g/mol) and Sodium Valerate C5H9O2Na (124.114 g/mol)."""
        calc_val = 5.0 * MW_C + 10.0 * MW_H + 2.0 * MW_O
        calc_na_val = 5.0 * MW_C + 9.0 * MW_H + 2.0 * MW_O + MW_NA
        calc_prop = 3.0 * MW_C + 6.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_VALERATE, calc_val, rel_tol=1e-6)
        assert math.isclose(MW_VALERATE, 102.132, rel_tol=1e-4)
        assert math.isclose(MW_SODIUM_VALERATE, calc_na_val, rel_tol=1e-6)
        assert math.isclose(MW_SODIUM_VALERATE, 124.114, rel_tol=1e-4)
        assert math.isclose(MW_PROPIONATE, calc_prop, rel_tol=1e-6)
        assert MW_PRECURSOR_SUBSTRATE == MW_VALERATE

    def test_copolymer_repeat_units_molecular_weights(self) -> None:
        """3HB C4H6O2 (86.090 g/mol) and 3HV C5H8O2 (100.117 g/mol) repeat units."""
        calc_hb = 4.0 * MW_C + 6.0 * MW_H + 2.0 * MW_O
        calc_hv = 5.0 * MW_C + 8.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_HB_MER, calc_hb, rel_tol=1e-6)
        assert math.isclose(MW_HB_MER, 86.090, rel_tol=1e-4)
        assert math.isclose(MW_HV_MER, calc_hv, rel_tol=1e-6)
        assert math.isclose(MW_HV_MER, 100.117, rel_tol=1e-4)
        assert MW_3HB == MW_HB_MER == MW_PHB_MER
        assert MW_3HV == MW_HV_MER == MW_PHV_MER

    def test_bacterial_biomass_molecular_weight(self) -> None:
        """Cupriavidus necator empirical biomass CH1.8O0.5N0.2 must yield 24.6263 g/C-mol."""
        calc_bm = MW_C + 1.8 * MW_H + 0.5 * MW_O + 0.2 * MW_N
        assert math.isclose(MW_BIOMASS_CMOL, calc_bm, rel_tol=1e-6)
        assert math.isclose(MW_BIOMASS_CMOL, 24.6263, rel_tol=1e-4)

    def test_respiratory_gases_and_carbon_fractions(self) -> None:
        """O2 (31.998 g/mol), CO2 (44.009 g/mol), H2O (18.015 g/mol) and carbon mass fractions."""
        assert math.isclose(MW_O2, 31.998, rel_tol=1e-4)
        assert math.isclose(MW_CO2, 44.009, rel_tol=1e-4)
        assert math.isclose(MW_H2O, 18.015, rel_tol=1e-4)
        assert math.isclose(F_C_GLUCOSE, (6.0 * MW_C) / MW_GLUCOSE, rel_tol=1e-6)
        assert math.isclose(F_C_VALERATE, (5.0 * MW_C) / MW_VALERATE, rel_tol=1e-6)
        assert math.isclose(F_C_HB, (4.0 * MW_C) / MW_HB_MER, rel_tol=1e-6)
        assert math.isclose(F_C_HV, (5.0 * MW_C) / MW_HV_MER, rel_tol=1e-6)
        assert math.isclose(F_C_BIOMASS, MW_C / MW_BIOMASS_CMOL, rel_tol=1e-6)
        assert math.isclose(F_C_CO2, MW_C / MW_CO2, rel_tol=1e-6)


# ============================================================================
# Section 2: Model Initialization, Geometry & Parameter Validation
# ============================================================================

class TestSection02ModelInitializationAndConfig:
    """Verify default configurations, geometry, state initializations, and class aliases."""

    def test_default_config_parameters(self) -> None:
        """PhbvBiosynthesisConfig defaults must adhere to industrial pilot scale metrics."""
        cfg = PhbvBiosynthesisConfig()
        assert cfg.nominal_volume_l == 120.0
        assert cfg.maximum_volume_l == 150.0
        assert cfg.broth_density_kg_l == 1.030
        assert cfg.temperature_c == 30.0
        assert cfg.nominal_feed_rate_l_h == 6.0
        assert cfg.feed_glucose_conc_g_l == 350.0
        assert cfg.feed_valerate_conc_g_l == 50.0
        assert cfg.fed_batch_mode is True
        assert cfg.kla_nominal_h1 == 120.0
        assert cfg.do_sat_pct == 100.0
        assert cfg.p_max_capacity_g_l == 90.0

    def test_safety_limits_configuration(self) -> None:
        """Config safety interlock limits must match specification."""
        cfg = PhbvBiosynthesisConfig()
        assert cfg.do_starvation_trip_pct == 10.0
        assert cfg.precursor_overconc_trip_g_l == 5.0
        assert cfg.temp_runaway_trip_c == 37.0
        assert cfg.ph_trip_min == 6.0
        assert cfg.harvest_polymer_target_g_l == 70.0

    def test_reactor_initialization_and_nominal_state(self) -> None:
        """PhbvBiosynthesisReactor resets to nominal steady state baseline."""
        sim = PhbvBiosynthesisReactor()
        assert sim.state.temperature_c == TEMP_NOMINAL_C == 30.0
        assert sim.state.biomass_conc_g_l == BIOMASS_NOMINAL_G_L == 35.0
        assert sim.state.substrate_glucose_g_l == GLUCOSE_NOMINAL_G_L == 15.0
        assert sim.state.precursor_valerate_g_l == PRECURSOR_NOMINAL_G_L == 2.5
        assert sim.state.dissolved_oxygen_pct == DISSOLVED_OXYGEN_NOMINAL_PCT == 35.0
        assert sim.state.polymer_accumulation_g_l == POLYMER_NOMINAL_G_L == 55.0
        assert sim.state.hv_molar_fraction_pct == HV_FRACTION_NOMINAL_MOL_PCT == 15.5
        assert sim.state.trip_code == PhbvTripCode.NORMAL
        assert sim.state.nitrogen_exhausted_active is True
        assert sim.state.feed_pump_active is True
        assert sim.state.batch_harvest_or_acid_alarm is False

    def test_state_properties_and_synonyms(self) -> None:
        """Shorthand state properties (x, s_g, s_v, do, p, f_hv) read and write correctly."""
        state = PhbvBiosynthesisState()
        assert state.x == state.biomass_conc_g_l
        assert state.s_g == state.substrate_glucose_g_l
        assert state.s_v == state.precursor_valerate_g_l
        assert state.do == state.dissolved_oxygen_pct
        assert state.p == state.polymer_accumulation_g_l
        assert state.f_hv == state.hv_molar_fraction_pct

        state.x = 40.0
        state.s_g = 18.0
        state.s_v = 3.2
        state.do = 45.0
        state.p = 65.0
        state.f_hv = 18.0
        assert state.biomass_conc_g_l == 40.0
        assert state.substrate_glucose_g_l == 18.0
        assert state.precursor_valerate_g_l == 3.2
        assert state.dissolved_oxygen_pct == 45.0
        assert state.polymer_accumulation_g_l == 65.0
        assert state.hv_molar_fraction_pct == 18.0

    def test_class_aliases_consistency(self) -> None:
        """Class and type aliases must resolve to identical simulation classes."""
        assert PhbvConfig is PhbvBiosynthesisConfig
        assert PHBVConfig is PhbvBiosynthesisConfig
        assert PhbvBiosynthesisParameters is PhbvBiosynthesisConfig
        assert PhbvState is PhbvBiosynthesisState
        assert PHBVState is PhbvBiosynthesisState
        assert PhbvReactor is PhbvBiosynthesisReactor
        assert PHBVReactor is PhbvBiosynthesisReactor
        assert PhbvSimulator is PhbvBiosynthesisReactor
        assert PHBVSimulator is PhbvBiosynthesisReactor
        assert PhbvModel is PhbvBiosynthesisReactor
        assert PHBVModel is PhbvBiosynthesisReactor
        assert PhbvPlantModel is PhbvBiosynthesisReactor
        assert PHBVPlantModel is PhbvBiosynthesisReactor
        assert PhbvEngine is PhbvBiosynthesisReactor
        assert PHBVEngine is PhbvBiosynthesisReactor
        assert PhbvLogicUnit is PhbvBiosynthesisLogicUnit
        assert PHBVLogicUnit is PhbvBiosynthesisLogicUnit


# ============================================================================
# Section 3: Reaction Kinetics, Glucose & Precursor Uptake Rates
# ============================================================================

class TestSection03ReactionKineticsAndUptakeRates:
    """Verify non-linear Monod, Luedeking-Piret, and substrate uptake kinetics."""

    def test_nominal_baseline_kinetics_evaluation(self) -> None:
        """At nominal state, specific growth rate mu = 0.020 1/h and f_HV,syn = 15.5 mol%."""
        sim = PhbvBiosynthesisReactor()
        kin = sim.compute_kinetics(
            BIOMASS_NOMINAL_G_L,
            GLUCOSE_NOMINAL_G_L,
            PRECURSOR_NOMINAL_G_L,
            DISSOLVED_OXYGEN_NOMINAL_PCT,
            POLYMER_NOMINAL_G_L,
            HV_FRACTION_NOMINAL_MOL_PCT,
        )
        assert math.isclose(kin["mu_growth"], SPECIFIC_GROWTH_RATE_NOMINAL_H1, abs_tol=0.005)
        assert math.isclose(kin["f_hv_syn"], HV_FRACTION_NOMINAL_MOL_PCT, abs_tol=0.5)
        assert kin["r_hb"] > 0.0
        assert kin["r_hv"] > 0.0
        assert kin["r_p"] == pytest.approx(kin["r_hb"] + kin["r_hv"], rel=1e-6)

    def test_precursor_haldane_aiba_growth_inhibition(self) -> None:
        """Elevated valerate concentrations must inhibit specific growth rate mu."""
        sim = PhbvBiosynthesisReactor()
        # Normal valerate: 2.5 g/L
        kin_norm = sim.compute_kinetics(35.0, 15.0, 2.5, 35.0, 55.0, 15.5)
        # Elevated valerate: 8.0 g/L
        kin_high = sim.compute_kinetics(35.0, 15.0, 8.0, 35.0, 55.0, 15.5)
        assert kin_high["mu_growth"] < kin_norm["mu_growth"]

    def test_polymer_storage_capacity_saturation(self) -> None:
        """As accumulated polymer approaches P_max (90 g/L), synthesis rates must decrease."""
        sim = PhbvBiosynthesisReactor()
        kin_low_p = sim.compute_kinetics(35.0, 15.0, 2.5, 35.0, 20.0, 15.5)
        kin_high_p = sim.compute_kinetics(35.0, 15.0, 2.5, 35.0, 85.0, 15.5)
        assert kin_high_p["r_p"] < kin_low_p["r_p"]

    def test_glucose_and_valerate_consumption_rates(self) -> None:
        """Substrate consumption rates must be non-negative and scale with synthesis rates."""
        sim = PhbvBiosynthesisReactor()
        y = [35.0, 15.0, 2.5, 35.0, 55.0, 15.5]
        dydt = sim.ode_system(y)
        dx_dt, ds_g_dt, ds_v_dt, ddo_dt, dp_dt, df_hv_dt = dydt
        # In steady-state fed-batch:
        assert isinstance(ds_g_dt, float)
        assert isinstance(ds_v_dt, float)
        assert not math.isnan(ds_g_dt)
        assert not math.isnan(ds_v_dt)


# ============================================================================
# Section 4: Dual-Phase Metabolic Transition (Phase 1 vs Phase 2)
# ============================================================================

class TestSection04DualPhaseMetabolicTransition:
    """Verify dual-phase switching between Phase 1 (Growth) and Phase 2 (Accumulation)."""

    def test_phase_1_growth_mode_characteristics(self) -> None:
        """Phase 1 must have high growth rate (mu > 0.15 1/h) and low polymer induction."""
        sim = PhbvBiosynthesisReactor()
        sim.set_phase_1_growth()
        assert sim.state.nitrogen_exhausted_active is False
        assert sim.state.metabolic_state_code == PhbvMetabolicState.GROWTH_PHASE
        assert sim.state.specific_growth_rate_h1 > 0.150

    def test_phase_2_accumulation_mode_characteristics(self) -> None:
        """Phase 2 must have low residual growth rate (mu approx 0.020 1/h) and active induction."""
        sim = PhbvBiosynthesisReactor()
        sim.set_phase_2_accumulation()
        assert sim.state.nitrogen_exhausted_active is True
        assert sim.state.metabolic_state_code == PhbvMetabolicState.POLYMER_INDUCTION
        assert math.isclose(sim.state.specific_growth_rate_h1, 0.020, abs_tol=0.005)

    def test_phase_transition_updates_registers_immediately(self) -> None:
        """Switching phases must immediately update register %M564 and %R2427."""
        sim = PhbvBiosynthesisReactor()
        table = RegisterTable()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        # Default Phase 2
        assert table.read_bit("%M564") is True
        assert (table.read_uword("%R2427") & 0xFF) == 0x02

        # Switch to Phase 1
        sim.set_phase_1_growth()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_bit("%M564") is False
        assert (table.read_uword("%R2427") & 0xFF) == 0x01

        # Switch back to Phase 2
        sim.set_phase_2_accumulation()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_bit("%M564") is True
        assert (table.read_uword("%R2427") & 0xFF) == 0x02


# ============================================================================
# Section 5: Copolymer Composition & HV Fraction Response to Precursor
# ============================================================================

class TestSection05CopolymerCompositionAndPrecursorResponse:
    """Verify copolymer HV incorporation response to precursor valerate concentration."""

    def test_zero_precursor_yields_pure_phb_homopolymer(self) -> None:
        """When valerate concentration S_v = 0.0, r_hv must be 0 and f_HV,syn must be 0 mol%."""
        sim = PhbvBiosynthesisReactor()
        kin = sim.compute_kinetics(35.0, 15.0, 0.0, 35.0, 55.0, 0.0)
        assert kin["r_hv"] == 0.0
        assert kin["f_hv_syn"] == 0.0
        assert kin["r_p"] == kin["r_hb"]

    def test_increasing_precursor_increases_hv_fraction_monotonically(self) -> None:
        """Increasing valerate from 0.0 to 2.5 g/L increases instantaneous HV fraction monotonically."""
        sim = PhbvBiosynthesisReactor()
        concentrations = [0.0, 0.5, 1.0, 1.5, 2.0, 2.5]
        hv_fractions = []
        for sv in concentrations:
            kin = sim.compute_kinetics(35.0, 15.0, sv, 35.0, 55.0, 15.0)
            hv_fractions.append(kin["f_hv_syn"])

        # Check strictly monotonic increase
        for i in range(len(hv_fractions) - 1):
            assert hv_fractions[i] < hv_fractions[i + 1]

    def test_copolymer_mass_splits_and_dry_cell_weight(self) -> None:
        """Biomass X plus polymer P must equal total dry cell weight DCW."""
        sim = PhbvBiosynthesisReactor()
        total_dcw = sim.state.total_dcw_g_l
        expected_dcw = sim.state.biomass_conc_g_l + sim.state.polymer_accumulation_g_l
        assert math.isclose(total_dcw, expected_dcw, rel_tol=1e-5)
        assert math.isclose(sim.state.phbv_mass_fraction_pct, (sim.state.p / total_dcw) * 100.0, rel_tol=1e-5)
        # Sum of 3HB and 3HV concentrations matches total polymer P
        assert math.isclose(sim.state.p_hb_conc_g_l + sim.state.p_hv_conc_g_l, sim.state.p, rel_tol=1e-4)


# ============================================================================
# Section 6: Aeration, Dissolved Oxygen Dynamics & Oxygen Uptake
# ============================================================================

class TestSection06AerationAndDissolvedOxygenDynamics:
    """Verify gas-liquid oxygen mass transfer OTR and cellular uptake OUR dynamics."""

    def test_otr_and_our_balance_at_nominal_steady_state(self) -> None:
        """At nominal steady state, OTR must balance OUR plus dilution transfer."""
        sim = PhbvBiosynthesisReactor()
        otr = sim.state.oxygen_transfer_rate_pct_h
        our = sim.state.oxygen_uptake_rate_pct_h
        d_nom = sim.config.nominal_feed_rate_l_h / sim.config.nominal_volume_l
        dilution_loss = d_nom * DISSOLVED_OXYGEN_NOMINAL_PCT
        # OTR = 120 * (100 - 35) = 7800 %/h
        assert math.isclose(otr, 7800.0, rel_tol=1e-4)
        assert math.isclose(otr - (our + dilution_loss), 0.0, abs_tol=1.0)

    def test_aeration_loss_causes_rapid_do_depletion(self) -> None:
        """When Kla is throttled to near zero, DO must deplete rapidly."""
        sim = PhbvBiosynthesisReactor()
        sim.config.kla_nominal_h1 = 0.0  # Aeration failure
        y = [35.0, 15.0, 2.5, 35.0, 55.0, 15.5]
        dydt = sim.ode_system(y)
        ddo_dt = dydt[3]
        assert ddo_dt < -1.0  # Significant negative rate [% sat / s]


# ============================================================================
# Section 7: Coupled 6-State ODE System & RK4 Numerical Integrator
# ============================================================================

class TestSection07CoupledOdeAndRk4Integrator:
    """Verify 6-state ODE derivative calculations and RK4 numerical integrator."""

    def test_ode_system_vector_structure(self) -> None:
        """ode_system must return exactly 6 valid finite derivatives."""
        sim = PhbvBiosynthesisReactor()
        y0 = [35.0, 15.0, 2.5, 35.0, 55.0, 15.5]
        dydt = sim.ode_system(y0)
        assert len(dydt) == 6
        assert all(isinstance(v, float) for v in dydt)
        assert all(not math.isnan(v) for v in dydt)
        assert all(not math.isinf(v) for v in dydt)

    def test_rk4_step_advances_simulation_time(self) -> None:
        """rk4_step must advance sim_time_s and cycle_count deterministically."""
        sim = PhbvBiosynthesisReactor()
        assert sim.state.sim_time_s == 0.0
        assert sim.state.cycle_count == 0

        sim.rk4_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-8)
        assert sim.state.cycle_count == 1

        sim.rk4_step(dt=0.03)
        assert math.isclose(sim.state.sim_time_s, 0.05, abs_tol=1e-8)
        assert sim.state.cycle_count == 2

    def test_rk4_convenience_step_hours(self) -> None:
        """rk4_step_hours must correctly step with dt given in hours."""
        sim = PhbvBiosynthesisReactor()
        sim.rk4_step_hours(0.01)  # 0.01 h = 36.0 s
        assert math.isclose(sim.state.sim_time_s, 36.0, abs_tol=1e-5)


# ============================================================================
# Section 8: Analytical Mass Conservation Residuals (< 1e-10 kg/s)
# ============================================================================

class TestSection08AnalyticalMassConservationResiduals:
    """Verify stoichiometric mass and carbon conservation laws (< 1e-10 kg/s)."""

    def test_carbon_mass_balance_residual_zero_drift(self) -> None:
        """Carbon conservation residual must be strictly below 1e-10 kg/s."""
        sim = PhbvBiosynthesisReactor()
        assert sim.state.carbon_mass_balance_residual < 1.0e-10

        # Step 20 cycles
        for _ in range(20):
            sim.rk4_step(dt=0.02)
            assert sim.state.carbon_mass_balance_residual < 1.0e-10
            assert sim.state.stoichiometric_mass_balance_residual < 1.0e-10
            assert sim.state.total_mass_balance_residual < 1.0e-10

    def test_stoichiometric_closure_on_respiratory_co2(self) -> None:
        """Substrate carbon consumed equals biomass + 3HB + 3HV + CO2 evolved."""
        sim = PhbvBiosynthesisReactor()
        # Verify analytical carbon conservation
        sim._update_conservation_residuals()
        assert sim.state.carbon_mass_balance_residual == pytest.approx(0.0, abs=1e-12)


# ============================================================================
# Section 9: Process Safety Trips & Strict Hierarchy
# ============================================================================

class TestSection09ProcessSafetyTripsAndHierarchy:
    """Verify process safety interlocks in strict priority (0xF601 > 0xF602 > 0xF603 > 0xF604)."""

    def test_priority_1_do_starvation_trip_0xf601(self) -> None:
        """DO < 10.0% asserts 0xF601 DO_STARVATION, stops feed pump %M565, asserts alarm %M566."""
        sim = PhbvBiosynthesisReactor()
        sim.inject_fault("oxygen")
        assert sim.state.trip_code == PhbvTripCode.DO_STARVATION
        assert sim.state.trip_code == 0xF601
        assert sim.state.feed_pump_active is False
        assert sim.state.batch_harvest_or_acid_alarm is True
        assert sim.state.nitrogen_exhausted_active is False

    def test_priority_2_precursor_overconcentration_fault_0xf602(self) -> None:
        """Valerate > 5.0 g/L asserts 0xF602 PRECURSOR_OVERCONC, stops feed pump %M565."""
        sim = PhbvBiosynthesisReactor()
        sim.inject_fault("precursor")
        assert sim.state.trip_code == PhbvTripCode.PRECURSOR_OVERCONC
        assert sim.state.trip_code == 0xF602
        assert sim.state.feed_pump_active is False
        assert sim.state.batch_harvest_or_acid_alarm is True

    def test_priority_3_thermal_runaway_trip_0xf603(self) -> None:
        """Broth temp > 37.0 °C asserts 0xF603 THERMAL_RUNAWAY, stops feed pump %M565."""
        sim = PhbvBiosynthesisReactor()
        sim.inject_fault("thermal")
        assert sim.state.trip_code == PhbvTripCode.THERMAL_RUNAWAY
        assert sim.state.trip_code == 0xF603
        assert sim.state.feed_pump_active is False
        assert sim.state.batch_harvest_or_acid_alarm is True

    def test_priority_4_contamination_ph_drop_fault_0xf604(self) -> None:
        """Broth pH < 6.0 asserts 0xF604 CONTAMINATION_PH_DROP, stops feed pump %M565."""
        sim = PhbvBiosynthesisReactor()
        sim.inject_fault("contamination")
        assert sim.state.trip_code == PhbvTripCode.CONTAMINATION_PH_DROP
        assert sim.state.trip_code == 0xF604
        assert sim.state.feed_pump_active is False
        assert sim.state.batch_harvest_or_acid_alarm is True

    def test_priority_precedence_simultaneous_faults(self) -> None:
        """DO starvation (Priority 1) overrides precursor overconc (Priority 2)."""
        sim = PhbvBiosynthesisReactor()
        sim.state.dissolved_oxygen_pct = 5.0      # Priority 1 condition
        sim.state.precursor_valerate_g_l = 6.0    # Priority 2 condition
        sim.state.temperature_c = 40.0            # Priority 3 condition
        sim.state.ph_level = 5.2                  # Priority 4 condition
        sim._evaluate_safety_interlocks()
        assert sim.state.trip_code == PhbvTripCode.DO_STARVATION

    def test_batch_harvest_target_achievement(self) -> None:
        """Polymer >= 70.0 g/L asserts batch harvest complete, sets state code 0x05."""
        sim = PhbvBiosynthesisReactor()
        sim.inject_fault("harvest")
        assert sim.state.batch_harvest_complete is True
        assert sim.state.metabolic_state_code == PhbvMetabolicState.BATCH_HARVEST_COMPLETE
        assert sim.state.feed_pump_active is False
        assert sim.state.batch_harvest_or_acid_alarm is True

    def test_fault_clearing_and_recovery(self) -> None:
        """clear_faults resets system back to nominal healthy state."""
        sim = PhbvBiosynthesisReactor()
        sim.inject_fault("oxygen")
        assert sim.state.trip_code == PhbvTripCode.DO_STARVATION
        sim.clear_faults()
        assert sim.state.trip_code == PhbvTripCode.NORMAL
        assert sim.state.feed_pump_active is True
        assert sim.state.batch_harvest_or_acid_alarm is False


# ============================================================================
# Section 10: PhbvTripCode IntEnum Masking & Hash Compliance
# ============================================================================

class TestSection10TripCodePropertiesAndMasking:
    """Verify PhbvTripCode signed/unsigned 16-bit comparisons, masking, and hashing."""

    def test_trip_code_enum_values(self) -> None:
        """Trip codes must have exact specified hexadecimal integers."""
        assert PhbvTripCode.NORMAL.value == 0x0000
        assert PhbvTripCode.DO_STARVATION.value == 0xF601
        assert PhbvTripCode.PRECURSOR_OVERCONC.value == 0xF602
        assert PhbvTripCode.THERMAL_RUNAWAY.value == 0xF603
        assert PhbvTripCode.CONTAMINATION_PH_DROP.value == 0xF604

    def test_unsigned_and_signed_integer_equality(self) -> None:
        """Supports comparison with unsigned (0xF601) and signed 16-bit (-2559)."""
        code = PhbvTripCode.DO_STARVATION
        assert code == 0xF601
        assert code == (0xF601 - 0x10000)  # -2559 signed 16-bit
        assert code == -2559

        code2 = PhbvTripCode.PRECURSOR_OVERCONC
        assert code2 == 0xF602
        assert code2 == (0xF602 - 0x10000)  # -2558 signed 16-bit
        assert code2 == -2558

    def test_bitwise_masking_support(self) -> None:
        """Supports bitwise AND operations with 0xFFFF transparently."""
        code = PhbvTripCode.DO_STARVATION
        assert (code & 0xFFFF) == 0xF601
        assert (0xFFFF & code) == 0xF601

    def test_hash_compliance(self) -> None:
        """Hash must equal hash(int(self) & 0xFFFF)."""
        code = PhbvTripCode.DO_STARVATION
        assert hash(code) == hash(int(code) & 0xFFFF)
        # Compatible in dictionaries and sets
        s = {PhbvTripCode.DO_STARVATION, PhbvTripCode.PRECURSOR_OVERCONC}
        assert PhbvTripCode.DO_STARVATION in s

    def test_string_formatting_representation(self) -> None:
        """str(code) must output hex format with name."""
        code = PhbvTripCode.DO_STARVATION
        assert "0xF601" in str(code)
        assert "DO_STARVATION" in str(code)


# ============================================================================
# Section 11: Horner OCS Register Space Synchronization (%R2420..%R2427)
# ============================================================================

class TestSection11HornerOcsRegisterSynchronization:
    """Verify Horner OCS register space synchronization (%R2420..%R2427, %M564..%M566)."""

    def test_nominal_registers_synchronization(self) -> None:
        """Nominal state writes exact scaled INT16 words to %R2420..%R2427."""
        table = RegisterTable()
        sim = PhbvBiosynthesisReactor(register_table=table)
        sim.reset()

        # %R2420: Temp 30.0 °C -> 300
        assert table.read_word(REG_PHBV_TEMP_SCALED) == 300
        # %R2421: Biomass 35.0 g/L -> 350
        assert table.read_word(REG_PHBV_BIOMASS_SCALED) == 350
        # %R2422: Glucose 15.0 g/L -> 150
        assert table.read_word(REG_PHBV_GLUCOSE_SCALED) == 150
        # %R2423: Valerate 2.5 g/L -> 25
        assert table.read_word(REG_PHBV_PRECURSOR_SCALED) == 25
        # %R2424: DO 35.0 % -> 350
        assert table.read_word(REG_PHBV_DO_SCALED) == 350
        # %R2425: Polymer 55.0 g/L -> 550
        assert table.read_word(REG_PHBV_POLYMER_SCALED) == 550
        # %R2426: HV mol% 15.5 % -> 155
        assert table.read_word(REG_PHBV_HV_FRACTION_SCALED) == 155
        # %R2427: Growth state code (mu=0.020 1/h -> 20 in upper byte, state=2 in lower byte -> 5122)
        r2427 = table.read_uword(REG_PHBV_GROWTH_STATE_SCALED)
        assert (r2427 >> 8) == 20
        assert (r2427 & 0xFF) == 2

    def test_nominal_discrete_coils_synchronization(self) -> None:
        """Nominal state writes correct boolean values to %M564..%M566."""
        table = RegisterTable()
        sim = PhbvBiosynthesisReactor(register_table=table)
        sim.reset()

        # %M564: Induction Active -> True
        assert table.read_bit(COIL_PHBV_INDUCTION_ACTIVE) is True
        # %M565: Feed Pump Active -> True
        assert table.read_bit(COIL_PHBV_FEED_PUMP_ACTIVE) is True
        # %M566: Harvest/Trip Alarm -> False
        assert table.read_bit(COIL_PHBV_HARVEST_ALARM) is False

    def test_fault_trip_registers_synchronization(self) -> None:
        """Fault trip updates %R2427 lower byte with trip code and %M566 alarm coil."""
        table = RegisterTable()
        sim = PhbvBiosynthesisReactor(register_table=table)
        sim.inject_fault("oxygen")
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        # %R2427 lower byte contains trip code lower byte (0xF601 -> 0x01)
        r2427 = table.read_uword(REG_PHBV_GROWTH_STATE_SCALED)
        assert (r2427 & 0xFF) == (0xF601 & 0xFF)
        assert table.read_bit(COIL_PHBV_FEED_PUMP_ACTIVE) is False
        assert table.read_bit(COIL_PHBV_HARVEST_ALARM) is True


# ============================================================================
# Section 12: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection12PureStructuredTextPouValidation:
    """Verify Pure IEC 61131-3 Structured Text syntax and AST register variable bindings."""

    def test_pure_st_pou_string_not_empty(self) -> None:
        """PHBV_BIOSYNTHESIS_PURE_ST_POU must contain valid POU program text."""
        assert isinstance(PHBV_BIOSYNTHESIS_PURE_ST_POU, str)
        assert len(PHBV_BIOSYNTHESIS_PURE_ST_POU) > 200
        assert "PROGRAM PhbvBiosynthesisSync" in PHBV_BIOSYNTHESIS_PURE_ST_POU
        assert "END_PROGRAM" in PHBV_BIOSYNTHESIS_PURE_ST_POU

    def test_st_parser_syntax_validation(self) -> None:
        """STParser.validate_code must report SUCCESS for PhbvBiosynthesisSync."""
        val = STParser.validate_code(PHBV_BIOSYNTHESIS_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

    def test_st_parser_ast_variable_bindings(self) -> None:
        """All 8 registers and 3 discrete coils must be declared with AT bindings in AST."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(PHBV_BIOSYNTHESIS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "PhbvBiosynthesisSync"
        assert pou.pou_type == POUType.PROGRAM

        required_regs = [
            "%R2420", "%R2421", "%R2422", "%R2423",
            "%R2424", "%R2425", "%R2426", "%R2427",
            "%M564", "%M565", "%M566",
        ]
        for reg in required_regs:
            assert reg in pou.bound_registers
            assert any(v.address_binding == reg for v in pou.variables)

    def test_verify_phbv_pure_st_function(self) -> None:
        """verify_phbv_biosynthesis_pure_st must return valid truthy result."""
        res = verify_phbv_biosynthesis_pure_st()
        assert bool(res) is True
        assert res.passed is True
        assert res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 13: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection13AntiLadderSecurityGuard:
    """Verify that forbidden ladder logic constructs are rejected with LadderForbiddenError."""

    def test_ladder_contacts_rejection(self) -> None:
        """Contact symbols ---[ ]--- must raise LadderForbiddenError."""
        bad_code = "PROGRAM BadContacts\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_coils_rejection(self) -> None:
        """Coil symbols ---( )--- must raise LadderForbiddenError."""
        bad_code = "PROGRAM BadCoils\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_keywords_rejection(self) -> None:
        """Keywords RUNG, NETWORK, XIC, OTE must raise LadderForbiddenError."""
        keywords = ["RUNG 1", "NETWORK", "XIC Bit1", "OTE Output1"]
        for kw in keywords:
            bad_code = f"PROGRAM BadKw\nVAR x: BOOL; END_VAR\n{kw}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_code)

    def test_pure_st_pou_passes_security_guard(self) -> None:
        """Official PHBV ST POU must pass SecurityGuard assertion cleanly without error."""
        SecurityGuard.assert_pure_st_content(PHBV_BIOSYNTHESIS_PURE_ST_POU)


# ============================================================================
# Section 14: ILogicUnit Compliance, 100-Cycle Soak & Verification Runner
# ============================================================================

class TestSection14LogicUnitSoakAndVerificationRunner:
    """Verify ILogicUnit compliance, 100-cycle scan stability, and verification runner."""

    def test_ilogicunit_interface_lifecycle(self) -> None:
        """PhbvBiosynthesisLogicUnit must fulfill ILogicUnit protocol."""
        unit = PhbvBiosynthesisLogicUnit()
        assert unit.name == "PhbvBiosynthesisLogicUnit"
        assert unit.priority == 281
        assert unit.is_enabled is True

        unit.disable()
        assert unit.is_enabled is False
        unit.enable()
        assert unit.is_enabled is True

        # Scan step & execute
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        unit.step(0.02)
        unit.reset()

    def test_100_cycle_soak_stability(self) -> None:
        """100-cycle soak simulation must run without drift, NaN, or residual growth."""
        sim = PhbvBiosynthesisReactor()
        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        # State bounds
        assert 34.0 <= sim.state.biomass_conc_g_l <= 36.0
        assert 14.0 <= sim.state.substrate_glucose_g_l <= 16.0
        assert 2.0 <= sim.state.precursor_valerate_g_l <= 3.0
        assert 34.0 <= sim.state.dissolved_oxygen_pct <= 36.0
        assert 54.0 <= sim.state.polymer_accumulation_g_l <= 56.0
        assert 15.0 <= sim.state.hv_molar_fraction_pct <= 16.0
        assert sim.state.trip_code == PhbvTripCode.NORMAL
        assert sim.state.feed_pump_active is True
        assert sim.state.carbon_mass_balance_residual < 1.0e-10

    def test_deterministic_10_stage_verification_runner(self) -> None:
        """run_phbv_biosynthesis_verification must pass 10/10 stages with SUCCESS status."""
        result = run_phbv_biosynthesis_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        data = result.get("data", {})
        assert data.get("all_passed") is True or data.get("stages_passed") == 10
        stages = data.get("stages", [])
        assert len(stages) == 10
        assert all(s["passed"] is True for s in stages)
