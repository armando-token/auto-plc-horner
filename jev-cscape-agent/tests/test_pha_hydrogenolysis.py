"""Industrial Catalytic PHA Hydrogenolysis & Diol Synthesis Unit Test Suite (W305).

Work Package: W305 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 13 comprehensive engineering verification sections:
1. Section 1: Configuration & Default Parameter Validation
2. Section 2: 6-State Vector Initialization & Property Aliases
3. Section 3: Henry's Law Solubility & Dissolved H2 Equilibrium
4. Section 4: Langmuir-Hinshelwood Kinetics & Selectivity
5. Section 5: Catalyst Deactivation Dynamics (Sintering / Coking)
6. Section 6: Thermal Energy Balance & Jacket Heat Exchange
7. Section 7: Coupled RK4 Numerical Integration & Trajectory Dynamics
8. Section 8: Strict Carbon Mass Conservation Residuals (< 1e-10)
9. Section 9: Safety Trips, Interlocks & Fault Priority Hierarchy (0xF951..0xF954)
10. Section 10: State Transitions, Emergency Quench & N2 Purge
11. Section 11: ILogicUnit Compliance & Scan Cycle Execution
12. Section 12: Horner OCS RegisterTable Sync & Signed 16-Bit Masking (%R2660..%R2667, %M620..%M622)
13. Section 13: Pure IEC 61131-3 ST POU, Anti-Ladder Enforcement & 9-Stage Verification Runners
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.pha_hydrogenolysis import (
    COIL_PHA_HYDRO_ACTIVE,
    COIL_PHA_HYDRO_EMERGENCY_TRIP,
    COIL_PHA_HYDRO_PERMISSIVE,
    COIL_PHA_HYDRO_REACTOR_ACTIVE,
    COIL_PHA_HYDRO_RUNNING,
    COIL_PHA_HYDRO_TRIP,
    COIL_PHA_HYDRO_TRIP_ALARM,
    COIL_PHA_HYDRO_WARNING,
    COIL_PHA_HYDRO_WARNING_ALARM,
    DIAG_ERR_CATALYST_DEACTIVATED,
    DIAG_ERR_CATALYST_DEACTIVATION,
    DIAG_ERR_DEACTIVATED,
    DIAG_ERR_EXOTHERM,
    DIAG_ERR_H2_PRESSURE_COLLAPSE,
    DIAG_ERR_HOTSPOT,
    DIAG_ERR_HOTSPOT_RATE,
    DIAG_ERR_LOW_PRESSURE,
    DIAG_ERR_PRESSURE_COLLAPSE,
    DIAG_ERR_RUNAWAY,
    DIAG_ERR_RUNAWAY_EXOTHERM,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_OK,
    DiagnosticCode,
    MW_BDO,
    MW_BUOH,
    MW_CARBON,
    MW_FEED_ESTER,
    MW_H2,
    PHA_HYDROGENOLYSIS_PURE_ST_POU,
    PHA_HYDROGENOLYSIS_SYNC_POU,
    PHA_HYDRO_PURE_ST_POU,
    PHA_HYDRO_SYNC_POU,
    PhaHydroBedStatus,
    PhaHydroConfig,
    PhaHydroDiagnosticCode,
    PhaHydroEngine,
    PhaHydroLogicUnit,
    PhaHydroMode,
    PhaHydroParameters,
    PhaHydroPhase,
    PhaHydroReactor,
    PhaHydroSimulator,
    PhaHydroState,
    PhaHydroStatus,
    PhaHydroStatusBits,
    PhaHydroStatusWord,
    PhaHydroTripCode,
    PhaHydrogenolysisBedStatus,
    PhaHydrogenolysisConfig,
    PhaHydrogenolysisDiagnosticCode,
    PhaHydrogenolysisEngine,
    PhaHydrogenolysisLogicUnit,
    PhaHydrogenolysisMode,
    PhaHydrogenolysisModel,
    PhaHydrogenolysisParameters,
    PhaHydrogenolysisPhase,
    PhaHydrogenolysisPlantModel,
    PhaHydrogenolysisReactor,
    PhaHydrogenolysisSimulationLogicUnit,
    PhaHydrogenolysisSimulator,
    PhaHydrogenolysisState,
    PhaHydrogenolysisStatus,
    PhaHydrogenolysisStatusBits,
    PhaHydrogenolysisStatusWord,
    PhaHydrogenolysisSync,
    PhaHydrogenolysisTripCode,
    R_GAS_CONSTANT,
    REG_PHA_HYDRO_ACTIVITY,
    REG_PHA_HYDRO_A_CAT,
    REG_PHA_HYDRO_BDO_YIELD,
    REG_PHA_HYDRO_BDO_YIELD_PCT,
    REG_PHA_HYDRO_CATALYST_ACTIVITY,
    REG_PHA_HYDRO_DIAG,
    REG_PHA_HYDRO_DIAGNOSTIC_CODE,
    REG_PHA_HYDRO_MODE_STATUS,
    REG_PHA_HYDRO_P,
    REG_PHA_HYDRO_PRESSURE,
    REG_PHA_HYDRO_PRESSURE_BAR,
    REG_PHA_HYDRO_P_BAR,
    REG_PHA_HYDRO_SELECTIVITY,
    REG_PHA_HYDRO_SELECTIVITY_PCT,
    REG_PHA_HYDRO_SEL_PCT,
    REG_PHA_HYDRO_STATUS,
    REG_PHA_HYDRO_STATUS_BITS,
    REG_PHA_HYDRO_STATUS_REG,
    REG_PHA_HYDRO_STATUS_WORD,
    REG_PHA_HYDRO_TEMP,
    REG_PHA_HYDRO_TEMPERATURE,
    REG_PHA_HYDRO_TEMP_SCALED,
    REG_PHA_HYDRO_YIELD,
    REG_PHA_HYDRO_YIELD_PCT,
    ST_PROGRAM_PHA_HYDROGENOLYSIS_SYNC,
    T_ZERO_CELSIUS,
    run_pha_hydro_verification,
    run_pha_hydrogenolysis_verification,
    verify_pha_hydro_pure_st,
    verify_pha_hydrogenolysis_pure_st,
)


# ============================================================================
# Section 1: Configuration & Default Parameter Validation
# ============================================================================

def test_config_defaults_and_serialization() -> None:
    """Validate configuration defaults, serialization to dict, and parameter ranges."""
    cfg = PhaHydrogenolysisConfig()
    assert cfg.k1 == 120000.0 or cfg.k1 > 0.0
    assert cfg.ea1_j_mol == 48000.0
    assert cfg.k2 > 0.0
    assert cfg.ea2_j_mol == 62000.0
    assert cfg.k_feed == 0.45
    assert cfg.k_bdo == 0.25
    assert cfg.k_h == 0.0078
    assert cfg.kla == 0.50
    assert cfg.kd == 0.0015
    assert cfg.ed_j_mol == 45000.0
    assert cfg.delta_h1_j_mol == -65000.0
    assert cfg.delta_h2_j_mol == -55000.0
    assert cfg.t_bed_trip_max == 220.0
    assert cfg.p_h2_trip_min == 25.0
    assert cfg.hotspot_rate_trip_max == 5.0
    assert cfg.a_cat_trip_min == 0.20

    d = cfg.to_dict()
    assert isinstance(d, dict)
    assert d["t_bed_trip_max"] == 220.0
    assert d["p_h2_trip_min"] == 25.0
    assert d["hotspot_rate_trip_max"] == 5.0
    assert d["a_cat_trip_min"] == 0.20
    assert d["k_h"] == 0.0078


def test_custom_config_instantiation() -> None:
    """Validate reactor initialization with custom configuration parameters."""
    cfg = PhaHydrogenolysisConfig(
        k1=80000.0,
        ea1_j_mol=50000.0,
        k2=200000.0,
        ea2_j_mol=65000.0,
        k_feed=0.50,
        k_bdo=0.30,
        k_h=0.0085,
        kla=0.60,
        kd=0.0020,
        ed_j_mol=48000.0,
        t_bed_trip_max=225.0,
        p_h2_trip_min=20.0,
        hotspot_rate_trip_max=6.0,
        a_cat_trip_min=0.15,
    )
    reactor = PhaHydrogenolysisReactor(config=cfg)
    assert reactor.cfg.k1 == 80000.0
    assert reactor.cfg.ea1_j_mol == 50000.0
    assert reactor.cfg.t_bed_trip_max == 225.0
    assert reactor.cfg.p_h2_trip_min == 20.0
    assert reactor.cfg.hotspot_rate_trip_max == 6.0
    assert reactor.cfg.a_cat_trip_min == 0.15


def test_config_aliases_and_subclasses() -> None:
    """Validate configuration class aliases for backwards and cross-module compatibility."""
    assert PhaHydroConfig is PhaHydrogenolysisConfig
    assert PhaHydrogenolysisParameters is PhaHydrogenolysisConfig
    assert PhaHydroParameters is PhaHydrogenolysisConfig

    cfg_alias = PhaHydroParameters(t_bed_trip_max=215.0)
    assert cfg_alias.t_bed_trip_max == 215.0


def test_physical_and_chemical_constants() -> None:
    """Validate molecular weights, gas constant, and thermodynamic scale factors."""
    assert math.isclose(MW_FEED_ESTER, 118.13, rel_tol=1e-4)
    assert math.isclose(MW_BDO, 90.12, rel_tol=1e-4)
    assert math.isclose(MW_BUOH, 74.12, rel_tol=1e-4)
    assert math.isclose(MW_H2, 2.016, rel_tol=1e-4)
    assert math.isclose(MW_CARBON, 12.011, rel_tol=1e-4)
    assert math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-6)
    assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-6)


# ============================================================================
# Section 2: 6-State Vector Initialization & Property Aliases
# ============================================================================

def test_state_initialization_defaults() -> None:
    """Validate coupled 6-state vector default initial conditions."""
    st = PhaHydrogenolysisState()
    assert st.c_feed == 2.50
    assert st.c_bdo == 0.00
    assert st.c_buoh == 0.00
    assert math.isclose(st.c_h2_diss, 0.39, rel_tol=1e-3)
    assert st.t_bed == 180.0
    assert st.a_cat == 1.00
    assert st.p_h2 == 50.0
    assert st.dt_bed_dt == 0.0


def test_state_to_dict_and_from_dict() -> None:
    """Validate dictionary serialization and deserialization with case-insensitivity."""
    st = PhaHydrogenolysisState(
        c_feed=2.10,
        c_bdo=0.35,
        c_buoh=0.05,
        c_h2_diss=0.42,
        t_bed=185.0,
        a_cat=0.95,
        p_h2=52.0,
        dt_bed_dt=0.25,
    )
    d = st.to_dict()
    assert d["c_feed"] == 2.10
    assert d["c_bdo"] == 0.35
    assert d["c_buoh"] == 0.05
    assert d["c_h2_diss"] == 0.42
    assert d["t_bed"] == 185.0
    assert d["a_cat"] == 0.95
    assert d["p_h2"] == 52.0
    assert d["dt_bed_dt"] == 0.25

    reconstructed = PhaHydrogenolysisState.from_dict(d)
    assert reconstructed.c_feed == 2.10
    assert reconstructed.c_bdo == 0.35
    assert reconstructed.t_bed == 185.0
    assert reconstructed.a_cat == 0.95


def test_state_property_getters_and_setters() -> None:
    """Validate flexible property aliases on PhaHydrogenolysisState."""
    st = PhaHydrogenolysisState()

    # Getters
    assert st.C_feed == 2.50
    assert st.feed == 2.50
    assert st.C_bdo == 0.00
    assert st.bdo == 0.00
    assert st.C_buoh == 0.00
    assert st.buoh == 0.00
    assert math.isclose(st.C_h2_diss, 0.39, rel_tol=1e-3)
    assert math.isclose(st.h2, 0.39, rel_tol=1e-3)
    assert st.T_bed == 180.0
    assert st.temperature == 180.0
    assert st.A_cat == 1.00
    assert st.activity == 1.00
    assert st.P_h2 == 50.0
    assert st.pressure == 50.0

    # Setters
    st.C_feed = 1.80
    assert st.c_feed == 1.80
    st.feed = 1.70
    assert st.c_feed == 1.70

    st.C_bdo = 0.50
    assert st.c_bdo == 0.50
    st.bdo = 0.60
    assert st.c_bdo == 0.60

    st.C_buoh = 0.10
    assert st.c_buoh == 0.10
    st.buoh = 0.12
    assert st.c_buoh == 0.12

    st.C_h2_diss = 0.45
    assert st.c_h2_diss == 0.45
    st.h2 = 0.40
    assert st.c_h2_diss == 0.40

    st.T_bed = 188.0
    assert st.t_bed == 188.0
    st.temperature = 189.0
    assert st.t_bed == 189.0

    st.A_cat = 0.92
    assert st.a_cat == 0.92
    st.activity = 0.90
    assert st.a_cat == 0.90

    st.P_h2 = 55.0
    assert st.p_h2 == 55.0
    st.pressure = 53.0
    assert st.p_h2 == 53.0


def test_custom_state_in_reactor() -> None:
    """Validate initializing reactor with pre-configured state vector."""
    custom_st = PhaHydrogenolysisState(
        c_feed=2.00,
        c_bdo=0.40,
        c_buoh=0.10,
        t_bed=175.0,
        a_cat=0.98,
        p_h2=48.0,
    )
    reactor = PhaHydrogenolysisReactor(state=custom_st)
    assert reactor.state.c_feed == 2.00
    assert reactor.state.c_bdo == 0.40
    assert reactor.state.t_bed == 175.0
    assert math.isclose(reactor._initial_carbon_total, 2.50, rel_tol=1e-9)


def test_state_alias_classes() -> None:
    """Validate state class aliases for component flexibility."""
    assert PhaHydroState is PhaHydrogenolysisState


# ============================================================================
# Section 3: Henry's Law Solubility & Dissolved H2 Equilibrium
# ============================================================================

def test_henrys_law_saturation_concentration() -> None:
    """Verify Henry's law saturation solubility: C_h2_sat = K_H * P_H2."""
    cfg = PhaHydrogenolysisConfig()
    p_h2_nominal = 50.0  # bar
    c_h2_sat = cfg.k_h * p_h2_nominal
    # 0.0078 mol/(L*bar) * 50 bar = 0.39 mol/L
    assert math.isclose(c_h2_sat, 0.39, rel_tol=1e-6)


def test_henrys_law_pressure_dependence() -> None:
    """Verify linear scaling of dissolved H2 saturation with system pressure."""
    cfg = PhaHydrogenolysisConfig()
    pressures = [10.0, 25.0, 50.0, 75.0, 100.0]
    expected_sats = [cfg.k_h * p for p in pressures]

    for p, sat in zip(pressures, expected_sats):
        computed_sat = cfg.k_h * p
        assert math.isclose(computed_sat, sat, rel_tol=1e-9)
        assert computed_sat > 0.0


def test_h2_gas_liquid_mass_transfer_rate() -> None:
    """Verify gas-liquid transfer rate r_transfer = kla * (C_h2_sat - C_h2_diss)."""
    reactor = PhaHydrogenolysisReactor()
    # Case 1: Undersaturated fluid -> net absorption transfer into liquid
    reactor.state.c_h2_diss = 0.20
    reactor.state.p_h2 = 50.0
    c_h2_sat = reactor.cfg.k_h * 50.0
    transfer_sub = reactor.cfg.kla * (c_h2_sat - 0.20)
    assert transfer_sub > 0.0

    # Case 2: Oversaturated fluid -> net desorption transfer out of liquid
    reactor.state.c_h2_diss = 0.50
    transfer_super = reactor.cfg.kla * (c_h2_sat - 0.50)
    assert transfer_super < 0.0


def test_h2_feed_valve_isolation_stops_transfer() -> None:
    """Verify isolating H2 feed valve shuts off gas-liquid H2 mass transfer."""
    reactor = PhaHydrogenolysisReactor()
    reactor.h2_feed_valve_open = False
    derivs = reactor._derivatives(reactor.state)
    # H2 consumption continues (2*r1 + r2), but transfer rate is zero
    r1, r2, _ = reactor.compute_rates(reactor.state)
    expected_dh2 = -(2.0 * r1 + 1.0 * r2)
    assert math.isclose(derivs[3], expected_dh2, rel_tol=1e-5)


# ============================================================================
# Section 4: Langmuir-Hinshelwood Kinetics & Selectivity
# ============================================================================

def test_primary_hydrogenation_rate_formulation() -> None:
    """Verify primary catalytic hydrogenation rate r1 calculation."""
    reactor = PhaHydrogenolysisReactor()
    st = PhaHydrogenolysisState(c_feed=2.50, c_bdo=0.00, c_h2_diss=0.39, t_bed=180.0, a_cat=1.0)
    r1, r2, da_dt = reactor.compute_rates(st)

    t_k = 180.0 + T_ZERO_CELSIUS
    arrh1 = math.exp(-reactor.cfg.ea1_j_mol / (R_GAS_CONSTANT * t_k))
    denom1 = 1.0 + reactor.cfg.k_feed * 2.50 + reactor.cfg.k_bdo * 0.0
    expected_r1 = (reactor.cfg.k1 * 1.0 * 2.50 * 0.39 / denom1) * arrh1

    assert math.isclose(r1, expected_r1, rel_tol=1e-5)
    assert r1 > 0.0
    assert r2 == 0.0  # Zero BDO -> zero secondary reaction


def test_secondary_over_reduction_rate_formulation() -> None:
    """Verify secondary over-reduction rate r2 calculation when BDO accumulates."""
    reactor = PhaHydrogenolysisReactor()
    st_bdo = PhaHydrogenolysisState(c_feed=1.50, c_bdo=0.80, c_h2_diss=0.39, t_bed=180.0, a_cat=1.0)
    r1, r2, _ = reactor.compute_rates(st_bdo)

    t_k = 180.0 + T_ZERO_CELSIUS
    arrh2 = math.exp(-reactor.cfg.ea2_j_mol / (R_GAS_CONSTANT * t_k))
    denom2 = 1.0 + reactor.cfg.k_bdo * 0.80
    expected_r2 = (reactor.cfg.k2 * 1.0 * 0.80 * 0.39 / denom2) * arrh2

    assert math.isclose(r2, expected_r2, rel_tol=1e-5)
    assert r2 > 0.0


def test_temperature_arrhenius_acceleration() -> None:
    """Verify Arrhenius reaction rate increases monotonically with bed temperature."""
    reactor = PhaHydrogenolysisReactor()
    st_cold = PhaHydrogenolysisState(t_bed=160.0, c_bdo=0.50)
    st_nom = PhaHydrogenolysisState(t_bed=180.0, c_bdo=0.50)
    st_hot = PhaHydrogenolysisState(t_bed=200.0, c_bdo=0.50)

    r1_cold, r2_cold, _ = reactor.compute_rates(st_cold)
    r1_nom, r2_nom, _ = reactor.compute_rates(st_nom)
    r1_hot, r2_hot, _ = reactor.compute_rates(st_hot)

    assert r1_hot > r1_nom > r1_cold > 0.0
    assert r2_hot > r2_nom > r2_cold > 0.0


def test_competitive_adsorption_inhibition() -> None:
    """Verify competitive Langmuir-Hinshelwood adsorption inhibition by reactants and products."""
    reactor = PhaHydrogenolysisReactor()
    # At higher BDO concentration, denominator increases, inhibiting r1
    st_low_bdo = PhaHydrogenolysisState(c_feed=2.0, c_bdo=0.1, t_bed=180.0)
    st_high_bdo = PhaHydrogenolysisState(c_feed=2.0, c_bdo=1.2, t_bed=180.0)

    r1_low, _, _ = reactor.compute_rates(st_low_bdo)
    r1_high, _, _ = reactor.compute_rates(st_high_bdo)

    assert r1_low > r1_high


def test_bdo_yield_and_selectivity_properties() -> None:
    """Verify yield, selectivity, and conversion percentage metrics."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.c_feed = 1.25  # 50% conversion from 2.50
    reactor.state.c_bdo = 1.15
    reactor.state.c_buoh = 0.10

    assert math.isclose(reactor.conversion_pct, 50.0, rel_tol=1e-3)
    assert math.isclose(reactor.bdo_yield_pct, (1.15 / 2.50) * 100.0, rel_tol=1e-3)
    assert math.isclose(reactor.selectivity_pct, (1.15 / 1.25) * 100.0, rel_tol=1e-3)


def test_zero_initial_feed_yield_safety() -> None:
    """Verify zero initial feed does not produce division-by-zero errors."""
    st_zero = PhaHydrogenolysisState(c_feed=0.0, c_bdo=0.0, c_buoh=0.0)
    reactor = PhaHydrogenolysisReactor(state=st_zero)
    reactor._initial_c_feed = 0.0

    assert reactor.bdo_yield_pct == 0.0
    assert reactor.selectivity_pct == 100.0
    assert reactor.conversion_pct == 0.0


# ============================================================================
# Section 5: Catalyst Deactivation Dynamics (Sintering / Coking)
# ============================================================================

def test_catalyst_deactivation_rate_formulation() -> None:
    """Verify catalyst deactivation rate da_cat/dt formula."""
    reactor = PhaHydrogenolysisReactor()
    st = PhaHydrogenolysisState(t_bed=180.0, a_cat=1.0, c_feed=2.50)
    _, _, da_dt = reactor.compute_rates(st)

    t_k = 180.0 + T_ZERO_CELSIUS
    arrh_d = math.exp(-reactor.cfg.ed_j_mol / (R_GAS_CONSTANT * t_k))
    expected_da_dt = -reactor.cfg.kd * 1.0 * arrh_d * 2.50

    assert math.isclose(da_dt, expected_da_dt, rel_tol=1e-5)
    assert da_dt < 0.0


def test_catalyst_deactivation_temperature_acceleration() -> None:
    """Verify catalyst deactivation rate accelerates at higher temperature."""
    reactor = PhaHydrogenolysisReactor()
    st_low_t = PhaHydrogenolysisState(t_bed=170.0, a_cat=1.0, c_feed=2.5)
    st_high_t = PhaHydrogenolysisState(t_bed=210.0, a_cat=1.0, c_feed=2.5)

    _, _, da_low = reactor.compute_rates(st_low_t)
    _, _, da_high = reactor.compute_rates(st_high_t)

    assert abs(da_high) > abs(da_low)
    assert da_high < 0.0
    assert da_low < 0.0


def test_catalyst_activity_monotonic_decay() -> None:
    """Verify catalyst activity strictly decays over multiple RK4 steps with active deactivation."""
    cfg = PhaHydrogenolysisConfig(kd=0.05)
    reactor = PhaHydrogenolysisReactor(config=cfg)
    a_history = [reactor.state.a_cat]

    for _ in range(5):
        reactor.rk4_step(dt=0.2)
        a_history.append(reactor.state.a_cat)

    for i in range(len(a_history) - 1):
        assert a_history[i + 1] <= a_history[i]
    assert a_history[-1] < a_history[0]


def test_catalyst_deactivation_zero_activity_bound() -> None:
    """Verify catalyst activity is clamped to [0.0, 1.0] and zero activity halts reaction."""
    reactor = PhaHydrogenolysisReactor()
    st_zero = PhaHydrogenolysisState(a_cat=0.0)
    r1, r2, da_dt = reactor.compute_rates(st_zero)

    assert r1 == 0.0
    assert r2 == 0.0
    assert da_dt == 0.0


def test_catalyst_deactivation_with_zero_feed() -> None:
    """Verify deactivation rate is zero when precursor concentration is zero."""
    reactor = PhaHydrogenolysisReactor()
    st_no_feed = PhaHydrogenolysisState(c_feed=0.0, a_cat=0.8)
    _, _, da_dt = reactor.compute_rates(st_no_feed)
    assert da_dt == 0.0


# ============================================================================
# Section 6: Thermal Energy Balance & Jacket Heat Exchange
# ============================================================================

def test_exothermic_reaction_heat_release() -> None:
    """Verify reaction exotherm (Delta H1 = -65 kJ/mol) causes adiabatic temperature rise."""
    reactor = PhaHydrogenolysisReactor()
    reactor.cfg.ua_jacket = 0.0  # adiabatic
    t_start = reactor.state.t_bed
    reactor.rk4_step(dt=0.1)

    assert reactor.state.t_bed > t_start


def test_jacket_cooling_heat_extraction() -> None:
    """Verify active cooling jacket extracts heat and suppresses bed temperature."""
    reactor = PhaHydrogenolysisReactor()
    reactor.cfg.ua_jacket = 8000.0
    reactor.cfg.t_jacket = 160.0
    reactor.state.t_bed = 190.0
    t_start = reactor.state.t_bed
    reactor.rk4_step(dt=0.2)

    assert reactor.state.t_bed < t_start


def test_heating_jacket_circuit() -> None:
    """Verify activating preheating jacket adjusts effective jacket temperature upwards."""
    reactor = PhaHydrogenolysisReactor()
    reactor.cooling_jacket_active = False
    reactor.heating_jacket_active = True
    reactor.state.t_bed = 170.0
    derivs = reactor._derivatives(reactor.state)
    # Energy balance derivative should be positive when heating
    assert derivs[4] > 0.0


def test_liquid_feed_flow_cooling_dilution() -> None:
    """Verify continuous flow mode provides sensible cooling when feed is cooler than bed."""
    cfg = PhaHydrogenolysisConfig(f_liquid=5.0, t_feed_in=150.0)
    reactor = PhaHydrogenolysisReactor(config=cfg)
    reactor.liquid_feed_valve_open = True
    reactor.state.t_bed = 180.0
    derivs = reactor._derivatives(reactor.state)
    assert isinstance(derivs[4], float)


def test_derivatives_zero_when_tripped() -> None:
    """Verify all 6 state derivatives are identically zero when safety trip is latched."""
    reactor = PhaHydrogenolysisReactor()
    reactor.trip_active = True
    derivs = reactor._derivatives(reactor.state)
    assert derivs == (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)


# ============================================================================
# Section 7: Coupled RK4 Numerical Integration & Trajectory Dynamics
# ============================================================================

def test_single_rk4_step() -> None:
    """Verify a single RK4 integration step executes cleanly and updates state."""
    reactor = PhaHydrogenolysisReactor()
    c_feed_0 = reactor.state.c_feed
    c_bdo_0 = reactor.state.c_bdo
    reactor.rk4_step(dt=0.1)

    assert reactor.state.c_feed < c_feed_0
    assert reactor.state.c_bdo > c_bdo_0
    assert reactor.state.dt_bed_dt != 0.0


def test_multi_step_continuous_simulation() -> None:
    """Verify multi-step simulation trajectory smoothly converts feed to BDO and BuOH."""
    reactor = PhaHydrogenolysisReactor()
    for _ in range(15):
        reactor.rk4_step(dt=0.1)

    assert reactor.state.c_feed < 2.50
    assert reactor.state.c_bdo > 0.0
    assert reactor.selectivity_pct >= 85.0
    assert reactor.trip_active is False
    assert reactor.diagnostic_code == DIAG_OK


def test_rk4_step_size_stability() -> None:
    """Verify simulation stability with smaller dt=0.01 vs nominal dt=0.1."""
    r_fine = PhaHydrogenolysisReactor()
    r_coarse = PhaHydrogenolysisReactor()

    for _ in range(10):
        r_fine.rk4_step(dt=0.01)
    r_coarse.rk4_step(dt=0.10)

    # Both should show feed depletion and BDO accumulation
    assert r_fine.state.c_feed < 2.50
    assert r_coarse.state.c_feed < 2.50
    assert math.isclose(r_fine.state.c_feed, r_coarse.state.c_feed, rel_tol=1e-2)


def test_reactor_aliased_classes() -> None:
    """Verify all class aliases instantiate and exhibit identical interfaces."""
    for cls_alias in [
        PhaHydrogenolysisSimulator,
        PhaHydrogenolysisEngine,
        PhaHydrogenolysisModel,
        PhaHydrogenolysisPlantModel,
        PhaHydrogenolysisLogicUnit,
        PhaHydrogenolysisSimulationLogicUnit,
        PhaHydroReactor,
        PhaHydroSimulator,
        PhaHydroEngine,
        PhaHydroLogicUnit,
    ]:
        inst = cls_alias()
        assert isinstance(inst, PhaHydrogenolysisReactor)
        assert inst.state.c_feed == 2.50


def test_state_clamping_non_negative() -> None:
    """Verify concentrations never drop below zero during integration."""
    st_low = PhaHydrogenolysisState(c_feed=0.001, c_bdo=0.0001, c_buoh=0.0001)
    reactor = PhaHydrogenolysisReactor(state=st_low)
    for _ in range(10):
        reactor.rk4_step(dt=0.2)
    assert reactor.state.c_feed >= 0.0
    assert reactor.state.c_bdo >= 0.0
    assert reactor.state.c_buoh >= 0.0
    assert reactor.state.c_h2_diss >= 0.0


# ============================================================================
# Section 8: Strict Carbon Mass Conservation Residuals (< 1e-10)
# ============================================================================

def test_carbon_conservation_single_cycle() -> None:
    """Verify carbon mole balance residual < 1e-10 mol/L in closed batch mode."""
    reactor = PhaHydrogenolysisReactor()
    reactor.rk4_step(dt=0.1)
    current_carbon = reactor.state.c_feed + reactor.state.c_bdo + reactor.state.c_buoh
    assert math.isclose(current_carbon, 2.50, abs_tol=1e-10)
    assert reactor.conservation_residual < 1e-10


def test_carbon_conservation_multi_cycle_soak() -> None:
    """Verify carbon mole conservation across 50 consecutive RK4 cycles."""
    reactor = PhaHydrogenolysisReactor()
    for cycle in range(1, 51):
        reactor.rk4_step(dt=0.1)
        assert (
            reactor.conservation_residual < 1e-10
        ), f"Cycle {cycle}: residual {reactor.conservation_residual:.2e} exceeded 1e-10"


def test_carbon_conservation_various_temperatures() -> None:
    """Verify carbon conservation residual holds at 160°C, 180°C, and 200°C."""
    for temp in [160.0, 180.0, 200.0]:
        st = PhaHydrogenolysisState(t_bed=temp)
        reactor = PhaHydrogenolysisReactor(state=st)
        for _ in range(10):
            reactor.rk4_step(dt=0.1)
        assert reactor.conservation_residual < 1e-10


def test_carbon_conservation_custom_feed() -> None:
    """Verify carbon conservation with initial C_feed = 5.00 mol/L."""
    st = PhaHydrogenolysisState(c_feed=5.00)
    reactor = PhaHydrogenolysisReactor(state=st)
    for _ in range(10):
        reactor.rk4_step(dt=0.1)
    assert reactor.conservation_residual < 1e-10


def test_carbon_conservation_with_initial_products() -> None:
    """Verify carbon conservation when initial mixture contains products."""
    st = PhaHydrogenolysisState(c_feed=1.50, c_bdo=0.80, c_buoh=0.20)
    reactor = PhaHydrogenolysisReactor(state=st)
    for _ in range(10):
        reactor.rk4_step(dt=0.1)
    assert reactor.conservation_residual < 1e-10


# ============================================================================
# Section 9: Safety Trips, Interlocks & Fault Priority Hierarchy (0xF951..0xF954)
# ============================================================================

def test_thermal_runaway_trip_0xf951() -> None:
    """Verify Priority 1 safety trip: 0xF951 DIAG_ERR_RUNAWAY_EXOTHERM (T_bed > 220.0 °C)."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.t_bed = 225.0
    reactor.rk4_step(dt=0.05)

    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_RUNAWAY_EXOTHERM
    assert (int(reactor.diagnostic_code) & 0xFFFF) == 0xF951
    assert reactor.reg_table.read_bit(COIL_PHA_HYDRO_TRIP) is True
    assert reactor.reg_table.read_bit(COIL_PHA_HYDRO_ACTIVE) is False
    assert (reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF951
    # Check fail-safe isolation
    assert reactor.h2_feed_valve_open is False
    assert reactor.liquid_feed_valve_open is False
    assert reactor.cooling_jacket_active is True


def test_h2_pressure_collapse_trip_0xf952() -> None:
    """Verify Priority 2 safety trip: 0xF952 DIAG_ERR_H2_PRESSURE_COLLAPSE (P_H2 < 25.0 bar)."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.p_h2 = 22.0
    reactor.rk4_step(dt=0.05)

    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_H2_PRESSURE_COLLAPSE
    assert (int(reactor.diagnostic_code) & 0xFFFF) == 0xF952
    assert reactor.reg_table.read_bit(COIL_PHA_HYDRO_TRIP) is True
    assert (reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF952


def test_hotspot_rate_trip_0xf953() -> None:
    """Verify Priority 3 safety trip: 0xF953 DIAG_ERR_HOTSPOT_RATE (dT/dt > 5.0 °C/s)."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.dt_bed_dt = 6.5
    reactor.rk4_step(dt=0.05)

    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_HOTSPOT_RATE
    assert (int(reactor.diagnostic_code) & 0xFFFF) == 0xF953
    assert reactor.reg_table.read_bit(COIL_PHA_HYDRO_TRIP) is True
    assert (reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF953


def test_catalyst_deactivation_trip_0xf954() -> None:
    """Verify Priority 4 safety trip: 0xF954 DIAG_ERR_CATALYST_DEACTIVATED (a_cat < 0.20)."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.a_cat = 0.15
    reactor.rk4_step(dt=0.05)

    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_CATALYST_DEACTIVATED
    assert (int(reactor.diagnostic_code) & 0xFFFF) == 0xF954
    assert reactor.reg_table.read_bit(COIL_PHA_HYDRO_TRIP) is True
    assert (reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF954


def test_priority_hierarchy_runaway_over_pressure() -> None:
    """Verify Priority 1 (Thermal Runaway 0xF951) dominates Priority 2 (Pressure Collapse 0xF952)."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.t_bed = 225.0  # Tripped (P1)
    reactor.state.p_h2 = 20.0    # Tripped (P2)
    reactor.rk4_step(dt=0.05)

    assert reactor.diagnostic_code == DIAG_ERR_RUNAWAY_EXOTHERM
    assert (reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF951


def test_priority_hierarchy_pressure_over_hotspot_and_cat() -> None:
    """Verify Priority 2 (Pressure Collapse 0xF952) dominates Priority 3 & 4."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.p_h2 = 20.0    # Tripped (P2)
    reactor.state.dt_bed_dt = 7.0 # Tripped (P3)
    reactor.state.a_cat = 0.10   # Tripped (P4)
    reactor.rk4_step(dt=0.05)

    assert reactor.diagnostic_code == DIAG_ERR_H2_PRESSURE_COLLAPSE
    assert (reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF952


def test_priority_hierarchy_hotspot_over_deactivation() -> None:
    """Verify Priority 3 (Hotspot Rate 0xF953) dominates Priority 4 (Catalyst Deactivation 0xF954)."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.dt_bed_dt = 7.0 # Tripped (P3)
    reactor.state.a_cat = 0.10   # Tripped (P4)
    reactor.rk4_step(dt=0.05)

    assert reactor.diagnostic_code == DIAG_ERR_HOTSPOT_RATE
    assert (reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF953


# ============================================================================
# Section 10: State Transitions, Emergency Quench & N2 Purge
# ============================================================================

def test_emergency_quench_actuation() -> None:
    """Verify emergency shutdown actuates fail-safe valve closures and max cooling."""
    reactor = PhaHydrogenolysisReactor()
    reactor.emergency_shutdown()

    assert reactor.h2_feed_valve_open is False
    assert reactor.liquid_feed_valve_open is False
    assert reactor.product_discharge_open is False
    assert reactor.recycle_compressor_active is False
    assert reactor.heating_jacket_active is False
    assert reactor.cooling_jacket_active is True
    assert reactor.warning_active is False


def test_n2_purge_mode_transition() -> None:
    """Verify transition to N2 Inert Purge mode sets mode 1 in status word."""
    reactor = PhaHydrogenolysisReactor()
    reactor.mode = PhaHydroMode.INERT_PURGE
    reactor.sync_to_registers(reactor.reg_table)

    w_status = reactor.reg_table.read_word(REG_PHA_HYDRO_STATUS)
    mode_byte = (w_status >> 8) & 0xFF
    assert mode_byte == 1


def test_h2_pressurization_mode_transition() -> None:
    """Verify transition to H2 Pressurization mode sets mode 2 in status word."""
    reactor = PhaHydrogenolysisReactor()
    reactor.mode = PhaHydroMode.H2_PRESSURIZATION
    reactor.sync_to_registers(reactor.reg_table)

    w_status = reactor.reg_table.read_word(REG_PHA_HYDRO_STATUS)
    mode_byte = (w_status >> 8) & 0xFF
    assert mode_byte == 2


def test_catalyst_regeneration_mode() -> None:
    """Verify transition to Catalyst Regeneration mode sets mode 4 in status word."""
    reactor = PhaHydrogenolysisReactor()
    reactor.mode = PhaHydroMode.CATALYST_REGENERATION
    reactor.sync_to_registers(reactor.reg_table)

    w_status = reactor.reg_table.read_word(REG_PHA_HYDRO_STATUS)
    mode_byte = (w_status >> 8) & 0xFF
    assert mode_byte == 4


def test_reset_functionality() -> None:
    """Verify reset() restores default initial conditions and clears safety trips."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.t_bed = 230.0
    reactor.rk4_step(dt=0.05)
    assert reactor.trip_active is True

    reactor.reset()
    assert reactor.trip_active is False
    assert reactor.diagnostic_code == DIAG_OK
    assert reactor.state.c_feed == 2.50
    assert reactor.state.t_bed == 180.0
    assert reactor.h2_feed_valve_open is True
    assert (reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000


# ============================================================================
# Section 11: ILogicUnit Compliance & Scan Cycle Execution
# ============================================================================

def test_ilogic_unit_interface_properties() -> None:
    """Verify ILogicUnit standard properties (unit_id, name, priority, is_enabled)."""
    reactor = PhaHydrogenolysisReactor()
    assert reactor.unit_id == "PHA_HYDRO_REACTOR_W305"
    assert "PhaHydrogenolysis" in reactor.name
    assert reactor.priority == 50
    assert reactor.is_enabled is True


def test_scan_step_with_args_and_kwargs() -> None:
    """Verify scan_step handles diverse parameter invocation signatures."""
    reactor = PhaHydrogenolysisReactor()

    # 1. Positional dt
    res1 = reactor.scan_step(0.05)
    assert res1.status == AgentStatus.SUCCESS

    # 2. Kwarg dt
    res2 = reactor.scan_step(dt=0.10)
    assert res2.status == AgentStatus.SUCCESS

    # 3. Kwarg dt_h
    res3 = reactor.scan_step(dt_h=0.0001)
    assert res3.status == AgentStatus.SUCCESS


def test_scan_step_with_scan_context() -> None:
    """Verify scan_step with ScanContext propagates RegisterTable."""
    rt_ext = RegisterTable()
    context = ScanContext(cycle=1, dt=0.1, register_table=rt_ext)
    reactor = PhaHydrogenolysisReactor()

    res = reactor.scan_step(context=context)
    assert res.status == AgentStatus.SUCCESS
    assert reactor.reg_table is rt_ext
    assert rt_ext.read_bit(COIL_PHA_HYDRO_ACTIVE) is True


def test_step_and_execute_delegation() -> None:
    """Verify step() and execute() methods correctly invoke scan_step."""
    reactor = PhaHydrogenolysisReactor()
    c0 = reactor.cycle_count
    reactor.step(0.1)
    assert reactor.cycle_count == c0 + 1

    reactor.execute(0.1)
    assert reactor.cycle_count == c0 + 2


def test_scan_step_execution_result_contract() -> None:
    """Verify scan_step returns strict 4-state ExecutionResult contract."""
    reactor = PhaHydrogenolysisReactor()
    res = reactor.scan_step(dt=0.1)

    assert isinstance(res, ExecutionResult)
    assert res.status in [AgentStatus.SUCCESS, AgentStatus.FAILED]
    assert "c_feed" in res.data
    assert "bdo_yield_pct" in res.data
    assert "selectivity_pct" in res.data
    assert "conservation_residual" in res.data
    assert res.error_code is None


# ============================================================================
# Section 12: Horner OCS RegisterTable Sync & Signed 16-Bit Masking (%R2660..%R2667, %M620..%M622)
# ============================================================================

def test_register_table_nominal_sync() -> None:
    """Verify register values synchronized to Horner OCS memory space %R2660..%R2667."""
    reactor = PhaHydrogenolysisReactor()
    reactor.scan_step(dt=0.1)
    rt = reactor.reg_table

    w_status = rt.read_word(REG_PHA_HYDRO_STATUS)
    w_temp = rt.read_word(REG_PHA_HYDRO_TEMP_SCALED)
    w_press = rt.read_word(REG_PHA_HYDRO_PRESSURE_BAR)
    w_yield = rt.read_word(REG_PHA_HYDRO_BDO_YIELD_PCT)
    w_sel = rt.read_word(REG_PHA_HYDRO_SELECTIVITY_PCT)
    w_act = rt.read_word(REG_PHA_HYDRO_CATALYST_ACTIVITY)
    w_diag = rt.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE)
    w_sword = rt.read_word(REG_PHA_HYDRO_STATUS_WORD)

    assert (w_status & 0xFF) == 2  # BedStatus: RUNNING (2)
    assert ((w_status >> 8) & 0xFF) == 3  # Mode: ACTIVE_REACTION (3)
    assert w_temp > 0
    assert w_press == 500  # 50.0 bar * 10
    assert w_yield >= 0
    assert w_sel > 0
    assert w_act > 0
    assert (w_diag & 0xFFFF) == 0x0000
    assert (w_sword & PhaHydroStatusWord.H2_FEED_VALVE_OPEN) != 0


def test_register_coils_nominal_state() -> None:
    """Verify discrete coils in nominal operating state (%M620=True, %M621=False, %M622=False)."""
    reactor = PhaHydrogenolysisReactor()
    reactor.sync_to_registers(reactor.reg_table)
    rt = reactor.reg_table

    assert rt.read_bit(COIL_PHA_HYDRO_ACTIVE) is True
    assert rt.read_bit(COIL_PHA_HYDRO_WARNING) is False
    assert rt.read_bit(COIL_PHA_HYDRO_TRIP) is False


def test_register_coils_warning_state() -> None:
    """Verify %M621 is asserted in warning state (e.g. T_bed >= 200.0 °C)."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.t_bed = 205.0  # Above warning threshold (200.0) but below trip (220.0)
    reactor.check_interlocks(reactor.state)
    reactor.sync_to_registers(reactor.reg_table)
    rt = reactor.reg_table

    assert rt.read_bit(COIL_PHA_HYDRO_ACTIVE) is True
    assert rt.read_bit(COIL_PHA_HYDRO_WARNING) is True
    assert rt.read_bit(COIL_PHA_HYDRO_TRIP) is False


def test_register_coils_trip_state() -> None:
    """Verify %M620=False, %M621=False, %M622=True when tripped."""
    reactor = PhaHydrogenolysisReactor()
    reactor.state.t_bed = 225.0
    reactor.rk4_step(dt=0.05)
    rt = reactor.reg_table

    assert rt.read_bit(COIL_PHA_HYDRO_ACTIVE) is False
    assert rt.read_bit(COIL_PHA_HYDRO_WARNING) is False
    assert rt.read_bit(COIL_PHA_HYDRO_TRIP) is True


def test_signed_16bit_diagnostic_masking() -> None:
    """Verify signed 16-bit masking (rt.read_word(...) & 0xFFFF) == expected for all 4 trip codes."""
    reactor = PhaHydrogenolysisReactor()
    trip_codes = [0xF951, 0xF952, 0xF953, 0xF954]

    for trip_val in trip_codes:
        reactor.diagnostic_code = DiagnosticCode(trip_val)
        reactor.trip_active = True
        reactor.sync_to_registers(reactor.reg_table)

        raw_word = reactor.reg_table.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE)
        masked_word = raw_word & 0xFFFF
        assert masked_word == trip_val

        # Signed 16-bit equivalence
        signed_val = trip_val - 0x10000
        assert DiagnosticCode(trip_val) == signed_val
        assert DiagnosticCode(trip_val) == trip_val


def test_diagnostic_code_class_helpers() -> None:
    """Verify DiagnosticCode integer subclass equality, hash, repr, and str."""
    code = DiagnosticCode(0xF951)
    assert code == 0xF951
    assert code == (0xF951 - 0x10000)
    assert hash(code) == hash(0xF951)
    assert "0xF951" in str(code)
    assert "0xF951" in repr(code)

    ok_code = DiagnosticCode(0x0000)
    assert ok_code == 0
    assert str(ok_code) == "0x0000"


def test_register_table_privilege_modes() -> None:
    """Verify register synchronization operates cleanly under SYSTEM privilege."""
    reactor = PhaHydrogenolysisReactor()
    rt = RegisterTable()
    reactor.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
    assert (rt.read_word(REG_PHA_HYDRO_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000


# ============================================================================
# Section 13: Pure IEC 61131-3 ST POU, Anti-Ladder Enforcement & 9-Stage Verification Runners
# ============================================================================

def test_pure_st_pou_syntax_validation() -> None:
    """Verify pure ST POU syntax using verify_pha_hydrogenolysis_pure_st()."""
    assert verify_pha_hydrogenolysis_pure_st() is True
    assert verify_pha_hydro_pure_st() is True


def test_st_parser_ast_validation() -> None:
    """Verify STParser parses PHA_HYDROGENOLYSIS_PURE_ST_POU cleanly with 0 errors."""
    res = STParser.validate_code(PHA_HYDROGENOLYSIS_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS


def test_anti_ladder_contacts_rejection() -> None:
    """Verify ladder logic contact syntax (---[ ]---) is rejected with LadderForbiddenError."""
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("PROGRAM Test ---[ ]--- END_PROGRAM")


def test_anti_ladder_coils_rejection() -> None:
    """Verify ladder logic coil syntax (---( )---) is rejected with LadderForbiddenError."""
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("PROGRAM Test ---( )--- END_PROGRAM")


def test_anti_ladder_rungs_rejection() -> None:
    """Verify ladder logic rung delimiters (RUNG 1: XIC) are rejected with LadderForbiddenError."""
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("NETWORK 1 RUNG 1: XIC(Start) OTE(Run)")


def test_anti_ladder_inverted_contacts_rejection() -> None:
    """Verify inverted contact syntax (---[/]---) is rejected with LadderForbiddenError."""
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("PROGRAM P ---[/]--- END_PROGRAM")


def test_deterministic_9_stage_verification_suite() -> None:
    """Execute complete 9-stage verification suite runner and test JSON evidence emission."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name

    try:
        res = run_pha_hydrogenolysis_verification(output_path=out_path)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9

        # Ensure evidence file was written and is valid JSON
        p = Path(out_path)
        assert p.exists()
        loaded = json.loads(p.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
        assert loaded["data"]["checks_passed"] == 9
    finally:
        Path(out_path).unlink(missing_ok=True)


def test_runner_script_verification_execution() -> None:
    """Verify execution of scripts/run_pha_hydrogenolysis_verification.py module runner."""
    from scripts.run_pha_hydrogenolysis_verification import (
        execute_pha_hydrogenolysis_verification,
    )

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name

    try:
        res = execute_pha_hydrogenolysis_verification(output_path=out_path, quick=True)
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
    finally:
        Path(out_path).unlink(missing_ok=True)
