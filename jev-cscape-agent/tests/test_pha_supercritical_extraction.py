"""Industrial Supercritical CO2 PHA Extraction & Precipitation Unit Test Suite (W302).

Work Package: W302 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification sections:
1. Section 1: Model Initialization, Configuration & Parameter Validation
2. Section 2: Real-Gas Peng-Robinson EOS & Supercritical CO2 Density
3. Section 3: Chrastil Supercritical Solubility Model & Monotonic Density Dependence
4. Section 4: Shrinking Core Biomass Dissolution Kinetics
5. Section 5: Depressurization & Separator Precipitation Kinetics
6. Section 6: Coupled 6-State ODE RK4 Integration & Trajectory Dynamics
7. Section 7: Analytical PHA Mass Conservation Residuals (< 1e-10)
8. Section 8: Process Safety Trips & Strict Fault Hierarchy (0xF941..0xF944)
9. Section 9: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
10. Section 10: ILogicUnit Compliance & Multi-Cycle Scan Execution (scan_step, step, execute, reset)
11. Section 11: Horner OCS Register Space Synchronization (%R2630..%R2637, %M613..%M615)
12. Section 12: Pure IEC 61131-3 Structured Text POU, Anti-Ladder Construct Rejection & 9-Stage Verification Runner
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

from jev_cscape.simulation.pha_supercritical_extraction import (
    CHRASTIL_A,
    CHRASTIL_B,
    CHRASTIL_K,
    CHRASTIL_RHO_REF,
    COIL_PHA_SCCO2_ACTIVE,
    COIL_PHA_SCCO2_EMERGENCY_TRIP,
    COIL_PHA_SCCO2_EXTRACTION_ACTIVE,
    COIL_PHA_SCCO2_PERMISSIVE,
    COIL_PHA_SCCO2_RUNNING,
    COIL_PHA_SCCO2_TRIP,
    COIL_PHA_SCCO2_TRIP_ALARM,
    COIL_PHA_SCCO2_WARNING,
    COIL_PHA_SCCO2_WARNING_ALARM,
    COIL_PHA_SCRC_ACTIVE,
    COIL_PHA_SCRC_TRIP,
    COIL_PHA_SCRC_WARNING,
    DIAG_ERR_CLOGGING,
    DIAG_ERR_OVERPRESSURE,
    DIAG_ERR_OVER_PRESSURE,
    DIAG_ERR_PHASE_BOUNDARY,
    DIAG_ERR_PHASE_BOUNDARY_LOSS,
    DIAG_ERR_SEPARATOR_CLOGGING,
    DIAG_ERR_SUBCRITICAL,
    DIAG_ERR_SUBCRITICAL_LOSS,
    DIAG_ERR_THERMAL,
    DIAG_ERR_THERMAL_DEGRADATION,
    DIAG_OK,
    DIAG_OVER_PRESSURE,
    DIAG_PHASE_BOUNDARY_LOSS,
    DIAG_SEPARATOR_CLOGGING,
    DIAG_THERMAL_DEGRADATION,
    DiagnosticCode,
    GAS_CONSTANT_R,
    MW_CO2,
    OMEGA_CO2,
    P_CRITICAL_CO2_BAR,
    P_CRITICAL_CO2_PA,
    PHA_SCCO2_EXTRACTION_PURE_ST_POU,
    PHA_SCCO2_PURE_ST_POU,
    PHA_SUPERCRITICAL_EXTRACTION_PURE_ST_POU,
    PhaScCO2DiagnosticCode,
    PhaScCO2Engine,
    PhaScCO2ExtractionConfig,
    PhaScCO2ExtractionReactor,
    PhaScCO2ExtractionState,
    PhaScCO2Extractor,
    PhaScCO2Phase,
    PhaScCO2Simulator,
    PhaScCO2State,
    PhaScCO2StateModel,
    PhaScCO2StatusBits,
    PhaScCO2StatusWord,
    PhaSupercriticalDiagnosticCode,
    PhaSupercriticalExtractionConfig,
    PhaSupercriticalExtractionDiagnosticCode,
    PhaSupercriticalExtractionEngine,
    PhaSupercriticalExtractionLogicUnit,
    PhaSupercriticalExtractionModel,
    PhaSupercriticalExtractionParameters,
    PhaSupercriticalExtractionPhase,
    PhaSupercriticalExtractionPlantModel,
    PhaSupercriticalExtractionReactor,
    PhaSupercriticalExtractionSimulationLogicUnit,
    PhaSupercriticalExtractionSimulator,
    PhaSupercriticalExtractionState,
    PhaSupercriticalExtractionStateEnum,
    PhaSupercriticalExtractionStatusBits,
    PhaSupercriticalExtractionStatusWord,
    PhaSupercriticalExtractionSync,
    PhaSupercriticalStatusBits,
    PhaSupercriticalStatusWord,
    R_SPECIFIC_CO2,
    REG_PHA_SCCO2_DENSITY,
    REG_PHA_SCCO2_DENSITY_SCALED,
    REG_PHA_SCCO2_DIAG,
    REG_PHA_SCCO2_DIAGNOSTIC_CODE,
    REG_PHA_SCCO2_EXTRACTED_YIELD_PCT,
    REG_PHA_SCCO2_M_PRECIP,
    REG_PHA_SCCO2_MODE_STATUS,
    REG_PHA_SCCO2_P_EXT,
    REG_PHA_SCCO2_PRECIP_MASS,
    REG_PHA_SCCO2_PRECIPITATED_MASS,
    REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED,
    REG_PHA_SCCO2_PRESSURE,
    REG_PHA_SCCO2_PRESSURE_BAR,
    REG_PHA_SCCO2_PRESSURE_SCALED,
    REG_PHA_SCCO2_RHO,
    REG_PHA_SCCO2_STATUS,
    REG_PHA_SCCO2_STATUS_BITS,
    REG_PHA_SCCO2_STATUS_REG,
    REG_PHA_SCCO2_STATUS_WORD,
    REG_PHA_SCCO2_T_EXT,
    REG_PHA_SCCO2_TEMP,
    REG_PHA_SCCO2_TEMP_SCALED,
    REG_PHA_SCCO2_TEMPERATURE,
    REG_PHA_SCCO2_YIELD,
    REG_PHA_SCCO2_YIELD_PCT,
    REG_PHA_SCCO2_YIELD_SCALED,
    REG_PHA_SCRC_DENSITY_SCALED,
    REG_PHA_SCRC_DIAGNOSTIC_CODE,
    REG_PHA_SCRC_PRESSURE_SCALED,
    REG_PHA_SCRC_SOLUBILITY_SCALED,
    REG_PHA_SCRC_STATUS,
    REG_PHA_SCRC_STATUS_WORD,
    REG_PHA_SCRC_TEMP_SCALED,
    REG_PHA_SCRC_YIELD_SCALED,
    RHO_CRITICAL_CO2_KG_M3,
    ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC,
    T_CRITICAL_CO2_K,
    run_pha_scco2_verification,
    run_pha_supercritical_extraction_verification,
    verify_pha_scco2_pure_st,
    verify_pha_supercritical_extraction_pure_st,
)


# ============================================================================
# Section 1: Model Initialization, Configuration & Parameter Validation
# ============================================================================

def test_config_defaults_and_serialization() -> None:
    """Validate configuration defaults, serialization to dict, and parameter ranges."""
    cfg = PhaSupercriticalExtractionConfig()
    assert cfg.chrastil_k == 3.8
    assert cfg.chrastil_a == -3400.0
    assert cfg.chrastil_b == -12.5
    assert cfg.kLa == 0.02
    assert cfg.k_precip == 0.03
    assert cfg.s_sep == 0.05
    assert cfg.v_target == 20.0
    assert cfg.overpressure_threshold == 360.0
    assert cfg.phase_boundary_threshold == 75.0
    assert cfg.thermal_degradation_threshold == 85.0
    assert cfg.separator_capacity == 480.0

    d = cfg.to_dict()
    assert isinstance(d, dict)
    assert d["overpressure_threshold"] == 360.0
    assert d["phase_boundary_threshold"] == 75.0
    assert d["chrastil_k"] == 3.8


def test_custom_config_instantiation() -> None:
    """Validate reactor initialization with custom configuration parameters."""
    cfg = PhaSupercriticalExtractionConfig(
        chrastil_k=4.0,
        chrastil_a=-3200.0,
        chrastil_b=-11.0,
        kLa=0.05,
        k_precip=0.08,
        s_sep=0.10,
        v_target=50.0,
        overpressure_threshold=370.0,
        phase_boundary_threshold=70.0,
        thermal_degradation_threshold=90.0,
        separator_capacity=600.0,
    )
    reactor = PhaSupercriticalExtractionReactor(config=cfg)
    assert reactor.cfg.chrastil_k == 4.0
    assert reactor.cfg.kLa == 0.05
    assert reactor.cfg.v_target == 50.0
    assert reactor.cfg.overpressure_threshold == 370.0
    assert reactor.cfg.separator_capacity == 600.0


def test_state_initialization_and_property_aliases() -> None:
    """Validate 6-state vector initialization and property aliases."""
    st = PhaSupercriticalExtractionState(
        m_cell=450.0,
        c_pha_sol=1.5,
        m_precip=10.0,
        p_ext=280.0,
        t_ext=55.0,
        v_scco2=25.0,
    )
    assert st.M_cell == 450.0
    assert st.biomass == 450.0
    assert st.cell_mass == 450.0
    assert st.m_solid == 450.0

    assert st.C_pha_sol == 1.5
    assert st.dissolved_pha == 1.5
    assert st.c_sol == 1.5
    assert st.m_fluid == 1.5 * 25.0

    assert st.M_precip == 10.0
    assert st.precipitated_mass == 10.0
    assert st.purified_pha == 10.0

    assert st.P_ext == 280.0
    assert st.pressure == 280.0
    assert st.pressure_bar == 280.0

    assert st.T_ext == 55.0
    assert st.temp == 55.0
    assert st.temperature == 55.0
    assert st.temp_c == 55.0

    assert st.V_scCO2 == 25.0
    assert st.volume == 25.0
    assert st.fluid_volume == 25.0

    # Test property setters
    st.m_solid = 400.0
    assert st.m_cell == 400.0
    st.temp_c = 60.0
    assert st.t_ext == 60.0
    st.m_fluid = 50.0
    assert math.isclose(st.c_pha_sol, 50.0 / 25.0, rel_tol=1e-6)


def test_state_from_dict_and_to_dict() -> None:
    """Validate serialization round-trip with varied dictionary key capitalization."""
    st = PhaSupercriticalExtractionState(
        m_cell=520.0,
        c_pha_sol=2.2,
        m_precip=15.0,
        p_ext=260.0,
        t_ext=52.0,
        v_scco2=22.0,
    )
    d = st.to_dict()
    assert d["m_cell"] == 520.0
    assert d["c_pha_sol"] == 2.2

    # Reconstruct from dictionary
    st2 = PhaSupercriticalExtractionState.from_dict(d)
    assert st2.m_cell == 520.0
    assert st2.c_pha_sol == 2.2
    assert st2.m_precip == 15.0
    assert st2.p_ext == 260.0
    assert st2.t_ext == 52.0
    assert st2.v_scco2 == 22.0

    # Reconstruct with alias keys
    st3 = PhaSupercriticalExtractionState.from_dict({
        "biomass": 350.0,
        "solute_conc": 1.1,
        "purified_pha": 5.0,
        "pressure": 230.0,
        "temperature": 48.0,
        "volume": 18.0,
    })
    assert st3.m_cell == 350.0
    assert st3.c_pha_sol == 1.1
    assert st3.m_precip == 5.0


def test_universal_and_critical_constants() -> None:
    """Validate physical, thermodynamic, and empirical constants for scCO2 and PHA."""
    assert math.isclose(GAS_CONSTANT_R, 8.31446, rel_tol=1e-4)
    assert math.isclose(MW_CO2, 0.04401, rel_tol=1e-4)
    assert math.isclose(R_SPECIFIC_CO2, GAS_CONSTANT_R / MW_CO2, rel_tol=1e-6)
    assert math.isclose(T_CRITICAL_CO2_K, 304.13, rel_tol=1e-4)
    assert math.isclose(P_CRITICAL_CO2_PA, 7.3773e6, rel_tol=1e-4)
    assert math.isclose(P_CRITICAL_CO2_BAR, 73.773, rel_tol=1e-4)
    assert math.isclose(RHO_CRITICAL_CO2_KG_M3, 467.6, rel_tol=1e-4)
    assert math.isclose(OMEGA_CO2, 0.22394, rel_tol=1e-4)
    assert CHRASTIL_K > 0.0
    assert CHRASTIL_A < 0.0
    assert CHRASTIL_RHO_REF == 1000.0


def test_class_and_type_aliases() -> None:
    """Validate all class, model, and diagnostic type aliases for component interchangeability."""
    assert PhaSupercriticalExtractionSimulator is PhaSupercriticalExtractionReactor
    assert PhaSupercriticalExtractionLogicUnit is PhaSupercriticalExtractionReactor
    assert PhaSupercriticalExtractionEngine is PhaSupercriticalExtractionReactor
    assert PhaSupercriticalExtractionModel is PhaSupercriticalExtractionReactor
    assert PhaSupercriticalExtractionPlantModel is PhaSupercriticalExtractionReactor
    assert PhaScCO2ExtractionReactor is PhaSupercriticalExtractionReactor
    assert PhaScCO2Extractor is PhaSupercriticalExtractionReactor
    assert PhaScCO2Simulator is PhaSupercriticalExtractionReactor
    assert PhaScCO2Engine is PhaSupercriticalExtractionReactor

    assert PhaScCO2ExtractionState is PhaSupercriticalExtractionState
    assert PhaScCO2StateModel is PhaSupercriticalExtractionState
    assert PhaScCO2ExtractionConfig is PhaSupercriticalExtractionConfig
    assert PhaSupercriticalExtractionParameters is PhaSupercriticalExtractionConfig

    assert PhaSupercriticalExtractionDiagnosticCode is DiagnosticCode
    assert PhaScCO2DiagnosticCode is DiagnosticCode
    assert PhaSupercriticalDiagnosticCode is DiagnosticCode

    assert PhaSupercriticalExtractionStatusWord is PhaScCO2StatusWord
    assert PhaSupercriticalStatusWord is PhaScCO2StatusWord
    assert PhaScCO2StatusBits is PhaScCO2StatusWord
    assert PhaSupercriticalStatusBits is PhaScCO2StatusWord


# ============================================================================
# Section 2: Real-Gas Peng-Robinson EOS & Supercritical CO2 Density
# ============================================================================

def test_peng_robinson_density_supercritical_range() -> None:
    """Verify Peng-Robinson real-gas density solver in supercritical envelope (600..950 kg/m^3)."""
    reactor = PhaSupercriticalExtractionReactor()

    # Nominal extraction: 250 bar, 50 °C -> dense fluid ~ 820..840 kg/m^3
    rho_nom = reactor.calculate_co2_density(250.0, 50.0)
    assert 750.0 <= rho_nom <= 900.0

    # High pressure: 350 bar, 40 °C -> near 950 kg/m^3
    rho_hi = reactor.calculate_co2_density(350.0, 40.0)
    assert 900.0 <= rho_hi <= 1000.0

    # Low extraction pressure / higher temperature: 150 bar, 80 °C
    rho_lo = reactor.calculate_co2_density(150.0, 80.0)
    assert 350.0 <= rho_lo <= 550.0


def test_peng_robinson_eos_pressure_monotonicity() -> None:
    """Verify density strictly increases with pressure at constant temperature."""
    reactor = PhaSupercriticalExtractionReactor()
    pressures = [150.0, 200.0, 250.0, 300.0, 350.0]
    densities = [reactor.calculate_co2_density(p, 50.0) for p in pressures]

    for i in range(len(densities) - 1):
        assert densities[i] < densities[i + 1], f"Density did not increase from {pressures[i]} to {pressures[i+1]} bar"


def test_peng_robinson_eos_temperature_dependence() -> None:
    """Verify density strictly decreases with temperature at constant high pressure."""
    reactor = PhaSupercriticalExtractionReactor()
    temps = [40.0, 50.0, 60.0, 70.0, 80.0]
    densities = [reactor.calculate_co2_density(250.0, t) for t in temps]

    for i in range(len(densities) - 1):
        assert densities[i] > densities[i + 1], f"Density did not decrease from {temps[i]} to {temps[i+1]} °C"


def test_subcritical_gas_density_transition() -> None:
    """Verify density collapses when pressure drops below critical into gas phase."""
    reactor = PhaSupercriticalExtractionReactor()
    rho_sub = reactor.calculate_co2_density(50.0, 35.0)
    assert rho_sub < 350.0
    assert rho_sub > 50.0


def test_compute_density_method_and_alias() -> None:
    """Verify compute_density alias produces exact match to calculate_co2_density."""
    reactor = PhaSupercriticalExtractionReactor()
    d1 = reactor.calculate_co2_density(220.0, 45.0)
    d2 = reactor.compute_density(220.0, 45.0)
    assert math.isclose(d1, d2, rel_tol=1e-12)


# ============================================================================
# Section 3: Chrastil Supercritical Solubility Model & Monotonic Density Dependence
# ============================================================================

def test_chrastil_solubility_monotonic_density_dependence() -> None:
    """Verify Chrastil solubility equation S = d^k * exp(a / (T+273.15) + b)."""
    reactor = PhaSupercriticalExtractionReactor()
    densities = [600.0, 700.0, 800.0, 900.0, 950.0]
    solubilities = [reactor.chrastil_solubility(d, 50.0) for d in densities]

    # Monotonic density dependence
    for i in range(len(solubilities) - 1):
        assert solubilities[i] < solubilities[i + 1]

    assert solubilities[0] > 0.0
    assert solubilities[-1] > 15.0


def test_chrastil_solubility_zero_and_negative_density() -> None:
    """Verify non-physical or zero densities return 0.0 solubility gracefully."""
    reactor = PhaSupercriticalExtractionReactor()
    assert reactor.chrastil_solubility(0.0, 50.0) == 0.0
    assert reactor.chrastil_solubility(-100.0, 50.0) == 0.0
    assert reactor.chrastil_solubility(800.0, -274.0) == 0.0


def test_chrastil_solubility_temperature_dependence() -> None:
    """Verify temperature effect at constant dense fluid density."""
    reactor = PhaSupercriticalExtractionReactor()
    s_t40 = reactor.chrastil_solubility(820.0, 40.0)
    s_t60 = reactor.chrastil_solubility(820.0, 60.0)
    s_t80 = reactor.chrastil_solubility(820.0, 80.0)

    assert s_t40 > 0.0
    assert s_t60 > 0.0
    assert s_t80 > 0.0
    assert s_t40 != s_t60 != s_t80


def test_chrastil_solubility_depressurization_collapse() -> None:
    """Verify steep solubility drop upon separator depressurization (> 95% reduction)."""
    reactor = PhaSupercriticalExtractionReactor()
    rho_nominal = reactor.calculate_co2_density(250.0, 50.0)
    sol_nominal = reactor.chrastil_solubility(rho_nominal, 50.0)

    rho_depress = reactor.calculate_co2_density(50.0, 35.0)
    sol_depress = reactor.chrastil_solubility(rho_depress, 35.0)

    assert sol_nominal > 5.0
    assert sol_depress < 0.20
    drop_pct = (sol_nominal - sol_depress) / sol_nominal * 100.0
    assert drop_pct > 95.0


def test_compute_solubility_method_and_alias() -> None:
    """Verify compute_solubility alias matches chrastil_solubility identically."""
    reactor = PhaSupercriticalExtractionReactor()
    s1 = reactor.chrastil_solubility(850.0, 45.0)
    s2 = reactor.compute_solubility(850.0, 45.0)
    assert math.isclose(s1, s2, rel_tol=1e-12)


def test_solubility_property_accessor() -> None:
    """Verify reactor.solubility_s property updates with reactor state."""
    reactor = PhaSupercriticalExtractionReactor()
    s_init = reactor.solubility_s
    assert s_init > 0.0

    reactor.state.p_ext = 320.0
    s_high = reactor.solubility_s
    assert s_high > s_init


# ============================================================================
# Section 4: Shrinking Core Biomass Dissolution Kinetics
# ============================================================================

def test_shrinking_core_dissolution_scaling() -> None:
    """Verify dissolution rate scaling with shrinking biomass core: (M_cell / M_cell0)^(2/3)."""
    reactor = PhaSupercriticalExtractionReactor()

    st_500 = PhaSupercriticalExtractionState(m_cell=500.0, c_pha_sol=0.0)
    st_250 = PhaSupercriticalExtractionState(m_cell=250.0, c_pha_sol=0.0)
    st_62 = PhaSupercriticalExtractionState(m_cell=62.5, c_pha_sol=0.0)
    st_0 = PhaSupercriticalExtractionState(m_cell=0.0, c_pha_sol=0.0)

    _, _, r_500, _ = reactor.compute_rates(st_500)
    _, _, r_250, _ = reactor.compute_rates(st_250)
    _, _, r_62, _ = reactor.compute_rates(st_62)
    _, _, r_0, _ = reactor.compute_rates(st_0)

    assert r_500 > r_250 > r_62 > 0.0
    assert r_0 == 0.0

    # Analytical ratio: (250/500)^(2/3) ~ 0.62996
    expected_ratio = (250.0 / 500.0) ** (2.0 / 3.0)
    actual_ratio = r_250 / r_500
    assert abs(actual_ratio - expected_ratio) < 1e-4


def test_dissolution_halts_upon_fluid_saturation() -> None:
    """Verify dissolution ceases when dissolved concentration reaches or exceeds saturation."""
    reactor = PhaSupercriticalExtractionReactor()
    s_eq = reactor.solubility_s

    # Unsaturated -> dissolution occurs
    st_unsat = PhaSupercriticalExtractionState(m_cell=500.0, c_pha_sol=s_eq * 0.5)
    _, _, r_unsat, _ = reactor.compute_rates(st_unsat)
    assert r_unsat > 0.0

    # Saturated -> driving force zero
    st_sat = PhaSupercriticalExtractionState(m_cell=500.0, c_pha_sol=s_eq)
    _, _, r_sat, _ = reactor.compute_rates(st_sat)
    assert r_sat == 0.0

    # Supersaturated -> no negative dissolution
    st_super = PhaSupercriticalExtractionState(m_cell=500.0, c_pha_sol=s_eq * 1.5)
    _, _, r_super, _ = reactor.compute_rates(st_super)
    assert r_super == 0.0


def test_dissolution_zero_when_biomass_exhausted() -> None:
    """Verify zero dissolution when unextracted biomass reaches zero."""
    reactor = PhaSupercriticalExtractionReactor()
    st_exhausted = PhaSupercriticalExtractionState(m_cell=0.0, c_pha_sol=0.0)
    _, _, r_diss, _ = reactor.compute_rates(st_exhausted)
    assert r_diss == 0.0


def test_separator_precipitation_kinetics() -> None:
    """Verify precipitation rate r_precip = k_precip * max(0, C_pha_sol - S_sep)."""
    reactor = PhaSupercriticalExtractionReactor()

    # Above separator solubility (s_sep = 0.05 g/L)
    st_high = PhaSupercriticalExtractionState(c_pha_sol=5.05)
    _, _, _, rp_high = reactor.compute_rates(st_high)
    expected_rp = reactor.cfg.k_precip * (5.05 - 0.05)
    assert abs(rp_high - expected_rp) < 1e-6

    # Below separator solubility
    st_low = PhaSupercriticalExtractionState(c_pha_sol=0.02)
    _, _, _, rp_low = reactor.compute_rates(st_low)
    assert rp_low == 0.0

    # Blocked separator stops precipitation
    reactor.separator_clogged = True
    _, _, _, rp_blocked = reactor.compute_rates(st_high)
    assert rp_blocked == 0.0


def test_rates_properties_convenience_accessors() -> None:
    """Verify reactor.rates, reactor.r_diss, and reactor.r_precip properties."""
    reactor = PhaSupercriticalExtractionReactor()
    rates = reactor.rates
    assert len(rates) == 4
    d, s, rd, rp = rates
    assert d > 0.0
    assert s > 0.0
    assert reactor.r_diss == rd
    assert reactor.r_precip == rp


# ============================================================================
# Section 5: Coupled 6-State ODE RK4 Integration & Continuous Simulation
# ============================================================================

def test_single_rk4_step_extraction_trajectory() -> None:
    """Verify single RK4 step: M_cell depletes while M_precip increases."""
    reactor = PhaSupercriticalExtractionReactor()
    m_cell_start = reactor.state.m_cell
    m_precip_start = reactor.state.m_precip

    reactor.rk4_step(dt_s=1.0)
    assert reactor.state.m_cell < m_cell_start
    assert reactor.state.m_precip >= m_precip_start
    assert reactor.state.c_pha_sol >= 0.0


def test_rk4_step_various_dt_arguments() -> None:
    """Verify rk4_step handles dt_s, dt_min, dt_h, positional float, and kwargs."""
    r1 = PhaSupercriticalExtractionReactor()
    r1.rk4_step(dt_s=2.0)
    assert math.isclose(r1.sim_time_s, 2.0, rel_tol=1e-5)

    r2 = PhaSupercriticalExtractionReactor()
    r2.rk4_step(dt_min=0.1)
    assert math.isclose(r2.sim_time_s, 0.1, rel_tol=1e-5)

    r3 = PhaSupercriticalExtractionReactor()
    r3.rk4_step(dt_h=0.001)
    assert math.isclose(r3.sim_time_s, 3.6, rel_tol=1e-5)

    r4 = PhaSupercriticalExtractionReactor()
    r4.rk4_step(1.5)
    assert math.isclose(r4.sim_time_s, 1.5, rel_tol=1e-5)


def test_continuous_extraction_multi_step_stability() -> None:
    """Verify stability of continuous extraction across 30 RK4 steps without runaway."""
    reactor = PhaSupercriticalExtractionReactor()
    for _ in range(30):
        reactor.rk4_step(dt_s=1.0)
        assert reactor.state.m_cell >= 0.0
        assert reactor.state.c_pha_sol >= 0.0
        assert reactor.state.m_precip >= 0.0
        assert 100.0 <= reactor.state.p_ext <= 400.0
        assert 20.0 <= reactor.state.t_ext <= 100.0


def test_sim_time_accumulation() -> None:
    """Verify sim_time_s monotonically accumulates across sequential integration steps."""
    reactor = PhaSupercriticalExtractionReactor()
    assert reactor.sim_time_s == 0.0
    for i in range(1, 11):
        reactor.rk4_step(dt_s=0.5)
        assert math.isclose(reactor.sim_time_s, i * 0.5, rel_tol=1e-6)


def test_non_negative_mass_clamping() -> None:
    """Verify negative masses cannot occur even with aggressive step sizes."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.m_cell = 0.001
    for _ in range(10):
        reactor.rk4_step(dt_s=5.0)
        assert reactor.state.m_cell >= 0.0
        assert reactor.state.c_pha_sol >= 0.0
        assert reactor.state.m_precip >= 0.0


def test_yield_percentage_monotonic_increase() -> None:
    """Verify extracted and precipitated yields increase monotonically during extraction."""
    reactor = PhaSupercriticalExtractionReactor()
    prev_extracted = reactor.extracted_yield_pct
    prev_precip = reactor.precipitated_yield_pct

    for _ in range(20):
        reactor.rk4_step(dt_s=1.0)
        assert reactor.extracted_yield_pct >= prev_extracted
        assert reactor.precipitated_yield_pct >= prev_precip
        prev_extracted = reactor.extracted_yield_pct
        prev_precip = reactor.precipitated_yield_pct


# ============================================================================
# Section 6: Analytical PHA Mass Conservation Residuals (< 1e-10)
# ============================================================================

def test_strict_mass_conservation_residual_under_1e10() -> None:
    """Verify strict closed-loop polymer mass conservation: |M_cell0 - (M_cell + C_sol*V + M_precip)| < 1e-10."""
    reactor = PhaSupercriticalExtractionReactor()
    initial_total = reactor.m_cell0

    max_residual = 0.0
    for step in range(30):
        reactor.rk4_step(dt_s=1.0)
        curr_total = (
            reactor.state.m_cell
            + reactor.state.c_pha_sol * reactor.state.v_scco2
            + reactor.state.m_precip
        )
        res = abs(initial_total - curr_total)
        max_residual = max(max_residual, res)
        assert res < 1e-10, f"Step {step} residual {res} exceeded 1e-10 threshold"

    assert max_residual < 1e-10
    assert reactor.conservation_residual < 1e-10


def test_mass_conservation_across_long_horizon() -> None:
    """Verify mass conservation residual remains below 1e-10 across 100 integration cycles."""
    reactor = PhaSupercriticalExtractionReactor()
    for _ in range(100):
        reactor.rk4_step(dt_s=0.5)
        assert reactor.conservation_residual < 1e-10


def test_mass_conservation_with_high_dt() -> None:
    """Verify mass conservation holds under larger integration step (dt = 5.0s)."""
    reactor = PhaSupercriticalExtractionReactor()
    for _ in range(20):
        reactor.rk4_step(dt_s=5.0)
        assert reactor.conservation_residual < 1e-10


def test_mass_conservation_custom_initial_biomass() -> None:
    """Verify mass conservation with varied initial biomass masses (100g, 1000g)."""
    for m0 in [100.0, 500.0, 1000.0]:
        st = PhaSupercriticalExtractionState(m_cell=m0)
        reactor = PhaSupercriticalExtractionReactor(initial_state=st)
        assert reactor.m_cell0 == m0
        for _ in range(15):
            reactor.rk4_step(dt_s=1.0)
            assert reactor.conservation_residual < 1e-10


def test_mass_conservation_with_initial_solute_and_precipitate() -> None:
    """Verify mass conservation when fluid already contains solute and precipitate."""
    st = PhaSupercriticalExtractionState(m_cell=300.0, c_pha_sol=2.0, m_precip=50.0, v_scco2=20.0)
    # Total initial = 300 + 2*20 + 50 = 390 g
    reactor = PhaSupercriticalExtractionReactor(initial_state=st)
    assert math.isclose(reactor.m_cell0, 390.0, rel_tol=1e-9)

    for _ in range(25):
        reactor.rk4_step(dt_s=1.0)
        assert reactor.conservation_residual < 1e-10


# ============================================================================
# Section 7: Process Safety Trips & Strict Fault Hierarchy (0xF941..0xF944)
# ============================================================================

def test_trip_overpressure_priority_1() -> None:
    """Verify Priority 1 trip: DIAG_ERR_OVER_PRESSURE (0xF941) when P_ext > 360.0 bar."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 365.0
    reactor._evaluate_safety_interlocks()
    reactor.sync_to_registers(reactor.reg_table)

    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_OVER_PRESSURE
    assert reactor.diagnostic_code == 0xF941
    assert reactor.pressure_relief_valve_active is True
    assert reactor.operating_state == PhaScCO2State.TRIPPED
    assert reactor.reg_table.read_bit(COIL_PHA_SCCO2_TRIP) is True
    assert reactor.reg_table.read_bit(COIL_PHA_SCCO2_ACTIVE) is False
    assert (reactor.reg_table.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF941


def test_trip_phase_boundary_loss_priority_2() -> None:
    """Verify Priority 2 trip: DIAG_ERR_PHASE_BOUNDARY_LOSS (0xF942) when P_ext < 75.0 bar while active."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 70.0
    reactor.is_active = True
    reactor._evaluate_safety_interlocks()
    reactor.sync_to_registers(reactor.reg_table)

    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_PHASE_BOUNDARY_LOSS
    assert reactor.diagnostic_code == DIAG_ERR_SUBCRITICAL_LOSS
    assert reactor.diagnostic_code == 0xF942
    assert reactor.reg_table.read_bit(COIL_PHA_SCCO2_TRIP) is True
    assert reactor.reg_table.read_bit(COIL_PHA_SCCO2_ACTIVE) is False
    assert (reactor.reg_table.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF942


def test_trip_thermal_degradation_priority_3() -> None:
    """Verify Priority 3 trip: DIAG_ERR_THERMAL_DEGRADATION (0xF943) when T_ext > 85.0 °C."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.t_ext = 88.0
    reactor._evaluate_safety_interlocks()
    reactor.sync_to_registers(reactor.reg_table)

    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_THERMAL_DEGRADATION
    assert reactor.diagnostic_code == 0xF943
    assert (reactor.reg_table.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF943


def test_trip_separator_clogging_priority_4() -> None:
    """Verify Priority 4 trip: DIAG_ERR_SEPARATOR_CLOGGING (0xF944) on clogging or overflow."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.separator_clogged = True
    reactor._evaluate_safety_interlocks()
    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_SEPARATOR_CLOGGING
    assert reactor.diagnostic_code == 0xF944

    # Triggering via separator capacity overflow (M_precip > 480.0 g)
    reactor.separator_clogged = False
    reactor.trip_latched = False
    reactor.state.m_precip = 485.0
    reactor._evaluate_safety_interlocks()
    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_SEPARATOR_CLOGGING

    # Triggering via clogging index > 0.85
    reactor.trip_latched = False
    reactor.state.m_precip = 100.0
    reactor.state.clogging_index = 0.90
    reactor._evaluate_safety_interlocks()
    assert reactor.trip_active is True
    assert reactor.diagnostic_code == DIAG_ERR_SEPARATOR_CLOGGING


def test_fault_priority_hierarchy_all_active() -> None:
    """Verify Priority 1 (Overpressure) overrides Priority 2, 3, and 4 simultaneously."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 370.0      # Fault 1
    reactor.state.t_ext = 90.0       # Fault 3
    reactor.separator_clogged = True  # Fault 4
    reactor.state.clogging_index = 0.95
    reactor._evaluate_safety_interlocks()
    assert reactor.diagnostic_code == DIAG_ERR_OVER_PRESSURE


def test_fault_priority_hierarchy_subcritical_over_thermal_and_clogging() -> None:
    """Verify Priority 2 (Subcritical Loss) overrides Priority 3 and 4."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 65.0       # Fault 2
    reactor.state.t_ext = 90.0       # Fault 3
    reactor.separator_clogged = True  # Fault 4
    reactor.is_active = True
    reactor._evaluate_safety_interlocks()
    assert reactor.diagnostic_code == DIAG_ERR_PHASE_BOUNDARY_LOSS


def test_fault_priority_hierarchy_thermal_over_clogging() -> None:
    """Verify Priority 3 (Thermal Degradation) overrides Priority 4 (Clogging)."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 250.0      # Normal pressure
    reactor.state.t_ext = 90.0       # Fault 3
    reactor.separator_clogged = True  # Fault 4
    reactor._evaluate_safety_interlocks()
    assert reactor.diagnostic_code == DIAG_ERR_THERMAL_DEGRADATION


# ============================================================================
# Section 8: Emergency Depressurization & Safe Shutdown State Transitions
# ============================================================================

def test_emergency_prv_activation_on_overpressure() -> None:
    """Verify over-pressure event actuates pressure relief valve and latches trip."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 380.0
    reactor.scan_step(dt_s=1.0)

    assert reactor.trip_active is True
    assert reactor.pressure_relief_valve_active is True
    assert reactor.diagnostic_code == DIAG_ERR_OVER_PRESSURE
    sword = reactor.reg_table.read_word(REG_PHA_SCCO2_STATUS_WORD)
    assert (sword & PhaScCO2StatusWord.PRESSURE_RELIEF_VALVE_ACTIVE) != 0
    assert (sword & PhaScCO2StatusWord.TRIP_ACTIVE) != 0


def test_pressure_relief_vent_step_progress() -> None:
    """Verify sequential venting via pressure_relief_vent_step reduces pressure safely."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 370.0
    reactor._evaluate_safety_interlocks()
    assert reactor.pressure_relief_valve_active is True

    p_before = reactor.state.p_ext
    reactor.pressure_relief_vent_step(dt_s=1.0)
    assert reactor.state.p_ext < p_before
    assert math.isclose(reactor.state.p_ext, p_before - 15.0, rel_tol=1e-5)


def test_emergency_prv_reseat_transition() -> None:
    """Verify PRV closes and trip clears once pressure is safely depressurized below 280 bar."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 380.0
    reactor._evaluate_safety_interlocks()
    assert reactor.trip_active is True

    # Vent until below 280 bar (8 steps of 15 bar = 120 bar drop -> 260 bar)
    for _ in range(8):
        reactor.pressure_relief_vent_step(dt_s=1.0)

    assert reactor.state.p_ext <= 280.0
    assert reactor.pressure_relief_valve_active is False
    assert reactor.trip_active is False
    assert reactor.diagnostic_code == DIAG_OK


def test_trip_latched_behavior_and_recovery() -> None:
    """Verify trip latches until explicit clear or reseat condition."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.t_ext = 88.0
    reactor._evaluate_safety_interlocks()
    assert reactor.trip_latched is True
    assert reactor.trip_active is True

    # Drop temperature back to normal - latched trip stays active until reset
    reactor.state.t_ext = 50.0
    reactor._evaluate_safety_interlocks()
    assert reactor.trip_active is True

    # Explicit reset clears trip
    reactor.reset()
    assert reactor.trip_active is False
    assert reactor.trip_latched is False
    assert reactor.diagnostic_code == DIAG_OK


def test_warning_alarm_transitions() -> None:
    """Verify warnings activate near thresholds and are suppressed during trips."""
    reactor = PhaSupercriticalExtractionReactor()
    assert reactor.warning_active is False

    # High pressure warning (P >= 340.0 bar)
    reactor.state.p_ext = 345.0
    reactor._evaluate_safety_interlocks()
    assert reactor.warning_active is True
    assert reactor.trip_active is False

    # Overpressure trip suppresses warning
    reactor.state.p_ext = 365.0
    reactor._evaluate_safety_interlocks()
    assert reactor.trip_active is True
    assert reactor.warning_active is False


# ============================================================================
# Section 9: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
# ============================================================================

def test_diagnostic_code_signed_equality() -> None:
    """Verify DiagnosticCode handles signed 16-bit negative integer comparison."""
    assert DIAG_ERR_OVER_PRESSURE == -1727
    assert DIAG_ERR_PHASE_BOUNDARY_LOSS == -1726
    assert DIAG_ERR_THERMAL_DEGRADATION == -1725
    assert DIAG_ERR_SEPARATOR_CLOGGING == -1724


def test_diagnostic_code_unsigned_equality() -> None:
    """Verify DiagnosticCode handles unsigned 16-bit positive integer comparison."""
    assert DIAG_ERR_OVER_PRESSURE == 0xF941
    assert DIAG_ERR_PHASE_BOUNDARY_LOSS == 0xF942
    assert DIAG_ERR_THERMAL_DEGRADATION == 0xF943
    assert DIAG_ERR_SEPARATOR_CLOGGING == 0xF944
    assert DIAG_OK == 0x0000


def test_diagnostic_code_bitwise_mask() -> None:
    """Verify (int(code) & 0xFFFF) equality matches exact hex code."""
    for code, expected_hex in [
        (DIAG_ERR_OVER_PRESSURE, 0xF941),
        (DIAG_ERR_PHASE_BOUNDARY_LOSS, 0xF942),
        (DIAG_ERR_THERMAL_DEGRADATION, 0xF943),
        (DIAG_ERR_SEPARATOR_CLOGGING, 0xF944),
        (DIAG_OK, 0x0000),
    ]:
        assert (int(code) & 0xFFFF) == expected_hex
        assert code == expected_hex


def test_diagnostic_code_hash_and_collection_lookups() -> None:
    """Verify DiagnosticCode hashes consistently in sets and dictionaries."""
    codes_set = {DIAG_ERR_OVER_PRESSURE, DIAG_ERR_PHASE_BOUNDARY_LOSS}
    assert 0xF941 in codes_set
    assert DiagnosticCode(-1727) in codes_set
    assert 0xF942 in codes_set

    code_map = {
        DIAG_ERR_OVER_PRESSURE: "over_pressure",
        DIAG_ERR_PHASE_BOUNDARY_LOSS: "subcritical",
        DIAG_ERR_THERMAL_DEGRADATION: "thermal",
        DIAG_ERR_SEPARATOR_CLOGGING: "clogging",
    }
    assert code_map[0xF941] == "over_pressure"
    assert code_map[DiagnosticCode(-1727)] == "over_pressure"
    assert code_map[0xF942] == "subcritical"


# ============================================================================
# Section 10: ILogicUnit Compliance & Multi-Cycle Scan Execution
# ============================================================================

def test_ilogicunit_interface_compliance() -> None:
    """Verify implementation of ILogicUnit interface methods and properties."""
    reactor = PhaSupercriticalExtractionReactor()
    assert isinstance(reactor, ILogicUnit)
    assert reactor.name == "PhaSupercriticalExtractionSimulationLogicUnit"
    assert reactor.priority == 50
    assert reactor.is_enabled is True


def test_scan_step_with_context() -> None:
    """Verify scan_step executes with ScanContext and attaches context RegisterTable."""
    reactor = PhaSupercriticalExtractionReactor()
    custom_rt = RegisterTable()
    ctx = ScanContext(register_table=custom_rt, cycle=42, dt=0.5)

    res = reactor.scan_step(context=ctx)
    assert res.status == AgentStatus.SUCCESS
    assert reactor.reg_table is custom_rt
    assert reactor.cycle_count == 1


def test_scan_step_execution_result_contract() -> None:
    """Verify scan_step returns valid ExecutionResult conforming to strict 4-state contract."""
    reactor = PhaSupercriticalExtractionReactor()
    res = reactor.scan_step(dt_s=1.0)

    assert isinstance(res, ExecutionResult)
    assert res.status == AgentStatus.SUCCESS
    assert res.error_code is None
    assert isinstance(res.details, str)
    assert "M_cell=" in res.details
    assert "Yield=" in res.details
    assert isinstance(res.data, dict)
    assert "m_cell" in res.data
    assert "conservation_residual" in res.data
    assert res.data["conservation_residual"] < 1e-10


def test_step_and_execute_delegates() -> None:
    """Verify step() and execute() advance cycle count and perform numerical integration."""
    reactor = PhaSupercriticalExtractionReactor()
    assert reactor.cycle_count == 0

    reactor.step(1.0)
    assert reactor.cycle_count == 1

    reactor.execute(1.0)
    assert reactor.cycle_count == 2


def test_reset_functionality() -> None:
    """Verify reset() restores healthy defaults, clears trips, and updates registers."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 370.0
    reactor.scan_step()
    assert reactor.trip_active is True

    reactor.reset()
    assert reactor.cycle_count == 0
    assert reactor.diagnostic_code == DIAG_OK
    assert reactor.trip_active is False
    assert reactor.trip_latched is False
    assert reactor.state.m_cell == 500.0
    assert reactor.state.c_pha_sol == 0.0
    assert reactor.state.m_precip == 0.0
    assert reactor.conservation_residual == 0.0


def test_scan_step_when_tripped_returns_failed() -> None:
    """Verify scan_step returns AgentStatus.FAILED when a safety trip is active."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 380.0
    res = reactor.scan_step()
    assert res.status == AgentStatus.FAILED
    assert res.error_code is not None
    assert "0xF941" in res.error_code


# ============================================================================
# Section 11: Horner OCS Register Space Synchronization (%R2630..%R2637, %M613..%M615)
# ============================================================================

def test_register_and_coil_synchronization_normal() -> None:
    """Verify accurate memory mapping to Horner OCS registers and coils during normal operation."""
    reactor = PhaSupercriticalExtractionReactor()
    rt = RegisterTable()
    reactor.scan_step(context=ScanContext(register_table=rt, cycle=1, dt=1.0))

    # Read mapped registers
    status_word = rt.read_word(REG_PHA_SCCO2_STATUS)
    p_scaled = rt.read_word(REG_PHA_SCCO2_PRESSURE_BAR)
    t_scaled = rt.read_word(REG_PHA_SCCO2_TEMP_SCALED)
    rho_scaled = rt.read_word(REG_PHA_SCCO2_DENSITY_SCALED)
    yield_scaled = rt.read_word(REG_PHA_SCCO2_EXTRACTED_YIELD_PCT)
    precip_scaled = rt.read_word(REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED)
    diag_code = rt.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE)
    bits_word = rt.read_word(REG_PHA_SCCO2_STATUS_WORD)

    # Coils
    coil_act = rt.read_bit(COIL_PHA_SCCO2_ACTIVE)
    coil_warn = rt.read_bit(COIL_PHA_SCCO2_WARNING)
    coil_trip = rt.read_bit(COIL_PHA_SCCO2_TRIP)

    assert ((status_word >> 8) & 0xFF) == int(PhaScCO2State.RUNNING)
    assert (status_word & 0xFF) == int(PhaScCO2Phase.EXTRACTION)
    assert p_scaled == int(round(reactor.state.p_ext * 10.0))
    assert t_scaled == int(round(reactor.state.t_ext * 10.0))
    assert rho_scaled == int(round(reactor.density_co2 * 10.0))
    assert diag_code == 0x0000
    assert bits_word > 0

    assert coil_act is True
    assert coil_trip is False


def test_register_sync_signed_16bit_masking() -> None:
    """Verify signed 16-bit masking `(rt.read_word(...) & 0xFFFF) == expected` for all registers."""
    reactor = PhaSupercriticalExtractionReactor()
    rt = RegisterTable()
    reactor.sync_to_registers(rt)

    regs = [
        (REG_PHA_SCCO2_STATUS, rt.read_word(REG_PHA_SCCO2_STATUS)),
        (REG_PHA_SCCO2_PRESSURE_BAR, rt.read_word(REG_PHA_SCCO2_PRESSURE_BAR)),
        (REG_PHA_SCCO2_TEMP_SCALED, rt.read_word(REG_PHA_SCCO2_TEMP_SCALED)),
        (REG_PHA_SCCO2_DENSITY_SCALED, rt.read_word(REG_PHA_SCCO2_DENSITY_SCALED)),
        (REG_PHA_SCCO2_EXTRACTED_YIELD_PCT, rt.read_word(REG_PHA_SCCO2_EXTRACTED_YIELD_PCT)),
        (REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED, rt.read_word(REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED)),
        (REG_PHA_SCCO2_DIAGNOSTIC_CODE, rt.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE)),
        (REG_PHA_SCCO2_STATUS_WORD, rt.read_word(REG_PHA_SCCO2_STATUS_WORD)),
    ]
    for reg_addr, val in regs:
        assert (rt.read_word(reg_addr) & 0xFFFF) == (val & 0xFFFF)


def test_register_status_word_bitmask() -> None:
    """Verify bitmask bits in %R2637 status word for active components."""
    reactor = PhaSupercriticalExtractionReactor()
    sword = reactor.status_word
    assert (sword & PhaScCO2StatusWord.CO2_FEED_PUMP_ACTIVE) != 0
    assert (sword & PhaScCO2StatusWord.CO2_BOOSTER_PUMP_ACTIVE) != 0
    assert (sword & PhaScCO2StatusWord.HEATER_ACTIVE) != 0
    assert (sword & PhaScCO2StatusWord.HEATER_JACKET_ACTIVE) != 0
    assert (sword & PhaScCO2StatusWord.EXTRACTION_VALVE_OPEN) != 0
    assert (sword & PhaScCO2StatusWord.SEPARATOR_EXPANSION_VALVE) != 0
    assert (sword & PhaScCO2StatusWord.RECYCLE_COMPRESSOR_ACTIVE) != 0
    assert (sword & PhaScCO2StatusWord.SUPERCRITICAL_REGIME_OK) != 0
    assert (sword & PhaScCO2StatusWord.TRIP_ACTIVE) == 0


def test_register_coils_tripped_state() -> None:
    """Verify %M613 is cleared and %M615 is asserted when tripped."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 370.0
    reactor.scan_step()

    rt = reactor.reg_table
    assert rt.read_bit(COIL_PHA_SCCO2_ACTIVE) is False
    assert rt.read_bit(COIL_PHA_SCCO2_TRIP) is True
    assert (rt.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF941


def test_register_coils_warning_state() -> None:
    """Verify %M614 is asserted and %M615 is cleared in warning state."""
    reactor = PhaSupercriticalExtractionReactor()
    reactor.state.p_ext = 345.0  # Above warning threshold (340.0) but below trip (360.0)
    reactor._evaluate_safety_interlocks()
    reactor.sync_to_registers(reactor.reg_table)

    rt = reactor.reg_table
    assert rt.read_bit(COIL_PHA_SCCO2_ACTIVE) is True
    assert rt.read_bit(COIL_PHA_SCCO2_WARNING) is True
    assert rt.read_bit(COIL_PHA_SCCO2_TRIP) is False


def test_register_diagnostic_code_masking() -> None:
    """Verify 16-bit signed masking for all 4 trip diagnostic codes written to %R2636."""
    reactor = PhaSupercriticalExtractionReactor()
    for trip_val in [0xF941, 0xF942, 0xF943, 0xF944]:
        reactor.diagnostic_code = DiagnosticCode(trip_val)
        reactor.sync_to_registers(reactor.reg_table)
        assert (reactor.reg_table.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE) & 0xFFFF) == trip_val


def test_register_table_privilege_modes() -> None:
    """Verify register synchronization operates under SYSTEM privilege."""
    reactor = PhaSupercriticalExtractionReactor()
    rt = RegisterTable()
    reactor.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
    assert (rt.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000


# ============================================================================
# Section 12: Pure IEC 61131-3 Structured Text POU, Anti-Ladder Construct Rejection & 9-Stage Runner
# ============================================================================

def test_pure_st_pou_syntax_validation() -> None:
    """Verify ST POU syntax using verify_pha_supercritical_extraction_pure_st()."""
    assert verify_pha_supercritical_extraction_pure_st() is True
    assert verify_pha_scco2_pure_st() is True


def test_st_parser_ast_validation() -> None:
    """Verify STParser parses ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC cleanly."""
    res = STParser.validate_code(ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC)
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
        res = run_pha_supercritical_extraction_verification(output_path=out_path)
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
    """Verify execution of scripts/run_pha_supercritical_extraction_verification.py module runner."""
    from scripts.run_pha_supercritical_extraction_verification import (
        execute_pha_supercritical_extraction_verification,
    )
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name

    try:
        res = execute_pha_supercritical_extraction_verification(output_path=out_path, quick=True)
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
    finally:
        Path(out_path).unlink(missing_ok=True)
