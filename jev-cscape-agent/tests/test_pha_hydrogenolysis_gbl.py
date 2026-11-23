"""Industrial Catalytic Polyhydroxyalkanoate Hydrogenolysis & Gamma-Butyrolactone (GBL) Synthesis CSTR ODE Simulation Unit Test Suite (W320).

Work Package: W320 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification test classes (100+ test cases):
1. TestPhysicalConstantsAndRegisters: Physical constants, stoichiometry, register %R2810..%R2817, coils %M655..%M657, signed 16-bit safe comparisons.
2. TestReactionRatesAndSelectivity: Catalytic GBL reaction rates, BDO byproduct, selectivity calculations, Langmuir-Hinshelwood kinetics.
3. TestCoupled6StateDerivatives: 6-state CSTR ODE derivative calculations, mass/energy balance, volume/concentration non-negativity.
4. TestRK4IntegrationStability: RK4 stability, step size variation (dt=0.01s to 0.2s), trajectory smoothness, and class aliases.
5. TestMassBalanceConservation: Continuous carbon backbone mass conservation residuals (< 1e-10) across diverse conversion regimes.
6. TestThermalExcursionTrip: Thermal excursion trip (0xF9A1, %M657 emergency quench asserted, %M656 feed valve de-asserted).
7. TestReactorOverpressureTrip: Reactor overpressure vent trip (0xF9A2, %M657 asserted, vent depressurization dynamics).
8. TestCatalystDeactivationAndCoolingFailureTrips: Catalyst deactivation (0xF9A3), cooling failure (0xF9A4), mass divergence (0xF9A5), fault priority hierarchy.
9. TestRegisterTableSynchronization: Horner OCS memory sync across %R2810..%R2817 and %M655..%M657 with signed 16-bit masking.
10. TestPureStructuredTextPOU: Pure IEC 61131-3 ST POU validation and anti-ladder rejection of all 9 constructs.
11. TestILogicUnitComplianceAndSoak: ILogicUnit scan step compliance, reset behavior, and 100-cycle simulation soak with memory profiling.
12. TestVerificationRunnerAndCLI: Deterministic 9-stage verification runner test and CLI interop (pass tempfile for --output!).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.pha_hydrogenolysis_gbl import (
    COIL_PHA_GBL_ACTIVE,
    COIL_PHA_GBL_EMERGENCY,
    COIL_PHA_GBL_EMERGENCY_QUENCH,
    COIL_PHA_GBL_FEED,
    COIL_PHA_GBL_FEED_VALVE,
    COIL_PHA_GBL_QUENCH,
    COIL_PHA_GBL_REACTOR_ACTIVE,
    COIL_PHA_GBL_RUNNING,
    COIL_PHA_GBL_VALVE,
    DIAG_ERR_CATALYST,
    DIAG_ERR_CATALYST_DEACTIVATION,
    DIAG_ERR_COKING,
    DIAG_ERR_COOLING,
    DIAG_ERR_COOLING_DUTY,
    DIAG_ERR_COOLING_FAILURE,
    DIAG_ERR_DEACTIVATED,
    DIAG_ERR_DEACTIVATION,
    DIAG_ERR_EXCURSION,
    DIAG_ERR_MASS_BALANCE,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_MASS_DIVERGENCE,
    DIAG_ERR_OVERHEAT,
    DIAG_ERR_OVERPRESSURE,
    DIAG_ERR_OVERPRESSURE_VENT,
    DIAG_ERR_PRESSURE,
    DIAG_ERR_RUNAWAY,
    DIAG_ERR_THERMAL,
    DIAG_ERR_THERMAL_EXCURSION,
    DIAG_ERR_VENT,
    DIAG_OK,
    DiagnosticCode,
    MW_BDO,
    MW_CARBON,
    MW_GBL,
    MW_H2,
    MW_METHANOL,
    MW_SUCCINATE_PRECURSOR,
    MW_WATER,
    PHA_GBL_CONTROL_POU,
    PHA_GBL_PURE_ST_POU,
    PHA_HYDROGENOLYSIS_GBL_CONTROL_POU,
    PHA_HYDROGENOLYSIS_GBL_PURE_ST_POU,
    PHAGBLConfig,
    PHAGBLDiagnosticCode,
    PHAGBLEngine,
    PHAGBLSimulator,
    PHAGBLState,
    PHAGBLStatusBits,
    PHAGBLStatusWord,
    PHAHydrogenolysisGBLConfig,
    PHAHydrogenolysisGBLControl,
    PHAHydrogenolysisGBLDiagnosticCode,
    PHAHydrogenolysisGBLEngine,
    PHAHydrogenolysisGBLLogicUnit,
    PHAHydrogenolysisGBLParameters,
    PHAHydrogenolysisGBLReactor,
    PHAHydrogenolysisGBLSimulator,
    PHAHydrogenolysisGBLState,
    PHAHydrogenolysisGBLStateModel,
    PHAHydrogenolysisGBLStatusBits,
    PHAHydrogenolysisGBLStatusWord,
    PhaGBLConfig,
    PhaGBLDiagnosticCode,
    PhaGBLEngine,
    PhaGBLSimulator,
    PhaGBLState,
    PhaGBLStatusBits,
    PhaGBLStatusWord,
    PhaHydrogenolysisGBLConfig,
    PhaHydrogenolysisGBLDiagnosticCode,
    PhaHydrogenolysisGBLEngine,
    PhaHydrogenolysisGBLLogicUnit,
    PhaHydrogenolysisGBLParameters,
    PhaHydrogenolysisGBLReactor,
    PhaHydrogenolysisGBLSimulator,
    PhaHydrogenolysisGBLState,
    PhaHydrogenolysisGBLStateModel,
    PhaHydrogenolysisGBLStatusBits,
    PhaHydrogenolysisGBLStatusWord,
    R_GAS_CONSTANT,
    REG_PHA_GBL_ACTIVITY,
    REG_PHA_GBL_CATALYST_ACTIVITY,
    REG_PHA_GBL_CONV,
    REG_PHA_GBL_CONVERSION,
    REG_PHA_GBL_COOLING,
    REG_PHA_GBL_COOLING_DUTY_KW,
    REG_PHA_GBL_DIAG,
    REG_PHA_GBL_DIAGNOSTIC_CODE,
    REG_PHA_GBL_DUTY,
    REG_PHA_GBL_ESTER_CONVERSION,
    REG_PHA_GBL_FLOW,
    REG_PHA_GBL_PRESSURE,
    REG_PHA_GBL_P_REACTOR,
    REG_PHA_GBL_REACTOR_PRESSURE,
    REG_PHA_GBL_REACTOR_TEMP,
    REG_PHA_GBL_REACTOR_TEMPERATURE,
    REG_PHA_GBL_RECIRC,
    REG_PHA_GBL_RECIRCULATION_FLOW,
    REG_PHA_GBL_TEMP,
    REG_PHA_GBL_T_REACTOR,
    REG_PHA_GBL_YIELD,
    REG_PHA_GBL_YIELD_PERCENT,
    ST_PROGRAM_PHA_HYDROGENOLYSIS_GBL_CONTROL,
    T_ZERO_CELSIUS,
    run_pha_gbl_verification,
    run_pha_hydrogenolysis_gbl_verification,
    verify_pha_gbl_pure_st,
    verify_pha_hydrogenolysis_gbl_pure_st,
)


# ============================================================================
# 1. TestPhysicalConstantsAndRegisters
# ============================================================================

class TestPhysicalConstantsAndRegisters:
    """Validate stoichiometry, molecular weights, register mappings, coils, and signed 16-bit diagnostic codes."""

    def test_molecular_weights_and_constants(self) -> None:
        """Verify molecular weights of precursor, GBL, BDO, water, H2, methanol, carbon, and universal constants."""
        assert math.isclose(MW_SUCCINATE_PRECURSOR, 146.14, rel_tol=1e-4)
        assert math.isclose(MW_GBL, 86.09, rel_tol=1e-4)
        assert math.isclose(MW_BDO, 90.12, rel_tol=1e-4)
        assert math.isclose(MW_WATER, 18.015, rel_tol=1e-4)
        assert math.isclose(MW_H2, 2.016, rel_tol=1e-4)
        assert math.isclose(MW_METHANOL, 32.04, rel_tol=1e-4)
        assert math.isclose(MW_CARBON, 12.011, rel_tol=1e-4)
        assert math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-6)

    def test_reaction_stoichiometry_and_carbon_conservation(self) -> None:
        """Verify stoichiometry and carbon balance: Precursor + 2 H2 -> GBL + 2 MeOH + H2O and GBL + 2 H2 -> BDO."""
        # Overall reaction: C6H10O4 (DMS, 6 C) + 2 H2 -> C4H6O2 (GBL, 4 C) + 2 CH3OH (2 C) + H2O
        c_prec = 6
        c_gbl = 4
        c_bdo = 4
        c_meoh = 1
        assert c_prec == c_gbl + 2 * c_meoh
        assert c_prec == c_bdo + 2 * c_meoh
        # C4 carbon backbone conservation (Precursor core C4 -> GBL C4 -> BDO C4)
        c4_core = 4
        assert c4_core == c_gbl == c_bdo

    def test_register_address_constants_and_aliases(self) -> None:
        """Verify Horner OCS word register addresses %R2810..%R2817 and string aliases."""
        assert REG_PHA_GBL_REACTOR_TEMP == "%R2810"
        assert REG_PHA_GBL_TEMP == "%R2810"
        assert REG_PHA_GBL_T_REACTOR == "%R2810"
        assert REG_PHA_GBL_REACTOR_TEMPERATURE == "%R2810"

        assert REG_PHA_GBL_REACTOR_PRESSURE == "%R2811"
        assert REG_PHA_GBL_PRESSURE == "%R2811"
        assert REG_PHA_GBL_P_REACTOR == "%R2811"

        assert REG_PHA_GBL_ESTER_CONVERSION == "%R2812"
        assert REG_PHA_GBL_CONVERSION == "%R2812"
        assert REG_PHA_GBL_CONV == "%R2812"

        assert REG_PHA_GBL_YIELD_PERCENT == "%R2813"
        assert REG_PHA_GBL_YIELD == "%R2813"

        assert REG_PHA_GBL_RECIRCULATION_FLOW == "%R2814"
        assert REG_PHA_GBL_FLOW == "%R2814"
        assert REG_PHA_GBL_RECIRC == "%R2814"

        assert REG_PHA_GBL_CATALYST_ACTIVITY == "%R2815"
        assert REG_PHA_GBL_ACTIVITY == "%R2815"

        assert REG_PHA_GBL_COOLING_DUTY_KW == "%R2816"
        assert REG_PHA_GBL_COOLING == "%R2816"
        assert REG_PHA_GBL_DUTY == "%R2816"

        assert REG_PHA_GBL_DIAGNOSTIC_CODE == "%R2817"
        assert REG_PHA_GBL_DIAG == "%R2817"

    def test_discrete_coils_constants_and_aliases(self) -> None:
        """Verify Horner OCS discrete coil addresses %M655..%M657 and string aliases."""
        assert COIL_PHA_GBL_REACTOR_ACTIVE == "%M655"
        assert COIL_PHA_GBL_ACTIVE == "%M655"
        assert COIL_PHA_GBL_RUNNING == "%M655"

        assert COIL_PHA_GBL_FEED_VALVE == "%M656"
        assert COIL_PHA_GBL_VALVE == "%M656"
        assert COIL_PHA_GBL_FEED == "%M656"

        assert COIL_PHA_GBL_EMERGENCY_QUENCH == "%M657"
        assert COIL_PHA_GBL_QUENCH == "%M657"
        assert COIL_PHA_GBL_EMERGENCY == "%M657"

    def test_diagnostic_codes_values_and_aliases(self) -> None:
        """Verify hexadecimal diagnostic error constants and convenience aliases."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_THERMAL_EXCURSION == 0xF9A1
        assert DIAG_ERR_EXCURSION == 0xF9A1
        assert DIAG_ERR_THERMAL == 0xF9A1
        assert DIAG_ERR_RUNAWAY == 0xF9A1
        assert DIAG_ERR_OVERHEAT == 0xF9A1

        assert DIAG_ERR_OVERPRESSURE_VENT == 0xF9A2
        assert DIAG_ERR_OVERPRESSURE == 0xF9A2
        assert DIAG_ERR_PRESSURE == 0xF9A2
        assert DIAG_ERR_VENT == 0xF9A2

        assert DIAG_ERR_CATALYST_DEACTIVATION == 0xF9A3
        assert DIAG_ERR_DEACTIVATION == 0xF9A3
        assert DIAG_ERR_CATALYST == 0xF9A3
        assert DIAG_ERR_DEACTIVATED == 0xF9A3
        assert DIAG_ERR_COKING == 0xF9A3

        assert DIAG_ERR_COOLING_FAILURE == 0xF9A4
        assert DIAG_ERR_COOLING == 0xF9A4
        assert DIAG_ERR_COOLING_DUTY == 0xF9A4

        assert DIAG_ERR_MASS_BALANCE_DIVERGENCE == 0xF9A5
        assert DIAG_ERR_MASS_DIVERGENCE == 0xF9A5
        assert DIAG_ERR_MASS_BALANCE == 0xF9A5

    def test_diagnostic_code_signed_safe_equality(self) -> None:
        """Verify DiagnosticCode handles signed/unsigned 16-bit comparisons and edge cases."""
        # Unsigned 0xF9A1 is signed -1631 in 16-bit two's complement
        code_a1 = DiagnosticCode(0xF9A1)
        assert code_a1 == 0xF9A1
        assert code_a1 == -1631
        assert code_a1 == DiagnosticCode(0xF9A1)
        assert hash(code_a1) == hash(0xF9A1)

        # Unsigned 0xF9A2 is signed -1630
        code_a2 = DiagnosticCode(0xF9A2)
        assert code_a2 == 0xF9A2
        assert code_a2 == -1630

        # Unsigned 0xF9A3 is signed -1629
        code_a3 = DiagnosticCode(0xF9A3)
        assert code_a3 == 0xF9A3
        assert code_a3 == -1629

        # Unsigned 0xF9A4 is signed -1628
        code_a4 = DiagnosticCode(0xF9A4)
        assert code_a4 == 0xF9A4
        assert code_a4 == -1628

        # Unsigned 0xF9A5 is signed -1627
        code_a5 = DiagnosticCode(0xF9A5)
        assert code_a5 == 0xF9A5
        assert code_a5 == -1627

        # Non-integer comparison returns False
        assert code_a1 != "0xF9A1"
        assert code_a1 != 3.14

    def test_diagnostic_code_string_and_repr(self) -> None:
        """Verify string formatting and representation of DiagnosticCode instances."""
        code_a1 = DiagnosticCode(0xF9A1)
        assert str(code_a1) == "0xF9A1"
        assert repr(code_a1) == "DiagnosticCode(0xF9A1)"

        code_ok = DiagnosticCode(0x0000)
        assert str(code_ok) == "0x0000"
        assert repr(code_ok) == "DiagnosticCode(0x0000)"

    def test_status_word_bitmask_flags(self) -> None:
        """Verify PHAHydrogenolysisGBLStatusWord bitmask definitions and aliases."""
        assert PHAHydrogenolysisGBLStatusWord.REACTOR_ACTIVE == 1 << 0
        assert PHAHydrogenolysisGBLStatusWord.FEED_VALVE == 1 << 1
        assert PHAHydrogenolysisGBLStatusWord.EMERGENCY_QUENCH == 1 << 2
        assert PHAHydrogenolysisGBLStatusWord.COOLING_JACKET == 1 << 3
        assert PHAHydrogenolysisGBLStatusWord.TEMP_WARN == 1 << 4
        assert PHAHydrogenolysisGBLStatusWord.PRESSURE_WARN == 1 << 5
        assert PHAHydrogenolysisGBLStatusWord.CATALYST_WARN == 1 << 6
        assert PHAHydrogenolysisGBLStatusWord.EMERGENCY_TRIP == 1 << 7

        assert PHAHydrogenolysisGBLStatusWord is PhaHydrogenolysisGBLStatusWord
        assert PHAHydrogenolysisGBLStatusWord is PHAGBLStatusWord
        assert PHAHydrogenolysisGBLStatusBits is PHAHydrogenolysisGBLStatusWord
        assert PhaHydrogenolysisGBLStatusBits is PHAHydrogenolysisGBLStatusWord
        assert PHAGBLStatusBits is PHAHydrogenolysisGBLStatusWord
        assert PhaGBLStatusBits is PHAHydrogenolysisGBLStatusWord

    def test_state_initialization_defaults_and_properties(self) -> None:
        """Verify PHAHydrogenolysisGBLState initial nominal values and property accessors."""
        st = PHAHydrogenolysisGBLState()
        assert math.isclose(st.c_succinate_precursor, 2.80, rel_tol=1e-4)
        assert math.isclose(st.c_gbl_product, 0.08, rel_tol=1e-4)
        assert math.isclose(st.c_bdo_byproduct, 0.02, rel_tol=1e-4)
        assert math.isclose(st.c_water, 0.05, rel_tol=1e-4)
        assert math.isclose(st.t_reactor_kelvin, 463.15, rel_tol=1e-4)
        assert math.isclose(st.a_catalyst, 1.00, rel_tol=1e-4)
        assert math.isclose(st.p_reactor, 45.0, rel_tol=1e-4)
        assert math.isclose(st.recirculation_flow_l_min, 120.0, rel_tol=1e-4)
        assert math.isclose(st.cooling_duty_kw, 45.0, rel_tol=1e-4)
        assert math.isclose(st.dt_reactor_dt, 0.0, abs_tol=1e-6)

        # Property aliases
        assert st.C_succinate_precursor == st.c_succinate_precursor
        assert st.succinate_precursor == st.c_succinate_precursor
        assert st.c_precursor == st.c_succinate_precursor
        assert st.C_precursor == st.c_succinate_precursor

        assert st.C_gbl_product == st.c_gbl_product
        assert st.gbl_product == st.c_gbl_product
        assert st.c_gbl == st.c_gbl_product
        assert st.C_gbl == st.c_gbl_product

        assert st.C_bdo_byproduct == st.c_bdo_byproduct
        assert st.bdo_byproduct == st.c_bdo_byproduct
        assert st.c_bdo == st.c_bdo_byproduct
        assert st.C_bdo == st.c_bdo_byproduct

        assert st.C_water == st.c_water
        assert st.water == st.c_water
        assert st.c_h2o == st.c_water

        assert st.T_reactor_kelvin == st.t_reactor_kelvin
        assert st.T_reactor == st.t_reactor_kelvin
        assert st.t_reactor == st.t_reactor_kelvin
        assert st.reactor_temp == st.t_reactor_kelvin

        assert st.a_cat == st.a_catalyst
        assert st.catalyst_activity == st.a_catalyst

        assert st.P_reactor == st.p_reactor
        assert st.reactor_pressure == st.p_reactor
        assert st.recirculation_flow == st.recirculation_flow_l_min
        assert st.cooling_duty == st.cooling_duty_kw
        assert st.dT_reactor_dt == st.dt_reactor_dt

        # Setter verification
        st.c_precursor = 2.40
        assert st.c_succinate_precursor == 2.40
        st.c_gbl = 0.50
        assert st.c_gbl_product == 0.50
        st.c_bdo = 0.15
        assert st.c_bdo_byproduct == 0.15
        st.water = 0.60
        assert st.c_water == 0.60
        st.reactor_temp = 470.0
        assert st.t_reactor_kelvin == 470.0
        st.a_cat = 0.92
        assert st.a_catalyst == 0.92
        st.reactor_pressure = 48.0
        assert st.p_reactor == 48.0
        st.recirculation_flow = 135.0
        assert st.recirculation_flow_l_min == 135.0
        st.cooling_duty = 52.0
        assert st.cooling_duty_kw == 52.0

    def test_state_serialization_roundtrip(self) -> None:
        """Verify to_dict() and from_dict() roundtrip serialization for PHAHydrogenolysisGBLState."""
        st = PHAHydrogenolysisGBLState(
            c_succinate_precursor=2.2,
            c_gbl_product=0.6,
            c_bdo_byproduct=0.1,
            c_water=0.7,
            t_reactor_kelvin=475.0,
            a_catalyst=0.88,
            p_reactor=46.5,
            recirculation_flow_l_min=110.0,
            cooling_duty_kw=42.0,
            dt_reactor_dt=0.5,
        )
        d = st.to_dict()
        assert "c_succinate_precursor" in d
        assert "t_reactor_kelvin" in d
        st_recon = PHAHydrogenolysisGBLState.from_dict(d)
        assert math.isclose(st_recon.c_succinate_precursor, 2.2, rel_tol=1e-4)
        assert math.isclose(st_recon.c_gbl_product, 0.6, rel_tol=1e-4)
        assert math.isclose(st_recon.t_reactor_kelvin, 475.0, rel_tol=1e-4)
        assert math.isclose(st_recon.cooling_duty_kw, 42.0, rel_tol=1e-4)

    def test_config_initialization_and_property_aliases(self) -> None:
        """Verify PHAHydrogenolysisGBLConfig default values and alias properties."""
        cfg = PHAHydrogenolysisGBLConfig()
        assert cfg.k1_forward == 3.5e4
        assert cfg.k1 == 3.5e4
        assert cfg.ea1_j_mol == 46000.0
        assert cfg.ea1 == 46000.0
        assert cfg.k2_forward == 1.8e4
        assert cfg.k2 == 1.8e4
        assert cfg.ea2_j_mol == 54000.0
        assert cfg.ea2 == 54000.0

        assert cfg.t_reactor_trip_max == 530.0
        assert cfg.dt_reactor_dt_trip_max == 12.0
        assert cfg.p_reactor_trip_max == 65.0
        assert cfg.catalyst_activity_min == 0.35
        assert cfg.t_coolant_max == 385.0
        assert cfg.cooling_duty_min_kw == 5.0
        assert cfg.mass_residual_max == 1e-4

        # Property setter
        cfg.k1 = 4.0e4
        assert cfg.k1_forward == 4.0e4
        cfg.k2 = 2.0e4
        assert cfg.k2_forward == 2.0e4
        cfg.ea1 = 45000.0
        assert cfg.ea1_j_mol == 45000.0
        cfg.ea2 = 53000.0
        assert cfg.ea2_j_mol == 53000.0

    def test_config_serialization(self) -> None:
        """Verify config to_dict serialization contains all required keys."""
        cfg = PHAHydrogenolysisGBLConfig()
        d = cfg.to_dict()
        assert d["k1_forward"] == 3.5e4
        assert d["t_reactor_trip_max"] == 530.0
        assert d["p_reactor_trip_max"] == 65.0
        assert d["catalyst_activity_min"] == 0.35


# ============================================================================
# 2. TestReactionRatesAndSelectivity
# ============================================================================

class TestReactionRatesAndSelectivity:
    """Validate Langmuir-Hinshelwood catalytic hydrogenolysis kinetics, GBL synthesis, and BDO byproduct."""

    def test_catalytic_reaction_rates_positive(self) -> None:
        """Verify reaction rates r1 and r2 are positive under nominal CSTR operating conditions."""
        engine = PHAHydrogenolysisGBLEngine()
        r1, r2 = engine.compute_rates(engine.state)
        assert r1 > 0.0
        assert r2 > 0.0
        assert isinstance(r1, float)
        assert isinstance(r2, float)

    def test_arrhenius_temperature_dependence(self) -> None:
        """Verify reaction rates increase strictly with temperature following Arrhenius kinetics."""
        engine = PHAHydrogenolysisGBLEngine()
        st_cold = PHAHydrogenolysisGBLState(t_reactor_kelvin=430.0)
        st_nom = PHAHydrogenolysisGBLState(t_reactor_kelvin=463.15)
        st_hot = PHAHydrogenolysisGBLState(t_reactor_kelvin=500.0)

        r1_cold, r2_cold = engine.compute_rates(st_cold)
        r1_nom, r2_nom = engine.compute_rates(st_nom)
        r1_hot, r2_hot = engine.compute_rates(st_hot)

        assert r1_hot > r1_nom > r1_cold > 0.0
        assert r2_hot > r2_nom > r2_cold > 0.0

    def test_catalyst_activity_scaling(self) -> None:
        """Verify reaction rates scale linearly with catalyst activity a_catalyst."""
        engine = PHAHydrogenolysisGBLEngine()
        st_full = PHAHydrogenolysisGBLState(a_catalyst=1.0)
        st_half = PHAHydrogenolysisGBLState(a_catalyst=0.5)

        r1_full, r2_full = engine.compute_rates(st_full)
        r1_half, r2_half = engine.compute_rates(st_half)

        assert math.isclose(r1_half, 0.5 * r1_full, rel_tol=1e-5)
        assert math.isclose(r2_half, 0.5 * r2_full, rel_tol=1e-5)

    def test_competitive_adsorption_denominator(self) -> None:
        """Verify that high product, byproduct, and water concentrations competitively inhibit the rate per site."""
        engine = PHAHydrogenolysisGBLEngine()
        st_dilute = PHAHydrogenolysisGBLState(
            c_succinate_precursor=2.5, c_gbl_product=0.01, c_bdo_byproduct=0.01, c_water=0.01
        )
        st_inhibited = PHAHydrogenolysisGBLState(
            c_succinate_precursor=2.5, c_gbl_product=1.5, c_bdo_byproduct=0.8, c_water=1.5
        )

        r1_dilute, _ = engine.compute_rates(st_dilute)
        r1_inhibited, _ = engine.compute_rates(st_inhibited)

        assert r1_dilute > r1_inhibited > 0.0

    def test_bdo_byproduct_consumption_kinetics(self) -> None:
        """Verify step 2 rate r2 is zero when GBL product is zero and positive when GBL > 0."""
        engine = PHAHydrogenolysisGBLEngine()
        st_zero_gbl = PHAHydrogenolysisGBLState(c_gbl_product=0.0)
        st_with_gbl = PHAHydrogenolysisGBLState(c_gbl_product=0.3)

        _, r2_zero = engine.compute_rates(st_zero_gbl)
        _, r2_with = engine.compute_rates(st_with_gbl)

        assert r2_zero == 0.0
        assert r2_with > 0.0

    def test_water_coproduct_generation(self) -> None:
        """Verify coproduct water concentration increases as precursor is converted."""
        engine = PHAHydrogenolysisGBLEngine()
        w_init = engine.state.c_water
        for _ in range(5):
            engine.step_rk4(dt=0.1)
        assert engine.state.c_water > w_init

    def test_gbl_selectivity_calculation(self) -> None:
        """Verify gbl_selectivity_pct calculation relative to converted precursor and products."""
        engine = PHAHydrogenolysisGBLEngine()
        sel_0 = engine.gbl_selectivity_pct
        assert 0.0 <= sel_0 <= 100.0

        for _ in range(10):
            engine.step_rk4(dt=0.1)

        sel_evolved = engine.gbl_selectivity_pct
        assert 0.0 <= sel_evolved <= 100.0

    def test_ester_conversion_calculation(self) -> None:
        """Verify ester_conversion_pct calculation based on consumed precursor."""
        engine = PHAHydrogenolysisGBLEngine()
        assert engine.ester_conversion_pct == 0.0

        for _ in range(5):
            engine.step_rk4(dt=0.1)

        conv = engine.ester_conversion_pct
        assert conv > 0.0
        assert conv <= 100.0

    def test_gbl_yield_calculation(self) -> None:
        """Verify gbl_yield_pct calculation based on synthesized GBL."""
        engine = PHAHydrogenolysisGBLEngine()
        assert engine.gbl_yield_pct == 0.0

        for _ in range(5):
            engine.step_rk4(dt=0.1)

        yld = engine.gbl_yield_pct
        assert yld > 0.0
        assert yld <= 100.0

    def test_zero_reaction_rates_when_tripped_or_subcooled(self) -> None:
        """Verify reaction rates return (0.0, 0.0) when trip is active or reactor fluid is subcooled."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.trip_active = True
        r1, r2 = engine.compute_rates(engine.state)
        assert r1 == 0.0
        assert r2 == 0.0

        engine.trip_active = False
        st_frozen = PHAHydrogenolysisGBLState(t_reactor_kelvin=200.0)
        r1_sub, r2_sub = engine.compute_rates(st_frozen)
        assert r1_sub == 0.0
        assert r2_sub == 0.0


# ============================================================================
# 3. TestCoupled6StateDerivatives
# ============================================================================

class TestCoupled6StateDerivatives:
    """Validate coupled 6-state CSTR ODE derivative calculations, mass balances, and conservation properties."""

    def test_derivative_calculation_nominal_state(self) -> None:
        """Verify _derivatives returns a 7-tuple of finite floats."""
        engine = PHAHydrogenolysisGBLEngine()
        derivs = engine._derivatives(engine.state)
        assert len(derivs) == 7
        for d in derivs:
            assert isinstance(d, float)
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_carbon_backbone_derivative_conservation(self) -> None:
        """Verify stoichiometric derivative sum for C4 backbone: dc_prec_dt + dc_gbl_dt + dc_bdo_dt == 0.0."""
        engine = PHAHydrogenolysisGBLEngine()
        d_prec, d_gbl, d_bdo, _, _, _, _ = engine._derivatives(engine.state)
        c4_derivative_sum = d_prec + d_gbl + d_bdo
        assert abs(c4_derivative_sum) < 1e-12

    def test_water_coproduct_derivative_balance(self) -> None:
        """Verify water derivative matches step 1 forward reaction rate r1."""
        engine = PHAHydrogenolysisGBLEngine()
        r1, _ = engine.compute_rates(engine.state)
        _, _, _, d_water, _, _, _ = engine._derivatives(engine.state)
        assert math.isclose(d_water, r1, rel_tol=1e-5)

    def test_catalyst_deactivation_derivative_negative(self) -> None:
        """Verify catalyst deactivation derivative da_cat/dt is non-positive."""
        engine = PHAHydrogenolysisGBLEngine()
        _, _, _, _, _, da_cat, _ = engine._derivatives(engine.state)
        assert da_cat <= 0.0

    def test_thermal_energy_balance_derivatives(self) -> None:
        """Verify reactor temperature derivative dt_reactor_dt balances exotherm, cooling, losses, and recirculation."""
        engine = PHAHydrogenolysisGBLEngine()
        derivs = engine._derivatives(engine.state)
        dt_reactor_dt = derivs[4]
        assert abs(dt_reactor_dt) < 50.0

    def test_nominal_pressure_derivative_zero(self) -> None:
        """Verify reactor pressure derivative is zero in steady operating state."""
        engine = PHAHydrogenolysisGBLEngine()
        derivs = engine._derivatives(engine.state)
        dp_reactor_dt = derivs[6]
        assert dp_reactor_dt == 0.0

    def test_derivatives_under_emergency_trip_and_quench(self) -> None:
        """Verify derivatives during emergency quench: rapid depressurization, thermal quench, zero forward reactions."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.trip_active = True
        engine.emergency_quench_active = True

        derivs = engine._derivatives(engine.state)
        d_prec, d_gbl, d_bdo, d_water, dt_reactor_dt, da_cat, dp_reactor_dt = derivs

        assert d_prec == 0.0
        assert d_gbl == 0.0
        assert d_bdo == 0.0
        assert d_water == 0.0
        assert da_cat == 0.0
        assert dp_reactor_dt < 0.0  # Vent depressurization
        assert dt_reactor_dt < 0.0  # Emergency quench cooling

    def test_derivatives_under_passive_trip(self) -> None:
        """Verify derivatives when trip is active but emergency quench is not active."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.trip_active = True
        engine.emergency_quench_active = False

        derivs = engine._derivatives(engine.state)
        for d in derivs:
            assert d == 0.0

    def test_concentration_non_negativity_in_derivatives(self) -> None:
        """Verify that when precursor is zero, consumption rate r1 is zero."""
        engine = PHAHydrogenolysisGBLEngine()
        st_empty = PHAHydrogenolysisGBLState(c_succinate_precursor=0.0)
        r1, _ = engine.compute_rates(st_empty)
        assert r1 == 0.0


# ============================================================================
# 4. TestRK4IntegrationStability
# ============================================================================

class TestRK4IntegrationStability:
    """Validate 4th-Order Runge-Kutta numerical integration stability, convergence, and class aliases."""

    def test_rk4_step_forward_evolution(self) -> None:
        """Verify that an RK4 step smoothly advances the reaction without numerical instability."""
        engine = PHAHydrogenolysisGBLEngine()
        prec_init = engine.state.c_succinate_precursor
        gbl_init = engine.state.c_gbl_product
        bdo_init = engine.state.c_bdo_byproduct

        engine.step_rk4(dt=0.1)

        assert engine.state.c_succinate_precursor < prec_init
        assert engine.state.c_gbl_product > gbl_init
        assert engine.state.c_bdo_byproduct > bdo_init
        assert engine.diagnostic_code == DIAG_OK
        assert not engine.trip_active

    def test_rk4_step_size_variation(self) -> None:
        """Verify stable numerical integration across varying step sizes dt in [0.01, 0.05, 0.1, 0.2] s."""
        for dt in [0.01, 0.05, 0.1, 0.2]:
            engine = PHAHydrogenolysisGBLEngine()
            for _ in range(5):
                engine.step_rk4(dt=dt)
            assert engine.state.c_succinate_precursor > 0.0
            assert engine.state.c_gbl_product > 0.0
            assert engine.state.c_bdo_byproduct > 0.0
            assert engine.state.t_reactor_kelvin > 300.0
            assert 0.0 <= engine.state.a_catalyst <= 1.0

    def test_rk4_convergence_dt_refinement(self) -> None:
        """Verify convergence: trajectory with smaller step size matches larger step size closely."""
        e_fine = PHAHydrogenolysisGBLEngine()
        for _ in range(10):
            e_fine.step_rk4(dt=0.02)

        e_coarse = PHAHydrogenolysisGBLEngine()
        for _ in range(2):
            e_coarse.step_rk4(dt=0.1)

        assert math.isclose(
            e_fine.state.c_succinate_precursor,
            e_coarse.state.c_succinate_precursor,
            rel_tol=1e-3,
        )
        assert math.isclose(
            e_fine.state.c_gbl_product,
            e_coarse.state.c_gbl_product,
            rel_tol=1e-3,
        )

    def test_rk4_concentration_non_negativity_clamping(self) -> None:
        """Verify integration maintains non-negative concentrations under severe depletion perturbations."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.state.c_succinate_precursor = 1e-4
        engine.step_rk4(dt=0.5)
        assert engine.state.c_succinate_precursor >= 0.0
        assert engine.state.c_gbl_product >= 0.0
        assert engine.state.c_bdo_byproduct >= 0.0
        assert engine.state.c_water >= 0.0

    def test_rk4_catalyst_activity_bounds(self) -> None:
        """Verify catalyst activity remains strictly bounded between 0.0 and 1.0 across steps."""
        engine = PHAHydrogenolysisGBLEngine()
        for _ in range(20):
            engine.step_rk4(dt=0.2)
        assert 0.0 <= engine.state.a_catalyst <= 1.0

    def test_rk4_step_alias(self) -> None:
        """Verify engine.rk4_step is an identical alias for engine.step_rk4."""
        e1 = PHAHydrogenolysisGBLEngine()
        e2 = PHAHydrogenolysisGBLEngine()

        e1.step_rk4(dt=0.1)
        e2.rk4_step(dt=0.1)

        assert e1.state.c_succinate_precursor == e2.state.c_succinate_precursor
        assert e1.state.c_gbl_product == e2.state.c_gbl_product

    def test_engine_class_aliases(self) -> None:
        """Verify all engine class and model aliases reference the core implementation."""
        assert PHAHydrogenolysisGBLSimulator is PHAHydrogenolysisGBLEngine
        assert PhaHydrogenolysisGBLSimulator is PHAHydrogenolysisGBLEngine
        assert PHAHydrogenolysisGBLReactor is PHAHydrogenolysisGBLEngine
        assert PhaHydrogenolysisGBLReactor is PHAHydrogenolysisGBLEngine
        assert PHAHydrogenolysisGBLLogicUnit is PHAHydrogenolysisGBLEngine
        assert PhaHydrogenolysisGBLLogicUnit is PHAHydrogenolysisGBLEngine
        assert PHAGBLEngine is PHAHydrogenolysisGBLEngine
        assert PhaGBLEngine is PHAHydrogenolysisGBLEngine
        assert PHAGBLSimulator is PHAHydrogenolysisGBLEngine
        assert PhaGBLSimulator is PHAHydrogenolysisGBLEngine


# ============================================================================
# 5. TestMassBalanceConservation
# ============================================================================

class TestMassBalanceConservation:
    """Validate strict continuous carbon backbone mass conservation (residuals < 1e-10) across regimes."""

    def test_carbon_backbone_conservation_low_conversion(self) -> None:
        """Verify continuous carbon backbone conservation residual < 1e-10 in low conversion regime (10 cycles)."""
        engine = PHAHydrogenolysisGBLEngine()
        for _ in range(10):
            engine.step_rk4(dt=0.05)
        assert engine.conservation_residual < 1e-10
        assert engine.diagnostic_code == DIAG_OK

    def test_carbon_backbone_conservation_medium_conversion(self) -> None:
        """Verify continuous carbon backbone conservation residual < 1e-10 in medium conversion regime (50 cycles)."""
        engine = PHAHydrogenolysisGBLEngine()
        for _ in range(50):
            engine.step_rk4(dt=0.1)
        assert engine.conservation_residual < 1e-10
        assert engine.ester_conversion_pct > 1.0

    def test_carbon_backbone_conservation_high_conversion(self) -> None:
        """Verify continuous carbon backbone conservation residual < 1e-10 in extended conversion regime."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.state.t_reactor_kelvin = 490.0
        for _ in range(30):
            engine.step_rk4(dt=0.1)
        assert engine.conservation_residual < 1e-10
        assert engine.ester_conversion_pct > 5.0

    def test_carbon_backbone_conservation_diverse_temperatures(self) -> None:
        """Verify conservation residual < 1e-10 across varied operating temperatures (420 K to 510 K)."""
        for t_k in [420.0, 450.0, 480.0, 510.0]:
            engine = PHAHydrogenolysisGBLEngine()
            engine.state.t_reactor_kelvin = t_k
            for _ in range(10):
                engine.step_rk4(dt=0.05)
            assert engine.conservation_residual < 1e-10

    def test_carbon_backbone_conservation_varying_recirculation(self) -> None:
        """Verify conservation residual < 1e-10 across varying recirculation flow rates (60 to 200 L/min)."""
        for flow in [60.0, 120.0, 200.0]:
            engine = PHAHydrogenolysisGBLEngine()
            engine.state.recirculation_flow_l_min = flow
            for _ in range(10):
                engine.step_rk4(dt=0.1)
            assert engine.conservation_residual < 1e-10

    def test_get_mass_residual_method(self) -> None:
        """Verify get_mass_residual() helper method matches tracked conservation residual."""
        engine = PHAHydrogenolysisGBLEngine()
        for _ in range(15):
            engine.step_rk4(dt=0.1)
        res = engine.get_mass_residual()
        assert res == engine.conservation_residual
        assert res < 1e-10

    def test_mass_residual_near_machine_epsilon(self) -> None:
        """Verify exact total molar inventory (Precursor + GBL + BDO) equals initial inventory within 1e-12."""
        engine = PHAHydrogenolysisGBLEngine()
        c4_initial = (
            engine.state.c_succinate_precursor
            + engine.state.c_gbl_product
            + engine.state.c_bdo_byproduct
        )
        for _ in range(25):
            engine.step_rk4(dt=0.1)
        c4_current = (
            engine.state.c_succinate_precursor
            + engine.state.c_gbl_product
            + engine.state.c_bdo_byproduct
        )
        assert math.isclose(c4_current, c4_initial, rel_tol=1e-12)


# ============================================================================
# 6. TestThermalExcursionTrip
# ============================================================================

class TestThermalExcursionTrip:
    """Validate thermal excursion trip (0xF9A1, %M657 asserted, %M656 de-asserted)."""

    def test_high_temperature_trip_assertion(self) -> None:
        """Verify high CSTR fluid temperature (> 530.0 K) trips system with 0xF9A1 DIAG_ERR_THERMAL_EXCURSION."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(temp_k=535.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
        assert engine.diagnostic_code == 0xF9A1

    def test_fast_temperature_rate_trip_assertion(self) -> None:
        """Verify fast temperature rate-of-rise (> 12.0 K/s) trips system with 0xF9A1."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_temperature_rate_excursion(rate_k_s=15.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION

    def test_thermal_excursion_coil_deassertion(self) -> None:
        """Verify %M655 (reactor active) and %M656 (feed valve) are immediately de-asserted on trip."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(535.0)
        engine.step_rk4(dt=0.05)

        assert engine.reactor_active is False
        assert engine.feed_valve is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_REACTOR_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_FEED_VALVE) is False

    def test_thermal_excursion_emergency_quench_coil(self) -> None:
        """Verify %M657 (emergency quench) is asserted immediately upon thermal excursion."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(535.0)
        engine.step_rk4(dt=0.05)

        assert engine.emergency_quench_active is True
        assert engine.reg_table.read_bit(COIL_PHA_GBL_EMERGENCY_QUENCH) is True

    def test_thermal_excursion_register_update(self) -> None:
        """Verify %R2817 reflects diagnostic code 0xF9A1 in OCS memory space."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(535.0)
        engine.step_rk4(dt=0.05)

        reg_val = engine.reg_table.read_word(REG_PHA_GBL_DIAGNOSTIC_CODE)
        assert (reg_val & 0xFFFF) == 0xF9A1

    def test_thermal_excursion_isolation_of_recirculation_flow(self) -> None:
        """Verify recirculation flow drops to zero and %R2814 is synchronized to 0 L/min."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(535.0)
        engine.step_rk4(dt=0.05)

        assert engine.state.recirculation_flow_l_min == 0.0
        assert engine.reg_table.read_word(REG_PHA_GBL_RECIRCULATION_FLOW) == 0

    def test_emergency_quench_cooling_dynamics(self) -> None:
        """Verify emergency quench cooling rapidly reduces CSTR temperature by at least 15 K during trip."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(535.0)
        engine.step_rk4(dt=0.05)
        t_peak = engine.state.t_reactor_kelvin

        for _ in range(20):
            engine.step_rk4(dt=0.2)

        t_quenched = engine.state.t_reactor_kelvin
        drop = t_peak - t_quenched
        assert drop >= 15.0
        assert t_quenched < t_peak

    def test_trip_latch_and_reset(self) -> None:
        """Verify trip condition remains latched across subsequent steps until reset() is invoked."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(535.0)
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True

        # Lower temperature; trip must remain latched
        engine.state.t_reactor_kelvin = 463.15
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION

        # Explicit reset restores nominal operation
        engine.reset()
        assert engine.trip_active is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.reactor_active is True
        assert engine.feed_valve is True
        assert engine.emergency_quench_active is False


# ============================================================================
# 7. TestReactorOverpressureTrip
# ============================================================================

class TestReactorOverpressureTrip:
    """Validate reactor overpressure vent trip (0xF9A2) and depressurization dynamics."""

    def test_overpressure_vent_trip_assertion(self) -> None:
        """Verify reactor pressure > 65.0 bar trips system with 0xF9A2 DIAG_ERR_OVERPRESSURE_VENT."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_overpressure(pressure_bar=70.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_OVERPRESSURE_VENT
        assert engine.diagnostic_code == 0xF9A2

    def test_overpressure_coils_actuation(self) -> None:
        """Verify coil actuation on overpressure: %M655=False, %M656=False, %M657=True."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_overpressure(70.0)
        engine.step_rk4(dt=0.05)

        assert engine.reg_table.read_bit(COIL_PHA_GBL_REACTOR_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_FEED_VALVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_EMERGENCY_QUENCH) is True

    def test_overpressure_register_diagnostic_code(self) -> None:
        """Verify register %R2817 contains 0xF9A2 upon overpressure trip."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_overpressure(70.0)
        engine.step_rk4(dt=0.05)

        reg_val = engine.reg_table.read_word(REG_PHA_GBL_DIAGNOSTIC_CODE)
        assert (reg_val & 0xFFFF) == 0xF9A2

    def test_overpressure_vent_depressurization_dynamics(self) -> None:
        """Verify emergency quench venting causes reactor pressure to decay toward ambient."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_overpressure(70.0)
        engine.step_rk4(dt=0.05)
        p_initial = engine.state.p_reactor

        for _ in range(15):
            engine.step_rk4(dt=0.2)

        p_final = engine.state.p_reactor
        assert p_final < p_initial
        assert p_final >= 1.01325

    def test_overpressure_rejection_of_feed_valve(self) -> None:
        """Verify feed valve remains closed throughout depressurization."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_overpressure(70.0)
        engine.step_rk4(dt=0.05)

        for _ in range(5):
            engine.step_rk4(dt=0.1)

        assert engine.feed_valve is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_FEED_VALVE) is False

    def test_inject_overpressure_helper(self) -> None:
        """Verify inject_overpressure helper properly modifies state and triggers trip."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_overpressure(68.0)
        assert engine.state.p_reactor == 68.0
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True


# ============================================================================
# 8. TestCatalystDeactivationAndCoolingFailureTrips
# ============================================================================

class TestCatalystDeactivationAndCoolingFailureTrips:
    """Validate catalyst deactivation (0xF9A3), cooling failure (0xF9A4), and fault priority hierarchy."""

    def test_catalyst_deactivation_trip_assertion(self) -> None:
        """Verify catalyst activity < 35.0% trips system with 0xF9A3 DIAG_ERR_CATALYST_DEACTIVATION."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_catalyst_deactivation(activity=0.30)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_CATALYST_DEACTIVATION
        assert engine.diagnostic_code == 0xF9A3

    def test_catalyst_deactivation_coils_and_registers(self) -> None:
        """Verify coils and registers on deactivation trip: %M655=False, %M656=False, %M657=True, %R2815=300."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_catalyst_deactivation(activity=0.30)
        engine.step_rk4(dt=0.05)

        assert engine.reg_table.read_bit(COIL_PHA_GBL_REACTOR_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_FEED_VALVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_EMERGENCY_QUENCH) is True
        assert engine.reg_table.read_word(REG_PHA_GBL_CATALYST_ACTIVITY) == 300
        assert (engine.reg_table.read_word(REG_PHA_GBL_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9A3

    def test_cooling_failure_temp_trip_assertion(self) -> None:
        """Verify coolant temperature > 385.0 K trips system with 0xF9A4 DIAG_ERR_COOLING_FAILURE."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_cooling_failure(t_coolant=390.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_COOLING_FAILURE
        assert engine.diagnostic_code == 0xF9A4

    def test_cooling_failure_duty_trip_assertion(self) -> None:
        """Verify cooling duty < 5.0 kW trips system with 0xF9A4 DIAG_ERR_COOLING_FAILURE."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_cooling_duty_loss(duty_kw=2.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_COOLING_FAILURE
        assert engine.diagnostic_code == 0xF9A4

    def test_cooling_failure_coils_and_registers(self) -> None:
        """Verify coils and registers on cooling failure: %M655=False, %M656=False, %M657=True, %R2817=0xF9A4."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_cooling_failure(t_coolant=390.0)
        engine.step_rk4(dt=0.05)

        assert engine.reg_table.read_bit(COIL_PHA_GBL_REACTOR_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_FEED_VALVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_GBL_EMERGENCY_QUENCH) is True
        assert (engine.reg_table.read_word(REG_PHA_GBL_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9A4

    def test_continuous_mass_balance_divergence_trip(self) -> None:
        """Verify mass balance residual > 1e-4 trips system with 0xF9A5 DIAG_ERR_MASS_BALANCE_DIVERGENCE."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_mass_divergence(residual=0.005)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        assert (engine.reg_table.read_word(REG_PHA_GBL_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9A5

    def test_priority_hierarchy_p1_dominates_p2(self) -> None:
        """Verify Priority 1 (Thermal Excursion 0xF9A1) dominates Priority 2 (Overpressure 0xF9A2)."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.state.t_reactor_kelvin = 535.0
        engine.state.p_reactor = 70.0
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION

    def test_priority_hierarchy_p2_dominates_p3(self) -> None:
        """Verify Priority 2 (Overpressure 0xF9A2) dominates Priority 3 (Catalyst Deactivation 0xF9A3)."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.state.p_reactor = 70.0
        engine.state.a_catalyst = 0.20
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_OVERPRESSURE_VENT

    def test_priority_hierarchy_p3_dominates_p4(self) -> None:
        """Verify Priority 3 (Catalyst Deactivation 0xF9A3) dominates Priority 4 (Cooling Failure 0xF9A4)."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.state.a_catalyst = 0.20
        engine.inject_cooling_failure(t_coolant=390.0)
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_CATALYST_DEACTIVATION

    def test_priority_hierarchy_p4_dominates_p5(self) -> None:
        """Verify Priority 4 (Cooling Failure 0xF9A4) dominates Priority 5 (Mass Divergence 0xF9A5)."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_cooling_failure(t_coolant=390.0)
        engine.conservation_residual = 0.005
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_COOLING_FAILURE


# ============================================================================
# 9. TestRegisterTableSynchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate Horner OCS memory synchronization across %R2810..%R2817 and %M655..%M657."""

    def test_sync_nominal_registers_scaled(self) -> None:
        """Verify correct scaling and unit conversions across all 8 word registers in nominal state."""
        engine = PHAHydrogenolysisGBLEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        # %R2810: Temperature in 0.1 °C
        # T_rxn = 463.15 K -> 190.0 °C -> 1900
        w_temp = rt.read_word(REG_PHA_GBL_REACTOR_TEMP)
        assert w_temp == 1900

        # %R2811: Pressure in 0.01 bar (45.0 bar -> 4500)
        w_press = rt.read_word(REG_PHA_GBL_REACTOR_PRESSURE)
        assert w_press == 4500

        # %R2812: Conversion in 0.1 % (0.0 % -> 0)
        w_conv = rt.read_word(REG_PHA_GBL_ESTER_CONVERSION)
        assert w_conv == 0

        # %R2813: Yield in 0.1 %
        w_yield = rt.read_word(REG_PHA_GBL_YIELD_PERCENT)
        assert w_yield == 0

        # %R2814: Recirculation flow in 0.1 L/min (120.0 -> 1200)
        w_flow = rt.read_word(REG_PHA_GBL_RECIRCULATION_FLOW)
        assert w_flow == 1200

        # %R2815: Catalyst activity in 0.1 % (1.0 -> 1000)
        w_act = rt.read_word(REG_PHA_GBL_CATALYST_ACTIVITY)
        assert w_act == 1000

        # %R2816: Cooling duty in 0.1 kW (45.0 -> 450)
        w_duty = rt.read_word(REG_PHA_GBL_COOLING_DUTY_KW)
        assert w_duty == 450

        # %R2817: Diagnostic code (0x0000)
        w_diag = rt.read_word(REG_PHA_GBL_DIAGNOSTIC_CODE)
        assert w_diag == 0x0000

    def test_sync_signed_16bit_temperature_subzero(self) -> None:
        """Verify signed 16-bit safe write for sub-zero temperatures (e.g. -10.0 °C -> 0xFF9C)."""
        engine = PHAHydrogenolysisGBLEngine()
        # 263.15 K = -10.0 °C -> scaled = -100 -> masked 16-bit = 0xFF9C (65436)
        engine.state.t_reactor_kelvin = 263.15
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        w_temp = rt.read_word(REG_PHA_GBL_REACTOR_TEMP)
        assert (w_temp & 0xFFFF) == (-100 & 0xFFFF)
        # Verify signed reconstruction
        val_s = w_temp - 0x10000 if w_temp >= 0x8000 else w_temp
        assert val_s == -100

    def test_sync_pressure_clamping_bounds(self) -> None:
        """Verify reactor pressure register clamping to [0, 10000]."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.state.p_reactor = 150.0  # Would be 15000 -> clamped to 10000
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_PHA_GBL_REACTOR_PRESSURE) == 10000

    def test_sync_conversion_and_yield_clamping(self) -> None:
        """Verify conversion efficiency and yield registers clamp between 0 and 1000."""
        engine = PHAHydrogenolysisGBLEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        w_conv = rt.read_word(REG_PHA_GBL_ESTER_CONVERSION)
        w_yield = rt.read_word(REG_PHA_GBL_YIELD_PERCENT)
        assert 0 <= w_conv <= 1000
        assert 0 <= w_yield <= 1000

    def test_sync_coils_normal_operating_state(self) -> None:
        """Verify discrete coils in normal operating state: %M655=True, %M656=True, %M657=False."""
        engine = PHAHydrogenolysisGBLEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_bit(COIL_PHA_GBL_REACTOR_ACTIVE) is True
        assert rt.read_bit(COIL_PHA_GBL_FEED_VALVE) is True
        assert rt.read_bit(COIL_PHA_GBL_EMERGENCY_QUENCH) is False

    def test_sync_coils_trip_operating_state(self) -> None:
        """Verify discrete coils in safety trip state: %M655=False, %M656=False, %M657=True."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(535.0)
        engine.step_rk4(dt=0.05)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_bit(COIL_PHA_GBL_REACTOR_ACTIVE) is False
        assert rt.read_bit(COIL_PHA_GBL_FEED_VALVE) is False
        assert rt.read_bit(COIL_PHA_GBL_EMERGENCY_QUENCH) is True

    def test_sync_with_user_privilege_mode(self) -> None:
        """Verify synchronization succeeds under PrivilegeMode.USER."""
        engine = PHAHydrogenolysisGBLEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert rt.read_word(REG_PHA_GBL_REACTOR_TEMP) == 1900

    def test_sync_with_custom_register_table(self) -> None:
        """Verify syncing to an external RegisterTable does not contaminate or miss state."""
        engine = PHAHydrogenolysisGBLEngine()
        rt1 = RegisterTable()
        rt2 = RegisterTable()

        engine.sync_to_registers(rt1)
        engine.sync_to_registers(rt2)

        for reg in [
            REG_PHA_GBL_REACTOR_TEMP,
            REG_PHA_GBL_REACTOR_PRESSURE,
            REG_PHA_GBL_ESTER_CONVERSION,
            REG_PHA_GBL_YIELD_PERCENT,
            REG_PHA_GBL_RECIRCULATION_FLOW,
            REG_PHA_GBL_CATALYST_ACTIVITY,
            REG_PHA_GBL_COOLING_DUTY_KW,
            REG_PHA_GBL_DIAGNOSTIC_CODE,
        ]:
            assert rt1.read_word(reg) == rt2.read_word(reg)


# ============================================================================
# 10. TestPureStructuredTextPOU
# ============================================================================

class TestPureStructuredTextPOU:
    """Validate pure IEC 61131-3 ST POU syntax and anti-ladder rejection of all 9 constructs."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify pure ST POU validation passes without error."""
        assert verify_pha_hydrogenolysis_gbl_pure_st() is True
        assert verify_pha_gbl_pure_st() is True

    def test_st_parser_ast_validation(self) -> None:
        """Verify STParser successfully parses the POU and returns AgentStatus.SUCCESS."""
        res = STParser.validate_code(PHA_HYDROGENOLYSIS_GBL_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None

    def test_st_program_variables_and_registers(self) -> None:
        """Verify all Horner OCS registers and coils are mapped in POU VAR block."""
        code = PHA_HYDROGENOLYSIS_GBL_PURE_ST_POU
        assert "rReactorTemp AT %R2810 : INT;" in code
        assert "rReactorPressure AT %R2811 : WORD;" in code
        assert "rEsterConversion AT %R2812 : WORD;" in code
        assert "rYieldPercent AT %R2813 : WORD;" in code
        assert "rRecirculationFlow AT %R2814 : WORD;" in code
        assert "rCatalystActivity AT %R2815 : WORD;" in code
        assert "rCoolingDutyKW AT %R2816 : WORD;" in code
        assert "wDiagnosticCode AT %R2817 : WORD;" in code
        assert "bReactorActive AT %M655 : BOOL;" in code
        assert "bFeedValve AT %M656 : BOOL;" in code
        assert "bEmergencyQuench AT %M657 : BOOL;" in code

    def test_st_pou_string_constants_and_aliases(self) -> None:
        """Verify POU string constants and aliases are identical."""
        assert PHA_HYDROGENOLYSIS_GBL_PURE_ST_POU == ST_PROGRAM_PHA_HYDROGENOLYSIS_GBL_CONTROL
        assert PHA_GBL_PURE_ST_POU == ST_PROGRAM_PHA_HYDROGENOLYSIS_GBL_CONTROL
        assert PHAHydrogenolysisGBLControl == ST_PROGRAM_PHA_HYDROGENOLYSIS_GBL_CONTROL
        assert PHA_HYDROGENOLYSIS_GBL_CONTROL_POU == ST_PROGRAM_PHA_HYDROGENOLYSIS_GBL_CONTROL
        assert PHA_GBL_CONTROL_POU == ST_PROGRAM_PHA_HYDROGENOLYSIS_GBL_CONTROL

    def test_anti_ladder_rejection_contact_open(self) -> None:
        """Verify SecurityGuard rejects open contact construct ---[ ]--- with LadderForbiddenError."""
        bad_code = "PROGRAM BadTest\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_contact_closed(self) -> None:
        """Verify SecurityGuard rejects closed contact construct ---[/]--- with LadderForbiddenError."""
        bad_code = "PROGRAM BadTest\nVAR x: BOOL; END_VAR\n---[/]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_coil_normal(self) -> None:
        """Verify SecurityGuard rejects normal coil construct ---( )--- with LadderForbiddenError."""
        bad_code = "PROGRAM BadTest\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_coil_inverted(self) -> None:
        """Verify SecurityGuard rejects inverted coil construct ---(/)--- with LadderForbiddenError."""
        bad_code = "PROGRAM BadTest\nVAR x: BOOL; END_VAR\n---(/)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_coil_set_reset(self) -> None:
        """Verify SecurityGuard rejects set/reset coil constructs ---(S)--- and ---(R)---."""
        bad_set = "PROGRAM BadTest\nVAR x: BOOL; END_VAR\n---(S)---\nEND_PROGRAM"
        bad_reset = "PROGRAM BadTest\nVAR x: BOOL; END_VAR\n---(R)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_set)
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_reset)

    def test_anti_ladder_rejection_rung_and_network_and_mnemonic(self) -> None:
        """Verify SecurityGuard rejects RUNG, NETWORK, and ladder mnemonic XIC constructs."""
        for bad_frag in ["RUNG 1: START", "NETWORK 10", "XIC %M655"]:
            bad_code = f"PROGRAM BadTest\nVAR x: BOOL; END_VAR\n{bad_frag}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Validate ILogicUnit interface compliance, reset behavior, and 100-cycle simulation soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        """Verify ILogicUnit interface properties: unit_id, name, priority, is_enabled."""
        engine = PHAHydrogenolysisGBLEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.unit_id == "PHA_GBL_REACTOR_W320"
        assert engine.name == "PHAHydrogenolysisGBLEngine"
        assert engine.priority == 50
        assert engine.is_enabled is True

    def test_ilogicunit_scan_step_execution_result(self) -> None:
        """Verify scan_step returns valid ExecutionResult with status, error_code, details, and data."""
        engine = PHAHydrogenolysisGBLEngine()
        res = engine.scan_step(dt=0.1)

        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert "PHA Hydrogenolysis GBL CSTR" in res.details
        assert isinstance(res.data, dict)
        assert "c_succinate_precursor" in res.data
        assert "c_gbl_product" in res.data
        assert "c_bdo_byproduct" in res.data
        assert "c_water" in res.data
        assert "ester_conversion_pct" in res.data
        assert "gbl_yield_pct" in res.data
        assert "gbl_selectivity_pct" in res.data
        assert res.data["cycle_count"] == 1

    def test_scan_context_integration(self) -> None:
        """Verify passing ScanContext updates engine's RegisterTable and synchronizes values."""
        rt_ctx = RegisterTable()
        ctx = ScanContext(cycle=5, dt_ms=100.0, register_table=rt_ctx)
        engine = PHAHydrogenolysisGBLEngine()

        res = engine.scan_step(ctx=ctx)
        assert res.status == AgentStatus.SUCCESS
        assert rt_ctx.read_word(REG_PHA_GBL_REACTOR_TEMP) > 0
        assert rt_ctx.read_bit(COIL_PHA_GBL_REACTOR_ACTIVE) is True

    def test_step_and_execute_interface_methods(self) -> None:
        """Verify step() and execute() methods adhere to ILogicUnit interface."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.step(0.1)
        assert engine.cycle_count == 1
        engine.execute(0.1)
        assert engine.cycle_count == 2

    def test_100_cycle_simulation_soak(self) -> None:
        """Execute 100 continuous scan cycles: verify stability, conservation, and monotonic conversion."""
        engine = PHAHydrogenolysisGBLEngine()
        prec_prev = engine.state.c_succinate_precursor

        for cycle in range(1, 101):
            res = engine.scan_step(dt=0.1)
            assert res.status == AgentStatus.SUCCESS
            assert engine.diagnostic_code == DIAG_OK
            assert engine.conservation_residual < 1e-10

        assert engine.cycle_count == 100
        assert engine.state.c_succinate_precursor < prec_prev
        assert engine.ester_conversion_pct > 0.0
        assert engine.gbl_yield_pct > 0.0

    def test_soak_memory_profiling_zero_leak(self) -> None:
        """Verify 100-cycle soak produces zero memory accumulation / leak using tracemalloc."""
        tracemalloc.start()
        engine = PHAHydrogenolysisGBLEngine()

        # Warmup 10 cycles
        for _ in range(10):
            engine.scan_step(dt=0.1)

        snapshot1 = tracemalloc.take_snapshot()

        # 100 soak cycles
        for _ in range(100):
            engine.scan_step(dt=0.1)

        snapshot2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        top_stats = snapshot2.compare_to(snapshot1, "lineno")
        total_growth_bytes = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)
        # Memory growth across 100 pure-software ODE steps must be minimal (< 150 KB)
        assert total_growth_bytes < 150 * 1024

    def test_reset_behavior_and_restoration(self) -> None:
        """Verify reset() restores nominal state, clears trips, and resets counters."""
        engine = PHAHydrogenolysisGBLEngine()
        engine.inject_thermal_excursion(535.0)
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True

        engine.reset()
        assert engine.trip_active is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.cycle_count == 0
        assert engine.conservation_residual == 0.0
        assert engine.state.c_succinate_precursor == 2.80
        assert engine.state.t_reactor_kelvin == 463.15


# ============================================================================
# 12. TestVerificationRunnerAndCLI
# ============================================================================

class TestVerificationRunnerAndCLI:
    """Validate 9-stage verification runner test and CLI interop (pass tempfile for --output!)."""

    def test_deterministic_9_stage_verification_suite(self) -> None:
        """Execute complete 9-stage verification suite runner and test JSON evidence emission."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = run_pha_hydrogenolysis_gbl_verification(output_path=out_path)
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

    def test_9_stage_verification_quick_mode(self) -> None:
        """Verify execution in quick mode with reduced iteration steps."""
        res = run_pha_hydrogenolysis_gbl_verification(quick=True)
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_evidence_json_structure_and_hashes(self) -> None:
        """Verify evidence JSON contains SHA-256 digests for POU and model config."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = run_pha_hydrogenolysis_gbl_verification(output_path=out_path, quick=True)
            digests = res["data"]["digests"]
            assert "pou_sha256" in digests
            assert "model_sha256" in digests
            assert len(digests["pou_sha256"]) == 64
            assert len(digests["model_sha256"]) == 64
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_scripts_runner_module_execution(self) -> None:
        """Verify execution of scripts/run_pha_hydrogenolysis_gbl_verification.py module runner."""
        from scripts.run_pha_hydrogenolysis_gbl_verification import (
            execute_pha_hydrogenolysis_gbl_verification,
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = execute_pha_hydrogenolysis_gbl_verification(output_path=out_path, quick=True)
            assert res["status"] == "success"
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_main_entrypoint_with_tempfile(self) -> None:
        """Verify CLI main() in scripts/run_pha_hydrogenolysis_gbl_verification.py passes cleanly."""
        from scripts.run_pha_hydrogenolysis_gbl_verification import main as script_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = script_main(["--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_simulation_cli_main_entrypoint(self) -> None:
        """Verify CLI main() in src/jev_cscape/simulation/pha_hydrogenolysis_gbl.py passes cleanly."""
        from jev_cscape.simulation.pha_hydrogenolysis_gbl import main as sim_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = sim_main(["--verify", "--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_compatibility_runner_alias(self) -> None:
        """Verify run_pha_gbl_verification is an alias to run_pha_hydrogenolysis_gbl_verification."""
        assert run_pha_gbl_verification is run_pha_hydrogenolysis_gbl_verification
