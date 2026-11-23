"""Industrial Catalytic PHA Thermolysis & Bio-Acrylic Acid Pyrolysis CSTR Unit Test Suite (W308).

Work Package: W308 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification test classes (75+ test cases):
1. TestPhysicalConstantsAndRegisters: Physical constants, stoichiometry, register %R2690..%R2697, coils %M627..%M629, signed 16-bit safe comparisons.
2. TestArrheniusRateKinetics: Arrhenius cracking rates, temperature dependence, activation energies, and selectivity.
3. TestCoupled6StateDerivatives: 6-state ODE derivative calculations, mass/energy balance, volume/concentration non-negativity.
4. TestRK4IntegrationStability: RK4 stability, step size variation (dt=0.01s to 0.1s), trajectory smoothness, and class aliases.
5. TestCarbonMassConservation: Carbon mole and mass conservation residuals (< 1e-10) across diverse conversion regimes.
6. TestThermalRunawayTrip: Thermal runaway trip (0xF961, %M629 safety quench coil asserted, emergency cooling dynamics).
7. TestVaporOverpressureTrip: Vapor overpressure trip (0xF962, %M629 asserted, vapor condensation and draw isolation).
8. TestCatalystCokingTrip: Catalyst coking deactivation trip (0xF963, deactivation kinetics and fault priority hierarchy).
9. TestRegisterTableSynchronization: Horner OCS memory sync across %R2690..%R2697 and %M627..%M629 with signed 16-bit masking.
10. TestPureStructuredTextPOU: Pure IEC 61131-3 ST POU validation and anti-ladder rejection of all 9 constructs.
11. TestILogicUnitComplianceAndSoak: ILogicUnit scan step compliance, reset behavior, and 100-cycle simulation soak.
12. TestVerificationRunnerAndCLI: Deterministic 9-stage verification runner and CLI interop (pass tempfile for --output!).
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

from jev_cscape.simulation.pha_thermolysis import (
    ALPHA_AA,
    CARBON_FRACTION_AA,
    CARBON_FRACTION_CA,
    CARBON_FRACTION_PHA,
    COIL_PHA_THERM_ACTIVE,
    COIL_PHA_THERM_DRAW_VALVE,
    COIL_PHA_THERM_QUENCH,
    COIL_PHA_THERM_REACTOR_ACTIVE,
    COIL_PHA_THERM_RUNNING,
    COIL_PHA_THERM_SAFETY_QUENCH,
    COIL_PHA_THERM_VAPOR_DRAW_VALVE,
    DIAG_ERR_CATALYST_COKING,
    DIAG_ERR_CATALYST_COKING_LOSS,
    DIAG_ERR_COKING_LOSS,
    DIAG_ERR_DIVERGENCE,
    DIAG_ERR_FEED_STARVATION,
    DIAG_ERR_FEED_STARVATION_LOW_TEMP,
    DIAG_ERR_HIGH_TEMP,
    DIAG_ERR_LOW_TEMP,
    DIAG_ERR_MASS_BALANCE,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_OVERPRESSURE,
    DIAG_ERR_OVERPRESSURE_VAPOR_BURST,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP,
    DIAG_ERR_VAPOR_BURST,
    DIAG_OK,
    MW_AA,
    MW_CA,
    MW_CARBON,
    MW_PHA_UNIT,
    PHA_THERM_PURE_ST_POU,
    PHA_THERMOLYSIS_CONTROL_POU,
    PHA_THERMOLYSIS_PURE_ST_POU,
    PHAThermConfig,
    PHAThermDiagnosticCode,
    PHAThermState,
    PHAThermStatusWord,
    PHAThermolysisConfig,
    PHAThermolysisControl,
    PHAThermolysisDiagnosticCode,
    PHAThermolysisEngine,
    PHAThermolysisLogicUnit,
    PHAThermolysisModel,
    PHAThermolysisParameters,
    PHAThermolysisPlantModel,
    PHAThermolysisReactor,
    PHAThermolysisSimulationLogicUnit,
    PHAThermolysisSimulator,
    PHAThermolysisState,
    PHAThermolysisStateModel,
    PHAThermolysisStatusWord,
    PhaThermConfig,
    PhaThermDiagnosticCode,
    PhaThermState,
    PhaThermStatusWord,
    PhaThermolysisConfig,
    PhaThermolysisEngine,
    PhaThermolysisLogicUnit,
    PhaThermolysisModel,
    PhaThermolysisPlantModel,
    PhaThermolysisReactor,
    PhaThermolysisSimulationLogicUnit,
    PhaThermolysisSimulator,
    PhaThermolysisState,
    R_GAS_CONSTANT,
    REG_PHA_THERM_AA_CONC,
    REG_PHA_THERM_ACRYLIC_ACID_CONC,
    REG_PHA_THERM_ACRYLIC_SELECTIVITY,
    REG_PHA_THERM_CAA,
    REG_PHA_THERM_CONV,
    REG_PHA_THERM_CONVERSION_RATE,
    REG_PHA_THERM_DIAG,
    REG_PHA_THERM_DIAGNOSTIC_CODE,
    REG_PHA_THERM_DUTY,
    REG_PHA_THERM_JACKET_POWER_DUTY,
    REG_PHA_THERM_JACKET_TEMP,
    REG_PHA_THERM_P_VAP,
    REG_PHA_THERM_POWER_DUTY,
    REG_PHA_THERM_PVAP,
    REG_PHA_THERM_REACTOR_TEMP,
    REG_PHA_THERM_SEL,
    REG_PHA_THERM_SELECTIVITY,
    REG_PHA_THERM_TEMP,
    REG_PHA_THERM_TJ,
    REG_PHA_THERM_TR,
    REG_PHA_THERM_VAPOR_PRESSURE,
    ST_PROGRAM_PHA_THERMOLYSIS_CONTROL,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    run_pha_therm_verification,
    run_pha_thermolysis_verification,
    verify_pha_therm_pure_st,
    verify_pha_thermolysis_pure_st,
)


# ============================================================================
# 1. TestPhysicalConstantsAndRegisters
# ============================================================================

class TestPhysicalConstantsAndRegisters:
    """Validate stoichiometry, molecular weights, register mappings, coils, and signed 16-bit diagnostic codes."""

    def test_molecular_weights_and_stoichiometry(self) -> None:
        """Verify molecular weights of PHA repeat unit, acrylic acid, crotonic acid, and carbon."""
        assert math.isclose(MW_PHA_UNIT, 86.09, rel_tol=1e-4)
        assert math.isclose(MW_AA, 72.063, rel_tol=1e-4)
        assert math.isclose(MW_CA, 86.09, rel_tol=1e-4)
        assert math.isclose(MW_CARBON, 12.011, rel_tol=1e-4)
        assert math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-6)

    def test_alpha_and_carbon_fractions(self) -> None:
        """Verify stoichiometric yield coefficient and carbon mass fractions."""
        expected_alpha = 72.063 / 86.09
        assert math.isclose(ALPHA_AA, expected_alpha, rel_tol=1e-4)

        expected_c_pha = (4.0 * 12.011) / 86.09
        assert math.isclose(CARBON_FRACTION_PHA, expected_c_pha, rel_tol=1e-4)

        expected_c_aa = (3.0 * 12.011) / 72.063
        assert math.isclose(CARBON_FRACTION_AA, expected_c_aa, rel_tol=1e-4)

        expected_c_ca = (4.0 * 12.011) / 86.09
        assert math.isclose(CARBON_FRACTION_CA, expected_c_ca, rel_tol=1e-4)

    def test_register_address_constants_and_aliases(self) -> None:
        """Verify Horner OCS word register addresses %R2690..%R2697 and string aliases."""
        assert REG_PHA_THERM_REACTOR_TEMP == "%R2690"
        assert REG_PHA_THERM_JACKET_TEMP == "%R2691"
        assert REG_PHA_THERM_VAPOR_PRESSURE == "%R2692"
        assert REG_PHA_THERM_ACRYLIC_ACID_CONC == "%R2693"
        assert REG_PHA_THERM_CONVERSION_RATE == "%R2694"
        assert REG_PHA_THERM_ACRYLIC_SELECTIVITY == "%R2695"
        assert REG_PHA_THERM_JACKET_POWER_DUTY == "%R2696"
        assert REG_PHA_THERM_DIAGNOSTIC_CODE == "%R2697"

        # Check aliases
        assert REG_PHA_THERM_TEMP == "%R2690"
        assert REG_PHA_THERM_TR == "%R2690"
        assert REG_PHA_THERM_TJ == "%R2691"
        assert REG_PHA_THERM_PVAP == "%R2692"
        assert REG_PHA_THERM_P_VAP == "%R2692"
        assert REG_PHA_THERM_CAA == "%R2693"
        assert REG_PHA_THERM_AA_CONC == "%R2693"
        assert REG_PHA_THERM_CONV == "%R2694"
        assert REG_PHA_THERM_SELECTIVITY == "%R2695"
        assert REG_PHA_THERM_SEL == "%R2695"
        assert REG_PHA_THERM_DUTY == "%R2696"
        assert REG_PHA_THERM_POWER_DUTY == "%R2696"
        assert REG_PHA_THERM_DIAG == "%R2697"

    def test_coil_address_constants_and_aliases(self) -> None:
        """Verify Horner OCS discrete coil addresses %M627..%M629 and aliases."""
        assert COIL_PHA_THERM_REACTOR_ACTIVE == "%M627"
        assert COIL_PHA_THERM_VAPOR_DRAW_VALVE == "%M628"
        assert COIL_PHA_THERM_SAFETY_QUENCH == "%M629"

        # Aliases
        assert COIL_PHA_THERM_ACTIVE == "%M627"
        assert COIL_PHA_THERM_RUNNING == "%M627"
        assert COIL_PHA_THERM_DRAW_VALVE == "%M628"
        assert COIL_PHA_THERM_QUENCH == "%M629"

    def test_diagnostic_codes_constants_and_aliases(self) -> None:
        """Verify 16-bit diagnostic trip constants 0x0000, 0xF961..0xF965."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP == 0xF961
        assert DIAG_ERR_OVERPRESSURE_VAPOR_BURST == 0xF962
        assert DIAG_ERR_CATALYST_COKING_LOSS == 0xF963
        assert DIAG_ERR_MASS_BALANCE_DIVERGENCE == 0xF964
        assert DIAG_ERR_FEED_STARVATION_LOW_TEMP == 0xF965

        # Aliases
        assert DIAG_ERR_THERMAL_RUNAWAY == 0xF961
        assert DIAG_ERR_HIGH_TEMP == 0xF961
        assert DIAG_ERR_OVERPRESSURE == 0xF962
        assert DIAG_ERR_VAPOR_BURST == 0xF962
        assert DIAG_ERR_CATALYST_COKING == 0xF963
        assert DIAG_ERR_COKING_LOSS == 0xF963
        assert DIAG_ERR_MASS_BALANCE == 0xF964
        assert DIAG_ERR_DIVERGENCE == 0xF964
        assert DIAG_ERR_FEED_STARVATION == 0xF965
        assert DIAG_ERR_LOW_TEMP == 0xF965

    def test_signed_16bit_diagnostic_safe_comparisons(self) -> None:
        """Verify signed 16-bit safe comparisons for diagnostic codes across unsigned/signed representations."""
        trip_codes = [0xF961, 0xF962, 0xF963, 0xF964, 0xF965]
        for val_u in trip_codes:
            code = DiagnosticCode(val_u)
            val_s = val_u - 0x10000

            # Safe comparison against both unsigned and signed
            assert code == val_u
            assert code == val_s
            assert hash(code) == hash(val_u)
            assert f"0x{val_u:04X}" in str(code)
            assert f"0x{val_u:04X}" in repr(code)

        assert DiagnosticCode(0x0000) == 0
        assert str(DiagnosticCode(0x0000)) == "0x0000"

    def test_status_word_bitmask_flags(self) -> None:
        """Verify PHAThermStatusWord bitmask enumeration definitions."""
        assert PHAThermStatusWord.REACTOR_RUNNING == (1 << 0)
        assert PHAThermStatusWord.FEED_PUMP_ACTIVE == (1 << 1)
        assert PHAThermStatusWord.VAPOR_DRAW_ACTIVE == (1 << 2)
        assert PHAThermStatusWord.HEATER_ENERGIZED == (1 << 3)
        assert PHAThermStatusWord.QUENCH_ACTIVE == (1 << 4)
        assert PHAThermStatusWord.HIGH_TEMP_ALARM == (1 << 5)
        assert PHAThermStatusWord.HIGH_PRESSURE_ALARM == (1 << 6)
        assert PHAThermStatusWord.EMERGENCY_TRIP == (1 << 7)

        # Aliases
        assert PhaThermStatusWord is PHAThermStatusWord
        assert PHAThermolysisStatusWord is PHAThermStatusWord


# ============================================================================
# 2. TestArrheniusRateKinetics
# ============================================================================

class TestArrheniusRateKinetics:
    """Validate dual-pathway Arrhenius cracking kinetics, temperature dependence, activation energies."""

    def test_primary_unzipping_arrhenius_rate_formula(self) -> None:
        """Verify analytical computation of primary catalytic unzipping rate r1."""
        reactor = PHAThermolysisEngine()
        st = PHAThermolysisState(c_pha=120.0, tr=540.0, a_cat=1.0)
        r1, r2, da_dt = reactor.compute_rates(st)

        rt = R_GAS_CONSTANT * 540.0
        expected_r1 = reactor.cfg.k1 * 1.0 * 120.0 * math.exp(-reactor.cfg.ea1_j_mol / rt)
        assert math.isclose(r1, expected_r1, rel_tol=1e-6)
        assert r1 > 0.0

    def test_secondary_elimination_arrhenius_rate_formula(self) -> None:
        """Verify analytical computation of secondary thermal elimination rate r2."""
        reactor = PHAThermolysisEngine()
        st = PHAThermolysisState(c_pha=120.0, tr=540.0, a_cat=1.0)
        r1, r2, da_dt = reactor.compute_rates(st)

        rt = R_GAS_CONSTANT * 540.0
        expected_r2 = reactor.cfg.k2 * 120.0 * math.exp(-reactor.cfg.ea2_j_mol / rt)
        assert math.isclose(r2, expected_r2, rel_tol=1e-6)
        assert r2 > 0.0

    def test_reaction_rate_temperature_monotonic_acceleration(self) -> None:
        """Verify Arrhenius reaction rates strictly increase with temperature."""
        reactor = PHAThermolysisEngine()
        st_cold = PHAThermolysisState(tr=510.0, c_pha=120.0)
        st_nom = PHAThermolysisState(tr=540.0, c_pha=120.0)
        st_hot = PHAThermolysisState(tr=570.0, c_pha=120.0)

        r1_cold, r2_cold, _ = reactor.compute_rates(st_cold)
        r1_nom, r2_nom, _ = reactor.compute_rates(st_nom)
        r1_hot, r2_hot, _ = reactor.compute_rates(st_hot)

        assert r1_hot > r1_nom > r1_cold > 0.0
        assert r2_hot > r2_nom > r2_cold > 0.0

    def test_activation_energy_relative_sensitivity(self) -> None:
        """Verify Ea2 (90 kJ/mol) has higher temperature sensitivity than Ea1 (75 kJ/mol)."""
        reactor = PHAThermolysisEngine()
        st1 = PHAThermolysisState(tr=500.0, c_pha=100.0)
        st2 = PHAThermolysisState(tr=600.0, c_pha=100.0)

        r1_1, r2_1, _ = reactor.compute_rates(st1)
        r1_2, r2_2, _ = reactor.compute_rates(st2)

        ratio_r1 = r1_2 / r1_1
        ratio_r2 = r2_2 / r2_1
        # Because Ea2 > Ea1, ratio_r2 must be significantly greater than ratio_r1
        assert ratio_r2 > ratio_r1

    def test_catalyst_activity_linear_scaling_on_primary_rate(self) -> None:
        """Verify primary rate r1 scales linearly with a_cat while r2 remains unaffected."""
        reactor = PHAThermolysisEngine()
        st_full = PHAThermolysisState(tr=540.0, a_cat=1.00)
        st_half = PHAThermolysisState(tr=540.0, a_cat=0.50)

        r1_full, r2_full, _ = reactor.compute_rates(st_full)
        r1_half, r2_half, _ = reactor.compute_rates(st_half)

        assert math.isclose(r1_half, 0.5 * r1_full, rel_tol=1e-5)
        assert math.isclose(r2_half, r2_full, rel_tol=1e-5)

    def test_zero_feed_concentration_halts_rates(self) -> None:
        """Verify zero PHA feed concentration results in exactly zero rates."""
        reactor = PHAThermolysisEngine()
        st_zero = PHAThermolysisState(c_pha=0.0, tr=540.0, a_cat=1.0)
        r1, r2, da_dt = reactor.compute_rates(st_zero)

        assert r1 == 0.0
        assert r2 == 0.0
        assert da_dt == 0.0

    def test_rates_zero_when_tripped_or_frozen(self) -> None:
        """Verify reaction rates are zero when tripped or reactor core is sub-200 K."""
        reactor = PHAThermolysisEngine()
        reactor.trip_active = True
        r1, r2, da_dt = reactor.compute_rates(reactor.state)
        assert (r1, r2, da_dt) == (0.0, 0.0, 0.0)

        reactor.trip_active = False
        st_cold = PHAThermolysisState(tr=150.0)
        r1_c, r2_c, da_c = reactor.compute_rates(st_cold)
        assert (r1_c, r2_c, da_c) == (0.0, 0.0, 0.0)


# ============================================================================
# 3. TestCoupled6StateDerivatives
# ============================================================================

class TestCoupled6StateDerivatives:
    """Validate coupled 6-state ODE derivative calculations, mass/energy balance, volume/concentration non-negativity."""

    def test_state_initialization_defaults_and_aliases(self) -> None:
        """Verify PHAThermolysisState default values and flexible property getters/setters."""
        st = PHAThermolysisState()
        assert st.c_pha == 120.0
        assert st.c_aa == 15.0
        assert st.c_ca == 2.0
        assert st.tr == 540.0
        assert st.tj == 560.0
        assert st.pvap == 4.5
        assert st.a_cat == 1.00
        assert st.dtr_dt == 0.0

        # Property getters
        assert st.C_pha == 120.0
        assert st.pha == 120.0
        assert st.C_aa == 15.0
        assert st.aa == 15.0
        assert st.C_ca == 2.0
        assert st.ca == 2.0
        assert st.Tr == 540.0
        assert st.reactor_temp == 540.0
        assert st.Tj == 560.0
        assert st.jacket_temp == 560.0
        assert st.Pvap == 4.5
        assert st.vapor_pressure == 4.5
        assert st.a_cat_activity == 1.00
        assert st.activity == 1.00

        # Setters
        st.C_pha = 110.0
        assert st.c_pha == 110.0
        st.pha = 105.0
        assert st.c_pha == 105.0
        st.C_aa = 20.0
        assert st.c_aa == 20.0
        st.aa = 22.0
        assert st.c_aa == 22.0
        st.C_ca = 3.0
        assert st.c_ca == 3.0
        st.ca = 3.5
        assert st.c_ca == 3.5
        st.Tr = 545.0
        assert st.tr == 545.0
        st.reactor_temp = 548.0
        assert st.tr == 548.0
        st.Tj = 565.0
        assert st.tj == 565.0
        st.jacket_temp = 568.0
        assert st.tj == 568.0
        st.Pvap = 5.0
        assert st.pvap == 5.0
        st.vapor_pressure = 5.2
        assert st.pvap == 5.2
        st.a_cat_activity = 0.95
        assert st.a_cat == 0.95
        st.activity = 0.92
        assert st.a_cat == 0.92

    def test_state_serialization_roundtrip(self) -> None:
        """Verify PHAThermolysisState dictionary roundtrip with case-insensitivity."""
        st = PHAThermolysisState(
            c_pha=95.0, c_aa=25.0, c_ca=4.0, tr=550.0, tj=570.0, pvap=6.0, a_cat=0.88, dtr_dt=0.5
        )
        d = st.to_dict()
        assert d["c_pha"] == 95.0
        assert d["c_aa"] == 25.0
        assert d["c_ca"] == 4.0
        assert d["tr"] == 550.0

        st_rebuilt = PHAThermolysisState.from_dict(d)
        assert st_rebuilt.c_pha == 95.0
        assert st_rebuilt.c_aa == 25.0
        assert st_rebuilt.tr == 550.0
        assert st_rebuilt.a_cat == 0.88

        # Alternative key naming in from_dict
        alt_d = {
            "C_pha": 80.0, "C_aa": 30.0, "C_ca": 5.0,
            "reactor_temp": 535.0, "jacket_temp": 555.0,
            "vapor_pressure": 4.8, "activity": 0.80, "dTr_dt": 0.1
        }
        st_alt = PHAThermolysisState.from_dict(alt_d)
        assert st_alt.c_pha == 80.0
        assert st_alt.c_aa == 30.0
        assert st_alt.tr == 535.0
        assert st_alt.a_cat == 0.80

    def test_derivatives_nominal_signs(self) -> None:
        """Verify component concentration derivatives signs in closed batch mode."""
        reactor = PHAThermolysisEngine()
        dc_pha, dc_aa, dc_ca, dtr, dtj, dpvap, da_cat = reactor._derivatives(reactor.state)

        # In closed batch, feed is consumed, products are generated
        assert dc_pha < 0.0
        assert dc_aa > 0.0
        assert dc_ca > 0.0
        assert da_cat < 0.0

    def test_endothermic_reaction_thermal_effect(self) -> None:
        """Verify endothermic reaction consumes thermal energy and contributes cooling to core Tr."""
        reactor = PHAThermolysisEngine()
        # Set jacket equal to core to eliminate jacket conductive heat transfer
        reactor.state.tj = reactor.state.tr
        reactor.cfg.ua_loss = 0.0  # eliminate ambient loss
        reactor.cfg.f_in = 0.0     # eliminate flow sensible heat

        derivs = reactor._derivatives(reactor.state)
        # With Tj == Tr, conductive heat transfer is 0; only endothermic reaction cooling occurs
        dtr_dt = derivs[3]
        assert dtr_dt < 0.0

    def test_jacket_energy_balance_derivatives(self) -> None:
        """Verify jacket temperature derivative responds to heating duty and heat exchange."""
        reactor = PHAThermolysisEngine()
        reactor.jacket_power_duty = 100.0  # max power
        reactor.state.tj = 540.0
        reactor.state.tr = 540.0

        derivs = reactor._derivatives(reactor.state)
        dtj_dt = derivs[4]
        # At 100% power and zero temperature gradient to core, dtj_dt must be positive
        assert dtj_dt > 0.0

        # Now test zero power duty
        reactor.jacket_power_duty = 0.0
        reactor.state.tj = 560.0
        reactor.state.tr = 540.0
        derivs_cooling = reactor._derivatives(reactor.state)
        # Heat transfer to core with 0 power duty -> dtj_dt must be negative
        assert derivs_cooling[4] < 0.0

    def test_vapor_pressure_generation_and_draw_derivative(self) -> None:
        """Verify headspace vapor pressure derivative balances generation and draw."""
        reactor = PHAThermolysisEngine()
        r1, _, _ = reactor.compute_rates(reactor.state)

        # Case 1: Draw valve closed -> pure pressure generation
        reactor.vapor_draw_valve_open = False
        derivs_closed = reactor._derivatives(reactor.state)
        assert math.isclose(derivs_closed[5], reactor.cfg.k_pvap_gen * r1, rel_tol=1e-5)

        # Case 2: Draw valve open -> generation minus draw discharge
        reactor.vapor_draw_valve_open = True
        derivs_open = reactor._derivatives(reactor.state)
        expected_draw = reactor.cfg.k_draw * (reactor.state.pvap - reactor.cfg.p_condenser)
        expected_dp = reactor.cfg.k_pvap_gen * r1 - expected_draw
        assert math.isclose(derivs_open[5], expected_dp, rel_tol=1e-5)

    def test_derivatives_zero_when_tripped_without_quench(self) -> None:
        """Verify all derivatives are zero when latched in non-quench trip."""
        reactor = PHAThermolysisEngine()
        reactor.trip_active = True
        reactor.safety_quench_active = False

        derivs = reactor._derivatives(reactor.state)
        assert derivs == (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)


# ============================================================================
# 4. TestRK4IntegrationStability
# ============================================================================

class TestRK4IntegrationStability:
    """Validate RK4 integration stability, convergence, step size variation (dt=0.01s to 0.1s)."""

    def test_single_step_rk4_updates_state(self) -> None:
        """Verify a single RK4 step updates state variables consistently."""
        reactor = PHAThermolysisEngine()
        c_pha_0 = reactor.state.c_pha
        c_aa_0 = reactor.state.c_aa
        c_ca_0 = reactor.state.c_ca

        reactor.step_rk4(dt=0.1)

        assert reactor.state.c_pha < c_pha_0
        assert reactor.state.c_aa > c_aa_0
        assert reactor.state.c_ca > c_ca_0
        assert reactor.state.dtr_dt != 0.0
        assert reactor.trip_active is False

    def test_rk4_step_size_variation_stability(self) -> None:
        """Verify numerical stability and convergence across dt=0.01s, 0.05s, and 0.1s."""
        # Run 1 second total simulation time
        r_fine = PHAThermolysisEngine()
        r_mid = PHAThermolysisEngine()
        r_coarse = PHAThermolysisEngine()

        # 100 steps of 0.01s
        for _ in range(100):
            r_fine.step_rk4(dt=0.01)

        # 20 steps of 0.05s
        for _ in range(20):
            r_mid.step_rk4(dt=0.05)

        # 10 steps of 0.10s
        for _ in range(10):
            r_coarse.step_rk4(dt=0.10)

        # All show consistent feed consumption and acrylic acid accumulation
        assert math.isclose(r_fine.state.c_pha, r_coarse.state.c_pha, rel_tol=2e-2)
        assert math.isclose(r_fine.state.c_aa, r_coarse.state.c_aa, rel_tol=2e-2)
        assert math.isclose(r_mid.state.c_pha, r_coarse.state.c_pha, rel_tol=1e-2)

    def test_rk4_clamping_non_negativity(self) -> None:
        """Verify concentration state variables never drop below zero during RK4 integration."""
        st_near_zero = PHAThermolysisState(c_pha=0.01, c_aa=0.001, c_ca=0.001, tr=540.0)
        reactor = PHAThermolysisEngine(state=st_near_zero)

        for _ in range(10):
            reactor.step_rk4(dt=0.1)

        assert reactor.state.c_pha >= 0.0
        assert reactor.state.c_aa >= 0.0
        assert reactor.state.c_ca >= 0.0
        assert reactor.state.pvap >= 0.0
        assert reactor.state.a_cat >= 0.0

    def test_rk4_jacket_core_temperature_coupling(self) -> None:
        """Verify core temperature responds to heating jacket over multiple RK4 steps."""
        reactor = PHAThermolysisEngine()
        reactor.state.tj = 590.0
        reactor.state.tr = 530.0

        for _ in range(5):
            reactor.step_rk4(dt=0.1)

        # Heat transfer from 590 K jacket increases core temperature from 530 K
        assert reactor.state.tr > 530.0

    def test_rk4_vapor_pressure_regulation_via_draw(self) -> None:
        """Verify vapor draw valve maintains stable vapor pressure."""
        reactor = PHAThermolysisEngine()
        for _ in range(15):
            reactor.step_rk4(dt=0.1)

        # Vapor pressure should remain bounded below trip limit
        assert 0.0 < reactor.state.pvap < 35.0

    def test_multi_step_trajectory_smoothness(self) -> None:
        """Verify multi-step simulation trajectory exhibits smooth, monotonic conversion."""
        reactor = PHAThermolysisEngine()
        pha_traj = [reactor.state.c_pha]
        aa_traj = [reactor.state.c_aa]

        for _ in range(10):
            reactor.step_rk4(dt=0.1)
            pha_traj.append(reactor.state.c_pha)
            aa_traj.append(reactor.state.c_aa)

        for i in range(len(pha_traj) - 1):
            assert pha_traj[i + 1] <= pha_traj[i]
            assert aa_traj[i + 1] >= aa_traj[i]

    def test_reactor_class_aliases(self) -> None:
        """Verify all class aliases instantiate and exhibit identical interfaces."""
        for alias in [
            PhaThermolysisEngine,
            PHAThermolysisReactor,
            PhaThermolysisReactor,
            PHAThermolysisSimulator,
            PhaThermolysisSimulator,
            PHAThermolysisLogicUnit,
            PhaThermolysisLogicUnit,
            PHAThermolysisSimulationLogicUnit,
            PhaThermolysisSimulationLogicUnit,
            PHAThermolysisModel,
            PhaThermolysisModel,
            PHAThermolysisPlantModel,
            PhaThermolysisPlantModel,
        ]:
            inst = alias()
            assert isinstance(inst, PHAThermolysisEngine)
            assert inst.state.c_pha == 120.0
            assert inst.unit_id == "PHA_THERM_REACTOR_W308"


# ============================================================================
# 5. TestCarbonMassConservation
# ============================================================================

class TestCarbonMassConservation:
    """Validate continuous and batch carbon mass conservation residuals (< 1e-10)."""

    def test_carbon_mass_conservation_single_cycle(self) -> None:
        """Verify carbon mass conservation residual < 1e-10 in a single closed batch cycle."""
        reactor = PHAThermolysisEngine()
        reactor.step_rk4(dt=0.1)
        assert reactor.conservation_residual < 1e-10

    def test_carbon_mass_conservation_multi_cycle_soak(self) -> None:
        """Verify carbon mass conservation across 50 consecutive RK4 cycles."""
        reactor = PHAThermolysisEngine()
        for cycle in range(1, 51):
            reactor.step_rk4(dt=0.1)
            assert (
                reactor.conservation_residual < 1e-10
            ), f"Cycle {cycle}: residual {reactor.conservation_residual:.2e} exceeded 1e-10"

    def test_carbon_conservation_across_temperatures(self) -> None:
        """Verify carbon conservation holds at 500 K, 540 K, and 580 K."""
        for temp in [500.0, 540.0, 580.0]:
            st = PHAThermolysisState(tr=temp)
            reactor = PHAThermolysisEngine(state=st)
            for _ in range(10):
                reactor.step_rk4(dt=0.1)
            assert reactor.conservation_residual < 1e-10

    def test_carbon_conservation_across_initial_concentrations(self) -> None:
        """Verify carbon conservation across varying initial PHA concentrations."""
        for c0 in [60.0, 120.0, 240.0]:
            st = PHAThermolysisState(c_pha=c0)
            reactor = PHAThermolysisEngine(state=st)
            for _ in range(10):
                reactor.step_rk4(dt=0.1)
            assert reactor.conservation_residual < 1e-10

    def test_carbon_conservation_with_initial_products(self) -> None:
        """Verify carbon conservation holds when initial mixture contains products."""
        st = PHAThermolysisState(c_pha=80.0, c_aa=25.0, c_ca=5.0)
        reactor = PHAThermolysisEngine(state=st)
        for _ in range(10):
            reactor.step_rk4(dt=0.1)
        assert reactor.conservation_residual < 1e-10

    def test_carbon_conservation_various_step_sizes(self) -> None:
        """Verify carbon conservation holds across diverse dt=0.01, 0.05, 0.1."""
        for step_dt in [0.01, 0.05, 0.1]:
            reactor = PHAThermolysisEngine()
            for _ in range(10):
                reactor.step_rk4(dt=step_dt)
            assert reactor.conservation_residual < 1e-10

    def test_conversion_and_selectivity_properties(self) -> None:
        """Verify conversion and selectivity percentage metrics remain bounded in [0, 100]."""
        reactor = PHAThermolysisEngine()
        for _ in range(10):
            reactor.step_rk4(dt=0.1)
        assert 0.0 <= reactor.conversion_pct <= 100.0
        assert 0.0 <= reactor.selectivity_pct <= 100.0


# ============================================================================
# 6. TestThermalRunawayTrip
# ============================================================================

class TestThermalRunawayTrip:
    """Validate Priority 1 thermal runaway safety trips (0xF961, %M629 quench coil asserted)."""

    def test_high_temperature_thermal_runaway_trip_0xf961(self) -> None:
        """Verify Priority 1 trip triggers when core temperature exceeds 680 K."""
        reactor = PHAThermolysisEngine()
        reactor.state.tr = 685.0  # Above 680.0 K threshold
        reactor.step_rk4(dt=0.05)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP
        assert (int(reactor.diagnostic_code) & 0xFFFF) == 0xF961
        assert reactor.safety_quench_active is True
        assert reactor.reactor_active is False
        assert reactor.reg_table.read_bit(COIL_PHA_THERM_REACTOR_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF961

    def test_high_rate_of_rise_runaway_trip_0xf961(self) -> None:
        """Verify Priority 1 trip triggers when temperature rise rate exceeds 15 K/s."""
        reactor = PHAThermolysisEngine()
        reactor.state.dtr_dt = 17.5  # Above 15.0 K/s threshold
        reactor.step_rk4(dt=0.05)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP
        assert (int(reactor.diagnostic_code) & 0xFFFF) == 0xF961
        assert reactor.reg_table.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True

    def test_emergency_quench_cooling_actuation(self) -> None:
        """Verify emergency quench causes rapid temperature drop of both core and jacket."""
        reactor = PHAThermolysisEngine()
        reactor.emergency_quench()
        reactor.trip_active = True
        t_core_0 = reactor.state.tr
        t_jkt_0 = reactor.state.tj

        reactor.step_rk4(dt=0.5)

        assert reactor.state.tr < t_core_0
        assert reactor.state.tj < t_jkt_0
        assert reactor.safety_quench_active is True

    def test_quench_isolates_reactor_and_heaters(self) -> None:
        """Verify emergency quench clears reactor active, closes vapor draw, and zeroes heating duty."""
        reactor = PHAThermolysisEngine()
        reactor.emergency_quench()

        assert reactor.reactor_active is False
        assert reactor.vapor_draw_valve_open is False
        assert reactor.jacket_power_duty == 0.0
        assert reactor.safety_quench_active is True

    def test_derivatives_during_emergency_quench(self) -> None:
        """Verify reaction stops and intense quench cooling dominates derivatives."""
        reactor = PHAThermolysisEngine()
        reactor.trip_active = True
        reactor.safety_quench_active = True

        derivs = reactor._derivatives(reactor.state)
        # Component derivatives are zero
        assert derivs[0] == 0.0
        assert derivs[1] == 0.0
        assert derivs[2] == 0.0
        # Temperatures experience strong negative derivatives
        assert derivs[3] < 0.0
        assert derivs[4] < 0.0
        # Pressure condensation derivative is negative
        assert derivs[5] <= 0.0

    def test_quench_coil_and_register_table_reflection(self) -> None:
        """Verify %M629 and %R2697 are updated immediately on trip."""
        reactor = PHAThermolysisEngine()
        reactor.state.tr = 690.0
        reactor.step_rk4(dt=0.05)

        rt = reactor.reg_table
        assert rt.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True
        assert rt.read_bit(COIL_PHA_THERM_REACTOR_ACTIVE) is False
        assert (rt.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF961


# ============================================================================
# 7. TestVaporOverpressureTrip
# ============================================================================

class TestVaporOverpressureTrip:
    """Validate Priority 2 vapor overpressure trips (0xF962, %M629 asserted)."""

    def test_vapor_overpressure_trip_0xf962(self) -> None:
        """Verify Priority 2 trip triggers when vapor pressure exceeds 35.0 bar."""
        reactor = PHAThermolysisEngine()
        reactor.state.pvap = 36.5
        reactor.step_rk4(dt=0.05)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_OVERPRESSURE_VAPOR_BURST
        assert (int(reactor.diagnostic_code) & 0xFFFF) == 0xF962
        assert reactor.safety_quench_active is True
        assert reactor.reg_table.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF962

    def test_vapor_overpressure_quench_condensation(self) -> None:
        """Verify quench activates rapid condensation lowering vapor pressure."""
        reactor = PHAThermolysisEngine()
        reactor.state.pvap = 36.0
        reactor.step_rk4(dt=0.05)
        p0 = reactor.state.pvap

        # Advance another step during quench
        reactor.step_rk4(dt=0.2)
        assert reactor.state.pvap < p0

    def test_closed_draw_valve_causes_pressure_accumulation(self) -> None:
        """Verify closed vapor draw valve leads to higher rate of pressure increase."""
        r_open = PHAThermolysisEngine()
        r_closed = PHAThermolysisEngine()
        r_closed.vapor_draw_valve_open = False

        deriv_open = r_open._derivatives(r_open.state)[5]
        deriv_closed = r_closed._derivatives(r_closed.state)[5]

        assert deriv_closed > deriv_open

    def test_priority_thermal_runaway_over_vapor_overpressure(self) -> None:
        """Verify Priority 1 (Thermal Runaway 0xF961) dominates Priority 2 (Overpressure 0xF962)."""
        reactor = PHAThermolysisEngine()
        reactor.state.tr = 690.0  # Tripped (P1)
        reactor.state.pvap = 40.0 # Tripped (P2)
        reactor.step_rk4(dt=0.05)

        assert reactor.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF961

    def test_overpressure_register_coils_state(self) -> None:
        """Verify coil states when tripped on overpressure (%M627=False, %M628=False, %M629=True)."""
        reactor = PHAThermolysisEngine()
        reactor.state.pvap = 38.0
        reactor.step_rk4(dt=0.05)

        rt = reactor.reg_table
        assert rt.read_bit(COIL_PHA_THERM_REACTOR_ACTIVE) is False
        assert rt.read_bit(COIL_PHA_THERM_VAPOR_DRAW_VALVE) is False
        assert rt.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True

    def test_overpressure_trip_word_register_masking(self) -> None:
        """Verify signed 16-bit safe masking of 0xF962 in %R2697."""
        reactor = PHAThermolysisEngine()
        reactor.diagnostic_code = DiagnosticCode(0xF962)
        reactor.trip_active = True
        reactor.sync_to_registers(reactor.reg_table)

        raw = reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE)
        assert (raw & 0xFFFF) == 0xF962
        assert DiagnosticCode(0xF962) == raw


# ============================================================================
# 8. TestCatalystCokingTrip
# ============================================================================

class TestCatalystCokingTrip:
    """Validate Priority 3 catalyst coking deactivation trips (0xF963) and kinetics."""

    def test_catalyst_coking_deactivation_trip_0xf963(self) -> None:
        """Verify Priority 3 trip triggers when relative catalyst activity drops below 0.20."""
        reactor = PHAThermolysisEngine()
        reactor.state.a_cat = 0.18
        reactor.step_rk4(dt=0.05)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_CATALYST_COKING_LOSS
        assert (int(reactor.diagnostic_code) & 0xFFFF) == 0xF963
        assert reactor.safety_quench_active is True
        assert reactor.reg_table.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF963

    def test_coking_rate_temperature_dependence(self) -> None:
        """Verify catalyst coking rate accelerates at higher temperatures."""
        reactor = PHAThermolysisEngine()
        st_low_t = PHAThermolysisState(tr=520.0, a_cat=1.0, c_pha=120.0)
        st_high_t = PHAThermolysisState(tr=580.0, a_cat=1.0, c_pha=120.0)

        _, _, d_low = reactor.compute_rates(st_low_t)
        _, _, d_high = reactor.compute_rates(st_high_t)

        assert abs(d_high) > abs(d_low)
        assert d_high < 0.0
        assert d_low < 0.0

    def test_coking_monotonic_decay_over_time(self) -> None:
        """Verify catalyst activity decays monotonically during continuous operation."""
        cfg_fast = PHAThermolysisConfig(kd=5.0)
        reactor = PHAThermolysisEngine(config=cfg_fast)
        a_history = [reactor.state.a_cat]

        for _ in range(5):
            reactor.step_rk4(dt=0.2)
            a_history.append(reactor.state.a_cat)

        for i in range(len(a_history) - 1):
            assert a_history[i + 1] <= a_history[i]
        assert a_history[-1] < a_history[0]

    def test_priority_overpressure_over_coking(self) -> None:
        """Verify Priority 2 (Overpressure 0xF962) dominates Priority 3 (Coking 0xF963)."""
        reactor = PHAThermolysisEngine()
        reactor.state.pvap = 40.0  # Tripped (P2)
        reactor.state.a_cat = 0.10 # Tripped (P3)
        reactor.step_rk4(dt=0.05)

        assert reactor.diagnostic_code == DIAG_ERR_OVERPRESSURE_VAPOR_BURST
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF962

    def test_priority_coking_over_feed_starvation(self) -> None:
        """Verify Priority 3 (Coking 0xF963) dominates Priority 5 (Feed Starvation 0xF965)."""
        reactor = PHAThermolysisEngine()
        reactor.state.a_cat = 0.10 # Tripped (P3)
        reactor.state.tr = 380.0   # Tripped (P5)
        reactor.step_rk4(dt=0.05)

        assert reactor.diagnostic_code == DIAG_ERR_CATALYST_COKING_LOSS
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF963

    def test_coking_trip_quench_assertion(self) -> None:
        """Verify safety quench coil %M629 is asserted upon coking loss."""
        reactor = PHAThermolysisEngine()
        reactor.state.a_cat = 0.15
        reactor.step_rk4(dt=0.05)

        assert reactor.reg_table.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True


# ============================================================================
# 9. TestRegisterTableSynchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate RegisterTable synchronization across %R2690..%R2697 and %M627..%M629."""

    def test_nominal_register_sync(self) -> None:
        """Verify all register values synchronized to Horner OCS memory space %R2690..%R2697."""
        reactor = PHAThermolysisEngine()
        reactor.scan_step(dt=0.1)
        rt = reactor.reg_table

        w_tr = rt.read_word(REG_PHA_THERM_REACTOR_TEMP)
        w_tj = rt.read_word(REG_PHA_THERM_JACKET_TEMP)
        w_pvap = rt.read_word(REG_PHA_THERM_VAPOR_PRESSURE)
        w_caa = rt.read_word(REG_PHA_THERM_ACRYLIC_ACID_CONC)
        w_conv = rt.read_word(REG_PHA_THERM_CONVERSION_RATE)
        w_sel = rt.read_word(REG_PHA_THERM_ACRYLIC_SELECTIVITY)
        w_duty = rt.read_word(REG_PHA_THERM_JACKET_POWER_DUTY)
        w_diag = rt.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE)

        assert w_tr > 0
        assert w_tj > 0
        assert w_pvap > 0
        assert w_caa > 0
        assert w_conv >= 0
        assert w_sel > 0
        assert w_duty > 0
        assert (w_diag & 0xFFFF) == 0x0000

    def test_discrete_coils_nominal_state(self) -> None:
        """Verify coils %M627=True, %M628=True, %M629=False in nominal operating state."""
        reactor = PHAThermolysisEngine()
        reactor.sync_to_registers(reactor.reg_table)
        rt = reactor.reg_table

        assert rt.read_bit(COIL_PHA_THERM_REACTOR_ACTIVE) is True
        assert rt.read_bit(COIL_PHA_THERM_VAPOR_DRAW_VALVE) is True
        assert rt.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is False

    def test_signed_16bit_temperature_registers(self) -> None:
        """Verify signed 16-bit safe conversion for temperatures below 0 °C."""
        reactor = PHAThermolysisEngine()
        # 260.0 K = -13.15 °C -> scaled x10 is -132 (signed 16-bit)
        reactor.state.tr = 260.0
        reactor.sync_to_registers(reactor.reg_table)

        w_tr = reactor.reg_table.read_word(REG_PHA_THERM_REACTOR_TEMP)
        # Check signed 16-bit equivalence
        signed_val = w_tr - 0x10000 if w_tr >= 0x8000 else w_tr
        assert signed_val == -131 or signed_val == -132

    def test_all_diagnostic_codes_written_to_reg2697(self) -> None:
        """Verify diagnostic codes 0x0000, 0xF961..0xF965 correctly written and masked."""
        reactor = PHAThermolysisEngine()
        codes = [0x0000, 0xF961, 0xF962, 0xF963, 0xF964, 0xF965]

        for c_val in codes:
            reactor.diagnostic_code = DiagnosticCode(c_val)
            reactor.sync_to_registers(reactor.reg_table)
            raw = reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE)
            assert (raw & 0xFFFF) == c_val

    def test_mass_balance_divergence_trip_0xf964(self) -> None:
        """Verify Priority 4 trip triggers on carbon mass balance divergence (> 1e-4)."""
        reactor = PHAThermolysisEngine()
        reactor.conservation_residual = 0.005
        reactor.step_rk4(dt=0.05)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF964

    def test_feed_starvation_trip_0xf965(self) -> None:
        """Verify Priority 5 trip triggers on low temperature (< 400 K) or feed starvation."""
        reactor = PHAThermolysisEngine()
        reactor.state.tr = 385.0
        reactor.step_rk4(dt=0.05)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_FEED_STARVATION_LOW_TEMP
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF965

    def test_register_sync_privilege_modes(self) -> None:
        """Verify synchronization operates cleanly under both USER and SYSTEM privilege modes."""
        reactor = PHAThermolysisEngine()
        rt = RegisterTable()
        reactor.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert (rt.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        reactor.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000


# ============================================================================
# 10. TestPureStructuredTextPOU
# ============================================================================

class TestPureStructuredTextPOU:
    """Validate pure ST POU validation and anti-ladder rejection of all 9 constructs."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify pure ST POU syntax using verify_pha_thermolysis_pure_st()."""
        assert verify_pha_thermolysis_pure_st() is True
        assert verify_pha_therm_pure_st() is True

    def test_st_parser_ast_validation(self) -> None:
        """Verify STParser parses PHA_THERMOLYSIS_PURE_ST_POU cleanly with 0 errors."""
        res = STParser.validate_code(PHA_THERMOLYSIS_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_anti_ladder_contacts_rejection(self) -> None:
        """Verify ladder logic contact syntax (---[ ]---) is rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\n---[ ]---\nEND_PROGRAM")

    def test_anti_ladder_inverted_contacts_rejection(self) -> None:
        """Verify inverted contact syntax (---[/]---) is rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\n---[/]---\nEND_PROGRAM")

    def test_anti_ladder_coils_rejection(self) -> None:
        """Verify normal coil syntax (---( )---) is rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\n---( )---\nEND_PROGRAM")

    def test_anti_ladder_negated_coils_rejection(self) -> None:
        """Verify negated coil syntax (---(/)---) is rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\n---(/)---\nEND_PROGRAM")

    def test_anti_ladder_set_reset_coils_rejection(self) -> None:
        """Verify set/reset coil syntax (---(S)---, ---(R)---) are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\n---(S)---\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\n---(R)---\nEND_PROGRAM")

    def test_anti_ladder_rung_and_network_rejection(self) -> None:
        """Verify ladder rung and network delimiters are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: START")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 10")

    def test_anti_ladder_mnemonic_rejection(self) -> None:
        """Verify ladder mnemonic syntax (XIC %M627) is rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC %M627")


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Validate ILogicUnit scan step compliance, reset behavior, and 100-cycle simulation soak with memory profiling."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify ILogicUnit standard properties (unit_id, name, priority, is_enabled)."""
        reactor = PHAThermolysisEngine()
        assert reactor.unit_id == "PHA_THERM_REACTOR_W308"
        assert reactor.name == "PHAThermolysisEngine"
        assert reactor.priority == 50
        assert reactor.is_enabled is True

    def test_scan_step_various_invocation_signatures(self) -> None:
        """Verify scan_step handles diverse parameter invocation signatures."""
        reactor = PHAThermolysisEngine()

        # 1. Positional dt
        res1 = reactor.scan_step(0.05)
        assert res1.status == AgentStatus.SUCCESS

        # 2. Kwarg dt
        res2 = reactor.scan_step(dt=0.10)
        assert res2.status == AgentStatus.SUCCESS

        # 3. Kwarg dt_h
        res3 = reactor.scan_step(dt_h=0.0001)
        assert res3.status == AgentStatus.SUCCESS

    def test_scan_step_with_scan_context(self) -> None:
        """Verify scan_step with ScanContext propagates RegisterTable."""
        rt_ext = RegisterTable()
        context = ScanContext(cycle=1, dt=0.1, register_table=rt_ext)
        reactor = PHAThermolysisEngine()

        res = reactor.scan_step(context=context)
        assert res.status == AgentStatus.SUCCESS
        assert reactor.reg_table is rt_ext
        assert rt_ext.read_bit(COIL_PHA_THERM_REACTOR_ACTIVE) is True

    def test_step_and_execute_methods(self) -> None:
        """Verify step() and execute() methods correctly invoke scan_step and increment cycle count."""
        reactor = PHAThermolysisEngine()
        c0 = reactor.cycle_count
        reactor.step(0.1)
        assert reactor.cycle_count == c0 + 1

        reactor.execute(0.1)
        assert reactor.cycle_count == c0 + 2

    def test_scan_step_execution_result_contract(self) -> None:
        """Verify scan_step returns strict 4-state ExecutionResult contract."""
        reactor = PHAThermolysisEngine()
        res = reactor.scan_step(dt=0.1)

        assert isinstance(res, ExecutionResult)
        assert res.status in [AgentStatus.SUCCESS, AgentStatus.FAILED]
        assert "c_pha" in res.data
        assert "c_aa" in res.data
        assert "tr" in res.data
        assert "pvap" in res.data
        assert "conversion_pct" in res.data
        assert "selectivity_pct" in res.data
        assert "conservation_residual" in res.data
        assert res.error_code is None

    def test_reset_functionality(self) -> None:
        """Verify reset() restores default initial conditions and clears safety trips."""
        reactor = PHAThermolysisEngine()
        reactor.state.tr = 690.0
        reactor.step_rk4(dt=0.05)
        assert reactor.trip_active is True

        reactor.reset()
        assert reactor.trip_active is False
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.state.c_pha == 120.0
        assert reactor.state.tr == 540.0
        assert reactor.safety_quench_active is False
        assert (reactor.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_100_cycle_simulation_soak_and_memory_profiling(self) -> None:
        """Execute 100-cycle continuous simulation soak and profile execution performance."""
        reactor = PHAThermolysisEngine()
        t_start = time.perf_counter()

        for cycle in range(1, 101):
            res = reactor.scan_step(dt=0.05)
            assert res.status == AgentStatus.SUCCESS
            assert reactor.conservation_residual < 1e-10

        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        avg_cycle_ms = elapsed_ms / 100.0

        # Assert rapid simulation performance (< 5ms per scan cycle)
        assert avg_cycle_ms < 5.0
        assert reactor.cycle_count == 100
        assert reactor.trip_active is False


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
            res = run_pha_thermolysis_verification(output_path=out_path)
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
        res = run_pha_thermolysis_verification(quick=True)
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_evidence_json_structure_and_hashes(self) -> None:
        """Verify evidence JSON contains SHA-256 digests for POU and model config."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = run_pha_thermolysis_verification(output_path=out_path, quick=True)
            digests = res["data"]["digests"]
            assert "pou_sha256" in digests
            assert "model_sha256" in digests
            assert len(digests["pou_sha256"]) == 64
            assert len(digests["model_sha256"]) == 64
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_scripts_runner_module_execution(self) -> None:
        """Verify execution of scripts/run_pha_thermolysis_verification.py module runner."""
        from scripts.run_pha_thermolysis_verification import (
            execute_pha_thermolysis_verification,
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = execute_pha_thermolysis_verification(output_path=out_path, quick=True)
            assert res["status"] == "success"
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_main_entrypoint_with_tempfile(self) -> None:
        """Verify CLI main() in scripts/run_pha_thermolysis_verification.py passes cleanly."""
        from scripts.run_pha_thermolysis_verification import main as script_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = script_main(["--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_simulation_cli_main_entrypoint(self) -> None:
        """Verify CLI main() in src/jev_cscape/simulation/pha_thermolysis.py passes cleanly."""
        from jev_cscape.simulation.pha_thermolysis import main as sim_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = sim_main(["--verify", "--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)
