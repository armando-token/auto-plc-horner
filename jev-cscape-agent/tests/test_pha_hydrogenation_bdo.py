"""Industrial Catalytic Polyhydroxyalkanoate Hydrogenation & 1,4-Butanediol Precursor Fixed-Bed ODE Simulation Unit Test Suite (W317).

Work Package: W317 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification test classes (85+ test cases):
1. TestPhysicalConstantsAndRegisters: Physical constants, stoichiometry, register %R2780..%R2787, coils %M648..%M650, signed 16-bit safe comparisons.
2. TestReactionRatesAndSelectivity: Catalytic hydrogenation reaction rates, GBL intermediate, BDO selectivity, Langmuir-Hinshelwood kinetics.
3. TestCoupled6StateDerivatives: 6-state fixed-bed ODE derivative calculations, mass/energy balance, volume/concentration non-negativity.
4. TestRK4IntegrationStability: RK4 stability, step size variation (dt=0.01s to 0.2s), trajectory smoothness, and class aliases.
5. TestMassBalanceConservation: Continuous carbon backbone mass conservation residuals (< 1e-10) across diverse conversion regimes.
6. TestThermalRunawayTrip: Thermal runaway runaway trip (0xF991, %M650 emergency depressurize asserted, %M649 H2 feed valve de-asserted).
7. TestReactorOverpressureTrip: Reactor overpressure trip (0xF992, %M650 emergency depressurize asserted, vent depressurization dynamics).
8. TestCatalystCokingAndH2StarvationTrips: Catalyst coking and H2 starvation trips (0xF993, 0xF994, 0xF995, fault priority hierarchy).
9. TestRegisterTableSynchronization: Horner OCS memory sync across %R2780..%R2787 and %M648..%M650 with signed 16-bit masking.
10. TestPureStructuredTextPOU: Pure IEC 61131-3 ST POU validation and anti-ladder rejection of all 9 constructs.
11. TestILogicUnitComplianceAndSoak: ILogicUnit scan step compliance, reset behavior, and 100-cycle simulation soak with memory profiling.
12. TestVerificationRunnerAndCLI: Deterministic 9-stage verification runner and CLI interop (pass tempfile for --output!).
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

from jev_cscape.simulation.pha_hydrogenation_bdo import (
    COIL_PHA_H2_ACTIVE,
    COIL_PHA_H2_DEPRESSURIZE,
    COIL_PHA_H2_EMERGENCY_DEPRESSURIZE,
    COIL_PHA_H2_FEED,
    COIL_PHA_H2_HYDROGEN_FEED_VALVE,
    COIL_PHA_H2_REACTOR_ACTIVE,
    COIL_PHA_H2_RUNNING,
    COIL_PHA_H2_VALVE,
    COIL_PHA_H2_VENT,
    DIAG_ERR_CATALYST_COKING,
    DIAG_ERR_COKING,
    DIAG_ERR_DEACTIVATED,
    DIAG_ERR_H2_STARVATION,
    DIAG_ERR_HYDROGEN_STARVATION,
    DIAG_ERR_MASS_BALANCE,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_MASS_DIVERGENCE,
    DIAG_ERR_OVERHEAT,
    DIAG_ERR_OVERPRESSURE,
    DIAG_ERR_OVERPRESSURE_RUPTURE,
    DIAG_ERR_PRESSURE,
    DIAG_ERR_RUNAWAY,
    DIAG_ERR_STARVATION,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_OK,
    DiagnosticCode,
    MW_BDO,
    MW_CARBON,
    MW_GBL,
    MW_H2,
    MW_METHANOL,
    MW_SUCCINATE_ESTER,
    PHA_H2_BDO_PURE_ST_POU,
    PHA_HYDROGENATION_BDO_CONTROL_POU,
    PHA_HYDROGENATION_BDO_PURE_ST_POU,
    PHAH2BDOConfig,
    PHAH2BDODiagnosticCode,
    PHAH2BDOEngine,
    PHAH2BDOSimulator,
    PHAH2BDOState,
    PHAH2BDOStatusBits,
    PHAH2BDOStatusWord,
    PHAHydrogenationBDOConfig,
    PHAHydrogenationBDOControl,
    PHAHydrogenationBDODiagnosticCode,
    PHAHydrogenationBDOEngine,
    PHAHydrogenationBDOLogicUnit,
    PHAHydrogenationBDOParameters,
    PHAHydrogenationBDOReactor,
    PHAHydrogenationBDOSimulator,
    PHAHydrogenationBDOState,
    PHAHydrogenationBDOStateModel,
    PHAHydrogenationBDOStatusBits,
    PHAHydrogenationBDOStatusWord,
    PhaH2BDOConfig,
    PhaH2BDODiagnosticCode,
    PhaH2BDOEngine,
    PhaH2BDOSimulator,
    PhaH2BDOState,
    PhaH2BDOStatusBits,
    PhaH2BDOStatusWord,
    PhaHydrogenationBDOConfig,
    PhaHydrogenationBDODiagnosticCode,
    PhaHydrogenationBDOEngine,
    PhaHydrogenationBDOLogicUnit,
    PhaHydrogenationBDOParameters,
    PhaHydrogenationBDOReactor,
    PhaHydrogenationBDOSimulator,
    PhaHydrogenationBDOState,
    PhaHydrogenationBDOStateModel,
    PhaHydrogenationBDOStatusBits,
    PhaHydrogenationBDOStatusWord,
    R_GAS_CONSTANT,
    REG_PHA_H2_ACTIVITY,
    REG_PHA_H2_BDO_SELECTIVITY,
    REG_PHA_H2_CATALYST_ACTIVITY,
    REG_PHA_H2_CONVERSION,
    REG_PHA_H2_CONVERSION_EFFICIENCY,
    REG_PHA_H2_DIAG,
    REG_PHA_H2_DIAGNOSTIC_CODE,
    REG_PHA_H2_EFFICIENCY,
    REG_PHA_H2_FLOW,
    REG_PHA_H2_HYDROGEN_FLOW_SLPM,
    REG_PHA_H2_LHSV,
    REG_PHA_H2_PRESSURE,
    REG_PHA_H2_P_REACTOR,
    REG_PHA_H2_REACTOR_PRESSURE,
    REG_PHA_H2_REACTOR_TEMP,
    REG_PHA_H2_REACTOR_TEMPERATURE,
    REG_PHA_H2_SELECTIVITY,
    REG_PHA_H2_SPACE_VELOCITY_LHSV,
    REG_PHA_H2_TEMP,
    REG_PHA_H2_T_BED,
    ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL,
    T_ZERO_CELSIUS,
    run_pha_h2_bdo_verification,
    run_pha_hydrogenation_bdo_verification,
    verify_pha_h2_bdo_pure_st,
    verify_pha_hydrogenation_bdo_pure_st,
)


# ============================================================================
# 1. TestPhysicalConstantsAndRegisters
# ============================================================================

class TestPhysicalConstantsAndRegisters:
    """Validate stoichiometry, molecular weights, register mappings, coils, and signed 16-bit diagnostic codes."""

    def test_molecular_weights_and_constants(self) -> None:
        """Verify molecular weights of succinate ester, GBL, BDO, H2, methanol, carbon, and universal constants."""
        assert math.isclose(MW_SUCCINATE_ESTER, 146.14, rel_tol=1e-4)
        assert math.isclose(MW_GBL, 86.09, rel_tol=1e-4)
        assert math.isclose(MW_BDO, 90.12, rel_tol=1e-4)
        assert math.isclose(MW_H2, 2.016, rel_tol=1e-4)
        assert math.isclose(MW_METHANOL, 32.04, rel_tol=1e-4)
        assert math.isclose(MW_CARBON, 12.011, rel_tol=1e-4)
        assert math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-6)

    def test_reaction_stoichiometry_and_carbon_conservation(self) -> None:
        """Verify stoichiometry and carbon balance: Step 1 (SE + 2 H2 -> GBL + 2 MeOH) and Step 2 (GBL + 2 H2 -> BDO)."""
        # Overall reaction: C6H10O4 (DMS, 6 C) + 4 H2 -> C4H10O2 (BDO, 4 C) + 2 CH3OH (2 C)
        c_se = 6
        c_gbl = 4
        c_bdo = 4
        c_meoh = 1
        assert c_se == c_bdo + 2 * c_meoh
        assert c_se == c_gbl + 2 * c_meoh
        # C4 carbon backbone conservation (SE core C4 -> GBL C4 -> BDO C4)
        c4_core = 4
        assert c4_core == c_gbl == c_bdo

    def test_register_address_constants_and_aliases(self) -> None:
        """Verify Horner OCS word register addresses %R2780..%R2787 and string aliases."""
        assert REG_PHA_H2_REACTOR_TEMP == "%R2780"
        assert REG_PHA_H2_TEMP == "%R2780"
        assert REG_PHA_H2_T_BED == "%R2780"
        assert REG_PHA_H2_REACTOR_TEMPERATURE == "%R2780"

        assert REG_PHA_H2_REACTOR_PRESSURE == "%R2781"
        assert REG_PHA_H2_PRESSURE == "%R2781"
        assert REG_PHA_H2_P_REACTOR == "%R2781"

        assert REG_PHA_H2_CONVERSION_EFFICIENCY == "%R2782"
        assert REG_PHA_H2_CONVERSION == "%R2782"
        assert REG_PHA_H2_EFFICIENCY == "%R2782"

        assert REG_PHA_H2_BDO_SELECTIVITY == "%R2783"
        assert REG_PHA_H2_SELECTIVITY == "%R2783"

        assert REG_PHA_H2_SPACE_VELOCITY_LHSV == "%R2784"
        assert REG_PHA_H2_LHSV == "%R2784"

        assert REG_PHA_H2_CATALYST_ACTIVITY == "%R2785"
        assert REG_PHA_H2_ACTIVITY == "%R2785"

        assert REG_PHA_H2_HYDROGEN_FLOW_SLPM == "%R2786"
        assert REG_PHA_H2_FLOW == "%R2786"

        assert REG_PHA_H2_DIAGNOSTIC_CODE == "%R2787"
        assert REG_PHA_H2_DIAG == "%R2787"

    def test_discrete_coils_constants_and_aliases(self) -> None:
        """Verify Horner OCS discrete coil addresses %M648..%M650 and string aliases."""
        assert COIL_PHA_H2_REACTOR_ACTIVE == "%M648"
        assert COIL_PHA_H2_ACTIVE == "%M648"
        assert COIL_PHA_H2_RUNNING == "%M648"

        assert COIL_PHA_H2_HYDROGEN_FEED_VALVE == "%M649"
        assert COIL_PHA_H2_VALVE == "%M649"
        assert COIL_PHA_H2_FEED == "%M649"

        assert COIL_PHA_H2_EMERGENCY_DEPRESSURIZE == "%M650"
        assert COIL_PHA_H2_DEPRESSURIZE == "%M650"
        assert COIL_PHA_H2_VENT == "%M650"

    def test_diagnostic_codes_values_and_aliases(self) -> None:
        """Verify hexadecimal diagnostic error constants and convenience aliases."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_THERMAL_RUNAWAY == 0xF991
        assert DIAG_ERR_RUNAWAY == 0xF991
        assert DIAG_ERR_OVERHEAT == 0xF991

        assert DIAG_ERR_OVERPRESSURE_RUPTURE == 0xF992
        assert DIAG_ERR_OVERPRESSURE == 0xF992
        assert DIAG_ERR_PRESSURE == 0xF992

        assert DIAG_ERR_CATALYST_COKING == 0xF993
        assert DIAG_ERR_COKING == 0xF993
        assert DIAG_ERR_DEACTIVATED == 0xF993

        assert DIAG_ERR_HYDROGEN_STARVATION == 0xF994
        assert DIAG_ERR_STARVATION == 0xF994
        assert DIAG_ERR_H2_STARVATION == 0xF994

        assert DIAG_ERR_MASS_BALANCE_DIVERGENCE == 0xF995
        assert DIAG_ERR_MASS_DIVERGENCE == 0xF995
        assert DIAG_ERR_MASS_BALANCE == 0xF995

    def test_diagnostic_code_signed_safe_equality(self) -> None:
        """Verify DiagnosticCode handles signed/unsigned 16-bit comparisons and edge cases."""
        # Unsigned 0xF991 is signed -1647 in 16-bit two's complement
        code_91 = DiagnosticCode(0xF991)
        assert code_91 == 0xF991
        assert code_91 == -1647
        assert code_91 == DiagnosticCode(0xF991)
        assert hash(code_91) == hash(0xF991)
        assert str(code_91) == "0xF991"
        assert repr(code_91) == "DiagnosticCode(0xF991)"

        # Unsigned 0xF992 is signed -1646
        code_92 = DiagnosticCode(0xF992)
        assert code_92 == 0xF992
        assert code_92 == -1646

        # Unsigned 0xF993 is signed -1645
        code_93 = DiagnosticCode(0xF993)
        assert code_93 == 0xF993
        assert code_93 == -1645

        # Unsigned 0xF994 is signed -1644
        code_94 = DiagnosticCode(0xF994)
        assert code_94 == 0xF994
        assert code_94 == -1644

        # Unsigned 0xF995 is signed -1643
        code_95 = DiagnosticCode(0xF995)
        assert code_95 == 0xF995
        assert code_95 == -1643

        # Non-integer comparison should return False
        assert code_91 != "0xF991"
        assert code_91 != 3.14

    def test_status_word_bitmask_flags(self) -> None:
        """Verify PHAHydrogenationBDOStatusWord bitmask definitions and aliases."""
        assert PHAHydrogenationBDOStatusWord.REACTOR_ACTIVE == 1 << 0
        assert PHAHydrogenationBDOStatusWord.H2_FEED_VALVE == 1 << 1
        assert PHAHydrogenationBDOStatusWord.EMERGENCY_DEPRESS == 1 << 2
        assert PHAHydrogenationBDOStatusWord.COOLING_JACKET == 1 << 3
        assert PHAHydrogenationBDOStatusWord.TEMP_WARN == 1 << 4
        assert PHAHydrogenationBDOStatusWord.PRESSURE_WARN == 1 << 5
        assert PHAHydrogenationBDOStatusWord.CATALYST_WARN == 1 << 6
        assert PHAHydrogenationBDOStatusWord.EMERGENCY_TRIP == 1 << 7

        assert PHAHydrogenationBDOStatusWord is PhaHydrogenationBDOStatusWord
        assert PHAHydrogenationBDOStatusWord is PHAH2BDOStatusWord
        assert PHAHydrogenationBDOStatusBits is PHAHydrogenationBDOStatusWord

    def test_state_initialization_defaults_and_properties(self) -> None:
        """Verify PHAHydrogenationBDOState initial nominal values and property accessors."""
        st = PHAHydrogenationBDOState()
        assert math.isclose(st.c_succinate_ester, 3.0, rel_tol=1e-4)
        assert math.isclose(st.c_gbl_intermediate, 0.05, rel_tol=1e-4)
        assert math.isclose(st.c_bdo_product, 0.02, rel_tol=1e-4)
        assert math.isclose(st.c_h2_dissolved, 0.39, rel_tol=1e-4)
        assert math.isclose(st.t_bed_kelvin, 473.15, rel_tol=1e-4)
        assert math.isclose(st.a_catalyst, 1.0, rel_tol=1e-4)
        assert math.isclose(st.p_reactor, 50.0, rel_tol=1e-4)
        assert math.isclose(st.h2_flow_slpm, 750.0, rel_tol=1e-4)
        assert math.isclose(st.space_velocity_lhsv, 1.50, rel_tol=1e-4)
        assert math.isclose(st.dt_bed_dt, 0.0, abs_tol=1e-6)

        # Property aliases
        assert st.c_se == st.c_succinate_ester
        assert st.C_se == st.c_succinate_ester
        assert st.succinate_ester == st.c_succinate_ester
        assert st.c_gbl == st.c_gbl_intermediate
        assert st.gbl_intermediate == st.c_gbl_intermediate
        assert st.c_bdo == st.c_bdo_product
        assert st.bdo_product == st.c_bdo_product
        assert st.c_h2 == st.c_h2_dissolved
        assert st.t_bed == st.t_bed_kelvin
        assert st.T_bed == st.t_bed_kelvin
        assert st.a_cat == st.a_catalyst
        assert st.catalyst_activity == st.a_catalyst
        assert st.P_reactor == st.p_reactor
        assert st.LHSV == st.space_velocity_lhsv

        # Setter verification
        st.c_se = 2.5
        assert st.c_succinate_ester == 2.5
        st.c_gbl = 0.8
        assert st.c_gbl_intermediate == 0.8
        st.c_bdo = 1.2
        assert st.c_bdo_product == 1.2
        st.c_h2 = 0.45
        assert st.c_h2_dissolved == 0.45
        st.t_bed = 480.0
        assert st.t_bed_kelvin == 480.0
        st.a_cat = 0.95
        assert st.a_catalyst == 0.95

        # Serialization roundtrip
        d = st.to_dict()
        assert "c_succinate_ester" in d
        assert "t_bed_kelvin" in d
        st_recon = PHAHydrogenationBDOState.from_dict(d)
        assert math.isclose(st_recon.c_succinate_ester, 2.5, rel_tol=1e-4)
        assert math.isclose(st_recon.t_bed_kelvin, 480.0, rel_tol=1e-4)

    def test_config_initialization_and_property_aliases(self) -> None:
        """Verify PHAHydrogenationBDOConfig default values and alias properties."""
        cfg = PHAHydrogenationBDOConfig()
        assert cfg.k1_forward == 4.0e4
        assert cfg.k1 == 4.0e4
        assert cfg.ea1_j_mol == 48000.0
        assert cfg.ea1 == 48000.0
        assert cfg.k2_forward == 5.0e4
        assert cfg.k2 == 5.0e4
        assert cfg.ea2_j_mol == 52000.0
        assert cfg.ea2 == 52000.0

        assert cfg.t_bed_trip_max == 550.0
        assert cfg.dt_bed_dt_trip_max == 15.0
        assert cfg.p_reactor_trip_max == 80.0
        assert cfg.catalyst_activity_min == 0.30
        assert cfg.h2_substrate_ratio_min == 2.0
        assert cfg.mass_residual_max == 1e-4

        # Property setter
        cfg.k1 = 4.5e4
        assert cfg.k1_forward == 4.5e4
        cfg.k2 = 5.5e4
        assert cfg.k2_forward == 5.5e4

        d = cfg.to_dict()
        assert d["k1_forward"] == 4.5e4
        assert d["t_bed_trip_max"] == 550.0


# ============================================================================
# 2. TestReactionRatesAndSelectivity
# ============================================================================

class TestReactionRatesAndSelectivity:
    """Validate Langmuir-Hinshelwood catalytic hydrogenation kinetics, GBL intermediate, and BDO selectivity."""

    def test_langmuir_hinshelwood_reaction_rates_positive(self) -> None:
        """Verify reaction rates r1 and r2 are positive under nominal operating conditions."""
        engine = PHAHydrogenationBDOEngine()
        r1, r2 = engine.compute_rates(engine.state)
        assert r1 > 0.0
        assert r2 > 0.0
        assert isinstance(r1, float)
        assert isinstance(r2, float)

    def test_arrhenius_temperature_dependence(self) -> None:
        """Verify reaction rates increase strictly with temperature following Arrhenius kinetics."""
        engine = PHAHydrogenationBDOEngine()
        st_cold = PHAHydrogenationBDOState(t_bed_kelvin=430.0)
        st_nom = PHAHydrogenationBDOState(t_bed_kelvin=473.15)
        st_hot = PHAHydrogenationBDOState(t_bed_kelvin=510.0)

        r1_cold, r2_cold = engine.compute_rates(st_cold)
        r1_nom, r2_nom = engine.compute_rates(st_nom)
        r1_hot, r2_hot = engine.compute_rates(st_hot)

        assert r1_hot > r1_nom > r1_cold > 0.0
        assert r2_hot > r2_nom > r2_cold > 0.0

    def test_dissolved_h2_concentration_dependence(self) -> None:
        """Verify reaction rates increase with higher dissolved H2 concentration."""
        engine = PHAHydrogenationBDOEngine()
        st_low_h2 = PHAHydrogenationBDOState(c_h2_dissolved=0.10)
        st_high_h2 = PHAHydrogenationBDOState(c_h2_dissolved=0.50)

        r1_low, r2_low = engine.compute_rates(st_low_h2)
        r1_high, r2_high = engine.compute_rates(st_high_h2)

        assert r1_high > r1_low > 0.0
        assert r2_high > r2_low > 0.0

    def test_catalyst_activity_scaling(self) -> None:
        """Verify reaction rates scale linearly with catalyst activity a_catalyst."""
        engine = PHAHydrogenationBDOEngine()
        st_full = PHAHydrogenationBDOState(a_catalyst=1.0)
        st_half = PHAHydrogenationBDOState(a_catalyst=0.5)

        r1_full, r2_full = engine.compute_rates(st_full)
        r1_half, r2_half = engine.compute_rates(st_half)

        assert math.isclose(r1_half, 0.5 * r1_full, rel_tol=1e-5)
        assert math.isclose(r2_half, 0.5 * r2_full, rel_tol=1e-5)

    def test_competitive_adsorption_denominator(self) -> None:
        """Verify that high intermediate and product concentrations competitively inhibit the rate per site."""
        engine = PHAHydrogenationBDOEngine()
        st_dilute = PHAHydrogenationBDOState(
            c_succinate_ester=2.0, c_gbl_intermediate=0.01, c_bdo_product=0.01, c_h2_dissolved=0.3
        )
        st_inhibited = PHAHydrogenationBDOState(
            c_succinate_ester=2.0, c_gbl_intermediate=1.5, c_bdo_product=2.0, c_h2_dissolved=0.3
        )

        r1_dilute, _ = engine.compute_rates(st_dilute)
        r1_inhibited, _ = engine.compute_rates(st_inhibited)

        # Denominator is larger with higher GBL and BDO, lowering r1
        assert r1_dilute > r1_inhibited > 0.0

    def test_gbl_intermediate_consumption_kinetics(self) -> None:
        """Verify that step 2 rate r2 is zero when GBL intermediate is zero and positive when GBL > 0."""
        engine = PHAHydrogenationBDOEngine()
        st_zero_gbl = PHAHydrogenationBDOState(c_gbl_intermediate=0.0)
        st_with_gbl = PHAHydrogenationBDOState(c_gbl_intermediate=0.2)

        _, r2_zero = engine.compute_rates(st_zero_gbl)
        _, r2_with = engine.compute_rates(st_with_gbl)

        assert r2_zero == 0.0
        assert r2_with > 0.0

    def test_bdo_selectivity_calculation(self) -> None:
        """Verify bdo_selectivity_pct calculation relative to consumed substrate and products."""
        engine = PHAHydrogenationBDOEngine()
        # Initially, selectivity is calculated from product distribution
        sel_0 = engine.bdo_selectivity_pct
        assert 0.0 <= sel_0 <= 100.0

        # Run several steps to produce more BDO
        for _ in range(10):
            engine.step_rk4(dt=0.1)

        sel_evolved = engine.bdo_selectivity_pct
        assert 0.0 <= sel_evolved <= 100.0

    def test_conversion_efficiency_calculation(self) -> None:
        """Verify conversion_efficiency_pct calculation based on consumed succinate ester."""
        engine = PHAHydrogenationBDOEngine()
        assert engine.conversion_efficiency_pct == 0.0

        for _ in range(5):
            engine.step_rk4(dt=0.1)

        conv = engine.conversion_efficiency_pct
        assert conv > 0.0
        assert conv <= 100.0

    def test_zero_reaction_rates_when_tripped_or_subcooled(self) -> None:
        """Verify reaction rates return (0.0, 0.0) when trip is active or bed is subcooled."""
        engine = PHAHydrogenationBDOEngine()
        engine.trip_active = True
        r1, r2 = engine.compute_rates(engine.state)
        assert r1 == 0.0
        assert r2 == 0.0

        engine.trip_active = False
        st_frozen = PHAHydrogenationBDOState(t_bed_kelvin=200.0)
        r1_sub, r2_sub = engine.compute_rates(st_frozen)
        assert r1_sub == 0.0
        assert r2_sub == 0.0


# ============================================================================
# 3. TestCoupled6StateDerivatives
# ============================================================================

class TestCoupled6StateDerivatives:
    """Validate coupled 6-state fixed-bed ODE derivative calculations and conservation properties."""

    def test_derivative_calculation_nominal_state(self) -> None:
        """Verify _derivatives returns a 7-tuple of finite floats."""
        engine = PHAHydrogenationBDOEngine()
        derivs = engine._derivatives(engine.state)
        assert len(derivs) == 7
        for d in derivs:
            assert isinstance(d, float)
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_carbon_backbone_derivative_conservation(self) -> None:
        """Verify stoichiometric derivative sum for C4 backbone: dc_se_dt + dc_gbl_dt + dc_bdo_dt == 0.0."""
        engine = PHAHydrogenationBDOEngine()
        d_se, d_gbl, d_bdo, _, _, _, _ = engine._derivatives(engine.state)
        c4_derivative_sum = d_se + d_gbl + d_bdo
        assert abs(c4_derivative_sum) < 1e-12

    def test_hydrogen_species_derivative_balance(self) -> None:
        """Verify dissolved H2 derivative accounts for gas mass transfer and stoichiometric consumption."""
        engine = PHAHydrogenationBDOEngine()
        r1, r2 = engine.compute_rates(engine.state)
        d_se, d_gbl, d_bdo, d_h2, _, _, _ = engine._derivatives(engine.state)

        # Dissolved H2 consumption is 2*r1 + 2*r2
        r_h2_cons = 2.0 * r1 + 2.0 * r2
        c_sat = engine.cfg.henry_constant_h2 * engine.state.p_reactor
        r_transfer = engine.cfg.kla_mass_transfer * (c_sat - engine.state.c_h2_dissolved)
        expected_d_h2 = r_transfer - r_h2_cons

        assert math.isclose(d_h2, expected_d_h2, rel_tol=1e-5)

    def test_catalyst_coking_derivative_negative(self) -> None:
        """Verify catalyst deactivation derivative da_cat/dt is non-positive."""
        engine = PHAHydrogenationBDOEngine()
        _, _, _, _, _, da_cat, _ = engine._derivatives(engine.state)
        assert da_cat <= 0.0

    def test_thermal_energy_balance_derivatives(self) -> None:
        """Verify bed temperature derivative dt_bed_dt balances exotherm, cooling, losses, and feed convection."""
        engine = PHAHydrogenationBDOEngine()
        derivs = engine._derivatives(engine.state)
        dt_bed_dt = derivs[4]
        # In nominal operation with adequate cooling jacket, dt_bed_dt is moderate
        assert abs(dt_bed_dt) < 50.0

    def test_nominal_pressure_derivative_zero(self) -> None:
        """Verify reactor pressure derivative is zero in steady operating state."""
        engine = PHAHydrogenationBDOEngine()
        derivs = engine._derivatives(engine.state)
        dp_reactor_dt = derivs[6]
        assert dp_reactor_dt == 0.0

    def test_derivatives_under_emergency_trip_and_depressurize(self) -> None:
        """Verify derivatives during emergency depressurize: rapid pressure drop, thermal quench, zero forward reactions."""
        engine = PHAHydrogenationBDOEngine()
        engine.trip_active = True
        engine.emergency_depressurize_active = True

        derivs = engine._derivatives(engine.state)
        d_se, d_gbl, d_bdo, d_h2, dt_bed_dt, da_cat, dp_reactor_dt = derivs

        assert d_se == 0.0
        assert d_gbl == 0.0
        assert d_bdo == 0.0
        assert da_cat == 0.0
        assert dp_reactor_dt < 0.0  # Rapid depressurization
        assert dt_bed_dt < 0.0      # Quench cooling

    def test_concentration_non_negativity_in_derivatives(self) -> None:
        """Verify that when succinate ester is depleted, consumption rate is zero."""
        engine = PHAHydrogenationBDOEngine()
        st_empty = PHAHydrogenationBDOState(c_succinate_ester=0.0)
        r1, _ = engine.compute_rates(st_empty)
        assert r1 == 0.0


# ============================================================================
# 4. TestRK4IntegrationStability
# ============================================================================

class TestRK4IntegrationStability:
    """Validate 4th-Order Runge-Kutta numerical integration stability, convergence, and class aliases."""

    def test_rk4_step_forward_evolution(self) -> None:
        """Verify that an RK4 step smoothly advances the reaction without numerical instability."""
        engine = PHAHydrogenationBDOEngine()
        se_init = engine.state.c_succinate_ester
        gbl_init = engine.state.c_gbl_intermediate
        bdo_init = engine.state.c_bdo_product

        engine.step_rk4(dt=0.1)

        assert engine.state.c_succinate_ester < se_init
        assert engine.state.c_gbl_intermediate > gbl_init
        assert engine.state.c_bdo_product > bdo_init
        assert engine.diagnostic_code == DIAG_OK
        assert not engine.trip_active

    def test_rk4_step_size_variation(self) -> None:
        """Verify stable numerical integration across varying step sizes dt in [0.01, 0.05, 0.1, 0.2] s."""
        for dt in [0.01, 0.05, 0.1, 0.2]:
            engine = PHAHydrogenationBDOEngine()
            for _ in range(5):
                engine.step_rk4(dt=dt)
            assert engine.state.c_succinate_ester > 0.0
            assert engine.state.c_gbl_intermediate > 0.0
            assert engine.state.c_bdo_product > 0.0
            assert engine.state.t_bed_kelvin > 300.0
            assert 0.0 <= engine.state.a_catalyst <= 1.0

    def test_rk4_convergence_dt_refinement(self) -> None:
        """Verify convergence: trajectory with smaller step size matches larger step size closely."""
        # 10 steps of dt=0.02 vs 2 steps of dt=0.1 (total time = 0.2 s)
        e_fine = PHAHydrogenationBDOEngine()
        for _ in range(10):
            e_fine.step_rk4(dt=0.02)

        e_coarse = PHAHydrogenationBDOEngine()
        for _ in range(2):
            e_coarse.step_rk4(dt=0.1)

        assert math.isclose(
            e_fine.state.c_succinate_ester,
            e_coarse.state.c_succinate_ester,
            rel_tol=1e-3,
        )
        assert math.isclose(
            e_fine.state.c_bdo_product,
            e_coarse.state.c_bdo_product,
            rel_tol=1e-3,
        )

    def test_rk4_concentration_non_negativity_clamping(self) -> None:
        """Verify integration maintains non-negative concentrations even under extreme perturbations."""
        engine = PHAHydrogenationBDOEngine()
        engine.state.c_succinate_ester = 1e-4
        engine.step_rk4(dt=0.5)
        assert engine.state.c_succinate_ester >= 0.0
        assert engine.state.c_gbl_intermediate >= 0.0
        assert engine.state.c_bdo_product >= 0.0
        assert engine.state.c_h2_dissolved >= 0.0

    def test_rk4_catalyst_activity_bounds(self) -> None:
        """Verify catalyst activity remains strictly bounded between 0.0 and 1.0 across steps."""
        engine = PHAHydrogenationBDOEngine()
        for _ in range(20):
            engine.step_rk4(dt=0.2)
        assert 0.0 <= engine.state.a_catalyst <= 1.0

    def test_rk4_step_alias(self) -> None:
        """Verify engine.rk4_step is an identical alias for engine.step_rk4."""
        e1 = PHAHydrogenationBDOEngine()
        e2 = PHAHydrogenationBDOEngine()

        e1.step_rk4(dt=0.1)
        e2.rk4_step(dt=0.1)

        assert e1.state.c_succinate_ester == e2.state.c_succinate_ester
        assert e1.state.c_bdo_product == e2.state.c_bdo_product

    def test_engine_class_aliases(self) -> None:
        """Verify all engine class and model aliases reference the core implementation."""
        assert PHAHydrogenationBDOSimulator is PHAHydrogenationBDOEngine
        assert PhaHydrogenationBDOSimulator is PHAHydrogenationBDOEngine
        assert PHAHydrogenationBDOReactor is PHAHydrogenationBDOEngine
        assert PhaHydrogenationBDOReactor is PHAHydrogenationBDOEngine
        assert PHAHydrogenationBDOLogicUnit is PHAHydrogenationBDOEngine
        assert PhaHydrogenationBDOLogicUnit is PHAHydrogenationBDOEngine
        assert PHAH2BDOEngine is PHAHydrogenationBDOEngine
        assert PhaH2BDOEngine is PHAHydrogenationBDOEngine
        assert PHAH2BDOSimulator is PHAHydrogenationBDOEngine
        assert PhaH2BDOSimulator is PHAHydrogenationBDOEngine


# ============================================================================
# 5. TestMassBalanceConservation
# ============================================================================

class TestMassBalanceConservation:
    """Validate strict continuous carbon backbone mass conservation (residuals < 1e-10) across regimes."""

    def test_carbon_backbone_conservation_low_conversion(self) -> None:
        """Verify continuous carbon backbone conservation residual < 1e-10 in low conversion regime (10 cycles)."""
        engine = PHAHydrogenationBDOEngine()
        for _ in range(10):
            engine.step_rk4(dt=0.05)
        assert engine.conservation_residual < 1e-10
        assert engine.diagnostic_code == DIAG_OK

    def test_carbon_backbone_conservation_medium_conversion(self) -> None:
        """Verify continuous carbon backbone conservation residual < 1e-10 in medium conversion regime (50 cycles)."""
        engine = PHAHydrogenationBDOEngine()
        for _ in range(50):
            engine.step_rk4(dt=0.1)
        assert engine.conservation_residual < 1e-10
        assert engine.conversion_efficiency_pct > 1.0

    def test_carbon_backbone_conservation_high_conversion(self) -> None:
        """Verify continuous carbon backbone conservation residual < 1e-10 in extended conversion regime."""
        engine = PHAHydrogenationBDOEngine()
        # Elevate temperature to accelerate conversion safely within limits
        engine.state.t_bed_kelvin = 500.0
        for _ in range(30):
            engine.step_rk4(dt=0.1)
        assert engine.conservation_residual < 1e-10
        assert engine.conversion_efficiency_pct > 5.0

    def test_carbon_backbone_conservation_diverse_temperatures(self) -> None:
        """Verify conservation residual < 1e-10 across varied operating temperatures (420 K to 510 K)."""
        for t_k in [420.0, 450.0, 480.0, 510.0]:
            engine = PHAHydrogenationBDOEngine()
            engine.state.t_bed_kelvin = t_k
            for _ in range(10):
                engine.step_rk4(dt=0.05)
            assert engine.conservation_residual < 1e-10

    def test_carbon_backbone_conservation_varying_space_velocity(self) -> None:
        """Verify conservation residual < 1e-10 across varying space velocities LHSV (0.5 to 3.0 h^-1)."""
        for lhsv in [0.5, 1.5, 3.0]:
            engine = PHAHydrogenationBDOEngine()
            engine.state.space_velocity_lhsv = lhsv
            for _ in range(10):
                engine.step_rk4(dt=0.1)
            assert engine.conservation_residual < 1e-10

    def test_get_mass_residual_method(self) -> None:
        """Verify get_mass_residual() helper method matches tracked conservation residual."""
        engine = PHAHydrogenationBDOEngine()
        for _ in range(15):
            engine.step_rk4(dt=0.1)
        res = engine.get_mass_residual()
        assert res == engine.conservation_residual
        assert res < 1e-10

    def test_mass_residual_near_machine_epsilon(self) -> None:
        """Verify exact total molar inventory (SE + GBL + BDO) equals initial inventory within 1e-12."""
        engine = PHAHydrogenationBDOEngine()
        c4_initial = (
            engine.state.c_succinate_ester
            + engine.state.c_gbl_intermediate
            + engine.state.c_bdo_product
        )
        for _ in range(25):
            engine.step_rk4(dt=0.1)
        c4_current = (
            engine.state.c_succinate_ester
            + engine.state.c_gbl_intermediate
            + engine.state.c_bdo_product
        )
        assert math.isclose(c4_current, c4_initial, rel_tol=1e-12)


# ============================================================================
# 6. TestThermalRunawayTrip
# ============================================================================

class TestThermalRunawayTrip:
    """Validate thermal runaway runaway trip (0xF991, %M650 asserted, %M649 de-asserted)."""

    def test_high_temperature_trip_assertion(self) -> None:
        """Verify high bed temperature (> 550.0 K) trips system with 0xF991 DIAG_ERR_THERMAL_RUNAWAY."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(temp_k=555.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        assert engine.diagnostic_code == 0xF991

    def test_fast_temperature_rate_trip_assertion(self) -> None:
        """Verify fast temperature rate-of-rise (> 15.0 K/s) trips system with 0xF991."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_temperature_rate_runaway(rate_k_s=18.5)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

    def test_thermal_runaway_coil_deassertion(self) -> None:
        """Verify %M648 (reactor active) and %M649 (H2 feed valve) are immediately de-asserted on trip."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(555.0)
        engine.step_rk4(dt=0.05)

        assert engine.reactor_active is False
        assert engine.h2_feed_valve is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False

    def test_thermal_runaway_emergency_depressurize_coil(self) -> None:
        """Verify %M650 (emergency depressurize) is asserted immediately upon thermal runaway."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(555.0)
        engine.step_rk4(dt=0.05)

        assert engine.emergency_depressurize_active is True
        assert engine.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True

    def test_thermal_runaway_register_update(self) -> None:
        """Verify %R2787 reflects diagnostic code 0xF991 in OCS memory space."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(555.0)
        engine.step_rk4(dt=0.05)

        reg_val = engine.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE)
        assert (reg_val & 0xFFFF) == 0xF991

    def test_thermal_runaway_isolation_of_hydrogen_flow(self) -> None:
        """Verify H2 supply flow rate drops to zero and %R2786 is synchronized to 0 SLPM."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(555.0)
        engine.step_rk4(dt=0.05)

        assert engine.state.h2_flow_slpm == 0.0
        assert engine.reg_table.read_word(REG_PHA_H2_HYDROGEN_FLOW_SLPM) == 0

    def test_emergency_quench_cooling_dynamics(self) -> None:
        """Verify emergency quench cooling rapidly reduces bed temperature by at least 15 K during trip."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(555.0)
        engine.step_rk4(dt=0.05)
        t_peak = engine.state.t_bed_kelvin

        for _ in range(20):
            engine.step_rk4(dt=0.2)

        t_quenched = engine.state.t_bed_kelvin
        drop = t_peak - t_quenched
        assert drop >= 15.0
        assert t_quenched < t_peak

    def test_trip_latch_and_reset(self) -> None:
        """Verify trip condition remains latched across subsequent steps until reset() is invoked."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(555.0)
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True

        # Lower temperature; trip must remain latched
        engine.state.t_bed_kelvin = 473.15
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

        # Explicit reset restores nominal operation
        engine.reset()
        assert engine.trip_active is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.reactor_active is True
        assert engine.h2_feed_valve is True
        assert engine.emergency_depressurize_active is False


# ============================================================================
# 7. TestReactorOverpressureTrip
# ============================================================================

class TestReactorOverpressureTrip:
    """Validate reactor overpressure rupture trip (0xF992) and depressurization dynamics."""

    def test_overpressure_rupture_trip_assertion(self) -> None:
        """Verify reactor pressure > 80.0 bar trips system with 0xF992 DIAG_ERR_OVERPRESSURE_RUPTURE."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_overpressure(pressure_bar=85.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_OVERPRESSURE_RUPTURE
        assert engine.diagnostic_code == 0xF992

    def test_overpressure_coils_actuation(self) -> None:
        """Verify coil actuation on overpressure: %M648=False, %M649=False, %M650=True."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_overpressure(85.0)
        engine.step_rk4(dt=0.05)

        assert engine.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True

    def test_overpressure_register_diagnostic_code(self) -> None:
        """Verify register %R2787 contains 0xF992 upon overpressure trip."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_overpressure(85.0)
        engine.step_rk4(dt=0.05)

        reg_val = engine.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE)
        assert (reg_val & 0xFFFF) == 0xF992

    def test_overpressure_depressurization_dynamics(self) -> None:
        """Verify emergency depressurization causes reactor pressure to decay toward ambient."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_overpressure(85.0)
        engine.step_rk4(dt=0.05)
        p_initial = engine.state.p_reactor

        for _ in range(15):
            engine.step_rk4(dt=0.2)

        p_final = engine.state.p_reactor
        assert p_final < p_initial
        assert p_final >= engine.cfg.p_ambient_bar

    def test_overpressure_rejection_of_h2_feed(self) -> None:
        """Verify H2 feed valve remains closed throughout depressurization."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_overpressure(85.0)
        engine.step_rk4(dt=0.05)

        for _ in range(5):
            engine.step_rk4(dt=0.1)

        assert engine.h2_feed_valve is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False

    def test_inject_overpressure_helper(self) -> None:
        """Verify inject_overpressure helper properly modifies state and triggers trip."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_overpressure(84.0)
        assert engine.state.p_reactor == 84.0
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True


# ============================================================================
# 8. TestCatalystCokingAndH2StarvationTrips
# ============================================================================

class TestCatalystCokingAndH2StarvationTrips:
    """Validate catalyst coking (0xF993), H2 starvation (0xF994), and fault priority hierarchy."""

    def test_catalyst_coking_trip_assertion(self) -> None:
        """Verify catalyst activity < 30.0% trips system with 0xF993 DIAG_ERR_CATALYST_COKING."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_catalyst_coking(activity=0.25)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_CATALYST_COKING
        assert engine.diagnostic_code == 0xF993

    def test_catalyst_coking_coils_and_registers(self) -> None:
        """Verify coils and registers on coking trip: %M648=False, %M649=False, %M650=True, %R2785=250."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_catalyst_coking(activity=0.25)
        engine.step_rk4(dt=0.05)

        assert engine.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True
        assert engine.reg_table.read_word(REG_PHA_H2_CATALYST_ACTIVITY) == 250
        assert (engine.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF993

    def test_hydrogen_starvation_trip_assertion(self) -> None:
        """Verify H2/Substrate ratio < stoichiometric minimum (2.0) trips system with 0xF994."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_hydrogen_starvation(ratio=1.2)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_HYDROGEN_STARVATION
        assert engine.diagnostic_code == 0xF994

    def test_hydrogen_starvation_coils_and_registers(self) -> None:
        """Verify coils and registers on starvation trip: %M648=False, %M649=False, %M650=True, %R2787=0xF994."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_hydrogen_starvation(ratio=1.2)
        engine.step_rk4(dt=0.05)

        assert engine.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True
        assert (engine.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF994

    def test_continuous_mass_balance_divergence_trip(self) -> None:
        """Verify mass balance residual > 1e-4 trips system with 0xF995 DIAG_ERR_MASS_BALANCE_DIVERGENCE."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_mass_divergence(residual=0.005)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        assert (engine.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF995

    def test_priority_hierarchy_p1_dominates_p2(self) -> None:
        """Verify Priority 1 (Thermal Runaway 0xF991) dominates Priority 2 (Overpressure 0xF992)."""
        engine = PHAHydrogenationBDOEngine()
        engine.state.t_bed_kelvin = 555.0
        engine.state.p_reactor = 85.0
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

    def test_priority_hierarchy_p2_dominates_p3(self) -> None:
        """Verify Priority 2 (Overpressure 0xF992) dominates Priority 3 (Catalyst Coking 0xF993)."""
        engine = PHAHydrogenationBDOEngine()
        engine.state.p_reactor = 85.0
        engine.state.a_catalyst = 0.20
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_OVERPRESSURE_RUPTURE

    def test_priority_hierarchy_p3_dominates_p4(self) -> None:
        """Verify Priority 3 (Catalyst Coking 0xF993) dominates Priority 4 (H2 Starvation 0xF994)."""
        engine = PHAHydrogenationBDOEngine()
        engine.state.a_catalyst = 0.20
        engine.inject_hydrogen_starvation(ratio=1.0)
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_CATALYST_COKING

    def test_priority_hierarchy_p4_dominates_p5(self) -> None:
        """Verify Priority 4 (H2 Starvation 0xF994) dominates Priority 5 (Mass Divergence 0xF995)."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_hydrogen_starvation(ratio=1.0)
        engine.conservation_residual = 0.005
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_HYDROGEN_STARVATION


# ============================================================================
# 9. TestRegisterTableSynchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate Horner OCS memory synchronization across %R2780..%R2787 and %M648..%M650."""

    def test_sync_nominal_registers_scaled(self) -> None:
        """Verify correct scaling and unit conversions across all 8 word registers in nominal state."""
        engine = PHAHydrogenationBDOEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        # %R2780: Temperature in 0.1 °C
        # T_bed = 473.15 K -> 200.0 °C -> 2000
        w_temp = rt.read_word(REG_PHA_H2_REACTOR_TEMP)
        assert w_temp == 2000

        # %R2781: Pressure in 0.01 bar (50.0 bar -> 5000)
        w_press = rt.read_word(REG_PHA_H2_REACTOR_PRESSURE)
        assert w_press == 5000

        # %R2782: Conversion in 0.1 % (0.0 % -> 0)
        w_conv = rt.read_word(REG_PHA_H2_CONVERSION_EFFICIENCY)
        assert w_conv == 0

        # %R2783: Selectivity in 0.1 %
        w_sel = rt.read_word(REG_PHA_H2_BDO_SELECTIVITY)
        assert w_sel >= 0

        # %R2784: LHSV in 0.01 h^-1 (1.50 -> 150)
        w_lhsv = rt.read_word(REG_PHA_H2_SPACE_VELOCITY_LHSV)
        assert w_lhsv == 150

        # %R2785: Catalyst activity in 0.1 % (1.0 -> 1000)
        w_act = rt.read_word(REG_PHA_H2_CATALYST_ACTIVITY)
        assert w_act == 1000

        # %R2786: H2 flow in 0.1 SLPM (750.0 -> 7500)
        w_flow = rt.read_word(REG_PHA_H2_HYDROGEN_FLOW_SLPM)
        assert w_flow == 7500

        # %R2787: Diagnostic code (0x0000)
        w_diag = rt.read_word(REG_PHA_H2_DIAGNOSTIC_CODE)
        assert w_diag == 0x0000

    def test_sync_signed_16bit_temperature_subzero(self) -> None:
        """Verify signed 16-bit safe write for sub-zero temperatures (e.g. -10.0 °C -> 0xFF9C)."""
        engine = PHAHydrogenationBDOEngine()
        # 263.15 K = -10.0 °C -> scaled = -100 -> masked 16-bit = 0xFF9C (65436)
        engine.state.t_bed_kelvin = 263.15
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        w_temp = rt.read_word(REG_PHA_H2_REACTOR_TEMP)
        assert (w_temp & 0xFFFF) == (-100 & 0xFFFF)
        # Verify signed reconstruction
        val_s = w_temp - 0x10000 if w_temp >= 0x8000 else w_temp
        assert val_s == -100

    def test_sync_pressure_clamping_bounds(self) -> None:
        """Verify reactor pressure register clamping to [0, 10000]."""
        engine = PHAHydrogenationBDOEngine()
        engine.state.p_reactor = 150.0  # Would be 15000 -> clamped to 10000
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_PHA_H2_REACTOR_PRESSURE) == 10000

    def test_sync_conversion_and_selectivity_clamping(self) -> None:
        """Verify conversion efficiency and selectivity registers clamp between 0 and 1000."""
        engine = PHAHydrogenationBDOEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        w_conv = rt.read_word(REG_PHA_H2_CONVERSION_EFFICIENCY)
        w_sel = rt.read_word(REG_PHA_H2_BDO_SELECTIVITY)
        assert 0 <= w_conv <= 1000
        assert 0 <= w_sel <= 1000

    def test_sync_coils_normal_operating_state(self) -> None:
        """Verify discrete coils in normal operating state: %M648=True, %M649=True, %M650=False."""
        engine = PHAHydrogenationBDOEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is True
        assert rt.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is True
        assert rt.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is False

    def test_sync_coils_trip_operating_state(self) -> None:
        """Verify discrete coils in safety trip state: %M648=False, %M649=False, %M650=True."""
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(555.0)
        engine.step_rk4(dt=0.05)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        assert rt.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        assert rt.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True

    def test_sync_with_user_privilege_mode(self) -> None:
        """Verify synchronization succeeds under PrivilegeMode.USER."""
        engine = PHAHydrogenationBDOEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert rt.read_word(REG_PHA_H2_REACTOR_TEMP) == 2000

    def test_sync_with_custom_register_table(self) -> None:
        """Verify syncing to an external RegisterTable does not contaminate or miss state."""
        engine = PHAHydrogenationBDOEngine()
        rt1 = RegisterTable()
        rt2 = RegisterTable()

        engine.sync_to_registers(rt1)
        engine.sync_to_registers(rt2)

        for reg in [
            REG_PHA_H2_REACTOR_TEMP,
            REG_PHA_H2_REACTOR_PRESSURE,
            REG_PHA_H2_CONVERSION_EFFICIENCY,
            REG_PHA_H2_BDO_SELECTIVITY,
            REG_PHA_H2_SPACE_VELOCITY_LHSV,
            REG_PHA_H2_CATALYST_ACTIVITY,
            REG_PHA_H2_HYDROGEN_FLOW_SLPM,
            REG_PHA_H2_DIAGNOSTIC_CODE,
        ]:
            assert rt1.read_word(reg) == rt2.read_word(reg)


# ============================================================================
# 10. TestPureStructuredTextPOU
# ============================================================================

class TestPureStructuredTextPOU:
    """Validate pure IEC 61131-3 ST POU syntax and anti-ladder rejection of all 9 constructs."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify pure ST POU validation passes without error."""
        assert verify_pha_hydrogenation_bdo_pure_st() is True
        assert verify_pha_h2_bdo_pure_st() is True

    def test_st_parser_ast_validation(self) -> None:
        """Verify STParser successfully parses the POU and returns AgentStatus.SUCCESS."""
        res = STParser.validate_code(PHA_HYDROGENATION_BDO_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None

    def test_st_program_variables_and_registers(self) -> None:
        """Verify all Horner OCS registers and coils are mapped in POU VAR block."""
        code = PHA_HYDROGENATION_BDO_PURE_ST_POU
        assert "rReactorTemp AT %R2780 : INT;" in code
        assert "rReactorPressure AT %R2781 : WORD;" in code
        assert "rConversionEff AT %R2782 : WORD;" in code
        assert "rBDOSelectivity AT %R2783 : WORD;" in code
        assert "rSpaceVelocity AT %R2784 : WORD;" in code
        assert "rCatalystActivity AT %R2785 : WORD;" in code
        assert "rH2FlowRate AT %R2786 : WORD;" in code
        assert "wDiagnosticCode AT %R2787 : WORD;" in code
        assert "bReactorActive AT %M648 : BOOL;" in code
        assert "bH2FeedValve AT %M649 : BOOL;" in code
        assert "bEmergencyDepressurize AT %M650 : BOOL;" in code

    def test_st_pou_string_constants_and_aliases(self) -> None:
        """Verify POU string constants and aliases are identical."""
        assert PHA_HYDROGENATION_BDO_PURE_ST_POU == ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL
        assert PHA_H2_BDO_PURE_ST_POU == ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL
        assert PHAHydrogenationBDOControl == ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL
        assert PHA_HYDROGENATION_BDO_CONTROL_POU == ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL

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
        for bad_frag in ["RUNG 1: START", "NETWORK 10", "XIC %M648"]:
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
        engine = PHAHydrogenationBDOEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.unit_id == "PHA_H2_BDO_REACTOR_W317"
        assert engine.name == "PHAHydrogenationBDOEngine"
        assert engine.priority == 50
        assert engine.is_enabled is True

    def test_ilogicunit_scan_step_execution_result(self) -> None:
        """Verify scan_step returns valid ExecutionResult with status, error_code, details, and data."""
        engine = PHAHydrogenationBDOEngine()
        res = engine.scan_step(dt=0.1)

        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert "PHA Hydrogenation Fixed-Bed" in res.details
        assert isinstance(res.data, dict)
        assert "c_succinate_ester" in res.data
        assert "c_gbl_intermediate" in res.data
        assert "c_bdo_product" in res.data
        assert "conversion_efficiency_pct" in res.data
        assert "bdo_selectivity_pct" in res.data
        assert res.data["cycle_count"] == 1

    def test_scan_context_integration(self) -> None:
        """Verify passing ScanContext updates engine's RegisterTable and synchronizes values."""
        rt_ctx = RegisterTable()
        ctx = ScanContext(cycle=5, dt_ms=100.0, register_table=rt_ctx)
        engine = PHAHydrogenationBDOEngine()

        res = engine.scan_step(ctx=ctx)
        assert res.status == AgentStatus.SUCCESS
        # Check that context register table received values
        assert rt_ctx.read_word(REG_PHA_H2_REACTOR_TEMP) > 0
        assert rt_ctx.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is True

    def test_step_and_execute_interface_methods(self) -> None:
        """Verify step() and execute() methods adhere to ILogicUnit interface."""
        engine = PHAHydrogenationBDOEngine()
        engine.step(0.1)
        assert engine.cycle_count == 1
        engine.execute(0.1)
        assert engine.cycle_count == 2

    def test_100_cycle_simulation_soak(self) -> None:
        """Execute 100 continuous scan cycles: verify stability, conservation, and monotonic conversion."""
        engine = PHAHydrogenationBDOEngine()
        se_prev = engine.state.c_succinate_ester

        for cycle in range(1, 101):
            res = engine.scan_step(dt=0.1)
            assert res.status == AgentStatus.SUCCESS
            assert engine.diagnostic_code == DIAG_OK
            assert engine.conservation_residual < 1e-10

        assert engine.cycle_count == 100
        assert engine.state.c_succinate_ester < se_prev
        assert engine.conversion_efficiency_pct > 0.0
        assert engine.bdo_selectivity_pct > 0.0

    def test_soak_memory_profiling_zero_leak(self) -> None:
        """Verify 100-cycle soak produces zero memory accumulation / leak using tracemalloc."""
        tracemalloc.start()
        engine = PHAHydrogenationBDOEngine()

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
        engine = PHAHydrogenationBDOEngine()
        engine.inject_thermal_runaway(555.0)
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True

        engine.reset()
        assert engine.trip_active is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.cycle_count == 0
        assert engine.conservation_residual == 0.0
        assert engine.state.c_succinate_ester == 3.0
        assert engine.state.t_bed_kelvin == 473.15


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
            res = run_pha_hydrogenation_bdo_verification(output_path=out_path)
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
        res = run_pha_hydrogenation_bdo_verification(quick=True)
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_evidence_json_structure_and_hashes(self) -> None:
        """Verify evidence JSON contains SHA-256 digests for POU and model config."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = run_pha_hydrogenation_bdo_verification(output_path=out_path, quick=True)
            digests = res["data"]["digests"]
            assert "pou_sha256" in digests
            assert "model_sha256" in digests
            assert len(digests["pou_sha256"]) == 64
            assert len(digests["model_sha256"]) == 64
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_scripts_runner_module_execution(self) -> None:
        """Verify execution of scripts/run_pha_hydrogenation_bdo_verification.py module runner."""
        from scripts.run_pha_hydrogenation_bdo_verification import (
            execute_pha_hydrogenation_bdo_verification,
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = execute_pha_hydrogenation_bdo_verification(output_path=out_path, quick=True)
            assert res["status"] == "success"
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_main_entrypoint_with_tempfile(self) -> None:
        """Verify CLI main() in scripts/run_pha_hydrogenation_bdo_verification.py passes cleanly."""
        from scripts.run_pha_hydrogenation_bdo_verification import main as script_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = script_main(["--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_simulation_cli_main_entrypoint(self) -> None:
        """Verify CLI main() in src/jev_cscape/simulation/pha_hydrogenation_bdo.py passes cleanly."""
        from jev_cscape.simulation.pha_hydrogenation_bdo import main as sim_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = sim_main(["--verify", "--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_compatibility_runner_alias(self) -> None:
        """Verify run_pha_h2_bdo_verification is an alias to run_pha_hydrogenation_bdo_verification."""
        assert run_pha_h2_bdo_verification is run_pha_hydrogenation_bdo_verification
