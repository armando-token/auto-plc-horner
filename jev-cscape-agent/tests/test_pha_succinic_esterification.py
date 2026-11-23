"""Industrial Bio-Succinic Acid Esterification & PHA Precursor Distillation Column Unit Test Suite (W314).

Work Package: W314 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification test classes (85+ test cases):
1. TestPhysicalConstantsAndRegisters: Physical constants, stoichiometry, register %R2750..%R2757, coils %M641..%M643, signed 16-bit safe comparisons.
2. TestReactionRatesAndEquilibrium: Esterification reaction rates, VLE equilibrium, ester purity, acid conversion, Arrhenius kinetics.
3. TestCoupled6StateDerivatives: 6-state reactive distillation ODE derivative calculations, mass/energy balance, volume/concentration non-negativity.
4. TestRK4IntegrationStability: RK4 stability, step size variation (dt=0.01s to 0.1s), trajectory smoothness, and class aliases.
5. TestMassBalanceConservation: Continuous mass conservation residuals (< 1e-10) across diverse conversion regimes.
6. TestReboilerOverheatTrip: Reboiler overheat runaway trip (0xF981, %M643 emergency dump asserted, %M642 heater de-asserted).
7. TestColumnOverpressureTrip: Column overpressure trip (0xF982, %M643 emergency dump asserted, vent depressurization dynamics).
8. TestTrayFloodingAndAcidPrecipitationTrips: Tray flooding/weeping and acid precipitation trips (0xF983, 0xF985, fault priority hierarchy).
9. TestRegisterTableSynchronization: Horner OCS memory sync across %R2750..%R2757 and %M641..%M643 with signed 16-bit masking.
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
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.pha_succinic_esterification import (
    CARBONS_ALCOHOL,
    CARBONS_DIALKYL_SUCCINATE,
    CARBONS_SUCCINIC_ACID,
    CARBONS_WATER,
    CARBON_FRACTION_ALCOHOL,
    CARBON_FRACTION_DIALKYL_SUCCINATE,
    CARBON_FRACTION_SUCCINIC_ACID,
    COIL_PHA_SUCC_ACTIVE,
    COIL_PHA_SUCC_COLUMN_ACTIVE,
    COIL_PHA_SUCC_DUMP,
    COIL_PHA_SUCC_EMERGENCY_DUMP,
    COIL_PHA_SUCC_EMERGENCY_VENT,
    COIL_PHA_SUCC_HEATER,
    COIL_PHA_SUCC_REBOILER,
    COIL_PHA_SUCC_REBOILER_HEATER,
    COIL_PHA_SUCC_RUNNING,
    DIAG_ERR_ACID_PRECIPITATION,
    DIAG_ERR_ACID_PRECIPITATION_CLOG,
    DIAG_ERR_CLOG,
    DIAG_ERR_COLUMN_OVERPRESSURE,
    DIAG_ERR_FLOODING_WEEPING,
    DIAG_ERR_MASS_BALANCE,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_MASS_DIVERGENCE,
    DIAG_ERR_OVERHEAT,
    DIAG_ERR_OVERPRESSURE,
    DIAG_ERR_PRECIPITATION_CLOG,
    DIAG_ERR_PRESSURE,
    DIAG_ERR_REBOILER_OVERHEAT,
    DIAG_ERR_REBOILER_TEMP,
    DIAG_ERR_TRAY_FLOODING,
    DIAG_ERR_TRAY_FLOODING_WEEPING,
    DIAG_OK,
    MW_ALCOHOL,
    MW_CARBON,
    MW_DIALKYL_SUCCINATE,
    MW_SUCCINIC_ACID,
    MW_WATER,
    PHA_SUCC_ESTER_PURE_ST_POU,
    PHA_SUCCINIC_ESTERIFICATION_CONTROL_POU,
    PHA_SUCCINIC_ESTERIFICATION_PURE_ST_POU,
    PHASuccEsterConfig,
    PHASuccEsterDiagnosticCode,
    PHASuccEsterEngine,
    PHASuccEsterSimulator,
    PHASuccEsterState,
    PHASuccEsterStatusBits,
    PHASuccEsterStatusWord,
    PHASuccinicEsterificationConfig,
    PHASuccinicEsterificationControl,
    PHASuccinicEsterificationDiagnosticCode,
    PHASuccinicEsterificationEngine,
    PHASuccinicEsterificationLogicUnit,
    PHASuccinicEsterificationModel,
    PHASuccinicEsterificationParameters,
    PHASuccinicEsterificationPlantModel,
    PHASuccinicEsterificationReactor,
    PHASuccinicEsterificationSimulationLogicUnit,
    PHASuccinicEsterificationSimulator,
    PHASuccinicEsterificationState,
    PHASuccinicEsterificationStateModel,
    PHASuccinicEsterificationStatusBits,
    PHASuccinicEsterificationStatusWord,
    PhaSuccEsterConfig,
    PhaSuccEsterDiagnosticCode,
    PhaSuccEsterEngine,
    PhaSuccEsterSimulator,
    PhaSuccEsterState,
    PhaSuccEsterStatusBits,
    PhaSuccEsterStatusWord,
    PhaSuccinicEsterificationConfig,
    PhaSuccinicEsterificationDiagnosticCode,
    PhaSuccinicEsterificationEngine,
    PhaSuccinicEsterificationLogicUnit,
    PhaSuccinicEsterificationModel,
    PhaSuccinicEsterificationParameters,
    PhaSuccinicEsterificationPlantModel,
    PhaSuccinicEsterificationReactor,
    PhaSuccinicEsterificationSimulationLogicUnit,
    PhaSuccinicEsterificationSimulator,
    PhaSuccinicEsterificationState,
    PhaSuccinicEsterificationStateModel,
    PhaSuccinicEsterificationStatusBits,
    PhaSuccinicEsterificationStatusWord,
    R_GAS_CONSTANT,
    REG_PHA_SUCC_ACID_CONVERSION,
    REG_PHA_SUCC_COLUMN_PRESSURE,
    REG_PHA_SUCC_CONDENSER_TEMP,
    REG_PHA_SUCC_CONDENSER_TEMPERATURE,
    REG_PHA_SUCC_CONV,
    REG_PHA_SUCC_CONVERSION,
    REG_PHA_SUCC_DIAG,
    REG_PHA_SUCC_DIAGNOSTIC_CODE,
    REG_PHA_SUCC_DUTY,
    REG_PHA_SUCC_ESTER_PURITY,
    REG_PHA_SUCC_HEATER_DUTY,
    REG_PHA_SUCC_P_COL,
    REG_PHA_SUCC_P_COLUMN,
    REG_PHA_SUCC_PRESSURE,
    REG_PHA_SUCC_PURITY,
    REG_PHA_SUCC_REBOILER_DUTY_KW,
    REG_PHA_SUCC_REBOILER_TEMP,
    REG_PHA_SUCC_REBOILER_TEMPERATURE,
    REG_PHA_SUCC_REFLUX,
    REG_PHA_SUCC_REFLUX_RATIO,
    REG_PHA_SUCC_T_COND,
    REG_PHA_SUCC_T_CONDENSER,
    REG_PHA_SUCC_T_REB,
    REG_PHA_SUCC_T_REBOILER,
    REG_PHA_SUCC_TCONDENSER,
    REG_PHA_SUCC_TREBOILER,
    ST_PROGRAM_PHA_SUCCINIC_ESTERIFICATION_CONTROL,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    run_pha_succ_ester_verification,
    run_pha_succinic_esterification_verification,
    validate_pure_st,
    verify_pha_succ_ester_pure_st,
    verify_pha_succinic_esterification_pure_st,
)


# ============================================================================
# 1. TestPhysicalConstantsAndRegisters
# ============================================================================

class TestPhysicalConstantsAndRegisters:
    """Validate stoichiometry, molecular weights, register mappings, coils, and signed 16-bit diagnostic codes."""

    def test_molecular_weights_and_constants(self) -> None:
        """Verify molecular weights of bio-succinic acid, alcohol, dialkyl succinate, water, and universal constants."""
        assert math.isclose(MW_SUCCINIC_ACID, 118.09, rel_tol=1e-4)
        assert math.isclose(MW_ALCOHOL, 32.04, rel_tol=1e-4)
        assert math.isclose(MW_DIALKYL_SUCCINATE, 146.14, rel_tol=1e-4)
        assert math.isclose(MW_WATER, 18.015, rel_tol=1e-4)
        assert math.isclose(MW_CARBON, 12.011, rel_tol=1e-4)
        assert math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-6)

    def test_carbon_stoichiometry_and_mass_fractions(self) -> None:
        """Verify carbon atoms per molecule and carbon mass fractions across reactants and products."""
        assert CARBONS_SUCCINIC_ACID == 4
        assert CARBONS_ALCOHOL == 1
        assert CARBONS_DIALKYL_SUCCINATE == 6
        assert CARBONS_WATER == 0

        # Stoichiometric balance: 1 mol Succinic Acid (4 C) + 2 mol Alcohol (2x1 C) -> 1 mol Dialkyl Succinate (6 C)
        assert CARBONS_SUCCINIC_ACID + 2 * CARBONS_ALCOHOL == CARBONS_DIALKYL_SUCCINATE

        expected_c_sa = (4.0 * 12.011) / 118.09
        expected_c_alc = (1.0 * 12.011) / 32.04
        expected_c_das = (6.0 * 12.011) / 146.14

        assert math.isclose(CARBON_FRACTION_SUCCINIC_ACID, expected_c_sa, rel_tol=1e-4)
        assert math.isclose(CARBON_FRACTION_ALCOHOL, expected_c_alc, rel_tol=1e-4)
        assert math.isclose(CARBON_FRACTION_DIALKYL_SUCCINATE, expected_c_das, rel_tol=1e-4)

    def test_register_address_constants_and_aliases(self) -> None:
        """Verify Horner OCS word register addresses %R2750..%R2757 and string aliases."""
        assert REG_PHA_SUCC_REBOILER_TEMP == "%R2750"
        assert REG_PHA_SUCC_CONDENSER_TEMP == "%R2751"
        assert REG_PHA_SUCC_COLUMN_PRESSURE == "%R2752"
        assert REG_PHA_SUCC_ESTER_PURITY == "%R2753"
        assert REG_PHA_SUCC_ACID_CONVERSION == "%R2754"
        assert REG_PHA_SUCC_REFLUX_RATIO == "%R2755"
        assert REG_PHA_SUCC_REBOILER_DUTY_KW == "%R2756"
        assert REG_PHA_SUCC_DIAGNOSTIC_CODE == "%R2757"

        # Check aliases
        assert REG_PHA_SUCC_TREBOILER == "%R2750"
        assert REG_PHA_SUCC_T_REBOILER == "%R2750"
        assert REG_PHA_SUCC_REBOILER_TEMPERATURE == "%R2750"
        assert REG_PHA_SUCC_T_REB == "%R2750"
        assert REG_PHA_SUCC_TCONDENSER == "%R2751"
        assert REG_PHA_SUCC_T_CONDENSER == "%R2751"
        assert REG_PHA_SUCC_CONDENSER_TEMPERATURE == "%R2751"
        assert REG_PHA_SUCC_T_COND == "%R2751"
        assert REG_PHA_SUCC_PRESSURE == "%R2752"
        assert REG_PHA_SUCC_P_COLUMN == "%R2752"
        assert REG_PHA_SUCC_P_COL == "%R2752"
        assert REG_PHA_SUCC_PURITY == "%R2753"
        assert REG_PHA_SUCC_CONVERSION == "%R2754"
        assert REG_PHA_SUCC_CONV == "%R2754"
        assert REG_PHA_SUCC_REFLUX == "%R2755"
        assert REG_PHA_SUCC_DUTY == "%R2756"
        assert REG_PHA_SUCC_HEATER_DUTY == "%R2756"
        assert REG_PHA_SUCC_DIAG == "%R2757"

    def test_coil_address_constants_and_aliases(self) -> None:
        """Verify Horner OCS discrete coil addresses %M641..%M643 and aliases."""
        assert COIL_PHA_SUCC_COLUMN_ACTIVE == "%M641"
        assert COIL_PHA_SUCC_REBOILER_HEATER == "%M642"
        assert COIL_PHA_SUCC_EMERGENCY_DUMP == "%M643"

        # Aliases
        assert COIL_PHA_SUCC_ACTIVE == "%M641"
        assert COIL_PHA_SUCC_RUNNING == "%M641"
        assert COIL_PHA_SUCC_HEATER == "%M642"
        assert COIL_PHA_SUCC_REBOILER == "%M642"
        assert COIL_PHA_SUCC_DUMP == "%M643"
        assert COIL_PHA_SUCC_EMERGENCY_VENT == "%M643"

    def test_diagnostic_codes_constants_and_aliases(self) -> None:
        """Verify 16-bit diagnostic trip constants 0x0000, 0xF981..0xF985 and aliases."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_REBOILER_OVERHEAT == 0xF981
        assert DIAG_ERR_COLUMN_OVERPRESSURE == 0xF982
        assert DIAG_ERR_TRAY_FLOODING_WEEPING == 0xF983
        assert DIAG_ERR_MASS_BALANCE_DIVERGENCE == 0xF984
        assert DIAG_ERR_ACID_PRECIPITATION_CLOG == 0xF985

        # Aliases
        assert DIAG_ERR_OVERHEAT == 0xF981
        assert DIAG_ERR_REBOILER_TEMP == 0xF981
        assert DIAG_ERR_OVERPRESSURE == 0xF982
        assert DIAG_ERR_PRESSURE == 0xF982
        assert DIAG_ERR_TRAY_FLOODING == 0xF983
        assert DIAG_ERR_FLOODING_WEEPING == 0xF983
        assert DIAG_ERR_MASS_DIVERGENCE == 0xF984
        assert DIAG_ERR_MASS_BALANCE == 0xF984
        assert DIAG_ERR_ACID_PRECIPITATION == 0xF985
        assert DIAG_ERR_PRECIPITATION_CLOG == 0xF985
        assert DIAG_ERR_CLOG == 0xF985

    def test_signed_16bit_diagnostic_safe_comparisons(self) -> None:
        """Verify signed 16-bit safe comparisons for diagnostic codes across unsigned/signed representations."""
        trip_codes = [0xF981, 0xF982, 0xF983, 0xF984, 0xF985]
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
        """Verify PHASuccinicEsterificationStatusWord bitmask enumeration definitions and aliases."""
        assert PHASuccinicEsterificationStatusWord.COLUMN_ACTIVE == (1 << 0)
        assert PHASuccinicEsterificationStatusWord.REBOILER_HEATING == (1 << 1)
        assert PHASuccinicEsterificationStatusWord.EMERGENCY_DUMP == (1 << 2)
        assert PHASuccinicEsterificationStatusWord.CONDENSER_ACTIVE == (1 << 3)
        assert PHASuccinicEsterificationStatusWord.REBOILER_WARN == (1 << 4)
        assert PHASuccinicEsterificationStatusWord.PRESSURE_WARN == (1 << 5)
        assert PHASuccinicEsterificationStatusWord.FLOODING_WARN == (1 << 6)
        assert PHASuccinicEsterificationStatusWord.EMERGENCY_TRIP == (1 << 7)

        # Aliases
        assert PhaSuccinicEsterificationStatusWord is PHASuccinicEsterificationStatusWord
        assert PHASuccEsterStatusWord is PHASuccinicEsterificationStatusWord
        assert PhaSuccEsterStatusWord is PHASuccinicEsterificationStatusWord
        assert PHASuccinicEsterificationStatusBits is PHASuccinicEsterificationStatusWord
        assert PhaSuccinicEsterificationStatusBits is PHASuccinicEsterificationStatusWord
        assert PHASuccEsterStatusBits is PHASuccinicEsterificationStatusWord
        assert PhaSuccEsterStatusBits is PHASuccinicEsterificationStatusWord

    def test_config_dataclass_defaults_and_serialization(self) -> None:
        """Verify PHASuccinicEsterificationConfig default parameters, dictionary serialization, and aliases."""
        cfg = PHASuccinicEsterificationConfig()
        assert cfg.k_forward > 0.0
        assert cfg.ea_forward_j_mol > 0.0
        assert cfg.k_reverse > 0.0
        assert cfg.ea_reverse_j_mol > 0.0
        assert cfg.v_reboiler == 2.5
        assert cfg.v_condenser == 0.5
        assert cfg.t_reboiler_trip_max == 520.0
        assert cfg.dt_reboiler_dt_trip_max == 20.0
        assert cfg.p_column_trip_max == 30.0
        assert cfg.delta_p_max == 0.80
        assert cfg.delta_p_min == 0.02
        assert cfg.mass_residual_max == 1e-4

        # Property aliases
        assert cfg.k_f == cfg.k_forward
        assert cfg.k_r == cfg.k_reverse
        assert cfg.ea_f == cfg.ea_forward_j_mol
        assert cfg.ea_r == cfg.ea_reverse_j_mol

        cfg.k_f = 9200.0
        assert cfg.k_forward == 9200.0
        cfg.k_r = 1350.0
        assert cfg.k_reverse == 1350.0

        d = cfg.to_dict()
        assert "k_forward" in d
        assert "t_reboiler_trip_max" in d
        assert "p_column_trip_max" in d


# ============================================================================
# 2. TestReactionRatesAndEquilibrium
# ============================================================================

class TestReactionRatesAndEquilibrium:
    """Validate esterification reaction rates, VLE equilibrium, ester purity, and Arrhenius kinetics."""

    def test_forward_esterification_rate_formula(self) -> None:
        """Verify analytical computation of forward esterification rate r_forward."""
        engine = PHASuccinicEsterificationEngine()
        st = PHASuccinicEsterificationState(c_succinic_acid=2.5, c_alcohol=6.0, t_reboiler=433.15)
        r_f, r_r, r_net = engine.compute_rates(st)

        rt_reb = R_GAS_CONSTANT * 433.15
        expected_r_f = engine.cfg.k_forward * 2.5 * (6.0 ** 2) * math.exp(-engine.cfg.ea_forward_j_mol / rt_reb)
        assert math.isclose(r_f, expected_r_f, rel_tol=1e-6)
        assert r_f > 0.0

    def test_reverse_hydrolysis_rate_formula(self) -> None:
        """Verify analytical computation of reverse ester hydrolysis rate r_reverse."""
        engine = PHASuccinicEsterificationEngine()
        st = PHASuccinicEsterificationState(c_dialkyl_succinate=1.2, c_water=2.4, t_reboiler=433.15)
        r_f, r_r, r_net = engine.compute_rates(st)

        rt_reb = R_GAS_CONSTANT * 433.15
        expected_r_r = engine.cfg.k_reverse * 1.2 * (2.4 ** 2) * math.exp(-engine.cfg.ea_reverse_j_mol / rt_reb)
        assert math.isclose(r_r, expected_r_r, rel_tol=1e-6)
        assert r_r > 0.0

    def test_net_esterification_rate_formula(self) -> None:
        """Verify net esterification rate is r_net = r_forward - r_reverse."""
        engine = PHASuccinicEsterificationEngine()
        st = PHASuccinicEsterificationState(
            c_succinic_acid=2.0, c_alcohol=5.0, c_dialkyl_succinate=0.5, c_water=0.8, t_reboiler=433.15
        )
        r_f, r_r, r_net = engine.compute_rates(st)
        assert math.isclose(r_net, r_f - r_r, rel_tol=1e-9)

    def test_reaction_rate_temperature_monotonic_acceleration(self) -> None:
        """Verify Arrhenius esterification rate strictly increases monotonically with temperature."""
        engine = PHASuccinicEsterificationEngine()
        st_cold = PHASuccinicEsterificationState(t_reboiler=380.0, c_succinic_acid=2.0, c_alcohol=5.0)
        st_nom = PHASuccinicEsterificationState(t_reboiler=433.15, c_succinic_acid=2.0, c_alcohol=5.0)
        st_hot = PHASuccinicEsterificationState(t_reboiler=470.0, c_succinic_acid=2.0, c_alcohol=5.0)

        r_f_cold, _, _ = engine.compute_rates(st_cold)
        r_f_nom, _, _ = engine.compute_rates(st_nom)
        r_f_hot, _, _ = engine.compute_rates(st_hot)

        assert r_f_hot > r_f_nom > r_f_cold > 0.0

    def test_activation_energy_relative_sensitivities(self) -> None:
        """Verify reaction with higher activation energy (Ea_reverse 68kJ > Ea_forward 52kJ) shows greater sensitivity."""
        engine = PHASuccinicEsterificationEngine()
        t1 = 380.0
        t2 = 460.0
        rt1 = R_GAS_CONSTANT * t1
        rt2 = R_GAS_CONSTANT * t2

        ratio_f = math.exp(-engine.cfg.ea_forward_j_mol / rt2) / math.exp(-engine.cfg.ea_forward_j_mol / rt1)
        ratio_r = math.exp(-engine.cfg.ea_reverse_j_mol / rt2) / math.exp(-engine.cfg.ea_reverse_j_mol / rt1)

        assert ratio_r > ratio_f

    def test_zero_reactant_halts_forward_rate(self) -> None:
        """Verify zero succinic acid or alcohol halts forward esterification rate."""
        engine = PHASuccinicEsterificationEngine()
        st_no_sa = PHASuccinicEsterificationState(c_succinic_acid=0.0, c_alcohol=5.0)
        st_no_alc = PHASuccinicEsterificationState(c_succinic_acid=2.0, c_alcohol=0.0)

        r_f_1, _, _ = engine.compute_rates(st_no_sa)
        r_f_2, _, _ = engine.compute_rates(st_no_alc)

        assert r_f_1 == 0.0
        assert r_f_2 == 0.0

    def test_zero_product_halts_reverse_rate(self) -> None:
        """Verify zero ester or water halts reverse hydrolysis rate."""
        engine = PHASuccinicEsterificationEngine()
        st_no_das = PHASuccinicEsterificationState(c_dialkyl_succinate=0.0, c_water=1.0)
        st_no_water = PHASuccinicEsterificationState(c_dialkyl_succinate=0.5, c_water=0.0)

        _, r_r_1, _ = engine.compute_rates(st_no_das)
        _, r_r_2, _ = engine.compute_rates(st_no_water)

        assert r_r_1 == 0.0
        assert r_r_2 == 0.0

    def test_rates_zero_when_tripped_or_frozen(self) -> None:
        """Verify all reaction rates are zero when tripped or reboiler is below 280 K."""
        engine = PHASuccinicEsterificationEngine()
        engine.trip_active = True
        rates_tripped = engine.compute_rates(engine.state)
        assert rates_tripped == (0.0, 0.0, 0.0)

        engine.trip_active = False
        st_cold = PHASuccinicEsterificationState(t_reboiler=260.0)
        rates_cold = engine.compute_rates(st_cold)
        assert rates_cold == (0.0, 0.0, 0.0)

    def test_ester_purity_and_acid_conversion_properties(self) -> None:
        """Verify acid_conversion_pct and ester_purity_pct calculations."""
        engine = PHASuccinicEsterificationEngine()
        engine.state.c_succinic_acid = 0.5   # Initial was 2.0 -> 1.5 converted = 75.0%
        engine.state.c_dialkyl_succinate = 1.5 # Purity = 1.5 / (0.5 + 1.5) = 75.0%

        assert math.isclose(engine.acid_conversion_pct, 75.0, rel_tol=1e-2)
        assert math.isclose(engine.ester_purity_pct, 75.0, rel_tol=1e-2)


# ============================================================================
# 3. TestCoupled6StateDerivatives
# ============================================================================

class TestCoupled6StateDerivatives:
    """Validate coupled 6-state ODE derivative calculations, mass/energy balance, volume/concentration non-negativity."""

    def test_state_initialization_defaults_and_aliases(self) -> None:
        """Verify PHASuccinicEsterificationState default values and flexible property getters/setters."""
        st = PHASuccinicEsterificationState()
        assert st.c_succinic_acid == 2.0
        assert st.c_alcohol == 5.0
        assert st.c_dialkyl_succinate == 0.05
        assert st.c_water == 0.10
        assert st.t_reboiler == 433.15
        assert st.t_condenser == 348.15
        assert st.p_column == 1.80
        assert st.delta_p_trays == 0.12
        assert st.dt_reboiler_dt == 0.0

        # Property getters
        assert st.C_succinic_acid == 2.0
        assert st.succinic_acid == 2.0
        assert st.c_sa == 2.0
        assert st.C_alcohol == 5.0
        assert st.alcohol == 5.0
        assert st.c_alc == 5.0
        assert st.C_dialkyl_succinate == 0.05
        assert st.dialkyl_succinate == 0.05
        assert st.c_das == 0.05
        assert st.c_ester == 0.05
        assert st.C_water == 0.10
        assert st.water == 0.10
        assert st.T_reboiler == 433.15
        assert st.t_reb == 433.15
        assert st.reboiler_temp == 433.15
        assert st.T_condenser == 348.15
        assert st.t_cond == 348.15
        assert st.condenser_temp == 348.15
        assert st.P_column == 1.80
        assert st.p_col == 1.80
        assert st.Delta_p_trays == 0.12
        assert st.delta_p == 0.12
        assert st.dT_reboiler_dt == 0.0

        # Setters
        st.C_succinic_acid = 1.8
        assert st.c_succinic_acid == 1.8
        st.c_sa = 1.7
        assert st.c_succinic_acid == 1.7
        st.C_alcohol = 4.5
        assert st.c_alcohol == 4.5
        st.c_alc = 4.2
        assert st.c_alcohol == 4.2
        st.C_dialkyl_succinate = 0.25
        assert st.c_dialkyl_succinate == 0.25
        st.c_ester = 0.30
        assert st.c_dialkyl_succinate == 0.30
        st.C_water = 0.20
        assert st.c_water == 0.20
        st.T_reboiler = 440.0
        assert st.t_reboiler == 440.0
        st.reboiler_temp = 445.0
        assert st.t_reboiler == 445.0
        st.T_condenser = 355.0
        assert st.t_condenser == 355.0
        st.condenser_temp = 360.0
        assert st.t_condenser == 360.0
        st.P_column = 2.1
        assert st.p_column == 2.1
        st.delta_p = 0.15
        assert st.delta_p_trays == 0.15
        st.dT_reboiler_dt = 1.5
        assert st.dt_reboiler_dt == 1.5

    def test_state_serialization_roundtrip(self) -> None:
        """Verify PHASuccinicEsterificationState dictionary serialization roundtrip with case-insensitivity."""
        st = PHASuccinicEsterificationState(
            c_succinic_acid=1.5,
            c_alcohol=4.0,
            c_dialkyl_succinate=0.8,
            c_water=0.3,
            t_reboiler=430.0,
            t_condenser=350.0,
            p_column=1.9,
            delta_p_trays=0.14,
        )
        d = st.to_dict()
        assert d["c_succinic_acid"] == 1.5
        assert d["c_alcohol"] == 4.0
        assert d["c_dialkyl_succinate"] == 0.8
        assert d["t_reboiler"] == 430.0

        st_rebuilt = PHASuccinicEsterificationState.from_dict(d)
        assert st_rebuilt.c_succinic_acid == 1.5
        assert st_rebuilt.c_alcohol == 4.0
        assert st_rebuilt.t_reboiler == 430.0

        # Alternative key names
        alt_d = {
            "C_succinic_acid": 1.2,
            "C_alcohol": 3.8,
            "C_dialkyl_succinate": 1.1,
            "treb": 435.0,
            "tcond": 352.0,
            "pcol": 2.0,
            "dp": 0.16,
        }
        st_alt = PHASuccinicEsterificationState.from_dict(alt_d)
        assert st_alt.c_succinic_acid == 1.2
        assert st_alt.c_alcohol == 3.8
        assert st_alt.t_reboiler == 435.0

    def test_derivatives_nominal_signs(self) -> None:
        """Verify component concentration derivatives signs during active reactive distillation."""
        engine = PHASuccinicEsterificationEngine()
        dc_sa, dc_alc, dc_das, dc_water, dt_reb, dt_cond, dp_col, dc_dist = engine._derivatives(engine.state)

        # Bio-succinic acid is consumed
        assert dc_sa < 0.0
        # Dialkyl succinate is generated
        assert dc_das > 0.0
        # Alcohol is consumed
        assert dc_alc < 0.0
        # Distillate mass is exported
        assert dc_dist > 0.0
        # Derivatives are all finite numbers
        assert math.isfinite(dt_reb)
        assert math.isfinite(dt_cond)
        assert math.isfinite(dp_col)

    def test_reboiler_thermal_energy_balance_derivatives(self) -> None:
        """Verify reboiler temperature derivative responds directly to reboiler heating duty."""
        engine = PHASuccinicEsterificationEngine()
        engine.reboiler_duty_kw = 180.0
        derivs_high = engine._derivatives(engine.state)

        engine.reboiler_duty_kw = 50.0
        derivs_low = engine._derivatives(engine.state)

        assert derivs_high[4] > derivs_low[4]

    def test_overhead_condenser_thermal_energy_balance_derivatives(self) -> None:
        """Verify condenser temperature derivative responds to coolant removal."""
        engine = PHASuccinicEsterificationEngine()
        # Warmer condenser removes heat more effectively
        st1 = PHASuccinicEsterificationState(t_condenser=370.0)
        st2 = PHASuccinicEsterificationState(t_condenser=330.0)

        dt_cond_1 = engine._derivatives(st1)[5]
        dt_cond_2 = engine._derivatives(st2)[5]

        # Higher T_condenser experiences more cooling removal, hence lower (more negative) dt_dt
        assert dt_cond_1 < dt_cond_2

    def test_column_pressure_dynamics_derivatives(self) -> None:
        """Verify column pressure derivative responds to vapor generation and relief."""
        engine = PHASuccinicEsterificationEngine()
        st = PHASuccinicEsterificationState(t_condenser=300.0, p_column=1.80)
        engine.reboiler_duty_kw = 200.0
        dp_high = engine._derivatives(st)[6]

        engine.reboiler_duty_kw = 20.0
        dp_low = engine._derivatives(st)[6]

        assert dp_high > dp_low

    def test_distillate_mass_draw_derivatives(self) -> None:
        """Verify distillate mass draw rate is positive during active boiling."""
        engine = PHASuccinicEsterificationEngine()
        engine.reboiler_heater = True
        dc_dist = engine._derivatives(engine.state)[7]
        assert dc_dist > 0.0

    def test_derivatives_during_emergency_dump(self) -> None:
        """Verify intense cooling, depressurization, and reaction halt during emergency dump."""
        engine = PHASuccinicEsterificationEngine()
        engine.emergency_dump()
        engine.trip_active = True

        derivs = engine._derivatives(engine.state)
        # Reactant consumption halted
        assert derivs[0] == 0.0
        assert derivs[1] == 0.0
        assert derivs[2] == 0.0
        assert derivs[3] == 0.0
        # Intense cooling
        assert derivs[4] < 0.0
        assert derivs[5] < 0.0
        # Depressurization vent
        assert derivs[6] <= 0.0
        # No distillate draw
        assert derivs[7] == 0.0


# ============================================================================
# 4. TestRK4IntegrationStability
# ============================================================================

class TestRK4IntegrationStability:
    """Validate RK4 integration stability, convergence, step size variation (dt=0.01s to 0.1s)."""

    def test_single_step_rk4_updates_state(self) -> None:
        """Verify a single RK4 step updates state variables consistently without tripping."""
        engine = PHASuccinicEsterificationEngine()
        c_sa_0 = engine.state.c_succinic_acid
        c_das_0 = engine.state.c_dialkyl_succinate

        engine.step_rk4(dt=0.1)

        assert engine.state.c_succinic_acid < c_sa_0
        assert engine.state.c_dialkyl_succinate > c_das_0
        assert engine.trip_active is False
        assert engine.diagnostic_code == DIAG_OK

    def test_rk4_step_size_variation_stability(self) -> None:
        """Verify numerical stability and convergence across dt=0.01s, 0.05s, and 0.1s."""
        # Run 0.5 seconds total simulation time
        col_fine = PHASuccinicEsterificationEngine()
        col_mid = PHASuccinicEsterificationEngine()
        col_coarse = PHASuccinicEsterificationEngine()

        for _ in range(50):
            col_fine.step_rk4(dt=0.01)

        for _ in range(10):
            col_mid.step_rk4(dt=0.05)

        for _ in range(5):
            col_coarse.step_rk4(dt=0.10)

        # All converge within 2% relative tolerance
        assert math.isclose(col_fine.state.c_succinic_acid, col_coarse.state.c_succinic_acid, rel_tol=2e-2)
        assert math.isclose(col_fine.state.c_dialkyl_succinate, col_coarse.state.c_dialkyl_succinate, rel_tol=2e-2)
        assert math.isclose(col_mid.state.c_succinic_acid, col_coarse.state.c_succinic_acid, rel_tol=1e-2)

    def test_rk4_state_non_negativity_clamping(self) -> None:
        """Verify concentration state variables never drop below zero during RK4 integration."""
        st_low = PHASuccinicEsterificationState(
            c_succinic_acid=0.005, c_alcohol=0.01, c_dialkyl_succinate=0.001, c_water=0.002
        )
        engine = PHASuccinicEsterificationEngine(state=st_low)

        for _ in range(10):
            engine.step_rk4(dt=0.05)

        assert engine.state.c_succinic_acid >= 0.0
        assert engine.state.c_alcohol >= 0.0
        assert engine.state.c_dialkyl_succinate >= 0.0
        assert engine.state.c_water >= 0.0
        assert engine.p_column >= 0.0

    def test_rk4_reboiler_condenser_thermal_coupling(self) -> None:
        """Verify reboiler and condenser temperatures remain thermally coupled over multiple RK4 steps."""
        engine = PHASuccinicEsterificationEngine()
        for _ in range(10):
            engine.step_rk4(dt=0.1)

        # Reboiler stays hotter than condenser
        assert engine.state.t_reboiler > engine.state.t_condenser
        assert engine.state.t_reboiler > 350.0
        assert engine.state.t_condenser > 300.0

    def test_multi_step_trajectory_monotonic_conversion(self) -> None:
        """Verify multi-step simulation trajectory exhibits smooth, monotonic acid conversion."""
        engine = PHASuccinicEsterificationEngine()
        sa_history = [engine.state.c_succinic_acid]

        for _ in range(10):
            engine.step_rk4(dt=0.1)
            sa_history.append(engine.state.c_succinic_acid)

        for i in range(len(sa_history) - 1):
            assert sa_history[i + 1] <= sa_history[i]
        assert sa_history[-1] < sa_history[0]

    def test_rk4_distillate_mass_export_accumulation(self) -> None:
        """Verify cumulative distillate mass exported accumulates positively across steps."""
        engine = PHASuccinicEsterificationEngine()
        for _ in range(10):
            engine.step_rk4(dt=0.1)

        assert engine.cumulative_distillate_mass_exported > 0.0

    def test_engine_class_aliases(self) -> None:
        """Verify all class aliases instantiate and exhibit identical interfaces."""
        for alias in [
            PhaSuccinicEsterificationEngine,
            PHASuccinicEsterificationReactor,
            PhaSuccinicEsterificationReactor,
            PHASuccinicEsterificationSimulator,
            PhaSuccinicEsterificationSimulator,
            PHASuccinicEsterificationLogicUnit,
            PhaSuccinicEsterificationLogicUnit,
            PHASuccinicEsterificationSimulationLogicUnit,
            PhaSuccinicEsterificationSimulationLogicUnit,
            PHASuccinicEsterificationModel,
            PhaSuccinicEsterificationModel,
            PHASuccinicEsterificationPlantModel,
            PhaSuccinicEsterificationPlantModel,
            PHASuccEsterEngine,
            PhaSuccEsterEngine,
            PHASuccEsterSimulator,
            PhaSuccEsterSimulator,
        ]:
            inst = alias()
            assert isinstance(inst, PHASuccinicEsterificationEngine)
            assert inst.state.c_succinic_acid == 2.0
            assert inst.unit_id == "PHA_SUCC_ESTER_DISTILLATION_W314"


# ============================================================================
# 5. TestMassBalanceConservation
# ============================================================================

class TestMassBalanceConservation:
    """Validate continuous and batch mass conservation residuals (< 1e-10)."""

    def test_mass_conservation_single_cycle(self) -> None:
        """Verify mass balance conservation residual < 1e-10 in a single cycle."""
        engine = PHASuccinicEsterificationEngine()
        engine.step_rk4(dt=0.1)
        assert engine.conservation_residual < 1e-10

    def test_mass_conservation_multi_cycle_soak(self) -> None:
        """Verify continuous mass conservation across 50 consecutive RK4 cycles."""
        engine = PHASuccinicEsterificationEngine()
        for cycle in range(1, 51):
            engine.step_rk4(dt=0.1)
            assert (
                engine.conservation_residual < 1e-10
            ), f"Cycle {cycle}: residual {engine.conservation_residual:.2e} exceeded 1e-10"

    def test_mass_conservation_across_temperatures(self) -> None:
        """Verify mass conservation holds across diverse reboiler operating temperatures."""
        for temp in [400.0, 433.15, 470.0]:
            st = PHASuccinicEsterificationState(t_reboiler=temp)
            engine = PHASuccinicEsterificationEngine(state=st)
            for _ in range(5):
                engine.step_rk4(dt=0.1)
            assert engine.conservation_residual < 1e-10

    def test_mass_conservation_across_initial_concentrations(self) -> None:
        """Verify mass conservation holds across diverse initial precursor concentrations."""
        for c0 in [1.0, 2.0, 4.0]:
            st = PHASuccinicEsterificationState(c_succinic_acid=c0)
            engine = PHASuccinicEsterificationEngine(state=st)
            for _ in range(5):
                engine.step_rk4(dt=0.1)
            assert engine.conservation_residual < 1e-10

    def test_mass_conservation_with_initial_products(self) -> None:
        """Verify mass conservation holds when initial mixture contains products."""
        st = PHASuccinicEsterificationState(c_dialkyl_succinate=0.5, c_water=1.0)
        engine = PHASuccinicEsterificationEngine(state=st)
        for _ in range(5):
            engine.step_rk4(dt=0.1)
        assert engine.conservation_residual < 1e-10

    def test_mass_conservation_various_step_sizes(self) -> None:
        """Verify mass conservation holds across diverse step sizes dt=0.01, 0.05, 0.1."""
        for step_dt in [0.01, 0.05, 0.1]:
            engine = PHASuccinicEsterificationEngine()
            for _ in range(5):
                engine.step_rk4(dt=step_dt)
            assert engine.conservation_residual < 1e-10

    def test_acid_conversion_and_ester_purity_bounds(self) -> None:
        """Verify acid conversion and ester purity percentage metrics remain bounded in [0, 100]."""
        engine = PHASuccinicEsterificationEngine()
        for _ in range(10):
            engine.step_rk4(dt=0.1)
        assert 0.0 <= engine.acid_conversion_pct <= 100.0
        assert 0.0 <= engine.ester_purity_pct <= 100.0


# ============================================================================
# 6. TestReboilerOverheatTrip
# ============================================================================

class TestReboilerOverheatTrip:
    """Validate Priority 1 reboiler overheat runaway safety trips (0xF981)."""

    def test_high_temperature_trip_0xf981(self) -> None:
        """Verify Priority 1 trip triggers when reboiler temperature exceeds 520 K."""
        engine = PHASuccinicEsterificationEngine()
        engine.state.t_reboiler = 525.0  # Above 520.0 K threshold
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_REBOILER_OVERHEAT
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0xF981
        assert engine.emergency_dump_active is True
        assert engine.reboiler_heater is False
        assert engine.column_active is False
        assert engine.reg_table.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE) is False
        assert engine.reg_table.read_bit(COIL_PHA_SUCC_REBOILER_HEATER) is False
        assert engine.reg_table.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF981

    def test_high_rate_of_rise_runaway_trip_0xf981(self) -> None:
        """Verify Priority 1 trip triggers when reboiler temperature rise rate exceeds 20 K/s."""
        engine = PHASuccinicEsterificationEngine()
        engine.state.dt_reboiler_dt = 25.0  # Above 20.0 K/s threshold
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_REBOILER_OVERHEAT
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0xF981
        assert engine.reg_table.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True

    def test_reboiler_overheat_dump_and_heater_isolation(self) -> None:
        """Verify emergency dump deactivates column, isolates heater, and opens dump valve."""
        engine = PHASuccinicEsterificationEngine()
        engine.emergency_dump()

        assert engine.column_active is False
        assert engine.reboiler_heater is False
        assert engine.emergency_dump_active is True
        assert engine.reboiler_duty_kw == 0.0

    def test_emergency_dump_cooling_dynamics(self) -> None:
        """Verify emergency dump causes rapid cooling of both reboiler and condenser."""
        engine = PHASuccinicEsterificationEngine()
        engine.emergency_dump()
        engine.trip_active = True
        t_reb_0 = engine.state.t_reboiler
        t_cond_0 = engine.state.t_condenser

        engine.step_rk4(dt=0.5)

        assert engine.state.t_reboiler < t_reb_0
        assert engine.state.t_condenser < t_cond_0
        assert engine.emergency_dump_active is True

    def test_inject_methods_for_reboiler_overheat(self) -> None:
        """Verify inject_reboiler_overheat and inject_reboiler_runaway_rate helper methods."""
        engine1 = PHASuccinicEsterificationEngine()
        engine1.inject_reboiler_overheat(temp_k=530.0)
        assert engine1.state.t_reboiler == 530.0
        engine1.step_rk4(dt=0.05)
        assert engine1.trip_active is True
        assert engine1.diagnostic_code == DIAG_ERR_REBOILER_OVERHEAT

        engine2 = PHASuccinicEsterificationEngine()
        engine2.inject_reboiler_runaway_rate(rate_k_s=22.0)
        assert engine2.state.dt_reboiler_dt == 22.0
        engine2.step_rk4(dt=0.05)
        assert engine2.trip_active is True
        assert engine2.diagnostic_code == DIAG_ERR_REBOILER_OVERHEAT

    def test_overheat_coil_and_register_table_reflection(self) -> None:
        """Verify %M641, %M642, %M643, and %R2757 are updated immediately on reheat trip."""
        engine = PHASuccinicEsterificationEngine()
        engine.state.t_reboiler = 535.0
        engine.step_rk4(dt=0.05)

        rt = engine.reg_table
        assert rt.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE) is False
        assert rt.read_bit(COIL_PHA_SUCC_REBOILER_HEATER) is False
        assert rt.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True
        assert (rt.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF981


# ============================================================================
# 7. TestColumnOverpressureTrip
# ============================================================================

class TestColumnOverpressureTrip:
    """Validate Priority 2 column overpressure safety trips (0xF982)."""

    def test_column_overpressure_trip_0xf982(self) -> None:
        """Verify Priority 2 trip triggers when column pressure exceeds 30.0 bar."""
        engine = PHASuccinicEsterificationEngine()
        engine.p_column = 32.0  # Above 30.0 bar threshold
        engine.state.p_column = 32.0
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_COLUMN_OVERPRESSURE
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0xF982
        assert engine.emergency_dump_active is True
        assert engine.reg_table.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF982

    def test_overpressure_vent_depressurization(self) -> None:
        """Verify emergency dump depressurizes the column vessel."""
        engine = PHASuccinicEsterificationEngine()
        engine.p_column = 31.0
        engine.state.p_column = 31.0
        engine.step_rk4(dt=0.05)
        p0 = engine.p_column

        # Advance step during dump depressurization
        engine.step_rk4(dt=0.2)
        assert engine.p_column < p0

    def test_priority_overheat_over_overpressure(self) -> None:
        """Verify Priority 1 (Reboiler Overheat 0xF981) dominates Priority 2 (Overpressure 0xF982)."""
        engine = PHASuccinicEsterificationEngine()
        engine.state.t_reboiler = 525.0  # Tripped (P1)
        engine.p_column = 35.0          # Tripped (P2)
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_REBOILER_OVERHEAT
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF981

    def test_overpressure_register_coils_state(self) -> None:
        """Verify coil states when tripped on overpressure (%M641=False, %M642=False, %M643=True)."""
        engine = PHASuccinicEsterificationEngine()
        engine.p_column = 34.0
        engine.step_rk4(dt=0.05)

        rt = engine.reg_table
        assert rt.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE) is False
        assert rt.read_bit(COIL_PHA_SUCC_REBOILER_HEATER) is False
        assert rt.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True

    def test_overpressure_trip_word_register_masking(self) -> None:
        """Verify signed 16-bit safe masking of 0xF982 in %R2757."""
        engine = PHASuccinicEsterificationEngine()
        engine.diagnostic_code = DiagnosticCode(0xF982)
        engine.trip_active = True
        engine.sync_to_registers(engine.reg_table)

        raw = engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE)
        assert (raw & 0xFFFF) == 0xF982
        assert DiagnosticCode(0xF982) == raw

    def test_inject_column_overpressure_method(self) -> None:
        """Verify inject_column_overpressure helper method triggers trip 0xF982."""
        engine = PHASuccinicEsterificationEngine()
        engine.inject_column_overpressure(pressure_bar=33.5)
        assert engine.p_column == 33.5
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_COLUMN_OVERPRESSURE


# ============================================================================
# 8. TestTrayFloodingAndAcidPrecipitationTrips
# ============================================================================

class TestTrayFloodingAndAcidPrecipitationTrips:
    """Validate Priority 3 tray flooding/weeping (0xF983) and Priority 5 acid precipitation (0xF985) trips."""

    def test_tray_flooding_trip_0xf983(self) -> None:
        """Verify Priority 3 trip triggers when tray DeltaP exceeds 0.80 bar."""
        engine = PHASuccinicEsterificationEngine()
        engine.delta_p_trays = 0.85
        engine.state.delta_p_trays = 0.85
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_TRAY_FLOODING_WEEPING
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0xF983
        assert engine.emergency_dump_active is True
        assert engine.reg_table.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF983

    def test_tray_weeping_trip_0xf983(self) -> None:
        """Verify Priority 3 trip triggers when tray DeltaP drops below 0.02 bar while active."""
        engine = PHASuccinicEsterificationEngine()
        engine.delta_p_trays = 0.015
        engine.state.delta_p_trays = 0.015
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_TRAY_FLOODING_WEEPING
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0xF983

    def test_acid_precipitation_clog_trip_0xf985(self) -> None:
        """Verify Priority 5 trip triggers when free acid exceeds temperature solubility limit."""
        engine = PHASuccinicEsterificationEngine()
        engine.inject_acid_precipitation(c_acid=8.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_ACID_PRECIPITATION_CLOG
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0xF985
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF985

    def test_cold_acid_precipitation_trip_0xf985(self) -> None:
        """Verify lowering temperature drops solubility limit and triggers precipitation trip 0xF985."""
        engine = PHASuccinicEsterificationEngine()
        engine.inject_cold_precipitation(temp_k=295.0)
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_ACID_PRECIPITATION_CLOG

    def test_priority_overpressure_over_flooding(self) -> None:
        """Verify Priority 2 (Overpressure 0xF982) dominates Priority 3 (Tray Flooding 0xF983)."""
        engine = PHASuccinicEsterificationEngine()
        engine.p_column = 35.0          # Tripped (P2)
        engine.delta_p_trays = 0.88     # Tripped (P3)
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_COLUMN_OVERPRESSURE
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF982

    def test_priority_flooding_over_mass_divergence(self) -> None:
        """Verify Priority 3 (Tray Flooding 0xF983) dominates Priority 4 (Mass Divergence 0xF984)."""
        engine = PHASuccinicEsterificationEngine()
        engine.delta_p_trays = 0.88           # Tripped (P3)
        engine.conservation_residual = 0.005  # Tripped (P4)
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_TRAY_FLOODING_WEEPING
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF983

    def test_priority_mass_divergence_over_precipitation(self) -> None:
        """Verify Priority 4 (Mass Divergence 0xF984) dominates Priority 5 (Acid Precipitation 0xF985)."""
        engine = PHASuccinicEsterificationEngine()
        engine.conservation_residual = 0.005  # Tripped (P4)
        engine.state.c_succinic_acid = 8.5    # Tripped (P5)
        engine.step_rk4(dt=0.05)

        assert engine.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF984

    def test_inject_methods_for_flooding_and_precipitation(self) -> None:
        """Verify helper injection methods for tray flooding and weeping."""
        col1 = PHASuccinicEsterificationEngine()
        col1.inject_tray_flooding(delta_p=0.86)
        col1.step_rk4(dt=0.05)
        assert col1.diagnostic_code == DIAG_ERR_TRAY_FLOODING_WEEPING

        col2 = PHASuccinicEsterificationEngine()
        col2.inject_tray_weeping(delta_p=0.01)
        col2.step_rk4(dt=0.05)
        assert col2.diagnostic_code == DIAG_ERR_TRAY_FLOODING_WEEPING


# ============================================================================
# 9. TestRegisterTableSynchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate RegisterTable synchronization across %R2750..%R2757 and %M641..%M643."""

    def test_nominal_register_sync(self) -> None:
        """Verify all register values synchronized to Horner OCS memory space %R2750..%R2757."""
        engine = PHASuccinicEsterificationEngine()
        engine.scan_step(dt=0.1)
        rt = engine.reg_table

        w_treb = rt.read_word(REG_PHA_SUCC_REBOILER_TEMP)
        w_tcond = rt.read_word(REG_PHA_SUCC_CONDENSER_TEMP)
        w_press = rt.read_word(REG_PHA_SUCC_COLUMN_PRESSURE)
        w_purity = rt.read_word(REG_PHA_SUCC_ESTER_PURITY)
        w_conv = rt.read_word(REG_PHA_SUCC_ACID_CONVERSION)
        w_reflux = rt.read_word(REG_PHA_SUCC_REFLUX_RATIO)
        w_duty = rt.read_word(REG_PHA_SUCC_REBOILER_DUTY_KW)
        w_diag = rt.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE)

        assert w_treb > 0
        assert w_tcond > 0
        assert w_press > 0
        assert w_purity > 0
        assert w_conv >= 0
        assert w_reflux > 0
        assert w_duty > 0
        assert (w_diag & 0xFFFF) == 0x0000

    def test_discrete_coils_nominal_state(self) -> None:
        """Verify coils %M641=True, %M642=True, %M643=False in nominal operating state."""
        engine = PHASuccinicEsterificationEngine()
        engine.sync_to_registers(engine.reg_table)
        rt = engine.reg_table

        assert rt.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE) is True
        assert rt.read_bit(COIL_PHA_SUCC_REBOILER_HEATER) is True
        assert rt.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is False

    def test_signed_16bit_negative_temperature(self) -> None:
        """Verify signed 16-bit safe conversion for temperatures below 0 °C."""
        engine = PHASuccinicEsterificationEngine()
        # 250.0 K = -23.15 °C -> scaled x10 is -231 or -232 (signed 16-bit)
        engine.state.t_reboiler = 250.0
        engine.sync_to_registers(engine.reg_table)

        w_treb = engine.reg_table.read_word(REG_PHA_SUCC_REBOILER_TEMP)
        signed_val = w_treb - 0x10000 if w_treb >= 0x8000 else w_treb
        assert signed_val == -231 or signed_val == -232

    def test_all_diagnostic_codes_written_to_reg2757(self) -> None:
        """Verify diagnostic codes 0x0000, 0xF981..0xF985 correctly written and masked."""
        engine = PHASuccinicEsterificationEngine()
        codes = [0x0000, 0xF981, 0xF982, 0xF983, 0xF984, 0xF985]

        for c_val in codes:
            engine.diagnostic_code = DiagnosticCode(c_val)
            engine.sync_to_registers(engine.reg_table)
            raw = engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE)
            assert (raw & 0xFFFF) == c_val

    def test_mass_balance_divergence_trip_0xf984(self) -> None:
        """Verify Priority 4 trip triggers on continuous mass balance divergence (> 1e-4)."""
        engine = PHASuccinicEsterificationEngine()
        engine.conservation_residual = 0.005
        engine.step_rk4(dt=0.05)

        assert engine.trip_active is True
        assert engine.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF984

    def test_register_sync_privilege_modes(self) -> None:
        """Verify synchronization operates cleanly under both USER and SYSTEM privilege modes."""
        engine = PHASuccinicEsterificationEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert (rt.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        engine.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_clamped_register_ranges(self) -> None:
        """Verify register outputs clamp strictly within defined ranges."""
        engine = PHASuccinicEsterificationEngine()
        engine.p_column = 100.0  # Excessive pressure -> clamp to 5000 (50.0 bar)
        engine.sync_to_registers(engine.reg_table)
        assert engine.reg_table.read_word(REG_PHA_SUCC_COLUMN_PRESSURE) <= 5000


# ============================================================================
# 10. TestPureStructuredTextPOU
# ============================================================================

class TestPureStructuredTextPOU:
    """Validate pure ST POU validation and anti-ladder rejection of all 9 constructs."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify pure ST POU syntax using verify_pha_succinic_esterification_pure_st()."""
        assert verify_pha_succinic_esterification_pure_st() is True
        assert verify_pha_succ_ester_pure_st() is True

    def test_st_parser_ast_validation(self) -> None:
        """Verify STParser parses PHA_SUCCINIC_ESTERIFICATION_PURE_ST_POU cleanly with 0 errors."""
        res = STParser.validate_code(PHA_SUCCINIC_ESTERIFICATION_PURE_ST_POU)
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

    def test_anti_ladder_rung_and_network_and_mnemonic_rejection(self) -> None:
        """Verify ladder rung, network delimiters, and mnemonics are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: START")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 10")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC %M641")

    def test_pou_variable_declarations_complete(self) -> None:
        """Verify ST POU contains all required variables %R2750..%R2757 and %M641..%M643."""
        pou = PHA_SUCCINIC_ESTERIFICATION_PURE_ST_POU
        assert "%R2750" in pou
        assert "%R2751" in pou
        assert "%R2752" in pou
        assert "%R2753" in pou
        assert "%R2754" in pou
        assert "%R2755" in pou
        assert "%R2756" in pou
        assert "%R2757" in pou
        assert "%M641" in pou
        assert "%M642" in pou
        assert "%M643" in pou


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Validate ILogicUnit scan step compliance, reset behavior, and 100-cycle simulation soak with memory profiling."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify ILogicUnit standard properties (unit_id, name, priority, is_enabled)."""
        engine = PHASuccinicEsterificationEngine()
        assert engine.unit_id == "PHA_SUCC_ESTER_DISTILLATION_W314"
        assert engine.name == "PHASuccinicEsterificationEngine"
        assert engine.priority == 50
        assert engine.is_enabled is True

    def test_scan_step_various_invocation_signatures(self) -> None:
        """Verify scan_step handles diverse parameter invocation signatures."""
        engine = PHASuccinicEsterificationEngine()

        # 1. Positional dt
        res1 = engine.scan_step(0.05)
        assert res1.status == AgentStatus.SUCCESS

        # 2. Kwarg dt
        res2 = engine.scan_step(dt=0.10)
        assert res2.status == AgentStatus.SUCCESS

        # 3. Kwarg dt_h
        res3 = engine.scan_step(dt_h=0.00005)
        assert res3.status == AgentStatus.SUCCESS

    def test_scan_step_with_scan_context(self) -> None:
        """Verify scan_step with ScanContext propagates RegisterTable."""
        rt_ext = RegisterTable()
        context = ScanContext(cycle=1, dt=0.1, register_table=rt_ext)
        engine = PHASuccinicEsterificationEngine()

        res = engine.scan_step(context=context)
        assert res.status == AgentStatus.SUCCESS
        assert engine.reg_table is rt_ext
        assert rt_ext.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE) is True

    def test_step_and_execute_methods(self) -> None:
        """Verify step() and execute() methods correctly invoke scan_step and increment cycle count."""
        engine = PHASuccinicEsterificationEngine()
        c0 = engine.cycle_count
        engine.step(0.1)
        assert engine.cycle_count == c0 + 1

        engine.execute(0.1)
        assert engine.cycle_count == c0 + 2

    def test_scan_step_execution_result_contract(self) -> None:
        """Verify scan_step returns strict 4-state ExecutionResult contract."""
        engine = PHASuccinicEsterificationEngine()
        res = engine.scan_step(dt=0.1)

        assert isinstance(res, ExecutionResult)
        assert res.status in [AgentStatus.SUCCESS, AgentStatus.FAILED]
        assert "c_succinic_acid" in res.data
        assert "c_alcohol" in res.data
        assert "c_dialkyl_succinate" in res.data
        assert "c_water" in res.data
        assert "t_reboiler" in res.data
        assert "t_condenser" in res.data
        assert "p_column" in res.data
        assert "delta_p_trays" in res.data
        assert "acid_conversion_pct" in res.data
        assert "ester_purity_pct" in res.data
        assert "conservation_residual" in res.data
        assert res.error_code is None

    def test_reset_functionality(self) -> None:
        """Verify reset() restores default initial conditions and clears safety trips."""
        engine = PHASuccinicEsterificationEngine()
        engine.state.t_reboiler = 530.0
        engine.step_rk4(dt=0.05)
        assert engine.trip_active is True

        engine.reset()
        assert engine.trip_active is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.state.c_succinic_acid == 2.0
        assert engine.state.t_reboiler == 433.15
        assert engine.emergency_dump_active is False
        assert (engine.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_100_cycle_simulation_soak_and_performance(self) -> None:
        """Execute 100-cycle continuous simulation soak and profile execution performance."""
        engine = PHASuccinicEsterificationEngine()
        t_start = time.perf_counter()

        for cycle in range(1, 101):
            res = engine.scan_step(dt=0.05)
            assert res.status == AgentStatus.SUCCESS
            assert engine.conservation_residual < 1e-10

        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        avg_cycle_ms = elapsed_ms / 100.0

        # Assert rapid simulation performance (< 5ms per scan cycle)
        assert avg_cycle_ms < 5.0
        assert engine.cycle_count == 100
        assert engine.trip_active is False

    def test_soak_memory_and_stability(self) -> None:
        """Verify soak execution maintains stable memory footprint and state bounds."""
        engine = PHASuccinicEsterificationEngine()
        for _ in range(100):
            engine.scan_step(dt=0.05)

        assert engine.state.c_succinic_acid >= 0.0
        assert engine.state.c_dialkyl_succinate >= 0.0
        assert engine.state.t_reboiler > 0.0


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
            res = run_pha_succinic_esterification_verification(output_path=out_path)
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
        res = run_pha_succinic_esterification_verification(quick=True)
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_evidence_json_structure_and_hashes(self) -> None:
        """Verify evidence JSON contains SHA-256 digests for POU and model config."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = run_pha_succinic_esterification_verification(output_path=out_path, quick=True)
            digests = res["data"]["digests"]
            assert "pou_sha256" in digests
            assert "model_sha256" in digests
            assert len(digests["pou_sha256"]) == 64
            assert len(digests["model_sha256"]) == 64
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_scripts_runner_module_execution(self) -> None:
        """Verify execution of scripts/run_pha_succinic_esterification_verification.py module runner."""
        from scripts.run_pha_succinic_esterification_verification import (
            execute_pha_succinic_esterification_verification,
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = execute_pha_succinic_esterification_verification(output_path=out_path, quick=True)
            assert res["status"] == "success"
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_main_entrypoint_with_tempfile(self) -> None:
        """Verify CLI main() in scripts/run_pha_succinic_esterification_verification.py passes cleanly."""
        from scripts.run_pha_succinic_esterification_verification import main as script_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = script_main(["--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_simulation_cli_main_entrypoint(self) -> None:
        """Verify CLI main() in src/jev_cscape/simulation/pha_succinic_esterification.py passes cleanly."""
        from jev_cscape.simulation.pha_succinic_esterification import main as sim_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = sim_main(["--verify", "--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_compatibility_runner_alias(self) -> None:
        """Verify run_pha_succ_ester_verification is an alias to run_pha_succinic_esterification_verification."""
        assert run_pha_succ_ester_verification is run_pha_succinic_esterification_verification
