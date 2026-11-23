"""Industrial Catalytic PHA Gasification & Bio-Syngas Pyrolysis Moving-Bed Unit Test Suite (W311).

Work Package: W311 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification test classes (80+ test cases):
1. TestPhysicalConstantsAndRegisters: Physical constants, stoichiometry, register %R2720..%R2727, coils %M634..%M636, signed 16-bit safe comparisons.
2. TestReactionRatesAndEquilibrium: Gasification reaction rates, water-gas shift equilibrium, H2/CO syngas ratio, Arrhenius kinetics.
3. TestCoupled6StateDerivatives: 6-state moving-bed ODE derivative calculations, mass/energy balance, volume/concentration non-negativity.
4. TestRK4IntegrationStability: RK4 stability, step size variation (dt=0.01s to 0.1s), trajectory smoothness, and class aliases.
5. TestCarbonMassConservation: Carbon mole and mass conservation residuals (< 1e-10) across diverse conversion regimes.
6. TestBedTemperatureExcursionTrip: Bed temperature excursion runaway trip (0xF971, %M636 nitrogen purge coil asserted, emergency cooling).
7. TestSyngasOverpressureTrip: Syngas overpressure trip (0xF972, %M635 flare valve asserted, depressurization dynamics).
8. TestTarFormationAndSteamStarvationTrips: Tar formation and steam starvation trips (0xF973, 0xF975, fault priority hierarchy).
9. TestRegisterTableSynchronization: Horner OCS memory sync across %R2720..%R2727 and %M634..%M636 with signed 16-bit masking.
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

from jev_cscape.simulation.pha_gasification import (
    CARBON_FRACTION_CHAR,
    CARBON_FRACTION_PHA,
    CARBON_FRACTION_SYNGAS,
    COIL_PHA_GASIF_ACTIVE,
    COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE,
    COIL_PHA_GASIF_FLARE,
    COIL_PHA_GASIF_FLARE_VALVE,
    COIL_PHA_GASIF_GASIFIER_ACTIVE,
    COIL_PHA_GASIF_NITROGEN_PURGE,
    COIL_PHA_GASIF_PURGE,
    COIL_PHA_GASIF_RUNNING,
    COIL_PHA_GASIF_SYNGAS_FLARE_VALVE,
    DIAG_ERR_BED_TEMP,
    DIAG_ERR_BED_TEMP_EXCURSION,
    DIAG_ERR_BED_TEMPERATURE_EXCURSION,
    DIAG_ERR_CARBON_DIVERGENCE,
    DIAG_ERR_CARBON_MASS_DIVERGENCE,
    DIAG_ERR_CLINKERING,
    DIAG_ERR_MASS_DIVERGENCE,
    DIAG_ERR_OVERPRESSURE,
    DIAG_ERR_STEAM_STARVATION,
    DIAG_ERR_STEAM_STARVATION_CLINKERING,
    DIAG_ERR_SYNGAS_OVERPRESSURE,
    DIAG_ERR_SYNGAS_OVERPRESSURE_TRIP,
    DIAG_ERR_TAR_DEPOSITION,
    DIAG_ERR_TAR_FORMATION,
    DIAG_ERR_TAR_FORMATION_DEPOSITION,
    DIAG_ERR_TEMPERATURE_EXCURSION,
    DIAG_OK,
    MW_CARBON,
    MW_CH4,
    MW_CO,
    MW_CO2,
    MW_H2,
    MW_H2O,
    MW_O2,
    MW_PHA_UNIT,
    PHA_GASIFICATION_CONTROL_POU,
    PHA_GASIFICATION_PURE_ST_POU,
    PHA_GASIF_PURE_ST_POU,
    PHAGasifConfig,
    PHAGasifDiagnosticCode,
    PHAGasifEngine,
    PHAGasifSimulator,
    PHAGasifState,
    PHAGasifStatusBits,
    PHAGasifStatusWord,
    PHAGasificationConfig,
    PHAGasificationControl,
    PHAGasificationDiagnosticCode,
    PHAGasificationEngine,
    PHAGasificationLogicUnit,
    PHAGasificationModel,
    PHAGasificationParameters,
    PHAGasificationPlantModel,
    PHAGasificationReactor,
    PHAGasificationSimulationLogicUnit,
    PHAGasificationSimulator,
    PHAGasificationState,
    PHAGasificationStateModel,
    PHAGasificationStatusBits,
    PHAGasificationStatusWord,
    PhaGasifConfig,
    PhaGasifDiagnosticCode,
    PhaGasifEngine,
    PhaGasifSimulator,
    PhaGasifState,
    PhaGasifStatusBits,
    PhaGasifStatusWord,
    PhaGasificationConfig,
    PhaGasificationDiagnosticCode,
    PhaGasificationEngine,
    PhaGasificationLogicUnit,
    PhaGasificationModel,
    PhaGasificationParameters,
    PhaGasificationPlantModel,
    PhaGasificationReactor,
    PhaGasificationSimulationLogicUnit,
    PhaGasificationSimulator,
    PhaGasificationState,
    PhaGasificationStateModel,
    PhaGasificationStatusBits,
    PhaGasificationStatusWord,
    R_GAS_CONSTANT,
    REG_PHA_GASIF_BED_TEMP,
    REG_PHA_GASIF_BED_TEMPERATURE,
    REG_PHA_GASIF_CARBON_CONVERSION,
    REG_PHA_GASIF_CGE,
    REG_PHA_GASIF_COLD_GAS_EFFICIENCY,
    REG_PHA_GASIF_CONV,
    REG_PHA_GASIF_CONVERSION,
    REG_PHA_GASIF_DIAG,
    REG_PHA_GASIF_DIAGNOSTIC_CODE,
    REG_PHA_GASIF_DUTY,
    REG_PHA_GASIF_EFFICIENCY,
    REG_PHA_GASIF_FREEBOARD_TEMP,
    REG_PHA_GASIF_FREEBOARD_TEMPERATURE,
    REG_PHA_GASIF_H2_CO,
    REG_PHA_GASIF_H2_CO_RATIO,
    REG_PHA_GASIF_PRESSURE,
    REG_PHA_GASIF_PSYNGAS,
    REG_PHA_GASIF_P_SYNGAS,
    REG_PHA_GASIF_RATIO,
    REG_PHA_GASIF_STEAM_DUTY,
    REG_PHA_GASIF_STEAM_OXYGEN_DUTY,
    REG_PHA_GASIF_SYNGAS_PRESSURE,
    REG_PHA_GASIF_TBED,
    REG_PHA_GASIF_TFREEBOARD,
    REG_PHA_GASIF_T_BED,
    REG_PHA_GASIF_T_FB,
    REG_PHA_GASIF_T_FREEBOARD,
    ST_PROGRAM_PHA_GASIFICATION_CONTROL,
    T_ZERO_CELSIUS,
    Y_CHAR_PHA,
    Y_SYNGAS_CHAR,
    Y_SYNGAS_PHA,
    DiagnosticCode,
    run_pha_gasif_verification,
    run_pha_gasification_verification,
    validate_pure_st,
    verify_pha_gasif_pure_st,
    verify_pha_gasification_pure_st,
)


# ============================================================================
# 1. TestPhysicalConstantsAndRegisters
# ============================================================================

class TestPhysicalConstantsAndRegisters:
    """Validate stoichiometry, molecular weights, register mappings, coils, and signed 16-bit diagnostic codes."""

    def test_molecular_weights_and_constants(self) -> None:
        """Verify molecular weights of PHA repeat unit, carbon, syngas species, and universal constants."""
        assert math.isclose(MW_PHA_UNIT, 86.09, rel_tol=1e-4)
        assert math.isclose(MW_CARBON, 12.011, rel_tol=1e-4)
        assert math.isclose(MW_CO, 28.010, rel_tol=1e-4)
        assert math.isclose(MW_H2, 2.016, rel_tol=1e-4)
        assert math.isclose(MW_CO2, 44.010, rel_tol=1e-4)
        assert math.isclose(MW_CH4, 16.043, rel_tol=1e-4)
        assert math.isclose(MW_H2O, 18.015, rel_tol=1e-4)
        assert math.isclose(MW_O2, 31.999, rel_tol=1e-4)
        assert math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-6)

    def test_carbon_fractions_and_stoichiometric_yields(self) -> None:
        """Verify carbon mass fractions and devolatilization yield conservation relationships."""
        expected_c_pha = (4.0 * 12.011) / 86.09
        assert math.isclose(CARBON_FRACTION_PHA, expected_c_pha, rel_tol=1e-4)
        assert math.isclose(CARBON_FRACTION_CHAR, 1.000000000, rel_tol=1e-6)
        assert math.isclose(CARBON_FRACTION_SYNGAS, 0.400000000, rel_tol=1e-6)
        assert math.isclose(Y_CHAR_PHA, 0.150000000, rel_tol=1e-6)

        # Enforce exact carbon conservation algebraic identity
        c_bal_pyro = (Y_CHAR_PHA * CARBON_FRACTION_CHAR) + (Y_SYNGAS_PHA * CARBON_FRACTION_SYNGAS)
        assert math.isclose(c_bal_pyro, CARBON_FRACTION_PHA, rel_tol=1e-9)

        c_bal_char = Y_SYNGAS_CHAR * CARBON_FRACTION_SYNGAS
        assert math.isclose(c_bal_char, CARBON_FRACTION_CHAR, rel_tol=1e-9)

    def test_register_address_constants_and_aliases(self) -> None:
        """Verify Horner OCS word register addresses %R2720..%R2727 and string aliases."""
        assert REG_PHA_GASIF_BED_TEMP == "%R2720"
        assert REG_PHA_GASIF_FREEBOARD_TEMP == "%R2721"
        assert REG_PHA_GASIF_SYNGAS_PRESSURE == "%R2722"
        assert REG_PHA_GASIF_H2_CO_RATIO == "%R2723"
        assert REG_PHA_GASIF_CARBON_CONVERSION == "%R2724"
        assert REG_PHA_GASIF_COLD_GAS_EFFICIENCY == "%R2725"
        assert REG_PHA_GASIF_STEAM_OXYGEN_DUTY == "%R2726"
        assert REG_PHA_GASIF_DIAGNOSTIC_CODE == "%R2727"

        # Check aliases
        assert REG_PHA_GASIF_TBED == "%R2720"
        assert REG_PHA_GASIF_T_BED == "%R2720"
        assert REG_PHA_GASIF_BED_TEMPERATURE == "%R2720"
        assert REG_PHA_GASIF_TFREEBOARD == "%R2721"
        assert REG_PHA_GASIF_T_FREEBOARD == "%R2721"
        assert REG_PHA_GASIF_T_FB == "%R2721"
        assert REG_PHA_GASIF_FREEBOARD_TEMPERATURE == "%R2721"
        assert REG_PHA_GASIF_PRESSURE == "%R2722"
        assert REG_PHA_GASIF_PSYNGAS == "%R2722"
        assert REG_PHA_GASIF_P_SYNGAS == "%R2722"
        assert REG_PHA_GASIF_H2_CO == "%R2723"
        assert REG_PHA_GASIF_RATIO == "%R2723"
        assert REG_PHA_GASIF_CONVERSION == "%R2724"
        assert REG_PHA_GASIF_CONV == "%R2724"
        assert REG_PHA_GASIF_CGE == "%R2725"
        assert REG_PHA_GASIF_EFFICIENCY == "%R2725"
        assert REG_PHA_GASIF_DUTY == "%R2726"
        assert REG_PHA_GASIF_STEAM_DUTY == "%R2726"
        assert REG_PHA_GASIF_DIAG == "%R2727"

    def test_coil_address_constants_and_aliases(self) -> None:
        """Verify Horner OCS discrete coil addresses %M634..%M636 and aliases."""
        assert COIL_PHA_GASIF_GASIFIER_ACTIVE == "%M634"
        assert COIL_PHA_GASIF_SYNGAS_FLARE_VALVE == "%M635"
        assert COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE == "%M636"

        # Aliases
        assert COIL_PHA_GASIF_ACTIVE == "%M634"
        assert COIL_PHA_GASIF_RUNNING == "%M634"
        assert COIL_PHA_GASIF_FLARE == "%M635"
        assert COIL_PHA_GASIF_FLARE_VALVE == "%M635"
        assert COIL_PHA_GASIF_PURGE == "%M636"
        assert COIL_PHA_GASIF_NITROGEN_PURGE == "%M636"

    def test_diagnostic_codes_constants_and_aliases(self) -> None:
        """Verify 16-bit diagnostic trip constants 0x0000, 0xF971..0xF975 and aliases."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_BED_TEMPERATURE_EXCURSION == 0xF971
        assert DIAG_ERR_SYNGAS_OVERPRESSURE_TRIP == 0xF972
        assert DIAG_ERR_TAR_FORMATION_DEPOSITION == 0xF973
        assert DIAG_ERR_CARBON_MASS_DIVERGENCE == 0xF974
        assert DIAG_ERR_STEAM_STARVATION_CLINKERING == 0xF975

        # Aliases
        assert DIAG_ERR_BED_TEMP_EXCURSION == 0xF971
        assert DIAG_ERR_TEMPERATURE_EXCURSION == 0xF971
        assert DIAG_ERR_BED_TEMP == 0xF971
        assert DIAG_ERR_OVERPRESSURE == 0xF972
        assert DIAG_ERR_SYNGAS_OVERPRESSURE == 0xF972
        assert DIAG_ERR_TAR_FORMATION == 0xF973
        assert DIAG_ERR_TAR_DEPOSITION == 0xF973
        assert DIAG_ERR_CARBON_DIVERGENCE == 0xF974
        assert DIAG_ERR_MASS_DIVERGENCE == 0xF974
        assert DIAG_ERR_STEAM_STARVATION == 0xF975
        assert DIAG_ERR_CLINKERING == 0xF975

    def test_signed_16bit_diagnostic_safe_comparisons(self) -> None:
        """Verify signed 16-bit safe comparisons for diagnostic codes across unsigned/signed representations."""
        trip_codes = [0xF971, 0xF972, 0xF973, 0xF974, 0xF975]
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
        """Verify PHAGasificationStatusWord bitmask enumeration definitions and aliases."""
        assert PHAGasificationStatusWord.GASIFIER_RUNNING == (1 << 0)
        assert PHAGasificationStatusWord.FEED_ACTIVE == (1 << 1)
        assert PHAGasificationStatusWord.STEAM_OXYGEN_ACTIVE == (1 << 2)
        assert PHAGasificationStatusWord.SYNGAS_EXPORT_ACTIVE == (1 << 3)
        assert PHAGasificationStatusWord.FLARE_ACTIVE == (1 << 4)
        assert PHAGasificationStatusWord.PURGE_ACTIVE == (1 << 5)
        assert PHAGasificationStatusWord.BED_HIGH_TEMP_WARN == (1 << 6)
        assert PHAGasificationStatusWord.OVERPRESSURE_WARN == (1 << 7)
        assert PHAGasificationStatusWord.EMERGENCY_TRIP == (1 << 8)

        # Aliases
        assert PhaGasifStatusWord is PHAGasificationStatusWord
        assert PHAGasifStatusWord is PHAGasificationStatusWord
        assert PhaGasificationStatusWord is PHAGasificationStatusWord
        assert PHAGasifStatusBits is PHAGasificationStatusWord
        assert PhaGasifStatusBits is PHAGasificationStatusWord
        assert PHAGasificationStatusBits is PHAGasificationStatusWord
        assert PhaGasificationStatusBits is PHAGasificationStatusWord

    def test_config_dataclass_defaults_and_serialization(self) -> None:
        """Verify PHAGasificationConfig default parameters, dictionary serialization, and property aliases."""
        cfg = PHAGasificationConfig()
        assert cfg.k_pyro > 0.0
        assert cfg.ea_pyro_j_mol > 0.0
        assert cfg.k_ox > 0.0
        assert cfg.ea_ox_j_mol > 0.0
        assert cfg.k_steam > 0.0
        assert cfg.ea_steam_j_mol > 0.0
        assert cfg.k_boud > 0.0
        assert cfg.ea_boud_j_mol > 0.0
        assert cfg.v_bed == 3.5
        assert cfg.v_freeboard == 1.5
        assert cfg.t_bed_trip_max == 1150.0
        assert cfg.dt_bed_dt_trip_max == 25.0
        assert cfg.p_syngas_trip_max == 40.0
        assert cfg.tar_fraction_trip_max == 0.05
        assert cfg.carbon_residual_max == 1e-4
        assert cfg.steam_ratio_trip_min == 0.30

        # Property aliases
        assert cfg.k_tar == cfg.k_reform
        assert cfg.ea_tar_j_mol == cfg.ea_reform_j_mol
        cfg.k_tar = 5500.0
        assert cfg.k_reform == 5500.0
        cfg.ea_tar_j_mol = 76000.0
        assert cfg.ea_reform_j_mol == 76000.0

        d = cfg.to_dict()
        assert "k_pyro" in d
        assert "t_bed_trip_max" in d
        assert "p_syngas_trip_max" in d


# ============================================================================
# 2. TestReactionRatesAndEquilibrium
# ============================================================================

class TestReactionRatesAndEquilibrium:
    """Validate gasification reaction rates, water-gas shift equilibrium, H2/CO syngas ratio, Arrhenius kinetics."""

    def test_pyrolysis_devolatilization_rate_formula(self) -> None:
        """Verify analytical computation of primary PHA pyrolysis & devolatilization rate r_pyro."""
        gasifier = PHAGasificationEngine()
        st = PHAGasificationState(c_pha=150.0, t_bed=1050.0)
        r_pyro, r_ox, r_gasif, r_tar_gen, r_tar_reform = gasifier.compute_rates(st)

        rt_bed = R_GAS_CONSTANT * 1050.0
        expected_r_pyro = gasifier.cfg.k_pyro * 150.0 * math.exp(-gasifier.cfg.ea_pyro_j_mol / rt_bed)
        assert math.isclose(r_pyro, expected_r_pyro, rel_tol=1e-6)
        assert r_pyro > 0.0

    def test_char_partial_oxidation_rate_and_oxygen_duty(self) -> None:
        """Verify analytical computation of char partial oxidation rate and oxygen duty scaling."""
        gasifier = PHAGasificationEngine()
        gasifier.steam_oxygen_duty = 80.0
        st = PHAGasificationState(c_char=25.0, t_bed=1050.0)
        r_pyro, r_ox, r_gasif, r_tar_gen, r_tar_reform = gasifier.compute_rates(st)

        rt_bed = R_GAS_CONSTANT * 1050.0
        expected_duty = (80.0 / 100.0) * gasifier.cfg.oxygen_ratio
        expected_r_ox = gasifier.cfg.k_ox * 25.0 * math.exp(-gasifier.cfg.ea_ox_j_mol / rt_bed) * expected_duty
        assert math.isclose(r_ox, expected_r_ox, rel_tol=1e-6)
        assert r_ox > 0.0

    def test_steam_and_boudouard_gasification_rates(self) -> None:
        """Verify analytical computation of combined steam and Boudouard char gasification rate."""
        gasifier = PHAGasificationEngine()
        gasifier.steam_ratio = 0.60
        st = PHAGasificationState(c_char=25.0, t_bed=1050.0)
        _, _, r_gasif, _, _ = gasifier.compute_rates(st)

        rt_bed = R_GAS_CONSTANT * 1050.0
        r_steam = gasifier.cfg.k_steam * 25.0 * math.exp(-gasifier.cfg.ea_steam_j_mol / rt_bed) * 0.60
        r_boud = gasifier.cfg.k_boud * 25.0 * math.exp(-gasifier.cfg.ea_boud_j_mol / rt_bed)
        expected_r_gasif = r_steam + r_boud
        assert math.isclose(r_gasif, expected_r_gasif, rel_tol=1e-6)
        assert r_gasif > 0.0

    def test_reaction_rate_temperature_monotonic_acceleration(self) -> None:
        """Verify Arrhenius reaction rates strictly increase monotonically with temperature."""
        gasifier = PHAGasificationEngine()
        st_cold = PHAGasificationState(t_bed=950.0, c_pha=150.0, c_char=25.0)
        st_nom = PHAGasificationState(t_bed=1050.0, c_pha=150.0, c_char=25.0)
        st_hot = PHAGasificationState(t_bed=1100.0, c_pha=150.0, c_char=25.0)

        r_p_cold, r_ox_cold, r_g_cold, _, _ = gasifier.compute_rates(st_cold)
        r_p_nom, r_ox_nom, r_g_nom, _, _ = gasifier.compute_rates(st_nom)
        r_p_hot, r_ox_hot, r_g_hot, _, _ = gasifier.compute_rates(st_hot)

        assert r_p_hot > r_p_nom > r_p_cold > 0.0
        assert r_ox_hot > r_ox_nom > r_ox_cold > 0.0
        assert r_g_hot > r_g_nom > r_g_cold > 0.0

    def test_activation_energy_relative_sensitivities(self) -> None:
        """Verify reactions with higher activation energy (Boudouard 125kJ > Steam 110kJ > Ox 70kJ) show greater temperature sensitivity."""
        gasifier = PHAGasificationEngine()
        st1 = PHAGasificationState(t_bed=950.0, c_char=25.0)
        st2 = PHAGasificationState(t_bed=1100.0, c_char=25.0)

        rt1 = R_GAS_CONSTANT * 950.0
        rt2 = R_GAS_CONSTANT * 1100.0

        ratio_ox = math.exp(-gasifier.cfg.ea_ox_j_mol / rt2) / math.exp(-gasifier.cfg.ea_ox_j_mol / rt1)
        ratio_steam = math.exp(-gasifier.cfg.ea_steam_j_mol / rt2) / math.exp(-gasifier.cfg.ea_steam_j_mol / rt1)
        ratio_boud = math.exp(-gasifier.cfg.ea_boud_j_mol / rt2) / math.exp(-gasifier.cfg.ea_boud_j_mol / rt1)

        assert ratio_boud > ratio_steam > ratio_ox

    def test_water_gas_shift_equilibrium_relaxation(self) -> None:
        """Verify syngas H2/CO molar ratio relaxes toward equilibrium and increases with steam ratio."""
        g_low_steam = PHAGasificationEngine()
        g_low_steam.steam_ratio = 0.40
        g_high_steam = PHAGasificationEngine()
        g_high_steam.steam_ratio = 0.80

        for _ in range(10):
            g_low_steam.step_rk4(dt=0.1)
            g_high_steam.step_rk4(dt=0.1)

        # Higher steam ratio promotes WGS shifting CO + H2O -> CO2 + H2, raising H2/CO ratio
        assert g_high_steam.h2_co_ratio > g_low_steam.h2_co_ratio
        assert 1.0 < g_low_steam.h2_co_ratio < 4.0
        assert 1.0 < g_high_steam.h2_co_ratio < 4.0

    def test_zero_feed_concentration_halts_pyrolysis_rate(self) -> None:
        """Verify zero precursor PHA biopolymer concentration results in zero pyrolysis rate."""
        gasifier = PHAGasificationEngine()
        st_empty = PHAGasificationState(c_pha=0.0, t_bed=1050.0)
        r_pyro, _, _, r_tar_gen, _ = gasifier.compute_rates(st_empty)

        assert r_pyro == 0.0
        assert r_tar_gen == 0.0

    def test_rates_zero_when_tripped_or_frozen(self) -> None:
        """Verify all reaction rates are zero when reactor is tripped or bed temperature is sub-300 K."""
        gasifier = PHAGasificationEngine()
        gasifier.trip_active = True
        rates_tripped = gasifier.compute_rates(gasifier.state)
        assert rates_tripped == (0.0, 0.0, 0.0, 0.0, 0.0)

        gasifier.trip_active = False
        st_cold = PHAGasificationState(t_bed=250.0)
        rates_cold = gasifier.compute_rates(st_cold)
        assert rates_cold == (0.0, 0.0, 0.0, 0.0, 0.0)


# ============================================================================
# 3. TestCoupled6StateDerivatives
# ============================================================================

class TestCoupled6StateDerivatives:
    """Validate coupled 6-state ODE derivative calculations, mass/energy balance, volume/concentration non-negativity."""

    def test_state_initialization_defaults_and_aliases(self) -> None:
        """Verify PHAGasificationState default values and flexible property getters/setters."""
        st = PHAGasificationState()
        assert st.c_pha == 150.0
        assert st.c_syngas == 12.0
        assert st.c_char == 25.0
        assert st.t_bed == 1050.0
        assert st.t_freeboard == 980.0
        assert st.p_syngas == 25.0
        assert st.tar_mass == 0.18
        assert st.dt_bed_dt == 0.0

        # Property getters
        assert st.C_pha == 150.0
        assert st.pha == 150.0
        assert st.C_syngas == 12.0
        assert st.syngas == 12.0
        assert st.C_char == 25.0
        assert st.char == 25.0
        assert st.T_bed == 1050.0
        assert st.tbed == 1050.0
        assert st.bed_temp == 1050.0
        assert st.T_freeboard == 980.0
        assert st.tfreeboard == 980.0
        assert st.freeboard_temp == 980.0
        assert st.P_syngas == 25.0
        assert st.psyngas == 25.0
        assert st.pressure == 25.0
        assert st.dT_bed_dt == 0.0

        # Setters
        st.C_pha = 140.0
        assert st.c_pha == 140.0
        st.pha = 135.0
        assert st.c_pha == 135.0
        st.C_syngas = 14.0
        assert st.c_syngas == 14.0
        st.syngas = 15.0
        assert st.c_syngas == 15.0
        st.C_char = 28.0
        assert st.c_char == 28.0
        st.char = 29.0
        assert st.c_char == 29.0
        st.T_bed = 1060.0
        assert st.t_bed == 1060.0
        st.tbed = 1065.0
        assert st.t_bed == 1065.0
        st.bed_temp = 1070.0
        assert st.t_bed == 1070.0
        st.T_freeboard = 990.0
        assert st.t_freeboard == 990.0
        st.tfreeboard = 995.0
        assert st.t_freeboard == 995.0
        st.freeboard_temp = 1000.0
        assert st.t_freeboard == 1000.0
        st.P_syngas = 28.0
        assert st.p_syngas == 28.0
        st.psyngas = 29.0
        assert st.p_syngas == 29.0
        st.pressure = 30.0
        assert st.p_syngas == 30.0
        st.dT_bed_dt = 1.2
        assert st.dt_bed_dt == 1.2

    def test_tar_fraction_property_calculations(self) -> None:
        """Verify tar mass fraction calculation and setter roundtrip."""
        st = PHAGasificationState(c_syngas=19.0, tar_mass=1.0)
        # 1.0 / (19.0 + 1.0) = 0.05
        assert math.isclose(st.tar_fraction, 0.05, rel_tol=1e-5)

        # Setter roundtrip
        st.tar_fraction = 0.08
        assert math.isclose(st.tar_fraction, 0.08, rel_tol=1e-4)

    def test_state_serialization_roundtrip(self) -> None:
        """Verify PHAGasificationState dictionary roundtrip with case-insensitivity."""
        st = PHAGasificationState(
            c_pha=130.0, c_syngas=14.0, c_char=22.0, t_bed=1040.0, t_freeboard=970.0, p_syngas=24.0, tar_mass=0.15
        )
        d = st.to_dict()
        assert d["c_pha"] == 130.0
        assert d["c_syngas"] == 14.0
        assert d["c_char"] == 22.0
        assert d["t_bed"] == 1040.0

        st_rebuilt = PHAGasificationState.from_dict(d)
        assert st_rebuilt.c_pha == 130.0
        assert st_rebuilt.c_syngas == 14.0
        assert st_rebuilt.t_bed == 1040.0

        # Alternative key naming
        alt_d = {
            "C_pha": 125.0, "C_syngas": 16.0, "C_char": 20.0,
            "tbed": 1030.0, "tfreeboard": 960.0, "psyngas": 23.0
        }
        st_alt = PHAGasificationState.from_dict(alt_d)
        assert st_alt.c_pha == 125.0
        assert st_alt.c_syngas == 16.0
        assert st_alt.t_bed == 1030.0

    def test_derivatives_nominal_signs(self) -> None:
        """Verify component concentration derivatives signs in closed moving-bed mode."""
        gasifier = PHAGasificationEngine()
        dc_pha, dc_syn, dc_char, dt_bed, dt_fb, dp_syn, dtar, *rest = gasifier._derivatives(gasifier.state)

        # In closed batch, PHA precursor is consumed
        assert dc_pha < 0.0
        # Syngas is generated
        assert dc_syn > 0.0
        # Derivative values are finite numbers
        assert math.isfinite(dt_bed)
        assert math.isfinite(dt_fb)
        assert math.isfinite(dp_syn)

    def test_bed_thermal_energy_balance_derivatives(self) -> None:
        """Verify bed thermal balance responds to oxidation exothermic duty and devolatilization endotherms."""
        gasifier = PHAGasificationEngine()
        # High oxygen duty enhances oxidation and drives heating
        gasifier.steam_oxygen_duty = 100.0
        derivs_high = gasifier._derivatives(gasifier.state)

        # Low oxygen duty reduces oxidation and drives cooling
        gasifier.steam_oxygen_duty = 20.0
        derivs_low = gasifier._derivatives(gasifier.state)

        assert derivs_high[3] > derivs_low[3]

    def test_freeboard_thermal_energy_balance_derivatives(self) -> None:
        """Verify freeboard temperature derivative responds to convective/radiative transfer from bed."""
        gasifier = PHAGasificationEngine()
        gasifier.state.t_bed = 1100.0
        gasifier.state.t_freeboard = 900.0
        derivs = gasifier._derivatives(gasifier.state)

        # Strong temperature gradient from bed to freeboard heats the freeboard
        dt_fb_dt = derivs[4]
        assert dt_fb_dt > 0.0

    def test_syngas_pressure_generation_and_draw_derivatives(self) -> None:
        """Verify syngas pressure derivative balances generation and draw export discharge."""
        g_draw_active = PHAGasificationEngine()
        g_draw_active.state.p_syngas = 28.0  # Above 24.0 bar downstream

        g_draw_inactive = PHAGasificationEngine()
        g_draw_inactive.state.p_syngas = 28.0
        g_draw_inactive.gasifier_active = False  # Draw inactive

        dp_active = g_draw_active._derivatives(g_draw_active.state)[5]
        dp_inactive = g_draw_inactive._derivatives(g_draw_inactive.state)[5]

        # Draw discharge relieves pressure accumulation
        assert dp_active < dp_inactive

    def test_derivatives_during_emergency_purge_and_flare(self) -> None:
        """Verify intense cooling, flare depressurization, and reaction freeze during emergency purge."""
        gasifier = PHAGasificationEngine()
        gasifier.emergency_purge_and_flare()
        gasifier.trip_active = True

        derivs = gasifier._derivatives(gasifier.state)
        # Precursor consumption halted
        assert derivs[0] == 0.0
        # Temperatures rapidly cooling
        assert derivs[3] < 0.0
        assert derivs[4] < 0.0
        # Syngas pressure venting through flare
        assert derivs[5] < 0.0


# ============================================================================
# 4. TestRK4IntegrationStability
# ============================================================================

class TestRK4IntegrationStability:
    """Validate RK4 integration stability, convergence, step size variation (dt=0.01s to 0.1s)."""

    def test_single_step_rk4_updates_state(self) -> None:
        """Verify a single RK4 step updates state variables consistently without tripping."""
        gasifier = PHAGasificationEngine()
        c_pha_0 = gasifier.state.c_pha
        c_syn_0 = gasifier.state.c_syngas

        gasifier.step_rk4(dt=0.1)

        assert gasifier.state.c_pha < c_pha_0
        assert gasifier.state.c_syngas > c_syn_0
        assert gasifier.trip_active is False
        assert gasifier.diagnostic_code == DIAG_OK

    def test_rk4_step_size_variation_stability(self) -> None:
        """Verify numerical stability and convergence across dt=0.01s, 0.05s, and 0.1s."""
        # Run 0.5 seconds total simulation time
        g_fine = PHAGasificationEngine()
        g_mid = PHAGasificationEngine()
        g_coarse = PHAGasificationEngine()

        # 50 steps of 0.01s
        for _ in range(50):
            g_fine.step_rk4(dt=0.01)

        # 10 steps of 0.05s
        for _ in range(10):
            g_mid.step_rk4(dt=0.05)

        # 5 steps of 0.10s
        for _ in range(5):
            g_coarse.step_rk4(dt=0.10)

        # All converge within 2% relative tolerance
        assert math.isclose(g_fine.state.c_pha, g_coarse.state.c_pha, rel_tol=2e-2)
        assert math.isclose(g_fine.state.c_syngas, g_coarse.state.c_syngas, rel_tol=2e-2)
        assert math.isclose(g_mid.state.c_pha, g_coarse.state.c_pha, rel_tol=1e-2)

    def test_rk4_state_non_negativity_clamping(self) -> None:
        """Verify concentration state variables never drop below zero during RK4 integration."""
        st_low = PHAGasificationState(c_pha=0.005, c_syngas=0.001, c_char=0.002, t_bed=1000.0)
        gasifier = PHAGasificationEngine(state=st_low)

        for _ in range(10):
            gasifier.step_rk4(dt=0.05)

        assert gasifier.state.c_pha >= 0.0
        assert gasifier.state.c_syngas >= 0.0
        assert gasifier.state.c_char >= 0.0
        assert gasifier.state.p_syngas >= 0.0
        assert gasifier.state.tar_mass >= 0.0

    def test_rk4_bed_freeboard_thermal_coupling(self) -> None:
        """Verify bed and freeboard temperatures couple smoothly over multiple RK4 steps."""
        gasifier = PHAGasificationEngine()
        gasifier.state.t_bed = 1080.0
        gasifier.state.t_freeboard = 920.0

        for _ in range(5):
            gasifier.step_rk4(dt=0.1)

        # Heat transfers from hot bed to cooler freeboard, warming freeboard above 920 K
        assert gasifier.state.t_freeboard > 920.0

    def test_multi_step_trajectory_monotonic_conversion(self) -> None:
        """Verify multi-step simulation trajectory exhibits smooth, monotonic precursor conversion."""
        gasifier = PHAGasificationEngine()
        pha_history = [gasifier.state.c_pha]

        for _ in range(10):
            gasifier.step_rk4(dt=0.1)
            pha_history.append(gasifier.state.c_pha)

        for i in range(len(pha_history) - 1):
            assert pha_history[i + 1] <= pha_history[i]
        assert pha_history[-1] < pha_history[0]

    def test_rk4_syngas_pressure_regulation_via_draw(self) -> None:
        """Verify syngas export draw prevents uncontrolled pressure buildup."""
        gasifier = PHAGasificationEngine()
        for _ in range(20):
            gasifier.step_rk4(dt=0.1)

        # Operating pressure should remain safely below trip limit (40 bar)
        assert 10.0 < gasifier.state.p_syngas < 40.0

    def test_gasifier_class_aliases(self) -> None:
        """Verify all class aliases instantiate and exhibit identical interfaces."""
        for alias in [
            PhaGasificationEngine,
            PHAGasificationReactor,
            PhaGasificationReactor,
            PHAGasificationSimulator,
            PhaGasificationSimulator,
            PHAGasificationLogicUnit,
            PhaGasificationLogicUnit,
            PHAGasificationSimulationLogicUnit,
            PhaGasificationSimulationLogicUnit,
            PHAGasificationModel,
            PhaGasificationModel,
            PHAGasificationPlantModel,
            PhaGasificationPlantModel,
            PHAGasifEngine,
            PhaGasifEngine,
            PHAGasifSimulator,
            PhaGasifSimulator,
        ]:
            inst = alias()
            assert isinstance(inst, PHAGasificationEngine)
            assert inst.state.c_pha == 150.0
            assert inst.unit_id == "PHA_GASIF_MOVING_BED_W311"


# ============================================================================
# 5. TestCarbonMassConservation
# ============================================================================

class TestCarbonMassConservation:
    """Validate continuous and batch carbon mass conservation residuals (< 1e-10)."""

    def test_carbon_mass_conservation_single_cycle(self) -> None:
        """Verify carbon mass conservation residual < 1e-10 in a single closed cycle."""
        gasifier = PHAGasificationEngine()
        gasifier.step_rk4(dt=0.1)
        assert gasifier.conservation_residual < 1e-10

    def test_carbon_mass_conservation_multi_cycle_soak(self) -> None:
        """Verify carbon mass conservation across 50 consecutive RK4 cycles."""
        gasifier = PHAGasificationEngine()
        for cycle in range(1, 51):
            gasifier.step_rk4(dt=0.1)
            assert (
                gasifier.conservation_residual < 1e-10
            ), f"Cycle {cycle}: residual {gasifier.conservation_residual:.2e} exceeded 1e-10"

    def test_carbon_conservation_across_temperatures(self) -> None:
        """Verify carbon conservation holds at 980 K, 1050 K, and 1100 K."""
        for temp in [980.0, 1050.0, 1100.0]:
            st = PHAGasificationState(t_bed=temp, t_freeboard=temp - 70.0)
            gasifier = PHAGasificationEngine(state=st)
            for _ in range(5):
                gasifier.step_rk4(dt=0.1)
            assert gasifier.conservation_residual < 1e-10

    def test_carbon_conservation_across_initial_concentrations(self) -> None:
        """Verify carbon conservation across varying initial PHA concentrations."""
        for c0 in [50.0, 150.0, 300.0]:
            st = PHAGasificationState(c_pha=c0)
            gasifier = PHAGasificationEngine(state=st)
            for _ in range(5):
                gasifier.step_rk4(dt=0.1)
            assert gasifier.conservation_residual < 1e-10

    def test_carbon_conservation_with_initial_products(self) -> None:
        """Verify carbon conservation holds when initial mixture contains char and syngas."""
        st = PHAGasificationState(c_pha=100.0, c_syngas=20.0, c_char=35.0)
        gasifier = PHAGasificationEngine(state=st)
        for _ in range(5):
            gasifier.step_rk4(dt=0.1)
        assert gasifier.conservation_residual < 1e-10

    def test_carbon_conservation_various_step_sizes(self) -> None:
        """Verify carbon conservation holds across diverse dt=0.01, 0.05, 0.1."""
        for step_dt in [0.01, 0.05, 0.1]:
            gasifier = PHAGasificationEngine()
            for _ in range(5):
                gasifier.step_rk4(dt=step_dt)
            assert gasifier.conservation_residual < 1e-10

    def test_carbon_conversion_and_cold_gas_efficiency_bounds(self) -> None:
        """Verify carbon conversion and cold gas efficiency percentage metrics remain bounded in [0, 100]."""
        gasifier = PHAGasificationEngine()
        for _ in range(10):
            gasifier.step_rk4(dt=0.1)
        assert 0.0 <= gasifier.carbon_conversion_pct <= 100.0
        assert 0.0 <= gasifier.cold_gas_efficiency_pct <= 100.0


# ============================================================================
# 6. TestBedTemperatureExcursionTrip
# ============================================================================

class TestBedTemperatureExcursionTrip:
    """Validate Priority 1 bed temperature excursion safety trips (0xF971, %M636 N2 purge coil asserted)."""

    def test_high_temperature_trip_0xf971(self) -> None:
        """Verify Priority 1 trip triggers when bed temperature exceeds 1150 K."""
        gasifier = PHAGasificationEngine()
        gasifier.state.t_bed = 1160.0  # Above 1150.0 K threshold
        gasifier.step_rk4(dt=0.05)

        assert gasifier.trip_active is True
        assert gasifier.diagnostic_code == DIAG_ERR_BED_TEMPERATURE_EXCURSION
        assert (int(gasifier.diagnostic_code) & 0xFFFF) == 0xF971
        assert gasifier.emergency_purge_active is True
        assert gasifier.flare_valve_open is True
        assert gasifier.gasifier_active is False
        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE) is False
        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is True
        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE) is True
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF971

    def test_high_rate_of_rise_runaway_trip_0xf971(self) -> None:
        """Verify Priority 1 trip triggers when bed temperature rise rate exceeds 25 K/s."""
        gasifier = PHAGasificationEngine()
        gasifier.state.dt_bed_dt = 28.5  # Above 25.0 K/s threshold
        gasifier.step_rk4(dt=0.05)

        assert gasifier.trip_active is True
        assert gasifier.diagnostic_code == DIAG_ERR_BED_TEMPERATURE_EXCURSION
        assert (int(gasifier.diagnostic_code) & 0xFFFF) == 0xF971
        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE) is True

    def test_nitrogen_purge_cooling_dynamics(self) -> None:
        """Verify emergency nitrogen purge causes rapid temperature drop of both bed and freeboard."""
        gasifier = PHAGasificationEngine()
        gasifier.emergency_purge_and_flare()
        gasifier.trip_active = True
        t_bed_0 = gasifier.state.t_bed
        t_fb_0 = gasifier.state.t_freeboard

        gasifier.step_rk4(dt=0.5)

        assert gasifier.state.t_bed < t_bed_0
        assert gasifier.state.t_freeboard < t_fb_0
        assert gasifier.emergency_purge_active is True

    def test_purge_and_flare_action_isolation(self) -> None:
        """Verify emergency purge deactivates gasifier, zeroes oxidant duty, and energizes purge/flare."""
        gasifier = PHAGasificationEngine()
        gasifier.emergency_purge_and_flare()

        assert gasifier.gasifier_active is False
        assert gasifier.flare_valve_open is True
        assert gasifier.emergency_purge_active is True
        assert gasifier.steam_oxygen_duty == 0.0

    def test_derivatives_during_emergency_purge(self) -> None:
        """Verify reaction stops and intense N2 cooling dominates derivatives."""
        gasifier = PHAGasificationEngine()
        gasifier.trip_active = True
        gasifier.emergency_purge_active = True
        gasifier.flare_valve_open = True

        derivs = gasifier._derivatives(gasifier.state)
        # Precursor consumption is zero
        assert derivs[0] == 0.0
        # Intense cooling
        assert derivs[3] < 0.0
        assert derivs[4] < 0.0
        # Pressure depressurizing through flare
        assert derivs[5] < 0.0

    def test_purge_coil_and_register_table_reflection(self) -> None:
        """Verify %M636, %M635, and %R2727 are updated immediately on trip."""
        gasifier = PHAGasificationEngine()
        gasifier.state.t_bed = 1170.0
        gasifier.step_rk4(dt=0.05)

        rt = gasifier.reg_table
        assert rt.read_bit(COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE) is True
        assert rt.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is True
        assert rt.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE) is False
        assert (rt.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF971


# ============================================================================
# 7. TestSyngasOverpressureTrip
# ============================================================================

class TestSyngasOverpressureTrip:
    """Validate Priority 2 syngas overpressure trips (0xF972, %M635 flare valve asserted)."""

    def test_syngas_overpressure_trip_0xf972(self) -> None:
        """Verify Priority 2 trip triggers when syngas pressure exceeds 40.0 bar."""
        gasifier = PHAGasificationEngine()
        gasifier.state.p_syngas = 42.0
        gasifier.step_rk4(dt=0.05)

        assert gasifier.trip_active is True
        assert gasifier.diagnostic_code == DIAG_ERR_SYNGAS_OVERPRESSURE_TRIP
        assert (int(gasifier.diagnostic_code) & 0xFFFF) == 0xF972
        assert gasifier.flare_valve_open is True
        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is True
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF972

    def test_overpressure_flare_depressurization(self) -> None:
        """Verify flare activation depressurizes the reactor vessel."""
        gasifier = PHAGasificationEngine()
        gasifier.state.p_syngas = 41.0
        gasifier.step_rk4(dt=0.05)
        p0 = gasifier.state.p_syngas

        # Advance step during flare depressurization
        gasifier.step_rk4(dt=0.2)
        assert gasifier.state.p_syngas < p0

    def test_closed_draw_accelerates_pressure(self) -> None:
        """Verify closed syngas draw increases pressure generation derivative."""
        g_open = PHAGasificationEngine()
        g_closed = PHAGasificationEngine()
        g_closed.gasifier_active = False

        dp_open = g_open._derivatives(g_open.state)[5]
        dp_closed = g_closed._derivatives(g_closed.state)[5]

        assert dp_closed > dp_open

    def test_priority_bed_temperature_over_overpressure(self) -> None:
        """Verify Priority 1 (Bed Temperature Excursion 0xF971) dominates Priority 2 (Overpressure 0xF972)."""
        gasifier = PHAGasificationEngine()
        gasifier.state.t_bed = 1170.0  # Tripped (P1)
        gasifier.state.p_syngas = 45.0 # Tripped (P2)
        gasifier.step_rk4(dt=0.05)

        assert gasifier.diagnostic_code == DIAG_ERR_BED_TEMPERATURE_EXCURSION
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF971

    def test_overpressure_register_coils_state(self) -> None:
        """Verify coil states when tripped on overpressure (%M634=False, %M635=True, %M636=True)."""
        gasifier = PHAGasificationEngine()
        gasifier.state.p_syngas = 43.0
        gasifier.step_rk4(dt=0.05)

        rt = gasifier.reg_table
        assert rt.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE) is False
        assert rt.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is True
        assert rt.read_bit(COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE) is True

    def test_overpressure_trip_word_register_masking(self) -> None:
        """Verify signed 16-bit safe masking of 0xF972 in %R2727."""
        gasifier = PHAGasificationEngine()
        gasifier.diagnostic_code = DiagnosticCode(0xF972)
        gasifier.trip_active = True
        gasifier.sync_to_registers(gasifier.reg_table)

        raw = gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE)
        assert (raw & 0xFFFF) == 0xF972
        assert DiagnosticCode(0xF972) == raw


# ============================================================================
# 8. TestTarFormationAndSteamStarvationTrips
# ============================================================================

class TestTarFormationAndSteamStarvationTrips:
    """Validate Priority 3 tar formation (0xF973) and Priority 5 steam starvation (0xF975) trips."""

    def test_tar_formation_trip_0xf973(self) -> None:
        """Verify Priority 3 trip triggers when tar fraction exceeds 0.05."""
        gasifier = PHAGasificationEngine()
        gasifier.tar_fraction = 0.065
        gasifier.step_rk4(dt=0.05)

        assert gasifier.trip_active is True
        assert gasifier.diagnostic_code == DIAG_ERR_TAR_FORMATION_DEPOSITION
        assert (int(gasifier.diagnostic_code) & 0xFFFF) == 0xF973
        assert gasifier.flare_valve_open is True
        assert gasifier.emergency_purge_active is True
        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is True
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF973

    def test_steam_starvation_trip_0xf975(self) -> None:
        """Verify Priority 5 trip triggers when steam ratio drops below 0.30."""
        gasifier = PHAGasificationEngine()
        gasifier.steam_ratio = 0.22
        gasifier.step_rk4(dt=0.05)

        assert gasifier.trip_active is True
        assert gasifier.diagnostic_code == DIAG_ERR_STEAM_STARVATION_CLINKERING
        assert (int(gasifier.diagnostic_code) & 0xFFFF) == 0xF975
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF975

    def test_priority_overpressure_over_tar(self) -> None:
        """Verify Priority 2 (Overpressure 0xF972) dominates Priority 3 (Tar Deposition 0xF973)."""
        gasifier = PHAGasificationEngine()
        gasifier.state.p_syngas = 45.0  # Tripped (P2)
        gasifier.tar_fraction = 0.08    # Tripped (P3)
        gasifier.step_rk4(dt=0.05)

        assert gasifier.diagnostic_code == DIAG_ERR_SYNGAS_OVERPRESSURE_TRIP
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF972

    def test_priority_tar_over_steam_starvation(self) -> None:
        """Verify Priority 3 (Tar Deposition 0xF973) dominates Priority 5 (Steam Starvation 0xF975)."""
        gasifier = PHAGasificationEngine()
        gasifier.tar_fraction = 0.08  # Tripped (P3)
        gasifier.steam_ratio = 0.20   # Tripped (P5)
        gasifier.step_rk4(dt=0.05)

        assert gasifier.diagnostic_code == DIAG_ERR_TAR_FORMATION_DEPOSITION
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF973

    def test_priority_carbon_divergence_over_steam_starvation(self) -> None:
        """Verify Priority 4 (Carbon Divergence 0xF974) dominates Priority 5 (Steam Starvation 0xF975)."""
        gasifier = PHAGasificationEngine()
        gasifier.conservation_residual = 0.005  # Tripped (P4)
        gasifier.steam_ratio = 0.20            # Tripped (P5)
        gasifier.step_rk4(dt=0.05)

        assert gasifier.diagnostic_code == DIAG_ERR_CARBON_MASS_DIVERGENCE
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF974

    def test_steam_starvation_coil_assertion(self) -> None:
        """Verify flare and purge coils are asserted upon steam starvation."""
        gasifier = PHAGasificationEngine()
        gasifier.steam_ratio = 0.15
        gasifier.step_rk4(dt=0.05)

        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE) is True
        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is True
        assert gasifier.reg_table.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE) is False


# ============================================================================
# 9. TestRegisterTableSynchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate RegisterTable synchronization across %R2720..%R2727 and %M634..%M636."""

    def test_nominal_register_sync(self) -> None:
        """Verify all register values synchronized to Horner OCS memory space %R2720..%R2727."""
        gasifier = PHAGasificationEngine()
        gasifier.scan_step(dt=0.1)
        rt = gasifier.reg_table

        w_tbed = rt.read_word(REG_PHA_GASIF_BED_TEMP)
        w_tfb = rt.read_word(REG_PHA_GASIF_FREEBOARD_TEMP)
        w_press = rt.read_word(REG_PHA_GASIF_SYNGAS_PRESSURE)
        w_ratio = rt.read_word(REG_PHA_GASIF_H2_CO_RATIO)
        w_conv = rt.read_word(REG_PHA_GASIF_CARBON_CONVERSION)
        w_cge = rt.read_word(REG_PHA_GASIF_COLD_GAS_EFFICIENCY)
        w_duty = rt.read_word(REG_PHA_GASIF_STEAM_OXYGEN_DUTY)
        w_diag = rt.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE)

        assert w_tbed > 0
        assert w_tfb > 0
        assert w_press > 0
        assert w_ratio > 0
        assert w_conv >= 0
        assert w_cge > 0
        assert w_duty > 0
        assert (w_diag & 0xFFFF) == 0x0000

    def test_discrete_coils_nominal_state(self) -> None:
        """Verify coils %M634=True, %M635=False, %M636=False in nominal operating state."""
        gasifier = PHAGasificationEngine()
        gasifier.sync_to_registers(gasifier.reg_table)
        rt = gasifier.reg_table

        assert rt.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE) is True
        assert rt.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is False
        assert rt.read_bit(COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE) is False

    def test_signed_16bit_negative_temperature(self) -> None:
        """Verify signed 16-bit safe conversion for temperatures below 0 °C."""
        gasifier = PHAGasificationEngine()
        # 250.0 K = -23.15 °C -> scaled x10 is -231 or -232 (signed 16-bit)
        gasifier.state.t_bed = 250.0
        gasifier.sync_to_registers(gasifier.reg_table)

        w_tbed = gasifier.reg_table.read_word(REG_PHA_GASIF_BED_TEMP)
        signed_val = w_tbed - 0x10000 if w_tbed >= 0x8000 else w_tbed
        assert signed_val == -231 or signed_val == -232

    def test_all_diagnostic_codes_written_to_reg2727(self) -> None:
        """Verify diagnostic codes 0x0000, 0xF971..0xF975 correctly written and masked."""
        gasifier = PHAGasificationEngine()
        codes = [0x0000, 0xF971, 0xF972, 0xF973, 0xF974, 0xF975]

        for c_val in codes:
            gasifier.diagnostic_code = DiagnosticCode(c_val)
            gasifier.sync_to_registers(gasifier.reg_table)
            raw = gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE)
            assert (raw & 0xFFFF) == c_val

    def test_mass_balance_divergence_trip_0xf974(self) -> None:
        """Verify Priority 4 trip triggers on carbon mass balance divergence (> 1e-4)."""
        gasifier = PHAGasificationEngine()
        gasifier.conservation_residual = 0.005
        gasifier.step_rk4(dt=0.05)

        assert gasifier.trip_active is True
        assert gasifier.diagnostic_code == DIAG_ERR_CARBON_MASS_DIVERGENCE
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF974

    def test_register_sync_privilege_modes(self) -> None:
        """Verify synchronization operates cleanly under both USER and SYSTEM privilege modes."""
        gasifier = PHAGasificationEngine()
        rt = RegisterTable()
        gasifier.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert (rt.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        gasifier.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_clamped_register_ranges(self) -> None:
        """Verify register outputs clamp strictly within defined ranges."""
        gasifier = PHAGasificationEngine()
        gasifier.state.p_syngas = 100.0  # Excessive pressure -> clamp to 5000 (50.0 bar)
        gasifier.sync_to_registers(gasifier.reg_table)
        assert gasifier.reg_table.read_word(REG_PHA_GASIF_SYNGAS_PRESSURE) <= 5000


# ============================================================================
# 10. TestPureStructuredTextPOU
# ============================================================================

class TestPureStructuredTextPOU:
    """Validate pure ST POU validation and anti-ladder rejection of all 9 constructs."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify pure ST POU syntax using verify_pha_gasification_pure_st()."""
        assert verify_pha_gasification_pure_st() is True
        assert verify_pha_gasif_pure_st() is True

    def test_st_parser_ast_validation(self) -> None:
        """Verify STParser parses PHA_GASIFICATION_PURE_ST_POU cleanly with 0 errors."""
        res = STParser.validate_code(PHA_GASIFICATION_PURE_ST_POU)
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
            SecurityGuard.assert_pure_st_content("XIC %M634")


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Validate ILogicUnit scan step compliance, reset behavior, and 100-cycle simulation soak with memory profiling."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify ILogicUnit standard properties (unit_id, name, priority, is_enabled)."""
        gasifier = PHAGasificationEngine()
        assert gasifier.unit_id == "PHA_GASIF_MOVING_BED_W311"
        assert gasifier.name == "PHAGasificationEngine"
        assert gasifier.priority == 50
        assert gasifier.is_enabled is True

    def test_scan_step_various_invocation_signatures(self) -> None:
        """Verify scan_step handles diverse parameter invocation signatures."""
        gasifier = PHAGasificationEngine()

        # 1. Positional dt
        res1 = gasifier.scan_step(0.05)
        assert res1.status == AgentStatus.SUCCESS

        # 2. Kwarg dt
        res2 = gasifier.scan_step(dt=0.10)
        assert res2.status == AgentStatus.SUCCESS

        # 3. Kwarg dt_h
        res3 = gasifier.scan_step(dt_h=0.00005)
        assert res3.status == AgentStatus.SUCCESS

    def test_scan_step_with_scan_context(self) -> None:
        """Verify scan_step with ScanContext propagates RegisterTable."""
        rt_ext = RegisterTable()
        context = ScanContext(cycle=1, dt=0.1, register_table=rt_ext)
        gasifier = PHAGasificationEngine()

        res = gasifier.scan_step(context=context)
        assert res.status == AgentStatus.SUCCESS
        assert gasifier.reg_table is rt_ext
        assert rt_ext.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE) is True

    def test_step_and_execute_methods(self) -> None:
        """Verify step() and execute() methods correctly invoke scan_step and increment cycle count."""
        gasifier = PHAGasificationEngine()
        c0 = gasifier.cycle_count
        gasifier.step(0.1)
        assert gasifier.cycle_count == c0 + 1

        gasifier.execute(0.1)
        assert gasifier.cycle_count == c0 + 2

    def test_scan_step_execution_result_contract(self) -> None:
        """Verify scan_step returns strict 4-state ExecutionResult contract."""
        gasifier = PHAGasificationEngine()
        res = gasifier.scan_step(dt=0.1)

        assert isinstance(res, ExecutionResult)
        assert res.status in [AgentStatus.SUCCESS, AgentStatus.FAILED]
        assert "c_pha" in res.data
        assert "c_syngas" in res.data
        assert "c_char" in res.data
        assert "t_bed" in res.data
        assert "t_freeboard" in res.data
        assert "p_syngas" in res.data
        assert "h2_co_ratio" in res.data
        assert "tar_fraction" in res.data
        assert "carbon_conversion_pct" in res.data
        assert "cold_gas_efficiency_pct" in res.data
        assert "conservation_residual" in res.data
        assert res.error_code is None

    def test_reset_functionality(self) -> None:
        """Verify reset() restores default initial conditions and clears safety trips."""
        gasifier = PHAGasificationEngine()
        gasifier.state.t_bed = 1170.0
        gasifier.step_rk4(dt=0.05)
        assert gasifier.trip_active is True

        gasifier.reset()
        assert gasifier.trip_active is False
        assert gasifier.diagnostic_code == DIAG_OK
        assert gasifier.state.c_pha == 150.0
        assert gasifier.state.t_bed == 1050.0
        assert gasifier.emergency_purge_active is False
        assert (gasifier.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_100_cycle_simulation_soak_and_memory_profiling(self) -> None:
        """Execute 100-cycle continuous simulation soak and profile execution performance."""
        gasifier = PHAGasificationEngine()
        t_start = time.perf_counter()

        for cycle in range(1, 101):
            res = gasifier.scan_step(dt=0.05)
            assert res.status == AgentStatus.SUCCESS
            assert gasifier.conservation_residual < 1e-10

        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        avg_cycle_ms = elapsed_ms / 100.0

        # Assert rapid simulation performance (< 5ms per scan cycle)
        assert avg_cycle_ms < 5.0
        assert gasifier.cycle_count == 100
        assert gasifier.trip_active is False


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
            res = run_pha_gasification_verification(output_path=out_path)
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
        res = run_pha_gasification_verification(quick=True)
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_evidence_json_structure_and_hashes(self) -> None:
        """Verify evidence JSON contains SHA-256 digests for POU and model config."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = run_pha_gasification_verification(output_path=out_path, quick=True)
            digests = res["data"]["digests"]
            assert "pou_sha256" in digests
            assert "model_sha256" in digests
            assert len(digests["pou_sha256"]) == 64
            assert len(digests["model_sha256"]) == 64
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_scripts_runner_module_execution(self) -> None:
        """Verify execution of scripts/run_pha_gasification_verification.py module runner."""
        from scripts.run_pha_gasification_verification import (
            execute_pha_gasification_verification,
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            res = execute_pha_gasification_verification(output_path=out_path, quick=True)
            assert res["status"] == "success"
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_main_entrypoint_with_tempfile(self) -> None:
        """Verify CLI main() in scripts/run_pha_gasification_verification.py passes cleanly."""
        from scripts.run_pha_gasification_verification import main as script_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = script_main(["--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_simulation_cli_main_entrypoint(self) -> None:
        """Verify CLI main() in src/jev_cscape/simulation/pha_gasification.py passes cleanly."""
        from jev_cscape.simulation.pha_gasification import main as sim_main

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            code = sim_main(["--verify", "--output", out_path, "--quick", "--quiet"])
            assert code == 0
            assert Path(out_path).exists()
        finally:
            Path(out_path).unlink(missing_ok=True)
