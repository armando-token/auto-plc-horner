"""Industrial Polyhydroxyalkanoate Bio-Recycling & Depolymerization Unit Test Suite (W299).

Work Package: W299 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification sections:
1. Section 1: Model Initialization, Configuration & Parameter Validation
2. Section 2: Kinetic Parameters, Arrhenius Temperature Factors & Cleavage Mechanisms
3. Section 3: Coupled 6-State ODE Discretization, RK4 Integration & Continuous Simulation
4. Section 4: Energy & Volume Balances in CSTR Mode
5. Section 5: Analytical Polymer Backbone Mass Conservation Residuals (< 1e-10)
6. Section 6: Process Safety Trips & Strict Fault Hierarchy (0xF931..0xF934)
7. Section 7: Emergency Quench & Safe Shutdown State Transitions
8. Section 8: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
9. Section 9: ILogicUnit Compliance & Multi-Cycle Scan Execution (scan_step, step, execute, reset)
10. Section 10: Horner OCS Register Space Synchronization (%R2600..%R2607, %M606..%M608)
11. Section 11: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Construct Rejection
12. Section 12: Deterministic 9-Stage Verification Runner Execution & JSON Evidence Emission
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

from jev_cscape.simulation.pha_depolymerization import (
    COIL_PHA_DEPOLY_ACTIVE,
    COIL_PHA_DEPOLY_DEPOLYMERIZATION_ACTIVE,
    COIL_PHA_DEPOLY_EMERGENCY_TRIP,
    COIL_PHA_DEPOLY_FEED_PERMISSIVE,
    COIL_PHA_DEPOLY_PERMISSIVE,
    COIL_PHA_DEPOLY_QUENCH_PERMISSIVE,
    COIL_PHA_DEPOLY_REACTOR_ACTIVE,
    COIL_PHA_DEPOLY_RUNNING,
    COIL_PHA_DEPOLY_TRIP,
    COIL_PHA_DEPOLY_TRIP_ALARM,
    COIL_PHA_DEPOLY_WARNING,
    COIL_PHA_DEPOLY_WARNING_ALARM,
    DIAG_ERR_CONTAINMENT_OVERFLOW,
    DIAG_ERR_CRYSTAL,
    DIAG_ERR_CRYSTALLIZATION,
    DIAG_ERR_HIGH_VISCOSITY,
    DIAG_ERR_OVERFLOW,
    DIAG_ERR_PRECIPITATION,
    DIAG_ERR_PRODUCT_CRYSTALLIZATION,
    DIAG_ERR_REACTOR_OVERFLOW,
    DIAG_ERR_RUNAWAY,
    DIAG_ERR_SLURRY_VISCOSITY,
    DIAG_ERR_THERMAL,
    DIAG_ERR_THERMAL_EXCURSION,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_ERR_VISCOSITY,
    DIAG_OK,
    DiagnosticCode,
    PHA_DEPOLY_PURE_ST_POU,
    PHA_DEPOLYMERIZATION_PURE_ST_POU,
    PhaDepolyConfig,
    PhaDepolyDiagnosticCode,
    PhaDepolyEngine,
    PhaDepolyMode,
    PhaDepolyPhase,
    PhaDepolyReactor,
    PhaDepolySimulator,
    PhaDepolyState,
    PhaDepolyStatus,
    PhaDepolyStatusBits,
    PhaDepolyStatusWord,
    PhaDepolyTripCode,
    PhaDepolymerizationConfig,
    PhaDepolymerizationDiagnosticCode,
    PhaDepolymerizationEngine,
    PhaDepolymerizationLogicUnit,
    PhaDepolymerizationMode,
    PhaDepolymerizationModel,
    PhaDepolymerizationParameters,
    PhaDepolymerizationPlantModel,
    PhaDepolymerizationReactor,
    PhaDepolymerizationSimulationLogicUnit,
    PhaDepolymerizationSimulator,
    PhaDepolymerizationState,
    PhaDepolymerizationStatus,
    PhaDepolymerizationStatusBits,
    PhaDepolymerizationStatusWord,
    PhaDepolymerizationSync,
    PhaDepolymerizationTripCode,
    PhaDepolymerizer,
    PhaDepolymerizerReactor,
    REG_PHA_DEPOLY_C_MONO,
    REG_PHA_DEPOLY_C_PHA,
    REG_PHA_DEPOLY_CONV,
    REG_PHA_DEPOLY_CONVERSION,
    REG_PHA_DEPOLY_CONVERSION_SCALED,
    REG_PHA_DEPOLY_DIAG,
    REG_PHA_DEPOLY_DIAGNOSTIC_CODE,
    REG_PHA_DEPOLY_MODE_STATUS,
    REG_PHA_DEPOLY_MONOMER,
    REG_PHA_DEPOLY_MONOMER_SCALED,
    REG_PHA_DEPOLY_POLYMER,
    REG_PHA_DEPOLY_POLYMER_SCALED,
    REG_PHA_DEPOLY_STATUS,
    REG_PHA_DEPOLY_STATUS_BITS,
    REG_PHA_DEPOLY_STATUS_REG,
    REG_PHA_DEPOLY_STATUS_WORD,
    REG_PHA_DEPOLY_TEMP,
    REG_PHA_DEPOLY_TEMP_SCALED,
    REG_PHA_DEPOLY_TEMPERATURE,
    REG_PHA_DEPOLY_V,
    REG_PHA_DEPOLY_VOLUME,
    REG_PHA_DEPOLY_VOLUME_SCALED,
    ST_PROGRAM_PHA_DEPOLYMERIZATION_SYNC,
    run_pha_depoly_verification,
    run_pha_depolymerization_verification,
    verify_pha_depoly_pure_st,
    verify_pha_depolymerization_pure_st,
)


# ============================================================================
# Section 1: Model Initialization, Configuration & Parameter Validation
# ============================================================================

class TestSection01ModelInitializationAndConfig:
    """Verify default configurations, state initializations, and class aliases."""

    def test_default_config_parameters(self) -> None:
        """PhaDepolymerizationConfig default kinetic parameters match CSTR depolymerization spec."""
        cfg = PhaDepolymerizationConfig()
        assert math.isclose(cfg.k_endo, 2.0e7, rel_tol=1e-6)
        assert math.isclose(cfg.Km, 15.0, rel_tol=1e-6)
        assert math.isclose(cfg.Ki, 150.0, rel_tol=1e-6)
        assert math.isclose(cfg.Ea, 42000.0, rel_tol=1e-6)
        assert math.isclose(cfg.R, 8.314, rel_tol=1e-6)

        assert math.isclose(cfg.k_exo, 6.0e6, rel_tol=1e-6)
        assert math.isclose(cfg.Km2, 10.0, rel_tol=1e-6)
        assert math.isclose(cfg.Ea2, 38000.0, rel_tol=1e-6)

        assert math.isclose(cfg.kd0, 0.05, rel_tol=1e-6)
        assert math.isclose(cfg.Tcrit, 60.0, rel_tol=1e-6)
        assert math.isclose(cfg.beta_d, 0.25, rel_tol=1e-6)

        assert math.isclose(cfg.f_in, 0.0, rel_tol=1e-6)
        assert math.isclose(cfg.f_out, 0.0, rel_tol=1e-6)
        assert math.isclose(cfg.c_pha_in, 150.0, rel_tol=1e-6)
        assert math.isclose(cfg.rho_cp, 4000.0, rel_tol=1e-6)
        assert math.isclose(cfg.delta_h_endo, 50.0, rel_tol=1e-6)
        assert math.isclose(cfg.delta_h_exo, 30.0, rel_tol=1e-6)
        assert math.isclose(cfg.ua_jacket, 25000.0, rel_tol=1e-6)
        assert math.isclose(cfg.t_jacket, 50.0, rel_tol=1e-6)

        assert math.isclose(cfg.thermal_runaway_threshold, 75.0, rel_tol=1e-6)
        assert math.isclose(cfg.high_viscosity_threshold, 220.0, rel_tol=1e-6)
        assert math.isclose(cfg.crystallization_threshold, 180.0, rel_tol=1e-6)
        assert math.isclose(cfg.v_max, 2000.0, rel_tol=1e-6)

    def test_custom_config_parameters(self) -> None:
        """PhaDepolymerizationConfig accepts user-specified parameter overrides."""
        cfg = PhaDepolymerizationConfig(
            k_endo=2.5e7,
            Km=18.0,
            Ki=160.0,
            Tcrit=58.0,
            thermal_runaway_threshold=72.0,
            v_max=2500.0,
        )
        assert math.isclose(cfg.k_endo, 2.5e7, rel_tol=1e-6)
        assert math.isclose(cfg.Km, 18.0, rel_tol=1e-6)
        assert math.isclose(cfg.Ki, 160.0, rel_tol=1e-6)
        assert math.isclose(cfg.Tcrit, 58.0, rel_tol=1e-6)
        assert math.isclose(cfg.thermal_runaway_threshold, 72.0, rel_tol=1e-6)
        assert math.isclose(cfg.v_max, 2500.0, rel_tol=1e-6)

    def test_config_to_dict_serialization(self) -> None:
        """PhaDepolymerizationConfig serializes to dict with complete key set."""
        cfg = PhaDepolymerizationConfig()
        d = cfg.to_dict()
        assert "k_endo" in d
        assert "Km" in d
        assert "Ki" in d
        assert "k_exo" in d
        assert "Tcrit" in d
        assert "thermal_runaway_threshold" in d
        assert d["high_viscosity_threshold"] == 220.0

    def test_default_state_initialization(self) -> None:
        """PhaDepolymerizationState initial values match standard reactor charge."""
        st = PhaDepolymerizationState()
        assert math.isclose(st.c_pha, 150.0, rel_tol=1e-6)
        assert math.isclose(st.c_mono, 2.0, rel_tol=1e-6)
        assert math.isclose(st.c_olig, 5.0, rel_tol=1e-6)
        assert math.isclose(st.e_act, 1.5, rel_tol=1e-6)
        assert math.isclose(st.t_rxn, 50.0, rel_tol=1e-6)
        assert math.isclose(st.v_slurry, 1000.0, rel_tol=1e-6)

    def test_state_to_and_from_dict_roundtrip(self) -> None:
        """PhaDepolymerizationState round-trips to and from dict cleanly."""
        st = PhaDepolymerizationState(
            c_pha=120.0,
            c_mono=15.0,
            c_olig=8.0,
            e_act=1.2,
            t_rxn=52.5,
            v_slurry=1050.0,
        )
        d = st.to_dict()
        assert d["c_pha"] == 120.0
        assert d["c_mono"] == 15.0
        assert d["c_olig"] == 8.0
        assert d["e_act"] == 1.2
        assert d["t_rxn"] == 52.5
        assert d["v_slurry"] == 1050.0

        restored = PhaDepolymerizationState.from_dict(d)
        assert math.isclose(restored.c_pha, 120.0, rel_tol=1e-6)
        assert math.isclose(restored.c_mono, 15.0, rel_tol=1e-6)
        assert math.isclose(restored.c_olig, 8.0, rel_tol=1e-6)
        assert math.isclose(restored.e_act, 1.2, rel_tol=1e-6)
        assert math.isclose(restored.t_rxn, 52.5, rel_tol=1e-6)
        assert math.isclose(restored.v_slurry, 1050.0, rel_tol=1e-6)

    def test_state_property_aliases(self) -> None:
        """Convenience property getters and setters work symmetrically."""
        st = PhaDepolymerizationState()
        st.C_pha = 140.0
        assert st.c_pha == 140.0
        st.polymer = 135.0
        assert st.c_pha == 135.0
        st.pha = 130.0
        assert st.c_pha == 130.0

        st.C_mono = 10.0
        assert st.c_mono == 10.0
        st.monomer = 12.0
        assert st.c_mono == 12.0
        st.product = 14.0
        assert st.c_mono == 14.0

        st.C_olig = 7.0
        assert st.c_olig == 7.0
        st.oligomer = 9.0
        assert st.c_olig == 9.0
        st.oligomers = 11.0
        assert st.c_olig == 11.0

        st.E_act = 2.0
        assert st.e_act == 2.0
        st.enzyme = 2.2
        assert st.e_act == 2.2
        st.catalyst = 2.4
        assert st.e_act == 2.4

        st.T_rxn = 53.0
        assert st.t_rxn == 53.0
        st.temperature = 54.0
        assert st.t_rxn == 54.0
        st.temp = 55.0
        assert st.t_rxn == 55.0
        st.temperature_c = 56.0
        assert st.t_rxn == 56.0

        st.V_slurry = 1100.0
        assert st.v_slurry == 1100.0
        st.volume = 1200.0
        assert st.v_slurry == 1200.0
        st.v = 1300.0
        assert st.v_slurry == 1300.0

    def test_class_and_module_aliases(self) -> None:
        """Engine class aliases resolve to the reactor implementation."""
        assert PhaDepolymerizationSimulationLogicUnit is PhaDepolymerizationReactor
        assert PhaDepolymerizationLogicUnit is PhaDepolymerizationReactor
        assert PhaDepolymerizationSimulator is PhaDepolymerizationReactor
        assert PhaDepolymerizationEngine is PhaDepolymerizationReactor
        assert PhaDepolymerizationModel is PhaDepolymerizationReactor
        assert PhaDepolymerizationPlantModel is PhaDepolymerizationReactor
        assert PhaDepolyReactor is PhaDepolymerizationReactor
        assert PhaDepolySimulator is PhaDepolymerizationReactor
        assert PhaDepolyEngine is PhaDepolymerizationReactor
        assert PhaDepolymerizerReactor is PhaDepolymerizationReactor
        assert PhaDepolymerizer is PhaDepolymerizationReactor
        assert PhaDepolyConfig is PhaDepolymerizationConfig
        assert PhaDepolymerizationParameters is PhaDepolymerizationConfig
        assert PhaDepolyState is PhaDepolymerizationState

    def test_register_and_coil_constants(self) -> None:
        """Register addresses %R2600..%R2607 and coils %M606..%M608 match specifications."""
        assert REG_PHA_DEPOLY_STATUS == "%R2600"
        assert REG_PHA_DEPOLY_TEMP_SCALED == "%R2601"
        assert REG_PHA_DEPOLY_POLYMER_SCALED == "%R2602"
        assert REG_PHA_DEPOLY_MONOMER_SCALED == "%R2603"
        assert REG_PHA_DEPOLY_CONVERSION_SCALED == "%R2604"
        assert REG_PHA_DEPOLY_VOLUME_SCALED == "%R2605"
        assert REG_PHA_DEPOLY_DIAGNOSTIC_CODE == "%R2606"
        assert REG_PHA_DEPOLY_STATUS_WORD == "%R2607"

        assert COIL_PHA_DEPOLY_ACTIVE == "%M606"
        assert COIL_PHA_DEPOLY_WARNING == "%M607"
        assert COIL_PHA_DEPOLY_TRIP == "%M608"

        # Aliases
        assert REG_PHA_DEPOLY_MODE_STATUS == "%R2600"
        assert REG_PHA_DEPOLY_STATUS_REG == "%R2600"
        assert REG_PHA_DEPOLY_TEMP == "%R2601"
        assert REG_PHA_DEPOLY_TEMPERATURE == "%R2601"
        assert REG_PHA_DEPOLY_POLYMER == "%R2602"
        assert REG_PHA_DEPOLY_C_PHA == "%R2602"
        assert REG_PHA_DEPOLY_MONOMER == "%R2603"
        assert REG_PHA_DEPOLY_C_MONO == "%R2603"
        assert REG_PHA_DEPOLY_CONVERSION == "%R2604"
        assert REG_PHA_DEPOLY_CONV == "%R2604"
        assert REG_PHA_DEPOLY_VOLUME == "%R2605"
        assert REG_PHA_DEPOLY_V == "%R2605"
        assert REG_PHA_DEPOLY_DIAG == "%R2606"
        assert REG_PHA_DEPOLY_STATUS_BITS == "%R2607"

        assert COIL_PHA_DEPOLY_DEPOLYMERIZATION_ACTIVE == "%M606"
        assert COIL_PHA_DEPOLY_REACTOR_ACTIVE == "%M606"
        assert COIL_PHA_DEPOLY_PERMISSIVE == "%M607"
        assert COIL_PHA_DEPOLY_WARNING_ALARM == "%M607"
        assert COIL_PHA_DEPOLY_TRIP_ALARM == "%M608"
        assert COIL_PHA_DEPOLY_EMERGENCY_TRIP == "%M608"

    def test_status_word_bitmask_flags(self) -> None:
        """PhaDepolyStatusWord bits match actuator and alarm definitions."""
        assert PhaDepolyStatusWord.AGITATOR_ACTIVE == 1 << 0
        assert PhaDepolyStatusWord.FEED_PUMP_ACTIVE == 1 << 1
        assert PhaDepolyStatusWord.DISCHARGE_PUMP_ACTIVE == 1 << 2
        assert PhaDepolyStatusWord.ENZYME_DOSING_ACTIVE == 1 << 3
        assert PhaDepolyStatusWord.HEATING_JACKET_ACTIVE == 1 << 4
        assert PhaDepolyStatusWord.COOLING_JACKET_ACTIVE == 1 << 5
        assert PhaDepolyStatusWord.HIGH_VISCOSITY_WARNING == 1 << 6
        assert PhaDepolyStatusWord.EMERGENCY_TRIP == 1 << 7

    def test_mode_and_status_enums(self) -> None:
        """Mode and status enum integer values match design specifications."""
        assert PhaDepolyMode.SLURRY_PREPARATION == 1
        assert PhaDepolyMode.DEPOLYMERIZATION == 2
        assert PhaDepolyMode.PRODUCT_RECOVERY == 3
        assert PhaDepolyMode.CLEAN_IN_PLACE == 4

        assert PhaDepolyStatus.STANDBY == 1
        assert PhaDepolyStatus.RUNNING == 2
        assert PhaDepolyStatus.TRIPPED == 3


# ============================================================================
# Section 2: Kinetic Parameters, Arrhenius Temperature Factors & Cleavage Mechanisms
# ============================================================================

class TestSection02KineticsAndArrheniusTemperature:
    """Verify enzymatic endocleavage, exocleavage, inhibition, and denaturation kinetics."""

    def test_arrhenius_temperature_dependence(self) -> None:
        """Higher temperatures accelerate cleavage rates below denaturation threshold."""
        r = PhaDepolymerizationReactor()
        st_30 = PhaDepolymerizationState(c_pha=150.0, c_mono=2.0, c_olig=5.0, e_act=1.5, t_rxn=30.0)
        st_50 = PhaDepolymerizationState(c_pha=150.0, c_mono=2.0, c_olig=5.0, e_act=1.5, t_rxn=50.0)
        st_58 = PhaDepolymerizationState(c_pha=150.0, c_mono=2.0, c_olig=5.0, e_act=1.5, t_rxn=58.0)

        r_endo_30, r_exo_30, _ = r.compute_rates(st_30)
        r_endo_50, r_exo_50, _ = r.compute_rates(st_50)
        r_endo_58, r_exo_58, _ = r.compute_rates(st_58)

        assert r_endo_50 > r_endo_30
        assert r_endo_58 > r_endo_50
        assert r_exo_50 > r_exo_30
        assert r_exo_58 > r_exo_50

    def test_endocleavage_rate_behavior(self) -> None:
        """Endocleavage rate r_endo increases with enzyme concentration."""
        r = PhaDepolymerizationReactor()
        st_low_e = PhaDepolymerizationState(e_act=0.5)
        st_high_e = PhaDepolymerizationState(e_act=2.5)

        r_endo_low, _, _ = r.compute_rates(st_low_e)
        r_endo_high, _, _ = r.compute_rates(st_high_e)

        assert r_endo_low > 0.0
        assert r_endo_high > r_endo_low
        assert math.isclose(r_endo_high / r_endo_low, 5.0, rel_tol=1e-3)

    def test_endocleavage_substrate_affinity_km(self) -> None:
        """Endocleavage follows hyperbolic saturation with increasing solid PHA concentration."""
        r = PhaDepolymerizationReactor()
        st_10 = PhaDepolymerizationState(c_pha=10.0, c_mono=0.0)
        st_50 = PhaDepolymerizationState(c_pha=50.0, c_mono=0.0)
        st_150 = PhaDepolymerizationState(c_pha=150.0, c_mono=0.0)

        r_10, _, _ = r.compute_rates(st_10)
        r_50, _, _ = r.compute_rates(st_50)
        r_150, _, _ = r.compute_rates(st_150)

        assert r_10 < r_50 < r_150

    def test_endocleavage_monomer_inhibition_ki(self) -> None:
        """Accumulated monomer product inhibits endocleavage via C_mono^2 / Ki term."""
        r = PhaDepolymerizationReactor()
        st_uninhibited = PhaDepolymerizationState(c_mono=1.0)
        st_moderate = PhaDepolymerizationState(c_mono=50.0)
        st_heavily_inhibited = PhaDepolymerizationState(c_mono=120.0)

        r_uninh, _, _ = r.compute_rates(st_uninhibited)
        r_mod, _, _ = r.compute_rates(st_moderate)
        r_heavy, _, _ = r.compute_rates(st_heavily_inhibited)

        assert r_uninh > r_mod > r_heavy

    def test_exocleavage_rate_behavior(self) -> None:
        """Exocleavage rate r_exo increases with oligomer and enzyme availability."""
        r = PhaDepolymerizationReactor()
        st_low_olig = PhaDepolymerizationState(c_olig=2.0)
        st_high_olig = PhaDepolymerizationState(c_olig=30.0)

        _, r_exo_low, _ = r.compute_rates(st_low_olig)
        _, r_exo_high, _ = r.compute_rates(st_high_olig)

        assert r_exo_low > 0.0
        assert r_exo_high > r_exo_low

    def test_enzyme_thermal_denaturation_onset(self) -> None:
        """Enzyme thermal denaturation is exactly zero when T <= Tcrit (60.0 °C)."""
        r = PhaDepolymerizationReactor()
        st_25 = PhaDepolymerizationState(t_rxn=25.0)
        st_50 = PhaDepolymerizationState(t_rxn=50.0)
        st_60 = PhaDepolymerizationState(t_rxn=60.0)

        _, _, r_denat_25 = r.compute_rates(st_25)
        _, _, r_denat_50 = r.compute_rates(st_50)
        _, _, r_denat_60 = r.compute_rates(st_60)

        assert r_denat_25 == 0.0
        assert r_denat_50 == 0.0
        assert r_denat_60 == 0.0

    def test_enzyme_thermal_denaturation_supercritical(self) -> None:
        """Enzyme thermal denaturation grows exponentially above Tcrit."""
        r = PhaDepolymerizationReactor()
        st_65 = PhaDepolymerizationState(t_rxn=65.0, e_act=1.5)
        st_70 = PhaDepolymerizationState(t_rxn=70.0, e_act=1.5)
        st_74 = PhaDepolymerizationState(t_rxn=74.0, e_act=1.5)

        _, _, r_denat_65 = r.compute_rates(st_65)
        _, _, r_denat_70 = r.compute_rates(st_70)
        _, _, r_denat_74 = r.compute_rates(st_74)

        assert r_denat_65 > 0.0
        assert r_denat_70 > r_denat_65
        assert r_denat_74 > r_denat_70

    def test_enzyme_depletion_under_high_temperature(self) -> None:
        """Prolonged operation above Tcrit rapidly degrades active enzyme concentration."""
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 68.0
        r.state.e_act = 2.0
        e_initial = r.state.e_act

        for _ in range(10):
            r.rk4_step(dt_h=0.05)

        assert r.state.e_act < e_initial


# ============================================================================
# Section 3: Coupled 6-State ODE Discretization, RK4 Integration & Continuous Simulation
# ============================================================================

class TestSection03CoupledODEAndRK4Integration:
    """Verify Runge-Kutta 4th-Order numerical integration step and state progression."""

    def test_single_rk4_step_nominal(self) -> None:
        """Single RK4 step consumes polymer and produces intermediate oligomers and monomers."""
        r = PhaDepolymerizationReactor()
        c_pha_0 = r.state.c_pha
        c_olig_0 = r.state.c_olig
        c_mono_0 = r.state.c_mono

        r.rk4_step(dt_h=0.02)

        assert r.state.c_pha < c_pha_0
        assert r.state.c_olig > c_olig_0 or r.state.c_mono > c_mono_0
        assert r.diagnostic_code == DIAG_OK
        assert r.trip_active is False

    def test_derivatives_calculation(self) -> None:
        """Time derivatives correctly reflect degradation dynamics in batch mode."""
        r = PhaDepolymerizationReactor()
        derivs = r._derivatives(r.state)
        dc_pha_dt, dc_mono_dt, dc_olig_dt, de_act_dt, dt_rxn_dt, dv_dt = derivs

        assert dc_pha_dt < 0.0  # PHA consumption
        assert dc_mono_dt > 0.0  # Monomer production
        assert dv_dt == 0.0  # Fin=Fout=0 in batch mode

    def test_conversion_and_yield_properties(self) -> None:
        """conversion_pct and monomer_yield_pct compute bounded percentages."""
        r = PhaDepolymerizationReactor()
        r.state.c_pha = 100.0
        r.state.c_olig = 30.0
        r.state.c_mono = 20.0

        # Total = 150.0; conv = (30+20)/150 * 100 = 33.33%
        assert math.isclose(r.conversion_pct, 50.0 / 150.0 * 100.0, rel_tol=1e-4)
        assert math.isclose(r.monomer_yield_pct, 20.0 / 150.0 * 100.0, rel_tol=1e-4)

        # Zero concentration protection
        r.state.c_pha = 0.0
        r.state.c_olig = 0.0
        r.state.c_mono = 0.0
        assert r.conversion_pct == 0.0
        assert r.monomer_yield_pct == 0.0

    def test_continuous_simulation_depolymerization_progression(self) -> None:
        """Multi-step continuous simulation steadily advances polymer depolymerization."""
        r = PhaDepolymerizationReactor()
        initial_pha = r.state.c_pha

        for step in range(25):
            r.rk4_step(dt_h=0.04)

        assert r.state.c_pha < initial_pha
        assert r.state.c_mono > 2.0
        assert r.conversion_pct > 1.0

    def test_operating_mode_transitions(self) -> None:
        """Mode transitions from SLURRY_PREPARATION to DEPOLYMERIZATION and PRODUCT_RECOVERY."""
        r = PhaDepolymerizationReactor()
        # Initial state: C_pha=150, C_mono=2, C_olig=5 -> SLURRY_PREPARATION
        assert r.get_current_mode() == int(PhaDepolyMode.SLURRY_PREPARATION)

        # Higher product: C_mono >= 10 -> DEPOLYMERIZATION
        r.state.c_mono = 12.0
        assert r.get_current_mode() == int(PhaDepolyMode.DEPOLYMERIZATION)

        # Conversion >= 85% -> PRODUCT_RECOVERY
        r.state.c_pha = 10.0
        r.state.c_mono = 70.0
        r.state.c_olig = 20.0
        assert r.get_current_mode() == int(PhaDepolyMode.PRODUCT_RECOVERY)

        # Empty reactor: C_pha=0, C_mono=0, C_olig=0 -> CLEAN_IN_PLACE
        r.state.c_pha = 0.0
        r.state.c_mono = 0.0
        r.state.c_olig = 0.0
        assert r.get_current_mode() == int(PhaDepolyMode.CLEAN_IN_PLACE)


# ============================================================================
# Section 4: Energy & Volume Balances in CSTR Mode
# ============================================================================

class TestSection04EnergyAndVolumeBalances:
    """Verify volume and thermal energy balances across continuous and batch modes."""

    def test_volume_balance_closed_batch(self) -> None:
        """In batch mode (Fin=Fout=0), volume remains exactly constant."""
        r = PhaDepolymerizationReactor()
        v_initial = r.state.v_slurry
        for _ in range(10):
            r.rk4_step(dt_h=0.05)
        assert math.isclose(r.state.v_slurry, v_initial, rel_tol=1e-6)

    def test_volume_balance_continuous_flow(self) -> None:
        """In CSTR mode with Fin > Fout, volume increases according to dV/dt = Fin - Fout."""
        cfg = PhaDepolymerizationConfig(f_in=100.0, f_out=40.0)
        r = PhaDepolymerizationReactor(config=cfg)
        v0 = r.state.v_slurry
        dt_h = 0.1
        r.rk4_step(dt_h=dt_h)
        delta_v = r.state.v_slurry - v0
        expected_delta_v = (100.0 - 40.0) * dt_h
        assert math.isclose(delta_v, expected_delta_v, abs_tol=1e-3)

    def test_energy_balance_jacket_heating(self) -> None:
        """Hot jacket heats cooler reactor slurry towards target utility temperature."""
        cfg = PhaDepolymerizationConfig(t_jacket=62.0, ua_jacket=30000.0)
        r = PhaDepolymerizationReactor(config=cfg)
        r.state.t_rxn = 45.0
        r.rk4_step(dt_h=0.1)
        assert r.state.t_rxn > 45.0

    def test_energy_balance_jacket_cooling(self) -> None:
        """Cool jacket removes heat from hotter reactor slurry."""
        cfg = PhaDepolymerizationConfig(t_jacket=35.0, ua_jacket=30000.0)
        r = PhaDepolymerizationReactor(config=cfg)
        r.state.t_rxn = 55.0
        r.rk4_step(dt_h=0.1)
        assert r.state.t_rxn < 55.0

    def test_energy_balance_reaction_exotherm(self) -> None:
        """Reaction heats reactor slurry through Delta_H_endo and Delta_H_exo."""
        cfg = PhaDepolymerizationConfig(
            delta_h_endo=200.0,
            delta_h_exo=150.0,
            ua_jacket=0.0,  # Adiabatic reactor
            f_in=0.0,
            f_out=0.0,
        )
        r = PhaDepolymerizationReactor(config=cfg)
        t0 = r.state.t_rxn
        r.rk4_step(dt_h=0.05)
        assert r.state.t_rxn > t0


# ============================================================================
# Section 5: Analytical Polymer Backbone Mass Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection05MassConservationResiduals:
    """Verify strict polymer backbone mass conservation across single and multi-step cycles."""

    def test_conservation_residual_single_step(self) -> None:
        """Single RK4 step satisfies mass conservation residual < 1e-10."""
        r = PhaDepolymerizationReactor()
        r.rk4_step(dt_h=0.01)
        assert r.conservation_residual < 1e-10

    def test_conservation_residual_multi_step_series(self) -> None:
        """50 consecutive RK4 steps preserve mass conservation residual < 1e-10."""
        r = PhaDepolymerizationReactor()
        for step in range(50):
            r.rk4_step(dt_h=0.02)
            assert r.conservation_residual < 1e-10, f"Residual exceeded at step {step}: {r.conservation_residual}"

    def test_conservation_residual_different_time_steps(self) -> None:
        """Mass conservation holds across various integration step sizes."""
        for dt in [0.001, 0.005, 0.01, 0.05]:
            r = PhaDepolymerizationReactor()
            for _ in range(10):
                r.rk4_step(dt_h=dt)
                assert r.conservation_residual < 1e-10, f"dt={dt} failed with residual {r.conservation_residual}"

    def test_conservation_residual_varying_initial_concentrations(self) -> None:
        """Mass conservation holds for arbitrary starting mass charges."""
        test_cases = [
            (50.0, 1.0, 2.0),
            (200.0, 5.0, 10.0),
            (80.0, 40.0, 30.0),
        ]
        for c_pha, c_mono, c_olig in test_cases:
            st = PhaDepolymerizationState(c_pha=c_pha, c_mono=c_mono, c_olig=c_olig)
            r = PhaDepolymerizationReactor(initial_state=st)
            for _ in range(15):
                r.rk4_step(dt_h=0.02)
                assert r.conservation_residual < 1e-10

    def test_cstr_mode_mass_balance_tracking(self) -> None:
        """Continuous CSTR mode with inflow and outflow maintains residual < 1e-10."""
        cfg = PhaDepolymerizationConfig(f_in=50.0, f_out=50.0, c_pha_in=150.0)
        r = PhaDepolymerizationReactor(config=cfg)
        for _ in range(20):
            r.rk4_step(dt_h=0.02)
            assert r.conservation_residual < 1e-10


# ============================================================================
# Section 6: Process Safety Trips & Strict Fault Hierarchy (0xF931..0xF934)
# ============================================================================

class TestSection06SafetyTripsAndPriorityHierarchy:
    """Verify safety trip assertions, diagnostic codes, and strict priority ordering."""

    def test_trip_thermal_runaway_0xf931(self) -> None:
        """Temperature exceeding 75.0 °C latches thermal runaway trip 0xF931."""
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 76.5
        r.rk4_step(dt_h=0.01)

        assert r.trip_active is True
        assert r.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        assert (int(r.diagnostic_code) & 0xFFFF) == 0xF931
        assert r.cooling_jacket_active is True
        assert r.heating_jacket_active is False

    def test_trip_high_viscosity_0xf932(self) -> None:
        """Solid PHA concentration > 220.0 g/L latches viscosity spike trip 0xF932."""
        r = PhaDepolymerizationReactor()
        r.state.c_pha = 225.0
        r.rk4_step(dt_h=0.01)

        assert r.trip_active is True
        assert r.diagnostic_code == DIAG_ERR_HIGH_VISCOSITY
        assert (int(r.diagnostic_code) & 0xFFFF) == 0xF932
        assert r.viscosity_warning_active is True

    def test_trip_crystallization_0xf933(self) -> None:
        """Monomer concentration > 180.0 g/L latches product crystallization trip 0xF933."""
        r = PhaDepolymerizationReactor()
        r.state.c_mono = 185.0
        r.rk4_step(dt_h=0.01)

        assert r.trip_active is True
        assert r.diagnostic_code == DIAG_ERR_CRYSTALLIZATION
        assert (int(r.diagnostic_code) & 0xFFFF) == 0xF933

    def test_trip_overflow_0xf934(self) -> None:
        """Slurry volume > 2000.0 L latches reactor overflow trip 0xF934."""
        r = PhaDepolymerizationReactor()
        r.state.v_slurry = 2050.0
        r.rk4_step(dt_h=0.01)

        assert r.trip_active is True
        assert r.diagnostic_code == DIAG_ERR_OVERFLOW
        assert (int(r.diagnostic_code) & 0xFFFF) == 0xF934
        assert r.feed_pump_active is False

    def test_fault_priority_thermal_over_viscosity(self) -> None:
        """Priority 1 (Thermal Runaway 0xF931) overrides Priority 2 (High Viscosity 0xF932)."""
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 78.0
        r.state.c_pha = 230.0
        r.rk4_step(dt_h=0.01)

        assert r.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

    def test_fault_priority_thermal_over_crystallization(self) -> None:
        """Priority 1 (Thermal Runaway 0xF931) overrides Priority 3 (Crystallization 0xF933)."""
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 77.0
        r.state.c_mono = 190.0
        r.rk4_step(dt_h=0.01)

        assert r.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

    def test_fault_priority_thermal_over_overflow(self) -> None:
        """Priority 1 (Thermal Runaway 0xF931) overrides Priority 4 (Overflow 0xF934)."""
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 79.0
        r.state.v_slurry = 2100.0
        r.rk4_step(dt_h=0.01)

        assert r.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

    def test_fault_priority_viscosity_over_crystallization(self) -> None:
        """Priority 2 (High Viscosity 0xF932) overrides Priority 3 (Crystallization 0xF933)."""
        r = PhaDepolymerizationReactor()
        r.state.c_pha = 225.0
        r.state.c_mono = 185.0
        r.rk4_step(dt_h=0.01)

        assert r.diagnostic_code == DIAG_ERR_HIGH_VISCOSITY

    def test_fault_priority_viscosity_over_overflow(self) -> None:
        """Priority 2 (High Viscosity 0xF932) overrides Priority 4 (Overflow 0xF934)."""
        r = PhaDepolymerizationReactor()
        r.state.c_pha = 225.0
        r.state.v_slurry = 2100.0
        r.rk4_step(dt_h=0.01)

        assert r.diagnostic_code == DIAG_ERR_HIGH_VISCOSITY

    def test_fault_priority_crystallization_over_overflow(self) -> None:
        """Priority 3 (Crystallization 0xF933) overrides Priority 4 (Overflow 0xF934)."""
        r = PhaDepolymerizationReactor()
        r.state.c_mono = 190.0
        r.state.v_slurry = 2050.0
        r.rk4_step(dt_h=0.01)

        assert r.diagnostic_code == DIAG_ERR_CRYSTALLIZATION

    def test_predictive_warning_thresholds(self) -> None:
        """Pre-trip warning levels assert warning_active without tripping the reactor."""
        # Temperature warning (>= 65.0 °C, < 75.0 °C)
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 68.0
        r.check_interlocks()
        assert r.warning_active is True
        assert r.trip_active is False

        # Polymer warning (>= 200.0 g/L, <= 220.0 g/L)
        r = PhaDepolymerizationReactor()
        r.state.c_pha = 205.0
        r.check_interlocks()
        assert r.warning_active is True
        assert r.viscosity_warning_active is True
        assert r.trip_active is False

        # Monomer warning (>= 160.0 g/L, <= 180.0 g/L)
        r = PhaDepolymerizationReactor()
        r.state.c_mono = 165.0
        r.check_interlocks()
        assert r.warning_active is True
        assert r.trip_active is False

        # Volume warning (>= 1800.0 L, <= 2000.0 L)
        r = PhaDepolymerizationReactor()
        r.state.v_slurry = 1850.0
        r.check_interlocks()
        assert r.warning_active is True
        assert r.trip_active is False


# ============================================================================
# Section 7: Emergency Quench & Safe Shutdown State Transitions
# ============================================================================

class TestSection07EmergencyQuenchAndSafeShutdown:
    """Verify actuators, rate freezing, and recovery during emergency shutdown."""

    def test_trip_halts_reaction_rates(self) -> None:
        """compute_rates returns exactly zero rates when trip_active is asserted."""
        r = PhaDepolymerizationReactor()
        r.trip_active = True
        r_endo, r_exo, r_denat = r.compute_rates(r.state)
        assert r_endo == 0.0
        assert r_exo == 0.0
        assert r_denat == 0.0

    def test_trip_derivatives_freeze(self) -> None:
        """_derivatives returns all zeros when trip_active is True."""
        r = PhaDepolymerizationReactor()
        r.trip_active = True
        derivs = r._derivatives(r.state)
        assert all(d == 0.0 for d in derivs)

    def test_trip_rk4_prestep_shortcircuit(self) -> None:
        """rk4_step freezes state when tripped before taking any integration step."""
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 77.0  # Tripped state
        c_pha_pre = r.state.c_pha

        r.rk4_step(dt_h=0.05)
        assert r.trip_active is True
        assert r.state.c_pha == c_pha_pre

    def test_emergency_quench_cooling_activated(self) -> None:
        """Thermal runaway activates cooling jacket and disables heating jacket."""
        r = PhaDepolymerizationReactor()
        r.heating_jacket_active = True
        r.cooling_jacket_active = False

        r.state.t_rxn = 76.0
        r.check_interlocks()

        assert r.trip_active is True
        assert r.cooling_jacket_active is True
        assert r.heating_jacket_active is False

    def test_safe_shutdown_feed_pump_isolation(self) -> None:
        """Overflow trip de-energizes the slurry feed pump to isolate inflow."""
        r = PhaDepolymerizationReactor()
        r.feed_pump_active = True

        r.state.v_slurry = 2050.0
        r.check_interlocks()

        assert r.trip_active is True
        assert r.feed_pump_active is False

    def test_scan_step_reports_failed_under_trip(self) -> None:
        """scan_step returns AgentStatus.FAILED when trip is active."""
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 76.5
        res = r.scan_step()

        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_ERR_THERMAL_RUNAWAY)
        assert res.data["trip_active"] is True

    def test_reset_restores_nominal_operation(self) -> None:
        """reset() clears trips, restores initial state, and re-enables actuators."""
        r = PhaDepolymerizationReactor()
        r.state.t_rxn = 78.0
        r.rk4_step(dt_h=0.01)
        assert r.trip_active is True

        r.reset()

        assert r.trip_active is False
        assert r.diagnostic_code == DIAG_OK
        assert r.feed_pump_active is True
        assert r.agitator_active is True
        assert math.isclose(r.state.c_pha, 150.0, rel_tol=1e-6)
        assert math.isclose(r.state.t_rxn, 50.0, rel_tol=1e-6)
        assert r.reg_table.read_bit(COIL_PHA_DEPOLY_TRIP) is False
        assert r.reg_table.read_bit(COIL_PHA_DEPOLY_ACTIVE) is True


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
# ============================================================================

class TestSection08DiagnosticCodeCompliance:
    """Verify 16-bit diagnostic code signed/unsigned representations and hashability."""

    def test_diagnostic_code_equality_unsigned(self) -> None:
        """DiagnosticCode instances compare equal to unsigned integer literals."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_THERMAL_RUNAWAY == 0xF931
        assert DIAG_ERR_HIGH_VISCOSITY == 0xF932
        assert DIAG_ERR_CRYSTALLIZATION == 0xF933
        assert DIAG_ERR_OVERFLOW == 0xF934

    def test_diagnostic_code_equality_signed_16bit(self) -> None:
        """DiagnosticCode compares equal to signed 16-bit two's complement integers."""
        # 0xF931 in signed 16-bit is 0xF931 - 0x10000 = -1743
        assert DIAG_ERR_THERMAL_RUNAWAY == -1743
        # 0xF932 in signed 16-bit is -1742
        assert DIAG_ERR_HIGH_VISCOSITY == -1742
        # 0xF933 in signed 16-bit is -1741
        assert DIAG_ERR_CRYSTALLIZATION == -1741
        # 0xF934 in signed 16-bit is -1740
        assert DIAG_ERR_OVERFLOW == -1740

    def test_diagnostic_code_aliases(self) -> None:
        """Diagnostic code aliases match base codes."""
        assert DIAG_ERR_THERMAL == DIAG_ERR_THERMAL_RUNAWAY
        assert DIAG_ERR_THERMAL_EXCURSION == DIAG_ERR_THERMAL_RUNAWAY
        assert DIAG_ERR_VISCOSITY == DIAG_ERR_HIGH_VISCOSITY
        assert DIAG_ERR_SLURRY_VISCOSITY == DIAG_ERR_HIGH_VISCOSITY
        assert DIAG_ERR_CRYSTAL == DIAG_ERR_CRYSTALLIZATION
        assert DIAG_ERR_PRODUCT_CRYSTALLIZATION == DIAG_ERR_CRYSTALLIZATION
        assert DIAG_ERR_REACTOR_OVERFLOW == DIAG_ERR_OVERFLOW
        assert DIAG_ERR_CONTAINMENT_OVERFLOW == DIAG_ERR_OVERFLOW

    def test_diagnostic_code_hashing(self) -> None:
        """DiagnosticCode instances hash correctly and work as dictionary keys."""
        code_map = {
            DIAG_OK: "nominal",
            DIAG_ERR_THERMAL_RUNAWAY: "thermal",
            DIAG_ERR_HIGH_VISCOSITY: "viscosity",
            DIAG_ERR_CRYSTALLIZATION: "crystallization",
            DIAG_ERR_OVERFLOW: "overflow",
        }
        assert code_map[0x0000] == "nominal"
        assert code_map[0xF931] == "thermal"
        assert code_map[0xF932] == "viscosity"
        assert code_map[0xF933] == "crystallization"
        assert code_map[0xF934] == "overflow"

    def test_diagnostic_code_repr_and_str(self) -> None:
        """String representation of DiagnosticCode renders standard hex format."""
        assert str(DIAG_OK) == "0x0000"
        assert str(DIAG_ERR_THERMAL_RUNAWAY) == "0xF931"
        assert repr(DIAG_ERR_HIGH_VISCOSITY) == "DiagnosticCode(0xF932)"


# ============================================================================
# Section 9: ILogicUnit Compliance & Multi-Cycle Scan Execution
# ============================================================================

class TestSection09ILogicUnitCompliance:
    """Verify ILogicUnit interface methods and scan cycle execution."""

    def test_ilogic_unit_properties(self) -> None:
        """PhaDepolymerizationReactor implements required ILogicUnit properties."""
        r = PhaDepolymerizationReactor()
        assert isinstance(r, ILogicUnit)
        assert r.name == "PhaDepolymerizationSimulationLogicUnit"
        assert r.priority == 50
        assert r.is_enabled is True

    def test_scan_step_with_positional_and_keyword_args(self) -> None:
        """scan_step accepts flexible positional and keyword time-step arguments."""
        r = PhaDepolymerizationReactor()
        res1 = r.scan_step(0.02)
        assert res1.status == AgentStatus.SUCCESS
        assert r.cycle_count == 1

        res2 = r.scan_step(dt_h=0.03)
        assert res2.status == AgentStatus.SUCCESS
        assert r.cycle_count == 2

        res3 = r.scan_step(None, 0.01)
        assert res3.status == AgentStatus.SUCCESS
        assert r.cycle_count == 3

    def test_step_method_delegation(self) -> None:
        """step() advances the scan cycle count identically to scan_step."""
        r = PhaDepolymerizationReactor()
        r.step(0.01)
        assert r.cycle_count == 1
        r.step(dt_h=0.02)
        assert r.cycle_count == 2

    def test_execute_method_delegation(self) -> None:
        """execute() method is compatible with ScanContext runner."""
        r = PhaDepolymerizationReactor()
        rt = RegisterTable()
        ctx = ScanContext(cycle=5, dt_ms=20.0, timestamp=time.time(), register_table=rt)
        r.execute(ctx)
        assert r.cycle_count == 1
        assert r.reg_table is rt

    def test_scan_context_register_table_binding(self) -> None:
        """ScanContext provided via kwargs attaches its RegisterTable to the reactor."""
        r = PhaDepolymerizationReactor()
        custom_rt = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=10.0, timestamp=time.time(), register_table=custom_rt)
        r.scan_step(context=ctx)
        assert r.reg_table is custom_rt
        assert (custom_rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_multi_cycle_soak_execution(self) -> None:
        """Multi-cycle soak executes smoothly without drift or numerical anomalies."""
        r = PhaDepolymerizationReactor()
        for c in range(1, 31):
            res = r.scan_step(0.01)
            assert res.status == AgentStatus.SUCCESS
            assert r.cycle_count == c
        assert r.conservation_residual < 1e-10


# ============================================================================
# Section 10: Horner OCS Register Space Synchronization (%R2600..%R2607, %M606..%M608)
# ============================================================================

class TestSection10HornerRegisterSpaceSync:
    """Verify bit-exact Horner register mappings and signed 16-bit masking."""

    def test_register_sync_nominal_word_readings(self) -> None:
        """Nominal state syncs correctly to %R2600..%R2607 words."""
        r = PhaDepolymerizationReactor()
        rt = RegisterTable()
        r.sync_to_registers(rt)

        w_status = rt.read_word(REG_PHA_DEPOLY_STATUS)
        w_temp = rt.read_word(REG_PHA_DEPOLY_TEMP_SCALED)
        w_poly = rt.read_word(REG_PHA_DEPOLY_POLYMER_SCALED)
        w_mono = rt.read_word(REG_PHA_DEPOLY_MONOMER_SCALED)
        w_conv = rt.read_word(REG_PHA_DEPOLY_CONVERSION_SCALED)
        w_vol = rt.read_word(REG_PHA_DEPOLY_VOLUME_SCALED)
        w_diag = rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE)
        w_sword = rt.read_word(REG_PHA_DEPOLY_STATUS_WORD)

        # Status: high byte mode (1..4), low byte status (1..3)
        mode = (w_status >> 8) & 0xFF
        status = w_status & 0xFF
        assert mode in [1, 2, 3, 4]
        assert status in [1, 2, 3]

        # Scaled values
        assert w_temp == int(round(50.0 * 10.0))  # 500
        assert w_poly == int(round(150.0 * 10.0))  # 1500
        assert w_mono == int(round(2.0 * 10.0))    # 20
        assert w_vol == int(round(1000.0 * 10.0))  # 10000
        assert (w_diag & 0xFFFF) == 0x0000

        # Status word bits
        assert (w_sword & PhaDepolyStatusWord.AGITATOR_ACTIVE) != 0
        assert (w_sword & PhaDepolyStatusWord.EMERGENCY_TRIP) == 0

    def test_register_signed_16bit_masking(self) -> None:
        """Diagnostic code words masked with & 0xFFFF match expected hex codes."""
        r = PhaDepolymerizationReactor()
        rt = RegisterTable()

        # Test OK code
        r.sync_to_registers(rt)
        assert (rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        # Test Thermal runaway trip
        r.diagnostic_code = DIAG_ERR_THERMAL_RUNAWAY
        r.trip_active = True
        r.sync_to_registers(rt)
        assert (rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF931

        # Test Viscosity trip
        r.diagnostic_code = DIAG_ERR_HIGH_VISCOSITY
        r.sync_to_registers(rt)
        assert (rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF932

        # Test Crystallization trip
        r.diagnostic_code = DIAG_ERR_CRYSTALLIZATION
        r.sync_to_registers(rt)
        assert (rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF933

        # Test Overflow trip
        r.diagnostic_code = DIAG_ERR_OVERFLOW
        r.sync_to_registers(rt)
        assert (rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF934

    def test_coil_synchronization(self) -> None:
        """Coils %M606..%M608 sync accurately under active, warning, and trip states."""
        r = PhaDepolymerizationReactor()
        rt = RegisterTable()

        # Nominal active state
        r.sync_to_registers(rt)
        assert rt.read_bit(COIL_PHA_DEPOLY_ACTIVE) is True
        assert rt.read_bit(COIL_PHA_DEPOLY_WARNING) is True
        assert rt.read_bit(COIL_PHA_DEPOLY_TRIP) is False

        # Warning active state
        r.warning_active = True
        r.sync_to_registers(rt)
        assert rt.read_bit(COIL_PHA_DEPOLY_ACTIVE) is True
        assert rt.read_bit(COIL_PHA_DEPOLY_WARNING) is False
        assert rt.read_bit(COIL_PHA_DEPOLY_TRIP) is False

        # Tripped state
        r.trip_active = True
        r.sync_to_registers(rt)
        assert rt.read_bit(COIL_PHA_DEPOLY_ACTIVE) is False
        assert rt.read_bit(COIL_PHA_DEPOLY_WARNING) is False
        assert rt.read_bit(COIL_PHA_DEPOLY_TRIP) is True

    def test_register_table_privilege_modes(self) -> None:
        """sync_to_registers succeeds with both APPLICATION and SYSTEM privilege modes."""
        r = PhaDepolymerizationReactor()
        rt = RegisterTable()
        r.sync_to_registers(rt, privilege=PrivilegeMode.APPLICATION)
        assert (rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        r.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_PHA_DEPOLY_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_status_word_register_bit_flags(self) -> None:
        """Actuator state changes reflect in the bits of %R2607 status word."""
        r = PhaDepolymerizationReactor()
        rt = RegisterTable()

        r.agitator_active = False
        r.heating_jacket_active = True
        r.sync_to_registers(rt)

        sword = rt.read_word(REG_PHA_DEPOLY_STATUS_WORD)
        assert (sword & PhaDepolyStatusWord.AGITATOR_ACTIVE) == 0
        assert (sword & PhaDepolyStatusWord.HEATING_JACKET_ACTIVE) != 0


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Construct Rejection
# ============================================================================

class TestSection11PureIECStructuredTextPOU:
    """Verify ST POU AST parsing, register bindings, and ladder logic rejection."""

    def test_st_program_text_integrity(self) -> None:
        """PhaDepolymerizationSync POU text contains all bound registers and coils."""
        pou_text = ST_PROGRAM_PHA_DEPOLYMERIZATION_SYNC
        assert "PROGRAM PhaDepolymerizationSync" in pou_text
        assert "END_PROGRAM" in pou_text
        assert "%R2600" in pou_text
        assert "%R2601" in pou_text
        assert "%R2602" in pou_text
        assert "%R2603" in pou_text
        assert "%R2604" in pou_text
        assert "%R2605" in pou_text
        assert "%R2606" in pou_text
        assert "%R2607" in pou_text
        assert "%M606" in pou_text
        assert "%M607" in pou_text
        assert "%M608" in pou_text

    def test_pure_st_pou_ast_parsing(self) -> None:
        """STParser parses PhaDepolymerizationSync POU successfully into an AST."""
        ast = STParser.parse_pou(ST_PROGRAM_PHA_DEPOLYMERIZATION_SYNC)
        assert ast.name == "PhaDepolymerizationSync"
        assert ast.pou_type == POUType.PROGRAM

        bound_regs = set(ast.bound_registers)
        expected_regs = {
            "%R2600", "%R2601", "%R2602", "%R2603",
            "%R2604", "%R2605", "%R2606", "%R2607",
            "%M606", "%M607", "%M608",
        }
        assert expected_regs.issubset(bound_regs)

    def test_verify_pha_depolymerization_pure_st_helper(self) -> None:
        """verify_pha_depolymerization_pure_st() helper returns True."""
        assert verify_pha_depolymerization_pure_st() is True
        assert verify_pha_depoly_pure_st() is True

    def test_anti_ladder_contacts_rejection(self) -> None:
        """SecurityGuard rejects ladder contact tokens (---[ ]---, ---[ / ]---)."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---[ ]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---[/]--- END_PROGRAM")

    def test_anti_ladder_coils_rejection(self) -> None:
        """SecurityGuard rejects ladder coil tokens (---( )---, ---(L)---, ---(U)---)."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---( )--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---(L)--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---(U)--- END_PROGRAM")

    def test_anti_ladder_rung_network_rejection(self) -> None:
        """SecurityGuard rejects RUNG and NETWORK delimiters."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P RUNG 1 END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P NETWORK 1 END_PROGRAM")

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        """SecurityGuard rejects legacy ladder instruction mnemonics."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P XIC B3:0/0 END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P OTE B3:0/1 END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P XIO B3:0/2 END_PROGRAM")


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Runner Execution & JSON Evidence Emission
# ============================================================================

class TestSection12VerificationRunnerAndEvidence:
    """Verify run_pha_depolymerization_verification across all 9 stages and file output."""

    def test_run_verification_runner_all_9_stages(self) -> None:
        """run_pha_depolymerization_verification passes all 9 verification stages deterministically."""
        res = run_pha_depolymerization_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert res["data"]["work_package"] == "W299"
        assert res["data"]["gate"] == "G7"

    def test_run_verification_runner_stage_details(self) -> None:
        """All 9 stages have passed=True, positive timing_ms, and factual descriptions."""
        res = run_pha_depolymerization_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9

        stage_names = [s["name"] for s in stages]
        expected_names = [
            "initial_state_and_depolymerization",
            "reaction_kinetics_endo_exo",
            "enzyme_thermal_denaturation",
            "energy_and_volume_balance",
            "thermal_runaway_trip",
            "high_viscosity_and_crystallization_trips",
            "overflow_safety_trip",
            "mass_conservation_residuals",
            "horner_ocs_registers_and_pure_st_pou",
        ]
        assert stage_names == expected_names

        for s in stages:
            assert s["passed"] is True
            assert s["timing_ms"] >= 0.0
            assert len(s["details"]) > 0

    def test_run_verification_runner_evidence_file_emission(self) -> None:
        """Runner writes valid evidence JSON payload when output_path is provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "artifacts" / "simulation" / "pha_depolymerization_evidence.json"
            res = run_pha_depolymerization_verification(output_path=str(out_file))

            assert res["status"] == "success"
            assert out_file.exists()

            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            assert data["status"] == "success"
            assert data["data"]["checks_passed"] == 9
            assert len(data["data"]["stages"]) == 9
            assert data["data"]["work_package"] == "W299"
