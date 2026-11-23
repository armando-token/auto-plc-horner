"""Industrial PHBV Nanocomposite Biosynthesis & Dispersion Unit Test Suite (W296).

Work Package: W296 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification sections:
1. Section 1: Model Initialization, Configuration & Parameter Validation
2. Section 2: Cupriavidus necator Growth Kinetics & Dual Carbon Substrate Coupling (S1, S2, N)
3. Section 3: Precursor Dosing, Consumption & Tunable 3HV Monomer Fraction Dynamics (5.0 to 30.0 mol%)
4. Section 4: Nanofiller Shear Dispersion Dynamics & Exfoliation
5. Section 5: Coupled 6-State ODE Discretization & RK4 Numerical Solver Stability
6. Section 6: Analytical Elemental & Mass Conservation Residuals (< 1e-10)
7. Section 7: Process Safety Trips & Strict Fault Hierarchy (0xF921..0xF924)
8. Section 8: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
9. Section 9: Horner OCS Register Space Synchronization (%R2570..%R2577, %M599..%M601)
10. Section 10: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Construct Rejection
11. Section 11: ILogicUnit Compliance & Multi-Cycle Scan Execution (scan_step, step, execute, reset)
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

from jev_cscape.simulation.phbv_nanocomposite import (
    BioPhbvNanocompositeReactor,
    COIL_PHBV_NANO_ACTIVE,
    COIL_PHBV_NANO_BIOSYNTHESIS_TRIP_ALARM,
    COIL_PHBV_NANO_DISPERSION_PERMISSIVE,
    COIL_PHBV_NANO_DISPERSION_WARNING,
    COIL_PHBV_NANO_EMERGENCY_TRIP,
    COIL_PHBV_NANO_FEED_PERMISSIVE,
    COIL_PHBV_NANO_FERMENTATION_ACTIVE,
    COIL_PHBV_NANO_NANOFILLER_PERMISSIVE,
    COIL_PHBV_NANO_PRECURSOR_ACTIVE,
    COIL_PHBV_NANO_PRECURSOR_PERMISSIVE,
    COIL_PHBV_NANO_SYNTHESIS_ACTIVE,
    COIL_PHBV_NANO_TRIP,
    COIL_PHBV_NANO_TRIP_ALARM,
    DIAG_ERR_AERATION_STARVATION,
    DIAG_ERR_AGGLOMERATION,
    DIAG_ERR_CLUMPING_ALARM,
    DIAG_ERR_DISSOLVED_OXYGEN_STARVATION,
    DIAG_ERR_DO_STARVATION,
    DIAG_ERR_NANOFILLER_AGGLOMERATION,
    DIAG_ERR_NANO_CLUMPING,
    DIAG_ERR_OXYGEN_STARVATION,
    DIAG_ERR_PRECURSOR_TOXICITY,
    DIAG_ERR_S2_TOXICITY,
    DIAG_ERR_THERMAL_EXCURSION,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_ERR_VALERATE_OVERCONC,
    DIAG_ERR_VALERATE_TOXIC,
    DIAG_ERR_VALERATE_TOXICITY,
    DIAG_OK,
    DiagnosticCode,
    PHBV_NANO_PURE_ST_POU,
    PHBV_NANO_SYNC_POU,
    PHBV_NANOCOMPOSITE_PURE_ST_POU,
    PHBV_NANOCOMPOSITE_SYNC_POU,
    PhbvNanoConfig,
    PhbvNanoDiagnosticCode,
    PhbvNanoEngine,
    PhbvNanoPhase,
    PhbvNanoReactor,
    PhbvNanoSimulator,
    PhbvNanoState,
    PhbvNanoStatus,
    PhbvNanoStatusBits,
    PhbvNanoStatusWord,
    PhbvNanoTripCode,
    PhbvNanocompositeBiosynthesisReactor,
    PhbvNanocompositeConfig,
    PhbvNanocompositeDiagnosticCode,
    PhbvNanocompositeEngine,
    PhbvNanocompositeLogicUnit,
    PhbvNanocompositeModel,
    PhbvNanocompositeParameters,
    PhbvNanocompositePlantModel,
    PhbvNanocompositeReactor,
    PhbvNanocompositeSimulationLogicUnit,
    PhbvNanocompositeSimulator,
    PhbvNanocompositeState,
    PhbvNanocompositeStatusBits,
    PhbvNanocompositeStatusWord,
    PhbvNanocompositeSync,
    PhbvNanocompositeTripCode,
    REG_PHBV_NANO_3HV_MOL_PCT,
    REG_PHBV_NANO_3HV_MOL_PCT_SCALED,
    REG_PHBV_NANO_BIOMASS,
    REG_PHBV_NANO_BIOMASS_SCALED,
    REG_PHBV_NANO_CYCLE_COUNT,
    REG_PHBV_NANO_DIAG,
    REG_PHBV_NANO_DIAGNOSTIC_CODE,
    REG_PHBV_NANO_DISPERSION,
    REG_PHBV_NANO_DISPERSION_SCALED,
    REG_PHBV_NANO_F_3HV,
    REG_PHBV_NANO_F_HV,
    REG_PHBV_NANO_FERMENTER_STATUS,
    REG_PHBV_NANO_GLUCOSE,
    REG_PHBV_NANO_GLUCOSE_SCALED,
    REG_PHBV_NANO_HV_MOL_PCT,
    REG_PHBV_NANO_MOL_PCT,
    REG_PHBV_NANO_P,
    REG_PHBV_NANO_PHASE_STATUS,
    REG_PHBV_NANO_PHBV,
    REG_PHBV_NANO_PHI,
    REG_PHBV_NANO_PHI_NANO,
    REG_PHBV_NANO_POLYMER,
    REG_PHBV_NANO_POLYMER_SCALED,
    REG_PHBV_NANO_PRECURSOR,
    REG_PHBV_NANO_PRECURSOR_S2,
    REG_PHBV_NANO_PRECURSOR_S2_SCALED,
    REG_PHBV_NANO_PRECURSOR_SCALED,
    REG_PHBV_NANO_S1,
    REG_PHBV_NANO_S2,
    REG_PHBV_NANO_SCAN_COUNT,
    REG_PHBV_NANO_STATUS,
    REG_PHBV_NANO_STATUS_BITS,
    REG_PHBV_NANO_STATUS_WORD,
    REG_PHBV_NANO_SUBSTRATE,
    REG_PHBV_NANO_SUBSTRATE_S1,
    REG_PHBV_NANO_SUBSTRATE_S1_SCALED,
    REG_PHBV_NANO_SUBSTRATE_SCALED,
    REG_PHBV_NANO_TEMP,
    REG_PHBV_NANO_TEMP_SCALED,
    REG_PHBV_NANO_TEMPERATURE,
    REG_PHBV_NANO_VALERATE,
    REG_PHBV_NANO_VALERATE_SCALED,
    REG_PHBV_NANO_X,
    ST_PROGRAM_PHBV_NANOCOMPOSITE_SYNC,
    run_phbv_nano_verification,
    run_phbv_nanocomposite_verification,
    verify_phbv_nano_pure_st,
    verify_phbv_nanocomposite_pure_st,
    verify_phbv_nanocomposite_st,
)


# ============================================================================
# Section 1: Model Initialization, Configuration & Parameter Validation
# ============================================================================

class TestSection01ModelInitializationAndConfig:
    """Verify default configurations, state initializations, and class aliases."""

    def test_default_config_parameters(self) -> None:
        """PhbvNanocompositeConfig default kinetic parameters match specifications."""
        cfg = PhbvNanocompositeConfig()
        assert math.isclose(cfg.mu_max, 0.38, rel_tol=1e-6)
        assert math.isclose(cfg.ks_s1, 0.50, rel_tol=1e-6)
        assert math.isclose(cfg.ks_n, 0.06, rel_tol=1e-6)
        assert math.isclose(cfg.ki_s2, 4.50, rel_tol=1e-6)
        assert math.isclose(cfg.ks_do, 5.0, rel_tol=1e-6)
        assert math.isclose(cfg.kd, 0.01, rel_tol=1e-6)
        assert math.isclose(cfg.q_3hb_max, 0.18, rel_tol=1e-6)
        assert math.isclose(cfg.q_3hv_max, 0.12, rel_tol=1e-6)
        assert math.isclose(cfg.k_disp, 0.005, rel_tol=1e-6)
        assert math.isclose(cfg.k_agg, 0.35, rel_tol=1e-6)
        assert math.isclose(cfg.shear_rate_nominal, 250.0, rel_tol=1e-6)
        assert math.isclose(cfg.f_hv_target_mol_pct, 15.0, rel_tol=1e-6)
        assert math.isclose(cfg.valerate_toxicity_threshold, 5.0, rel_tol=1e-6)
        assert math.isclose(cfg.nanofiller_agglomeration_threshold, 0.20, rel_tol=1e-6)
        assert math.isclose(cfg.thermal_runaway_threshold, 38.5, rel_tol=1e-6)
        assert math.isclose(cfg.do_starvation_threshold, 5.0, rel_tol=1e-6)

    def test_default_state_initialization(self) -> None:
        """PhbvNanocompositeState initializes with correct default state values."""
        st = PhbvNanocompositeState()
        assert math.isclose(st.biomass_x, 3.0, rel_tol=1e-6)
        assert math.isclose(st.substrate_s1, 35.0, rel_tol=1e-6)
        assert math.isclose(st.precursor_s2, 2.0, rel_tol=1e-6)
        assert math.isclose(st.nitrogen_n, 1.5, rel_tol=1e-6)
        assert math.isclose(st.polymer_p, 0.5, rel_tol=1e-6)
        assert math.isclose(st.dispersion_phi, 0.75, rel_tol=1e-6)
        assert math.isclose(st.monomer_f_hv, 15.0, rel_tol=1e-6)
        assert math.isclose(st.temperature_c, 30.0, rel_tol=1e-6)
        assert math.isclose(st.dissolved_oxygen_c_do, 80.0, rel_tol=1e-6)
        assert math.isclose(st.shear_rate, 250.0, rel_tol=1e-6)

    def test_property_aliases(self) -> None:
        """State property getters and setters function correctly."""
        st = PhbvNanocompositeState()
        st.biomass = 4.2
        assert st.biomass_x == 4.2
        assert st.x == 4.2

        st.substrate = 25.0
        assert st.substrate_s1 == 25.0
        assert st.s1 == 25.0
        assert st.glucose == 25.0

        st.precursor = 1.8
        assert st.precursor_s2 == 1.8
        assert st.s2 == 1.8
        assert st.valerate == 1.8

        st.nitrogen = 0.8
        assert st.nitrogen_n == 0.8
        assert st.n == 0.8

        st.polymer = 2.4
        assert st.polymer_p == 2.4
        assert st.p == 2.4
        assert st.phbv == 2.4

        st.dispersion = 0.88
        assert st.dispersion_phi == 0.88
        assert st.phi == 0.88
        assert st.phi_nano == 0.88

        st.monomer_fraction = 18.5
        assert st.monomer_f_hv == 18.5
        assert st.f_hv == 18.5
        assert st.hv_mol_pct == 18.5

        st.temperature = 31.5
        assert st.temperature_c == 31.5
        assert st.temp == 31.5

        st.dissolved_oxygen = 65.0
        assert st.dissolved_oxygen_c_do == 65.0
        assert st.c_do == 65.0

        st.shear_rate = 320.0
        assert st.shear_rate == 320.0

    def test_class_and_module_aliases(self) -> None:
        """Engine class aliases resolve to the reactor implementation."""
        assert PhbvNanocompositeSimulationLogicUnit is PhbvNanocompositeReactor
        assert PhbvNanocompositeBiosynthesisReactor is PhbvNanocompositeReactor
        assert PhbvNanocompositeEngine is PhbvNanocompositeReactor
        assert PhbvNanocompositeSimulator is PhbvNanocompositeReactor
        assert PhbvNanocompositeLogicUnit is PhbvNanocompositeReactor
        assert PhbvNanocompositeModel is PhbvNanocompositeReactor
        assert PhbvNanocompositePlantModel is PhbvNanocompositeReactor
        assert BioPhbvNanocompositeReactor is PhbvNanocompositeReactor
        assert PhbvNanoReactor is PhbvNanocompositeReactor
        assert PhbvNanoSimulator is PhbvNanocompositeReactor
        assert PhbvNanoEngine is PhbvNanocompositeReactor

    def test_register_and_coil_constants(self) -> None:
        """Register addresses %R2570..%R2577 and coil addresses %M599..%M601 match allocation."""
        assert REG_PHBV_NANO_FERMENTER_STATUS == "%R2570"
        assert REG_PHBV_NANO_BIOMASS_SCALED == "%R2571"
        assert REG_PHBV_NANO_POLYMER_SCALED == "%R2572"
        assert REG_PHBV_NANO_3HV_MOL_PCT_SCALED == "%R2573"
        assert REG_PHBV_NANO_DISPERSION_SCALED == "%R2574"
        assert REG_PHBV_NANO_DIAGNOSTIC_CODE == "%R2575"
        assert REG_PHBV_NANO_STATUS_WORD == "%R2576"
        assert REG_PHBV_NANO_SCAN_COUNT == "%R2577"

        assert COIL_PHBV_NANO_ACTIVE == "%M599"
        assert COIL_PHBV_NANO_DISPERSION_WARNING == "%M600"
        assert COIL_PHBV_NANO_TRIP == "%M601"

        # Register aliases
        assert REG_PHBV_NANO_STATUS == "%R2570"
        assert REG_PHBV_NANO_BIOMASS == "%R2571"
        assert REG_PHBV_NANO_X == "%R2571"
        assert REG_PHBV_NANO_POLYMER == "%R2572"
        assert REG_PHBV_NANO_P == "%R2572"
        assert REG_PHBV_NANO_PHBV == "%R2572"
        assert REG_PHBV_NANO_3HV_MOL_PCT == "%R2573"
        assert REG_PHBV_NANO_HV_MOL_PCT == "%R2573"
        assert REG_PHBV_NANO_F_HV == "%R2573"
        assert REG_PHBV_NANO_MOL_PCT == "%R2573"
        assert REG_PHBV_NANO_DISPERSION == "%R2574"
        assert REG_PHBV_NANO_PHI == "%R2574"
        assert REG_PHBV_NANO_PHI_NANO == "%R2574"
        assert REG_PHBV_NANO_DIAG == "%R2575"
        assert REG_PHBV_NANO_STATUS_BITS == "%R2576"
        assert REG_PHBV_NANO_CYCLE_COUNT == "%R2577"



# ============================================================================
# Section 2: Cupriavidus necator Growth Kinetics & Dual Carbon Substrates
# ============================================================================

class TestSection02GrowthKineticsAndDualSubstrates:
    """Verify coupled Monod cell growth on Glucose S1, Valerate S2, and Nitrogen N."""

    def test_biomass_growth_in_growth_phase(self) -> None:
        """Biomass concentration increases when nitrogen and glucose are abundant."""
        reactor = PhbvNanocompositeReactor()
        x0 = reactor.state.biomass_x
        for _ in range(10):
            reactor.rk4_step(dt_h=0.05)
        assert reactor.state.biomass_x > x0
        assert reactor.diagnostic_code == DIAG_OK

    def test_dual_substrate_consumption(self) -> None:
        """Glucose S1 and precursor S2 are simultaneously consumed."""
        reactor = PhbvNanocompositeReactor()
        s1_init = reactor.state.substrate_s1
        s2_init = reactor.state.precursor_s2
        n_init = reactor.state.nitrogen_n

        for _ in range(8):
            reactor.rk4_step(dt_h=0.05)

        assert reactor.state.substrate_s1 < s1_init
        assert reactor.state.precursor_s2 < s2_init
        assert reactor.state.nitrogen_n < n_init


# ============================================================================
# Section 3: Precursor Dosing & 3HV Monomer Fraction Dynamics
# ============================================================================

class TestSection03PrecursorAnd3HvMonomerFraction:
    """Verify 3HV monomer fraction tuning within target 5.0 to 30.0 mol%."""

    def test_3hv_fraction_tuning_increase(self) -> None:
        """3HV monomer fraction relaxes upward toward higher target fraction."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.monomer_f_hv = 10.0
        reactor.set_target_3hv_fraction(25.0)

        for _ in range(10):
            reactor.rk4_step(dt_h=0.05)

        assert reactor.state.monomer_f_hv > 10.0
        assert reactor.state.monomer_f_hv <= 25.0

    def test_3hv_fraction_tuning_decrease(self) -> None:
        """3HV monomer fraction relaxes downward toward lower target fraction."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.monomer_f_hv = 28.0
        reactor.set_target_3hv_fraction(12.0)

        for _ in range(10):
            reactor.rk4_step(dt_h=0.05)

        assert reactor.state.monomer_f_hv < 28.0
        assert reactor.state.monomer_f_hv >= 12.0

    def test_target_boundary_clamping(self) -> None:
        """Target 3HV fraction clamps strictly within [5.0, 30.0] mol%."""
        reactor = PhbvNanocompositeReactor()
        reactor.set_target_3hv_fraction(2.0)
        assert reactor.cfg.f_hv_target_mol_pct == 5.0

        reactor.set_target_3hv_fraction(45.0)
        assert reactor.cfg.f_hv_target_mol_pct == 30.0


# ============================================================================
# Section 4: Nanofiller Shear Dispersion Dynamics
# ============================================================================

class TestSection04NanofillerShearDispersion:
    """Verify dPhi/dt = k_disp * shear_rate * (1 - Phi) - k_agg * Phi^2."""

    def test_shear_dispersion_under_high_agitation(self) -> None:
        """Dispersion index increases under active impeller shear from low dispersion."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.dispersion_phi = 0.30
        reactor.state.shear_rate = 300.0

        for _ in range(5):
            reactor.rk4_step(dt_h=0.05)

        assert reactor.state.dispersion_phi > 0.30
        assert reactor.state.dispersion_phi <= 1.0

    def test_agglomeration_when_shear_is_zero(self) -> None:
        """Dispersion index decays due to aggregation when impeller shear is stopped."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.dispersion_phi = 0.80
        reactor.state.shear_rate = 0.0

        for _ in range(10):
            reactor.rk4_step(dt_h=0.05)

        assert reactor.state.dispersion_phi < 0.80

    def test_dispersion_index_bounded(self) -> None:
        """Dispersion index Phi_nano remains clamped within [0.0, 1.0]."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.dispersion_phi = 0.99
        reactor.state.shear_rate = 500.0
        for _ in range(10):
            reactor.rk4_step(dt_h=0.05)
        assert 0.0 <= reactor.state.dispersion_phi <= 1.0


# ============================================================================
# Section 5: Coupled 6-State ODE RK4 Discretization
# ============================================================================

class TestSection05CoupledOdeRk4Discretization:
    """Verify RK4 micro-step discretization and numerical stability."""

    def test_rk4_discretization_step(self) -> None:
        """RK4 step advances all states without numerical instability."""
        reactor = PhbvNanocompositeReactor()
        for _ in range(20):
            reactor.rk4_step(dt_h=0.01)
            assert not math.isnan(reactor.state.biomass_x)
            assert not math.isnan(reactor.state.substrate_s1)
            assert not math.isnan(reactor.state.precursor_s2)
            assert not math.isnan(reactor.state.nitrogen_n)
            assert not math.isnan(reactor.state.polymer_p)
            assert not math.isnan(reactor.state.dispersion_phi)
            assert not math.isnan(reactor.state.monomer_f_hv)

    def test_phbv_polymer_accumulation(self) -> None:
        """PHBV copolymer biopolymer accumulates over cultivation time."""
        reactor = PhbvNanocompositeReactor()
        p0 = reactor.state.polymer_p
        for _ in range(15):
            reactor.rk4_step(dt_h=0.05)
        assert reactor.state.polymer_p > p0


# ============================================================================
# Section 6: Analytical Elemental & Mass Conservation Residuals
# ============================================================================

class TestSection06MassConservationResiduals:
    """Verify elemental mass and carbon conservation balance residuals strictly < 1e-10."""

    def test_carbon_balance_residual_strict_bound(self) -> None:
        """Carbon conservation residual remains strictly below 1e-10."""
        reactor = PhbvNanocompositeReactor()
        for _ in range(10):
            reactor.rk4_step(dt_h=0.05)
            assert reactor.conservation_residual < 1e-10

    def test_carbon_balance_residual_zero_without_growth(self) -> None:
        """Carbon conservation residual is zero when reactor trips."""
        reactor = PhbvNanocompositeReactor()
        reactor.trip_active = True
        reactor.rk4_step(dt_h=0.01)
        assert reactor.conservation_residual == 0.0


# ============================================================================
# Section 7: Process Safety Trips & Strict Fault Hierarchy
# ============================================================================

class TestSection07SafetyTripsAndFaultHierarchy:
    """Verify 4 safety trips and priority hierarchy (0xF921 > 0xF922 > 0xF923 > 0xF924)."""

    def test_priority_1_valerate_toxicity(self) -> None:
        """S2 > 5.0 g/L trips 0xF921 VALERATE_TOXICITY, shuts off precursor feed, %M600=False."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.precursor_s2 = 5.2
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_VALERATE_TOXICITY
        assert reactor.precursor_feed_permissive is False
        assert reactor.reg_table.read_bit(COIL_PHBV_NANO_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_PHBV_NANO_DISPERSION_WARNING) is False
        assert reactor.reg_table.read_bit(COIL_PHBV_NANO_TRIP) is True

    def test_priority_2_nanofiller_agglomeration(self) -> None:
        """Phi_nano < 0.20 trips 0xF922 NANOFILLER_AGGLOMERATION and clumping alarm."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.dispersion_phi = 0.18
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_NANOFILLER_AGGLOMERATION
        assert reactor.clumping_alarm_active is True
        assert reactor.reg_table.read_bit(COIL_PHBV_NANO_TRIP) is True

    def test_priority_3_thermal_runaway(self) -> None:
        """T > 38.5 °C trips 0xF923 THERMAL_RUNAWAY and cooling interlock."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.temperature_c = 39.2
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        assert reactor.cooling_interlock_tripped is True
        assert reactor.reg_table.read_bit(COIL_PHBV_NANO_TRIP) is True

    def test_priority_4_do_starvation(self) -> None:
        """C_DO < 5.0 % trips 0xF924 DO_STARVATION and aeration interlock."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.dissolved_oxygen_c_do = 4.2
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_DO_STARVATION
        assert reactor.aeration_interlock_tripped is True
        assert reactor.reg_table.read_bit(COIL_PHBV_NANO_TRIP) is True

    def test_priority_hierarchy_ordering(self) -> None:
        """Priority 1 dominates Priority 2, 3, and 4 when multiple faults occur."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.precursor_s2 = 5.8       # P1
        reactor.state.dispersion_phi = 0.10     # P2
        reactor.state.temperature_c = 40.0     # P3
        reactor.state.dissolved_oxygen_c_do = 2.0  # P4
        reactor.rk4_step(dt_h=0.01)

        assert reactor.diagnostic_code == DIAG_ERR_VALERATE_TOXICITY


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned Equality
# ============================================================================

class TestSection08DiagnosticCodeCompliance:
    """Verify DiagnosticCode signed/unsigned integer equality and hashing."""

    def test_diagnostic_code_equality(self) -> None:
        """DiagnosticCode compares equal to signed/unsigned int representations."""
        diag = DiagnosticCode(0xF921)
        assert diag == 0xF921
        assert diag == -1759  # 0xF921 as 16-bit signed int
        assert hash(diag) == hash(0xF921)

    def test_diagnostic_code_string(self) -> None:
        """DiagnosticCode renders as 0xXXXX hexadecimal string."""
        diag = DiagnosticCode(0xF922)
        assert str(diag) == "0xF922"
        assert repr(diag) == "DiagnosticCode(0xF922)"

    def test_all_diagnostic_codes_signed_equality_and_masking(self) -> None:
        """All 4 diagnostic codes support unsigned and signed two's complement equality and bitmasking."""
        codes = [
            (DIAG_ERR_VALERATE_TOXICITY, 0xF921, -1759),
            (DIAG_ERR_NANOFILLER_AGGLOMERATION, 0xF922, -1758),
            (DIAG_ERR_THERMAL_RUNAWAY, 0xF923, -1757),
            (DIAG_ERR_DO_STARVATION, 0xF924, -1756),
        ]
        for diag, u_val, s_val in codes:
            assert diag == u_val
            assert diag == s_val
            assert (diag & 0xFFFF) == u_val
            assert hash(diag) == hash(u_val)



# ============================================================================
# Section 9: Horner OCS Register Space Synchronization
# ============================================================================

class TestSection09HornerOcsRegisterSync:
    """Verify bit-exact synchronization to %R2570..%R2577 and %M599..%M601."""

    def test_normal_register_synchronization(self) -> None:
        """Registers and coils reflect nominal process state."""
        reactor = PhbvNanocompositeReactor()
        reactor.scan_step()

        rt = reactor.reg_table
        w_status = rt.read_word(REG_PHBV_NANO_FERMENTER_STATUS)
        w_x = rt.read_word(REG_PHBV_NANO_BIOMASS_SCALED)
        w_p = rt.read_word(REG_PHBV_NANO_POLYMER_SCALED)
        w_fhv = rt.read_word(REG_PHBV_NANO_3HV_MOL_PCT_SCALED)
        w_disp = rt.read_word(REG_PHBV_NANO_DISPERSION_SCALED)
        w_diag = rt.read_word(REG_PHBV_NANO_DIAGNOSTIC_CODE)
        w_sword = rt.read_word(REG_PHBV_NANO_STATUS_WORD)
        w_scan = rt.read_word(REG_PHBV_NANO_SCAN_COUNT)

        assert (w_status & 0xFF) == int(PhbvNanoStatus.RUNNING)
        assert 1 <= ((w_status >> 8) & 0xFF) <= 4
        assert w_x > 0
        assert w_p > 0
        assert w_fhv > 0
        assert w_disp > 0
        assert (w_diag & 0xFFFF) == 0x0000
        assert (w_sword & PhbvNanoStatusWord.AGITATOR_ACTIVE) != 0
        assert (w_sword & PhbvNanoStatusWord.PRECURSOR_FEED_ACTIVE) != 0
        assert (w_sword & PhbvNanoStatusWord.EMERGENCY_TRIP) == 0
        assert w_scan == 1

        assert rt.read_bit(COIL_PHBV_NANO_ACTIVE) is True
        assert rt.read_bit(COIL_PHBV_NANO_DISPERSION_WARNING) is True
        assert rt.read_bit(COIL_PHBV_NANO_TRIP) is False

    def test_tripped_register_synchronization(self) -> None:
        """Fault trip updates %R2575 diagnostic code, %R2576 status word, and coils."""
        table = RegisterTable()
        reactor = PhbvNanocompositeReactor(register_table=table)
        reactor.state.precursor_s2 = 5.5
        reactor.scan_step()

        assert (table.read_uword(REG_PHBV_NANO_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF921
        w_sword = table.read_word(REG_PHBV_NANO_STATUS_WORD)
        assert (w_sword & PhbvNanoStatusWord.EMERGENCY_TRIP) != 0
        assert table.read_bit(COIL_PHBV_NANO_ACTIVE) is False
        assert table.read_bit(COIL_PHBV_NANO_DISPERSION_WARNING) is False
        assert table.read_bit(COIL_PHBV_NANO_TRIP) is True

    def test_privilege_modes(self) -> None:
        """sync_to_registers functions properly under both USER and SYSTEM privilege modes."""
        table = RegisterTable()
        reactor = PhbvNanocompositeReactor(register_table=table)
        reactor.sync_to_registers(table, privilege=PrivilegeMode.USER)
        assert table.read_word(REG_PHBV_NANO_BIOMASS_SCALED) == 300

        reactor.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word(REG_PHBV_NANO_BIOMASS_SCALED) == 300



# ============================================================================
# Section 10: Pure IEC 61131-3 Structured Text POU
# ============================================================================

class TestSection10PureIec61131StPou:
    """Verify pure ST POU syntax and anti-ladder construct rejection."""

    def test_pure_st_pou_string(self) -> None:
        """ST_PROGRAM_PHBV_NANOCOMPOSITE_SYNC contains valid program text."""
        assert isinstance(ST_PROGRAM_PHBV_NANOCOMPOSITE_SYNC, str)
        assert "PROGRAM PhbvNanocompositeSync" in ST_PROGRAM_PHBV_NANOCOMPOSITE_SYNC
        assert "END_PROGRAM" in ST_PROGRAM_PHBV_NANOCOMPOSITE_SYNC

    def test_verify_phbv_nanocomposite_pure_st(self) -> None:
        """verify_phbv_nanocomposite_pure_st returns True."""
        assert verify_phbv_nanocomposite_pure_st() is True
        assert verify_phbv_nano_pure_st() is True
        assert verify_phbv_nanocomposite_st() is True

    def test_ladder_construct_rejection(self) -> None:
        """SecurityGuard strictly rejects ladder contacts and coils."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test ---[ ]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test ---( )--- END_PROGRAM")

    def test_st_ast_variable_bindings(self) -> None:
        """STParser binds %R2570..%R2577 and %M599..%M601 in AST."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(ST_PROGRAM_PHBV_NANOCOMPOSITE_SYNC)
        assert pou is not None
        assert pou.name == "PhbvNanocompositeSync"

        required_regs = [
            "%R2570", "%R2571", "%R2572", "%R2573",
            "%R2574", "%R2575", "%R2576", "%R2577",
            "%M599", "%M600", "%M601",
        ]
        for reg in required_regs:
            assert reg in pou.bound_registers, f"Missing AST binding for {reg}"

    def test_reject_ladder_keywords(self) -> None:
        """Keywords RUNG, NETWORK, XIC, OTE raise LadderForbiddenError."""
        for kw in ["RUNG 1", "NETWORK 5", "XIC Agit1", "OTE FeedPump1"]:
            bad_code = f"PROGRAM Bad\nVAR x: BOOL; END_VAR\n{kw}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_code)



# ============================================================================
# Section 11: ILogicUnit Compliance & Multi-Cycle Scan Execution
# ============================================================================

class TestSection11ILogicUnitCompliance:
    """Verify scan_step, step, execute, and reset ILogicUnit contracts."""

    def test_scan_step_with_context(self) -> None:
        """scan_step accepts ScanContext and uses its register table."""
        rt = RegisterTable()
        ctx = ScanContext(register_table=rt)
        reactor = PhbvNanocompositeReactor()

        res = reactor.scan_step(context=ctx)
        assert res.status == AgentStatus.SUCCESS
        assert reactor.reg_table is rt
        assert rt.read_word(REG_PHBV_NANO_SCAN_COUNT) == 1

    def test_reset_method(self) -> None:
        """reset restores default state and clears trips."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.precursor_s2 = 10.0
        reactor.scan_step()
        assert reactor.trip_active is True

        reactor.reset()
        assert reactor.trip_active is False
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.state.precursor_s2 == 2.0

    def test_ilogicunit_properties(self) -> None:
        """PhbvNanocompositeReactor fulfills ILogicUnit properties."""
        reactor = PhbvNanocompositeReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "PhbvNanocompositeSimulationLogicUnit"
        assert reactor.priority == 50
        assert reactor.is_enabled is True

    def test_step_and_execute_methods(self) -> None:
        """step() and execute() advance cycle count."""
        reactor = PhbvNanocompositeReactor()
        reactor.step()
        assert reactor.cycle_count == 1
        reactor.execute()
        assert reactor.cycle_count == 2


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Runner Execution
# ============================================================================

class TestSection12VerificationRunner:
    """Verify run_phbv_nanocomposite_verification output contract and evidence emission."""

    def test_run_verification_success(self) -> None:
        """run_phbv_nanocomposite_verification passes all 9 stages."""
        res = run_phbv_nanocomposite_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9

    def test_evidence_file_emission(self, tmp_path: Path) -> None:
        """Verification evidence emits valid JSON to disk."""
        out_file = tmp_path / "phbv_nano_evidence.json"
        res = run_phbv_nanocomposite_verification(output_path=str(out_file))

        assert res["status"] == "success"
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_runner_alias(self) -> None:
        """run_phbv_nano_verification is an alias for run_phbv_nanocomposite_verification."""
        assert run_phbv_nano_verification is run_phbv_nanocomposite_verification


# ============================================================================
# Section 13: Continuous Scan Soak Test (50+ Cycles)
# ============================================================================

class TestSection13ContinuousScanSoakTest:
    """Verify 50+ scan cycles run continuously with zero faults, bounded values, and stable memory."""

    def test_continuous_60_cycle_soak(self) -> None:
        """Execute 60 consecutive scan cycles without trips, non-finite values, or leaks."""
        table = RegisterTable()
        reactor = PhbvNanocompositeReactor(register_table=table)

        initial_time = time.perf_counter()
        for cycle in range(1, 61):
            res = reactor.scan_step(dt_h=0.01)
            assert res.status == AgentStatus.SUCCESS
            assert reactor.trip_active is False
            assert reactor.cycle_count == cycle

            # Ensure all physical state variables remain bounded and non-negative
            assert reactor.state.biomass_x > 0.0
            assert reactor.state.substrate_s1 > 0.0
            assert reactor.state.precursor_s2 > 0.0
            assert reactor.state.nitrogen_n >= 0.0
            assert reactor.state.polymer_p > 0.0
            assert 0.0 <= reactor.state.dispersion_phi <= 1.0
            assert 5.0 <= reactor.state.monomer_f_hv <= 30.0

            # Ensure mass conservation residual remains < 1e-10 throughout soak
            assert reactor.conservation_residual < 1e-10

            # Ensure no NaN or infinite values
            assert not math.isnan(reactor.state.biomass_x)
            assert not math.isinf(reactor.state.biomass_x)

        elapsed = time.perf_counter() - initial_time
        assert elapsed < 5.0  # Must be fast and highly efficient (< 5000 ms)


# ============================================================================
# Section 14: State & Configuration Model Roundtrip & Status Words
# ============================================================================

class TestSection14ModelRoundtripAndConfig:
    """Verify serialization, config export, and status bit combinations."""

    def test_state_to_dict_and_from_dict_roundtrip(self) -> None:
        """PhbvNanocompositeState round-trips cleanly through dictionary serialization."""
        s1 = PhbvNanocompositeState(
            biomass_x=4.2,
            substrate_s1=28.5,
            precursor_s2=1.8,
            nitrogen_n=0.9,
            polymer_p=1.2,
            dispersion_phi=0.82,
            monomer_f_hv=18.4,
            temperature_c=31.2,
            dissolved_oxygen_c_do=75.0,
            shear_rate=300.0,
        )
        d = s1.to_dict()
        s2 = PhbvNanocompositeState.from_dict(d)
        assert math.isclose(s1.biomass_x, s2.biomass_x)
        assert math.isclose(s1.substrate_s1, s2.substrate_s1)
        assert math.isclose(s1.precursor_s2, s2.precursor_s2)
        assert math.isclose(s1.nitrogen_n, s2.nitrogen_n)
        assert math.isclose(s1.polymer_p, s2.polymer_p)
        assert math.isclose(s1.dispersion_phi, s2.dispersion_phi)
        assert math.isclose(s1.monomer_f_hv, s2.monomer_f_hv)
        assert math.isclose(s1.temperature_c, s2.temperature_c)
        assert math.isclose(s1.dissolved_oxygen_c_do, s2.dissolved_oxygen_c_do)
        assert math.isclose(s1.shear_rate, s2.shear_rate)

    def test_config_to_dict(self) -> None:
        """PhbvNanocompositeConfig serializes to dict containing key thresholds."""
        cfg = PhbvNanocompositeConfig()
        d = cfg.to_dict()
        assert d["valerate_toxicity_threshold"] == 5.0
        assert d["nanofiller_agglomeration_threshold"] == 0.20
        assert d["thermal_runaway_threshold"] == 38.5
        assert d["do_starvation_threshold"] == 5.0

    def test_status_word_bitmask_combinations(self) -> None:
        """PhbvNanoStatusWord combinations evaluate accurately."""
        sw = PhbvNanoStatusWord.AGITATOR_ACTIVE | PhbvNanoStatusWord.DO_OK
        assert bool(sw & PhbvNanoStatusWord.AGITATOR_ACTIVE) is True
        assert bool(sw & PhbvNanoStatusWord.DO_OK) is True
        assert bool(sw & PhbvNanoStatusWord.EMERGENCY_TRIP) is False


# ============================================================================
# Section 15: Specialized Kinetics, Shear Recovery & Runner Verification
# ============================================================================

class TestSection15SpecializedKineticsAndRunnerDetails:
    """Verify specific growth inhibition, thermal optimum, shear recovery, and runner metadata."""

    def test_haldane_substrate_inhibition_on_growth(self) -> None:
        """Elevated precursor S2 decreases growth rate compared to optimal moderate S2."""
        r_opt = PhbvNanocompositeReactor()
        r_opt.state.precursor_s2 = 1.0
        derivs_opt = r_opt._derivatives(r_opt.state)

        r_inhib = PhbvNanocompositeReactor()
        r_inhib.state.precursor_s2 = 4.5  # High but below 5.0 trip
        derivs_inhib = r_inhib._derivatives(r_inhib.state)

        # dX/dt should be lower due to Haldane inhibition
        assert derivs_inhib[0] < derivs_opt[0]

    def test_temperature_bell_curve_around_optimum(self) -> None:
        """Cultivation at optimal 30°C produces higher growth rate than sub-optimal temperatures."""
        r_opt = PhbvNanocompositeReactor()
        r_opt.state.temperature_c = 30.0
        d_opt = r_opt._derivatives(r_opt.state)[0]

        r_cold = PhbvNanocompositeReactor()
        r_cold.state.temperature_c = 22.0
        d_cold = r_cold._derivatives(r_cold.state)[0]

        r_warm = PhbvNanocompositeReactor()
        r_warm.state.temperature_c = 37.0
        d_warm = r_warm._derivatives(r_warm.state)[0]

        assert d_opt > d_cold
        assert d_opt > d_warm

    def test_nanofiller_dispersion_recovery_under_shear(self) -> None:
        """Nanofiller dispersion recovers towards high exfoliation under sustained shear."""
        reactor = PhbvNanocompositeReactor()
        reactor.state.dispersion_phi = 0.35  # Moderately low initial dispersion
        reactor.state.shear_rate = 300.0     # High shear agitation
        for _ in range(15):
            reactor.rk4_step(dt_h=0.05)
        assert reactor.state.dispersion_phi > 0.50

    def test_scan_step_with_custom_dt_parameters(self) -> None:
        """scan_step accepts custom dt values and updates state consistently."""
        reactor = PhbvNanocompositeReactor()
        res1 = reactor.scan_step(dt=0.02)
        assert res1.status == AgentStatus.SUCCESS
        assert reactor.cycle_count == 1

        res2 = reactor.scan_step(dt_h=0.005)
        assert res2.status == AgentStatus.SUCCESS
        assert reactor.cycle_count == 2

    def test_interlock_recovery_matrix(self) -> None:
        """Test clearing and recovery across all 4 trip types using reset()."""
        reactor = PhbvNanocompositeReactor()
        trips = [
            ("precursor_s2", 6.0, DIAG_ERR_VALERATE_TOXICITY),
            ("dispersion_phi", 0.10, DIAG_ERR_NANOFILLER_AGGLOMERATION),
            ("temperature_c", 40.0, DIAG_ERR_THERMAL_RUNAWAY),
            ("dissolved_oxygen_c_do", 3.0, DIAG_ERR_DO_STARVATION),
        ]
        for attr, bad_val, expected_diag in trips:
            reactor.reset()
            setattr(reactor.state, attr, bad_val)
            reactor.rk4_step(dt_h=0.01)
            assert reactor.trip_active is True
            assert reactor.diagnostic_code == expected_diag
            # Verify clean reset
            reactor.reset()
            assert reactor.trip_active is False
            assert reactor.diagnostic_code == DIAG_OK

    def test_runner_evidence_metadata_integrity(self) -> None:
        """Verification runner output includes complete metadata and stage records."""
        evidence = run_phbv_nanocomposite_verification()
        assert evidence["status"] == "success"
        data = evidence["data"]
        assert data["work_package"] == "W296"
        assert data["gate"] == "G7"
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9
        for s in data["stages"]:
            assert "stage" in s
            assert "name" in s
            assert "passed" in s
            assert "timing_ms" in s
            assert "details" in s
            assert s["passed"] is True
            assert s["timing_ms"] >= 0.0

    def test_nitrogen_limitation_polymer_induction(self) -> None:
        """Polymer synthesis specific rate q_p increases under nitrogen limitation."""
        r_n_high = PhbvNanocompositeReactor()
        r_n_high.state.nitrogen_n = 2.0
        d_p_n_high = r_n_high._derivatives(r_n_high.state)[4]

        r_n_low = PhbvNanocompositeReactor()
        r_n_low.state.nitrogen_n = 0.01  # Nitrogen depletion
        d_p_n_low = r_n_low._derivatives(r_n_low.state)[4]

        # Depleted nitrogen stimulates polymer synthesis derivative
        assert d_p_n_low > d_p_n_high


