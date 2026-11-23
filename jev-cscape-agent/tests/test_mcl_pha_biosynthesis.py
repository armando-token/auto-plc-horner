"""Industrial Medium-Chain-Length Polyhydroxyalkanoate (mcl-PHA) Biosynthesis Unit Test Suite.

Work Package: W290 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification sections:
1. Section 1: Model Initialization, Configuration & Parameter Validation
2. Section 2: Pseudomonas putida Growth Kinetics & Fatty Acid Coupling
3. Section 3: Tunable C10 Monomer Fraction Dynamics (50-80 mol%)
4. Section 4: Coupled 6-State ODE Discretization & RK4 Numerical Solver Stability
5. Section 5: Analytical Elemental & Mass Conservation Residuals (< 1e-10)
6. Section 6: Process Safety Trips & Strict Fault Hierarchy (0xF901..0xF904)
7. Section 7: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
8. Section 8: Horner OCS Register Space Synchronization (%R2510..%R2517, %M585..%M587)
9. Section 9: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
10. Section 10: Anti-Ladder Security Guard Rejection (Contacts, Coils, Keywords)
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

from jev_cscape.simulation.mcl_pha_biosynthesis import (
    BioMclPhaReactor,
    COIL_MCL_PHA_ACTIVE,
    COIL_MCL_PHA_AERATION_NORMAL,
    COIL_MCL_PHA_FEED_ACTIVE,
    COIL_MCL_PHA_TRIP_ALARM,
    DIAG_ERR_AERATION_STARVATION,
    DIAG_ERR_DO_STARVATION,
    DIAG_ERR_NITROGEN_DEPLETION,
    DIAG_ERR_NITROGEN_STARVATION,
    DIAG_ERR_OXYGEN_STARVATION,
    DIAG_ERR_SUBSTRATE_OVERACCUMULATION,
    DIAG_ERR_SUBSTRATE_TOXICITY,
    DIAG_ERR_THERMAL_EXCURSION,
    DIAG_OK,
    DiagnosticCode,
    MCL_PHA_BIOSYNTHESIS_PURE_ST_POU,
    MCL_PHA_BIOSYNTHESIS_SYNC_POU,
    MCL_PHA_PURE_ST_POU,
    MclPhaBiosynthesisConfig,
    MclPhaBiosynthesisReactor,
    MclPhaBiosynthesisState,
    MclPhaBiosynthesisSync,
    MclPhaConfig,
    MclPhaDiagnosticCode,
    MclPhaEngine,
    MclPhaLogicUnit,
    MclPhaModel,
    MclPhaPlantModel,
    MclPhaReactor,
    MclPhaSimulator,
    MclPhaState,
    MclPhaStatusBits,
    MclPhaTripCode,
    REG_MCL_PHA_BIOMASS,
    REG_MCL_PHA_BIOMASS_SCALED,
    REG_MCL_PHA_C10_MOL_PCT,
    REG_MCL_PHA_C10_MOL_PCT_SCALED,
    REG_MCL_PHA_DIAGNOSTIC_CODE,
    REG_MCL_PHA_DO,
    REG_MCL_PHA_DO_SCALED,
    REG_MCL_PHA_NITROGEN,
    REG_MCL_PHA_NITROGEN_SCALED,
    REG_MCL_PHA_POLYMER,
    REG_MCL_PHA_POLYMER_SCALED,
    REG_MCL_PHA_SUBSTRATE,
    REG_MCL_PHA_SUBSTRATE_SCALED,
    REG_MCL_PHA_TEMP,
    REG_MCL_PHA_TEMP_SCALED,
    ST_PROGRAM_MCL_PHA_BIOSYNTHESIS_SYNC,
    run_mcl_pha_biosynthesis_verification,
    run_mcl_pha_verification,
    verify_mcl_pha_biosynthesis_pure_st,
    verify_mcl_pha_pure_st,
)


# ============================================================================
# Section 1: Model Initialization, Configuration & Parameter Validation
# ============================================================================

class TestSection01ModelInitializationAndConfig:
    """Verify default configurations, state initializations, and class aliases."""

    def test_default_config_parameters(self) -> None:
        """MclPhaConfig default kinetic parameters match Pseudomonas putida specifications."""
        cfg = MclPhaConfig()
        assert math.isclose(cfg.mu_max, 0.38, rel_tol=1e-6)
        assert math.isclose(cfg.ks_s, 0.40, rel_tol=1e-6)
        assert math.isclose(cfg.ki_s, 28.0, rel_tol=1e-6)
        assert math.isclose(cfg.ks_n, 0.04, rel_tol=1e-6)
        assert math.isclose(cfg.ks_do, 5.0, rel_tol=1e-6)
        assert math.isclose(cfg.kd, 0.01, rel_tol=1e-6)
        assert math.isclose(cfg.q_p_max, 0.18, rel_tol=1e-6)
        assert math.isclose(cfg.ks_p, 0.50, rel_tol=1e-6)
        assert math.isclose(cfg.ki_n_p, 0.05, rel_tol=1e-6)
        assert math.isclose(cfg.y_xs, 0.52, rel_tol=1e-6)
        assert math.isclose(cfg.y_xn, 10.5, rel_tol=1e-6)
        assert math.isclose(cfg.y_ps, 0.45, rel_tol=1e-6)
        assert math.isclose(cfg.kla, 120.0, rel_tol=1e-6)
        assert math.isclose(cfg.c10_target_mol_pct, 65.0, rel_tol=1e-6)
        assert math.isclose(cfg.k_c10_rate, 0.25, rel_tol=1e-6)
        assert math.isclose(cfg.target_temperature_c, 30.0, rel_tol=1e-6)

    def test_custom_config_parameters(self) -> None:
        """MclPhaConfig accepts custom overrides."""
        cfg = MclPhaConfig(
            mu_max=0.42,
            ks_s=0.75,
            ki_s=25.0,
            y_xs=0.55,
            target_temperature_c=32.0,
        )
        assert cfg.mu_max == 0.42
        assert cfg.ks_s == 0.75
        assert cfg.ki_s == 25.0
        assert cfg.y_xs == 0.55
        assert cfg.target_temperature_c == 32.0
        assert cfg.ks_n == 0.04

    def test_default_state_initialization(self) -> None:
        """MclPhaState initializes with nominal bioreactor operating conditions."""
        state = MclPhaState()
        assert math.isclose(state.biomass_x, 2.0, rel_tol=1e-6)
        assert math.isclose(state.substrate_s, 15.0, rel_tol=1e-6)
        assert math.isclose(state.nitrogen_n, 1.0, rel_tol=1e-6)
        assert math.isclose(state.dissolved_oxygen_c_do, 80.0, rel_tol=1e-6)
        assert math.isclose(state.dissolved_oxygen_pct, 80.0, rel_tol=1e-6)
        assert math.isclose(state.polymer_p_mcl, 0.2, rel_tol=1e-6)
        assert math.isclose(state.polymer_poly, 0.2, rel_tol=1e-6)
        assert math.isclose(state.c10_fraction_f_c10, 65.0, rel_tol=1e-6)
        assert math.isclose(state.c10_mol_pct, 65.0, rel_tol=1e-6)
        assert math.isclose(state.temperature_c, 30.0, rel_tol=1e-6)

    def test_reactor_initialization_defaults(self) -> None:
        """MclPhaBiosynthesisReactor initializes cleanly with nominal state and healthy registers."""
        table = RegisterTable()
        reactor = MclPhaBiosynthesisReactor(register_table=table)
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.diagnostic_code == 0x0000
        assert reactor.trip_active is False
        assert reactor.feed_active is True
        assert reactor.cycle_count == 0
        assert reactor.conservation_residual == 0.0
        assert reactor.state.biomass_x == 2.0
        assert reactor.state.substrate_s == 15.0

        # Register table populated immediately upon init
        # %R2510: Biomass x100 (2.0 -> 200)
        assert table.read_word(REG_MCL_PHA_BIOMASS_SCALED) == 200
        # %R2511: Substrate x100 (15.0 -> 1500)
        assert table.read_word(REG_MCL_PHA_SUBSTRATE_SCALED) == 1500
        # %R2512: Nitrogen x100 (1.0 -> 100)
        assert table.read_word(REG_MCL_PHA_NITROGEN_SCALED) == 100
        # %R2513: DO x10 (80.0 -> 800)
        assert table.read_word(REG_MCL_PHA_DO_SCALED) == 800
        # %R2514: Polymer x100 (0.2 -> 20)
        assert table.read_word(REG_MCL_PHA_POLYMER_SCALED) == 20
        # %R2515: C10 Mol% x10 (65.0 -> 650)
        assert table.read_word(REG_MCL_PHA_C10_MOL_PCT_SCALED) == 650
        # %R2516: Temp x10 (30.0 -> 300)
        assert table.read_word(REG_MCL_PHA_TEMP_SCALED) == 300
        # %R2517: Diagnostic Code -> 0
        assert table.read_word(REG_MCL_PHA_DIAGNOSTIC_CODE) == 0

        # Discrete Coils %M585..%M587
        assert table.read_bit(COIL_MCL_PHA_ACTIVE) is True
        assert table.read_bit(COIL_MCL_PHA_AERATION_NORMAL) is True
        assert table.read_bit(COIL_MCL_PHA_TRIP_ALARM) is False

    def test_class_and_alias_identities(self) -> None:
        """Class aliases resolve to canonical classes."""
        assert BioMclPhaReactor is MclPhaBiosynthesisReactor
        assert MclPhaReactor is MclPhaBiosynthesisReactor
        assert MclPhaSimulator is MclPhaBiosynthesisReactor
        assert MclPhaEngine is MclPhaBiosynthesisReactor
        assert MclPhaLogicUnit is MclPhaBiosynthesisReactor
        assert MclPhaModel is MclPhaBiosynthesisReactor
        assert MclPhaPlantModel is MclPhaBiosynthesisReactor

        assert MclPhaBiosynthesisConfig is MclPhaConfig
        assert MclPhaBiosynthesisState is MclPhaState
        assert MclPhaTripCode is DiagnosticCode
        assert MclPhaDiagnosticCode is DiagnosticCode


# ============================================================================
# Section 2: Pseudomonas putida Growth Kinetics & Fatty Acid Coupling
# ============================================================================

class TestSection02PseudomonasPutidaGrowthKinetics:
    """Verify dual Monod-Haldane growth kinetics and fatty acid consumption."""

    def test_derivatives_shape_and_finite(self) -> None:
        """_derivatives returns exactly 6 finite floating point rates."""
        reactor = MclPhaBiosynthesisReactor()
        derivs = reactor._derivatives(reactor.state)
        assert len(derivs) == 6
        assert all(isinstance(v, float) for v in derivs)
        assert all(not math.isnan(v) for v in derivs)
        assert all(not math.isinf(v) for v in derivs)

    def test_active_growth_kinetics(self) -> None:
        """Under nominal growth conditions, biomass increases while substrates are consumed."""
        reactor = MclPhaBiosynthesisReactor()
        d_x, d_s, d_n, d_do, d_p, d_c10 = reactor._derivatives(reactor.state)

        # Biomass growth rate must be positive
        assert d_x > 0.0
        # Substrate and nitrogen rates must be negative (consumption)
        assert d_s < 0.0
        assert d_n < 0.0
        # Polymer accumulation must be active
        assert d_p > 0.0

    def test_fatty_acid_haldane_toxicity_inhibition(self) -> None:
        """Substrate toxicity Haldane term exerts inhibition at high fatty acid concentrations."""
        reactor = MclPhaBiosynthesisReactor()

        state_mod = MclPhaState(substrate_s=10.0)
        d_mod = reactor._derivatives(state_mod)
        mu_mod = d_mod[0] / state_mod.biomass_x

        state_high = MclPhaState(substrate_s=35.0)
        d_high = reactor._derivatives(state_high)
        mu_high = d_high[0] / state_high.biomass_x

        # Haldane inhibition at 35 g/L reduces specific growth rate compared to optimal 10 g/L
        assert mu_high < mu_mod

    def test_nitrogen_exhaustion_promotes_mcl_pha_accumulation(self) -> None:
        """Nitrogen depletion strongly accelerates specific mcl-PHA accumulation rate."""
        reactor = MclPhaBiosynthesisReactor()

        # High nitrogen (2.5 g/L) - active growth, lower specific PHA synthesis
        state_high_n = MclPhaState(nitrogen_n=2.5)
        d_p_high_n = reactor._derivatives(state_high_n)[4]

        # Low nitrogen (0.005 g/L) - lipid accumulation phase
        state_low_n = MclPhaState(nitrogen_n=0.005)
        d_p_low_n = reactor._derivatives(state_low_n)[4]

        assert d_p_low_n > d_p_high_n * 5.0

    def test_stoichiometric_yield_coupling(self) -> None:
        """Fatty acid consumption balances biomass yield, polymer yield, and maintenance."""
        reactor = MclPhaBiosynthesisReactor()
        d_x, d_s, d_n, d_do, d_p, d_c10 = reactor._derivatives(reactor.state)

        # In _derivatives:
        # r_s_cons = (r_x / y_xs) + (r_p / y_ps) + m_s * x
        # d_s = feed_s - r_s_cons (with feed_s = 0)
        # Therefore, -d_s must equal consumption
        r_x = d_x + reactor.cfg.kd * reactor.state.biomass_x
        r_p = d_p + reactor.cfg.kd_p * reactor.state.polymer_p_mcl
        expected_r_s = (r_x / reactor.cfg.y_xs) + (r_p / reactor.cfg.y_ps) + reactor.cfg.m_s * reactor.state.biomass_x
        assert math.isclose(-d_s, expected_r_s, rel_tol=1e-5)

        expected_r_n = r_x / reactor.cfg.y_xn
        assert math.isclose(-d_n, expected_r_n, rel_tol=1e-5)


# ============================================================================
# Section 3: Tunable C10 Monomer Fraction Dynamics (50-80 mol%)
# ============================================================================

class TestSection03TunableC10MonomerFraction:
    """Verify continuous tuning of 3-hydroxydecanoate (C10) monomer fraction within 50-80 mol%."""

    def test_c10_fraction_clamped_within_spec_range(self) -> None:
        """set_target_c10_fraction strictly clamps inputs to target [50.0, 80.0] mol% range."""
        reactor = MclPhaBiosynthesisReactor()

        # In range
        for target in [50.0, 55.0, 65.0, 75.0, 80.0]:
            reactor.set_target_c10_fraction(target)
            assert reactor.cfg.c10_target_mol_pct == target
            assert 50.0 <= reactor.cfg.c10_target_mol_pct <= 80.0

        # Below range -> clamped to 50.0
        reactor.set_target_c10_fraction(35.0)
        assert reactor.cfg.c10_target_mol_pct == 50.0

        # Above range -> clamped to 80.0
        reactor.set_target_c10_fraction(95.0)
        assert reactor.cfg.c10_target_mol_pct == 80.0

    def test_c10_relaxation_derivative_dynamics(self) -> None:
        """dF_C10/dt drives current fraction towards target asymptotically."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.set_target_c10_fraction(75.0)

        # Current fraction (65.0) < target (75.0) -> positive derivative
        derivs = reactor._derivatives(reactor.state)
        d_c10 = derivs[5]
        assert d_c10 > 0.0
        assert math.isclose(d_c10, 0.25 * (75.0 - 65.0), rel_tol=1e-6)

        # Set target below current fraction (55.0 < 65.0) -> negative derivative
        reactor.set_target_c10_fraction(55.0)
        derivs2 = reactor._derivatives(reactor.state)
        d_c10_neg = derivs2[5]
        assert d_c10_neg < 0.0
        assert math.isclose(d_c10_neg, 0.25 * (55.0 - 65.0), rel_tol=1e-6)

    def test_multi_step_c10_convergence(self) -> None:
        """Advancing multiple RK4 steps shifts C10 fraction towards target monotonically."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.set_target_c10_fraction(75.0)
        c0 = reactor.state.c10_fraction_f_c10

        for _ in range(10):
            reactor.rk4_step(dt_h=0.05)

        c1 = reactor.state.c10_fraction_f_c10
        assert c1 > c0
        assert 50.0 <= c1 <= 80.0


# ============================================================================
# Section 4: Coupled 6-State ODE Discretization & RK4 Numerical Solver Stability
# ============================================================================

class TestSection04CoupledOdeAndRk4SolverStability:
    """Verify RK4 convergence, non-negativity enforcement, and solver stability."""

    def test_rk4_step_advances_state(self) -> None:
        """Single rk4_step updates all state variables deterministically."""
        reactor = MclPhaBiosynthesisReactor()
        s0_x = reactor.state.biomass_x
        s0_s = reactor.state.substrate_s
        s0_n = reactor.state.nitrogen_n
        s0_p = reactor.state.polymer_p_mcl

        reactor.rk4_step(dt_h=0.02)

        assert reactor.state.biomass_x > s0_x
        assert reactor.state.substrate_s < s0_s
        assert reactor.state.nitrogen_n < s0_n
        assert reactor.state.polymer_p_mcl > s0_p

    def test_state_non_negativity_clamping(self) -> None:
        """RK4 step enforces non-negativity clamping on all concentrations."""
        low_state = MclPhaState(
            biomass_x=10.0,
            substrate_s=0.001,
            nitrogen_n=0.0001,
            polymer_p_mcl=0.001,
        )
        reactor = MclPhaBiosynthesisReactor(initial_state=low_state)
        reactor.rk4_step(dt_h=0.1)

        assert reactor.state.biomass_x >= 0.0
        assert reactor.state.substrate_s >= 0.0
        assert reactor.state.nitrogen_n >= 0.0
        assert reactor.state.polymer_p_mcl >= 0.0
        assert 50.0 <= reactor.state.c10_fraction_f_c10 <= 80.0

    def test_rk4_solver_step_size_convergence(self) -> None:
        """Varying dt (0.01 vs 0.02) shows smooth numerical convergence and close agreement."""
        r1 = MclPhaBiosynthesisReactor()
        for _ in range(10):
            r1.rk4_step(dt_h=0.01)

        r2 = MclPhaBiosynthesisReactor()
        for _ in range(5):
            r2.rk4_step(dt_h=0.02)

        assert math.isclose(r1.state.biomass_x, r2.state.biomass_x, rel_tol=0.01)
        assert math.isclose(r1.state.polymer_p_mcl, r2.state.polymer_p_mcl, rel_tol=0.01)

    def test_derivatives_freeze_on_trip_active(self) -> None:
        """When trip_active is True, derivatives immediately freeze at zero."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.trip_active = True
        derivs = reactor._derivatives(reactor.state)
        assert derivs == (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)


# ============================================================================
# Section 5: Analytical Elemental & Mass Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection05ElementalMassConservationResiduals:
    """Verify elemental mass balance and computational conservation residuals (< 1e-10)."""

    def test_conservation_residual_single_step(self) -> None:
        """Mass conservation residual is strictly below 1e-10."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.rk4_step(dt_h=0.01)
        assert reactor.conservation_residual < 1.0e-10
        assert reactor.conservation_residual >= 0.0

    def test_conservation_residual_multi_step_stability(self) -> None:
        """Conservation residual remains bounded < 1e-10 over 50 consecutive steps."""
        reactor = MclPhaBiosynthesisReactor()
        for _ in range(50):
            reactor.rk4_step(dt_h=0.01)
            assert reactor.conservation_residual < 1.0e-10


# ============================================================================
# Section 6: Process Safety Trips & Strict Fault Hierarchy (0xF901..0xF904)
# ============================================================================

class TestSection06ProcessSafetyTripsAndHierarchy:
    """Verify safety trips 0xF901..0xF904 and priority hierarchy: 0xF901 > 0xF902 > 0xF903 > 0xF904."""

    def test_substrate_toxicity_trip_0xf901(self) -> None:
        """Substrate S > 25.0 g/L asserts 0xF901 and disables feed."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.state.substrate_s = 26.5
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_SUBSTRATE_TOXICITY
        assert reactor.diagnostic_code == 0xF901
        assert reactor.feed_active is False
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_TRIP_ALARM) is True

    def test_nitrogen_starvation_trip_0xf902(self) -> None:
        """Nitrogen depletion starvation (N < 0.005 g/L with starvation_trip_enabled) asserts 0xF902."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.cfg.starvation_trip_enabled = True
        reactor.state.nitrogen_n = 0.002
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_NITROGEN_STARVATION
        assert reactor.diagnostic_code == 0xF902
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_TRIP_ALARM) is True

    def test_nitrogen_depletion_healthy_when_trip_disabled(self) -> None:
        """When starvation_trip_enabled is False, low nitrogen triggers lipid accumulation without trip."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.cfg.starvation_trip_enabled = False
        reactor.state.nitrogen_n = 0.002
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is False
        assert reactor.lipid_accumulation_phase is True
        assert reactor.diagnostic_code == DIAG_OK

    def test_thermal_excursion_trip_0xf903(self) -> None:
        """Temperature > 35.0 °C asserts 0xF903 THERMAL_EXCURSION."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.state.temperature_c = 36.5
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
        assert reactor.diagnostic_code == 0xF903
        assert reactor.cooling_interlock_tripped is True
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_TRIP_ALARM) is True

    def test_oxygen_starvation_trip_0xf904(self) -> None:
        """Dissolved oxygen < 5.0% asserts 0xF904 OXYGEN_STARVATION."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.state.dissolved_oxygen_c_do = 3.5
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_OXYGEN_STARVATION
        assert reactor.diagnostic_code == 0xF904
        assert reactor.aeration_interlock_tripped is True
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_TRIP_ALARM) is True

    def test_strict_priority_hierarchy(self) -> None:
        """Priority order 0xF901 > 0xF902 > 0xF903 > 0xF904 is strictly obeyed."""
        # 0xF901 preempts 0xF902, 0xF903, 0xF904
        r1 = MclPhaBiosynthesisReactor()
        r1.cfg.starvation_trip_enabled = True
        r1.state.substrate_s = 28.0
        r1.state.nitrogen_n = 0.001
        r1.state.temperature_c = 38.0
        r1.state.dissolved_oxygen_c_do = 2.0
        r1.rk4_step(dt_h=0.01)
        assert r1.diagnostic_code == DIAG_ERR_SUBSTRATE_TOXICITY
        assert r1.diagnostic_code == 0xF901

        # 0xF902 preempts 0xF903 and 0xF904
        r2 = MclPhaBiosynthesisReactor()
        r2.cfg.starvation_trip_enabled = True
        r2.state.substrate_s = 15.0
        r2.state.nitrogen_n = 0.001
        r2.state.temperature_c = 38.0
        r2.state.dissolved_oxygen_c_do = 2.0
        r2.rk4_step(dt_h=0.01)
        assert r2.diagnostic_code == DIAG_ERR_NITROGEN_STARVATION
        assert r2.diagnostic_code == 0xF902

        # 0xF903 preempts 0xF904
        r3 = MclPhaBiosynthesisReactor()
        r3.state.substrate_s = 15.0
        r3.state.nitrogen_n = 1.0
        r3.state.temperature_c = 38.0
        r3.state.dissolved_oxygen_c_do = 2.0
        r3.rk4_step(dt_h=0.01)
        assert r3.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
        assert r3.diagnostic_code == 0xF903


# ============================================================================
# Section 7: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
# ============================================================================

class TestSection07DiagnosticCodeSignedUnsignedAndMasking:
    """Verify 16-bit signed/unsigned comparisons, bitwise masking, and hash compliance."""

    def test_diagnostic_code_hex_values(self) -> None:
        """Hex integer values match W290 specification."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_SUBSTRATE_TOXICITY == 0xF901
        assert DIAG_ERR_SUBSTRATE_OVERACCUMULATION == 0xF901
        assert DIAG_ERR_NITROGEN_STARVATION == 0xF902
        assert DIAG_ERR_NITROGEN_DEPLETION == 0xF902
        assert DIAG_ERR_THERMAL_EXCURSION == 0xF903
        assert DIAG_ERR_DO_STARVATION == 0xF904
        assert DIAG_ERR_AERATION_STARVATION == 0xF904
        assert DIAG_ERR_OXYGEN_STARVATION == 0xF904

    def test_signed_16bit_equality(self) -> None:
        """Signed two's complement 16-bit comparisons match."""
        # 0xF901 = 63745 -> 63745 - 65536 = -1791
        assert DIAG_ERR_SUBSTRATE_TOXICITY == 0xF901
        assert DIAG_ERR_SUBSTRATE_TOXICITY == 63745
        assert DIAG_ERR_SUBSTRATE_TOXICITY == -1791

        # 0xF902 = 63746 -> -1790
        assert DIAG_ERR_NITROGEN_STARVATION == 0xF902
        assert DIAG_ERR_NITROGEN_STARVATION == -1790

        # 0xF903 = 63747 -> -1789
        assert DIAG_ERR_THERMAL_EXCURSION == 0xF903
        assert DIAG_ERR_THERMAL_EXCURSION == -1789

        # 0xF904 = 63748 -> -1788
        assert DIAG_ERR_DO_STARVATION == 0xF904
        assert DIAG_ERR_DO_STARVATION == -1788

    def test_bitwise_masking_support(self) -> None:
        """Bitwise AND operations with 0xFFFF transparently supported."""
        assert (DIAG_ERR_SUBSTRATE_TOXICITY & 0xFFFF) == 0xF901
        assert (0xFFFF & DIAG_ERR_NITROGEN_STARVATION) == 0xF902

    def test_hash_and_formatting(self) -> None:
        """Hash and string formatting work cleanly."""
        assert hash(DIAG_ERR_SUBSTRATE_TOXICITY) == hash(0xF901)
        assert str(DIAG_ERR_SUBSTRATE_TOXICITY) == "0xF901"
        assert repr(DIAG_ERR_SUBSTRATE_TOXICITY) == "DiagnosticCode(0xF901)"

    def test_status_bits_enum(self) -> None:
        """MclPhaStatusBits flags combine properly."""
        flags = MclPhaStatusBits.BIOMASS_GROWTH_ACTIVE | MclPhaStatusBits.FEED_DOSING_ON
        assert bool(flags & MclPhaStatusBits.BIOMASS_GROWTH_ACTIVE) is True
        assert bool(flags & MclPhaStatusBits.PROCESS_TRIP_ACTIVE) is False


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization (%R2510..%R2517)
# ============================================================================

class TestSection08HornerOcsRegisterSynchronization:
    """Verify Horner OCS register space synchronization (%R2510..%R2517, %M585..%M587)."""

    def test_nominal_registers_synchronization(self) -> None:
        """Nominal state writes scaled INT16 words to %R2510..%R2517."""
        table = RegisterTable()
        reactor = MclPhaBiosynthesisReactor(register_table=table)
        reactor.reset()

        # %R2510: Biomass x100 (2.0 -> 200)
        assert table.read_word(REG_MCL_PHA_BIOMASS_SCALED) == 200
        # %R2511: Substrate x100 (15.0 -> 1500)
        assert table.read_word(REG_MCL_PHA_SUBSTRATE_SCALED) == 1500
        # %R2512: Nitrogen x100 (1.0 -> 100)
        assert table.read_word(REG_MCL_PHA_NITROGEN_SCALED) == 100
        # %R2513: DO x10 (80.0 -> 800)
        assert table.read_word(REG_MCL_PHA_DO_SCALED) == 800
        # %R2514: Polymer x100 (0.2 -> 20)
        assert table.read_word(REG_MCL_PHA_POLYMER_SCALED) == 20
        # %R2515: C10 Mol% x10 (65.0 -> 650)
        assert table.read_word(REG_MCL_PHA_C10_MOL_PCT_SCALED) == 650
        # %R2516: Temp x10 (30.0 -> 300)
        assert table.read_word(REG_MCL_PHA_TEMP_SCALED) == 300
        # %R2517: Diagnostic Code -> 0
        assert table.read_word(REG_MCL_PHA_DIAGNOSTIC_CODE) == 0

        assert table.read_bit(COIL_MCL_PHA_ACTIVE) is True
        assert table.read_bit(COIL_MCL_PHA_AERATION_NORMAL) is True
        assert table.read_bit(COIL_MCL_PHA_TRIP_ALARM) is False

    def test_trip_registers_synchronization(self) -> None:
        """Fault trip updates %R2517 and %M587 alarm coil."""
        table = RegisterTable()
        reactor = MclPhaBiosynthesisReactor(register_table=table)
        reactor.state.substrate_s = 27.0
        reactor.rk4_step(dt_h=0.01)

        assert (table.read_uword(REG_MCL_PHA_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF901
        assert table.read_bit(COIL_MCL_PHA_ACTIVE) is False
        assert table.read_bit(COIL_MCL_PHA_TRIP_ALARM) is True

    def test_privilege_modes(self) -> None:
        """sync_to_registers works with both USER and SYSTEM privileges."""
        table = RegisterTable()
        reactor = MclPhaBiosynthesisReactor(register_table=table)
        reactor.sync_to_registers(table, privilege=PrivilegeMode.USER)
        assert table.read_word(REG_MCL_PHA_TEMP_SCALED) == 300

        reactor.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word(REG_MCL_PHA_TEMP_SCALED) == 300


# ============================================================================
# Section 9: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection09PureStructuredTextPouValidation:
    """Verify IEC 61131-3 Structured Text compliance and AST memory bindings."""

    def test_pure_st_pou_constants(self) -> None:
        """MCL_PHA_BIOSYNTHESIS_PURE_ST_POU contains valid POU text."""
        assert isinstance(ST_PROGRAM_MCL_PHA_BIOSYNTHESIS_SYNC, str)
        assert ST_PROGRAM_MCL_PHA_BIOSYNTHESIS_SYNC == MCL_PHA_BIOSYNTHESIS_PURE_ST_POU
        assert "PROGRAM MclPhaBiosynthesisSync" in ST_PROGRAM_MCL_PHA_BIOSYNTHESIS_SYNC
        assert "END_PROGRAM" in ST_PROGRAM_MCL_PHA_BIOSYNTHESIS_SYNC

    def test_st_parser_syntax_validation(self) -> None:
        """STParser.validate_code reports SUCCESS for MclPhaBiosynthesisSync."""
        val = STParser.validate_code(ST_PROGRAM_MCL_PHA_BIOSYNTHESIS_SYNC)
        assert val.status == AgentStatus.SUCCESS

    def test_st_parser_ast_variable_bindings(self) -> None:
        """Registers %R2510..%R2517 and coils %M585..%M587 bound in AST."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(ST_PROGRAM_MCL_PHA_BIOSYNTHESIS_SYNC)
        assert pou is not None
        assert pou.name == "MclPhaBiosynthesisSync"

        required_regs = [
            "%R2510", "%R2511", "%R2512", "%R2513",
            "%R2514", "%R2515", "%R2516", "%R2517",
            "%M585", "%M586", "%M587",
        ]
        for reg in required_regs:
            assert reg in pou.bound_registers, f"Missing binding for {reg}"

    def test_verify_mcl_pha_pure_st_function(self) -> None:
        """verify_mcl_pha_biosynthesis_pure_st returns True."""
        assert verify_mcl_pha_biosynthesis_pure_st() is True
        assert verify_mcl_pha_pure_st() is True


# ============================================================================
# Section 10: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection10AntiLadderSecurityGuard:
    """Verify forbidden ladder logic constructs are rejected with LadderForbiddenError."""

    def test_reject_ladder_contacts(self) -> None:
        """Contact symbols ---[ ]--- raise LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_coils(self) -> None:
        """Coil symbols ---( )--- raise LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_keywords(self) -> None:
        """Keywords RUNG, NETWORK, XIC, OTE raise LadderForbiddenError."""
        for kw in ["RUNG 1", "NETWORK 5", "XIC Bit0", "OTE Out0"]:
            bad_code = f"PROGRAM Bad\nVAR x: BOOL; END_VAR\n{kw}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_code)

    def test_pure_st_pou_passes_security_guard(self) -> None:
        """Official mcl-PHA ST POU passes SecurityGuard cleanly."""
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_MCL_PHA_BIOSYNTHESIS_SYNC)


# ============================================================================
# Section 11: ILogicUnit Compliance & Multi-Cycle Scan Execution
# ============================================================================

class TestSection11LogicUnitComplianceAndScanCycle:
    """Verify ILogicUnit interface compliance, scan_step, step, execute, and reset."""

    def test_ilogicunit_interface_attributes(self) -> None:
        """MclPhaBiosynthesisReactor fulfills ILogicUnit properties."""
        reactor = MclPhaBiosynthesisReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "MclPhaBiosynthesisReactor"
        assert reactor.priority == 50
        assert reactor.is_enabled is True

    def test_scan_step_nominal(self) -> None:
        """scan_step returns AgentStatus.SUCCESS when healthy."""
        reactor = MclPhaBiosynthesisReactor()
        res = reactor.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert reactor.cycle_count == 1
        assert "mcl-PHA State:" in res.details
        assert res.data["trip_active"] is False

    def test_scan_step_with_context(self) -> None:
        """scan_step accepts ScanContext gracefully."""
        reactor = MclPhaBiosynthesisReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        res = reactor.scan_step(ctx)
        assert res.status == AgentStatus.SUCCESS
        assert reactor.cycle_count == 1

    def test_step_and_execute_methods(self) -> None:
        """step() and execute() advance cycle count."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.step()
        assert reactor.cycle_count == 1

        ctx = ScanContext(cycle=2, dt_ms=20.0, elapsed_time_ms=40.0, dt=0.02)
        reactor.execute(ctx)
        assert reactor.cycle_count == 2

        reactor.execute()
        assert reactor.cycle_count == 3

    def test_scan_step_faulted(self) -> None:
        """scan_step returns AgentStatus.FAILED when trip active."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.state.temperature_c = 38.0
        res = reactor.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_ERR_THERMAL_EXCURSION)
        assert res.data["trip_active"] is True

    def test_reset_method_restores_state(self) -> None:
        """reset() restores initial state and clears trips."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.state.temperature_c = 40.0
        reactor.scan_step()
        assert reactor.trip_active is True

        reactor.reset()
        assert reactor.trip_active is False
        assert reactor.state.temperature_c == 30.0
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.reg_table.read_bit(COIL_MCL_PHA_ACTIVE) is True

    def test_continuous_scan_soak_50_cycles(self) -> None:
        """50 continuous scan steps execute with zero NaN and bounded state."""
        reactor = MclPhaBiosynthesisReactor()
        reactor.reset()

        for _ in range(50):
            res = reactor.scan_step()
            assert res.status == AgentStatus.SUCCESS

        assert not math.isnan(reactor.state.biomass_x)
        assert not math.isnan(reactor.state.polymer_p_mcl)
        assert not math.isinf(reactor.state.biomass_x)
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.conservation_residual < 1.0e-10


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Runner Execution
# ============================================================================

class TestSection12VerificationSuiteExecution:
    """Verify run_mcl_pha_biosynthesis_verification output contract and evidence emission."""

    def test_run_verification_suite_success(self, tmp_path: Path) -> None:
        """Verification suite runs all 9 stages cleanly and writes evidence JSON."""
        evidence_file = tmp_path / "mcl_pha_test_evidence.json"
        res = run_mcl_pha_biosynthesis_verification(output_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "data" in res
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert evidence_file.exists()

        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["stages"]) == 9

    def test_runner_alias_identity(self) -> None:
        """run_mcl_pha_verification resolves to run_mcl_pha_biosynthesis_verification."""
        assert run_mcl_pha_verification is run_mcl_pha_biosynthesis_verification
