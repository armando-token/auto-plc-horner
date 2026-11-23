"""Industrial Polyhydroxyalkanoate Copolymer P(3HB-co-4HB) Biosynthesis Unit Test Suite.

Work Package: W293 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification sections:
1. Section 1: Model Initialization, Configuration & Parameter Validation
2. Section 2: Cupriavidus necator Growth Kinetics & Dual Carbon Substrate Coupling (S1, S2, N)
3. Section 3: Precursor Dosing, Consumption & Tunable 4HB Monomer Fraction Dynamics (5.0 to 40.0 mol%)
4. Section 4: Coupled 6-State ODE Discretization & RK4 Numerical Solver Stability
5. Section 5: Analytical Elemental & Mass Conservation Residuals (< 1e-10)
6. Section 6: Process Safety Trips & Strict Fault Hierarchy (0xF911..0xF914)
7. Section 7: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
8. Section 8: Horner OCS Register Space Synchronization (%R2540..%R2547, %M592..%M594)
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

from jev_cscape.simulation.p3hb_4hb_biosynthesis import (
    BioP3hb4hbReactor,
    COIL_P3HB_4HB_ACTIVE,
    COIL_P3HB_4HB_BIOSYNTHESIS_TRIP_ALARM,
    COIL_P3HB_4HB_FEED_PERMISSIVE,
    COIL_P3HB_4HB_FERMENTATION_ACTIVE,
    COIL_P3HB_4HB_PRECURSOR_ACTIVE,
    COIL_P3HB_4HB_PRECURSOR_PERMISSIVE,
    COIL_P3HB_4HB_SYNTHESIS_ACTIVE,
    COIL_P3HB_4HB_TRIP_ALARM,
    DIAG_ERR_AERATION_STARVATION,
    DIAG_ERR_DISSOLVED_OXYGEN_STARVATION,
    DIAG_ERR_DO_STARVATION,
    DIAG_ERR_NITROGEN_DEPLETION,
    DIAG_ERR_NITROGEN_STARVATION,
    DIAG_ERR_OXYGEN_STARVATION,
    DIAG_ERR_PRECURSOR_OVERCONC,
    DIAG_ERR_PRECURSOR_TOXIC,
    DIAG_ERR_PRECURSOR_TOXICITY,
    DIAG_ERR_S2_TOXICITY,
    DIAG_ERR_THERMAL_EXCURSION,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_OK,
    DiagnosticCode,
    P3HB_4HB_BIOSYNTHESIS_PURE_ST_POU,
    P3HB_4HB_BIOSYNTHESIS_SYNC_POU,
    P3HB_4HB_PURE_ST_POU,
    P3HB_4HB_SYNC_POU,
    P3hb4hbBiosynthesisConfig,
    P3hb4hbBiosynthesisReactor,
    P3hb4hbBiosynthesisState,
    P3hb4hbBiosynthesisSync,
    P3hb4hbConfig,
    P3hb4hbDiagnosticCode,
    P3hb4hbEngine,
    P3hb4hbLogicUnit,
    P3hb4hbModel,
    P3hb4hbPlantModel,
    P3hb4hbReactor,
    P3hb4hbSimulator,
    P3hb4hbState,
    P3hb4hbStatusBits,
    P3hb4hbTripCode,
    REG_P3HB_4HB_4HB_MOL_PCT,
    REG_P3HB_4HB_4HB_MOL_PCT_SCALED,
    REG_P3HB_4HB_BDO,
    REG_P3HB_4HB_BDO_SCALED,
    REG_P3HB_4HB_BIOMASS,
    REG_P3HB_4HB_BIOMASS_SCALED,
    REG_P3HB_4HB_DIAGNOSTIC_CODE,
    REG_P3HB_4HB_F_4HB,
    REG_P3HB_4HB_GLUCOSE,
    REG_P3HB_4HB_GLUCOSE_SCALED,
    REG_P3HB_4HB_MOL_PCT,
    REG_P3HB_4HB_N,
    REG_P3HB_4HB_NITROGEN,
    REG_P3HB_4HB_NITROGEN_SCALED,
    REG_P3HB_4HB_P,
    REG_P3HB_4HB_POLYMER,
    REG_P3HB_4HB_POLYMER_SCALED,
    REG_P3HB_4HB_PRECURSOR,
    REG_P3HB_4HB_PRECURSOR_S2,
    REG_P3HB_4HB_PRECURSOR_S2_SCALED,
    REG_P3HB_4HB_S1,
    REG_P3HB_4HB_S2,
    REG_P3HB_4HB_SUBSTRATE,
    REG_P3HB_4HB_SUBSTRATE_S1,
    REG_P3HB_4HB_SUBSTRATE_S1_SCALED,
    REG_P3HB_4HB_TEMP,
    REG_P3HB_4HB_TEMP_SCALED,
    REG_P3HB_4HB_TEMPERATURE,
    REG_P3HB_4HB_X,
    ST_PROGRAM_P3HB_4HB_BIOSYNTHESIS_SYNC,
    run_p3hb_4hb_biosynthesis_verification,
    run_p3hb_4hb_verification,
    verify_p3hb_4hb_biosynthesis_pure_st,
    verify_p3hb_4hb_pure_st,
)


# ============================================================================
# Section 1: Model Initialization, Configuration & Parameter Validation
# ============================================================================

class TestSection01ModelInitializationAndConfig:
    """Verify default configurations, state initializations, and class aliases."""

    def test_default_config_parameters(self) -> None:
        """P3hb4hbConfig default kinetic parameters match Cupriavidus necator specifications."""
        cfg = P3hb4hbConfig()
        assert math.isclose(cfg.mu_max, 0.36, rel_tol=1e-6)
        assert math.isclose(cfg.ks_s1, 0.45, rel_tol=1e-6)
        assert math.isclose(cfg.ks_n, 0.05, rel_tol=1e-6)
        assert math.isclose(cfg.ki_s2, 22.0, rel_tol=1e-6)
        assert math.isclose(cfg.ks_do, 5.0, rel_tol=1e-6)
        assert math.isclose(cfg.kd, 0.01, rel_tol=1e-6)
        assert math.isclose(cfg.q_3hb_max, 0.16, rel_tol=1e-6)
        assert math.isclose(cfg.q_4hb_max, 0.10, rel_tol=1e-6)
        assert math.isclose(cfg.ks_p_s1, 0.50, rel_tol=1e-6)
        assert math.isclose(cfg.ks_p_s2, 0.35, rel_tol=1e-6)
        assert math.isclose(cfg.ki_n_p, 0.05, rel_tol=1e-6)
        assert math.isclose(cfg.y_xs1, 0.48, rel_tol=1e-6)
        assert math.isclose(cfg.y_xn, 10.0, rel_tol=1e-6)
        assert math.isclose(cfg.y_ps1, 0.40, rel_tol=1e-6)
        assert math.isclose(cfg.y_ps2, 0.70, rel_tol=1e-6)
        assert math.isclose(cfg.kla, 120.0, rel_tol=1e-6)
        assert math.isclose(cfg.f_4hb_target_mol_pct, 15.0, rel_tol=1e-6)

    def test_custom_config_parameters(self) -> None:
        """P3hb4hbConfig accepts user-specified parameter overrides."""
        cfg = P3hb4hbConfig(
            mu_max=0.42,
            ks_s1=0.60,
            f_4hb_target_mol_pct=25.0,
            precursor_toxicity_threshold=22.0,
        )
        assert math.isclose(cfg.mu_max, 0.42, rel_tol=1e-6)
        assert math.isclose(cfg.ks_s1, 0.60, rel_tol=1e-6)
        assert math.isclose(cfg.f_4hb_target_mol_pct, 25.0, rel_tol=1e-6)
        assert math.isclose(cfg.precursor_toxicity_threshold, 22.0, rel_tol=1e-6)

    def test_default_state_initialization(self) -> None:
        """P3hb4hbState initial values match standard bioreactor charge."""
        state = P3hb4hbState()
        assert math.isclose(state.biomass_x, 2.5, rel_tol=1e-6)
        assert math.isclose(state.substrate_s1, 30.0, rel_tol=1e-6)
        assert math.isclose(state.precursor_s2, 5.0, rel_tol=1e-6)
        assert math.isclose(state.nitrogen_n, 1.2, rel_tol=1e-6)
        assert math.isclose(state.polymer_p, 0.5, rel_tol=1e-6)
        assert math.isclose(state.monomer_f_4hb, 15.0, rel_tol=1e-6)
        assert math.isclose(state.temperature_c, 30.0, rel_tol=1e-6)
        assert math.isclose(state.dissolved_oxygen_c_do, 80.0, rel_tol=1e-6)

    def test_state_dictionary_serialization(self) -> None:
        """State converts to and from dict cleanly."""
        state = P3hb4hbState(
            biomass_x=4.0,
            substrate_s1=20.0,
            precursor_s2=6.0,
            nitrogen_n=0.8,
            polymer_p=2.0,
            monomer_f_4hb=18.5,
            temperature_c=31.0,
            dissolved_oxygen_c_do=75.0,
        )
        d = state.to_dict()
        assert d["biomass_x"] == 4.0
        assert d["substrate_s1"] == 20.0
        assert d["precursor_s2"] == 6.0
        assert d["nitrogen_n"] == 0.8
        assert d["polymer_p"] == 2.0
        assert d["monomer_f_4hb"] == 18.5

        restored = P3hb4hbState.from_dict(d)
        assert math.isclose(restored.biomass_x, 4.0, rel_tol=1e-6)
        assert math.isclose(restored.monomer_f_4hb, 18.5, rel_tol=1e-6)

    def test_state_property_aliases(self) -> None:
        """Convenience property getters and setters work identically."""
        state = P3hb4hbState()
        state.biomass = 3.5
        assert state.biomass_x == 3.5

        state.substrate = 25.0
        assert state.substrate_s1 == 25.0
        state.s1 = 28.0
        assert state.substrate_s1 == 28.0

        state.precursor = 7.0
        assert state.precursor_s2 == 7.0
        state.s2 = 8.5
        assert state.precursor_s2 == 8.5

        state.nitrogen = 1.5
        assert state.nitrogen_n == 1.5
        state.n = 0.9
        assert state.nitrogen_n == 0.9

        state.polymer = 1.8
        assert state.polymer_p == 1.8
        state.p = 2.4
        assert state.polymer_p == 2.4

        state.f_4hb = 22.0
        assert state.monomer_f_4hb == 22.0
        state.mol_pct_4hb = 19.0
        assert state.monomer_f_4hb == 19.0

        state.temp = 32.0
        assert state.temperature_c == 32.0
        state.temperature = 30.5
        assert state.temperature_c == 30.5

        state.dissolved_oxygen = 88.0
        assert state.dissolved_oxygen_c_do == 88.0
        state.c_do = 82.0
        assert state.dissolved_oxygen_c_do == 82.0

    def test_class_aliases(self) -> None:
        """Class aliases resolve to P3hb4hbBiosynthesisReactor and configs."""
        assert BioP3hb4hbReactor is P3hb4hbBiosynthesisReactor
        assert P3hb4hbReactor is P3hb4hbBiosynthesisReactor
        assert P3hb4hbSimulator is P3hb4hbBiosynthesisReactor
        assert P3hb4hbEngine is P3hb4hbBiosynthesisReactor
        assert P3hb4hbLogicUnit is P3hb4hbBiosynthesisReactor
        assert P3hb4hbModel is P3hb4hbBiosynthesisReactor
        assert P3hb4hbPlantModel is P3hb4hbBiosynthesisReactor
        assert P3hb4hbBiosynthesisConfig is P3hb4hbConfig
        assert P3hb4hbBiosynthesisState is P3hb4hbState


# ============================================================================
# Section 2: Cupriavidus necator Growth Kinetics & Dual Substrate Coupling
# ============================================================================

class TestSection02GrowthKineticsAndDualSubstrateCoupling:
    """Verify coupled growth kinetics on glucose S1, precursor S2, and nitrogen N."""

    def test_initial_biomass_growth_rate(self) -> None:
        """Inoculation growth increases biomass concentration."""
        reactor = P3hb4hbBiosynthesisReactor()
        x0 = reactor.state.biomass_x
        reactor.rk4_step(dt_h=0.05)
        assert reactor.state.biomass_x > x0

    def test_glucose_and_nitrogen_consumption(self) -> None:
        """Growth and metabolism consume glucose S1 and nitrogen N simultaneously."""
        reactor = P3hb4hbBiosynthesisReactor()
        s1_init = reactor.state.substrate_s1
        n_init = reactor.state.nitrogen_n
        reactor.rk4_step(dt_h=0.05)
        assert reactor.state.substrate_s1 < s1_init
        assert reactor.state.nitrogen_n < n_init

    def test_precursor_haldane_inhibition_on_growth(self) -> None:
        """Elevated precursor S2 inhibits specific growth rate mu via Haldane factor."""
        cfg = P3hb4hbConfig()
        s_low = P3hb4hbState(precursor_s2=1.0)
        s_high = P3hb4hbState(precursor_s2=18.0)

        r_low = P3hb4hbBiosynthesisReactor(config=cfg, initial_state=s_low)
        r_high = P3hb4hbBiosynthesisReactor(config=cfg, initial_state=s_high)

        d_low = r_low._derivatives(s_low)
        d_high = r_high._derivatives(s_high)

        # dX/dt should be higher with low precursor concentration
        assert d_low[0] > d_high[0]

    def test_temperature_inhibition(self) -> None:
        """Growth rate drops when temperature deviates from optimal 30°C."""
        cfg = P3hb4hbConfig(t_opt_c=30.0, t_width_c=5.0)
        s_opt = P3hb4hbState(temperature_c=30.0)
        s_hot = P3hb4hbState(temperature_c=35.0)

        r_opt = P3hb4hbBiosynthesisReactor(config=cfg, initial_state=s_opt)
        r_hot = P3hb4hbBiosynthesisReactor(config=cfg, initial_state=s_hot)

        d_opt = r_opt._derivatives(s_opt)
        d_hot = r_hot._derivatives(s_hot)

        assert d_opt[0] > d_hot[0]


# ============================================================================
# Section 3: Precursor Dosing, Consumption & Tunable 4HB Monomer Fraction
# ============================================================================

class TestSection03PrecursorDosingAndMonomerFractionTuning:
    """Verify precursor S2 consumption and tunable 4HB fraction dynamics (5-40 mol%)."""

    def test_tunable_4hb_fraction_set_target(self) -> None:
        """Target 4HB fraction can be tuned dynamically via set_target_4hb_fraction."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.set_target_4hb_fraction(25.0)
        assert math.isclose(reactor.cfg.f_4hb_target_mol_pct, 25.0, rel_tol=1e-6)

    def test_target_4hb_fraction_bounds_clamping(self) -> None:
        """Target 4HB fraction is clamped within [5.0, 40.0] mol% range."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.set_target_4hb_fraction(2.0)
        assert reactor.cfg.f_4hb_target_mol_pct == 5.0

        reactor.set_target_4hb_fraction(55.0)
        assert reactor.cfg.f_4hb_target_mol_pct == 40.0

    def test_4hb_monomer_fraction_evolution(self) -> None:
        """Monomer fraction relaxes dynamically towards the set target."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.state.monomer_f_4hb = 10.0
        reactor.set_target_4hb_fraction(30.0)

        for _ in range(10):
            reactor.rk4_step(dt_h=0.05)

        assert reactor.state.monomer_f_4hb > 10.0
        assert reactor.state.monomer_f_4hb <= 30.0

    def test_precursor_s2_consumption(self) -> None:
        """Secondary precursor S2 is consumed into 4HB repeat units."""
        reactor = P3hb4hbBiosynthesisReactor()
        s2_0 = reactor.state.precursor_s2
        for _ in range(5):
            reactor.rk4_step(dt_h=0.05)
        assert reactor.state.precursor_s2 < s2_0


# ============================================================================
# Section 4: Coupled 6-State ODE Discretization & RK4 Numerical Stability
# ============================================================================

class TestSection04CoupledOdeDiscretizationAndRk4Stability:
    """Verify 4th-order Runge-Kutta numerical solver stability and state tracking."""

    def test_single_rk4_step_state_transition(self) -> None:
        """Single RK4 integration step updates all 6 state variables smoothly."""
        reactor = P3hb4hbBiosynthesisReactor()
        s0_x = reactor.state.biomass_x
        s0_s1 = reactor.state.substrate_s1
        s0_s2 = reactor.state.precursor_s2
        s0_n = reactor.state.nitrogen_n
        s0_p = reactor.state.polymer_p

        reactor.rk4_step(dt_h=0.02)

        assert reactor.state.biomass_x > s0_x
        assert reactor.state.substrate_s1 < s0_s1
        assert reactor.state.precursor_s2 < s0_s2
        assert reactor.state.nitrogen_n < s0_n
        assert reactor.state.polymer_p > s0_p

    def test_state_non_negativity_clamping(self) -> None:
        """RK4 step enforces non-negativity clamping on all concentrations."""
        low_state = P3hb4hbState(
            biomass_x=10.0,
            substrate_s1=0.001,
            precursor_s2=0.001,
            nitrogen_n=0.0001,
            polymer_p=0.001,
        )
        reactor = P3hb4hbBiosynthesisReactor(initial_state=low_state)
        reactor.rk4_step(dt_h=0.1)

        assert reactor.state.biomass_x >= 0.0
        assert reactor.state.substrate_s1 >= 0.0
        assert reactor.state.precursor_s2 >= 0.0
        assert reactor.state.nitrogen_n >= 0.0
        assert reactor.state.polymer_p >= 0.0
        assert 5.0 <= reactor.state.monomer_f_4hb <= 40.0

    def test_rk4_solver_step_size_convergence(self) -> None:
        """Varying dt (0.01 vs 0.02) shows smooth numerical convergence."""
        r1 = P3hb4hbBiosynthesisReactor()
        for _ in range(10):
            r1.rk4_step(dt_h=0.01)

        r2 = P3hb4hbBiosynthesisReactor()
        for _ in range(5):
            r2.rk4_step(dt_h=0.02)

        assert math.isclose(r1.state.biomass_x, r2.state.biomass_x, rel_tol=0.02)
        assert math.isclose(r1.state.polymer_p, r2.state.polymer_p, rel_tol=0.02)

    def test_derivatives_freeze_on_trip_active(self) -> None:
        """When trip_active is True, derivatives immediately freeze at zero."""
        reactor = P3hb4hbBiosynthesisReactor()
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
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.rk4_step(dt_h=0.01)
        assert reactor.conservation_residual < 1.0e-10
        assert reactor.conservation_residual >= 0.0

    def test_conservation_residual_multi_step_stability(self) -> None:
        """Conservation residual remains bounded < 1e-10 over 50 consecutive steps."""
        reactor = P3hb4hbBiosynthesisReactor()
        for _ in range(50):
            reactor.rk4_step(dt_h=0.01)
            assert reactor.conservation_residual < 1.0e-10


# ============================================================================
# Section 6: Process Safety Trips & Strict Fault Hierarchy (0xF911..0xF914)
# ============================================================================

class TestSection06ProcessSafetyTripsAndHierarchy:
    """Verify safety trips 0xF911..0xF914 and priority hierarchy: 0xF911 > 0xF912 > 0xF913 > 0xF914."""

    def test_precursor_toxicity_trip_0xf911(self) -> None:
        """Precursor S2 > 20.0 g/L asserts 0xF911 and shuts off precursor feed."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.state.precursor_s2 = 21.5
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_PRECURSOR_TOXICITY
        assert reactor.diagnostic_code == 0xF911
        assert reactor.precursor_feed_permissive is False
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_PRECURSOR_PERMISSIVE) is False
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_TRIP_ALARM) is True

    def test_nitrogen_starvation_trip_0xf912(self) -> None:
        """Nitrogen starvation (N < 0.005 g/L with starvation_trip_enabled) asserts 0xF912."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.cfg.starvation_trip_enabled = True
        reactor.state.nitrogen_n = 0.002
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_NITROGEN_STARVATION
        assert reactor.diagnostic_code == 0xF912
        assert reactor.lipid_accumulation_phase is True
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_TRIP_ALARM) is True

    def test_thermal_runaway_trip_0xf913(self) -> None:
        """Temperature T > 36.0 °C asserts 0xF913 and trips cooling interlock."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.state.temperature_c = 37.0
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        assert reactor.diagnostic_code == 0xF913
        assert reactor.cooling_interlock_tripped is True
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_TRIP_ALARM) is True

    def test_dissolved_oxygen_starvation_trip_0xf914(self) -> None:
        """DO < 5.0 % asserts 0xF914 and trips aeration interlock."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.state.dissolved_oxygen_c_do = 3.5
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_DO_STARVATION
        assert reactor.diagnostic_code == 0xF914
        assert reactor.aeration_interlock_tripped is True
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_TRIP_ALARM) is True

    def test_strict_priority_hierarchy(self) -> None:
        """0xF911 preempts 0xF912, 0xF913, and 0xF914."""
        # 0xF911 preempts all
        r1 = P3hb4hbBiosynthesisReactor()
        r1.cfg.starvation_trip_enabled = True
        r1.state.precursor_s2 = 25.0
        r1.state.nitrogen_n = 0.001
        r1.state.temperature_c = 39.0
        r1.state.dissolved_oxygen_c_do = 1.0
        r1.rk4_step(dt_h=0.01)
        assert r1.diagnostic_code == DIAG_ERR_PRECURSOR_TOXICITY
        assert r1.diagnostic_code == 0xF911

        # 0xF912 preempts 0xF913 and 0xF914
        r2 = P3hb4hbBiosynthesisReactor()
        r2.cfg.starvation_trip_enabled = True
        r2.state.precursor_s2 = 5.0
        r2.state.nitrogen_n = 0.001
        r2.state.temperature_c = 39.0
        r2.state.dissolved_oxygen_c_do = 1.0
        r2.rk4_step(dt_h=0.01)
        assert r2.diagnostic_code == DIAG_ERR_NITROGEN_STARVATION
        assert r2.diagnostic_code == 0xF912

        # 0xF913 preempts 0xF914
        r3 = P3hb4hbBiosynthesisReactor()
        r3.state.precursor_s2 = 5.0
        r3.state.nitrogen_n = 1.0
        r3.state.temperature_c = 39.0
        r3.state.dissolved_oxygen_c_do = 1.0
        r3.rk4_step(dt_h=0.01)
        assert r3.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        assert r3.diagnostic_code == 0xF913


# ============================================================================
# Section 7: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
# ============================================================================

class TestSection07DiagnosticCodeSignedUnsignedAndMasking:
    """Verify 16-bit signed/unsigned comparisons, bitwise masking, and hash compliance."""

    def test_diagnostic_code_hex_values(self) -> None:
        """Hex integer values match W293 specification."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_PRECURSOR_TOXICITY == 0xF911
        assert DIAG_ERR_PRECURSOR_OVERCONC == 0xF911
        assert DIAG_ERR_S2_TOXICITY == 0xF911
        assert DIAG_ERR_NITROGEN_STARVATION == 0xF912
        assert DIAG_ERR_NITROGEN_DEPLETION == 0xF912
        assert DIAG_ERR_THERMAL_RUNAWAY == 0xF913
        assert DIAG_ERR_THERMAL_EXCURSION == 0xF913
        assert DIAG_ERR_DO_STARVATION == 0xF914
        assert DIAG_ERR_AERATION_STARVATION == 0xF914
        assert DIAG_ERR_OXYGEN_STARVATION == 0xF914

    def test_signed_16bit_equality(self) -> None:
        """Signed two's complement 16-bit comparisons match."""
        # 0xF911 = 63761 -> 63761 - 65536 = -1775
        assert DIAG_ERR_PRECURSOR_TOXICITY == 0xF911
        assert DIAG_ERR_PRECURSOR_TOXICITY == 63761
        assert DIAG_ERR_PRECURSOR_TOXICITY == -1775

        # 0xF912 = 63762 -> -1774
        assert DIAG_ERR_NITROGEN_STARVATION == 0xF912
        assert DIAG_ERR_NITROGEN_STARVATION == -1774

        # 0xF913 = 63763 -> -1773
        assert DIAG_ERR_THERMAL_RUNAWAY == 0xF913
        assert DIAG_ERR_THERMAL_RUNAWAY == -1773

        # 0xF914 = 63764 -> -1772
        assert DIAG_ERR_DO_STARVATION == 0xF914
        assert DIAG_ERR_DO_STARVATION == -1772

    def test_bitwise_masking_support(self) -> None:
        """Bitwise AND operations with 0xFFFF transparently supported."""
        assert (DIAG_ERR_PRECURSOR_TOXICITY & 0xFFFF) == 0xF911
        assert (0xFFFF & DIAG_ERR_NITROGEN_STARVATION) == 0xF912

    def test_hash_and_formatting(self) -> None:
        """Hash and string formatting work cleanly."""
        assert hash(DIAG_ERR_PRECURSOR_TOXICITY) == hash(0xF911)
        assert str(DIAG_ERR_PRECURSOR_TOXICITY) == "0xF911"
        assert repr(DIAG_ERR_PRECURSOR_TOXICITY) == "DiagnosticCode(0xF911)"

    def test_status_bits_enum(self) -> None:
        """P3hb4hbStatusBits flags combine properly."""
        flags = P3hb4hbStatusBits.BIOMASS_GROWTH_ACTIVE | P3hb4hbStatusBits.PRECURSOR_FEED_PERMISSIVE
        assert bool(flags & P3hb4hbStatusBits.BIOMASS_GROWTH_ACTIVE) is True
        assert bool(flags & P3hb4hbStatusBits.PROCESS_TRIP_ACTIVE) is False


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization (%R2540..%R2547)
# ============================================================================

class TestSection08HornerOcsRegisterSynchronization:
    """Verify Horner OCS register space synchronization (%R2540..%R2547, %M592..%M594)."""

    def test_nominal_registers_synchronization(self) -> None:
        """Nominal state writes scaled INT16 words to %R2540..%R2547."""
        table = RegisterTable()
        reactor = P3hb4hbBiosynthesisReactor(register_table=table)
        reactor.reset()

        # %R2540: Biomass x100 (2.5 -> 250)
        assert table.read_word(REG_P3HB_4HB_BIOMASS_SCALED) == 250
        # %R2541: Primary Substrate S1 x100 (30.0 -> 3000)
        assert table.read_word(REG_P3HB_4HB_SUBSTRATE_S1_SCALED) == 3000
        # %R2542: Precursor S2 x100 (5.0 -> 500)
        assert table.read_word(REG_P3HB_4HB_PRECURSOR_S2_SCALED) == 500
        # %R2543: Nitrogen x100 (1.2 -> 120)
        assert table.read_word(REG_P3HB_4HB_NITROGEN_SCALED) == 120
        # %R2544: Polymer x100 (0.5 -> 50)
        assert table.read_word(REG_P3HB_4HB_POLYMER_SCALED) == 50
        # %R2545: 4HB Mol% x10 (15.0 -> 150)
        assert table.read_word(REG_P3HB_4HB_4HB_MOL_PCT_SCALED) == 150
        # %R2546: Temp x10 (30.0 -> 300)
        assert table.read_word(REG_P3HB_4HB_TEMP_SCALED) == 300
        # %R2547: Diagnostic Code -> 0
        assert table.read_word(REG_P3HB_4HB_DIAGNOSTIC_CODE) == 0

        assert table.read_bit(COIL_P3HB_4HB_ACTIVE) is True
        assert table.read_bit(COIL_P3HB_4HB_PRECURSOR_PERMISSIVE) is True
        assert table.read_bit(COIL_P3HB_4HB_TRIP_ALARM) is False

    def test_trip_registers_synchronization(self) -> None:
        """Fault trip updates %R2547 and %M594 alarm coil."""
        table = RegisterTable()
        reactor = P3hb4hbBiosynthesisReactor(register_table=table)
        reactor.state.precursor_s2 = 22.0
        reactor.rk4_step(dt_h=0.01)

        assert (table.read_uword(REG_P3HB_4HB_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF911
        assert table.read_bit(COIL_P3HB_4HB_ACTIVE) is False
        assert table.read_bit(COIL_P3HB_4HB_PRECURSOR_PERMISSIVE) is False
        assert table.read_bit(COIL_P3HB_4HB_TRIP_ALARM) is True

    def test_privilege_modes(self) -> None:
        """sync_to_registers works with both USER and SYSTEM privileges."""
        table = RegisterTable()
        reactor = P3hb4hbBiosynthesisReactor(register_table=table)
        reactor.sync_to_registers(table, privilege=PrivilegeMode.USER)
        assert table.read_word(REG_P3HB_4HB_TEMP_SCALED) == 300

        reactor.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word(REG_P3HB_4HB_TEMP_SCALED) == 300


# ============================================================================
# Section 9: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection09PureStructuredTextPouValidation:
    """Verify IEC 61131-3 Structured Text compliance and AST memory bindings."""

    def test_pure_st_pou_constants(self) -> None:
        """P3HB_4HB_BIOSYNTHESIS_PURE_ST_POU contains valid POU text."""
        assert isinstance(ST_PROGRAM_P3HB_4HB_BIOSYNTHESIS_SYNC, str)
        assert ST_PROGRAM_P3HB_4HB_BIOSYNTHESIS_SYNC == P3HB_4HB_BIOSYNTHESIS_PURE_ST_POU
        assert "PROGRAM P3hb4hbBiosynthesisSync" in ST_PROGRAM_P3HB_4HB_BIOSYNTHESIS_SYNC
        assert "END_PROGRAM" in ST_PROGRAM_P3HB_4HB_BIOSYNTHESIS_SYNC

    def test_st_parser_syntax_validation(self) -> None:
        """STParser.validate_code reports SUCCESS for P3hb4hbBiosynthesisSync."""
        val = STParser.validate_code(ST_PROGRAM_P3HB_4HB_BIOSYNTHESIS_SYNC)
        assert val.status == AgentStatus.SUCCESS

    def test_st_parser_ast_variable_bindings(self) -> None:
        """Registers %R2540..%R2547 and coils %M592..%M594 bound in AST."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(ST_PROGRAM_P3HB_4HB_BIOSYNTHESIS_SYNC)
        assert pou is not None
        assert pou.name == "P3hb4hbBiosynthesisSync"

        required_regs = [
            "%R2540", "%R2541", "%R2542", "%R2543",
            "%R2544", "%R2545", "%R2546", "%R2547",
            "%M592", "%M593", "%M594",
        ]
        for reg in required_regs:
            assert reg in pou.bound_registers, f"Missing binding for {reg}"

    def test_verify_p3hb_4hb_pure_st_function(self) -> None:
        """verify_p3hb_4hb_biosynthesis_pure_st returns True."""
        assert verify_p3hb_4hb_biosynthesis_pure_st() is True
        assert verify_p3hb_4hb_pure_st() is True


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
        """Official P(3HB-co-4HB) ST POU passes SecurityGuard cleanly."""
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_P3HB_4HB_BIOSYNTHESIS_SYNC)


# ============================================================================
# Section 11: ILogicUnit Compliance & Multi-Cycle Scan Execution
# ============================================================================

class TestSection11LogicUnitComplianceAndScanCycle:
    """Verify ILogicUnit interface compliance, scan_step, step, execute, and reset."""

    def test_ilogicunit_interface_attributes(self) -> None:
        """P3hb4hbBiosynthesisReactor fulfills ILogicUnit properties."""
        reactor = P3hb4hbBiosynthesisReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "P3hb4hbBiosynthesisReactor"
        assert reactor.priority == 50
        assert reactor.is_enabled is True

    def test_scan_step_nominal(self) -> None:
        """scan_step returns AgentStatus.SUCCESS when healthy."""
        reactor = P3hb4hbBiosynthesisReactor()
        res = reactor.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert reactor.cycle_count == 1
        assert "P(3HB-co-4HB) State:" in res.details
        assert res.data["trip_active"] is False

    def test_scan_step_with_context(self) -> None:
        """scan_step accepts ScanContext gracefully."""
        reactor = P3hb4hbBiosynthesisReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        res = reactor.scan_step(ctx)
        assert res.status == AgentStatus.SUCCESS
        assert reactor.cycle_count == 1

    def test_step_and_execute_methods(self) -> None:
        """step() and execute() advance cycle count."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.step()
        assert reactor.cycle_count == 1

        ctx = ScanContext(cycle=2, dt_ms=20.0, elapsed_time_ms=40.0, dt=0.02)
        reactor.execute(ctx)
        assert reactor.cycle_count == 2

        reactor.execute()
        assert reactor.cycle_count == 3

    def test_scan_step_faulted(self) -> None:
        """scan_step returns AgentStatus.FAILED when trip active."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.state.temperature_c = 38.0
        res = reactor.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_ERR_THERMAL_RUNAWAY)
        assert res.data["trip_active"] is True

    def test_reset_method_restores_state(self) -> None:
        """reset() restores initial state and clears trips."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.state.temperature_c = 40.0
        reactor.scan_step()
        assert reactor.trip_active is True

        reactor.reset()
        assert reactor.trip_active is False
        assert reactor.state.temperature_c == 30.0
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.reg_table.read_bit(COIL_P3HB_4HB_ACTIVE) is True

    def test_continuous_scan_soak_50_cycles(self) -> None:
        """50 continuous scan steps execute with zero NaN and bounded state."""
        reactor = P3hb4hbBiosynthesisReactor()
        reactor.reset()

        for _ in range(50):
            res = reactor.scan_step()
            assert res.status == AgentStatus.SUCCESS

        assert not math.isnan(reactor.state.biomass_x)
        assert not math.isnan(reactor.state.polymer_p)
        assert not math.isinf(reactor.state.biomass_x)
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.conservation_residual < 1.0e-10


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Runner Execution
# ============================================================================

class TestSection12VerificationSuiteExecution:
    """Verify run_p3hb_4hb_biosynthesis_verification output contract and evidence emission."""

    def test_run_verification_suite_success(self, tmp_path: Path) -> None:
        """Verification suite runs all 9 stages cleanly and writes evidence JSON."""
        evidence_file = tmp_path / "p3hb_4hb_test_evidence.json"
        res = run_p3hb_4hb_biosynthesis_verification(output_path=str(evidence_file))

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

    def test_verification_runner_stage_names(self) -> None:
        """Verify the exact 9 stages in the verification sequence."""
        res = run_p3hb_4hb_biosynthesis_verification()
        stage_names = [s["name"] for s in res["data"]["stages"]]
        expected = [
            "initial_state_and_growth",
            "dual_substrate_kinetics",
            "p3hb_4hb_accumulation",
            "monomer_fraction_tuning",
            "precursor_toxicity_trip",
            "thermal_runaway_trip",
            "mass_conservation_residuals",
            "horner_ocs_register_sync",
            "pure_st_pou_and_ladder_rejection",
        ]
        assert stage_names == expected

    def test_runner_alias_identity(self) -> None:
        """run_p3hb_4hb_verification resolves to run_p3hb_4hb_biosynthesis_verification."""
        assert run_p3hb_4hb_verification is run_p3hb_4hb_biosynthesis_verification
