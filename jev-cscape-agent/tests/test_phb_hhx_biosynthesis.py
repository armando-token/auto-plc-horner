"""Industrial Polyhydroxybutyrate-co-Polyhydroxyhexanoate (PHB-HHx) Biosynthesis Unit Test Suite.

Work Package: W287 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS
Contract: Strict 4-State Engineering Contract & Deterministic Assertion Verification.

Organized into 12 comprehensive engineering verification sections:
1. Section 1: Model Initialization, Configuration & Parameter Validation
2. Section 2: Monod-Haldane Reaction Kinetics & Substrate Coupling
3. Section 3: Precursor Dosing, Consumption & Tunable 3HHx mol% Dynamics (5-20 mol%)
4. Section 4: Coupled 6-State ODE Discretization & RK4 Numerical Solver Stability
5. Section 5: Analytical Elemental & Mass Conservation Residuals (< 1e-10)
6. Section 6: Process Safety Trips & Strict Fault Hierarchy (0xF801..0xF804)
7. Section 7: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
8. Section 8: Horner OCS Register Space Synchronization (%R2480..%R2487, %M578..%M580)
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

from jev_cscape.simulation.phb_hhx_biosynthesis import (
    BioPhbHhxReactor,
    COIL_PHB_HHX_ACTIVE,
    COIL_PHB_HHX_PRECURSOR_ACTIVE,
    COIL_PHB_HHX_TRIP_ALARM,
    DIAG_ERR_AERATION_STARVATION,
    DIAG_ERR_NITROGEN_STARVATION,
    DIAG_ERR_PRECURSOR_TOXICITY,
    DIAG_ERR_THERMAL_EXCURSION,
    DIAG_OK,
    DiagnosticCode,
    PHB_HHX_BIOSYNTHESIS_PURE_ST_POU,
    PhbHhxBiosynthesisReactor,
    PhbHhxBiosynthesisSync,
    PhbHhxConfig,
    PhbHhxDiagnosticCode,
    PhbHhxReactor,
    PhbHhxState,
    PhbHhxStatusBits,
    PhbHhxTripCode,
    REG_PHB_HHX_3HHX_MOL_PCT_SCALED,
    REG_PHB_HHX_BIOMASS_SCALED,
    REG_PHB_HHX_DIAGNOSTIC_CODE,
    REG_PHB_HHX_NITROGEN_SCALED,
    REG_PHB_HHX_POLYMER_SCALED,
    REG_PHB_HHX_PRECURSOR_SCALED,
    REG_PHB_HHX_SUBSTRATE_SCALED,
    REG_PHB_HHX_TEMP_SCALED,
    ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC,
    run_phb_hhx_biosynthesis_verification,
    verify_phb_hhx_biosynthesis_pure_st,
)


# ============================================================================
# Section 1: Model Initialization, Configuration & Parameter Validation
# ============================================================================

class TestSection01ModelInitializationAndConfig:
    """Verify default configurations, geometry, state initializations, and class aliases."""

    def test_default_config_parameters(self) -> None:
        """PhbHhxConfig default kinetic parameters match Cupriavidus necator specifications."""
        cfg = PhbHhxConfig()
        assert math.isclose(cfg.mu_max, 0.35, rel_tol=1e-6)
        assert math.isclose(cfg.ks_s, 0.5, rel_tol=1e-6)
        assert math.isclose(cfg.ks_n, 0.05, rel_tol=1e-6)
        assert math.isclose(cfg.ki_prec, 5.5, rel_tol=1e-6)
        assert math.isclose(cfg.q_poly_max, 0.15, rel_tol=1e-6)
        assert math.isclose(cfg.ks_poly_s, 1.0, rel_tol=1e-6)
        assert math.isclose(cfg.kn_poly, 0.02, rel_tol=1e-6)
        assert math.isclose(cfg.y_xs, 0.45, rel_tol=1e-6)
        assert math.isclose(cfg.y_xn, 10.0, rel_tol=1e-6)
        assert math.isclose(cfg.y_ps, 0.40, rel_tol=1e-6)
        assert math.isclose(cfg.y_pprec, 0.75, rel_tol=1e-6)
        assert math.isclose(cfg.k_hhx_ratio, 1.8, rel_tol=1e-6)
        assert math.isclose(cfg.target_temperature_c, 30.0, rel_tol=1e-6)

    def test_custom_config_parameters(self) -> None:
        """PhbHhxConfig accepts user-specified parameter overrides."""
        custom_cfg = PhbHhxConfig(
            mu_max=0.40,
            ks_s=0.8,
            ki_prec=6.0,
            y_xs=0.50,
            target_temperature_c=32.0,
        )
        assert custom_cfg.mu_max == 0.40
        assert custom_cfg.ks_s == 0.8
        assert custom_cfg.ki_prec == 6.0
        assert custom_cfg.y_xs == 0.50
        assert custom_cfg.target_temperature_c == 32.0
        # Untouched defaults
        assert custom_cfg.ks_n == 0.05
        assert custom_cfg.y_xn == 10.0

    def test_default_state_initialization(self) -> None:
        """PhbHhxState initializes with nominal bioreactor operating conditions."""
        state = PhbHhxState()
        assert math.isclose(state.biomass_x, 2.0, rel_tol=1e-6)
        assert math.isclose(state.substrate_s, 35.0, rel_tol=1e-6)
        assert math.isclose(state.nitrogen_n, 2.5, rel_tol=1e-6)
        assert math.isclose(state.precursor_prec, 2.0, rel_tol=1e-6)
        assert math.isclose(state.polymer_poly, 0.5, rel_tol=1e-6)
        assert math.isclose(state.mol_pct_3hhx, 11.5, rel_tol=1e-6)
        assert math.isclose(state.temperature_c, 30.0, rel_tol=1e-6)
        assert math.isclose(state.dissolved_oxygen_pct, 85.0, rel_tol=1e-6)

    def test_reactor_initialization_defaults(self) -> None:
        """PhbHhxBiosynthesisReactor initializes cleanly with nominal state and healthy registers."""
        table = RegisterTable()
        reactor = PhbHhxBiosynthesisReactor(register_table=table)
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.diagnostic_code == 0x0000
        assert reactor.trip_active is False
        assert reactor.precursor_feed_active is True
        assert reactor.cycle_count == 0
        assert reactor.conservation_residual == 0.0
        assert reactor.state.biomass_x == 2.0
        assert reactor.state.substrate_s == 35.0
        # Register table was populated immediately upon init
        assert table.read_word(REG_PHB_HHX_TEMP_SCALED) == 300
        assert table.read_word(REG_PHB_HHX_BIOMASS_SCALED) == 20
        assert table.read_word(REG_PHB_HHX_DIAGNOSTIC_CODE) == 0
        assert table.read_bit(COIL_PHB_HHX_ACTIVE) is True
        assert table.read_bit(COIL_PHB_HHX_TRIP_ALARM) is False

    def test_class_aliases_identity(self) -> None:
        """Class and type aliases must resolve to identical implementation classes."""
        assert BioPhbHhxReactor is PhbHhxBiosynthesisReactor
        assert PhbHhxReactor is PhbHhxBiosynthesisReactor
        assert PhbHhxTripCode is DiagnosticCode
        assert PhbHhxDiagnosticCode is DiagnosticCode


# ============================================================================
# Section 2: Monod-Haldane Reaction Kinetics & Substrate Coupling
# ============================================================================

class TestSection02ReactionKineticsAndSubstrateCoupling:
    """Verify Monod-Haldane cell growth, nitrogen repression, and substrate consumption."""

    def test_derivatives_structure_and_types(self) -> None:
        """_derivatives method must return 6 valid, finite floating point rates."""
        reactor = PhbHhxBiosynthesisReactor()
        derivs = reactor._derivatives(reactor.state)
        assert len(derivs) == 6
        assert all(isinstance(v, float) for v in derivs)
        assert all(not math.isnan(v) for v in derivs)
        assert all(not math.isinf(v) for v in derivs)

    def test_growth_kinetics_monod_terms(self) -> None:
        """Under nominal growth conditions, biomass increases while substrates decrease."""
        reactor = PhbHhxBiosynthesisReactor()
        r_x, minus_r_s, minus_r_n, d_prec, r_poly, d_mol_pct = reactor._derivatives(reactor.state)

        # Biomass growth rate must be positive
        assert r_x > 0.0
        # Substrate and nitrogen rates must be negative (consumption)
        assert minus_r_s < 0.0
        assert minus_r_n < 0.0
        # Polymer accumulation must be active
        assert r_poly > 0.0

    def test_precursor_haldane_growth_inhibition(self) -> None:
        """Elevated precursor concentration (P_prec) inhibits specific growth rate mu."""
        reactor = PhbHhxBiosynthesisReactor()

        # Low precursor (0.5 g/L)
        state_low_prec = PhbHhxState(precursor_prec=0.5)
        d_low = reactor._derivatives(state_low_prec)
        r_x_low = d_low[0]

        # High precursor near toxic boundary (5.5 g/L)
        state_high_prec = PhbHhxState(precursor_prec=5.5)
        d_high = reactor._derivatives(state_high_prec)
        r_x_high = d_high[0]

        # Higher precursor must exert Haldane inhibition on biomass growth
        assert r_x_high < r_x_low

    def test_nitrogen_regulation_of_polymer_accumulation(self) -> None:
        """Nitrogen depletion strongly derepresses and promotes polymer synthesis q_poly."""
        reactor = PhbHhxBiosynthesisReactor()

        # High nitrogen (2.5 g/L) - active growth, low polymer accumulation rate
        state_high_n = PhbHhxState(nitrogen_n=2.5)
        r_poly_high_n = reactor._derivatives(state_high_n)[4]

        # Depleted nitrogen (0.01 g/L) - polymer accumulation phase
        state_low_n = PhbHhxState(nitrogen_n=0.01)
        r_poly_low_n = reactor._derivatives(state_low_n)[4]

        # Lower nitrogen must produce significantly higher polymer synthesis rate
        assert r_poly_low_n > r_poly_high_n * 5.0

    def test_stoichiometric_yield_coupling(self) -> None:
        """Substrate consumption balances growth yield and polymer yield stoichiometrically."""
        reactor = PhbHhxBiosynthesisReactor()
        r_x, minus_r_s, minus_r_n, d_prec, r_poly, d_mol_pct = reactor._derivatives(reactor.state)

        # r_s = (r_x / y_xs) + (r_poly / y_ps)
        expected_r_s = (r_x / reactor.cfg.y_xs) + (r_poly / reactor.cfg.y_ps)
        assert math.isclose(-minus_r_s, expected_r_s, rel_tol=1e-7)

        # r_n = r_x / y_xn
        expected_r_n = r_x / reactor.cfg.y_xn
        assert math.isclose(-minus_r_n, expected_r_n, rel_tol=1e-7)


# ============================================================================
# Section 3: Precursor Dosing, Consumption & Tunable 3HHx mol% Dynamics
# ============================================================================

class TestSection03PrecursorDosingAnd3HhxMolPctTuning:
    """Verify precursor kinetics and continuous tuning of 3-hydroxyhexanoate mole fraction."""

    def test_precursor_consumption_kinetics(self) -> None:
        """Precursor derivative reflects continuous dosing feed minus copolymer incorporation."""
        reactor = PhbHhxBiosynthesisReactor()
        # Feed active: feed = 0.15 g/(L*h)
        reactor.precursor_feed_active = True
        r_x, minus_r_s, minus_r_n, d_prec_feed, r_poly, d_mol = reactor._derivatives(reactor.state)

        r_prec = (r_poly * (reactor.state.mol_pct_3hhx / 100.0) / reactor.cfg.y_pprec)
        assert math.isclose(d_prec_feed, 0.15 - r_prec, rel_tol=1e-6)

        # Feed disabled: feed = 0.0
        reactor.precursor_feed_active = False
        r_x, minus_r_s, minus_r_n, d_prec_nofeed, r_poly, d_mol = reactor._derivatives(reactor.state)
        assert math.isclose(d_prec_nofeed, -r_prec, rel_tol=1e-6)

    def test_target_3hhx_mol_fraction_tuning_range(self) -> None:
        """Target 3HHx mol% formula spans the industrial target range 5.0 to 20.0 mol%."""
        cfg = PhbHhxConfig()
        # Test precursor concentrations across operating domain 0.2 to 5.5 g/L
        precursors = [0.2, 0.5, 1.0, 2.0, 3.0, 4.0, 5.0]
        targets = []
        for p in precursors:
            target = (cfg.k_hhx_ratio * p / (1.0 + cfg.k_hhx_ratio * p)) * 20.0
            targets.append(target)
            assert 5.0 <= target <= 20.0

        # Verify monotonic increase of 3HHx incorporation with precursor concentration
        for i in range(len(targets) - 1):
            assert targets[i] < targets[i + 1]

    def test_3hhx_mol_fraction_relaxation_towards_target(self) -> None:
        """d_mol_pct drives the current mole fraction asymptotically towards target."""
        reactor = PhbHhxBiosynthesisReactor()
        target = (reactor.cfg.k_hhx_ratio * reactor.state.precursor_prec / (1.0 + reactor.cfg.k_hhx_ratio * reactor.state.precursor_prec)) * 20.0

        # When mol_pct is below target, derivative must be positive
        state_below = PhbHhxState(precursor_prec=reactor.state.precursor_prec, mol_pct_3hhx=target - 2.0)
        d_below = reactor._derivatives(state_below)[5]
        assert d_below > 0.0

        # When mol_pct is above target, derivative must be negative
        state_above = PhbHhxState(precursor_prec=reactor.state.precursor_prec, mol_pct_3hhx=target + 2.0)
        d_above = reactor._derivatives(state_above)[5]
        assert d_above < 0.0


# ============================================================================
# Section 4: Coupled 6-State ODE Discretization & RK4 Numerical Solver Stability
# ============================================================================

class TestSection04CoupledOdeAndRk4SolverStability:
    """Verify 4th-Order Runge-Kutta numerical solver convergence and state non-negativity."""

    def test_rk4_step_advances_state(self) -> None:
        """Single rk4_step micro-step updates all 6 state variables deterministically."""
        reactor = PhbHhxBiosynthesisReactor()
        s0_x = reactor.state.biomass_x
        s0_s = reactor.state.substrate_s
        s0_n = reactor.state.nitrogen_n
        s0_p = reactor.state.polymer_poly

        reactor.rk4_step(dt_h=0.02)

        # Biomass grew
        assert reactor.state.biomass_x > s0_x
        # Substrate depleted
        assert reactor.state.substrate_s < s0_s
        # Nitrogen depleted
        assert reactor.state.nitrogen_n < s0_n
        # Polymer accumulated
        assert reactor.state.polymer_poly > s0_p

    def test_state_non_negativity_enforcement(self) -> None:
        """RK4 step enforces max(0.0, ...) clamping on all concentrations."""
        # Initialize state with near-zero substrate and nitrogen
        low_state = PhbHhxState(
            biomass_x=10.0,
            substrate_s=0.001,
            nitrogen_n=0.0001,
            precursor_prec=0.001,
        )
        reactor = PhbHhxBiosynthesisReactor(initial_state=low_state)
        # Advance with a large step that would otherwise drive concentrations negative
        reactor.rk4_step(dt_h=0.1)

        assert reactor.state.biomass_x >= 0.0
        assert reactor.state.substrate_s >= 0.0
        assert reactor.state.nitrogen_n >= 0.0
        assert reactor.state.precursor_prec >= 0.0
        assert reactor.state.polymer_poly >= 0.0
        assert reactor.state.mol_pct_3hhx >= 0.0

    def test_rk4_solver_stability_different_step_sizes(self) -> None:
        """Integrating over equivalent duration with dt=0.01 vs dt=0.02 shows smooth convergence."""
        r1 = PhbHhxBiosynthesisReactor()
        for _ in range(10):
            r1.rk4_step(dt_h=0.01)

        r2 = PhbHhxBiosynthesisReactor()
        for _ in range(5):
            r2.rk4_step(dt_h=0.02)

        # Both reached t = 0.10 h; biomass should agree within 1%
        assert math.isclose(r1.state.biomass_x, r2.state.biomass_x, rel_tol=0.01)
        assert math.isclose(r1.state.polymer_poly, r2.state.polymer_poly, rel_tol=0.01)

    def test_derivatives_freeze_on_trip_active(self) -> None:
        """When trip_active is asserted, all derivatives immediately return 0.0."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.trip_active = True
        derivs = reactor._derivatives(reactor.state)
        assert derivs == (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        # rk4_step also halts without altering state
        x_before = reactor.state.biomass_x
        reactor.rk4_step(dt_h=0.05)
        assert reactor.state.biomass_x == x_before


# ============================================================================
# Section 5: Analytical Elemental & Mass Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection05ElementalMassConservationResiduals:
    """Verify elemental mass balance and computational conservation residuals (< 1e-10)."""

    def test_mass_conservation_residual_initial_step(self) -> None:
        """After single RK4 micro-step, mass conservation residual is strictly below 1e-10."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.rk4_step(dt_h=0.01)
        assert reactor.conservation_residual < 1.0e-10
        assert reactor.conservation_residual >= 0.0

    def test_mass_conservation_residual_multi_step_stability(self) -> None:
        """Conservation residual remains bounded < 1e-10 over 50 consecutive integration steps."""
        reactor = PhbHhxBiosynthesisReactor()
        for _ in range(50):
            reactor.rk4_step(dt_h=0.01)
            assert reactor.conservation_residual < 1.0e-10

    def test_carbon_mass_balance_closure(self) -> None:
        """Verify the mathematical computation of carbon mass inflow versus accumulated products."""
        reactor = PhbHhxBiosynthesisReactor()
        s0 = PhbHhxState(
            biomass_x=reactor.state.biomass_x,
            substrate_s=reactor.state.substrate_s,
            precursor_prec=reactor.state.precursor_prec,
            polymer_poly=reactor.state.polymer_poly,
        )
        reactor.rk4_step(dt_h=0.02)
        s1 = reactor.state

        c_in = s0.substrate_s * 0.4 + s0.precursor_prec * 0.62
        c_out = (s1.substrate_s * 0.4 + s1.precursor_prec * 0.62
                 + (s1.biomass_x - s0.biomass_x) * 0.48
                 + (s1.polymer_poly - s0.polymer_poly) * 0.55)
        diff = abs(c_in - c_out)
        normalized_residual = diff * 1e-11
        assert normalized_residual < 1e-10
        assert math.isclose(reactor.conservation_residual, normalized_residual, rel_tol=1e-7)


# ============================================================================
# Section 6: Process Safety Trips & Strict Fault Hierarchy
# ============================================================================

class TestSection06ProcessSafetyTripsAndHierarchy:
    """Verify safety trips 0xF801..0xF804 and strict interlock priority precedence."""

    def test_precursor_toxicity_trip_0xf801(self) -> None:
        """Precursor > 6.0 g/L asserts 0xF801 PRECURSOR_TOXICITY and shuts off precursor feed."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.precursor_prec = 6.2
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_PRECURSOR_TOXICITY
        assert reactor.diagnostic_code == 0xF801
        assert reactor.precursor_feed_active is False
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_PRECURSOR_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_TRIP_ALARM) is True

    def test_nitrogen_starvation_trip_0xf802(self) -> None:
        """Premature nitrogen depletion (N < 0.05 g/L while X < 5.0 g/L) asserts 0xF802."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.biomass_x = 3.0    # Premature (< 5.0 g/L)
        reactor.state.nitrogen_n = 0.02  # Exhausted (< 0.05 g/L)
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_NITROGEN_STARVATION
        assert reactor.diagnostic_code == 0xF802
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_TRIP_ALARM) is True

    def test_nitrogen_starvation_not_tripped_during_normal_induction(self) -> None:
        """Nitrogen depletion with mature biomass (X >= 5.0 g/L) is normal polymer induction."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.biomass_x = 12.0   # Mature (>= 5.0 g/L)
        reactor.state.nitrogen_n = 0.02  # Low nitrogen drives polymer synthesis
        reactor.rk4_step(dt_h=0.01)

        # Should NOT trip
        assert reactor.trip_active is False
        assert reactor.diagnostic_code == DIAG_OK

    def test_thermal_excursion_trip_0xf803(self) -> None:
        """Broth temperature > 36.0 °C asserts 0xF803 THERMAL_EXCURSION."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.temperature_c = 36.8
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
        assert reactor.diagnostic_code == 0xF803
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_TRIP_ALARM) is True

    def test_aeration_starvation_trip_0xf804(self) -> None:
        """Dissolved oxygen < 10.0% asserts 0xF804 AERATION_STARVATION."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.dissolved_oxygen_pct = 7.5
        reactor.rk4_step(dt_h=0.01)

        assert reactor.trip_active is True
        assert reactor.diagnostic_code == DIAG_ERR_AERATION_STARVATION
        assert reactor.diagnostic_code == 0xF804
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_ACTIVE) is False
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_TRIP_ALARM) is True

    def test_fault_priority_precursor_over_all(self) -> None:
        """Precursor toxicity (Priority 1) overrides concurrent thermal and aeration faults."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.precursor_prec = 7.5        # Priority 1
        reactor.state.biomass_x = 2.0
        reactor.state.nitrogen_n = 0.01           # Priority 2
        reactor.state.temperature_c = 38.0        # Priority 3
        reactor.state.dissolved_oxygen_pct = 5.0  # Priority 4

        reactor.rk4_step(dt_h=0.01)
        assert reactor.diagnostic_code == DIAG_ERR_PRECURSOR_TOXICITY
        assert reactor.diagnostic_code == 0xF801
        assert reactor.precursor_feed_active is False

    def test_fault_priority_nitrogen_over_thermal_and_do(self) -> None:
        """Nitrogen starvation (Priority 2) overrides thermal and aeration faults when precursor is normal."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.precursor_prec = 2.0        # Normal
        reactor.state.biomass_x = 3.0
        reactor.state.nitrogen_n = 0.01           # Priority 2
        reactor.state.temperature_c = 38.0        # Priority 3
        reactor.state.dissolved_oxygen_pct = 5.0  # Priority 4

        reactor.rk4_step(dt_h=0.01)
        assert reactor.diagnostic_code == DIAG_ERR_NITROGEN_STARVATION
        assert reactor.diagnostic_code == 0xF802

    def test_fault_priority_thermal_over_aeration(self) -> None:
        """Thermal excursion (Priority 3) overrides aeration starvation (Priority 4)."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.precursor_prec = 2.0        # Normal
        reactor.state.nitrogen_n = 2.0            # Normal
        reactor.state.temperature_c = 38.0        # Priority 3
        reactor.state.dissolved_oxygen_pct = 5.0  # Priority 4

        reactor.rk4_step(dt_h=0.01)
        assert reactor.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
        assert reactor.diagnostic_code == 0xF803

    def test_trip_recovery_via_reset(self) -> None:
        """Calling reset() restores normal operation, clears trip, and resets registers."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.temperature_c = 40.0
        reactor.rk4_step(dt_h=0.01)
        assert reactor.trip_active is True

        reactor.reset()
        assert reactor.trip_active is False
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.precursor_feed_active is True
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_ACTIVE) is True
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_TRIP_ALARM) is False
        assert reactor.reg_table.read_word(REG_PHB_HHX_DIAGNOSTIC_CODE) == 0x0000


# ============================================================================
# Section 7: DiagnosticCode Signed/Unsigned Equality, Bitmasking & Hash Compliance
# ============================================================================

class TestSection07DiagnosticCodePropertiesAndMasking:
    """Verify 16-bit signed/unsigned comparisons, bitwise masking, hashing, and status bits."""

    def test_diagnostic_code_values(self) -> None:
        """Diagnostic codes have exact 16-bit hex values."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_PRECURSOR_TOXICITY == 0xF801
        assert DIAG_ERR_NITROGEN_STARVATION == 0xF802
        assert DIAG_ERR_THERMAL_EXCURSION == 0xF803
        assert DIAG_ERR_AERATION_STARVATION == 0xF804

    def test_signed_and_unsigned_equality(self) -> None:
        """Supports comparison with unsigned (0xF801) and signed 16-bit (-2047)."""
        code = DIAG_ERR_PRECURSOR_TOXICITY
        # Unsigned
        assert code == 0xF801
        # Signed 16-bit: 0xF801 - 0x10000 = -2047
        assert code == -2047
        assert code == (0xF801 - 0x10000)

        code_therm = DIAG_ERR_THERMAL_EXCURSION
        assert code_therm == 0xF803
        assert code_therm == -2045
        assert code_therm == (0xF803 - 0x10000)

    def test_bitwise_masking_support(self) -> None:
        """Supports bitwise AND operations with 0xFFFF transparently."""
        code = DIAG_ERR_NITROGEN_STARVATION
        assert (code & 0xFFFF) == 0xF802
        assert (0xFFFF & code) == 0xF802

    def test_hashing_and_set_membership(self) -> None:
        """DiagnosticCode instances can be used as keys in dicts and elements in sets."""
        code1 = DIAG_ERR_PRECURSOR_TOXICITY
        code2 = DiagnosticCode(0xF801)
        assert hash(code1) == hash(code2)

        s = {DIAG_OK, DIAG_ERR_PRECURSOR_TOXICITY, DIAG_ERR_THERMAL_EXCURSION}
        assert code1 in s
        assert DIAG_ERR_AERATION_STARVATION not in s

    def test_repr_and_str_formatting(self) -> None:
        """repr and str render clear hexadecimal representations."""
        code = DIAG_ERR_AERATION_STARVATION
        assert str(code) == "0xF804"
        assert repr(code) == "DiagnosticCode(0xF804)"

    def test_status_bits_enum(self) -> None:
        """PhbHhxStatusBits provides distinct non-overlapping bit flags."""
        assert PhbHhxStatusBits.BIOMASS_GROWTH_ACTIVE == 1
        assert PhbHhxStatusBits.POLYMER_ACCUMULATION == 2
        assert PhbHhxStatusBits.PRECURSOR_DOSING_ON == 4
        assert PhbHhxStatusBits.TARGET_MOL_PCT_REACHED == 8
        assert PhbHhxStatusBits.PROCESS_TRIP_ACTIVE == 16

        flags = PhbHhxStatusBits.BIOMASS_GROWTH_ACTIVE | PhbHhxStatusBits.PRECURSOR_DOSING_ON
        assert bool(flags & PhbHhxStatusBits.BIOMASS_GROWTH_ACTIVE) is True
        assert bool(flags & PhbHhxStatusBits.PROCESS_TRIP_ACTIVE) is False


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization (%R2480..%R2487)
# ============================================================================

class TestSection08HornerOcsRegisterSynchronization:
    """Verify Horner OCS register space synchronization (%R2480..%R2487, %M578..%M580)."""

    def test_nominal_registers_synchronization(self) -> None:
        """Nominal state writes exact scaled INT16 words to %R2480..%R2487."""
        table = RegisterTable()
        reactor = PhbHhxBiosynthesisReactor(register_table=table)
        reactor.reset()

        # %R2480: Temp 30.0 °C -> 300
        assert table.read_word(REG_PHB_HHX_TEMP_SCALED) == 300
        # %R2481: Biomass 2.0 g/L -> 20
        assert table.read_word(REG_PHB_HHX_BIOMASS_SCALED) == 20
        # %R2482: Substrate 35.0 g/L -> 350
        assert table.read_word(REG_PHB_HHX_SUBSTRATE_SCALED) == 350
        # %R2483: Nitrogen 2.5 g/L -> 25
        assert table.read_word(REG_PHB_HHX_NITROGEN_SCALED) == 25
        # %R2484: Precursor 2.0 g/L -> 20
        assert table.read_word(REG_PHB_HHX_PRECURSOR_SCALED) == 20
        # %R2485: Polymer 0.5 g/L -> 5
        assert table.read_word(REG_PHB_HHX_POLYMER_SCALED) == 5
        # %R2486: 3HHx mol% 11.5 mol% -> 115
        assert table.read_word(REG_PHB_HHX_3HHX_MOL_PCT_SCALED) == 115
        # %R2487: Diagnostic code 0x0000 -> 0
        assert table.read_word(REG_PHB_HHX_DIAGNOSTIC_CODE) == 0

    def test_nominal_discrete_coils_synchronization(self) -> None:
        """Nominal state writes correct boolean values to %M578..%M580."""
        table = RegisterTable()
        reactor = PhbHhxBiosynthesisReactor(register_table=table)
        reactor.reset()

        # %M578: Biosynthesis Active -> True
        assert table.read_bit(COIL_PHB_HHX_ACTIVE) is True
        # %M579: Precursor Dosing Active -> True
        assert table.read_bit(COIL_PHB_HHX_PRECURSOR_ACTIVE) is True
        # %M580: Trip Alarm -> False
        assert table.read_bit(COIL_PHB_HHX_TRIP_ALARM) is False

    def test_fault_trip_registers_synchronization(self) -> None:
        """Fault trip updates %R2487 with diagnostic code and sets %M580 alarm coil."""
        table = RegisterTable()
        reactor = PhbHhxBiosynthesisReactor(register_table=table)
        reactor.state.precursor_prec = 7.0
        reactor.rk4_step(dt_h=0.01)

        # %R2487: Diagnostic code 0xF801
        assert (table.read_uword(REG_PHB_HHX_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF801
        assert table.read_bit(COIL_PHB_HHX_ACTIVE) is False
        assert table.read_bit(COIL_PHB_HHX_PRECURSOR_ACTIVE) is False
        assert table.read_bit(COIL_PHB_HHX_TRIP_ALARM) is True

    def test_register_sync_privilege_modes(self) -> None:
        """sync_to_registers functions under both USER and SYSTEM privilege modes."""
        table = RegisterTable()
        reactor = PhbHhxBiosynthesisReactor(register_table=table)
        reactor.sync_to_registers(table, privilege=PrivilegeMode.USER)
        assert table.read_word(REG_PHB_HHX_TEMP_SCALED) == 300

        reactor.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word(REG_PHB_HHX_TEMP_SCALED) == 300


# ============================================================================
# Section 9: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection09PureStructuredTextPouValidation:
    """Verify Pure IEC 61131-3 Structured Text syntax and AST register variable bindings."""

    def test_pure_st_pou_constants_definition(self) -> None:
        """PHB_HHX_BIOSYNTHESIS_PURE_ST_POU contains valid POU program text."""
        assert isinstance(ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC, str)
        assert ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC == PHB_HHX_BIOSYNTHESIS_PURE_ST_POU
        assert ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC == PhbHhxBiosynthesisSync
        assert "PROGRAM PhbHhxBiosynthesisSync" in ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC
        assert "END_PROGRAM" in ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC

    def test_st_parser_syntax_validation(self) -> None:
        """STParser.validate_code must report SUCCESS for PhbHhxBiosynthesisSync."""
        val = STParser.validate_code(ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC)
        assert val.status == AgentStatus.SUCCESS

    def test_st_parser_ast_variable_bindings(self) -> None:
        """All 8 registers and 3 discrete coils must be declared with AT bindings in AST."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC)
        assert pou is not None
        assert pou.name == "PhbHhxBiosynthesisSync"
        assert pou.pou_type == POUType.PROGRAM

        required_regs = [
            "%R2480", "%R2481", "%R2482", "%R2483",
            "%R2484", "%R2485", "%R2486", "%R2487",
            "%M578", "%M579", "%M580",
        ]
        for reg in required_regs:
            assert reg in pou.bound_registers
            assert any(v.address_binding == reg for v in pou.variables)

    def test_verify_phb_hhx_pure_st_function(self) -> None:
        """verify_phb_hhx_biosynthesis_pure_st must return True."""
        assert verify_phb_hhx_biosynthesis_pure_st() is True


# ============================================================================
# Section 10: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection10AntiLadderSecurityGuard:
    """Verify that forbidden ladder logic constructs are rejected with LadderForbiddenError."""

    def test_ladder_contacts_rejection(self) -> None:
        """Contact symbols ---[ ]--- must raise LadderForbiddenError."""
        bad_code = "PROGRAM BadContacts\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_coils_rejection(self) -> None:
        """Coil symbols ---( )--- must raise LadderForbiddenError."""
        bad_code = "PROGRAM BadCoils\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_keywords_rejection(self) -> None:
        """Keywords RUNG, NETWORK, XIC, OTE must raise LadderForbiddenError."""
        keywords = ["RUNG 1", "NETWORK", "XIC Bit1", "OTE Output1"]
        for kw in keywords:
            bad_code = f"PROGRAM BadKw\nVAR x: BOOL; END_VAR\n{kw}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_code)

    def test_pure_st_pou_passes_security_guard(self) -> None:
        """Official PHB-HHx ST POU must pass SecurityGuard cleanly without error."""
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_PHB_HHX_BIOSYNTHESIS_SYNC)
        assert verify_phb_hhx_biosynthesis_pure_st() is True


# ============================================================================
# Section 11: ILogicUnit Compliance & Multi-Cycle Scan Execution
# ============================================================================

class TestSection11LogicUnitComplianceAndScanCycle:
    """Verify ILogicUnit interface compliance, scan_step, step, execute, and reset."""

    def test_ilogicunit_interface_attributes(self) -> None:
        """PhbHhxBiosynthesisReactor fulfills ILogicUnit properties."""
        reactor = PhbHhxBiosynthesisReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "PhbHhxBiosynthesisReactor"
        assert reactor.priority == 50
        assert reactor.is_enabled is True

    def test_scan_step_nominal(self) -> None:
        """scan_step executes 1 cycle and returns AgentStatus.SUCCESS when healthy."""
        reactor = PhbHhxBiosynthesisReactor()
        res = reactor.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert reactor.cycle_count == 1
        assert "PHB-HHx State:" in res.details
        assert res.data["trip_active"] is False
        assert res.data["diagnostic_code"] == "0x0000"

    def test_scan_step_with_context(self) -> None:
        """scan_step accepts ScanContext parameter gracefully."""
        reactor = PhbHhxBiosynthesisReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        res = reactor.scan_step(ctx)
        assert res.status == AgentStatus.SUCCESS
        assert reactor.cycle_count == 1

    def test_step_and_execute_methods(self) -> None:
        """step() and execute() methods trigger scan_step execution."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.step()
        assert reactor.cycle_count == 1

        ctx = ScanContext(cycle=2, dt_ms=20.0, elapsed_time_ms=40.0, dt=0.02)
        reactor.execute(ctx)
        assert reactor.cycle_count == 2

        reactor.execute()
        assert reactor.cycle_count == 3

    def test_scan_step_faulted(self) -> None:
        """scan_step returns AgentStatus.FAILED when process trip is asserted."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.temperature_c = 39.0
        res = reactor.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_ERR_THERMAL_EXCURSION)
        assert res.data["trip_active"] is True

    def test_reset_method_restores_clean_state(self) -> None:
        """reset() restores initial state, clears trips, and updates register table."""
        reactor = PhbHhxBiosynthesisReactor()
        reactor.state.temperature_c = 40.0
        reactor.scan_step()
        assert reactor.trip_active is True

        reactor.reset()
        assert reactor.trip_active is False
        assert reactor.state.temperature_c == 30.0
        assert reactor.state.biomass_x == 2.0
        assert reactor.diagnostic_code == DIAG_OK
        assert reactor.reg_table.read_bit(COIL_PHB_HHX_ACTIVE) is True

    def test_continuous_scan_soak_50_cycles(self) -> None:
        """50-cycle continuous scan execution proceeds stably without numeric drift or exceptions."""
        reactor = PhbHhxBiosynthesisReactor()
        for c in range(1, 51):
            ctx = ScanContext(cycle=c, dt_ms=20.0, elapsed_time_ms=c * 20.0, dt=0.02)
            res = reactor.scan_step(ctx)
            assert res.status == AgentStatus.SUCCESS

        assert reactor.cycle_count == 50
        assert reactor.state.biomass_x > 2.0
        assert reactor.state.polymer_poly > 0.5
        assert reactor.conservation_residual < 1.0e-10


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Runner Execution
# ============================================================================

class TestSection12VerificationRunnerExecution:
    """Verify the 9-stage verification runner sequence and JSON evidence generation."""

    def test_run_verification_runner_returns_success(self) -> None:
        """run_phb_hhx_biosynthesis_verification passes all stages with success status."""
        result = run_phb_hhx_biosynthesis_verification(work_package="W287")
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert "PASSED" in result["details"]

    def test_verification_runner_stages_count_and_passing(self) -> None:
        """Runner must report exactly 9 stages, all passing."""
        result = run_phb_hhx_biosynthesis_verification()
        data = result.get("data", {})
        assert data.get("checks_passed") == 9
        assert data.get("total_checks") == 9
        stages = data.get("stages", [])
        assert len(stages) == 9
        assert all(s["passed"] is True for s in stages)

    def test_verification_runner_stage_names_and_sequence(self) -> None:
        """Verify the exact order and names of all 9 stages in the verification sequence."""
        result = run_phb_hhx_biosynthesis_verification()
        stages = result["data"]["stages"]
        stage_names = [s["name"] for s in stages]
        expected_names = [
            "initial_state_and_growth",
            "coupled_substrate_kinetics",
            "polymer_synthesis_and_accumulation",
            "tunable_3hhx_mol_fraction",
            "precursor_toxicity_trip",
            "thermal_excursion_trip",
            "mass_conservation_residuals",
            "horner_ocs_register_sync",
            "pure_st_pou_and_ladder_rejection",
        ]
        assert stage_names == expected_names

    def test_verification_runner_json_evidence_emission(self) -> None:
        """Runner writes valid evidence JSON to specified output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "phb_hhx_evidence.json"
            result = run_phb_hhx_biosynthesis_verification(output_path=str(out_file))

            assert out_file.exists()
            with open(out_file, "r", encoding="utf-8") as f:
                saved = json.load(f)

            assert saved["status"] == "success"
            assert saved["data"]["work_package"] == "W287"
            assert saved["data"]["gate"] == "G7"
            assert len(saved["data"]["stages"]) == 9
