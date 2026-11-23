"""Comprehensive Unit and Integration Test Suite for Wave W245:
Industrial Ethylbenzene Dehydrogenation to Styrene Monomer Catalytic Radial-Flow Reactor ODE Simulation.

Work Package: W245 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS (100+ Deterministic Assertions across 16 Test Classes)
Status Contract: Strict 4-State JSON output & evidence emission.

Covers 16 Engineering Test Classes:
1.  TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2.  TestDehydrogenationPhysicsAndKinetics: Reaction enthalpies (+121.0, +105.0, -64.0 kJ/mol), Arrhenius rate constants, activation energies.
3.  TestRK4NumericalSolver: RK4 state transitions, dt stability, convergence, non-negative concentrations.
4.  TestNominalSteadyStateConvergence: Conversion >= 68.0%, Selectivity >= 92.0%, Inlet 620 °C, Outlet 575 °C, Pressure 0.45 bar, Rate 4200 kg/h.
5.  TestConservationLawsAndThermodynamics: Mass conservation error < 1e-10 kg/s, elemental mass balance, enthalpy conservation < 1e-10 kW.
6.  TestThermalOvertempFault0xF201: Bed temp > 660 °C trips 0xF201, asserts %M482 emergency trip.
7.  TestVacuumLossFault0xF202: Pressure > 1.20 bar trips 0xF202, emergency trip %M482.
8.  TestSteamStarvationFault0xF203: Steam ratio < 7.0 pre-alarm %M481, < 6.0 trips 0xF203 coking shutdown.
9.  TestSelectivityDegradationFault0xF204: Selectivity < 85% trips 0xF204.
10. TestProcessSafetyStrictPriorityHierarchy: Strict priority resolution (0xF201 > 0xF202 > 0xF203 > 0xF204 > 0x0000).
11. TestHornerOCSSynchronizationAndRegisters: %R2060..%R2067, %M480..%M482 bit-exact synchronization, PrivilegeMode.SYSTEM.
12. TestPureSTAndSecurity: STParser & SecurityGuard verification of StyreneDehydrogenationSync POU.
13. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts `---[ ]---`, coils `---( )---`, rungs, networks, mnemonics) with LadderForbiddenError.
14. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
15. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
16. TestEdgeCasesAndConfigModels: Custom configurations, property aliases, and edge conditions.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import tracemalloc
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, ReadOnlyChannelError, RegisterTable

from jev_cscape.simulation.styrene_dehydrogenation import (
    BED_DP_MAX_MBAR,
    CATALYST_COKING_NOMINAL_PCT,
    COIL_EMERGENCY_TRIP,
    COIL_EMERGENCY_TRIP_ACTIVE,
    COIL_PREALARM_ACTIVE,
    COIL_REACTOR_ACTIVE,
    COIL_REACTOR_EMERGENCY_TRIP,
    COIL_STEAM_PREALARM,
    COIL_STEAM_STARVATION_PREALARM,
    COIL_STYRENE_ACTIVE,
    COIL_STYRENE_REACTOR_ACTIVE,
    COIL_STYRENE_REACTOR_RUNNING,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    EB_CONV_NOMINAL_PCT,
    MW_BZ,
    MW_C,
    MW_CH4,
    MW_EB,
    MW_ETHYLENE,
    MW_H,
    MW_H2,
    MW_O,
    MW_SM,
    MW_STEAM,
    MW_TOL,
    P_REACTOR_NOMINAL_BAR,
    P_REACTOR_NOMINAL_MBAR,
    P_VACUUM_LOSS_TRIP_BAR,
    P_VACUUM_LOSS_TRIP_MBAR,
    PureSTValidationResult,
    R_GAS_CONST,
    REACTOR_PRESSURE_MAX_MBAR,
    REG_BED_TEMP_SCALED,
    REG_CATALYST_COKING_SCALED,
    REG_COKING_INDEX_SCALED,
    REG_CONVERSION_SCALED,
    REG_DIAGNOSTIC_CODE,
    REG_EB_CONVERSION_SCALED,
    REG_INLET_TEMP_SCALED,
    REG_OPERATING_PRESSURE_SCALED,
    REG_OUTLET_TEMP_SCALED,
    REG_PRESSURE_SCALED,
    REG_PRODUCTION_RATE_SCALED,
    REG_REACTOR_BED_TEMPERATURE_SCALED,
    REG_REACTOR_INLET_TEMP_SCALED,
    REG_REACTOR_OUTLET_TEMP_SCALED,
    REG_REACTOR_PRESSURE_SCALED,
    REG_SELECTIVITY_SCALED,
    REG_STEAM_EB_RATIO_SCALED,
    REG_STEAM_RATIO_SCALED,
    REG_STEAM_TO_EB_RATIO_SCALED,
    REG_STYRENE_PRODUCTION_RATE_KG_H,
    REG_STYRENE_RATE_SCALED,
    REG_STYRENE_SELECTIVITY_SCALED,
    STEAM_EB_RATIO_NOMINAL,
    STEAM_EB_RATIO_PRE_ALARM,
    STEAM_EB_RATIO_TRIP,
    STYRENE_DEHYDROGENATION_PURE_ST_POU,
    STYRENE_DEHYDROGENATION_SYNC_POU,
    STYRENE_PROD_NOMINAL_KG_H,
    STYRENE_PURE_ST_POU,
    STYRENE_SEL_MIN_PCT,
    STYRENE_SEL_NOMINAL_PCT,
    STYRENE_SYNC_POU,
    StatusBits,
    StyreneConfig,
    StyreneDehydrogenation,
    StyreneDehydrogenationConfig,
    StyreneDehydrogenationDiagnosticCode,
    StyreneDehydrogenationEngine,
    StyreneDehydrogenationLogicUnit,
    StyreneDehydrogenationParameters,
    StyreneDehydrogenationSimulator,
    StyreneDehydrogenationState,
    StyreneDehydrogenationStatusBits,
    StyreneDiagCode,
    StyreneDiagnosticCode,
    StyreneEngine,
    StyreneLogicUnit,
    StyreneParameters,
    StyreneReactor,
    StyreneReactorDiagnosticCode,
    StyreneReactorLogicUnit,
    StyreneReactorStatusBits,
    StyreneReactorStatusWord,
    StyreneSimulator,
    StyreneState,
    StyreneStatusBits,
    StyreneStatusWord,
    T_BED_EXCURSION_TRIP_C,
    T_BED_NOMINAL_C,
    T_INLET_NOMINAL_C,
    T_OUTLET_NOMINAL_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    run_styrene_dehydrogenation_verification,
    run_styrene_reactor_verification,
    run_styrene_verification,
    validate_pure_st,
    verify_styrene_dehydrogenation_pure_st,
    verify_styrene_pure_st,
    verify_styrene_reactor_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate register bindings, diagnostic codes, enum representations, and status bits."""

    def test_diagnostic_codes_values(self) -> None:
        assert DiagnosticCode.REACTOR_OK == 0x0000
        assert DiagnosticCode.THERMAL_OVERTEMP == 0xF201
        assert DiagnosticCode.VACUUM_LOSS == 0xF202
        assert DiagnosticCode.STEAM_STARVATION == 0xF203
        assert DiagnosticCode.SELECTIVITY_DEGRADATION == 0xF204

    def test_diagnostic_code_signed_equality(self) -> None:
        # Signed 16-bit representation: 0xF201 - 0x10000 = -3583
        assert DiagnosticCode.THERMAL_OVERTEMP == -3583
        assert DiagnosticCode.VACUUM_LOSS == -3582
        assert DiagnosticCode.STEAM_STARVATION == -3581
        assert DiagnosticCode.SELECTIVITY_DEGRADATION == -3580
        assert DiagnosticCode.REACTOR_OK == 0

    def test_diagnostic_code_unsigned_equality(self) -> None:
        assert DiagnosticCode.THERMAL_OVERTEMP == 0xF201
        assert DiagnosticCode.VACUUM_LOSS == 0xF202
        assert DiagnosticCode.STEAM_STARVATION == 0xF203
        assert DiagnosticCode.SELECTIVITY_DEGRADATION == 0xF204
        assert DiagnosticCode.REACTOR_OK == 0x0000

    def test_diagnostic_code_lookup_via_missing(self) -> None:
        assert DiagnosticCode(-3583) == DiagnosticCode.THERMAL_OVERTEMP
        assert DiagnosticCode(-3582) == DiagnosticCode.VACUUM_LOSS
        assert DiagnosticCode(-3581) == DiagnosticCode.STEAM_STARVATION
        assert DiagnosticCode(-3580) == DiagnosticCode.SELECTIVITY_DEGRADATION
        assert DiagnosticCode(0xF201) == DiagnosticCode.THERMAL_OVERTEMP
        assert DiagnosticCode(0x0000) == DiagnosticCode.REACTOR_OK

    def test_diagnostic_code_bitwise_and(self) -> None:
        assert (DiagnosticCode.THERMAL_OVERTEMP & 0xFFFF) == 0xF201
        assert (0xFFFF & DiagnosticCode.VACUUM_LOSS) == 0xF202
        assert (DiagnosticCode.STEAM_STARVATION & 0xF000) == 0xF000
        assert (DiagnosticCode.SELECTIVITY_DEGRADATION & 0x00FF) == 0x0004

    def test_diagnostic_code_hashing(self) -> None:
        assert hash(DiagnosticCode.THERMAL_OVERTEMP) == hash(0xF201)
        assert hash(DiagnosticCode.VACUUM_LOSS) == hash(0xF202)
        assert hash(DiagnosticCode.REACTOR_OK) == hash(0)

    def test_status_bits_definitions(self) -> None:
        assert StyreneDehydrogenationStatusBits.RUNNING == 0x0001
        assert StyreneDehydrogenationStatusBits.STYRENE_REACTOR_ACTIVE == 0x0002
        assert StyreneDehydrogenationStatusBits.STEAM_STARVATION_PREALARM == 0x0004
        assert StyreneDehydrogenationStatusBits.REACTOR_EMERGENCY_TRIP == 0x0008
        assert StyreneDehydrogenationStatusBits.THERMAL_OVERTEMP_FAULT == 0x0010
        assert StyreneDehydrogenationStatusBits.VACUUM_LOSS_FAULT == 0x0020
        assert StyreneDehydrogenationStatusBits.STEAM_STARVATION_FAULT == 0x0040
        assert StyreneDehydrogenationStatusBits.SELECTIVITY_DEGRADATION_FAULT == 0x0080

    def test_status_bits_composition(self) -> None:
        flag = (
            StyreneDehydrogenationStatusBits.RUNNING
            | StyreneDehydrogenationStatusBits.STYRENE_REACTOR_ACTIVE
            | StyreneDehydrogenationStatusBits.STEAM_STARVATION_PREALARM
        )
        assert bool(flag & StyreneDehydrogenationStatusBits.RUNNING) is True
        assert bool(flag & StyreneDehydrogenationStatusBits.REACTOR_EMERGENCY_TRIP) is False

    def test_register_address_constants(self) -> None:
        assert REG_REACTOR_INLET_TEMP_SCALED == "%R2060"
        assert REG_EB_CONVERSION_SCALED == "%R2061"
        assert REG_STYRENE_SELECTIVITY_SCALED == "%R2062"
        assert REG_STEAM_TO_EB_RATIO_SCALED == "%R2063"
        assert REG_REACTOR_OUTLET_TEMP_SCALED == "%R2064"
        assert REG_OPERATING_PRESSURE_SCALED == "%R2065"
        assert REG_STYRENE_PRODUCTION_RATE_KG_H == "%R2066"
        assert REG_DIAGNOSTIC_CODE == "%R2067"

    def test_coil_address_constants(self) -> None:
        assert COIL_STYRENE_REACTOR_RUNNING == "%M480"
        assert COIL_STEAM_STARVATION_PREALARM == "%M481"
        assert COIL_REACTOR_EMERGENCY_TRIP == "%M482"

    def test_register_aliases_consistency(self) -> None:
        assert REG_REACTOR_BED_TEMPERATURE_SCALED == "%R2064"
        assert REG_OUTLET_TEMP_SCALED == "%R2064"
        assert REG_BED_TEMP_SCALED == "%R2064"
        assert REG_INLET_TEMP_SCALED == "%R2060"
        assert REG_PRESSURE_SCALED == "%R2065"
        assert REG_REACTOR_PRESSURE_SCALED == "%R2065"
        assert REG_CONVERSION_SCALED == "%R2061"
        assert REG_SELECTIVITY_SCALED == "%R2062"
        assert REG_STEAM_RATIO_SCALED == "%R2063"
        assert REG_STEAM_EB_RATIO_SCALED == "%R2063"
        assert REG_PRODUCTION_RATE_SCALED == "%R2066"
        assert REG_STYRENE_RATE_SCALED == "%R2066"
        assert REG_COKING_INDEX_SCALED == "%R2066"

    def test_coil_aliases_consistency(self) -> None:
        assert COIL_STYRENE_REACTOR_ACTIVE == "%M480"
        assert COIL_STYRENE_ACTIVE == "%M480"
        assert COIL_REACTOR_ACTIVE == "%M480"
        assert COIL_STEAM_PREALARM == "%M481"
        assert COIL_PREALARM_ACTIVE == "%M481"
        assert COIL_EMERGENCY_TRIP == "%M482"
        assert COIL_EMERGENCY_TRIP_ACTIVE == "%M482"

    def test_diagnostic_code_aliases(self) -> None:
        assert StyreneDehydrogenationDiagnosticCode is DiagnosticCode
        assert StyreneDiagnosticCode is DiagnosticCode
        assert StyreneDiagCode is DiagnosticCode
        assert StyreneReactorDiagnosticCode is DiagnosticCode

    def test_status_bits_aliases(self) -> None:
        assert StyreneStatusBits is StyreneDehydrogenationStatusBits
        assert StyreneStatusWord is StyreneDehydrogenationStatusBits
        assert StyreneReactorStatusBits is StyreneDehydrogenationStatusBits
        assert StatusBits is StyreneDehydrogenationStatusBits


# ============================================================================
# 2. TestDehydrogenationPhysicsAndKinetics
# ============================================================================

class TestDehydrogenationPhysicsAndKinetics:
    """Validate chemical stoichiometry, thermochemical enthalpies, and Arrhenius kinetics."""

    def test_universal_physical_constants(self) -> None:
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-9)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, abs_tol=1e-6)
        assert math.isclose(T_REF_K, 575.0 + 273.15, abs_tol=1e-6)

    def test_molecular_weights_iupac(self) -> None:
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)

    def test_hydrocarbon_species_molecular_weights(self) -> None:
        assert math.isclose(MW_EB, 8.0 * MW_C + 10.0 * MW_H, rel_tol=1e-9)
        assert math.isclose(MW_SM, 8.0 * MW_C + 8.0 * MW_H, rel_tol=1e-9)
        assert math.isclose(MW_H2, 2.0 * MW_H, rel_tol=1e-9)
        assert math.isclose(MW_BZ, 6.0 * MW_C + 6.0 * MW_H, rel_tol=1e-9)
        assert math.isclose(MW_ETHYLENE, 2.0 * MW_C + 4.0 * MW_H, rel_tol=1e-9)
        assert math.isclose(MW_TOL, 7.0 * MW_C + 8.0 * MW_H, rel_tol=1e-9)
        assert math.isclose(MW_CH4, 1.0 * MW_C + 4.0 * MW_H, rel_tol=1e-9)
        assert math.isclose(MW_STEAM, 2.0 * MW_H + MW_O, rel_tol=1e-9)

    def test_reaction1_stoichiometric_mass_balance(self) -> None:
        # R1: C8H10 (EB) <=> C8H8 (SM) + H2
        mass_in = MW_EB
        mass_out = MW_SM + MW_H2
        assert abs(mass_in - mass_out) < 1e-12

    def test_reaction2_stoichiometric_mass_balance(self) -> None:
        # R2: C8H10 (EB) -> C6H6 (BZ) + C2H4 (Ethylene)
        mass_in = MW_EB
        mass_out = MW_BZ + MW_ETHYLENE
        assert abs(mass_in - mass_out) < 1e-12

    def test_reaction3_stoichiometric_mass_balance(self) -> None:
        # R3: C8H10 (EB) + H2 -> C7H8 (TOL) + CH4
        mass_in = MW_EB + MW_H2
        mass_out = MW_TOL + MW_CH4
        assert abs(mass_in - mass_out) < 1e-12

    def test_reaction_enthalpies(self) -> None:
        # R1 primary dehydrogenation: +121.0 kJ/mol (endothermic)
        assert DELTA_H1_KJ_MOL == 121.0
        assert DELTA_H1_J_MOL == 121000.0

        # R2 side pyrolysis: +105.0 kJ/mol (endothermic)
        assert DELTA_H2_KJ_MOL == 105.0
        assert DELTA_H2_J_MOL == 105000.0

        # R3 side hydrodealkylation: -64.0 kJ/mol (exothermic)
        assert DELTA_H3_KJ_MOL == -64.0
        assert DELTA_H3_J_MOL == -64000.0

    def test_arrhenius_kinetics_temperature_monotonicity(self) -> None:
        sim = StyreneDehydrogenation()
        t_low = 560.0 + T_ZERO_CELSIUS
        t_mid = 575.0 + T_ZERO_CELSIUS
        t_high = 620.0 + T_ZERO_CELSIUS

        k1_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_low)
        k1_mid = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_mid)
        k1_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_high)

        assert k1_high > k1_mid > k1_low > 0.0

        k2_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t_low)
        k2_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t_high)
        assert k2_high > k2_low > 0.0

        k3_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t_low)
        k3_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t_high)
        assert k3_high > k3_low > 0.0

    def test_arrhenius_activation_energy_recovery(self) -> None:
        sim = StyreneDehydrogenation()
        t_low = 560.0 + T_ZERO_CELSIUS
        t_high = 620.0 + T_ZERO_CELSIUS

        k1_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_low)
        k1_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_high)

        # Arrhenius slope formula: Ea = -R * ln(k2/k1) / (1/T2 - 1/T1)
        recovered_ea1 = -R_GAS_CONST * math.log(k1_high / k1_low) / ((1.0 / t_high) - (1.0 / t_low))
        assert abs(recovered_ea1 - sim.config.activation_e1_j_mol) < 1e-3

    def test_equilibrium_constant_temperature_shift(self) -> None:
        sim = StyreneDehydrogenation()
        t_low = 560.0 + T_ZERO_CELSIUS
        t_high = 620.0 + T_ZERO_CELSIUS

        keq_low = sim.compute_equilibrium_constant(t_low)
        keq_high = sim.compute_equilibrium_constant(t_high)

        # Endothermic reaction shifts forward at higher temperature
        assert keq_high > keq_low > 0.0


# ============================================================================
# 3. TestRK4NumericalSolver
# ============================================================================

class TestRK4NumericalSolver:
    """Validate 6-state ODE derivative formulation and Runge-Kutta 4th order solver."""

    def test_compute_derivatives_structure_and_length(self) -> None:
        sim = StyreneDehydrogenation()
        y = [0.55269, 1.12016, 1.08346, 0.045, 0.0367, 575.0]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6

    def test_compute_derivatives_finiteness(self) -> None:
        sim = StyreneDehydrogenation()
        y = [0.55269, 1.12016, 1.08346, 0.045, 0.0367, 575.0]
        derivs = sim.compute_derivatives(0.0, y)
        assert all(not math.isnan(d) for d in derivs)
        assert all(not math.isinf(d) for d in derivs)

    def test_rk4_step_advances_simulation_time(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        t_start = sim.state.sim_time_s
        sim.step(dt=0.02)
        assert abs(sim.state.sim_time_s - (t_start + 0.02)) < 1e-6

    def test_rk4_step_increments_scan_count(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sc_start = sim.state.scan_count
        sim.step(dt=0.02)
        assert sim.state.scan_count == sc_start + 1

    def test_rk4_step_returns_execution_result(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        res = sim.step(dt=0.02)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None

    def test_non_negative_concentration_clamping(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        # Set state near zero
        sim.state.c_eb = 0.0
        sim.state.c_sm = 0.0
        sim.step(dt=0.02)
        assert sim.state.c_eb >= 0.0
        assert sim.state.c_sm >= 0.0
        assert sim.state.c_h2 >= 0.0

    def test_advance_time_multi_step_trajectory(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        res = sim.advance_time(duration_s=1.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert abs(sim.state.sim_time_s - 1.0) < 1e-5
        assert sim.state.scan_count == 50

    def test_advance_time_rejects_non_positive_duration_or_dt(self) -> None:
        sim = StyreneDehydrogenation()
        res_zero = sim.advance_time(duration_s=0.0)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.02)
        assert res_neg.status == AgentStatus.FAILED


# ============================================================================
# 4. TestNominalSteadyStateConvergence
# ============================================================================

class TestNominalSteadyStateConvergence:
    """Validate nominal operating regime convergence and baseline telemetry."""

    def test_nominal_temperatures(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        assert math.isclose(sim.config.nominal_inlet_temp_c, 620.0, abs_tol=0.1)
        assert math.isclose(sim.state.t_bed_c, 575.0, abs_tol=0.5)
        # Adiabatic temperature drop of approximately 45 °C
        delta_t = sim.config.nominal_inlet_temp_c - sim.state.t_bed_c
        assert math.isclose(delta_t, 45.0, abs_tol=0.5)

    def test_nominal_operating_pressure(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        assert math.isclose(sim.state.p_reactor_bar, 0.45, abs_tol=0.01)
        assert math.isclose(sim.state.p_reactor_mbar, 450.0, abs_tol=10.0)

    def test_nominal_eb_conversion(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        assert sim.state.eb_conversion_pct >= 68.0
        assert math.isclose(sim.state.eb_conversion_pct, 68.50, abs_tol=0.5)

    def test_nominal_styrene_selectivity(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        assert sim.state.styrene_selectivity_pct >= 92.0
        assert math.isclose(sim.state.styrene_selectivity_pct, 92.40, abs_tol=0.5)

    def test_nominal_production_rate(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        assert math.isclose(sim.state.styrene_production_rate_kg_h, 4200.0, abs_tol=50.0)

    def test_nominal_steam_eb_molar_ratio(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        assert 8.0 <= sim.state.steam_eb_molar_ratio <= 12.0
        assert math.isclose(sim.state.steam_eb_molar_ratio, 8.50, abs_tol=0.1)

    def test_nominal_catalyst_coking_index(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        assert math.isclose(sim.state.catalyst_coking_index_pct, 1.20, abs_tol=0.1)

    def test_nominal_discrete_coils_and_diagnostic(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK
        assert sim.state.styrene_reactor_running is True
        assert sim.state.steam_starvation_prealarm is False
        assert sim.state.reactor_emergency_trip is False


# ============================================================================
# 5. TestConservationLawsAndThermodynamics
# ============================================================================

class TestConservationLawsAndThermodynamics:
    """Validate mathematical mass, elemental, and enthalpy conservation (< 1e-10)."""

    def test_total_mass_balance_residual_less_than_1e10(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_carbon_balance_residual_less_than_1e10(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_hydrogen_balance_residual_less_than_1e10(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_total_mass_residual_less_than_1e10(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_residuals_conserved_over_extended_simulation(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        for _ in range(50):
            sim.step(dt=0.02)
            assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_thermal_duty_components_balance(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        kin = sim.compute_kinetics(
            t_bed_k=575.0 + T_ZERO_CELSIUS,
            c_eb=sim.state.c_eb,
            c_sm=sim.state.c_sm,
            c_h2=sim.state.c_h2,
        )
        assert kin["q1_kw"] > 1000.0   # Endothermic dehydrogenation load
        assert kin["q2_kw"] > 0.0      # Endothermic pyrolysis
        assert kin["q3_kw"] < 0.0      # Exothermic hydrodealkylation release
        assert kin["q_total_kw"] > 1000.0


# ============================================================================
# 6. TestThermalOvertempFault0xF201
# ============================================================================

class TestThermalOvertempFault0xF201:
    """Validate 0xF201 bed over-temperature runaway trip and %M482 actuation."""

    def test_overtemp_trip_threshold_trips_0xF201(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 665.0  # > 660.0 °C threshold
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_OVERTEMP

    def test_overtemp_trip_asserts_emergency_trip_coil_m482(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 665.0
        sim._evaluate_safety_interlocks()
        assert sim.state.reactor_emergency_trip is True

    def test_overtemp_trip_clears_reactor_running_coil_m480(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 665.0
        sim._evaluate_safety_interlocks()
        assert sim.state.styrene_reactor_running is False

    def test_overtemp_trip_sets_status_bit(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 665.0
        sim._evaluate_safety_interlocks()
        assert StyreneDehydrogenationStatusBits.THERMAL_OVERTEMP_FAULT in sim.state.status_bits
        assert StyreneDehydrogenationStatusBits.REACTOR_EMERGENCY_TRIP in sim.state.status_bits

    def test_overtemp_at_safe_temperature_does_not_trip(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 650.0  # Safe temperature below 660 °C
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.styrene_reactor_running is True

    def test_overtemp_purging_flushes_hydrocarbons(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 665.0
        sim._evaluate_safety_interlocks()
        sim.advance_time(duration_s=6.0, dt=0.02)
        assert sim.state.c_eb < 0.10
        assert sim.state.c_sm < 0.10

    def test_overtemp_reaction_power_quenched(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 665.0
        sim._evaluate_safety_interlocks()
        sim._update_kinetics_and_conversion()
        assert sim.state.q_rxn_total_kw == 0.0


# ============================================================================
# 7. TestVacuumLossFault0xF202
# ============================================================================

class TestVacuumLossFault0xF202:
    """Validate 0xF202 vacuum loss / overpressure trip and %M482 actuation."""

    def test_vacuum_loss_threshold_trips_0xF202(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.p_reactor_bar = 1.25  # > 1.20 bar threshold
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS

    def test_vacuum_loss_asserts_emergency_trip_coil_m482(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.p_reactor_bar = 1.25
        sim._evaluate_safety_interlocks()
        assert sim.state.reactor_emergency_trip is True

    def test_vacuum_loss_clears_reactor_running_coil_m480(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.p_reactor_bar = 1.25
        sim._evaluate_safety_interlocks()
        assert sim.state.styrene_reactor_running is False

    def test_vacuum_loss_sets_status_bit(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.p_reactor_bar = 1.25
        sim._evaluate_safety_interlocks()
        assert StyreneDehydrogenationStatusBits.VACUUM_LOSS_FAULT in sim.state.status_bits
        assert StyreneDehydrogenationStatusBits.REACTOR_EMERGENCY_TRIP in sim.state.status_bits

    def test_nominal_vacuum_0_45_bar_does_not_trip(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.p_reactor_bar = 0.45
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.styrene_reactor_running is True

    def test_vacuum_loss_subatmospheric_margin(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.p_reactor_bar = 0.90  # Elevated but under 1.20 bar
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code != DiagnosticCode.VACUUM_LOSS


# ============================================================================
# 8. TestSteamStarvationFault0xF203
# ============================================================================

class TestSteamStarvationFault0xF203:
    """Validate 0xF203 steam starvation coking trip and %M481 pre-alarm."""

    def test_steam_starvation_prealarm_coil_m481_activates(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.steam_eb_molar_ratio = 6.8  # < 7.0 pre-alarm threshold
        sim._evaluate_safety_interlocks()
        assert sim.state.steam_starvation_prealarm is True

    def test_steam_starvation_prealarm_does_not_trip_reactor(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.steam_eb_molar_ratio = 6.8
        sim._evaluate_safety_interlocks()
        assert sim.state.styrene_reactor_running is True
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_steam_starvation_shutdown_threshold_trips_0xF203(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.steam_eb_molar_ratio = 5.5  # < 6.0 shutdown threshold
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STEAM_STARVATION

    def test_steam_starvation_shutdown_asserts_emergency_trip_coil_m482(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.steam_eb_molar_ratio = 5.5
        sim._evaluate_safety_interlocks()
        assert sim.state.reactor_emergency_trip is True

    def test_steam_starvation_shutdown_clears_reactor_running_coil_m480(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.steam_eb_molar_ratio = 5.5
        sim._evaluate_safety_interlocks()
        assert sim.state.styrene_reactor_running is False

    def test_steam_starvation_shutdown_sets_status_bit(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.steam_eb_molar_ratio = 5.5
        sim._evaluate_safety_interlocks()
        assert StyreneDehydrogenationStatusBits.STEAM_STARVATION_FAULT in sim.state.status_bits
        assert StyreneDehydrogenationStatusBits.REACTOR_EMERGENCY_TRIP in sim.state.status_bits

    def test_adequate_steam_ratio_clears_prealarm(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.steam_eb_molar_ratio = 9.5
        sim._evaluate_safety_interlocks()
        assert sim.state.steam_starvation_prealarm is False

    def test_steam_starvation_accelerates_catalyst_coking(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.steam_eb_molar_ratio = 6.5
        coking_before = sim.state.catalyst_coking_index_pct
        sim.step(dt=0.02)
        assert sim.state.catalyst_coking_index_pct > coking_before


# ============================================================================
# 9. TestSelectivityDegradationFault0xF204
# ============================================================================

class TestSelectivityDegradationFault0xF204:
    """Validate 0xF204 selectivity degradation warning without emergency trip."""

    def test_selectivity_degradation_threshold_sets_0xF204(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.styrene_selectivity_pct = 82.0  # < 85.0% threshold
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.SELECTIVITY_DEGRADATION

    def test_selectivity_degradation_non_tripping_keeps_m480(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.styrene_selectivity_pct = 82.0
        sim._evaluate_safety_interlocks()
        assert sim.state.styrene_reactor_running is True

    def test_selectivity_degradation_keeps_m482_cleared(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.styrene_selectivity_pct = 82.0
        sim._evaluate_safety_interlocks()
        assert sim.state.reactor_emergency_trip is False

    def test_selectivity_degradation_sets_status_bit(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.styrene_selectivity_pct = 82.0
        sim._evaluate_safety_interlocks()
        assert StyreneDehydrogenationStatusBits.SELECTIVITY_DEGRADATION_FAULT in sim.state.status_bits

    def test_high_selectivity_clears_0xF204(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.styrene_selectivity_pct = 93.20  # Safe selectivity
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_selectivity_degradation_signed_equality(self) -> None:
        assert DiagnosticCode.SELECTIVITY_DEGRADATION == -3580
        assert DiagnosticCode(-3580) == DiagnosticCode.SELECTIVITY_DEGRADATION


# ============================================================================
# 10. TestProcessSafetyStrictPriorityHierarchy
# ============================================================================

class TestProcessSafetyStrictPriorityHierarchy:
    """Validate strict priority resolution among competing faults (P1 > P2 > P3 > P4 > P5)."""

    def test_all_faults_simultaneous_priority_1_overtemp_wins(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        # Activate P1, P2, P3, and P4 simultaneously
        sim.state.t_bed_c = 665.0               # P1: 0xF201
        sim.state.p_reactor_bar = 1.30          # P2: 0xF202
        sim.state.steam_eb_molar_ratio = 5.0    # P3: 0xF203
        sim.state.styrene_selectivity_pct = 80.0# P4: 0xF204
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_OVERTEMP
        assert sim.state.reactor_emergency_trip is True
        assert sim.state.styrene_reactor_running is False

    def test_clear_p1_priority_2_vacuum_loss_wins(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 575.0               # P1 cleared
        sim.state.p_reactor_bar = 1.30          # P2: 0xF202
        sim.state.steam_eb_molar_ratio = 5.0    # P3: 0xF203
        sim.state.styrene_selectivity_pct = 80.0# P4: 0xF204
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS
        assert sim.state.reactor_emergency_trip is True
        assert sim.state.styrene_reactor_running is False

    def test_clear_p2_priority_3_steam_starvation_wins(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 575.0               # P1 cleared
        sim.state.p_reactor_bar = 0.45          # P2 cleared
        sim.state.steam_eb_molar_ratio = 5.0    # P3: 0xF203
        sim.state.styrene_selectivity_pct = 80.0# P4: 0xF204
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STEAM_STARVATION
        assert sim.state.reactor_emergency_trip is True
        assert sim.state.styrene_reactor_running is False

    def test_clear_p3_priority_4_selectivity_degradation_wins(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 575.0               # P1 cleared
        sim.state.p_reactor_bar = 0.45          # P2 cleared
        sim.state.steam_eb_molar_ratio = 9.5    # P3 cleared
        sim.state.styrene_selectivity_pct = 80.0# P4: 0xF204
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.SELECTIVITY_DEGRADATION
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.styrene_reactor_running is True

    def test_clear_p4_priority_5_reactor_ok_wins(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.t_bed_c = 575.0               # P1 cleared
        sim.state.p_reactor_bar = 0.45          # P2 cleared
        sim.state.steam_eb_molar_ratio = 9.5    # P3 cleared
        sim.state.styrene_selectivity_pct = 93.2# P4 cleared
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.styrene_reactor_running is True

    def test_fail_safe_lockout_priority(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()
        sim.state.reactor_emergency_trip = True
        sim._evaluate_safety_interlocks()
        assert sim.state.styrene_reactor_running is False


# ============================================================================
# 11. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate bit-exact Horner OCS memory map (%R2060..%R2067, %M480..%M482)."""

    def test_sync_registers_nominal_values(self) -> None:
        table = RegisterTable()
        sim = StyreneDehydrogenation(register_table=table)
        sim.reset()

        assert table.read_word("%R2060") == 6200   # 620.0 °C inlet temp scaled x10
        assert table.read_word("%R2061") == 6850   # 68.50% conversion scaled x100
        assert table.read_word("%R2062") == 9240   # 92.40% selectivity scaled x100
        assert table.read_word("%R2063") == 850    # 8.50:1 steam:EB ratio scaled x100
        assert table.read_word("%R2064") == 5750   # 575.0 °C outlet temp scaled x10
        assert table.read_word("%R2065") == 45     # 0.45 bar scaled x100
        assert table.read_word("%R2066") == 4200   # 4200 kg/h
        assert table.read_uword("%R2067") == 0x0000# REACTOR_OK

    def test_sync_discrete_coils_nominal(self) -> None:
        table = RegisterTable()
        sim = StyreneDehydrogenation(register_table=table)
        sim.reset()

        assert table.read_bit("%M480") is True     # StyreneReactorActive
        assert table.read_bit("%M481") is False    # SteamStarvationPreAlarm
        assert table.read_bit("%M482") is False    # ReactorEmergencyTrip

    def test_sync_registers_overtemp_fault_0xF201(self) -> None:
        table = RegisterTable()
        sim = StyreneDehydrogenation(register_table=table)
        sim.reset()
        sim.state.t_bed_c = 665.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert table.read_uword("%R2067") == 0xF201
        assert table.read_word("%R2067") == -3583
        assert table.read_bit("%M480") is False
        assert table.read_bit("%M482") is True

    def test_sync_registers_vacuum_loss_fault_0xF202(self) -> None:
        table = RegisterTable()
        sim = StyreneDehydrogenation(register_table=table)
        sim.reset()
        sim.state.p_reactor_bar = 1.25
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert table.read_uword("%R2067") == 0xF202
        assert table.read_word("%R2067") == -3582
        assert table.read_bit("%M480") is False
        assert table.read_bit("%M482") is True

    def test_sync_registers_steam_starvation_fault_0xF203(self) -> None:
        table = RegisterTable()
        sim = StyreneDehydrogenation(register_table=table)
        sim.reset()
        sim.state.steam_eb_molar_ratio = 5.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert table.read_uword("%R2067") == 0xF203
        assert table.read_word("%R2067") == -3581
        assert table.read_bit("%M480") is False
        assert table.read_bit("%M481") is True
        assert table.read_bit("%M482") is True

    def test_sync_registers_selectivity_degradation_0xF204(self) -> None:
        table = RegisterTable()
        sim = StyreneDehydrogenation(register_table=table)
        sim.reset()
        sim.state.styrene_selectivity_pct = 82.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert table.read_uword("%R2067") == 0xF204
        assert table.read_word("%R2067") == -3580
        assert table.read_bit("%M480") is True
        assert table.read_bit("%M482") is False

    def test_system_privilege_mode_enforcement(self) -> None:
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.SYSTEM
        sim = StyreneDehydrogenation(register_table=table)
        sim.reset()
        # Ensure sync succeeds cleanly with SYSTEM privilege
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2060") == 6200

    def test_unprivileged_write_rejected(self) -> None:
        table = RegisterTable()
        with pytest.raises(ReadOnlyChannelError):
            table.write_word("%AI1", 100, privilege=PrivilegeMode.APPLICATION)
        table.write_word("%AI1", 100, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%AI1") == 100

    def test_backward_compatible_registers_also_updated(self) -> None:
        table = RegisterTable()
        sim = StyreneDehydrogenation(register_table=table)
        sim.reset()
        # Legacy %R1850..%R1857 & %M431..%M433 are populated
        assert table.read_word("%R1850") == 5750
        assert table.read_uword("%R1857") == 0x0000
        assert table.read_bit("%M431") is True


# ============================================================================
# 12. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 Structured Text POU and AST parsing."""

    def test_pure_st_security_guard_assertion(self) -> None:
        SecurityGuard.assert_pure_st_content(STYRENE_DEHYDROGENATION_PURE_ST_POU)

    def test_st_parser_syntax_validation(self) -> None:
        val = STParser.validate_code(STYRENE_DEHYDROGENATION_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

    def test_st_pou_ast_parsing(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(STYRENE_DEHYDROGENATION_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "StyreneDehydrogenationSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_st_pou_bound_registers(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(STYRENE_DEHYDROGENATION_PURE_ST_POU)
        assert ast is not None
        expected_regs = [
            "%R2060", "%R2061", "%R2062", "%R2063",
            "%R2064", "%R2065", "%R2066", "%R2067",
            "%M480", "%M481", "%M482",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_verify_styrene_pure_st_function(self) -> None:
        res = verify_styrene_dehydrogenation_pure_st()
        assert bool(res) is True
        assert res.status == AgentStatus.SUCCESS

    def test_pou_text_aliases(self) -> None:
        assert STYRENE_DEHYDROGENATION_SYNC_POU == STYRENE_DEHYDROGENATION_PURE_ST_POU
        assert STYRENE_PURE_ST_POU == STYRENE_DEHYDROGENATION_PURE_ST_POU
        assert STYRENE_SYNC_POU == STYRENE_DEHYDROGENATION_PURE_ST_POU


# ============================================================================
# 13. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate strict rejection of 6+ ladder logic constructs (ERR_LADDER_FORBIDDEN)."""

    def test_reject_ladder_contact(self) -> None:
        bad_code = "PROGRAM Bad ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_negated_contact(self) -> None:
        bad_code = "PROGRAM Bad ---[/]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_coil(self) -> None:
        bad_code = "PROGRAM Bad ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_set_coil(self) -> None:
        bad_code = "PROGRAM Bad ---(S)--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_reset_coil(self) -> None:
        bad_code = "PROGRAM Bad ---(R)--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_rung_delimiter(self) -> None:
        bad_code = "PROGRAM Bad RUNG 1: X := 1; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_network_delimiter(self) -> None:
        bad_code = "PROGRAM Bad NETWORK 1: Y := 2; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_mnemonics_xic_ote(self) -> None:
        bad_xic = "PROGRAM Bad XIC(InputBit); END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_xic)

        bad_ote = "PROGRAM Bad OTE(OutputCoil); END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_ote)


# ============================================================================
# 14. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit protocol compliance and 100-cycle soak stability."""

    def test_ilogic_unit_properties(self) -> None:
        sim = StyreneDehydrogenation()
        assert sim.name == "StyreneDehydrogenationSync"
        assert sim.priority in (10, 100)
        assert sim.is_enabled is True

    def test_enable_disable_lifecycle(self) -> None:
        sim = StyreneDehydrogenation()
        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_scan_step_with_context(self) -> None:
        table = RegisterTable()
        sim = StyreneDehydrogenation(register_table=table)
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02, register_table=table)
        sim.scan_step(dt=0.02, context=ctx)
        assert sim.state.scan_count == 1
        assert abs(sim.state.sim_time_s - 0.02) < 1e-6
        assert table.read_word("%R2060") == 6200
        assert table.read_word("%R2064") == 5750

    def test_execute_via_scan_context(self) -> None:
        sim = StyreneDehydrogenation()
        ctx = ScanContext(cycle=2, dt_ms=20.0, elapsed_time_ms=40.0, dt=0.02)
        sim.execute(ctx)
        assert sim.state.scan_count == 1

    def test_reset_restores_nominal_state(self) -> None:
        sim = StyreneDehydrogenation()
        sim.state.t_bed_c = 665.0
        sim._evaluate_safety_interlocks()
        assert sim.state.reactor_emergency_trip is True
        sim.reset()
        assert sim.state.t_bed_c == 575.0
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.styrene_reactor_running is True
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_100_cycle_soak_stability(self) -> None:
        sim = StyreneDehydrogenation()
        sim.reset()

        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()
        for c in range(1, 101):
            ctx = ScanContext(cycle=c, dt_ms=20.0, elapsed_time_ms=c * 20.0, dt=0.02)
            sim.execute(ctx)
        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snap2.compare_to(snap1, "lineno")
        mem_diff_kb = sum(s.size_diff for s in stats if s.size_diff > 0) / 1024.0

        assert not math.isnan(sim.state.t_bed_c)
        assert not math.isnan(sim.state.c_sm)
        assert 560.0 <= sim.state.t_bed_c <= 590.0
        assert sim.state.eb_conversion_pct >= 67.0
        assert sim.state.styrene_selectivity_pct >= 91.0
        assert mem_diff_kb < 1000.0

    def test_logic_unit_adapter(self) -> None:
        unit = StyreneDehydrogenationLogicUnit()
        assert unit.name == "StyreneDehydrogenationSync"
        assert unit.is_enabled is True
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        assert unit.state.scan_count == 1
        unit.reset()
        assert unit.state.t_bed_c == 575.0


# ============================================================================
# 15. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate 9-stage verification runner returning strict 4-state contract."""

    def test_verification_runner_returns_dict(self) -> None:
        res = run_styrene_dehydrogenation_verification(work_package="W245")
        assert isinstance(res, dict)
        assert "status" in res
        assert "error_code" in res
        assert "details" in res
        assert "data" in res

    def test_verification_runner_status_success(self) -> None:
        res = run_styrene_dehydrogenation_verification(work_package="W245")
        assert res["status"] == "success"
        assert res["error_code"] is None

    def test_all_9_verification_stages_passed(self) -> None:
        res = run_styrene_dehydrogenation_verification(work_package="W245")
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_verification_stages_structure(self) -> None:
        res = run_styrene_dehydrogenation_verification(work_package="W245")
        tests = res["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert "stage" in t
            assert "check" in t
            assert "passed" in t
            assert t["passed"] is True

    def test_verification_file_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "w245_styrene_verification.json"
            res = run_styrene_dehydrogenation_verification(output_path=out_file)
            assert out_file.exists()
            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["data"]["checks_passed"] == 9

    def test_verification_runner_aliases(self) -> None:
        assert run_styrene_verification is run_styrene_dehydrogenation_verification
        assert run_styrene_reactor_verification is run_styrene_dehydrogenation_verification


# ============================================================================
# 16. TestEdgeCasesAndConfigModels
# ============================================================================

class TestEdgeCasesAndConfigModels:
    """Validate custom configurations, property aliases, and edge conditions."""

    def test_custom_config_initialization(self) -> None:
        cfg = StyreneDehydrogenationConfig(
            nominal_bed_temp_c=580.0,
            nominal_reactor_pressure_bar=0.50,
            nominal_steam_eb_molar_ratio=11.0,
        )
        sim = StyreneDehydrogenation(config=cfg)
        assert sim.config.nominal_bed_temp_c == 580.0
        assert sim.state.t_bed_c == 580.0
        assert sim.state.p_reactor_bar == 0.50
        assert sim.state.steam_eb_molar_ratio == 11.0

    def test_state_property_setters(self) -> None:
        st = StyreneDehydrogenationState()
        st.bed_temp_c = 582.0
        assert st.t_bed_c == 582.0
        assert st.bed_temp_c == 582.0

        st.outlet_temp_c = 578.0
        assert st.t_bed_c == 578.0

        st.inlet_pressure_bar = 0.55
        assert st.p_reactor_bar == 0.55
        assert st.p_reactor_mbar == 550.0

    def test_zero_feed_rate_graceful_handling(self) -> None:
        sim = StyreneDehydrogenation()
        sim.config.nominal_eb_feed_rate_mol_s = 0.0
        sim.state.c_eb = 0.0
        sim.state.c_sm = 0.0
        sim.state.c_bz = 0.0
        sim.state.c_tol = 0.0
        sim.step(dt=0.02)
        assert sim.state.eb_conversion_pct == 0.0
        assert sim.state.styrene_selectivity_pct == 0.0
        assert sim.state.styrene_production_rate_kg_h == 0.0

    def test_invalid_step_duration_negative(self) -> None:
        sim = StyreneDehydrogenation()
        res = sim.advance_time(duration_s=-1.0)
        assert res.status == AgentStatus.FAILED

    def test_diagnostic_code_missing_fallback(self) -> None:
        assert DiagnosticCode._missing_(999999) is None
        assert DiagnosticCode._missing_("invalid_code") is None

    def test_diagnostic_code_bitwise_and_with_int(self) -> None:
        val = int(DiagnosticCode.THERMAL_OVERTEMP)
        assert val == 0xF201
        assert (val & 0xFFFF) == 0xF201

    def test_simulator_class_aliases(self) -> None:
        assert StyreneSimulator is StyreneDehydrogenation
        assert StyreneEngine is StyreneDehydrogenation
        assert StyreneReactor is StyreneDehydrogenation
        assert StyreneDehydrogenationSimulator is StyreneDehydrogenation
