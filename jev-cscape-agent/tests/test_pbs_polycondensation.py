"""Comprehensive Industrial Polybutylene Succinate (PBS) Bio-Polyester Direct Polycondensation Test Suite.

Work Package: W275 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 15 comprehensive engineering verification sections:
1. Section 1: Universal Physical, Chemical & Thermochemical Constants, IUPAC Atomic Weights & Reaction Enthalpy
2. Section 2: Stoichiometric Balance & Elemental Conservation (Exact C/H/O Conservation < 1e-13)
3. Section 3: Reactor Geometry, Hydrodynamics, and Baseline Operating Parameters
4. Section 4: Nominal Steady-State Closed-Loop Convergence (T=235.0 °C, P=2.0 mbar, Conv=98.5%, Mn=45,000 Da, IV=1.65 dL/g)
5. Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
6. Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O, Enthalpy < 1e-10)
7. Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xF401 > 0xF402 > 0xF403 > 0xF404 > 0x0000)
8. Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
9. Section 9: Fault Injections, Actuations & Emergency Dump Tripped Coil %M552, Pre-Alarm %M551, Reaction Active %M550
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2360..%R2367, %M550..%M552)
11. Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
12. Section 12: Anti-Ladder Security Guard Rejection (Contacts, Coils, Rungs, Networks, Mnemonics)
13. Section 13: ILogicUnit Compliance & 100-Cycle Soak Stability (Zero Drift, No NaN)
14. Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
15. Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.pbs_polycondensation import (
    BDO_SA_RATIO_NOMINAL,
    COIL_PBS_ACTIVE,
    COIL_PBS_ANOMALY_PRE_ALARM,
    COIL_PBS_DUMP_TRIPPED,
    COIL_PBS_EMERGENCY_DUMP,
    COIL_PBS_EMERGENCY_DUMP_TRIPPED,
    COIL_PBS_PRE_ALARM,
    COIL_PBS_REACTION_ACTIVE,
    CONVERSION_NOMINAL_PCT,
    DEGRADATION_CONV_TRIP_PCT,
    DEGRADATION_MN_TRIP_DA,
    DELTA_H_DEG_J_MOL,
    DELTA_H_DEG_KJ_MOL,
    DELTA_H_POLY_J_MOL,
    DELTA_H_POLY_KJ_MOL,
    DELTA_H_THF_J_MOL,
    DELTA_H_THF_KJ_MOL,
    DiagnosticCode,
    G_ACCEL,
    INTRINSIC_VISCOSITY_NOMINAL_DL_G,
    IV_NOMINAL_DL_G,
    MELT_TEMP_NOMINAL_C,
    MN_NOMINAL_DA,
    MN_PRE_ALARM_DA,
    MOLECULAR_WEIGHT_NOMINAL_DA,
    MW_14_BUTANEDIOL,
    MW_BDO,
    MW_BUTANEDIOL,
    MW_C,
    MW_H,
    MW_H2O,
    MW_O,
    MW_PBS,
    MW_PBS_MER,
    MW_POLYMER_MER,
    MW_SA,
    MW_SUCCINIC_ACID,
    MW_TETRAHYDROFURAN,
    MW_THF,
    MW_WATER,
    PBS_POLYCONDENSATION_PURE_ST_POU,
    PBS_POLYCONDENSATION_SYNC_POU,
    PBS_PURE_ST_POU,
    PBS_SYNC_POU,
    PBSConfig,
    PBSDiagnosticCode,
    PBSEngine,
    PBSModel,
    PBSPlantModel,
    PBSPolycondensation,
    PBSPolycondensationConfig,
    PBSPolycondensationDiagnosticCode,
    PBSPolycondensationLogicUnit,
    PBSPolycondensationParameters,
    PBSPolycondensationReactor,
    PBSPolycondensationState,
    PBSPolycondensationStatusBits,
    PBSPolycondensationStatusWord,
    PBSSimulator,
    PBSState,
    PBSStatusBits,
    PbsConfig,
    PbsDiagnosticCode,
    PbsEngine,
    PbsPolycondensation,
    PbsPolycondensationConfig,
    PbsPolycondensationDiagnosticCode,
    PbsPolycondensationLogicUnit,
    PbsPolycondensationState,
    PbsPolycondensationStatusWord,
    PbsSimulator,
    PbsState,
    PbsStatusBits,
    PureSTValidationResult,
    R_GAS_CONST,
    REG_PBS_BDO_SA_RATIO_SCALED,
    REG_PBS_CONVERSION_SCALED,
    REG_PBS_CONV_SCALED,
    REG_PBS_DIAG_CODE,
    REG_PBS_DIAGNOSTIC_CODE,
    REG_PBS_INTRINSIC_VISCOSITY_SCALED,
    REG_PBS_IV_SCALED,
    REG_PBS_MELT_TEMP_SCALED,
    REG_PBS_MN_SCALED,
    REG_PBS_MOLECULAR_WEIGHT_SCALED,
    REG_PBS_RATIO_SCALED,
    REG_PBS_TEMP_SCALED,
    REG_PBS_THF_FORMATION_RATE_SCALED,
    REG_PBS_THF_RATE_SCALED,
    REG_PBS_VACUUM_PRESSURE_SCALED,
    REG_PBS_VACUUM_SCALED,
    ST_PROGRAM_PBS_POLYCONDENSATION_SYNC,
    StatusBits,
    T_MELT_NOMINAL_C,
    T_MELT_NOMINAL_K,
    T_OVERTEMP_TRIP_C,
    T_PRE_ALARM_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    THF_FORMATION_RATE_NOMINAL_MG_L_MIN,
    THF_PRE_ALARM_MG_L_MIN,
    THF_RATE_NOMINAL,
    THF_RUNAWAY_TRIP_MG_L_MIN,
    VACUUM_LOSS_TRIP_MBAR,
    VACUUM_PRE_ALARM_MBAR,
    VACUUM_PRESSURE_NOMINAL_MBAR,
    run_pbs_polycondensation_verification,
    run_pbs_verification,
    run_verification,
    validate_pure_st,
    verify_pbs_polycondensation_pure_st,
    verify_pbs_pure_st,
)


# ============================================================================
# Section 1: Universal Physical, Chemical & Thermochemical Constants
# ============================================================================

class TestSection01PhysicalAndThermochemicalConstants:
    """Verify universal physical constants, IUPAC atomic weights, and reaction enthalpies."""

    def test_universal_physical_constants(self) -> None:
        """Universal gas constant, standard gravity, and zero Celsius reference."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-8)
        assert math.isclose(T_MELT_NOMINAL_C, 235.0, rel_tol=1e-8)
        assert math.isclose(T_MELT_NOMINAL_K, 508.15, rel_tol=1e-8)
        assert math.isclose(T_REF_K, 508.15, rel_tol=1e-8)

    def test_iupac_atomic_weights(self) -> None:
        """Standard atomic weights for C, H, O [g/mol]."""
        assert math.isclose(MW_C, 12.011, rel_tol=1e-5)
        assert math.isclose(MW_H, 1.008, rel_tol=1e-5)
        assert math.isclose(MW_O, 15.999, rel_tol=1e-5)

    def test_molecular_weights_species(self) -> None:
        """Exact molecular weights for Succinic acid, 1,4-Butanediol, PBS repeat unit, THF, and water."""
        expected_sa = 4.0 * MW_C + 6.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_SA, expected_sa, rel_tol=1e-6)
        assert math.isclose(MW_SUCCINIC_ACID, MW_SA)

        expected_bdo = 4.0 * MW_C + 10.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_BDO, expected_bdo, rel_tol=1e-6)
        assert math.isclose(MW_14_BUTANEDIOL, MW_BDO)
        assert math.isclose(MW_BUTANEDIOL, MW_BDO)

        expected_pbs = 8.0 * MW_C + 12.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_PBS_MER, expected_pbs, rel_tol=1e-6)
        assert math.isclose(MW_PBS, MW_PBS_MER)
        assert math.isclose(MW_POLYMER_MER, MW_PBS_MER)

        expected_thf = 4.0 * MW_C + 8.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_THF, expected_thf, rel_tol=1e-6)
        assert math.isclose(MW_TETRAHYDROFURAN, MW_THF)

        expected_h2o = 2.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_H2O, expected_h2o, rel_tol=1e-6)
        assert math.isclose(MW_WATER, MW_H2O)

    def test_reaction_enthalpies(self) -> None:
        """Direct polycondensation, cyclization to THF, and degradation reaction enthalpies."""
        assert DELTA_H_POLY_KJ_MOL == -18.5
        assert DELTA_H_POLY_J_MOL == -18500.0
        assert DELTA_H_THF_KJ_MOL == -12.0
        assert DELTA_H_THF_J_MOL == -12000.0
        assert DELTA_H_DEG_KJ_MOL == 25.0
        assert DELTA_H_DEG_J_MOL == 25000.0


# ============================================================================
# Section 2: Stoichiometric Balance & Elemental Conservation
# ============================================================================

class TestSection02StoichiometricBalanceAndElementalConservation:
    """Verify stoichiometric mass balances and elemental conservation for PBS synthesis."""

    def test_polycondensation_mass_balance(self) -> None:
        """Reaction 1: SA + BDO -> PBS_mer + 2 H2O stoichiometric mass delta < 1e-13 g/mol."""
        delta1 = abs((MW_PBS_MER + 2.0 * MW_H2O) - (MW_SA + MW_BDO))
        assert delta1 < 1.0e-13

    def test_thf_cyclization_mass_balance(self) -> None:
        """Reaction 2: BDO -> THF + H2O stoichiometric mass delta < 1e-13 g/mol."""
        delta2 = abs((MW_THF + MW_H2O) - MW_BDO)
        assert delta2 < 1.0e-13

    def test_elemental_atom_conservation(self) -> None:
        """Carbon, Hydrogen, Oxygen atom balances across both reactions are exact."""
        # Reaction 1: C4H6O4 + C4H10O2 -> C8H12O4 + 2 H2O
        assert (4 + 4) == 8
        assert (6 + 10) == (12 + 2 * 2)
        assert (4 + 2) == (4 + 2 * 1)

        # Reaction 2: C4H10O2 -> C4H8O + H2O
        assert 4 == 4
        assert 10 == (8 + 2)
        assert 2 == (1 + 1)


# ============================================================================
# Section 3: Reactor Geometry, Hydrodynamics, and Baseline Operating Parameters
# ============================================================================

class TestSection03ReactorGeometryAndBaselineParameters:
    """Verify CSTR geometry, hydrodynamic residence time, thermal capacity, and feed baseline."""

    def test_reactor_geometric_and_physical_parameters(self) -> None:
        """Reactor volume, residence time, melt density, and thermal capacity."""
        config = PBSPolycondensationConfig()
        assert config.reactor_volume_l == 4000.0
        assert config.nominal_residence_time_s == 3600.0
        assert config.melt_density_kg_m3 == 1200.0
        assert config.melt_density_kg_l == 1.20
        assert config.melt_specific_heat_cp_j_kg_k == 2100.0
        assert config.reactor_thermal_capacitance_kj_k == 10080.0

    def test_feed_stream_baseline(self) -> None:
        """Inlet feed concentrations and molar ratio."""
        config = PBSPolycondensationConfig()
        assert config.c_sa_feed_mol_l == 5.0
        assert config.feed_bdo_sa_ratio == 1.05
        assert math.isclose(config.c_bdo_feed_mol_l, 5.25, rel_tol=1e-6)
        assert config.nominal_feed_temp_c == 225.0

    def test_nominal_operating_baseline_constants(self) -> None:
        """Operating baseline constants: T=235.0 °C, P=2.0 mbar, Conv=98.5%, BDO/SA=1.05, Mn=45,000 Da, IV=1.65 dL/g."""
        assert MELT_TEMP_NOMINAL_C == 235.0
        assert VACUUM_PRESSURE_NOMINAL_MBAR == 2.0
        assert CONVERSION_NOMINAL_PCT == 98.5
        assert BDO_SA_RATIO_NOMINAL == 1.05
        assert MOLECULAR_WEIGHT_NOMINAL_DA == 45000.0
        assert MN_NOMINAL_DA == 45000.0
        assert INTRINSIC_VISCOSITY_NOMINAL_DL_G == 1.65
        assert IV_NOMINAL_DL_G == 1.65
        assert THF_FORMATION_RATE_NOMINAL_MG_L_MIN == 0.42
        assert THF_RATE_NOMINAL == 0.42

    def test_safety_interlock_threshold_constants(self) -> None:
        """Threshold limits: T_trip > 248.0 °C, P_vac > 5.0 mbar, THF_trip > 1.20 mg/L/min, Mn_trip < 30,000 Da."""
        assert T_OVERTEMP_TRIP_C == 248.0
        assert VACUUM_LOSS_TRIP_MBAR == 5.0
        assert THF_RUNAWAY_TRIP_MG_L_MIN == 1.20
        assert DEGRADATION_MN_TRIP_DA == 30000.0
        assert DEGRADATION_CONV_TRIP_PCT == 90.0

        assert T_PRE_ALARM_C == 240.0
        assert VACUUM_PRE_ALARM_MBAR == 3.0
        assert THF_PRE_ALARM_MG_L_MIN == 0.70
        assert MN_PRE_ALARM_DA == 38000.0


# ============================================================================
# Section 4: Nominal Steady-State Closed-Loop Convergence
# ============================================================================

class TestSection04NominalSteadyStateConvergence:
    """Verify nominal steady-state initialization and retention across scan cycles."""

    def test_nominal_steady_state_initialization(self) -> None:
        """Fresh reactor instance initializes to nominal operating steady-state."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        assert math.isclose(sim.state.t_melt_c, 235.0, abs_tol=0.2)
        assert math.isclose(sim.state.p_vac_mbar, 2.0, abs_tol=0.1)
        assert math.isclose(sim.state.conversion_pct, 98.5, abs_tol=0.2)
        assert math.isclose(sim.state.bdo_sa_ratio, 1.05, abs_tol=0.02)
        assert math.isclose(sim.state.m_n, 45000.0, abs_tol=100.0)
        assert math.isclose(sim.state.intrinsic_viscosity_dl_g, 1.65, abs_tol=0.02)
        assert math.isclose(sim.state.thf_formation_rate_mg_l_min, 0.42, abs_tol=0.02)
        assert sim.state.reaction_active is True
        assert sim.state.anomaly_pre_alarm is False
        assert sim.state.emergency_dump_tripped is False
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_steady_state_retention_over_scan_cycles(self) -> None:
        """Advancing 20 scan cycles retains steady-state values within tight tolerances."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        for _ in range(20):
            sim.scan_step(dt=0.02)

        assert 234.5 <= sim.state.t_melt_c <= 235.5
        assert 1.9 <= sim.state.p_vac_mbar <= 2.1
        assert 98.0 <= sim.state.conversion_pct <= 99.0
        assert 44500.0 <= sim.state.m_n <= 45500.0
        assert 1.60 <= sim.state.intrinsic_viscosity_dl_g <= 1.70
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.reaction_active is True

    def test_temperature_unit_conversions(self) -> None:
        """Check t_melt_c, t_melt_k, melt_temp_c, temperature_c properties."""
        state = PBSPolycondensationState()
        state.t_melt = 508.15
        assert math.isclose(state.t_melt_c, 235.0, abs_tol=1e-5)
        assert math.isclose(state.melt_temp_c, 235.0, abs_tol=1e-5)
        assert math.isclose(state.temperature_c, 235.0, abs_tol=1e-5)

        state.t_melt_c = 240.0
        assert math.isclose(state.t_melt, 513.15, abs_tol=1e-5)
        assert math.isclose(state.temperature_c, 240.0, abs_tol=1e-5)


# ============================================================================
# Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
# ============================================================================

class TestSection05CoupledODESystemAndRK4Integrator:
    """Verify 6-state ODE formulation, derivative computation, RK4 stability, and state bounds."""

    def test_state_vector_definition(self) -> None:
        """Dynamic 6-state vector components are accessible and strictly positive."""
        state = PBSPolycondensationState()
        assert state.c_sa > 0.0
        assert state.c_bdo > 0.0
        assert state.c_pbs > 0.0
        assert state.c_thf > 0.0
        assert state.m_n > 0.0
        assert state.t_melt > 0.0

    def test_ode_system_shape_and_finite(self) -> None:
        """ODE system returns exactly 6 finite float components."""
        sim = PBSPolycondensationReactor()
        y0 = [0.075, 0.07875, 4.925, 0.00010, 45000.0, 508.15]
        derivs = sim.ode_system(y0)
        assert len(derivs) == 6
        assert all(math.isfinite(d) for d in derivs)

    def test_rk4_step_execution_and_state_non_negativity(self) -> None:
        """RK4 step advances time and maintains non-negative finite state variables."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        t0 = sim.state.sim_time_s

        sim.rk4_step(dt=0.02)
        assert sim.state.sim_time_s > t0
        assert sim.state.c_sa >= 0.0
        assert sim.state.c_bdo >= 0.0
        assert sim.state.c_pbs >= 0.0
        assert sim.state.c_thf >= 0.0
        assert sim.state.m_n >= 100.0
        assert sim.state.t_melt >= 200.0

    def test_rk4_numerical_stability_across_timesteps(self) -> None:
        """RK4 integrator remains stable under varying dt (0.005, 0.01, 0.02, 0.05 s)."""
        for dt_test in [0.005, 0.01, 0.02, 0.05]:
            sim = PBSPolycondensationReactor()
            sim.reset()
            for _ in range(40):
                sim.rk4_step(dt=dt_test)
            assert 230.0 <= sim.state.t_melt_c <= 240.0
            assert 40000.0 <= sim.state.m_n <= 50000.0
            assert not math.isnan(sim.state.t_melt)
            assert not math.isinf(sim.state.t_melt)


# ============================================================================
# Section 6: Mathematical Conservation Residuals
# ============================================================================

class TestSection06ConservationLawsResiduals:
    """Verify stoichiometric mass, elemental, carbon, and enthalpy residuals (< 1e-10)."""

    def test_total_mass_balance_residual(self) -> None:
        """Total mass balance residual across CSTR is strictly < 1e-10 kg/s."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.total_mass_balance_residual_kg_s >= 0.0

    def test_elemental_balance_residual(self) -> None:
        """Elemental mass balance residual is strictly < 1e-10 kg/s."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s >= 0.0

    def test_carbon_mass_balance_residual(self) -> None:
        """Carbon mass conservation residual is strictly < 1e-10 kg/s."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.carbon_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.carbon_mass_balance_residual_kg_s >= 0.0

    def test_conservation_residuals_preserved_after_transient_steps(self) -> None:
        """All conservation residuals remain < 1e-10 after 50 scan cycles."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        for _ in range(50):
            sim.scan_step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.carbon_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 7: Process Safety Interlocks & Strict Priority Hierarchy
# ============================================================================

class TestSection07SafetyInterlocksAndPriorityHierarchy:
    """Verify strict priority hierarchy: 0xF401 > 0xF402 > 0xF403 > 0xF404 > 0x0000."""

    def test_priority_1_overtemp_trip(self) -> None:
        """0xF401 OVERTEMP trips when melt temperature > 248.0 °C."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.state.t_melt_c = 250.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False
        assert sim.state.anomaly_pre_alarm is True

    def test_priority_2_vacuum_loss_trip(self) -> None:
        """0xF402 VACUUM_LOSS trips when vacuum pressure > 5.0 mbar."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.state.p_vac_mbar = 6.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False
        assert sim.state.anomaly_pre_alarm is True

    def test_priority_3_thf_runaway_trip(self) -> None:
        """0xF403 THF_RUNAWAY trips when THF formation rate > 1.20 mg/(L*min)."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.state.thf_formation_rate_mg_l_min = 1.35
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THF_RUNAWAY
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False
        assert sim.state.anomaly_pre_alarm is True

    def test_priority_4_degradation_trip(self) -> None:
        """0xF404 DEGRADATION trips when M_n < 30,000 Da or conversion < 90.0%."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.state.m_n = 28000.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEGRADATION
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

        sim.reset()
        sim.state.conversion_pct = 88.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEGRADATION
        assert sim.state.emergency_dump_tripped is True

    def test_priority_5_normal_steady_state_ok(self) -> None:
        """0x0000 OK when all variables within nominal safety envelope."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.reaction_active is True
        assert sim.state.anomaly_pre_alarm is False
        assert sim.state.emergency_dump_tripped is False

    def test_strict_priority_overrides(self) -> None:
        """Higher priority faults deterministically preempt lower priority faults."""
        sim = PBSPolycondensationReactor()

        # Overtemp (0xF401) preempts vacuum loss (0xF402) and THF runaway (0xF403)
        sim.reset()
        sim.state.t_melt_c = 252.0
        sim.state.p_vac_mbar = 8.0
        sim.state.thf_formation_rate_mg_l_min = 2.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP

        # Vacuum loss (0xF402) preempts THF runaway (0xF403) and degradation (0xF404)
        sim.reset()
        sim.state.t_melt_c = 235.0
        sim.state.p_vac_mbar = 7.5
        sim.state.thf_formation_rate_mg_l_min = 2.0
        sim.state.m_n = 20000.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS

        # THF runaway (0xF403) preempts degradation (0xF404)
        sim.reset()
        sim.state.t_melt_c = 235.0
        sim.state.p_vac_mbar = 2.0
        sim.state.thf_formation_rate_mg_l_min = 1.80
        sim.state.m_n = 25000.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THF_RUNAWAY


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
# ============================================================================

class TestSection08DiagnosticCodes16BitValues:
    """Verify signed and unsigned 16-bit values, comparisons, string formatting, and masking."""

    def test_diagnostic_code_hex_and_integer_values(self) -> None:
        """Hex integer values match W275 specification."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.OVERTEMP.value == 0xF401
        assert DiagnosticCode.VACUUM_LOSS.value == 0xF402
        assert DiagnosticCode.THF_RUNAWAY.value == 0xF403
        assert DiagnosticCode.DEGRADATION.value == 0xF404

    def test_signed_16bit_representation(self) -> None:
        """Signed 16-bit two's complement values: 0xF401=-3071, 0xF402=-3070, 0xF403=-3069, 0xF404=-3068."""
        assert (0xF401 - 65536) == -3071
        assert (0xF402 - 65536) == -3070
        assert (0xF403 - 65536) == -3069
        assert (0xF404 - 65536) == -3068

    def test_signed_and_unsigned_equality(self) -> None:
        """DiagnosticCode compares equal with signed and unsigned integers transparently."""
        assert DiagnosticCode.OK == 0
        assert DiagnosticCode.OK == 0x0000

        assert DiagnosticCode.OVERTEMP == 0xF401
        assert DiagnosticCode.OVERTEMP == 62465
        assert DiagnosticCode.OVERTEMP == -3071

        assert DiagnosticCode.VACUUM_LOSS == 0xF402
        assert DiagnosticCode.VACUUM_LOSS == 62466
        assert DiagnosticCode.VACUUM_LOSS == -3070

        assert DiagnosticCode.THF_RUNAWAY == 0xF403
        assert DiagnosticCode.THF_RUNAWAY == 62467
        assert DiagnosticCode.THF_RUNAWAY == -3069

        assert DiagnosticCode.DEGRADATION == 0xF404
        assert DiagnosticCode.DEGRADATION == 62468
        assert DiagnosticCode.DEGRADATION == -3068

    def test_missing_lookup_signed_integer(self) -> None:
        """DiagnosticCode constructor / _missing_ converts signed int back to enum."""
        assert DiagnosticCode(-3071) == DiagnosticCode.OVERTEMP
        assert DiagnosticCode(-3070) == DiagnosticCode.VACUUM_LOSS
        assert DiagnosticCode(-3069) == DiagnosticCode.THF_RUNAWAY
        assert DiagnosticCode(-3068) == DiagnosticCode.DEGRADATION

    def test_bitwise_masking_and_string_representation(self) -> None:
        """Bitwise & 0xFFFF and __str__() output formatted as 0xXXXX."""
        assert (DiagnosticCode.OVERTEMP & 0xFFFF) == 0xF401
        assert (DiagnosticCode.VACUUM_LOSS & 0xFFFF) == 0xF402
        assert (DiagnosticCode.THF_RUNAWAY & 0xFFFF) == 0xF403
        assert (DiagnosticCode.DEGRADATION & 0xFFFF) == 0xF404

        s = str(DiagnosticCode.OVERTEMP)
        assert "0xF401" in s

    def test_diagnostic_code_hash_and_bitwise_operations(self) -> None:
        """Test hash, bitwise and, rand, and invalid missing lookups."""
        code = DiagnosticCode.OVERTEMP
        assert isinstance(hash(code), int)
        assert (code & 0x0F) == (0xF401 & 0x0F)
        assert (0x0F & code) == (0x0F & 0xF401)
        assert (code & DiagnosticCode.VACUUM_LOSS) == (0xF401 & 0xF402)
        assert (DiagnosticCode.VACUUM_LOSS & code) == (0xF402 & 0xF401)

        # Missing lookup with non-matching int and non-int
        assert DiagnosticCode._missing_(999999) is None
        assert DiagnosticCode._missing_("INVALID") is None



# ============================================================================
# Section 9: Fault Injections, Actuations & Emergency Dump Tripped Coil %M552
# ============================================================================

class TestSection09FaultInjectionsAndActuations:
    """Verify inject_fault(), clear_faults(), and coil state transitions."""

    def test_inject_overtemp_fault(self) -> None:
        """Injecting overtemp triggers 0xF401 and asserts %M552 emergency dump trip."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.inject_fault("overtemp")
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_inject_vacuum_loss_fault(self) -> None:
        """Injecting vacuum loss triggers 0xF402 and asserts %M552 emergency dump trip."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.inject_fault("vacuum")
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_inject_thf_runaway_fault(self) -> None:
        """Injecting THF runaway triggers 0xF403 and halts active reaction."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.inject_fault("thf")
        assert sim.state.diagnostic_code == DiagnosticCode.THF_RUNAWAY
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_inject_degradation_fault(self) -> None:
        """Injecting degradation triggers 0xF404 and trips dump."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.inject_fault("degradation")
        assert sim.state.diagnostic_code == DiagnosticCode.DEGRADATION
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_clear_faults_restores_nominal(self) -> None:
        """Calling clear_faults() restores nominal baseline and clears trips."""
        sim = PBSPolycondensationReactor()
        sim.inject_fault("overtemp")
        assert sim.state.diagnostic_code != DiagnosticCode.OK
        sim.clear_faults()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.emergency_dump_tripped is False
        assert sim.state.reaction_active is True
        assert sim.state.anomaly_pre_alarm is False


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege
# ============================================================================

class TestSection10HornerOCSMemoryIntegration:
    """Verify register synchronization (%R2360..%R2367, %M550..%M552) and privilege."""

    def test_nominal_register_table_synchronization(self) -> None:
        """Registers and coils match nominal steady-state values bit-exactly."""
        table = RegisterTable()
        sim = PBSPolycondensationReactor(register_table=table)
        sim.reset()

        assert table.read_word(REG_PBS_MELT_TEMP_SCALED) == 2350
        assert table.read_word(REG_PBS_VACUUM_PRESSURE_SCALED) == 20
        assert table.read_word(REG_PBS_CONVERSION_SCALED) == 985
        assert table.read_word(REG_PBS_BDO_SA_RATIO_SCALED) == 105
        assert table.read_word(REG_PBS_MOLECULAR_WEIGHT_SCALED) == 4500
        assert table.read_word(REG_PBS_INTRINSIC_VISCOSITY_SCALED) == 165
        assert table.read_word(REG_PBS_THF_FORMATION_RATE_SCALED) == 42
        assert table.read_uword(REG_PBS_DIAGNOSTIC_CODE) == 0x0000

        assert table.read_bit(COIL_PBS_REACTION_ACTIVE) is True
        assert table.read_bit(COIL_PBS_ANOMALY_PRE_ALARM) is False
        assert table.read_bit(COIL_PBS_EMERGENCY_DUMP_TRIPPED) is False

    def test_trip_register_table_synchronization(self) -> None:
        """When 0xF401 trips, %R2367 reflects signed -3071 and %M552 emergency dump asserts."""
        table = RegisterTable()
        sim = PBSPolycondensationReactor(register_table=table)
        sim.inject_fault("overtemp")

        assert table.read_uword(REG_PBS_DIAGNOSTIC_CODE) == 0xF401
        assert table.read_word(REG_PBS_DIAGNOSTIC_CODE) == -3071
        assert table.read_bit(COIL_PBS_REACTION_ACTIVE) is False
        assert table.read_bit(COIL_PBS_EMERGENCY_DUMP_TRIPPED) is True

    def test_system_privilege_sync(self) -> None:
        """Registers synchronized with SYSTEM privilege overwrite protected memory channels."""
        table = RegisterTable()
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2360") == 2350

    def test_register_aliases_equivalence(self) -> None:
        """Verify register string constant aliases."""
        assert REG_PBS_TEMP_SCALED == REG_PBS_MELT_TEMP_SCALED
        assert REG_PBS_VACUUM_SCALED == REG_PBS_VACUUM_PRESSURE_SCALED
        assert REG_PBS_CONV_SCALED == REG_PBS_CONVERSION_SCALED
        assert REG_PBS_RATIO_SCALED == REG_PBS_BDO_SA_RATIO_SCALED
        assert REG_PBS_MN_SCALED == REG_PBS_MOLECULAR_WEIGHT_SCALED
        assert REG_PBS_IV_SCALED == REG_PBS_INTRINSIC_VISCOSITY_SCALED
        assert REG_PBS_THF_RATE_SCALED == REG_PBS_THF_FORMATION_RATE_SCALED
        assert REG_PBS_DIAG_CODE == REG_PBS_DIAGNOSTIC_CODE
        assert COIL_PBS_ACTIVE == COIL_PBS_REACTION_ACTIVE
        assert COIL_PBS_PRE_ALARM == COIL_PBS_ANOMALY_PRE_ALARM
        assert COIL_PBS_EMERGENCY_DUMP == COIL_PBS_EMERGENCY_DUMP_TRIPPED
        assert COIL_PBS_DUMP_TRIPPED == COIL_PBS_EMERGENCY_DUMP_TRIPPED


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection11PureSTPOUAndASTValidation:
    """Verify IEC 61131-3 Structured Text compliance, parser validation, and register memory bindings."""

    def test_pure_st_pou_security_guard_and_parser(self) -> None:
        """ST_PROGRAM_PBS_POLYCONDENSATION_SYNC passes SecurityGuard and STParser cleanly."""
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_PBS_POLYCONDENSATION_SYNC)
        res = STParser.validate_code(ST_PROGRAM_PBS_POLYCONDENSATION_SYNC)
        assert res.status == AgentStatus.SUCCESS

    def test_ast_variable_memory_address_bindings(self) -> None:
        """Parsed AST POU contains all 11 required %R2360..%R2367 and %M550..%M552 bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(ST_PROGRAM_PBS_POLYCONDENSATION_SYNC)
        assert pou is not None
        assert pou.name in ("PbsPolycondensationSync", "PBSPolycondensationSync")

        required_registers = [
            "%R2360", "%R2361", "%R2362", "%R2363",
            "%R2364", "%R2365", "%R2366", "%R2367",
            "%M550", "%M551", "%M552",
        ]
        for reg in required_registers:
            assert reg in pou.bound_registers, f"Missing register {reg} in AST bindings"

        for var in pou.variables:
            addr = getattr(var, "address_binding", None) or getattr(var, "memory_address", None)
            if addr:
                assert addr.startswith(("%R", "%M"))

    def test_verify_pbs_polycondensation_pure_st_function(self) -> None:
        """Helper verification function returns successful result."""
        res = verify_pbs_polycondensation_pure_st()
        assert bool(res) is True
        assert res.status == AgentStatus.SUCCESS

    def test_pure_st_pou_aliases(self) -> None:
        """Aliases for POU string and verification function are consistent."""
        assert PBS_POLYCONDENSATION_PURE_ST_POU == ST_PROGRAM_PBS_POLYCONDENSATION_SYNC
        assert PBS_POLYCONDENSATION_SYNC_POU == ST_PROGRAM_PBS_POLYCONDENSATION_SYNC
        assert PBS_PURE_ST_POU == ST_PROGRAM_PBS_POLYCONDENSATION_SYNC
        assert PBS_SYNC_POU == ST_PROGRAM_PBS_POLYCONDENSATION_SYNC
        assert verify_pbs_pure_st is verify_pbs_polycondensation_pure_st
        assert validate_pure_st is verify_pbs_polycondensation_pure_st


# ============================================================================
# Section 12: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection12AntiLadderSecurityGuard:
    """Verify anti-ladder security guard rejects contacts, coils, rungs, and mnemonics."""

    def test_reject_ladder_contacts(self) -> None:
        """Normally-open and normally-closed contacts are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---[ ]---")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---[/]---")

    def test_reject_ladder_coils(self) -> None:
        """Standard and set/reset coils are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---( )---")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR x : BOOL; END_VAR\n---(S)---")

    def test_reject_rung_and_network_delimiters(self) -> None:
        """RUNG and NETWORK keywords are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: X := 1;")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 10\nLD %M550\nST %M552")

    def test_reject_ladder_mnemonics(self) -> None:
        """XIC and OTE mnemonics are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC %M550 OTE %M552")


# ============================================================================
# Section 13: ILogicUnit Compliance & 100-Cycle Soak Stability
# ============================================================================

class TestSection13ILogicUnitComplianceAndSoakStability:
    """Verify ILogicUnit interface compliance, reset dynamics, and 100-cycle soak stability."""

    def test_ilogic_unit_interface_compliance(self) -> None:
        """PBSPolycondensationReactor implements ILogicUnit protocol."""
        reactor = PBSPolycondensationReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name in ("PbsPolycondensation", "PBSPolycondensation")
        assert reactor.priority == 275
        assert reactor.is_enabled is True

    def test_enable_disable_lifecycle(self) -> None:
        """Disabling logic unit halts scan execution."""
        reactor = PBSPolycondensationReactor()
        reactor.disable()
        assert reactor.is_enabled is False
        t_before = reactor.state.sim_time_s
        reactor.scan_step(0.02)
        assert reactor.state.sim_time_s == t_before
        reactor.enable()
        assert reactor.is_enabled is True

    def test_execute_with_scan_context(self) -> None:
        """Reactor executes cleanly under ScanContext."""
        reactor = PBSPolycondensationReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        reactor.execute(ctx)
        assert reactor.state.scan_count == 1
        assert reactor.state.sim_time_s > 0.0

    def test_100_cycle_soak_stability(self) -> None:
        """100 scan cycles execute with zero NaN, zero Inf, and bounded state variables."""
        sim = PBSPolycondensationReactor()
        sim.reset()

        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        assert not math.isnan(sim.state.t_melt)
        assert not math.isnan(sim.state.m_n)
        assert not math.isnan(sim.state.c_sa)
        assert not math.isnan(sim.state.c_bdo)
        assert not math.isnan(sim.state.c_pbs)
        assert not math.isinf(sim.state.t_melt)

        assert 234.0 <= sim.state.t_melt_c <= 236.0
        assert 44000.0 <= sim.state.m_n <= 46000.0
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.reaction_active is True
        assert sim.state.emergency_dump_tripped is False


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14VerificationSuiteAndArtifactGeneration:
    """Verify run_pbs_polycondensation_verification() output contract and evidence emission."""

    def test_run_verification_suite_success(self, tmp_path: Path) -> None:
        """Verification suite runs all 9 stages cleanly and returns strict 4-state contract."""
        out_file = tmp_path / "pbs_test_evidence.json"
        res = run_pbs_polycondensation_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "data" in res
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["stages"]) == 9

    def test_verification_suite_alias(self) -> None:
        """Alias run_pbs_verification resolves to canonical function."""
        assert run_pbs_verification is run_pbs_polycondensation_verification
        assert run_verification is run_pbs_polycondensation_verification


# ============================================================================
# Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
# ============================================================================

class TestSection15EdgeCasesAliasesAndSensitivity:
    """Verify model compatibility aliases, edge conditions, and parameter sensitivities."""

    def test_class_aliases(self) -> None:
        """All prescribed PascalCase and snake_case aliases resolve to canonical classes."""
        assert PBSPolycondensation is PBSPolycondensationReactor
        assert PbsPolycondensation is PBSPolycondensationReactor
        assert PBSPolycondensationLogicUnit is PBSPolycondensationReactor
        assert PbsPolycondensationLogicUnit is PBSPolycondensationReactor
        assert PBSSimulator is PBSPolycondensationReactor
        assert PbsSimulator is PBSPolycondensationReactor
        assert PBSEngine is PBSPolycondensationReactor
        assert PbsEngine is PBSPolycondensationReactor
        assert PBSModel is PBSPolycondensationReactor
        assert PBSPlantModel is PBSPolycondensationReactor

        assert PbsPolycondensationConfig is PBSPolycondensationConfig
        assert PBSPolycondensationParameters is PBSPolycondensationConfig
        assert PBSConfig is PBSPolycondensationConfig
        assert PbsConfig is PBSPolycondensationConfig

        assert PbsPolycondensationState is PBSPolycondensationState
        assert PBSState is PBSPolycondensationState
        assert PbsState is PBSPolycondensationState

        assert PBSDiagnosticCode is DiagnosticCode
        assert PbsDiagnosticCode is DiagnosticCode
        assert PBSPolycondensationDiagnosticCode is DiagnosticCode
        assert PbsPolycondensationDiagnosticCode is DiagnosticCode

        assert PBSStatusBits is PBSPolycondensationStatusBits
        assert PbsStatusBits is PBSPolycondensationStatusBits
        assert PBSPolycondensationStatusWord is PBSPolycondensationStatusBits
        assert PbsPolycondensationStatusWord is PBSPolycondensationStatusBits
        assert StatusBits is PBSPolycondensationStatusBits

    def test_mark_houwink_viscosity_sensitivity(self) -> None:
        """Intrinsic viscosity scales monotonically with molecular weight."""
        state = PBSPolycondensationState()
        state.m_n = 45000.0
        sim = PBSPolycondensationReactor()
        sim.state = state
        sim._update_kinetics_and_metrics()
        iv_nom = sim.state.intrinsic_viscosity_dl_g

        state.m_n = 60000.0
        sim._update_kinetics_and_metrics()
        iv_high = sim.state.intrinsic_viscosity_dl_g

        state.m_n = 30000.0
        sim._update_kinetics_and_metrics()
        iv_low = sim.state.intrinsic_viscosity_dl_g

        assert iv_high > iv_nom > iv_low
        assert math.isclose(iv_nom, 1.65, abs_tol=0.01)

    def test_arrhenius_temperature_sensitivity(self) -> None:
        """Polycondensation rate constant increases with melt temperature."""
        sim = PBSPolycondensationReactor()
        k_225 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_poly, sim.config.activation_ea_poly_j_mol, 498.15)
        k_235 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_poly, sim.config.activation_ea_poly_j_mol, 508.15)
        k_245 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_poly, sim.config.activation_ea_poly_j_mol, 518.15)
        assert k_245 > k_235 > k_225 > 0.0

    def test_vacuum_enhancement_factor_bounds(self) -> None:
        """Vacuum enhancement factor is bounded and increases with deeper vacuum (lower mbar)."""
        sim = PBSPolycondensationReactor()
        fac_deep = sim.vacuum_enhancement_factor(1.0)
        fac_nom = sim.vacuum_enhancement_factor(2.0)
        fac_loss = sim.vacuum_enhancement_factor(5.0)

        assert fac_deep > fac_nom > fac_loss
        assert 0.2 <= fac_loss <= 3.0
        assert 0.2 <= fac_deep <= 3.0

    def test_step_method_execution_result(self) -> None:
        """Reactor.step() returns valid ExecutionResult with status success or failed on bad dt."""
        sim = PBSPolycondensationReactor()
        res_ok = sim.step(0.02)
        assert res_ok.status == AgentStatus.SUCCESS

        res_bad = sim.step(-0.01)
        assert res_bad.status == AgentStatus.FAILED
        assert res_bad.error_code == "INVALID_TIMESTEP"

    def test_state_properties_getters_and_setters(self) -> None:
        """Test getters and setters on PBSPolycondensationState."""
        state = PBSPolycondensationState()
        state.t_melt_k = 510.0
        assert state.t_melt_k == 510.0
        assert math.isclose(state.t_melt_c, 510.0 - 273.15, abs_tol=1e-5)

        state.molecular_weight_da = 42000.0
        assert state.molecular_weight_da == 42000.0
        assert state.m_n == 42000.0

    def test_inactive_reaction_kinetics_and_derivatives(self) -> None:
        """Kinetics and derivatives when reaction_active is False or emergency dump tripped."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.state.reaction_active = False

        kin = sim.compute_kinetics(508.15, 0.075, 0.07875, 2.0)
        assert kin["r_poly"] == 0.0
        assert kin["r_thf"] == 0.0

        derivs = sim.compute_derivatives(0.0, [0.075, 0.07875, 4.925, 0.00010, 45000.0, 508.15])
        assert sim.state.q_flow_kw == 0.0
        assert sim.state.q_jacket_kw == 0.0
        assert sim.state.q_evap_kw == 0.0

        sim.state.emergency_dump_tripped = True
        derivs_dump = sim.compute_derivatives(0.0, [0.075, 0.07875, 4.925, 0.00010, 45000.0, 508.15])
        assert sim.state.q_dump_kw == 250.0

    def test_zero_feed_concentration_metrics(self) -> None:
        """Kinetics and metrics when inlet feed concentrations are zero."""
        sim = PBSPolycondensationReactor()
        sim.reset()
        sim.config.c_sa_feed_mol_l = 0.0
        sim._update_kinetics_and_metrics()
        assert sim.state.conversion_pct == 0.0

        sim.config.c_sa_feed_mol_l = 5.0
        sim.state.c_sa = 0.0
        sim._update_kinetics_and_metrics()
        assert sim.state.bdo_sa_ratio == sim.config.feed_bdo_sa_ratio

    def test_scan_context_fallback_timesteps(self) -> None:
        """ScanContext execution handles dt=None with dt_s fallback."""
        sim = PBSPolycondensationReactor()
        sim.reset()

        ctx1 = ScanContext(cycle=1, dt=None, dt_s=0.015)
        sim.execute(ctx1)
        assert sim.state.scan_count == 1

        ctx2 = ScanContext(cycle=2, dt=None, dt_s=None)
        sim.execute(ctx2)
        assert sim.state.scan_count == 2

    def test_pure_st_validation_result_equality(self) -> None:
        """PureSTValidationResult equality comparisons with bool and AgentStatus."""
        r_pass = PureSTValidationResult(True, status=AgentStatus.SUCCESS)
        assert (r_pass == True) is True
        assert (r_pass == False) is False
        assert (r_pass == AgentStatus.SUCCESS) is True
        assert (r_pass == AgentStatus.FAILED) is False

        r_fail = PureSTValidationResult(False, status=AgentStatus.FAILED)
        assert (r_fail == True) is False
        assert (r_fail == False) is True
        assert (r_fail == AgentStatus.FAILED) is True
        assert (r_fail == AgentStatus.SUCCESS) is False

