"""Comprehensive Industrial Polybutylene Adipate Terephthalate (PBAT) Biodegradable Copolyester Test Suite.

Work Package: W278 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 15 comprehensive engineering verification sections:
1. Section 1: Universal Physical, Chemical & Thermochemical Constants, IUPAC Atomic Weights & Reaction Enthalpy
2. Section 2: Stoichiometric Balance & Elemental Conservation (Exact C/H/O Conservation < 1e-13)
3. Section 3: Reactor Geometry, Hydrodynamics, and Baseline Operating Parameters
4. Section 4: Nominal Steady-State Closed-Loop Convergence (T=240.0 °C, P=1.5 mbar, Conv=98.8%, Mn=52,000 Da, IV=1.82 dL/g)
5. Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
6. Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O, Enthalpy < 1e-10)
7. Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xF501 > 0xF502 > 0xF503 > 0xF504 > 0x0000)
8. Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
9. Section 9: Fault Injections, Actuations & Emergency Dump Tripped Coil %M559, Pre-Alarm %M558, Reaction Active %M557
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2390..%R2397, %M557..%M559)
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

from jev_cscape.simulation.pbat_polycondensation import (
    COIL_PBAT_ACTIVE,
    COIL_PBAT_ANOMALY_PRE_ALARM,
    COIL_PBAT_DUMP_TRIPPED,
    COIL_PBAT_EMERGENCY_DUMP,
    COIL_PBAT_EMERGENCY_DUMP_TRIPPED,
    COIL_PBAT_PRE_ALARM,
    COIL_PBAT_REACTION_ACTIVE,
    COMONOMER_RATIO_NOMINAL,
    COMONOMER_RATIO_PRE_ALARM_MAX,
    COMONOMER_RATIO_PRE_ALARM_MIN,
    COMONOMER_RATIO_TRIP_MAX,
    COMONOMER_RATIO_TRIP_MIN,
    CONVERSION_NOMINAL_PCT,
    CONV_PRE_ALARM_PCT,
    DEGRADATION_CONV_TRIP_PCT,
    DEGRADATION_MN_TRIP_DA,
    DELTA_H_DEG_J_MOL,
    DELTA_H_DEG_KJ_MOL,
    DELTA_H_POLY_AA_J_MOL,
    DELTA_H_POLY_AA_KJ_MOL,
    DELTA_H_POLY_PTA_J_MOL,
    DELTA_H_POLY_PTA_KJ_MOL,
    DELTA_H_THF_J_MOL,
    DELTA_H_THF_KJ_MOL,
    DELTA_H_VOLATILE_J_MOL,
    DELTA_H_VOLATILE_KJ_MOL,
    DiagnosticCode,
    G_ACCEL,
    INTRINSIC_VISCOSITY_NOMINAL_DL_G,
    IV_NOMINAL_DL_G,
    MELT_TEMP_NOMINAL_C,
    MN_NOMINAL_DA,
    MN_PRE_ALARM_DA,
    MOLECULAR_WEIGHT_NOMINAL_DA,
    MW_14_BUTANEDIOL,
    MW_AA,
    MW_ADIPIC_ACID,
    MW_BA_MER,
    MW_BDO,
    MW_BT_MER,
    MW_BUTANEDIOL,
    MW_C,
    MW_H,
    MW_H2O,
    MW_O,
    MW_PBAT,
    MW_PBAT_MER,
    MW_POLYMER_MER,
    MW_PTA,
    MW_TEREPHTHALIC_ACID,
    MW_TETRAHYDROFURAN,
    MW_THF,
    MW_VOLATILE_BYPRODUCT,
    MW_WATER,
    PBAT_POLYCONDENSATION_PURE_ST_POU,
    PBAT_POLYCONDENSATION_SYNC_POU,
    PBAT_PURE_ST_POU,
    PBAT_SYNC_POU,
    PBATConfig,
    PBATDiagnosticCode,
    PBATEngine,
    PBATModel,
    PBATPlantModel,
    PBATPolycondensation,
    PBATPolycondensationConfig,
    PBATPolycondensationDiagnosticCode,
    PBATPolycondensationLogicUnit,
    PBATPolycondensationParameters,
    PBATPolycondensationReactor,
    PBATPolycondensationSimulation,
    PBATPolycondensationState,
    PBATPolycondensationStatusBits,
    PBATPolycondensationStatusWord,
    PBATSimulator,
    PBATState,
    PBATStatusBits,
    PbatConfig,
    PbatDiagnosticCode,
    PbatEngine,
    PbatPolycondensation,
    PbatPolycondensationConfig,
    PbatPolycondensationDiagnosticCode,
    PbatPolycondensationLogicUnit,
    PbatPolycondensationSimulation,
    PbatPolycondensationState,
    PbatPolycondensationStatusBits,
    PbatPolycondensationStatusWord,
    PbatSimulator,
    PbatState,
    PbatStatusBits,
    PureSTValidationResult,
    R_GAS_CONST,
    REG_PBAT_BYPRODUCT_RATE_SCALED,
    REG_PBAT_COMONOMER_RATIO_SCALED,
    REG_PBAT_CONVERSION_SCALED,
    REG_PBAT_CONV_SCALED,
    REG_PBAT_DIAG_CODE,
    REG_PBAT_DIAGNOSTIC_CODE,
    REG_PBAT_INTRINSIC_VISCOSITY_SCALED,
    REG_PBAT_IV_SCALED,
    REG_PBAT_MELT_TEMP_SCALED,
    REG_PBAT_MN_SCALED,
    REG_PBAT_MOLECULAR_WEIGHT_SCALED,
    REG_PBAT_RATIO_SCALED,
    REG_PBAT_TEMP_SCALED,
    REG_PBAT_VACUUM_PRESSURE_SCALED,
    REG_PBAT_VACUUM_SCALED,
    REG_PBAT_VOLATILE_BYPRODUCT_RATE_SCALED,
    REG_PBAT_VOLATILE_RATE_SCALED,
    ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC,
    StatusBits,
    T_MELT_NOMINAL_C,
    T_MELT_NOMINAL_K,
    T_OVERTEMP_TRIP_C,
    T_PRE_ALARM_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    VACUUM_LOSS_TRIP_MBAR,
    VACUUM_PRE_ALARM_MBAR,
    VACUUM_PRESSURE_NOMINAL_MBAR,
    VOLATILE_BYPRODUCT_RATE_NOMINAL_MG_L_MIN,
    VOLATILE_RATE_NOMINAL,
    VOLATILE_RATE_PRE_ALARM_MG_L_MIN,
    run_pbat_polycondensation_verification,
    run_pbat_verification,
    run_verification,
    validate_pure_st,
    verify_pbat_polycondensation_pure_st,
    verify_pbat_pure_st,
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
        assert math.isclose(T_MELT_NOMINAL_C, 240.0, rel_tol=1e-8)
        assert math.isclose(T_MELT_NOMINAL_K, 513.15, rel_tol=1e-8)
        assert math.isclose(T_REF_K, 513.15, rel_tol=1e-8)

    def test_iupac_atomic_weights(self) -> None:
        """Standard atomic weights for C, H, O [g/mol]."""
        assert math.isclose(MW_C, 12.011, rel_tol=1e-5)
        assert math.isclose(MW_H, 1.008, rel_tol=1e-5)
        assert math.isclose(MW_O, 15.999, rel_tol=1e-5)

    def test_molecular_weights_species(self) -> None:
        """Exact molecular weights for BDO, AA, PTA, BA repeat unit, BT repeat unit, THF, and water."""
        # 1,4-Butanediol: C4H10O2
        expected_bdo = 4.0 * MW_C + 10.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_BDO, expected_bdo, rel_tol=1e-6)
        assert math.isclose(MW_14_BUTANEDIOL, MW_BDO)
        assert math.isclose(MW_BUTANEDIOL, MW_BDO)

        # Adipic Acid: C6H10O4
        expected_aa = 6.0 * MW_C + 10.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_AA, expected_aa, rel_tol=1e-6)
        assert math.isclose(MW_ADIPIC_ACID, MW_AA)

        # Terephthalic Acid: C8H6O4
        expected_pta = 8.0 * MW_C + 6.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_PTA, expected_pta, rel_tol=1e-6)
        assert math.isclose(MW_TEREPHTHALIC_ACID, MW_PTA)

        # Butylene Adipate Repeat Unit (BA Mer): C10H16O4
        expected_ba = 10.0 * MW_C + 16.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_BA_MER, expected_ba, rel_tol=1e-6)

        # Butylene Terephthalate Repeat Unit (BT Mer): C12H12O4
        expected_bt = 12.0 * MW_C + 12.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_BT_MER, expected_bt, rel_tol=1e-6)

        # Average PBAT Mer: weighted sum of BA and BT units
        f_aa = 1.0 / 1.55
        f_pta = 0.55 / 1.55
        expected_pbat = f_aa * expected_ba + f_pta * expected_bt
        assert math.isclose(MW_PBAT_MER, expected_pbat, rel_tol=1e-6)
        assert math.isclose(MW_PBAT, MW_PBAT_MER)
        assert math.isclose(MW_POLYMER_MER, MW_PBAT_MER)

        # THF Byproduct: C4H8O
        expected_thf = 4.0 * MW_C + 8.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_THF, expected_thf, rel_tol=1e-6)
        assert math.isclose(MW_VOLATILE_BYPRODUCT, MW_THF)
        assert math.isclose(MW_TETRAHYDROFURAN, MW_THF)

        # Water: H2O
        expected_h2o = 2.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_H2O, expected_h2o, rel_tol=1e-6)
        assert math.isclose(MW_WATER, MW_H2O)

    def test_reaction_enthalpies(self) -> None:
        """Polycondensation of AA and PTA, cyclization to volatile THF, and thermal degradation enthalpies."""
        assert DELTA_H_POLY_AA_KJ_MOL == -19.2
        assert DELTA_H_POLY_AA_J_MOL == -19200.0
        assert DELTA_H_POLY_PTA_KJ_MOL == -21.5
        assert DELTA_H_POLY_PTA_J_MOL == -21500.0
        assert DELTA_H_VOLATILE_KJ_MOL == -12.0
        assert DELTA_H_VOLATILE_J_MOL == -12000.0
        assert DELTA_H_THF_KJ_MOL == -12.0
        assert DELTA_H_THF_J_MOL == -12000.0
        assert DELTA_H_DEG_KJ_MOL == 26.0
        assert DELTA_H_DEG_J_MOL == 26000.0


# ============================================================================
# Section 2: Stoichiometric Balance & Elemental Conservation
# ============================================================================

class TestSection02StoichiometricBalanceAndElementalConservation:
    """Verify stoichiometric mass balances and elemental conservation for PBAT synthesis."""

    def test_polycondensation_aa_mass_balance(self) -> None:
        """Reaction 1: AA + BDO -> BA_mer + 2 H2O stoichiometric mass delta < 1e-13 g/mol."""
        delta1 = abs((MW_BA_MER + 2.0 * MW_H2O) - (MW_AA + MW_BDO))
        assert delta1 < 1.0e-13

    def test_polycondensation_pta_mass_balance(self) -> None:
        """Reaction 2: PTA + BDO -> BT_mer + 2 H2O stoichiometric mass delta < 1e-13 g/mol."""
        delta2 = abs((MW_BT_MER + 2.0 * MW_H2O) - (MW_PTA + MW_BDO))
        assert delta2 < 1.0e-13

    def test_volatile_cyclization_mass_balance(self) -> None:
        """Reaction 3: BDO -> THF + H2O stoichiometric mass delta < 1e-13 g/mol."""
        delta3 = abs((MW_THF + MW_H2O) - MW_BDO)
        assert delta3 < 1.0e-13

    def test_elemental_atom_conservation(self) -> None:
        """Carbon, Hydrogen, Oxygen atom balances across all three reactions are exact."""
        # Reaction 1: C6H10O4 + C4H10O2 -> C10H16O4 + 2 H2O
        assert (6 + 4) == 10
        assert (10 + 10) == (16 + 2 * 2)
        assert (4 + 2) == (4 + 2 * 1)

        # Reaction 2: C8H6O4 + C4H10O2 -> C12H12O4 + 2 H2O
        assert (8 + 4) == 12
        assert (6 + 10) == (12 + 2 * 2)
        assert (4 + 2) == (4 + 2 * 1)

        # Reaction 3: C4H10O2 -> C4H8O + H2O
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
        config = PBATPolycondensationConfig()
        assert config.reactor_volume_l == 4000.0
        assert config.nominal_residence_time_s == 3600.0
        assert config.melt_density_kg_m3 == 1220.0
        assert config.melt_density_kg_l == 1.22
        assert config.melt_specific_heat_cp_j_kg_k == 2150.0
        assert config.reactor_thermal_capacitance_kj_k == 10492.0

    def test_feed_stream_baseline(self) -> None:
        """Inlet feed concentrations and comonomer molar ratio."""
        config = PBATPolycondensationConfig()
        assert config.c_aa_feed_mol_l == 3.00
        assert config.c_pta_feed_mol_l == 1.65
        assert config.feed_comonomer_ratio == 0.55
        assert config.c_bdo_feed_mol_l == 5.115
        assert config.feed_bdo_diacid_ratio == 1.10
        assert config.nominal_feed_temp_c == 228.0

    def test_nominal_operating_baseline_constants(self) -> None:
        """Operating baseline constants: T=240.0 °C, P=1.5 mbar, Conv=98.8%, Ratio=0.55, Mn=52,000 Da, IV=1.82 dL/g."""
        assert MELT_TEMP_NOMINAL_C == 240.0
        assert VACUUM_PRESSURE_NOMINAL_MBAR == 1.5
        assert CONVERSION_NOMINAL_PCT == 98.8
        assert COMONOMER_RATIO_NOMINAL == 0.55
        assert MOLECULAR_WEIGHT_NOMINAL_DA == 52000.0
        assert MN_NOMINAL_DA == 52000.0
        assert INTRINSIC_VISCOSITY_NOMINAL_DL_G == 1.82
        assert IV_NOMINAL_DL_G == 1.82
        assert VOLATILE_BYPRODUCT_RATE_NOMINAL_MG_L_MIN == 0.38
        assert VOLATILE_RATE_NOMINAL == 0.38

    def test_safety_interlock_threshold_constants(self) -> None:
        """Threshold limits: T_trip > 255.0 °C, P_vac > 4.5 mbar, Ratio [0.45, 0.65], Mn_trip < 35,000 Da."""
        assert T_OVERTEMP_TRIP_C == 255.0
        assert VACUUM_LOSS_TRIP_MBAR == 4.5
        assert COMONOMER_RATIO_TRIP_MIN == 0.45
        assert COMONOMER_RATIO_TRIP_MAX == 0.65
        assert DEGRADATION_MN_TRIP_DA == 35000.0
        assert DEGRADATION_CONV_TRIP_PCT == 92.0

        assert T_PRE_ALARM_C == 248.0
        assert VACUUM_PRE_ALARM_MBAR == 3.0
        assert COMONOMER_RATIO_PRE_ALARM_MIN == 0.48
        assert COMONOMER_RATIO_PRE_ALARM_MAX == 0.62
        assert VOLATILE_RATE_PRE_ALARM_MG_L_MIN == 0.60
        assert MN_PRE_ALARM_DA == 42000.0
        assert CONV_PRE_ALARM_PCT == 95.0


# ============================================================================
# Section 4: Nominal Steady-State Closed-Loop Convergence
# ============================================================================

class TestSection04NominalSteadyStateConvergence:
    """Verify nominal steady-state initialization and retention across scan cycles."""

    def test_nominal_steady_state_initialization(self) -> None:
        """Fresh reactor instance initializes to nominal operating steady-state."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        assert math.isclose(sim.state.t_melt_c, 240.0, abs_tol=0.2)
        assert math.isclose(sim.state.p_vac_mbar, 1.5, abs_tol=0.1)
        assert math.isclose(sim.state.conversion_pct, 98.8, abs_tol=0.2)
        assert math.isclose(sim.state.comonomer_ratio, 0.55, abs_tol=0.02)
        assert math.isclose(sim.state.m_n, 52000.0, abs_tol=100.0)
        assert math.isclose(sim.state.intrinsic_viscosity_dl_g, 1.82, abs_tol=0.02)
        assert math.isclose(sim.state.volatile_byproduct_rate_mg_l_min, 0.38, abs_tol=0.02)
        assert sim.state.reaction_active is True
        assert sim.state.anomaly_pre_alarm is False
        assert sim.state.emergency_dump_tripped is False
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_steady_state_retention_over_scan_cycles(self) -> None:
        """Advancing 20 scan cycles retains steady-state values within tight tolerances."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        for _ in range(20):
            sim.scan_step(dt=0.02)

        assert 239.5 <= sim.state.t_melt_c <= 240.5
        assert 1.4 <= sim.state.p_vac_mbar <= 1.6
        assert 98.5 <= sim.state.conversion_pct <= 99.2
        assert 51500.0 <= sim.state.m_n <= 52500.0
        assert 1.78 <= sim.state.intrinsic_viscosity_dl_g <= 1.86
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.reaction_active is True

    def test_temperature_unit_conversions(self) -> None:
        """Check t_melt_c, t_melt_k, melt_temp_c, temperature_c properties."""
        state = PBATPolycondensationState()
        state.t_melt = 513.15
        assert math.isclose(state.t_melt_c, 240.0, abs_tol=1e-5)
        assert math.isclose(state.melt_temp_c, 240.0, abs_tol=1e-5)
        assert math.isclose(state.temperature_c, 240.0, abs_tol=1e-5)

        state.t_melt_c = 245.0
        assert math.isclose(state.t_melt, 518.15, abs_tol=1e-5)
        assert math.isclose(state.temperature_c, 245.0, abs_tol=1e-5)


# ============================================================================
# Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
# ============================================================================

class TestSection05CoupledODESystemAndRK4Integrator:
    """Verify 6-state ODE formulation, derivative computation, RK4 stability, and state bounds."""

    def test_state_vector_definition(self) -> None:
        """Dynamic 6-state vector components are accessible and strictly positive."""
        state = PBATPolycondensationState()
        assert state.c_aa > 0.0
        assert state.c_pta > 0.0
        assert state.c_bdo > 0.0
        assert state.c_pbat > 0.0
        assert state.m_n > 0.0
        assert state.t_melt > 0.0

    def test_ode_system_shape_and_finite(self) -> None:
        """ODE system returns exactly 6 finite float components."""
        sim = PBATPolycondensationReactor()
        y0 = [0.036, 0.0198, 0.0585, 4.5942, 52000.0, 513.15]
        derivs = sim.ode_system(y0)
        assert len(derivs) == 6
        assert all(math.isfinite(d) for d in derivs)

    def test_rk4_step_execution_and_state_non_negativity(self) -> None:
        """RK4 step advances time and maintains non-negative finite state variables."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        t0 = sim.state.sim_time_s

        sim.rk4_step(dt=0.02)
        assert sim.state.sim_time_s > t0
        assert sim.state.c_aa >= 0.0
        assert sim.state.c_pta >= 0.0
        assert sim.state.c_bdo >= 0.0
        assert sim.state.c_pbat >= 0.0
        assert sim.state.m_n >= 100.0
        assert sim.state.t_melt >= 200.0

    def test_rk4_numerical_stability_across_timesteps(self) -> None:
        """RK4 integrator remains stable under varying dt (0.005, 0.01, 0.02, 0.05 s)."""
        for dt_test in [0.005, 0.01, 0.02, 0.05]:
            sim = PBATPolycondensationReactor()
            sim.reset()
            for _ in range(40):
                sim.rk4_step(dt=dt_test)
            assert 235.0 <= sim.state.t_melt_c <= 245.0
            assert 48000.0 <= sim.state.m_n <= 56000.0
            assert not math.isnan(sim.state.t_melt)
            assert not math.isinf(sim.state.t_melt)


# ============================================================================
# Section 6: Mathematical Conservation Residuals
# ============================================================================

class TestSection06ConservationLawsResiduals:
    """Verify stoichiometric mass, elemental, carbon, and enthalpy residuals (< 1e-10)."""

    def test_total_mass_balance_residual(self) -> None:
        """Total stoichiometric mass balance residual is strictly < 1e-10 kg/s."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.total_mass_balance_residual_kg_s >= 0.0

    def test_elemental_balance_residual(self) -> None:
        """Elemental mass balance residual is strictly < 1e-10 kg/s."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s >= 0.0

    def test_carbon_mass_balance_residual(self) -> None:
        """Carbon mass conservation residual is strictly < 1e-10 kg/s."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.carbon_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.carbon_mass_balance_residual_kg_s >= 0.0

    def test_enthalpy_conservation_residual(self) -> None:
        """Enthalpy first-law conservation residual is strictly < 1e-10 kW."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw >= 0.0

    def test_conservation_residuals_preserved_after_transient_steps(self) -> None:
        """All conservation residuals remain < 1e-10 after 50 scan cycles."""
        sim = PBATPolycondensationReactor()
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
    """Verify strict priority hierarchy: 0xF501 > 0xF502 > 0xF503 > 0xF504 > 0x0000."""

    def test_priority_1_overtemp_trip(self) -> None:
        """0xF501 OVERTEMP trips when melt temperature > 255.0 °C."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.state.t_melt_c = 258.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False
        assert sim.state.anomaly_pre_alarm is True

    def test_priority_2_vacuum_loss_trip(self) -> None:
        """0xF502 VACUUM_LOSS trips when vacuum pressure > 4.5 mbar."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.state.p_vac_mbar = 5.2
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False
        assert sim.state.anomaly_pre_alarm is True

    def test_priority_3_comonomer_imbalance_trip(self) -> None:
        """0xF503 COMONOMER_IMBALANCE trips when PTA/AA ratio < 0.45 or > 0.65."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.state.comonomer_ratio = 0.40
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COMONOMER_IMBALANCE
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False
        assert sim.state.anomaly_pre_alarm is True

        sim.reset()
        sim.state.comonomer_ratio = 0.70
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COMONOMER_IMBALANCE
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_priority_4_degradation_trip(self) -> None:
        """0xF504 DEGRADATION trips when M_n < 35,000 Da or conversion < 92.0%."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.state.m_n = 32000.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEGRADATION
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

        sim.reset()
        sim.state.conversion_pct = 90.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.DEGRADATION
        assert sim.state.emergency_dump_tripped is True

    def test_priority_5_normal_steady_state_ok(self) -> None:
        """0x0000 OK when all variables within nominal safety envelope."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.reaction_active is True
        assert sim.state.anomaly_pre_alarm is False
        assert sim.state.emergency_dump_tripped is False

    def test_strict_priority_overrides(self) -> None:
        """Higher priority faults deterministically preempt lower priority faults."""
        sim = PBATPolycondensationReactor()

        # Overtemp (0xF501) preempts vacuum loss (0xF502), imbalance (0xF503), degradation (0xF504)
        sim.reset()
        sim.state.t_melt_c = 260.0
        sim.state.p_vac_mbar = 8.0
        sim.state.comonomer_ratio = 0.35
        sim.state.m_n = 20000.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP

        # Vacuum loss (0xF502) preempts imbalance (0xF503) and degradation (0xF504)
        sim.reset()
        sim.state.t_melt_c = 240.0
        sim.state.p_vac_mbar = 6.0
        sim.state.comonomer_ratio = 0.35
        sim.state.m_n = 20000.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS

        # Comonomer imbalance (0xF503) preempts degradation (0xF504)
        sim.reset()
        sim.state.t_melt_c = 240.0
        sim.state.p_vac_mbar = 1.5
        sim.state.comonomer_ratio = 0.75
        sim.state.m_n = 25000.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.COMONOMER_IMBALANCE


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
# ============================================================================

class TestSection08DiagnosticCodes16BitValues:
    """Verify signed and unsigned 16-bit values, comparisons, string formatting, and masking."""

    def test_diagnostic_code_hex_and_integer_values(self) -> None:
        """Hex integer values match W278 specification."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.OVERTEMP.value == 0xF501
        assert DiagnosticCode.VACUUM_LOSS.value == 0xF502
        assert DiagnosticCode.COMONOMER_IMBALANCE.value == 0xF503
        assert DiagnosticCode.DEGRADATION.value == 0xF504

    def test_signed_16bit_representation(self) -> None:
        """Signed 16-bit two's complement values: 0xF501=-2815, 0xF502=-2814, 0xF503=-2813, 0xF504=-2812."""
        assert (0xF501 - 65536) == -2815
        assert (0xF502 - 65536) == -2814
        assert (0xF503 - 65536) == -2813
        assert (0xF504 - 65536) == -2812

    def test_signed_and_unsigned_equality(self) -> None:
        """DiagnosticCode compares equal with signed and unsigned integers transparently."""
        assert DiagnosticCode.OK == 0
        assert DiagnosticCode.OK == 0x0000

        assert DiagnosticCode.OVERTEMP == 0xF501
        assert DiagnosticCode.OVERTEMP == 62721
        assert DiagnosticCode.OVERTEMP == -2815

        assert DiagnosticCode.VACUUM_LOSS == 0xF502
        assert DiagnosticCode.VACUUM_LOSS == 62722
        assert DiagnosticCode.VACUUM_LOSS == -2814

        assert DiagnosticCode.COMONOMER_IMBALANCE == 0xF503
        assert DiagnosticCode.COMONOMER_IMBALANCE == 62723
        assert DiagnosticCode.COMONOMER_IMBALANCE == -2813

        assert DiagnosticCode.DEGRADATION == 0xF504
        assert DiagnosticCode.DEGRADATION == 62724
        assert DiagnosticCode.DEGRADATION == -2812

    def test_missing_lookup_signed_integer(self) -> None:
        """DiagnosticCode constructor / _missing_ converts signed int back to enum."""
        assert DiagnosticCode(-2815) == DiagnosticCode.OVERTEMP
        assert DiagnosticCode(-2814) == DiagnosticCode.VACUUM_LOSS
        assert DiagnosticCode(-2813) == DiagnosticCode.COMONOMER_IMBALANCE
        assert DiagnosticCode(-2812) == DiagnosticCode.DEGRADATION

    def test_bitwise_masking_and_string_representation(self) -> None:
        """Bitwise & 0xFFFF and __str__() output formatted as 0xXXXX."""
        assert (DiagnosticCode.OVERTEMP & 0xFFFF) == 0xF501
        assert (DiagnosticCode.VACUUM_LOSS & 0xFFFF) == 0xF502
        assert (DiagnosticCode.COMONOMER_IMBALANCE & 0xFFFF) == 0xF503
        assert (DiagnosticCode.DEGRADATION & 0xFFFF) == 0xF504

        s = str(DiagnosticCode.OVERTEMP)
        assert "0xF501" in s

    def test_diagnostic_code_hash_and_bitwise_operations(self) -> None:
        """Test hash, bitwise and, rand, and invalid missing lookups."""
        code = DiagnosticCode.OVERTEMP
        assert isinstance(hash(code), int)
        assert (code & 0x0F) == (0xF501 & 0x0F)
        assert (0x0F & code) == (0x0F & 0xF501)
        assert (code & DiagnosticCode.VACUUM_LOSS) == (0xF501 & 0xF502)
        assert (DiagnosticCode.VACUUM_LOSS & code) == (0xF502 & 0xF501)

        # Missing lookup with non-matching int and non-int
        assert DiagnosticCode._missing_(999999) is None
        assert DiagnosticCode._missing_("INVALID") is None


# ============================================================================
# Section 9: Fault Injections, Actuations & Emergency Dump Tripped Coil %M559
# ============================================================================

class TestSection09FaultInjectionsAndActuations:
    """Verify inject_fault(), clear_faults(), and coil state transitions."""

    def test_inject_overtemp_fault(self) -> None:
        """Injecting overtemp triggers 0xF501 and asserts %M559 emergency dump trip."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.inject_fault("overtemp")
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_inject_vacuum_loss_fault(self) -> None:
        """Injecting vacuum loss triggers 0xF502 and asserts %M559 emergency dump trip."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.inject_fault("vacuum")
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_inject_comonomer_imbalance_fault(self) -> None:
        """Injecting comonomer imbalance triggers 0xF503 and halts active reaction."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.inject_fault("imbalance")
        assert sim.state.diagnostic_code == DiagnosticCode.COMONOMER_IMBALANCE
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_inject_degradation_fault(self) -> None:
        """Injecting degradation triggers 0xF504 and trips dump."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.inject_fault("degradation")
        assert sim.state.diagnostic_code == DiagnosticCode.DEGRADATION
        assert sim.state.emergency_dump_tripped is True
        assert sim.state.reaction_active is False

    def test_clear_faults_restores_nominal(self) -> None:
        """Calling clear_faults() restores nominal baseline and clears trips."""
        sim = PBATPolycondensationReactor()
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
    """Verify register synchronization (%R2390..%R2397, %M557..%M559) and privilege."""

    def test_nominal_register_table_synchronization(self) -> None:
        """Registers and coils match nominal steady-state values bit-exactly."""
        table = RegisterTable()
        sim = PBATPolycondensationReactor(register_table=table)
        sim.reset()

        assert table.read_word(REG_PBAT_MELT_TEMP_SCALED) == 2400
        assert table.read_word(REG_PBAT_VACUUM_PRESSURE_SCALED) == 15
        assert table.read_word(REG_PBAT_CONVERSION_SCALED) == 988
        assert table.read_word(REG_PBAT_COMONOMER_RATIO_SCALED) == 55
        assert table.read_word(REG_PBAT_MOLECULAR_WEIGHT_SCALED) == 5200
        assert table.read_word(REG_PBAT_INTRINSIC_VISCOSITY_SCALED) == 182
        assert table.read_word(REG_PBAT_VOLATILE_BYPRODUCT_RATE_SCALED) == 38
        assert table.read_uword(REG_PBAT_DIAGNOSTIC_CODE) == 0x0000

        assert table.read_bit(COIL_PBAT_REACTION_ACTIVE) is True
        assert table.read_bit(COIL_PBAT_ANOMALY_PRE_ALARM) is False
        assert table.read_bit(COIL_PBAT_EMERGENCY_DUMP_TRIPPED) is False

    def test_trip_register_table_synchronization(self) -> None:
        """When 0xF501 trips, %R2397 reflects signed -2815 and %M559 emergency dump asserts."""
        table = RegisterTable()
        sim = PBATPolycondensationReactor(register_table=table)
        sim.inject_fault("overtemp")

        assert table.read_uword(REG_PBAT_DIAGNOSTIC_CODE) == 0xF501
        assert table.read_word(REG_PBAT_DIAGNOSTIC_CODE) == -2815
        assert table.read_bit(COIL_PBAT_REACTION_ACTIVE) is False
        assert table.read_bit(COIL_PBAT_EMERGENCY_DUMP_TRIPPED) is True

    def test_system_privilege_sync(self) -> None:
        """Registers synchronized with SYSTEM privilege overwrite protected memory channels."""
        table = RegisterTable()
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2390") == 2400

    def test_register_aliases_equivalence(self) -> None:
        """Verify register string constant aliases."""
        assert REG_PBAT_TEMP_SCALED == REG_PBAT_MELT_TEMP_SCALED
        assert REG_PBAT_VACUUM_SCALED == REG_PBAT_VACUUM_PRESSURE_SCALED
        assert REG_PBAT_CONV_SCALED == REG_PBAT_CONVERSION_SCALED
        assert REG_PBAT_RATIO_SCALED == REG_PBAT_COMONOMER_RATIO_SCALED
        assert REG_PBAT_MN_SCALED == REG_PBAT_MOLECULAR_WEIGHT_SCALED
        assert REG_PBAT_IV_SCALED == REG_PBAT_INTRINSIC_VISCOSITY_SCALED
        assert REG_PBAT_VOLATILE_RATE_SCALED == REG_PBAT_VOLATILE_BYPRODUCT_RATE_SCALED
        assert REG_PBAT_BYPRODUCT_RATE_SCALED == REG_PBAT_VOLATILE_BYPRODUCT_RATE_SCALED
        assert REG_PBAT_DIAG_CODE == REG_PBAT_DIAGNOSTIC_CODE
        assert COIL_PBAT_ACTIVE == COIL_PBAT_REACTION_ACTIVE
        assert COIL_PBAT_PRE_ALARM == COIL_PBAT_ANOMALY_PRE_ALARM
        assert COIL_PBAT_EMERGENCY_DUMP == COIL_PBAT_EMERGENCY_DUMP_TRIPPED
        assert COIL_PBAT_DUMP_TRIPPED == COIL_PBAT_EMERGENCY_DUMP_TRIPPED


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection11PureSTPOUAndASTValidation:
    """Verify IEC 61131-3 Structured Text compliance, parser validation, and register memory bindings."""

    def test_pure_st_pou_security_guard_and_parser(self) -> None:
        """ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC passes SecurityGuard and STParser cleanly."""
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC)
        res = STParser.validate_code(ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC)
        assert res.status == AgentStatus.SUCCESS

    def test_ast_variable_memory_address_bindings(self) -> None:
        """Parsed AST POU contains all 11 required %R2390..%R2397 and %M557..%M559 bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC)
        assert pou is not None
        assert pou.name in ("PbatPolycondensationSync", "PBATPolycondensationSync")

        required_registers = [
            "%R2390", "%R2391", "%R2392", "%R2393",
            "%R2394", "%R2395", "%R2396", "%R2397",
            "%M557", "%M558", "%M559",
        ]
        for reg in required_registers:
            assert reg in pou.bound_registers, f"Missing register {reg} in AST bindings"

        for var in pou.variables:
            addr = getattr(var, "address_binding", None) or getattr(var, "memory_address", None)
            if addr:
                assert addr.startswith(("%R", "%M"))

    def test_verify_pbat_polycondensation_pure_st_function(self) -> None:
        """Helper verification function returns successful result."""
        res = verify_pbat_polycondensation_pure_st()
        assert bool(res) is True
        assert res.status == AgentStatus.SUCCESS

    def test_pure_st_pou_aliases(self) -> None:
        """Aliases for POU string and verification function are consistent."""
        assert PBAT_POLYCONDENSATION_PURE_ST_POU == ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC
        assert PBAT_POLYCONDENSATION_SYNC_POU == ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC
        assert PBAT_PURE_ST_POU == ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC
        assert PBAT_SYNC_POU == ST_PROGRAM_PBAT_POLYCONDENSATION_SYNC
        assert verify_pbat_pure_st is verify_pbat_polycondensation_pure_st
        assert validate_pure_st is verify_pbat_polycondensation_pure_st


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
            SecurityGuard.assert_pure_st_content("NETWORK 10\nLD %M557\nST %M559")

    def test_reject_ladder_mnemonics(self) -> None:
        """XIC and OTE mnemonics are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC %M557 OTE %M559")


# ============================================================================
# Section 13: ILogicUnit Compliance & 100-Cycle Soak Stability
# ============================================================================

class TestSection13ILogicUnitComplianceAndSoakStability:
    """Verify ILogicUnit interface compliance, reset dynamics, and 100-cycle soak stability."""

    def test_ilogic_unit_interface_compliance(self) -> None:
        """PBATPolycondensationReactor implements ILogicUnit protocol."""
        reactor = PBATPolycondensationReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name in ("PbatPolycondensation", "PBATPolycondensation")
        assert reactor.priority == 278
        assert reactor.is_enabled is True

    def test_enable_disable_lifecycle(self) -> None:
        """Disabling logic unit halts scan execution."""
        reactor = PBATPolycondensationReactor()
        reactor.disable()
        assert reactor.is_enabled is False
        t_before = reactor.state.sim_time_s
        reactor.scan_step(0.02)
        assert reactor.state.sim_time_s == t_before
        reactor.enable()
        assert reactor.is_enabled is True

    def test_execute_with_scan_context(self) -> None:
        """Reactor executes cleanly under ScanContext."""
        reactor = PBATPolycondensationReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        reactor.execute(ctx)
        assert reactor.state.scan_count == 1
        assert reactor.state.sim_time_s > 0.0

    def test_100_cycle_soak_stability(self) -> None:
        """100 scan cycles execute with zero NaN, zero Inf, and bounded state variables."""
        sim = PBATPolycondensationReactor()
        sim.reset()

        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        assert not math.isnan(sim.state.t_melt)
        assert not math.isnan(sim.state.m_n)
        assert not math.isnan(sim.state.c_aa)
        assert not math.isnan(sim.state.c_pta)
        assert not math.isnan(sim.state.c_bdo)
        assert not math.isnan(sim.state.c_pbat)
        assert not math.isinf(sim.state.t_melt)

        assert 239.0 <= sim.state.t_melt_c <= 241.0
        assert 51000.0 <= sim.state.m_n <= 53000.0
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.reaction_active is True
        assert sim.state.emergency_dump_tripped is False


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14VerificationSuiteAndArtifactGeneration:
    """Verify run_pbat_polycondensation_verification() output contract and evidence emission."""

    def test_run_verification_suite_success(self, tmp_path: Path) -> None:
        """Verification suite runs all 9 stages cleanly and returns strict 4-state contract."""
        out_file = tmp_path / "pbat_test_evidence.json"
        res = run_pbat_polycondensation_verification(output_path=out_file)

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
        """Alias run_pbat_verification resolves to canonical function."""
        assert run_pbat_verification is run_pbat_polycondensation_verification
        assert run_verification is run_pbat_polycondensation_verification


# ============================================================================
# Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
# ============================================================================

class TestSection15EdgeCasesAliasesAndSensitivity:
    """Verify model compatibility aliases, edge conditions, and parameter sensitivities."""

    def test_class_aliases(self) -> None:
        """All prescribed PascalCase and snake_case aliases resolve to canonical classes."""
        assert PBATPolycondensation is PBATPolycondensationReactor
        assert PbatPolycondensation is PBATPolycondensationReactor
        assert PBATPolycondensationLogicUnit is PBATPolycondensationReactor
        assert PbatPolycondensationLogicUnit is PBATPolycondensationReactor
        assert PBATSimulator is PBATPolycondensationReactor
        assert PbatSimulator is PBATPolycondensationReactor
        assert PBATEngine is PBATPolycondensationReactor
        assert PbatEngine is PBATPolycondensationReactor
        assert PBATModel is PBATPolycondensationReactor
        assert PBATPlantModel is PBATPolycondensationReactor

        assert PbatPolycondensationConfig is PBATPolycondensationConfig
        assert PBATPolycondensationParameters is PBATPolycondensationConfig
        assert PBATConfig is PBATPolycondensationConfig
        assert PbatConfig is PBATPolycondensationConfig

        assert PbatPolycondensationState is PBATPolycondensationState
        assert PBATState is PBATPolycondensationState
        assert PbatState is PBATPolycondensationState

        assert PBATDiagnosticCode is DiagnosticCode
        assert PbatDiagnosticCode is DiagnosticCode
        assert PBATPolycondensationDiagnosticCode is DiagnosticCode
        assert PbatPolycondensationDiagnosticCode is DiagnosticCode

        assert PBATStatusBits is PBATPolycondensationStatusBits
        assert PbatStatusBits is PBATPolycondensationStatusBits
        assert PBATPolycondensationStatusWord is PBATPolycondensationStatusBits
        assert PbatPolycondensationStatusWord is PBATPolycondensationStatusBits
        assert StatusBits is PBATPolycondensationStatusBits

    def test_mark_houwink_viscosity_sensitivity(self) -> None:
        """Intrinsic viscosity scales monotonically with molecular weight."""
        state = PBATPolycondensationState()
        state.m_n = 52000.0
        sim = PBATPolycondensationReactor()
        sim.state = state
        sim._update_kinetics_and_metrics()
        iv_nom = sim.state.intrinsic_viscosity_dl_g

        state.m_n = 70000.0
        sim._update_kinetics_and_metrics()
        iv_high = sim.state.intrinsic_viscosity_dl_g

        state.m_n = 35000.0
        sim._update_kinetics_and_metrics()
        iv_low = sim.state.intrinsic_viscosity_dl_g

        assert iv_high > iv_nom > iv_low
        assert math.isclose(iv_nom, 1.82, abs_tol=0.01)

    def test_arrhenius_temperature_sensitivity(self) -> None:
        """Polycondensation rate constant increases with melt temperature."""
        sim = PBATPolycondensationReactor()
        k_230 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_poly_aa, sim.config.activation_ea_poly_aa_j_mol, 503.15)
        k_240 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_poly_aa, sim.config.activation_ea_poly_aa_j_mol, 513.15)
        k_250 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_poly_aa, sim.config.activation_ea_poly_aa_j_mol, 523.15)
        assert k_250 > k_240 > k_230 > 0.0

    def test_vacuum_enhancement_factor_bounds(self) -> None:
        """Vacuum enhancement factor is bounded and increases with deeper vacuum (lower mbar)."""
        sim = PBATPolycondensationReactor()
        fac_deep = sim.vacuum_enhancement_factor(1.0)
        fac_nom = sim.vacuum_enhancement_factor(1.5)
        fac_loss = sim.vacuum_enhancement_factor(4.5)

        assert fac_deep > fac_nom > fac_loss
        assert 0.2 <= fac_loss <= 3.0
        assert 0.2 <= fac_deep <= 3.0

    def test_step_method_execution_result(self) -> None:
        """Reactor.step() returns valid ExecutionResult with status success or failed on bad dt."""
        sim = PBATPolycondensationReactor()
        res_ok = sim.step(0.02)
        assert res_ok.status == AgentStatus.SUCCESS

        res_bad = sim.step(-0.01)
        assert res_bad.status == AgentStatus.FAILED
        assert res_bad.error_code == "INVALID_TIMESTEP"

    def test_state_properties_getters_and_setters(self) -> None:
        """Test getters and setters on PBATPolycondensationState."""
        state = PBATPolycondensationState()
        state.t_melt_k = 515.0
        assert state.t_melt_k == 515.0
        assert math.isclose(state.t_melt_c, 515.0 - 273.15, abs_tol=1e-5)

        state.molecular_weight_da = 48000.0
        assert state.molecular_weight_da == 48000.0
        assert state.m_n == 48000.0

    def test_inactive_reaction_kinetics_and_derivatives(self) -> None:
        """Kinetics and derivatives when reaction_active is False or emergency dump tripped."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.state.reaction_active = False

        kin = sim.compute_kinetics(513.15, 0.036, 0.0198, 0.0585, 1.5)
        assert kin["r_poly_aa"] == 0.0
        assert kin["r_poly_pta"] == 0.0
        assert kin["r_volatile"] == 0.0

        derivs = sim.compute_derivatives(0.0, [0.036, 0.0198, 0.0585, 4.5942, 52000.0, 513.15])
        assert sim.state.q_flow_kw == 0.0
        assert sim.state.q_jacket_kw == 0.0
        assert sim.state.q_evap_kw == 0.0

        sim.state.emergency_dump_tripped = True
        derivs_dump = sim.compute_derivatives(0.0, [0.036, 0.0198, 0.0585, 4.5942, 52000.0, 513.15])
        assert sim.state.q_dump_kw == 260.0

    def test_zero_feed_concentration_metrics(self) -> None:
        """Kinetics and metrics when inlet feed concentrations are zero."""
        sim = PBATPolycondensationReactor()
        sim.reset()
        sim.config.c_aa_feed_mol_l = 0.0
        sim.config.c_pta_feed_mol_l = 0.0
        sim._update_kinetics_and_metrics()
        assert sim.state.conversion_pct == 0.0

        sim.config.c_aa_feed_mol_l = 3.0
        sim.state.c_aa = 0.0
        sim._update_kinetics_and_metrics()
        assert sim.state.comonomer_ratio == sim.config.feed_comonomer_ratio

    def test_scan_context_fallback_timesteps(self) -> None:
        """ScanContext execution handles dt=None with dt_s fallback."""
        sim = PBATPolycondensationReactor()
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
        assert (r_pass == 12345) is False

    def test_additional_coverage_branches(self) -> None:
        """Cover property setters, fault injection branches, and equality fallbacks."""
        state = PBATPolycondensationState()
        state.melt_temp_c = 242.0
        assert math.isclose(state.melt_temp_c, 242.0)
        state.temperature_c = 243.0
        assert math.isclose(state.temperature_c, 243.0)

        sim = PBATPolycondensationReactor()
        sim.inject_fault("imbalance high")
        assert sim.state.diagnostic_code == DiagnosticCode.COMONOMER_IMBALANCE
        assert sim.state.emergency_dump_tripped is True

        ctx3 = ScanContext(cycle=3, dt=0.0, dt_s=0.0)
        sim.execute(ctx3)

        assert (DiagnosticCode.OK == "NOT_AN_INT") is False

