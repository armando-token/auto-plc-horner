"""Comprehensive Unit Test Suite for Wave W326 PHA Hydrogenolysis & 2-MeTHF Synthesis CSTR ODE Simulation.

Work Package: W326 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Simulation: Industrial Catalytic Polyhydroxyalkanoate Hydrogenolysis & 2-Methyltetrahydrofuran (2-MeTHF) Synthesis CSTR ODE Simulation.

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes (70+ Tests):
1. TestPhysicalConstantsAndRegisters
2. TestReactionRatesAndSelectivity
3. TestCoupled6StateDerivatives
4. TestRK4IntegrationStability
5. TestMassBalanceConservation
6. TestThermalRunawayTrip
7. TestReactorOverpressureQuenchTrip
8. TestCatalystSinteringAndByproductSpikeTrips
9. TestRegisterTableSynchronization
10. TestPureStructuredTextPOU
11. TestILogicUnitComplianceAndSoak
12. TestVerificationRunnerAndCLI
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.pha_hydrogenolysis_methef import (
    COIL_PHA_METH_ACTIVE,
    COIL_PHA_METH_EMERGENCY,
    COIL_PHA_METH_EMERGENCY_QUENCH,
    COIL_PHA_METH_FEED,
    COIL_PHA_METH_FEED_PUMP,
    COIL_PHA_METH_PUMP,
    COIL_PHA_METH_QUENCH,
    COIL_PHA_METH_REACTOR_ACTIVE,
    COIL_PHA_METH_RUNNING,
    DIAG_ERR_BYPRODUCT,
    DIAG_ERR_BYPRODUCT_SPIKE,
    DIAG_ERR_CATALYST,
    DIAG_ERR_CATALYST_SINTERING,
    DIAG_ERR_DEACTIVATION,
    DIAG_ERR_MASS_BALANCE,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_MASS_DIVERGENCE,
    DIAG_ERR_OVERHEAT,
    DIAG_ERR_OVERPRESSURE,
    DIAG_ERR_OVERPRESSURE_QUENCH,
    DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE,
    DIAG_ERR_PENTANEDIOL_SPIKE,
    DIAG_ERR_PRESSURE,
    DIAG_ERR_QUENCH,
    DIAG_ERR_RUNAWAY,
    DIAG_ERR_SINTERING,
    DIAG_ERR_THERMAL,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_OK,
    MW_2METHEF,
    MW_CARBON,
    MW_PENTANEDIOL,
    MW_PRECURSOR,
    MW_WATER,
    PHA_HYDROGENOLYSIS_METHEF_CONTROL_POU,
    PHA_HYDROGENOLYSIS_METHEF_PURE_ST_POU,
    PHA_METHEF_CONTROL_POU,
    PHA_METHEF_PURE_ST_POU,
    PHAHydrogenolysisMethefConfig,
    PHAHydrogenolysisMethefControl,
    PHAHydrogenolysisMethefDiagnosticCode,
    PHAHydrogenolysisMethefEngine,
    PHAHydrogenolysisMethefLogicUnit,
    PHAHydrogenolysisMethefParameters,
    PHAHydrogenolysisMethefReactor,
    PHAHydrogenolysisMethefSimulator,
    PHAHydrogenolysisMethefState,
    PHAHydrogenolysisMethefStateModel,
    PHAHydrogenolysisMethefStatusBits,
    PHAHydrogenolysisMethefStatusWord,
    PHAMethefConfig,
    PHAMethefDiagnosticCode,
    PHAMethefEngine,
    PHAMethefSimulator,
    PHAMethefState,
    REG_PHA_METH_ACTIVITY,
    REG_PHA_METH_CATALYST,
    REG_PHA_METH_CATALYST_ACTIVITY,
    REG_PHA_METH_CONV,
    REG_PHA_METH_CONVERSION,
    REG_PHA_METH_COOLING,
    REG_PHA_METH_COOLING_DUTY_KW,
    REG_PHA_METH_DIAG,
    REG_PHA_METH_DIAGNOSTIC_CODE,
    REG_PHA_METH_DUTY,
    REG_PHA_METH_FEED_FLOW,
    REG_PHA_METH_FEED_FLOW_RATE,
    REG_PHA_METH_FLOW,
    REG_PHA_METH_PRECURSOR_CONVERSION,
    REG_PHA_METH_PRESSURE,
    REG_PHA_METH_P_REACTOR,
    REG_PHA_METH_REACTOR_PRESSURE,
    REG_PHA_METH_REACTOR_TEMP,
    REG_PHA_METH_REACTOR_TEMPERATURE,
    REG_PHA_METH_SEL,
    REG_PHA_METH_SELECTIVITY,
    REG_PHA_METH_SELECTIVITY_PERCENT,
    REG_PHA_METH_TEMP,
    REG_PHA_METH_T_REACTOR,
    R_GAS_CONSTANT,
    ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    run_pha_hydrogenolysis_methef_verification,
    run_pha_methef_verification,
    verify_pha_hydrogenolysis_methef_pure_st,
    verify_pha_methef_pure_st,
)


class TestPhysicalConstantsAndRegisters:
    """Class 1: Physical constants, registers, coils, and diagnostic comparisons."""

    def test_molecular_weights(self):
        assert MW_PRECURSOR > 0
        assert MW_2METHEF > 0
        assert MW_PENTANEDIOL > 0
        assert MW_WATER > 0
        assert MW_CARBON == 12.011

    def test_register_mappings(self):
        assert REG_PHA_METH_REACTOR_TEMP == "%R2870"
        assert REG_PHA_METH_REACTOR_PRESSURE == "%R2871"
        assert REG_PHA_METH_PRECURSOR_CONVERSION == "%R2872"
        assert REG_PHA_METH_SELECTIVITY_PERCENT == "%R2873"
        assert REG_PHA_METH_FEED_FLOW_RATE == "%R2874"
        assert REG_PHA_METH_CATALYST_ACTIVITY == "%R2875"
        assert REG_PHA_METH_COOLING_DUTY_KW == "%R2876"
        assert REG_PHA_METH_DIAGNOSTIC_CODE == "%R2877"
        assert COIL_PHA_METH_REACTOR_ACTIVE == "%M669"
        assert COIL_PHA_METH_FEED_PUMP == "%M670"
        assert COIL_PHA_METH_EMERGENCY_QUENCH == "%M671"

    def test_diagnostic_codes_values(self):
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_ERR_THERMAL_RUNAWAY) == 0xF9C1
        assert int(DIAG_ERR_OVERPRESSURE_QUENCH) == 0xF9C2
        assert int(DIAG_ERR_CATALYST_SINTERING) == 0xF9C3
        assert int(DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE) == 0xF9C4
        assert int(DIAG_ERR_MASS_BALANCE_DIVERGENCE) == 0xF9C5

    def test_diagnostic_code_signed_equality(self):
        s16 = 0xF9C1 - 0x10000
        assert DIAG_ERR_THERMAL_RUNAWAY == 0xF9C1
        assert DIAG_ERR_THERMAL_RUNAWAY == s16
        assert DIAG_ERR_THERMAL_RUNAWAY != 0x0000

    def test_state_initialization(self):
        state = PHAHydrogenolysisMethefState()
        assert state.c_precursor_feed >= 0
        assert state.c_methef_product >= 0
        assert state.a_catalyst == 1.0


class TestReactionRatesAndSelectivity:
    """Class 2: Reaction rates and selectivity calculations."""

    def test_reaction_rates_positive(self):
        engine = PHAHydrogenolysisMethefEngine()
        r1, r2 = engine.compute_rates(engine.state)
        assert r1 > 0
        assert r2 >= 0

    def test_temperature_sensitivity(self):
        engine_cold = PHAHydrogenolysisMethefEngine()
        engine_cold.state.t_reactor_kelvin = 430.0
        r_cold, _ = engine_cold.compute_rates(engine_cold.state)

        engine_hot = PHAHydrogenolysisMethefEngine()
        engine_hot.state.t_reactor_kelvin = 480.0
        r_hot, _ = engine_hot.compute_rates(engine_hot.state)

        assert r_hot > r_cold


class TestCoupled6StateDerivatives:
    """Class 3: Coupled 6-state continuous ODE derivatives."""

    def test_derivative_calculation(self):
        engine = PHAHydrogenolysisMethefEngine()
        derivs = engine._derivatives(engine.state)
        assert len(derivs) >= 6
        assert derivs[0] < 0  # Precursor being consumed
        assert derivs[1] > 0  # 2-MeTHF being formed


class TestRK4IntegrationStability:
    """Class 4: RK4 integration and step size."""

    def test_rk4_step_forward(self):
        engine = PHAHydrogenolysisMethefEngine()
        initial_c_prec = engine.state.c_precursor_feed
        engine.step_rk4(dt=0.010)
        assert engine.state.c_precursor_feed < initial_c_prec
        assert engine.state.c_methef_product > 0

    @pytest.mark.parametrize("dt", [0.005, 0.01, 0.02, 0.05])
    def test_rk4_step_sizes(self, dt):
        engine = PHAHydrogenolysisMethefEngine()
        engine.step_rk4(dt=dt)
        assert not math.isnan(engine.state.c_methef_product)
        assert engine.state.c_methef_product >= 0


class TestMassBalanceConservation:
    """Class 5: Mass balance conservation across conversion regimes."""

    def test_mass_conservation_residual(self):
        engine = PHAHydrogenolysisMethefEngine()
        for _ in range(50):
            engine.step_rk4(dt=0.010)
        residual = engine.get_mass_residual()
        assert residual < 1e-10


class TestThermalRunawayTrip:
    """Class 6: Thermal runaway safety trip (0xF9C1)."""

    def test_thermal_runaway_high_temperature(self):
        engine = PHAHydrogenolysisMethefEngine()
        engine.inject_thermal_runaway(temp_k=540.0)
        engine.scan_step()
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        assert engine.emergency_quench_active is True
        assert engine.feed_pump is False

    def test_thermal_runaway_high_rate_of_rise(self):
        engine = PHAHydrogenolysisMethefEngine()
        engine.inject_rate_of_rise(rate_k_s=15.0)
        engine.scan_step()
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        assert engine.emergency_quench_active is True


class TestReactorOverpressureQuenchTrip:
    """Class 7: Reactor overpressure quench trip (0xF9C2)."""

    def test_overpressure_trip(self):
        engine = PHAHydrogenolysisMethefEngine()
        engine.inject_overpressure(pressure_bar=55.0)
        engine.scan_step()
        assert engine.diagnostic_code == DIAG_ERR_OVERPRESSURE_QUENCH
        assert engine.emergency_quench_active is True
        assert engine.feed_pump is False


class TestCatalystSinteringAndByproductSpikeTrips:
    """Class 8: Catalyst sintering (0xF9C3) and byproduct spike (0xF9C4)."""

    def test_catalyst_sintering_trip(self):
        engine = PHAHydrogenolysisMethefEngine()
        engine.inject_catalyst_sintering(activity=0.30)
        engine.scan_step()
        assert engine.diagnostic_code == DIAG_ERR_CATALYST_SINTERING

    def test_byproduct_spike_trip(self):
        engine = PHAHydrogenolysisMethefEngine()
        engine.inject_byproduct_spike(yield_pct=30.0)
        engine.scan_step()
        assert engine.diagnostic_code == DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE

    def test_mass_divergence_trip(self):
        engine = PHAHydrogenolysisMethefEngine()
        engine.inject_mass_divergence()
        engine.scan_step()
        assert engine.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE


class TestRegisterTableSynchronization:
    """Class 9: Register table synchronization."""

    def test_nominal_synchronization(self):
        rt = RegisterTable()
        engine = PHAHydrogenolysisMethefEngine(register_table=rt)
        engine.scan_step()

        assert rt.read_bit(COIL_PHA_METH_REACTOR_ACTIVE) is True
        assert rt.read_bit(COIL_PHA_METH_FEED_PUMP) is True
        assert rt.read_bit(COIL_PHA_METH_EMERGENCY_QUENCH) is False
        assert (rt.read_word(REG_PHA_METH_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_trip_synchronization(self):
        rt = RegisterTable()
        engine = PHAHydrogenolysisMethefEngine(register_table=rt)
        engine.inject_thermal_runaway(temp_k=540.0)
        engine.scan_step()

        assert rt.read_bit(COIL_PHA_METH_EMERGENCY_QUENCH) is True
        assert rt.read_bit(COIL_PHA_METH_FEED_PUMP) is False
        assert (rt.read_word(REG_PHA_METH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9C1


class TestPureStructuredTextPOU:
    """Class 10: Pure ST POU validation and anti-ladder construct rejection."""

    def test_pure_st_pou_valid(self):
        assert verify_pha_hydrogenolysis_methef_pure_st() is True

    def test_anti_ladder_security_guard(self):
        ladder_snippets = [
            "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM",
            "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM",
            "PROGRAM LadderTest RUNG 1 END_PROGRAM",
            "PROGRAM LadderTest NETWORK 10 END_PROGRAM",
            "PROGRAM LadderTest XIC(StartPB); END_PROGRAM",
            "PROGRAM LadderTest OTE(MotorCoil); END_PROGRAM",
        ]
        for bad in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad)


class TestILogicUnitComplianceAndSoak:
    """Class 11: ILogicUnit compliance and 100-cycle continuous simulation soak."""

    def test_ilogicunit_interface(self):
        engine = PHAHydrogenolysisMethefEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "PHAHydrogenolysisMethefEngine"
        assert engine.priority == 50
        assert engine.is_enabled is True

    def test_simulation_soak_100_cycles(self):
        engine = PHAHydrogenolysisMethefEngine()
        tracemalloc.start()
        for _ in range(100):
            engine.scan_step()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert peak < 50 * 1024 * 1024


class TestVerificationRunnerAndCLI:
    """Class 12: Verification runner and CLI execution."""

    def test_run_verification_direct(self):
        res = run_pha_hydrogenolysis_methef_verification()
        assert res.get("status") == "success"
        assert res.get("stages_passed") == 9

    def test_cli_subprocess_execution(self):
        cmd = [sys.executable, "scripts/run_pha_hydrogenolysis_methef_verification.py", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data.get("status") == "success"
        assert data.get("stages_passed") == 9

    @pytest.mark.parametrize("temp_c", [120, 140, 160, 180, 200])
    def test_temperature_register_scaling(self, temp_c):
        engine = PHAHydrogenolysisMethefEngine()
        engine.state.t_reactor_kelvin = temp_c + 273.15
        engine.scan_step()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_PHA_METH_REACTOR_TEMP) == temp_c * 10

    @pytest.mark.parametrize("press_bar", [10.0, 20.0, 30.0, 40.0])
    def test_pressure_register_scaling(self, press_bar):
        engine = PHAHydrogenolysisMethefEngine()
        engine.state.p_reactor = press_bar
        engine.scan_step()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_PHA_METH_REACTOR_PRESSURE) == int(press_bar * 100.0)

    @pytest.mark.parametrize("act_pct", [40.0, 60.0, 80.0, 100.0])
    def test_activity_register_scaling(self, act_pct):
        engine = PHAHydrogenolysisMethefEngine()
        engine.state.a_catalyst = act_pct / 100.0
        engine.scan_step()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_PHA_METH_CATALYST_ACTIVITY) == int(act_pct * 10.0)


class TestExtendedParametricRegimes:
    """Class 13: Extended parametric regimes and state transitions."""

    @pytest.mark.parametrize("flow_rate", [5.0, 10.0, 15.0, 20.0, 25.0])
    def test_feed_flow_rate_scaling(self, flow_rate):
        engine = PHAHydrogenolysisMethefEngine()
        engine.state.feed_flow_rate_l_min = flow_rate
        engine.scan_step()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_PHA_METH_FEED_FLOW_RATE) == int(flow_rate * 10.0)

    @pytest.mark.parametrize("cooling_kw", [10.0, 25.0, 50.0, 75.0, 100.0])
    def test_cooling_duty_scaling(self, cooling_kw):
        engine = PHAHydrogenolysisMethefEngine()
        engine.state.cooling_duty_kw = cooling_kw
        engine.scan_step()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_PHA_METH_COOLING_DUTY_KW) == int(cooling_kw * 10.0)

    @pytest.mark.parametrize("prec_conv", [5.0, 25.0, 50.0, 75.0, 95.0])
    def test_conversion_scaling(self, prec_conv):
        engine = PHAHydrogenolysisMethefEngine()
        c_in = engine._initial_c_precursor
        c_out = c_in * (1.0 - prec_conv / 100.0)
        engine.state.c_precursor_feed = c_out
        engine.scan_step()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert abs(rt.read_word(REG_PHA_METH_PRECURSOR_CONVERSION) - int(prec_conv * 10.0)) <= 2

    @pytest.mark.parametrize("diag_code,expected_hex", [
        (DIAG_OK, 0x0000),
        (DIAG_ERR_THERMAL_RUNAWAY, 0xF9C1),
        (DIAG_ERR_OVERPRESSURE_QUENCH, 0xF9C2),
        (DIAG_ERR_CATALYST_SINTERING, 0xF9C3),
        (DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE, 0xF9C4),
        (DIAG_ERR_MASS_BALANCE_DIVERGENCE, 0xF9C5),
    ])
    def test_all_diagnostic_codes_representation(self, diag_code, expected_hex):
        assert int(diag_code) == expected_hex
        assert str(diag_code) == f"0x{expected_hex:04X}"
        assert repr(diag_code) == f"DiagnosticCode(0x{expected_hex:04X})"

    @pytest.mark.parametrize("step_idx", list(range(1, 11)))
    def test_multi_step_trajectory(self, step_idx):
        engine = PHAHydrogenolysisMethefEngine()
        for _ in range(step_idx):
            engine.scan_step()
        assert engine.state.c_precursor_feed < engine._initial_c_precursor
        assert engine.state.c_methef_product > 0
        assert engine.diagnostic_code == DIAG_OK

    def test_clear_injections_restores_nominal(self):
        engine = PHAHydrogenolysisMethefEngine()
        engine.inject_byproduct_spike(yield_pct=28.0)
        assert engine._byproduct_spike_injected is True
        engine.clear_injections()
        assert engine._byproduct_spike_injected is False

    def test_reset_restores_nominal(self):
        engine = PHAHydrogenolysisMethefEngine()
        engine.inject_thermal_runaway()
        engine.scan_step()
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        engine.reset()
        assert engine.diagnostic_code == DIAG_OK
        assert engine.emergency_quench_active is False
        assert engine.feed_pump is True
