"""Comprehensive Unit and Integration Test Suite for CIP Energy & Power Management Protocol Engine.

Work Package: W220 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (100 Unit Tests across 13 Sections):
1. Section 1: Constants, Enums & Protocol Identifiers (Class 0x4F, 0x50, States, Codes, Quadrants, Defaults).
2. Section 2: ODVA CIP Objects (Class 0x4F Energy Management & Class 0x50 Electrical Energy Base).
3. Section 3: 4-Quadrant Power Calculations (Q1..Q4 Active, Reactive, Apparent, Power Factor, THD, 3-Phase).
4. Section 4: Dual-Word Energy Counter (%R1813 high word, %R1814 low word) Rollover and DINT Encoding.
5. Section 5: Sliding Window Peak Demand Profiling & Moving Average Calculation.
6. Section 6: Curtailment Trip Protection (0xEC01, %M423) and Load Shedding Interlocks.
7. Section 7: Reverse Power Flow Trip Protection (0xEC02, Backfeed Prevention).
8. Section 8: Low Power Factor Penalty Warning (0xEC03) & Harmonic Distortion Warning (0xEC04).
9. Section 9: Energy State Machine Transitions (NonOperational -> Operational -> EnergySaving -> CurtailmentActive).
10. Section 10: Horner OCS Register Synchronization (%R1810..%R1817, %M422..%M423 with PrivilegeMode.SYSTEM).
11. Section 11: ILogicUnit 100-Cycle Simulation (scan_step, execute, priority, reset).
12. Section 12: Pure IEC 61131-3 ST POU & SecurityGuard Anti-Ladder Rejection (LadderForbiddenError).
13. Section 13: Deterministic 9-Stage Verification Runner (run_cip_energy_mgmt_verification execution & JSON export).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_energy_mgmt import (
    CIP_CLASS_ELECTRICAL_ENERGY_BASE,
    CIP_CLASS_ENERGY_MANAGEMENT,
    CIP_ELECTRICAL_BASE_CLASS_ID,
    CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID,
    CIP_ENERGY_BASE_CLASS_ID,
    CIP_ENERGY_MANAGEMENT_CLASS_ID,
    CIP_ENERGY_MGMT_CLASS_ID,
    CIP_ENERGY_MGMT_ENGINE,
    CIP_ENERGY_MGMT_POU,
    CIP_ENERGY_MGMT_SYNC_POU,
    CIP_ENERGY_SYNC_POU,
    DEFAULT_CURTAILMENT_THRESHOLD_KW,
    DEFAULT_DEMAND_WINDOW_SECONDS,
    DEFAULT_ENERGY_BASELINE_KW,
    DEFAULT_PEAK_DEMAND_THRESHOLD_KW,
    DEFAULT_POWER_FACTOR_PENALTY_THRESHOLD,
    DEFAULT_REVERSE_POWER_TRIP_THRESHOLD_KW,
    DEFAULT_SLIDING_WINDOW_SECONDS,
    HIGH_THD_WARNING_THRESHOLD_PCT,
    NOMINAL_ACTIVE_POWER_KW,
    NOMINAL_LINE_VOLTAGE_RMS,
    NOMINAL_PEAK_DEMAND_WINDOW_KW,
    NOMINAL_POWER_FACTOR_PCT,
    NOMINAL_REACTIVE_POWER_KVAR,
    NOMINAL_SYSTEM_FREQUENCY_HZ,
    POWER_FACTOR_PENALTY_THRESHOLD,
    REVERSE_POWER_THRESHOLD_KW,
    CipEnergyDiagnosticCode,
    CipEnergyEngine,
    CipEnergyManagementEngine,
    CipEnergyManagementObject,
    CipEnergyMgmtDiagnosticCode,
    CipEnergyMgmtEngine,
    CipEnergyMgmtObject,
    CipEnergyMgmtSnapshot,
    CipEnergyMgmtState,
    CipEnergyObject,
    CipEnergySnapshot,
    CipEnergyState,
    CipEnergySyncPOU,
    CipPowerQuadrant,
    DualWordEnergyCounter,
    EnergyManagementState,
    PowerQuadrant,
    SlidingWindowDemandProfiler,
    calculate_3phase_power,
    calculate_4quadrant_power,
    calculate_power_triangle,
    calculate_thd,
    decode_dint_words,
    determine_power_quadrant,
    encode_dint_words,
    run_cip_energy_mgmt_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    verify_cip_energy_mgmt_pure_st,
)


# ============================================================================
# Section 1: Constants, Enums & Protocol Identifiers
# ============================================================================

class TestConstantsAndEnums:
    """Tests for protocol identifiers, threshold constants, and enumerations."""

    def test_cip_class_ids(self) -> None:
        assert CIP_ENERGY_MGMT_CLASS_ID == 0x4F
        assert CIP_ENERGY_MANAGEMENT_CLASS_ID == 0x4F
        assert CIP_CLASS_ENERGY_MANAGEMENT == 0x4F
        assert CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID == 0x50
        assert CIP_ENERGY_BASE_CLASS_ID == 0x50
        assert CIP_CLASS_ELECTRICAL_ENERGY_BASE == 0x50
        assert CIP_ELECTRICAL_BASE_CLASS_ID == 0x50

    def test_energy_management_state_values(self) -> None:
        assert EnergyManagementState.NON_OPERATIONAL == 0
        assert EnergyManagementState.OPERATIONAL == 1
        assert EnergyManagementState.ENERGY_SAVING == 2
        assert EnergyManagementState.PEAK_DEMAND_CURTAILMENT == 3
        assert EnergyManagementState.CURTAILMENT_ACTIVE == 3

        # Aliases
        assert CipEnergyMgmtState.NonOperational == 0
        assert CipEnergyMgmtState.Operational == 1
        assert CipEnergyMgmtState.EnergySaving == 2
        assert CipEnergyMgmtState.CurtailmentActive == 3
        assert CipEnergyState.Operational == 1

    def test_diagnostic_code_values(self) -> None:
        assert CipEnergyMgmtDiagnosticCode.OK == 0x0000
        assert CipEnergyMgmtDiagnosticCode.PEAK_DEMAND_LIMIT_EXCEEDED == 0xEC01
        assert CipEnergyMgmtDiagnosticCode.CURTAILMENT_TRIP == 0xEC01
        assert CipEnergyMgmtDiagnosticCode.REVERSE_POWER_FLOW_FAULT == 0xEC02
        assert CipEnergyMgmtDiagnosticCode.REVERSE_POWER_FLOW_TRIP == 0xEC02
        assert CipEnergyMgmtDiagnosticCode.POWER_FACTOR_BELOW_PENALTY_THRESHOLD == 0xEC03
        assert CipEnergyMgmtDiagnosticCode.LOW_POWER_FACTOR_PENALTY == 0xEC03
        assert CipEnergyMgmtDiagnosticCode.CURRENT_HARMONIC_DISTORTION_HIGH == 0xEC04

        # Aliases
        assert CipEnergyDiagnosticCode.CurtailmentTrip == 0xEC01
        assert CipEnergyDiagnosticCode.ReversePowerTrip == 0xEC02
        assert CipEnergyDiagnosticCode.LowPowerFactorPenalty == 0xEC03

    def test_power_quadrant_values(self) -> None:
        assert PowerQuadrant.QUADRANT_1 == 1
        assert PowerQuadrant.QUADRANT_2 == 2
        assert PowerQuadrant.QUADRANT_3 == 3
        assert PowerQuadrant.QUADRANT_4 == 4

        # Aliases
        assert PowerQuadrant.Q1 == 1
        assert PowerQuadrant.Q2 == 2
        assert PowerQuadrant.Q3 == 3
        assert PowerQuadrant.Q4 == 4
        assert CipPowerQuadrant.FORWARD_INDUCTIVE == 1
        assert CipPowerQuadrant.REVERSE_INDUCTIVE == 2
        assert CipPowerQuadrant.REVERSE_CAPACITIVE == 3
        assert CipPowerQuadrant.FORWARD_CAPACITIVE == 4

    def test_engineering_threshold_constants(self) -> None:
        assert NOMINAL_LINE_VOLTAGE_RMS == 480.0
        assert NOMINAL_SYSTEM_FREQUENCY_HZ == 60.0
        assert NOMINAL_ACTIVE_POWER_KW == 145.0
        assert NOMINAL_REACTIVE_POWER_KVAR == 62.0
        assert NOMINAL_POWER_FACTOR_PCT == 92.0
        assert NOMINAL_PEAK_DEMAND_WINDOW_KW == 182.0
        assert DEFAULT_PEAK_DEMAND_THRESHOLD_KW == 200.0
        assert DEFAULT_DEMAND_WINDOW_SECONDS == 900.0
        assert DEFAULT_SLIDING_WINDOW_SECONDS == 900.0
        assert POWER_FACTOR_PENALTY_THRESHOLD == 0.85
        assert DEFAULT_POWER_FACTOR_PENALTY_THRESHOLD == 0.85
        assert REVERSE_POWER_THRESHOLD_KW == -0.1
        assert DEFAULT_REVERSE_POWER_TRIP_THRESHOLD_KW == -0.1
        assert HIGH_THD_WARNING_THRESHOLD_PCT == 8.0

    def test_memory_map_register_addresses(self) -> None:
        pou = CIP_ENERGY_MGMT_SYNC_POU
        for reg in [
            "%R1810", "%R1811", "%R1812", "%R1813",
            "%R1814", "%R1815", "%R1816", "%R1817",
            "%M422", "%M423",
        ]:
            assert reg in pou


# ============================================================================
# Section 2: ODVA CIP Objects (Class 0x4F & Class 0x50)
# ============================================================================

class TestCipEnergyObjects:
    """Tests for ODVA CIP Class 0x4F Energy Management and Class 0x50 Base Object models."""

    def test_energy_mgmt_object_default_attributes(self) -> None:
        obj = CipEnergyMgmtObject()
        assert obj.energy_state == EnergyManagementState.OPERATIONAL
        assert obj.supported_energy_states == 0x0F
        assert obj.requested_energy_state == EnergyManagementState.OPERATIONAL
        assert obj.time_to_transition_ms == 0
        assert obj.peak_demand_threshold_kw == DEFAULT_PEAK_DEMAND_THRESHOLD_KW
        assert obj.curtailment_trip_active is False
        assert obj.diagnostic_code == CipEnergyMgmtDiagnosticCode.OK
        assert obj.active_power_kw == NOMINAL_ACTIVE_POWER_KW
        assert obj.power_quadrant == PowerQuadrant.QUADRANT_1

    def test_class_4f_get_attribute_single(self) -> None:
        obj = CipEnergyMgmtObject(
            energy_state=EnergyManagementState.ENERGY_SAVING,
            peak_demand_threshold_kw=210.0,
            demand_window_duration_s=600.0,
            peak_demand_window_kw=175.0,
            curtailment_trip_active=False,
            curtailment_capacity_kw=45.0,
        )
        assert obj.get_attribute_single(1, CIP_ENERGY_MGMT_CLASS_ID) == int(EnergyManagementState.ENERGY_SAVING)
        assert obj.get_attribute_single(2, CIP_ENERGY_MGMT_CLASS_ID) == 0x0F
        assert obj.get_attribute_single(5, CIP_ENERGY_MGMT_CLASS_ID) == 210.0
        assert obj.get_attribute_single(6, CIP_ENERGY_MGMT_CLASS_ID) == 600.0
        assert obj.get_attribute_single(7, CIP_ENERGY_MGMT_CLASS_ID) == 175.0
        assert obj.get_attribute_single(8, CIP_ENERGY_MGMT_CLASS_ID) is False
        assert obj.get_attribute_single(9, CIP_ENERGY_MGMT_CLASS_ID) == 0x0000
        assert obj.get_attribute_single(10, CIP_ENERGY_MGMT_CLASS_ID) == 45.0

    def test_class_50_get_attribute_single(self) -> None:
        obj = CipEnergyMgmtObject(
            active_power_kw=150.0,
            reactive_power_kvar=50.0,
            apparent_power_kva=158.11,
            power_factor=0.9487,
            total_energy_kwh=1234.5,
            power_quadrant=PowerQuadrant.QUADRANT_1,
            voltage_rms=480.0,
            current_rms=190.0,
            frequency_hz=60.0,
            current_thd_pct=3.1,
            reverse_power_detected=False,
            low_power_factor_detected=False,
            accuracy_class=1,
        )
        assert obj.get_attribute_single(1, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 150.0
        assert obj.get_attribute_single(2, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 50.0
        assert obj.get_attribute_single(3, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 158.11
        assert obj.get_attribute_single(4, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 0.9487
        assert obj.get_attribute_single(5, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 1234.5
        assert obj.get_attribute_single(6, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == int(PowerQuadrant.QUADRANT_1)
        assert obj.get_attribute_single(7, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 480.0
        assert obj.get_attribute_single(8, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 190.0
        assert obj.get_attribute_single(9, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 60.0
        assert obj.get_attribute_single(10, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 3.1
        assert obj.get_attribute_single(11, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) is False
        assert obj.get_attribute_single(12, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) is False
        assert obj.get_attribute_single(13, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID) == 1

    def test_class_4f_set_attribute_single_valid(self) -> None:
        obj = CipEnergyMgmtObject()
        obj.set_attribute_single(1, EnergyManagementState.ENERGY_SAVING, CIP_ENERGY_MGMT_CLASS_ID)
        assert obj.energy_state == EnergyManagementState.ENERGY_SAVING

        obj.set_attribute_single(5, 230.0, CIP_ENERGY_MGMT_CLASS_ID)
        assert obj.peak_demand_threshold_kw == 230.0

        obj.set_attribute_single(6, 1200.0, CIP_ENERGY_MGMT_CLASS_ID)
        assert obj.demand_window_duration_s == 1200.0

        obj.set_attribute_single(8, True, CIP_ENERGY_MGMT_CLASS_ID)
        assert obj.curtailment_trip_active is True

    def test_class_50_set_attribute_single_valid(self) -> None:
        obj = CipEnergyMgmtObject()
        obj.set_attribute_single(1, 160.0, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID)
        assert obj.active_power_kw == 160.0

        obj.set_attribute_single(2, 70.0, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID)
        assert obj.reactive_power_kvar == 70.0

        obj.set_attribute_single(4, 0.91, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID)
        assert obj.power_factor == 0.91

        obj.set_attribute_single(5, 500.0, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID)
        assert obj.total_energy_kwh == 500.0

    def test_class_4f_set_attribute_readonly_raises_keyerror(self) -> None:
        obj = CipEnergyMgmtObject()
        with pytest.raises(KeyError):
            obj.set_attribute_single(2, 0x1F, CIP_ENERGY_MGMT_CLASS_ID)  # Supported states is read-only

    def test_class_50_set_attribute_readonly_raises_keyerror(self) -> None:
        obj = CipEnergyMgmtObject()
        with pytest.raises(KeyError):
            obj.set_attribute_single(13, 2, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID)  # Accuracy class is read-only

    def test_get_attribute_all_class_4f(self) -> None:
        obj = CipEnergyMgmtObject()
        attrs = obj.get_attribute_all(CIP_ENERGY_MGMT_CLASS_ID)
        assert isinstance(attrs, dict)
        assert 1 in attrs and 2 in attrs and 5 in attrs and 8 in attrs
        assert attrs[1] == int(EnergyManagementState.OPERATIONAL)

    def test_get_attribute_all_class_50(self) -> None:
        obj = CipEnergyMgmtObject()
        attrs = obj.get_attribute_all(CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID)
        assert isinstance(attrs, dict)
        assert 1 in attrs and 2 in attrs and 6 in attrs and 13 in attrs
        assert attrs[1] == NOMINAL_ACTIVE_POWER_KW

    def test_unsupported_class_id_raises_valueerror(self) -> None:
        obj = CipEnergyMgmtObject()
        with pytest.raises(ValueError):
            obj.get_attribute_single(1, class_id=0x99)
        with pytest.raises(ValueError):
            obj.set_attribute_single(1, 10, class_id=0x99)
        with pytest.raises(ValueError):
            obj.get_attribute_all(class_id=0x99)

    def test_unsupported_attribute_id_raises_keyerror(self) -> None:
        obj = CipEnergyMgmtObject()
        with pytest.raises(KeyError):
            obj.get_attribute_single(99, CIP_ENERGY_MGMT_CLASS_ID)
        with pytest.raises(KeyError):
            obj.get_attribute_single(99, CIP_ELECTRICAL_ENERGY_BASE_CLASS_ID)

    def test_object_aliases(self) -> None:
        assert CipEnergyManagementObject is CipEnergyMgmtObject
        assert CipEnergyObject is CipEnergyMgmtObject


# ============================================================================
# Section 3: 4-Quadrant Power Calculations
# ============================================================================

class TestFourQuadrantPowerCalculations:
    """Tests for 4-quadrant active/reactive power metering and triangle mathematics."""

    def test_quadrant_1_inductive_load_calculation(self) -> None:
        p, q = 145.0, 62.0
        s, pf, quad = calculate_4quadrant_power(p, q)
        exp_s = math.sqrt(p * p + q * q)
        exp_pf = p / exp_s

        assert abs(s - exp_s) < 1e-4
        assert abs(pf - exp_pf) < 1e-4
        assert pf > 0.0
        assert quad == PowerQuadrant.QUADRANT_1
        assert quad == PowerQuadrant.Q1

    def test_quadrant_2_inductive_generator_calculation(self) -> None:
        p, q = -50.0, 30.0
        s, pf, quad = calculate_4quadrant_power(p, q)
        exp_s = math.sqrt(p * p + q * q)
        exp_pf = p / exp_s

        assert abs(s - exp_s) < 1e-4
        assert abs(pf - exp_pf) < 1e-4
        assert pf < 0.0
        assert quad == PowerQuadrant.QUADRANT_2
        assert quad == PowerQuadrant.Q2

    def test_quadrant_3_capacitive_generator_calculation(self) -> None:
        p, q = -50.0, -30.0
        s, pf, quad = calculate_4quadrant_power(p, q)
        exp_s = math.sqrt(p * p + q * q)
        exp_pf = p / exp_s

        assert abs(s - exp_s) < 1e-4
        assert abs(pf - exp_pf) < 1e-4
        assert pf < 0.0
        assert quad == PowerQuadrant.QUADRANT_3
        assert quad == PowerQuadrant.Q3

    def test_quadrant_4_capacitive_load_calculation(self) -> None:
        p, q = 100.0, -40.0
        s, pf, quad = calculate_4quadrant_power(p, q)
        exp_s = math.sqrt(p * p + q * q)
        exp_pf = p / exp_s

        assert abs(s - exp_s) < 1e-4
        assert abs(pf - exp_pf) < 1e-4
        assert pf > 0.0
        assert quad == PowerQuadrant.QUADRANT_4
        assert quad == PowerQuadrant.Q4

    def test_power_triangle_pure_active(self) -> None:
        s, pf = calculate_power_triangle(100.0, 0.0)
        assert abs(s - 100.0) < 1e-4
        assert abs(pf - 1.0) < 1e-4

    def test_power_triangle_pure_reactive(self) -> None:
        s, pf = calculate_power_triangle(0.0, 50.0)
        assert abs(s - 50.0) < 1e-4
        assert abs(pf - 0.0) < 1e-4

    def test_power_triangle_zero_power_edge_case(self) -> None:
        s, pf = calculate_power_triangle(0.0, 0.0)
        assert abs(s - 0.0) < 1e-4
        assert abs(pf - 1.0) < 1e-4

    def test_3phase_power_balanced_rms(self) -> None:
        v_ll = 480.0
        i_l = 189.68
        pf = 0.9195
        p, q, s = calculate_3phase_power(v_ll, i_l, pf=pf)
        exp_s = (math.sqrt(3.0) * v_ll * i_l) / 1000.0
        exp_p = exp_s * pf
        exp_q = math.sqrt(exp_s * exp_s - exp_p * exp_p)

        assert abs(s - exp_s) < 1e-4
        assert abs(p - exp_p) < 1e-4
        assert abs(q - exp_q) < 1e-4

    def test_determine_power_quadrant_boundary_conditions(self) -> None:
        assert determine_power_quadrant(0.0, 0.0) == PowerQuadrant.QUADRANT_1
        assert determine_power_quadrant(0.0, 10.0) == PowerQuadrant.QUADRANT_1
        assert determine_power_quadrant(0.0, -10.0) == PowerQuadrant.QUADRANT_4
        assert determine_power_quadrant(-0.001, 0.0) == PowerQuadrant.QUADRANT_2
        assert determine_power_quadrant(-0.001, -0.001) == PowerQuadrant.QUADRANT_3

    def test_calculate_thd_harmonic_components(self) -> None:
        fund = 100.0
        harmonics = [3.0, 4.0]  # sqrt(9 + 16) = 5.0 -> 5.0% THD
        thd = calculate_thd(fund, harmonics)
        assert abs(thd - 5.0) < 1e-4

        # Zero fundamental returns 0.0
        assert calculate_thd(0.0, harmonics) == 0.0
        # Empty harmonics returns 0.0
        assert calculate_thd(fund, []) == 0.0


# ============================================================================
# Section 4: Dual-Word Energy Counter & Rollover
# ============================================================================

class TestDualWordEnergyCounter:
    """Tests for dual 16-bit energy counter (%R1813, %R1814) encoding and rollover."""

    def test_encode_and_decode_dint_zero(self) -> None:
        high, low = encode_dint_words(0)
        assert high == 0
        assert low == 0
        dec = decode_dint_words(high, low)
        assert dec == 0

    def test_encode_and_decode_positive_dint(self) -> None:
        high, low = encode_dint_words(145)
        assert high == 0
        assert low == 145
        assert decode_dint_words(high, low) == 145

    def test_encode_and_decode_large_dint_boundary(self) -> None:
        # 100,000 = 0x000186A0 -> high=1, low=0x86A0=34464 -> signed -31072
        high, low = encode_dint_words(100000)
        assert high == 1
        assert low == -31072
        assert decode_dint_words(high, low) == 100000

    def test_counter_initialization_and_increment(self) -> None:
        counter = DualWordEnergyCounter(initial_kwh=10.0)
        assert counter.energy_kwh == 10.0
        assert counter.raw_counter == 10
        counter.increment(5.5)
        assert counter.energy_kwh == 15.5
        assert counter.raw_counter == 16

    def test_counter_low_word_rollover_at_65535(self) -> None:
        counter = DualWordEnergyCounter()
        counter.set_raw(65535)  # 0x0000FFFF
        u_h_before, u_l_before = counter.get_unsigned_words()
        assert u_h_before == 0
        assert u_l_before == 65535

        # Increment by 1.0 -> 65536 (0x00010000)
        counter.increment(1.0)
        u_h_after, u_l_after = counter.get_unsigned_words()
        assert u_h_after == 1
        assert u_l_after == 0

        h_signed, l_signed = counter.get_words()
        assert h_signed == 1
        assert l_signed == 0
        assert decode_dint_words(h_signed, l_signed) == 65536

    def test_counter_signed_word_representation(self) -> None:
        counter = DualWordEnergyCounter()
        # 32768: low word becomes signed -32768
        counter.set_raw(32768)
        h, l = counter.get_words()
        assert h == 0
        assert l == -32768
        assert decode_dint_words(h, l) == 32768

    def test_counter_reset_to_zero(self) -> None:
        counter = DualWordEnergyCounter(initial_kwh=500.0)
        counter.reset()
        assert counter.energy_kwh == 0.0
        assert counter.raw_counter == 0
        h, l = counter.get_words()
        assert h == 0 and l == 0

    def test_counter_set_raw_value(self) -> None:
        counter = DualWordEnergyCounter()
        counter.set_raw(0x12345678)
        h, l = counter.get_unsigned_words()
        assert h == 0x1234
        assert l == 0x5678
        assert decode_dint_words(*counter.get_words()) == 0x12345678

    def test_energy_counter_scan_integration_accuracy(self) -> None:
        engine = CipEnergyMgmtEngine(active_power_kw=120.0)
        # 120 kW over 1800 seconds (0.5 hour) = 60.0 kWh
        for _ in range(180):
            engine.scan_step(dt=10.0)
        assert abs(engine.total_energy_kwh - 60.0) < 1e-4


# ============================================================================
# Section 5: Sliding Window Peak Demand Profiling
# ============================================================================

class TestSlidingWindowDemandProfiler:
    """Tests for moving window rolling average demand profiler."""

    def test_profiler_initialization_and_empty_state(self) -> None:
        profiler = SlidingWindowDemandProfiler(window_duration_s=60.0)
        assert profiler.window_duration_s == 60.0
        assert profiler.peak_demand_kw == 0.0
        assert profiler.current_average_demand_kw == 0.0

    def test_profiler_single_sample_average(self) -> None:
        profiler = SlidingWindowDemandProfiler(window_duration_s=60.0)
        avg = profiler.add_sample(100.0, dt_s=1.0)
        assert abs(avg - 100.0) < 1e-4
        assert abs(profiler.peak_demand_kw - 100.0) < 1e-4

    def test_profiler_rolling_average_calculation(self) -> None:
        profiler = SlidingWindowDemandProfiler(window_duration_s=10.0)
        # 5 seconds at 100 kW, 5 seconds at 200 kW -> average 150 kW
        for _ in range(5):
            profiler.add_sample(100.0, dt_s=1.0)
        for _ in range(5):
            profiler.add_sample(200.0, dt_s=1.0)
        assert abs(profiler.current_average_demand_kw - 150.0) < 1e-3

    def test_profiler_sliding_window_sample_eviction(self) -> None:
        profiler = SlidingWindowDemandProfiler(window_duration_s=2.0)
        profiler.add_sample(100.0, dt_s=1.0)
        profiler.add_sample(200.0, dt_s=1.0)
        assert abs(profiler.current_average_demand_kw - 150.0) < 1e-3
        # Third sample evicts the 100 kW sample; now window has two 200 kW samples
        profiler.add_sample(200.0, dt_s=1.0)
        assert abs(profiler.current_average_demand_kw - 200.0) < 1e-3

    def test_profiler_peak_demand_tracking(self) -> None:
        profiler = SlidingWindowDemandProfiler(window_duration_s=5.0)
        profiler.add_sample(250.0, dt_s=5.0)
        assert abs(profiler.peak_demand_kw - 250.0) < 1e-3
        # Demand drops to 50 kW
        profiler.add_sample(50.0, dt_s=5.0)
        assert abs(profiler.current_average_demand_kw - 50.0) < 1e-3
        # Peak demand remains at 250 kW
        assert abs(profiler.peak_demand_kw - 250.0) < 1e-3

    def test_profiler_reset_behavior(self) -> None:
        profiler = SlidingWindowDemandProfiler(window_duration_s=10.0)
        profiler.add_sample(180.0, dt_s=5.0)
        profiler.reset()
        assert profiler.peak_demand_kw == 0.0
        assert profiler.current_average_demand_kw == 0.0

    def test_engine_sliding_window_accumulation_over_scans(self) -> None:
        engine = CipEnergyMgmtEngine(
            demand_window_seconds=10.0,
            active_power_kw=100.0,
        )
        for _ in range(10):
            engine.scan_step(dt=1.0)
        assert abs(engine.peak_demand_window_kw - 100.0) < 1e-3


# ============================================================================
# Section 6: Curtailment Trip (0xEC01, %M423) and Interlocks
# ============================================================================

class TestCurtailmentTripAndInterlocks:
    """Tests for sliding window peak demand curtailment trip and interlocks."""

    def test_normal_demand_below_threshold_healthy(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(
            reg_table=rt,
            peak_demand_threshold_kw=200.0,
            nominal_peak_demand_window_kw=150.0,
        )
        assert engine.is_curtailment_tripped is False
        assert rt.read_bit("%M423") is False
        assert rt.read_bit("%M422") is True
        assert rt.read_word("%R1816") == int(EnergyManagementState.OPERATIONAL)
        assert rt.read_uword("%R1817") == 0x0000

    def test_demand_breach_triggers_curtailment_trip_0xec01(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(
            reg_table=rt,
            peak_demand_threshold_kw=180.0,
            nominal_peak_demand_window_kw=150.0,
        )
        engine.set_peak_demand_window(195.0)  # > 180.0 kW
        assert engine.is_curtailment_tripped is True
        assert engine.diagnostic_code == CipEnergyMgmtDiagnosticCode.PEAK_DEMAND_LIMIT_EXCEEDED
        assert engine.state == EnergyManagementState.PEAK_DEMAND_CURTAILMENT

    def test_curtailment_asserts_coil_m423(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, peak_demand_threshold_kw=180.0)
        engine.set_peak_demand_window(185.0)
        assert rt.read_bit("%M423") is True

    def test_curtailment_deasserts_engine_active_m422(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, peak_demand_threshold_kw=180.0)
        engine.set_peak_demand_window(185.0)
        assert rt.read_bit("%M422") is False
        assert engine.is_engine_active is False

    def test_curtailment_trip_register_read_masked_status_code(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, peak_demand_threshold_kw=180.0)
        engine.set_peak_demand_window(190.0)
        # CRITICAL TEST: reg_table.read_word returns signed INT16; mask with & 0xFFFF
        raw_signed = rt.read_word("%R1817")
        masked_code = raw_signed & 0xFFFF
        assert masked_code == 0xEC01
        assert rt.read_uword("%R1817") == 0xEC01

    def test_curtailment_recovery_after_demand_reduction(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, peak_demand_threshold_kw=180.0)
        engine.set_peak_demand_window(190.0)
        assert engine.is_curtailment_tripped is True

        # Reduce demand and call reset
        engine.set_peak_demand_window(150.0)
        res = engine.reset_curtailment()
        assert res is True
        assert engine.is_curtailment_tripped is False
        assert rt.read_bit("%M423") is False
        assert rt.read_bit("%M422") is True
        assert rt.read_uword("%R1817") == 0x0000
        assert engine.state == EnergyManagementState.OPERATIONAL

    def test_curtailment_recovery_blocked_if_demand_high(self) -> None:
        engine = CipEnergyMgmtEngine(peak_demand_threshold_kw=180.0)
        engine.set_peak_demand_window(195.0)
        res = engine.reset_curtailment(force=False)
        assert res is False
        assert engine.is_curtailment_tripped is True

    def test_explicit_trip_curtailment_api(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.trip_curtailment("Manual demand trip command")
        assert engine.is_curtailment_tripped is True
        assert rt.read_bit("%M423") is True
        assert rt.read_uword("%R1817") == 0xEC01


# ============================================================================
# Section 7: Reverse Power Flow Trip (0xEC02)
# ============================================================================

class TestReversePowerFlowTrip:
    """Tests for reverse active power backfeed trip (0xEC02)."""

    def test_positive_active_power_no_reverse_trip(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, active_power_kw=100.0, reactive_power_kvar=20.0)
        assert engine.is_reverse_power_fault is False
        assert rt.read_uword("%R1817") == 0x0000
        assert rt.read_bit("%M422") is True

    def test_reverse_power_flow_triggers_0xec02(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.update_telemetry(active_kw=-10.0, reactive_kvar=5.0)
        assert engine.is_reverse_power_fault is True
        assert engine.diagnostic_code == CipEnergyMgmtDiagnosticCode.REVERSE_POWER_FLOW_FAULT
        assert rt.read_uword("%R1817") == 0xEC02

    def test_reverse_power_deasserts_engine_active_m422(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.update_telemetry(active_kw=-5.0, reactive_kvar=2.0)
        assert rt.read_bit("%M422") is False
        assert engine.is_engine_active is False

    def test_reverse_power_register_read_masked_status_code(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.update_telemetry(active_kw=-15.0, reactive_kvar=5.0)
        raw_signed = rt.read_word("%R1817")
        assert (raw_signed & 0xFFFF) == 0xEC02
        assert rt.read_uword("%R1817") == 0xEC02

    def test_reverse_power_recovery_on_reset_fault(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.update_telemetry(active_kw=-10.0, reactive_kvar=5.0)
        assert engine.is_reverse_power_fault is True

        # Restore positive power and reset
        engine.update_telemetry(active_kw=120.0, reactive_kvar=50.0)
        engine.reset_fault(force=True)
        assert engine.is_reverse_power_fault is False
        assert rt.read_uword("%R1817") == 0x0000
        assert rt.read_bit("%M422") is True

    def test_reverse_power_energy_accumulation_behavior(self) -> None:
        engine = CipEnergyMgmtEngine(active_power_kw=-50.0)
        engine.scan_step(dt=3600.0)  # 1 hour at -50 kW export
        assert engine.export_active_energy_kwh > 0.0
        assert engine.total_energy_kwh == 0.0  # Total import remains 0


# ============================================================================
# Section 8: Low Power Factor Penalty Warning (0xEC03) & THD (0xEC04)
# ============================================================================

class TestLowPowerFactorPenaltyWarning:
    """Tests for low power factor penalty warning (0xEC03) and harmonic distortion (0xEC04)."""

    def test_normal_power_factor_no_penalty(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, active_power_kw=145.0, reactive_power_kvar=62.0)
        assert engine.is_low_pf_warning is False
        assert rt.read_uword("%R1817") == 0x0000

    def test_low_power_factor_triggers_warning_0xec03(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        # Set active=60 kW, reactive=120 kvar -> PF = 60 / sqrt(3600 + 14400) = 60 / 134.16 = 0.447 < 0.85
        engine.update_telemetry(active_kw=60.0, reactive_kvar=120.0)
        assert engine.is_low_pf_warning is True
        assert engine.diagnostic_code == CipEnergyMgmtDiagnosticCode.POWER_FACTOR_BELOW_PENALTY_THRESHOLD

    def test_low_power_factor_register_read_masked_status_code(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.update_telemetry(active_kw=50.0, reactive_kvar=100.0)
        raw_signed = rt.read_word("%R1817")
        assert (raw_signed & 0xFFFF) == 0xEC03
        assert rt.read_uword("%R1817") == 0xEC03

    def test_low_power_factor_does_not_trip_curtailment(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.update_telemetry(active_kw=50.0, reactive_kvar=100.0)
        # Curtailment trip coil %M423 must remain FALSE during pure low PF warning
        assert rt.read_bit("%M423") is False
        assert engine.is_curtailment_tripped is False

    def test_low_power_factor_zero_power_no_penalty(self) -> None:
        engine = CipEnergyMgmtEngine()
        engine.update_telemetry(active_kw=0.0, reactive_kvar=0.0)
        assert engine.is_low_pf_warning is False

    def test_high_thd_triggers_warning_0xec04(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.update_telemetry(active_kw=145.0, reactive_kvar=62.0, current_thd_pct=9.2)
        assert engine.is_high_thd_warning is True
        assert engine.diagnostic_code == CipEnergyMgmtDiagnosticCode.CURRENT_HARMONIC_DISTORTION_HIGH
        assert (rt.read_word("%R1817") & 0xFFFF) == 0xEC04

    def test_reset_fault_clears_power_factor_and_thd_warnings(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.update_telemetry(active_kw=50.0, reactive_kvar=100.0)
        assert engine.is_low_pf_warning is True
        engine.reset_fault(force=True)
        assert engine.is_low_pf_warning is False
        assert rt.read_uword("%R1817") == 0x0000


# ============================================================================
# Section 9: Energy State Machine Transitions
# ============================================================================

class TestEnergyStateMachineTransitions:
    """Tests for Energy State Machine transitions and validations."""

    def test_initial_operational_state(self) -> None:
        engine = CipEnergyMgmtEngine()
        assert engine.state == EnergyManagementState.OPERATIONAL
        assert engine.is_engine_active is True

    def test_transition_operational_to_energy_saving(self) -> None:
        engine = CipEnergyMgmtEngine()
        res = engine.request_energy_state(EnergyManagementState.ENERGY_SAVING)
        assert res is True
        assert engine.state == EnergyManagementState.ENERGY_SAVING
        assert engine.cip_object.energy_state == EnergyManagementState.ENERGY_SAVING

    def test_transition_energy_saving_to_operational(self) -> None:
        engine = CipEnergyMgmtEngine()
        engine.request_energy_state(EnergyManagementState.ENERGY_SAVING)
        res = engine.request_energy_state(EnergyManagementState.OPERATIONAL)
        assert res is True
        assert engine.state == EnergyManagementState.OPERATIONAL

    def test_transition_operational_to_non_operational(self) -> None:
        engine = CipEnergyMgmtEngine()
        engine.set_energy_state(EnergyManagementState.NON_OPERATIONAL)
        assert engine.state == EnergyManagementState.NON_OPERATIONAL
        assert engine.is_engine_active is False

    def test_transition_non_operational_to_operational(self) -> None:
        engine = CipEnergyMgmtEngine()
        engine.set_energy_state(EnergyManagementState.NON_OPERATIONAL)
        engine.set_energy_state(EnergyManagementState.OPERATIONAL)
        assert engine.state == EnergyManagementState.OPERATIONAL
        assert engine.is_engine_active is True

    def test_curtailment_forces_state_to_curtailment_active(self) -> None:
        engine = CipEnergyMgmtEngine(peak_demand_threshold_kw=180.0)
        engine.set_peak_demand_window(190.0)
        assert engine.state == EnergyManagementState.PEAK_DEMAND_CURTAILMENT
        assert engine.state == EnergyManagementState.CURTAILMENT_ACTIVE

    def test_blocked_transition_during_curtailment_trip(self) -> None:
        engine = CipEnergyMgmtEngine(peak_demand_threshold_kw=180.0)
        engine.set_peak_demand_window(190.0)
        # Attempt to transition back to OPERATIONAL while trip is active must fail
        res = engine.request_energy_state(EnergyManagementState.OPERATIONAL)
        assert res is False
        assert engine.state == EnergyManagementState.PEAK_DEMAND_CURTAILMENT

    def test_blocked_transition_during_reverse_power_fault(self) -> None:
        engine = CipEnergyMgmtEngine()
        engine.update_telemetry(active_kw=-20.0, reactive_kvar=10.0)
        assert engine.is_reverse_power_fault is True
        res = engine.request_energy_state(EnergyManagementState.ENERGY_SAVING)
        assert res is False

    def test_full_state_cycle_progression(self) -> None:
        engine = CipEnergyMgmtEngine()
        # 0. Start NonOperational
        engine.set_energy_state(EnergyManagementState.NON_OPERATIONAL)
        assert engine.state == EnergyManagementState.NON_OPERATIONAL

        # 1. NonOperational -> Operational
        engine.set_energy_state(EnergyManagementState.OPERATIONAL)
        assert engine.state == EnergyManagementState.OPERATIONAL

        # 2. Operational -> EnergySaving
        engine.request_energy_state(EnergyManagementState.ENERGY_SAVING)
        assert engine.state == EnergyManagementState.ENERGY_SAVING

        # 3. EnergySaving -> CurtailmentActive
        engine.trip_curtailment()
        assert engine.state == EnergyManagementState.CURTAILMENT_ACTIVE


# ============================================================================
# Section 10: Horner OCS Register Table Synchronization
# ============================================================================

class TestHornerRegisterSynchronization:
    """Tests for Horner OCS memory map synchronization with PrivilegeMode.SYSTEM."""

    def test_register_synchronization_privilege_mode_system(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        # Verify writing occurs with PrivilegeMode.SYSTEM without raising PermissionError
        engine.sync_to_registers(privilege=PrivilegeMode.SYSTEM)

    def test_active_reactive_power_registers_r1810_r1811(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, active_power_kw=125.0, reactive_power_kvar=45.0)
        assert rt.read_word("%R1810") == 1250  # 125.0 kW * 10
        assert rt.read_word("%R1811") == 450   # 45.0 kvar * 10

    def test_power_factor_register_r1812(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, active_power_kw=145.0, reactive_power_kvar=62.0)
        # Power factor is ~91.95%, register scaled x10 -> 919 or 920
        pf_reg = rt.read_word("%R1812")
        assert pf_reg in (919, 920)

    def test_energy_counter_registers_r1813_r1814(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.total_energy_kwh = 100000.0  # 100,000 kWh = high: 1, low: -31072
        engine.sync_to_registers()
        h = rt.read_word("%R1813")
        l = rt.read_word("%R1814")
        assert h == 1
        assert l == -31072
        reconstructed = decode_dint_words(h, l)
        assert reconstructed == 100000

    def test_peak_demand_register_r1815(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, nominal_peak_demand_window_kw=182.0)
        assert rt.read_word("%R1815") == 1820  # 182.0 kW * 10

    def test_energy_state_register_r1816(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        assert rt.read_word("%R1816") == 1  # Operational
        engine.request_energy_state(EnergyManagementState.ENERGY_SAVING)
        assert rt.read_word("%R1816") == 2  # EnergySaving

    def test_diagnostic_status_register_r1817_masked(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        assert rt.read_word("%R1817") == 0x0000

        engine.trip_curtailment()
        # MUST mask with & 0xFFFF when comparing signed 16-bit status codes
        raw_code = rt.read_word("%R1817")
        assert (raw_code & 0xFFFF) == 0xEC01

    def test_discrete_coils_m422_and_m423(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        assert rt.read_bit("%M422") is True
        assert rt.read_bit("%M423") is False

        engine.trip_curtailment()
        assert rt.read_bit("%M422") is False
        assert rt.read_bit("%M423") is True

    def test_telemetry_snapshot_dataclass_fidelity(self) -> None:
        engine = CipEnergyMgmtEngine(active_power_kw=145.0, reactive_power_kvar=62.0)
        snap = engine.get_snapshot()
        assert isinstance(snap, CipEnergyMgmtSnapshot)
        assert snap.active_power_kw == 145.0
        assert snap.reactive_power_kvar == 62.0
        d = snap.to_dict()
        assert "active_power_kw" in d
        assert "power_quadrant" in d
        assert "energy_state" in d


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Simulation
# ============================================================================

class TestILogicUnitSimulation:
    """Tests for ILogicUnit interface, scan_step, ScanContext, and reset."""

    def test_ilogicunit_properties(self) -> None:
        engine = CipEnergyMgmtEngine()
        assert engine.name == "cip_energy_mgmt"
        assert engine.priority == 94
        assert engine.is_enabled is True

    def test_ilogicunit_execute_scan_context(self) -> None:
        engine = CipEnergyMgmtEngine(active_power_kw=100.0)
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        engine.execute(context=ctx)
        assert engine.total_scan_cycles == 1
        assert abs(engine.elapsed_simulation_s - 0.02) < 1e-4

    def test_ilogicunit_100_cycle_soak_energy_integration(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt, active_power_kw=145.0, reactive_power_kvar=62.0)
        for c in range(100):
            ctx = ScanContext(cycle=c, dt_ms=10.0, elapsed_time_ms=c * 10.0, dt=0.01)
            engine.execute(context=ctx)
        assert engine.total_scan_cycles == 100
        assert abs(engine.elapsed_simulation_s - 1.0) < 1e-6
        # Expected energy: 145 kW * 1s / 3600s = 0.0402778 kWh
        assert abs(engine.total_energy_kwh - 0.0402778) < 1e-4
        assert rt.read_word("%R1810") == 1450

    def test_ilogicunit_reset_restores_nominal_state(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.trip_curtailment()
        assert engine.is_curtailment_tripped is True
        assert rt.read_bit("%M423") is True

        engine.reset()
        assert engine.is_curtailment_tripped is False
        assert engine.state == EnergyManagementState.OPERATIONAL
        assert rt.read_bit("%M423") is False
        assert rt.read_bit("%M422") is True
        assert rt.read_uword("%R1817") == 0x0000

    def test_ilogicunit_is_enabled_toggle(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyMgmtEngine(reg_table=rt)
        engine.is_enabled = False
        assert engine.is_enabled is False
        assert engine.is_engine_active is False
        assert rt.read_bit("%M422") is False


# ============================================================================
# Section 12: Pure ST POU Validation & Anti-Ladder Security
# ============================================================================

class TestPureSTPOUAndSecurityGuard:
    """Tests for IEC 61131-3 Pure Structured Text parsing and ladder rejection."""

    def test_security_guard_assert_pure_st_content_passes(self) -> None:
        # Must pass without raising LadderForbiddenError
        SecurityGuard.assert_pure_st_content(CIP_ENERGY_SYNC_POU)

    def test_st_parser_validate_code_success(self) -> None:
        val = STParser.validate_code(CIP_ENERGY_SYNC_POU)
        assert val.status == AgentStatus.SUCCESS

    def test_st_parser_parse_pou_ast_and_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_ENERGY_SYNC_POU)
        assert ast.name == "CipEnergySync"
        expected_regs = {
            "%R1810", "%R1811", "%R1812", "%R1813",
            "%R1814", "%R1815", "%R1816", "%R1817",
            "%M422", "%M423",
        }
        bound = set(ast.bound_registers)
        assert expected_regs.issubset(bound)

    def test_anti_ladder_rejects_contact_construct(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\n---[ ]---\nEND_PROGRAM"
            )

    def test_anti_ladder_rejects_coil_construct(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\n---( )---\nEND_PROGRAM"
            )

    def test_anti_ladder_rejects_rung_delimiters(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\nRUNG 1\nEND_PROGRAM"
            )

    def test_anti_ladder_rejects_ladder_mnemonics(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\nXIC CurtailmentRelay\nEND_PROGRAM"
            )

    def test_verify_cip_energy_mgmt_pure_st_helper(self) -> None:
        assert verify_cip_energy_mgmt_pure_st() is True


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestVerificationRunner:
    """Tests for run_cip_energy_mgmt_verification execution and evidence export."""

    def test_verification_runner_executes_cleanly(self) -> None:
        report = run_cip_energy_mgmt_verification()
        assert isinstance(report, dict)
        assert report.get("status") in ("success", "failed", "blocked", "inconclusive")

    def test_verification_runner_returns_success_contract(self) -> None:
        report = run_cip_energy_mgmt_verification()
        assert report["status"] == "success"
        assert report["error_code"] is None
        assert "data" in report

    def test_verification_runner_passes_all_9_stages(self) -> None:
        report = run_cip_energy_mgmt_verification()
        stages = report["data"]["stages"]
        assert len(stages) == 9
        assert report["data"]["stages_passed"] == 9
        for s in stages:
            assert s["passed"] is True, f"Stage {s['stage']} failed: {s.get('details')}"

    def test_verification_runner_exports_json_evidence(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_energy_mgmt_evidence_test.json"
        report = run_cip_energy_mgmt_verification(output_path=out_file)
        assert out_file.exists()
        assert report["status"] == "success"

        with open(out_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["status"] == "success"
        assert loaded["data"]["total_stages"] == 9

    def test_verification_runner_json_evidence_integrity(self) -> None:
        default_evidence = Path("artifacts/telemetry/cip_energy_mgmt_evidence.json")
        if default_evidence.exists():
            with open(default_evidence, "r", encoding="utf-8") as f:
                evidence = json.load(f)
            assert evidence["status"] == "success"
            assert len(evidence["data"]["stages"]) == 9
