"""Comprehensive Unit and Integration Test Suite for Industrial EtherNet/IP CIP Energy Protocol Engine.

Work Package: W190 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (59 Unit Tests across 12 Sections):
1. Section 1: Enums & Constants (CipEnergyState, CipEnergyPowerType, CipEnergyDiagnosticCode, Protocol Constants).
2. Section 2: Telemetry Snapshot Dataclass (CipEnergySnapshot fields, defaults, serialization).
3. Section 3: 3-Phase Power Triangle Mathematics (S = sqrt(P^2 + Q^2), PF = P / S, 3-phase line formulas).
4. Section 4: Total Harmonic Distortion (THD) & IEEE 519 Thresholds (Warning >5.0%, Trip >8.0%).
5. Section 5: High-Precision Active Energy Integration (kWh accumulation over discrete dt steps).
6. Section 6: Peak Demand Detection & State Machine Transitions (Operational -> EnergySaving, Standby).
7. Section 7: ODVA CIP Energy Object (Class 0x4E / Class 0x4F attribute resolution, sets, alarms).
8. Section 8: Pure IEC 61131-3 ST POU & SecurityGuard (STParser AST binding, anti-ladder rejection).
9. Section 9: Horner OCS Register Table Synchronization (%R1510..%R1517, %M352..%M353 with PrivilegeMode.SYSTEM).
10. Section 10: ILogicUnit 100-Cycle Simulation (scan_step, execute, priority, reset).
11. Section 11: Process Safety Interlocks & Fault Scenarios (0xD101..0xD104 trips and reset recovery).
12. Section 12: Deterministic 9-Stage Verification Runner (run_cip_energy_verification returns status == 'success').
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_energy import (
    CIP_ENERGY_BASE_CLASS_ID,
    CIP_ENERGY_CLASS_ID,
    CIP_ENERGY_MANAGEMENT_SYNC_POU,
    CIP_ENERGY_POU,
    DEFAULT_ENERGY_BASELINE_KW,
    DEFAULT_PEAK_DEMAND_THRESHOLD_KW,
    IEEE519_THD_TRIP_THRESHOLD_PCT,
    IEEE519_THD_WARNING_THRESHOLD_PCT,
    NOMINAL_LINE_VOLTAGE_RMS,
    NOMINAL_SYSTEM_FREQUENCY_HZ,
    PHASE_IMBALANCE_LIMIT_PCT,
    POWER_FACTOR_ALARM_THRESHOLD,
    REVERSE_POWER_TRIP_THRESHOLD_KW,
    VOLTAGE_SAG_THRESHOLD_VOLTS,
    VOLTAGE_SWELL_THRESHOLD_VOLTS,
    CipEnergyDiagnosticCode,
    CipEnergyEngine,
    CipEnergyManagementSyncPOU,
    CipEnergyObject,
    CipEnergyPowerType,
    CipEnergySnapshot,
    CipEnergyState,
    calculate_3phase_power,
    calculate_power_triangle,
    calculate_thd,
    decode_dint_words,
    encode_dint_words,
    run_cip_energy_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
)


# ============================================================================
# Section 1: Enums & Constants
# ============================================================================

class TestCipEnergyEnumsAndConstants:
    """Tests for protocol enumeration types, status codes, and threshold constants."""

    def test_cip_energy_state_values_and_aliases(self) -> None:
        assert CipEnergyState.NON_OPERATIONAL == 0
        assert CipEnergyState.OPERATIONAL == 1
        assert CipEnergyState.STANDBY == 2
        assert CipEnergyState.ENERGY_SAVING == 3
        assert CipEnergyState.SLEEP == 4
        assert CipEnergyState.FAULTED == 5

        # Compatibility aliases
        assert CipEnergyState.NonOperational == 0
        assert CipEnergyState.Operational == 1
        assert CipEnergyState.Normal == 1
        assert CipEnergyState.NORMAL == 1
        assert CipEnergyState.Standby == 2
        assert CipEnergyState.EnergySaving == 3
        assert CipEnergyState.Sleep == 4
        assert CipEnergyState.Faulted == 5

    def test_cip_energy_power_type_values_and_aliases(self) -> None:
        assert CipEnergyPowerType.ACTIVE == 1
        assert CipEnergyPowerType.REACTIVE == 2
        assert CipEnergyPowerType.APPARENT == 3

        # Aliases
        assert CipEnergyPowerType.Active == 1
        assert CipEnergyPowerType.Real == 1
        assert CipEnergyPowerType.Reactive == 2
        assert CipEnergyPowerType.Apparent == 3

    def test_cip_energy_diagnostic_code_values_and_aliases(self) -> None:
        assert CipEnergyDiagnosticCode.OK == 0x0000
        assert CipEnergyDiagnosticCode.VOLTAGE_SAG_SWELL == 0xD101
        assert CipEnergyDiagnosticCode.THD_LIMIT_EXCEEDED == 0xD102
        assert CipEnergyDiagnosticCode.REVERSE_POWER_TRIP == 0xD103
        assert CipEnergyDiagnosticCode.PHASE_IMBALANCE == 0xD104

        # Aliases
        assert CipEnergyDiagnosticCode.ERR_VOLTAGE_SAG_SWELL == 0xD101
        assert CipEnergyDiagnosticCode.ERR_THD_LIMIT_EXCEEDED == 0xD102
        assert CipEnergyDiagnosticCode.ERR_REVERSE_POWER_TRIP == 0xD103
        assert CipEnergyDiagnosticCode.ERR_PHASE_IMBALANCE == 0xD104
        assert CipEnergyDiagnosticCode.CIP_ENERGY_ERR_VOLTAGE_SAG_SWELL == 0xD101
        assert CipEnergyDiagnosticCode.VoltageSagSwell == 0xD101
        assert CipEnergyDiagnosticCode.ThdLimitExceeded == 0xD102
        assert CipEnergyDiagnosticCode.ReversePowerTrip == 0xD103
        assert CipEnergyDiagnosticCode.PhaseImbalance == 0xD104

    def test_cip_energy_constants_and_thresholds(self) -> None:
        assert CIP_ENERGY_CLASS_ID == 0x4E
        assert CIP_ENERGY_BASE_CLASS_ID == 0x4F
        assert NOMINAL_LINE_VOLTAGE_RMS == 480.0
        assert NOMINAL_SYSTEM_FREQUENCY_HZ == 60.0
        assert DEFAULT_PEAK_DEMAND_THRESHOLD_KW == 150.0
        assert DEFAULT_ENERGY_BASELINE_KW == 50.0
        assert POWER_FACTOR_ALARM_THRESHOLD == 0.85
        assert IEEE519_THD_WARNING_THRESHOLD_PCT == 5.0
        assert IEEE519_THD_TRIP_THRESHOLD_PCT == 8.0
        assert VOLTAGE_SAG_THRESHOLD_VOLTS == 432.0
        assert VOLTAGE_SWELL_THRESHOLD_VOLTS == 528.0
        assert REVERSE_POWER_TRIP_THRESHOLD_KW == -0.1
        assert PHASE_IMBALANCE_LIMIT_PCT == 3.0


# ============================================================================
# Section 2: Telemetry Snapshot Dataclass
# ============================================================================

class TestCipEnergySnapshotDataclass:
    """Tests for the instantaneous telemetry snapshot representation."""

    def test_snapshot_default_instantiation(self) -> None:
        snap = CipEnergySnapshot()
        assert snap.active_kw == 0.0
        assert snap.reactive_kvar == 0.0
        assert snap.apparent_kva == 0.0
        assert snap.pf == 1.0
        assert snap.energy_kwh == 0.0
        assert snap.thd_pct == 0.0
        assert snap.energy_state == CipEnergyState.OPERATIONAL
        assert snap.diagnostic_code == CipEnergyDiagnosticCode.OK
        assert snap.voltage_rms == 480.0
        assert snap.frequency_hz == 60.0
        assert snap.metering_healthy is True
        assert snap.peak_demand_tripped is False
        assert snap.power_factor_alarm is False
        assert snap.thd_warning is False

    def test_snapshot_to_dict_serialization(self) -> None:
        snap = CipEnergySnapshot(
            active_kw=125.4567,
            reactive_kvar=45.1234,
            apparent_kva=133.321,
            pf=0.9412,
            energy_kwh=12345.6789,
            thd_pct=3.21,
            energy_state=CipEnergyState.ENERGY_SAVING,
            diagnostic_code=CipEnergyDiagnosticCode.OK,
            voltage_rms=480.25,
            current_rms=160.5,
            frequency_hz=59.98,
            timestamp_s=12.5,
            peak_demand_tripped=True,
            metering_healthy=False,
            power_factor_alarm=False,
            thd_warning=False,
        )
        d = snap.to_dict()
        assert d["active_kw"] == 125.457
        assert d["reactive_kvar"] == 45.123
        assert d["apparent_kva"] == 133.321
        assert d["pf"] == 0.9412
        assert d["energy_kwh"] == 12345.6789
        assert d["thd_pct"] == 3.21
        assert d["energy_state"] == "ENERGY_SAVING"
        assert d["diagnostic_code"] == "0x0"
        assert d["voltage_rms"] == 480.25
        assert d["current_rms"] == 160.5
        assert d["frequency_hz"] == 59.98
        assert d["timestamp_s"] == 12.5
        assert d["peak_demand_tripped"] is True
        assert d["metering_healthy"] is False


# ============================================================================
# Section 3: 3-Phase Power Triangle Mathematics
# ============================================================================

class TestPowerTriangleMathematics:
    """Tests for S = sqrt(P^2 + Q^2), PF = P / S, and 3-phase line calculations."""

    def test_power_triangle_zero_power(self) -> None:
        s, pf = calculate_power_triangle(0.0, 0.0)
        assert s == 0.0
        assert pf == 1.0

    def test_power_triangle_pure_active_load(self) -> None:
        s, pf = calculate_power_triangle(100.0, 0.0)
        assert s == 100.0
        assert pf == 1.0

    def test_power_triangle_pure_reactive_load(self) -> None:
        s, pf = calculate_power_triangle(0.0, 100.0)
        assert s == 100.0
        assert pf == 0.0

    def test_power_triangle_canonical_3_4_5_triangle(self) -> None:
        # P = 300 kW, Q = 400 kVAR -> S = 500 kVA, PF = 0.6
        s, pf = calculate_power_triangle(300.0, 400.0)
        assert pytest.approx(s, rel=1e-6) == 500.0
        assert pytest.approx(pf, rel=1e-6) == 0.6

    def test_power_triangle_odva_w190_standard_point(self) -> None:
        # P = 125.0 kW, Q = 45.0 kVAR
        s, pf = calculate_power_triangle(125.0, 45.0)
        expected_s = math.sqrt(125.0**2 + 45.0**2)  # sqrt(17650) ~ 132.8533
        expected_pf = 125.0 / expected_s            # ~ 0.940887
        assert pytest.approx(s, rel=1e-6) == expected_s
        assert pytest.approx(pf, rel=1e-6) == expected_pf

    def test_power_triangle_negative_active_power(self) -> None:
        # P = -50.0 kW (generator reverse power), Q = 0.0
        s, pf = calculate_power_triangle(-50.0, 0.0)
        assert s == 50.0
        assert pf == -1.0

    def test_power_triangle_power_factor_clamping(self) -> None:
        # Numerical limits: pf clamped to [-1.0, 1.0]
        s, pf = calculate_power_triangle(100.0, 1e-12)
        assert -1.0 <= pf <= 1.0

    def test_3phase_power_balanced_rms_calculation(self) -> None:
        # 480 V line-to-line, 160 A line current, PF = 0.941
        p, q, s = calculate_3phase_power(480.0, 160.0, pf=0.941)
        expected_s = (math.sqrt(3.0) * 480.0 * 160.0) / 1000.0  # 133.0207 kVA
        expected_p = expected_s * 0.941                          # 125.1725 kW
        expected_q = math.sqrt(expected_s**2 - expected_p**2)    # 45.0069 kVAR
        assert pytest.approx(s, rel=1e-5) == expected_s
        assert pytest.approx(p, rel=1e-5) == expected_p
        assert pytest.approx(q, rel=1e-5) == expected_q

    def test_3phase_power_zero_current_or_voltage(self) -> None:
        p, q, s = calculate_3phase_power(0.0, 100.0, pf=0.9)
        assert p == 0.0 and q == 0.0 and s == 0.0

        p2, q2, s2 = calculate_3phase_power(480.0, 0.0, pf=0.9)
        assert p2 == 0.0 and q2 == 0.0 and s2 == 0.0


# ============================================================================
# Section 4: Total Harmonic Distortion (THD) & IEEE 519 Thresholds
# ============================================================================

class TestTotalHarmonicDistortionIEEE519:
    """Tests for THD calculation and IEEE 519 harmonic limits."""

    def test_thd_pure_sine_wave_zero_harmonics(self) -> None:
        thd = calculate_thd(480.0, [])
        assert thd == 0.0

        thd_zeros = calculate_thd(480.0, [0.0, 0.0, 0.0])
        assert thd_zeros == 0.0

    def test_thd_zero_fundamental_edge_case(self) -> None:
        thd = calculate_thd(0.0, [10.0, 5.0])
        assert thd == 0.0

    def test_thd_known_harmonic_components(self) -> None:
        # V1 = 480.0 V, V3 = 9.6 V, V5 = 12.0 V
        # Harmonic RSS = sqrt(9.6^2 + 12^2) = sqrt(92.16 + 144) = sqrt(236.16) ~ 15.3675 V
        # THD = (15.3675 / 480) * 100 = 3.20156 %
        thd = calculate_thd(480.0, [9.6, 12.0])
        assert pytest.approx(thd, rel=1e-4) == 3.20156

    def test_ieee519_normal_harmonic_level_healthy(self) -> None:
        engine = CipEnergyEngine()
        thd = engine.set_harmonic_spectrum(480.0, [9.6, 12.0])
        assert thd < IEEE519_THD_WARNING_THRESHOLD_PCT  # 3.2% < 5.0%
        assert engine.thd_warning_active is False
        assert engine.is_thd_tripped is False
        assert engine.diagnostic_code == CipEnergyDiagnosticCode.OK
        assert engine.is_metering_healthy is True

    def test_ieee519_warning_threshold_assertion(self) -> None:
        engine = CipEnergyEngine()
        # V3 = 20.0 V, V5 = 20.0 V -> RSS = 28.284 V -> THD = 5.89% (> 5.0% warning, < 8.0% trip)
        thd = engine.set_harmonic_spectrum(480.0, [20.0, 20.0])
        assert 5.0 < thd < 8.0
        assert engine.thd_warning_active is True
        assert engine.is_thd_tripped is False
        assert engine.diagnostic_code == CipEnergyDiagnosticCode.OK
        # Metering healthy deasserts on THD warning per safety rules
        assert engine.is_metering_healthy is False

    def test_ieee519_trip_threshold_exceeded(self) -> None:
        engine = CipEnergyEngine()
        # V3 = 30.0 V, V5 = 35.0 V -> RSS = 46.0977 V -> THD = 9.60% (> 8.0% trip)
        thd = engine.set_harmonic_spectrum(480.0, [30.0, 35.0])
        assert thd > IEEE519_THD_TRIP_THRESHOLD_PCT
        assert engine.is_thd_tripped is True
        assert engine.is_peak_demand_tripped is True
        assert engine.diagnostic_code == CipEnergyDiagnosticCode.THD_LIMIT_EXCEEDED
        assert engine.state == CipEnergyState.FAULTED
        assert engine.is_metering_healthy is False


# ============================================================================
# Section 5: High-Precision Active Energy Integration
# ============================================================================

class TestActiveEnergyIntegration:
    """Tests for discrete-time active energy accumulation (kWh = P * dt / 3600)."""

    def test_energy_accumulation_single_step(self) -> None:
        engine = CipEnergyEngine()
        engine.active_power_kw = 120.0
        engine.scan_step(dt=10.0)  # 10 seconds
        expected_kwh = 120.0 * (10.0 / 3600.0)  # 0.333333 kWh
        assert pytest.approx(engine.energy_accumulation_kwh, rel=1e-9) == expected_kwh

    def test_energy_accumulation_full_hour_120kw(self) -> None:
        engine = CipEnergyEngine()
        engine.active_power_kw = 120.0
        # 360 steps of 10s = 3600s (1 hour)
        for _ in range(360):
            engine.scan_step(dt=10.0)
        assert pytest.approx(engine.energy_accumulation_kwh, rel=1e-6) == 120.0

    def test_energy_accumulation_two_stage_power_profile(self) -> None:
        engine = CipEnergyEngine()
        # Stage 1: 50 kW for 1800s (0.5h) -> 25.0 kWh
        engine.active_power_kw = 50.0
        for _ in range(180):
            engine.scan_step(dt=10.0)
        assert pytest.approx(engine.energy_accumulation_kwh, rel=1e-6) == 25.0

        # Stage 2: 100 kW for 1800s (0.5h) -> +50.0 kWh -> total 75.0 kWh
        engine.active_power_kw = 100.0
        for _ in range(180):
            engine.scan_step(dt=10.0)
        assert pytest.approx(engine.energy_accumulation_kwh, rel=1e-6) == 75.0

    def test_energy_accumulation_zero_power_constant(self) -> None:
        engine = CipEnergyEngine()
        engine.active_power_kw = 0.0
        for _ in range(100):
            engine.scan_step(dt=0.1)
        assert engine.energy_accumulation_kwh == 0.0

    def test_energy_accumulation_halted_during_reverse_power_trip(self) -> None:
        engine = CipEnergyEngine()
        engine.energy_accumulation_kwh = 100.0
        engine.simulate_reverse_power_trip(-5.0)
        assert engine.diagnostic_code == CipEnergyDiagnosticCode.REVERSE_POWER_TRIP

        # Scans while faulted in reverse power should not accumulate negative energy
        engine.scan_step(dt=10.0)
        assert engine.energy_accumulation_kwh == 100.0


# ============================================================================
# Section 6: Peak Demand Detection & State Machine Transitions
# ============================================================================

class TestPeakDemandAndEnergySavingStateMachine:
    """Tests for peak demand thresholds, demand-shedding state transitions, and state management."""

    def test_peak_demand_threshold_detection(self) -> None:
        engine = CipEnergyEngine(peak_demand_threshold_kw=150.0)
        engine.update_telemetry(active_kw=145.0, reactive_kvar=40.0)
        assert engine.is_peak_demand_tripped is False
        assert engine.state == CipEnergyState.OPERATIONAL

        # Exceed threshold
        engine.update_telemetry(active_kw=155.0, reactive_kvar=45.0)
        assert engine.is_peak_demand_tripped is True
        assert engine.state == CipEnergyState.ENERGY_SAVING

    def test_peak_demand_state_transition_only_from_operational(self) -> None:
        engine = CipEnergyEngine(peak_demand_threshold_kw=100.0)
        engine.state = CipEnergyState.STANDBY
        engine.update_telemetry(active_kw=110.0, reactive_kvar=30.0)
        assert engine.is_peak_demand_tripped is True
        # Did not transition from STANDBY
        assert engine.state == CipEnergyState.STANDBY

    def test_manual_energy_state_transitions(self) -> None:
        engine = CipEnergyEngine()
        assert engine.state == CipEnergyState.OPERATIONAL

        # Transition to STANDBY
        ok = engine.request_energy_state(CipEnergyState.STANDBY)
        assert ok is True
        assert engine.state == CipEnergyState.STANDBY

        # Transition to ENERGY_SAVING
        ok = engine.request_energy_state(CipEnergyState.ENERGY_SAVING)
        assert ok is True
        assert engine.state == CipEnergyState.ENERGY_SAVING

        # Transition to SLEEP
        ok = engine.request_energy_state(CipEnergyState.SLEEP)
        assert ok is True
        assert engine.state == CipEnergyState.SLEEP

        # Return to OPERATIONAL
        ok = engine.request_energy_state(CipEnergyState.OPERATIONAL)
        assert ok is True
        assert engine.state == CipEnergyState.OPERATIONAL

    def test_energy_state_transition_blocked_when_faulted(self) -> None:
        engine = CipEnergyEngine()
        engine.simulate_voltage_sag_swell(380.0)
        assert engine.state == CipEnergyState.FAULTED

        # Cannot manually transition while faulted
        ok = engine.request_energy_state(CipEnergyState.OPERATIONAL)
        assert ok is False
        assert engine.state == CipEnergyState.FAULTED


# ============================================================================
# Section 7: ODVA CIP Energy Object (Class 0x4E / Class 0x4F)
# ============================================================================

class TestCipEnergyObjectOdvaAttributes:
    """Tests for ODVA CIP Class 0x4E and Class 0x4F attribute dictionaries and accessors."""

    def test_cip_object_get_attribute_single_class_4e(self) -> None:
        obj = CipEnergyObject(
            energy_type=1,
            active_energy_kwh=123.4,
            apparent_energy_kvah=130.0,
            reactive_energy_kvarh=40.0,
            active_power_kw=100.0,
            reactive_power_kvar=35.0,
            apparent_power_kva=105.9,
            power_factor=0.944,
            voltage_rms=480.0,
            current_rms=127.4,
            thd_pct=2.8,
            peak_demand_kw=110.0,
            peak_demand_threshold_kw=150.0,
            energy_baseline_kw=50.0,
            power_factor_alarm=False,
            diagnostic_code=CipEnergyDiagnosticCode.OK,
        )
        assert obj.get_attribute_single(1, CIP_ENERGY_CLASS_ID) == 1
        assert obj.get_attribute_single(2, CIP_ENERGY_CLASS_ID) == 123.4
        assert obj.get_attribute_single(3, CIP_ENERGY_CLASS_ID) == 130.0
        assert obj.get_attribute_single(4, CIP_ENERGY_CLASS_ID) == 40.0
        assert obj.get_attribute_single(5, CIP_ENERGY_CLASS_ID) == 100.0
        assert obj.get_attribute_single(6, CIP_ENERGY_CLASS_ID) == 35.0
        assert obj.get_attribute_single(7, CIP_ENERGY_CLASS_ID) == 105.9
        assert obj.get_attribute_single(8, CIP_ENERGY_CLASS_ID) == 0.944
        assert obj.get_attribute_single(9, CIP_ENERGY_CLASS_ID) == 480.0
        assert obj.get_attribute_single(10, CIP_ENERGY_CLASS_ID) == 127.4
        assert obj.get_attribute_single(11, CIP_ENERGY_CLASS_ID) == 2.8
        assert obj.get_attribute_single(12, CIP_ENERGY_CLASS_ID) == 110.0
        assert obj.get_attribute_single(13, CIP_ENERGY_CLASS_ID) == 150.0
        assert obj.get_attribute_single(14, CIP_ENERGY_CLASS_ID) == 50.0
        assert obj.get_attribute_single(15, CIP_ENERGY_CLASS_ID) is False
        assert obj.get_attribute_single(16, CIP_ENERGY_CLASS_ID) == 0x0000

    def test_cip_object_get_attribute_single_class_4f(self) -> None:
        obj = CipEnergyObject(
            energy_state=CipEnergyState.OPERATIONAL,
            supported_energy_states=0x3F,
            requested_energy_state=CipEnergyState.STANDBY,
            time_to_transition_ms=500,
            active_energy_kwh=999.0,
            accuracy_class=0.2,
        )
        assert obj.get_attribute_single(1, CIP_ENERGY_BASE_CLASS_ID) == 1
        assert obj.get_attribute_single(2, CIP_ENERGY_BASE_CLASS_ID) == 0x3F
        assert obj.get_attribute_single(3, CIP_ENERGY_BASE_CLASS_ID) == 2
        assert obj.get_attribute_single(4, CIP_ENERGY_BASE_CLASS_ID) == 500
        assert obj.get_attribute_single(5, CIP_ENERGY_BASE_CLASS_ID) == 999.0
        assert obj.get_attribute_single(6, CIP_ENERGY_BASE_CLASS_ID) == 0.2

    def test_cip_object_set_attribute_single_valid(self) -> None:
        obj = CipEnergyObject()
        # Set Class 0x4E peak demand threshold (attr 13)
        res = obj.set_attribute_single(13, 250.0, CIP_ENERGY_CLASS_ID)
        assert res is True
        assert obj.peak_demand_threshold_kw == 250.0

        # Set Class 0x4E baseline kw (attr 14)
        res = obj.set_attribute_single(14, 75.0, CIP_ENERGY_CLASS_ID)
        assert res is True
        assert obj.energy_baseline_kw == 75.0

        # Set Class 0x4F requested energy state (attr 3)
        res = obj.set_attribute_single(3, int(CipEnergyState.STANDBY), CIP_ENERGY_BASE_CLASS_ID)
        assert res is True
        assert obj.energy_state == CipEnergyState.STANDBY

    def test_cip_object_set_attribute_single_read_only_rejection(self) -> None:
        obj = CipEnergyObject()
        with pytest.raises(PermissionError, match="read-only"):
            obj.set_attribute_single(5, 500.0, CIP_ENERGY_CLASS_ID)  # Active power is read-only

        with pytest.raises(PermissionError, match="read-only"):
            obj.set_attribute_single(1, 0, CIP_ENERGY_BASE_CLASS_ID)  # State is read-only directly

    def test_cip_object_get_attribute_invalid_id_raises_key_error(self) -> None:
        obj = CipEnergyObject()
        with pytest.raises(KeyError, match="does not support Attribute ID 99"):
            obj.get_attribute_single(99, CIP_ENERGY_CLASS_ID)

    def test_cip_object_get_attribute_invalid_class_raises_value_error(self) -> None:
        obj = CipEnergyObject()
        with pytest.raises(ValueError, match="Unsupported CIP Energy Class ID"):
            obj.get_attribute_single(1, 0x99)

    def test_cip_object_get_attribute_all(self) -> None:
        obj = CipEnergyObject()
        d_4e = obj.get_attribute_all(CIP_ENERGY_CLASS_ID)
        assert len(d_4e) == 16
        assert d_4e[1] == 1  # Electrical

        d_4f = obj.get_attribute_all(CIP_ENERGY_BASE_CLASS_ID)
        assert len(d_4f) == 6
        assert d_4f[2] == 0x3F

    def test_cip_object_power_factor_alarm_evaluation(self) -> None:
        obj = CipEnergyObject(apparent_power_kva=50.0, power_factor=0.95)
        obj.evaluate_alarms()
        assert obj.power_factor_alarm is False

        # Drop PF below 0.85
        obj.power_factor = 0.79
        obj.evaluate_alarms()
        assert obj.power_factor_alarm is True

        # When apparent power is tiny (< 1.0 kVA), PF alarm is suppressed
        obj.apparent_power_kva = 0.5
        obj.evaluate_alarms()
        assert obj.power_factor_alarm is False


# ============================================================================
# Section 8: Pure IEC 61131-3 ST POU & SecurityGuard
# ============================================================================

class TestStructuredTextPouAndSecurityGuard:
    """Tests for POU 'CipEnergyManagementSync' syntax, AST bindings, and ladder rejection."""

    def test_cip_energy_pou_syntax_validation(self) -> None:
        res = STParser.validate_code(CIP_ENERGY_MANAGEMENT_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS
        assert CIP_ENERGY_POU == CIP_ENERGY_MANAGEMENT_SYNC_POU
        assert CipEnergyManagementSyncPOU == CIP_ENERGY_MANAGEMENT_SYNC_POU

    def test_cip_energy_pou_ast_registers_binding(self) -> None:
        ast_pou = STParser.parse_pou(CIP_ENERGY_MANAGEMENT_SYNC_POU)
        assert ast_pou.name == "CipEnergyManagementSync"

        expected_regs = {
            "%R1510", "%R1511", "%R1512", "%R1513",
            "%R1514", "%R1515", "%R1516", "%R1517",
            "%M352", "%M353",
        }
        bound_regs = set(ast_pou.bound_registers)
        assert expected_regs.issubset(bound_regs)

    def test_cip_energy_pou_pure_st_security_guard(self) -> None:
        # Must pass assert_pure_st_content cleanly
        SecurityGuard.assert_pure_st_content(CIP_ENERGY_MANAGEMENT_SYNC_POU)

    def test_ladder_logic_interception_contacts(self) -> None:
        bad_ladder = """PROGRAM BadContacts
VAR RunCmd : BOOL; END_VAR
---[ ]--- RunCmd
END_PROGRAM"""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_ladder)

        res = STParser.validate_code(bad_ladder)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_logic_interception_coils(self) -> None:
        bad_coil = """PROGRAM BadCoils
VAR MtrCoil : BOOL; END_VAR
---( )--- MtrCoil
END_PROGRAM"""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_coil)

    def test_ladder_logic_interception_rung_delimiters_and_mnemonics(self) -> None:
        for bad_construct in ["RUNG 1", "NETWORK 5", "XIC BitStart", "OTE SolenoidCoil"]:
            st_snippet = f"PROGRAM BadMnemonic\nVAR B : BOOL; END_VAR\n{bad_construct}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(st_snippet)


# ============================================================================
# Section 9: Horner OCS Register Table Synchronization
# ============================================================================

class TestHornerRegisterTableSynchronization:
    """Tests for Horner OCS memory map (%R1510..%R1517, %M352..%M353) updates."""

    def test_register_encoding_and_decoding_dint_roundtrip(self) -> None:
        test_values = [0, 1, 1000, 32767, 32768, 65535, 65536, 1_000_000, -1, -50000]
        for val in test_values:
            high, low = encode_dint_words(val)
            reconstructed = decode_dint_words(high, low)
            assert reconstructed == val

    def test_register_sync_nominal_telemetry_values(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)

        engine.active_power_kw = 125.0
        engine.reactive_power_kvar = 45.0
        engine.apparent_power_kva = 132.8
        engine.power_factor = 0.941
        engine.energy_accumulation_kwh = 50000.0
        engine.thd_pct = 3.2
        engine.diagnostic_code = CipEnergyDiagnosticCode.OK
        engine.is_metering_healthy = True
        engine.is_peak_demand_tripped = False

        engine.sync_to_registers()

        assert rt.read_word("%R1510") == 1250    # 125.0 kW * 10
        assert rt.read_word("%R1511") == 450     # 45.0 kVAR * 10
        assert rt.read_word("%R1512") == 1328    # 132.8 kVA * 10
        assert rt.read_word("%R1513") == 941     # 0.941 * 1000
        assert rt.read_word("%R1516") == 32      # 3.2 % * 10
        assert rt.read_uword("%R1517") == 0x0000 # OK
        assert rt.read_bit("%M352") is True      # Healthy
        assert rt.read_bit("%M353") is False     # Not tripped

        # Verify 32-bit energy decoding
        h = rt.read_word("%R1514")
        l = rt.read_word("%R1515")
        assert decode_dint_words(h, l) == 50000

    def test_register_sync_uses_privilege_mode_system(self) -> None:
        rt = RegisterTable()
        # safe_write functions enforce PrivilegeMode.SYSTEM
        safe_write_word(rt, "%R1510", 1234)
        assert rt.read_word("%R1510") == 1234

        safe_write_uword(rt, "%R1517", 0xD101)
        assert rt.read_uword("%R1517") == 0xD101

        safe_write_bit(rt, "%M352", True)
        assert rt.read_bit("%M352") is True

    def test_register_sync_clamping_behavior(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)

        # Extremely high active power exceeds 3276.7 kW
        engine.active_power_kw = 5000.0
        engine.power_factor = 1.5  # invalid > 1.0
        engine.sync_to_registers()

        assert rt.read_word("%R1510") == 32767
        assert rt.read_word("%R1513") == 1000


# ============================================================================
# Section 10: ILogicUnit 100-Cycle Simulation
# ============================================================================

class TestILogicUnitScanCycleExecution:
    """Tests for ILogicUnit interface compliance and scan cycle simulation."""

    def test_ilogic_unit_contract_properties(self) -> None:
        engine = CipEnergyEngine()
        assert engine.name == "cip_energy"
        assert engine.priority == 93
        assert engine.is_enabled is True

    def test_execute_via_scan_context(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.active_power_kw = 50.0

        ctx = ScanContext(
            cycle=1,
            dt_ms=20.0,
            elapsed_time_ms=20.0,
            get_register=rt.read_register,
            set_register=rt.write_register,
            get_variable=lambda name, default=None: default,
            set_variable=lambda name, val: None,
            record_fault=lambda fault: None,
        )
        engine.execute(ctx)

        assert engine.total_scan_cycles == 1
        assert pytest.approx(engine.elapsed_simulation_ms, abs=1e-4) == 20.0
        assert engine.energy_accumulation_kwh > 0.0

    def test_100_scan_steps_continuous_run(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.update_telemetry(active_kw=100.0, reactive_kvar=30.0)

        initial_energy = engine.energy_accumulation_kwh
        for _ in range(100):
            engine.scan_step(dt=0.01)  # 10ms discrete scan

        final_energy = engine.energy_accumulation_kwh
        expected_inc = 100.0 * (1.0 / 3600.0)  # 100 * 0.01s = 1.0s elapsed

        assert engine.total_scan_cycles == 100
        assert pytest.approx(engine.elapsed_simulation_ms, abs=1e-4) == 1000.0
        assert pytest.approx(final_energy - initial_energy, abs=1e-6) == expected_inc
        assert rt.read_word("%R1510") == 1000

    def test_engine_reset_clears_faults_and_restores_health(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.simulate_voltage_sag_swell(350.0)
        assert engine.diagnostic_code == CipEnergyDiagnosticCode.VOLTAGE_SAG_SWELL
        assert engine.is_metering_healthy is False

        engine.reset()
        assert engine.diagnostic_code == CipEnergyDiagnosticCode.OK
        assert engine.is_metering_healthy is True
        assert engine.state == CipEnergyState.OPERATIONAL
        assert rt.read_uword("%R1517") == 0x0000
        assert rt.read_bit("%M352") is True


# ============================================================================
# Section 11: Process Safety Interlocks & Fault Scenarios
# ============================================================================

class TestProcessSafetyFaultScenarios:
    """Tests for fault trips (0xD101..0xD104), register interlocking, and recovery."""

    def test_fault_voltage_sag_trip(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.simulate_voltage_sag_swell(400.0)  # < 432V sag

        assert engine.diagnostic_code == CipEnergyDiagnosticCode.VOLTAGE_SAG_SWELL
        assert engine.state == CipEnergyState.FAULTED
        assert engine.is_metering_healthy is False
        assert rt.read_uword("%R1517") == 0xD101
        assert rt.read_bit("%M352") is False

    def test_fault_voltage_swell_trip(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.simulate_voltage_sag_swell(540.0)  # > 528V swell

        assert engine.diagnostic_code == CipEnergyDiagnosticCode.VOLTAGE_SAG_SWELL
        assert engine.state == CipEnergyState.FAULTED
        assert engine.is_metering_healthy is False
        assert rt.read_uword("%R1517") == 0xD101
        assert rt.read_bit("%M352") is False

    def test_fault_thd_breach_trip(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.simulate_thd_limit_exceeded(9.8)  # > 8.0% trip

        assert engine.diagnostic_code == CipEnergyDiagnosticCode.THD_LIMIT_EXCEEDED
        assert engine.state == CipEnergyState.FAULTED
        assert engine.is_metering_healthy is False
        assert engine.is_thd_tripped is True
        assert engine.is_peak_demand_tripped is True
        assert rt.read_uword("%R1517") == 0xD102
        assert rt.read_bit("%M352") is False
        assert rt.read_bit("%M353") is True

    def test_fault_reverse_power_trip(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.simulate_reverse_power_trip(-10.0)  # < -0.1 kW reverse power

        assert engine.diagnostic_code == CipEnergyDiagnosticCode.REVERSE_POWER_TRIP
        assert engine.state == CipEnergyState.FAULTED
        assert engine.is_metering_healthy is False
        assert rt.read_uword("%R1517") == 0xD103
        assert rt.read_bit("%M352") is False

    def test_fault_phase_imbalance_trip(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.simulate_phase_imbalance(4.2)  # > 3.0% imbalance

        assert engine.diagnostic_code == CipEnergyDiagnosticCode.PHASE_IMBALANCE
        assert engine.state == CipEnergyState.FAULTED
        assert engine.is_metering_healthy is False
        assert rt.read_uword("%R1517") == 0xD104
        assert rt.read_bit("%M352") is False

    def test_fault_reset_force_recovery(self) -> None:
        rt = RegisterTable()
        engine = CipEnergyEngine(reg_table=rt)
        engine.simulate_thd_limit_exceeded(10.5)
        assert engine.diagnostic_code == CipEnergyDiagnosticCode.THD_LIMIT_EXCEEDED

        engine.reset_fault(force=True)
        assert engine.diagnostic_code == CipEnergyDiagnosticCode.OK
        assert engine.is_metering_healthy is True
        assert engine.is_peak_demand_tripped is False
        assert engine.is_thd_tripped is False
        assert engine.state == CipEnergyState.OPERATIONAL
        assert rt.read_uword("%R1517") == 0x0000
        assert rt.read_bit("%M352") is True
        assert rt.read_bit("%M353") is False


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestDeterministicVerificationRunner:
    """Tests for run_cip_energy_verification deterministic execution and strict 4-state contract."""

    def test_verification_runner_execution_success(self) -> None:
        res = run_cip_energy_verification()
        assert isinstance(res, dict)
        assert res["status"] == "success"
        assert res["stages_passed"] == 9
        assert res["total_stages"] == 9
        assert "stages" in res["data"]
        assert len(res["data"]["stages"]) == 9

    def test_verification_runner_exports_json_evidence(self, tmp_path: Path) -> None:
        out_file = tmp_path / "test_cip_energy_evidence.json"
        res = run_cip_energy_verification(output_path=str(out_file))
        assert res["status"] == "success"
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["stages_passed"] == 9

    def test_verification_runner_all_9_individual_stages_passed(self) -> None:
        res = run_cip_energy_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for s in stages:
            assert s["passed"] is True, f"Stage {s.get('stage')} ({s.get('check')}) failed: {s.get('details')}"
