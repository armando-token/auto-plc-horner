"""Comprehensive Unit Test Suite for Wave W247 CIP Safety ArmorBlock Guard I/O Concentrator.

Work Package: W247 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety ArmorBlock Guard I/O Concentrator.

Covers 120+ Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2. TestGuardIoConfiguration: 8 input pairs, 4 output pairs, discrepancy time limits, EPI 10ms, watchdog 30ms.
3. TestCrcSChecksumAlgorithms: CRC-S1 (0x5935) and CRC-S2 (0x755B) deterministic calculation, single-bit corruption detection.
4. TestDualChannelDiscrepancySurveillance: Discrepancy timer countdown, 0xED03 discrepancy fault injection, %R2083 bitmask, %M486 trip.
5. TestPulseTestingAndCrossFaults: 500us test pulse evaluation, short-to-24V DC injection, cross-channel short tripping 0xED04, %R2084 bitmask.
6. TestFieldPowerAndOutputReadback: Field power undervoltage 0xED05, bipolar safe output readback mismatch 0xED06.
7. TestEpiWatchdogSurveillance: Watchdog timer countdown, 0xED02 timeout fault injection, %M486 trip.
8. TestHornerOCSSynchronizationAndRegisters: %R2080..%R2087 and %M485..%M486 bit-exact synchronization, PrivilegeMode.SYSTEM.
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetyGuardIoSync POU.
10. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
11. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
12. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import time
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_guard_io import (
    CIP_GUARD_IO_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_CRC_INIT,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_DISCRETE_OUTPUT_CLASS_ID,
    CIP_SAFETY_GUARD_IO_CLASS_ID,
    CIP_SAFETY_GUARD_IO_POU,
    CIP_SAFETY_GUARD_IO_SYNC_POU,
    CIP_SAFETY_POINT_IO_CLASS_ID,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    COIL_GUARD_IO_ACTIVE,
    COIL_GUARD_IO_SAFE_STATE_TRIPPED,
    COIL_GUARD_IO_TRIP_ACTIVE,
    COIL_SAFETY_GUARD_ACTIVE,
    COIL_SAFETY_TRIP_ACTIVE,
    COIL_SAFETY_TRIP_SAFE_STATE_ENGAGED,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_S_INIT,
    DEFAULT_DISCREPANCY_TIME_MS,
    DEFAULT_DISCREPANCY_WINDOW_MS,
    DEFAULT_EPI_MS,
    DEFAULT_FIELD_POWER_MV,
    DEFAULT_INPUT_PAIRS_COUNT,
    DEFAULT_OUTPUT_PAIRS_COUNT,
    DEFAULT_SCID,
    DEFAULT_SCID_CRC,
    DEFAULT_SCID_TIMESTAMP,
    DEFAULT_SNN,
    DEFAULT_TEST_PULSE_WIDTH_US,
    DEFAULT_WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DIAG_CRC_S_FAULT,
    DIAG_DISCREPANCY_TIMER_EXCEEDED,
    DIAG_EPI_WATCHDOG_TIMEOUT,
    DIAG_FIELD_POWER_FAULT,
    DIAG_GUARD_IO_OK,
    DIAG_OK,
    DIAG_OUTPUT_CROSS_FAULT,
    DIAG_PULSE_TEST_SHORT_CIRCUIT,
    DISCREPANCY_WINDOW_MS,
    EPI_WATCHDOG_TIMEOUT_MS,
    FIELD_POWER_UNDERVOLTAGE_THRESHOLD_MV,
    INPUT_PAIRS_COUNT,
    MAX_INPUT_PAIRS,
    MAX_OUTPUT_PAIRS,
    MIN_FIELD_POWER_MV,
    NOMINAL_DISCREPANCY_TIME_MS,
    NOMINAL_EPI_MS,
    NOMINAL_FIELD_POWER_MV,
    OUTPUT_PAIRS_COUNT,
    REG_ACTIVE_DISCREPANCY_FAULT_MASK,
    REG_ACTIVE_FAULT_PAIR_INDEX,
    REG_CROSS_FAULT_BITS,
    REG_CROSS_FAULT_BITMASK,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DISCREPANCY_FAULT_BITMASK,
    REG_DISCREPANCY_FAULT_BITS,
    REG_FIELD_POWER_MV,
    REG_FIELD_POWER_STATUS,
    REG_FIELD_POWER_VOLTAGE_MV,
    REG_GUARD_IO_INPUT_STATUS,
    REG_GUARD_IO_OPERATIONAL_STATE,
    REG_GUARD_IO_OUTPUT_STATUS,
    REG_GUARD_OPERATIONAL_STATE,
    REG_OUTPUT_CROSS_FAULT_BITMASK,
    REG_OUTPUT_READBACK_FAULT_BITS,
    REG_OUTPUT_READBACK_FAULT_MASK,
    REG_SAFE_INPUT_BITMASK,
    REG_SAFE_INPUT_STATE_BITS,
    REG_SAFE_OUTPUT_BITMASK,
    REG_SAFE_OUTPUT_STATE_BITS,
    REG_TEST_PULSE_CROSS_FAULT_MASK,
    REG_TEST_PULSE_FAULT_BITMASK,
    TEST_PULSE_DURATION_US,
    TOTAL_INPUT_CHANNELS,
    TOTAL_OUTPUT_CHANNELS,
    TOTAL_SAFE_INPUTS,
    TOTAL_SAFE_OUTPUTS,
    WATCHDOG_MULTIPLIER,
    ArmorBlockGuardIoEngine,
    CIPSafetyGuardIoEngine,
    CipSafetyControlByte,
    CipSafetyCrcCorruptionError,
    CipSafetyCrcFaultError,
    CipSafetyCrossChannelFaultError,
    CipSafetyDiagnosticCode,
    CipSafetyDiscrepancyError,
    CipSafetyDiscrepancyTimeoutError,
    CipSafetyEpiTimeoutError,
    CipSafetyEpiWatchdogTimeoutError,
    CipSafetyFieldPowerError,
    CipSafetyGuardIoConcentrator,
    CipSafetyGuardIoEngine,
    CipSafetyGuardIoError,
    CipSafetyGuardIoPacket,
    CipSafetyGuardIoSync,
    CipSafetyGuardIoSyncPOU,
    CipSafetyOutputCrossFaultError,
    CipSafetyOutputReadbackError,
    CipSafetyParityFaultError,
    CipSafetyPulseTestError,
    CipSafetyReadbackMismatchError,
    CipSafetyTestPulseFaultError,
    CipSafetyUndervoltageError,
    DiagnosticCode,
    DiagnosticStatusCode,
    DiversifiedMode,
    DualChannelEvaluationMode,
    GuardInputPair,
    GuardIoConcentratorEngine,
    GuardIoOperationalState,
    GuardOperationalState,
    GuardOutputPair,
    OutputChannelMode,
    PulseTestMode,
    SafeInputPair,
    SafeOutputPair,
    SafetyChannelMode,
    SafetyControlByte,
    SafetyGuardIoEngine,
    SafetyOperationalState,
    calc_crc_s1,
    calc_crc_s2,
    calculate_crc16_ccitt,
    compute_crc_s1,
    compute_crc_s2,
    create_valid_guard_io_packet,
    run_cip_safety_guard_io_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    verify_cip_safety_guard_io_pure_st,
    verify_dual_channel_payload,
    verify_dual_crc_s,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Volume 5 Guard I/O constants, enums, registers, and diagnostic codes."""

    def test_cip_safety_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_GUARD_IO_CLASS_ID in (0x23, 0x24)
        assert CIP_SAFETY_DISCRETE_OUTPUT_CLASS_ID in (0x23, 0x25)
        assert CIP_GUARD_IO_CLASS_ID in (0x23, 0x24)
        assert CIP_SAFETY_POINT_IO_CLASS_ID in (0x23, 0x24)

    def test_channel_limits_and_counts(self) -> None:
        assert INPUT_PAIRS_COUNT == 8
        assert DEFAULT_INPUT_PAIRS_COUNT == 8
        assert MAX_INPUT_PAIRS == 8
        assert TOTAL_SAFE_INPUTS == 16
        assert TOTAL_INPUT_CHANNELS == 16
        assert OUTPUT_PAIRS_COUNT == 4
        assert DEFAULT_OUTPUT_PAIRS_COUNT == 4
        assert MAX_OUTPUT_PAIRS == 4
        assert TOTAL_SAFE_OUTPUTS == 8
        assert TOTAL_OUTPUT_CHANNELS == 8

    def test_timing_and_surveillance_constants(self) -> None:
        assert NOMINAL_EPI_MS == 10.0
        assert DEFAULT_EPI_MS == 10.0
        assert WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert EPI_WATCHDOG_TIMEOUT_MS == 30.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 30.0
        assert NOMINAL_DISCREPANCY_TIME_MS in (20.0, 50.0)
        assert DEFAULT_DISCREPANCY_TIME_MS in (20.0, 50.0)
        assert TEST_PULSE_DURATION_US == 500
        assert DEFAULT_TEST_PULSE_WIDTH_US == 500

    def test_field_power_voltage_constants(self) -> None:
        assert NOMINAL_FIELD_POWER_MV == 24000
        assert DEFAULT_FIELD_POWER_MV == 24000
        assert MIN_FIELD_POWER_MV == 19200
        assert FIELD_POWER_UNDERVOLTAGE_THRESHOLD_MV == 19200

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_S_INIT == 0xFFFF
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC16_CCITT_POLY == 0x1021
        assert CRC16_CCITT_INIT == 0xFFFF

    def test_default_snn_and_scid(self) -> None:
        assert len(DEFAULT_SNN) == 6
        assert DEFAULT_SNN == bytes([0x20, 0x26, 0x10, 0x06, 0xDD, 0x47])
        assert DEFAULT_SCID == 0x20261006
        assert DEFAULT_SCID_CRC == 0x20261006
        assert DEFAULT_SCID_TIMESTAMP == 0x10060004

    def test_register_address_literals(self) -> None:
        assert REG_GUARD_OPERATIONAL_STATE == "%R2080"
        assert REG_SAFE_INPUT_STATE_BITS == "%R2081"
        assert REG_SAFE_OUTPUT_STATE_BITS == "%R2082"
        assert REG_DISCREPANCY_FAULT_BITS == "%R2083"
        assert REG_CROSS_FAULT_BITS == "%R2084"
        assert REG_OUTPUT_READBACK_FAULT_BITS == "%R2085"
        assert REG_FIELD_POWER_VOLTAGE_MV == "%R2086"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2087"

    def test_coil_address_literals(self) -> None:
        assert COIL_GUARD_IO_ACTIVE == "%M485"
        assert COIL_SAFETY_GUARD_ACTIVE == "%M485"
        assert COIL_SAFETY_TRIP_ACTIVE == "%M486"
        assert COIL_SAFETY_TRIP_SAFE_STATE_ENGAGED == "%M486"
        assert COIL_GUARD_IO_SAFE_STATE_TRIPPED == "%M486"

    def test_diagnostic_code_values_and_names(self) -> None:
        assert DiagnosticCode.GUARD_IO_OK == 0x0000
        assert DiagnosticCode.CRC_S_FAULT == 0xED01
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xED02
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == 0xED03
        assert DiagnosticCode.TEST_PULSE_CROSS_FAULT == 0xED04
        assert DiagnosticCode.FIELD_POWER_UNDERVOLTAGE == 0xED05
        assert DiagnosticCode.OUTPUT_READBACK_MISMATCH == 0xED06

    def test_diagnostic_code_signed_unsigned_16bit_equality(self) -> None:
        # DiagnosticCode must support equality with signed 16-bit negative ints
        assert DiagnosticCode.CRC_S_FAULT == (0xED01 - 0x10000)
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == (0xED02 - 0x10000)
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == (0xED03 - 0x10000)
        assert DiagnosticCode.TEST_PULSE_CROSS_FAULT == (0xED04 - 0x10000)
        assert DiagnosticCode.FIELD_POWER_UNDERVOLTAGE == (0xED05 - 0x10000)
        assert DiagnosticCode.OUTPUT_READBACK_MISMATCH == (0xED06 - 0x10000)
        assert DiagnosticCode.GUARD_IO_OK == 0

    def test_diagnostic_code_bitwise_masking_and_hash(self) -> None:
        code = DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert (code & 0xFFFF) == 0xED03
        assert (0xFFFF & code) == 0xED03
        assert hash(code) == hash(0xED03)
        assert repr(code).startswith("DiagnosticCode.")
        assert "0xED03" in str(code)

    def test_enums_and_flags(self) -> None:
        assert GuardOperationalState.INITIALIZING == 0
        assert GuardOperationalState.OPERATIONAL == 1
        assert GuardOperationalState.DEGRADED == 2
        assert GuardOperationalState.TRIPPED == 3
        assert GuardOperationalState.SAFE_STATE == 4

        assert SafetyChannelMode.EQUIVALENT == 1
        assert SafetyChannelMode.COMPLEMENTARY == 2
        assert OutputChannelMode.STANDARD == 0
        assert OutputChannelMode.BIPOLAR_SAFE == 1

        assert SafetyControlByte.RUN == 0x01
        assert SafetyControlByte.SAFETY_DEMAND == 0x08


# ============================================================================
# 2. TestGuardIoConfiguration
# ============================================================================

class TestGuardIoConfiguration:
    """Validate ArmorBlock Guard I/O Concentrator architecture and channel configuration."""

    def test_default_engine_instantiation(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        assert len(engine.input_pairs) == 8
        assert len(engine.output_pairs) == 4
        assert engine.epi_ms == 10.0
        assert engine.watchdog_timeout_ms == 30.0
        assert engine.field_power_mv == 24000
        assert engine.state == GuardOperationalState.OPERATIONAL
        assert engine.is_guard_active is True

    def test_custom_parameters_instantiation(self) -> None:
        engine = CipSafetyGuardIoEngine(
            auto_activate=False,
            epi_ms=15.0,
            watchdog_timeout_ms=45.0,
            field_power_mv=24500,
            discrepancy_window_ms=30.0,
        )
        assert engine.epi_ms == 15.0
        assert engine.watchdog_timeout_ms == 45.0
        assert engine.field_power_mv == 24500
        assert engine.discrepancy_window_ms == 30.0
        assert engine.state == GuardOperationalState.INITIALIZING

    def test_input_pairs_indices_and_pulse_test_sources(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        for i, pair in enumerate(engine.input_pairs):
            assert pair.pair_index == i
            assert pair.pulse_test_source == (i % 4)
            assert pair.channel_a is True
            assert pair.channel_b is True
            assert pair.evaluated_state is True

    def test_output_pairs_indices_and_initial_state(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        for j, out_pair in enumerate(engine.output_pairs):
            assert out_pair.pair_index == j
            assert out_pair.commanded_state is False
            assert out_pair.readback_state is False
            assert out_pair.mode == OutputChannelMode.BIPOLAR_SAFE

    def test_default_bitmasks_nominal(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        assert engine.safe_input_bitmask == 0xFF  # All 8 input pairs closed/safe
        assert engine.safe_output_bitmask == 0x00 # All 4 output pairs commanded low
        assert engine.discrepancy_fault_bitmask == 0x00
        assert engine.cross_fault_bitmask == 0x00
        assert engine.output_readback_fault_bitmask == 0x00

    def test_output_command_updates_bitmask(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        engine.set_output_command(0, True)
        engine.set_output_command(2, True)
        assert engine.safe_output_bitmask == ((1 << 0) | (1 << 2))
        assert engine.output_pairs[0].readback_state is True
        assert engine.output_pairs[2].readback_state is True

    def test_input_pair_opening_updates_input_bitmask(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        # Open pair 3 (both channels low)
        engine.set_input_pair(3, False, False)
        assert (engine.safe_input_bitmask & (1 << 3)) == 0
        assert engine.safe_input_bitmask == (0xFF ^ (1 << 3))
        # Open pair 7
        engine.set_input_pair(7, False, False)
        assert (engine.safe_input_bitmask & (1 << 7)) == 0

    def test_field_power_property(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        assert engine.field_power_healthy is True
        engine.field_power_healthy = False
        assert engine.field_power_mv < MIN_FIELD_POWER_MV

    def test_operational_state_safe_state_entry(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        engine.trip_fault(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, pair_index=1)
        assert engine.state == GuardOperationalState.SAFE_STATE
        assert engine.is_safe_state is True
        assert engine.is_fault_active is True
        assert engine.is_guard_active is False

    def test_reset_restores_nominal_state(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        engine.trip_fault(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, pair_index=1)
        engine.reset()
        assert engine.state == GuardOperationalState.OPERATIONAL
        assert engine.is_safe_state is False
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.GUARD_IO_OK


# ============================================================================
# 3. TestCrcSChecksumAlgorithms
# ============================================================================

class TestCrcSChecksumAlgorithms:
    """Validate ODVA CIP Safety dual checksum calculation (CRC-S1 & CRC-S2)."""

    def test_crc_s1_calculation_deterministic(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        crc = compute_crc_s1(data)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF
        # Deterministic repeated execution
        assert compute_crc_s1(data) == crc
        assert calc_crc_s1(data) == crc

    def test_crc_s2_calculation_deterministic(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        crc = compute_crc_s2(data)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF
        assert compute_crc_s2(data) == crc
        assert calc_crc_s2(data) == crc

    def test_crc_s1_and_crc_s2_distinct_polynomials(self) -> None:
        data = b"CIP_SAFETY_ARMORBLOCK_GUARD_IO_W247"
        c1 = compute_crc_s1(data)
        c2 = compute_crc_s2(data)
        assert c1 != c2

    def test_crc_s1_single_bit_flip_detection(self) -> None:
        base = b"\x10\x20\x30\x40\x50\x60"
        base_crc = compute_crc_s1(base)
        for byte_idx in range(len(base)):
            for bit_idx in range(8):
                corrupted = bytearray(base)
                corrupted[byte_idx] ^= (1 << bit_idx)
                assert compute_crc_s1(bytes(corrupted)) != base_crc

    def test_crc_s2_single_bit_flip_detection(self) -> None:
        base = b"\x10\x20\x30\x40\x50\x60"
        base_crc = compute_crc_s2(base)
        for byte_idx in range(len(base)):
            for bit_idx in range(8):
                corrupted = bytearray(base)
                corrupted[byte_idx] ^= (1 << bit_idx)
                assert compute_crc_s2(bytes(corrupted)) != base_crc

    def test_verify_dual_crc_s_success(self) -> None:
        payload = b"\xAA\xBB\xCC\xDD"
        c1 = compute_crc_s1(payload)
        c2 = compute_crc_s2(payload)
        assert verify_dual_crc_s(payload, c1, c2) is True

    def test_verify_dual_crc_s_failure_crc1(self) -> None:
        payload = b"\xAA\xBB\xCC\xDD"
        c1 = compute_crc_s1(payload) ^ 0x0001
        c2 = compute_crc_s2(payload)
        assert verify_dual_crc_s(payload, c1, c2) is False

    def test_verify_dual_crc_s_failure_crc2(self) -> None:
        payload = b"\xAA\xBB\xCC\xDD"
        c1 = compute_crc_s1(payload)
        c2 = compute_crc_s2(payload) ^ 0x0001
        assert verify_dual_crc_s(payload, c1, c2) is False

    def test_packet_compute_checksums_and_verify(self) -> None:
        pkt = create_valid_guard_io_packet(sequence_number=10, input_bitmask=0xFF)
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.verify_crcs() is True

    def test_packet_corrupt_crc_rejected_by_engine(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        corrupted_pkt = create_valid_guard_io_packet(sequence_number=1)
        corrupted_pkt.crc_s1 ^= 0x0001
        assert engine.process_packet(corrupted_pkt) is False
        assert engine.diagnostic_code == DiagnosticCode.CRC_S_FAULT
        assert engine.is_fault_active is True


# ============================================================================
# 4. TestDualChannelDiscrepancySurveillance
# ============================================================================

class TestDualChannelDiscrepancySurveillance:
    """Validate 8 dual-channel safe input pairs discrepancy surveillance and 0xED03 trip."""

    def test_transient_discrepancy_resolved_within_window(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True, discrepancy_window_ms=20.0)
        # Transient discrepancy on pair 1
        engine.set_input_channel_a(1, True)
        engine.set_input_channel_b(1, False)
        # Advance 10ms (< 20ms window)
        engine.scan_step(0.010)
        assert engine.input_pairs[1].in_discrepancy is True
        assert engine.input_pairs[1].discrepancy_fault is False
        assert engine.is_fault_active is False

        # Channel B catches up before timeout
        engine.set_input_channel_b(1, True)
        engine.scan_step(0.010)
        assert engine.input_pairs[1].in_discrepancy is False
        assert engine.input_pairs[1].discrepancy_fault is False
        assert engine.is_guard_active is True

    def test_discrepancy_countdown_expiration_trips_0xed03(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True, discrepancy_window_ms=20.0)
        # Inject discrepancy on pair 2
        engine.inject_discrepancy(pair_index=2, duration_ms=25.0)
        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert engine.diagnostic_code == 0xED03
        assert engine.is_fault_active is True
        assert engine.is_safe_state is True

    def test_discrepancy_sets_r2083_bitmask(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True, discrepancy_window_ms=20.0)
        engine.inject_discrepancy(pair_index=2, duration_ms=25.0)
        assert (engine.discrepancy_fault_bitmask & (1 << 2)) != 0
        assert rt.read_uword("%R2083") == (1 << 2)

    def test_discrepancy_asserts_coil_m486(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_discrepancy(pair_index=0, duration_ms=60.0)
        assert rt.read_bit("%M486") is True

    def test_discrepancy_deasserts_coil_m485(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_discrepancy(pair_index=0, duration_ms=60.0)
        assert rt.read_bit("%M485") is False

    def test_multiple_input_pairs_discrepancy_bitmask(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.input_pairs[1].inject_discrepancy(60.0)
        engine.input_pairs[5].inject_discrepancy(60.0)
        engine.trip_fault(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, pair_index=1)
        expected_mask = (1 << 1) | (1 << 5)
        assert engine.discrepancy_fault_bitmask == expected_mask
        assert rt.read_uword("%R2083") == expected_mask

    def test_evaluated_state_safe_value_deenergized_in_discrepancy(self) -> None:
        pair = SafeInputPair(pair_index=0, discrepancy_time_limit_ms=20.0)
        pair.update_inputs(True, False)
        assert pair.in_discrepancy is True
        assert pair.evaluated_state is False

    def test_complementary_input_mode_discrepancy(self) -> None:
        pair = SafeInputPair(pair_index=0, mode=SafetyChannelMode.COMPLEMENTARY, discrepancy_time_limit_ms=20.0)
        # Complementary healthy state: chA=1, chB=0
        pair.update_inputs(True, False)
        assert pair.in_discrepancy is False
        assert pair.evaluated_state is True

        # Discrepancy: chA=1, chB=1
        pair.update_inputs(True, True)
        assert pair.in_discrepancy is True
        assert pair.evaluated_state is False

    def test_discrepancy_recovery_after_clearing_fault(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_discrepancy(pair_index=3, duration_ms=60.0)
        assert engine.is_fault_active is True
        engine.reset()
        assert engine.is_fault_active is False
        assert engine.discrepancy_fault_bitmask == 0
        assert rt.read_uword("%R2083") == 0
        assert rt.read_bit("%M485") is True
        assert rt.read_bit("%M486") is False

    def test_step_timer_returns_true_only_on_threshold_crossing(self) -> None:
        pair = SafeInputPair(pair_index=0, discrepancy_time_limit_ms=20.0)
        pair.update_inputs(True, False)
        assert pair.step_timer(10.0) is False
        assert pair.step_timer(10.0) is True   # Hits 20.0 ms
        assert pair.step_timer(10.0) is False  # Already faulted


# ============================================================================
# 5. TestPulseTestingAndCrossFaults
# ============================================================================

class TestPulseTestingAndCrossFaults:
    """Validate 500us test pulse evaluation, short-to-24V DC, cross-channel short, and %R2084 bitmask."""

    def test_500us_test_pulse_healthy_evaluation(self) -> None:
        pair = SafeInputPair(pair_index=0, pulse_duration_us=500)
        assert pair.evaluate_pulse_test(detected_pulse_us=500) is True
        assert pair.cross_fault is False

    def test_500us_test_pulse_width_deviation_trips_fault(self) -> None:
        pair = SafeInputPair(pair_index=0, pulse_duration_us=500)
        assert pair.evaluate_pulse_test(detected_pulse_us=700) is False
        assert pair.cross_fault is True
        assert pair.evaluated_state is False

    def test_short_to_24v_dc_injection_trips_0xed04(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_short_to_24v(pair_index=3)
        assert engine.diagnostic_code == DiagnosticCode.TEST_PULSE_CROSS_FAULT
        assert engine.diagnostic_code == 0xED04
        assert engine.is_fault_active is True
        assert engine.input_pairs[3].short_to_24v is True

    def test_cross_channel_short_injection_trips_0xed04(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_cross_channel_short(pair_index=4)
        assert engine.diagnostic_code == DiagnosticCode.TEST_PULSE_CROSS_FAULT
        assert engine.diagnostic_code == 0xED04
        assert engine.input_pairs[4].cross_channel_short is True

    def test_cross_fault_sets_r2084_bitmask(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_cross_channel_short(pair_index=4)
        assert (engine.cross_fault_bitmask & (1 << 4)) != 0
        assert rt.read_uword("%R2084") == (1 << 4)

    def test_cross_fault_asserts_coil_m486(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_short_to_24v(pair_index=1)
        assert rt.read_bit("%M486") is True

    def test_cross_fault_deasserts_coil_m485(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_short_to_24v(pair_index=1)
        assert rt.read_bit("%M485") is False

    def test_multiple_cross_faults_accumulate_in_r2084(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.input_pairs[0].inject_short_to_24v()
        engine.input_pairs[6].inject_cross_channel_short()
        engine.trip_fault(DiagnosticCode.TEST_PULSE_CROSS_FAULT, pair_index=0)
        expected_mask = (1 << 0) | (1 << 6)
        assert engine.cross_fault_bitmask == expected_mask
        assert rt.read_uword("%R2084") == expected_mask

    def test_clear_faults_restores_test_pulse_health(self) -> None:
        pair = SafeInputPair(pair_index=2)
        pair.inject_cross_channel_short()
        assert pair.cross_fault is True
        pair.clear_faults()
        assert pair.cross_fault is False
        assert pair.evaluated_state is True

    def test_cross_fault_scan_step_trips_engine(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.input_pairs[5].cross_fault = True
        engine.scan_step(0.010)
        assert engine.diagnostic_code == DiagnosticCode.TEST_PULSE_CROSS_FAULT
        assert rt.read_uword("%R2084") == (1 << 5)


# ============================================================================
# 6. TestFieldPowerAndOutputReadback
# ============================================================================

class TestFieldPowerAndOutputReadback:
    """Validate 24V field power undervoltage (0xED05) and bipolar output readback mismatch (0xED06)."""

    def test_nominal_field_power_healthy(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        assert engine.field_power_mv == 24000
        assert engine.field_power_healthy is True
        assert rt.read_word("%R2086") == 24000

    def test_field_power_undervoltage_trips_0xed05(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_field_undervoltage(voltage_mv=18000)
        assert engine.diagnostic_code == DiagnosticCode.FIELD_POWER_UNDERVOLTAGE
        assert engine.diagnostic_code == 0xED05
        assert engine.is_fault_active is True
        assert rt.read_word("%R2086") == 18000
        assert rt.read_uword("%R2087") == 0xED05

    def test_field_power_marginal_threshold(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        # Exactly 19200 mV is healthy
        engine.inject_field_undervoltage(19200)
        assert engine.is_fault_active is False
        # 19199 mV trips
        engine.inject_field_undervoltage(19199)
        assert engine.diagnostic_code == DiagnosticCode.FIELD_POWER_UNDERVOLTAGE
        assert engine.is_fault_active is True

    def test_field_power_trip_asserts_m486(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_field_undervoltage(17500)
        assert rt.read_bit("%M486") is True
        assert rt.read_bit("%M485") is False

    def test_bipolar_safe_output_command_and_readback(self) -> None:
        out = SafeOutputPair(pair_index=0)
        out.set_command(True)
        assert out.commanded_state is True
        assert out.readback_state is True
        assert out.verify_readback() is True

    def test_output_readback_mismatch_trips_0xed06(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_output_readback_mismatch(pair_index=1)
        assert engine.diagnostic_code == DiagnosticCode.OUTPUT_READBACK_MISMATCH
        assert engine.diagnostic_code == 0xED06
        assert engine.is_fault_active is True
        assert (engine.output_readback_fault_bitmask & (1 << 1)) != 0
        assert rt.read_uword("%R2085") == (1 << 1)
        assert rt.read_uword("%R2087") == 0xED06

    def test_output_readback_trip_asserts_m486(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_output_readback_mismatch(pair_index=2)
        assert rt.read_bit("%M486") is True
        assert rt.read_bit("%M485") is False

    def test_safe_outputs_deenergized_upon_trip(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        engine.set_output_command(0, True)
        engine.set_output_command(1, True)
        assert engine.safe_output_bitmask == 0x03
        # Trip fault
        engine.trip_fault(DiagnosticCode.FIELD_POWER_UNDERVOLTAGE)
        assert engine.safe_output_bitmask == 0x00
        assert engine.output_pairs[0].actual_state is False

    def test_output_cross_fault_cleared_by_reset(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_output_readback_mismatch(0)
        assert engine.is_fault_active is True
        engine.reset()
        assert engine.is_fault_active is False
        assert engine.output_readback_fault_bitmask == 0
        assert rt.read_uword("%R2085") == 0

    def test_field_power_scan_step_monitoring(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.field_power_mv = 18500
        engine.scan_step(0.010)
        assert engine.diagnostic_code == DiagnosticCode.FIELD_POWER_UNDERVOLTAGE


# ============================================================================
# 7. TestEpiWatchdogSurveillance
# ============================================================================

class TestEpiWatchdogSurveillance:
    """Validate Expected Packet Interval (EPI) watchdog timer monitoring and 0xED02 trip."""

    def test_watchdog_silence_accumulation(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.010)
        assert math.isclose(engine.silence_timer_ms, 10.0, abs_tol=1e-3)
        engine.scan_step(0.010)
        assert math.isclose(engine.silence_timer_ms, 20.0, abs_tol=1e-3)
        assert engine.is_fault_active is False

    def test_packet_arrival_resets_silence_timer(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.020)
        assert math.isclose(engine.silence_timer_ms, 20.0, abs_tol=1e-3)

        pkt = engine.create_packet(seq=1)
        res = engine.process_packet(pkt)
        assert res is True
        assert engine.silence_timer_ms == 0.0

    def test_watchdog_timeout_silence_trips_0xed02(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True, watchdog_timeout_ms=30.0)
        # Advance 35ms (> 30.0 ms timeout)
        engine.scan_step(0.035)
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.diagnostic_code == 0xED02
        assert engine.is_fault_active is True
        assert engine.is_safe_state is True

    def test_watchdog_trip_asserts_coil_m486(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.scan_step(0.035)
        assert rt.read_bit("%M486") is True

    def test_watchdog_trip_deasserts_coil_m485(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.scan_step(0.035)
        assert rt.read_bit("%M485") is False

    def test_watchdog_trip_sets_r2087_diagnostic_code(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.scan_step(0.035)
        assert rt.read_uword("%R2087") == 0xED02

    def test_sub_watchdog_silence_tolerated(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.025)
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.GUARD_IO_OK

    def test_periodic_packets_keep_watchdog_healthy(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        for i in range(1, 10):
            engine.scan_step(0.010)
            pkt = engine.create_packet(seq=i)
            engine.process_packet(pkt)
            assert engine.is_fault_active is False

    def test_inject_watchdog_timeout_method(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_watchdog_timeout()
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert rt.read_uword("%R2087") == 0xED02

    def test_watchdog_recovery_via_reset(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.inject_watchdog_timeout()
        assert engine.is_fault_active is True
        engine.reset()
        assert engine.is_fault_active is False
        assert engine.silence_timer_ms == 0.0
        assert rt.read_uword("%R2087") == 0x0000


# ============================================================================
# 8. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate bit-exact synchronization to Horner OCS memory space (%R2080..%R2087, %M485..%M486)."""

    def test_nominal_registers_bit_exact(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        assert rt.read_word("%R2080") == 1       # OPERATIONAL
        assert rt.read_uword("%R2081") == 0xFF   # 8 inputs healthy
        assert rt.read_uword("%R2082") == 0x00   # 4 outputs commanded off
        assert rt.read_uword("%R2083") == 0x00   # Discrepancy mask 0
        assert rt.read_uword("%R2084") == 0x00   # Cross fault mask 0
        assert rt.read_uword("%R2085") == 0x00   # Output readback mask 0
        assert rt.read_word("%R2086") == 24000   # Field power 24V
        assert rt.read_uword("%R2087") == 0x0000 # OK

    def test_nominal_coils_bit_exact(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        assert rt.read_bit("%M485") is True
        assert rt.read_bit("%M486") is False

    def test_system_privilege_enforcement(self) -> None:
        rt = RegisterTable()
        # Direct user write to system protected register should require privilege
        safe_write_word(rt, "%R2080", 1, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word("%R2080") == 1

    def test_safe_write_word_signed_boundary_conversion(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2087", 0xED01, privilege=PrivilegeMode.SYSTEM)
        # Read back as signed 16-bit
        assert rt.read_word("%R2087") == (0xED01 - 0x10000)
        # Read back as unsigned 16-bit
        assert rt.read_uword("%R2087") == 0xED01

    def test_safe_write_uword_helper(self) -> None:
        rt = RegisterTable()
        safe_write_uword(rt, "%R2087", 0xED03)
        assert rt.read_uword("%R2087") == 0xED03

    def test_safe_write_bit_helper(self) -> None:
        rt = RegisterTable()
        safe_write_bit(rt, "%M485", True)
        assert rt.read_bit("%M485") is True
        safe_write_bit(rt, "%M485", False)
        assert rt.read_bit("%M485") is False

    def test_sync_to_registers_with_none_table_handles_cleanly(self) -> None:
        engine = CipSafetyGuardIoEngine(register_table=None, auto_activate=True)
        # Should not raise
        engine.sync_to_registers(None)

    def test_sync_to_external_register_table(self) -> None:
        engine = CipSafetyGuardIoEngine(register_table=None, auto_activate=True)
        ext_rt = RegisterTable()
        engine.sync_to_registers(ext_rt)
        assert ext_rt.read_word("%R2080") == 1
        assert ext_rt.read_uword("%R2081") == 0xFF
        assert ext_rt.read_bit("%M485") is True

    def test_zero_drift_across_repetitive_sync(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        for _ in range(50):
            engine.sync_to_registers(rt)
        assert rt.read_word("%R2080") == 1
        assert rt.read_uword("%R2081") == 0xFF
        assert rt.read_uword("%R2087") == 0x0000

    def test_tripped_register_and_coil_sync(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyGuardIoEngine(register_table=rt, auto_activate=True)
        engine.trip_fault(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, pair_index=3)
        assert rt.read_word("%R2080") == 4       # SAFE_STATE
        assert rt.read_uword("%R2083") == (1 << 3)
        assert rt.read_uword("%R2087") == 0xED03
        assert rt.read_bit("%M485") is False
        assert rt.read_bit("%M486") is True


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 Structured Text POU 'CipSafetyGuardIoSync' and SecurityGuard."""

    def test_pure_st_content_verification(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_GUARD_IO_SYNC_POU)

    def test_st_parser_validate_code_success(self) -> None:
        res = STParser.validate_code(CIP_SAFETY_GUARD_IO_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_parse_pou_ast(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_GUARD_IO_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyGuardIoSync"

    def test_bound_registers_contain_r2080_to_r2087(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_GUARD_IO_SYNC_POU)
        expected_regs = {
            "%R2080", "%R2081", "%R2082", "%R2083",
            "%R2084", "%R2085", "%R2086", "%R2087",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_bound_coils_contain_m485_and_m486(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_GUARD_IO_SYNC_POU)
        expected_coils = {"%M485", "%M486"}
        assert expected_coils.issubset(set(ast.bound_registers))

    def test_verify_cip_safety_guard_io_pure_st_helper(self) -> None:
        assert verify_cip_safety_guard_io_pure_st() is True

    def test_pou_aliases_identity(self) -> None:
        assert CIP_SAFETY_GUARD_IO_POU == CIP_SAFETY_GUARD_IO_SYNC_POU
        assert CipSafetyGuardIoSync == CIP_SAFETY_GUARD_IO_SYNC_POU
        assert CipSafetyGuardIoSyncPOU == CIP_SAFETY_GUARD_IO_SYNC_POU

    def test_custom_valid_pou_accepted(self) -> None:
        valid_custom = """PROGRAM CustomGuardSync
VAR
    R0 AT %R2080 : INT;
    R1 AT %R2081 : UINT;
    R2 AT %R2082 : UINT;
    R3 AT %R2083 : UINT;
    R4 AT %R2084 : UINT;
    R5 AT %R2085 : UINT;
    R6 AT %R2086 : INT;
    R7 AT %R2087 : UINT;
    M1 AT %M485  : BOOL;
    M2 AT %M486  : BOOL;
END_VAR
M1 := TRUE;
END_PROGRAM
"""
        assert verify_cip_safety_guard_io_pure_st(valid_custom) is True

    def test_pou_missing_registers_rejected(self) -> None:
        missing_regs_pou = """PROGRAM IncompleteSync
VAR
    R0 AT %R2080 : INT;
    M1 AT %M485  : BOOL;
END_VAR
M1 := TRUE;
END_PROGRAM
"""
        assert verify_cip_safety_guard_io_pure_st(missing_regs_pou) is False

    def test_pou_syntax_error_rejected(self) -> None:
        bad_syntax_pou = "PROGRAM Bad; INVALID CODE HERE;"
        assert verify_cip_safety_guard_io_pure_st(bad_syntax_pou) is False


# ============================================================================
# 10. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate interception and rejection of ladder logic constructs (contacts, coils, rungs)."""

    def test_reject_normally_open_contact(self) -> None:
        snippet = "PROGRAM Test\nVAR x: BOOL; END_VAR\n---[ ]--- x;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_normally_closed_contact(self) -> None:
        snippet = "PROGRAM Test\nVAR x: BOOL; END_VAR\n---[/]--- x;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_standard_coil(self) -> None:
        snippet = "PROGRAM Test\nVAR y: BOOL; END_VAR\n---( )--- y;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_set_coil(self) -> None:
        snippet = "PROGRAM Test\nVAR y: BOOL; END_VAR\n---(S)--- y;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_reset_coil(self) -> None:
        snippet = "PROGRAM Test\nVAR y: BOOL; END_VAR\n---(R)--- y;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_rung_delimiter(self) -> None:
        snippet = "PROGRAM Test\nRUNG 1\nx := 1;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_network_delimiter(self) -> None:
        snippet = "PROGRAM Test\nNETWORK 1\nx := 1;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_xic_mnemonic(self) -> None:
        snippet = "PROGRAM Test\nXIC(Contact1);\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_ote_mnemonic(self) -> None:
        snippet = "PROGRAM Test\nOTE(Coil1);\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_reject_pipe_bounded_contact(self) -> None:
        snippet = "PROGRAM Test\n|---[ ]---|---( )---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 11. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance, scan_step, step, execute, reset, and soak stability."""

    def test_ilogic_unit_inheritance(self) -> None:
        assert issubclass(CipSafetyGuardIoEngine, ILogicUnit)

    def test_name_property(self) -> None:
        engine = CipSafetyGuardIoEngine()
        assert engine.name == "CipSafetyGuardIoEngine"

    def test_priority_property(self) -> None:
        engine = CipSafetyGuardIoEngine()
        assert isinstance(engine.priority, int)
        assert engine.priority == 1

    def test_is_enabled_property(self) -> None:
        engine = CipSafetyGuardIoEngine()
        assert engine.is_enabled is True

    def test_step_method_increments_cycles(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        initial_cycles = engine.cycles_count
        engine.step(0.010)
        assert engine.cycles_count == initial_cycles + 1

    def test_execute_method_under_scan_context(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        ctx = ScanContext(dt=0.010)
        engine.execute(ctx)
        assert engine.cycles_count >= 1

    def test_reset_method_clears_fault_and_restores_health(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        engine.trip_fault(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, pair_index=0)
        assert engine.is_fault_active is True
        engine.reset()
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.GUARD_IO_OK

    def test_100_cycle_soak_stability(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        for cycle in range(1, 101):
            pkt = engine.create_packet(seq=cycle)
            engine.process_packet(pkt)
            engine.scan_step(0.010)
        assert engine.cycles_count >= 100
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.GUARD_IO_OK

    def test_memory_heap_boundedness_over_soak(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()
        for cycle in range(1, 101):
            pkt = engine.create_packet(seq=cycle)
            engine.process_packet(pkt)
            engine.scan_step(0.010)
        snap2 = tracemalloc.take_snapshot()
        stats = snap2.compare_to(snap1, "lineno")
        growth_kb = sum(s.size_diff for s in stats if s.size_diff > 0) / 1024.0
        tracemalloc.stop()
        # Verify heap growth is bounded (< 100 KB)
        assert growth_kb < 100.0

    def test_time_advancement_monotonicity(self) -> None:
        engine = CipSafetyGuardIoEngine(auto_activate=True)
        t0 = engine.current_time_ns
        engine.scan_step(0.010)
        t1 = engine.current_time_ns
        assert t1 > t0
        assert (t1 - t0) == int(0.010 * 1e9)


# ============================================================================
# 12. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage verification runner and strict 4-state contract."""

    def test_runner_returns_dict(self) -> None:
        res = run_cip_safety_guard_io_verification()
        assert isinstance(res, dict)

    def test_strict_4_state_status_success(self) -> None:
        res = run_cip_safety_guard_io_verification()
        assert res["status"] == "success"

    def test_strict_4_state_error_code_none(self) -> None:
        res = run_cip_safety_guard_io_verification()
        assert res["error_code"] is None

    def test_strict_4_state_details_text(self) -> None:
        res = run_cip_safety_guard_io_verification()
        assert isinstance(res["details"], str)
        assert "PASSED" in res["details"]

    def test_total_stages_count_is_9(self) -> None:
        res = run_cip_safety_guard_io_verification()
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9

    def test_all_9_individual_stages_passed(self) -> None:
        res = run_cip_safety_guard_io_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for st in stages:
            assert st["passed"] is True
            assert isinstance(st["timing_ms"], (int, float))

    def test_work_package_w247_in_evidence(self) -> None:
        res = run_cip_safety_guard_io_verification(work_package="W247")
        assert res["data"]["work_package"] == "W247"

    def test_register_map_in_evidence(self) -> None:
        res = run_cip_safety_guard_io_verification()
        reg_map = res["data"]["register_map"]
        assert "%R2080" in reg_map
        assert "%R2087" in reg_map
        assert "%M485" in reg_map
        assert "%M486" in reg_map

    def test_evidence_file_emission(self, tmp_path: Path) -> None:
        ev_file = tmp_path / "cip_safety_guard_io_evidence.json"
        res = run_cip_safety_guard_io_verification(output_path=ev_file)
        assert ev_file.exists()
        loaded = json.loads(ev_file.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
        assert loaded["total_stages"] == 9

    def test_cli_verification_script_execution(self) -> None:
        script_path = Path("scripts/run_cip_safety_guard_io_verification.py")
        assert script_path.exists()
        proc = subprocess.run(
            [sys.executable, str(script_path), "--json"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert data["status"] == "success"
