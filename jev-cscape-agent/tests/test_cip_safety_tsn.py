"""Comprehensive Unit Test Suite for Wave W259 CIP Safety Over TSN Protocol Engine.

Work Package: W259 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Time-Sensitive Networking (TSN) IEEE 802.1Qbv / IEEE 802.1Qbu for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit values, string representations,
   bitwise operations, hashing, enums, register names, coil addresses, and class IDs.
2. TestDualCrcAndPacketFraming: CRC-S1 (0x5935), CRC-S2 (0x755B), dual CRC verification, diversified sequence
   counters (~seq_1 & 0xFFFF), frame serialization, and single-bit mutation corruption detection.
3. TestStateTransitions: Progression across TSNGateState (CLOSED, PREEMPTABLE_OPEN, EXPRESS_SCHEDULED_OPEN,
   GUARD_BAND_ACTIVE, FAILSAFE_CLOSED), property setters, and recovery resets.
4. TestScheduleMismatchTrip: Scheduled express traffic surveillance, transmission outside express window (0xEE31),
   CRC/sequence mismatch on express packet, register reflection, and recovery reset.
5. TestJitterThresholdExceededTrip: Time-sync jitter surveillance, nominal jitter (45 ns), boundary limit (< 100 ns),
   watchdog trip (>= 100 ns -> 0xEE32 JITTER_EXCEEDED_TRIP), scan-step watchdog trip, register reflection, and recovery reset.
6. TestGuardBandViolation: Guard band surveillance, preemptable frame transmission during guard band (0xEE33),
   transmission during express window, frame duration encroaching into guard band, register reflection, and recovery reset.
7. TestFramePreemptionFailureTrip: IEEE 802.1Qbu frame preemption logic, successful fragmentation (>= 64 bytes),
   preemption failure on undersized frames (< 64 bytes -> 0xEE34 PREEMPTION_FAIL_TRIP), simulated preemption failure,
   register reflection, and recovery reset.
8. TestRegisterSynchronization: %R2200..%R2207 and %M513..%M514 bit-exact synchronization, PrivilegeMode.SYSTEM,
   preemption count (%R2204), express packet count (%R2205), flow priority (%R2206), and safe write wrappers.
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetyTsnSync POU, bound registers validation.
10. TestAntiLadderConstructRejection: Rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)
    with LadderForbiddenError.
11. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
    properties validation, 100-cycle continuous soak simulation, and heap boundedness (< 100 KB growth).
12. TestVerificationRunnerAndContract: Deterministic 10-stage runner execution, strict 4-state contract validation,
    and exception inheritance hierarchy.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_tsn import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_TSN_CLASS_ID,
    NOMINAL_TSN_PCP,
    DEFAULT_PCP,
    NOMINAL_TSN_SAFE_CLASS,
    DEFAULT_SAFE_CLASS,
    NOMINAL_TSN_SAFETY_FLOW_PRIORITY,
    DEFAULT_SAFETY_FLOW_PRIORITY,
    NOMINAL_TSN_CYCLE_TIME_US,
    DEFAULT_CYCLE_TIME_US,
    MIN_CYCLE_TIME_US,
    MAX_CYCLE_TIME_US,
    NOMINAL_TSN_SCHEDULE_OFFSET_US,
    DEFAULT_SCHEDULE_OFFSET_US,
    DEFAULT_EXPRESS_DURATION_US,
    DEFAULT_GUARD_BAND_DURATION_US,
    NOMINAL_TSN_MAX_JITTER_NS,
    DEFAULT_MAX_JITTER_NS,
    DEFAULT_JITTER_NS,
    MAX_ALLOWED_JITTER_NS,
    JITTER_WATCHDOG_LIMIT_NS,
    NOMINAL_TSN_PREEMPTION_COUNT,
    DEFAULT_PREEMPTION_COUNT,
    NOMINAL_TSN_EXPRESS_PACKET_COUNT,
    DEFAULT_EXPRESS_PACKET_COUNT,
    MIN_PREEMPTABLE_FRAME_LEN,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    REG_TSN_SAFETY_GATE_STATE,
    REG_TSN_CYCLE_TIME_US,
    REG_TSN_SCHEDULE_OFFSET_US,
    REG_TSN_MAX_JITTER_NS,
    REG_TSN_PREEMPTION_COUNT,
    REG_TSN_EXPRESS_PACKET_COUNT,
    REG_TSN_SAFETY_FLOW_PRIORITY,
    REG_TSN_SAFETY_DIAGNOSTIC_CODE,
    COIL_TSN_SCHEDULE_SYNCED,
    COIL_TSN_SAFETY_INTERLOCK_TRIPPED,
    REG_TSN_GATE_STATE,
    REG_SAFETY_GATE_STATE,
    REG_TSN_STATE,
    REG_GATE_STATE,
    REG_TSN_CYCLE_US,
    REG_TSN_CYCLE_TIME,
    REG_CYCLE_TIME_US,
    REG_CYCLE_US,
    REG_TSN_OFFSET_US,
    REG_TSN_SCHEDULE_OFFSET,
    REG_SCHEDULE_OFFSET_US,
    REG_SCHEDULE_OFFSET,
    REG_TSN_JITTER_NS,
    REG_TSN_MAX_JITTER,
    REG_MAX_JITTER_NS,
    REG_JITTER_NS,
    REG_PREEMPTION_COUNT,
    REG_TSN_PREEMPTION,
    REG_PREEMPTIONS,
    REG_EXPRESS_PACKET_COUNT,
    REG_EXPRESS_COUNT,
    REG_TSN_EXPRESS_COUNT,
    REG_EXPRESS_PACKETS,
    REG_TSN_FLOW_PRIORITY,
    REG_SAFETY_FLOW_PRIORITY,
    REG_TSN_PRIORITY,
    REG_FLOW_PRIORITY,
    REG_TSN_DIAGNOSTIC_CODE,
    REG_TSN_DIAG_CODE,
    REG_SAFETY_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DIAGNOSTIC_CODE,
    COIL_TSN_SYNCED,
    COIL_TSN_SYNC,
    COIL_SCHEDULE_SYNCED,
    COIL_TSN_SCHEDULE_SYNC,
    COIL_SYNCED,
    COIL_TSN_INTERLOCK_TRIPPED,
    COIL_TSN_TRIPPED,
    COIL_SAFETY_INTERLOCK_TRIPPED,
    COIL_INTERLOCK_TRIPPED,
    COIL_TSN_FAULT,
    COIL_TSN_SAFE_STOP_TRIPPED,
    TSNGateState,
    TsnGateState,
    CipSafetyTsnGateState,
    CIPTSNGateState,
    SafetyGateState,
    DiagnosticCode,
    DIAG_OK,
    DIAG_SCHEDULE_MISMATCH_TRIP,
    DIAG_JITTER_EXCEEDED_TRIP,
    DIAG_GUARD_BAND_VIOLATION,
    DIAG_PREEMPTION_FAIL_TRIP,
    DiagnosticStatusCode,
    TSNDiagnosticCode,
    TsnDiagnosticCode,
    CipSafetyTsnDiagnosticCode,
    TSNDiagnosticStatusCode,
    CIPTSNSafetyError,
    CIPSafetyTSNError,
    CipSafetyTsnError,
    TSNScheduleMismatchError,
    ScheduleMismatchTripError,
    TSNJitterExceededError,
    JitterExceededTripError,
    TSNGuardBandViolationError,
    GuardBandViolationTripError,
    TSNPreemptionFailError,
    PreemptionFailTripError,
    CIP_SAFETY_TSN_PURE_ST_POU,
    CIP_SAFETY_TSN_SYNC_POU,
    CIP_SAFETY_TSN_POU,
    PURE_ST_POU,
    CipSafetyTsnSync,
    CipSafetyTsnSyncPOU,
    verify_cip_safety_tsn_pure_st,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPSafetyTSNPacket,
    CipSafetyTsnPacket,
    CIPSafetyTsnPacket,
    CIP_SAFETY_TSN_PACKET,
    TSNSafetyPacket,
    TsnSafetyPacket,
    create_valid_tsn_safety_packet,
    create_valid_cip_safety_tsn_packet,
    CIPSafetyTSNEngine,
    CipSafetyTsnEngine,
    CIPSafetyTsnEngine,
    CipSafetyTSNEngine,
    CIP_SAFETY_TSN_ENGINE,
    TSNEngine,
    TsnEngine,
    CIPSafetyTSNProtocolEngine,
    run_cip_safety_tsn_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety TSN constants, enums, register names, and diagnostic codes."""

    def test_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_TSN_CLASS_ID == 0x39

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S_INIT == 0xFFFF

    def test_timing_and_priority_constants(self) -> None:
        assert NOMINAL_TSN_CYCLE_TIME_US == 1000
        assert DEFAULT_CYCLE_TIME_US == 1000
        assert MIN_CYCLE_TIME_US == 100
        assert MAX_CYCLE_TIME_US == 100000

        assert NOMINAL_TSN_SCHEDULE_OFFSET_US == 250
        assert DEFAULT_SCHEDULE_OFFSET_US == 250

        assert DEFAULT_EXPRESS_DURATION_US == 250
        assert DEFAULT_GUARD_BAND_DURATION_US == 50

        assert NOMINAL_TSN_MAX_JITTER_NS == 45
        assert DEFAULT_MAX_JITTER_NS == 45
        assert DEFAULT_JITTER_NS == 45
        assert MAX_ALLOWED_JITTER_NS == 100
        assert JITTER_WATCHDOG_LIMIT_NS == 100

        assert NOMINAL_TSN_PREEMPTION_COUNT == 0
        assert DEFAULT_PREEMPTION_COUNT == 0
        assert NOMINAL_TSN_EXPRESS_PACKET_COUNT == 100
        assert DEFAULT_EXPRESS_PACKET_COUNT == 100

        assert NOMINAL_TSN_PCP == 7
        assert DEFAULT_PCP == 7
        assert NOMINAL_TSN_SAFE_CLASS == 0x39
        assert DEFAULT_SAFE_CLASS == 0x39
        assert NOMINAL_TSN_SAFETY_FLOW_PRIORITY == 0x0739
        assert DEFAULT_SAFETY_FLOW_PRIORITY == 0x0739

        assert MIN_PREEMPTABLE_FRAME_LEN == 64

    def test_register_mappings_and_aliases(self) -> None:
        # %R2200
        assert REG_TSN_SAFETY_GATE_STATE == "%R2200"
        assert REG_TSN_GATE_STATE == "%R2200"
        assert REG_SAFETY_GATE_STATE == "%R2200"
        assert REG_TSN_STATE == "%R2200"
        assert REG_GATE_STATE == "%R2200"

        # %R2201
        assert REG_TSN_CYCLE_TIME_US == "%R2201"
        assert REG_TSN_CYCLE_US == "%R2201"
        assert REG_TSN_CYCLE_TIME == "%R2201"
        assert REG_CYCLE_TIME_US == "%R2201"
        assert REG_CYCLE_US == "%R2201"

        # %R2202
        assert REG_TSN_SCHEDULE_OFFSET_US == "%R2202"
        assert REG_TSN_OFFSET_US == "%R2202"
        assert REG_TSN_SCHEDULE_OFFSET == "%R2202"
        assert REG_SCHEDULE_OFFSET_US == "%R2202"
        assert REG_SCHEDULE_OFFSET == "%R2202"

        # %R2203
        assert REG_TSN_MAX_JITTER_NS == "%R2203"
        assert REG_TSN_JITTER_NS == "%R2203"
        assert REG_TSN_MAX_JITTER == "%R2203"
        assert REG_MAX_JITTER_NS == "%R2203"
        assert REG_JITTER_NS == "%R2203"

        # %R2204
        assert REG_TSN_PREEMPTION_COUNT == "%R2204"
        assert REG_PREEMPTION_COUNT == "%R2204"
        assert REG_TSN_PREEMPTION == "%R2204"
        assert REG_PREEMPTIONS == "%R2204"

        # %R2205
        assert REG_TSN_EXPRESS_PACKET_COUNT == "%R2205"
        assert REG_EXPRESS_PACKET_COUNT == "%R2205"
        assert REG_EXPRESS_COUNT == "%R2205"
        assert REG_TSN_EXPRESS_COUNT == "%R2205"
        assert REG_EXPRESS_PACKETS == "%R2205"

        # %R2206
        assert REG_TSN_SAFETY_FLOW_PRIORITY == "%R2206"
        assert REG_TSN_FLOW_PRIORITY == "%R2206"
        assert REG_SAFETY_FLOW_PRIORITY == "%R2206"
        assert REG_TSN_PRIORITY == "%R2206"
        assert REG_FLOW_PRIORITY == "%R2206"

        # %R2207
        assert REG_TSN_SAFETY_DIAGNOSTIC_CODE == "%R2207"
        assert REG_TSN_DIAGNOSTIC_CODE == "%R2207"
        assert REG_TSN_DIAG_CODE == "%R2207"
        assert REG_SAFETY_DIAGNOSTIC_CODE == "%R2207"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2207"
        assert REG_DIAGNOSTIC_CODE == "%R2207"

        # %M513
        assert COIL_TSN_SCHEDULE_SYNCED == "%M513"
        assert COIL_TSN_SYNCED == "%M513"
        assert COIL_TSN_SYNC == "%M513"
        assert COIL_SCHEDULE_SYNCED == "%M513"
        assert COIL_TSN_SCHEDULE_SYNC == "%M513"
        assert COIL_SYNCED == "%M513"

        # %M514
        assert COIL_TSN_SAFETY_INTERLOCK_TRIPPED == "%M514"
        assert COIL_TSN_INTERLOCK_TRIPPED == "%M514"
        assert COIL_TSN_TRIPPED == "%M514"
        assert COIL_SAFETY_INTERLOCK_TRIPPED == "%M514"
        assert COIL_INTERLOCK_TRIPPED == "%M514"
        assert COIL_TSN_FAULT == "%M514"
        assert COIL_TSN_SAFE_STOP_TRIPPED == "%M514"

    def test_tsn_gate_state_enum_and_aliases(self) -> None:
        assert TSNGateState.CLOSED == 0
        assert TSNGateState.PREEMPTABLE_OPEN == 1
        assert TSNGateState.EXPRESS_SCHEDULED_OPEN == 2
        assert TSNGateState.GUARD_BAND_ACTIVE == 3
        assert TSNGateState.FAILSAFE_CLOSED == 4

        # Aliases
        assert TSNGateState.Closed == 0
        assert TSNGateState.PreemptableOpen == 1
        assert TSNGateState.ExpressScheduledOpen == 2
        assert TSNGateState.GuardBandActive == 3
        assert TSNGateState.FailsafeClosed == 4

        assert TSNGateState.PREEMPTABLE == 1
        assert TSNGateState.EXPRESS_OPEN == 2
        assert TSNGateState.EXPRESS == 2
        assert TSNGateState.GUARD_BAND == 3
        assert TSNGateState.SAFE_STOP == 4
        assert TSNGateState.SafeStop == 4
        assert TSNGateState.TRIPPED == 4

        assert TsnGateState == TSNGateState
        assert CipSafetyTsnGateState == TSNGateState
        assert CIPTSNGateState == TSNGateState
        assert SafetyGateState == TSNGateState

    def test_diagnostic_codes_signed_unsigned_equality(self) -> None:
        # 0x0000: OK
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.OK == 0
        assert (DiagnosticCode.OK & 0xFFFF) == 0x0000
        assert int(DiagnosticCode.OK) == 0

        # 0xEE31: SCHEDULE_MISMATCH_TRIP (signed: 0xEE31 - 0x10000 = -4559)
        assert DiagnosticCode.SCHEDULE_MISMATCH_TRIP == 0xEE31
        assert (DiagnosticCode.SCHEDULE_MISMATCH_TRIP & 0xFFFF) == 0xEE31
        assert DiagnosticCode.SCHEDULE_MISMATCH_TRIP == (0xEE31 - 0x10000)
        assert DiagnosticCode.SCHEDULE_MISMATCH_TRIP == -4559

        # 0xEE32: JITTER_EXCEEDED_TRIP (signed: 0xEE32 - 0x10000 = -4558)
        assert DiagnosticCode.JITTER_EXCEEDED_TRIP == 0xEE32
        assert (DiagnosticCode.JITTER_EXCEEDED_TRIP & 0xFFFF) == 0xEE32
        assert DiagnosticCode.JITTER_EXCEEDED_TRIP == (0xEE32 - 0x10000)
        assert DiagnosticCode.JITTER_EXCEEDED_TRIP == -4558

        # 0xEE33: GUARD_BAND_VIOLATION (signed: 0xEE33 - 0x10000 = -4557)
        assert DiagnosticCode.GUARD_BAND_VIOLATION == 0xEE33
        assert (DiagnosticCode.GUARD_BAND_VIOLATION & 0xFFFF) == 0xEE33
        assert DiagnosticCode.GUARD_BAND_VIOLATION == (0xEE33 - 0x10000)
        assert DiagnosticCode.GUARD_BAND_VIOLATION == -4557

        # 0xEE34: PREEMPTION_FAIL_TRIP (signed: 0xEE34 - 0x10000 = -4556)
        assert DiagnosticCode.PREEMPTION_FAIL_TRIP == 0xEE34
        assert (DiagnosticCode.PREEMPTION_FAIL_TRIP & 0xFFFF) == 0xEE34
        assert DiagnosticCode.PREEMPTION_FAIL_TRIP == (0xEE34 - 0x10000)
        assert DiagnosticCode.PREEMPTION_FAIL_TRIP == -4556

    def test_diagnostic_code_string_and_repr(self) -> None:
        assert str(DiagnosticCode.OK) == "0x0000 (OK)"
        assert str(DiagnosticCode.SCHEDULE_MISMATCH_TRIP) == "0xEE31 (SCHEDULE_MISMATCH_TRIP)"
        assert str(DiagnosticCode.JITTER_EXCEEDED_TRIP) == "0xEE32 (JITTER_EXCEEDED_TRIP)"
        assert str(DiagnosticCode.GUARD_BAND_VIOLATION) == "0xEE33 (GUARD_BAND_VIOLATION)"
        assert str(DiagnosticCode.PREEMPTION_FAIL_TRIP) == "0xEE34 (PREEMPTION_FAIL_TRIP)"

        assert repr(DiagnosticCode.OK) == "DiagnosticCode.OK(0x0000)"
        assert repr(DiagnosticCode.SCHEDULE_MISMATCH_TRIP) == "DiagnosticCode.SCHEDULE_MISMATCH_TRIP(0xEE31)"
        assert repr(DiagnosticCode.JITTER_EXCEEDED_TRIP) == "DiagnosticCode.JITTER_EXCEEDED_TRIP(0xEE32)"
        assert repr(DiagnosticCode.GUARD_BAND_VIOLATION) == "DiagnosticCode.GUARD_BAND_VIOLATION(0xEE33)"
        assert repr(DiagnosticCode.PREEMPTION_FAIL_TRIP) == "DiagnosticCode.PREEMPTION_FAIL_TRIP(0xEE34)"

    def test_diagnostic_code_bitwise_and_hashing(self) -> None:
        assert (DiagnosticCode.SCHEDULE_MISMATCH_TRIP & 0xFFFF) == 0xEE31
        assert (0xFFFF & DiagnosticCode.SCHEDULE_MISMATCH_TRIP) == 0xEE31
        assert (DiagnosticCode.JITTER_EXCEEDED_TRIP & 0xFFFF) == 0xEE32
        assert (DiagnosticCode.GUARD_BAND_VIOLATION & 0xFFFF) == 0xEE33
        assert (DiagnosticCode.PREEMPTION_FAIL_TRIP & 0xFFFF) == 0xEE34

        diag_set = {
            DiagnosticCode.OK,
            DiagnosticCode.SCHEDULE_MISMATCH_TRIP,
            DiagnosticCode.JITTER_EXCEEDED_TRIP,
            DiagnosticCode.GUARD_BAND_VIOLATION,
            DiagnosticCode.PREEMPTION_FAIL_TRIP,
        }
        assert len(diag_set) == 5
        assert DiagnosticCode.OK in diag_set
        assert DiagnosticCode.SCHEDULE_MISMATCH_TRIP in diag_set
        assert DiagnosticCode.JITTER_EXCEEDED_TRIP in diag_set
        assert DiagnosticCode.GUARD_BAND_VIOLATION in diag_set
        assert DiagnosticCode.PREEMPTION_FAIL_TRIP in diag_set

    def test_diagnostic_code_aliases(self) -> None:
        assert DiagnosticCode.SAFETY_OK == DiagnosticCode.OK
        assert DiagnosticCode.TSN_OK == DiagnosticCode.OK
        assert DiagnosticCode.SCHEDULE_MISMATCH == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        assert DiagnosticCode.ERR_SCHEDULE_MISMATCH == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        assert DiagnosticCode.JITTER_EXCEEDED == DiagnosticCode.JITTER_EXCEEDED_TRIP
        assert DiagnosticCode.ERR_JITTER_EXCEEDED == DiagnosticCode.JITTER_EXCEEDED_TRIP
        assert DiagnosticCode.GUARD_BAND_TRIP == DiagnosticCode.GUARD_BAND_VIOLATION
        assert DiagnosticCode.ERR_GUARD_BAND_VIOLATION == DiagnosticCode.GUARD_BAND_VIOLATION
        assert DiagnosticCode.PREEMPTION_FAIL == DiagnosticCode.PREEMPTION_FAIL_TRIP
        assert DiagnosticCode.ERR_PREEMPTION_FAIL == DiagnosticCode.PREEMPTION_FAIL_TRIP

        assert DIAG_OK == DiagnosticCode.OK
        assert DIAG_SCHEDULE_MISMATCH_TRIP == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        assert DIAG_JITTER_EXCEEDED_TRIP == DiagnosticCode.JITTER_EXCEEDED_TRIP
        assert DIAG_GUARD_BAND_VIOLATION == DiagnosticCode.GUARD_BAND_VIOLATION
        assert DIAG_PREEMPTION_FAIL_TRIP == DiagnosticCode.PREEMPTION_FAIL_TRIP

        assert DiagnosticStatusCode == DiagnosticCode
        assert TSNDiagnosticCode == DiagnosticCode
        assert TsnDiagnosticCode == DiagnosticCode
        assert CipSafetyTsnDiagnosticCode == DiagnosticCode
        assert TSNDiagnosticStatusCode == DiagnosticCode


# ============================================================================
# 2. TestDualCrcAndPacketFraming
# ============================================================================

class TestDualCrcAndPacketFraming:
    """Validate dual CRC-S1 / CRC-S2 calculation, sequence diversification, and corruption detection."""

    def test_crc_calculation_distinct(self) -> None:
        payload = b"HornerOCS-TSN-CIP-Safety-Payload-W259"
        c1 = compute_crc_s1(payload)
        c2 = compute_crc_s2(payload)

        assert 0 <= c1 <= 0xFFFF
        assert 0 <= c2 <= 0xFFFF
        assert c1 != 0 and c2 != 0
        assert c1 != c2  # Distinct polynomials 0x5935 vs 0x755B
        assert calc_crc_s1(payload) == c1
        assert calc_crc_s2(payload) == c2

    def test_crc_multi_argument_joining(self) -> None:
        p1 = b"TSN-Gate-"
        p2 = b"Schedule-Qbv"
        combined = b"TSN-Gate-Schedule-Qbv"
        assert compute_crc_s1(p1, p2) == compute_crc_s1(combined)
        assert compute_crc_s2(p1, p2) == compute_crc_s2(combined)

    def test_crc_invalid_argument_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_crc_s1(12345)  # type: ignore
        with pytest.raises(ValueError):
            compute_crc_s2(12345)  # type: ignore

    def test_verify_dual_crc_s_helper(self) -> None:
        d1 = b"PrimaryData-TSN"
        d2 = b"DiversifiedData-TSN"
        c1 = compute_crc_s1(d1)
        c2 = compute_crc_s2(d2)

        assert verify_dual_crc_s(d1, d2, c1, c2) is True
        assert verify_dual_crc_s(d1, d2, c1 ^ 1, c2) is False
        assert verify_dual_crc_s(d1, d2, c1, c2 ^ 1) is False

    def test_packet_creation_and_crc_verification(self) -> None:
        pkt = create_valid_tsn_safety_packet(sequence_primary=42)
        assert pkt.sequence_primary == 42
        assert pkt.sequence_diversified == (~42) & 0xFFFF
        assert pkt.verify_sequence() is True
        assert pkt.verify_crcs() is True

        pkt2 = create_valid_cip_safety_tsn_packet(sequence_primary=100)
        assert pkt2.verify_sequence() is True
        assert pkt2.verify_crcs() is True

    def test_packet_payload_mutation_detected(self) -> None:
        pkt = create_valid_tsn_safety_packet(sequence_primary=77)
        assert pkt.verify_crcs() is True

        # Mutate payload bit
        pkt.mutate_bit(byte_offset=0, bit_pos=3)
        assert pkt.verify_crcs() is False

    def test_packet_sequence_diversification_check(self) -> None:
        pkt = create_valid_tsn_safety_packet(sequence_primary=200)
        assert pkt.verify_sequence() is True

        # Corrupt diversified sequence
        pkt.sequence_diversified = pkt.sequence_primary
        assert pkt.verify_sequence() is False


# ============================================================================
# 3. TestStateTransitions
# ============================================================================

class TestStateTransitions:
    """Validate TSN gate state transitions: CLOSED -> PREEMPTABLE -> EXPRESS_OPEN -> GUARD_BAND -> FAILSAFE."""

    def test_gate_state_evaluation_throughout_cycle(self) -> None:
        engine = CIPSafetyTSNEngine(
            cycle_time_us=1000,
            schedule_offset_us=250,
            express_duration_us=250,
            guard_band_duration_us=50,
            auto_activate=True,
        )
        # Schedule layout:
        # Preemptable: 0..200 us
        # Guard Band: 200..250 us
        # Express Scheduled Open: 250..500 us
        # Preemptable: 500..1000 us

        assert engine.evaluate_gate_state_at_time(0.0) == TSNGateState.PREEMPTABLE_OPEN
        assert engine.evaluate_gate_state_at_time(150.0) == TSNGateState.PREEMPTABLE_OPEN
        assert engine.evaluate_gate_state_at_time(200.0) == TSNGateState.GUARD_BAND_ACTIVE
        assert engine.evaluate_gate_state_at_time(249.0) == TSNGateState.GUARD_BAND_ACTIVE
        assert engine.evaluate_gate_state_at_time(250.0) == TSNGateState.EXPRESS_SCHEDULED_OPEN
        assert engine.evaluate_gate_state_at_time(350.0) == TSNGateState.EXPRESS_SCHEDULED_OPEN
        assert engine.evaluate_gate_state_at_time(499.0) == TSNGateState.EXPRESS_SCHEDULED_OPEN
        assert engine.evaluate_gate_state_at_time(500.0) == TSNGateState.PREEMPTABLE_OPEN
        assert engine.evaluate_gate_state_at_time(900.0) == TSNGateState.PREEMPTABLE_OPEN
        assert engine.evaluate_gate_state_at_time(1250.0) == TSNGateState.EXPRESS_SCHEDULED_OPEN

    def test_inactive_initial_state_closed(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=False)

        assert engine.gate_state == TSNGateState.CLOSED
        assert engine.schedule_synced is False
        assert engine.is_healthy is False
        assert rt.read_word("%R2200") == 0
        assert rt.read_bit("%M513") is False

    def test_state_properties_and_setters(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.gate_state = TSNGateState.PREEMPTABLE_OPEN
        assert engine.gate_state == TSNGateState.PREEMPTABLE_OPEN
        assert rt.read_word("%R2200") == 1

        engine.gate_state = TSNGateState.EXPRESS_SCHEDULED_OPEN
        assert engine.gate_state == TSNGateState.EXPRESS_SCHEDULED_OPEN
        assert rt.read_word("%R2200") == 2

        engine.gate_state = TSNGateState.GUARD_BAND_ACTIVE
        assert engine.gate_state == TSNGateState.GUARD_BAND_ACTIVE
        assert rt.read_word("%R2200") == 3

        engine.gate_state = TSNGateState.FAILSAFE_CLOSED
        assert engine.gate_state == TSNGateState.FAILSAFE_CLOSED
        assert rt.read_word("%R2200") == 4

    def test_reset_variants_restore_nominal(self) -> None:
        engine = CIPSafetyTSNEngine(auto_activate=True)
        engine.trip_fault(DiagnosticCode.SCHEDULE_MISMATCH_TRIP)
        assert engine.gate_state == TSNGateState.FAILSAFE_CLOSED
        assert engine.interlock_tripped is True
        assert engine.is_healthy is False

        engine.reset()
        assert engine.gate_state == TSNGateState.EXPRESS_SCHEDULED_OPEN
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.interlock_tripped is False
        assert engine.schedule_synced is True
        assert engine.is_healthy is True

        # operator_reset and fault_reset aliases
        engine.trip_fault(DiagnosticCode.JITTER_EXCEEDED_TRIP)
        engine.operator_reset()
        assert engine.is_healthy is True

        engine.trip_fault(DiagnosticCode.GUARD_BAND_VIOLATION)
        engine.fault_reset()
        assert engine.is_healthy is True


# ============================================================================
# 4. TestScheduleMismatchTrip
# ============================================================================

class TestScheduleMismatchTrip:
    """Validate schedule mismatch surveillance and 0xEE31 safe stop trip."""

    def test_express_packet_outside_window_trips_mismatch(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        # Force gate state to PREEMPTABLE_OPEN
        engine.gate_state = TSNGateState.PREEMPTABLE_OPEN
        pkt = engine.create_packet(seq=1)

        assert engine.process_express_packet(pkt) is False
        assert engine.diagnostic_code == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        assert engine.diagnostic_code == 0xEE31
        assert engine.diagnostic_code == -4559
        assert engine.gate_state == TSNGateState.FAILSAFE_CLOSED
        assert engine.interlock_tripped is True
        assert engine.schedule_synced is False
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2200") == 4
        assert rt.read_uword("%R2207") == 0xEE31
        assert rt.read_word("%R2207") == -4559
        assert rt.read_bit("%M513") is False
        assert rt.read_bit("%M514") is True

    def test_express_packet_during_guard_band_trips_mismatch(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.gate_state = TSNGateState.GUARD_BAND_ACTIVE
        pkt = engine.create_packet(seq=2)

        assert engine.process_express_packet(pkt) is False
        assert engine.diagnostic_code == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        assert rt.read_uword("%R2207") == 0xEE31

    def test_express_packet_corrupted_crc_trips_mismatch(self) -> None:
        engine = CIPSafetyTSNEngine(auto_activate=True)
        engine.gate_state = TSNGateState.EXPRESS_SCHEDULED_OPEN

        pkt = engine.create_packet(seq=3)
        pkt.crc_s1 ^= 0xABCD  # Corrupt CRC-S1

        assert engine.process_express_packet(pkt) is False
        assert engine.diagnostic_code == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        assert engine.is_tripped is True

    def test_express_packet_corrupted_sequence_trips_mismatch(self) -> None:
        engine = CIPSafetyTSNEngine(auto_activate=True)
        engine.gate_state = TSNGateState.EXPRESS_SCHEDULED_OPEN

        pkt = engine.create_packet(seq=4)
        pkt.sequence_diversified = pkt.sequence_primary  # Invalidate diversified sequence

        assert engine.process_express_packet(pkt) is False
        assert engine.diagnostic_code == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        assert engine.is_tripped is True

    def test_trip_schedule_mismatch_helper_and_recovery(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.trip_schedule_mismatch("Custom schedule mismatch description")
        assert engine.diagnostic_code == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        assert engine.interlock_tripped is True
        assert rt.read_uword("%R2207") == 0xEE31

        engine.reset()
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.interlock_tripped is False
        assert engine.is_healthy is True
        assert rt.read_uword("%R2207") == 0x0000


# ============================================================================
# 5. TestJitterThresholdExceededTrip
# ============================================================================

class TestJitterThresholdExceededTrip:
    """Validate time-sync jitter watchdog surveillance and 0xEE32 trip handling."""

    def test_nominal_jitter_passes_cleanly(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.update_jitter(45)
        assert engine.max_jitter_ns == 45
        assert engine.jitter_ns == 45
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True
        assert rt.read_word("%R2203") == 45
        assert rt.read_uword("%R2207") == 0x0000
        assert rt.read_bit("%M513") is True
        assert rt.read_bit("%M514") is False

    def test_boundary_jitter_below_100ns(self) -> None:
        engine = CIPSafetyTSNEngine(auto_activate=True)
        engine.update_jitter(99)
        assert engine.max_jitter_ns == 99
        assert engine.is_healthy is True

    def test_jitter_exceeded_trips_at_100ns_and_above(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.update_jitter(100)
        assert engine.diagnostic_code == DiagnosticCode.JITTER_EXCEEDED_TRIP
        assert engine.diagnostic_code == 0xEE32
        assert engine.diagnostic_code == -4558
        assert engine.gate_state == TSNGateState.FAILSAFE_CLOSED
        assert engine.interlock_tripped is True
        assert engine.schedule_synced is False
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2200") == 4
        assert rt.read_word("%R2203") == 100
        assert rt.read_uword("%R2207") == 0xEE32
        assert rt.read_word("%R2207") == -4558
        assert rt.read_bit("%M513") is False
        assert rt.read_bit("%M514") is True

    def test_jitter_watchdog_during_scan_step(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)
        # Invalidate jitter internally
        engine._jitter_ns = 120

        engine.scan_step(0.001)
        assert engine.diagnostic_code == DiagnosticCode.JITTER_EXCEEDED_TRIP
        assert engine.gate_state == TSNGateState.FAILSAFE_CLOSED
        assert rt.read_uword("%R2207") == 0xEE32
        assert rt.read_bit("%M514") is True

    def test_trip_jitter_exceeded_helper_and_recovery(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.trip_jitter_exceeded("Clock oscillator jitter surge")
        assert engine.diagnostic_code == DiagnosticCode.JITTER_EXCEEDED_TRIP
        assert rt.read_uword("%R2207") == 0xEE32

        engine.reset()
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.max_jitter_ns == NOMINAL_TSN_MAX_JITTER_NS
        assert engine.is_healthy is True
        assert rt.read_word("%R2203") == 45
        assert rt.read_uword("%R2207") == 0x0000


# ============================================================================
# 6. TestGuardBandViolation
# ============================================================================

class TestGuardBandViolation:
    """Validate guard band window surveillance and 0xEE33 trip handling."""

    def test_preemptable_transmission_in_guard_band_trips(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        # Force gate state to GUARD_BAND_ACTIVE
        engine.gate_state = TSNGateState.GUARD_BAND_ACTIVE
        frame = b"BestEffortEthernetPayload"

        assert engine.transmit_preemptable_frame(frame, duration_us=10) is False
        assert engine.diagnostic_code == DiagnosticCode.GUARD_BAND_VIOLATION
        assert engine.diagnostic_code == 0xEE33
        assert engine.diagnostic_code == -4557
        assert engine.gate_state == TSNGateState.FAILSAFE_CLOSED
        assert engine.interlock_tripped is True
        assert engine.schedule_synced is False

        # Register reflection
        assert rt.read_word("%R2200") == 4
        assert rt.read_uword("%R2207") == 0xEE33
        assert rt.read_word("%R2207") == -4557
        assert rt.read_bit("%M513") is False
        assert rt.read_bit("%M514") is True

    def test_preemptable_transmission_in_express_window_trips(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.gate_state = TSNGateState.EXPRESS_SCHEDULED_OPEN
        frame = b"StandardTcpIpFrame"

        assert engine.transmit_preemptable_frame(frame, duration_us=10) is False
        assert engine.diagnostic_code == DiagnosticCode.GUARD_BAND_VIOLATION
        assert rt.read_uword("%R2207") == 0xEE33

    def test_preemptable_transmission_encroaching_guard_band_trips(self) -> None:
        engine = CIPSafetyTSNEngine(
            cycle_time_us=1000,
            schedule_offset_us=250,
            guard_band_duration_us=50,
            auto_activate=True,
        )
        # guard band starts at 200 us.
        # At time 180 us, available time to guard band is 20 us.
        # A frame with duration 30 us will encroach into the guard band window!
        frame = b"LargeFrameEncroaching"
        res = engine.transmit_preemptable_frame(frame, duration_us=30, current_time_us=180.0)

        assert res is False
        assert engine.diagnostic_code == DiagnosticCode.GUARD_BAND_VIOLATION
        assert engine.interlock_tripped is True

    def test_safe_preemptable_transmission_in_open_window_succeeds(self) -> None:
        engine = CIPSafetyTSNEngine(
            cycle_time_us=1000,
            schedule_offset_us=250,
            guard_band_duration_us=50,
            auto_activate=True,
        )
        # At time 100 us, available time to guard band is 100 us.
        # A frame with duration 20 us finishes well before 200 us!
        frame = b"SafeFrameFitsWindow"
        res = engine.transmit_preemptable_frame(frame, duration_us=20, current_time_us=100.0)

        assert res is True
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True

    def test_trip_guard_band_violation_helper_and_recovery(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.trip_guard_band_violation("Illegal frame egress in guard window")
        assert engine.diagnostic_code == DiagnosticCode.GUARD_BAND_VIOLATION
        assert rt.read_uword("%R2207") == 0xEE33

        engine.reset()
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True
        assert rt.read_uword("%R2207") == 0x0000


# ============================================================================
# 7. TestFramePreemptionFailureTrip
# ============================================================================

class TestFramePreemptionFailureTrip:
    """Validate IEEE 802.1Qbu frame preemption logic and 0xEE34 failure trip."""

    def test_successful_frame_preemption(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        large_frame = b"M" * 128
        frag1, frag2 = engine.preempt_frame(large_frame, fragment_size=64)

        assert len(frag1) == 64
        assert len(frag2) == 64
        assert frag1 + frag2 == large_frame
        assert engine.preemption_count == 1
        assert rt.read_word("%R2204") == 1
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True

    def test_short_frame_preemption_raises_and_trips(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        short_frame = b"TooShort"
        assert len(short_frame) < MIN_PREEMPTABLE_FRAME_LEN

        with pytest.raises(TSNPreemptionFailError):
            engine.preempt_frame(short_frame)

        assert engine.diagnostic_code == DiagnosticCode.PREEMPTION_FAIL_TRIP
        assert engine.diagnostic_code == 0xEE34
        assert engine.diagnostic_code == -4556
        assert engine.gate_state == TSNGateState.FAILSAFE_CLOSED
        assert engine.interlock_tripped is True
        assert engine.schedule_synced is False
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2200") == 4
        assert rt.read_uword("%R2207") == 0xEE34
        assert rt.read_word("%R2207") == -4556
        assert rt.read_bit("%M513") is False
        assert rt.read_bit("%M514") is True

    def test_simulate_preemption_failure_helper(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        engine.simulate_preemption_failure("MAC merge sublayer queue buffer overflow")
        assert engine.diagnostic_code == DiagnosticCode.PREEMPTION_FAIL_TRIP
        assert engine.interlock_tripped is True
        assert rt.read_uword("%R2207") == 0xEE34

        engine.reset()
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True
        assert rt.read_uword("%R2207") == 0x0000


# ============================================================================
# 8. TestRegisterSynchronization
# ============================================================================

class TestRegisterSynchronization:
    """Validate bit-exact Horner OCS register synchronization (%R2200..%R2207, %M513..%M514)."""

    def test_initial_synchronization(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        assert rt.read_word("%R2200") == 2         # EXPRESS_SCHEDULED_OPEN
        assert rt.read_word("%R2201") == 1000      # Cycle time us
        assert rt.read_word("%R2202") == 250       # Schedule offset us
        assert rt.read_word("%R2203") == 45        # Max jitter ns
        assert rt.read_word("%R2204") == 0         # Preemption count
        assert rt.read_word("%R2205") == 100       # Express packet count
        assert rt.read_uword("%R2206") == 0x0739   # Flow priority (PCP 7, Class 0x39)
        assert rt.read_uword("%R2207") == 0x0000   # Diagnostic code OK
        assert rt.read_bit("%M513") is True        # Schedule synced
        assert rt.read_bit("%M514") is False       # Safety interlock tripped

    def test_all_diagnostic_trip_codes_reflection(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        trips = [
            (DiagnosticCode.SCHEDULE_MISMATCH_TRIP, 0xEE31, -4559),
            (DiagnosticCode.JITTER_EXCEEDED_TRIP, 0xEE32, -4558),
            (DiagnosticCode.GUARD_BAND_VIOLATION, 0xEE33, -4557),
            (DiagnosticCode.PREEMPTION_FAIL_TRIP, 0xEE34, -4556),
        ]

        for code, expected_uhex, expected_sword in trips:
            engine.trip_fault(code)
            assert rt.read_word("%R2200") == 4
            assert rt.read_uword("%R2207") == expected_uhex
            assert rt.read_word("%R2207") == expected_sword
            assert rt.read_bit("%M513") is False
            assert rt.read_bit("%M514") is True

            engine.reset()
            assert rt.read_word("%R2200") == 2
            assert rt.read_uword("%R2207") == 0x0000
            assert rt.read_bit("%M513") is True
            assert rt.read_bit("%M514") is False

    def test_express_packet_transmission_counter_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        assert engine.express_packet_count == 100
        assert rt.read_word("%R2205") == 100

        engine.send_express_packet()
        assert engine.express_packet_count == 101
        assert rt.read_word("%R2205") == 101

        engine.send_express_packet()
        assert engine.express_packet_count == 102
        assert rt.read_word("%R2205") == 102

    def test_flow_priority_and_pcp_property_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        # Update flow priority with full word
        engine.flow_priority = 0x063A
        assert engine.flow_priority == 0x063A
        assert engine.pcp == 6
        assert engine.safe_class == 0x3A
        assert rt.read_uword("%R2206") == 0x063A

        # Update flow priority with PCP alone
        engine.flow_priority = 5
        assert engine.pcp == 5
        assert rt.read_word("%R2206") == 5

    def test_safe_write_wrappers(self) -> None:
        rt = RegisterTable()
        # Word wrapping test (> 32767 wraps to signed negative)
        safe_write_word(rt, "%R2200", 40000)
        assert rt.read_word("%R2200") == 40000 - 65536

        # UWord test
        safe_write_uword(rt, "%R2207", 0xEE31)
        assert rt.read_uword("%R2207") == 0xEE31
        assert rt.read_word("%R2207") == -4559

        # Bit test
        safe_write_bit(rt, "%M513", True)
        assert rt.read_bit("%M513") is True
        safe_write_bit(rt, "%M513", False)
        assert rt.read_bit("%M513") is False


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 ST POU verification with SecurityGuard and STParser."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cip_safety_tsn_pure_st() is True
        assert verify_cip_safety_tsn_pure_st(CIP_SAFETY_TSN_PURE_ST_POU) is True
        assert verify_cip_safety_tsn_pure_st(CIP_SAFETY_TSN_SYNC_POU) is True
        assert verify_cip_safety_tsn_pure_st(CIP_SAFETY_TSN_POU) is True
        assert verify_cip_safety_tsn_pure_st(PURE_ST_POU) is True
        assert verify_cip_safety_tsn_pure_st(CipSafetyTsnSync) is True
        assert verify_cip_safety_tsn_pure_st(CipSafetyTsnSyncPOU) is True

    def test_security_guard_and_st_parser(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_TSN_PURE_ST_POU)
        res = STParser.validate_code(CIP_SAFETY_TSN_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CIP_SAFETY_TSN_PURE_ST_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2200", "%R2201", "%R2202", "%R2203",
            "%R2204", "%R2205", "%R2206", "%R2207",
            "%M513", "%M514",
        }
        assert expected_regs.issubset(set(ast.bound_registers))


# ============================================================================
# 10. TestAntiLadderConstructRejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Verify security guard immediately rejects ladder constructs with LadderForbiddenError."""

    @pytest.mark.parametrize(
        "construct",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 10",
            "NETWORK 1",
            "XIC(Channel1);",
            "OTE(Coil1);",
        ],
    )
    def test_ladder_constructs_rejected(self, construct: str) -> None:
        snippet = f"PROGRAM TestLadder\n VAR b : BOOL; END_VAR\n {construct}\n END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Verify ILogicUnit compliance: properties, scan_step, step, execute, reset, and 100-cycle soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        engine = CIPSafetyTSNEngine(auto_activate=True)
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CIPSafetyTSNEngine"
        assert engine.priority == 10
        assert engine.is_enabled is True
        assert engine.is_healthy is True
        assert engine.is_tripped is False
        assert engine.gate_state == TSNGateState.EXPRESS_SCHEDULED_OPEN

    def test_scan_step_and_step(self) -> None:
        engine = CIPSafetyTSNEngine(auto_activate=True)
        assert engine.cycles_count == 0
        engine.scan_step(0.001)
        assert engine.cycles_count == 1

        engine.step(0.001)
        assert engine.cycles_count == 2
        assert engine.cycle_count == 2

    def test_execute_scan_context(self) -> None:
        engine = CIPSafetyTSNEngine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_ms=1.0)
        engine.execute(ctx)
        assert engine.cycles_count == 1

    def test_100_cycle_soak_stability(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyTSNEngine(register_table=rt, auto_activate=True)

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        for cycle_i in range(1, 101):
            engine.scan_step(0.001)
            # Transmit express packet during express window
            if engine.gate_state == TSNGateState.EXPRESS_SCHEDULED_OPEN:
                pkt = engine.create_packet(seq=cycle_i)
                assert engine.process_express_packet(pkt) is True

        snapshot_after = tracemalloc.take_snapshot()
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        heap_growth_kb = sum(st.size_diff for st in stats if st.size_diff > 0) / 1024.0
        tracemalloc.stop()

        assert engine.cycles_count == 100
        assert engine.is_healthy is True
        assert engine.interlock_tripped is False
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert heap_growth_kb < 100.0  # Zero leak tolerance


# ============================================================================
# 12. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Verify 10-stage verification suite export, strict 4-state contract, and exception hierarchy."""

    def test_runner_returns_success(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_tsn_evidence.json"
        res = run_cip_safety_tsn_verification(output_path=str(out_file), work_package="W259")

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["work_package"] == "W259"
        assert res["stages_passed"] == 10
        assert res["total_stages"] == 10
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["stages_passed"] == 10
        assert len(data["data"]["stages"]) == 10
        assert data["data"]["protocol"] == "ODVA CIP Safety Over TSN (IEEE 802.1Qbv / IEEE 802.1Qbu)"

    def test_exception_inheritance(self) -> None:
        assert issubclass(TSNScheduleMismatchError, CIPTSNSafetyError)
        assert issubclass(TSNJitterExceededError, CIPTSNSafetyError)
        assert issubclass(TSNGuardBandViolationError, CIPTSNSafetyError)
        assert issubclass(TSNPreemptionFailError, CIPTSNSafetyError)

        assert issubclass(ScheduleMismatchTripError, CIPSafetyTSNError)
        assert issubclass(JitterExceededTripError, CIPSafetyTSNError)
        assert issubclass(GuardBandViolationTripError, CipSafetyTsnError)
        assert issubclass(PreemptionFailTripError, CipSafetyTsnError)

    def test_engine_class_aliases(self) -> None:
        assert CipSafetyTsnEngine == CIPSafetyTSNEngine
        assert CIPSafetyTsnEngine == CIPSafetyTSNEngine
        assert CipSafetyTSNEngine == CIPSafetyTSNEngine
        assert CIP_SAFETY_TSN_ENGINE == CIPSafetyTSNEngine
        assert TSNEngine == CIPSafetyTSNEngine
        assert TsnEngine == CIPSafetyTSNEngine
        assert CIPSafetyTSNProtocolEngine == CIPSafetyTSNEngine

        assert CipSafetyTsnPacket == CIPSafetyTSNPacket
        assert CIPSafetyTsnPacket == CIPSafetyTSNPacket
        assert CIP_SAFETY_TSN_PACKET == CIPSafetyTSNPacket
        assert TSNSafetyPacket == CIPSafetyTSNPacket
        assert TsnSafetyPacket == CIPSafetyTSNPacket
