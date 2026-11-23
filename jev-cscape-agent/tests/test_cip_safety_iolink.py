"""Comprehensive Unit Test Suite for Wave W271 CIP Safety IO-Link Safety Protocol Engine.

Work Package: W271 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety IO-Link Safety (IEC 61131-9 Safe Sensor/Actuator) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit values, string representations,
   bitwise operations, hashing, enums, register names, coil addresses, and class IDs.
2. TestDualCrcAndFrameIntegrity: CRC-S1 (0x5935), CRC-S2 (0x755B), dual CRC verification, diversified sequence
   counters (~seq & 0xFFFF), frame serialization, and single-bit mutation corruption detection.
3. TestStateTransitions: Progression across CIPSafetyIOLinkState (SAFE_INIT -> SAFE_COMMISSIONING -> SAFE_OPERATIONAL -> SAFE_FAULT_TRIP),
   commission, activate, disconnect, fault trips, and recovery resets.
4. TestOssdMonitoringAndTrip: Dual-channel OSSD monitoring (OSSD1 and OSSD2), OSSDE enable signal, discrepancy detection,
   single-channel drop trip (0xEE71 OSSD_FAULT_TRIP), OSSDE fault trip, coil %M542 assertion, %M541 deassertion,
   register %R2321 update, and recovery reset.
5. TestCrcFaultTrip: Frame CRC-S1 / CRC-S2 corruption detection, rejection of damaged frames, fault trip (0xEE72 CRC_FAULT),
   CRC error counter increment (%R2325), coil %M542 assertion, safe fallback, and reset.
6. TestSequenceCounterAndMismatch: Monotonic increment, 16-bit rollover (65535 -> 0), sequence mismatch detection,
   sequence frozen / non-monotonic trip (0xEE73 SEQUENCE_COUNTER_FAULT), coil %M542 assertion, and recovery reset.
7. TestWatchdogExpirationTrip: Safety communication watchdog surveillance, nominal tracking, watchdog silence expiration
   (0xEE74 WATCHDOG_TIMEOUT_FAULT), safe state fallback to SAFE_FAULT_TRIP, feeding / kicking watchdog, coil %M542 assertion, and reset.
8. TestRegisterSynchronization: %R2320..%R2327 and %M541..%M542 bit-exact synchronization, PrivilegeMode.SYSTEM,
   safe write wrappers (safe_write_word, safe_write_uword, safe_write_bit), register readback verification.
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetyIOLinkSync POU, AST variable memory_address
   and bound registers validation (%R2320..%R2327, %M541..%M542).
10. TestAntiLadderConstructRejection: Rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)
    with LadderForbiddenError.
11. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
    properties validation, 100-cycle continuous soak simulation, and heap boundedness (< 100 KB growth).
12. TestExceptionsAndVerificationRunner: Exception inheritance hierarchy, 9-stage runner execution
    run_cip_safety_iolink_verification(), strict 4-state contract validation, and evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_iolink import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_IOLINK_CLASS_ID,
    CIP_IOLINK_SAFETY_CLASS_ID,
    NOMINAL_CIP_SAFETY_IOLINK_STATE,
    DEFAULT_LINK_STATE,
    NOMINAL_CIP_SAFETY_IOLINK_OSSD_STATE,
    DEFAULT_OSSD_STATE,
    NOMINAL_CIP_SAFETY_IOLINK_CYCLE_TIME_MS,
    DEFAULT_CYCLE_TIME_MS,
    NOMINAL_CIP_SAFETY_IOLINK_DEVICE_ID,
    DEFAULT_DEVICE_ID,
    NOMINAL_CIP_SAFETY_IOLINK_SEQUENCE_COUNTER,
    DEFAULT_SEQUENCE_COUNTER,
    NOMINAL_CIP_SAFETY_IOLINK_CRC_ERROR_COUNT,
    DEFAULT_CRC_ERROR_COUNT,
    NOMINAL_CIP_SAFETY_IOLINK_TX_FRAME_COUNT,
    DEFAULT_TX_FRAME_COUNT,
    NOMINAL_CIP_SAFETY_IOLINK_WATCHDOG_TIMER_US,
    DEFAULT_WATCHDOG_TIMER_US,
    DEFAULT_WATCHDOG_TIMEOUT_US,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    NOMINAL_CIP_SAFETY_IOLINK_DIAGNOSTIC_CODE,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    REG_CIP_SAFETY_IOLINK_STATE,
    REG_CIP_SAFETY_IOLINK_OSSD_STATE,
    REG_CIP_SAFETY_IOLINK_CYCLE_TIME_MS,
    REG_CIP_SAFETY_IOLINK_DEVICE_ID,
    REG_CIP_SAFETY_IOLINK_SEQUENCE_COUNTER,
    REG_CIP_SAFETY_IOLINK_CRC_ERROR_COUNT,
    REG_CIP_SAFETY_IOLINK_WATCHDOG_TIMER_US,
    REG_CIP_SAFETY_IOLINK_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_IOLINK_OPERATIONAL,
    COIL_CIP_SAFETY_IOLINK_TRIPPED,
    REG_IOLINK_SAFETY_STATE,
    REG_IOLINK_STATE,
    REG_CIP_IOLINK_STATE,
    REG_CIP_SAFETY_IOLINK_LINK_STATE,
    REG_IOLINK_LINK_STATE,
    REG_IOLINK_OSSD_STATE,
    REG_OSSD_STATE,
    REG_OSSD_STATUS_WORD,
    REG_CIP_SAFETY_IOLINK_OSSD_STATUS_WORD,
    REG_IOLINK_CYCLE_TIME_MS,
    REG_CIP_SAFETY_IOLINK_CYCLE_TIME,
    REG_IOLINK_CYCLE_TIME,
    REG_IOLINK_DEVICE_ID,
    REG_CIP_SAFETY_IOLINK_SNN,
    REG_IOLINK_SNN,
    REG_IOLINK_SEQUENCE_COUNTER,
    REG_IOLINK_SEQ_COUNT,
    REG_CIP_SAFETY_IOLINK_SEQ_COUNT,
    REG_IOLINK_CRC_ERROR_COUNT,
    REG_CIP_SAFETY_IOLINK_TX_FRAME_COUNT,
    REG_IOLINK_TX_COUNT,
    REG_IOLINK_TX_FRAMES,
    REG_CIP_IOLINK_TX_FRAMES,
    REG_IOLINK_WATCHDOG_TIMER_US,
    REG_CIP_SAFETY_IOLINK_WATCHDOG_MS,
    REG_IOLINK_WATCHDOG_MS,
    REG_IOLINK_WATCHDOG_TIMER,
    REG_IOLINK_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_CODE,
    REG_IOLINK_DIAG_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_CIP_SAFETY_IOLINK_DIAG_CODE,
    COIL_IOLINK_OPERATIONAL,
    COIL_IOLINK_SAFETY_OPERATIONAL,
    COIL_IOLINK_LINK_HEALTHY,
    COIL_CIP_SAFETY_IOLINK_HEALTHY,
    COIL_SAFETY_OPERATIONAL,
    COIL_SAFETY_LINK_HEALTHY,
    COIL_IOLINK_TRIPPED,
    COIL_IOLINK_SAFETY_TRIPPED,
    COIL_IOLINK_SAFE_STOP_TRIPPED,
    COIL_CIP_SAFETY_IOLINK_STOP_TRIPPED,
    COIL_SAFETY_TRIPPED,
    COIL_SAFETY_STOP_TRIPPED,
    COIL_SAFE_STOP_TRIPPED,
    DiagnosticCode,
    DIAG_OK,
    DIAG_OSSD_FAULT_TRIP,
    DIAG_CRC_FAULT,
    DIAG_SEQUENCE_COUNTER_FAULT,
    DIAG_WATCHDOG_TIMEOUT_FAULT,
    DiagnosticStatusCode,
    IOLinkDiagnosticCode,
    CIPSafetyIOLinkDiagnosticCode,
    CIPSafetyIOLinkState,
    SafeIOLinkState,
    IOLinkSafetyState,
    CipIOLinkSafetyState,
    CIPSafetyIOLinkError,
    IOLinkOssdFaultError,
    IOLinkCrcFaultError,
    IOLinkSequenceFaultError,
    IOLinkWatchdogTimeoutError,
    CIP_SAFETY_IOLINK_PURE_ST_POU,
    CIP_SAFETY_IOLINK_SYNC_POU,
    CIP_SAFETY_IOLINK_POU,
    PURE_ST_POU,
    CipSafetyIOLinkSync,
    verify_cip_safety_iolink_pure_st,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPSafeIOLinkPacket,
    CIPSafeIOLinkFrame,
    CIPSafetyIOLinkPacket,
    CIPSafetyIOLinkFrame,
    IOLinkSafetyPacket,
    IOLinkSafetyFrame,
    create_valid_iolink_packet,
    create_valid_iolink_frame,
    create_valid_packet,
    CIPSafetyIOLinkEngine,
    CipSafetyIOLinkEngine,
    CIPSafetyIoLinkEngine,
    IOLinkSafetyEngine,
    CIP_SAFETY_IOLINK_ENGINE,
    run_cip_safety_iolink_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety IO-Link Safety protocol constants, class IDs, enums, and diagnostic codes."""

    def test_class_ids_and_protocol_constants(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_IOLINK_CLASS_ID == 0x48
        assert CIP_IOLINK_SAFETY_CLASS_ID == 0x48

        assert NOMINAL_CIP_SAFETY_IOLINK_STATE == 2
        assert DEFAULT_LINK_STATE == 2

        assert NOMINAL_CIP_SAFETY_IOLINK_OSSD_STATE == 0x0003
        assert DEFAULT_OSSD_STATE == 0x0003

        assert NOMINAL_CIP_SAFETY_IOLINK_CYCLE_TIME_MS == 5
        assert DEFAULT_CYCLE_TIME_MS == 5

        assert NOMINAL_CIP_SAFETY_IOLINK_DEVICE_ID == 0x0123
        assert DEFAULT_DEVICE_ID == 0x0123

        assert NOMINAL_CIP_SAFETY_IOLINK_SEQUENCE_COUNTER == 0
        assert DEFAULT_SEQUENCE_COUNTER == 0

        assert NOMINAL_CIP_SAFETY_IOLINK_CRC_ERROR_COUNT == 0
        assert DEFAULT_CRC_ERROR_COUNT == 0

        assert NOMINAL_CIP_SAFETY_IOLINK_TX_FRAME_COUNT == 100
        assert DEFAULT_TX_FRAME_COUNT == 100

        assert NOMINAL_CIP_SAFETY_IOLINK_WATCHDOG_TIMER_US == 5000
        assert DEFAULT_WATCHDOG_TIMER_US == 5000
        assert DEFAULT_WATCHDOG_TIMEOUT_US == 20000
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 20.0

        assert NOMINAL_CIP_SAFETY_IOLINK_DIAGNOSTIC_CODE == 0x0000
        assert DEFAULT_SAFETY_NETWORK_NUMBER == 0x3A4B
        assert DEFAULT_SNN == 0x3A4B

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S_INIT == 0xFFFF

    def test_canonical_register_and_coil_mappings(self) -> None:
        assert REG_CIP_SAFETY_IOLINK_STATE == "%R2320"
        assert REG_CIP_SAFETY_IOLINK_OSSD_STATE == "%R2321"
        assert REG_CIP_SAFETY_IOLINK_CYCLE_TIME_MS == "%R2322"
        assert REG_CIP_SAFETY_IOLINK_DEVICE_ID == "%R2323"
        assert REG_CIP_SAFETY_IOLINK_SEQUENCE_COUNTER == "%R2324"
        assert REG_CIP_SAFETY_IOLINK_CRC_ERROR_COUNT == "%R2325"
        assert REG_CIP_SAFETY_IOLINK_WATCHDOG_TIMER_US == "%R2326"
        assert REG_CIP_SAFETY_IOLINK_DIAGNOSTIC_CODE == "%R2327"

        assert COIL_CIP_SAFETY_IOLINK_OPERATIONAL == "%M541"
        assert COIL_CIP_SAFETY_IOLINK_TRIPPED == "%M542"

    def test_register_and_coil_aliases(self) -> None:
        assert REG_IOLINK_SAFETY_STATE == "%R2320"
        assert REG_IOLINK_STATE == "%R2320"
        assert REG_CIP_IOLINK_STATE == "%R2320"
        assert REG_CIP_SAFETY_IOLINK_LINK_STATE == "%R2320"
        assert REG_IOLINK_LINK_STATE == "%R2320"

        assert REG_IOLINK_OSSD_STATE == "%R2321"
        assert REG_OSSD_STATE == "%R2321"
        assert REG_OSSD_STATUS_WORD == "%R2321"
        assert REG_CIP_SAFETY_IOLINK_OSSD_STATUS_WORD == "%R2321"

        assert REG_IOLINK_CYCLE_TIME_MS == "%R2322"
        assert REG_CIP_SAFETY_IOLINK_CYCLE_TIME == "%R2322"
        assert REG_IOLINK_CYCLE_TIME == "%R2322"

        assert REG_IOLINK_DEVICE_ID == "%R2323"
        assert REG_CIP_SAFETY_IOLINK_SNN == "%R2323"
        assert REG_IOLINK_SNN == "%R2323"

        assert REG_IOLINK_SEQUENCE_COUNTER == "%R2324"
        assert REG_IOLINK_SEQ_COUNT == "%R2324"
        assert REG_CIP_SAFETY_IOLINK_SEQ_COUNT == "%R2324"

        assert REG_IOLINK_CRC_ERROR_COUNT == "%R2325"
        assert REG_CIP_SAFETY_IOLINK_TX_FRAME_COUNT == "%R2325"
        assert REG_IOLINK_TX_COUNT == "%R2325"
        assert REG_IOLINK_TX_FRAMES == "%R2325"
        assert REG_CIP_IOLINK_TX_FRAMES == "%R2325"

        assert REG_IOLINK_WATCHDOG_TIMER_US == "%R2326"
        assert REG_CIP_SAFETY_IOLINK_WATCHDOG_MS == "%R2326"
        assert REG_IOLINK_WATCHDOG_MS == "%R2326"
        assert REG_IOLINK_WATCHDOG_TIMER == "%R2326"

        assert REG_IOLINK_DIAGNOSTIC_CODE == "%R2327"
        assert REG_DIAGNOSTIC_CODE == "%R2327"
        assert REG_IOLINK_DIAG_CODE == "%R2327"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2327"
        assert REG_CIP_SAFETY_IOLINK_DIAG_CODE == "%R2327"

        assert COIL_IOLINK_OPERATIONAL == "%M541"
        assert COIL_IOLINK_SAFETY_OPERATIONAL == "%M541"
        assert COIL_IOLINK_LINK_HEALTHY == "%M541"
        assert COIL_CIP_SAFETY_IOLINK_HEALTHY == "%M541"
        assert COIL_SAFETY_OPERATIONAL == "%M541"
        assert COIL_SAFETY_LINK_HEALTHY == "%M541"

        assert COIL_IOLINK_TRIPPED == "%M542"
        assert COIL_IOLINK_SAFETY_TRIPPED == "%M542"
        assert COIL_IOLINK_SAFE_STOP_TRIPPED == "%M542"
        assert COIL_CIP_SAFETY_IOLINK_STOP_TRIPPED == "%M542"
        assert COIL_SAFETY_TRIPPED == "%M542"
        assert COIL_SAFETY_STOP_TRIPPED == "%M542"
        assert COIL_SAFE_STOP_TRIPPED == "%M542"

    def test_diagnostic_code_values_and_signed_representations(self) -> None:
        # 0x0000 OK
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.OK == 0
        assert int(DiagnosticCode.OK) == 0x0000
        assert (DiagnosticCode.OK & 0xFFFF) == 0x0000

        # 0xEE71 OSSD_FAULT_TRIP (-4495 in signed 16-bit)
        assert DiagnosticCode.OSSD_FAULT_TRIP == 0xEE71
        assert DiagnosticCode.OSSD_FAULT_TRIP == (0xEE71 - 0x10000)
        assert DiagnosticCode.OSSD_FAULT_TRIP == -4495
        assert (DiagnosticCode.OSSD_FAULT_TRIP & 0xFFFF) == 0xEE71

        # 0xEE72 CRC_FAULT (-4494 in signed 16-bit)
        assert DiagnosticCode.CRC_FAULT == 0xEE72
        assert DiagnosticCode.CRC_FAULT == (0xEE72 - 0x10000)
        assert DiagnosticCode.CRC_FAULT == -4494
        assert (DiagnosticCode.CRC_FAULT & 0xFFFF) == 0xEE72

        # 0xEE73 SEQUENCE_COUNTER_FAULT (-4493 in signed 16-bit)
        assert DiagnosticCode.SEQUENCE_COUNTER_FAULT == 0xEE73
        assert DiagnosticCode.SEQUENCE_COUNTER_FAULT == (0xEE73 - 0x10000)
        assert DiagnosticCode.SEQUENCE_COUNTER_FAULT == -4493
        assert (DiagnosticCode.SEQUENCE_COUNTER_FAULT & 0xFFFF) == 0xEE73

        # 0xEE74 WATCHDOG_TIMEOUT_FAULT (-4492 in signed 16-bit)
        assert DiagnosticCode.WATCHDOG_TIMEOUT_FAULT == 0xEE74
        assert DiagnosticCode.WATCHDOG_TIMEOUT_FAULT == (0xEE74 - 0x10000)
        assert DiagnosticCode.WATCHDOG_TIMEOUT_FAULT == -4492
        assert (DiagnosticCode.WATCHDOG_TIMEOUT_FAULT & 0xFFFF) == 0xEE74

    def test_diagnostic_code_string_and_repr_representations(self) -> None:
        assert "0x0000" in str(DiagnosticCode.OK)
        assert "0xEE71" in str(DiagnosticCode.OSSD_FAULT_TRIP)
        assert "0xEE72" in str(DiagnosticCode.CRC_FAULT)
        assert "0xEE73" in str(DiagnosticCode.SEQUENCE_COUNTER_FAULT)
        assert "0xEE74" in str(DiagnosticCode.WATCHDOG_TIMEOUT_FAULT)

        assert "DiagnosticCode" in repr(DiagnosticCode.OK)
        assert "DiagnosticCode" in repr(DiagnosticCode.OSSD_FAULT_TRIP)

    def test_diagnostic_code_bitwise_operations(self) -> None:
        code = DiagnosticCode.OSSD_FAULT_TRIP  # 0xEE71
        masked = code & 0xFF00
        assert masked == 0xEE00
        assert isinstance(masked, (int, DiagnosticCode))

        or_res = code | 0x0002
        assert or_res == 0xEE73

        xor_res = code ^ 0x0001
        assert xor_res == 0xEE70

    def test_diagnostic_code_hash_and_dict_keys(self) -> None:
        c1 = DiagnosticCode.OSSD_FAULT_TRIP  # 0xEE71
        c2 = DiagnosticCode.WATCHDOG_TIMEOUT_FAULT  # 0xEE74

        code_set = {c1, c2, DiagnosticCode(0xEE71), DiagnosticCode(-4495)}
        assert len(code_set) == 2
        assert c1 in code_set
        assert c2 in code_set
        assert DiagnosticCode(-4492) in code_set

        d = {
            DiagnosticCode.OK: "healthy",
            DiagnosticCode.OSSD_FAULT_TRIP: "ossd_trip",
            DiagnosticCode.CRC_FAULT: "crc_corrupted",
            DiagnosticCode.SEQUENCE_COUNTER_FAULT: "seq_fault",
            DiagnosticCode.WATCHDOG_TIMEOUT_FAULT: "watchdog_trip",
        }
        assert d[0x0000] == "healthy"
        assert d[0xEE71] == "ossd_trip"
        assert d[DiagnosticCode(-4495)] == "ossd_trip"
        assert d[0xEE72] == "crc_corrupted"
        assert d[0xEE73] == "seq_fault"
        assert d[0xEE74] == "watchdog_trip"

    def test_state_machine_enums_and_aliases(self) -> None:
        assert CIPSafetyIOLinkState.SAFE_INIT == 0
        assert CIPSafetyIOLinkState.SAFE_COMMISSIONING == 1
        assert CIPSafetyIOLinkState.SAFE_OPERATIONAL == 2
        assert CIPSafetyIOLinkState.SAFE_FAULT_TRIP == 3

        assert SafeIOLinkState is CIPSafetyIOLinkState
        assert IOLinkSafetyState is CIPSafetyIOLinkState
        assert CipIOLinkSafetyState is CIPSafetyIOLinkState

        assert CIPSafetyIOLinkState.SafeInit == 0
        assert CIPSafetyIOLinkState.SafeCommissioning == 1
        assert CIPSafetyIOLinkState.SafeOperational == 2
        assert CIPSafetyIOLinkState.SafeFaultTrip == 3
        assert CIPSafetyIOLinkState.OPERATIONAL == 2
        assert CIPSafetyIOLinkState.TRIPPED == 3


# ============================================================================
# 2. TestDualCrcAndFrameIntegrity
# ============================================================================

class TestDualCrcAndFrameIntegrity:
    """Validate CRC-S1 (0x5935), CRC-S2 (0x755B), diversified sequence, and frame mutation detection."""

    def test_crc_s1_and_crc_s2_calculation_deterministic(self) -> None:
        test_payload = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        crc1 = compute_crc_s1(test_payload)
        crc2 = compute_crc_s2(test_payload)

        assert 0 <= crc1 <= 0xFFFF
        assert 0 <= crc2 <= 0xFFFF
        assert crc1 != crc2
        # Repeatability
        assert compute_crc_s1(test_payload) == crc1
        assert compute_crc_s2(test_payload) == crc2
        assert calc_crc_s1(test_payload) == crc1
        assert calc_crc_s2(test_payload) == crc2

    def test_frame_serialization_crc_s1_and_crc_s2(self) -> None:
        pkt = CIPSafeIOLinkPacket(
            device_id=0x0123,
            sequence_primary=10,
            ossd1=True,
            ossd2=True,
            ossde=True,
            cycle_time_ms=5,
            watchdog_timer_us=5000,
            payload=b"\x10\x20\x30\x40",
        )
        s1_bytes = pkt.serialize_for_crc_s1()
        s2_bytes = pkt.serialize_for_crc_s2()

        assert len(s1_bytes) == len(s2_bytes)
        assert s1_bytes != s2_bytes
        # Verify sequence diversification in s2_bytes
        expected_div = (~10) & 0xFFFF
        assert pkt.sequence_diversified == expected_div

    def test_diversified_sequence_inversion(self) -> None:
        for seq in [0, 1, 42, 255, 1000, 32767, 65534, 65535]:
            pkt = create_valid_iolink_packet(sequence_primary=seq)
            assert pkt.sequence_primary == seq
            assert pkt.sequence_diversified == ((~seq) & 0xFFFF)
            assert pkt.verify_sequence() is True

    def test_frame_single_bit_mutation_detection(self) -> None:
        pkt = create_valid_iolink_packet(sequence_primary=123, payload=b"\xAA\xBB\xCC\xDD")
        assert pkt.verify_crcs() is True

        # Mutate bit in payload
        for bit in range(8):
            mutated = create_valid_iolink_packet(sequence_primary=123, payload=b"\xAA\xBB\xCC\xDD")
            mutated.mutate_bit(byte_offset=0, bit_pos=bit)
            assert mutated.verify_crcs() is False

    def test_frame_multi_byte_mutation_detection(self) -> None:
        pkt = create_valid_iolink_packet(sequence_primary=77, payload=b"\xDE\xAD\xBE\xEF")
        assert pkt.verify_crcs() is True

        pkt.payload = b"\xDE\xAD\xBE\xEE"  # mutated last byte
        assert pkt.verify_crcs() is False

    def test_valid_frame_factory_helper(self) -> None:
        pkt = create_valid_iolink_packet(
            sequence_primary=99,
            device_id=0x0123,
            ossd1=True,
            ossd2=True,
            ossde=True,
        )
        assert isinstance(pkt, CIPSafeIOLinkPacket)
        assert pkt.verify_crcs() is True
        assert pkt.verify_sequence() is True
        assert pkt.verify_snn(DEFAULT_SNN) is True

    def test_frame_property_setters(self) -> None:
        pkt = create_valid_iolink_packet(sequence_primary=10)
        pkt.sequence_number = 20
        assert pkt.sequence_primary == 20
        assert pkt.sequence_diversified == ((~20) & 0xFFFF)
        assert pkt.verify_sequence() is True


# ============================================================================
# 3. TestStateTransitions
# ============================================================================

class TestStateTransitions:
    """Validate progression across SafeIOLinkState: SAFE_INIT -> SAFE_COMMISSIONING -> SAFE_OPERATIONAL -> SAFE_FAULT_TRIP."""

    def test_initial_state_auto_activate_true(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        assert eng.state == CIPSafetyIOLinkState.SAFE_OPERATIONAL
        assert eng.is_healthy is True
        assert eng.is_safe_stop_tripped is False
        assert eng.diagnostic_code == DiagnosticCode.OK
        assert rt.read_word("%R2320") == 2
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_initial_state_auto_activate_false(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=False)
        assert eng.state == CIPSafetyIOLinkState.SAFE_INIT
        assert eng.is_healthy is False
        assert eng.is_safe_stop_tripped is True
        assert rt.read_word("%R2320") == 0
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_commission_transition(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=False)
        assert eng.commission() is True
        assert eng.state == CIPSafetyIOLinkState.SAFE_COMMISSIONING
        assert rt.read_word("%R2320") == 1

    def test_activate_transition(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=False)
        eng.commission()
        assert eng.activate() is True
        assert eng.state == CIPSafetyIOLinkState.SAFE_OPERATIONAL
        assert eng.is_healthy is True
        assert rt.read_word("%R2320") == 2
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_disconnect_transition(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.disconnect()
        assert eng.state == CIPSafetyIOLinkState.SAFE_INIT
        assert eng.is_healthy is False
        assert rt.read_word("%R2320") == 0
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_trip_fault_transition(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_fault(DiagnosticCode.OSSD_FAULT_TRIP, "Test trip")
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.OSSD_FAULT_TRIP
        assert eng.is_healthy is False
        assert eng.is_safe_stop_tripped is True
        assert rt.read_word("%R2320") == 3
        assert rt.read_uword("%R2327") == 0xEE71
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_reset_recovery_transition(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_fault(DiagnosticCode.OSSD_FAULT_TRIP, "Test trip")
        assert eng.is_safe_stop_tripped is True

        eng.reset()
        assert eng.state == CIPSafetyIOLinkState.SAFE_OPERATIONAL
        assert eng.diagnostic_code == DiagnosticCode.OK
        assert eng.is_healthy is True
        assert eng.is_safe_stop_tripped is False
        assert rt.read_word("%R2320") == 2
        assert rt.read_uword("%R2327") == 0x0000
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_state_equality_and_int_conversion(self) -> None:
        st = CIPSafetyIOLinkState.SAFE_OPERATIONAL
        assert int(st) == 2
        assert st == 2
        assert st != 3


# ============================================================================
# 4. TestOssdMonitoringAndTrip
# ============================================================================

class TestOssdMonitoringAndTrip:
    """Validate dual-channel OSSD monitoring (OSSD1 and OSSD2), OSSDE enable signal, and fault trips (0xEE71)."""

    def test_nominal_ossd_monitoring_healthy(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_ossd(ossd1=True, ossd2=True, ossde=True)
        assert res is True
        assert eng.is_healthy is True
        assert eng.ossd_status_word == 0x0007
        assert rt.read_word("%R2321") == 0x0007
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_ossd1_drop_trips_fault(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_ossd(ossd1=False, ossd2=True, ossde=True)
        assert res is False
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.OSSD_FAULT_TRIP
        assert eng.ossd_status_word == 0x0006  # bit1 (OSSD2) + bit2 (OSSDE)
        assert rt.read_word("%R2321") == 0x0006
        assert rt.read_uword("%R2327") == 0xEE71
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_ossd2_drop_trips_fault(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_ossd(ossd1=True, ossd2=False, ossde=True)
        assert res is False
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.OSSD_FAULT_TRIP
        assert eng.ossd_status_word == 0x0005  # bit0 (OSSD1) + bit2 (OSSDE)
        assert rt.read_word("%R2321") == 0x0005
        assert rt.read_uword("%R2327") == 0xEE71
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_dual_ossd_drop_trips_fault(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_ossd(ossd1=False, ossd2=False, ossde=True)
        assert res is False
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.OSSD_FAULT_TRIP
        assert eng.ossd_status_word == 0x0004  # bit2 only (OSSDE)
        assert rt.read_word("%R2321") == 0x0004
        assert rt.read_bit("%M542") is True

    def test_ossde_disable_trips_fault(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_ossd(ossd1=True, ossd2=True, ossde=False)
        assert res is False
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.OSSD_FAULT_TRIP
        assert eng.ossd_status_word == 0x0003  # bit0 + bit1, no bit2
        assert rt.read_word("%R2321") == 0x0003
        assert rt.read_bit("%M542") is True

    def test_ossd_status_word_bitmask_representation(self) -> None:
        pkt = CIPSafeIOLinkPacket(ossd1=True, ossd2=True, ossde=True)
        assert pkt.ossd_status_word == 0x0007

        pkt_no_e = CIPSafeIOLinkPacket(ossd1=True, ossd2=True, ossde=False)
        assert pkt_no_e.ossd_status_word == 0x0003

        pkt_o1_only = CIPSafeIOLinkPacket(ossd1=True, ossd2=False, ossde=False)
        assert pkt_o1_only.ossd_status_word == 0x0001

        pkt_zero = CIPSafeIOLinkPacket(ossd1=False, ossd2=False, ossde=False)
        assert pkt_zero.ossd_status_word == 0x0000

    def test_ossd_fault_coils_and_registers(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_ossd_fault("Manual OSSD trip")
        assert rt.read_word("%R2320") == 3
        assert rt.read_uword("%R2327") == 0xEE71
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_ossd_fault_recovery_after_reset(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.monitor_ossd(ossd1=False, ossd2=True, ossde=True)
        assert eng.is_safe_stop_tripped is True

        eng.reset()
        assert eng.is_healthy is True
        assert eng.ossd1 is True
        assert eng.ossd2 is True
        assert eng.ossde is True
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_process_packet_with_ossd_failure(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        pkt_bad_ossd = create_valid_iolink_packet(sequence_primary=1, ossd1=False, ossd2=True)
        res = eng.process_packet(pkt_bad_ossd)
        assert res is False
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.OSSD_FAULT_TRIP
        assert rt.read_bit("%M542") is True


# ============================================================================
# 5. TestCrcFaultTrip
# ============================================================================

class TestCrcFaultTrip:
    """Validate safe CRC-S1 / CRC-S2 corruption detection and fault trip (0xEE72)."""

    def test_corrupted_crc_s1_frame_rejected(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        pkt = create_valid_iolink_packet(sequence_primary=1)
        pkt.crc_s1 ^= 0x0001  # Corrupt CRC-S1
        res = eng.process_packet(pkt)
        assert res is False
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.CRC_FAULT
        assert eng.crc_error_count == 1
        assert rt.read_word("%R2325") == 1
        assert rt.read_uword("%R2327") == 0xEE72
        assert rt.read_bit("%M542") is True

    def test_corrupted_crc_s2_frame_rejected(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        pkt = create_valid_iolink_packet(sequence_primary=1)
        pkt.crc_s2 ^= 0x0001  # Corrupt CRC-S2
        res = eng.process_packet(pkt)
        assert res is False
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.CRC_FAULT
        assert eng.crc_error_count == 1
        assert rt.read_uword("%R2327") == 0xEE72
        assert rt.read_bit("%M542") is True

    def test_both_crcs_corrupted_rejected(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        pkt = create_valid_iolink_packet(sequence_primary=1)
        pkt.crc_s1 = 0x0000
        pkt.crc_s2 = 0x0000
        res = eng.process_packet(pkt)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.CRC_FAULT

    def test_trip_crc_fault_increments_error_counter(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        assert eng.crc_error_count == 0
        eng.trip_crc_fault("Test CRC error 1")
        assert eng.crc_error_count == 1
        assert rt.read_word("%R2325") == 1
        eng.trip_crc_fault("Test CRC error 2")
        assert eng.crc_error_count == 2
        assert rt.read_word("%R2325") == 2

    def test_crc_fault_coils_and_registers_reflection(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_crc_fault()
        assert rt.read_word("%R2320") == 3
        assert rt.read_uword("%R2327") == 0xEE72
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_crc_error_recovery_reset(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_crc_fault()
        assert eng.is_safe_stop_tripped is True
        eng.reset()
        assert eng.is_healthy is True
        assert eng.diagnostic_code == DiagnosticCode.OK
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False


# ============================================================================
# 6. TestSequenceCounterAndMismatch
# ============================================================================

class TestSequenceCounterAndMismatch:
    """Validate sequence counter increment, 16-bit rollover, and mismatch detection (0xEE73)."""

    def test_monotonic_sequence_progression(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        for i in range(1, 11):
            pkt = eng.create_packet(seq=i)
            assert eng.process_packet(pkt) is True
            assert eng.sequence_counter == i
            assert rt.read_uword("%R2324") == i

    def test_sequence_counter_rollover_65535(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.sequence_counter = 65535
        eng.frames_processed = 1

        # Next expected sequence is 0
        pkt = eng.create_packet(seq=0)
        assert eng.process_packet(pkt) is True
        assert eng.sequence_counter == 0
        assert rt.read_uword("%R2324") == 0

    def test_sequence_jump_mismatch_detected(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        p1 = eng.create_packet(seq=1)
        assert eng.process_packet(p1) is True

        # Non-monotonic jump: expected 2, receive 5
        p_bad = eng.create_packet(seq=5)
        res = eng.process_packet(p_bad)
        assert res is False
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.SEQUENCE_COUNTER_FAULT
        assert rt.read_uword("%R2327") == 0xEE73
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_diversified_sequence_mismatch_detected(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        pkt = create_valid_iolink_packet(sequence_primary=1)
        pkt.sequence_diversified = 0x1234  # Break ~sequence_primary relationship
        pkt.calculate_crcs()  # Valid CRCs over bad packet
        res = eng.process_packet(pkt)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.SEQUENCE_COUNTER_FAULT
        assert rt.read_uword("%R2327") == 0xEE73

    def test_sequence_fault_trips_safe_state(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_sequence_fault("Sequence jump detected")
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.SEQUENCE_COUNTER_FAULT
        assert rt.read_bit("%M542") is True

    def test_sequence_fault_recovery_reset(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_sequence_fault()
        eng.reset()
        assert eng.is_healthy is True
        assert eng.diagnostic_code == DiagnosticCode.OK
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False


# ============================================================================
# 7. TestWatchdogExpirationTrip
# ============================================================================

class TestWatchdogExpirationTrip:
    """Validate safety communication watchdog surveillance and timeout fallback (0xEE74)."""

    def test_nominal_watchdog_sub_threshold(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True, watchdog_timeout_ms=20.0)
        # Advance 10 ms (below 20 ms timeout)
        eng.scan_step(0.010)
        assert eng.is_healthy is True
        assert eng.diagnostic_code == DiagnosticCode.OK
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_watchdog_silence_expiration_trips_fault(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True, watchdog_timeout_ms=20.0)
        # Advance 25 ms (above 20 ms timeout)
        eng.scan_step(0.025)
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.WATCHDOG_TIMEOUT_FAULT
        assert eng.is_healthy is False
        assert eng.is_safe_stop_tripped is True
        assert rt.read_word("%R2320") == 3
        assert rt.read_uword("%R2327") == 0xEE74
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_watchdog_timeout_diagnostic_code_and_coils(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_watchdog_timeout("Watchdog expired")
        assert rt.read_uword("%R2327") == 0xEE74
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_feed_watchdog_prevents_expiration(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True, watchdog_timeout_ms=20.0)
        # 3 cycles of 8 ms with feeds in between
        for _ in range(3):
            eng.scan_step(0.008)
            assert eng.is_healthy is True
            eng.feed_watchdog()
        assert eng.is_healthy is True
        assert rt.read_bit("%M541") is True

    def test_custom_watchdog_timeout_configuration(self) -> None:
        rt = RegisterTable()
        # Custom timeout 50 ms
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True, watchdog_timeout_ms=50.0)
        eng.scan_step(0.030)
        assert eng.is_healthy is True
        eng.scan_step(0.025)  # total 55 ms > 50 ms
        assert eng.state == CIPSafetyIOLinkState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.WATCHDOG_TIMEOUT_FAULT

    def test_watchdog_fault_recovery_reset(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True, watchdog_timeout_ms=20.0)
        eng.scan_step(0.030)
        assert eng.is_safe_stop_tripped is True
        eng.reset()
        assert eng.is_healthy is True
        assert eng.diagnostic_code == DiagnosticCode.OK
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False


# ============================================================================
# 8. TestRegisterSynchronization
# ============================================================================

class TestRegisterSynchronization:
    """Validate %R2320..%R2327 and %M541..%M542 synchronization with RegisterTable and PrivilegeMode.SYSTEM."""

    def test_sync_to_registers_nominal_operational(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)

        assert rt.read_word("%R2320") == 2
        assert rt.read_word("%R2321") == 0x0007
        assert rt.read_word("%R2322") == 5
        assert rt.read_uword("%R2323") == 0x0123
        assert rt.read_uword("%R2324") == 0
        assert rt.read_word("%R2325") == 0
        assert rt.read_uword("%R2326") == 5000
        assert rt.read_uword("%R2327") == 0x0000

        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_sync_to_registers_privilege_mode_system(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2320", 2, privilege=PrivilegeMode.SYSTEM)
        safe_write_uword(rt, "%R2327", 0x0000, privilege=PrivilegeMode.SYSTEM)
        safe_write_bit(rt, "%M541", True, privilege=PrivilegeMode.SYSTEM)
        safe_write_bit(rt, "%M542", False, privilege=PrivilegeMode.SYSTEM)

        assert rt.read_word("%R2320") == 2
        assert rt.read_uword("%R2327") == 0x0000
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_safe_write_word_bounds_clamping(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2320", 32767)
        assert rt.read_word("%R2320") == 32767

        # Value wrapping
        safe_write_word(rt, "%R2320", 65535)
        assert rt.read_word("%R2320") == -1

    def test_safe_write_uword_bounds(self) -> None:
        rt = RegisterTable()
        safe_write_uword(rt, "%R2327", 0xEE71)
        assert rt.read_uword("%R2327") == 0xEE71
        assert rt.read_word("%R2327") == (0xEE71 - 0x10000)

    def test_safe_write_bit_privilege(self) -> None:
        rt = RegisterTable()
        safe_write_bit(rt, "%M541", True)
        assert rt.read_bit("%M541") is True
        safe_write_bit(rt, "%M541", False)
        assert rt.read_bit("%M541") is False

    def test_sync_after_state_change(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=False)
        assert rt.read_word("%R2320") == 0
        eng.commission()
        assert rt.read_word("%R2320") == 1
        eng.activate()
        assert rt.read_word("%R2320") == 2

    def test_sync_after_fault_trip(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        eng.trip_fault(DiagnosticCode.OSSD_FAULT_TRIP)
        assert rt.read_word("%R2320") == 3
        assert rt.read_uword("%R2327") == 0xEE71
        assert rt.read_bit("%M541") is False
        assert rt.read_bit("%M542") is True

    def test_readback_all_registers_and_coils(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        expected_regs = {
            "%R2320": 2,
            "%R2321": 0x0007,
            "%R2322": 5,
            "%R2323": 0x0123,
            "%R2324": 0,
            "%R2325": 0,
            "%R2326": 5000,
            "%R2327": 0x0000,
        }
        for addr, expected_val in expected_regs.items():
            if addr in ("%R2323", "%R2324", "%R2326", "%R2327"):
                assert rt.read_uword(addr) == expected_val
            else:
                assert rt.read_word(addr) == expected_val
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 ST POU CipSafetyIOLinkSync with STParser and SecurityGuard."""

    def test_verify_cip_safety_iolink_pure_st_pou_default(self) -> None:
        assert verify_cip_safety_iolink_pure_st() is True

    def test_st_parser_pou_type_program(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_IOLINK_PURE_ST_POU)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyIOLinkSync"

    def test_security_guard_assert_pure_st_content_passes(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_IOLINK_PURE_ST_POU)

    def test_bound_registers_contain_all_required_addresses(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_IOLINK_PURE_ST_POU)
        required_registers = {
            "%R2320", "%R2321", "%R2322", "%R2323",
            "%R2324", "%R2325", "%R2326", "%R2327",
            "%M541", "%M542",
        }
        assert required_registers.issubset(set(ast.bound_registers))

    def test_ast_variable_memory_address_bindings(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_IOLINK_PURE_ST_POU)
        var_map = {
            v.name: getattr(v, "address_binding", getattr(v, "memory_address", None))
            for v in ast.variables
        }

        assert var_map["IOLinkSafetyState"] == "%R2320"
        assert var_map["IOLinkOssdStatusWord"] == "%R2321"
        assert var_map["IOLinkCycleTimeMs"] == "%R2322"
        assert var_map["IOLinkDeviceId"] == "%R2323"
        assert var_map["IOLinkSequenceCounter"] == "%R2324"
        assert var_map["IOLinkCrcErrorCount"] == "%R2325"
        assert var_map["IOLinkWatchdogTimerUs"] == "%R2326"
        assert var_map["IOLinkDiagnosticCode"] == "%R2327"
        assert var_map["IOLinkSafetyOperational"] == "%M541"
        assert var_map["IOLinkSafetyTripped"] == "%M542"


# ============================================================================
# 10. TestAntiLadderConstructRejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Validate rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)."""

    def test_reject_ladder_contact_open(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM")

    def test_reject_ladder_contact_closed(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR X: BOOL; END_VAR ---[/]--- END_PROGRAM")

    def test_reject_ladder_coil_normal(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR X: BOOL; END_VAR ---( )--- END_PROGRAM")

    def test_reject_ladder_coil_set_reset(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR X: BOOL; END_VAR ---(S)--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR X: BOOL; END_VAR ---(R)--- END_PROGRAM")

    def test_reject_ladder_rung_delimiters(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P RUNG 1: X := TRUE; END_PROGRAM")

    def test_reject_ladder_network_delimiters(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P NETWORK 1: X := TRUE; END_PROGRAM")

    def test_reject_ladder_mnemonics(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P XIC %I0001 OTE %Q0001 END_PROGRAM")


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Validate ILogicUnit interface compliance, properties, 100-cycle soak, and memory boundedness."""

    def test_ilogicunit_interface_inheritance(self) -> None:
        assert issubclass(CIPSafetyIOLinkEngine, ILogicUnit)

    def test_ilogicunit_properties(self) -> None:
        eng = CIPSafetyIOLinkEngine(auto_activate=True)
        assert eng.name == "CIPSafetyIOLinkEngine"
        assert eng.priority == 10
        assert eng.is_enabled is True
        assert eng.is_healthy is True
        assert eng.is_safe_stop_tripped is False

    def test_step_and_execute_methods(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)
        assert eng.cycles_count == 0

        eng.step(0.005)
        assert eng.cycles_count == 1

        context = ScanContext(cycle=2, dt_ms=5.0)
        eng.execute(context)
        assert eng.cycles_count == 2

    def test_100_cycle_soak_simulation_stability(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)

        for cycle in range(1, 101):
            pkt = eng.create_packet(seq=cycle)
            assert eng.process_packet(pkt) is True
            eng.scan_step(0.005)

        assert eng.cycles_count == 100
        assert eng.sequence_counter == 100
        assert eng.is_healthy is True
        assert rt.read_word("%R2320") == 2
        assert rt.read_uword("%R2324") == 100
        assert rt.read_bit("%M541") is True
        assert rt.read_bit("%M542") is False

    def test_heap_boundedness_memory_growth_under_100kb(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyIOLinkEngine(register_table=rt, auto_activate=True)

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        for cycle in range(1, 101):
            pkt = eng.create_packet(seq=cycle)
            eng.process_packet(pkt)
            eng.scan_step(0.005)

        snapshot_after = tracemalloc.take_snapshot()
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        heap_growth_kb = sum(st.size_diff for st in stats if st.size_diff > 0) / 1024.0
        tracemalloc.stop()

        assert heap_growth_kb < 100.0

    def test_engine_class_aliases(self) -> None:
        assert CipSafetyIOLinkEngine is CIPSafetyIOLinkEngine
        assert CIPSafetyIoLinkEngine is CIPSafetyIOLinkEngine
        assert IOLinkSafetyEngine is CIPSafetyIOLinkEngine
        assert CIP_SAFETY_IOLINK_ENGINE is CIPSafetyIOLinkEngine


# ============================================================================
# 12. TestExceptionsAndVerificationRunner
# ============================================================================

class TestExceptionsAndVerificationRunner:
    """Verify custom exception inheritance, 9-stage verification runner, and strict 4-state contract."""

    def test_exception_inheritance_hierarchy(self) -> None:
        assert issubclass(IOLinkOssdFaultError, CIPSafetyIOLinkError)
        assert issubclass(IOLinkCrcFaultError, CIPSafetyIOLinkError)
        assert issubclass(IOLinkSequenceFaultError, CIPSafetyIOLinkError)
        assert issubclass(IOLinkWatchdogTimeoutError, CIPSafetyIOLinkError)
        assert issubclass(CIPSafetyIOLinkError, Exception)

    def test_verification_runner_execution_success(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        try:
            result = run_cip_safety_iolink_verification(output_path=temp_path)
            assert isinstance(result, dict)
            assert result["status"] == "success"
            assert result["error_code"] is None
            assert result["stages_passed"] == 9
            assert result["total_stages"] == 9
            assert result["work_package"] == "W271"

            # Verify saved JSON evidence
            with open(temp_path, "r", encoding="utf-8") as f:
                saved_evidence = json.load(f)
            assert saved_evidence["status"] == "success"
            assert saved_evidence["stages_passed"] == 9
            assert saved_evidence["total_stages"] == 9
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_verification_runner_saved_evidence_json(self) -> None:
        evidence_file = Path("artifacts/telemetry/cip_safety_iolink_evidence.json")
        res = run_cip_safety_iolink_verification(output_path=str(evidence_file))
        assert res["status"] == "success"
        assert evidence_file.exists()

        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["stages"]) == 9

    def test_strict_4_state_contract_fields(self) -> None:
        res = run_cip_safety_iolink_verification()
        valid_states = {"success", "failed", "blocked", "inconclusive"}
        assert res["status"] in valid_states
        assert "error_code" in res
        assert "details" in res
        assert "data" in res
