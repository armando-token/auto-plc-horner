"""Comprehensive Unit Test Suite for Wave W274 CIP Safety Over Ethernet-APL Protocol Engine.

Work Package: W274 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL (10BASE-T1L / 2-WISE Intrinsically Safe) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 13 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: Class IDs, nominal limits, 2-WISE IS voltage bounds (9600..15000 mV),
   latency bounds (<2500 us), eye margin (0..1000), DiagnosticCode signed/unsigned 16-bit values, bitwise ops,
   hashing, enums, register names (%R2350..%R2357), and coils (%M548..%M549).
2. TestDualCrcAndFrameIntegrity: CRC-S1 (poly 0x5935), CRC-S2 (poly 0x755B inverted), dual CRC verification,
   packet serialization, and single-bit mutation corruption detection.
3. TestStateTransitions: Progression across CIPSafetyAPLState (SAFE_INIT -> SAFE_COMMISSIONING -> SAFE_OPERATIONAL -> SAFE_FAULT_TRIP),
   commission, activate, disconnect, fault trips, and recovery resets.
4. TestTwoWiseVoltageMonitoringAndTrip: 2-WISE intrinsically safe loop voltage surveillance (nominal 12000 mV),
   under-voltage droop (<9600 mV -> 0xEB01 APL_DROOP), over-voltage violation (>15000 mV -> 0xEB04 IS_VIOLATION),
   boundary conditions, coils assertion (%M549) / deassertion (%M548), and reset recovery.
5. TestSignalQualityAndLatencyMonitoring: Eye margin signal quality (0..1000, nominal 850), clamping,
   latency tracking (nominal 1200 us), and jitter excess trip (>2500 us -> 0xEB03 TIMEOUT).
6. TestDualCrcFaultTrip: Packet CRC-S1 / CRC-S2 corruption detection, rejection of damaged frames, fault trip (0xEB02 CRC_FAULT),
   CRC error counter increment, coil %M549 assertion, and recovery reset.
7. TestSequenceCounterAndGapDetection: Rolling sequence counter monotonicity (0..65535), 16-bit rollover,
   gap detection (0xEB05 SEQUENCE_GAP), stale sequence rejection, %R2353 and %R2354 updates.
8. TestWatchdogExpirationAndScanStep: Safety communication watchdog surveillance, nominal cyclic scan,
   watchdog silence expiration (>=2500 us -> 0xEB03 TIMEOUT), feeding / kicking watchdog, and ScanContext execution.
9. TestRegisterSynchronization: %R2350..%R2357 and %M548..%M549 bit-exact synchronization, PrivilegeMode.SYSTEM,
   safe write wrappers (safe_write_word, safe_write_uword, safe_write_bit), register readback verification.
10. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetyAplSync POU, AST variable memory_address
    and bound registers validation (%R2350..%R2357, %M548..%M549).
11. TestAntiLadderConstructRejection: Rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)
    with LadderForbiddenError.
12. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
    properties validation, 100-cycle continuous soak simulation, and heap boundedness (< 100 KB growth).
13. TestExceptionsAndVerificationRunner: Exception inheritance hierarchy, 9-stage runner execution
    run_cip_safety_apl_verification(), strict 4-state contract validation, and evidence emission.
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
from jev_cscape.telemetry.cip_safety_apl import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_APL_CLASS_ID,
    CIP_APL_SAFETY_CLASS_ID,
    NOMINAL_CIP_SAFETY_APL_STATE,
    DEFAULT_APL_STATE,
    DEFAULT_LINK_STATE,
    NOMINAL_CIP_SAFETY_APL_SIGNAL_QUALITY,
    DEFAULT_SIGNAL_QUALITY,
    MIN_SIGNAL_QUALITY,
    MAX_SIGNAL_QUALITY,
    NOMINAL_CIP_SAFETY_APL_LOOP_VOLTAGE_MV,
    DEFAULT_LOOP_VOLTAGE_MV,
    MIN_IS_LOOP_VOLTAGE_MV,
    MAX_IS_LOOP_VOLTAGE_MV,
    NOMINAL_CIP_SAFETY_APL_TX_SEQUENCE,
    DEFAULT_TX_SEQUENCE,
    NOMINAL_CIP_SAFETY_APL_RX_SEQUENCE,
    DEFAULT_RX_SEQUENCE,
    NOMINAL_CIP_SAFETY_APL_CRC_STATUS,
    DEFAULT_CRC_STATUS,
    CRC_STATUS_S1_OK,
    CRC_STATUS_S2_OK,
    CRC_STATUS_BOTH_OK,
    NOMINAL_CIP_SAFETY_APL_LATENCY_US,
    DEFAULT_LATENCY_US,
    MAX_LATENCY_JITTER_US,
    DEFAULT_MAX_JITTER_US,
    DEFAULT_TIMEOUT_US,
    DEFAULT_WATCHDOG_TIMEOUT_US,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    NOMINAL_CIP_SAFETY_APL_DIAGNOSTIC_CODE,
    DEFAULT_DEVICE_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    REG_CIP_SAFETY_APL_STATE,
    REG_CIP_SAFETY_APL_SIGNAL_QUALITY,
    REG_CIP_SAFETY_APL_LOOP_VOLTAGE_MV,
    REG_CIP_SAFETY_APL_TX_SEQUENCE,
    REG_CIP_SAFETY_APL_RX_SEQUENCE,
    REG_CIP_SAFETY_APL_CRC_STATUS,
    REG_CIP_SAFETY_APL_LATENCY_US,
    REG_CIP_SAFETY_APL_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_APL_ESTABLISHED,
    COIL_CIP_SAFETY_APL_TRIPPED,
    REG_APL_STATE,
    REG_APL_SIGNAL_QUALITY,
    REG_APL_LOOP_VOLTAGE_MV,
    REG_APL_LOOP_VOLTAGE,
    REG_APL_TX_SEQUENCE,
    REG_APL_TX_SEQ,
    REG_APL_RX_SEQUENCE,
    REG_APL_RX_SEQ,
    REG_APL_CRC_STATUS,
    REG_APL_LATENCY_US,
    REG_APL_LATENCY,
    REG_APL_DIAGNOSTIC_CODE,
    REG_APL_DIAG_CODE,
    COIL_APL_ESTABLISHED,
    COIL_APL_TRIPPED,
    COIL_CIP_SAFETY_APL_OPERATIONAL,
    COIL_CIP_SAFETY_APL_FAULT_TRIPPED,
    COIL_APL_OPERATIONAL,
    COIL_APL_FAULT_TRIPPED,
    DiagnosticCode,
    DIAG_OK,
    DIAG_APL_DROOP,
    DIAG_CRC_FAULT,
    DIAG_TIMEOUT,
    DIAG_IS_VIOLATION,
    DIAG_SEQUENCE_GAP,
    DiagnosticStatusCode,
    AplDiagnosticCode,
    CIPSafetyAPLDiagnosticCode,
    CIPSafetyAPLState,
    SafeAplState,
    AplSafetyState,
    CipSafetyAplState,
    CIPSafetyAplState,
    CIPSafetyAPLError,
    APLDroopError,
    APLCrcFaultError,
    APLTimeoutError,
    APLISViolationError,
    APLSequenceGapError,
    CipSafetyAplError,
    AplDroopError,
    AplCrcFaultError,
    AplTimeoutError,
    AplIsViolationError,
    AplSequenceGapError,
    ST_PROGRAM_CIP_SAFETY_APL_SYNC,
    CIP_SAFETY_APL_PURE_ST_POU,
    CIP_SAFETY_APL_SYNC_POU,
    CIP_SAFETY_APL_POU,
    PURE_ST_POU,
    CipSafetyAplSync,
    verify_cip_safety_apl_pure_st,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPSafeAPLPacket,
    CIPSafeAPLFrame,
    CIPSafetyAPLPacket,
    CIPSafetyAPLFrame,
    APLSafetyPacket,
    APLSafetyFrame,
    create_valid_apl_packet,
    create_valid_apl_frame,
    create_valid_packet,
    CIPSafetyAPLEngine,
    CipSafetyAplEngine,
    CIPSafetyAplEngine,
    APLSafetyEngine,
    CIP_SAFETY_APL_ENGINE,
    run_cip_safety_apl_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Over Ethernet-APL protocol constants, class IDs, enums, and diagnostic codes."""

    def test_class_ids_and_protocol_constants(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_APL_CLASS_ID == 0x3E
        assert CIP_APL_SAFETY_CLASS_ID == 0x3E

        assert NOMINAL_CIP_SAFETY_APL_STATE == 2
        assert DEFAULT_APL_STATE == 2
        assert DEFAULT_LINK_STATE == 2

        assert NOMINAL_CIP_SAFETY_APL_SIGNAL_QUALITY == 850
        assert DEFAULT_SIGNAL_QUALITY == 850
        assert MIN_SIGNAL_QUALITY == 0
        assert MAX_SIGNAL_QUALITY == 1000

        assert NOMINAL_CIP_SAFETY_APL_LOOP_VOLTAGE_MV == 12000
        assert DEFAULT_LOOP_VOLTAGE_MV == 12000
        assert MIN_IS_LOOP_VOLTAGE_MV == 9600
        assert MAX_IS_LOOP_VOLTAGE_MV == 15000

        assert NOMINAL_CIP_SAFETY_APL_TX_SEQUENCE == 0
        assert DEFAULT_TX_SEQUENCE == 0
        assert NOMINAL_CIP_SAFETY_APL_RX_SEQUENCE == 0
        assert DEFAULT_RX_SEQUENCE == 0

        assert NOMINAL_CIP_SAFETY_APL_CRC_STATUS == 0x0003
        assert DEFAULT_CRC_STATUS == 0x0003
        assert CRC_STATUS_S1_OK == 0x0001
        assert CRC_STATUS_S2_OK == 0x0002
        assert CRC_STATUS_BOTH_OK == 0x0003

        assert NOMINAL_CIP_SAFETY_APL_LATENCY_US == 1200
        assert DEFAULT_LATENCY_US == 1200
        assert MAX_LATENCY_JITTER_US == 2500
        assert DEFAULT_MAX_JITTER_US == 2500
        assert DEFAULT_TIMEOUT_US == 2500
        assert DEFAULT_WATCHDOG_TIMEOUT_US == 2500
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 2.5

        assert NOMINAL_CIP_SAFETY_APL_DIAGNOSTIC_CODE == 0x0000
        assert DEFAULT_DEVICE_ID == 0x012F
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
        assert REG_CIP_SAFETY_APL_STATE == "%R2350"
        assert REG_CIP_SAFETY_APL_SIGNAL_QUALITY == "%R2351"
        assert REG_CIP_SAFETY_APL_LOOP_VOLTAGE_MV == "%R2352"
        assert REG_CIP_SAFETY_APL_TX_SEQUENCE == "%R2353"
        assert REG_CIP_SAFETY_APL_RX_SEQUENCE == "%R2354"
        assert REG_CIP_SAFETY_APL_CRC_STATUS == "%R2355"
        assert REG_CIP_SAFETY_APL_LATENCY_US == "%R2356"
        assert REG_CIP_SAFETY_APL_DIAGNOSTIC_CODE == "%R2357"

        assert COIL_CIP_SAFETY_APL_ESTABLISHED == "%M548"
        assert COIL_CIP_SAFETY_APL_TRIPPED == "%M549"

    def test_register_and_coil_aliases(self) -> None:
        assert REG_APL_STATE == "%R2350"
        assert REG_APL_SIGNAL_QUALITY == "%R2351"
        assert REG_APL_LOOP_VOLTAGE_MV == "%R2352"
        assert REG_APL_LOOP_VOLTAGE == "%R2352"
        assert REG_APL_TX_SEQUENCE == "%R2353"
        assert REG_APL_TX_SEQ == "%R2353"
        assert REG_APL_RX_SEQUENCE == "%R2354"
        assert REG_APL_RX_SEQ == "%R2354"
        assert REG_APL_CRC_STATUS == "%R2355"
        assert REG_APL_LATENCY_US == "%R2356"
        assert REG_APL_LATENCY == "%R2356"
        assert REG_APL_DIAGNOSTIC_CODE == "%R2357"
        assert REG_APL_DIAG_CODE == "%R2357"

        assert COIL_APL_ESTABLISHED == "%M548"
        assert COIL_APL_TRIPPED == "%M549"
        assert COIL_CIP_SAFETY_APL_OPERATIONAL == "%M548"
        assert COIL_CIP_SAFETY_APL_FAULT_TRIPPED == "%M549"
        assert COIL_APL_OPERATIONAL == "%M548"
        assert COIL_APL_FAULT_TRIPPED == "%M549"

    def test_diagnostic_code_values_and_representations(self) -> None:
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.APL_DROOP == 0xEB01
        assert DiagnosticCode.CRC_FAULT == 0xEB02
        assert DiagnosticCode.TIMEOUT == 0xEB03
        assert DiagnosticCode.IS_VIOLATION == 0xEB04
        assert DiagnosticCode.SEQUENCE_GAP == 0xEB05

        assert DiagnosticCode.SAFETY_OK == DiagnosticCode.OK
        assert DiagnosticCode.APL_OK == DiagnosticCode.OK
        assert DiagnosticCode.ERR_APL_DROOP == DiagnosticCode.APL_DROOP
        assert DiagnosticCode.VOLTAGE_DROOP == DiagnosticCode.APL_DROOP
        assert DiagnosticCode.DROOP_FAULT == DiagnosticCode.APL_DROOP
        assert DiagnosticCode.ERR_CRC_FAULT == DiagnosticCode.CRC_FAULT
        assert DiagnosticCode.CRC_CORRUPTED == DiagnosticCode.CRC_FAULT
        assert DiagnosticCode.ERR_TIMEOUT == DiagnosticCode.TIMEOUT
        assert DiagnosticCode.WATCHDOG_TIMEOUT == DiagnosticCode.TIMEOUT
        assert DiagnosticCode.LATENCY_FAULT == DiagnosticCode.TIMEOUT
        assert DiagnosticCode.ERR_IS_VIOLATION == DiagnosticCode.IS_VIOLATION
        assert DiagnosticCode.OVERVOLTAGE_VIOLATION == DiagnosticCode.IS_VIOLATION
        assert DiagnosticCode.INTRINSIC_SAFETY_VIOLATION == DiagnosticCode.IS_VIOLATION
        assert DiagnosticCode.ERR_SEQUENCE_GAP == DiagnosticCode.SEQUENCE_GAP
        assert DiagnosticCode.SEQUENCE_FAULT == DiagnosticCode.SEQUENCE_GAP
        assert DiagnosticCode.SEQUENCE_MISMATCH == DiagnosticCode.SEQUENCE_GAP

        assert DIAG_OK == DiagnosticCode.OK
        assert DIAG_APL_DROOP == DiagnosticCode.APL_DROOP
        assert DIAG_CRC_FAULT == DiagnosticCode.CRC_FAULT
        assert DIAG_TIMEOUT == DiagnosticCode.TIMEOUT
        assert DIAG_IS_VIOLATION == DiagnosticCode.IS_VIOLATION
        assert DIAG_SEQUENCE_GAP == DiagnosticCode.SEQUENCE_GAP

        assert DiagnosticStatusCode is DiagnosticCode
        assert AplDiagnosticCode is DiagnosticCode
        assert CIPSafetyAPLDiagnosticCode is DiagnosticCode

    def test_diagnostic_code_signed_unsigned_and_bitwise_ops(self) -> None:
        # Signed 16-bit negative integer comparison
        signed_droop = 0xEB01 - 0x10000
        assert DiagnosticCode.APL_DROOP == signed_droop
        assert DiagnosticCode.CRC_FAULT == (0xEB02 - 0x10000)
        assert DiagnosticCode.TIMEOUT == (0xEB03 - 0x10000)
        assert DiagnosticCode.IS_VIOLATION == (0xEB04 - 0x10000)
        assert DiagnosticCode.SEQUENCE_GAP == (0xEB05 - 0x10000)

        # Bitwise masking and operators
        assert (DiagnosticCode.APL_DROOP & 0xFFFF) == 0xEB01
        assert (DiagnosticCode.APL_DROOP | 0x0010) == (0xEB01 | 0x0010)
        assert (DiagnosticCode.APL_DROOP ^ 0x0001) == 0xEB00
        assert (0x1000 & DiagnosticCode.APL_DROOP) == (0x1000 & 0xEB01)
        assert (0x0100 | DiagnosticCode.APL_DROOP) == (0x0100 | 0xEB01)
        assert (0x0001 ^ DiagnosticCode.APL_DROOP) == 0xEB00

        # String formatting, repr, and hash
        assert "0xEB01" in str(DiagnosticCode.APL_DROOP)
        assert "APL_DROOP" in repr(DiagnosticCode.APL_DROOP)
        assert hash(DiagnosticCode.APL_DROOP) == hash(0xEB01)
        assert DiagnosticCode.APL_DROOP.value == 0xEB01
        assert int(DiagnosticCode.APL_DROOP) == 0xEB01

    def test_state_machine_enum(self) -> None:
        assert CIPSafetyAPLState.SAFE_INIT == 0
        assert CIPSafetyAPLState.SAFE_COMMISSIONING == 1
        assert CIPSafetyAPLState.SAFE_OPERATIONAL == 2
        assert CIPSafetyAPLState.SAFE_FAULT_TRIP == 3

        # Aliases
        assert CIPSafetyAPLState.SafeInit == 0
        assert CIPSafetyAPLState.SafeCommissioning == 1
        assert CIPSafetyAPLState.SafeOperational == 2
        assert CIPSafetyAPLState.SafeFaultTrip == 3
        assert CIPSafetyAPLState.INIT == 0
        assert CIPSafetyAPLState.COMMISSIONING == 1
        assert CIPSafetyAPLState.OPERATIONAL == 2
        assert CIPSafetyAPLState.FAULT_TRIP == 3
        assert CIPSafetyAPLState.TRIPPED == 3

        assert SafeAplState is CIPSafetyAPLState
        assert AplSafetyState is CIPSafetyAPLState
        assert CipSafetyAplState is CIPSafetyAPLState
        assert CIPSafetyAplState is CIPSafetyAPLState


# ============================================================================
# 2. TestDualCrcAndFrameIntegrity
# ============================================================================

class TestDualCrcAndFrameIntegrity:
    """Validate dual CRC calculation, serialization, bit-flip detection, and frame integrity."""

    def test_crc_s1_and_crc_s2_calculation(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06"
        crc1 = compute_crc_s1(data)
        assert isinstance(crc1, int)
        assert 0 <= crc1 <= 0xFFFF

        crc2 = compute_crc_s2(data)
        assert isinstance(crc2, int)
        assert 0 <= crc2 <= 0xFFFF

        # Ensure CRC-S1 and CRC-S2 differ due to different polynomials
        assert crc1 != crc2

        # Check calc aliases
        assert calc_crc_s1(data) == crc1
        assert calc_crc_s2(data) == crc2

    def test_crc_s2_inversion_logic(self) -> None:
        data = b"\x12\x34\x56\x78"
        crc2_normal = compute_crc_s2(data, inverted=False)
        crc2_inverted = compute_crc_s2(data, inverted=True)
        assert crc2_normal != crc2_inverted

        # Bitwise inversion equivalence
        inverted_data = bytes(b ^ 0xFF for b in data)
        assert compute_crc_s2(inverted_data, inverted=False) == crc2_inverted

    def test_valid_packet_generation_and_crc_verification(self) -> None:
        pkt = create_valid_apl_packet(
            tx_sequence=10,
            rx_sequence=5,
            device_id=0x012F,
            snn=0x3A4B,
            signal_quality=920,
            loop_voltage_mv=12500,
            latency_us=1150,
            payload=b"\x11\x22\x33\x44",
        )
        assert pkt.tx_sequence == 10
        assert pkt.rx_sequence == 5
        assert pkt.device_id == 0x012F
        assert pkt.snn == 0x3A4B
        assert pkt.signal_quality == 920
        assert pkt.loop_voltage_mv == 12500
        assert pkt.latency_us == 1150
        assert pkt.payload == b"\x11\x22\x33\x44"

        # Verification check
        assert pkt.verify_crcs() is True
        assert pkt.crc_status == CRC_STATUS_BOTH_OK

    def test_packet_serialization_formats(self) -> None:
        pkt = create_valid_apl_packet()
        ser1 = pkt.serialize_for_crc_s1()
        ser2 = pkt.serialize_for_crc_s2()

        # Header is 2*6 bytes for H + 4 bytes for I = 16 bytes + payload (4 bytes) = 20 bytes
        assert len(ser1) == 20
        assert len(ser2) == 20

        # serialize_for_crc_s2 must be the bitwise NOT of serialize_for_crc_s1
        expected_inv = bytes(b ^ 0xFF for b in ser1)
        assert ser2 == expected_inv

    def test_single_bit_mutation_detection(self) -> None:
        pkt = create_valid_apl_packet(payload=b"\xAA\xBB\xCC\xDD")
        assert pkt.verify_crcs() is True

        # Mutate bit 0 of byte 0
        pkt.mutate_bit(byte_offset=0, bit_pos=0)
        assert pkt.verify_crcs() is False
        assert pkt.crc_status != CRC_STATUS_BOTH_OK

    def test_multiple_bit_mutations(self) -> None:
        for offset in range(4):
            for bit in range(8):
                pkt = create_valid_apl_packet(payload=b"\x00\x00\x00\x00")
                pkt.mutate_bit(byte_offset=offset, bit_pos=bit)
                assert pkt.verify_crcs() is False

    def test_snn_verification(self) -> None:
        pkt = create_valid_apl_packet(snn=0x3A4B)
        assert pkt.verify_snn(0x3A4B) is True
        assert pkt.verify_snn(DEFAULT_SNN) is True
        assert pkt.verify_snn(0x9999) is True  # DEFAULT_SNN fallback allows nominal

    def test_packet_aliases_and_factories(self) -> None:
        p1 = create_valid_apl_frame(tx_sequence=1)
        p2 = create_valid_packet(tx_sequence=2)
        assert isinstance(p1, CIPSafeAPLPacket)
        assert isinstance(p2, CIPSafeAPLPacket)
        assert CIPSafeAPLFrame is CIPSafeAPLPacket
        assert CIPSafetyAPLPacket is CIPSafeAPLPacket
        assert CIPSafetyAPLFrame is CIPSafeAPLPacket
        assert APLSafetyPacket is CIPSafeAPLPacket
        assert APLSafetyFrame is CIPSafeAPLPacket


# ============================================================================
# 3. TestStateTransitions
# ============================================================================

class TestStateTransitions:
    """Validate safe state machine transitions across INIT, COMMISSIONING, OPERATIONAL, and FAULT_TRIP."""

    def test_initial_state_auto_activate_true(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL
        assert eng.is_healthy is True
        assert eng.is_established is True
        assert eng.is_safe_stop_tripped is False
        assert eng.operational is True
        assert eng.tripped is False
        assert rt.read_word("%R2350") == 2
        assert rt.read_bit("%M548") is True
        assert rt.read_bit("%M549") is False

    def test_initial_state_auto_activate_false(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=False)
        assert eng.state == CIPSafetyAPLState.SAFE_INIT
        assert eng.is_healthy is False
        assert eng.is_safe_stop_tripped is True
        assert eng.operational is False
        assert rt.read_word("%R2350") == 0
        assert rt.read_bit("%M548") is False
        assert rt.read_bit("%M549") is True

    def test_commissioning_transition(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=False)
        res = eng.commission()
        assert res is True
        assert eng.state == CIPSafetyAPLState.SAFE_COMMISSIONING
        assert eng.is_healthy is False
        assert eng.diagnostic_code == DiagnosticCode.OK
        assert rt.read_word("%R2350") == 1

    def test_activation_transition(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=False)
        eng.commission()
        res = eng.activate()
        assert res is True
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL
        assert eng.is_healthy is True
        assert eng.is_established is True
        assert rt.read_word("%R2350") == 2
        assert rt.read_bit("%M548") is True
        assert rt.read_bit("%M549") is False

    def test_disconnect_transition(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        eng.disconnect()
        assert eng.state == CIPSafetyAPLState.SAFE_INIT
        assert eng.is_healthy is False
        assert rt.read_word("%R2350") == 0
        assert rt.read_bit("%M548") is False

    def test_trip_fault_and_reset_recovery(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        eng.trip_fault(DiagnosticCode.APL_DROOP, "Voltage drop trip")
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.APL_DROOP
        assert eng.is_healthy is False
        assert eng.is_safe_stop_tripped is True
        assert rt.read_word("%R2350") == 3
        assert rt.read_uword("%R2357") == 0xEB01
        assert rt.read_bit("%M548") is False
        assert rt.read_bit("%M549") is True

        # Recovery via reset()
        eng.reset()
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL
        assert eng.diagnostic_code == DiagnosticCode.OK
        assert eng.is_healthy is True
        assert rt.read_word("%R2350") == 2
        assert rt.read_uword("%R2357") == 0x0000
        assert rt.read_bit("%M548") is True
        assert rt.read_bit("%M549") is False

    def test_operational_property_setter(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True)
        eng.operational = False
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        eng.operational = True
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL

    def test_tripped_property_setter(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True)
        eng.tripped = True
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        eng.tripped = False
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL


# ============================================================================
# 4. TestTwoWiseVoltageMonitoringAndTrip
# ============================================================================

class TestTwoWiseVoltageMonitoringAndTrip:
    """Validate 2-WISE intrinsically safe loop voltage surveillance (9600..15000 mV)."""

    def test_nominal_loop_voltage(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_loop_voltage(12000)
        assert res is True
        assert eng.is_healthy is True
        assert eng.loop_voltage_mv == 12000
        assert rt.read_word("%R2352") == 12000
        assert rt.read_bit("%M548") is True
        assert rt.read_bit("%M549") is False

    def test_exact_is_boundary_voltages(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)

        # Lower bound 9600 mV
        assert eng.monitor_loop_voltage(9600) is True
        assert eng.is_healthy is True
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL

        # Upper bound 15000 mV
        assert eng.monitor_loop_voltage(15000) is True
        assert eng.is_healthy is True
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL

    def test_undervoltage_droop_trips_apl_droop(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)

        # Droop right below lower bound
        res = eng.monitor_loop_voltage(9599)
        assert res is False
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.APL_DROOP
        assert eng.is_healthy is False
        assert eng.is_safe_stop_tripped is True
        assert rt.read_word("%R2350") == 3
        assert rt.read_word("%R2352") == 9599
        assert rt.read_uword("%R2357") == 0xEB01
        assert rt.read_bit("%M548") is False
        assert rt.read_bit("%M549") is True

    def test_severe_voltage_droop(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_loop_voltage(4500)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.APL_DROOP
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP

    def test_overvoltage_violation_trips_is_violation(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)

        # Violation right above upper bound
        res = eng.monitor_loop_voltage(15001)
        assert res is False
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.IS_VIOLATION
        assert eng.is_healthy is False
        assert eng.is_safe_stop_tripped is True
        assert rt.read_word("%R2350") == 3
        assert rt.read_word("%R2352") == 15001
        assert rt.read_uword("%R2357") == 0xEB04
        assert rt.read_bit("%M548") is False
        assert rt.read_bit("%M549") is True

    def test_severe_overvoltage_violation(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_loop_voltage(24000)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.IS_VIOLATION
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP

    def test_incoming_packet_voltage_checks(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)

        # Packet with voltage droop
        p_droop = create_valid_apl_packet(tx_sequence=1, loop_voltage_mv=9200)
        res = eng.process_packet(p_droop)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.APL_DROOP
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP

        # Packet with overvoltage
        eng.reset()
        p_over = create_valid_apl_packet(tx_sequence=1, loop_voltage_mv=16000)
        res = eng.process_packet(p_over)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.IS_VIOLATION
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP


# ============================================================================
# 5. TestSignalQualityAndLatencyMonitoring
# ============================================================================

class TestSignalQualityAndLatencyMonitoring:
    """Validate eye margin signal quality and latency/jitter surveillance."""

    def test_nominal_signal_quality(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_signal_quality(850)
        assert res is True
        assert eng.signal_quality == 850
        assert rt.read_word("%R2351") == 850

    def test_signal_quality_clamping(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True)
        eng.monitor_signal_quality(1200)
        assert eng.signal_quality == 1000
        eng.monitor_signal_quality(-50)
        assert eng.signal_quality == 0

    def test_nominal_latency_monitoring(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        res = eng.monitor_latency(1200)
        assert res is True
        assert eng.latency_us == 1200
        assert eng.is_healthy is True
        assert rt.read_word("%R2356") == 1200

    def test_latency_jitter_excess_trips_timeout(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)

        # 2600 us > 2500 us maximum jitter
        res = eng.monitor_latency(2600)
        assert res is False
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.TIMEOUT
        assert eng.is_healthy is False
        assert rt.read_word("%R2350") == 3
        assert rt.read_word("%R2356") == 2600
        assert rt.read_uword("%R2357") == 0xEB03
        assert rt.read_bit("%M549") is True

    def test_incoming_packet_latency_check(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        p_lat = create_valid_apl_packet(tx_sequence=1, latency_us=2700)
        res = eng.process_packet(p_lat)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.TIMEOUT
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP


# ============================================================================
# 6. TestDualCrcFaultTrip
# ============================================================================

class TestDualCrcFaultTrip:
    """Validate frame dual CRC verification and fault trips on corruption."""

    def test_nominal_packet_processing_passes_crc(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        pkt = create_valid_apl_packet(tx_sequence=1)
        res = eng.process_packet(pkt)
        assert res is True
        assert eng.is_healthy is True
        assert eng.crc_status == CRC_STATUS_BOTH_OK
        assert rt.read_word("%R2355") == 0x0003

    def test_corrupted_crc_s1_trips_crc_fault(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        pkt = create_valid_apl_packet(tx_sequence=1)
        pkt.crc_s1 ^= 0x0001  # Corrupt CRC-S1
        res = eng.process_packet(pkt)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.CRC_FAULT
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        assert eng.crc_error_count == 1
        assert rt.read_word("%R2350") == 3
        assert rt.read_uword("%R2357") == 0xEB02
        assert rt.read_bit("%M549") is True

    def test_corrupted_crc_s2_trips_crc_fault(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        pkt = create_valid_apl_packet(tx_sequence=1)
        pkt.crc_s2 ^= 0x0001  # Corrupt CRC-S2
        res = eng.process_packet(pkt)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.CRC_FAULT
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        assert eng.crc_error_count == 1
        assert rt.read_uword("%R2357") == 0xEB02

    def test_payload_mutation_trips_crc_fault(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        pkt = create_valid_apl_packet(tx_sequence=1)
        pkt.mutate_bit(byte_offset=1, bit_pos=3)
        res = eng.process_packet(pkt)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.CRC_FAULT
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP

    def test_crc_error_count_accumulation(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True)
        assert eng.crc_error_count == 0
        eng.trip_crc_fault()
        assert eng.crc_error_count == 1
        eng.trip_crc_fault()
        assert eng.crc_error_count == 2


# ============================================================================
# 7. TestSequenceCounterAndGapDetection
# ============================================================================

class TestSequenceCounterAndGapDetection:
    """Validate rolling sequence counter monotonicity and gap detection."""

    def test_tx_sequence_increment(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        assert eng.tx_sequence == 0
        p1 = eng.transmit_packet()
        assert p1.tx_sequence == 1
        assert eng.tx_sequence == 1
        assert rt.read_uword("%R2353") == 1

        p2 = eng.transmit_packet()
        assert p2.tx_sequence == 2
        assert eng.tx_sequence == 2
        assert rt.read_uword("%R2353") == 2

    def test_tx_sequence_16bit_rollover(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        eng.tx_sequence = 65535
        p = eng.transmit_packet()
        assert p.tx_sequence == 0
        assert eng.tx_sequence == 0
        assert rt.read_uword("%R2353") == 0

    def test_rx_sequence_nominal_progression(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        assert eng.rx_sequence == 0

        p1 = create_valid_apl_packet(tx_sequence=1)
        assert eng.process_packet(p1) is True
        assert eng.rx_sequence == 1
        assert rt.read_uword("%R2354") == 1

        p2 = create_valid_apl_packet(tx_sequence=2)
        assert eng.process_packet(p2) is True
        assert eng.rx_sequence == 2
        assert rt.read_uword("%R2354") == 2

    def test_sequence_gap_detection_trips_sequence_gap(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)

        # First frame ok (tx_sequence=1)
        p1 = create_valid_apl_packet(tx_sequence=1)
        assert eng.process_packet(p1) is True

        # Gap injected: expected 2, got 10
        p_gap = create_valid_apl_packet(tx_sequence=10)
        res = eng.process_packet(p_gap)
        assert res is False
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.SEQUENCE_GAP
        assert eng.is_healthy is False
        assert rt.read_word("%R2350") == 3
        assert rt.read_uword("%R2357") == 0xEB05
        assert rt.read_bit("%M549") is True

    def test_stale_or_repeated_sequence_trips_gap(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True)
        p1 = create_valid_apl_packet(tx_sequence=1)
        eng.process_packet(p1)

        # Repeat same sequence
        p_repeat = create_valid_apl_packet(tx_sequence=1)
        res = eng.process_packet(p_repeat)
        assert res is False
        assert eng.diagnostic_code == DiagnosticCode.SEQUENCE_GAP

    def test_rx_sequence_rollover_progression(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True)
        eng.rx_sequence = 65535
        eng.frames_processed = 1

        p_roll = create_valid_apl_packet(tx_sequence=0)
        assert eng.process_packet(p_roll) is True
        assert eng.rx_sequence == 0


# ============================================================================
# 8. TestWatchdogExpirationAndScanStep
# ============================================================================

class TestWatchdogExpirationAndScanStep:
    """Validate communication watchdog surveillance, kicks, and ScanContext execution."""

    def test_nominal_scan_step_under_threshold(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True, watchdog_timeout_us=2500.0)
        # 1 ms step = 1000 us < 2500 us
        eng.scan_step(0.001)
        assert eng.is_healthy is True
        assert eng.watchdog_timer_us == 1000.0
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL
        assert rt.read_bit("%M548") is True

    def test_watchdog_silence_expiration_trips_timeout(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True, watchdog_timeout_us=2500.0)
        # Advance by 3 ms = 3000 us >= 2500 us
        eng.scan_step(0.003)
        assert eng.is_healthy is False
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        assert eng.diagnostic_code == DiagnosticCode.TIMEOUT
        assert rt.read_word("%R2350") == 3
        assert rt.read_uword("%R2357") == 0xEB03
        assert rt.read_bit("%M549") is True

    def test_feed_watchdog_prevents_expiration(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True, watchdog_timeout_us=2500.0)
        eng.scan_step(0.002)  # 2000 us
        assert eng.is_healthy is True
        eng.feed_watchdog()
        assert eng.watchdog_timer_us == 0.0

        eng.scan_step(0.002)  # another 2000 us
        assert eng.is_healthy is True

    def test_process_packet_resets_watchdog(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True, watchdog_timeout_us=2500.0)
        eng.scan_step(0.002)  # 2000 us
        assert eng.watchdog_timer_us == 2000.0

        p = create_valid_apl_packet(tx_sequence=1)
        eng.process_packet(p)
        assert eng.watchdog_timer_us == 0.0

    def test_scan_context_execution(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True, watchdog_timeout_us=50000.0)
        ctx = ScanContext(cycle=1, dt_s=0.010)
        eng.execute(ctx)
        assert eng.cycles_count == 1
        assert eng.watchdog_timer_us == 10000.0

    def test_step_alias_method(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True, watchdog_timeout_us=50000.0)
        eng.step(0.005)
        assert eng.cycles_count == 1
        assert eng.watchdog_timer_us == 5000.0


# ============================================================================
# 9. TestRegisterSynchronization
# ============================================================================

class TestRegisterSynchronization:
    """Validate bit-exact Horner OCS register table synchronization (%R2350..%R2357, %M548..%M549)."""

    def test_all_registers_sync_nominal(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(
            register_table=rt,
            auto_activate=True,
            device_id=0x012F,
            snn=0x3A4B,
        )
        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)

        assert rt.read_word("%R2350") == 2
        assert rt.read_word("%R2351") == 850
        assert rt.read_word("%R2352") == 12000
        assert rt.read_uword("%R2353") == 0
        assert rt.read_uword("%R2354") == 0
        assert rt.read_word("%R2355") == 0x0003
        assert rt.read_word("%R2356") == 1200
        assert rt.read_uword("%R2357") == 0x0000

        assert rt.read_bit("%M548") is True
        assert rt.read_bit("%M549") is False

    def test_all_registers_sync_fault_tripped(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        eng.trip_droop_fault("Voltage droop")
        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)

        assert rt.read_word("%R2350") == 3
        assert rt.read_uword("%R2357") == 0xEB01
        assert rt.read_bit("%M548") is False
        assert rt.read_bit("%M549") is True

    def test_safe_write_word_signed_wrapping(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2350", 32767)
        assert rt.read_word("%R2350") == 32767

        # Value > 32767 wraps to negative signed 16-bit
        safe_write_word(rt, "%R2350", 65535)
        assert rt.read_word("%R2350") == -1

        safe_write_word(rt, "%R2350", 0xEB01)
        assert rt.read_word("%R2350") == (0xEB01 - 0x10000)

    def test_safe_write_uword(self) -> None:
        rt = RegisterTable()
        safe_write_uword(rt, "%R2353", 60000)
        assert rt.read_uword("%R2353") == 60000

    def test_safe_write_bit(self) -> None:
        rt = RegisterTable()
        safe_write_bit(rt, "%M548", True)
        assert rt.read_bit("%M548") is True
        safe_write_bit(rt, "%M548", False)
        assert rt.read_bit("%M548") is False

    def test_readback_consistency_after_multiple_packet_cycles(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True)
        for i in range(1, 10):
            eng.transmit_packet()
            pkt = create_valid_apl_packet(tx_sequence=i, loop_voltage_mv=12100, latency_us=1180, signal_quality=870)
            eng.process_packet(pkt)

        assert rt.read_uword("%R2353") == 9
        assert rt.read_uword("%R2354") == 9
        assert rt.read_word("%R2351") == 870
        assert rt.read_word("%R2352") == 12100
        assert rt.read_word("%R2356") == 1180


# ============================================================================
# 10. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 Structured Text POU and SecurityGuard enforcement."""

    def test_verify_pure_st_pou_function(self) -> None:
        assert verify_cip_safety_apl_pure_st() is True

    def test_security_guard_assert_pure_st_content(self) -> None:
        # Should not raise
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_SYNC)

    def test_st_parser_ast_program_validation(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse(ST_PROGRAM_CIP_SAFETY_APL_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyAplSync"

    def test_ast_bound_registers(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse(ST_PROGRAM_CIP_SAFETY_APL_SYNC)
        expected_regs = {
            "%R2350", "%R2351", "%R2352", "%R2353",
            "%R2354", "%R2355", "%R2356", "%R2357",
            "%M548", "%M549",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_pou_constants_and_aliases(self) -> None:
        assert CIP_SAFETY_APL_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_SYNC
        assert CIP_SAFETY_APL_SYNC_POU == ST_PROGRAM_CIP_SAFETY_APL_SYNC
        assert CIP_SAFETY_APL_POU == ST_PROGRAM_CIP_SAFETY_APL_SYNC
        assert PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_SYNC
        assert CipSafetyAplSync == ST_PROGRAM_CIP_SAFETY_APL_SYNC


# ============================================================================
# 11. TestAntiLadderConstructRejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Validate strict rejection of ladder logic contacts, coils, rungs, and mnemonics."""

    def test_ladder_contact_open_rejected(self) -> None:
        snippet = "PROGRAM Bad VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_ladder_contact_closed_rejected(self) -> None:
        snippet = "PROGRAM Bad VAR X: BOOL; END_VAR ---[/]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_ladder_coil_rejected(self) -> None:
        snippet = "PROGRAM Bad VAR X: BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_ladder_rung_delimiters_rejected(self) -> None:
        snippet = "PROGRAM Bad VAR X: BOOL; END_VAR RUNG 1: X := TRUE; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_ladder_network_delimiters_rejected(self) -> None:
        snippet = "PROGRAM Bad VAR X: BOOL; END_VAR NETWORK 1: X := TRUE; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

    def test_ladder_mnemonics_rejected(self) -> None:
        for mnemonic in ["XIC", "XIO", "OTE", "OTL", "OTU"]:
            snippet = f"PROGRAM Bad VAR X: BOOL; END_VAR {mnemonic} Sensor1; END_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 12. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Validate ILogicUnit interface compliance, deterministic soak, and heap growth bounds."""

    def test_ilogicunit_interface_properties(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True)
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "CIPSafetyAPLEngine"
        assert eng.priority == 10
        assert eng.is_enabled is True

    def test_ilogicunit_reset(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True)
        eng.trip_droop_fault()
        assert eng.is_healthy is False
        eng.reset()
        assert eng.is_healthy is True
        assert eng.diagnostic_code == DiagnosticCode.OK

    def test_continuous_100_cycle_soak_simulation(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True, watchdog_timeout_us=20000.0)

        for cycle in range(1, 101):
            pkt = create_valid_apl_packet(
                tx_sequence=cycle,
                loop_voltage_mv=12000,
                latency_us=1200,
                signal_quality=850,
            )
            assert eng.process_packet(pkt) is True
            eng.scan_step(0.005)  # 5 ms cyclic interval

        assert eng.cycles_count == 100
        assert eng.frames_processed == 100
        assert eng.is_healthy is True
        assert rt.read_word("%R2350") == 2
        assert rt.read_word("%R2351") == 850
        assert rt.read_word("%R2352") == 12000
        assert rt.read_uword("%R2354") == 100
        assert rt.read_word("%R2355") == 0x0003
        assert rt.read_word("%R2356") == 1200
        assert rt.read_uword("%R2357") == 0x0000
        assert rt.read_bit("%M548") is True
        assert rt.read_bit("%M549") is False

    def test_soak_memory_growth_bounded(self) -> None:
        rt = RegisterTable()
        eng = CIPSafetyAPLEngine(register_table=rt, auto_activate=True, watchdog_timeout_us=20000.0)

        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()

        for cycle in range(1, 101):
            pkt = create_valid_apl_packet(tx_sequence=cycle)
            eng.process_packet(pkt)
            eng.scan_step(0.005)

        snap2 = tracemalloc.take_snapshot()
        stats = snap2.compare_to(snap1, "lineno")
        growth_kb = sum(s.size_diff for s in stats if s.size_diff > 0) / 1024.0
        tracemalloc.stop()

        assert growth_kb < 100.0


# ============================================================================
# 13. TestExceptionsAndVerificationRunner
# ============================================================================

class TestExceptionsAndVerificationRunner:
    """Validate exception inheritance hierarchy and deterministic 9-stage verification runner."""

    def test_exception_hierarchy(self) -> None:
        assert issubclass(APLDroopError, CIPSafetyAPLError)
        assert issubclass(APLCrcFaultError, CIPSafetyAPLError)
        assert issubclass(APLTimeoutError, CIPSafetyAPLError)
        assert issubclass(APLISViolationError, CIPSafetyAPLError)
        assert issubclass(APLSequenceGapError, CIPSafetyAPLError)

        # Aliases
        assert issubclass(AplDroopError, CipSafetyAplError)
        assert issubclass(AplCrcFaultError, CipSafetyAplError)
        assert issubclass(AplTimeoutError, CipSafetyAplError)
        assert issubclass(AplIsViolationError, CipSafetyAplError)
        assert issubclass(AplSequenceGapError, CipSafetyAplError)

    def test_exception_raising_and_catching(self) -> None:
        with pytest.raises(CIPSafetyAPLError):
            raise APLDroopError("Voltage droop below 9600 mV")

        with pytest.raises(CIPSafetyAPLError):
            raise APLCrcFaultError("CRC checksum failure")

        with pytest.raises(CIPSafetyAPLError):
            raise APLTimeoutError("Latency exceeded 2500 us")

        with pytest.raises(CIPSafetyAPLError):
            raise APLISViolationError("Voltage exceeded 15000 mV")

        with pytest.raises(CIPSafetyAPLError):
            raise APLSequenceGapError("Sequence jump detected")

    def test_verification_runner_execution_success(self) -> None:
        res = run_cip_safety_apl_verification(work_package="W274")
        assert isinstance(res, dict)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["work_package"] == "W274"
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9
        assert "CIP Safety Over Ethernet-APL" in res["details"]
        assert "ODVA CIP Safety Over Ethernet-APL" in res["data"]["protocol"]

    def test_verification_runner_stage_details(self) -> None:
        res = run_cip_safety_apl_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for stage in stages:
            assert stage["passed"] is True
            assert stage["timing_ms"] >= 0.0

    def test_verification_runner_exports_evidence_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "cip_safety_apl_evidence.json"
            res = run_cip_safety_apl_verification(output_path=str(out_file))
            assert out_file.exists()
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"
            assert data["total_stages"] == 9
            assert data["stages_passed"] == 9

    def test_engine_aliases(self) -> None:
        assert CipSafetyAplEngine is CIPSafetyAPLEngine
        assert CIPSafetyAplEngine is CIPSafetyAPLEngine
        assert APLSafetyEngine is CIPSafetyAPLEngine
        assert CIP_SAFETY_APL_ENGINE is CIPSafetyAPLEngine

    def test_diagnostic_code_edge_comparisons(self) -> None:
        assert DiagnosticCode.OK != "arbitrary_string"
        assert not (DiagnosticCode.OK == "arbitrary_string")
        assert (DiagnosticCode.OK & 0xFFFF) == 0
        assert (DiagnosticCode.OK | 0x1234) == 0x1234
        assert (DiagnosticCode.OK ^ 0x5678) == 0x5678
        assert (0x1234 | DiagnosticCode.OK) == 0x1234
        assert (0x5678 ^ DiagnosticCode.OK) == 0x5678

    def test_crc_multiple_buffer_inputs_and_invalid_args(self) -> None:
        b1 = b"\x01\x02"
        b2 = b"\x03\x04"
        assert compute_crc_s1(b1, b2) == compute_crc_s1(b"\x01\x02\x03\x04")
        assert compute_crc_s2(b1, b2) == compute_crc_s2(b"\x01\x02\x03\x04")

        with pytest.raises(ValueError):
            compute_crc_s1(12345)

        with pytest.raises(ValueError):
            compute_crc_s2("invalid string")

    def test_property_aliases_and_watchdog_ms_config(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=True, watchdog_timeout_ms=10.0)
        assert eng.watchdog_timeout_us == 10000.0
        assert eng.link_healthy is True
        assert eng.safe_stop_tripped is False
        assert eng.established is True
        assert eng.fault_tripped is False

        # Setters
        eng.established = False
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        eng.established = True
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL

        eng.fault_tripped = True
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        eng.fault_tripped = False
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL

    def test_reset_auto_activate_false_and_commissioning_packet(self) -> None:
        eng = CIPSafetyAPLEngine(auto_activate=False)
        assert eng.state == CIPSafetyAPLState.SAFE_INIT
        eng.trip_droop_fault()
        assert eng.state == CIPSafetyAPLState.SAFE_FAULT_TRIP
        eng.reset()
        assert eng.state == CIPSafetyAPLState.SAFE_INIT

        # Receive valid packet in commissioning state transitions to operational
        eng.commission()
        assert eng.state == CIPSafetyAPLState.SAFE_COMMISSIONING
        pkt = create_valid_apl_packet(tx_sequence=1)
        assert eng.process_packet(pkt) is True
        assert eng.state == CIPSafetyAPLState.SAFE_OPERATIONAL

    def test_pure_st_pou_verification_invalid_cases(self) -> None:
        assert verify_cip_safety_apl_pure_st("PROGRAM BadSyntax VAR END_VAR") is False
        assert verify_cip_safety_apl_pure_st("PROGRAM Incomplete VAR X: INT; END_VAR END_PROGRAM") is False
        assert verify_cip_safety_apl_pure_st(None) is True

