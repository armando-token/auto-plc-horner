"""Comprehensive Unit Test Suite for Wave W235 CIP Safety Ring Protocol Engine.

Work Package: W235 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 100+ Comprehensive Unit Tests across 17 Sections:
1. Section 1: Protocol Constants, Identifiers, Enums & Diagnostic Codes (signed/unsigned & 0xFFFF).
2. Section 2: SNN Format, SCID, TUNID, & OUNID Configuration & Parsing.
3. Section 3: Dual-Channel Payload Verification & CRC-S Checksums.
4. Section 4: CIP Safety Ring Packet Serialization, Deserialization, & Beacon Frames.
5. Section 5: Ring Topology State Machine (CLOSED_NORMAL, RING_FAULT_OPEN, NODE_ACTIVE, SUPERVISOR_ACTIVE, FAULT_SAFE_STATE).
6. Section 6: Beacon Frame Transmission, Beacon Timeout Calculation, & Beacon Fault (0xEA06).
7. Section 7: Sequence Number Monotonicity & Replay Attack Rejection.
8. Section 8: Expected Packet Interval (EPI) Watchdogs & Timeout Tripping (0xEA02).
9. Section 9: Dual-Channel Discrepancy Fault (0xEA03).
10. Section 10: Safety Network Number (SNN) & SCID Mismatch Fault (0xEA01).
11. Section 11: CRC-S Checksum Corruption Fault (0xEA04).
12. Section 12: Ring Break Fault & Fast Recovery (< 10 ms) (0xEA05).
13. Section 13: Horner OCS Register Synchronization (%R1960..%R1967, %M457..%M458 with SYSTEM privilege).
14. Section 14: Pure ST POU Validation with STParser(pou_type=POUType.PROGRAM) & Anti-Ladder Guard Interception.
15. Section 15: ILogicUnit Interface Compliance & Scan Cycle Simulation.
16. Section 16: Reset Nominal Recovery & Safe State Coordination.
17. Section 17: Verification Runner & Strict 4-State Engineering Contract.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_ring import (
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_RING_CLASS_ID,
    CIP_SAFETY_RING_CONNECTION_CLASS_ID,
    CIP_SAFETY_RING_POU,
    CIP_SAFETY_RING_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_RING_SYNC_POU,
    CIP_SAFETY_RING_VALIDATOR_CLASS_ID,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyRingEngine,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    DEFAULT_BEACON_INTERVAL_MS,
    DEFAULT_BEACON_INTERVAL_US,
    DEFAULT_BEACON_TIMEOUT_US,
    DEFAULT_EPI_MS,
    DEFAULT_PORT1_UNID,
    DEFAULT_PORT2_UNID,
    DEFAULT_RECOVERY_TIME_MS,
    DEFAULT_SCID,
    DEFAULT_SCID_CRC,
    DEFAULT_SCID_TIMESTAMP,
    DEFAULT_SNN,
    DEFAULT_TUNID,
    DEFAULT_OUNID,
    DEFAULT_WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DIAG_BEACON_SUPERVISOR_TIMEOUT,
    DIAG_BEACON_TIMEOUT,
    DIAG_CRC_S_CORRUPTION,
    DIAG_DUAL_CHANNEL_DISCREPANCY,
    DIAG_EPI_TIMEOUT,
    DIAG_EPI_WATCHDOG_TIMEOUT,
    DIAG_OK,
    DIAG_RING_BREAK,
    DIAG_RING_BREAK_FAULT,
    DIAG_SNN_MISMATCH,
    DIAG_SNN_SIGNATURE_MISMATCH,
    EPI_WATCHDOG_TIMEOUT_MS,
    MAX_RESTORATION_TIME_MS,
    NOMINAL_BEACON_INTERVAL_MS,
    NOMINAL_BEACON_INTERVAL_US,
    NOMINAL_EPI_MS,
    NOMINAL_RESTORATION_TIME_MS,
    PORT1,
    PORT1_PRIMARY,
    PORT2,
    PORT2_SECONDARY,
    PURE_ST_POU,
    RING_PORT1,
    RING_PORT2,
    RING_SUPERVISOR_MODE,
    WATCHDOG_MULTIPLIER,
    CipSafetyBeaconTimeoutError,
    CipSafetyControlByte,
    CipSafetyCrcCorruptionError,
    CipSafetyDiagnosticCode,
    CipSafetyDualChannelDiscrepancyError,
    CipSafetyEpiTimeoutError,
    CipSafetyPacket,
    CipSafetyReplayAttackError,
    CipSafetyRing,
    CipSafetyRingBreakError,
    CipSafetyRingDiagnosticCode,
    CipSafetyRingEngine,
    CipSafetyRingError,
    CipSafetyRingPacket,
    CipSafetyRingState,
    CipSafetySequenceError,
    CipSafetySnnMismatchError,
    DiagnosticCode,
    DiagnosticStatusCode,
    DiversifiedMode,
    DlrSafetyBeaconFrame,
    PortId,
    PortIdentifier,
    RingDiagnosticCode,
    RingNodeRole,
    RingPort,
    RingPortIdentifier,
    RingPortLinkState,
    RingPortTrafficState,
    RingRole,
    RingSafetyConnection,
    RingSafetyConnectionObject,
    RingStatusBits,
    RingTopologyState,
    SafetyConfigurationIdentifier,
    SafetyControlByte,
    SafetyNetworkNumber,
    SafetyOperationalState,
    SafetySupervisorObject,
    SafetyValidatorObject,
    TargetUniqueNetworkId,
    OriginatorUniqueNetworkId,
    TopologyState,
    calc_crc_s1,
    calc_crc_s2,
    calculate_crc16_ccitt,
    compute_crc_s1,
    compute_crc_s2,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_ring_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    scale_time_ms_to_int16,
    validate_snn,
    verify_cip_safety_ring_pure_st,
    verify_dual_channel_payload,
)


# ============================================================================
# Section 1: Protocol Constants, Identifiers, Enums & Diagnostic Codes
# ============================================================================

class TestSection1ProtocolConstantsAndDiagnosticCodes:
    """Validate CIP Safety ring protocol constants, classes, and DiagnosticCode."""

    def test_odva_object_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_RING_CLASS_ID == 0x3B
        assert CIP_SAFETY_RING_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_RING_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_RING_CONNECTION_CLASS_ID == 0x3B

    def test_port_identifiers(self) -> None:
        assert PORT1_PRIMARY == 1
        assert PORT2_SECONDARY == 2
        assert RING_PORT1 == 1
        assert RING_PORT2 == 2
        assert PortIdentifier.PORT1 == 1
        assert PortIdentifier.PORT2 == 2
        assert RingPortIdentifier.PRIMARY == 1
        assert RingPortIdentifier.SECONDARY == 2

    def test_timing_constants(self) -> None:
        assert NOMINAL_EPI_MS == 10.0
        assert DEFAULT_EPI_MS == 10.0
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 30.0
        assert EPI_WATCHDOG_TIMEOUT_MS == 30.0
        assert DEFAULT_BEACON_INTERVAL_US in (400, 1000)
        assert DEFAULT_BEACON_INTERVAL_MS in (0.4, 1.0)
        assert NOMINAL_BEACON_INTERVAL_MS in (0.4, 1.0)
        assert MAX_RESTORATION_TIME_MS == 10.0
        assert NOMINAL_RESTORATION_TIME_MS == 8.5
        assert DEFAULT_RECOVERY_TIME_MS == 8.5
        assert RING_SUPERVISOR_MODE == 1

    def test_diagnostic_code_values_and_representations(self) -> None:
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.SNN_SIGNATURE_MISMATCH == 0xEA01
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xEA02
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == 0xEA03
        assert DiagnosticCode.CRC_S_CORRUPTION == 0xEA04
        assert DiagnosticCode.RING_BREAK_FAULT == 0xEA05
        assert DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT == 0xEA06

    def test_diagnostic_code_aliases(self) -> None:
        assert DiagnosticCode.SNN_MISMATCH == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert DiagnosticCode.EPI_TIMEOUT == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DiagnosticCode.EPI_WATCHDOG == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DiagnosticCode.DISCREPANCY_FAULT == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert DiagnosticCode.CRC_FAULT == DiagnosticCode.CRC_S_CORRUPTION
        assert DiagnosticCode.CRC_CORRUPTED == DiagnosticCode.CRC_S_CORRUPTION
        assert DiagnosticCode.RING_BREAK == DiagnosticCode.RING_BREAK_FAULT
        assert DiagnosticCode.RING_FAULT == DiagnosticCode.RING_BREAK_FAULT
        assert DiagnosticCode.BEACON_TIMEOUT == DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT
        assert DiagnosticCode.BEACON_TIMEOUT_FAULT == DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        # 0xEA01: 59905 unsigned, -5631 signed 16-bit
        code_snn = DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert code_snn == 0xEA01
        assert code_snn == 59905
        assert code_snn == -5631
        assert code_snn == (0xEA01 & 0xFFFF)

        # 0xEA02: 59906 unsigned, -5630 signed 16-bit
        code_epi = DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert code_epi == 0xEA02
        assert code_epi == -5630

        # 0xEA03: 59907 unsigned, -5629 signed 16-bit
        code_disc = DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert code_disc == 0xEA03
        assert code_disc == -5629

        # 0xEA04: 59908 unsigned, -5628 signed 16-bit
        code_crc = DiagnosticCode.CRC_S_CORRUPTION
        assert code_crc == 0xEA04
        assert code_crc == -5628

        # 0xEA05: 59909 unsigned, -5627 signed 16-bit
        code_break = DiagnosticCode.RING_BREAK_FAULT
        assert code_break == 0xEA05
        assert code_break == -5627

        # 0xEA06: 59910 unsigned, -5626 signed 16-bit
        code_bcn = DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT
        assert code_bcn == 0xEA06
        assert code_bcn == -5626

    def test_diagnostic_code_masking_and_bitwise_operations(self) -> None:
        code = DiagnosticCode.RING_BREAK_FAULT
        masked = code & 0xFFFF
        assert masked == 0xEA05
        assert isinstance(masked, DiagnosticCode)
        rmasked = 0xFFFF & code
        assert rmasked == 0xEA05
        assert isinstance(rmasked, DiagnosticCode)

    def test_diagnostic_code_hashing_and_formatting(self) -> None:
        codes = {DiagnosticCode.OK, DiagnosticCode.RING_BREAK_FAULT, DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT}
        assert len(codes) == 3
        assert DiagnosticCode.OK in codes
        assert "0xEA05" in repr(DiagnosticCode.RING_BREAK_FAULT)
        assert "RING_BREAK_FAULT" in str(DiagnosticCode.RING_BREAK_FAULT)

    def test_ring_status_bits_enum(self) -> None:
        assert RingStatusBits.RING_ACTIVE == 1 << 0
        assert RingStatusBits.TRIP_SAFE_STATE_ENGAGED == 1 << 1
        assert RingStatusBits.FAULT_LATCHED == 1 << 2
        assert RingStatusBits.SNN_MISMATCH_LATCH == 1 << 3
        assert RingStatusBits.EPI_TIMEOUT_LATCH == 1 << 4
        assert RingStatusBits.DISCREPANCY_LATCH == 1 << 5
        assert RingStatusBits.CRC_ERROR_LATCH == 1 << 6
        assert RingStatusBits.RING_BREAK_LATCH == 1 << 7
        assert RingStatusBits.BEACON_TIMEOUT_LATCH == 1 << 8
        assert RingStatusBits.PORT1_LINK_UP == 1 << 9
        assert RingStatusBits.PORT2_LINK_UP == 1 << 10
        assert RingStatusBits.PORT2_BLOCKED == 1 << 11

    def test_safety_control_byte_flags(self) -> None:
        assert SafetyControlByte.IDLE == 0x00
        assert SafetyControlByte.RUN == 1 << 0
        assert SafetyControlByte.PING_REQ == 1 << 1
        assert SafetyControlByte.PING_RESP == 1 << 2
        assert SafetyControlByte.SAFETY_DEMAND == 1 << 3
        assert SafetyControlByte.FAULT_PRESENT == 1 << 4
        assert SafetyControlByte.RESET_REQUEST == 1 << 5
        assert SafetyControlByte.BEACON_FRAME == 1 << 6
        assert SafetyControlByte.DISCONNECT_REQ == 1 << 7

    def test_port_link_and_traffic_states(self) -> None:
        assert RingPortLinkState.LINK_DOWN == 0
        assert RingPortLinkState.LINK_UP == 1
        assert RingPortTrafficState.BLOCKED == 0
        assert RingPortTrafficState.UNBLOCKED == 1

    def test_ring_roles(self) -> None:
        assert RingRole.RING_NODE == 0
        assert RingRole.BACKUP_SUPERVISOR == 1
        assert RingRole.RING_SUPERVISOR == 2


# ============================================================================
# Section 2: SNN Format, SCID, TUNID, & OUNID Configuration & Parsing
# ============================================================================

class TestSection2SnnFormatScidTunidOunidConfiguration:
    """Validate SNN generation, format, validation, and configuration structures."""

    def test_generate_and_format_snn(self) -> None:
        raw = generate_snn(0x2026, 0x1006AA77)
        assert len(raw) == 6
        fmt = format_snn(raw)
        assert fmt == "2026-1006AA77"

    def test_parse_snn_round_trip(self) -> None:
        original = bytes([0x20, 0x26, 0x10, 0x06, 0x12, 0x34])
        fmt = format_snn(original)
        parsed = parse_snn(fmt)
        assert parsed == original

    def test_validate_snn_valid_and_invalid(self) -> None:
        valid_snn = bytes([0x20, 0x26, 0x10, 0x06, 0xAA, 0x77])
        assert validate_snn(valid_snn) is True
        assert validate_snn(format_snn(valid_snn)) is True

        # Invalid SNN criteria
        assert validate_snn(b"\x00" * 6) is False
        assert validate_snn(b"\xFF" * 6) is False
        assert validate_snn(b"\x00\x00\x10\x06\xAA\x77") is False
        assert validate_snn(b"\x20\x26\x00\x00\x00\x00") is False
        assert validate_snn(b"\x01\x02\x03") is False
        assert validate_snn("NOT_A_HEX_STRING") is False

    def test_safety_network_number_class(self) -> None:
        snn_obj = SafetyNetworkNumber(DEFAULT_SNN, crc_id=0x0001)
        assert len(snn_obj.timestamp_bytes) == 6
        assert len(snn_obj.raw_bytes) == 8
        assert snn_obj.to_hex() == (DEFAULT_SNN + b"\x00\x01").hex().upper()

        from_b = SafetyNetworkNumber.from_bytes(DEFAULT_SNN)
        assert from_b.timestamp_bytes == DEFAULT_SNN

    def test_safety_configuration_identifier(self) -> None:
        scid = SafetyConfigurationIdentifier(crc=0x20261006, timestamp=0x10060005)
        raw = scid.to_bytes()
        assert len(raw) == 8
        loaded = SafetyConfigurationIdentifier.from_bytes(raw)
        assert loaded.crc == 0x20261006
        assert loaded.timestamp == 0x10060005

    def test_target_and_originator_unid(self) -> None:
        snn_obj = SafetyNetworkNumber(DEFAULT_SNN)
        tunid = TargetUniqueNetworkId(snn=snn_obj, target_node_id=DEFAULT_TUNID)
        ounid = OriginatorUniqueNetworkId(snn=snn_obj, originator_node_id=DEFAULT_OUNID)
        assert len(tunid.to_bytes()) == 12
        assert len(ounid.to_bytes()) == 12
        tunid_rt = TargetUniqueNetworkId.from_bytes(tunid.to_bytes())
        assert tunid.matches(tunid_rt)
        ounid_rt = OriginatorUniqueNetworkId.from_bytes(ounid.to_bytes())
        assert ounid.matches(ounid_rt)

    def test_safety_supervisor_locking(self) -> None:
        sup = SafetySupervisorObject(snn=DEFAULT_SNN, scid_crc=DEFAULT_SCID_CRC)
        assert sup.is_locked() is False
        sup.lock_configuration()
        assert sup.is_locked() is True
        sup.unlock_configuration()
        assert sup.is_locked() is False


# ============================================================================
# Section 3: Dual-Channel Payload Parity & CRC-S Checksums
# ============================================================================

class TestSection3DualChannelPayloadParityAndCrcChecksums:
    """Validate dual-channel complement cross-comparison and CRC-S calculations."""

    def test_verify_dual_channel_inverted_mode_success(self) -> None:
        ch_a = bytes([0x00, 0x55, 0xAA, 0xFF])
        ch_b = bytes([0xFF, 0xAA, 0x55, 0x00])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is True

    def test_verify_dual_channel_inverted_mode_failure(self) -> None:
        ch_a = bytes([0x00, 0x55, 0xAA, 0xFF])
        ch_b = bytes([0xFF, 0xAA, 0x55, 0x01])  # Corrupted last byte
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_identical_mode(self) -> None:
        ch_a = bytes([0x01, 0x02, 0x03, 0x04])
        ch_b = bytes([0x01, 0x02, 0x03, 0x04])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.IDENTICAL) is True
        assert verify_dual_channel_payload(ch_a, b"\x01\x02\x03\x05", DiversifiedMode.IDENTICAL) is False

    def test_verify_dual_channel_length_mismatch(self) -> None:
        ch_a = bytes([0x01, 0x02])
        ch_b = bytes([0xFE])
        assert verify_dual_channel_payload(ch_a, ch_b) is False

    def test_calculate_crc16_ccitt(self) -> None:
        data = b"123456789"
        crc = calculate_crc16_ccitt(data, seed=0xFFFF)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

    def test_calc_crc_s1_and_crc_s2_inversion(self) -> None:
        payload = bytes([0x10, 0x20, 0x30, 0x40])
        crc1 = compute_crc_s1(payload)
        crc2 = compute_crc_s2(payload, inverted=True)
        assert crc2 == ((~crc1) & 0xFFFF)

    def test_crc_sensitivity_to_single_bit_flip(self) -> None:
        payload1 = bytes([0x00, 0x00])
        payload2 = bytes([0x00, 0x01])
        crc1 = compute_crc_s1(payload1)
        crc2 = compute_crc_s1(payload2)
        assert crc1 != crc2


# ============================================================================
# Section 4: CIP Safety Ring Packet Serialization, Deserialization, & Beacon Frames
# ============================================================================

class TestSection4PacketAndBeaconSerialization:
    """Validate CIP Safety ring packets and DLR beacon frame encoding/decoding."""

    def test_cip_safety_ring_packet_creation_and_crc(self) -> None:
        pkt = CipSafetyRingPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            channel_a_payload=b"\x12\x34",
            channel_b_payload=b"\xED\xCB",
        )
        pkt.calculate_crcs()
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.verify_crcs() is True

    def test_packet_serialization_round_trip(self) -> None:
        pkt = CipSafetyRingPacket(
            snn=DEFAULT_SNN,
            tunid=101,
            ounid=102,
            sequence_number=42,
            channel_a_payload=b"\xAA\xBB\xCC",
            channel_b_payload=b"\x55\x44\x33",
            ring_latency_ms=1.5,
        )
        pkt.calculate_crcs()
        raw = pkt.serialize()
        assert isinstance(raw, bytes)
        assert len(raw) >= 33

        deser = CipSafetyRingPacket.deserialize(raw)
        assert deser.snn == pkt.snn
        assert deser.tunid == 101
        assert deser.ounid == 102
        assert deser.sequence_number == 42
        assert deser.channel_a_payload == b"\xAA\xBB\xCC"
        assert deser.channel_b_payload == b"\x55\x44\x33"
        assert deser.verify_crcs() is True

    def test_packet_deserialize_truncated_raises(self) -> None:
        with pytest.raises(ValueError):
            CipSafetyRingPacket.deserialize(b"\x00" * 15)

    def test_packet_corrupted_crc_fails_verification(self) -> None:
        pkt = CipSafetyRingPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        pkt.crc_s1 ^= 0x0001
        assert pkt.verify_crcs() is False

    def test_dlr_safety_beacon_frame_creation(self) -> None:
        beacon = DlrSafetyBeaconFrame(
            source_mac="00:1D:9C:C0:02:01",
            sequence_id=1,
            ring_state=RingTopologyState.CLOSED_NORMAL,
            supervisor_precedence=100,
            beacon_interval_us=400,
            beacon_timeout_us=1600,
            timestamp_us=1000.0,
        )
        assert beacon.sequence_id == 1
        assert beacon.ring_state == RingTopologyState.CLOSED_NORMAL
        raw = beacon.serialize()
        assert len(raw) == 18

    def test_dlr_safety_beacon_frame_round_trip(self) -> None:
        beacon = DlrSafetyBeaconFrame(
            source_mac="00:1D:9C:C0:02:01",
            sequence_id=55,
            ring_state=RingTopologyState.RING_FAULT_OPEN,
            supervisor_precedence=100,
            beacon_interval_us=1000,
            beacon_timeout_us=3000,
            timestamp_us=5000.0,
        )
        raw = beacon.serialize()
        deser = DlrSafetyBeaconFrame.deserialize(raw)
        assert deser.sequence_id == 55
        assert deser.ring_state == RingTopologyState.RING_FAULT_OPEN
        assert deser.beacon_interval_us == 1000

    def test_beacon_deserialize_truncated_raises(self) -> None:
        with pytest.raises(ValueError):
            DlrSafetyBeaconFrame.deserialize(b"\x00" * 10)


# ============================================================================
# Section 5: Ring Topology State Machine & Dual-Port Binding
# ============================================================================

class TestSection5RingTopologyStateMachine:
    """Validate ring topology states, loop prevention, and port traffic states."""

    def test_initial_supervisor_state_closed_normal(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, role=RingRole.RING_SUPERVISOR)
        assert engine.topology_state == RingTopologyState.CLOSED_NORMAL
        assert engine.port1_link_up is True
        assert engine.port2_link_up is True
        assert engine.port2_blocked is True  # Port 2 blocked to prevent loops
        assert engine.is_active is True
        assert engine.is_tripped is False

    def test_initial_node_state_node_active(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, role=RingRole.RING_NODE)
        assert engine.topology_state == RingTopologyState.NODE_ACTIVE
        assert engine.port1_link_up is True
        assert engine.port2_link_up is True
        assert engine.port2_blocked is False  # Node unblocks both ports
        assert engine.is_active is True

    def test_bind_ring_establishes_topology(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=False, supervisor_mode=True)
        assert engine.port1_link_up is False
        assert engine.port2_link_up is False
        assert engine.topology_state == RingTopologyState.RING_FAULT_OPEN

        bind_ok = engine.bind_ring(port1_unid=101, port2_unid=102, snn=DEFAULT_SNN, scid=DEFAULT_SCID)
        assert bind_ok is True
        assert engine.port1_link_up is True
        assert engine.port2_link_up is True
        assert engine.topology_state == RingTopologyState.SUPERVISOR_ACTIVE
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_ring_topology_state_enum_values(self) -> None:
        assert RingTopologyState.CLOSED_NORMAL == 0
        assert RingTopologyState.RING_FAULT_OPEN == 1
        assert RingTopologyState.NODE_ACTIVE == 2
        assert RingTopologyState.SUPERVISOR_ACTIVE == 3
        assert RingTopologyState.FAULT_SAFE_STATE == 4

    def test_ring_topology_state_aliases(self) -> None:
        assert RingTopologyState.RING_NORMAL == RingTopologyState.CLOSED_NORMAL
        assert RingTopologyState.RingNormal == RingTopologyState.CLOSED_NORMAL
        assert RingTopologyState.RING_FAULT == RingTopologyState.RING_FAULT_OPEN
        assert RingTopologyState.RingFault == RingTopologyState.RING_FAULT_OPEN
        assert RingTopologyState.FaultSafeState == RingTopologyState.FAULT_SAFE_STATE

    def test_safe_state_engaged_on_fault(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        assert engine.safe_state_engaged is False
        engine.trip(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY)
        assert engine.safe_state_engaged is True
        assert engine.is_tripped is True
        assert engine.is_active is False
        assert engine.topology_state == RingTopologyState.FAULT_SAFE_STATE


# ============================================================================
# Section 6: Beacon Frame Transmission, Beacon Timeout, & Beacon Fault (0xEA06)
# ============================================================================

class TestSection6BeaconFrameTransmissionAndTimeout:
    """Validate high-priority periodic beacon frame generation and 0xEA06 watchdog."""

    def test_beacon_transmission_increments_counter(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, role=RingRole.RING_SUPERVISOR)
        assert engine.beacon_frames_transmitted_count == 0
        b1 = engine.transmit_beacon()
        assert b1.sequence_id == 1
        assert engine.beacon_frames_transmitted_count == 1
        b2 = engine.transmit_beacon()
        assert b2.sequence_id == 2
        assert engine.beacon_frames_transmitted_count == 2

    def test_receive_beacon_resets_silence_timer(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, role=RingRole.RING_SUPERVISOR)
        b = engine.transmit_beacon()
        engine.connection.beacon_silence_us = 800.0
        rc = engine.receive_beacon(b, ingress_port=RING_PORT2)
        assert rc is True
        assert engine.connection.beacon_silence_us == 0.0

    def test_beacon_supervisor_timeout_trips_0xEA06(self) -> None:
        engine = CipSafetyRingEngine(
            auto_activate=True,
            role=RingRole.RING_SUPERVISOR,
            beacon_interval_us=400,
            beacon_timeout_us=1600,
            auto_loopback_beacon=False,
        )
        engine.simulate_beacon_timeout()
        assert engine.diagnostic_code == DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT
        assert engine.diagnostic_code == 0xEA06
        assert engine.diagnostic_code == -5626
        assert engine.is_tripped is True

    def test_beacon_timeout_unblocks_port2(self) -> None:
        engine = CipSafetyRingEngine(
            auto_activate=True,
            role=RingRole.RING_SUPERVISOR,
            auto_loopback_beacon=False,
        )
        assert engine.port2.traffic_state == RingPortTrafficState.BLOCKED
        engine.simulate_beacon_timeout()
        assert engine.port2.traffic_state == RingPortTrafficState.UNBLOCKED

    def test_beacon_silence_in_cyclic_scan_step(self) -> None:
        engine = CipSafetyRingEngine(
            auto_activate=True,
            role=RingRole.RING_SUPERVISOR,
            beacon_interval_us=400,
            beacon_timeout_us=1600,
            auto_loopback_beacon=False,
        )
        # Advance 2 ms (2000 us) > 1600 us beacon timeout
        engine.scan_step(0.002)
        assert engine.diagnostic_code == DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT
        assert engine.is_tripped is True


# ============================================================================
# Section 7: Sequence Number Monotonicity & Replay Attack Rejection
# ============================================================================

class TestSection7SequenceMonotonicityAndReplayDefense:
    """Validate packet sequencing, monotonic validation, and replay attack rejection."""

    def test_strictly_monotonic_packets_accepted(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        pkt1 = engine.send_safety_packet(b"\x01\x02", sequence_number=1)
        pkt2 = engine.send_safety_packet(b"\x01\x02", sequence_number=2)
        pkt3 = engine.send_safety_packet(b"\x01\x02", sequence_number=3)

        engine.process_safety_packet(pkt1)
        engine.process_safety_packet(pkt2)
        engine.process_safety_packet(pkt3)
        assert engine.monitored_safety_sequence_number == 3
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_forward_sequence_gaps_accepted(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        pkt1 = engine.send_safety_packet(b"\x01\x02", sequence_number=5)
        pkt2 = engine.send_safety_packet(b"\x01\x02", sequence_number=10)
        engine.process_safety_packet(pkt1)
        engine.process_safety_packet(pkt2)
        assert engine.monitored_safety_sequence_number == 10
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_duplicate_packet_raises_replay_attack_error(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        pkt = engine.send_safety_packet(b"\x01\x02", sequence_number=10)
        engine.process_safety_packet(pkt)

        with pytest.raises(CipSafetyReplayAttackError):
            engine.process_safety_packet(pkt)

    def test_older_packet_raises_replay_attack_error(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        pkt_newer = engine.send_safety_packet(b"\x01\x02", sequence_number=20)
        pkt_older = engine.send_safety_packet(b"\x01\x02", sequence_number=15)
        engine.process_safety_packet(pkt_newer)

        with pytest.raises(CipSafetyReplayAttackError):
            engine.process_safety_packet(pkt_older)

    def test_replay_attack_trips_into_safe_state(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        pkt = engine.send_safety_packet(b"\x01\x02", sequence_number=5)
        engine.process_safety_packet(pkt)
        try:
            engine.process_safety_packet(pkt)
        except CipSafetyReplayAttackError:
            pass
        assert engine.is_tripped is True


# ============================================================================
# Section 8: Expected Packet Interval (EPI) Watchdogs & Timeout Tripping (0xEA02)
# ============================================================================

class TestSection8EpiWatchdogsAndTimeout:
    """Validate 10 ms nominal EPI, 30 ms 3x watchdog timeout, and 0xEA02 trip."""

    def test_silence_below_watchdog_timeout_remains_healthy(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.010)
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_tripped is False
        engine.scan_step(0.010)
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_tripped is False

    def test_silence_exceeding_watchdog_trips_0xEA02(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.020)
        engine.scan_step(0.015)  # Total 35 ms > 30.0 ms
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.diagnostic_code == 0xEA02
        assert engine.diagnostic_code == -5630
        assert engine.is_tripped is True
        assert engine.topology_state == RingTopologyState.FAULT_SAFE_STATE

    def test_simulate_epi_timeout_method(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        engine.simulate_epi_timeout()
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.is_tripped is True

    def test_packet_rx_resets_watchdog_silence(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.025)  # 25 ms silence
        pkt = engine.send_safety_packet(b"\x11\x22", sequence_number=1)
        engine.process_safety_packet(pkt)
        # Advance another 10 ms: total without reset would be 35 ms, but reset happened!
        engine.scan_step(0.010)
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_tripped is False


# ============================================================================
# Section 9: Dual-Channel Discrepancy Fault (0xEA03)
# ============================================================================

class TestSection9DualChannelDiscrepancyFault:
    """Validate dual-channel payload cross-comparison fault injection (0xEA03)."""

    def test_discrepancy_raises_and_trips_0xEA03(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        pkt = CipSafetyRingPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\x00",  # Corrupted byte
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetyDualChannelDiscrepancyError):
            engine.process_safety_packet(pkt)

        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert engine.diagnostic_code == 0xEA03
        assert engine.diagnostic_code == -5629
        assert engine.is_tripped is True
        assert engine.safe_state_engaged is True

    def test_simulate_dual_channel_discrepancy_method(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        engine.simulate_dual_channel_discrepancy()
        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert engine.is_tripped is True


# ============================================================================
# Section 10: Safety Network Number (SNN) & SCID Mismatch Fault (0xEA01)
# ============================================================================

class TestSection10SnnSignatureMismatchFault:
    """Validate SNN & SCID authentication and 0xEA01 fault trip."""

    def test_snn_mismatch_raises_and_trips_0xEA01(self) -> None:
        engine = CipSafetyRingEngine(snn=DEFAULT_SNN, auto_activate=True)
        bad_snn = bytes([0x20, 0x26, 0x99, 0x99, 0x00, 0x01])
        pkt = CipSafetyRingPacket(
            snn=bad_snn,
            tunid=1,
            ounid=100,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetySnnMismatchError):
            engine.process_safety_packet(pkt)

        assert engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert engine.diagnostic_code == 0xEA01
        assert engine.diagnostic_code == -5631
        assert engine.is_tripped is True

    def test_simulate_snn_signature_mismatch_method(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        engine.simulate_snn_signature_mismatch()
        assert engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert engine.is_tripped is True


# ============================================================================
# Section 11: CRC-S Checksum Corruption Fault (0xEA04)
# ============================================================================

class TestSection11CrcCorruptionFault:
    """Validate Safety CRC-S1 and CRC-S2 checksum verification and 0xEA04 fault."""

    def test_corrupted_crc_raises_and_trips_0xEA04(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        pkt = engine.send_safety_packet(b"\x12\x34", sequence_number=1)
        pkt.crc_s1 ^= 0xFFFF  # Invert checksum
        with pytest.raises(CipSafetyCrcCorruptionError):
            engine.process_safety_packet(pkt)

        assert engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION
        assert engine.diagnostic_code == 0xEA04
        assert engine.diagnostic_code == -5628
        assert engine.is_tripped is True

    def test_simulate_crc_s_corruption_method(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        engine.simulate_crc_s_corruption()
        assert engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION
        assert engine.is_tripped is True


# ============================================================================
# Section 12: Ring Break Fault & Fast Recovery (< 10 ms) (0xEA05)
# ============================================================================

class TestSection12RingBreakFaultAndFastRecovery:
    """Validate rapid restoration (< 10 ms mandate) and 0xEA05 link break trip."""

    def test_simulate_ring_break_on_port1(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, trip_on_break=True)
        engine.simulate_ring_break(port=1)
        assert engine.port1_link_up is False
        assert engine.diagnostic_code == DiagnosticCode.RING_BREAK_FAULT
        assert engine.diagnostic_code == 0xEA05
        assert engine.diagnostic_code == -5627
        assert engine.port2_blocked is False  # Port 2 unblocked immediately

    def test_simulate_ring_break_on_port2(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, trip_on_break=True)
        engine.simulate_ring_break(port=2)
        assert engine.port2_link_up is False
        assert engine.diagnostic_code == DiagnosticCode.RING_BREAK_FAULT

    def test_rapid_restoration_time_strictly_under_10ms(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        engine.detect_ring_break(port_id=1, measured_recovery_ms=8.5)
        assert engine.recovery_time_ms < 10.0
        assert engine.recovery_time_ms == 8.5

    def test_recover_ring_restores_closed_normal(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True, trip_on_break=True)
        engine.simulate_ring_break(port=1)
        assert engine.diagnostic_code == DiagnosticCode.RING_BREAK_FAULT
        engine.recover_ring()
        assert engine.port1_link_up is True
        assert engine.port2_link_up is True
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_tripped is False


# ============================================================================
# Section 13: Horner OCS Register Synchronization (%R1960..%R1967, %M457..%M458)
# ============================================================================

class TestSection13HornerOcsRegisterSynchronization:
    """Validate register memory mapping (%R1960..%R1967, %M457..%M458) with SYSTEM privilege."""

    def test_register_synchronization_nominal(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRingEngine(register_table=rt, auto_activate=True)
        engine.beacon_packets_transmitted_count = 150
        engine.recovery_time_ms = 8.5
        engine.max_ring_latency_ms = 12.0
        engine.monitored_safety_sequence_number = 42
        engine.safety_payload_word = 1234
        engine.sync_to_registers(rt)

        assert rt.read_word("%R1960") == int(RingTopologyState.CLOSED_NORMAL)
        assert rt.read_word("%R1961") == 150
        assert rt.read_word("%R1962") == 85  # 8.5 * 10
        assert rt.read_word("%R1963") == 120  # 12.0 * 10
        assert rt.read_word("%R1964") == 0
        assert rt.read_word("%R1965") == 42
        assert rt.read_word("%R1966") == 1234
        assert rt.read_word("%R1967") == 0x0000
        assert rt.read_bit("%M457") is True
        assert rt.read_bit("%M458") is False

    def test_register_synchronization_on_fault(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRingEngine(register_table=rt, auto_activate=True)
        engine.trip(DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT)
        engine.sync_to_registers(rt)

        assert rt.read_word("%R1960") == int(RingTopologyState.FAULT_SAFE_STATE)
        assert rt.read_word("%R1967") == 0xEA06 or rt.read_word("%R1967") == -5626
        assert rt.read_bit("%M457") is False
        assert rt.read_bit("%M458") is True

    def test_negative_safety_word_storage(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRingEngine(register_table=rt, auto_activate=True)
        engine.safety_payload_word = -500
        engine.sync_to_registers(rt)
        assert rt.read_word("%R1966") == -500


# ============================================================================
# Section 14: Pure ST POU Validation & Anti-Ladder Security Guard Interception
# ============================================================================

class TestSection14PureStPouValidationAndSecurityGuard:
    """Validate IEC 61131-3 Structured Text compliance and anti-ladder interception."""

    def test_cip_safety_ring_sync_pou_syntax_with_st_parser(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse(CIP_SAFETY_RING_SYNC_POU)
        assert ast is not None
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyRingSync"

    def test_pou_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_RING_SYNC_POU)
        regs = set(ast.bound_registers)
        for expected in ["%R1960", "%R1961", "%R1962", "%R1963", "%R1964", "%R1965", "%R1966", "%R1967", "%M457", "%M458"]:
            assert expected in regs

    def test_verify_cip_safety_ring_pure_st_function(self) -> None:
        assert verify_cip_safety_ring_pure_st() is True

    def test_security_guard_assert_pure_st_passes(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_RING_SYNC_POU)

    def test_anti_ladder_contacts_interception(self) -> None:
        bad_st = CIP_SAFETY_RING_SYNC_POU + "\n---[ ]--- RUNG 01"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_anti_ladder_coils_interception(self) -> None:
        bad_st = CIP_SAFETY_RING_SYNC_POU + "\n---( )--- COIL_01"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_anti_ladder_rung_delimiters_interception(self) -> None:
        bad_st = CIP_SAFETY_RING_SYNC_POU + "\nNETWORK 1: MAIN_LADDER\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_anti_ladder_mnemonics_interception(self) -> None:
        bad_st = CIP_SAFETY_RING_SYNC_POU + "\nXIC Sensor1 OTE Motor1;\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# Section 15: ILogicUnit Compliance & Scan Cycle Simulation
# ============================================================================

class TestSection15ILogicUnitCompliance:
    """Validate ILogicUnit interface implementation, scan steps, and execution."""

    def test_ilogicunit_interface_inheritance(self) -> None:
        engine = CipSafetyRingEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CipSafetyRingEngine"
        assert engine.priority == 95
        assert engine.is_enabled is True

    def test_is_enabled_toggle(self) -> None:
        engine = CipSafetyRingEngine()
        engine.is_enabled = False
        assert engine.is_enabled is False
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        engine.execute(ctx)
        assert engine.words_processed == 0

    def test_scan_step_with_context(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        engine.scan_step(0.010, context=ctx)
        assert engine.words_processed == 1

    def test_multi_cycle_cyclic_simulation(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        for i in range(1, 21):
            pkt = engine.send_safety_packet(b"\x01\x02", sequence_number=i)
            engine.process_safety_packet(pkt)
            ctx = ScanContext(cycle=i, dt_ms=10.0, elapsed_time_ms=float(i * 10))
            engine.execute(ctx)
        assert engine.words_processed == 20
        assert engine.diagnostic_code == DiagnosticCode.OK


# ============================================================================
# Section 16: Reset Nominal Recovery & Safe State Coordination
# ============================================================================

class TestSection16ResetNominalRecovery:
    """Validate fault clearing, latched resets, and return to nominal closed state."""

    def test_reset_clears_fault_and_restores_closed_normal(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        engine.trip(DiagnosticCode.BEACON_SUPERVISOR_TIMEOUT)
        assert engine.is_tripped is True
        assert engine.topology_state == RingTopologyState.FAULT_SAFE_STATE

        engine.reset()
        assert engine.is_tripped is False
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.topology_state == RingTopologyState.CLOSED_NORMAL
        assert engine.port2_blocked is True
        assert engine.consecutive_fault_count == 0

    def test_reset_fault_method_returns_success_result(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        engine.trip(DiagnosticCode.EPI_WATCHDOG_TIMEOUT)
        res = engine.reset_fault(force=True, restore_closed=True)
        assert res.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == DiagnosticCode.OK


# ============================================================================
# Section 17: Verification Runner & Strict 4-State Engineering Contract
# ============================================================================

class TestSection17VerificationRunnerAndContract:
    """Validate deterministic verification runner and strict 4-state contract response."""

    def test_verification_runner_returns_strict_4_state_dict(self) -> None:
        res = run_cip_safety_ring_verification()
        assert isinstance(res, dict)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 12
        assert res["stages_passed"] == 12
        assert res["passed_stages"] == 12
        assert res["data"]["work_package"] == "W235"

    def test_verification_runner_all_stages_pass(self) -> None:
        res = run_cip_safety_ring_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 12
        for s in stages:
            assert s["passed"] is True, f"Stage {s['stage']} ({s['name']}) failed: {s['details']}"

    def test_verification_runner_writes_evidence_json(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_ring_evidence.json"
        res = run_cip_safety_ring_verification(output_path=out_file)
        assert out_file.exists()
        loaded = json.loads(out_file.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
        assert loaded["data"]["work_package"] == "W235"

    def test_cli_verification_script_execution(self) -> None:
        cmd = [sys.executable, "scripts/run_cip_safety_ring_verification.py"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0
        assert "All 9 CIP Safety Ring protocol stages PASSED" in proc.stdout

    def test_register_map_in_verification_output(self) -> None:
        res = run_cip_safety_ring_verification()
        reg_map = res["data"]["register_map"]
        assert "%R1960" in reg_map
        assert "%R1967" in reg_map
        assert "%M457" in reg_map
        assert "%M458" in reg_map


# ============================================================================
# Section 18: Extended Protocol Edge Cases & Boundary Verification
# ============================================================================

class TestSection18ExtendedEdgeCasesAndProtocolBoundaries:
    """Additional edge cases, bitmasks, and boundary tests for Wave W235."""

    def test_scale_time_ms_to_int16_boundaries(self) -> None:
        assert scale_time_ms_to_int16(8.5) == 85
        assert scale_time_ms_to_int16(0.0) == 0
        assert scale_time_ms_to_int16(4000.0) == 32767
        assert scale_time_ms_to_int16(-4000.0) == -32768

    def test_safe_write_word_and_uword_bounds(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R1960", 0)
        assert rt.read_word("%R1960") == 0
        safe_write_word(rt, "%R1967", 0xEA01)
        assert rt.read_word("%R1967") == -5631
        safe_write_uword(rt, "%R1967", 0xEA06)
        assert rt.read_word("%R1967") == -5626

    def test_safe_write_bit(self) -> None:
        rt = RegisterTable()
        safe_write_bit(rt, "%M457", True)
        assert rt.read_bit("%M457") is True
        safe_write_bit(rt, "%M458", False)
        assert rt.read_bit("%M458") is False

    def test_validate_snn_edge_cases(self) -> None:
        assert validate_snn(DEFAULT_SNN) is True
        assert validate_snn("2026-1006AA77") is True
        assert validate_snn(b"\x00" * 6) is False
        assert validate_snn(b"\xff" * 6) is False
        assert validate_snn(b"\x00\x00\x12\x34\x56\x78") is False
        assert validate_snn(b"\x12\x34\x00\x00\x00\x00") is False
        assert validate_snn(b"short") is False
        assert validate_snn(12345) is False

    def test_parse_and_format_snn_roundtrip(self) -> None:
        formatted = format_snn(DEFAULT_SNN)
        assert formatted == "2026-1006AA77"
        parsed = parse_snn(formatted)
        assert parsed == DEFAULT_SNN
        with pytest.raises(ValueError):
            format_snn(b"\x01")
        with pytest.raises(ValueError):
            parse_snn("NOT_A_VALID_SNN")

    def test_snn_dataclass_invalid_inputs(self) -> None:
        with pytest.raises(ValueError):
            SafetyNetworkNumber(b"12345")
        with pytest.raises(ValueError):
            SafetyNetworkNumber(DEFAULT_SNN, crc_id=0x10000)

    def test_scid_invalid_from_bytes(self) -> None:
        with pytest.raises(ValueError):
            SafetyConfigurationIdentifier.from_bytes(b"short")
        with pytest.raises(ValueError):
            SafetyConfigurationIdentifier.from_bytes(b"too_long_bytes_123")

    def test_tunid_and_ounid_invalid_from_bytes(self) -> None:
        with pytest.raises(ValueError):
            TargetUniqueNetworkId.from_bytes(b"short")
        with pytest.raises(ValueError):
            OriginatorUniqueNetworkId.from_bytes(b"short")

    def test_dual_channel_integer_payload_verification(self) -> None:
        assert verify_dual_channel_payload(0x1234, (~0x1234) & 0xFFFF, DiversifiedMode.INVERTED) is True
        assert verify_dual_channel_payload(0x1234, 0x1234, DiversifiedMode.INVERTED) is False
        assert verify_dual_channel_payload(0x1234, 0x1234, DiversifiedMode.IDENTICAL) is True
        assert verify_dual_channel_payload(0x1234, 0x5678, DiversifiedMode.IDENTICAL) is False

    def test_dual_channel_invalid_types(self) -> None:
        assert verify_dual_channel_payload("bad", "types") is False

    def test_engine_get_state_dict_contents(self) -> None:
        engine = CipSafetyRingEngine()
        sd = engine.get_state_dict()
        assert "topology_state" in sd
        assert "diagnostic_code" in sd
        assert "diagnostic_code_hex" in sd
        assert "port1_link_up" in sd
        assert "port2_link_up" in sd
        assert "port2_blocked" in sd
        assert "beacon_count" in sd
        assert "consecutive_fault_count" in sd

    def test_engine_double_fault_trip_keeps_first(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        engine.trip(DiagnosticCode.SNN_SIGNATURE_MISMATCH)
        engine.trip(DiagnosticCode.CRC_S_CORRUPTION)
        assert engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert engine.consecutive_fault_count == 2

    def test_engine_reset_fault_when_not_faulted(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        res = engine.reset_fault()
        assert res.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_engine_set_port_link_toggle(self) -> None:
        engine = CipSafetyRingEngine(auto_activate=True)
        assert engine.port1_link_up is True
        assert engine.port2_link_up is True
        engine.set_port_link(RING_PORT1, False)
        assert engine.port1_link_up is False
        assert engine.topology_state == RingTopologyState.FAULT_SAFE_STATE

    def test_diagnostic_code_bitwise_operators(self) -> None:
        dc = DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert (dc & 0xFFFF) == 0xEA02
        assert (0xFFFF & dc) == 0xEA02
        assert (dc | 0) == 0xEA02
        assert (dc ^ 0) == 0xEA02

    def test_safety_control_byte_composition(self) -> None:
        flags = SafetyControlByte.RUN | SafetyControlByte.RING_BEACON
        assert SafetyControlByte.RUN in flags
        assert SafetyControlByte.RING_BEACON in flags
        assert SafetyControlByte.SAFETY_DEMAND not in flags
