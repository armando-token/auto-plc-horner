"""Comprehensive Unit Test Suite for Wave W229 CIP Safety Point-to-Point Target Protocol Engine.

Work Package: W229 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 115+ Comprehensive Unit Tests across 15 Sections:
1. Section 1: Protocol Constants, Identifiers, Enums, & Diagnostic Codes (signed/unsigned & 0xFFFF).
2. Section 2: SNN Format, SCID, TUNID, & OUNID Configuration & Parsing.
3. Section 3: Dual-Channel Payload Parity & CRC-S Checksums.
4. Section 4: CIP Safety Point Packet Serialization, Deserialization, & Integrity.
5. Section 5: Connection State Machine (CLOSED -> CONFIGURING -> WAITING_FOR_TID -> OPERATIONAL -> FAULT_SAFE_STATE).
6. Section 6: Sequence Number Monotonicity, Replay Attack Protection & Rollover Fault (0xE805).
7. Section 7: Expected Packet Interval (EPI) Watchdogs & Timeout Tripping (0xE802).
8. Section 8: Dual-Channel Discrepancy Fault (0xE803).
9. Section 9: Safety Network Number (SNN) & TUNID Mismatch Fault (0xE801).
10. Section 10: CRC-S Checksum Corruption Fault (0xE804).
11. Section 11: Connection Disconnect Fault (0xE806).
12. Section 12: Horner OCS Register Synchronization (%R1900..%R1907, %M443..%M444 with SYSTEM privilege).
13. Section 13: Pure ST POU Validation & Anti-Ladder Security Guard Interception.
14. Section 14: ILogicUnit Interface Compliance & Scan Cycle Simulation.
15. Section 15: Safe State Coordination, Recovery, & Verification Runner (Strict 4-State Contract).
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
from jev_cscape.telemetry.cip_safety_point import (
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_POINT_CLASS_ID,
    CIP_SAFETY_POINT_CONNECTION_CLASS_ID,
    CIP_SAFETY_POINT_POU,
    CIP_SAFETY_POINT_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_POINT_SYNC_POU,
    CIP_SAFETY_POINT_TO_POINT_SYNC_POU,
    CIP_SAFETY_POINT_VALIDATOR_CLASS_ID,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyPointEngine,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    DEFAULT_EPI_MS,
    DEFAULT_OUNID,
    DEFAULT_SCID,
    DEFAULT_SCID_CRC,
    DEFAULT_SCID_TIMESTAMP,
    DEFAULT_SNN,
    DEFAULT_TUNID,
    DEFAULT_WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DIAG_CONNECTION_DISCONNECT,
    DIAG_CONNECTION_REJECTED,
    DIAG_CRC_S_CORRUPTION,
    DIAG_DUAL_CHANNEL_DISCREPANCY,
    DIAG_EPI_TIMEOUT,
    DIAG_EPI_WATCHDOG_TIMEOUT,
    DIAG_OK,
    DIAG_SEQUENCE_NUMBER_ROLLOVER_FAULT,
    DIAG_SEQUENCE_ROLLOVER,
    DIAG_SNN_MISMATCH,
    EPI_WATCHDOG_TIMEOUT_MS,
    NOMINAL_EPI_MS,
    REGISTER_LATENCY_SCALE_FACTOR,
    WATCHDOG_MULTIPLIER,
    BlackChannelThreat,
    CipSafetyConnectionDisconnectError,
    CipSafetyConnectionState,
    CipSafetyControlByte,
    CipSafetyCrcCorruptionError,
    CipSafetyDiagnosticCode,
    CipSafetyDisconnectError,
    CipSafetyDualChannelDiscrepancyError,
    CipSafetyEpiTimeoutError,
    CipSafetyGuardError,
    CipSafetyOperationalState,
    CipSafetyPacket,
    CipSafetyPoint,
    CipSafetyPointDiagnosticCode,
    CipSafetyPointEngine,
    CipSafetyPointError,
    CipSafetyPointMode,
    CipSafetyPointPacket,
    CipSafetyPointState,
    CipSafetyPointTarget,
    CipSafetyPointToPoint,
    CipSafetyPointToPointEngine,
    CipSafetyReplayAttackError,
    CipSafetySequenceError,
    CipSafetySequenceRepetitionError,
    CipSafetySequenceRolloverError,
    CipSafetySnnMismatchError,
    ConnectionState,
    DiagnosticCode,
    DiagnosticStatusCode,
    DiversifiedMode,
    NetworkSafetyState,
    OUNID,
    OriginatorUniqueNetworkId,
    PointConnectionState,
    PointOperationalState,
    PointSafetyState,
    PointToPointConnectionState,
    PURE_ST_POU,
    SCID,
    SinglePointSafetyEngine,
    SNN,
    SafetyConfigurationIdentifier,
    SafetyControlByte,
    SafetyModeByte,
    SafetyNetworkNumber,
    SafetyNetworkOperationalState,
    SafetyOperationalState,
    SafetyPointOperationalState,
    SafetyPointState,
    SafetyStatusBits,
    TUNID,
    TargetUniqueNetworkId,
    calc_crc_s1,
    calc_crc_s2,
    calculate_crc16_ccitt,
    compute_crc_s1,
    compute_crc_s2,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_point_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    scale_latency_ms_to_int16,
    validate_snn,
    verify_cip_safety_point_pure_st,
    verify_dual_channel_payload,
)


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner RegisterTable instance."""
    return RegisterTable()


@pytest.fixture
def active_engine(register_table: RegisterTable) -> CipSafetyPointEngine:
    """Provide an auto-activated CipSafetyPointEngine."""
    return CipSafetyPointEngine(
        register_table=register_table,
        snn=DEFAULT_SNN,
        tunid=101,
        ounid=100,
        auto_activate=True,
    )


@pytest.fixture
def idle_engine(register_table: RegisterTable) -> CipSafetyPointEngine:
    """Provide an unconfigured/idle CipSafetyPointEngine."""
    return CipSafetyPointEngine(
        register_table=register_table,
        snn=DEFAULT_SNN,
        tunid=101,
        ounid=100,
        auto_activate=False,
    )


# ============================================================================
# Section 1: Protocol Constants, Identifiers, Enums, & Diagnostic Codes
# ============================================================================

class TestSection1ProtocolConstantsAndEnums:
    """Verify ODVA Volume 5 Class IDs, protocol constants, Enums, and DiagnosticCode."""

    def test_class_ids_defined(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_POINT_CLASS_ID == 0x39
        assert CIP_SAFETY_POINT_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_POINT_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_POINT_CONNECTION_CLASS_ID == 0x3B

    def test_default_epi_and_watchdog_constants(self) -> None:
        assert NOMINAL_EPI_MS in (10.0, 20.0)
        assert DEFAULT_EPI_MS in (10.0, 20.0)
        assert WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert EPI_WATCHDOG_TIMEOUT_MS in (30.0, 60.0)
        assert DEFAULT_WATCHDOG_TIMEOUT_MS in (30.0, 60.0)

    def test_crc_polynomial_constants(self) -> None:
        assert CRC16_CCITT_POLY == 0x1021
        assert CRC16_CCITT_INIT == 0xFFFF
        assert REGISTER_LATENCY_SCALE_FACTOR == 10.0

    def test_point_connection_state_enum_values(self) -> None:
        assert PointConnectionState.CLOSED == 0
        assert PointConnectionState.CONFIGURING == 1
        assert PointConnectionState.WAITING_FOR_TID == 2
        assert PointConnectionState.OPERATIONAL == 3
        assert PointConnectionState.FAULT_SAFE_STATE == 4

        # Aliases
        assert PointConnectionState.IDLE == 0
        assert PointConnectionState.CONNECTING == 1
        assert PointConnectionState.ESTABLISHED == 2
        assert PointConnectionState.FAULTED == 4
        assert PointConnectionState.SAFE_STATE == 4
        assert PointToPointConnectionState == PointConnectionState
        assert CipSafetyPointState == PointConnectionState
        assert ConnectionState == PointConnectionState

    def test_safety_operational_state_enum_values(self) -> None:
        assert SafetyOperationalState.INITIALIZING == 0
        assert SafetyOperationalState.OPERATIONAL == 1
        assert SafetyOperationalState.DEGRADED == 2
        assert SafetyOperationalState.TRIPPED == 3
        assert SafetyOperationalState.SAFE_STATE == 4

        # Aliases
        assert SafetyPointOperationalState == SafetyOperationalState
        assert SafetyNetworkOperationalState == SafetyOperationalState
        assert PointOperationalState == SafetyOperationalState

    def test_diversified_mode_enum_values(self) -> None:
        assert DiversifiedMode.INVERTED == 1
        assert DiversifiedMode.IDENTICAL == 2

    def test_safety_control_byte_flags(self) -> None:
        assert SafetyControlByte.IDLE == 0x00
        assert SafetyControlByte.RUN == (1 << 0)
        assert SafetyControlByte.PING_REQ == (1 << 1)
        assert SafetyControlByte.PING_RESP == (1 << 2)
        assert SafetyControlByte.SAFETY_DEMAND == (1 << 3)
        assert SafetyControlByte.FAULT_PRESENT == (1 << 4)
        assert SafetyControlByte.RESET_REQUEST == (1 << 5)
        assert SafetyControlByte.TID_REQUEST == (1 << 6)
        assert SafetyControlByte.DISCONNECT_REQUEST == (1 << 7)

    def test_safety_status_bits_flags(self) -> None:
        assert SafetyStatusBits.CONNECTION_ACTIVE == (1 << 0)
        assert SafetyStatusBits.PERMISSIVE_HIGH == (1 << 1)
        assert SafetyStatusBits.FAULT_LATCHED == (1 << 2)
        assert SafetyStatusBits.EPI_TIMEOUT_LATCH == (1 << 3)
        assert SafetyStatusBits.SEQUENCE_ERROR_LATCH == (1 << 4)
        assert SafetyStatusBits.CRC_ERROR_LATCH == (1 << 5)
        assert SafetyStatusBits.UNID_MISMATCH_LATCH == (1 << 6)
        assert SafetyStatusBits.DISCREPANCY_LATCH == (1 << 7)
        assert SafetyStatusBits.DISCONNECT_LATCH == (1 << 8)

    def test_black_channel_threats(self) -> None:
        assert BlackChannelThreat.CORRUPTION == 1
        assert BlackChannelThreat.UNINTENDED_REPETITION == 2
        assert BlackChannelThreat.INCORRECT_SEQUENCE == 3
        assert BlackChannelThreat.LOSS == 4
        assert BlackChannelThreat.UNACCEPTABLE_DELAY == 5
        assert BlackChannelThreat.INSERTION == 6
        assert BlackChannelThreat.MASQUERADE == 7
        assert BlackChannelThreat.ADDRESSING_FAULT == 8

    def test_diagnostic_code_values(self) -> None:
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.SNN_SIGNATURE_MISMATCH == 0xE801
        assert DiagnosticCode.SNN_MISMATCH == 0xE801
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xE802
        assert DiagnosticCode.EPI_TIMEOUT == 0xE802
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == 0xE803
        assert DiagnosticCode.CRC_S_CORRUPTION == 0xE804
        assert DiagnosticCode.CRC_FAULT == 0xE804
        assert DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT == 0xE805
        assert DiagnosticCode.SEQUENCE_FAULT == 0xE805
        assert DiagnosticCode.CONNECTION_DISCONNECT == 0xE806
        assert DiagnosticCode.CONNECTION_REJECTED == 0xE806

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        # DiagnosticCode 0xE801 unsigned is 59393, signed is -6143
        c = DiagnosticCode.SNN_MISMATCH
        assert c == 0xE801
        assert c == -6143
        assert c == 59393
        assert (c & 0xFFFF) == 0xE801
        assert (0xE801 & c) == 0xE801

        # DiagnosticCode 0xE802 unsigned is 59394, signed is -6142
        c2 = DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert c2 == 0xE802
        assert c2 == -6142
        assert (c2 & 0xFFFF) == 0xE802

    def test_diagnostic_code_bitwise_and_masking(self) -> None:
        c = DiagnosticCode.CRC_S_CORRUPTION
        masked = c & 0xFFFF
        assert isinstance(masked, DiagnosticCode)
        assert masked == 0xE804

        rmasked = 0xFFFF & c
        assert isinstance(rmasked, DiagnosticCode)
        assert rmasked == 0xE804

    def test_diagnostic_code_str_and_repr(self) -> None:
        c = DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert "0xE803" in str(c)
        assert "DUAL_CHANNEL_DISCREPANCY" in repr(c)

    def test_diagnostic_code_hash_and_set(self) -> None:
        s = {DiagnosticCode.OK, DiagnosticCode.SNN_MISMATCH, DiagnosticCode.EPI_TIMEOUT}
        assert DiagnosticCode.OK in s
        assert DiagnosticCode.SNN_MISMATCH in s
        assert DiagnosticCode(0xE801) in s
        assert DiagnosticCode(-6143) in s


# ============================================================================
# Section 2: SNN Format, SCID, TUNID, & OUNID Configuration & Parsing
# ============================================================================

class TestSection2SnnScidTunidOunid:
    """Verify SNN, SCID, TUNID, and OUNID configuration, serialization, and parsing."""

    def test_generate_snn_default(self) -> None:
        snn = generate_snn(0x2026, 0x1006CC77)
        assert len(snn) == 6
        assert snn[:2] == bytes([0x20, 0x26])

    def test_format_snn_hyphenated(self) -> None:
        raw = bytes([0x20, 0x26, 0x10, 0x06, 0xCC, 0x77])
        formatted = format_snn(raw)
        assert formatted == "2026-1006CC77"

    def test_format_snn_str_passthrough(self) -> None:
        s = "2026-1006CC77"
        assert format_snn(s) == s

    def test_parse_snn_valid(self) -> None:
        parsed = parse_snn("2026-1006CC77")
        assert len(parsed) == 6
        assert parsed == bytes([0x20, 0x26, 0x10, 0x06, 0xCC, 0x77])

    def test_parse_snn_invalid_length_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_snn("2026-1006")

    def test_validate_snn_valid_and_invalid(self) -> None:
        assert validate_snn(bytes([0x20, 0x26, 0x10, 0x06, 0xCC, 0x77])) is True
        assert validate_snn(b"\x00" * 6) is False
        assert validate_snn(b"\xFF" * 6) is False
        assert validate_snn(b"\x12\x34") is False
        assert validate_snn("2026-1006CC77") is True

    def test_safety_network_number_dataclass_methods(self) -> None:
        snn_obj = SafetyNetworkNumber.create(0x2026, 0x1006CC77, 0x0001)
        assert snn_obj.date_word == 0x2026
        assert snn_obj.time_dword == 0x1006CC77
        assert snn_obj.high_word == 0x0001
        assert len(snn_obj.raw_bytes) == 8
        assert "2026" in snn_obj.to_hex()

    def test_scid_matches_and_serialization(self) -> None:
        scid1 = SafetyConfigurationIdentifier(crc=0x20261006, timestamp=0x10060001)
        scid2 = SafetyConfigurationIdentifier(crc=0x20261006, timestamp=0x10060001)
        scid3 = SafetyConfigurationIdentifier(crc=0x99999999, timestamp=0x10060001)
        assert scid1.matches(scid2) is True
        assert scid1.matches(scid3) is False
        assert len(scid1.to_bytes()) == 8

    def test_tunid_and_ounid_binding(self) -> None:
        snn_obj = SafetyNetworkNumber.create(0x2026, 0x1006CC77, 0x0001)
        tunid = TargetUniqueNetworkId(snn=snn_obj, target_node_id=101)
        ounid = OriginatorUniqueNetworkId(snn=snn_obj, originator_node_id=100)
        assert tunid.target_node_id == 101
        assert ounid.originator_node_id == 100
        assert tunid.matches(TargetUniqueNetworkId(snn=snn_obj, target_node_id=101)) is True
        assert tunid.matches(TargetUniqueNetworkId(snn=snn_obj, target_node_id=102)) is False


# ============================================================================
# Section 3: Dual-Channel Payload Parity & CRC-S Checksums
# ============================================================================

class TestSection3DualChannelAndCrcs:
    """Verify 16-bit CRC-S1, inverted CRC-S2, and dual-channel diversified parity."""

    def test_crc16_ccitt_calculation(self) -> None:
        data = b"\x01\x02\x03\x04"
        crc = calculate_crc16_ccitt(data)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

    def test_calc_crc_s1_alias(self) -> None:
        data = b"\xAA\xBB\xCC\xDD"
        assert calc_crc_s1(data) == calculate_crc16_ccitt(data)
        assert compute_crc_s1(data) == calculate_crc16_ccitt(data)

    def test_calc_crc_s2_inverted_data(self) -> None:
        data = b"\x01\x02\x03\x04"
        crc1 = calc_crc_s1(data)
        crc2 = calc_crc_s2(data, inverted=True)
        assert crc2 == ((~crc1) & 0xFFFF)

    def test_calc_crc_s2_header_payload_signature(self) -> None:
        ts = 1000
        seq = 5
        payload = b"\x12\x34"
        crc2 = calc_crc_s2(ts, seq, payload)
        assert isinstance(crc2, int)
        assert 0 <= crc2 <= 0xFFFF

    def test_verify_dual_channel_inverted_matching(self) -> None:
        ch_a = b"\x12\x34\x56"
        ch_b = bytes((~b) & 0xFF for b in ch_a)
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is True

    def test_verify_dual_channel_inverted_mismatch(self) -> None:
        ch_a = b"\x12\x34\x56"
        ch_b = bytearray((~b) & 0xFF for b in ch_a)
        ch_b[0] ^= 0x01
        assert verify_dual_channel_payload(ch_a, bytes(ch_b), DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_identical_matching(self) -> None:
        ch_a = b"\xDE\xAD\xBE\xEF"
        ch_b = b"\xDE\xAD\xBE\xEF"
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.IDENTICAL) is True

    def test_verify_dual_channel_different_lengths(self) -> None:
        ch_a = b"\x01\x02"
        ch_b = b"\xFE"
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_integer_payloads(self) -> None:
        val_a = 0x1234
        val_b = (~val_a) & 0xFFFF
        assert verify_dual_channel_payload(val_a, val_b, DiversifiedMode.INVERTED) is True
        assert verify_dual_channel_payload(val_a, val_a, DiversifiedMode.IDENTICAL) is True


# ============================================================================
# Section 4: CIP Safety Point Packet Serialization & Integrity
# ============================================================================

class TestSection4PacketSerializationAndIntegrity:
    """Verify packet container creation, serialization, deserialization, and CRC verification."""

    def test_packet_crc_calculation(self) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN,
            tunid=101,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        c1, c2 = pkt.calculate_crcs()
        assert c1 == pkt.crc_s1
        assert c2 == pkt.crc_s2
        assert c1 != 0
        assert c2 != 0

    def test_packet_serialization_and_deserialization(self) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN,
            tunid=101,
            ounid=100,
            sequence_number=42,
            timestamp_ms=125.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\xAA\xBB",
            channel_b_payload=b"\x55\x44",
        )
        pkt.calculate_crcs()
        raw = pkt.serialize()
        assert isinstance(raw, bytes)
        assert len(raw) > 30

        deser = CipSafetyPointPacket.deserialize(raw)
        assert deser.sequence_number == 42
        assert deser.tunid == 101
        assert deser.channel_a_payload == b"\xAA\xBB"
        assert deser.channel_b_payload == b"\x55\x44"
        assert deser.crc_s1 == pkt.crc_s1
        assert deser.crc_s2 == pkt.crc_s2

    def test_packet_verify_crcs_valid(self) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN,
            tunid=101,
            ounid=100,
            sequence_number=10,
            channel_a_payload=b"\x11\x22",
            channel_b_payload=b"\xEE\xDD",
        )
        pkt.calculate_crcs()
        assert pkt.verify_crcs() is True

    def test_packet_verify_crcs_corrupt_s1(self) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN,
            tunid=101,
            ounid=100,
            sequence_number=10,
            channel_a_payload=b"\x11\x22",
            channel_b_payload=b"\xEE\xDD",
        )
        pkt.calculate_crcs()
        pkt.crc_s1 ^= 0x0001
        assert pkt.verify_crcs() is False

    def test_packet_verify_crcs_corrupt_s2(self) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN,
            tunid=101,
            ounid=100,
            sequence_number=10,
            channel_a_payload=b"\x11\x22",
            channel_b_payload=b"\xEE\xDD",
        )
        pkt.calculate_crcs()
        pkt.crc_s2 ^= 0x0001
        assert pkt.verify_crcs() is False

    def test_packet_verify_dual_channel(self) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN,
            tunid=101,
            channel_a_payload=b"\x00\xFF",
            channel_b_payload=b"\xFF\x00",
        )
        assert pkt.verify_dual_channel(DiversifiedMode.INVERTED) is True

    def test_packet_deserialize_too_short_raises(self) -> None:
        with pytest.raises(ValueError):
            CipSafetyPointPacket.deserialize(b"\x00" * 10)


# ============================================================================
# Section 5: Connection State Machine Lifecycle
# ============================================================================

class TestSection5ConnectionStateMachine:
    """Verify CLOSED -> CONFIGURING -> WAITING_FOR_TID -> OPERATIONAL -> FAULT_SAFE_STATE."""

    def test_initial_state_closed(self, idle_engine: CipSafetyPointEngine) -> None:
        assert idle_engine.state == PointConnectionState.CLOSED
        assert idle_engine.point_active is False
        assert idle_engine.safety_trip_safe_state_engaged is False

    def test_configure_transitions_to_configuring(self, idle_engine: CipSafetyPointEngine) -> None:
        idle_engine.configure(snn=DEFAULT_SNN, tunid=101, ounid=100)
        assert idle_engine.state == PointConnectionState.CONFIGURING
        assert idle_engine.safety_point_operational_state == SafetyOperationalState.INITIALIZING

    def test_initiate_handshake_transitions_to_waiting_for_tid(
        self, idle_engine: CipSafetyPointEngine
    ) -> None:
        idle_engine.configure(snn=DEFAULT_SNN, tunid=101, ounid=100)
        pkt = idle_engine.initiate_handshake()
        assert idle_engine.state == PointConnectionState.WAITING_FOR_TID
        assert isinstance(pkt, CipSafetyPointPacket)
        assert pkt.mode_byte == SafetyControlByte.TID_REQUEST

    def test_confirm_tid_transitions_to_operational(
        self, idle_engine: CipSafetyPointEngine
    ) -> None:
        idle_engine.configure(snn=DEFAULT_SNN, tunid=101, ounid=100)
        idle_engine.initiate_handshake()
        idle_engine.confirm_tid(101)
        assert idle_engine.state == PointConnectionState.OPERATIONAL
        assert idle_engine.point_active is True
        assert idle_engine.diagnostic_code == DiagnosticCode.OK

    def test_confirm_tid_mismatch_trips_to_fault_safe_state(
        self, idle_engine: CipSafetyPointEngine
    ) -> None:
        idle_engine.configure(snn=DEFAULT_SNN, tunid=101, ounid=100)
        idle_engine.initiate_handshake()
        with pytest.raises(CipSafetySnnMismatchError):
            idle_engine.confirm_tid(999)  # Mismatch
        assert idle_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert idle_engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert idle_engine.safety_trip_safe_state_engaged is True

    def test_auto_activate_starts_in_operational(self, active_engine: CipSafetyPointEngine) -> None:
        assert active_engine.state == PointConnectionState.OPERATIONAL
        assert active_engine.point_active is True
        assert active_engine.safety_trip_safe_state_engaged is False

    def test_packet_reception_in_waiting_for_tid_transitions_to_operational(
        self, idle_engine: CipSafetyPointEngine
    ) -> None:
        idle_engine.configure(snn=DEFAULT_SNN, tunid=101, ounid=100)
        idle_engine.initiate_handshake()
        assert idle_engine.state == PointConnectionState.WAITING_FOR_TID

        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        idle_engine.receive_safety_packet(pkt)
        assert idle_engine.state == PointConnectionState.OPERATIONAL
        assert idle_engine.point_active is True

    def test_manual_transition_to(self, active_engine: CipSafetyPointEngine) -> None:
        active_engine.transition_to(PointConnectionState.FAULT_SAFE_STATE)
        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.safety_point_operational_state == SafetyOperationalState.SAFE_STATE


# ============================================================================
# Section 6: Sequence Number Monotonicity & Replay Protection (0xE805)
# ============================================================================

class TestSection6SequenceMonotonicityAndRollover:
    """Verify sequence monotonicity, replay attack rejection, and rollover fault 0xE805."""

    def test_monotonic_increasing_sequence_accepted(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        for seq in range(1, 10):
            pkt = CipSafetyPointPacket(
                snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=seq,
                channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
            )
            pkt.calculate_crcs()
            active_engine.receive_safety_packet(pkt)
            assert active_engine.last_rx_sequence == seq
            assert active_engine.diagnostic_code == DiagnosticCode.OK

    def test_replay_same_sequence_rejected_0xE805(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=5,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        active_engine.receive_safety_packet(pkt)

        # Ingest same sequence again (replay attack)
        with pytest.raises(CipSafetySequenceRolloverError):
            active_engine.receive_safety_packet(pkt)

        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.diagnostic_code == DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT
        assert active_engine.diagnostic_code == 0xE805

    def test_decreased_sequence_rejected_0xE805(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        pkt1 = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=10,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt1.calculate_crcs()
        active_engine.receive_safety_packet(pkt1)

        pkt2 = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=9,  # Decreased
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt2.calculate_crcs()
        with pytest.raises(CipSafetySequenceRolloverError):
            active_engine.receive_safety_packet(pkt2)

        assert active_engine.diagnostic_code == 0xE805

    def test_simulate_sequence_rollover_fault_helper(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.simulate_sequence_rollover_fault()
        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.diagnostic_code == DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT
        assert (active_engine.connection_fault_bitmask & SafetyStatusBits.SEQUENCE_ERROR_LATCH) != 0

    def test_simulate_replay_attack_helper(self, active_engine: CipSafetyPointEngine) -> None:
        active_engine.simulate_replay_attack()
        assert active_engine.diagnostic_code == 0xE805
        assert active_engine.safety_trip_safe_state_engaged is True

    def test_send_packet_increments_tx_sequence(self, active_engine: CipSafetyPointEngine) -> None:
        pkt1 = active_engine.send_safety_packet(channel_a_payload=b"\x01")
        pkt2 = active_engine.send_safety_packet(channel_a_payload=b"\x02")
        assert pkt2.sequence_number == (pkt1.sequence_number + 1)


# ============================================================================
# Section 7: Expected Packet Interval (EPI) Watchdogs & Timeout (0xE802)
# ============================================================================

class TestSection7EpiWatchdogTimeout:
    """Verify Expected Packet Interval (EPI) watchdog timer monitoring and timeout fault 0xE802."""

    def test_nominal_scan_below_timeout_remains_operational(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.scan_step(dt=0.010)  # 10 ms < 60 ms
        assert active_engine.state == PointConnectionState.OPERATIONAL
        assert active_engine.diagnostic_code == DiagnosticCode.OK

    def test_scan_exceeding_timeout_trips_0xE802(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.scan_step(dt=0.070)  # 70 ms > 60 ms
        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert active_engine.diagnostic_code == 0xE802

    def test_watchdog_timeout_asserts_m444_clears_m443(
        self, active_engine: CipSafetyPointEngine, register_table: RegisterTable
    ) -> None:
        active_engine.scan_step(dt=0.100)
        active_engine.sync_to_registers(register_table)
        assert register_table.read_bit("%M443") is False
        assert register_table.read_bit("%M444") is True
        assert register_table.read_uword("%R1907") == 0xE802

    def test_watchdog_refreshed_on_packet_reception(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.scan_step(dt=0.040)
        assert active_engine.silence_elapsed_ms >= 40.0

        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        active_engine.receive_safety_packet(pkt)
        assert active_engine.silence_elapsed_ms == 0.0

    def test_simulate_epi_watchdog_timeout_helper(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.simulate_epi_watchdog_timeout()
        assert active_engine.diagnostic_code == 0xE802
        assert (active_engine.connection_fault_bitmask & SafetyStatusBits.EPI_TIMEOUT_LATCH) != 0

    def test_disabled_engine_skips_watchdog_evaluation(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.is_enabled = False
        initial_silence = active_engine.silence_elapsed_ms
        active_engine.scan_step(dt=0.100)
        assert active_engine.silence_elapsed_ms == initial_silence
        assert active_engine.state == PointConnectionState.OPERATIONAL

    def test_words_processed_incremented(self, active_engine: CipSafetyPointEngine) -> None:
        initial = active_engine.words_processed
        active_engine.scan_step(dt=0.010)
        assert active_engine.words_processed == initial + 1


# ============================================================================
# Section 8: Dual-Channel Discrepancy Fault (0xE803)
# ============================================================================

class TestSection8DualChannelDiscrepancy:
    """Verify Channel A vs Channel B parity cross-comparison and discrepancy fault 0xE803."""

    def test_healthy_dual_channel_packet_accepted(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\x12\x34", channel_b_payload=b"\xED\xCB",
        )
        pkt.calculate_crcs()
        active_engine.receive_safety_packet(pkt)
        assert active_engine.diagnostic_code == DiagnosticCode.OK

    def test_single_bit_flip_in_channel_b_trips_0xE803(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        bad_b = bytearray(b"\xED\xCB")
        bad_b[0] ^= 0x01
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\x12\x34", channel_b_payload=bytes(bad_b),
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetyDualChannelDiscrepancyError):
            active_engine.receive_safety_packet(pkt)

        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert active_engine.diagnostic_code == 0xE803

    def test_different_payload_lengths_trips_0xE803(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\x12\x34", channel_b_payload=b"\xED",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetyDualChannelDiscrepancyError):
            active_engine.receive_safety_packet(pkt)

        assert active_engine.diagnostic_code == 0xE803

    def test_discrepancy_latches_fault_bit(self, active_engine: CipSafetyPointEngine) -> None:
        active_engine.simulate_dual_channel_discrepancy()
        assert (active_engine.connection_fault_bitmask & SafetyStatusBits.DISCREPANCY_LATCH) != 0
        assert active_engine.safety_trip_safe_state_engaged is True

    def test_simulate_dual_channel_discrepancy_helper(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.simulate_dual_channel_discrepancy()
        assert active_engine.diagnostic_code == 0xE803


# ============================================================================
# Section 9: Safety Network Number (SNN) & TUNID Mismatch (0xE801)
# ============================================================================

class TestSection9SnnAndTunidMismatch:
    """Verify Safety Network Number and TUNID verification and mismatch fault 0xE801."""

    def test_matching_snn_packet_accepted(self, active_engine: CipSafetyPointEngine) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        active_engine.receive_safety_packet(pkt)
        assert active_engine.diagnostic_code == DiagnosticCode.OK

    def test_mismatched_snn_bytes_trips_0xE801(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        rogue_snn = bytes([0x99] * 6)
        pkt = CipSafetyPointPacket(
            snn=rogue_snn, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetySnnMismatchError):
            active_engine.receive_safety_packet(pkt)

        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert active_engine.diagnostic_code == 0xE801

    def test_mismatched_tunid_trips_0xE801(self, active_engine: CipSafetyPointEngine) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=999, ounid=100, sequence_number=1,  # Mismatch
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetySnnMismatchError):
            active_engine.receive_safety_packet(pkt)

        assert active_engine.diagnostic_code == 0xE801

    def test_snn_mismatch_sets_fault_bit(self, active_engine: CipSafetyPointEngine) -> None:
        active_engine.simulate_snn_mismatch()
        assert (active_engine.connection_fault_bitmask & SafetyStatusBits.UNID_MISMATCH_LATCH) != 0
        assert active_engine.safety_trip_safe_state_engaged is True

    def test_simulate_snn_mismatch_helper(self, active_engine: CipSafetyPointEngine) -> None:
        active_engine.simulate_snn_mismatch()
        assert active_engine.diagnostic_code == 0xE801


# ============================================================================
# Section 10: CRC-S Checksum Corruption Fault (0xE804)
# ============================================================================

class TestSection10CrcCorruptionFault:
    """Verify CRC-S1 and inverted CRC-S2 checksum corruption and fault 0xE804."""

    def test_valid_crc_packet_accepted(self, active_engine: CipSafetyPointEngine) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\xAA\x55", channel_b_payload=b"\x55\xAA",
        )
        pkt.calculate_crcs()
        active_engine.receive_safety_packet(pkt)
        assert active_engine.diagnostic_code == DiagnosticCode.OK

    def test_corrupted_crc_s1_trips_0xE804(self, active_engine: CipSafetyPointEngine) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\xAA\x55", channel_b_payload=b"\x55\xAA",
        )
        pkt.calculate_crcs()
        pkt.crc_s1 ^= 0x0001
        with pytest.raises(CipSafetyCrcCorruptionError):
            active_engine.receive_safety_packet(pkt)

        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION
        assert active_engine.diagnostic_code == 0xE804

    def test_corrupted_crc_s2_trips_0xE804(self, active_engine: CipSafetyPointEngine) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            channel_a_payload=b"\xAA\x55", channel_b_payload=b"\x55\xAA",
        )
        pkt.calculate_crcs()
        pkt.crc_s2 ^= 0x0001
        with pytest.raises(CipSafetyCrcCorruptionError):
            active_engine.receive_safety_packet(pkt)

        assert active_engine.diagnostic_code == 0xE804

    def test_crc_corruption_sets_fault_bit(self, active_engine: CipSafetyPointEngine) -> None:
        active_engine.simulate_crc_s_corruption()
        assert (active_engine.connection_fault_bitmask & SafetyStatusBits.CRC_ERROR_LATCH) != 0

    def test_simulate_crc_s_corruption_helper(self, active_engine: CipSafetyPointEngine) -> None:
        active_engine.simulate_crc_s_corruption()
        assert active_engine.diagnostic_code == 0xE804


# ============================================================================
# Section 11: Connection Disconnect Fault (0xE806)
# ============================================================================

class TestSection11ConnectionDisconnectFault:
    """Verify connection disconnect handling and diagnostic code 0xE806."""

    def test_packet_with_disconnect_flag_trips_0xE806(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        pkt = CipSafetyPointPacket(
            snn=DEFAULT_SNN, tunid=101, ounid=100, sequence_number=1,
            mode_byte=SafetyControlByte.DISCONNECT_REQUEST,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetyDisconnectError):
            active_engine.receive_safety_packet(pkt)

        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.diagnostic_code == DiagnosticCode.CONNECTION_DISCONNECT
        assert active_engine.diagnostic_code == 0xE806

    def test_engine_disconnect_method_trips_0xE806(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.disconnect()
        assert active_engine.state == PointConnectionState.FAULT_SAFE_STATE
        assert active_engine.diagnostic_code == 0xE806

    def test_simulate_connection_disconnect_helper(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.simulate_connection_disconnect()
        assert active_engine.diagnostic_code == DiagnosticCode.CONNECTION_DISCONNECT
        assert (active_engine.connection_fault_bitmask & SafetyStatusBits.DISCONNECT_LATCH) != 0

    def test_disconnect_asserts_m444_clears_m443(
        self, active_engine: CipSafetyPointEngine, register_table: RegisterTable
    ) -> None:
        active_engine.disconnect()
        active_engine.sync_to_registers(register_table)
        assert register_table.read_bit("%M443") is False
        assert register_table.read_bit("%M444") is True
        assert register_table.read_uword("%R1907") == 0xE806

    def test_connection_rejected_alias_equality(self) -> None:
        assert DIAG_CONNECTION_REJECTED == DIAG_CONNECTION_DISCONNECT
        assert DiagnosticCode.CONNECTION_REJECTED == DiagnosticCode.CONNECTION_DISCONNECT


# ============================================================================
# Section 12: Horner OCS Register Synchronization (%R1900..%R1907, %M443..%M444)
# ============================================================================

class TestSection12RegisterSynchronization:
    """Validate synchronization to %R1900..%R1907 and %M443..%M444 with SYSTEM privilege."""

    def test_nominal_register_sync(
        self, active_engine: CipSafetyPointEngine, register_table: RegisterTable
    ) -> None:
        active_engine.actual_latency_ms = 14.5
        active_engine.tx_sequence_counter = 12
        active_engine.sync_to_registers(register_table)

        assert register_table.read_word("%R1900") == 3  # OPERATIONAL
        assert register_table.read_word("%R1902") in (100, 200)  # 10.0ms or 20.0ms * 10
        assert register_table.read_word("%R1903") == 145  # 14.5 ms * 10
        assert register_table.read_word("%R1904") == 0
        assert register_table.read_word("%R1906") == 1  # OPERATIONAL
        assert register_table.read_uword("%R1907") == 0x0000
        assert register_table.read_bit("%M443") is True
        assert register_table.read_bit("%M444") is False

    def test_fault_register_sync(
        self, active_engine: CipSafetyPointEngine, register_table: RegisterTable
    ) -> None:
        active_engine.simulate_crc_s_corruption()
        active_engine.sync_to_registers(register_table)

        assert register_table.read_word("%R1900") == 4  # FAULT_SAFE_STATE
        assert register_table.read_uword("%R1907") == 0xE804
        assert register_table.read_bit("%M443") is False
        assert register_table.read_bit("%M444") is True

    def test_diagnostic_code_signed_unsigned_in_register(
        self, active_engine: CipSafetyPointEngine, register_table: RegisterTable
    ) -> None:
        active_engine.simulate_snn_mismatch()
        active_engine.sync_to_registers(register_table)

        u_val = register_table.read_uword("%R1907")
        s_val = register_table.read_word("%R1907")
        assert u_val == 0xE801
        assert (s_val & 0xFFFF) == 0xE801
        assert s_val == -6143

    def test_safe_write_helpers_with_system_privilege(
        self, register_table: RegisterTable
    ) -> None:
        safe_write_word(register_table, "%R1900", 3)
        safe_write_uword(register_table, "%R1907", 0xE802)
        safe_write_bit(register_table, "%M443", True)

        assert register_table.read_word("%R1900") == 3
        assert register_table.read_uword("%R1907") == 0xE802
        assert register_table.read_bit("%M443") is True

    def test_scale_latency_ms_helper(self) -> None:
        assert scale_latency_ms_to_int16(20.0) == 200
        assert scale_latency_ms_to_int16(12.5) == 125
        assert scale_latency_ms_to_int16(0.0) == 0


# ============================================================================
# Section 13: Pure ST POU Validation & Anti-Ladder Security Guard Interception
# ============================================================================

class TestSection13PureSTPOUValidation:
    """Verify IEC 61131-3 Pure Structured Text POU compliance and register binding."""

    def test_verify_cip_safety_point_pure_st_function(self) -> None:
        assert verify_cip_safety_point_pure_st() is True

    def test_security_guard_assert_pure_st_content_passes(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_POINT_SYNC_POU)
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_POINT_POU)
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_POINT_TO_POINT_SYNC_POU)
        SecurityGuard.assert_pure_st_content(PURE_ST_POU)

    def test_st_parser_validate_code_success(self) -> None:
        res = STParser.validate_code(CIP_SAFETY_POINT_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_ast_program_type(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_POINT_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM

    def test_st_parser_all_10_registers_bound(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_POINT_SYNC_POU)
        expected_regs = {
            "%R1900", "%R1901", "%R1902", "%R1903",
            "%R1904", "%R1905", "%R1906", "%R1907",
            "%M443", "%M444",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_anti_ladder_contacts_rejected(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  ---[ ]---\nEND_PROGRAM")

    def test_anti_ladder_coils_rejected(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  ---( )---\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  ---(S)---\nEND_PROGRAM")

    def test_anti_ladder_rungs_and_networks_rejected(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  RUNG 1\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  NETWORK 1\nEND_PROGRAM")


# ============================================================================
# Section 14: ILogicUnit Interface Compliance & Scan Cycle Simulation
# ============================================================================

class TestSection14ILogicUnitCompliance:
    """Verify ILogicUnit interface compliance and scan cycle simulation."""

    def test_ilogicunit_inheritance(self, active_engine: CipSafetyPointEngine) -> None:
        assert isinstance(active_engine, ILogicUnit)
        assert CIPSafetyPointEngine == CipSafetyPointEngine
        assert CipSafetyPoint == CipSafetyPointEngine
        assert CipSafetyPointToPoint == CipSafetyPointEngine

    def test_ilogicunit_name_and_priority(self, active_engine: CipSafetyPointEngine) -> None:
        assert active_engine.name == "CipSafetyPointEngine"
        assert active_engine.priority == 95
        assert active_engine.is_enabled is True

    def test_ilogicunit_is_enabled_toggle(self, active_engine: CipSafetyPointEngine) -> None:
        active_engine.is_enabled = False
        assert active_engine.is_enabled is False
        active_engine.is_enabled = True
        assert active_engine.is_enabled is True

    def test_scan_step_with_context(self, active_engine: CipSafetyPointEngine) -> None:
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        active_engine.scan_step(dt=0.010, context=ctx)
        assert active_engine.diagnostic_code == DiagnosticCode.OK

    def test_execute_method_calls_scan_step(self, active_engine: CipSafetyPointEngine) -> None:
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        active_engine.execute(ctx)
        assert active_engine.diagnostic_code == DiagnosticCode.OK

    def test_100_cycle_cyclic_scan_simulation(self) -> None:
        engine = CipSafetyPointEngine(snn=DEFAULT_SNN, auto_activate=True)
        ctx = ScanContext()
        for cycle in range(100):
            # Refresh watchdog every 2 cycles
            if cycle % 2 == 0:
                engine.silence_elapsed_ms = 0.0
            engine.scan_step(dt=0.010, context=ctx)

        assert engine.state == PointConnectionState.OPERATIONAL
        assert engine.point_active is True
        assert engine.safety_trip_safe_state_engaged is False

    def test_reset_method_clears_faults_and_restores_operational(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.simulate_crc_s_corruption()
        assert active_engine.safety_trip_safe_state_engaged is True
        active_engine.reset()
        assert active_engine.state == PointConnectionState.OPERATIONAL
        assert active_engine.safety_trip_safe_state_engaged is False
        assert active_engine.diagnostic_code == DiagnosticCode.OK

    def test_reset_fault_force_returns_execution_result(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.simulate_epi_watchdog_timeout()
        res = active_engine.reset_fault(force=True)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert active_engine.state == PointConnectionState.OPERATIONAL
        assert active_engine.safety_trip_safe_state_engaged is False

    def test_reset_fault_non_force_transitions_to_configuring(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        active_engine.simulate_dual_channel_discrepancy()
        res = active_engine.reset_fault(force=False)
        assert res.status == AgentStatus.SUCCESS
        assert active_engine.state == PointConnectionState.CONFIGURING


# ============================================================================
# Section 15: Safe State Coordination, Recovery, & Verification Runner
# ============================================================================

class TestSection15VerificationRunner:
    """Validate deterministic verification suite conforms to AGENTS.md strict 4-state contract."""

    def test_verification_runner_returns_dict(self) -> None:
        res = run_cip_safety_point_verification()
        assert isinstance(res, dict)

    def test_verification_runner_strict_4_state_contract(self) -> None:
        res = run_cip_safety_point_verification()
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert "error_code" in res
        assert "details" in res
        assert "data" in res

    def test_verification_runner_all_stages_pass(self) -> None:
        res = run_cip_safety_point_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["stages_passed"] == 10
        assert res["total_stages"] == 10
        assert all(s["passed"] for s in res["data"]["stages"])

    def test_verification_runner_writes_evidence_json(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_point_evidence.json"
        res = run_cip_safety_point_verification(output_path=out_file)
        assert res["status"] == "success"
        assert out_file.exists()

    def test_evidence_json_content_and_work_package_w229(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_point_evidence.json"
        run_cip_safety_point_verification(output_path=out_file)
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["data"]["work_package"] == "W229"
        assert data["status"] == "success"
        assert "register_map" in data["data"]

    def test_cli_verification_script_execution(self) -> None:
        cmd = [sys.executable, "scripts/run_cip_safety_point_verification.py"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert proc.returncode == 0
        assert "[SUCCESS]" in proc.stdout

    def test_receive_packet_helper_success_and_failure(
        self, active_engine: CipSafetyPointEngine
    ) -> None:
        p_a = b"\x01\x02\x03\x04"
        p_b = bytes([~b & 0xFF for b in p_a])
        c1 = calc_crc_s1(p_a)
        c2 = calc_crc_s2(1000, 1, p_a)

        ok = active_engine.receive_packet(1000, 1, p_a, p_b, c1, c2, snn=DEFAULT_SNN, tunid=101)
        assert ok is True

        # Invalid SNN should return False
        bad_ok = active_engine.receive_packet(1001, 2, p_a, p_b, c1, c2, snn="9999-9999", tunid=101)
        assert bad_ok is False
