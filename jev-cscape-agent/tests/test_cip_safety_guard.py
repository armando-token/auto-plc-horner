"""Comprehensive Unit and Integration Test Suite for W226 CIP Safety Guard Engine.

Work Package: W226 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 110+ Comprehensive Unit and Integration Tests across 15 Sections:
1. Section 1: Protocol Constants, Identifiers, Enums, & Diagnostic Codes (signed/unsigned & 0xFFFF).
2. Section 2: Safety Network Number (SNN), SCID, TUNID, & OUNID Configuration & Parsing.
3. Section 3: Dual-Channel Payload Verification & CRC-S1/S2 Checksums.
4. Section 4: CIP Safety Guard Packet Serialization & Deserialization.
5. Section 5: Target Registration & Capacity Limits (Max 8 Targets, 0xE706 on Overrun).
6. Section 6: Sequence Number Monotonicity, Replay Attack Rejection & Rollover Fault (0xE705).
7. Section 7: Expected Packet Interval (EPI) Watchdogs & Timeout Tripping (0xE702).
8. Section 8: Dual-Channel Discrepancy Fault (0xE703).
9. Section 9: Safety Network Number (SNN) & Signature Mismatch Fault (0xE701).
10. Section 10: CRC-S Checksum Corruption Fault (0xE704).
11. Section 11: Horner OCS Register Synchronization (%R1870..%R1877, %M436..%M437 with PrivilegeMode.SYSTEM).
12. Section 12: Pure ST POU Validation & Anti-Ladder Security Guard Interception.
13. Section 13: ILogicUnit Interface Compliance & Scan Cycle Simulation.
14. Section 14: Multi-Target Safe State Coordination & Reset Nominal Recovery.
15. Section 15: Verification Runner & Strict 4-State Engineering Contract.
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
from jev_cscape.telemetry.cip_safety_guard import (
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_GUARD_CLASS_ID,
    CIP_SAFETY_GUARD_POU,
    CIP_SAFETY_GUARD_SYNC_POU,
    CIP_SAFETY_MULTIPOINT_CLASS_ID,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyGuardEngine,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    DEFAULT_EPI_MS,
    DEFAULT_OUNID,
    DEFAULT_SCID,
    DEFAULT_SCID_CRC,
    DEFAULT_SCID_TIMESTAMP,
    DEFAULT_SNN,
    DEFAULT_WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DIAG_CRC_S_CORRUPTION,
    DIAG_DUAL_CHANNEL_DISCREPANCY,
    DIAG_EPI_WATCHDOG_TIMEOUT,
    DIAG_OK,
    DIAG_SEQUENCE_NUMBER_ROLLOVER_FAULT,
    DIAG_SNN_SIGNATURE_MISMATCH,
    DIAG_TARGET_CAPACITY_OVERRUN,
    MAX_SAFETY_CONNECTIONS,
    MAX_SAFETY_TARGETS,
    NOMINAL_EPI_MS,
    REGISTER_LATENCY_SCALE_FACTOR,
    BlackChannelThreat,
    CipSafetyConnectionState,
    CipSafetyControlByte,
    CipSafetyCrcCorruptionError,
    CipSafetyDiagnosticCode,
    CipSafetyDualChannelDiscrepancyError,
    CipSafetyEpiTimeoutError,
    CipSafetyGuard,
    CipSafetyGuardDiagnosticCode,
    CipSafetyGuardEngine,
    CipSafetyGuardError,
    CipSafetyGuardMode,
    CipSafetyGuardOperationalMode,
    CipSafetyGuardPacket,
    CipSafetyOperationalMode,
    CipSafetyOperationalState,
    CipSafetyPacket,
    CipSafetySequenceError,
    CipSafetySequenceRepetitionError,
    CipSafetySequenceRolloverError,
    CipSafetySnnMismatchError,
    CipSafetyTargetCapacityOverrunError,
    CipSafetyTargetState,
    ConnectionState,
    DiagnosticCode,
    DiagnosticStatusCode,
    DiversifiedMode,
    GuardMode,
    GuardSafetyState,
    NetworkSafetyState,
    OUNID,
    OperationalMode,
    OriginatorUniqueNetworkId,
    PURE_ST_POU,
    RemoteSafetyTarget,
    SCID,
    SafetyConfigurationIdentifier,
    SafetyConnectionState,
    SafetyControlByte,
    SafetyModeByte,
    SafetyNetworkNumber,
    SafetyNetworkOperationalState,
    SafetyStatusBits,
    SafetySupervisorObject,
    SafetyTargetObject,
    SafetyTargetState,
    SafetyValidatorObject,
    TUNID,
    TargetState,
    TargetUniqueNetworkId,
    calculate_crc16_ccitt,
    compute_crc_s1,
    compute_crc_s2,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_guard_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    scale_latency_ms_to_int16,
    validate_snn,
    verify_cip_safety_guard_pure_st,
    verify_dual_channel_payload,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def cip_safety_guard_engine(register_table: RegisterTable) -> CipSafetyGuardEngine:
    """Provide a fresh CipSafetyGuardEngine initialized with 4 targets."""
    engine = CipSafetyGuardEngine(
        register_table=register_table,
        snn=DEFAULT_SNN,
        epi_ms=NOMINAL_EPI_MS,
        watchdog_timeout_ms=DEFAULT_WATCHDOG_TIMEOUT_MS,
    )
    for i in range(4):
        engine.attach_target(target_id=i, tunid=10 + i, ounid=100, auto_activate=True)
    return engine


# ============================================================================
# Section 1: Protocol Constants, Identifiers, Enums & Diagnostic Codes
# ============================================================================

class TestSection1ConstantsAndEnums:
    """Validate ODVA Volume 5 CIP Safety protocol constants and enumerations."""

    def test_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_GUARD_CLASS_ID == 0x39
        assert CIP_SAFETY_MULTIPOINT_CLASS_ID == 0x39

    def test_timing_and_scale_defaults(self) -> None:
        assert MAX_SAFETY_TARGETS == 8
        assert MAX_SAFETY_CONNECTIONS == 8
        assert NOMINAL_EPI_MS == 20.0
        assert DEFAULT_EPI_MS == 20.0
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 60.0
        assert REGISTER_LATENCY_SCALE_FACTOR == 10.0
        assert CRC16_CCITT_POLY == 0x1021
        assert CRC16_CCITT_INIT == 0xFFFF

    def test_operational_state_enum(self) -> None:
        assert SafetyNetworkOperationalState.INITIALIZING == 0
        assert SafetyNetworkOperationalState.OPERATIONAL == 1
        assert SafetyNetworkOperationalState.DEGRADED == 2
        assert SafetyNetworkOperationalState.TRIPPED == 3
        assert SafetyNetworkOperationalState.SAFE_STATE == 4

    def test_target_state_enum(self) -> None:
        assert SafetyTargetState.UNCONFIGURED == 0
        assert SafetyTargetState.INITIALIZING == 1
        assert SafetyTargetState.OPERATIONAL == 2
        assert SafetyTargetState.EXECUTING == 2
        assert SafetyTargetState.FAULTED == 3
        assert SafetyTargetState.SAFE_STATE == 4

    def test_operational_mode_enum(self) -> None:
        assert CipSafetyGuardMode.DISABLED == 0
        assert CipSafetyGuardMode.MONITOR_ONLY == 1
        assert CipSafetyGuardMode.GUARD_ENFORCING == 2
        assert CipSafetyGuardMode.DUAL_MODE == 3
        assert CipSafetyGuardOperationalMode == CipSafetyGuardMode
        assert OperationalMode == CipSafetyGuardMode
        assert GuardMode == CipSafetyGuardMode

    def test_diagnostic_codes_signed_unsigned_and_masking(self) -> None:
        # 0x0000: OK
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.OK == 0
        assert (DiagnosticCode.OK & 0xFFFF) == 0

        # 0xE701: SNN_SIGNATURE_MISMATCH (signed INT16: -6399)
        assert DiagnosticCode.SNN_SIGNATURE_MISMATCH == 0xE701
        assert DiagnosticCode.SNN_SIGNATURE_MISMATCH == -6399
        assert (DiagnosticCode.SNN_SIGNATURE_MISMATCH & 0xFFFF) == 0xE701
        assert (DiagnosticCode.SNN_SIGNATURE_MISMATCH & 0xFFFF) == -6399

        # 0xE702: EPI_WATCHDOG_TIMEOUT (signed INT16: -6398)
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xE702
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == -6398
        assert (DiagnosticCode.EPI_WATCHDOG_TIMEOUT & 0xFFFF) == 0xE702

        # 0xE703: DUAL_CHANNEL_DISCREPANCY (signed INT16: -6397)
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == 0xE703
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == -6397
        assert (DiagnosticCode.DUAL_CHANNEL_DISCREPANCY & 0xFFFF) == 0xE703

        # 0xE704: CRC_S_CORRUPTION (signed INT16: -6396)
        assert DiagnosticCode.CRC_S_CORRUPTION == 0xE704
        assert DiagnosticCode.CRC_S_CORRUPTION == -6396
        assert (DiagnosticCode.CRC_S_CORRUPTION & 0xFFFF) == 0xE704

        # 0xE705: SEQUENCE_NUMBER_ROLLOVER_FAULT (signed INT16: -6395)
        assert DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT == 0xE705
        assert DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT == -6395
        assert (DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT & 0xFFFF) == 0xE705

        # 0xE706: TARGET_CAPACITY_OVERRUN (signed INT16: -6394)
        assert DiagnosticCode.TARGET_CAPACITY_OVERRUN == 0xE706
        assert DiagnosticCode.TARGET_CAPACITY_OVERRUN == -6394
        assert (DiagnosticCode.TARGET_CAPACITY_OVERRUN & 0xFFFF) == 0xE706

    def test_diagnostic_code_signed_int16_representations(self) -> None:
        assert struct.unpack(">h", struct.pack(">H", 0xE701))[0] == -6399
        assert struct.unpack(">h", struct.pack(">H", 0xE702))[0] == -6398
        assert struct.unpack(">h", struct.pack(">H", 0xE703))[0] == -6397
        assert struct.unpack(">h", struct.pack(">H", 0xE704))[0] == -6396
        assert struct.unpack(">h", struct.pack(">H", 0xE705))[0] == -6395
        assert struct.unpack(">h", struct.pack(">H", 0xE706))[0] == -6394

    def test_diagnostic_code_aliases(self) -> None:
        assert DIAG_OK == DiagnosticCode.OK
        assert DIAG_SNN_SIGNATURE_MISMATCH == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert DIAG_EPI_WATCHDOG_TIMEOUT == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DIAG_DUAL_CHANNEL_DISCREPANCY == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert DIAG_CRC_S_CORRUPTION == DiagnosticCode.CRC_S_CORRUPTION
        assert DIAG_SEQUENCE_NUMBER_ROLLOVER_FAULT == DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT
        assert DIAG_TARGET_CAPACITY_OVERRUN == DiagnosticCode.TARGET_CAPACITY_OVERRUN
        assert DiagnosticCode.SNN_MISMATCH == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert DiagnosticCode.EPI_TIMEOUT == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DiagnosticCode.SEQUENCE_FAULT == DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT
        assert DiagnosticCode.TARGET_LIMIT_OVERRUN == DiagnosticCode.TARGET_CAPACITY_OVERRUN
        assert CipSafetyGuardDiagnosticCode == DiagnosticCode
        assert DiagnosticStatusCode == DiagnosticCode

    def test_safety_control_byte_flags(self) -> None:
        assert SafetyControlByte.IDLE == 0x00
        assert SafetyControlByte.RUN == 1 << 0
        assert SafetyControlByte.PING_REQ == 1 << 1
        assert SafetyControlByte.PING_RESP == 1 << 2
        assert SafetyControlByte.SAFETY_DEMAND == 1 << 3
        assert SafetyControlByte.FAULT_PRESENT == 1 << 4
        assert SafetyControlByte.RESET_REQUEST == 1 << 5

    def test_safety_status_bits_mask(self) -> None:
        assert SafetyStatusBits.ACTIVE_MASK == 0x00FF
        assert SafetyStatusBits.PERMISSIVE_HIGH == 1 << 8
        assert SafetyStatusBits.FAULT_LATCHED == 1 << 9
        assert SafetyStatusBits.EPI_TIMEOUT_LATCH == 1 << 10
        assert SafetyStatusBits.SEQUENCE_ERROR_LATCH == 1 << 11
        assert SafetyStatusBits.CRC_ERROR_LATCH == 1 << 12
        assert SafetyStatusBits.UNID_MISMATCH_LATCH == 1 << 13
        assert SafetyStatusBits.DISCREPANCY_LATCH == 1 << 14
        assert SafetyStatusBits.TARGET_LIMIT_LATCH == 1 << 15

    def test_black_channel_threats(self) -> None:
        assert BlackChannelThreat.CORRUPTION == 1
        assert BlackChannelThreat.UNINTENDED_REPETITION == 2
        assert BlackChannelThreat.INCORRECT_SEQUENCE == 3
        assert BlackChannelThreat.LOSS == 4
        assert BlackChannelThreat.UNACCEPTABLE_DELAY == 5
        assert BlackChannelThreat.INSERTION == 6
        assert BlackChannelThreat.MASQUERADE == 7
        assert BlackChannelThreat.ADDRESSING_FAULT == 8

    def test_diagnostic_code_and_operations(self) -> None:
        code = DiagnosticCode.EPI_TIMEOUT
        masked = code & 0xFFFF
        assert masked == 0xE702
        assert 0xFFFF & code == 0xE702
        assert str(code) == "EPI_WATCHDOG_TIMEOUT"
        assert repr(code).startswith("DiagnosticCode.")


# ============================================================================
# Section 2: Safety Network Number (SNN), SCID, TUNID, & OUNID Configuration
# ============================================================================

class TestSection2SNNAndSignatures:
    """Validate SNN, SCID, TUNID, and OUNID format and integrity."""

    def test_snn_generation_and_formatting(self) -> None:
        snn = generate_snn(0x2026, 0x1006BB66)
        assert len(snn) == 6
        formatted = format_snn(snn)
        assert formatted == "2026-1006BB66"
        parsed = parse_snn(formatted)
        assert parsed == snn

    def test_snn_validation_valid_cases(self) -> None:
        valid_snn = generate_snn(0x2026, 0x1006BB66)
        assert validate_snn(valid_snn) is True

    def test_snn_validation_invalid_cases(self) -> None:
        assert validate_snn(b"\x00" * 6) is False
        assert validate_snn(b"\xFF" * 6) is False
        assert validate_snn(b"short") is False
        assert validate_snn(12345) is False
        assert validate_snn(None) is False

    def test_snn_dataclass_create(self) -> None:
        snn = SafetyNetworkNumber.create(0x2026, 0x1006BB66, 0x0001)
        assert snn.low_word == 0x2026
        assert len(snn.raw_bytes) == 8
        assert snn.to_hex() == "20261006BB660001"

    def test_snn_dataclass_from_bytes(self) -> None:
        raw_6 = bytes([0x20, 0x26, 0x10, 0x06, 0xBB, 0x66])
        snn = SafetyNetworkNumber.from_bytes(raw_6)
        assert snn.low_word == 0x2026
        with pytest.raises(ValueError):
            SafetyNetworkNumber.from_bytes(b"\x01\x02\x03")

    def test_scid_creation_and_matching(self) -> None:
        scid1 = SafetyConfigurationIdentifier(crc=0x20261006, timestamp=0x10060001)
        scid2 = SafetyConfigurationIdentifier(crc=0x20261006, timestamp=0x10060001)
        scid3 = SafetyConfigurationIdentifier(crc=0x99999999, timestamp=0x10060001)
        assert scid1.matches(scid2) is True
        assert scid1.matches(scid3) is False

    def test_scid_serialization_to_bytes(self) -> None:
        scid = SafetyConfigurationIdentifier(crc=0xAABBCCDD, timestamp=0x11223344)
        raw = scid.to_bytes()
        assert len(raw) == 8
        c, ts = struct.unpack(">II", raw)
        assert c == 0xAABBCCDD
        assert ts == 0x11223344

    def test_tunid_creation_and_matching(self) -> None:
        snn = SafetyNetworkNumber.create(0x2026, 0x1006BB66, 0x0001)
        tunid1 = TargetUniqueNetworkId(snn=snn, target_node_id=1)
        tunid2 = TargetUniqueNetworkId(snn=snn, target_node_id=1)
        tunid3 = TargetUniqueNetworkId(snn=snn, target_node_id=2)
        assert tunid1.matches(tunid2) is True
        assert tunid1.matches(tunid3) is False

    def test_ounid_creation_and_matching(self) -> None:
        snn = SafetyNetworkNumber.create(0x2026, 0x1006BB66, 0x0001)
        ounid1 = OriginatorUniqueNetworkId(snn=snn, originator_node_id=100)
        ounid2 = OriginatorUniqueNetworkId(snn=snn, originator_node_id=100)
        ounid3 = OriginatorUniqueNetworkId(snn=snn, originator_node_id=200)
        assert ounid1.matches(ounid2) is True
        assert ounid1.matches(ounid3) is False

    def test_tunid_ounid_byte_serialization(self) -> None:
        snn = SafetyNetworkNumber.create(0x2026, 0x1006BB66, 0x0001)
        tunid = TargetUniqueNetworkId(snn=snn, target_node_id=42)
        raw = tunid.to_bytes()
        assert len(raw) == 12  # 8 bytes SNN + 4 bytes target ID
        assert raw.startswith(snn.raw_bytes)


# ============================================================================
# Section 3: Dual-Channel Payload Verification & CRC-S Checksums
# ============================================================================

class TestSection3ChecksumsAndPayloads:
    """Validate ODVA CCITT CRC-S1 and inverted CRC-S2 checksum calculations."""

    def test_crc16_ccitt_deterministic_calculation(self) -> None:
        data = b"\x01\x02\x03\x04"
        c1 = calculate_crc16_ccitt(data)
        c2 = calculate_crc16_ccitt(data)
        assert c1 == c2
        assert 0 <= c1 <= 0xFFFF

    def test_compute_crc_s1_and_inverted_crc_s2(self) -> None:
        data = b"TEST_SAFETY_DATA_PAYLOAD"
        crc1 = compute_crc_s1(data)
        crc2 = compute_crc_s2(data, inverted=True)
        assert 0 <= crc1 <= 0xFFFF
        assert 0 <= crc2 <= 0xFFFF
        assert crc2 == ((~crc1) & 0xFFFF)

    def test_compute_crc_s2_non_inverted(self) -> None:
        data = b"TEST_DATA"
        crc1 = compute_crc_s1(data)
        crc2 = compute_crc_s2(data, inverted=False)
        assert crc1 == crc2

    def test_dual_channel_inverted_verification_bytes_pass(self) -> None:
        ch_a = bytes([0xAA, 0x55, 0xF0, 0x0F])
        ch_b_valid = bytes([0x55, 0xAA, 0x0F, 0xF0])
        assert verify_dual_channel_payload(ch_a, ch_b_valid, DiversifiedMode.INVERTED) is True

    def test_dual_channel_inverted_verification_bytes_bit_flip(self) -> None:
        ch_a = bytes([0xAA, 0x55, 0xF0, 0x0F])
        ch_b_invalid = bytes([0x55, 0xAA, 0x0F, 0x00])
        assert verify_dual_channel_payload(ch_a, ch_b_invalid, DiversifiedMode.INVERTED) is False

    def test_dual_channel_inverted_verification_integers(self) -> None:
        ch_a = 0x1234
        ch_b_valid = (~ch_a) & 0xFFFF
        ch_b_invalid = 0x1234
        assert verify_dual_channel_payload(ch_a, ch_b_valid, DiversifiedMode.INVERTED) is True
        assert verify_dual_channel_payload(ch_a, ch_b_invalid, DiversifiedMode.INVERTED) is False

    def test_dual_channel_identical_mode_verification(self) -> None:
        ch_a = bytes([0x12, 0x34, 0x56, 0x78])
        assert verify_dual_channel_payload(ch_a, ch_a, DiversifiedMode.IDENTICAL) is True
        assert verify_dual_channel_payload(ch_a, b"bad", DiversifiedMode.IDENTICAL) is False

    def test_dual_channel_length_mismatch_fails(self) -> None:
        ch_a = b"\x01\x02"
        ch_b = b"\xFE\xFD\x00"
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False


# ============================================================================
# Section 4: CIP Safety Guard Packet Serialization & Deserialization
# ============================================================================

class TestSection4PacketSerialization:
    """Validate CIP Safety frame serialization, deserialization, and CRC verification."""

    def test_packet_instantiation_and_defaults(self) -> None:
        snn = generate_snn(0x2026, 0x1006BB66)
        pkt = CipSafetyPacket(
            snn=snn,
            tunid=1,
            ounid=100,
            target_id=0,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01",
            channel_b_payload=b"\xFE",
        )
        assert pkt.connection_id == 0
        assert pkt.crc_s1 == 0
        assert pkt.crc_s2 == 0

    def test_packet_crc_calculation_and_verification(self) -> None:
        snn = generate_snn(0x2026, 0x1006BB66)
        pkt = CipSafetyPacket(
            snn=snn,
            tunid=1,
            ounid=100,
            target_id=0,
            sequence_number=10,
            timestamp_ms=500.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        c1, c2 = pkt.calculate_crcs()
        assert pkt.crc_s1 == c1
        assert pkt.crc_s2 == c2
        assert pkt.verify_crcs() is True

    def test_packet_dual_channel_inverted_verification(self) -> None:
        snn = generate_snn(0x2026, 0x1006BB66)
        pkt = CipSafetyPacket(
            snn=snn,
            tunid=1,
            ounid=100,
            target_id=0,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\xAA\x55",
            channel_b_payload=b"\x55\xAA",
        )
        assert pkt.verify_dual_channel(DiversifiedMode.INVERTED) is True

    def test_packet_serialization_length(self) -> None:
        snn = generate_snn(0x2026, 0x1006BB66)
        pkt = CipSafetyPacket(
            snn=snn,
            tunid=1,
            ounid=100,
            target_id=0,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01",
            channel_b_payload=b"\xFE",
        )
        raw = pkt.serialize()
        assert len(raw) > 30

    def test_packet_serialization_roundtrip(self) -> None:
        snn = generate_snn(0x2026, 0x1006BB66)
        pkt = CipSafetyPacket(
            snn=snn,
            tunid=2,
            ounid=102,
            target_id=1,
            sequence_number=100,
            timestamp_ms=5000.0,
            mode_byte=SafetyControlByte.RUN | SafetyControlByte.PING_REQ,
            channel_a_payload=b"\xAA\xBB\xCC",
            channel_b_payload=b"\x55\x44\x33",
            ping_producer_ts_ms=5000.0,
            ping_turnaround_delay_ms=2.5,
        )
        pkt.calculate_crcs()
        raw = pkt.serialize()

        pkt_dec = CipSafetyPacket.deserialize(raw)
        assert pkt_dec.snn[:6] == pkt.snn[:6]
        assert pkt_dec.tunid == pkt.tunid
        assert pkt_dec.ounid == pkt.ounid
        assert pkt_dec.sequence_number == pkt.sequence_number
        assert pkt_dec.verify_crcs() is True
        assert pkt_dec.verify_dual_channel(DiversifiedMode.INVERTED) is True

    def test_packet_deserialization_short_buffer_raises(self) -> None:
        with pytest.raises(ValueError):
            CipSafetyPacket.deserialize(b"\x00" * 20)

    def test_packet_ping_timestamp_preservation(self) -> None:
        snn = generate_snn(0x2026, 0x1006BB66)
        pkt = CipSafetyPacket(
            snn=snn,
            tunid=3,
            ounid=103,
            target_id=2,
            sequence_number=1,
            timestamp_ms=1000.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x00",
            channel_b_payload=b"\xFF",
            ping_producer_ts_ms=999.0,
            ping_turnaround_delay_ms=1.5,
        )
        raw = pkt.serialize()
        dec = CipSafetyPacket.deserialize(raw)
        assert abs(dec.ping_producer_ts_ms - 999.0) < 0.001
        assert abs(dec.ping_turnaround_delay_ms - 1.5) < 0.001

    def test_packet_crc_corruption_fails_verify(self) -> None:
        snn = generate_snn(0x2026, 0x1006BB66)
        pkt = CipSafetyPacket(
            snn=snn,
            tunid=1,
            ounid=101,
            target_id=0,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01",
            channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        pkt.crc_s1 ^= 0x0001
        assert pkt.verify_crcs() is False


# ============================================================================
# Section 5: Target Registration & Capacity Limits (Max 8 Targets, 0xE706)
# ============================================================================

class TestSection5MultiTargetProvisioning:
    """Validate 8-target attachment limit and capacity overrun trip (0xE706)."""

    def test_attach_single_target_success(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        t = engine.attach_target(target_id=0, tunid=10, auto_activate=True)
        assert t.is_operational is True
        assert engine.active_safety_target_count == 1

    def test_attach_max_8_targets_success(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        for i in range(MAX_SAFETY_TARGETS):
            t = engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)
            assert t.is_operational is True

        assert engine.active_safety_target_count == 8
        assert engine.safety_network_operational_state == SafetyNetworkOperationalState.OPERATIONAL
        assert engine.guard_active is True
        assert engine.safety_trip_safe_state_engaged is False

    def test_active_target_count_tracking(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        for i in range(5):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)
        assert engine.active_safety_target_count == 5
        assert engine.active_target_count == 5

    def test_attach_9th_target_raises_overrun(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        for i in range(MAX_SAFETY_TARGETS):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)

        with pytest.raises(CipSafetyTargetCapacityOverrunError):
            engine.attach_target(target_id=8, tunid=99)

    def test_overrun_sets_diagnostic_code_0xE706(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        for i in range(MAX_SAFETY_TARGETS):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)
        try:
            engine.attach_target(target_id=8, tunid=99)
        except CipSafetyTargetCapacityOverrunError:
            pass
        assert engine.diagnostic_code == DiagnosticCode.TARGET_CAPACITY_OVERRUN
        assert engine.diagnostic_code == 0xE706
        assert engine.diagnostic_code == -6394

    def test_overrun_engages_safety_trip_safe_state(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        for i in range(MAX_SAFETY_TARGETS):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)
        try:
            engine.attach_target(target_id=8, tunid=99)
        except CipSafetyTargetCapacityOverrunError:
            pass
        assert engine.safety_trip_safe_state_engaged is True
        assert engine.safety_trip_fault_active is True

    def test_overrun_transitions_network_state_to_tripped(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        for i in range(MAX_SAFETY_TARGETS):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)
        try:
            engine.attach_target(target_id=8, tunid=99)
        except CipSafetyTargetCapacityOverrunError:
            pass
        assert engine.safety_network_operational_state == SafetyNetworkOperationalState.TRIPPED

    def test_overrun_increments_consecutive_fault_count(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        for i in range(MAX_SAFETY_TARGETS):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)
        assert engine.consecutive_safety_fault_count == 0
        try:
            engine.attach_target(target_id=8, tunid=99)
        except CipSafetyTargetCapacityOverrunError:
            pass
        assert engine.consecutive_safety_fault_count == 1


# ============================================================================
# Section 6: Sequence Number Monotonicity, Replay Attack & Rollover (0xE705)
# ============================================================================

class TestSection6SequenceIntegrity:
    """Validate packet repetition and sequence monotonicity detection."""

    def test_initial_packet_accepted(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        engine.receive_safety_packet(0, pkt)
        assert engine.get_target(0).last_rx_sequence == 1

    def test_sequential_packets_accepted(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        for seq in [1, 2, 3]:
            pkt = CipSafetyPacket(
                snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
                sequence_number=seq, timestamp_ms=float(seq * 10), mode_byte=SafetyControlByte.RUN,
                channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
            )
            pkt.calculate_crcs()
            engine.receive_safety_packet(0, pkt)
            assert engine.get_target(0).last_rx_sequence == seq

    def test_forward_gap_packets_accepted(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        pkt1 = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=5, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt1.calculate_crcs()
        engine.receive_safety_packet(0, pkt1)

        pkt2 = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=10, timestamp_ms=20.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt2.calculate_crcs()
        engine.receive_safety_packet(0, pkt2)
        assert engine.get_target(0).last_rx_sequence == 10

    def test_duplicate_packet_repetition_raises(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=5, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        engine.receive_safety_packet(0, pkt)
        with pytest.raises(CipSafetySequenceRolloverError):
            engine.receive_safety_packet(0, pkt)

    def test_replay_attack_sets_diagnostic_code_0xE705(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=5, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        engine.receive_safety_packet(0, pkt)
        try:
            engine.receive_safety_packet(0, pkt)
        except CipSafetySequenceError:
            pass
        assert engine.diagnostic_code == DiagnosticCode.SEQUENCE_NUMBER_ROLLOVER_FAULT
        assert engine.diagnostic_code == 0xE705

    def test_replay_attack_engages_safe_state(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=5, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        engine.receive_safety_packet(0, pkt)
        try:
            engine.receive_safety_packet(0, pkt)
        except CipSafetySequenceError:
            pass
        assert engine.get_target(0).state == SafetyTargetState.SAFE_STATE
        assert engine.safety_trip_safe_state_engaged is True

    def test_backward_sequence_jump_raises(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        pkt1 = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=100, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt1.calculate_crcs()
        engine.receive_safety_packet(0, pkt1)

        pkt2 = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=50, timestamp_ms=20.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt2.calculate_crcs()
        with pytest.raises(CipSafetySequenceRolloverError):
            engine.receive_safety_packet(0, pkt2)

    def test_simulate_sequence_rollover_helper(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.simulate_sequence_rollover_fault(0)
        assert engine.diagnostic_code == 0xE705
        assert engine.safety_trip_safe_state_engaged is True


# ============================================================================
# Section 7: Expected Packet Interval (EPI) Watchdogs & Timeout (0xE702)
# ============================================================================

class TestSection7EpiWatchdog:
    """Validate Expected Packet Interval watchdog silence timeout."""

    def test_watchdog_healthy_under_nominal_epi(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN, watchdog_timeout_ms=60.0)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.scan_step(dt=0.020)
        assert engine.get_target(0).is_operational is True
        assert engine.safety_trip_safe_state_engaged is False
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_partial_silence_below_timeout(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN, watchdog_timeout_ms=60.0)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.scan_step(dt=0.030)
        assert engine.get_target(0).is_operational is True
        assert engine.safety_trip_safe_state_engaged is False

    def test_silence_exceeding_timeout_trips_target(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN, watchdog_timeout_ms=60.0)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.scan_step(dt=0.030)
        engine.scan_step(dt=0.040)
        assert engine.get_target(0).is_faulted is True
        assert engine.get_target(0).state == SafetyTargetState.SAFE_STATE

    def test_silence_timeout_sets_diagnostic_code_0xE702(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN, watchdog_timeout_ms=60.0)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.scan_step(dt=0.070)
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.diagnostic_code == 0xE702
        assert engine.diagnostic_code == -6398

    def test_silence_timeout_engages_trip_state(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN, watchdog_timeout_ms=60.0)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.scan_step(dt=0.070)
        assert engine.safety_trip_safe_state_engaged is True
        assert engine.consecutive_safety_fault_count == 1

    def test_valid_packet_reception_resets_silence_timer(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN, watchdog_timeout_ms=60.0)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.scan_step(dt=0.030)
        assert engine.get_target(0).silence_elapsed_ms >= 30.0

        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=30.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        engine.receive_safety_packet(0, pkt)
        assert engine.get_target(0).silence_elapsed_ms == 0.0

    def test_independent_target_silence_timers(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN, watchdog_timeout_ms=60.0)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.attach_target(target_id=1, tunid=2, auto_activate=True)

        engine.scan_step(dt=0.030)
        # Refresh target 1
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=2, ounid=100, target_id=1,
            sequence_number=1, timestamp_ms=30.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        engine.receive_safety_packet(1, pkt)

        assert engine.get_target(1).silence_elapsed_ms == 0.0
        assert engine.get_target(0).silence_elapsed_ms >= 30.0

    def test_simulate_epi_watchdog_timeout_helper(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.simulate_epi_watchdog_timeout(0)
        assert engine.diagnostic_code == 0xE702
        assert engine.safety_trip_safe_state_engaged is True


# ============================================================================
# Section 8: Dual-Channel Discrepancy Fault (0xE703)
# ============================================================================

class TestSection8DualChannelDiscrepancy:
    """Verify dual-channel discrepancy fault detection, latching, and 0xE703."""

    def test_valid_dual_channel_packet_accepted(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=10, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x12\x34\x56", channel_b_payload=b"\xED\xCB\xA9",
        )
        pkt.calculate_crcs()
        cip_safety_guard_engine.receive_safety_packet(0, pkt)
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.OK

    def test_payload_single_bit_flip_trips_discrepancy(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        bad_b = bytearray(b"\xED\xCB\xA9")
        bad_b[0] ^= 0x01
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=10, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x12\x34\x56", channel_b_payload=bytes(bad_b),
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetyDualChannelDiscrepancyError):
            cip_safety_guard_engine.receive_safety_packet(0, pkt)

    def test_discrepancy_sets_diagnostic_code_0xE703(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        bad_b = bytearray(b"\xED\xCB\xA9")
        bad_b[0] ^= 0x01
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=10, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x12\x34\x56", channel_b_payload=bytes(bad_b),
        )
        pkt.calculate_crcs()
        try:
            cip_safety_guard_engine.receive_safety_packet(0, pkt)
        except CipSafetyDualChannelDiscrepancyError:
            pass
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert cip_safety_guard_engine.diagnostic_code == 0xE703

    def test_discrepancy_transitions_target_to_safe_state(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_dual_channel_discrepancy(0)
        assert cip_safety_guard_engine.get_target(0).state == SafetyTargetState.SAFE_STATE
        assert cip_safety_guard_engine.safety_trip_safe_state_engaged is True

    def test_discrepancy_updates_fault_bitmask(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_dual_channel_discrepancy(2)
        assert (cip_safety_guard_engine.active_target_fault_bitmask & (1 << 2)) != 0

    def test_simulate_dual_channel_discrepancy_helper(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_dual_channel_discrepancy(1)
        assert cip_safety_guard_engine.diagnostic_code == 0xE703


# ============================================================================
# Section 9: Safety Network Number (SNN) & Signature Mismatch (0xE701)
# ============================================================================

class TestSection9SnnAndSignatureMismatch:
    """Verify Safety Network Number, TUNID, and OUNID authentication and fault 0xE701."""

    def test_matching_snn_packet_accepted(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=10, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        cip_safety_guard_engine.receive_safety_packet(0, pkt)
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.OK

    def test_mismatched_snn_packet_raises_error(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        rogue_snn = bytes([0x99] * 6)
        pkt = CipSafetyPacket(
            snn=rogue_snn, tunid=10, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetySnnMismatchError):
            cip_safety_guard_engine.receive_safety_packet(0, pkt)

    def test_snn_mismatch_sets_diagnostic_code_0xE701(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_snn_signature_mismatch(0)
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert cip_safety_guard_engine.diagnostic_code == 0xE701

    def test_snn_mismatch_transitions_target_to_safe_state(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_snn_signature_mismatch(1)
        assert cip_safety_guard_engine.get_target(1).state == SafetyTargetState.SAFE_STATE
        assert cip_safety_guard_engine.safety_trip_safe_state_engaged is True

    def test_mismatched_tunid_raises_mismatch_error(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=999, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01", channel_b_payload=b"\xFE",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetySnnMismatchError):
            cip_safety_guard_engine.receive_safety_packet(0, pkt)

    def test_simulate_snn_mismatch_helper(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_snn_signature_mismatch(2)
        assert cip_safety_guard_engine.diagnostic_code == 0xE701


# ============================================================================
# Section 10: CRC-S Checksum Corruption Fault (0xE704)
# ============================================================================

class TestSection10CrcChecksumCorruption:
    """Verify Safety CRC-S1 and inverted CRC-S2 checksum verification and fault 0xE704."""

    def test_valid_crc_packet_accepted(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=10, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\xAA\x55", channel_b_payload=b"\x55\xAA",
        )
        pkt.calculate_crcs()
        cip_safety_guard_engine.receive_safety_packet(0, pkt)
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.OK

    def test_corrupted_crc_s1_raises_crc_error(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=10, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\xAA\x55", channel_b_payload=b"\x55\xAA",
        )
        pkt.calculate_crcs()
        pkt.crc_s1 ^= 0x0001
        with pytest.raises(CipSafetyCrcCorruptionError):
            cip_safety_guard_engine.receive_safety_packet(0, pkt)

    def test_corrupted_crc_s2_raises_crc_error(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN, tunid=10, ounid=100, target_id=0,
            sequence_number=1, timestamp_ms=10.0, mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\xAA\x55", channel_b_payload=b"\x55\xAA",
        )
        pkt.calculate_crcs()
        pkt.crc_s2 ^= 0x0001
        with pytest.raises(CipSafetyCrcCorruptionError):
            cip_safety_guard_engine.receive_safety_packet(0, pkt)

    def test_crc_corruption_sets_diagnostic_code_0xE704(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_crc_s_corruption(0)
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION
        assert cip_safety_guard_engine.diagnostic_code == 0xE704

    def test_crc_corruption_transitions_target_to_safe_state(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_crc_s_corruption(1)
        assert cip_safety_guard_engine.get_target(1).state == SafetyTargetState.SAFE_STATE
        assert cip_safety_guard_engine.safety_trip_safe_state_engaged is True

    def test_simulate_crc_corruption_helper(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_crc_s_corruption(3)
        assert (cip_safety_guard_engine.active_target_fault_bitmask & (1 << 3)) != 0


# ============================================================================
# Section 11: Horner OCS Register Synchronization (%R1870..%R1877, %M436..%M437)
# ============================================================================

class TestSection11RegisterSynchronization:
    """Validate synchronization to %R1870..%R1877 and %M436..%M437 with SYSTEM privilege."""

    def test_nominal_register_sync(self, register_table: RegisterTable) -> None:
        engine = CipSafetyGuardEngine(register_table=register_table, snn=DEFAULT_SNN)
        for i in range(3):
            engine.attach_target(target_id=i, tunid=20 + i, auto_activate=True)
        engine.monitored_safety_payload_words = 120
        engine.mean_safety_latency_ms = 15.5
        engine.max_safety_latency_ms = 19.0
        engine.sync_to_registers(register_table)

        assert register_table.read_word("%R1870") == 3
        assert register_table.read_word("%R1871") == 120
        assert register_table.read_word("%R1872") == 190
        assert register_table.read_word("%R1873") == 155
        assert register_table.read_word("%R1874") == 0
        assert register_table.read_word("%R1875") == 0
        assert register_table.read_word("%R1876") == 1
        assert register_table.read_uword("%R1877") == 0x0000
        assert register_table.read_bit("%M436") is True
        assert register_table.read_bit("%M437") is False

    def test_register_sync_on_fault_asserts_m437_clears_m436(
        self, register_table: RegisterTable
    ) -> None:
        engine = CipSafetyGuardEngine(register_table=register_table, snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.simulate_dual_channel_discrepancy(0)
        engine.sync_to_registers(register_table)

        assert register_table.read_bit("%M436") is False
        assert register_table.read_bit("%M437") is True
        assert register_table.read_word("%R1876") == 3

    def test_register_sync_diagnostic_code_written_to_r1877(
        self, register_table: RegisterTable
    ) -> None:
        engine = CipSafetyGuardEngine(register_table=register_table, snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.simulate_crc_s_corruption(0)
        engine.sync_to_registers(register_table)
        assert register_table.read_uword("%R1877") == 0xE704

    def test_register_sync_signed_unsigned_word_equality(
        self, register_table: RegisterTable
    ) -> None:
        engine = CipSafetyGuardEngine(register_table=register_table, snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.simulate_snn_signature_mismatch(0)
        engine.sync_to_registers(register_table)

        u_code = register_table.read_uword("%R1877")
        s_code = register_table.read_word("%R1877")
        assert u_code == 0xE701
        assert (s_code & 0xFFFF) == 0xE701

    def test_register_sync_latency_scale_x10(
        self, register_table: RegisterTable
    ) -> None:
        engine = CipSafetyGuardEngine(register_table=register_table, snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.mean_safety_latency_ms = 12.3
        engine.max_safety_latency_ms = 17.8
        engine.sync_to_registers(register_table)

        assert register_table.read_word("%R1873") == 123
        assert register_table.read_word("%R1872") == 178

    def test_register_sync_active_fault_bitmask(
        self, register_table: RegisterTable
    ) -> None:
        engine = CipSafetyGuardEngine(register_table=register_table, snn=DEFAULT_SNN)
        for i in range(4):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)
        engine.simulate_epi_watchdog_timeout(1)
        engine.simulate_crc_s_corruption(3)
        engine.sync_to_registers(register_table)

        expected_mask = (1 << 1) | (1 << 3)
        assert register_table.read_word("%R1875") == expected_mask

    def test_safe_write_helpers_system_privilege(
        self, register_table: RegisterTable
    ) -> None:
        safe_write_word(register_table, "%R1870", 2)
        safe_write_uword(register_table, "%R1877", 0xE701)
        safe_write_bit(register_table, "%M436", True)

        assert register_table.read_word("%R1870") == 2
        assert register_table.read_uword("%R1877") == 0xE701
        assert register_table.read_bit("%M436") is True

    def test_fault_trip_and_reset_recovery(
        self, register_table: RegisterTable
    ) -> None:
        engine = CipSafetyGuardEngine(register_table=register_table, snn=DEFAULT_SNN)
        engine.attach_target(target_id=0, tunid=1, auto_activate=True)
        engine.simulate_dual_channel_discrepancy(0)

        assert register_table.read_uword("%R1877") == 0xE703
        assert register_table.read_bit("%M436") is False
        assert register_table.read_bit("%M437") is True

        res = engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS

        assert register_table.read_uword("%R1877") == 0x0000
        assert register_table.read_bit("%M436") is True
        assert register_table.read_bit("%M437") is False


# ============================================================================
# Section 12: Pure ST POU Validation & Anti-Ladder Security Guard Interception
# ============================================================================

class TestSection12PureSTPOU:
    """Verify IEC 61131-3 Pure Structured Text POU compliance and register binding."""

    def test_cip_safety_guard_pure_st_helper(self) -> None:
        assert verify_cip_safety_guard_pure_st() is True

    def test_security_guard_pure_st_pou_passes(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_GUARD_SYNC_POU)
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_GUARD_POU)
        SecurityGuard.assert_pure_st_content(PURE_ST_POU)

    def test_st_parser_pou_validation_success(self) -> None:
        res = STParser.validate_code(CIP_SAFETY_GUARD_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_ast_program_type(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_GUARD_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM

    def test_st_parser_all_10_registers_bound(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_GUARD_SYNC_POU)
        expected_regs = {
            "%R1870", "%R1871", "%R1872", "%R1873",
            "%R1874", "%R1875", "%R1876", "%R1877",
            "%M436", "%M437",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_anti_ladder_contacts_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  ---[ ]---\nEND_PROGRAM")

    def test_anti_ladder_coils_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  ---( )---\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  ---(S)---\nEND_PROGRAM")

    def test_anti_ladder_rung_network_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  RUNG 1\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T VAR END_VAR\n  NETWORK 1\nEND_PROGRAM")


# ============================================================================
# Section 13: ILogicUnit Interface Compliance & Scan Cycle Simulation
# ============================================================================

class TestSection13LogicUnitCompliance:
    """Verify ILogicUnit interface compliance and scan cycle simulation."""

    def test_ilogicunit_interface_inheritance(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        assert isinstance(cip_safety_guard_engine, ILogicUnit)
        assert CIPSafetyGuardEngine == CipSafetyGuardEngine
        assert CipSafetyGuard == CipSafetyGuardEngine

    def test_ilogicunit_properties(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        assert cip_safety_guard_engine.name == "CipSafetyGuardEngine"
        assert cip_safety_guard_engine.priority == 95
        assert cip_safety_guard_engine.is_enabled is True

    def test_scan_step_cyclic_execution(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.scan_step(dt=0.010)
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.OK

    def test_execute_with_scan_context(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        cip_safety_guard_engine.execute(ctx)
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.OK

    def test_disabled_engine_skips_scan(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.is_enabled = False
        t0 = cip_safety_guard_engine.get_target(0)
        initial_silence = t0.silence_elapsed_ms
        ctx = ScanContext(cycle=1, dt_ms=100.0, elapsed_time_ms=100.0)
        cip_safety_guard_engine.execute(ctx)
        assert t0.silence_elapsed_ms == initial_silence

    def test_100_cycle_scan_simulation_stability(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN, watchdog_timeout_ms=100.0)
        for i in range(4):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)

        ctx = ScanContext()
        for cycle in range(100):
            if cycle % 3 == 0:
                for i in range(4):
                    engine.get_target(i).silence_elapsed_ms = 0.0
            engine.scan_step(dt=0.010, context=ctx)

        assert engine.safety_network_operational_state == SafetyNetworkOperationalState.OPERATIONAL
        assert engine.guard_active is True
        assert engine.safety_trip_safe_state_engaged is False

    def test_reset_method_restores_nominal_state(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_crc_s_corruption(0)
        assert cip_safety_guard_engine.safety_trip_safe_state_engaged is True
        cip_safety_guard_engine.reset()
        assert cip_safety_guard_engine.safety_trip_safe_state_engaged is False
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.OK
        assert cip_safety_guard_engine.safety_network_operational_state == SafetyNetworkOperationalState.OPERATIONAL

    def test_reset_fault_force_returns_execution_result(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_epi_watchdog_timeout(0)
        res = cip_safety_guard_engine.reset_fault(force=True)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert cip_safety_guard_engine.safety_trip_safe_state_engaged is False


# ============================================================================
# Section 14: Multi-Target State Machine Coordination & Recovery
# ============================================================================

class TestSection14StateMachine:
    """Validate aggregate network states: INITIALIZING, OPERATIONAL, DEGRADED, TRIPPED, SAFE_STATE."""

    def test_network_state_initializing_without_targets(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        assert engine.safety_network_operational_state == SafetyNetworkOperationalState.INITIALIZING
        assert engine.guard_active is False
        assert engine.safety_trip_safe_state_engaged is False

    def test_network_state_operational_all_healthy(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        assert cip_safety_guard_engine.safety_network_operational_state == SafetyNetworkOperationalState.OPERATIONAL
        assert cip_safety_guard_engine.guard_active is True
        assert cip_safety_guard_engine.active_target_fault_bitmask == 0

    def test_network_state_degraded_partial_fault(self) -> None:
        engine = CipSafetyGuardEngine(snn=DEFAULT_SNN)
        for i in range(4):
            engine.attach_target(target_id=i, tunid=10 + i, auto_activate=True)
        assert engine.safety_network_operational_state == SafetyNetworkOperationalState.OPERATIONAL

        t1 = engine.get_target(1)
        t1.state = SafetyTargetState.FAULTED
        engine._update_aggregate_state()

        assert engine.safety_network_operational_state == SafetyNetworkOperationalState.DEGRADED
        assert (engine.active_target_fault_bitmask & (1 << 1)) != 0

    def test_network_state_tripped_on_diagnostic(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_crc_s_corruption(0)
        assert cip_safety_guard_engine.safety_network_operational_state == SafetyNetworkOperationalState.TRIPPED
        assert cip_safety_guard_engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION
        assert cip_safety_guard_engine.guard_active is False
        assert cip_safety_guard_engine.safety_trip_safe_state_engaged is True

    def test_nominal_recovery_after_fault_clear(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        cip_safety_guard_engine.simulate_dual_channel_discrepancy(1)
        assert cip_safety_guard_engine.safety_network_operational_state == SafetyNetworkOperationalState.TRIPPED
        cip_safety_guard_engine.reset_fault(force=True)
        assert cip_safety_guard_engine.safety_network_operational_state == SafetyNetworkOperationalState.OPERATIONAL
        assert cip_safety_guard_engine.active_target_fault_bitmask == 0

    def test_remove_target_updates_state(
        self, cip_safety_guard_engine: CipSafetyGuardEngine
    ) -> None:
        assert cip_safety_guard_engine.active_safety_target_count == 4
        cip_safety_guard_engine.remove_target(3)
        assert cip_safety_guard_engine.active_safety_target_count == 3
        with pytest.raises(KeyError):
            cip_safety_guard_engine.get_target(3)


# ============================================================================
# Section 15: Verification Runner & Strict 4-State Engineering Contract
# ============================================================================

class TestSection15VerificationRunner:
    """Validate deterministic verification suite conforms to AGENTS.md."""

    def test_verification_runner_returns_dict(self) -> None:
        res = run_cip_safety_guard_verification()
        assert isinstance(res, dict)

    def test_verification_runner_strict_4_state_format(self) -> None:
        res = run_cip_safety_guard_verification()
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert "error_code" in res
        assert "details" in res
        assert "data" in res

    def test_verification_runner_all_stages_pass(self) -> None:
        res = run_cip_safety_guard_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["stages_passed"] == 10
        assert res["total_stages"] == 10
        assert all(s["passed"] for s in res["data"]["stages"])

    def test_verification_runner_writes_json_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_guard_evidence.json"
        res = run_cip_safety_guard_verification(output_path=out_file)
        assert res["status"] == "success"
        assert out_file.exists()

    def test_verification_runner_evidence_work_package_w226(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_guard_evidence.json"
        run_cip_safety_guard_verification(output_path=out_file)
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["data"]["work_package"] == "W226"
        assert data["status"] == "success"
        assert "register_map" in data["data"]

    def test_cli_verification_script_executes_successfully(self) -> None:
        cmd = [sys.executable, "scripts/run_cip_safety_guard_verification.py"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert proc.returncode == 0
        assert "[SUCCESS]" in proc.stdout
