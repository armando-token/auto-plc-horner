"""Comprehensive Unit Test Suite for Wave W241 CIP Safety Multicast Producer-Consumer Engine.

Work Package: W241 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 100+ Comprehensive Unit Tests across 17 Sections:
1. Section 1: Protocol Constants, Identifiers, Enums & Diagnostic Codes (signed/unsigned & 0xFFFF).
2. Section 2: SNN Format (6 octets), SCID, TUNID, & OUNID Parsing, Formatting, Validation & Generation.
3. Section 3: Dual CRC-S Calculations (CRC-S1 poly 0x5935 and CRC-S2 poly 0x755B).
4. Section 4: Dual-Channel Diversified Payload Verification & Discrepancy Detection.
5. Section 5: Managed Registered Consumers (Consumer 0..3) Initialization & Telemetry.
6. Section 6: Multicast Producer Broadcast Engine (produce_and_broadcast, broadcast_packet).
7. Section 7: Expected Packet Interval (EPI) Surveillance & Timeout Tripping (0xEB02).
8. Section 8: Consumer Desynchronization Surveillance (0xEB04) & Active Desync Index (%R2024).
9. Section 9: Consumer Node Dropout (0xEB05) & Multicast Group Corruption (0xEB06).
10. Section 10: Horner OCS Register Table Synchronization (%R2020..%R2027, %M471..%M472).
11. Section 11: Pure IEC 61131-3 Structured Text POU Validation (SecurityGuard & STParser).
12. Section 12: Anti-Ladder Security Guard Interception (contacts, coils, rungs, mnemonics).
13. Section 13: ILogicUnit Interface Compliance & Scan Cycle Simulation.
14. Section 14: 100-Cycle Soak Simulation & Bounded Execution (Heap & Memory Stability).
15. Section 15: Operator Reset & Safe State Recovery.
16. Section 16: Verification Runner & Strict 4-State Engineering Contract.
17. Section 17: Additional Consumer Scenarios & Security Guard Safety.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
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
from jev_cscape.telemetry.cip_safety_multicast import (
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_CRC_INIT,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_MULTICAST_CLASS_ID,
    CIP_SAFETY_MULTICAST_CONNECTION_CLASS_ID,
    CIP_SAFETY_MULTICAST_POU,
    CIP_SAFETY_MULTICAST_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_MULTICAST_SYNC_POU,
    CIP_SAFETY_MULTICAST_VALIDATOR_CLASS_ID,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyMulticastEngine,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_S_INIT,
    DEFAULT_CONSUMER_COUNT,
    DEFAULT_CONSUMER_NODES_COUNT,
    DEFAULT_CONSUMER_UNIDS,
    DEFAULT_EPI_MS,
    DEFAULT_GROUP_ID,
    DEFAULT_MULTICAST_HEALTH_INDEX,
    DEFAULT_MULTICAST_HEALTH_INDEX_SCALED,
    DEFAULT_OUNID,
    DEFAULT_PRODUCER_UNID,
    DEFAULT_SCID,
    DEFAULT_SCID_CRC,
    DEFAULT_SCID_TIMESTAMP,
    DEFAULT_SNN,
    DEFAULT_TUNID,
    DEFAULT_WATCHDOG_MULTIPLIER,
    WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DIAG_ACK_DESYNC,
    DIAG_CONSUMER_ACK_DESYNC,
    DIAG_CONSUMER_DROPOUT,
    DIAG_CONSUMER_NODE_DROPOUT,
    DIAG_CRC_FAULT,
    DIAG_CRC_S_CORRUPTION,
    DIAG_CRC_S_FAULT,
    DIAG_DISCREPANCY,
    DIAG_DUAL_CHANNEL_DISCREPANCY,
    DIAG_EPI_TIMEOUT,
    DIAG_EPI_WATCHDOG_TIMEOUT,
    DIAG_GROUP_CORRUPTED,
    DIAG_MULTICAST_CORRUPTED,
    DIAG_MULTICAST_GROUP_CORRUPTED,
    DIAG_MULTICAST_OK,
    DIAG_NODE_DROPOUT,
    DIAG_OK,
    EPI_WATCHDOG_TIMEOUT_MS,
    NOMINAL_EPI_MS,
    CipSafetyConsumerAckDesyncError,
    CipSafetyConsumerDesyncError,
    CipSafetyConsumerDropoutError,
    CipSafetyConsumerNodeDropoutError,
    CipSafetyCrcFaultError,
    CipSafetyDiscrepancyError,
    CipSafetyEpiTimeoutError,
    CipSafetyMulticast,
    CipSafetyMulticastDiagnosticCode,
    CipSafetyMulticastEngine,
    CipSafetyMulticastError,
    CipSafetyMulticastGroupCorruptedError,
    CipSafetyMulticastGroupError,
    CipSafetyMulticastPacket,
    CipSafetyMulticastState,
    CipSafetyMulticastSync,
    CipSafetyPacket,
    ConsumerNode,
    ConsumerNodeIndex,
    DiagnosticCode,
    DiversifiedMode,
    MulticastDiagnosticCode,
    MulticastState,
    MulticastStatusBits,
    MulticastTopologyState,
    MulticastTopologyStatusBits,
    OriginatorUniqueNetworkId,
    SafetyConfigurationIdentifier,
    SafetyControlByte,
    SafetyMulticastEngine,
    SafetyNetworkNumber,
    TargetUniqueNetworkId,
    compute_crc_s1,
    compute_crc_s2,
    create_default_consumers,
    create_valid_packet,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_multicast_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    validate_snn,
    verify_cip_safety_multicast_pure_st,
    verify_dual_channel_payload,
)


# ============================================================================
# Section 1: Protocol Constants, Identifiers, Enums & Diagnostic Codes
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA Volume 5 CIP Safety Multicast constants and diagnostic code semantics."""

    def test_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_MULTICAST_CLASS_ID in (0x39, 0x3B)
        assert CIP_SAFETY_MULTICAST_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_MULTICAST_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_MULTICAST_CONNECTION_CLASS_ID == 0x3B

    def test_crc_polynomials(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S_INIT == 0xFFFF

    def test_timing_defaults(self) -> None:
        assert NOMINAL_EPI_MS == 10.0
        assert DEFAULT_EPI_MS == 10.0
        assert WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert EPI_WATCHDOG_TIMEOUT_MS == 30.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 30.0

    def test_defaults(self) -> None:
        assert DEFAULT_MULTICAST_HEALTH_INDEX == 9985
        assert DEFAULT_MULTICAST_HEALTH_INDEX_SCALED == 9985
        assert DEFAULT_CONSUMER_COUNT == 4
        assert DEFAULT_CONSUMER_NODES_COUNT == 4
        assert DEFAULT_CONSUMER_UNIDS == [20, 21, 22, 23]
        assert DEFAULT_PRODUCER_UNID == 100
        assert DEFAULT_OUNID == 100
        assert DEFAULT_TUNID == 20
        assert DEFAULT_GROUP_ID == 1
        assert DEFAULT_SCID == 0x20261006

    def test_diagnostic_code_values_and_signed_equality(self) -> None:
        codes = [
            (DiagnosticCode.MULTICAST_OK, 0x0000, 0),
            (DiagnosticCode.CRC_S_FAULT, 0xEB01, -5375),
            (DiagnosticCode.EPI_WATCHDOG_TIMEOUT, 0xEB02, -5374),
            (DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, 0xEB03, -5373),
            (DiagnosticCode.CONSUMER_ACK_DESYNC, 0xEB04, -5372),
            (DiagnosticCode.CONSUMER_NODE_DROPOUT, 0xEB05, -5371),
            (DiagnosticCode.MULTICAST_GROUP_CORRUPTED, 0xEB06, -5370),
        ]
        for diag_obj, unsigned_val, signed_val in codes:
            assert diag_obj == unsigned_val
            assert (diag_obj & 0xFFFF) == unsigned_val
            assert diag_obj == signed_val
            assert int(diag_obj) == unsigned_val
            assert isinstance(diag_obj, int)

    def test_diagnostic_code_bitwise_and(self) -> None:
        code = DiagnosticCode.CRC_S_FAULT  # 0xEB01
        masked = code & 0xFFFF
        assert masked == 0xEB01
        assert (0xFFFF & code) == 0xEB01
        assert isinstance(masked, DiagnosticCode)

    def test_diagnostic_code_aliases(self) -> None:
        assert DiagnosticCode.OK == DiagnosticCode.MULTICAST_OK
        assert DiagnosticCode.NOMINAL == DiagnosticCode.MULTICAST_OK
        assert DiagnosticCode.CRC_FAULT == DiagnosticCode.CRC_S_FAULT
        assert DiagnosticCode.CRC_S_CORRUPTION == DiagnosticCode.CRC_S_FAULT
        assert DiagnosticCode.EPI_TIMEOUT == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DiagnosticCode.DISCREPANCY_FAULT == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert DiagnosticCode.ACK_DESYNC == DiagnosticCode.CONSUMER_ACK_DESYNC
        assert DiagnosticCode.CONSUMER_DESYNC == DiagnosticCode.CONSUMER_ACK_DESYNC
        assert DiagnosticCode.NODE_DROPOUT == DiagnosticCode.CONSUMER_NODE_DROPOUT
        assert DiagnosticCode.CONSUMER_DROPOUT == DiagnosticCode.CONSUMER_NODE_DROPOUT
        assert DiagnosticCode.GROUP_CORRUPTED == DiagnosticCode.MULTICAST_GROUP_CORRUPTED
        assert DiagnosticCode.MULTICAST_CORRUPTED == DiagnosticCode.MULTICAST_GROUP_CORRUPTED

    def test_diagnostic_code_repr_and_str(self) -> None:
        code = DiagnosticCode.CRC_S_FAULT
        assert "0xEB01" in repr(code)
        assert "CRC_S_FAULT" in repr(code)
        assert "0xEB01" in str(code)

    def test_multicast_state_enum(self) -> None:
        assert MulticastState.INIT == 0
        assert MulticastState.PRODUCING_ACTIVE == 1
        assert MulticastState.DEGRADED == 2
        assert MulticastState.SAFE_STATE == 3
        assert MulticastState.FAULTED == 4

    def test_safety_control_byte_flags(self) -> None:
        assert SafetyControlByte.RUN == 1 << 0
        assert SafetyControlByte.PING_REQ == 1 << 1
        assert SafetyControlByte.PING_RESP == 1 << 2
        assert SafetyControlByte.SAFETY_DEMAND == 1 << 3
        assert SafetyControlByte.FAULT_PRESENT == 1 << 4
        assert SafetyControlByte.RESET_REQUEST == 1 << 5
        assert SafetyControlByte.MULTICAST_CAST == 1 << 6
        assert SafetyControlByte.DISCONNECT_REQ == 1 << 7


TestSection1ConstantsAndDiagnosticCodes = TestConstantsEnumsAndDiagnostics


# ============================================================================
# Section 2: SNN Format, SCID, TUNID & OUNID Management
# ============================================================================

class TestCipSafetyMulticastConfiguration:
    """Validate Safety Network Number and Identifier data structures."""

    def test_default_snn_length(self) -> None:
        assert len(DEFAULT_SNN) == 6
        assert validate_snn(DEFAULT_SNN) is True

    def test_format_and_parse_snn(self) -> None:
        snn_bytes = bytes([0x20, 0x26, 0x10, 0x06, 0xDD, 0x77])
        snn_str = format_snn(snn_bytes)
        assert snn_str == "2026-1006-DD77"
        parsed = parse_snn(snn_str)
        assert parsed == snn_bytes

    def test_generate_snn(self) -> None:
        gen = generate_snn(seed=0x20261006)
        assert len(gen) == 6
        assert validate_snn(gen) is True

    def test_snn_dataclass(self) -> None:
        snn = SafetyNetworkNumber(DEFAULT_SNN)
        assert snn.matches(DEFAULT_SNN) is True
        assert snn.format() == format_snn(DEFAULT_SNN)
        from_str = SafetyNetworkNumber.from_string(format_snn(DEFAULT_SNN))
        assert from_str.matches(snn) is True

    def test_scid_dataclass(self) -> None:
        scid = SafetyConfigurationIdentifier(crc=0x12345678, timestamp=0x9ABCDEF0)
        assert scid.to_bytes() == struct.pack(">II", 0x12345678, 0x9ABCDEF0)
        scid2 = SafetyConfigurationIdentifier(crc=0x12345678, timestamp=0x9ABCDEF0)
        assert scid.matches(scid2) is True

    def test_tunid_and_ounid(self) -> None:
        snn = SafetyNetworkNumber(DEFAULT_SNN)
        tunid = TargetUniqueNetworkId(snn=snn, target_node_id=20)
        ounid = OriginatorUniqueNetworkId(snn=snn, originator_node_id=100)
        assert tunid.target_node_id == 20
        assert ounid.originator_node_id == 100
        tunid2 = TargetUniqueNetworkId(snn=snn, target_node_id=20)
        assert tunid.matches(tunid2) is True


# ============================================================================
# Section 3: Dual CRC-S Calculations (CRC-S1 poly 0x5935 and CRC-S2 poly 0x755B)
# ============================================================================

class TestCrcSChecksumAlgorithms:
    """Validate 16-bit safety checksums CRC-S1 and CRC-S2."""

    def test_crc_s1_basic(self) -> None:
        data = b"CIP_SAFETY_MULTICAST"
        crc1 = compute_crc_s1(data)
        assert 0 <= crc1 <= 0xFFFF
        assert crc1 == compute_crc_s1(data)

    def test_crc_s2_basic(self) -> None:
        data = b"CIP_SAFETY_MULTICAST"
        crc2 = compute_crc_s2(data)
        assert 0 <= crc2 <= 0xFFFF
        assert crc2 == compute_crc_s2(data)
        # CRC-S1 and CRC-S2 must differ due to different polynomials
        assert compute_crc_s1(data) != compute_crc_s2(data)

    def test_crc_s1_and_s2_polynomial_difference(self) -> None:
        sample = bytes([0x01, 0x02, 0x03, 0x04])
        s1 = compute_crc_s1(sample, poly=0x5935)
        s2 = compute_crc_s2(sample, poly=0x755B)
        assert s1 != s2

    def test_crc_s1_single_bit_flip_detection(self) -> None:
        orig = bytes([0xAA, 0x55, 0x12, 0x34])
        flipped = bytes([0xAB, 0x55, 0x12, 0x34])  # 1 bit flipped
        assert compute_crc_s1(orig) != compute_crc_s1(flipped)

    def test_crc_s2_single_bit_flip_detection(self) -> None:
        orig = bytes([0xAA, 0x55, 0x12, 0x34])
        flipped = bytes([0xAA, 0x55, 0x12, 0x35])  # 1 bit flipped
        assert compute_crc_s2(orig) != compute_crc_s2(flipped)

    def test_crc_s2_unpacked_arguments(self) -> None:
        ts = 1000
        seq = 5
        payload = bytes([0x12, 0x34])
        crc = compute_crc_s2(ts, seq, payload)
        expected_data = struct.pack(">IH", ts, seq) + payload
        assert crc == compute_crc_s2(expected_data)

    def test_crc_empty_data(self) -> None:
        assert compute_crc_s1(b"") == 0xFFFF
        assert compute_crc_s2(b"") == 0xFFFF


# ============================================================================
# Section 4: Dual-Channel Diversified Payload Cross-Comparison
# ============================================================================

class TestDualChannelParityAndDiscrepancy:
    """Validate dual-channel complement parity verification."""

    def test_verify_payload_bytes_inverted(self) -> None:
        ch_a = bytes([0x01, 0x00])
        ch_b = bytes([0xFE, 0xFF])  # bitwise complement
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is True

    def test_verify_payload_bytes_discrepancy(self) -> None:
        ch_a = bytes([0x01, 0x00])
        ch_b = bytes([0x01, 0x00])  # identical -> not complement
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False

    def test_verify_payload_int_inverted(self) -> None:
        ch_a = 0x1234
        ch_b = (~ch_a) & 0xFFFF
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is True

    def test_verify_payload_int_discrepancy(self) -> None:
        ch_a = 0x1234
        ch_b = 0x1234
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False

    def test_verify_payload_length_mismatch(self) -> None:
        ch_a = bytes([0x01, 0x00])
        ch_b = bytes([0xFE])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False


# ============================================================================
# Section 5: Managed Registered Consumers Initialization & Telemetry
# ============================================================================

class TestSection5ManagedConsumers:
    """Validate consumer directory and default consumer nodes."""

    def test_create_default_consumers_count(self) -> None:
        consumers = create_default_consumers()
        assert len(consumers) == 4

    def test_default_consumer_names(self) -> None:
        consumers = create_default_consumers()
        assert consumers[0].name == "Robot Cell Safety Zone"
        assert consumers[1].name == "Conveyor Line Safety Gate"
        assert consumers[2].name == "Gantry Crane Travel Zone"
        assert consumers[3].name == "Palletizer Light Curtain"

    def test_consumer_indices_and_node_ids(self) -> None:
        consumers = create_default_consumers()
        for i, c in enumerate(consumers):
            assert c.consumer_index == i
            assert c.node_id == i + 1
            assert c.is_connected is True
            assert c.is_faulted is False
            assert c.is_synchronized is True
            assert c.diagnostic_code == DiagnosticCode.MULTICAST_OK

    def test_consumer_to_dict(self) -> None:
        c = create_default_consumers()[0]
        d = c.to_dict()
        assert d["consumer_index"] == 0
        assert d["name"] == "Robot Cell Safety Zone"
        assert d["is_connected"] is True
        assert d["diagnostic_code"] == 0x0000


# ============================================================================
# Section 6: Multicast Producer Broadcast Engine
# ============================================================================

class TestMulticastGroupBroadcast:
    """Validate produce_and_broadcast and broadcast_packet mechanics."""

    def test_produce_and_broadcast_nominal(self) -> None:
        engine = CipSafetyMulticastEngine()
        initial_seq = engine.producer_sequence_number
        pkt = engine.produce_and_broadcast(payload_word=0x1234)
        assert pkt is not None
        assert engine.producer_sequence_number == initial_seq + 1
        assert engine.total_broadcast_packets == 1
        assert pkt.verify_dual_channel() is True
        assert pkt.verify_crcs() is True
        # All connected consumers received packet
        for c in engine.consumers:
            assert c.packets_received == 1
            assert c.silence_time_ms == 0.0

    def test_broadcast_packet_crc_corruption_trips_0xeb01(self) -> None:
        engine = CipSafetyMulticastEngine()
        pkt = create_valid_packet(sequence_number=1)
        pkt.crc_s1 ^= 0xFFFF  # Corrupt CRC-S1
        success = engine.broadcast_packet(pkt)
        assert success is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.CRC_S_FAULT
        assert engine.multicast_state == MulticastState.SAFE_STATE

    def test_broadcast_packet_discrepancy_trips_0xeb03(self) -> None:
        engine = CipSafetyMulticastEngine()
        pkt = CipSafetyMulticastPacket(
            channel_a_payload=bytes([0x01, 0x00]),
            channel_b_payload=bytes([0x01, 0x00]),  # Not complementary
        )
        pkt.calculate_crcs()
        success = engine.broadcast_packet(pkt)
        assert success is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY

    def test_broadcast_packet_updates_aggregated_payload(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.produce_and_broadcast(payload_word=0xABCD)
        assert engine.aggregated_safety_payload == 0xABCD


# ============================================================================
# Section 7: Expected Packet Interval (EPI) Surveillance & Timeout Tripping
# ============================================================================

class TestEpiWatchdogSurveillance:
    """Validate 10.0 ms EPI and 30.0 ms watchdog silence trip."""

    def test_watchdog_silence_under_threshold(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.scan_step(0.010)  # 10 ms
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.MULTICAST_OK

    def test_watchdog_timeout_trips_at_30ms(self) -> None:
        engine = CipSafetyMulticastEngine()
        # 4 steps of 10 ms = 40 ms > 30 ms watchdog
        for _ in range(4):
            engine.scan_step(0.010)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.multicast_state == MulticastState.SAFE_STATE
        assert engine.trip_safe_state_engaged is True

    def test_watchdog_reset_on_broadcast(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.scan_step(0.010)  # 10 ms silence
        engine.scan_step(0.010)  # 20 ms silence
        assert engine.consumers[0].silence_time_ms == 20.0
        # Broadcast resets silence
        engine.produce_and_broadcast()
        assert engine.consumers[0].silence_time_ms == 0.0
        assert engine.is_fault_active is False

    def test_simulate_epi_timeout_helper(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.simulate_epi_timeout(consumer_index=2)
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.active_desync_consumer_index == 2
        assert engine.is_fault_active is True


# ============================================================================
# Section 8: Consumer Desynchronization Surveillance (0xEB04)
# ============================================================================

class TestSection8ConsumerDesync:
    """Validate consumer acknowledgment sequence gap and desync surveillance."""

    def test_ack_nominal_matching_sequence(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.produce_and_broadcast()
        current_seq = engine.producer_sequence_number
        ack_ok = engine.acknowledge_packet(consumer_index=0, ack_sequence=current_seq)
        assert ack_ok is True
        assert engine.is_fault_active is False
        assert engine.consumers[0].is_synchronized is True
        assert engine.consumers[0].last_acked_sequence == current_seq

    def test_ack_sequence_gap_trips_0xeb04(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.produce_and_broadcast()
        current_seq = engine.producer_sequence_number
        # Acknowledge with mismatched sequence number (sequence gap)
        ack_ok = engine.acknowledge_packet(consumer_index=1, ack_sequence=current_seq + 5)
        assert ack_ok is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.CONSUMER_ACK_DESYNC
        assert engine.active_desync_consumer_index == 1
        assert engine.consumers[1].is_synchronized is False

    def test_simulate_ack_desync_helper(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.simulate_ack_desync(consumer_index=3)
        assert engine.diagnostic_code == DiagnosticCode.CONSUMER_ACK_DESYNC
        assert engine.active_desync_consumer_index == 3
        assert engine.is_fault_active is True


# ============================================================================
# Section 9: Consumer Node Dropout & Multicast Group Corruption
# ============================================================================

class TestConsumerDesyncAndDropout:
    """Validate 0xEB05 consumer dropout and 0xEB06 multicast group corruption."""

    def test_disconnect_consumer_trips_0xeb05(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.disconnect_consumer(2)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.CONSUMER_NODE_DROPOUT
        assert engine.active_desync_consumer_index == 2
        assert engine.consumers[2].is_connected is False

    def test_reconnect_consumer_restores_parameters(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.disconnect_consumer(2)
        assert engine.consumers[2].is_connected is False
        engine.reconnect_consumer(2)
        assert engine.consumers[2].is_connected is True
        assert engine.consumers[2].watchdog_timer_ms == engine.consumers[2].watchdog_timeout_ms

    def test_ack_from_disconnected_consumer_trips_0xeb05(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.consumers[0].is_connected = False
        ack_ok = engine.acknowledge_packet(consumer_index=0, ack_sequence=engine.producer_sequence_number)
        assert ack_ok is False
        assert engine.diagnostic_code == DiagnosticCode.CONSUMER_NODE_DROPOUT

    def test_multicast_group_corrupted_flag_trips_0xeb06(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.multicast_group_corrupted = True
        pkt = create_valid_packet()
        broadcast_ok = engine.broadcast_packet(pkt)
        assert broadcast_ok is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.MULTICAST_GROUP_CORRUPTED

    def test_acknowledge_out_of_bounds_consumer_trips_0xeb06(self) -> None:
        engine = CipSafetyMulticastEngine()
        ack_ok = engine.acknowledge_packet(consumer_index=99, ack_sequence=1)
        assert ack_ok is False
        assert engine.diagnostic_code == DiagnosticCode.MULTICAST_GROUP_CORRUPTED

    def test_simulate_group_corruption_helper(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.simulate_group_corruption()
        assert engine.diagnostic_code == DiagnosticCode.MULTICAST_GROUP_CORRUPTED
        assert engine.is_fault_active is True


TestSection9DropoutAndGroupCorruption = TestConsumerDesyncAndDropout


# ============================================================================
# Section 10: Horner OCS Register Table Synchronization
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate %R2020..%R2027 and %M471..%M472 memory mapping."""

    def test_register_synchronization_nominal(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyMulticastEngine(register_table=rt, auto_activate=True)
        assert rt.read_word("%R2020") == 4
        assert rt.read_word("%R2021") == 9985
        assert rt.read_uword("%R2022") == 1
        assert rt.read_word("%R2023") == 0
        assert rt.read_word("%R2024") == -1
        assert rt.read_word("%R2026") == 0
        assert rt.read_uword("%R2027") == 0x0000
        assert rt.read_bit("%M471") is True
        assert rt.read_bit("%M472") is False

    def test_register_synchronization_on_fault(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyMulticastEngine(register_table=rt, auto_activate=True)
        engine.trip_fault(DiagnosticCode.CONSUMER_ACK_DESYNC, consumer_index=2)
        assert rt.read_word("%R2024") == 2
        assert rt.read_uword("%R2027") == 0xEB04
        assert rt.read_bit("%M471") is False
        assert rt.read_bit("%M472") is True
        assert rt.read_word("%R2021") < 9985

    def test_register_synchronization_packets_scaled(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyMulticastEngine(register_table=rt, auto_activate=True)
        for i in range(250):
            pkt = create_valid_packet(sequence_number=i + 1)
            engine.broadcast_packet(pkt)
        assert rt.read_word("%R2023") == 2  # 250 // 100 = 2

    def test_safe_write_helpers(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2024", -1)
        assert rt.read_word("%R2024") == -1
        safe_write_uword(rt, "%R2027", 0xEB01)
        assert rt.read_uword("%R2027") == 0xEB01
        safe_write_bit(rt, "%M471", True)
        assert rt.read_bit("%M471") is True


TestSection10RegisterTableSynchronization = TestHornerOCSSynchronizationAndRegisters


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU Validation
# ============================================================================

class TestSection11PureStructuredTextPouValidation:
    """Validate pure IEC 61131-3 ST POU compliance."""

    def test_pure_st_pou_syntax_and_ast_structure(self) -> None:
        res = STParser.validate_code(CIP_SAFETY_MULTICAST_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_pure_st_ast_program_type_and_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_MULTICAST_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2020", "%R2021", "%R2022", "%R2023",
            "%R2024", "%R2025", "%R2026", "%R2027",
            "%M471", "%M472",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_pure_st_guard_assertion(self) -> None:
        assert verify_cip_safety_multicast_pure_st() is True

    def test_pure_st_pou_constants_match(self) -> None:
        assert CIP_SAFETY_MULTICAST_POU == CIP_SAFETY_MULTICAST_SYNC_POU
        assert CipSafetyMulticastSync == CIP_SAFETY_MULTICAST_SYNC_POU


# ============================================================================
# Section 12: Anti-Ladder Security Guard Interception
# ============================================================================

class TestSection12AntiLadderSecurityGuardInterception:
    """Validate anti-ladder fail-closed security interception."""

    def test_reject_normally_open_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR a: BOOL; END_VAR\n|---[ ]---|")

    def test_reject_normally_closed_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR a: BOOL; END_VAR\n|---[/]---|")

    def test_reject_coil_construct(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("VAR a: BOOL; END_VAR\n|---( )---|")

    def test_reject_rung_delimiter(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: XIC(In) OTE(Out);")

    def test_reject_network_delimiter(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 1\nLD In\nST Out")

    def test_reject_ladder_mnemonic_xic(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC(StartPB)")

    def test_reject_ladder_mnemonic_ote(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("OTE(MotorRun)")


# ============================================================================
# Section 13: ILogicUnit Compliance & Scan Cycle Simulation
# ============================================================================

class TestSection13ILogicUnitCompliance:
    """Validate ILogicUnit protocol compliance and scan cycle behavior."""

    def test_ilogic_unit_interface_properties(self) -> None:
        engine = CipSafetyMulticastEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CipSafetyMulticastSync"
        assert engine.priority == 95
        assert engine.is_enabled is True

    def test_ilogic_unit_execute_method(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyMulticastEngine(register_table=rt)
        ctx = ScanContext(cycle=1, dt=0.010, register_table=rt)
        engine.execute(ctx)
        assert engine.execution_count == 1

    def test_step_method_convenience(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.step(0.010)
        assert engine.execution_count == 1

    def test_disabled_engine_skips_execution(self) -> None:
        engine = CipSafetyMulticastEngine(auto_activate=False)
        assert engine.is_enabled is False
        engine.scan_step(0.010)
        assert engine.execution_count == 0


# ============================================================================
# Section 14: 100-Cycle Soak Simulation & Bounded Execution
# ============================================================================

class TestSection14SoakSimulation100Cycles:
    """Validate 100-cycle continuous simulation soak stability."""

    def test_soak_100_cycles_stability(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyMulticastEngine(register_table=rt, auto_activate=True)
        for cycle in range(1, 101):
            now_ms = cycle * 10.0
            pkt = create_valid_packet(sequence_number=cycle, timestamp_ms=now_ms)
            engine.broadcast_packet(pkt)
            for c_idx in range(4):
                engine.acknowledge_packet(c_idx, ack_sequence=cycle)
            engine.scan_step(0.010)

        assert engine.execution_count == 100
        assert engine.total_broadcast_packets == 100
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.MULTICAST_OK
        assert rt.read_word("%R2020") == 4
        assert rt.read_word("%R2021") == 9985
        assert rt.read_word("%R2024") == -1
        assert rt.read_uword("%R2027") == 0x0000
        assert rt.read_bit("%M471") is True
        assert rt.read_bit("%M472") is False


# ============================================================================
# Section 15: Operator Reset & Safe State Recovery
# ============================================================================

class TestSection15OperatorResetAndSafeStateRecovery:
    """Validate engine recovery and reset from fault states."""

    def test_reset_restores_nominal_from_fault(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyMulticastEngine(register_table=rt, auto_activate=True)
        engine.trip_fault(DiagnosticCode.CONSUMER_ACK_DESYNC, consumer_index=2)
        assert engine.is_fault_active is True
        assert rt.read_bit("%M472") is True

        engine.reset()
        assert engine.is_fault_active is False
        assert engine.is_active is True
        assert engine.diagnostic_code == DiagnosticCode.MULTICAST_OK
        assert engine.active_desync_consumer_index == -1
        assert engine.multicast_health_index_scaled == 9985
        assert rt.read_bit("%M471") is True
        assert rt.read_bit("%M472") is False
        assert rt.read_word("%R2024") == -1
        assert rt.read_uword("%R2027") == 0x0000

    def test_reset_reloads_all_consumer_watchdogs(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.consumers[0].silence_time_ms = 25.0
        engine.consumers[0].watchdog_timer_ms = 5.0
        engine.reset()
        assert engine.consumers[0].silence_time_ms == 0.0
        assert engine.consumers[0].watchdog_timer_ms == engine.consumers[0].watchdog_timeout_ms


# ============================================================================
# Section 16: Verification Runner & Strict 4-State Engineering Contract
# ============================================================================

class TestSection16VerificationRunnerContract:
    """Validate verification runner returns strict 4-state contract."""

    def test_run_verification_returns_strict_contract(self) -> None:
        res = run_cip_safety_multicast_verification(work_package="W241")
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9
        assert res["passed_stages"] == 9
        assert "stages" in res["data"]
        assert len(res["data"]["stages"]) == 9
        for stage in res["data"]["stages"]:
            assert stage["passed"] is True

    def test_run_verification_emits_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_multicast_evidence.json"
        res = run_cip_safety_multicast_verification(output_path=out_file)
        assert out_file.exists()
        loaded = json.loads(out_file.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
        assert loaded["stages_passed"] == 9


# ============================================================================
# Section 17: Additional Consumer Scenarios & Security Guard Safety
# ============================================================================

class TestSection17AdditionalScenariosAndGuardSafety:
    """Validate status bits, consumer lookup, packet serializing, and hardware guards."""

    def test_status_bitmask_individual_consumer_active_bits(self) -> None:
        engine = CipSafetyMulticastEngine()
        mask = engine.status_bitmask
        assert mask & MulticastTopologyStatusBits.MULTICAST_ACTIVE
        assert mask & MulticastTopologyStatusBits.CONSUMER_0_ACTIVE
        assert mask & MulticastTopologyStatusBits.CONSUMER_1_ACTIVE
        assert mask & MulticastTopologyStatusBits.CONSUMER_2_ACTIVE
        assert mask & MulticastTopologyStatusBits.CONSUMER_3_ACTIVE
        assert mask & MulticastTopologyStatusBits.ALL_CONSUMERS_HEALTHY
        assert mask & MulticastTopologyStatusBits.DUAL_CHANNEL_VERIFIED
        assert mask & MulticastTopologyStatusBits.CRC_VERIFIED
        assert mask & MulticastTopologyStatusBits.MULTICAST_GROUP_VALID
        assert mask & MulticastTopologyStatusBits.CONSUMER_SYNC_OK

    def test_status_bitmask_degraded_when_consumer_disconnected(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.disconnect_consumer(2)  # disconnect Gantry Crane
        mask = engine.status_bitmask
        assert not (mask & MulticastTopologyStatusBits.CONSUMER_2_ACTIVE)
        assert not (mask & MulticastTopologyStatusBits.ALL_CONSUMERS_HEALTHY)
        assert mask & MulticastTopologyStatusBits.CONSUMER_DROPOUT_LATCH

    def test_status_bitmask_crc_fault_latch(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.trip_fault(DiagnosticCode.CRC_S_FAULT, consumer_index=0)
        mask = engine.status_bitmask
        assert mask & MulticastTopologyStatusBits.CRC_FAULT_LATCH
        assert not (mask & MulticastTopologyStatusBits.CRC_VERIFIED)

    def test_status_bitmask_discrepancy_latch(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.trip_fault(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, consumer_index=1)
        mask = engine.status_bitmask
        assert mask & MulticastTopologyStatusBits.DISCREPANCY_LATCH
        assert not (mask & MulticastTopologyStatusBits.DUAL_CHANNEL_VERIFIED)

    def test_status_bitmask_desync_latch(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.trip_fault(DiagnosticCode.CONSUMER_ACK_DESYNC, consumer_index=3)
        mask = engine.status_bitmask
        assert mask & MulticastTopologyStatusBits.CONSUMER_DESYNC_LATCH
        assert not (mask & MulticastTopologyStatusBits.CONSUMER_SYNC_OK)

    def test_packet_compute_s1_and_s2_bytes(self) -> None:
        pkt = create_valid_packet(sequence_number=1)
        b1 = pkt.compute_s1_bytes()
        b2 = pkt.compute_s2_bytes()
        assert len(b1) == len(DEFAULT_SNN) + 9 + len(pkt.channel_a_payload)
        assert len(b2) == len(DEFAULT_SNN) + 9 + len(pkt.channel_b_payload)

    def test_engine_registered_consumers_property(self) -> None:
        engine = CipSafetyMulticastEngine()
        reg_consumers = engine.registered_consumers
        assert len(reg_consumers) == 4
        assert 0 in reg_consumers
        assert 1 in reg_consumers
        assert 2 in reg_consumers
        assert 3 in reg_consumers
        assert reg_consumers[0].consumer_index == 0

    def test_engine_get_consumer_by_id_and_index(self) -> None:
        engine = CipSafetyMulticastEngine()
        c0 = engine.get_consumer(1)  # 1-based id 1 -> consumer 0
        assert c0 is not None
        assert c0.consumer_index == 0

        c_invalid = engine.get_consumer(99)
        assert c_invalid is None

    def test_engine_register_consumer_update_and_add(self) -> None:
        engine = CipSafetyMulticastEngine()
        updated = engine.register_consumer(1, description="Updated description")
        assert updated.description == "Updated description"

    def test_hardware_lockout_guard_safety(self) -> None:
        for port in ["COM1", "COM3", "\\\\.\\COM10", "/dev/ttyS0", "CAN0", "USB1", "JTAG_PROBE"]:
            with pytest.raises(Exception):
                SecurityGuard.assert_port_safe(port)

    def test_binary_lockout_guard_safety(self) -> None:
        for bin_name in ["pgmupdateutility.exe", "dfusecommand.exe", "stmflashloader.exe", "winjtag.exe"]:
            with pytest.raises(Exception):
                SecurityGuard.assert_binary_execution_safe(bin_name)

    def test_cli_switches_lockout_guard_safety(self) -> None:
        for switch in ["/d", "/download", "/flash", "/burn", "/write-flash"]:
            with pytest.raises(Exception):
                SecurityGuard.assert_cli_switches_safe([switch])

    def test_win32_command_lockout_guard_safety(self) -> None:
        for cmd_id in [32827, 33149]:
            with pytest.raises(Exception):
                SecurityGuard.assert_win32_command_safe(cmd_id)


# ============================================================================
# Section 18: Exception Hierarchy & Diagnostic Code Hash / Int Semantics
# ============================================================================

class TestSection18ExceptionHierarchyAndDiagnostics:
    """Validate exception inheritance and diagnostic code hash / dictionary semantics."""

    def test_exception_inheritance(self) -> None:
        assert issubclass(CipSafetyCrcFaultError, CipSafetyMulticastError)
        assert issubclass(CipSafetyEpiTimeoutError, CipSafetyMulticastError)
        assert issubclass(CipSafetyDiscrepancyError, CipSafetyMulticastError)
        assert issubclass(CipSafetyConsumerDesyncError, CipSafetyMulticastError)
        assert issubclass(CipSafetyConsumerDropoutError, CipSafetyMulticastError)
        assert issubclass(CipSafetyMulticastGroupError, CipSafetyMulticastError)

    def test_diagnostic_code_hash_and_dict_keys(self) -> None:
        mapping = {
            DiagnosticCode.MULTICAST_OK: "Nominal",
            DiagnosticCode.CRC_S_FAULT: "CRC Fault",
            DiagnosticCode.EPI_WATCHDOG_TIMEOUT: "Watchdog Timeout",
        }
        assert mapping[DiagnosticCode(0x0000)] == "Nominal"
        assert mapping[DiagnosticCode(0xEB01)] == "CRC Fault"
        assert mapping[DiagnosticCode(0xEB02)] == "Watchdog Timeout"

    def test_diagnostic_code_signed_matching_all(self) -> None:
        assert DiagnosticCode.MULTICAST_OK == 0
        assert DiagnosticCode.CRC_S_FAULT == -5375
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == -5374
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == -5373
        assert DiagnosticCode.CONSUMER_ACK_DESYNC == -5372
        assert DiagnosticCode.CONSUMER_NODE_DROPOUT == -5371
        assert DiagnosticCode.MULTICAST_GROUP_CORRUPTED == -5370

    def test_diagnostic_code_bitwise_and_masking(self) -> None:
        assert (DiagnosticCode.CRC_S_FAULT & 0xFFFF) == 0xEB01
        assert (0xFFFF & DiagnosticCode.CRC_S_FAULT) == 0xEB01
        assert (DiagnosticCode.EPI_WATCHDOG_TIMEOUT & 0x00FF) == 0x02

    def test_diagnostic_code_string_and_repr(self) -> None:
        c = DiagnosticCode.CONSUMER_ACK_DESYNC
        assert "0xEB04" in str(c)
        assert "CONSUMER_ACK_DESYNC" in repr(c)


# ============================================================================
# Section 19: Multicast Group, Timing & Sequence Edge Cases
# ============================================================================

class TestSection19EdgeCasesAndAdvancedScenarios:
    """Validate sequence wrapping, SNN edge cases, SCID/TUNID comparison, and timing."""

    def test_snn_invalid_inputs(self) -> None:
        assert validate_snn(bytes([0, 0, 0, 0, 0, 0])) is False
        assert validate_snn(bytes([0x12, 0x34])) is False
        assert validate_snn("not_bytes") is False  # type: ignore
        with pytest.raises(ValueError):
            format_snn(bytes([0x12, 0x34]))
        with pytest.raises(ValueError):
            parse_snn("invalid_hex")

    def test_scid_matching_inequality(self) -> None:
        scid1 = SafetyConfigurationIdentifier(crc=0x1111, timestamp=0x2222)
        scid2 = SafetyConfigurationIdentifier(crc=0x1111, timestamp=0x3333)
        assert scid1.matches(scid2) is False

    def test_tunid_and_ounid_matching_inequality(self) -> None:
        snn = SafetyNetworkNumber(DEFAULT_SNN)
        t1 = TargetUniqueNetworkId(snn=snn, target_node_id=20)
        t2 = TargetUniqueNetworkId(snn=snn, target_node_id=21)
        assert t1.matches(t2) is False

        o1 = OriginatorUniqueNetworkId(snn=snn, originator_node_id=100)
        o2 = OriginatorUniqueNetworkId(snn=snn, originator_node_id=101)
        assert o1.matches(o2) is False

    def test_producer_sequence_number_wrapping(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.producer_sequence_number = 65535
        pkt = engine.produce_and_broadcast()
        assert engine.producer_sequence_number == 1
        assert pkt.sequence_number == 1

    def test_reconnect_consumer_resets_silence(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.consumers[1].silence_time_ms = 28.0
        engine.disconnect_consumer(1)
        assert engine.consumers[1].is_connected is False
        engine.reconnect_consumer(1)
        assert engine.consumers[1].is_connected is True
        assert engine.consumers[1].silence_time_ms == 0.0

    def test_trip_convenience_alias(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.trip(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY)
        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert engine.is_fault_active is True

    def test_watchdog_exact_trip_boundary(self) -> None:
        engine = CipSafetyMulticastEngine()
        # 29 ms silence: should NOT trip
        engine.scan_step(0.029)
        assert engine.is_fault_active is False
        # Additional 2 ms = 31 ms total > 30 ms: should trip!
        engine.scan_step(0.002)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT

    def test_multiple_consumer_dropout_sequence(self) -> None:
        engine = CipSafetyMulticastEngine()
        engine.disconnect_consumer(0)
        assert engine.active_desync_consumer_index == 0
        assert engine.active_consumers_count == 3
        engine.disconnect_consumer(1)
        assert engine.active_consumers_count == 2
        engine.reset()
        assert engine.active_consumers_count == 4
        assert engine.active_desync_consumer_index == -1

    def test_diversified_mode_identical_payload(self) -> None:
        ch_a = bytes([0x12, 0x34])
        ch_b = bytes([0x12, 0x34])
        assert verify_dual_channel_payload(ch_a, ch_b, mode=DiversifiedMode.IDENTICAL) is True

    def test_pure_st_pou_program_name(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_MULTICAST_SYNC_POU)
        assert ast.name == "CipSafetyMulticastSync"

    def test_verification_runner_stage_details_format(self) -> None:
        res = run_cip_safety_multicast_verification()
        for st in res["data"]["stages"]:
            assert "stage" in st
            assert "name" in st
            assert "passed" in st
            assert "timing_ms" in st
            assert "details" in st

