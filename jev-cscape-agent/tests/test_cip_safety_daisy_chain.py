"""Comprehensive Unit Test Suite for Wave W232 CIP Safety Dual-Port Daisy-Chain Engine.

Work Package: W232 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 115+ Comprehensive Unit Tests across 16 Sections:
1. Section 1: Protocol Constants, Identifiers, Enums, & Diagnostic Codes (signed/unsigned & 0xFFFF).
2. Section 2: SNN Format, SCID, TUNID, & OUNID Configuration & Parsing.
3. Section 3: Dual-Channel Payload Parity & CRC-S Checksums.
4. Section 4: CIP Safety Daisy-Chain Packet Serialization, Deserialization, & Integrity.
5. Section 5: Topology State Machine (DISCONNECTED -> PORT1_ONLY / PORT2_ONLY -> DUAL_PORT_BRIDGED -> FAULT_SAFE_STATE).
6. Section 6: Upstream and Downstream Packet Forwarding and Counter Tracking (%R1931, %R1932).
7. Section 7: Expected Packet Interval (EPI) Watchdogs & Timeout Tripping (0xE902).
8. Section 8: Forwarding Jitter Monitoring & Overrun Fault (0xE906).
9. Section 9: Dual-Channel Discrepancy Fault (0xE903).
10. Section 10: Safety Network Number (SNN) & SCID Mismatch Fault (0xE901).
11. Section 11: CRC-S Checksum Corruption Fault (0xE904).
12. Section 12: Daisy-Chain Link Break Handling & Fault (0xE905).
13. Section 13: Horner OCS Register Synchronization (%R1930..%R1937, %M450..%M451 with SYSTEM privilege).
14. Section 14: Pure ST POU Validation & Anti-Ladder Security Guard Interception.
15. Section 15: ILogicUnit Interface Compliance & Scan Cycle Simulation.
16. Section 16: Safe State Coordination, Recovery, & Verification Runner (Strict 4-State Contract).
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
from jev_cscape.telemetry.cip_safety_daisy_chain import (
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_DAISY_CHAIN_CLASS_ID,
    CIP_SAFETY_DAISY_CHAIN_CONNECTION_CLASS_ID,
    CIP_SAFETY_DAISY_CHAIN_POU,
    CIP_SAFETY_DAISY_CHAIN_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_DAISY_CHAIN_SYNC_POU,
    CIP_SAFETY_DAISY_CHAIN_VALIDATOR_CLASS_ID,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyDaisyChainEngine,
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
    DIAG_CRC_S_CORRUPTION,
    DIAG_DAISY_CHAIN_LINK_BREAK,
    DIAG_DUAL_CHANNEL_DISCREPANCY,
    DIAG_EPI_TIMEOUT,
    DIAG_EPI_WATCHDOG_TIMEOUT,
    DIAG_FORWARDING_JITTER_OVERRUN,
    DIAG_JITTER_OVERRUN,
    DIAG_LINK_BREAK,
    DIAG_OK,
    DIAG_SNN_MISMATCH,
    DIAG_SNN_SIGNATURE_MISMATCH,
    EPI_WATCHDOG_TIMEOUT_MS,
    FORWARDING_JITTER_THRESHOLD_US,
    MAX_ALLOWABLE_JITTER_US,
    NOMINAL_EPI_MS,
    NOMINAL_FORWARDING_LATENCY_US,
    PORT1_INGRESS,
    PORT2_EGRESS,
    PURE_ST_POU,
    WATCHDOG_MULTIPLIER,
    CipSafetyControlByte,
    CipSafetyCrcCorruptionError,
    CipSafetyDaisyChain,
    CipSafetyDaisyChainDiagnosticCode,
    CipSafetyDaisyChainEngine,
    CipSafetyDaisyChainError,
    CipSafetyDaisyChainLinkBreakError,
    CipSafetyDaisyChainPacket,
    CipSafetyDaisyChainState,
    CipSafetyDiagnosticCode,
    CipSafetyDualChannelDiscrepancyError,
    CipSafetyDualPortEngine,
    CipSafetyEpiTimeoutError,
    CipSafetyForwardingJitterOverrunError,
    CipSafetyPacket,
    CipSafetySnnMismatchError,
    DaisyChainDiagnosticCode,
    DaisyChainPort,
    DaisyChainSafetyEngine,
    DaisyChainStatusBits,
    DaisyChainTopologyState,
    DiagnosticCode,
    DiagnosticStatusCode,
    DiversifiedMode,
    DualPortSafetyConnection,
    DualPortSafetyEngine,
    ForwardingDirection,
    PortId,
    PortIdentifier,
    SafetyConfigurationIdentifier,
    SafetyControlByte,
    SafetyNetworkNumber,
    TargetUniqueNetworkId,
    OriginatorUniqueNetworkId,
    SafetySupervisorObject,
    SafetyValidatorObject,
    TopologyState,
    calc_crc_s1,
    calc_crc_s2,
    calculate_crc16_ccitt,
    compute_crc_s1,
    compute_crc_s2,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_daisy_chain_verification,
    scale_jitter_us_to_int16,
    validate_snn,
    verify_cip_safety_daisy_chain_pure_st,
    verify_dual_channel_payload,
)


# ============================================================================
# Section 1: Protocol Constants, Identifiers, Enums & Diagnostic Codes
# ============================================================================

class TestSection1ProtocolConstantsAndDiagnosticCodes:
    """Validate CIP Safety dual-port daisy chain constants, classes, and DiagnosticCode."""

    def test_odva_object_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_DAISY_CHAIN_CLASS_ID == 0x3B
        assert CIP_SAFETY_DAISY_CHAIN_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_DAISY_CHAIN_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_DAISY_CHAIN_CONNECTION_CLASS_ID == 0x3B

    def test_port_identifiers(self) -> None:
        assert PORT1_INGRESS == 1
        assert PORT2_EGRESS == 2
        assert PortIdentifier.PORT1 == 1
        assert PortIdentifier.PORT2 == 2
        assert PortIdentifier.UPSTREAM == 1
        assert PortIdentifier.DOWNSTREAM == 2
        assert PortId.PORT1 == 1
        assert PortId.PORT2 == 2

    def test_timing_constants(self) -> None:
        assert NOMINAL_EPI_MS == 10.0
        assert DEFAULT_EPI_MS == 10.0
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 30.0
        assert EPI_WATCHDOG_TIMEOUT_MS == 30.0
        assert NOMINAL_FORWARDING_LATENCY_US == 850.0
        assert MAX_ALLOWABLE_JITTER_US == 2000.0
        assert FORWARDING_JITTER_THRESHOLD_US == 2000.0

    def test_diagnostic_code_values(self) -> None:
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.SNN_SIGNATURE_MISMATCH == 0xE901
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xE902
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == 0xE903
        assert DiagnosticCode.CRC_S_CORRUPTION == 0xE904
        assert DiagnosticCode.DAISY_CHAIN_LINK_BREAK == 0xE905
        assert DiagnosticCode.FORWARDING_JITTER_OVERRUN == 0xE906

    def test_diagnostic_code_signed_equality(self) -> None:
        # 0xE901 = 59649 unsigned -> -5887 signed 16-bit
        assert DiagnosticCode.SNN_SIGNATURE_MISMATCH == -5887
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == -5886
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == -5885
        assert DiagnosticCode.CRC_S_CORRUPTION == -5884
        assert DiagnosticCode.DAISY_CHAIN_LINK_BREAK == -5883
        assert DiagnosticCode.FORWARDING_JITTER_OVERRUN == -5882

    def test_diagnostic_code_masking_and_bitwise(self) -> None:
        assert (DiagnosticCode.SNN_SIGNATURE_MISMATCH & 0xFFFF) == 0xE901
        assert (0xFFFF & DiagnosticCode.EPI_WATCHDOG_TIMEOUT) == 0xE902
        assert (DiagnosticCode.DUAL_CHANNEL_DISCREPANCY & 0xFFFF) == 0xE903
        assert (DiagnosticCode.CRC_S_CORRUPTION & 0xFFFF) == 0xE904
        assert (DiagnosticCode.DAISY_CHAIN_LINK_BREAK & 0xFFFF) == 0xE905
        assert (DiagnosticCode.FORWARDING_JITTER_OVERRUN & 0xFFFF) == 0xE906

    def test_diagnostic_code_aliases(self) -> None:
        assert DIAG_OK == DiagnosticCode.OK
        assert DIAG_SNN_MISMATCH == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert DIAG_SNN_SIGNATURE_MISMATCH == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert DIAG_EPI_WATCHDOG_TIMEOUT == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DIAG_EPI_TIMEOUT == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DIAG_DUAL_CHANNEL_DISCREPANCY == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert DIAG_CRC_S_CORRUPTION == DiagnosticCode.CRC_S_CORRUPTION
        assert DIAG_DAISY_CHAIN_LINK_BREAK == DiagnosticCode.DAISY_CHAIN_LINK_BREAK
        assert DIAG_LINK_BREAK == DiagnosticCode.DAISY_CHAIN_LINK_BREAK
        assert DIAG_FORWARDING_JITTER_OVERRUN == DiagnosticCode.FORWARDING_JITTER_OVERRUN
        assert DIAG_JITTER_OVERRUN == DiagnosticCode.FORWARDING_JITTER_OVERRUN

    def test_diagnostic_code_string_and_repr(self) -> None:
        rep = repr(DiagnosticCode.FORWARDING_JITTER_OVERRUN)
        assert "FORWARDING_JITTER_OVERRUN" in rep
        assert "E906" in rep
        s = str(DiagnosticCode.DAISY_CHAIN_LINK_BREAK)
        assert "0xE905" in s

    def test_topology_state_enum(self) -> None:
        assert DaisyChainTopologyState.DISCONNECTED == 0
        assert DaisyChainTopologyState.PORT1_ONLY == 1
        assert DaisyChainTopologyState.PORT2_ONLY == 2
        assert DaisyChainTopologyState.DUAL_PORT_BRIDGED == 3
        assert DaisyChainTopologyState.FAULT_SAFE_STATE == 4
        assert TopologyState.BRIDGED == 3
        assert CipSafetyDaisyChainState.OPERATIONAL == 3


# ============================================================================
# Section 2: SNN Format, SCID, TUNID, & OUNID Configuration & Parsing
# ============================================================================

class TestSection2SnnScidTunidOunid:
    """Validate SNN generation, parsing, validation, and SCID/TUNID models."""

    def test_default_snn_length(self) -> None:
        assert len(DEFAULT_SNN) == 6

    def test_generate_and_format_snn(self) -> None:
        snn = generate_snn(0x2026, 0x1006DD88)
        assert len(snn) == 6
        formatted = format_snn(snn)
        assert formatted == "2026-1006DD88"

    def test_parse_snn(self) -> None:
        raw = parse_snn("2026-1006DD88")
        assert raw == bytes([0x20, 0x26, 0x10, 0x06, 0xDD, 0x88])

    def test_parse_snn_invalid(self) -> None:
        with pytest.raises(ValueError):
            parse_snn("12345")

    def test_validate_snn_clean_and_dirty(self) -> None:
        assert validate_snn(DEFAULT_SNN) is True
        assert validate_snn(b"\x00" * 6) is False
        assert validate_snn(b"\xFF" * 6) is False
        assert validate_snn(b"\x00\x00\x11\x22\x33\x44") is False
        assert validate_snn("2026-1006DD88") is True
        assert validate_snn(12345) is False

    def test_safety_network_number_class(self) -> None:
        snn_obj = SafetyNetworkNumber(DEFAULT_SNN, crc_id=0x0001)
        assert len(snn_obj.raw_bytes) == 8
        assert snn_obj.to_hex() == "20261006DD880001"

    def test_scid_matching(self) -> None:
        scid1 = SafetyConfigurationIdentifier(0x12345678, 0x9ABCDEF0)
        scid2 = SafetyConfigurationIdentifier(0x12345678, 0x9ABCDEF0)
        scid3 = SafetyConfigurationIdentifier(0x12345678, 0x9ABCDEF1)
        assert scid1.matches(scid2) is True
        assert scid1.matches(scid3) is False
        assert len(scid1.to_bytes()) == 8


# ============================================================================
# Section 3: Dual-Channel Payload Parity & CRC-S Checksums
# ============================================================================

class TestSection3DualChannelPayloadAndCrc:
    """Validate dual-channel payload parity and CRC-S1 / CRC-S2 calculations."""

    def test_crc16_ccitt_deterministic(self) -> None:
        data = b"CIP_SAFETY_TEST"
        crc1 = calculate_crc16_ccitt(data)
        assert isinstance(crc1, int)
        assert 0 <= crc1 <= 0xFFFF
        assert compute_crc_s1(data) == crc1

    def test_compute_crc_s2_inverted(self) -> None:
        data = b"CIP_SAFETY_TEST"
        c1 = compute_crc_s1(data)
        c2 = compute_crc_s2(data, inverted=True)
        assert c2 == ((~c1) & 0xFFFF)

    def test_compute_crc_s2_timestamp_seq_signature(self) -> None:
        ts = 1000
        seq = 1
        payload = b"\x01\x02\x03\x04"
        crc = calc_crc_s2(ts, seq, payload)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

    def test_verify_dual_channel_inverted_mode(self) -> None:
        ch_a = bytes([0xAA, 0x55, 0x00, 0xFF])
        ch_b_inv = bytes([0x55, 0xAA, 0xFF, 0x00])
        ch_b_bad = bytes([0x55, 0xAA, 0xFF, 0x01])
        assert verify_dual_channel_payload(ch_a, ch_b_inv, mode=DiversifiedMode.INVERTED) is True
        assert verify_dual_channel_payload(ch_a, ch_b_bad, mode=DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_identical_mode(self) -> None:
        ch_a = bytes([0x01, 0x02])
        ch_b = bytes([0x01, 0x02])
        assert verify_dual_channel_payload(ch_a, ch_b, mode=DiversifiedMode.IDENTICAL) is True

    def test_verify_dual_channel_int_values(self) -> None:
        assert verify_dual_channel_payload(0x1234, (~0x1234) & 0xFFFF, mode=DiversifiedMode.INVERTED) is True
        assert verify_dual_channel_payload(0x1234, 0x1234, mode=DiversifiedMode.IDENTICAL) is True


# ============================================================================
# Section 4: Packet Serialization, Deserialization & Integrity
# ============================================================================

class TestSection4PacketSerializationAndDeserialization:
    """Validate CipSafetyDaisyChainPacket serialization and deserialization."""

    def test_packet_creation_and_crc_calculation(self) -> None:
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=5,
            timestamp_ms=10.0,
            channel_a_payload=b"\x12\x34",
            channel_b_payload=b"\xED\xCB",
        )
        c1, c2 = pkt.calculate_crcs()
        assert c1 != 0
        assert c2 != 0
        assert pkt.verify_crcs() is True
        assert pkt.verify_dual_channel() is True

    def test_packet_serialization_round_trip(self) -> None:
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=2,
            ounid=102,
            target_connection_id=1,
            sequence_number=42,
            timestamp_ms=125.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\xAA\xBB\xCC\xDD",
            channel_b_payload=b"\x55\x44\x33\x22",
        )
        pkt.calculate_crcs()
        raw = pkt.serialize()
        assert len(raw) > 20

        deser = CipSafetyDaisyChainPacket.deserialize(raw)
        assert deser.snn == DEFAULT_SNN
        assert deser.tunid == 2
        assert deser.ounid == 102
        assert deser.sequence_number == 42
        assert deser.channel_a_payload == b"\xAA\xBB\xCC\xDD"
        assert deser.channel_b_payload == b"\x55\x44\x33\x22"
        assert deser.crc_s1 == pkt.crc_s1
        assert deser.crc_s2 == pkt.crc_s2
        assert deser.verify_crcs() is True

    def test_deserialize_too_short_error(self) -> None:
        with pytest.raises(ValueError):
            CipSafetyDaisyChainPacket.deserialize(b"\x00\x01\x02")


# ============================================================================
# Section 5: Topology State Machine
# ============================================================================

class TestSection5TopologyStateMachine:
    """Validate DaisyChainTopologyState transitions across DISCONNECTED, PORT1, PORT2, BRIDGED, FAULT."""

    def test_initial_state_auto_activate(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        assert engine.topology_state == DaisyChainTopologyState.DUAL_PORT_BRIDGED
        assert engine.is_active is True
        assert engine.is_tripped is False

    def test_initial_state_not_auto_activated(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=False)
        assert engine.topology_state == DaisyChainTopologyState.DISCONNECTED
        assert engine.is_active is False
        assert engine.is_tripped is False

    def test_single_port_transitions(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=False, trip_on_link_break=False)
        engine.set_port_link_status(PORT1_INGRESS, True)
        assert engine.topology_state == DaisyChainTopologyState.PORT1_ONLY
        assert engine.is_active is False

        engine.set_port_link_status(PORT1_INGRESS, False)
        engine.set_port_link_status(PORT2_EGRESS, True)
        assert engine.topology_state == DaisyChainTopologyState.PORT2_ONLY
        assert engine.is_active is False

        engine.set_port_link_status(PORT1_INGRESS, True)
        assert engine.topology_state == DaisyChainTopologyState.DUAL_PORT_BRIDGED
        assert engine.is_active is True

    def test_manual_trip_transitions_to_fault_safe_state(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.trip(DiagnosticCode.DAISY_CHAIN_LINK_BREAK, "Manual trip")
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.is_active is False
        assert engine.is_tripped is True
        assert engine.diagnostic_code == DiagnosticCode.DAISY_CHAIN_LINK_BREAK


# ============================================================================
# Section 6: Upstream and Downstream Packet Forwarding and Counter Tracking
# ============================================================================

class TestSection6PacketForwardingAndCounterAccounting:
    """Validate store-and-forward routing between Port 1 and Port 2 and modulo 32767 counters."""

    def test_forward_downstream_increments_r1932(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x00\x10",
            channel_b_payload=b"\xFF\xEF",
        )
        pkt.calculate_crcs()

        fwd = engine.forward_downstream(pkt, forwarding_delay_us=850.0)
        assert fwd.ingress_port == PORT1_INGRESS
        assert fwd.egress_port == PORT2_EGRESS
        assert engine.downstream_packets_forwarded_count == 1
        assert engine.upstream_packets_forwarded_count == 0

    def test_forward_upstream_increments_r1931(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=100,
            ounid=1,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x00\x20",
            channel_b_payload=b"\xFF\xDF",
        )
        pkt.calculate_crcs()

        fwd = engine.forward_upstream(pkt, forwarding_delay_us=900.0)
        assert fwd.ingress_port == PORT2_EGRESS
        assert fwd.egress_port == PORT1_INGRESS
        assert engine.upstream_packets_forwarded_count == 1
        assert engine.downstream_packets_forwarded_count == 0

    def test_payload_mirroring_into_r1936(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        val = 1234
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=2,
            timestamp_ms=20.0,
            channel_a_payload=struct.pack(">h", val),
            channel_b_payload=struct.pack(">h", ~val),
        )
        pkt.calculate_crcs()
        engine.forward_downstream(pkt)
        assert engine.monitored_safety_payload_word == val

    def test_counter_modulo_32767(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.connection.downstream_forwarded_count = 32766
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=3,
            timestamp_ms=30.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        engine.forward_downstream(pkt)
        assert engine.downstream_packets_forwarded_count == 0


# ============================================================================
# Section 7: Expected Packet Interval (EPI) Watchdog Timeout (0xE902)
# ============================================================================

class TestSection7EpiWatchdogSurveillance:
    """Validate 3x EPI watchdog timeout detection and safe state tripping."""

    def test_silence_below_watchdog_timeout_remains_active(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.020)  # 20 ms < 30 ms
        assert engine.topology_state == DaisyChainTopologyState.DUAL_PORT_BRIDGED
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_active is True

    def test_silence_exceeding_watchdog_timeout_trips_0xE902(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.020)
        engine.scan_step(0.015)  # 35 ms total > 30 ms
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.is_tripped is True
        assert engine.is_active is False

    def test_packet_forwarding_refreshes_watchdog_timer(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(0.020)
        assert engine.connection.silence_elapsed_ms == 20.0

        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=20.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        engine.forward_downstream(pkt)
        assert engine.connection.silence_elapsed_ms == 0.0

        engine.scan_step(0.020)
        assert engine.topology_state == DaisyChainTopologyState.DUAL_PORT_BRIDGED
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_simulate_epi_watchdog_timeout_helper(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.simulate_epi_watchdog_timeout()
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE


# ============================================================================
# Section 8: Forwarding Jitter Monitoring & Overrun Fault (0xE906)
# ============================================================================

class TestSection8ForwardingJitterMonitoring:
    """Validate bridge forwarding latency tracking and 2000 us overrun fault (0xE906)."""

    def test_nominal_forwarding_jitter_accepted(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()

        engine.forward_downstream(pkt, forwarding_delay_us=850.0)
        assert engine.measured_jitter_us == 850.0
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_active is True

    def test_max_jitter_tracking(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()

        engine.forward_downstream(pkt, forwarding_delay_us=900.0)
        assert engine.max_jitter_us == 900.0

        engine.forward_downstream(pkt, forwarding_delay_us=1200.0)
        assert engine.max_jitter_us == 1200.0

        engine.forward_downstream(pkt, forwarding_delay_us=800.0)
        assert engine.max_jitter_us == 1200.0

    def test_forwarding_jitter_exceeding_2000us_trips_0xE906(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()

        with pytest.raises(CipSafetyForwardingJitterOverrunError):
            engine.forward_downstream(pkt, forwarding_delay_us=2001.0)

        assert engine.diagnostic_code == DiagnosticCode.FORWARDING_JITTER_OVERRUN
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.is_tripped is True
        assert engine.is_active is False

    def test_simulate_forwarding_jitter_overrun_helper(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.simulate_forwarding_jitter_overrun(2500.0)
        assert engine.diagnostic_code == DiagnosticCode.FORWARDING_JITTER_OVERRUN
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.measured_jitter_us == 2500.0


# ============================================================================
# Section 9: Dual-Channel Discrepancy Fault (0xE903)
# ============================================================================

class TestSection9DualChannelDiscrepancy:
    """Validate Channel A vs Channel B parity checking and 0xE903 trip."""

    def test_corrupted_channel_b_raises_and_trips_0xE903(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\x00",  # Bit flipped
        )
        pkt.calculate_crcs()

        with pytest.raises(CipSafetyDualChannelDiscrepancyError):
            engine.forward_downstream(pkt)

        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.is_tripped is True

    def test_simulate_dual_channel_discrepancy_helper(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.simulate_dual_channel_discrepancy()
        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE


# ============================================================================
# Section 10: Safety Network Number (SNN) & SCID Mismatch Fault (0xE901)
# ============================================================================

class TestSection10SnnSignatureMismatch:
    """Validate SNN authentication and 0xE901 trip."""

    def test_mismatched_snn_raises_and_trips_0xE901(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        bad_snn = bytes([0x99, 0x88, 0x77, 0x66, 0x55, 0x44])
        pkt = CipSafetyDaisyChainPacket(
            snn=bad_snn,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()

        with pytest.raises(CipSafetySnnMismatchError):
            engine.forward_downstream(pkt)

        assert engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.is_tripped is True

    def test_simulate_snn_mismatch_helper(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.simulate_snn_signature_mismatch()
        assert engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE


# ============================================================================
# Section 11: CRC-S Checksum Corruption Fault (0xE904)
# ============================================================================

class TestSection11CrcCorruptionFault:
    """Validate CRC-S1 and CRC-S2 corruption detection and 0xE904 trip."""

    def test_corrupted_crc_s1_raises_and_trips_0xE904(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        pkt.crc_s1 ^= 0x0001

        with pytest.raises(CipSafetyCrcCorruptionError):
            engine.forward_downstream(pkt)

        assert engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.is_tripped is True

    def test_corrupted_crc_s2_raises_and_trips_0xE904(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        pkt.crc_s2 ^= 0x0002

        with pytest.raises(CipSafetyCrcCorruptionError):
            engine.forward_downstream(pkt)

        assert engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE

    def test_simulate_crc_s_corruption_helper(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.simulate_crc_s_corruption()
        assert engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE


# ============================================================================
# Section 12: Daisy-Chain Link Break Handling & Fault (0xE905)
# ============================================================================

class TestSection12DaisyChainLinkBreakHandling:
    """Validate Port 1 / Port 2 physical link drop detection and 0xE905 trip."""

    def test_link_drop_on_port1_trips_0xE905(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, trip_on_link_break=True)
        engine.set_port_link_status(PORT1_INGRESS, False)
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.diagnostic_code == DiagnosticCode.DAISY_CHAIN_LINK_BREAK
        assert engine.is_tripped is True
        assert engine.is_active is False

    def test_link_drop_on_port2_trips_0xE905(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, trip_on_link_break=True)
        engine.set_port_link_status(PORT2_EGRESS, False)
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE
        assert engine.diagnostic_code == DiagnosticCode.DAISY_CHAIN_LINK_BREAK

    def test_forward_packet_with_egress_link_down_raises_and_trips(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, trip_on_link_break=False)
        engine.connection.port2.is_link_up = False
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=100,
            sequence_number=1,
            timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()

        with pytest.raises(CipSafetyDaisyChainLinkBreakError):
            engine.forward_downstream(pkt)

        assert engine.diagnostic_code == DiagnosticCode.DAISY_CHAIN_LINK_BREAK
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE

    def test_simulate_link_break_helper(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.simulate_daisy_chain_link_break(PORT1_INGRESS)
        assert engine.diagnostic_code == DiagnosticCode.DAISY_CHAIN_LINK_BREAK
        assert engine.topology_state == DaisyChainTopologyState.FAULT_SAFE_STATE


# ============================================================================
# Section 13: Horner OCS Register Synchronization (%R1930..%R1937, %M450..%M451)
# ============================================================================

class TestSection13RegisterSynchronization:
    """Validate mapping and scaling into %R1930..%R1937 and %M450..%M451."""

    def test_healthy_register_sync(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyDaisyChainEngine(register_table=rt, auto_activate=True)
        engine.connection.upstream_forwarded_count = 50
        engine.connection.downstream_forwarded_count = 100
        engine.connection.measured_jitter_us = 850.0
        engine.connection.max_jitter_us = 1450.0
        engine.connection.monitored_payload_word = 999
        engine.sync_to_registers(rt)

        assert rt.read_word("%R1930") == 3       # DUAL_PORT_BRIDGED
        assert rt.read_word("%R1931") == 50      # Upstream
        assert rt.read_word("%R1932") == 100     # Downstream
        assert rt.read_word("%R1933") == 850     # Measured Jitter
        assert rt.read_word("%R1934") == 1450    # Max Jitter
        assert rt.read_word("%R1935") == 0       # Consecutive Faults
        assert rt.read_word("%R1936") == 999     # Payload Word
        assert rt.read_uword("%R1937") == 0      # Diagnostic Code OK
        assert rt.read_bit("%M450") is True      # Bridge Active
        assert rt.read_bit("%M451") is False     # Trip Engaged

    def test_fault_register_sync_with_signed_unsigned(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyDaisyChainEngine(register_table=rt, auto_activate=True)
        engine.trip(DiagnosticCode.FORWARDING_JITTER_OVERRUN, "Jitter fault")
        engine.sync_to_registers(rt)

        assert rt.read_word("%R1930") == 4       # FAULT_SAFE_STATE
        assert rt.read_uword("%R1937") == 0xE906 # Unsigned 0xE906
        assert rt.read_word("%R1937") == -5882   # Signed 16-bit
        assert rt.read_bit("%M450") is False
        assert rt.read_bit("%M451") is True

    def test_scale_jitter_helper(self) -> None:
        assert scale_jitter_us_to_int16(850.4) == 850
        assert scale_jitter_us_to_int16(2500.0) == 2500


# ============================================================================
# Section 14: Pure IEC 61131-3 Structured Text POU Validation
# ============================================================================

class TestSection14PureSTPOUValidation:
    """Validate ST POU 'CipSafetyDaisyChainSync' and anti-ladder interception."""

    def test_pou_verification_function(self) -> None:
        assert verify_cip_safety_daisy_chain_pure_st() is True

    def test_security_guard_assert_pure_st_content(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_DAISY_CHAIN_SYNC_POU)

    def test_st_parser_validate_code_success(self) -> None:
        res = STParser.validate_code(CIP_SAFETY_DAISY_CHAIN_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_ast_program_type_and_registers(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_DAISY_CHAIN_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected = {
            "%R1930", "%R1931", "%R1932", "%R1933",
            "%R1934", "%R1935", "%R1936", "%R1937",
            "%M450", "%M451",
        }
        assert expected.issubset(set(ast.bound_registers))

    def test_anti_ladder_contacts_rejected(self) -> None:
        bad_ladder = "PROGRAM Test VAR END_VAR\n  ---[ ]---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_ladder)

    def test_anti_ladder_rungs_rejected(self) -> None:
        bad_ladder = "PROGRAM Test VAR END_VAR\n  RUNG 1\n  XIC Sw OTE Coil;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_ladder)

    def test_anti_ladder_network_prohibited(self) -> None:
        bad_ladder = "PROGRAM Test VAR END_VAR\n  NETWORK 1\n  |---| |---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_ladder)


# ============================================================================
# Section 15: ILogicUnit Compliance & Scan Cycle Simulation
# ============================================================================

class TestSection15ILogicUnitCompliance:
    """Validate ILogicUnit interface implementation and cyclic simulation."""

    def test_ilogicunit_inheritance(self) -> None:
        engine = CipSafetyDaisyChainEngine()
        assert isinstance(engine, ILogicUnit)

    def test_ilogicunit_properties(self) -> None:
        engine = CipSafetyDaisyChainEngine()
        assert engine.name == "CipSafetyDaisyChainEngine"
        assert engine.priority == 95
        assert engine.is_enabled is True

        engine.is_enabled = False
        assert engine.is_enabled is False

    def test_scan_step_with_context(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        engine.scan_step(0.010, context=ctx)
        assert engine.words_processed == 1

    def test_execute_method_calls_scan_step(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        engine.execute(ctx)
        assert engine.words_processed == 1

    def test_disabled_engine_skips_processing(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.is_enabled = False
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        engine.execute(ctx)
        assert engine.words_processed == 0

    def test_multi_cycle_cyclic_simulation(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyDaisyChainEngine(register_table=rt, auto_activate=True)
        for i in range(1, 101):
            ctx = ScanContext(cycle=i, dt_ms=10.0, elapsed_time_ms=float(i * 10))
            if i % 2 == 0:
                pkt = CipSafetyDaisyChainPacket(
                    snn=DEFAULT_SNN, tunid=1, ounid=100, sequence_number=i,
                    timestamp_ms=float(i * 10),
                    channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
                )
                pkt.calculate_crcs()
                engine.forward_downstream(pkt)
            engine.execute(ctx)

        assert engine.words_processed == 100
        assert engine.is_active is True
        assert rt.read_bit("%M450") is True
        assert rt.read_bit("%M451") is False


# ============================================================================
# Section 16: Safe State Coordination, Recovery, & Verification Runner
# ============================================================================

class TestSection16SafeStateCoordinationAndVerificationRunner:
    """Validate fault clearing, reset recovery, and deterministic 12-stage verification runner."""

    def test_reset_method_clears_faults_and_restores_bridged(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.trip(DiagnosticCode.DAISY_CHAIN_LINK_BREAK, "Test fault")
        assert engine.is_tripped is True

        engine.reset()
        assert engine.topology_state == DaisyChainTopologyState.DUAL_PORT_BRIDGED
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_active is True
        assert engine.is_tripped is False

    def test_reset_fault_returns_execution_result_success(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.trip(DiagnosticCode.CRC_S_CORRUPTION, "CRC fault")
        res = engine.reset_fault(force=True, restore_bridged=True)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.data["topology_state"] == 3
        assert res.data["diagnostic_code"] == 0

    def test_verification_runner_returns_strict_4_state_dict(self) -> None:
        res = run_cip_safety_daisy_chain_verification()
        assert isinstance(res, dict)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 12
        assert res["stages_passed"] == 12
        assert res["passed_stages"] == 12
        assert res["data"]["work_package"] == "W232"

    def test_verification_runner_all_stages_pass(self) -> None:
        res = run_cip_safety_daisy_chain_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 12
        for s in stages:
            assert s["passed"] is True, f"Stage {s['stage']} ({s['name']}) failed: {s['details']}"

    def test_verification_runner_writes_evidence_json(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_daisy_chain_evidence.json"
        res = run_cip_safety_daisy_chain_verification(output_path=out_file)
        assert out_file.exists()
        loaded = json.loads(out_file.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
        assert loaded["data"]["work_package"] == "W232"

    def test_cli_verification_script_execution(self) -> None:
        cmd = [sys.executable, "src/jev_cscape/telemetry/cip_safety_daisy_chain.py"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert data["status"] == "success"

    def test_receive_and_forward_alias(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            sequence_number=1, timestamp_ms=10.0,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        fwd = engine.receive_and_forward(pkt, ingress_port=PORT1_INGRESS)
        assert fwd.egress_port == PORT2_EGRESS
        assert engine.downstream_packets_forwarded_count == 1

    def test_verification_runner_stage_details_not_empty(self) -> None:
        res = run_cip_safety_daisy_chain_verification()
        for s in res["data"]["stages"]:
            assert len(s["details"]) > 0
            assert "check" in s

    def test_register_map_in_verification_output(self) -> None:
        res = run_cip_safety_daisy_chain_verification()
        reg_map = res["data"]["register_map"]
        assert "%R1930" in reg_map
        assert "%R1937" in reg_map
        assert "%M450" in reg_map
        assert "%M451" in reg_map


# ============================================================================
# Section 17: Deep Protocol Edge Cases & Boundary Conditions
# ============================================================================

class TestSection17DeepEdgeCasesAndBoundaries:
    """Validate boundary values, edge cases, and robustness across all subsystems."""

    def test_diagnostic_code_as_dictionary_key(self) -> None:
        d = {
            DiagnosticCode.OK: "healthy",
            DiagnosticCode.FORWARDING_JITTER_OVERRUN: "jitter_fault",
            DiagnosticCode.DAISY_CHAIN_LINK_BREAK: "link_break",
        }
        assert d[0x0000] == "healthy"
        assert d[0xE906] == "jitter_fault"
        assert d[DiagnosticCode(-5882)] == "jitter_fault"
        assert d[0xE905] == "link_break"
        assert d[DiagnosticCode(-5883)] == "link_break"

    def test_diagnostic_code_in_set(self) -> None:
        s = {DiagnosticCode.EPI_WATCHDOG_TIMEOUT, DiagnosticCode.CRC_S_CORRUPTION}
        assert 0xE902 in s
        assert DiagnosticCode(-5886) in s
        assert 0xE904 in s
        assert DiagnosticCode(-5884) in s
        assert 0x0000 not in s

    def test_status_bits_flags_combination(self) -> None:
        flags = DaisyChainStatusBits.DAISY_CHAIN_ACTIVE | DaisyChainStatusBits.PORT1_LINK_UP | DaisyChainStatusBits.PORT2_LINK_UP
        assert flags & DaisyChainStatusBits.DAISY_CHAIN_ACTIVE
        assert flags & DaisyChainStatusBits.PORT1_LINK_UP
        assert flags & DaisyChainStatusBits.PORT2_LINK_UP
        assert not (flags & DaisyChainStatusBits.FAULT_LATCHED)

    def test_control_byte_flags(self) -> None:
        ctrl = SafetyControlByte.RUN | SafetyControlByte.PING_REQ
        assert ctrl & SafetyControlByte.RUN
        assert ctrl & SafetyControlByte.PING_REQ
        assert not (ctrl & SafetyControlByte.DISCONNECT_REQ)

    def test_forwarding_direction_enum_values(self) -> None:
        assert ForwardingDirection.UPSTREAM_TO_DOWNSTREAM == 1
        assert ForwardingDirection.DOWNSTREAM_TO_UPSTREAM == 2
        assert ForwardingDirection.DOWNSTREAM == 1
        assert ForwardingDirection.UPSTREAM == 2

    def test_tunid_and_ounid_matching(self) -> None:
        snn1 = SafetyNetworkNumber(DEFAULT_SNN, 0x0001)
        tunid1 = TargetUniqueNetworkId(snn1, target_node_id=10)
        tunid2 = TargetUniqueNetworkId(snn1, target_node_id=10)
        tunid3 = TargetUniqueNetworkId(snn1, target_node_id=20)
        assert tunid1.matches(tunid2) is True
        assert tunid1.matches(tunid3) is False

        ounid1 = OriginatorUniqueNetworkId(snn1, originator_node_id=100)
        ounid2 = OriginatorUniqueNetworkId(snn1, originator_node_id=100)
        ounid3 = OriginatorUniqueNetworkId(snn1, originator_node_id=200)
        assert ounid1.matches(ounid2) is True
        assert ounid1.matches(ounid3) is False

    def test_snn_from_8_bytes(self) -> None:
        raw_8 = DEFAULT_SNN + struct.pack(">H", 0x0042)
        snn_obj = SafetyNetworkNumber.from_bytes(raw_8)
        assert snn_obj.timestamp_bytes == DEFAULT_SNN
        assert snn_obj.crc_id == 0x0042

    def test_snn_invalid_lengths(self) -> None:
        with pytest.raises(ValueError):
            SafetyNetworkNumber.from_bytes(b"\x01\x02\x03")
        with pytest.raises(ValueError):
            SafetyNetworkNumber(b"\x01\x02\x03\x04\x05")

    def test_crc16_different_data_returns_different_crc(self) -> None:
        c1 = compute_crc_s1(b"PacketA")
        c2 = compute_crc_s1(b"PacketB")
        assert c1 != c2

    def test_crc_s1_empty_data(self) -> None:
        c = compute_crc_s1(b"")
        assert c == CRC16_CCITT_INIT

    def test_verify_dual_channel_empty_and_mismatched_lengths(self) -> None:
        assert verify_dual_channel_payload(b"", b"") is True
        assert verify_dual_channel_payload(b"\x01", b"\x01\x02") is False

    def test_verify_dual_channel_bytearray(self) -> None:
        ba = bytearray([0x55, 0xAA])
        bb = bytearray([0xAA, 0x55])
        assert verify_dual_channel_payload(ba, bb, mode=DiversifiedMode.INVERTED) is True

    def test_packet_with_empty_payloads(self) -> None:
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"", channel_b_payload=b"",
        )
        c1, c2 = pkt.calculate_crcs()
        assert c1 != 0
        assert pkt.verify_crcs() is True

    def test_packet_crc_verification_failure_on_tamper(self) -> None:
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        pkt.channel_a_payload = b"\x01\x03"  # Tampered without recalculating
        assert pkt.verify_crcs() is False

    def test_packet_property_setters(self) -> None:
        pkt = CipSafetyDaisyChainPacket(snn=DEFAULT_SNN, tunid=1, connection_id=5)
        assert pkt.connection_id == 5
        pkt.connection_id = 10
        assert pkt.connection_id == 10

    def test_port_link_status_both_false_sets_disconnected(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, trip_on_link_break=False)
        engine.set_port_link_status(PORT1_INGRESS, False)
        engine.set_port_link_status(PORT2_EGRESS, False)
        assert engine.topology_state == DaisyChainTopologyState.DISCONNECTED

    def test_receive_safety_packet_without_forwarding(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"\x0A\x0B", channel_b_payload=b"\xF5\xF4",
        )
        pkt.calculate_crcs()
        engine.receive_safety_packet(pkt, ingress_port=PORT1_INGRESS)
        assert engine.port1.rx_packet_count == 1
        assert engine.downstream_packets_forwarded_count == 0  # Not forwarded

    def test_send_safety_packet_egress_port1(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = engine.send_safety_packet(
            payload_a=b"\x12\x34",
            egress_port=PORT1_INGRESS,
            sequence_number=10,
        )
        assert pkt.egress_port == PORT1_INGRESS
        assert pkt.sequence_number == 10
        assert engine.port1.tx_packet_count == 1
        assert pkt.verify_crcs() is True

    def test_send_safety_packet_egress_port2(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = engine.send_safety_packet(
            payload_a=b"\x56\x78",
            egress_port=PORT2_EGRESS,
            sequence_number=20,
        )
        assert pkt.egress_port == PORT2_EGRESS
        assert pkt.sequence_number == 20
        assert engine.port2.tx_packet_count == 1
        assert pkt.verify_crcs() is True

    def test_bidirectional_forwarding_stream(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        for i in range(1, 11):
            if i % 2 != 0:
                pkt = CipSafetyDaisyChainPacket(
                    snn=DEFAULT_SNN, tunid=1, ounid=100,
                    sequence_number=i, channel_a_payload=b"\x01\x02",
                    channel_b_payload=b"\xFE\xFD",
                )
                pkt.calculate_crcs()
                engine.forward_downstream(pkt)
            else:
                pkt = CipSafetyDaisyChainPacket(
                    snn=DEFAULT_SNN, tunid=100, ounid=1,
                    sequence_number=i, channel_a_payload=b"\x03\x04",
                    channel_b_payload=b"\xFC\xFB",
                )
                pkt.calculate_crcs()
                engine.forward_upstream(pkt)

        assert engine.downstream_packets_forwarded_count == 5
        assert engine.upstream_packets_forwarded_count == 5
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_payload_mirroring_single_byte(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"\x42", channel_b_payload=b"\xBD",
        )
        pkt.calculate_crcs()
        engine.forward_downstream(pkt)
        assert engine.monitored_safety_payload_word == 0x42

    def test_payload_mirroring_zero_byte(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"", channel_b_payload=b"",
        )
        pkt.calculate_crcs()
        engine.forward_downstream(pkt)
        assert engine.monitored_safety_payload_word == 0

    def test_custom_watchdog_timeout_ms(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, watchdog_timeout_ms=50.0)
        engine.scan_step(0.040)
        assert engine.is_active is True
        engine.scan_step(0.015)
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT

    def test_check_watchdog_returns_false_when_healthy(self) -> None:
        conn = DualPortSafetyConnection(watchdog_timeout_ms=30.0)
        assert conn.check_watchdog(10.0) is False
        assert conn.check_watchdog(10.0) is False
        assert conn.check_watchdog(15.0) is True

    def test_jitter_boundary_exactly_2000_does_not_trip(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        engine.forward_downstream(pkt, forwarding_delay_us=2000.0)
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.measured_jitter_us == 2000.0

    def test_jitter_boundary_2000_point_1_trips_fault(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetyForwardingJitterOverrunError):
            engine.forward_downstream(pkt, forwarding_delay_us=2000.1)
        assert engine.diagnostic_code == DiagnosticCode.FORWARDING_JITTER_OVERRUN

    def test_zero_jitter_handled_cleanly(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        engine.forward_downstream(pkt, forwarding_delay_us=0.0)
        assert engine.measured_jitter_us == 0.0
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_identical_mode_diversification(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=1, ounid=100,
            channel_a_payload=b"\x55\xAA", channel_b_payload=b"\x55\xAA",
        )
        pkt.calculate_crcs()
        fwd = engine.forward_packet(pkt, ingress_port=PORT1_INGRESS, diversified_mode=DiversifiedMode.IDENTICAL)
        assert fwd.egress_port == PORT2_EGRESS
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_dual_channel_discrepancy_on_upstream_forwarding(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=100, ounid=1,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\x00",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetyDualChannelDiscrepancyError):
            engine.forward_upstream(pkt)
        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY

    def test_snn_mismatch_on_upstream_forwarding(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=b"\x11\x22\x33\x44\x55\x66", tunid=100, ounid=1,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        with pytest.raises(CipSafetySnnMismatchError):
            engine.forward_upstream(pkt)
        assert engine.diagnostic_code == DiagnosticCode.SNN_SIGNATURE_MISMATCH

    def test_crc_corruption_on_upstream_forwarding(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        pkt = CipSafetyDaisyChainPacket(
            snn=DEFAULT_SNN, tunid=100, ounid=1,
            channel_a_payload=b"\x01\x02", channel_b_payload=b"\xFE\xFD",
        )
        pkt.calculate_crcs()
        pkt.crc_s1 ^= 0xFFFF
        with pytest.raises(CipSafetyCrcCorruptionError):
            engine.forward_upstream(pkt)
        assert engine.diagnostic_code == DiagnosticCode.CRC_S_CORRUPTION

    def test_trip_on_link_break_false_does_not_trip_safe_state(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, trip_on_link_break=False)
        engine.set_port_link_status(PORT1_INGRESS, False)
        assert engine.topology_state == DaisyChainTopologyState.PORT2_ONLY
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_tripped is False

    def test_sync_registers_without_register_table_safe(self) -> None:
        engine = CipSafetyDaisyChainEngine(register_table=None, auto_activate=True)
        engine.sync_to_registers(None)  # No-op, should not raise

    def test_negative_monitored_payload_word_stored_correctly(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyDaisyChainEngine(register_table=rt, auto_activate=True)
        engine.connection.monitored_payload_word = -1234
        engine.sync_to_registers(rt)
        assert rt.read_word("%R1936") == -1234

    def test_supervisor_lock_and_unlock(self) -> None:
        sup = SafetySupervisorObject(DEFAULT_SNN)
        assert sup.is_locked() is False
        sup.lock_configuration()
        assert sup.is_locked() is True
        sup.unlock_configuration()
        assert sup.is_locked() is False

    def test_scan_step_with_large_dt_interpreted_as_ms(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True, watchdog_timeout_ms=30.0)
        engine.scan_step(35.0)  # > 5.0 -> interpreted as ms
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT

    def test_execute_handles_various_ctx_attributes(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        ctx1 = ScanContext(cycle=1, dt=0.010)
        engine.execute(ctx1)
        assert engine.words_processed == 1

    def test_reset_clears_fault_count(self) -> None:
        engine = CipSafetyDaisyChainEngine(auto_activate=True)
        engine.trip(DiagnosticCode.DAISY_CHAIN_LINK_BREAK)
        assert engine.consecutive_fault_count == 1
        engine.reset()
        assert engine.consecutive_fault_count == 0
        assert engine.diagnostic_code == DiagnosticCode.OK
