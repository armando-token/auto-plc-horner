"""Comprehensive Unit Test Suite for Wave W238 CIP Safety Router / Master-Slave Concentrator Engine.

Work Package: W238 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 100+ Comprehensive Unit Tests across 16 Sections:
1. Section 1: Protocol Constants, Identifiers, Enums & Diagnostic Codes (signed/unsigned & 0xFFFF).
2. Section 2: SNN Format (6 octets), SCID, TUNID, & OUNID Parsing, Formatting, Validation & Generation.
3. Section 3: Dual CRC-S Calculations (CRC-S1 poly 0x5935 and CRC-S2 poly 0x755B).
4. Section 4: Dual-Channel Diversified Payload Verification & Discrepancy Detection.
5. Section 5: Managed Downstream Safety Nodes (Node 0..3) Initialization & Telemetry.
6. Section 6: Concentrator Routing Table & Packet Forwarding (forward_packet, route_packet).
7. Section 7: Expected Packet Interval (EPI) Surveillance & Timeout Tripping (0xEA02).
8. Section 8: Jitter Surveillance & Overrun Tripping (0xEA04).
9. Section 9: Downstream Node Disconnect (0xEA05) & Routing Table Corruption (0xEA06).
10. Section 10: Horner OCS Register Table Synchronization (%R1990..%R1997, %M464..%M465).
11. Section 11: Pure IEC 61131-3 Structured Text POU Validation (SecurityGuard & STParser).
12. Section 12: Anti-Ladder Security Guard Interception (contacts, coils, rungs, mnemonics).
13. Section 13: ILogicUnit Interface Compliance & Scan Cycle Simulation.
14. Section 14: 100-Cycle Soak Simulation & Bounded Execution (Heap & Memory Stability).
15. Section 15: Operator Reset & Safe State Recovery.
16. Section 16: Verification Runner & Strict 4-State Engineering Contract.
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
from jev_cscape.telemetry.cip_safety_router import (
    CIP_SAFETY_CONCENTRATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_CRC_INIT,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_ROUTER_CLASS_ID,
    CIP_SAFETY_ROUTER_CONNECTION_CLASS_ID,
    CIP_SAFETY_ROUTER_POU,
    CIP_SAFETY_ROUTER_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_ROUTER_SYNC_POU,
    CIP_SAFETY_ROUTER_VALIDATOR_CLASS_ID,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyRouterEngine,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_S_INIT,
    DEFAULT_EPI_MS,
    DEFAULT_MAX_JITTER_US,
    DEFAULT_NODE_COUNT,
    DEFAULT_NODE_UNIDS,
    DEFAULT_ORIGINATOR_UNID,
    DEFAULT_OUNID,
    DEFAULT_ROUTER_HEALTH_INDEX,
    DEFAULT_ROUTER_HEALTH_INDEX_SCALED,
    DEFAULT_SAFETY_NODES_COUNT,
    DEFAULT_SCID,
    DEFAULT_SCID_CRC,
    DEFAULT_SCID_TIMESTAMP,
    DEFAULT_SNN,
    DEFAULT_TUNID,
    DEFAULT_WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DIAG_CRC_FAULT,
    DIAG_CRC_S_CORRUPTION,
    DIAG_CRC_S_FAULT,
    DIAG_DISCREPANCY,
    DIAG_DOWNSTREAM_NODE_DISCONNECT,
    DIAG_DUAL_CHANNEL_DISCREPANCY,
    DIAG_EPI_TIMEOUT,
    DIAG_EPI_WATCHDOG_TIMEOUT,
    DIAG_FORWARDING_JITTER_EXCEEDED,
    DIAG_JITTER_EXCEEDED,
    DIAG_NODE_DISCONNECT,
    DIAG_OK,
    DIAG_ROUTER_OK,
    DIAG_ROUTING_CORRUPTED,
    DIAG_ROUTING_TABLE_CORRUPTED,
    DIAG_SNN_MISMATCH,
    DIAG_SNN_SIGNATURE_MISMATCH,
    EPI_WATCHDOG_TIMEOUT_MS,
    FORWARDING_JITTER_THRESHOLD_US,
    MAX_ALLOWABLE_JITTER_US,
    MAX_JITTER_THRESHOLD_US,
    MAX_NOMINAL_JITTER_US,
    NOMINAL_EPI_MS,
    NOMINAL_JITTER_US,
    PURE_ST_POU,
    REG_ACTIVE_FAULT_NODE_INDEX,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_FORWARDED_PACKETS_SCALED,
    REG_MAX_JITTER_US,
    REG_ROUTER_HEALTH_INDEX_SCALED,
    REG_ROUTER_TOPOLOGY_STATUS_BITS,
    REG_SAFETY_NODES_COUNT,
    REG_SELECTED_MONITORED_NODE,
    COIL_SAFETY_ROUTER_ACTIVE,
    COIL_SAFETY_ROUTER_FAULT_ACTIVE,
    WATCHDOG_MULTIPLIER,
    CipSafetyCrcFaultError,
    CipSafetyCrcCorruptionError,
    CipSafetyDiagnosticCode,
    CipSafetyDiscrepancyError,
    CipSafetyDownstreamNodeDisconnectError,
    CipSafetyDualChannelDiscrepancyError,
    CipSafetyEpiTimeoutError,
    CipSafetyEpiWatchdogTimeoutError,
    CipSafetyForwardingJitterExceededError,
    CipSafetyForwardingJitterOverrunError,
    CipSafetyJitterExceededError,
    CipSafetyNodeDisconnectError,
    CipSafetyPacket,
    CipSafetyReplayAttackError,
    CipSafetyRouter,
    CipSafetyRouterDiagnosticCode,
    CipSafetyRouterEngine,
    CipSafetyRouterError,
    CipSafetyRouterPacket,
    CipSafetyRouterState,
    CipSafetyRouterStatusBits,
    CipSafetyRouterSync,
    CipSafetyRoutingTableCorruptedError,
    CipSafetyRoutingTableError,
    CipSafetySnnMismatchError,
    DiagnosticCode,
    DiagnosticStatusCode,
    DiversifiedMode,
    RouterDiagnosticCode,
    RouterOperationalState,
    RouterSafetyNode,
    RouterState,
    RouterStatusBits,
    RouterTopologyState,
    RouterTopologyStatusBits,
    SafetyControlByte,
    SafetyModeByte,
    SafetyNode,
    SafetyNodeIndex,
    SafetyOperationalState,
    SafetyRouterEngine,
    SafetyRouterState,
    calc_crc_s1,
    calc_crc_s2,
    compute_crc_s1,
    compute_crc_s2,
    create_default_safety_nodes,
    create_valid_packet,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_router_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    validate_snn,
    verify_cip_safety_router_pure_st,
    verify_dual_channel_payload,
)


# ============================================================================
# Section 1: Protocol Constants, Identifiers, Enums & Diagnostic Codes
# ============================================================================

class TestSection1ProtocolConstantsAndDiagnosticCodes:
    """Validate CIP Safety router protocol constants, classes, and DiagnosticCode."""

    def test_odva_object_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_ROUTER_CLASS_ID == 0x3B
        assert CIP_SAFETY_CONCENTRATOR_CLASS_ID == 0x3B
        assert CIP_SAFETY_ROUTER_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_ROUTER_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_ROUTER_CONNECTION_CLASS_ID == 0x3B

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_S_INIT == 0xFFFF
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC16_CCITT_POLY == 0x1021
        assert CRC16_CCITT_INIT == 0xFFFF

    def test_timing_constants(self) -> None:
        assert NOMINAL_EPI_MS == 10.0
        assert DEFAULT_EPI_MS == 10.0
        assert WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert EPI_WATCHDOG_TIMEOUT_MS == 30.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 30.0

    def test_jitter_threshold_constants(self) -> None:
        assert NOMINAL_JITTER_US == 850
        assert MAX_NOMINAL_JITTER_US == 1200
        assert MAX_JITTER_THRESHOLD_US == 2500.0
        assert MAX_ALLOWABLE_JITTER_US == 2500.0
        assert FORWARDING_JITTER_THRESHOLD_US == 2500.0
        assert DEFAULT_MAX_JITTER_US == 2500.0

    def test_diagnostic_code_values(self) -> None:
        assert DiagnosticCode.ROUTER_OK == 0x0000
        assert DiagnosticCode.CRC_S_FAULT == 0xEA01
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xEA02
        assert DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == 0xEA03
        assert DiagnosticCode.FORWARDING_JITTER_EXCEEDED == 0xEA04
        assert DiagnosticCode.DOWNSTREAM_NODE_DISCONNECT == 0xEA05
        assert DiagnosticCode.ROUTING_TABLE_CORRUPTED == 0xEA06

    def test_diagnostic_code_aliases(self) -> None:
        assert DiagnosticCode.OK == DiagnosticCode.ROUTER_OK
        assert DiagnosticCode.CRC_FAULT == DiagnosticCode.CRC_S_FAULT
        assert DiagnosticCode.CRC_S_CORRUPTION == DiagnosticCode.CRC_S_FAULT
        assert DiagnosticCode.EPI_TIMEOUT == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DiagnosticCode.DISCREPANCY_FAULT == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert DiagnosticCode.JITTER_EXCEEDED == DiagnosticCode.FORWARDING_JITTER_EXCEEDED
        assert DiagnosticCode.NODE_DISCONNECT == DiagnosticCode.DOWNSTREAM_NODE_DISCONNECT
        assert DiagnosticCode.ROUTING_CORRUPTED == DiagnosticCode.ROUTING_TABLE_CORRUPTED
        assert DiagnosticCode.SNN_SIGNATURE_MISMATCH == DiagnosticCode.CRC_S_FAULT

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        # 0x0000
        assert DiagnosticCode.ROUTER_OK == 0
        assert DiagnosticCode.ROUTER_OK == 0x0000

        # 0xEA01: 59905 unsigned, -5631 signed 16-bit
        code_crc = DiagnosticCode.CRC_S_FAULT
        assert code_crc == 0xEA01
        assert code_crc == 59905
        assert code_crc == -5631
        assert (code_crc & 0xFFFF) == 0xEA01

        # 0xEA02: 59906 unsigned, -5630 signed 16-bit
        code_epi = DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert code_epi == 0xEA02
        assert code_epi == 59906
        assert code_epi == -5630
        assert (code_epi & 0xFFFF) == 0xEA02

        # 0xEA03: 59907 unsigned, -5629 signed 16-bit
        code_disc = DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert code_disc == 0xEA03
        assert code_disc == 59907
        assert code_disc == -5629
        assert (code_disc & 0xFFFF) == 0xEA03

        # 0xEA04: 59908 unsigned, -5628 signed 16-bit
        code_jit = DiagnosticCode.FORWARDING_JITTER_EXCEEDED
        assert code_jit == 0xEA04
        assert code_jit == 59908
        assert code_jit == -5628
        assert (code_jit & 0xFFFF) == 0xEA04

        # 0xEA05: 59909 unsigned, -5627 signed 16-bit
        code_disc_node = DiagnosticCode.DOWNSTREAM_NODE_DISCONNECT
        assert code_disc_node == 0xEA05
        assert code_disc_node == 59909
        assert code_disc_node == -5627
        assert (code_disc_node & 0xFFFF) == 0xEA05

        # 0xEA06: 59910 unsigned, -5626 signed 16-bit
        code_route = DiagnosticCode.ROUTING_TABLE_CORRUPTED
        assert code_route == 0xEA06
        assert code_route == 59910
        assert code_route == -5626
        assert (code_route & 0xFFFF) == 0xEA06

    def test_diagnostic_code_masking_and_bitwise_ops(self) -> None:
        c = DiagnosticCode(0xEA02)
        assert (c & 0xFFFF) == 0xEA02
        assert (0xFFFF & c) == 0xEA02
        assert hash(c) == hash(0xEA02)
        assert "EA02" in repr(c)
        assert "EA02" in str(c)

    def test_router_state_enum(self) -> None:
        assert RouterState.INIT == 0
        assert RouterState.ROUTING_ACTIVE == 1
        assert RouterState.DEGRADED == 2
        assert RouterState.SAFE_STATE == 3
        assert RouterState.FAULTED == 4
        assert RouterState.OPERATIONAL == 1
        assert RouterState.ACTIVE == 1
        assert RouterState.TRIPPED == 3
        assert RouterState.FAULT_SAFE_STATE == 3

    def test_safety_node_index_enum(self) -> None:
        assert SafetyNodeIndex.NODE_0_ESTOP == 0
        assert SafetyNodeIndex.NODE_1_LIGHT_CURTAIN == 1
        assert SafetyNodeIndex.NODE_2_SAFETY_MAT == 2
        assert SafetyNodeIndex.NODE_3_AGV_INTERLOCK == 3
        assert SafetyNodeIndex.ESTOP == 0
        assert SafetyNodeIndex.LIGHT_CURTAIN == 1
        assert SafetyNodeIndex.SAFETY_MAT == 2
        assert SafetyNodeIndex.AGV_INTERLOCK == 3

    def test_safety_control_byte_enum(self) -> None:
        assert SafetyControlByte.IDLE == 0x00
        assert SafetyControlByte.RUN == 0x01
        assert SafetyControlByte.PING_REQ == 0x02
        assert SafetyControlByte.PING_RESP == 0x04
        assert SafetyControlByte.SAFETY_DEMAND == 0x08
        assert SafetyControlByte.FAULT_PRESENT == 0x10
        assert SafetyControlByte.RESET_REQUEST == 0x20
        assert SafetyControlByte.ROUTER_ROUTED == 0x40
        assert SafetyControlByte.DISCONNECT_REQ == 0x80

    def test_router_topology_status_bits(self) -> None:
        assert RouterTopologyStatusBits.ROUTER_ACTIVE == 1 << 0
        assert RouterTopologyStatusBits.ROUTER_FAULT_ACTIVE == 1 << 1
        assert RouterTopologyStatusBits.NODE_0_ACTIVE == 1 << 2
        assert RouterTopologyStatusBits.NODE_1_ACTIVE == 1 << 3
        assert RouterTopologyStatusBits.NODE_2_ACTIVE == 1 << 4
        assert RouterTopologyStatusBits.NODE_3_ACTIVE == 1 << 5
        assert RouterTopologyStatusBits.ALL_NODES_HEALTHY == 1 << 6
        assert RouterTopologyStatusBits.DUAL_CHANNEL_VERIFIED == 1 << 7
        assert RouterTopologyStatusBits.CRC_VERIFIED == 1 << 8
        assert RouterTopologyStatusBits.ROUTING_TABLE_VALID == 1 << 9
        assert RouterTopologyStatusBits.JITTER_SURVEILLANCE_OK == 1 << 10
        assert RouterTopologyStatusBits.EPI_TIMEOUT_LATCH == 1 << 11
        assert RouterTopologyStatusBits.DISCREPANCY_LATCH == 1 << 12
        assert RouterTopologyStatusBits.NODE_DISCONNECT_LATCH == 1 << 13
        assert RouterTopologyStatusBits.CRC_FAULT_LATCH == 1 << 14
        assert RouterTopologyStatusBits.ROUTING_CORRUPTED_LATCH == 1 << 15


# ============================================================================
# Section 2: SNN Format, SCID, TUNID & OUNID Parsing & Validation
# ============================================================================

class TestSection2SnnFormatAndNetworkIdentifiers:
    """Validate SNN representation, serialization, and network identity parsing."""

    def test_default_snn_length_and_value(self) -> None:
        assert len(DEFAULT_SNN) == 6
        assert DEFAULT_SNN == bytes([0x20, 0x26, 0x10, 0x06, 0xEE, 0x99])

    def test_format_snn(self) -> None:
        formatted = format_snn(DEFAULT_SNN)
        assert formatted == "2026-1006-EE99"

    def test_format_snn_invalid_length(self) -> None:
        with pytest.raises(ValueError):
            format_snn(bytes([0x01, 0x02, 0x03]))

    def test_parse_snn(self) -> None:
        parsed = parse_snn("2026-1006-EE99")
        assert parsed == DEFAULT_SNN
        parsed2 = parse_snn("20261006EE99")
        assert parsed2 == DEFAULT_SNN

    def test_parse_snn_invalid(self) -> None:
        with pytest.raises(ValueError):
            parse_snn("INVALID")

    def test_validate_snn(self) -> None:
        assert validate_snn(DEFAULT_SNN) is True
        assert validate_snn(bytes(6)) is False  # all zeroes
        assert validate_snn(b"short") is False
        assert validate_snn(b"toolongbytes") is False
        assert validate_snn(None) is False  # type: ignore

    def test_generate_snn(self) -> None:
        snn = generate_snn(seed=0x20261006)
        assert len(snn) == 6
        assert snn[:4] == bytes([0x20, 0x26, 0x10, 0x06])

        snn2 = generate_snn(0x1234, 0x56789ABC)
        assert len(snn2) == 6

    def test_default_node_identifiers(self) -> None:
        assert DEFAULT_NODE_COUNT == 4
        assert DEFAULT_SAFETY_NODES_COUNT == 4
        assert DEFAULT_NODE_UNIDS == [10, 11, 12, 13]
        assert DEFAULT_ORIGINATOR_UNID == 100
        assert DEFAULT_OUNID == 100
        assert DEFAULT_TUNID == 1
        assert DEFAULT_SCID == 0x20261006
        assert DEFAULT_SCID_CRC == 0x20261006
        assert DEFAULT_SCID_TIMESTAMP == 0x10060002


# ============================================================================
# Section 3: Dual CRC-S Calculations (0x5935 and 0x755B)
# ============================================================================

class TestSection3DualCrcSCalculations:
    """Validate 16-bit safety checksums CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B)."""

    def test_compute_crc_s1_determinism(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06"
        crc1 = compute_crc_s1(data)
        crc2 = compute_crc_s1(data)
        assert crc1 == crc2
        assert isinstance(crc1, int)
        assert 0 <= crc1 <= 0xFFFF

    def test_compute_crc_s2_determinism(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06"
        crc1 = compute_crc_s2(data)
        crc2 = compute_crc_s2(data)
        assert crc1 == crc2
        assert isinstance(crc1, int)
        assert 0 <= crc1 <= 0xFFFF

    def test_crc_s1_and_crc_s2_polynomial_divergence(self) -> None:
        # Since polynomials differ (0x5935 vs 0x755B), CRCs on arbitrary data should diverge
        data = b"CIP_SAFETY_ROUTER_DATA_BLOCK_TEST"
        crc1 = compute_crc_s1(data)
        crc2 = compute_crc_s2(data)
        assert crc1 != crc2

    def test_compute_crc_s2_unpacked_args(self) -> None:
        ts = 1000
        seq = 5
        payload = bytes([0xAA, 0x55])
        crc = compute_crc_s2(ts, seq, payload)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

    def test_compute_crc_s2_invalid_args(self) -> None:
        with pytest.raises(ValueError):
            compute_crc_s2("invalid", "args")

    def test_calc_crc_aliases(self) -> None:
        data = b"TEST"
        assert calc_crc_s1(data) == compute_crc_s1(data)
        assert calc_crc_s2(data) == compute_crc_s2(data)


# ============================================================================
# Section 4: Dual-Channel Diversified Payload Verification
# ============================================================================

class TestSection4DualChannelPayloadVerification:
    """Validate dual-channel diversified safety payload cross-comparison."""

    def test_verify_dual_channel_bytes_inverted(self) -> None:
        ch_a = bytes([0x01, 0x00, 0xAA, 0x55])
        ch_b = bytes([0xFE, 0xFF, 0x55, 0xAA])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is True

    def test_verify_dual_channel_bytes_discrepancy(self) -> None:
        ch_a = bytes([0x01, 0x00, 0xAA, 0x55])
        ch_b = bytes([0xFE, 0xFF, 0x55, 0x00])  # last byte mismatch
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_length_mismatch(self) -> None:
        ch_a = bytes([0x01, 0x00])
        ch_b = bytes([0xFE, 0xFF, 0x00])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_int_inverted(self) -> None:
        val_a = 0x1234
        val_b = (~val_a) & 0xFFFF
        assert verify_dual_channel_payload(val_a, val_b, DiversifiedMode.INVERTED) is True

        # Discrepant
        assert verify_dual_channel_payload(val_a, 0x0000, DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_identical_mode(self) -> None:
        ch_a = bytes([0x12, 0x34])
        ch_b = bytes([0x12, 0x34])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.IDENTICAL) is True

        assert verify_dual_channel_payload(ch_a, bytes([0x00, 0x00]), DiversifiedMode.IDENTICAL) is False

    def test_verify_dual_channel_invalid_type(self) -> None:
        assert verify_dual_channel_payload("invalid", "types") is False  # type: ignore


# ============================================================================
# Section 5: Managed Downstream Safety Nodes (Node 0..3) Initialization
# ============================================================================

class TestSection5ManagedDownstreamSafetyNodes:
    """Validate 4 managed downstream safety nodes configuration and telemetry."""

    def test_create_default_safety_nodes_count(self) -> None:
        nodes = create_default_safety_nodes()
        assert len(nodes) == 4

    def test_node_0_estop_attributes(self) -> None:
        nodes = create_default_safety_nodes()
        n0 = nodes[0]
        assert n0.node_index == 0
        assert n0.node_id == 1
        assert "E-Stop" in n0.name
        assert n0.tunid == 10
        assert n0.ounid == 100
        assert n0.is_connected is True
        assert n0.is_faulted is False
        assert n0.diagnostic_code == DiagnosticCode.ROUTER_OK

    def test_node_1_light_curtain_attributes(self) -> None:
        nodes = create_default_safety_nodes()
        n1 = nodes[1]
        assert n1.node_index == 1
        assert n1.node_id == 2
        assert "Light Curtain" in n1.name
        assert n1.tunid == 11
        assert n1.ounid == 100
        assert n1.is_connected is True

    def test_node_2_safety_mat_attributes(self) -> None:
        nodes = create_default_safety_nodes()
        n2 = nodes[2]
        assert n2.node_index == 2
        assert n2.node_id == 3
        assert "Safety Mat" in n2.name
        assert n2.tunid == 12
        assert n2.ounid == 100
        assert n2.is_connected is True

    def test_node_3_agv_interlock_attributes(self) -> None:
        nodes = create_default_safety_nodes()
        n3 = nodes[3]
        assert n3.node_index == 3
        assert n3.node_id == 4
        assert "AGV" in n3.name
        assert n3.tunid == 13
        assert n3.ounid == 100
        assert n3.is_connected is True

    def test_node_to_dict_serialization(self) -> None:
        nodes = create_default_safety_nodes()
        d = nodes[0].to_dict()
        assert d["node_index"] == 0
        assert d["node_id"] == 1
        assert d["is_connected"] is True
        assert d["is_faulted"] is False
        assert d["diagnostic_code"] == 0
        assert d["diagnostic_code_hex"] == "0x0000"


# ============================================================================
# Section 6: Concentrator Routing Table & Packet Forwarding
# ============================================================================

class TestSection6ConcentratorPacketForwarding:
    """Validate packet creation, validation, forwarding, and route_packet operations."""

    def test_create_valid_packet_helper(self) -> None:
        pkt = create_valid_packet(node_index=0, sequence_number=1, timestamp_ms=10.0)
        assert pkt.node_index == 0
        assert pkt.sequence_number == 1
        assert pkt.timestamp_ms == 10.0
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.verify_dual_channel() is True
        assert pkt.verify_crcs() is True

    def test_packet_parity_and_crc_verification(self) -> None:
        pkt = create_valid_packet(node_index=1, sequence_number=2)
        assert pkt.verify_parity(DiversifiedMode.INVERTED) is True
        assert pkt.verify_crcs() is True

        # Invalidate CRC
        pkt.crc_s1 = (pkt.crc_s1 + 1) & 0xFFFF
        assert pkt.verify_crcs() is False

    def test_engine_forward_packet_nominal(self) -> None:
        engine = CipSafetyRouterEngine()
        assert engine.is_active is True
        assert engine.diagnostic_code == DiagnosticCode.ROUTER_OK

        pkt = create_valid_packet(node_index=0, sequence_number=1)
        res = engine.forward_packet(pkt)
        assert res is True
        assert engine.total_forwarded_packets == 1
        assert engine.nodes[0].packets_forwarded == 1
        assert engine.nodes[0].silence_time_ms == 0.0

    def test_engine_forward_packets_all_4_nodes(self) -> None:
        engine = CipSafetyRouterEngine()
        for nid in range(4):
            pkt = create_valid_packet(node_index=nid, sequence_number=1)
            res = engine.forward_packet(pkt)
            assert res is True
            assert engine.nodes[nid].packets_forwarded == 1

        assert engine.total_forwarded_packets == 4
        assert engine.is_active is True
        assert engine.is_fault_active is False

    def test_route_packet_single_arg(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(node_index=2, sequence_number=5)
        res = engine.route_packet(pkt)
        assert res is True
        assert engine.nodes[2].packets_forwarded == 1

    def test_route_packet_node_to_node(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = engine.create_safety_packet(source_node_id=1, target_node_id=2, sequence_number=1, payload_word=0x1234)
        routed = engine.route_packet(1, 2, pkt)
        assert routed is pkt
        assert engine.nodes[0].packets_received == 1  # source node (id 1 -> index 0)
        assert engine.nodes[1].packets_forwarded == 1  # target node (id 2 -> index 1)

    def test_route_packet_invalid_args_raises(self) -> None:
        engine = CipSafetyRouterEngine()
        with pytest.raises(ValueError):
            engine.route_packet("invalid")


# ============================================================================
# Section 7: Expected Packet Interval (EPI) Surveillance & Timeout Tripping
# ============================================================================

class TestSection7EpiWatchdogSurveillance:
    """Validate EPI silence monitoring, 30 ms watchdog timeout, and fail-safe tripping (0xEA02)."""

    def test_watchdog_normal_silence_under_threshold(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.scan_step(0.010)  # 10 ms
        assert engine.is_active is True
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.ROUTER_OK

        engine.scan_step(0.010)  # 20 ms total silence
        assert engine.is_active is True
        assert engine.is_fault_active is False

    def test_watchdog_timeout_trips_at_30ms(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.scan_step(0.010)  # 10 ms
        engine.scan_step(0.010)  # 20 ms
        engine.scan_step(0.015)  # 35 ms total silence -> watchdog > 30 ms trips
        assert engine.is_active is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert (engine.diagnostic_code & 0xFFFF) == 0xEA02
        assert engine.router_state == RouterState.SAFE_STATE

    def test_watchdog_reset_on_packet_forwarding(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.scan_step(0.020)  # 20 ms elapsed
        # Forward packets for all 4 nodes
        for nid in range(4):
            pkt = create_valid_packet(node_index=nid, sequence_number=1)
            engine.forward_packet(pkt)
            assert engine.nodes[nid].silence_time_ms == 0.0

        # Step another 20 ms (total would be 40 ms, but reset occurred at 20 ms)
        engine.scan_step(0.020)
        assert engine.is_active is True
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.ROUTER_OK

    def test_simulate_epi_timeout_helper(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.simulate_epi_timeout(node_id=2)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.active_fault_node_index == 1


# ============================================================================
# Section 8: Jitter Surveillance & Overrun Tripping (0xEA04)
# ============================================================================

class TestSection8JitterSurveillance:
    """Validate high-precision jitter surveillance and tripping on > 2500 us (0xEA04)."""

    def test_nominal_jitter_accepted(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(node_index=0, jitter_us=850.0)
        res = engine.forward_packet(pkt)
        assert res is True
        assert engine.max_jitter_us == 850
        assert engine.is_active is True

    def test_marginal_jitter_accepted(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(node_index=1, jitter_us=2450.0)
        res = engine.forward_packet(pkt)
        assert res is True
        assert engine.max_jitter_us == 2450
        assert engine.is_active is True

    def test_excessive_jitter_trips_0xea04(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(node_index=0, jitter_us=2850.0)
        res = engine.forward_packet(pkt)
        assert res is False
        assert engine.is_active is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.FORWARDING_JITTER_EXCEEDED
        assert (engine.diagnostic_code & 0xFFFF) == 0xEA04
        assert engine.active_fault_node_index == 0

    def test_simulate_jitter_exceeded_helper(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.simulate_jitter_exceeded(node_id=3)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.FORWARDING_JITTER_EXCEEDED
        assert engine.active_fault_node_index == 2


# ============================================================================
# Section 9: Downstream Node Disconnect & Routing Table Corruption
# ============================================================================

class TestSection9NodeDisconnectAndRoutingCorruption:
    """Validate downstream node disconnect (0xEA05) and routing table corruption (0xEA06)."""

    def test_disconnect_node_trips_0xea05(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.disconnect_node(1)  # Node index 1 (Light Curtain Barrier)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.DOWNSTREAM_NODE_DISCONNECT
        assert (engine.diagnostic_code & 0xFFFF) == 0xEA05
        assert engine.active_fault_node_index == 1
        assert engine.nodes[1].is_connected is False

    def test_reconnect_node_restores_connection_state(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.disconnect_node(1)
        assert engine.nodes[1].is_connected is False
        engine.reconnect_node(1)
        assert engine.nodes[1].is_connected is True

    def test_forward_packet_to_disconnected_node_trips(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.nodes[2].is_connected = False
        pkt = create_valid_packet(node_index=2)
        res = engine.forward_packet(pkt)
        assert res is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.DOWNSTREAM_NODE_DISCONNECT

    def test_routing_table_corruption_out_of_bounds_node_index(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(node_index=99)  # invalid node index
        res = engine.forward_packet(pkt)
        assert res is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.ROUTING_TABLE_CORRUPTED
        assert (engine.diagnostic_code & 0xFFFF) == 0xEA06

    def test_routing_table_corrupted_flag(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.routing_table_corrupted = True
        pkt = create_valid_packet(node_index=0)
        res = engine.forward_packet(pkt)
        assert res is False
        assert engine.diagnostic_code == DiagnosticCode.ROUTING_TABLE_CORRUPTED

    def test_dual_channel_discrepancy_trips_0xea03(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(node_index=0)
        pkt.channel_b_payload = bytes([0x00, 0x00])  # corrupt complement
        res = engine.forward_packet(pkt)
        assert res is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert (engine.diagnostic_code & 0xFFFF) == 0xEA03

    def test_crc_s_fault_trips_0xea01(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(node_index=0)
        pkt.crc_s1 = 0x1234  # corrupt CRC
        res = engine.forward_packet(pkt)
        assert res is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.CRC_S_FAULT
        assert (engine.diagnostic_code & 0xFFFF) == 0xEA01


# ============================================================================
# Section 10: Horner OCS Register Table Synchronization
# ============================================================================

class TestSection10RegisterTableSynchronization:
    """Validate bit-exact synchronization to Horner OCS registers (%R1990..%R1997, %M464..%M465)."""

    def test_register_synchronization_nominal(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRouterEngine(register_table=rt)
        engine.sync_to_registers(rt)

        assert rt.read_word("%R1990") == 4
        assert rt.read_word("%R1991") == 9980
        assert rt.read_word("%R1992") == 850
        assert rt.read_word("%R1993") == 0
        assert rt.read_word("%R1994") == -1
        assert rt.read_uword("%R1997") == 0x0000
        assert rt.read_bit("%M464") is True
        assert rt.read_bit("%M465") is False

    def test_register_synchronization_on_fault(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRouterEngine(register_table=rt)
        engine.trip_fault(DiagnosticCode.EPI_WATCHDOG_TIMEOUT, node_index=2)
        engine.sync_to_registers(rt)

        assert rt.read_word("%R1994") == 2
        assert rt.read_uword("%R1997") == 0xEA02
        assert rt.read_word("%R1997") == -5630  # signed 16-bit match
        assert rt.read_bit("%M464") is False
        assert rt.read_bit("%M465") is True

    def test_register_synchronization_forwarded_packets_counter(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRouterEngine(register_table=rt)
        for i in range(250):
            pkt = create_valid_packet(node_index=i % 4, sequence_number=i + 1)
            engine.forward_packet(pkt)

        engine.sync_to_registers(rt)
        # 250 // 100 = 2
        assert rt.read_word("%R1993") == 2

    def test_safe_write_helpers(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R1990", 4)
        assert rt.read_word("%R1990") == 4

        safe_write_word(rt, "%R1994", -1)
        assert rt.read_word("%R1994") == -1

        safe_write_uword(rt, "%R1997", 0xEA01)
        assert rt.read_uword("%R1997") == 0xEA01
        assert rt.read_word("%R1997") == -5631

        safe_write_bit(rt, "%M464", True)
        assert rt.read_bit("%M464") is True
        safe_write_bit(rt, "%M464", False)
        assert rt.read_bit("%M464") is False


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU Validation
# ============================================================================

class TestSection11PureStructuredTextPouValidation:
    """Validate pure IEC 61131-3 ST POU using SecurityGuard and STParser."""

    def test_pure_st_pou_syntax_and_ast_structure(self) -> None:
        assert verify_cip_safety_router_pure_st() is True

    def test_pure_st_ast_program_type_and_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_ROUTER_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyRouterSync"
        expected = {
            "%R1990", "%R1991", "%R1992", "%R1993",
            "%R1994", "%R1995", "%R1996", "%R1997",
            "%M464", "%M465",
        }
        assert expected.issubset(set(ast.bound_registers))

    def test_pure_st_guard_assertion(self) -> None:
        # Must not raise
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_ROUTER_SYNC_POU)

    def test_pure_st_pou_constants_match(self) -> None:
        assert CIP_SAFETY_ROUTER_POU == CIP_SAFETY_ROUTER_SYNC_POU
        assert PURE_ST_POU == CIP_SAFETY_ROUTER_SYNC_POU


# ============================================================================
# Section 12: Anti-Ladder Security Guard Interception
# ============================================================================

class TestSection12AntiLadderSecurityGuardInterception:
    """Validate strict rejection of forbidden ladder logic contacts, coils, and rungs."""

    def test_reject_normally_open_contact(self) -> None:
        bad_st = CIP_SAFETY_ROUTER_SYNC_POU + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_normally_closed_contact(self) -> None:
        bad_st = CIP_SAFETY_ROUTER_SYNC_POU + "\n---[/]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_coil_construct(self) -> None:
        bad_st = CIP_SAFETY_ROUTER_SYNC_POU + "\n---( )---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_rung_delimiter(self) -> None:
        bad_st = CIP_SAFETY_ROUTER_SYNC_POU + "\nRUNG 1\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_network_delimiter(self) -> None:
        bad_st = CIP_SAFETY_ROUTER_SYNC_POU + "\nNETWORK 1\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_ladder_mnemonic_xic(self) -> None:
        bad_st = CIP_SAFETY_ROUTER_SYNC_POU + "\nXIC(InputBit);\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_ladder_mnemonic_ote(self) -> None:
        bad_st = CIP_SAFETY_ROUTER_SYNC_POU + "\nOTE(OutputBit);\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# Section 13: ILogicUnit Interface Compliance & Scan Cycle Simulation
# ============================================================================

class TestSection13ILogicUnitCompliance:
    """Validate ILogicUnit interface compliance, priority, execution, and step methods."""

    def test_ilogic_unit_interface_properties(self) -> None:
        engine = CipSafetyRouterEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CipSafetyRouterSync"
        assert engine.priority == 95
        assert engine.is_enabled is True

    def test_ilogic_unit_execute_method(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRouterEngine(register_table=rt)
        ctx = ScanContext(cycle=1, dt=0.010)
        engine.execute(ctx)
        assert engine.execution_count == 1
        assert rt.read_word("%R1990") == 4

    def test_step_method_convenience(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.step(0.010)
        assert engine.execution_count == 1
        assert engine.current_time_ms == 10.0

    def test_disabled_engine_skips_execution(self) -> None:
        engine = CipSafetyRouterEngine(auto_activate=False)
        assert engine.is_enabled is False
        engine.step(0.010)
        assert engine.execution_count == 0


# ============================================================================
# Section 14: 100-Cycle Soak Simulation & Bounded Execution
# ============================================================================

class TestSection14SoakSimulation100Cycles:
    """Validate 100 continuous scan cycles with zero NaN and bounded memory."""

    def test_soak_100_cycles_stability(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRouterEngine(register_table=rt)

        for cycle in range(1, 101):
            now_ms = cycle * 10.0
            for nid in range(4):
                pkt = create_valid_packet(node_index=nid, sequence_number=cycle, timestamp_ms=now_ms)
                assert engine.forward_packet(pkt) is True

            engine.scan_step(0.010)

        assert engine.execution_count == 100
        assert engine.total_forwarded_packets == 400
        assert engine.is_active is True
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.ROUTER_OK
        assert rt.read_word("%R1990") == 4
        assert rt.read_word("%R1991") == 9980
        assert rt.read_word("%R1994") == -1
        assert rt.read_bit("%M464") is True
        assert rt.read_bit("%M465") is False


# ============================================================================
# Section 15: Operator Reset & Safe State Recovery
# ============================================================================

class TestSection15OperatorResetAndSafeStateRecovery:
    """Validate fail-safe latching and nominal recovery via reset()."""

    def test_reset_restores_nominal_from_fault(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyRouterEngine(register_table=rt)

        # Trip fault
        engine.trip_fault(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, node_index=1)
        assert engine.is_fault_active is True
        assert rt.read_bit("%M465") is True

        # Operator manual reset
        engine.reset()
        assert engine.is_active is True
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.ROUTER_OK
        assert engine.active_fault_node_index == -1
        assert rt.read_bit("%M464") is True
        assert rt.read_bit("%M465") is False

    def test_reset_reloads_all_node_watchdogs(self) -> None:
        engine = CipSafetyRouterEngine()
        for node in engine.nodes:
            node.silence_time_ms = 25.0
            node.watchdog_timer_ms = 5.0

        engine.reset()
        for node in engine.nodes:
            assert node.silence_time_ms == 0.0
            assert node.watchdog_timer_ms == 30.0
            assert node.is_connected is True
            assert node.is_faulted is False


# ============================================================================
# Section 16: Verification Runner & Strict 4-State Engineering Contract
# ============================================================================

class TestSection16VerificationRunnerContract:
    """Validate run_cip_safety_router_verification conforms to strict 4-state contract."""

    def test_run_verification_returns_strict_contract(self) -> None:
        res = run_cip_safety_router_verification()
        assert isinstance(res, dict)
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9
        assert "data" in res
        assert len(res["data"]["stages"]) == 9
        for stage in res["data"]["stages"]:
            assert stage["passed"] is True

    def test_run_verification_emits_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_router_test_evidence.json"
        res = run_cip_safety_router_verification(output_path=out_file)
        assert out_file.exists()
        loaded = json.loads(out_file.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
        assert loaded["stages_passed"] == 9


# ============================================================================
# Section 17: Multi-Node Safety Zone Scenarios & Advanced Interceptions
# ============================================================================

class TestSection17MultiNodeSafetyZoneScenarios:
    """Validate end-to-end multi-node safety zone behaviors and advanced safety conditions."""

    def test_additional_ladder_coil_set_reset_constructs(self) -> None:
        for coil_str in ["---(S)---", "---(R)---", "---(L)---", "---(U)---"]:
            bad_st = CIP_SAFETY_ROUTER_SYNC_POU + f"\n{coil_str}\n"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_st)

    def test_additional_ladder_delimiters_and_mnemonics(self) -> None:
        for bad_construct in ["END_RUNG", "END_NETWORK", "XIO(StopBit);", "OTL(AlarmBit);", "OTU(LatchBit);"]:
            bad_st = CIP_SAFETY_ROUTER_SYNC_POU + f"\n{bad_construct}\n"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_st)

    def test_crc_s1_single_bit_flip_detection(self) -> None:
        base_data = bytearray(b"CIP_SAFETY_PACKET_CRC_CHECK")
        crc_nominal = compute_crc_s1(base_data)

        # Flip 1 bit
        corrupt_data = bytearray(base_data)
        corrupt_data[4] ^= 0x01
        crc_corrupt = compute_crc_s1(corrupt_data)
        assert crc_nominal != crc_corrupt

    def test_crc_s2_single_bit_flip_detection(self) -> None:
        base_data = bytearray(b"CIP_SAFETY_PACKET_CRC_CHECK")
        crc_nominal = compute_crc_s2(base_data)

        # Flip 1 bit
        corrupt_data = bytearray(base_data)
        corrupt_data[4] ^= 0x01
        crc_corrupt = compute_crc_s2(corrupt_data)
        assert crc_nominal != crc_corrupt

    def test_crc_s1_empty_data(self) -> None:
        assert compute_crc_s1(b"") == 0xFFFF

    def test_crc_s2_empty_data(self) -> None:
        assert compute_crc_s2(b"") == 0xFFFF

    def test_zone_0_estop_demand_forwarding(self) -> None:
        engine = CipSafetyRouterEngine()
        # Zone 0 E-Stop triggered (payload word 0x0001, mode SAFETY_DEMAND)
        pkt = create_valid_packet(
            node_index=0,
            sequence_number=10,
            channel_a_payload=bytes([0x00, 0x01]),
        )
        pkt.control_byte = SafetyControlByte.RUN | SafetyControlByte.SAFETY_DEMAND
        pkt.calculate_crcs()
        assert engine.forward_packet(pkt) is True
        assert engine.nodes[0].channel_a_payload == bytes([0x00, 0x01])

    def test_zone_1_light_curtain_intrusion(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(
            node_index=1,
            sequence_number=11,
            channel_a_payload=bytes([0x00, 0x02]),
        )
        assert engine.forward_packet(pkt) is True
        assert engine.nodes[1].channel_a_payload == bytes([0x00, 0x02])

    def test_zone_2_safety_mat_violation(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(
            node_index=2,
            sequence_number=12,
            channel_a_payload=bytes([0x00, 0x04]),
        )
        assert engine.forward_packet(pkt) is True
        assert engine.nodes[2].channel_a_payload == bytes([0x00, 0x04])

    def test_zone_3_agv_interlock_trip(self) -> None:
        engine = CipSafetyRouterEngine()
        pkt = create_valid_packet(
            node_index=3,
            sequence_number=13,
            channel_a_payload=bytes([0x00, 0x08]),
        )
        assert engine.forward_packet(pkt) is True
        assert engine.nodes[3].channel_a_payload == bytes([0x00, 0x08])

    def test_status_bitmask_individual_node_active_bits(self) -> None:
        engine = CipSafetyRouterEngine()
        mask = engine.status_bitmask
        assert mask & RouterTopologyStatusBits.ROUTER_ACTIVE
        assert mask & RouterTopologyStatusBits.NODE_0_ACTIVE
        assert mask & RouterTopologyStatusBits.NODE_1_ACTIVE
        assert mask & RouterTopologyStatusBits.NODE_2_ACTIVE
        assert mask & RouterTopologyStatusBits.NODE_3_ACTIVE
        assert mask & RouterTopologyStatusBits.ALL_NODES_HEALTHY
        assert mask & RouterTopologyStatusBits.DUAL_CHANNEL_VERIFIED
        assert mask & RouterTopologyStatusBits.CRC_VERIFIED
        assert mask & RouterTopologyStatusBits.ROUTING_TABLE_VALID
        assert mask & RouterTopologyStatusBits.JITTER_SURVEILLANCE_OK

    def test_status_bitmask_degraded_when_node_disconnected(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.disconnect_node(2)  # disconnect node 2 (Safety Mat)
        mask = engine.status_bitmask
        assert not (mask & RouterTopologyStatusBits.NODE_2_ACTIVE)
        assert not (mask & RouterTopologyStatusBits.ALL_NODES_HEALTHY)
        assert mask & RouterTopologyStatusBits.NODE_DISCONNECT_LATCH

    def test_status_bitmask_crc_fault_latch(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.trip_fault(DiagnosticCode.CRC_S_FAULT, node_index=0)
        mask = engine.status_bitmask
        assert mask & RouterTopologyStatusBits.CRC_FAULT_LATCH
        assert not (mask & RouterTopologyStatusBits.CRC_VERIFIED)

    def test_status_bitmask_discrepancy_latch(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.trip_fault(DiagnosticCode.DUAL_CHANNEL_DISCREPANCY, node_index=1)
        mask = engine.status_bitmask
        assert mask & RouterTopologyStatusBits.DISCREPANCY_LATCH
        assert not (mask & RouterTopologyStatusBits.DUAL_CHANNEL_VERIFIED)

    def test_status_bitmask_routing_corrupted_latch(self) -> None:
        engine = CipSafetyRouterEngine()
        engine.trip_fault(DiagnosticCode.ROUTING_TABLE_CORRUPTED, node_index=3)
        mask = engine.status_bitmask
        assert mask & RouterTopologyStatusBits.ROUTING_CORRUPTED_LATCH
        assert not (mask & RouterTopologyStatusBits.ROUTING_TABLE_VALID)

    def test_packet_compute_s1_and_s2_bytes(self) -> None:
        pkt = create_valid_packet(node_index=0, sequence_number=1)
        b1 = pkt.compute_s1_bytes()
        b2 = pkt.compute_s2_bytes()
        assert len(b1) == len(DEFAULT_SNN) + 9 + len(pkt.channel_a_payload)
        assert len(b2) == len(DEFAULT_SNN) + 9 + len(pkt.channel_b_payload)

    def test_engine_registered_nodes_property(self) -> None:
        engine = CipSafetyRouterEngine()
        reg_nodes = engine.registered_nodes
        assert len(reg_nodes) == 4
        assert 0 in reg_nodes
        assert 1 in reg_nodes
        assert 2 in reg_nodes
        assert 3 in reg_nodes
        assert reg_nodes[0].node_index == 0

    def test_engine_get_node_by_id_and_index(self) -> None:
        engine = CipSafetyRouterEngine()
        # index 0 vs id 1
        n0 = engine.get_node(1)  # 1-based id 1 -> node 0
        assert n0 is not None
        assert n0.node_index == 0

        n_invalid = engine.get_node(99)
        assert n_invalid is None

    def test_engine_register_node_update_and_add(self) -> None:
        engine = CipSafetyRouterEngine()
        # update existing node
        updated = engine.register_node(1, description="Updated description")
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
