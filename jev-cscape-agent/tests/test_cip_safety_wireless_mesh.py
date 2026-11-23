"""Comprehensive Unit Test Suite for Wave W280 CIP Safety Over Wireless Mesh Protocol Engine.

Work Package: W280 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Wireless Mesh (IEEE 802.15.4 / 6LoWPAN) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: Protocol constants, timing parameters, register mappings (%R2410..%R2417),
   coil mappings (%M562..%M563), CipSafetyWirelessMeshState, CipSafetyWirelessMeshDiagnosticCode, hashing & operators.
2. TestNodeAndRouteDataclasses: WirelessMeshNode, WirelessMeshRoute, field defaults, custom instances, equality & repr.
3. TestDualSafetyCrcCalculation: CRC-S1 (poly 0x1021 / 0x8408) and CRC-S2 calculations, determinism,
   mutation detection across payload and header fields, argument validation.
4. TestCipSafetyWirelessMeshFrame: CipSafetyWirelessMeshFrame dataclass, calculation, verification, pack/unpack
   wire format serialization, mutation detection, and frame constructor helpers.
5. TestEngineInitializationAndDefaults: CipSafetyWirelessMeshEngine initialization with/without RegisterTable,
   auto_activate behaviors, reset behaviors, metadata and compatibility aliases.
6. TestMultiHopRoutingAndForwarding: Dynamic route selection, lowest ETX and hop count optimization,
   destination filtering, empty table handling, multi-hop metric scaling.
7. TestLinkQualityEvaluationAndFailover: Dynamic route fallback on low RSSI (< -82 dBm) and packet loss (> 5.0%),
   failover count, alarm assertion (%M563), failover failure when no alternate route exists.
8. TestDynamicWatchdogAndLatencyCompensation: Dynamic threshold scaling (base_timeout + hop_count * hop_delay),
   effective timeout calculations across hop counts, watchdog accumulation, kicking, and timeout trip (0x03 TIMEOUT_EXPIRED).
9. TestFrameTransmissionAndProcessing: Outgoing frame creation and transmit sequence advancing, incoming frame
   verification, dual CRC checking, SNN verification, safe input updates, and recovery.
10. TestFailSafeStateAndFaultHandling: Safe state transitions, de-energization (zero outputs, %M562 cleared),
    CRC corruption trips, network partition / SNN mismatch trip (0x07 SPLIT_BRAIN_PARTITION), engine reset recovery.
11. TestRegisterTableSynchronization: Bit-exact register synchronization (%R2410..%R2417, %M562..%M563),
    privilege mode support, boundary value packing, scaled RSSI & LQI, packet loss rate scaling.
12. TestILogicUnitCompliance: ILogicUnit interface compliance (scan_step, step, execute, reset), sequence counter
    progression, strict 4-state ExecutionResult contract, and 100-cycle soak scan.
13. TestPureStructuredTextAndSecurity: Pure IEC 61131-3 ST POU AST validation with STParser, bound register
    verification (%R2410..%R2417, %M562..%M563), and anti-ladder construct rejection with LadderForbiddenError.
14. TestVerificationRunner9StagesAndEvidence: 9-stage verification suite run_cip_safety_wireless_mesh_verification,
    strict 4-state contract validation, and JSON evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_wireless_mesh import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_WIRELESS_MESH_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    DEFAULT_NODE_ID,
    DEFAULT_PAN_ID,
    DEFAULT_CHANNEL,
    DEFAULT_BASE_TIMEOUT_MS,
    DEFAULT_HOP_DELAY_MS,
    DEFAULT_RSSI_DBM,
    DEFAULT_LQI,
    DEFAULT_RSSI_THRESHOLD_DBM,
    DEFAULT_PACKET_LOSS_THRESHOLD,
    DEFAULT_PACKET_LOSS_RATE,
    DEFAULT_SAFETY_TIMEOUT_MS,
    CRC_POLY_1021,
    CRC_POLY_8408,
    CRC16_CCITT_POLY,
    CIP_SAFETY_CRC_INIT,
    REG_WIRELESS_MESH_NODE_STATUS,
    REG_WIRELESS_MESH_CHANNEL_PAN,
    REG_WIRELESS_MESH_LINK_QUALITY,
    REG_WIRELESS_MESH_HOP_METRIC,
    REG_WIRELESS_MESH_SNN_HIGH,
    REG_WIRELESS_MESH_SNN_LOW,
    REG_WIRELESS_MESH_PACKET_LOSS,
    REG_WIRELESS_MESH_DIAGNOSTIC_CODE,
    REG_NODE_STATUS,
    REG_CHANNEL_PAN,
    REG_LINK_QUALITY,
    REG_HOP_METRIC,
    REG_SNN_HIGH,
    REG_SNN_LOW,
    REG_PACKET_LOSS,
    REG_DIAGNOSTIC_CODE,
    COIL_WIRELESS_MESH_ROUTE_ACTIVE,
    COIL_WIRELESS_MESH_PATH_FAILOVER,
    COIL_ROUTE_ACTIVE,
    COIL_SAFETY_ESTABLISHED,
    COIL_PATH_FAILOVER,
    COIL_DEGRADATION_ALARM,
    CipSafetyWirelessMeshState,
    CipSafetyWirelessMeshDiagnosticCode,
    DiagnosticCode,
    DIAG_OK,
    DIAG_CRC_S1_ERROR,
    DIAG_CRC_S2_ERROR,
    DIAG_TIMEOUT_EXPIRED,
    DIAG_ROUTE_UNREACHABLE,
    DIAG_RSSI_BELOW_THRESHOLD,
    DIAG_PACKET_LOSS_HIGH,
    DIAG_SPLIT_BRAIN_PARTITION,
    CipSafetyWirelessMeshError,
    CrcS1CorruptionError,
    CrcS2CorruptionError,
    SafetyTimeoutExpiredError,
    RouteUnreachableError,
    SplitBrainPartitionError,
    WirelessMeshNode,
    WirelessMeshRoute,
    CipSafetyWirelessMeshFrame,
    CipSafetyWirelessMeshEngine,
    CIPSafetyWirelessMeshEngine,
    CIPSafetyWirelessMesh,
    WirelessMeshSafetyEngine,
    compute_crc16,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    create_valid_frame,
    create_valid_packet,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC,
    CIP_SAFETY_WIRELESS_MESH_SYNC_POU,
    CIP_SAFETY_WIRELESS_MESH_PURE_ST_POU,
    CipSafetyWirelessMeshSync,
    verify_cip_safety_wireless_mesh_pure_st,
    run_cip_safety_wireless_mesh_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Over Wireless Mesh constants, enums, and diagnostic codes."""

    def test_protocol_constants_and_defaults(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_WIRELESS_MESH_CLASS_ID == 0x2F
        assert DEFAULT_SAFETY_NETWORK_NUMBER == 0x00012345
        assert DEFAULT_SNN == 0x00012345
        assert DEFAULT_NODE_ID == 1
        assert DEFAULT_PAN_ID == 0x1A2B
        assert DEFAULT_CHANNEL == 15
        assert DEFAULT_BASE_TIMEOUT_MS == 200.0
        assert DEFAULT_SAFETY_TIMEOUT_MS == 200.0
        assert DEFAULT_HOP_DELAY_MS == 25.0
        assert DEFAULT_RSSI_DBM == -65.0
        assert DEFAULT_LQI == 220
        assert DEFAULT_RSSI_THRESHOLD_DBM == -82.0
        assert DEFAULT_PACKET_LOSS_THRESHOLD == 0.05
        assert DEFAULT_PACKET_LOSS_RATE == 0.002
        assert CRC_POLY_1021 == 0x1021
        assert CRC16_CCITT_POLY == 0x1021
        assert CRC_POLY_8408 == 0x8408
        assert CIP_SAFETY_CRC_INIT == 0xFFFF

    def test_register_and_coil_addresses(self) -> None:
        assert REG_WIRELESS_MESH_NODE_STATUS == "%R2410"
        assert REG_WIRELESS_MESH_CHANNEL_PAN == "%R2411"
        assert REG_WIRELESS_MESH_LINK_QUALITY == "%R2412"
        assert REG_WIRELESS_MESH_HOP_METRIC == "%R2413"
        assert REG_WIRELESS_MESH_SNN_HIGH == "%R2414"
        assert REG_WIRELESS_MESH_SNN_LOW == "%R2415"
        assert REG_WIRELESS_MESH_PACKET_LOSS == "%R2416"
        assert REG_WIRELESS_MESH_DIAGNOSTIC_CODE == "%R2417"

        assert COIL_WIRELESS_MESH_ROUTE_ACTIVE == "%M562"
        assert COIL_WIRELESS_MESH_PATH_FAILOVER == "%M563"

    def test_register_and_coil_alias_constants(self) -> None:
        assert REG_NODE_STATUS == REG_WIRELESS_MESH_NODE_STATUS
        assert REG_CHANNEL_PAN == REG_WIRELESS_MESH_CHANNEL_PAN
        assert REG_LINK_QUALITY == REG_WIRELESS_MESH_LINK_QUALITY
        assert REG_HOP_METRIC == REG_WIRELESS_MESH_HOP_METRIC
        assert REG_SNN_HIGH == REG_WIRELESS_MESH_SNN_HIGH
        assert REG_SNN_LOW == REG_WIRELESS_MESH_SNN_LOW
        assert REG_PACKET_LOSS == REG_WIRELESS_MESH_PACKET_LOSS
        assert REG_DIAGNOSTIC_CODE == REG_WIRELESS_MESH_DIAGNOSTIC_CODE

        assert COIL_ROUTE_ACTIVE == COIL_WIRELESS_MESH_ROUTE_ACTIVE
        assert COIL_SAFETY_ESTABLISHED == COIL_WIRELESS_MESH_ROUTE_ACTIVE
        assert COIL_PATH_FAILOVER == COIL_WIRELESS_MESH_PATH_FAILOVER
        assert COIL_DEGRADATION_ALARM == COIL_WIRELESS_MESH_PATH_FAILOVER

    def test_state_enum_values(self) -> None:
        assert CipSafetyWirelessMeshState.INIT == 0
        assert CipSafetyWirelessMeshState.OPERATIONAL == 1
        assert CipSafetyWirelessMeshState.DEGRADED == 2
        assert CipSafetyWirelessMeshState.FAIL_SAFE == 3

        assert CipSafetyWirelessMeshState(0).name == "INIT"
        assert CipSafetyWirelessMeshState(1).name == "OPERATIONAL"
        assert CipSafetyWirelessMeshState(2).name == "DEGRADED"
        assert CipSafetyWirelessMeshState(3).name == "FAIL_SAFE"

    def test_diagnostic_code_enum_values_and_hash(self) -> None:
        assert CipSafetyWirelessMeshDiagnosticCode.OK == 0
        assert CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR == 1
        assert CipSafetyWirelessMeshDiagnosticCode.CRC_S2_ERROR == 2
        assert CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED == 3
        assert CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE == 4
        assert CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD == 5
        assert CipSafetyWirelessMeshDiagnosticCode.PACKET_LOSS_HIGH == 6
        assert CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION == 7

        # Hashing capability for dictionary and set storage
        code_dict = {
            CipSafetyWirelessMeshDiagnosticCode.OK: "healthy",
            CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR: "crc_s1",
            CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED: "timeout",
        }
        assert code_dict[CipSafetyWirelessMeshDiagnosticCode.OK] == "healthy"
        assert hash(CipSafetyWirelessMeshDiagnosticCode.OK) == hash(0)

        code_set = {CipSafetyWirelessMeshDiagnosticCode.OK, CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED}
        assert len(code_set) == 2
        assert CipSafetyWirelessMeshDiagnosticCode.OK in code_set

    def test_diagnostic_code_comparisons_and_operators(self) -> None:
        diag = CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED
        assert diag == 3
        assert diag == CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED
        assert diag != 0
        assert int(diag) == 3
        assert (diag & 0xFFFF) == 3
        assert (3 & diag) == 3
        assert (diag | 0x00) == 3
        assert "TIMEOUT_EXPIRED" in str(diag)
        assert repr(diag).startswith("CipSafetyWirelessMeshDiagnosticCode.")

    def test_diagnostic_code_module_aliases(self) -> None:
        assert DiagnosticCode is CipSafetyWirelessMeshDiagnosticCode
        assert DIAG_OK == CipSafetyWirelessMeshDiagnosticCode.OK
        assert DIAG_CRC_S1_ERROR == CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR
        assert DIAG_CRC_S2_ERROR == CipSafetyWirelessMeshDiagnosticCode.CRC_S2_ERROR
        assert DIAG_TIMEOUT_EXPIRED == CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED
        assert DIAG_ROUTE_UNREACHABLE == CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE
        assert DIAG_RSSI_BELOW_THRESHOLD == CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD
        assert DIAG_PACKET_LOSS_HIGH == CipSafetyWirelessMeshDiagnosticCode.PACKET_LOSS_HIGH
        assert DIAG_SPLIT_BRAIN_PARTITION == CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION


# ============================================================================
# 2. TestNodeAndRouteDataclasses
# ============================================================================

class TestNodeAndRouteDataclasses:
    """Validate IEEE 802.15.4 / 6LoWPAN node and routing dataclasses."""

    def test_mesh_node_defaults(self) -> None:
        node = WirelessMeshNode()
        assert node.node_id == DEFAULT_NODE_ID
        assert node.pan_id == DEFAULT_PAN_ID
        assert node.channel == DEFAULT_CHANNEL
        assert node.parent_id == 0
        assert node.hop_count == 1
        assert node.rssi_dbm == DEFAULT_RSSI_DBM
        assert node.lqi == DEFAULT_LQI
        assert node.is_coordinator is False

    def test_mesh_node_custom_and_coordinator(self) -> None:
        coord = WirelessMeshNode(
            node_id=0,
            pan_id=0x2000,
            channel=26,
            parent_id=0,
            hop_count=0,
            rssi_dbm=-45.0,
            lqi=255,
            is_coordinator=True,
        )
        assert coord.node_id == 0
        assert coord.pan_id == 0x2000
        assert coord.channel == 26
        assert coord.hop_count == 0
        assert coord.rssi_dbm == -45.0
        assert coord.lqi == 255
        assert coord.is_coordinator is True

    def test_mesh_route_defaults(self) -> None:
        route = WirelessMeshRoute()
        assert route.route_id == 1
        assert route.destination_id == 2
        assert route.next_hop_id == 2
        assert route.hop_count == 1
        assert route.path_etx == 1.0
        assert route.path_latency_ms == 12.0
        assert route.is_active is True

    def test_mesh_route_custom(self) -> None:
        route = WirelessMeshRoute(
            route_id=99,
            destination_id=10,
            next_hop_id=3,
            hop_count=4,
            path_etx=2.5,
            path_latency_ms=60.0,
            is_active=False,
        )
        assert route.route_id == 99
        assert route.destination_id == 10
        assert route.next_hop_id == 3
        assert route.hop_count == 4
        assert route.path_etx == 2.5
        assert route.path_latency_ms == 60.0
        assert route.is_active is False

    def test_node_and_route_equality_and_repr(self) -> None:
        n1 = WirelessMeshNode(node_id=1, pan_id=100)
        n2 = WirelessMeshNode(node_id=1, pan_id=100)
        n3 = WirelessMeshNode(node_id=2, pan_id=100)
        assert n1 == n2
        assert n1 != n3
        assert "WirelessMeshNode" in repr(n1)

        r1 = WirelessMeshRoute(route_id=1, destination_id=2)
        r2 = WirelessMeshRoute(route_id=1, destination_id=2)
        r3 = WirelessMeshRoute(route_id=2, destination_id=2)
        assert r1 == r2
        assert r1 != r3
        assert "WirelessMeshRoute" in repr(r1)


# ============================================================================
# 3. TestDualSafetyCrcCalculation
# ============================================================================

class TestDualSafetyCrcCalculation:
    """Validate 16-bit CRC-S1 and CRC-S2 dual safety checksums."""

    def test_crc16_poly_1021_deterministic(self) -> None:
        payload = b"123456789"
        crc1 = compute_crc16(payload, poly=0x1021, init=0xFFFF)
        crc2 = compute_crc16(payload, poly=0x1021, init=0xFFFF)
        assert crc1 == crc2
        assert crc1 == 0x29B1  # Standard CCITT-16 check value

    def test_crc16_poly_8408_reflected(self) -> None:
        payload = b"123456789"
        crc1 = compute_crc16(payload, poly=0x8408, init=0xFFFF)
        crc2 = compute_crc16(payload, poly=0x8408, init=0xFFFF)
        assert crc1 == crc2
        assert isinstance(crc1, int)
        assert 0 <= crc1 <= 0xFFFF

    def test_crc_s1_over_payload_and_alias(self) -> None:
        data = b"\x01\x02\x03\x04"
        crc_s1 = compute_crc_s1(data)
        crc_alias = calc_crc_s1(data)
        assert crc_s1 == crc_alias
        assert isinstance(crc_s1, int)
        assert 0 <= crc_s1 <= 0xFFFF

    def test_crc_s1_multi_chunk_and_list_support(self) -> None:
        c1 = compute_crc_s1(b"\x01\x02", b"\x03\x04")
        c2 = compute_crc_s1(b"\x01\x02\x03\x04")
        assert c1 == c2

        c3 = compute_crc_s1([0x01, 0x02, 0x03, 0x04])
        assert c3 == c2

    def test_crc_s1_invalid_arguments_raise_error(self) -> None:
        with pytest.raises(ValueError):
            compute_crc_s1(12345)  # Int not supported directly without bytes

    def test_crc_s2_over_header_and_crc_s1_and_alias(self) -> None:
        snn = 0x00012345
        seq = 10
        ts = 5000
        crc_s1 = 0xABCD
        crc_s2 = compute_crc_s2(snn, seq, ts, crc_s1)
        crc_alias = calc_crc_s2(snn, seq, ts, crc_s1)
        assert crc_s2 == crc_alias
        assert isinstance(crc_s2, int)
        assert 0 <= crc_s2 <= 0xFFFF

    def test_crc_s2_keyword_args_and_raw_bytes(self) -> None:
        snn = 0x00012345
        seq = 10
        ts = 5000
        crc_s1 = 0xABCD
        c_pos = compute_crc_s2(snn, seq, ts, crc_s1)
        c_kw = compute_crc_s2(snn=snn, seq=seq, ts=ts, crc_s1=crc_s1)
        assert c_pos == c_kw

        raw_header = struct.pack(">IHIH", snn, seq, ts, crc_s1)
        c_raw = compute_crc_s2(raw_header)
        assert c_pos == c_raw

    def test_crc_s1_and_crc_s2_distinctness(self) -> None:
        payload = b"\x01\x02\x03\x04"
        crc_s1 = compute_crc_s1(payload)
        crc_s2 = compute_crc_s2(DEFAULT_SNN, 1, 1000, crc_s1)
        assert crc_s1 != crc_s2

    def test_single_bit_tamper_detection_across_all_payload_bits(self) -> None:
        base_payload = b"\x11\x22\x33\x44"
        nominal_crc = compute_crc_s1(base_payload)

        for byte_idx in range(len(base_payload)):
            for bit_idx in range(8):
                ba = bytearray(base_payload)
                ba[byte_idx] ^= (1 << bit_idx)
                mutated_crc = compute_crc_s1(bytes(ba))
                assert mutated_crc != nominal_crc, f"Failed tamper detection at byte {byte_idx}, bit {bit_idx}"

    def test_header_tamper_detection_in_crc_s2(self) -> None:
        snn = 0x00012345
        seq = 10
        ts = 5000
        crc_s1 = 0xABCD
        nominal_s2 = compute_crc_s2(snn, seq, ts, crc_s1)

        # Alter SNN
        assert compute_crc_s2(snn ^ 1, seq, ts, crc_s1) != nominal_s2
        # Alter sequence
        assert compute_crc_s2(snn, seq ^ 1, ts, crc_s1) != nominal_s2
        # Alter timestamp
        assert compute_crc_s2(snn, seq, ts ^ 1, crc_s1) != nominal_s2
        # Alter CRC-S1
        assert compute_crc_s2(snn, seq, ts, crc_s1 ^ 1) != nominal_s2


# ============================================================================
# 4. TestCipSafetyWirelessMeshFrame
# ============================================================================

class TestCipSafetyWirelessMeshFrame:
    """Validate CipSafetyWirelessMeshFrame serialization, verification, and mutation."""

    def test_frame_defaults_and_initialization(self) -> None:
        frame = CipSafetyWirelessMeshFrame()
        assert frame.safety_network_number == DEFAULT_SNN
        assert frame.node_id == 1
        assert frame.sequence_number == 1
        assert frame.timestamp_ms == 1000
        assert frame.payload_bytes == b"\x00\x00\x00\x00"
        assert frame.crc_s1 == 0
        assert frame.crc_s2 == 0

    def test_frame_calculate_and_populate_crcs(self) -> None:
        frame = CipSafetyWirelessMeshFrame(payload_bytes=b"\x05\x06\x07\x08")
        assert frame.crc_s1 == 0
        assert frame.crc_s2 == 0

        frame.calculate_crcs()
        assert frame.crc_s1 != 0
        assert frame.crc_s2 != 0
        assert frame.verify_crc_s1() is True
        assert frame.verify_crc_s2() is True
        assert frame.is_valid() is True

    def test_frame_populate_crcs_alias(self) -> None:
        frame = CipSafetyWirelessMeshFrame(payload_bytes=b"\xAA\xBB\xCC\xDD")
        frame.populate_crcs()
        assert frame.is_valid() is True

    def test_frame_verification_methods(self) -> None:
        frame = create_valid_frame(payload_bytes=b"\x10\x20\x30\x40")
        assert frame.verify_crc_s1() is True
        assert frame.verify_crc_s2() is True
        assert frame.is_valid() is True
        assert frame.verify_crcs() == (True, True)

        # Invalidate CRC-S1
        frame.crc_s1 ^= 0xFFFF
        assert frame.verify_crc_s1() is False
        assert frame.is_valid() is False
        assert frame.verify_crcs() == (False, False)

    def test_frame_mutation_detection_at_offsets(self) -> None:
        for offset in [0, 1, 2, 3]:
            frame = create_valid_frame(payload_bytes=b"\x10\x20\x30\x40")
            assert frame.is_valid() is True
            frame.mutate_payload(byte_offset=offset, bit_pos=offset)
            assert frame.verify_crc_s1() is False
            assert frame.is_valid() is False

    def test_frame_wire_packing_and_unpacking(self) -> None:
        original = create_valid_frame(
            safety_network_number=0x12345678,
            node_id=5,
            sequence_number=42,
            timestamp_ms=123456,
            payload_bytes=b"\xAA\xBB\xCC\xDD",
        )
        packed = original.pack()
        assert len(packed) == 13 + len(original.payload_bytes) + 4  # 13 + 4 + 4 = 21 bytes

        unpacked = CipSafetyWirelessMeshFrame.unpack(packed)
        assert unpacked.safety_network_number == original.safety_network_number
        assert unpacked.node_id == original.node_id
        assert unpacked.sequence_number == original.sequence_number
        assert unpacked.timestamp_ms == original.timestamp_ms
        assert unpacked.payload_bytes == original.payload_bytes
        assert unpacked.crc_s1 == original.crc_s1
        assert unpacked.crc_s2 == original.crc_s2
        assert unpacked.is_valid() is True

    def test_frame_unpack_invalid_or_short_raises(self) -> None:
        with pytest.raises(ValueError):
            CipSafetyWirelessMeshFrame.unpack(b"\x00" * 10)  # Shorter than 17 bytes

        short_packed = create_valid_frame().pack()[:-2]  # Truncated trailer
        with pytest.raises(ValueError):
            CipSafetyWirelessMeshFrame.unpack(short_packed)

    def test_create_valid_frame_and_create_valid_packet_helpers(self) -> None:
        f1 = create_valid_frame(node_id=2, sequence_number=10)
        assert f1.is_valid() is True
        assert f1.node_id == 2
        assert f1.sequence_number == 10

        f2 = create_valid_packet(node_id=3, sequence_number=20)
        assert f2.is_valid() is True
        assert f2.node_id == 3
        assert f2.sequence_number == 20


# ============================================================================
# 5. TestEngineInitializationAndDefaults
# ============================================================================

class TestEngineInitializationAndDefaults:
    """Validate CipSafetyWirelessMeshEngine initialization, configuration, and defaults."""

    def test_engine_initialization_defaults_no_regtable(self) -> None:
        eng = CipSafetyWirelessMeshEngine()
        assert eng.name == "CipSafetyWirelessMeshEngine"
        assert eng.priority == 10
        assert eng.is_enabled is True
        assert eng.is_healthy is True
        assert eng.is_operational is True
        assert eng.is_fail_safe is False
        assert eng.is_failover_active is False
        assert eng.state == CipSafetyWirelessMeshState.OPERATIONAL
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK
        assert eng.safety_network_number == DEFAULT_SNN
        assert eng.local_node.node_id == DEFAULT_NODE_ID
        assert eng.active_route is not None
        assert eng.active_route.route_id == 1
        assert eng.tx_sequence == 0
        assert eng.rx_sequence == 0
        assert eng.cycles_count == 0
        assert eng.watchdog_timer_ms == 0.0

    def test_engine_initialization_with_regtable(self) -> None:
        rt = RegisterTable()
        eng = CipSafetyWirelessMeshEngine(register_table=rt, auto_activate=True)
        assert eng.register_table is rt
        # Verify initial sync occurred
        assert rt.read_uword(REG_WIRELESS_MESH_NODE_STATUS) & 0xFF == DEFAULT_NODE_ID
        assert rt.read_bit(COIL_WIRELESS_MESH_ROUTE_ACTIVE) is True

    def test_engine_initialization_auto_activate_false(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=False)
        assert eng.state == CipSafetyWirelessMeshState.INIT
        assert eng.is_healthy is False
        assert eng.is_operational is False
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK

    def test_engine_custom_config_parameters(self) -> None:
        custom_node = WirelessMeshNode(node_id=7, pan_id=0x9999, channel=20, rssi_dbm=-60.0, lqi=240)
        custom_route = WirelessMeshRoute(route_id=42, destination_id=9, next_hop_id=9, hop_count=3, is_active=True)
        eng = CipSafetyWirelessMeshEngine(
            safety_network_number=0x87654321,
            local_node=custom_node,
            routes=[custom_route],
            base_timeout_ms=300.0,
            hop_delay_ms=30.0,
            rssi_threshold_dbm=-85.0,
            packet_loss_threshold=0.08,
        )
        assert eng.safety_network_number == 0x87654321
        assert eng.local_node.node_id == 7
        assert eng.active_route.route_id == 42
        assert eng.base_timeout_ms == 300.0
        assert eng.hop_delay_ms == 30.0
        assert eng.rssi_threshold_dbm == -85.0
        assert eng.packet_loss_threshold == 0.08

    def test_engine_reset_operator_reset_fault_reset(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        eng.trip_watchdog_timeout()
        assert eng.is_fail_safe is True
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED

        # operator_reset
        eng.operator_reset()
        assert eng.is_healthy is True
        assert eng.state == CipSafetyWirelessMeshState.OPERATIONAL
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK
        assert eng.watchdog_timer_ms == 0.0

        # fault_reset
        eng.trip_crc_s1_error()
        assert eng.is_fail_safe is True
        eng.fault_reset()
        assert eng.is_healthy is True
        assert eng.state == CipSafetyWirelessMeshState.OPERATIONAL

    def test_engine_compatibility_aliases(self) -> None:
        assert CIPSafetyWirelessMeshEngine is CipSafetyWirelessMeshEngine
        assert CIPSafetyWirelessMesh is CipSafetyWirelessMeshEngine
        assert WirelessMeshSafetyEngine is CipSafetyWirelessMeshEngine


# ============================================================================
# 6. TestMultiHopRoutingAndForwarding
# ============================================================================

class TestMultiHopRoutingAndForwarding:
    """Validate multi-hop routing, best route selection, and path metrics."""

    def test_add_route_to_routing_table(self) -> None:
        r1 = WirelessMeshRoute(route_id=10, destination_id=2, next_hop_id=2, is_active=True)
        eng = CipSafetyWirelessMeshEngine(routes=[r1])
        assert len(eng.routes) == 1
        assert eng.active_route is r1

        r2 = WirelessMeshRoute(route_id=20, destination_id=2, next_hop_id=3, is_active=False)
        eng.add_route(r2)
        assert len(eng.routes) == 2
        assert eng.active_route is r1  # Active route maintained

    def test_select_best_route_lowest_etx_and_hop_count(self) -> None:
        r1 = WirelessMeshRoute(route_id=1, destination_id=2, next_hop_id=2, hop_count=3, path_etx=2.5)
        r2 = WirelessMeshRoute(route_id=2, destination_id=2, next_hop_id=3, hop_count=2, path_etx=1.5)
        r3 = WirelessMeshRoute(route_id=3, destination_id=2, next_hop_id=4, hop_count=1, path_etx=1.5)

        eng = CipSafetyWirelessMeshEngine(routes=[r1, r2, r3])
        best = eng.select_best_route(destination_id=2)
        assert best is not None
        assert best.route_id == 3  # Equal ETX, lower hop count

    def test_select_best_route_by_destination_id(self) -> None:
        r1 = WirelessMeshRoute(route_id=1, destination_id=5, next_hop_id=5, hop_count=1, path_etx=1.0)
        r2 = WirelessMeshRoute(route_id=2, destination_id=8, next_hop_id=8, hop_count=1, path_etx=1.0)
        eng = CipSafetyWirelessMeshEngine(routes=[r1, r2])

        best5 = eng.select_best_route(destination_id=5)
        assert best5 is not None
        assert best5.route_id == 1

        best8 = eng.select_best_route(destination_id=8)
        assert best8 is not None
        assert best8.route_id == 2

    def test_select_best_route_empty_routes(self) -> None:
        eng = CipSafetyWirelessMeshEngine(routes=[])
        assert eng.select_best_route(destination_id=99) is None

    def test_multi_hop_route_traversal_metric_scaling(self) -> None:
        # Route 3-hop, ETX 2.4
        route3 = WirelessMeshRoute(route_id=3, hop_count=3, path_etx=2.4, is_active=True)
        rt = RegisterTable()
        eng = CipSafetyWirelessMeshEngine(register_table=rt, routes=[route3], auto_activate=True)

        # %R2413: hop_count in lower byte, ETX x10 in upper byte
        reg_val = rt.read_uword(REG_WIRELESS_MESH_HOP_METRIC)
        lower_hop = reg_val & 0xFF
        upper_etx = (reg_val >> 8) & 0xFF

        assert lower_hop == 3
        assert upper_etx == 24  # 2.4 * 10 = 24


# ============================================================================
# 7. TestLinkQualityEvaluationAndFailover
# ============================================================================

class TestLinkQualityEvaluationAndFailover:
    """Validate dynamic route alternate path failover under RF degradation."""

    def test_evaluate_link_quality_nominal_stays_operational(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        res = eng.evaluate_link_quality(rssi_dbm=-65.0, packet_loss=0.002)
        assert res is True
        assert eng.state == CipSafetyWirelessMeshState.OPERATIONAL
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK
        assert eng.is_path_failover is False

    def test_dynamic_fallback_on_rssi_threshold(self) -> None:
        r1 = WirelessMeshRoute(route_id=1, destination_id=2, next_hop_id=2, hop_count=1, is_active=True)
        r2 = WirelessMeshRoute(route_id=2, destination_id=2, next_hop_id=3, hop_count=2, is_active=False)
        eng = CipSafetyWirelessMeshEngine(routes=[r1, r2], auto_activate=True)
        assert eng.active_route.route_id == 1
        assert not eng.is_path_failover

        # Degrade RSSI to -85 dBm (< -82 dBm)
        ok = eng.evaluate_link_quality(rssi_dbm=-85.0)
        assert ok is True
        assert eng.state == CipSafetyWirelessMeshState.DEGRADED
        assert eng.active_route.route_id == 2
        assert eng.is_failover_active is True
        assert eng.failover_count == 1
        assert eng.is_path_failover is True

    def test_dynamic_fallback_on_high_packet_loss(self) -> None:
        r1 = WirelessMeshRoute(route_id=1, destination_id=2, next_hop_id=2, hop_count=1, is_active=True)
        r2 = WirelessMeshRoute(route_id=2, destination_id=2, next_hop_id=3, hop_count=2, is_active=False)
        eng = CipSafetyWirelessMeshEngine(routes=[r1, r2], auto_activate=True)

        # Degrade packet loss to 8% (> 5.0%)
        ok = eng.evaluate_link_quality(packet_loss=0.08)
        assert ok is True
        assert eng.state == CipSafetyWirelessMeshState.DEGRADED
        assert eng.active_route.route_id == 2
        assert eng.is_failover_active is True
        assert eng.is_path_failover is True

    def test_failover_count_increments_on_repeated_failovers(self) -> None:
        r1 = WirelessMeshRoute(route_id=1, destination_id=2, next_hop_id=2, hop_count=1, is_active=True)
        r2 = WirelessMeshRoute(route_id=2, destination_id=2, next_hop_id=3, hop_count=2, is_active=False)
        eng = CipSafetyWirelessMeshEngine(routes=[r1, r2], auto_activate=True)

        eng.evaluate_link_quality(rssi_dbm=-85.0)
        assert eng.failover_count == 1

        # Now r2 is active, fail back to r1 if r2 degrades
        eng.evaluate_link_quality(rssi_dbm=-88.0)
        assert eng.failover_count == 2
        assert eng.active_route.route_id == 1

    def test_fallback_failure_when_no_alternate_route_rssi(self) -> None:
        r1 = WirelessMeshRoute(route_id=1, destination_id=2, next_hop_id=2, hop_count=1, is_active=True)
        eng = CipSafetyWirelessMeshEngine(routes=[r1], auto_activate=True)

        ok = eng.evaluate_link_quality(rssi_dbm=-90.0)
        assert ok is False
        assert eng.state == CipSafetyWirelessMeshState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD
        assert eng.safe_outputs == b"\x00\x00\x00\x00"

    def test_fallback_failure_when_no_alternate_route_packet_loss(self) -> None:
        r1 = WirelessMeshRoute(route_id=1, destination_id=2, next_hop_id=2, hop_count=1, is_active=True)
        eng = CipSafetyWirelessMeshEngine(routes=[r1], auto_activate=True)

        ok = eng.evaluate_link_quality(packet_loss=0.15)
        assert ok is False
        assert eng.state == CipSafetyWirelessMeshState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.PACKET_LOSS_HIGH
        assert eng.safe_outputs == b"\x00\x00\x00\x00"


# ============================================================================
# 8. TestDynamicWatchdogAndLatencyCompensation
# ============================================================================

class TestDynamicWatchdogAndLatencyCompensation:
    """Validate dynamic multi-hop latency compensated safety watchdog."""

    def test_watchdog_threshold_scaling_with_hop_count(self) -> None:
        eng = CipSafetyWirelessMeshEngine(base_timeout_ms=200.0, hop_delay_ms=25.0)
        assert eng.get_effective_watchdog_timeout_ms(hop_count=0) == 200.0
        assert eng.get_effective_watchdog_timeout_ms(hop_count=1) == 225.0
        assert eng.get_effective_watchdog_timeout_ms(hop_count=2) == 250.0
        assert eng.get_effective_watchdog_timeout_ms(hop_count=3) == 275.0
        assert eng.get_effective_watchdog_timeout_ms(hop_count=4) == 300.0

    def test_effective_timeout_property(self) -> None:
        r = WirelessMeshRoute(route_id=1, hop_count=3, is_active=True)
        eng = CipSafetyWirelessMeshEngine(routes=[r], base_timeout_ms=150.0, hop_delay_ms=20.0)
        # 150 + 3 * 20 = 210 ms
        assert eng.effective_timeout_ms == 210.0

    def test_watchdog_timer_accumulation_in_scan_step(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True, base_timeout_ms=500.0)
        assert eng.watchdog_timer_ms == 0.0

        eng.scan_step(0.010)
        assert eng.watchdog_timer_ms == pytest.approx(10.0)

        eng.scan_step(0.015)
        assert eng.watchdog_timer_ms == pytest.approx(25.0)

    def test_feed_and_kick_watchdog_resets_timer(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        eng.scan_step(0.050)
        assert eng.watchdog_timer_ms == pytest.approx(50.0)

        eng.feed_watchdog()
        assert eng.watchdog_timer_ms == 0.0

        eng.scan_step(0.030)
        assert eng.watchdog_timer_ms == pytest.approx(30.0)

        eng.kick_watchdog()
        assert eng.watchdog_timer_ms == 0.0

    def test_watchdog_timeout_trip_to_fail_safe(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True, base_timeout_ms=100.0, hop_delay_ms=10.0)
        # Hop count 1 -> effective timeout = 110 ms
        assert eng.is_healthy is True
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK

        # Advance 50 ms (safe)
        eng.scan_step(0.050)
        assert eng.is_healthy is True

        # Advance another 70 ms (total 120 ms > 110 ms -> expired)
        eng.scan_step(0.070)
        assert not eng.is_healthy
        assert eng.state == CipSafetyWirelessMeshState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED
        assert eng.safe_outputs == b"\x00\x00\x00\x00"


# ============================================================================
# 9. TestFrameTransmissionAndProcessing
# ============================================================================

class TestFrameTransmissionAndProcessing:
    """Validate frame generation, transmission progression, and inbound processing."""

    def test_create_frame_and_transmit_frame(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        f_create = eng.create_frame(payload_bytes=b"\x11\x22\x33\x44")
        assert f_create.is_valid() is True
        assert f_create.payload_bytes == b"\x11\x22\x33\x44"
        assert eng.tx_sequence == 0  # create_frame does not advance sequence

        f_tx = eng.transmit_frame(payload_bytes=b"\x55\x66\x77\x88")
        assert f_tx.is_valid() is True
        assert f_tx.payload_bytes == b"\x55\x66\x77\x88"
        assert eng.tx_sequence == 1
        assert f_tx.sequence_number == 1

        f_tx2 = eng.transmit_frame()
        assert eng.tx_sequence == 2
        assert f_tx2.sequence_number == 2

    def test_process_frame_nominal_success(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        frame = create_valid_frame(
            safety_network_number=eng.safety_network_number,
            node_id=2,
            sequence_number=101,
            payload_bytes=b"\xCA\xFE\xBA\xBE",
        )
        res = eng.process_frame(frame)
        assert res is True
        assert eng.rx_sequence == 101
        assert eng.safe_inputs == b"\xCA\xFE\xBA\xBE"
        assert eng.frames_processed == 1
        assert eng.watchdog_timer_ms == 0.0

    def test_process_frame_crc_s1_corruption_trips_fail_safe(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        frame = create_valid_frame(safety_network_number=eng.safety_network_number)
        frame.crc_s1 ^= 0x1234  # Corrupt CRC-S1

        res = eng.process_frame(frame)
        assert res is False
        assert eng.state == CipSafetyWirelessMeshState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR
        assert eng.safe_outputs == b"\x00\x00\x00\x00"

    def test_process_frame_crc_s2_corruption_trips_fail_safe(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        frame = create_valid_frame(safety_network_number=eng.safety_network_number)
        frame.crc_s2 ^= 0x5678  # Corrupt CRC-S2

        res = eng.process_frame(frame)
        assert res is False
        assert eng.state == CipSafetyWirelessMeshState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.CRC_S2_ERROR
        assert eng.safe_outputs == b"\x00\x00\x00\x00"

    def test_process_frame_snn_mismatch_trips_split_brain(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True, safety_network_number=0x11112222)
        frame = create_valid_frame(safety_network_number=0x99998888)  # Different SNN

        res = eng.process_frame(frame)
        assert res is False
        assert eng.state == CipSafetyWirelessMeshState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION
        assert eng.safe_outputs == b"\x00\x00\x00\x00"

    def test_process_frame_recovers_init_state(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=False)
        assert eng.state == CipSafetyWirelessMeshState.INIT

        frame = create_valid_frame(safety_network_number=eng.safety_network_number)
        res = eng.process_frame(frame)
        assert res is True
        assert eng.state == CipSafetyWirelessMeshState.OPERATIONAL


# ============================================================================
# 10. TestFailSafeStateAndFaultHandling
# ============================================================================

class TestFailSafeStateAndFaultHandling:
    """Validate fail-safe state entry, output de-energizing, and fault trips."""

    def test_direct_trip_fail_safe(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        eng.trip_fail_safe(CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE, reason="Manual trip")
        assert eng.state == CipSafetyWirelessMeshState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE
        assert eng.safe_outputs == b"\x00\x00\x00\x00"

    def test_direct_trip_methods(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)

        eng.trip_crc_s1_error()
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR

        eng.trip_crc_s2_error()
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.CRC_S2_ERROR

        eng.trip_watchdog_timeout()
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED

        eng.trip_route_unreachable()
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE

        eng.trip_rssi_below_threshold()
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD

        eng.trip_packet_loss_high()
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.PACKET_LOSS_HIGH

        eng.trip_split_brain_partition()
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION

    def test_inject_split_brain_partition(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        eng.inject_split_brain_partition()
        assert eng.state == CipSafetyWirelessMeshState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION
        assert eng.safe_outputs == b"\x00\x00\x00\x00"

    def test_engine_reset_recovery_from_fault(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        eng.trip_crc_s1_error()
        assert eng.is_fail_safe is True

        eng.reset()
        assert eng.is_healthy is True
        assert eng.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK
        assert eng.state == CipSafetyWirelessMeshState.OPERATIONAL
        assert eng.safe_outputs == b"\x01\x00\x00\x00"


# ============================================================================
# 11. TestRegisterTableSynchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate bit-exact synchronization to Horner OCS %R2410..%R2417 and %M562..%M563."""

    def test_register_table_sync_nominal(self) -> None:
        rt = RegisterTable()
        node = WirelessMeshNode(node_id=1, pan_id=0x1A2B, channel=15, rssi_dbm=-65.0, lqi=220)
        route = WirelessMeshRoute(route_id=1, hop_count=1, path_etx=1.0, is_active=True)
        eng = CipSafetyWirelessMeshEngine(
            register_table=rt,
            auto_activate=True,
            safety_network_number=0x00012345,
            local_node=node,
            routes=[route],
            packet_loss_rate=0.002,
        )

        # %R2410: node_id=1, state=1 (OPERATIONAL) -> (1 << 8) | 1 = 0x0101
        assert rt.read_uword("%R2410") == ((1 << 8) | 1)

        # %R2411: channel=15, pan_id=0x1A2B -> ((0x2B) << 8) | 15
        assert rt.read_uword("%R2411") == (((0x1A2B & 0xFF) << 8) | 15)

        # %R2412: scaled_rssi = -65 + 100 = 35, lqi = 220 -> (220 << 8) | 35
        assert rt.read_uword("%R2412") == ((220 << 8) | 35)

        # %R2413: hop_count=1, etx_x10 = round(1.0 * 10) = 10 -> (10 << 8) | 1
        assert rt.read_uword("%R2413") == ((10 << 8) | 1)

        # %R2414: SNN high word (0x0001)
        assert rt.read_uword("%R2414") == 0x0001

        # %R2415: SNN low word (0x2345)
        assert rt.read_uword("%R2415") == 0x2345

        # %R2416: packet loss 0.002 -> 0.20% -> 20 units
        assert rt.read_uword("%R2416") == 20

        # %R2417: diagnostic code OK (0)
        assert rt.read_uword("%R2417") == 0

        # Discrete Coils
        assert rt.read_bit("%M562") is True   # Route active
        assert rt.read_bit("%M563") is False  # Path failover alarm false

    def test_register_table_sync_failover_and_fail_safe(self) -> None:
        rt = RegisterTable()
        r1 = WirelessMeshRoute(route_id=1, destination_id=2, next_hop_id=2, hop_count=1, is_active=True)
        r2 = WirelessMeshRoute(route_id=2, destination_id=2, next_hop_id=3, hop_count=2, is_active=False)
        eng = CipSafetyWirelessMeshEngine(register_table=rt, routes=[r1, r2], auto_activate=True)

        # Trigger failover
        eng.evaluate_link_quality(rssi_dbm=-85.0)
        assert rt.read_bit("%M563") is True   # Alarm active!
        # Status code is now DEGRADED (2)
        assert (rt.read_uword("%R2410") >> 8) == 2

        # Trip fail-safe
        eng.trip_crc_s1_error()
        assert rt.read_uword("%R2417") == 1
        assert rt.read_bit("%M562") is False  # Route active bit de-energized!

    def test_register_table_sync_scaled_rssi_boundaries(self) -> None:
        rt = RegisterTable()
        eng = CipSafetyWirelessMeshEngine(register_table=rt, auto_activate=True)

        # Minimum RSSI boundary: -100 dBm -> scaled = 0
        eng.local_node.rssi_dbm = -100.0
        eng.local_node.lqi = 0
        eng.sync_to_registers(rt)
        r2412 = rt.read_uword("%R2412")
        assert (r2412 & 0xFF) == 0
        assert ((r2412 >> 8) & 0xFF) == 0

        # Maximum RSSI boundary: 0 dBm -> scaled = 100
        eng.local_node.rssi_dbm = 0.0
        eng.local_node.lqi = 255
        eng.sync_to_registers(rt)
        r2412 = rt.read_uword("%R2412")
        assert (r2412 & 0xFF) == 100
        assert ((r2412 >> 8) & 0xFF) == 255

    def test_register_table_sync_packet_loss_scaling_formats(self) -> None:
        rt = RegisterTable()
        eng = CipSafetyWirelessMeshEngine(register_table=rt, auto_activate=True)

        # Fractional format (0.05 = 5.0% -> 500 units)
        eng.packet_loss_rate = 0.05
        eng.sync_to_registers(rt)
        assert rt.read_uword("%R2416") == 500

        # Percentage format (5.0 = 5.0% -> 500 units)
        eng.packet_loss_rate = 5.0
        eng.sync_to_registers(rt)
        assert rt.read_uword("%R2416") == 500

    def test_safe_write_helpers_with_privilege(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2410", 0x1234, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_uword("%R2410") == 0x1234

        safe_write_uword(rt, "%R2414", 0xABCD, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_uword("%R2414") == 0xABCD

        safe_write_bit(rt, "%M562", True, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_bit("%M562") is True


# ============================================================================
# 12. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance and scan cycle behavior."""

    def test_ilogicunit_properties(self) -> None:
        eng = CipSafetyWirelessMeshEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "CipSafetyWirelessMeshEngine"
        assert eng.priority == 10
        assert eng.is_enabled is True
        assert eng.is_healthy is True

    def test_scan_step_and_step(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        assert eng.cycles_count == 0
        eng.scan_step(0.010)
        assert eng.cycles_count == 1
        eng.step(0.010)
        assert eng.cycles_count == 2

    def test_execute_success_and_failure(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_s=0.010)
        res = eng.execute(ctx)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert "data" in res.__dict__ or hasattr(res, "data")
        assert res.data["state"] == 1

        # Force failure
        eng.trip_watchdog_timeout()
        res_fail = eng.execute(ctx)
        assert res_fail.status == AgentStatus.FAILED
        assert res_fail.error_code == "TIMEOUT_EXPIRED"
        assert res_fail.data["state"] == 3

    def test_100_cycle_soak_scan(self) -> None:
        eng = CipSafetyWirelessMeshEngine(auto_activate=True)
        for _ in range(100):
            eng.feed_watchdog()
            eng.scan_step(0.005)
        assert eng.cycles_count == 100
        assert eng.is_healthy is True


# ============================================================================
# 13. TestPureStructuredTextAndSecurity
# ============================================================================

class TestPureStructuredTextAndSecurity:
    """Validate pure IEC 61131-3 Structured Text POU and anti-ladder security."""

    def test_pure_st_pou_syntax_and_bound_registers(self) -> None:
        assert verify_cip_safety_wireless_mesh_pure_st() is True

        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2410", "%R2411", "%R2412", "%R2413",
            "%R2414", "%R2415", "%R2416", "%R2417",
            "%M562", "%M563",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_st_program_constant_aliases(self) -> None:
        assert CIP_SAFETY_WIRELESS_MESH_SYNC_POU == ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC
        assert CIP_SAFETY_WIRELESS_MESH_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC
        assert CipSafetyWirelessMeshSync == ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC

    def test_security_guard_assert_pure_st(self) -> None:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC)

    def test_ladder_logic_rejection_contacts(self) -> None:
        bad_code = "PROGRAM BadContacts VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_logic_rejection_coils(self) -> None:
        bad_code = "PROGRAM BadCoils VAR X: BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_logic_rejection_rungs(self) -> None:
        bad_code = "PROGRAM BadRung RUNG 1: X := TRUE; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_logic_rejection_networks(self) -> None:
        bad_code = "PROGRAM BadNetwork NETWORK 1: X := TRUE; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_logic_rejection_mnemonics(self) -> None:
        bad_code = "PROGRAM BadMnemonic XIC(Tag1); OTE(Tag2); END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# 14. TestVerificationRunner9StagesAndEvidence
# ============================================================================

class TestVerificationRunner9StagesAndEvidence:
    """Validate deterministic 9-stage verification runner and evidence file."""

    def test_run_verification_runner_in_memory(self) -> None:
        evidence = run_cip_safety_wireless_mesh_verification()
        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["total_stages"] == 9
        assert evidence["stages_passed"] == 9
        assert len(evidence["data"]["stages"]) == 9

    def test_run_verification_runner_file_emission(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "evidence.json"
            evidence = run_cip_safety_wireless_mesh_verification(output_path=out_file)
            assert out_file.exists()

            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["total_stages"] == 9
            assert loaded["stages_passed"] == 9

    def test_verification_runner_stage_data_structure(self) -> None:
        evidence = run_cip_safety_wireless_mesh_verification()
        stages = evidence["data"]["stages"]
        assert len(stages) == 9
        for i, s in enumerate(stages):
            assert s["stage"] == i + 1
            assert "name" in s
            assert s["passed"] is True
            assert s["timing_ms"] >= 0.0
            assert isinstance(s["details"], str)

    def test_exceptions_hierarchy(self) -> None:
        assert issubclass(CrcS1CorruptionError, CipSafetyWirelessMeshError)
        assert issubclass(CrcS2CorruptionError, CipSafetyWirelessMeshError)
        assert issubclass(SafetyTimeoutExpiredError, CipSafetyWirelessMeshError)
        assert issubclass(RouteUnreachableError, CipSafetyWirelessMeshError)
        assert issubclass(SplitBrainPartitionError, CipSafetyWirelessMeshError)
