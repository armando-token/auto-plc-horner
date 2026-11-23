"""Unit Test Suite for Industrial WirelessHART (IEC 62591) TDMA Network Manager & Mesh Engine.

Work Package: W127 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R880..%R887, %M205..%M206).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs.
3. Section 3: TDMA 10ms timeslot superframe timing, channel hopping sequence generation, and timeslot allocation.
4. Section 4: Multi-hop mesh routing table, parent/child node graph, and RSSI metrics.
5. Section 5: WirelessHART payload encoding/decoding (Cmd 1, 3, 9, 48) and MIC integrity checks.
6. Section 6: Process safety trips (0x9801, 0x9802, 0x9803, 0x9804) and Horner coil assertion (%M205, %M206).
7. Section 7: Horner OCS register space synchronization (%R880..%R887).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import struct
import time
from typing import Any, Dict

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.wireless_hart import (
    DEFAULT_SUPERFRAME_SIZE,
    TDMA_TIMESLOT_DURATION_MS,
    TDMA_TIMESLOT_DURATION_S,
    WIRELESS_HART_BROADCAST_NICKNAME,
    WIRELESS_HART_CHANNELS,
    WIRELESS_HART_DEFAULT_KEY,
    WIRELESS_HART_DEFAULT_NETWORK_ID,
    WIRELESS_HART_DEFAULT_WATCHDOG_TIMEOUT_S,
    WIRELESS_HART_GATEWAY_NICKNAME,
    WIRELESS_HART_MAX_NODES,
    WIRELESS_HART_MESH_SYNC_PURE_ST_POU,
    WIRELESS_HART_NETWORK_SYNC_PURE_ST_POU,
    WIRELESS_HART_NUM_CHANNELS,
    WIRELESS_HART_PURE_ST_POU,
    WIRELESS_HART_SUPERFRAME_TIMEOUT_S,
    Cmd1Response,
    Cmd3Response,
    Cmd9Response,
    Cmd48Response,
    MICIntegrityError,
    MeshRoutingError,
    MeshRoutingTable,
    PayloadDecodeError,
    TDMASchedulingError,
    TDMASuperframe,
    WirelessHartCommand,
    WirelessHartDiagnosticCode,
    WirelessHartError,
    WirelessHartLink,
    WirelessHartLinkType,
    WirelessHartNetworkManager,
    WirelessHartNode,
    WirelessHartPacket,
    WirelessHartStatusBits,
    calc_channel_hopping,
    calc_mic,
    decode_cmd1_response,
    decode_cmd3_response,
    decode_cmd9_response,
    decode_cmd48_response,
    encode_cmd1_response,
    encode_cmd3_response,
    encode_cmd9_response,
    encode_cmd48_response,
    run_wireless_hart_verification,
    verify_mic,
    verify_wireless_hart_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def network_manager(register_table: RegisterTable) -> WirelessHartNetworkManager:
    """Provides a fresh WirelessHartNetworkManager initialized with register table."""
    return WirelessHartNetworkManager(reg_table=register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================


class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance, AST verification, and register bindings."""

    def test_verify_wireless_hart_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_wireless_hart_pure_st() is True

    def test_pure_st_network_sync_pou_ast_parsing(self) -> None:
        """Parse WIRELESS_HART_NETWORK_SYNC_PURE_ST_POU and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(WIRELESS_HART_NETWORK_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "WirelessHartNetworkSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R880", "%R881", "%R882", "%R883", "%R884",
            "%R885", "%R886", "%R887", "%M205", "%M206",
        }
        assert expected_regs.issubset(set(pou.bound_registers))

    def test_pure_st_network_manager_sync_pou_ast_parsing(self) -> None:
        """Parse WIRELESS_HART_PURE_ST_POU (WirelessHartNetworkManagerSync) and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(WIRELESS_HART_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "WirelessHartNetworkManagerSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "WirelessHartStatusWord",
            "ActiveNodesCount",
            "LastExecutedCommand",
            "PrimaryVariablePvScaled",
            "SecondaryVariableSvScaled",
            "AverageMeshRssi",
            "PacketCounter",
            "DiagnosticEventCode",
            "WirelessHartNetworkActive",
            "WirelessHartFaultTrip",
            "NetworkActiveBit",
            "MeshSyncBit",
            "SuperframeTimeoutTripBit",
            "NodeDisconnectTripBit",
            "DiagnosticTrip",
        }
        assert expected_vars.issubset(var_names)

        expected_bound_regs = {
            "%R880", "%R881", "%R882", "%R883", "%R884",
            "%R885", "%R886", "%R887", "%M205", "%M206",
        }
        assert expected_bound_regs.issubset(set(pou.bound_registers))

    def test_pure_st_mesh_sync_pou_ast_parsing(self) -> None:
        """Parse WIRELESS_HART_MESH_SYNC_PURE_ST_POU and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(WIRELESS_HART_MESH_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "WirelessHartMeshSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_bound_regs = {
            "%R880", "%R881", "%R882", "%R883", "%R884",
            "%R885", "%R886", "%R887", "%M205", "%M206",
        }
        assert expected_bound_regs.issubset(set(pou.bound_registers))

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POUs pass SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(WIRELESS_HART_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(WIRELESS_HART_MESH_SYNC_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(WIRELESS_HART_NETWORK_SYNC_PURE_ST_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard Asserting LadderForbiddenError
# ============================================================================


class TestSection2AntiLadderSecurity:
    """Tests for SecurityGuard strict rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "sample",
        [
            "PROGRAM BadContacts\nVAR Flag: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
            "PROGRAM BadNegative\nVAR Flag: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M205 OTE %M206 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM BadReset\nVAR Out: BOOL; END_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM BadMnemonic\nVAR Out: BOOL; END_VAR\nXIO %M205\nEND_PROGRAM",
            "PROGRAM BadLatch\nVAR Out: BOOL; END_VAR\nOTL %M206\nEND_PROGRAM",
            "PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: TDMA 10ms Timeslot Timing & Channel Hopping Generation
# ============================================================================


class TestSection3TDMASuperframeAndChannelHopping:
    """Tests for TDMA 10ms timeslot superframe timing, channel hopping sequence, and link scheduling."""

    def test_superframe_creation_and_defaults(self) -> None:
        """Assert default superframe has 100 slots of 10ms each (1.0 second total)."""
        sf = TDMASuperframe(superframe_id=1, num_slots=100)
        assert sf.num_slots == 100
        assert sf.total_slots == 100
        assert len(sf.links) == 0
        assert TDMA_TIMESLOT_DURATION_MS == 10
        assert math.isclose(TDMA_TIMESLOT_DURATION_S, 0.010, abs_tol=1e-6)

    def test_channel_hopping_formula_default(self) -> None:
        """Verify standard WirelessHART channel hopping formula: Channel = 11 + ((ASN + Offset) % 16)."""
        # ASN 0, offset 0 -> 11
        assert calc_channel_hopping(0, 0) == 11
        # ASN 1, offset 0 -> 12
        assert calc_channel_hopping(1, 0) == 12
        # ASN 15, offset 0 -> 26
        assert calc_channel_hopping(15, 0) == 26
        # ASN 16, offset 0 -> 11 (wraparound)
        assert calc_channel_hopping(16, 0) == 11
        # ASN 5, offset 3 -> 11 + ((5+3)%16) = 19
        assert calc_channel_hopping(5, 3) == 19
        # ASN 100, offset 7 -> 11 + ((100+7)%16) = 11 + 11 = 22
        assert calc_channel_hopping(100, 7) == 22

        # Verify all 16 channels are spanned over 16 consecutive slots
        spanned = {calc_channel_hopping(asn=i, channel_offset=0) for i in range(16)}
        assert spanned == set(range(11, 27))
        assert len(spanned) == 16

    def test_channel_hopping_with_blacklisting(self) -> None:
        """Verify channel hopping respects active channels list when blacklisting interference channels."""
        permitted_channels = [11, 15, 20, 25, 26]
        for asn in range(50):
            for offset in range(5):
                ch = calc_channel_hopping(asn, offset, active_channels=permitted_channels)
                assert ch in permitted_channels

    def test_superframe_link_allocation_and_retrieval(self) -> None:
        """Verify scheduling links across superframe slots and retrieving by slot."""
        sf = TDMASuperframe(superframe_id=1, num_slots=100)
        link1 = WirelessHartLink(
            slot_index=0,
            source_nickname=0x0002,
            dest_nickname=0x0001,
            channel_offset=0,
            link_type=WirelessHartLinkType.TRANSMIT,
        )
        link2 = WirelessHartLink(
            slot_index=0,
            source_nickname=0x0003,
            dest_nickname=0x0001,
            channel_offset=1,
            link_type=WirelessHartLinkType.TRANSMIT,
        )
        link3 = WirelessHartLink(
            slot_index=1,
            source_nickname=0x0004,
            dest_nickname=0x0002,
            channel_offset=0,
            link_type=WirelessHartLinkType.TRANSMIT,
        )
        sf.add_link(link1)
        sf.add_link(link2)
        sf.add_link(link3)

        assert len(sf.links) == 3
        slot0_links = sf.get_links_for_slot(0)
        assert len(slot0_links) == 2
        assert slot0_links[0] == link1
        assert slot0_links[1] == link2

        slot1_links = sf.get_links_for_slot(1)
        assert len(slot1_links) == 1
        assert slot1_links[0] == link3

        # Verify removal
        removed = sf.remove_link(slot_index=0, source_nickname=0x0002, dest_nickname=0x0001)
        assert removed is True
        assert len(sf.get_links_for_slot(0)) == 1

        # Clear links
        sf.clear_links()
        assert len(sf.links) == 0

    def test_superframe_collision_detection(self) -> None:
        """Verify scheduling collision detection for duplicate slot and channel offset."""
        sf = TDMASuperframe(superframe_id=1, num_slots=50)
        link_a = WirelessHartLink(slot_index=5, source_nickname=0x0002, dest_nickname=0x0001, channel_offset=3)
        sf.add_link(link_a)

        # Attempt adding conflicting link with same slot and same channel offset
        link_conflict = WirelessHartLink(slot_index=5, source_nickname=0x0003, dest_nickname=0x0001, channel_offset=3)
        with pytest.raises(TDMASchedulingError, match="collision"):
            sf.add_link(link_conflict)

    def test_superframe_out_of_bounds_slot_raises(self) -> None:
        """Verify adding link exceeding superframe length raises TDMASchedulingError."""
        sf = TDMASuperframe(num_slots=20)
        bad_link = WirelessHartLink(slot_index=25, source_nickname=0x0002, dest_nickname=0x0001)
        with pytest.raises(TDMASchedulingError, match="exceeds superframe size"):
            sf.add_link(bad_link)

    def test_link_invalid_fields_raise(self) -> None:
        """Verify link field boundaries (negative slot, channel offset > 15)."""
        with pytest.raises(ValueError, match="Slot index must be non-negative"):
            WirelessHartLink(slot_index=-1, source_nickname=0x0002, dest_nickname=0x0001)

        with pytest.raises(ValueError, match="Channel offset must be 0..15"):
            WirelessHartLink(slot_index=0, source_nickname=0x0002, dest_nickname=0x0001, channel_offset=16)


# ============================================================================
# Section 4: Multi-Hop Mesh Routing Table, Parent/Child Graph, & RSSI Metrics
# ============================================================================


class TestSection4MultiHopMeshRoutingTable:
    """Tests for mesh routing table, multi-hop path traversal, spatial path redundancy, and RSSI tracking."""

    def test_routing_table_32_node_capacity(self) -> None:
        """Assert mesh table supports up to 32 field nodes and rejects 33rd."""
        table = MeshRoutingTable(max_nodes=32)
        for i in range(1, 33):
            table.register_or_update_node(
                nickname=i,
                primary_parent=WIRELESS_HART_GATEWAY_NICKNAME if i <= 10 else ((i % 10) + 1),
                hop_count=1 if i <= 10 else 2,
                rssi_dbm=-65.0 - (i % 20),
            )
        assert table.active_count == 32
        assert table.total_nodes == 32

        # 33rd node must raise MeshRoutingError
        with pytest.raises(MeshRoutingError):
            table.register_or_update_node(nickname=33)

    def test_node_parent_child_relationships(self) -> None:
        """Verify parent node tracks registered children in children set."""
        table = MeshRoutingTable()
        parent = table.register_or_update_node(nickname=0x0002, primary_parent=0x0001, hop_count=1)
        child1 = table.register_or_update_node(nickname=0x0003, primary_parent=0x0002, hop_count=2)
        child2 = table.register_or_update_node(nickname=0x0004, primary_parent=0x0002, hop_count=2)

        assert 0x0003 in parent.children
        assert 0x0004 in parent.children
        assert child1.primary_parent == 0x0002
        assert child2.primary_parent == 0x0002
        assert child1.hex_id == "0003"

    def test_multi_hop_path_resolution(self) -> None:
        """Verify 1-hop, 2-hop, and 3-hop shortest path resolution to gateway."""
        table = MeshRoutingTable()
        table.register_or_update_node(nickname=0x0002, primary_parent=0x0001, hop_count=1)
        table.register_or_update_node(nickname=0x0003, primary_parent=0x0001, hop_count=1)
        table.register_or_update_node(
            nickname=0x0004,
            primary_parent=0x0002,
            secondary_parent=0x0003,
            hop_count=2,
            rssi_dbm=-75.0,
        )

        path = table.find_path_to_gateway(0x0004)
        assert path == [0x0004, 0x0002, 0x0001]
        assert table.has_redundant_path(0x0004) is True

    def test_spatial_path_redundancy(self) -> None:
        """Verify has_redundant_path detects when a node has two distinct paths to gateway."""
        table = MeshRoutingTable()
        table.register_or_update_node(nickname=0x0002, primary_parent=0x0001, hop_count=1)
        table.register_or_update_node(nickname=0x0003, primary_parent=0x0001, hop_count=1)

        table.register_or_update_node(
            nickname=0x0004,
            primary_parent=0x0002,
            secondary_parent=0x0003,
            hop_count=2,
        )
        assert table.has_redundant_path(0x0004) is True

        table.register_or_update_node(
            nickname=0x0005,
            primary_parent=0x0002,
            secondary_parent=None,
            hop_count=2,
        )
        assert table.has_redundant_path(0x0005) is False

    def test_fallback_to_secondary_parent_when_primary_offline(self) -> None:
        """Verify find_path_to_gateway falls back to secondary parent when primary is offline."""
        table = MeshRoutingTable()
        n2 = table.register_or_update_node(nickname=0x0002, primary_parent=0x0001)
        table.register_or_update_node(nickname=0x0003, primary_parent=0x0001)
        table.register_or_update_node(
            nickname=0x0004,
            primary_parent=0x0002,
            secondary_parent=0x0003,
        )

        n2.is_online = False
        fallback_path = table.find_path_to_gateway(0x0004)
        assert fallback_path == [0x0004, 0x0003, 0x0001]

    def test_routing_cycle_detection(self) -> None:
        """Verify routing table detects cycle and raises MeshRoutingError."""
        table = MeshRoutingTable()
        table.register_or_update_node(nickname=0x0002, primary_parent=0x0003)
        table.register_or_update_node(nickname=0x0003, primary_parent=0x0002)

        with pytest.raises(MeshRoutingError, match="cycle detected"):
            table.find_path_to_gateway(0x0002)

    def test_average_rssi_metric(self) -> None:
        """Verify average RSSI computation across all online field devices."""
        table = MeshRoutingTable()
        table.register_or_update_node(nickname=0x0002, primary_parent=0x0001, rssi_dbm=-60.0)
        table.register_or_update_node(nickname=0x0003, primary_parent=0x0001, rssi_dbm=-80.0)

        assert math.isclose(table.average_rssi, -70.0, abs_tol=0.1)

    def test_node_removal_and_clear(self) -> None:
        """Verify removing nodes updates children sets and clearing empties table."""
        table = MeshRoutingTable()
        table.register_or_update_node(nickname=0x0002, primary_parent=0x0001)
        table.register_or_update_node(nickname=0x0003, primary_parent=0x0002)
        assert table.active_count == 2

        assert table.remove_node(0x0003) is True
        assert table.active_count == 1
        assert table.get_node(0x0003) is None

        table.clear()
        assert table.active_count == 0

    def test_node_watchdog_inactivity(self) -> None:
        """Verify check_watchdogs marks inactive nodes offline after timeout."""
        table = MeshRoutingTable()
        t0 = time.time()
        table.register_or_update_node(nickname=0x0002, primary_parent=0x0001, now=t0 - 40.0)
        table.register_or_update_node(nickname=0x0003, primary_parent=0x0001, now=t0)

        expired = table.check_watchdogs(timeout_s=30.0, current_time=t0)
        assert len(expired) == 1
        assert expired[0].nickname == 0x0002
        assert table.online_count == 1
        assert table.active_count == 2


# ============================================================================
# Section 5: WirelessHART Payload Encoding/Decoding (Cmd 1, 3, 9, 48) & MIC
# ============================================================================


class TestSection5PayloadEncodingDecodingAndMIC:
    """Tests for Cmd 1, 3, 9, 48 payload serialization/deserialization and AES/HMAC MIC validation."""

    def test_cmd1_encoding_decoding_roundtrip(self) -> None:
        """Verify Cmd 1 (Read Primary Variable) encoding and decoding."""
        enc = encode_cmd1_response(device_status=0x00, pv_units=32, pv=125.4)
        dec = decode_cmd1_response(enc)
        assert dec.device_status == 0x00
        assert dec.pv_units == 32
        assert math.isclose(dec.pv, 125.4, abs_tol=0.01)

    def test_cmd3_encoding_decoding_roundtrip(self) -> None:
        """Verify Cmd 3 (Read Dynamic Variables & Loop Current) encoding and decoding."""
        enc = encode_cmd3_response(
            device_status=0x00,
            loop_current_ma=16.50,
            pv_units=32,
            pv=250.0,
            sv_units=32,
            sv=75.5,
            tv_units=32,
            tv=10.0,
            qv_units=32,
            qv=5.0,
        )
        dec = decode_cmd3_response(enc)
        assert math.isclose(dec.loop_current_ma, 16.50, abs_tol=0.01)
        assert math.isclose(dec.pv, 250.0, abs_tol=0.01)
        assert math.isclose(dec.sv, 75.5, abs_tol=0.01)
        assert math.isclose(dec.tv, 10.0, abs_tol=0.01)
        assert math.isclose(dec.qv, 5.0, abs_tol=0.01)

    def test_cmd9_encoding_decoding_roundtrip(self) -> None:
        """Verify Cmd 9 (Read Device Variables with Status) encoding and decoding."""
        enc = encode_cmd9_response(
            extended_status=0x00,
            device_var_code=0,
            classification=65,
            units=32,
            value=42.1,
            var_status=0xC0,
        )
        dec = decode_cmd9_response(enc)
        assert dec.device_var_code == 0
        assert dec.classification == 65
        assert dec.units == 32
        assert math.isclose(dec.value, 42.1, abs_tol=0.01)
        assert dec.var_status == 0xC0

    def test_cmd48_encoding_decoding_diagnostics(self) -> None:
        """Verify Cmd 48 (Read Additional Transmitter Status) 25-byte diagnostic parsing."""
        raw_diag = bytes([0x01, 0x02, 0x03, 0x05] + [0x00] * 21)
        dec = decode_cmd48_response(raw_diag)
        assert dec.is_cold_junction_fault is True
        assert dec.is_power_failure is True
        assert dec.is_sensor_out_of_limits is False

    def test_payload_truncation_raises(self) -> None:
        """Verify truncated payloads raise PayloadDecodeError."""
        with pytest.raises(PayloadDecodeError, match="Cmd 1 payload too short"):
            decode_cmd1_response(b"\x00\x20")

        with pytest.raises(PayloadDecodeError, match="Cmd 3 payload too short"):
            decode_cmd3_response(b"\x00" * 20)

        with pytest.raises(PayloadDecodeError, match="Cmd 9 payload too short"):
            decode_cmd9_response(b"\x00" * 8)

        with pytest.raises(PayloadDecodeError, match="Cmd 48 payload too short"):
            decode_cmd48_response(b"\x00" * 20)

    def test_mic_calculation_and_verification(self) -> None:
        """Assert valid MIC matches and corrupted MIC fails."""
        data = b"\x12\x34\x00\x02\x00\x01\x00\x00\x00\x00\x00\x64\x01\x00\x20\x42\xFA\xCC\xCD"
        key = WIRELESS_HART_DEFAULT_KEY
        mic = calc_mic(data, key)
        assert len(mic) == 4
        assert verify_mic(data, mic, key) is True
        assert verify_mic(key, data, mic) is True

        corrupt_mic = bytes([mic[0] ^ 0xFF, mic[1], mic[2], mic[3]])
        assert verify_mic(data, corrupt_mic, key) is False

    def test_packet_serialization_deserialization_roundtrip(self) -> None:
        """Verify full WirelessHART packet serialization and deserialization with MIC."""
        pkt = WirelessHartPacket(
            network_id=WIRELESS_HART_DEFAULT_NETWORK_ID,
            source_nickname=0x0002,
            dest_nickname=0x0001,
            asn=100,
            command=1,
            payload=encode_cmd1_response(0x00, 32, 125.4),
        )
        raw = pkt.serialize(key=WIRELESS_HART_DEFAULT_KEY)
        p_ok = WirelessHartPacket.deserialize(raw, key=WIRELESS_HART_DEFAULT_KEY, verify=True)
        assert p_ok.source_nickname == 0x0002
        assert p_ok.asn == 100
        assert p_ok.command == 1

    def test_tampered_packet_raises_mic_integrity_error(self) -> None:
        """Verify tampered raw packet raises MICIntegrityError."""
        pkt = WirelessHartPacket(
            network_id=WIRELESS_HART_DEFAULT_NETWORK_ID,
            source_nickname=0x0002,
            dest_nickname=0x0001,
            asn=1,
            command=1,
            payload=b"\x00\x20\x00\x00\x00\x00",
        )
        raw = bytearray(pkt.serialize(WIRELESS_HART_DEFAULT_KEY))
        raw[5] ^= 0x01
        with pytest.raises(MICIntegrityError):
            WirelessHartPacket.deserialize(bytes(raw), key=WIRELESS_HART_DEFAULT_KEY, verify=True)

    def test_packet_truncation_raises_wireless_hart_error(self) -> None:
        """Verify packet smaller than minimum header size raises WirelessHartError."""
        with pytest.raises(WirelessHartError, match="Raw packet too short"):
            WirelessHartPacket.deserialize(b"\x12\x34\x00\x02")


# ============================================================================
# Section 6: Process Safety Trips & Diagnostic Codes
# ============================================================================


class TestSection6ProcessSafetyTrips:
    """Tests for safety trips 0x9801..0x9804 asserting %M205/%M206 and diagnostic codes."""

    def test_superframe_timeout_trip_0x9801(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify 0x9801 Superframe Sync Timeout Trip asserts %M206 and clears %M205."""
        mgr = network_manager
        mgr.routing_table.register_or_update_node(nickname=0x0002)
        mgr._sync_registers()
        assert mgr.reg_table.read_bit("%M205") is True
        assert mgr.reg_table.read_bit("%M206") is False

        tripped = mgr.check_superframe_watchdog(simulated_elapsed_s=WIRELESS_HART_SUPERFRAME_TIMEOUT_S + 5.0)
        assert tripped is True
        assert mgr.reg_table.read_uword("%R887") == int(WirelessHartDiagnosticCode.SUPERFRAME_TIMEOUT_TRIP)
        assert mgr.reg_table.read_bit("%M206") is True
        assert mgr.reg_table.read_bit("%M205") is False
        assert bool(mgr.reg_table.read_uword("%R880") & WirelessHartStatusBits.SUPERFRAME_TIMEOUT_TRIP) is True

    def test_mic_integrity_alarm_0x9802(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify 0x9802 MIC Integrity Failure Alarm sets bit 5 in %R880 and updates %R887."""
        mgr = network_manager
        mgr.routing_table.register_or_update_node(nickname=0x0002)

        bad_frame = b"\x12\x34\x00\x02\x00\x01\x00\x00\x00\x00\x00\x64\x01\x00\x20\x42\xFA\xCC\xCD\xDE\xAD\xBE\xEF"
        res = mgr.process_raw_bytes(bad_frame)
        assert res is False
        assert mgr.reg_table.read_uword("%R887") == int(WirelessHartDiagnosticCode.MIC_INTEGRITY_FAIL_ALARM)
        assert bool(mgr.reg_table.read_uword("%R880") & WirelessHartStatusBits.MIC_FAILURE_ALARM) is True

    def test_routing_fail_alarm_0x9803(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify 0x9803 Routing Failure Alarm sets bit 6 in %R880 and updates %R887."""
        mgr = network_manager
        res = mgr.process_raw_bytes(b"\xFF\xFF\x01\x02")
        assert res is False
        assert mgr.reg_table.read_uword("%R887") == int(WirelessHartDiagnosticCode.ROUTING_FAIL_ALARM)
        assert bool(mgr.reg_table.read_uword("%R880") & WirelessHartStatusBits.ROUTING_FAIL_ALARM) is True

    def test_node_disconnect_trip_0x9804(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify 0x9804 Node Disconnect Trip asserts %M206 and clears %M205 when all field nodes disconnect."""
        mgr = network_manager
        mgr.routing_table.register_or_update_node(nickname=0x0002, now=100.0)
        mgr._sync_registers()
        assert mgr.reg_table.read_bit("%M205") is True

        tripped = mgr.check_nodes_watchdog(simulated_elapsed_s=WIRELESS_HART_DEFAULT_WATCHDOG_TIMEOUT_S + 10.0)
        assert tripped is True
        assert mgr.reg_table.read_uword("%R887") == int(WirelessHartDiagnosticCode.NODE_DISCONNECT_TRIP)
        assert mgr.reg_table.read_bit("%M206") is True
        assert mgr.reg_table.read_bit("%M205") is False
        assert bool(mgr.reg_table.read_uword("%R880") & WirelessHartStatusBits.NODE_DISCONNECT_TRIP) is True

    def test_reset_fault_trip_recovery(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify reset_fault_trip clears all alarms and restores %M205."""
        mgr = network_manager
        mgr.check_superframe_watchdog(simulated_elapsed_s=100.0)
        assert mgr.reg_table.read_bit("%M206") is True

        mgr.reset_fault_trip()
        assert mgr.diagnostic_code == WirelessHartDiagnosticCode.OK
        assert mgr.reg_table.read_uword("%R887") == 0x0000
        assert mgr.reg_table.read_bit("%M206") is False
        assert mgr.reg_table.read_bit("%M205") is True

    def test_diagnostic_codes_and_status_bits_enumerations(self) -> None:
        """Verify process safety trip codes and Horner status bits bitmask definitions."""
        assert int(WirelessHartDiagnosticCode.OK) == 0x0000
        assert int(WirelessHartDiagnosticCode.SUPERFRAME_TIMEOUT_TRIP) == 0x9801
        assert int(WirelessHartDiagnosticCode.MIC_INTEGRITY_FAIL_ALARM) == 0x9802
        assert int(WirelessHartDiagnosticCode.ROUTING_FAIL_ALARM) == 0x9803
        assert int(WirelessHartDiagnosticCode.NODE_DISCONNECT_TRIP) == 0x9804

        assert int(WirelessHartStatusBits.NETWORK_ACTIVE) == 0x0001
        assert int(WirelessHartStatusBits.MESH_SYNCHRONIZED) == 0x0002
        assert int(WirelessHartStatusBits.TDMA_RUNNING) == 0x0004
        assert int(WirelessHartStatusBits.BURST_RECEIVING) == 0x0008
        assert int(WirelessHartStatusBits.SUPERFRAME_TIMEOUT_TRIP) == 0x0010
        assert int(WirelessHartStatusBits.MIC_FAILURE_ALARM) == 0x0020
        assert int(WirelessHartStatusBits.ROUTING_FAIL_ALARM) == 0x0040
        assert int(WirelessHartStatusBits.NODE_DISCONNECT_TRIP) == 0x0080


# ============================================================================
# Section 7: Horner OCS Memory Space Integration (%R880..%R887)
# ============================================================================


class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS register space synchronization (%R880..%R887, %M205..%M206)."""

    def test_initial_register_space_state(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify initial register state matches Horner OCS specifications."""
        assert network_manager.reg_table.read_word("%R881") == 0
        assert network_manager.reg_table.read_word("%R882") == 0
        assert network_manager.reg_table.read_word("%R883") == 0
        assert network_manager.reg_table.read_word("%R884") == 0
        assert network_manager.reg_table.read_word("%R886") == 0
        assert network_manager.reg_table.read_uword("%R887") == 0x0000
        assert network_manager.reg_table.read_bit("%M205") is True
        assert network_manager.reg_table.read_bit("%M206") is False

    def test_cmd1_packet_register_sync(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify Cmd 1 packet updates %R882 (Cmd), %R883 (PV x10), %R886 (Packets), and %M205."""
        cmd1_pay = encode_cmd1_response(device_status=0x00, pv_units=32, pv=125.4)
        pkt = WirelessHartPacket(
            source_nickname=0x0002,
            command=int(WirelessHartCommand.READ_PRIMARY_VARIABLE),
            payload=cmd1_pay,
        )
        ok = network_manager.process_packet(pkt)
        assert ok is True

        assert network_manager.reg_table.read_word("%R881") == 1
        assert network_manager.reg_table.read_word("%R882") == 1
        assert network_manager.reg_table.read_word("%R883") == 1254  # 125.4 * 10
        assert network_manager.reg_table.read_word("%R886") == 1
        assert network_manager.reg_table.read_bit("%M205") is True
        assert network_manager.reg_table.read_bit("%M206") is False

    def test_cmd3_packet_register_sync(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify Cmd 3 packet updates %R883 (PV x10) and %R884 (SV x10)."""
        cmd3_pay = encode_cmd3_response(
            device_status=0x00,
            loop_current_ma=16.0,
            pv_units=32,
            pv=250.0,
            sv_units=32,
            sv=75.5,
            tv_units=32,
            tv=10.0,
            qv_units=32,
            qv=5.0,
        )
        pkt = WirelessHartPacket(
            source_nickname=0x0002,
            command=int(WirelessHartCommand.READ_DYNAMIC_VARS_CURRENT),
            payload=cmd3_pay,
        )
        ok = network_manager.process_packet(pkt)
        assert ok is True

        assert network_manager.reg_table.read_word("%R882") == 3
        assert network_manager.reg_table.read_word("%R883") == 2500  # 250.0 * 10
        assert network_manager.reg_table.read_word("%R884") == 755   # 75.5 * 10
        assert network_manager.reg_table.read_bit("%M205") is True

    def test_average_mesh_rssi_register_sync(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify %R885 accurately reflects average mesh RSSI in signed dBm."""
        network_manager.routing_table.register_or_update_node(0x0002, primary_parent=0x0001, rssi_dbm=-65.0)
        network_manager.routing_table.register_or_update_node(0x0003, primary_parent=0x0001, rssi_dbm=-75.0)
        network_manager._sync_registers()

        assert network_manager.reg_table.read_word("%R885") == -70

    def test_clamped_signed_int_values(self, network_manager: WirelessHartNetworkManager) -> None:
        """Verify scaled PV and SV values clamp cleanly to signed 16-bit range."""
        network_manager.primary_variable = 5000.0  # Scaled x10 = 50000 -> clamps to 32767
        network_manager.secondary_variable = -5000.0  # Scaled x10 = -50000 -> clamps to -32768
        network_manager._sync_registers()

        assert network_manager.reg_table.read_word("%R883") == 32767
        assert network_manager.reg_table.read_word("%R884") == -32768


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================


class TestSection8VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_wireless_hart_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_wireless_hart_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

    def test_run_wireless_hart_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "wireless_hart_evidence.json"
        result = run_wireless_hart_verification(evidence_path=str(evidence_file))

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W127"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert data["data"]["component"] == "Industrial WirelessHART TDMA Network Manager & Field Sensor Mesh Engine"
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9
        assert data["data"]["register_map"]["status_word"] == "%R880"
        assert data["data"]["register_map"]["active_nodes_count"] == "%R881"
        assert data["data"]["register_map"]["network_active_coil"] == "%M205"
        assert data["data"]["register_map"]["fault_trip_coil"] == "%M206"
