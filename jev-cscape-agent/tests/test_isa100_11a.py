"""Unit Test Suite for Industrial ISA100.11a (IEC 62734) Protocol Engine & Wireless Mesh Manager.

Work Package: W130 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R910..%R917, %M212..%M213).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: TDMA timeslot superframe timing, slotted channel hopping sequence, and slow hopping pattern generation.
4. Section 4: Security Manager join handshake, AES-CCM* MIC calculation, and tamper rejection.
5. Section 5: UAP Object model (AI, DI, Concentrator) encoding/decoding and engineering unit scaling.
6. Section 6: Multi-hop mesh routing table, RSSI tracking, and route disconnect detection.
7. Section 7: Process safety trips (0x9B01, 0x9B02, 0x9B03, 0x9B04) and Horner coil assertion (%M212, %M213).
8. Section 8: Horner OCS register space synchronization (%R910..%R917, %M212..%M213).
9. Section 9: 9-stage verification suite integration test writing evidence JSON.
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
from jev_cscape.telemetry.isa100_11a import (
    DEFAULT_SUPERFRAME_SIZE,
    ISA100_BROADCAST_ADDRESS,
    ISA100_CHANNELS,
    ISA100_DEFAULT_JOIN_KEY,
    ISA100_DEFAULT_KEY,
    ISA100_DEFAULT_SUBNET_ID,
    ISA100_DEFAULT_WATCHDOG_TIMEOUT_S,
    ISA100_GATEWAY_ADDRESS,
    ISA100_MAX_NODES,
    ISA100_MESH_SYNC_PURE_ST_POU,
    ISA100_NETWORK_SYNC_PURE_ST_POU,
    ISA100_NUM_CHANNELS,
    ISA100_11A_PURE_ST_POU,
    ISA100_SUPERFRAME_TIMEOUT_S,
    TDMA_TIMESLOT_DURATION_MS,
    TDMA_TIMESLOT_DURATION_S,
    ISA100AnalogInputPayload,
    ISA100ConcentratorPayload,
    ISA100DiagnosticCode,
    ISA100DiscreteInputPayload,
    ISA100Error,
    ISA100JoinRequest,
    ISA100JoinResponse,
    ISA100Link,
    ISA100LinkType,
    ISA100MeshRoutingTable,
    ISA100NetworkManager,
    ISA100Node,
    ISA100ObjectClass,
    ISA100Packet,
    ISA100SecurityManager,
    ISA100StatusBits,
    ISA100Superframe,
    MICIntegrityError,
    MeshRoutingError,
    MeshRoutingTable,
    PayloadDecodeError,
    SecurityHandshakeError,
    TDMASchedulingError,
    TDMASuperframe,
    calc_ccm_mic,
    calc_channel_hopping,
    calc_mic,
    calc_slotted_channel_hopping,
    calc_slow_hopping_channel,
    decode_ai_response,
    decode_concentrator_response,
    decode_di_response,
    encode_ai_response,
    encode_concentrator_response,
    encode_di_response,
    generate_slow_hopping_pattern,
    run_isa100_11a_verification,
    scale_pv_to_int16,
    verify_ccm_mic,
    verify_isa100_11a_pure_st,
    verify_mic,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def network_manager(register_table: RegisterTable) -> ISA100NetworkManager:
    """Provides a fresh ISA100NetworkManager initialized with register table."""
    return ISA100NetworkManager(reg_table=register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================


class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance, AST verification, and register bindings."""

    def test_verify_isa100_11a_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_isa100_11a_pure_st() is True

    def test_pure_st_network_sync_pou_ast_parsing(self) -> None:
        """Parse ISA100_NETWORK_SYNC_PURE_ST_POU and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(ISA100_NETWORK_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "ISA100NetworkSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R910", "%R911", "%R912", "%R913", "%R914",
            "%R915", "%R916", "%R917", "%M212", "%M213",
        }
        assert expected_regs.issubset(set(pou.bound_registers))

    def test_pure_st_manager_sync_pou_ast_parsing(self) -> None:
        """Parse ISA100_11A_PURE_ST_POU (ISA100ManagerSync) and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(ISA100_11A_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "ISA100ManagerSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "ISA100StatusWord",
            "ActiveNodesCount",
            "LastExecutedObjectService",
            "PrimaryVariablePvScaled",
            "SecondaryVariableSvScaled",
            "AverageMeshRssi",
            "PacketCounter",
            "DiagnosticEventCode",
            "ISA100NetworkActive",
            "ISA100FaultTrip",
            "NetworkActiveBit",
            "MeshSyncBit",
            "SuperframeTimeoutTripBit",
            "NodeDisconnectTripBit",
            "DiagnosticTrip",
        }
        assert expected_vars.issubset(var_names)

        expected_bound_regs = {
            "%R910", "%R911", "%R912", "%R913", "%R914",
            "%R915", "%R916", "%R917", "%M212", "%M213",
        }
        assert expected_bound_regs.issubset(set(pou.bound_registers))

    def test_pure_st_mesh_sync_pou_ast_parsing(self) -> None:
        """Parse ISA100_MESH_SYNC_PURE_ST_POU and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(ISA100_MESH_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "ISA100MeshSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_bound_regs = {
            "%R910", "%R911", "%R912", "%R913", "%R914",
            "%R915", "%R916", "%R917", "%M212", "%M213",
        }
        assert expected_bound_regs.issubset(set(pou.bound_registers))

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POUs pass SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(ISA100_11A_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(ISA100_MESH_SYNC_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(ISA100_NETWORK_SYNC_PURE_ST_POU)


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
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M212 OTE %M213 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM BadReset\nVAR Out: BOOL; END_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM BadMnemonic\nVAR Out: BOOL; END_VAR\nXIO %M212\nEND_PROGRAM",
            "PROGRAM BadLatch\nVAR Out: BOOL; END_VAR\nOTL %M213\nEND_PROGRAM",
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
# Section 3: TDMA Timeslot Superframe Timing & Slotted / Slow Hopping
# ============================================================================


class TestSection3TDMASuperframeAndChannelHopping:
    """Tests for TDMA 10ms timeslot superframe timing, slotted hopping, and slow hopping pattern generation."""

    def test_superframe_creation_and_defaults(self) -> None:
        """Assert default superframe has 100 slots of 10ms each (1.0 second total)."""
        sf = ISA100Superframe(superframe_id=1, num_slots=100)
        assert sf.num_slots == 100
        assert sf.total_slots == 100
        assert len(sf.links) == 0
        assert TDMA_TIMESLOT_DURATION_MS == 10
        assert math.isclose(TDMA_TIMESLOT_DURATION_S, 0.010, abs_tol=1e-6)

    def test_slotted_channel_hopping_formula_default(self) -> None:
        """Verify standard slotted channel hopping formula: Channel = 11 + ((ASN + Offset) % 16)."""
        assert calc_slotted_channel_hopping(0, 0) == 11
        assert calc_slotted_channel_hopping(1, 0) == 12
        assert calc_slotted_channel_hopping(15, 0) == 26
        assert calc_slotted_channel_hopping(16, 0) == 11  # Wraparound
        assert calc_slotted_channel_hopping(5, 3) == 19
        assert calc_slotted_channel_hopping(100, 7) == 22

        # Verify all 16 channels are spanned over 16 consecutive slots
        spanned = {calc_slotted_channel_hopping(asn=i, channel_offset=0) for i in range(16)}
        assert spanned == set(range(11, 27))
        assert len(spanned) == 16

    def test_slotted_channel_hopping_with_blacklisting(self) -> None:
        """Verify slotted channel hopping respects active channels list when blacklisting interference channels."""
        permitted = [11, 15, 20, 25, 26]
        for asn in range(50):
            for offset in range(5):
                ch = calc_slotted_channel_hopping(asn, offset, active_channels=permitted)
                assert ch in permitted

    def test_slow_hopping_pattern_generation(self) -> None:
        """Verify deterministic generation of slow-hopping channel pattern permutation."""
        pattern1 = generate_slow_hopping_pattern(seed=0x100A)
        assert len(pattern1) == 16
        assert set(pattern1) == set(range(11, 27))

        # Deterministic check: same seed gives identical sequence
        pattern2 = generate_slow_hopping_pattern(seed=0x100A)
        assert pattern1 == pattern2

        # Different seed gives different permutation
        pattern3 = generate_slow_hopping_pattern(seed=0x200B)
        assert pattern1 != pattern3
        assert set(pattern3) == set(range(11, 27))

    def test_slow_hopping_channel_retrieval(self) -> None:
        """Verify slow hopping channel index retrieval and cyclic wraparound."""
        pattern = generate_slow_hopping_pattern(seed=0x100A)
        assert calc_slow_hopping_channel(0, pattern=pattern) == pattern[0]
        assert calc_slow_hopping_channel(1, pattern=pattern) == pattern[1]
        assert calc_slow_hopping_channel(16, pattern=pattern) == pattern[0]
        assert calc_slow_hopping_channel(17, pattern=pattern) == pattern[1]

    def test_superframe_link_allocation_and_retrieval(self) -> None:
        """Verify scheduling links across superframe slots and retrieving by slot."""
        sf = ISA100Superframe(superframe_id=1, num_slots=100)
        link1 = ISA100Link(
            slot_index=0,
            source_address=0x0002,
            dest_address=0x0001,
            channel_offset=0,
            link_type=ISA100LinkType.TRANSMIT,
        )
        link2 = ISA100Link(
            slot_index=0,
            source_address=0x0003,
            dest_address=0x0001,
            channel_offset=1,
            link_type=ISA100LinkType.TRANSMIT,
        )
        link3 = ISA100Link(
            slot_index=1,
            source_address=0x0004,
            dest_address=0x0002,
            channel_offset=0,
            link_type=ISA100LinkType.SLOW_HOPPING,
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
        removed = sf.remove_link(slot_index=0, source_address=0x0002, dest_address=0x0001)
        assert removed is True
        assert len(sf.get_links_for_slot(0)) == 1

        # Clear links
        sf.clear_links()
        assert len(sf.links) == 0

    def test_superframe_collision_detection(self) -> None:
        """Verify scheduling collision detection for duplicate slot and channel offset."""
        sf = ISA100Superframe(superframe_id=1, num_slots=50)
        link_a = ISA100Link(slot_index=5, source_address=0x0002, dest_address=0x0001, channel_offset=3)
        sf.add_link(link_a)

        # Attempt adding conflicting link with same slot and same channel offset
        link_conflict = ISA100Link(slot_index=5, source_address=0x0003, dest_address=0x0001, channel_offset=3)
        with pytest.raises(TDMASchedulingError, match="collision"):
            sf.add_link(link_conflict)

    def test_superframe_out_of_bounds_slot_raises(self) -> None:
        """Verify adding link exceeding superframe length raises TDMASchedulingError."""
        sf = ISA100Superframe(num_slots=20)
        bad_link = ISA100Link(slot_index=25, source_address=0x0002, dest_address=0x0001)
        with pytest.raises(TDMASchedulingError, match="exceeds superframe size"):
            sf.add_link(bad_link)

    def test_link_invalid_fields_raise(self) -> None:
        """Verify link field boundaries (negative slot, channel offset > 15)."""
        with pytest.raises(ValueError, match="Slot index must be non-negative"):
            ISA100Link(slot_index=-1, source_address=0x0002, dest_address=0x0001)

        with pytest.raises(ValueError, match="Channel offset must be 0..15"):
            ISA100Link(slot_index=0, source_address=0x0002, dest_address=0x0001, channel_offset=16)


# ============================================================================
# Section 4: Security Manager Join Handshake, AES-CCM* MIC, & Tamper Rejection
# ============================================================================


class TestSection4SecurityManagerAndAESCCM:
    """Tests for Security Manager join handshake, session key derivation, and AES-CCM* MIC validation."""

    def test_ccm_mic_calculation_and_verification(self) -> None:
        """Assert valid CCM* MIC matches and corrupted MIC fails."""
        data = b"\x10\x0A\x00\x02\x00\x01\x00\x00\x00\x00\x00\x64\x00\x07\x00\x03\xC0\x00\x20\x42\xFA\xCC\xCD"
        key = ISA100_DEFAULT_KEY
        mic = calc_ccm_mic(data, key)
        assert len(mic) == 4
        assert verify_ccm_mic(data, mic, key) is True
        assert verify_ccm_mic(key, data, mic) is True

        corrupt_mic = bytes([mic[0] ^ 0xFF, mic[1], mic[2], mic[3]])
        assert verify_ccm_mic(data, corrupt_mic, key) is False

    def test_security_manager_join_handshake(self) -> None:
        """Verify device join handshake, short address assignment, and session key generation."""
        sec_mgr = ISA100SecurityManager(join_key=ISA100_DEFAULT_JOIN_KEY, subnet_id=0x100A)
        nonce = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        resp = sec_mgr.process_join_request("00:15:8D:00:00:12:34:56", join_nonce=nonce)

        assert resp.status_code == 0x00
        assert resp.short_address == 0x0002
        assert resp.subnet_id == 0x100A
        assert len(resp.session_key) == 16
        assert len(resp.mic) == 4

        # Second device joins
        resp2 = sec_mgr.process_join_request("00:15:8D:00:00:12:34:57", join_nonce=nonce)
        assert resp2.short_address == 0x0003

        # Re-joining device gets its existing address
        resp1_rejoin = sec_mgr.process_join_request("00:15:8D:00:00:12:34:56", join_nonce=nonce)
        assert resp1_rejoin.short_address == 0x0002

    def test_security_manager_invalid_join_key_raises(self) -> None:
        """Verify join request with incorrect join key raises SecurityHandshakeError."""
        sec_mgr = ISA100SecurityManager(join_key=b"CorrectJoinKey16")
        with pytest.raises(SecurityHandshakeError, match="Join key authentication failure"):
            sec_mgr.process_join_request("00:15:8D:00:00:12:34:56", join_nonce=b"\x01\x02\x03\x04", provided_key=b"WrongJoinKey16__")

    def test_security_manager_subnet_mismatch_raises(self) -> None:
        """Verify join request with mismatched subnet ID raises SecurityHandshakeError."""
        sec_mgr = ISA100SecurityManager(subnet_id=0x100A)
        with pytest.raises(SecurityHandshakeError, match="Subnet ID mismatch"):
            sec_mgr.process_join_request("00:15:8D:00:00:12:34:56", join_nonce=b"\x01\x02\x03\x04", subnet_id=0x9999)

    def test_packet_serialization_deserialization_roundtrip(self) -> None:
        """Verify full ISA100.11a packet serialization and deserialization with 4-byte MIC."""
        pkt = ISA100Packet(
            subnet_id=ISA100_DEFAULT_SUBNET_ID,
            source_address=0x0002,
            dest_address=0x0001,
            asn=100,
            object_class=int(ISA100ObjectClass.ANALOG_INPUT),
            payload=encode_ai_response(status=0xC0, units=32, pv=125.4),
        )
        raw = pkt.serialize(key=ISA100_DEFAULT_KEY)
        p_ok = ISA100Packet.deserialize(raw, key=ISA100_DEFAULT_KEY, verify=True)
        assert p_ok.source_address == 0x0002
        assert p_ok.asn == 100
        assert p_ok.object_class == int(ISA100ObjectClass.ANALOG_INPUT)

    def test_tampered_packet_raises_mic_integrity_error(self) -> None:
        """Verify tampered raw packet raises MICIntegrityError."""
        pkt = ISA100Packet(
            subnet_id=ISA100_DEFAULT_SUBNET_ID,
            source_address=0x0002,
            dest_address=0x0001,
            asn=1,
            object_class=int(ISA100ObjectClass.ANALOG_INPUT),
            payload=b"\xC0\x00\x20\x00\x00\x00\x00",
        )
        raw = bytearray(pkt.serialize(ISA100_DEFAULT_KEY))
        raw[5] ^= 0x01  # Tamper with byte
        with pytest.raises(MICIntegrityError):
            ISA100Packet.deserialize(bytes(raw), key=ISA100_DEFAULT_KEY, verify=True)

    def test_packet_truncation_raises_isa100_error(self) -> None:
        """Verify packet smaller than minimum header size raises ISA100Error."""
        with pytest.raises(ISA100Error, match="Raw packet too short"):
            ISA100Packet.deserialize(b"\x10\x0A\x00\x02")


# ============================================================================
# Section 5: UAP Object Model (AI, DI, Concentrator) Encoding & Decoding
# ============================================================================


class TestSection5UAPObjectModelAndScaling:
    """Tests for UAP Object Model (AI, DI, Concentrator) serialization/deserialization and unit scaling."""

    def test_ai_encoding_decoding_roundtrip(self) -> None:
        """Verify Analog Input (AI) Object encoding and decoding."""
        enc = encode_ai_response(status=0xC0, units=32, pv=125.4, high_limit=500.0, low_limit=-50.0)
        dec = decode_ai_response(enc)
        assert dec.status == 0xC0
        assert dec.units == 32
        assert math.isclose(dec.pv, 125.4, abs_tol=0.01)
        assert math.isclose(dec.high_limit, 500.0, abs_tol=0.01)
        assert math.isclose(dec.low_limit, -50.0, abs_tol=0.01)

    def test_di_encoding_decoding_roundtrip(self) -> None:
        """Verify Discrete Input (DI) Object encoding and decoding."""
        enc_true = encode_di_response(status=0xC0, state=True, direction=1)
        dec_true = decode_di_response(enc_true)
        assert dec_true.status == 0xC0
        assert dec_true.state is True
        assert dec_true.direction == 1

        enc_false = encode_di_response(status=0x80, state=False, direction=0)
        dec_false = decode_di_response(enc_false)
        assert dec_false.status == 0x80
        assert dec_false.state is False
        assert dec_false.direction == 0

    def test_concentrator_encoding_decoding_roundtrip(self) -> None:
        """Verify Concentrator Object encoding and decoding."""
        enc = encode_concentrator_response(
            ai_values=[25.0, 75.5, 100.2],
            di_states=[True, False, True],
            status=0xC0,
        )
        dec = decode_concentrator_response(enc)
        assert dec.status == 0xC0
        assert len(dec.ai_values) == 3
        assert math.isclose(dec.ai_values[0], 25.0, abs_tol=0.01)
        assert math.isclose(dec.ai_values[1], 75.5, abs_tol=0.01)
        assert math.isclose(dec.ai_values[2], 100.2, abs_tol=0.01)
        assert dec.di_states == [True, False, True]

    def test_scale_pv_to_int16(self) -> None:
        """Verify scaling float32 values to INT16 engineering units with clamping."""
        assert scale_pv_to_int16(125.4, scale_factor=10.0) == 1254
        assert scale_pv_to_int16(250.0, scale_factor=10.0) == 2500
        assert scale_pv_to_int16(5000.0, scale_factor=10.0) == 32767  # Clamped to INT16 max
        assert scale_pv_to_int16(-5000.0, scale_factor=10.0) == -32768  # Clamped to INT16 min

    def test_payload_truncation_raises(self) -> None:
        """Verify truncated payloads raise PayloadDecodeError."""
        with pytest.raises(PayloadDecodeError, match="AI payload too short"):
            decode_ai_response(b"\xC0\x00")

        with pytest.raises(PayloadDecodeError, match="DI payload too short"):
            decode_di_response(b"\xC0\x01")

        with pytest.raises(PayloadDecodeError, match="Concentrator payload"):
            decode_concentrator_response(b"\xC0\x02\x01\x42")


# ============================================================================
# Section 6: Multi-Hop Mesh Routing Table, RSSI Tracking, & Disconnect Detection
# ============================================================================


class TestSection6MultiHopMeshRoutingTable:
    """Tests for mesh routing table, multi-hop path traversal, spatial path redundancy, and RSSI tracking."""

    def test_routing_table_32_node_capacity(self) -> None:
        """Assert mesh table supports up to 32 field nodes and rejects 33rd."""
        table = ISA100MeshRoutingTable(max_nodes=32)
        for i in range(1, 33):
            table.register_or_update_node(
                short_address=i,
                primary_parent=ISA100_GATEWAY_ADDRESS if i <= 10 else ((i % 10) + 1),
                hop_count=1 if i <= 10 else 2,
                rssi_dbm=-65.0 - (i % 20),
            )
        assert table.active_count == 32
        assert table.total_nodes == 32

        # 33rd node must raise MeshRoutingError
        with pytest.raises(MeshRoutingError):
            table.register_or_update_node(short_address=33)

    def test_node_parent_child_relationships(self) -> None:
        """Verify parent node tracks registered children in children set."""
        table = ISA100MeshRoutingTable()
        parent = table.register_or_update_node(short_address=0x0002, primary_parent=0x0001, hop_count=1)
        child1 = table.register_or_update_node(short_address=0x0003, primary_parent=0x0002, hop_count=2)
        child2 = table.register_or_update_node(short_address=0x0004, primary_parent=0x0002, hop_count=2)

        assert 0x0003 in parent.children
        assert 0x0004 in parent.children
        assert child1.primary_parent == 0x0002
        assert child2.primary_parent == 0x0002
        assert child1.hex_id == "0003"

    def test_multi_hop_path_resolution(self) -> None:
        """Verify 1-hop, 2-hop, and 3-hop shortest path resolution to gateway."""
        table = ISA100MeshRoutingTable()
        table.register_or_update_node(short_address=0x0002, primary_parent=0x0001, hop_count=1)
        table.register_or_update_node(short_address=0x0003, primary_parent=0x0001, hop_count=1)
        table.register_or_update_node(
            short_address=0x0004,
            primary_parent=0x0002,
            secondary_parent=0x0003,
            hop_count=2,
            rssi_dbm=-75.0,
        )

        path = table.find_path_to_gateway(0x0004)
        assert path == [0x0004, 0x0002, 0x0001]
        assert table.has_redundant_path(0x0004) is True

    def test_fallback_to_secondary_parent_when_primary_offline(self) -> None:
        """Verify find_path_to_gateway falls back to secondary parent when primary is offline."""
        table = ISA100MeshRoutingTable()
        n2 = table.register_or_update_node(short_address=0x0002, primary_parent=0x0001)
        table.register_or_update_node(short_address=0x0003, primary_parent=0x0001)
        table.register_or_update_node(
            short_address=0x0004,
            primary_parent=0x0002,
            secondary_parent=0x0003,
        )

        n2.is_online = False
        fallback_path = table.find_path_to_gateway(0x0004)
        assert fallback_path == [0x0004, 0x0003, 0x0001]

    def test_route_disconnect_detection(self) -> None:
        """Verify find_path_to_gateway detects disconnected node and raises MeshRoutingError."""
        table = ISA100MeshRoutingTable()
        n2 = table.register_or_update_node(short_address=0x0002, primary_parent=0x0001)
        table.register_or_update_node(short_address=0x0004, primary_parent=0x0002, secondary_parent=None)

        n2.is_online = False
        with pytest.raises(MeshRoutingError, match="Route disconnect"):
            table.find_path_to_gateway(0x0004)

    def test_routing_cycle_detection(self) -> None:
        """Verify routing table detects cycle and raises MeshRoutingError."""
        table = ISA100MeshRoutingTable()
        table.register_or_update_node(short_address=0x0002, primary_parent=0x0003)
        table.register_or_update_node(short_address=0x0003, primary_parent=0x0002)

        with pytest.raises(MeshRoutingError, match="cycle detected"):
            table.find_path_to_gateway(0x0002)

    def test_average_rssi_metric(self) -> None:
        """Verify average RSSI computation across all online field devices."""
        table = ISA100MeshRoutingTable()
        table.register_or_update_node(short_address=0x0002, primary_parent=0x0001, rssi_dbm=-60.0)
        table.register_or_update_node(short_address=0x0003, primary_parent=0x0001, rssi_dbm=-80.0)

        assert math.isclose(table.average_rssi, -70.0, abs_tol=0.1)

    def test_node_watchdog_inactivity(self) -> None:
        """Verify check_watchdogs marks inactive nodes offline after timeout."""
        table = ISA100MeshRoutingTable()
        t0 = time.time()
        table.register_or_update_node(short_address=0x0002, primary_parent=0x0001, now=t0 - 40.0)
        table.register_or_update_node(short_address=0x0003, primary_parent=0x0001, now=t0)

        expired = table.check_watchdogs(timeout_s=30.0, current_time=t0)
        assert len(expired) == 1
        assert expired[0].short_address == 0x0002
        assert table.online_count == 1
        assert table.active_count == 2

    def test_node_removal_and_clear(self) -> None:
        """Verify removing nodes updates children sets and clearing empties table."""
        table = ISA100MeshRoutingTable()
        table.register_or_update_node(short_address=0x0002, primary_parent=0x0001)
        table.register_or_update_node(short_address=0x0003, primary_parent=0x0002)
        assert table.active_count == 2

        assert table.remove_node(0x0003) is True
        assert table.active_count == 1
        assert table.get_node(0x0003) is None

        table.clear()
        assert table.active_count == 0


# ============================================================================
# Section 7: Process Safety Trips & Diagnostic Codes
# ============================================================================


class TestSection7ProcessSafetyTrips:
    """Tests for safety trips 0x9B01..0x9B04 asserting %M212/%M213 and diagnostic codes."""

    def test_superframe_timeout_trip_0x9B01(self, network_manager: ISA100NetworkManager) -> None:
        """Verify 0x9B01 Superframe Sync Timeout Trip asserts %M213 and clears %M212."""
        mgr = network_manager
        mgr.routing_table.register_or_update_node(short_address=0x0002)
        mgr._sync_registers()
        assert mgr.reg_table.read_bit("%M212") is True
        assert mgr.reg_table.read_bit("%M213") is False

        tripped = mgr.check_superframe_watchdog(simulated_elapsed_s=ISA100_SUPERFRAME_TIMEOUT_S + 5.0)
        assert tripped is True
        assert mgr.reg_table.read_uword("%R917") == int(ISA100DiagnosticCode.SUPERFRAME_TIMEOUT_TRIP)
        assert mgr.reg_table.read_bit("%M213") is True
        assert mgr.reg_table.read_bit("%M212") is False
        assert bool(mgr.reg_table.read_uword("%R910") & ISA100StatusBits.SUPERFRAME_TIMEOUT_TRIP) is True

    def test_security_mic_fail_alarm_0x9B02(self, network_manager: ISA100NetworkManager) -> None:
        """Verify 0x9B02 Security MIC Failure Alarm sets bit 5 in %R910 and updates %R917."""
        mgr = network_manager
        mgr.routing_table.register_or_update_node(short_address=0x0002)

        bad_frame = b"\x10\x0A\x00\x02\x00\x01\x00\x00\x00\x00\x00\x64\x00\x07\x00\x03\xC0\x00\x20\x42\xFA\xCC\xCD\xDE\xAD\xBE\xEF"
        res = mgr.process_raw_bytes(bad_frame)
        assert res is False
        assert mgr.reg_table.read_uword("%R917") == int(ISA100DiagnosticCode.SECURITY_MIC_FAIL_ALARM)
        assert bool(mgr.reg_table.read_uword("%R910") & ISA100StatusBits.SECURITY_MIC_FAIL_ALARM) is True

    def test_routing_fail_alarm_0x9B03(self, network_manager: ISA100NetworkManager) -> None:
        """Verify 0x9B03 Routing Failure Alarm sets bit 6 in %R910 and updates %R917."""
        mgr = network_manager
        res = mgr.process_raw_bytes(b"\xFF\xFF\x01\x02")
        assert res is False
        assert mgr.reg_table.read_uword("%R917") == int(ISA100DiagnosticCode.ROUTING_FAIL_ALARM)
        assert bool(mgr.reg_table.read_uword("%R910") & ISA100StatusBits.ROUTING_FAIL_ALARM) is True

    def test_node_disconnect_trip_0x9B04(self, network_manager: ISA100NetworkManager) -> None:
        """Verify 0x9B04 Node Disconnect Trip asserts %M213 and clears %M212 when all field nodes disconnect."""
        mgr = network_manager
        mgr.routing_table.register_or_update_node(short_address=0x0002, now=100.0)
        mgr._sync_registers()
        assert mgr.reg_table.read_bit("%M212") is True

        tripped = mgr.check_nodes_watchdog(simulated_elapsed_s=ISA100_DEFAULT_WATCHDOG_TIMEOUT_S + 10.0)
        assert tripped is True
        assert mgr.reg_table.read_uword("%R917") == int(ISA100DiagnosticCode.NODE_DISCONNECT_TRIP)
        assert mgr.reg_table.read_bit("%M213") is True
        assert mgr.reg_table.read_bit("%M212") is False
        assert bool(mgr.reg_table.read_uword("%R910") & ISA100StatusBits.NODE_DISCONNECT_TRIP) is True

    def test_reset_fault_trip_recovery(self, network_manager: ISA100NetworkManager) -> None:
        """Verify reset_fault_trip clears all alarms and restores %M212."""
        mgr = network_manager
        mgr.check_superframe_watchdog(simulated_elapsed_s=100.0)
        assert mgr.reg_table.read_bit("%M213") is True

        mgr.reset_fault_trip()
        assert mgr.diagnostic_code == ISA100DiagnosticCode.OK
        assert mgr.reg_table.read_uword("%R917") == 0x0000
        assert mgr.reg_table.read_bit("%M213") is False
        assert mgr.reg_table.read_bit("%M212") is True

    def test_diagnostic_codes_and_status_bits_enumerations(self) -> None:
        """Verify process safety trip codes and Horner status bits bitmask definitions."""
        assert int(ISA100DiagnosticCode.OK) == 0x0000
        assert int(ISA100DiagnosticCode.SUPERFRAME_TIMEOUT_TRIP) == 0x9B01
        assert int(ISA100DiagnosticCode.SECURITY_MIC_FAIL_ALARM) == 0x9B02
        assert int(ISA100DiagnosticCode.ROUTING_FAIL_ALARM) == 0x9B03
        assert int(ISA100DiagnosticCode.NODE_DISCONNECT_TRIP) == 0x9B04

        assert int(ISA100StatusBits.NETWORK_ACTIVE) == 0x0001
        assert int(ISA100StatusBits.MESH_SYNCHRONIZED) == 0x0002
        assert int(ISA100StatusBits.TDMA_RUNNING) == 0x0004
        assert int(ISA100StatusBits.SLOW_HOPPING_ACTIVE) == 0x0008
        assert int(ISA100StatusBits.SUPERFRAME_TIMEOUT_TRIP) == 0x0010
        assert int(ISA100StatusBits.SECURITY_MIC_FAIL_ALARM) == 0x0020
        assert int(ISA100StatusBits.ROUTING_FAIL_ALARM) == 0x0040
        assert int(ISA100StatusBits.NODE_DISCONNECT_TRIP) == 0x0080


# ============================================================================
# Section 8: Horner OCS Memory Space Integration (%R910..%R917, %M212..%M213)
# ============================================================================


class TestSection8HornerOCSMemoryIntegration:
    """Tests for Horner OCS register space synchronization (%R910..%R917, %M212..%M213)."""

    def test_initial_register_space_state(self, network_manager: ISA100NetworkManager) -> None:
        """Verify initial register state matches Horner OCS specifications."""
        assert network_manager.reg_table.read_word("%R911") == 0
        assert network_manager.reg_table.read_word("%R912") == 0
        assert network_manager.reg_table.read_word("%R913") == 0
        assert network_manager.reg_table.read_word("%R914") == 0
        assert network_manager.reg_table.read_word("%R916") == 0
        assert network_manager.reg_table.read_uword("%R917") == 0x0000
        assert network_manager.reg_table.read_bit("%M212") is True
        assert network_manager.reg_table.read_bit("%M213") is False

    def test_ai_packet_register_sync(self, network_manager: ISA100NetworkManager) -> None:
        """Verify AI packet updates %R912 (Service), %R913 (PV x10), %R916 (Packets), and %M212."""
        ai_pay = encode_ai_response(status=0xC0, units=32, pv=125.4)
        pkt = ISA100Packet(
            source_address=0x0002,
            object_class=int(ISA100ObjectClass.ANALOG_INPUT),
            payload=ai_pay,
        )
        ok = network_manager.process_packet(pkt)
        assert ok is True

        assert network_manager.reg_table.read_word("%R911") == 1
        assert network_manager.reg_table.read_word("%R912") == int(ISA100ObjectClass.ANALOG_INPUT)
        assert network_manager.reg_table.read_word("%R913") == 1254  # 125.4 * 10
        assert network_manager.reg_table.read_word("%R916") == 1
        assert network_manager.reg_table.read_bit("%M212") is True
        assert network_manager.reg_table.read_bit("%M213") is False

    def test_di_packet_register_sync(self, network_manager: ISA100NetworkManager) -> None:
        """Verify DI packet updates %R912 and %R914 (SV x10)."""
        di_pay = encode_di_response(status=0xC0, state=True, direction=1)
        pkt = ISA100Packet(
            source_address=0x0002,
            object_class=int(ISA100ObjectClass.DISCRETE_INPUT),
            payload=di_pay,
        )
        ok = network_manager.process_packet(pkt)
        assert ok is True

        assert network_manager.reg_table.read_word("%R912") == int(ISA100ObjectClass.DISCRETE_INPUT)
        assert network_manager.reg_table.read_word("%R914") == 10  # 1.0 * 10
        assert network_manager.reg_table.read_bit("%M212") is True

    def test_concentrator_packet_register_sync(self, network_manager: ISA100NetworkManager) -> None:
        """Verify Concentrator packet updates %R913 (AI[0] x10) and %R914 (AI[1] x10)."""
        conc_pay = encode_concentrator_response(
            ai_values=[250.0, 75.5],
            di_states=[True, False],
            status=0xC0,
        )
        pkt = ISA100Packet(
            source_address=0x0002,
            object_class=int(ISA100ObjectClass.CONCENTRATOR),
            payload=conc_pay,
        )
        ok = network_manager.process_packet(pkt)
        assert ok is True

        assert network_manager.reg_table.read_word("%R912") == int(ISA100ObjectClass.CONCENTRATOR)
        assert network_manager.reg_table.read_word("%R913") == 2500  # 250.0 * 10
        assert network_manager.reg_table.read_word("%R914") == 755   # 75.5 * 10
        assert network_manager.reg_table.read_bit("%M212") is True

    def test_average_mesh_rssi_register_sync(self, network_manager: ISA100NetworkManager) -> None:
        """Verify %R915 accurately reflects average mesh RSSI in signed dBm."""
        network_manager.routing_table.register_or_update_node(short_address=0x0002, primary_parent=0x0001, rssi_dbm=-65.0)
        network_manager.routing_table.register_or_update_node(short_address=0x0003, primary_parent=0x0001, rssi_dbm=-75.0)
        network_manager._sync_registers()

        assert network_manager.reg_table.read_word("%R915") == -70

    def test_clamped_signed_int_values(self, network_manager: ISA100NetworkManager) -> None:
        """Verify scaled PV and SV values clamp cleanly to signed 16-bit range."""
        network_manager.primary_variable = 5000.0  # Scaled x10 = 50000 -> clamps to 32767
        network_manager.secondary_variable = -5000.0  # Scaled x10 = -50000 -> clamps to -32768
        network_manager._sync_registers()

        assert network_manager.reg_table.read_word("%R913") == 32767
        assert network_manager.reg_table.read_word("%R914") == -32768


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================


class TestSection9VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_isa100_11a_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_isa100_11a_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

    def test_run_isa100_11a_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "isa100_11a_evidence.json"
        result = run_isa100_11a_verification(evidence_path=str(evidence_file))

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W130"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert data["data"]["component"] == "Industrial ISA100.11a (IEC 62734) Protocol Engine & Wireless Mesh Manager"
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9
        assert data["data"]["register_map"]["status_word"] == "%R910"
        assert data["data"]["register_map"]["active_nodes_count"] == "%R911"
        assert data["data"]["register_map"]["network_active_coil"] == "%M212"
        assert data["data"]["register_map"]["fault_trip_coil"] == "%M213"
