"""Unit Test Suite for Industrial KNXnet/IP Master Protocol Engine.

Work Package: W121 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (KnxIPMasterSync).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs.
3. Section 3: KNXnet/IP packet header serialization, deserialization, service types, and framing error guards.
4. Section 4: CEMI L_Data frame encoding/decoding and DPT payload scaling (DPT 1.001, DPT 5.001, DPT 9.001).
5. Section 5: Multi-endpoint tunneling session management and sequence counter tracking.
6. Section 6: Process safety trips (0x9201, 0x9202, 0x9203, 0x9204) and Horner coil assertion (%M191, %M192).
7. Section 7: Horner OCS register space synchronization (%R820..%R827).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
import struct
from typing import Any, Dict

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.knx_ip import (
    KNX_IP_DEFAULT_PORT,
    KNX_IP_DEFAULT_WATCHDOG_TIMEOUT_S,
    KNX_IP_MAX_ENDPOINTS,
    KNX_NETIP_HEADER_SIZE,
    KNX_NETIP_VERSION_10,
    KNX_IP_PURE_ST_POU,
    CemiAPCI,
    CemiLData,
    CemiMessageCode,
    KnxAddress,
    KnxDiagnosticCode,
    KnxGroupAddress,
    KnxIndividualAddress,
    KnxIPDiagnosticCode,
    KnxIPMasterEngine,
    KnxIPStatusBits,
    KnxNetIPHeader,
    KnxNetIPPacket,
    KnxNetIPServiceType,
    KnxServiceType,
    KnxStatusBits,
    KnxTunnelEndpoint,
    decode_dpt1,
    decode_dpt5,
    decode_dpt9,
    encode_dpt1,
    encode_dpt5,
    encode_dpt9,
    run_knx_ip_verification,
    verify_knx_ip_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def knx_engine(register_table: RegisterTable) -> KnxIPMasterEngine:
    """Provide a fresh KnxIPMasterEngine with an initialized register table."""
    return KnxIPMasterEngine(reg_table=register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance, AST verification, and register bindings."""

    def test_verify_knx_ip_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_knx_ip_pure_st() is True

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Parse KNX_IP_PURE_ST_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(KNX_IP_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "KnxIPMasterSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "KnxIPStatusWord",
            "ActiveEndpointsCount",
            "LastServiceTypeExecuted",
            "DPT1SwitchState",
            "DPT5ScalingScaled",
            "DPT9TemperatureScaled",
            "SequenceCounter",
            "DiagnosticEventCode",
            "KnxIPSessionActive",
            "KnxIPFaultTrip",
            "SessionActiveBit",
            "HeartbeatOkBit",
            "TunnelConnectedBit",
            "TimeoutTripBit",
            "FramingAlarmBit",
            "SequenceAlarmBit",
            "DptOverflowBit",
            "DiagnosticTrip",
        }
        assert expected_vars.issubset(var_names)

        expected_bound_regs = {
            "%R820", "%R821", "%R822", "%R823", "%R824",
            "%R825", "%R826", "%R827", "%M191", "%M192",
        }
        assert expected_bound_regs.issubset(set(pou.bound_registers))

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POU passes SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(KNX_IP_PURE_ST_POU)


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
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M191 OTE %M192 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: KNXnet/IP Packet Header Serialization, Deserialization, & Framing
# ============================================================================

class TestSection3KnxNetIPPacketFraming:
    """Tests for KNXnet/IP encapsulation framing, service types, and error guards."""

    def test_header_serialization_deserialization(self) -> None:
        """Verify 6-byte header packing and unpacking roundtrip."""
        hdr = KnxNetIPHeader(
            header_length=6,
            protocol_version=0x10,
            service_type=KnxNetIPServiceType.CONNECT_REQUEST,
            total_length=26,
        )
        raw = hdr.serialize()
        assert len(raw) == KNX_NETIP_HEADER_SIZE
        assert raw[0] == 0x06
        assert raw[1] == 0x10

        unpacked = KnxNetIPHeader.deserialize(raw)
        assert unpacked.header_length == 6
        assert unpacked.protocol_version == 0x10
        assert unpacked.service_type == int(KnxNetIPServiceType.CONNECT_REQUEST)
        assert unpacked.total_length == 26

    def test_packet_tunnelling_request_roundtrip(self) -> None:
        """Verify TUNNELLING_REQUEST datagram serialization and deserialization."""
        body_payload = b"\x04\x01\x05\x00\x11\x00\xBC\xE0\x11\x01\x08\x01\x01\x00\x81"
        pkt = KnxNetIPPacket(
            service_type=KnxNetIPServiceType.TUNNELLING_REQUEST,
            body=body_payload,
        )
        raw = pkt.serialize()
        assert len(raw) == KNX_NETIP_HEADER_SIZE + len(body_payload)
        assert pkt.total_length == len(raw)

        unpacked = KnxNetIPPacket.deserialize(raw)
        assert unpacked.service_type == int(KnxNetIPServiceType.TUNNELLING_REQUEST)
        assert unpacked.body == body_payload
        assert unpacked.total_length == len(raw)

    def test_packet_connectionstate_request_roundtrip(self) -> None:
        """Verify CONNECTIONSTATE_REQUEST packet serialization and deserialization."""
        body = b"\x01\x00\x08\x01\xC0\xA8\x01\x64\x0E\x57"  # Channel 1, reserved 0, HPAI IPv4 UDP
        pkt = KnxNetIPPacket(
            service_type=KnxNetIPServiceType.CONNECTIONSTATE_REQUEST,
            body=body,
        )
        raw = pkt.pack()
        unpacked = KnxNetIPPacket.unpack(raw)
        assert unpacked.service_type == int(KnxNetIPServiceType.CONNECTIONSTATE_REQUEST)
        assert unpacked.body == body

    def test_packet_invalid_header_length_raises(self) -> None:
        """Verify header length other than 6 raises ValueError."""
        with pytest.raises(ValueError, match="KNXnet/IP header length must be 6"):
            KnxNetIPHeader.deserialize(b"\x08\x10\x02\x05\x00\x0E")

        with pytest.raises(ValueError, match="KNXnet/IP header length must be 6"):
            KnxNetIPPacket(header_length=8)

    def test_packet_invalid_protocol_version_raises(self) -> None:
        """Verify protocol version other than 0x10 raises ValueError."""
        with pytest.raises(ValueError, match="KNXnet/IP protocol version must be 0x10"):
            KnxNetIPHeader.deserialize(b"\x06\x20\x02\x05\x00\x0E")

        with pytest.raises(ValueError, match="KNXnet/IP protocol version must be 0x10"):
            KnxNetIPPacket(protocol_version=0x20)

    def test_packet_truncated_raises(self) -> None:
        """Verify header buffer shorter than 6 bytes raises ValueError."""
        with pytest.raises(ValueError, match="less than minimum KNXnet/IP header size"):
            KnxNetIPPacket.deserialize(b"\x06\x10\x02")

    def test_packet_total_length_mismatch_raises(self) -> None:
        """Verify payload length mismatch against header total length raises ValueError."""
        pkt = KnxNetIPPacket(
            service_type=KnxNetIPServiceType.TUNNELLING_ACK,
            body=b"\x04\x01\x00\x00",
        )
        raw = bytearray(pkt.pack())
        # Truncate trailing byte
        with pytest.raises(ValueError, match="framing mismatch"):
            KnxNetIPPacket.deserialize(bytes(raw[:-1]))

    def test_service_type_enumerations(self) -> None:
        """Verify all standard KNXnet/IP service types conform to specification."""
        assert int(KnxNetIPServiceType.SEARCH_REQUEST) == 0x0201
        assert int(KnxNetIPServiceType.SEARCH_RESPONSE) == 0x0202
        assert int(KnxNetIPServiceType.DESCRIPTION_REQUEST) == 0x0203
        assert int(KnxNetIPServiceType.DESCRIPTION_RESPONSE) == 0x0204
        assert int(KnxNetIPServiceType.CONNECT_REQUEST) == 0x0205
        assert int(KnxNetIPServiceType.CONNECT_RESPONSE) == 0x0206
        assert int(KnxNetIPServiceType.CONNECTIONSTATE_REQUEST) == 0x0207
        assert int(KnxNetIPServiceType.CONNECTIONSTATE_RESPONSE) == 0x0208
        assert int(KnxNetIPServiceType.DISCONNECT_REQUEST) == 0x0209
        assert int(KnxNetIPServiceType.DISCONNECT_RESPONSE) == 0x020A
        assert int(KnxNetIPServiceType.TUNNELLING_REQUEST) == 0x0420
        assert int(KnxNetIPServiceType.TUNNELLING_ACK) == 0x0421
        assert int(KnxNetIPServiceType.ROUTING_INDICATION) == 0x0530


# ============================================================================
# Section 4: CEMI L_Data Frame Encoding/Decoding & DPT Payload Scaling
# ============================================================================

class TestSection4CemiAndDptScaling:
    """Tests for CEMI L_Data frame structure and DPT 1.001, 5.001, 9.001 conversions."""

    def test_knx_individual_address_parsing(self) -> None:
        """Verify Area.Line.Device individual address packing and parsing."""
        addr = KnxAddress.from_string("1.2.34")
        assert addr.area == 1
        assert addr.line == 2
        assert addr.device == 34
        packed = addr.to_int()
        # (1 << 12) | (2 << 8) | 34 = 4096 + 512 + 34 = 4642
        assert packed == 4642
        assert str(addr) == "1.2.34"
        assert KnxAddress.from_int(packed) == addr

        # Out of bounds
        with pytest.raises(ValueError):
            KnxAddress(area=16, line=0, device=0)
        with pytest.raises(ValueError):
            KnxAddress.from_string("1.2")

    def test_knx_group_address_parsing(self) -> None:
        """Verify Main/Middle/Sub 3-level group address packing and parsing."""
        grp = KnxGroupAddress.from_string("3/4/56")
        assert grp.main == 3
        assert grp.middle == 4
        assert grp.sub == 56
        packed = grp.to_int()
        # (3 << 11) | (4 << 8) | 56 = 6144 + 1024 + 56 = 7224
        assert packed == 7224
        assert str(grp) == "3/4/56"
        assert KnxGroupAddress.from_int(packed) == grp

        # Out of bounds
        with pytest.raises(ValueError):
            KnxGroupAddress(main=32, middle=0, sub=0)
        with pytest.raises(ValueError):
            KnxGroupAddress.from_string("1/2")

    def test_cemi_ldata_pack_unpack_dpt1_switch(self) -> None:
        """Verify CEMI L_Data frame with DPT 1.001 (1-bit small payload)."""
        cemi = CemiLData(
            message_code=CemiMessageCode.L_DATA_REQ,
            source_address="1.1.10",
            destination_address="1/2/3",
            apci=CemiAPCI.A_GROUP_VALUE_WRITE,
            data=bytes([encode_dpt1(True)]),
            is_small_payload=True,
        )
        raw = cemi.pack()
        unpacked = CemiLData.unpack(raw)

        assert unpacked.message_code == int(CemiMessageCode.L_DATA_REQ)
        assert unpacked.source_address == KnxAddress.from_string("1.1.10").to_int()
        assert unpacked.destination_address == KnxGroupAddress.from_string("1/2/3").to_int()
        assert unpacked.is_small_payload is True
        assert decode_dpt1(unpacked.data) is True

    def test_cemi_ldata_pack_unpack_dpt5_scaling(self) -> None:
        """Verify CEMI L_Data frame with DPT 5.001 (8-bit scaling percentage)."""
        cemi = CemiLData(
            message_code=CemiMessageCode.L_DATA_IND,
            source_address="1.1.20",
            destination_address="2/1/5",
            apci=CemiAPCI.A_GROUP_VALUE_WRITE,
            data=bytes([encode_dpt5(80.0)]),
            is_small_payload=False,
        )
        raw = cemi.pack()
        unpacked = CemiLData.unpack(raw)

        assert unpacked.message_code == int(CemiMessageCode.L_DATA_IND)
        assert unpacked.is_small_payload is False
        assert abs(decode_dpt5(unpacked.data) - 80.0) < 0.5

    def test_cemi_ldata_pack_unpack_dpt9_float(self) -> None:
        """Verify CEMI L_Data frame with DPT 9.001 (2-octet float temperature)."""
        raw_word = encode_dpt9(21.5)
        cemi = CemiLData(
            message_code=CemiMessageCode.L_DATA_REQ,
            source_address="1.1.30",
            destination_address="3/2/1",
            apci=CemiAPCI.A_GROUP_VALUE_WRITE,
            data=struct.pack(">H", raw_word),
            is_small_payload=False,
        )
        raw = cemi.pack()
        unpacked = CemiLData.unpack(raw)

        assert unpacked.is_small_payload is False
        assert abs(decode_dpt9(unpacked.data) - 21.5) < 0.05

    def test_dpt1_switch_encoding_decoding(self) -> None:
        """Verify DPT 1.001 boolean states encode and decode correctly."""
        assert encode_dpt1(True) == 1
        assert encode_dpt1(False) == 0
        assert decode_dpt1(1) is True
        assert decode_dpt1(0) is False
        assert decode_dpt1(b"\x01") is True
        assert decode_dpt1(b"\x00") is False

    def test_dpt5_scaling_encoding_decoding(self) -> None:
        """Verify DPT 5.001 percentage conversions across 0%, 50%, 100%."""
        assert encode_dpt5(0.0) == 0
        assert encode_dpt5(100.0) == 255
        assert encode_dpt5(50.0) in (127, 128)

        assert decode_dpt5(0) == 0.0
        assert decode_dpt5(255) == 100.0
        assert abs(decode_dpt5(128) - 50.2) < 0.5

    def test_dpt5_out_of_range_raises(self) -> None:
        """Verify DPT 5.001 values out of 0.0..100.0% range raise ValueError."""
        with pytest.raises(ValueError, match="out of range"):
            encode_dpt5(-0.1)
        with pytest.raises(ValueError, match="out of range"):
            encode_dpt5(100.1)
        with pytest.raises(ValueError, match="out of range"):
            decode_dpt5(256)

    def test_dpt9_temperature_encoding_decoding(self) -> None:
        """Verify DPT 9.001 2-octet float conversions across various temperatures."""
        temperatures = [0.0, 15.0, 21.5, 37.8, 100.0, -5.0, -25.5]
        for t in temperatures:
            encoded = encode_dpt9(t)
            decoded = decode_dpt9(encoded)
            assert abs(decoded - t) < 0.1

    def test_dpt9_negative_values(self) -> None:
        """Verify DPT 9.001 signed negative numbers decode accurately."""
        encoded = encode_dpt9(-10.0)
        assert (encoded & 0x8000) != 0  # Sign bit set
        decoded = decode_dpt9(encoded)
        assert abs(decoded - (-10.0)) < 0.05

    def test_dpt9_zero_value(self) -> None:
        """Verify DPT 9.001 zero encodes to 0x0000."""
        assert encode_dpt9(0.0) == 0x0000
        assert decode_dpt9(0x0000) == 0.0

    def test_dpt9_bounds_and_overflow(self) -> None:
        """Verify DPT 9.001 handles float bounds and rejects NaN/Inf."""
        with pytest.raises(ValueError, match="Invalid float"):
            encode_dpt9(float("nan"))
        with pytest.raises(ValueError, match="Invalid float"):
            encode_dpt9(float("inf"))
        with pytest.raises(ValueError, match="out of range"):
            encode_dpt9(1_000_000.0)

    def test_cemi_frame_truncated_raises(self) -> None:
        """Verify truncated CEMI frame buffer raises ValueError."""
        with pytest.raises(ValueError, match="CEMI frame shorter than minimum"):
            CemiLData.deserialize(b"\x11\x00\xBC")


# ============================================================================
# Section 5: Multi-Endpoint Tunneling Session Management & Sequence Tracking
# ============================================================================

class TestSection5MultiEndpointTunneling:
    """Tests for tunneling endpoint registry, 16-channel capacity, and sequence tracking."""

    def test_tunnel_endpoint_initiate_and_capacity_limit(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify up to 16 endpoints can be registered, and 17th is rejected."""
        endpoints = []
        for i in range(KNX_IP_MAX_ENDPOINTS):
            ep = knx_engine.initiate_tunnel(
                endpoint_ip=f"192.168.1.{10 + i}",
                individual_address=f"1.1.{i + 1}",
            )
            endpoints.append(ep)
            assert ep.channel_id == i + 1

        assert len(knx_engine.active_endpoints) == 16
        assert knx_engine.reg_table.read_word("%R821") == 16

        with pytest.raises(ValueError, match="Maximum active KNX/IP tunneling endpoints limit"):
            knx_engine.initiate_tunnel(endpoint_ip="192.168.1.100")

    def test_tunnel_endpoint_close(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify closing a tunnel endpoint frees channel and updates table."""
        ep1 = knx_engine.initiate_tunnel(endpoint_ip="192.168.1.10")
        ep2 = knx_engine.initiate_tunnel(endpoint_ip="192.168.1.11")
        assert len(knx_engine.active_endpoints) == 2

        assert knx_engine.close_tunnel(ep1.channel_id) is True
        assert len(knx_engine.active_endpoints) == 1
        assert knx_engine.reg_table.read_word("%R821") == 1

        assert knx_engine.close_tunnel(999) is False

    def test_tunnel_sequence_counter_tracking(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify each tunneling request increments sequence counter monotonically."""
        ep = knx_engine.initiate_tunnel(endpoint_ip="192.168.1.10")
        cemi = CemiLData(source_address="1.1.1", destination_address="1/1/1")

        pkt0 = knx_engine.build_tunneling_request(ep.channel_id, cemi)
        seq0 = struct.unpack(">BBBB", pkt0.body[:4])[2]
        assert seq0 == 0

        pkt1 = knx_engine.build_tunneling_request(ep.channel_id, cemi)
        seq1 = struct.unpack(">BBBB", pkt1.body[:4])[2]
        assert seq1 == 1

        assert ep.sequence_counter == 2
        assert knx_engine.reg_table.read_word("%R826") == 2

    def test_tunneling_request_and_ack_roundtrip(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify dispatching tunneling request and processing corresponding ACK."""
        ep = knx_engine.initiate_tunnel(endpoint_ip="192.168.1.10")
        cemi = CemiLData(source_address="1.1.1", destination_address="1/1/1")

        req_pkt = knx_engine.build_tunneling_request(ep.channel_id, cemi)
        seq = struct.unpack(">BBBB", req_pkt.body[:4])[2]

        ack_pkt = knx_engine.build_tunneling_ack(ep.channel_id, seq)
        ok = knx_engine.process_incoming_tunneling_ack(ep.channel_id, ack_pkt, expected_sequence=seq)
        assert ok is True
        assert bool(knx_engine.status_bits & KnxIPStatusBits.HEARTBEAT_OK) is True

    def test_connectionstate_request_and_response(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify CONNECTIONSTATE_REQUEST dispatch and response parsing."""
        ep = knx_engine.initiate_tunnel(endpoint_ip="192.168.1.10")
        resp_pkt = KnxNetIPPacket(
            service_type=KnxNetIPServiceType.CONNECTIONSTATE_RESPONSE,
            body=struct.pack(">BB", ep.channel_id, 0),  # Channel ID, Status E_NO_ERROR
        )
        res = knx_engine.process_incoming_packet(resp_pkt.pack())
        assert res["status"] == "ok"
        assert res["channel_id"] == ep.channel_id


# ============================================================================
# Section 6: Process Safety Trips & Diagnostic Codes
# ============================================================================

class TestSection6ProcessSafetyTrips:
    """Tests for safety trip 0x9201 and alarms 0x9202, 0x9203, 0x9204, asserting %M191/%M192."""

    def test_session_timeout_trip_0x9201(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify 0x9201 Session Timeout Trip asserts %M192 and deasserts %M191."""
        knx_engine.initiate_tunnel(endpoint_ip="192.168.1.10")
        assert knx_engine.reg_table.read_bit("%M191") is True
        assert knx_engine.reg_table.read_bit("%M192") is False

        # Inactivity watchdog timeout
        knx_engine.check_connectionstate_watchdog(simulated_elapsed_s=15.0)

        assert knx_engine.diagnostic_code == KnxIPDiagnosticCode.SESSION_TIMEOUT_TRIP
        assert knx_engine.reg_table.read_uword("%R827") == 0x9201
        assert knx_engine.reg_table.read_bit("%M192") is True
        assert knx_engine.reg_table.read_bit("%M191") is False
        assert bool(knx_engine.reg_table.read_uword("%R820") & KnxIPStatusBits.SESSION_TIMEOUT_TRIP) is True

    def test_framing_error_alarm_0x9202(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify 0x9202 Framing Error sets bit 5 in %R820 and updates %R827."""
        knx_engine.initiate_tunnel()
        # Send packet with corrupted total length
        with pytest.raises(ValueError):
            knx_engine.process_incoming_packet(b"\x06\x10\x04\x20\x00\xFF\x01\x02")

        assert knx_engine.diagnostic_code == KnxIPDiagnosticCode.FRAMING_ERROR_ALARM
        assert knx_engine.reg_table.read_uword("%R827") == 0x9202
        assert bool(knx_engine.reg_table.read_uword("%R820") & KnxIPStatusBits.FRAMING_ERROR_ALARM) is True

    def test_sequence_out_of_order_alarm_0x9203(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify 0x9203 Sequence Alarm sets bit 6 in %R820 and updates %R827."""
        ep = knx_engine.initiate_tunnel()
        bad_ack = knx_engine.build_tunneling_ack(ep.channel_id, sequence_counter=99)
        ok = knx_engine.process_incoming_tunneling_ack(ep.channel_id, bad_ack, expected_sequence=1)
        assert ok is False

        assert knx_engine.diagnostic_code == KnxIPDiagnosticCode.SEQUENCE_OUT_OF_ORDER_ALARM
        assert knx_engine.reg_table.read_uword("%R827") == 0x9203
        assert bool(knx_engine.reg_table.read_uword("%R820") & KnxIPStatusBits.SEQUENCE_FAULT_ALARM) is True

    def test_dpt_overflow_alarm_0x9204(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify 0x9204 DPT Payload Overflow sets bit 7 in %R820 and updates %R827."""
        ep = knx_engine.initiate_tunnel()
        # Create CEMI frame with invalid DPT 5 value (e.g. invalid bytes)
        cemi = CemiLData(
            source_address="1.1.1",
            destination_address="1/1/1",
            data=b"\x01\x02\x03\x04\x05",  # 5 bytes, unhandled
        )
        # Force DPT decode error
        knx_engine._trigger_dpt_overflow_alarm()
        assert knx_engine.diagnostic_code == KnxIPDiagnosticCode.DPT_OVERFLOW_ALARM
        assert knx_engine.reg_table.read_uword("%R827") == 0x9204
        assert bool(knx_engine.reg_table.read_uword("%R820") & KnxIPStatusBits.DPT_OVERFLOW_ALARM) is True

    def test_heartbeat_loss_trip_0x9204(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify 0x9204 Heartbeat Loss Trip asserts %M192=True and clears %M191=False."""
        knx_engine.initiate_tunnel(endpoint_ip="192.168.1.55")
        assert knx_engine.reg_table.read_bit("%M191") is True
        assert knx_engine.reg_table.read_bit("%M192") is False

        knx_engine._trigger_heartbeat_loss_trip()
        assert knx_engine.diagnostic_code == KnxIPDiagnosticCode.HEARTBEAT_LOSS_TRIP
        assert knx_engine.reg_table.read_uword("%R827") == 0x9204
        assert knx_engine.reg_table.read_bit("%M192") is True
        assert knx_engine.reg_table.read_bit("%M191") is False
        assert bool(knx_engine.reg_table.read_uword("%R820") & KnxIPStatusBits.HEARTBEAT_LOSS_TRIP) is True

    def test_fault_trip_reset(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify resetting fault clears trip bits and restores nominal status."""
        knx_engine.initiate_tunnel()
        knx_engine.simulate_session_timeout()
        assert knx_engine.reg_table.read_bit("%M192") is True

        knx_engine.reset_fault_trip()
        assert knx_engine.diagnostic_code == KnxIPDiagnosticCode.OK
        assert knx_engine.reg_table.read_uword("%R827") == 0x0000
        assert knx_engine.reg_table.read_bit("%M192") is False
        assert knx_engine.reg_table.read_bit("%M191") is True



# ============================================================================
# Section 7: Horner OCS Memory Space Integration (%R820..%R827)
# ============================================================================

class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS memory space synchronization and register scaling."""

    def test_register_space_synchronization(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify %R820..%R827 and %M191..%M192 reflect engine state accurately."""
        knx_engine.initiate_tunnel()
        knx_engine.dpt1_switch_state = 1
        knx_engine.dpt5_scaling_percent = 75.50
        knx_engine.dpt9_temperature_c = 21.5
        knx_engine.total_telegrams = 10
        knx_engine.last_service_type = int(KnxNetIPServiceType.TUNNELLING_REQUEST)
        knx_engine._sync_registers()

        assert knx_engine.reg_table.read_word("%R821") == 1
        assert knx_engine.reg_table.read_uword("%R822") == 0x0420
        assert knx_engine.reg_table.read_word("%R823") == 1
        assert knx_engine.reg_table.read_word("%R824") == 7550  # 75.50% * 100
        assert knx_engine.reg_table.read_word("%R825") == 215   # 21.5 * 10
        assert knx_engine.reg_table.read_word("%R826") == 10
        assert knx_engine.reg_table.read_uword("%R827") == 0x0000
        assert knx_engine.reg_table.read_bit("%M191") is True
        assert knx_engine.reg_table.read_bit("%M192") is False

    def test_dpt1_switch_register_sync(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify DPT 1.001 switch state writes directly to %R823."""
        cemi = CemiLData(
            source_address="1.1.1",
            destination_address="1/1/1",
            data=bytes([1]),
            is_small_payload=True,
        )
        knx_engine.process_cemi_telegram(cemi)
        assert knx_engine.reg_table.read_word("%R823") == 1

        cemi_off = CemiLData(
            source_address="1.1.1",
            destination_address="1/1/1",
            data=bytes([0]),
            is_small_payload=True,
        )
        knx_engine.process_cemi_telegram(cemi_off)
        assert knx_engine.reg_table.read_word("%R823") == 0

    def test_dpt5_scaling_register_sync(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify DPT 5.001 scaling percentage writes to %R824 scaled x100."""
        cemi = CemiLData(
            source_address="1.1.1",
            destination_address="1/1/1",
            data=bytes([encode_dpt5(50.0)]),
            is_small_payload=False,
        )
        knx_engine.process_cemi_telegram(cemi)
        # 50.0% -> ~5020 or ~5000 depending on resolution
        r824 = knx_engine.reg_table.read_word("%R824")
        assert 4980 <= r824 <= 5040

    def test_dpt9_temperature_register_sync(self, knx_engine: KnxIPMasterEngine) -> None:
        """Verify DPT 9.001 temperature float writes to %R825 scaled x10."""
        cemi = CemiLData(
            source_address="1.1.1",
            destination_address="1/1/1",
            data=struct.pack(">H", encode_dpt9(24.5)),
            is_small_payload=False,
        )
        knx_engine.process_cemi_telegram(cemi)
        assert knx_engine.reg_table.read_word("%R825") == 245


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================

class TestSection8VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_knx_ip_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_knx_ip_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

    def test_run_knx_ip_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "knx_ip_evidence.json"
        result = run_knx_ip_verification(evidence_path=str(evidence_file))

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W121"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert data["data"]["component"] == "Industrial KNX/IP Net'n'Node Protocol Engine"
        assert data["data"]["checks_passed"] == 9
