"""Comprehensive Unit and Integration Test Suite for Industrial HART Over IP (HART-IP) & WirelessHART Gateway Engine.

Work Package: W184 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation
   (%R1450..%R1457, %M338..%M339).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: HART-IP packet framing (port 5094), 8-byte header serialization, sequence tracking,
   and malformed packet detection (0xD103).
4. Section 4: WirelessHART Time-Slotted Channel Hopping (TSCH 10ms, 15 channels 11..25),
   and channel blacklisting bitmask (%R1456).
5. Section 5: Mesh topology, device registration, and security join procedure (MIC & join key, 0xD102).
6. Section 6: Standard HART application commands execution (Cmd 0, Cmd 1, Cmd 3, Cmd 48)
   and structured payload decoding.
7. Section 7: Mesh burst publishing, latency tracking (nominal 145 = 14.5ms), PDR tracking (nominal 992 = 99.2%),
   and superframe timing (%R1451..%R1453).
8. Section 8: Process safety trips (0xD101 mesh collapse, 0xD104 device comm timeout)
   and Horner discrete coils (%M338, %M339).
9. Section 9: Horner OCS register space synchronization with PrivilegeMode.SYSTEM,
   ILogicUnit scan cycle execution, and the deterministic 9-stage verification suite.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import tempfile
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.hart_ip_gateway import (
    DEFAULT_SUPERFRAME_CYCLE_MS,
    DEVICE_COMM_TIMEOUT,
    DEVICE_COMM_TIMEOUT_MS,
    ERR_DEVICE_COMM_TIMEOUT,
    ERR_MALFORMED_PACKET,
    ERR_MESH_COMMUNICATION_COLLAPSE,
    ERR_SECURITY_JOIN_REJECTED,
    HART_ERR_DEVICE_COMM_TIMEOUT,
    HART_ERR_MALFORMED_PACKET,
    HART_ERR_MESH_COMMUNICATION_COLLAPSE,
    HART_ERR_SECURITY_JOIN_REJECTED,
    HART_IP_DEFAULT_VERSION,
    HART_IP_HEADER_SIZE,
    HART_IP_PORT,
    HART_IP_WIRELESS_GATEWAY_SYNC_POU,
    MALFORMED_PACKET,
    MAX_CONSECUTIVE_SUPERFRAME_DROPS,
    MAX_WIRELESS_DEVICES,
    MESH_COMMUNICATION_COLLAPSE,
    MIN_PERMISSIBLE_PDR_SCALED,
    NOMINAL_DEVICES_COUNT,
    NOMINAL_LATENCY_SCALED,
    NOMINAL_PDR_PERCENT,
    NOMINAL_PDR_SCALED,
    NOMINAL_TRANSACTION_LATENCY_MS,
    SECURITY_JOIN_REJECTED,
    TSCH_CHANNELS,
    TSCH_NUM_CHANNELS,
    TSCH_TIMESLOT_DURATION_MS,
    WIRELESS_HART_DEFAULT_JOIN_KEY,
    WIRELESS_HART_MAX_DEVICES,
    WIRELESS_HART_NETWORK_ENGINE_SYNC_POU,
    HartCommand,
    HartIpDeviceTimeoutError,
    HartIpDiagnosticCode,
    HartIpGateway,
    HartIpGatewayState,
    HartIpGatewayStateBits,
    HartIpHeader,
    HartIpMalformedPacketError,
    HartIpMessageID,
    HartIpMessageType,
    HartIpPacket,
    HartIpSecurityJoinError,
    HartIpStatusCode,
    HartIpWirelessGatewayEngine,
    HartUnitCode,
    WirelessDeviceDescriptor,
    build_cmd0_response,
    build_cmd1_response,
    build_cmd3_response,
    build_cmd48_response,
    calc_channel_hopping,
    calc_mic,
    verify_mic,
    parse_cmd0_response,
    parse_cmd1_response,
    parse_cmd3_response,
    parse_cmd48_response,
    run_hart_ip_gateway_verification,
    verify_hart_ip_gateway_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Symbol Binding
# ============================================================================

class TestSection1PureSTPOU:
    """Validates IEC 61131-3 Pure ST POU syntax and register bindings."""

    def test_verify_hart_ip_gateway_pure_st_helper(self) -> None:
        """Helper verify_hart_ip_gateway_pure_st returns True deterministically."""
        assert verify_hart_ip_gateway_pure_st() is True

    def test_pure_st_pou_ast_parsing_and_variables(self) -> None:
        """Parses HartIpWirelessGatewaySync and checks register bindings."""
        ast = STParser.parse_pou(HART_IP_WIRELESS_GATEWAY_SYNC_POU)
        assert ast.name == "HartIpWirelessGatewaySync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1450", "%R1451", "%R1452", "%R1453",
            "%R1454", "%R1455", "%R1456", "%R1457",
            "%M338", "%M339",
        }
        assert set(ast.bound_registers) == expected_regs

    def test_alias_pou_ast_parsing(self) -> None:
        """Parses WirelessHartNetworkEngineSync alias POU."""
        ast = STParser.parse_pou(WIRELESS_HART_NETWORK_ENGINE_SYNC_POU)
        assert ast.name == "WirelessHartNetworkEngineSync"
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R1450", "%R1451", "%R1452", "%R1453",
            "%R1454", "%R1455", "%R1456", "%R1457",
            "%M338", "%M339",
        }
        assert set(ast.bound_registers) == expected_regs

    def test_st_parser_validate_code(self) -> None:
        """Validates code via STParser.validate_code."""
        res1 = STParser.validate_code(HART_IP_WIRELESS_GATEWAY_SYNC_POU)
        assert res1.status == AgentStatus.SUCCESS

        res2 = STParser.validate_code(WIRELESS_HART_NETWORK_ENGINE_SYNC_POU)
        assert res2.status == AgentStatus.SUCCESS

    def test_pure_st_security_guard_assertion(self) -> None:
        """SecurityGuard accepts pure ST POUs without raising."""
        SecurityGuard.assert_pure_st_content(HART_IP_WIRELESS_GATEWAY_SYNC_POU)
        SecurityGuard.assert_pure_st_content(WIRELESS_HART_NETWORK_ENGINE_SYNC_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Asserts SecurityGuard rejects ladder logic constructs with LadderForbiddenError."""

    def test_ladder_contacts_rejected(self) -> None:
        """Ladder contact constructs trigger LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nVAR\nEND_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_coils_rejected(self) -> None:
        """Ladder coil constructs trigger LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nVAR\nEND_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_rungs_rejected(self) -> None:
        """RUNG delimiters trigger LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nVAR\nEND_VAR\nRUNG 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_ladder_mnemonics_rejected(self) -> None:
        """Ladder mnemonics like XIC and OTE trigger LadderForbiddenError."""
        for mnemonic in ["XIC In_1", "OTE Out_1"]:
            bad_code = f"PROGRAM Bad\nVAR\nEND_VAR\n{mnemonic}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 3: HART-IP Framing & Header Serialization
# ============================================================================

class TestSection3HartIpFramingAndHeaders:
    """Validates UDP/TCP port 5094 HART-IP header and packet framing."""

    def test_header_pack_unpack_roundtrip(self) -> None:
        """Pack and unpack 8-byte HART-IP header."""
        hdr = HartIpHeader(
            version=1,
            message_type=HartIpMessageType.REQUEST,
            message_id=HartIpMessageID.PASS_THROUGH_PDU,
            status=HartIpStatusCode.SUCCESS,
            sequence_number=1234,
            byte_count=20,
        )
        raw = hdr.serialize()
        assert len(raw) == HART_IP_HEADER_SIZE

        decoded = HartIpHeader.deserialize(raw)
        assert decoded.version == 1
        assert decoded.message_type == HartIpMessageType.REQUEST
        assert decoded.message_id == HartIpMessageID.PASS_THROUGH_PDU
        assert decoded.status == HartIpStatusCode.SUCCESS
        assert decoded.sequence_number == 1234
        assert decoded.byte_count == 20

    def test_packet_pack_unpack_roundtrip(self) -> None:
        """Pack and unpack complete HART-IP packet with payload."""
        payload = b"\x01\x02\x03\x04\x05\x06"
        pkt = HartIpPacket(
            version=1,
            message_type=HartIpMessageType.RESPONSE,
            message_id=HartIpMessageID.PASS_THROUGH_PDU,
            status=HartIpStatusCode.SUCCESS,
            sequence_number=555,
            payload=payload,
        )
        raw = pkt.serialize()
        assert len(raw) == HART_IP_HEADER_SIZE + len(payload)

        decoded = HartIpPacket.deserialize(raw)
        assert decoded.version == 1
        assert decoded.message_type == HartIpMessageType.RESPONSE
        assert decoded.sequence_number == 555
        assert decoded.payload == payload
        assert decoded.byte_count == len(raw)

    def test_malformed_packet_truncated_header(self) -> None:
        """Header shorter than 8 bytes raises HartIpMalformedPacketError."""
        with pytest.raises(HartIpMalformedPacketError):
            HartIpHeader.deserialize(b"\x01\x02\x03")

        with pytest.raises(HartIpMalformedPacketError):
            HartIpPacket.deserialize(b"\x01\x02\x03")

    def test_malformed_packet_framing_mismatch(self) -> None:
        """Byte count mismatch raises HartIpMalformedPacketError."""
        hdr = HartIpHeader(byte_count=20)
        raw = hdr.serialize() + b"short"  # Only 13 bytes total instead of 20
        with pytest.raises(HartIpMalformedPacketError):
            HartIpPacket.deserialize(raw)

    def test_malformed_packet_illegal_message_type(self) -> None:
        """Message type outside (0..3) raises HartIpMalformedPacketError."""
        bad_raw = struct.pack(">BBBBHH", 1, 99, 3, 0, 1, 8)
        with pytest.raises(HartIpMalformedPacketError):
            HartIpHeader.deserialize(bad_raw)


# ============================================================================
# Section 4: WirelessHART TSCH & Channel Blacklisting
# ============================================================================

class TestSection4WirelessHartTSCHAndBlacklisting:
    """Validates 10ms timeslots, 15 channels (11..25), and blacklisting bitmask (%R1456)."""

    def test_tsch_channels_and_slot_timing(self) -> None:
        """15 physical IEEE 802.15.4 channels from 11 through 25, 10ms slot."""
        assert TSCH_TIMESLOT_DURATION_MS == 10
        assert TSCH_NUM_CHANNELS == 15
        assert TSCH_CHANNELS == (11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25)

    def test_channel_hopping_formula(self) -> None:
        """calc_channel_hopping computes deterministic channel."""
        ch0 = calc_channel_hopping(asn=100, channel_offset=0)
        ch1 = calc_channel_hopping(asn=100, channel_offset=1)
        assert 11 <= ch0 <= 25
        assert 11 <= ch1 <= 25
        assert ch0 != ch1

    def test_channel_blacklisting_bitmask_operations(self) -> None:
        """Blacklist channel 15 and 20 via bitmask (%R1456)."""
        engine = HartIpWirelessGatewayEngine()
        assert engine.channel_blacklist_mask == 0

        engine.blacklist_channel(15)
        # 15 - 11 = 4 -> bit 4 = 16
        assert engine.channel_blacklist_mask == 16
        assert engine.is_channel_blacklisted(15) is True
        assert engine.is_channel_blacklisted(16) is False

        engine.blacklist_channel(20)
        # 20 - 11 = 9 -> bit 9 = 512 -> 16 | 512 = 528
        assert engine.channel_blacklist_mask == 528
        assert engine.is_channel_blacklisted(20) is True

        active = engine.get_active_channels()
        assert 15 not in active
        assert 20 not in active
        assert len(active) == 13

        # Unblacklist
        engine.unblacklist_channel(15)
        assert engine.channel_blacklist_mask == 512
        assert engine.is_channel_blacklisted(15) is False
        assert 15 in engine.get_active_channels()

    def test_hopping_avoids_blacklisted_channels(self) -> None:
        """Channel hopping never picks blacklisted channels across sequence."""
        active = [ch for ch in TSCH_CHANNELS if ch not in (15, 20)]
        for asn_val in range(1000, 1100):
            for offset in range(15):
                ch = calc_channel_hopping(asn=asn_val, channel_offset=offset, active_channels=active)
                assert ch != 15
                assert ch != 20


# ============================================================================
# Section 5: Topology & Security Join Procedure
# ============================================================================

class TestSection5MeshTopologyAndSecurityJoin:
    """Validates network manager, field devices, join keys, and 4-byte MIC."""

    def test_mic_generation_and_verification(self) -> None:
        """calc_mic and verify_mic HMAC-SHA256 calculations."""
        data = b"JoinPayloadTest123"
        mic = calc_mic(data, WIRELESS_HART_DEFAULT_JOIN_KEY)
        assert len(mic) == 4
        assert verify_mic(data, mic, WIRELESS_HART_DEFAULT_JOIN_KEY) is True
        assert verify_mic(data, b"\x00\x00\x00\x00", WIRELESS_HART_DEFAULT_JOIN_KEY) is False

    def test_successful_device_join(self) -> None:
        """New wireless device successfully joins the mesh network."""
        engine = HartIpWirelessGatewayEngine()
        initial_count = engine.active_wireless_devices_count
        new_nick = 0x0025
        uid = b"\x00\x1B\x1E\x00\x25"
        join_data = uid + struct.pack(">H", new_nick)
        valid_mic = calc_mic(join_data, WIRELESS_HART_DEFAULT_JOIN_KEY)

        ok, dev = engine.join_device(
            unique_id=uid,
            requested_nickname=new_nick,
            join_key=WIRELESS_HART_DEFAULT_JOIN_KEY,
            provided_mic=valid_mic,
            tag="PT_250",
        )
        assert ok is True
        assert dev is not None
        assert dev.nickname == new_nick
        assert engine.active_wireless_devices_count == initial_count + 1
        assert engine.devices[new_nick].tag == "PT_250"

    def test_security_join_rejection_bad_key(self) -> None:
        """Mismatched join key triggers 0xD102 security rejection."""
        engine = HartIpWirelessGatewayEngine()
        uid = b"\x00\x1B\x1E\x00\x99"
        bad_key = b"BadKey1234567890"
        mic = calc_mic(uid + struct.pack(">H", 0x0099), bad_key)

        ok, dev = engine.join_device(
            unique_id=uid,
            requested_nickname=0x0099,
            join_key=bad_key,
            provided_mic=mic,
        )
        assert ok is False
        assert dev is None
        assert engine.diagnostic_code == HartIpDiagnosticCode.HART_ERR_SECURITY_JOIN_REJECTED
        assert engine.fault_trip is True
        assert engine.permissive is False


# ============================================================================
# Section 6: Standard HART Application Commands
# ============================================================================

class TestSection6StandardHARTCommands:
    """Validates execution and decoding of Cmd 0, Cmd 1, Cmd 3, and Cmd 48."""

    def test_cmd0_read_unique_id(self) -> None:
        """Command 0 returns device identification payload."""
        engine = HartIpWirelessGatewayEngine()
        resp = engine.transact_command(device_nickname=0x0002, command=HartCommand.READ_UNIQUE_ID)
        parsed = parse_cmd0_response(resp.payload)
        assert parsed["manufacturer_id"] == 0x0026
        assert parsed["universal_rev"] == 7
        assert "device_id" in parsed

    def test_cmd1_read_primary_variable(self) -> None:
        """Command 1 returns status, PV units, and PV float value."""
        engine = HartIpWirelessGatewayEngine()
        dev = engine.devices[0x0002]
        resp = engine.transact_command(device_nickname=0x0002, command=HartCommand.READ_PRIMARY_VARIABLE)
        parsed = parse_cmd1_response(resp.payload)
        assert parsed["device_status"] == dev.device_status
        assert parsed["pv_units"] == dev.pv_units
        assert math.isclose(parsed["pv_value"], dev.pv_value, rel_tol=1e-3)

    def test_cmd3_read_dynamic_variables_and_current(self) -> None:
        """Command 3 returns loop current mA and 4 dynamic process variables."""
        engine = HartIpWirelessGatewayEngine()
        dev = engine.devices[0x0002]
        resp = engine.transact_command(device_nickname=0x0002, command=HartCommand.READ_DYNAMIC_VARS_CURRENT)
        parsed = parse_cmd3_response(resp.payload)
        assert math.isclose(parsed["loop_current_ma"], dev.loop_current_ma, rel_tol=1e-3)
        assert math.isclose(parsed["pv_value"], dev.pv_value, rel_tol=1e-3)
        assert math.isclose(parsed["sv_value"], dev.sv_value, rel_tol=1e-3)
        assert math.isclose(parsed["tv_value"], dev.tv_value, rel_tol=1e-3)
        assert math.isclose(parsed["qv_value"], dev.qv_value, rel_tol=1e-3)

    def test_cmd48_read_additional_transmitter_status(self) -> None:
        """Command 48 returns 25-byte diagnostic status array."""
        engine = HartIpWirelessGatewayEngine()
        resp = engine.transact_command(device_nickname=0x0002, command=HartCommand.READ_ADDITIONAL_STATUS)
        assert len(resp.payload) == 25
        parsed = parse_cmd48_response(resp.payload)
        assert len(parsed["raw_bytes"]) == 25


# ============================================================================
# Section 7: Mesh Burst Publishing & Latency / PDR Tracking
# ============================================================================

class TestSection7MeshBurstPublishingAndMetrics:
    """Validates burst publish cycle, latency scaling (x10), and PDR scaling (x10)."""

    def test_nominal_burst_publish_metrics(self) -> None:
        """Nominal burst publishing reports 99.2% PDR (992) and 14.5ms latency (145)."""
        engine = HartIpWirelessGatewayEngine()
        res = engine.execute_mesh_burst_cycle()
        assert res["status"] == "success"
        assert res["pdr_scaled"] == NOMINAL_PDR_SCALED
        assert res["latency_scaled"] == NOMINAL_LATENCY_SCALED
        assert engine.reg_table.read_word("%R1451") == 992
        assert engine.reg_table.read_word("%R1452") == 145
        assert engine.reg_table.read_word("%R1453") == 250

    def test_state_word_bitmask_under_burst(self) -> None:
        """State word reflects BURST_PUBLISHING and GATEWAY_ACTIVE."""
        engine = HartIpWirelessGatewayEngine()
        engine.execute_mesh_burst_cycle()
        sw = engine.reg_table.read_word("%R1455")
        assert (sw & int(HartIpGatewayStateBits.BURST_PUBLISHING)) != 0
        assert (sw & int(HartIpGatewayStateBits.GATEWAY_ACTIVE)) != 0
        assert (sw & int(HartIpGatewayStateBits.PERMISSIVE)) != 0
        assert (sw & int(HartIpGatewayStateBits.FAULT_TRIP)) == 0


# ============================================================================
# Section 8: Process Safety Interlocks & Discrete Coils
# ============================================================================

class TestSection8ProcessSafetyInterlocks:
    """Validates 0xD101 collapse and 0xD104 timeout trips (%M338, %M339)."""

    def test_trip_d101_mesh_communication_collapse_pdr(self) -> None:
        """PDR < 80.0% asserts 0xD101, trips %M339, clears %M338."""
        engine = HartIpWirelessGatewayEngine()
        res = engine.execute_superframe(force_pdr_scaled=750)  # 75.0% < 80.0%
        assert res["status"] == "fault"
        assert engine.diagnostic_code == HartIpDiagnosticCode.HART_ERR_MESH_COMMUNICATION_COLLAPSE
        assert engine.reg_table.read_uword("%R1457") == 0xD101
        assert engine.reg_table.read_bit("%M339") is True
        assert engine.reg_table.read_bit("%M338") is False

    def test_trip_d101_three_consecutive_superframe_drops(self) -> None:
        """3 consecutive dropped superframes assert 0xD101."""
        engine = HartIpWirelessGatewayEngine()
        res = engine.execute_superframe(simulate_consecutive_drops=3)
        assert res["status"] == "fault"
        assert engine.diagnostic_code == HartIpDiagnosticCode.HART_ERR_MESH_COMMUNICATION_COLLAPSE
        assert engine.reg_table.read_uword("%R1457") == 0xD101
        assert engine.reg_table.read_bit("%M339") is True
        assert engine.reg_table.read_bit("%M338") is False

    def test_trip_d104_target_device_communication_timeout(self) -> None:
        """Response delay > 3000ms raises HartIpDeviceTimeoutError and asserts 0xD104."""
        engine = HartIpWirelessGatewayEngine()
        with pytest.raises(HartIpDeviceTimeoutError):
            engine.transact_command(device_nickname=0x0002, command=1, simulate_delay_ms=3500.0)

        assert engine.diagnostic_code == HartIpDiagnosticCode.HART_ERR_DEVICE_COMM_TIMEOUT
        assert engine.reg_table.read_uword("%R1457") == 0xD104
        assert engine.reg_table.read_bit("%M339") is True
        assert engine.reg_table.read_bit("%M338") is False

    def test_operator_reset_handshake_restores_permissive(self) -> None:
        """Operator reset clears fault trip and restores permissive coil."""
        engine = HartIpWirelessGatewayEngine()
        engine.simulate_mesh_collapse(pdr_scaled=700)
        assert engine.reg_table.read_bit("%M339") is True

        res = engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == HartIpDiagnosticCode.OK
        assert engine.reg_table.read_uword("%R1457") == 0x0000
        assert engine.reg_table.read_bit("%M338") is True
        assert engine.reg_table.read_bit("%M339") is False


# ============================================================================
# Section 9: Register Space Synchronization & ILogicUnit
# ============================================================================

class TestSection9RegisterSpaceAndILogicUnit:
    """Validates ILogicUnit scan cycle and 9-stage verification suite."""

    def test_ilogicunit_interface_compliance(self) -> None:
        """Engine conforms to ILogicUnit interface."""
        engine = HartIpWirelessGatewayEngine()
        assert engine.name == "hart_ip_gateway"
        assert engine.priority == 94
        assert engine.is_enabled is True

    def test_closed_loop_scan_context_execution(self) -> None:
        """ScanContext execution advances simulation clock."""
        engine = HartIpWirelessGatewayEngine()
        rt = engine.reg_table
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=100.0,
            get_register=rt.read_register,
            set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )
        engine.execute(ctx)
        assert engine.elapsed_simulation_ms == 10.0
        assert rt.read_bit("%M338") is True

    def test_full_deterministic_9_stage_verification_suite(self) -> None:
        """Executes run_hart_ip_gateway_verification and validates 4-state output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = Path(tmpdir) / "evidence_w184.json"
            result = run_hart_ip_gateway_verification(output_path=out_json)

            assert result["status"] == "success"
            assert result["error_code"] is None
            assert result["data"]["checks_passed"] == 9
            assert result["data"]["total_checks"] == 9
            assert out_json.exists()

            with open(out_json, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert saved["data"]["work_package"] == "W184"
