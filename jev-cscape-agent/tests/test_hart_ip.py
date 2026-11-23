"""Unit Test Suite for Industrial HART-IP Protocol Engine.

Work Package: W118 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure IEC 61131-3 Structured Text (ST) POU validation & AST parsing (HartIPMasterSync).
2. HART-IP packet framing (v1/v2, message types, message IDs, status, seq, byte count).
3. HART Token / Burst PDU parser and XOR longitudinal parity check (LRC).
4. Multi-drop session management (table capacity of 16 devices, keep-alive watchdog).
5. Universal & common practice command parsers (Cmd 0, 1, 3, 9, 48) & dynamic variables.
6. Process safety interlocks: 0x8F01 Session Timeout Trip, 0x8F02 Checksum Alarm,
   0x8F03 Sequence Alarm, 0x8F04 Keep-Alive Loss Trip.
7. Horner OCS register space synchronization (%R790..%R797, %M184, %M185).
8. Anti-ladder construct security guard interception (ERR_LADDER_FORBIDDEN).
9. End-to-end 9-stage verification suite (run_hart_ip_verification).
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
import struct

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.hart_ip import (
    DELIMITER_ACK_LONG,
    DELIMITER_ACK_SHORT,
    DELIMITER_BACK_LONG,
    DELIMITER_BACK_SHORT,
    DELIMITER_STX_LONG,
    DELIMITER_STX_SHORT,
    HART_IP_DEFAULT_INACTIVITY_MS,
    HART_IP_DEFAULT_VERSION,
    HART_IP_DEFAULT_WATCHDOG_TIMEOUT_S,
    HART_IP_HEADER_SIZE,
    HART_IP_MAX_SESSIONS,
    HART_IP_PURE_ST_POU,
    HartCommand,
    HartIPDeviceSession,
    HartIPDiagnosticCode,
    HartIPMasterEngine,
    HartIPMessageID,
    HartIPMessageType,
    HartIPPacket,
    HartIPStatusBits,
    HartIPStatusCode,
    HartTokenPDU,
    HartUnitCode,
    build_cmd0_response,
    build_cmd1_response,
    build_cmd3_response,
    build_cmd9_response,
    build_cmd48_response,
    calculate_hart_lrc,
    parse_cmd0_response,
    parse_cmd1_response,
    parse_cmd3_response,
    parse_cmd9_response,
    parse_cmd48_response,
    run_hart_ip_verification,
    scale_engineering_units,
    verify_hart_ip_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def hart_engine(register_table: RegisterTable) -> HartIPMasterEngine:
    """Provide a fresh HartIPMasterEngine with an initialized register table."""
    return HartIPMasterEngine(reg_table=register_table)


# ============================================================================
# 1. Pure ST POU AST Validation & Anti-Ladder Check
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance and anti-ladder security."""

    def test_verify_hart_ip_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_hart_ip_pure_st() is True

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Parse HART_IP_PURE_ST_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(HART_IP_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "HartIPMasterSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "HartIPStatusWord",
            "ActiveSessionsCount",
            "LastCommandExecuted",
            "PrimaryVariablePvScaled",
            "LoopCurrentMaScaled",
            "SecondaryVariableSvScaled",
            "SequenceNumberCounter",
            "DiagnosticEventCode",
            "HartIPSessionActive",
            "HartIPFaultTrip",
            "SessionActiveBit",
            "KeepAliveOkBit",
            "TimeoutTripBit",
            "KeepAliveLossBit",
            "DiagnosticTrip",
        }
        assert expected_vars.issubset(var_names)

        expected_bound_regs = {
            "%R790", "%R791", "%R792", "%R793", "%R794",
            "%R795", "%R796", "%R797", "%M184", "%M185",
        }
        assert expected_bound_regs.issubset(set(pou.bound_registers))

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POU passes SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(HART_IP_PURE_ST_POU)


# ============================================================================
# 2. HART-IP Packet Framing & Protocol Specification
# ============================================================================

class TestSection2HartIPPacketFraming:
    """Tests for HART-IP encapsulation framing, message types, and validation."""

    def test_packet_pack_unpack_v1(self) -> None:
        """Verify version 1 packet serialization and deserialization."""
        pkt = HartIPPacket(
            version=1,
            message_type=HartIPMessageType.REQUEST,
            message_id=HartIPMessageID.SESSION_INITIATE,
            status=HartIPStatusCode.SUCCESS,
            sequence_number=42,
            payload=b"\x00\x00\x27\x10",
        )
        raw = pkt.pack()
        assert len(raw) == HART_IP_HEADER_SIZE + 4
        assert raw[0] == 1  # Version 1

        unpacked = HartIPPacket.unpack(raw)
        assert unpacked.version == 1
        assert unpacked.message_type == HartIPMessageType.REQUEST
        assert unpacked.message_id == HartIPMessageID.SESSION_INITIATE
        assert unpacked.status == HartIPStatusCode.SUCCESS
        assert unpacked.sequence_number == 42
        assert unpacked.byte_count == 12
        assert unpacked.payload == b"\x00\x00\x27\x10"

    def test_packet_pack_unpack_v2(self) -> None:
        """Verify version 2 packet serialization and deserialization."""
        pkt = HartIPPacket(
            version=2,
            message_type=HartIPMessageType.PUBLISH,
            message_id=HartIPMessageID.PASS_THROUGH_PDU,
            status=HartIPStatusCode.SUCCESS,
            sequence_number=1000,
            payload=b"\x01\x02\x03\x04\x05",
        )
        raw = pkt.pack()
        assert raw[0] == 2
        unpacked = HartIPPacket.unpack(raw)
        assert unpacked.version == 2
        assert unpacked.message_type == HartIPMessageType.PUBLISH
        assert unpacked.message_id == HartIPMessageID.PASS_THROUGH_PDU
        assert unpacked.payload == b"\x01\x02\x03\x04\x05"

    def test_packet_invalid_version_raises(self) -> None:
        """Verify version other than 1 or 2 raises ValueError."""
        with pytest.raises(ValueError, match="HART-IP version must be 1 or 2"):
            HartIPPacket(version=3)

    def test_packet_truncated_raises(self) -> None:
        """Verify header shorter than 8 bytes raises ValueError."""
        with pytest.raises(ValueError, match="less than minimum HART-IP header size"):
            HartIPPacket.unpack(b"\x01\x00\x00\x00")

    def test_packet_length_mismatch_raises(self) -> None:
        """Verify payload length mismatch against header byte count raises ValueError."""
        valid_pkt = HartIPPacket(sequence_number=1, payload=b"\xAA\xBB")
        raw = bytearray(valid_pkt.pack())
        # Corrupt packet length by trimming trailing byte
        with pytest.raises(ValueError, match="framing mismatch"):
            HartIPPacket.unpack(bytes(raw[:-1]))


# ============================================================================
# 3. HART Token / Burst PDU Parser & LRC Parity Check
# ============================================================================

class TestSection3HartTokenPDU:
    """Tests for Token & Burst PDU encoding, addressing, and XOR LRC checksum."""

    def test_lrc_calculation(self) -> None:
        """Verify XOR longitudinal parity check (LRC) calculation."""
        data = bytes([0x02, 0x80, 0x00, 0x00])
        # 0x02 ^ 0x80 ^ 0x00 ^ 0x00 = 0x82
        assert calculate_hart_lrc(data) == 0x82

    def test_short_address_pdu_pack_and_unpack(self) -> None:
        """Verify STX request PDU with 1-byte polling address roundtrips."""
        pdu = HartTokenPDU(
            delimiter=DELIMITER_STX_SHORT,
            address=3,
            command=HartCommand.READ_PRIMARY_VARIABLE,
            data=b"",
        )
        raw = pdu.pack()
        assert raw[0] == DELIMITER_STX_SHORT
        assert raw[1] == 3
        assert raw[2] == int(HartCommand.READ_PRIMARY_VARIABLE)
        assert raw[3] == 0  # 0 data bytes
        assert pdu.checksum == calculate_hart_lrc(raw[:-1])

        unpacked = HartTokenPDU.unpack(raw)
        assert unpacked.delimiter == DELIMITER_STX_SHORT
        assert unpacked.address == 3
        assert unpacked.command == int(HartCommand.READ_PRIMARY_VARIABLE)
        assert unpacked.data == b""
        assert unpacked.is_long_address is False

    def test_long_address_pdu_pack_and_unpack(self) -> None:
        """Verify ACK response PDU with 5-byte long address roundtrips."""
        long_tag = b"\x80\x01\x11\x22\x33"
        data_payload = build_cmd1_response(pv=100.5, unit_code=32)
        pdu = HartTokenPDU(
            delimiter=DELIMITER_ACK_LONG,
            address=long_tag,
            command=HartCommand.READ_PRIMARY_VARIABLE,
            data=data_payload,
        )
        raw = pdu.pack()
        assert raw[0] == DELIMITER_ACK_LONG
        assert raw[1:6] == long_tag
        assert raw[6] == int(HartCommand.READ_PRIMARY_VARIABLE)
        assert raw[7] == len(data_payload)

        unpacked = HartTokenPDU.unpack(raw)
        assert unpacked.delimiter == DELIMITER_ACK_LONG
        assert unpacked.address == long_tag
        assert unpacked.is_long_address is True
        assert unpacked.data == data_payload

    def test_corrupted_lrc_raises(self) -> None:
        """Verify corrupted LRC checksum raises ValueError."""
        pdu = HartTokenPDU(
            delimiter=DELIMITER_STX_SHORT,
            address=0,
            command=0,
            data=b"",
        )
        raw = bytearray(pdu.pack())
        raw[-1] ^= 0x55  # Corrupt checksum byte
        with pytest.raises(ValueError, match="HART LRC checksum failure"):
            HartTokenPDU.unpack(bytes(raw), verify_lrc=True)

    def test_corrupted_byte_count_raises(self) -> None:
        """Verify corrupted byte count raises ValueError."""
        pdu = HartTokenPDU(
            delimiter=DELIMITER_STX_SHORT,
            address=0,
            command=0,
            data=b"\x01\x02",
        )
        raw = bytearray(pdu.pack())
        raw[3] = 10  # Alter count to 10
        with pytest.raises(ValueError, match="byte count mismatch"):
            HartTokenPDU.unpack(bytes(raw), verify_lrc=False)

    def test_all_delimiter_variants(self) -> None:
        """Verify STX, ACK, and BACK delimiters for short and long frames."""
        delims = [
            (DELIMITER_STX_SHORT, 1, False, False),
            (DELIMITER_ACK_SHORT, 1, True, False),
            (DELIMITER_BACK_SHORT, 1, True, True),
            (DELIMITER_STX_LONG, 5, False, False),
            (DELIMITER_ACK_LONG, 5, True, False),
            (DELIMITER_BACK_LONG, 5, True, True),
        ]
        for delim, addr_len, is_resp, is_burst in delims:
            addr: Union[int, bytes] = 1 if addr_len == 1 else b"\x80\x01\x02\x03\x04"
            pdu = HartTokenPDU(delimiter=delim, address=addr, command=1, data=b"")
            raw = pdu.pack()
            unpacked = HartTokenPDU.unpack(raw)
            assert unpacked.delimiter == delim
            assert (unpacked.is_long_address) == (addr_len == 5)
            assert (unpacked.is_response) == is_resp
            assert (unpacked.is_burst) == is_burst


# ============================================================================
# 4. Multi-Drop Session Management & Keep-Alive Watchdog
# ============================================================================

class TestSection4MultiDropSessionManagement:
    """Tests for multi-drop device session table and keep-alive heartbeat watchdog."""

    def test_session_initiate_and_limit_enforcement(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify up to 16 devices can be registered, and 17th device is rejected."""
        sessions = []
        for d in range(HART_IP_MAX_SESSIONS):
            sess = hart_engine.initiate_session(device_address=d)
            sessions.append(sess)
            assert sess.session_id >= 1001

        assert len(hart_engine.active_sessions) == 16
        assert hart_engine.reg_table.read_word("%R791") == 16

        with pytest.raises(ValueError, match="Maximum active HART-IP sessions limit"):
            hart_engine.initiate_session(device_address=16)

    def test_session_close(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify closing a session removes it and updates active count."""
        s1 = hart_engine.initiate_session(device_address=1)
        s2 = hart_engine.initiate_session(device_address=2)
        assert len(hart_engine.active_sessions) == 2

        assert hart_engine.close_session(s1.session_id) is True
        assert len(hart_engine.active_sessions) == 1
        assert hart_engine.reg_table.read_word("%R791") == 1

        assert hart_engine.close_session(9999) is False

    def test_send_and_receive_keep_alive(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify Keep-Alive request dispatch and response receipt."""
        sess = hart_engine.initiate_session(device_address=1)
        pkt = hart_engine.send_keep_alive(sess.session_id)
        assert pkt.message_id == HartIPMessageID.KEEP_ALIVE
        assert pkt.message_type == HartIPMessageType.REQUEST

        resp = HartIPPacket(
            version=1,
            message_type=HartIPMessageType.RESPONSE,
            message_id=HartIPMessageID.KEEP_ALIVE,
            sequence_number=pkt.sequence_number,
        )
        ok = hart_engine.receive_keep_alive_response(sess.session_id, resp)
        assert ok is True
        assert bool(hart_engine.status_bits & HartIPStatusBits.KEEP_ALIVE_OK) is True


# ============================================================================
# 5. Dynamic Variable & Command Payloads Parsers / Builders
# ============================================================================

class TestSection5DynamicVariablesAndCommandParsers:
    """Tests for universal command builders and dynamic variable parsing."""

    def test_cmd0_unique_id(self) -> None:
        """Verify Cmd 0 Read Unique ID payload builder and parser."""
        data = build_cmd0_response(
            manufacturer_id=0x0037,
            device_type=0x0001,
            device_id=0xABCDEF,
            device_revision=2,
            software_revision=5,
            hardware_revision=0x18,
        )
        parsed = parse_cmd0_response(data)
        assert parsed["manufacturer_id"] == 0x0037
        assert parsed["device_type"] == 0x0001
        assert parsed["device_id"] == 0xABCDEF
        assert parsed["device_revision"] == 2
        assert parsed["software_revision"] == 5
        assert parsed["unique_id"] == "0037-0001-ABCDEF"

    def test_cmd1_primary_variable(self) -> None:
        """Verify Cmd 1 Read Primary Variable builder and parser."""
        data = build_cmd1_response(pv=78.6, unit_code=32)
        parsed = parse_cmd1_response(data)
        assert parsed["unit_code"] == 32
        assert abs(parsed["primary_variable"] - 78.6) < 1e-3

    def test_cmd3_dynamic_variables_and_loop_current(self) -> None:
        """Verify Cmd 3 Read Dynamic Variables & Loop Current builder and parser."""
        data = build_cmd3_response(
            loop_current_ma=16.00,
            pv=100.2,
            sv=50.1,
            tv=25.0,
            qv=12.5,
            pv_unit=32,
            sv_unit=57,
            tv_unit=12,
            qv_unit=39,
        )
        parsed = parse_cmd3_response(data)
        assert abs(parsed["loop_current_ma"] - 16.00) < 1e-3
        assert abs(parsed["primary_variable"] - 100.2) < 1e-3
        assert abs(parsed["secondary_variable"] - 50.1) < 1e-3
        assert abs(parsed["tertiary_variable"] - 25.0) < 1e-3
        assert abs(parsed["quaternary_variable"] - 12.5) < 1e-3
        assert parsed["pv_unit"] == 32
        assert parsed["sv_unit"] == 57

    def test_cmd9_device_variables_with_status(self) -> None:
        """Verify Cmd 9 Read Device Variables with Status builder and parser."""
        vars_in = [
            (0, 64, 32, 23.5, 0xC0),
            (1, 65, 57, 85.0, 0xC0),
            (2, 66, 12, 101.3, 0xC0),
        ]
        data = build_cmd9_response(variables=vars_in)
        parsed = parse_cmd9_response(data)
        assert len(parsed["variables"]) == 3
        assert parsed["variables"][0]["variable_code"] == 0
        assert abs(parsed["variables"][0]["value"] - 23.5) < 1e-3
        assert parsed["variables"][1]["variable_code"] == 1
        assert abs(parsed["variables"][1]["value"] - 85.0) < 1e-3

    def test_cmd48_additional_transmitter_status(self) -> None:
        """Verify Cmd 48 Read Additional Transmitter Status builder and parser."""
        status_raw = b"\x01\x02\x03\x04\x05\x06"
        data = build_cmd48_response(status_bytes=status_raw)
        parsed = parse_cmd48_response(data)
        assert parsed["status_length"] == 6
        assert parsed["raw_status_bytes"] == status_raw

    def test_engineering_unit_scaling(self) -> None:
        """Verify engineering unit conversions across temperature, pressure, and current."""
        # Temperature
        c_to_f = scale_engineering_units(100.0, int(HartUnitCode.CELSIUS), int(HartUnitCode.FAHRENHEIT))
        assert abs(c_to_f - 212.0) < 1e-4
        f_to_c = scale_engineering_units(212.0, int(HartUnitCode.FAHRENHEIT), int(HartUnitCode.CELSIUS))
        assert abs(f_to_c - 100.0) < 1e-4
        c_to_k = scale_engineering_units(0.0, int(HartUnitCode.CELSIUS), int(HartUnitCode.KELVIN))
        assert abs(c_to_k - 273.15) < 1e-4
        k_to_c = scale_engineering_units(273.15, int(HartUnitCode.KELVIN), int(HartUnitCode.CELSIUS))
        assert abs(k_to_c - 0.0) < 1e-4

        # Pressure
        bar_to_psi = scale_engineering_units(1.0, int(HartUnitCode.BAR), int(HartUnitCode.PSI))
        assert abs(bar_to_psi - 14.50377) < 1e-4
        psi_to_bar = scale_engineering_units(14.50377, int(HartUnitCode.PSI), int(HartUnitCode.BAR))
        assert abs(psi_to_bar - 1.0) < 1e-4
        bar_to_mbar = scale_engineering_units(1.0, int(HartUnitCode.BAR), int(HartUnitCode.MBAR))
        assert abs(bar_to_mbar - 1000.0) < 1e-4

        # 4..20 mA loop current to percentage
        ma_to_pct = scale_engineering_units(12.0, int(HartUnitCode.MILLIAMPERES), int(HartUnitCode.PERCENT))
        assert abs(ma_to_pct - 50.0) < 1e-4
        pct_to_ma = scale_engineering_units(50.0, int(HartUnitCode.PERCENT), int(HartUnitCode.MILLIAMPERES))
        assert abs(pct_to_ma - 12.0) < 1e-4

    def test_cmd48_namur_ne107_categorization(self) -> None:
        """Verify Cmd 48 maps transmitter diagnostic bitmasks to NAMUR NE107 categories."""
        cases = [
            (b"\x01\x00\x00\x00\x00\x00", "FAILURE"),
            (b"\x10\x00\x00\x00\x00\x00", "FUNCTION_CHECK"),
            (b"\x20\x00\x00\x00\x00\x00", "OUT_OF_SPEC"),
            (b"\x08\x00\x00\x00\x00\x00", "MAINTENANCE_REQUIRED"),
            (b"\x00\x00\x00\x00\x00\x00", "NORMAL"),
        ]
        for raw, expected_cat in cases:
            res = parse_cmd48_response(raw)
            assert res["namur_ne107_category"] == expected_cat


# ============================================================================
# 6. Process Safety Interlocks & Diagnostics
# ============================================================================

class TestSection6ProcessSafetyInterlocks:
    """Tests for safety trips, diagnostic event codes, and alarm conditions."""

    def test_session_timeout_trip_0x8f01(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify 0x8F01 Session Timeout Trip asserts %M185 and deasserts %M184."""
        sess = hart_engine.initiate_session(device_address=1)
        assert hart_engine.reg_table.read_bit("%M184") is True
        assert hart_engine.reg_table.read_bit("%M185") is False

        hart_engine.simulate_session_timeout(sess.session_id)
        assert hart_engine.diagnostic_code == HartIPDiagnosticCode.SESSION_TIMEOUT_TRIP
        assert hart_engine.reg_table.read_uword("%R797") == int(HartIPDiagnosticCode.SESSION_TIMEOUT_TRIP)
        assert hart_engine.reg_table.read_bit("%M185") is True
        assert hart_engine.reg_table.read_bit("%M184") is False
        assert bool(hart_engine.reg_table.read_uword("%R790") & HartIPStatusBits.SESSION_TIMEOUT_TRIP) is True

    def test_keep_alive_loss_trip_0x8f04(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify 0x8F04 Keep-Alive Loss Trip asserts %M185 after watchdog expires."""
        hart_engine.initiate_session(device_address=1)
        assert hart_engine.reg_table.read_bit("%M184") is True

        # Simulate 12 seconds elapsed without keep-alive
        ok = hart_engine.check_keep_alive_watchdog(simulated_elapsed_s=12.0)
        assert ok is False
        assert hart_engine.diagnostic_code == HartIPDiagnosticCode.KEEPALIVE_LOSS_TRIP
        assert hart_engine.reg_table.read_uword("%R797") == int(HartIPDiagnosticCode.KEEPALIVE_LOSS_TRIP)
        assert hart_engine.reg_table.read_bit("%M185") is True
        assert hart_engine.reg_table.read_bit("%M184") is False
        assert bool(hart_engine.reg_table.read_uword("%R790") & HartIPStatusBits.KEEPALIVE_LOSS_TRIP) is True

    def test_checksum_framing_mismatch_alarm_0x8f02(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify 0x8F02 Checksum Alarm sets bit 5 in %R790 and updates %R797."""
        sess = hart_engine.initiate_session(device_address=1)
        # Create invalid PDU with bad LRC
        pdu = HartTokenPDU(delimiter=DELIMITER_STX_SHORT, address=1, command=1)
        corrupted = bytearray(pdu.pack())
        corrupted[-1] ^= 0xAA

        with pytest.raises(ValueError):
            hart_engine.process_pdu_response(sess.session_id, bytes(corrupted))

        assert hart_engine.diagnostic_code == HartIPDiagnosticCode.CHECKSUM_FRAMING_MISMATCH_ALARM
        assert hart_engine.reg_table.read_uword("%R797") == int(HartIPDiagnosticCode.CHECKSUM_FRAMING_MISMATCH_ALARM)
        assert bool(hart_engine.reg_table.read_uword("%R790") & HartIPStatusBits.CHECKSUM_ERROR_ALARM) is True

    def test_sequence_out_of_order_alarm_0x8f03(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify 0x8F03 Sequence Alarm sets bit 6 in %R790 and updates %R797."""
        sess = hart_engine.initiate_session(device_address=1)
        pkt = HartIPPacket(sequence_number=555)

        hart_engine.receive_packet(pkt.pack(), expected_seq=1)
        assert hart_engine.diagnostic_code == HartIPDiagnosticCode.SEQUENCE_OUT_OF_ORDER_ALARM
        assert hart_engine.reg_table.read_uword("%R797") == int(HartIPDiagnosticCode.SEQUENCE_OUT_OF_ORDER_ALARM)
        assert bool(hart_engine.reg_table.read_uword("%R790") & HartIPStatusBits.SEQUENCE_FAULT_ALARM) is True

    def test_fault_trip_reset(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify resetting fault clears trip bits and restores nominal status."""
        sess = hart_engine.initiate_session(device_address=1)
        hart_engine.simulate_session_timeout(sess.session_id)
        assert hart_engine.reg_table.read_bit("%M185") is True

        hart_engine.reset_fault_trip()
        assert hart_engine.diagnostic_code == HartIPDiagnosticCode.OK
        assert hart_engine.reg_table.read_uword("%R797") == 0
        assert hart_engine.reg_table.read_bit("%M185") is False
        assert hart_engine.reg_table.read_bit("%M184") is True


# ============================================================================
# 7. Horner OCS Memory Space Integration
# ============================================================================

class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS memory space synchronization and register scaling."""

    def test_register_scaling_synchronization(self, hart_engine: HartIPMasterEngine) -> None:
        """Verify PV x10, Loop Current x100, and SV x10 scalings in %R793..%R795."""
        sess = hart_engine.initiate_session(device_address=1)

        # Dispatch Cmd 3 response with known engineering values
        data = build_cmd3_response(
            loop_current_ma=12.34,
            pv=45.6,
            sv=78.9,
            tv=10.0,
            qv=5.0,
        )
        pdu = HartTokenPDU(
            delimiter=DELIMITER_ACK_SHORT,
            address=1,
            command=HartCommand.READ_DYNAMIC_VARS_AND_CURRENT,
            data=data,
        )
        hart_engine.process_pdu_response(sess.session_id, pdu.pack())

        # %R792: LastCommandExecuted = 3
        assert hart_engine.reg_table.read_word("%R792") == 3
        # %R793: PV scaled x10 -> 45.6 * 10 = 456
        assert hart_engine.reg_table.read_word("%R793") == 456
        # %R794: Loop Current scaled x100 -> 12.34 * 100 = 1234
        assert hart_engine.reg_table.read_word("%R794") == 1234
        # %R795: SV scaled x10 -> 78.9 * 10 = 789
        assert hart_engine.reg_table.read_word("%R795") == 789


# ============================================================================
# 8. Anti-Ladder Security Guard Interception
# ============================================================================

class TestSection8AntiLadderSecurity:
    """Tests for SecurityGuard strict rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "sample",
        [
            "PROGRAM BadContacts\nVAR X: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
            "PROGRAM BadNegative\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
            "PROGRAM BadRung\nVAR X: BOOL; END_VAR\nRUNG 1: XIC %M184 OTE %M185 END_RUNG\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 9. End-to-End 9-Stage Verification Suite
# ============================================================================

class TestSection9VerificationSuite:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_hart_ip_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_hart_ip_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

    def test_run_hart_ip_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "hart_ip_evidence.json"
        result = run_hart_ip_verification(evidence_path=str(evidence_file))

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W118"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert data["data"]["component"] == "Industrial HART-IP Protocol Engine"
        assert data["data"]["checks_passed"] == 9
