"""Unit Test Suite for Industrial EnOcean IP Gateway & Wireless Telemetry Bridge.

Work Package: W124 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R850..%R857, %M198..%M199).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs.
3. Section 3: ESP3 packet framing, sync byte 0x55, CRC8 calculation, and corrupt packet rejection.
4. Section 4: EEP telegram decoders (A5-02-05, A5-04-01, F6-02-01, D5-00-01) and engineering unit scaling.
5. Section 5: Multi-sensor session tracking table and RSSI signal level monitoring.
6. Section 6: Process safety trips (0x9501, 0x9502, 0x9503, 0x9504) and Horner coil assertion (%M198, %M199).
7. Section 7: Horner OCS register space synchronization (%R850..%R857).
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
from jev_cscape.telemetry.enocean_ip import (
    CRC8_TABLE,
    ENOCEAN_CRC8_POLYNOMIAL,
    ENOCEAN_DEFAULT_WATCHDOG_TIMEOUT_S,
    ENOCEAN_GATEWAY_INACTIVITY_TIMEOUT_S,
    ENOCEAN_HEADER_LENGTH,
    ENOCEAN_HEADER_TOTAL_SIZE,
    ENOCEAN_IP_PURE_ST_POU,
    ENOCEAN_MAX_SENSORS,
    ENOCEAN_SYNC_BYTE,
    ContactReading,
    CRC8DataError,
    CRC8HeaderError,
    EEPDecodeError,
    EnOceanDiagnosticCode,
    EnOceanError,
    EnOceanGatewayEngine,
    EnOceanReturnCode,
    EnOceanRORG,
    EnOceanSensorNode,
    EnOceanStatusBits,
    ESP3FramingError,
    ESP3Header,
    ESP3Packet,
    ESP3PacketType,
    RadioERP1OptionalData,
    RockerAction,
    RockerSwitchReading,
    SensorTrackingTable,
    TemperatureReading,
    TempHumidityReading,
    calc_crc8,
    create_erp1_packet,
    decode_eep_a5_02_05,
    decode_eep_a5_04_01,
    decode_eep_d5_00_01,
    decode_eep_f6_02_01,
    run_enocean_ip_verification,
    verify_enocean_ip_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def gateway_engine(register_table: RegisterTable) -> EnOceanGatewayEngine:
    """Provide a fresh EnOceanGatewayEngine with an initialized register table."""
    return EnOceanGatewayEngine(reg_table=register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance, AST verification, and register bindings."""

    def test_verify_enocean_ip_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_enocean_ip_pure_st() is True

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Parse ENOCEAN_IP_PURE_ST_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(ENOCEAN_IP_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "EnOceanIPGatewaySync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "EnOceanStatusWord",
            "ActiveSensorsCount",
            "LastPacketType",
            "RockerSwitchContactState",
            "LastTemperatureScaled",
            "LastHumidityScaled",
            "TelegramCount",
            "DiagnosticEventCode",
            "EnOceanGatewayActive",
            "EnOceanFaultTrip",
            "GatewayActiveBit",
            "SensorsOnlineBit",
            "InactivityTripBit",
            "SensorOfflineTripBit",
            "DiagnosticTrip",
        }
        assert expected_vars.issubset(var_names)

        expected_bound_regs = {
            "%R850", "%R851", "%R852", "%R853", "%R854",
            "%R855", "%R856", "%R857", "%M198", "%M199",
        }
        assert expected_bound_regs.issubset(set(pou.bound_registers))

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POU passes SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(ENOCEAN_IP_PURE_ST_POU)


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
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M198 OTE %M199 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM BadReset\nVAR Out: BOOL; END_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM BadMnemonic\nVAR Out: BOOL; END_VAR\nXIO %M198\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: ESP3 Packet Framing, Sync Byte 0x55, CRC8 Calculation, & Framing Guards
# ============================================================================

class TestSection3ESP3PacketFraming:
    """Tests for ESP3 packet framing, sync byte 0x55, CRC8 calculation, and corrupt packet rejection."""

    def test_header_create_and_serialization(self) -> None:
        """Verify ESP3 6-byte header packing, CRC8 calculation, and serialization."""
        hdr = ESP3Header.create(
            data_length=10,
            optional_length=7,
            packet_type=ESP3PacketType.RADIO_ERP1,
        )
        raw = hdr.serialize()
        assert len(raw) == ENOCEAN_HEADER_TOTAL_SIZE
        assert raw[0] == ENOCEAN_SYNC_BYTE
        assert raw[0] == 0x55

        # Check CRC8 calculated correctly over data_length (2), optional_length (1), packet_type (1)
        expected_crc = calc_crc8(raw[1:5])
        assert raw[5] == expected_crc
        assert hdr.crc8 == expected_crc

    def test_header_deserialize_success(self) -> None:
        """Verify unpacking 6-byte header buffer."""
        hdr = ESP3Header.create(data_length=4, optional_length=2, packet_type=ESP3PacketType.EVENT)
        raw = hdr.serialize()
        unpacked = ESP3Header.deserialize(raw)

        assert unpacked.data_length == 4
        assert unpacked.optional_length == 2
        assert unpacked.packet_type == int(ESP3PacketType.EVENT)
        assert unpacked.crc8 == hdr.crc8

    def test_packet_create_serialize_deserialize_roundtrip(self) -> None:
        """Verify full ESP3 packet serialization and deserialization roundtrip."""
        data_body = bytes([int(EnOceanRORG.BS4), 0x00, 138, 134, 0x08, 0x01, 0x81, 0xA2, 0xB3, 0x00])
        opt_body = bytes([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x44, 0x00])  # RSSI = -68 dBm

        pkt = ESP3Packet.create(
            packet_type=ESP3PacketType.RADIO_ERP1,
            data=data_body,
            optional_data=opt_body,
        )
        raw = pkt.serialize()
        assert len(raw) == ENOCEAN_HEADER_TOTAL_SIZE + len(data_body) + len(opt_body) + 1

        unpacked = ESP3Packet.deserialize(raw)
        assert unpacked.header.packet_type == int(ESP3PacketType.RADIO_ERP1)
        assert unpacked.data == data_body
        assert unpacked.optional_data == opt_body
        assert unpacked.crc8_data == calc_crc8(data_body + opt_body)

    def test_crc8_known_test_vectors(self) -> None:
        """Verify CRC8 matches official EnOcean ESP3 test vectors."""
        # Standard CO_RD_VERSION header: Data Length 1, Optional Length 0, Packet Type 5
        h_bytes = bytes([0x00, 0x01, 0x00, 0x05])
        assert calc_crc8(h_bytes) == 0x70

        # CO_RD_VERSION data byte: 0x03
        d_bytes = bytes([0x03])
        assert calc_crc8(d_bytes) == 0x09

        # Empty payload
        assert calc_crc8(b"") == 0x00

        # Table dimensions
        assert len(CRC8_TABLE) == 256
        assert ENOCEAN_CRC8_POLYNOMIAL == 0x07

    def test_invalid_sync_byte_raises(self) -> None:
        """Verify header or packet with invalid sync byte raises ESP3FramingError."""
        bad_sync_hdr = bytes([0x56, 0x00, 0x01, 0x00, 0x05, 0x70])
        with pytest.raises(ESP3FramingError, match="Invalid sync byte"):
            ESP3Header.deserialize(bad_sync_hdr)

        bad_sync_pkt = bytes([0x56, 0x00, 0x01, 0x00, 0x05, 0x70, 0x03, 0x09])
        with pytest.raises(ESP3FramingError, match="Invalid sync byte"):
            ESP3Packet.deserialize(bad_sync_pkt)

    def test_header_crc_mismatch_raises(self) -> None:
        """Verify corrupt CRC8-Header raises CRC8HeaderError."""
        corrupt_hdr = bytes([0x55, 0x00, 0x01, 0x00, 0x05, 0xFF])  # CRC should be 0x70
        with pytest.raises(CRC8HeaderError, match="CRC8 Header mismatch"):
            ESP3Header.deserialize(corrupt_hdr)

    def test_data_crc_mismatch_raises(self) -> None:
        """Verify corrupt CRC8-Data raises CRC8DataError."""
        corrupt_pkt = bytes([0x55, 0x00, 0x01, 0x00, 0x05, 0x70, 0x03, 0xFF])  # CRC should be 0x09
        with pytest.raises(CRC8DataError, match="CRC8 Data mismatch"):
            ESP3Packet.deserialize(corrupt_pkt)

    def test_truncated_buffer_raises(self) -> None:
        """Verify truncated buffer raises ESP3FramingError."""
        with pytest.raises(ESP3FramingError, match="too short for ESP3 header"):
            ESP3Header.deserialize(b"\x55\x00\x01")

        with pytest.raises(ESP3FramingError, match="Buffer too short for ESP3 packet"):
            ESP3Packet.deserialize(b"\x55\x00\x01\x00\x05")

    def test_packet_truncation_mismatch_raises(self) -> None:
        """Verify packet truncated relative to declared header length raises ESP3FramingError."""
        # Declares data_length=10, but provides only 1 byte
        hdr = ESP3Header.create(data_length=10, optional_length=0, packet_type=ESP3PacketType.COMMON_COMMAND)
        truncated_raw = hdr.serialize() + b"\x01\x09"
        with pytest.raises(ESP3FramingError, match="Packet length truncated"):
            ESP3Packet.deserialize(truncated_raw)

    def test_all_core_packet_types(self) -> None:
        """Verify serialization and deserialization across all core ESP3 packet types."""
        packet_types = [
            ESP3PacketType.RADIO_ERP1,
            ESP3PacketType.RESPONSE,
            ESP3PacketType.RADIO_SUB_TEL,
            ESP3PacketType.EVENT,
            ESP3PacketType.COMMON_COMMAND,
            ESP3PacketType.SMART_ACK_COMMAND,
            ESP3PacketType.REMOTE_MAN_COMMAND,
        ]
        for pt in packet_types:
            pkt = ESP3Packet.create(packet_type=pt, data=b"\xDE\xAD\xBE\xEF")
            raw = pkt.serialize()
            unpacked = ESP3Packet.deserialize(raw)
            assert unpacked.header.packet_type == int(pt)
            assert unpacked.data == b"\xDE\xAD\xBE\xEF"

    def test_radio_erp1_optional_data_serialization(self) -> None:
        """Verify RadioERP1OptionalData 7-byte packing and unpacking."""
        opt = RadioERP1OptionalData(
            subtel_num=3,
            destination_id=0x0182C3D4,
            rssi_dbm=-68,
            security_level=0,
        )
        raw = opt.serialize()
        assert len(raw) == 7

        unpacked = RadioERP1OptionalData.deserialize(raw)
        assert unpacked.subtel_num == 3
        assert unpacked.destination_id == 0x0182C3D4
        assert unpacked.rssi_dbm == -68
        assert unpacked.security_level == 0

    def test_header_invalid_fields_raise(self) -> None:
        """Verify ESP3Header rejects invalid out-of-range fields."""
        with pytest.raises(ValueError, match="Data length must be 0..65535"):
            ESP3Header(data_length=-1, optional_length=0, packet_type=1, crc8=0)
        with pytest.raises(ValueError, match="Data length must be 0..65535"):
            ESP3Header(data_length=0x10000, optional_length=0, packet_type=1, crc8=0)
        with pytest.raises(ValueError, match="Optional length must be 0..255"):
            ESP3Header(data_length=0, optional_length=256, packet_type=1, crc8=0)
        with pytest.raises(ValueError, match="Packet type must be 0..255"):
            ESP3Header(data_length=0, optional_length=0, packet_type=-1, crc8=0)

    def test_enocean_return_codes(self) -> None:
        """Verify ESP3 response return code enumeration values."""
        assert int(EnOceanReturnCode.RET_OK) == 0x00
        assert int(EnOceanReturnCode.RET_ERROR) == 0x01
        assert int(EnOceanReturnCode.RET_NOT_SUPPORTED) == 0x02
        assert int(EnOceanReturnCode.RET_WRONG_PARAM) == 0x03
        assert int(EnOceanReturnCode.RET_OPERATION_DENIED) == 0x04


# ============================================================================
# Section 4: EEP Telegram Decoders & Engineering Unit Scaling
# ============================================================================

class TestSection4EEPTelegramDecoders:
    """Tests for EEP A5-02-05, A5-04-01, F6-02-01, D5-00-01 decoders and scaling."""

    def test_decode_eep_a5_02_05_direct_and_inverted(self) -> None:
        """Verify A5-02-05 4BS temperature decoding (0.0 .. +40.0 °C)."""
        # Direct linear: raw 0 -> 0.0°C, raw 128 -> ~20.08°C, raw 255 -> 40.0°C
        r_min = decode_eep_a5_02_05(bytes([0x00, 0, 0x00, 0x08]))
        assert math.isclose(r_min.temperature_c, 0.0, abs_tol=0.05)
        assert r_min.learn_bit is True

        r_mid = decode_eep_a5_02_05(bytes([0x00, 128, 0x00, 0x08]))
        assert math.isclose(r_mid.temperature_c, 20.08, abs_tol=0.1)

        r_max = decode_eep_a5_02_05(bytes([0x00, 255, 0x00, 0x08]))
        assert math.isclose(r_max.temperature_c, 40.0, abs_tol=0.05)

        # Inverted linear
        r_inv_0 = decode_eep_a5_02_05(bytes([0x00, 0, 0x00, 0x08]), inverted=True)
        assert math.isclose(r_inv_0.temperature_c, 40.0, abs_tol=0.05)

        r_inv_255 = decode_eep_a5_02_05(bytes([0x00, 255, 0x00, 0x08]), inverted=True)
        assert math.isclose(r_inv_255.temperature_c, 0.0, abs_tol=0.05)

        # 1-byte payload format
        r_single = decode_eep_a5_02_05(bytes([128]))
        assert math.isclose(r_single.temperature_c, 20.08, abs_tol=0.1)

        # Full ERP1 format: RORG(1) + 4BS(4) + SENDER(4) + STATUS(1)
        erp1_bytes = bytes([0xA5, 0x00, 64, 0x00, 0x08, 0x01, 0x81, 0xA2, 0xB3, 0x00])
        r_erp1 = decode_eep_a5_02_05(erp1_bytes)
        assert math.isclose(r_erp1.temperature_c, 10.04, abs_tol=0.1)

    def test_decode_eep_a5_02_05_invalid_length_raises(self) -> None:
        """Verify invalid payload lengths raise EEPDecodeError."""
        with pytest.raises(EEPDecodeError):
            decode_eep_a5_02_05(bytes([0x00, 0x01]))

    def test_decode_eep_a5_04_01_scaling(self) -> None:
        """Verify A5-04-01 combined temperature (0..40°C) and relative humidity (0..100% RH)."""
        # Min boundary (0, 0)
        r_min = decode_eep_a5_04_01(bytes([0x00, 0, 0, 0x08]))
        assert r_min.humidity_rh == 0.0
        assert r_min.temperature_c == 0.0
        assert r_min.learn_bit is True

        # Mid boundary (125, 125) -> 50% RH, 20°C
        r_mid = decode_eep_a5_04_01(bytes([0x00, 125, 125, 0x08]))
        assert math.isclose(r_mid.humidity_rh, 50.0, abs_tol=0.1)
        assert math.isclose(r_mid.temperature_c, 20.0, abs_tol=0.1)

        # Max boundary (250, 250) -> 100% RH, 40°C
        r_max = decode_eep_a5_04_01(bytes([0x00, 250, 250, 0x08]))
        assert math.isclose(r_max.humidity_rh, 100.0, abs_tol=0.1)
        assert math.isclose(r_max.temperature_c, 40.0, abs_tol=0.1)

        # Full ERP1 payload format
        erp1_th = bytes([0xA5, 0x00, 150, 100, 0x08, 0x01, 0x81, 0xA2, 0xB3, 0x00])
        r_th = decode_eep_a5_04_01(erp1_th)
        assert math.isclose(r_th.humidity_rh, 60.0, abs_tol=0.1)
        assert math.isclose(r_th.temperature_c, 16.0, abs_tol=0.1)

    def test_decode_eep_a5_04_01_invalid_length_raises(self) -> None:
        """Verify invalid payload lengths raise EEPDecodeError."""
        with pytest.raises(EEPDecodeError):
            decode_eep_a5_04_01(bytes([0x00, 0x01, 0x02]))

    def test_decode_eep_f6_02_01_rocker_actions(self) -> None:
        """Verify F6-02-01 RPS rocker switch states (AI, AO, BI, BO, and Released)."""
        # Released: Energy bow = 0
        r_rel = decode_eep_f6_02_01(0x00)
        assert r_rel.action == RockerAction.RELEASED
        assert r_rel.energy_bow is False
        assert r_rel.is_pressed is False

        # Button AI pressed (EB=1, code=0): 0x10 | (0 << 5) = 0x10
        r_ai = decode_eep_f6_02_01(0x10)
        assert r_ai.action == RockerAction.BUTTON_AI_PRESSED
        assert r_ai.energy_bow is True
        assert r_ai.is_pressed is True

        # Button AO pressed (EB=1, code=1): 0x10 | (1 << 5) = 0x30
        r_ao = decode_eep_f6_02_01(0x30)
        assert r_ao.action == RockerAction.BUTTON_AO_PRESSED
        assert r_ao.is_pressed is True

        # Button BI pressed (EB=1, code=2): 0x10 | (2 << 5) = 0x50
        r_bi = decode_eep_f6_02_01(0x50)
        assert r_bi.action == RockerAction.BUTTON_BI_PRESSED
        assert r_bi.is_pressed is True

        # Button BO pressed (EB=1, code=3): 0x10 | (3 << 5) = 0x70
        r_bo = decode_eep_f6_02_01(0x70)
        assert r_bo.action == RockerAction.BUTTON_BO_PRESSED
        assert r_bo.is_pressed is True

    def test_decode_eep_d5_00_01_reed_contact(self) -> None:
        """Verify D5-00-01 1BS reed switch / single contact decoding."""
        # Contact Closed: bit 0 = 0 (0x08 has LRN bit set, bit 0 = 0)
        r_closed = decode_eep_d5_00_01(0x08)
        assert r_closed.contact_closed is True
        assert r_closed.contact_open is False
        assert r_closed.learn_bit is True

        # Contact Open: bit 0 = 1 (0x09 has LRN bit set, bit 0 = 1)
        r_open = decode_eep_d5_00_01(0x09)
        assert r_open.contact_closed is False
        assert r_open.contact_open is True
        assert r_open.learn_bit is True


# ============================================================================
# Section 5: Multi-Sensor Session Tracking Table & RSSI Monitoring
# ============================================================================

class TestSection5MultiSensorTracking:
    """Tests for multi-sensor session tracking table and RSSI monitoring."""

    def test_sensor_table_capacity_and_overflow(self) -> None:
        """Verify up to 32 sensors can be registered, and 33rd is rejected."""
        table = SensorTrackingTable(max_nodes=ENOCEAN_MAX_SENSORS)
        assert ENOCEAN_MAX_SENSORS == 32

        for i in range(ENOCEAN_MAX_SENSORS):
            node = table.register_or_update(
                sensor_id=0x01800000 + i,
                eep="A5-04-01",
                rssi_dbm=-65 - (i % 20),
            )
            assert node.sensor_id == 0x01800000 + i

        assert table.active_count == 32
        assert table.online_count == 32

        with pytest.raises(ValueError, match="Max active sensor capacity"):
            table.register_or_update(sensor_id=0x0180FFFF, eep="A5-02-05")

    def test_sensor_node_attributes_and_rssi(self) -> None:
        """Verify individual sensor node attributes, hex formatting, and RSSI tracking."""
        table = SensorTrackingTable()
        node = table.register_or_update(
            sensor_id=0x0181A2B3,
            eep="A5-04-01",
            rssi_dbm=-68,
            subtel_num=2,
        )
        assert node.hex_id == "0181A2B3"
        assert node.rssi_dbm == -68
        assert node.subtel_num == 2
        assert node.packet_count == 1
        assert node.is_online is True

        # Update existing node with second packet
        updated = table.register_or_update(
            sensor_id=0x0181A2B3,
            eep="A5-04-01",
            rssi_dbm=-62,
            subtel_num=1,
        )
        assert updated.packet_count == 2
        assert updated.rssi_dbm == -62
        assert table.active_count == 1

    def test_sensor_node_removal_and_clear(self) -> None:
        """Verify removing individual sensors and clearing the table."""
        table = SensorTrackingTable()
        table.register_or_update(0x01800001, "A5-02-05")
        table.register_or_update(0x01800002, "F6-02-01")
        assert table.active_count == 2

        assert table.remove(0x01800001) is True
        assert table.active_count == 1
        assert table.get(0x01800001) is None

        assert table.remove(0x01809999) is False

        table.clear()
        assert table.active_count == 0

    def test_sensor_watchdog_evaluation(self) -> None:
        """Verify sensor inactivity watchdog marks nodes offline."""
        table = SensorTrackingTable()
        table.register_or_update(0x01800001, "A5-02-05")
        table.register_or_update(0x01800002, "A5-04-01")

        # Simulate 40s elapsed > 30s timeout
        offline_nodes = table.check_watchdogs(timeout_s=30.0, current_time=time.time() + 40.0)
        assert len(offline_nodes) == 2
        assert table.online_count == 0
        assert table.active_count == 2

    def test_partial_sensor_offline_watchdog(self) -> None:
        """Verify check_watchdogs marks only expired nodes offline while keeping active nodes online."""
        table = SensorTrackingTable()
        now = time.time()
        n1 = table.register_or_update(0x01800001, "A5-02-05", now=now - 50.0)  # Expired
        n2 = table.register_or_update(0x01800002, "A5-04-01", now=now)         # Still active

        offline = table.check_watchdogs(timeout_s=30.0, current_time=now)
        assert len(offline) == 1
        assert offline[0].sensor_id == 0x01800001
        assert n1.is_online is False
        assert n2.is_online is True
        assert table.online_count == 1
        assert table.active_count == 2


# ============================================================================
# Section 6: Process Safety Trips & Diagnostic Codes
# ============================================================================

class TestSection6ProcessSafetyTrips:
    """Tests for safety trips 0x9501..0x9504 asserting %M198/%M199 and diagnostic codes."""

    def test_inactivity_timeout_trip_0x9501(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify 0x9501 Gateway Inactivity Timeout Trip asserts %M199 and clears %M198."""
        pkt = create_erp1_packet(
            rorg=EnOceanRORG.BS1,
            payload=bytes([0x08]),
            sender_id=0x01820010,
        )
        gateway_engine.process_raw_bytes(pkt.serialize())
        assert gateway_engine.reg_table.read_bit("%M198") is True
        assert gateway_engine.reg_table.read_bit("%M199") is False

        # Inactivity timeout (elapsed 70s > 60s)
        tripped = gateway_engine.check_inactivity_watchdog(simulated_elapsed_s=70.0)
        assert tripped is True

        assert gateway_engine.diagnostic_code == EnOceanDiagnosticCode.INACTIVITY_TIMEOUT_TRIP
        assert gateway_engine.reg_table.read_uword("%R857") == 0x9501
        assert gateway_engine.reg_table.read_bit("%M199") is True
        assert gateway_engine.reg_table.read_bit("%M198") is False
        assert bool(gateway_engine.reg_table.read_uword("%R850") & EnOceanStatusBits.INACTIVITY_TIMEOUT_TRIP) is True

    def test_crc8_header_alarm_0x9502(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify 0x9502 CRC8 Header Failure Alarm sets bit 5 in %R850 and updates %R857."""
        # Corrupt CRC8H: 0xFF
        bad_hdr_packet = b"\x55\x00\x01\x00\x05\xFF\x01\x00"
        ok = gateway_engine.process_raw_bytes(bad_hdr_packet)
        assert ok is False

        assert gateway_engine.diagnostic_code == EnOceanDiagnosticCode.CRC8_HEADER_FAIL_ALARM
        assert gateway_engine.reg_table.read_uword("%R857") == 0x9502
        assert bool(gateway_engine.reg_table.read_uword("%R850") & EnOceanStatusBits.CRC8_HEADER_ALARM) is True

    def test_crc8_data_alarm_0x9503(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify 0x9503 CRC8 Data Failure Alarm sets bit 6 in %R850 and updates %R857."""
        valid_hdr = ESP3Header.create(data_length=2, optional_length=0, packet_type=ESP3PacketType.COMMON_COMMAND)
        bad_data_packet = valid_hdr.serialize() + b"\x01\x02\xFF"  # Corrupt CRC8D 0xFF
        ok = gateway_engine.process_raw_bytes(bad_data_packet)
        assert ok is False

        assert gateway_engine.diagnostic_code == EnOceanDiagnosticCode.CRC8_DATA_FAIL_ALARM
        assert gateway_engine.reg_table.read_uword("%R857") == 0x9503
        assert bool(gateway_engine.reg_table.read_uword("%R850") & EnOceanStatusBits.CRC8_DATA_ALARM) is True

    def test_sensor_offline_trip_0x9504(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify 0x9504 Sensor Offline Trip asserts %M199 and clears %M198."""
        gateway_engine.sensor_table.register_or_update(0x0181A2B3, "A5-04-01")
        assert gateway_engine.sensor_table.active_count == 1

        # Sensor watchdog timeout (elapsed 40s > 30s)
        tripped = gateway_engine.check_sensors_watchdog(simulated_elapsed_s=40.0)
        assert tripped is True

        assert gateway_engine.diagnostic_code == EnOceanDiagnosticCode.SENSOR_OFFLINE_TRIP
        assert gateway_engine.reg_table.read_uword("%R857") == 0x9504
        assert gateway_engine.reg_table.read_bit("%M199") is True
        assert gateway_engine.reg_table.read_bit("%M198") is False
        assert bool(gateway_engine.reg_table.read_uword("%R850") & EnOceanStatusBits.SENSOR_OFFLINE_TRIP) is True

    def test_reset_fault_trip_recovery(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify reset_fault_trip clears all alarms and restores %M198."""
        gateway_engine.check_inactivity_watchdog(simulated_elapsed_s=100.0)
        assert gateway_engine.reg_table.read_bit("%M199") is True

        gateway_engine.reset_fault_trip()
        assert gateway_engine.diagnostic_code == EnOceanDiagnosticCode.OK
        assert gateway_engine.reg_table.read_uword("%R857") == 0x0000
        assert gateway_engine.reg_table.read_bit("%M199") is False
        assert gateway_engine.reg_table.read_bit("%M198") is True

    def test_diagnostic_codes_and_status_bits_enumerations(self) -> None:
        """Verify process safety trip codes and Horner status bits bitmask definitions."""
        assert int(EnOceanDiagnosticCode.OK) == 0x0000
        assert int(EnOceanDiagnosticCode.INACTIVITY_TIMEOUT_TRIP) == 0x9501
        assert int(EnOceanDiagnosticCode.CRC8_HEADER_FAIL_ALARM) == 0x9502
        assert int(EnOceanDiagnosticCode.CRC8_DATA_FAIL_ALARM) == 0x9503
        assert int(EnOceanDiagnosticCode.SENSOR_OFFLINE_TRIP) == 0x9504

        assert int(EnOceanStatusBits.GATEWAY_ACTIVE) == 0x0001
        assert int(EnOceanStatusBits.SENSORS_ONLINE) == 0x0002
        assert int(EnOceanStatusBits.TELEMETRY_RECEIVING) == 0x0004
        assert int(EnOceanStatusBits.REED_CONTACT_CLOSED) == 0x0008
        assert int(EnOceanStatusBits.INACTIVITY_TIMEOUT_TRIP) == 0x0010
        assert int(EnOceanStatusBits.CRC8_HEADER_ALARM) == 0x0020
        assert int(EnOceanStatusBits.CRC8_DATA_ALARM) == 0x0040
        assert int(EnOceanStatusBits.SENSOR_OFFLINE_TRIP) == 0x0080


# ============================================================================
# Section 7: Horner OCS Memory Space Integration (%R850..%R857)
# ============================================================================

class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS register space synchronization (%R850..%R857, %M198..%M199)."""

    def test_register_space_synchronization(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify initial register state matches Horner OCS specifications."""
        assert gateway_engine.reg_table.read_word("%R851") == 0
        assert gateway_engine.reg_table.read_uword("%R852") == 0
        assert gateway_engine.reg_table.read_word("%R853") == 0
        assert gateway_engine.reg_table.read_word("%R854") == 0
        assert gateway_engine.reg_table.read_word("%R855") == 0
        assert gateway_engine.reg_table.read_word("%R856") == 0
        assert gateway_engine.reg_table.read_uword("%R857") == 0x0000
        assert gateway_engine.reg_table.read_bit("%M198") is False
        assert gateway_engine.reg_table.read_bit("%M199") is False

        # When packet received, gateway active coil %M198 is asserted
        pkt = create_erp1_packet(
            rorg=EnOceanRORG.BS1,
            payload=bytes([0x08]),
            sender_id=0x01820010,
        )
        gateway_engine.process_raw_bytes(pkt.serialize())
        assert gateway_engine.reg_table.read_bit("%M198") is True

    def test_temperature_and_humidity_register_sync(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify A5-04-01 ERP1 telegram writes scaled temperature and humidity to %R854 and %R855."""
        # 21.44°C -> DB1 = 134; 55.2% RH -> DB2 = 138
        erp1_pkt = create_erp1_packet(
            rorg=EnOceanRORG.BS4,
            payload=bytes([0x00, 138, 134, 0x08]),
            sender_id=0x0181A2B3,
            rssi_dbm=-68,
        )
        ok = gateway_engine.process_raw_bytes(erp1_pkt.serialize())
        assert ok is True

        assert gateway_engine.reg_table.read_word("%R851") == 1
        assert gateway_engine.reg_table.read_uword("%R852") == 0x0001  # RADIO_ERP1
        assert abs(gateway_engine.reg_table.read_word("%R854") - 214) <= 1  # 21.4 °C * 10
        assert abs(gateway_engine.reg_table.read_word("%R855") - 552) <= 1  # 55.2 %RH * 10
        assert gateway_engine.reg_table.read_word("%R856") >= 1
        assert gateway_engine.reg_table.read_bit("%M198") is True
        assert gateway_engine.reg_table.read_bit("%M199") is False

    def test_reed_contact_register_sync(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify D5-00-01 reed contact telegram updates %R853 and %R850 bit 3."""
        # Contact Closed
        closed_pkt = create_erp1_packet(
            rorg=EnOceanRORG.BS1,
            payload=bytes([0x08]),  # Contact closed (bit 0 = 0)
            sender_id=0x01820010,
        )
        gateway_engine.process_esp3_packet(closed_pkt)
        assert gateway_engine.reg_table.read_word("%R853") == 1
        assert bool(gateway_engine.reg_table.read_uword("%R850") & EnOceanStatusBits.REED_CONTACT_CLOSED) is True

        # Contact Open
        open_pkt = create_erp1_packet(
            rorg=EnOceanRORG.BS1,
            payload=bytes([0x09]),  # Contact open (bit 0 = 1)
            sender_id=0x01820010,
        )
        gateway_engine.process_esp3_packet(open_pkt)
        assert gateway_engine.reg_table.read_word("%R853") == 0
        assert bool(gateway_engine.reg_table.read_uword("%R850") & EnOceanStatusBits.REED_CONTACT_CLOSED) is False

    def test_rocker_switch_register_sync(self, gateway_engine: EnOceanGatewayEngine) -> None:
        """Verify F6-02-01 rocker switch telegram updates %R853 action codes (1..4)."""
        actions_to_test = [
            (0x10, int(RockerAction.BUTTON_AI_PRESSED)),
            (0x30, int(RockerAction.BUTTON_AO_PRESSED)),
            (0x50, int(RockerAction.BUTTON_BI_PRESSED)),
            (0x70, int(RockerAction.BUTTON_BO_PRESSED)),
            (0x00, int(RockerAction.RELEASED)),
        ]
        for db, expected_code in actions_to_test:
            pkt = create_erp1_packet(
                rorg=EnOceanRORG.RPS,
                payload=bytes([db]),
                sender_id=0x01830020,
            )
            gateway_engine.process_esp3_packet(pkt)
            assert gateway_engine.reg_table.read_word("%R853") == expected_code


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================

class TestSection8VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_enocean_ip_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_enocean_ip_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

    def test_run_enocean_ip_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "enocean_ip_evidence.json"
        result = run_enocean_ip_verification(evidence_path=str(evidence_file))

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W124"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert data["data"]["component"] == "Industrial EnOcean IP Gateway & Wireless Telemetry Bridge"
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9
