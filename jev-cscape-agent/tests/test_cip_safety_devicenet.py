"""Comprehensive Unit and Integration Test Suite for W205 CIP Safety on DeviceNet Engine.

Work Package: W205 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 70+ Unit Tests across 10 Sections:
1. Section 1: Constants, Enums & Protocol Defaults (DeviceNetSafetyState, DiagnosticCode, etc.).
2. Section 2: 11-Bit CAN Frame Encoding, Arbitration ID Allocation & Priority Ranking.
3. Section 3: Safety Network Number (SNN) Serialization & TUNID Matching.
4. Section 4: Dual-Channel Payload Comparison & Safety CRC-S1/CRC-S2 Checksum Calculation.
5. Section 5: Expected Packet Interval (EPI) Watchdog Tracking (< 20 ms) & Timeout Trips.
6. Section 6: Target Connection State Machine Lifecycle & Process Safety Interlocks.
7. Section 7: Horner OCS Register Synchronization (%R1660..%R1667, %M387..%M388) with PrivilegeMode.SYSTEM.
8. Section 8: ILogicUnit Scan Step Cycle Integration (100-cycle scan simulation).
9. Section 9: Pure ST POU Validation & Anti-Ladder Security Guard Interception (SecurityGuard, STParser).
10. Section 10: 9-Stage Deterministic Verification Runner & Evidence JSON Export.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import time
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_devicenet import (
    CAN_BAUD_125K,
    CAN_BAUD_250K,
    CAN_BAUD_500K,
    CAN_BIT_TIME_125K_US,
    CAN_BIT_TIME_250K_US,
    CAN_BIT_TIME_500K_US,
    CIP_SAFETY_DEVICENET_CLASS_ID,
    CIP_SAFETY_DEVICENET_ENGINE,
    CIP_SAFETY_DEVICENET_POU,
    CIP_SAFETY_DEVICENET_SYNC_POU,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyDeviceNetEngine,
    CIPSafetyDeviceNetPacket,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    CRC32_IEEE_INIT,
    CRC32_IEEE_POLY,
    DEFAULT_EPI_MS,
    DEFAULT_SCID,
    DEFAULT_SNN,
    DEFAULT_TUNID,
    DEVICENET_SAFETY_DEFAULT_MAC_ID,
    DEVICENET_SAFETY_MAX_NODES,
    DEVICENET_SAFETY_TARGET_MAC_ID,
    EPI_TIMEOUT_MULTIPLIER,
    MAX_TIMESTAMP_DRIFT_MARGIN_MS,
    MAX_TOLERABLE_DELAY_MS,
    NOMINAL_EPI_MS,
    NOMINAL_EPI_SCALED,
    NOMINAL_WATCHDOG_MS,
    NOMINAL_WATCHDOG_SCALED,
    PURE_ST_POU,
    BlackChannelThreat,
    CANArbitrationEngine,
    CANArbitrationResult,
    CANBaudRate,
    CANFrame,
    CipSafetyDeviceNetConfigError,
    CipSafetyDeviceNetCrcError,
    CipSafetyDeviceNetDiagnostic,
    CipSafetyDeviceNetDiagnosticCode,
    CipSafetyDeviceNetEngine,
    CipSafetyDeviceNetError,
    CipSafetyDeviceNetMtdError,
    CipSafetyDeviceNetSequenceError,
    CipSafetyDeviceNetStatusBits,
    CipSafetyDeviceNetTimeoutError,
    DeviceNetSafetyDiagnosticCode,
    DeviceNetSafetyEngine,
    DeviceNetSafetyPacket,
    DeviceNetSafetyState,
    DeviceNetSNN,
    DiagnosticCode,
    DiagnosticStatusCode,
    DualChannelSafetyPayload,
    RedundantSafetyPayload,
    SafetyConnectionState,
    SafetyModeByte,
    SafetyNetworkNumber,
    TargetUniqueNetworkId,
    TUNID,
    allocate_devicenet_safety_arbitration_id,
    calculate_crc16_ccitt,
    calculate_crc32_ieee,
    can_id_for_safety_pdu,
    compute_crc_s1,
    compute_crc_s2,
    compute_crc32,
    format_snn,
    generate_snn,
    is_high_priority_safety_id,
    parse_snn,
    rank_can_arbitration_priority,
    resolve_can_arbitration,
    run_cip_safety_devicenet_verification,
    validate_snn,
    verify_cip_safety_devicenet_pure_st,
    verify_dual_channel_payload,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner APG OCS register table."""
    return RegisterTable()


@pytest.fixture
def default_engine(register_table: RegisterTable) -> CipSafetyDeviceNetEngine:
    """Provides a fresh CipSafetyDeviceNetEngine instance bound to register table."""
    return CipSafetyDeviceNetEngine(
        originator_mac=10,
        target_mac=20,
        snn=DEFAULT_SNN,
        scid=DEFAULT_SCID,
        configured_epi_ms=20.0,
        max_tolerable_delay_ms=50.0,
        reg_table=register_table,
    )


# ============================================================================
# Section 1: Constants, Enums & Configuration Defaults
# ============================================================================

class TestSection1ConstantsAndEnums:
    """Validates protocol constants, class identifiers, enums, and configuration defaults."""

    def test_class_ids_and_mac_bounds(self) -> None:
        assert CIP_SAFETY_DEVICENET_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert DEVICENET_SAFETY_MAX_NODES == 64
        assert DEVICENET_SAFETY_DEFAULT_MAC_ID == 10
        assert DEVICENET_SAFETY_TARGET_MAC_ID == 20

    def test_timing_and_epi_defaults(self) -> None:
        assert DEFAULT_EPI_MS == 20.0
        assert NOMINAL_EPI_MS == 20.0
        assert NOMINAL_EPI_SCALED == 200
        assert EPI_TIMEOUT_MULTIPLIER == 3
        assert NOMINAL_WATCHDOG_MS == 60.0
        assert NOMINAL_WATCHDOG_SCALED == 600
        assert MAX_TOLERABLE_DELAY_MS == 50.0
        assert MAX_TIMESTAMP_DRIFT_MARGIN_MS == 5.0

    def test_can_baud_rate_enum_and_bit_times(self) -> None:
        assert CANBaudRate.BAUD_125K == 125_000
        assert CANBaudRate.BAUD_250K == 250_000
        assert CANBaudRate.BAUD_500K == 500_000

        assert CANBaudRate.BAUD_125K.bit_time_us == pytest.approx(CAN_BIT_TIME_125K_US)
        assert CANBaudRate.BAUD_250K.bit_time_us == pytest.approx(CAN_BIT_TIME_250K_US)
        assert CANBaudRate.BAUD_500K.bit_time_us == pytest.approx(CAN_BIT_TIME_500K_US)

    def test_safety_connection_state_enum(self) -> None:
        assert SafetyConnectionState.NON_EXISTENT == 0
        assert SafetyConnectionState.CONFIGURING == 1
        assert SafetyConnectionState.WAITING_FOR_TUNID == 2
        assert SafetyConnectionState.SAFETY_RUN == 3
        assert SafetyConnectionState.SAFETY_FAULT == 4

        # Verify DeviceNetSafetyState alias
        assert DeviceNetSafetyState == SafetyConnectionState
        assert DeviceNetSafetyState.NON_EXISTENT == 0
        assert DeviceNetSafetyState.SAFETY_RUN == 3

    def test_diagnostic_code_enum_and_aliases(self) -> None:
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_CRC == 0xDD01
        assert DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_SEQUENCE_DRIFT == 0xDD02
        assert DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_EPI_TIMEOUT == 0xDD03
        assert DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_SNN_TUNID_MISMATCH == 0xDD04
        assert DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_PING_PONG_MTD == 0xDD05

        # Check aliases
        assert DiagnosticCode.CRC_CORRUPTED == 0xDD01
        assert DiagnosticCode.CRC_MISMATCH == 0xDD01
        assert DiagnosticCode.SEQUENCE_FAULT == 0xDD02
        assert DiagnosticCode.EPI_TIMEOUT == 0xDD03
        assert DiagnosticCode.TIMEOUT == 0xDD03
        assert DiagnosticCode.SNN_TUNID_MISMATCH == 0xDD04
        assert DiagnosticCode.MTD_EXCEEDED == 0xDD05

        assert DeviceNetSafetyDiagnosticCode == DiagnosticCode
        assert DiagnosticStatusCode == DiagnosticCode

    def test_safety_mode_byte_flags(self) -> None:
        assert SafetyModeByte.IDLE == 0x00
        assert SafetyModeByte.RUN_MODE == 1 << 0
        assert SafetyModeByte.RUN == 1 << 0
        assert SafetyModeByte.TIME_PING_ACK == 1 << 1
        assert SafetyModeByte.SAFETY_DEMAND == 1 << 2
        assert SafetyModeByte.FAULT_PRESENT == 1 << 3
        assert SafetyModeByte.RESET_REQUEST == 1 << 4

        # Test bit combination
        mode = SafetyModeByte.RUN_MODE | SafetyModeByte.SAFETY_DEMAND
        assert SafetyModeByte.RUN_MODE in mode
        assert SafetyModeByte.SAFETY_DEMAND in mode
        assert SafetyModeByte.FAULT_PRESENT not in mode

    def test_cip_safety_status_bits(self) -> None:
        assert CipSafetyDeviceNetStatusBits.STATE_MASK == 0x0007
        assert CipSafetyDeviceNetStatusBits.CONNECTION_ACTIVE == 1 << 3
        assert CipSafetyDeviceNetStatusBits.PERMISSIVE_HIGH == 1 << 4
        assert CipSafetyDeviceNetStatusBits.FAULT_LATCHED == 1 << 5
        assert CipSafetyDeviceNetStatusBits.CRC_ERROR_LATCH == 1 << 6
        assert CipSafetyDeviceNetStatusBits.TIMEOUT_ERROR_LATCH == 1 << 7

    def test_black_channel_threats_iec61784(self) -> None:
        assert BlackChannelThreat.NONE == 0
        assert BlackChannelThreat.BIT_INVERSION == 1
        assert BlackChannelThreat.DELAY == 2
        assert BlackChannelThreat.SEQUENCE_DROP == 3
        assert BlackChannelThreat.DUPLICATE == 4
        assert BlackChannelThreat.SNN_MISMATCH == 5
        assert BlackChannelThreat.INSERTION == 6
        assert BlackChannelThreat.OUT_OF_ORDER == 7
        assert BlackChannelThreat.TIMESTAMP_DESYNC == 8


# ============================================================================
# Section 2: 11-Bit CAN Frame Encoding, Arbitration ID Allocation & Ranking
# ============================================================================

class TestSection2CANFramingAndArbitration:
    """Validates 11-bit CAN frame serialization, priority ranking, and arbitration."""

    def test_can_frame_valid_creation(self) -> None:
        frame = CANFrame(can_id=0x015, data=bytes([0x01, 0x02, 0x03]), rtr=False)
        assert frame.can_id == 0x015
        assert frame.dlc == 3
        assert frame.is_safety_frame is True

    def test_can_frame_invalid_id_rejection(self) -> None:
        with pytest.raises(ValueError, match="11-bit"):
            CANFrame(can_id=0x800)

        with pytest.raises(ValueError, match="11-bit"):
            CANFrame(can_id=-1)

    def test_can_frame_payload_length_restriction(self) -> None:
        with pytest.raises(ValueError, match="cannot exceed 8 bytes"):
            CANFrame(can_id=0x010, data=b"123456789")

    def test_can_frame_serialization_and_deserialization(self) -> None:
        frame = CANFrame(can_id=0x025, data=bytes([0xAA, 0xBB, 0xCC, 0xDD]), rtr=False, dlc=4)
        raw = frame.serialize()
        assert len(raw) >= 4
        deserialized = CANFrame.deserialize(raw)
        assert deserialized.can_id == frame.can_id
        assert deserialized.dlc == frame.dlc
        assert deserialized.data == frame.data
        assert deserialized.rtr == frame.rtr

    def test_can_frame_bit_stream_and_stuffing(self) -> None:
        frame = CANFrame(can_id=0x000, data=bytes([0x00, 0x00]))
        stuffed, stuff_count = frame.calculate_bit_stuffing()
        assert len(stuffed) > 0
        assert stuff_count >= 1

    def test_can_frame_wire_duration_calculation(self) -> None:
        frame = CANFrame(can_id=0x010, data=bytes([0x11, 0x22, 0x33, 0x44]))
        dur_125k = frame.calculate_wire_duration_us(CANBaudRate.BAUD_125K)
        dur_250k = frame.calculate_wire_duration_us(CANBaudRate.BAUD_250K)
        dur_500k = frame.calculate_wire_duration_us(CANBaudRate.BAUD_500K)

        assert dur_125k > dur_250k > dur_500k
        assert dur_125k == pytest.approx(dur_250k * 2.0, rel=1e-3)
        assert dur_250k == pytest.approx(dur_500k * 2.0, rel=1e-3)

    def test_can_id_for_safety_pdu(self) -> None:
        for mac in range(64):
            can_id = can_id_for_safety_pdu(mac)
            assert can_id == mac
            assert is_high_priority_safety_id(can_id) is True

        with pytest.raises(ValueError):
            can_id_for_safety_pdu(64)

    def test_allocate_devicenet_safety_arbitration_id_helper(self) -> None:
        id_10 = allocate_devicenet_safety_arbitration_id(10)
        assert id_10 == 10
        assert is_high_priority_safety_id(id_10) is True

    def test_rank_can_arbitration_priority(self) -> None:
        # Smaller CAN ID must have higher priority
        assert rank_can_arbitration_priority(0x005) < rank_can_arbitration_priority(0x010)
        assert rank_can_arbitration_priority(0x010) < rank_can_arbitration_priority(0x400)

    def test_can_arbitration_safety_wins_over_standard(self) -> None:
        safety_f = CANFrame(can_id=0x00A, sender_description="Safety_Node_10")
        std_poll = CANFrame(can_id=0x08A, sender_description="Group1_Poll")
        std_exp = CANFrame(can_id=0x40A, sender_description="Group2_Explicit")
        std_mgmt = CANFrame(can_id=0x60A, sender_description="Group3_Mgmt")

        result = CANArbitrationEngine.arbitrate([std_mgmt, std_poll, safety_f, std_exp])
        assert result.winner == safety_f
        assert result.safety_won is True
        assert len(result.losers) == 3

    def test_can_arbitration_between_safety_nodes(self) -> None:
        node_3 = CANFrame(can_id=0x003, sender_description="Safety_MAC_3")
        node_7 = CANFrame(can_id=0x007, sender_description="Safety_MAC_7")
        winner = resolve_can_arbitration([node_7, node_3])
        assert winner == node_3


# ============================================================================
# Section 3: Safety Network Number (SNN) Serialization & TUNID Matching
# ============================================================================

class TestSection3SNNAndTUNID:
    """Validates SNN creation, parsing, serialization, and TUNID authentication."""

    def test_snn_default_creation(self) -> None:
        snn = SafetyNetworkNumber()
        assert len(snn.to_bytes()) == 6
        assert snn.to_bytes() == bytes([0x20, 0x26, 0x10, 0x06, 0xAA, 0x55])
        assert snn.high_word == 0x2026
        assert snn.mid_word == 0x1006
        assert snn.low_word == 0xAA55

    def test_snn_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="exactly 6 bytes"):
            SafetyNetworkNumber(snn_bytes=b"12345")

    def test_snn_from_words(self) -> None:
        snn = SafetyNetworkNumber.from_words(low=0xAA55, high=0x2026, mid=0x1006)
        assert snn.to_bytes() == bytes([0x20, 0x26, 0x10, 0x06, 0xAA, 0x55])

    def test_snn_hex_and_dict(self) -> None:
        snn = SafetyNetworkNumber()
        assert snn.hex() == "20261006AA55"
        d = snn.to_dict()
        assert d["hex"] == "20261006AA55"
        assert d["low_word"] == 0xAA55
        assert d["high_word"] == 0x2026

    def test_generate_snn_helper(self) -> None:
        raw = generate_snn(0x2026, 0x1006AA55)
        assert len(raw) == 6
        assert raw == bytes([0x20, 0x26, 0x10, 0x06, 0xAA, 0x55])

    def test_format_snn_and_parse_snn(self) -> None:
        snn = SafetyNetworkNumber()
        formatted = format_snn(snn)
        assert formatted == "2026-1006AA55"
        parsed = parse_snn(formatted)
        assert parsed == snn.to_bytes()

    def test_parse_snn_invalid(self) -> None:
        with pytest.raises(ValueError, match="12 hex digits"):
            parse_snn("1234")

    def test_validate_snn_valid_and_invalid(self) -> None:
        valid_b = bytes([0x20, 0x26, 0x10, 0x06, 0xAA, 0x55])
        assert validate_snn(valid_b) is True
        assert validate_snn(b"\x00" * 6) is False
        assert validate_snn(b"\xFF" * 6) is False
        assert validate_snn(b"short") is False
        assert validate_snn("not_bytes") is False

    def test_tunid_creation_and_matching(self) -> None:
        snn = SafetyNetworkNumber()
        tunid = TUNID(snn=snn, mac_id=10)
        assert tunid.mac_id == 10
        assert tunid.snn_bytes == snn.to_bytes()
        assert len(tunid.to_bytes()) == 7

        # Matching
        assert tunid.matches(snn, 10) is True
        assert tunid.matches(snn, 20) is False

        rogue_snn = SafetyNetworkNumber(bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]))
        assert tunid.matches(rogue_snn, 10) is False

    def test_tunid_invalid_mac(self) -> None:
        with pytest.raises(ValueError, match="0..63"):
            TUNID(snn=SafetyNetworkNumber(), mac_id=64)


# ============================================================================
# Section 4: Dual-Channel Payload Comparison & Safety CRC Calculation
# ============================================================================

class TestSection4DualChannelCRC:
    """Validates CRC-S1, CRC-S2, and dual-channel inverted payload verification."""

    def test_calculate_crc16_ccitt_determinism(self) -> None:
        data = b"123456789"
        crc1 = calculate_crc16_ccitt(data, CRC16_CCITT_INIT)
        crc2 = calculate_crc16_ccitt(data, CRC16_CCITT_INIT)
        assert crc1 == crc2
        assert 0 <= crc1 <= 0xFFFF

    def test_calculate_crc32_ieee_determinism(self) -> None:
        data = b"123456789"
        crc = calculate_crc32_ieee(data)
        assert crc == 0xCBF43926

    def test_crc_function_aliases(self) -> None:
        data = bytes([0x10, 0x20, 0x30, 0x40])
        assert compute_crc_s1(data) == calculate_crc16_ccitt(data)
        assert compute_crc_s2(data) == calculate_crc16_ccitt(data)
        assert compute_crc32(data) == calculate_crc32_ieee(data)

    def test_verify_dual_channel_payload_bytes_inverted(self) -> None:
        ch1 = bytes([0xAA, 0x55, 0x12, 0x34])
        ch2 = bytes([0x55, 0xAA, 0xED, 0xCB])
        assert verify_dual_channel_payload(ch1, ch2, inverted=True) is True

    def test_verify_dual_channel_payload_bytes_corruption(self) -> None:
        ch1 = bytes([0xAA, 0x55, 0x12, 0x34])
        ch2_bad = bytes([0x55, 0xAA, 0xED, 0xCC])  # Corrupted last byte
        assert verify_dual_channel_payload(ch1, ch2_bad, inverted=True) is False

    def test_verify_dual_channel_payload_integers(self) -> None:
        primary = 1234
        comp = (~1234) & 0xFFFF
        assert verify_dual_channel_payload(primary, comp, inverted=True) is True

        assert verify_dual_channel_payload(primary, primary, inverted=True) is False
        assert verify_dual_channel_payload(primary, primary, inverted=False) is True

    def test_device_net_safety_packet_creation_and_crcs(self) -> None:
        pkt = DeviceNetSafetyPacket(
            primary_data=500,
            mode=SafetyModeByte.RUN_MODE,
            sequence_counter=1,
            snn=DEFAULT_SNN,
            tunid=DEFAULT_TUNID,
        )
        pkt.compute_crcs()
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.complement_data == ((~500) & 0xFFFF)

    def test_device_net_safety_packet_integrity_success(self) -> None:
        pkt = DeviceNetSafetyPacket(
            primary_data=100,
            mode=SafetyModeByte.RUN_MODE,
            sequence_counter=5,
            snn=DEFAULT_SNN,
            tunid=DEFAULT_TUNID,
        )
        pkt.compute_crcs()
        valid, threat = pkt.verify_integrity(DEFAULT_SNN, DEFAULT_TUNID)
        assert valid is True
        assert threat is None

    def test_device_net_safety_packet_crc_corruption_detection(self) -> None:
        pkt = DeviceNetSafetyPacket(
            primary_data=100,
            mode=SafetyModeByte.RUN_MODE,
            sequence_counter=5,
            snn=DEFAULT_SNN,
            tunid=DEFAULT_TUNID,
        )
        pkt.compute_crcs()
        pkt.crc_s1 ^= 0x0001  # Flip one bit
        valid, threat = pkt.verify_integrity(DEFAULT_SNN, DEFAULT_TUNID)
        assert valid is False
        assert threat == BlackChannelThreat.BIT_INVERSION

    def test_device_net_safety_packet_snn_mismatch_detection(self) -> None:
        pkt = DeviceNetSafetyPacket(
            primary_data=100,
            mode=SafetyModeByte.RUN_MODE,
            sequence_counter=5,
            snn=DEFAULT_SNN,
            tunid=DEFAULT_TUNID,
        )
        pkt.compute_crcs()
        other_snn = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        valid, threat = pkt.verify_integrity(other_snn, DEFAULT_TUNID)
        assert valid is False
        assert threat == BlackChannelThreat.SNN_MISMATCH

    def test_device_net_safety_packet_tunid_mismatch_detection(self) -> None:
        pkt = DeviceNetSafetyPacket(
            primary_data=100,
            mode=SafetyModeByte.RUN_MODE,
            sequence_counter=5,
            snn=DEFAULT_SNN,
            tunid=DEFAULT_TUNID,
        )
        pkt.compute_crcs()
        valid, threat = pkt.verify_integrity(DEFAULT_SNN, 0x9999)
        assert valid is False
        assert threat == BlackChannelThreat.INSERTION

    def test_device_net_safety_packet_serialize_can_payload(self) -> None:
        pkt = DeviceNetSafetyPacket(
            primary_data=1234,
            mode=SafetyModeByte.RUN_MODE,
            sequence_counter=10,
        )
        pkt.compute_crcs()
        can_bytes = pkt.serialize_can_payload()
        assert len(can_bytes) == 8
        unpacked_primary = struct.unpack(">h", can_bytes[:2])[0]
        assert unpacked_primary == 1234


# ============================================================================
# Section 5: EPI Watchdog Tracking (< 20 ms) & Timeout Trips
# ============================================================================

class TestSection5EPIWatchdogTracking:
    """Validates Expected Packet Interval watchdog tracking, reaction time (< 20 ms), and trips."""

    def test_engine_initial_watchdog_state(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        assert engine.configured_epi_ms == 20.0
        assert engine.watchdog_timeout_ms == 60.0
        assert engine.watchdog_timer_ms == 0.0

    def test_watchdog_healthy_under_threshold(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        # Advance clock by 30 ms (well below 60 ms timeout)
        engine.scan_step(0.030)
        assert engine.state == SafetyConnectionState.SAFETY_RUN
        assert engine.permissive is True
        assert engine.fault_trip is False
        assert engine.diagnostic_code == DiagnosticCode.OK

    def test_watchdog_timeout_trip_0xdd03(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        # Silence > 60 ms watchdog threshold (step 65 ms)
        engine.scan_step(0.065)
        assert engine.state == SafetyConnectionState.SAFETY_FAULT
        assert engine.diagnostic_code == DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_EPI_TIMEOUT
        assert engine.permissive is False
        assert engine.fault_trip is True
        assert engine.timeout_error_count == 1

    def test_watchdog_reset_on_valid_packet_consumption(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        # Advance 40 ms
        engine.scan_step(0.040)
        assert engine.watchdog_timer_ms == pytest.approx(40.0)

        # Feed valid packet
        pkt = engine.produce_safety_packet(10)
        accepted = engine.consume_safety_packet(pkt)
        assert accepted is True
        # Watchdog must reset to 0
        assert engine.watchdog_timer_ms == 0.0

    def test_watchdog_reaction_time_bound_under_20ms(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        # Test tight boundary: 61 ms silence trips with reaction latency = 1.0 ms (< 20 ms)
        engine.scan_step(0.061)
        reaction_latency = engine.watchdog_timer_ms - engine.watchdog_timeout_ms
        assert reaction_latency < 20.0
        assert engine.state == SafetyConnectionState.SAFETY_FAULT

    def test_watchdog_trip_latched_until_reset(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)
        engine.scan_step(0.070)

        assert engine.fault_trip is True
        # Feeding valid packet must NOT unlatch fault
        pkt = engine.produce_safety_packet(123)
        res = engine.consume_safety_packet(pkt)
        assert res is False
        assert engine.state == SafetyConnectionState.SAFETY_FAULT

        # Explicit reset required
        engine.reset_fault()
        assert engine.state == SafetyConnectionState.NON_EXISTENT
        assert engine.fault_trip is False
        assert engine.diagnostic_code == DiagnosticCode.OK


# ============================================================================
# Section 6: Target Connection State Machine & Process Safety Interlocks
# ============================================================================

class TestSection6StateMachineAndInterlocks:
    """Validates connection state transitions, handshake, and safety fault interlocks."""

    def test_connection_lifecycle_full_progression(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        assert engine.state == SafetyConnectionState.NON_EXISTENT

        engine.open_connection()
        assert engine.state == SafetyConnectionState.CONFIGURING

        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 15.0)
        assert engine.state == SafetyConnectionState.WAITING_FOR_TUNID
        assert engine.configured_epi_ms == 15.0

        engine.establish_safety_run(DEFAULT_TUNID)
        assert engine.state == SafetyConnectionState.SAFETY_RUN
        assert engine.permissive is True
        assert engine.fault_trip is False

    def test_tunid_handshake_mismatch_trip_0xdd04(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)

        with pytest.raises(CipSafetyDeviceNetConfigError, match="TUNID mismatch"):
            engine.establish_safety_run(0x9999)  # Wrong TUNID

        assert engine.state == SafetyConnectionState.SAFETY_FAULT
        assert engine.diagnostic_code == DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_SNN_TUNID_MISMATCH
        assert engine.fault_trip is True

    def test_consume_crc_corrupted_packet_trip_0xdd01(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        bad_pkt = engine.produce_safety_packet(500)
        bad_pkt.crc_s1 ^= 0x5555  # Corrupt CRC-S1
        accepted = engine.consume_safety_packet(bad_pkt)

        assert accepted is False
        assert engine.state == SafetyConnectionState.SAFETY_FAULT
        assert engine.diagnostic_code == DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_CRC
        assert engine.fault_trip is True
        assert engine.crc_error_count == 1

    def test_consume_packet_sequence_drift_trip_0xdd02(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        p1 = engine.produce_safety_packet(10)
        assert engine.consume_safety_packet(p1) is True

        # Duplicate packet with same sequence number
        p_dup = engine.produce_safety_packet(11)
        p_dup.sequence_counter = p1.sequence_counter
        p_dup.compute_crcs()
        accepted = engine.consume_safety_packet(p_dup)

        assert accepted is False
        assert engine.state == SafetyConnectionState.SAFETY_FAULT
        assert engine.diagnostic_code == DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_SEQUENCE_DRIFT
        assert engine.sequence_error_count == 1

    def test_consume_packet_excessive_sequence_jump_0xdd02(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        p1 = engine.produce_safety_packet(10)
        engine.consume_safety_packet(p1)

        # Sequence jump > 5
        p_jump = engine.produce_safety_packet(12)
        p_jump.sequence_counter = p1.sequence_counter + 10
        p_jump.compute_crcs()
        accepted = engine.consume_safety_packet(p_jump)

        assert accepted is False
        assert engine.state == SafetyConnectionState.SAFETY_FAULT
        assert engine.diagnostic_code == DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_SEQUENCE_DRIFT

    def test_ping_pong_transit_delay_and_mtd_bounding(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        p = engine.produce_safety_packet(100)
        p.time_ping_ts = engine.current_time_ms - 4.0  # round trip = 4 ms
        p.consumer_delay_ms = 1.0  # one way = (4.0 - 1.0)/2 = 1.5 ms
        p.compute_crcs()

        assert engine.consume_safety_packet(p) is True
        assert engine.observed_transit_delay_ms == pytest.approx(1.5, rel=1e-2)
        assert engine.observed_transit_delay_ms < 50.0

    def test_ping_pong_mtd_exceeded_trip_0xdd05(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        p = engine.produce_safety_packet(100)
        engine.current_time_ms = 200.0
        p.time_ping_ts = 80.0  # round trip = 120 ms -> one way ~59.75 ms > 50 ms MTD
        p.consumer_delay_ms = 0.5
        p.compute_crcs()

        accepted = engine.consume_safety_packet(p)
        assert accepted is False
        assert engine.state == SafetyConnectionState.SAFETY_FAULT
        assert engine.diagnostic_code == DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_PING_PONG_MTD
        assert engine.fault_trip is True
        assert engine.mtd_exceeded_count == 1


# ============================================================================
# Section 7: Horner OCS Register Table Synchronization
# ============================================================================

class TestSection7HornerOCSRegisters:
    """Validates Horner OCS register space synchronization (%R1660..%R1667, %M387..%M388)."""

    def test_register_sync_safety_run_normal(
        self, default_engine: CipSafetyDeviceNetEngine, register_table: RegisterTable
    ) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        pkt = engine.produce_safety_packet(777)
        engine.consume_safety_packet(pkt)
        engine.sync_to_registers(register_table, privilege=PrivilegeMode.SYSTEM)

        assert register_table.read_word("%R1660") == int(SafetyConnectionState.SAFETY_RUN)
        assert register_table.read_word("%R1661") == 200  # 20.0 ms * 10
        assert register_table.read_word("%R1662") >= 0   # Transit delay
        assert register_table.read_uword("%R1663") == engine.sequence_counter
        assert register_table.read_word("%R1664") == 777  # Primary
        # Complement is signed 16-bit representation
        expected_comp = ((~777) & 0xFFFF)
        if expected_comp > 32767:
            expected_comp -= 65536
        assert register_table.read_word("%R1665") == expected_comp
        assert register_table.read_word("%R1666") == 0    # CRC error count
        assert register_table.read_uword("%R1667") == int(DiagnosticCode.OK)
        assert register_table.read_bit("%M387") is True   # Permissive
        assert register_table.read_bit("%M388") is False  # Trip

    def test_register_sync_fault_state(
        self, default_engine: CipSafetyDeviceNetEngine, register_table: RegisterTable
    ) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)
        engine.scan_step(0.070)  # Trip timeout

        engine.sync_to_registers(register_table, privilege=PrivilegeMode.SYSTEM)

        assert register_table.read_word("%R1660") == int(SafetyConnectionState.SAFETY_FAULT)
        diag_val = int(DiagnosticCode.CIP_DEVICENET_SAFETY_ERR_EPI_TIMEOUT)
        assert register_table.read_uword("%R1667") == diag_val
        assert register_table.read_bit("%M387") is False
        assert register_table.read_bit("%M388") is True

    def test_register_sync_privilege_mode_enforcement(
        self, default_engine: CipSafetyDeviceNetEngine, register_table: RegisterTable
    ) -> None:
        engine = default_engine
        engine.open_connection()
        # Default sync uses PrivilegeMode.SYSTEM
        engine.sync_to_registers(register_table, privilege=PrivilegeMode.SYSTEM)
        assert register_table.read_word("%R1660") == int(SafetyConnectionState.CONFIGURING)


# ============================================================================
# Section 8: ILogicUnit Scan Step Cycle Integration
# ============================================================================

class TestSection8ILogicUnitScanSimulation:
    """Validates ILogicUnit scan cycle execution and 100-cycle simulation."""

    def test_ilogic_unit_interface_methods(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        assert isinstance(default_engine, ILogicUnit)
        assert hasattr(default_engine, "scan_step")
        assert hasattr(default_engine, "execute")
        assert hasattr(default_engine, "reset")

    def test_scan_step_advances_clock(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        assert engine.current_time_ms == 0.0
        engine.scan_step(0.010)
        assert engine.current_time_ms == pytest.approx(10.0)
        engine.scan_step(0.025)
        assert engine.current_time_ms == pytest.approx(35.0)

    def test_execute_method_with_none_context(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.execute(None)
        assert engine.current_time_ms == pytest.approx(10.0)

    def test_100_cycle_closed_loop_simulation(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)

        # Run 100 scan cycles at 10 ms resolution
        for cycle in range(100):
            # Feed packet every 2 cycles (20 ms)
            if cycle % 2 == 0:
                pkt = engine.produce_safety_packet(1000 + cycle)
                assert engine.consume_safety_packet(pkt) is True
            engine.scan_step(0.010)

        assert engine.state == SafetyConnectionState.SAFETY_RUN
        assert engine.permissive is True
        assert engine.fault_trip is False
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.current_time_ms == pytest.approx(1000.0)
        assert engine.total_packets_received == 50

    def test_engine_reset(self, default_engine: CipSafetyDeviceNetEngine) -> None:
        engine = default_engine
        engine.open_connection()
        engine.configure_parameters(DEFAULT_SNN, DEFAULT_SCID, 20.0)
        engine.establish_safety_run(DEFAULT_TUNID)
        engine.scan_step(0.050)

        engine.reset()
        assert engine.state == SafetyConnectionState.NON_EXISTENT
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.current_time_ms == 0.0
        assert engine.total_packets_received == 0
        assert engine.permissive is False


# ============================================================================
# Section 9: Pure ST POU Validation & Anti-Ladder Security Guard
# ============================================================================

class TestSection9PureSTPOUAndAntiLadder:
    """Validates IEC 61131-3 Pure ST POU compliance and anti-ladder security enforcement."""

    def test_pure_st_pou_constants(self) -> None:
        assert isinstance(CIP_SAFETY_DEVICENET_SYNC_POU, str)
        assert "PROGRAM CipSafetyDeviceNetSync" in CIP_SAFETY_DEVICENET_SYNC_POU
        assert "%R1660" in CIP_SAFETY_DEVICENET_SYNC_POU
        assert "%R1667" in CIP_SAFETY_DEVICENET_SYNC_POU
        assert "%M387" in CIP_SAFETY_DEVICENET_SYNC_POU
        assert "%M388" in CIP_SAFETY_DEVICENET_SYNC_POU
        assert PURE_ST_POU == CIP_SAFETY_DEVICENET_SYNC_POU

    def test_pure_st_pou_ast_parsing_and_registers(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_DEVICENET_SYNC_POU)
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(CIP_SAFETY_DEVICENET_SYNC_POU)
        assert pou is not None
        assert pou.name == "CipSafetyDeviceNetSync"
        assert pou.pou_type == POUType.PROGRAM

        required_regs = {
            "%R1660", "%R1661", "%R1662", "%R1663",
            "%R1664", "%R1665", "%R1666", "%R1667",
            "%M387", "%M388",
        }
        for reg in required_regs:
            assert reg in pou.bound_registers

    def test_verify_cip_safety_devicenet_pure_st_function(self) -> None:
        assert verify_cip_safety_devicenet_pure_st() is True

    def test_anti_ladder_contacts_rejection(self) -> None:
        ladder_code = """
        PROGRAM BadLadderContacts
        VAR x : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_code)

    def test_anti_ladder_inverted_contacts_rejection(self) -> None:
        ladder_code = """
        PROGRAM BadLadderInvertedContact
        VAR x : BOOL; END_VAR
        ---[/]---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_code)

    def test_anti_ladder_rung_delimiters_rejection(self) -> None:
        ladder_code = """
        PROGRAM BadLadderRung
        RUNG 1
        x := TRUE;
        END_RUNG
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_code)

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        ladder_code = """
        PROGRAM BadLadderMnemonic
        XIC MyBit;
        OTE MyOut;
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_code)


# ============================================================================
# Section 10: 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection10VerificationRunner:
    """Validates execution of the 9-stage verification suite and JSON evidence emission."""

    def test_run_cip_safety_devicenet_verification_all_passed(self) -> None:
        result = run_cip_safety_devicenet_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        data = result["data"]
        assert data["work_package"] == "W205"
        assert data["gate"] == "Gate G8 / G4"
        assert data["stages_passed"] == 9
        assert data["total_stages"] == 9
        assert len(data["stages"]) == 9
        for stage in data["stages"]:
            assert stage["passed"] is True

    def test_run_cip_safety_devicenet_verification_json_export(self, tmp_path: Path) -> None:
        out_json = tmp_path / "cip_safety_devicenet_evidence.json"
        result = run_cip_safety_devicenet_verification(output_path=str(out_json))
        assert result["status"] == "success"
        assert out_json.exists()

        with open(out_json, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["status"] == "success"
        assert loaded["data"]["stages_passed"] == 9
        assert "%R1660" in loaded["data"]["register_map"]
        assert "%M387" in loaded["data"]["register_map"]

    def test_register_map_completeness_in_evidence(self) -> None:
        result = run_cip_safety_devicenet_verification()
        reg_map = result["data"]["register_map"]
        expected = {
            "%R1660": "SafetyConnectionStateWord",
            "%R1661": "ConfiguredEpiMsScaled",
            "%R1662": "ObservedTransitDelayMsScaled",
            "%R1663": "SafeSequenceCounter",
            "%R1664": "SafetyPayloadPrimary",
            "%R1665": "SafetyPayloadComplement",
            "%R1666": "CrcErrorCounter",
            "%R1667": "DiagnosticStatusCode",
            "%M387": "CipDeviceNetSafetyPermissive",
            "%M388": "CipDeviceNetSafetyFaultTrip",
        }
        for k, v in expected.items():
            assert reg_map[k] == v
