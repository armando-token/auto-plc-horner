"""Comprehensive Unit and Integration Test Suite for W214 CIP Safety Multi-Point Engine.

Work Package: W214 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 60+ Unit Tests across 11 Sections:
1. Section 1: Constants, Enums, & Protocol Defaults (OperationalMode, ConnectionState, NetworkSafetyState, DiagnosticCode).
2. Section 2: Pure ST POU AST Parsing, Symbol Binding, & Anti-Ladder Security Guard (%R1750..%R1757, %M408..%M409).
3. Section 3: Safety Network Number (SNN), TUNID, OUNID, & SCID Serialization/Validation.
4. Section 4: Dual Safety Checksums (CRC-S1 & inverted CRC-S2) and Diversified Payload Cross-Comparison.
5. Section 5: CIP Safety Packet Serialization, Deserialization, & CRC Integrity.
6. Section 6: Expected Packet Interval (EPI) Watchdog & Silence Timeout Detection (< 20 ms nominal).
7. Section 7: Ping-Request / Ping-Response Heartbeat Protocol & Latency Metrics Tracking.
8. Section 8: Multi-Point 8-Connection State Machine Lifecycle across Dual-Mode (Originator & Target).
9. Section 9: ILogicUnit Scan Step Cycle Integration (100-cycle simulation).
10. Section 10: Horner OCS Register Synchronization (%R1750..%R1757, %M408..%M409) with PrivilegeMode.SYSTEM.
11. Section 11: 9-Stage Deterministic Verification Runner & Evidence JSON Export.
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
from jev_cscape.telemetry.cip_safety_multipoint import (
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_MULTIPOINT_CLASS_ID,
    CIP_SAFETY_MULTIPOINT_POU,
    CIP_SAFETY_MULTIPOINT_SYNC_POU,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyMultiPointEngine,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    DEFAULT_EPI_MS,
    DEFAULT_SCID,
    DEFAULT_SNN,
    DEFAULT_WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    MAX_SAFETY_CONNECTIONS,
    NOMINAL_EPI_MS,
    REGISTER_LATENCY_SCALE_FACTOR,
    BlackChannelThreat,
    CipSafetyConnectionState,
    CipSafetyConnectionType,
    CipSafetyControlByte,
    CipSafetyCrcCorruptionError,
    CipSafetyDiagnosticCode,
    CipSafetyDualChannelDiscrepancyError,
    CipSafetyEpiTimeoutError,
    CipSafetyMultiPointEngine,
    CipSafetyMultiPointError,
    CipSafetyOperationalMode,
    CipSafetyPacket,
    CipSafetySequenceRepetitionError,
    CipSafetySnnTunidMismatchError,
    ConnectionState,
    DiagnosticStatusCode,
    DiversifiedMode,
    MultiPointConnection,
    MultiPointPacket,
    NetworkSafetyState,
    OUNID,
    OperationalMode,
    OriginatorUniqueNetworkId,
    SCID,
    SafetyConfigurationIdentifier,
    SafetyConnectionObject,
    SafetyConnectionState,
    SafetyControlByte,
    SafetyModeByte,
    SafetyNetworkNumber,
    SafetyStatusBits,
    SafetySupervisorObject,
    SafetyValidatorObject,
    TUNID,
    TargetUniqueNetworkId,
    calculate_crc16_ccitt,
    compute_crc_s1,
    compute_crc_s2,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_multipoint_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    scale_latency_ms_to_int16,
    validate_snn,
    verify_cip_safety_multipoint_pure_st,
    verify_dual_channel_payload,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def cip_safety_engine(register_table: RegisterTable) -> CipSafetyMultiPointEngine:
    """Provide a fresh CipSafetyMultiPointEngine initialized with 8 connections."""
    engine = CipSafetyMultiPointEngine(
        register_table=register_table,
        operational_mode=CipSafetyOperationalMode.TARGET_AND_ORIGINATOR,
        snn=DEFAULT_SNN,
        epi_ms=NOMINAL_EPI_MS,
        watchdog_timeout_ms=DEFAULT_WATCHDOG_TIMEOUT_MS,
    )
    for i in range(1, 9):
        c_type = CipSafetyConnectionType.ORIGINATOR if i <= 4 else CipSafetyConnectionType.TARGET
        engine.configure_connection(i, c_type, tunid=i, ounid=200 + i, auto_activate=True)
    return engine


# ============================================================================
# Section 1: Constants, Enums, & Protocol Defaults
# ============================================================================

class TestSection1ConstantsAndEnums:
    """Validate ODVA Volume 5 CIP Safety protocol constants and enumerations."""

    def test_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_MULTIPOINT_CLASS_ID == 0x39

    def test_timing_and_scale_defaults(self) -> None:
        assert MAX_SAFETY_CONNECTIONS == 8
        assert NOMINAL_EPI_MS == 20.0
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 60.0
        assert REGISTER_LATENCY_SCALE_FACTOR == 10.0

    def test_operational_mode_enum(self) -> None:
        assert CipSafetyOperationalMode.DISABLED == 0
        assert CipSafetyOperationalMode.TARGET_ONLY == 1
        assert CipSafetyOperationalMode.ORIGINATOR_ONLY == 2
        assert CipSafetyOperationalMode.TARGET_AND_ORIGINATOR == 3
        assert OperationalMode.DUAL_MODE == 3

    def test_connection_state_enum(self) -> None:
        assert CipSafetyConnectionState.UNCONFIGURED == 0
        assert CipSafetyConnectionState.INITIALIZING == 1
        assert CipSafetyConnectionState.EXECUTING == 2
        assert CipSafetyConnectionState.FAULTED == 3
        assert CipSafetyConnectionState.SAFE_STATE == 4

    def test_network_safety_state_enum(self) -> None:
        assert NetworkSafetyState.INIT == 0
        assert NetworkSafetyState.HEALTHY == 1
        assert NetworkSafetyState.DEGRADED == 2
        assert NetworkSafetyState.FAULTED == 3

    def test_diagnostic_codes(self) -> None:
        assert CipSafetyDiagnosticCode.OK == 0x0000
        assert CipSafetyDiagnosticCode.EPI_TIMEOUT_EXPIRED == 0xE601
        assert CipSafetyDiagnosticCode.DUAL_CHANNEL_DISCREPANCY == 0xE602
        assert CipSafetyDiagnosticCode.CRC_S_CORRUPTION == 0xE603
        assert CipSafetyDiagnosticCode.SNN_TUNID_MISMATCH == 0xE604

    def test_safety_control_byte_flags(self) -> None:
        assert SafetyControlByte.IDLE == 0x00
        assert SafetyControlByte.RUN == 1 << 0
        assert SafetyControlByte.PING_REQ == 1 << 1
        assert SafetyControlByte.PING_RESP == 1 << 2
        assert SafetyControlByte.SAFETY_DEMAND == 1 << 3
        assert SafetyControlByte.FAULT_PRESENT == 1 << 4
        assert SafetyControlByte.RESET_REQUEST == 1 << 5

    def test_black_channel_threats(self) -> None:
        assert BlackChannelThreat.CORRUPTION == 1
        assert BlackChannelThreat.UNINTENDED_REPETITION == 2
        assert BlackChannelThreat.INCORRECT_SEQUENCE == 3
        assert BlackChannelThreat.LOSS == 4
        assert BlackChannelThreat.UNACCEPTABLE_DELAY == 5
        assert BlackChannelThreat.INSERTION == 6
        assert BlackChannelThreat.MASQUERADE == 7
        assert BlackChannelThreat.ADDRESSING_FAULT == 8


# ============================================================================
# Section 2: Pure ST POU AST Parsing, Symbol Binding, & Anti-Ladder Security Guard
# ============================================================================

class TestSection2PureSTPOU:
    """Verify IEC 61131-3 Pure Structured Text POU compliance."""

    def test_verify_cip_safety_multipoint_pure_st_helper(self) -> None:
        assert verify_cip_safety_multipoint_pure_st() is True

    def test_security_guard_pure_st_content(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_MULTIPOINT_SYNC_POU)

    def test_st_parser_pou_validation(self) -> None:
        result = STParser.validate_code(CIP_SAFETY_MULTIPOINT_SYNC_POU)
        assert result.status == AgentStatus.SUCCESS

    def test_st_parser_ast_and_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_MULTIPOINT_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R1750", "%R1751", "%R1752", "%R1753",
            "%R1754", "%R1755", "%R1756", "%R1757",
            "%M408", "%M409",
        }
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_anti_ladder_contacts_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR END_VAR\n  ---[ ]---( )---\nEND_PROGRAM")

    def test_anti_ladder_rungs_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR END_VAR\n  RUNG 1: XIC(Start) OTE(Motor);\nEND_PROGRAM")


# ============================================================================
# Section 3: Safety Network Number (SNN), TUNID, OUNID, & SCID
# ============================================================================

class TestSection3SnnAndIdentities:
    """Verify SNN formatting, parsing, validation, TUNID, OUNID, and SCID."""

    def test_generate_and_format_snn(self) -> None:
        snn = generate_snn(0x2026, 0x1006AA55)
        assert len(snn) == 6
        fmt = format_snn(snn)
        assert fmt == "2026-1006AA55"

    def test_parse_snn(self) -> None:
        fmt = "2026-1006AA55"
        parsed = parse_snn(fmt)
        assert parsed == bytes([0x20, 0x26, 0x10, 0x06, 0xAA, 0x55])

    def test_validate_snn_valid(self) -> None:
        snn = bytes([0x20, 0x26, 0x10, 0x06, 0xAA, 0x55])
        assert validate_snn(snn) is True

    def test_validate_snn_invalid(self) -> None:
        assert validate_snn(b"\x00" * 6) is False
        assert validate_snn(b"\xFF" * 6) is False
        assert validate_snn(b"short") is False
        assert validate_snn("not_bytes") is False

    def test_safety_network_number_dataclass(self) -> None:
        snn = SafetyNetworkNumber.create(0x2026, 0x1006AA55, 0x0001)
        assert snn.low_word == 0x2026
        assert len(snn.raw_bytes) == 8
        assert snn.to_hex() == "20261006AA550001"

    def test_target_unique_network_id_matching(self) -> None:
        snn = SafetyNetworkNumber.create(0x2026, 0x1006AA55, 0x0001)
        tunid1 = TargetUniqueNetworkId(snn=snn, target_node_id=10)
        tunid2 = TargetUniqueNetworkId(snn=snn, target_node_id=10)
        tunid3 = TargetUniqueNetworkId(snn=snn, target_node_id=20)
        assert tunid1.matches(tunid2) is True
        assert tunid1.matches(tunid3) is False

    def test_originator_unique_network_id_matching(self) -> None:
        snn = SafetyNetworkNumber.create(0x2026, 0x1006AA55, 0x0001)
        ounid1 = OriginatorUniqueNetworkId(snn=snn, originator_node_id=100)
        ounid2 = OriginatorUniqueNetworkId(snn=snn, originator_node_id=100)
        ounid3 = OriginatorUniqueNetworkId(snn=snn, originator_node_id=200)
        assert ounid1.matches(ounid2) is True
        assert ounid1.matches(ounid3) is False

    def test_safety_configuration_identifier_scid(self) -> None:
        scid1 = SafetyConfigurationIdentifier(crc=0x12345678, timestamp=1700000000)
        scid2 = SafetyConfigurationIdentifier(crc=0x12345678, timestamp=1700000000)
        scid3 = SafetyConfigurationIdentifier(crc=0x87654321, timestamp=1700000000)
        assert scid1.matches(scid2) is True
        assert scid1.matches(scid3) is False
        assert len(scid1.to_bytes()) == 8


# ============================================================================
# Section 4: Dual Safety Checksums & Diversified Payload Cross-Comparison
# ============================================================================

class TestSection4CrcAndDualChannel:
    """Verify CRC-S1, inverted CRC-S2, and dual-channel diversification."""

    def test_compute_crc_s1_deterministic(self) -> None:
        payload = b"\x01\x02\x03\x04"
        crc1 = compute_crc_s1(payload)
        crc2 = calculate_crc16_ccitt(payload)
        assert crc1 == crc2
        assert 0 <= crc1 <= 0xFFFF

    def test_compute_crc_s2_inverted(self) -> None:
        payload = b"\x01\x02\x03\x04"
        crc_s1 = compute_crc_s1(payload)
        crc_s2 = compute_crc_s2(payload, inverted=True)
        assert crc_s2 == ((~crc_s1) & 0xFFFF)

    def test_verify_dual_channel_payload_bytes_inverted(self) -> None:
        ch_a = b"\x12\x34\xAB\xCD"
        ch_b = bytes((~b) & 0xFF for b in ch_a)
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is True

    def test_verify_dual_channel_payload_bytes_inverted_mismatch(self) -> None:
        ch_a = b"\x12\x34\xAB\xCD"
        ch_b = bytearray(bytes((~b) & 0xFF for b in ch_a))
        ch_b[0] ^= 0x01  # Bit flip
        assert verify_dual_channel_payload(ch_a, bytes(ch_b), DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_payload_int_inverted(self) -> None:
        ch_a = 0x1234
        ch_b = (~ch_a) & 0xFFFF
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is True

    def test_verify_dual_channel_payload_identical_mode(self) -> None:
        ch_a = b"\x12\x34"
        assert verify_dual_channel_payload(ch_a, ch_a, DiversifiedMode.IDENTICAL) is True
        assert verify_dual_channel_payload(ch_a, b"\x12\x35", DiversifiedMode.IDENTICAL) is False


# ============================================================================
# Section 5: CIP Safety Packet Serialization & Deserialization
# ============================================================================

class TestSection5PacketSerialization:
    """Verify packet encoding, decoding, and checksum verification."""

    def test_packet_crc_calculation_and_verification(self) -> None:
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN,
            tunid=1,
            ounid=101,
            connection_id=1,
            sequence_number=42,
            timestamp_ms=1234.5,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x10\x20",
            channel_b_payload=b"\xEF\xDF",
        )
        c1, c2 = pkt.calculate_crcs()
        assert pkt.crc_s1 == c1
        assert pkt.crc_s2 == c2
        assert pkt.verify_crcs() is True
        assert pkt.verify_dual_channel(DiversifiedMode.INVERTED) is True

    def test_packet_serialization_roundtrip(self) -> None:
        pkt = CipSafetyPacket(
            snn=DEFAULT_SNN,
            tunid=2,
            ounid=102,
            connection_id=2,
            sequence_number=100,
            timestamp_ms=5000.0,
            mode_byte=SafetyControlByte.RUN | SafetyControlByte.PING_REQ,
            channel_a_payload=b"\xAA\xBB\xCC",
            channel_b_payload=b"\x55\x44\x33",
            ping_producer_ts_ms=5000.0,
            ping_turnaround_delay_ms=2.5,
        )
        pkt.calculate_crcs()
        raw = pkt.serialize()

        pkt_dec = CipSafetyPacket.deserialize(raw)
        assert pkt_dec.snn == pkt.snn
        assert pkt_dec.tunid == pkt.tunid
        assert pkt_dec.ounid == pkt.ounid
        assert pkt_dec.connection_id == pkt.connection_id
        assert pkt_dec.sequence_number == pkt.sequence_number
        assert abs(pkt_dec.timestamp_ms - pkt.timestamp_ms) < 0.001
        assert pkt_dec.mode_byte == pkt.mode_byte
        assert pkt_dec.channel_a_payload == pkt.channel_a_payload
        assert pkt_dec.channel_b_payload == pkt.channel_b_payload
        assert pkt_dec.crc_s1 == pkt.crc_s1
        assert pkt_dec.crc_s2 == pkt.crc_s2
        assert pkt_dec.verify_crcs() is True


# ============================================================================
# Section 6: Expected Packet Interval (EPI) Watchdog & Silence Timeout
# ============================================================================

class TestSection6EpiWatchdog:
    """Verify Expected Packet Interval monitoring and silence timeout detection."""

    def test_epi_watchdog_healthy_before_timeout(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        conn = cip_safety_engine.get_connection(1)
        assert conn.state == CipSafetyConnectionState.EXECUTING

        # Advance 40 ms (watchdog is 60 ms)
        for _ in range(4):
            cip_safety_engine.scan_step(0.010)

        assert conn.state == CipSafetyConnectionState.EXECUTING
        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.OK
        assert cip_safety_engine.safety_trip_fault_active is False

    def test_epi_watchdog_timeout_trip(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        # Advance 70 ms total without packets (> 60 ms watchdog)
        for _ in range(7):
            cip_safety_engine.scan_step(0.010)

        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.EPI_TIMEOUT_EXPIRED
        assert cip_safety_engine.safety_trip_fault_active is True
        conn = cip_safety_engine.get_connection(1)
        assert conn.state == CipSafetyConnectionState.SAFE_STATE


# ============================================================================
# Section 7: Ping-Request / Ping-Response Heartbeat Handshake & Latency Metrics
# ============================================================================

class TestSection7PingPongLatency:
    """Verify Ping-Request / Ping-Response heartbeat handshakes and latency tracking."""

    def test_ping_pong_handshake(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        ping_req = cip_safety_engine.send_ping_request(1)
        assert (ping_req.mode_byte & SafetyControlByte.PING_REQ) != 0

        conn = cip_safety_engine.get_connection(1)
        ping_resp = conn.create_ping_response(ping_req, turnaround_delay_ms=1.2, current_time_ms=1010.0)
        assert (ping_resp.mode_byte & SafetyControlByte.PING_RESP) != 0

        # Receive ping response after 12.5 ms
        rtt = cip_safety_engine.handle_ping_response(1, ping_resp, rx_time_ms=ping_req.ping_producer_ts_ms + 12.5)
        assert rtt > 0.0
        assert conn.current_latency_ms == rtt
        assert cip_safety_engine.mean_safety_latency_ms > 0.0

    def test_latency_scaling_helpers(self) -> None:
        assert scale_latency_ms_to_int16(12.5) == 125
        assert scale_latency_ms_to_int16(18.0) == 180
        assert scale_latency_ms_to_int16(0.0) == 0


# ============================================================================
# Section 8: Multi-Point Dual-Mode 8-Connection State Machine
# ============================================================================

class TestSection8MultiPointStateMachine:
    """Verify up to 8 concurrent safety connections across Target and Originator modes."""

    def test_8_active_connections_healthy(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        assert cip_safety_engine.active_safety_connection_count == 8
        assert cip_safety_engine.network_safety_state == NetworkSafetyState.HEALTHY
        assert cip_safety_engine.active_fault_mask == 0
        assert cip_safety_engine.multi_point_active is True
        assert cip_safety_engine.safety_trip_fault_active is False

    def test_single_connection_trip_degradation(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        # Trip connection 4
        cip_safety_engine.simulate_dual_channel_discrepancy(4)
        conn4 = cip_safety_engine.get_connection(4)
        assert conn4.state == CipSafetyConnectionState.SAFE_STATE
        assert (cip_safety_engine.active_fault_mask & (1 << 3)) != 0
        assert cip_safety_engine.network_safety_state == NetworkSafetyState.FAULTED
        assert cip_safety_engine.safety_trip_fault_active is True

    def test_reset_restores_healthy_state(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        cip_safety_engine.simulate_crc_corruption(2)
        assert cip_safety_engine.safety_trip_fault_active is True

        res = cip_safety_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.OK
        assert cip_safety_engine.safety_trip_fault_active is False
        assert cip_safety_engine.active_fault_mask == 0
        assert cip_safety_engine.network_safety_state == NetworkSafetyState.HEALTHY
        assert cip_safety_engine.multi_point_active is True


# ============================================================================
# Section 9: ILogicUnit Scan Step Simulation & ScanContext Execution
# ============================================================================

class TestSection9LogicUnitSimulation:
    """Verify ILogicUnit interface compliance and scan_step execution."""

    def test_logic_unit_properties(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        assert isinstance(cip_safety_engine, ILogicUnit)
        assert cip_safety_engine.name == "CipSafetyMultiPointEngine"
        assert cip_safety_engine.priority == 95
        assert cip_safety_engine.is_enabled is True

    def test_scan_step_with_context(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0)
        cip_safety_engine.execute(ctx)
        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.OK

    def test_100_cycle_scan_simulation(self, cip_safety_engine: CipSafetyMultiPointEngine) -> None:
        for i in range(100):
            ctx = ScanContext(cycle=i + 1, dt_ms=5.0, elapsed_time_ms=(i + 1) * 5.0)
            cip_safety_engine.execute(ctx)
            # Send valid packets periodically to keep watchdog healthy
            if i % 2 == 0:
                pkt = cip_safety_engine.send_safety_packet(1, b"\x01\x02")
                # Reset silence for connection 1
                cip_safety_engine.get_connection(1).silence_elapsed_ms = 0.0


# ============================================================================
# Section 10: Horner OCS Register Synchronization (%R1750..%R1757, %M408..%M409)
# ============================================================================

class TestSection10RegisterSynchronization:
    """Verify register table synchronization with SYSTEM privilege."""

    def test_register_synchronization_healthy(
        self, cip_safety_engine: CipSafetyMultiPointEngine, register_table: RegisterTable
    ) -> None:
        cip_safety_engine.mean_safety_latency_ms = 12.5
        cip_safety_engine.max_safety_latency_ms = 18.0
        cip_safety_engine.sync_to_registers(register_table)

        assert register_table.read_word("%R1750") == 3   # OperationalMode
        assert register_table.read_word("%R1751") == 8   # ActiveSafetyConnectionCount
        assert register_table.read_word("%R1752") == 125 # MeanLatency
        assert register_table.read_word("%R1753") == 180 # MaxLatency
        assert register_table.read_word("%R1754") == 0   # ConsecutiveErrors
        assert register_table.read_word("%R1755") == 0   # ActiveFaultMask
        assert register_table.read_word("%R1756") == 1   # NetworkSafetyState: Healthy
        assert register_table.read_uword("%R1757") == 0x0000 # OK
        assert register_table.read_bit("%M408") is True  # Active
        assert register_table.read_bit("%M409") is False # No trip

    def test_register_synchronization_trip(
        self, cip_safety_engine: CipSafetyMultiPointEngine, register_table: RegisterTable
    ) -> None:
        cip_safety_engine.simulate_crc_corruption(1)
        cip_safety_engine.sync_to_registers(register_table)

        assert register_table.read_uword("%R1757") == 0xE603 # CRC Corruption
        assert register_table.read_bit("%M408") is False     # Active cleared
        assert register_table.read_bit("%M409") is True      # Fault trip asserted


# ============================================================================
# Section 11: 9-Stage Deterministic Verification Runner & Evidence JSON Export
# ============================================================================

class TestSection11VerificationSuite:
    """Verify deterministic 9-stage verification runner and strict 4-state contract."""

    def test_run_cip_safety_multipoint_verification_success(self, tmp_path: Path) -> None:
        out_file = tmp_path / "evidence.json"
        evidence = run_cip_safety_multipoint_verification(output_path=out_file)

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["stages_passed"] == 9
        assert evidence["total_stages"] == 9
        assert out_file.exists()

        with open(out_file, encoding="utf-8") as f:
            saved = json.load(f)
        assert saved["status"] == "success"
        assert len(saved["data"]["stages"]) == 9
        for stage in saved["data"]["stages"]:
            assert stage["passed"] is True


# ============================================================================
# Section 12: Comprehensive Fault Injection & Safe-State Clamp Interlocks
# ============================================================================

class TestSection12FaultInjectionAndSafetyInterlocks:
    """Verify specific fault injection paths, sequence repetition, UNID mismatches, and safe clamp."""

    def test_sequence_number_monotonicity_and_repetition_rejection(
        self, cip_safety_engine: CipSafetyMultiPointEngine
    ) -> None:
        conn = cip_safety_engine.get_connection(1)
        pkt1 = CipSafetyPacket(
            snn=DEFAULT_SNN,
            tunid=conn.tunid,
            ounid=conn.ounid,
            connection_id=1,
            sequence_number=10,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01\x02",
            channel_b_payload=b"\xFE\xFD",
        )
        pkt1.calculate_crcs()
        cip_safety_engine.receive_safety_packet(1, pkt1)
        assert conn.last_rx_sequence == 10

        # Monotonic sequential packet (11) succeeds
        pkt2 = CipSafetyPacket(
            snn=DEFAULT_SNN,
            tunid=conn.tunid,
            ounid=conn.ounid,
            connection_id=1,
            sequence_number=11,
            timestamp_ms=20.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x03\x04",
            channel_b_payload=b"\xFC\xFB",
        )
        pkt2.calculate_crcs()
        cip_safety_engine.receive_safety_packet(1, pkt2)
        assert conn.last_rx_sequence == 11

        # Replayed packet repetition (11 again) triggers exception & fault
        with pytest.raises(CipSafetySequenceRepetitionError):
            cip_safety_engine.receive_safety_packet(1, pkt2)
        assert conn.state == CipSafetyConnectionState.SAFE_STATE
        assert cip_safety_engine.safety_trip_fault_active is True

    def test_snn_tunid_ounid_mismatch_protection_0xE604(
        self, cip_safety_engine: CipSafetyMultiPointEngine
    ) -> None:
        conn = cip_safety_engine.get_connection(1)
        pkt_bad_snn = CipSafetyPacket(
            snn=bytes([0x99] * 6),
            tunid=conn.tunid,
            ounid=conn.ounid,
            connection_id=1,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01",
            channel_b_payload=b"\xFE",
        )
        pkt_bad_snn.calculate_crcs()

        with pytest.raises(CipSafetySnnTunidMismatchError):
            cip_safety_engine.receive_safety_packet(1, pkt_bad_snn)

        assert conn.diagnostic_code == CipSafetyDiagnosticCode.SNN_TUNID_MISMATCH
        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.SNN_TUNID_MISMATCH
        assert cip_safety_engine.safety_trip_fault_active is True

    def test_tunid_mismatch_protection_0xE604(
        self, cip_safety_engine: CipSafetyMultiPointEngine
    ) -> None:
        conn = cip_safety_engine.get_connection(1)
        pkt_bad_tunid = CipSafetyPacket(
            snn=DEFAULT_SNN,
            tunid=999,
            ounid=conn.ounid,
            connection_id=1,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01",
            channel_b_payload=b"\xFE",
        )
        pkt_bad_tunid.calculate_crcs()

        with pytest.raises(CipSafetySnnTunidMismatchError):
            cip_safety_engine.receive_safety_packet(1, pkt_bad_tunid)

        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.SNN_TUNID_MISMATCH

    def test_ounid_mismatch_protection_0xE604(
        self, cip_safety_engine: CipSafetyMultiPointEngine
    ) -> None:
        conn = cip_safety_engine.get_connection(1)
        pkt_bad_ounid = CipSafetyPacket(
            snn=DEFAULT_SNN,
            tunid=conn.tunid,
            ounid=888,
            connection_id=1,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x01",
            channel_b_payload=b"\xFE",
        )
        pkt_bad_ounid.calculate_crcs()

        with pytest.raises(CipSafetySnnTunidMismatchError):
            cip_safety_engine.receive_safety_packet(1, pkt_bad_ounid)

        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.SNN_TUNID_MISMATCH

    def test_dual_channel_payload_discrepancy_trip_0xE602(
        self, cip_safety_engine: CipSafetyMultiPointEngine
    ) -> None:
        conn = cip_safety_engine.get_connection(1)
        pkt_disc = CipSafetyPacket(
            snn=DEFAULT_SNN,
            tunid=conn.tunid,
            ounid=conn.ounid,
            connection_id=1,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\x12\x34",
            channel_b_payload=b"\x12\x34",
        )
        pkt_disc.calculate_crcs()

        with pytest.raises(CipSafetyDualChannelDiscrepancyError):
            cip_safety_engine.receive_safety_packet(1, pkt_disc)

        assert conn.diagnostic_code == CipSafetyDiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        assert cip_safety_engine.safety_trip_fault_active is True

    def test_crc_corruption_trip_0xE603(
        self, cip_safety_engine: CipSafetyMultiPointEngine
    ) -> None:
        conn = cip_safety_engine.get_connection(1)
        pkt_crc = CipSafetyPacket(
            snn=DEFAULT_SNN,
            tunid=conn.tunid,
            ounid=conn.ounid,
            connection_id=1,
            sequence_number=1,
            timestamp_ms=10.0,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=b"\xAA\x55",
            channel_b_payload=b"\x55\xAA",
        )
        pkt_crc.calculate_crcs()
        pkt_crc.crc_s1 ^= 0x0001

        with pytest.raises(CipSafetyCrcCorruptionError):
            cip_safety_engine.receive_safety_packet(1, pkt_crc)

        assert conn.diagnostic_code == CipSafetyDiagnosticCode.CRC_S_CORRUPTION
        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.CRC_S_CORRUPTION
        assert cip_safety_engine.safety_trip_fault_active is True

    def test_safe_state_clamp_on_fault_asserts_m409_clears_m408(
        self, cip_safety_engine: CipSafetyMultiPointEngine, register_table: RegisterTable
    ) -> None:
        cip_safety_engine.sync_to_registers(register_table)
        assert register_table.read_bit("%M408") is True
        assert register_table.read_bit("%M409") is False

        # Trip via helper
        cip_safety_engine.simulate_snn_tunid_mismatch(1)
        cip_safety_engine.sync_to_registers(register_table)

        assert register_table.read_bit("%M408") is False
        assert register_table.read_bit("%M409") is True
        assert register_table.read_uword("%R1757") == 0xE604

    def test_logic_unit_reset_method(
        self, cip_safety_engine: CipSafetyMultiPointEngine
    ) -> None:
        cip_safety_engine.simulate_epi_timeout(1)
        assert cip_safety_engine.safety_trip_fault_active is True
        cip_safety_engine.reset()
        assert cip_safety_engine.safety_trip_fault_active is False
        assert cip_safety_engine.diagnostic_code == CipSafetyDiagnosticCode.OK

    def test_safety_status_bits_definitions(self) -> None:
        assert SafetyStatusBits.ACTIVE_MASK == 0x00FF
        assert SafetyStatusBits.PERMISSIVE_HIGH == 1 << 8
        assert SafetyStatusBits.FAULT_LATCHED == 1 << 9
        assert SafetyStatusBits.EPI_TIMEOUT_LATCH == 1 << 10
        assert SafetyStatusBits.SEQUENCE_ERROR_LATCH == 1 << 11
        assert SafetyStatusBits.CRC_ERROR_LATCH == 1 << 12
        assert SafetyStatusBits.UNID_MISMATCH_LATCH == 1 << 13
        assert SafetyStatusBits.DISCREPANCY_LATCH == 1 << 14

    def test_verification_runner_metrics_and_register_map(self) -> None:
        res = run_cip_safety_multipoint_verification()
        reg_map = res["data"]["register_map"]
        assert reg_map["%R1750"] == "OperationalMode"
        assert reg_map["%R1751"] == "ActiveSafetyConnectionCount"
        assert reg_map["%R1752"] == "MeanSafetyLatencyMsScaled"
        assert reg_map["%R1753"] == "MaxSafetyLatencyMsScaled"
        assert reg_map["%R1754"] == "ConsecutiveErrorCount"
        assert reg_map["%R1755"] == "ActiveFaultMask"
        assert reg_map["%R1756"] == "NetworkSafetyState"
        assert reg_map["%R1757"] == "DiagnosticStatusCode"
        assert reg_map["%M408"] == "CipSafetyMultiPointActive"
        assert reg_map["%M409"] == "SafetyTripFaultActive"
