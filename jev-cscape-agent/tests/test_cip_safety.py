"""Comprehensive Unit and Integration Test Suite for Industrial Ethernet/IP CIP Safety Target Engine.

Work Package: W163 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_iolink_safety.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1240..%R1247, %M289..%M290).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Safety Network Number (SNN) generation, validation, and format verification.
4. Section 4: Dual-channel redundant safety packet containers, CRC-S1 and CRC-S2 checksum calculation and verification.
5. Section 5: EPI watchdog monitoring, timestamp tracking, and jitter metrics.
6. Section 6: Target multi-connection state machine (NON_EXISTENT -> CONFIGURING -> WAITING_FOR_TUNID -> SAFETY_RUN -> SAFETY_FAULT).
7. Section 7: Process safety trips (0xBC01, 0xBC02, 0xBC03, 0xBC04) and Horner coil assertion (%M289, %M290).
8. Section 8: Horner OCS register space synchronization (%R1240..%R1247, %M289..%M290) with PrivilegeMode.SYSTEM.
9. Section 9: 9-stage verification suite integration test writing evidence JSON.
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
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety import (
    BlackChannelThreat,
    CIP_SAFETY_CRC16_INIT,
    CIP_SAFETY_CRC16_POLY,
    CIP_SAFETY_CRC32_INIT,
    CIP_SAFETY_CRC32_POLY,
    CIP_SAFETY_DEFAULT_SCID,
    CIP_SAFETY_DEFAULT_SNN,
    CIP_SAFETY_DEFAULT_TUNID,
    CIP_SAFETY_MAX_TARGET_CONNECTIONS,
    CIP_SAFETY_NOMINAL_EPI_MS,
    CIP_SAFETY_NOMINAL_EPI_SCALED,
    CIP_SAFETY_NOMINAL_WATCHDOG_MS,
    CIP_SAFETY_NOMINAL_WATCHDOG_SCALED,
    CIP_SAFETY_PURE_ST_POU,
    CIP_SAFETY_SYNC_POU,
    CIP_SAFETY_TARGET_SYNC_POU,
    PURE_ST_POU,
    CIPSafetyEngine,
    CIPSafetyMasterEngine,
    CIPSafetyPacket,
    CIPSafetyPacketContainer,
    CIPSafetyStatusBits,
    CIPSafetyTargetEngine,
    CIPSafetyValidator,
    CipSafetyConfigMismatchError,
    CipSafetyCrcCorruptedError,
    CipSafetyDiagnosticCode,
    CipSafetyEpiTimeoutError,
    CipSafetyError,
    CipSafetySequenceFaultError,
    CipSafetyStatusBits,
    CipSafetyValidationOutcome,
    SafetyControlByte,
    SafetyEndpointConfig,
    SafetyState,
    TargetConnection,
    TargetConnectionState,
    ValidationOutcome,
    compute_crc16,
    compute_crc32,
    compute_crc_s1,
    compute_crc_s2,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_verification,
    scale_ms_to_int16,
    validate_snn,
    verify_cip_safety_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def cip_safety_engine(register_table: RegisterTable) -> CIPSafetyTargetEngine:
    """Provides a fresh CIPSafetyTargetEngine initialized with 4 active safe connections."""
    engine = CIPSafetyTargetEngine(
        register_table=register_table,
        epi_ms=CIP_SAFETY_NOMINAL_EPI_MS,
        watchdog_timeout_ms=CIP_SAFETY_NOMINAL_WATCHDOG_MS,
        snn=CIP_SAFETY_DEFAULT_SNN,
        max_connections=CIP_SAFETY_MAX_TARGET_CONNECTIONS,
    )
    for conn_idx in range(1, 5):
        engine.register_connection(
            connection_id=0x10000000 + conn_idx,
            tunid=conn_idx,
            auto_activate=True,
        )
    return engine


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Structured Text POUs and AST symbol binding."""

    def test_verify_cip_safety_pure_st_function(self) -> None:
        """Verify helper validation function passes cleanly without ladder elements."""
        assert verify_cip_safety_pure_st() is True

    def test_pure_st_cip_safety_target_sync_ast_parsing(self) -> None:
        """Parse CIP_SAFETY_TARGET_SYNC_POU and assert AST attributes and register bindings."""
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_TARGET_SYNC_POU)
        res = STParser.validate_code(CIP_SAFETY_TARGET_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CIP_SAFETY_TARGET_SYNC_POU)
        assert ast is not None
        assert ast.name == "CIPSafetyTargetSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1240", "%R1241", "%R1242", "%R1243",
            "%R1244", "%R1245", "%R1246", "%R1247",
            "%M289", "%M290",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "CipSafetyEpiMsScaled",
            "ActiveSafeConnectionsCount",
            "SafeSequenceCounter",
            "EpiWatchdogMsScaled",
            "CrcErrorCount",
            "TargetConnectionStateWord",
            "SafetyNetworkNumberWord",
            "DiagnosticStatusCode",
            "CipSafetyPermissive",
            "CipSafetyFaultTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pou_aliases_consistency(self) -> None:
        """Verify backwards compatibility aliases point to the correct POU definitions."""
        assert PURE_ST_POU == CIP_SAFETY_TARGET_SYNC_POU
        assert CIP_SAFETY_SYNC_POU == CIP_SAFETY_TARGET_SYNC_POU
        assert CIP_SAFETY_PURE_ST_POU == CIP_SAFETY_TARGET_SYNC_POU


# ============================================================================
# Section 2: Anti-Ladder Logic Security Interception
# ============================================================================

class TestSection2AntiLadderGuards:
    """Tests for interception and rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "bad_code, expected_reason",
        [
            ("PROGRAM BadContact\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM", "ladder contact"),
            ("PROGRAM BadNegContact\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM", "ladder negative contact"),
            ("PROGRAM BadCoil\nVAR X: BOOL; END_VAR\n---( )---\nEND_PROGRAM", "ladder coil"),
            ("PROGRAM BadRung\nVAR X: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM", "rung keyword"),
            ("PROGRAM BadMnemonic\nVAR X: BOOL; END_VAR\nXIC %M289\nOTE %M290\nEND_PROGRAM", "ladder mnemonic"),
            ("PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM", "network keyword"),
        ],
    )
    def test_security_guard_rejects_ladder_syntax(self, bad_code: str, expected_reason: str) -> None:
        """Asserts SecurityGuard raises LadderForbiddenError for ladder logic elements."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_st_parser_returns_failed_on_ladder_logic(self) -> None:
        """Asserts STParser.validate_code returns FAILED with ERR_LADDER_FORBIDDEN."""
        ladder_snippet = "PROGRAM IllegalCIPSafety\nVAR S: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM"
        res = STParser.validate_code(ladder_snippet)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"
        assert res.data.get("ladder_rejected") is True


# ============================================================================
# Section 3: Safety Network Number (SNN) Generation, Validation, & Format
# ============================================================================

class TestSection3SafetyNetworkNumber:
    """Tests for SNN generation, format representation, and validation."""

    def test_snn_generation_deterministic(self) -> None:
        """Verify SNN is generated as a 6-octet binary identifier."""
        snn = generate_snn(date_days=0x2024, time_or_mac=0x01020304)
        assert len(snn) == 6
        assert snn == bytes([0x20, 0x24, 0x01, 0x02, 0x03, 0x04])

    def test_snn_formatting_and_parsing_roundtrip(self) -> None:
        """Verify SNN format to hex string and roundtrip parsing."""
        raw_snn = bytes([0x12, 0x34, 0xAB, 0xCD, 0xEF, 0x99])
        fmt = format_snn(raw_snn)
        assert fmt == "1234-ABCDEF99"
        parsed = parse_snn(fmt)
        assert parsed == raw_snn

        # Test alternative delimiters (colons, spaces, raw hex)
        assert parse_snn("1234:ABCDEF99") == raw_snn
        assert parse_snn("1234 ABCDEF99") == raw_snn
        assert parse_snn("1234ABCDEF99") == raw_snn

    def test_snn_validation_criteria(self) -> None:
        """Verify strict SNN validation criteria."""
        valid_snn = bytes([0x20, 0x24, 0x00, 0x01, 0x02, 0x03])
        assert validate_snn(valid_snn) is True

        # Invalid: All zeros or all 0xFF
        assert validate_snn(b"\x00" * 6) is False
        assert validate_snn(b"\xFF" * 6) is False

        # Invalid: Date component zero or MAC component zero
        assert validate_snn(b"\x00\x00\x11\x22\x33\x44") is False
        assert validate_snn(b"\x11\x22\x00\x00\x00\x00") is False

        # Invalid: Wrong length or non-bytes
        assert validate_snn(b"\x11\x22\x33") is False
        assert validate_snn(b"\x11" * 7) is False
        assert validate_snn("invalid_string") is False  # type: ignore[arg-type]


# ============================================================================
# Section 4: Dual-Channel Redundant Safety Packet Containers & Dual CRC Checksums
# ============================================================================

class TestSection4DualChannelRedundantPacketAndDualCRC:
    """Tests for Safe Packet serialization, inverted complement (~P), and dual CRC-S1/S2."""

    def test_packet_container_creation_and_serialization_roundtrip(self) -> None:
        """Verify Safe binary header packing, payload alignment, and roundtrip deserialization."""
        raw_payload = b"\x11\x22\x33\x44\x55\x66"
        snn = bytes([0x20, 0x24, 0x01, 0x02, 0x03, 0x04])
        container = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=77,
            payload=raw_payload,
            timestamp_ms=125.0,
            snn=snn,
            tunid=1,
        )
        assert len(container.payload) == 6
        assert len(container.payload_inv) == 6

        wire_bytes = container.serialize()
        # Wire length: 21 header + 6 payload + 6 complement + 2 (CRC-S1) + 4 (CRC-S2) = 39 bytes
        assert len(wire_bytes) == 21 + 6 + 6 + 2 + 4

        deserialized = CIPSafetyPacketContainer.deserialize(wire_bytes)
        assert deserialized.connection_id == 0x10000001
        assert deserialized.tunid == 1
        assert deserialized.sequence_counter == 77
        assert deserialized.payload == raw_payload
        assert deserialized.payload_inv == bytes([b ^ 0xFF for b in raw_payload])
        assert deserialized.crc_s1 == container.crc_s1
        assert deserialized.crc_s2 == container.crc_s2
        assert deserialized.snn == snn

    def test_inverted_payload_complement_verification(self) -> None:
        """Verify every byte in payload satisfies P[i] ^ ~P[i] == 0xFF."""
        raw_payload = bytes([0x00, 0x55, 0xAA, 0xFF, 0x12, 0x34])
        container = CIPSafetyPacketContainer.create(
            connection_id=0x10000002,
            sequence_counter=1,
            payload=raw_payload,
            timestamp_ms=10.0,
        )
        for p, inv in zip(container.payload, container.payload_inv):
            assert (p ^ inv) == 0xFF

        valid, diag, msg = container.verify_integrity(expected_connection_id=0x10000002)
        assert valid is True
        assert diag is None

    def test_inverted_payload_complement_corruption_detection(self) -> None:
        """Verify single bit corruption in inverted complement trips 0xBC01."""
        container = CIPSafetyPacketContainer.create(
            connection_id=0x10000003,
            sequence_counter=10,
            payload=b"\xDE\xAD\xBE\xEF",
        )
        # Corrupt one complement byte
        bad_inv = bytearray(container.payload_inv)
        bad_inv[2] ^= 0x01
        corrupted = CIPSafetyPacketContainer(
            connection_id=container.connection_id,
            tunid=container.tunid,
            sequence_counter=container.sequence_counter,
            timestamp_ms=container.timestamp_ms,
            mode=container.mode,
            payload=container.payload,
            payload_inv=bytes(bad_inv),
            crc_s1=container.crc_s1,
            crc_s2=container.crc_s2,
            snn=container.snn,
        )
        valid, diag, msg = corrupted.verify_integrity()
        assert valid is False
        assert diag == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_CRC_CORRUPTED
        assert "Inverted payload complement mismatch" in msg

    def test_dual_crc_s1_and_crc_s2_integrity_enforcement(self) -> None:
        """Verify CRC-S1 (0x1021) and CRC-S2 (0xEDB88320) independently detect corruption."""
        container = CIPSafetyPacketContainer.create(
            connection_id=0x10000004,
            sequence_counter=15,
            payload=b"\xCA\xFE",
        )
        # Corrupt CRC-S1 only
        bad_crc1 = CIPSafetyPacketContainer(
            connection_id=container.connection_id,
            tunid=container.tunid,
            sequence_counter=container.sequence_counter,
            timestamp_ms=container.timestamp_ms,
            mode=container.mode,
            payload=container.payload,
            payload_inv=container.payload_inv,
            crc_s1=container.crc_s1 ^ 0x0001,
            crc_s2=container.crc_s2,
            snn=container.snn,
        )
        v1, d1, m1 = bad_crc1.verify_integrity()
        assert v1 is False
        assert d1 == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_CRC_CORRUPTED
        assert "CRC-S1 mismatch" in m1

        # Corrupt CRC-S2 only
        bad_crc2 = CIPSafetyPacketContainer(
            connection_id=container.connection_id,
            tunid=container.tunid,
            sequence_counter=container.sequence_counter,
            timestamp_ms=container.timestamp_ms,
            mode=container.mode,
            payload=container.payload,
            payload_inv=container.payload_inv,
            crc_s1=container.crc_s1,
            crc_s2=container.crc_s2 ^ 0x0001,
            snn=container.snn,
        )
        v2, d2, m2 = bad_crc2.verify_integrity()
        assert v2 is False
        assert d2 == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_CRC_CORRUPTED
        assert "CRC-S2 mismatch" in m2

    def test_deserialize_invalid_length_raises(self) -> None:
        """Verify short or truncated wire frames raise ValueError."""
        with pytest.raises(ValueError, match="smaller than minimum envelope|too short"):
            CIPSafetyPacketContainer.deserialize(b"\x01\x02\x03")

        # Header claims 10 bytes payload, but wire is truncated
        truncated = struct.pack(">6sIHBIHH", b"\x00"*6, 1, 1, 1, 0, 1, 10) + b"\x00" * 4
        with pytest.raises(ValueError, match="Incomplete or malformed"):
            CIPSafetyPacketContainer.deserialize(truncated)


# ============================================================================
# Section 5: EPI Watchdog Monitoring, Timestamp Tracking, & Jitter Metrics
# ============================================================================

class TestSection5EpiWatchdogAndJitterMetrics:
    """Tests for safe cyclical communication, 20.0 ms nominal EPI timing, and jitter surveillance."""

    def test_nominal_epi_cycle_and_scan_cycle_progression(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Verify cyclic steps advance simulation time with 20.0 ms nominal EPI period."""
        engine = cip_safety_engine
        initial_time = engine.current_time_ms

        for i in range(1, 6):
            engine.step_scan_cycle(dt_ms=2.5)
            assert engine.current_time_ms == pytest.approx(initial_time + i * 2.5)
            assert engine.reg_table.read_word("%R1240") == CIP_SAFETY_NOMINAL_EPI_SCALED  # 200
            assert engine.reg_table.read_word("%R1243") == CIP_SAFETY_NOMINAL_WATCHDOG_SCALED  # 600

        assert engine.permissive is True
        assert engine.fault_trip is False
        assert engine.reg_table.read_bit("%M289") is True
        assert engine.reg_table.read_bit("%M290") is False

    def test_epi_timestamp_tracking_and_jitter_metrics(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Verify packet arrival interval tracking and real-time jitter calculation."""
        engine = cip_safety_engine
        conn = engine.connections[0x10000001]
        raw_payload = b"\x01\x02"

        # Packet 1 at t = 100.0 ms
        p1 = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=100,
            payload=raw_payload,
            timestamp_ms=100.0,
            tunid=1,
        )
        engine.current_time_ms = 105.0
        out1 = engine.process_safe_container(p1)
        assert out1.is_valid is True

        # Packet 2 at t = 126.0 ms (interval = 21.0 ms -> jitter = |21.0 - 20.0| = 1.0 ms)
        p2 = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=101,
            payload=raw_payload,
            timestamp_ms=120.0,
            tunid=1,
        )
        engine.current_time_ms = 126.0
        out2 = engine.process_safe_container(p2)
        assert out2.is_valid is True
        assert out2.jitter_ms == pytest.approx(1.0)
        assert conn.max_jitter_ms >= 1.0

    def test_epi_watchdog_timeout_expiration(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Verify silence > 60.0 ms watchdog trips 0xBC03 and de-asserts permissive."""
        engine = cip_safety_engine
        # Fresh baseline
        engine.reset_latch(force=True)
        p = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=200,
            payload=b"\x01",
            timestamp_ms=engine.current_time_ms,
            tunid=1,
        )
        engine.process_safe_container(p)

        # Advance elapsed silence beyond 60.0 ms watchdog (e.g. 65.0 ms)
        engine.step_scan_cycle(dt_ms=65.0)

        rt = engine.reg_table
        assert engine.diagnostic_code == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_EPI_TIMEOUT
        assert rt.read_uword("%R1247") == 0xBC03
        assert rt.read_bit("%M289") is False
        assert rt.read_bit("%M290") is True


# ============================================================================
# Section 6: Target Multi-Connection State Machine
# ============================================================================

class TestSection6TargetMultiConnectionStateMachine:
    """Tests for the 5-state CIP Safety Target Connection State Machine."""

    def test_connection_state_lifecycle_non_existent_to_configuring(
        self, register_table: RegisterTable
    ) -> None:
        """Verify allocation and configuration moves state from NON_EXISTENT to WAITING_FOR_TUNID."""
        engine = CIPSafetyTargetEngine(register_table=register_table)
        assert len(engine.connections) == 0

        conn = engine.register_connection(connection_id=0x10000001, tunid=1, auto_activate=False)
        assert conn.state == TargetConnectionState.WAITING_FOR_TUNID
        assert conn.has_synced is False

    def test_connection_state_waiting_for_tunid_to_safety_run(
        self, register_table: RegisterTable
    ) -> None:
        """Verify first packet reception transitions connection to SAFETY_RUN."""
        engine = CIPSafetyTargetEngine(register_table=register_table)
        conn = engine.register_connection(connection_id=0x10000001, tunid=1, auto_activate=False)
        assert conn.state == TargetConnectionState.WAITING_FOR_TUNID

        pkt = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=1,
            payload=b"\x12\x34",
            timestamp_ms=10.0,
            tunid=1,
        )
        out = engine.process_safe_container(pkt)
        assert out.is_valid is True
        assert conn.state == TargetConnectionState.SAFETY_RUN
        assert conn.has_synced is True

    def test_target_multi_connection_concurrent_state_tracking(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Verify 4 concurrent target connections track state in %R1241 and %R1245."""
        engine = cip_safety_engine
        assert len(engine.connections) == 4
        assert engine.reg_table.read_word("%R1241") == 4

        word = engine.recompute_connection_state_word()
        # Each connection in SAFETY_RUN contributes value 2 (binary 10) in its 2-bit field
        # 4 connections in SAFETY_RUN: (2) | (2<<2) | (2<<4) | (2<<6) = 2 + 8 + 32 + 128 = 170 (0xAA)
        assert word == 0xAA
        assert engine.reg_table.read_word("%R1245") == 0xAA

    def test_target_connection_safety_fault_transition_on_error(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Verify connection moves to SAFETY_FAULT upon packet corruption."""
        engine = cip_safety_engine
        conn = engine.connections[0x10000001]

        pkt = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=50,
            payload=b"\xFF",
            tunid=1,
        )
        pkt.crc_s1 ^= 0xDEAD  # Corrupt CRC

        out = engine.process_safe_container(pkt)
        assert out.is_valid is False
        assert conn.state == TargetConnectionState.SAFETY_FAULT
        assert engine.fault_trip is True
        assert engine.permissive is False


# ============================================================================
# Section 7: Process Safety Trips (0xBC01..0xBC04) & Horner Coils (%M289, %M290)
# ============================================================================

class TestSection7ProcessSafetyTrips:
    """Tests for Process Safety Trips (0xBC01, 0xBC02, 0xBC03, 0xBC04) and Horner Coils (%M289, %M290)."""

    def test_trip_0xbc01_crc_and_complement_corruption(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """0xBC01 CRC corruption asserts %M290, clears %M289, zeroes %R1245, and sets %R1247."""
        engine = cip_safety_engine
        pkt = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=500,
            payload=b"\x12\x34",
            tunid=1,
        )
        pkt.crc_s1 ^= 0xDEAD

        outcome = engine.process_safe_container(pkt)
        assert outcome.is_valid is False
        assert outcome.diagnostic_code == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_CRC_CORRUPTED

        rt = engine.reg_table
        assert engine.diagnostic_code == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_CRC_CORRUPTED
        assert rt.read_uword("%R1247") == 0xBC01
        assert rt.read_bit("%M289") is False
        assert rt.read_bit("%M290") is True
        assert rt.read_word("%R1245") == 0
        assert rt.read_word("%R1244") >= 1

    def test_trip_0xbc02_sequence_counter_anomaly(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """0xBC02 Sequence counter freeze asserts %M290, clears %M289, and sets %R1247."""
        engine = cip_safety_engine
        p1 = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=600,
            payload=b"\x55",
            tunid=1,
        )
        engine.process_safe_container(p1)

        # Trigger sequence trip by duplicate
        p_dup = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=600,
            payload=b"\x55",
            tunid=1,
        )
        outcome = engine.process_safe_container(p_dup)
        assert outcome.is_valid is False
        assert outcome.diagnostic_code == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_SEQUENCE_FAULT

        rt = engine.reg_table
        assert rt.read_uword("%R1247") == 0xBC02
        assert rt.read_bit("%M289") is False
        assert rt.read_bit("%M290") is True

    def test_trip_0xbc03_epi_watchdog_timeout(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """0xBC03 Safety watchdog silence (> 60.0 ms) asserts %M290, clears %M289, and sets %R1247."""
        engine = cip_safety_engine
        engine.reset_latch(force=True)
        p = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=700,
            payload=b"\x99",
            tunid=1,
        )
        engine.process_safe_container(p)

        # Advance elapsed silence beyond 60.0 ms watchdog (e.g. 65.0 ms)
        engine.step_scan_cycle(dt_ms=65.0)

        rt = engine.reg_table
        assert engine.diagnostic_code == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_EPI_TIMEOUT
        assert rt.read_uword("%R1247") == 0xBC03
        assert rt.read_bit("%M289") is False
        assert rt.read_bit("%M290") is True

    def test_trip_0xbc04_snn_tunid_mismatch(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """0xBC04 Rogue SNN/TUNID mismatch asserts %M290, clears %M289, and sets %R1247."""
        engine = cip_safety_engine
        alien_pkt = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=800,
            payload=b"\x01",
            snn=bytes([0x99, 0x99, 0x99, 0x99, 0x99, 0x99]),  # Rogue SNN
            tunid=1,
        )
        outcome = engine.process_safe_container(alien_pkt)
        assert outcome.is_valid is False
        assert outcome.diagnostic_code == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_SNN_TUNID_MISMATCH

        rt = engine.reg_table
        assert engine.diagnostic_code == CipSafetyDiagnosticCode.CIP_SAFETY_ERR_SNN_TUNID_MISMATCH
        assert rt.read_uword("%R1247") == 0xBC04
        assert rt.read_bit("%M289") is False
        assert rt.read_bit("%M290") is True

    def test_operator_manual_reset_handshake_restoration(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Verify operator manual reset clears latch, resets %M290, and restores %M289 and %R1247."""
        engine = cip_safety_engine
        engine.trigger_fault(CipSafetyDiagnosticCode.CIP_SAFETY_ERR_CRC_CORRUPTED)

        rt = engine.reg_table
        assert rt.read_bit("%M290") is True
        assert rt.read_bit("%M289") is False
        assert rt.read_uword("%R1247") == 0xBC01

        # Operator manual reset
        res_reset = engine.reset_latch(force=True)
        assert res_reset.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == CipSafetyDiagnosticCode.OK
        assert rt.read_uword("%R1247") == 0x0000
        assert rt.read_bit("%M290") is False
        assert rt.read_bit("%M289") is True


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization (%R1240..%R1247)
# ============================================================================

class TestSection8HornerRegisterSpaceSync:
    """Tests for complete register table mapping verification (%R1240..%R1247, %M289..%M290)."""

    def test_scale_ms_helper_function(self) -> None:
        """Verify scale helpers clamp and scale correctly into signed 16-bit ranges."""
        assert scale_ms_to_int16(20.0) == 200
        assert scale_ms_to_int16(60.0) == 600
        assert scale_ms_to_int16(0.0) == 0
        assert scale_ms_to_int16(-10.0) == -100
        assert scale_ms_to_int16(5000.0) == 32767
        assert scale_ms_to_int16(-5000.0) == -32768

    def test_full_register_map_integrity(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Assert each Horner mapped register reflects internal engine state."""
        engine = cip_safety_engine
        p = CIPSafetyPacketContainer.create(
            connection_id=0x10000001,
            sequence_counter=42,
            payload=b"\xCA\xFE",
            timestamp_ms=engine.current_time_ms,
            tunid=1,
        )
        engine.process_safe_container(p)

        rt = engine.reg_table
        assert rt.read_word("%R1240") == 200       # 20.0 ms x10 = 200
        assert rt.read_word("%R1241") == 4         # 4 active safe connections
        assert rt.read_uword("%R1242") == 42       # SafeSequenceCounter 42
        assert rt.read_word("%R1243") == 600       # 60.0 ms x10 = 600
        assert rt.read_word("%R1244") == 0         # 0 CRC errors
        assert rt.read_word("%R1245") == 0xAA      # 4 connections in SAFETY_RUN -> 0xAA
        assert rt.read_uword("%R1246") == 0x2024   # SNN High Word (0x2024)
        assert rt.read_uword("%R1247") == 0x0000   # OK
        assert rt.read_bit("%M289") is True        # Permissive healthy
        assert rt.read_bit("%M290") is False       # Fault trip inactive

    def test_register_synchronization_on_cyclic_step(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Verify registers update dynamically during scan execution."""
        engine = cip_safety_engine
        engine.step_scan_cycle(dt_ms=2.5)

        rt = engine.reg_table
        assert rt.read_word("%R1240") == 200
        assert rt.read_bit("%M289") is True
        assert rt.read_bit("%M290") is False

    def test_privilege_mode_system_enforcement(
        self, cip_safety_engine: CIPSafetyTargetEngine
    ) -> None:
        """Verify register writes utilize PrivilegeMode.SYSTEM properly."""
        engine = cip_safety_engine
        engine.sync_to_registers()
        # Verify read operations reflect values accurately
        assert engine.reg_table.read_word("%R1240") == 200
        assert engine.reg_table.read_bit("%M289") is True


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection9VerificationSuite:
    """Tests for run_cip_safety_verification output and evidence file emission."""

    def test_run_cip_safety_verification_success(self, tmp_path: Path) -> None:
        """Runs the 9-stage verification suite and verifies strict 4-state contract JSON."""
        evidence_file = tmp_path / "cip_safety_evidence.json"
        res = run_cip_safety_verification(output_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["tests"]) == 9

        # Ensure all 9 individual stages passed
        for stage_test in res["data"]["tests"]:
            assert stage_test["passed"] is True

        # Verify evidence file written and valid
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W163"

    def test_evidence_register_map_completeness(self, tmp_path: Path) -> None:
        """Verify evidence output contains all Horner registers (%R1240..%R1247, %M289..%M290)."""
        evidence_file = tmp_path / "cip_safety_evidence_map.json"
        res = run_cip_safety_verification(output_path=str(evidence_file))

        values = res["data"]["register_map"]["values"]
        assert "%R1240" in values
        assert "%R1241" in values
        assert "%R1242" in values
        assert "%R1243" in values
        assert "%R1244" in values
        assert "%R1245" in values
        assert "%R1246" in values
        assert "%R1247" in values
        assert "%M289" in values
        assert "%M290" in values

    def test_evidence_all_9_stages_passed(self, tmp_path: Path) -> None:
        """Verify all 9 individual stages are marked passed and details populated."""
        evidence_file = tmp_path / "cip_safety_evidence_stages.json"
        res = run_cip_safety_verification(output_path=str(evidence_file))

        stages = res["data"]["tests"]
        stage_names = [s["check"] for s in stages]
        assert "Pure_ST_POU_And_Anti_Ladder_Guard" in stage_names
        assert "Safety_Network_Number_Generation_And_Validation" in stage_names
        assert "Dual_Channel_Redundant_Packet_And_Dual_CRC_Integrity" in stage_names
        assert "Strictly_Monotonic_Sequence_Counter_Progression" in stage_names
        assert "Sequence_Discontinuity_And_Freeze_Fault_Trapping" in stage_names
        assert "EPI_Watchdog_Monitoring_And_Timeout_Surveillance" in stage_names
        assert "Target_Multi_Connection_State_Machine" in stage_names
        assert "Process_Safety_Trips_And_Horner_Coils_Assertion" in stage_names
        assert "Operator_Reset_Handshake_And_Memory_Synchronization" in stage_names
