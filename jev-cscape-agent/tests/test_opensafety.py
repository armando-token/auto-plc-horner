"""Comprehensive Unit and Integration Test Suite for Industrial OpenSAFETY Over Black Channel Transport Engine.

Work Package: W151 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_powerlink_mn.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1120..%R1127, %M261..%M262).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: OpenSAFETY frame structure, dual subframe inverted payloads (P and ~P), and dual CRC-16 checks.
4. Section 4: Monotonic sequence tracking, frame loss/duplication/reordering detection, and timeout watchdog.
5. Section 5: Black channel transport simulation with injected noise and latency tracking.
6. Section 6: Process safety trips (0xB001, 0xB002, 0xB003, 0xB004) and Horner coil assertion (%M261, %M262).
7. Section 7: Horner OCS register space synchronization (%R1120..%R1127, %M261..%M262).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
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
from jev_cscape.telemetry.opensafety import (
    OPENSAFETY_BROADCAST_SNN,
    OPENSAFETY_CCITT_INIT,
    OPENSAFETY_CCITT_POLY,
    OPENSAFETY_CRC16_INIT,
    OPENSAFETY_CRC16_POLY,
    OPENSAFETY_DEFAULT_DOMAIN_ID,
    OPENSAFETY_DEFAULT_MAX_LATENCY_US,
    OPENSAFETY_DEFAULT_WATCHDOG_US,
    OPENSAFETY_JITTER_ALLOWANCE_US,
    OPENSAFETY_MAGIC_HEADER,
    OPENSAFETY_MAX_SAFETY_NODES,
    OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU,
    OPEN_SAFETY_SYNC_POU,
    OPENSAFETY_BLACK_CHANNEL_SYNC_POU,
    OPENSAFETY_PURE_ST_POU,
    OPENSAFETY_SYNC_POU,
    PURE_ST_POU,
    BlackChannelTransport,
    OpenSafetyBlackChannelEngine,
    OpenSafetyDiagnosticCode,
    OpenSafetyEngine,
    OpenSafetyError,
    OpenSafetyFrame,
    OpenSafetyFrameType,
    OpenSafetyNode,
    OpenSafetyState,
    OpenSafetyStatusBits,
    OpenSafetySubframe,
    OpenSafetyTimeoutError,
    OpenSafetyTransportEngine,
    OpenSafetyValidationOutcome,
    compute_crc16_ccitt,
    compute_opensafety_crc16,
    run_opensafety_verification,
    scale_safety_pv_to_int16,
    verify_opensafety_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def opensafety_engine(register_table: RegisterTable) -> OpenSafetyTransportEngine:
    """Provides a fresh OpenSafetyTransportEngine with 4 configured Safety Nodes."""
    engine = OpenSafetyTransportEngine(
        domain_id=OPENSAFETY_DEFAULT_DOMAIN_ID,
        register_table=register_table,
        max_tolerable_latency_us=OPENSAFETY_DEFAULT_MAX_LATENCY_US,
        watchdog_timeout_us=OPENSAFETY_DEFAULT_WATCHDOG_US,
        jitter_allowance_us=OPENSAFETY_JITTER_ALLOWANCE_US,
        initial_time_us=1000,
    )
    for i in range(1, 5):
        engine.configure_safety_node(snn=i, name=f"SafetySensor_{i}")
    return engine


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Structured Text POUs and AST symbol binding."""

    def test_verify_opensafety_pure_st_function(self) -> None:
        """Verify helper validation function passes cleanly."""
        assert verify_opensafety_pure_st() is True

    def test_pure_st_opensafety_sync_ast_parsing(self) -> None:
        """Parse OPEN_SAFETY_SYNC_POU and assert AST attributes and register bindings."""
        SecurityGuard.assert_pure_st_content(OPEN_SAFETY_SYNC_POU)
        res = STParser.validate_code(OPEN_SAFETY_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(OPEN_SAFETY_SYNC_POU)
        assert ast is not None
        assert ast.name == "OpenSafetySync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1120", "%R1121", "%R1122", "%R1123",
            "%R1124", "%R1125", "%R1126", "%R1127",
            "%M261", "%M262",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "SafetyDomainNumber",
            "ActiveSafetyNodesCount",
            "SafetyCycleCounter",
            "ConsecutiveCrcErrors",
            "PrimarySafetyWordScaled",
            "SecondarySafetyWordScaled",
            "BlackChannelTransportLatencyUs",
            "DiagnosticStatusCode",
            "OpenSafetyPermissive",
            "BlackChannelIntegrityTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_opensafety_black_channel_sync_ast_parsing(self) -> None:
        """Parse OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU)
        res = STParser.validate_code(OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU)
        assert ast is not None
        assert ast.name == "OpenSafetyBlackChannelSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1120", "%R1121", "%R1122", "%R1123",
            "%R1124", "%R1125", "%R1126", "%R1127",
            "%M261", "%M262",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_pou_aliases_consistency(self) -> None:
        """Verify backwards compatibility aliases point to the correct POU definitions."""
        assert OPENSAFETY_SYNC_POU == OPEN_SAFETY_SYNC_POU
        assert OPENSAFETY_BLACK_CHANNEL_SYNC_POU == OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU
        assert OPENSAFETY_PURE_ST_POU == OPEN_SAFETY_SYNC_POU
        assert PURE_ST_POU == OPEN_SAFETY_SYNC_POU


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
            ("PROGRAM BadMnemonic\nVAR X: BOOL; END_VAR\nXIC %M261\nOTE %M262\nEND_PROGRAM", "ladder mnemonic"),
            ("PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM", "network keyword"),
        ],
    )
    def test_security_guard_rejects_ladder_syntax(self, bad_code: str, expected_reason: str) -> None:
        """Asserts SecurityGuard raises LadderForbiddenError for ladder logic elements."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_st_parser_returns_failed_on_ladder_logic(self) -> None:
        """Asserts STParser.validate_code returns FAILED with ERR_LADDER_FORBIDDEN."""
        ladder_snippet = "PROGRAM Illegal\nVAR S: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM"
        res = STParser.validate_code(ladder_snippet)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"
        assert res.data.get("ladder_rejected") is True


# ============================================================================
# Section 3: OpenSAFETY Frame Structure, Dual Subframes, & Dual CRC-16 Checks
# ============================================================================

class TestSection3OpenSafetyFrameCodec:
    """Tests for OpenSAFETY frame serialization, dual subframes (P and ~P), and dual CRC-16."""

    def test_crc16_algorithms_determinism(self) -> None:
        """Verify OpenSAFETY CRC-16 (poly 0x5935) and CCITT-16 (poly 0x1021) checksums."""
        sample_data = b"OpenSAFETY_BlackChannel_Payload_Verification_12345678"
        crc1 = compute_opensafety_crc16(sample_data)
        crc2 = compute_crc16_ccitt(sample_data)

        assert 0 <= crc1 <= 0xFFFF
        assert 0 <= crc2 <= 0xFFFF
        assert crc1 != crc2  # Distinct generator polynomials
        # Verify deterministic idempotence
        assert compute_opensafety_crc16(sample_data) == crc1
        assert compute_crc16_ccitt(sample_data) == crc2

    def test_subframe_serialization_and_deserialization(self) -> None:
        """Verify OpenSafetySubframe serialization and exact field reconstruction."""
        payload = b"\x12\x34\x56\x78"
        sf = OpenSafetySubframe(
            sdn=OPENSAFETY_DEFAULT_DOMAIN_ID,
            snn=2,
            seq_num=42,
            frame_type=int(OpenSafetyFrameType.SPDO),
            timestamp_us=125_000,
            payload=payload,
            crc16=0,
        )
        sf.crc16 = sf.compute_expected_crc()
        raw = sf.serialize()

        assert len(raw) == OpenSafetySubframe.HEADER_SIZE + len(payload) + 2
        deser = OpenSafetySubframe.deserialize(raw)

        assert deser.sdn == OPENSAFETY_DEFAULT_DOMAIN_ID
        assert deser.snn == 2
        assert deser.seq_num == 42
        assert deser.frame_type == int(OpenSafetyFrameType.SPDO)
        assert deser.timestamp_us == 125_000
        assert deser.payload == payload
        assert deser.crc16 == sf.crc16

    def test_dual_subframe_inverted_payload_complement_invariant(
        self, opensafety_engine: OpenSafetyTransportEngine
    ) -> None:
        """Verify dual subframes contain complementary inverted payloads (P[i] ^ ~P[i] == 0xFF)."""
        payload_p = struct.pack(">hh", 320, -150)  # 32.0 V, -15.0 V
        frame = opensafety_engine.encode_safety_frame(snn=1, payload=payload_p, timestamp_us=2000)

        assert frame.subframe1.payload == payload_p
        payload_inv = frame.subframe2.payload
        assert len(payload_p) == len(payload_inv)

        # Strict bitwise complementary check
        for b1, b2 in zip(payload_p, payload_inv):
            assert (b1 ^ b2) == 0xFF

    def test_dual_crc16_independence(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """Verify Subframe 1 and Subframe 2 have independently valid CRC-16 checksums."""
        payload_p = struct.pack(">h", 450)
        frame = opensafety_engine.encode_safety_frame(snn=1, payload=payload_p, timestamp_us=2500)

        assert frame.subframe1.crc16 == frame.subframe1.compute_expected_crc()
        assert frame.subframe2.crc16 == frame.subframe2.compute_expected_crc()
        # Since payload_p != payload_inv, the CRCs must be distinct
        assert frame.subframe1.crc16 != frame.subframe2.crc16

    def test_frame_wire_serialization_deserialization_roundtrip(
        self, opensafety_engine: OpenSafetyTransportEngine
    ) -> None:
        """Verify complete OpenSafetyFrame wire serialization and deserialization with magic prefix."""
        payload_p = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        frame = opensafety_engine.encode_safety_frame(snn=3, payload=payload_p, timestamp_us=5000)
        raw_wire = frame.serialize()

        assert raw_wire.startswith(OPENSAFETY_MAGIC_HEADER)
        deser = OpenSafetyFrame.deserialize(raw_wire)

        assert deser.subframe1.sdn == OPENSAFETY_DEFAULT_DOMAIN_ID
        assert deser.subframe1.snn == 3
        assert deser.subframe1.payload == payload_p
        assert deser.subframe2.payload == bytes((~b) & 0xFF for b in payload_p)
        assert deser.subframe1.crc16 == frame.subframe1.crc16
        assert deser.subframe2.crc16 == frame.subframe2.crc16

    def test_truncated_frame_deserialization_raises(self) -> None:
        """Verify truncated wire bytes trigger ValueError."""
        truncated = b"OS\x00\x01\x02"
        with pytest.raises(ValueError, match="Payload too short"):
            OpenSafetyFrame.deserialize(truncated)


# ============================================================================
# Section 4: Monotonic Sequence Tracking, Loss/Duplication/Reorder, & Watchdog
# ============================================================================

class TestSection4SequenceTrackingAndWatchdog:
    """Tests for monotonic sequence progression, frame anomaly detection, and watchdog timer."""

    def test_monotonic_sequence_progression(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """Verify sequential sequence counter progression (1 -> 2 -> 3) and OPERATIONAL transition."""
        payload = struct.pack(">h", 240)

        f1 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=10_000)
        res1 = opensafety_engine.validate_safety_frame(f1, current_time_us=10_200)
        assert res1.is_valid is True
        assert opensafety_engine.state == OpenSafetyState.OPERATIONAL
        assert opensafety_engine.has_synced is True
        assert opensafety_engine.rx_seq == f1.subframe1.seq_num

        f2 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=20_000)
        res2 = opensafety_engine.validate_safety_frame(f2, current_time_us=20_200)
        assert res2.is_valid is True
        assert opensafety_engine.rx_seq == f2.subframe1.seq_num

        f3 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=30_000)
        res3 = opensafety_engine.validate_safety_frame(f3, current_time_us=30_200)
        assert res3.is_valid is True
        assert opensafety_engine.rx_seq == f3.subframe1.seq_num
        assert opensafety_engine.cycle_counter == 3

    def test_frame_duplication_replay_attack_rejected_0xB002(
        self, opensafety_engine: OpenSafetyTransportEngine
    ) -> None:
        """Verify replaying an identical sequence counter triggers sequence fault 0xB002."""
        payload = struct.pack(">h", 240)
        f1 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=10_000)
        assert opensafety_engine.validate_safety_frame(f1, current_time_us=10_200).is_valid is True

        f2 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=20_000)
        assert opensafety_engine.validate_safety_frame(f2, current_time_us=20_200).is_valid is True

        # Replay f2
        res_replay = opensafety_engine.validate_safety_frame(f2, current_time_us=20_300)
        assert res_replay.is_valid is False
        assert res_replay.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_SEQUENCE_GAP
        assert opensafety_engine.is_latched is True
        assert opensafety_engine.reg_table.read_uword("%R1127") == 0xB002
        assert opensafety_engine.reg_table.read_bit("%M261") is False
        assert opensafety_engine.reg_table.read_bit("%M262") is True

    def test_frame_loss_gap_detection_0xB002(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """Verify sequence counter discontinuity (skipped sequence) triggers 0xB002."""
        payload = struct.pack(">h", 240)
        f1 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=10_000)
        assert opensafety_engine.validate_safety_frame(f1, current_time_us=10_200).is_valid is True

        # Dropped frame seq 2:
        _ = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=20_000)

        # Arrived frame seq 3:
        f3 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=30_000)
        res_gap = opensafety_engine.validate_safety_frame(f3, current_time_us=30_200)

        assert res_gap.is_valid is False
        assert res_gap.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_SEQUENCE_GAP
        assert opensafety_engine.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_SEQUENCE_GAP
        assert opensafety_engine.reg_table.read_uword("%R1127") == 0xB002
        assert opensafety_engine.reg_table.read_bit("%M261") is False
        assert opensafety_engine.reg_table.read_bit("%M262") is True

    def test_out_of_order_reordering_detection_0xB002(
        self, opensafety_engine: OpenSafetyTransportEngine
    ) -> None:
        """Verify out-of-order stale sequence counter delivery triggers 0xB002."""
        payload = struct.pack(">h", 240)
        f1 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=10_000)
        f2 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=20_000)

        assert opensafety_engine.validate_safety_frame(f1, current_time_us=10_200).is_valid is True
        assert opensafety_engine.validate_safety_frame(f2, current_time_us=20_200).is_valid is True

        # Now re-deliver older f1
        res_old = opensafety_engine.validate_safety_frame(f1, current_time_us=20_500)
        assert res_old.is_valid is False
        assert res_old.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_SEQUENCE_GAP
        assert opensafety_engine.reg_table.read_uword("%R1127") == 0xB002

    def test_watchdog_timeout_surveillance_0xB003(
        self, opensafety_engine: OpenSafetyTransportEngine
    ) -> None:
        """Verify watchdog silence timeout (> 50,000 us) triggers safe shutdown 0xB003."""
        payload = struct.pack(">h", 240)
        f1 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=10_000)
        assert opensafety_engine.validate_safety_frame(f1, current_time_us=10_200).is_valid is True
        assert opensafety_engine.state == OpenSafetyState.OPERATIONAL

        # Advance tick beyond watchdog threshold (60 ms > 50 ms)
        res_wd = opensafety_engine.step_tick(delta_us=60_000)
        assert res_wd.status == AgentStatus.FAILED
        assert opensafety_engine.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT
        assert opensafety_engine.reg_table.read_uword("%R1127") == 0xB003
        assert opensafety_engine.reg_table.read_bit("%M261") is False
        assert opensafety_engine.reg_table.read_bit("%M262") is True
        assert opensafety_engine.reg_table.read_word("%R1124") == 0


# ============================================================================
# Section 5: Black Channel Transport Simulation with Injected Noise & Latency
# ============================================================================

class TestSection5BlackChannelTransport:
    """Tests for Black Channel transport abstraction, latency surveillance, and noise injection."""

    def test_black_channel_transport_nominal(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """Verify normal black channel transmission and latency measurement."""
        transport = BlackChannelTransport(default_latency_us=450)
        payload = struct.pack(">h", 240)
        frame = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=1000)

        raw, latency = transport.transmit(frame, simulated_latency_us=600)
        assert latency == 600
        assert transport.current_latency_us == 600
        assert transport.total_transmitted == 1

        # Deliver to engine at t = 1000 + 600 = 1600
        outcome = opensafety_engine.validate_safety_frame(raw, current_time_us=1600)
        assert outcome.is_valid is True
        assert outcome.latency_us == 600
        assert opensafety_engine.reg_table.read_word("%R1126") == 600

    def test_black_channel_bit_flip_noise_injection_0xB001(
        self, opensafety_engine: OpenSafetyTransportEngine
    ) -> None:
        """Verify black channel noise bit-flip corruption is detected by dual CRC checks (0xB001)."""
        transport = BlackChannelTransport()
        payload = struct.pack(">h", 240)
        frame = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=1000)

        raw_noisy, _ = transport.transmit(frame, inject_noise=True)
        assert transport.total_corrupted == 1

        outcome = opensafety_engine.validate_safety_frame(raw_noisy, current_time_us=1450)
        assert outcome.is_valid is False
        assert outcome.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH
        assert opensafety_engine.reg_table.read_uword("%R1127") == 0xB001
        assert opensafety_engine.reg_table.read_bit("%M261") is False
        assert opensafety_engine.reg_table.read_bit("%M262") is True

    def test_black_channel_excessive_latency_excursion_0xB003(
        self, opensafety_engine: OpenSafetyTransportEngine
    ) -> None:
        """Verify transport delay exceeding max tolerable latency (35,000 us > 20,000 us) triggers 0xB003."""
        payload = struct.pack(">h", 240)
        frame = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=10_000)

        # Arrival at 45,000 us -> latency is 35,000 us (> 20,000 us limit)
        outcome = opensafety_engine.validate_safety_frame(frame, current_time_us=45_000)
        assert outcome.is_valid is False
        assert outcome.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT
        assert opensafety_engine.reg_table.read_uword("%R1127") == 0xB003
        assert opensafety_engine.reg_table.read_bit("%M261") is False
        assert opensafety_engine.reg_table.read_bit("%M262") is True

    def test_black_channel_future_timestamp_anomaly_0xB003(
        self, opensafety_engine: OpenSafetyTransportEngine
    ) -> None:
        """Verify negative latency exceeding jitter allowance triggers timeout fault (0xB003)."""
        payload = struct.pack(">h", 240)
        # Frame stamped at t = 20,000 us, but arrives at t = 10,000 us (-10,000 us delta)
        frame = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=20_000)
        outcome = opensafety_engine.validate_safety_frame(frame, current_time_us=10_000)

        assert outcome.is_valid is False
        assert outcome.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT


# ============================================================================
# Section 6: Process Safety Trips (0xB001..0xB004) & Horner Coil Assertion
# ============================================================================

class TestSection6ProcessSafetyTrips:
    """Tests for Process Safety Trips (0xB001, 0xB002, 0xB003, 0xB004) and Horner Coils."""

    def test_trip_0xb001_crc_redundancy_mismatch(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """0xB001 Corrupted redundant payload or CRC asserts %M262, clears %M261, and sets %R1127."""
        payload = struct.pack(">h", 240)
        f = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=1000)

        # Corrupt Subframe 2 payload byte
        raw = bytearray(f.serialize())
        raw[-3] ^= 0xFF
        opensafety_engine.validate_safety_frame(bytes(raw), current_time_us=1200)

        rt = opensafety_engine.reg_table
        assert opensafety_engine.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH
        assert rt.read_uword("%R1127") == 0xB001
        assert rt.read_bit("%M261") is False
        assert rt.read_bit("%M262") is True
        assert rt.read_word("%R1124") == 0

    def test_trip_0xb002_sequence_discontinuity(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """0xB002 Consecutive Time / sequence counter gap asserts %M262, clears %M261, and sets %R1127."""
        payload = struct.pack(">h", 240)
        f1 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=1000)
        opensafety_engine.validate_safety_frame(f1, current_time_us=1200)

        # Skip a sequence (frame loss / sequence gap)
        _ = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=2000)
        f3 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=3000)
        opensafety_engine.validate_safety_frame(f3, current_time_us=3200)

        rt = opensafety_engine.reg_table
        assert opensafety_engine.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_SEQUENCE_GAP
        assert rt.read_uword("%R1127") == 0xB002
        assert rt.read_bit("%M261") is False
        assert rt.read_bit("%M262") is True
        assert rt.read_word("%R1124") == 0

    def test_trip_0xb003_watchdog_timeout(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """0xB003 Watchdog / Latency timeout asserts %M262, clears %M261, and zeroes %R1124."""
        payload = struct.pack(">h", 240)
        f1 = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=1000)
        opensafety_engine.validate_safety_frame(f1, current_time_us=1200)

        # Trigger watchdog timeout (60 ms > 50 ms limit)
        opensafety_engine.step_tick(delta_us=60_000)

        rt = opensafety_engine.reg_table
        assert opensafety_engine.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT
        assert rt.read_uword("%R1127") == 0xB003
        assert rt.read_bit("%M261") is False
        assert rt.read_bit("%M262") is True
        assert rt.read_word("%R1124") == 0

    def test_trip_0xb004_domain_collision(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """0xB004 Alien Safety Domain ID (SDN) collision asserts %M262, clears %M261, and sets %R1127."""
        payload = struct.pack(">h", 240)
        f_init = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=1000)
        opensafety_engine.validate_safety_frame(f_init, current_time_us=1200)

        # Rogue frame from domain 0x7777
        rogue_engine = OpenSafetyTransportEngine(domain_id=0x7777, register_table=RegisterTable())
        f_rogue = rogue_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=2000)
        outcome = opensafety_engine.validate_safety_frame(f_rogue, current_time_us=2200)

        assert outcome.is_valid is False
        assert outcome.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_DOMAIN_COLLISION
        rt = opensafety_engine.reg_table
        assert rt.read_uword("%R1127") == 0xB004
        assert rt.read_bit("%M261") is False
        assert rt.read_bit("%M262") is True

    def test_operator_manual_reset_handshake(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """Verify operator reset handshake clears latch and restores healthy state."""
        payload = struct.pack(">h", 240)
        f = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=1000)
        raw_bad = bytearray(f.serialize())
        raw_bad[-3] ^= 0x01
        opensafety_engine.validate_safety_frame(bytes(raw_bad), current_time_us=1200)

        assert opensafety_engine.is_latched is True
        assert opensafety_engine.reg_table.read_bit("%M262") is True

        # Operator issues reset
        res_reset = opensafety_engine.reset_latch(force=True)
        assert res_reset.status == AgentStatus.SUCCESS
        assert opensafety_engine.is_latched is False
        assert opensafety_engine.diagnostic_code == OpenSafetyDiagnosticCode.OK
        assert opensafety_engine.reg_table.read_uword("%R1127") == 0x0000
        assert opensafety_engine.reg_table.read_bit("%M262") is False


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1120..%R1127)
# ============================================================================

class TestSection7HornerRegisterSpaceSync:
    """Tests for complete register table mapping verification (%R1120..%R1127, %M261..%M262)."""

    def test_scale_safety_pv_to_int16(self) -> None:
        """Verify scale_safety_pv_to_int16 clamps to 16-bit signed range [-32768, 32767]."""
        assert scale_safety_pv_to_int16(24.0, 10.0) == 240
        assert scale_safety_pv_to_int16(-15.5, 10.0) == -155
        assert scale_safety_pv_to_int16(5000.0, 10.0) == 32767
        assert scale_safety_pv_to_int16(-5000.0, 10.0) == -32768

    def test_full_register_map_integrity(self, opensafety_engine: OpenSafetyTransportEngine) -> None:
        """Assert each Horner mapped register reflects internal engine state."""
        payload = struct.pack(">h", 240)
        f = opensafety_engine.encode_safety_frame(snn=1, payload=payload, timestamp_us=1000)
        opensafety_engine.validate_safety_frame(f, current_time_us=1350)

        rt = opensafety_engine.reg_table
        assert rt.read_word("%R1120") == opensafety_engine.sdn
        assert rt.read_word("%R1121") == len(opensafety_engine.active_safety_nodes)
        assert rt.read_word("%R1122") == (opensafety_engine.cycle_counter & 0xFFFF)
        assert rt.read_word("%R1123") == opensafety_engine.consecutive_crc_errors
        assert rt.read_word("%R1124") == 240  # 24.0 V x 10
        assert rt.read_word("%R1125") == 240  # Inverted channel decoded back
        assert rt.read_word("%R1126") == 350  # 1350 - 1000 us latency
        assert rt.read_uword("%R1127") == 0x0000
        assert rt.read_bit("%M261") is True
        assert rt.read_bit("%M262") is False

    def test_active_safety_node_count_updates(self, register_table: RegisterTable) -> None:
        """Verify registering safety nodes updates active node count in %R1121."""
        engine = OpenSafetyTransportEngine(register_table=register_table)
        assert register_table.read_word("%R1121") == 0

        for i in range(1, 9):
            engine.configure_safety_node(snn=i, name=f"Node_{i}")
        assert register_table.read_word("%R1121") == 8
        assert len(engine.active_safety_nodes) == 8


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection8VerificationSuite:
    """Tests for run_opensafety_verification output and evidence file emission."""

    def test_run_opensafety_verification_success(self, tmp_path: Path) -> None:
        """Runs the 9-stage verification suite and verifies strict 4-state contract JSON."""
        evidence_file = tmp_path / "opensafety_evidence.json"
        res = run_opensafety_verification(output_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["tests"]) == 9

        # Ensure all individual stages passed
        for stage_test in res["data"]["tests"]:
            assert stage_test["passed"] is True

        # Verify evidence file written and valid
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W151"

    def test_evidence_register_map_completeness(self, tmp_path: Path) -> None:
        """Verify evidence output contains all Horner registers (%R1120..%R1127, %M261..%M262)."""
        evidence_file = tmp_path / "opensafety_evidence_map.json"
        res = run_opensafety_verification(output_path=str(evidence_file))

        values = res["data"]["register_map"]["values"]
        assert "%R1120" in values
        assert "%R1121" in values
        assert "%R1122" in values
        assert "%R1123" in values
        assert "%R1124" in values
        assert "%R1125" in values
        assert "%R1126" in values
        assert "%R1127" in values
        assert "%M261" in values
        assert "%M262" in values
