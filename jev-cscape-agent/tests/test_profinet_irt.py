"""Comprehensive Unit and Integration Test Suite for Industrial PROFINET IO IRT Engine.

Work Package: W157 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_cip_motion.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1180..%R1187, %M275..%M276).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: PROFINET IO IRT isochronous cycle timing, phase-lock synchronization, and sub-microsecond jitter.
4. Section 4: Dynamic Frame Packing (DFP) subframe packing, unpacking, and container CRC verification.
5. Section 5: MRPD media redundancy seamless ring failover and frame duplication rejection.
6. Section 6: Process safety trips (0xB601, 0xB602, 0xB603, 0xB604) and Horner coil assertion (%M275, %M276).
7. Section 7: Horner OCS register space synchronization (%R1180..%R1187, %M275..%M276).
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
from jev_cscape.telemetry.profinet_irt import (
    PROFINET_IRT_DEFAULT_CYCLE_TIME_US,
    PROFINET_IRT_DEFAULT_WATCHDOG_TIMEOUT_MS,
    PROFINET_IRT_ETHERTYPE,
    PROFINET_IRT_FRAME_ID_DFP,
    PROFINET_IRT_MAX_JITTER_NS,
    PROFINET_IRT_MAX_SYNC_JITTER_NS,
    PROFINET_IRT_NOMINAL_JITTER_NS,
    PROFINET_IRT_NOMINAL_SYNC_JITTER_NS,
    PROFINET_IRT_ADAPTER_SYNC_POU,
    PROFINET_IRT_ENGINE_SYNC_POU,
    PROFINET_IRT_PURE_ST_POU,
    PROFINET_IRT_SYNC_POU,
    PROFINET_IO_IRT_DFP_SYNC_POU,
    PROFINETIRT_SYNC_POU,
    PURE_ST_POU,
    DfpContainerFrame,
    DfpSubframe,
    IrtDiagnosticCode,
    IrtPhaseLockState,
    MrpdRingManager,
    MrpdRingPort,
    MrpdRingState,
    ProfinetIrtConfig,
    ProfinetIrtDiagnosticCode,
    ProfinetIrtEngine,
    ProfinetIrtStatusBits,
    ProfinetIrtSyncState,
    calculate_container_crc,
    calculate_crc16_ccitt,
    run_profinet_irt_verification,
    scale_cycle_time_to_int16,
    scale_jitter_to_int16,
    verify_profinet_irt_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def profinet_irt_engine(register_table: RegisterTable) -> ProfinetIrtEngine:
    """Provides a fresh ProfinetIrtEngine with default configuration."""
    config = ProfinetIrtConfig(
        station_name="Test_Profinet_IRT_Station_1",
        cycle_time_us=PROFINET_IRT_DEFAULT_CYCLE_TIME_US,
        max_jitter_ns=PROFINET_IRT_MAX_SYNC_JITTER_NS,
        watchdog_timeout_ms=PROFINET_IRT_DEFAULT_WATCHDOG_TIMEOUT_MS,
        port1_enabled=True,
        port2_enabled=True,
    )
    return ProfinetIrtEngine(config=config, register_table=register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Structured Text POUs and AST symbol binding."""

    def test_verify_profinet_irt_pure_st_function(self) -> None:
        """Verify helper validation function passes cleanly."""
        assert verify_profinet_irt_pure_st() is True

    def test_pure_st_profinet_irt_sync_ast_parsing(self) -> None:
        """Parse PROFINET_IRT_SYNC_POU and assert AST attributes and register bindings."""
        SecurityGuard.assert_pure_st_content(PROFINET_IRT_SYNC_POU)
        res = STParser.validate_code(PROFINET_IRT_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(PROFINET_IRT_SYNC_POU)
        assert ast is not None
        assert ast.name == "ProfinetIrtSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1180", "%R1181", "%R1182", "%R1183",
            "%R1184", "%R1185", "%R1186", "%R1187",
            "%M275", "%M276",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "IRTCycleTimeMicroseconds",
            "PhaseSyncJitterNanoseconds",
            "DfpSubframesPacked",
            "DfpContainerBytes",
            "MrpdDuplicateFramesRejected",
            "MrpdRingStatusWord",
            "CycleCounter",
            "DiagnosticStatusCode",
            "IRTCommReadyPermissive",
            "IRTSafetyTripActive",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_profinetirt_sync_ast_parsing(self) -> None:
        """Parse PROFINETIRT_SYNC_POU and assert AST attributes and register bindings."""
        SecurityGuard.assert_pure_st_content(PROFINETIRT_SYNC_POU)
        res = STParser.validate_code(PROFINETIRT_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(PROFINETIRT_SYNC_POU)
        assert ast is not None
        assert ast.name == "PROFINETIRTSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1180", "%R1181", "%R1182", "%R1183",
            "%R1184", "%R1185", "%R1186", "%R1187",
            "%M275", "%M276",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "IRTCycleTimeMicroseconds",
            "PhaseSyncJitterNanoseconds",
            "DfpSubframesPacked",
            "DfpContainerBytes",
            "MrpdDuplicateFramesRejected",
            "MrpdRingStatusWord",
            "CycleCounter",
            "DiagnosticStatusCode",
            "PROFINETIRTPermissive",
            "PROFINETIRTTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pou_aliases_consistency(self) -> None:
        """Verify backwards compatibility aliases point to the correct POU definitions."""
        assert PROFINET_IRT_ENGINE_SYNC_POU == PROFINET_IRT_SYNC_POU
        assert PROFINET_IRT_PURE_ST_POU == PROFINET_IRT_SYNC_POU
        assert PROFINET_IRT_ADAPTER_SYNC_POU == PROFINET_IRT_SYNC_POU
        assert PURE_ST_POU == PROFINET_IRT_SYNC_POU


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
            ("PROGRAM BadMnemonic\nVAR X: BOOL; END_VAR\nXIC %M275\nOTE %M276\nEND_PROGRAM", "ladder mnemonic"),
            ("PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM", "network keyword"),
        ],
    )
    def test_security_guard_rejects_ladder_syntax(self, bad_code: str, expected_reason: str) -> None:
        """Asserts SecurityGuard raises LadderForbiddenError for ladder logic elements."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_st_parser_returns_failed_on_ladder_logic(self) -> None:
        """Asserts STParser.validate_code returns FAILED with ERR_LADDER_FORBIDDEN."""
        ladder_snippet = "PROGRAM IllegalIrt\nVAR S: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM"
        res = STParser.validate_code(ladder_snippet)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"
        assert res.data.get("ladder_rejected") is True


# ============================================================================
# Section 3: PROFINET IO IRT Isochronous Timing & Sub-Microsecond Jitter
# ============================================================================

class TestSection3IsochronousCycleTimingAndJitter:
    """Tests for PROFINET IO IRT isochronous cycle timing, phase-lock synchronization, and sub-microsecond jitter."""

    def test_nominal_isochronous_cycle_and_submicrosecond_jitter_tracking(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """Verify cyclic sync pulses update jitter register %R1181 with sub-microsecond precision."""
        engine = profinet_irt_engine
        engine.enable()

        jitters = [20.0, 35.0, 42.0, 15.0, 48.0]
        for j in jitters:
            res = engine.receive_sync_pulse(jitter_ns=j)
            assert res.status == AgentStatus.SUCCESS
            engine.step_cycle(delta_ms=1.0)

            # %R1181 must reflect integer nanoseconds
            assert engine.reg_table.read_word("%R1181") == int(round(j))

        assert engine.max_observed_jitter_ns == 48.0
        assert engine.sync_state == IrtPhaseLockState.LOCKED
        assert engine.is_locked is True
        assert engine.comm_ready is True
        assert engine.reg_table.read_bit("%M275") is True

    def test_phase_lock_synchronization_state_transitions(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """Verify phase lock transitions UNLOCKED -> LOCKING -> LOCKED -> UNLOCKED."""
        engine = profinet_irt_engine
        assert engine.sync_state == IrtPhaseLockState.UNLOCKED
        assert engine.is_locked is False

        # Start -> LOCKING
        engine.enable()
        assert engine.sync_state == IrtPhaseLockState.LOCKING
        assert engine.consecutive_lock_cycles == 0

        # Feed 3 sync pulses to achieve lock
        engine.receive_sync_pulse(jitter_ns=30.0)
        assert engine.sync_state == IrtPhaseLockState.LOCKING
        engine.receive_sync_pulse(jitter_ns=32.0)
        assert engine.sync_state == IrtPhaseLockState.LOCKING
        engine.receive_sync_pulse(jitter_ns=28.0)
        assert engine.sync_state == IrtPhaseLockState.LOCKED
        assert engine.is_locked is True

        # Stop -> UNLOCKED
        engine.disable()
        assert engine.sync_state == IrtPhaseLockState.UNLOCKED
        assert engine.is_locked is False
        assert engine.comm_ready is False

    def test_cycle_counter_monotonic_progression(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """Verify cycle counter increments monotonically and updates %R1186."""
        engine = profinet_irt_engine
        engine.enable()

        start_cycle = engine.cycle_counter
        for i in range(1, 11):
            res = engine.step_cycle(delta_ms=1.0, simulated_jitter_ns=30.0)
            assert res.status == AgentStatus.SUCCESS
            assert engine.cycle_counter == start_cycle + i
            assert engine.reg_table.read_word("%R1186") == (start_cycle + i) & 0x7FFF


# ============================================================================
# Section 4: Dynamic Frame Packing (DFP) Serialization & Container CRC
# ============================================================================

class TestSection4DynamicFramePackingDFP:
    """Tests for DFP subframe serialization, container packing, unpacking, and CRC verification."""

    def test_dfp_subframe_serialization_roundtrip(self) -> None:
        """Verify DFP subframe header encoding, length computation, and payload extraction."""
        subframe = DfpSubframe(
            subframe_id=1,
            device_id=42,
            payload=b"\x01\x02\x03\x04\x05\x06",
            control=0x80,
        )
        assert subframe.data_length == 6
        raw = subframe.serialize()
        assert len(raw) == 5 + 6  # 5-byte header + 6-byte payload

        unpacked, rem = DfpSubframe.deserialize(raw + b"TRAILER")
        assert rem == b"TRAILER"
        assert unpacked.subframe_id == 1
        assert unpacked.device_id == 42
        assert unpacked.payload == b"\x01\x02\x03\x04\x05\x06"
        assert unpacked.control == 0x80

    def test_dfp_container_packing_and_unpacking(self) -> None:
        """Verify DFP container frame aggregation of multiple subframes."""
        subframes = [
            DfpSubframe(subframe_id=1, device_id=10, payload=b"\x10\x20"),
            DfpSubframe(subframe_id=2, device_id=11, payload=b"\x30\x40\x50\x60"),
            DfpSubframe(subframe_id=3, device_id=12, payload=b"\x70\x80\x90"),
        ]
        container = DfpContainerFrame(cycle_counter=250, subframes=subframes)
        packed = container.pack()

        # 6B container header + (5B+2B) + (5B+4B) + (5B+3B) + 2B CRC = 6 + 7 + 9 + 8 + 2 = 32 bytes
        assert len(packed) == 32

        unpacked = DfpContainerFrame.unpack(packed, verify_crc=True)
        assert unpacked.frame_id == PROFINET_IRT_FRAME_ID_DFP
        assert unpacked.cycle_counter == 250
        assert len(unpacked.subframes) == 3
        assert unpacked.subframes[0].payload == b"\x10\x20"
        assert unpacked.subframes[1].payload == b"\x30\x40\x50\x60"
        assert unpacked.subframes[2].payload == b"\x70\x80\x90"

    def test_dfp_container_crc_verification_and_corruption_detection(self) -> None:
        """Verify CRC-16-CCITT integrity enforcement detects and rejects corrupted frames."""
        subframes = [DfpSubframe(subframe_id=1, device_id=5, payload=b"HELLO")]
        container = DfpContainerFrame(cycle_counter=12, subframes=subframes)
        packed = container.pack()

        # Clean unpack succeeds
        unpacked = DfpContainerFrame.unpack(packed, verify_crc=True)
        assert unpacked.cycle_counter == 12

        # Corrupt 1 byte in container payload
        corrupted = bytearray(packed)
        corrupted[7] ^= 0xFF
        with pytest.raises(ValueError, match="DFP container CRC mismatch"):
            DfpContainerFrame.unpack(bytes(corrupted), verify_crc=True)

        # Corrupt CRC field directly
        bad_crc = packed[:-2] + b"\x00\x00"
        with pytest.raises(ValueError, match="DFP container CRC mismatch"):
            DfpContainerFrame.unpack(bad_crc, verify_crc=True)

    def test_dfp_multiple_subframes_aggregation(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """Verify ProfinetIrtEngine processes DFP cycle and updates %R1182 and %R1183."""
        engine = profinet_irt_engine
        engine.enable()

        subframes = [
            DfpSubframe(subframe_id=1, device_id=20, payload=b"\x01\x02"),
            DfpSubframe(subframe_id=2, device_id=21, payload=b"\x03\x04\x05"),
            DfpSubframe(subframe_id=3, device_id=22, payload=b"\x06\x07"),
            DfpSubframe(subframe_id=4, device_id=23, payload=b"\x08\x09\x0A\x0B"),
        ]
        res = engine.step_cycle(delta_ms=1.0, subframes=subframes)
        assert res.status == AgentStatus.SUCCESS

        rt = engine.reg_table
        assert rt.read_word("%R1182") == 4
        assert rt.read_word("%R1183") > 0


# ============================================================================
# Section 5: MRPD Media Redundancy Seamless Ring Failover & Duplication
# ============================================================================

class TestSection5MRPDMediaRedundancy:
    """Tests for MRPD seamless redundancy, duplicate rejection, and single-port break immunity."""

    def test_mrpd_frame_duplication_transmission(self) -> None:
        """Verify MRPD duplicate frame generation across Port 1 and Port 2."""
        mrpd = MrpdRingManager()
        subframes = [DfpSubframe(subframe_id=1, device_id=1, payload=b"\xAA\xBB")]
        container = DfpContainerFrame(cycle_counter=10, subframes=subframes)

        frames = mrpd.transmit_frame(container)
        assert "port1" in frames and "port2" in frames
        assert len(frames["port1"]) > 0
        assert frames["port1"] == frames["port2"]

    def test_mrpd_duplicate_frame_rejection_tracking(self) -> None:
        """Verify first arrival is accepted and identical redundant frame on second port is rejected."""
        mrpd = MrpdRingManager()
        subframes = [DfpSubframe(subframe_id=1, device_id=1, payload=b"\xAA\xBB")]
        container = DfpContainerFrame(cycle_counter=77, subframes=subframes)
        wire_data = container.pack()

        # Arrival on Port 1 accepted
        acc1, u1 = mrpd.receive_frame(MrpdRingPort.PORT_1, wire_data)
        assert acc1 is True
        assert u1 is not None
        assert mrpd.frames_received_port1 == 1
        assert mrpd.duplicate_frames_rejected == 0

        # Duplicate arrival on Port 2 rejected
        acc2, u2 = mrpd.receive_frame(MrpdRingPort.PORT_2, wire_data)
        assert acc2 is False
        assert mrpd.frames_received_port2 == 1
        assert mrpd.duplicate_frames_rejected == 1

    def test_mrpd_seamless_ring_failover_port1_break(self) -> None:
        """Verify Port 1 cable break allows seamless zero-loss reception via Port 2."""
        mrpd = MrpdRingManager()
        subframes = [DfpSubframe(subframe_id=1, device_id=1, payload=b"\x01")]

        # Simulate cable break on Port 1
        mrpd.simulate_link_break(1)
        assert mrpd.ring_state == MrpdRingState.RING_OPEN_PORT1_FAIL

        c_next = DfpContainerFrame(cycle_counter=88, subframes=subframes)
        frames = mrpd.transmit_frame(c_next)
        assert frames["port1"] == b""
        assert len(frames["port2"]) > 0

        # Port 2 delivers without packet loss
        acc, u = mrpd.receive_frame(MrpdRingPort.PORT_2, frames["port2"])
        assert acc is True
        assert u is not None
        assert u.cycle_counter == 88

    def test_mrpd_seamless_ring_failover_port2_break(self) -> None:
        """Verify Port 2 cable break allows seamless zero-loss reception via Port 1."""
        mrpd = MrpdRingManager()
        subframes = [DfpSubframe(subframe_id=1, device_id=1, payload=b"\x02")]

        # Simulate cable break on Port 2
        mrpd.simulate_link_break(2)
        assert mrpd.ring_state == MrpdRingState.RING_OPEN_PORT2_FAIL

        c_next = DfpContainerFrame(cycle_counter=89, subframes=subframes)
        frames = mrpd.transmit_frame(c_next)
        assert len(frames["port1"]) > 0
        assert frames["port2"] == b""

        # Port 1 delivers seamlessly
        acc, u = mrpd.receive_frame(MrpdRingPort.PORT_1, frames["port1"])
        assert acc is True
        assert u is not None
        assert u.cycle_counter == 89

    def test_mrpd_dual_ring_break_detection(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """Verify dual ring break trips 0xB603 (IRT_ERR_MRPD_RING_BREAK)."""
        engine = profinet_irt_engine
        engine.enable()

        # Break both ports
        engine.mrpd_manager.simulate_link_break(1)
        engine.mrpd_manager.simulate_link_break(2)
        assert engine.mrpd_manager.ring_state == MrpdRingState.RING_COLLAPSED

        res = engine.process_mrpd_cycle()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "IRT_ERR_MRPD_RING_BREAK"
        assert engine.diagnostic_code == ProfinetIrtDiagnosticCode.IRT_ERR_MRPD_RING_BREAK
        assert engine.reg_table.read_uword("%R1187") == 0xB603
        assert engine.reg_table.read_bit("%M275") is False
        assert engine.reg_table.read_bit("%M276") is True


# ============================================================================
# Section 6: Process Safety Trips (0xB601..0xB604) & Horner Coils
# ============================================================================

class TestSection6ProcessSafetyTrips:
    """Tests for Process Safety Trips (0xB601, 0xB602, 0xB603, 0xB604) and Horner Coils (%M275, %M276)."""

    def test_trip_0xb601_phase_sync_jitter_excursion(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """0xB601 Phase sync jitter (>= 1000 ns) clears %M275, asserts %M276, and sets %R1187."""
        engine = profinet_irt_engine
        engine.enable()
        engine.receive_sync_pulse(jitter_ns=35.0)

        # Inject jitter excursion: 1250.0 ns >= 1000.0 ns
        res = engine.step_cycle(delta_ms=1.0, simulated_jitter_ns=1250.0)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "IRT_ERR_PHASE_JITTER"

        rt = engine.reg_table
        assert engine.diagnostic_code == ProfinetIrtDiagnosticCode.IRT_ERR_PHASE_JITTER
        assert rt.read_uword("%R1187") == 0xB601
        assert rt.read_bit("%M275") is False
        assert rt.read_bit("%M276") is True
        assert engine.sync_state == IrtPhaseLockState.JITTER_FAULT

    def test_trip_0xb602_dfp_container_crc_violation(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """0xB602 DFP container CRC mismatch asserts %M276, clears %M275, and sets %R1187."""
        engine = profinet_irt_engine
        engine.enable()
        engine.receive_sync_pulse(jitter_ns=30.0)

        subframes = [DfpSubframe(subframe_id=1, device_id=2, payload=b"\xDE\xAD")]
        res = engine.process_dfp_cycle(subframes=subframes, corrupt_crc=True)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "IRT_ERR_DFP_CRC"

        rt = engine.reg_table
        assert engine.diagnostic_code == ProfinetIrtDiagnosticCode.IRT_ERR_DFP_CRC
        assert rt.read_uword("%R1187") == 0xB602
        assert rt.read_bit("%M275") is False
        assert rt.read_bit("%M276") is True

    def test_trip_0xb603_mrpd_ring_collapse(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """0xB603 Dual ring collapse asserts %M276, clears %M275, and sets %R1187."""
        engine = profinet_irt_engine
        engine.enable()
        engine.receive_sync_pulse(jitter_ns=30.0)

        # Simulate dual link break
        engine.mrpd_manager.simulate_link_break(1)
        engine.mrpd_manager.simulate_link_break(2)

        res = engine.step_cycle(delta_ms=1.0, simulated_jitter_ns=30.0)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "IRT_ERR_MRPD_RING_BREAK"

        rt = engine.reg_table
        assert engine.diagnostic_code == ProfinetIrtDiagnosticCode.IRT_ERR_MRPD_RING_BREAK
        assert rt.read_uword("%R1187") == 0xB603
        assert rt.read_bit("%M275") is False
        assert rt.read_bit("%M276") is True

    def test_trip_0xb604_isochronous_watchdog_timeout(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """0xB604 Isochronous silence watchdog timeout (> 50.0 ms) asserts %M276, clears %M275, and sets %R1187."""
        engine = profinet_irt_engine
        engine.enable()
        engine.receive_sync_pulse(jitter_ns=30.0)

        # Advance elapsed time beyond 50.0 ms watchdog without receiving sync pulse
        res_timeout = engine.step_cycle(delta_ms=65.0, receive_sync=False)
        assert res_timeout.status == AgentStatus.FAILED
        assert res_timeout.error_code == "IRT_ERR_COMM_TIMEOUT"

        rt = engine.reg_table
        assert engine.diagnostic_code == ProfinetIrtDiagnosticCode.IRT_ERR_COMM_TIMEOUT
        assert rt.read_uword("%R1187") == 0xB604
        assert rt.read_bit("%M275") is False
        assert rt.read_bit("%M276") is True

    def test_operator_manual_reset_handshake(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """Verify operator reset handshake clears fault latch, resets %M276, and restores %M275."""
        engine = profinet_irt_engine
        engine.enable()
        engine.trigger_safety_trip(ProfinetIrtDiagnosticCode.IRT_ERR_DFP_CRC)

        rt = engine.reg_table
        assert rt.read_bit("%M276") is True
        assert rt.read_bit("%M275") is False
        assert rt.read_uword("%R1187") == 0xB602

        # Operator manual reset
        res_reset = engine.reset_safety(force=True)
        assert res_reset.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == ProfinetIrtDiagnosticCode.OK
        assert rt.read_uword("%R1187") == 0x0000
        assert rt.read_bit("%M276") is False
        assert rt.read_bit("%M275") is True


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1180..%R1187)
# ============================================================================

class TestSection7HornerRegisterSpaceSync:
    """Tests for complete register table mapping verification (%R1180..%R1187, %M275..%M276)."""

    def test_scale_helper_functions(self) -> None:
        """Verify scale helpers clamp and scale correctly into signed 16-bit ranges."""
        assert scale_jitter_to_int16(35.4) == 35
        assert scale_jitter_to_int16(-10.0) == -10
        assert scale_jitter_to_int16(50000.0) == 32767
        assert scale_jitter_to_int16(-50000.0) == -32768

        assert scale_cycle_time_to_int16(1000.0) == 1000
        assert scale_cycle_time_to_int16(250.0) == 250
        assert scale_cycle_time_to_int16(60000.0) == 32767

    def test_full_register_map_integrity(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """Assert each Horner mapped register reflects internal engine kinematics and status."""
        engine = profinet_irt_engine
        engine.start_engine()
        engine.receive_sync_pulse(jitter_ns=45.0)

        subframes = [
            DfpSubframe(subframe_id=1, device_id=1, payload=b"\x01\x02"),
            DfpSubframe(subframe_id=2, device_id=2, payload=b"\x03\x04"),
        ]
        engine.process_dfp_cycle(subframes=subframes)
        engine.mrpd_manager.duplicate_frames_rejected = 3
        engine.cycle_counter = 42
        engine._sync_registers()

        rt = engine.reg_table
        assert rt.read_word("%R1180") == 1000       # 1000 us cycle time
        assert rt.read_word("%R1181") == 45         # 45 ns jitter
        assert rt.read_word("%R1182") == 2          # 2 subframes packed
        assert rt.read_word("%R1183") > 0           # Container byte length
        assert rt.read_word("%R1184") == 3          # 3 duplicates rejected
        assert rt.read_uword("%R1185") > 0          # Ring status word
        assert rt.read_word("%R1186") == 42         # Cycle counter 42
        assert rt.read_uword("%R1187") == 0x0000    # OK
        assert rt.read_bit("%M275") is True         # Permissive ready
        assert rt.read_bit("%M276") is False        # Trip inactive

    def test_register_synchronization_on_cyclic_step(
        self, profinet_irt_engine: ProfinetIrtEngine
    ) -> None:
        """Verify registers update dynamically during isochronous execution."""
        engine = profinet_irt_engine
        engine.start_engine()

        subframes = [DfpSubframe(subframe_id=1, device_id=3, payload=b"\x0A\x0B\x0C")]
        engine.step_cycle(delta_ms=1.0, simulated_jitter_ns=28.0, subframes=subframes)

        rt = engine.reg_table
        assert rt.read_word("%R1181") == 28
        assert rt.read_word("%R1182") == 1
        assert rt.read_bit("%M275") is True
        assert rt.read_bit("%M276") is False


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection8VerificationSuite:
    """Tests for run_profinet_irt_verification output and evidence file emission."""

    def test_run_profinet_irt_verification_success(self, tmp_path: Path) -> None:
        """Runs the 9-stage verification suite and verifies strict 4-state contract JSON."""
        evidence_file = tmp_path / "profinet_irt_evidence.json"
        res = run_profinet_irt_verification(output_path=str(evidence_file))

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
        assert data["data"]["work_package"] == "W157"

    def test_evidence_register_map_completeness(self, tmp_path: Path) -> None:
        """Verify evidence output contains all Horner registers (%R1180..%R1187, %M275..%M276)."""
        evidence_file = tmp_path / "profinet_irt_evidence_map.json"
        res = run_profinet_irt_verification(output_path=str(evidence_file))

        values = res["data"]["register_map"]["values"]
        assert "%R1180" in values
        assert "%R1181" in values
        assert "%R1182" in values
        assert "%R1183" in values
        assert "%R1184" in values
        assert "%R1185" in values
        assert "%R1186" in values
        assert "%R1187" in values
        assert "%M275" in values
        assert "%M276" in values

    def test_evidence_metrics_schema(self, tmp_path: Path) -> None:
        """Verify evidence metrics dictionary has all expected fields."""
        evidence_file = tmp_path / "profinet_irt_metrics.json"
        res = run_profinet_irt_verification(output_path=str(evidence_file))

        metrics = res["data"]["metrics"]
        assert "cycle_time_us" in metrics
        assert "max_jitter_ns" in metrics
        assert "dfp_subframes_packed" in metrics
        assert "dfp_container_bytes" in metrics
        assert "mrpd_duplicates_rejected" in metrics
        assert "ring_status_word" in metrics
