"""Comprehensive Unit and Integration Test Suite for Industrial IO-Link Safety Master Engine.

Work Package: W160 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_profinet_irt.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1210..%R1217, %M282..%M283).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Safe cyclical communication, master cycle timing (2.5 ms), and OSSD dual-channel state machine.
4. Section 4: Safe PD container packing, inverted payload complement verification, and dual CRC-16 checksum integrity.
5. Section 5: Safe sequence counter monotonic tracking and frozen/out-of-order counter fault detection.
6. Section 6: Process safety trips (0xB901, 0xB902, 0xB903, 0xB904) and Horner coil assertion (%M282, %M283).
7. Section 7: Horner OCS register space synchronization (%R1210..%R1217, %M282..%M283).
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
from jev_cscape.telemetry.iolink_safety import (
    IOLINK_SAFETY_CRC16_INIT,
    IOLINK_SAFETY_CRC16_POLY_A,
    IOLINK_SAFETY_CRC16_POLY_B,
    IOLINK_SAFETY_DEFAULT_DEVICE_ID,
    IOLINK_SAFETY_DEFAULT_VENDOR_ID,
    IOLINK_SAFETY_MASTER_SYNC_POU,
    IOLINK_SAFETY_MAX_SAFE_DEVICES,
    IOLINK_SAFETY_NOMINAL_CYCLE_TIME_MS,
    IOLINK_SAFETY_NOMINAL_CYCLE_TIME_SCALED,
    IOLINK_SAFETY_NOMINAL_WATCHDOG_MS,
    IOLINK_SAFETY_NOMINAL_WATCHDOG_SCALED,
    IOLINK_SAFETY_PURE_ST_POU,
    IOLINK_SAFETY_SYNC_POU,
    PURE_ST_POU,
    IoLinkSafetyCrcCorruptedError,
    IoLinkSafetyDeviceAuthenticationError,
    IoLinkSafetyDiagnosticCode,
    IoLinkSafetyEngine,
    IoLinkSafetyError,
    IoLinkSafetyMaster,
    IoLinkSafetyMasterEngine,
    IoLinkSafetySequenceCounterFaultError,
    IoLinkSafetyState,
    IoLinkSafetyStatusBits,
    IoLinkSafetyValidationOutcome,
    IoLinkSafetyWatchdogTimeoutError,
    SafeDeviceState,
    SafeProcessDataContainer,
    SafePdContainer,
    compute_crc16_a,
    compute_crc16_b,
    run_iolink_safety_verification,
    scale_ms_to_int16,
    verify_iolink_safety_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def iolink_safety_engine(register_table: RegisterTable) -> IoLinkSafetyMasterEngine:
    """Provides a fresh IoLinkSafetyMasterEngine initialized with 4 active safe devices."""
    engine = IoLinkSafetyMasterEngine(
        register_table=register_table,
        cycle_time_ms=IOLINK_SAFETY_NOMINAL_CYCLE_TIME_MS,
        watchdog_timeout_ms=IOLINK_SAFETY_NOMINAL_WATCHDOG_MS,
        expected_vendor_id=IOLINK_SAFETY_DEFAULT_VENDOR_ID,
        max_devices=IOLINK_SAFETY_MAX_SAFE_DEVICES,
    )
    for dev_idx in range(1, 5):
        engine.register_safe_device(
            device_id=dev_idx,
            device_name=f"SafeSensor_Port{dev_idx}",
            ossd_ch1=True,
            ossd_ch2=True,
        )
    return engine


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Structured Text POUs and AST symbol binding."""

    def test_verify_iolink_safety_pure_st_function(self) -> None:
        """Verify helper validation function passes cleanly without ladder elements."""
        assert verify_iolink_safety_pure_st() is True

    def test_pure_st_iolink_safety_sync_ast_parsing(self) -> None:
        """Parse IOLINK_SAFETY_SYNC_POU and assert AST attributes and register bindings."""
        SecurityGuard.assert_pure_st_content(IOLINK_SAFETY_SYNC_POU)
        res = STParser.validate_code(IOLINK_SAFETY_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(IOLINK_SAFETY_SYNC_POU)
        assert ast is not None
        assert ast.name == "IoLinkSafetySync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1210", "%R1211", "%R1212", "%R1213",
            "%R1214", "%R1215", "%R1216", "%R1217",
            "%M282", "%M283",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "IoLinkCycleTimeMsScaled",
            "ActiveSafeDevicesCount",
            "SafeSequenceCounter",
            "SafetyWatchdogMsScaled",
            "CrcErrorCount",
            "OssdOutputStateWord",
            "DeviceVendorId",
            "DiagnosticStatusCode",
            "IoLinkSafetyPermissive",
            "IoLinkSafetyFaultTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_iolink_safety_master_sync_ast_parsing(self) -> None:
        """Parse IOLINK_SAFETY_MASTER_SYNC_POU and assert AST attributes and bindings."""
        SecurityGuard.assert_pure_st_content(IOLINK_SAFETY_MASTER_SYNC_POU)
        res = STParser.validate_code(IOLINK_SAFETY_MASTER_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(IOLINK_SAFETY_MASTER_SYNC_POU)
        assert ast is not None
        assert ast.name == "IoLinkSafetyMasterSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1210", "%R1211", "%R1212", "%R1213",
            "%R1214", "%R1215", "%R1216", "%R1217",
            "%M282", "%M283",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "IoLinkCycleTimeMsScaled",
            "ActiveSafeDevicesCount",
            "SafeSequenceCounter",
            "SafetyWatchdogMsScaled",
            "CrcErrorCount",
            "OssdOutputStateWord",
            "DeviceVendorId",
            "DiagnosticStatusCode",
            "IoLinkSafetyPermissive",
            "IoLinkSafetyFaultTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pou_aliases_consistency(self) -> None:
        """Verify backwards compatibility aliases point to the correct POU definitions."""
        assert PURE_ST_POU == IOLINK_SAFETY_SYNC_POU
        assert IOLINK_SAFETY_PURE_ST_POU == IOLINK_SAFETY_SYNC_POU


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
            ("PROGRAM BadMnemonic\nVAR X: BOOL; END_VAR\nXIC %M282\nOTE %M283\nEND_PROGRAM", "ladder mnemonic"),
            ("PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM", "network keyword"),
        ],
    )
    def test_security_guard_rejects_ladder_syntax(self, bad_code: str, expected_reason: str) -> None:
        """Asserts SecurityGuard raises LadderForbiddenError for ladder logic elements."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_st_parser_returns_failed_on_ladder_logic(self) -> None:
        """Asserts STParser.validate_code returns FAILED with ERR_LADDER_FORBIDDEN."""
        ladder_snippet = "PROGRAM IllegalIoLink\nVAR S: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM"
        res = STParser.validate_code(ladder_snippet)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"
        assert res.data.get("ladder_rejected") is True


# ============================================================================
# Section 3: Safe Cyclical Communication, Master Timing, & OSSD State Machine
# ============================================================================

class TestSection3CyclicCommMasterTimingAndOSSD:
    """Tests for safe cyclical communication, 2.5 ms master cycle timing, and OSSD state machine."""

    def test_nominal_master_cycle_timing_2_5ms(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify cyclic steps advance simulation time with 2.5 ms nominal cycle period."""
        engine = iolink_safety_engine
        initial_time = engine.current_time_ms

        for i in range(1, 6):
            engine.step_scan_cycle(dt_ms=2.5)
            assert engine.current_time_ms == pytest.approx(initial_time + i * 2.5)
            assert engine.reg_table.read_word("%R1210") == IOLINK_SAFETY_NOMINAL_CYCLE_TIME_SCALED  # 25

        assert engine.state == IoLinkSafetyState.OPERATIONAL
        assert engine.permissive is True
        assert engine.reg_table.read_bit("%M282") is True
        assert engine.reg_table.read_bit("%M283") is False

    def test_ossd_dual_channel_energized_state_machine(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify 4 energized safe devices generate 8 active OSSD bits (0x00FF = 255)."""
        engine = iolink_safety_engine
        ossd_word = engine.recompute_ossd_state_word()
        assert ossd_word == 0x00FF
        assert engine.reg_table.read_word("%R1215") == 0x00FF
        assert bool(engine.status_bits & IoLinkSafetyStatusBits.OSSD_ENERGIZED) is True
        assert bool(engine.status_bits & IoLinkSafetyStatusBits.PERMISSIVE_HEALTHY) is True

    def test_ossd_dual_channel_discrepancy_and_deenergization(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify OSSD discrepancy (Ch1 != Ch2) safely de-energizes the discrepant channel pair."""
        engine = iolink_safety_engine
        dev2 = engine.devices[2]

        # Incur discrepancy on Device 2 (Ch1 High, Ch2 Low)
        dev2.ossd_ch1 = True
        dev2.ossd_ch2 = False
        discrepant_word = engine.recompute_ossd_state_word()
        engine.sync_to_registers()

        assert dev2.has_discrepancy is True
        assert dev2.is_safe is False
        # Device 2 corresponds to bits 2 and 3; they must be cleared (0)
        assert (discrepant_word & 0x000C) == 0
        assert engine.reg_table.read_word("%R1215") == discrepant_word
        assert bool(engine.status_bits & IoLinkSafetyStatusBits.OSSD_ENERGIZED) is False

        # Restore Device 2 channels
        dev2.ossd_ch1 = True
        dev2.ossd_ch2 = True
        restored_word = engine.recompute_ossd_state_word()
        engine.sync_to_registers()

        assert dev2.has_discrepancy is False
        assert dev2.is_safe is True
        assert restored_word == 0x00FF
        assert engine.reg_table.read_word("%R1215") == 0x00FF

    def test_device_registration_bounds_enforcement(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify registering devices out of bounds (1..8) raises ValueError."""
        engine = iolink_safety_engine
        with pytest.raises(ValueError, match="out of bounds"):
            engine.register_safe_device(device_id=0)

        with pytest.raises(ValueError, match="out of bounds"):
            engine.register_safe_device(device_id=9)


# ============================================================================
# Section 4: Safe PD Container Packing, Complement (~P), & Dual CRC-16
# ============================================================================

class TestSection4SafePdContainerAndDualCRC:
    """Tests for Safe PD serialization, bitwise inverted complement (~P), and dual CRC-16."""

    def test_safe_pd_container_creation_and_serialization_roundtrip(self) -> None:
        """Verify Safe PD binary header packing, payload alignment, and roundtrip deserialization."""
        raw_payload = b"\x11\x22\x33\x44\x55\x66"
        container = SafeProcessDataContainer.create(
            device_id=2,
            vendor_id=0x0123,
            sequence_counter=77,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=raw_payload,
            timestamp_ms=125.0,
        )
        assert len(container.payload) == 6
        assert len(container.payload_inv) == 6

        wire_bytes = container.serialize()
        # Wire length: 8 header + 6 payload + 6 complement + 4 dual CRC = 24 bytes
        assert len(wire_bytes) == 8 + 6 + 6 + 4

        deserialized = SafeProcessDataContainer.deserialize(wire_bytes, timestamp_ms=125.0)
        assert deserialized.device_id == 2
        assert deserialized.vendor_id == 0x0123
        assert deserialized.sequence_counter == 77
        assert deserialized.ossd_ch1 is True
        assert deserialized.ossd_ch2 is True
        assert deserialized.payload == raw_payload
        assert deserialized.payload_inv == bytes([b ^ 0xFF for b in raw_payload])
        assert deserialized.crc_1 == container.crc_1
        assert deserialized.crc_2 == container.crc_2

    def test_inverted_payload_complement_verification(self) -> None:
        """Verify every byte in payload satisfies P[i] ^ ~P[i] == 0xFF."""
        raw_payload = bytes([0x00, 0x55, 0xAA, 0xFF, 0x12, 0x34])
        container = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=1,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=raw_payload,
        )
        for p, inv in zip(container.payload, container.payload_inv):
            assert (p ^ inv) == 0xFF

        valid, diag, msg = container.verify_integrity(expected_vendor_id=0x0123)
        assert valid is True
        assert diag is None

    def test_inverted_payload_complement_corruption_detection(self) -> None:
        """Verify single bit corruption in inverted complement triggers 0xB901."""
        container = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=10,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=b"\xDE\xAD\xBE\xEF",
        )
        # Corrupt one complement byte
        bad_inv = bytearray(container.payload_inv)
        bad_inv[2] ^= 0x01
        corrupted = SafeProcessDataContainer(
            device_id=container.device_id,
            vendor_id=container.vendor_id,
            sequence_counter=container.sequence_counter,
            ossd_ch1=container.ossd_ch1,
            ossd_ch2=container.ossd_ch2,
            payload=container.payload,
            payload_inv=bytes(bad_inv),
            crc_1=container.crc_1,
            crc_2=container.crc_2,
        )
        valid, diag, msg = corrupted.verify_integrity()
        assert valid is False
        assert diag == IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED
        assert "Inverted payload complement mismatch" in msg

    def test_dual_crc16_integrity_enforcement(self) -> None:
        """Verify CRC-16-A (0x1021) and CRC-16-B (0x8005) independently detect corruption."""
        container = SafeProcessDataContainer.create(
            device_id=3,
            vendor_id=0x0123,
            sequence_counter=15,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=b"\xCA\xFE",
        )
        # Corrupt CRC-1 only
        bad_crc1 = SafeProcessDataContainer(
            device_id=container.device_id,
            vendor_id=container.vendor_id,
            sequence_counter=container.sequence_counter,
            ossd_ch1=container.ossd_ch1,
            ossd_ch2=container.ossd_ch2,
            payload=container.payload,
            payload_inv=container.payload_inv,
            crc_1=container.crc_1 ^ 0x0001,
            crc_2=container.crc_2,
        )
        v1, d1, m1 = bad_crc1.verify_integrity()
        assert v1 is False
        assert d1 == IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED
        assert "CRC-1 mismatch" in m1

        # Corrupt CRC-2 only
        bad_crc2 = SafeProcessDataContainer(
            device_id=container.device_id,
            vendor_id=container.vendor_id,
            sequence_counter=container.sequence_counter,
            ossd_ch1=container.ossd_ch1,
            ossd_ch2=container.ossd_ch2,
            payload=container.payload,
            payload_inv=container.payload_inv,
            crc_1=container.crc_1,
            crc_2=container.crc_2 ^ 0x0002,
        )
        v2, d2, m2 = bad_crc2.verify_integrity()
        assert v2 is False
        assert d2 == IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED
        assert "CRC-2 mismatch" in m2

    def test_deserialize_invalid_length_raises(self) -> None:
        """Verify short or truncated wire frames raise ValueError."""
        with pytest.raises(ValueError, match="too short"):
            SafeProcessDataContainer.deserialize(b"\x01\x02\x03")

        # Header claims 10 bytes payload, but wire is truncated
        truncated = struct.pack("<BBHHH", 1, 3, 0x0123, 1, 10) + b"\x00" * 4
        with pytest.raises(ValueError, match="Incomplete safe frame"):
            SafeProcessDataContainer.deserialize(truncated)


# ============================================================================
# Section 5: Safe Sequence Counter Monotonic Tracking & Fault Detection
# ============================================================================

class TestSection5SafeSequenceCounterTracking:
    """Tests for safe monotonic sequence counter surveillance and freeze/gap fault detection."""

    def test_monotonic_sequence_progression(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify strictly incrementing sequence numbers are accepted and update %R1212."""
        engine = iolink_safety_engine
        raw_payload = b"\x01\x02\x03"

        for seq in range(100, 106):
            c = SafeProcessDataContainer.create(
                device_id=1,
                vendor_id=0x0123,
                sequence_counter=seq,
                ossd_ch1=True,
                ossd_ch2=True,
                payload=raw_payload,
                timestamp_ms=engine.current_time_ms,
            )
            outcome = engine.process_safe_container(c)
            assert outcome.is_valid is True
            assert outcome.diagnostic_code == IoLinkSafetyDiagnosticCode.OK
            assert engine.safe_sequence_counter == seq
            assert engine.reg_table.read_uword("%R1212") == seq

    def test_frozen_sequence_counter_fault_detection(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify duplicate / repeated sequence counter trips 0xB902."""
        engine = iolink_safety_engine
        raw_payload = b"\xAA\xBB"

        c1 = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=250,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=raw_payload,
            timestamp_ms=engine.current_time_ms,
        )
        outcome1 = engine.process_safe_container(c1)
        assert outcome1.is_valid is True

        # Replay same sequence counter 250
        c_replay = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=250,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=raw_payload,
            timestamp_ms=engine.current_time_ms,
        )
        outcome_replay = engine.process_safe_container(c_replay)
        assert outcome_replay.is_valid is False
        assert outcome_replay.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT
        assert engine.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT
        assert engine.reg_table.read_uword("%R1217") == 0xB902
        assert engine.reg_table.read_bit("%M283") is True
        assert engine.reg_table.read_bit("%M282") is False

    def test_out_of_order_sequence_counter_fault_detection(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify sequence counter decrement / out-of-order packet trips 0xB902."""
        engine = iolink_safety_engine
        raw_payload = b"\x05"

        c_first = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=50,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=raw_payload,
            timestamp_ms=engine.current_time_ms,
        )
        engine.process_safe_container(c_first)

        # Send older packet 45 (< 50)
        c_old = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=45,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=raw_payload,
            timestamp_ms=engine.current_time_ms,
        )
        outcome_old = engine.process_safe_container(c_old)
        assert outcome_old.is_valid is False
        assert outcome_old.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT
        assert engine.reg_table.read_uword("%R1217") == 0xB902

    def test_excessive_sequence_gap_fault_detection(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify massive sequence jump gap (> 100) trips 0xB902."""
        engine = iolink_safety_engine
        raw_payload = b"\x07"

        c_base = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=10,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=raw_payload,
            timestamp_ms=engine.current_time_ms,
        )
        engine.process_safe_container(c_base)

        # Jump from 10 to 150 (delta = 140 > 100)
        c_jump = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=150,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=raw_payload,
            timestamp_ms=engine.current_time_ms,
        )
        outcome_jump = engine.process_safe_container(c_jump)
        assert outcome_jump.is_valid is False
        assert outcome_jump.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT


# ============================================================================
# Section 6: Process Safety Trips (0xB901..0xB904) & Horner Coils
# ============================================================================

class TestSection6ProcessSafetyTrips:
    """Tests for Process Safety Trips (0xB901, 0xB902, 0xB903, 0xB904) and Horner Coils (%M282, %M283)."""

    def test_trip_0xb901_crc_and_complement_corruption(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """0xB901 CRC corruption asserts %M283, clears %M282, zeroes %R1215, and sets %R1217."""
        engine = iolink_safety_engine
        container = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=500,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=b"\x12\x34",
            timestamp_ms=engine.current_time_ms,
        )
        container.crc_1 ^= 0xDEAD

        outcome = engine.process_safe_container(container)
        assert outcome.is_valid is False
        assert outcome.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED

        rt = engine.reg_table
        assert engine.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED
        assert rt.read_uword("%R1217") == 0xB901
        assert rt.read_bit("%M282") is False
        assert rt.read_bit("%M283") is True
        assert rt.read_word("%R1215") == 0
        assert rt.read_word("%R1214") >= 1

    def test_trip_0xb902_sequence_counter_anomaly(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """0xB902 Sequence counter freeze asserts %M283, clears %M282, and sets %R1217."""
        engine = iolink_safety_engine
        c = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=600,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=b"\x55",
            timestamp_ms=engine.current_time_ms,
        )
        engine.process_safe_container(c)

        # Trigger sequence trip by duplicate
        c_dup = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=600,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=b"\x55",
            timestamp_ms=engine.current_time_ms,
        )
        outcome = engine.process_safe_container(c_dup)
        assert outcome.is_valid is False
        assert outcome.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT

        rt = engine.reg_table
        assert rt.read_uword("%R1217") == 0xB902
        assert rt.read_bit("%M282") is False
        assert rt.read_bit("%M283") is True

    def test_trip_0xb903_watchdog_timeout_expiration(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """0xB903 Safety watchdog silence (> 20.0 ms) asserts %M283, clears %M282, and sets %R1217."""
        engine = iolink_safety_engine
        # Ensure fresh baseline
        engine.reset_latch(force=True)
        c = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=700,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=b"\x99",
            timestamp_ms=engine.current_time_ms,
        )
        engine.process_safe_container(c)

        # Advance elapsed silence beyond 20.0 ms watchdog (e.g. 25.0 ms)
        engine.step_scan_cycle(dt_ms=25.0)

        rt = engine.reg_table
        assert engine.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_WATCHDOG_TIMEOUT
        assert rt.read_uword("%R1217") == 0xB903
        assert rt.read_bit("%M282") is False
        assert rt.read_bit("%M283") is True
        assert rt.read_word("%R1215") == 0

    def test_trip_0xb904_device_authentication_failure(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """0xB904 Rogue device/vendor ID mismatch asserts %M283, clears %M282, and sets %R1217."""
        engine = iolink_safety_engine
        alien_container = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x9999,  # Rogue Vendor ID
            sequence_counter=800,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=b"\x01",
            timestamp_ms=engine.current_time_ms,
        )
        outcome = engine.process_safe_container(alien_container)
        assert outcome.is_valid is False
        assert outcome.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED

        rt = engine.reg_table
        assert engine.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED
        assert rt.read_uword("%R1217") == 0xB904
        assert rt.read_bit("%M282") is False
        assert rt.read_bit("%M283") is True

    def test_operator_manual_reset_handshake_restoration(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify operator manual reset clears latch, resets %M283, and restores %M282 and %R1217."""
        engine = iolink_safety_engine
        engine.trigger_fault(IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED)

        rt = engine.reg_table
        assert rt.read_bit("%M283") is True
        assert rt.read_bit("%M282") is False
        assert rt.read_uword("%R1217") == 0xB901

        # Operator manual reset
        res_reset = engine.reset_latch(force=True)
        assert res_reset.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == IoLinkSafetyDiagnosticCode.OK
        assert rt.read_uword("%R1217") == 0x0000
        assert rt.read_bit("%M283") is False
        assert rt.read_bit("%M282") is True
        assert rt.read_word("%R1215") == 0x00FF


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1210..%R1217)
# ============================================================================

class TestSection7HornerRegisterSpaceSync:
    """Tests for complete register table mapping verification (%R1210..%R1217, %M282..%M283)."""

    def test_scale_ms_helper_function(self) -> None:
        """Verify scale helpers clamp and scale correctly into signed 16-bit ranges."""
        assert scale_ms_to_int16(2.5) == 25
        assert scale_ms_to_int16(20.0) == 200
        assert scale_ms_to_int16(0.0) == 0
        assert scale_ms_to_int16(-10.0) == -100
        assert scale_ms_to_int16(5000.0) == 32767
        assert scale_ms_to_int16(-5000.0) == -32768

    def test_full_register_map_integrity(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Assert each Horner mapped register reflects internal engine state."""
        engine = iolink_safety_engine
        c = SafeProcessDataContainer.create(
            device_id=1,
            vendor_id=0x0123,
            sequence_counter=42,
            ossd_ch1=True,
            ossd_ch2=True,
            payload=b"\xCA\xFE",
            timestamp_ms=engine.current_time_ms,
        )
        engine.process_safe_container(c)

        rt = engine.reg_table
        assert rt.read_word("%R1210") == 25        # 2.5 ms x10 = 25
        assert rt.read_word("%R1211") == 4         # 4 active safe devices
        assert rt.read_uword("%R1212") == 42       # SafeSequenceCounter 42
        assert rt.read_word("%R1213") == 200       # 20.0 ms x10 = 200
        assert rt.read_word("%R1214") == 0         # 0 CRC errors
        assert rt.read_word("%R1215") == 0x00FF    # 4 devices energized -> 0x00FF
        assert rt.read_uword("%R1216") == 0x0123   # Vendor ID 0x0123
        assert rt.read_uword("%R1217") == 0x0000   # OK
        assert rt.read_bit("%M282") is True        # Permissive healthy
        assert rt.read_bit("%M283") is False       # Fault trip inactive

    def test_register_synchronization_on_cyclic_step(
        self, iolink_safety_engine: IoLinkSafetyMasterEngine
    ) -> None:
        """Verify registers update dynamically during scan execution."""
        engine = iolink_safety_engine
        engine.step_scan_cycle(dt_ms=2.5)

        rt = engine.reg_table
        assert rt.read_word("%R1210") == 25
        assert rt.read_bit("%M282") is True
        assert rt.read_bit("%M283") is False


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection8VerificationSuite:
    """Tests for run_iolink_safety_verification output and evidence file emission."""

    def test_run_iolink_safety_verification_success(self, tmp_path: Path) -> None:
        """Runs the 9-stage verification suite and verifies strict 4-state contract JSON."""
        evidence_file = tmp_path / "iolink_safety_evidence.json"
        res = run_iolink_safety_verification(output_path=str(evidence_file))

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
        assert data["data"]["work_package"] == "W160"

    def test_evidence_register_map_completeness(self, tmp_path: Path) -> None:
        """Verify evidence output contains all Horner registers (%R1210..%R1217, %M282..%M283)."""
        evidence_file = tmp_path / "iolink_safety_evidence_map.json"
        res = run_iolink_safety_verification(output_path=str(evidence_file))

        values = res["data"]["register_map"]["values"]
        assert "%R1210" in values
        assert "%R1211" in values
        assert "%R1212" in values
        assert "%R1213" in values
        assert "%R1214" in values
        assert "%R1215" in values
        assert "%R1216" in values
        assert "%R1217" in values
        assert "%M282" in values
        assert "%M283" in values

    def test_evidence_metrics_schema(self, tmp_path: Path) -> None:
        """Verify evidence metrics dictionary has all expected fields."""
        evidence_file = tmp_path / "iolink_safety_metrics.json"
        res = run_iolink_safety_verification(output_path=str(evidence_file))

        metrics = res["data"]["metrics"]
        assert "master_cycle_time_ms" in metrics
        assert "master_cycle_time_ms_scaled" in metrics
        assert "active_devices_count" in metrics
        assert "safe_sequence_counter" in metrics
        assert "watchdog_timeout_ms" in metrics
        assert "crc_error_count" in metrics
        assert "ossd_output_state_word" in metrics
        assert "expected_vendor_id" in metrics
