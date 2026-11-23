"""Unit Test Suite for Industrial DeviceNet / CANopen Safety Physical Layer & Master Bridge Engine.

Work Package: W142 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1030..%R1037, %M240..%M241).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: CAN physical layer arbitration, bit timing, and error state transitions (Active, Passive, Bus-off).
4. Section 4: CIP Safety & CANopen Safety SRDO redundant inverted payload (P and ~P) and dual CRC verification.
5. Section 5: EPI timeout detection (< 20ms reaction time) and sequence number tracking.
6. Section 6: Process safety trips (0xA701, 0xA702, 0xA703, 0xA704) and Horner coil assertion (%M240, %M241).
7. Section 7: Horner OCS register space synchronization (%R1030..%R1037, %M240..%M241).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
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
from jev_cscape.telemetry.devicenet_safety import (
    CAN_BAUD_125K,
    CAN_BAUD_250K,
    CAN_BAUD_500K,
    CAN_BIT_TIME_125K_US,
    CAN_BIT_TIME_250K_US,
    CAN_BIT_TIME_500K_US,
    CANOPEN_SAFETY_PURE_ST_POU,
    CANOPEN_SAFETY_SYNC_POU,
    CANOPEN_SAFETY_SYNC_PURE_ST_POU,
    DEVICENET_DEFAULT_EPI_MS,
    DEVICENET_MAX_NODES,
    DEVICENET_MAX_REACTION_TIME_MS,
    DEVICENET_MAX_TOLERABLE_DELAY_MS,
    DEVICENET_SAFETY_PURE_ST_POU,
    DEVICENET_SAFETY_SYNC_POU,
    DEVICENET_SAFETY_SYNC_PURE_ST_POU,
    PURE_ST_POU,
    CANBaudRate,
    CANBusOffError,
    CANBusState,
    CANFrame,
    CANFrameType,
    CANPhysicalLayer,
    CANopenSDOCommand,
    DeviceNetDiagnosticCode,
    DeviceNetNode,
    DeviceNetSafetyEngine,
    DeviceNetSafetyError,
    DeviceNetSafetyMasterEngine,
    DeviceNetSafetyStatusBits,
    DuplicateMacIdError,
    EPITimeoutError,
    InvertedCRCMismatchError,
    RedundantSafetyPayload,
    SafetyNetworkNumber,
    SafetyNetworkNumberMismatchError,
    SequenceIntegrityError,
    compute_crc15_can,
    compute_crc16_ccitt,
    run_devicenet_safety_verification,
    scale_safety_pv_to_int16,
    simulate_can_arbitration,
    unstuff_can_bits,
    verify_devicenet_safety_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def safety_master(register_table: RegisterTable) -> DeviceNetSafetyMasterEngine:
    """Provides a fresh DeviceNetSafetyMasterEngine with register table."""
    return DeviceNetSafetyMasterEngine(
        master_mac_id=0,
        baud_rate=CANBaudRate.BAUD_500K,
        register_table=register_table,
    )


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================


class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Structured Text POUs and AST symbol binding."""

    def test_verify_devicenet_safety_pure_st_function(self) -> None:
        """Verify helper function passes cleanly."""
        assert verify_devicenet_safety_pure_st() is True

    def test_pure_st_devicenet_sync_ast_parsing(self) -> None:
        """Parse DEVICENET_SAFETY_SYNC_POU and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(DEVICENET_SAFETY_SYNC_POU)
        res = STParser.validate_code(DEVICENET_SAFETY_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(DEVICENET_SAFETY_SYNC_POU)
        assert ast is not None
        assert ast.name == "DeviceNetSafetySync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1030", "%R1031", "%R1032", "%R1033",
            "%R1034", "%R1035", "%R1036", "%R1037",
            "%M240", "%M241",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "ActiveNodeCount",
            "SafetyNetworkNumberWord",
            "SafetyScanCycleCounter",
            "PrimarySafetyDataScaled",
            "SecondarySafetyDataScaled",
            "CanBusErrorPassiveCounter",
            "CanopenSdoTransactionCounter",
            "DiagnosticStatusCode",
            "DeviceNetMasterActive",
            "SafetyConnectionTimeoutTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_canopen_sync_ast_parsing(self) -> None:
        """Parse CANOPEN_SAFETY_SYNC_POU and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(CANOPEN_SAFETY_SYNC_POU)
        res = STParser.validate_code(CANOPEN_SAFETY_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CANOPEN_SAFETY_SYNC_POU)
        assert ast is not None
        assert ast.name == "CanopenSafetySync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1030", "%R1031", "%R1032", "%R1033",
            "%R1034", "%R1035", "%R1036", "%R1037",
            "%M240", "%M241",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_pure_st_pou_aliases(self) -> None:
        """Verify alias constants point to valid pure ST POU definitions."""
        assert DEVICENET_SAFETY_SYNC_PURE_ST_POU == DEVICENET_SAFETY_SYNC_POU
        assert CANOPEN_SAFETY_SYNC_PURE_ST_POU == CANOPEN_SAFETY_SYNC_POU
        assert DEVICENET_SAFETY_PURE_ST_POU == DEVICENET_SAFETY_SYNC_POU
        assert CANOPEN_SAFETY_PURE_ST_POU == CANOPEN_SAFETY_SYNC_POU
        assert PURE_ST_POU == DEVICENET_SAFETY_SYNC_POU

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify all pure ST POU variants pass SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(DEVICENET_SAFETY_SYNC_POU)
        SecurityGuard.assert_pure_st_content(CANOPEN_SAFETY_SYNC_POU)
        SecurityGuard.assert_pure_st_content(DEVICENET_SAFETY_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(CANOPEN_SAFETY_PURE_ST_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================


class TestSection2AntiLadderSecurity:
    """Tests for SecurityGuard strict rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "sample",
        [
            "PROGRAM BadContacts\nVAR Flag: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
            "PROGRAM BadNegative\nVAR Flag: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M240 OTE %M241 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM BadReset\nVAR Out: BOOL; END_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM BadMnemonic\nVAR Out: BOOL; END_VAR\nXIO %M240\nEND_PROGRAM",
            "PROGRAM BadLatch\nVAR Out: BOOL; END_VAR\nOTL %M241\nEND_PROGRAM",
            "PROGRAM BadUnlatch\nVAR Out: BOOL; END_VAR\nOTU %M241\nEND_PROGRAM",
            "PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: CAN Physical Layer Arbitration, Bit Timing, & Error State Transitions
# ============================================================================


class TestSection3CANPhysicalLayer:
    """Tests for CAN Physical and Data Link Layer: Arbitration, Bit Timing, and Error States."""

    def test_can_arbitration_dominant_priority(self) -> None:
        """Verify bitwise non-destructive arbitration: lowest numerical arbitration ID wins."""
        f_low = CANFrame(can_id=0x181, data=b"\x01")
        f_mid = CANFrame(can_id=0x182, data=b"\x02")
        f_high = CANFrame(can_id=0x185, data=b"\x03")

        winner = simulate_can_arbitration([f_high, f_mid, f_low])
        assert winner.can_id == 0x181
        assert winner.data == b"\x01"

        # Verify standard frame wins over extended frame with same base ID
        f_std = CANFrame(can_id=0x100, data=b"\xAA", is_extended=False)
        f_ext = CANFrame(can_id=0x100, data=b"\xBB", is_extended=True)
        winner2 = simulate_can_arbitration([f_ext, f_std])
        assert winner2.is_extended is False
        assert winner2.data == b"\xAA"

    def test_can_physical_layer_arbitrate_method(self) -> None:
        """Verify CANPhysicalLayer.arbitrate delegates to simulate_can_arbitration."""
        phy = CANPhysicalLayer(baud_rate=CANBaudRate.BAUD_500K)
        frames = [
            CANFrame(can_id=0x200, data=b"\x01"),
            CANFrame(can_id=0x105, data=b"\x02"),
            CANFrame(can_id=0x300, data=b"\x03"),
        ]
        winner = phy.arbitrate(frames)
        assert winner.can_id == 0x105

    def test_baud_rate_nominal_timings(self) -> None:
        """Verify nominal bit durations across 125k, 250k, and 500k baud rates."""
        assert math.isclose(CANBaudRate.BAUD_125K.bit_time_us, CAN_BIT_TIME_125K_US)
        assert math.isclose(CANBaudRate.BAUD_250K.bit_time_us, CAN_BIT_TIME_250K_US)
        assert math.isclose(CANBaudRate.BAUD_500K.bit_time_us, CAN_BIT_TIME_500K_US)
        assert CANBaudRate.BAUD_500K.bit_time_ns == 2000
        assert CANBaudRate.BAUD_250K.bit_time_ns == 4000
        assert CANBaudRate.BAUD_125K.bit_time_ns == 8000

    def test_can_frame_serialization_roundtrip(self) -> None:
        """Verify serialization and deserialization of standard and extended frames."""
        f_std = CANFrame(can_id=0x3C5, data=b"\x01\x02\x03\x04", is_extended=False)
        raw_std = f_std.serialize()
        d_std = CANFrame.deserialize(raw_std)
        assert d_std.can_id == 0x3C5
        assert d_std.data == b"\x01\x02\x03\x04"
        assert d_std.is_extended is False
        assert d_std.dlc == 4

        f_ext = CANFrame(can_id=0x18DAF100, data=b"\x10\x20\x30\x40\x50", is_extended=True)
        raw_ext = f_ext.serialize()
        d_ext = CANFrame.deserialize(raw_ext)
        assert d_ext.can_id == 0x18DAF100
        assert d_ext.data == b"\x10\x20\x30\x40\x50"
        assert d_ext.is_extended is True
        assert d_ext.dlc == 5

    def test_bit_stuffing_and_unstuffing(self) -> None:
        """Verify bit stuffing on 5 consecutive bits and unstuffing roundtrip."""
        f = CANFrame(can_id=0x100, data=b"\x00\x00\xFF\xFF")
        stuffed, count = f.calculate_bit_stuffing()
        assert count > 0

        # Unstuffing candidate field (exclude 13 trailer bits)
        unstuffed, has_err = unstuff_can_bits(stuffed[:-13])
        assert has_err is False
        assert len(unstuffed) < len(stuffed[:-13])

    def test_bit_stuff_error_detection(self) -> None:
        """Verify detection of bit stuff error when 6 consecutive identical bits occur."""
        corrupted_bits = [0, 0, 0, 0, 0, 0]  # 6 dominant bits without stuff bit
        _, has_err = unstuff_can_bits(corrupted_bits)
        assert has_err is True

    def test_wire_transmission_duration(self) -> None:
        """Verify transmission duration calculation across baud rates."""
        f = CANFrame(can_id=0x405, data=b"\x11\x22\x33\x44\x55\x66\x77\x88")
        dur_125 = f.calculate_wire_duration_us(CANBaudRate.BAUD_125K)
        dur_250 = f.calculate_wire_duration_us(CANBaudRate.BAUD_250K)
        dur_500 = f.calculate_wire_duration_us(CANBaudRate.BAUD_500K)

        assert math.isclose(dur_125, dur_250 * 2.0, rel_tol=1e-3)
        assert math.isclose(dur_250, dur_500 * 2.0, rel_tol=1e-3)

    def test_error_active_to_passive_transition(self) -> None:
        """Verify transition to Error Passive when TEC > 127 or REC > 127."""
        phy = CANPhysicalLayer(baud_rate=CANBaudRate.BAUD_500K)
        assert phy.bus_state == CANBusState.ERROR_ACTIVE
        assert phy.tec == 0
        assert phy.rec == 0

        # Inject 16 transmit errors (16 * 8 = 128 > 127)
        for _ in range(16):
            phy.record_tx_error()

        assert phy.tec == 128
        assert phy.bus_state == CANBusState.ERROR_PASSIVE
        assert phy.error_passive_transitions == 1

    def test_error_passive_to_bus_off_transition_0xA703(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify transition to Bus Off when TEC > 255 and diagnostic code 0xA703."""
        master = safety_master
        master.is_active = True
        master.phy.tec = 250
        master.phy._update_state()
        assert master.phy.bus_state == CANBusState.ERROR_PASSIVE

        # Exceed 255: 250 + 8 = 258 > 255
        master.phy.record_tx_error()
        assert master.phy.tec == 258
        assert master.phy.bus_state == CANBusState.BUS_OFF

        # Master scan cycle recognizes bus off
        master.step_scan_cycle()
        assert master.reg_table.read_uword("%R1037") == DeviceNetDiagnosticCode.DEVICENET_ERR_CAN_BUS_OFF
        assert master.reg_table.read_bit("%M240") is False
        assert master.reg_table.read_bit("%M241") is True

    def test_bus_recovery_handshake(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify recovery from Bus Off resets counters and restores normal state."""
        master = safety_master
        master.phy.tec = 260
        master.phy._update_state()
        master.step_scan_cycle()
        assert master.safety_tripped is True

        # Operator reset
        master.reset_fault()
        assert master.phy.bus_state == CANBusState.ERROR_ACTIVE
        assert master.phy.tec == 0
        assert master.diagnostic_code == DeviceNetDiagnosticCode.OK
        assert master.reg_table.read_bit("%M240") is True
        assert master.reg_table.read_bit("%M241") is False

    def test_rx_error_and_success_counter_adjustments(self) -> None:
        """Verify REC increments on receive errors and decrements on successful reception."""
        phy = CANPhysicalLayer(baud_rate=CANBaudRate.BAUD_500K)
        assert phy.rec == 0

        phy.record_rx_error(increment=1)
        assert phy.rec == 1

        phy.record_rx_success()
        assert phy.rec == 0

        phy.record_tx_error(increment=8)
        assert phy.tec == 8
        phy.record_tx_success()
        assert phy.tec == 7


# ============================================================================
# Section 4: CIP Safety & CANopen Safety SRDO Redundant Payload & Dual CRC
# ============================================================================


class TestSection4RedundantPayloadAndDualCRC:
    """Tests for Redundant Inverted Payload (P and ~P) and Dual 16-bit CRC Verification."""

    def test_valid_redundant_payload_creation(self) -> None:
        """Verify P and ~P bitwise inversion strictly asserts P[i] ^ ~P[i] == 0xFF."""
        data = b"\x12\x34\x56\x78"
        p = RedundantSafetyPayload.create(data=data, sequence_num=1, timestamp_ms=0.0)
        assert p.payload_p == data
        assert p.payload_inv == bytes([~b & 0xFF for b in data])
        assert all(b1 ^ b2 == 0xFF for b1, b2 in zip(p.payload_p, p.payload_inv))

        ok, err = p.verify()
        assert ok is True
        assert err is None

    def test_corrupted_inverted_byte_detection_0xA702(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify corruption in ~P triggers 0xA702."""
        master = safety_master
        master.is_active = True
        master.register_node(mac_id=8)

        data = b"\xAA\xBB\xCC\xDD"
        good = RedundantSafetyPayload.create(data=data, sequence_num=1, timestamp_ms=0.0, snn=master.snn)
        # Flip 1 bit in ~P
        corrupt_inv = bytes([good.payload_inv[0] ^ 0x02]) + good.payload_inv[1:]
        bad = RedundantSafetyPayload(
            payload_p=good.payload_p,
            payload_inv=corrupt_inv,
            sequence_num=good.sequence_num,
            timestamp_ms=good.timestamp_ms,
            crc_p=good.crc_p,
            crc_inv=good.crc_inv,
        )

        ok = master.process_safety_telegram(mac_id=8, payload=bad)
        assert ok is False
        assert master.reg_table.read_uword("%R1037") == DeviceNetDiagnosticCode.DEVICENET_ERR_INVERTED_CRC_MISMATCH
        assert master.reg_table.read_bit("%M240") is False
        assert master.reg_table.read_bit("%M241") is True

    def test_dual_crc_checksum_integrity_and_mismatch(self) -> None:
        """Verify dual CRC verification detects corruptions in crc_p and crc_inv."""
        data = b"\x55\xAA\x33\xCC"
        payload = RedundantSafetyPayload.create(data=data, sequence_num=5, timestamp_ms=50.0)

        # Corrupt CRC P
        bad_crc_p = RedundantSafetyPayload(
            payload_p=payload.payload_p,
            payload_inv=payload.payload_inv,
            sequence_num=payload.sequence_num,
            timestamp_ms=payload.timestamp_ms,
            crc_p=payload.crc_p ^ 0x0001,
            crc_inv=payload.crc_inv,
        )
        ok, reason = bad_crc_p.verify()
        assert ok is False
        assert reason == "CRC_P_MISMATCH"

        # Corrupt CRC Inv
        bad_crc_inv = RedundantSafetyPayload(
            payload_p=payload.payload_p,
            payload_inv=payload.payload_inv,
            sequence_num=payload.sequence_num,
            timestamp_ms=payload.timestamp_ms,
            crc_p=payload.crc_p,
            crc_inv=payload.crc_inv ^ 0x0001,
        )
        ok, reason = bad_crc_inv.verify()
        assert ok is False
        assert reason == "CRC_INV_MISMATCH"

    def test_payload_length_mismatch(self) -> None:
        """Verify length mismatch between P and ~P is rejected."""
        payload = RedundantSafetyPayload(
            payload_p=b"\x01\x02",
            payload_inv=b"\xFE",
            sequence_num=1,
            timestamp_ms=0.0,
            crc_p=0,
            crc_inv=0,
        )
        ok, reason = payload.verify()
        assert ok is False
        assert reason == "PAYLOAD_LENGTH_MISMATCH"

    def test_snn_serialization_and_crc(self) -> None:
        """Verify 6-byte SNN serialization, deserialization, and CRC calculation."""
        snn = SafetyNetworkNumber(date_word=0x1975, time_mac_dword=0x12345678)
        raw = snn.to_bytes()
        assert len(raw) == 6
        assert snn.compute_crc() != 0
        assert snn.network_id_word == (0x1975 ^ 0x5678 ^ 0x1234)

        parsed = SafetyNetworkNumber.from_bytes(raw)
        assert parsed.date_word == snn.date_word
        assert parsed.time_mac_dword == snn.time_mac_dword

    def test_snn_mismatch_rejection(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify telegram from alien SNN is rejected."""
        master = safety_master
        master.is_active = True
        master.register_node(mac_id=5)

        snn_alien = SafetyNetworkNumber(date_word=0x9999, time_mac_dword=0x88888888)
        payload = RedundantSafetyPayload.create(
            data=b"\x01\x02\x03\x04",
            sequence_num=1,
            timestamp_ms=master.current_time_ms,
            snn=snn_alien,
        )
        ok = master.process_safety_telegram(mac_id=5, payload=payload, received_snn=snn_alien)
        assert ok is False
        assert master.safety_tripped is True
        assert master.reg_table.read_uword("%R1037") == DeviceNetDiagnosticCode.DEVICENET_ERR_INVERTED_CRC_MISMATCH


# ============================================================================
# Section 5: EPI Timeout Detection & Sequence Number Tracking
# ============================================================================


class TestSection5EPITimeoutAndSequenceTracking:
    """Tests for Expected Packet Interval (EPI) Watchdog and Sequence Tracking."""

    def test_epi_timeout_trips_0xA701_and_clears_m240(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify watchdog timeout (> EPI * 3) triggers 0xA701 and zeroes process data."""
        master = safety_master
        master.is_active = True
        master.primary_pv = 55.4
        master.secondary_pv = 22.1
        master.step_scan_cycle(dt_ms=10.0)

        assert master.reg_table.read_bit("%M240") is True
        assert master.reg_table.read_bit("%M241") is False

        # Timeout threshold is 20ms * 3 = 60ms. Advance 65ms.
        master.current_time_ms += 65.0
        tripped = master.check_epi_watchdog()

        assert tripped is True
        assert master.reg_table.read_bit("%M240") is False
        assert master.reg_table.read_bit("%M241") is True
        assert master.reg_table.read_uword("%R1037") == DeviceNetDiagnosticCode.DEVICENET_ERR_EPI_TIMEOUT
        assert master.reg_table.read_word("%R1033") == 0
        assert master.reg_table.read_word("%R1034") == 0

    def test_epi_nominal_packets_keep_safety_active(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify telegrams arriving within nominal EPI interval maintain healthy active state."""
        master = safety_master
        master.is_active = True
        master.register_node(mac_id=1)

        for c in range(1, 6):
            payload = RedundantSafetyPayload.create(
                data=struct.pack("<hh", c * 100, c * 200),
                sequence_num=c,
                timestamp_ms=float(c * 15),
                snn=master.snn,
            )
            ok = master.process_safety_telegram(mac_id=1, payload=payload, arrival_time_ms=float(c * 15))
            assert ok is True
            assert master.check_epi_watchdog() is False
            assert master.is_operational is True

    def test_sequence_monotonicity_and_replay_detection(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify replay of stale sequence numbers is detected and rejected."""
        master = safety_master
        master.is_active = True
        master.register_node(mac_id=6)

        p1 = RedundantSafetyPayload.create(data=b"\x10\x20", sequence_num=1, timestamp_ms=0.0, snn=master.snn)
        p2 = RedundantSafetyPayload.create(data=b"\x10\x20", sequence_num=2, timestamp_ms=10.0, snn=master.snn)

        assert master.process_safety_telegram(mac_id=6, payload=p1, arrival_time_ms=0.0) is True
        assert master.process_safety_telegram(mac_id=6, payload=p2, arrival_time_ms=10.0) is True

        # Replay sequence 2
        p_replay = RedundantSafetyPayload.create(data=b"\x10\x20", sequence_num=2, timestamp_ms=20.0, snn=master.snn)
        assert master.process_safety_telegram(mac_id=6, payload=p_replay, arrival_time_ms=20.0) is False
        assert master.safety_tripped is True

    def test_sequence_gap_detection(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify missing packets / sequence gaps are detected and rejected."""
        master = safety_master
        master.is_active = True
        master.register_node(mac_id=7)

        p1 = RedundantSafetyPayload.create(data=b"\x05\x05", sequence_num=1, timestamp_ms=0.0, snn=master.snn)
        p3 = RedundantSafetyPayload.create(data=b"\x05\x05", sequence_num=3, timestamp_ms=20.0, snn=master.snn)  # gap

        assert master.process_safety_telegram(mac_id=7, payload=p1, arrival_time_ms=0.0) is True
        assert master.process_safety_telegram(mac_id=7, payload=p3, arrival_time_ms=20.0) is False
        assert master.safety_tripped is True

    def test_time_expectation_and_latency_limit(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify transport delay exceeding maximum tolerable delay triggers safety trip."""
        master = safety_master
        master.is_active = True
        master.register_node(mac_id=9)

        # Excess latency (> DEVICENET_MAX_TOLERABLE_DELAY_MS = 50ms)
        p_delayed = RedundantSafetyPayload.create(data=b"\x01\x02", sequence_num=1, timestamp_ms=0.0, snn=master.snn)
        assert master.process_safety_telegram(mac_id=9, payload=p_delayed, arrival_time_ms=65.0) is False
        assert master.safety_tripped is True
        assert master.reg_table.read_uword("%R1037") == DeviceNetDiagnosticCode.DEVICENET_ERR_EPI_TIMEOUT


# ============================================================================
# Section 6: Process Safety Trips (0xA701..0xA704) & Horner Coil Assertion
# ============================================================================


class TestSection6ProcessSafetyTrips:
    """Tests for Process Safety Trips (0xA701, 0xA702, 0xA703, 0xA704) and Horner Coils."""

    def test_trip_0xa701_epi_timeout(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """0xA701 EPI connection timeout asserts %M241, clears %M240, and sets %R1037."""
        master = safety_master
        master.is_active = True
        master.trigger_safety_trip(DeviceNetDiagnosticCode.DEVICENET_ERR_EPI_TIMEOUT)

        assert master.reg_table.read_bit("%M240") is False
        assert master.reg_table.read_bit("%M241") is True
        assert master.reg_table.read_uword("%R1037") == 0xA701
        assert master.is_safety_tripped is True
        status = master.reg_table.read_uword("%R1030")
        assert bool(status & DeviceNetSafetyStatusBits.EPI_TIMEOUT_TRIP) is True

    def test_trip_0xa702_redundant_payload_crc_mismatch(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """0xA702 Redundant inverted payload / CRC mismatch asserts %M241, clears %M240, and sets %R1037."""
        master = safety_master
        master.is_active = True
        master.trigger_safety_trip(DeviceNetDiagnosticCode.DEVICENET_ERR_INVERTED_CRC_MISMATCH)

        assert master.reg_table.read_bit("%M240") is False
        assert master.reg_table.read_bit("%M241") is True
        assert master.reg_table.read_uword("%R1037") == 0xA702
        assert master.is_safety_tripped is True
        status = master.reg_table.read_uword("%R1030")
        assert bool(status & DeviceNetSafetyStatusBits.CRC_MISMATCH_TRIP) is True

    def test_trip_0xa703_can_bus_off(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """0xA703 CAN bus off fault asserts %M241, clears %M240, and sets %R1037."""
        master = safety_master
        master.is_active = True
        master.trigger_safety_trip(DeviceNetDiagnosticCode.DEVICENET_ERR_CAN_BUS_OFF)

        assert master.reg_table.read_bit("%M240") is False
        assert master.reg_table.read_bit("%M241") is True
        assert master.reg_table.read_uword("%R1037") == 0xA703
        assert master.is_safety_tripped is True
        status = master.reg_table.read_uword("%R1030")
        assert bool(status & DeviceNetSafetyStatusBits.BUS_OFF_TRIP) is True

    def test_trip_0xa704_duplicate_mac_id(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """0xA704 Duplicate MAC ID collision asserts %M241, clears %M240, and sets %R1037."""
        master = safety_master
        master.is_active = True
        master.trigger_safety_trip(DeviceNetDiagnosticCode.DEVICENET_ERR_DUPLICATE_MAC_ID)

        assert master.reg_table.read_bit("%M240") is False
        assert master.reg_table.read_bit("%M241") is True
        assert master.reg_table.read_uword("%R1037") == 0xA704
        assert master.is_safety_tripped is True
        status = master.reg_table.read_uword("%R1030")
        assert bool(status & DeviceNetSafetyStatusBits.DUPLICATE_MAC_TRIP) is True

    def test_operator_manual_reset_handshake(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify operator reset clears trips and restores normal operation."""
        master = safety_master
        master.is_active = True
        master.trigger_safety_trip(DeviceNetDiagnosticCode.DEVICENET_ERR_EPI_TIMEOUT)

        assert master.reg_table.read_bit("%M240") is False
        assert master.reg_table.read_bit("%M241") is True

        master.reset_safety()
        assert master.reg_table.read_bit("%M240") is True
        assert master.reg_table.read_bit("%M241") is False
        assert master.reg_table.read_uword("%R1037") == 0x0000
        assert master.is_safety_tripped is False


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1030..%R1037)
# ============================================================================


class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS memory map %R1030..%R1037 and %M240..%M241."""

    def test_full_register_map_and_scaling(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify scaling float x10 and all register bindings."""
        master = safety_master
        master.is_active = True
        master.register_node(mac_id=1)
        master.register_node(mac_id=2)

        master.step_scan_cycle(dt_ms=20.0, primary_pv=28.7, secondary_pv=-9.4)

        rt = master.reg_table
        r1030 = rt.read_uword("%R1030")
        assert (r1030 >> 8) & 0x7F == 2  # 2 active nodes
        assert bool(r1030 & DeviceNetSafetyStatusBits.MASTER_ACTIVE) is True

        assert rt.read_uword("%R1031") == master.snn.network_id_word
        assert rt.read_uword("%R1032") == 1  # cycle 1
        assert rt.read_word("%R1033") == 287   # 28.7 x 10
        assert rt.read_word("%R1034") == -94   # -9.4 x 10
        assert rt.read_uword("%R1035") == 0
        assert rt.read_uword("%R1037") == 0x0000
        assert rt.read_bit("%M240") is True
        assert rt.read_bit("%M241") is False

    def test_engineering_unit_scaling_helper(self) -> None:
        """Verify scale_safety_pv_to_int16 scaling and clamping to signed INT16 boundaries."""
        assert scale_safety_pv_to_int16(55.4) == 554
        assert scale_safety_pv_to_int16(-12.8) == -128
        assert scale_safety_pv_to_int16(5000.0) == 32767   # Clamped max
        assert scale_safety_pv_to_int16(-5000.0) == -32768  # Clamped min

    def test_sdo_transactions_update_r1036_and_status(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify SDO transactions increment counter %R1036 and assert SDO_ACTIVE."""
        master = safety_master
        assert master.reg_table.read_uword("%R1036") == 0

        res_read = master.execute_sdo_read(mac_id=1, index=0x1000, subindex=0)
        assert len(res_read) == 4
        assert master.reg_table.read_uword("%R1036") == 1

        res_write = master.execute_sdo_write(mac_id=1, index=0x1301, subindex=1, data=b"\x01")
        assert res_write is True
        assert master.reg_table.read_uword("%R1036") == 2

    def test_mac_id_scanner_updates_r1030_node_count(self, safety_master: DeviceNetSafetyMasterEngine) -> None:
        """Verify scanning discovered nodes updates active node count in %R1030."""
        master = safety_master
        nodes = [1, 2, 3, 4, 10, 20, 63]
        count = master.scan_network_nodes(nodes)
        assert count == len(nodes)
        assert master.active_node_count == len(nodes)

        r1030 = master.reg_table.read_uword("%R1030")
        active_in_r1030 = (r1030 >> 8) & 0x7F
        assert active_in_r1030 == len(nodes)


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================


class TestSection8VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_devicenet_safety_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_devicenet_safety_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9
        for t in result["data"]["tests"]:
            assert t["passed"] is True

    def test_run_devicenet_safety_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "devicenet_safety_evidence.json"
        result = run_devicenet_safety_verification(output_path=evidence_file)

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W142"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert "DeviceNet" in data["data"]["component"]
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9

        reg_map = data["data"]["register_map"]
        assert "%R1030" in reg_map
        assert "%R1031" in reg_map
        assert "%R1032" in reg_map
        assert "%R1033" in reg_map
        assert "%R1034" in reg_map
        assert "%R1035" in reg_map
        assert "%R1036" in reg_map
        assert "%R1037" in reg_map
        assert "%M240" in reg_map
        assert "%M241" in reg_map

    def test_evidence_metrics_schema(self) -> None:
        """Verify evidence metrics dictionary has all expected fields."""
        result = run_devicenet_safety_verification()
        metrics = result["data"]["metrics"]
        assert metrics["master_mac_id"] == 0
        assert metrics["supported_baud_rates"] == [125000, 250000, 500000]
        assert metrics["default_epi_ms"] == 20.0
        assert metrics["max_reaction_time_ms"] == 20.0
        assert metrics["max_nodes"] == 64
