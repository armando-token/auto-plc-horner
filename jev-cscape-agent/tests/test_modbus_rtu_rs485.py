"""Unit and Integration Test Suite for Industrial Modbus RTU Over RS-485 Engine.

Work Package: W169 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation
   (%R1300..%R1307, %M303..%M304).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: RS-485 character timing math (11 bits), t1.5 inter-character gap, and t3.5 inter-frame silent interval at various baud rates.
4. Section 4: Half-duplex turnaround delay (500 us) and transceiver driver enable/disable direction control.
5. Section 5: Modbus RTU CRC-16 calculation, verification, and corruption detection.
6. Section 6: Transceiver bus state machine transitions
   (BUS_IDLE -> RECEIVING -> SILENT_INTERVAL_T35 -> TRANSMITTING -> TURNAROUND_WAIT -> BUS_COLLISION_FAULT).
7. Section 7: Process safety trips (0xC201, 0xC202, 0xC203, 0xC204) and Horner coil assertion (%M303, %M304).
8. Section 8: Horner OCS register space synchronization (%R1300..%R1307, %M303..%M304) with PrivilegeMode.SYSTEM.
9. Section 9: ILogicUnit interface compliance and 9-stage verification suite integration test.
"""

from __future__ import annotations

import json
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
from jev_cscape.telemetry.modbus_rtu_rs485 import (
    MODBUS_RTU_BITS_PER_CHAR,
    MODBUS_RTU_DEFAULT_BAUD,
    MODBUS_RTU_DEFAULT_BAUD_CODE,
    MODBUS_RTU_FIXED_T15_US,
    MODBUS_RTU_FIXED_T35_US,
    MODBUS_RTU_NOMINAL_TURNAROUND_US,
    MODBUS_RTU_RS485_SYNC_POU,
    PURE_ST_POU,
    RS485_HALF_DUPLEX_TIMING_SYNC_POU,
    SUPPORTED_BAUD_RATES,
    ModbusBaudRate,
    ModbusRtuBusStateBits,
    ModbusRtuCharacterOverrunError,
    ModbusRtuDiagnosticCode,
    ModbusRtuEngine,
    ModbusRtuFrame,
    ModbusRtuFrameCrcMismatchError,
    ModbusRtuRs485Engine,
    ModbusRtuRs485Error,
    ModbusRtuSilentIntervalViolationError,
    ModbusRtuTurnaroundCollisionError,
    Rs485BusStateBits,
    Rs485TransceiverState,
    baud_to_code,
    calculate_char_time_us,
    calculate_t15_us,
    calculate_t35_us,
    code_to_baud,
    compute_modbus_crc16,
    decode_slave_function_word,
    encode_slave_function_word,
    run_modbus_rtu_rs485_verification,
    verify_modbus_crc16,
    verify_modbus_rtu_rs485_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def rtu_engine(register_table: RegisterTable) -> ModbusRtuRs485Engine:
    """Provide a fresh Modbus RTU RS-485 slave engine bound to register table."""
    return ModbusRtuRs485Engine(
        slave_address=1,
        baud_rate=19200,
        turnaround_delay_us=500.0,
        is_master=False,
        register_table=register_table,
    )


@pytest.fixture
def master_engine(register_table: RegisterTable) -> ModbusRtuRs485Engine:
    """Provide a fresh Modbus RTU RS-485 master engine bound to register table."""
    return ModbusRtuRs485Engine(
        slave_address=1,
        baud_rate=19200,
        turnaround_delay_us=500.0,
        is_master=True,
        register_table=register_table,
    )


# ============================================================================
# 1. Pure ST POU AST Validation & Register Binding (%R1300..%R1307, %M303..%M304)
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU compliance and register bindings."""

    def test_verify_modbus_rtu_rs485_pure_st_helper(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_modbus_rtu_rs485_pure_st() is True

    def test_pure_st_pou_ast_parsing_primary(self) -> None:
        """Parse MODBUS_RTU_RS485_SYNC_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(MODBUS_RTU_RS485_SYNC_POU)
        assert pou is not None
        assert pou.name == "ModbusRtuRs485Sync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "BaudRateCode",
            "SilentIntervalT35Microseconds",
            "TurnaroundDelayMicroseconds",
            "FrameTransmissionCounter",
            "Crc16ErrorCounter",
            "BusStateWord",
            "SlaveAddressAndFunctionWord",
            "DiagnosticStatusCode",
            "ModbusRtuPermissive",
            "ModbusRtuFaultTrip",
            "BusOperational",
        }
        assert expected_vars.issubset(var_names)

        bound = set(pou.bound_registers)
        expected_regs = {
            "%R1300", "%R1301", "%R1302", "%R1303",
            "%R1304", "%R1305", "%R1306", "%R1307",
            "%M303", "%M304",
        }
        assert bound == expected_regs

    def test_pure_st_pou_ast_parsing_alias(self) -> None:
        """Parse RS485_HALF_DUPLEX_TIMING_SYNC_POU alias with STParser."""
        parser = STParser()
        pou = parser.parse_pou(RS485_HALF_DUPLEX_TIMING_SYNC_POU)
        assert pou is not None
        assert pou.name == "Rs485HalfDuplexTimingSync"
        assert pou.pou_type == POUType.PROGRAM

        bound = set(pou.bound_registers)
        expected_regs = {
            "%R1300", "%R1301", "%R1302", "%R1303",
            "%R1304", "%R1305", "%R1306", "%R1307",
            "%M303", "%M304",
        }
        assert bound == expected_regs

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify both POUs pass SecurityGuard assertion cleanly."""
        SecurityGuard.assert_pure_st_content(MODBUS_RTU_RS485_SYNC_POU)
        SecurityGuard.assert_pure_st_content(RS485_HALF_DUPLEX_TIMING_SYNC_POU)
        SecurityGuard.assert_pure_st_content(PURE_ST_POU)


# ============================================================================
# 2. Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests verifying ladder logic constructs are strictly rejected."""

    def test_ladder_contacts_rejected(self) -> None:
        """Reject ASCII ladder contacts ---[ ]--- and inverted ---[/]---."""
        bad_st_1 = "PROGRAM BadContacts\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadContactsInv\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_coils_rejected(self) -> None:
        """Reject ASCII ladder coils ---( )---, set ---(S)---, and reset ---(R)---."""
        bad_st_1 = "PROGRAM BadCoils\nVAR Y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadCoilsSet\nVAR Y: BOOL; END_VAR\n---(S)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_mnemonics_rejected(self) -> None:
        """Reject ladder mnemonics XIC, OTE, OTL, OTU, and RUNG blocks."""
        bad_st_1 = "PROGRAM BadMnemonics\nVAR Z: BOOL; END_VAR\nRUNG 1: XIC %M1 OTE %M2 END_RUNG\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadNetwork\nVAR W: BOOL; END_VAR\nNETWORK 1\nOTL %M303\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 3. RS-485 Character Timing Math (11 Bits), t1.5, & t3.5 Silent Intervals
# ============================================================================

class TestSection3RS485TimingMath:
    """Tests for 11-bit serial character, t1.5, and t3.5 timing calculations."""

    def test_character_time_calculations(self) -> None:
        """Verify 11-bit character duration across supported baud rates."""
        assert MODBUS_RTU_BITS_PER_CHAR == 11
        assert SUPPORTED_BAUD_RATES == (9600, 19200, 38400, 57600, 115200)

        # 9600 bps: 11 * 1e6 / 9600 = 1145.833... us
        assert pytest.approx(calculate_char_time_us(9600), rel=1e-4) == 1145.8333
        # 19200 bps: 11 * 1e6 / 19200 = 572.916... us
        assert pytest.approx(calculate_char_time_us(19200), rel=1e-4) == 572.9167
        # 38400 bps: 11 * 1e6 / 38400 = 286.458... us
        assert pytest.approx(calculate_char_time_us(38400), rel=1e-4) == 286.4583
        # 57600 bps: 11 * 1e6 / 57600 = 190.972... us
        assert pytest.approx(calculate_char_time_us(57600), rel=1e-4) == 190.9722
        # 115200 bps: 11 * 1e6 / 115200 = 95.486... us
        assert pytest.approx(calculate_char_time_us(115200), rel=1e-4) == 95.4861

    def test_invalid_baud_rate_raises(self) -> None:
        """Verify non-positive baud rate raises ValueError."""
        with pytest.raises(ValueError):
            calculate_char_time_us(0)
        with pytest.raises(ValueError):
            calculate_char_time_us(-9600)

    def test_inter_character_gap_t15(self) -> None:
        """Verify t1.5 calculation per Modbus Serial Line Protocol v1.02."""
        # For <= 19200 bps: t1.5 = 1.5 * char_time
        t15_9600 = calculate_t15_us(9600)
        assert pytest.approx(t15_9600, rel=1e-4) == 1.5 * 1145.8333
        assert pytest.approx(t15_9600, rel=1e-4) == 1718.75

        t15_19200 = calculate_t15_us(19200)
        assert pytest.approx(t15_19200, rel=1e-4) == 1.5 * 572.9167
        assert pytest.approx(t15_19200, rel=1e-4) == 859.375

        # For > 19200 bps: fixed 750.0 us
        assert calculate_t15_us(38400) == MODBUS_RTU_FIXED_T15_US
        assert calculate_t15_us(38400) == 750.0
        assert calculate_t15_us(57600) == 750.0
        assert calculate_t15_us(115200) == 750.0

    def test_inter_frame_silent_interval_t35(self) -> None:
        """Verify t3.5 calculation per Modbus Serial Line Protocol v1.02."""
        # For <= 19200 bps: t3.5 = 3.5 * char_time
        t35_9600 = calculate_t35_us(9600)
        assert pytest.approx(t35_9600, rel=1e-4) == 3.5 * 1145.8333
        assert pytest.approx(t35_9600, rel=1e-4) == 4010.4167

        t35_19200 = calculate_t35_us(19200)
        assert pytest.approx(t35_19200, rel=1e-4) == 3.5 * 572.9167
        assert pytest.approx(t35_19200, rel=1e-4) == 2005.2083

        # For > 19200 bps: fixed 1750.0 us
        assert calculate_t35_us(38400) == MODBUS_RTU_FIXED_T35_US
        assert calculate_t35_us(38400) == 1750.0
        assert calculate_t35_us(57600) == 1750.0
        assert calculate_t35_us(115200) == 1750.0

    def test_baud_code_conversions(self) -> None:
        """Verify BaudRateCode integer mapping (bps // 100)."""
        assert baud_to_code(9600) == 96
        assert baud_to_code(19200) == 192
        assert baud_to_code(38400) == 384
        assert baud_to_code(57600) == 576
        assert baud_to_code(115200) == 1152

        assert code_to_baud(96) == 9600
        assert code_to_baud(192) == 19200
        assert code_to_baud(384) == 38400
        assert code_to_baud(576) == 57600
        assert code_to_baud(1152) == 115200


# ============================================================================
# 4. Half-Duplex Turnaround Delay (500 us) & Direction Control (RTS/DE/~RE)
# ============================================================================

class TestSection4TurnaroundAndDirectionControl:
    """Tests for half-duplex direction control and 500 us turnaround delay."""

    def test_initial_transceiver_direction_signals(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify initial quiescent transceiver state: DE=0, ~RE=0, RTS=0 (listening)."""
        signals = rtu_engine.get_transceiver_signals()
        assert signals["DE"] is False
        assert signals["RE_N"] is False
        assert signals["RTS"] is False
        assert rtu_engine.turnaround_delay_us == MODBUS_RTU_NOMINAL_TURNAROUND_US
        assert rtu_engine.turnaround_delay_us == 500.0

    def test_transmitting_asserts_driver_signals(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify transmitting asserts RTS, DE, and negates ~RE (receiver disabled)."""
        frame = ModbusRtuFrame(slave_address=1, function_code=3, pdu_data=b"\x00\x00\x00\x01")
        res = rtu_engine.transmit_frame(frame, force=True)
        assert res.status == AgentStatus.SUCCESS

        signals = rtu_engine.get_transceiver_signals()
        assert signals["DE"] is True
        assert signals["RTS"] is True
        assert signals["RE_N"] is True  # Receiver disabled during half-duplex TX
        assert rtu_engine.state == Rs485TransceiverState.TRANSMITTING

    def test_turnaround_delay_sequence_on_tx_completion(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify transmission completes into TURNAROUND_WAIT (DE=0, ~RE=1) for 500 us."""
        frame = ModbusRtuFrame(slave_address=1, function_code=3, pdu_data=b"\x00\x00\x00\x01")
        rtu_engine.transmit_frame(frame, force=True)
        tx_dur_us = rtu_engine.tx_remaining_us

        # Advance clock to just finish transmission
        rtu_engine.scan_step(dt=tx_dur_us / 1_000_000.0)

        # Transceiver must enter TURNAROUND_WAIT: DE drops to 0, ~RE remains 1 (settling)
        assert rtu_engine.state == Rs485TransceiverState.TURNAROUND_WAIT
        signals = rtu_engine.get_transceiver_signals()
        assert signals["DE"] is False
        assert signals["RTS"] is False
        assert signals["RE_N"] is True
        assert pytest.approx(rtu_engine.turnaround_remaining_us, abs=1.0) == 500.0

        # Advance 250 us (halfway through turnaround delay)
        rtu_engine.scan_step(dt=0.00025)
        assert rtu_engine.state == Rs485TransceiverState.TURNAROUND_WAIT
        assert rtu_engine.get_transceiver_signals()["RE_N"] is True

        # Advance remaining 260 us (completing turnaround delay)
        rtu_engine.scan_step(dt=0.00026)
        assert rtu_engine.state == Rs485TransceiverState.SILENT_INTERVAL_T35
        # Receiver re-enabled!
        assert rtu_engine.get_transceiver_signals()["RE_N"] is False

    def test_set_baud_rate_recomputes_timings(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify dynamic baud rate configuration recomputes character and silent interval timers."""
        rtu_engine.set_baud_rate(38400)
        assert rtu_engine.baud_rate == 38400
        assert rtu_engine.t15_us == 750.0
        assert rtu_engine.t35_us == 1750.0
        assert rtu_engine.reg_table.read_word("%R1300") == 384
        assert rtu_engine.reg_table.read_word("%R1301") == 1750

        with pytest.raises(ValueError):
            rtu_engine.set_baud_rate(12345)


# ============================================================================
# 5. Modbus RTU CRC-16 Calculation, Verification, & Serialization
# ============================================================================

class TestSection5ModbusCRC16AndFrames:
    """Tests for Modbus RTU CRC-16 (0xA001/0xFFFF) and frame serialization."""

    def test_compute_modbus_crc16_standard_vectors(self) -> None:
        """Verify CRC-16 against known standard Modbus vectors."""
        # Standard Modbus query: Slave 1, FC 3, Addr 0x006B, Qty 0x0003
        data1 = b"\x01\x03\x00\x6B\x00\x03"
        crc1 = compute_modbus_crc16(data1)
        assert crc1 == 0x1774
        # On wire, little-endian: [0x74, 0x17]
        wire_crc = struct.pack("<H", crc1)
        assert wire_crc == b"\x74\x17"

        # Another query: Slave 2, FC 4, Addr 0x0000, Qty 0x000A
        data2 = b"\x02\x04\x00\x00\x00\x0A"
        crc2 = compute_modbus_crc16(data2)
        assert crc2 == 0x3E70
        assert struct.pack("<H", crc2) == b"\x70\x3E"

    def test_verify_modbus_crc16_valid(self) -> None:
        """Verify valid frames pass verify_modbus_crc16."""
        full_frame = b"\x01\x03\x00\x6B\x00\x03\x74\x17"
        assert verify_modbus_crc16(full_frame) is True

    def test_verify_modbus_crc16_corrupted(self) -> None:
        """Verify flipped bit in CRC fails verification."""
        bad_frame = b"\x01\x03\x00\x6B\x00\x03\x74\x18"
        assert verify_modbus_crc16(bad_frame) is False

    def test_verify_modbus_crc16_truncated(self) -> None:
        """Verify frames shorter than 4 bytes fail verification."""
        assert verify_modbus_crc16(b"\x01\x03\x00") is False
        assert verify_modbus_crc16(b"") is False

    def test_frame_serialization_and_deserialization_roundtrip(self) -> None:
        """Verify ModbusRtuFrame serialize and deserialize roundtrip."""
        frame = ModbusRtuFrame(
            slave_address=1,
            function_code=3,
            pdu_data=b"\x00\x6B\x00\x03",
        )
        assert frame.slave_function_word == encode_slave_function_word(1, 3)
        assert frame.slave_function_word == 0x0103
        assert frame.total_length == 8

        wire_bytes = frame.serialize()
        assert wire_bytes == b"\x01\x03\x00\x6B\x00\x03\x74\x17"

        parsed = ModbusRtuFrame.deserialize(wire_bytes)
        assert parsed.slave_address == 1
        assert parsed.function_code == 3
        assert parsed.pdu_data == b"\x00\x6B\x00\x03"
        assert parsed.crc == 0x1774

    def test_frame_deserialize_crc_mismatch_raises(self) -> None:
        """Verify deserialization of corrupted frame raises ModbusRtuFrameCrcMismatchError."""
        bad_bytes = b"\x01\x03\x00\x6B\x00\x03\xAA\xBB"
        with pytest.raises(ModbusRtuFrameCrcMismatchError, match="CRC mismatch"):
            ModbusRtuFrame.deserialize(bad_bytes)

    def test_frame_deserialize_truncated_raises(self) -> None:
        """Verify deserialization of truncated frame raises ModbusRtuFrameCrcMismatchError."""
        with pytest.raises(ModbusRtuFrameCrcMismatchError, match="truncated"):
            ModbusRtuFrame.deserialize(b"\x01\x03")

    def test_slave_function_word_encoding_decoding(self) -> None:
        """Verify slave address and function code packing into UINT16 (%R1306)."""
        word = encode_slave_function_word(slave_address=0x05, function_code=0x10)
        assert word == 0x0510
        slave, fc = decode_slave_function_word(word)
        assert slave == 0x05
        assert fc == 0x10


# ============================================================================
# 6. Transceiver Bus State Machine Transitions
# ============================================================================

class TestSection6BusStateMachineTransitions:
    """Tests verifying RS-485 transceiver state machine lifecycle."""

    def test_state_enum_values(self) -> None:
        """Verify state machine enum identifiers."""
        assert Rs485TransceiverState.BUS_IDLE == 0
        assert Rs485TransceiverState.RECEIVING == 1
        assert Rs485TransceiverState.SILENT_INTERVAL_T35 == 2
        assert Rs485TransceiverState.TRANSMITTING == 3
        assert Rs485TransceiverState.TURNAROUND_WAIT == 4
        assert Rs485TransceiverState.BUS_COLLISION_FAULT == 5

    def test_complete_tx_lifecycle_transition(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify IDLE -> TRANSMITTING -> TURNAROUND_WAIT -> SILENT_INTERVAL_T35 -> BUS_IDLE."""
        assert rtu_engine.state == Rs485TransceiverState.BUS_IDLE

        frame = ModbusRtuFrame(slave_address=1, function_code=3, pdu_data=b"\x00\x01\x00\x01")
        rtu_engine.transmit_frame(frame, force=True)
        assert rtu_engine.state == Rs485TransceiverState.TRANSMITTING

        # Finish transmit duration
        rtu_engine.scan_step(dt=rtu_engine.tx_remaining_us / 1_000_000.0)
        assert rtu_engine.state == Rs485TransceiverState.TURNAROUND_WAIT

        # Finish turnaround delay
        rtu_engine.scan_step(dt=rtu_engine.turnaround_remaining_us / 1_000_000.0)
        assert rtu_engine.state == Rs485TransceiverState.SILENT_INTERVAL_T35

        # Finish t3.5 inter-frame silence
        rtu_engine.scan_step(dt=rtu_engine.t35_us / 1_000_000.0)
        assert rtu_engine.state == Rs485TransceiverState.BUS_IDLE

    def test_complete_rx_lifecycle_transition(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify IDLE -> RECEIVING -> (t3.5 frame boundary) -> BUS_IDLE."""
        assert rtu_engine.state == Rs485TransceiverState.BUS_IDLE
        valid_wire = b"\x01\x03\x00\x6B\x00\x03\x74\x17"

        res = rtu_engine.receive_raw_frame(valid_wire, pre_silence_us=3000.0)
        assert res.status == AgentStatus.SUCCESS
        assert rtu_engine.state == Rs485TransceiverState.BUS_IDLE
        assert rtu_engine.committed_rx_frame is not None
        assert rtu_engine.committed_rx_frame.crc == 0x1774
        assert rtu_engine.frame_transmission_counter == 1


# ============================================================================
# 7. Process Safety Trips & Horner Discrete Interlock Assertions (%M303, %M304)
# ============================================================================

class TestSection7ProcessSafetyTrips:
    """Tests for all 4 diagnostic fault codes (0xC201..0xC204) and coil trips."""

    def test_trip_0xc201_silent_interval_violation_on_tx(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """0xC201: Premature transmission before t3.5 asserts %M304 and clears %M303."""
        # Put bus in SILENT_INTERVAL_T35 with only 500 us elapsed (< 2005 us t3.5)
        rtu_engine.state = Rs485TransceiverState.SILENT_INTERVAL_T35
        rtu_engine.silence_elapsed_us = 500.0

        frame = ModbusRtuFrame(slave_address=1, function_code=3)
        res = rtu_engine.transmit_frame(frame, force=False)

        assert res.status == AgentStatus.FAILED
        assert res.error_code == "RTU_ERR_SILENT_INTERVAL_VIOLATION"
        assert rtu_engine.state == Rs485TransceiverState.BUS_COLLISION_FAULT
        assert rtu_engine.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_SILENT_INTERVAL_VIOLATION
        assert rtu_engine.diagnostic_code == 0xC201

        # Check Horner OCS coils and registers
        assert rtu_engine.reg_table.read_bit("%M304") is True   # Fault trip asserted
        assert rtu_engine.reg_table.read_bit("%M303") is False  # Permissive cleared
        assert rtu_engine.reg_table.read_uword("%R1307") == 0xC201

    def test_trip_0xc201_silent_interval_violation_on_rx(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """0xC201: Incoming byte arriving before t3.5 elapses trips safety latch."""
        rtu_engine.silence_elapsed_us = 400.0  # < t3.5 (2005.2 us)
        res = rtu_engine.receive_character(0x01)

        assert res.status == AgentStatus.FAILED
        assert res.error_code == "RTU_ERR_SILENT_INTERVAL_VIOLATION"
        assert rtu_engine.diagnostic_code == 0xC201
        assert rtu_engine.reg_table.read_bit("%M304") is True
        assert rtu_engine.reg_table.read_bit("%M303") is False

    def test_trip_0xc202_turnaround_collision_on_tx_attempt(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """0xC202: Driver enable attempted during turnaround delay trips safety latch."""
        rtu_engine.state = Rs485TransceiverState.TURNAROUND_WAIT
        rtu_engine.turnaround_remaining_us = 300.0

        frame = ModbusRtuFrame(slave_address=1, function_code=3)
        res = rtu_engine.transmit_frame(frame, force=False)

        assert res.status == AgentStatus.FAILED
        assert res.error_code == "RTU_ERR_TURNAROUND_COLLISION"
        assert rtu_engine.state == Rs485TransceiverState.BUS_COLLISION_FAULT
        assert rtu_engine.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION
        assert rtu_engine.diagnostic_code == 0xC202

        assert rtu_engine.reg_table.read_bit("%M304") is True
        assert rtu_engine.reg_table.read_bit("%M303") is False
        assert rtu_engine.reg_table.read_uword("%R1307") == 0xC202

    def test_trip_0xc202_turnaround_collision_on_rx_during_tx(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """0xC202: Bus collision when incoming character detected while transmitting."""
        frame = ModbusRtuFrame(slave_address=1, function_code=3)
        rtu_engine.transmit_frame(frame, force=True)
        assert rtu_engine.state == Rs485TransceiverState.TRANSMITTING

        res = rtu_engine.receive_character(0xAA)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "RTU_ERR_TURNAROUND_COLLISION"
        assert rtu_engine.diagnostic_code == 0xC202
        assert rtu_engine.reg_table.read_bit("%M304") is True

    def test_trip_0xc203_frame_crc16_mismatch(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """0xC203: Corrupted frame CRC increments %R1304, trips %M304, and clears %M303."""
        corrupted_wire = b"\x01\x03\x00\x6B\x00\x03\xFF\xFF"  # Bad CRC
        res = rtu_engine.receive_raw_frame(corrupted_wire, pre_silence_us=3000.0)

        assert res.status == AgentStatus.FAILED
        assert res.error_code == "RTU_ERR_FRAME_CRC16_MISMATCH"
        assert rtu_engine.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_FRAME_CRC16_MISMATCH
        assert rtu_engine.diagnostic_code == 0xC203

        assert rtu_engine.crc16_error_counter == 1
        assert rtu_engine.reg_table.read_word("%R1304") == 1
        assert rtu_engine.reg_table.read_uword("%R1307") == 0xC203
        assert rtu_engine.reg_table.read_bit("%M304") is True
        assert rtu_engine.reg_table.read_bit("%M303") is False

    def test_trip_0xc204_character_overrun(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """0xC204: Inter-character silence > t1.5 mid-frame trips safety latch and discards buffer."""
        rtu_engine.silence_elapsed_us = 3000.0
        # First character accepted
        res1 = rtu_engine.receive_character(0x01)
        assert res1.status == AgentStatus.SUCCESS
        assert rtu_engine.state == Rs485TransceiverState.RECEIVING

        # Inject gap > t1.5 (at 19200 bps, t1.5 = 859.38 us; inject 1500 us)
        res2 = rtu_engine.receive_character(0x03, gap_since_last_char_us=1500.0)

        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "RTU_ERR_CHARACTER_OVERRUN"
        assert rtu_engine.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_CHARACTER_OVERRUN
        assert rtu_engine.diagnostic_code == 0xC204

        assert len(rtu_engine.rx_buffer) == 0  # Buffer discarded
        assert rtu_engine.reg_table.read_uword("%R1307") == 0xC204
        assert rtu_engine.reg_table.read_bit("%M304") is True
        assert rtu_engine.reg_table.read_bit("%M303") is False

    def test_operator_fault_reset_handshake(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify manual operator reset clears latched fault and re-establishes healthy bus."""
        rtu_engine.trigger_fault(ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION)
        assert rtu_engine.fault_trip is True
        assert rtu_engine.reg_table.read_bit("%M304") is True

        res = rtu_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert rtu_engine.fault_trip is False
        assert rtu_engine.permissive is True
        assert rtu_engine.diagnostic_code == ModbusRtuDiagnosticCode.OK
        assert rtu_engine.state == Rs485TransceiverState.BUS_IDLE

        assert rtu_engine.reg_table.read_bit("%M304") is False
        assert rtu_engine.reg_table.read_bit("%M303") is True
        assert rtu_engine.reg_table.read_uword("%R1307") == 0x0000


# ============================================================================
# 8. Horner OCS Register Space Synchronization & PrivilegeMode.SYSTEM
# ============================================================================

class TestSection8RegisterSpaceSynchronization:
    """Tests for %R1300..%R1307 and %M303..%M304 Horner memory bindings."""

    def test_complete_register_layout_at_19200_bps(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify exact values across %R1300..%R1307 and %M303..%M304."""
        rt = rtu_engine.reg_table
        # %R1300: BaudRateCode (192)
        assert rt.read_word("%R1300") == 192
        # %R1301: SilentIntervalT35Microseconds (2005)
        assert rt.read_word("%R1301") == 2005
        # %R1302: TurnaroundDelayMicroseconds (500)
        assert rt.read_word("%R1302") == 500
        # %R1303: FrameTransmissionCounter (0)
        assert rt.read_uword("%R1303") == 0
        # %R1304: Crc16ErrorCounter (0)
        assert rt.read_word("%R1304") == 0
        # %R1305: BusStateWord (bitmask with PERMISSIVE bit set)
        bus_word = rt.read_word("%R1305")
        assert (bus_word & ModbusRtuBusStateBits.PERMISSIVE) != 0
        # %R1306: SlaveAddressAndFunctionWord (slave=1, fc=0 -> 0x0100)
        assert rt.read_uword("%R1306") == 0x0100
        # %R1307: DiagnosticStatusCode (0x0000)
        assert rt.read_uword("%R1307") == 0x0000
        # Discrete coils
        assert rt.read_bit("%M303") is True
        assert rt.read_bit("%M304") is False

    def test_master_mode_flag_in_bus_state_word(self, master_engine: ModbusRtuRs485Engine) -> None:
        """Verify master node asserts MASTER_MODE bit (bit 15) in %R1305."""
        bus_word = master_engine.reg_table.read_uword("%R1305")
        assert (bus_word & Rs485BusStateBits.MASTER_MODE) != 0

    def test_bus_state_word_bitmask_flags(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify bitmask flags correspond to transceiver states."""
        # Idle state
        word = rtu_engine.compute_bus_state_word()
        assert (word & Rs485BusStateBits.PERMISSIVE) != 0
        assert (word & Rs485BusStateBits.FAULT_TRIP) == 0

        # Transmitting state
        frame = ModbusRtuFrame(slave_address=1, function_code=3)
        rtu_engine.transmit_frame(frame, force=True)
        word_tx = rtu_engine.compute_bus_state_word()
        assert (word_tx & Rs485BusStateBits.DRIVER_ENABLE) != 0
        assert (word_tx & Rs485BusStateBits.RECEIVER_DISABLE) != 0
        assert (word_tx & Rs485BusStateBits.REQUEST_TO_SEND) != 0

        # Trip state
        rtu_engine.trigger_fault(ModbusRtuDiagnosticCode.RTU_ERR_FRAME_CRC16_MISMATCH)
        word_trip = rtu_engine.compute_bus_state_word()
        assert (word_trip & Rs485BusStateBits.FAULT_TRIP) != 0
        assert (word_trip & Rs485BusStateBits.CRC_ERROR) != 0


# ============================================================================
# 9. ILogicUnit Interface Compliance & Verification Suite Integration
# ============================================================================

class TestSection9ILogicUnitAndVerificationSuite:
    """Tests verifying simulation engine ILogicUnit interface and 9-stage verification suite."""

    def test_ilogicunit_properties_and_execution(self, rtu_engine: ModbusRtuRs485Engine) -> None:
        """Verify name, priority, is_enabled, execute with ScanContext, and reset."""
        assert rtu_engine.name == "modbus_rtu_rs485"
        assert rtu_engine.priority == 95
        assert rtu_engine.is_enabled is True

        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda addr: rtu_engine.reg_table.read_register(addr),
            set_register=lambda addr, val: rtu_engine.reg_table.write_register(addr, val, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: None,
            set_variable=lambda k, v: None,
            record_fault=lambda fault: None,
        )
        rtu_engine.execute(ctx)
        assert rtu_engine.elapsed_time_us >= 10_000.0

        rtu_engine.trigger_fault(ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION)
        assert rtu_engine.fault_trip is True
        rtu_engine.reset()
        assert rtu_engine.fault_trip is False

    def test_run_modbus_rtu_rs485_verification_suite(self) -> None:
        """Execute 9-stage verification suite, assert all pass, and verify evidence JSON file."""
        with tempfile.TemporaryDirectory() as td:
            output_file = Path(td) / "modbus_rtu_rs485_evidence.json"
            res = run_modbus_rtu_rs485_verification(output_path=output_file)

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
            assert len(res["data"]["tests"]) == 9

            for t in res["data"]["tests"]:
                assert t["passed"] is True
                assert "stage" in t
                assert "check" in t

            assert output_file.exists()
            with open(output_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert saved["data"]["checks_passed"] == 9
            assert saved["data"]["work_package"] == "W169"
            assert saved["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
            assert saved["data"]["register_map"]["analog_registers"] == "%R1300..%R1307"
            assert saved["data"]["register_map"]["discrete_coils"] == "%M303..%M304"
