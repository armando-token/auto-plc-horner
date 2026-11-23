"""Industrial Modbus RTU Over RS-485 Half-Duplex Turnaround & Inter-Frame Silent Interval Engine.

Work Package: W169 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- Modbus Serial Line Protocol and Implementation Guide v1.02 (Modbus-IDA / Modbus Organization)
- TIA/EIA-485-A Electrical Characteristics of Generators and Receivers for Use in Balanced Digital Multipoint Systems
- IEC 61131-3 Programmable Controllers - Part 3: Programming Languages (Structured Text)

Architecture:
1. Pure IEC 61131-3 Structured Text POUs:
   - 'ModbusRtuRs485Sync' (and alias 'Rs485HalfDuplexTimingSync').
   - Bound to Horner OCS registers (%R1300..%R1307, %M303..%M304).
   - Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN using SecurityGuard and STParser.

2. Modbus RTU Over RS-485 Physical / Data-Link Layer:
   - Half-duplex 2-wire serial transmission timing with directional transceiver driver control (RTS / DE / ~RE).
   - Baud rate support (9600, 19200, 38400, 57600, 115200 bps). Default: 19200 bps.
   - Character timing: 11 bits per character (1 start bit, 8 data bits, 1 parity bit, 1 stop bit or 2 stop bits without parity).
   - Inter-character silence limit t1.5: 1.5 character times (or 750 us if baud > 19200). Exceeding t1.5 mid-frame causes character overrun/frame discard.
   - Inter-frame silent interval t3.5: 3.5 character times (or 1750 us if baud > 19200) demarcating start and end of Modbus RTU frames.
   - Turnaround delay: Driver enable/disable delay (nominal 500 us) preventing bus contention during transmitter turn-off and receiver turn-on.
   - CRC-16 (Modbus polynomial 0xA001 / init 0xFFFF, little-endian on wire) calculation and verification.
   - RS-485 transceiver bus state machine: BUS_IDLE, RECEIVING, SILENT_INTERVAL_T35, TRANSMITTING, TURNAROUND_WAIT, BUS_COLLISION_FAULT.
   - Double-buffering and master/slave frame dispatching.
   - Implements ILogicUnit interface with scan_step(dt).

3. Process Safety Interlocks & Diagnostics:
   - 0x0000: OK (Normal healthy serial bus communication)
   - 0xC201: RTU_ERR_SILENT_INTERVAL_VIOLATION (Transmission started before 3.5 character silence elapsed) -> asserts %M304, clears %M303
   - 0xC202: RTU_ERR_TURNAROUND_COLLISION (Direction contention or driver enabled before turnaround delay) -> asserts %M304, clears %M303
   - 0xC203: RTU_ERR_FRAME_CRC16_MISMATCH (Corrupted frame CRC-16 checksum) -> asserts %M304, clears %M303
   - 0xC204: RTU_ERR_CHARACTER_OVERRUN (Inter-character gap > 1.5 char times mid-frame) -> asserts %M304, clears %M303

4. Horner OCS Memory Space Integration:
   - %R1300: BaudRateCode (INT16, direct bps/100, e.g. 192 = 19200 bps)
   - %R1301: SilentIntervalT35Microseconds (INT16, e.g. 1750 us or 2005 us)
   - %R1302: TurnaroundDelayMicroseconds (INT16, nominal 500 us)
   - %R1303: FrameTransmissionCounter (UINT16 monotonic 0..65535)
   - %R1304: Crc16ErrorCounter (INT16 count of CRC errors)
   - %R1305: BusStateWord (INT16 bitmask of transceiver state and control signals)
   - %R1306: SlaveAddressAndFunctionWord (UINT16, slave address byte + function code byte)
   - %R1307: DiagnosticStatusCode (0x0000=OK, 0xC201, 0xC202, 0xC203, 0xC204)
   - %M303: ModbusRtuPermissive (BOOL)
   - %M304: ModbusRtuFaultTrip (BOOL)
   - All RegisterTable writes pass privilege=PrivilegeMode.SYSTEM.

5. Deterministic 9-Stage Verification Suite:
   - run_modbus_rtu_rs485_verification(output_path) returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
from pathlib import Path
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Timing Definitions (Modbus Serial Line Protocol v1.02 / TIA-485-A)
# ============================================================================

MODBUS_RTU_DEFAULT_BAUD: int = 19200
MODBUS_RTU_DEFAULT_BAUD_CODE: int = 192
MODBUS_RTU_BITS_PER_CHAR: int = 11  # 1 start + 8 data + 1 parity + 1 stop, or 1 start + 8 data + 2 stop
MODBUS_RTU_NOMINAL_TURNAROUND_US: float = 500.0
MODBUS_RTU_NOMINAL_TURNAROUND_INT: int = 500

# Fixed timing limits for baud rates > 19200 bps (Modbus Serial Line Protocol v1.02 Section 2.5.1.1)
MODBUS_RTU_FIXED_T15_US: float = 750.0   # 750 microseconds
MODBUS_RTU_FIXED_T35_US: float = 1750.0  # 1.750 milliseconds (1750 microseconds)

# Modbus RTU CRC-16 Parameters
MODBUS_RTU_CRC16_INIT: int = 0xFFFF
MODBUS_RTU_CRC16_POLY: int = 0xA001      # Reflected polynomial for 0x8005

# Supported Baud Rates
SUPPORTED_BAUD_RATES: Tuple[int, ...] = (9600, 19200, 38400, 57600, 115200)


def calculate_char_time_us(baud_rate: int) -> float:
    """Calculate transmission duration of a single 11-bit serial character in microseconds.

    Args:
        baud_rate: Serial line speed in bits per second (bps).

    Returns:
        Duration of 1 character in microseconds.
    """
    if baud_rate <= 0:
        raise ValueError(f"Baud rate must be positive, got {baud_rate}")
    return (float(MODBUS_RTU_BITS_PER_CHAR) * 1_000_000.0) / float(baud_rate)


def calculate_t15_us(baud_rate: int) -> float:
    """Calculate inter-character silence limit t1.5 in microseconds per Modbus v1.02.

    For baud rates <= 19200 bps: t1.5 = 1.5 * character time.
    For baud rates > 19200 bps: fixed recommended value of 750 microseconds.

    Args:
        baud_rate: Serial line speed in bits per second (bps).

    Returns:
        Inter-character timeout t1.5 in microseconds.
    """
    if baud_rate > 19200:
        return MODBUS_RTU_FIXED_T15_US
    return 1.5 * calculate_char_time_us(baud_rate)


def calculate_t35_us(baud_rate: int) -> float:
    """Calculate inter-frame silent interval t3.5 in microseconds per Modbus v1.02.

    For baud rates <= 19200 bps: t3.5 = 3.5 * character time.
    For baud rates > 19200 bps: fixed recommended value of 1750 microseconds.

    Args:
        baud_rate: Serial line speed in bits per second (bps).

    Returns:
        Inter-frame silent interval t3.5 in microseconds.
    """
    if baud_rate > 19200:
        return MODBUS_RTU_FIXED_T35_US
    return 3.5 * calculate_char_time_us(baud_rate)


def baud_to_code(baud_rate: int) -> int:
    """Convert baud rate in bps to Horner OCS INT16 BaudRateCode (bps / 100)."""
    return int(baud_rate // 100)


def code_to_baud(baud_code: int) -> int:
    """Convert Horner OCS INT16 BaudRateCode (bps / 100) back to bps."""
    return int(baud_code * 100)


# ============================================================================
# 2. Enums, Status Flags, & Diagnostic Codes
# ============================================================================

class ModbusBaudRate(IntEnum):
    """Standard Modbus RTU Baud Rates supported by Horner OCS RS-485 ports."""
    BAUD_9600   = 9600
    BAUD_19200  = 19200
    BAUD_38400  = 38400
    BAUD_57600  = 57600
    BAUD_115200 = 115200


class Rs485TransceiverState(IntEnum):
    """RS-485 Half-Duplex Transceiver Bus State Machine."""
    BUS_IDLE             = 0  # No activity; silent interval t3.5 has fully elapsed
    RECEIVING            = 1  # Characters actively arriving on serial line (DE=0, ~RE=0)
    SILENT_INTERVAL_T35  = 2  # Inter-frame t3.5 silence accumulating after reception/transmission
    TRANSMITTING         = 3  # Actively driving RS-485 line (DE=1, ~RE=1, RTS=1)
    TURNAROUND_WAIT      = 4  # Line settling delay before receiver enable (DE=0, ~RE=1)
    BUS_COLLISION_FAULT  = 5  # Contention, timing violation, or physical collision latched


# Aliases for transceiver state
Rs485BusState = Rs485TransceiverState
RS485BusState = Rs485TransceiverState
ModbusRtuBusState = Rs485TransceiverState


class ModbusRtuDiagnosticCode(IntEnum):
    """Horner OCS %R1307 Diagnostic Event Codes for Modbus RTU RS-485 (W169)."""
    OK                                 = 0x0000  # Normal healthy serial line communication
    RTU_ERR_SILENT_INTERVAL_VIOLATION  = 0xC201  # Transmission started before 3.5 character silence elapsed
    RTU_ERR_TURNAROUND_COLLISION       = 0xC202  # Direction contention or driver enabled before turnaround delay
    RTU_ERR_FRAME_CRC16_MISMATCH       = 0xC203  # Corrupted frame CRC-16 checksum
    RTU_ERR_CHARACTER_OVERRUN          = 0xC204  # Inter-character silence limit t1.5 exceeded mid-frame

    # Convenience aliases
    SILENT_INTERVAL_VIOLATION = 0xC201
    TURNAROUND_COLLISION      = 0xC202
    FRAME_CRC16_MISMATCH      = 0xC203
    CHARACTER_OVERRUN         = 0xC204
    ERR_SILENT_INTERVAL_VIOLATION = 0xC201
    ERR_TURNAROUND_COLLISION      = 0xC202
    ERR_FRAME_CRC16_MISMATCH      = 0xC203
    ERR_CHARACTER_OVERRUN         = 0xC204


DiagnosticStatusCode = ModbusRtuDiagnosticCode


class Rs485BusStateBits(IntFlag):
    """Horner OCS %R1305 BusStateWord Bitmask Definitions."""
    DRIVER_ENABLE              = 1 << 0   # Bit 0 (0x0001): DE asserted (Transmitter enabled)
    RECEIVER_DISABLE           = 1 << 1   # Bit 1 (0x0002): ~RE negated (Receiver disabled)
    REQUEST_TO_SEND            = 1 << 2   # Bit 2 (0x0004): RTS asserted
    STATE_BIT_0                = 1 << 3   # Bit 3 (0x0008): State enum bit 0
    STATE_BIT_1                = 1 << 4   # Bit 4 (0x0010): State enum bit 1
    STATE_BIT_2                = 1 << 5   # Bit 5 (0x0020): State enum bit 2
    T35_SILENCE_ACTIVE         = 1 << 6   # Bit 6 (0x0040): Inter-frame t3.5 silent interval active
    TURNAROUND_ACTIVE          = 1 << 7   # Bit 7 (0x0080): Turnaround delay timer active
    FRAME_BUFFER_READY         = 1 << 8   # Bit 8 (0x0100): Committed frame ready in RX buffer
    PERMISSIVE                 = 1 << 9   # Bit 9 (0x0200): ModbusRtuPermissive (%M303) asserted
    FAULT_TRIP                 = 1 << 10  # Bit 10 (0x0400): ModbusRtuFaultTrip (%M304) asserted
    SILENT_INTERVAL_VIOLATION  = 1 << 11  # Bit 11 (0x0800): 0xC201 fault active
    TURNAROUND_COLLISION       = 1 << 12  # Bit 12 (0x1000): 0xC202 fault active
    CRC_ERROR                  = 1 << 13  # Bit 13 (0x2000): 0xC203 fault active
    CHARACTER_OVERRUN          = 1 << 14  # Bit 14 (0x4000): 0xC204 fault active
    MASTER_MODE                = 1 << 15  # Bit 15 (0x8000): 1 if master node, 0 if slave


ModbusRtuBusStateBits = Rs485BusStateBits


# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class ModbusRtuRs485Error(Exception):
    """Base exception for Modbus RTU RS-485 physical and data-link layer faults."""
    pass


class ModbusRtuSilentIntervalViolationError(ModbusRtuRs485Error):
    """Raised when transmission or character arrives before 3.5 char silence elapses (0xC201)."""
    pass


class ModbusRtuTurnaroundCollisionError(ModbusRtuRs485Error):
    """Raised on directional contention or driver enable before turnaround delay elapses (0xC202)."""
    pass


class ModbusRtuFrameCrcMismatchError(ModbusRtuRs485Error):
    """Raised when incoming frame CRC-16 checksum fails verification (0xC203)."""
    pass


class ModbusRtuCharacterOverrunError(ModbusRtuRs485Error):
    """Raised when silence between consecutive characters exceeds t1.5 mid-frame (0xC204)."""
    pass


# Aliases for exceptions
SilentIntervalViolationError = ModbusRtuSilentIntervalViolationError
TurnaroundCollisionError = ModbusRtuTurnaroundCollisionError
FrameCrcMismatchError = ModbusRtuFrameCrcMismatchError
CharacterOverrunError = ModbusRtuCharacterOverrunError


# ============================================================================
# 4. CRC-16 & Register Word Encoding Utilities
# ============================================================================

def compute_modbus_crc16(data: bytes) -> int:
    """Calculate standard Modbus RTU CRC-16 (reflected polynomial 0xA001, init 0xFFFF).

    Args:
        data: Raw byte payload over which CRC-16 is computed.

    Returns:
        16-bit unsigned integer checksum.
    """
    crc = MODBUS_RTU_CRC16_INIT
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ MODBUS_RTU_CRC16_POLY
            else:
                crc >>= 1
    return crc & 0xFFFF


def verify_modbus_crc16(frame_with_crc: bytes) -> bool:
    """Verify that a Modbus RTU frame has a valid trailing little-endian CRC-16.

    Args:
        frame_with_crc: Frame bytes including the final 2 CRC bytes.

    Returns:
        True if checksum matches exactly, False otherwise.
    """
    if len(frame_with_crc) < 4:
        return False
    payload = frame_with_crc[:-2]
    expected_crc = compute_modbus_crc16(payload)
    received_crc = struct.unpack("<H", frame_with_crc[-2:])[0]
    return expected_crc == received_crc


# Utility aliases
compute_crc16 = compute_modbus_crc16
calculate_crc16 = compute_modbus_crc16
calculate_modbus_crc16 = compute_modbus_crc16
verify_crc16 = verify_modbus_crc16


def encode_slave_function_word(slave_address: int, function_code: int) -> int:
    """Encode slave address (high byte) and function code (low byte) into UINT16 (%R1306)."""
    return ((int(slave_address) & 0xFF) << 8) | (int(function_code) & 0xFF)


def decode_slave_function_word(word: int) -> Tuple[int, int]:
    """Decode UINT16 (%R1306) into slave address (high byte) and function code (low byte)."""
    slave_address = (int(word) >> 8) & 0xFF
    function_code = int(word) & 0xFF
    return slave_address, function_code


def safe_write_word(rt: RegisterTable, address: str, value: int) -> None:
    """Safely writes a 16-bit signed word to RegisterTable with SYSTEM privilege."""
    val_16 = int(value) & 0xFFFF
    if val_16 > 32767:
        val_16 -= 65536
    rt.write_word(address, val_16, privilege=PrivilegeMode.SYSTEM)


def safe_write_uword(rt: RegisterTable, address: str, value: int) -> None:
    """Safely writes a 16-bit unsigned word to RegisterTable with SYSTEM privilege."""
    val_16 = int(value) & 0xFFFF
    if val_16 > 32767:
        val_16 -= 65536
    rt.write_word(address, val_16, privilege=PrivilegeMode.SYSTEM)


def safe_write_bit(rt: RegisterTable, address: str, value: bool) -> None:
    """Safely writes a discrete bit to RegisterTable with SYSTEM privilege."""
    rt.write_bit(address, bool(value), privilege=PrivilegeMode.SYSTEM)


# ============================================================================
# 5. Modbus RTU Frame Container
# ============================================================================

@dataclass
class ModbusRtuFrame:
    """Modbus RTU Serial Application Frame container.

    Wire format:
    - Slave Address: 1 octet (1..247 for unicast, 0 for broadcast)
    - Function Code: 1 octet (1..127 standard, 128..255 exception)
    - Data / PDU Payload: N octets
    - CRC-16 Checksum: 2 octets (little-endian: low-order byte first, then high-order byte)
    """
    slave_address: int = 1
    function_code: int = 3
    pdu_data: bytes = b""
    crc: Optional[int] = None

    def serialize(self) -> bytes:
        """Serialize frame to wire bytes with trailing little-endian CRC-16."""
        header_and_data = bytes([self.slave_address & 0xFF, self.function_code & 0xFF]) + self.pdu_data
        checksum = self.crc if self.crc is not None else compute_modbus_crc16(header_and_data)
        return header_and_data + struct.pack("<H", checksum)

    @classmethod
    def deserialize(cls, data: bytes) -> "ModbusRtuFrame":
        """Deserialize wire bytes into ModbusRtuFrame, validating CRC-16 integrity.

        Raises:
            ModbusRtuFrameCrcMismatchError: If frame is truncated (< 4 bytes) or CRC mismatches.
        """
        if len(data) < 4:
            raise ModbusRtuFrameCrcMismatchError(
                f"Modbus RTU frame truncated: length {len(data)} < minimum 4 bytes."
            )
        slave_address = data[0]
        function_code = data[1]
        pdu_data = data[2:-2]
        received_crc = struct.unpack("<H", data[-2:])[0]
        calculated_crc = compute_modbus_crc16(data[:-2])

        if received_crc != calculated_crc:
            raise ModbusRtuFrameCrcMismatchError(
                f"Modbus RTU CRC mismatch: received 0x{received_crc:04X}, computed 0x{calculated_crc:04X}."
            )

        return cls(
            slave_address=slave_address,
            function_code=function_code,
            pdu_data=pdu_data,
            crc=received_crc,
        )

    @classmethod
    def parse(cls, data: bytes) -> "ModbusRtuFrame":
        """Alias for deserialize."""
        return cls.deserialize(data)

    @classmethod
    def create(
        cls,
        slave_address: int = 1,
        function_code: int = 3,
        pdu_data: bytes = b"",
        crc: Optional[int] = None,
    ) -> "ModbusRtuFrame":
        """Create and return a new ModbusRtuFrame instance."""
        return cls(
            slave_address=slave_address,
            function_code=function_code,
            pdu_data=pdu_data,
            crc=crc,
        )

    @property
    def slave_function_word(self) -> int:
        """Combined UINT16 word representing slave address and function code."""
        return encode_slave_function_word(self.slave_address, self.function_code)

    @property
    def total_length(self) -> int:
        """Total frame length in bytes including 2-byte CRC."""
        return 2 + len(self.pdu_data) + 2

    def transmission_time_us(self, baud_rate: int) -> float:
        """Calculate on-wire transmission time in microseconds at a specific baud rate."""
        return float(self.total_length) * calculate_char_time_us(baud_rate)


# ============================================================================
# 6. Pure IEC 61131-3 Structured Text (ST) POUs
# ============================================================================

MODBUS_RTU_RS485_SYNC_POU: str = """PROGRAM ModbusRtuRs485Sync
VAR
    (* Horner OCS Mapped Registers (W169 - Modbus RTU RS-485 Engine) *)
    BaudRateCode                  AT %R1300 : INT;    (* Baud rate in bps/100 (e.g. 192 = 19200 bps) *)
    SilentIntervalT35Microseconds AT %R1301 : INT;    (* Inter-frame silent interval t3.5 in us *)
    TurnaroundDelayMicroseconds   AT %R1302 : INT;    (* RS-485 turnaround delay in us (nominal 500 us) *)
    FrameTransmissionCounter      AT %R1303 : UINT;   (* Rolling count of transmitted/processed frames *)
    Crc16ErrorCounter             AT %R1304 : INT;    (* Accumulated CRC-16 error counter *)
    BusStateWord                  AT %R1305 : INT;    (* Transceiver bus state and control bitmask *)
    SlaveAddressAndFunctionWord   AT %R1306 : UINT;   (* Slave address (high) and function code (low) *)
    DiagnosticStatusCode          AT %R1307 : UINT;   (* Diagnostic status code (0x0000, 0xC201..0xC204) *)

    (* Discrete Safety Interlock Coils *)
    ModbusRtuPermissive           AT %M303  : BOOL;   (* TRUE when RS-485 Modbus RTU bus healthy *)
    ModbusRtuFaultTrip            AT %M304  : BOOL;   (* TRUE on collision, timeout, or CRC fault *)
END_VAR
VAR
    BusOperational                : BOOL;
END_VAR

IF ModbusRtuFaultTrip OR (DiagnosticStatusCode <> 0) THEN
    ModbusRtuPermissive := FALSE;
    ModbusRtuFaultTrip := TRUE;
    BusOperational := FALSE;
ELSIF ModbusRtuPermissive THEN
    FrameTransmissionCounter := FrameTransmissionCounter + 1;
    DiagnosticStatusCode := 0;
    BusOperational := TRUE;
ELSE
    BusOperational := FALSE;
END_IF;

IF Crc16ErrorCounter > 0 THEN
    DiagnosticStatusCode := 49667; (* 0xC203: RTU_ERR_FRAME_CRC16_MISMATCH *)
    ModbusRtuPermissive := FALSE;
    ModbusRtuFaultTrip := TRUE;
END_IF;
END_PROGRAM
"""

RS485_HALF_DUPLEX_TIMING_SYNC_POU: str = """PROGRAM Rs485HalfDuplexTimingSync
VAR
    (* Horner OCS Mapped Registers (W169 - Modbus RTU RS-485 Engine) *)
    BaudRateCode                  AT %R1300 : INT;    (* Baud rate in bps/100 (e.g. 192 = 19200 bps) *)
    SilentIntervalT35Microseconds AT %R1301 : INT;    (* Inter-frame silent interval t3.5 in us *)
    TurnaroundDelayMicroseconds   AT %R1302 : INT;    (* RS-485 turnaround delay in us (nominal 500 us) *)
    FrameTransmissionCounter      AT %R1303 : UINT;   (* Rolling count of transmitted/processed frames *)
    Crc16ErrorCounter             AT %R1304 : INT;    (* Accumulated CRC-16 error counter *)
    BusStateWord                  AT %R1305 : INT;    (* Transceiver bus state and control bitmask *)
    SlaveAddressAndFunctionWord   AT %R1306 : UINT;   (* Slave address (high) and function code (low) *)
    DiagnosticStatusCode          AT %R1307 : UINT;   (* Diagnostic status code (0x0000, 0xC201..0xC204) *)

    (* Discrete Safety Interlock Coils *)
    ModbusRtuPermissive           AT %M303  : BOOL;   (* TRUE when RS-485 Modbus RTU bus healthy *)
    ModbusRtuFaultTrip            AT %M304  : BOOL;   (* TRUE on collision, timeout, or CRC fault *)
END_VAR
VAR
    BusOperational                : BOOL;
END_VAR

IF ModbusRtuFaultTrip OR (DiagnosticStatusCode <> 0) THEN
    ModbusRtuPermissive := FALSE;
    ModbusRtuFaultTrip := TRUE;
    BusOperational := FALSE;
ELSIF ModbusRtuPermissive THEN
    FrameTransmissionCounter := FrameTransmissionCounter + 1;
    DiagnosticStatusCode := 0;
    BusOperational := TRUE;
ELSE
    BusOperational := FALSE;
END_IF;

IF Crc16ErrorCounter > 0 THEN
    DiagnosticStatusCode := 49667; (* 0xC203: RTU_ERR_FRAME_CRC16_MISMATCH *)
    ModbusRtuPermissive := FALSE;
    ModbusRtuFaultTrip := TRUE;
END_IF;
END_PROGRAM
"""

# POU Aliases
PURE_ST_POU: str = MODBUS_RTU_RS485_SYNC_POU
MODBUS_RTU_SYNC_POU: str = MODBUS_RTU_RS485_SYNC_POU
RS485_TIMING_SYNC_POU: str = RS485_HALF_DUPLEX_TIMING_SYNC_POU
MODBUS_RTU_PURE_ST_POU: str = MODBUS_RTU_RS485_SYNC_POU
MODBUS_RTU_TURNAROUND_SYNC_POU: str = MODBUS_RTU_RS485_SYNC_POU.replace("PROGRAM ModbusRtuRs485Sync", "PROGRAM ModbusRTUTurnaroundSync")


def verify_modbus_rtu_rs485_pure_st() -> bool:
    """Validate Modbus RTU RS-485 POUs for strict IEC 61131-3 syntax and anti-ladder safety.

    Returns:
        True if all checks pass deterministically.
    """
    SecurityGuard.assert_pure_st_content(MODBUS_RTU_RS485_SYNC_POU)
    SecurityGuard.assert_pure_st_content(RS485_HALF_DUPLEX_TIMING_SYNC_POU)

    res1 = STParser.validate_code(MODBUS_RTU_RS485_SYNC_POU)
    if res1.status != AgentStatus.SUCCESS:
        return False

    res2 = STParser.validate_code(RS485_HALF_DUPLEX_TIMING_SYNC_POU)
    if res2.status != AgentStatus.SUCCESS:
        return False

    ast1 = STParser.parse_pou(MODBUS_RTU_RS485_SYNC_POU)
    ast2 = STParser.parse_pou(RS485_HALF_DUPLEX_TIMING_SYNC_POU)

    expected_regs = {
        "%R1300", "%R1301", "%R1302", "%R1303",
        "%R1304", "%R1305", "%R1306", "%R1307",
        "%M303", "%M304",
    }
    return set(ast1.bound_registers) == expected_regs and set(ast2.bound_registers) == expected_regs


# ============================================================================
# 7. Modbus RTU RS-485 Engine (ILogicUnit)
# ============================================================================

class ModbusRtuRs485Engine(ILogicUnit):
    """Industrial Modbus RTU Over RS-485 Half-Duplex Turnaround & Timing Engine.

    Work Package: W169 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
    Classification: PRODUCTION_READY

    Implements:
    - Half-duplex transceiver direction control (RTS / DE / ~RE).
    - Precise character, t1.5, t3.5, and turnaround delay timers.
    - Double-buffered frame reception and transmission.
    - Discrete simulation scan cycles conforming to ILogicUnit.
    - Horner OCS register space synchronization (%R1300..%R1307, %M303..%M304).
    """

    def __init__(
        self,
        slave_address: int = 1,
        baud_rate: int = MODBUS_RTU_DEFAULT_BAUD,
        turnaround_delay_us: float = MODBUS_RTU_NOMINAL_TURNAROUND_US,
        is_master: bool = False,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.slave_address: int = max(1, min(247, slave_address))
        self.baud_rate: int = baud_rate
        self.turnaround_delay_us: float = float(turnaround_delay_us)
        self.is_master: bool = is_master
        self.reg_table: RegisterTable = register_table or RegisterTable()

        # Computed timing parameters
        self.char_time_us: float = calculate_char_time_us(self.baud_rate)
        self.t15_us: float = calculate_t15_us(self.baud_rate)
        self.t35_us: float = calculate_t35_us(self.baud_rate)

        # Transceiver State & Direction Signals
        self.state: Rs485TransceiverState = Rs485TransceiverState.BUS_IDLE
        self.rts: bool = False       # Request To Send
        self.de: bool = False        # Driver Enable (HIGH = Transmit)
        self.re_n: bool = False      # Receiver Enable Active Low (LOW = Receive Active)

        # Safety & Diagnostics
        self.permissive: bool = True
        self.fault_trip: bool = False
        self.diagnostic_code: ModbusRtuDiagnosticCode = ModbusRtuDiagnosticCode.OK
        self.frame_transmission_counter: int = 0
        self.crc16_error_counter: int = 0
        self.current_slave_address: int = self.slave_address
        self.current_function_code: int = 0

        # Physical Bus Timers (in microseconds)
        self.elapsed_time_us: float = 0.0
        self.silence_elapsed_us: float = self.t35_us * 2.0  # Initially quiet bus
        self.turnaround_remaining_us: float = 0.0
        self.tx_remaining_us: float = 0.0
        self.time_since_last_char_us: float = 0.0

        # Double-Buffering Containers
        self.rx_buffer: bytearray = bytearray()
        self.committed_rx_frame: Optional[ModbusRtuFrame] = None
        self.staged_tx_frame: Optional[ModbusRtuFrame] = None
        self.last_transmitted_frame: Optional[ModbusRtuFrame] = None

        self.sync_to_registers()

    # ------------------------------------------------------------------------
    # ILogicUnit Properties & Lifecycle
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "modbus_rtu_rs485"

    @property
    def priority(self) -> int:
        return 95

    @property
    def is_enabled(self) -> bool:
        return True

    def execute(self, ctx: ScanContext) -> None:
        """Scan cycle logic solve execution during simulation Phase 2."""
        dt_ms = getattr(ctx, "dt_ms", 1.0)
        self.scan_step(dt=dt_ms / 1000.0)

    def reset(self) -> None:
        """Reset internal unit state to initial conditions."""
        self.reset_fault(force=True)

    # ------------------------------------------------------------------------
    # Configuration & Parameter Access
    # ------------------------------------------------------------------------

    def set_baud_rate(self, baud_rate: int) -> None:
        """Configure serial line speed and recompute timing parameters."""
        if baud_rate not in SUPPORTED_BAUD_RATES:
            raise ValueError(f"Unsupported baud rate {baud_rate}. Must be one of {SUPPORTED_BAUD_RATES}")
        self.baud_rate = baud_rate
        self.char_time_us = calculate_char_time_us(self.baud_rate)
        self.t15_us = calculate_t15_us(self.baud_rate)
        self.t35_us = calculate_t35_us(self.baud_rate)
        self.sync_to_registers()

    def get_transceiver_signals(self) -> Dict[str, bool]:
        """Return physical transceiver direction control signals."""
        return {
            "RTS": self.rts,
            "DE": self.de,
            "RE_N": self.re_n,
        }

    # ------------------------------------------------------------------------
    # State Machine & Timing Progression
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.001) -> Dict[str, Any]:
        """Advance deterministic simulation clock and evaluate transceiver state machine.

        Args:
            dt: Scan time delta in seconds (or milliseconds if dt >= 1.0).

        Returns:
            Dictionary containing cycle telemetry and transceiver status.
        """
        dt_us = (dt * 1000.0 if dt >= 1.0 else dt * 1_000_000.0)
        self.elapsed_time_us += dt_us

        if self.fault_trip:
            # Latched fault state: hold driver disabled
            self.de = False
            self.rts = False
            self.re_n = False
            self.sync_to_registers()
            return self._build_status_telemetry()

        # Active state machine progression
        if self.state == Rs485TransceiverState.TRANSMITTING:
            self.tx_remaining_us -= dt_us
            if self.tx_remaining_us <= 0.0:
                # Wire transmission finished! Disable transmitter driver
                self.frame_transmission_counter = (self.frame_transmission_counter + 1) & 0xFFFF
                self.last_transmitted_frame = self.staged_tx_frame
                self.staged_tx_frame = None
                self.de = False
                self.rts = False
                # Enter TURNAROUND_WAIT (hold receiver disabled while line settles)
                self.state = Rs485TransceiverState.TURNAROUND_WAIT
                self.turnaround_remaining_us = self.turnaround_delay_us

        elif self.state == Rs485TransceiverState.TURNAROUND_WAIT:
            self.turnaround_remaining_us -= dt_us
            if self.turnaround_remaining_us <= 0.0:
                # Turnaround delay expired! Re-enable receiver (~RE = 0)
                self.re_n = False
                self.turnaround_remaining_us = 0.0
                # Enter SILENT_INTERVAL_T35 demarcating frame boundary
                self.state = Rs485TransceiverState.SILENT_INTERVAL_T35
                self.silence_elapsed_us = 0.0

        elif self.state == Rs485TransceiverState.SILENT_INTERVAL_T35:
            self.silence_elapsed_us += dt_us
            if self.silence_elapsed_us >= self.t35_us:
                # Frame demarcation complete; bus is now idle
                self.state = Rs485TransceiverState.BUS_IDLE

        elif self.state == Rs485TransceiverState.BUS_IDLE:
            self.silence_elapsed_us += dt_us

        elif self.state == Rs485TransceiverState.RECEIVING:
            self.time_since_last_char_us += dt_us
            if self.time_since_last_char_us >= self.t35_us:
                # Inter-frame silence t3.5 reached while in RECEIVING -> demarcates frame end
                self._complete_frame_reception()

        self.sync_to_registers()
        return self._build_status_telemetry()

    def _build_status_telemetry(self) -> Dict[str, Any]:
        """Build a snapshot of current telemetry data."""
        return {
            "elapsed_time_us": self.elapsed_time_us,
            "state": self.state.name,
            "de": self.de,
            "re_n": self.re_n,
            "rts": self.rts,
            "permissive": self.permissive,
            "fault_trip": self.fault_trip,
            "diagnostic_code": f"0x{int(self.diagnostic_code):04X}",
            "frames_transmitted": self.frame_transmission_counter,
            "crc_errors": self.crc16_error_counter,
            "silence_elapsed_us": self.silence_elapsed_us,
        }

    # ------------------------------------------------------------------------
    # Transmission Operations
    # ------------------------------------------------------------------------

    def transmit_frame(self, frame: ModbusRtuFrame, force: bool = False) -> ExecutionResult:
        """Stage and initiate physical transmission of a Modbus RTU frame.

        Args:
            frame: ModbusRtuFrame to transmit.
            force: If True, bypass inter-frame silence and turnaround checks.

        Returns:
            ExecutionResult indicating success or safety fault.
        """
        if not force:
            if self.fault_trip:
                return ExecutionResult.failed(
                    error_code="ERR_FAULT_ACTIVE",
                    details="Transceiver cannot transmit while in fault trip state.",
                )

            # Check for silent interval violation (t3.5)
            if self.state == Rs485TransceiverState.SILENT_INTERVAL_T35 or (
                self.state == Rs485TransceiverState.BUS_IDLE and self.silence_elapsed_us < self.t35_us
            ):
                self._trip_fault(
                    ModbusRtuDiagnosticCode.RTU_ERR_SILENT_INTERVAL_VIOLATION,
                    details=(
                        f"Silent interval violation: transmission attempted after only "
                        f"{self.silence_elapsed_us:.1f} us silence (< t3.5 threshold {self.t35_us:.1f} us)."
                    ),
                )
                return ExecutionResult.failed(
                    error_code="RTU_ERR_SILENT_INTERVAL_VIOLATION",
                    details="Transmission started before 3.5 character silence elapsed.",
                )

            # Check for turnaround contention
            if self.state == Rs485TransceiverState.TURNAROUND_WAIT or self.turnaround_remaining_us > 0.0:
                self._trip_fault(
                    ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION,
                    details="Driver enable attempted while turnaround delay is still active.",
                )
                return ExecutionResult.failed(
                    error_code="RTU_ERR_TURNAROUND_COLLISION",
                    details="Direction contention: driver enabled before turnaround delay elapsed.",
                )

            # Check for receiving contention
            if self.state == Rs485TransceiverState.RECEIVING:
                self._trip_fault(
                    ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION,
                    details="Direction contention: transmission initiated while actively receiving data.",
                )
                return ExecutionResult.failed(
                    error_code="RTU_ERR_TURNAROUND_COLLISION",
                    details="Direction contention: attempted transmission during reception.",
                )

        # Transmit initiation
        wire_data = frame.serialize()
        tx_duration_us = float(len(wire_data)) * self.char_time_us

        self.state = Rs485TransceiverState.TRANSMITTING
        self.de = True
        self.rts = True
        self.re_n = True  # Receiver disabled during half-duplex transmit
        self.tx_remaining_us = tx_duration_us
        self.current_slave_address = frame.slave_address
        self.current_function_code = frame.function_code
        self.staged_tx_frame = frame
        self.silence_elapsed_us = 0.0

        self.sync_to_registers()
        return ExecutionResult.success(
            details=f"Frame transmission started ({len(wire_data)} bytes, {tx_duration_us:.1f} us on-wire duration)."
        )

    # ------------------------------------------------------------------------
    # Reception Operations
    # ------------------------------------------------------------------------

    def receive_character(
        self,
        char_byte: int,
        gap_since_last_char_us: float = 0.0,
    ) -> ExecutionResult:
        """Receive a single 8-bit character from the RS-485 serial bus.

        Args:
            char_byte: Byte value (0..255).
            gap_since_last_char_us: Silence duration preceding this character in microseconds.

        Returns:
            ExecutionResult indicating success or diagnostic trip.
        """
        if self.fault_trip:
            return ExecutionResult.failed(
                error_code="ERR_FAULT_ACTIVE",
                details="Cannot receive while in fault trip state.",
            )

        # Contention checks
        if self.state == Rs485TransceiverState.TRANSMITTING:
            self._trip_fault(
                ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION,
                details="Bus contention: incoming character detected while transmitter is active.",
            )
            return ExecutionResult.failed(
                error_code="RTU_ERR_TURNAROUND_COLLISION",
                details="Bus collision: incoming byte during transmission.",
            )

        if self.state == Rs485TransceiverState.TURNAROUND_WAIT:
            self._trip_fault(
                ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION,
                details="Bus contention: incoming character detected during turnaround delay.",
            )
            return ExecutionResult.failed(
                error_code="RTU_ERR_TURNAROUND_COLLISION",
                details="Bus collision: incoming byte during turnaround wait.",
            )

        # Start of a new frame
        if self.state in (Rs485TransceiverState.BUS_IDLE, Rs485TransceiverState.SILENT_INTERVAL_T35) and len(self.rx_buffer) == 0:
            if self.silence_elapsed_us < self.t35_us:
                self._trip_fault(
                    ModbusRtuDiagnosticCode.RTU_ERR_SILENT_INTERVAL_VIOLATION,
                    details=(
                        f"Frame start violated t3.5: received byte after only "
                        f"{self.silence_elapsed_us:.1f} us silence (< {self.t35_us:.1f} us required)."
                    ),
                )
                return ExecutionResult.failed(
                    error_code="RTU_ERR_SILENT_INTERVAL_VIOLATION",
                    details="Frame transmission started before 3.5 character silence elapsed.",
                )

            # Valid frame start
            self.state = Rs485TransceiverState.RECEIVING
            self.rx_buffer = bytearray([char_byte & 0xFF])
            self.time_since_last_char_us = 0.0
            self.silence_elapsed_us = 0.0
            self.sync_to_registers()
            return ExecutionResult.success(details="First frame character accepted.")

        # Continuation of active frame
        if self.state == Rs485TransceiverState.RECEIVING:
            # Check inter-character silence limit t1.5
            if gap_since_last_char_us > self.t15_us:
                self._trip_fault(
                    ModbusRtuDiagnosticCode.RTU_ERR_CHARACTER_OVERRUN,
                    details=(
                        f"Inter-character silence limit t1.5 exceeded mid-frame: "
                        f"{gap_since_last_char_us:.1f} us > {self.t15_us:.1f} us. Frame discarded."
                    ),
                )
                self.rx_buffer.clear()
                return ExecutionResult.failed(
                    error_code="RTU_ERR_CHARACTER_OVERRUN",
                    details="Inter-character silence limit t1.5 exceeded mid-frame.",
                )

            self.rx_buffer.append(char_byte & 0xFF)
            self.time_since_last_char_us = 0.0
            self.silence_elapsed_us = 0.0
            self.sync_to_registers()
            return ExecutionResult.success(details=f"Character {len(self.rx_buffer)} accepted.")

        return ExecutionResult.failed(
            error_code="ERR_UNEXPECTED_STATE",
            details=f"Character received in unexpected state {self.state.name}.",
        )

    def receive_raw_frame(
        self,
        raw_bytes: bytes,
        inter_char_gap_us: float = 0.0,
        pre_silence_us: Optional[float] = None,
    ) -> ExecutionResult:
        """Receive a complete sequence of raw bytes, validating character timing and CRC.

        Args:
            raw_bytes: Full byte stream.
            inter_char_gap_us: Simulated inter-character gap in microseconds.
            pre_silence_us: Bus silence before frame start (defaults to 2 * t3.5).

        Returns:
            ExecutionResult indicating outcome.
        """
        if pre_silence_us is not None:
            self.silence_elapsed_us = pre_silence_us
            if self.silence_elapsed_us >= self.t35_us:
                self.state = Rs485TransceiverState.BUS_IDLE

        for i, b in enumerate(raw_bytes):
            gap = 0.0 if i == 0 else inter_char_gap_us
            res = self.receive_character(b, gap_since_last_char_us=gap)
            if res.status != AgentStatus.SUCCESS:
                return res

        # Complete frame reception by applying t3.5 boundary
        return self._complete_frame_reception()

    def _complete_frame_reception(self) -> ExecutionResult:
        """Validate received bytes at the t3.5 frame boundary and commit to double-buffer."""
        data = bytes(self.rx_buffer)
        self.rx_buffer.clear()

        if len(data) < 4:
            self.crc16_error_counter += 1
            self._trip_fault(
                ModbusRtuDiagnosticCode.RTU_ERR_FRAME_CRC16_MISMATCH,
                details=f"Truncated frame received ({len(data)} bytes < minimum 4 bytes).",
            )
            return ExecutionResult.failed(
                error_code="RTU_ERR_FRAME_CRC16_MISMATCH",
                details="Truncated frame CRC mismatch.",
            )

        try:
            frame = ModbusRtuFrame.deserialize(data)
        except ModbusRtuFrameCrcMismatchError as err:
            self.crc16_error_counter += 1
            self._trip_fault(
                ModbusRtuDiagnosticCode.RTU_ERR_FRAME_CRC16_MISMATCH,
                details=str(err),
            )
            return ExecutionResult.failed(
                error_code="RTU_ERR_FRAME_CRC16_MISMATCH",
                details="Frame CRC-16 checksum mismatch.",
            )

        # Frame successfully parsed and validated
        self.committed_rx_frame = frame
        self.current_slave_address = frame.slave_address
        self.current_function_code = frame.function_code
        self.frame_transmission_counter = (self.frame_transmission_counter + 1) & 0xFFFF
        self.state = Rs485TransceiverState.BUS_IDLE
        self.silence_elapsed_us = self.t35_us
        self.sync_to_registers()

        return ExecutionResult.success(
            details=f"Modbus RTU frame received and validated cleanly (slave={frame.slave_address}, fc={frame.function_code}).",
            data={"slave_address": frame.slave_address, "function_code": frame.function_code, "crc": frame.crc},
        )

    # ------------------------------------------------------------------------
    # Process Safety Interlocks & Fault Management
    # ------------------------------------------------------------------------

    def _trip_fault(self, code: ModbusRtuDiagnosticCode, details: str = "") -> None:
        """Assert fail-safe trip, latch safe shutdown, and clear permissive."""
        self.diagnostic_code = code
        self.state = Rs485TransceiverState.BUS_COLLISION_FAULT
        self.fault_trip = True
        self.permissive = False
        self.de = False
        self.rts = False
        self.re_n = False
        self.sync_to_registers()

    def trigger_fault(self, code: ModbusRtuDiagnosticCode) -> None:
        """Explicitly inject a diagnostic fault code."""
        self._trip_fault(code=code, details=f"Injected fault {code.name}")

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Manual / operator reset to clear latched safety trips."""
        self.diagnostic_code = ModbusRtuDiagnosticCode.OK
        self.fault_trip = False
        self.permissive = True
        self.state = Rs485TransceiverState.BUS_IDLE
        self.de = False
        self.rts = False
        self.re_n = False
        self.silence_elapsed_us = self.t35_us * 2.0
        self.turnaround_remaining_us = 0.0
        self.tx_remaining_us = 0.0
        self.rx_buffer.clear()
        self.current_function_code = 0
        self.sync_to_registers()
        return ExecutionResult.success(details="Modbus RTU RS-485 fault reset successfully.")

    def reset_latch(self, force: bool = False) -> ExecutionResult:
        """Alias for reset_fault."""
        return self.reset_fault(force=force)

    # ------------------------------------------------------------------------
    # Horner OCS Register Space Synchronization
    # ------------------------------------------------------------------------

    def compute_bus_state_word(self) -> int:
        """Compute 16-bit status word (%R1305) reflecting transceiver state and bitmask."""
        flags = Rs485BusStateBits(0)

        if self.de:
            flags |= Rs485BusStateBits.DRIVER_ENABLE
        if self.re_n:
            flags |= Rs485BusStateBits.RECEIVER_DISABLE
        if self.rts:
            flags |= Rs485BusStateBits.REQUEST_TO_SEND

        # Encode state (0..5 in bits 3..5)
        state_val = int(self.state.value) & 0x07
        flags |= Rs485BusStateBits(state_val << 3)

        if self.state == Rs485TransceiverState.SILENT_INTERVAL_T35:
            flags |= Rs485BusStateBits.T35_SILENCE_ACTIVE
        if self.state == Rs485TransceiverState.TURNAROUND_WAIT:
            flags |= Rs485BusStateBits.TURNAROUND_ACTIVE
        if self.committed_rx_frame is not None:
            flags |= Rs485BusStateBits.FRAME_BUFFER_READY
        if self.permissive:
            flags |= Rs485BusStateBits.PERMISSIVE
        if self.fault_trip:
            flags |= Rs485BusStateBits.FAULT_TRIP

        if self.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_SILENT_INTERVAL_VIOLATION:
            flags |= Rs485BusStateBits.SILENT_INTERVAL_VIOLATION
        elif self.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION:
            flags |= Rs485BusStateBits.TURNAROUND_COLLISION
        elif self.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_FRAME_CRC16_MISMATCH:
            flags |= Rs485BusStateBits.CRC_ERROR
        elif self.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_CHARACTER_OVERRUN:
            flags |= Rs485BusStateBits.CHARACTER_OVERRUN

        if self.is_master:
            flags |= Rs485BusStateBits.MASTER_MODE

        return int(flags)

    def sync_to_registers(self) -> None:
        """Synchronize internal engine state to Horner OCS register space.

        All writes to RegisterTable MUST pass privilege=PrivilegeMode.SYSTEM.
        """
        baud_code = baud_to_code(self.baud_rate)
        t35_micro = int(round(self.t35_us))
        turnaround_micro = int(round(self.turnaround_delay_us))
        bus_state_word = self.compute_bus_state_word()
        addr_func_word = encode_slave_function_word(self.current_slave_address, self.current_function_code)

        # %R1300: BaudRateCode (INT16, bps / 100)
        safe_write_word(self.reg_table, "%R1300", baud_code)
        # %R1301: SilentIntervalT35Microseconds (INT16)
        safe_write_word(self.reg_table, "%R1301", t35_micro)
        # %R1302: TurnaroundDelayMicroseconds (INT16)
        safe_write_word(self.reg_table, "%R1302", turnaround_micro)
        # %R1303: FrameTransmissionCounter (UINT16 monotonic 0..65535)
        safe_write_uword(self.reg_table, "%R1303", self.frame_transmission_counter & 0xFFFF)
        # %R1304: Crc16ErrorCounter (INT16 count of CRC errors)
        safe_write_word(self.reg_table, "%R1304", self.crc16_error_counter)
        # %R1305: BusStateWord (INT16 bitmask)
        safe_write_word(self.reg_table, "%R1305", bus_state_word)
        # %R1306: SlaveAddressAndFunctionWord (UINT16)
        safe_write_uword(self.reg_table, "%R1306", addr_func_word)
        # %R1307: DiagnosticStatusCode (0x0000=OK, 0xC201..0xC204)
        safe_write_uword(self.reg_table, "%R1307", int(self.diagnostic_code))

        # Discrete interlock coils
        safe_write_bit(self.reg_table, "%M303", self.permissive)
        safe_write_bit(self.reg_table, "%M304", self.fault_trip)


# Aliases for Engine
ModbusRtuRs485Sync = ModbusRtuRs485Engine
Rs485HalfDuplexTimingSync = ModbusRtuRs485Engine
Rs485HalfDuplexTimingSyncEngine = ModbusRtuRs485Engine
Rs485HalfDuplexEngine = ModbusRtuRs485Engine
ModbusRtuEngine = ModbusRtuRs485Engine
ModbusRTUTurnaroundSync = ModbusRtuRs485Engine


# ============================================================================
# 8. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_modbus_rtu_rs485_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W169.

    Returns strict 4-state contract JSON response:
    - Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings (%R1300..%R1307, %M303..%M304)
    - Stage 2: RS-485 Baud Rate Support & Character / t1.5 / t3.5 Timing Calculations
    - Stage 3: Modbus RTU Frame Serialization, Parsing, & Little-Endian CRC-16 Checksum
    - Stage 4: Half-Duplex Transceiver Direction Control (RTS/DE/~RE) & Turnaround Delay (500 us)
    - Stage 5: RS-485 Transceiver Bus State Machine Transitions
    - Stage 6: Inter-Frame Silent Interval (t3.5) Violation Trapping (0xC201)
    - Stage 7: Direction Contention & Turnaround Collision Trapping (0xC202)
    - Stage 8: Frame CRC-16 Mismatch (0xC203) & Inter-Character Overrun (t1.5, 0xC204) Trapping
    - Stage 9: Closed-Loop Scan Cycle Execution, Operator Reset Handshake, & Register Synchronization
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings
    # ------------------------------------------------------------------------
    val_pou1 = STParser.validate_code(MODBUS_RTU_RS485_SYNC_POU)
    ast_pou1 = STParser.parse_pou(MODBUS_RTU_RS485_SYNC_POU)
    val_pou2 = STParser.validate_code(RS485_HALF_DUPLEX_TIMING_SYNC_POU)
    ast_pou2 = STParser.parse_pou(RS485_HALF_DUPLEX_TIMING_SYNC_POU)

    expected_regs = {
        "%R1300", "%R1301", "%R1302", "%R1303",
        "%R1304", "%R1305", "%R1306", "%R1307",
        "%M303", "%M304",
    }

    # Verify anti-ladder security guard rejects forbidden ladder constructs
    ladder_rejected = True
    for bad_construct in ["---[ ]---", "---( )---", "RUNG 1", "XIC Input_1"]:
        try:
            SecurityGuard.assert_pure_st_content(f"PROGRAM Bad\nVAR\nEND_VAR\n{bad_construct}\nEND_PROGRAM")
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    s1_pass = (
        val_pou1.status == AgentStatus.SUCCESS
        and val_pou2.status == AgentStatus.SUCCESS
        and ast_pou1.name == "ModbusRtuRs485Sync"
        and ast_pou2.name == "Rs485HalfDuplexTimingSync"
        and set(ast_pou1.bound_registers) == expected_regs
        and set(ast_pou2.bound_registers) == expected_regs
        and verify_modbus_rtu_rs485_pure_st() is True
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Register_Bindings",
        "passed": s1_pass,
        "details": f"Parsed ModbusRtuRs485Sync and alias with 10 registered bindings: {sorted(ast_pou1.bound_registers)}.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: RS-485 Baud Rate Support & Character / t1.5 / t3.5 Timing Calculations
    # ------------------------------------------------------------------------
    # 9600 bps: t_char = 11 / 9600 s ≈ 1145.83 us, t1.5 ≈ 1718.75 us, t3.5 ≈ 4010.42 us
    tc_9600 = calculate_char_time_us(9600)
    t15_9600 = calculate_t15_us(9600)
    t35_9600 = calculate_t35_us(9600)

    # 19200 bps: t_char = 11 / 19200 s ≈ 572.92 us, t1.5 ≈ 859.38 us, t3.5 ≈ 2005.21 us
    tc_19200 = calculate_char_time_us(19200)
    t15_19200 = calculate_t15_us(19200)
    t35_19200 = calculate_t35_us(19200)

    # >19200 bps (38400, 57600, 115200): fixed t1.5 = 750 us, t3.5 = 1750 us
    t15_38400 = calculate_t15_us(38400)
    t35_38400 = calculate_t35_us(38400)
    t15_115200 = calculate_t15_us(115200)
    t35_115200 = calculate_t35_us(115200)

    s2_pass = (
        abs(tc_9600 - 1145.833) < 0.1
        and abs(t15_9600 - 1718.75) < 0.1
        and abs(t35_9600 - 4010.417) < 0.1
        and abs(tc_19200 - 572.917) < 0.1
        and abs(t15_19200 - 859.375) < 0.1
        and abs(t35_19200 - 2005.208) < 0.1
        and t15_38400 == 750.0
        and t35_38400 == 1750.0
        and t15_115200 == 750.0
        and t35_115200 == 1750.0
        and baud_to_code(19200) == 192
        and baud_to_code(115200) == 1152
    )
    test_results.append({
        "stage": 2,
        "check": "Baud_Rate_Support_And_Character_Timing_Calculations",
        "passed": s2_pass,
        "details": "Deterministic 11-bit character timing, t1.5, and t3.5 calculations verified across all standard baud rates.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Modbus RTU Frame Serialization, Parsing, & CRC-16 Checksum
    # ------------------------------------------------------------------------
    # Test frame: Slave 1, Function 3 (Read Holding Registers), Addr 107 (0x006B), Count 3 (0x0003)
    frame = ModbusRtuFrame(slave_address=1, function_code=3, pdu_data=b"\x00\x6B\x00\x03")
    serialized = frame.serialize()
    # Expected CRC for b"\x01\x03\x00\x6B\x00\x03" is 0x1774, wire bytes: 0x74, 0x17
    crc_wire = serialized[-2:]
    deserialized = ModbusRtuFrame.deserialize(serialized)

    # Verification of full wire frame checksum evaluating to 0
    crc_over_full = compute_modbus_crc16(serialized)

    # Verification of truncated frame rejection
    trunc_rejected = False
    try:
        ModbusRtuFrame.deserialize(b"\x01\x03")
    except ModbusRtuFrameCrcMismatchError:
        trunc_rejected = True

    s3_pass = (
        len(serialized) == 8
        and crc_wire == b"\x74\x17"
        and deserialized.slave_address == 1
        and deserialized.function_code == 3
        and deserialized.pdu_data == b"\x00\x6B\x00\x03"
        and deserialized.crc == 0x1774
        and crc_over_full == 0x0000
        and trunc_rejected is True
    )
    test_results.append({
        "stage": 3,
        "check": "Modbus_RTU_Frame_Serialization_Parsing_And_CRC16",
        "passed": s3_pass,
        "details": "Serialization, little-endian CRC-16 (0xA001/0xFFFF), and deserialization verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Half-Duplex Transceiver Direction Control & Turnaround Delay
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine = ModbusRtuRs485Engine(slave_address=1, baud_rate=19200, turnaround_delay_us=500.0, register_table=rt)

    # Initial state: IDLE (DE=0, RE_N=0, RTS=0)
    sig_idle = engine.get_transceiver_signals()

    # Initiate transmission
    tx_res = engine.transmit_frame(frame)
    sig_tx = engine.get_transceiver_signals()

    # Step simulation just past transmission completion (8 bytes * 572.92 us ≈ 4583.33 us)
    # Using dt_ms = 4.6 ms (4600 us)
    engine.scan_step(dt=0.0046)
    sig_turnaround = engine.get_transceiver_signals()
    state_turnaround = engine.state

    # Step past turnaround delay (500 us, e.g. dt_ms = 0.6 ms)
    engine.scan_step(dt=0.0006)
    sig_t35 = engine.get_transceiver_signals()
    state_t35 = engine.state

    s4_pass = (
        tx_res.status == AgentStatus.SUCCESS
        and sig_idle == {"RTS": False, "DE": False, "RE_N": False}
        and sig_tx == {"RTS": True, "DE": True, "RE_N": True}
        and state_turnaround == Rs485TransceiverState.TURNAROUND_WAIT
        and sig_turnaround == {"RTS": False, "DE": False, "RE_N": True}
        and state_t35 == Rs485TransceiverState.SILENT_INTERVAL_T35
        and sig_t35 == {"RTS": False, "DE": False, "RE_N": False}
        and rt.read_word("%R1302") == 500
    )
    test_results.append({
        "stage": 4,
        "check": "Half_Duplex_Directional_Transceiver_Control_And_Turnaround",
        "passed": s4_pass,
        "details": "RTS/DE/~RE transceiver transitions and 500 us turnaround delay verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: RS-485 Transceiver Bus State Machine Transitions
    # ------------------------------------------------------------------------
    # Step past t3.5 (2005.2 us, e.g. dt_ms = 2.1 ms) to return to BUS_IDLE
    engine.scan_step(dt=0.0021)
    state_back_idle = engine.state
    r1305_idle = rt.read_word("%R1305")
    r1303_tx_count = rt.read_uword("%R1303")

    s5_pass = (
        state_back_idle == Rs485TransceiverState.BUS_IDLE
        and (r1305_idle & 0x0200) != 0  # PERMISSIVE bit set
        and (r1305_idle & 0x0400) == 0  # FAULT_TRIP bit clear
        and r1303_tx_count == 1
    )
    test_results.append({
        "stage": 5,
        "check": "Transceiver_Bus_State_Machine_Lifecycle",
        "passed": s5_pass,
        "details": "IDLE -> TRANSMIT -> TURNAROUND -> SILENT_INTERVAL_T35 -> IDLE state cycle verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Inter-Frame Silent Interval (t3.5) Violation Trapping
    # ------------------------------------------------------------------------
    # Reset engine, simulate silence < t3.5 (e.g. 500 us), then attempt transmission
    engine.reset_fault(force=True)
    engine.silence_elapsed_us = 500.0  # < t3.5 (2005 us)
    res_viol = engine.transmit_frame(frame)

    r1307_viol = rt.read_uword("%R1307")
    m303_viol = rt.read_bit("%M303")
    m304_viol = rt.read_bit("%M304")

    s6_pass = (
        res_viol.status == AgentStatus.FAILED
        and engine.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_SILENT_INTERVAL_VIOLATION
        and r1307_viol == 0xC201
        and m303_viol is False
        and m304_viol is True
    )
    test_results.append({
        "stage": 6,
        "check": "Inter_Frame_Silent_Interval_Violation_Trapping",
        "passed": s6_pass,
        "details": "Premature transmission before 3.5 character silence trapped deterministically with 0xC201.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Direction Contention & Turnaround Collision Trapping
    # ------------------------------------------------------------------------
    engine.reset_fault(force=True)
    # Initiate valid transmit, advance into TURNAROUND_WAIT
    engine.transmit_frame(frame)
    engine.scan_step(dt=0.0046)  # now in TURNAROUND_WAIT

    # Attempt to transmit during turnaround wait -> direction contention!
    res_collision = engine.transmit_frame(frame)
    r1307_coll = rt.read_uword("%R1307")
    m303_coll = rt.read_bit("%M303")
    m304_coll = rt.read_bit("%M304")

    s7_pass = (
        res_collision.status == AgentStatus.FAILED
        and engine.diagnostic_code == ModbusRtuDiagnosticCode.RTU_ERR_TURNAROUND_COLLISION
        and r1307_coll == 0xC202
        and m303_coll is False
        and m304_coll is True
    )
    test_results.append({
        "stage": 7,
        "check": "Direction_Contention_And_Turnaround_Collision_Trapping",
        "passed": s7_pass,
        "details": "Driver enable during turnaround line settling trapped deterministically with 0xC202.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Frame CRC-16 Mismatch (0xC203) & Inter-Character Overrun (0xC204) Trapping
    # ------------------------------------------------------------------------
    # Part A: CRC Mismatch
    engine.reset_fault(force=True)
    corrupted_frame_bytes = b"\x01\x03\x00\x6B\x00\x03\xFF\xFF"  # Bad CRC
    res_crc = engine.receive_raw_frame(corrupted_frame_bytes, pre_silence_us=3000.0)
    r1307_crc = rt.read_uword("%R1307")
    r1304_crc_cnt = rt.read_word("%R1304")

    # Part B: Character Overrun (> t1.5 mid-frame)
    engine.reset_fault(force=True)
    engine.silence_elapsed_us = 3000.0
    engine.receive_character(0x01)  # First byte
    # Inject inter-character silence 1500 us (> t1.5 of 859.38 us)
    res_overrun = engine.receive_character(0x03, gap_since_last_char_us=1500.0)
    r1307_overrun = rt.read_uword("%R1307")

    s8_pass = (
        res_crc.status == AgentStatus.FAILED
        and r1307_crc == 0xC203
        and r1304_crc_cnt == 1
        and res_overrun.status == AgentStatus.FAILED
        and r1307_overrun == 0xC204
    )
    test_results.append({
        "stage": 8,
        "check": "CRC16_Mismatch_And_Character_Overrun_Trapping",
        "passed": s8_pass,
        "details": "Corrupted CRC (0xC203) and t1.5 character overrun (0xC204) trapped deterministically.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Closed-Loop Scan Cycle Execution, Operator Reset Handshake, & Register Synchronization
    # ------------------------------------------------------------------------
    # Verify ILogicUnit execution
    ctx = ScanContext(
        cycle=1,
        dt_ms=1.0,
        elapsed_time_ms=1.0,
        get_register=rt.read_register,
        set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
        get_variable=lambda k, d=None: d,
        set_variable=lambda k, v: None,
        record_fault=lambda f: None,
    )
    engine.execute(ctx)

    # Perform operator reset handshake
    res_reset = engine.reset_fault(force=True)
    engine.sync_to_registers()

    s9_pass = (
        engine.name == "modbus_rtu_rs485"
        and engine.priority == 95
        and engine.is_enabled is True
        and res_reset.status == AgentStatus.SUCCESS
        and engine.diagnostic_code == ModbusRtuDiagnosticCode.OK
        and rt.read_uword("%R1307") == 0x0000
        and rt.read_bit("%M303") is True
        and rt.read_bit("%M304") is False
        and rt.read_word("%R1300") == 192
        and rt.read_word("%R1301") == 2005
        and rt.read_word("%R1302") == 500
        and rt.read_uword("%R1306") == 0x0100
    )
    test_results.append({
        "stage": 9,
        "check": "Closed_Loop_Scan_Cycle_And_Operator_Reset_Synchronization",
        "passed": s9_pass,
        "details": "ILogicUnit scan execution, manual operator reset handshake, and full memory synchronization verified.",
    })

    # ------------------------------------------------------------------------
    # Verification Summary & Evidence Serialization
    # ------------------------------------------------------------------------
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Industrial Modbus RTU RS-485 Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} stages passed).",
        "data": {
            "work_package": "W169",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial Modbus RTU Over RS-485 Half-Duplex Turnaround & Inter-Frame Silent Interval Engine",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R1300..%R1307",
                "discrete_coils": "%M303..%M304",
                "values": {
                    "%R1300": rt.read_word("%R1300"),
                    "%R1301": rt.read_word("%R1301"),
                    "%R1302": rt.read_word("%R1302"),
                    "%R1303": rt.read_uword("%R1303"),
                    "%R1304": rt.read_word("%R1304"),
                    "%R1305": rt.read_word("%R1305"),
                    "%R1306": rt.read_uword("%R1306"),
                    "%R1307": rt.read_uword("%R1307"),
                    "%M303": rt.read_bit("%M303"),
                    "%M304": rt.read_bit("%M304"),
                },
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    out_target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_modbus_rtu_rs485_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
