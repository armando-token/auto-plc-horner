"""CC-Link IE Field Basic Cyclic Transmission & Slave Station Protocol Engine.

Work Package: W166 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- CLPA CC-Link IE Field Basic Specification
- IEC 61158 Fieldbus Standards for Industrial Control
- IEC 61131-3 Programmable Controllers - Structured Text (ST)

Architecture:
1. CC-Link IE Field Basic Protocol Engine:
   - Cyclic transmission over 100BASE-TX / 1000BASE-T Ethernet UDP (nominal port 61450 / 0xF002).
   - Master-to-Slave cyclic request and response frame parsing:
     * Link devices: RX (remote inputs bitmask), RY (remote outputs bitmask),
       RWr (remote read registers INT16), RWw (remote write registers INT16).
     * Double-buffered link device storage to eliminate torn reads/writes across scans.
     * Group cycle time tracking (nominal 10.0 ms, scaled x10 ms = 100 in INT16).
     * Disconnection detection timeout monitoring (nominal 50.0 ms, scaled x10 ms = 500 in INT16).
     * Slave station diagnostic state machine:
       DISCONNECTED (0), LINK_SCAN_WAIT (1), CYCLIC_INITIALIZING (2),
       CYCLIC_OPERATION (3), COMMUNICATION_FAULT (4).
     * Frame transaction ID and sequence consistency surveillance.
     * CRC-16-CCITT packet checksum integrity verification.
     * Implements ILogicUnit interface with scan_step(dt).

2. Process Safety Interlocks & Diagnostics:
   - 0x0000: OK (healthy cyclic communication)
   - 0xBF01: CCLINK_ERR_CYCLIC_TIMEOUT (cyclic frame timeout > 50.0 ms) -> asserts %M297, clears %M296
   - 0xBF02: CCLINK_ERR_TRANSACTION_ID_MISMATCH (unexpected or out-of-sequence transaction ID)
   - 0xBF03: CCLINK_ERR_STATION_NUMBER_COLLISION (duplicate station ID or IP collision)
   - 0xBF04: CCLINK_ERR_FRAME_CRC_CORRUPTED (packet CRC mismatch or truncated cyclic frame)

3. Horner OCS Memory Space Integration:
   - %R1270: CyclicCycleTimeMsScaled (INT16, scaled x10 ms, e.g. 100 = 10.0 ms)
   - %R1271: OccupiedStationsCount (INT16, e.g. 1 station, 4 link devices)
   - %R1272: TransactionSequenceCounter (UINT16, monotonic sequence 0..65535)
   - %R1273: CyclicTimeoutMsScaled (INT16, scaled x10 ms, e.g. 500 = 50.0 ms)
   - %R1274: FrameCrcErrorCount (INT16, count of CRC errors)
   - %R1275: SlaveStationStatusWord (INT16, bitmask of slave status and link state)
   - %R1276: StationNumberAndGroupWord (UINT16, station ID byte + group ID byte)
   - %R1277: DiagnosticStatusCode (0x0000=OK, 0xBF01, 0xBF02, 0xBF03, 0xBF04)
   - %M296: CcLinkPermissive (BOOL)
   - %M297: CcLinkFaultTrip (BOOL)
   - All RegisterTable writes performed with PrivilegeMode.SYSTEM.

4. Pure IEC 61131-3 Structured Text POUs:
   - 'CcLinkIeFieldBasicSync' (and alias 'CcLinkIeBasicSlaveSync')
   - Validated against ladder logic constructs with ERR_LADDER_FORBIDDEN.

5. Deterministic 9-Stage Verification Suite:
   - run_cclink_basic_verification(output_path) returning strict 4-state contract JSON.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
from pathlib import Path
import struct
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Timing Definitions (CLPA CC-Link IE Field Basic / IEC 61158)
# ============================================================================

CCLINK_BASIC_MAGIC: bytes = b"CCBF"                      # 4-byte header magic: CC-Link Basic Frame
CCLINK_BASIC_PROTOCOL_VERSION: int = 0x0100             # Protocol version 1.0
CCLINK_BASIC_DEFAULT_PORT: int = 61450                  # Standard UDP Port (0xF002)
CCLINK_BASIC_NOMINAL_CYCLE_TIME_MS: float = 10.0        # 10.0 ms nominal group cycle time
CCLINK_BASIC_NOMINAL_TIMEOUT_MS: float = 50.0           # 50.0 ms disconnection detection timeout
CCLINK_BASIC_MAX_STATION_ID: int = 64                   # CC-Link IE Field Basic supports 1..64
CCLINK_BASIC_MAX_GROUP_ID: int = 4                      # Up to 4 cyclic groups
CCLINK_BASIC_MAX_OCCUPIED_STATIONS: int = 4             # 1 to 4 occupied stations per slave device

# Standard Link Device Allocation per Occupied Station (CLPA Specification)
CCLINK_BASIC_BITS_PER_STATION: int = 64                 # 64 RX / RY bits (8 bytes) per occupied station
CCLINK_BASIC_BYTES_PER_STATION: int = 8                 # 8 bytes per occupied station
CCLINK_BASIC_WORDS_PER_STATION: int = 32                # 32 RWr / RWw 16-bit words (64 bytes) per station

# Binary Frame Header Structure:
#   magic: 4 bytes (s)
#   version: 2 bytes (H)
#   frame_type: 1 byte (B)
#   group_id: 1 byte (B)
#   station_id: 1 byte (B)
#   occupied_stations: 1 byte (B)
#   transaction_id: 2 bytes (H)
#   cycle_time_scaled: 2 bytes (h)
#   timeout_scaled: 2 bytes (h)
#   payload_len: 2 bytes (H)
CCLINK_BASIC_HEADER_FORMAT: str = ">4sHBBBBHhhH"
CCLINK_BASIC_HEADER_SIZE: int = struct.calcsize(CCLINK_BASIC_HEADER_FORMAT)  # 18 bytes


# ============================================================================
# 2. Enums, Status Flags, & Diagnostic Codes
# ============================================================================

class CcLinkBasicDiagnosticCode(IntEnum):
    """Horner OCS %R1277 Diagnostic Event Codes for CC-Link IE Field Basic."""
    OK = 0x0000                                         # Healthy cyclic communication
    CCLINK_ERR_CYCLIC_TIMEOUT = 0xBF01                  # Frame timeout > 50.0 ms
    CCLINK_ERR_TRANSACTION_ID_MISMATCH = 0xBF02         # Corrupted / unexpected transaction ID
    CCLINK_ERR_STATION_NUMBER_COLLISION = 0xBF03        # Duplicate station ID or IP collision
    CCLINK_ERR_FRAME_CRC_CORRUPTED = 0xBF04             # CRC checksum failure or truncated frame

    # Standard W166 Aliases
    CYCLIC_TIMEOUT = 0xBF01
    TRANSACTION_ID_MISMATCH = 0xBF02
    STATION_NUMBER_COLLISION = 0xBF03
    FRAME_CRC_CORRUPTED = 0xBF04
    ERR_CYCLIC_TIMEOUT = 0xBF01
    ERR_TRANSACTION_ID_MISMATCH = 0xBF02
    ERR_STATION_NUMBER_COLLISION = 0xBF03
    ERR_FRAME_CRC_CORRUPTED = 0xBF04


class CcLinkBasicSlaveState(IntEnum):
    """CC-Link IE Field Basic Slave Station Diagnostic State Machine."""
    DISCONNECTED = 0          # Station disconnected / initial unlinked state
    LINK_SCAN_WAIT = 1        # Listening for master link scan / discovery frame
    CYCLIC_INITIALIZING = 2   # Request received; validating parameters and group cycle
    CYCLIC_OPERATION = 3      # Normal deterministic cyclic process data exchange
    COMMUNICATION_FAULT = 4   # Latched process safety fault condition

    # Case aliases
    Disconnected = 0
    LinkScanWait = 1
    CyclicInitializing = 2
    CyclicOperation = 3
    CommunicationFault = 4


class CcLinkBasicStatusBits(IntFlag):
    """Horner OCS %R1275 SlaveStationStatusWord Bitmask Definitions."""
    PERMISSIVE = 1 << 0             # Bit 0 (0x0001): %M296 CcLinkPermissive active
    FAULT_TRIP = 1 << 1             # Bit 1 (0x0002): %M297 CcLinkFaultTrip active
    LINK_ESTABLISHED = 1 << 2       # Bit 2 (0x0004): Ethernet link scan synchronized
    CYCLIC_RUNNING = 1 << 3         # Bit 3 (0x0008): Active cyclic I/O data exchange
    TIMEOUT_ALARM = 1 << 4          # Bit 4 (0x0010): Cyclic timeout exceeded (> 50.0 ms)
    TRANSACTION_ID_ALARM = 1 << 5   # Bit 5 (0x0020): Transaction ID mismatch / sequence error
    COLLISION_ALARM = 1 << 6        # Bit 6 (0x0040): Duplicate station or IP address collision
    CRC_ERROR_ALARM = 1 << 7        # Bit 7 (0x0080): Frame CRC or truncation corrupted
    RX_VALID = 1 << 8               # Bit 8 (0x0100): Remote inputs RX image updated
    RY_VALID = 1 << 9               # Bit 9 (0x0200): Remote outputs RY image updated
    RWW_VALID = 1 << 10             # Bit 10 (0x0400): Remote word writes RWw image updated
    RWR_VALID = 1 << 11             # Bit 11 (0x0800): Remote word reads RWr image updated


class CcLinkBasicFrameType(IntEnum):
    """CC-Link IE Field Basic frame type specifiers."""
    CYCLIC_REQUEST = 0x01       # Master -> Slave cyclic transmission request (RY + RWw)
    CYCLIC_RESPONSE = 0x02      # Slave -> Master cyclic transmission response (RX + RWr)
    DISCOVERY_REQUEST = 0x03    # Master broadcast station discovery / link scan
    DISCOVERY_RESPONSE = 0x04   # Slave unicast discovery response
    DIAGNOSTIC_REQUEST = 0x05   # Diagnostic / parameter query
    DIAGNOSTIC_RESPONSE = 0x06  # Diagnostic / parameter reply


# ============================================================================
# 3. Exceptions
# ============================================================================

class CcLinkBasicError(Exception):
    """Base exception for CC-Link IE Field Basic protocol errors."""
    pass


class CcLinkCyclicTimeoutError(CcLinkBasicError):
    """Raised when cyclic frame arrival exceeds disconnection detection timeout (0xBF01)."""
    pass


class CcLinkTransactionIdMismatchError(CcLinkBasicError):
    """Raised when frame transaction ID or sequence counter is corrupted or out-of-order (0xBF02)."""
    pass


class CcLinkStationCollisionError(CcLinkBasicError):
    """Raised when duplicate station ID or IP collision is detected on the network (0xBF03)."""
    pass


class CcLinkFrameCrcError(CcLinkBasicError):
    """Raised when frame CRC-16 checksum fails or payload is truncated (0xBF04)."""
    pass


# ============================================================================
# 4. Scaling, Word Packing, & CRC Utility Functions
# ============================================================================

def calculate_cclink_crc16(data: bytes, init: int = 0xFFFF) -> int:
    """Calculate CRC-16-CCITT (polynomial 0x1021) for CC-Link IE Field Basic frame.

    Args:
        data: Byte sequence over which checksum is computed.
        init: Initial CRC register value (default 0xFFFF).

    Returns:
        16-bit unsigned integer checksum.
    """
    crc = init
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


# CRC aliases
compute_crc16 = calculate_cclink_crc16
calculate_crc16_ccitt = calculate_cclink_crc16


def scale_time_ms_to_int16(time_ms: float) -> int:
    """Scale millisecond duration to Horner INT16 (scaled x10 ms, e.g. 10.0 ms -> 100)."""
    scaled = int(round(time_ms * 10.0))
    return max(-32768, min(32767, scaled))


def unscale_int16_to_time_ms(val_scaled: int) -> float:
    """Convert scaled x10 ms Horner INT16 back to floating-point milliseconds."""
    return float(val_scaled) / 10.0


def compute_crc32(data: bytes, init: int = 0xFFFFFFFF, poly: int = 0xEDB88320) -> int:
    """Compute 32-bit CRC with polynomial 0xEDB88320 (IEEE 802.3)."""
    crc = init
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc = (crc >> 1) & 0xFFFFFFFF
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


scale_ms_to_int16 = scale_time_ms_to_int16

# Additional protocol constants & aliases
CCLINK_BASIC_CRC16_INIT: int = 0xFFFF
CCLINK_BASIC_CRC16_POLY: int = 0x1021
CCLINK_BASIC_CRC32_INIT: int = 0xFFFFFFFF
CCLINK_BASIC_CRC32_POLY: int = 0xEDB88320

CCLINK_BASIC_NOMINAL_CYCLE_MS: float = CCLINK_BASIC_NOMINAL_CYCLE_TIME_MS
CCLINK_BASIC_NOMINAL_CYCLE_SCALED: int = 100
CCLINK_BASIC_DEFAULT_CYCLE_MS: float = CCLINK_BASIC_NOMINAL_CYCLE_TIME_MS
CCLINK_BASIC_DEFAULT_CYCLE_SCALED: int = 100
CCLINK_BASIC_DISCONNECTION_TIMEOUT_MS: float = CCLINK_BASIC_NOMINAL_TIMEOUT_MS
CCLINK_BASIC_NOMINAL_TIMEOUT_SCALED: int = 500
CCLINK_BASIC_DEFAULT_WATCHDOG_MS: float = CCLINK_BASIC_NOMINAL_TIMEOUT_MS

CCLINK_BASIC_MAX_SLAVE_STATIONS: int = CCLINK_BASIC_MAX_STATION_ID
CCLINK_BASIC_DEFAULT_STATION_NO: int = 1
CCLINK_BASIC_DEFAULT_GROUP_NO: int = 1
CCLINK_BASIC_DEFAULT_RX_BYTES: int = CCLINK_BASIC_BYTES_PER_STATION
CCLINK_BASIC_DEFAULT_RY_BYTES: int = CCLINK_BASIC_BYTES_PER_STATION
CCLINK_BASIC_DEFAULT_RWW_WORDS: int = CCLINK_BASIC_WORDS_PER_STATION
CCLINK_BASIC_DEFAULT_RWR_WORDS: int = CCLINK_BASIC_WORDS_PER_STATION
CCLINK_BASIC_PORT: int = CCLINK_BASIC_DEFAULT_PORT
CCLINK_BASIC_HEADER_MAGIC: bytes = CCLINK_BASIC_MAGIC


def encode_station_group_word(station_id: int, group_id: int) -> int:
    """Encode station ID (high byte) and group ID (low byte) into UINT16 word (%R1276)."""
    return ((int(station_id) & 0xFF) << 8) | (int(group_id) & 0xFF)


def decode_station_group_word(word: int) -> Tuple[int, int]:
    """Decode UINT16 word (%R1276) into station ID (high byte) and group ID (low byte)."""
    station_id = (int(word) >> 8) & 0xFF
    group_id = int(word) & 0xFF
    return station_id, group_id


def safe_write_uword(rt: RegisterTable, address: str, value: int) -> None:
    """Safely writes a 16-bit unsigned word to RegisterTable with SYSTEM privilege."""
    val_16 = int(value) & 0xFFFF
    if val_16 > 32767:
        val_16 -= 65536
    rt.write_word(address, val_16, privilege=PrivilegeMode.SYSTEM)


def safe_write_word(rt: RegisterTable, address: str, value: int) -> None:
    """Safely writes a 16-bit signed word to RegisterTable with SYSTEM privilege."""
    val_16 = int(value) & 0xFFFF
    if val_16 > 32767:
        val_16 -= 65536
    rt.write_word(address, val_16, privilege=PrivilegeMode.SYSTEM)


def safe_write_bit(rt: RegisterTable, address: str, value: bool) -> None:
    """Safely writes a discrete bit to RegisterTable with SYSTEM privilege."""
    rt.write_bit(address, bool(value), privilege=PrivilegeMode.SYSTEM)


# ============================================================================
# 5. Link Device Storage Container (RX, RY, RWw, RWr)
# ============================================================================

class CcLinkBasicLinkDevices:
    """Double-buffered link device storage for CC-Link IE Field Basic.

    Devices:
    - RX: Remote Inputs (bitmask, Slave -> Master, 64 bits per occupied station)
    - RY: Remote Outputs (bitmask, Master -> Slave, 64 bits per occupied station)
    - RWw: Remote Register Writes (16-bit words, Master -> Slave, 32 words per occupied station)
    - RWr: Remote Register Reads (16-bit words, Slave -> Master, 32 words per occupied station)

    Double buffering guarantees atomic scan snapshots, preventing torn reads/writes.
    """

    def __init__(self, occupied_stations: int = 1) -> None:
        self.occupied_stations = max(1, min(CCLINK_BASIC_MAX_OCCUPIED_STATIONS, occupied_stations))
        self.num_bits: int = CCLINK_BASIC_BITS_PER_STATION * self.occupied_stations
        self.num_bytes: int = CCLINK_BASIC_BYTES_PER_STATION * self.occupied_stations
        self.num_words: int = CCLINK_BASIC_WORDS_PER_STATION * self.occupied_stations

        # Working buffers (for active protocol frame I/O)
        self.rx_bytes: bytearray = bytearray(self.num_bytes)
        self.ry_bytes: bytearray = bytearray(self.num_bytes)
        self.rww_words: List[int] = [0] * self.num_words
        self.rwr_words: List[int] = [0] * self.num_words

        # Shadow buffers (for isolated user application / simulation solve)
        self.shadow_rx_bytes: bytearray = bytearray(self.num_bytes)
        self.shadow_ry_bytes: bytearray = bytearray(self.num_bytes)
        self.shadow_rww_words: List[int] = [0] * self.num_words
        self.shadow_rwr_words: List[int] = [0] * self.num_words

    # --- Discrete Bit Access ---

    def get_rx_bit(self, point: int) -> bool:
        """Read a single Remote Input (RX) bit (0..num_bits-1)."""
        if point < 0 or point >= self.num_bits:
            raise IndexError(f"RX point {point} out of range (0..{self.num_bits - 1})")
        byte_idx = point // 8
        bit_idx = point % 8
        return bool((self.shadow_rx_bytes[byte_idx] >> bit_idx) & 0x01)

    def set_rx_bit(self, point: int, value: bool) -> None:
        """Write a single Remote Input (RX) bit in shadow buffer."""
        if point < 0 or point >= self.num_bits:
            raise IndexError(f"RX point {point} out of range (0..{self.num_bits - 1})")
        byte_idx = point // 8
        bit_idx = point % 8
        if value:
            self.shadow_rx_bytes[byte_idx] |= (1 << bit_idx)
        else:
            self.shadow_rx_bytes[byte_idx] &= ~(1 << bit_idx)

    def get_ry_bit(self, point: int) -> bool:
        """Read a single Remote Output (RY) bit (0..num_bits-1)."""
        if point < 0 or point >= self.num_bits:
            raise IndexError(f"RY point {point} out of range (0..{self.num_bits - 1})")
        byte_idx = point // 8
        bit_idx = point % 8
        return bool((self.shadow_ry_bytes[byte_idx] >> bit_idx) & 0x01)

    def set_ry_bit(self, point: int, value: bool) -> None:
        """Write a single Remote Output (RY) bit in working buffer."""
        if point < 0 or point >= self.num_bits:
            raise IndexError(f"RY point {point} out of range (0..{self.num_bits - 1})")
        byte_idx = point // 8
        bit_idx = point % 8
        if value:
            self.ry_bytes[byte_idx] |= (1 << bit_idx)
        else:
            self.ry_bytes[byte_idx] &= ~(1 << bit_idx)

    # --- 16-Bit Word Access ---

    def get_rww_word(self, index: int) -> int:
        """Read a Remote Word Write (RWw) register from shadow buffer."""
        if index < 0 or index >= self.num_words:
            raise IndexError(f"RWw index {index} out of range (0..{self.num_words - 1})")
        return self.shadow_rww_words[index]

    def set_rww_word(self, index: int, value: int) -> None:
        """Write a Remote Word Write (RWw) register in working buffer."""
        if index < 0 or index >= self.num_words:
            raise IndexError(f"RWw index {index} out of range (0..{self.num_words - 1})")
        val_16 = int(value) & 0xFFFF
        if val_16 > 32767:
            val_16 -= 65536
        self.rww_words[index] = val_16

    def get_rwr_word(self, index: int) -> int:
        """Read a Remote Word Read (RWr) register from shadow buffer."""
        if index < 0 or index >= self.num_words:
            raise IndexError(f"RWr index {index} out of range (0..{self.num_words - 1})")
        return self.shadow_rwr_words[index]

    def set_rwr_word(self, index: int, value: int) -> None:
        """Write a Remote Word Read (RWr) register in shadow buffer."""
        if index < 0 or index >= self.num_words:
            raise IndexError(f"RWr index {index} out of range (0..{self.num_words - 1})")
        val_16 = int(value) & 0xFFFF
        if val_16 > 32767:
            val_16 -= 65536
        self.shadow_rwr_words[index] = val_16

    # --- Raw Stream Access & Double Buffering ---

    def get_rx_bytes(self) -> bytes:
        """Get packed bytes of outgoing Remote Inputs (RX)."""
        return bytes(self.rx_bytes)

    def set_rx_bytes(self, data: bytes) -> None:
        """Set packed bytes of outgoing Remote Inputs (RX) in shadow buffer."""
        limit = min(len(data), self.num_bytes)
        self.shadow_rx_bytes[:limit] = data[:limit]

    def get_ry_bytes(self) -> bytes:
        """Get packed bytes of incoming Remote Outputs (RY)."""
        return bytes(self.ry_bytes)

    def set_ry_bytes(self, data: bytes) -> None:
        """Set packed bytes of incoming Remote Outputs (RY) in working buffer."""
        limit = min(len(data), self.num_bytes)
        self.ry_bytes[:limit] = data[:limit]

    def get_rww_words(self) -> List[int]:
        """Get copy of incoming Remote Word Writes (RWw)."""
        return list(self.rww_words)

    def set_rww_words(self, words: Sequence[int]) -> None:
        """Set incoming Remote Word Writes (RWw) in working buffer."""
        limit = min(len(words), self.num_words)
        for i in range(limit):
            val_16 = int(words[i]) & 0xFFFF
            if val_16 > 32767:
                val_16 -= 65536
            self.rww_words[i] = val_16

    def get_rwr_words(self) -> List[int]:
        """Get copy of outgoing Remote Word Reads (RWr)."""
        return list(self.rwr_words)

    def set_rwr_words(self, words: Sequence[int]) -> None:
        """Set outgoing Remote Word Reads (RWr) in shadow buffer."""
        limit = min(len(words), self.num_words)
        for i in range(limit):
            val_16 = int(words[i]) & 0xFFFF
            if val_16 > 32767:
                val_16 -= 65536
            self.shadow_rwr_words[i] = val_16

    def commit_inbound(self) -> None:
        """Atomically copy incoming RY and RWw from working buffer to shadow buffer."""
        self.shadow_ry_bytes[:] = self.ry_bytes[:]
        self.shadow_rww_words[:] = self.rww_words[:]

    def commit_outbound(self) -> None:
        """Atomically copy outgoing RX and RWr from shadow buffer to working buffer."""
        self.rx_bytes[:] = self.shadow_rx_bytes[:]
        self.rwr_words[:] = self.shadow_rwr_words[:]

    def zero_outputs(self) -> None:
        """Fail-safe output forcing: zero all Remote Outputs (RY) and Remote Word Writes (RWw)."""
        for i in range(len(self.ry_bytes)):
            self.ry_bytes[i] = 0
            self.shadow_ry_bytes[i] = 0
        for i in range(len(self.rww_words)):
            self.rww_words[i] = 0
            self.shadow_rww_words[i] = 0

    def pack_rx(self) -> bytes:
        return self.get_rx_bytes()

    def unpack_rx(self, data: bytes) -> None:
        self.set_rx_bytes(data)

    def pack_ry(self) -> bytes:
        return self.get_ry_bytes()

    def unpack_ry(self, data: bytes) -> None:
        self.set_ry_bytes(data)

    def pack_rww(self) -> bytes:
        words = self.get_rww_words()
        return struct.pack(f">{len(words)}h", *words)

    def unpack_rww(self, data: bytes) -> None:
        count = len(data) // 2
        if count > 0:
            words = list(struct.unpack(f">{count}h", data[:count * 2]))
            self.set_rww_words(words)

    def pack_rwr(self) -> bytes:
        words = self.get_rwr_words()
        return struct.pack(f">{len(words)}h", *words)

    def unpack_rwr(self, data: bytes) -> None:
        count = len(data) // 2
        if count > 0:
            words = list(struct.unpack(f">{count}h", data[:count * 2]))
            self.set_rwr_words(words)


# ============================================================================
# 6. CC-Link IE Field Basic Network Frame Structure
# ============================================================================

@dataclass
class CcLinkBasicFrame:
    """CC-Link IE Field Basic Data Link Layer / UDP Cyclic Frame Descriptor."""
    frame_type: CcLinkBasicFrameType
    transaction_id: int
    station_id: int
    group_id: int = 1
    occupied_stations: int = 1
    cycle_time_scaled: int = 100                     # nominal 10.0 ms (scaled x10)
    timeout_scaled: int = 500                        # nominal 50.0 ms (scaled x10)
    version: int = CCLINK_BASIC_PROTOCOL_VERSION
    rx_bits: bytes = b""                             # Remote Inputs bitmask (Response)
    ry_bits: bytes = b""                             # Remote Outputs bitmask (Request)
    rww_registers: List[int] = field(default_factory=list) # Remote Word Writes (Request)
    rwr_registers: List[int] = field(default_factory=list) # Remote Word Reads (Response)
    raw_payload: bytes = b""
    crc: int = 0
    ip_address: str = "192.168.3.10"
    udp_port: int = CCLINK_BASIC_DEFAULT_PORT

    def serialize(self) -> bytes:
        """Serializes the frame to binary bytes with CRC-16-CCITT integrity checksum."""
        payload = bytearray()
        occ = max(1, self.occupied_stations)
        req_bits_len = CCLINK_BASIC_BYTES_PER_STATION * occ
        req_words_count = CCLINK_BASIC_WORDS_PER_STATION * occ

        if self.frame_type == CcLinkBasicFrameType.CYCLIC_REQUEST:
            ry = self.ry_bits if isinstance(self.ry_bits, (bytes, bytearray)) else bytes(self.ry_bits)
            payload.extend(ry.ljust(req_bits_len, b"\x00")[:req_bits_len])
            words = self.rww_registers[:req_words_count]
            for w in words:
                val = int(w) & 0xFFFF
                if val > 32767:
                    val -= 65536
                payload.extend(struct.pack(">h", val))
            remaining = req_words_count - len(words)
            if remaining > 0:
                payload.extend(b"\x00" * (remaining * 2))

        elif self.frame_type == CcLinkBasicFrameType.CYCLIC_RESPONSE:
            rx = self.rx_bits if isinstance(self.rx_bits, (bytes, bytearray)) else bytes(self.rx_bits)
            payload.extend(rx.ljust(req_bits_len, b"\x00")[:req_bits_len])
            words = self.rwr_registers[:req_words_count]
            for w in words:
                val = int(w) & 0xFFFF
                if val > 32767:
                    val -= 65536
                payload.extend(struct.pack(">h", val))
            remaining = req_words_count - len(words)
            if remaining > 0:
                payload.extend(b"\x00" * (remaining * 2))

        elif self.raw_payload:
            payload.extend(self.raw_payload)

        header = struct.pack(
            CCLINK_BASIC_HEADER_FORMAT,
            CCLINK_BASIC_MAGIC,
            self.version,
            int(self.frame_type),
            int(self.group_id) & 0xFF,
            int(self.station_id) & 0xFF,
            int(self.occupied_stations) & 0xFF,
            int(self.transaction_id) & 0xFFFF,
            int(self.cycle_time_scaled),
            int(self.timeout_scaled),
            len(payload),
        )

        raw_packet = bytes(header + payload)
        computed_crc = calculate_cclink_crc16(raw_packet)
        self.crc = computed_crc
        return raw_packet + struct.pack(">H", computed_crc)

    @classmethod
    def parse(cls, data: bytes) -> "CcLinkBasicFrame":
        """Parses a binary frame, verifying magic, payload length, and CRC-16 checksum.

        Raises:
            CcLinkFrameCrcError: If frame is truncated, magic is wrong, or CRC mismatch.
        """
        if len(data) < CCLINK_BASIC_HEADER_SIZE + 2:
            raise CcLinkFrameCrcError(
                f"Frame truncated: length {len(data)} is less than minimum {CCLINK_BASIC_HEADER_SIZE + 2} bytes."
            )

        header_data = data[:CCLINK_BASIC_HEADER_SIZE]
        (
            magic,
            version,
            frame_type_val,
            group_id,
            station_id,
            occupied_stations,
            transaction_id,
            cycle_time_scaled,
            timeout_scaled,
            payload_len,
        ) = struct.unpack(CCLINK_BASIC_HEADER_FORMAT, header_data)

        if magic != CCLINK_BASIC_MAGIC:
            raise CcLinkFrameCrcError(
                f"Invalid header magic: {magic!r}, expected {CCLINK_BASIC_MAGIC!r}."
            )

        expected_total_len = CCLINK_BASIC_HEADER_SIZE + payload_len + 2
        if len(data) < expected_total_len:
            raise CcLinkFrameCrcError(
                f"Frame truncated: received {len(data)} bytes, expected {expected_total_len} bytes."
            )

        payload = data[CCLINK_BASIC_HEADER_SIZE : CCLINK_BASIC_HEADER_SIZE + payload_len]
        received_crc = struct.unpack(">H", data[CCLINK_BASIC_HEADER_SIZE + payload_len : expected_total_len])[0]
        calculated_crc = calculate_cclink_crc16(data[: CCLINK_BASIC_HEADER_SIZE + payload_len])

        if received_crc != calculated_crc:
            raise CcLinkFrameCrcError(
                f"Frame CRC corrupted: received 0x{received_crc:04X}, computed 0x{calculated_crc:04X}."
            )

        try:
            frame_type = CcLinkBasicFrameType(frame_type_val)
        except ValueError:
            frame_type = CcLinkBasicFrameType.CYCLIC_REQUEST

        rx_bits = b""
        ry_bits = b""
        rww_registers: List[int] = []
        rwr_registers: List[int] = []

        occ = max(1, occupied_stations)
        req_bits_len = CCLINK_BASIC_BYTES_PER_STATION * occ

        if frame_type == CcLinkBasicFrameType.CYCLIC_REQUEST:
            ry_bits = payload[:req_bits_len]
            word_data = payload[req_bits_len:]
            num_words = len(word_data) // 2
            for i in range(num_words):
                val = struct.unpack(">h", word_data[i * 2 : (i + 1) * 2])[0]
                rww_registers.append(val)

        elif frame_type == CcLinkBasicFrameType.CYCLIC_RESPONSE:
            rx_bits = payload[:req_bits_len]
            word_data = payload[req_bits_len:]
            num_words = len(word_data) // 2
            for i in range(num_words):
                val = struct.unpack(">h", word_data[i * 2 : (i + 1) * 2])[0]
                rwr_registers.append(val)

        return cls(
            frame_type=frame_type,
            transaction_id=transaction_id,
            station_id=station_id,
            group_id=group_id,
            occupied_stations=occupied_stations,
            cycle_time_scaled=cycle_time_scaled,
            timeout_scaled=timeout_scaled,
            version=version,
            rx_bits=rx_bits,
            ry_bits=ry_bits,
            rww_registers=rww_registers,
            rwr_registers=rwr_registers,
            raw_payload=payload,
            crc=received_crc,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "CcLinkBasicFrame":
        """Alias for parse."""
        return cls.parse(data)

    @classmethod
    def create(
        cls,
        command: Union[CcLinkBasicFrameType, int] = CcLinkBasicFrameType.CYCLIC_REQUEST,
        transaction_id: int = 1,
        station_no: int = 1,
        group_no: int = 1,
        occupied_stations: int = 1,
        cycle_time_scaled: int = 100,
        timeout_scaled: int = 500,
        rx_payload: bytes = b"",
        ry_payload: bytes = b"",
        rww_payload: Union[bytes, Sequence[int]] = (),
        rwr_payload: Union[bytes, Sequence[int]] = (),
        rx_bits: bytes = b"",
        ry_bits: bytes = b"",
        rww_registers: Sequence[int] = (),
        rwr_registers: Sequence[int] = (),
        station_id: Optional[int] = None,
        group_id: Optional[int] = None,
    ) -> "CcLinkBasicFrame":
        ft = command if isinstance(command, CcLinkBasicFrameType) else CcLinkBasicFrameType(command)
        st_id = station_id if station_id is not None else station_no
        grp_id = group_id if group_id is not None else group_no
        rx = rx_payload or rx_bits
        ry = ry_payload or ry_bits

        if isinstance(rww_payload, (bytes, bytearray)):
            cnt = len(rww_payload) // 2
            rww = list(struct.unpack(f">{cnt}h", rww_payload[:cnt * 2])) if cnt > 0 else []
        else:
            rww = list(rww_payload) if rww_payload else list(rww_registers)

        if isinstance(rwr_payload, (bytes, bytearray)):
            cnt = len(rwr_payload) // 2
            rwr = list(struct.unpack(f">{cnt}h", rwr_payload[:cnt * 2])) if cnt > 0 else []
        else:
            rwr = list(rwr_payload) if rwr_payload else list(rwr_registers)

        return cls(
            frame_type=ft,
            transaction_id=transaction_id,
            station_id=st_id,
            group_id=grp_id,
            occupied_stations=occupied_stations,
            cycle_time_scaled=cycle_time_scaled,
            timeout_scaled=timeout_scaled,
            rx_bits=rx,
            ry_bits=ry,
            rww_registers=rww,
            rwr_registers=rwr,
        )

    @property
    def command(self) -> CcLinkBasicFrameType:
        return self.frame_type

    @property
    def station_no(self) -> int:
        return self.station_id

    @property
    def group_no(self) -> int:
        return self.group_id

    @property
    def rx_payload(self) -> bytes:
        return self.rx_bits

    @property
    def ry_payload(self) -> bytes:
        return self.ry_bits

    @property
    def rww_payload(self) -> bytes:
        return struct.pack(f">{len(self.rww_registers)}h", *self.rww_registers)

    @property
    def rwr_payload(self) -> bytes:
        return struct.pack(f">{len(self.rwr_registers)}h", *self.rwr_registers)


# ============================================================================
# 7. Pure IEC 61131-3 Structured Text POUs
# ============================================================================

CCLINK_BASIC_SYNC_POU: str = """PROGRAM CcLinkIeFieldBasicSync
VAR
    (* Horner OCS Mapped Registers (W166 - CC-Link IE Field Basic Cyclic Protocol Engine) *)
    CyclicCycleTimeMsScaled AT %R1270 : INT;
    OccupiedStationsCount AT %R1271 : INT;
    TransactionSequenceCounter AT %R1272 : UINT;
    CyclicTimeoutMsScaled AT %R1273 : INT;
    FrameCrcErrorCount AT %R1274 : INT;
    SlaveStationStatusWord AT %R1275 : INT;
    StationNumberAndGroupWord AT %R1276 : UINT;
    DiagnosticStatusCode AT %R1277 : UINT;
    CcLinkPermissive AT %M296 : BOOL;
    CcLinkFaultTrip AT %M297 : BOOL;

    (* Internal IEC 61131-3 Diagnostics & Control Flags *)
    CycleWatchdogTimer : INT := 0;
    StationOnline : BOOL := FALSE;
    HeartbeatBit : BOOL := FALSE;
END_VAR

(* CC-Link IE Field Basic Slave Station Diagnostic Interlock *)
IF DiagnosticStatusCode = 0 THEN
    CcLinkPermissive := TRUE;
    CcLinkFaultTrip := FALSE;
ELSE
    CcLinkPermissive := FALSE;
    CcLinkFaultTrip := TRUE;
END_IF;

IF CyclicTimeoutMsScaled > 500 THEN
    CcLinkPermissive := FALSE;
    CcLinkFaultTrip := TRUE;
    DiagnosticStatusCode := 48897; (* 0xBF01: CCLINK_ERR_CYCLIC_TIMEOUT *)
END_IF;

IF FrameCrcErrorCount > 0 THEN
    DiagnosticStatusCode := 48900; (* 0xBF04: CCLINK_ERR_FRAME_CRC_CORRUPTED *)
    CcLinkPermissive := FALSE;
    CcLinkFaultTrip := TRUE;
END_IF;
END_PROGRAM
"""

CCLINK_BASIC_SLAVE_SYNC_POU: str = """PROGRAM CcLinkIeBasicSlaveSync
VAR
    (* Horner OCS Mapped Registers (W166 - CC-Link IE Field Basic Cyclic Protocol Engine) *)
    CyclicCycleTimeMsScaled AT %R1270 : INT;
    OccupiedStationsCount AT %R1271 : INT;
    TransactionSequenceCounter AT %R1272 : UINT;
    CyclicTimeoutMsScaled AT %R1273 : INT;
    FrameCrcErrorCount AT %R1274 : INT;
    SlaveStationStatusWord AT %R1275 : INT;
    StationNumberAndGroupWord AT %R1276 : UINT;
    DiagnosticStatusCode AT %R1277 : UINT;
    CcLinkPermissive AT %M296 : BOOL;
    CcLinkFaultTrip AT %M297 : BOOL;

    (* Internal IEC 61131-3 Diagnostics & Control Flags *)
    CycleWatchdogTimer : INT := 0;
    StationOnline : BOOL := FALSE;
    HeartbeatBit : BOOL := FALSE;
END_VAR

(* CC-Link IE Field Basic Slave Station Diagnostic Interlock *)
IF DiagnosticStatusCode = 0 THEN
    CcLinkPermissive := TRUE;
    CcLinkFaultTrip := FALSE;
ELSE
    CcLinkPermissive := FALSE;
    CcLinkFaultTrip := TRUE;
END_IF;

IF CyclicTimeoutMsScaled > 500 THEN
    CcLinkPermissive := FALSE;
    CcLinkFaultTrip := TRUE;
    DiagnosticStatusCode := 48897; (* 0xBF01: CCLINK_ERR_CYCLIC_TIMEOUT *)
END_IF;

IF FrameCrcErrorCount > 0 THEN
    DiagnosticStatusCode := 48900; (* 0xBF04: CCLINK_ERR_FRAME_CRC_CORRUPTED *)
    CcLinkPermissive := FALSE;
    CcLinkFaultTrip := TRUE;
END_IF;
END_PROGRAM
"""

# Aliases for POU strings
CCLINK_IE_FIELD_BASIC_SYNC_POU: str = CCLINK_BASIC_SYNC_POU
PURE_ST_POU: str = CCLINK_BASIC_SYNC_POU
CCLINK_BASIC_PURE_ST_POU: str = CCLINK_BASIC_SYNC_POU


def verify_cclink_basic_pure_st() -> bool:
    """Validate CC-Link IE Field Basic POUs for strict IEC 61131-3 syntax and anti-ladder safety.

    Returns:
        True if all checks pass deterministically.
    """
    SecurityGuard.assert_pure_st_content(CCLINK_BASIC_SYNC_POU)
    SecurityGuard.assert_pure_st_content(CCLINK_BASIC_SLAVE_SYNC_POU)

    res1 = STParser.validate_code(CCLINK_BASIC_SYNC_POU)
    if res1.status != AgentStatus.SUCCESS:
        return False

    res2 = STParser.validate_code(CCLINK_BASIC_SLAVE_SYNC_POU)
    if res2.status != AgentStatus.SUCCESS:
        return False

    ast1 = STParser.parse_pou(CCLINK_BASIC_SYNC_POU)
    ast2 = STParser.parse_pou(CCLINK_BASIC_SLAVE_SYNC_POU)

    expected_regs = {
        "%R1270", "%R1271", "%R1272", "%R1273",
        "%R1274", "%R1275", "%R1276", "%R1277",
        "%M296", "%M297",
    }
    return set(ast1.bound_registers) == expected_regs and set(ast2.bound_registers) == expected_regs


@dataclass
class CcLinkBasicValidationOutcome:
    """Outcome report from processing an incoming CC-Link IE Field Basic frame."""
    is_valid: bool
    diagnostic_code: CcLinkBasicDiagnosticCode
    details: str
    transaction_id: int = 0
    jitter_ms: float = 0.0
    state: CcLinkBasicSlaveState = CcLinkBasicSlaveState.DISCONNECTED


CCLinkBasicValidationOutcome = CcLinkBasicValidationOutcome
ValidationOutcome = CcLinkBasicValidationOutcome


# ============================================================================
# 8. CC-Link IE Field Basic Slave Station Engine (ILogicUnit)
# ============================================================================

class CcLinkIeFieldBasicSlaveEngine(ILogicUnit):
    """CC-Link IE Field Basic Slave Station Protocol Engine.

    Work Package: W166 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
    Classification: PRODUCTION_READY

    Implements:
    - CLPA CC-Link IE Field Basic cyclic transmission slave stack.
    - Diagnostic state machine (DISCONNECTED, LINK_SCAN_WAIT, CYCLIC_INITIALIZING,
      CYCLIC_OPERATION, COMMUNICATION_FAULT).
    - Monotonic transaction ID verification and watchdog timeout monitoring.
    - Horner OCS register space synchronization (%R1270..%R1277, %M296..%M297).
    - Scan cycle simulation integration conforming to ILogicUnit interface.
    """

    def __init__(
        self,
        station_id: int = 1,
        group_id: int = 1,
        occupied_stations: int = 1,
        group_cycle_time_ms: float = CCLINK_BASIC_NOMINAL_CYCLE_TIME_MS,
        disconnection_timeout_ms: float = CCLINK_BASIC_NOMINAL_TIMEOUT_MS,
        ip_address: str = "192.168.3.10",
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.station_id: int = max(1, min(CCLINK_BASIC_MAX_STATION_ID, station_id))
        self.group_id: int = max(1, min(CCLINK_BASIC_MAX_GROUP_ID, group_id))
        self.occupied_stations: int = max(1, min(CCLINK_BASIC_MAX_OCCUPIED_STATIONS, occupied_stations))
        self.group_cycle_time_ms: float = float(group_cycle_time_ms)
        self.disconnection_timeout_ms: float = float(disconnection_timeout_ms)
        self.ip_address: str = ip_address
        self.master_ip: Optional[str] = None

        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.link_devices: CcLinkBasicLinkDevices = CcLinkBasicLinkDevices(occupied_stations=self.occupied_stations)

        # Operational & Diagnostic State
        self.state: CcLinkBasicSlaveState = CcLinkBasicSlaveState.DISCONNECTED
        self.status_bits: CcLinkBasicStatusBits = CcLinkBasicStatusBits(0)
        self.diagnostic_code: CcLinkBasicDiagnosticCode = CcLinkBasicDiagnosticCode.OK
        self.permissive: bool = False
        self.fault_trip: bool = False

        # Protocol Tracking
        self.last_transaction_id: int = 0
        self.transaction_sequence_counter: int = 0
        self.frame_crc_error_count: int = 0
        self.time_since_last_rx_ms: float = 0.0
        self.elapsed_time_ms: float = 0.0
        self.total_cyclic_frames: int = 0
        self.duplicate_station_detected: bool = False
        self.last_rx_time_ms: float = 0.0
        self.observed_jitter_ms: float = 0.0
        self.max_jitter_ms: float = 0.0

        # Network Registry for collision detection
        self.known_station_ips: Dict[int, str] = {self.station_id: self.ip_address}

        self.sync_to_registers()

    @property
    def station_no(self) -> int:
        return self.station_id

    @property
    def group_no(self) -> int:
        return self.group_id

    @property
    def cycle_time_ms(self) -> float:
        return self.group_cycle_time_ms

    @property
    def watchdog_timeout_ms(self) -> float:
        return self.disconnection_timeout_ms

    @property
    def current_time_ms(self) -> float:
        return self.elapsed_time_ms

    @current_time_ms.setter
    def current_time_ms(self, val: float) -> None:
        self.elapsed_time_ms = val

    @property
    def transaction_id(self) -> int:
        return self.transaction_sequence_counter

    @transaction_id.setter
    def transaction_id(self, val: int) -> None:
        self.transaction_sequence_counter = val
        self.last_transaction_id = val

    @property
    def crc_error_count(self) -> int:
        return self.frame_crc_error_count

    @crc_error_count.setter
    def crc_error_count(self, val: int) -> None:
        self.frame_crc_error_count = val

    def step_scan_cycle(self, dt_ms: float = 2.5) -> None:
        self.scan_step(dt=dt_ms / 1000.0)

    def reset_latch(self, force: bool = False) -> ExecutionResult:
        res = self.reset_fault(force=force)
        if res.status == AgentStatus.SUCCESS:
            self.permissive = True
            self.sync_to_registers()
        return res

    def recompute_state_word(self) -> int:
        return int(self.state.value)

    def build_response_frame(self) -> CcLinkBasicFrame:
        self.link_devices.commit_outbound()
        return CcLinkBasicFrame(
            frame_type=CcLinkBasicFrameType.CYCLIC_RESPONSE,
            transaction_id=self.last_transaction_id,
            station_id=self.station_id,
            group_id=self.group_id,
            occupied_stations=self.occupied_stations,
            cycle_time_scaled=scale_time_ms_to_int16(self.group_cycle_time_ms),
            timeout_scaled=scale_time_ms_to_int16(self.disconnection_timeout_ms),
            rx_bits=self.link_devices.get_rx_bytes(),
            rwr_registers=self.link_devices.get_rwr_words(),
            ip_address=self.ip_address,
        )

    def process_frame(self, frame_or_bytes: Union[CcLinkBasicFrame, bytes]) -> Any:
        if isinstance(frame_or_bytes, bytes):
            self.handle_raw_frame(frame_or_bytes)
            valid = not self.fault_trip
            return ValidationOutcome(
                is_valid=valid,
                diagnostic_code=self.diagnostic_code,
                details=f"State: {self.state.name}",
                transaction_id=self.last_transaction_id,
                jitter_ms=self.observed_jitter_ms,
                state=self.state,
            )
        else:
            resp = self.handle_cyclic_request(frame_or_bytes)
            valid = not self.fault_trip and resp is not None
            return ValidationOutcome(
                is_valid=valid,
                diagnostic_code=self.diagnostic_code,
                details=f"State: {self.state.name}",
                transaction_id=self.last_transaction_id,
                jitter_ms=self.observed_jitter_ms,
                state=self.state,
            )

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "cclink_ie_field_basic"

    @property
    def priority(self) -> int:
        return 94

    @property
    def is_enabled(self) -> bool:
        return True

    def execute(self, ctx: ScanContext) -> None:
        """Scan cycle logic solve execution during simulation Phase 2."""
        dt_ms = getattr(ctx, "dt_ms", 10.0)
        self.scan_step(dt=dt_ms / 1000.0)

    def reset(self) -> None:
        """Reset internal unit state to initial conditions."""
        self.reset_fault(force=True)

    # ------------------------------------------------------------------------
    # State Machine & Network Lifecycle
    # ------------------------------------------------------------------------

    def start_link_scan(self) -> None:
        """Transition from DISCONNECTED to LINK_SCAN_WAIT state."""
        if self.state == CcLinkBasicSlaveState.DISCONNECTED:
            self.state = CcLinkBasicSlaveState.LINK_SCAN_WAIT
            self.sync_to_registers()

    def detect_station_collision(self, conflicting_ip: str, conflicting_station_id: int) -> None:
        """Surveillance check for station number or duplicate IP collisions."""
        if conflicting_station_id == self.station_id and conflicting_ip != self.ip_address:
            self.duplicate_station_detected = True
            self._trip_fault(
                code=CcLinkBasicDiagnosticCode.CCLINK_ERR_STATION_NUMBER_COLLISION,
                details=f"Station ID {self.station_id} collision detected with foreign host at {conflicting_ip}.",
            )

    def handle_raw_frame(self, raw_data: bytes, sender_ip: str = "192.168.3.1") -> Optional[bytes]:
        """Receive and process a raw binary UDP frame from master.

        Returns serialized binary response frame if applicable, or None.
        """
        try:
            frame = CcLinkBasicFrame.parse(raw_data)
        except CcLinkFrameCrcError as err:
            self.frame_crc_error_count += 1
            self._trip_fault(
                code=CcLinkBasicDiagnosticCode.CCLINK_ERR_FRAME_CRC_CORRUPTED,
                details=str(err),
            )
            return None

        resp_frame = self.handle_cyclic_request(frame, sender_ip=sender_ip)
        return resp_frame.serialize() if resp_frame else None

    def handle_cyclic_request(
        self,
        request_frame: CcLinkBasicFrame,
        sender_ip: str = "192.168.3.1",
    ) -> Optional[CcLinkBasicFrame]:
        """Process incoming master cyclic request frame and generate slave response."""
        # Check for station number collision
        if self.duplicate_station_detected:
            self._trip_fault(
                code=CcLinkBasicDiagnosticCode.CCLINK_ERR_STATION_NUMBER_COLLISION,
                details="Duplicate station ID collision condition active.",
            )
            return None

        # Check if frame is addressed to this station
        if request_frame.station_id != self.station_id:
            # Foreign station frame
            return None

        # Check if master IP collision with station IP
        if sender_ip == self.ip_address:
            self.duplicate_station_detected = True
            self._trip_fault(
                code=CcLinkBasicDiagnosticCode.CCLINK_ERR_STATION_NUMBER_COLLISION,
                details="Station IP address collision with master.",
            )
            return None

        # Handle State Progression
        if self.state in (CcLinkBasicSlaveState.DISCONNECTED, CcLinkBasicSlaveState.LINK_SCAN_WAIT):
            self.state = CcLinkBasicSlaveState.CYCLIC_INITIALIZING
            self.master_ip = sender_ip
            self.last_transaction_id = request_frame.transaction_id
            self.transaction_sequence_counter = request_frame.transaction_id
            self.state = CcLinkBasicSlaveState.CYCLIC_OPERATION
            self.permissive = True
            self.fault_trip = False
            self.diagnostic_code = CcLinkBasicDiagnosticCode.OK

        elif self.state == CcLinkBasicSlaveState.CYCLIC_OPERATION:
            # Transaction ID sequence consistency surveillance
            expected_id = (self.last_transaction_id + 1) & 0xFFFF
            if request_frame.transaction_id != expected_id:
                self._trip_fault(
                    code=CcLinkBasicDiagnosticCode.CCLINK_ERR_TRANSACTION_ID_MISMATCH,
                    details=(
                        f"Transaction ID mismatch: expected {expected_id}, "
                        f"received {request_frame.transaction_id}."
                    ),
                )
                return None

            self.last_transaction_id = request_frame.transaction_id
            self.transaction_sequence_counter = request_frame.transaction_id

        elif self.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT:
            # Intercept and reject frames while faulted
            return None

        # Jitter tracking
        if self.last_rx_time_ms > 0:
            interval_ms = self.elapsed_time_ms - self.last_rx_time_ms
            self.observed_jitter_ms = abs(interval_ms - self.group_cycle_time_ms)
            self.max_jitter_ms = max(self.max_jitter_ms, self.observed_jitter_ms)
        self.last_rx_time_ms = self.elapsed_time_ms

        # Reset cyclic watchdog timer
        self.time_since_last_rx_ms = 0.0

        # Unpack incoming RY bits and RWw words into working buffers
        if request_frame.ry_bits:
            self.link_devices.set_ry_bytes(request_frame.ry_bits)
        if request_frame.rww_registers:
            self.link_devices.set_rww_words(request_frame.rww_registers)
        self.link_devices.commit_inbound()

        # Commit outbound RX and RWr buffers and format response frame
        self.link_devices.commit_outbound()
        rx_payload = self.link_devices.get_rx_bytes()
        rwr_payload = self.link_devices.get_rwr_words()

        resp = CcLinkBasicFrame(
            frame_type=CcLinkBasicFrameType.CYCLIC_RESPONSE,
            transaction_id=request_frame.transaction_id,
            station_id=self.station_id,
            group_id=self.group_id,
            occupied_stations=self.occupied_stations,
            cycle_time_scaled=scale_time_ms_to_int16(self.group_cycle_time_ms),
            timeout_scaled=scale_time_ms_to_int16(self.disconnection_timeout_ms),
            rx_bits=rx_payload,
            rwr_registers=rwr_payload,
            ip_address=self.ip_address,
        )

        self.total_cyclic_frames += 1
        self.sync_to_registers()
        return resp

    # ------------------------------------------------------------------------
    # Discrete Scan Step & Timeout Monitoring
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.01) -> Dict[str, Any]:
        """Execute one complete discrete simulation scan cycle.

        Args:
            dt: Delta time in seconds (or milliseconds if dt >= 1.0).

        Returns:
            Dictionary containing cycle telemetry and status flags.
        """
        dt_ms = dt * 1000.0 if dt < 1.0 else dt
        self.elapsed_time_ms += dt_ms

        if self.state == CcLinkBasicSlaveState.CYCLIC_OPERATION:
            self.time_since_last_rx_ms += dt_ms
            if self.time_since_last_rx_ms > self.disconnection_timeout_ms:
                self._trip_fault(
                    code=CcLinkBasicDiagnosticCode.CCLINK_ERR_CYCLIC_TIMEOUT,
                    details=(
                        f"Disconnection detection timeout exceeded: "
                        f"{self.time_since_last_rx_ms:.1f} ms > {self.disconnection_timeout_ms:.1f} ms."
                    ),
                )

        self.sync_to_registers()
        return {
            "timestamp_ms": self.elapsed_time_ms,
            "state": self.state.name,
            "permissive": self.permissive,
            "fault_trip": self.fault_trip,
            "diagnostic_code": f"0x{int(self.diagnostic_code):04X}",
            "time_since_last_rx_ms": self.time_since_last_rx_ms,
            "total_cyclic_frames": self.total_cyclic_frames,
        }

    # ------------------------------------------------------------------------
    # Safety Interlocks & Fault Management
    # ------------------------------------------------------------------------

    def _trip_fault(self, code: CcLinkBasicDiagnosticCode, details: str = "") -> None:
        """Assert fail-safe trip, latch safe shutdown, and clear permissive."""
        self.diagnostic_code = code
        self.state = CcLinkBasicSlaveState.COMMUNICATION_FAULT
        self.fault_trip = True
        self.permissive = False
        self.link_devices.zero_outputs()
        self.sync_to_registers()

    def trigger_fault(self, code: CcLinkBasicDiagnosticCode) -> None:
        """Explicitly inject a diagnostic fault code."""
        self._trip_fault(code=code, details=f"Injected fault {code.name}")

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Manual / operator reset to clear latched safety trips."""
        if not force and self.time_since_last_rx_ms > self.disconnection_timeout_ms and self.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT:
            if self.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_CYCLIC_TIMEOUT:
                return ExecutionResult.failed(
                    error_code="ERR_FAULT_PERSISTENT",
                    details="Reset rejected: cyclic timeout condition is still active.",
                )

        self.diagnostic_code = CcLinkBasicDiagnosticCode.OK
        self.fault_trip = False
        self.permissive = True
        self.duplicate_station_detected = False
        self.time_since_last_rx_ms = 0.0
        self.state = CcLinkBasicSlaveState.LINK_SCAN_WAIT
        self.sync_to_registers()
        return ExecutionResult.success(details="CC-Link IE Field Basic slave fault reset successfully.")

    # ------------------------------------------------------------------------
    # Horner OCS Register Space Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(self) -> None:
        """Synchronize internal engine state to Horner OCS register space.

        All writes to RegisterTable MUST pass privilege=PrivilegeMode.SYSTEM.
        """
        cycle_time_scaled = scale_time_ms_to_int16(self.group_cycle_time_ms)
        timeout_scaled = scale_time_ms_to_int16(self.disconnection_timeout_ms)
        st_group_word = encode_station_group_word(self.station_id, self.group_id)

        status_flags = CcLinkBasicStatusBits(0)
        if self.permissive:
            status_flags |= CcLinkBasicStatusBits.PERMISSIVE
        if self.fault_trip:
            status_flags |= CcLinkBasicStatusBits.FAULT_TRIP

        if self.state in (
            CcLinkBasicSlaveState.LINK_SCAN_WAIT,
            CcLinkBasicSlaveState.CYCLIC_INITIALIZING,
            CcLinkBasicSlaveState.CYCLIC_OPERATION,
        ):
            status_flags |= CcLinkBasicStatusBits.LINK_ESTABLISHED

        if self.state == CcLinkBasicSlaveState.CYCLIC_OPERATION:
            status_flags |= CcLinkBasicStatusBits.CYCLIC_RUNNING

        if self.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_CYCLIC_TIMEOUT:
            status_flags |= CcLinkBasicStatusBits.TIMEOUT_ALARM
        elif self.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_TRANSACTION_ID_MISMATCH:
            status_flags |= CcLinkBasicStatusBits.TRANSACTION_ID_ALARM
        elif self.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_STATION_NUMBER_COLLISION:
            status_flags |= CcLinkBasicStatusBits.COLLISION_ALARM
        elif self.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_FRAME_CRC_CORRUPTED:
            status_flags |= CcLinkBasicStatusBits.CRC_ERROR_ALARM

        if any(self.link_devices.rx_bytes):
            status_flags |= CcLinkBasicStatusBits.RX_VALID
        if any(self.link_devices.ry_bytes):
            status_flags |= CcLinkBasicStatusBits.RY_VALID
        if any(self.link_devices.rww_words):
            status_flags |= CcLinkBasicStatusBits.RWW_VALID
        if any(self.link_devices.rwr_words):
            status_flags |= CcLinkBasicStatusBits.RWR_VALID

        self.status_bits = status_flags

        # %R1270: CyclicCycleTimeMsScaled (INT16, scaled x10 ms)
        safe_write_word(self.reg_table, "%R1270", cycle_time_scaled)
        # %R1271: OccupiedStationsCount (INT16)
        safe_write_word(self.reg_table, "%R1271", self.occupied_stations)
        # %R1272: TransactionSequenceCounter (UINT16, monotonic sequence 0..65535)
        safe_write_uword(self.reg_table, "%R1272", self.transaction_sequence_counter & 0xFFFF)
        # %R1273: CyclicTimeoutMsScaled (INT16, scaled x10 ms)
        safe_write_word(self.reg_table, "%R1273", timeout_scaled)
        # %R1274: FrameCrcErrorCount (INT16, count of CRC errors)
        safe_write_word(self.reg_table, "%R1274", self.frame_crc_error_count)
        # %R1275: SlaveStationStatusWord (INT16, bitmask of slave status and link state)
        safe_write_word(self.reg_table, "%R1275", int(self.status_bits))
        # %R1276: StationNumberAndGroupWord (UINT16, station ID byte + group ID byte)
        safe_write_uword(self.reg_table, "%R1276", st_group_word)
        # %R1277: DiagnosticStatusCode (0x0000=OK, 0xBF01, 0xBF02, 0xBF03, 0xBF04)
        safe_write_uword(self.reg_table, "%R1277", int(self.diagnostic_code))

        # Discrete interlock coils
        safe_write_bit(self.reg_table, "%M296", self.permissive)
        safe_write_bit(self.reg_table, "%M297", self.fault_trip)


# Aliases for Slave Station Engine
CcLinkBasicSlaveEngine = CcLinkIeFieldBasicSlaveEngine
CcLinkIeBasicSlaveEngine = CcLinkIeFieldBasicSlaveEngine
CcLinkBasicEngine = CcLinkIeFieldBasicSlaveEngine
CCLinkBasicEngine = CcLinkIeFieldBasicSlaveEngine
CCLinkBasicSlaveEngine = CcLinkIeFieldBasicSlaveEngine

LinkDeviceMap = CcLinkBasicLinkDevices
SlaveStationState = CcLinkBasicSlaveState
CCLinkBasicSlaveState = CcLinkBasicSlaveState
CCLinkBasicState = CcLinkBasicSlaveState
CCLinkBasicStatusBits = CcLinkBasicStatusBits
CCLinkBasicCommand = CcLinkBasicFrameType
CCLinkBasicFrameType = CcLinkBasicFrameType
CCLinkBasicFrame = CcLinkBasicFrame
CCLinkBasicDiagnosticCode = CcLinkBasicDiagnosticCode
CCLinkBasicError = CcLinkBasicError
CCLinkBasicCrcCorruptedError = CcLinkFrameCrcError
CCLinkBasicTransactionDesyncError = CcLinkTransactionIdMismatchError
CCLinkBasicDisconnectionTimeoutError = CcLinkCyclicTimeoutError
CCLinkBasicConfigError = CcLinkStationCollisionError
ValidationOutcome = CCLinkBasicValidationOutcome


# ============================================================================
# 9. CC-Link IE Field Basic Master Simulator (for Testing & Closed-Loop Sim)
# ============================================================================

class CcLinkBasicMasterSimulator:
    """Master Station Simulator for testing CC-Link IE Field Basic slave stations."""

    def __init__(
        self,
        master_ip: str = "192.168.3.1",
        group_cycle_time_ms: float = CCLINK_BASIC_NOMINAL_CYCLE_TIME_MS,
        disconnection_timeout_ms: float = CCLINK_BASIC_NOMINAL_TIMEOUT_MS,
    ) -> None:
        self.master_ip: str = master_ip
        self.group_cycle_time_ms: float = group_cycle_time_ms
        self.disconnection_timeout_ms: float = disconnection_timeout_ms
        self.tx_sequence_counter: int = 0

    def build_cyclic_request(
        self,
        station_id: int,
        group_id: int = 1,
        occupied_stations: int = 1,
        ry_bits: bytes = b"",
        rww_words: Sequence[int] = (),
        advance_seq: bool = True,
    ) -> CcLinkBasicFrame:
        """Create a new cyclic transmission request frame."""
        if advance_seq:
            self.tx_sequence_counter = (self.tx_sequence_counter + 1) & 0xFFFF

        return CcLinkBasicFrame(
            frame_type=CcLinkBasicFrameType.CYCLIC_REQUEST,
            transaction_id=self.tx_sequence_counter,
            station_id=station_id,
            group_id=group_id,
            occupied_stations=occupied_stations,
            cycle_time_scaled=scale_time_ms_to_int16(self.group_cycle_time_ms),
            timeout_scaled=scale_time_ms_to_int16(self.disconnection_timeout_ms),
            ry_bits=ry_bits,
            rww_registers=list(rww_words),
            ip_address=self.master_ip,
        )

    def send_cyclic_request(
        self,
        slave: CcLinkIeFieldBasicSlaveEngine,
        ry_bits: bytes = b"",
        rww_words: Sequence[int] = (),
    ) -> Optional[CcLinkBasicFrame]:
        """Dispatch cyclic request frame directly to slave station."""
        req = self.build_cyclic_request(
            station_id=slave.station_id,
            group_id=slave.group_id,
            occupied_stations=slave.occupied_stations,
            ry_bits=ry_bits,
            rww_words=rww_words,
        )
        return slave.handle_cyclic_request(req, sender_ip=self.master_ip)


CCLinkBasicMasterEngine = CcLinkBasicMasterSimulator
CcLinkBasicMasterEngine = CcLinkBasicMasterSimulator


# ============================================================================
# 10. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cclink_basic_verification(
    output_path: Optional[Union[str, Path]] = None,
    evidence_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W166.

    Returns strict 4-state contract JSON response:
    - Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings (%R1270..%R1277, %M296..%M297)
    - Stage 2: CC-Link IE Field Basic Frame Serialization, Parsing, & CRC-16 Checksum
    - Stage 3: Link Devices Cyclic Data Exchange (RX, RY, RWw, RWr) & Double-Buffering
    - Stage 4: Slave Station Diagnostic State Machine Lifecycle
    - Stage 5: Group Cycle Time Tracking & Timing Surveillance (Nominal 10.0 ms, Scaled 100)
    - Stage 6: Disconnection Detection Timeout Monitoring (0xBF01, Trip %M297, Drop %M296)
    - Stage 7: Frame Transaction ID & Sequence Consistency Verification (0xBF02)
    - Stage 8: Duplicate Station Number & IP Collision Detection (0xBF03)
    - Stage 9: Frame CRC Corruption / Truncation Rejection (0xBF04) & Anti-Ladder Security Rejection
    """
    tests_record: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings
    # ------------------------------------------------------------------------
    val_pou1 = STParser.validate_code(CCLINK_BASIC_SYNC_POU)
    ast_pou1 = STParser.parse_pou(CCLINK_BASIC_SYNC_POU)
    val_pou2 = STParser.validate_code(CCLINK_BASIC_SLAVE_SYNC_POU)
    ast_pou2 = STParser.parse_pou(CCLINK_BASIC_SLAVE_SYNC_POU)

    expected_regs = {
        "%R1270", "%R1271", "%R1272", "%R1273",
        "%R1274", "%R1275", "%R1276", "%R1277",
        "%M296", "%M297",
    }
    s1_pass = (
        val_pou1.status == AgentStatus.SUCCESS
        and val_pou2.status == AgentStatus.SUCCESS
        and ast_pou1.name == "CcLinkIeFieldBasicSync"
        and ast_pou2.name == "CcLinkIeBasicSlaveSync"
        and set(ast_pou1.bound_registers) == expected_regs
        and set(ast_pou2.bound_registers) == expected_regs
        and verify_cclink_basic_pure_st() is True
    )
    tests_record.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Register_Binding",
        "passed": s1_pass,
        "details": f"Parsed CcLinkIeFieldBasicSync and alias with 10 registered bindings: {sorted(ast_pou1.bound_registers)}.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Frame Serialization, Parsing, & CRC-16 Checksum
    # ------------------------------------------------------------------------
    sample_frame = CcLinkBasicFrame(
        frame_type=CcLinkBasicFrameType.CYCLIC_REQUEST,
        transaction_id=101,
        station_id=1,
        group_id=1,
        occupied_stations=1,
        cycle_time_scaled=100,
        timeout_scaled=500,
        ry_bits=b"\xAA\x55\x12\x34\x00\x00\x00\x00",
        rww_registers=[100, 200, -300, 400],
    )
    serialized = sample_frame.serialize()
    parsed_frame = CcLinkBasicFrame.parse(serialized)

    s2_pass = (
        len(serialized) >= CCLINK_BASIC_HEADER_SIZE + 2
        and parsed_frame.transaction_id == 101
        and parsed_frame.station_id == 1
        and parsed_frame.group_id == 1
        and parsed_frame.cycle_time_scaled == 100
        and parsed_frame.timeout_scaled == 500
        and parsed_frame.ry_bits[:4] == b"\xAA\x55\x12\x34"
        and parsed_frame.rww_registers[:4] == [100, 200, -300, 400]
        and parsed_frame.crc == calculate_cclink_crc16(serialized[:-2])
    )
    tests_record.append({
        "stage": 2,
        "check": "Frame_Serialization_Parsing_And_CRC16_Checksum",
        "passed": s2_pass,
        "details": f"Serialized {len(serialized)} bytes with CRC 0x{parsed_frame.crc:04X} validated successfully.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Link Devices Cyclic Exchange & Atomic Double-Buffering
    # ------------------------------------------------------------------------
    reg_table = RegisterTable()
    engine = CcLinkIeFieldBasicSlaveEngine(
        station_id=1,
        group_id=1,
        occupied_stations=1,
        register_table=reg_table,
    )
    master = CcLinkBasicMasterSimulator(group_cycle_time_ms=10.0, disconnection_timeout_ms=50.0)

    # Slave configures local inputs (RX bit 5, RWr word 2)
    engine.link_devices.set_rx_bit(5, True)
    engine.link_devices.set_rwr_word(2, 4567)

    # Master sends cyclic request with RY bit 3, RWw word 1
    req_frame = master.build_cyclic_request(station_id=1, advance_seq=True)
    req_frame.ry_bits = b"\x08\x00\x00\x00\x00\x00\x00\x00"  # bit 3
    req_frame.rww_registers = [0, 8910]

    resp_frame = engine.handle_cyclic_request(req_frame, sender_ip=master.master_ip)

    s3_pass = (
        resp_frame is not None
        and engine.link_devices.get_ry_bit(3) is True
        and engine.link_devices.get_rww_word(1) == 8910
        and resp_frame.rx_bits[0] & (1 << 5) != 0
        and len(resp_frame.rwr_registers) >= 3
        and resp_frame.rwr_registers[2] == 4567
    )
    tests_record.append({
        "stage": 3,
        "check": "Link_Devices_Cyclic_Data_Exchange_And_Double_Buffering",
        "passed": s3_pass,
        "details": "RX, RY, RWw, and RWr cyclic image exchange and atomic staging verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Slave Station Diagnostic State Machine Lifecycle
    # ------------------------------------------------------------------------
    master_s4 = CcLinkBasicMasterSimulator(group_cycle_time_ms=10.0, disconnection_timeout_ms=50.0)
    new_engine = CcLinkIeFieldBasicSlaveEngine(station_id=2, group_id=1)
    st_init = new_engine.state
    new_engine.start_link_scan()
    st_scan = new_engine.state

    # Send first cyclic frame
    req_init = master_s4.build_cyclic_request(station_id=2, advance_seq=True)
    new_engine.handle_cyclic_request(req_init)
    st_oper = new_engine.state
    permissive_active = new_engine.permissive
    fault_trip_low = new_engine.fault_trip

    s4_pass = (
        st_init == CcLinkBasicSlaveState.DISCONNECTED
        and st_scan == CcLinkBasicSlaveState.LINK_SCAN_WAIT
        and st_oper == CcLinkBasicSlaveState.CYCLIC_OPERATION
        and permissive_active is True
        and fault_trip_low is False
    )
    tests_record.append({
        "stage": 4,
        "check": "Slave_Station_Diagnostic_State_Machine_Lifecycle",
        "passed": s4_pass,
        "details": f"Progression DISCONNECTED({st_init.value}) -> LINK_SCAN_WAIT({st_scan.value}) -> CYCLIC_OPERATION({st_oper.value}) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Group Cycle Time Tracking & Timing Surveillance
    # ------------------------------------------------------------------------
    reg_r1270 = reg_table.read_word("%R1270")
    engine.scan_step(dt=0.01)  # 10.0 ms nominal step
    master.tx_sequence_counter = engine.last_transaction_id
    # send sequential frames
    for _ in range(5):
        master.send_cyclic_request(engine)
        engine.scan_step(dt=0.01)

    reg_r1272 = reg_table.read_uword("%R1272")
    diag_code_s5 = reg_table.read_uword("%R1277")

    s5_pass = (
        reg_r1270 == 100  # 10.0 ms scaled x10
        and reg_r1272 == master.tx_sequence_counter
        and diag_code_s5 == 0x0000
        and engine.permissive is True
    )
    tests_record.append({
        "stage": 5,
        "check": "Group_Cycle_Time_Tracking_And_Nominal_Timing",
        "passed": s5_pass,
        "details": f"Nominal 10.0 ms cycle (%R1270={reg_r1270}) with monotonic sequence %R1272={reg_r1272} verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Disconnection Detection Timeout Monitoring (0xBF01)
    # ------------------------------------------------------------------------
    # Advance virtual time by 55.0 ms without receiving cyclic frame
    engine.scan_step(dt=0.055)

    diag_code_s6 = reg_table.read_uword("%R1277")
    trip_s6 = reg_table.read_bit("%M297")
    perm_s6 = reg_table.read_bit("%M296")
    status_w_s6 = reg_table.read_word("%R1275")
    timeout_bit = bool(status_w_s6 & CcLinkBasicStatusBits.TIMEOUT_ALARM)

    s6_pass = (
        engine.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT
        and diag_code_s6 == int(CcLinkBasicDiagnosticCode.CCLINK_ERR_CYCLIC_TIMEOUT)
        and trip_s6 is True
        and perm_s6 is False
        and timeout_bit is True
    )
    tests_record.append({
        "stage": 6,
        "check": "Disconnection_Detection_Timeout_Monitoring_0xBF01",
        "passed": s6_pass,
        "details": f"55.0 ms silence triggered 0x{diag_code_s6:04X} (TIMEOUT), %M297=True, %M296=False.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Frame Transaction ID & Sequence Consistency Surveillance (0xBF02)
    # ------------------------------------------------------------------------
    engine.reset_fault(force=True)
    # Establish valid cyclic operation
    master.send_cyclic_request(engine)
    cur_tx = engine.last_transaction_id

    # Master sends duplicate or jumped transaction ID (corrupted sequence)
    corrupted_seq_frame = CcLinkBasicFrame(
        frame_type=CcLinkBasicFrameType.CYCLIC_REQUEST,
        transaction_id=(cur_tx + 99) & 0xFFFF,  # jump instead of cur_tx + 1
        station_id=engine.station_id,
        group_id=engine.group_id,
    )
    engine.handle_cyclic_request(corrupted_seq_frame, sender_ip=master.master_ip)

    diag_code_s7 = reg_table.read_uword("%R1277")
    trip_s7 = reg_table.read_bit("%M297")
    perm_s7 = reg_table.read_bit("%M296")

    s7_pass = (
        engine.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT
        and diag_code_s7 == int(CcLinkBasicDiagnosticCode.CCLINK_ERR_TRANSACTION_ID_MISMATCH)
        and trip_s7 is True
        and perm_s7 is False
    )
    tests_record.append({
        "stage": 7,
        "check": "Transaction_ID_Sequence_Consistency_Surveillance_0xBF02",
        "passed": s7_pass,
        "details": f"Out-of-order transaction ID intercepted with code 0x{diag_code_s7:04X}.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Duplicate Station Number & IP Collision Detection (0xBF03)
    # ------------------------------------------------------------------------
    engine.reset_fault(force=True)
    master.send_cyclic_request(engine)

    # Injected collision from duplicate station
    engine.detect_station_collision(conflicting_ip="192.168.3.99", conflicting_station_id=engine.station_id)

    diag_code_s8 = reg_table.read_uword("%R1277")
    trip_s8 = reg_table.read_bit("%M297")
    perm_s8 = reg_table.read_bit("%M296")
    collision_bit = bool(reg_table.read_word("%R1275") & CcLinkBasicStatusBits.COLLISION_ALARM)

    s8_pass = (
        engine.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT
        and diag_code_s8 == int(CcLinkBasicDiagnosticCode.CCLINK_ERR_STATION_NUMBER_COLLISION)
        and trip_s8 is True
        and perm_s8 is False
        and collision_bit is True
    )
    tests_record.append({
        "stage": 8,
        "check": "Duplicate_Station_Number_And_IP_Collision_Detection_0xBF03",
        "passed": s8_pass,
        "details": f"Station collision intercepted with code 0x{diag_code_s8:04X} and fail-closed trip.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Frame CRC Corruption / Truncation Rejection (0xBF04) & Anti-Ladder
    # ------------------------------------------------------------------------
    engine.reset_fault(force=True)
    master.send_cyclic_request(engine)

    # Send corrupted packet (corrupted CRC bytes)
    good_bytes = sample_frame.serialize()
    bad_bytes = good_bytes[:-2] + b"\xDE\xAD"  # Corrupt CRC
    engine.handle_raw_frame(bad_bytes, sender_ip=master.master_ip)

    crc_errs = reg_table.read_word("%R1274")
    diag_code_s9 = reg_table.read_uword("%R1277")
    trip_s9 = reg_table.read_bit("%M297")

    # Anti-ladder check
    forbidden_samples = [
        "PROGRAM BadLadder\nVAR Flag: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
        "PROGRAM BadLadderNeg\nVAR Flag: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
        "PROGRAM BadLadderRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M100 OTE %M101 END_RUNG\nEND_PROGRAM",
    ]
    ladder_rejected = True
    for sample in forbidden_samples:
        try:
            SecurityGuard.assert_pure_st_content(sample)
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    s9_pass = (
        crc_errs >= 1
        and diag_code_s9 == int(CcLinkBasicDiagnosticCode.CCLINK_ERR_FRAME_CRC_CORRUPTED)
        and trip_s9 is True
        and ladder_rejected is True
    )
    tests_record.append({
        "stage": 9,
        "check": "Frame_CRC_Corruption_Truncation_And_Anti_Ladder_Rejection_0xBF04",
        "passed": s9_pass,
        "details": f"Corrupted packet CRC trapped (0x{diag_code_s9:04X}) and ladder constructs rejected.",
    })

    # Compile Final Verification Summary
    checks_passed = sum(1 for t in tests_record if t["passed"])
    total_checks = len(tests_record)
    overall_status = "success" if checks_passed == total_checks else "failed"

    evidence: Dict[str, Any] = {
        "status": overall_status,
        "error_code": None if overall_status == "success" else "ERR_CCLINK_BASIC_VERIFICATION_FAILED",
        "details": (
            f"CC-Link IE Field Basic Cyclic Transmission & Slave Station Protocol Engine "
            f"verified cleanly ({checks_passed}/{total_checks} checks passed)."
        ),
        "data": {
            "work_package": "W166",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "CC-Link IE Field Basic Cyclic Protocol Engine",
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "tests": tests_record,
            "register_map": {
                "%R1270": reg_table.read_word("%R1270"),
                "%R1271": reg_table.read_word("%R1271"),
                "%R1272": reg_table.read_uword("%R1272"),
                "%R1273": reg_table.read_word("%R1273"),
                "%R1274": reg_table.read_word("%R1274"),
                "%R1275": f"0x{reg_table.read_uword('%R1275'):04X}",
                "%R1276": f"0x{reg_table.read_uword('%R1276'):04X}",
                "%R1277": f"0x{reg_table.read_uword('%R1277'):04X}",
                "%M296": reg_table.read_bit("%M296"),
                "%M297": reg_table.read_bit("%M297"),
            },
            "metrics": {
                "nominal_cycle_time_ms": CCLINK_BASIC_NOMINAL_CYCLE_TIME_MS,
                "disconnection_timeout_ms": CCLINK_BASIC_NOMINAL_TIMEOUT_MS,
                "total_cyclic_frames": engine.total_cyclic_frames,
                "crc_errors_detected": crc_errs,
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    target_path = output_path or evidence_path
    if target_path:
        out_p = Path(target_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence
