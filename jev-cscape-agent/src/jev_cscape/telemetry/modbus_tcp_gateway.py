"""Industrial Modbus TCP Multi-Client Gateway & Transaction Multiplexer Engine.

Work Package: W175 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- Modbus Messaging on TCP/IP Implementation Guide v1.0b (Modbus Organization)
- Modbus Application Protocol Specification v1.1b3 (Modbus-IDA)
- IEC 61131-3 Programmable Controllers - Part 3: Programming Languages (Structured Text)

Architecture:
1. Strict Pure IEC 61131-3 Structured Text POUs:
   - 'ModbusTcpGatewaySync' (and alias 'TcpMultiClientMultiplexerSync').
   - Bound to Horner OCS registers (%R1360..%R1367, %M317..%M318).
   - Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN using SecurityGuard and STParser.

2. Complete Modbus TCP Multi-Client Gateway Architecture:
   - Modbus Application Protocol (MBAP) header:
     * Transaction Identifier (2 bytes, big-endian)
     * Protocol Identifier (0x0000, 2 bytes, big-endian)
     * Length (2 bytes, big-endian)
     * Unit Identifier (1 byte)
   - Multi-client connection pooling: Support up to 16 concurrent client connections on standard port 502.
   - Transaction Multiplexing & FIFO Queue: Request queue management (depth up to 32 entries),
     monotonic transaction ID tracking, asynchronous response dispatching to matching client socket.
   - Gateway Unit ID routing: Virtual routing across local Horner OCS memory image and downstream slave device IDs.
   - Round-trip latency tracking (scaled x10 ms, nominal 1.5 ms -> 15).
   - Socket timeout surveillance (> 50.0 ms) and connection lifecycle management
     (LISTENING, CONNECTED, DISCONNECTING, RECONNECTING).
   - Gateway state machine:
     GATEWAY_IDLE, LISTENING, MULTIPLEXING_REQUEST, DISPATCHING_RESPONSE, RECONNECT_WAIT, GATEWAY_FAULT.
   - Implements ILogicUnit interface with scan_step(dt).

3. Process Safety Interlocks & Diagnostics:
   - 0x0000: OK (Normal healthy gateway operation)
   - 0xC801: GATEWAY_ERR_CLIENT_OVERFLOW (Active clients exceed maximum pool capacity of 16)
             -> asserts %M318 (ModbusTcpGatewayFaultTrip), clears %M317 (ModbusTcpGatewayPermissive)
   - 0xC802: GATEWAY_ERR_TRANSACTION_TIMEOUT (Transaction round-trip latency exceeds 50.0 ms)
             -> asserts %M318, clears %M317, increments %R1364
   - 0xC803: GATEWAY_ERR_MALFORMED_MBAP (Invalid protocol ID != 0x0000, truncated MBAP, or invalid length)
             -> asserts %M318, clears %M317
   - 0xC804: GATEWAY_ERR_UNIT_ID_UNREACHABLE (Destination Unit ID not mapped or unreachable)
             -> asserts %M318, clears %M317

4. Horner OCS Memory Space Integration:
   - %R1360: ActiveTcpClientsCount (INT16, 0..16)
   - %R1361: TransactionIdTrackingWord (UINT16 monotonic 0..65535)
   - %R1362: GatewayRoundTripLatencyMsScaled (INT16, scaled x10 ms, e.g. 15 = 1.5 ms)
   - %R1363: MultiplexerQueueDepth (INT16, 0..32)
   - %R1364: SocketTimeoutErrorCounter (INT16 count of socket timeouts)
   - %R1365: GatewayStateWord (INT16 bitmask of gateway status, socket listener, queue status)
   - %R1366: ClientIpAndUnitIdWord (UINT16, client IP lower octet + Unit ID byte)
   - %R1367: DiagnosticStatusCode (0x0000=OK, 0xC801, 0xC802, 0xC803, 0xC804)
   - %M317: ModbusTcpGatewayPermissive (BOOL)
   - %M318: ModbusTcpGatewayFaultTrip (BOOL)
   - All RegisterTable writes pass privilege=PrivilegeMode.SYSTEM.

5. Deterministic 9-Stage Verification Suite:
   - Function run_modbus_tcp_gateway_verification(output_path) returning strict 4-state contract JSON.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
import json
from pathlib import Path
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (Modbus Messaging on TCP/IP v1.0b)
# ============================================================================

MODBUS_TCP_DEFAULT_PORT: int = 502
MAX_CLIENT_CONNECTIONS: int = 16
MAX_QUEUE_DEPTH: int = 32

SOCKET_TIMEOUT_THRESHOLD_MS: float = 50.0
NOMINAL_ROUND_TRIP_LATENCY_MS: float = 1.5
NOMINAL_LATENCY_SCALED: int = 15  # 1.5 ms * 10

MBAP_HEADER_LENGTH: int = 7
MODBUS_PROTOCOL_ID: int = 0x0000

# Standard Modbus Function Codes
FC_READ_COILS: int = 0x01
FC_READ_DISCRETE_INPUTS: int = 0x02
FC_READ_HOLDING_REGISTERS: int = 0x03
FC_READ_INPUT_REGISTERS: int = 0x04
FC_WRITE_SINGLE_COIL: int = 0x05
FC_WRITE_SINGLE_REGISTER: int = 0x06
FC_WRITE_MULTIPLE_COILS: int = 0x0F
FC_WRITE_MULTIPLE_REGISTERS: int = 0x10

# Standard Modbus Exception Codes
EX_ILLEGAL_FUNCTION: int = 0x01
EX_ILLEGAL_DATA_ADDRESS: int = 0x02
EX_ILLEGAL_DATA_VALUE: int = 0x03
EX_SLAVE_DEVICE_FAILURE: int = 0x04
EX_GATEWAY_PATH_UNAVAILABLE: int = 0x0A
EX_GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND: int = 0x0B


# ============================================================================
# 2. Enums, Status Flags, & Diagnostic Codes
# ============================================================================

class ModbusTcpGatewayDiagnosticCode(IntEnum):
    """Horner OCS %R1367 Diagnostic Event Codes for Modbus TCP Gateway (W175)."""
    OK                            = 0x0000  # Normal healthy gateway operation
    GATEWAY_ERR_CLIENT_OVERFLOW   = 0xC801  # Active clients exceed maximum pool capacity of 16
    GATEWAY_ERR_TRANSACTION_TIMEOUT= 0xC802 # Transaction round-trip latency exceeds 50.0 ms
    GATEWAY_ERR_MALFORMED_MBAP    = 0xC803  # Invalid protocol ID != 0, truncated MBAP, or invalid length
    GATEWAY_ERR_UNIT_ID_UNREACHABLE=0xC804  # Destination Unit ID not mapped or unreachable

    # Convenience aliases
    CLIENT_OVERFLOW               = 0xC801
    TRANSACTION_TIMEOUT           = 0xC802
    MALFORMED_MBAP                = 0xC803
    UNIT_ID_UNREACHABLE           = 0xC804
    ERR_CLIENT_OVERFLOW           = 0xC801
    ERR_TRANSACTION_TIMEOUT       = 0xC802
    ERR_MALFORMED_MBAP            = 0xC803
    ERR_UNIT_ID_UNREACHABLE       = 0xC804


DiagnosticStatusCode = ModbusTcpGatewayDiagnosticCode


class ClientConnectionState(IntEnum):
    """Lifecycle state of a client TCP socket connection."""
    LISTENING     = 0  # Socket listener initialized
    CONNECTED     = 1  # Client socket connected and actively communicating
    DISCONNECTING = 2  # Client tear-down in progress
    RECONNECTING  = 3  # Client reconnecting or waiting for handshake
    CLOSED        = 4  # Socket closed/released


class GatewayState(IntEnum):
    """Modbus TCP Multi-Client Gateway Operating State Machine."""
    GATEWAY_IDLE         = 0  # Listening on port 502, no active transactions pending, queue empty
    LISTENING            = 1  # Socket listener active, accepting incoming client connections
    MULTIPLEXING_REQUEST = 2  # Dequeuing and routing requests from FIFO queue across client sessions
    DISPATCHING_RESPONSE = 3  # Routing response PDU and MBAP header back to matching client socket
    RECONNECT_WAIT       = 4  # Handling client disconnect/reconnect backoff or socket retry settling
    GATEWAY_FAULT        = 5  # Latched diagnostic fault condition (overflow, timeout, malformed, unreachable)


class GatewayStateBits(IntFlag):
    """Horner OCS %R1365 GatewayStateWord Bitmask Definitions."""
    LISTENER_ACTIVE            = 1 << 0   # Bit 0 (0x0001): Port 502 socket listener active
    CLIENT_CONNECTED           = 1 << 1   # Bit 1 (0x0002): At least 1 client connected
    QUEUE_NOT_EMPTY            = 1 << 2   # Bit 2 (0x0004): Request queue depth > 0
    STATE_BIT_0                = 1 << 3   # Bit 3 (0x0008): State enum bit 0
    STATE_BIT_1                = 1 << 4   # Bit 4 (0x0010): State enum bit 1
    STATE_BIT_2                = 1 << 5   # Bit 5 (0x0020): State enum bit 2
    MULTIPLEXER_BUSY           = 1 << 6   # Bit 6 (0x0040): Transaction multiplexer actively dispatching
    RECONNECT_ACTIVE           = 1 << 7   # Bit 7 (0x0080): Reconnection backoff timer active
    RESPONSE_READY             = 1 << 8   # Bit 8 (0x0100): Response ready in dispatch buffer
    PERMISSIVE                 = 1 << 9   # Bit 9 (0x0200): ModbusTcpGatewayPermissive (%M317)
    FAULT_TRIP                 = 1 << 10  # Bit 10 (0x0400): ModbusTcpGatewayFaultTrip (%M318)
    CLIENT_OVERFLOW_FAULT      = 1 << 11  # Bit 11 (0x0800): 0xC801 active
    TRANSACTION_TIMEOUT_FAULT  = 1 << 12  # Bit 12 (0x1000): 0xC802 active
    MALFORMED_MBAP_FAULT       = 1 << 13  # Bit 13 (0x2000): 0xC803 active
    UNIT_ID_UNREACHABLE_FAULT  = 1 << 14  # Bit 14 (0x4000): 0xC804 active
    ROUTING_LOCAL              = 1 << 15  # Bit 15 (0x8000): 1 if last transaction local OCS memory, 0 if downstream


class TransactionStatus(str, Enum):
    """Status of an in-flight multiplexed transaction."""
    QUEUED     = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED  = "COMPLETED"
    TIMED_OUT  = "TIMED_OUT"
    FAILED     = "FAILED"


# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class ModbusTcpGatewayError(Exception):
    """Base exception for Modbus TCP Gateway faults."""
    pass


class ModbusTcpClientOverflowError(ModbusTcpGatewayError):
    """Raised when active clients exceed pool capacity of 16 (0xC801)."""
    pass


class ModbusTcpTransactionTimeoutError(ModbusTcpGatewayError):
    """Raised when transaction round-trip latency exceeds 50.0 ms (0xC802)."""
    pass


class ModbusTcpMalformedMbapError(ModbusTcpGatewayError):
    """Raised when MBAP header is corrupted, truncated, or invalid (0xC803)."""
    pass


class ModbusTcpUnitIdUnreachableError(ModbusTcpGatewayError):
    """Raised when destination Unit ID is not mapped or unreachable (0xC804)."""
    pass


# Convenient aliases
ClientOverflowError = ModbusTcpClientOverflowError
TransactionTimeoutError = ModbusTcpTransactionTimeoutError
MalformedMbapError = ModbusTcpMalformedMbapError
UnitIdUnreachableError = ModbusTcpUnitIdUnreachableError


# ============================================================================
# 4. Helper & Encoding Functions
# ============================================================================

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


def encode_client_ip_unit_id_word(client_ip: Union[str, int], unit_id: int) -> int:
    """Encode client IP lower octet (high byte) and Unit ID (low byte) into UINT16 (%R1366).

    Args:
        client_ip: IPv4 string (e.g. '192.168.1.105') or integer octet (105).
        unit_id: Modbus Unit ID byte (0..255).

    Returns:
        16-bit unsigned integer word.
    """
    if isinstance(client_ip, str):
        parts = client_ip.strip().split(".")
        try:
            last_octet = int(parts[-1]) if parts else 0
        except ValueError:
            last_octet = 0
    else:
        last_octet = int(client_ip)
    return (((last_octet & 0xFF) << 8) | (int(unit_id) & 0xFF)) & 0xFFFF


def decode_client_ip_unit_id_word(word: int) -> Tuple[int, int]:
    """Decode UINT16 (%R1366) into client IP lower octet and Unit ID."""
    last_octet = (int(word) >> 8) & 0xFF
    unit_id = int(word) & 0xFF
    return last_octet, unit_id


# ============================================================================
# 5. MBAP Header & ADU Data Containers
# ============================================================================

@dataclass
class MbapHeader:
    """Modbus Application Protocol (MBAP) Header (7 bytes).

    Fields:
    - transaction_id: 2 bytes (0x0000..0xFFFF, monotonic or client-assigned)
    - protocol_id: 2 bytes (0x0000 for standard MODBUS TCP)
    - length: 2 bytes (count of following bytes: 1 byte Unit ID + len(PDU))
    - unit_id: 1 byte (0x00..0xFF)
    """
    transaction_id: int = 1
    protocol_id: int = MODBUS_PROTOCOL_ID
    length: int = 2
    unit_id: int = 1

    def serialize(self) -> bytes:
        """Serialize MBAP header to 7 network bytes (big-endian)."""
        return struct.pack(
            ">HHHB",
            self.transaction_id & 0xFFFF,
            self.protocol_id & 0xFFFF,
            self.length & 0xFFFF,
            self.unit_id & 0xFF,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "MbapHeader":
        """Deserialize 7 network bytes into MbapHeader.

        Raises:
            ModbusTcpMalformedMbapError: If truncated (< 7 bytes).
        """
        if len(data) < MBAP_HEADER_LENGTH:
            raise ModbusTcpMalformedMbapError(
                f"MBAP header truncated: received {len(data)} bytes (< {MBAP_HEADER_LENGTH} required)."
            )
        transaction_id, protocol_id, length, unit_id = struct.unpack_from(">HHHB", data, 0)
        return cls(
            transaction_id=transaction_id,
            protocol_id=protocol_id,
            length=length,
            unit_id=unit_id,
        )


@dataclass
class ModbusTcpAdu:
    """Modbus TCP Application Data Unit (ADU = MBAP Header + PDU)."""
    header: MbapHeader
    function_code: int = FC_READ_HOLDING_REGISTERS
    pdu_data: bytes = b""

    @property
    def transaction_id(self) -> int:
        return self.header.transaction_id

    @property
    def protocol_id(self) -> int:
        return self.header.protocol_id

    @property
    def unit_id(self) -> int:
        return self.header.unit_id

    @property
    def pdu(self) -> bytes:
        return bytes([self.function_code & 0xFF]) + self.pdu_data

    @property
    def total_length(self) -> int:
        return MBAP_HEADER_LENGTH - 1 + self.header.length

    def serialize(self) -> bytes:
        """Serialize entire ADU to bytes, updating MBAP length field automatically."""
        # Length in MBAP includes 1 byte Unit Identifier + PDU bytes
        self.header.length = 1 + len(self.pdu)
        return self.header.serialize() + self.pdu

    @classmethod
    def deserialize(cls, data: bytes) -> "ModbusTcpAdu":
        """Deserialize raw TCP byte stream into ModbusTcpAdu.

        Validates:
        1. Length >= 7 (MBAP header present)
        2. Protocol ID == 0x0000
        3. Length field >= 2 (at least unit_id + 1 byte function code)
        4. Buffer contains full frame (len(data) >= 6 + length)
        """
        if len(data) < MBAP_HEADER_LENGTH:
            raise ModbusTcpMalformedMbapError(
                f"Truncated Modbus TCP ADU: length {len(data)} < minimum 7 bytes."
            )

        header = MbapHeader.deserialize(data[:MBAP_HEADER_LENGTH])

        if header.protocol_id != MODBUS_PROTOCOL_ID:
            raise ModbusTcpMalformedMbapError(
                f"Invalid Protocol Identifier 0x{header.protocol_id:04X} (expected 0x{MODBUS_PROTOCOL_ID:04X})."
            )

        if header.length < 2:
            raise ModbusTcpMalformedMbapError(
                f"Invalid MBAP Length field {header.length} (< minimum 2 bytes for Unit ID + FC)."
            )

        # The length field specifies the count of following bytes starting after the length field (offset 6)
        expected_total_len = 6 + header.length
        if len(data) < expected_total_len:
            raise ModbusTcpMalformedMbapError(
                f"Truncated ADU payload: expected {expected_total_len} bytes, got {len(data)}."
            )

        pdu = data[MBAP_HEADER_LENGTH:expected_total_len]
        if len(pdu) < 1:
            raise ModbusTcpMalformedMbapError("PDU missing Function Code byte.")

        function_code = pdu[0]
        pdu_data = pdu[1:]
        return cls(header=header, function_code=function_code, pdu_data=pdu_data)

    @classmethod
    def create_read_holding_registers(
        cls,
        transaction_id: int = 1,
        unit_id: int = 1,
        start_address: int = 1360,
        count: int = 8,
    ) -> "ModbusTcpAdu":
        """Create Read Holding Registers (FC 0x03) request ADU."""
        pdu_data = struct.pack(">HH", start_address & 0xFFFF, count & 0xFFFF)
        header = MbapHeader(transaction_id=transaction_id, protocol_id=0, length=1 + 1 + len(pdu_data), unit_id=unit_id)
        return cls(header=header, function_code=FC_READ_HOLDING_REGISTERS, pdu_data=pdu_data)

    @classmethod
    def create_read_coils(
        cls,
        transaction_id: int = 1,
        unit_id: int = 1,
        start_address: int = 317,
        count: int = 2,
    ) -> "ModbusTcpAdu":
        """Create Read Coils (FC 0x01) request ADU."""
        pdu_data = struct.pack(">HH", start_address & 0xFFFF, count & 0xFFFF)
        header = MbapHeader(transaction_id=transaction_id, protocol_id=0, length=1 + 1 + len(pdu_data), unit_id=unit_id)
        return cls(header=header, function_code=FC_READ_COILS, pdu_data=pdu_data)

    @classmethod
    def create_read_discrete_inputs(
        cls,
        transaction_id: int = 1,
        unit_id: int = 1,
        start_address: int = 1,
        count: int = 8,
    ) -> "ModbusTcpAdu":
        """Create Read Discrete Inputs (FC 0x02) request ADU."""
        pdu_data = struct.pack(">HH", start_address & 0xFFFF, count & 0xFFFF)
        header = MbapHeader(transaction_id=transaction_id, protocol_id=0, length=1 + 1 + len(pdu_data), unit_id=unit_id)
        return cls(header=header, function_code=FC_READ_DISCRETE_INPUTS, pdu_data=pdu_data)

    @classmethod
    def create_read_input_registers(
        cls,
        transaction_id: int = 1,
        unit_id: int = 1,
        start_address: int = 1,
        count: int = 4,
    ) -> "ModbusTcpAdu":
        """Create Read Input Registers (FC 0x04) request ADU."""
        pdu_data = struct.pack(">HH", start_address & 0xFFFF, count & 0xFFFF)
        header = MbapHeader(transaction_id=transaction_id, protocol_id=0, length=1 + 1 + len(pdu_data), unit_id=unit_id)
        return cls(header=header, function_code=FC_READ_INPUT_REGISTERS, pdu_data=pdu_data)

    @classmethod
    def create_write_single_coil(
        cls,
        transaction_id: int = 1,
        unit_id: int = 1,
        address: int = 317,
        value: bool = True,
    ) -> "ModbusTcpAdu":
        """Create Write Single Coil (FC 0x05) request ADU."""
        val_code = 0xFF00 if value else 0x0000
        pdu_data = struct.pack(">HH", address & 0xFFFF, val_code)
        header = MbapHeader(transaction_id=transaction_id, protocol_id=0, length=1 + 1 + len(pdu_data), unit_id=unit_id)
        return cls(header=header, function_code=FC_WRITE_SINGLE_COIL, pdu_data=pdu_data)

    @classmethod
    def create_write_single_register(
        cls,
        transaction_id: int = 1,
        unit_id: int = 1,
        address: int = 1360,
        value: int = 42,
    ) -> "ModbusTcpAdu":
        """Create Write Single Register (FC 0x06) request ADU."""
        pdu_data = struct.pack(">HH", address & 0xFFFF, value & 0xFFFF)
        header = MbapHeader(transaction_id=transaction_id, protocol_id=0, length=1 + 1 + len(pdu_data), unit_id=unit_id)
        return cls(header=header, function_code=FC_WRITE_SINGLE_REGISTER, pdu_data=pdu_data)

    @classmethod
    def create_write_multiple_registers(
        cls,
        transaction_id: int = 1,
        unit_id: int = 1,
        start_address: int = 100,
        values: Sequence[int] = (),
    ) -> "ModbusTcpAdu":
        """Create Write Multiple Registers (FC 0x10) request ADU."""
        count = len(values)
        byte_count = count * 2
        val_bytes = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
        pdu_data = struct.pack(">HHB", start_address & 0xFFFF, count & 0xFFFF, byte_count) + val_bytes
        header = MbapHeader(transaction_id=transaction_id, protocol_id=0, length=1 + 1 + len(pdu_data), unit_id=unit_id)
        return cls(header=header, function_code=FC_WRITE_MULTIPLE_REGISTERS, pdu_data=pdu_data)

    @classmethod
    def create_exception_response(
        cls,
        transaction_id: int,
        unit_id: int,
        function_code: int,
        exception_code: int,
    ) -> "ModbusTcpAdu":
        """Create Modbus Exception Response ADU (FC | 0x80)."""
        fc = (function_code | 0x80) & 0xFF
        pdu_data = bytes([exception_code & 0xFF])
        header = MbapHeader(
            transaction_id=transaction_id,
            protocol_id=0,
            length=1 + 1 + len(pdu_data),
            unit_id=unit_id,
        )
        return cls(header=header, function_code=fc, pdu_data=pdu_data)


# ============================================================================
# 6. Connection, Routing, & Transaction Models
# ============================================================================

@dataclass
class ModbusTcpTransaction:
    """Represents an outstanding or completed transaction in the multiplexer queue."""
    transaction_id: int
    client_id: int
    request_adu: ModbusTcpAdu
    enqueued_at_ms: float
    client_ip: str = "127.0.0.1"
    unit_id: int = 1
    response_adu: Optional[ModbusTcpAdu] = None
    round_trip_latency_ms: float = 0.0
    status: TransactionStatus = TransactionStatus.QUEUED
    error_code: Optional[int] = None


@dataclass
class ClientConnection:
    """Represents a connected client session within the connection pool."""
    client_id: int
    ip_address: str = "127.0.0.1"
    port: int = MODBUS_TCP_DEFAULT_PORT
    state: ClientConnectionState = ClientConnectionState.CONNECTED
    connected_at_ms: float = 0.0
    last_activity_ms: float = 0.0
    active_transactions: Dict[int, ModbusTcpTransaction] = field(default_factory=dict)
    dispatched_responses: List[ModbusTcpAdu] = field(default_factory=list)
    total_requests: int = 0
    total_responses: int = 0
    socket_timeouts: int = 0


@dataclass
class DownstreamRoute:
    """Represents a virtual downstream slave device accessible via the gateway."""
    unit_id: int
    name: str
    endpoint: str = "192.168.1.200:502"
    simulated_latency_ms: float = NOMINAL_ROUND_TRIP_LATENCY_MS
    is_reachable: bool = True
    holding_registers: Dict[int, int] = field(default_factory=dict)
    coils: Dict[int, bool] = field(default_factory=dict)
    discrete_inputs: Dict[int, bool] = field(default_factory=dict)
    input_registers: Dict[int, int] = field(default_factory=dict)


# ============================================================================
# 7. Pure IEC 61131-3 Structured Text (ST) POUs
# ============================================================================

MODBUS_TCP_GATEWAY_SYNC_POU: str = """PROGRAM ModbusTcpGatewaySync
VAR
    (* Horner OCS Mapped Registers (W175 - Modbus TCP Gateway & Transaction Multiplexer Engine) *)
    ActiveTcpClientsCount          AT %R1360 : INT;    (* Active TCP client connections (0..16) *)
    TransactionIdTrackingWord      AT %R1361 : UINT;   (* Rolling Monotonic MBAP Transaction ID (0..65535) *)
    GatewayRoundTripLatencyMsScaled AT %R1362 : INT;   (* Round-trip latency scaled x10 ms (e.g. 15 = 1.5 ms) *)
    MultiplexerQueueDepth          AT %R1363 : INT;    (* Outstanding transaction queue depth (0..32) *)
    SocketTimeoutErrorCounter      AT %R1364 : INT;    (* Accumulated socket timeout occurrences *)
    GatewayStateWord               AT %R1365 : INT;    (* Gateway state bitmask and socket status *)
    ClientIpAndUnitIdWord          AT %R1366 : UINT;   (* Client IP lower octet (high byte) and Unit ID (low byte) *)
    DiagnosticStatusCode           AT %R1367 : UINT;   (* Diagnostic event code (0x0000, 0xC801..0xC804) *)

    (* Discrete Safety Interlock Coils *)
    ModbusTcpGatewayPermissive     AT %M317  : BOOL;   (* TRUE when Modbus TCP Gateway operational and healthy *)
    ModbusTcpGatewayFaultTrip      AT %M318  : BOOL;   (* TRUE on client overflow, timeout, malformed MBAP, or unreachable unit *)
END_VAR
VAR
    GatewayHealthy                 : BOOL;
END_VAR

IF ModbusTcpGatewayFaultTrip OR (DiagnosticStatusCode <> 0) THEN
    ModbusTcpGatewayPermissive := FALSE;
    ModbusTcpGatewayFaultTrip := TRUE;
    GatewayHealthy := FALSE;
ELSIF ModbusTcpGatewayPermissive THEN
    TransactionIdTrackingWord := TransactionIdTrackingWord + 1;
    DiagnosticStatusCode := 0;
    GatewayHealthy := TRUE;
ELSE
    GatewayHealthy := FALSE;
END_IF;

IF ActiveTcpClientsCount > 16 THEN
    DiagnosticStatusCode := 51201; (* 0xC801: GATEWAY_ERR_CLIENT_OVERFLOW *)
    ModbusTcpGatewayPermissive := FALSE;
    ModbusTcpGatewayFaultTrip := TRUE;
ELSIF GatewayRoundTripLatencyMsScaled > 500 THEN
    DiagnosticStatusCode := 51202; (* 0xC802: GATEWAY_ERR_TRANSACTION_TIMEOUT *)
    ModbusTcpGatewayPermissive := FALSE;
    ModbusTcpGatewayFaultTrip := TRUE;
ELSIF SocketTimeoutErrorCounter > 0 THEN
    DiagnosticStatusCode := 51202; (* 0xC802: GATEWAY_ERR_TRANSACTION_TIMEOUT *)
    ModbusTcpGatewayPermissive := FALSE;
    ModbusTcpGatewayFaultTrip := TRUE;
END_IF;
END_PROGRAM
"""

TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU: str = MODBUS_TCP_GATEWAY_SYNC_POU.replace(
    "PROGRAM ModbusTcpGatewaySync", "PROGRAM TcpMultiClientMultiplexerSync"
)

# POU Aliases
PURE_ST_POU: str = MODBUS_TCP_GATEWAY_SYNC_POU
MODBUS_TCP_GATEWAY_POU: str = MODBUS_TCP_GATEWAY_SYNC_POU
TCP_MULTIPLEXER_SYNC_POU: str = TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU


def verify_modbus_tcp_gateway_pure_st() -> bool:
    """Validate Modbus TCP Gateway POUs for strict IEC 61131-3 syntax and anti-ladder safety.

    Returns:
        True if all checks pass deterministically.
    """
    SecurityGuard.assert_pure_st_content(MODBUS_TCP_GATEWAY_SYNC_POU)
    SecurityGuard.assert_pure_st_content(TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU)

    res1 = STParser.validate_code(MODBUS_TCP_GATEWAY_SYNC_POU)
    if res1.status != AgentStatus.SUCCESS:
        return False

    res2 = STParser.validate_code(TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU)
    if res2.status != AgentStatus.SUCCESS:
        return False

    ast1 = STParser.parse_pou(MODBUS_TCP_GATEWAY_SYNC_POU)
    ast2 = STParser.parse_pou(TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU)

    expected_regs = {
        "%R1360", "%R1361", "%R1362", "%R1363",
        "%R1364", "%R1365", "%R1366", "%R1367",
        "%M317", "%M318",
    }
    return set(ast1.bound_registers) == expected_regs and set(ast2.bound_registers) == expected_regs


# ============================================================================
# 8. Modbus TCP Gateway Engine (ILogicUnit)
# ============================================================================

class ModbusTcpGatewayEngine(ILogicUnit):
    """Industrial Modbus TCP Multi-Client Gateway & Transaction Multiplexer Engine.

    Work Package: W175 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
    Classification: PRODUCTION_READY

    Implements:
    - Multi-client connection pooling (up to 16 concurrent client sockets on port 502).
    - Transaction multiplexing & FIFO request queue (depth up to 32 entries).
    - Monotonic transaction ID tracking and asynchronous response dispatching.
    - Virtual routing across local Horner OCS memory (%R, %M, %I, %AI) and downstream devices.
    - Round-trip latency tracking (scaled x10 ms) and socket timeout surveillance (> 50.0 ms).
    - Horner OCS register space synchronization (%R1360..%R1367, %M317..%M318).
    """

    def __init__(
        self,
        max_clients: int = MAX_CLIENT_CONNECTIONS,
        port: int = MODBUS_TCP_DEFAULT_PORT,
        max_queue_depth: int = MAX_QUEUE_DEPTH,
        socket_timeout_ms: float = SOCKET_TIMEOUT_THRESHOLD_MS,
        nominal_latency_ms: float = NOMINAL_ROUND_TRIP_LATENCY_MS,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.max_clients: int = max(1, min(16, max_clients))
        self.port: int = port
        self.max_queue_depth: int = max_queue_depth
        self.socket_timeout_ms: float = socket_timeout_ms
        self.nominal_latency_ms: float = nominal_latency_ms

        self.register_table: RegisterTable = register_table if register_table is not None else RegisterTable()

        # Gateway state machine
        self.state: GatewayState = GatewayState.LISTENING
        self.permissive: bool = True
        self.fault_trip: bool = False
        self.diagnostic_code: ModbusTcpGatewayDiagnosticCode = ModbusTcpGatewayDiagnosticCode.OK

        # Connection pooling (1..16)
        self.clients: Dict[int, ClientConnection] = {}
        self._next_client_id: int = 1

        # Transaction multiplexing & FIFO Queue
        self.request_queue: deque[ModbusTcpTransaction] = deque()
        self.completed_transactions: List[ModbusTcpTransaction] = []
        self.transaction_id_counter: int = 0
        self.socket_timeout_error_counter: int = 0
        self.last_round_trip_latency_ms: float = nominal_latency_ms

        # Unit ID Virtual Routing Table
        # By standard, Unit ID 0, 1, and 255 typically target local controller
        self.local_unit_ids: Set[int] = {0, 1, 255}
        self.downstream_routes: Dict[int, DownstreamRoute] = {}
        self.is_last_routing_local: bool = True

        # Telemetry metadata
        self.current_client_ip: str = "127.0.0.1"
        self.current_unit_id: int = 1
        self.elapsed_time_ms: float = 0.0

        # Initialize default downstream routes for industrial simulation
        self._initialize_default_downstream_routes()

        self.sync_to_registers()

    def _initialize_default_downstream_routes(self) -> None:
        """Populate initial downstream device routes for simulation."""
        self.add_downstream_route(
            unit_id=2,
            name="FlowTransmitter_FT101",
            endpoint="192.168.1.102:502",
            simulated_latency_ms=1.5,
            is_reachable=True,
            holding_registers={100: 1250, 101: 3400, 200: 8888},
        )
        self.add_downstream_route(
            unit_id=3,
            name="PressureTransmitter_PT202",
            endpoint="192.168.1.103:502",
            simulated_latency_ms=1.8,
            is_reachable=True,
            holding_registers={100: 450, 101: 520},
        )
        self.add_downstream_route(
            unit_id=4,
            name="TemperatureChamber_TT303",
            endpoint="192.168.1.104:502",
            simulated_latency_ms=2.1,
            is_reachable=True,
            holding_registers={100: 752, 101: 755},
        )
        self.add_downstream_route(
            unit_id=5,
            name="OfflineSubNode_X999",
            endpoint="192.168.1.105:502",
            simulated_latency_ms=1.5,
            is_reachable=False,  # Unreachable route to test 0xC804
        )

    # ------------------------------------------------------------------------
    # ILogicUnit Properties & Lifecycle
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "modbus_tcp_gateway"

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
    # Multi-Client Connection Pooling Management
    # ------------------------------------------------------------------------

    def get_active_clients_count(self) -> int:
        """Return the count of currently connected client sessions."""
        return sum(
            1 for c in self.clients.values()
            if c.state in (ClientConnectionState.CONNECTED, ClientConnectionState.RECONNECTING)
        )

    def connect_client(self, ip_address: str = "127.0.0.1", port: int = MODBUS_TCP_DEFAULT_PORT) -> ClientConnection:
        """Establish a new client connection session in the gateway pool.

        Raises:
            ModbusTcpClientOverflowError: If maximum pool capacity (16) is reached.
        """
        active_count = self.get_active_clients_count()
        if active_count >= self.max_clients:
            self._trip_fault(
                ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_CLIENT_OVERFLOW,
                details=f"Client pool overflow: {active_count} active clients exceeds capacity of {self.max_clients}.",
            )
            raise ModbusTcpClientOverflowError(
                f"Modbus TCP client connection limit reached: {active_count}/{self.max_clients} active clients."
            )

        client_id = self._allocate_client_id()
        connection = ClientConnection(
            client_id=client_id,
            ip_address=ip_address,
            port=port,
            state=ClientConnectionState.CONNECTED,
            connected_at_ms=self.elapsed_time_ms,
            last_activity_ms=self.elapsed_time_ms,
        )
        self.clients[client_id] = connection
        self.current_client_ip = ip_address

        if not self.fault_trip:
            self.state = GatewayState.LISTENING

        self.sync_to_registers()
        return connection

    def _allocate_client_id(self) -> int:
        """Allocate the next available unique client ID in range 1..16."""
        for cid in range(1, self.max_clients + 1):
            if cid not in self.clients or self.clients[cid].state == ClientConnectionState.CLOSED:
                return cid
        return len(self.clients) + 1

    def disconnect_client(self, client_id: int) -> ExecutionResult:
        """Gracefully disconnect a client socket session."""
        if client_id not in self.clients:
            return ExecutionResult.failed(
                error_code="ERR_CLIENT_NOT_FOUND",
                details=f"Client ID {client_id} not registered in pool.",
            )

        client = self.clients[client_id]
        client.state = ClientConnectionState.DISCONNECTING
        client.state = ClientConnectionState.CLOSED
        client.last_activity_ms = self.elapsed_time_ms

        if not self.fault_trip:
            self.state = GatewayState.LISTENING if self.get_active_clients_count() > 0 else GatewayState.GATEWAY_IDLE

        self.sync_to_registers()
        return ExecutionResult.success(details=f"Client ID {client_id} disconnected cleanly.")

    def reconnect_client(self, client_id: int) -> ExecutionResult:
        """Simulate client socket reconnect lifecycle (DISCONNECT -> RECONNECTING -> CONNECTED)."""
        if client_id not in self.clients:
            return ExecutionResult.failed(
                error_code="ERR_CLIENT_NOT_FOUND",
                details=f"Client ID {client_id} not registered in pool.",
            )

        client = self.clients[client_id]
        client.state = ClientConnectionState.RECONNECTING
        self.state = GatewayState.RECONNECT_WAIT
        self.sync_to_registers()

        client.state = ClientConnectionState.CONNECTED
        client.last_activity_ms = self.elapsed_time_ms
        if not self.fault_trip:
            self.state = GatewayState.LISTENING

        self.sync_to_registers()
        return ExecutionResult.success(details=f"Client ID {client_id} reconnected successfully.")

    def get_client(self, client_id: int) -> Optional[ClientConnection]:
        """Retrieve client connection by ID."""
        return self.clients.get(client_id)

    # ------------------------------------------------------------------------
    # Routing Management
    # ------------------------------------------------------------------------

    def add_downstream_route(
        self,
        unit_id: int,
        name: str,
        endpoint: str = "192.168.1.200:502",
        simulated_latency_ms: float = NOMINAL_ROUND_TRIP_LATENCY_MS,
        is_reachable: bool = True,
        holding_registers: Optional[Dict[int, int]] = None,
        coils: Optional[Dict[int, bool]] = None,
    ) -> None:
        """Register a downstream Modbus slave device route."""
        route = DownstreamRoute(
            unit_id=unit_id,
            name=name,
            endpoint=endpoint,
            simulated_latency_ms=simulated_latency_ms,
            is_reachable=is_reachable,
            holding_registers=holding_registers if holding_registers is not None else {},
            coils=coils if coils is not None else {},
        )
        self.downstream_routes[unit_id] = route

    def set_downstream_reachability(self, unit_id: int, is_reachable: bool) -> None:
        """Toggle online reachability of a downstream slave device."""
        if unit_id in self.downstream_routes:
            self.downstream_routes[unit_id].is_reachable = is_reachable

    # ------------------------------------------------------------------------
    # Transaction Multiplexer & FIFO Queue Operations
    # ------------------------------------------------------------------------

    def enqueue_request(
        self,
        client_id: int,
        request: Union[ModbusTcpAdu, bytes],
        simulated_latency_ms: Optional[float] = None,
    ) -> ExecutionResult:
        """Enqueue an incoming Modbus TCP request into the FIFO multiplexer queue.

        Args:
            client_id: Registered client connection ID.
            request: ModbusTcpAdu instance or raw TCP bytes.
            simulated_latency_ms: Optional simulated processing latency override.

        Returns:
            ExecutionResult indicating queue outcome.
        """
        if client_id not in self.clients:
            return ExecutionResult.failed(
                error_code="ERR_CLIENT_NOT_FOUND",
                details=f"Client ID {client_id} does not exist in connection pool.",
            )

        client = self.clients[client_id]
        if client.state != ClientConnectionState.CONNECTED:
            return ExecutionResult.failed(
                error_code="ERR_CLIENT_NOT_CONNECTED",
                details=f"Client ID {client_id} is in state {client.state.name}, not CONNECTED.",
            )

        # Parse and validate ADU
        if isinstance(request, bytes):
            try:
                adu = ModbusTcpAdu.deserialize(request)
            except ModbusTcpMalformedMbapError as err:
                self._trip_fault(
                    ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_MALFORMED_MBAP,
                    details=str(err),
                )
                return ExecutionResult.failed(
                    error_code="GATEWAY_ERR_MALFORMED_MBAP",
                    details=f"Malformed MBAP header: {err}",
                )
        else:
            adu = request
            if adu.header.protocol_id != MODBUS_PROTOCOL_ID:
                self._trip_fault(
                    ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_MALFORMED_MBAP,
                    details=f"Invalid Protocol ID 0x{adu.header.protocol_id:04X}.",
                )
                return ExecutionResult.failed(
                    error_code="GATEWAY_ERR_MALFORMED_MBAP",
                    details=f"Protocol ID 0x{adu.header.protocol_id:04X} != 0x0000.",
                )

        # Check queue capacity (32 entries max)
        if len(self.request_queue) >= self.max_queue_depth:
            return ExecutionResult.failed(
                error_code="ERR_QUEUE_OVERFLOW",
                details=f"Multiplexer FIFO queue full ({len(self.request_queue)}/{self.max_queue_depth}).",
            )

        tx = ModbusTcpTransaction(
            transaction_id=adu.transaction_id,
            client_id=client_id,
            request_adu=adu,
            enqueued_at_ms=self.elapsed_time_ms,
            client_ip=client.ip_address,
            unit_id=adu.unit_id,
            round_trip_latency_ms=(
                simulated_latency_ms if simulated_latency_ms is not None else self.nominal_latency_ms
            ),
            status=TransactionStatus.QUEUED,
        )

        self.request_queue.append(tx)
        client.active_transactions[tx.transaction_id] = tx
        client.total_requests += 1
        client.last_activity_ms = self.elapsed_time_ms

        self.current_client_ip = client.ip_address
        self.current_unit_id = adu.unit_id
        if not self.fault_trip:
            self.state = GatewayState.MULTIPLEXING_REQUEST

        self.sync_to_registers()
        return ExecutionResult.success(
            details=f"Transaction {tx.transaction_id} enqueued (queue depth: {len(self.request_queue)}).",
            data={"transaction_id": tx.transaction_id, "queue_depth": len(self.request_queue)},
        )

    def process_next_transaction(self, simulated_latency_override_ms: Optional[float] = None) -> Optional[ModbusTcpTransaction]:
        """Pop the next transaction from the FIFO queue, route it, and dispatch response.

        Returns:
            The processed ModbusTcpTransaction, or None if queue was empty.
        """
        if not self.request_queue:
            return None

        tx = self.request_queue.popleft()
        tx.status = TransactionStatus.PROCESSING
        self.state = GatewayState.MULTIPLEXING_REQUEST

        # Update monotonic tracking word
        self.transaction_id_counter = (self.transaction_id_counter + 1) & 0xFFFF
        self.current_client_ip = tx.client_ip
        self.current_unit_id = tx.unit_id

        adu = tx.request_adu
        unit_id = adu.unit_id

        # Determine latency
        latency_ms = (
            simulated_latency_override_ms
            if simulated_latency_override_ms is not None
            else tx.round_trip_latency_ms
        )

        # Check socket timeout surveillance (> 50.0 ms)
        is_timed_out = latency_ms > self.socket_timeout_ms
        if is_timed_out:
            self.socket_timeout_error_counter += 1
            tx.status = TransactionStatus.TIMED_OUT
            self._trip_fault(
                ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT,
                details=f"Transaction round-trip latency {latency_ms:.1f} ms exceeded timeout {self.socket_timeout_ms:.1f} ms.",
            )
            client = self.clients.get(tx.client_id)
            if client:
                client.socket_timeouts += 1

        # Route by Unit ID
        response_adu: ModbusTcpAdu
        if unit_id in self.local_unit_ids:
            # Local Horner OCS Memory routing
            self.is_last_routing_local = True
            response_adu = self._handle_local_ocs_request(adu)
        elif unit_id in self.downstream_routes:
            # Downstream slave routing
            self.is_last_routing_local = False
            route = self.downstream_routes[unit_id]
            if not route.is_reachable:
                # Downstream device is offline/unreachable
                self._trip_fault(
                    ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_UNIT_ID_UNREACHABLE,
                    details=f"Downstream Unit ID {unit_id} ({route.name}) is unreachable.",
                )
                response_adu = ModbusTcpAdu.create_exception_response(
                    transaction_id=adu.transaction_id,
                    unit_id=unit_id,
                    function_code=adu.function_code,
                    exception_code=EX_GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND,
                )
            else:
                response_adu = self._handle_downstream_request(route, adu)
        else:
            # Unmapped Unit ID
            self.is_last_routing_local = False
            self._trip_fault(
                ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_UNIT_ID_UNREACHABLE,
                details=f"Unit ID {unit_id} not mapped in gateway routing table.",
            )
            response_adu = ModbusTcpAdu.create_exception_response(
                transaction_id=adu.transaction_id,
                unit_id=unit_id,
                function_code=adu.function_code,
                exception_code=EX_GATEWAY_PATH_UNAVAILABLE,
            )

        # Commit latency and response
        tx.round_trip_latency_ms = latency_ms
        self.last_round_trip_latency_ms = latency_ms
        tx.response_adu = response_adu

        if not is_timed_out and not self.fault_trip:
            tx.status = TransactionStatus.COMPLETED

        # Asynchronous response dispatching to matching client socket
        self.state = GatewayState.DISPATCHING_RESPONSE
        client = self.clients.get(tx.client_id)
        if client:
            client.dispatched_responses.append(response_adu)
            client.total_responses += 1
            if tx.transaction_id in client.active_transactions:
                del client.active_transactions[tx.transaction_id]

        self.completed_transactions.append(tx)

        # Transition state back to LISTENING if not faulted and queue is clear
        if not self.fault_trip:
            self.state = (
                GatewayState.MULTIPLEXING_REQUEST
                if len(self.request_queue) > 0
                else GatewayState.LISTENING
            )

        self.sync_to_registers()
        return tx

    def _handle_local_ocs_request(self, adu: ModbusTcpAdu) -> ModbusTcpAdu:
        """Handle request directly against Horner OCS RegisterTable memory image."""
        fc = adu.function_code
        data = adu.pdu_data
        tx_id = adu.transaction_id
        unit_id = adu.unit_id

        try:
            if fc == FC_READ_HOLDING_REGISTERS:
                start_addr, count = struct.unpack_from(">HH", data, 0)
                reg_bytes = bytearray()
                for i in range(count):
                    addr_idx = start_addr + i
                    # Map to %R register
                    reg_name = f"%R{addr_idx if addr_idx >= 1 else 1}"
                    try:
                        val = self.register_table.read_uword(reg_name) & 0xFFFF
                    except Exception:
                        val = 0
                    reg_bytes.extend(struct.pack(">H", val))
                pdu = bytes([fc, len(reg_bytes)]) + bytes(reg_bytes)

            elif fc == FC_READ_INPUT_REGISTERS:
                start_addr, count = struct.unpack_from(">HH", data, 0)
                reg_bytes = bytearray()
                for i in range(count):
                    addr_idx = start_addr + i
                    reg_name = f"%AI{addr_idx if addr_idx >= 1 else 1}"
                    try:
                        val = self.register_table.read_uword(reg_name) & 0xFFFF
                    except Exception:
                        val = 0
                    reg_bytes.extend(struct.pack(">H", val))
                pdu = bytes([fc, len(reg_bytes)]) + bytes(reg_bytes)

            elif fc == FC_READ_COILS:
                start_addr, count = struct.unpack_from(">HH", data, 0)
                byte_cnt = (count + 7) // 8
                buf = bytearray(byte_cnt)
                for i in range(count):
                    bit_idx = start_addr + i
                    reg_name = f"%M{bit_idx if bit_idx >= 1 else 1}"
                    try:
                        b_val = self.register_table.read_bit(reg_name)
                    except Exception:
                        b_val = False
                    if b_val:
                        buf[i // 8] |= (1 << (i % 8))
                pdu = bytes([fc, byte_cnt]) + bytes(buf)

            elif fc == FC_READ_DISCRETE_INPUTS:
                start_addr, count = struct.unpack_from(">HH", data, 0)
                byte_cnt = (count + 7) // 8
                buf = bytearray(byte_cnt)
                for i in range(count):
                    bit_idx = start_addr + i
                    reg_name = f"%I{bit_idx if bit_idx >= 1 else 1}"
                    try:
                        b_val = self.register_table.read_bit(reg_name)
                    except Exception:
                        b_val = False
                    if b_val:
                        buf[i // 8] |= (1 << (i % 8))
                pdu = bytes([fc, byte_cnt]) + bytes(buf)

            elif fc == FC_WRITE_SINGLE_COIL:
                addr, val = struct.unpack_from(">HH", data, 0)
                reg_name = f"%M{addr if addr >= 1 else 1}"
                is_on = (val == 0xFF00)
                self.register_table.write_bit(reg_name, is_on, privilege=PrivilegeMode.SYSTEM)
                pdu = bytes([fc]) + data

            elif fc == FC_WRITE_SINGLE_REGISTER:
                addr, val = struct.unpack_from(">HH", data, 0)
                reg_name = f"%R{addr if addr >= 1 else 1}"
                safe_write_word(self.register_table, reg_name, val)
                pdu = bytes([fc]) + data

            elif fc == FC_WRITE_MULTIPLE_REGISTERS:
                start_addr, count, byte_count = struct.unpack_from(">HHB", data, 0)
                for i in range(count):
                    val = struct.unpack_from(">H", data, 5 + i * 2)[0]
                    reg_name = f"%R{(start_addr + i) if (start_addr + i) >= 1 else 1}"
                    safe_write_word(self.register_table, reg_name, val)
                pdu = bytes([fc]) + struct.pack(">HH", start_addr, count)

            else:
                pdu = bytes([fc | 0x80, EX_ILLEGAL_FUNCTION])

        except Exception:
            pdu = bytes([fc | 0x80, EX_SLAVE_DEVICE_FAILURE])

        header = MbapHeader(transaction_id=tx_id, protocol_id=0, length=1 + len(pdu), unit_id=unit_id)
        return ModbusTcpAdu(header=header, function_code=pdu[0], pdu_data=pdu[1:])

    def _handle_downstream_request(self, route: DownstreamRoute, adu: ModbusTcpAdu) -> ModbusTcpAdu:
        """Handle request forwarded to a downstream virtual slave node."""
        fc = adu.function_code
        data = adu.pdu_data
        tx_id = adu.transaction_id
        unit_id = adu.unit_id

        try:
            if fc == FC_READ_HOLDING_REGISTERS:
                start_addr, count = struct.unpack_from(">HH", data, 0)
                reg_bytes = bytearray()
                for i in range(count):
                    val = route.holding_registers.get(start_addr + i, 0)
                    reg_bytes.extend(struct.pack(">H", val & 0xFFFF))
                pdu = bytes([fc, len(reg_bytes)]) + bytes(reg_bytes)

            elif fc == FC_WRITE_SINGLE_REGISTER:
                addr, val = struct.unpack_from(">HH", data, 0)
                route.holding_registers[addr] = val & 0xFFFF
                pdu = bytes([fc]) + data

            elif fc == FC_WRITE_MULTIPLE_REGISTERS:
                start_addr, count, byte_count = struct.unpack_from(">HHB", data, 0)
                for i in range(count):
                    val = struct.unpack_from(">H", data, 5 + i * 2)[0]
                    route.holding_registers[start_addr + i] = val & 0xFFFF
                pdu = bytes([fc]) + struct.pack(">HH", start_addr, count)

            elif fc == FC_READ_COILS:
                start_addr, count = struct.unpack_from(">HH", data, 0)
                byte_cnt = (count + 7) // 8
                buf = bytearray(byte_cnt)
                for i in range(count):
                    if route.coils.get(start_addr + i, False):
                        buf[i // 8] |= (1 << (i % 8))
                pdu = bytes([fc, byte_cnt]) + bytes(buf)

            elif fc == FC_WRITE_SINGLE_COIL:
                addr, val = struct.unpack_from(">HH", data, 0)
                route.coils[addr] = (val == 0xFF00)
                pdu = bytes([fc]) + data

            else:
                pdu = bytes([fc | 0x80, EX_ILLEGAL_FUNCTION])

        except Exception:
            pdu = bytes([fc | 0x80, EX_SLAVE_DEVICE_FAILURE])

        header = MbapHeader(transaction_id=tx_id, protocol_id=0, length=1 + len(pdu), unit_id=unit_id)
        return ModbusTcpAdu(header=header, function_code=pdu[0], pdu_data=pdu[1:])

    # ------------------------------------------------------------------------
    # State Machine & Scan Step
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.001) -> Dict[str, Any]:
        """Advance deterministic simulation clock and evaluate gateway state machine.

        Args:
            dt: Scan time delta in seconds (or milliseconds if dt >= 1.0).

        Returns:
            Dictionary containing cycle telemetry and gateway status.
        """
        dt_ms = (dt if dt >= 1.0 else dt * 1000.0)
        self.elapsed_time_ms += dt_ms

        if self.fault_trip:
            self.state = GatewayState.GATEWAY_FAULT
            self.sync_to_registers()
            return self._build_status_telemetry()

        # If transactions are in queue, process next FIFO entry
        if self.request_queue:
            self.process_next_transaction()
        else:
            if self.state not in (GatewayState.RECONNECT_WAIT, GatewayState.GATEWAY_FAULT):
                self.state = (
                    GatewayState.LISTENING
                    if self.get_active_clients_count() > 0
                    else GatewayState.GATEWAY_IDLE
                )

        self.sync_to_registers()
        return self._build_status_telemetry()

    def _build_status_telemetry(self) -> Dict[str, Any]:
        """Build telemetry snapshot."""
        return {
            "elapsed_time_ms": self.elapsed_time_ms,
            "state": self.state.name,
            "active_clients": self.get_active_clients_count(),
            "transaction_id_counter": self.transaction_id_counter,
            "latency_ms": self.last_round_trip_latency_ms,
            "latency_ms_scaled": int(round(self.last_round_trip_latency_ms * 10.0)),
            "queue_depth": len(self.request_queue),
            "timeout_errors": self.socket_timeout_error_counter,
            "permissive": self.permissive,
            "fault_trip": self.fault_trip,
            "diagnostic_code": f"0x{int(self.diagnostic_code):04X}",
            "diagnostic_name": self.diagnostic_code.name,
        }

    # ------------------------------------------------------------------------
    # Process Safety Interlocks & Diagnostics
    # ------------------------------------------------------------------------

    def _trip_fault(self, code: ModbusTcpGatewayDiagnosticCode, details: str = "") -> None:
        """Assert fail-safe trip, latch safe shutdown, and clear permissive."""
        self.diagnostic_code = code
        self.state = GatewayState.GATEWAY_FAULT
        self.fault_trip = True
        self.permissive = False
        self.sync_to_registers()

    def trigger_fault(self, code: ModbusTcpGatewayDiagnosticCode) -> None:
        """Explicitly inject a diagnostic fault code."""
        self._trip_fault(code=code, details=f"Injected fault {code.name}")

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Manual / operator reset to clear latched safety trips."""
        self.diagnostic_code = ModbusTcpGatewayDiagnosticCode.OK
        self.fault_trip = False
        self.permissive = True
        self.state = (
            GatewayState.LISTENING
            if self.get_active_clients_count() > 0
            else GatewayState.GATEWAY_IDLE
        )
        if force:
            self.request_queue.clear()
        self.sync_to_registers()
        return ExecutionResult.success(details="Modbus TCP Gateway fault reset successfully.")

    def reset_latch(self, force: bool = False) -> ExecutionResult:
        """Alias for reset_fault."""
        return self.reset_fault(force=force)

    # ------------------------------------------------------------------------
    # Horner OCS Register Space Synchronization
    # ------------------------------------------------------------------------

    def compute_gateway_state_word(self) -> int:
        """Compute 16-bit status word (%R1365) reflecting gateway status bitmask."""
        flags = GatewayStateBits(0)

        # Port 502 socket listener status
        if self.state in (
            GatewayState.GATEWAY_IDLE,
            GatewayState.LISTENING,
            GatewayState.MULTIPLEXING_REQUEST,
            GatewayState.DISPATCHING_RESPONSE,
        ):
            flags |= GatewayStateBits.LISTENER_ACTIVE

        if self.get_active_clients_count() > 0:
            flags |= GatewayStateBits.CLIENT_CONNECTED

        if len(self.request_queue) > 0:
            flags |= GatewayStateBits.QUEUE_NOT_EMPTY

        # State enum in bits 3..5
        state_val = int(self.state.value) & 0x07
        flags |= GatewayStateBits(state_val << 3)

        if self.state == GatewayState.MULTIPLEXING_REQUEST:
            flags |= GatewayStateBits.MULTIPLEXER_BUSY
        elif self.state == GatewayState.RECONNECT_WAIT:
            flags |= GatewayStateBits.RECONNECT_ACTIVE
        elif self.state == GatewayState.DISPATCHING_RESPONSE:
            flags |= GatewayStateBits.RESPONSE_READY

        if self.permissive:
            flags |= GatewayStateBits.PERMISSIVE
        if self.fault_trip:
            flags |= GatewayStateBits.FAULT_TRIP

        if self.diagnostic_code == ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_CLIENT_OVERFLOW:
            flags |= GatewayStateBits.CLIENT_OVERFLOW_FAULT
        elif self.diagnostic_code == ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT:
            flags |= GatewayStateBits.TRANSACTION_TIMEOUT_FAULT
        elif self.diagnostic_code == ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_MALFORMED_MBAP:
            flags |= GatewayStateBits.MALFORMED_MBAP_FAULT
        elif self.diagnostic_code == ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_UNIT_ID_UNREACHABLE:
            flags |= GatewayStateBits.UNIT_ID_UNREACHABLE_FAULT

        if self.is_last_routing_local:
            flags |= GatewayStateBits.ROUTING_LOCAL

        return int(flags)

    def sync_to_registers(self) -> None:
        """Synchronize internal engine state to Horner OCS register space.

        All writes to RegisterTable MUST pass privilege=PrivilegeMode.SYSTEM.
        """
        active_clients = self.get_active_clients_count()
        latency_scaled = int(round(self.last_round_trip_latency_ms * 10.0))
        queue_depth = len(self.request_queue)
        state_word = self.compute_gateway_state_word()
        client_unit_word = encode_client_ip_unit_id_word(self.current_client_ip, self.current_unit_id)

        # %R1360: ActiveTcpClientsCount (INT16, 0..16)
        safe_write_word(self.register_table, "%R1360", active_clients)
        # %R1361: TransactionIdTrackingWord (UINT16 monotonic 0..65535)
        safe_write_uword(self.register_table, "%R1361", self.transaction_id_counter & 0xFFFF)
        # %R1362: GatewayRoundTripLatencyMsScaled (INT16, scaled x10 ms)
        safe_write_word(self.register_table, "%R1362", latency_scaled)
        # %R1363: MultiplexerQueueDepth (INT16, 0..32)
        safe_write_word(self.register_table, "%R1363", queue_depth)
        # %R1364: SocketTimeoutErrorCounter (INT16)
        safe_write_word(self.register_table, "%R1364", self.socket_timeout_error_counter)
        # %R1365: GatewayStateWord (INT16 bitmask)
        safe_write_word(self.register_table, "%R1365", state_word)
        # %R1366: ClientIpAndUnitIdWord (UINT16)
        safe_write_uword(self.register_table, "%R1366", client_unit_word)
        # %R1367: DiagnosticStatusCode (UINT16: 0x0000=OK, 0xC801..0xC804)
        safe_write_uword(self.register_table, "%R1367", int(self.diagnostic_code))

        # Discrete interlock coils
        safe_write_bit(self.register_table, "%M317", self.permissive)
        safe_write_bit(self.register_table, "%M318", self.fault_trip)


# Aliases for Engine
ModbusTcpGatewaySync = ModbusTcpGatewayEngine
TcpMultiClientMultiplexerSync = ModbusTcpGatewayEngine
TcpMultiClientMultiplexerSyncEngine = ModbusTcpGatewayEngine
ModbusTcpGateway = ModbusTcpGatewayEngine
ModbusTcpMultiplexerEngine = ModbusTcpGatewayEngine


# ============================================================================
# 9. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_modbus_tcp_gateway_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W175.

    Returns strict 4-state contract JSON response:
    - Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings (%R1360..%R1367, %M317..%M318)
    - Stage 2: MBAP Header Framing, Parsing, Serialization & Protocol ID Validation (0x0000)
    - Stage 3: Multi-Client Connection Pool Lifecycle & 16-Client Capacity Ceiling
    - Stage 4: Client Overflow Safety Interlock (0xC801) & Permissive/Trip Assertions
    - Stage 5: Transaction Multiplexing & FIFO Queue Dispatching (Depth <= 32, Monotonic %R1361)
    - Stage 6: Unit ID Gateway Routing (Local Horner OCS RegisterTable vs Downstream Nodes)
    - Stage 7: Round-Trip Latency Tracking (%R1362 scaled x10 ms) & Socket Timeout Surveillance (> 50.0 ms -> 0xC802)
    - Stage 8: Malformed MBAP Trapping (0xC803) & Unreachable Unit ID Trapping (0xC804)
    - Stage 9: Closed-Loop Scan Cycle Simulation (ILogicUnit), Operator Reset Handshake, & Register Space Synchronization
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings
    # ------------------------------------------------------------------------
    val_pou1 = STParser.validate_code(MODBUS_TCP_GATEWAY_SYNC_POU)
    ast_pou1 = STParser.parse_pou(MODBUS_TCP_GATEWAY_SYNC_POU)
    val_pou2 = STParser.validate_code(TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU)
    ast_pou2 = STParser.parse_pou(TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU)

    expected_regs = {
        "%R1360", "%R1361", "%R1362", "%R1363",
        "%R1364", "%R1365", "%R1366", "%R1367",
        "%M317", "%M318",
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
        and ast_pou1.name == "ModbusTcpGatewaySync"
        and ast_pou2.name == "TcpMultiClientMultiplexerSync"
        and set(ast_pou1.bound_registers) == expected_regs
        and set(ast_pou2.bound_registers) == expected_regs
        and verify_modbus_tcp_gateway_pure_st() is True
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Register_Bindings",
        "passed": s1_pass,
        "details": f"Parsed ModbusTcpGatewaySync and alias with 10 registered bindings: {sorted(ast_pou1.bound_registers)}.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: MBAP Header Framing, Parsing, Serialization & Protocol ID Validation
    # ------------------------------------------------------------------------
    mbap = MbapHeader(transaction_id=101, protocol_id=MODBUS_PROTOCOL_ID, length=6, unit_id=1)
    serialized_mbap = mbap.serialize()
    deserialized_mbap = MbapHeader.deserialize(serialized_mbap)

    adu = ModbusTcpAdu.create_read_holding_registers(
        transaction_id=101, unit_id=1, start_address=1360, count=8
    )
    serialized_adu = adu.serialize()
    deserialized_adu = ModbusTcpAdu.deserialize(serialized_adu)

    s2_pass = (
        len(serialized_mbap) == 7
        and deserialized_mbap.transaction_id == 101
        and deserialized_mbap.protocol_id == 0
        and deserialized_mbap.length == 6
        and deserialized_mbap.unit_id == 1
        and len(serialized_adu) == 12  # 7 MBAP + 1 FC + 4 data
        and deserialized_adu.function_code == FC_READ_HOLDING_REGISTERS
        and deserialized_adu.unit_id == 1
        and deserialized_adu.transaction_id == 101
    )
    test_results.append({
        "stage": 2,
        "check": "MBAP_Header_Framing_Parsing_And_Protocol_ID_Validation",
        "passed": s2_pass,
        "details": "MBAP 7-byte framing, protocol ID 0x0000, and ADU serialization/deserialization verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Multi-Client Connection Pool Lifecycle & 16-Client Capacity Ceiling
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine = ModbusTcpGatewayEngine(max_clients=16, register_table=rt)

    # Initial state
    c_count_init = engine.get_active_clients_count()

    # Connect 16 clients sequentially
    clients: List[ClientConnection] = []
    for i in range(1, 17):
        c = engine.connect_client(ip_address=f"192.168.1.{100 + i}", port=502)
        clients.append(c)

    c_count_16 = engine.get_active_clients_count()
    r1360_val = rt.read_word("%R1360")

    # Disconnect client 5
    engine.disconnect_client(5)
    c_count_15 = engine.get_active_clients_count()
    r1360_disconn = rt.read_word("%R1360")

    # Reconnect client 5
    engine.reconnect_client(5)
    c_count_reconn = engine.get_active_clients_count()

    s3_pass = (
        c_count_init == 0
        and c_count_16 == 16
        and r1360_val == 16
        and c_count_15 == 15
        and r1360_disconn == 15
        and c_count_reconn == 16
        and all(c.state == ClientConnectionState.CONNECTED for c in clients)
    )
    test_results.append({
        "stage": 3,
        "check": "Multi_Client_Connection_Pool_Lifecycle_And_16_Capacity",
        "passed": s3_pass,
        "details": "Pool capacity of 16 clients, disconnect, and reconnect lifecycles verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Client Overflow Safety Interlock (0xC801) & Permissive/Trip Assertions
    # ------------------------------------------------------------------------
    overflow_caught = False
    try:
        # Attempt to connect 17th client with 16 already active
        engine.connect_client(ip_address="192.168.1.117", port=502)
    except ModbusTcpClientOverflowError:
        overflow_caught = True

    r1367_overflow = rt.read_uword("%R1367")
    m317_overflow = rt.read_bit("%M317")
    m318_overflow = rt.read_bit("%M318")
    state_word_overflow = rt.read_word("%R1365")

    s4_pass = (
        overflow_caught is True
        and engine.fault_trip is True
        and engine.permissive is False
        and engine.diagnostic_code == ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_CLIENT_OVERFLOW
        and r1367_overflow == 0xC801
        and m317_overflow is False
        and m318_overflow is True
        and (state_word_overflow & int(GatewayStateBits.CLIENT_OVERFLOW_FAULT)) != 0
        and (state_word_overflow & int(GatewayStateBits.FAULT_TRIP)) != 0
    )
    test_results.append({
        "stage": 4,
        "check": "Client_Overflow_Interlock_And_Trip_Assertions",
        "passed": s4_pass,
        "details": "Client pool overflow above 16 trapped deterministically with 0xC801 and fail-safe coil trips.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Transaction Multiplexing & FIFO Queue Dispatching (Depth <= 32)
    # ------------------------------------------------------------------------
    engine.reset_fault(force=True)

    # Client 1 and Client 2 enqueue requests
    adu1 = ModbusTcpAdu.create_read_holding_registers(transaction_id=1001, unit_id=1, start_address=100, count=1)
    adu2 = ModbusTcpAdu.create_read_holding_registers(transaction_id=1002, unit_id=1, start_address=101, count=1)
    adu3 = ModbusTcpAdu.create_read_holding_registers(transaction_id=2001, unit_id=1, start_address=102, count=1)

    engine.enqueue_request(client_id=1, request=adu1)
    engine.enqueue_request(client_id=1, request=adu2)
    engine.enqueue_request(client_id=2, request=adu3)

    q_depth_enqueued = len(engine.request_queue)
    r1363_enqueued = rt.read_word("%R1363")

    # Process all three transactions sequentially
    tx1 = engine.process_next_transaction()
    tx2 = engine.process_next_transaction()
    tx3 = engine.process_next_transaction()

    q_depth_after = len(engine.request_queue)
    r1363_after = rt.read_word("%R1363")
    r1361_tx_track = rt.read_uword("%R1361")

    # Verify dispatching to matching client sockets
    c1 = engine.get_client(1)
    c2 = engine.get_client(2)

    s5_pass = (
        q_depth_enqueued == 3
        and r1363_enqueued == 3
        and tx1 is not None and tx1.transaction_id == 1001 and tx1.client_id == 1
        and tx2 is not None and tx2.transaction_id == 1002 and tx2.client_id == 1
        and tx3 is not None and tx3.transaction_id == 2001 and tx3.client_id == 2
        and q_depth_after == 0
        and r1363_after == 0
        and r1361_tx_track >= 3
        and c1 is not None and len(c1.dispatched_responses) == 2
        and c2 is not None and len(c2.dispatched_responses) == 1
        and c1.dispatched_responses[0].transaction_id == 1001
        and c2.dispatched_responses[0].transaction_id == 2001
    )
    test_results.append({
        "stage": 5,
        "check": "Transaction_Multiplexing_And_FIFO_Queue_Dispatching",
        "passed": s5_pass,
        "details": "FIFO request queue, monotonic transaction ID tracking, and client socket matching verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Unit ID Gateway Routing (Local Horner OCS RegisterTable vs Downstream)
    # ------------------------------------------------------------------------
    engine.reset_fault(force=True)

    # 1. Local OCS register write & read (Unit ID 1)
    safe_write_word(rt, "%R500", 7777)
    req_local = ModbusTcpAdu.create_read_holding_registers(transaction_id=3001, unit_id=1, start_address=500, count=1)
    engine.enqueue_request(client_id=1, request=req_local)
    tx_local = engine.process_next_transaction()

    # 2. Downstream slave route read (Unit ID 2, "FlowTransmitter_FT101")
    req_downstream = ModbusTcpAdu.create_read_holding_registers(transaction_id=3002, unit_id=2, start_address=200, count=1)
    engine.enqueue_request(client_id=1, request=req_downstream)
    tx_downstream = engine.process_next_transaction()

    r1366_val = rt.read_uword("%R1366")
    last_octet, unit_id_out = decode_client_ip_unit_id_word(r1366_val)

    s6_pass = (
        tx_local is not None
        and tx_local.response_adu is not None
        and tx_local.response_adu.function_code == FC_READ_HOLDING_REGISTERS
        and struct.unpack(">H", tx_local.response_adu.pdu_data[1:3])[0] == 7777
        and tx_downstream is not None
        and tx_downstream.response_adu is not None
        and struct.unpack(">H", tx_downstream.response_adu.pdu_data[1:3])[0] == 8888
        and unit_id_out == 2
    )
    test_results.append({
        "stage": 6,
        "check": "Unit_ID_Gateway_Virtual_Routing",
        "passed": s6_pass,
        "details": "Virtual routing between local Horner OCS memory image and downstream device holding registers verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Round-Trip Latency Tracking & Socket Timeout Surveillance (> 50.0 ms)
    # ------------------------------------------------------------------------
    engine.reset_fault(force=True)

    # Part A: Nominal latency (1.5 ms -> 15 scaled in %R1362)
    req_nom = ModbusTcpAdu.create_read_holding_registers(transaction_id=4001, unit_id=1, start_address=100, count=1)
    engine.enqueue_request(client_id=1, request=req_nom, simulated_latency_ms=1.5)
    engine.process_next_transaction(simulated_latency_override_ms=1.5)
    r1362_nom = rt.read_word("%R1362")

    # Part B: Socket Timeout (> 50.0 ms -> 0xC802)
    req_slow = ModbusTcpAdu.create_read_holding_registers(transaction_id=4002, unit_id=1, start_address=100, count=1)
    engine.enqueue_request(client_id=1, request=req_slow, simulated_latency_ms=55.0)
    engine.process_next_transaction(simulated_latency_override_ms=55.0)

    r1367_timeout = rt.read_uword("%R1367")
    r1364_timeout = rt.read_word("%R1364")
    m317_timeout = rt.read_bit("%M317")
    m318_timeout = rt.read_bit("%M318")

    s7_pass = (
        r1362_nom == 15
        and engine.fault_trip is True
        and engine.permissive is False
        and engine.diagnostic_code == ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT
        and r1367_timeout == 0xC802
        and r1364_timeout >= 1
        and m317_timeout is False
        and m318_timeout is True
    )
    test_results.append({
        "stage": 7,
        "check": "Latency_Tracking_And_Socket_Timeout_Surveillance",
        "passed": s7_pass,
        "details": "Nominal round-trip latency (1.5 ms -> 15) and socket timeout (> 50.0 ms -> 0xC802) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Malformed MBAP Trapping (0xC803) & Unreachable Unit ID Trapping (0xC804)
    # ------------------------------------------------------------------------
    # Part A: Malformed MBAP (Protocol ID = 0x0001 != 0x0000)
    engine.reset_fault(force=True)
    bad_mbap_bytes = struct.pack(">HHHB", 9999, 0x0001, 2, 1) + bytes([FC_READ_HOLDING_REGISTERS])
    res_malformed = engine.enqueue_request(client_id=1, request=bad_mbap_bytes)
    r1367_malformed = rt.read_uword("%R1367")
    m317_malformed = rt.read_bit("%M317")
    m318_malformed = rt.read_bit("%M318")

    # Part B: Unreachable Unit ID (Unit ID 5 is configured offline)
    engine.reset_fault(force=True)
    req_unreachable = ModbusTcpAdu.create_read_holding_registers(transaction_id=5001, unit_id=5, start_address=100, count=1)
    engine.enqueue_request(client_id=1, request=req_unreachable)
    tx_unreachable = engine.process_next_transaction()
    r1367_unreachable = rt.read_uword("%R1367")
    m317_unreachable = rt.read_bit("%M317")
    m318_unreachable = rt.read_bit("%M318")

    s8_pass = (
        res_malformed.status == AgentStatus.FAILED
        and r1367_malformed == 0xC803
        and m317_malformed is False
        and m318_malformed is True
        and tx_unreachable is not None
        and tx_unreachable.response_adu is not None
        and (tx_unreachable.response_adu.function_code & 0x80) != 0
        and r1367_unreachable == 0xC804
        and m317_unreachable is False
        and m318_unreachable is True
    )
    test_results.append({
        "stage": 8,
        "check": "Malformed_MBAP_And_Unreachable_Unit_ID_Trapping",
        "passed": s8_pass,
        "details": "Malformed MBAP frames (0xC803) and unreachable/offline Unit IDs (0xC804) trapped cleanly.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Closed-Loop Scan Cycle Simulation & Operator Reset Handshake
    # ------------------------------------------------------------------------
    # Execute scan cycle via ILogicUnit ScanContext
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

    # Perform manual operator reset handshake
    res_reset = engine.reset_fault(force=True)
    engine.sync_to_registers()

    s9_pass = (
        engine.name == "modbus_tcp_gateway"
        and engine.priority == 95
        and engine.is_enabled is True
        and res_reset.status == AgentStatus.SUCCESS
        and engine.diagnostic_code == ModbusTcpGatewayDiagnosticCode.OK
        and rt.read_uword("%R1367") == 0x0000
        and rt.read_bit("%M317") is True
        and rt.read_bit("%M318") is False
        and rt.read_word("%R1360") == 16
        and rt.read_word("%R1363") == 0
    )
    test_results.append({
        "stage": 9,
        "check": "Closed_Loop_Scan_Cycle_And_Operator_Reset_Synchronization",
        "passed": s9_pass,
        "details": "ILogicUnit scan execution, manual operator reset handshake, and memory synchronization verified.",
    })

    # ------------------------------------------------------------------------
    # Verification Summary & Evidence Serialization
    # ------------------------------------------------------------------------
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Industrial Modbus TCP Multi-Client Gateway Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} stages passed).",
        "data": {
            "work_package": "W175",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial Modbus TCP Multi-Client Gateway & Transaction Multiplexer Engine",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R1360..%R1367",
                "discrete_coils": "%M317..%M318",
                "values": {
                    "%R1360": rt.read_word("%R1360"),
                    "%R1361": rt.read_uword("%R1361"),
                    "%R1362": rt.read_word("%R1362"),
                    "%R1363": rt.read_word("%R1363"),
                    "%R1364": rt.read_word("%R1364"),
                    "%R1365": rt.read_word("%R1365"),
                    "%R1366": rt.read_uword("%R1366"),
                    "%R1367": rt.read_uword("%R1367"),
                    "%M317": rt.read_bit("%M317"),
                    "%M318": rt.read_bit("%M318"),
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
    result = run_modbus_tcp_gateway_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
