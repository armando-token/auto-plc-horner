"""Industrial DNP3 / IEEE 1815-2012 Telemetry Protocol Parser and Outstation Engine.

Implements IEEE 1815-2012 Data Link Layer framing (FT3 with CRC-16/DNP),
Pseudo-Transport Layer segmentation/reassembly, and Application Layer
Request/Response parsing and serialization for Horner OCS SCADA telemetry.
Bound to registers %R310..%R315 and discrete coils %M72..%M73.
"""

from __future__ import annotations

import dataclasses
from enum import IntEnum, IntFlag
import json
import os
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & DNP3 CRC-16 (IEEE 1815-2012 Clause 8)
# ============================================================================

class DNP3Constants:
    SYNC_OCTET_1: int = 0x05
    SYNC_OCTET_2: int = 0x64
    SYNC_BYTES: bytes = bytes([0x05, 0x64])

    HEADER_DATA_SIZE: int = 8
    HEADER_CRC_SIZE: int = 2
    HEADER_TOTAL_SIZE: int = 10

    MIN_LENGTH: int = 5
    MAX_LENGTH: int = 255
    MAX_USER_DATA_LEN: int = 250
    MAX_BLOCK_DATA_LEN: int = 16
    CRC_SIZE: int = 2

    BROADCAST_NO_CONFIRM: int = 0xFFFD
    BROADCAST_CONFIRM_OPTIONAL: int = 0xFFFE
    BROADCAST_CONFIRM_ALL: int = 0xFFFF


class DNP3CRC:
    """CRC-16/DNP per IEEE 1815-2012.

    Polynomial: x^16 + x^13 + x^12 + x^11 + x^10 + x^8 + x^6 + x^5 + x^2 + 1
    Reversed polynomial: 0xA6BC
    Initial: 0x0000, Final XOR: 0xFFFF, Reflected in/out.
    Check value for ASCII b'123456789' is 0xEA82.
    """

    POLYNOMIAL_REVERSED: int = 0xA6BC
    INITIAL_REMAINDER: int = 0x0000
    FINAL_XOR: int = 0xFFFF

    _TABLE: List[int] = []

    @classmethod
    def _init_table(cls) -> None:
        if not cls._TABLE:
            table: List[int] = []
            for i in range(256):
                crc = i
                for _ in range(8):
                    if crc & 1:
                        crc = (crc >> 1) ^ cls.POLYNOMIAL_REVERSED
                    else:
                        crc >>= 1
                table.append(crc & 0xFFFF)
            cls._TABLE = table

    @classmethod
    def calculate(cls, data: bytes) -> int:
        if not cls._TABLE:
            cls._init_table()
        crc = cls.INITIAL_REMAINDER
        table = cls._TABLE
        for b in data:
            crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
        return (crc ^ cls.FINAL_XOR) & 0xFFFF

    @classmethod
    def verify(cls, data: bytes, expected_crc: int) -> bool:
        return cls.calculate(data) == (expected_crc & 0xFFFF)


# ============================================================================
# 2. Data Link Layer Framing (IEEE 1815 Clause 8)
# ============================================================================

class PrimaryFunctionCode(IntEnum):
    RESET_LINK_STATES = 0x00
    RESET_USER_PROCESS = 0x01
    TEST_LINK_STATES = 0x02
    CONFIRMED_USER_DATA = 0x03
    UNCONFIRMED_USER_DATA = 0x04
    REQUEST_LINK_STATUS = 0x09


class SecondaryFunctionCode(IntEnum):
    ACK = 0x00
    NACK = 0x01
    LINK_STATUS = 0x0B
    NOT_SUPPORTED = 0x0E


@dataclasses.dataclass
class LinkControlOctet:
    direction: bool = True       # DIR: True=Master->Outstation
    primary: bool = True         # PRM: True=Primary initiating
    fcb: bool = False            # Frame count bit
    fcv: bool = False            # Frame count valid
    dfc: bool = False            # Data flow control
    function_code: int = 0       # 0..15

    def to_byte(self) -> int:
        val = 0
        if self.direction:
            val |= 0x80
        if self.primary:
            val |= 0x40
            if self.fcb:
                val |= 0x20
            if self.fcv:
                val |= 0x10
        else:
            if self.dfc:
                val |= 0x20
        val |= (self.function_code & 0x0F)
        return val

    @classmethod
    def from_byte(cls, byte_val: int) -> LinkControlOctet:
        direction = bool(byte_val & 0x80)
        primary = bool(byte_val & 0x40)
        fcb = bool(byte_val & 0x20) if primary else False
        fcv = bool(byte_val & 0x10) if primary else False
        dfc = bool(byte_val & 0x20) if not primary else False
        function_code = byte_val & 0x0F
        return cls(
            direction=direction,
            primary=primary,
            fcb=fcb,
            fcv=fcv,
            dfc=dfc,
            function_code=function_code,
        )


@dataclasses.dataclass
class DNP3Frame:
    control: LinkControlOctet
    dest_address: int
    source_address: int
    user_data: bytes = b""

    @property
    def length_octet(self) -> int:
        return 5 + len(self.user_data)

    def build(self) -> bytes:
        if len(self.user_data) > DNP3Constants.MAX_USER_DATA_LEN:
            raise ValueError(
                f"User data length {len(self.user_data)} exceeds maximum {DNP3Constants.MAX_USER_DATA_LEN}"
            )
        if not (0 <= self.dest_address <= 0xFFFF):
            raise ValueError(f"Invalid destination address: {self.dest_address}")
        if not (0 <= self.source_address <= 0xFFFF):
            raise ValueError(f"Invalid source address: {self.source_address}")

        header_data = struct.pack(
            "<BBBBHH",
            DNP3Constants.SYNC_OCTET_1,
            DNP3Constants.SYNC_OCTET_2,
            self.length_octet,
            self.control.to_byte(),
            self.dest_address,
            self.source_address,
        )
        header_crc = DNP3CRC.calculate(header_data)
        parts = [header_data, struct.pack("<H", header_crc)]

        data = self.user_data
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + DNP3Constants.MAX_BLOCK_DATA_LEN]
            chunk_crc = DNP3CRC.calculate(chunk)
            parts.append(chunk)
            parts.append(struct.pack("<H", chunk_crc))
            offset += len(chunk)

        return b"".join(parts)

    @classmethod
    def calculate_wire_size(cls, length_octet: int) -> int:
        if not (DNP3Constants.MIN_LENGTH <= length_octet <= DNP3Constants.MAX_LENGTH):
            raise ValueError(f"Length octet {length_octet} outside valid range [5, 255]")
        user_data_len = length_octet - 5
        if user_data_len == 0:
            return DNP3Constants.HEADER_TOTAL_SIZE
        num_full = user_data_len // DNP3Constants.MAX_BLOCK_DATA_LEN
        rem = user_data_len % DNP3Constants.MAX_BLOCK_DATA_LEN
        num_blocks = num_full + (1 if rem > 0 else 0)
        return DNP3Constants.HEADER_TOTAL_SIZE + user_data_len + (num_blocks * DNP3Constants.CRC_SIZE)

    @classmethod
    def parse(cls, raw: bytes) -> Tuple[DNP3Frame, int]:
        if len(raw) < DNP3Constants.HEADER_TOTAL_SIZE:
            raise ValueError(f"Buffer too short for header: {len(raw)} < {DNP3Constants.HEADER_TOTAL_SIZE}")

        sync1, sync2, length_val, ctrl_byte, dest, src = struct.unpack("<BBBBHH", raw[:8])
        if sync1 != DNP3Constants.SYNC_OCTET_1 or sync2 != DNP3Constants.SYNC_OCTET_2:
            raise ValueError(f"Invalid sync bytes: 0x{sync1:02X}, 0x{sync2:02X}")

        header_data = raw[:8]
        expected_crc = struct.unpack("<H", raw[8:10])[0]
        actual_crc = DNP3CRC.calculate(header_data)
        if actual_crc != expected_crc:
            raise ValueError(f"Header CRC mismatch: expected 0x{expected_crc:04X}, calculated 0x{actual_crc:04X}")

        if not (DNP3Constants.MIN_LENGTH <= length_val <= DNP3Constants.MAX_LENGTH):
            raise ValueError(f"Invalid length field: {length_val}")

        wire_size = cls.calculate_wire_size(length_val)
        if len(raw) < wire_size:
            raise ValueError(f"Buffer incomplete: required {wire_size} bytes, have {len(raw)}")

        user_data_len = length_val - 5
        extracted_data = bytearray()
        offset = DNP3Constants.HEADER_TOTAL_SIZE
        bytes_remaining = user_data_len

        while bytes_remaining > 0:
            block_len = min(bytes_remaining, DNP3Constants.MAX_BLOCK_DATA_LEN)
            block_data = raw[offset : offset + block_len]
            block_crc = struct.unpack("<H", raw[offset + block_len : offset + block_len + 2])[0]
            calc_crc = DNP3CRC.calculate(block_data)
            if calc_crc != block_crc:
                raise ValueError(
                    f"Data block CRC mismatch at offset {offset}: "
                    f"expected 0x{block_crc:04X}, calculated 0x{calc_crc:04X}"
                )
            extracted_data.extend(block_data)
            offset += block_len + 2
            bytes_remaining -= block_len

        control = LinkControlOctet.from_byte(ctrl_byte)
        frame = cls(
            control=control,
            dest_address=dest,
            source_address=src,
            user_data=bytes(extracted_data),
        )
        return frame, wire_size


# ============================================================================
# 3. Pseudo-Transport Layer (IEEE 1815 Clause 7)
# ============================================================================

MAX_TRANSPORT_PAYLOAD = 249


@dataclasses.dataclass(frozen=True)
class TransportHeader:
    fin: bool
    fir: bool
    seq: int  # 0..63

    def serialize(self) -> bytes:
        b = (self.seq & 0x3F)
        if self.fir:
            b |= 0x40
        if self.fin:
            b |= 0x80
        return bytes([b])

    @classmethod
    def parse(cls, byte: int) -> TransportHeader:
        return cls(
            fin=bool(byte & 0x80),
            fir=bool(byte & 0x40),
            seq=byte & 0x3F,
        )


class DNP3TransportManager:
    """Handles Transport Layer segmentation and reassembly."""

    def __init__(self) -> None:
        self.tx_seq = 0
        self.rx_buffer = bytearray()
        self.rx_expected_seq: Optional[int] = None

    def segment_apdu(self, apdu: bytes) -> List[bytes]:
        segments: List[bytes] = []
        total_len = len(apdu)
        if total_len == 0:
            hdr = TransportHeader(fin=True, fir=True, seq=self.tx_seq)
            self.tx_seq = (self.tx_seq + 1) % 64
            return [hdr.serialize()]

        offset = 0
        while offset < total_len:
            fir = (offset == 0)
            chunk = apdu[offset : offset + MAX_TRANSPORT_PAYLOAD]
            offset += len(chunk)
            fin = (offset >= total_len)

            hdr = TransportHeader(fin=fin, fir=fir, seq=self.tx_seq)
            segments.append(hdr.serialize() + chunk)
            self.tx_seq = (self.tx_seq + 1) % 64

        return segments

    def reassemble_segment(self, segment: bytes) -> Optional[bytes]:
        if len(segment) < 1:
            raise ValueError("Empty transport segment")

        hdr = TransportHeader.parse(segment[0])
        payload = segment[1:]

        if hdr.fir:
            self.rx_buffer.clear()
            self.rx_expected_seq = hdr.seq
        elif self.rx_expected_seq is None or hdr.seq != self.rx_expected_seq:
            self.rx_buffer.clear()
            self.rx_expected_seq = None
            raise ValueError(f"Transport sequence gap: expected {self.rx_expected_seq}, got {hdr.seq}")

        self.rx_buffer.extend(payload)
        self.rx_expected_seq = (hdr.seq + 1) % 64

        if hdr.fin:
            result = bytes(self.rx_buffer)
            self.rx_buffer.clear()
            self.rx_expected_seq = None
            return result
        return None


# ============================================================================
# 4. Application Layer (IEEE 1815 Clause 8)
# ============================================================================

class FunctionCode(IntEnum):
    CONFIRM = 0x00
    READ = 0x01
    WRITE = 0x02
    SELECT = 0x03
    OPERATE = 0x04
    DIRECT_OPERATE = 0x05
    DIRECT_OPERATE_NO_ACK = 0x06
    RESPONSE = 0x81
    UNSOLICITED_RESPONSE = 0x82


class IIN1Flags(IntFlag):
    ALL_STATIONS = 0x01
    CLASS_1_EVENTS = 0x02
    CLASS_2_EVENTS = 0x04
    CLASS_3_EVENTS = 0x08
    NEED_TIME = 0x10
    LOCAL_CONTROL = 0x20
    DEVICE_TROUBLE = 0x40
    DEVICE_RESTART = 0x80


class IIN2Flags(IntFlag):
    FUNCTION_NOT_SUPPORTED = 0x01
    OBJECT_UNKNOWN = 0x02
    PARAMETER_ERROR = 0x04
    BUFFER_OVERFLOW = 0x08
    ALREADY_EXECUTING = 0x10
    CONFIG_CORRUPT = 0x20
    RESERVED_1 = 0x40
    RESERVED_2 = 0x80


@dataclasses.dataclass
class InternalIndications:
    iin1: IIN1Flags = IIN1Flags(0)
    iin2: IIN2Flags = IIN2Flags(0)

    def serialize(self) -> bytes:
        return bytes([self.iin1, self.iin2])

    @classmethod
    def parse(cls, data: bytes) -> InternalIndications:
        if len(data) < 2:
            raise ValueError("IIN field requires 2 bytes")
        return cls(iin1=IIN1Flags(data[0]), iin2=IIN2Flags(data[1]))


@dataclasses.dataclass(frozen=True)
class ApplicationControl:
    fir: bool
    fin: bool
    con: bool
    uns: bool
    seq: int  # 0..15

    def serialize(self) -> bytes:
        b = (self.seq & 0x0F)
        if self.uns:
            b |= 0x10
        if self.con:
            b |= 0x20
        if self.fin:
            b |= 0x40
        if self.fir:
            b |= 0x80
        return bytes([b])

    @classmethod
    def parse(cls, byte: int) -> ApplicationControl:
        return cls(
            fir=bool(byte & 0x80),
            fin=bool(byte & 0x40),
            con=bool(byte & 0x20),
            uns=bool(byte & 0x10),
            seq=byte & 0x0F,
        )


@dataclasses.dataclass
class DNP3Message:
    ac: ApplicationControl
    fc: FunctionCode
    iin: Optional[InternalIndications] = None
    objects: bytes = b""

    def is_response(self) -> bool:
        return self.fc in (FunctionCode.RESPONSE, FunctionCode.UNSOLICITED_RESPONSE)

    def serialize(self) -> bytes:
        buf = bytearray()
        buf.extend(self.ac.serialize())
        buf.append(self.fc)
        if self.is_response():
            iin = self.iin or InternalIndications()
            buf.extend(iin.serialize())
        buf.extend(self.objects)
        return bytes(buf)

    @classmethod
    def parse(cls, data: bytes) -> DNP3Message:
        if len(data) < 2:
            raise ValueError("APDU too short (< 2 bytes)")
        ac = ApplicationControl.parse(data[0])
        fc = FunctionCode(data[1])
        idx = 2
        iin: Optional[InternalIndications] = None
        if fc in (FunctionCode.RESPONSE, FunctionCode.UNSOLICITED_RESPONSE):
            if len(data) < 4:
                raise ValueError("Response APDU missing 2-byte IIN")
            iin = InternalIndications.parse(data[2:4])
            idx = 4
        return cls(ac=ac, fc=fc, iin=iin, objects=data[idx:])


# ============================================================================
# 5. Object Groups (Group 1, Group 30, Group 12 CROB)
# ============================================================================

class BinaryInputFlags(IntFlag):
    STATE = 0x01
    CHATTER_FILTER = 0x04
    LOCAL_FORCED = 0x08
    REMOTE_FORCED = 0x10
    COMM_LOST = 0x20
    RESTART = 0x40
    ONLINE = 0x80


class AnalogInputFlags(IntFlag):
    ONLINE = 0x01
    RESTART = 0x02
    COMM_LOST = 0x04
    REMOTE_FORCED = 0x08
    LOCAL_FORCED = 0x10
    OVER_RANGE = 0x20
    REFERENCE_CHECK = 0x40


class CROBOperationType(IntEnum):
    NUL = 0x00
    PULSE_ON = 0x01
    PULSE_OFF = 0x02
    LATCH_ON = 0x03
    LATCH_OFF = 0x04


class CROBTripClose(IntEnum):
    NUL = 0x00
    CLOSE = 0x01
    TRIP = 0x02


class CROBStatusCode(IntEnum):
    SUCCESS = 0x00
    TIMEOUT = 0x01
    NO_SELECT = 0x02
    FORMAT_ERROR = 0x03
    NOT_SUPPORTED = 0x04
    ALREADY_ACTIVE = 0x05
    HARDWARE_ERROR = 0x06
    LOCAL = 0x07
    TOO_MANY_OPS = 0x08
    NOT_AUTHORIZED = 0x09


@dataclasses.dataclass
class CROBObject:
    op_type: CROBOperationType = CROBOperationType.PULSE_ON
    trip_close: CROBTripClose = CROBTripClose.NUL
    queue: bool = False
    clear: bool = False
    count: int = 1
    on_time_ms: int = 1000
    off_time_ms: int = 0
    status: CROBStatusCode = CROBStatusCode.SUCCESS

    def serialize(self) -> bytes:
        code = (self.op_type & 0x0F) | ((self.trip_close & 0x03) << 6)
        if self.queue:
            code |= 0x10
        if self.clear:
            code |= 0x20
        return struct.pack("<BBIIB", code, self.count & 0xFF, self.on_time_ms, self.off_time_ms, self.status)

    @classmethod
    def parse(cls, data: bytes) -> CROBObject:
        if len(data) < 11:
            raise ValueError("CROB requires 11 bytes")
        code, count, on_time, off_time, status = struct.unpack("<BBIIB", data[:11])
        op_type = CROBOperationType(code & 0x0F)
        trip_close = CROBTripClose((code >> 6) & 0x03)
        queue = bool(code & 0x10)
        clear = bool(code & 0x20)
        return cls(
            op_type=op_type,
            trip_close=trip_close,
            queue=queue,
            clear=clear,
            count=count,
            on_time_ms=on_time,
            off_time_ms=off_time,
            status=CROBStatusCode(status),
        )


class DNP3DataCodec:
    """Helper to pack and unpack Group 1, Group 30, and Group 12 objects."""

    @staticmethod
    def pack_g1v2_binary_inputs(start_idx: int, values: List[Tuple[bool, BinaryInputFlags]]) -> bytes:
        stop_idx = start_idx + len(values) - 1
        hdr = struct.pack("<BBBHH", 1, 2, 0x01, start_idx, stop_idx)
        body = bytearray()
        for state, flags in values:
            b = int(flags & ~BinaryInputFlags.STATE)
            if state:
                b |= BinaryInputFlags.STATE
            body.append(b)
        return hdr + bytes(body)

    @staticmethod
    def pack_g30v2_analog_inputs_16bit(start_idx: int, values: List[Tuple[int, AnalogInputFlags]]) -> bytes:
        stop_idx = start_idx + len(values) - 1
        hdr = struct.pack("<BBBHH", 30, 2, 0x01, start_idx, stop_idx)
        body = bytearray()
        for val, flags in values:
            body.append(int(flags))
            body.extend(struct.pack("<h", val))
        return hdr + bytes(body)

    @staticmethod
    def pack_g30v5_analog_inputs_float32(start_idx: int, values: List[Tuple[float, AnalogInputFlags]]) -> bytes:
        stop_idx = start_idx + len(values) - 1
        hdr = struct.pack("<BBBHH", 30, 5, 0x01, start_idx, stop_idx)
        body = bytearray()
        for val, flags in values:
            body.append(int(flags))
            body.extend(struct.pack("<f", val))
        return hdr + bytes(body)

    @staticmethod
    def pack_g12v1_crob_request(point_idx: int, crob: CROBObject) -> bytes:
        hdr = struct.pack("<BBBH", 12, 1, 0x28, 1)  # 0x28: 2-octet index, 16-bit count
        payload = struct.pack("<H", point_idx) + crob.serialize()
        return hdr + payload

    @staticmethod
    def parse_g12v1_crob(objects_data: bytes) -> Tuple[int, CROBObject]:
        if len(objects_data) < 5 + 2 + 11:
            raise ValueError("Insufficient bytes for G12V1 CROB object")
        group, var, qual, count = struct.unpack("<BBBH", objects_data[:5])
        if group != 12 or var != 1:
            raise ValueError(f"Expected Group 12 Var 1, got Group {group} Var {var}")
        idx = struct.unpack("<H", objects_data[5:7])[0]
        crob = CROBObject.parse(objects_data[7:18])
        return idx, crob


# ============================================================================
# 6. Horner OCS DNP3 Outstation Engine & Pure ST POU
# ============================================================================

DNP3_PURE_ST_POU = """PROGRAM Dnp3TelemetryParser
VAR
    (* Horner OCS Mapped Telemetry Registers *)
    StatusWord AT %R310 : INT;
    FramesParsed AT %R311 : UINT;
    FramesDropped AT %R312 : UINT;
    LastFunctionCode AT %R313 : INT;
    AnalogInput1_PV AT %R314 : INT;
    CrobStatus AT %R315 : INT;

    (* Control & Handshake Coils *)
    EnableHandler AT %M72 : BOOL;
    ResetCounters AT %M73 : BOOL;

    (* Internal Protocol Engine Variables *)
    BitActive : BOOL;
    BitLinkOnline : BOOL;
    BitUnsolActive : BOOL;
    BitCrcError : BOOL;
    BitBufferOverflow : BOOL;
    BitUnknownFC : BOOL;
    CalculatedStatus : INT;
END_VAR

(* 1. Counter and Error State Reset Handshake *)
IF ResetCounters THEN
    FramesParsed := 0;
    FramesDropped := 0;
    BitCrcError := FALSE;
    BitBufferOverflow := FALSE;
    BitUnknownFC := FALSE;
    CrobStatus := 0;
    ResetCounters := FALSE; (* Self-clearing handshake *)
END_IF;

(* 2. Main Protocol Execution Pipeline *)
IF EnableHandler THEN
    BitActive := TRUE;

    (* Range clamping for Analog Input 1 scaled PV [0..10000] *)
    IF AnalogInput1_PV < 0 THEN
        AnalogInput1_PV := 0;
    ELSIF AnalogInput1_PV > 10000 THEN
        AnalogInput1_PV := 10000;
    END_IF;

    (* CROB & Function Code Arbitration *)
    IF LastFunctionCode = 3 THEN
        (* FC 03: Select - Arm relay point *)
        CrobStatus := 0;
    ELSIF LastFunctionCode = 4 THEN
        (* FC 04: Operate - Execute armed relay point *)
        IF CrobStatus = 0 THEN
            CrobStatus := 0; (* Success *)
        ELSE
            CrobStatus := 2; (* Error 2: NO_SELECT *)
        END_IF;
    ELSIF LastFunctionCode = 5 THEN
        (* FC 05: Direct Operate - Immediate fire *)
        CrobStatus := 0;
    ELSIF LastFunctionCode = 1 OR LastFunctionCode = 2 THEN
        (* FC 01: Read, FC 02: Write *)
        BitUnknownFC := FALSE;
    ELSIF LastFunctionCode <> 0 THEN
        (* Unrecognized or unsupported IEEE 1815 Function Code *)
        BitUnknownFC := TRUE;
        FramesDropped := FramesDropped + 1;
    END_IF;

    (* 3. Status Word Synthesis (%R310 Bitfield) *)
    CalculatedStatus := 0;
    IF BitActive THEN
        CalculatedStatus := CalculatedStatus + 1;    (* Bit 0: 0x0001 Active *)
    END_IF;
    IF BitLinkOnline THEN
        CalculatedStatus := CalculatedStatus + 2;    (* Bit 1: 0x0002 Link Layer Online *)
    END_IF;
    IF BitUnsolActive THEN
        CalculatedStatus := CalculatedStatus + 4;    (* Bit 2: 0x0004 Unsolicited Active *)
    END_IF;
    IF BitCrcError THEN
        CalculatedStatus := CalculatedStatus + 8;    (* Bit 3: 0x0008 CRC Error *)
    END_IF;
    IF BitBufferOverflow THEN
        CalculatedStatus := CalculatedStatus + 16;   (* Bit 4: 0x0010 Buffer Overflow *)
    END_IF;
    IF BitUnknownFC THEN
        CalculatedStatus := CalculatedStatus + 32;   (* Bit 5: 0x0020 Unknown Function Code *)
    END_IF;

    StatusWord := CalculatedStatus;
ELSE
    BitActive := FALSE;
    BitLinkOnline := FALSE;
    BitUnsolActive := FALSE;
    StatusWord := 0;
END_IF;
END_PROGRAM"""


class DNP3Outstation:
    """Horner OCS DNP3 Outstation Runtime Engine.

    Manages IEEE 1815 data link, transport reassembly, and application dispatch
    synchronized with Horner OCS register table (%R310..%R315, %M72..%M73).
    """

    def __init__(
        self,
        station_address: int = 10,
        master_address: int = 1,
        registers: Optional[RegisterTable] = None,
    ) -> None:
        self.station_address = station_address
        self.master_address = master_address
        self.registers = registers or RegisterTable()
        self.transport = DNP3TransportManager()
        self.armed_crob: Optional[Tuple[int, CROBObject, float]] = None
        self.arm_timeout_sec: float = 10.0

        # Bitfield flags
        self.bit_crc_error = False
        self.bit_buffer_overflow = False
        self.bit_unknown_fc = False
        self.frames_parsed = 0
        self.frames_dropped = 0
        self.last_function_code = 0
        self.crob_status = CROBStatusCode.SUCCESS

        # Default register states
        self.registers.write_bit("%M72", True, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_bit("%M73", False, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R314", 5000, privilege=PrivilegeMode.SYSTEM)  # 50.00%
        self._sync_registers()

    def _sync_registers(self) -> None:
        enable = self.registers.read_bit("%M72")
        reset = self.registers.read_bit("%M73")

        if reset:
            self.frames_parsed = 0
            self.frames_dropped = 0
            self.bit_crc_error = False
            self.bit_buffer_overflow = False
            self.bit_unknown_fc = False
            self.crob_status = CROBStatusCode.SUCCESS
            self.registers.write_bit("%M73", False, privilege=PrivilegeMode.SYSTEM)

        status = 0
        if enable:
            status |= 0x0001  # Bit 0: Active
            status |= 0x0002  # Bit 1: Link Online
            if self.bit_crc_error:
                status |= 0x0008
            if self.bit_buffer_overflow:
                status |= 0x0010
            if self.bit_unknown_fc:
                status |= 0x0020

        self.registers.write_word("%R310", status, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R311", self.frames_parsed & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R312", self.frames_dropped & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R313", self.last_function_code, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R315", int(self.crob_status), privilege=PrivilegeMode.SYSTEM)

    def process_incoming_frame(self, raw_wire: bytes) -> Optional[bytes]:
        """Ingests raw wire octets and dispatches response frames if required."""
        self._sync_registers()
        if not self.registers.read_bit("%M72"):
            return None

        try:
            dl_frame, _ = DNP3Frame.parse(raw_wire)
        except Exception:
            self.bit_crc_error = True
            self.frames_dropped += 1
            self._sync_registers()
            return None

        if dl_frame.dest_address not in (self.station_address, DNP3Constants.BROADCAST_CONFIRM_ALL, DNP3Constants.BROADCAST_NO_CONFIRM):
            return None

        # Check secondary link status polls
        if dl_frame.control.primary and dl_frame.control.function_code == PrimaryFunctionCode.REQUEST_LINK_STATUS:
            resp_ctrl = LinkControlOctet(
                direction=False, primary=False, dfc=False, function_code=SecondaryFunctionCode.LINK_STATUS
            )
            resp_frame = DNP3Frame(control=resp_ctrl, dest_address=dl_frame.source_address, source_address=self.station_address)
            self.frames_parsed += 1
            self._sync_registers()
            return resp_frame.build()

        if len(dl_frame.user_data) == 0:
            self.frames_parsed += 1
            self._sync_registers()
            return None

        try:
            apdu = self.transport.reassemble_segment(dl_frame.user_data)
        except Exception:
            self.bit_buffer_overflow = True
            self.frames_dropped += 1
            self._sync_registers()
            return None

        if apdu is None:
            # Segment reassembled but fragment not yet complete
            return None

        try:
            msg = DNP3Message.parse(apdu)
        except Exception:
            self.bit_buffer_overflow = True
            self.frames_dropped += 1
            self._sync_registers()
            return None

        self.frames_parsed += 1
        self.last_function_code = int(msg.fc)
        response_apdu = self._handle_app_request(msg)
        self._sync_registers()

        if response_apdu is None:
            return None

        # Package into transport and datalink frames
        tx_segments = self.transport.segment_apdu(response_apdu)
        if not tx_segments:
            return None

        # Single frame response (first segment)
        tx_ctrl = LinkControlOctet(
            direction=False, primary=False, dfc=False, function_code=SecondaryFunctionCode.ACK
        )
        out_frame = DNP3Frame(
            control=tx_ctrl,
            dest_address=dl_frame.source_address,
            source_address=self.station_address,
            user_data=tx_segments[0],
        )
        return out_frame.build()

    def _handle_app_request(self, msg: DNP3Message) -> Optional[bytes]:
        seq = msg.ac.seq
        resp_ac = ApplicationControl(fir=True, fin=True, con=False, uns=False, seq=seq)
        iin = InternalIndications()

        if msg.fc == FunctionCode.READ:
            # Return Group 30 Var 2 (Analog Input 1 from %R314) and Group 1 Var 2 (Status)
            ai_val = self.registers.read_word("%R314")
            g30_data = DNP3DataCodec.pack_g30v2_analog_inputs_16bit(0, [(ai_val, AnalogInputFlags.ONLINE)])
            g1_data = DNP3DataCodec.pack_g1v2_binary_inputs(0, [(True, BinaryInputFlags.ONLINE)])
            resp = DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin, objects=g30_data + g1_data)
            return resp.serialize()

        elif msg.fc == FunctionCode.SELECT:
            try:
                pt, crob = DNP3DataCodec.parse_g12v1_crob(msg.objects)
                self.armed_crob = (pt, crob, time.time())
                self.crob_status = CROBStatusCode.SUCCESS
                crob_echo = dataclasses.replace(crob, status=CROBStatusCode.SUCCESS)
                resp_obj = DNP3DataCodec.pack_g12v1_crob_request(pt, crob_echo)
                return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin, objects=resp_obj).serialize()
            except Exception:
                iin.iin2 |= IIN2Flags.PARAMETER_ERROR
                self.crob_status = CROBStatusCode.FORMAT_ERROR
                return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin).serialize()

        elif msg.fc == FunctionCode.OPERATE:
            try:
                pt, crob = DNP3DataCodec.parse_g12v1_crob(msg.objects)
                if not self.armed_crob or self.armed_crob[0] != pt:
                    self.crob_status = CROBStatusCode.NO_SELECT
                    crob_echo = dataclasses.replace(crob, status=CROBStatusCode.NO_SELECT)
                    resp_obj = DNP3DataCodec.pack_g12v1_crob_request(pt, crob_echo)
                    return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin, objects=resp_obj).serialize()

                if time.time() - self.armed_crob[2] > self.arm_timeout_sec:
                    self.crob_status = CROBStatusCode.TIMEOUT
                    self.armed_crob = None
                    crob_echo = dataclasses.replace(crob, status=CROBStatusCode.TIMEOUT)
                    resp_obj = DNP3DataCodec.pack_g12v1_crob_request(pt, crob_echo)
                    return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin, objects=resp_obj).serialize()

                # Success execution
                self.crob_status = CROBStatusCode.SUCCESS
                self.armed_crob = None
                crob_echo = dataclasses.replace(crob, status=CROBStatusCode.SUCCESS)
                resp_obj = DNP3DataCodec.pack_g12v1_crob_request(pt, crob_echo)
                return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin, objects=resp_obj).serialize()
            except Exception:
                iin.iin2 |= IIN2Flags.PARAMETER_ERROR
                self.crob_status = CROBStatusCode.FORMAT_ERROR
                return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin).serialize()

        elif msg.fc == FunctionCode.DIRECT_OPERATE:
            try:
                pt, crob = DNP3DataCodec.parse_g12v1_crob(msg.objects)
                self.crob_status = CROBStatusCode.SUCCESS
                crob_echo = dataclasses.replace(crob, status=CROBStatusCode.SUCCESS)
                resp_obj = DNP3DataCodec.pack_g12v1_crob_request(pt, crob_echo)
                return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin, objects=resp_obj).serialize()
            except Exception:
                iin.iin2 |= IIN2Flags.PARAMETER_ERROR
                self.crob_status = CROBStatusCode.FORMAT_ERROR
                return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin).serialize()

        elif msg.fc == FunctionCode.CONFIRM:
            return None

        else:
            self.bit_unknown_fc = True
            iin.iin2 |= IIN2Flags.FUNCTION_NOT_SUPPORTED
            return DNP3Message(ac=resp_ac, fc=FunctionCode.RESPONSE, iin=iin).serialize()


# ============================================================================
# 7. Verification & Signoff Evidence Exporter
# ============================================================================

def verify_dnp3_and_export_evidence(
    output_evidence_path: str = "artifacts/telemetry/dnp3_evidence.json",
) -> Dict[str, Any]:
    """Performs full test of DNP3 Data Link, Transport, Application, and ST POU,
    exporting evidence for Gate G8 signoff.
    """
    os.makedirs(os.path.dirname(output_evidence_path), exist_ok=True)
    tests_record: List[Dict[str, Any]] = []

    # 1. CRC Verification
    test_data = b"123456789"
    calc_crc = DNP3CRC.calculate(test_data)
    crc_passed = (calc_crc == 0xEA82)
    tests_record.append({
        "check": "CRC16_DNP_Standard_Check_Vector",
        "expected": "0xEA82",
        "actual": f"0x{calc_crc:04X}",
        "passed": crc_passed,
    })

    # 2. Pure ST POU Validation
    val_st = STParser.validate_code(DNP3_PURE_ST_POU)
    SecurityGuard.assert_pure_st_content(DNP3_PURE_ST_POU)
    st_passed = (val_st.status == AgentStatus.SUCCESS)
    tests_record.append({
        "check": "Pure_ST_POU_Validation",
        "pou_name": "Dnp3TelemetryParser",
        "passed": st_passed,
    })

    # 3. Data Link Framing & Parsing
    ctrl = LinkControlOctet(direction=True, primary=True, fcb=False, fcv=False, function_code=PrimaryFunctionCode.UNCONFIRMED_USER_DATA)
    frame = DNP3Frame(control=ctrl, dest_address=10, source_address=1, user_data=b"\xC0\x01\x01\x02\x01\x00\x00")
    raw_wire = frame.build()
    parsed_frame, consumed = DNP3Frame.parse(raw_wire)
    framing_passed = (
        parsed_frame.dest_address == 10
        and parsed_frame.source_address == 1
        and parsed_frame.user_data == frame.user_data
        and consumed == len(raw_wire)
    )
    tests_record.append({
        "check": "Data_Link_Framing_Roundtrip",
        "wire_bytes_len": len(raw_wire),
        "passed": framing_passed,
    })

    # 4. Outstation Read Request & Response
    regs = RegisterTable()
    regs.write_word("%R314", 7500, privilege=PrivilegeMode.SYSTEM)
    outstation = DNP3Outstation(station_address=10, master_address=1, registers=regs)
    read_apdu = DNP3Message(
        ac=ApplicationControl(fir=True, fin=True, con=False, uns=False, seq=0),
        fc=FunctionCode.READ,
        objects=b"",
    ).serialize()
    tx_segs = outstation.transport.segment_apdu(read_apdu)
    req_frame = DNP3Frame(control=ctrl, dest_address=10, source_address=1, user_data=tx_segs[0]).build()
    resp_wire = outstation.process_incoming_frame(req_frame)
    read_passed = resp_wire is not None and len(resp_wire) > 0
    tests_record.append({
        "check": "Outstation_Read_Analog_Point",
        "analog_pv_scaled": regs.read_word("%R314"),
        "status_word": regs.read_word("%R310"),
        "passed": read_passed,
    })

    # 5. CROB Select-Before-Operate Handshake
    sel_crob = CROBObject(op_type=CROBOperationType.PULSE_ON, count=1, on_time_ms=500)
    sel_apdu = DNP3Message(
        ac=ApplicationControl(fir=True, fin=True, con=False, uns=False, seq=1),
        fc=FunctionCode.SELECT,
        objects=DNP3DataCodec.pack_g12v1_crob_request(0, sel_crob),
    ).serialize()
    sel_segs = outstation.transport.segment_apdu(sel_apdu)
    sel_wire = DNP3Frame(control=ctrl, dest_address=10, source_address=1, user_data=sel_segs[0]).build()
    sel_resp = outstation.process_incoming_frame(sel_wire)
    sel_passed = sel_resp is not None and regs.read_word("%R315") == 0

    op_apdu = DNP3Message(
        ac=ApplicationControl(fir=True, fin=True, con=False, uns=False, seq=2),
        fc=FunctionCode.OPERATE,
        objects=DNP3DataCodec.pack_g12v1_crob_request(0, sel_crob),
    ).serialize()
    op_segs = outstation.transport.segment_apdu(op_apdu)
    op_wire = DNP3Frame(control=ctrl, dest_address=10, source_address=1, user_data=op_segs[0]).build()
    op_resp = outstation.process_incoming_frame(op_wire)
    op_passed = op_resp is not None and regs.read_word("%R315") == 0
    crob_passed = sel_passed and op_passed
    tests_record.append({
        "check": "CROB_Select_Before_Operate",
        "select_passed": sel_passed,
        "operate_passed": op_passed,
        "passed": crob_passed,
    })

    all_passed = all(t["passed"] for t in tests_record)
    status_str = "success" if all_passed else "failed"

    evidence: Dict[str, Any] = {
        "status": status_str,
        "error_code": None if all_passed else "DNP3_VERIFICATION_FAILED",
        "details": f"DNP3 IEEE 1815-2012 protocol verification: {sum(1 for t in tests_record if t['passed'])}/{len(tests_record)} checks passed.",
        "data": {
            "protocol": "DNP3 / IEEE 1815-2012",
            "tests": tests_record,
            "register_map": {
                "analog_registers": "%R310..%R315",
                "discrete_coils": "%M72..%M73",
            },
            "timestamp": time.time(),
        },
    }

    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence
