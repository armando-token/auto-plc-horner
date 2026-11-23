"""Industrial EtherNet/IP & CIP Protocol Telemetry Adapter Engine.

Work Package: W079 (Gate G8 Telemetry Protocols & Scaling Bridge / Gate G4 Simulation)
Standards: ODVA CIP Networks Library Volume 1 (CIP) & Volume 2 (EtherNet/IP Adaptation)
Conformance:
- 24-octet Little-Endian Encapsulation Header
- Common Packet Format (CPF) Items (Null Address, Connected Address, Unconnected Data, Connected Data)
- CIP Message Router & Symbolic EPATH Parsing
- CIP Services: 0x01 Get_Attributes_All, 0x0E Get_Attribute_Single, 0x10 Set_Attribute_Single,
  0x4C Read_Tag, 0x4D Write_Tag
- CIP Identity Object (Class 0x01, Vendor ID 0x0059 Horner Electric, Product Code 102 OCS)
- CIP Assembly Object (Class 0x04, Instance 100 Input Assembly, Instance 101 Output Assembly)
- Horner OCS Register Table Mapping (%R400..%R405, %M93..%M94)
- Pure Structured Text (ST) POU Definition & Ladder Logic Rejection Guard
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import re
import struct
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import (
    PrivilegeMode,
    RegisterTable,
    WordOrder,
)


# ============================================================================
# 1. EtherNet/IP & CIP Enumerations
# ============================================================================

class EIPCommand(IntEnum):
    """EtherNet/IP Encapsulation Header Command Codes (ODVA Vol 2 Chapter 2)."""
    NOP = 0x0000
    LIST_TARGETS = 0x0004
    LIST_IDENTITY = 0x0063
    LIST_INTERFACES = 0x0064
    REGISTER_SESSION = 0x0065
    UNREGISTER_SESSION = 0x0066
    SEND_RR_DATA = 0x006F
    SEND_UNIT_DATA = 0x0070
    INDICATE_STATUS = 0x0072
    CANCEL = 0x0073


class EIPStatus(IntEnum):
    """EtherNet/IP Encapsulation Status / Error Codes (ODVA Vol 2 Table 2-3)."""
    SUCCESS = 0x00000000
    INVALID_COMMAND = 0x00000001
    INSUFFICIENT_MEMORY = 0x00000002
    INCORRECT_DATA = 0x00000003
    INVALID_SESSION_HANDLE = 0x00000064
    INVALID_SESSION_ID = 0x00000065
    UNSUPPORTED_PROTOCOL_REVISION = 0x00000069


class CPFTypeId(IntEnum):
    """Common Packet Format (CPF) Item Type IDs (ODVA Vol 2 Table 2-6)."""
    NULL_ADDRESS = 0x0000
    LIST_IDENTITY_RESPONSE = 0x000C
    SEQUENCED_ADDRESS = 0x0080
    CONNECTED_ADDRESS = 0x00A1
    CONNECTED_DATA = 0x00B1
    UNCONNECTED_DATA = 0x00B2
    LIST_SERVICES_RESPONSE = 0x0100
    SOCKADDR_INFO_O_TO_T = 0x8000
    SOCKADDR_INFO_T_TO_O = 0x8001


class CIPServiceCode(IntEnum):
    """Standard CIP Service Codes (ODVA CIP Vol 1, Appendix A)."""
    GET_ATTRIBUTES_ALL = 0x01
    SET_ATTRIBUTES_ALL = 0x02
    GET_ATTRIBUTE_LIST = 0x03
    SET_ATTRIBUTE_LIST = 0x04
    RESET = 0x05
    START = 0x06
    STOP = 0x07
    CREATE = 0x08
    DELETE = 0x09
    MULTIPLE_SERVICE_PACKET = 0x0A
    APPLY_ATTRIBUTES = 0x0D
    GET_ATTRIBUTE_SINGLE = 0x0E
    SET_ATTRIBUTE_SINGLE = 0x10
    FIND_NEXT_OBJECT_INSTANCE = 0x11
    READ_TAG = 0x4C
    WRITE_TAG = 0x4D
    READ_TAG_FRAGMENTED = 0x4E
    WRITE_TAG_FRAGMENTED = 0x4F
    FORWARD_CLOSE = 0x4E
    UNCONNECTED_SEND = 0x52
    FORWARD_OPEN = 0x54
    LARGE_FORWARD_OPEN = 0x5B


class CIPClassCode(IntEnum):
    """Well-Known CIP Object Class Codes (ODVA CIP Vol 1)."""
    IDENTITY = 0x01
    MESSAGE_ROUTER = 0x02
    ASSEMBLY = 0x04
    CONNECTION = 0x05
    CONNECTION_MANAGER = 0x06
    REGISTER = 0x07
    DISCRETE_INPUT = 0x08
    DISCRETE_OUTPUT = 0x09
    ANALOG_INPUT = 0x0A
    ANALOG_OUTPUT = 0x0B
    TCP_IP_INTERFACE = 0xF5
    ETHERNET_LINK = 0xF6


class CIPGeneralStatus(IntEnum):
    """Standard CIP General Status Codes (ODVA CIP Vol 1, Appendix B)."""
    SUCCESS = 0x00
    CONNECTION_FAILURE = 0x01
    RESOURCE_UNAVAILABLE = 0x02
    INVALID_PARAMETER_VALUE = 0x03
    PATH_SEGMENT_ERROR = 0x04
    PATH_DESTINATION_UNKNOWN = 0x05
    PARTIAL_TRANSFER = 0x06
    CONNECTION_LOST = 0x07
    SERVICE_NOT_SUPPORTED = 0x08
    INVALID_ATTRIBUTE_VALUE = 0x09
    ATTRIBUTE_LIST_ERROR = 0x0A
    ALREADY_IN_REQUESTED_MODE = 0x0B
    OBJECT_STATE_CONFLICT = 0x0C
    OBJECT_ALREADY_EXISTS = 0x0D
    ATTRIBUTE_NOT_SETTABLE = 0x0E
    PRIVILEGE_VIOLATION = 0x0F
    DEVICE_STATE_CONFLICT = 0x10
    REPLY_DATA_TOO_LARGE = 0x11
    FRAGMENTATION_OF_PRIMITIVE_VALUE = 0x12
    NOT_ENOUGH_DATA = 0x13
    ATTRIBUTE_NOT_SUPPORTED = 0x14
    TOO_MUCH_DATA = 0x15
    OBJECT_DOES_NOT_EXIST = 0x16
    SERVICE_REQUEST_ERROR = 0x19
    PATH_SIZE_INVALID = 0x26
    EXTENDED_STATUS = 0xFF


class CIPDataType(IntEnum):
    """Elementary CIP Data Types (ODVA CIP Vol 1, Appendix C)."""
    BOOL = 0x00C1
    SINT = 0x00C2
    INT = 0x00C3
    DINT = 0x00C4
    LINT = 0x00C5
    USINT = 0x00C6
    UINT = 0x00C7
    UDINT = 0x00C8
    ULINT = 0x00C9
    REAL = 0x00CA
    LREAL = 0x00CB
    STRING = 0x00D0


class LogicalType(IntEnum):
    """CIP Logical Segment Types (ODVA CIP Vol 1, Section C-1.4.2)."""
    CLASS = 0
    INSTANCE = 1
    MEMBER = 2
    CONNECTION_POINT = 3
    ATTRIBUTE = 4
    SPECIAL = 5
    SERVICE = 6
    EXTENDED_LOGICAL = 7


class IdentityStatusBits(IntFlag):
    """CIP Identity Object Status Word Bitmask."""
    OWNED = 1 << 0
    CONFIGURED = 1 << 2
    EXT_STATUS_NO_IO = 0b0011 << 4
    EXT_STATUS_RUN = 0b0110 << 4
    EXT_STATUS_MAJOR_FLT = 0b0111 << 4
    MINOR_RECOVERABLE_FAULT = 1 << 8
    MINOR_UNRECOVERABLE_FAULT = 1 << 9
    MAJOR_RECOVERABLE_FAULT = 1 << 10
    MAJOR_UNRECOVERABLE_FAULT = 1 << 11


# ============================================================================
# 2. Encapsulation Header & Common Packet Format (CPF)
# ============================================================================

@dataclass
class EIPHeader:
    """24-octet EtherNet/IP Encapsulation Header (Little-Endian)."""
    command: Union[EIPCommand, int]
    length: int = 0
    session_handle: int = 0x00000000
    status: Union[EIPStatus, int] = EIPStatus.SUCCESS
    sender_context: bytes = b"\x00" * 8
    options: int = 0x00000000

    HEADER_SIZE: int = 24
    STRUCT_FORMAT: str = "<HHII8sI"

    def serialize(self) -> bytes:
        ctx = self.sender_context
        if len(ctx) < 8:
            ctx = ctx.ljust(8, b"\x00")
        elif len(ctx) > 8:
            ctx = ctx[:8]
        return struct.pack(
            self.STRUCT_FORMAT,
            int(self.command),
            self.length & 0xFFFF,
            self.session_handle & 0xFFFFFFFF,
            int(self.status) & 0xFFFFFFFF,
            ctx,
            self.options & 0xFFFFFFFF,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple["EIPHeader", bytes]:
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Encapsulation header requires {cls.HEADER_SIZE} octets, got {len(data)}")
        cmd, length, session_handle, status, sender_context, options = struct.unpack_from(
            cls.STRUCT_FORMAT, data, 0
        )
        return cls(
            command=cmd,
            length=length,
            session_handle=session_handle,
            status=status,
            sender_context=sender_context,
            options=options,
        ), data[cls.HEADER_SIZE:]


@dataclass
class CPFItem:
    """Individual item within a Common Packet Format (CPF) frame."""
    type_id: Union[CPFTypeId, int]
    data: bytes = b""

    @property
    def length(self) -> int:
        return len(self.data)

    def serialize(self) -> bytes:
        return struct.pack("<HH", int(self.type_id), len(self.data)) + self.data

    @classmethod
    def deserialize(cls, buffer: bytes, offset: int = 0) -> Tuple["CPFItem", int]:
        if len(buffer) < offset + 4:
            raise ValueError(f"Insufficient bytes for CPF item header at offset {offset}")
        type_id, length = struct.unpack_from("<HH", buffer, offset)
        offset += 4
        if len(buffer) < offset + length:
            raise ValueError(f"CPF item payload truncated: expected {length}, got {len(buffer) - offset}")
        data = buffer[offset : offset + length]
        return cls(type_id=type_id, data=data), offset + length

    @classmethod
    def null_address(cls) -> "CPFItem":
        return cls(type_id=CPFTypeId.NULL_ADDRESS, data=b"")

    @classmethod
    def connected_address(cls, connection_id: int) -> "CPFItem":
        return cls(type_id=CPFTypeId.CONNECTED_ADDRESS, data=struct.pack("<I", connection_id & 0xFFFFFFFF))

    @classmethod
    def unconnected_data(cls, cip_payload: bytes) -> "CPFItem":
        return cls(type_id=CPFTypeId.UNCONNECTED_DATA, data=cip_payload)

    @classmethod
    def connected_data(cls, cip_payload: bytes, sequence_count: Optional[int] = None) -> "CPFItem":
        if sequence_count is not None:
            data = struct.pack("<H", sequence_count & 0xFFFF) + cip_payload
        else:
            data = cip_payload
        return cls(type_id=CPFTypeId.CONNECTED_DATA, data=data)


def serialize_cpf(items: Sequence[CPFItem]) -> bytes:
    """Serialize a list of CPF items with 16-bit item count prefix."""
    buf = bytearray(struct.pack("<H", len(items)))
    for it in items:
        buf.extend(it.serialize())
    return bytes(buf)


def deserialize_cpf(data: bytes) -> List[CPFItem]:
    """Deserialize raw bytes containing a CPF item count and item array."""
    if len(data) < 2:
        raise ValueError("Insufficient bytes for CPF item count prefix")
    item_count = struct.unpack_from("<H", data, 0)[0]
    items: List[CPFItem] = []
    offset = 2
    for _ in range(item_count):
        it, offset = CPFItem.deserialize(data, offset)
        items.append(it)
    return items


# ============================================================================
# 3. CIP EPATH Segment Architecture
# ============================================================================

@dataclass(frozen=True)
class LogicalSegment:
    """CIP Logical Segment (Class, Instance, Attribute, Member)."""
    logical_type: LogicalType
    value: int

    def encode(self) -> bytes:
        if self.value <= 0xFF:
            return bytes([0x20 | (int(self.logical_type) << 2) | 0x00, self.value])
        elif self.value <= 0xFFFF:
            return bytes([0x20 | (int(self.logical_type) << 2) | 0x01, 0x00]) + struct.pack("<H", self.value)
        else:
            return bytes([0x20 | (int(self.logical_type) << 2) | 0x02, 0x00]) + struct.pack("<I", self.value)


@dataclass(frozen=True)
class SymbolicSegment:
    """ANSI Extended Symbol Segment (0x91) with 16-bit word alignment padding."""
    name: str

    def encode(self) -> bytes:
        raw = self.name.encode("ascii")
        n = len(raw)
        pad = b"\x00" if (n % 2 != 0) else b""
        return bytes([0x91, n]) + raw + pad


@dataclass(frozen=True)
class PortSegment:
    """Port Segment for routing across backplanes and bridges."""
    port: int
    link_address: Union[int, str, bytes]

    def encode(self) -> bytes:
        if isinstance(self.link_address, int):
            addr_bytes = bytes([self.link_address])
            ext = 0
        elif isinstance(self.link_address, str):
            raw = self.link_address.encode("ascii")
            ext = 1
            pad = b"\x00" if (len(raw) % 2 != 0) else b""
            addr_bytes = bytes([len(raw)]) + raw + pad
        else:
            raw = bytes(self.link_address)
            ext = 1
            pad = b"\x00" if (len(raw) % 2 != 0) else b""
            addr_bytes = bytes([len(raw)]) + raw + pad

        port_id_byte = self.port if self.port < 15 else 15
        b0 = (ext << 4) | (port_id_byte & 0x0F)
        port_ext = struct.pack("<H", self.port) if self.port >= 15 else b""
        return bytes([b0]) + port_ext + addr_bytes


CIPSegment = Union[LogicalSegment, SymbolicSegment, PortSegment]


@dataclass
class EPATH:
    """Sequence of CIP segments with word count validation."""
    segments: List[CIPSegment] = field(default_factory=list)

    def encode(self) -> bytes:
        buf = bytearray()
        for seg in self.segments:
            buf.extend(seg.encode())
        return bytes(buf)

    @property
    def word_count(self) -> int:
        b = self.encode()
        if len(b) % 2 != 0:
            raise ValueError(f"EPATH length ({len(b)} bytes) is not word-aligned")
        return len(b) // 2

    @classmethod
    def from_logical(cls, class_id: int, instance_id: int, attribute_id: Optional[int] = None) -> "EPATH":
        segs: List[CIPSegment] = [
            LogicalSegment(LogicalType.CLASS, class_id),
            LogicalSegment(LogicalType.INSTANCE, instance_id),
        ]
        if attribute_id is not None:
            segs.append(LogicalSegment(LogicalType.ATTRIBUTE, attribute_id))
        return cls(segments=segs)

    @classmethod
    def from_tag(cls, tag_path: str) -> "EPATH":
        tokens = re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)|\[(\d+)\]", tag_path)
        segs: List[CIPSegment] = []
        for ident, index in tokens:
            if ident:
                segs.append(SymbolicSegment(ident))
            elif index:
                segs.append(LogicalSegment(LogicalType.MEMBER, int(index)))
        return cls(segments=segs)

    @classmethod
    def decode(cls, data: bytes) -> "EPATH":
        offset = 0
        segments: List[CIPSegment] = []
        while offset < len(data):
            b0 = data[offset]
            seg_type = (b0 >> 5) & 0x07
            if seg_type == 1:  # Logical Segment
                log_type = LogicalType((b0 >> 2) & 0x07)
                fmt = b0 & 0x03
                if fmt == 0:
                    val = data[offset + 1]
                    offset += 2
                elif fmt == 1:
                    val = struct.unpack_from("<H", data, offset + 2)[0]
                    offset += 4
                elif fmt == 2:
                    val = struct.unpack_from("<I", data, offset + 2)[0]
                    offset += 6
                else:
                    raise ValueError(f"Invalid logical format: {fmt}")
                segments.append(LogicalSegment(log_type, val))
            elif b0 == 0x91:  # ANSI Extended Symbolic
                s_len = data[offset + 1]
                name = data[offset + 2 : offset + 2 + s_len].decode("ascii")
                pad = s_len % 2
                offset += 2 + s_len + pad
                segments.append(SymbolicSegment(name))
            elif seg_type == 0:  # Port Segment
                ext = (b0 >> 4) & 0x01
                port = b0 & 0x0F
                cur = offset + 1
                if port == 15:
                    port = struct.unpack_from("<H", data, cur)[0]
                    cur += 2
                if ext == 0:
                    addr: Union[int, str, bytes] = data[cur]
                    cur += 1
                else:
                    a_len = data[cur]
                    cur += 1
                    addr_bytes = data[cur : cur + a_len]
                    cur += a_len
                    if a_len % 2 != 0:
                        cur += 1
                    try:
                        addr = addr_bytes.decode("ascii")
                    except UnicodeDecodeError:
                        addr = addr_bytes
                segments.append(PortSegment(port, addr))
                offset = cur
            else:
                raise ValueError(f"Unsupported CIP segment type: 0x{b0:02x}")
        return cls(segments=segments)


# ============================================================================
# 4. CIP Request & Response Codecs
# ============================================================================

class CIPDataTypeCodec:
    """Encoder and decoder for primitive CIP data types."""

    _FORMAT_MAP: Dict[CIPDataType, str] = {
        CIPDataType.BOOL: "?B",
        CIPDataType.SINT: "<b",
        CIPDataType.INT: "<h",
        CIPDataType.DINT: "<i",
        CIPDataType.LINT: "<q",
        CIPDataType.USINT: "<B",
        CIPDataType.UINT: "<H",
        CIPDataType.UDINT: "<I",
        CIPDataType.ULINT: "<Q",
        CIPDataType.REAL: "<f",
        CIPDataType.LREAL: "<d",
    }

    @classmethod
    def encode(cls, data_type: CIPDataType, value: Any) -> bytes:
        if data_type == CIPDataType.BOOL:
            return bytes([1 if value else 0])
        elif data_type == CIPDataType.STRING:
            raw = str(value).encode("utf-8")
            return struct.pack("<I", len(raw)) + raw
        fmt = cls._FORMAT_MAP.get(data_type)
        if not fmt:
            raise ValueError(f"Unsupported CIP data type: {hex(data_type)}")
        return struct.pack(fmt, value)

    @classmethod
    def decode(cls, data_type: CIPDataType, raw: bytes, offset: int = 0) -> Tuple[Any, int]:
        if data_type == CIPDataType.BOOL:
            return bool(raw[offset]), 1
        elif data_type == CIPDataType.STRING:
            str_len = struct.unpack_from("<I", raw, offset)[0]
            val = raw[offset + 4 : offset + 4 + str_len].decode("utf-8")
            return val, 4 + str_len
        fmt = cls._FORMAT_MAP.get(data_type)
        if not fmt:
            raise ValueError(f"Unsupported CIP data type: {hex(data_type)}")
        size = struct.calcsize(fmt)
        val = struct.unpack_from(fmt, raw, offset)[0]
        return val, size


@dataclass
class CIPRequest:
    """CIP Request Message Structure."""
    service_code: Union[CIPServiceCode, int]
    epath: EPATH
    data: bytes = b""

    def encode(self) -> bytes:
        path_bytes = self.epath.encode()
        if len(path_bytes) % 2 != 0:
            raise ValueError(f"EPATH length ({len(path_bytes)}) must be word-aligned")
        path_words = len(path_bytes) // 2
        header = struct.pack("BB", int(self.service_code) & 0x7F, path_words)
        return header + path_bytes + self.data

    @classmethod
    def decode(cls, raw: bytes) -> "CIPRequest":
        if len(raw) < 2:
            raise ValueError(f"CIP Request too short ({len(raw)} bytes, min 2)")
        service_byte, path_words = struct.unpack_from("BB", raw, 0)
        path_len = path_words * 2
        if len(raw) < 2 + path_len:
            raise ValueError(f"Truncated CIP Request EPATH: needs {2 + path_len}, got {len(raw)}")
        path_bytes = raw[2 : 2 + path_len]
        req_data = raw[2 + path_len :]
        epath = EPATH.decode(path_bytes)
        try:
            svc: Union[CIPServiceCode, int] = CIPServiceCode(service_byte & 0x7F)
        except ValueError:
            svc = service_byte & 0x7F
        return cls(service_code=svc, epath=epath, data=req_data)


@dataclass
class CIPResponse:
    """CIP Response Message Structure."""
    reply_service_code: int
    general_status: CIPGeneralStatus
    additional_status: List[int] = field(default_factory=list)
    data: bytes = b""
    reserved: int = 0x00

    @property
    def is_success(self) -> bool:
        return self.general_status == CIPGeneralStatus.SUCCESS

    @property
    def original_service_code(self) -> int:
        return self.reply_service_code & 0x7F

    def encode(self) -> bytes:
        add_words = len(self.additional_status)
        header = struct.pack("BBBB", self.reply_service_code, self.reserved, int(self.general_status), add_words)
        add_bytes = struct.pack(f"<{add_words}H", *self.additional_status) if add_words else b""
        return header + add_bytes + self.data

    @classmethod
    def decode(cls, raw: bytes) -> "CIPResponse":
        if len(raw) < 4:
            raise ValueError(f"CIP Response too short ({len(raw)} bytes, min 4)")
        reply_svc, res, status_val, add_words = struct.unpack_from("BBBB", raw, 0)
        expected_add_len = 4 + add_words * 2
        if len(raw) < expected_add_len:
            raise ValueError(f"Truncated additional status: needs {expected_add_len}, got {len(raw)}")
        add_status = []
        if add_words > 0:
            add_status = list(struct.unpack_from(f"<{add_words}H", raw, 4))
        resp_data = raw[expected_add_len:]
        try:
            status = CIPGeneralStatus(status_val)
        except ValueError:
            status = CIPGeneralStatus.EXTENDED_STATUS
        return cls(
            reply_service_code=reply_svc,
            general_status=status,
            additional_status=add_status,
            data=resp_data,
            reserved=res,
        )


# ============================================================================
# 5. CIP Identity & Assembly Objects (Emulating Horner OCS)
# ============================================================================

@dataclass
class IdentityObject:
    """CIP Identity Object (Class 0x01, Instance 0x01) for Horner OCS."""
    vendor_id: int = 0x0059          # Horner Electric / Horner APG
    device_type: int = 0x000E        # Programmable Logic Controller
    product_code: int = 102          # Cscape OCS
    major_revision: int = 10         # Major Revision
    minor_revision: int = 2          # Minor Revision
    status: int = int(IdentityStatusBits.CONFIGURED | IdentityStatusBits.EXT_STATUS_NO_IO)
    serial_number: int = 0x12345678  # 32-bit serial number
    product_name: str = "HE-EXL1E2"  # Horner OCS Product Model
    state: int = 0x03                # Operational

    @staticmethod
    def encode_short_string(text: str) -> bytes:
        encoded = text.encode("ascii", errors="replace")
        length = min(len(encoded), 255)
        return struct.pack("B", length) + encoded[:length]

    def get_attribute_single(self, attribute_id: int) -> Tuple[CIPGeneralStatus, bytes]:
        if attribute_id == 1:
            return CIPGeneralStatus.SUCCESS, struct.pack("<H", self.vendor_id)
        elif attribute_id == 2:
            return CIPGeneralStatus.SUCCESS, struct.pack("<H", self.device_type)
        elif attribute_id == 3:
            return CIPGeneralStatus.SUCCESS, struct.pack("<H", self.product_code)
        elif attribute_id == 4:
            return CIPGeneralStatus.SUCCESS, struct.pack("<BB", self.major_revision, self.minor_revision)
        elif attribute_id == 5:
            return CIPGeneralStatus.SUCCESS, struct.pack("<H", self.status)
        elif attribute_id == 6:
            return CIPGeneralStatus.SUCCESS, struct.pack("<I", self.serial_number)
        elif attribute_id == 7:
            return CIPGeneralStatus.SUCCESS, self.encode_short_string(self.product_name)
        elif attribute_id == 8:
            return CIPGeneralStatus.SUCCESS, struct.pack("B", self.state)
        else:
            return CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED, b""

    def get_attributes_all(self) -> Tuple[CIPGeneralStatus, bytes]:
        data = (
            struct.pack(
                "<HHHBBHI",
                self.vendor_id,
                self.device_type,
                self.product_code,
                self.major_revision,
                self.minor_revision,
                self.status,
                self.serial_number,
            )
            + self.encode_short_string(self.product_name)
        )
        return CIPGeneralStatus.SUCCESS, data

    def set_attribute_single(self, attribute_id: int, data: bytes) -> Tuple[CIPGeneralStatus, bytes]:
        if attribute_id == 5:
            if len(data) < 2:
                return CIPGeneralStatus.NOT_ENOUGH_DATA, b""
            self.status = struct.unpack_from("<H", data, 0)[0]
            return CIPGeneralStatus.SUCCESS, b""
        elif attribute_id in (1, 2, 3, 4, 6, 7):
            return CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE, b""
        else:
            return CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED, b""


@dataclass
class AssemblyInstance:
    """Individual CIP Assembly instance (Class 0x04)."""
    instance_id: int
    name: str
    size: int
    buffer: bytearray = field(default_factory=bytearray)
    is_read_only: bool = False

    def __post_init__(self) -> None:
        if len(self.buffer) < self.size:
            self.buffer = bytearray(self.size)

    def read_buffer(self) -> bytes:
        return bytes(self.buffer)

    def write_buffer(self, data: bytes) -> CIPGeneralStatus:
        if self.is_read_only:
            return CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE
        if len(data) > self.size:
            return CIPGeneralStatus.TOO_MUCH_DATA
        if len(data) < self.size:
            return CIPGeneralStatus.NOT_ENOUGH_DATA
        self.buffer[:] = data
        return CIPGeneralStatus.SUCCESS


# ============================================================================
# 6. EtherNet/IP Telemetry Adapter Engine
# ============================================================================

class EtherNetIpAdapterEngine:
    """EtherNet/IP & CIP Protocol Telemetry Adapter Engine."""

    def __init__(self, register_table: Optional[RegisterTable] = None) -> None:
        self.registers: RegisterTable = register_table or RegisterTable()
        self.identity = IdentityObject()
        self.input_assembly = AssemblyInstance(
            instance_id=100,
            name="Input Assembly (Telemetry PVs)",
            size=32,
            is_read_only=True,
        )
        self.output_assembly = AssemblyInstance(
            instance_id=101,
            name="Output Assembly (Control SPs)",
            size=16,
            is_read_only=False,
        )
        self.active_sessions: Set[int] = set()
        self._next_session_handle: int = 0x20001
        self.packets_received: int = 0
        self.packets_transmitted: int = 0
        self.last_cip_service: int = 0
        self.last_cip_general_status: int = 0
        self.adapter_enabled: bool = True
        self.named_tags: Dict[str, Tuple[CIPDataType, Any]] = {
            "SolidsDischargeTemp": (CIPDataType.REAL, 1050.0),
            "MaxShellTemp": (CIPDataType.REAL, 285.4),
            "KilnSpeed": (CIPDataType.REAL, 1.5),
            "CalcinationPct": (CIPDataType.REAL, 96.5),
            "SystemStatusWord": (CIPDataType.UINT, 0x0001),
        }
        self.registers.write_register("%M93", True)
        self.sync_registers()

    def sync_registers(self) -> None:
        """Synchronize telemetry status and counters to Horner OCS registers (%R400..%R405)."""
        prev_priv = self.registers.privilege_mode
        self.registers.privilege_mode = PrivilegeMode.SYSTEM
        try:
            m93 = bool(self.registers.read_register("%M93"))
            self.adapter_enabled = m93

            m94 = bool(self.registers.read_register("%M94"))
            if m94:
                self.packets_received = 0
                self.packets_transmitted = 0
                self.active_sessions.clear()
                self.last_cip_service = 0
                self.last_cip_general_status = 0
                self.registers.write_register("%M94", False)

            if not self.adapter_enabled:
                self.registers.write_register("%R400", 0)
                self.registers.write_register("%R401", 0)
                return

            status_word = 0
            if self.adapter_enabled:
                status_word |= 0x0001  # Bit 0: EIP Server Active
            if len(self.active_sessions) > 0:
                status_word |= 0x0002  # Bit 1: Active Session Registered
            if self.last_cip_service != 0:
                status_word |= 0x0004  # Bit 2: CIP Message Handled
            if self.last_cip_service == CIPServiceCode.READ_TAG:
                status_word |= 0x0008  # Bit 3: Tag Read Request
            elif self.last_cip_service == CIPServiceCode.WRITE_TAG:
                status_word |= 0x0010  # Bit 4: Tag Write Request

            if self.last_cip_general_status != 0:
                status_word |= 0x0020  # Bit 5: Protocol / Framing Error

            self.registers.write_register("%R400", status_word)
            self.registers.write_register("%R401", len(self.active_sessions))
            self.registers.write_register("%R402", self.packets_received & 0xFFFF)
            self.registers.write_register("%R403", self.packets_transmitted & 0xFFFF)
            self.registers.write_register("%R404", self.last_cip_service & 0xFFFF)
            self.registers.write_register("%R405", self.last_cip_general_status & 0xFFFF)
        finally:
            self.registers.privilege_mode = prev_priv

    def handle_packet(self, packet_bytes: bytes) -> bytes:
        """Process an incoming EtherNet/IP encapsulation frame and produce response."""
        self.packets_received += 1
        if not self.adapter_enabled:
            return b""

        if len(packet_bytes) < EIPHeader.HEADER_SIZE:
            self.last_cip_general_status = int(CIPGeneralStatus.NOT_ENOUGH_DATA)
            self.sync_registers()
            raise ValueError(f"Packet too short: {len(packet_bytes)} < {EIPHeader.HEADER_SIZE}")

        header, remaining = EIPHeader.deserialize(packet_bytes)
        payload = remaining[:header.length]
        cmd = header.command
        resp_payload = b""
        resp_status = EIPStatus.SUCCESS
        session_handle = header.session_handle

        if cmd == EIPCommand.REGISTER_SESSION:
            session_handle = self._next_session_handle
            self._next_session_handle += 1
            self.active_sessions.add(session_handle)
            resp_payload = struct.pack("<HH", 1, 0)

        elif cmd == EIPCommand.UNREGISTER_SESSION:
            if session_handle in self.active_sessions:
                self.active_sessions.remove(session_handle)
            self.sync_registers()
            return b""

        elif cmd == EIPCommand.LIST_IDENTITY:
            sock_addr = struct.pack(">HHI4s8s", 2, 44818, 0, bytes([127, 0, 0, 1]), b"\x00" * 8)
            identity_body = (
                struct.pack("<H", 1)
                + sock_addr
                + struct.pack(
                    "<HHHBBHI",
                    self.identity.vendor_id,
                    self.identity.device_type,
                    self.identity.product_code,
                    self.identity.major_revision,
                    self.identity.minor_revision,
                    self.identity.status,
                    self.identity.serial_number,
                )
                + self.identity.encode_short_string(self.identity.product_name)
                + struct.pack("B", self.identity.state)
            )
            resp_payload = serialize_cpf([CPFItem(type_id=CPFTypeId.LIST_IDENTITY_RESPONSE, data=identity_body)])

        elif cmd == EIPCommand.SEND_RR_DATA:
            if session_handle not in self.active_sessions:
                resp_status = EIPStatus.INVALID_SESSION_HANDLE
            elif len(payload) < 6:
                resp_status = EIPStatus.INCORRECT_DATA
            else:
                iface_handle, timeout = struct.unpack_from("<IH", payload, 0)
                items = deserialize_cpf(payload[6:])
                unconnected_item = next((it for it in items if it.type_id == CPFTypeId.UNCONNECTED_DATA), None)
                if not unconnected_item:
                    resp_status = EIPStatus.INCORRECT_DATA
                else:
                    cip_reply = self.dispatch_cip_request(unconnected_item.data)
                    resp_items = [
                        CPFItem.null_address(),
                        CPFItem.unconnected_data(cip_reply),
                    ]
                    resp_payload = struct.pack("<IH", iface_handle, timeout) + serialize_cpf(resp_items)

        elif cmd == EIPCommand.SEND_UNIT_DATA:
            if session_handle not in self.active_sessions:
                resp_status = EIPStatus.INVALID_SESSION_HANDLE
            elif len(payload) < 6:
                resp_status = EIPStatus.INCORRECT_DATA
            else:
                iface_handle, timeout = struct.unpack_from("<IH", payload, 0)
                items = deserialize_cpf(payload[6:])
                conn_addr_item = next((it for it in items if it.type_id == CPFTypeId.CONNECTED_ADDRESS), None)
                conn_data_item = next((it for it in items if it.type_id == CPFTypeId.CONNECTED_DATA), None)
                if not conn_addr_item or not conn_data_item or len(conn_data_item.data) < 2:
                    resp_status = EIPStatus.INCORRECT_DATA
                else:
                    seq_count = struct.unpack_from("<H", conn_data_item.data, 0)[0]
                    cip_reply = self.dispatch_cip_request(conn_data_item.data[2:])
                    resp_items = [
                        CPFItem.connected_address(struct.unpack_from("<I", conn_addr_item.data, 0)[0]),
                        CPFItem.connected_data(cip_reply, sequence_count=seq_count),
                    ]
                    resp_payload = struct.pack("<IH", iface_handle, timeout) + serialize_cpf(resp_items)
        else:
            resp_status = EIPStatus.INVALID_COMMAND

        resp_header = EIPHeader(
            command=cmd,
            length=len(resp_payload),
            session_handle=session_handle,
            status=int(resp_status),
            sender_context=header.sender_context,
            options=header.options,
        )
        self.packets_transmitted += 1
        self.sync_registers()
        return resp_header.serialize() + resp_payload

    def dispatch_cip_request(self, cip_request_bytes: bytes) -> bytes:
        """Route CIP request to appropriate object instance and produce CIP response."""
        if len(cip_request_bytes) < 2:
            self.last_cip_general_status = int(CIPGeneralStatus.NOT_ENOUGH_DATA)
            return struct.pack("<BBBB", 0x14 | 0x80, 0, CIPGeneralStatus.NOT_ENOUGH_DATA, 0)

        service = cip_request_bytes[0]
        self.last_cip_service = service
        path_size_words = cip_request_bytes[1]
        path_byte_len = path_size_words * 2
        if len(cip_request_bytes) < 2 + path_byte_len:
            self.last_cip_general_status = int(CIPGeneralStatus.PATH_SEGMENT_ERROR)
            return struct.pack("<BBBB", service | 0x80, 0, CIPGeneralStatus.PATH_SEGMENT_ERROR, 0)

        path_bytes = cip_request_bytes[2 : 2 + path_byte_len]
        request_data = cip_request_bytes[2 + path_byte_len :]

        try:
            epath = EPATH.decode(path_bytes)
        except Exception:
            self.last_cip_general_status = int(CIPGeneralStatus.PATH_SEGMENT_ERROR)
            return struct.pack("<BBBB", service | 0x80, 0, CIPGeneralStatus.PATH_SEGMENT_ERROR, 0)

        status = CIPGeneralStatus.SUCCESS
        resp_data = b""

        # 1. Identity Object (Class 0x01)
        if any(isinstance(s, LogicalSegment) and s.logical_type == LogicalType.CLASS and s.value == CIPClassCode.IDENTITY for s in epath.segments):
            attr_seg = next((s for s in epath.segments if isinstance(s, LogicalSegment) and s.logical_type == LogicalType.ATTRIBUTE), None)
            attr_id = attr_seg.value if attr_seg else None

            if service == CIPServiceCode.GET_ATTRIBUTE_SINGLE:
                if attr_id is not None:
                    status, resp_data = self.identity.get_attribute_single(attr_id)
                else:
                    status = CIPGeneralStatus.PATH_SEGMENT_ERROR
            elif service == CIPServiceCode.GET_ATTRIBUTES_ALL:
                status, resp_data = self.identity.get_attributes_all()
            elif service == CIPServiceCode.SET_ATTRIBUTE_SINGLE:
                if attr_id is not None:
                    status, resp_data = self.identity.set_attribute_single(attr_id, request_data)
                else:
                    status = CIPGeneralStatus.PATH_SEGMENT_ERROR
            else:
                status = CIPGeneralStatus.SERVICE_NOT_SUPPORTED

        # 2. Assembly Object (Class 0x04)
        elif any(isinstance(s, LogicalSegment) and s.logical_type == LogicalType.CLASS and s.value == CIPClassCode.ASSEMBLY for s in epath.segments):
            inst_seg = next((s for s in epath.segments if isinstance(s, LogicalSegment) and s.logical_type == LogicalType.INSTANCE), None)
            inst_id = inst_seg.value if inst_seg else None

            if inst_id == 100:
                if service == CIPServiceCode.GET_ATTRIBUTE_SINGLE:
                    resp_data = self.input_assembly.read_buffer()
                else:
                    status = CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE
            elif inst_id == 101:
                if service == CIPServiceCode.GET_ATTRIBUTE_SINGLE:
                    resp_data = self.output_assembly.read_buffer()
                elif service == CIPServiceCode.SET_ATTRIBUTE_SINGLE:
                    status = self.output_assembly.write_buffer(request_data)
                else:
                    status = CIPGeneralStatus.SERVICE_NOT_SUPPORTED
            else:
                status = CIPGeneralStatus.PATH_DESTINATION_UNKNOWN

        # 3. Symbolic Tag Access (0x4C Read Tag / 0x4D Write Tag)
        elif any(isinstance(s, SymbolicSegment) for s in epath.segments):
            sym_seg = next(s for s in epath.segments if isinstance(s, SymbolicSegment))
            tag_name = sym_seg.name

            if service == CIPServiceCode.READ_TAG:
                if tag_name in self.named_tags:
                    dtype, val = self.named_tags[tag_name]
                    val_bytes = CIPDataTypeCodec.encode(dtype, val)
                    resp_data = struct.pack("<H", int(dtype)) + val_bytes
                else:
                    status = CIPGeneralStatus.PATH_DESTINATION_UNKNOWN
            elif service == CIPServiceCode.WRITE_TAG:
                if tag_name in self.named_tags:
                    if len(request_data) >= 4:
                        dtype_int, count = struct.unpack_from("<HH", request_data, 0)
                        val_raw = request_data[4:]
                        dtype = CIPDataType(dtype_int)
                        val, _ = CIPDataTypeCodec.decode(dtype, val_raw)
                        self.named_tags[tag_name] = (dtype, val)
                    else:
                        status = CIPGeneralStatus.NOT_ENOUGH_DATA
                else:
                    status = CIPGeneralStatus.PATH_DESTINATION_UNKNOWN
            else:
                status = CIPGeneralStatus.SERVICE_NOT_SUPPORTED
        else:
            status = CIPGeneralStatus.PATH_DESTINATION_UNKNOWN

        self.last_cip_general_status = int(status)
        return struct.pack("<BBBB", service | 0x80, 0, int(status), 0) + resp_data


# ============================================================================
# 7. IEC 61131-3 Pure Structured Text POU Definition
# ============================================================================

EIP_CIP_ST_POU: str = """PROGRAM EtherNetIpTelemetryAdapter
VAR
    (* Horner OCS Mapped Registers (W079) *)
    StatusWord AT %R400 : INT;
    ActiveSessionCount AT %R401 : UINT;
    PacketsReceivedCounter AT %R402 : UINT;
    PacketsTransmittedCounter AT %R403 : UINT;
    LastCipServiceCode AT %R404 : INT;
    LastCipGeneralStatus AT %R405 : INT;

    (* Control & Handshake Coils *)
    EnableAdapter AT %M93 : BOOL;
    ResetCounters AT %M94 : BOOL;

    (* Internal Protocol Engine Variables *)
    BitServerActive : BOOL;
    BitActiveSession : BOOL;
    BitCipMsgHandled : BOOL;
    BitTagReadReq : BOOL;
    BitTagWriteReq : BOOL;
    BitProtocolError : BOOL;
    BitSessionExpired : BOOL;
    CalculatedStatus : INT;
END_VAR

(* 1. Counter and Session Reset Handshake *)
IF ResetCounters THEN
    ActiveSessionCount := 0;
    PacketsReceivedCounter := 0;
    PacketsTransmittedCounter := 0;
    BitProtocolError := FALSE;
    BitSessionExpired := FALSE;
    BitCipMsgHandled := FALSE;
    BitTagReadReq := FALSE;
    BitTagWriteReq := FALSE;
    ResetCounters := FALSE; (* Self-clearing pulse *)
END_IF;

(* 2. Main Protocol Arbitration Pipeline *)
IF EnableAdapter THEN
    BitServerActive := TRUE;

    (* Active Session State Arbitration *)
    IF ActiveSessionCount > 0 THEN
        BitActiveSession := TRUE;
    ELSE
        BitActiveSession := FALSE;
    END_IF;

    (* CIP Service Handling and Classification *)
    IF LastCipServiceCode = 14 THEN
        (* CIP 0x0E (14): Get_Attribute_Single *)
        BitCipMsgHandled := TRUE;
        BitTagReadReq := FALSE;
        BitTagWriteReq := FALSE;
    ELSIF LastCipServiceCode = 16 THEN
        (* CIP 0x10 (16): Set_Attribute_Single *)
        BitCipMsgHandled := TRUE;
        BitTagReadReq := FALSE;
        BitTagWriteReq := FALSE;
    ELSIF LastCipServiceCode = 76 THEN
        (* CIP 0x4C (76): Read_Tag *)
        BitCipMsgHandled := TRUE;
        BitTagReadReq := TRUE;
        BitTagWriteReq := FALSE;
    ELSIF LastCipServiceCode = 77 THEN
        (* CIP 0x4D (77): Write_Tag *)
        BitCipMsgHandled := TRUE;
        BitTagReadReq := FALSE;
        BitTagWriteReq := TRUE;
    ELSIF LastCipServiceCode = 1 THEN
        (* CIP 0x01 (1): Get_Attributes_All *)
        BitCipMsgHandled := TRUE;
        BitTagReadReq := FALSE;
        BitTagWriteReq := FALSE;
    ELSIF LastCipServiceCode = 0 THEN
        BitCipMsgHandled := FALSE;
        BitTagReadReq := FALSE;
        BitTagWriteReq := FALSE;
    ELSE
        BitCipMsgHandled := FALSE;
        BitTagReadReq := FALSE;
        BitTagWriteReq := FALSE;
    END_IF;

    (* CIP General Status Code Error Evaluation *)
    IF LastCipGeneralStatus = 0 THEN
        BitProtocolError := FALSE;
    ELSIF LastCipGeneralStatus = 4 OR LastCipGeneralStatus = 8 OR LastCipGeneralStatus = 5 THEN
        (* 0x04 Path Error, 0x08 Unsupported, 0x05 Destination Unknown *)
        BitProtocolError := TRUE;
    ELSE
        BitProtocolError := TRUE;
    END_IF;

    (* 3. Status Word Synthesis (%R400 Bitfield) *)
    CalculatedStatus := 0;
    IF BitServerActive THEN
        CalculatedStatus := CalculatedStatus + 1;    (* Bit 0: 0x0001 EIP Server Active *)
    END_IF;
    IF BitActiveSession THEN
        CalculatedStatus := CalculatedStatus + 2;    (* Bit 1: 0x0002 Active Session Registered *)
    END_IF;
    IF BitCipMsgHandled THEN
        CalculatedStatus := CalculatedStatus + 4;    (* Bit 2: 0x0004 CIP Message Handled *)
    END_IF;
    IF BitTagReadReq THEN
        CalculatedStatus := CalculatedStatus + 8;    (* Bit 3: 0x0008 Tag Read Request *)
    END_IF;
    IF BitTagWriteReq THEN
        CalculatedStatus := CalculatedStatus + 16;   (* Bit 4: 0x0010 Tag Write Request *)
    END_IF;
    IF BitProtocolError THEN
        CalculatedStatus := CalculatedStatus + 32;   (* Bit 5: 0x0020 Protocol / Framing Error *)
    END_IF;
    IF BitSessionExpired THEN
        CalculatedStatus := CalculatedStatus + 64;   (* Bit 6: 0x0040 Session Expired/Closed *)
    END_IF;

    StatusWord := CalculatedStatus;
ELSE
    BitServerActive := FALSE;
    BitActiveSession := FALSE;
    BitCipMsgHandled := FALSE;
    BitTagReadReq := FALSE;
    BitTagWriteReq := FALSE;
    BitProtocolError := FALSE;
    BitSessionExpired := FALSE;
    StatusWord := 0;
    ActiveSessionCount := 0;
END_IF;
END_PROGRAM
"""


def validate_pure_st() -> ExecutionResult:
    """Validate EtherNet/IP Pure ST code adhering to fail-closed contract."""
    SecurityGuard.assert_pure_st_content(EIP_CIP_ST_POU)
    res = STParser.validate_code(EIP_CIP_ST_POU)
    return res
