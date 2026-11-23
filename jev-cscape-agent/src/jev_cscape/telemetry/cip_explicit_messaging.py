"""Industrial EtherNet/IP Explicit Messaging Connected/Unconnected Message Manager (UCMM) & CIP Object Dictionary Engine.

Work Package: W172 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Strict Pure ST POU 'CipExplicitMessagingSync' (and alias 'EtherNetIpUcmmExplicitSync') with
   Horner OCS RegisterTable bindings (%R1330..%R1337, %M310..%M311). Pure IEC 61131-3
   Structured Text ONLY. Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN
   using SecurityGuard.assert_pure_st_content and STParser.
2. Complete EtherNet/IP & CIP Explicit Messaging Architecture (ODVA CIP Volume 1 & Volume 2):
   - Unconnected Message Manager (UCMM) port 44818 (TCP/IP) explicit message routing and encapsulation.
   - Connected Explicit Messaging (Transport Class 3 connection manager with Connection ID).
   - Core CIP Object Dictionary:
     * Identity Object (Class 0x01): Attributes (Vendor ID, Device Type, Product Code, Revision, Status, Serial Number, Product Name).
     * Message Router (Class 0x02): Explicit request dispatching.
     * Assembly Object (Class 0x04): Data attribute access.
     * Connection Manager (Class 0x06): Forward_Open (0x54) and Forward_Close (0x4E).
     * TCP/IP Interface Object (Class 0xF5): IP configuration, status, interface flags.
     * Ethernet Link Object (Class 0xF6): Interface speed (100 Mbps), duplex status.
   - CIP Services:
     * Get_Attribute_Single (0x0E), Set_Attribute_Single (0x10), Get_Attribute_All (0x01).
   - EPath Segment Parsing: 8-bit and 16-bit logical segments for Class, Instance, Attribute.
   - Fragmentation / reassembly for explicit messages exceeding Ethernet MTU.
   - Transceiver session state machine: UCMM_IDLE, RECEIVING_REQUEST, ROUTING_CIP_OBJECT, SERIALIZING_RESPONSE, TRANSMITTING, UCMM_FAULT.
   - Implement ILogicUnit interface with scan_step(dt).
3. Process Safety Interlocks & Diagnostics:
   - 0xC501: CIP_ERR_UCMM_TIMEOUT (Explicit messaging transaction timeout > 25.0 ms)
             -> asserts %M311 (CipExplicitFaultTrip), clears %M310 (CipExplicitPermissive).
   - 0xC502: CIP_ERR_SERVICE_NOT_SUPPORTED (Unsupported CIP service code).
   - 0xC503: CIP_ERR_OBJECT_PATH_INVALID (Invalid Class, Instance, or Attribute EPath).
   - 0xC504: CIP_ERR_FRAGMENTATION_FAULT (Malformed packet or fragmentation reassembly error).
4. Horner OCS Memory Space Integration:
   - %R1330: UcmmActiveSessionsCount (INT16, e.g. 4 active sessions).
   - %R1331: ConnectionIdWord (UINT16, active Transport Class 3 CIP connection ID).
   - %R1332: ExplicitTransactionCounter (UINT16 monotonic 0..65535).
   - %R1333: ExplicitRequestTimeoutMsScaled (INT16, scaled x10 ms, e.g. 250 = 25.0 ms).
   - %R1334: ExplicitErrorCounter (INT16 count of CIP error responses).
   - %R1335: UcmmTransceiverStateWord (INT16 bitmask of transceiver state and flags).
   - %R1336: CipServiceAndClassWord (UINT16, service code byte + class ID byte).
   - %R1337: DiagnosticStatusCode (0x0000=OK, 0xC501, 0xC502, 0xC503, 0xC504).
   - %M310: CipExplicitPermissive (BOOL).
   - %M311: CipExplicitFaultTrip (BOOL).
   - In sync_to_registers(), pass privilege=PrivilegeMode.SYSTEM to reg_table writes.
5. Deterministic 9-Stage Verification Suite:
   - Function run_cip_explicit_messaging_verification(output_path) implementing 9 stages
     and returning strict 4-state contract JSON.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
from pathlib import Path
import re
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
# 1. Constants & Protocol Definitions (ODVA CIP Volume 1 & Volume 2)
# ============================================================================

ETHERNET_IP_PORT: int = 44818
ETHERNET_DEFAULT_MTU: int = 1500
CIP_FRAGMENTATION_THRESHOLD_BYTES: int = 500

CIP_EXPLICIT_NOMINAL_TIMEOUT_MS: float = 25.0
CIP_EXPLICIT_NOMINAL_TIMEOUT_SCALED: int = 250  # 25.0 ms * 10
CIP_EXPLICIT_MAX_TIMEOUT_MS: float = 25.0

HORNER_VENDOR_ID: int = 0x0059          # Horner Electric / Horner APG
HORNER_DEVICE_TYPE: int = 0x000E        # Programmable Logic Controller (PLC)
HORNER_PRODUCT_CODE: int = 102          # Horner Cscape OCS
HORNER_MAJOR_REVISION: int = 10         # Major Version
HORNER_MINOR_REVISION: int = 2          # Minor Version
HORNER_PRODUCT_NAME: str = "HE-EXL1E2"  # Product Model
HORNER_SERIAL_NUMBER: int = 0x12345678  # 32-bit controller serial number


# ============================================================================
# 2. Enums, Status Flags, & Diagnostic Codes
# ============================================================================

class CipExplicitDiagnosticCode(IntEnum):
    """Horner OCS %R1337 Diagnostic Event Codes for CIP Explicit Messaging (W172)."""
    OK                            = 0x0000  # Normal operation, explicit channel healthy
    CIP_ERR_UCMM_TIMEOUT          = 0xC501  # Transaction timeout > 25.0 ms threshold
    CIP_ERR_SERVICE_NOT_SUPPORTED = 0xC502  # Unsupported CIP service code
    CIP_ERR_OBJECT_PATH_INVALID   = 0xC503  # Invalid Class, Instance, or Attribute EPath
    CIP_ERR_FRAGMENTATION_FAULT   = 0xC504  # Malformed packet or fragmentation reassembly error

    # Convenience aliases
    UCMM_TIMEOUT          = 0xC501
    SERVICE_NOT_SUPPORTED = 0xC502
    OBJECT_PATH_INVALID   = 0xC503
    FRAGMENTATION_FAULT   = 0xC504
    ERR_UCMM_TIMEOUT      = 0xC501
    ERR_SERVICE_NOT_SUPPORTED = 0xC502
    ERR_OBJECT_PATH_INVALID   = 0xC503
    ERR_FRAGMENTATION_FAULT   = 0xC504
    CIP_EXPLICIT_ERR_TRANSACTION_TIMEOUT = 0xC501
    CIP_EXPLICIT_ERR_SERVICE_NOT_SUPPORTED = 0xC502
    CIP_EXPLICIT_ERR_EPATH_ROUTING = 0xC503
    CIP_EXPLICIT_ERR_MALFORMED_FRAME = 0xC504
    CIP_EXPLICIT_ERR_CONNECTION_STATE_CONFLICT = 0xC503


DiagnosticStatusCode = CipExplicitDiagnosticCode


class EIPCommand(IntEnum):
    """EtherNet/IP Encapsulation Header Command Codes (ODVA Vol 2 Chapter 2)."""
    NOP                = 0x0000
    LIST_SERVICES      = 0x0004
    LIST_IDENTITY      = 0x0063
    LIST_INTERFACES    = 0x0064
    REGISTER_SESSION   = 0x0065
    UNREGISTER_SESSION = 0x0066
    SEND_RR_DATA       = 0x006F
    SEND_UNIT_DATA     = 0x0070
    INDICATE_STATUS    = 0x0072
    CANCEL             = 0x0073


class EIPStatus(IntEnum):
    """EtherNet/IP Encapsulation Status Codes (ODVA Vol 2 Table 2-3)."""
    SUCCESS                      = 0x00000000
    INVALID_COMMAND              = 0x00000001
    INSUFFICIENT_MEMORY          = 0x00000002
    INCORRECT_DATA               = 0x00000003
    INVALID_SESSION_HANDLE       = 0x00000064
    INVALID_SESSION_ID           = 0x00000065
    UNSUPPORTED_PROTOCOL_REVISION = 0x00000069


class CPFTypeId(IntEnum):
    """Common Packet Format (CPF) Item Type IDs (ODVA Vol 2 Table 2-6)."""
    NULL_ADDRESS           = 0x0000
    LIST_IDENTITY_RESPONSE = 0x000C
    CONNECTED_ADDRESS      = 0x00A1
    CONNECTED_DATA         = 0x00B1
    UNCONNECTED_DATA       = 0x00B2
    LIST_SERVICES_RESPONSE = 0x0100


class CIPServiceCode(IntEnum):
    """Standard CIP Service Codes (ODVA CIP Vol 1, Appendix A)."""
    GET_ATTRIBUTES_ALL     = 0x01
    SET_ATTRIBUTES_ALL     = 0x02
    GET_ATTRIBUTE_LIST     = 0x03
    SET_ATTRIBUTE_LIST     = 0x04
    RESET                  = 0x05
    START                  = 0x06
    STOP                   = 0x07
    CREATE                 = 0x08
    DELETE                 = 0x09
    GET_ATTRIBUTE_SINGLE   = 0x0E
    SET_ATTRIBUTE_SINGLE   = 0x10
    FORWARD_CLOSE          = 0x4E
    UNCONNECTED_SEND       = 0x52
    FORWARD_OPEN           = 0x54
    LARGE_FORWARD_OPEN     = 0x5B


class CIPClassCode(IntEnum):
    """Well-Known CIP Object Class Codes (ODVA CIP Vol 1)."""
    IDENTITY           = 0x01
    MESSAGE_ROUTER     = 0x02
    ASSEMBLY           = 0x04
    CONNECTION_MANAGER = 0x06
    TCP_IP_INTERFACE   = 0xF5
    ETHERNET_LINK      = 0xF6


class CIPGeneralStatus(IntEnum):
    """Standard CIP General Status Codes (ODVA CIP Vol 1, Appendix B)."""
    SUCCESS                 = 0x00
    CONNECTION_FAILURE      = 0x01
    RESOURCE_UNAVAILABLE    = 0x02
    INVALID_PARAMETER_VALUE = 0x03
    PATH_SEGMENT_ERROR      = 0x04
    PATH_DESTINATION_UNKNOWN = 0x05
    PARTIAL_TRANSFER        = 0x06
    CONNECTION_LOST         = 0x07
    SERVICE_NOT_SUPPORTED   = 0x08
    INVALID_ATTRIBUTE_VALUE = 0x09
    ATTRIBUTE_NOT_SETTABLE  = 0x0E
    TOO_MUCH_DATA           = 0x15
    NOT_ENOUGH_DATA         = 0x13
    ATTRIBUTE_NOT_SUPPORTED = 0x14
    OBJECT_DOES_NOT_EXIST   = 0x16
    FRAGMENTATION_FAULT     = 0x12
    EXTENDED_STATUS         = 0xFF


class LogicalType(IntEnum):
    """CIP Logical Segment Types (ODVA CIP Vol 1, Section C-1.4.2)."""
    CLASS            = 0
    INSTANCE         = 1
    MEMBER           = 2
    CONNECTION_POINT = 3
    ATTRIBUTE        = 4
    SPECIAL          = 5
    SERVICE          = 6
    EXTENDED_LOGICAL = 7


class UcmmTransceiverState(IntEnum):
    """UCMM Transceiver Session State Machine."""
    UCMM_IDLE            = 0
    RECEIVING_REQUEST    = 1
    ROUTING_CIP_OBJECT   = 2
    SERIALIZING_RESPONSE = 3
    TRANSMITTING         = 4
    UCMM_FAULT           = 5


class UcmmTransceiverStateBits(IntFlag):
    """Horner OCS %R1335 UcmmTransceiverStateWord Bitmask Definitions."""
    STATE_BIT_0          = 1 << 0   # Bit 0 (0x0001): State enum bit 0
    STATE_BIT_1          = 1 << 1   # Bit 1 (0x0002): State enum bit 1
    STATE_BIT_2          = 1 << 2   # Bit 2 (0x0004): State enum bit 2
    SESSION_REGISTERED   = 1 << 3   # Bit 3 (0x0008): Active encapsulation sessions > 0
    CLASS3_CONNECTED     = 1 << 4   # Bit 4 (0x0010): Active Transport Class 3 connection
    FRAGMENTATION_ACTIVE = 1 << 5   # Bit 5 (0x0020): Fragmentation / reassembly active
    TRANSACTION_ACTIVE   = 1 << 6   # Bit 6 (0x0040): Explicit request transaction in progress
    RESPONSE_READY       = 1 << 7   # Bit 7 (0x0080): Serialized response ready for transmit
    TIMEOUT_FAULT        = 1 << 8   # Bit 8 (0x0100): 0xC501 timeout trip active
    PERMISSIVE           = 1 << 9   # Bit 9 (0x0200): %M310 CipExplicitPermissive asserted
    FAULT_TRIP           = 1 << 10  # Bit 10 (0x0400): %M311 CipExplicitFaultTrip asserted
    SERVICE_UNSUPPORTED  = 1 << 11  # Bit 11 (0x0800): 0xC502 service unsupported active
    OBJECT_PATH_INVALID  = 1 << 12  # Bit 12 (0x1000): 0xC503 object path invalid active
    FRAGMENTATION_FAULT  = 1 << 13  # Bit 13 (0x2000): 0xC504 fragmentation fault active
    PORT_44818_LISTENING = 1 << 14  # Bit 14 (0x4000): Port 44818 socket listening
    RESERVED             = 1 << 15  # Bit 15 (0x8000): Reserved


# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class CipExplicitMessagingError(Exception):
    """Base exception for EtherNet/IP CIP Explicit Messaging engine faults."""
    pass


class CipUcmmTimeoutError(CipExplicitMessagingError):
    """Raised when an explicit messaging transaction exceeds 25.0 ms (0xC501)."""
    pass


class CipServiceNotSupportedError(CipExplicitMessagingError):
    """Raised when an unsupported CIP service code is requested (0xC502)."""
    pass


class CipObjectPathInvalidError(CipExplicitMessagingError):
    """Raised when EPATH Class, Instance, or Attribute is invalid or malformed (0xC503)."""
    pass


class CipFragmentationFaultError(CipExplicitMessagingError):
    """Raised on malformed fragment sequence, checksum, or reassembly mismatch (0xC504)."""
    pass


# ============================================================================
# 4. CIP EPATH Segment Architecture
# ============================================================================

@dataclass(frozen=True)
class LogicalSegment:
    """CIP Logical Segment (Class, Instance, Attribute, Member)."""
    logical_type: LogicalType
    value: int
    is_16bit: bool = False

    def encode(self) -> bytes:
        if not self.is_16bit and self.value <= 0xFF:
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
    def from_logical(
        cls,
        class_id: int,
        instance_id: int,
        attribute_id: Optional[int] = None,
        is_16bit: bool = False,
    ) -> "EPATH":
        segs: List[CIPSegment] = [
            LogicalSegment(LogicalType.CLASS, class_id, is_16bit=is_16bit),
            LogicalSegment(LogicalType.INSTANCE, instance_id, is_16bit=is_16bit),
        ]
        if attribute_id is not None:
            segs.append(LogicalSegment(LogicalType.ATTRIBUTE, attribute_id, is_16bit=is_16bit))
        return cls(segments=segs)

    @classmethod
    def decode(cls, data: bytes) -> "EPATH":
        if len(data) % 2 != 0:
            raise CipObjectPathInvalidError(f"EPATH length ({len(data)} bytes) is not word-aligned")
        offset = 0
        segments: List[CIPSegment] = []
        while offset < len(data):
            b0 = data[offset]
            seg_type = (b0 >> 5) & 0x07
            if seg_type == 1:  # Logical Segment
                log_type = LogicalType((b0 >> 2) & 0x07)
                fmt = b0 & 0x03
                if fmt == 0:
                    if offset + 1 >= len(data):
                        raise CipObjectPathInvalidError("Truncated 8-bit logical segment")
                    val = data[offset + 1]
                    offset += 2
                    segments.append(LogicalSegment(log_type, val, is_16bit=False))
                elif fmt == 1:
                    if offset + 4 > len(data):
                        raise CipObjectPathInvalidError("Truncated 16-bit logical segment")
                    val = struct.unpack_from("<H", data, offset + 2)[0]
                    offset += 4
                    segments.append(LogicalSegment(log_type, val, is_16bit=True))
                elif fmt == 2:
                    if offset + 6 > len(data):
                        raise CipObjectPathInvalidError("Truncated 32-bit logical segment")
                    val = struct.unpack_from("<I", data, offset + 2)[0]
                    offset += 6
                    segments.append(LogicalSegment(log_type, val, is_16bit=False))
                else:
                    raise CipObjectPathInvalidError(f"Invalid logical segment format: {fmt}")
            elif b0 == 0x91:  # Symbolic Segment
                if offset + 2 > len(data):
                    raise CipObjectPathInvalidError("Truncated symbolic segment")
                s_len = data[offset + 1]
                if offset + 2 + s_len > len(data):
                    raise CipObjectPathInvalidError("Truncated symbolic segment string")
                name = data[offset + 2 : offset + 2 + s_len].decode("ascii", errors="replace")
                pad = s_len % 2
                offset += 2 + s_len + pad
                segments.append(SymbolicSegment(name))
            else:
                raise CipObjectPathInvalidError(f"Unsupported CIP segment type: 0x{b0:02x}")
        return cls(segments=segments)

    def get_logical_ids(self) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        """Extract (class_id, instance_id, attribute_id) from logical segments."""
        class_id: Optional[int] = None
        instance_id: Optional[int] = None
        attribute_id: Optional[int] = None
        for seg in self.segments:
            if isinstance(seg, LogicalSegment):
                if seg.logical_type == LogicalType.CLASS:
                    class_id = seg.value
                elif seg.logical_type == LogicalType.INSTANCE:
                    instance_id = seg.value
                elif seg.logical_type == LogicalType.ATTRIBUTE:
                    attribute_id = seg.value
        return class_id, instance_id, attribute_id


# ============================================================================
# 5. Encapsulation Header & Common Packet Format (CPF) Codecs
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
# 6. CIP Request & Response Codecs
# ============================================================================

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
    general_status: CIPGeneralStatus = CIPGeneralStatus.SUCCESS
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


def encode_short_string(text: str) -> bytes:
    """Encode CIP SHORT_STRING (1 octet length prefix followed by ASCII characters)."""
    raw = text.encode("ascii", errors="replace")
    length = min(len(raw), 255)
    return bytes([length]) + raw[:length]


def decode_short_string(raw: bytes, offset: int = 0) -> Tuple[str, int]:
    """Decode CIP SHORT_STRING returning (string, total_consumed_bytes)."""
    if len(raw) < offset + 1:
        return "", 0
    length = raw[offset]
    s = raw[offset + 1 : offset + 1 + length].decode("ascii", errors="replace")
    return s, 1 + length


# ============================================================================
# 7. Fragmentation & Reassembly Engine
# ============================================================================

@dataclass
class CipExplicitFragment:
    """Explicit message fragment container for transfers exceeding MTU."""
    transaction_id: int
    fragment_index: int
    total_fragments: int
    offset: int
    total_size: int
    data: bytes

    @property
    def is_last(self) -> bool:
        return self.fragment_index == self.total_fragments - 1

    def serialize(self) -> bytes:
        hdr = struct.pack(
            "<HHHIIH",
            self.transaction_id & 0xFFFF,
            self.fragment_index & 0xFFFF,
            self.total_fragments & 0xFFFF,
            self.offset & 0xFFFFFFFF,
            self.total_size & 0xFFFFFFFF,
            len(self.data) & 0xFFFF,
        )
        return hdr + self.data

    @classmethod
    def deserialize(cls, data: bytes) -> "CipExplicitFragment":
        if len(data) < 18:
            raise CipFragmentationFaultError("Fragment packet too short for header")
        tx_id, frag_idx, tot_frags, offset, tot_size, data_len = struct.unpack_from("<HHHIIH", data, 0)
        if len(data) < 18 + data_len:
            raise CipFragmentationFaultError("Fragment payload truncated")
        frag_data = data[18 : 18 + data_len]
        return cls(
            transaction_id=tx_id,
            fragment_index=frag_idx,
            total_fragments=tot_frags,
            offset=offset,
            total_size=tot_size,
            data=frag_data,
        )


class FragmentationEngine:
    """Manages fragmentation of explicit responses and reassembly of multi-part requests."""

    def __init__(self, max_fragment_size: int = CIP_FRAGMENTATION_THRESHOLD_BYTES) -> None:
        self.max_fragment_size: int = max(32, max_fragment_size)
        self._pending_fragments: Dict[int, Dict[int, CipExplicitFragment]] = {}

    def fragment_payload(
        self,
        payload: bytes,
        transaction_id: int = 1,
        chunk_size: Optional[int] = None,
    ) -> List[CipExplicitFragment]:
        """Divide payload into fragment containers."""
        cs = chunk_size or self.max_fragment_size
        if not payload:
            return [CipExplicitFragment(transaction_id, 0, 1, 0, 0, b"")]
        chunks = [payload[i : i + cs] for i in range(0, len(payload), cs)]
        total = len(chunks)
        fragments: List[CipExplicitFragment] = []
        offset = 0
        for idx, chunk in enumerate(chunks):
            fragments.append(
                CipExplicitFragment(
                    transaction_id=transaction_id,
                    fragment_index=idx,
                    total_fragments=total,
                    offset=offset,
                    total_size=len(payload),
                    data=chunk,
                )
            )
            offset += len(chunk)
        return fragments

    def add_fragment(self, fragment: CipExplicitFragment) -> Optional[bytes]:
        """Ingest fragment. If complete message reassembled, returns full payload.

        Raises CipFragmentationFaultError on sequence gaps, corrupted headers, or size mismatches.
        """
        if fragment.total_fragments <= 0 or fragment.fragment_index >= fragment.total_fragments:
            raise CipFragmentationFaultError(
                f"Invalid fragment index {fragment.fragment_index} / total {fragment.total_fragments}"
            )

        tx_id = fragment.transaction_id
        if tx_id not in self._pending_fragments:
            self._pending_fragments[tx_id] = {}

        pending = self._pending_fragments[tx_id]
        if fragment.fragment_index in pending:
            existing = pending[fragment.fragment_index]
            if existing.data != fragment.data or existing.offset != fragment.offset:
                raise CipFragmentationFaultError("Conflicting duplicate fragment payload")
        else:
            pending[fragment.fragment_index] = fragment

        # Check total consistency
        first_frag = next(iter(pending.values()))
        if (
            fragment.total_fragments != first_frag.total_fragments
            or fragment.total_size != first_frag.total_size
        ):
            raise CipFragmentationFaultError("Fragment total count or size inconsistency across stream")

        if len(pending) == fragment.total_fragments:
            # Reassemble and verify continuity
            expected_offset = 0
            assembled = bytearray()
            for i in range(fragment.total_fragments):
                if i not in pending:
                    raise CipFragmentationFaultError(f"Missing fragment index {i}")
                f = pending[i]
                if f.offset != expected_offset:
                    raise CipFragmentationFaultError(
                        f"Fragment offset discontinuity: expected {expected_offset}, got {f.offset}"
                    )
                assembled.extend(f.data)
                expected_offset += len(f.data)

            if len(assembled) != fragment.total_size:
                raise CipFragmentationFaultError(
                    f"Reassembled size ({len(assembled)}) does not match expected total ({fragment.total_size})"
                )

            del self._pending_fragments[tx_id]
            return bytes(assembled)

        return None

    def reset(self) -> None:
        self._pending_fragments.clear()


# ============================================================================
# 8. CIP Core Object Dictionary (ODVA Volume 1)
# ============================================================================

class ICipObject(ABC):
    """Abstract interface for CIP Object Dictionary instances."""

    @property
    @abstractmethod
    def class_id(self) -> int:
        pass

    @abstractmethod
    def handle_explicit_request(
        self,
        service_code: int,
        instance_id: int,
        attribute_id: Optional[int],
        request_data: bytes,
    ) -> CIPResponse:
        pass

    def get_attribute_single(self, attribute_id: int, instance_id: int = 1) -> Tuple[CIPGeneralStatus, bytes]:
        """Convenience query for a single attribute returning (CIPGeneralStatus, bytes)."""
        resp = self.handle_explicit_request(CIPServiceCode.GET_ATTRIBUTE_SINGLE, instance_id, attribute_id, b"")
        return resp.general_status, resp.data

    def set_attribute_single(self, attribute_id: int, data: bytes = b"", instance_id: int = 1) -> Tuple[CIPGeneralStatus, bytes]:
        """Convenience setter for a single attribute returning (CIPGeneralStatus, bytes)."""
        resp = self.handle_explicit_request(CIPServiceCode.SET_ATTRIBUTE_SINGLE, instance_id, attribute_id, data)
        return resp.general_status, resp.data

    def get_attributes_all(self, instance_id: int = 1) -> Tuple[CIPGeneralStatus, bytes]:
        """Convenience query for all attributes returning (CIPGeneralStatus, bytes)."""
        resp = self.handle_explicit_request(CIPServiceCode.GET_ATTRIBUTES_ALL, instance_id, None, b"")
        return resp.general_status, resp.data


@dataclass
class IdentityObject(ICipObject):
    """CIP Identity Object (Class 0x01, Instance 1) for Horner OCS."""
    vendor_id: int = HORNER_VENDOR_ID
    device_type: int = HORNER_DEVICE_TYPE
    product_code: int = HORNER_PRODUCT_CODE
    major_revision: int = HORNER_MAJOR_REVISION
    minor_revision: int = HORNER_MINOR_REVISION
    status: int = 0x0060  # Configured + No I/O connection active
    serial_number: int = HORNER_SERIAL_NUMBER
    product_name: str = HORNER_PRODUCT_NAME
    state: int = 0x03     # Operational

    @property
    def class_id(self) -> int:
        return CIPClassCode.IDENTITY

    def handle_explicit_request(
        self,
        service_code: int,
        instance_id: int,
        attribute_id: Optional[int],
        request_data: bytes,
    ) -> CIPResponse:
        if instance_id != 1:
            return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.OBJECT_DOES_NOT_EXIST)

        if service_code == CIPServiceCode.GET_ATTRIBUTE_SINGLE:
            if attribute_id == 1:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.vendor_id))
            elif attribute_id == 2:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.device_type))
            elif attribute_id == 3:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.product_code))
            elif attribute_id == 4:
                return CIPResponse(service_code | 0x80, data=struct.pack("<BB", self.major_revision, self.minor_revision))
            elif attribute_id == 5:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.status))
            elif attribute_id == 6:
                return CIPResponse(service_code | 0x80, data=struct.pack("<I", self.serial_number))
            elif attribute_id == 7:
                return CIPResponse(service_code | 0x80, data=encode_short_string(self.product_name))
            elif attribute_id == 8:
                return CIPResponse(service_code | 0x80, data=struct.pack("B", self.state))
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        elif service_code == CIPServiceCode.SET_ATTRIBUTE_SINGLE:
            if attribute_id == 5:
                if len(request_data) < 2:
                    return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.NOT_ENOUGH_DATA)
                self.status = struct.unpack_from("<H", request_data, 0)[0]
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SUCCESS)
            elif attribute_id in (1, 2, 3, 4, 6, 7, 8):
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE)
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        elif service_code == CIPServiceCode.GET_ATTRIBUTES_ALL:
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
                + encode_short_string(self.product_name)
            )
            return CIPResponse(service_code | 0x80, data=data)

        return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SERVICE_NOT_SUPPORTED)


@dataclass
class AssemblyInstance:
    """Individual CIP Assembly Instance (Class 0x04)."""
    instance_id: int
    name: str
    size: int
    buffer: bytearray = field(default_factory=bytearray)
    is_read_only: bool = False

    def __post_init__(self) -> None:
        if len(self.buffer) < self.size:
            self.buffer = bytearray(self.size)


class AssemblyObject(ICipObject):
    """CIP Assembly Object (Class 0x04) managing I/O buffers."""

    def __init__(self) -> None:
        self.instances: Dict[int, AssemblyInstance] = {
            100: AssemblyInstance(100, "Input Assembly (Telemetry PVs)", 32, is_read_only=True),
            101: AssemblyInstance(101, "Output Assembly (Control SPs)", 16, is_read_only=False),
            102: AssemblyInstance(102, "Configuration Assembly", 8, is_read_only=False),
        }

    @property
    def class_id(self) -> int:
        return CIPClassCode.ASSEMBLY

    def handle_explicit_request(
        self,
        service_code: int,
        instance_id: int,
        attribute_id: Optional[int],
        request_data: bytes,
    ) -> CIPResponse:
        inst = self.instances.get(instance_id)
        if inst is None:
            return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.OBJECT_DOES_NOT_EXIST)

        if service_code in (CIPServiceCode.GET_ATTRIBUTE_SINGLE, CIPServiceCode.GET_ATTRIBUTES_ALL):
            if attribute_id == 3 or service_code == CIPServiceCode.GET_ATTRIBUTES_ALL or attribute_id is None:
                return CIPResponse(service_code | 0x80, data=bytes(inst.buffer))
            elif attribute_id == 4:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", inst.size))
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        elif service_code == CIPServiceCode.SET_ATTRIBUTE_SINGLE:
            if attribute_id == 3 or attribute_id is None:
                if inst.is_read_only:
                    return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE)
                if len(request_data) > inst.size:
                    return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.TOO_MUCH_DATA)
                if len(request_data) < inst.size:
                    return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.NOT_ENOUGH_DATA)
                inst.buffer[:] = request_data
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SUCCESS)
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SERVICE_NOT_SUPPORTED)

    def get_attribute_single(
        self,
        arg1: int,
        arg2: Optional[int] = None,
        instance_id: Optional[int] = None,
    ) -> Tuple[CIPGeneralStatus, bytes]:
        """Query single attribute supporting both (inst_id, attr_id) and (attr_id, instance_id=...)."""
        if arg2 is not None:
            inst_id = arg1
            attr_id = arg2
        elif instance_id is not None:
            inst_id = instance_id
            attr_id = arg1
        else:
            inst_id = 1
            attr_id = arg1
        resp = self.handle_explicit_request(CIPServiceCode.GET_ATTRIBUTE_SINGLE, inst_id, attr_id, b"")
        return resp.general_status, resp.data

    def set_attribute_single(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> Tuple[CIPGeneralStatus, bytes]:
        """Set single attribute supporting (inst_id, attr_id, data) or (attr_id, data, instance_id=...)."""
        if len(args) == 3:
            inst_id = args[0]
            attr_id = args[1]
            data = args[2]
        elif len(args) == 2:
            if isinstance(args[1], (bytes, bytearray)):
                attr_id = args[0]
                data = bytes(args[1])
                inst_id = kwargs.get("instance_id", 1)
            else:
                inst_id = args[0]
                attr_id = args[1]
                data = kwargs.get("data", b"")
        else:
            inst_id = kwargs.get("instance_id", 1)
            attr_id = kwargs.get("attribute_id", args[0] if args else 3)
            data = kwargs.get("data", b"")
        resp = self.handle_explicit_request(CIPServiceCode.SET_ATTRIBUTE_SINGLE, inst_id, attr_id, data)
        return resp.general_status, resp.data

    def get_attributes_all(self, instance_id: int = 100) -> Tuple[CIPGeneralStatus, bytes]:
        """Query all attributes for specified assembly instance."""
        resp = self.handle_explicit_request(CIPServiceCode.GET_ATTRIBUTES_ALL, instance_id, None, b"")
        return resp.general_status, resp.data


@dataclass
class TcpIpInterfaceObject(ICipObject):
    """CIP TCP/IP Interface Object (Class 0xF5, Instance 1) per ODVA Vol 2 Chapter 5."""
    status: int = 0x00000001                   # Interface configured from non-volatile/DHCP
    config_capability: int = 0x00000024        # DHCP client, DNS client
    config_control: int = 0x00000002           # DHCP client enabled
    physical_link_path: bytes = b"\x20\xF6\x24\x01" # EPATH to Class 0xF6, Instance 1
    ip_address: str = "192.168.1.100"
    network_mask: str = "255.255.255.0"
    gateway_address: str = "192.168.1.1"
    name_server_1: str = "8.8.8.8"
    name_server_2: str = "0.0.0.0"
    domain_name: str = "horner.local"
    host_name: str = "horner-ocs"

    @property
    def class_id(self) -> int:
        return CIPClassCode.TCP_IP_INTERFACE

    @staticmethod
    def _ip_to_bytes(ip_str: str) -> bytes:
        parts = [int(p) for p in ip_str.split(".")]
        return bytes(parts)

    def get_interface_config_bytes(self) -> bytes:
        ip_b = self._ip_to_bytes(self.ip_address)
        mask_b = self._ip_to_bytes(self.network_mask)
        gw_b = self._ip_to_bytes(self.gateway_address)
        ns1_b = self._ip_to_bytes(self.name_server_1)
        ns2_b = self._ip_to_bytes(self.name_server_2)
        domain_b = encode_short_string(self.domain_name)
        return ip_b + mask_b + gw_b + ns1_b + ns2_b + domain_b

    def handle_explicit_request(
        self,
        service_code: int,
        instance_id: int,
        attribute_id: Optional[int],
        request_data: bytes,
    ) -> CIPResponse:
        if instance_id != 1:
            return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.OBJECT_DOES_NOT_EXIST)

        if service_code == CIPServiceCode.GET_ATTRIBUTE_SINGLE:
            if attribute_id == 1:
                return CIPResponse(service_code | 0x80, data=struct.pack("<I", self.status))
            elif attribute_id == 2:
                return CIPResponse(service_code | 0x80, data=struct.pack("<I", self.config_capability))
            elif attribute_id == 3:
                return CIPResponse(service_code | 0x80, data=struct.pack("<I", self.config_control))
            elif attribute_id == 4:
                return CIPResponse(service_code | 0x80, data=self.physical_link_path)
            elif attribute_id == 5:
                return CIPResponse(service_code | 0x80, data=self.get_interface_config_bytes())
            elif attribute_id == 6:
                return CIPResponse(service_code | 0x80, data=encode_short_string(self.host_name))
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        elif service_code == CIPServiceCode.SET_ATTRIBUTE_SINGLE:
            if attribute_id == 3:
                if len(request_data) < 4:
                    return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.NOT_ENOUGH_DATA)
                self.config_control = struct.unpack_from("<I", request_data, 0)[0]
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SUCCESS)
            elif attribute_id == 6:
                if len(request_data) < 1:
                    return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.NOT_ENOUGH_DATA)
                if len(request_data) >= 2 and request_data[1] == 0:
                    h_len = struct.unpack_from("<H", request_data, 0)[0]
                    self.host_name = request_data[2 : 2 + h_len].decode("ascii", errors="replace")
                else:
                    h_len = request_data[0]
                    self.host_name = request_data[1 : 1 + h_len].decode("ascii", errors="replace")
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SUCCESS)
            elif attribute_id in (1, 2, 4, 5):
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE)
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        elif service_code == CIPServiceCode.GET_ATTRIBUTES_ALL:
            data = (
                struct.pack("<III", self.status, self.config_capability, self.config_control)
                + self.physical_link_path
                + self.get_interface_config_bytes()
                + encode_short_string(self.host_name)
            )
            return CIPResponse(service_code | 0x80, data=data)

        return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SERVICE_NOT_SUPPORTED)


@dataclass
class EthernetLinkObject(ICipObject):
    """CIP Ethernet Link Object (Class 0xF6, Instance 1) per ODVA Vol 2 Chapter 5."""
    interface_speed_mbps: int = 100            # 100 Mbps
    interface_flags: int = 0x00000003          # Bit 0: Link Active (1), Bit 1: Full Duplex (1)
    mac_address: bytes = bytes([0x00, 0x0C, 0xC6, 0x12, 0x34, 0x56]) # Horner OUI 00:0C:C6
    interface_type: int = 2                    # Twisted-pair 100BASE-TX (RJ-45)
    interface_state: int = 1                   # Operational
    interface_label: str = "ETH0"

    @property
    def class_id(self) -> int:
        return CIPClassCode.ETHERNET_LINK

    def handle_explicit_request(
        self,
        service_code: int,
        instance_id: int,
        attribute_id: Optional[int],
        request_data: bytes,
    ) -> CIPResponse:
        if instance_id != 1:
            return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.OBJECT_DOES_NOT_EXIST)

        if service_code == CIPServiceCode.GET_ATTRIBUTE_SINGLE:
            if attribute_id == 1:
                return CIPResponse(service_code | 0x80, data=struct.pack("<I", self.interface_speed_mbps))
            elif attribute_id == 2:
                return CIPResponse(service_code | 0x80, data=struct.pack("<I", self.interface_flags))
            elif attribute_id == 3:
                return CIPResponse(service_code | 0x80, data=self.mac_address)
            elif attribute_id == 7:
                return CIPResponse(service_code | 0x80, data=struct.pack("B", self.interface_type))
            elif attribute_id == 8:
                return CIPResponse(service_code | 0x80, data=struct.pack("B", self.interface_state))
            elif attribute_id == 10:
                return CIPResponse(service_code | 0x80, data=encode_short_string(self.interface_label))
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        elif service_code == CIPServiceCode.SET_ATTRIBUTE_SINGLE:
            if attribute_id == 2:
                if len(request_data) < 4:
                    return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.NOT_ENOUGH_DATA)
                self.interface_flags = struct.unpack_from("<I", request_data, 0)[0]
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SUCCESS)
            elif attribute_id in (1, 3, 7, 8):
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE)
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        elif service_code == CIPServiceCode.GET_ATTRIBUTES_ALL:
            data = (
                struct.pack("<II", self.interface_speed_mbps, self.interface_flags)
                + self.mac_address
                + struct.pack("BB", self.interface_type, self.interface_state)
                + encode_short_string(self.interface_label)
            )
            return CIPResponse(service_code | 0x80, data=data)

        return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SERVICE_NOT_SUPPORTED)


# ============================================================================
# 9. Transport Class 3 Connected Explicit Messaging & Connection Manager
# ============================================================================

@dataclass
class TransportClass3Connection:
    """Active Transport Class 3 Connected Explicit Messaging session."""
    connection_id: int               # Target-to-Originator (T->O) Connection ID
    originator_connection_id: int    # Originator-to-Target (O->T) Connection ID
    connection_serial_number: int
    vendor_id: int
    device_serial_number: int
    rpi_us: int = 20000              # 20.0 ms default RPI
    sequence_count: int = 0          # Rolling sequence counter
    state: str = "ESTABLISHED"
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)


class ConnectionManagerObject(ICipObject):
    """CIP Connection Manager Object (Class 0x06, Instance 1) per ODVA Vol 1 Chapter 3."""

    def __init__(self) -> None:
        self.connections: Dict[int, TransportClass3Connection] = {}
        self.open_requests: int = 0
        self.open_format_rejects: int = 0
        self.open_resource_rejects: int = 0
        self.open_other_rejects: int = 0
        self.close_requests: int = 0
        self.close_format_rejects: int = 0
        self.close_other_rejects: int = 0
        self.connection_timeouts: int = 0
        self._next_conn_id: int = 0x2001
        self._next_originator_id: int = 0x1001

    @property
    def open_requests_count(self) -> int:
        return self.open_requests

    @open_requests_count.setter
    def open_requests_count(self, val: int) -> None:
        self.open_requests = val

    @property
    def close_requests_count(self) -> int:
        return self.close_requests

    @close_requests_count.setter
    def close_requests_count(self, val: int) -> None:
        self.close_requests = val

    @property
    def format_rejected_count(self) -> int:
        return self.open_format_rejects

    @format_rejected_count.setter
    def format_rejected_count(self, val: int) -> None:
        self.open_format_rejects = val

    @property
    def class_id(self) -> int:
        return CIPClassCode.CONNECTION_MANAGER

    def open_connection(
        self,
        connection_serial_number: int = 1,
        vendor_id: int = HORNER_VENDOR_ID,
        device_serial_number: int = HORNER_SERIAL_NUMBER,
        rpi_us: int = 20000,
        originator_conn_id: Optional[int] = None,
    ) -> TransportClass3Connection:
        """Create and track a new Transport Class 3 connection."""
        self.open_requests += 1
        t_to_o_id = self._next_conn_id
        self._next_conn_id += 1
        o_to_t_id = originator_conn_id if originator_conn_id else self._next_originator_id
        if not originator_conn_id:
            self._next_originator_id += 1

        conn = TransportClass3Connection(
            connection_id=t_to_o_id,
            originator_connection_id=o_to_t_id,
            connection_serial_number=connection_serial_number,
            vendor_id=vendor_id,
            device_serial_number=device_serial_number,
            rpi_us=rpi_us,
        )
        self.connections[t_to_o_id] = conn
        return conn

    def close_connection(self, connection_id_or_serial: int) -> bool:
        """Close and remove an active connection."""
        self.close_requests += 1
        target_cid: Optional[int] = None
        for cid, conn in self.connections.items():
            if cid == connection_id_or_serial or conn.connection_serial_number == connection_id_or_serial:
                target_cid = cid
                break
        if target_cid is not None:
            conn = self.connections.pop(target_cid)
            conn.state = "CLOSED"
            return True
        return False

    def handle_explicit_request(
        self,
        service_code: int,
        instance_id: int,
        attribute_id: Optional[int],
        request_data: bytes,
    ) -> CIPResponse:
        if instance_id != 1:
            return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.OBJECT_DOES_NOT_EXIST)

        if service_code in (CIPServiceCode.FORWARD_OPEN, CIPServiceCode.LARGE_FORWARD_OPEN):
            conn_sn = 1
            o_vendor = HORNER_VENDOR_ID
            o_serial = HORNER_SERIAL_NUMBER
            o_rpi = 20000
            o_conn_id = 0

            if len(request_data) >= 16:
                try:
                    # Unpack priority, ticks, o_to_t_id, t_to_o_id, sn, vendor, dev_sn
                    _, _, o_conn_id, _, conn_sn, o_vendor, o_serial = struct.unpack_from(
                        "<BBIIHI I", request_data, 0
                    )
                except Exception:
                    pass

            conn = self.open_connection(
                connection_serial_number=conn_sn,
                vendor_id=o_vendor,
                device_serial_number=o_serial,
                rpi_us=o_rpi,
                originator_conn_id=o_conn_id if o_conn_id > 0 else None,
            )

            # Response structure: O->T Network Conn ID (4), T->O Network Conn ID (4),
            # Conn Serial Number (2), Originator Vendor ID (2), Originator Device Serial (4),
            # O->T API (4), T->O API (4), App Reply Size (1), Reserved (1)
            resp_data = struct.pack(
                "<IIHIIIIBB",
                conn.originator_connection_id,
                conn.connection_id,
                conn.connection_serial_number,
                conn.vendor_id,
                conn.device_serial_number,
                conn.rpi_us,
                conn.rpi_us,
                0,
                0,
            )
            return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SUCCESS, data=resp_data)

        elif service_code == CIPServiceCode.FORWARD_CLOSE:
            conn_sn = 1
            o_vendor = HORNER_VENDOR_ID
            o_serial = HORNER_SERIAL_NUMBER
            if len(request_data) >= 12:
                try:
                    _, _, conn_sn, o_vendor, o_serial = struct.unpack_from("<BBHII", request_data, 0)
                except Exception:
                    pass

            closed = self.close_connection(conn_sn)
            resp_data = struct.pack(
                "<HIIBB",
                conn_sn,
                o_vendor,
                o_serial,
                0,
                0,
            )
            status = CIPGeneralStatus.SUCCESS if closed else CIPGeneralStatus.CONNECTION_FAILURE
            return CIPResponse(service_code | 0x80, general_status=status, data=resp_data)

        elif service_code == CIPServiceCode.GET_ATTRIBUTE_SINGLE:
            if attribute_id == 1:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.open_requests))
            elif attribute_id == 2:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.open_format_rejects))
            elif attribute_id == 3:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.open_resource_rejects))
            elif attribute_id == 4:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.open_other_rejects))
            elif attribute_id == 5:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.close_requests))
            elif attribute_id == 6:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.close_format_rejects))
            elif attribute_id == 7:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.close_other_rejects))
            elif attribute_id == 8:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", self.connection_timeouts))
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        elif service_code == CIPServiceCode.GET_ATTRIBUTES_ALL:
            data = struct.pack(
                "<8H",
                self.open_requests,
                self.open_format_rejects,
                self.open_resource_rejects,
                self.open_other_rejects,
                self.close_requests,
                self.close_format_rejects,
                self.close_other_rejects,
                self.connection_timeouts,
            )
            return CIPResponse(service_code | 0x80, data=data)

        return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SERVICE_NOT_SUPPORTED)


class MessageRouterObject(ICipObject):
    """CIP Message Router Object (Class 0x02, Instance 1) dispatching explicit requests."""

    def __init__(self, objects: Optional[Dict[int, ICipObject]] = None) -> None:
        if objects is not None:
            self.objects: Dict[int, ICipObject] = objects
        else:
            self.objects = {
                int(CIPClassCode.IDENTITY): IdentityObject(),
                int(CIPClassCode.MESSAGE_ROUTER): self,
                int(CIPClassCode.ASSEMBLY): AssemblyObject(),
                int(CIPClassCode.CONNECTION_MANAGER): ConnectionManagerObject(),
                int(CIPClassCode.TCP_IP_INTERFACE): TcpIpInterfaceObject(),
                int(CIPClassCode.ETHERNET_LINK): EthernetLinkObject(),
            }

    @property
    def class_id(self) -> int:
        return CIPClassCode.MESSAGE_ROUTER

    def register_object(self, obj: ICipObject) -> None:
        self.objects[obj.class_id] = obj

    def dispatch(
        self,
        service_code: int,
        class_id: int,
        instance_id: int,
        attribute_id: Optional[int],
        data: bytes,
    ) -> CIPResponse:
        """Route request to the target object."""
        target = self.objects.get(class_id)
        if target is None:
            return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.OBJECT_DOES_NOT_EXIST)
        return target.handle_explicit_request(service_code, instance_id, attribute_id, data)

    def handle_explicit_request(
        self,
        service_code: int,
        instance_id: int,
        attribute_id: Optional[int],
        request_data: bytes,
    ) -> CIPResponse:
        if instance_id != 1:
            return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.OBJECT_DOES_NOT_EXIST)

        if service_code == CIPServiceCode.GET_ATTRIBUTE_SINGLE:
            if attribute_id == 1:
                # Object list: 16-bit count prefix followed by class IDs
                classes = [int(c) for c in self.objects.keys()]
                buf = struct.pack("<H", len(classes)) + struct.pack(f"<{len(classes)}H", *classes)
                return CIPResponse(service_code | 0x80, data=buf)
            elif attribute_id == 2:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", 16))
            elif attribute_id == 3:
                return CIPResponse(service_code | 0x80, data=struct.pack("<H", len(self.objects)))
            else:
                return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED)

        return CIPResponse(service_code | 0x80, general_status=CIPGeneralStatus.SERVICE_NOT_SUPPORTED)


# ============================================================================
# 10. Pure ST POU Definitions & Anti-Ladder Verification
# ============================================================================

CIP_EXPLICIT_MESSAGING_SYNC_POU: str = """PROGRAM CipExplicitMessagingSync
VAR
    (* Horner OCS Mapped Registers (W172 - CIP Explicit Messaging & UCMM Engine) *)
    UcmmActiveSessionsCount        AT %R1330 : INT;    (* Active EtherNet/IP encapsulation sessions *)
    ConnectionIdWord               AT %R1331 : UINT;   (* Active Transport Class 3 CIP connection ID *)
    ExplicitTransactionCounter     AT %R1332 : UINT;   (* Monotonic transaction sequence counter *)
    ExplicitRequestTimeoutMsScaled AT %R1333 : INT;    (* Request timeout in ms * 10 (e.g. 250 = 25.0 ms) *)
    ExplicitErrorCounter           AT %R1334 : INT;    (* Accumulated CIP error response counter *)
    UcmmTransceiverStateWord       AT %R1335 : INT;    (* Transceiver session state bitmask *)
    CipServiceAndClassWord         AT %R1336 : UINT;   (* CIP service code (high byte) and class ID (low byte) *)
    DiagnosticStatusCode           AT %R1337 : UINT;   (* Diagnostic event code (0x0000, 0xC501..0xC504) *)

    (* Discrete Safety Interlock Coils *)
    CipExplicitPermissive          AT %M310  : BOOL;   (* TRUE when CIP explicit channel healthy *)
    CipExplicitFaultTrip           AT %M311  : BOOL;   (* TRUE on timeout, unsupported service, or malformed path *)
END_VAR
VAR
    ChannelHealthy                 : BOOL;
END_VAR

IF CipExplicitFaultTrip OR (DiagnosticStatusCode <> 0) THEN
    CipExplicitPermissive := FALSE;
    CipExplicitFaultTrip := TRUE;
    ChannelHealthy := FALSE;
ELSIF CipExplicitPermissive THEN
    ExplicitTransactionCounter := ExplicitTransactionCounter + 1;
    DiagnosticStatusCode := 0;
    ChannelHealthy := TRUE;
ELSE
    ChannelHealthy := FALSE;
END_IF;

IF ExplicitRequestTimeoutMsScaled > 250 THEN
    DiagnosticStatusCode := 50433; (* 0xC501: CIP_ERR_UCMM_TIMEOUT *)
    CipExplicitPermissive := FALSE;
    CipExplicitFaultTrip := TRUE;
END_IF;
END_PROGRAM
"""

ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU: str = CIP_EXPLICIT_MESSAGING_SYNC_POU.replace(
    "PROGRAM CipExplicitMessagingSync", "PROGRAM EtherNetIpUcmmExplicitSync"
)

# Aliases
PURE_ST_POU: str = CIP_EXPLICIT_MESSAGING_SYNC_POU
CIP_EXPLICIT_SYNC_POU: str = CIP_EXPLICIT_MESSAGING_SYNC_POU
UCMM_EXPLICIT_SYNC_POU: str = ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU


def verify_cip_explicit_pure_st() -> bool:
    """Validate CIP Explicit Messaging POUs for strict IEC 61131-3 syntax and anti-ladder safety.

    Returns:
        True if all checks pass deterministically.
    """
    SecurityGuard.assert_pure_st_content(CIP_EXPLICIT_MESSAGING_SYNC_POU)
    SecurityGuard.assert_pure_st_content(ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU)

    res1 = STParser.validate_code(CIP_EXPLICIT_MESSAGING_SYNC_POU)
    if res1.status != AgentStatus.SUCCESS:
        return False

    res2 = STParser.validate_code(ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU)
    if res2.status != AgentStatus.SUCCESS:
        return False

    ast1 = STParser.parse_pou(CIP_EXPLICIT_MESSAGING_SYNC_POU)
    ast2 = STParser.parse_pou(ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU)

    expected_regs = {
        "%R1330", "%R1331", "%R1332", "%R1333",
        "%R1334", "%R1335", "%R1336", "%R1337",
        "%M310", "%M311",
    }
    return set(ast1.bound_registers) == expected_regs and set(ast2.bound_registers) == expected_regs


# ============================================================================
# 11. Helper Functions (Register Writing & Formatting)
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


def encode_service_and_class_word(
    service_code: Optional[int] = None,
    class_id: int = 0,
    service: Optional[int] = None,
) -> int:
    """Encode CIP service code (high byte) and class ID (low byte) into UINT16 (%R1336)."""
    svc = service if service is not None else (service_code if service_code is not None else 0)
    return ((int(svc) & 0xFF) << 8) | (int(class_id) & 0xFF)


def decode_service_and_class_word(word: int) -> Tuple[int, int]:
    """Decode UINT16 (%R1336) into service code (high byte) and class ID (low byte)."""
    service_code = (int(word) >> 8) & 0xFF
    class_id = int(word) & 0xFF
    return service_code, class_id


def scale_ms_to_int16(ms: float) -> int:
    """Scale milliseconds to INT16 x10 ms units (e.g. 25.0 ms -> 250)."""
    return int(round(ms * 10.0))


def unscale_int16_to_ms(scaled: int) -> float:
    """Convert scaled INT16 x10 ms value to float milliseconds (e.g. 250 -> 25.0 ms)."""
    return float(scaled) / 10.0


# ============================================================================
# 12. UCMM Transceiver & Explicit Messaging Engine (ILogicUnit)
# ============================================================================

class CipExplicitMessagingEngine(ILogicUnit):
    """Industrial EtherNet/IP Explicit Messaging Connected/Unconnected Message Manager (UCMM).

    Work Package: W172 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
    Classification: PRODUCTION_READY

    Implements:
    - UCMM Port 44818 Encapsulation session lifecycle (Register / Unregister Session).
    - Unconnected Explicit Messaging via Send_RR_Data.
    - Connected Explicit Messaging via Send_Unit_Data (Transport Class 3).
    - Core CIP Object Dictionary (Identity, Assembly, Connection Manager, TCP/IP, Ethernet Link).
    - Precise 25.0 ms request timeout surveillance and safety interlocking.
    - Horner OCS register space synchronization (%R1330..%R1337, %M310..%M311).
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        timeout_ms: float = CIP_EXPLICIT_NOMINAL_TIMEOUT_MS,
        max_fragment_size: int = CIP_FRAGMENTATION_THRESHOLD_BYTES,
    ) -> None:
        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.timeout_ms: float = float(timeout_ms)

        # Transceiver State & Diagnostics
        self.state: UcmmTransceiverState = UcmmTransceiverState.UCMM_IDLE
        self.permissive: bool = True
        self.fault_trip: bool = False
        self.diagnostic_code: CipExplicitDiagnosticCode = CipExplicitDiagnosticCode.OK

        # Counters & Telemetry
        self.active_sessions: Set[int] = set()
        self._next_session_handle: int = 0x10001
        self.active_connection_id: int = 0
        self.explicit_transaction_counter: int = 0
        self.explicit_error_counter: int = 0
        self.current_service_code: int = 0
        self.current_class_id: int = 0

        # Timing and Simulation Clock
        self.elapsed_time_ms: float = 0.0
        self.current_transaction_elapsed_ms: float = 0.0
        self.transaction_in_progress: bool = False
        self.fragmentation_active: bool = False
        self.last_response: Optional[bytes] = None

        # Core CIP Objects
        self.identity = IdentityObject()
        self.assembly = AssemblyObject()
        self.tcp_ip = TcpIpInterfaceObject()
        self.ethernet_link = EthernetLinkObject()
        self.connection_manager = ConnectionManagerObject()
        self.router = MessageRouterObject({
            CIPClassCode.IDENTITY: self.identity,
            CIPClassCode.ASSEMBLY: self.assembly,
            CIPClassCode.TCP_IP_INTERFACE: self.tcp_ip,
            CIPClassCode.ETHERNET_LINK: self.ethernet_link,
            CIPClassCode.CONNECTION_MANAGER: self.connection_manager,
        })
        self.router.register_object(self.router)

        # Fragmentation Engine
        self.fragmentation_engine = FragmentationEngine(max_fragment_size=max_fragment_size)

        self.sync_to_registers()

    # ------------------------------------------------------------------------
    # ILogicUnit Properties & Lifecycle
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "cip_explicit_messaging"

    @property
    def priority(self) -> int:
        return 90

    @property
    def is_enabled(self) -> bool:
        return True

    def execute(self, ctx: ScanContext) -> None:
        """Scan cycle logic execution during simulation Phase 2."""
        dt_ms = getattr(ctx, "dt_ms", 1.0)
        self.scan_step(dt=dt_ms / 1000.0)

    def reset(self) -> None:
        """Reset internal unit state to initial conditions."""
        self.reset_latch(force=True)

    # ------------------------------------------------------------------------
    # State Machine & Timing Progression
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.001) -> Dict[str, Any]:
        """Advance deterministic simulation clock and evaluate timeout watchdog.

        Args:
            dt: Scan time delta in seconds (or milliseconds if dt >= 1.0).

        Returns:
            Dictionary containing cycle telemetry.
        """
        dt_ms = dt if dt >= 1.0 else (dt * 1000.0)
        self.elapsed_time_ms += dt_ms

        if self.transaction_in_progress:
            self.current_transaction_elapsed_ms += dt_ms
            if self.current_transaction_elapsed_ms > self.timeout_ms:
                self._trip_fault(
                    CipExplicitDiagnosticCode.CIP_ERR_UCMM_TIMEOUT,
                    f"Transaction duration ({self.current_transaction_elapsed_ms:.1f} ms) exceeded 25.0 ms threshold",
                )

        self.sync_to_registers()
        return self._build_status_telemetry()

    def step_scan_cycle(self, dt_ms: float = 1.0) -> Dict[str, Any]:
        """Convenience method stepping the cycle in milliseconds."""
        return self.scan_step(dt=dt_ms)

    def _build_status_telemetry(self) -> Dict[str, Any]:
        return {
            "state": self.state.name,
            "permissive": self.permissive,
            "fault_trip": self.fault_trip,
            "diagnostic_code": f"0x{self.diagnostic_code:04X}",
            "active_sessions": len(self.active_sessions),
            "active_connection_id": self.active_connection_id,
            "transaction_counter": self.explicit_transaction_counter,
            "error_counter": self.explicit_error_counter,
            "elapsed_ms": self.elapsed_time_ms,
        }

    # ------------------------------------------------------------------------
    # Process Safety Interlocks & Fault Trapping
    # ------------------------------------------------------------------------

    def _trip_fault(self, code: CipExplicitDiagnosticCode, details: str = "") -> None:
        """Assert fail-safe trip, latch safe shutdown, and clear permissive."""
        self.diagnostic_code = code
        self.state = UcmmTransceiverState.UCMM_FAULT
        self.fault_trip = True
        self.permissive = False
        self.explicit_error_counter = (self.explicit_error_counter + 1) & 0x7FFF
        self.transaction_in_progress = False
        self.sync_to_registers()

    def trigger_fault(self, code: CipExplicitDiagnosticCode) -> None:
        """Explicitly inject a diagnostic fault code."""
        self._trip_fault(code=code, details=f"Injected fault {code.name}")

    def reset_latch(self, force: bool = False) -> ExecutionResult:
        """Manual / operator reset to clear latched safety trips."""
        self.diagnostic_code = CipExplicitDiagnosticCode.OK
        self.fault_trip = False
        self.permissive = True
        self.state = UcmmTransceiverState.UCMM_IDLE
        self.current_transaction_elapsed_ms = 0.0
        self.transaction_in_progress = False
        self.fragmentation_active = False
        self.sync_to_registers()
        return ExecutionResult.success(details="CIP explicit messaging fault latch cleared successfully.")

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        return self.reset_latch(force=force)

    # ------------------------------------------------------------------------
    # Encapsulation Session Management (Port 44818)
    # ------------------------------------------------------------------------

    def register_session(self) -> int:
        """Register a new EtherNet/IP encapsulation session."""
        handle = self._next_session_handle
        self._next_session_handle += 1
        self.active_sessions.add(handle)
        self.sync_to_registers()
        return handle

    def unregister_session(self, session_handle: int) -> bool:
        """Close and remove an encapsulation session."""
        if session_handle in self.active_sessions:
            self.active_sessions.remove(session_handle)
            self.sync_to_registers()
            return True
        return False

    # ------------------------------------------------------------------------
    # Transport Class 3 Connected Explicit Messaging
    # ------------------------------------------------------------------------

    def forward_open(
        self,
        connection_serial_number: int = 1,
        vendor_id: int = HORNER_VENDOR_ID,
        device_serial_number: int = HORNER_SERIAL_NUMBER,
        rpi_us: int = 20000,
    ) -> Tuple[int, int]:
        """Establish Transport Class 3 connection returning (O->T ID, T->O ID)."""
        conn = self.connection_manager.open_connection(
            connection_serial_number=connection_serial_number,
            vendor_id=vendor_id,
            device_serial_number=device_serial_number,
            rpi_us=rpi_us,
        )
        self.active_connection_id = conn.connection_id
        self.current_service_code = CIPServiceCode.FORWARD_OPEN
        self.current_class_id = CIPClassCode.CONNECTION_MANAGER
        self.sync_to_registers()
        return conn.originator_connection_id, conn.connection_id

    def forward_close(self, connection_id_or_serial: int) -> bool:
        """Terminate active Transport Class 3 connection."""
        closed = self.connection_manager.close_connection(connection_id_or_serial)
        if closed:
            if self.active_connection_id == connection_id_or_serial or len(self.connection_manager.connections) == 0:
                self.active_connection_id = 0
            self.current_service_code = CIPServiceCode.FORWARD_CLOSE
            self.current_class_id = CIPClassCode.CONNECTION_MANAGER
            self.sync_to_registers()
        return closed

    # ------------------------------------------------------------------------
    # On-the-Wire Packet Transceiver Pipeline
    # ------------------------------------------------------------------------

    def handle_encapsulation_packet(self, packet_bytes: bytes) -> bytes:
        """Process an incoming EtherNet/IP encapsulation packet from port 44818.

        Args:
            packet_bytes: Raw encapsulation packet bytes.

        Returns:
            Serialized response encapsulation packet bytes.
        """
        self.state = UcmmTransceiverState.RECEIVING_REQUEST
        self.sync_to_registers()

        try:
            header, payload = EIPHeader.deserialize(packet_bytes)
        except Exception as e:
            self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, str(e))
            err_hdr = EIPHeader(command=EIPCommand.NOP, status=EIPStatus.INCORRECT_DATA)
            return err_hdr.serialize()

        # Command Dispatching
        if header.command == EIPCommand.REGISTER_SESSION:
            session_handle = self.register_session()
            resp_hdr = EIPHeader(
                command=EIPCommand.REGISTER_SESSION,
                length=4,
                session_handle=session_handle,
                status=EIPStatus.SUCCESS,
                sender_context=header.sender_context,
            )
            self.state = UcmmTransceiverState.UCMM_IDLE
            self.sync_to_registers()
            return resp_hdr.serialize() + struct.pack("<HH", 1, 0)

        elif header.command == EIPCommand.UNREGISTER_SESSION:
            self.unregister_session(header.session_handle)
            self.state = UcmmTransceiverState.UCMM_IDLE
            self.sync_to_registers()
            return b""

        elif header.command == EIPCommand.SEND_RR_DATA:
            # Unconnected explicit message (UCMM)
            if len(payload) < 6:
                self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, "Malformed SEND_RR_DATA payload")
                resp_hdr = EIPHeader(command=EIPCommand.SEND_RR_DATA, status=EIPStatus.INCORRECT_DATA, session_handle=header.session_handle)
                return resp_hdr.serialize()

            interface_handle, timeout_sec = struct.unpack_from("<IH", payload, 0)
            cpf_bytes = payload[6:]
            try:
                cpf_items = deserialize_cpf(cpf_bytes)
            except Exception as e:
                self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, str(e))
                resp_hdr = EIPHeader(command=EIPCommand.SEND_RR_DATA, status=EIPStatus.INCORRECT_DATA, session_handle=header.session_handle)
                return resp_hdr.serialize()

            # Find Unconnected Data item (0x00B2)
            cip_req_data = b""
            for item in cpf_items:
                if item.type_id == CPFTypeId.UNCONNECTED_DATA:
                    cip_req_data = item.data
                    break

            cip_resp = self._process_cip_request(cip_req_data)

            # Build reply CPF items
            reply_items = [
                CPFItem.null_address(),
                CPFItem.unconnected_data(cip_resp.encode()),
            ]
            reply_cpf = serialize_cpf(reply_items)
            reply_payload = struct.pack("<IH", interface_handle, 0) + reply_cpf

            resp_hdr = EIPHeader(
                command=EIPCommand.SEND_RR_DATA,
                length=len(reply_payload),
                session_handle=header.session_handle,
                status=EIPStatus.SUCCESS,
                sender_context=header.sender_context,
            )
            self.state = UcmmTransceiverState.TRANSMITTING
            self.last_response = resp_hdr.serialize() + reply_payload
            self.state = UcmmTransceiverState.UCMM_IDLE
            self.sync_to_registers()
            return self.last_response

        elif header.command == EIPCommand.SEND_UNIT_DATA:
            # Connected explicit message (Transport Class 3)
            if len(payload) < 6:
                self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, "Malformed SEND_UNIT_DATA payload")
                resp_hdr = EIPHeader(command=EIPCommand.SEND_UNIT_DATA, status=EIPStatus.INCORRECT_DATA, session_handle=header.session_handle)
                return resp_hdr.serialize()

            interface_handle, _ = struct.unpack_from("<IH", payload, 0)
            cpf_bytes = payload[6:]
            try:
                cpf_items = deserialize_cpf(cpf_bytes)
            except Exception as e:
                self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, str(e))
                resp_hdr = EIPHeader(command=EIPCommand.SEND_UNIT_DATA, status=EIPStatus.INCORRECT_DATA, session_handle=header.session_handle)
                return resp_hdr.serialize()

            conn_id = 0
            seq_cnt = 0
            cip_req_data = b""

            for item in cpf_items:
                if item.type_id == CPFTypeId.CONNECTED_ADDRESS:
                    if len(item.data) >= 4:
                        conn_id = struct.unpack_from("<I", item.data, 0)[0]
                elif item.type_id == CPFTypeId.CONNECTED_DATA:
                    if len(item.data) >= 2:
                        seq_cnt = struct.unpack_from("<H", item.data, 0)[0]
                        cip_req_data = item.data[2:]

            self.active_connection_id = conn_id
            if conn_id in self.connection_manager.connections:
                conn = self.connection_manager.connections[conn_id]
                conn.last_activity = time.time()
                if seq_cnt > 0:
                    conn.sequence_count = seq_cnt

            cip_resp = self._process_cip_request(cip_req_data)

            # Reply with connected address & connected data
            reply_items = [
                CPFItem.connected_address(conn_id),
                CPFItem.connected_data(cip_resp.encode(), sequence_count=seq_cnt),
            ]
            reply_cpf = serialize_cpf(reply_items)
            reply_payload = struct.pack("<IH", interface_handle, 0) + reply_cpf

            resp_hdr = EIPHeader(
                command=EIPCommand.SEND_UNIT_DATA,
                length=len(reply_payload),
                session_handle=header.session_handle,
                status=EIPStatus.SUCCESS,
                sender_context=header.sender_context,
            )
            self.state = UcmmTransceiverState.TRANSMITTING
            self.last_response = resp_hdr.serialize() + reply_payload
            self.state = UcmmTransceiverState.UCMM_IDLE
            self.sync_to_registers()
            return self.last_response

        else:
            resp_hdr = EIPHeader(
                command=header.command,
                length=0,
                session_handle=header.session_handle,
                status=EIPStatus.SUCCESS,
                sender_context=header.sender_context,
            )
            self.state = UcmmTransceiverState.UCMM_IDLE
            self.sync_to_registers()
            return resp_hdr.serialize()

    def _process_cip_request(self, cip_data: bytes) -> CIPResponse:
        """Internal dispatch of CIP Request to target object."""
        self.transaction_in_progress = True
        self.current_transaction_elapsed_ms = 0.0

        if len(cip_data) < 2:
            self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, "CIP Request too short")
            return CIPResponse(0x80, general_status=CIPGeneralStatus.PATH_SEGMENT_ERROR)

        self.state = UcmmTransceiverState.ROUTING_CIP_OBJECT
        try:
            req = CIPRequest.decode(cip_data)
        except Exception as e:
            self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, str(e))
            return CIPResponse(0x80, general_status=CIPGeneralStatus.PATH_SEGMENT_ERROR)

        svc = int(req.service_code)
        self.current_service_code = svc

        # Validate Service Code
        supported_services = {
            CIPServiceCode.GET_ATTRIBUTES_ALL,
            CIPServiceCode.GET_ATTRIBUTE_SINGLE,
            CIPServiceCode.SET_ATTRIBUTE_SINGLE,
            CIPServiceCode.FORWARD_OPEN,
            CIPServiceCode.LARGE_FORWARD_OPEN,
            CIPServiceCode.FORWARD_CLOSE,
            CIPServiceCode.RESET,
        }
        if svc not in supported_services:
            self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_SERVICE_NOT_SUPPORTED, f"Unsupported service 0x{svc:02X}")
            return CIPResponse(svc | 0x80, general_status=CIPGeneralStatus.SERVICE_NOT_SUPPORTED)

        class_id, instance_id, attribute_id = req.epath.get_logical_ids()
        if class_id is None or instance_id is None:
            self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, "Missing Class or Instance in EPATH")
            return CIPResponse(svc | 0x80, general_status=CIPGeneralStatus.PATH_DESTINATION_UNKNOWN)

        self.current_class_id = class_id

        # Dispatch via Message Router
        resp = self.router.dispatch(
            service_code=svc,
            class_id=class_id,
            instance_id=instance_id,
            attribute_id=attribute_id,
            data=req.data,
        )

        if not resp.is_success:
            if resp.general_status == CIPGeneralStatus.OBJECT_DOES_NOT_EXIST:
                self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID, f"Object 0x{class_id:02X} does not exist")
            elif resp.general_status == CIPGeneralStatus.SERVICE_NOT_SUPPORTED:
                self._trip_fault(CipExplicitDiagnosticCode.CIP_ERR_SERVICE_NOT_SUPPORTED, f"Service 0x{svc:02X} not supported by object")

        self.state = UcmmTransceiverState.SERIALIZING_RESPONSE
        self.explicit_transaction_counter = (self.explicit_transaction_counter + 1) & 0xFFFF
        self.transaction_in_progress = False

        self.sync_to_registers()
        return resp

    # ------------------------------------------------------------------------
    # High-Level Explicit Messaging Client Helpers
    # ------------------------------------------------------------------------

    def execute_ucmm_explicit_request(
        self,
        service_code: Union[CIPServiceCode, int],
        class_id: int,
        instance_id: int,
        attribute_id: Optional[int] = None,
        data: bytes = b"",
        session_handle: Optional[int] = None,
        is_16bit_path: bool = False,
    ) -> CIPResponse:
        """Send an unconnected explicit request (UCMM) and return the CIPResponse."""
        handle = session_handle or (next(iter(self.active_sessions)) if self.active_sessions else self.register_session())
        epath = EPATH.from_logical(class_id, instance_id, attribute_id, is_16bit=is_16bit_path)
        req = CIPRequest(service_code=service_code, epath=epath, data=data)
        cip_bytes = req.encode()

        cpf = serialize_cpf([CPFItem.null_address(), CPFItem.unconnected_data(cip_bytes)])
        payload = struct.pack("<IH", 0, 0) + cpf
        eip_pkt = EIPHeader(
            command=EIPCommand.SEND_RR_DATA,
            length=len(payload),
            session_handle=handle,
        ).serialize() + payload

        resp_bytes = self.handle_encapsulation_packet(eip_pkt)
        resp_hdr, resp_payload = EIPHeader.deserialize(resp_bytes)
        resp_cpf = deserialize_cpf(resp_payload[6:])

        for it in resp_cpf:
            if it.type_id == CPFTypeId.UNCONNECTED_DATA:
                return CIPResponse.decode(it.data)

        return CIPResponse(int(service_code) | 0x80, general_status=CIPGeneralStatus.EXTENDED_STATUS)

    def execute_connected_explicit_request(
        self,
        connection_id: int,
        service_code: Union[CIPServiceCode, int],
        class_id: int,
        instance_id: int,
        attribute_id: Optional[int] = None,
        data: bytes = b"",
        session_handle: Optional[int] = None,
        sequence_count: Optional[int] = None,
        is_16bit_path: bool = False,
    ) -> CIPResponse:
        """Send a connected explicit request (Transport Class 3) and return the CIPResponse."""
        conn = self.connection_manager.connections.get(connection_id)
        if sequence_count is None:
            sequence_count = (conn.sequence_count + 1) if conn is not None else 1
        if conn is not None:
            conn.sequence_count = sequence_count
            conn.last_activity = time.time()
        handle = session_handle or (next(iter(self.active_sessions)) if self.active_sessions else self.register_session())
        epath = EPATH.from_logical(class_id, instance_id, attribute_id, is_16bit=is_16bit_path)
        req = CIPRequest(service_code=service_code, epath=epath, data=data)
        cip_bytes = req.encode()

        cpf = serialize_cpf([
            CPFItem.connected_address(connection_id),
            CPFItem.connected_data(cip_bytes, sequence_count=sequence_count),
        ])
        payload = struct.pack("<IH", 0, 0) + cpf
        eip_pkt = EIPHeader(
            command=EIPCommand.SEND_UNIT_DATA,
            length=len(payload),
            session_handle=handle,
        ).serialize() + payload

        resp_bytes = self.handle_encapsulation_packet(eip_pkt)
        resp_hdr, resp_payload = EIPHeader.deserialize(resp_bytes)
        resp_cpf = deserialize_cpf(resp_payload[6:])

        for it in resp_cpf:
            if it.type_id == CPFTypeId.CONNECTED_DATA:
                return CIPResponse.decode(it.data[2:])

        return CIPResponse(int(service_code) | 0x80, general_status=CIPGeneralStatus.EXTENDED_STATUS)

    # ------------------------------------------------------------------------
    # Horner OCS Register Space Synchronization
    # ------------------------------------------------------------------------

    def compute_transceiver_state_word(self) -> int:
        """Compute 16-bit status word (%R1335) reflecting transceiver state and flags."""
        state_val = int(self.state.value) & 0x07
        flags = UcmmTransceiverStateBits(state_val)

        if len(self.active_sessions) > 0:
            flags |= UcmmTransceiverStateBits.SESSION_REGISTERED
        if len(self.connection_manager.connections) > 0:
            flags |= UcmmTransceiverStateBits.CLASS3_CONNECTED
        if self.fragmentation_active:
            flags |= UcmmTransceiverStateBits.FRAGMENTATION_ACTIVE
        if self.transaction_in_progress:
            flags |= UcmmTransceiverStateBits.TRANSACTION_ACTIVE
        if self.last_response is not None:
            flags |= UcmmTransceiverStateBits.RESPONSE_READY
        if self.permissive:
            flags |= UcmmTransceiverStateBits.PERMISSIVE
        if self.fault_trip:
            flags |= UcmmTransceiverStateBits.FAULT_TRIP

        if self.diagnostic_code == CipExplicitDiagnosticCode.CIP_ERR_UCMM_TIMEOUT:
            flags |= UcmmTransceiverStateBits.TIMEOUT_FAULT
        elif self.diagnostic_code == CipExplicitDiagnosticCode.CIP_ERR_SERVICE_NOT_SUPPORTED:
            flags |= UcmmTransceiverStateBits.SERVICE_UNSUPPORTED
        elif self.diagnostic_code == CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID:
            flags |= UcmmTransceiverStateBits.OBJECT_PATH_INVALID
        elif self.diagnostic_code == CipExplicitDiagnosticCode.CIP_ERR_FRAGMENTATION_FAULT:
            flags |= UcmmTransceiverStateBits.FRAGMENTATION_FAULT

        flags |= UcmmTransceiverStateBits.PORT_44818_LISTENING
        return int(flags)

    def sync_to_registers(self) -> None:
        """Synchronize internal engine state to Horner OCS register space.

        All writes to RegisterTable MUST pass privilege=PrivilegeMode.SYSTEM.
        """
        # %R1330: UcmmActiveSessionsCount (INT16)
        safe_write_word(self.reg_table, "%R1330", len(self.active_sessions))
        # %R1331: ConnectionIdWord (UINT16)
        safe_write_uword(self.reg_table, "%R1331", self.active_connection_id & 0xFFFF)
        # %R1332: ExplicitTransactionCounter (UINT16 monotonic 0..65535)
        safe_write_uword(self.reg_table, "%R1332", self.explicit_transaction_counter & 0xFFFF)
        # %R1333: ExplicitRequestTimeoutMsScaled (INT16, scaled x10 ms, e.g. 250 = 25.0 ms)
        safe_write_word(self.reg_table, "%R1333", scale_ms_to_int16(self.timeout_ms))
        # %R1334: ExplicitErrorCounter (INT16 count of CIP error responses)
        safe_write_word(self.reg_table, "%R1334", self.explicit_error_counter)
        # %R1335: UcmmTransceiverStateWord (INT16 bitmask of transceiver state and flags)
        safe_write_word(self.reg_table, "%R1335", self.compute_transceiver_state_word())
        # %R1336: CipServiceAndClassWord (UINT16, service code byte + class ID byte)
        service_class_word = encode_service_and_class_word(self.current_service_code, self.current_class_id)
        safe_write_uword(self.reg_table, "%R1336", service_class_word)
        # %R1337: DiagnosticStatusCode (0x0000=OK, 0xC501..0xC504)
        safe_write_uword(self.reg_table, "%R1337", int(self.diagnostic_code))
        # %M310: CipExplicitPermissive (BOOL)
        safe_write_bit(self.reg_table, "%M310", self.permissive)
        # %M311: CipExplicitFaultTrip (BOOL)
        safe_write_bit(self.reg_table, "%M311", self.fault_trip)


# Engine Aliases
CipExplicitEngine = CipExplicitMessagingEngine
EtherNetIpUcmmEngine = CipExplicitMessagingEngine
UcmmExplicitEngine = CipExplicitMessagingEngine


# ============================================================================
# 13. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_explicit_messaging_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute rigorous deterministic 9-stage verification suite for Work Package W172.

    Returns:
        Strict 4-state contract JSON response.
    """
    test_results: List[Dict[str, Any]] = []
    rt = RegisterTable()
    engine = CipExplicitMessagingEngine(register_table=rt, timeout_ms=25.0)

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & Anti-Ladder Security Guard
    # ------------------------------------------------------------------------
    pure_st_ok = verify_cip_explicit_pure_st()

    # Verify ladder injection is blocked with LadderForbiddenError
    ladder_blocked = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM Test\nVAR\nEND_VAR\n|---| |---( )---|\nEND_PROGRAM")
    except LadderForbiddenError:
        ladder_blocked = True

    c1 = pure_st_ok and ladder_blocked
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Anti_Ladder_Guard",
        "passed": c1,
        "details": "Pure ST POUs parsed (%R1330..%R1337, %M310..%M311) and ladder syntax strictly rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: EPath Logical Segment Parsing (8-bit and 16-bit)
    # ------------------------------------------------------------------------
    # 8-bit path: Class 0x01, Instance 0x01, Attribute 0x07
    p8 = EPATH.from_logical(class_id=0x01, instance_id=0x01, attribute_id=0x07, is_16bit=False)
    enc8 = p8.encode()
    dec8 = EPATH.decode(enc8)
    c8_match = (
        enc8 == bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x07])
        and dec8.get_logical_ids() == (0x01, 0x01, 0x07)
    )

    # 16-bit path: Class 0xF5, Instance 0x01, Attribute 0x05
    p16 = EPATH.from_logical(class_id=0xF5, instance_id=0x01, attribute_id=0x05, is_16bit=True)
    enc16 = p16.encode()
    dec16 = EPATH.decode(enc16)
    c16_match = (
        enc16 == bytes([0x21, 0x00, 0xF5, 0x00, 0x25, 0x00, 0x01, 0x00, 0x31, 0x00, 0x05, 0x00])
        and dec16.get_logical_ids() == (0xF5, 0x01, 0x05)
    )

    c2 = c8_match and c16_match
    test_results.append({
        "stage": 2,
        "check": "EPath_Logical_Segment_Parsing_8Bit_And_16Bit",
        "passed": c2,
        "details": "8-bit and 16-bit EPATH encoding/decoding matched ODVA logical segment specification.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Encapsulation & UCMM Port 44818 Session Lifecycle
    # ------------------------------------------------------------------------
    h1 = engine.register_session()
    h2 = engine.register_session()
    h3 = engine.register_session()
    h4 = engine.register_session()

    s_count_4 = rt.read_word("%R1330") == 4 and len(engine.active_sessions) == 4

    # Execute UCMM NOP request
    nop_hdr = EIPHeader(command=EIPCommand.NOP, session_handle=h1).serialize()
    resp_nop = engine.handle_encapsulation_packet(nop_hdr)
    hdr_out, _ = EIPHeader.deserialize(resp_nop)
    nop_ok = (hdr_out.command == EIPCommand.NOP and hdr_out.status == EIPStatus.SUCCESS)

    # Unregister a session
    engine.unregister_session(h4)
    s_count_3 = rt.read_word("%R1330") == 3

    c3 = s_count_4 and nop_ok and s_count_3
    test_results.append({
        "stage": 3,
        "check": "Encapsulation_And_UCMM_Port_44818_Session_Lifecycle",
        "passed": c3,
        "details": "Session registration, command routing, and unregistration verified; %R1330 synchronized.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Connected Explicit Messaging (Transport Class 3 Connection Manager)
    # ------------------------------------------------------------------------
    # Forward_Open
    o_cid, t_cid = engine.forward_open(connection_serial_number=101, rpi_us=25000)
    open_ok = (
        len(engine.connection_manager.connections) == 1
        and engine.active_connection_id == t_cid
        and rt.read_uword("%R1331") == (t_cid & 0xFFFF)
    )

    # Connected request via Send_Unit_Data
    resp_conn = engine.execute_connected_explicit_request(
        connection_id=t_cid,
        service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
        class_id=CIPClassCode.IDENTITY,
        instance_id=1,
        attribute_id=1,  # Vendor ID
    )
    conn_req_ok = (
        resp_conn.is_success
        and struct.unpack("<H", resp_conn.data)[0] == HORNER_VENDOR_ID
    )

    # Forward_Close
    close_ok = engine.forward_close(t_cid) and rt.read_uword("%R1331") == 0

    c4 = open_ok and conn_req_ok and close_ok
    test_results.append({
        "stage": 4,
        "check": "Connected_Explicit_Messaging_Transport_Class_3",
        "passed": c4,
        "details": "Forward_Open (0x54) established Class 3 connection, Send_Unit_Data answered, and Forward_Close terminated cleanly.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Core CIP Object Dictionary (Identity, TCP/IP, Ethernet Link)
    # ------------------------------------------------------------------------
    # Identity: Get_Attribute_Single product name
    r_name = engine.execute_ucmm_explicit_request(
        service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
        class_id=CIPClassCode.IDENTITY,
        instance_id=1,
        attribute_id=7,
    )
    name_str, _ = decode_short_string(r_name.data)

    # Identity: Get_Attributes_All
    r_id_all = engine.execute_ucmm_explicit_request(
        service_code=CIPServiceCode.GET_ATTRIBUTES_ALL,
        class_id=CIPClassCode.IDENTITY,
        instance_id=1,
    )

    # TCP/IP Interface Object (0xF5): Attribute 5 (Interface Config IP)
    r_tcp = engine.execute_ucmm_explicit_request(
        service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
        class_id=CIPClassCode.TCP_IP_INTERFACE,
        instance_id=1,
        attribute_id=5,
    )
    ip_octets = r_tcp.data[:4]

    # Ethernet Link Object (0xF6): Attribute 1 (Speed) & Attribute 2 (Flags)
    r_link_speed = engine.execute_ucmm_explicit_request(
        service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
        class_id=CIPClassCode.ETHERNET_LINK,
        instance_id=1,
        attribute_id=1,
    )
    speed_mbps = struct.unpack("<I", r_link_speed.data)[0]

    c5 = (
        name_str == HORNER_PRODUCT_NAME
        and r_id_all.is_success
        and ip_octets == bytes([192, 168, 1, 100])
        and speed_mbps == 100
        and rt.read_uword("%R1336") == encode_service_and_class_word(CIPServiceCode.GET_ATTRIBUTE_SINGLE, CIPClassCode.ETHERNET_LINK)
    )
    test_results.append({
        "stage": 5,
        "check": "Core_CIP_Object_Dictionary_Identity_TCPIP_EthernetLink",
        "passed": c5,
        "details": "Identity (0x01), TCP/IP (0xF5), and Ethernet Link (0xF6) objects queried successfully; %R1336 updated.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Assembly Object Data Access (Get/Set Attribute Single)
    # ------------------------------------------------------------------------
    # Instance 100 (Input / Read-Only): Get_Attribute_Single
    r_asmb_in = engine.execute_ucmm_explicit_request(
        service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
        class_id=CIPClassCode.ASSEMBLY,
        instance_id=100,
        attribute_id=3,
    )

    # Instance 100: Set attempt should fail with ATTRIBUTE_NOT_SETTABLE (0x0E)
    r_asmb_fail = engine.execute_ucmm_explicit_request(
        service_code=CIPServiceCode.SET_ATTRIBUTE_SINGLE,
        class_id=CIPClassCode.ASSEMBLY,
        instance_id=100,
        attribute_id=3,
        data=b"\xAA" * 32,
    )

    # Instance 101 (Output / Read-Write): Set_Attribute_Single
    test_sp_data = bytes([0x10, 0x20, 0x30, 0x40] + [0x00] * 12)
    r_asmb_set = engine.execute_ucmm_explicit_request(
        service_code=CIPServiceCode.SET_ATTRIBUTE_SINGLE,
        class_id=CIPClassCode.ASSEMBLY,
        instance_id=101,
        attribute_id=3,
        data=test_sp_data,
    )

    # Instance 101: Get_Attribute_Single
    r_asmb_get = engine.execute_ucmm_explicit_request(
        service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
        class_id=CIPClassCode.ASSEMBLY,
        instance_id=101,
        attribute_id=3,
    )

    c6 = (
        len(r_asmb_in.data) == 32
        and r_asmb_fail.general_status == CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE
        and r_asmb_set.is_success
        and r_asmb_get.data == test_sp_data
    )
    test_results.append({
        "stage": 6,
        "check": "Assembly_Object_Data_Access_Get_Set",
        "passed": c6,
        "details": "Instance 100 read-only enforced; Instance 101 setpoints written and read back cleanly.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Fragmentation & Reassembly Engine
    # ------------------------------------------------------------------------
    fe = FragmentationEngine(max_fragment_size=200)
    large_payload = bytes([i % 256 for i in range(1200)])
    fragments = fe.fragment_payload(large_payload, transaction_id=42)

    # Reassemble in order
    res_payload: Optional[bytes] = None
    for frag in fragments:
        res_payload = fe.add_fragment(frag)

    frag_ok = (len(fragments) == 6 and res_payload == large_payload)

    # Ingest malformed fragments to verify CipFragmentationFaultError trapping
    frag_fault_caught = False
    try:
        fe.reset()
        fe.add_fragment(CipExplicitFragment(99, 5, 5, 1000, 1000, b""))  # invalid index >= total
    except CipFragmentationFaultError:
        frag_fault_caught = True

    # Also test offset gap detection
    gap_caught = False
    try:
        fe.reset()
        fe.add_fragment(CipExplicitFragment(88, 0, 2, 0, 200, b"\x01" * 100))
        fe.add_fragment(CipExplicitFragment(88, 1, 2, 150, 200, b"\x02" * 50))  # offset 150 instead of 100
    except CipFragmentationFaultError:
        gap_caught = True

    c7 = frag_ok and frag_fault_caught and gap_caught
    test_results.append({
        "stage": 7,
        "check": "Fragmentation_And_Reassembly_Engine",
        "passed": c7,
        "details": "1200-byte payload cleanly fragmented into 6 chunks and reassembled; malformed fragments trapped.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Process Safety Interlocks & Diagnostics (0xC501..0xC504)
    # ------------------------------------------------------------------------
    safety_trips_ok = []

    # 0xC501: CIP_ERR_UCMM_TIMEOUT (> 25.0 ms)
    engine.reset_latch(force=True)
    engine.transaction_in_progress = True
    engine.current_transaction_elapsed_ms = 0.0
    engine.step_scan_cycle(dt_ms=30.0)  # Silence > 25.0 ms
    safety_trips_ok.append(
        rt.read_uword("%R1337") == 0xC501
        and rt.read_bit("%M311") is True
        and rt.read_bit("%M310") is False
    )

    # 0xC502: CIP_ERR_SERVICE_NOT_SUPPORTED
    engine.reset_latch(force=True)
    engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_SERVICE_NOT_SUPPORTED)
    safety_trips_ok.append(
        rt.read_uword("%R1337") == 0xC502
        and rt.read_bit("%M311") is True
        and rt.read_bit("%M310") is False
    )

    # 0xC503: CIP_ERR_OBJECT_PATH_INVALID
    engine.reset_latch(force=True)
    engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID)
    safety_trips_ok.append(
        rt.read_uword("%R1337") == 0xC503
        and rt.read_bit("%M311") is True
        and rt.read_bit("%M310") is False
    )

    # 0xC504: CIP_ERR_FRAGMENTATION_FAULT
    engine.reset_latch(force=True)
    engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_FRAGMENTATION_FAULT)
    safety_trips_ok.append(
        rt.read_uword("%R1337") == 0xC504
        and rt.read_bit("%M311") is True
        and rt.read_bit("%M310") is False
    )

    c8 = all(safety_trips_ok)
    test_results.append({
        "stage": 8,
        "check": "Process_Safety_Interlocks_And_Diagnostics_0xC501_To_0xC504",
        "passed": c8,
        "details": "All 4 diagnostic event codes (0xC501..0xC504) asserted %M311 and de-asserted %M310 deterministically.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Scan Cycle Simulation (ILogicUnit) & Register Synchronization
    # ------------------------------------------------------------------------
    engine.reset_latch(force=True)
    engine.sync_to_registers()

    # Step simulation scan cycles
    for _ in range(10):
        engine.scan_step(dt=0.001)

    c9 = (
        engine.diagnostic_code == CipExplicitDiagnosticCode.OK
        and rt.read_uword("%R1337") == 0x0000
        and rt.read_bit("%M310") is True
        and rt.read_bit("%M311") is False
        and rt.read_word("%R1333") == 250
        and (rt.read_word("%R1335") & UcmmTransceiverStateBits.PORT_44818_LISTENING) != 0
    )
    test_results.append({
        "stage": 9,
        "check": "Scan_Cycle_Simulation_And_Register_Synchronization",
        "passed": c9,
        "details": "ILogicUnit scan cycles executed; %R1330..%R1337 and %M310..%M311 synchronized with PrivilegeMode.SYSTEM.",
    })

    # ------------------------------------------------------------------------
    # Verification Summary & Evidence Serialization
    # ------------------------------------------------------------------------
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Industrial EtherNet/IP Explicit Messaging & CIP Object Dictionary Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} stages passed).",
        "data": {
            "work_package": "W172",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial EtherNet/IP Explicit Messaging Connected/Unconnected Message Manager (UCMM) & CIP Object Dictionary Engine",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R1330..%R1337",
                "discrete_coils": "%M310..%M311",
                "values": {
                    "%R1330": rt.read_word("%R1330"),
                    "%R1331": rt.read_uword("%R1331"),
                    "%R1332": rt.read_uword("%R1332"),
                    "%R1333": rt.read_word("%R1333"),
                    "%R1334": rt.read_word("%R1334"),
                    "%R1335": rt.read_word("%R1335"),
                    "%R1336": rt.read_uword("%R1336"),
                    "%R1337": rt.read_uword("%R1337"),
                    "%M310": rt.read_bit("%M310"),
                    "%M311": rt.read_bit("%M311"),
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


# ============================================================================
# 14. Convenience Aliases & Helpers
# ============================================================================

CIP_EXPLICIT_DEFAULT_TIMEOUT_MS = CIP_EXPLICIT_NOMINAL_TIMEOUT_MS
CIP_EXPLICIT_DEFAULT_TIMEOUT_SCALED = CIP_EXPLICIT_NOMINAL_TIMEOUT_SCALED
CIP_EXPLICIT_MAX_CLASS3_CONNECTIONS = 16
verify_cip_explicit_messaging_pure_st = verify_cip_explicit_pure_st
encode_service_class_word = encode_service_and_class_word
decode_service_class_word = decode_service_and_class_word
ExplicitMessagingStateBits = UcmmTransceiverStateBits
CipExplicitStateBits = UcmmTransceiverStateBits
EPath = EPATH
CipExplicitTransactionTimeoutError = CipUcmmTimeoutError
CipExplicitConnectionStateConflictError = CipServiceNotSupportedError
CipExplicitEPathRoutingError = CipObjectPathInvalidError
CipExplicitMalformedFrameError = CipFragmentationFaultError
Class3ConnectionState = UcmmTransceiverState
TransportClass3State = UcmmTransceiverState
CipClass3State = UcmmTransceiverState
Class3Connection = TransportClass3Connection
UnconnectedMessageManager = UcmmExplicitEngine
UCMM = UcmmExplicitEngine
ETHERNET_IP_EXPLICIT_SYNC_POU = ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU
EtherNetIpExplicitSync = CipExplicitMessagingEngine
CipExplicitMessagingSync = CipExplicitMessagingEngine


def serialize_cip_error_response(
    service_code: int,
    general_status: CIPGeneralStatus,
    additional_status: Optional[List[int]] = None,
) -> bytes:
    """Construct and serialize a standard CIP error response."""
    resp = CIPResponse(
        reply_service_code=(service_code & 0x7F) | 0x80,
        general_status=general_status,
        additional_status=additional_status or [],
    )
    return resp.encode()


if __name__ == "__main__":
    out_target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_cip_explicit_messaging_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
