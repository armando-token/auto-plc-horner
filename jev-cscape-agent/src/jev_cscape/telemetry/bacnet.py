"""BACnet/IP Telemetry Protocol Engine & APDU BACnet-COV Notification Server.

Work Package: W076 (Gate G8 / G4)
Standard: ANSI/ASHRAE Standard 135 (BACnet), Annex J (BACnet/IP), Clauses 20 & 21
Horner OCS Register Mappings:
- %R370: Status Word (Bit 0: Active, Bit 1: UDP Bound, Bit 2: COV Active, Bit 3: COV Sent, Bit 4: Protocol Error, Bit 5: Unknown Service)
- %R371: Packets Received Counter (monotonic UINT16)
- %R372: Packets Sent Counter (monotonic UINT16)
- %R373: Last Service Choice Received (e.g. 12 ReadProperty, 15 WriteProperty, 5 SubscribeCOV, 2 UnconfirmedCOV)
- %R374: Scaled Analog Input 0 Present Value (0..10000 representing 0.00..100.00 EU)
- %R375: Binary Input 0 Present Value / Status Flags
- %M86: Enable BACnet Server
- %M87: Trigger Manual COV Notification Broadcast
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class BVLLFunction(IntEnum):
    BVLC_RESULT = 0x00
    FORWARDED_NPDU = 0x04
    REGISTER_FOREIGN_DEVICE = 0x05
    READ_FOREIGN_DEVICE_TABLE = 0x06
    ORIGINAL_UNICAST_NPDU = 0x0A
    ORIGINAL_BROADCAST_NPDU = 0x0B


class PDUType(IntEnum):
    CONFIRMED_REQUEST = 0
    UNCONFIRMED_REQUEST = 1
    SIMPLE_ACK = 2
    COMPLEX_ACK = 3
    SEGMENT_ACK = 4
    ERROR = 5
    REJECT = 6
    ABORT = 7


class ConfirmedServiceChoice(IntEnum):
    SUBSCRIBE_COV = 5
    READ_PROPERTY = 12
    READ_PROPERTY_MULTIPLE = 14
    WRITE_PROPERTY = 15


class UnconfirmedServiceChoice(IntEnum):
    I_AM = 0
    UNCONFIRMED_COV_NOTIFICATION = 2
    WHO_IS = 8


class ApplicationTag(IntEnum):
    NULL = 0
    BOOLEAN = 1
    UNSIGNED_INT = 2
    SIGNED_INT = 3
    REAL = 4
    DOUBLE = 5
    OCTET_STRING = 6
    CHARACTER_STRING = 7
    BIT_STRING = 8
    ENUMERATED = 9
    DATE = 10
    TIME = 11
    OBJECT_IDENTIFIER = 12


class BACnetObjectType(IntEnum):
    ANALOG_INPUT = 0
    ANALOG_OUTPUT = 1
    ANALOG_VALUE = 2
    BINARY_INPUT = 3
    BINARY_OUTPUT = 4
    BINARY_VALUE = 5
    DEVICE = 8


class BACnetPropertyIdentifier(IntEnum):
    PRESENT_VALUE = 85
    STATUS_FLAGS = 111
    UNITS = 117
    COV_INCREMENT = 44


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BACnetObjectID:
    """BACnet 32-bit Object Identifier: 10-bit type + 22-bit instance."""
    object_type: Union[int, BACnetObjectType]
    instance: int

    def __post_init__(self) -> None:
        obj_int = int(self.object_type)
        if not (0 <= obj_int <= 1023):
            raise ValueError(f"Object type must be 0..1023, got {obj_int}")
        if not (0 <= self.instance <= 0x3FFFFF):
            raise ValueError(f"Instance must be 0..4194303, got {self.instance}")

    def to_uint32(self) -> int:
        return ((int(self.object_type) & 0x3FF) << 22) | (self.instance & 0x3FFFFF)

    @classmethod
    def from_uint32(cls, val: int) -> BACnetObjectID:
        obj_type_raw = (val >> 22) & 0x3FF
        try:
            obj_type = BACnetObjectType(obj_type_raw)
        except ValueError:
            obj_type = obj_type_raw
        return cls(object_type=obj_type, instance=val & 0x3FFFFF)

    def encode(self) -> bytes:
        return struct.pack(">I", self.to_uint32())

    @classmethod
    def decode(cls, data: bytes) -> BACnetObjectID:
        if len(data) < 4:
            raise ValueError(f"Expected at least 4 bytes for ObjectID, got {len(data)}")
        return cls.from_uint32(struct.unpack(">I", data[:4])[0])


@dataclass
class StatusFlags:
    """BACnet 4-bit Status Flags."""
    in_alarm: bool = False
    fault: bool = False
    overridden: bool = False
    out_of_service: bool = False

    def to_bits(self) -> List[bool]:
        return [self.in_alarm, self.fault, self.overridden, self.out_of_service]

    @classmethod
    def from_bits(cls, bits: List[bool]) -> StatusFlags:
        return cls(
            in_alarm=bool(bits[0]) if len(bits) > 0 else False,
            fault=bool(bits[1]) if len(bits) > 1 else False,
            overridden=bool(bits[2]) if len(bits) > 2 else False,
            out_of_service=bool(bits[3]) if len(bits) > 3 else False,
        )


@dataclass(frozen=True)
class BACnetBitString:
    unused_bits: int
    data: bytes

    def get_bit(self, index: int) -> bool:
        byte_i = index // 8
        bit_i = 7 - (index % 8)
        return bool((self.data[byte_i] >> bit_i) & 1) if byte_i < len(self.data) else False

    @classmethod
    def from_bool_list(cls, bits: List[bool]) -> BACnetBitString:
        if not bits:
            return cls(0, b"")
        num_bytes = (len(bits) + 7) // 8
        unused = (num_bytes * 8) - len(bits)
        buf = bytearray(num_bytes)
        for i, val in enumerate(bits):
            if val:
                buf[i // 8] |= (1 << (7 - (i % 8)))
        return cls(unused, bytes(buf))


# ---------------------------------------------------------------------------
# Tag Codecs
# ---------------------------------------------------------------------------

def encode_unsigned(val: int) -> bytes:
    if val == 0:
        return bytes([0])
    out = []
    temp = val
    while temp > 0:
        out.append(temp & 0xFF)
        temp >>= 8
    return bytes(reversed(out))


def decode_unsigned(b: bytes) -> int:
    res = 0
    for byte in b:
        res = (res << 8) | byte
    return res


def encode_tag_header(
    tag_number: int,
    is_context: bool,
    length: int = 0,
    is_opening: bool = False,
    is_closing: bool = False,
    bool_value: bool = False,
) -> bytes:
    if tag_number < 15:
        initial_tag = tag_number << 4
        ext_tag = b""
    else:
        initial_tag = 0xF0
        ext_tag = bytes([tag_number & 0xFF])

    class_bit = 0x08 if is_context else 0x00

    if is_context:
        if is_opening:
            lvt = 6
            ext_len = b""
        elif is_closing:
            lvt = 7
            ext_len = b""
        elif length < 5:
            lvt = length
            ext_len = b""
        else:
            lvt = 5
            ext_len = bytes([length & 0xFF])
    else:
        if tag_number == ApplicationTag.BOOLEAN:
            lvt = 1 if bool_value else 0
            ext_len = b""
        elif length < 5:
            lvt = length
            ext_len = b""
        else:
            lvt = 5
            ext_len = bytes([length & 0xFF])

    return bytes([initial_tag | class_bit | lvt]) + ext_tag + ext_len


def decode_tag_header(data: bytes, offset: int = 0) -> Tuple[int, bool, int, int, bool, bool, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of data parsing tag header")
    b0 = data[offset]
    offset += 1
    tag_num = (b0 >> 4) & 0x0F
    is_context = bool(b0 & 0x08)
    lvt = b0 & 0x07

    if tag_num == 15:
        if offset >= len(data):
            raise ValueError("Truncated extended tag number")
        tag_num = data[offset]
        offset += 1

    is_opening = False
    is_closing = False
    length_or_val = 0

    if is_context:
        if lvt == 6:
            is_opening = True
        elif lvt == 7:
            is_closing = True
        elif lvt < 5:
            length_or_val = lvt
        else:
            length_or_val = data[offset]
            offset += 1
    else:
        if tag_num == ApplicationTag.BOOLEAN:
            length_or_val = 1 if lvt == 1 else 0
        elif lvt < 5:
            length_or_val = lvt
        else:
            length_or_val = data[offset]
            offset += 1

    return (tag_num, is_context, lvt, length_or_val, is_opening, is_closing, offset)


def encode_application_data(tag: Union[int, ApplicationTag], value: Any) -> bytes:
    tag = ApplicationTag(tag)
    if tag == ApplicationTag.NULL:
        return bytes([0x00])
    elif tag == ApplicationTag.BOOLEAN:
        return encode_tag_header(ApplicationTag.BOOLEAN, is_context=False, bool_value=bool(value))
    elif tag in (ApplicationTag.UNSIGNED_INT, ApplicationTag.ENUMERATED):
        b = encode_unsigned(int(value))
        return encode_tag_header(tag, is_context=False, length=len(b)) + b
    elif tag == ApplicationTag.SIGNED_INT:
        val = int(value)
        needed = (val.bit_length() + 1 + 7) // 8 if val != 0 else 1
        b = val.to_bytes(needed, "big", signed=True)
        return encode_tag_header(ApplicationTag.SIGNED_INT, is_context=False, length=len(b)) + b
    elif tag == ApplicationTag.REAL:
        return encode_tag_header(ApplicationTag.REAL, is_context=False, length=4) + struct.pack(">f", float(value))
    elif tag == ApplicationTag.OBJECT_IDENTIFIER:
        oid = value if isinstance(value, BACnetObjectID) else BACnetObjectID.from_uint32(int(value))
        return encode_tag_header(ApplicationTag.OBJECT_IDENTIFIER, is_context=False, length=4) + oid.encode()
    elif tag == ApplicationTag.BIT_STRING:
        if isinstance(value, StatusFlags):
            bs = BACnetBitString.from_bool_list(value.to_bits())
        elif isinstance(value, BACnetBitString):
            bs = value
        elif isinstance(value, list):
            bs = BACnetBitString.from_bool_list(value)
        else:
            bs = BACnetBitString(0, bytes(value))
        raw = bytes([bs.unused_bits]) + bs.data
        return encode_tag_header(ApplicationTag.BIT_STRING, is_context=False, length=len(raw)) + raw
    elif tag == ApplicationTag.CHARACTER_STRING:
        raw = bytes([0x00]) + str(value).encode("utf-8")
        return encode_tag_header(ApplicationTag.CHARACTER_STRING, is_context=False, length=len(raw)) + raw
    raise NotImplementedError(f"Application tag {tag} encoding not implemented")


def decode_application_data(data: bytes, offset: int = 0) -> Tuple[Any, int, int]:
    tnum, is_ctx, lvt, length_or_val, _, _, new_offset = decode_tag_header(data, offset)
    if is_ctx:
        raise ValueError(f"Expected application tag, got context tag {tnum}")
    if tnum == ApplicationTag.NULL:
        return None, tnum, new_offset
    elif tnum == ApplicationTag.BOOLEAN:
        return bool(length_or_val == 1), tnum, new_offset
    elif tnum in (ApplicationTag.UNSIGNED_INT, ApplicationTag.ENUMERATED):
        val = int.from_bytes(data[new_offset:new_offset + length_or_val], "big", signed=False)
        return val, tnum, new_offset + length_or_val
    elif tnum == ApplicationTag.SIGNED_INT:
        val = int.from_bytes(data[new_offset:new_offset + length_or_val], "big", signed=True)
        return val, tnum, new_offset + length_or_val
    elif tnum == ApplicationTag.REAL:
        val = struct.unpack(">f", data[new_offset:new_offset + 4])[0]
        return val, tnum, new_offset + 4
    elif tnum == ApplicationTag.OBJECT_IDENTIFIER:
        oid = BACnetObjectID.decode(data[new_offset:new_offset + 4])
        return oid, tnum, new_offset + 4
    elif tnum == ApplicationTag.BIT_STRING:
        unused = data[new_offset]
        raw_bytes = data[new_offset + 1:new_offset + length_or_val]
        return BACnetBitString(unused, raw_bytes), tnum, new_offset + length_or_val
    elif tnum == ApplicationTag.CHARACTER_STRING:
        text = data[new_offset + 1:new_offset + length_or_val].decode("utf-8", errors="replace")
        return text, tnum, new_offset + length_or_val
    return data[new_offset:new_offset + length_or_val], tnum, new_offset + length_or_val


def encode_context_data(tag_number: int, data: bytes) -> bytes:
    return encode_tag_header(tag_number, is_context=True, length=len(data)) + data


# ---------------------------------------------------------------------------
# BVLL & NPDU Framing
# ---------------------------------------------------------------------------

@dataclass
class BVLLHeader:
    """BACnet Virtual Link Layer (Annex J) 4-octet header."""
    bvll_type: int = 0x81  # BACnet/IP
    function: BVLLFunction = BVLLFunction.ORIGINAL_UNICAST_NPDU
    length: int = 4

    def serialize(self) -> bytes:
        return struct.pack(">BBH", self.bvll_type, int(self.function), self.length)

    @classmethod
    def parse(cls, data: bytes) -> Tuple[BVLLHeader, int]:
        if len(data) < 4:
            raise ValueError(f"BVLL header requires 4 octets, got {len(data)}")
        btype, func_code, length = struct.unpack(">BBH", data[:4])
        if btype != 0x81:
            raise ValueError(f"Invalid BVLL type 0x{btype:02X}, expected 0x81")
        try:
            func = BVLLFunction(func_code)
        except ValueError:
            func = func_code
        return cls(bvll_type=btype, function=func, length=length), 4


@dataclass
class NPDUHeader:
    """BACnet Network Protocol Data Unit (Clause 6) header."""
    version: int = 0x01
    network_message: bool = False
    dnet_present: bool = False
    snet_present: bool = False
    expecting_reply: bool = False
    priority: int = 0  # 00: Normal, 01: Urgent, 10: Critical, 11: Life Safety
    dnet: Optional[int] = None
    dadr: Optional[bytes] = None
    snet: Optional[int] = None
    sadr: Optional[bytes] = None
    hop_count: Optional[int] = None

    def serialize(self) -> bytes:
        npci = 0
        if self.network_message:
            npci |= 0x80
        if self.dnet_present:
            npci |= 0x20
        if self.snet_present:
            npci |= 0x08
        if self.expecting_reply:
            npci |= 0x04
        npci |= (self.priority & 0x03)

        buf = bytearray([self.version, npci])
        if self.dnet_present:
            buf.extend(struct.pack(">H", self.dnet or 0))
            dadr = self.dadr or b""
            buf.append(len(dadr))
            buf.extend(dadr)
        if self.snet_present:
            buf.extend(struct.pack(">H", self.snet or 0))
            sadr = self.sadr or b""
            buf.append(len(sadr))
            buf.extend(sadr)
        if self.dnet_present:
            buf.append(self.hop_count if self.hop_count is not None else 255)
        return bytes(buf)

    @classmethod
    def parse(cls, data: bytes) -> Tuple[NPDUHeader, int]:
        if len(data) < 2:
            raise ValueError("NPDU requires at least 2 octets")
        version = data[0]
        npci = data[1]
        offset = 2

        net_msg = bool(npci & 0x80)
        dnet_pres = bool(npci & 0x20)
        snet_pres = bool(npci & 0x08)
        exp_reply = bool(npci & 0x04)
        priority = npci & 0x03

        dnet, dadr, snet, sadr, hop_count = None, None, None, None, None

        if dnet_pres:
            dnet = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            dlen = data[offset]
            offset += 1
            dadr = data[offset:offset + dlen]
            offset += dlen

        if snet_pres:
            snet = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            slen = data[offset]
            offset += 1
            sadr = data[offset:offset + slen]
            offset += slen

        if dnet_pres:
            hop_count = data[offset]
            offset += 1

        return cls(
            version=version,
            network_message=net_msg,
            dnet_present=dnet_pres,
            snet_present=snet_pres,
            expecting_reply=exp_reply,
            priority=priority,
            dnet=dnet,
            dadr=dadr,
            snet=snet,
            sadr=sadr,
            hop_count=hop_count,
        ), offset


# ---------------------------------------------------------------------------
# APDU Structures
# ---------------------------------------------------------------------------

@dataclass
class ConfirmedRequestPDU:
    invoke_id: int
    service_choice: Union[int, ConfirmedServiceChoice]
    service_data: bytes = b""
    segmented: bool = False
    more_segments: bool = False
    segmented_response_accepted: bool = True
    max_segments: int = 0
    max_apdu_length: int = 5  # 1476 octets

    def serialize(self) -> bytes:
        octet0 = (0 << 4) | (int(self.segmented) << 3) | (int(self.more_segments) << 2) | (int(self.segmented_response_accepted) << 1)
        octet1 = ((self.max_segments & 0x07) << 4) | (self.max_apdu_length & 0x0F)
        return bytes([octet0, octet1, self.invoke_id & 0xFF, int(self.service_choice) & 0xFF]) + self.service_data

    @classmethod
    def parse(cls, data: bytes) -> ConfirmedRequestPDU:
        if len(data) < 4:
            raise ValueError("ConfirmedRequest requires at least 4 octets")
        seg = bool((data[0] >> 3) & 1)
        mor = bool((data[0] >> 2) & 1)
        sa = bool((data[0] >> 1) & 1)
        max_segs = (data[1] >> 4) & 0x07
        max_apdu = data[1] & 0x0F
        inv_id = data[2]
        sc = data[3]
        try:
            choice = ConfirmedServiceChoice(sc)
        except ValueError:
            choice = sc
        return cls(
            invoke_id=inv_id,
            service_choice=choice,
            service_data=data[4:],
            segmented=seg,
            more_segments=mor,
            segmented_response_accepted=sa,
            max_segments=max_segs,
            max_apdu_length=max_apdu,
        )


@dataclass
class SimpleACKPDU:
    invoke_id: int
    service_choice: Union[int, ConfirmedServiceChoice]

    def serialize(self) -> bytes:
        return bytes([(2 << 4), self.invoke_id & 0xFF, int(self.service_choice) & 0xFF])

    @classmethod
    def parse(cls, data: bytes) -> SimpleACKPDU:
        if len(data) < 3:
            raise ValueError("SimpleACK requires 3 octets")
        sc = data[2]
        try:
            choice = ConfirmedServiceChoice(sc)
        except ValueError:
            choice = sc
        return cls(invoke_id=data[1], service_choice=choice)


@dataclass
class ComplexACKPDU:
    invoke_id: int
    service_choice: Union[int, ConfirmedServiceChoice]
    service_data: bytes = b""

    def serialize(self) -> bytes:
        return bytes([(3 << 4), self.invoke_id & 0xFF, int(self.service_choice) & 0xFF]) + self.service_data

    @classmethod
    def parse(cls, data: bytes) -> ComplexACKPDU:
        if len(data) < 3:
            raise ValueError("ComplexACK requires at least 3 octets")
        sc = data[2]
        try:
            choice = ConfirmedServiceChoice(sc)
        except ValueError:
            choice = sc
        return cls(invoke_id=data[1], service_choice=choice, service_data=data[3:])


@dataclass
class UnconfirmedRequestPDU:
    service_choice: Union[int, UnconfirmedServiceChoice]
    service_data: bytes = b""

    def serialize(self) -> bytes:
        return bytes([(1 << 4), int(self.service_choice) & 0xFF]) + self.service_data

    @classmethod
    def parse(cls, data: bytes) -> UnconfirmedRequestPDU:
        if len(data) < 2:
            raise ValueError("UnconfirmedRequest requires at least 2 octets")
        sc = data[1]
        try:
            choice = UnconfirmedServiceChoice(sc)
        except ValueError:
            choice = sc
        return cls(service_choice=choice, service_data=data[2:])


# ---------------------------------------------------------------------------
# COV (Change of Value) Structures
# ---------------------------------------------------------------------------

@dataclass
class COVSubscription:
    subscriber_process_id: int
    monitored_object_id: BACnetObjectID
    issue_confirmed: bool
    lifetime: int
    cov_increment: Optional[float] = None
    last_reported_pv: Optional[Union[float, bool]] = None
    last_reported_status: Optional[StatusFlags] = None

    def evaluate_trigger(self, current_pv: Union[float, bool], current_status: StatusFlags) -> bool:
        if self.last_reported_pv is None or self.last_reported_status is None:
            return True
        if self.last_reported_status != current_status:
            return True
        if isinstance(current_pv, bool):
            return current_pv != self.last_reported_pv
        if self.cov_increment is not None:
            return abs(float(current_pv) - float(self.last_reported_pv)) >= self.cov_increment
        return current_pv != self.last_reported_pv

    def mark_reported(self, current_pv: Union[float, bool], current_status: StatusFlags) -> None:
        self.last_reported_pv = current_pv
        self.last_reported_status = current_status


@dataclass
class UnconfirmedCOVNotification:
    subscriber_process_id: int
    initiating_device_id: BACnetObjectID
    monitored_object_id: BACnetObjectID
    time_remaining: int
    present_value: Union[float, bool, int]
    status_flags: StatusFlags = field(default_factory=StatusFlags)

    def serialize(self) -> bytes:
        buf = bytearray()
        # [0] subscriberProcessIdentifier
        buf.extend(encode_context_data(0, encode_unsigned(self.subscriber_process_id)))
        # [1] initiatingDeviceIdentifier
        buf.extend(encode_context_data(1, self.initiating_device_id.encode()))
        # [2] monitoredObjectIdentifier
        buf.extend(encode_context_data(2, self.monitored_object_id.encode()))
        # [3] timeRemaining
        buf.extend(encode_context_data(3, encode_unsigned(self.time_remaining)))
        # [4] listOfValues opening tag
        buf.extend(encode_tag_header(4, is_context=True, is_opening=True))

        # Present_Value property (85)
        buf.extend(encode_context_data(0, encode_unsigned(int(BACnetPropertyIdentifier.PRESENT_VALUE))))
        buf.extend(encode_tag_header(2, is_context=True, is_opening=True))
        if isinstance(self.present_value, bool):
            buf.extend(encode_application_data(ApplicationTag.ENUMERATED, 1 if self.present_value else 0))
        elif isinstance(self.present_value, float):
            buf.extend(encode_application_data(ApplicationTag.REAL, self.present_value))
        else:
            buf.extend(encode_application_data(ApplicationTag.UNSIGNED_INT, self.present_value))
        buf.extend(encode_tag_header(2, is_context=True, is_closing=True))

        # Status_Flags property (111)
        buf.extend(encode_context_data(0, encode_unsigned(int(BACnetPropertyIdentifier.STATUS_FLAGS))))
        buf.extend(encode_tag_header(2, is_context=True, is_opening=True))
        buf.extend(encode_application_data(ApplicationTag.BIT_STRING, self.status_flags))
        buf.extend(encode_tag_header(2, is_context=True, is_closing=True))

        # listOfValues closing tag
        buf.extend(encode_tag_header(4, is_context=True, is_closing=True))
        return bytes(buf)

    @classmethod
    def parse(cls, data: bytes) -> UnconfirmedCOVNotification:
        offset = 0
        t0, is_ctx0, _, l0, _, _, offset = decode_tag_header(data, offset)
        sub_id = decode_unsigned(data[offset:offset + l0])
        offset += l0

        t1, is_ctx1, _, l1, _, _, offset = decode_tag_header(data, offset)
        init_dev = BACnetObjectID.decode(data[offset:offset + l1])
        offset += l1

        t2, is_ctx2, _, l2, _, _, offset = decode_tag_header(data, offset)
        mon_obj = BACnetObjectID.decode(data[offset:offset + l2])
        offset += l2

        t3, is_ctx3, _, l3, _, _, offset = decode_tag_header(data, offset)
        time_rem = decode_unsigned(data[offset:offset + l3])
        offset += l3

        # Opening tag 4
        _, _, _, _, is_open4, _, offset = decode_tag_header(data, offset)

        pv_val = None
        st_flags = None

        while offset < len(data):
            t_num, is_ctx, _, length, is_open, is_close, offset = decode_tag_header(data, offset)
            if is_ctx and t_num == 4 and is_close:
                break
            prop_id = decode_unsigned(data[offset:offset + length])
            offset += length

            # Value container opening tag 2
            _, _, _, _, _, _, offset = decode_tag_header(data, offset)
            val, app_tag, offset = decode_application_data(data, offset)
            # Value container closing tag 2
            _, _, _, _, _, _, offset = decode_tag_header(data, offset)

            if prop_id == BACnetPropertyIdentifier.PRESENT_VALUE:
                pv_val = val
            elif prop_id == BACnetPropertyIdentifier.STATUS_FLAGS:
                if isinstance(val, BACnetBitString):
                    st_flags = StatusFlags(
                        in_alarm=val.get_bit(0),
                        fault=val.get_bit(1),
                        overridden=val.get_bit(2),
                        out_of_service=val.get_bit(3),
                    )

        return cls(
            subscriber_process_id=sub_id,
            initiating_device_id=init_dev,
            monitored_object_id=mon_obj,
            time_remaining=time_rem,
            present_value=pv_val,
            status_flags=st_flags or StatusFlags(),
        )


# ---------------------------------------------------------------------------
# BACnet/IP Telemetry Server Engine
# ---------------------------------------------------------------------------

class BACnetServerEngine:
    """Industrial BACnet/IP Server Engine and COV Notification Manager."""

    def __init__(self, device_id: int = 100, device_name: str = "HORNER_OCS_P1") -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.device_oid = BACnetObjectID(BACnetObjectType.DEVICE, device_id)

        # Telemetry State
        self.ai0_oid = BACnetObjectID(BACnetObjectType.ANALOG_INPUT, 0)
        self.bi0_oid = BACnetObjectID(BACnetObjectType.BINARY_INPUT, 0)
        self.ai0_pv: float = 0.0
        self.bi0_pv: bool = False
        self.ai0_status = StatusFlags()
        self.bi0_status = StatusFlags()

        # Subscriptions
        self.subscriptions: List[COVSubscription] = []

        # Horner OCS Registers
        self.status_word: int = 0
        self.packets_received: int = 0
        self.packets_sent: int = 0
        self.last_service_choice: int = 0
        self.ai0_scaled_pv: int = 0
        self.bi0_raw_status: int = 0
        self.enable_server: bool = True
        self.trigger_manual_cov: bool = False

    def update_registers(
        self,
        ai0_pv_scaled: int,
        bi0_state: int,
        enable: bool = True,
        trigger_cov: bool = False,
    ) -> None:
        """Update telemetry values and execute server cycle."""
        self.enable_server = enable
        self.trigger_manual_cov = trigger_cov
        self.ai0_scaled_pv = max(0, min(10000, ai0_pv_scaled))
        self.ai0_pv = self.ai0_scaled_pv / 100.0  # 0.00 .. 100.00 EU
        self.bi0_raw_status = bi0_state
        self.bi0_pv = bool(bi0_state & 0x01)
        self.bi0_status = StatusFlags(
            in_alarm=bool(bi0_state & 0x02),
            fault=bool(bi0_state & 0x04),
            overridden=bool(bi0_state & 0x08),
            out_of_service=bool(bi0_state & 0x10),
        )

        if not self.enable_server:
            self.status_word = 0
            return

        # Bit 0: Active, Bit 1: UDP Bound
        status = 0x0001 | 0x0002
        if len(self.subscriptions) > 0:
            status |= 0x0004  # Bit 2: COV Subscription Active

        if self.trigger_manual_cov:
            status |= 0x0008  # Bit 3: COV Notification Sent
            self.packets_sent += 1
            self.trigger_manual_cov = False

        self.status_word = status

    def handle_packet(self, packet_bytes: bytes) -> Optional[bytes]:
        """Process an incoming BACnet/IP packet (BVLL + NPDU + APDU) and return response."""
        if not self.enable_server:
            return None

        self.packets_received += 1
        try:
            bvll, offset = BVLLHeader.parse(packet_bytes)
            npdu, npdu_len = NPDUHeader.parse(packet_bytes[offset:])
            apdu_bytes = packet_bytes[offset + npdu_len:bvll.length]

            if len(apdu_bytes) == 0:
                return None

            pdu_type = (apdu_bytes[0] >> 4) & 0x0F
            if pdu_type == PDUType.CONFIRMED_REQUEST:
                req = ConfirmedRequestPDU.parse(apdu_bytes)
                self.last_service_choice = int(req.service_choice)
                return self._handle_confirmed_request(req, npdu)
            elif pdu_type == PDUType.UNCONFIRMED_REQUEST:
                unconf_req = UnconfirmedRequestPDU.parse(apdu_bytes)
                self.last_service_choice = int(unconf_req.service_choice)
                return self._handle_unconfirmed_request(unconf_req, npdu)
            else:
                self.status_word |= 0x0020  # Unknown Service
                return None
        except Exception:
            self.status_word |= 0x0010  # Protocol / Decode Error
            return None

    def _handle_confirmed_request(self, req: ConfirmedRequestPDU, npdu: NPDUHeader) -> Optional[bytes]:
        if req.service_choice == ConfirmedServiceChoice.READ_PROPERTY:
            # Parse ReadPropertyRequest: [0] objectId, [1] propertyId
            t0, _, _, l0, _, _, off = decode_tag_header(req.service_data, 0)
            obj_id = BACnetObjectID.decode(req.service_data[off:off + l0])
            off += l0
            t1, _, _, l1, _, _, off = decode_tag_header(req.service_data, off)
            prop_id = decode_unsigned(req.service_data[off:off + l1])

            # Build ReadProperty ComplexACK
            val = self.ai0_pv if obj_id == self.ai0_oid else 0.0
            ack_payload = (
                encode_context_data(0, obj_id.encode())
                + encode_context_data(1, encode_unsigned(prop_id))
                + encode_tag_header(3, is_context=True, is_opening=True)
                + encode_application_data(ApplicationTag.REAL, val)
                + encode_tag_header(3, is_context=True, is_closing=True)
            )
            complex_ack = ComplexACKPDU(
                invoke_id=req.invoke_id,
                service_choice=ConfirmedServiceChoice.READ_PROPERTY,
                service_data=ack_payload,
            )
            return self._wrap_pdu(complex_ack.serialize(), expecting_reply=False)

        elif req.service_choice == ConfirmedServiceChoice.SUBSCRIBE_COV:
            # Parse SubscribeCOV: [0] subscriberProcessId, [1] monitoredObjectId, [2] issueConfirmed, [3] lifetime
            off = 0
            t0, _, _, l0, _, _, off = decode_tag_header(req.service_data, off)
            sub_proc_id = decode_unsigned(req.service_data[off:off + l0])
            off += l0

            t1, _, _, l1, _, _, off = decode_tag_header(req.service_data, off)
            mon_obj = BACnetObjectID.decode(req.service_data[off:off + l1])
            off += l1

            issue_confirmed = False
            lifetime = 300
            if off < len(req.service_data):
                _, _, _, l2, _, _, off = decode_tag_header(req.service_data, off)
                issue_confirmed = bool(decode_unsigned(req.service_data[off:off + l2]))
                off += l2
            if off < len(req.service_data):
                _, _, _, l3, _, _, off = decode_tag_header(req.service_data, off)
                lifetime = decode_unsigned(req.service_data[off:off + l3])
                off += l3

            # Register subscription
            sub = COVSubscription(
                subscriber_process_id=sub_proc_id,
                monitored_object_id=mon_obj,
                issue_confirmed=issue_confirmed,
                lifetime=lifetime,
                cov_increment=0.5,
            )
            self.subscriptions.append(sub)
            self.status_word |= 0x0004  # Bit 2: COV Active

            simple_ack = SimpleACKPDU(invoke_id=req.invoke_id, service_choice=ConfirmedServiceChoice.SUBSCRIBE_COV)
            return self._wrap_pdu(simple_ack.serialize(), expecting_reply=False)

        elif req.service_choice == ConfirmedServiceChoice.WRITE_PROPERTY:
            simple_ack = SimpleACKPDU(invoke_id=req.invoke_id, service_choice=ConfirmedServiceChoice.WRITE_PROPERTY)
            return self._wrap_pdu(simple_ack.serialize(), expecting_reply=False)

        self.status_word |= 0x0020
        return None

    def _handle_unconfirmed_request(self, req: UnconfirmedRequestPDU, npdu: NPDUHeader) -> Optional[bytes]:
        if req.service_choice == UnconfirmedServiceChoice.WHO_IS:
            # Reply with I-Am broadcast: AppTag12 OID, AppTag2 MaxAPDU(1476), AppTag9 SegSupport(3), AppTag2 VendorID(42)
            iam_payload = (
                encode_application_data(ApplicationTag.OBJECT_IDENTIFIER, self.device_oid)
                + encode_application_data(ApplicationTag.UNSIGNED_INT, 1476)
                + encode_application_data(ApplicationTag.ENUMERATED, 3)  # No segmentation
                + encode_application_data(ApplicationTag.UNSIGNED_INT, 42)  # Vendor ID
            )
            iam_pdu = UnconfirmedRequestPDU(
                service_choice=UnconfirmedServiceChoice.I_AM,
                service_data=iam_payload,
            )
            return self._wrap_pdu(iam_pdu.serialize(), is_broadcast=True)
        return None

    def build_cov_notification(
        self,
        monitored_object: BACnetObjectID,
        subscriber_process_id: int = 1,
        time_remaining: int = 300,
    ) -> bytes:
        """Construct an UnconfirmedCOVNotification packet for monitored object."""
        pv = self.ai0_pv if monitored_object == self.ai0_oid else (1.0 if self.bi0_pv else 0.0)
        flags = self.ai0_status if monitored_object == self.ai0_oid else self.bi0_status

        notif = UnconfirmedCOVNotification(
            subscriber_process_id=subscriber_process_id,
            initiating_device_id=self.device_oid,
            monitored_object_id=monitored_object,
            time_remaining=time_remaining,
            present_value=pv,
            status_flags=flags,
        )
        notif_pdu = UnconfirmedRequestPDU(
            service_choice=UnconfirmedServiceChoice.UNCONFIRMED_COV_NOTIFICATION,
            service_data=notif.serialize(),
        )
        return self._wrap_pdu(notif_pdu.serialize(), is_broadcast=True)

    def _wrap_pdu(self, apdu_bytes: bytes, expecting_reply: bool = False, is_broadcast: bool = False) -> bytes:
        npdu = NPDUHeader(expecting_reply=expecting_reply)
        npdu_bytes = npdu.serialize()
        total_len = 4 + len(npdu_bytes) + len(apdu_bytes)
        bvll = BVLLHeader(
            function=BVLLFunction.ORIGINAL_BROADCAST_NPDU if is_broadcast else BVLLFunction.ORIGINAL_UNICAST_NPDU,
            length=total_len,
        )
        self.packets_sent += 1
        return bvll.serialize() + npdu_bytes + apdu_bytes

    def sync_to_register_table(self, reg_table: Any) -> None:
        """Synchronize BACnet state with Horner OCS RegisterTable."""
        write_fn = getattr(reg_table, "write_register", getattr(reg_table, "write", None))
        if write_fn is None:
            return
        write_fn("%R370", self.status_word)
        write_fn("%R371", self.packets_received & 0xFFFF)
        write_fn("%R372", self.packets_sent & 0xFFFF)
        write_fn("%R373", self.last_service_choice)
        write_fn("%R374", self.ai0_scaled_pv)
        write_fn("%R375", self.bi0_raw_status)
        write_fn("%M86", self.enable_server)
        write_fn("%M87", self.trigger_manual_cov)

    def sync_from_register_table(self, reg_table: Any) -> None:
        """Read control registers and telemetry from Horner OCS RegisterTable."""
        read_fn = getattr(reg_table, "read_register", getattr(reg_table, "read", None))
        if read_fn is None:
            return
        enable = bool(read_fn("%M86"))
        trigger = bool(read_fn("%M87"))
        ai0_raw = int(read_fn("%R374"))
        bi0_raw = int(read_fn("%R375"))
        self.update_registers(ai0_raw, bi0_raw, enable=enable, trigger_cov=trigger)


# ---------------------------------------------------------------------------
# Pure Structured Text POU Definition
# ---------------------------------------------------------------------------

BACNET_TELEMETRY_ST_CODE = """PROGRAM BacnetTelemetryServer
VAR
    StatusWord AT %R370 : INT;
    PacketsReceivedCounter AT %R371 : UINT;
    PacketsSentCounter AT %R372 : UINT;
    LastServiceChoice AT %R373 : INT;
    AnalogInput0_PV AT %R374 : INT;
    BinaryInput0_PV AT %R375 : INT;

    EnableServer AT %M86 : BOOL;
    TriggerManualCOV AT %M87 : BOOL;

    BitServerActive : BOOL;
    BitUdpBound : BOOL;
    BitCovSubActive : BOOL;
    BitCovNotifSent : BOOL;
    BitProtocolError : BOOL;
    BitUnknownService : BOOL;
    CalculatedStatus : INT;
END_VAR

IF NOT EnableServer THEN
    BitServerActive := FALSE;
    BitUdpBound := FALSE;
    BitCovSubActive := FALSE;
    BitCovNotifSent := FALSE;
    BitProtocolError := FALSE;
    BitUnknownService := FALSE;
    StatusWord := 0;
    TriggerManualCOV := FALSE;
ELSE
    BitServerActive := TRUE;
    BitUdpBound := TRUE;

    IF AnalogInput0_PV < 0 THEN
        AnalogInput0_PV := 0;
    ELSIF AnalogInput0_PV > 10000 THEN
        AnalogInput0_PV := 10000;
    END_IF;

    IF BinaryInput0_PV < 0 THEN
        BinaryInput0_PV := 0;
    ELSIF BinaryInput0_PV > 1 THEN
        BinaryInput0_PV := 1;
    END_IF;

    IF TriggerManualCOV THEN
        PacketsSentCounter := PacketsSentCounter + 1;
        BitCovNotifSent := TRUE;
        TriggerManualCOV := FALSE;
    ELSE
        BitCovNotifSent := FALSE;
    END_IF;

    IF LastServiceChoice = 0 THEN
        BitProtocolError := FALSE;
        BitUnknownService := FALSE;
    ELSIF LastServiceChoice = 5 THEN
        BitCovSubActive := TRUE;
        BitProtocolError := FALSE;
        BitUnknownService := FALSE;
    ELSIF LastServiceChoice = 12 OR LastServiceChoice = 14 OR LastServiceChoice = 15 OR LastServiceChoice = 26 THEN
        BitProtocolError := FALSE;
        BitUnknownService := FALSE;
    ELSE
        BitUnknownService := TRUE;
        BitProtocolError := TRUE;
    END_IF;

    CalculatedStatus := 0;
    IF BitServerActive THEN
        CalculatedStatus := CalculatedStatus + 1;
    END_IF;
    IF BitUdpBound THEN
        CalculatedStatus := CalculatedStatus + 2;
    END_IF;
    IF BitCovSubActive THEN
        CalculatedStatus := CalculatedStatus + 4;
    END_IF;
    IF BitCovNotifSent THEN
        CalculatedStatus := CalculatedStatus + 8;
    END_IF;
    IF BitProtocolError THEN
        CalculatedStatus := CalculatedStatus + 16;
    END_IF;
    IF BitUnknownService THEN
        CalculatedStatus := CalculatedStatus + 32;
    END_IF;

    StatusWord := CalculatedStatus;
END_IF;
END_PROGRAM
"""
