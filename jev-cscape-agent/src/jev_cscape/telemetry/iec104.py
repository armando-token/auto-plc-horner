"""IEC 60870-5-104 Telemetry Protocol Server & APCI/ASDU Engine.

Work Package: W073 (Gate G8 / G4)
Standard: IEC 60870-5-104:2006 (Telecontrol equipment and systems over TCP/IP)
OCS Register Mappings: %R340..%R345, %M79..%M80

Provides:
- APCI Framing: I-Format, S-Format, U-Format (STARTDT, STOPDT, TESTFR)
- ASDU Codecs: Type 1 (M_SP_NA_1), Type 30 (M_SP_TB_1), Type 13 (M_ME_NC_1),
               Type 36 (M_ME_TF_1), Type 45 (C_SC_NA_1), Type 100 (C_IC_NA_1)
- CP56Time2a 7-octet high-resolution timestamp codec
- Pure IEC 61131-3 Structured Text POU definition and AST validation
- IEC104ServerEngine state machine with register synchronization
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime
from enum import Enum, IntEnum
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from jev_cscape.contracts import AgentStatus


# --- APCI Constants ---
APCI_START_BYTE: int = 0x68
MIN_APCI_LENGTH: int = 4
MAX_APDU_LENGTH: int = 253
MAX_SEQUENCE_NUMBER: int = 32767
MAX_ASDU_LENGTH: int = 249


class APCIFormat(str, Enum):
    """APCI Frame Formats."""
    I_FORMAT = "I"
    S_FORMAT = "S"
    U_FORMAT = "U"


class UFunction(IntEnum):
    """U-Format control function octets."""
    STARTDT_ACT = 0x07
    STARTDT_CON = 0x0B
    STOPDT_ACT = 0x13
    STOPDT_CON = 0x23
    TESTFR_ACT = 0x43
    TESTFR_CON = 0x83


# --- CP56Time2a Timestamp Codec ---

@dataclass(frozen=True)
class CP56Time2a:
    """7-octet binary timestamp structure compliant with IEC 60870-5-104."""
    dt: datetime.datetime
    invalid: bool = False
    summer_time: bool = False

    def encode(self) -> bytes:
        """Encode to 7-octet binary CP56Time2a (Little-Endian)."""
        ms = self.dt.second * 1000 + self.dt.microsecond // 1000
        ms_bytes = struct.pack("<H", ms & 0xFFFF)
        b2 = (self.dt.minute & 0x3F) | (0x80 if self.invalid else 0x00)
        b3 = (self.dt.hour & 0x1F) | (0x80 if self.summer_time else 0x00)
        dow = self.dt.isoweekday()  # 1=Monday..7=Sunday
        b4 = (self.dt.day & 0x1F) | ((dow & 0x07) << 5)
        b5 = self.dt.month & 0x0F
        b6 = (self.dt.year % 100) & 0x7F
        return ms_bytes + bytes([b2, b3, b4, b5, b6])

    @classmethod
    def decode(cls, data: bytes, century_base: int = 2000) -> CP56Time2a:
        """Decode 7 octets to CP56Time2a."""
        if len(data) < 7:
            raise ValueError(f"CP56Time2a requires 7 octets, got {len(data)}")
        ms = struct.unpack("<H", data[0:2])[0]
        second = ms // 1000
        microsecond = (ms % 1000) * 1000
        minute = data[2] & 0x3F
        invalid = bool(data[2] & 0x80)
        hour = data[3] & 0x1F
        summer_time = bool(data[3] & 0x80)
        day = data[4] & 0x1F
        month = data[5] & 0x0F
        year = century_base + (data[6] & 0x7F)
        dt = datetime.datetime(year, month, day, hour, minute, second, microsecond)
        return cls(dt=dt, invalid=invalid, summer_time=summer_time)


# --- IOA Helper ---

def pack_ioa(ioa: int) -> bytes:
    """Pack 24-bit IOA into 3 octets Little-Endian."""
    if not (0 <= ioa <= 0xFFFFFF):
        raise ValueError(f"IOA {ioa} exceeds 24-bit range (0..16777215)")
    return struct.pack("<I", ioa)[:3]


def unpack_ioa(data: bytes) -> int:
    """Unpack 3 octets Little-Endian into 24-bit IOA."""
    if len(data) < 3:
        raise ValueError("IOA requires 3 octets")
    return data[0] | (data[1] << 8) | (data[2] << 16)


# --- APCI Frame Dataclasses ---

@dataclass(frozen=True)
class IFrame:
    """I-Format (Information Transfer) Frame."""
    send_seq: int  # N(S): 0..32767
    recv_seq: int  # N(R): 0..32767
    asdu: bytes = b""

    @property
    def format(self) -> APCIFormat:
        return APCIFormat.I_FORMAT

    def serialize(self) -> bytes:
        cf1 = (self.send_seq << 1) & 0xFE
        cf2 = (self.send_seq >> 7) & 0xFF
        cf3 = (self.recv_seq << 1) & 0xFE
        cf4 = (self.recv_seq >> 7) & 0xFF
        length = 4 + len(self.asdu)
        return bytes([APCI_START_BYTE, length, cf1, cf2, cf3, cf4]) + self.asdu


@dataclass(frozen=True)
class SFrame:
    """S-Format (Numbered Supervisory) Frame."""
    recv_seq: int  # N(R): 0..32767

    @property
    def format(self) -> APCIFormat:
        return APCIFormat.S_FORMAT

    def serialize(self) -> bytes:
        cf3 = (self.recv_seq << 1) & 0xFE
        cf4 = (self.recv_seq >> 7) & 0xFF
        return bytes([APCI_START_BYTE, 0x04, 0x01, 0x00, cf3, cf4])


@dataclass(frozen=True)
class UFrame:
    """U-Format (Unnumbered Control) Frame."""
    function: UFunction

    @property
    def format(self) -> APCIFormat:
        return APCIFormat.U_FORMAT

    def serialize(self) -> bytes:
        return bytes([APCI_START_BYTE, 0x04, self.function.value, 0x00, 0x00, 0x00])


APCIFrame = Union[IFrame, SFrame, UFrame]


def deserialize_apci(data: bytes) -> APCIFrame:
    """Deserialize complete APDU packet into an APCIFrame instance."""
    if len(data) < 6:
        raise ValueError(f"Buffer too short for APCI: need >= 6 bytes, got {len(data)}")
    if data[0] != APCI_START_BYTE:
        raise ValueError(f"Invalid start octet: expected 0x68, got 0x{data[0]:02X}")

    length = data[1]
    if length < MIN_APCI_LENGTH or length > MAX_APDU_LENGTH:
        raise ValueError(f"Invalid APDU length field: {length}")

    expected_total = length + 2
    if len(data) < expected_total:
        raise ValueError(f"Truncated APDU buffer: length={length}, got {len(data)}")

    cf1, cf2, cf3, cf4 = data[2], data[3], data[4], data[5]

    # I-Format: bit 0 == 0
    if (cf1 & 0x01) == 0:
        send_seq = (cf1 | (cf2 << 8)) >> 1
        recv_seq = (cf3 | (cf4 << 8)) >> 1
        asdu = data[6:expected_total]
        return IFrame(send_seq=send_seq, recv_seq=recv_seq, asdu=asdu)

    # S-Format: bit 0 == 1, bit 1 == 0
    elif (cf1 & 0x03) == 0x01:
        recv_seq = (cf3 | (cf4 << 8)) >> 1
        return SFrame(recv_seq=recv_seq)

    # U-Format: bit 0 == 1, bit 1 == 1
    elif (cf1 & 0x03) == 0x03:
        func = UFunction(cf1)
        return UFrame(function=func)

    raise ValueError(f"Malformed APCI control fields: CF1=0x{cf1:02X}")


# --- ASDU Header & Payload Codecs ---

@dataclass
class ASDUHeader:
    """ASDU Data Unit Identifier (6 octets)."""
    type_id: int
    is_sequence: bool
    num_objects: int
    cause: int
    is_test: bool = False
    is_negative_confirm: bool = False
    originator_addr: int = 0
    common_addr: int = 1

    def encode(self) -> bytes:
        vsq = (self.num_objects & 0x7F) | (0x80 if self.is_sequence else 0x00)
        cot_b1 = (self.cause & 0x3F) | (0x40 if self.is_negative_confirm else 0x00) | (0x80 if self.is_test else 0x00)
        cot_b2 = self.originator_addr & 0xFF
        coa_bytes = struct.pack("<H", self.common_addr & 0xFFFF)
        return bytes([self.type_id, vsq, cot_b1, cot_b2]) + coa_bytes

    @classmethod
    def decode(cls, data: bytes) -> Tuple[ASDUHeader, bytes]:
        if len(data) < 6:
            raise ValueError(f"ASDU Header requires 6 octets, got {len(data)}")
        type_id = data[0]
        vsq = data[1]
        is_sequence = bool(vsq & 0x80)
        num_objects = vsq & 0x7F
        cot_b1 = data[2]
        cause = cot_b1 & 0x3F
        is_negative = bool(cot_b1 & 0x40)
        is_test = bool(cot_b1 & 0x80)
        originator_addr = data[3]
        common_addr = struct.unpack("<H", data[4:6])[0]
        return cls(
            type_id=type_id,
            is_sequence=is_sequence,
            num_objects=num_objects,
            cause=cause,
            is_test=is_test,
            is_negative_confirm=is_negative,
            originator_addr=originator_addr,
            common_addr=common_addr,
        ), data[6:]


@dataclass
class SIQ:
    """Single-Point Information with Quality (1 octet)."""
    value: bool
    blocked: bool = False
    substituted: bool = False
    not_topical: bool = False
    invalid: bool = False

    def encode(self) -> int:
        b = 1 if self.value else 0
        if self.blocked: b |= 0x10
        if self.substituted: b |= 0x20
        if self.not_topical: b |= 0x40
        if self.invalid: b |= 0x80
        return b

    @classmethod
    def decode(cls, b: int) -> SIQ:
        return cls(
            value=bool(b & 0x01),
            blocked=bool(b & 0x10),
            substituted=bool(b & 0x20),
            not_topical=bool(b & 0x40),
            invalid=bool(b & 0x80),
        )


@dataclass
class QDS:
    """Quality Descriptor for Measured Values (1 octet)."""
    overflow: bool = False
    blocked: bool = False
    substituted: bool = False
    not_topical: bool = False
    invalid: bool = False

    def encode(self) -> int:
        b = 0
        if self.overflow: b |= 0x01
        if self.blocked: b |= 0x10
        if self.substituted: b |= 0x20
        if self.not_topical: b |= 0x40
        if self.invalid: b |= 0x80
        return b

    @classmethod
    def decode(cls, b: int) -> QDS:
        return cls(
            overflow=bool(b & 0x01),
            blocked=bool(b & 0x10),
            substituted=bool(b & 0x20),
            not_topical=bool(b & 0x40),
            invalid=bool(b & 0x80),
        )


@dataclass
class SCO:
    """Single Command Qualifier (1 octet)."""
    state: bool            # True = ON/Close, False = OFF/Trip
    qualifier: int = 0     # 0=none, 1=short pulse, 2=long pulse, 3=persistent
    select: bool = False   # False = Execute, True = Select (SBO)

    def encode(self) -> int:
        b = 1 if self.state else 0
        b |= (self.qualifier & 0x1F) << 2
        if self.select: b |= 0x80
        return b

    @classmethod
    def decode(cls, b: int) -> SCO:
        return cls(
            state=bool(b & 0x01),
            qualifier=(b >> 2) & 0x1F,
            select=bool(b & 0x80),
        )


# ASDU Type Codecs
def encode_asdu_type1(objects: List[Tuple[int, SIQ]], is_sequence: bool = False, cause: int = 3, common_addr: int = 1) -> bytes:
    hdr = ASDUHeader(type_id=1, is_sequence=is_sequence, num_objects=len(objects), cause=cause, common_addr=common_addr)
    payload = bytearray(hdr.encode())
    if is_sequence:
        if objects:
            payload.extend(pack_ioa(objects[0][0]))
            for _, siq in objects:
                payload.append(siq.encode())
    else:
        for ioa, siq in objects:
            payload.extend(pack_ioa(ioa))
            payload.append(siq.encode())
    return bytes(payload)


def decode_asdu_type1(data: bytes) -> Tuple[ASDUHeader, List[Tuple[int, SIQ]]]:
    hdr, body = ASDUHeader.decode(data)
    objects: List[Tuple[int, SIQ]] = []
    if hdr.is_sequence:
        if hdr.num_objects > 0:
            base_ioa = unpack_ioa(body[0:3])
            for i in range(hdr.num_objects):
                objects.append((base_ioa + i, SIQ.decode(body[3 + i])))
    else:
        for i in range(hdr.num_objects):
            offset = i * 4
            ioa = unpack_ioa(body[offset:offset + 3])
            siq = SIQ.decode(body[offset + 3])
            objects.append((ioa, siq))
    return hdr, objects


def encode_asdu_type30(objects: List[Tuple[int, SIQ, CP56Time2a]], cause: int = 3, common_addr: int = 1) -> bytes:
    hdr = ASDUHeader(type_id=30, is_sequence=False, num_objects=len(objects), cause=cause, common_addr=common_addr)
    payload = bytearray(hdr.encode())
    for ioa, siq, ts in objects:
        payload.extend(pack_ioa(ioa))
        payload.append(siq.encode())
        payload.extend(ts.encode())
    return bytes(payload)


def decode_asdu_type30(data: bytes) -> Tuple[ASDUHeader, List[Tuple[int, SIQ, CP56Time2a]]]:
    hdr, body = ASDUHeader.decode(data)
    objects: List[Tuple[int, SIQ, CP56Time2a]] = []
    for i in range(hdr.num_objects):
        offset = i * 11
        ioa = unpack_ioa(body[offset:offset + 3])
        siq = SIQ.decode(body[offset + 3])
        ts = CP56Time2a.decode(body[offset + 4:offset + 11])
        objects.append((ioa, siq, ts))
    return hdr, objects


def encode_asdu_type13(objects: List[Tuple[int, float, QDS]], is_sequence: bool = False, cause: int = 3, common_addr: int = 1) -> bytes:
    hdr = ASDUHeader(type_id=13, is_sequence=is_sequence, num_objects=len(objects), cause=cause, common_addr=common_addr)
    payload = bytearray(hdr.encode())
    if is_sequence:
        if objects:
            payload.extend(pack_ioa(objects[0][0]))
            for _, val, qds in objects:
                payload.extend(struct.pack("<f", float(val)))
                payload.append(qds.encode())
    else:
        for ioa, val, qds in objects:
            payload.extend(pack_ioa(ioa))
            payload.extend(struct.pack("<f", float(val)))
            payload.append(qds.encode())
    return bytes(payload)


def decode_asdu_type13(data: bytes) -> Tuple[ASDUHeader, List[Tuple[int, float, QDS]]]:
    hdr, body = ASDUHeader.decode(data)
    objects: List[Tuple[int, float, QDS]] = []
    if hdr.is_sequence:
        if hdr.num_objects > 0:
            base_ioa = unpack_ioa(body[0:3])
            idx = 3
            for i in range(hdr.num_objects):
                val = struct.unpack("<f", body[idx:idx + 4])[0]
                qds = QDS.decode(body[idx + 4])
                objects.append((base_ioa + i, round(val, 5), qds))
                idx += 5
    else:
        for i in range(hdr.num_objects):
            offset = i * 8
            ioa = unpack_ioa(body[offset:offset + 3])
            val = struct.unpack("<f", body[offset + 3:offset + 7])[0]
            qds = QDS.decode(body[offset + 7])
            objects.append((ioa, round(val, 5), qds))
    return hdr, objects


def encode_asdu_type36(objects: List[Tuple[int, float, QDS, CP56Time2a]], cause: int = 3, common_addr: int = 1) -> bytes:
    hdr = ASDUHeader(type_id=36, is_sequence=False, num_objects=len(objects), cause=cause, common_addr=common_addr)
    payload = bytearray(hdr.encode())
    for ioa, val, qds, ts in objects:
        payload.extend(pack_ioa(ioa))
        payload.extend(struct.pack("<f", float(val)))
        payload.append(qds.encode())
        payload.extend(ts.encode())
    return bytes(payload)


def decode_asdu_type36(data: bytes) -> Tuple[ASDUHeader, List[Tuple[int, float, QDS, CP56Time2a]]]:
    hdr, body = ASDUHeader.decode(data)
    objects: List[Tuple[int, float, QDS, CP56Time2a]] = []
    for i in range(hdr.num_objects):
        offset = i * 15
        ioa = unpack_ioa(body[offset:offset + 3])
        val = struct.unpack("<f", body[offset + 3:offset + 7])[0]
        qds = QDS.decode(body[offset + 7])
        ts = CP56Time2a.decode(body[offset + 8:offset + 15])
        objects.append((ioa, round(val, 5), qds, ts))
    return hdr, objects


def encode_asdu_type45(ioa: int, sco: SCO, cause: int = 6, common_addr: int = 1) -> bytes:
    hdr = ASDUHeader(type_id=45, is_sequence=False, num_objects=1, cause=cause, common_addr=common_addr)
    return hdr.encode() + pack_ioa(ioa) + bytes([sco.encode()])


def decode_asdu_type45(data: bytes) -> Tuple[ASDUHeader, int, SCO]:
    hdr, body = ASDUHeader.decode(data)
    ioa = unpack_ioa(body[0:3])
    sco = SCO.decode(body[3])
    return hdr, ioa, sco


def encode_asdu_type100(qoi: int = 20, ioa: int = 0, cause: int = 6, common_addr: int = 1) -> bytes:
    hdr = ASDUHeader(type_id=100, is_sequence=False, num_objects=1, cause=cause, common_addr=common_addr)
    return hdr.encode() + pack_ioa(ioa) + bytes([qoi & 0xFF])


def decode_asdu_type100(data: bytes) -> Tuple[ASDUHeader, int, int]:
    hdr, body = ASDUHeader.decode(data)
    ioa = unpack_ioa(body[0:3])
    qoi = body[3]
    return hdr, ioa, qoi


# --- Pure IEC 61131-3 Structured Text POU Block ---

IEC104_SERVER_ST_CODE = """PROGRAM Iec104TelemetryServer
VAR
    StatusWord AT %R340 : INT;
    FramesReceivedCounter AT %R341 : UINT;
    FramesSentCounter AT %R342 : UINT;
    LastAsduTypeId AT %R343 : INT;
    MeasuredAnalogPV1 AT %R344 : INT;
    SingleCmdControlStatus AT %R345 : INT;

    EnableServer AT %M79 : BOOL;
    TriggerSpontaneous AT %M80 : BOOL;

    BitServerActive : BOOL;
    BitTcpConnected : BOOL;
    BitStartDtActive : BOOL;
    BitInterrogationRunning : BOOL;
    BitProtocolError : BOOL;
    BitSequenceError : BOOL;
    CalculatedStatus : INT;
END_VAR

IF NOT EnableServer THEN
    BitServerActive := FALSE;
    BitTcpConnected := FALSE;
    BitStartDtActive := FALSE;
    BitInterrogationRunning := FALSE;
    BitProtocolError := FALSE;
    BitSequenceError := FALSE;
    StatusWord := 0;
    SingleCmdControlStatus := 0;
ELSE
    BitServerActive := TRUE;

    IF MeasuredAnalogPV1 < 0 THEN
        MeasuredAnalogPV1 := 0;
    ELSIF MeasuredAnalogPV1 > 10000 THEN
        MeasuredAnalogPV1 := 10000;
    END_IF;

    IF TriggerSpontaneous THEN
        FramesSentCounter := FramesSentCounter + 1;
        TriggerSpontaneous := FALSE;
    END_IF;

    IF LastAsduTypeId = 100 THEN
        BitInterrogationRunning := TRUE;
        BitProtocolError := FALSE;
    ELSIF LastAsduTypeId = 45 THEN
        IF SingleCmdControlStatus = 2 THEN
            SingleCmdControlStatus := 1;
        ELSIF SingleCmdControlStatus = 1 THEN
            SingleCmdControlStatus := 0;
        END_IF;
        BitProtocolError := FALSE;
    ELSIF LastAsduTypeId = 0 THEN
        BitProtocolError := FALSE;
    ELSIF LastAsduTypeId <> 1 AND LastAsduTypeId <> 9 AND LastAsduTypeId <> 11 AND LastAsduTypeId <> 13 AND LastAsduTypeId <> 30 AND LastAsduTypeId <> 36 AND LastAsduTypeId <> 46 THEN
        BitProtocolError := TRUE;
    END_IF;

    CalculatedStatus := 0;
    IF BitServerActive THEN
        CalculatedStatus := CalculatedStatus + 1;
    END_IF;
    IF BitTcpConnected THEN
        CalculatedStatus := CalculatedStatus + 2;
    END_IF;
    IF BitStartDtActive THEN
        CalculatedStatus := CalculatedStatus + 4;
    END_IF;
    IF BitInterrogationRunning THEN
        CalculatedStatus := CalculatedStatus + 8;
    END_IF;
    IF BitProtocolError THEN
        CalculatedStatus := CalculatedStatus + 16;
    END_IF;
    IF BitSequenceError THEN
        CalculatedStatus := CalculatedStatus + 32;
    END_IF;

    StatusWord := CalculatedStatus;
END_IF;
END_PROGRAM"""


# --- IEC 104 Server Engine ---

class IEC104ServerEngine:
    """Pure-software IEC 60870-5-104 Telemetry Server Engine.

    Manages APCI sequence numbers, connection state, ASDU dispatch,
    and OCS register synchronization (%R340..%R345, %M79..%M80).
    """

    def __init__(self, common_addr: int = 1) -> None:
        self.common_addr = common_addr
        self.send_seq = 0
        self.recv_seq = 0
        self.is_connected = False
        self.startdt_active = False
        self.interrogation_running = False
        self.protocol_error = False
        self.sequence_error = False

        # Register states
        self.status_word: int = 0
        self.frames_received_counter: int = 0
        self.frames_sent_counter: int = 0
        self.last_asdu_type_id: int = 0
        self.measured_analog_pv1: int = 5000  # 50.00% default
        self.single_cmd_status: int = 0       # 0: Idle, 1: Execute, 2: Select
        self.enable_server: bool = True
        self.trigger_spontaneous: bool = False

    def reset_counters(self) -> None:
        """Reset sequence and frame counters."""
        self.send_seq = 0
        self.recv_seq = 0
        self.frames_received_counter = 0
        self.frames_sent_counter = 0

    def compute_status_word(self) -> int:
        """Synthesize 16-bit status word %R340."""
        st = 0
        if self.enable_server:
            st |= 0x0001  # Bit 0: Active
        if self.is_connected:
            st |= 0x0002  # Bit 1: TCP Connected
        if self.startdt_active:
            st |= 0x0004  # Bit 2: STARTDT Active
        if self.interrogation_running:
            st |= 0x0008  # Bit 3: Interrogation Running
        if self.protocol_error:
            st |= 0x0010  # Bit 4: Protocol Error
        if self.sequence_error:
            st |= 0x0020  # Bit 5: Sequence Error
        self.status_word = st
        return st

    def process_incoming_apdu(self, data: bytes) -> List[bytes]:
        """Process an inbound APDU and produce response APDUs."""
        if not self.enable_server:
            return []

        self.frames_received_counter += 1
        self.is_connected = True
        responses: List[bytes] = []

        try:
            frame = deserialize_apci(data)
        except Exception:
            self.protocol_error = True
            self.compute_status_word()
            return []

        if frame.format == APCIFormat.U_FORMAT:
            u_frame = frame  # type: ignore
            if u_frame.function == UFunction.STARTDT_ACT:
                self.startdt_active = True
                con = UFrame(function=UFunction.STARTDT_CON)
                responses.append(con.serialize())
                self.frames_sent_counter += 1
            elif u_frame.function == UFunction.STOPDT_ACT:
                self.startdt_active = False
                con = UFrame(function=UFunction.STOPDT_CON)
                responses.append(con.serialize())
                self.frames_sent_counter += 1
            elif u_frame.function == UFunction.TESTFR_ACT:
                con = UFrame(function=UFunction.TESTFR_CON)
                responses.append(con.serialize())
                self.frames_sent_counter += 1

        elif frame.format == APCIFormat.S_FORMAT:
            # Acknowledgment frame received
            pass

        elif frame.format == APCIFormat.I_FORMAT:
            i_frame = frame  # type: ignore
            expected_ns = self.recv_seq
            if i_frame.send_seq != expected_ns:
                self.sequence_error = True
            self.recv_seq = (i_frame.send_seq + 1) & MAX_SEQUENCE_NUMBER

            # Auto-respond with S-frame acknowledgment
            s_ack = SFrame(recv_seq=self.recv_seq)
            responses.append(s_ack.serialize())
            self.frames_sent_counter += 1

            if i_frame.asdu:
                hdr, body = ASDUHeader.decode(i_frame.asdu)
                self.last_asdu_type_id = hdr.type_id

                if hdr.type_id == 100:  # General Interrogation
                    self.interrogation_running = True
                    # 1. Interrogation Act Confirmation
                    act_con = encode_asdu_type100(qoi=20, ioa=0, cause=7, common_addr=self.common_addr)
                    iframe_con = IFrame(send_seq=self.send_seq, recv_seq=self.recv_seq, asdu=act_con)
                    responses.append(iframe_con.serialize())
                    self.send_seq = (self.send_seq + 1) & MAX_SEQUENCE_NUMBER
                    self.frames_sent_counter += 1

                    # 2. Transmit Monitored Data (Type 1 and Type 13)
                    sp_data = encode_asdu_type1(
                        objects=[(1001, SIQ(value=self.startdt_active))],
                        is_sequence=False,
                        cause=20,
                        common_addr=self.common_addr,
                    )
                    iframe_sp = IFrame(send_seq=self.send_seq, recv_seq=self.recv_seq, asdu=sp_data)
                    responses.append(iframe_sp.serialize())
                    self.send_seq = (self.send_seq + 1) & MAX_SEQUENCE_NUMBER
                    self.frames_sent_counter += 1

                    me_data = encode_asdu_type13(
                        objects=[(2001, float(self.measured_analog_pv1) / 100.0, QDS())],
                        is_sequence=False,
                        cause=20,
                        common_addr=self.common_addr,
                    )
                    iframe_me = IFrame(send_seq=self.send_seq, recv_seq=self.recv_seq, asdu=me_data)
                    responses.append(iframe_me.serialize())
                    self.send_seq = (self.send_seq + 1) & MAX_SEQUENCE_NUMBER
                    self.frames_sent_counter += 1

                    # 3. Interrogation Termination
                    act_term = encode_asdu_type100(qoi=20, ioa=0, cause=10, common_addr=self.common_addr)
                    iframe_term = IFrame(send_seq=self.send_seq, recv_seq=self.recv_seq, asdu=act_term)
                    responses.append(iframe_term.serialize())
                    self.send_seq = (self.send_seq + 1) & MAX_SEQUENCE_NUMBER
                    self.frames_sent_counter += 1
                    self.interrogation_running = False

                elif hdr.type_id == 45:  # Single Command
                    _, ioa, sco = decode_asdu_type45(i_frame.asdu)
                    if sco.select:
                        self.single_cmd_status = 2  # Select
                    else:
                        self.single_cmd_status = 1  # Execute

                    # Act Confirmation
                    resp_asdu = encode_asdu_type45(ioa=ioa, sco=sco, cause=7, common_addr=self.common_addr)
                    iframe_cmd = IFrame(send_seq=self.send_seq, recv_seq=self.recv_seq, asdu=resp_asdu)
                    responses.append(iframe_cmd.serialize())
                    self.send_seq = (self.send_seq + 1) & MAX_SEQUENCE_NUMBER
                    self.frames_sent_counter += 1

        self.compute_status_word()
        return responses

    def emit_spontaneous_event(self, ioa: int = 1001, value: bool = True) -> bytes:
        """Emit a spontaneous event (ASDU Type 30 with CP56Time2a timestamp)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        ts = CP56Time2a(dt=now)
        asdu = encode_asdu_type30(
            objects=[(ioa, SIQ(value=value), ts)],
            cause=3,  # Spontaneous
            common_addr=self.common_addr,
        )
        iframe = IFrame(send_seq=self.send_seq, recv_seq=self.recv_seq, asdu=asdu)
        self.send_seq = (self.send_seq + 1) & MAX_SEQUENCE_NUMBER
        self.frames_sent_counter += 1
        self.compute_status_word()
        return iframe.serialize()

    def sync_to_registers(self, reg_table: Any) -> None:
        """Write current engine state to OCS RegisterTable."""
        self.compute_status_word()
        write_fn = getattr(reg_table, "write_register", getattr(reg_table, "write", None))
        if write_fn:
            write_fn("%R340", self.status_word)
            write_fn("%R341", self.frames_received_counter & 0xFFFF)
            write_fn("%R342", self.frames_sent_counter & 0xFFFF)
            write_fn("%R343", self.last_asdu_type_id)
            write_fn("%R344", self.measured_analog_pv1)
            write_fn("%R345", self.single_cmd_status)
            write_fn("%M79", self.enable_server)
            write_fn("%M80", self.trigger_spontaneous)

    def sync_from_registers(self, reg_table: Any) -> None:
        """Read engine parameters and command triggers from OCS RegisterTable."""
        read_fn = getattr(reg_table, "read_register", getattr(reg_table, "read", None))
        write_fn = getattr(reg_table, "write_register", getattr(reg_table, "write", None))
        if read_fn:
            self.enable_server = bool(read_fn("%M79"))
            spont_req = bool(read_fn("%M80"))
            if spont_req:
                self.emit_spontaneous_event()
                if write_fn:
                    write_fn("%M80", False)
            pv1 = read_fn("%R344")
            if isinstance(pv1, (int, float)):
                self.measured_analog_pv1 = max(0, min(10000, int(pv1)))
        self.compute_status_word()
        if write_fn:
            write_fn("%R340", self.status_word)
            write_fn("%R341", self.frames_received_counter & 0xFFFF)
            write_fn("%R342", self.frames_sent_counter & 0xFFFF)
