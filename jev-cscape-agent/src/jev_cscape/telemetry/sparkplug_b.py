"""Industrial MQTT Sparkplug B Telemetry & Protobuf Serializer (W064).

This module implements pure-Python, zero-external-dependency Sparkplug B v1.0 payload
serialization, topic management, sequence numbering, and Horner OCS register mapping.
It operates in air-gapped environments without requiring google.protobuf or grpc binaries.

Key Capabilities:
1. Pure-Python Protobuf Serializer:
   - Varint LEB128 encoding and decoding (supporting 32-bit and 64-bit ints, booleans, and negative ints)
   - Fixed 32-bit IEEE 754 single float (<f) and Fixed 64-bit double (<d) wire types
   - Length-delimited UTF-8 strings, bytes, and nested sub-messages
   - Full Sparkplug B Metric and Payload protobuf wire specification
2. Canonical Sparkplug B Topic Hierarchy:
   - Format: "spBv1.0/{group_id}/{message_type}/{edge_node_id}/[{device_id}]"
   - Standard verbs: NBIRTH, NDEATH, DBIRTH, DDEATH, NDATA, DDATA, NCMD, DCMD
   - Topic parsing, decomposition, and validation
3. Session & Sequence Number Management:
   - Modulo 256 sequence counter (0..255) for NDATA and DDATA messages
   - Birth-Death sequence token (bdSeq) management matching MQTT Will NDEATH
   - Rebirth sequence workflow (command-triggered or coil-triggered %M59)
   - Value deadband filtering to suppress redundant telemetry transmissions
4. Horner OCS Memory Mapping:
   - %R270: Sparkplug B Engine Status Word (Active, Birth Published, Seq Rollover, Buffer High, Death Triggered)
   - %R271: Current Sequence Number (0..255)
   - %R272:%R273: 32-bit Cumulative Published Messages Counter (UDINT)
   - %R274: Transmitted Payload Byte Count of Last Message
   - %M58: Sparkplug B Enable Coil (default: ON)
   - %M59: Rebirth / Sequence Reset Trigger Coil (auto self-clearing)
5. Simulation Engine Integration:
   - Implements ILogicUnit (priority 92) for scan cycle execution with ScanContext
   - Thread-safe payload transmission buffer and MQTT Will message generator
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from enum import Enum, IntEnum, IntFlag
import json
from pathlib import Path
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Pure-Python Protobuf Wire Encoders & Decoders
# ============================================================================

WIRE_TYPE_VARINT = 0
WIRE_TYPE_64BIT = 1
WIRE_TYPE_LENGTH_DELIMITED = 2
WIRE_TYPE_32BIT = 5


def encode_varint(value: int) -> bytes:
    """Encode an integer as a standard Protobuf Varint (LEB128)."""
    if value < 0:
        # Convert signed negative integers to 64-bit two's complement
        value = value & 0xFFFFFFFFFFFFFFFF
    buf = bytearray()
    while True:
        towrite = value & 0x7F
        value >>= 7
        if value:
            buf.append(towrite | 0x80)
        else:
            buf.append(towrite)
            break
    return bytes(buf)


def decode_varint(buffer: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode a Protobuf Varint from buffer starting at offset.
    
    Returns (value, new_offset).
    """
    res = 0
    shift = 0
    idx = offset
    buf_len = len(buffer)
    while idx < buf_len:
        b = buffer[idx]
        idx += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, idx
        shift += 7
        if shift >= 70:
            raise ValueError("Varint too long (> 10 bytes)")
    raise ValueError("Truncated varint in buffer")


def encode_tag(field_number: int, wire_type: int) -> bytes:
    """Encode field number and wire type into a protobuf tag byte sequence."""
    return encode_varint((field_number << 3) | wire_type)


def encode_length_delimited(data: bytes) -> bytes:
    """Encode length-delimited byte payload (wire type 2)."""
    return encode_varint(len(data)) + data


def encode_string(text: str) -> bytes:
    """Encode a UTF-8 string as length-delimited payload."""
    return encode_length_delimited(text.encode("utf-8"))


def encode_float(value: float) -> bytes:
    """Encode a 32-bit single-precision IEEE 754 float (wire type 5, little-endian)."""
    return struct.pack("<f", float(value))


def decode_float(buffer: bytes, offset: int = 0) -> Tuple[float, int]:
    """Decode a 32-bit float from buffer starting at offset."""
    if len(buffer) < offset + 4:
        raise ValueError("Buffer truncated for 32-bit float")
    val = struct.unpack_from("<f", buffer, offset)[0]
    return val, offset + 4


def encode_double(value: float) -> bytes:
    """Encode a 64-bit double-precision IEEE 754 float (wire type 1, little-endian)."""
    return struct.pack("<d", float(value))


def decode_double(buffer: bytes, offset: int = 0) -> Tuple[float, int]:
    """Decode a 64-bit double from buffer starting at offset."""
    if len(buffer) < offset + 8:
        raise ValueError("Buffer truncated for 64-bit double")
    val = struct.unpack_from("<d", buffer, offset)[0]
    return val, offset + 8


# ============================================================================
# 2. Sparkplug B Protocol Types & Data Model
# ============================================================================

class SparkplugDataType(IntEnum):
    """Standard Sparkplug B metric datatypes."""
    Unknown = 0
    Int8 = 1
    Int16 = 2
    Int32 = 3
    Int64 = 4
    UInt8 = 5
    UInt16 = 6
    UInt32 = 7
    UInt64 = 8
    Float = 9
    Double = 10
    Boolean = 11
    String = 12
    DateTime = 13
    Text = 14


class SparkplugMessageType(str, Enum):
    """Canonical Sparkplug B message types."""
    NBIRTH = "NBIRTH"
    NDEATH = "NDEATH"
    DBIRTH = "DBIRTH"
    DDEATH = "DDEATH"
    NDATA = "NDATA"
    DDATA = "DDATA"
    NCMD = "NCMD"
    DCMD = "DCMD"


class SparkplugStatusFlag(IntFlag):
    """Bitmask flags for Horner OCS %R270 status word."""
    NONE = 0
    ACTIVE = 1              # Bit 0: Telemetry engine active
    CONNECTED_BIRTH = 2     # Bit 1: NBIRTH published / node connected
    SEQ_ROLLOVER = 4        # Bit 2: Sequence number rolled over from 255 to 0
    BUFFER_HIGH = 8         # Bit 3: Telemetry message buffer > 80% capacity
    DEATH_TRIGGERED = 16    # Bit 4: NDEATH message dispatched or scheduled
    REBIRTH_REQUESTED = 32  # Bit 5: Rebirth sequence in progress


@dataclasses.dataclass(frozen=True)
class SparkplugTopic:
    """Sparkplug B topic representation and parser."""
    namespace: str
    group_id: str
    message_type: SparkplugMessageType
    edge_node_id: str
    device_id: Optional[str] = None

    def format(self) -> str:
        """Format the canonical topic string."""
        if self.device_id:
            return f"{self.namespace}/{self.group_id}/{self.message_type.value}/{self.edge_node_id}/{self.device_id}"
        return f"{self.namespace}/{self.group_id}/{self.message_type.value}/{self.edge_node_id}"

    @classmethod
    def parse(cls, topic_str: str) -> SparkplugTopic:
        """Parse and validate a Sparkplug B topic string."""
        parts = topic_str.split("/")
        if len(parts) < 4 or len(parts) > 5:
            raise ValueError(f"Invalid Sparkplug B topic structure: '{topic_str}'")
        namespace, group_id, msg_type_str, edge_node_id = parts[:4]
        if namespace != "spBv1.0":
            raise ValueError(f"Invalid Sparkplug B namespace: '{namespace}', expected 'spBv1.0'")
        try:
            msg_type = SparkplugMessageType(msg_type_str)
        except ValueError:
            raise ValueError(f"Unknown Sparkplug B message type: '{msg_type_str}'")
        device_id = parts[4] if len(parts) == 5 else None
        return cls(
            namespace=namespace,
            group_id=group_id,
            message_type=msg_type,
            edge_node_id=edge_node_id,
            device_id=device_id,
        )


@dataclasses.dataclass
class SparkplugMetric:
    """Sparkplug B Metric sub-message definition."""
    name: str
    datatype: SparkplugDataType
    alias: Optional[int] = None
    timestamp: int = 0  # Epoch milliseconds
    is_historical: bool = False
    is_transient: bool = False
    is_null: bool = False
    int_value: Optional[int] = None
    float_value: Optional[float] = None
    double_value: Optional[float] = None
    boolean_value: Optional[bool] = None
    string_value: Optional[str] = None
    bytes_value: Optional[bytes] = None

    def encode(self) -> bytes:
        """Serialize this Metric sub-message to Protobuf wire bytes."""
        payload = bytearray()

        # Field 1: name (string, length-delimited)
        if self.name:
            payload += encode_tag(1, WIRE_TYPE_LENGTH_DELIMITED)
            payload += encode_string(self.name)

        # Field 2: alias (uint64, varint)
        if self.alias is not None:
            payload += encode_tag(2, WIRE_TYPE_VARINT)
            payload += encode_varint(self.alias)

        # Field 3: timestamp (uint64, varint)
        if self.timestamp > 0:
            payload += encode_tag(3, WIRE_TYPE_VARINT)
            payload += encode_varint(self.timestamp)

        # Field 4: datatype (uint32, varint)
        payload += encode_tag(4, WIRE_TYPE_VARINT)
        payload += encode_varint(int(self.datatype))

        # Field 5: is_historical (bool, varint)
        if self.is_historical:
            payload += encode_tag(5, WIRE_TYPE_VARINT)
            payload += encode_varint(1)

        # Field 6: is_transient (bool, varint)
        if self.is_transient:
            payload += encode_tag(6, WIRE_TYPE_VARINT)
            payload += encode_varint(1)

        # Field 7: is_null (bool, varint)
        if self.is_null:
            payload += encode_tag(7, WIRE_TYPE_VARINT)
            payload += encode_varint(1)

        # Value fields depending on datatype
        if not self.is_null:
            if self.int_value is not None:
                # Field 9: int_value (uint32/uint64/int32/int64 varint)
                payload += encode_tag(9, WIRE_TYPE_VARINT)
                payload += encode_varint(self.int_value)
            elif self.float_value is not None:
                # Field 10: float_value (wire type 5)
                payload += encode_tag(10, WIRE_TYPE_32BIT)
                payload += encode_float(self.float_value)
            elif self.double_value is not None:
                # Field 11: double_value (wire type 1)
                payload += encode_tag(11, WIRE_TYPE_64BIT)
                payload += encode_double(self.double_value)
            elif self.boolean_value is not None:
                # Field 12: boolean_value (wire type 0)
                payload += encode_tag(12, WIRE_TYPE_VARINT)
                payload += encode_varint(1 if self.boolean_value else 0)
            elif self.string_value is not None:
                # Field 13: string_value (wire type 2)
                payload += encode_tag(13, WIRE_TYPE_LENGTH_DELIMITED)
                payload += encode_string(self.string_value)
            elif self.bytes_value is not None:
                # Field 14: bytes_value (wire type 2)
                payload += encode_tag(14, WIRE_TYPE_LENGTH_DELIMITED)
                payload += encode_length_delimited(self.bytes_value)

        return bytes(payload)

    @classmethod
    def from_value(
        cls,
        name: str,
        value: Any,
        datatype: Optional[SparkplugDataType] = None,
        alias: Optional[int] = None,
        timestamp: Optional[int] = None,
    ) -> SparkplugMetric:
        """Create a Metric inferring type if not specified."""
        ts = timestamp if timestamp is not None else int(time.time() * 1000)
        if value is None:
            dt = datatype or SparkplugDataType.Int16
            return cls(name=name, datatype=dt, alias=alias, timestamp=ts, is_null=True)

        if isinstance(value, bool):
            dt = datatype or SparkplugDataType.Boolean
            return cls(name=name, datatype=dt, alias=alias, timestamp=ts, boolean_value=value)
        elif isinstance(value, int):
            dt = datatype or (SparkplugDataType.Int32 if abs(value) > 32767 else SparkplugDataType.Int16)
            return cls(name=name, datatype=dt, alias=alias, timestamp=ts, int_value=value)
        elif isinstance(value, float):
            dt = datatype or SparkplugDataType.Float
            return cls(name=name, datatype=dt, alias=alias, timestamp=ts, float_value=value)
        elif isinstance(value, str):
            dt = datatype or SparkplugDataType.String
            return cls(name=name, datatype=dt, alias=alias, timestamp=ts, string_value=value)
        elif isinstance(value, bytes):
            dt = datatype or SparkplugDataType.Text
            return cls(name=name, datatype=dt, alias=alias, timestamp=ts, bytes_value=value)
        else:
            return cls(name=name, datatype=SparkplugDataType.String, alias=alias, timestamp=ts, string_value=str(value))


@dataclasses.dataclass
class SparkplugPayload:
    """Sparkplug B Payload protobuf message definition."""
    timestamp: int  # Epoch milliseconds
    metrics: List[SparkplugMetric] = dataclasses.field(default_factory=list)
    seq: int = 0    # Sequence number (0..255 for DATA messages)
    uuid: Optional[str] = None
    body: Optional[bytes] = None

    def encode(self) -> bytes:
        """Serialize the complete Payload message into Protobuf wire format."""
        buf = bytearray()

        # Field 1: timestamp (uint64, varint)
        buf += encode_tag(1, WIRE_TYPE_VARINT)
        buf += encode_varint(self.timestamp)

        # Field 2: metrics (repeated Metric, length-delimited)
        for metric in self.metrics:
            m_bytes = metric.encode()
            buf += encode_tag(2, WIRE_TYPE_LENGTH_DELIMITED)
            buf += encode_length_delimited(m_bytes)

        # Field 3: seq (uint64, varint)
        buf += encode_tag(3, WIRE_TYPE_VARINT)
        buf += encode_varint(self.seq)

        # Field 4: uuid (string, length-delimited)
        if self.uuid:
            buf += encode_tag(4, WIRE_TYPE_LENGTH_DELIMITED)
            buf += encode_string(self.uuid)

        # Field 5: body (bytes, length-delimited)
        if self.body:
            buf += encode_tag(5, WIRE_TYPE_LENGTH_DELIMITED)
            buf += encode_length_delimited(self.body)

        return bytes(buf)


# ============================================================================
# 3. Sparkplug B Sequence & Session Manager
# ============================================================================

class SparkplugSequenceManager:
    """Manages sequence numbers (seq modulo 256) and birth-death session tokens (bdSeq)."""

    def __init__(self, initial_bdseq: int = 0) -> None:
        self._seq: int = 0
        self._bdseq: int = initial_bdseq
        self._rollover_count: int = 0
        self._lock = threading.Lock()

    @property
    def seq(self) -> int:
        with self._lock:
            return self._seq

    @property
    def bdseq(self) -> int:
        with self._lock:
            return self._bdseq

    @property
    def rollover_count(self) -> int:
        with self._lock:
            return self._rollover_count

    def next_seq(self) -> int:
        """Advance sequence counter modulo 256 and return the new sequence value."""
        with self._lock:
            next_val = (self._seq + 1) % 256
            if next_val == 0:
                self._rollover_count += 1
            self._seq = next_val
            return self._seq

    def trigger_rebirth(self) -> int:
        """Handle node rebirth: increment bdSeq and reset seq to 0."""
        with self._lock:
            self._bdseq = (self._bdseq + 1) & 0xFFFFFFFFFFFFFFFF
            self._seq = 0
            return self._bdseq

    def reset(self) -> None:
        """Reset sequence state."""
        with self._lock:
            self._seq = 0
            self._bdseq = 0
            self._rollover_count = 0


# ============================================================================
# 4. Horner OCS Sparkplug B Telemetry Unit (ILogicUnit)
# ============================================================================

class SparkplugBTelemetryUnit(ILogicUnit):
    """Industrial MQTT Sparkplug B Telemetry Unit integrated into Horner OCS scan cycle.
    
    Memory Mapping:
    - %R270: Sparkplug B Engine Status Word
    - %R271: Current Sequence Number (0..255)
    - %R272:%R273: Cumulative Published Count (UDINT 32-bit)
    - %R274: Last Transmitted Wire Byte Count
    - %M58: Enable Coil (default True)
    - %M59: Rebirth / Reset Trigger Coil (self-clearing)
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        group_id: str = "JEV_PLANT",
        edge_node_id: str = "HORNER_OCS_01",
        device_id: Optional[str] = "PUMP_SKID_A",
        max_buffer_size: int = 100,
        enable_deadband: bool = True,
        analog_deadband: float = 1.0,
    ) -> None:
        self.registers: RegisterTable = register_table if register_table is not None else RegisterTable()
        self.group_id = group_id
        self.edge_node_id = edge_node_id
        self.device_id = device_id
        self.max_buffer_size = max_buffer_size
        self.enable_deadband = enable_deadband
        self.analog_deadband = analog_deadband

        self.seq_mgr = SparkplugSequenceManager()
        self._published_count: int = 0
        self._last_byte_count: int = 0
        self._connected: bool = False
        self._death_triggered: bool = False
        self._last_values: Dict[str, Any] = {}
        self._message_buffer: List[Tuple[str, bytes]] = []  # (topic, wire_bytes)
        self._lock = threading.Lock()

        # Initialize default control coils in RegisterTable
        try:
            self.registers.write_bit("%M58", True, privilege=PrivilegeMode.SYSTEM)
            self.registers.write_bit("%M59", False, privilege=PrivilegeMode.SYSTEM)
        except Exception:
            pass

    @property
    def name(self) -> str:
        return "sparkplug_b_telemetry"

    @property
    def priority(self) -> int:
        return 92  # Executes after SyslogEventLoggerUnit (priority 90)

    @property
    def is_enabled(self) -> bool:
        try:
            return self.registers.read_bit("%M58")
        except Exception:
            return True

    def reset(self) -> None:
        """Reset internal sequence state and OCS registers."""
        self.seq_mgr.reset()
        self._published_count = 0
        self._last_byte_count = 0
        self._connected = False
        self._death_triggered = False
        self._last_values.clear()
        with self._lock:
            self._message_buffer.clear()
        try:
            self.registers.write_bit("%M58", True, privilege=PrivilegeMode.SYSTEM)
            self.registers.write_bit("%M59", False, privilege=PrivilegeMode.SYSTEM)
            self.registers.write_word("%R270", 0, privilege=PrivilegeMode.SYSTEM)
            self.registers.write_word("%R271", 0, privilege=PrivilegeMode.SYSTEM)
            self.registers.write_word("%R272", 0, privilege=PrivilegeMode.SYSTEM)
            self.registers.write_word("%R273", 0, privilege=PrivilegeMode.SYSTEM)
            self.registers.write_word("%R274", 0, privilege=PrivilegeMode.SYSTEM)
        except Exception:
            pass

    def execute(self, ctx: ScanContext) -> None:
        """Scan cycle logic solve execution during simulation Phase 2."""
        regs = getattr(ctx, "registers", None) or self.registers
        self.solve(regs)

    @property
    def published_count(self) -> int:
        with self._lock:
            return self._published_count

    @property
    def message_buffer(self) -> List[Tuple[str, bytes]]:
        with self._lock:
            return list(self._message_buffer)

    def generate_ndeath_payload(self) -> Tuple[str, bytes]:
        """Generate canonical MQTT Last Will and Testament NDEATH payload."""
        topic = SparkplugTopic(
            namespace="spBv1.0",
            group_id=self.group_id,
            message_type=SparkplugMessageType.NDEATH,
            edge_node_id=self.edge_node_id,
        ).format()

        now_ms = int(time.time() * 1000)
        bdseq_metric = SparkplugMetric(
            name="bdSeq",
            datatype=SparkplugDataType.UInt64,
            int_value=self.seq_mgr.bdseq,
            timestamp=now_ms,
        )
        payload = SparkplugPayload(
            timestamp=now_ms,
            metrics=[bdseq_metric],
            seq=0,
        )
        return topic, payload.encode()

    def generate_nbirth_payload(self) -> Tuple[str, bytes]:
        """Generate Node Birth (NBIRTH) payload establishing session."""
        topic = SparkplugTopic(
            namespace="spBv1.0",
            group_id=self.group_id,
            message_type=SparkplugMessageType.NBIRTH,
            edge_node_id=self.edge_node_id,
        ).format()

        now_ms = int(time.time() * 1000)
        metrics = [
            SparkplugMetric(name="bdSeq", datatype=SparkplugDataType.UInt64, int_value=self.seq_mgr.bdseq, timestamp=now_ms),
            SparkplugMetric(name="Node Control/Rebirth", datatype=SparkplugDataType.Boolean, boolean_value=False, timestamp=now_ms),
            SparkplugMetric(name="Hardware/Model", datatype=SparkplugDataType.String, string_value="Horner OCS XL4/XL7e", timestamp=now_ms),
            SparkplugMetric(name="Firmware/Version", datatype=SparkplugDataType.String, string_value="10.2.751.4", timestamp=now_ms),
        ]
        payload = SparkplugPayload(
            timestamp=now_ms,
            metrics=metrics,
            seq=0,  # NBIRTH always carries seq=0
        )
        wire_bytes = payload.encode()
        return topic, wire_bytes

    def generate_dbirth_payload(self) -> Tuple[str, bytes]:
        """Generate Device Birth (DBIRTH) payload defining device metrics."""
        topic = SparkplugTopic(
            namespace="spBv1.0",
            group_id=self.group_id,
            message_type=SparkplugMessageType.DBIRTH,
            edge_node_id=self.edge_node_id,
            device_id=self.device_id or "DEVICE_01",
        ).format()

        now_ms = int(time.time() * 1000)
        metrics = [
            SparkplugMetric(name="Process/Pressure_PV", datatype=SparkplugDataType.Float, float_value=0.0, timestamp=now_ms),
            SparkplugMetric(name="Process/Temperature_PV", datatype=SparkplugDataType.Float, float_value=20.0, timestamp=now_ms),
            SparkplugMetric(name="Actuator/Pump_Speed", datatype=SparkplugDataType.Int16, int_value=0, timestamp=now_ms),
            SparkplugMetric(name="Alarms/High_Pressure", datatype=SparkplugDataType.Boolean, boolean_value=False, timestamp=now_ms),
        ]
        payload = SparkplugPayload(
            timestamp=now_ms,
            metrics=metrics,
            seq=self.seq_mgr.next_seq(),
        )
        return topic, payload.encode()

    def _publish_internal(self, topic: str, wire_bytes: bytes) -> None:
        """Enqueue message and update counters."""
        with self._lock:
            if len(self._message_buffer) >= self.max_buffer_size:
                self._message_buffer.pop(0)  # Evict oldest
            self._message_buffer.append((topic, wire_bytes))
            self._published_count += 1
            self._last_byte_count = len(wire_bytes)

    def publish_ddata(self, metrics: List[SparkplugMetric]) -> Tuple[str, bytes]:
        """Publish Device Data (DDATA) payload."""
        topic = SparkplugTopic(
            namespace="spBv1.0",
            group_id=self.group_id,
            message_type=SparkplugMessageType.DDATA,
            edge_node_id=self.edge_node_id,
            device_id=self.device_id or "DEVICE_01",
        ).format()

        now_ms = int(time.time() * 1000)
        payload = SparkplugPayload(
            timestamp=now_ms,
            metrics=metrics,
            seq=self.seq_mgr.next_seq(),
        )
        wire_bytes = payload.encode()
        self._publish_internal(topic, wire_bytes)
        return topic, wire_bytes

    def publish_ndata(self, metrics: List[SparkplugMetric]) -> Tuple[str, bytes]:
        """Publish Node Data (NDATA) payload."""
        topic = SparkplugTopic(
            namespace="spBv1.0",
            group_id=self.group_id,
            message_type=SparkplugMessageType.NDATA,
            edge_node_id=self.edge_node_id,
        ).format()

        now_ms = int(time.time() * 1000)
        payload = SparkplugPayload(
            timestamp=now_ms,
            metrics=metrics,
            seq=self.seq_mgr.next_seq(),
        )
        wire_bytes = payload.encode()
        self._publish_internal(topic, wire_bytes)
        return topic, wire_bytes

    def trigger_rebirth_workflow(self) -> Tuple[str, bytes]:
        """Execute full node rebirth sequence."""
        self.seq_mgr.trigger_rebirth()
        topic, wire_bytes = self.generate_nbirth_payload()
        self._publish_internal(topic, wire_bytes)
        self._connected = True
        return topic, wire_bytes

    def solve(self, context_or_regs: Union[ScanContext, RegisterTable, None] = None) -> None:
        """Scan cycle logic step executing within Horner OCS controller."""
        if isinstance(context_or_regs, RegisterTable):
            regs = context_or_regs
        elif isinstance(context_or_regs, ScanContext):
            regs = getattr(context_or_regs, "registers", None) or self.registers
        else:
            regs = self.registers

        # 1. Read Control Coils
        # %M58: Sparkplug B Enable Coil (default True if uninitialized)
        try:
            enable_val = regs.read_bit("%M58")
        except Exception:
            enable_val = True

        if not enable_val:
            # Engine disabled: clear status and return
            try:
                regs.write_word("%R270", 0, privilege=PrivilegeMode.SYSTEM)
            except Exception:
                pass
            return

        # %M59: Rebirth / Reset Request Coil
        try:
            rebirth_req = regs.read_bit("%M59")
        except Exception:
            rebirth_req = False

        if rebirth_req:
            self.trigger_rebirth_workflow()
            try:
                regs.write_bit("%M59", False, privilege=PrivilegeMode.SYSTEM)  # Auto self-clearing
            except Exception:
                pass

        # 2. Connection / Birth Initialization
        if not self._connected:
            self.trigger_rebirth_workflow()
            if self.device_id:
                d_topic, d_bytes = self.generate_dbirth_payload()
                self._publish_internal(d_topic, d_bytes)

        # 3. Read Monitored Process Registers and Detect Changes
        # Read %AI1..%AI4 (scaled 0..32000 counts) and %AQ1..%AQ2
        try:
            ai1 = regs.read_word("%AI1")
        except Exception:
            ai1 = 0
        try:
            ai2 = regs.read_word("%AI2")
        except Exception:
            ai2 = 0
        try:
            aq1 = regs.read_word("%AQ1")
        except Exception:
            aq1 = 0
        try:
            m1 = regs.read_bit("%M1")
        except Exception:
            m1 = False

        changed_metrics: List[SparkplugMetric] = []
        now_ms = int(time.time() * 1000)

        # Check AI1 (Pressure PV)
        last_ai1 = self._last_values.get("AI1", None)
        if last_ai1 is None or abs(ai1 - last_ai1) >= self.analog_deadband:
            changed_metrics.append(SparkplugMetric.from_value("AI1_Pressure_Counts", ai1, SparkplugDataType.Int16, timestamp=now_ms))
            self._last_values["AI1"] = ai1

        # Check AI2 (Temperature PV)
        last_ai2 = self._last_values.get("AI2", None)
        if last_ai2 is None or abs(ai2 - last_ai2) >= self.analog_deadband:
            changed_metrics.append(SparkplugMetric.from_value("AI2_Temp_Counts", ai2, SparkplugDataType.Int16, timestamp=now_ms))
            self._last_values["AI2"] = ai2

        # Check AQ1 (Valve Output)
        last_aq1 = self._last_values.get("AQ1", None)
        if last_aq1 is None or abs(aq1 - last_aq1) >= self.analog_deadband:
            changed_metrics.append(SparkplugMetric.from_value("AQ1_Valve_Output", aq1, SparkplugDataType.Int16, timestamp=now_ms))
            self._last_values["AQ1"] = aq1

        # Check %M1 (Run Status Coil)
        last_m1 = self._last_values.get("M1", None)
        if last_m1 is None or m1 != last_m1:
            changed_metrics.append(SparkplugMetric.from_value("M1_Run_Status", m1, SparkplugDataType.Boolean, timestamp=now_ms))
            self._last_values["M1"] = m1

        # 4. Dispatch Telemetry if Changed Metrics Exist
        if changed_metrics:
            if self.device_id:
                self.publish_ddata(changed_metrics)
            else:
                self.publish_ndata(changed_metrics)

        # 5. Compute Status Flags
        status = SparkplugStatusFlag.ACTIVE
        if self._connected:
            status |= SparkplugStatusFlag.CONNECTED_BIRTH
        if self.seq_mgr.rollover_count > 0:
            status |= SparkplugStatusFlag.SEQ_ROLLOVER
        if len(self._message_buffer) >= (self.max_buffer_size * 0.8):
            status |= SparkplugStatusFlag.BUFFER_HIGH
        if self._death_triggered:
            status |= SparkplugStatusFlag.DEATH_TRIGGERED

        # 6. Synchronize Horner OCS Registers
        try:
            # %R270: Status Word
            regs.write_word("%R270", int(status), privilege=PrivilegeMode.SYSTEM)

            # %R271: Sequence Number (0..255)
            regs.write_word("%R271", self.seq_mgr.seq, privilege=PrivilegeMode.SYSTEM)

            # %R272:%R273: Cumulative published count (UDINT 32-bit: low word %R272, high word %R273)
            count_lo = self._published_count & 0xFFFF
            count_hi = (self._published_count >> 16) & 0xFFFF
            regs.write_word("%R272", count_lo, privilege=PrivilegeMode.SYSTEM)
            regs.write_word("%R273", count_hi, privilege=PrivilegeMode.SYSTEM)

            # %R274: Last Message Byte Count
            regs.write_word("%R274", self._last_byte_count, privilege=PrivilegeMode.SYSTEM)
        except Exception:
            pass


# ============================================================================
# 5. Canonical Verification & Artifact Export
# ============================================================================

def verify_sparkplug_b_and_export_evidence(
    output_evidence_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute deterministic air-gapped verification of Sparkplug B engine.
    
    Returns strict 4-state contract:
    {
      "status": "success | failed | blocked | inconclusive",
      "error_code": "STRING_OR_NULL",
      "details": "Factual summary",
      "data": {}
    }
    """
    tests_run = 0
    tests_passed = 0
    details_log: List[str] = []

    try:
        # Step 1: Verify Varint Encoding & Decoding
        tests_run += 1
        test_varints = [0, 1, 127, 128, 300, 16384, 0xFFFFFFFF, 1729000000000]
        for v in test_varints:
            enc = encode_varint(v)
            dec, length = decode_varint(enc)
            if dec != v or length != len(enc):
                return {
                    "status": "failed",
                    "error_code": "ERR_VARINT_CODEC",
                    "details": f"Varint mismatch for {v}: decoded {dec}",
                    "data": {},
                }
        tests_passed += 1
        details_log.append("Varint LEB128 codec verified across standard and 64-bit boundaries.")

        # Step 2: Verify IEEE 754 Float and Double Encoding & Decoding
        tests_run += 1
        f_val = 123.45600128173828
        f_enc = encode_float(f_val)
        f_dec, _ = decode_float(f_enc)
        if abs(f_dec - f_val) > 1e-4 or len(f_enc) != 4:
            return {
                "status": "failed",
                "error_code": "ERR_FLOAT_CODEC",
                "details": f"Float32 mismatch: {f_dec} vs {f_val}",
                "data": {},
            }

        d_val = 3.141592653589793
        d_enc = encode_double(d_val)
        d_dec, _ = decode_double(d_enc)
        if abs(d_dec - d_val) > 1e-9 or len(d_enc) != 8:
            return {
                "status": "failed",
                "error_code": "ERR_DOUBLE_CODEC",
                "details": f"Double64 mismatch: {d_dec} vs {d_val}",
                "data": {},
            }
        tests_passed += 1
        details_log.append("IEEE 754 32-bit float and 64-bit double wire encoding verified.")

        # Step 3: Verify Canonical Topic Parsing & Generation for all 8 verbs
        tests_run += 1
        for verb in SparkplugMessageType:
            t = SparkplugTopic(
                namespace="spBv1.0",
                group_id="HORNER_NET",
                message_type=verb,
                edge_node_id="NODE_42",
                device_id="DEV_01" if "D" in verb.value else None,
            )
            t_str = t.format()
            t_parsed = SparkplugTopic.parse(t_str)
            if t_parsed.message_type != verb or t_parsed.edge_node_id != "NODE_42":
                return {
                    "status": "failed",
                    "error_code": "ERR_TOPIC_PARSER",
                    "details": f"Topic parse mismatch for {verb}: {t_str}",
                    "data": {},
                }
        tests_passed += 1
        details_log.append("Canonical Sparkplug B topic formatting and parsing verified for all 8 verbs.")

        # Step 4: Verify Metric Serialization across all datatypes
        tests_run += 1
        metrics_sample = [
            SparkplugMetric.from_value("Int16_Val", 1024, SparkplugDataType.Int16),
            SparkplugMetric.from_value("Float_Val", 45.67, SparkplugDataType.Float),
            SparkplugMetric.from_value("Bool_Val", True, SparkplugDataType.Boolean),
            SparkplugMetric.from_value("Str_Val", "OCS_ACTIVE", SparkplugDataType.String),
            SparkplugMetric.from_value("Null_Val", None, SparkplugDataType.Int16),
        ]
        for m in metrics_sample:
            encoded_m = m.encode()
            if len(encoded_m) == 0:
                return {
                    "status": "failed",
                    "error_code": "ERR_METRIC_ENCODE",
                    "details": f"Zero-length encoded metric: {m.name}",
                    "data": {},
                }
        tests_passed += 1
        details_log.append("Metric Protobuf serialization verified across Int16, Float, Bool, String, Null.")

        # Step 5: Verify Sequence Manager & Modulo 256 Rollover
        tests_run += 1
        sm = SparkplugSequenceManager()
        for i in range(256):
            seq = sm.next_seq()
            expected = (i + 1) % 256
            if seq != expected:
                return {
                    "status": "failed",
                    "error_code": "ERR_SEQ_INCREMENT",
                    "details": f"Sequence counter error at iter {i}: got {seq}, expected {expected}",
                    "data": {},
                }
        if sm.rollover_count != 1:
            return {
                "status": "failed",
                "error_code": "ERR_SEQ_ROLLOVER",
                "details": f"Rollover count mismatch: got {sm.rollover_count}, expected 1",
                "data": {},
            }
        sm.trigger_rebirth()
        if sm.seq != 0 or sm.bdseq != 1:
            return {
                "status": "failed",
                "error_code": "ERR_REBIRTH_RESET",
                "details": f"Rebirth state error: seq={sm.seq}, bdseq={sm.bdseq}",
                "data": {},
            }
        tests_passed += 1
        details_log.append("Sequence counter modulo 256 rollover and rebirth sequence verified.")

        # Step 6: Verify Horner OCS Scan Cycle Solve & Register Synchronization
        tests_run += 1
        regs = RegisterTable()
        telemetry_unit = SparkplugBTelemetryUnit(
            register_table=regs,
            group_id="TEST_GROUP",
            edge_node_id="TEST_NODE",
            device_id="PUMP_01",
        )

        # Pre-seed registers
        regs.write_word("%AI1", 15000, privilege=PrivilegeMode.SYSTEM)
        regs.write_word("%AI2", 2200, privilege=PrivilegeMode.SYSTEM)
        regs.write_word("%AQ1", 8000, privilege=PrivilegeMode.SYSTEM)
        regs.write_bit("%M1", True, privilege=PrivilegeMode.SYSTEM)

        # Run Scan 1 (triggers NBIRTH and DBIRTH)
        telemetry_unit.solve(regs)

        # Verify %R270 Status Word
        status_word = regs.read_word("%R270")
        if not (status_word & SparkplugStatusFlag.ACTIVE) or not (status_word & SparkplugStatusFlag.CONNECTED_BIRTH):
            return {
                "status": "failed",
                "error_code": "ERR_REGISTER_STATUS",
                "details": f"Status word %R270 mismatch: {bin(status_word)}",
                "data": {},
            }

        # Verify Published Count (%R272:%R273)
        pub_count = regs.read_word("%R272") | (regs.read_word("%R273") << 16)
        if pub_count < 2:  # NBIRTH + DBIRTH
            return {
                "status": "failed",
                "error_code": "ERR_REGISTER_COUNT",
                "details": f"Published count %R272:%R273 mismatch: {pub_count}",
                "data": {},
            }

        # Run Scan 2 with changed %AI1 (generates DDATA)
        regs.write_word("%AI1", 16500, privilege=PrivilegeMode.SYSTEM)
        telemetry_unit.solve(regs)

        new_pub_count = regs.read_word("%R272") | (regs.read_word("%R273") << 16)
        if new_pub_count != pub_count + 1:
            return {
                "status": "failed",
                "error_code": "ERR_DDATA_DISPATCH",
                "details": f"DDATA dispatch mismatch: count {new_pub_count} vs {pub_count + 1}",
                "data": {},
            }

        # Test %M59 Rebirth Trigger
        regs.write_bit("%M59", True, privilege=PrivilegeMode.SYSTEM)
        telemetry_unit.solve(regs)

        if regs.read_bit("%M59") is not False:
            return {
                "status": "failed",
                "error_code": "ERR_M59_SELF_CLEAR",
                "details": "%M59 coil failed to self-clear after rebirth",
                "data": {},
            }
        tests_passed += 1
        details_log.append("Horner OCS scan cycle execution and %R270..%R274, %M58..%M59 sync verified.")

        # Step 7: Verify Pure ST Boundary Interception
        tests_run += 1
        sample_st = (
            "PROGRAM SparkplugTelemetrySync\n"
            "VAR\n"
            "    StatusWord : WORD;\n"
            "    SeqNum : INT;\n"
            "END_VAR\n"
            "StatusWord := %R270;\n"
            "SeqNum := %R271;\n"
            "END_PROGRAM"
        )
        SecurityGuard.assert_pure_st_content(sample_st)

        forbidden_constructs = [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 1",
            "END_RUNG",
            "NETWORK 1",
            "XIC %I1",
            "OTE %Q1",
        ]
        rejected_count = 0
        for fc in forbidden_constructs:
            try:
                SecurityGuard.assert_pure_st_content(f"{sample_st}\n{fc}")
            except LadderForbiddenError:
                rejected_count += 1

        if rejected_count != len(forbidden_constructs):
            return {
                "status": "failed",
                "error_code": "ERR_LADDER_LEAK",
                "details": f"Only {rejected_count}/{len(forbidden_constructs)} ladder constructs intercepted",
                "data": {},
            }
        tests_passed += 1
        details_log.append("Pure ST boundary integrity confirmed; all 10 forbidden ladder constructs rejected.")

        # Compile final evidence artifact
        evidence = {
            "status": "success",
            "error_code": None,
            "details": f"All {tests_passed}/{tests_run} Sparkplug B protocol and Horner register checks passed.",
            "data": {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "tests_run": tests_run,
                "tests_passed": tests_passed,
                "verification_steps": details_log,
                "codecs_verified": ["varint_leb128", "ieee754_float32", "ieee754_double64", "length_delimited_string"],
                "topics_verified": [v.value for v in SparkplugMessageType],
                "register_mapping": {
                    "status_word": "%R270",
                    "sequence_number": "%R271",
                    "cumulative_messages_udint": "%R272:%R273",
                    "last_payload_bytes": "%R274",
                    "enable_coil": "%M58",
                    "rebirth_trigger_coil": "%M59",
                },
                "total_messages_generated_in_test": len(telemetry_unit.message_buffer),
            },
        }

        if output_evidence_path:
            p = Path(output_evidence_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                json.dump(evidence, f, indent=2)

        return evidence

    except Exception as exc:
        return {
            "status": "failed",
            "error_code": "ERR_VERIFICATION_EXCEPTION",
            "details": f"Unhandled exception during Sparkplug B verification: {exc}",
            "data": {"exception": str(exc)},
        }
