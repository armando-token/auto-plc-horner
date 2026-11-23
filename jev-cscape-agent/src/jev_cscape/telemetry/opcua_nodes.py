"""OPC UA Part 5 Information Model & In-Memory Address Space Node Manager.

Work Package: W052 (Gate G8 / G6)
Classification: PRODUCTION [industrial telemetry & closed-loop simulation]

Provides:
- NodeId: Canonical OPC UA NodeId supporting Numeric, String, Guid, and ByteString types across namespaces.
- NodeClass: Standard OPC UA NodeClasses (Object, Variable, Method, DataType, View, ReferenceType).
- AccessLevel & StatusCode: Comprehensive bitmasks and 32-bit OPC UA status codes (Good, Uncertain, Bad).
- DataValue: Value container with timestamping, quality code, and source/server picoseconds.
- BaseNode, VariableNode, ObjectNode, MethodNode: In-memory information model nodes with Reference links.
- OPCUAAddressSpace: Thread-safe in-memory address space supporting hierarchical browsing, read/write services,
  bidirectional Horner OCS RegisterTable synchronization, and ModbusScalingBridge integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
import math
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
import uuid

from jev_cscape.simulation.register_table import (
    PrivilegeMode,
    RegisterTable,
    WordOrder,
    float_to_words,
    words_to_float,
)
from jev_cscape.telemetry.scaling_bridge import (
    ModbusScalingBridge,
    OPCQualityFlag,
    QualityCode,
    TelemetryPoint,
)


class IdType(str, Enum):
    """OPC UA NodeId identifier types."""
    NUMERIC = "i"
    STRING = "s"
    GUID = "g"
    BYTESTRING = "b"


@dataclass(frozen=True)
class NodeId:
    """Canonical OPC UA NodeId conforming to OPC UA Part 3 / Part 6.

    Canonical string formats:
    - ns=0;i=84 (Standard numeric)
    - ns=1;s=HornerOCS.Registers.R1 (String identifier)
    - ns=1;g=12345678-1234-5678-1234-567812345678 (Guid identifier)
    - ns=1;b=AQIDBA== (Opaque ByteString base64 identifier)
    """
    namespace: int
    identifier: Union[int, str, uuid.UUID, bytes]
    id_type: IdType = IdType.NUMERIC

    def __post_init__(self) -> None:
        if self.id_type == IdType.NUMERIC and not isinstance(self.identifier, int):
            object.__setattr__(self, "identifier", int(self.identifier))
        elif self.id_type == IdType.STRING and not isinstance(self.identifier, str):
            object.__setattr__(self, "identifier", str(self.identifier))
        elif self.id_type == IdType.GUID and not isinstance(self.identifier, uuid.UUID):
            if isinstance(self.identifier, str):
                object.__setattr__(self, "identifier", uuid.UUID(self.identifier))
            else:
                object.__setattr__(self, "identifier", uuid.UUID(bytes=bytes(self.identifier)))
        elif self.id_type == IdType.BYTESTRING and not isinstance(self.identifier, bytes):
            if isinstance(self.identifier, str):
                import base64
                object.__setattr__(self, "identifier", base64.b64decode(self.identifier))
            else:
                object.__setattr__(self, "identifier", bytes(self.identifier))

    def __str__(self) -> str:
        if self.id_type == IdType.NUMERIC:
            return f"ns={self.namespace};i={self.identifier}"
        elif self.id_type == IdType.STRING:
            return f"ns={self.namespace};s={self.identifier}"
        elif self.id_type == IdType.GUID:
            return f"ns={self.namespace};g={self.identifier}"
        elif self.id_type == IdType.BYTESTRING:
            import base64
            b64_str = base64.b64encode(self.identifier).decode("ascii")  # type: ignore[arg-type]
            return f"ns={self.namespace};b={b64_str}"
        return f"ns={self.namespace};{self.id_type.value}={self.identifier}"

    @classmethod
    def parse(cls, text: str) -> NodeId:
        """Parse canonical OPC UA NodeId string."""
        text = text.strip()
        if not text.startswith("ns="):
            # Check shorthand i=... or s=... in namespace 0
            if text.startswith("i="):
                return cls(namespace=0, identifier=int(text[2:]), id_type=IdType.NUMERIC)
            elif text.startswith("s="):
                return cls(namespace=0, identifier=text[2:], id_type=IdType.STRING)
            elif text.startswith("g="):
                return cls(namespace=0, identifier=uuid.UUID(text[2:]), id_type=IdType.GUID)
            raise ValueError(f"Invalid NodeId format: {text}")

        parts = text.split(";", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid NodeId format: {text}")

        ns_str = parts[0][3:]
        namespace = int(ns_str)
        id_part = parts[1]

        if id_part.startswith("i="):
            return cls(namespace=namespace, identifier=int(id_part[2:]), id_type=IdType.NUMERIC)
        elif id_part.startswith("s="):
            return cls(namespace=namespace, identifier=id_part[2:], id_type=IdType.STRING)
        elif id_part.startswith("g="):
            return cls(namespace=namespace, identifier=uuid.UUID(id_part[2:]), id_type=IdType.GUID)
        elif id_part.startswith("b="):
            import base64
            raw_bytes = base64.b64decode(id_part[2:])
            return cls(namespace=namespace, identifier=raw_bytes, id_type=IdType.BYTESTRING)
        else:
            raise ValueError(f"Unsupported NodeId identifier type: {id_part}")


class NodeClass(IntEnum):
    """OPC UA NodeClass bit enum conforming to OPC UA Part 3."""
    UNSPECIFIED = 0
    OBJECT = 1
    VARIABLE = 2
    METHOD = 4
    OBJECT_TYPE = 8
    VARIABLE_TYPE = 16
    REFERENCE_TYPE = 32
    DATA_TYPE = 64
    VIEW = 128


class AccessLevel(IntFlag):
    """OPC UA Variable AccessLevel bitmask."""
    NONE = 0x00
    CURRENT_READ = 0x01
    CURRENT_WRITE = 0x02
    HISTORY_READ = 0x04
    HISTORY_WRITE = 0x08
    SEMANTIC_CHANGE = 0x10
    STATUS_WRITE = 0x20
    TIMESTAMP_WRITE = 0x40


class StatusCode(IntEnum):
    """Standard 32-bit OPC UA StatusCodes conforming to OPC UA Part 4."""
    GOOD = 0x00000000
    GOOD_CLAMPED = 0x00300000
    UNCERTAIN = 0x40000000
    UNCERTAIN_LAST_USABLE_VALUE = 0x408F0000
    UNCERTAIN_SENSOR_NOT_ACCURATE = 0x40900000
    UNCERTAIN_EU_EXCEEDED = 0x40910000
    UNCERTAIN_SUB_NORMAL = 0x40920000
    BAD = 0x80000000
    BAD_UNEXPECTED_ERROR = 0x80010000
    BAD_TIMEOUT = 0x800A0000
    BAD_USER_ACCESS_DENIED = 0x801F0000
    BAD_NODE_ID_UNKNOWN = 0x80340000
    BAD_ATTRIBUTE_ID_INVALID = 0x80350000
    BAD_NOT_READABLE = 0x803A0000
    BAD_NOT_WRITABLE = 0x803B0000
    BAD_OUT_OF_RANGE = 0x803C0000
    BAD_TYPE_MISMATCH = 0x803D0000
    BAD_CONFIG_ERROR = 0x80890000
    BAD_NOT_CONNECTED = 0x808A0000
    BAD_DEVICE_FAILURE = 0x808B0000
    BAD_SENSOR_FAILURE = 0x808C0000
    BAD_OUT_OF_SERVICE = 0x808D0000

    @property
    def is_good(self) -> bool:
        return (self.value & 0xC0000000) == 0x00000000

    @property
    def is_uncertain(self) -> bool:
        return (self.value & 0xC0000000) == 0x40000000

    @property
    def is_bad(self) -> bool:
        return (self.value & 0x80000000) == 0x80000000


@dataclass
class QualifiedName:
    """OPC UA QualifiedName structure."""
    namespace_index: int
    name: str

    def __str__(self) -> str:
        return f"{self.namespace_index}:{self.name}"


@dataclass
class LocalizedText:
    """OPC UA LocalizedText structure."""
    text: str
    locale: Optional[str] = "en"

    def __str__(self) -> str:
        return self.text


@dataclass
class DataValue:
    """OPC UA DataValue structure containing value, StatusCode, and timestamps."""
    value: Any
    status_code: StatusCode = StatusCode.GOOD
    source_timestamp: float = field(default_factory=time.time)
    server_timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "status_code": hex(int(self.status_code)),
            "status_name": self.status_code.name,
            "is_good": self.status_code.is_good,
            "source_timestamp": self.source_timestamp,
            "server_timestamp": self.server_timestamp,
        }


@dataclass
class Reference:
    """OPC UA Reference structure linking nodes."""
    reference_type_id: NodeId
    is_forward: bool
    target_node_id: NodeId


# Standard OPC UA ReferenceType NodeIds in Namespace 0
REF_ORGANIZES = NodeId(0, 35, IdType.NUMERIC)
REF_HAS_COMPONENT = NodeId(0, 47, IdType.NUMERIC)
REF_HAS_PROPERTY = NodeId(0, 46, IdType.NUMERIC)
REF_HAS_TYPE_DEFINITION = NodeId(0, 40, IdType.NUMERIC)

# Standard OPC UA DataType NodeIds in Namespace 0
DATA_TYPE_BOOLEAN = NodeId(0, 1, IdType.NUMERIC)
DATA_TYPE_INT16 = NodeId(0, 4, IdType.NUMERIC)
DATA_TYPE_UINT16 = NodeId(0, 5, IdType.NUMERIC)
DATA_TYPE_INT32 = NodeId(0, 6, IdType.NUMERIC)
DATA_TYPE_UINT32 = NodeId(0, 7, IdType.NUMERIC)
DATA_TYPE_FLOAT = NodeId(0, 10, IdType.NUMERIC)
DATA_TYPE_DOUBLE = NodeId(0, 11, IdType.NUMERIC)
DATA_TYPE_STRING = NodeId(0, 12, IdType.NUMERIC)


@dataclass
class BaseNode:
    """Base class for all OPC UA in-memory nodes."""
    node_id: NodeId
    node_class: NodeClass
    browse_name: QualifiedName
    display_name: LocalizedText
    description: Optional[LocalizedText] = None
    references: List[Reference] = field(default_factory=list)

    def add_reference(self, reference_type_id: NodeId, target_node_id: NodeId, is_forward: bool = True) -> None:
        self.references.append(Reference(reference_type_id, is_forward, target_node_id))


@dataclass
class ObjectNode(BaseNode):
    """OPC UA ObjectNode (e.g., Folder, Controller, Device, System)."""
    event_notifier: int = 0

    def __init__(
        self,
        node_id: NodeId,
        browse_name: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        namespace_index: Optional[int] = None,
        event_notifier: int = 0,
    ) -> None:
        ns = namespace_index if namespace_index is not None else node_id.namespace
        super().__init__(
            node_id=node_id,
            node_class=NodeClass.OBJECT,
            browse_name=QualifiedName(ns, browse_name),
            display_name=LocalizedText(display_name or browse_name),
            description=LocalizedText(description) if description else None,
            references=[],
        )
        self.event_notifier = event_notifier


@dataclass
class VariableNode(BaseNode):
    """OPC UA VariableNode representing telemetry values and register bindings."""
    data_type: NodeId = DATA_TYPE_FLOAT
    value: DataValue = field(default_factory=lambda: DataValue(None))
    access_level: AccessLevel = AccessLevel.CURRENT_READ | AccessLevel.CURRENT_WRITE
    user_access_level: AccessLevel = AccessLevel.CURRENT_READ | AccessLevel.CURRENT_WRITE
    horner_register: Optional[str] = None
    eu_range: Optional[Tuple[float, float]] = None
    engineering_units: Optional[str] = None

    def __init__(
        self,
        node_id: NodeId,
        browse_name: str,
        data_type: NodeId = DATA_TYPE_FLOAT,
        initial_value: Any = None,
        access_level: AccessLevel = AccessLevel.CURRENT_READ | AccessLevel.CURRENT_WRITE,
        horner_register: Optional[str] = None,
        eu_range: Optional[Tuple[float, float]] = None,
        engineering_units: Optional[str] = None,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        namespace_index: Optional[int] = None,
    ) -> None:
        ns = namespace_index if namespace_index is not None else node_id.namespace
        super().__init__(
            node_id=node_id,
            node_class=NodeClass.VARIABLE,
            browse_name=QualifiedName(ns, browse_name),
            display_name=LocalizedText(display_name or browse_name),
            description=LocalizedText(description) if description else None,
            references=[],
        )
        self.data_type = data_type
        self.value = DataValue(initial_value)
        self.access_level = access_level
        self.user_access_level = access_level
        self.horner_register = horner_register
        self.eu_range = eu_range
        self.engineering_units = engineering_units


@dataclass
class MethodNode(BaseNode):
    """OPC UA MethodNode representing callable procedures."""
    executable: bool = True
    user_executable: bool = True
    handler: Optional[Callable[[List[Any]], Tuple[StatusCode, List[Any]]]] = None

    def __init__(
        self,
        node_id: NodeId,
        browse_name: str,
        handler: Optional[Callable[[List[Any]], Tuple[StatusCode, List[Any]]]] = None,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        namespace_index: Optional[int] = None,
    ) -> None:
        ns = namespace_index if namespace_index is not None else node_id.namespace
        super().__init__(
            node_id=node_id,
            node_class=NodeClass.METHOD,
            browse_name=QualifiedName(ns, browse_name),
            display_name=LocalizedText(display_name or browse_name),
            description=LocalizedText(description) if description else None,
            references=[],
        )
        self.executable = True
        self.user_executable = True
        self.handler = handler


class OPCUAAddressSpace:
    """Thread-safe pure-software in-memory OPC UA Part 5 Information Model address space.

    Guarantees:
    - Zero host socket bindings or network listeners.
    - Zero COM port, CAN, USB, or hardware interaction.
    - Strict thread safety via reentrant lock (RLock).
    - Sub-millisecond deterministic browsing and read/write execution.
    - Full synchronization with Horner OCS RegisterTable and ModbusScalingBridge.
    """

    def __init__(self, default_horner_space: bool = True) -> None:
        self._lock = threading.RLock()
        self._nodes: Dict[NodeId, BaseNode] = {}
        self._namespaces: List[str] = [
            "http://opcfoundation.org/UA/",  # ns=0: Standard OPC UA Foundation
            "urn:horner:ocs:telemetry",       # ns=1: Horner OCS Space
        ]
        self._register_index: Dict[str, NodeId] = {}

        # Standard Root Hierarchy (ns=0)
        self._init_standard_roots()

        if default_horner_space:
            self._init_horner_standard_space()

    @property
    def namespaces(self) -> List[str]:
        with self._lock:
            return list(self._namespaces)

    def register_namespace(self, uri: str) -> int:
        with self._lock:
            if uri in self._namespaces:
                return self._namespaces.index(uri)
            self._namespaces.append(uri)
            return len(self._namespaces) - 1

    def _init_standard_roots(self) -> None:
        """Create standard OPC UA Part 5 root folders."""
        root_id = NodeId(0, 84, IdType.NUMERIC)
        objects_id = NodeId(0, 85, IdType.NUMERIC)
        types_id = NodeId(0, 86, IdType.NUMERIC)
        views_id = NodeId(0, 87, IdType.NUMERIC)

        root = ObjectNode(root_id, "Root", "Root", "The Root folder of the OPC UA Address Space")
        objects = ObjectNode(objects_id, "Objects", "Objects", "Standard Objects folder")
        types = ObjectNode(types_id, "Types", "Types", "Standard Types folder")
        views = ObjectNode(views_id, "Views", "Views", "Standard Views folder")

        self.add_node(root)
        self.add_node(objects)
        self.add_node(types)
        self.add_node(views)

        self.add_reference(root_id, REF_ORGANIZES, objects_id)
        self.add_reference(root_id, REF_ORGANIZES, types_id)
        self.add_reference(root_id, REF_ORGANIZES, views_id)

    def _init_horner_standard_space(self) -> None:
        """Initialize standard Horner OCS controller hierarchy and channel folders."""
        objects_id = NodeId(0, 85, IdType.NUMERIC)
        controller_id = NodeId(1, "HornerOCS", IdType.STRING)

        controller = ObjectNode(
            controller_id,
            "HornerOCS",
            "Horner OCS Controller",
            "Horner APG OCS in-memory emulation controller node",
        )
        self.add_node(controller)
        self.add_reference(objects_id, REF_ORGANIZES, controller_id)

        # Create memory channel folders
        channels = [
            ("DigitalInputs", "HornerOCS.Inputs", "%I"),
            ("DigitalOutputs", "HornerOCS.Outputs", "%Q"),
            ("InternalMarkers", "HornerOCS.Markers", "%M"),
            ("AnalogInputs", "HornerOCS.AnalogInputs", "%AI"),
            ("AnalogOutputs", "HornerOCS.AnalogOutputs", "%AQ"),
            ("Registers", "HornerOCS.Registers", "%R"),
        ]

        for folder_name, folder_id_str, prefix in channels:
            fid = NodeId(1, folder_id_str, IdType.STRING)
            folder_node = ObjectNode(fid, folder_name, folder_name, f"Horner {prefix} memory channel group")
            self.add_node(folder_node)
            self.add_reference(controller_id, REF_ORGANIZES, fid)

    def add_node(self, node: BaseNode) -> None:
        with self._lock:
            self._nodes[node.node_id] = node
            if isinstance(node, VariableNode) and node.horner_register:
                self._register_index[node.horner_register.upper()] = node.node_id

    def add_reference(
        self,
        source_id: Union[str, NodeId],
        reference_type_id: Union[str, NodeId],
        target_id: Union[str, NodeId],
        is_forward: bool = True,
    ) -> None:
        src = NodeId.parse(source_id) if isinstance(source_id, str) else source_id
        ref_type = NodeId.parse(reference_type_id) if isinstance(reference_type_id, str) else reference_type_id
        tgt = NodeId.parse(target_id) if isinstance(target_id, str) else target_id

        with self._lock:
            source_node = self._nodes.get(src)
            target_node = self._nodes.get(tgt)
            if not source_node:
                raise ValueError(f"Source node not found: {src}")
            if not target_node:
                raise ValueError(f"Target node not found: {tgt}")

            source_node.add_reference(ref_type, tgt, is_forward=is_forward)
            # Add inverse reference on target
            target_node.add_reference(ref_type, src, is_forward=not is_forward)

    def get_node(self, node_id: Union[str, NodeId]) -> Optional[BaseNode]:
        nid = NodeId.parse(node_id) if isinstance(node_id, str) else node_id
        with self._lock:
            return self._nodes.get(nid)

    def get_node_by_register(self, reg_address: str) -> Optional[VariableNode]:
        with self._lock:
            nid = self._register_index.get(reg_address.strip().upper())
            if nid:
                node = self._nodes.get(nid)
                if isinstance(node, VariableNode):
                    return node
            return None

    def browse(
        self,
        node_id: Union[str, NodeId],
        direction: str = "forward",
        reference_type_id: Optional[Union[str, NodeId]] = None,
    ) -> List[Tuple[Reference, BaseNode]]:
        """Browse references from a node.

        direction: 'forward', 'inverse', or 'both'.
        """
        nid = NodeId.parse(node_id) if isinstance(node_id, str) else node_id
        ref_filter = (
            NodeId.parse(reference_type_id)
            if isinstance(reference_type_id, str)
            else reference_type_id
        )

        results: List[Tuple[Reference, BaseNode]] = []
        with self._lock:
            node = self._nodes.get(nid)
            if not node:
                return []

            for ref in node.references:
                if direction == "forward" and not ref.is_forward:
                    continue
                if direction == "inverse" and ref.is_forward:
                    continue
                if ref_filter and ref.reference_type_id != ref_filter:
                    continue

                target_node = self._nodes.get(ref.target_node_id)
                if target_node:
                    results.append((ref, target_node))

        return results

    def read_value(self, node_id: Union[str, NodeId]) -> Tuple[StatusCode, Optional[DataValue]]:
        nid = NodeId.parse(node_id) if isinstance(node_id, str) else node_id
        with self._lock:
            node = self._nodes.get(nid)
            if not node:
                return StatusCode.BAD_NODE_ID_UNKNOWN, None
            if not isinstance(node, VariableNode):
                return StatusCode.BAD_ATTRIBUTE_ID_INVALID, None
            if not (node.access_level & AccessLevel.CURRENT_READ):
                return StatusCode.BAD_NOT_READABLE, None

            return node.value.status_code, node.value

    def write_value(
        self,
        node_id: Union[str, NodeId],
        value: Any,
        status_code: StatusCode = StatusCode.GOOD,
        privilege: str = "USER",
    ) -> StatusCode:
        nid = NodeId.parse(node_id) if isinstance(node_id, str) else node_id
        with self._lock:
            node = self._nodes.get(nid)
            if not node:
                return StatusCode.BAD_NODE_ID_UNKNOWN
            if not isinstance(node, VariableNode):
                return StatusCode.BAD_ATTRIBUTE_ID_INVALID

            # Enforce access level
            if not (node.access_level & AccessLevel.CURRENT_WRITE):
                if privilege.upper() != "SYSTEM":
                    return StatusCode.BAD_NOT_WRITABLE

            # Range validation if eu_range is configured
            if node.eu_range is not None and isinstance(value, (int, float)):
                low, high = node.eu_range
                if value < low or value > high:
                    status_code = StatusCode.UNCERTAIN_EU_EXCEEDED

            now = time.time()
            node.value = DataValue(
                value=value,
                status_code=status_code,
                source_timestamp=now,
                server_timestamp=now,
            )
            return status_code

    def call_method(
        self,
        node_id: Union[str, NodeId],
        arguments: List[Any],
    ) -> Tuple[StatusCode, List[Any]]:
        nid = NodeId.parse(node_id) if isinstance(node_id, str) else node_id
        with self._lock:
            node = self._nodes.get(nid)
            if not node:
                return StatusCode.BAD_NODE_ID_UNKNOWN, []
            if not isinstance(node, MethodNode):
                return StatusCode.BAD_ATTRIBUTE_ID_INVALID, []
            if not node.executable or not node.handler:
                return StatusCode.BAD_NOT_WRITABLE, []

            try:
                return node.handler(arguments)
            except Exception:
                return StatusCode.BAD_UNEXPECTED_ERROR, []

    def sync_from_register_table(self, reg_table: RegisterTable) -> int:
        """Synchronize VariableNode values from Horner OCS RegisterTable."""
        synced_count = 0
        now = time.time()
        with self._lock:
            for node in self._nodes.values():
                if not isinstance(node, VariableNode) or not node.horner_register:
                    continue

                reg = node.horner_register.strip().upper()
                try:
                    # Parse channel prefix
                    if reg.startswith("%I") or reg.startswith("%Q") or reg.startswith("%M"):
                        val_bool = reg_table.read_bit(reg)
                        node.value = DataValue(
                            value=val_bool,
                            status_code=StatusCode.GOOD,
                            source_timestamp=now,
                            server_timestamp=now,
                        )
                        synced_count += 1
                    elif reg.startswith("%AI") or reg.startswith("%AQ"):
                        val_word = reg_table.read_word(reg)
                        node.value = DataValue(
                            value=val_word,
                            status_code=StatusCode.GOOD,
                            source_timestamp=now,
                            server_timestamp=now,
                        )
                        synced_count += 1
                    elif reg.startswith("%R"):
                        # Check if node data_type is FLOAT (dual-register %R:2)
                        if node.data_type == DATA_TYPE_FLOAT:
                            val_float = reg_table.read_real(reg)
                            node.value = DataValue(
                                value=val_float,
                                status_code=StatusCode.GOOD,
                                source_timestamp=now,
                                server_timestamp=now,
                            )
                        else:
                            val_word = reg_table.read_word(reg)
                            node.value = DataValue(
                                value=val_word,
                                status_code=StatusCode.GOOD,
                                source_timestamp=now,
                                server_timestamp=now,
                            )
                        synced_count += 1
                except Exception:
                    node.value = DataValue(
                        value=None,
                        status_code=StatusCode.BAD_DEVICE_FAILURE,
                        source_timestamp=now,
                        server_timestamp=now,
                    )
        return synced_count

    def sync_to_register_table(
        self,
        reg_table: RegisterTable,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> int:
        """Write VariableNode values to Horner OCS RegisterTable."""
        synced_count = 0
        with self._lock:
            for node in self._nodes.values():
                if not isinstance(node, VariableNode) or not node.horner_register:
                    continue
                if node.value.value is None:
                    continue

                reg = node.horner_register.strip().upper()
                val = node.value.value
                try:
                    if reg.startswith("%I") or reg.startswith("%Q") or reg.startswith("%M"):
                        reg_table.write_bit(reg, bool(val), privilege=privilege)
                        synced_count += 1
                    elif reg.startswith("%AI") or reg.startswith("%AQ"):
                        reg_table.write_word(reg, int(val), privilege=privilege)
                        synced_count += 1
                    elif reg.startswith("%R"):
                        if node.data_type == DATA_TYPE_FLOAT and isinstance(val, (int, float)):
                            reg_table.write_real(reg, float(val), privilege=privilege)
                        else:
                            reg_table.write_word(reg, int(val), privilege=privilege)
                        synced_count += 1
                except Exception:
                    pass
        return synced_count

    def sync_from_scaling_bridge(self, bridge: ModbusScalingBridge) -> int:
        """Synchronize telemetry points from ModbusScalingBridge to OPC UA VariableNodes."""
        synced_count = 0
        now = time.time()
        with self._lock:
            for point in bridge.points.values():
                # Locate node by register
                node = self.get_node_by_register(point.channel)
                if not node:
                    # Automatically generate variable node in Namespace 1
                    nid = NodeId(1, f"HornerOCS.Telemetry.{point.name}", IdType.STRING)
                    dtype = DATA_TYPE_FLOAT if point.is_32bit_float else DATA_TYPE_INT16
                    node = VariableNode(
                        node_id=nid,
                        browse_name=point.name,
                        data_type=dtype,
                        horner_register=point.channel,
                        eu_range=(point.eu_min, point.eu_max),
                        engineering_units=point.eu_unit,
                        description=f"{point.name} scaled telemetry point",
                    )
                    self.add_node(node)
                    # Link to HornerOCS
                    controller_id = NodeId(1, "HornerOCS", IdType.STRING)
                    self.add_reference(controller_id, REF_HAS_COMPONENT, nid)

                # Map QualityCode and OPCQualityFlag to StatusCode
                sc = StatusCode.GOOD
                if point.current_quality == QualityCode.BAD:
                    sc = StatusCode.BAD_SENSOR_FAILURE
                elif point.current_quality == QualityCode.UNCERTAIN:
                    if point.current_quality_word & OPCQualityFlag.EU_EXCEEDED:
                        sc = StatusCode.UNCERTAIN_EU_EXCEEDED
                    else:
                        sc = StatusCode.UNCERTAIN_SENSOR_NOT_ACCURATE

                node.value = DataValue(
                    value=point.current_eu,
                    status_code=sc,
                    source_timestamp=point.last_update_timestamp or now,
                    server_timestamp=now,
                )
                synced_count += 1
        return synced_count

    def to_dict(self) -> Dict[str, Any]:
        """Serialize address space metadata into structured dictionary."""
        with self._lock:
            node_summaries = []
            for n in self._nodes.values():
                summary: Dict[str, Any] = {
                    "node_id": str(n.node_id),
                    "node_class": n.node_class.name,
                    "browse_name": str(n.browse_name),
                    "display_name": str(n.display_name),
                    "references_count": len(n.references),
                }
                if isinstance(n, VariableNode):
                    summary["data_type"] = str(n.data_type)
                    summary["access_level"] = hex(int(n.access_level))
                    summary["horner_register"] = n.horner_register
                    summary["value"] = n.value.to_dict()
                    summary["eu_range"] = n.eu_range
                    summary["engineering_units"] = n.engineering_units
                elif isinstance(n, MethodNode):
                    summary["executable"] = n.executable
                node_summaries.append(summary)

            return {
                "namespaces": list(self._namespaces),
                "total_nodes": len(self._nodes),
                "nodes": node_summaries,
            }
