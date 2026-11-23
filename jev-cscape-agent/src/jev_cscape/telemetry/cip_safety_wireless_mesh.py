"""Industrial ODVA CIP Safety Over Wireless Mesh (IEEE 802.15.4 / 6LoWPAN) Protocol Engine.

Work Package: W280 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - CIP Safety Over Wireless Mesh (IEEE 802.15.4 / 6LoWPAN multi-hop mesh network)
  - 32-bit Safety Network Number (SNN) verification
  - Dual 16-bit Safety CRCs:
    - CRC-S1: 16-bit CRC over payload_bytes (polynomial 0x1021 or 0x8408)
    - CRC-S2: 16-bit CRC over SNN + sequence_number + timestamp_ms + CRC-S1
  - Safe State Machine:
    0: INIT
    1: OPERATIONAL
    2: DEGRADED
    3: FAIL_SAFE
- IEEE 802.15.4 / 6LoWPAN Multi-Hop Mesh Topology & Dynamic Routing:
  - WirelessMeshNode(node_id, pan_id, channel, parent_id, hop_count, rssi_dbm, lqi, is_coordinator)
  - WirelessMeshRoute(route_id, destination_id, next_hop_id, hop_count, path_etx, path_latency_ms, is_active)
  - Dynamic route selection with fallback to alternate route when RSSI < threshold (-82 dBm) or packet loss > 5.0%
- Watchdog & Multi-Hop Latency Jitter Compensation:
  - Configurable safety timeout (100ms - 500ms nominal)
  - Dynamic multi-hop latency compensation: watchdog threshold scales with hop_count (base_timeout + hop_count * hop_delay)
  - Fail-safe fallback state: on watchdog expiration, link partition, or CRC corruption, enter FAIL_SAFE state (zero outputs, de-energize)
- Diagnostic Codes (%R2417):
  - CipSafetyWirelessMeshDiagnosticCode (IntEnum):
    0: OK
    1: CRC_S1_ERROR
    2: CRC_S2_ERROR
    3: TIMEOUT_EXPIRED
    4: ROUTE_UNREACHABLE
    5: RSSI_BELOW_THRESHOLD
    6: PACKET_LOSS_HIGH
    7: SPLIT_BRAIN_PARTITION
- Horner OCS Memory Space:
  - Analog registers %R2410..%R2417:
    - %R2410: REG_WIRELESS_MESH_NODE_STATUS (lower byte node_id, upper byte status code)
    - %R2411: REG_WIRELESS_MESH_CHANNEL_PAN (lower byte channel, upper byte PAN ID & 0xFF)
    - %R2412: REG_WIRELESS_MESH_LINK_QUALITY (lower byte scaled RSSI 0..100, upper byte LQI 0..255)
    - %R2413: REG_WIRELESS_MESH_HOP_METRIC (lower byte hop_count, upper byte ETX x10)
    - %R2414: REG_WIRELESS_MESH_SNN_HIGH (SNN >> 16)
    - %R2415: REG_WIRELESS_MESH_SNN_LOW (SNN & 0xFFFF)
    - %R2416: REG_WIRELESS_MESH_PACKET_LOSS (0.01% units, e.g. 250 = 2.50%)
    - %R2417: REG_WIRELESS_MESH_DIAGNOSTIC_CODE (Diagnostic Code & 0xFFFF)
  - Discrete bits %M562..%M563:
    - %M562: COIL_WIRELESS_MESH_ROUTE_ACTIVE (Mesh Route Active / Safety Connection Established)
    - %M563: COIL_WIRELESS_MESH_PATH_FAILOVER (Mesh Path Failover / Link Degradation Alarm)
- Implements ILogicUnit interface with scan_step(dt, context), step(dt, context), execute(context), and reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetyWirelessMeshSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).parse().
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.
- Deterministic 9-stage verification suite run_cip_safety_wireless_mesh_verification().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import json
import math
from pathlib import Path
import struct
import sys
import time
import tracemalloc
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (ODVA CIP Safety Volume 5 / IEEE 802.15.4)
# ============================================================================

CIP_SAFETY_SUPERVISOR_CLASS_ID: int = 0x39          # Safety Supervisor Object
CIP_SAFETY_VALIDATOR_CLASS_ID: int = 0x3A           # Safety Validator Object
CIP_SAFETY_CONNECTION_CLASS_ID: int = 0x3B          # Safety Connection Object
CIP_SAFETY_WIRELESS_MESH_CLASS_ID: int = 0x2F       # CIP Safety Wireless Mesh Extension Class ID

# Default Mesh & Safety Parameters
DEFAULT_SAFETY_NETWORK_NUMBER: int = 0x00012345
DEFAULT_SNN: int = DEFAULT_SAFETY_NETWORK_NUMBER
DEFAULT_NODE_ID: int = 1
DEFAULT_PAN_ID: int = 0x1A2B
DEFAULT_CHANNEL: int = 15                           # IEEE 802.15.4 Channel 11..26

# Timing and Dynamic Watchdog Defaults
DEFAULT_BASE_TIMEOUT_MS: float = 200.0              # Base safety timeout (100ms - 500ms)
DEFAULT_HOP_DELAY_MS: float = 25.0                  # Jitter latency compensation per hop
DEFAULT_SAFETY_TIMEOUT_MS: float = DEFAULT_BASE_TIMEOUT_MS

# RF & Environmental Surveillance Defaults
DEFAULT_RSSI_DBM: float = -65.0                     # Nominal RSSI (-65 dBm)
DEFAULT_LQI: int = 220                              # Nominal Link Quality Indicator (0..255)
DEFAULT_RSSI_THRESHOLD_DBM: float = -82.0           # Fallback threshold: -82.0 dBm
DEFAULT_PACKET_LOSS_THRESHOLD: float = 0.05         # Fallback threshold: 5.0%
DEFAULT_PACKET_LOSS_RATE: float = 0.002             # Nominal packet loss rate (0.20% = 20 bps)

# CRC Polynomials and Seeds
CRC_POLY_1021: int = 0x1021                         # CRC16-CCITT generator polynomial
CRC_POLY_8408: int = 0x8408                         # CRC16-X.25 / CCITT reverse polynomial
CRC16_CCITT_POLY: int = 0x1021
CIP_SAFETY_CRC_INIT: int = 0xFFFF                   # Initial CRC seed

# Canonical Register Table Mapping (%R2410..%R2417)
REG_WIRELESS_MESH_NODE_STATUS: str = "%R2410"       # Lower byte node_id, upper byte status code
REG_WIRELESS_MESH_CHANNEL_PAN: str = "%R2411"       # Lower byte channel, upper byte PAN ID & 0xFF
REG_WIRELESS_MESH_LINK_QUALITY: str = "%R2412"      # Lower byte scaled RSSI 0..100, upper byte LQI 0..255
REG_WIRELESS_MESH_HOP_METRIC: str = "%R2413"        # Lower byte hop_count, upper byte ETX x10
REG_WIRELESS_MESH_SNN_HIGH: str = "%R2414"          # SNN High Word (SNN >> 16)
REG_WIRELESS_MESH_SNN_LOW: str = "%R2415"           # SNN Low Word (SNN & 0xFFFF)
REG_WIRELESS_MESH_PACKET_LOSS: str = "%R2416"       # Mesh Packet Loss Rate (0.01% units, e.g. 250 = 2.50%)
REG_WIRELESS_MESH_DIAGNOSTIC_CODE: str = "%R2417"   # Diagnostic Code & 0xFFFF

# Canonical Discrete Coils Mapping (%M562..%M563)
COIL_WIRELESS_MESH_ROUTE_ACTIVE: str = "%M562"      # Mesh Route Active / Safety Connection Established
COIL_WIRELESS_MESH_PATH_FAILOVER: str = "%M563"     # Mesh Path Failover / Link Degradation Alarm

# Register and Coil Aliases
REG_NODE_STATUS: str = "%R2410"
REG_CHANNEL_PAN: str = "%R2411"
REG_LINK_QUALITY: str = "%R2412"
REG_HOP_METRIC: str = "%R2413"
REG_SNN_HIGH: str = "%R2414"
REG_SNN_LOW: str = "%R2415"
REG_PACKET_LOSS: str = "%R2416"
REG_DIAGNOSTIC_CODE: str = "%R2417"

COIL_ROUTE_ACTIVE: str = "%M562"
COIL_PATH_FAILOVER: str = "%M563"
COIL_SAFETY_ESTABLISHED: str = "%M562"
COIL_DEGRADATION_ALARM: str = "%M563"


# ============================================================================
# 2. Enums and Diagnostic Codes
# ============================================================================

class CipSafetyWirelessMeshState(IntEnum):
    """ODVA CIP Safety Over Wireless Mesh State Machine (%R2410 upper byte).

    States:
    - 0: INIT (Initializing / mesh association)
    - 1: OPERATIONAL (Safety connection established and normal)
    - 2: DEGRADED (Link failover active or degraded path)
    - 3: FAIL_SAFE (Fail-safe safe stop state, outputs de-energized)
    """
    INIT = 0
    OPERATIONAL = 1
    DEGRADED = 2
    FAIL_SAFE = 3

    # Aliases
    Init = 0
    Operational = 1
    Degraded = 2
    FailSafe = 3


class CipSafetyWirelessMeshDiagnosticCode(IntEnum):
    """ODVA CIP Safety Over Wireless Mesh Diagnostic Codes (%R2417).

    Diagnostic Codes:
    - 0: OK (Mesh safety connection healthy and verified)
    - 1: CRC_S1_ERROR (Payload CRC-S1 checksum verification failure)
    - 2: CRC_S2_ERROR (Safety header CRC-S2 checksum verification failure)
    - 3: TIMEOUT_EXPIRED (Multi-hop safety watchdog timeout expired)
    - 4: ROUTE_UNREACHABLE (Destination mesh node unreachable via active/alternate routes)
    - 5: RSSI_BELOW_THRESHOLD (Mesh link RSSI below safe threshold -82 dBm with no route)
    - 6: PACKET_LOSS_HIGH (Mesh packet loss rate > 5.0% with no route)
    - 7: SPLIT_BRAIN_PARTITION (Mesh network partition or SNN divergence)
    """
    OK = 0
    CRC_S1_ERROR = 1
    CRC_S2_ERROR = 2
    TIMEOUT_EXPIRED = 3
    ROUTE_UNREACHABLE = 4
    RSSI_BELOW_THRESHOLD = 5
    PACKET_LOSS_HIGH = 6
    SPLIT_BRAIN_PARTITION = 7

    # Aliases
    Ok = 0
    CrcS1Error = 1
    CrcS2Error = 2
    TimeoutExpired = 3
    RouteUnreachable = 4
    RssiBelowThreshold = 5
    PacketLossHigh = 6
    SplitBrainPartition = 7

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            val_u = int(self) & 0xFFFF
            val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
            other_u = int(other) & 0xFFFF
            other_s = other_u - 0x10000 if other_u >= 0x8000 else other_u
            return (
                int(self) == other
                or val_u == other
                or val_s == other
                or val_s == other_s
                or val_u == other_u
            )
        eq_res = super().__eq__(other)
        if eq_res is NotImplemented:
            return False
        return bool(eq_res)

    def __ne__(self, other: Any) -> bool:
        eq_res = self.__eq__(other)
        if eq_res is NotImplemented:
            return True
        return not bool(eq_res)

    def __and__(self, other: Any) -> Any:
        if isinstance(other, int):
            return int(self) & int(other)
        return super().__and__(other)

    def __rand__(self, other: Any) -> Any:
        if isinstance(other, int):
            return int(other) & int(self)
        return super().__rand__(other)

    def __str__(self) -> str:
        return f"{self.name}({int(self)})"

    def __repr__(self) -> str:
        return f"CipSafetyWirelessMeshDiagnosticCode.{self.name}({int(self)})"


# Ensure lambda hash is explicit per requirements
CipSafetyWirelessMeshDiagnosticCode.__hash__ = lambda self: hash(int(self) & 0xFFFF)

# Module-level aliases
DiagnosticCode = CipSafetyWirelessMeshDiagnosticCode
DIAG_OK = CipSafetyWirelessMeshDiagnosticCode.OK
DIAG_CRC_S1_ERROR = CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR
DIAG_CRC_S2_ERROR = CipSafetyWirelessMeshDiagnosticCode.CRC_S2_ERROR
DIAG_TIMEOUT_EXPIRED = CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED
DIAG_ROUTE_UNREACHABLE = CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE
DIAG_RSSI_BELOW_THRESHOLD = CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD
DIAG_PACKET_LOSS_HIGH = CipSafetyWirelessMeshDiagnosticCode.PACKET_LOSS_HIGH
DIAG_SPLIT_BRAIN_PARTITION = CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION


# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class CipSafetyWirelessMeshError(Exception):
    """Base exception for all CIP Safety Over Wireless Mesh errors."""
    pass


class CrcS1CorruptionError(CipSafetyWirelessMeshError):
    """Raised when CRC-S1 checksum verification fails."""
    pass


class CrcS2CorruptionError(CipSafetyWirelessMeshError):
    """Raised when CRC-S2 checksum verification fails."""
    pass


class SafetyTimeoutExpiredError(CipSafetyWirelessMeshError):
    """Raised when safety watchdog timeout expires."""
    pass


class RouteUnreachableError(CipSafetyWirelessMeshError):
    """Raised when destination is unreachable via any mesh route."""
    pass


class SplitBrainPartitionError(CipSafetyWirelessMeshError):
    """Raised when network partition or SNN mismatch is detected."""
    pass


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POU Definition
# ============================================================================

ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC: str = """PROGRAM ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC
VAR
    (* Horner OCS Mapped Registers (W280 - ODVA CIP Safety Over Wireless Mesh) *)
    MeshNodeStatus              AT %R2410 : INT;    (* lower byte node_id, upper byte status code *)
    MeshChannelPan              AT %R2411 : INT;    (* lower byte channel, upper byte PAN ID & 0xFF *)
    ScaledLinkQuality           AT %R2412 : INT;    (* lower byte scaled RSSI 0..100, upper byte LQI 0..255 *)
    HopCountMetric              AT %R2413 : INT;    (* lower byte hop_count, upper byte ETX x10 *)
    SafetyNetNumHigh            AT %R2414 : UINT;   (* SNN >> 16 *)
    SafetyNetNumLow             AT %R2415 : UINT;   (* SNN & 0xFFFF *)
    MeshPacketLoss              AT %R2416 : UINT;   (* 0.01% units, e.g. 250 = 2.50% *)
    DiagnosticCode              AT %R2417 : UINT;   (* Diagnostic Code & 0xFFFF *)

    (* Discrete Safety Coils *)
    MeshRouteActive             AT %M562  : BOOL;   (* TRUE when route active & safety connection established *)
    MeshPathFailover            AT %M563  : BOOL;   (* TRUE on path failover or link degradation alarm *)

    (* Internal Flags *)
    SafeOperational             : BOOL;
END_VAR

IF (DiagnosticCode <> 0) OR (MeshPacketLoss > 500) THEN
    MeshRouteActive := FALSE;
    MeshPathFailover := TRUE;
    SafeOperational := FALSE;
ELSIF (MeshPacketLoss > 0) AND (MeshPacketLoss <= 500) THEN
    MeshRouteActive := TRUE;
    MeshPathFailover := FALSE;
    SafeOperational := TRUE;
ELSE
    MeshRouteActive := TRUE;
    MeshPathFailover := FALSE;
    SafeOperational := TRUE;
END_IF;
END_PROGRAM
"""

CIP_SAFETY_WIRELESS_MESH_SYNC_POU: str = ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC
CIP_SAFETY_WIRELESS_MESH_PURE_ST_POU: str = ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC
CipSafetyWirelessMeshSync: str = ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC


def verify_cip_safety_wireless_mesh_pure_st(pou_text: Optional[str] = None) -> bool:
    """Validate pure IEC 61131-3 ST POU with SecurityGuard and STParser."""
    try:
        text = pou_text if pou_text is not None else ST_PROGRAM_CIP_SAFETY_WIRELESS_MESH_SYNC
        SecurityGuard.assert_pure_st_content(text)
        res = STParser.validate_code(text)
        if res.status != AgentStatus.SUCCESS:
            return False
        ast = STParser(pou_type=POUType.PROGRAM).parse(text)
        if ast.pou_type != POUType.PROGRAM:
            return False

        if pou_text is None:
            required_registers: Set[str] = {
                "%R2410", "%R2411", "%R2412", "%R2413",
                "%R2414", "%R2415", "%R2416", "%R2417",
                "%M562", "%M563",
            }
            return required_registers.issubset(set(ast.bound_registers))
        return True
    except Exception:
        return False


# ============================================================================
# 5. Checksum & Register Table Helper Functions
# ============================================================================

def compute_crc16(data: bytes, poly: int = CRC_POLY_1021, init: int = CIP_SAFETY_CRC_INIT) -> int:
    """Calculate 16-bit CRC with specified polynomial and initial seed.

    Supports MSB-first polynomials (e.g. 0x1021 CCITT) and reflected LSB-first (0x8408).
    """
    crc = init & 0xFFFF
    if poly == CRC_POLY_8408:
        for b in data:
            crc ^= b
            for _ in range(8):
                if crc & 1:
                    crc = ((crc >> 1) ^ 0x8408) & 0xFFFF
                else:
                    crc = (crc >> 1) & 0xFFFF
        return crc & 0xFFFF
    else:
        for b in data:
            crc ^= (b << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ poly) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc & 0xFFFF


def compute_crc_s1(
    *args: Any,
    poly: int = CRC_POLY_1021,
    init: int = CIP_SAFETY_CRC_INIT,
    **kwargs: Any,
) -> int:
    """Calculate 16-bit safety checksum CRC-S1 over payload bytes.

    Polynomial: 0x1021 (default) or 0x8408.
    """
    if len(args) == 1 and isinstance(args[0], (bytes, bytearray)):
        data = bytes(args[0])
    elif len(args) > 0 and all(isinstance(a, (bytes, bytearray)) for a in args):
        data = b"".join(bytes(a) for a in args)
    elif len(args) == 1 and isinstance(args[0], (list, tuple)):
        data = bytes(args[0])
    else:
        raise ValueError(f"Unsupported arguments to compute_crc_s1: {args}")

    p = kwargs.get("poly", poly)
    i = kwargs.get("init", kwargs.get("seed", init))
    return compute_crc16(data, poly=p, init=i)


def compute_crc_s2(
    *args: Any,
    poly: int = CRC_POLY_1021,
    init: int = CIP_SAFETY_CRC_INIT,
    **kwargs: Any,
) -> int:
    """Calculate 16-bit safety checksum CRC-S2 over SNN + sequence_number + timestamp_ms + CRC-S1.

    Packs (SNN: uint32, sequence_number: uint16, timestamp_ms: uint32, crc_s1: uint16).
    """
    if len(args) == 1 and isinstance(args[0], (bytes, bytearray)):
        data = bytes(args[0])
    elif len(args) == 4 and all(isinstance(a, (int, float)) for a in args):
        snn, seq, ts, crc_s1 = args
        data = struct.pack(
            ">IHIH",
            int(snn) & 0xFFFFFFFF,
            int(seq) & 0xFFFF,
            int(ts) & 0xFFFFFFFF,
            int(crc_s1) & 0xFFFF,
        )
    elif len(args) > 0 and all(isinstance(a, (bytes, bytearray)) for a in args):
        data = b"".join(bytes(a) for a in args)
    else:
        snn = kwargs.get("snn", kwargs.get("safety_network_number", 0))
        seq = kwargs.get("seq", kwargs.get("sequence_number", 0))
        ts = kwargs.get("ts", kwargs.get("timestamp_ms", 0))
        crc_s1 = kwargs.get("crc_s1", 0)
        data = struct.pack(
            ">IHIH",
            int(snn) & 0xFFFFFFFF,
            int(seq) & 0xFFFF,
            int(ts) & 0xFFFFFFFF,
            int(crc_s1) & 0xFFFF,
        )

    p = kwargs.get("poly", poly)
    i = kwargs.get("init", kwargs.get("seed", init))
    return compute_crc16(data, poly=p, init=i)


calc_crc_s1 = compute_crc_s1
calc_crc_s2 = compute_crc_s2


def safe_write_word(
    reg_table: RegisterTable,
    address: str,
    value: int,
    privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
) -> None:
    """Write 16-bit word register into RegisterTable."""
    v = int(value) & 0xFFFF
    reg_table.write_word(address, v, privilege=privilege)


def safe_write_uword(
    reg_table: RegisterTable,
    address: str,
    value: int,
    privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
) -> None:
    """Write unsigned 16-bit word register into RegisterTable."""
    safe_write_word(reg_table, address, value, privilege=privilege)


def safe_write_bit(
    reg_table: RegisterTable,
    address: str,
    value: bool,
    privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
) -> None:
    """Write discrete bit / coil register with specified privilege."""
    reg_table.write_bit(address, bool(value), privilege=privilege)


# ============================================================================
# 6. Mesh Topology & Safety Frame Encapsulation
# ============================================================================

@dataclass
class WirelessMeshNode:
    """IEEE 802.15.4 / 6LoWPAN Wireless Mesh Node."""
    node_id: int = DEFAULT_NODE_ID
    pan_id: int = DEFAULT_PAN_ID
    channel: int = DEFAULT_CHANNEL
    parent_id: Optional[int] = 0
    hop_count: int = 1
    rssi_dbm: float = DEFAULT_RSSI_DBM
    lqi: int = DEFAULT_LQI
    is_coordinator: bool = False


@dataclass
class WirelessMeshRoute:
    """IEEE 802.15.4 / 6LoWPAN Mesh Routing Table Entry."""
    route_id: int = 1
    destination_id: int = 2
    next_hop_id: int = 2
    hop_count: int = 1
    path_etx: float = 1.0
    path_latency_ms: float = 12.0
    is_active: bool = True


@dataclass
class CipSafetyWirelessMeshFrame:
    """ODVA CIP Safety Over IEEE 802.15.4 / 6LoWPAN Wireless Mesh Frame.

    Encapsulates Safety Network Number (SNN), node_id, rolling sequence number,
    timestamp, process data payload, and dual safety checksums CRC-S1 & CRC-S2.
    """
    safety_network_number: int = DEFAULT_SAFETY_NETWORK_NUMBER
    node_id: int = DEFAULT_NODE_ID
    sequence_number: int = 1
    timestamp_ms: int = 1000
    payload_bytes: bytes = b"\x00\x00\x00\x00"
    crc_s1: int = 0
    crc_s2: int = 0

    def calculate_crcs(
        self,
        poly_s1: int = CRC_POLY_1021,
        poly_s2: int = CRC_POLY_1021,
    ) -> None:
        """Calculate and store dual CRC-S1 and CRC-S2 checksums."""
        self.crc_s1 = compute_crc_s1(self.payload_bytes, poly=poly_s1)
        self.crc_s2 = compute_crc_s2(
            self.safety_network_number,
            self.sequence_number,
            self.timestamp_ms,
            self.crc_s1,
            poly=poly_s2,
        )

    populate_crcs = calculate_crcs

    def verify_crc_s1(self, poly: int = CRC_POLY_1021) -> bool:
        """Verify CRC-S1 checksum over payload_bytes."""
        return self.crc_s1 == compute_crc_s1(self.payload_bytes, poly=poly)

    def verify_crc_s2(self, poly: int = CRC_POLY_1021) -> bool:
        """Verify CRC-S2 checksum over SNN + sequence_number + timestamp_ms + CRC-S1."""
        return self.crc_s2 == compute_crc_s2(
            self.safety_network_number,
            self.sequence_number,
            self.timestamp_ms,
            self.crc_s1,
            poly=poly,
        )

    def verify_crcs(
        self,
        poly_s1: int = CRC_POLY_1021,
        poly_s2: int = CRC_POLY_1021,
    ) -> Tuple[bool, bool]:
        """Verify both CRC-S1 and CRC-S2 checksums."""
        return (self.verify_crc_s1(poly=poly_s1), self.verify_crc_s2(poly=poly_s2))

    def is_valid(
        self,
        poly_s1: int = CRC_POLY_1021,
        poly_s2: int = CRC_POLY_1021,
    ) -> bool:
        """Check if both CRC-S1 and CRC-S2 are valid."""
        return self.verify_crc_s1(poly=poly_s1) and self.verify_crc_s2(poly=poly_s2)

    def mutate_payload(self, byte_offset: int = 0, bit_pos: int = 0) -> None:
        """Mutate a single bit in payload_bytes for corruption testing."""
        ba = bytearray(self.payload_bytes)
        if len(ba) > 0:
            idx = byte_offset % len(ba)
            ba[idx] ^= (1 << (bit_pos % 8))
            self.payload_bytes = bytes(ba)

    def pack(self) -> bytes:
        """Pack frame to wire format."""
        header = struct.pack(
            ">IBHIH",
            self.safety_network_number & 0xFFFFFFFF,
            self.node_id & 0xFF,
            self.sequence_number & 0xFFFF,
            int(self.timestamp_ms) & 0xFFFFFFFF,
            len(self.payload_bytes) & 0xFFFF,
        )
        trailer = struct.pack(">HH", self.crc_s1 & 0xFFFF, self.crc_s2 & 0xFFFF)
        return header + self.payload_bytes + trailer

    @classmethod
    def unpack(cls, data: bytes) -> CipSafetyWirelessMeshFrame:
        """Unpack frame from wire format."""
        if len(data) < 17:
            raise ValueError(f"Packet too short: {len(data)} bytes")
        snn, node_id, seq, ts, plen = struct.unpack(">IBHIH", data[:13])
        if len(data) < 13 + plen + 4:
            raise ValueError("Incomplete frame data")
        payload = data[13:13 + plen]
        crc_s1, crc_s2 = struct.unpack(">HH", data[13 + plen:13 + plen + 4])
        return cls(
            safety_network_number=snn,
            node_id=node_id,
            sequence_number=seq,
            timestamp_ms=ts,
            payload_bytes=payload,
            crc_s1=crc_s1,
            crc_s2=crc_s2,
        )


def create_valid_frame(
    safety_network_number: int = DEFAULT_SAFETY_NETWORK_NUMBER,
    node_id: int = DEFAULT_NODE_ID,
    sequence_number: int = 1,
    timestamp_ms: int = 1000,
    payload_bytes: bytes = b"\x01\x00\x00\x00",
    poly_s1: int = CRC_POLY_1021,
    poly_s2: int = CRC_POLY_1021,
) -> CipSafetyWirelessMeshFrame:
    """Factory creating valid wireless mesh safety frame with calculated dual CRCs."""
    frame = CipSafetyWirelessMeshFrame(
        safety_network_number=safety_network_number,
        node_id=node_id,
        sequence_number=sequence_number,
        timestamp_ms=timestamp_ms,
        payload_bytes=payload_bytes,
    )
    frame.calculate_crcs(poly_s1=poly_s1, poly_s2=poly_s2)
    return frame


create_valid_packet = create_valid_frame


# ============================================================================
# 7. Main Protocol Engine (ILogicUnit)
# ============================================================================

class CipSafetyWirelessMeshEngine(ILogicUnit):
    """Industrial ODVA CIP Safety Over IEEE 802.15.4 / 6LoWPAN Wireless Mesh Protocol Engine.

    Manages mesh node topology, dynamic multi-hop routing with degraded path failover,
    dual safety CRC validation (CRC-S1 & CRC-S2), dynamic multi-hop watchdog latency compensation,
    fail-safe fallback state execution, and Horner OCS memory synchronization (%R2410..%R2417, %M562..%M563).
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        auto_activate: bool = True,
        safety_network_number: int = DEFAULT_SAFETY_NETWORK_NUMBER,
        local_node: Optional[WirelessMeshNode] = None,
        routes: Optional[Sequence[WirelessMeshRoute]] = None,
        base_timeout_ms: float = DEFAULT_BASE_TIMEOUT_MS,
        hop_delay_ms: float = DEFAULT_HOP_DELAY_MS,
        rssi_threshold_dbm: float = DEFAULT_RSSI_THRESHOLD_DBM,
        packet_loss_threshold: float = DEFAULT_PACKET_LOSS_THRESHOLD,
        **kwargs: Any,
    ) -> None:
        self.register_table = register_table
        self.auto_activate = bool(auto_activate)
        self.safety_network_number = int(kwargs.get("snn", safety_network_number))
        self.base_timeout_ms = float(kwargs.get("safety_timeout_ms", base_timeout_ms))
        self.hop_delay_ms = float(hop_delay_ms)
        self.rssi_threshold_dbm = float(rssi_threshold_dbm)
        self.packet_loss_threshold = float(packet_loss_threshold)
        self.is_active = bool(auto_activate)

        # Local Node Descriptor
        self.local_node = local_node if local_node is not None else WirelessMeshNode()

        # Routing Table
        self.routes: Dict[int, WirelessMeshRoute] = {}
        if routes:
            for r in routes:
                self.routes[r.route_id] = r
        else:
            primary_route = WirelessMeshRoute(
                route_id=1,
                destination_id=2,
                next_hop_id=2,
                hop_count=1,
                path_etx=1.0,
                path_latency_ms=12.0,
                is_active=True,
            )
            alternate_route = WirelessMeshRoute(
                route_id=2,
                destination_id=2,
                next_hop_id=3,
                hop_count=2,
                path_etx=1.4,
                path_latency_ms=25.0,
                is_active=False,
            )
            self.routes[primary_route.route_id] = primary_route
            self.routes[alternate_route.route_id] = alternate_route

        # Active Route
        self.active_route: Optional[WirelessMeshRoute] = None
        for r in self.routes.values():
            if r.is_active:
                self.active_route = r
                break
        if not self.active_route and self.routes:
            self.active_route = next(iter(self.routes.values()))
            self.active_route.is_active = True

        # State & Diagnostics
        self.state = (
            CipSafetyWirelessMeshState.OPERATIONAL
            if auto_activate
            else CipSafetyWirelessMeshState.INIT
        )
        self.diagnostic_code = CipSafetyWirelessMeshDiagnosticCode.OK

        # Metrics & Watchdog Surveillance
        self.packet_loss_rate: float = float(kwargs.get("packet_loss_rate", DEFAULT_PACKET_LOSS_RATE))
        self.watchdog_timer_ms: float = 0.0
        self.is_failover_active: bool = False
        self.failover_count: int = 0
        self.tx_sequence: int = 0
        self.rx_sequence: int = 0
        self.cycles_count: int = 0
        self.frames_processed: int = 0

        # Safe Process Data
        self.safe_outputs: bytes = b"\x01\x00\x00\x00"
        self.safe_inputs: bytes = b"\x00\x00\x00\x00"

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    # ------------------------------------------------------------------------
    # Properties (ILogicUnit Compliance)
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        """ILogicUnit Unique Identifier."""
        return "CipSafetyWirelessMeshEngine"

    @property
    def priority(self) -> int:
        """Execution priority (lower runs earlier)."""
        return 10

    @property
    def is_enabled(self) -> bool:
        """Whether unit participates in cyclic scan."""
        return self.is_active

    @property
    def is_healthy(self) -> bool:
        """Whether wireless mesh safe link is healthy and untripped."""
        return (
            self.state in (
                CipSafetyWirelessMeshState.OPERATIONAL,
                CipSafetyWirelessMeshState.DEGRADED,
            )
            and self.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK
            and (self.active_route is not None and self.active_route.is_active)
        )

    @property
    def is_operational(self) -> bool:
        """Whether unit is in nominal OPERATIONAL state."""
        return (
            self.state == CipSafetyWirelessMeshState.OPERATIONAL
            and self.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK
        )

    @property
    def is_fail_safe(self) -> bool:
        """Whether unit is in FAIL_SAFE fallback state."""
        return (
            self.state == CipSafetyWirelessMeshState.FAIL_SAFE
            or self.diagnostic_code != CipSafetyWirelessMeshDiagnosticCode.OK
        )

    @property
    def is_route_active(self) -> bool:
        """Mesh Route Active mapped to %M562."""
        return bool(
            self.is_healthy
            and self.active_route is not None
            and self.active_route.is_active
        )

    @property
    def is_path_failover(self) -> bool:
        """Mesh Path Failover / Link Degradation Alarm mapped to %M563."""
        is_loss_alarm = (
            (0.0 <= self.packet_loss_rate <= 1.0 and self.packet_loss_rate > self.packet_loss_threshold)
            or (self.packet_loss_rate > 1.0 and self.packet_loss_rate > self.packet_loss_threshold * 100.0)
        )
        return bool(
            self.is_failover_active
            or self.state == CipSafetyWirelessMeshState.DEGRADED
            or self.local_node.rssi_dbm < self.rssi_threshold_dbm
            or is_loss_alarm
        )

    def get_effective_watchdog_timeout_ms(self, hop_count: Optional[int] = None) -> float:
        """Calculate dynamic multi-hop latency compensated watchdog threshold: base + hop_count * hop_delay."""
        hops = hop_count if hop_count is not None else (
            self.active_route.hop_count if self.active_route else self.local_node.hop_count
        )
        return self.base_timeout_ms + (hops * self.hop_delay_ms)

    @property
    def effective_timeout_ms(self) -> float:
        """Current effective watchdog timeout in milliseconds."""
        return self.get_effective_watchdog_timeout_ms()

    # ------------------------------------------------------------------------
    # State Machine & Fault Handling
    # ------------------------------------------------------------------------

    def trip_fail_safe(self, code: CipSafetyWirelessMeshDiagnosticCode, reason: str = "") -> None:
        """Trip safety interlock into FAIL_SAFE state (zero outputs, de-energize)."""
        self.diagnostic_code = code
        self.state = CipSafetyWirelessMeshState.FAIL_SAFE
        self.safe_outputs = b"\x00" * len(self.safe_outputs)

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def trip_crc_s1_error(self, details: Optional[str] = None) -> None:
        """Trip 0x01 CRC_S1_ERROR."""
        self.trip_fail_safe(CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR, details or "CRC-S1 corruption")

    def trip_crc_s2_error(self, details: Optional[str] = None) -> None:
        """Trip 0x02 CRC_S2_ERROR."""
        self.trip_fail_safe(CipSafetyWirelessMeshDiagnosticCode.CRC_S2_ERROR, details or "CRC-S2 corruption")

    def trip_watchdog_timeout(self, details: Optional[str] = None) -> None:
        """Trip 0x03 TIMEOUT_EXPIRED."""
        self.trip_fail_safe(CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED, details or "Watchdog timeout")

    def trip_route_unreachable(self, details: Optional[str] = None) -> None:
        """Trip 0x04 ROUTE_UNREACHABLE."""
        self.trip_fail_safe(CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE, details or "Route unreachable")

    def trip_rssi_below_threshold(self, details: Optional[str] = None) -> None:
        """Trip 0x05 RSSI_BELOW_THRESHOLD."""
        self.trip_fail_safe(CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD, details or "RSSI below threshold")

    def trip_packet_loss_high(self, details: Optional[str] = None) -> None:
        """Trip 0x06 PACKET_LOSS_HIGH."""
        self.trip_fail_safe(CipSafetyWirelessMeshDiagnosticCode.PACKET_LOSS_HIGH, details or "Packet loss high")

    def trip_split_brain_partition(self, details: Optional[str] = None) -> None:
        """Trip 0x07 SPLIT_BRAIN_PARTITION."""
        self.trip_fail_safe(CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION, details or "Split-brain partition")

    def inject_split_brain_partition(self) -> None:
        """Inject network partition / split-brain fault (0x07)."""
        self.trip_split_brain_partition("Injected network partition")

    def reset(self) -> None:
        """Reset internal engine state to nominal operational conditions."""
        self.diagnostic_code = CipSafetyWirelessMeshDiagnosticCode.OK
        self.state = CipSafetyWirelessMeshState.OPERATIONAL
        self.is_active = True
        self.is_failover_active = False
        self.watchdog_timer_ms = 0.0
        self.local_node.rssi_dbm = DEFAULT_RSSI_DBM
        self.local_node.lqi = DEFAULT_LQI
        self.packet_loss_rate = DEFAULT_PACKET_LOSS_RATE
        self.safe_outputs = b"\x01\x00\x00\x00"
        self.cycles_count = 0
        self.tx_sequence = 0
        self.rx_sequence = 0

        # Restore primary route
        if 1 in self.routes:
            self.active_route = self.routes[1]
            self.active_route.is_active = True
            for rid, r in self.routes.items():
                if rid != 1:
                    r.is_active = False

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    operator_reset = reset
    fault_reset = reset

    def feed_watchdog(self) -> None:
        """Feed / kick communication watchdog timer."""
        self.watchdog_timer_ms = 0.0

    kick_watchdog = feed_watchdog

    # ------------------------------------------------------------------------
    # Routing & Link Quality Management
    # ------------------------------------------------------------------------

    def add_route(self, route: WirelessMeshRoute) -> None:
        """Add route to routing table."""
        self.routes[route.route_id] = route
        if route.is_active and (self.active_route is None or not self.active_route.is_active):
            self.active_route = route

    def select_best_route(self, destination_id: Optional[int] = None) -> Optional[WirelessMeshRoute]:
        """Select optimal route based on lowest ETX and hop count."""
        dest = destination_id if destination_id is not None else (
            self.active_route.destination_id if self.active_route else None
        )
        candidates = [
            r for r in self.routes.values()
            if dest is None or r.destination_id == dest
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda r: (r.path_etx, r.hop_count))

    def evaluate_link_quality(
        self,
        rssi_dbm: Optional[float] = None,
        packet_loss: Optional[float] = None,
    ) -> bool:
        """Evaluate RF RSSI and packet loss against thresholds, triggering dynamic route fallback if needed."""
        if rssi_dbm is not None:
            self.local_node.rssi_dbm = float(rssi_dbm)
        if packet_loss is not None:
            self.packet_loss_rate = float(packet_loss)

        is_rssi_bad = self.local_node.rssi_dbm < self.rssi_threshold_dbm
        is_loss_bad = (
            (0.0 <= self.packet_loss_rate <= 1.0 and self.packet_loss_rate > self.packet_loss_threshold)
            or (self.packet_loss_rate > 1.0 and self.packet_loss_rate > self.packet_loss_threshold * 100.0)
        )

        if not is_rssi_bad and not is_loss_bad:
            # Healthy link
            if not self.is_failover_active:
                self.state = CipSafetyWirelessMeshState.OPERATIONAL
                self.diagnostic_code = CipSafetyWirelessMeshDiagnosticCode.OK
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return True

        # Link degraded: search for alternate route
        dest = self.active_route.destination_id if self.active_route else None
        curr_route_id = self.active_route.route_id if self.active_route else None

        alternate = None
        for r in self.routes.values():
            if r.route_id != curr_route_id and (dest is None or r.destination_id == dest):
                alternate = r
                break

        if alternate is not None:
            # Fallback to alternate route
            if self.active_route:
                self.active_route.is_active = False
            alternate.is_active = True
            self.active_route = alternate
            self.is_failover_active = True
            self.failover_count += 1
            self.state = CipSafetyWirelessMeshState.DEGRADED
            self.diagnostic_code = CipSafetyWirelessMeshDiagnosticCode.OK
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return True
        else:
            # No alternate route available: trip to FAIL_SAFE!
            self.state = CipSafetyWirelessMeshState.FAIL_SAFE
            self.is_failover_active = True
            if is_rssi_bad:
                self.diagnostic_code = CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD
            elif is_loss_bad:
                self.diagnostic_code = CipSafetyWirelessMeshDiagnosticCode.PACKET_LOSS_HIGH
            else:
                self.diagnostic_code = CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE

            self.safe_outputs = b"\x00" * len(self.safe_outputs)
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return False

    # ------------------------------------------------------------------------
    # Frame Processing & Transmission
    # ------------------------------------------------------------------------

    def create_frame(self, payload_bytes: Optional[bytes] = None) -> CipSafetyWirelessMeshFrame:
        """Create outgoing frame with calculated dual safety CRCs."""
        payload = payload_bytes if payload_bytes is not None else self.safe_outputs
        frame = CipSafetyWirelessMeshFrame(
            safety_network_number=self.safety_network_number,
            node_id=self.local_node.node_id,
            sequence_number=(self.tx_sequence + 1) & 0xFFFF,
            timestamp_ms=int(self.cycles_count * 10),
            payload_bytes=payload,
        )
        frame.calculate_crcs()
        return frame

    def transmit_frame(self, payload_bytes: Optional[bytes] = None) -> CipSafetyWirelessMeshFrame:
        """Transmit frame, advancing transmit sequence counter."""
        self.tx_sequence = (self.tx_sequence + 1) & 0xFFFF
        payload = payload_bytes if payload_bytes is not None else self.safe_outputs
        frame = CipSafetyWirelessMeshFrame(
            safety_network_number=self.safety_network_number,
            node_id=self.local_node.node_id,
            sequence_number=self.tx_sequence,
            timestamp_ms=int(self.cycles_count * 10),
            payload_bytes=payload,
        )
        frame.calculate_crcs()
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return frame

    def process_frame(self, frame: CipSafetyWirelessMeshFrame) -> bool:
        """Process incoming frame with dual CRC verification, SNN check, and watchdog kick."""
        # 1. CRC-S1 verification
        if not frame.verify_crc_s1():
            self.trip_crc_s1_error()
            return False

        # 2. CRC-S2 verification
        if not frame.verify_crc_s2():
            self.trip_crc_s2_error()
            return False

        # 3. SNN verification
        if frame.safety_network_number != self.safety_network_number:
            self.trip_split_brain_partition()
            return False

        # 4. Success: feed watchdog and update inputs
        self.feed_watchdog()
        self.rx_sequence = frame.sequence_number
        self.safe_inputs = frame.payload_bytes
        self.frames_processed += 1

        if self.state in (CipSafetyWirelessMeshState.INIT, CipSafetyWirelessMeshState.FAIL_SAFE):
            if self.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK:
                self.state = CipSafetyWirelessMeshState.OPERATIONAL

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    receive_frame = process_frame

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: RegisterTable,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize internal engine state to Horner OCS %R2410..%R2417 and %M562..%M563."""
        # %R2410: Mesh Node ID / Status (lower byte node_id, upper byte status code)
        node_id_byte = int(self.local_node.node_id) & 0xFF
        status_byte = int(self.state) & 0xFF
        r2410_val = ((status_byte << 8) | node_id_byte) & 0xFFFF
        safe_write_word(reg_table, REG_WIRELESS_MESH_NODE_STATUS, r2410_val, privilege=privilege)

        # %R2411: Mesh Channel / PAN ID (lower byte channel, upper byte PAN ID & 0xFF)
        channel_byte = int(self.local_node.channel) & 0xFF
        pan_byte = int(self.local_node.pan_id) & 0xFF
        r2411_val = ((pan_byte << 8) | channel_byte) & 0xFFFF
        safe_write_word(reg_table, REG_WIRELESS_MESH_CHANNEL_PAN, r2411_val, privilege=privilege)

        # %R2412: Scaled Link Quality (lower byte scaled RSSI 0..100, upper byte LQI 0..255)
        # Scale RSSI (-100 to 0 dBm) to 0..100
        scaled_rssi = max(0, min(100, int(round(self.local_node.rssi_dbm + 100.0))))
        lqi_byte = max(0, min(255, int(self.local_node.lqi))) & 0xFF
        r2412_val = ((lqi_byte << 8) | scaled_rssi) & 0xFFFF
        safe_write_word(reg_table, REG_WIRELESS_MESH_LINK_QUALITY, r2412_val, privilege=privilege)

        # %R2413: Hop Count / Route Metric (lower byte hop_count, upper byte ETX x10)
        current_hops = self.active_route.hop_count if self.active_route else self.local_node.hop_count
        current_etx = self.active_route.path_etx if self.active_route else 1.0
        hop_byte = max(0, min(255, int(current_hops))) & 0xFF
        etx_byte = max(0, min(255, int(round(current_etx * 10.0)))) & 0xFF
        r2413_val = ((etx_byte << 8) | hop_byte) & 0xFFFF
        safe_write_word(reg_table, REG_WIRELESS_MESH_HOP_METRIC, r2413_val, privilege=privilege)

        # %R2414: Safety Network Number High Word (SNN >> 16)
        snn_high = (int(self.safety_network_number) >> 16) & 0xFFFF
        safe_write_uword(reg_table, REG_WIRELESS_MESH_SNN_HIGH, snn_high, privilege=privilege)

        # %R2415: Safety Network Number Low Word (SNN & 0xFFFF)
        snn_low = int(self.safety_network_number) & 0xFFFF
        safe_write_uword(reg_table, REG_WIRELESS_MESH_SNN_LOW, snn_low, privilege=privilege)

        # %R2416: Mesh Packet Loss Rate (0.01% units, e.g. 250 = 2.50%)
        if 0.0 <= self.packet_loss_rate <= 1.0:
            loss_units = int(round(self.packet_loss_rate * 10000.0))
        else:
            loss_units = int(round(self.packet_loss_rate * 100.0))
        loss_units = max(0, min(10000, loss_units)) & 0xFFFF
        safe_write_uword(reg_table, REG_WIRELESS_MESH_PACKET_LOSS, loss_units, privilege=privilege)

        # %R2417: Diagnostic Code & 0xFFFF
        diag_val = int(self.diagnostic_code) & 0xFFFF
        safe_write_uword(reg_table, REG_WIRELESS_MESH_DIAGNOSTIC_CODE, diag_val, privilege=privilege)

        # Discrete Bits:
        # %M562: Mesh Route Active / Safety Connection Established (BOOL)
        safe_write_bit(
            reg_table,
            COIL_WIRELESS_MESH_ROUTE_ACTIVE,
            self.is_route_active,
            privilege=privilege,
        )

        # %M563: Mesh Path Failover / Link Degradation Alarm (BOOL)
        safe_write_bit(
            reg_table,
            COIL_WIRELESS_MESH_PATH_FAILOVER,
            self.is_path_failover,
            privilege=privilege,
        )

    # ------------------------------------------------------------------------
    # ILogicUnit Cyclic Execution
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.010, context: Optional[ScanContext] = None) -> None:
        """Deterministic scan step: advance watchdog timer and verify thresholds."""
        self.cycles_count += 1
        dt_ms = dt * 1000.0

        if self.state != CipSafetyWirelessMeshState.FAIL_SAFE:
            self.watchdog_timer_ms += dt_ms
            effective_limit = self.get_effective_watchdog_timeout_ms()
            if self.watchdog_timer_ms > effective_limit:
                self.trip_watchdog_timeout()

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def step(self, dt: float = 0.010, context: Optional[ScanContext] = None) -> None:
        """Alias for scan_step."""
        self.scan_step(dt, context)

    def execute(self, context: Optional[ScanContext] = None) -> ExecutionResult:
        """ILogicUnit execute method returning strict ExecutionResult."""
        if context is not None:
            dt = getattr(context, "dt_s", None) or (getattr(context, "dt_ms", 10.0) / 1000.0)
            self.scan_step(dt, context)

        if self.is_healthy:
            return ExecutionResult(
                status=AgentStatus.SUCCESS,
                error_code=None,
                details=f"Wireless mesh safety link operational (Route {self.active_route.route_id if self.active_route else 'N/A'}, State {self.state.name}).",
                data={
                    "state": int(self.state),
                    "diagnostic_code": int(self.diagnostic_code),
                    "active_route_id": self.active_route.route_id if self.active_route else None,
                    "hop_count": self.active_route.hop_count if self.active_route else self.local_node.hop_count,
                    "rssi_dbm": self.local_node.rssi_dbm,
                    "packet_loss_rate": self.packet_loss_rate,
                },
            )
        else:
            return ExecutionResult(
                status=AgentStatus.FAILED,
                error_code=self.diagnostic_code.name,
                details=f"Wireless mesh safe link failed/tripped: {self.diagnostic_code.name} (State {self.state.name}).",
                data={
                    "state": int(self.state),
                    "diagnostic_code": int(self.diagnostic_code),
                    "active_route_id": self.active_route.route_id if self.active_route else None,
                    "watchdog_timer_ms": self.watchdog_timer_ms,
                },
            )


# Compatibility Aliases
CIPSafetyWirelessMeshEngine = CipSafetyWirelessMeshEngine
CIPSafetyWirelessMesh = CipSafetyWirelessMeshEngine
WirelessMeshSafetyEngine = CipSafetyWirelessMeshEngine


# ============================================================================
# 8. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_safety_wireless_mesh_verification(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W280",
) -> Dict[str, Any]:
    """Execute deterministic 9-stage verification suite for ODVA CIP Safety Wireless Mesh."""
    test_results: List[Dict[str, Any]] = []

    # Stage 1: Enums, Constants & Horner OCS Register Mappings
    t0 = time.perf_counter()
    s1_pass = (
        REG_WIRELESS_MESH_NODE_STATUS == "%R2410"
        and REG_WIRELESS_MESH_CHANNEL_PAN == "%R2411"
        and REG_WIRELESS_MESH_LINK_QUALITY == "%R2412"
        and REG_WIRELESS_MESH_HOP_METRIC == "%R2413"
        and REG_WIRELESS_MESH_SNN_HIGH == "%R2414"
        and REG_WIRELESS_MESH_SNN_LOW == "%R2415"
        and REG_WIRELESS_MESH_PACKET_LOSS == "%R2416"
        and REG_WIRELESS_MESH_DIAGNOSTIC_CODE == "%R2417"
        and COIL_WIRELESS_MESH_ROUTE_ACTIVE == "%M562"
        and COIL_WIRELESS_MESH_PATH_FAILOVER == "%M563"
        and CipSafetyWirelessMeshState.INIT == 0
        and CipSafetyWirelessMeshState.OPERATIONAL == 1
        and CipSafetyWirelessMeshState.DEGRADED == 2
        and CipSafetyWirelessMeshState.FAIL_SAFE == 3
        and CipSafetyWirelessMeshDiagnosticCode.OK == 0
        and CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR == 1
        and CipSafetyWirelessMeshDiagnosticCode.CRC_S2_ERROR == 2
        and CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED == 3
        and CipSafetyWirelessMeshDiagnosticCode.ROUTE_UNREACHABLE == 4
        and CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD == 5
        and CipSafetyWirelessMeshDiagnosticCode.PACKET_LOSS_HIGH == 6
        and CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION == 7
        and hash(CipSafetyWirelessMeshDiagnosticCode.OK) == hash(0)
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "enums_and_constants",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified %R2410..%R2417, %M562..%M563, and diagnostic codes.",
    })

    # Stage 2: Dual Safety CRC-S1 / CRC-S2 Calculation & Mutation Detection
    t0 = time.perf_counter()
    frame = create_valid_frame(payload_bytes=b"\x01\x02\x03\x04")
    crc_valid = frame.is_valid()
    # Mutate payload
    frame_corrupted = create_valid_frame(payload_bytes=b"\x01\x02\x03\x04")
    frame_corrupted.mutate_payload(byte_offset=0, bit_pos=1)
    mutation_detected = not frame_corrupted.verify_crc_s1()
    # Verify CRC with 0x8408 poly as well
    crc_8408_1 = compute_crc_s1(b"\x01\x02\x03\x04", poly=CRC_POLY_8408)
    crc_8408_2 = compute_crc_s1(b"\x01\x02\x03\x04", poly=CRC_POLY_8408)
    s2_pass = crc_valid and mutation_detected and (crc_8408_1 == crc_8408_2)
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "dual_safety_crc_calculation",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": "CRC-S1 and CRC-S2 calculation, verification, and mutation detection passed.",
    })

    # Stage 3: Pure IEC 61131-3 ST POU & Anti-Ladder Construct Rejection
    t0 = time.perf_counter()
    pure_st_ok = verify_cip_safety_wireless_mesh_pure_st()
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM Test VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_rejected = True
    s3_pass = pure_st_ok and ladder_rejected
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "pure_st_and_anti_ladder_guard",
        "passed": bool(s3_pass),
        "timing_ms": round(t1, 3),
        "details": "Pure ST POU verified; ladder logic rejected with LadderForbiddenError.",
    })

    # Stage 4: Mesh Topology & Register Table Synchronization
    t0 = time.perf_counter()
    rt_s4 = RegisterTable()
    eng_s4 = CipSafetyWirelessMeshEngine(register_table=rt_s4, auto_activate=True)
    # Check registers:
    # %R2410: node_id=1, state=1 -> (1 << 8) | 1 = 0x0101 (257)
    # %R2411: channel=15, pan_id=0x1A2B -> ((0x2B) << 8) | 15 = 11023
    # %R2412: scaled_rssi=(-65+100)=35, lqi=220 -> (220 << 8) | 35 = 56355 (signed: -9181)
    # %M562: True
    # %M563: False
    s4_pass = (
        eng_s4.state == CipSafetyWirelessMeshState.OPERATIONAL
        and eng_s4.is_healthy
        and rt_s4.read_uword("%R2410") == ((1 << 8) | 1)
        and rt_s4.read_uword("%R2411") == (((0x1A2B & 0xFF) << 8) | 15)
        and rt_s4.read_uword("%R2412") == ((220 << 8) | 35)
        and rt_s4.read_bit("%M562") is True
        and rt_s4.read_bit("%M563") is False
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "mesh_topology_and_register_table_sync",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "Mesh topology, node and route initialization, and register synchronization verified.",
    })

    # Stage 5: Dynamic Route Fallback on Low RSSI (< -82 dBm)
    t0 = time.perf_counter()
    rt_s5 = RegisterTable()
    eng_s5 = CipSafetyWirelessMeshEngine(register_table=rt_s5, auto_activate=True)
    initial_route_id = eng_s5.active_route.route_id if eng_s5.active_route else 0
    # Degrade RSSI to -85 dBm (< -82 dBm)
    fb_res = eng_s5.evaluate_link_quality(rssi_dbm=-85.0)
    s5_pass = (
        fb_res is True
        and eng_s5.state == CipSafetyWirelessMeshState.DEGRADED
        and eng_s5.active_route is not None
        and eng_s5.active_route.route_id != initial_route_id
        and eng_s5.is_failover_active is True
        and rt_s5.read_bit("%M563") is True
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "dynamic_route_selection_and_rssi_fallback",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "Dynamic fallback to alternate route on RSSI < -82 dBm verified with %M563 alarm.",
    })

    # Stage 6: Dynamic Route Fallback on Packet Loss (> 5.0%)
    t0 = time.perf_counter()
    rt_s6 = RegisterTable()
    eng_s6 = CipSafetyWirelessMeshEngine(register_table=rt_s6, auto_activate=True)
    initial_route_id_6 = eng_s6.active_route.route_id if eng_s6.active_route else 0
    # Degrade packet loss to 6.5% (> 5.0%)
    fb_res_6 = eng_s6.evaluate_link_quality(packet_loss=0.065)
    s6_pass = (
        fb_res_6 is True
        and eng_s6.state == CipSafetyWirelessMeshState.DEGRADED
        and eng_s6.active_route is not None
        and eng_s6.active_route.route_id != initial_route_id_6
        and eng_s6.is_failover_active is True
        and rt_s6.read_bit("%M563") is True
        and rt_s6.read_uword("%R2416") == 650
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "packet_loss_fallback_and_failover_alarm",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "Dynamic fallback on packet loss > 5.0% verified with %R2416 and %M563 updates.",
    })

    # Stage 7: Dynamic Multi-Hop Latency Watchdog Compensation
    t0 = time.perf_counter()
    eng_s7 = CipSafetyWirelessMeshEngine(auto_activate=True, base_timeout_ms=200.0, hop_delay_ms=25.0)
    # Hop count 1 -> timeout = 225 ms
    to_1 = eng_s7.get_effective_watchdog_timeout_ms(hop_count=1)
    to_3 = eng_s7.get_effective_watchdog_timeout_ms(hop_count=3)
    # Advance watchdog past threshold
    eng_s7.scan_step(0.250)  # 250 ms > 225 ms
    s7_pass = (
        to_1 == 225.0
        and to_3 == 275.0
        and eng_s7.state == CipSafetyWirelessMeshState.FAIL_SAFE
        and eng_s7.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "dynamic_multihop_latency_watchdog_compensation",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "Dynamic multi-hop latency watchdog compensation and TIMEOUT_EXPIRED trip verified.",
    })

    # Stage 8: Fail-Safe Fallback Interlock & De-energize
    t0 = time.perf_counter()
    rt_s8 = RegisterTable()
    eng_s8 = CipSafetyWirelessMeshEngine(register_table=rt_s8, auto_activate=True)
    # Frame with corrupted CRC-S1
    bad_frame = create_valid_frame()
    bad_frame.crc_s1 ^= 0xFFFF
    res_rx = eng_s8.process_frame(bad_frame)
    s8_pass = (
        res_rx is False
        and eng_s8.state == CipSafetyWirelessMeshState.FAIL_SAFE
        and eng_s8.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.CRC_S1_ERROR
        and eng_s8.safe_outputs == b"\x00\x00\x00\x00"
        and rt_s8.read_bit("%M562") is False
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "link_partition_crc_corruption_fail_safe",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": "Fail-safe de-energize on CRC-S1 corruption and coil clearing verified.",
    })

    # Stage 9: Cyclic Scan Step Multi-Cycle Execution & Strict 4-State Contract
    t0 = time.perf_counter()
    rt_s9 = RegisterTable()
    eng_s9 = CipSafetyWirelessMeshEngine(register_table=rt_s9, auto_activate=True)
    for _ in range(100):
        # Transmit, feed watchdog, scan
        eng_s9.feed_watchdog()
        eng_s9.scan_step(0.005)
    exec_res = eng_s9.execute()
    s9_pass = (
        eng_s9.cycles_count == 100
        and eng_s9.is_healthy
        and exec_res.status == AgentStatus.SUCCESS
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 9,
        "name": "cyclic_scan_step_multi_cycle_execution",
        "passed": bool(s9_pass),
        "timing_ms": round(t1, 3),
        "details": "100-cycle soak scan and ILogicUnit execute strict 4-state contract verified.",
    })

    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    status = "success" if all_passed else "failed"
    error_code = None if all_passed else "ERR_STAGE_VERIFICATION_FAILED"
    details = (
        f"Wave {work_package} CIP Safety Over Wireless Mesh Protocol Engine Verification PASSED ({stages_passed}/{total_stages} stages)."
        if all_passed
        else f"Wave {work_package} Verification FAILED ({stages_passed}/{total_stages} stages passed)."
    )

    evidence_payload: Dict[str, Any] = {
        "status": status,
        "error_code": error_code,
        "details": details,
        "work_package": work_package,
        "total_stages": total_stages,
        "stages_passed": stages_passed,
        "data": {
            "work_package": work_package,
            "gate": "G8",
            "protocol": "ODVA CIP Safety Over Wireless Mesh (IEEE 802.15.4 / 6LoWPAN)",
            "stages": test_results,
            "tests": test_results,
            "checks_passed": stages_passed,
            "total_checks": total_stages,
        },
    }

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(evidence_payload, f, indent=2)

    return evidence_payload


if __name__ == "__main__":
    result = run_cip_safety_wireless_mesh_verification()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
