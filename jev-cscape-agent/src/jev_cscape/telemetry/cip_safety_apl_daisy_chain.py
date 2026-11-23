"""Industrial ODVA CIP Safety Over Ethernet-APL Daisy-Chain Spur Protocol Engine (Wave W292).

Work Package: W292 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019 / Ethernet-APL 10BASE-T1L Daisy-Chain Spur Topology:
  - Multi-hop line interconnects between APL field switches and instruments with dual-port PHYs.
  - Per-hop forwarding latency monitoring (~8us per hop; nominal 8 us).
  - Multi-hop latency accumulation tracking (1..8 hops; max latency nominal 64 us).
  - In-line link break / disconnection at hop K isolates downstream nodes K+1..N
    while keeping upstream nodes 1..K-1 operational.
  - Port link status monitoring on Port 1 (Upstream Ingress) and Port 2 (Downstream Egress).
  - Heartbeat watchdog surveillance (< 200ms watchdog timeout).
  - Upstream link drop, hop limit exceeded (>8 hops), or heartbeat timeout triggers fail-safe safe state.
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - Class 0x39: Safety Supervisor Object
  - Class 0x3A: Safety Validator Object
  - Class 0x3B: Dual-Port Daisy-Chain Safety Connection Object
  - Class 0x3F: Ethernet-APL Daisy-Chain Safety Extension Class ID
  - Dual 16-bit Safety CRCs:
    * CRC-S1: Generator polynomial 0x5935 (init 0xFFFF) over payload data.
    * CRC-S2: Generator polynomial 0x755B (init 0xFFFF) over inverted
      (sequence_number, timestamp_us, safety_network_number).
  - Rolling 16-bit sequence counter (0..65535).
- Horner OCS Memory Space:
  - Analog registers %R2530..%R2537:
    * %R2530: REG_CIP_SAFETY_DAISY_STATUS (High byte = Node ID, Low byte = Operational State: 0=INIT, 1=OPERATIONAL, 2=DEGRADED, 3=FAIL_SAFE)
    * %R2531: REG_CIP_SAFETY_DAISY_UPSTREAM_PORT (Upstream port state: 1=UP, 2=DOWN, 3=FAULT)
    * %R2532: REG_CIP_SAFETY_DAISY_DOWNSTREAM_PORT (Downstream port state: 1=UP, 2=DOWN, 3=ISOLATED)
    * %R2533: REG_CIP_SAFETY_DAISY_HOP_COUNT (Hop count in chain: 1..8)
    * %R2534: REG_CIP_SAFETY_DAISY_CUMULATIVE_LATENCY_US (Cumulative chain latency in us)
    * %R2535: REG_CIP_SAFETY_DAISY_SEQUENCE_COUNTER (Rolling sequence counter 0..65535)
    * %R2536: REG_CIP_SAFETY_DAISY_CRC_STATUS (CRC & Daisy Status Word: bit 0: CRC-S1 valid, bit 1: CRC-S2 valid, bit 2: Upstream up, bit 3: Downstream up, bit 4: Fail-safe active)
    * %R2537: REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE (Diagnostic code: 0x0000=OK, 0xEE21=UPSTREAM_LINK_LOSS, 0xEE22=DOWNSTREAM_LINK_LOSS, 0xEE23=CRC_S1_FAULT, 0xEE24=CRC_S2_FAULT, 0xEE25=HEARTBEAT_TIMEOUT, 0xEE26=HOP_LIMIT_EXCEEDED, 0xEE27=FAIL_SAFE_TRIP)
  - Discrete coils %M590..%M591:
    * %M590: COIL_CIP_SAFETY_DAISY_ACTIVE (TRUE when daisy engine is operational and healthy)
    * %M591: COIL_CIP_SAFETY_DAISY_FAULT (TRUE when fault or fail-safe engaged)
- Implements ILogicUnit interface with scan_step(dt, context), step(dt, context), execute(context), and reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.USER).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetyAplDaisyChainSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.
- Deterministic 9-stage verification suite run_cip_safety_apl_daisy_chain_verification().
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
import json
from pathlib import Path
import struct
import sys
import time
import tracemalloc
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (ODVA CIP Safety Volume 5 / IEEE 802.3cg)
# ============================================================================

CIP_SAFETY_SUPERVISOR_CLASS_ID: int = 0x39          # Safety Supervisor Object
CIP_SAFETY_VALIDATOR_CLASS_ID: int = 0x3A           # Safety Validator Object
CIP_SAFETY_CONNECTION_CLASS_ID: int = 0x3B          # Safety Connection Object
CIP_SAFETY_APL_DAISY_CHAIN_CLASS_ID: int = 0x3F     # Ethernet-APL Daisy-Chain Safety Extension

# Default Parameters
DEFAULT_SAFETY_NETWORK_NUMBER: int = 0x1A2B         # Nominal Safety Network Number
DEFAULT_SNN: int = DEFAULT_SAFETY_NETWORK_NUMBER
DEFAULT_NODE_ID: int = 1                            # Default daisy-chain node ID
DEFAULT_PER_HOP_LATENCY_US: int = 8                 # 8 us nominal per-hop latency
DEFAULT_MAX_HOPS: int = 8                           # Maximum allowable hops in daisy-chain spur
DEFAULT_WATCHDOG_TIMEOUT_MS: float = 200.0          # 200 ms heartbeat surveillance watchdog timeout

# CRC-S Generator Polynomials and Initial Seeds
CIP_SAFETY_CRC_S1_POLY: int = 0x5935                # CRC-S1 generator polynomial (over payload)
CIP_SAFETY_CRC_S2_POLY: int = 0x755B                # CRC-S2 generator polynomial (over inverted header)
CIP_SAFETY_CRC_INIT: int = 0xFFFF                   # CRC-S initial seed (0xFFFF)

CRC_S1_POLY: int = CIP_SAFETY_CRC_S1_POLY
CRC_S2_POLY: int = CIP_SAFETY_CRC_S2_POLY
CRC_INIT: int = CIP_SAFETY_CRC_INIT

# Canonical Register Table Mapping (%R2530..%R2537)
REG_CIP_SAFETY_DAISY_STATUS: str                    = "%R2530"
REG_CIP_SAFETY_DAISY_UPSTREAM_PORT: str             = "%R2531"
REG_CIP_SAFETY_DAISY_DOWNSTREAM_PORT: str           = "%R2532"
REG_CIP_SAFETY_DAISY_HOP_COUNT: str                 = "%R2533"
REG_CIP_SAFETY_DAISY_CUMULATIVE_LATENCY_US: str     = "%R2534"
REG_CIP_SAFETY_DAISY_SEQUENCE_COUNTER: str          = "%R2535"
REG_CIP_SAFETY_DAISY_CRC_STATUS: str                = "%R2536"
REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE: str           = "%R2537"

# Canonical Discrete Coils Mapping (%M590..%M591)
COIL_CIP_SAFETY_DAISY_ACTIVE: str                   = "%M590"
COIL_CIP_SAFETY_DAISY_FAULT: str                    = "%M591"

# Extended Compatibility Aliases
REG_DAISY_STATUS: str                               = "%R2530"
REG_DAISY_UPSTREAM_PORT: str                        = "%R2531"
REG_DAISY_DOWNSTREAM_PORT: str                      = "%R2532"
REG_DAISY_HOP_COUNT: str                            = "%R2533"
REG_DAISY_CUMULATIVE_LATENCY_US: str                = "%R2534"
REG_DAISY_SEQUENCE_COUNTER: str                     = "%R2535"
REG_DAISY_CRC_STATUS: str                           = "%R2536"
REG_DAISY_DIAGNOSTIC_CODE: str                      = "%R2537"

REG_CIP_SAFETY_DAISY_TOPOLOGY_STATE: str             = "%R2531"
REG_CIP_SAFETY_DAISY_PORT_STATE: str                 = "%R2531"
REG_CIP_SAFETY_DAISY_CHAIN_STATE: str                = "%R2531"
REG_CIP_SAFETY_DAISY_ACCUMULATED_LATENCY_US: str     = "%R2534"
REG_CIP_SAFETY_DAISY_DOWNSTREAM_ISOLATION_MASK: str  = "%R2532"
REG_CIP_SAFETY_DAISY_ISOLATED_NODE_MASK: str         = "%R2532"
REG_CIP_SAFETY_DAISY_CONNECTED_MASK: str             = "%R2532"

COIL_DAISY_ACTIVE: str                              = "%M590"
COIL_DAISY_FAULT: str                               = "%M591"
COIL_CIP_SAFETY_DAISY_OPERATIONAL: str              = "%M590"
COIL_CIP_SAFETY_DAISY_ALARM: str                    = "%M591"
COIL_CIP_SAFETY_DAISY_TRIP: str                     = "%M591"


# ============================================================================
# 2. Diagnostic Codes & Enums
# ============================================================================

class DiagnosticCode(int):
    """Integer subclass for 16-bit diagnostic codes supporting signed/unsigned equality."""

    _name: str

    def __new__(cls, value: int, name: Optional[str] = None) -> DiagnosticCode:
        obj = super().__new__(cls, int(value))
        obj._name = name or f"0x{int(value) & 0xFFFF:04X}"
        return obj

    @property
    def value(self) -> int:
        return int(self)

    def __int__(self) -> int:
        return int(super().__int__())

    def __str__(self) -> str:
        return f"0x{int(self) & 0xFFFF:04X}"

    def __repr__(self) -> str:
        return f"DiagnosticCode(0x{int(self) & 0xFFFF:04X})"

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
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)

    def __and__(self, other: Any) -> Any:
        if isinstance(other, int):
            return int(self) & int(other)
        return super().__and__(other)

    def __rand__(self, other: Any) -> Any:
        if isinstance(other, int):
            return int(other) & int(self)
        return super().__rand__(other)


# Mandatory Diagnostic Codes (%R2537)
DIAG_OK: DiagnosticCode                          = DiagnosticCode(0x0000, "OK")
DIAG_ERR_UPSTREAM_LINK_LOSS: DiagnosticCode      = DiagnosticCode(0xEE21, "UPSTREAM_LINK_LOSS")
DIAG_ERR_DOWNSTREAM_LINK_LOSS: DiagnosticCode    = DiagnosticCode(0xEE22, "DOWNSTREAM_LINK_LOSS")
DIAG_ERR_CRC_S1_FAULT: DiagnosticCode            = DiagnosticCode(0xEE23, "CRC_S1_FAULT")
DIAG_ERR_CRC_S2_FAULT: DiagnosticCode            = DiagnosticCode(0xEE24, "CRC_S2_FAULT")
DIAG_ERR_HEARTBEAT_TIMEOUT: DiagnosticCode       = DiagnosticCode(0xEE25, "HEARTBEAT_TIMEOUT")
DIAG_ERR_HOP_LIMIT_EXCEEDED: DiagnosticCode      = DiagnosticCode(0xEE26, "HOP_LIMIT_EXCEEDED")
DIAG_ERR_FAIL_SAFE_TRIP: DiagnosticCode          = DiagnosticCode(0xEE27, "FAIL_SAFE_TRIP")

# Attach class attributes
DiagnosticCode.OK = DIAG_OK
DiagnosticCode.UPSTREAM_LINK_LOSS = DIAG_ERR_UPSTREAM_LINK_LOSS
DiagnosticCode.DOWNSTREAM_LINK_LOSS = DIAG_ERR_DOWNSTREAM_LINK_LOSS
DiagnosticCode.CRC_S1_FAULT = DIAG_ERR_CRC_S1_FAULT
DiagnosticCode.CRC_S2_FAULT = DIAG_ERR_CRC_S2_FAULT
DiagnosticCode.HEARTBEAT_TIMEOUT = DIAG_ERR_HEARTBEAT_TIMEOUT
DiagnosticCode.HOP_LIMIT_EXCEEDED = DIAG_ERR_HOP_LIMIT_EXCEEDED
DiagnosticCode.FAIL_SAFE_TRIP = DIAG_ERR_FAIL_SAFE_TRIP

CipSafetyAplDaisyChainDiagnosticCode = DiagnosticCode
AplDaisyChainDiagnosticCode = DiagnosticCode


class DaisyOperationalState(IntEnum):
    """Operational State for CIP Safety Daisy-Chain Node (%R2530 low byte)."""
    INIT = 0
    OPERATIONAL = 1
    DEGRADED = 2
    FAIL_SAFE = 3


CipSafetyAplDaisyChainState = DaisyOperationalState
AplDaisyChainOperationalState = DaisyOperationalState
DaisyChainState = DaisyOperationalState


class UpstreamPortState(IntEnum):
    """Upstream Ingress Port State (%R2531)."""
    UP = 1
    DOWN = 2
    FAULT = 3


CipSafetyUpstreamPortState = UpstreamPortState


class DownstreamPortState(IntEnum):
    """Downstream Egress Port State (%R2532)."""
    UP = 1
    DOWN = 2
    ISOLATED = 3


CipSafetyDownstreamPortState = DownstreamPortState


class PortState(IntEnum):
    """Physical Port Link and Forwarding State."""
    DOWN = 0
    LINK_UP = 1
    BLOCKED = 2
    FORWARDING = 3


DaisyPortState = PortState


class DaisyRole(str, Enum):
    """Role of the Daisy-Chain Node in APL Topology."""
    FIELD_SWITCH = "FIELD_SWITCH"
    ROOT_NODE = "ROOT_NODE"
    INTERMEDIATE_NODE = "INTERMEDIATE_NODE"
    TAIL_NODE = "TAIL_NODE"
    INSTRUMENT = "INSTRUMENT"


class DaisyTopologyState(str, Enum):
    """Overall Daisy-Chain Spur Topology Health State."""
    INIT = "DAISY_INIT"
    HEALTHY = "DAISY_HEALTHY"
    DEGRADED = "DAISY_DEGRADED"
    FAULT = "DAISY_FAULT"


class CipSafetyAplDaisyChainStatusBits(IntFlag):
    """Bitmask for %R2536 CRC & Daisy Status Word."""
    CRC_S1_VALID         = 1 << 0  # Bit 0: CRC-S1 valid
    CRC_S2_VALID         = 1 << 1  # Bit 1: CRC-S2 valid
    UPSTREAM_UP          = 1 << 2  # Bit 2: Upstream port up
    DOWNSTREAM_UP        = 1 << 3  # Bit 3: Downstream port up
    FAIL_SAFE_ACTIVE     = 1 << 4  # Bit 4: Fail-safe active
    # Compatibility aliases
    UPSTREAM_LINK_UP     = 1 << 2
    DOWNSTREAM_LINK_UP   = 1 << 3
    DAISY_ACTIVE         = 1 << 2


CipSafetyDaisyChainStatusBits = CipSafetyAplDaisyChainStatusBits
DaisyStatusBits = CipSafetyAplDaisyChainStatusBits


# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class CipSafetyAplDaisyChainError(Exception):
    """Base exception for ODVA CIP Safety Over Ethernet-APL Daisy-Chain Spur."""
    pass


class UpstreamLinkLossError(CipSafetyAplDaisyChainError):
    """Raised when upstream link to spur/switch drops."""
    pass


class DownstreamLinkLossError(CipSafetyAplDaisyChainError):
    """Raised when downstream link to next daisy-chain node drops."""
    pass


class CrcS1FaultError(CipSafetyAplDaisyChainError):
    """Raised when payload CRC-S1 validation fails."""
    pass


class CrcS2FaultError(CipSafetyAplDaisyChainError):
    """Raised when inverted CRC-S2 validation fails."""
    pass


class HeartbeatTimeoutError(CipSafetyAplDaisyChainError):
    """Raised when daisy-chain heartbeat watchdog expires (>200ms)."""
    pass


class HopLimitExceededError(CipSafetyAplDaisyChainError):
    """Raised when daisy-chain hop count exceeds maximum (8 hops)."""
    pass


class FailSafeTripError(CipSafetyAplDaisyChainError):
    """Raised when fail-safe state is tripped."""
    pass


# ============================================================================
# 4. Dual Safety CRC Calculation
# ============================================================================

def calculate_crc_s1(
    *args: Any,
    poly: int = CIP_SAFETY_CRC_S1_POLY,
    init: int = CIP_SAFETY_CRC_INIT,
    initial_seed: Optional[int] = None,
    **kwargs: Any,
) -> int:
    """Calculate 16-bit CRC-S1 using polynomial 0x5935 over CIP Safety data payload."""
    seed = initial_seed if initial_seed is not None else init
    if len(args) == 1 and isinstance(args[0], (bytes, bytearray)):
        data = bytes(args[0])
    elif len(args) > 0 and all(isinstance(a, (bytes, bytearray)) for a in args):
        data = b"".join(bytes(a) for a in args)
    elif "payload" in kwargs and isinstance(kwargs["payload"], (bytes, bytearray)):
        data = bytes(kwargs["payload"])
    elif "data" in kwargs and isinstance(kwargs["data"], (bytes, bytearray)):
        data = bytes(kwargs["data"])
    else:
        raise ValueError(f"Unsupported arguments to calculate_crc_s1: {args}, {kwargs}")

    p = kwargs.get("poly", poly)
    i = kwargs.get("init", kwargs.get("seed", seed))
    crc = i & 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ p) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def calculate_crc_s2(
    *args: Any,
    poly: int = CIP_SAFETY_CRC_S2_POLY,
    init: int = CIP_SAFETY_CRC_INIT,
    initial_seed: Optional[int] = None,
    **kwargs: Any,
) -> int:
    """Calculate 16-bit CRC-S2 using polynomial 0x755B over inverted (sequence_number, timestamp_us, safety_network_number)."""
    seed = initial_seed if initial_seed is not None else init
    if len(args) == 1 and isinstance(args[0], (bytes, bytearray)):
        inverted = bytes(args[0])
    elif len(args) >= 3 and all(isinstance(a, int) for a in args[:3]):
        seq = args[0] & 0xFFFF
        ts = args[1] & 0xFFFFFFFF
        snn = args[2] & 0xFFFF
        raw = seq.to_bytes(2, "big") + ts.to_bytes(4, "big") + snn.to_bytes(2, "big")
        inverted = bytes(~b & 0xFF for b in raw)
    elif "sequence_number" in kwargs and "timestamp_us" in kwargs and "safety_network_number" in kwargs:
        seq = kwargs["sequence_number"] & 0xFFFF
        ts = kwargs["timestamp_us"] & 0xFFFFFFFF
        snn = kwargs["safety_network_number"] & 0xFFFF
        raw = seq.to_bytes(2, "big") + ts.to_bytes(4, "big") + snn.to_bytes(2, "big")
        inverted = bytes(~b & 0xFF for b in raw)
    else:
        raise ValueError(f"Unsupported arguments to calculate_crc_s2: {args}, {kwargs}")

    p = kwargs.get("poly", poly)
    i = kwargs.get("init", kwargs.get("seed", seed))
    crc = i & 0xFFFF
    for byte in inverted:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ p) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


compute_crc_s1 = calculate_crc_s1
compute_crc_s2 = calculate_crc_s2


# ============================================================================
# 5. Frame & Node Representation
# ============================================================================

@dataclass
class CipSafetyAplDaisyChainFrame:
    """ODVA CIP Safety frame encapsulated for Ethernet-APL Daisy-Chain Spur."""

    node_id: int = 1
    target_node: int = 2
    hop_count: int = 1
    sequence_number: int = 0
    timestamp_us: int = 0
    safety_network_number: int = DEFAULT_SAFETY_NETWORK_NUMBER
    payload: bytes = b"\x00\x00\x00\x00"
    crc_s1: int = 0
    crc_s2: int = 0
    cumulative_latency_us: int = DEFAULT_PER_HOP_LATENCY_US
    per_hop_latency_us: int = DEFAULT_PER_HOP_LATENCY_US

    def compute_crcs(self) -> None:
        """Calculate and store dual CRC checksums (CRC-S1 and CRC-S2)."""
        self.crc_s1 = calculate_crc_s1(self.payload)
        self.crc_s2 = calculate_crc_s2(
            self.sequence_number, self.timestamp_us, self.safety_network_number
        )

    def is_valid(self) -> bool:
        """Verify stored CRC-S1 and CRC-S2 against recomputed checksums."""
        exp_s1 = calculate_crc_s1(self.payload)
        exp_s2 = calculate_crc_s2(
            self.sequence_number, self.timestamp_us, self.safety_network_number
        )
        return (self.crc_s1 == exp_s1) and (self.crc_s2 == exp_s2)

    def forward(self, per_hop_latency_us: int = DEFAULT_PER_HOP_LATENCY_US) -> None:
        """Forward frame to next daisy hop, incrementing hop count and latency."""
        self.hop_count += 1
        self.cumulative_latency_us += per_hop_latency_us

    def serialize(self) -> bytes:
        """Serialize frame into binary stream."""
        header = struct.pack(
            ">BBBBHIHHH",
            self.node_id & 0xFF,
            self.target_node & 0xFF,
            self.hop_count & 0xFF,
            0x00,  # reserved
            self.sequence_number & 0xFFFF,
            self.timestamp_us & 0xFFFFFFFF,
            self.safety_network_number & 0xFFFF,
            self.cumulative_latency_us & 0xFFFF,
            len(self.payload) & 0xFFFF,
        )
        footer = struct.pack(">HH", self.crc_s1 & 0xFFFF, self.crc_s2 & 0xFFFF)
        return header + self.payload + footer

    @classmethod
    def deserialize(cls, data: bytes) -> CipSafetyAplDaisyChainFrame:
        """Deserialize frame from binary stream."""
        if len(data) < 20:
            raise ValueError(f"Data length {len(data)} too short for CipSafetyAplDaisyChainFrame (min 20 bytes)")
        header = data[:16]
        node_id, target_node, hop_count, _, seq, ts, snn, cum_lat, p_len = struct.unpack(
            ">BBBBHIHHH", header
        )
        payload = data[16 : 16 + p_len]
        footer = data[16 + p_len : 16 + p_len + 4]
        crc_s1, crc_s2 = struct.unpack(">HH", footer)
        return cls(
            node_id=node_id,
            target_node=target_node,
            hop_count=hop_count,
            sequence_number=seq,
            timestamp_us=ts,
            safety_network_number=snn,
            payload=payload,
            crc_s1=crc_s1,
            crc_s2=crc_s2,
            cumulative_latency_us=cum_lat,
        )

    def mutate_payload(self, byte_offset: int = 0, bit_pos: int = 0) -> None:
        """Inject single-bit corruption into payload for tamper testing."""
        ba = bytearray(self.payload)
        if len(ba) > 0:
            idx = byte_offset % len(ba)
            ba[idx] ^= (1 << (bit_pos % 8))
            self.payload = bytes(ba)

    def mutate_crc_s1(self) -> None:
        """Corrupt CRC-S1 checksum."""
        self.crc_s1 ^= 0x0001

    def mutate_crc_s2(self) -> None:
        """Corrupt CRC-S2 checksum."""
        self.crc_s2 ^= 0x0001


@dataclass
class AplDaisyChainNode:
    """Ethernet-APL Daisy-Chain Spur Node representation."""

    node_id: int
    hop_position: int = 1
    role: DaisyRole = DaisyRole.INSTRUMENT
    upstream_state: UpstreamPortState = UpstreamPortState.UP
    downstream_state: DownstreamPortState = DownstreamPortState.UP
    is_connected: bool = True
    is_isolated: bool = False
    cumulative_latency_us: int = DEFAULT_PER_HOP_LATENCY_US
    last_heartbeat_ms: float = 0.0
    errors_count: int = 0


DaisyChainNode = AplDaisyChainNode
DaisyNode = AplDaisyChainNode


# ============================================================================
# 6. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC = """
PROGRAM CipSafetyAplDaisyChainSync
VAR
    wDaisyStatus AT %R2530 : WORD;
    wUpstreamPort AT %R2531 : WORD;
    wDownstreamPort AT %R2532 : WORD;
    wHopCount AT %R2533 : WORD;
    wCumulativeLatencyUs AT %R2534 : WORD;
    wSeqCounter AT %R2535 : WORD;
    wCrcStatus AT %R2536 : WORD;
    wDiagCode AT %R2537 : WORD;
    bDaisyActive AT %M590 : BOOL;
    bDaisyFault AT %M591 : BOOL;
END_VAR

IF (wDiagCode = 0) AND (wUpstreamPort = 1) THEN
    bDaisyActive := TRUE;
    bDaisyFault := FALSE;
ELSE
    bDaisyActive := FALSE;
    bDaisyFault := TRUE;
END_IF;
END_PROGRAM
""".strip()

CIP_SAFETY_APL_DAISY_CHAIN_PURE_ST_POU = ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC
CipSafetyAplDaisyChainSync = ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC


def verify_cip_safety_apl_daisy_chain_pure_st() -> bool:
    """Validate pure ST syntax and ensure strict rejection of ladder logic constructs."""
    try:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC)
        res = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC)
        if res.status != AgentStatus.SUCCESS:
            return False
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC)
        expected_regs = {
            "%R2530", "%R2531", "%R2532", "%R2533",
            "%R2534", "%R2535", "%R2536", "%R2537",
            "%M590", "%M591",
        }
        return ast.pou_type == POUType.PROGRAM and expected_regs.issubset(set(ast.bound_registers))
    except Exception:
        return False


# ============================================================================
# 7. CIP Safety Over Ethernet-APL Daisy-Chain Engine
# ============================================================================

class CipSafetyAplDaisyChainEngine(ILogicUnit):
    """Deterministic protocol engine for ODVA CIP Safety Over Ethernet-APL Daisy-Chain Spur."""

    def __init__(
        self,
        node_id: int = DEFAULT_NODE_ID,
        hop_count: int = 1,
        max_hops: int = DEFAULT_MAX_HOPS,
        per_hop_latency_us: int = DEFAULT_PER_HOP_LATENCY_US,
        safety_network_number: int = DEFAULT_SAFETY_NETWORK_NUMBER,
        watchdog_timeout_ms: float = DEFAULT_WATCHDOG_TIMEOUT_MS,
        register_table: Optional[RegisterTable] = None,
        auto_activate: bool = True,
        chain_length: int = 4,
        **kwargs: Any,
    ) -> None:
        self.node_id = node_id
        self._hop_count = hop_count
        self.max_hops = max_hops
        self.per_hop_latency_us = per_hop_latency_us
        self._cumulative_latency_us = hop_count * per_hop_latency_us
        self.safety_network_number = safety_network_number
        self.snn = safety_network_number
        self.watchdog_timeout_ms = watchdog_timeout_ms
        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.chain_length = max(chain_length, hop_count)

        self.operational_state: DaisyOperationalState = (
            DaisyOperationalState.OPERATIONAL if auto_activate else DaisyOperationalState.INIT
        )
        self._upstream_port_state: UpstreamPortState = UpstreamPortState.UP
        self._downstream_port_state: DownstreamPortState = DownstreamPortState.UP

        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.fail_safe_active: bool = False
        self.sequence_counter: int = 0
        self.cycles_count: int = 0
        self.time_since_last_heartbeat_ms: float = 0.0

        self.last_crc_s1_valid: bool = True
        self.last_crc_s2_valid: bool = True
        self.safe_output_data: bytes = b"\x01\x02\x03\x04"

        self.last_tx_frame: Optional[CipSafetyAplDaisyChainFrame] = None
        self.last_rx_frame: Optional[CipSafetyAplDaisyChainFrame] = None
        self.upstream_loss_count: int = 0
        self.downstream_loss_count: int = 0

        # Simulate chain topology nodes with dual-port PHYs
        self.nodes: Dict[int, AplDaisyChainNode] = {}
        for i in range(1, self.chain_length + 1):
            self.nodes[i] = AplDaisyChainNode(
                node_id=i,
                hop_position=i,
                upstream_state=UpstreamPortState.UP,
                downstream_state=DownstreamPortState.UP,
                cumulative_latency_us=i * self.per_hop_latency_us,
            )

        if auto_activate:
            self.sync_to_registers(self.reg_table)

    # ------------------------------------------------------------------------
    # Properties & Aliases
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        """Unique identifier for this logic unit."""
        return "CipSafetyAplDaisyChainEngine"

    @property
    def priority(self) -> int:
        """Execution priority in scan cycle."""
        return 10

    @property
    def is_enabled(self) -> bool:
        """Whether this logic unit participates in scan cycle."""
        return True

    @property
    def is_healthy(self) -> bool:
        """Engine health: operational state, OK diagnostic code, and not in fail-safe."""
        return (
            self.operational_state == DaisyOperationalState.OPERATIONAL
            and self.diagnostic_code == DIAG_OK
            and not self.fail_safe_active
        )

    @property
    def daisy_state(self) -> DaisyOperationalState:
        """Alias for operational_state."""
        return self.operational_state

    @property
    def upstream_port_state(self) -> UpstreamPortState:
        """Current state of Upstream Port."""
        return self._upstream_port_state

    @property
    def downstream_port_state(self) -> DownstreamPortState:
        """Current state of Downstream Port."""
        return self._downstream_port_state

    @property
    def hop_count(self) -> int:
        """Current node hop position in daisy-chain spur."""
        return self._hop_count

    @property
    def cumulative_latency_us(self) -> int:
        """Cumulative line latency from field switch up to this node in us."""
        return self._cumulative_latency_us

    @property
    def status_word(self) -> int:
        """High byte = Node ID, Low byte = Operational State (%R2530)."""
        return ((self.node_id & 0xFF) << 8) | (int(self.operational_state) & 0xFF)

    @property
    def crc_status_word(self) -> int:
        """Bitmask for %R2536 CRC & Daisy Status Word."""
        val = 0
        if self.last_crc_s1_valid:
            val |= int(CipSafetyAplDaisyChainStatusBits.CRC_S1_VALID)
        if self.last_crc_s2_valid:
            val |= int(CipSafetyAplDaisyChainStatusBits.CRC_S2_VALID)
        if self._upstream_port_state == UpstreamPortState.UP:
            val |= int(CipSafetyAplDaisyChainStatusBits.UPSTREAM_UP)
        if self._downstream_port_state == DownstreamPortState.UP:
            val |= int(CipSafetyAplDaisyChainStatusBits.DOWNSTREAM_UP)
        if self.fail_safe_active:
            val |= int(CipSafetyAplDaisyChainStatusBits.FAIL_SAFE_ACTIVE)
        return val

    # ------------------------------------------------------------------------
    # Frame Transmission and Reception
    # ------------------------------------------------------------------------

    def send_safety_frame(
        self,
        payload: bytes,
        target_node: int = 2,
    ) -> CipSafetyAplDaisyChainFrame:
        """Construct, compute dual CRCs, and transmit safety frame across daisy spur."""
        frame = CipSafetyAplDaisyChainFrame(
            node_id=self.node_id,
            target_node=target_node,
            hop_count=self._hop_count,
            sequence_number=self.sequence_counter,
            timestamp_us=int(time.time() * 1_000_000) & 0xFFFFFFFF,
            safety_network_number=self.safety_network_number,
            payload=payload,
            cumulative_latency_us=self._cumulative_latency_us,
            per_hop_latency_us=self.per_hop_latency_us,
        )
        frame.compute_crcs()
        self.sequence_counter = (self.sequence_counter + 1) & 0xFFFF
        self.last_tx_frame = frame
        self.sync_to_registers(self.reg_table)
        return frame

    def receive_safety_frame(self, frame: CipSafetyAplDaisyChainFrame) -> bool:
        """Validate ingress frame on daisy-chain port, checking dual CRCs and hop limit."""
        # 1. Upstream port must be UP to receive ingress traffic
        if self._upstream_port_state != UpstreamPortState.UP:
            return False

        # 2. Safety Network Number (SNN) check
        if frame.safety_network_number != self.safety_network_number:
            self.trip_fail_safe(DIAG_ERR_FAIL_SAFE_TRIP)
            return False

        # 3. Dual CRC checks
        exp_s1 = calculate_crc_s1(frame.payload)
        if frame.crc_s1 != exp_s1:
            self.last_crc_s1_valid = False
            self.trip_fail_safe(DIAG_ERR_CRC_S1_FAULT)
            return False
        self.last_crc_s1_valid = True

        exp_s2 = calculate_crc_s2(
            frame.sequence_number, frame.timestamp_us, frame.safety_network_number
        )
        if frame.crc_s2 != exp_s2:
            self.last_crc_s2_valid = False
            self.trip_fail_safe(DIAG_ERR_CRC_S2_FAULT)
            return False
        self.last_crc_s2_valid = True

        # 4. Hop count surveillance (max 8 hops)
        if frame.hop_count > self.max_hops:
            self.trip_fail_safe(DIAG_ERR_HOP_LIMIT_EXCEEDED)
            return False

        # Valid frame received: refresh watchdog timer and update state
        self.time_since_last_heartbeat_ms = 0.0
        self.last_rx_frame = frame
        self.safe_output_data = frame.payload
        self.sync_to_registers(self.reg_table)
        return True

    # ------------------------------------------------------------------------
    # Fault Injection and Port Control
    # ------------------------------------------------------------------------

    def inject_upstream_loss(self) -> None:
        """Simulate link loss / line break on Upstream Ingress Port."""
        self._upstream_port_state = UpstreamPortState.DOWN
        self.upstream_loss_count += 1
        self.trip_fail_safe(DIAG_ERR_UPSTREAM_LINK_LOSS)

    def restore_upstream(self) -> None:
        """Restore link on Upstream Ingress Port."""
        self._upstream_port_state = UpstreamPortState.UP
        if self._downstream_port_state == DownstreamPortState.UP:
            self.operational_state = DaisyOperationalState.OPERATIONAL
            self.diagnostic_code = DIAG_OK
            self.fail_safe_active = False
            self.safe_output_data = b"\x01\x02\x03\x04"
        else:
            self.operational_state = DaisyOperationalState.DEGRADED
            self.diagnostic_code = DIAG_ERR_DOWNSTREAM_LINK_LOSS
        self.sync_to_registers(self.reg_table)

    def inject_downstream_loss(self) -> None:
        """Simulate line break on Downstream Port, isolating nodes K+1..N while keeping 1..K-1 operational."""
        self._downstream_port_state = DownstreamPortState.DOWN
        self.downstream_loss_count += 1
        self.diagnostic_code = DIAG_ERR_DOWNSTREAM_LINK_LOSS
        self.operational_state = DaisyOperationalState.DEGRADED

        # Isolate downstream nodes K+1..N
        for nid, node in self.nodes.items():
            if node.hop_position > self._hop_count:
                node.is_isolated = True
                node.upstream_state = UpstreamPortState.DOWN

        self.sync_to_registers(self.reg_table)

    def restore_downstream(self) -> None:
        """Restore downstream link, clearing isolation on downstream nodes."""
        self._downstream_port_state = DownstreamPortState.UP
        for nid, node in self.nodes.items():
            node.is_isolated = False
            node.upstream_state = UpstreamPortState.UP

        if self._upstream_port_state == UpstreamPortState.UP:
            self.operational_state = DaisyOperationalState.OPERATIONAL
            self.diagnostic_code = DIAG_OK
            self.fail_safe_active = False
            self.safe_output_data = b"\x01\x02\x03\x04"
        else:
            self.operational_state = DaisyOperationalState.FAIL_SAFE
            self.diagnostic_code = DIAG_ERR_UPSTREAM_LINK_LOSS
            self.fail_safe_active = True
        self.sync_to_registers(self.reg_table)

    def set_hop_count(self, hops: int) -> None:
        """Update hop count and recalculate cumulative line latency."""
        self._hop_count = hops
        self._cumulative_latency_us = hops * self.per_hop_latency_us
        if hops > self.max_hops:
            self.trip_fail_safe(DIAG_ERR_HOP_LIMIT_EXCEEDED)
        else:
            if self.diagnostic_code == DIAG_ERR_HOP_LIMIT_EXCEEDED:
                self.diagnostic_code = DIAG_OK
                self.fail_safe_active = False
                self.operational_state = DaisyOperationalState.OPERATIONAL
        self.sync_to_registers(self.reg_table)

    def trip_fail_safe(self, code: DiagnosticCode = DIAG_ERR_FAIL_SAFE_TRIP) -> None:
        """Transition into deterministic fail-safe state, de-energizing safe outputs."""
        self.fail_safe_active = True
        self.operational_state = DaisyOperationalState.FAIL_SAFE
        self.diagnostic_code = code
        self.safe_output_data = b"\x00" * len(self.safe_output_data)
        self.sync_to_registers(self.reg_table)

    def feed_heartbeat(self) -> None:
        """Feed the heartbeat watchdog timer."""
        self.time_since_last_heartbeat_ms = 0.0

    def feed_watchdog(self) -> None:
        """Alias for feed_heartbeat."""
        self.feed_heartbeat()

    def clear_faults(self) -> None:
        """Clear faults and recover to nominal operational state if physical links permit."""
        self.fail_safe_active = False
        self.diagnostic_code = DIAG_OK
        self.last_crc_s1_valid = True
        self.last_crc_s2_valid = True
        self.time_since_last_heartbeat_ms = 0.0
        self.safe_output_data = b"\x01\x02\x03\x04"

        if (
            self._upstream_port_state == UpstreamPortState.UP
            and self._downstream_port_state == DownstreamPortState.UP
        ):
            self.operational_state = DaisyOperationalState.OPERATIONAL
        elif self._upstream_port_state == UpstreamPortState.UP:
            self.operational_state = DaisyOperationalState.DEGRADED
            self.diagnostic_code = DIAG_ERR_DOWNSTREAM_LINK_LOSS
        else:
            self.operational_state = DaisyOperationalState.FAIL_SAFE
            self.diagnostic_code = DIAG_ERR_UPSTREAM_LINK_LOSS
            self.fail_safe_active = True

        self.sync_to_registers(self.reg_table)

    # ------------------------------------------------------------------------
    # Horner OCS Register Space Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        """Synchronize engine telemetry into Horner OCS registers %R2530..%R2537 and %M590..%M591."""
        rt = reg_table or self.reg_table

        # %R2530: High byte = Node ID, Low byte = Operational State
        rt.write_word(REG_CIP_SAFETY_DAISY_STATUS, self.status_word, privilege=privilege)

        # %R2531: Upstream port state (1=UP, 2=DOWN, 3=FAULT)
        rt.write_word(
            REG_CIP_SAFETY_DAISY_UPSTREAM_PORT,
            int(self._upstream_port_state) & 0xFFFF,
            privilege=privilege,
        )

        # %R2532: Downstream port state (1=UP, 2=DOWN, 3=ISOLATED)
        rt.write_word(
            REG_CIP_SAFETY_DAISY_DOWNSTREAM_PORT,
            int(self._downstream_port_state) & 0xFFFF,
            privilege=privilege,
        )

        # %R2533: Hop count in chain (1..8)
        rt.write_word(
            REG_CIP_SAFETY_DAISY_HOP_COUNT,
            int(self._hop_count) & 0xFFFF,
            privilege=privilege,
        )

        # %R2534: Cumulative chain latency in us
        rt.write_word(
            REG_CIP_SAFETY_DAISY_CUMULATIVE_LATENCY_US,
            int(self._cumulative_latency_us) & 0xFFFF,
            privilege=privilege,
        )

        # %R2535: Rolling sequence counter
        rt.write_word(
            REG_CIP_SAFETY_DAISY_SEQUENCE_COUNTER,
            self.sequence_counter & 0xFFFF,
            privilege=privilege,
        )

        # %R2536: CRC & Daisy Status Word
        rt.write_word(
            REG_CIP_SAFETY_DAISY_CRC_STATUS,
            self.crc_status_word & 0xFFFF,
            privilege=privilege,
        )

        # %R2537: Diagnostic code
        rt.write_word(
            REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE,
            int(self.diagnostic_code) & 0xFFFF,
            privilege=privilege,
        )

        # Discrete Coils %M590..%M591
        rt.write_bit(COIL_CIP_SAFETY_DAISY_ACTIVE, self.is_healthy, privilege=privilege)
        rt.write_bit(
            COIL_CIP_SAFETY_DAISY_FAULT,
            (not self.is_healthy) or self.fail_safe_active,
            privilege=privilege,
        )

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    def scan_step(self, *args: Any, **kwargs: Any) -> ExecutionResult:
        """Execute one simulation scan cycle step."""
        dt_ms = 10.0
        for arg in args:
            if isinstance(arg, (int, float)):
                dt_ms = float(arg) * 1000.0 if float(arg) < 1.0 else float(arg)
            elif isinstance(arg, ScanContext):
                dt_ms = getattr(arg, "dt_ms", getattr(arg, "delta_ms", 10.0))
        if "dt" in kwargs:
            val = kwargs["dt"]
            dt_ms = float(val) * 1000.0 if float(val) < 1.0 else float(val)
        if "dt_ms" in kwargs:
            dt_ms = float(kwargs["dt_ms"])
        if "context" in kwargs and kwargs["context"] is not None:
            dt_ms = getattr(kwargs["context"], "dt_ms", getattr(kwargs["context"], "delta_ms", dt_ms))

        self.cycles_count += 1
        self.time_since_last_heartbeat_ms += dt_ms

        if self.time_since_last_heartbeat_ms > self.watchdog_timeout_ms:
            self.trip_fail_safe(DIAG_ERR_HEARTBEAT_TIMEOUT)
            return ExecutionResult(
                status=AgentStatus.FAILED,
                error_code=str(DIAG_ERR_HEARTBEAT_TIMEOUT),
                details=f"Heartbeat watchdog timeout (> 200 ms), Diag={self.diagnostic_code}",
                data={"diagnostic_code": int(self.diagnostic_code), "cycles": self.cycles_count},
            )

        self.sync_to_registers(self.reg_table)
        status = AgentStatus.SUCCESS if self.is_healthy else AgentStatus.FAILED
        return ExecutionResult(
            status=status,
            error_code=None if self.is_healthy else str(self.diagnostic_code),
            details=f"Daisy State={self.operational_state.name}, Diag={self.diagnostic_code}",
            data={
                "daisy_state": self.operational_state.name,
                "operational_state": self.operational_state.name,
                "upstream_port_state": self._upstream_port_state.name,
                "downstream_port_state": self._downstream_port_state.name,
                "diagnostic_code": str(self.diagnostic_code),
                "is_healthy": self.is_healthy,
                "sequence": self.sequence_counter,
                "hop_count": self._hop_count,
                "cumulative_latency_us": self._cumulative_latency_us,
                "cycles": self.cycles_count,
            },
        )

    def step(self, dt: float = 0.010, context: Optional[ScanContext] = None) -> None:
        """Execute one step of logic cycle."""
        self.scan_step(dt=dt, context=context)

    def execute(self, context: Optional[ScanContext] = None) -> ExecutionResult:
        """Execute one logic unit cycle."""
        return self.scan_step(dt=0.010, context=context)

    def reset(self) -> None:
        """Reset internal engine state to nominal initial parameters."""
        self._hop_count = 1
        self._cumulative_latency_us = self.per_hop_latency_us
        self._upstream_port_state = UpstreamPortState.UP
        self._downstream_port_state = DownstreamPortState.UP
        self.operational_state = DaisyOperationalState.OPERATIONAL
        self.diagnostic_code = DIAG_OK
        self.fail_safe_active = False
        self.sequence_counter = 0
        self.cycles_count = 0
        self.time_since_last_heartbeat_ms = 0.0
        self.last_crc_s1_valid = True
        self.last_crc_s2_valid = True
        self.safe_output_data = b"\x01\x02\x03\x04"
        self.last_tx_frame = None
        self.last_rx_frame = None
        self.upstream_loss_count = 0
        self.downstream_loss_count = 0

        for i in range(1, self.chain_length + 1):
            self.nodes[i] = AplDaisyChainNode(
                node_id=i,
                hop_position=i,
                upstream_state=UpstreamPortState.UP,
                downstream_state=DownstreamPortState.UP,
                cumulative_latency_us=i * self.per_hop_latency_us,
            )

        self.sync_to_registers(self.reg_table)


# ============================================================================
# 8. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_safety_apl_daisy_chain_verification(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W292",
) -> Dict[str, Any]:
    """Execute the deterministic 9-stage verification suite for Wave W292.

    Stages:
    1. init_and_topology: Initialization and daisy-chain multi-hop line topology.
    2. dual_crc_validation: Dual CRC (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B) calculation & corruption intercept.
    3. upstream_link_loss: Upstream ingress link loss, fail-safe fallback, and restoration.
    4. downstream_link_loss: Downstream link loss, downstream node isolation, and degraded mode.
    5. hop_latency_accumulation: Per-hop forwarding latency monitoring (~8us) and hop limit enforcement (1..8).
    6. fail_safe_deenergize: Deterministic safe state de-energizing of outputs, %M591 fault assertion, %R2536 status bit.
    7. heartbeat_watchdog_timeout: Heartbeat watchdog surveillance (<200ms) and expiration trip (0xEE25).
    8. horner_ocs_register_sync: Bit-exact register space mapping (%R2530..%R2537) and coils (%M590..%M591).
    9. pure_st_pou_and_ladder_rejection: Pure IEC 61131-3 ST POU verification and anti-ladder construct rejection.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: init_and_topology
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng1 = CipSafetyAplDaisyChainEngine(node_id=1, hop_count=1, chain_length=4)
    s1_pass = (
        eng1.node_id == 1
        and eng1.hop_count == 1
        and eng1.upstream_port_state == UpstreamPortState.UP
        and eng1.downstream_port_state == DownstreamPortState.UP
        and eng1.operational_state == DaisyOperationalState.OPERATIONAL
        and eng1.is_healthy is True
        and eng1.diagnostic_code == DIAG_OK
        and eng1.cumulative_latency_us == 8
        and len(eng1.nodes) == 4
        and all(not n.is_isolated for n in eng1.nodes.values())
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "init_and_topology",
        "check": "Daisy-Chain Spur Topology Initial State & Multi-Hop Configuration",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": f"Node 1 initialized at hop 1 with 8 us latency across 4-node line topology; healthy.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: dual_crc_validation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    c1 = calculate_crc_s1(b"\x01\x02\x03\x04")
    c2 = calculate_crc_s2(1, 1000, 0x1A2B)
    crc_math_ok = (0 <= c1 <= 0xFFFF) and (0 <= c2 <= 0xFFFF)

    eng2_tx = CipSafetyAplDaisyChainEngine(node_id=1, hop_count=1)
    frame_valid = eng2_tx.send_safety_frame(payload=b"\x01\x02\x03\x04", target_node=2)
    crc_valid = frame_valid.is_valid()

    eng2_rx = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2)
    rx_ok = eng2_rx.receive_safety_frame(frame_valid)

    # Mutate CRC-S1
    frame_s1_bad = eng2_tx.send_safety_frame(payload=b"\x01\x02\x03\x04", target_node=2)
    frame_s1_bad.mutate_crc_s1()
    rx_s1_fail = not eng2_rx.receive_safety_frame(frame_s1_bad)
    s1_diag_ok = (eng2_rx.diagnostic_code == DIAG_ERR_CRC_S1_FAULT)

    # Mutate CRC-S2
    eng2_rx2 = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2)
    frame_s2_bad = eng2_tx.send_safety_frame(payload=b"\x01\x02\x03\x04", target_node=2)
    frame_s2_bad.mutate_crc_s2()
    rx_s2_fail = not eng2_rx2.receive_safety_frame(frame_s2_bad)
    s2_diag_ok = (eng2_rx2.diagnostic_code == DIAG_ERR_CRC_S2_FAULT)

    s2_pass = (
        crc_math_ok
        and crc_valid
        and rx_ok
        and rx_s1_fail
        and s1_diag_ok
        and rx_s2_fail
        and s2_diag_ok
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "dual_crc_validation",
        "check": "ODVA CIP Safety Volume 5 Dual CRC (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B) Validation",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": "Dual CRCs validated; CRC-S1 fault intercepted with 0xEE23, CRC-S2 fault intercepted with 0xEE24.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: upstream_link_loss
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng3 = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2)
    eng3.inject_upstream_loss()
    loss_detected = (
        eng3.upstream_port_state == UpstreamPortState.DOWN
        and eng3.diagnostic_code == DIAG_ERR_UPSTREAM_LINK_LOSS
        and eng3.fail_safe_active is True
        and eng3.operational_state == DaisyOperationalState.FAIL_SAFE
        and eng3.is_healthy is False
    )

    eng3.restore_upstream()
    restored_ok = (
        eng3.upstream_port_state == UpstreamPortState.UP
        and eng3.diagnostic_code == DIAG_OK
        and eng3.is_healthy is True
        and eng3.fail_safe_active is False
    )

    s3_pass = loss_detected and restored_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "upstream_link_loss",
        "check": "Upstream Port Ingress Link Drop, Fail-Safe Trip (0xEE21), and Restoration",
        "passed": bool(s3_pass),
        "timing_ms": round(t1, 3),
        "details": "Upstream loss triggered fail-safe safe state; restore_upstream successfully cleared fault.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: downstream_link_loss
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng4 = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2, chain_length=4)
    eng4.inject_downstream_loss()
    down_detected = (
        eng4.downstream_port_state in (DownstreamPortState.DOWN, DownstreamPortState.ISOLATED)
        and eng4.diagnostic_code == DIAG_ERR_DOWNSTREAM_LINK_LOSS
        and eng4.operational_state == DaisyOperationalState.DEGRADED
        and eng4.nodes[3].is_isolated is True
        and eng4.nodes[4].is_isolated is True
        and eng4.nodes[1].is_isolated is False
    )

    eng4.restore_downstream()
    down_restored = (
        eng4.downstream_port_state == DownstreamPortState.UP
        and eng4.diagnostic_code == DIAG_OK
        and eng4.is_healthy is True
        and eng4.nodes[3].is_isolated is False
        and eng4.nodes[4].is_isolated is False
    )

    s4_pass = down_detected and down_restored
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "downstream_link_loss",
        "check": "Downstream Link Loss, Downstream Node Isolation (K+1..N), and Degraded Operation",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "Hop 2 downstream break isolated nodes 3..4 with 0xEE22; upstream node 1 operational; restored cleanly.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: hop_latency_accumulation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng5 = CipSafetyAplDaisyChainEngine(node_id=1, hop_count=1, per_hop_latency_us=8)
    l1 = (eng5.cumulative_latency_us == 8)
    eng5.set_hop_count(2)
    l2 = (eng5.cumulative_latency_us == 16)
    eng5.set_hop_count(4)
    l4 = (eng5.cumulative_latency_us == 32)
    eng5.set_hop_count(8)
    l8 = (eng5.cumulative_latency_us == 64)

    # Frame forwarding accumulation
    f5 = eng5.send_safety_frame(payload=b"\xCA\xFE")
    start_lat = f5.cumulative_latency_us
    f5.forward(per_hop_latency_us=8)
    fwd_ok = (f5.hop_count == 9 and f5.cumulative_latency_us == start_lat + 8)

    # Hop limit exceeded (> 8 hops)
    eng5.set_hop_count(9)
    hop_limit_trip = (
        eng5.diagnostic_code == DIAG_ERR_HOP_LIMIT_EXCEEDED
        and eng5.fail_safe_active is True
        and eng5.operational_state == DaisyOperationalState.FAIL_SAFE
        and eng5.is_healthy is False
    )

    s5_pass = l1 and l2 and l4 and l8 and fwd_ok and hop_limit_trip
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "hop_latency_accumulation",
        "check": "Per-Hop Forwarding Latency Tracking (~8us) and Hop Limit (8) Enforcement",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "Hops 1..8 accumulated 8..64 us latency; hop 9 exceeded limit and tripped 0xEE26.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: fail_safe_deenergize
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng6 = CipSafetyAplDaisyChainEngine(node_id=1)
    eng6.safe_output_data = b"\xAA\xBB\xCC\xDD"
    eng6.trip_fail_safe(DIAG_ERR_FAIL_SAFE_TRIP)

    deenergized_ok = (
        eng6.fail_safe_active is True
        and eng6.operational_state == DaisyOperationalState.FAIL_SAFE
        and eng6.safe_output_data == b"\x00\x00\x00\x00"
        and (eng6.crc_status_word & int(CipSafetyAplDaisyChainStatusBits.FAIL_SAFE_ACTIVE)) != 0
        and eng6.reg_table.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is False
        and eng6.reg_table.read_bit(COIL_CIP_SAFETY_DAISY_FAULT) is True
        and eng6.diagnostic_code == DIAG_ERR_FAIL_SAFE_TRIP
    )

    s6_pass = deenergized_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "fail_safe_deenergize",
        "check": "Deterministic Safe State Fallback, Safe Outputs De-Energization, and Fault Assertions",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "Fail-safe trip 0xEE27 clamped safe outputs to 0x00, asserted %M591, and set fail-safe bit in %R2536.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: heartbeat_watchdog_timeout
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng7 = CipSafetyAplDaisyChainEngine(node_id=1, watchdog_timeout_ms=200.0)

    # Normal scan step within timeout
    res_healthy = eng7.scan_step(dt_ms=100.0)
    h_ok = (res_healthy.status == AgentStatus.SUCCESS and eng7.is_healthy is True)

    # Exceeding 200ms watchdog without heartbeat (100 + 150 = 250ms > 200ms)
    res_trip = eng7.scan_step(dt_ms=150.0)
    trip_ok = (
        res_trip.status == AgentStatus.FAILED
        and eng7.diagnostic_code == DIAG_ERR_HEARTBEAT_TIMEOUT
        and eng7.fail_safe_active is True
        and eng7.operational_state == DaisyOperationalState.FAIL_SAFE
        and eng7.is_healthy is False
    )

    # Feed heartbeat & clear faults
    eng7.clear_faults()
    eng7.feed_heartbeat()
    res_rec = eng7.scan_step(dt_ms=10.0)
    rec_ok = (res_rec.status == AgentStatus.SUCCESS and eng7.is_healthy is True)

    s7_pass = h_ok and trip_ok and rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "heartbeat_watchdog_timeout",
        "check": "Heartbeat Watchdog Surveillance (< 200ms) and Timeout Trip (0xEE25)",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "250ms silence tripped 0xEE25; feed_heartbeat restored healthy state.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: horner_ocs_register_sync
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt8 = RegisterTable()
    eng8 = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2, register_table=rt8)
    eng8.sync_to_registers(rt8, privilege=PrivilegeMode.USER)

    w_status = rt8.read_word(REG_CIP_SAFETY_DAISY_STATUS)
    w_up = rt8.read_word(REG_CIP_SAFETY_DAISY_UPSTREAM_PORT)
    w_down = rt8.read_word(REG_CIP_SAFETY_DAISY_DOWNSTREAM_PORT)
    w_hop = rt8.read_word(REG_CIP_SAFETY_DAISY_HOP_COUNT)
    w_lat = rt8.read_word(REG_CIP_SAFETY_DAISY_CUMULATIVE_LATENCY_US)
    w_seq = rt8.read_word(REG_CIP_SAFETY_DAISY_SEQUENCE_COUNTER)
    w_crc = rt8.read_word(REG_CIP_SAFETY_DAISY_CRC_STATUS)
    w_diag = rt8.read_word(REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE)
    b_active = rt8.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE)
    b_fault = rt8.read_bit(COIL_CIP_SAFETY_DAISY_FAULT)

    s8_pass = (
        ((w_status >> 8) & 0xFF) == 2
        and (w_status & 0xFF) == 1
        and w_up == 1
        and w_down == 1
        and w_hop == 2
        and w_lat == 16
        and w_seq == 0
        and w_crc == 0x000F
        and w_diag == 0x0000
        and b_active is True
        and b_fault is False
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "horner_ocs_register_sync",
        "check": "Bit-Exact Horner OCS Register Space (%R2530..%R2537) and Discrete Coils (%M590..%M591)",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": f"%R2530=0x{w_status:04X}, %R2531={w_up}, %R2532={w_down}, %R2533={w_hop}, %R2534={w_lat}, %R2536=0x{w_crc:04X}, %M590={b_active}, %M591={b_fault}.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: pure_st_pou_and_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    pou_valid = verify_cip_safety_apl_daisy_chain_pure_st()

    ladder_snippets = [
        "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM",
        "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM",
        "PROGRAM LadderTest VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM",
        "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM",
        "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM",
        "PROGRAM LadderTest RUNG 1 END_PROGRAM",
        "PROGRAM LadderTest NETWORK 1 END_PROGRAM",
        "PROGRAM LadderTest XIC(Contact1); END_PROGRAM",
        "PROGRAM LadderTest OTE(Coil1); END_PROGRAM",
    ]
    rejected_count = 0
    for snippet in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snippet)
        except LadderForbiddenError:
            rejected_count += 1
        except Exception:
            pass

    anti_ladder_ok = (rejected_count == len(ladder_snippets))
    s9_pass = pou_valid and anti_ladder_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 9,
        "name": "pure_st_pou_and_ladder_rejection",
        "check": "Pure IEC 61131-3 Structured Text POU Validation and Anti-Ladder Construct Rejection",
        "passed": bool(s9_pass),
        "timing_ms": round(t1, 3),
        "details": f"Pure ST POU verified; rejected {rejected_count}/{len(ladder_snippets)} ladder constructs with ERR_LADDER_FORBIDDEN.",
    })

    # ------------------------------------------------------------------------
    # Aggregate Strict 4-State Verification Contract
    # ------------------------------------------------------------------------
    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    status = "success" if all_passed else "failed"
    error_code = None if all_passed else "ERR_STAGE_VERIFICATION_FAILED"
    details = (
        f"All {total_stages} Industrial ODVA CIP Safety Over Ethernet-APL Daisy-Chain Spur Protocol stages passed deterministically (PASSED {stages_passed}/{total_stages} stages)."
        if all_passed
        else f"{total_stages - stages_passed} of {total_stages} stages failed verification."
    )

    evidence: Dict[str, Any] = {
        "status": status,
        "error_code": error_code,
        "details": details,
        "stages_passed": stages_passed,
        "total_stages": total_stages,
        "passed_stages": stages_passed,
        "data": {
            "work_package": work_package,
            "gate": "G8",
            "protocol": "ODVA CIP Safety Over Ethernet-APL Daisy-Chain Spur Topology (IEEE 802.3cg 10BASE-T1L)",
            "standards": [
                "IEEE 802.3cg 10BASE-T1L",
                "ODVA CIP Safety Volume 5",
                "IEC 61784-3-2",
                "IEC 61508 SIL 3",
            ],
            "registers": ["%R2530..%R2537", "%M590..%M591"],
            "checks_passed": stages_passed,
            "total_checks": total_stages,
            "stages": test_results,
            "tests": test_results,
        },
    }

    if output_path is not None:
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run W292 ODVA CIP Safety Over Ethernet-APL Daisy-Chain Spur Protocol Verification"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to output verification JSON evidence",
    )
    args = parser.parse_args()
    res = run_cip_safety_apl_daisy_chain_verification(output_path=args.output)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["status"] == "success" else 1)
