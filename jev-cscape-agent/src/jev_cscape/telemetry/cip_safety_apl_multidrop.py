"""Industrial ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk Protocol Engine.

Work Package: W283 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019 / Ethernet-APL & 10BASE-T1S Multi-Drop (Clause 147 / Clause 148):
  - 10BASE-T1S / 2-WISE Intrinsically Safe Multi-Drop Trunk operating over balanced single twisted pair.
  - Physical Layer Collision Avoidance (PLCA - Clause 148):
    - Deterministic round-robin transmit opportunity (TO) slot allocation.
    - Node 0 functions as PLCA Coordinator broadcasting periodic synchronization BEACONs.
    - Nodes 1..N-1 transmit strictly within their assigned TO slots, eliminating CSMA/CD collisions.
    - Configurable Transmit Opportunity Timer (to_timer_us, default 32 us) and Max Node Count (default 8).
    - PLCA cycle time = max_nodes * to_timer_us + beacon_timer_us (e.g. 8 * 32 + 20 = 276 us).
  - Spur / Drop Cable Reflection & Termination Surveillance:
    - Characteristic trunk line impedance Z0 = 100.0 Ohms (nominal).
    - Bus termination resistor RT = 100.0 Ohms.
    - Reflection coefficient Gamma = |ZL - Z0| / (ZL + Z0).
    - Under nominal matched conditions (ZL = 100 Ohms), Gamma = 0.0 (0.0% reflection).
    - Impedance mismatch exceeding 15.0% reflection (Gamma > 0.15) trips DEGRADED state with
      REFLECTION_MISMATCH alert (0xED02).
  - Trunk Fault & Bus Collision Interception:
    - Simultaneous non-PLCA transmission or arbitration collision triggers BUS_COLLISION (0xED01).
    - Bus short circuit (impedance ~0 Ohms) or line cut triggers trunk fault asserting discrete coil %M570.
  - Fail-Safe Fallback on Trunk Partition:
    - Safety watchdog timeout (200 ms nominal) or severed trunk cable transitions engine into FAIL_SAFE (state 3).
    - Safe outputs are zeroed and de-energized to guarantee SIL 3 / PLe safe state.
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - Class 0x39: Safety Supervisor Object
  - Class 0x3A: Safety Validator Object
  - Class 0x3B: Safety Connection Object
  - Class 0x3E: Ethernet-APL Safety Object Class ID
  - Dual 16-bit Safety CRCs:
    - CRC-S1: Generator polynomial 0x5935 (init 0xFFFF) over process data payload.
    - CRC-S2: Generator polynomial 0x755B (init 0xFFFF) over SNN, sequence, timestamp, and CRC-S1.
- Horner OCS Memory Space:
  - Analog registers %R2440..%R2447:
    - %R2440: REG_CIP_SAFETY_MULTIDROP_STATE (upper byte: node_id, lower byte: state code)
    - %R2441: REG_CIP_SAFETY_MULTIDROP_PLCA_CONFIG (upper byte: max_nodes, lower byte: plca_slot)
    - %R2442: REG_CIP_SAFETY_MULTIDROP_PLCA_CYCLE_US (PLCA cycle time in us, nominal 276 us)
    - %R2443: REG_CIP_SAFETY_MULTIDROP_REFLECTION_PCT (Reflection coefficient scaled 0..1000, e.g. 150 = 15.0%)
    - %R2444: REG_CIP_SAFETY_MULTIDROP_LINE_IMPEDANCE_OHM (Line impedance in Ohms, nominal 100 Ohms)
    - %R2445: REG_CIP_SAFETY_MULTIDROP_SEQUENCE_COUNTER (Rolling safety sequence 0..65535)
    - %R2446: REG_CIP_SAFETY_MULTIDROP_CRC_STATUS (Bit0=S1 OK, Bit1=S2 OK, Bit2=Slot Synced, 0x0007 nominal)
    - %R2447: REG_CIP_SAFETY_MULTIDROP_DIAGNOSTIC_CODE (Diagnostic code: 0x0000 OK, 0xED01..0xED07)
  - Discrete coils %M569..%M570:
    - %M569: COIL_CIP_SAFETY_MULTIDROP_ACTIVE (BOOL, True when trunk active & operational)
    - %M570: COIL_CIP_SAFETY_MULTIDROP_FAULT (BOOL, True on trunk collision, short, mismatch, or trip)
- Implements ILogicUnit interface with scan_step(dt, context), step(dt, context), execute(context), and reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetyAplMultidropSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).parse().
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.
- Deterministic 9-stage verification sequence runner run_cip_safety_apl_multidrop_verification().
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
# 1. Constants & Protocol Definitions (ODVA CIP Safety Volume 5 / IEEE 802.3cg)
# ============================================================================

CIP_SAFETY_SUPERVISOR_CLASS_ID: int = 0x39          # Safety Supervisor Object
CIP_SAFETY_VALIDATOR_CLASS_ID: int = 0x3A           # Safety Validator Object
CIP_SAFETY_CONNECTION_CLASS_ID: int = 0x3B          # Safety Connection Object
CIP_SAFETY_APL_MULTIDROP_CLASS_ID: int = 0x3E       # Ethernet-APL Safety Object Class ID
CIP_SAFETY_MULTIDROP_CLASS_ID: int = 0x3E

# Default Safety Parameters
DEFAULT_SAFETY_NETWORK_NUMBER: int = 0x00012345
DEFAULT_SNN: int = DEFAULT_SAFETY_NETWORK_NUMBER
DEFAULT_NODE_ID: int = 1                            # Node 0 is coordinator; 1 is default local worker
DEFAULT_MAX_NODES: int = 8                          # Default PLCA cluster size (0..7)
DEFAULT_PLCA_TO_TIMER_US: int = 32                  # Transmit opportunity slot duration
DEFAULT_PLCA_BEACON_TIMER_US: int = 20              # Synchronization beacon duration

# Physical Trunk Parameters
NOMINAL_TRUNK_IMPEDANCE_OHM: float = 100.0          # Characteristic line impedance Z0 = 100 Ohm
DEFAULT_LINE_IMPEDANCE_OHM: float = 100.0
NOMINAL_BUS_TERMINATION_OHM: float = 100.0
MAX_REFLECTION_COEFF_THRESHOLD: float = 0.15        # 15.0% reflection threshold (Gamma > 0.15)
DEFAULT_WATCHDOG_TIMEOUT_MS: float = 200.0          # 200 ms safety communication timeout
DEFAULT_BASE_TIMEOUT_MS: float = DEFAULT_WATCHDOG_TIMEOUT_MS

# CRC Polynomials and Seeds (ODVA CIP Safety Volume 5)
CIP_SAFETY_CRC_S1_POLY: int = 0x5935                # CRC-S1 generator polynomial
CIP_SAFETY_CRC_S2_POLY: int = 0x755B                # CRC-S2 generator polynomial
CRC_POLY_1021: int = 0x1021
CRC_POLY_8408: int = 0x8408
CIP_SAFETY_CRC_INIT: int = 0xFFFF                   # CRC-S initial seed

# CRC Status Word Bitmasks (%R2446)
CRC_STATUS_S1_OK: int = 0x0001                      # Bit0: Payload CRC-S1 valid
CRC_STATUS_S2_OK: int = 0x0002                      # Bit1: Header/Sequence CRC-S2 valid
CRC_STATUS_SLOT_SYNCED: int = 0x0004                # Bit2: PLCA transmit opportunity synced
CRC_STATUS_NOMINAL: int = 0x0007                    # All 3 nominal bits set

# Canonical Register Table Mapping (%R2440..%R2447)
REG_CIP_SAFETY_MULTIDROP_STATE: str = "%R2440"
REG_CIP_SAFETY_MULTIDROP_PLCA_CONFIG: str = "%R2441"
REG_CIP_SAFETY_MULTIDROP_PLCA_CYCLE_US: str = "%R2442"
REG_CIP_SAFETY_MULTIDROP_REFLECTION_PCT: str = "%R2443"
REG_CIP_SAFETY_MULTIDROP_LINE_IMPEDANCE_OHM: str = "%R2444"
REG_CIP_SAFETY_MULTIDROP_SEQUENCE_COUNTER: str = "%R2445"
REG_CIP_SAFETY_MULTIDROP_CRC_STATUS: str = "%R2446"
REG_CIP_SAFETY_MULTIDROP_DIAGNOSTIC_CODE: str = "%R2447"

# Canonical Discrete Coils Mapping (%M569..%M570)
COIL_CIP_SAFETY_MULTIDROP_ACTIVE: str = "%M569"
COIL_CIP_SAFETY_MULTIDROP_FAULT: str = "%M570"

# Register & Coil Convenience Aliases
REG_MULTIDROP_STATE: str = "%R2440"
REG_MULTIDROP_PLCA_CONFIG: str = "%R2441"
REG_MULTIDROP_PLCA_CYCLE: str = "%R2442"
REG_MULTIDROP_REFLECTION: str = "%R2443"
REG_MULTIDROP_LINE_IMPEDANCE: str = "%R2444"
REG_MULTIDROP_SEQUENCE: str = "%R2445"
REG_MULTIDROP_CRC_STATUS: str = "%R2446"
REG_MULTIDROP_DIAGNOSTIC_CODE: str = "%R2447"

COIL_MULTIDROP_TRUNK_ACTIVE: str = "%M569"
COIL_MULTIDROP_TRUNK_FAULT: str = "%M570"
COIL_MULTIDROP_BUS_COLLISION: str = "%M570"


# ============================================================================
# 2. Enums and Diagnostic Codes
# ============================================================================

class CipSafetyAplMultidropState(IntEnum):
    """ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk State Machine (%R2440).

    States:
    - 0: INIT (Unconfigured / Bus Joining / Synchronization Training)
    - 1: OPERATIONAL (Nominal Multi-Drop Communication Active & Healthy)
    - 2: DEGRADED (Impedance Mismatch / Reflection Warning, link maintained)
    - 3: FAIL_SAFE (Safe State Fallback: de-energized outputs, collision / partition trip)
    """
    INIT = 0
    OPERATIONAL = 1
    DEGRADED = 2
    FAIL_SAFE = 3

    # Aliases
    SafeInit = 0
    SafeOperational = 1
    SafeDegraded = 2
    SafeFailSafe = 3
    TRIPPED = 3


class CipSafetyAplMultidropDiagnosticCode(IntEnum):
    """Integer diagnostic code enum supporting signed/unsigned 16-bit comparisons (%R2447).

    Codes:
    - 0x0000: OK (Multi-drop trunk operational, zero faults)
    - 0xED01: BUS_COLLISION (Trunk bus collision or PLCA arbitration failure)
    - 0xED02: REFLECTION_MISMATCH (Drop reflection / line impedance mismatch > 15.0%)
    - 0xED03: CRC_S1_FAULT (Process data payload CRC-S1 corrupted)
    - 0xED04: CRC_S2_FAULT (Sequence/timestamp header CRC-S2 corrupted)
    - 0xED05: TRUNK_PARTITION (Trunk severed / disconnected, watchdog timeout)
    - 0xED06: TERMINATION_FAULT (Bus termination resistor missing, short, or open)
    - 0xED07: PLCA_BEACON_LOSS (PLCA Coordinator beacon lost or out of sync)
    """
    OK = 0x0000
    BUS_COLLISION = 0xED01
    REFLECTION_MISMATCH = 0xED02
    CRC_S1_FAULT = 0xED03
    CRC_S2_FAULT = 0xED04
    TRUNK_PARTITION = 0xED05
    TERMINATION_FAULT = 0xED06
    PLCA_BEACON_LOSS = 0xED07

    # Aliases
    BusCollision = 0xED01
    ReflectionMismatch = 0xED02
    CrcS1Fault = 0xED03
    CrcS2Fault = 0xED04
    TrunkPartition = 0xED05
    TerminationFault = 0xED06
    PlcaBeaconLoss = 0xED07

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

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)

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

    def __or__(self, other: Any) -> Any:
        if isinstance(other, int):
            return int(self) | int(other)
        return super().__or__(other)

    def __ror__(self, other: Any) -> Any:
        if isinstance(other, int):
            return int(other) | int(self)
        return super().__ror__(other)

    def __str__(self) -> str:
        return f"0x{int(self) & 0xFFFF:04X} ({self.name})"

    def __repr__(self) -> str:
        return f"CipSafetyAplMultidropDiagnosticCode.{self.name}(0x{int(self) & 0xFFFF:04X})"


# Module-level aliases
DiagnosticCode = CipSafetyAplMultidropDiagnosticCode
DIAG_OK = CipSafetyAplMultidropDiagnosticCode.OK
DIAG_BUS_COLLISION = CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
DIAG_REFLECTION_MISMATCH = CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH
DIAG_CRC_S1_FAULT = CipSafetyAplMultidropDiagnosticCode.CRC_S1_FAULT
DIAG_CRC_S2_FAULT = CipSafetyAplMultidropDiagnosticCode.CRC_S2_FAULT
DIAG_TRUNK_PARTITION = CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
DIAG_TERMINATION_FAULT = CipSafetyAplMultidropDiagnosticCode.TERMINATION_FAULT
DIAG_PLCA_BEACON_LOSS = CipSafetyAplMultidropDiagnosticCode.PLCA_BEACON_LOSS

AplMultidropState = CipSafetyAplMultidropState
AplMultidropDiagnosticCode = CipSafetyAplMultidropDiagnosticCode


class AplMultidropStatusBits(IntEnum):
    """Status bits bitmask for multi-drop CRC status word (%R2446)."""
    S1_OK = 0x0001
    S2_OK = 0x0002
    SLOT_SYNCED = 0x0004
    NOMINAL = 0x0007


CipSafetyAplMultidropStatusBits = AplMultidropStatusBits



# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class CipSafetyAplMultidropError(Exception):
    """Base exception for all CIP Safety Over Ethernet-APL Multi-Drop Trunk violations."""
    pass


class BusCollisionError(CipSafetyAplMultidropError):
    """Raised when trunk collision or arbitration contention occurs (0xED01)."""
    pass


class ReflectionMismatchError(CipSafetyAplMultidropError):
    """Raised when drop cable reflection or impedance mismatch exceeds threshold (0xED02)."""
    pass


class TrunkPartitionError(CipSafetyAplMultidropError):
    """Raised when trunk cable is severed, partitioned, or watchdog expires (0xED05)."""
    pass


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POU Definition
# ============================================================================

ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC: str = """PROGRAM CipSafetyAplMultidropSync
VAR
    (* Horner OCS Mapped Registers (W283 - ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk) *)
    MultidropNodeStatus         AT %R2440 : INT;    (* Upper byte: Node ID, Lower byte: State (0=INIT, 1=OPERATIONAL, 2=DEGRADED, 3=FAIL_SAFE) *)
    MultidropPlcaConfig         AT %R2441 : INT;    (* Upper byte: Max Nodes, Lower byte: PLCA Slot *)
    MultidropPlcaCycleUs        AT %R2442 : INT;    (* PLCA cycle time in us (nominal 276 us) *)
    MultidropReflectionPct      AT %R2443 : INT;    (* Drop reflection coefficient scaled 0..1000 (e.g. 150 = 15.0%) *)
    MultidropLineImpedanceOhm   AT %R2444 : INT;    (* Trunk line impedance in Ohms (nominal 100 Ohms) *)
    MultidropSequenceCounter    AT %R2445 : UINT;   (* Safe rolling sequence counter 0..65535 *)
    MultidropCrcStatus          AT %R2446 : INT;    (* CRC status word (bit0=S1, bit1=S2, bit2=Slot Sync, nominal 7) *)
    MultidropDiagnosticCode     AT %R2447 : UINT;   (* Diagnostic code: 0x0000 OK, 0xED01..0xED07 *)

    (* Discrete Safety Coils *)
    MultidropTrunkActive        AT %M569  : BOOL;   (* TRUE when multi-drop trunk is active & operational *)
    MultidropTrunkFault         AT %M570  : BOOL;   (* TRUE on trunk collision, impedance fault, or fail-safe trip *)

    (* Internal Flags *)
    InternalTrunkHealthy        : BOOL;
END_VAR

IF MultidropTrunkFault OR (MultidropDiagnosticCode <> 0) THEN
    MultidropTrunkActive := FALSE;
    MultidropTrunkFault := TRUE;
    InternalTrunkHealthy := FALSE;
ELSIF ((MultidropNodeStatus AND 255) = 1) AND (MultidropReflectionPct <= 150) AND (MultidropLineImpedanceOhm >= 80) AND (MultidropLineImpedanceOhm <= 120) THEN
    MultidropTrunkActive := TRUE;
    MultidropTrunkFault := FALSE;
    InternalTrunkHealthy := TRUE;
ELSE
    MultidropTrunkActive := FALSE;
    MultidropTrunkFault := TRUE;
    InternalTrunkHealthy := FALSE;
END_IF;
END_PROGRAM
"""

CIP_SAFETY_APL_MULTIDROP_POU: str = ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC
CIP_SAFETY_APL_MULTIDROP_PURE_ST_POU: str = ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC
CIP_SAFETY_APL_MULTIDROP_SYNC_POU: str = ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC
CipSafetyAplMultidropSync: str = ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC
CipSafetyAplMultidropSyncPOU: str = ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC


def verify_cip_safety_apl_multidrop_pure_st(pou_text: Optional[str] = None) -> bool:
    """Validate pure IEC 61131-3 ST POU with SecurityGuard and STParser."""
    try:
        text = pou_text if pou_text is not None else ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC
        SecurityGuard.assert_pure_st_content(text)
        res = STParser.validate_code(text)
        if res.status != AgentStatus.SUCCESS:
            return False
        ast = STParser(pou_type=POUType.PROGRAM).parse(text)
        if ast.pou_type != POUType.PROGRAM:
            return False

        required_registers: Set[str] = {
            "%R2440", "%R2441", "%R2442", "%R2443",
            "%R2444", "%R2445", "%R2446", "%R2447",
            "%M569", "%M570",
        }
        return required_registers.issubset(set(ast.bound_registers))
    except Exception:
        return False


# ============================================================================
# 5. Checksum & Helper Functions
# ============================================================================

def compute_crc16(
    data: bytes,
    poly: int = CIP_SAFETY_CRC_S1_POLY,
    init: int = CIP_SAFETY_CRC_INIT,
) -> int:
    """Compute 16-bit CRC with specified polynomial and initial seed."""
    crc = init & 0xFFFF
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
    poly: int = CIP_SAFETY_CRC_S1_POLY,
    init: int = CIP_SAFETY_CRC_INIT,
    **kwargs: Any,
) -> int:
    """Calculate 16-bit safety checksum CRC-S1 over payload bytes (generator 0x5935)."""
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
    poly: int = CIP_SAFETY_CRC_S2_POLY,
    init: int = CIP_SAFETY_CRC_INIT,
    **kwargs: Any,
) -> int:
    """Calculate 16-bit safety checksum CRC-S2 over SNN + sequence_number + timestamp_ms + CRC-S1.

    Generator polynomial 0x755B computed over bitwise-inverted packed representation.
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

    # Inverted data for safety CRC-S2 as per ODVA Volume 5
    inv_data = bytes(b ^ 0xFF for b in data)
    p = kwargs.get("poly", poly)
    i = kwargs.get("init", kwargs.get("seed", init))
    return compute_crc16(inv_data, poly=p, init=i)


def compute_reflection_coefficient(zl: float, z0: float = NOMINAL_TRUNK_IMPEDANCE_OHM) -> float:
    """Calculate drop cable / trunk reflection coefficient Gamma = |ZL - Z0| / (ZL + Z0)."""
    denom = zl + z0
    if denom <= 1e-9:
        return 1.0
    return abs(zl - z0) / denom


def safe_write_word(
    reg_table: RegisterTable,
    address: str,
    value: int,
    privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
) -> None:
    """Write word register with signed 16-bit wrapping into RegisterTable."""
    val = int(value)
    if val > 32767:
        val -= 65536
    val = max(-32768, min(32767, val))
    reg_table.write_word(address, val, privilege=privilege)


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
# 6. PLCA Configuration & Safety Frame Encapsulation
# ============================================================================

@dataclass
class PlcaConfig:
    """IEEE 802.3cg Clause 148 PLCA Configuration Parameters."""
    node_id: int = DEFAULT_NODE_ID
    max_nodes: int = DEFAULT_MAX_NODES
    to_timer_us: int = DEFAULT_PLCA_TO_TIMER_US
    beacon_timer_us: int = DEFAULT_PLCA_BEACON_TIMER_US
    is_coordinator: bool = False

    @property
    def cycle_time_us(self) -> int:
        """Total PLCA round-robin cycle duration in microseconds."""
        return int(self.max_nodes * self.to_timer_us + self.beacon_timer_us)


@dataclass
class AplMultidropNode:
    """Model representing an individual Ethernet-APL / 10BASE-T1S multi-drop trunk node.

    Standards: IEEE 802.3cg Clause 147/148 / ODVA CIP Safety Volume 5.
    """
    node_id: int = DEFAULT_NODE_ID
    plca_slot: int = DEFAULT_NODE_ID
    is_coordinator: bool = False
    spur_impedance_ohm: float = NOMINAL_TRUNK_IMPEDANCE_OHM
    reflection_coefficient: float = 0.0
    is_active: bool = True
    last_seen_ms: float = 0.0
    tx_sequence: int = 0
    rx_sequence: int = 0
    safe_payload: bytes = b"\x00\x00\x00\x00"

    def calculate_reflection(self, z0: float = NOMINAL_TRUNK_IMPEDANCE_OHM) -> float:
        """Calculate spur cable reflection coefficient Gamma = |ZL - Z0| / (ZL + Z0)."""
        self.reflection_coefficient = compute_reflection_coefficient(self.spur_impedance_ohm, z0)
        return self.reflection_coefficient

    def can_transmit_in_slot(self, slot: int, max_nodes: int = DEFAULT_MAX_NODES) -> bool:
        """Check if node has transmit opportunity in given round-robin slot."""
        return (slot % max_nodes) == (self.node_id % max_nodes)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize node model to dictionary."""
        return {
            "node_id": self.node_id,
            "plca_slot": self.plca_slot,
            "is_coordinator": self.is_coordinator,
            "spur_impedance_ohm": self.spur_impedance_ohm,
            "reflection_coefficient": self.reflection_coefficient,
            "is_active": self.is_active,
            "last_seen_ms": self.last_seen_ms,
            "tx_sequence": self.tx_sequence,
            "rx_sequence": self.rx_sequence,
        }


@dataclass
class AplMultidropTrunkState:
    """Model representing physical multi-drop trunk and PLCA state.

    Standards: IEEE 802.3cg Clause 147/148 / 2-WISE Intrinsically Safe / ODVA CIP Safety.
    """
    state: CipSafetyAplMultidropState = CipSafetyAplMultidropState.OPERATIONAL
    diagnostic_code: CipSafetyAplMultidropDiagnosticCode = CipSafetyAplMultidropDiagnosticCode.OK
    z0_ohm: float = NOMINAL_TRUNK_IMPEDANCE_OHM
    rt_ohm: float = NOMINAL_BUS_TERMINATION_OHM
    line_impedance_ohm: float = NOMINAL_TRUNK_IMPEDANCE_OHM
    reflection_coefficient: float = 0.0
    reflection_threshold: float = MAX_REFLECTION_COEFF_THRESHOLD
    nodes: Dict[int, AplMultidropNode] = field(default_factory=dict)
    active_slot: int = 0
    max_nodes: int = DEFAULT_MAX_NODES
    to_timer_us: int = DEFAULT_PLCA_TO_TIMER_US
    beacon_timer_us: int = DEFAULT_PLCA_BEACON_TIMER_US
    coil_trunk_active: bool = True
    coil_trunk_fault: bool = False
    watchdog_timeout_ms: float = DEFAULT_WATCHDOG_TIMEOUT_MS
    watchdog_elapsed_ms: float = 0.0

    # Class constants mirroring enum states for convenience
    INIT = CipSafetyAplMultidropState.INIT
    OPERATIONAL = CipSafetyAplMultidropState.OPERATIONAL
    DEGRADED = CipSafetyAplMultidropState.DEGRADED
    FAIL_SAFE = CipSafetyAplMultidropState.FAIL_SAFE

    @property
    def plca_cycle_time_us(self) -> int:
        """PLCA cycle duration in us = max_nodes * to_timer + beacon_timer."""
        return int(self.max_nodes * self.to_timer_us + self.beacon_timer_us)

    def calculate_reflection(self, zl: Optional[float] = None) -> float:
        """Calculate line reflection coefficient Gamma."""
        val = self.line_impedance_ohm if zl is None else float(zl)
        self.reflection_coefficient = compute_reflection_coefficient(val, self.z0_ohm)
        return self.reflection_coefficient

    def evaluate_health(self) -> bool:
        """Evaluate trunk health status."""
        return (
            self.state in (CipSafetyAplMultidropState.OPERATIONAL, CipSafetyAplMultidropState.DEGRADED)
            and self.diagnostic_code in (
                CipSafetyAplMultidropDiagnosticCode.OK,
                CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH,
            )
        )

    def register_node(self, node: AplMultidropNode) -> None:
        """Register or update node on trunk."""
        self.nodes[node.node_id] = node

    def get_node(self, node_id: int) -> Optional[AplMultidropNode]:
        """Retrieve node by node_id."""
        return self.nodes.get(node_id)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize trunk state model to dictionary."""
        return {
            "state": int(self.state),
            "state_name": self.state.name,
            "diagnostic_code": f"0x{int(self.diagnostic_code) & 0xFFFF:04X}",
            "z0_ohm": self.z0_ohm,
            "rt_ohm": self.rt_ohm,
            "line_impedance_ohm": self.line_impedance_ohm,
            "reflection_coefficient": self.reflection_coefficient,
            "plca_cycle_time_us": self.plca_cycle_time_us,
            "coil_trunk_active": self.coil_trunk_active,
            "coil_trunk_fault": self.coil_trunk_fault,
            "nodes_count": len(self.nodes),
        }



@dataclass
class CipSafetyAplMultidropFrame:
    """ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk Frame.

    Encapsulates Safety Network Number (SNN), node_id, PLCA slot, sequence number,
    timestamp, process data payload, and dual safety checksums CRC-S1 & CRC-S2.
    """
    safety_network_number: int = DEFAULT_SAFETY_NETWORK_NUMBER
    node_id: int = DEFAULT_NODE_ID
    plca_slot: int = DEFAULT_NODE_ID
    sequence_number: int = 1
    timestamp_ms: int = 1000
    payload_bytes: bytes = b"\x00\x00\x00\x00"
    crc_s1: int = 0
    crc_s2: int = 0

    def calculate_crcs(
        self,
        poly_s1: int = CIP_SAFETY_CRC_S1_POLY,
        poly_s2: int = CIP_SAFETY_CRC_S2_POLY,
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

    def verify_crc_s1(self, poly: int = CIP_SAFETY_CRC_S1_POLY) -> bool:
        """Verify CRC-S1 checksum over payload_bytes."""
        return self.crc_s1 == compute_crc_s1(self.payload_bytes, poly=poly)

    def verify_crc_s2(self, poly: int = CIP_SAFETY_CRC_S2_POLY) -> bool:
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
        poly_s1: int = CIP_SAFETY_CRC_S1_POLY,
        poly_s2: int = CIP_SAFETY_CRC_S2_POLY,
    ) -> Tuple[bool, bool]:
        """Verify both CRC-S1 and CRC-S2 checksums."""
        return (self.verify_crc_s1(poly=poly_s1), self.verify_crc_s2(poly=poly_s2))

    def is_valid(
        self,
        poly_s1: int = CIP_SAFETY_CRC_S1_POLY,
        poly_s2: int = CIP_SAFETY_CRC_S2_POLY,
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
            ">IBBHIH",
            self.safety_network_number & 0xFFFFFFFF,
            self.node_id & 0xFF,
            self.plca_slot & 0xFF,
            self.sequence_number & 0xFFFF,
            int(self.timestamp_ms) & 0xFFFFFFFF,
            len(self.payload_bytes) & 0xFFFF,
        )
        trailer = struct.pack(">HH", self.crc_s1 & 0xFFFF, self.crc_s2 & 0xFFFF)
        return header + self.payload_bytes + trailer

    @classmethod
    def unpack(cls, data: bytes) -> CipSafetyAplMultidropFrame:
        """Unpack frame from wire format."""
        if len(data) < 18:
            raise ValueError(f"Packet too short: {len(data)} bytes")
        snn, node_id, slot, seq, ts, plen = struct.unpack(">IBBHIH", data[:14])
        if len(data) < 14 + plen + 4:
            raise ValueError("Incomplete frame data")
        payload = data[14:14 + plen]
        crc_s1, crc_s2 = struct.unpack(">HH", data[14 + plen:14 + plen + 4])
        return cls(
            safety_network_number=snn,
            node_id=node_id,
            plca_slot=slot,
            sequence_number=seq,
            timestamp_ms=ts,
            payload_bytes=payload,
            crc_s1=crc_s1,
            crc_s2=crc_s2,
        )


def create_valid_frame(
    safety_network_number: int = DEFAULT_SAFETY_NETWORK_NUMBER,
    node_id: int = DEFAULT_NODE_ID,
    plca_slot: int = DEFAULT_NODE_ID,
    sequence_number: int = 1,
    timestamp_ms: int = 1000,
    payload_bytes: bytes = b"\x01\x00\x00\x00",
    poly_s1: int = CIP_SAFETY_CRC_S1_POLY,
    poly_s2: int = CIP_SAFETY_CRC_S2_POLY,
) -> CipSafetyAplMultidropFrame:
    """Factory creating valid multi-drop safety frame with calculated dual CRCs."""
    frame = CipSafetyAplMultidropFrame(
        safety_network_number=safety_network_number,
        node_id=node_id,
        plca_slot=plca_slot,
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

class CipSafetyAplMultidropEngine(ILogicUnit):
    """ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk Protocol Engine.

    Implements full ILogicUnit interface, PLCA collision avoidance, drop cable
    reflection surveillance, dual CRC-S1/S2 verification, and bit-exact Horner OCS
    register space synchronization (%R2440..%R2447, %M569..%M570).
    """

    def __init__(
        self,
        safety_network_number: int = DEFAULT_SAFETY_NETWORK_NUMBER,
        plca_config: Optional[PlcaConfig] = None,
        line_impedance_ohm: float = NOMINAL_TRUNK_IMPEDANCE_OHM,
        reflection_threshold: float = MAX_REFLECTION_COEFF_THRESHOLD,
        watchdog_timeout_ms: float = DEFAULT_WATCHDOG_TIMEOUT_MS,
        register_table: Optional[RegisterTable] = None,
        auto_activate: bool = True,
    ) -> None:
        self.safety_network_number: int = safety_network_number
        self.plca: PlcaConfig = plca_config or PlcaConfig()
        self.line_impedance_ohm: float = float(line_impedance_ohm)
        self.reflection_threshold: float = float(reflection_threshold)
        self.watchdog_timeout_ms: float = float(watchdog_timeout_ms)
        self.register_table: Optional[RegisterTable] = register_table

        # Operational State
        self.state: CipSafetyAplMultidropState = (
            CipSafetyAplMultidropState.OPERATIONAL
            if auto_activate
            else CipSafetyAplMultidropState.INIT
        )
        self.diagnostic_code: CipSafetyAplMultidropDiagnosticCode = (
            CipSafetyAplMultidropDiagnosticCode.OK
        )
        self.reflection_coefficient: float = compute_reflection_coefficient(
            self.line_impedance_ohm, NOMINAL_TRUNK_IMPEDANCE_OHM
        )
        self.current_plca_slot: int = self.plca.node_id
        self.tx_sequence: int = 0
        self.rx_sequence: int = 0
        self.crc_status: int = CRC_STATUS_NOMINAL
        self.watchdog_timer_ms: float = 0.0
        self.cycles_count: int = 0
        self.frames_transmitted: int = 0
        self.frames_processed: int = 0

        # Safety IO Process Data
        self.safe_inputs: bytes = b"\x00\x00\x00\x00"
        self.safe_outputs: bytes = b"\x00\x00\x00\x00"

        # Multi-drop Trunk State Model
        self.trunk_state: AplMultidropTrunkState = AplMultidropTrunkState(
            state=self.state,
            diagnostic_code=self.diagnostic_code,
            z0_ohm=NOMINAL_TRUNK_IMPEDANCE_OHM,
            rt_ohm=NOMINAL_BUS_TERMINATION_OHM,
            line_impedance_ohm=self.line_impedance_ohm,
            reflection_coefficient=self.reflection_coefficient,
            reflection_threshold=self.reflection_threshold,
            active_slot=self.current_plca_slot,
            max_nodes=self.plca.max_nodes,
            to_timer_us=self.plca.to_timer_us,
            beacon_timer_us=self.plca.beacon_timer_us,
            coil_trunk_active=(self.state in (CipSafetyAplMultidropState.OPERATIONAL, CipSafetyAplMultidropState.DEGRADED)),
            coil_trunk_fault=(self.state == CipSafetyAplMultidropState.FAIL_SAFE),
            watchdog_timeout_ms=self.watchdog_timeout_ms,
        )

        # Initial register synchronization
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)


    # ------------------------------------------------------------------------
    # ILogicUnit Metadata Properties
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "CIP_SAFETY_APL_MULTIDROP"

    @property
    def priority(self) -> int:
        return 10

    @property
    def is_enabled(self) -> bool:
        return True

    @property
    def is_healthy(self) -> bool:
        return (
            self.state in (
                CipSafetyAplMultidropState.OPERATIONAL,
                CipSafetyAplMultidropState.DEGRADED,
            )
            and self.diagnostic_code in (
                CipSafetyAplMultidropDiagnosticCode.OK,
                CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH,
            )
        )

    @property
    def is_fail_safe(self) -> bool:
        return self.state == CipSafetyAplMultidropState.FAIL_SAFE

    @property
    def local_node_id(self) -> int:
        return self.plca.node_id

    @property
    def max_nodes(self) -> int:
        return self.plca.max_nodes

    @property
    def plca_cycle_time_us(self) -> int:
        return self.plca.cycle_time_us

    # ------------------------------------------------------------------------
    # State Reset
    # ------------------------------------------------------------------------

    def reset(self) -> None:
        """Reset protocol engine to clean operational state."""
        self.state = CipSafetyAplMultidropState.OPERATIONAL
        self.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.OK
        self.line_impedance_ohm = NOMINAL_TRUNK_IMPEDANCE_OHM
        self.reflection_coefficient = compute_reflection_coefficient(
            self.line_impedance_ohm, NOMINAL_TRUNK_IMPEDANCE_OHM
        )
        self.current_plca_slot = self.plca.node_id
        self.tx_sequence = 0
        self.rx_sequence = 0
        self.crc_status = CRC_STATUS_NOMINAL
        self.watchdog_timer_ms = 0.0
        self.safe_inputs = b"\x00\x00\x00\x00"
        self.safe_outputs = b"\x00\x00\x00\x00"
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    # ------------------------------------------------------------------------
    # PLCA & Line Impedance Surveillance
    # ------------------------------------------------------------------------

    def configure_plca(
        self,
        node_id: int,
        max_nodes: int,
        to_timer_us: int = DEFAULT_PLCA_TO_TIMER_US,
        is_coordinator: bool = False,
    ) -> None:
        """Update PLCA arbitration parameters."""
        self.plca.node_id = node_id
        self.plca.max_nodes = max_nodes
        self.plca.to_timer_us = to_timer_us
        self.plca.is_coordinator = is_coordinator
        self.current_plca_slot = node_id
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def update_bus_impedance(self, line_impedance_ohm: float) -> float:
        """Update trunk line impedance and calculate reflection coefficient Gamma.

        If reflection coefficient exceeds threshold (0.15 / 15.0%), transitions
        to DEGRADED state with REFLECTION_MISMATCH alert (0xED02).
        """
        self.line_impedance_ohm = float(line_impedance_ohm)
        self.reflection_coefficient = compute_reflection_coefficient(
            self.line_impedance_ohm, NOMINAL_TRUNK_IMPEDANCE_OHM
        )

        if self.reflection_coefficient > self.reflection_threshold:
            if self.state != CipSafetyAplMultidropState.FAIL_SAFE:
                self.state = CipSafetyAplMultidropState.DEGRADED
                self.diagnostic_code = (
                    CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH
                )
        else:
            if self.state == CipSafetyAplMultidropState.DEGRADED:
                self.state = CipSafetyAplMultidropState.OPERATIONAL
                self.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.OK

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

        return self.reflection_coefficient

    def simulate_collision(self) -> None:
        """Simulate bus collision or non-PLCA contention trip (0xED01)."""
        self.state = CipSafetyAplMultidropState.FAIL_SAFE
        self.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
        self.crc_status &= ~CRC_STATUS_SLOT_SYNCED
        self.safe_outputs = b"\x00" * len(self.safe_outputs)
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def simulate_trunk_short(self) -> None:
        """Simulate trunk short circuit (impedance 0 Ohm) trip."""
        self.line_impedance_ohm = 0.0
        self.reflection_coefficient = 1.0
        self.state = CipSafetyAplMultidropState.FAIL_SAFE
        self.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
        self.crc_status &= ~CRC_STATUS_SLOT_SYNCED
        self.safe_outputs = b"\x00" * len(self.safe_outputs)
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def simulate_trunk_partition(self) -> None:
        """Simulate trunk partition / disconnect / severed cable trip (0xED05)."""
        self.state = CipSafetyAplMultidropState.FAIL_SAFE
        self.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
        self.crc_status = 0x0000
        self.safe_outputs = b"\x00" * len(self.safe_outputs)
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    # ------------------------------------------------------------------------
    # Transmission & Reception
    # ------------------------------------------------------------------------

    def can_transmit_in_slot(self, slot: int) -> bool:
        """Check if local node is arbitrated to transmit in the given PLCA slot."""
        return (slot % self.plca.max_nodes) == (self.plca.node_id % self.plca.max_nodes)

    def transmit_frame(
        self,
        payload_bytes: bytes = b"\x01\x00\x00\x00",
        slot: Optional[int] = None,
    ) -> CipSafetyAplMultidropFrame:
        """Transmit multi-drop safety frame within assigned PLCA slot.

        If a specific slot is requested that does not match local_node_id,
        raises BusCollisionError or blocks to enforce PLCA collision avoidance.
        """
        active_slot = slot if slot is not None else self.plca.node_id
        if not self.can_transmit_in_slot(active_slot):
            raise BusCollisionError(
                f"PLCA collision avoidance: Node {self.plca.node_id} cannot transmit in slot {active_slot}"
            )

        self.tx_sequence = (self.tx_sequence + 1) & 0xFFFF
        self.current_plca_slot = active_slot
        frame = create_valid_frame(
            safety_network_number=self.safety_network_number,
            node_id=self.plca.node_id,
            plca_slot=active_slot,
            sequence_number=self.tx_sequence,
            timestamp_ms=int(time.time() * 1000) & 0xFFFFFFFF,
            payload_bytes=payload_bytes,
        )
        self.frames_transmitted += 1

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

        return frame

    def process_frame(self, frame: CipSafetyAplMultidropFrame) -> bool:
        """Process received frame, verifying dual CRC-S1/S2 and SNN integrity."""
        # 1. Foreign SNN check
        if frame.safety_network_number != self.safety_network_number:
            self.state = CipSafetyAplMultidropState.FAIL_SAFE
            self.diagnostic_code = (
                CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
            )
            self.safe_outputs = b"\x00" * len(self.safe_outputs)
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return False

        # 2. Dual Safety CRC checks
        s1_ok = frame.verify_crc_s1()
        s2_ok = frame.verify_crc_s2()

        if not s1_ok:
            self.state = CipSafetyAplMultidropState.FAIL_SAFE
            self.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.CRC_S1_FAULT
            self.crc_status &= ~CRC_STATUS_S1_OK
            self.safe_outputs = b"\x00" * len(self.safe_outputs)
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return False

        if not s2_ok:
            self.state = CipSafetyAplMultidropState.FAIL_SAFE
            self.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.CRC_S2_FAULT
            self.crc_status &= ~CRC_STATUS_S2_OK
            self.safe_outputs = b"\x00" * len(self.safe_outputs)
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return False

        # Nominal reception
        self.rx_sequence = frame.sequence_number
        self.current_plca_slot = frame.plca_slot
        self.safe_inputs = frame.payload_bytes
        self.crc_status = CRC_STATUS_NOMINAL
        self.feed_watchdog()
        self.frames_processed += 1

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

        return True

    def feed_watchdog(self) -> None:
        """Feed safety communication watchdog timer."""
        self.watchdog_timer_ms = 0.0

    # ------------------------------------------------------------------------
    # ILogicUnit Cyclic Execution
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float, context: Optional[ScanContext] = None) -> None:
        """Execute one PLC scan cycle step of duration dt seconds."""
        self.cycles_count += 1
        dt_ms = dt * 1000.0
        self.watchdog_timer_ms += dt_ms

        if self.watchdog_timer_ms >= self.watchdog_timeout_ms:
            self.state = CipSafetyAplMultidropState.FAIL_SAFE
            self.diagnostic_code = (
                CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
            )
            self.safe_outputs = b"\x00" * len(self.safe_outputs)

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def step(self, dt: float, context: Optional[ScanContext] = None) -> None:
        """Alias for scan_step."""
        self.scan_step(dt, context)
    
    def execute(self, context: Optional[ScanContext] = None) -> ExecutionResult:
        """Execute logic unit under ScanContext."""
        dt = context.dt if context is not None else 0.010
        self.scan_step(dt, context)
        status = AgentStatus.SUCCESS if self.is_healthy else AgentStatus.FAILED
        err_code = (
            None
            if self.is_healthy
            else f"0x{int(self.diagnostic_code) & 0xFFFF:04X}"
        )
        details = (
            "Multi-drop trunk healthy and operational."
            if self.is_healthy
            else f"Multi-drop trunk fault: {self.diagnostic_code.name}"
        )
        return ExecutionResult(
            status=status,
            error_code=err_code,
            details=details,
            data={
                "state": self.state.name,
                "diagnostic_code": f"0x{int(self.diagnostic_code) & 0xFFFF:04X}",
                "line_impedance_ohm": self.line_impedance_ohm,
                "reflection_coefficient": self.reflection_coefficient,
            },
        )

    # ------------------------------------------------------------------------
    # Register Space Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize multi-drop state to Horner OCS %R2440..%R2447 and %M569..%M570."""
        if hasattr(self, "trunk_state") and self.trunk_state is not None:
            self.trunk_state.state = self.state
            self.trunk_state.diagnostic_code = self.diagnostic_code
            self.trunk_state.line_impedance_ohm = self.line_impedance_ohm
            self.trunk_state.reflection_coefficient = self.reflection_coefficient
            self.trunk_state.active_slot = self.current_plca_slot
            self.trunk_state.coil_trunk_active = self.state in (
                CipSafetyAplMultidropState.OPERATIONAL,
                CipSafetyAplMultidropState.DEGRADED,
            )
            self.trunk_state.coil_trunk_fault = (
                self.state == CipSafetyAplMultidropState.FAIL_SAFE
                or self.diagnostic_code != CipSafetyAplMultidropDiagnosticCode.OK
            )

        target_table = reg_table or self.register_table
        if target_table is None:
            return


        # %R2440: upper byte node_id, lower byte state
        r2440_val = ((self.plca.node_id & 0xFF) << 8) | (int(self.state) & 0xFF)
        safe_write_uword(target_table, "%R2440", r2440_val, privilege=privilege)

        # %R2441: upper byte max_nodes, lower byte plca_slot
        r2441_val = ((self.plca.max_nodes & 0xFF) << 8) | (self.current_plca_slot & 0xFF)
        safe_write_uword(target_table, "%R2441", r2441_val, privilege=privilege)

        # %R2442: PLCA cycle time in us
        safe_write_uword(target_table, "%R2442", self.plca_cycle_time_us & 0xFFFF, privilege=privilege)

        # %R2443: Reflection coefficient scaled 0..1000 (e.g. 15.0% -> 150)
        refl_scaled = int(round(min(1.0, max(0.0, self.reflection_coefficient)) * 1000.0))
        safe_write_uword(target_table, "%R2443", refl_scaled & 0xFFFF, privilege=privilege)

        # %R2444: Line impedance in Ohms
        z_val = int(round(max(0.0, min(65535.0, self.line_impedance_ohm))))
        safe_write_uword(target_table, "%R2444", z_val & 0xFFFF, privilege=privilege)

        # %R2445: Rolling sequence counter
        safe_write_uword(target_table, "%R2445", self.tx_sequence & 0xFFFF, privilege=privilege)

        # %R2446: CRC status word
        safe_write_uword(target_table, "%R2446", self.crc_status & 0xFFFF, privilege=privilege)

        # %R2447: Diagnostic code
        safe_write_uword(target_table, "%R2447", int(self.diagnostic_code) & 0xFFFF, privilege=privilege)

        # %M569: Trunk Active (True when OPERATIONAL or DEGRADED)
        active_bool = self.state in (
            CipSafetyAplMultidropState.OPERATIONAL,
            CipSafetyAplMultidropState.DEGRADED,
        )
        safe_write_bit(target_table, "%M569", active_bool, privilege=privilege)

        # %M570: Trunk Fault / Bus Collision (True on FAIL_SAFE or non-zero diagnostic)
        fault_bool = (
            self.state == CipSafetyAplMultidropState.FAIL_SAFE
            or self.diagnostic_code != CipSafetyAplMultidropDiagnosticCode.OK
        )
        safe_write_bit(target_table, "%M570", fault_bool, privilege=privilege)


# Compatibility aliases
CIPSafetyAplMultidropEngine = CipSafetyAplMultidropEngine
CIPSafetyAPLMultidropEngine = CipSafetyAplMultidropEngine


# ============================================================================
# 8. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_safety_apl_multidrop_verification(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W283",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W283.

    Stages:
      Stage 1: init_and_config
      Stage 2: payload_and_dual_crc_s1_s2
      Stage 3: plca_collision_avoidance_and_arbitration
      Stage 4: drop_reflection_and_termination_surveillance
      Stage 5: trunk_fault_and_bus_collision_detection
      Stage 6: fail_safe_fallback_on_trunk_partition
      Stage 7: horner_ocs_register_sync
      Stage 8: pure_st_pou_generation_and_ladder_rejection
      Stage 9: cyclic_soak_100_scans

    Returns strict 4-state contract JSON evidence.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: init_and_config
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1.1 Default configuration verification
    eng_def = CipSafetyAplMultidropEngine()
    def_ok = (
        eng_def.safety_network_number == DEFAULT_SAFETY_NETWORK_NUMBER
        and eng_def.state == CipSafetyAplMultidropState.OPERATIONAL
        and eng_def.local_node_id == DEFAULT_NODE_ID
        and eng_def.max_nodes == DEFAULT_MAX_NODES
        and eng_def.plca_cycle_time_us == (8 * 32 + 20)
        and eng_def.line_impedance_ohm == 100.0
        and eng_def.reflection_coefficient == 0.0
        and eng_def.is_healthy is True
        and eng_def.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.OK
    )

    # 1.2 Custom configuration verification
    plca_cust = PlcaConfig(
        node_id=3,
        max_nodes=16,
        to_timer_us=50,
        beacon_timer_us=30,
        is_coordinator=False,
    )
    eng_cust = CipSafetyAplMultidropEngine(
        safety_network_number=0xAABBCCDD,
        plca_config=plca_cust,
        line_impedance_ohm=100.0,
        watchdog_timeout_ms=300.0,
        auto_activate=False,
    )
    cust_ok = (
        eng_cust.safety_network_number == 0xAABBCCDD
        and eng_cust.local_node_id == 3
        and eng_cust.max_nodes == 16
        and eng_cust.plca_cycle_time_us == (16 * 50 + 30)
        and eng_cust.state == CipSafetyAplMultidropState.INIT
        and eng_cust.watchdog_timeout_ms == 300.0
    )

    # 1.3 Constants and Class ID verification
    const_ok = (
        CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        and CIP_SAFETY_APL_MULTIDROP_CLASS_ID == 0x3E
        and REG_CIP_SAFETY_MULTIDROP_STATE == "%R2440"
        and REG_CIP_SAFETY_MULTIDROP_PLCA_CONFIG == "%R2441"
        and REG_CIP_SAFETY_MULTIDROP_PLCA_CYCLE_US == "%R2442"
        and REG_CIP_SAFETY_MULTIDROP_REFLECTION_PCT == "%R2443"
        and REG_CIP_SAFETY_MULTIDROP_LINE_IMPEDANCE_OHM == "%R2444"
        and REG_CIP_SAFETY_MULTIDROP_SEQUENCE_COUNTER == "%R2445"
        and REG_CIP_SAFETY_MULTIDROP_CRC_STATUS == "%R2446"
        and REG_CIP_SAFETY_MULTIDROP_DIAGNOSTIC_CODE == "%R2447"
        and COIL_CIP_SAFETY_MULTIDROP_ACTIVE == "%M569"
        and COIL_CIP_SAFETY_MULTIDROP_FAULT == "%M570"
        and hash(CipSafetyAplMultidropDiagnosticCode.OK) == hash(0)
    )

    s1_pass = def_ok and cust_ok and const_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "init_and_config",
        "check": "Multi-Drop Trunk Engine Initialization & PLCA Configuration",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": "Default engine, custom PLCA cluster (16 nodes), Class IDs (0x39/0x3A/0x3B/0x3E), and %R2440..%R2447 mappings verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: payload_and_dual_crc_s1_s2
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sample_payload = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    crc1_val = compute_crc_s1(sample_payload)
    crc1_repeat = compute_crc_s1(sample_payload)
    crc2_val = compute_crc_s2(DEFAULT_SAFETY_NETWORK_NUMBER, 1, 1000, crc1_val)
    crc2_repeat = compute_crc_s2(DEFAULT_SAFETY_NETWORK_NUMBER, 1, 1000, crc1_val)

    crc_calc_ok = (
        crc1_val == crc1_repeat
        and crc2_val == crc2_repeat
        and crc1_val != crc2_val
        and crc1_val != 0
        and crc2_val != 0
    )

    # Valid frame creation & verification
    valid_frame = create_valid_frame(
        safety_network_number=DEFAULT_SAFETY_NETWORK_NUMBER,
        node_id=1,
        plca_slot=1,
        sequence_number=10,
        timestamp_ms=2000,
        payload_bytes=sample_payload,
    )
    frame_valid_ok = valid_frame.verify_crc_s1() and valid_frame.verify_crc_s2() and valid_frame.is_valid()

    # Corrupted payload rejection
    corrupt_payload_frame = create_valid_frame(
        safety_network_number=DEFAULT_SAFETY_NETWORK_NUMBER,
        node_id=1,
        plca_slot=1,
        sequence_number=10,
        timestamp_ms=2000,
        payload_bytes=sample_payload,
    )
    corrupt_payload_frame.mutate_payload(byte_offset=2, bit_pos=3)
    payload_corrupt_detected = (
        not corrupt_payload_frame.verify_crc_s1()
        and not corrupt_payload_frame.is_valid()
    )

    # Corrupted S2 rejection (sequence number tampered)
    bad_seq_frame = create_valid_frame(
        safety_network_number=DEFAULT_SAFETY_NETWORK_NUMBER,
        node_id=1,
        plca_slot=1,
        sequence_number=10,
        timestamp_ms=2000,
        payload_bytes=sample_payload,
    )
    bad_seq_frame.sequence_number = 9999
    bad_seq_detected = (
        bad_seq_frame.verify_crc_s1() is True       # Payload intact
        and bad_seq_frame.verify_crc_s2() is False  # Header sequence mutated
        and not bad_seq_frame.is_valid()
    )

    # Wire format pack & unpack round-trip
    packed_bytes = valid_frame.pack()
    unpacked_frame = CipSafetyAplMultidropFrame.unpack(packed_bytes)
    pack_unpack_ok = (
        unpacked_frame.is_valid()
        and unpacked_frame.payload_bytes == sample_payload
        and unpacked_frame.crc_s1 == valid_frame.crc_s1
        and unpacked_frame.crc_s2 == valid_frame.crc_s2
        and unpacked_frame.sequence_number == 10
        and unpacked_frame.plca_slot == 1
    )

    s2_pass = crc_calc_ok and frame_valid_ok and payload_corrupt_detected and bad_seq_detected and pack_unpack_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "payload_and_dual_crc_s1_s2",
        "check": "Payload Framing & Dual Safety CRC-S1/S2 Verification and Corruption Detection",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": "CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B inverted) calculations, mutation rejection, and pack/unpack verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: plca_collision_avoidance_and_arbitration
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng_plca = CipSafetyAplMultidropEngine(auto_activate=True)

    # 3.1 Transmit timing in assigned slot (Slot 1)
    tx_slot_ok = False
    try:
        tx_frame = eng_plca.transmit_frame(payload_bytes=b"\xCA\xFE\xBA\xBE", slot=1)
        tx_slot_ok = (
            tx_frame.is_valid()
            and tx_frame.plca_slot == 1
            and eng_plca.tx_sequence == 1
        )
    except Exception:
        tx_slot_ok = False

    # 3.2 Blocked transmission when attempting to transmit out of slot (Slot 4 != Node 1)
    blocked_out_of_slot = False
    try:
        eng_plca.transmit_frame(payload_bytes=b"\x12\x34\x56\x78", slot=4)
    except BusCollisionError:
        blocked_out_of_slot = True
    except Exception:
        blocked_out_of_slot = False

    # 3.3 PLCA cycle timing verification across cluster
    # Node 0 (Coordinator), Node 1, Node 2 round-robin allocation
    plca_timing_ok = (
        eng_plca.plca_cycle_time_us == (8 * 32 + 20)
        and eng_plca.can_transmit_in_slot(1) is True
        and eng_plca.can_transmit_in_slot(2) is False
        and eng_plca.can_transmit_in_slot(9) is True  # 9 % 8 == 1 (next round-robin cycle)
    )

    s3_pass = tx_slot_ok and blocked_out_of_slot and plca_timing_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "plca_collision_avoidance_and_arbitration",
        "check": "PLCA Collision Avoidance Transmission Timing and Round-Robin Slot Arbitration",
        "passed": bool(s3_pass),
        "timing_ms": round(t1, 3),
        "details": "Allotted slot transmission (Slot 1), non-allotted slot blocking (Slot 4), and modulo cycle timing verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: drop_reflection_and_termination_surveillance
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng_refl = CipSafetyAplMultidropEngine(auto_activate=True)

    # 4.1 Nominal matched line (ZL = 100 Ohm -> Gamma = 0.0)
    g0 = compute_reflection_coefficient(100.0, 100.0)
    nom_refl_ok = (g0 == 0.0)

    # 4.2 Mild spur drop within 15% margin (ZL = 88 Ohm -> Gamma = 12/188 = 0.0638 <= 0.15)
    eng_refl.update_bus_impedance(88.0)
    mild_ok = (
        eng_refl.reflection_coefficient <= 0.15
        and eng_refl.state == CipSafetyAplMultidropState.OPERATIONAL
        and eng_refl.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.OK
    )

    # 4.3 Severe spur mismatch / damaged cable (ZL = 60 Ohm -> Gamma = 40/160 = 0.25 > 0.15)
    eng_refl.update_bus_impedance(60.0)
    mismatch_ok = (
        eng_refl.reflection_coefficient > 0.15
        and eng_refl.state == CipSafetyAplMultidropState.DEGRADED
        and eng_refl.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH
        and eng_refl.is_healthy is True  # Degraded link remains healthy for safety communication
    )

    # 4.4 Open circuit spur (ZL = 1000 Ohm -> Gamma = 900/1100 = 0.818)
    eng_refl.update_bus_impedance(1000.0)
    open_ok = (
        eng_refl.reflection_coefficient > 0.50
        and eng_refl.state == CipSafetyAplMultidropState.DEGRADED
    )

    s4_pass = nom_refl_ok and mild_ok and mismatch_ok and open_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "drop_reflection_and_termination_surveillance",
        "check": "Drop Cable Reflection Surveillance and Line Impedance Mismatch Alerts",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "Reflection Gamma calculation (ZL=100 -> 0.0, ZL=88 -> 0.064, ZL=60 -> 0.25), and REFLECTION_MISMATCH alert confirmed.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: trunk_fault_and_bus_collision_detection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s5 = RegisterTable()
    eng_coll = CipSafetyAplMultidropEngine(register_table=rt_s5, auto_activate=True)

    # 5.1 Simulate bus collision & verify %M570 asserted
    eng_coll.simulate_collision()
    collision_ok = (
        eng_coll.state == CipSafetyAplMultidropState.FAIL_SAFE
        and eng_coll.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
        and eng_coll.is_fail_safe is True
        and rt_s5.read_bit("%M569") is False
        and rt_s5.read_bit("%M570") is True
        and rt_s5.read_uword("%R2447") == 0xED01
    )

    # 5.2 Reset and simulate trunk short circuit
    eng_coll.reset()
    eng_coll.simulate_trunk_short()
    short_ok = (
        eng_coll.state == CipSafetyAplMultidropState.FAIL_SAFE
        and eng_coll.line_impedance_ohm == 0.0
        and eng_coll.reflection_coefficient == 1.0
        and rt_s5.read_bit("%M569") is False
        and rt_s5.read_bit("%M570") is True
    )

    s5_pass = collision_ok and short_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "trunk_fault_and_bus_collision_detection",
        "check": "Trunk Bus Collision & Short Circuit Detection with %M570 Alarm Assertion",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "Simulated collision and short circuit, verified FAIL_SAFE transition and %M570 assertion in RegisterTable.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: fail_safe_fallback_on_trunk_partition
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s6 = RegisterTable()
    eng_part = CipSafetyAplMultidropEngine(register_table=rt_s6, auto_activate=True)
    eng_part.safe_outputs = b"\xDE\xAD\xBE\xEF"

    # 6.1 Simulate trunk partition / severed cable
    eng_part.simulate_trunk_partition()
    part_ok = (
        eng_part.state == CipSafetyAplMultidropState.FAIL_SAFE
        and eng_part.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
        and eng_part.safe_outputs == b"\x00\x00\x00\x00"  # De-energized safe outputs
        and rt_s6.read_bit("%M569") is False
        and rt_s6.read_bit("%M570") is True
        and rt_s6.read_uword("%R2447") == 0xED05
    )

    # 6.2 Watchdog timeout expiration triggers partition
    eng_part2 = CipSafetyAplMultidropEngine(watchdog_timeout_ms=150.0, auto_activate=True)
    eng_part2.safe_outputs = b"\xAA\xBB\xCC\xDD"
    eng_part2.scan_step(0.200)  # 200 ms > 150 ms watchdog threshold
    wdog_part_ok = (
        eng_part2.state == CipSafetyAplMultidropState.FAIL_SAFE
        and eng_part2.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
        and eng_part2.safe_outputs == b"\x00\x00\x00\x00"
    )

    # 6.3 Rejection of frame from foreign SNN during partition
    eng_snn_test = CipSafetyAplMultidropEngine(safety_network_number=0x11112222, auto_activate=True)
    foreign_frame = create_valid_frame(safety_network_number=0x99998888)
    foreign_rx = eng_snn_test.process_frame(foreign_frame)
    foreign_reject_ok = (
        foreign_rx is False
        and eng_snn_test.state == CipSafetyAplMultidropState.FAIL_SAFE
        and eng_snn_test.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
    )

    s6_pass = part_ok and wdog_part_ok and foreign_reject_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "fail_safe_fallback_on_trunk_partition",
        "check": "Fail-Safe Transition & De-Energized Safe Outputs on Trunk Partition",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "Trunk severance, watchdog silence expiration (200ms), and foreign SNN rejection into de-energized FAIL_SAFE state confirmed.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: horner_ocs_register_sync
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s7 = RegisterTable()
    eng_sync = CipSafetyAplMultidropEngine(register_table=rt_s7, auto_activate=True)

    # 7.1 Verify nominal register space mapping
    # %R2440: (1 << 8) | 1 = 257 (Node 1, State 1)
    # %R2441: (8 << 8) | 1 = 2049 (Max nodes 8, Slot 1)
    # %R2442: 276 us
    # %R2443: 0 (0.0% reflection)
    # %R2444: 100 Ohm
    # %R2445: 0 (TX sequence)
    # %R2446: 7 (CRC status nominal 0x0007)
    # %R2447: 0 (Diagnostic OK)
    # %M569: True (Trunk Active)
    # %M570: False (Trunk Fault)
    nom_sync_ok = (
        rt_s7.read_uword("%R2440") == 257
        and rt_s7.read_uword("%R2441") == 2049
        and rt_s7.read_uword("%R2442") == 276
        and rt_s7.read_uword("%R2443") == 0
        and rt_s7.read_uword("%R2444") == 100
        and rt_s7.read_uword("%R2445") == 0
        and rt_s7.read_uword("%R2446") == 7
        and rt_s7.read_uword("%R2447") == 0
        and rt_s7.read_bit("%M569") is True
        and rt_s7.read_bit("%M570") is False
    )

    # 7.2 Update under reflection degradation
    eng_sync.update_bus_impedance(65.0)  # Gamma = 35/165 = 0.212 -> scaled 212
    # State = 2 (DEGRADED) -> %R2440 = ((1 << 8) | 2) = 258
    degrade_sync_ok = (
        rt_s7.read_uword("%R2440") == 258
        and rt_s7.read_uword("%R2443") == 212
        and rt_s7.read_uword("%R2444") == 65
        and rt_s7.read_uword("%R2447") == 0xED02
        and rt_s7.read_bit("%M569") is True
        and rt_s7.read_bit("%M570") is True  # Non-zero diagnostic asserts fault alarm
    )

    # 7.3 Update under FAIL_SAFE trip
    eng_sync.simulate_collision()
    # State = 3 (FAIL_SAFE) -> %R2440 = ((1 << 8) | 3) = 259
    failsafe_sync_ok = (
        rt_s7.read_uword("%R2440") == 259
        and rt_s7.read_uword("%R2447") == 0xED01
        and rt_s7.read_bit("%M569") is False
        and rt_s7.read_bit("%M570") is True
    )

    s7_pass = nom_sync_ok and degrade_sync_ok and failsafe_sync_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "horner_ocs_register_sync",
        "check": "Horner OCS Register Space Synchronization (%R2440..%R2447 and %M569..%M570)",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified full synchronization of %R2440..%R2447 and discrete coils %M569..%M570 across nominal, degraded, and fail-safe states.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_generation_and_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    pou_valid = verify_cip_safety_apl_multidrop_pure_st()

    # Verify bound registers in POU AST
    ast = STParser(pou_type=POUType.PROGRAM).parse(CipSafetyAplMultidropSync)
    expected_regs = {
        "%R2440", "%R2441", "%R2442", "%R2443",
        "%R2444", "%R2445", "%R2446", "%R2447",
        "%M569", "%M570",
    }
    regs_bound_ok = expected_regs.issubset(set(ast.bound_registers))

    # Reject forbidden ladder constructs
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

    s8_pass = pou_valid and regs_bound_ok and anti_ladder_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "pure_st_pou_generation_and_ladder_rejection",
        "check": "Pure IEC 61131-3 Structured Text POU Validation and Anti-Ladder Construct Rejection",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": f"CipSafetyAplMultidropSync pure ST verified with {len(ast.bound_registers)} bound registers; rejected {rejected_count}/{len(ladder_snippets)} ladder constructs.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: cyclic_soak_100_scans
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    tracemalloc.start()
    rt_s9 = RegisterTable()
    eng_soak = CipSafetyAplMultidropEngine(register_table=rt_s9, auto_activate=True)

    scan_errors = 0
    for cycle in range(100):
        try:
            eng_soak.feed_watchdog()
            eng_soak.transmit_frame(payload_bytes=b"\x01\x02\x03\x04")
            eng_soak.scan_step(0.010)
            if not eng_soak.is_healthy or eng_soak.diagnostic_code != CipSafetyAplMultidropDiagnosticCode.OK:
                scan_errors += 1
        except Exception:
            scan_errors += 1

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # ILogicUnit execute method verification
    exec_result = eng_soak.execute()
    exec_ok = (
        exec_result.status == AgentStatus.SUCCESS
        and exec_result.error_code is None
        and eng_soak.cycles_count == 101  # 100 soak scans + 1 execute scan
        and scan_errors == 0
        and peak_mem < 2 * 1024 * 1024  # Less than 2MB memory footprint
    )

    s9_pass = exec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 9,
        "name": "cyclic_soak_100_scans",
        "check": "100 Cyclic Scan Soak Execution, Memory Leak & Latency Stability Surveillance",
        "passed": bool(s9_pass),
        "timing_ms": round(t1, 3),
        "details": f"100 scan cycles executed cleanly with 0 faults (peak memory: {peak_mem / 1024:.1f} KB, execution status: SUCCESS).",
    })

    # ------------------------------------------------------------------------
    # Aggregate Results & Strict 4-State Evidence
    # ------------------------------------------------------------------------
    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    status = "success" if all_passed else "failed"
    error_code = None if all_passed else "ERR_STAGE_VERIFICATION_FAILED"
    details = (
        f"All {total_stages} Industrial ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk stages passed deterministically."
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
            "protocol": "ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk (10BASE-T1S / 2-WISE)",
            "standards": ["IEEE 802.3cg Clause 147/148", "IEC 61784-3-2", "IEC 61508 SIL 3"],
            "registers": ["%R2440..%R2447", "%M569..%M570"],
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
