"""Industrial ODVA CIP Safety Time-Sensitive Networking (TSN) Safe Scheduling Protocol Engine.

Work Package: W259 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- IEEE 802.1Qbv-2015: Enhancements for Scheduled Traffic (Time-Aware Shaper / TAS):
  - Cyclic schedule windowing with Gate Control List (GCL).
  - Repeating cycle time: 1000 us (1.0 ms nominal).
  - Scheduled Transmission Window Offset: 250 us.
  - Guard Band active window preceding scheduled express traffic: 50 us (or configurable).
- IEEE 802.1Qbu-2016 / IEEE 802.3br: Frame Preemption:
  - Express traffic prioritization (PCP = 7) preempting lower-priority / best-effort frames.
  - Frame preemption fragmentation & preemption failure interlock.
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - Class 0x39: Safety Supervisor Object.
  - Class 0x3A: Safety Validator Object.
  - Class 0x3B: Safety Connection Object.
  - Flow Priority: PCP = 7 (VLAN Priority Code Point 7), Safe Class 0x39.
  - Dual 16-bit Safety Checksums:
    - CRC-S1: Generator polynomial 0x5935 (init 0xFFFF).
    - CRC-S2: Generator polynomial 0x755B (init 0xFFFF).
  - Diversified Sequence Counters:
    - Primary seq_1 (0..65535 rolling).
    - Secondary seq_2 = (~seq_1) & 0xFFFF.
- IEEE 802.1AS-2020 / TSN Time Synchronization:
  - Sub-microsecond time-sync jitter watchdog surveillance (< 100 ns limit, nominal 45 ns).
- Horner OCS Memory Space:
  - Analog registers %R2200..%R2207:
    - %R2200: REG_TSN_SAFETY_GATE_STATE (0=CLOSED, 1=PREEMPTABLE_OPEN, 2=EXPRESS_SCHEDULED_OPEN, 3=GUARD_BAND_ACTIVE, 4=FAILSAFE_CLOSED)
    - %R2201: REG_TSN_CYCLE_TIME_US (nominal 1000 us = 1 ms)
    - %R2202: REG_TSN_SCHEDULE_OFFSET_US (nominal 250 us)
    - %R2203: REG_TSN_MAX_JITTER_NS (nominal 45 ns, trip threshold >= 100 ns)
    - %R2204: REG_TSN_PREEMPTION_COUNT (nominal 0)
    - %R2205: REG_TSN_EXPRESS_PACKET_COUNT (nominal 100)
    - %R2206: REG_TSN_SAFETY_FLOW_PRIORITY (PCP = 7, Safe Class 0x39 -> 0x0739)
    - %R2207: REG_TSN_SAFETY_DIAGNOSTIC_CODE (0x0000 OK, 0xEE31 SCHEDULE_MISMATCH_TRIP, 0xEE32 JITTER_EXCEEDED_TRIP, 0xEE33 GUARD_BAND_VIOLATION, 0xEE34 PREEMPTION_FAIL_TRIP)
  - Discrete coils %M513..%M514:
    - %M513: COIL_TSN_SCHEDULE_SYNCED (BOOL: True when schedule synced & operational)
    - %M514: COIL_TSN_SAFETY_INTERLOCK_TRIPPED (BOOL: True when safety interlock tripped)
- Implements ILogicUnit interface with scan_step(dt, context), step(dt, context), execute(context), and reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetyTsnSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.
- Deterministic 10-stage verification suite run_cip_safety_tsn_verification().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import json
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
# 1. Constants & Protocol Definitions (ODVA CIP Safety Volume 5 / TSN 802.1Qbv/bu)
# ============================================================================

CIP_SAFETY_SUPERVISOR_CLASS_ID: int = 0x39          # Safety Supervisor Object
CIP_SAFETY_VALIDATOR_CLASS_ID: int = 0x3A           # Safety Validator Object
CIP_SAFETY_CONNECTION_CLASS_ID: int = 0x3B          # Safety Connection Object
CIP_SAFETY_TSN_CLASS_ID: int = 0x39

# TSN Flow Priority & Class
NOMINAL_TSN_PCP: int = 7                            # 802.1Q Priority Code Point 7 (Network Control / Safe)
DEFAULT_PCP: int = 7
NOMINAL_TSN_SAFE_CLASS: int = 0x39                  # Safe Class 0x39
DEFAULT_SAFE_CLASS: int = 0x39
NOMINAL_TSN_SAFETY_FLOW_PRIORITY: int = (7 << 8) | 0x39  # 0x0739 (1849)
DEFAULT_SAFETY_FLOW_PRIORITY: int = NOMINAL_TSN_SAFETY_FLOW_PRIORITY

# Timing Defaults
NOMINAL_TSN_CYCLE_TIME_US: int = 1000               # 1000 us (1.0 ms) nominal TSN cycle
DEFAULT_CYCLE_TIME_US: int = 1000
MIN_CYCLE_TIME_US: int = 100
MAX_CYCLE_TIME_US: int = 100000

NOMINAL_TSN_SCHEDULE_OFFSET_US: int = 250           # Nominal schedule offset: 250 us
DEFAULT_SCHEDULE_OFFSET_US: int = 250

DEFAULT_EXPRESS_DURATION_US: int = 250              # Scheduled express window duration: 250 us
DEFAULT_GUARD_BAND_DURATION_US: int = 50            # Guard band duration: 50 us

NOMINAL_TSN_MAX_JITTER_NS: int = 45                 # Nominal time-sync jitter: 45 ns
DEFAULT_MAX_JITTER_NS: int = 45
DEFAULT_JITTER_NS: int = 45
MAX_ALLOWED_JITTER_NS: int = 100                    # Jitter watchdog limit: < 100 ns
JITTER_WATCHDOG_LIMIT_NS: int = 100

# Packet and Preemption Counters
NOMINAL_TSN_PREEMPTION_COUNT: int = 0               # Cumulative preemption count
DEFAULT_PREEMPTION_COUNT: int = 0
NOMINAL_TSN_EXPRESS_PACKET_COUNT: int = 100         # Nominal express safety packet count
DEFAULT_EXPRESS_PACKET_COUNT: int = 100

# Minimum frame size eligible for IEEE 802.1Qbu preemption (IEEE 802.3br min fragment size 64 bytes)
MIN_PREEMPTABLE_FRAME_LEN: int = 64

# Dual CRC Polynomials and Seeds (ODVA CIP Safety Volume 5)
CIP_SAFETY_CRC_S1_POLY: int = 0x5935                # CRC-S1 generator polynomial
CIP_SAFETY_CRC_S2_POLY: int = 0x755B                # CRC-S2 generator polynomial
CRC_S1_POLY: int = 0x5935
CRC_S2_POLY: int = 0x755B
CIP_SAFETY_CRC_INIT: int = 0xFFFF                   # CRC-S initial seed
CRC_S_INIT: int = 0xFFFF

# Canonical Register Table Mapping (%R2200..%R2207)
REG_TSN_SAFETY_GATE_STATE: str = "%R2200"           # TSN Gate State (0..4)
REG_TSN_CYCLE_TIME_US: str = "%R2201"               # TSN Cycle Time (us, nominal 1000)
REG_TSN_SCHEDULE_OFFSET_US: str = "%R2202"          # Schedule Offset (us, nominal 250)
REG_TSN_MAX_JITTER_NS: str = "%R2203"               # Max Time-Sync Jitter (ns, nominal 45)
REG_TSN_PREEMPTION_COUNT: str = "%R2204"            # Cumulative Preemption Count (nominal 0)
REG_TSN_EXPRESS_PACKET_COUNT: str = "%R2205"        # Express Safety Packet Count (nominal 100)
REG_TSN_SAFETY_FLOW_PRIORITY: str = "%R2206"        # Safety Flow Priority (PCP=7, Safe Class 0x39)
REG_TSN_SAFETY_DIAGNOSTIC_CODE: str = "%R2207"      # Diagnostic Code (0x0000, 0xEE31..0xEE34)

# Canonical Discrete Coils Mapping (%M513..%M514)
COIL_TSN_SCHEDULE_SYNCED: str = "%M513"             # BOOL: Schedule synchronized & operational
COIL_TSN_SAFETY_INTERLOCK_TRIPPED: str = "%M514"    # BOOL: Safety interlock tripped

# Register & Coil Aliases
REG_TSN_GATE_STATE: str = "%R2200"
REG_SAFETY_GATE_STATE: str = "%R2200"
REG_TSN_STATE: str = "%R2200"
REG_GATE_STATE: str = "%R2200"

REG_TSN_CYCLE_US: str = "%R2201"
REG_TSN_CYCLE_TIME: str = "%R2201"
REG_CYCLE_TIME_US: str = "%R2201"
REG_CYCLE_US: str = "%R2201"

REG_TSN_OFFSET_US: str = "%R2202"
REG_TSN_SCHEDULE_OFFSET: str = "%R2202"
REG_SCHEDULE_OFFSET_US: str = "%R2202"
REG_SCHEDULE_OFFSET: str = "%R2202"

REG_TSN_JITTER_NS: str = "%R2203"
REG_TSN_MAX_JITTER: str = "%R2203"
REG_MAX_JITTER_NS: str = "%R2203"
REG_JITTER_NS: str = "%R2203"

REG_PREEMPTION_COUNT: str = "%R2204"
REG_TSN_PREEMPTION: str = "%R2204"
REG_PREEMPTIONS: str = "%R2204"

REG_EXPRESS_PACKET_COUNT: str = "%R2205"
REG_EXPRESS_COUNT: str = "%R2205"
REG_TSN_EXPRESS_COUNT: str = "%R2205"
REG_EXPRESS_PACKETS: str = "%R2205"

REG_TSN_FLOW_PRIORITY: str = "%R2206"
REG_SAFETY_FLOW_PRIORITY: str = "%R2206"
REG_TSN_PRIORITY: str = "%R2206"
REG_FLOW_PRIORITY: str = "%R2206"

REG_TSN_DIAGNOSTIC_CODE: str = "%R2207"
REG_TSN_DIAG_CODE: str = "%R2207"
REG_SAFETY_DIAGNOSTIC_CODE: str = "%R2207"
REG_DIAGNOSTIC_STATUS_CODE: str = "%R2207"
REG_DIAGNOSTIC_CODE: str = "%R2207"

COIL_TSN_SYNCED: str = "%M513"
COIL_TSN_SYNC: str = "%M513"
COIL_SCHEDULE_SYNCED: str = "%M513"
COIL_TSN_SCHEDULE_SYNC: str = "%M513"
COIL_SYNCED: str = "%M513"

COIL_TSN_INTERLOCK_TRIPPED: str = "%M514"
COIL_TSN_TRIPPED: str = "%M514"
COIL_SAFETY_INTERLOCK_TRIPPED: str = "%M514"
COIL_INTERLOCK_TRIPPED: str = "%M514"
COIL_TSN_FAULT: str = "%M514"
COIL_TSN_SAFE_STOP_TRIPPED: str = "%M514"

# Telemetry __init__.py Interoperability Aliases
REG_TSN_SAFETY_STATE: str = REG_TSN_SAFETY_GATE_STATE
REG_TSN_GCL_CYCLE_TIME_US: str = REG_TSN_CYCLE_TIME_US
REG_TSN_TAS_WINDOW_US: str = REG_TSN_SCHEDULE_OFFSET_US
REG_TSN_GUARD_BAND_NS: str = REG_TSN_SCHEDULE_OFFSET_US
REG_TSN_SCHEDULE_JITTER_NS: str = REG_TSN_MAX_JITTER_NS
REG_TSN_FRAME_PREEMPTION_COUNT: str = REG_TSN_PREEMPTION_COUNT
REG_TSN_TRANSMIT_SEQUENCE: str = REG_TSN_EXPRESS_PACKET_COUNT
COIL_TSN_SAFETY_LINK_HEALTHY: str = COIL_TSN_SCHEDULE_SYNCED
COIL_TSN_SAFETY_STOP_TRIPPED: str = COIL_TSN_SAFETY_INTERLOCK_TRIPPED


# ============================================================================
# 2. TSN Gate States (IEEE 802.1Qbv)
# ============================================================================

class TSNGateState(IntEnum):
    """IEEE 802.1Qbv Time-Aware Shaper (TAS) Gate States mapped to %R2200."""
    CLOSED = 0                     # All traffic gates closed (idle / uninitialized)
    PREEMPTABLE_OPEN = 1           # Preemptable / best-effort traffic open, express closed
    EXPRESS_SCHEDULED_OPEN = 2     # CIP Safety express scheduled window open (PCP = 7)
    GUARD_BAND_ACTIVE = 3          # Guard band active: preemptable frames held before express window
    FAILSAFE_CLOSED = 4            # Safety interlock tripped; safe state latched closed

    # Aliases
    Closed = 0
    PreemptableOpen = 1
    ExpressScheduledOpen = 2
    GuardBandActive = 3
    FailsafeClosed = 4

    PREEMPTABLE = 1
    EXPRESS_OPEN = 2
    EXPRESS = 2
    GUARD_BAND = 3
    SAFE_STOP = 4
    SafeStop = 4
    TRIPPED = 4


TsnGateState = TSNGateState
CipSafetyTsnGateState = TSNGateState
CIPTSNGateState = TSNGateState
SafetyGateState = TSNGateState
SafeTsnState = TSNGateState
CipTsnSafetyState = TSNGateState
CIPTsnSafetyState = TSNGateState


# ============================================================================
# 3. Diagnostic Codes & Enums
# ============================================================================

class DiagnosticCode(int):
    """Integer subclass for 16-bit diagnostic codes supporting signed/unsigned equality, masking (& 0xFFFF), and formatted representation.

    Diagnostic Codes:
    - 0x0000: OK (TSN Safe Scheduling link healthy and synchronized)
    - 0xEE31: SCHEDULE_MISMATCH_TRIP (Packet transmitted outside express window or schedule drift)
    - 0xEE32: JITTER_EXCEEDED_TRIP (Time-sync jitter exceeded 100 ns watchdog threshold)
    - 0xEE33: GUARD_BAND_VIOLATION (Transmission attempted during guard band active window)
    - 0xEE34: PREEMPTION_FAIL_TRIP (IEEE 802.1Qbu frame preemption or fragmentation failure)
    """

    OK: DiagnosticCode
    SCHEDULE_MISMATCH_TRIP: DiagnosticCode
    JITTER_EXCEEDED_TRIP: DiagnosticCode
    GUARD_BAND_VIOLATION: DiagnosticCode
    PREEMPTION_FAIL_TRIP: DiagnosticCode

    # Aliases
    SAFETY_OK: DiagnosticCode
    TSN_OK: DiagnosticCode
    SCHEDULE_MISMATCH: DiagnosticCode
    ERR_SCHEDULE_MISMATCH: DiagnosticCode
    JITTER_EXCEEDED: DiagnosticCode
    ERR_JITTER_EXCEEDED: DiagnosticCode
    GUARD_BAND_TRIP: DiagnosticCode
    ERR_GUARD_BAND_VIOLATION: DiagnosticCode
    PREEMPTION_FAIL: DiagnosticCode
    ERR_PREEMPTION_FAIL: DiagnosticCode

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
        return f"0x{int(self) & 0xFFFF:04X} ({self._name})"

    def __repr__(self) -> str:
        return f"DiagnosticCode.{self._name}(0x{int(self) & 0xFFFF:04X})"

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

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __and__(self, other: Any) -> Any:
        if isinstance(other, int):
            res_val = int(self) & int(other)
            return DiagnosticCode(res_val)
        return super().__and__(other)

    def __rand__(self, other: Any) -> Any:
        if isinstance(other, int):
            res_val = int(other) & int(self)
            return DiagnosticCode(res_val)
        return super().__rand__(other)

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)


# Initialize Diagnostic Codes
DiagnosticCode.OK = DiagnosticCode(0x0000, "OK")
DiagnosticCode.SCHEDULE_MISMATCH_TRIP = DiagnosticCode(0xEE31, "SCHEDULE_MISMATCH_TRIP")
DiagnosticCode.JITTER_EXCEEDED_TRIP = DiagnosticCode(0xEE32, "JITTER_EXCEEDED_TRIP")
DiagnosticCode.GUARD_BAND_VIOLATION = DiagnosticCode(0xEE33, "GUARD_BAND_VIOLATION")
DiagnosticCode.PREEMPTION_FAIL_TRIP = DiagnosticCode(0xEE34, "PREEMPTION_FAIL_TRIP")

# Aliases
DiagnosticCode.SAFETY_OK = DiagnosticCode.OK
DiagnosticCode.TSN_OK = DiagnosticCode.OK
DiagnosticCode.SCHEDULE_MISMATCH = DiagnosticCode.SCHEDULE_MISMATCH_TRIP
DiagnosticCode.ERR_SCHEDULE_MISMATCH = DiagnosticCode.SCHEDULE_MISMATCH_TRIP
DiagnosticCode.JITTER_EXCEEDED = DiagnosticCode.JITTER_EXCEEDED_TRIP
DiagnosticCode.ERR_JITTER_EXCEEDED = DiagnosticCode.JITTER_EXCEEDED_TRIP
DiagnosticCode.GUARD_BAND_TRIP = DiagnosticCode.GUARD_BAND_VIOLATION
DiagnosticCode.ERR_GUARD_BAND_VIOLATION = DiagnosticCode.GUARD_BAND_VIOLATION
DiagnosticCode.PREEMPTION_FAIL = DiagnosticCode.PREEMPTION_FAIL_TRIP
DiagnosticCode.ERR_PREEMPTION_FAIL = DiagnosticCode.PREEMPTION_FAIL_TRIP

# Module-Level Diagnostic Code Exports
DIAG_OK = DiagnosticCode.OK
DIAG_SCHEDULE_MISMATCH_TRIP = DiagnosticCode.SCHEDULE_MISMATCH_TRIP
DIAG_JITTER_EXCEEDED_TRIP = DiagnosticCode.JITTER_EXCEEDED_TRIP
DIAG_GUARD_BAND_VIOLATION = DiagnosticCode.GUARD_BAND_VIOLATION
DIAG_PREEMPTION_FAIL_TRIP = DiagnosticCode.PREEMPTION_FAIL_TRIP

DiagnosticStatusCode = DiagnosticCode
TSNDiagnosticCode = DiagnosticCode
TsnDiagnosticCode = DiagnosticCode
CipSafetyTsnDiagnosticCode = DiagnosticCode
TSNDiagnosticStatusCode = DiagnosticCode
CipTsnDiagnosticCode = DiagnosticCode
CIP_TSN_DIAGNOSTIC_CODE = DiagnosticCode
TsnSafetyDiagnosticCode = DiagnosticCode


# ============================================================================
# 4. Exceptions
# ============================================================================

class CIPTSNSafetyError(Exception):
    """Base exception for all CIP Safety TSN errors."""
    pass


CIPSafetyTSNError = CIPTSNSafetyError
CipSafetyTsnError = CIPTSNSafetyError


class TSNScheduleMismatchError(CIPTSNSafetyError):
    """Raised on schedule mismatch or transmission outside scheduled express window (0xEE31)."""
    pass


ScheduleMismatchTripError = TSNScheduleMismatchError


class TSNJitterExceededError(CIPTSNSafetyError):
    """Raised when TSN time-sync jitter exceeds 100 ns watchdog limit (0xEE32)."""
    pass


JitterExceededTripError = TSNJitterExceededError


class TSNGuardBandViolationError(CIPTSNSafetyError):
    """Raised when preemptable frame encroaches on or transmits in guard band (0xEE33)."""
    pass


GuardBandViolationTripError = TSNGuardBandViolationError


class TSNPreemptionFailError(CIPTSNSafetyError):
    """Raised when IEEE 802.1Qbu frame preemption fails (0xEE34)."""
    pass


PreemptionFailTripError = TSNPreemptionFailError


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text (ST) POU Definition
# ============================================================================

CIP_SAFETY_TSN_PURE_ST_POU: str = """PROGRAM CipSafetyTsnSync
VAR
    (* Horner OCS Mapped Registers (W259 - ODVA CIP Safety TSN IEEE 802.1Qbv / IEEE 802.1Qbu) *)
    SafetyGateState             AT %R2200 : INT;    (* 0=CLOSED, 1=PREEMPTABLE_OPEN, 2=EXPRESS_SCHEDULED_OPEN, 3=GUARD_BAND_ACTIVE, 4=FAILSAFE_CLOSED *)
    CycleTimeUs                 AT %R2201 : INT;    (* TSN cycle time in us (nominal 1000 us = 1 ms) *)
    ScheduleOffsetUs            AT %R2202 : INT;    (* Schedule offset in us (nominal 250 us) *)
    MaxJitterNs                 AT %R2203 : INT;    (* Measured max jitter in ns (nominal 45 ns, limit < 100 ns) *)
    PreemptionCount             AT %R2204 : INT;    (* Cumulative IEEE 802.1Qbu preemption count *)
    ExpressPacketCount          AT %R2205 : INT;    (* Cumulative express safety packet count *)
    SafetyFlowPriority          AT %R2206 : INT;    (* TSN Flow Priority (PCP = 7, Safe Class 0x39) *)
    SafetyDiagnosticCode        AT %R2207 : UINT;   (* Diagnostic code: 0x0000 OK, 0xEE31..0xEE34 *)

    (* Discrete Safety Coils *)
    ScheduleSynced              AT %M513  : BOOL;   (* TRUE when TSN schedule is synchronized and active *)
    SafetyInterlockTripped      AT %M514  : BOOL;   (* TRUE when safe scheduling interlock is tripped *)

    (* Internal Safety Logic *)
    InternalSyncHealthy         : BOOL;
END_VAR

IF SafetyInterlockTripped OR (SafetyDiagnosticCode <> 0) OR (SafetyGateState = 4) THEN
    ScheduleSynced := FALSE;
    SafetyInterlockTripped := TRUE;
    InternalSyncHealthy := FALSE;
ELSIF (SafetyGateState >= 1) AND (SafetyGateState <= 3) AND (MaxJitterNs < 100) AND (CycleTimeUs = 1000) THEN
    ScheduleSynced := TRUE;
    SafetyInterlockTripped := FALSE;
    InternalSyncHealthy := TRUE;
ELSE
    ScheduleSynced := FALSE;
    SafetyInterlockTripped := TRUE;
    InternalSyncHealthy := FALSE;
END_IF;
END_PROGRAM
"""

CIP_SAFETY_TSN_SYNC_POU: str = CIP_SAFETY_TSN_PURE_ST_POU
CIP_SAFETY_TSN_POU: str = CIP_SAFETY_TSN_PURE_ST_POU
PURE_ST_POU: str = CIP_SAFETY_TSN_PURE_ST_POU
CipSafetyTsnSync: str = CIP_SAFETY_TSN_PURE_ST_POU
CipSafetyTsnSyncPOU: str = CIP_SAFETY_TSN_PURE_ST_POU


def verify_cip_safety_tsn_pure_st(pou_text: Optional[str] = None) -> bool:
    """Validate pure IEC 61131-3 ST POU with SecurityGuard and STParser."""
    try:
        text = pou_text if pou_text is not None else CIP_SAFETY_TSN_PURE_ST_POU
        SecurityGuard.assert_pure_st_content(text)
        res = STParser.validate_code(text)
        if res.status != AgentStatus.SUCCESS:
            return False
        ast = STParser.parse_pou(text)
        if ast.pou_type != POUType.PROGRAM:
            return False

        required_registers: Set[str] = {
            "%R2200", "%R2201", "%R2202", "%R2203",
            "%R2204", "%R2205", "%R2206", "%R2207",
            "%M513", "%M514",
        }
        return required_registers.issubset(set(ast.bound_registers))
    except Exception:
        return False


# ============================================================================
# 6. Checksum, Dual CRC-S & Helper Functions
# ============================================================================

def compute_crc_s1(*args: Any, poly: int = CIP_SAFETY_CRC_S1_POLY, init: int = CIP_SAFETY_CRC_INIT, **kwargs: Any) -> int:
    """Calculate 16-bit safety checksum CRC-S1 with generator polynomial 0x5935."""
    if len(args) == 1 and isinstance(args[0], (bytes, bytearray)):
        data = bytes(args[0])
    elif len(args) > 0 and all(isinstance(a, (bytes, bytearray)) for a in args):
        data = b"".join(bytes(a) for a in args)
    else:
        raise ValueError(f"Unsupported arguments to compute_crc_s1: {args}")

    p = kwargs.get("poly", poly)
    i = kwargs.get("init", kwargs.get("seed", init))
    crc = i & 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ p) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def compute_crc_s2(*args: Any, poly: int = CIP_SAFETY_CRC_S2_POLY, init: int = CIP_SAFETY_CRC_INIT, **kwargs: Any) -> int:
    """Calculate 16-bit safety checksum CRC-S2 with generator polynomial 0x755B."""
    if len(args) == 1 and isinstance(args[0], (bytes, bytearray)):
        data = bytes(args[0])
    elif len(args) > 0 and all(isinstance(a, (bytes, bytearray)) for a in args):
        data = b"".join(bytes(a) for a in args)
    else:
        raise ValueError(f"Unsupported arguments to compute_crc_s2: {args}")

    p = kwargs.get("poly", poly)
    i = kwargs.get("init", kwargs.get("seed", init))
    crc = i & 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ p) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


calc_crc_s1 = compute_crc_s1
calc_crc_s2 = compute_crc_s2


def verify_dual_crc_s(data1: bytes, data2: bytes, crc_s1: int, crc_s2: int) -> bool:
    """Verify both CRC-S1 and CRC-S2 checksums match calculated values."""
    return (compute_crc_s1(data1) == (crc_s1 & 0xFFFF)) and (compute_crc_s2(data2) == (crc_s2 & 0xFFFF))


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
# 7. Safety Frame Packet Structure & Dual CRC Verification
# ============================================================================

@dataclass
class CIPSafetyTSNPacket:
    """ODVA CIP Safety Over TSN (IEEE 802.1Qbv / 802.1Qbu) Packet Container.

    Encapsulates dual-channel diversified safety sequence, flow priority (PCP=7),
    safe class ID (0x39), timestamp, payload, and dual CRC-S checksums (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B).
    """
    sequence_primary: int = 1
    sequence_diversified: int = 0  # (~sequence_primary) & 0xFFFF
    cycle_count: int = 0
    timestamp_ns: int = 0
    pcp: int = NOMINAL_TSN_PCP
    class_id: int = NOMINAL_TSN_SAFE_CLASS
    payload: bytes = b"\x01\x00\x00\x00"
    crc_s1: int = 0
    crc_s2: int = 0

    def __post_init__(self) -> None:
        if self.sequence_diversified == 0:
            self.sequence_diversified = (~self.sequence_primary) & 0xFFFF

    def serialize_for_crc_s1(self) -> bytes:
        """Serialize primary header, sequence, and payload for CRC-S1 (poly 0x5935)."""
        header = struct.pack(
            ">HHQBBH",
            self.sequence_primary & 0xFFFF,
            self.cycle_count & 0xFFFF,
            self.timestamp_ns & 0xFFFFFFFFFFFFFFFF,
            self.pcp & 0xFF,
            self.class_id & 0xFF,
            len(self.payload) & 0xFFFF,
        )
        return header + self.payload

    def serialize_for_crc_s2(self) -> bytes:
        """Serialize diversified header, inverted sequence, and inverted payload for CRC-S2 (poly 0x755B)."""
        header = struct.pack(
            ">HHQBBH",
            self.sequence_diversified & 0xFFFF,
            (self.cycle_count ^ 0xFFFF) & 0xFFFF,
            (self.timestamp_ns ^ 0xFFFFFFFFFFFFFFFF) & 0xFFFFFFFFFFFFFFFF,
            (self.pcp ^ 0xFF) & 0xFF,
            (self.class_id ^ 0xFF) & 0xFF,
            len(self.payload) & 0xFFFF,
        )
        inv_payload = bytes(b ^ 0xFF for b in self.payload)
        return header + inv_payload

    def calculate_crcs(self) -> None:
        """Calculate and store dual safety checksums CRC-S1 and CRC-S2."""
        self.crc_s1 = compute_crc_s1(self.serialize_for_crc_s1())
        self.crc_s2 = compute_crc_s2(self.serialize_for_crc_s2())

    populate_crcs = calculate_crcs

    def verify_crcs(self) -> bool:
        """Verify that stored CRC-S1 and CRC-S2 match freshly recomputed checksums."""
        exp1 = compute_crc_s1(self.serialize_for_crc_s1())
        exp2 = compute_crc_s2(self.serialize_for_crc_s2())
        return (self.crc_s1 == exp1) and (self.crc_s2 == exp2)

    def verify_sequence(self) -> bool:
        """Verify that diversified sequence counter satisfies bitwise inversion property."""
        expected_div = (~self.sequence_primary) & 0xFFFF
        return (self.sequence_diversified & 0xFFFF) == expected_div

    def mutate_bit(self, byte_offset: int = 0, bit_pos: int = 0) -> None:
        """Inject single-bit corruption into payload for test suites."""
        ba = bytearray(self.payload)
        idx = byte_offset % len(ba)
        ba[idx] ^= (1 << (bit_pos % 8))
        self.payload = bytes(ba)


CipSafetyTsnPacket = CIPSafetyTSNPacket
CIPSafetyTsnPacket = CIPSafetyTSNPacket
CIP_SAFETY_TSN_PACKET = CIPSafetyTSNPacket
TSNSafetyPacket = CIPSafetyTSNPacket
TsnSafetyPacket = CIPSafetyTSNPacket


def create_valid_tsn_safety_packet(
    sequence_primary: int = 1,
    cycle_count: int = 0,
    timestamp_ns: int = 0,
    pcp: int = NOMINAL_TSN_PCP,
    class_id: int = NOMINAL_TSN_SAFE_CLASS,
    payload: bytes = b"\x01\x00\x00\x00",
    **kwargs: Any,
) -> CIPSafetyTSNPacket:
    """Factory creating valid CIP Safety TSN packet with pre-calculated CRCs."""
    pkt = CIPSafetyTSNPacket(
        sequence_primary=sequence_primary,
        cycle_count=cycle_count,
        timestamp_ns=timestamp_ns,
        pcp=pcp,
        class_id=class_id,
        payload=payload,
        **kwargs,
    )
    pkt.calculate_crcs()
    return pkt


create_valid_cip_safety_tsn_packet = create_valid_tsn_safety_packet


# ============================================================================
# 8. Main Protocol Engine (ILogicUnit)
# ============================================================================

class CIPSafetyTSNEngine(ILogicUnit):
    """Industrial ODVA CIP Safety Time-Sensitive Networking (TSN) Protocol Engine.

    Implements IEEE 802.1Qbv Time-Aware Shaper (TAS) Gate Control List (GCL) windowing,
    IEEE 802.1Qbu frame preemption logic, time-sync jitter watchdog (< 100 ns),
    dual CRC-S1/S2 checking, and Horner OCS register bindings %R2200..%R2207 and %M513..%M514.
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        cycle_time_us: int = NOMINAL_TSN_CYCLE_TIME_US,
        schedule_offset_us: int = NOMINAL_TSN_SCHEDULE_OFFSET_US,
        express_duration_us: int = DEFAULT_EXPRESS_DURATION_US,
        guard_band_duration_us: int = DEFAULT_GUARD_BAND_DURATION_US,
        jitter_ns: int = NOMINAL_TSN_MAX_JITTER_NS,
        preemption_count: int = NOMINAL_TSN_PREEMPTION_COUNT,
        express_packet_count: int = NOMINAL_TSN_EXPRESS_PACKET_COUNT,
        pcp: int = NOMINAL_TSN_PCP,
        safe_class: int = NOMINAL_TSN_SAFE_CLASS,
        flow_priority: Optional[int] = None,
        auto_activate: bool = True,
        initial_gate_state: Optional[TSNGateState] = None,
        **kwargs: Any,
    ) -> None:
        self.register_table: Optional[RegisterTable] = register_table
        self._auto_sync: bool = True
        self.is_active: bool = bool(auto_activate)

        self._cycle_time_us: int = int(cycle_time_us)
        self._schedule_offset_us: int = int(schedule_offset_us)
        self._express_duration_us: int = int(express_duration_us)
        self._guard_band_duration_us: int = int(guard_band_duration_us)

        self._jitter_ns: int = int(jitter_ns)
        self._preemption_count: int = int(preemption_count)
        self._express_packet_count: int = int(express_packet_count)

        self._pcp: int = int(pcp)
        self._safe_class: int = int(safe_class)
        if flow_priority is not None:
            self._flow_priority: int = int(flow_priority)
        else:
            self._flow_priority = (self._pcp << 8) | (self._safe_class & 0xFF)

        self._diagnostic_code: DiagnosticCode = DiagnosticCode.OK
        self._schedule_synced: bool = bool(auto_activate)
        self._interlock_tripped: bool = False

        self._current_time_us: float = float(self._schedule_offset_us) if auto_activate else 0.0
        self._cycles_count: int = 0
        self.packets_transmitted: int = 0
        self.packets_received: int = 0

        if initial_gate_state is not None:
            self._gate_state: TSNGateState = TSNGateState(initial_gate_state)
        elif auto_activate:
            self._gate_state = self.evaluate_gate_state_at_time(self._current_time_us)
        else:
            self._gate_state = TSNGateState.CLOSED

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    # ------------------------------------------------------------------------
    # Properties (ILogicUnit Compliance)
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        """ILogicUnit Unique Identifier."""
        return "CIPSafetyTSNEngine"

    @property
    def priority(self) -> int:
        """Execution priority (lower runs earlier)."""
        return 10

    @property
    def is_enabled(self) -> bool:
        """Whether unit participates in cyclic scan."""
        return self.is_active

    @property
    def gate_state(self) -> TSNGateState:
        """Current TSN Gate State mapped to %R2200."""
        return self._gate_state

    @gate_state.setter
    def gate_state(self, val: Union[TSNGateState, int]) -> None:
        self._gate_state = TSNGateState(int(val))
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def state(self) -> TSNGateState:
        """Alias for gate_state."""
        return self._gate_state

    @state.setter
    def state(self, val: Union[TSNGateState, int]) -> None:
        self.gate_state = val

    @property
    def safety_state(self) -> TSNGateState:
        """Alias for gate_state."""
        return self._gate_state

    @safety_state.setter
    def safety_state(self, val: Union[TSNGateState, int]) -> None:
        self.gate_state = val

    @property
    def cycle_time_us(self) -> int:
        """TSN cycle time in microseconds mapped to %R2201."""
        return self._cycle_time_us

    @cycle_time_us.setter
    def cycle_time_us(self, val: int) -> None:
        self._cycle_time_us = int(val)
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def schedule_offset_us(self) -> int:
        """Scheduled express window offset in microseconds mapped to %R2202."""
        return self._schedule_offset_us

    @schedule_offset_us.setter
    def schedule_offset_us(self, val: int) -> None:
        self._schedule_offset_us = int(val)
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def max_jitter_ns(self) -> int:
        """Max time-sync jitter in nanoseconds mapped to %R2203."""
        return self._jitter_ns

    @max_jitter_ns.setter
    def max_jitter_ns(self, val: int) -> None:
        self._jitter_ns = int(val)
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def jitter_ns(self) -> int:
        """Alias for max_jitter_ns."""
        return self._jitter_ns

    @jitter_ns.setter
    def jitter_ns(self, val: int) -> None:
        self.max_jitter_ns = val

    @property
    def preemption_count(self) -> int:
        """Cumulative IEEE 802.1Qbu preemption count mapped to %R2204."""
        return self._preemption_count

    @preemption_count.setter
    def preemption_count(self, val: int) -> None:
        self._preemption_count = int(val)
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def express_packet_count(self) -> int:
        """Cumulative express safety packet count mapped to %R2205."""
        return self._express_packet_count

    @express_packet_count.setter
    def express_packet_count(self, val: int) -> None:
        self._express_packet_count = int(val)
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def transmit_sequence(self) -> int:
        """Alias for express_packet_count mapped to %R2205 / %R2206."""
        return self._express_packet_count

    @transmit_sequence.setter
    def transmit_sequence(self, val: int) -> None:
        self.express_packet_count = val

    @property
    def flow_priority(self) -> int:
        """TSN Flow Priority (PCP=7, Safe Class 0x39) mapped to %R2206."""
        return self._flow_priority

    @flow_priority.setter
    def flow_priority(self, val: int) -> None:
        self._flow_priority = int(val)
        if val <= 7:
            self._pcp = val
        else:
            self._pcp = (val >> 8) & 0x07
            self._safe_class = val & 0xFF
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def pcp(self) -> int:
        """VLAN Priority Code Point (PCP = 7)."""
        return self._pcp

    @property
    def safe_class(self) -> int:
        """CIP Safety Class ID (0x39)."""
        return self._safe_class

    @property
    def diagnostic_code(self) -> DiagnosticCode:
        """Diagnostic code mapped to %R2207."""
        return self._diagnostic_code

    @diagnostic_code.setter
    def diagnostic_code(self, val: Union[DiagnosticCode, int]) -> None:
        self._diagnostic_code = DiagnosticCode(int(val))
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def schedule_synced(self) -> bool:
        """TSN schedule synced coil mapped to %M513."""
        return self._schedule_synced

    @schedule_synced.setter
    def schedule_synced(self, val: bool) -> None:
        self._schedule_synced = bool(val)
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def interlock_tripped(self) -> bool:
        """TSN safety interlock tripped coil mapped to %M514."""
        return self._interlock_tripped

    @interlock_tripped.setter
    def interlock_tripped(self, val: bool) -> None:
        self._interlock_tripped = bool(val)
        if self._auto_sync and self.register_table is not None:
            self.sync_to_registers(self.register_table)

    @property
    def is_healthy(self) -> bool:
        """Whether TSN schedule is synchronized and untripped."""
        return (
            self._schedule_synced
            and not self._interlock_tripped
            and self._diagnostic_code == DiagnosticCode.OK
            and self._gate_state != TSNGateState.FAILSAFE_CLOSED
        )

    @property
    def link_healthy(self) -> bool:
        """Alias for is_healthy."""
        return self.is_healthy

    @property
    def is_tripped(self) -> bool:
        """Whether safety interlock is latched tripped."""
        return self._interlock_tripped

    @property
    def safe_stop_tripped(self) -> bool:
        """Alias for interlock_tripped."""
        return self._interlock_tripped

    @property
    def is_safe_stop_tripped(self) -> bool:
        """Alias for interlock_tripped."""
        return self._interlock_tripped

    @property
    def current_time_us(self) -> float:
        """Current TSN time in microseconds."""
        return self._current_time_us

    @property
    def cycles_count(self) -> int:
        """Total completed simulation cycles."""
        return self._cycles_count

    @property
    def cycle_count(self) -> int:
        """Alias for cycles_count."""
        return self._cycles_count

    # ------------------------------------------------------------------------
    # IEEE 802.1Qbv Gate Control List (GCL) Windowing
    # ------------------------------------------------------------------------

    def evaluate_gate_state_at_time(self, time_us: float) -> TSNGateState:
        """Determine IEEE 802.1Qbv gate state at a specific time within TSN cycle."""
        if self._interlock_tripped:
            return TSNGateState.FAILSAFE_CLOSED
        if not self._schedule_synced:
            return TSNGateState.CLOSED

        t = time_us % self._cycle_time_us
        guard_start = (self._schedule_offset_us - self._guard_band_duration_us) % self._cycle_time_us
        express_start = self._schedule_offset_us % self._cycle_time_us
        express_end = (self._schedule_offset_us + self._express_duration_us) % self._cycle_time_us

        # Check guard band window
        if guard_start < express_start:
            if guard_start <= t < express_start:
                return TSNGateState.GUARD_BAND_ACTIVE
        else:
            # Wrapped over cycle boundary
            if t >= guard_start or t < express_start:
                return TSNGateState.GUARD_BAND_ACTIVE

        # Check express window
        if express_start < express_end:
            if express_start <= t < express_end:
                return TSNGateState.EXPRESS_SCHEDULED_OPEN
        else:
            # Wrapped over cycle boundary
            if t >= express_start or t < express_end:
                return TSNGateState.EXPRESS_SCHEDULED_OPEN

        # Preemptable window
        return TSNGateState.PREEMPTABLE_OPEN

    # ------------------------------------------------------------------------
    # Safety Interlocks & Fault Trips
    # ------------------------------------------------------------------------

    def trip_fault(
        self,
        code: Union[DiagnosticCode, int],
        details: Optional[str] = None,
    ) -> None:
        """Latch safety interlock trip with diagnostic code and transition to FAILSAFE_CLOSED."""
        self._diagnostic_code = DiagnosticCode(code)
        self._gate_state = TSNGateState.FAILSAFE_CLOSED
        self._schedule_synced = False
        self._interlock_tripped = True
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def trip_schedule_mismatch(self, details: Optional[str] = None) -> None:
        """Trip 0xEE31 SCHEDULE_MISMATCH_TRIP."""
        self.trip_fault(DiagnosticCode.SCHEDULE_MISMATCH_TRIP, details or "Schedule mismatch detected")

    def trip_jitter_exceeded(self, details: Optional[str] = None) -> None:
        """Trip 0xEE32 JITTER_EXCEEDED_TRIP."""
        self.trip_fault(DiagnosticCode.JITTER_EXCEEDED_TRIP, details or "Time-sync jitter exceeded limit")

    def trip_guard_band_violation(self, details: Optional[str] = None) -> None:
        """Trip 0xEE33 GUARD_BAND_VIOLATION."""
        self.trip_fault(DiagnosticCode.GUARD_BAND_VIOLATION, details or "Guard band transmission violation")

    def trip_preemption_fail(self, details: Optional[str] = None) -> None:
        """Trip 0xEE34 PREEMPTION_FAIL_TRIP."""
        self.trip_fault(DiagnosticCode.PREEMPTION_FAIL_TRIP, details or "Frame preemption failure")

    def reset(self) -> None:
        """Reset fault diagnostic code, clear interlock trip, and restore synchronized schedule."""
        self._diagnostic_code = DiagnosticCode.OK
        self._interlock_tripped = False
        self._schedule_synced = True
        self._jitter_ns = NOMINAL_TSN_MAX_JITTER_NS
        self._gate_state = self.evaluate_gate_state_at_time(self._current_time_us)
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    operator_reset = reset
    fault_reset = reset

    # ------------------------------------------------------------------------
    # Time-Sync Jitter Watchdog
    # ------------------------------------------------------------------------

    def update_jitter(self, jitter_ns: Union[int, float]) -> None:
        """Update measured time-sync jitter and verify watchdog threshold (< 100 ns)."""
        val = int(jitter_ns)
        self._jitter_ns = val
        if val >= MAX_ALLOWED_JITTER_NS:
            self.trip_jitter_exceeded(
                f"Time-sync jitter {val} ns exceeded watchdog threshold ({MAX_ALLOWED_JITTER_NS} ns)"
            )
        elif self.register_table is not None:
            self.sync_to_registers(self.register_table)

    # ------------------------------------------------------------------------
    # Packet Transmission & IEEE 802.1Qbu Preemption
    # ------------------------------------------------------------------------

    def create_packet(
        self,
        seq: Optional[int] = None,
        payload: Optional[bytes] = None,
        **kwargs: Any,
    ) -> CIPSafetyTSNPacket:
        """Factory generating valid CIPSafetyTSNPacket with calculated dual CRCs."""
        sequence_num = seq if seq is not None else ((self.packets_transmitted + 1) & 0xFFFF)
        pkt = CIPSafetyTSNPacket(
            sequence_primary=sequence_num,
            sequence_diversified=(~sequence_num) & 0xFFFF,
            cycle_count=self._cycles_count,
            timestamp_ns=int(self._current_time_us * 1000.0),
            pcp=self._pcp,
            class_id=self._safe_class,
            payload=payload if payload is not None else b"\x01\x00\x00\x00",
            **kwargs,
        )
        pkt.calculate_crcs()
        return pkt

    def send_express_packet(self, packet: Optional[CIPSafetyTSNPacket] = None) -> bool:
        """Transmit express CIP Safety packet during scheduled express open window."""
        pkt = packet or self.create_packet()
        return self.process_express_packet(pkt)

    def receive_express_packet(self, packet: CIPSafetyTSNPacket) -> bool:
        """Receive and validate incoming express CIP Safety packet."""
        return self.process_express_packet(packet)

    def process_express_packet(
        self,
        packet: CIPSafetyTSNPacket,
        current_time_us: Optional[float] = None,
    ) -> bool:
        """Process express safety packet with window check, dual CRC, and sequence verification."""
        check_time = current_time_us if current_time_us is not None else self._current_time_us
        active_state = self.evaluate_gate_state_at_time(check_time) if current_time_us is not None else self._gate_state

        # 1. Gate windowing verification (must be EXPRESS_SCHEDULED_OPEN)
        if active_state != TSNGateState.EXPRESS_SCHEDULED_OPEN:
            self.trip_schedule_mismatch(
                f"Express safety packet transmission outside express scheduled window (gate state: {active_state.name})"
            )
            return False

        # 2. Dual CRC-S1/S2 integrity verification
        if not packet.verify_crcs():
            self.trip_schedule_mismatch("CRC-S checksum corruption detected on express safety packet")
            return False

        # 3. Diversified sequence counter verification
        if not packet.verify_sequence():
            self.trip_schedule_mismatch("Diversified sequence counter mismatch on express safety packet")
            return False

        # Valid express packet successfully transmitted / received
        self.packets_transmitted += 1
        self.packets_received += 1
        self._express_packet_count += 1
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def transmit_preemptable_frame(
        self,
        frame: bytes,
        duration_us: int = 20,
        current_time_us: Optional[float] = None,
    ) -> bool:
        """Attempt to transmit a non-express / preemptable frame, checking guard band rules."""
        check_time = current_time_us if current_time_us is not None else self._current_time_us
        active_state = self.evaluate_gate_state_at_time(check_time) if current_time_us is not None else self._gate_state

        if active_state in (TSNGateState.GUARD_BAND_ACTIVE, TSNGateState.EXPRESS_SCHEDULED_OPEN):
            self.trip_guard_band_violation(
                f"Preemptable frame transmission attempted during {active_state.name}"
            )
            return False

        # If in PREEMPTABLE_OPEN, check if duration would encroach into guard band
        t = check_time % self._cycle_time_us
        guard_start = (self._schedule_offset_us - self._guard_band_duration_us) % self._cycle_time_us
        if t < guard_start:
            time_to_guard = guard_start - t
            if duration_us > time_to_guard:
                self.trip_guard_band_violation(
                    f"Preemptable frame duration ({duration_us} us) encroaches into guard band window"
                )
                return False

        return True

    def preempt_frame(self, frame: bytes, fragment_size: int = 64) -> Tuple[bytes, bytes]:
        """Perform IEEE 802.1Qbu frame preemption by fragmenting preemptable frame."""
        if len(frame) < MIN_PREEMPTABLE_FRAME_LEN:
            self.trip_preemption_fail(
                f"Frame size {len(frame)} bytes is below minimum {MIN_PREEMPTABLE_FRAME_LEN} bytes for IEEE 802.1Qbu preemption"
            )
            raise TSNPreemptionFailError(f"Frame length {len(frame)} too short for preemption")

        frag_len = min(max(fragment_size, MIN_PREEMPTABLE_FRAME_LEN // 2), len(frame) - 1)
        part1 = frame[:frag_len]
        part2 = frame[frag_len:]
        self._preemption_count += 1
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return part1, part2

    def simulate_preemption_failure(self, details: Optional[str] = None) -> None:
        """Simulate hardware or queue preemption failure, tripping 0xEE34."""
        self.trip_preemption_fail(details or "Simulated hardware preemption failure")

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: RegisterTable,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize internal engine state to Horner OCS %R2200..%R2207 and %M513..%M514."""
        # %R2200: REG_TSN_SAFETY_GATE_STATE (0..4)
        safe_write_word(reg_table, REG_TSN_SAFETY_GATE_STATE, int(self._gate_state), privilege=privilege)

        # %R2201: REG_TSN_CYCLE_TIME_US (nominal 1000)
        safe_write_word(reg_table, REG_TSN_CYCLE_TIME_US, int(self._cycle_time_us), privilege=privilege)

        # %R2202: REG_TSN_SCHEDULE_OFFSET_US (nominal 250)
        safe_write_word(reg_table, REG_TSN_SCHEDULE_OFFSET_US, int(self._schedule_offset_us), privilege=privilege)

        # %R2203: REG_TSN_MAX_JITTER_NS (nominal 45)
        safe_write_word(reg_table, REG_TSN_MAX_JITTER_NS, int(self._jitter_ns), privilege=privilege)

        # %R2204: REG_TSN_PREEMPTION_COUNT (nominal 0)
        safe_write_word(reg_table, REG_TSN_PREEMPTION_COUNT, int(self._preemption_count), privilege=privilege)

        # %R2205: REG_TSN_EXPRESS_PACKET_COUNT (nominal 100)
        safe_write_word(reg_table, REG_TSN_EXPRESS_PACKET_COUNT, int(self._express_packet_count), privilege=privilege)

        # %R2206: REG_TSN_SAFETY_FLOW_PRIORITY (PCP = 7, Safe Class 0x39 -> 0x0739)
        safe_write_word(reg_table, REG_TSN_SAFETY_FLOW_PRIORITY, int(self._flow_priority), privilege=privilege)

        # %R2207: REG_TSN_SAFETY_DIAGNOSTIC_CODE (0x0000, 0xEE31..0xEE34)
        safe_write_word(reg_table, REG_TSN_SAFETY_DIAGNOSTIC_CODE, int(self._diagnostic_code), privilege=privilege)

        # %M513: COIL_TSN_SCHEDULE_SYNCED (BOOL)
        safe_write_bit(reg_table, COIL_TSN_SCHEDULE_SYNCED, bool(self._schedule_synced), privilege=privilege)

        # %M514: COIL_TSN_SAFETY_INTERLOCK_TRIPPED (BOOL)
        safe_write_bit(reg_table, COIL_TSN_SAFETY_INTERLOCK_TRIPPED, bool(self._interlock_tripped), privilege=privilege)

    # ------------------------------------------------------------------------
    # ILogicUnit Cyclic Execution
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.001, context: Optional[ScanContext] = None) -> None:
        """Deterministic scan step: advance TSN cycle time and update GCL gate state."""
        dt_us = dt * 1_000_000.0
        self._current_time_us += dt_us
        self._cycles_count += 1

        if not self._interlock_tripped and self._schedule_synced:
            # Jitter watchdog verification
            if self._jitter_ns >= MAX_ALLOWED_JITTER_NS:
                self.trip_jitter_exceeded(
                    f"Time-sync jitter {self._jitter_ns} ns exceeded limit ({MAX_ALLOWED_JITTER_NS} ns)"
                )
                return

            self._gate_state = self.evaluate_gate_state_at_time(self._current_time_us)

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def step(self, dt: float = 0.001, context: Optional[ScanContext] = None) -> None:
        """Alias for scan_step."""
        self.scan_step(dt, context)

    def execute(self, context: Optional[ScanContext] = None) -> None:
        """ILogicUnit execute method invoked during simulation scan Phase 2."""
        dt = 0.001
        if context is not None:
            dt = getattr(context, "dt_s", None) or (getattr(context, "dt_ms", 1.0) / 1000.0)
        self.scan_step(dt, context)


CipSafetyTsnEngine = CIPSafetyTSNEngine
CIPSafetyTsnEngine = CIPSafetyTSNEngine
CipSafetyTSNEngine = CIPSafetyTSNEngine
CIP_SAFETY_TSN_ENGINE = CIPSafetyTSNEngine
TSNEngine = CIPSafetyTSNEngine
TsnEngine = CIPSafetyTSNEngine
CIPSafetyTSNProtocolEngine = CIPSafetyTSNEngine
CIPTsnSafetyEngine = CIPSafetyTSNEngine
CipTsnSafetyEngine = CIPSafetyTSNEngine


# ============================================================================
# 9. Deterministic 10-Stage Verification Suite
# ============================================================================

def run_cip_safety_tsn_verification(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W259",
) -> Dict[str, Any]:
    """Execute complete deterministic 10-stage verification suite.

    Returns strict 4-state contract JSON evidence.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Protocol Constants, Register Mappings & Diagnostic Codes
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s1_pass = (
        CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        and NOMINAL_TSN_CYCLE_TIME_US == 1000
        and NOMINAL_TSN_SCHEDULE_OFFSET_US == 250
        and NOMINAL_TSN_MAX_JITTER_NS == 45
        and MAX_ALLOWED_JITTER_NS == 100
        and NOMINAL_TSN_PREEMPTION_COUNT == 0
        and NOMINAL_TSN_EXPRESS_PACKET_COUNT == 100
        and NOMINAL_TSN_PCP == 7
        and NOMINAL_TSN_SAFE_CLASS == 0x39
        and REG_TSN_SAFETY_GATE_STATE == "%R2200"
        and REG_TSN_CYCLE_TIME_US == "%R2201"
        and REG_TSN_SCHEDULE_OFFSET_US == "%R2202"
        and REG_TSN_MAX_JITTER_NS == "%R2203"
        and REG_TSN_PREEMPTION_COUNT == "%R2204"
        and REG_TSN_EXPRESS_PACKET_COUNT == "%R2205"
        and REG_TSN_SAFETY_FLOW_PRIORITY == "%R2206"
        and REG_TSN_SAFETY_DIAGNOSTIC_CODE == "%R2207"
        and COIL_TSN_SCHEDULE_SYNCED == "%M513"
        and COIL_TSN_SAFETY_INTERLOCK_TRIPPED == "%M514"
        and TSNGateState.CLOSED == 0
        and TSNGateState.PREEMPTABLE_OPEN == 1
        and TSNGateState.EXPRESS_SCHEDULED_OPEN == 2
        and TSNGateState.GUARD_BAND_ACTIVE == 3
        and TSNGateState.FAILSAFE_CLOSED == 4
        and DiagnosticCode.OK == 0x0000
        and DiagnosticCode.SCHEDULE_MISMATCH_TRIP == 0xEE31
        and DiagnosticCode.JITTER_EXCEEDED_TRIP == 0xEE32
        and DiagnosticCode.GUARD_BAND_VIOLATION == 0xEE33
        and DiagnosticCode.PREEMPTION_FAIL_TRIP == 0xEE34
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "Protocol_Constants_Register_Mappings_And_Diagnostics",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified all %R2200..%R2207, %M513..%M514, TSNGateState (0..4), and DiagnosticCode (0x0000, 0xEE31..0xEE34).",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Dual CRC-S1 (0x5935) / CRC-S2 (0x755B) and Frame Container Integrity
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    pkt_s2 = create_valid_tsn_safety_packet(sequence_primary=10, payload=b"\xCA\xFE\xBA\xBE")
    s2_valid_before = pkt_s2.verify_crcs() and pkt_s2.verify_sequence()

    # Verify bit mutation causes CRC failure
    pkt_s2.mutate_bit(byte_offset=0, bit_pos=0)
    s2_corrupt_detected = not pkt_s2.verify_crcs()

    # Verify diversified sequence counter inversion
    s2_seq_inv = (pkt_s2.sequence_diversified == ((~10) & 0xFFFF))

    s2_pass = s2_valid_before and s2_corrupt_detected and s2_seq_inv
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "Dual_CRC_S_And_Diversified_Sequence_Integrity",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified CRC-S1 (poly 0x5935), CRC-S2 (poly 0x755B), inverted sequence, and single-bit corruption detection.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: IEEE 802.1Qbv GCL Windowing Progression
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    engine_s3 = CIPSafetyTSNEngine(auto_activate=True)
    # schedule_offset = 250 us, guard_band = 50 us (200..250), express = 250 us (250..500)
    g_pre1 = engine_s3.evaluate_gate_state_at_time(100.0)   # 100 us -> PREEMPTABLE_OPEN
    g_gb = engine_s3.evaluate_gate_state_at_time(220.0)     # 220 us -> GUARD_BAND_ACTIVE
    g_exp = engine_s3.evaluate_gate_state_at_time(300.0)    # 300 us -> EXPRESS_SCHEDULED_OPEN
    g_pre2 = engine_s3.evaluate_gate_state_at_time(600.0)   # 600 us -> PREEMPTABLE_OPEN

    s3_pass = (
        g_pre1 == TSNGateState.PREEMPTABLE_OPEN
        and g_gb == TSNGateState.GUARD_BAND_ACTIVE
        and g_exp == TSNGateState.EXPRESS_SCHEDULED_OPEN
        and g_pre2 == TSNGateState.PREEMPTABLE_OPEN
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "IEEE_802_1Qbv_GCL_Windowing_Progression",
        "passed": bool(s3_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified cyclic progression across PREEMPTABLE_OPEN, GUARD_BAND_ACTIVE, and EXPRESS_SCHEDULED_OPEN.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Time-Sync Jitter Watchdog Surveillance (< 100 ns)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s4 = RegisterTable()
    engine_s4 = CIPSafetyTSNEngine(register_table=rt_s4, auto_activate=True)

    # Nominal jitter 45 ns passes cleanly
    engine_s4.update_jitter(45)
    s4_nom_pass = (
        engine_s4.diagnostic_code == DiagnosticCode.OK
        and not engine_s4.interlock_tripped
        and engine_s4.schedule_synced
    )

    # Exceeding 100 ns trips 0xEE32
    engine_s4.update_jitter(105)
    s4_trip_pass = (
        engine_s4.diagnostic_code == DiagnosticCode.JITTER_EXCEEDED_TRIP
        and engine_s4.gate_state == TSNGateState.FAILSAFE_CLOSED
        and engine_s4.interlock_tripped
        and not engine_s4.schedule_synced
        and rt_s4.read_word("%R2200") == 4
        and rt_s4.read_uword("%R2207") == 0xEE32
        and rt_s4.read_bit("%M514") is True
        and rt_s4.read_bit("%M513") is False
    )

    # Operator reset restores nominal state
    engine_s4.reset()
    s4_reset_pass = (
        engine_s4.diagnostic_code == DiagnosticCode.OK
        and not engine_s4.interlock_tripped
        and engine_s4.schedule_synced
        and rt_s4.read_uword("%R2207") == 0x0000
        and rt_s4.read_bit("%M514") is False
        and rt_s4.read_bit("%M513") is True
    )

    s4_pass = s4_nom_pass and s4_trip_pass and s4_reset_pass
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "Time_Sync_Jitter_Watchdog_Surveillance",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified jitter watchdog trip at 105 ns (0xEE32 JITTER_EXCEEDED_TRIP), failsafe transition, and operator reset.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Schedule Mismatch Surveillance (0xEE31)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s5 = RegisterTable()
    engine_s5 = CIPSafetyTSNEngine(register_table=rt_s5, auto_activate=True)

    # Force gate state to PREEMPTABLE_OPEN (outside express window)
    engine_s5.gate_state = TSNGateState.PREEMPTABLE_OPEN
    pkt_s5 = engine_s5.create_packet()
    res_mismatch = engine_s5.process_express_packet(pkt_s5)

    s5_pass = (
        res_mismatch is False
        and engine_s5.diagnostic_code == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        and engine_s5.gate_state == TSNGateState.FAILSAFE_CLOSED
        and engine_s5.interlock_tripped
        and not engine_s5.schedule_synced
        and rt_s5.read_uword("%R2207") == 0xEE31
        and rt_s5.read_bit("%M514") is True
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "Schedule_Mismatch_Surveillance",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified 0xEE31 SCHEDULE_MISMATCH_TRIP on transmission outside scheduled express window.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Guard Band Violation Surveillance (0xEE33)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s6 = RegisterTable()
    engine_s6 = CIPSafetyTSNEngine(register_table=rt_s6, auto_activate=True)

    # Force gate state to GUARD_BAND_ACTIVE
    engine_s6.gate_state = TSNGateState.GUARD_BAND_ACTIVE
    res_gb = engine_s6.transmit_preemptable_frame(b"preemptable_data_frame", duration_us=20)

    s6_pass = (
        res_gb is False
        and engine_s6.diagnostic_code == DiagnosticCode.GUARD_BAND_VIOLATION
        and engine_s6.gate_state == TSNGateState.FAILSAFE_CLOSED
        and engine_s6.interlock_tripped
        and not engine_s6.schedule_synced
        and rt_s6.read_uword("%R2207") == 0xEE33
        and rt_s6.read_bit("%M514") is True
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "Guard_Band_Violation_Surveillance",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified 0xEE33 GUARD_BAND_VIOLATION when preemptable frame attempts transmission during guard band.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: IEEE 802.1Qbu Frame Preemption Logic & Failure Trip (0xEE34)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s7 = RegisterTable()
    engine_s7 = CIPSafetyTSNEngine(register_table=rt_s7, auto_activate=True)

    # Successful preemption of large frame
    large_frame = b"A" * 128
    frag1, frag2 = engine_s7.preempt_frame(large_frame, fragment_size=64)
    s7_preempt_ok = (
        len(frag1) == 64
        and len(frag2) == 64
        and engine_s7.preemption_count == 1
        and rt_s7.read_word("%R2204") == 1
    )

    # Preemption failure on short frame (< 64 bytes)
    short_frame = b"SHORT"
    s7_caught_preempt_fail = False
    try:
        engine_s7.preempt_frame(short_frame)
    except TSNPreemptionFailError:
        s7_caught_preempt_fail = True
    except Exception:
        pass

    s7_trip_ok = (
        s7_caught_preempt_fail
        and engine_s7.diagnostic_code == DiagnosticCode.PREEMPTION_FAIL_TRIP
        and engine_s7.gate_state == TSNGateState.FAILSAFE_CLOSED
        and engine_s7.interlock_tripped
        and not engine_s7.schedule_synced
        and rt_s7.read_uword("%R2207") == 0xEE34
        and rt_s7.read_bit("%M514") is True
    )

    s7_pass = s7_preempt_ok and s7_trip_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "IEEE_802_1Qbu_Frame_Preemption_Logic_And_Failure_Trip",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified successful 802.1Qbu preemption fragmentation and 0xEE34 PREEMPTION_FAIL_TRIP for undersized frame.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Horner OCS Register Table Bit-Exact Synchronization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s8 = RegisterTable()
    engine_s8 = CIPSafetyTSNEngine(register_table=rt_s8, auto_activate=True)

    s8_nom = (
        rt_s8.read_word("%R2200") == 2
        and rt_s8.read_word("%R2201") == 1000
        and rt_s8.read_word("%R2202") == 250
        and rt_s8.read_word("%R2203") == 45
        and rt_s8.read_word("%R2204") == 0
        and rt_s8.read_word("%R2205") == 100
        and rt_s8.read_uword("%R2206") == 0x0739
        and rt_s8.read_uword("%R2207") == 0x0000
        and rt_s8.read_bit("%M513") is True
        and rt_s8.read_bit("%M514") is False
    )

    # Trip and test synchronization
    engine_s8.trip_fault(DiagnosticCode.SCHEDULE_MISMATCH_TRIP)
    s8_trip = (
        rt_s8.read_word("%R2200") == 4
        and rt_s8.read_uword("%R2207") == 0xEE31
        and rt_s8.read_bit("%M513") is False
        and rt_s8.read_bit("%M514") is True
    )

    # Operator reset
    engine_s8.reset()
    s8_reset = (
        rt_s8.read_word("%R2200") == 2
        and rt_s8.read_uword("%R2207") == 0x0000
        and rt_s8.read_bit("%M513") is True
        and rt_s8.read_bit("%M514") is False
    )

    s8_pass = s8_nom and s8_trip and s8_reset
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "Horner_OCS_Register_Table_Synchronization_And_Operator_Reset",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact %R2200..%R2207 and %M513..%M514 synchronization verified under SYSTEM privilege.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Pure IEC 61131-3 ST POU & Ladder Rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_valid = verify_cip_safety_tsn_pure_st()

    ladder_rejected = False
    ladder_sample = "PROGRAM Test VAR X: BOOL; END_VAR ---[ ]--- ( )--- END_PROGRAM"
    try:
        SecurityGuard.assert_pure_st_content(ladder_sample)
    except LadderForbiddenError:
        ladder_rejected = True
    except Exception:
        pass

    s9_pass = st_valid and ladder_rejected
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 9,
        "name": "Pure_ST_POU_Validation_And_Ladder_Rejection",
        "passed": bool(s9_pass),
        "timing_ms": round(t1, 3),
        "details": "STParser / SecurityGuard confirmed CipSafetyTsnSync POU validity; LadderForbiddenError intercepted.",
    })

    # ------------------------------------------------------------------------
    # Stage 10: ILogicUnit 100-Cycle Soak Simulation & Zero Memory Leak
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s10 = RegisterTable()
    engine_s10 = CIPSafetyTSNEngine(register_table=rt_s10, auto_activate=True)

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()
    soak_stable = True
    for cycle_i in range(1, 101):
        try:
            # Advance time by 1 ms (1000 us = 1 full TSN cycle)
            engine_s10.scan_step(0.001)
        except Exception:
            soak_stable = False
            break

    snapshot_after = tracemalloc.take_snapshot()
    stats = snapshot_after.compare_to(snapshot_before, "lineno")
    heap_growth_kb = sum(st.size_diff for st in stats if st.size_diff > 0) / 1024.0
    tracemalloc.stop()

    s10_pass = (
        soak_stable
        and engine_s10.cycles_count >= 100
        and heap_growth_kb < 100.0
        and rt_s10.read_word("%R2201") == 1000
        and rt_s10.read_uword("%R2207") == 0x0000
        and rt_s10.read_bit("%M513") is True
        and rt_s10.read_bit("%M514") is False
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 10,
        "name": "ILogicUnit_100_Cycle_Soak_Simulation_And_Heap_Boundedness",
        "passed": bool(s10_pass),
        "timing_ms": round(t1, 3),
        "details": f"100 scan cycles executed cleanly, heap growth {heap_growth_kb:.2f} KB (< 100 KB limit).",
    })

    # ------------------------------------------------------------------------
    # Aggregate Verification Result
    # ------------------------------------------------------------------------
    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    status = "success" if all_passed else "failed"
    error_code = None if all_passed else "ERR_STAGE_VERIFICATION_FAILED"
    details = (
        f"Wave {work_package} CIP Safety Over TSN Protocol Engine Verification PASSED ({stages_passed}/{total_stages} stages)."
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
            "protocol": "ODVA CIP Safety Over TSN (IEEE 802.1Qbv / IEEE 802.1Qbu)",
            "work_package": work_package,
            "classes": {
                "0x39": "Safety Supervisor Object",
                "0x3A": "Safety Validator Object",
                "0x3B": "Safety Connection Object",
            },
            "register_map": {
                "%R2200": "TSN Gate State (0..4)",
                "%R2201": "TSN Cycle Time (us)",
                "%R2202": "Schedule Offset (us)",
                "%R2203": "Max Time-Sync Jitter (ns)",
                "%R2204": "Cumulative Preemption Count",
                "%R2205": "Express Packet Count",
                "%R2206": "Safety Flow Priority (PCP=7, Safe Class 0x39)",
                "%R2207": "Safety Diagnostic Code",
                "%M513": "TSN Schedule Synced Coil",
                "%M514": "Safety Interlock Tripped Coil",
            },
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
    result = run_cip_safety_tsn_verification()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
