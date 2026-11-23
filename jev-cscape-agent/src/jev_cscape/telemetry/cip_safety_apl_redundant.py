"""Industrial ODVA CIP Safety Over Ethernet-APL Redundant Trunks Protocol Engine.

Work Package: W277 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019 / Ethernet-APL:
  - 10BASE-T1L Single Pair Ethernet operating at 10 Mb/s full-duplex over single balanced twisted-pair cabling.
  - Dual Redundant Trunks: Trunk A (Primary) and Trunk B (Secondary).
  - IEC 60079-47 (2-WISE: 2-Wire Intrinsically Safe Ethernet) for Zone 0 / Class I, Div 1 explosive atmospheres:
    - Loop voltage nominal: 12000 mV (12.0 V DC).
    - Intrinsic Safety (IS) permissible bounds: 9600 mV .. 15000 mV (9.6 V .. 15.0 V).
    - Under-voltage droop (< 9600 mV) trips fault:
      - Trunk A droop trips 0xEC01 (TRUNK_A_DROOP).
      - Trunk B droop trips 0xEC02 (TRUNK_B_DROOP).
      - Dual trunk failure trips 0xEC03 (DUAL_TRUNK_FAIL).
    - Over-voltage violation (> 15000 mV) also treated as Intrinsic Safety violation.
  - Failover Latency & Jitter Surveillance:
    - Nominal latency: < 2500 us (nominal 1200 us).
    - Maximum allowable failover switchover threshold: 2500 us (2.5 ms).
    - Switchover latency >= 2500 us trips fault 0xEC04 (SWITCHOVER_TIMEOUT).
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - Class 0x39: Safety Supervisor Object
  - Class 0x3A: Safety Validator Object
  - Class 0x3B: Safety Connection Object
  - Class 0x3E: Ethernet-APL Safety Object Class ID
  - Dual 16-bit Safety CRCs:
    - CRC-S1: Generator polynomial 0x5935 (init 0xFFFF)
    - CRC-S2: Generator polynomial 0x755B (init 0xFFFF), computed over bitwise-inverted data
    - CRC status register (%R2385):
      - Bit0: Trunk A CRC OK (0x0001)
      - Bit1: Trunk B CRC OK (0x0002)
      - Bit2: Sequence Synced (0x0004)
      - Nominal status: 0x0007
  - Monotonic Rolling Sequence Tracking & Split-Brain Detection:
    - Trunk A rolling sequence (0..65535)
    - Trunk B rolling sequence (0..65535)
    - Divergence between Trunk A and Trunk B during dual tracking trips 0xEC05 (SPLIT_BRAIN_SYNC_LOSS).
- Horner OCS Memory Space:
  - Analog registers %R2380..%R2387:
    - %R2380: REG_CIP_SAFETY_REDUNDANT_STATE (0=TRUNK_A_ACTIVE, 1=TRUNK_B_ACTIVE, 2=DUAL_TRACKING, 3=SAFETY_FALLBACK_DEGRADED, 4=TRIP_SHUTDOWN)
    - %R2381: REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK (1=Trunk A, 2=Trunk B, 3=Both synchronized)
    - %R2382: REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV (nominal 12000 mV, IS bounds 9600..15000 mV)
    - %R2383: REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV (nominal 12000 mV, IS bounds 9600..15000 mV)
    - %R2384: REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT (0..65535)
    - %R2385: REG_CIP_SAFETY_REDUNDANT_CRC_STATUS (Bit0=Trunk A CRC OK, Bit1=Trunk B CRC OK, Bit2=Seq Synced, 0x0007 nominal)
    - %R2386: REG_CIP_SAFETY_REDUNDANT_LATENCY_US (nominal < 2500 us)
    - %R2387: REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE (0x0000=OK, 0xEC01..0xEC05)
  - Discrete coils %M555..%M556:
    - %M555: COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED (BOOL, True when state in (0, 1, 2))
    - %M556: COIL_CIP_SAFETY_REDUNDANT_TRIPPED (BOOL, True when state in (3, 4))
- Implements ILogicUnit interface with scan_step(dt, context), step(dt, context), execute(context), and reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).parse().
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.
- Deterministic 9-stage verification suite run_cip_safety_apl_redundant_verification().
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
# 1. Constants & Protocol Definitions (ODVA CIP Safety Volume 5 / IEEE 802.3cg / 2-WISE)
# ============================================================================

CIP_SAFETY_SUPERVISOR_CLASS_ID: int = 0x39          # Safety Supervisor Object
CIP_SAFETY_VALIDATOR_CLASS_ID: int = 0x3A           # Safety Validator Object
CIP_SAFETY_CONNECTION_CLASS_ID: int = 0x3B          # Safety Connection Object
CIP_SAFETY_APL_CLASS_ID: int = 0x3E                 # Ethernet-APL Safety Object Class ID
CIP_SAFETY_REDUNDANT_CLASS_ID: int = 0x3E

# Nominal Voltage & Latency Parameters
NOMINAL_VOLTAGE_MV: int = 12000                     # 12000 mV (12.0 V DC nominal)
DEFAULT_VOLTAGE_MV: int = 12000
MIN_IS_VOLTAGE_MV: int = 9600                       # 9600 mV lower 2-WISE IS bound
MAX_IS_VOLTAGE_MV: int = 15000                      # 15000 mV upper 2-WISE IS bound

NOMINAL_LATENCY_US: int = 1200                      # 1200 us nominal latency
DEFAULT_LATENCY_US: int = 1200
MAX_SWITCHOVER_LATENCY_US: int = 2500               # 2500 us maximum failover switchover latency
DEFAULT_WATCHDOG_TIMEOUT_US: float = 2500.0         # 2500 us watchdog timeout
DEFAULT_WATCHDOG_TIMEOUT_MS: float = 2.5

DEFAULT_DEVICE_ID: int = 0x1A2B                     # Safe Redundant APL Device ID
DEFAULT_SAFETY_NETWORK_NUMBER: int = 0x9876         # Nominal Safety Network Number
DEFAULT_SNN: int = 0x9876

# CRC Polynomials and Seeds (ODVA CIP Safety Volume 5)
CIP_SAFETY_CRC_S1_POLY: int = 0x5935                # CRC-S1 generator polynomial
CIP_SAFETY_CRC_S2_POLY: int = 0x755B                # CRC-S2 generator polynomial
CRC_S1_POLY: int = 0x5935
CRC_S2_POLY: int = 0x755B
CIP_SAFETY_CRC_INIT: int = 0xFFFF                   # CRC-S initial seed
CRC_S_INIT: int = 0xFFFF

# Redundant CRC Status Bitmasks (%R2385)
CRC_STATUS_TRUNK_A_OK: int = 0x0001                 # Bit0: Trunk A CRC OK
CRC_STATUS_TRUNK_B_OK: int = 0x0002                 # Bit1: Trunk B CRC OK
CRC_STATUS_SEQ_SYNCED: int = 0x0004                 # Bit2: Sequence Synced
CRC_STATUS_NOMINAL: int = 0x0007                    # 0x0007 (Bit0 | Bit1 | Bit2)

# Canonical Register Table Mapping (%R2380..%R2387)
REG_CIP_SAFETY_REDUNDANT_STATE: str = "%R2380"
REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK: str = "%R2381"
REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV: str = "%R2382"
REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV: str = "%R2383"
REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT: str = "%R2384"
REG_CIP_SAFETY_REDUNDANT_CRC_STATUS: str = "%R2385"
REG_CIP_SAFETY_REDUNDANT_LATENCY_US: str = "%R2386"
REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE: str = "%R2387"

# Canonical Discrete Coils Mapping (%M555..%M556)
COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED: str = "%M555"
COIL_CIP_SAFETY_REDUNDANT_TRIPPED: str = "%M556"

# Register and Coil Aliases
REG_REDUNDANT_STATE: str = "%R2380"
REG_REDUNDANT_ACTIVE_TRUNK: str = "%R2381"
REG_REDUNDANT_TRUNK_A_VOLTAGE_MV: str = "%R2382"
REG_REDUNDANT_TRUNK_B_VOLTAGE_MV: str = "%R2383"
REG_REDUNDANT_SWITCHOVER_COUNT: str = "%R2384"
REG_REDUNDANT_CRC_STATUS: str = "%R2385"
REG_REDUNDANT_LATENCY_US: str = "%R2386"
REG_REDUNDANT_DIAGNOSTIC_CODE: str = "%R2387"

COIL_REDUNDANT_ESTABLISHED: str = "%M555"
COIL_REDUNDANT_TRIPPED: str = "%M556"


# ============================================================================
# 2. Enums and Diagnostic Codes
# ============================================================================

class CipSafetyRedundantState(IntEnum):
    """ODVA CIP Safety Over Ethernet-APL Redundant State Machine (%R2380).

    States:
    - 0: TRUNK_A_ACTIVE (Primary Trunk A active)
    - 1: TRUNK_B_ACTIVE (Secondary Trunk B active)
    - 2: DUAL_TRACKING (Dual trunks active and synchronized)
    - 3: SAFETY_FALLBACK_DEGRADED (Single trunk degraded or loss of redundancy)
    - 4: TRIP_SHUTDOWN (Safety trip shutdown, fail-closed safe state)
    """
    TRUNK_A_ACTIVE = 0
    TRUNK_B_ACTIVE = 1
    DUAL_TRACKING = 2
    SAFETY_FALLBACK_DEGRADED = 3
    TRIP_SHUTDOWN = 4

    # Aliases
    TrunkAActive = 0
    TrunkBActive = 1
    DualTracking = 2
    SafetyFallbackDegraded = 3
    TripShutdown = 4
    DEGRADED = 3
    SHUTDOWN = 4
    TRIPPED = 4


class ActiveTrunkId(IntEnum):
    """Active Trunk Identifier (%R2381).

    Trunk Identifiers:
    - 1: TRUNK_A (Trunk A active)
    - 2: TRUNK_B (Trunk B active)
    - 3: BOTH_SYNCHRONIZED (Both trunks actively synchronized)
    """
    TRUNK_A = 1
    TRUNK_B = 2
    BOTH_SYNCHRONIZED = 3

    # Aliases
    TrunkA = 1
    TrunkB = 2
    BothSynchronized = 3
    BOTH = 3


class CipSafetyRedundantDiagnosticCode(IntEnum):
    """Integer diagnostic code enum supporting signed/unsigned 16-bit comparisons (%R2387).

    Diagnostic Codes:
    - 0x0000: OK (Dual redundant APL safe link operational)
    - 0xEC01: TRUNK_A_DROOP (Trunk A loop voltage droop < 9600 mV or > 15000 mV)
    - 0xEC02: TRUNK_B_DROOP (Trunk B loop voltage droop < 9600 mV or > 15000 mV)
    - 0xEC03: DUAL_TRUNK_FAIL (Both Trunk A and Trunk B failed)
    - 0xEC04: SWITCHOVER_TIMEOUT (Failover switchover latency >= 2500 us)
    - 0xEC05: SPLIT_BRAIN_SYNC_LOSS (Trunk A and Trunk B sequence desynchronization)
    """
    OK = 0x0000
    TRUNK_A_DROOP = 0xEC01
    TRUNK_B_DROOP = 0xEC02
    DUAL_TRUNK_FAIL = 0xEC03
    SWITCHOVER_TIMEOUT = 0xEC04
    SPLIT_BRAIN_SYNC_LOSS = 0xEC05

    # Aliases
    TrunkADroop = 0xEC01
    TrunkBDroop = 0xEC02
    DualTrunkFail = 0xEC03
    SwitchoverTimeout = 0xEC04
    SplitBrainSyncLoss = 0xEC05

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
        return f"CipSafetyRedundantDiagnosticCode.{self.name}(0x{int(self) & 0xFFFF:04X})"


# Module-level aliases
DiagnosticCode = CipSafetyRedundantDiagnosticCode
DIAG_OK = CipSafetyRedundantDiagnosticCode.OK
DIAG_TRUNK_A_DROOP = CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP
DIAG_TRUNK_B_DROOP = CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP
DIAG_DUAL_TRUNK_FAIL = CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL
DIAG_SWITCHOVER_TIMEOUT = CipSafetyRedundantDiagnosticCode.SWITCHOVER_TIMEOUT
DIAG_SPLIT_BRAIN_SYNC_LOSS = CipSafetyRedundantDiagnosticCode.SPLIT_BRAIN_SYNC_LOSS


# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class CipSafetyAplRedundantError(Exception):
    """Base exception for all CIP Safety Over Ethernet-APL Redundant violations."""
    pass


class TrunkDroopError(CipSafetyAplRedundantError):
    """Raised when trunk voltage droops below 2-WISE lower limit (< 9600 mV) (0xEC01/0xEC02)."""
    pass


class DualTrunkFailError(CipSafetyAplRedundantError):
    """Raised when both redundant trunks fail simultaneously (0xEC03)."""
    pass


class SwitchoverTimeoutError(CipSafetyAplRedundantError):
    """Raised when failover switchover latency exceeds 2500 us (0xEC04)."""
    pass


class SplitBrainSyncLossError(CipSafetyAplRedundantError):
    """Raised when sequence counters desynchronize between Trunk A and Trunk B (0xEC05)."""
    pass


class TrunkCrcFaultError(CipSafetyAplRedundantError):
    """Raised when safety CRC-S checksum corruption is detected on a trunk frame."""
    pass


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POU Definition
# ============================================================================

ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC: str = """PROGRAM ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC
VAR
    (* Horner OCS Mapped Registers (W277 - ODVA CIP Safety Over Ethernet-APL Redundant Trunks) *)
    RedundantState              AT %R2380 : INT;    (* 0=TRUNK_A_ACTIVE, 1=TRUNK_B_ACTIVE, 2=DUAL_TRACKING, 3=SAFETY_FALLBACK_DEGRADED, 4=TRIP_SHUTDOWN *)
    ActiveTrunk                 AT %R2381 : INT;    (* 1=Trunk A, 2=Trunk B, 3=Both synchronized *)
    TrunkAVoltageMv             AT %R2382 : INT;    (* Trunk A Voltage in mV (nominal 12000 mV, IS bounds 9600..15000 mV) *)
    TrunkBVoltageMv             AT %R2383 : INT;    (* Trunk B Voltage in mV (nominal 12000 mV, IS bounds 9600..15000 mV) *)
    SwitchoverCount             AT %R2384 : UINT;   (* Switchover count 0..65535 *)
    CrcStatus                   AT %R2385 : INT;    (* Bit0=Trunk A CRC OK, Bit1=Trunk B CRC OK, Bit2=Seq Synced, 0x0007 nominal *)
    FailoverLatencyUs           AT %R2386 : INT;    (* Latency in us (< 2500 us) *)
    DiagnosticCode              AT %R2387 : UINT;   (* Diagnostic code: 0x0000=OK, 0xEC01..0xEC05 *)

    (* Discrete Safety Coils *)
    LinkEstablished             AT %M555  : BOOL;   (* TRUE when RedundantState in (0, 1, 2) and healthy *)
    LinkTripped                 AT %M556  : BOOL;   (* TRUE when RedundantState in (3, 4) *)

    (* Internal Flags *)
    InternalHealthy             : BOOL;
END_VAR

IF (RedundantState >= 3) OR (DiagnosticCode <> 0) THEN
    LinkEstablished := FALSE;
    LinkTripped := TRUE;
    InternalHealthy := FALSE;
ELSIF (RedundantState <= 2) AND ((TrunkAVoltageMv >= 9600) OR (TrunkBVoltageMv >= 9600)) THEN
    LinkEstablished := TRUE;
    LinkTripped := FALSE;
    InternalHealthy := TRUE;
ELSE
    LinkEstablished := FALSE;
    LinkTripped := TRUE;
    InternalHealthy := FALSE;
END_IF;
END_PROGRAM
"""

CIP_SAFETY_APL_REDUNDANT_PURE_ST_POU: str = ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC
CIP_SAFETY_APL_REDUNDANT_SYNC_POU: str = ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC
CipSafetyAplRedundantSync: str = ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC


def verify_cip_safety_apl_redundant_pure_st(pou_text: Optional[str] = None) -> bool:
    """Validate pure IEC 61131-3 ST POU with SecurityGuard and STParser."""
    try:
        text = pou_text if pou_text is not None else ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC
        SecurityGuard.assert_pure_st_content(text)
        res = STParser.validate_code(text)
        if res.status != AgentStatus.SUCCESS:
            return False
        ast = STParser(pou_type=POUType.PROGRAM).parse(text)
        if ast.pou_type != POUType.PROGRAM:
            return False

        if pou_text is None:
            required_registers: Set[str] = {
                "%R2380", "%R2381", "%R2382", "%R2383",
                "%R2384", "%R2385", "%R2386", "%R2387",
                "%M555", "%M556",
            }
            return required_registers.issubset(set(ast.bound_registers))
        return True
    except Exception:
        return False


# ============================================================================
# 5. Checksum & Register Table Helper Functions
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


def compute_crc_s2(*args: Any, poly: int = CIP_SAFETY_CRC_S2_POLY, init: int = CIP_SAFETY_CRC_INIT, inverted: bool = False, **kwargs: Any) -> int:
    """Calculate 16-bit safety checksum CRC-S2 with generator polynomial 0x755B."""
    if len(args) == 1 and isinstance(args[0], (bytes, bytearray)):
        data = bytes(args[0])
    elif len(args) > 0 and all(isinstance(a, (bytes, bytearray)) for a in args):
        data = b"".join(bytes(a) for a in args)
    else:
        raise ValueError(f"Unsupported arguments to compute_crc_s2: {args}")

    if inverted or kwargs.get("invert", False):
        data = bytes(b ^ 0xFF for b in data)

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
# 6. Safety Frame Packet Structure & Dual CRC Verification
# ============================================================================

@dataclass
class CipSafeAplRedundantPacket:
    """ODVA CIP Safety Over Ethernet-APL redundant trunk cyclic packet.

    Encapsulates safe cyclical APL process data, trunk identification (Trunk A / B),
    monotonic rolling sequence numbers, 2-WISE loop voltage surveillance, latency telemetry,
    and dual CRC-S checksums (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B inverted).
    """
    device_id: int = DEFAULT_DEVICE_ID
    snn: int = DEFAULT_SNN
    trunk_id: ActiveTrunkId = ActiveTrunkId.TRUNK_A
    sequence: int = 1
    loop_voltage_mv: int = NOMINAL_VOLTAGE_MV
    latency_us: int = NOMINAL_LATENCY_US
    payload: bytes = b"\x01\x00\x00\x00"
    crc_s1: int = 0
    crc_s2: int = 0
    timestamp_us: float = 0.0

    @property
    def crc_status(self) -> int:
        """CRC Status: returns bitmask indicating CRC-S1 and CRC-S2 validity."""
        status = 0
        if self.crc_s1 == compute_crc_s1(self.serialize_for_crc_s1()):
            status |= 0x0001
        if self.crc_s2 == compute_crc_s2(self.serialize_for_crc_s2()):
            status |= 0x0002
        return status

    def serialize_for_crc_s1(self) -> bytes:
        """Serialize primary header, trunk ID, sequence, voltage, and payload for CRC-S1."""
        header = struct.pack(
            ">HHHHHI",
            self.device_id & 0xFFFF,
            self.snn & 0xFFFF,
            int(self.trunk_id) & 0xFFFF,
            self.sequence & 0xFFFF,
            self.loop_voltage_mv & 0xFFFF,
            min(0xFFFFFFFF, max(0, int(self.latency_us))),
        )
        return header + self.payload

    def serialize_for_crc_s2(self) -> bytes:
        """Serialize bitwise-inverted header and inverted payload for CRC-S2."""
        header = struct.pack(
            ">HHHHHI",
            (self.device_id ^ 0xFFFF) & 0xFFFF,
            (self.snn ^ 0xFFFF) & 0xFFFF,
            (int(self.trunk_id) ^ 0xFFFF) & 0xFFFF,
            (self.sequence ^ 0xFFFF) & 0xFFFF,
            (self.loop_voltage_mv ^ 0xFFFF) & 0xFFFF,
            min(0xFFFFFFFF, max(0, int(self.latency_us))) ^ 0xFFFFFFFF,
        )
        inv_payload = bytes(b ^ 0xFF for b in self.payload)
        return header + inv_payload

    def calculate_crcs(self) -> None:
        """Calculate and populate dual safety checksums CRC-S1 and CRC-S2."""
        self.crc_s1 = compute_crc_s1(self.serialize_for_crc_s1())
        self.crc_s2 = compute_crc_s2(self.serialize_for_crc_s2())

    populate_crcs = calculate_crcs

    def verify_crcs(self) -> bool:
        """Verify that stored CRC-S1 and CRC-S2 match computed checksums."""
        exp1 = compute_crc_s1(self.serialize_for_crc_s1())
        exp2 = compute_crc_s2(self.serialize_for_crc_s2())
        return (self.crc_s1 == exp1) and (self.crc_s2 == exp2)

    def mutate_bit(self, byte_offset: int = 0, bit_pos: int = 0) -> None:
        """Inject single-bit corruption into payload for deterministic testing."""
        ba = bytearray(self.payload)
        idx = byte_offset % len(ba)
        ba[idx] ^= (1 << (bit_pos % 8))
        self.payload = bytes(ba)


CIPSafeAPLRedundantPacket = CipSafeAplRedundantPacket
RedundantSafePacket = CipSafeAplRedundantPacket


def create_valid_redundant_packet(
    trunk_id: Union[ActiveTrunkId, int] = ActiveTrunkId.TRUNK_A,
    sequence: int = 1,
    loop_voltage_mv: int = NOMINAL_VOLTAGE_MV,
    latency_us: int = NOMINAL_LATENCY_US,
    device_id: int = DEFAULT_DEVICE_ID,
    snn: int = DEFAULT_SNN,
    payload: bytes = b"\x01\x00\x00\x00",
    **kwargs: Any,
) -> CipSafeAplRedundantPacket:
    """Factory creating valid redundant APL packet with calculated dual CRCs."""
    t_id = ActiveTrunkId(int(trunk_id)) if int(trunk_id) in (1, 2, 3) else ActiveTrunkId.TRUNK_A
    pkt = CipSafeAplRedundantPacket(
        device_id=device_id,
        snn=snn,
        trunk_id=t_id,
        sequence=sequence,
        loop_voltage_mv=loop_voltage_mv,
        latency_us=latency_us,
        payload=payload,
        **kwargs,
    )
    pkt.calculate_crcs()
    return pkt


create_valid_packet = create_valid_redundant_packet


# ============================================================================
# 7. Main Protocol Engine (ILogicUnit)
# ============================================================================

class CipSafetyAplRedundantEngine(ILogicUnit):
    """Industrial ODVA CIP Safety Over Ethernet-APL Redundant Trunks Protocol Engine.

    Governs dual-redundant 10BASE-T1L trunks (Trunk A & Trunk B),
    IEC 60079-47 2-WISE voltage surveillance (9600..15000 mV),
    bumpless switchover (< 2500 us failover latency),
    dual 16-bit safety CRCs (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B inverted),
    rolling sequence tracking & split-brain loss detection (0xEC05),
    and Horner OCS memory registers %R2380..%R2387 and %M555..%M556.
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        auto_activate: bool = True,
        watchdog_timeout_us: float = DEFAULT_WATCHDOG_TIMEOUT_US,
        device_id: int = DEFAULT_DEVICE_ID,
        snn: int = DEFAULT_SNN,
        initial_state: Optional[CipSafetyRedundantState] = None,
        state: Optional[CipSafetyRedundantState] = None,
        active_trunk: Optional[ActiveTrunkId] = None,
        trunk_a_voltage_mv: Optional[int] = None,
        trunk_b_voltage_mv: Optional[int] = None,
        switchover_count: Optional[int] = None,
        crc_status: Optional[int] = None,
        latency_us: Optional[int] = None,
        diagnostic_code: Optional[CipSafetyRedundantDiagnosticCode] = None,
        tx_sequence: int = 0,
        rx_sequence: int = 0,
        **kwargs: Any,
    ) -> None:
        self.register_table = register_table
        self.auto_activate = bool(auto_activate)
        self.device_id = int(device_id)
        self.snn = int(snn)
        self.is_active = bool(auto_activate)

        wd_lim = kwargs.get("watchdog_timeout_ms", None)
        if wd_lim is not None:
            self.watchdog_timeout_us = float(wd_lim) * 1000.0
        else:
            self.watchdog_timeout_us = float(kwargs.get("watchdog_timeout_us", watchdog_timeout_us))

        if state is not None:
            self.state = state
        elif initial_state is not None:
            self.state = initial_state
        elif auto_activate:
            self.state = CipSafetyRedundantState.DUAL_TRACKING
        else:
            self.state = CipSafetyRedundantState.TRIP_SHUTDOWN

        if active_trunk is not None:
            self.active_trunk = active_trunk
        elif self.state == CipSafetyRedundantState.DUAL_TRACKING:
            self.active_trunk = ActiveTrunkId.BOTH_SYNCHRONIZED
        else:
            self.active_trunk = ActiveTrunkId.TRUNK_A

        self.diagnostic_code = (
            diagnostic_code if diagnostic_code is not None else CipSafetyRedundantDiagnosticCode.OK
        )

        # Trunk Voltages (%R2382, %R2383)
        self.trunk_a_voltage_mv: int = int(trunk_a_voltage_mv) if trunk_a_voltage_mv is not None else NOMINAL_VOLTAGE_MV
        self.trunk_b_voltage_mv: int = int(trunk_b_voltage_mv) if trunk_b_voltage_mv is not None else NOMINAL_VOLTAGE_MV

        # Switchover & Sequence Tracking
        self.switchover_count: int = int(switchover_count) if switchover_count is not None else 0
        self.trunk_a_sequence: int = 0
        self.trunk_b_sequence: int = 0
        self.tx_sequence: int = int(tx_sequence)
        self.rx_sequence: int = int(rx_sequence)

        # CRC Status (%R2385: Bit0=Trunk A OK, Bit1=Trunk B OK, Bit2=Seq Synced, 0x0007 nominal)
        self.crc_status: int = int(crc_status) if crc_status is not None else CRC_STATUS_NOMINAL
        self.trunk_a_crc_ok: bool = bool(self.crc_status & CRC_STATUS_TRUNK_A_OK)
        self.trunk_b_crc_ok: bool = bool(self.crc_status & CRC_STATUS_TRUNK_B_OK)

        # Latency & Watchdog Surveillance
        self.latency_us: int = int(latency_us) if latency_us is not None else NOMINAL_LATENCY_US
        self.watchdog_timer_us: float = 0.0
        self.cycles_count: int = 0
        self.frames_processed: int = 0
        self.switchover_latency_us: float = float(self.latency_us)

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    # ------------------------------------------------------------------------
    # Properties (ILogicUnit Compliance)
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        """ILogicUnit Unique Identifier."""
        return "CipSafetyAplRedundantEngine"

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
        """Whether redundant link is healthy, untripped, and in state 0, 1, or 2."""
        return (
            self.state in (
                CipSafetyRedundantState.TRUNK_A_ACTIVE,
                CipSafetyRedundantState.TRUNK_B_ACTIVE,
                CipSafetyRedundantState.DUAL_TRACKING,
            )
            and self.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK
            and (
                (self.active_trunk == ActiveTrunkId.TRUNK_A and self.is_trunk_a_healthy)
                or (self.active_trunk == ActiveTrunkId.TRUNK_B and self.is_trunk_b_healthy)
                or (self.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED and (self.is_trunk_a_healthy or self.is_trunk_b_healthy))
            )
        )

    @property
    def is_established(self) -> bool:
        """Established coil mapped to %M555."""
        return (
            self.state in (
                CipSafetyRedundantState.TRUNK_A_ACTIVE,
                CipSafetyRedundantState.TRUNK_B_ACTIVE,
                CipSafetyRedundantState.DUAL_TRACKING,
            )
            and (self.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK)
        )

    @property
    def is_tripped(self) -> bool:
        """Tripped coil mapped to %M556."""
        return (
            self.state in (
                CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED,
                CipSafetyRedundantState.TRIP_SHUTDOWN,
            )
            or (self.diagnostic_code != CipSafetyRedundantDiagnosticCode.OK)
        )

    @property
    def established(self) -> bool:
        """Alias for is_established."""
        return self.is_established

    @established.setter
    def established(self, val: bool) -> None:
        if val:
            self.state = CipSafetyRedundantState.DUAL_TRACKING
            self.diagnostic_code = CipSafetyRedundantDiagnosticCode.OK
        else:
            self.state = CipSafetyRedundantState.TRIP_SHUTDOWN

    @property
    def tripped(self) -> bool:
        """Alias for is_tripped."""
        return self.is_tripped

    @tripped.setter
    def tripped(self, val: bool) -> None:
        if val:
            self.state = CipSafetyRedundantState.TRIP_SHUTDOWN
        else:
            self.state = CipSafetyRedundantState.DUAL_TRACKING
            self.diagnostic_code = CipSafetyRedundantDiagnosticCode.OK

    @property
    def is_trunk_a_healthy(self) -> bool:
        """Whether Trunk A loop voltage is within 2-WISE IS bounds and CRC is OK."""
        return (
            (MIN_IS_VOLTAGE_MV <= self.trunk_a_voltage_mv <= MAX_IS_VOLTAGE_MV)
            and self.trunk_a_crc_ok
        )

    @property
    def trunk_a_healthy(self) -> bool:
        """Alias for is_trunk_a_healthy."""
        return self.is_trunk_a_healthy

    @property
    def is_trunk_b_healthy(self) -> bool:
        """Whether Trunk B loop voltage is within 2-WISE IS bounds and CRC is OK."""
        return (
            (MIN_IS_VOLTAGE_MV <= self.trunk_b_voltage_mv <= MAX_IS_VOLTAGE_MV)
            and self.trunk_b_crc_ok
        )

    @property
    def trunk_b_healthy(self) -> bool:
        """Alias for is_trunk_b_healthy."""
        return self.is_trunk_b_healthy

    # ------------------------------------------------------------------------
    # State Machine & Fault Handling
    # ------------------------------------------------------------------------

    def commission(self) -> bool:
        """Transition into TRUNK_A_ACTIVE commissioning state."""
        self.state = CipSafetyRedundantState.TRUNK_A_ACTIVE
        self.active_trunk = ActiveTrunkId.TRUNK_A
        self.diagnostic_code = CipSafetyRedundantDiagnosticCode.OK
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def activate(self) -> bool:
        """Transition into DUAL_TRACKING state."""
        self.state = CipSafetyRedundantState.DUAL_TRACKING
        self.active_trunk = ActiveTrunkId.BOTH_SYNCHRONIZED
        self.diagnostic_code = CipSafetyRedundantDiagnosticCode.OK
        self.watchdog_timer_us = 0.0
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def trip_fault(self, code: CipSafetyRedundantDiagnosticCode, reason: str = "") -> None:
        """Trip safety interlock with specified diagnostic code."""
        self.diagnostic_code = code
        if code in (
            CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL,
            CipSafetyRedundantDiagnosticCode.SWITCHOVER_TIMEOUT,
        ):
            self.state = CipSafetyRedundantState.TRIP_SHUTDOWN
        else:
            self.state = CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def trip_trunk_a_droop(self, details: Optional[str] = None) -> None:
        """Trip 0xEC01 TRUNK_A_DROOP (< 9600 mV or > 15000 mV)."""
        self.trunk_a_crc_ok = False
        self.crc_status &= ~CRC_STATUS_TRUNK_A_OK
        self.trip_fault(CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP, details or "Trunk A voltage droop")

    def trip_trunk_b_droop(self, details: Optional[str] = None) -> None:
        """Trip 0xEC02 TRUNK_B_DROOP (< 9600 mV or > 15000 mV)."""
        self.trunk_b_crc_ok = False
        self.crc_status &= ~CRC_STATUS_TRUNK_B_OK
        self.trip_fault(CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP, details or "Trunk B voltage droop")

    def trip_dual_trunk_fail(self, details: Optional[str] = None) -> None:
        """Trip 0xEC03 DUAL_TRUNK_FAIL."""
        self.trunk_a_crc_ok = False
        self.trunk_b_crc_ok = False
        self.crc_status &= ~(CRC_STATUS_TRUNK_A_OK | CRC_STATUS_TRUNK_B_OK)
        self.trip_fault(CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL, details or "Both trunks failed")

    def trip_switchover_timeout(self, details: Optional[str] = None) -> None:
        """Trip 0xEC04 SWITCHOVER_TIMEOUT (>= 2500 us)."""
        self.trip_fault(CipSafetyRedundantDiagnosticCode.SWITCHOVER_TIMEOUT, details or "Switchover timeout")

    def trip_split_brain_sync_loss(self, details: Optional[str] = None) -> None:
        """Trip 0xEC05 SPLIT_BRAIN_SYNC_LOSS."""
        self.crc_status &= ~CRC_STATUS_SEQ_SYNCED
        self.trip_fault(CipSafetyRedundantDiagnosticCode.SPLIT_BRAIN_SYNC_LOSS, details or "Split-brain sync loss")

    def inject_split_brain_sync_loss(self) -> None:
        """Inject split-brain sequence sync loss fault (0xEC05)."""
        self.state = CipSafetyRedundantState.TRIP_SHUTDOWN
        self.diagnostic_code = CipSafetyRedundantDiagnosticCode.SPLIT_BRAIN_SYNC_LOSS
        self.crc_status &= ~CRC_STATUS_SEQ_SYNCED
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def reset(self) -> None:
        """Reset internal engine state to nominal operational conditions."""
        self.diagnostic_code = CipSafetyRedundantDiagnosticCode.OK
        self.state = CipSafetyRedundantState.DUAL_TRACKING
        self.active_trunk = ActiveTrunkId.BOTH_SYNCHRONIZED
        self.is_active = True
        self.trunk_a_voltage_mv = NOMINAL_VOLTAGE_MV
        self.trunk_b_voltage_mv = NOMINAL_VOLTAGE_MV
        self.switchover_count = 0
        self.crc_status = CRC_STATUS_NOMINAL
        self.trunk_a_crc_ok = True
        self.trunk_b_crc_ok = True
        self.latency_us = NOMINAL_LATENCY_US
        self.watchdog_timer_us = 0.0
        self.tx_sequence = 0
        self.rx_sequence = 0
        self.cycles_count = 0
        self.trunk_a_sequence = 0
        self.trunk_b_sequence = 0
        self.switchover_latency_us = float(NOMINAL_LATENCY_US)

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    operator_reset = reset
    fault_reset = reset

    def feed_watchdog(self) -> None:
        """Feed / kick communication watchdog timer."""
        self.watchdog_timer_us = 0.0

    kick_watchdog = feed_watchdog

    # ------------------------------------------------------------------------
    # Redundant Switchover & Voltage Surveillance
    # ------------------------------------------------------------------------

    def switchover_to_trunk(
        self,
        trunk_id: Union[ActiveTrunkId, int],
        latency_us: Optional[float] = None,
        switchover_time_us: Optional[float] = None,
    ) -> bool:
        """Execute bumpless failover switchover to designated trunk (< 2500 us latency)."""
        target_trunk = ActiveTrunkId(int(trunk_id))
        lat = switchover_time_us if switchover_time_us is not None else (latency_us if latency_us is not None else float(NOMINAL_LATENCY_US))
        self.latency_us = int(lat)
        self.switchover_latency_us = float(lat)

        # Exact threshold 2500 us is permitted; > 2500 trips timeout
        if self.latency_us > MAX_SWITCHOVER_LATENCY_US:
            self.active_trunk = target_trunk
            self.switchover_count = (self.switchover_count + 1) & 0xFFFF
            self.trip_switchover_timeout(
                f"Switchover latency {self.latency_us} us > threshold {MAX_SWITCHOVER_LATENCY_US} us"
            )
            return False

        if target_trunk == ActiveTrunkId.TRUNK_A:
            if not self.is_trunk_a_healthy:
                self.trip_trunk_a_droop(f"Cannot switchover to Trunk A: voltage {self.trunk_a_voltage_mv} mV out of bounds")
                return False
            self.switchover_count = (self.switchover_count + 1) & 0xFFFF
            self.active_trunk = ActiveTrunkId.TRUNK_A
            self.state = CipSafetyRedundantState.TRUNK_A_ACTIVE

        elif target_trunk == ActiveTrunkId.TRUNK_B:
            if not self.is_trunk_b_healthy:
                self.trip_trunk_b_droop(f"Cannot switchover to Trunk B: voltage {self.trunk_b_voltage_mv} mV out of bounds")
                return False
            self.switchover_count = (self.switchover_count + 1) & 0xFFFF
            self.active_trunk = ActiveTrunkId.TRUNK_B
            self.state = CipSafetyRedundantState.TRUNK_B_ACTIVE

        elif target_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED:
            if not (self.is_trunk_a_healthy and self.is_trunk_b_healthy):
                self.trip_dual_trunk_fail("Cannot synchronize dual tracking: one or both trunks unhealthy")
                return False
            self.switchover_count = (self.switchover_count + 1) & 0xFFFF
            self.active_trunk = ActiveTrunkId.BOTH_SYNCHRONIZED
            self.state = CipSafetyRedundantState.DUAL_TRACKING

        self.diagnostic_code = CipSafetyRedundantDiagnosticCode.OK
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def monitor_trunk_a_voltage(self, voltage_mv: int) -> bool:
        """Monitor Trunk A loop voltage (%R2382). Permissible bounds: 9600..15000 mV."""
        self.trunk_a_voltage_mv = int(voltage_mv)
        if self.trunk_a_voltage_mv < MIN_IS_VOLTAGE_MV or self.trunk_a_voltage_mv > MAX_IS_VOLTAGE_MV:
            if self.trunk_b_voltage_mv < MIN_IS_VOLTAGE_MV or self.trunk_b_voltage_mv > MAX_IS_VOLTAGE_MV:
                self.trip_dual_trunk_fail(f"Both trunks drooped: Trunk A {self.trunk_a_voltage_mv} mV, Trunk B {self.trunk_b_voltage_mv} mV")
            else:
                self.trip_trunk_a_droop(f"Trunk A droop: {self.trunk_a_voltage_mv} mV out of IS bounds")
            return False

        self.trunk_a_crc_ok = True
        self.crc_status |= CRC_STATUS_TRUNK_A_OK
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def monitor_trunk_b_voltage(self, voltage_mv: int) -> bool:
        """Monitor Trunk B loop voltage (%R2383). Permissible bounds: 9600..15000 mV."""
        self.trunk_b_voltage_mv = int(voltage_mv)
        if self.trunk_b_voltage_mv < MIN_IS_VOLTAGE_MV or self.trunk_b_voltage_mv > MAX_IS_VOLTAGE_MV:
            if self.trunk_a_voltage_mv < MIN_IS_VOLTAGE_MV or self.trunk_a_voltage_mv > MAX_IS_VOLTAGE_MV:
                self.trip_dual_trunk_fail(f"Both trunks drooped: Trunk A {self.trunk_a_voltage_mv} mV, Trunk B {self.trunk_b_voltage_mv} mV")
            else:
                self.trip_trunk_b_droop(f"Trunk B droop: {self.trunk_b_voltage_mv} mV out of IS bounds")
            return False

        self.trunk_b_crc_ok = True
        self.crc_status |= CRC_STATUS_TRUNK_B_OK
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def monitor_voltages(self, voltage_a_mv: int, voltage_b_mv: int) -> bool:
        """Monitor both Trunk A and Trunk B voltages simultaneously with automatic failover."""
        self.trunk_a_voltage_mv = int(voltage_a_mv)
        self.trunk_b_voltage_mv = int(voltage_b_mv)
        a_ok = (MIN_IS_VOLTAGE_MV <= self.trunk_a_voltage_mv <= MAX_IS_VOLTAGE_MV)
        b_ok = (MIN_IS_VOLTAGE_MV <= self.trunk_b_voltage_mv <= MAX_IS_VOLTAGE_MV)

        if not a_ok and not b_ok:
            self.crc_status &= ~(CRC_STATUS_TRUNK_A_OK | CRC_STATUS_TRUNK_B_OK)
            self.trunk_a_crc_ok = False
            self.trunk_b_crc_ok = False
            self.state = CipSafetyRedundantState.TRIP_SHUTDOWN
            self.diagnostic_code = CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return False
        elif not a_ok:
            self.crc_status &= ~CRC_STATUS_TRUNK_A_OK
            self.crc_status |= CRC_STATUS_TRUNK_B_OK
            self.trunk_a_crc_ok = False
            self.trunk_b_crc_ok = True
            if self.active_trunk != ActiveTrunkId.TRUNK_B:
                self.switchover_count = (self.switchover_count + 1) & 0xFFFF
            self.active_trunk = ActiveTrunkId.TRUNK_B
            self.state = CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
            self.diagnostic_code = CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return False
        elif not b_ok:
            self.crc_status |= CRC_STATUS_TRUNK_A_OK
            self.crc_status &= ~CRC_STATUS_TRUNK_B_OK
            self.trunk_a_crc_ok = True
            self.trunk_b_crc_ok = False
            if self.active_trunk != ActiveTrunkId.TRUNK_A:
                self.switchover_count = (self.switchover_count + 1) & 0xFFFF
            self.active_trunk = ActiveTrunkId.TRUNK_A
            self.state = CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
            self.diagnostic_code = CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return False
        else:
            self.crc_status |= (CRC_STATUS_TRUNK_A_OK | CRC_STATUS_TRUNK_B_OK)
            self.trunk_a_crc_ok = True
            self.trunk_b_crc_ok = True
            self.state = CipSafetyRedundantState.DUAL_TRACKING
            self.active_trunk = ActiveTrunkId.BOTH_SYNCHRONIZED
            self.diagnostic_code = CipSafetyRedundantDiagnosticCode.OK
            if self.register_table is not None:
                self.sync_to_registers(self.register_table)
            return True

    def monitor_trunk_voltages(self, voltage_a_mv: int, voltage_b_mv: int) -> bool:
        return self.monitor_voltages(voltage_a_mv, voltage_b_mv)

    def monitor_latency(self, latency_us: int) -> bool:
        """Monitor failover latency in microseconds (%R2386)."""
        self.latency_us = int(latency_us)
        if self.latency_us >= MAX_SWITCHOVER_LATENCY_US:
            self.trip_switchover_timeout(f"Latency exceeded threshold: {self.latency_us} us >= {MAX_SWITCHOVER_LATENCY_US} us")
            return False

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    # ------------------------------------------------------------------------
    # Packet Processing & Cyclic Transmission
    # ------------------------------------------------------------------------

    def create_packet(
        self,
        trunk_id: Union[ActiveTrunkId, int] = ActiveTrunkId.TRUNK_A,
        sequence: Optional[int] = None,
        loop_voltage_mv: Optional[int] = None,
        latency_us: Optional[int] = None,
        payload: Optional[bytes] = None,
        **kwargs: Any,
    ) -> CipSafeAplRedundantPacket:
        """Generate valid outgoing redundant safe APL packet with fresh sequence & dual CRCs."""
        t_id = ActiveTrunkId(int(trunk_id)) if int(trunk_id) in (1, 2, 3) else ActiveTrunkId.TRUNK_A
        seq = sequence if sequence is not None else (
            (self.trunk_a_sequence + 1) & 0xFFFF if t_id == ActiveTrunkId.TRUNK_A
            else (self.trunk_b_sequence + 1) & 0xFFFF
        )
        vol = loop_voltage_mv if loop_voltage_mv is not None else (
            self.trunk_a_voltage_mv if t_id == ActiveTrunkId.TRUNK_A else self.trunk_b_voltage_mv
        )
        lat = latency_us if latency_us is not None else self.latency_us

        pkt = CipSafeAplRedundantPacket(
            device_id=self.device_id,
            snn=self.snn,
            trunk_id=t_id,
            sequence=int(seq) & 0xFFFF,
            loop_voltage_mv=int(vol),
            latency_us=int(lat),
            payload=payload if payload is not None else b"\x01\x00\x00\x00",
            timestamp_us=float(self.cycles_count * NOMINAL_LATENCY_US),
            **kwargs,
        )
        pkt.calculate_crcs()
        return pkt

    def transmit_packet(
        self,
        trunk_id: Optional[Union[ActiveTrunkId, int]] = None,
        payload: Optional[bytes] = None,
    ) -> CipSafeAplRedundantPacket:
        """Transmit packet on specified or active trunk; increments trunk sequence counter."""
        if trunk_id is None:
            target_trunk = (
                self.active_trunk
                if self.active_trunk in (ActiveTrunkId.TRUNK_A, ActiveTrunkId.TRUNK_B)
                else ActiveTrunkId.TRUNK_A
            )
        else:
            target_trunk = ActiveTrunkId(int(trunk_id))

        if target_trunk == ActiveTrunkId.TRUNK_B:
            self.trunk_b_sequence = (self.trunk_b_sequence + 1) & 0xFFFF
            seq = self.trunk_b_sequence
            vol = self.trunk_b_voltage_mv
        else:
            self.trunk_a_sequence = (self.trunk_a_sequence + 1) & 0xFFFF
            seq = self.trunk_a_sequence
            vol = self.trunk_a_voltage_mv

        pkt = self.create_packet(
            trunk_id=target_trunk,
            sequence=seq,
            loop_voltage_mv=vol,
            payload=payload,
        )
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return pkt

    def process_packet(self, pkt: CipSafeAplRedundantPacket) -> bool:
        """Process incoming packet with dual CRC validation, voltage surveillance, and split-brain check."""
        # 1. Dual CRC-S1 / CRC-S2 verification
        crc_s1_ok = (pkt.crc_s1 == compute_crc_s1(pkt.serialize_for_crc_s1()))
        crc_s2_ok = (pkt.crc_s2 == compute_crc_s2(pkt.serialize_for_crc_s2()))
        crc_ok = crc_s1_ok and crc_s2_ok

        if pkt.trunk_id == ActiveTrunkId.TRUNK_A:
            if crc_ok:
                self.crc_status |= CRC_STATUS_TRUNK_A_OK
                self.trunk_a_crc_ok = True
            else:
                self.crc_status &= ~CRC_STATUS_TRUNK_A_OK
                self.trunk_a_crc_ok = False
        elif pkt.trunk_id == ActiveTrunkId.TRUNK_B:
            if crc_ok:
                self.crc_status |= CRC_STATUS_TRUNK_B_OK
                self.trunk_b_crc_ok = True
            else:
                self.crc_status &= ~CRC_STATUS_TRUNK_B_OK
                self.trunk_b_crc_ok = False

        if not crc_ok:
            if self.active_trunk == pkt.trunk_id:
                # Active trunk corrupted: attempt failover
                alt_trunk = ActiveTrunkId.TRUNK_B if pkt.trunk_id == ActiveTrunkId.TRUNK_A else ActiveTrunkId.TRUNK_A
                alt_ok = self.is_trunk_b_healthy if pkt.trunk_id == ActiveTrunkId.TRUNK_A else self.is_trunk_a_healthy
                if alt_ok:
                    self.switchover_to_trunk(alt_trunk)
                else:
                    self.trip_dual_trunk_fail(f"Active trunk {pkt.trunk_id.name} CRC corrupted and alternate trunk unhealthy")
                    return False
            return False

        # 2. Sequence progression & Split-Brain synchronization check
        if pkt.trunk_id == ActiveTrunkId.TRUNK_A:
            self.trunk_a_sequence = pkt.sequence
        elif pkt.trunk_id == ActiveTrunkId.TRUNK_B:
            self.trunk_b_sequence = pkt.sequence

        if self.state == CipSafetyRedundantState.DUAL_TRACKING:
            if self.trunk_a_sequence == self.trunk_b_sequence:
                self.crc_status |= CRC_STATUS_SEQ_SYNCED
            else:
                self.crc_status &= ~CRC_STATUS_SEQ_SYNCED
                self.trip_split_brain_sync_loss(
                    f"Split-brain sequence divergence: Trunk A seq {self.trunk_a_sequence} != Trunk B seq {self.trunk_b_sequence}"
                )
                return False
        else:
            if self.trunk_a_sequence == self.trunk_b_sequence:
                self.crc_status |= CRC_STATUS_SEQ_SYNCED
            else:
                self.crc_status &= ~CRC_STATUS_SEQ_SYNCED

        # 3. Voltage verification
        if pkt.trunk_id == ActiveTrunkId.TRUNK_A:
            self.trunk_a_voltage_mv = pkt.loop_voltage_mv
            if self.trunk_a_voltage_mv < MIN_IS_VOLTAGE_MV or self.trunk_a_voltage_mv > MAX_IS_VOLTAGE_MV:
                if self.active_trunk == ActiveTrunkId.TRUNK_A:
                    if self.is_trunk_b_healthy:
                        self.switchover_to_trunk(ActiveTrunkId.TRUNK_B)
                    else:
                        self.trip_dual_trunk_fail()
                        return False
        elif pkt.trunk_id == ActiveTrunkId.TRUNK_B:
            self.trunk_b_voltage_mv = pkt.loop_voltage_mv
            if self.trunk_b_voltage_mv < MIN_IS_VOLTAGE_MV or self.trunk_b_voltage_mv > MAX_IS_VOLTAGE_MV:
                if self.active_trunk == ActiveTrunkId.TRUNK_B:
                    if self.is_trunk_a_healthy:
                        self.switchover_to_trunk(ActiveTrunkId.TRUNK_A)
                    else:
                        self.trip_dual_trunk_fail()
                        return False

        # 4. Latency
        self.latency_us = pkt.latency_us
        if self.latency_us >= MAX_SWITCHOVER_LATENCY_US:
            self.trip_switchover_timeout()
            return False

        self.feed_watchdog()
        self.frames_processed += 1
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    process_frame = process_packet

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: RegisterTable,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize internal engine state to Horner OCS %R2380..%R2387 and %M555..%M556."""
        # %R2380: State (0..4)
        safe_write_word(reg_table, REG_CIP_SAFETY_REDUNDANT_STATE, int(self.state), privilege=privilege)

        # %R2381: Active Trunk (1=Trunk A, 2=Trunk B, 3=Both synchronized)
        safe_write_word(reg_table, REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK, int(self.active_trunk), privilege=privilege)

        # %R2382: Trunk A Voltage in mV (9600..15000 mV)
        safe_write_word(reg_table, REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV, int(self.trunk_a_voltage_mv), privilege=privilege)

        # %R2383: Trunk B Voltage in mV (9600..15000 mV)
        safe_write_word(reg_table, REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV, int(self.trunk_b_voltage_mv), privilege=privilege)

        # %R2384: Switchover Count (0..65535 rolling)
        safe_write_uword(reg_table, REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT, int(self.switchover_count) & 0xFFFF, privilege=privilege)

        # %R2385: Redundant CRC Status (Bit0=Trunk A OK, Bit1=Trunk B OK, Bit2=Seq Synced, 0x0007 nominal)
        safe_write_word(reg_table, REG_CIP_SAFETY_REDUNDANT_CRC_STATUS, int(self.crc_status) & 0xFFFF, privilege=privilege)

        # %R2386: Latency in us (< 2500 us)
        safe_write_word(reg_table, REG_CIP_SAFETY_REDUNDANT_LATENCY_US, int(self.latency_us), privilege=privilege)

        # %R2387: Diagnostic Code (0x0000=OK, 0xEC01..0xEC05)
        diag_val = int(self.diagnostic_code) & 0xFFFF
        safe_write_uword(reg_table, REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE, diag_val, privilege=privilege)

        # %M555: Established Coil (BOOL, True when state in (0, 1, 2) and healthy)
        est_val = (
            self.state in (
                CipSafetyRedundantState.TRUNK_A_ACTIVE,
                CipSafetyRedundantState.TRUNK_B_ACTIVE,
                CipSafetyRedundantState.DUAL_TRACKING,
            )
            and (self.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK)
        )
        safe_write_bit(reg_table, COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED, est_val, privilege=privilege)

        # %M556: Tripped Coil (BOOL, True when state in (3, 4) or diagnostic_code != OK)
        tripped_val = (
            self.state in (
                CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED,
                CipSafetyRedundantState.TRIP_SHUTDOWN,
            )
            or (self.diagnostic_code != CipSafetyRedundantDiagnosticCode.OK)
        )
        safe_write_bit(reg_table, COIL_CIP_SAFETY_REDUNDANT_TRIPPED, tripped_val, privilege=privilege)

    # ------------------------------------------------------------------------
    # ILogicUnit Cyclic Execution
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.010, context: Optional[ScanContext] = None) -> None:
        """Deterministic scan step: increment cycles and sequence counters."""
        self.cycles_count += 1
        self.tx_sequence = (self.tx_sequence + 1) & 0xFFFF
        self.rx_sequence = (self.rx_sequence + 1) & 0xFFFF
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
            status = AgentStatus.SUCCESS
            error_code = None
            details = "Redundant links healthy and synchronized."
        else:
            status = AgentStatus.FAILED
            error_code = f"ERR_{self.diagnostic_code.name}"
            details = f"Redundant link fault: {self.diagnostic_code.name}"

        return ExecutionResult(
            status=status,
            error_code=error_code,
            details=details,
            data={
                "state": self.state.name,
                "active_trunk": self.active_trunk.name,
                "diagnostic_code": f"0x{int(self.diagnostic_code) & 0xFFFF:04X}",
                "switchover_count": self.switchover_count,
            },
        )


CIPSafetyAPLRedundantEngine = CipSafetyAplRedundantEngine
CipSafetyRedundantEngine = CipSafetyAplRedundantEngine
CIPSafetyRedundantEngine = CipSafetyAplRedundantEngine
CIP_SAFETY_APL_REDUNDANT_ENGINE = CipSafetyAplRedundantEngine


# ============================================================================
# 8. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_safety_apl_redundant_verification(
    output_path: Optional[str] = None,
    work_package: str = "W277",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W277."""
    test_results: List[Dict[str, Any]] = []

    # Stage 1: enums_and_constants
    t0 = time.perf_counter()
    s1_pass = (
        REG_CIP_SAFETY_REDUNDANT_STATE == "%R2380"
        and REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK == "%R2381"
        and REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV == "%R2382"
        and REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV == "%R2383"
        and REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT == "%R2384"
        and REG_CIP_SAFETY_REDUNDANT_CRC_STATUS == "%R2385"
        and REG_CIP_SAFETY_REDUNDANT_LATENCY_US == "%R2386"
        and REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE == "%R2387"
        and COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED == "%M555"
        and COIL_CIP_SAFETY_REDUNDANT_TRIPPED == "%M556"
        and CipSafetyRedundantState.TRUNK_A_ACTIVE == 0
        and CipSafetyRedundantState.TRUNK_B_ACTIVE == 1
        and CipSafetyRedundantState.DUAL_TRACKING == 2
        and CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED == 3
        and CipSafetyRedundantState.TRIP_SHUTDOWN == 4
        and ActiveTrunkId.TRUNK_A == 1
        and ActiveTrunkId.TRUNK_B == 2
        and ActiveTrunkId.BOTH_SYNCHRONIZED == 3
        and CipSafetyRedundantDiagnosticCode.OK == 0x0000
        and CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP == 0xEC01
        and CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP == 0xEC02
        and CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL == 0xEC03
        and CipSafetyRedundantDiagnosticCode.SWITCHOVER_TIMEOUT == 0xEC04
        and CipSafetyRedundantDiagnosticCode.SPLIT_BRAIN_SYNC_LOSS == 0xEC05
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "enums_and_constants",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified registers %R2380..%R2387, coils %M555..%M556, and enums.",
    })

    # Stage 2: dual_safety_crc_calculation
    t0 = time.perf_counter()
    pkt_a = create_valid_redundant_packet(trunk_id=ActiveTrunkId.TRUNK_A, sequence=101)
    s2_a_crc_valid = pkt_a.verify_crcs()
    pkt_corrupted = create_valid_redundant_packet(trunk_id=ActiveTrunkId.TRUNK_A, sequence=101)
    pkt_corrupted.mutate_bit(byte_offset=0, bit_pos=2)
    s2_mutation_detected = not pkt_corrupted.verify_crcs()
    s2_pass = s2_a_crc_valid and s2_mutation_detected
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "dual_safety_crc_calculation",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": "CRC-S1 & CRC-S2 calculations and mutation detection verified.",
    })

    # Stage 3: pure_st_anti_ladder_guard
    t0 = time.perf_counter()
    s3_pure_st = verify_cip_safety_apl_redundant_pure_st()
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM Test VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_rejected = True
    s3_pass = s3_pure_st and ladder_rejected
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "pure_st_anti_ladder_guard",
        "passed": bool(s3_pass),
        "timing_ms": round(t1, 3),
        "details": "Pure ST POU verified; ladder logic rejected with LadderForbiddenError.",
    })

    # Stage 4: nominal_dual_tracking
    t0 = time.perf_counter()
    rt_s4 = RegisterTable()
    eng_s4 = CipSafetyAplRedundantEngine(register_table=rt_s4, auto_activate=True)
    s4_pass = (
        eng_s4.state == CipSafetyRedundantState.DUAL_TRACKING
        and eng_s4.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED
        and eng_s4.is_healthy
        and rt_s4.read_word("%R2380") == 2
        and rt_s4.read_word("%R2381") == 3
        and rt_s4.read_bit("%M555") is True
        and rt_s4.read_bit("%M556") is False
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "nominal_dual_tracking",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "Nominal dual tracking operation verified with register sync.",
    })

    # Stage 5: trunk_a_droop_failover
    t0 = time.perf_counter()
    rt_s5 = RegisterTable()
    eng_s5 = CipSafetyAplRedundantEngine(register_table=rt_s5, auto_activate=True)
    droop_res = eng_s5.monitor_voltages(8000, 12000)
    s5_pass = (
        (not droop_res)
        and eng_s5.state == CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
        and eng_s5.active_trunk == ActiveTrunkId.TRUNK_B
        and eng_s5.diagnostic_code == CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP
        and eng_s5.switchover_count == 1
        and rt_s5.read_bit("%M556") is True
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "trunk_a_droop_failover",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "Trunk A droop (< 9600 mV) triggers bumpless failover to Trunk B with 0xEC01.",
    })

    # Stage 6: trunk_b_droop_failover
    t0 = time.perf_counter()
    rt_s6 = RegisterTable()
    eng_s6 = CipSafetyAplRedundantEngine(register_table=rt_s6, auto_activate=True)
    droop_b_res = eng_s6.monitor_voltages(12000, 8000)
    s6_pass = (
        (not droop_b_res)
        and eng_s6.state == CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
        and eng_s6.active_trunk == ActiveTrunkId.TRUNK_A
        and eng_s6.diagnostic_code == CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP
        and eng_s6.switchover_count == 1
        and rt_s6.read_bit("%M556") is True
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "trunk_b_droop_failover",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "Trunk B droop triggers failover to Trunk A with 0xEC02.",
    })

    # Stage 7: dual_trunk_trip_shutdown
    t0 = time.perf_counter()
    rt_s7 = RegisterTable()
    eng_s7 = CipSafetyAplRedundantEngine(register_table=rt_s7, auto_activate=True)
    dual_res = eng_s7.monitor_voltages(8000, 8000)
    s7_pass = (
        (not dual_res)
        and eng_s7.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        and eng_s7.diagnostic_code == CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL
        and rt_s7.read_uword("%R2387") == 0xEC03
        and rt_s7.read_bit("%M556") is True
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "dual_trunk_trip_shutdown",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "Dual trunk failure trips TRIP_SHUTDOWN with 0xEC03.",
    })

    # Stage 8: switchover_timeout_detection
    t0 = time.perf_counter()
    rt_s8 = RegisterTable()
    eng_s8 = CipSafetyAplRedundantEngine(register_table=rt_s8, auto_activate=True)
    sw_res = eng_s8.switchover_to_trunk(ActiveTrunkId.TRUNK_B, switchover_time_us=2600)
    s8_pass = (
        (not sw_res)
        and eng_s8.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        and eng_s8.diagnostic_code == CipSafetyRedundantDiagnosticCode.SWITCHOVER_TIMEOUT
        and rt_s8.read_uword("%R2387") == 0xEC04
        and rt_s8.read_bit("%M556") is True
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "switchover_timeout_detection",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": "Switchover latency > 2500 us trips 0xEC04 SWITCHOVER_TIMEOUT.",
    })

    # Stage 9: split_brain_sync_loss_and_scan
    t0 = time.perf_counter()
    rt_s9 = RegisterTable()
    eng_s9 = CipSafetyAplRedundantEngine(register_table=rt_s9, auto_activate=True)
    eng_s9.inject_split_brain_sync_loss()
    sb_tripped = (
        eng_s9.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        and eng_s9.diagnostic_code == CipSafetyRedundantDiagnosticCode.SPLIT_BRAIN_SYNC_LOSS
        and rt_s9.read_uword("%R2387") == 0xEC05
    )
    eng_s9.reset()
    reset_ok = eng_s9.is_healthy
    for cycle in range(100):
        eng_s9.scan_step(0.005)
    s9_pass = sb_tripped and reset_ok and eng_s9.cycles_count == 100 and eng_s9.is_healthy
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 9,
        "name": "split_brain_sync_loss_and_scan",
        "passed": bool(s9_pass),
        "timing_ms": round(t1, 3),
        "details": "Split-brain sync loss and 100-cycle soak scan verified.",
    })

    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    status = "success" if all_passed else "failed"
    error_code = None if all_passed else "ERR_STAGE_VERIFICATION_FAILED"
    details = (
        f"Wave {work_package} CIP Safety Over Ethernet-APL Redundant Trunks Protocol Engine Verification PASSED ({stages_passed}/{total_stages} stages)."
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
            "protocol": "ODVA CIP Safety Over Ethernet-APL Redundant Trunks (10BASE-T1L / 2-WISE Intrinsically Safe)",
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
    result = run_cip_safety_apl_redundant_verification()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)

# Compatibility Aliases
CRC16_S1_POLY = CRC_S1_POLY
CRC16_S2_POLY = CRC_S2_POLY
CRC16_INIT = CRC_S_INIT
CIPSafetyAplRedundantEngine = CipSafetyAplRedundantEngine
CIPSafetyAPLRedundantEngine = CipSafetyAplRedundantEngine


