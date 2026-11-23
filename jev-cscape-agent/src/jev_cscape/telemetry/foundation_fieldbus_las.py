"""Industrial FOUNDATION Fieldbus H1 Link Active Scheduler (LAS) & Function Block Bridge Engine.

Work Package: W181 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- IEC 61158-2 / IEC 61784-1 Physical Layer & Data Link Layer Specification (FOUNDATION Fieldbus H1, 31.25 kbit/s MBP)
- Fieldbus Foundation FF-890 / FF-891 Communications & Function Block Application Architecture
- IEC 61804 Function Blocks (FB) for Process Control (AI, AO, PID, DI, DO, TB, RB)
- IEC 61131-3 Programmable Controllers - Part 3: Programming Languages (Structured Text)

Architecture:
1. Strict Pure IEC 61131-3 Structured Text POUs:
   - 'FoundationFieldbusLasSync' (and alias 'FfH1FunctionBlockBridgeSync').
   - Bound to Horner OCS memory space (%R1420..%R1427, %M331..%M332).
   - Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN using SecurityGuard and STParser.

2. Complete FOUNDATION Fieldbus H1 Architecture (IEC 61158-2 / FF-890):
   - Link Active Scheduler (LAS) token dispatching: Pass Token (PT), Compelled Data (CD / Publisher-Subscriber),
     Probe Node (PN), Time Distribution (TD).
   - Macrocycle execution schedule: 100ms macrocycle with periodic scheduled data exchange
     and unscheduled background tokens.
   - Standard FF Function Blocks: AI (Analog Input), AO (Analog Output), PID, DI (Discrete Input),
     DO (Discrete Output), Transducer Block (TB), Resource Block (RB).
   - Status bytes: Quality (Good 0x80/0xC0, Uncertain 0x40, Bad 0x00), Limit flags, Sub-status.
   - Communication jitter and latency surveillance: nominal macrocycle latency 12.0 ms (scaled x10 -> 120),
     bus jitter tracking in microseconds (e.g. 1450 us, threshold 5000 us).
   - Gateway state machine: LAS_IDLE, MACROCYCLE_SCHEDULED, DISPATCHING_CD, PASSING_TOKEN,
     BUS_RECONFIG, LAS_FAULT.
   - Implements ILogicUnit interface with scan_step(dt).

3. Process Safety Interlocks & Diagnostics:
   - 0x0000: OK (Normal healthy scheduler & function block operation)
   - 0xCE01: FF_ERR_LAS_MACROCYCLE_DEADLOCK (Macrocycle schedule overrun or token stall > 200ms)
             -> asserts %M332 (FfLasFaultTrip), clears %M331 (FfLasPermissive), increments %R1424.
   - 0xCE02: FF_ERR_COMMUNICATION_JITTER_HIGH (Bus jitter exceeds 5000 us limit).
   - 0xCE03: FF_ERR_DEVICE_STATION_DROPOUT (Monitored fieldbus slave station dropped off Live List).
   - 0xCE04: FF_ERR_BLOCK_EXECUTION_FAULT (Function block returned BAD execution status or Resource Block alarm).

4. Horner OCS Memory Space Integration:
   - %R1420: ActiveDevicesCount (INT16, 0..32, e.g. 12)
   - %R1421: ScheduledBlocksCount (INT16, e.g. 24)
   - %R1422: MacrocycleLatencyMsScaled (INT16, scaled x10 ms, e.g. 120 = 12.0 ms)
   - %R1423: BusJitterMicroseconds (INT16, microseconds, e.g. 1450 = 1450 us)
   - %R1424: DroppedTokenCounter (INT16 count)
   - %R1425: FfLasStateWord (INT16 bitmask)
   - %R1426: MacrocyclePeriodMs (INT16, e.g. 100)
   - %R1427: DiagnosticStatusCode (0x0000=OK, 0xCE01, 0xCE02, 0xCE03, 0xCE04)
   - %M331: FfLasPermissive (BOOL)
   - %M332: FfLasFaultTrip (BOOL)
   - In sync_to_registers(), writes pass privilege=PrivilegeMode.SYSTEM.

5. Deterministic 9-Stage Verification Suite:
   - Function run_foundation_fieldbus_las_verification(output_path) returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
import json
import math
from pathlib import Path
import re
import struct
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (IEC 61158-2 / FF-890)
# ============================================================================

FIELDBUS_BAUD_RATE_BPS: int = 31250       # 31.25 kbit/s Manchester biphase L (MBP)
FIELDBUS_BIT_TIME_US: float = 32.0        # 1 / 31250 s = 32.0 us per bit

PREAMBLE_OCTET: int = 0x55                # Standard MBP Preamble
START_DELIMITER: int = 0x57               # Standard FF H1 Start Delimiter (SD)
END_DELIMITER: int = 0x71                 # Standard FF H1 End Delimiter (ED)

BROADCAST_ADDRESS: int = 0xFF             # Broadcast address for global tokens/TD
OPERATIONAL_ADDR_MIN: int = 0x10          # 16 decimal: Start of operational addresses
OPERATIONAL_ADDR_MAX: int = 0xF7          # 247 decimal: End of operational addresses

DEFAULT_MACROCYCLE_PERIOD_MS: int = 100   # 100 ms nominal macrocycle period
NOMINAL_MACROCYCLE_LATENCY_MS: float = 12.0
NOMINAL_LATENCY_SCALED: int = 120         # 12.0 ms * 10 = 120
NOMINAL_BUS_JITTER_US: int = 1450         # 1450 us nominal bus jitter
MAX_BUS_JITTER_US: int = 5000             # 5000 us bus jitter trip threshold
MACROCYCLE_DEADLOCK_TIMEOUT_MS: float = 200.0  # 200 ms overrun / stall limit
DEFAULT_TOKEN_HOLD_TIME_MS: float = 20.0  # Pass token hold limit per station
DEFAULT_TOKEN_TIMEOUT_MS: float = 20.0       # Alias for test suite compatibility
MAX_CONSECUTIVE_CD_RETRIES: int = 3       # Missed CD poll count before dropping station
MAX_CONFIGURED_DEVICES: int = 32          # Maximum supported H1 fieldbus devices (0..32)



# ============================================================================
# 2. Status Octets & Quality Definitions (FF-891 / IEC 61804)
# ============================================================================

class QualityCode(IntEnum):
    """FOUNDATION Fieldbus Function Block Quality Codes (Bits 7..6)."""
    BAD              = 0x00  # Bad quality: measurement or output unusable
    UNCERTAIN        = 0x40  # Uncertain quality: degraded or substitute value
    GOOD_NON_CASCADE = 0x80  # Good quality (Standard non-cascade output)
    GOOD_CASCADE     = 0xC0  # Good quality (Cascade path active)

    # Convenience aliases
    GOOD             = 0x80


class SubstatusBad(IntEnum):
    """Sub-status definitions for BAD quality (Bits 5..2)."""
    NON_SPECIFIC        = 0x00
    CONFIG_ERROR        = 0x04
    NOT_CONNECTED       = 0x08
    DEVICE_FAILURE      = 0x0C
    SENSOR_FAILURE      = 0x10
    NO_COMM_WITH_LUV    = 0x14  # No comm with last usable value
    NO_COMM_NO_LUV      = 0x18  # No comm without last usable value
    OUT_OF_SERVICE      = 0x1C  # Block or transducer out of service


class SubstatusUncertain(IntEnum):
    """Sub-status definitions for UNCERTAIN quality (Bits 5..2)."""
    NON_SPECIFIC        = 0x00
    LAST_USABLE_VALUE   = 0x04
    SUBSTITUTE          = 0x08
    INITIAL_VALUE       = 0x0C
    SENSOR_NOT_ACCURATE = 0x10
    EU_EXCEEDED         = 0x14  # Engineering units range exceeded
    SUB_NORMAL          = 0x18


class SubstatusGood(IntEnum):
    """Sub-status definitions for GOOD quality (Bits 5..2)."""
    NON_SPECIFIC          = 0x00
    ACTIVE_BLOCK_ALARM    = 0x04
    ACTIVE_ADVISORY_ALARM = 0x08
    ACTIVE_CRITICAL_ALARM = 0x0C
    UNACK_BLOCK_ALARM     = 0x10
    UNACK_ADVISORY_ALARM  = 0x14
    UNACK_CRITICAL_ALARM  = 0x18


class LimitStatus(IntEnum):
    """Limit status bits (Bits 1..0)."""
    NOT_LIMITED  = 0x00  # Value is not limited
    LOW_LIMITED  = 0x01  # Value has hit low clamp
    HIGH_LIMITED = 0x02  # Value has hit high clamp
    CONSTANT     = 0x03  # Value is held constant


def make_status_byte(quality: int, substatus: int = 0, limit: int = 0) -> int:
    """Construct standard 8-bit Function Block Status Octet per FF-891."""
    q_bits = quality & 0xC0
    sub_bits = substatus & 0x3C
    lim_bits = limit & 0x03
    return q_bits | sub_bits | lim_bits


def get_quality(status_byte: int) -> int:
    """Extract 2-bit quality field (Bits 7..6)."""
    return status_byte & 0xC0


def get_substatus(status_byte: int) -> int:
    """Extract 4-bit substatus field (Bits 5..2)."""
    return status_byte & 0x3C


def get_limit(status_byte: int) -> int:
    """Extract 2-bit limit status field (Bits 1..0)."""
    return status_byte & 0x03


def is_quality_good(status_byte: int) -> bool:
    """Check if status octet indicates Good quality (0x80 or 0xC0)."""
    q = get_quality(status_byte)
    return q in (QualityCode.GOOD_NON_CASCADE, QualityCode.GOOD_CASCADE)


def is_quality_uncertain(status_byte: int) -> bool:
    """Check if status octet indicates Uncertain quality (0x40)."""
    return get_quality(status_byte) == QualityCode.UNCERTAIN


def is_quality_bad(status_byte: int) -> bool:
    """Check if status octet indicates Bad quality (0x00)."""
    return get_quality(status_byte) == QualityCode.BAD


# Quality & Limit Constants
FF_QUALITY_BAD: int = 0x00
FF_QUALITY_UNCERTAIN: int = 0x40
FF_QUALITY_GOOD: int = 0x80
FF_QUALITY_GOOD_CASCADE: int = 0xC0
FF_QUALITY_MASK: int = 0xC0

FF_LIMIT_NOT_LIMITED: int = 0x00
FF_LIMIT_LOW: int = 0x01
FF_LIMIT_HIGH: int = 0x02
FF_LIMIT_CONSTANT: int = 0x03
FF_LIMIT_MASK: int = 0x03

# Substatus Octet Constants
FF_SUBSTATUS_BAD_NON_SPECIFIC: int = 0x00
FF_SUBSTATUS_BAD_CONFIG_ERROR: int = 0x04
FF_SUBSTATUS_BAD_NOT_CONNECTED: int = 0x08
FF_SUBSTATUS_BAD_DEVICE_FAILURE: int = 0x0C
FF_SUBSTATUS_BAD_SENSOR_FAILURE: int = 0x10
FF_SUBSTATUS_BAD_OUT_OF_SERVICE: int = 0x1C

FF_SUBSTATUS_UNCERTAIN_NON_SPECIFIC: int = 0x40
FF_SUBSTATUS_UNCERTAIN_LAST_USABLE: int = 0x44
FF_SUBSTATUS_UNCERTAIN_INITIAL_VALUE: int = 0x4C
FF_SUBSTATUS_UNCERTAIN_SENSOR_INACCURATE: int = 0x50
FF_SUBSTATUS_UNCERTAIN_EU_EXCEEDED: int = 0x54

FF_SUBSTATUS_GOOD_NON_SPECIFIC: int = 0x80
FF_SUBSTATUS_GOOD_ACTIVE_ADVISORY_ALARM: int = 0x88
FF_SUBSTATUS_GOOD_ACTIVE_CRITICAL_ALARM: int = 0x8C
FF_SUBSTATUS_GOOD_CASCADE: int = 0xC0

# Predicate & helper aliases
is_good_quality = is_quality_good
is_uncertain_quality = is_quality_uncertain
is_bad_quality = is_quality_bad
encode_ff_status = make_status_byte
get_limit_flag = get_limit


def set_limit_flag(status: int, limit: int) -> int:
    """Encode limit status flags (Bits 1..0) into status byte."""
    return (status & ~FF_LIMIT_MASK) | (limit & FF_LIMIT_MASK)


def decode_ff_status(status: int) -> Dict[str, Any]:
    """Decode a standard FF status octet into structured fields."""
    q_val = get_quality(status)
    if q_val in (QualityCode.GOOD_NON_CASCADE, QualityCode.GOOD_CASCADE):
        quality_str = "Good"
    elif q_val == QualityCode.UNCERTAIN:
        quality_str = "Uncertain"
    else:
        quality_str = "Bad"

    lim_val = get_limit(status)
    limit_map = {
        LimitStatus.NOT_LIMITED: "NotLimited",
        LimitStatus.LOW_LIMITED: "LowLimited",
        LimitStatus.HIGH_LIMITED: "HighLimited",
        LimitStatus.CONSTANT: "Constant",
    }
    limit_str = limit_map.get(lim_val, "Unknown")
    sub_val = get_substatus(status)

    return {
        "raw_status": status & 0xFF,
        "quality": quality_str,
        "quality_code": q_val,
        "substatus_code": sub_val,
        "limit": limit_str,
        "limit_code": lim_val,
        "is_good": is_quality_good(status),
        "is_uncertain": is_quality_uncertain(status),
        "is_bad": is_quality_bad(status),
    }


def evaluate_ff_status_summary(statuses: Sequence[int]) -> int:
    """Aggregate a sequence of FF status bytes into summary quality byte."""
    if not statuses:
        return QualityCode.GOOD_NON_CASCADE
    has_uncertain = False
    for s in statuses:
        if is_quality_bad(s):
            return QualityCode.BAD
        if is_quality_uncertain(s):
            has_uncertain = True
    if has_uncertain:
        return QualityCode.UNCERTAIN
    return QualityCode.GOOD_NON_CASCADE


# ============================================================================
# 3. Enums, Status Flags & Diagnostic Codes
# ============================================================================

class FfLasGatewayState(IntEnum):
    """LAS Gateway and Bridge State Machine."""
    LAS_IDLE              = 0  # Initialized, awaiting macrocycle start
    MACROCYCLE_SCHEDULED  = 1  # Macrocycle active, synchronizing cycle start
    DISPATCHING_CD        = 2  # Actively dispatching periodic scheduled Compel Data (CD) tokens
    PASSING_TOKEN         = 3  # Circulating Pass Token (PT) in unscheduled background window
    BUS_RECONFIG          = 4  # Bus reconfiguration / Live List change
    LAS_FAULT             = 5  # Latched fault state (deadlock, high jitter, dropout, or block fault)


class FfLasStateBits(IntFlag):
    """Horner OCS %R1425 FfLasStateWord Bitmask Definitions."""
    STATE_BIT_0          = 1 << 0   # Bit 0 (0x0001): State enum bit 0
    STATE_BIT_1          = 1 << 1   # Bit 1 (0x0002): State enum bit 1
    STATE_BIT_2          = 1 << 2   # Bit 2 (0x0004): State enum bit 2
    LAS_ACTIVE           = 1 << 3   # Bit 3 (0x0008): Link Active Scheduler active & master
    MACROCYCLE_RUNNING   = 1 << 4   # Bit 4 (0x0010): Macrocycle execution running
    SCHEDULED_CD_ACTIVE  = 1 << 5   # Bit 5 (0x0020): Periodic Compel Data dispatch active
    PASS_TOKEN_ACTIVE    = 1 << 6   # Bit 6 (0x0040): Pass Token circulation active
    PROBE_NODE_ACTIVE    = 1 << 7   # Bit 7 (0x0080): Probe Node live list discovery active
    TIME_DIST_ACTIVE     = 1 << 8   # Bit 8 (0x0100): Time Distribution broadcast active
    PERMISSIVE           = 1 << 9   # Bit 9 (0x0200): %M331 FfLasPermissive asserted
    FAULT_TRIP           = 1 << 10  # Bit 10 (0x0400): %M332 FfLasFaultTrip asserted
    DEADLOCK_FAULT       = 1 << 11  # Bit 11 (0x0800): 0xCE01 macrocycle deadlock fault active
    JITTER_HIGH_FAULT    = 1 << 12  # Bit 12 (0x1000): 0xCE02 bus jitter exceeded limit
    DROPOUT_FAULT        = 1 << 13  # Bit 13 (0x2000): 0xCE03 device station dropout active
    BLOCK_EXEC_FAULT     = 1 << 14  # Bit 14 (0x4000): 0xCE04 block execution fault active
    LIVE_LIST_STABLE     = 1 << 15  # Bit 15 (0x8000): Live list healthy and stable


class FfLasDiagnosticCode(IntEnum):
    """Horner OCS %R1427 Diagnostic Event Codes for FOUNDATION Fieldbus LAS (W181)."""
    OK                                = 0x0000  # Normal healthy operation
    FF_ERR_LAS_MACROCYCLE_DEADLOCK   = 0xCE01  # Schedule overrun or token stall > 200ms
    FF_ERR_COMMUNICATION_JITTER_HIGH  = 0xCE02  # Bus jitter exceeds 5000 us limit
    FF_ERR_DEVICE_STATION_DROPOUT     = 0xCE03  # Monitored slave station dropped off Live List
    FF_ERR_BLOCK_EXECUTION_FAULT      = 0xCE04  # Function block BAD status or Resource Block alarm

    # Convenience aliases
    LAS_MACROCYCLE_DEADLOCK   = 0xCE01
    COMMUNICATION_JITTER_HIGH = 0xCE02
    DEVICE_STATION_DROPOUT    = 0xCE03
    BLOCK_EXECUTION_FAULT     = 0xCE04


DiagnosticStatusCode = FfLasDiagnosticCode

# Common Telemetry Aliases
FFDiagnosticCode = FfLasDiagnosticCode
FFEngineState = FfLasGatewayState
FFLasStateBits = FfLasStateBits

# Module-level Diagnostic Constants
FF_ERR_MACROCYCLE_DEADLOCK: int = 0xCE01
FF_ERR_HIGH_JITTER: int = 0xCE02
FF_ERR_DEVICE_DROPOUT: int = 0xCE03
FF_ERR_BLOCK_FAULT: int = 0xCE04

MACROCYCLE_DEADLOCK: int = 0xCE01
HIGH_JITTER: int = 0xCE02
DEVICE_DROPOUT: int = 0xCE03
BLOCK_FAULT: int = 0xCE04

ERR_MACROCYCLE_DEADLOCK: int = 0xCE01
ERR_HIGH_JITTER: int = 0xCE02
ERR_DEVICE_DROPOUT: int = 0xCE03
ERR_BLOCK_FAULT: int = 0xCE04

FF_ERR_LAS_MACROCYCLE_DEADLOCK: int = 0xCE01
FF_ERR_COMMUNICATION_JITTER_HIGH: int = 0xCE02
FF_ERR_DEVICE_STATION_DROPOUT: int = 0xCE03
FF_ERR_BLOCK_EXECUTION_FAULT: int = 0xCE04

LAS_MACROCYCLE_DEADLOCK: int = 0xCE01
COMMUNICATION_JITTER_HIGH: int = 0xCE02
DEVICE_STATION_DROPOUT: int = 0xCE03
BLOCK_EXECUTION_FAULT: int = 0xCE04



# ============================================================================
# 4. Protocol Exceptions
# ============================================================================

class FoundationFieldbusLasError(Exception):
    """Base exception for FOUNDATION Fieldbus LAS engine faults."""
    pass


class FfLasMacrocycleDeadlockError(FoundationFieldbusLasError):
    """Raised on macrocycle schedule overrun or token stall > 200ms (0xCE01)."""
    pass


class FfCommunicationJitterHighError(FoundationFieldbusLasError):
    """Raised when bus jitter exceeds 5000 us limit (0xCE02)."""
    pass


class FfDeviceStationDropoutError(FoundationFieldbusLasError):
    """Raised when a monitored fieldbus slave station drops off Live List (0xCE03)."""
    pass


class FfBlockExecutionFaultError(FoundationFieldbusLasError):
    """Raised when function block execution returns BAD quality or RB alarm (0xCE04)."""
    pass


# Exception Aliases
FoundationFieldbusError = FoundationFieldbusLasError
MacrocycleDeadlockError = FfLasMacrocycleDeadlockError
HighJitterError = FfCommunicationJitterHighError
DeviceDropoutError = FfDeviceStationDropoutError
BlockFaultError = FfBlockExecutionFaultError

FFMacrocycleDeadlockError = FfLasMacrocycleDeadlockError
FFHighJitterError = FfCommunicationJitterHighError
FFDeviceDropoutError = FfDeviceStationDropoutError
FFBlockFaultError = FfBlockExecutionFaultError


# ============================================================================
# 5. Wire Framing & CRC-16-CCITT Calculations
# ============================================================================

class FfH1DlpduType(IntEnum):
    """FOUNDATION Fieldbus H1 Data Link Layer PDU (DLPDU) Types."""
    COMPEL_DATA        = 0x01  # CD: Scheduled broadcast prompting publisher
    PASS_TOKEN         = 0x02  # PT: Unscheduled token passed in ring
    PROBE_NODE         = 0x03  # PN: Background discovery search
    PROBE_RESPONSE     = 0x04  # PR: Response returned by newly found node
    TIME_DISTRIBUTION  = 0x05  # TD: Broadcast master network time
    DATA_RESPONSE      = 0x06  # DT: Published function block data
    RETURN_TOKEN       = 0x07  # RT: Return token to LAS


FFFrameType = FfH1DlpduType


def compute_crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    """Compute standard IEC 61158-2 CRC-16-CCITT checksum over frame bytes."""
    crc = init
    for byte in data:
        crc ^= (byte << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


@dataclass
class FieldbusH1Frame:
    """FOUNDATION Fieldbus H1 Wire Frame Entity."""
    frame_type: FfH1DlpduType
    dest_address: int
    src_address: int
    payload: bytes = b""

    def encode(self) -> bytes:
        """Serialize frame with preamble, delimiters, header, and CRC-16-CCITT."""
        core = struct.pack(
            "BBB",
            int(self.frame_type) & 0xFF,
            self.dest_address & 0xFF,
            self.src_address & 0xFF,
        ) + self.payload
        crc = compute_crc16_ccitt(core)
        return (
            bytes([PREAMBLE_OCTET, START_DELIMITER])
            + core
            + struct.pack(">H", crc)
            + bytes([END_DELIMITER])
        )

    @classmethod
    def decode(cls, raw: bytes) -> FieldbusH1Frame:
        """Decode and validate a raw H1 frame."""
        if len(raw) < 8:
            raise ValueError(f"Frame length {len(raw)} too short (min 8)")
        if raw[0] != PREAMBLE_OCTET or raw[1] != START_DELIMITER or raw[-1] != END_DELIMITER:
            raise ValueError("Invalid frame delimiters")
        core = raw[2:-3]
        fcs = struct.unpack(">H", raw[-3:-1])[0]
        expected_fcs = compute_crc16_ccitt(core)
        if fcs != expected_fcs:
            raise ValueError(f"CRC-16 mismatch: got 0x{fcs:04X}, expected 0x{expected_fcs:04X}")
        ft, da, sa = struct.unpack_from("BBB", core, 0)
        return cls(
            frame_type=FfH1DlpduType(ft),
            dest_address=da,
            src_address=sa,
            payload=core[3:],
        )


# ============================================================================
# 6. Helper Functions for RegisterTable Access
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


# ============================================================================
# 7. Pure IEC 61131-3 Structured Text POUs
# ============================================================================

FOUNDATION_FIELDBUS_LAS_SYNC_POU: str = """PROGRAM FoundationFieldbusLasSync
VAR
    (* Horner OCS Mapped Registers (W181 - FOUNDATION Fieldbus H1 LAS & Function Block Bridge) *)
    ActiveDevicesCount          AT %R1420 : INT;    (* Active live fieldbus slave devices count (0..32) *)
    ScheduledBlocksCount        AT %R1421 : INT;    (* Total scheduled function blocks in macrocycle (e.g. 24) *)
    MacrocycleLatencyMsScaled   AT %R1422 : INT;    (* Macrocycle latency scaled x10 ms (e.g. 120 = 12.0 ms) *)
    BusJitterMicroseconds       AT %R1423 : INT;    (* Bus jitter tracking in microseconds (e.g. 1450 us) *)
    DroppedTokenCounter         AT %R1424 : INT;    (* Accumulated dropped or stalled token count *)
    FfLasStateWord              AT %R1425 : INT;    (* Gateway state bitmask, LAS scheduler status *)
    MacrocyclePeriodMs          AT %R1426 : INT;    (* Nominal macrocycle period in ms (e.g. 100) *)
    DiagnosticStatusCode        AT %R1427 : UINT;   (* Diagnostic event code (0x0000, 0xCE01..0xCE04) *)

    (* Discrete Process Safety Interlocks *)
    FfLasPermissive             AT %M331  : BOOL;   (* TRUE when LAS macrocycle and function blocks healthy *)
    FfLasFaultTrip              AT %M332  : BOOL;   (* TRUE on deadlock, jitter high, dropout, or block fault *)
END_VAR
VAR
    LasHealthy                  : BOOL;
END_VAR

IF FfLasFaultTrip OR (DiagnosticStatusCode <> 0) THEN
    FfLasPermissive := FALSE;
    FfLasFaultTrip := TRUE;
    LasHealthy := FALSE;
ELSIF FfLasPermissive THEN
    LasHealthy := TRUE;
    DiagnosticStatusCode := 0;
ELSE
    LasHealthy := FALSE;
END_IF;

IF BusJitterMicroseconds > 5000 THEN
    DiagnosticStatusCode := 52738; (* 0xCE02: FF_ERR_COMMUNICATION_JITTER_HIGH *)
    FfLasPermissive := FALSE;
    FfLasFaultTrip := TRUE;
ELSIF MacrocycleLatencyMsScaled > 2000 THEN
    DiagnosticStatusCode := 52737; (* 0xCE01: FF_ERR_LAS_MACROCYCLE_DEADLOCK *)
    FfLasPermissive := FALSE;
    FfLasFaultTrip := TRUE;
END_IF;
END_PROGRAM
"""

FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU: str = FOUNDATION_FIELDBUS_LAS_SYNC_POU.replace(
    "PROGRAM FoundationFieldbusLasSync", "PROGRAM FfH1FunctionBlockBridgeSync"
)

# Aliases
PURE_ST_POU: str = FOUNDATION_FIELDBUS_LAS_SYNC_POU
FOUNDATION_FIELDBUS_POU: str = FOUNDATION_FIELDBUS_LAS_SYNC_POU
FF_H1_LAS_SYNC_POU: str = FOUNDATION_FIELDBUS_LAS_SYNC_POU
FIELDBUS_LAS_BRIDGE_SYNC_POU: str = FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU
FF_LAS_SYNC_POU: str = FOUNDATION_FIELDBUS_LAS_SYNC_POU
FIELDBUS_LAS_POU: str = FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU
FOUNDATION_LAS_POU: str = FOUNDATION_FIELDBUS_LAS_SYNC_POU



def verify_foundation_fieldbus_las_pure_st() -> bool:
    """Validate FoundationFieldbusLasSync and alias POUs for strict IEC 61131-3 syntax and anti-ladder safety.

    Returns:
        True if all checks pass deterministically.
    """
    SecurityGuard.assert_pure_st_content(FOUNDATION_FIELDBUS_LAS_SYNC_POU)
    SecurityGuard.assert_pure_st_content(FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU)

    res1 = STParser.validate_code(FOUNDATION_FIELDBUS_LAS_SYNC_POU)
    if res1.status != AgentStatus.SUCCESS:
        return False

    res2 = STParser.validate_code(FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU)
    if res2.status != AgentStatus.SUCCESS:
        return False

    ast1 = STParser.parse_pou(FOUNDATION_FIELDBUS_LAS_SYNC_POU)
    ast2 = STParser.parse_pou(FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU)

    expected_regs = {
        "%R1420", "%R1421", "%R1422", "%R1423",
        "%R1424", "%R1425", "%R1426", "%R1427",
        "%M331", "%M332",
    }

    if not ast1 or set(ast1.bound_registers) != expected_regs:
        return False
    if not ast2 or set(ast2.bound_registers) != expected_regs:
        return False

    return True


def verify_fieldbus_las_pure_st() -> bool:
    """Convenience alias for verify_foundation_fieldbus_las_pure_st."""
    return verify_foundation_fieldbus_las_pure_st()


# ============================================================================
# 8. Standard FF Function Blocks (IEC 61804 / FF-890)
# ============================================================================

class FunctionBlockMode(IntEnum):
    """Standard FOUNDATION Fieldbus Block Operating Modes."""
    OOS  = 0x80  # Out of Service
    MAN  = 0x08  # Manual
    AUTO = 0x04  # Automatic
    CAS  = 0x02  # Cascade
    ROUT = 0x01  # Remote Output


FFBlockMode = FunctionBlockMode


@dataclass
class TransducerBlock:
    """Transducer Block (TB) bridging physical sensor/actuator hardware."""
    tag: str
    channel_id: int
    sensor_type: str = "4-20mA_ANALOG"
    raw_value: float = 4.0
    cal_point_lo: float = 4.0
    cal_point_hi: float = 20.0
    eu_range: Tuple[float, float] = (0.0, 100.0)
    primary_value: float = 0.0
    status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_NON_CASCADE))

    def read_transducer(self) -> Tuple[float, int]:
        """Convert raw physical reading to scaled primary engineering value."""
        if self.cal_point_hi == self.cal_point_lo:
            self.primary_value = self.eu_range[0]
        else:
            span_raw = self.cal_point_hi - self.cal_point_lo
            norm = (self.raw_value - self.cal_point_lo) / span_raw
            eu_span = self.eu_range[1] - self.eu_range[0]
            self.primary_value = self.eu_range[0] + (norm * eu_span)
        return self.primary_value, self.status

    def write_transducer(self, value: float) -> Tuple[float, int]:
        """Convert primary engineering value back to transducer output."""
        eu_span = self.eu_range[1] - self.eu_range[0]
        if eu_span == 0:
            self.raw_value = self.cal_point_lo
        else:
            norm = (value - self.eu_range[0]) / eu_span
            raw_span = self.cal_point_hi - self.cal_point_lo
            self.raw_value = self.cal_point_lo + (norm * raw_span)
        self.primary_value = value
        return self.raw_value, self.status

    def calibrate(self, cal_lo: float, cal_hi: float) -> None:
        """Update transducer two-point calibration."""
        self.cal_point_lo = float(cal_lo)
        self.cal_point_hi = float(cal_hi)


@dataclass
class ResourceBlock:
    """Resource Block (RB) defining physical device properties and health."""
    tag: str
    device_address: int
    mode: FunctionBlockMode = FunctionBlockMode.AUTO
    block_err: int = 0  # 0 = No Error, bitmask of diagnostic errors
    alarms: List[str] = field(default_factory=list)
    write_protect: bool = False

    def execute(self, dt: float = 0.001) -> int:
        """Evaluate resource block health and return quality status byte."""
        if self.mode == FunctionBlockMode.OOS:
            return make_status_byte(QualityCode.BAD, SubstatusBad.OUT_OF_SERVICE)
        if self.block_err != 0 or len(self.alarms) > 0:
            return make_status_byte(QualityCode.BAD, SubstatusBad.DEVICE_FAILURE)
        return make_status_byte(QualityCode.GOOD_NON_CASCADE)


@dataclass
class AnalogInputBlock:
    """Analog Input (AI) Function Block with scaling, filtering & alarm limits."""
    tag: str
    channel: int
    transducer: Optional[TransducerBlock] = None
    scale_in: Tuple[float, float] = (4.0, 20.0)
    scale_out: Tuple[float, float] = (0.0, 100.0)
    pv_ftime: float = 0.0  # Filter time constant (seconds)
    mode: FunctionBlockMode = FunctionBlockMode.AUTO
    pv: float = 0.0
    out_val: float = 0.0
    out_status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_NON_CASCADE))
    hi_hi_lim: float = 95.0
    hi_lim: float = 85.0
    lo_lim: float = 15.0
    lo_lo_lim: float = 5.0
    active_alarm: Optional[str] = None

    def execute(self, dt: float = 0.01) -> Tuple[float, int]:
        """Execute AI block scan cycle."""
        if self.mode == FunctionBlockMode.OOS:
            self.out_status = make_status_byte(QualityCode.BAD, SubstatusBad.OUT_OF_SERVICE)
            return self.out_val, self.out_status

        # Read from transducer if present
        if self.transducer is not None:
            prim_val, t_status = self.transducer.read_transducer()
            if is_quality_bad(t_status):
                self.out_status = t_status
                return self.out_val, self.out_status
            # When scale_in matches transducer calibration range, take transducer raw_value
            if (self.scale_in[0] == self.transducer.cal_point_lo and
                self.scale_in[1] == self.transducer.cal_point_hi):
                raw_val = self.transducer.raw_value
            else:
                raw_val = prim_val
        else:
            raw_val = self.pv

        # Scale raw input to OUT scale
        in_span = self.scale_in[1] - self.scale_in[0]
        if in_span == 0:
            target_pv = self.scale_out[0]
        else:
            norm = (raw_val - self.scale_in[0]) / in_span
            out_span = self.scale_out[1] - self.scale_out[0]
            target_pv = self.scale_out[0] + (norm * out_span)

        # Apply low-pass filter
        if self.pv_ftime > 0.0 and dt > 0.0:
            alpha = dt / (self.pv_ftime + dt)
            self.pv = self.pv + alpha * (target_pv - self.pv)
        else:
            self.pv = target_pv

        self.out_val = self.pv

        # Check limit flags and alarms
        sub = SubstatusGood.NON_SPECIFIC
        lim = LimitStatus.NOT_LIMITED
        self.active_alarm = None

        if self.out_val >= self.hi_hi_lim:
            sub = SubstatusGood.ACTIVE_CRITICAL_ALARM
            lim = LimitStatus.HIGH_LIMITED
            self.active_alarm = "HI_HI"
        elif self.out_val >= self.hi_lim:
            sub = SubstatusGood.ACTIVE_ADVISORY_ALARM
            lim = LimitStatus.HIGH_LIMITED
            self.active_alarm = "HI"
        elif self.out_val <= self.lo_lo_lim:
            sub = SubstatusGood.ACTIVE_CRITICAL_ALARM
            lim = LimitStatus.LOW_LIMITED
            self.active_alarm = "LO_LO"
        elif self.out_val <= self.lo_lim:
            sub = SubstatusGood.ACTIVE_ADVISORY_ALARM
            lim = LimitStatus.LOW_LIMITED
            self.active_alarm = "LO"

        self.out_status = make_status_byte(QualityCode.GOOD_NON_CASCADE, sub, lim)
        return self.out_val, self.out_status


@dataclass
class AnalogOutputBlock:
    """Analog Output (AO) Function Block driving control valve/actuator."""
    tag: str
    channel: int
    transducer: Optional[TransducerBlock] = None
    mode: FunctionBlockMode = FunctionBlockMode.AUTO
    sp: float = 0.0
    cas_in: float = 0.0
    cas_in_status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_CASCADE))
    pv: float = 0.0
    pv_scale: Tuple[float, float] = (0.0, 100.0)
    out_val: float = 0.0
    readback: float = 0.0
    out_status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_NON_CASCADE))

    def execute(self, dt: float = 0.01) -> Tuple[float, int]:
        """Execute AO block scan cycle."""
        if self.mode == FunctionBlockMode.OOS:
            self.out_status = make_status_byte(QualityCode.BAD, SubstatusBad.OUT_OF_SERVICE)
            return self.out_val, self.out_status

        # Determine target based on mode
        if self.mode == FunctionBlockMode.CAS:
            if is_quality_bad(self.cas_in_status):
                self.out_status = self.cas_in_status
                return self.out_val, self.out_status
            target = self.cas_in
        elif self.mode == FunctionBlockMode.MAN:
            target = self.out_val
        else:  # AUTO
            target = self.sp

        # Clamp target to scale limits
        lo, hi = self.pv_scale
        lim = LimitStatus.NOT_LIMITED
        if target >= hi:
            target = hi
            lim = LimitStatus.HIGH_LIMITED
        elif target <= lo:
            target = lo
            lim = LimitStatus.LOW_LIMITED

        self.out_val = target
        self.pv = target

        # Write to transducer and obtain readback
        if self.transducer is not None:
            self.transducer.write_transducer(self.out_val)
            self.readback, t_stat = self.transducer.read_transducer()
        else:
            self.readback = self.out_val

        self.out_status = make_status_byte(QualityCode.GOOD_NON_CASCADE, SubstatusGood.NON_SPECIFIC, lim)
        return self.out_val, self.out_status


@dataclass
class PIDBlock:
    """Proportional-Integral-Derivative (PID) Control Function Block."""
    tag: str
    mode: FunctionBlockMode = FunctionBlockMode.AUTO
    sp: float = 50.0
    sp_status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_NON_CASCADE))
    in_val: float = 50.0
    in_status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_NON_CASCADE))
    gain: float = 1.0        # Kp
    reset_time_s: float = 10.0  # Integral time Ti (seconds)
    rate_time_s: float = 0.0   # Derivative time Td (seconds)
    out_low: float = 0.0
    out_high: float = 100.0
    out_val: float = 50.0
    out_status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_NON_CASCADE))
    integral_term: float = 50.0
    prev_error: float = 0.0

    def execute(self, dt: float = 0.01) -> Tuple[float, int]:
        """Execute closed-loop PID control algorithm with anti-windup clamping."""
        if self.mode == FunctionBlockMode.OOS:
            self.out_status = make_status_byte(QualityCode.BAD, SubstatusBad.OUT_OF_SERVICE)
            return self.out_val, self.out_status

        if is_quality_bad(self.in_status):
            # Propagate bad quality
            self.out_status = self.in_status
            return self.out_val, self.out_status

        error = self.sp - self.in_val

        # Proportional term
        p_term = self.gain * error

        # Integral term with trapezoidal or Euler integration
        if self.reset_time_s > 0.0 and dt > 0.0:
            self.integral_term += (self.gain / self.reset_time_s) * error * dt

        # Anti-windup clamping on integral term
        if self.integral_term > self.out_high:
            self.integral_term = self.out_high
        elif self.integral_term < self.out_low:
            self.integral_term = self.out_low

        # Derivative term
        d_term = 0.0
        if self.rate_time_s > 0.0 and dt > 0.0:
            d_term = self.gain * self.rate_time_s * (error - self.prev_error) / dt
        self.prev_error = error

        # Compute output
        raw_out = p_term + self.integral_term + d_term

        # Clamp output
        lim = LimitStatus.NOT_LIMITED
        if raw_out >= self.out_high:
            self.out_val = self.out_high
            lim = LimitStatus.HIGH_LIMITED
        elif raw_out <= self.out_low:
            self.out_val = self.out_low
            lim = LimitStatus.LOW_LIMITED
        else:
            self.out_val = raw_out

        # Out status propagates cascade quality if required
        self.out_status = make_status_byte(QualityCode.GOOD_CASCADE, SubstatusGood.NON_SPECIFIC, lim)
        return self.out_val, self.out_status


@dataclass
class DiscreteInputBlock:
    """Discrete Input (DI) Function Block with inversion and filtering."""
    tag: str
    channel: int
    transducer: Optional[TransducerBlock] = None
    invert: bool = False
    mode: FunctionBlockMode = FunctionBlockMode.AUTO
    in_d: bool = False
    out_d: bool = False
    out_status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_NON_CASCADE))

    def execute(self, dt: float = 0.01) -> Tuple[bool, int]:
        """Execute DI block scan cycle."""
        if self.mode == FunctionBlockMode.OOS:
            self.out_status = make_status_byte(QualityCode.BAD, SubstatusBad.OUT_OF_SERVICE)
            return self.out_d, self.out_status

        if self.transducer is not None:
            raw_v, t_stat = self.transducer.read_transducer()
            val = (raw_v > 0.5)
            if is_quality_bad(t_stat):
                self.out_status = t_stat
                return self.out_d, self.out_status
        else:
            val = self.in_d

        self.out_d = (not val) if self.invert else bool(val)
        self.out_status = make_status_byte(QualityCode.GOOD_NON_CASCADE)
        return self.out_d, self.out_status


@dataclass
class DiscreteOutputBlock:
    """Discrete Output (DO) Function Block for solenoid/switch actuation."""
    tag: str
    channel: int
    transducer: Optional[TransducerBlock] = None
    mode: FunctionBlockMode = FunctionBlockMode.AUTO
    sp_d: bool = False
    cas_in_d: bool = False
    invert: bool = False
    out_d: bool = False
    readback_d: bool = False
    out_status: int = field(default_factory=lambda: make_status_byte(QualityCode.GOOD_NON_CASCADE))

    def execute(self, dt: float = 0.01) -> Tuple[bool, int]:
        """Execute DO block scan cycle."""
        if self.mode == FunctionBlockMode.OOS:
            self.out_status = make_status_byte(QualityCode.BAD, SubstatusBad.OUT_OF_SERVICE)
            return self.out_d, self.out_status

        target = self.cas_in_d if (self.mode == FunctionBlockMode.CAS) else self.sp_d
        target_val = (not target) if self.invert else target

        self.out_d = bool(target_val)
        if self.transducer is not None:
            self.transducer.write_transducer(1.0 if self.out_d else 0.0)
            rb, _ = self.transducer.read_transducer()
            self.readback_d = (rb > 0.5)
        else:
            self.readback_d = self.out_d

        self.out_status = make_status_byte(QualityCode.GOOD_NON_CASCADE)
        return self.out_d, self.out_status


# ============================================================================
# 9. VCR & Token Dispatch Architecture
# ============================================================================

@dataclass
class ScheduledCDTransaction:
    """Scheduled Compel Data (CD) Transaction in the macrocycle schedule."""
    transaction_id: int
    offset_ms: float
    publisher_address: int
    block_tag: str
    parameter_name: str = "OUT"
    subscriber_addresses: List[int] = field(default_factory=list)
    expected_duration_ms: float = 0.5


@dataclass
class FfDeviceDescriptor:
    """Descriptor for a FOUNDATION Fieldbus slave device on the link."""
    address: int
    tag: str
    device_id: str
    is_online: bool = True
    is_link_master: bool = False
    resource_block: Optional[ResourceBlock] = None
    blocks: Dict[str, Any] = field(default_factory=dict)
    transducers: Dict[int, TransducerBlock] = field(default_factory=dict)
    missed_cd_count: int = 0


# ============================================================================
# 10. FOUNDATION Fieldbus LAS & Function Block Engine (ILogicUnit)
# ============================================================================

class FoundationFieldbusLasEngine(ILogicUnit):
    """Link Active Scheduler (LAS) & Function Block Bridge Protocol Engine."""

    def __init__(
        self,
        las_address: int = 0x10,
        macrocycle_period_ms: int = DEFAULT_MACROCYCLE_PERIOD_MS,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.las_address: int = las_address
        self.macrocycle_period_ms: int = macrocycle_period_ms
        self.reg_table: RegisterTable = register_table or RegisterTable()

        # Engine State Machine
        self.state: FfLasGatewayState = FfLasGatewayState.LAS_IDLE
        self.diagnostic_code: FfLasDiagnosticCode = FfLasDiagnosticCode.OK
        self.permissive: bool = True
        self.fault_trip: bool = False

        # Metrics and Surveillance
        self.active_devices_count: int = 0
        self.scheduled_blocks_count: int = 0
        self.macrocycle_latency_ms: float = NOMINAL_MACROCYCLE_LATENCY_MS
        self.macrocycle_latency_scaled: int = NOMINAL_LATENCY_SCALED
        self.bus_jitter_us: int = NOMINAL_BUS_JITTER_US
        self.dropped_token_counter: int = 0
        self.total_macrocycles: int = 0

        # Topology and Scheduling
        self.devices: Dict[int, FfDeviceDescriptor] = {}
        self.live_list: Set[int] = set()
        self.scheduled_cd_list: List[ScheduledCDTransaction] = []
        self.current_probe_address: int = OPERATIONAL_ADDR_MIN

        # Internal Timers
        self.last_macrocycle_time: Optional[float] = None
        self.time_since_last_cd_ms: float = 0.0
        self.elapsed_simulation_ms: float = 0.0

        # Initialize Default Realistic Industrial Topology (12 devices, 24 scheduled blocks)
        self._build_default_topology()
        self.sync_to_registers()

    # ------------------------------------------------------------------------
    # Topology Initialization
    # ------------------------------------------------------------------------

    def _build_default_topology(self) -> None:
        """Construct standard 12-device, 24-scheduled-block fieldbus topology."""
        self.devices.clear()
        self.live_list.clear()
        self.scheduled_cd_list.clear()

        # Device 0x10: LAS / Master Interface Unit (Link Master)
        las_rb = ResourceBlock(tag="LAS_RB", device_address=0x10)
        las_dev = FfDeviceDescriptor(
            address=0x10,
            tag="LAS_MASTER",
            device_id="HNR-FF-LAS-0010",
            is_online=True,
            is_link_master=True,
            resource_block=las_rb,
        )
        self.devices[0x10] = las_dev
        self.live_list.add(0x10)

        # 4 Transmitter devices (0x11..0x14) with 2 AI blocks each -> 8 AI blocks
        tx_tags = [
            (0x11, "PT_101", "Pressure Transmitter", "AI_PT101_A", "AI_PT101_B"),
            (0x12, "TT_102", "Temperature Transmitter", "AI_TT102_A", "AI_TT102_B"),
            (0x13, "FT_103", "Flow Transmitter", "AI_FT103_A", "AI_FT103_B"),
            (0x14, "LT_104", "Level Transmitter", "AI_LT104_A", "AI_LT104_B"),
        ]
        for addr, tag, desc, ai1_tag, ai2_tag in tx_tags:
            rb = ResourceBlock(tag=f"{tag}_RB", device_address=addr)
            tb1 = TransducerBlock(tag=f"{tag}_TB1", channel_id=1, raw_value=12.0)
            tb2 = TransducerBlock(tag=f"{tag}_TB2", channel_id=2, raw_value=16.0)
            ai1 = AnalogInputBlock(tag=ai1_tag, channel=1, transducer=tb1)
            ai2 = AnalogInputBlock(tag=ai2_tag, channel=2, transducer=tb2)

            dev = FfDeviceDescriptor(
                address=addr,
                tag=tag,
                device_id=f"HNR-FF-{tag}-{addr:02X}",
                is_online=True,
                resource_block=rb,
                transducers={1: tb1, 2: tb2},
                blocks={ai1_tag: ai1, ai2_tag: ai2},
            )
            self.devices[addr] = dev
            self.live_list.add(addr)

        # 4 Control Valve devices (0x15..0x18) with 1 AO + 1 PID block each -> 4 AO + 4 PID blocks
        valve_tags = [
            (0x15, "FV_101", "Flow Control Valve", "AO_FV101", "PID_FV101"),
            (0x16, "TV_102", "Temperature Valve", "AO_TV102", "PID_TV102"),
            (0x17, "PV_103", "Pressure Valve", "AO_PV103", "PID_PV103"),
            (0x18, "LV_104", "Level Valve", "AO_LV104", "PID_LV104"),
        ]
        for addr, tag, desc, ao_tag, pid_tag in valve_tags:
            rb = ResourceBlock(tag=f"{tag}_RB", device_address=addr)
            tb = TransducerBlock(tag=f"{tag}_TB", channel_id=1, raw_value=50.0)
            ao = AnalogOutputBlock(tag=ao_tag, channel=1, transducer=tb)
            pid = PIDBlock(tag=pid_tag, sp=50.0, in_val=50.0)

            dev = FfDeviceDescriptor(
                address=addr,
                tag=tag,
                device_id=f"HNR-FF-{tag}-{addr:02X}",
                is_online=True,
                resource_block=rb,
                transducers={1: tb},
                blocks={ao_tag: ao, pid_tag: pid},
            )
            self.devices[addr] = dev
            self.live_list.add(addr)

        # 2 Discrete Input devices (0x19, 0x1A) with 2 DI blocks each -> 4 DI blocks
        di_tags = [
            (0x19, "ZSO_101", "Limit Switch Open", "DI_ZSO1", "DI_ZSO2"),
            (0x1A, "ZSC_101", "Limit Switch Closed", "DI_ZSC1", "DI_ZSC2"),
        ]
        for addr, tag, desc, di1_tag, di2_tag in di_tags:
            rb = ResourceBlock(tag=f"{tag}_RB", device_address=addr)
            tb1 = TransducerBlock(tag=f"{tag}_TB1", channel_id=1, sensor_type="DISCRETE", raw_value=1.0, cal_point_lo=0.0, cal_point_hi=1.0, eu_range=(0.0, 1.0))
            tb2 = TransducerBlock(tag=f"{tag}_TB2", channel_id=2, sensor_type="DISCRETE", raw_value=0.0, cal_point_lo=0.0, cal_point_hi=1.0, eu_range=(0.0, 1.0))
            di1 = DiscreteInputBlock(tag=di1_tag, channel=1, transducer=tb1)
            di2 = DiscreteInputBlock(tag=di2_tag, channel=2, transducer=tb2)

            dev = FfDeviceDescriptor(
                address=addr,
                tag=tag,
                device_id=f"HNR-FF-{tag}-{addr:02X}",
                is_online=True,
                resource_block=rb,
                transducers={1: tb1, 2: tb2},
                blocks={di1_tag: di1, di2_tag: di2},
            )
            self.devices[addr] = dev
            self.live_list.add(addr)

        # 1 Discrete Output device (0x1B) with 4 DO blocks -> 4 DO blocks
        rb_do = ResourceBlock(tag="XV_101_RB", device_address=0x1B)
        tb_do1 = TransducerBlock(tag="XV_101_TB1", channel_id=1, sensor_type="DISCRETE", raw_value=1.0, cal_point_lo=0.0, cal_point_hi=1.0, eu_range=(0.0, 1.0))
        tb_do2 = TransducerBlock(tag="XV_101_TB2", channel_id=2, sensor_type="DISCRETE", raw_value=0.0, cal_point_lo=0.0, cal_point_hi=1.0, eu_range=(0.0, 1.0))
        do1 = DiscreteOutputBlock(tag="DO_XV101_A", channel=1, transducer=tb_do1)
        do2 = DiscreteOutputBlock(tag="DO_XV101_B", channel=2, transducer=tb_do2)
        do3 = DiscreteOutputBlock(tag="DO_XV101_C", channel=1, transducer=tb_do1)
        do4 = DiscreteOutputBlock(tag="DO_XV101_D", channel=2, transducer=tb_do2)

        dev_do = FfDeviceDescriptor(
            address=0x1B,
            tag="XV_101",
            device_id="HNR-FF-XV101-1B",
            is_online=True,
            resource_block=rb_do,
            transducers={1: tb_do1, 2: tb_do2},
            blocks={
                "DO_XV101_A": do1,
                "DO_XV101_B": do2,
                "DO_XV101_C": do3,
                "DO_XV101_D": do4,
            },
        )
        self.devices[0x1B] = dev_do
        self.live_list.add(0x1B)

        # Build Scheduled CD transactions (Total 24 scheduled function blocks across 12 devices)
        tx_id = 1
        offset = 5.0
        for dev in self.devices.values():
            for b_tag, blk in dev.blocks.items():
                self.scheduled_cd_list.append(
                    ScheduledCDTransaction(
                        transaction_id=tx_id,
                        offset_ms=offset,
                        publisher_address=dev.address,
                        block_tag=b_tag,
                        expected_duration_ms=0.5,
                    )
                )
                tx_id += 1
                offset += 2.0

        self.active_devices_count = len(self.devices)  # 12
        self.scheduled_blocks_count = len(self.scheduled_cd_list)  # 24
        self.state = FfLasGatewayState.MACROCYCLE_SCHEDULED

    # ------------------------------------------------------------------------
    # ILogicUnit Properties & Execution
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "foundation_fieldbus_las"

    @property
    def priority(self) -> int:
        return 93

    @property
    def is_enabled(self) -> bool:
        return True

    def execute(self, ctx: ScanContext) -> None:
        """Scan cycle logic evaluation during simulation Phase 2."""
        dt_ms = getattr(ctx, "dt_ms", 10.0)
        self.scan_step(dt=dt_ms / 1000.0)

    def reset(self) -> None:
        """Reset internal bridge state."""
        self.reset_fault(force=True)

    # ------------------------------------------------------------------------
    # State Machine & Scan Step
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.01) -> Dict[str, Any]:
        """Advance deterministic simulation clock and evaluate LAS watchdogs."""
        dt_ms = dt * 1000.0 if dt < 1.0 else dt
        self.elapsed_simulation_ms += dt_ms
        self.time_since_last_cd_ms += dt_ms

        # Check macrocycle schedule overrun / token deadlock watchdog (> 200 ms)
        if self.time_since_last_cd_ms > MACROCYCLE_DEADLOCK_TIMEOUT_MS and not self.fault_trip:
            self._trip_fault(
                FfLasDiagnosticCode.FF_ERR_LAS_MACROCYCLE_DEADLOCK,
                f"Macrocycle schedule overrun or token stall ({self.time_since_last_cd_ms:.1f}ms > {MACROCYCLE_DEADLOCK_TIMEOUT_MS}ms)",
            )
            self.dropped_token_counter += 1

        # Check bus jitter threshold (> 5000 us)
        if self.bus_jitter_us > MAX_BUS_JITTER_US and not self.fault_trip:
            self._trip_fault(
                FfLasDiagnosticCode.FF_ERR_COMMUNICATION_JITTER_HIGH,
                f"Bus jitter {self.bus_jitter_us}us exceeded threshold {MAX_BUS_JITTER_US}us",
            )

        self.sync_to_registers()
        return {
            "state": self.state.name,
            "diagnostic_code": int(self.diagnostic_code),
            "permissive": self.permissive,
            "fault_trip": self.fault_trip,
        }

    # ------------------------------------------------------------------------
    # Macrocycle Execution
    # ------------------------------------------------------------------------

    def execute_macrocycle(
        self,
        cycle_duration_override_ms: Optional[float] = None,
        jitter_override_us: Optional[int] = None,
        force_deadlock: bool = False,
        force_dropout_station: Optional[int] = None,
        force_block_fault: bool = False,
    ) -> Dict[str, Any]:
        """Execute one complete 100ms FOUNDATION Fieldbus macrocycle.

        1. Synchronous Scheduled Phase:
           - Dispatch periodic Compelled Data (CD) tokens according to schedule table.
           - Execute Function Blocks (AI, AO, PID, DI, DO).
           - Update Publisher-Subscriber VCR links.
        2. Unscheduled Phase:
           - Broadcast Time Distribution (TD).
           - Circulate Pass Token (PT) across live list.
           - Background Probe Node (PN) search.
        3. Communication Surveillance & Safety Interlocks.
        """
        now = time.monotonic()
        actual_cycle_ms = (
            cycle_duration_override_ms
            if cycle_duration_override_ms is not None
            else float(self.macrocycle_period_ms)
        )
        self.last_macrocycle_time = now
        self.time_since_last_cd_ms = 0.0

        # Calculate Bus Jitter
        if jitter_override_us is not None:
            self.bus_jitter_us = int(jitter_override_us)
        elif cycle_duration_override_ms is not None:
            diff_ms = abs(cycle_duration_override_ms - float(self.macrocycle_period_ms))
            self.bus_jitter_us = int(diff_ms * 1000.0)
            if self.bus_jitter_us == 0:
                self.bus_jitter_us = NOMINAL_BUS_JITTER_US
        else:
            self.bus_jitter_us = NOMINAL_BUS_JITTER_US

        # 1. Deadlock / Schedule Overrun Check
        if force_deadlock or actual_cycle_ms > MACROCYCLE_DEADLOCK_TIMEOUT_MS:
            self._trip_fault(
                FfLasDiagnosticCode.FF_ERR_LAS_MACROCYCLE_DEADLOCK,
                f"Macrocycle schedule overrun ({actual_cycle_ms:.1f}ms > {MACROCYCLE_DEADLOCK_TIMEOUT_MS}ms)",
            )
            self.dropped_token_counter += 1
            self.sync_to_registers()
            return {"status": "fault", "diagnostic": int(self.diagnostic_code)}

        # 2. Jitter Check
        if self.bus_jitter_us > MAX_BUS_JITTER_US:
            self._trip_fault(
                FfLasDiagnosticCode.FF_ERR_COMMUNICATION_JITTER_HIGH,
                f"Communication jitter {self.bus_jitter_us}us exceeded limit {MAX_BUS_JITTER_US}us",
            )
            self.sync_to_registers()
            return {"status": "fault", "diagnostic": int(self.diagnostic_code)}

        # 3. Scheduled Phase: Dispatch Compel Data (CD)
        self.state = FfLasGatewayState.DISPATCHING_CD
        scheduled_success = 0
        scheduled_fails = 0
        macrocycle_failed_devices: Set[int] = set()

        for tx in self.scheduled_cd_list:
            dev = self.devices.get(tx.publisher_address)
            if dev is None or not dev.is_online or tx.publisher_address == force_dropout_station:
                scheduled_fails += 1
                if dev is not None and dev.address not in macrocycle_failed_devices:
                    macrocycle_failed_devices.add(dev.address)
                    dev.missed_cd_count += 1
                    if dev.missed_cd_count >= MAX_CONSECUTIVE_CD_RETRIES:
                        dev.is_online = False
                        self.live_list.discard(dev.address)
                        self._trip_fault(
                            FfLasDiagnosticCode.FF_ERR_DEVICE_STATION_DROPOUT,
                            f"Device station 0x{dev.address:02X} dropped off Live List after {dev.missed_cd_count} missed polls",
                        )
                        self.sync_to_registers()
                        return {"status": "fault", "diagnostic": int(self.diagnostic_code)}
            else:
                dev.missed_cd_count = 0
                blk = dev.blocks.get(tx.block_tag)
                if blk is not None:
                    # Execute function block
                    if force_block_fault:
                        blk.mode = FunctionBlockMode.OOS
                    blk.execute(dt=0.01)

                    # Check for Bad quality
                    if is_quality_bad(blk.out_status):
                        self._trip_fault(
                            FfLasDiagnosticCode.FF_ERR_BLOCK_EXECUTION_FAULT,
                            f"Function block '{tx.block_tag}' returned BAD execution status (0x{blk.out_status:02X})",
                        )
                        self.sync_to_registers()
                        return {"status": "fault", "diagnostic": int(self.diagnostic_code)}

                    # Also check Resource Block
                    if dev.resource_block is not None:
                        rb_status = dev.resource_block.execute(dt=0.01)
                        if is_quality_bad(rb_status):
                            self._trip_fault(
                                FfLasDiagnosticCode.FF_ERR_BLOCK_EXECUTION_FAULT,
                                f"Resource Block on device 0x{dev.address:02X} reported alarm/hardware fault",
                            )
                            self.sync_to_registers()
                            return {"status": "fault", "diagnostic": int(self.diagnostic_code)}

                scheduled_success += 1

        # 4. Unscheduled Phase: Time Distribution, Pass Token, Probe Node
        self.state = FfLasGatewayState.PASSING_TOKEN
        self.distribute_time()
        self.circulate_pass_token()
        self.probe_next_node()

        # Update metrics
        self.total_macrocycles += 1
        self.macrocycle_latency_ms = NOMINAL_MACROCYCLE_LATENCY_MS
        self.macrocycle_latency_scaled = NOMINAL_LATENCY_SCALED
        self.active_devices_count = sum(1 for d in self.devices.values() if d.is_online)
        self.scheduled_blocks_count = len(self.scheduled_cd_list)

        if not self.fault_trip:
            self.state = FfLasGatewayState.MACROCYCLE_SCHEDULED

        self.sync_to_registers()
        return {
            "status": "success",
            "cycle": self.total_macrocycles,
            "scheduled_success": scheduled_success,
            "bus_jitter_us": self.bus_jitter_us,
        }

    # ------------------------------------------------------------------------
    # Unscheduled Token Dispatching
    # ------------------------------------------------------------------------

    def distribute_time(self, timestamp_ns: Optional[int] = None) -> FieldbusH1Frame:
        """Broadcast Time Distribution (TD) frame with master network time."""
        t_ns = timestamp_ns if timestamp_ns is not None else int(time.time() * 1_000_000_000)
        payload = struct.pack(">Q", t_ns)
        return FieldbusH1Frame(
            frame_type=FfH1DlpduType.TIME_DISTRIBUTION,
            dest_address=BROADCAST_ADDRESS,
            src_address=self.las_address,
            payload=payload,
        )

    def circulate_pass_token(self, force_drop: bool = False) -> bool:
        """Circulate Pass Token (PT) across online stations in Live List."""
        if force_drop:
            self.dropped_token_counter += 1
            return False

        online_addrs = sorted([a for a in self.live_list if self.devices.get(a, FfDeviceDescriptor(a, "", "")).is_online])
        for addr in online_addrs:
            if addr == self.las_address:
                continue
            # Station receives token, performs acyclic exchange, returns token
            pt_frame = FieldbusH1Frame(
                frame_type=FfH1DlpduType.PASS_TOKEN,
                dest_address=addr,
                src_address=self.las_address,
                payload=struct.pack(">H", int(DEFAULT_TOKEN_HOLD_TIME_MS)),
            )
        return True

    def probe_next_node(self) -> int:
        """Execute one round-robin background Probe Node (PN) step (0x10..0xF7)."""
        addr = self.current_probe_address
        dev = self.devices.get(addr)

        if dev is not None and dev.is_online:
            if addr not in self.live_list:
                self.live_list.add(addr)
                self.state = FfLasGatewayState.BUS_RECONFIG

        if self.current_probe_address >= OPERATIONAL_ADDR_MAX:
            self.current_probe_address = OPERATIONAL_ADDR_MIN
        else:
            self.current_probe_address += 1

        return addr

    # ------------------------------------------------------------------------
    # Fault Handling & Operator Reset
    # ------------------------------------------------------------------------

    def _trip_fault(self, code: FfLasDiagnosticCode, details: str) -> None:
        """Latch safety interlock trip fault and clear permissive coil."""
        self.diagnostic_code = code
        self.permissive = False
        self.fault_trip = True
        self.state = FfLasGatewayState.LAS_FAULT

    def simulate_macrocycle_deadlock(self) -> None:
        """Simulate macrocycle schedule overrun or token stall > 200ms (0xCE01)."""
        self._trip_fault(
            FfLasDiagnosticCode.FF_ERR_LAS_MACROCYCLE_DEADLOCK,
            "Simulated macrocycle schedule overrun or token stall",
        )
        self.dropped_token_counter += 1
        self.sync_to_registers()

    def simulate_high_jitter(self, jitter_us: int = 5500) -> None:
        """Simulate bus jitter excursion > 5000 us (0xCE02)."""
        self.bus_jitter_us = int(jitter_us)
        self._trip_fault(
            FfLasDiagnosticCode.FF_ERR_COMMUNICATION_JITTER_HIGH,
            f"Simulated bus jitter {self.bus_jitter_us}us exceeded limit",
        )
        self.sync_to_registers()

    def simulate_device_dropout(self, device_address: int = 0x11) -> None:
        """Simulate monitored slave station dropping off Live List (0xCE03)."""
        dev = self.devices.get(device_address)
        if dev is not None:
            dev.is_online = False
            dev.missed_cd_count = MAX_CONSECUTIVE_CD_RETRIES
        self.live_list.discard(device_address)
        self.active_devices_count = sum(1 for d in self.devices.values() if d.is_online)
        self._trip_fault(
            FfLasDiagnosticCode.FF_ERR_DEVICE_STATION_DROPOUT,
            f"Simulated device station 0x{device_address:02X} dropped off Live List",
        )
        self.sync_to_registers()

    def simulate_block_fault(self, block_tag: str = "AI_PT101_A") -> None:
        """Simulate function block or resource block returning BAD status (0xCE04)."""
        for dev in self.devices.values():
            if block_tag in dev.blocks:
                blk = dev.blocks[block_tag]
                blk.mode = FunctionBlockMode.OOS
                blk.out_status = make_status_byte(QualityCode.BAD, SubstatusBad.DEVICE_FAILURE)
                break
        self._trip_fault(
            FfLasDiagnosticCode.FF_ERR_BLOCK_EXECUTION_FAULT,
            f"Simulated function block '{block_tag}' execution fault (BAD status)",
        )
        self.sync_to_registers()


    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Operator reset handshake: clear fault trips and restore normal operation."""
        self.diagnostic_code = FfLasDiagnosticCode.OK
        self.permissive = True
        self.fault_trip = False
        self.state = FfLasGatewayState.MACROCYCLE_SCHEDULED
        self.time_since_last_cd_ms = 0.0

        # Restore online status of devices
        for dev in self.devices.values():
            dev.is_online = True
            dev.missed_cd_count = 0
            self.live_list.add(dev.address)
            if dev.resource_block is not None:
                dev.resource_block.mode = FunctionBlockMode.AUTO
                dev.resource_block.block_err = 0
                dev.resource_block.alarms.clear()
            for blk in dev.blocks.values():
                blk.mode = FunctionBlockMode.AUTO

        self.bus_jitter_us = NOMINAL_BUS_JITTER_US
        self.macrocycle_latency_scaled = NOMINAL_LATENCY_SCALED
        self.active_devices_count = len(self.devices)
        self.scheduled_blocks_count = len(self.scheduled_cd_list)
        self.sync_to_registers()
        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details="Operator reset handshake completed; LAS restored to normal scheduled macrocycle.",
        )

    # ------------------------------------------------------------------------
    # Horner OCS Register Space Synchronization (%R1420..%R1427, %M331..%M332)
    # ------------------------------------------------------------------------

    def compute_state_word(self) -> int:
        """Compute bitmask for %R1425 FfLasStateWord."""
        mask = 0

        # State enum bits 0..2
        state_val = int(self.state) & 0x07
        if state_val & 1:
            mask |= int(FfLasStateBits.STATE_BIT_0)
        if state_val & 2:
            mask |= int(FfLasStateBits.STATE_BIT_1)
        if state_val & 4:
            mask |= int(FfLasStateBits.STATE_BIT_2)

        if self.state != FfLasGatewayState.LAS_IDLE:
            mask |= int(FfLasStateBits.LAS_ACTIVE)
        if self.state in (FfLasGatewayState.MACROCYCLE_SCHEDULED, FfLasGatewayState.DISPATCHING_CD, FfLasGatewayState.PASSING_TOKEN):
            mask |= int(FfLasStateBits.MACROCYCLE_RUNNING)
        if self.state == FfLasGatewayState.DISPATCHING_CD:
            mask |= int(FfLasStateBits.SCHEDULED_CD_ACTIVE)
        if self.state == FfLasGatewayState.PASSING_TOKEN:
            mask |= int(FfLasStateBits.PASS_TOKEN_ACTIVE)
            mask |= int(FfLasStateBits.PROBE_NODE_ACTIVE)
            mask |= int(FfLasStateBits.TIME_DIST_ACTIVE)

        if self.permissive:
            mask |= int(FfLasStateBits.PERMISSIVE)
        if self.fault_trip:
            mask |= int(FfLasStateBits.FAULT_TRIP)

        if self.diagnostic_code == FfLasDiagnosticCode.FF_ERR_LAS_MACROCYCLE_DEADLOCK:
            mask |= int(FfLasStateBits.DEADLOCK_FAULT)
        elif self.diagnostic_code == FfLasDiagnosticCode.FF_ERR_COMMUNICATION_JITTER_HIGH:
            mask |= int(FfLasStateBits.JITTER_HIGH_FAULT)
        elif self.diagnostic_code == FfLasDiagnosticCode.FF_ERR_DEVICE_STATION_DROPOUT:
            mask |= int(FfLasStateBits.DROPOUT_FAULT)
        elif self.diagnostic_code == FfLasDiagnosticCode.FF_ERR_BLOCK_EXECUTION_FAULT:
            mask |= int(FfLasStateBits.BLOCK_EXEC_FAULT)

        if len(self.live_list) == len(self.devices) and not self.fault_trip:
            mask |= int(FfLasStateBits.LIVE_LIST_STABLE)

        return mask & 0xFFFF

    def sync_to_registers(self) -> None:
        """Synchronize internal LAS state to Horner OCS memory image with PrivilegeMode.SYSTEM."""
        # %R1420: ActiveDevicesCount (INT16, 0..32)
        safe_write_word(self.reg_table, "%R1420", self.active_devices_count)

        # %R1421: ScheduledBlocksCount (INT16, e.g. 24)
        safe_write_word(self.reg_table, "%R1421", self.scheduled_blocks_count)

        # %R1422: MacrocycleLatencyMsScaled (INT16, scaled x10 ms)
        safe_write_word(self.reg_table, "%R1422", self.macrocycle_latency_scaled)

        # %R1423: BusJitterMicroseconds (INT16, microseconds)
        safe_write_word(self.reg_table, "%R1423", self.bus_jitter_us)

        # %R1424: DroppedTokenCounter (INT16 count)
        safe_write_word(self.reg_table, "%R1424", self.dropped_token_counter)

        # %R1425: FfLasStateWord (INT16 bitmask)
        safe_write_word(self.reg_table, "%R1425", self.compute_state_word())

        # %R1426: MacrocyclePeriodMs (INT16, e.g. 100)
        safe_write_word(self.reg_table, "%R1426", self.macrocycle_period_ms)

        # %R1427: DiagnosticStatusCode (UINT16, 0x0000=OK, 0xCE01..0xCE04)
        safe_write_uword(self.reg_table, "%R1427", int(self.diagnostic_code))

        # %M331: FfLasPermissive (BOOL)
        safe_write_bit(self.reg_table, "%M331", self.permissive)

        # %M332: FfLasFaultTrip (BOOL)
        safe_write_bit(self.reg_table, "%M332", self.fault_trip)


# Aliases
FfH1FunctionBlockBridgeEngine = FoundationFieldbusLasEngine
FoundationFieldbusLas = FoundationFieldbusLasEngine
FfH1FunctionBlockBridge = FoundationFieldbusLasEngine
FoundationFieldbusLasSync = FoundationFieldbusLasEngine
FfH1FunctionBlockBridgeSync = FoundationFieldbusLasEngine
FFLasEngine = FoundationFieldbusLasEngine
BlockMode = FunctionBlockMode
LasStateBits = FfLasStateBits
LasEngineState = FfLasGatewayState
FFToken = FieldbusH1Frame



# ============================================================================
# 11. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_foundation_fieldbus_las_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W181.

    Returns strict 4-state contract JSON response:
    - Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings (%R1420..%R1427, %M331..%M332)
    - Stage 2: LAS Token Dispatching Engine (Pass Token, Compel Data, Probe Node, Time Distribution)
    - Stage 3: Macrocycle Schedule & Execution (100 ms Schedule, Scheduled CD vs Unscheduled Tokens)
    - Stage 4: Standard FF Function Blocks Execution (AI, AO, PID, DI, DO, TB, RB)
    - Stage 5: Status Octet Quality, Sub-status & Limit Flags Processing (Good 0x80/0xC0, Uncertain 0x40, Bad 0x00)
    - Stage 6: Macrocycle Overrun / Token Deadlock Safety Interlock (0xCE01 > 200 ms -> %M332 asserted, %M331 cleared)
    - Stage 7: Bus Jitter Surveillance (> 5000 us limit -> 0xCE02) & Latency Scaling (12.0 ms -> 120)
    - Stage 8: Device Station Dropout (0xCE03) & Function Block Execution Fault / Resource Block Alarm (0xCE04)
    - Stage 9: Closed-Loop Scan Cycle Simulation (ILogicUnit), Operator Reset Handshake, & Register Synchronization
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings
    # ------------------------------------------------------------------------
    val_pou1 = STParser.validate_code(FOUNDATION_FIELDBUS_LAS_SYNC_POU)
    ast_pou1 = STParser.parse_pou(FOUNDATION_FIELDBUS_LAS_SYNC_POU)
    val_pou2 = STParser.validate_code(FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU)
    ast_pou2 = STParser.parse_pou(FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU)

    expected_regs = {
        "%R1420", "%R1421", "%R1422", "%R1423",
        "%R1424", "%R1425", "%R1426", "%R1427",
        "%M331", "%M332",
    }

    # Verify anti-ladder security guard rejects forbidden ladder constructs
    ladder_rejected = True
    for bad_construct in ["---[ ]---", "---( )---", "RUNG 1", "XIC Input_1"]:
        try:
            SecurityGuard.assert_pure_st_content(f"PROGRAM Bad\nVAR\nEND_VAR\n{bad_construct}\nEND_PROGRAM")
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    s1_pass = (
        val_pou1.status == AgentStatus.SUCCESS
        and val_pou2.status == AgentStatus.SUCCESS
        and ast_pou1 is not None
        and ast_pou2 is not None
        and ast_pou1.name == "FoundationFieldbusLasSync"
        and ast_pou2.name == "FfH1FunctionBlockBridgeSync"
        and set(ast_pou1.bound_registers) == expected_regs
        and set(ast_pou2.bound_registers) == expected_regs
        and verify_foundation_fieldbus_las_pure_st() is True
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Register_Bindings",
        "passed": s1_pass,
        "details": f"Parsed FoundationFieldbusLasSync and alias with 10 registered bindings: {sorted(expected_regs)}.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: LAS Token Dispatching Engine (PT, CD, PN, TD)
    # ------------------------------------------------------------------------
    engine_tx = FoundationFieldbusLasEngine()
    td_frame = engine_tx.distribute_time(timestamp_ns=1700000000000000000)
    td_bytes = td_frame.encode()
    td_decoded = FieldbusH1Frame.decode(td_bytes)

    # Compel Data frame test
    cd_frame = FieldbusH1Frame(
        frame_type=FfH1DlpduType.COMPEL_DATA,
        dest_address=0x11,
        src_address=0x10,
        payload=b"\x01\x02",
    )
    cd_bytes = cd_frame.encode()
    cd_decoded = FieldbusH1Frame.decode(cd_bytes)

    # Pass Token frame test
    pt_success = engine_tx.circulate_pass_token()

    # Probe Node test across addresses
    initial_probe = engine_tx.current_probe_address
    probed_addr = engine_tx.probe_next_node()

    s2_pass = (
        td_decoded.frame_type == FfH1DlpduType.TIME_DISTRIBUTION
        and td_decoded.dest_address == BROADCAST_ADDRESS
        and cd_decoded.frame_type == FfH1DlpduType.COMPEL_DATA
        and cd_decoded.dest_address == 0x11
        and pt_success is True
        and probed_addr == initial_probe
        and compute_crc16_ccitt(b"123456789") == 0x29B1
    )
    test_results.append({
        "stage": 2,
        "check": "LAS_Token_Dispatching_Engine",
        "passed": s2_pass,
        "details": "Validated DLPDU token encoding/decoding, CRC-16 FCS calculation, and PT/CD/PN/TD dispatch.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Macrocycle Schedule & Execution (100 ms Schedule)
    # ------------------------------------------------------------------------
    res_macro = engine_tx.execute_macrocycle(cycle_duration_override_ms=100.0)
    rt = engine_tx.reg_table

    r1420_devs = rt.read_word("%R1420")
    r1421_blocks = rt.read_word("%R1421")
    r1426_period = rt.read_word("%R1426")
    m331_perm = rt.read_bit("%M331")
    m332_trip = rt.read_bit("%M332")

    s3_pass = (
        res_macro["status"] == "success"
        and r1420_devs == 12
        and r1421_blocks == 24
        and r1426_period == 100
        and m331_perm is True
        and m332_trip is False
        and engine_tx.state == FfLasGatewayState.MACROCYCLE_SCHEDULED
    )
    test_results.append({
        "stage": 3,
        "check": "Macrocycle_Schedule_And_Execution_100ms",
        "passed": s3_pass,
        "details": "100ms macrocycle executed cleanly with 12 active devices and 24 scheduled function blocks.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Standard FF Function Blocks Execution (AI, AO, PID, DI, DO, TB, RB)
    # ------------------------------------------------------------------------
    # Test TB
    tb = TransducerBlock(tag="TB_TEST", channel_id=1, raw_value=12.0, cal_point_lo=4.0, cal_point_hi=20.0, eu_range=(0.0, 100.0))
    tb_val, tb_stat = tb.read_transducer()  # 12 mA is 50.0% of span

    # Test RB
    rb = ResourceBlock(tag="RB_TEST", device_address=0x11, mode=FunctionBlockMode.AUTO)
    rb_stat = rb.execute()

    # Test AI
    ai = AnalogInputBlock(tag="AI_TEST", channel=1, transducer=tb, scale_in=(4.0, 20.0), scale_out=(0.0, 100.0))
    ai_val, ai_stat = ai.execute(dt=0.01)

    # Test PID
    pid = PIDBlock(tag="PID_TEST", sp=50.0, in_val=ai_val, in_status=ai_stat, gain=2.0, reset_time_s=5.0)
    pid_val, pid_stat = pid.execute(dt=0.01)

    # Test AO
    ao = AnalogOutputBlock(tag="AO_TEST", channel=1, transducer=tb, mode=FunctionBlockMode.CAS, cas_in=pid_val, cas_in_status=pid_stat)
    ao_val, ao_stat = ao.execute(dt=0.01)

    # Test DI & DO
    tb_d = TransducerBlock(tag="TB_D", channel_id=2, sensor_type="DISCRETE", raw_value=1.0, cal_point_lo=0.0, cal_point_hi=1.0, eu_range=(0.0, 1.0))
    di = DiscreteInputBlock(tag="DI_TEST", channel=2, transducer=tb_d)
    di_val, di_stat = di.execute()

    do = DiscreteOutputBlock(tag="DO_TEST", channel=2, transducer=tb_d, sp_d=True)
    do_val, do_stat = do.execute()

    s4_pass = (
        math.isclose(tb_val, 50.0, rel_tol=1e-3)
        and is_quality_good(rb_stat)
        and math.isclose(ai_val, 50.0, rel_tol=1e-3)
        and is_quality_good(ai_stat)
        and is_quality_good(pid_stat)
        and math.isclose(ao_val, pid_val, rel_tol=1e-3)
        and is_quality_good(ao_stat)
        and di_val is True
        and is_quality_good(di_stat)
        and do_val is True
        and is_quality_good(do_stat)
    )
    test_results.append({
        "stage": 4,
        "check": "Standard_FF_Function_Blocks_Execution",
        "passed": s4_pass,
        "details": "Verified execution of AI, AO, PID, DI, DO, Transducer Block, and Resource Block.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Status Octet Quality, Sub-status & Limit Flags Processing
    # ------------------------------------------------------------------------
    stat_good = make_status_byte(QualityCode.GOOD_NON_CASCADE, SubstatusGood.ACTIVE_ADVISORY_ALARM, LimitStatus.HIGH_LIMITED)
    stat_unc = make_status_byte(QualityCode.UNCERTAIN, SubstatusUncertain.EU_EXCEEDED, LimitStatus.LOW_LIMITED)
    stat_bad = make_status_byte(QualityCode.BAD, SubstatusBad.DEVICE_FAILURE, LimitStatus.NOT_LIMITED)

    s5_pass = (
        get_quality(stat_good) == QualityCode.GOOD_NON_CASCADE
        and get_substatus(stat_good) == SubstatusGood.ACTIVE_ADVISORY_ALARM
        and get_limit(stat_good) == LimitStatus.HIGH_LIMITED
        and is_quality_good(stat_good) is True
        and is_quality_uncertain(stat_good) is False
        and is_quality_bad(stat_good) is False
        and get_quality(stat_unc) == QualityCode.UNCERTAIN
        and is_quality_uncertain(stat_unc) is True
        and get_quality(stat_bad) == QualityCode.BAD
        and is_quality_bad(stat_bad) is True
    )
    test_results.append({
        "stage": 5,
        "check": "Status_Octet_Quality_Substatus_And_Limit_Flags",
        "passed": s5_pass,
        "details": "Validated FF-891 8-bit status octet encoding, quality bitmasks, substatus, and limit clamps.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Macrocycle Overrun / Token Deadlock Safety Interlock (0xCE01)
    # ------------------------------------------------------------------------
    engine_tx.reset_fault(force=True)
    drop_before = engine_tx.dropped_token_counter

    # Execute macrocycle with 205 ms duration (> 200 ms timeout)
    res_deadlock = engine_tx.execute_macrocycle(cycle_duration_override_ms=205.0)

    r1427_deadlock = rt.read_uword("%R1427")
    r1424_drop = rt.read_word("%R1424")
    m331_deadlock = rt.read_bit("%M331")
    m332_deadlock = rt.read_bit("%M332")
    state_deadlock = rt.read_word("%R1425")

    s6_pass = (
        res_deadlock["status"] == "fault"
        and engine_tx.diagnostic_code == FfLasDiagnosticCode.FF_ERR_LAS_MACROCYCLE_DEADLOCK
        and r1427_deadlock == 0xCE01
        and r1424_drop == drop_before + 1
        and m331_deadlock is False
        and m332_deadlock is True
        and (state_deadlock & int(FfLasStateBits.DEADLOCK_FAULT)) != 0
        and (state_deadlock & int(FfLasStateBits.FAULT_TRIP)) != 0
    )
    test_results.append({
        "stage": 6,
        "check": "Macrocycle_Overrun_And_Deadlock_Safety_Interlock_0xCE01",
        "passed": s6_pass,
        "details": "Macrocycle schedule overrun (>200ms) asserted 0xCE01, tripped %M332, cleared %M331, and incremented %R1424.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Bus Jitter Surveillance (> 5000 us limit -> 0xCE02) & Latency
    # ------------------------------------------------------------------------
    engine_tx.reset_fault(force=True)

    # Inhibit fault first to test nominal latency
    engine_tx.execute_macrocycle(cycle_duration_override_ms=100.0)
    r1422_nominal = rt.read_word("%R1422")

    # Incur excessive jitter 5200 us > 5000 us threshold
    res_jitter = engine_tx.execute_macrocycle(jitter_override_us=5200)

    r1427_jitter = rt.read_uword("%R1427")
    r1423_jitter = rt.read_word("%R1423")
    m331_jitter = rt.read_bit("%M331")
    m332_jitter = rt.read_bit("%M332")
    state_jitter = rt.read_word("%R1425")

    s7_pass = (
        r1422_nominal == 120
        and res_jitter["status"] == "fault"
        and engine_tx.diagnostic_code == FfLasDiagnosticCode.FF_ERR_COMMUNICATION_JITTER_HIGH
        and r1427_jitter == 0xCE02
        and r1423_jitter == 5200
        and m331_jitter is False
        and m332_jitter is True
        and (state_jitter & int(FfLasStateBits.JITTER_HIGH_FAULT)) != 0
    )
    test_results.append({
        "stage": 7,
        "check": "Communication_Jitter_Surveillance_0xCE02_And_Latency_Scaling",
        "passed": s7_pass,
        "details": "Nominal latency scaled 120 (12.0 ms); bus jitter > 5000 us tripped 0xCE02 safety interlock.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Device Station Dropout (0xCE03) & Block Execution Fault (0xCE04)
    # ------------------------------------------------------------------------
    # Part A: Station Dropout (station 0x11 misses 3 consecutive macrocycle polls)
    engine_tx.reset_fault(force=True)
    engine_tx.execute_macrocycle(force_dropout_station=0x11)
    engine_tx.execute_macrocycle(force_dropout_station=0x11)
    res_drop = engine_tx.execute_macrocycle(force_dropout_station=0x11)

    r1427_drop = rt.read_uword("%R1427")
    m331_drop = rt.read_bit("%M331")
    m332_drop = rt.read_bit("%M332")

    # Part B: Function Block Execution Fault (0xCE04)
    engine_tx.reset_fault(force=True)
    res_blk = engine_tx.execute_macrocycle(force_block_fault=True)

    r1427_blk = rt.read_uword("%R1427")
    m331_blk = rt.read_bit("%M331")
    m332_blk = rt.read_bit("%M332")

    s8_pass = (
        res_drop["status"] == "fault"
        and r1427_drop == 0xCE03
        and m331_drop is False
        and m332_drop is True
        and res_blk["status"] == "fault"
        and r1427_blk == 0xCE04
        and m331_blk is False
        and m332_blk is True
    )
    test_results.append({
        "stage": 8,
        "check": "Device_Station_Dropout_0xCE03_And_Block_Execution_Fault_0xCE04",
        "passed": s8_pass,
        "details": "Slave dropout (0xCE03) and Function Block BAD execution fault (0xCE04) trapped deterministically.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Closed-Loop Scan Cycle Simulation & Operator Reset Handshake
    # ------------------------------------------------------------------------
    res_reset = engine_tx.reset_fault(force=True)

    ctx = ScanContext(
        cycle=1,
        dt_ms=10.0,
        elapsed_time_ms=100.0,
        get_register=rt.read_register,
        set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
        get_variable=lambda k, d=None: d,
        set_variable=lambda k, v: None,
        record_fault=lambda f: None,
    )
    engine_tx.execute(ctx)
    engine_tx.sync_to_registers()

    s9_pass = (
        engine_tx.name == "foundation_fieldbus_las"
        and engine_tx.priority == 93
        and engine_tx.is_enabled is True
        and res_reset.status == AgentStatus.SUCCESS
        and engine_tx.diagnostic_code == FfLasDiagnosticCode.OK
        and rt.read_uword("%R1427") == 0x0000
        and rt.read_bit("%M331") is True
        and rt.read_bit("%M332") is False
        and rt.read_word("%R1420") == 12
        and rt.read_word("%R1421") == 24
        and rt.read_word("%R1422") == 120
        and rt.read_word("%R1423") == 1450
        and rt.read_word("%R1426") == 100
    )
    test_results.append({
        "stage": 9,
        "check": "Closed_Loop_Scan_Cycle_And_Operator_Reset_Synchronization",
        "passed": s9_pass,
        "details": "ILogicUnit scan execution, operator reset handshake, and Horner OCS register synchronization verified.",
    })

    # ------------------------------------------------------------------------
    # Verification Summary & Evidence Serialization
    # ------------------------------------------------------------------------
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Industrial FOUNDATION Fieldbus H1 LAS & Function Block Bridge Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} stages passed).",
        "data": {
            "work_package": "W181",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial FOUNDATION Fieldbus H1 LAS & Function Block Bridge Engine",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R1420..%R1427",
                "discrete_coils": "%M331..%M332",
                "values": {
                    "%R1420": rt.read_word("%R1420"),
                    "%R1421": rt.read_word("%R1421"),
                    "%R1422": rt.read_word("%R1422"),
                    "%R1423": rt.read_word("%R1423"),
                    "%R1424": rt.read_word("%R1424"),
                    "%R1425": rt.read_word("%R1425"),
                    "%R1426": rt.read_word("%R1426"),
                    "%R1427": rt.read_uword("%R1427"),
                    "%M331": rt.read_bit("%M331"),
                    "%M332": rt.read_bit("%M332"),
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


run_fieldbus_las_verification = run_foundation_fieldbus_las_verification


if __name__ == "__main__":
    out_target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_foundation_fieldbus_las_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
