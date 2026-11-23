"""Industrial ODVA CIP Sync Profile & IEEE 802.1AS Generalized Precision Time Protocol (gPTP) TSN Engine.

Work Package: W208 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- IEEE 802.1AS-2020: Timing and Synchronization for Time-Sensitive Applications in Bridged Local Area Networks (gPTP).
- ODVA CIP Networks Library Volume 1: Common Industrial Protocol (CIP) - Time Sync Object (Class 0x43).
- IEEE 802.1Qbv-2015: Enhancements for Scheduled Traffic (Time-Aware Shaper / TAS).
- IEEE 802.1Qav-2009: Forwarding and Queuing for Time-Sensitive Streams (Credit-Based Shaper / CBS).
- IEC 61131-3 Programmable Controllers - Part 3: Programming Languages (Structured Text).
- Horner OCS Memory Space: %R1690..%R1697, %M394..%M395.

Architecture:
1. Strict Pure IEC 61131-3 Structured Text POU:
   - 'CipSyncGptpSync' bound to Horner OCS memory space (%R1690..%R1697, %M394..%M395).
   - Anti-ladder security guard: Intercepts ladder constructs with ERR_LADDER_FORBIDDEN
     using SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).

2. IEEE 802.1AS-2020 & ODVA CIP Sync Protocol Implementation:
   - GptpSyncState (IntEnum: UNINITIALIZED=0, INITIALIZING=1, LISTENING=2, SLAVE_LOCKED=3,
     MASTER_GRANDMASTER=4, SYNC_TIMEOUT_FAULT=5, PATH_DELAY_EXCEEDED_FAULT=6).
   - GptpClockClass (IntEnum: PRIMARY_REF=6, HOLDOVER=7, DEGRADED=52, DEFAULT=248, SLAVE_ONLY=255).
   - GptpMessageType (IntEnum: SYNC=0x0, PDELAY_REQ=0x2, PDELAY_RESP=0x3,
     FOLLOW_UP=0x8, PDELAY_RESP_FOLLOW_UP=0xA, ANNOUNCE=0xB, SIGNALING=0xC, MANAGEMENT=0xD).
   - GptpTimestamp dataclass (seconds: int, nanoseconds: int) with full arithmetic (+, -, to_ns, from_ns, to_float_seconds).
   - GptpClockIdentity (EUI-64, 8 bytes hex).
   - GptpClockQuality (clockClass, clockAccuracy, offsetScaledLogVariance).
   - Best Master Clock Algorithm (BMCA) dataset comparison comparing:
     priority1, clockClass (6, 7, 52, 248), clockAccuracy, offsetScaledLogVariance, priority2, clockIdentity.
   - Peer-to-Peer Path Delay Measurement: Pdelay_Req, Pdelay_Resp, Pdelay_Resp_Follow_Up
     calculating turnaround time and mean propagation delay:
     turnaround = t3 - t2
     round_trip = t4 - t1
     mean_path_delay = ((t4 - t1) - (t3 - t2)) // 2
   - Sub-microsecond time offset tracking (target jitter < 1.0 us) via PI clock servo and jitter filter.
   - Time-Sensitive Networking (TSN) alignment with 802.1Qbv time-aware traffic scheduling
     (TAS Gate Control List & Guard Band) and 802.1Qav credit-based shaper (CBS).

3. Process Safety Interlocks & Diagnostics:
   - 0x0000: OK (Normal healthy synchronization)
   - 0xE001: SYNC_TIMEOUT (Missed Sync or Follow_Up messages beyond timeout limit) -> sets %M395, state=5
   - 0xE002: PATH_DELAY_EXCEEDED (Peer-to-peer path delay exceeds limit) -> sets %M395, state=6
   - 0xE003: JITTER_DRIFT_EXCEEDED (Jitter excursion or clock drift rate exceeds threshold) -> sets %M395, clears %M394
   - 0xE004: GRANDMASTER_LOST (BMCA announce timeout expired without valid master) -> sets %M395, clears %M394

4. Horner OCS Memory Space Integration:
   - %R1690: SyncEngineState (INT16, 0..6)
   - %R1691: CurrentTimeSecLow (INT16, low 16 bits of PTP timestamp seconds)
   - %R1692: CurrentTimeSecHigh (INT16, high 16 bits of PTP timestamp seconds)
   - %R1693: SubsecondOffsetNsScaled (INT16 scaled, nanosecond offset from Grandmaster, e.g. -250 ns)
   - %R1694: MeanPathDelayNsScaled (INT16 scaled, link peer-to-peer path delay in ns, e.g. 1450 ns)
   - %R1695: GrandmasterClockClass (INT16, 6, 7, 52, 248)
   - %R1696: SyncHealthScore (INT16, 0..100)
   - %R1697: DiagnosticStatusCode (0x0000=OK, 0xE001..0xE004)
   - %M394: ClockSynchronized (BOOL, True when locked with jitter < 1.0 us)
   - %M395: SyncFaultTrip (BOOL, True on timeout or loss of grandmaster)

5. Deterministic 9-Stage Verification Suite:
   - run_cip_sync_gptp_verification(output_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]
   - Returns strict 4-state contract response: {'status': 'success', 'stages_passed': 9, 'total_stages': 9, 'data': {...}}.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import re
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Timing Definitions (IEEE 802.1AS & ODVA CIP Sync)
# ============================================================================

GPTP_VERSION: int = 2
GPTP_TRANSPORT_SPECIFIC: int = 0x1  # IEEE 802.1AS transportSpecific nibble
CIP_SYNC_CLASS_ID: int = 0x43       # ODVA CIP Time Sync Object Class ID
DEFAULT_DOMAIN_NUMBER: int = 0      # gPTP standard domain number (Domain 0)

DEFAULT_PDELAY_INTERVAL_S: float = 1.0        # 1 Hz nominal Pdelay rate (IEEE 802.1AS)
DEFAULT_SYNC_INTERVAL_S: float = 0.125        # 8 Hz nominal Sync rate (logMessageInterval = -3)
DEFAULT_ANNOUNCE_INTERVAL_S: float = 1.0      # 1 Hz nominal Announce rate (logMessageInterval = 0)
DEFAULT_ANNOUNCE_RECEIPT_TIMEOUT: int = 3     # 3 missed Announce messages = 3.0s
DEFAULT_SYNC_RECEIPT_TIMEOUT_S: float = 1.0   # 1.0s sync timeout limit

DEFAULT_SYNC_THRESHOLD_NS: int = 1000         # 1000 ns (1.0 us) sub-microsecond synchronization threshold
DEFAULT_JITTER_TARGET_NS: float = 1000.0      # Target jitter < 1.0 us
DEFAULT_JITTER_SPIKE_THRESHOLD_NS: int = 15_000 # 15,000 ns (15 us) jitter spike trigger
MAX_ALLOWABLE_PATH_DELAY_NS: int = 50_000     # 50,000 ns (50 us) critical peer-to-peer path delay limit
MAX_SERVO_DRIFT_PPB: int = 32_767             # Clamped to INT16 range (-32768..32767)
DEFAULT_STEP_THRESHOLD_NS: int = 100_000      # 100,000 ns (100 us) step vs slewing boundary
DEFAULT_TSN_CYCLE_TIME_NS: int = 1_000_000     # 1,000,000 ns (1 ms) nominal TSN cycle time

NOMINAL_MEAN_PATH_DELAY_NS: int = 1_450       # 1,450 ns (1.45 us) nominal peer-to-peer path delay


# ============================================================================
# 2. Protocol Enums & Diagnostic Codes
# ============================================================================

class GptpSyncState(IntEnum):
    """IEEE 802.1AS / ODVA CIP Sync Time Synchronization State Machine & %R1690 Values."""
    UNINITIALIZED            = 0  # Engine not initialized or in unconfigured state
    INITIALIZING             = 1  # Startup phase, calibrating local hardware clocks and ports
    LISTENING                = 2  # Listening for gPTP Announce frames from master or peers
    SLAVE_LOCKED             = 3  # Synchronized slave tracking active Grandmaster (jitter < 1.0 us)
    MASTER_GRANDMASTER       = 4  # Clock port acting as Grandmaster transmitting Announce and Sync
    SYNC_TIMEOUT_FAULT       = 5  # Missed Sync / Follow_Up stream beyond timeout threshold
    PATH_DELAY_EXCEEDED_FAULT = 6 # Peer-to-peer path delay exceeded maximum threshold limit

    # Convenience aliases
    Uninitialized = 0
    Initializing = 1
    Listening = 2
    SlaveLocked = 3
    MasterGrandmaster = 4
    SyncTimeoutFault = 5
    PathDelayExceededFault = 6


GptpState = GptpSyncState
GptpPortState = GptpSyncState
PtpPortState = GptpSyncState
PtpClockState = GptpSyncState
CipSyncGptpState = GptpSyncState
SyncEngineState = GptpSyncState


class GptpClockClass(IntEnum):
    """IEEE 802.1AS-2020 / IEEE 1588-2008 Clock Class Definitions (%R1695)."""
    PRIMARY_REF = 6    # Primary reference standard (GPS, PRC atomic clock, time-traceable)
    HOLDOVER    = 7    # Lost primary reference standard, operating within holdover specifications
    DEGRADED    = 52   # Holdover specification exceeded or degraded trace
    DEFAULT     = 248  # Default free-running local oscillator
    SLAVE_ONLY  = 255  # Slave-only clock node (cannot become Grandmaster)

    # Convenience aliases
    PrimaryRef = 6
    Holdover = 7
    Degraded = 52
    Default = 248
    SlaveOnly = 255


ClockClass = GptpClockClass
CipSyncGptpClockClass = GptpClockClass
PtpClockClass = GptpClockClass


class GptpMessageType(IntEnum):
    """IEEE 802.1AS gPTP Message Types (Header messageType nibble)."""
    SYNC                  = 0x0  # Event message: Master egress time t1
    PDELAY_REQ            = 0x2  # Event message: Peer delay request egress time t1
    PDELAY_RESP           = 0x3  # Event message: Peer delay response egress time t3 (carrying t2)
    FOLLOW_UP             = 0x8  # General message: Precise origin timestamp t1 + 802.1AS TLV
    PDELAY_RESP_FOLLOW_UP = 0xA  # General message: Peer delay response follow-up (carrying t3)
    ANNOUNCE              = 0xB  # General message: GM dataset advertising
    SIGNALING             = 0xC  # General message: Unicast / L2 signaling
    MANAGEMENT            = 0xD  # General message: Management query/command


PtpMessageType = GptpMessageType


class GptpDiagnosticCode(IntEnum):
    """Horner OCS %R1697 Diagnostic Event Codes."""
    OK                    = 0x0000  # Normal healthy synchronization
    SYNC_TIMEOUT          = 0xE001  # Missed Sync/Follow_Up messages beyond timeout limit
    PATH_DELAY_EXCEEDED   = 0xE002  # Peer-to-peer path delay exceeded threshold limit
    JITTER_DRIFT_EXCEEDED = 0xE003  # Jitter excursion or clock drift rate exceeds safety limit
    GRANDMASTER_LOST      = 0xE004  # BMCA announce timeout expired without valid Grandmaster

    # Convenience aliases
    ERR_SYNC_TIMEOUT          = 0xE001
    ERR_PATH_DELAY_EXCEEDED   = 0xE002
    ERR_JITTER_DRIFT_EXCEEDED = 0xE003
    ERR_GRANDMASTER_LOST      = 0xE004
    CIP_SYNC_ERR_TIMEOUT      = 0xE001
    CIP_SYNC_ERR_PATH_DELAY   = 0xE002
    CIP_SYNC_ERR_JITTER       = 0xE003
    CIP_SYNC_ERR_GM_LOST      = 0xE004


DiagnosticCode = GptpDiagnosticCode
CipSyncGptpDiagnosticCode = GptpDiagnosticCode
DiagnosticStatusCode = GptpDiagnosticCode
CIPSyncDiagnosticCode = GptpDiagnosticCode
PtpDiagnosticCode = GptpDiagnosticCode


class GptpFlagField(IntFlag):
    """IEEE 802.1AS-2020 Header Flag Field."""
    TWO_STEP                 = 1 << 1   # Bit 1 (0x0002): Two-Step clock flag
    UNICAST                  = 1 << 2   # Bit 2 (0x0004): Unicast transmission
    PTP_TIMESCALE            = 1 << 3   # Bit 3 (0x0008): PTP timescale (always 1 for 802.1AS)
    TIME_TRACEABLE           = 1 << 4   # Bit 4 (0x0010): Time traceable to PRC
    FREQUENCY_TRACEABLE      = 1 << 5   # Bit 5 (0x0020): Frequency traceable
    SYNCHRONIZATION_UNCERTAIN = 1 << 6  # Bit 6 (0x0040): 802.1AS sync uncertainty flag


PtpFlagField = GptpFlagField


# ============================================================================
# 3. GptpTimestamp, TimeInterval, ClockIdentity, & ClockQuality
# ============================================================================

class GptpTimeInterval(int):
    """Time interval or duration in nanoseconds with seconds/nanoseconds accessors."""

    @property
    def seconds(self) -> int:
        """Integral seconds of interval."""
        return int(self) // 1_000_000_000

    @property
    def nanoseconds(self) -> int:
        """Sub-second nanoseconds (0..999_999_999 or signed remainder)."""
        return int(self) % 1_000_000_000

    def to_ns(self) -> int:
        """Return total nanoseconds as int."""
        return int(self)

    def to_float_seconds(self) -> float:
        """Convert duration to floating-point seconds."""
        return int(self) / 1_000_000_000.0


PtpTimeInterval = GptpTimeInterval


@dataclass(order=True)
class GptpTimestamp:
    """IEEE 802.1AS / IEEE 1588-2008 PTP Timestamp (seconds: uint48/int, nanoseconds: uint32)."""
    seconds: int = 0
    nanoseconds: int = 0

    def __post_init__(self) -> None:
        if self.nanoseconds >= 1_000_000_000 or self.nanoseconds < 0:
            sec_add, rem_ns = divmod(self.nanoseconds, 1_000_000_000)
            self.seconds += sec_add
            self.nanoseconds = rem_ns

    def to_ns(self) -> int:
        """Convert timestamp to total nanoseconds since epoch."""
        return self.seconds * 1_000_000_000 + self.nanoseconds

    @classmethod
    def from_ns(cls, total_ns: int) -> GptpTimestamp:
        """Construct GptpTimestamp from total nanoseconds."""
        sec, nsec = divmod(int(total_ns), 1_000_000_000)
        return cls(seconds=sec, nanoseconds=nsec)

    def to_float_seconds(self) -> float:
        """Convert timestamp to floating-point seconds."""
        return self.seconds + (self.nanoseconds / 1_000_000_000.0)

    @classmethod
    def from_float_seconds(cls, val_s: float) -> GptpTimestamp:
        """Construct GptpTimestamp from floating-point seconds."""
        sec = int(math.floor(val_s))
        nsec = int(round((val_s - sec) * 1_000_000_000.0))
        if nsec >= 1_000_000_000:
            sec += 1
            nsec -= 1_000_000_000
        return cls(seconds=sec, nanoseconds=nsec)

    def __add__(self, other: Union[GptpTimestamp, int, float]) -> GptpTimestamp:
        if isinstance(other, GptpTimestamp):
            return GptpTimestamp.from_ns(self.to_ns() + other.to_ns())
        elif isinstance(other, int):
            return GptpTimestamp.from_ns(self.to_ns() + other)
        elif isinstance(other, float):
            return GptpTimestamp.from_float_seconds(self.to_float_seconds() + other)
        return NotImplemented

    def __radd__(self, other: Union[int, float]) -> GptpTimestamp:
        return self.__add__(other)

    def __sub__(self, other: Union[GptpTimestamp, int, float]) -> Union[GptpTimeInterval, GptpTimestamp]:
        if isinstance(other, GptpTimestamp):
            return GptpTimeInterval(self.to_ns() - other.to_ns())
        elif isinstance(other, int):
            return GptpTimestamp.from_ns(self.to_ns() - other)
        elif isinstance(other, float):
            return GptpTimestamp.from_float_seconds(self.to_float_seconds() - other)
        return NotImplemented

    def __rsub__(self, other: Union[int, float]) -> Union[GptpTimeInterval, GptpTimestamp]:
        if isinstance(other, int):
            return GptpTimeInterval(other - self.to_ns())
        elif isinstance(other, float):
            return GptpTimestamp.from_float_seconds(other - self.to_float_seconds())
        return NotImplemented

    def __floordiv__(self, other: int) -> GptpTimestamp:
        return GptpTimestamp.from_ns(self.to_ns() // int(other))

    def __int__(self) -> int:
        return self.to_ns()

    def pack(self) -> bytes:
        """Pack into 10-octet standard IEEE 1588/802.1AS timestamp format."""
        sec_high = (self.seconds >> 32) & 0xFFFF
        sec_low = self.seconds & 0xFFFFFFFF
        return struct.pack(">HII", sec_high, sec_low, self.nanoseconds)

    @classmethod
    def unpack(cls, data: bytes) -> GptpTimestamp:
        """Unpack from 10-octet standard IEEE 1588/802.1AS timestamp format."""
        if len(data) < 10:
            raise ValueError(f"GptpTimestamp requires at least 10 bytes, got {len(data)}")
        sec_high, sec_low, nsec = struct.unpack(">HII", data[:10])
        total_sec = (sec_high << 32) | sec_low
        return cls(seconds=total_sec, nanoseconds=nsec)


GPTPTimestamp = GptpTimestamp
PtpTimestamp = GptpTimestamp


class GptpClockIdentity:
    """IEEE 802.1AS / EUI-64 Clock Identity (8 octets)."""

    def __init__(self, value: Union[str, bytes, bytearray, int, Sequence[int], None] = None) -> None:
        if value is None:
            self._bytes = bytes([0x00, 0x80, 0xC2, 0xFF, 0xFE, 0x00, 0x00, 0x01])
        elif isinstance(value, (bytes, bytearray)):
            if len(value) != 8:
                raise ValueError(f"GptpClockIdentity bytes must be 8 octets, got {len(value)}")
            self._bytes = bytes(value)
        elif isinstance(value, int):
            self._bytes = value.to_bytes(8, byteorder="big", signed=False)
        elif isinstance(value, str):
            clean = re.sub(r"[-:]", "", value.strip())
            if len(clean) != 16:
                raise ValueError(f"GptpClockIdentity hex string must be 16 hex digits (8 octets), got '{value}'")
            self._bytes = bytes.fromhex(clean)
        elif isinstance(value, (list, tuple)):
            if len(value) != 8:
                raise ValueError(f"GptpClockIdentity sequence must have 8 elements, got {len(value)}")
            self._bytes = bytes(value)
        else:
            raise TypeError(f"Unsupported clock identity type: {type(value)}")

    @property
    def raw_bytes(self) -> bytes:
        return self._bytes

    def to_bytes(self) -> bytes:
        return self._bytes

    def to_hex(self, separator: str = "-") -> str:
        return separator.join(f"{b:02X}" for b in self._bytes)

    def to_int(self) -> int:
        return int.from_bytes(self._bytes, byteorder="big", signed=False)

    @classmethod
    def from_mac(cls, mac: str) -> GptpClockIdentity:
        """Convert 48-bit MAC address to 64-bit gPTP Clock Identity (insert 0xFF, 0xFE)."""
        clean = re.sub(r"[-:]", "", mac.strip())
        if len(clean) != 12:
            raise ValueError(f"MAC address must have 12 hex digits, got '{mac}'")
        b = bytes.fromhex(clean)
        eui64 = bytes([b[0], b[1], b[2], 0xFF, 0xFE, b[3], b[4], b[5]])
        return cls(eui64)

    @classmethod
    def default_local(cls) -> GptpClockIdentity:
        return cls("00-80-C2-FF-FE-01-20-80")

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, GptpClockIdentity):
            return self._bytes == other._bytes
        if isinstance(other, (bytes, bytearray)):
            return self._bytes == bytes(other)
        if isinstance(other, str):
            try:
                return self == GptpClockIdentity(other)
            except Exception:
                return False
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, GptpClockIdentity):
            return self.to_int() < other.to_int()
        if isinstance(other, str):
            return self.to_int() < GptpClockIdentity(other).to_int()
        return NotImplemented

    def __le__(self, other: Any) -> bool:
        return self == other or self < other

    def __gt__(self, other: Any) -> bool:
        if isinstance(other, GptpClockIdentity):
            return self.to_int() > other.to_int()
        if isinstance(other, str):
            return self.to_int() > GptpClockIdentity(other).to_int()
        return NotImplemented

    def __ge__(self, other: Any) -> bool:
        return self == other or self > other

    def __hash__(self) -> int:
        return hash(self._bytes)

    def __str__(self) -> str:
        return self.to_hex()

    def __repr__(self) -> str:
        return f"GptpClockIdentity('{self.to_hex()}')"


GPTPClockIdentity = GptpClockIdentity
PtpClockIdentity = GptpClockIdentity


@dataclass
class GptpClockQuality:
    """IEEE 802.1AS / IEEE 1588 Clock Quality descriptor."""
    clockClass: int = int(GptpClockClass.DEFAULT)
    clockAccuracy: int = 0xFE
    offsetScaledLogVariance: int = 0xFFFF

    def __lt__(self, other: GptpClockQuality) -> bool:
        return (self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance) < (
            other.clockClass, other.clockAccuracy, other.offsetScaledLogVariance
        )

    def __le__(self, other: GptpClockQuality) -> bool:
        return (self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance) <= (
            other.clockClass, other.clockAccuracy, other.offsetScaledLogVariance
        )

    def __gt__(self, other: GptpClockQuality) -> bool:
        return (self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance) > (
            other.clockClass, other.clockAccuracy, other.offsetScaledLogVariance
        )

    def __ge__(self, other: GptpClockQuality) -> bool:
        return (self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance) >= (
            other.clockClass, other.clockAccuracy, other.offsetScaledLogVariance
        )

    def pack(self) -> bytes:
        return struct.pack(">BBH", self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance)

    @classmethod
    def unpack(cls, data: bytes) -> GptpClockQuality:
        if len(data) < 4:
            raise ValueError("GptpClockQuality requires at least 4 bytes")
        c_class, c_acc, var = struct.unpack(">BBH", data[:4])
        return cls(clockClass=c_class, clockAccuracy=c_acc, offsetScaledLogVariance=var)


GPTPClockQuality = GptpClockQuality
PtpClockQuality = GptpClockQuality


@dataclass
class GptpPortIdentity:
    """IEEE 802.1AS Port Identity (ClockIdentity 8 bytes + PortNumber 2 bytes)."""
    clockIdentity: GptpClockIdentity = field(default_factory=GptpClockIdentity)
    portNumber: int = 1

    def pack(self) -> bytes:
        return self.clockIdentity.to_bytes() + struct.pack(">H", self.portNumber)

    @classmethod
    def unpack(cls, data: bytes) -> GptpPortIdentity:
        if len(data) < 10:
            raise ValueError("GptpPortIdentity requires 10 bytes")
        cid = GptpClockIdentity(data[:8])
        pnum = struct.unpack(">H", data[8:10])[0]
        return cls(clockIdentity=cid, portNumber=pnum)


GPTPPortIdentity = GptpPortIdentity
PtpPortIdentity = GptpPortIdentity


# ============================================================================
# 4. Best Master Clock Algorithm (BMCA) & Dataset Definitions
# ============================================================================

@dataclass
class GptpDataset:
    """Dataset descriptor used in IEEE 802.1AS Best Master Clock Algorithm (BMCA)."""
    priority1: int = 128
    clockQuality: GptpClockQuality = field(default_factory=GptpClockQuality)
    priority2: int = 128
    clockIdentity: GptpClockIdentity = field(default_factory=GptpClockIdentity)
    stepsRemoved: int = 0


GPTPDataset = GptpDataset
PtpDataset = GptpDataset


class BestMasterClockAlgorithm:
    """IEEE 802.1AS-2020 / IEEE 1588-2008 Best Master Clock Algorithm (BMCA) logic."""

    @staticmethod
    def compare_datasets(a: GptpDataset, b: GptpDataset) -> int:
        """Compare datasets A and B per IEEE 802.1AS clause 10.3 and IEEE 1588 clause 9.3.4.

        Evaluation Priority:
        1. priority1 (lower integer wins)
        2. clockClass (6=Primary Ref, 7=Holdover, 52=Degraded, 248=Default, 255=Slave Only)
        3. clockAccuracy (lower integer wins)
        4. offsetScaledLogVariance (lower integer wins)
        5. priority2 (lower integer wins)
        6. stepsRemoved (lower network hops wins)
        7. clockIdentity (lower numerical value is tie-breaker)

        Returns:
            -1 if dataset A is better (wins)
             1 if dataset B is better (wins)
             0 if datasets are identical
        """
        # 1. priority1
        if a.priority1 < b.priority1:
            return -1
        if a.priority1 > b.priority1:
            return 1

        # 2. clockClass (6 < 7 < 52 < 248 < 255)
        if a.clockQuality.clockClass < b.clockQuality.clockClass:
            return -1
        if a.clockQuality.clockClass > b.clockQuality.clockClass:
            return 1

        # 3. clockAccuracy
        if a.clockQuality.clockAccuracy < b.clockQuality.clockAccuracy:
            return -1
        if a.clockQuality.clockAccuracy > b.clockQuality.clockAccuracy:
            return 1

        # 4. offsetScaledLogVariance
        if a.clockQuality.offsetScaledLogVariance < b.clockQuality.offsetScaledLogVariance:
            return -1
        if a.clockQuality.offsetScaledLogVariance > b.clockQuality.offsetScaledLogVariance:
            return 1

        # 5. priority2
        if a.priority2 < b.priority2:
            return -1
        if a.priority2 > b.priority2:
            return 1

        # 6. stepsRemoved
        if a.stepsRemoved < b.stepsRemoved:
            return -1
        if a.stepsRemoved > b.stepsRemoved:
            return 1

        # 7. clockIdentity
        if a.clockIdentity < b.clockIdentity:
            return -1
        if a.clockIdentity > b.clockIdentity:
            return 1

        return 0

    @classmethod
    def select_master(
        cls,
        local_dataset: GptpDataset,
        foreign_datasets: Sequence[GptpDataset],
    ) -> Tuple[GptpDataset, bool]:
        """Evaluate BMCA across local dataset and foreign announces.

        Returns:
            (best_dataset, is_local_master)
        """
        best = local_dataset
        is_local = True

        for foreign in foreign_datasets:
            if cls.compare_datasets(foreign, best) < 0:
                best = foreign
                is_local = False

        return best, is_local


BMCA = BestMasterClockAlgorithm
GptpBMCA = BestMasterClockAlgorithm


# ============================================================================
# 5. Clock PI Servo Controller & Jitter Filter
# ============================================================================

class GptpServo:
    """Proportional-Integral (PI) Clock Servo Controller for sub-microsecond gPTP synchronization."""

    def __init__(
        self,
        kp: float = 0.6,
        ki: float = 1.0,
        step_threshold_ns: int = DEFAULT_STEP_THRESHOLD_NS,
        max_drift_ppb: int = MAX_SERVO_DRIFT_PPB,
        jitter_spike_threshold_ns: int = DEFAULT_JITTER_SPIKE_THRESHOLD_NS,
        target_jitter_ns: float = DEFAULT_JITTER_TARGET_NS,
    ) -> None:
        self.kp = float(kp)
        self.ki = float(ki)
        self.step_threshold_ns = int(step_threshold_ns)
        self.max_drift_ppb = int(max_drift_ppb)
        self.jitter_spike_threshold_ns = int(jitter_spike_threshold_ns)
        self.target_jitter_ns = float(target_jitter_ns)

        self.integral_error: float = 0.0
        self.frequency_drift_ppb: int = 0
        self.last_offset_ns: int = 0
        self.jitter_spike_count: int = 0
        self.last_phase_adj_ns: int = 0
        self.is_locked: bool = False
        self.current_jitter_ns: float = 0.0

        # Circular buffer for recent offsets
        self.recent_offsets: List[int] = []
        self._max_history: int = 16

    def reset(self) -> None:
        """Reset internal servo state, drift counters, and offset history."""
        self.integral_error = 0.0
        self.frequency_drift_ppb = 0
        self.last_offset_ns = 0
        self.jitter_spike_count = 0
        self.last_phase_adj_ns = 0
        self.is_locked = False
        self.current_jitter_ns = 0.0
        self.recent_offsets.clear()

    def update_jitter(self, offset_ns: int) -> float:
        """Calculate running standard deviation (jitter) across recent offset samples."""
        self.recent_offsets.append(offset_ns)
        if len(self.recent_offsets) > self._max_history:
            self.recent_offsets.pop(0)

        if len(self.recent_offsets) < 2:
            self.current_jitter_ns = 0.0
            return 0.0

        n = len(self.recent_offsets)
        mean = sum(self.recent_offsets) / n
        var = sum((x - mean) ** 2 for x in self.recent_offsets) / (n - 1)
        self.current_jitter_ns = math.sqrt(var)
        return self.current_jitter_ns

    def sample(self, offset_ns: int, dt: float = 0.125) -> Tuple[int, int]:
        """Process phase offset sample, calculate frequency drift (ppb), phase adjustment, and jitter.

        Args:
            offset_ns: Phase offset from Grandmaster in nanoseconds.
            dt: Time step in seconds.

        Returns:
            Tuple of (frequency_drift_ppb: int, phase_adjustment_ns: int).
        """
        dt_clamped = max(0.001, min(10.0, float(dt)))
        abs_offset = abs(offset_ns)

        # 1. Update running jitter
        self.update_jitter(offset_ns)

        # 2. Jitter Spike Detection & Filter Clamping
        is_spike = abs_offset > self.jitter_spike_threshold_ns
        if is_spike:
            self.jitter_spike_count += 1
            clamped_offset = int(math.copysign(self.jitter_spike_threshold_ns, offset_ns))
        else:
            clamped_offset = offset_ns

        # 3. Phase Step vs Slewing
        if abs_offset > self.step_threshold_ns:
            # Coarse step phase correction
            phase_adj = offset_ns
            self.integral_error = 0.0
            self.is_locked = False
        else:
            # Fine slewing via PI control law
            self.integral_error += clamped_offset * dt_clamped
            raw_drift = self.ki * self.integral_error
            self.frequency_drift_ppb = max(-self.max_drift_ppb, min(self.max_drift_ppb, int(round(raw_drift))))
            phase_adj = int(round(self.kp * clamped_offset))

            if abs_offset < DEFAULT_SYNC_THRESHOLD_NS and self.current_jitter_ns < self.target_jitter_ns:
                self.is_locked = True
            else:
                self.is_locked = False

        self.last_offset_ns = offset_ns
        self.last_phase_adj_ns = phase_adj
        return self.frequency_drift_ppb, phase_adj


CIPSyncServo = GptpServo
PtpServo = GptpServo


# ============================================================================
# 6. Time-Sensitive Networking (TSN): IEEE 802.1Qbv TAS & IEEE 802.1Qav CBS
# ============================================================================

@dataclass
class TsnGateControlEntry:
    """IEEE 802.1Qbv Gate Control List (GCL) entry."""
    gate_states: int           # 8-bit bitmask for Traffic Classes TC0..TC7 (1=open, 0=closed)
    time_interval_ns: int      # Duration of this gate state in nanoseconds
    slot_index: int = 0
    name: str = ""

    def is_tc_open(self, traffic_class: int) -> bool:
        """Check if specific Traffic Class (0..7) transmission gate is open."""
        if not (0 <= traffic_class <= 7):
            return False
        return bool((self.gate_states >> traffic_class) & 1)


@dataclass
class TsnTasSchedule:
    """IEEE 802.1Qbv Time-Aware Shaper (TAS) Traffic Scheduler."""
    cycle_time_ns: int = 1_000_000   # 1 ms standard cycle time
    base_time: GptpTimestamp = field(default_factory=GptpTimestamp)
    entries: List[TsnGateControlEntry] = field(default_factory=list)
    guard_band_ns: int = 12_144      # Standard 1518B @ 1Gbps guard band (12.144 us)

    @classmethod
    def create_default(cls, base_time: Optional[GptpTimestamp] = None) -> TsnTasSchedule:
        """Create standard TSN schedule: TC7/TC6 time-critical window + TC0..TC5 best-effort window."""
        btime = base_time if base_time is not None else GptpTimestamp(0, 0)
        return cls(
            cycle_time_ns=1_000_000,
            base_time=btime,
            entries=[
                # Slot 0: Time-critical CIP Sync & Motion (TC7, TC6 open, TC0..TC5 closed: 0xC0) for 200 us
                TsnGateControlEntry(gate_states=0xC0, time_interval_ns=200_000),
                # Slot 1: Best-effort traffic (TC0..TC5 open, TC6, TC7 closed: 0x3F) for 800 us
                TsnGateControlEntry(gate_states=0x3F, time_interval_ns=800_000),
            ],
            guard_band_ns=cls.calculate_guard_band(link_speed_mbps=1000, max_frame_bytes=1518),
        )

    @staticmethod
    def calculate_guard_band(link_speed_mbps: int = 1000, max_frame_bytes: int = 1518) -> int:
        """Calculate non-preemptible frame transmission guard band in nanoseconds."""
        # Transmission time in nanoseconds = (bytes * 8 bits / mbps) * 1000
        bits = max_frame_bytes * 8
        time_ns = int(math.ceil((bits / float(link_speed_mbps)) * 1000.0))
        return time_ns

    def get_current_gate_state(self, timestamp: GptpTimestamp) -> int:
        """Determine active gate state bitmask at given timestamp."""
        if not self.entries or self.cycle_time_ns <= 0:
            return 0xFF  # All gates open fallback

        elapsed_ns = (timestamp - self.base_time).to_ns() % self.cycle_time_ns
        if elapsed_ns < 0:
            elapsed_ns += self.cycle_time_ns

        accum = 0
        for entry in self.entries:
            accum += entry.time_interval_ns
            if elapsed_ns < accum:
                return entry.gate_states

        return self.entries[-1].gate_states

    def is_traffic_class_open(self, timestamp: GptpTimestamp, traffic_class: int) -> bool:
        """Check if traffic class (0..7) gate is open at given timestamp."""
        if traffic_class < 0 or traffic_class > 7:
            return False
        states = self.get_current_gate_state(timestamp)
        return bool(states & (1 << traffic_class))


TsnGateControlList = TsnTasSchedule


@dataclass
class TsnCreditBasedShaper:
    """IEEE 802.1Qav Credit-Based Shaper (CBS) for Audio/Video and Industrial Streams."""
    traffic_class: int = 6
    idle_slope_kbps: int = 100_000     # 100 Mbps reserved bandwidth
    send_slope_kbps: int = -900_000    # port_rate (1000M) - idle_slope (100M) = -900 Mbps
    hi_credit: int = 2000              # Maximum accumulated positive credit
    lo_credit: int = -2000             # Minimum negative credit
    current_credit: float = 0.0

    def update(self, dt_s: float, transmitting: bool) -> float:
        """Update credit based on transmission status and delta time."""
        dt_clamped = max(0.000001, float(dt_s))
        if transmitting:
            # Credit decreases at send_slope
            self.current_credit += self.send_slope_kbps * dt_clamped
            if self.current_credit < self.lo_credit:
                self.current_credit = float(self.lo_credit)
        else:
            # Credit accumulates at idle_slope up to hi_credit
            self.current_credit += self.idle_slope_kbps * dt_clamped
            if self.current_credit > self.hi_credit:
                self.current_credit = float(self.hi_credit)

        return self.current_credit

    def can_transmit(self) -> bool:
        """Check if traffic queue has non-negative credit allowing transmission."""
        return self.current_credit >= 0.0


# ============================================================================
# 7. Wire Framing & Protocol Messages (IEEE 802.1AS & ODVA CIP Sync)
# ============================================================================

@dataclass
class GptpHeader:
    """IEEE 802.1AS Standard 34-Octet Message Header."""
    messageType: GptpMessageType = GptpMessageType.SYNC
    transportSpecific: int = GPTP_TRANSPORT_SPECIFIC
    versionPTP: int = GPTP_VERSION
    messageLength: int = 34
    domainNumber: int = DEFAULT_DOMAIN_NUMBER
    flagField: int = int(GptpFlagField.TWO_STEP | GptpFlagField.PTP_TIMESCALE)
    correctionField: int = 0
    sourcePortIdentity: GptpPortIdentity = field(default_factory=GptpPortIdentity)
    sequenceId: int = 0
    controlField: int = 0
    logMessageInterval: int = 0

    def pack(self) -> bytes:
        first_byte = ((self.transportSpecific & 0x0F) << 4) | (int(self.messageType) & 0x0F)
        sec_byte = (self.versionPTP & 0x0F)
        port_bytes = self.sourcePortIdentity.pack()
        return (
            struct.pack(
                ">BBHBBHQ",
                first_byte,
                sec_byte,
                self.messageLength,
                self.domainNumber,
                0,  # reserved1
                self.flagField,
                self.correctionField,
            )
            + b"\x00\x00\x00\x00"  # messageTypeSpecific
            + port_bytes
            + struct.pack(
                ">HBB",
                self.sequenceId,
                self.controlField,
                self.logMessageInterval,
            )
        )

    @classmethod
    def unpack(cls, data: bytes) -> GptpHeader:
        """Unpack IEEE 802.1AS standard 34-octet message header."""
        if len(data) < 34:
            raise ValueError(f"GptpHeader requires at least 34 bytes, got {len(data)}")
        first_byte, sec_byte, msg_len, domain, _, flags, corr = struct.unpack(">BBHBBHQ", data[:16])
        port_id = GptpPortIdentity.unpack(data[20:30])
        seq_id, ctrl, log_int = struct.unpack(">HBB", data[30:34])
        return cls(
            messageType=GptpMessageType(first_byte & 0x0F),
            transportSpecific=(first_byte >> 4) & 0x0F,
            versionPTP=sec_byte & 0x0F,
            messageLength=msg_len,
            domainNumber=domain,
            flagField=flags,
            correctionField=corr,
            sourcePortIdentity=port_id,
            sequenceId=seq_id,
            controlField=ctrl,
            logMessageInterval=struct.unpack(">b", bytes([log_int]))[0],
        )

    @classmethod
    def create(
        cls,
        msg_type: GptpMessageType,
        source_identity: GptpClockIdentity,
        sequence_id: int,
        two_step: bool = True,
        msg_len: int = 44,
        log_interval: int = 0,
    ) -> GptpHeader:
        flags = int(GptpFlagField.PTP_TIMESCALE)
        if two_step:
            flags |= int(GptpFlagField.TWO_STEP)
        return cls(
            messageType=msg_type,
            transportSpecific=GPTP_TRANSPORT_SPECIFIC,
            versionPTP=GPTP_VERSION,
            messageLength=msg_len,
            domainNumber=DEFAULT_DOMAIN_NUMBER,
            flagField=flags,
            correctionField=0,
            sourcePortIdentity=GptpPortIdentity(clockIdentity=source_identity, portNumber=1),
            sequenceId=sequence_id,
            controlField=0,
            logMessageInterval=log_interval,
        )


PtpHeader = GptpHeader


@dataclass
class GptpPdelayReqMessage:
    """IEEE 802.1AS Peer Delay Request (Pdelay_Req) Message."""
    header: GptpHeader
    originTimestamp: GptpTimestamp = field(default_factory=GptpTimestamp)  # t1


@dataclass
class GptpPdelayRespMessage:
    """IEEE 802.1AS Peer Delay Response (Pdelay_Resp) Message."""
    header: GptpHeader
    requestReceiptTimestamp: GptpTimestamp = field(default_factory=GptpTimestamp)  # t2
    requestingPortIdentity: GptpPortIdentity = field(default_factory=GptpPortIdentity)


@dataclass
class GptpPdelayRespFollowUpMessage:
    """IEEE 802.1AS Peer Delay Response Follow-Up (Pdelay_Resp_Follow_Up) Message."""
    header: GptpHeader
    responseOriginTimestamp: GptpTimestamp = field(default_factory=GptpTimestamp)  # t3
    requestingPortIdentity: GptpPortIdentity = field(default_factory=GptpPortIdentity)


@dataclass
class GptpSyncMessage:
    """IEEE 802.1AS Sync Message."""
    header: GptpHeader
    originTimestamp: GptpTimestamp = field(default_factory=GptpTimestamp)  # 0 in two-step


PtpSyncMessage = GptpSyncMessage


@dataclass
class GptpFollowUpMessage:
    """IEEE 802.1AS Follow_Up Message carrying precise t1 timestamp and rate ratio TLV."""
    header: GptpHeader
    preciseOriginTimestamp: GptpTimestamp = field(default_factory=GptpTimestamp)  # t1
    cumulativeScaledRateOffset: int = 0
    gmTimeBaseIndicator: int = 0


PtpFollowUpMessage = GptpFollowUpMessage


@dataclass
class GptpAnnounceMessage:
    """IEEE 802.1AS Announce Message carrying BMCA Grandmaster dataset."""
    header: GptpHeader
    originTimestamp: GptpTimestamp = field(default_factory=GptpTimestamp)
    currentUtcOffset: int = 37
    grandmasterPriority1: int = 128
    grandmasterClockQuality: GptpClockQuality = field(default_factory=GptpClockQuality)
    grandmasterPriority2: int = 128
    grandmasterIdentity: GptpClockIdentity = field(default_factory=GptpClockIdentity)
    stepsRemoved: int = 0
    timeSource: int = 0xA0  # Internal oscillator

    def to_dataset(self) -> GptpDataset:
        return GptpDataset(
            priority1=self.grandmasterPriority1,
            clockQuality=self.grandmasterClockQuality,
            priority2=self.grandmasterPriority2,
            clockIdentity=self.grandmasterIdentity,
            stepsRemoved=self.stepsRemoved,
        )


PdelayReqMessage = GptpPdelayReqMessage
PdelayRespMessage = GptpPdelayRespMessage
PdelayRespFollowUpMessage = GptpPdelayRespFollowUpMessage
SyncMessage = GptpSyncMessage
FollowUpMessage = GptpFollowUpMessage
AnnounceMessage = GptpAnnounceMessage


@dataclass
class CipTimeSyncObject:
    """ODVA CIP Sync Profile - Time Sync Object (Class 0x43) Attributes."""
    IsSynchronized: bool = False             # Attribute 1 (%M394)
    IsOwner: bool = False                    # Attribute 2 (GrandmasterActiveFlag)
    SystemTimeMicroseconds: int = 0          # Attribute 3
    OffsetFromMasterNs: int = 0              # Attribute 4 (%R1693)
    MeanPathDelayNs: int = 0                 # Attribute 5 (%R1694)
    GrandmasterClockClass: int = 248         # Attribute 6 (%R1695)
    GrandmasterIdentity: str = ""            # Attribute 7
    ClockState: int = 0                      # Attribute 8 (%R1690)
    StepsRemoved: int = 0                    # Attribute 9
    ClockType: int = 0                       # Attribute 10 (0=Ordinary Clock)
    SyncHealthScore: int = 0                 # Attribute 11 (%R1696)
    DiagnosticStatusCode: int = 0            # Attribute 12 (%R1697)
    SyncFaultTrip: bool = False              # Attribute 13 (%M395)
    DomainNumber: int = 0


CIPTimeSyncObject = CipTimeSyncObject


def calculate_peer_path_delay(
    t1: Union[GptpTimestamp, int],
    t2: Union[GptpTimestamp, int],
    t3: Union[GptpTimestamp, int],
    t4: Union[GptpTimestamp, int],
    neighbor_rate_ratio: float = 1.0,
) -> int:
    """Compute IEEE 802.1AS Peer-to-Peer Mean Path Propagation Delay.

    Formula:
      turnaround = t3 - t2
      round_trip = t4 - t1
      peer_mean_path_delay = ((t4 - t1) - neighbor_rate_ratio * (t3 - t2)) / 2
    """
    t1_ns = t1.to_ns() if isinstance(t1, GptpTimestamp) else int(t1)
    t2_ns = t2.to_ns() if isinstance(t2, GptpTimestamp) else int(t2)
    t3_ns = t3.to_ns() if isinstance(t3, GptpTimestamp) else int(t3)
    t4_ns = t4.to_ns() if isinstance(t4, GptpTimestamp) else int(t4)

    turnaround_ns = t3_ns - t2_ns
    round_trip_ns = t4_ns - t1_ns

    pdelay = (round_trip_ns - (neighbor_rate_ratio * turnaround_ns)) / 2.0
    return int(round(pdelay))


# ============================================================================
# 8. Register Helper Functions (%R1690..%R1697, %M394..%M395)
# ============================================================================

def safe_write_word(rt: RegisterTable, address: str, value: int) -> None:
    """Safely write signed 16-bit word to RegisterTable with SYSTEM privilege."""
    val_16 = int(value) & 0xFFFF
    if val_16 > 32767:
        val_16 -= 65536
    rt.write_word(address, val_16, privilege=PrivilegeMode.SYSTEM)


def safe_write_uword(rt: RegisterTable, address: str, value: int) -> None:
    """Safely write unsigned 16-bit word to RegisterTable with SYSTEM privilege."""
    val_16 = int(value) & 0xFFFF
    if val_16 > 32767:
        val_16 -= 65536
    rt.write_word(address, val_16, privilege=PrivilegeMode.SYSTEM)


def safe_write_bit(rt: RegisterTable, address: str, value: bool) -> None:
    """Safely write discrete coil bit to RegisterTable with SYSTEM privilege."""
    rt.write_bit(address, bool(value), privilege=PrivilegeMode.SYSTEM)


def encode_dint_words(value_32: int) -> Tuple[int, int]:
    """Encode 32-bit integer into (low_word, high_word) pair for Horner OCS."""
    val = int(value_32) & 0xFFFFFFFF
    low = val & 0xFFFF
    high = (val >> 16) & 0xFFFF
    low_s = low - 65536 if low > 32767 else low
    high_s = high - 65536 if high > 32767 else high
    return low_s, high_s


def decode_dint_words(low_word: int, high_word: int) -> int:
    """Reconstruct 32-bit unsigned/signed integer from (low_word, high_word) pair."""
    l = int(low_word) & 0xFFFF
    h = int(high_word) & 0xFFFF
    val_32 = (h << 16) | l
    return val_32


# ============================================================================
# 9. Pure IEC 61131-3 Structured Text POU
# ============================================================================

CIP_SYNC_GPTP_SYNC_POU: str = """PROGRAM CipSyncGptpSync
VAR
    (* Horner OCS Mapped Registers (W208 - ODVA CIP Sync / IEEE 802.1AS gPTP TSN Engine) *)
    SyncEngineState           AT %R1690 : INT;    (* 0=Uninitialized, 1=Initializing, 2=Listening, 3=Slave_Locked, 4=Master_GM, 5=Sync_Timeout_Fault, 6=Path_Delay_Exceeded_Fault *)
    CurrentTimeSecLow         AT %R1691 : INT;    (* Low 16 bits of PTP timestamp seconds *)
    CurrentTimeSecHigh        AT %R1692 : INT;    (* High 16 bits of PTP timestamp seconds *)
    SubsecondOffsetNsScaled   AT %R1693 : INT;    (* Nanosecond offset from Grandmaster (-32768..32767 ns) *)
    MeanPathDelayNsScaled     AT %R1694 : INT;    (* Mean P2P propagation delay in nanoseconds *)
    GrandmasterClockClass     AT %R1695 : INT;    (* GM Clock Class: 6=Primary Ref, 7=Holdover, 52=Degraded, 248=Default *)
    SyncHealthScore           AT %R1696 : INT;    (* Health Score: 0..100 *)
    DiagnosticStatusCode      AT %R1697 : UINT;   (* Diagnostic Status Code (0x0000=OK, 0xE001..0xE004) *)

    (* Discrete Synchronization & Safety Flags *)
    ClockSynchronized         AT %M394  : BOOL;   (* TRUE when locked with jitter < 1.0 us *)
    SyncFaultTrip             AT %M395  : BOOL;   (* TRUE on timeout or loss of grandmaster *)
END_VAR
VAR
    IsEngineHealthy           : BOOL;
    IsMasterActive            : BOOL;
END_VAR

(* Process Safety Evaluation and Status Interlocking *)
IF (DiagnosticStatusCode <> 0) OR (SyncEngineState = 5) OR (SyncEngineState = 6) THEN
    SyncFaultTrip := TRUE;
    ClockSynchronized := FALSE;
    IsEngineHealthy := FALSE;
    IsMasterActive := FALSE;
ELSIF (SyncEngineState = 4) THEN
    (* Master Grandmaster Mode *)
    SyncFaultTrip := FALSE;
    ClockSynchronized := TRUE;
    IsEngineHealthy := TRUE;
    IsMasterActive := TRUE;
ELSIF (SyncEngineState = 3) THEN
    (* Slave Locked Mode *)
    SyncFaultTrip := FALSE;
    ClockSynchronized := (SubsecondOffsetNsScaled >= -1000) AND (SubsecondOffsetNsScaled <= 1000);
    IsEngineHealthy := ClockSynchronized AND (SyncHealthScore >= 70);
    IsMasterActive := FALSE;
ELSE
    (* Initializing / Listening / Uninitialized *)
    SyncFaultTrip := FALSE;
    ClockSynchronized := FALSE;
    IsEngineHealthy := FALSE;
    IsMasterActive := FALSE;
END_IF;
END_PROGRAM
"""

CIP_SYNC_GPTP_POU = CIP_SYNC_GPTP_SYNC_POU


# ============================================================================
# 10. CipSyncGptpEngine (ILogicUnit Implementation)
# ============================================================================

class CipSyncGptpEngine(ILogicUnit):
    """ODVA CIP Sync Profile & IEEE 802.1AS-2020 Generalized Precision Time Protocol TSN Engine."""

    def __init__(
        self,
        clock_identity: Optional[Union[str, GptpClockIdentity]] = None,
        clock_class: GptpClockClass = GptpClockClass.DEFAULT,
        priority1: int = 128,
        priority2: int = 128,
        reg_table: Optional[RegisterTable] = None,
        sync_threshold_ns: int = DEFAULT_SYNC_THRESHOLD_NS,
        max_path_delay_ns: int = MAX_ALLOWABLE_PATH_DELAY_NS,
        servo: Optional[GptpServo] = None,
        tas_schedule: Optional[TsnTasSchedule] = None,
        cbs_shaper: Optional[TsnCreditBasedShaper] = None,
    ) -> None:
        self.clock_identity = (
            GptpClockIdentity(clock_identity)
            if clock_identity is not None
            else GptpClockIdentity.default_local()
        )
        self.clock_class = clock_class
        self.local_dataset = GptpDataset(
            priority1=priority1,
            clockQuality=GptpClockQuality(
                clockClass=int(clock_class),
                clockAccuracy=0x20 if clock_class == GptpClockClass.PRIMARY_REF else (0x21 if clock_class == GptpClockClass.HOLDOVER else 0xFE),
                offsetScaledLogVariance=0x4000 if clock_class == GptpClockClass.PRIMARY_REF else 0xFFFF,
            ),
            priority2=priority2,
            clockIdentity=self.clock_identity,
            stepsRemoved=0,
        )

        self.reg_table: Optional[RegisterTable] = reg_table
        self.sync_threshold_ns: int = int(sync_threshold_ns)
        self.max_path_delay_ns: int = int(max_path_delay_ns)
        self.servo: GptpServo = servo if servo is not None else GptpServo()
        self.tas_schedule: TsnTasSchedule = tas_schedule if tas_schedule is not None else TsnTasSchedule.create_default()
        self.cbs_shaper: TsnCreditBasedShaper = cbs_shaper if cbs_shaper is not None else TsnCreditBasedShaper()

        # Port State & Master Tracking
        self.state: GptpSyncState = GptpSyncState.LISTENING
        self.gm_dataset: Optional[GptpDataset] = None
        self.is_grandmaster: bool = False
        self.is_synchronized: bool = False
        self.fault_trip: bool = False

        # Clocks & Timestamps
        self.local_clock: GptpTimestamp = GptpTimestamp(seconds=1000, nanoseconds=0)
        self.t1: Optional[GptpTimestamp] = None  # Sync egress (master) or Pdelay_Req egress (requester)
        self.t2: Optional[GptpTimestamp] = None  # Sync ingress (slave) or Pdelay_Req ingress (responder)
        self.t3: Optional[GptpTimestamp] = None  # Pdelay_Resp egress (responder)
        self.t4: Optional[GptpTimestamp] = None  # Pdelay_Resp ingress (requester)

        # Metrics
        self.offset_from_master_ns: int = 0
        self.mean_path_delay_ns: int = NOMINAL_MEAN_PATH_DELAY_NS
        self.frequency_drift_ppb: int = 0
        self.jitter_ns: float = 0.0
        self.health_score: int = 100
        self.message_counter: int = 0
        self.diagnostic_code: GptpDiagnosticCode = GptpDiagnosticCode.OK

        # Sequence IDs
        self.sync_sequence_id: int = 0
        self.pdelay_sequence_id: int = 0

        # Watchdogs & Timing
        self.time_since_last_sync_s: float = 0.0
        self.time_since_last_announce_s: float = 0.0
        self.sync_timeout_s: float = DEFAULT_SYNC_RECEIPT_TIMEOUT_S
        self.announce_timeout_s: float = DEFAULT_ANNOUNCE_INTERVAL_S * DEFAULT_ANNOUNCE_RECEIPT_TIMEOUT
        self.elapsed_simulation_ms: float = 0.0
        self.total_scan_cycles: int = 0
        self._enabled: bool = True

        if self.reg_table is not None:
            self.sync_to_registers()

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "cip_sync_gptp"

    @property
    def priority(self) -> int:
        return 93

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def execute(self, ctx: ScanContext) -> None:
        """Execute one discrete scan cycle within the Horner simulation framework."""
        dt_ms = getattr(ctx, "dt_ms", 10.0)
        self.scan_step(dt=dt_ms / 1000.0, context=ctx)

    def reset(self) -> None:
        """Reset internal engine state and clear fault latches."""
        self.reset_fault(force=True)

    def scan_step(self, dt: float = 0.01, context: Optional[ScanContext] = None) -> None:
        """Advance discrete simulation clock, evaluate watchdogs, and synchronize registers."""
        dt_s = float(dt)
        self.elapsed_simulation_ms += dt_s * 1000.0
        self.total_scan_cycles += 1

        # Advance local clock with frequency drift
        drift_rate = 1.0 + (self.frequency_drift_ppb / 1_000_000_000.0)
        dt_advanced_ns = int(round(dt_s * drift_rate * 1_000_000_000.0))
        self.local_clock = self.local_clock + dt_advanced_ns

        # Evaluate watchdogs if tracking as SLAVE_LOCKED
        if self.state == GptpSyncState.SLAVE_LOCKED:
            self.time_since_last_sync_s += dt_s
            self.time_since_last_announce_s += dt_s

            if (
                self.time_since_last_sync_s > self.sync_timeout_s
                and self.diagnostic_code == GptpDiagnosticCode.OK
            ):
                self.trip_fault(
                    GptpDiagnosticCode.SYNC_TIMEOUT,
                    f"Sync message receipt timeout ({self.time_since_last_sync_s:.2f}s > {self.sync_timeout_s}s)",
                )

            elif (
                self.time_since_last_announce_s > self.announce_timeout_s
                and self.diagnostic_code == GptpDiagnosticCode.OK
            ):
                self.trip_fault(
                    GptpDiagnosticCode.GRANDMASTER_LOST,
                    f"Grandmaster announce timeout ({self.time_since_last_announce_s:.2f}s > {self.announce_timeout_s}s)",
                )

        # Update health score
        self._update_health_score()

        # Update register table if bound
        reg_t = self.reg_table
        if reg_t is None and context is not None and hasattr(context, "get_register"):
            # Context present without direct RegisterTable binding
            pass
        elif reg_t is not None:
            self.sync_to_registers(reg_table=reg_t)

    def _update_health_score(self) -> int:
        """Compute 0..100 Health Score based on offset, jitter, and diagnostic faults."""
        if self.diagnostic_code != GptpDiagnosticCode.OK or self.state in (
            GptpSyncState.SYNC_TIMEOUT_FAULT,
            GptpSyncState.PATH_DELAY_EXCEEDED_FAULT,
        ):
            self.health_score = 0
            self.fault_trip = True
            return 0

        score = 100
        abs_off = abs(self.offset_from_master_ns)

        if abs_off > 5000:
            score -= 50
        elif abs_off > 1000:
            score -= 25
        elif abs_off > 500:
            score -= 10
        elif abs_off > 200:
            score -= 5

        if self.jitter_ns > 2000.0:
            score -= 30
        elif self.jitter_ns > 1000.0:
            score -= 15
        elif self.jitter_ns > 500.0:
            score -= 5

        self.health_score = max(0, min(100, score))
        return self.health_score

    # ------------------------------------------------------------------------
    # Protocol Message Handlers & Equations
    # ------------------------------------------------------------------------

    def process_announce(self, announce_msg: GptpAnnounceMessage) -> bool:
        """Process received gPTP Announce message and evaluate BMCA."""
        foreign_dataset = announce_msg.to_dataset()
        self.time_since_last_announce_s = 0.0

        best_dataset, is_local_master = BMCA.select_master(self.local_dataset, [foreign_dataset])
        if is_local_master:
            self.state = GptpSyncState.MASTER_GRANDMASTER
            self.is_grandmaster = True
            self.is_synchronized = True
            self.fault_trip = False
            self.gm_dataset = self.local_dataset
            self.offset_from_master_ns = 0
        else:
            self.gm_dataset = foreign_dataset
            self.is_grandmaster = False
            if self.state in (GptpSyncState.LISTENING, GptpSyncState.INITIALIZING, GptpSyncState.MASTER_GRANDMASTER):
                self.state = GptpSyncState.LISTENING

        self.message_counter += 1
        self._update_health_score()
        if self.reg_table is not None:
            self.sync_to_registers()
        return is_local_master

    # --- Peer-to-Peer Path Delay (Pdelay) Handlers ---

    def send_pdelay_req(
        self,
        egress_timestamp: Optional[GptpTimestamp] = None,
    ) -> Tuple[GptpPdelayReqMessage, GptpTimestamp]:
        """Transmit Pdelay_Req message and record local egress timestamp t1."""
        self.pdelay_sequence_id += 1
        t1 = egress_timestamp if egress_timestamp is not None else self.local_clock
        self.t1 = t1

        header = GptpHeader.create(
            msg_type=GptpMessageType.PDELAY_REQ,
            source_identity=self.local_dataset.clockIdentity,
            sequence_id=self.pdelay_sequence_id,
            two_step=True,
            msg_len=54,
        )
        msg = GptpPdelayReqMessage(header=header, originTimestamp=t1)
        self.message_counter += 1
        return msg, t1

    def process_pdelay_req(
        self,
        req: GptpPdelayReqMessage,
        ingress_timestamp: Optional[GptpTimestamp] = None,
    ) -> Tuple[GptpPdelayRespMessage, GptpTimestamp]:
        """Process received Pdelay_Req as link responder, record t2, and generate Pdelay_Resp."""
        t2 = ingress_timestamp if ingress_timestamp is not None else self.local_clock
        self.t2 = t2

        header = GptpHeader.create(
            msg_type=GptpMessageType.PDELAY_RESP,
            source_identity=self.local_dataset.clockIdentity,
            sequence_id=req.header.sequenceId,
            two_step=True,
            msg_len=54,
        )
        resp = GptpPdelayRespMessage(
            header=header,
            requestReceiptTimestamp=t2,
            requestingPortIdentity=req.header.sourcePortIdentity,
        )
        self.message_counter += 1
        return resp, t2

    def create_pdelay_resp_follow_up(
        self,
        requesting_port: GptpPortIdentity,
        egress_timestamp: GptpTimestamp,
        sequence_id: int,
    ) -> GptpPdelayRespFollowUpMessage:
        """Create Pdelay_Resp_Follow_Up message carrying egress timestamp t3."""
        header = GptpHeader.create(
            msg_type=GptpMessageType.PDELAY_RESP_FOLLOW_UP,
            source_identity=self.local_dataset.clockIdentity,
            sequence_id=sequence_id,
            two_step=False,
            msg_len=54,
        )
        return GptpPdelayRespFollowUpMessage(
            header=header,
            responseOriginTimestamp=egress_timestamp,
            requestingPortIdentity=requesting_port,
        )

    def process_pdelay_resp(
        self,
        resp: GptpPdelayRespMessage,
        ingress_timestamp: Optional[GptpTimestamp] = None,
    ) -> None:
        """Process received Pdelay_Resp, record requester ingress timestamp t4 and responder t2."""
        t4 = ingress_timestamp if ingress_timestamp is not None else self.local_clock
        self.t4 = t4
        self.t2 = resp.requestReceiptTimestamp
        self.message_counter += 1

    def process_pdelay_resp_follow_up(
        self,
        fu: GptpPdelayRespFollowUpMessage,
        neighbor_rate_ratio: float = 1.0,
    ) -> Dict[str, Any]:
        """Process received Pdelay_Resp_Follow_Up carrying t3 and compute mean propagation delay."""
        self.t3 = fu.responseOriginTimestamp
        self.message_counter += 1
        return self._compute_pdelay(neighbor_rate_ratio=neighbor_rate_ratio)

    def measure_pdelay(
        self,
        t1: GptpTimestamp,
        t2: GptpTimestamp,
        t3: GptpTimestamp,
        t4: GptpTimestamp,
        neighbor_rate_ratio: float = 1.0,
    ) -> Dict[str, Any]:
        """Convenience evaluation for peer-to-peer path delay calculation from timestamps t1..t4."""
        self.t1 = t1
        self.t2 = t2
        self.t3 = t3
        self.t4 = t4
        return self._compute_pdelay(neighbor_rate_ratio=neighbor_rate_ratio)

    def _compute_pdelay(self, neighbor_rate_ratio: float = 1.0) -> Dict[str, Any]:
        """Calculate turnaround time and mean propagation delay per IEEE 802.1AS clause 11.2.19."""
        if self.t1 is None or self.t2 is None or self.t3 is None or self.t4 is None:
            raise ValueError("All timestamps (t1, t2, t3, t4) must be populated for Pdelay calculation.")

        turnaround_ns = (self.t3 - self.t2).to_ns()
        round_trip_ns = (self.t4 - self.t1).to_ns()

        # Mean propagation delay: ((t4 - t1) - neighborRateRatio * (t3 - t2)) / 2
        delay_calc = (round_trip_ns - (neighbor_rate_ratio * turnaround_ns)) / 2.0
        mean_delay_ns = int(round(delay_calc))

        # Check for path delay excursion
        if mean_delay_ns > self.max_path_delay_ns:
            self.trip_fault(
                GptpDiagnosticCode.PATH_DELAY_EXCEEDED,
                f"Peer-to-peer path delay excursion ({mean_delay_ns}ns > {self.max_path_delay_ns}ns)",
            )
        else:
            self.mean_path_delay_ns = max(0, mean_delay_ns)

        if self.reg_table is not None:
            self.sync_to_registers()

        return {
            "mean_path_delay_ns": self.mean_path_delay_ns,
            "turnaround_ns": turnaround_ns,
            "round_trip_ns": round_trip_ns,
            "neighbor_rate_ratio": neighbor_rate_ratio,
        }

    # --- Sync & Follow_Up Handlers ---

    def process_sync(
        self,
        sync_msg: GptpSyncMessage,
        ingress_timestamp: Optional[GptpTimestamp] = None,
    ) -> GptpTimestamp:
        """Process incoming Sync message and record slave ingress timestamp t2."""
        t2 = ingress_timestamp if ingress_timestamp is not None else self.local_clock
        self.t2 = t2
        self.sync_sequence_id = sync_msg.header.sequenceId
        self.time_since_last_sync_s = 0.0

        if not (sync_msg.header.flagField & int(GptpFlagField.TWO_STEP)):
            self.t1 = sync_msg.originTimestamp
            self._compute_offset_and_servo()

        self.message_counter += 1
        return t2

    def process_follow_up(self, fu_msg: GptpFollowUpMessage) -> bool:
        """Process incoming Follow_Up message containing precise t1 and update clock offset."""
        if fu_msg.header.sequenceId != self.sync_sequence_id:
            return False

        self.t1 = fu_msg.preciseOriginTimestamp
        self._compute_offset_and_servo()
        self.message_counter += 1
        return True

    def _compute_offset_and_servo(self) -> None:
        """Calculate offset from master and execute PI clock servo adjustment."""
        if self.t1 is None or self.t2 is None:
            return

        # Canonical gPTP offset equation:
        # offset_from_master = (t2 - t1) - mean_path_delay
        elapsed_ingress = (self.t2 - self.t1).to_ns()
        offset_ns = elapsed_ingress - self.mean_path_delay_ns
        self.offset_from_master_ns = offset_ns

        # Execute PI Servo sample
        drift_ppb, phase_adj = self.servo.sample(offset_ns, dt=DEFAULT_SYNC_INTERVAL_S)
        self.frequency_drift_ppb = drift_ppb
        self.jitter_ns = self.servo.current_jitter_ns

        # Evaluate jitter excursion
        if abs(offset_ns) > DEFAULT_JITTER_SPIKE_THRESHOLD_NS or self.jitter_ns > DEFAULT_JITTER_TARGET_NS * 5.0:
            if self.diagnostic_code == GptpDiagnosticCode.OK:
                self.diagnostic_code = GptpDiagnosticCode.JITTER_DRIFT_EXCEEDED
                self.fault_trip = True
                self.is_synchronized = False

        # State transition to SLAVE_LOCKED if conditions met
        if (
            self.servo.is_locked
            and abs(offset_ns) < self.sync_threshold_ns
            and self.jitter_ns < DEFAULT_JITTER_TARGET_NS
            and self.diagnostic_code == GptpDiagnosticCode.OK
        ):
            self.state = GptpSyncState.SLAVE_LOCKED
            self.is_synchronized = True
            self.fault_trip = False
        elif self.state == GptpSyncState.SLAVE_LOCKED and (
            abs(offset_ns) >= self.sync_threshold_ns or self.jitter_ns >= DEFAULT_JITTER_TARGET_NS
        ):
            self.is_synchronized = False

        self._update_health_score()
        if self.reg_table is not None:
            self.sync_to_registers()

    # ------------------------------------------------------------------------
    # Fault Injection, Safety Tripping, & Reset Handshake
    # ------------------------------------------------------------------------

    def trip_fault(self, code: GptpDiagnosticCode, details: str = "") -> None:
        """Trip safety interlock, latch diagnostic code, and de-energize sync flag."""
        self.diagnostic_code = code
        self.is_synchronized = False
        self.fault_trip = True

        if code == GptpDiagnosticCode.SYNC_TIMEOUT:
            self.state = GptpSyncState.SYNC_TIMEOUT_FAULT
        elif code == GptpDiagnosticCode.PATH_DELAY_EXCEEDED:
            self.state = GptpSyncState.PATH_DELAY_EXCEEDED_FAULT
        elif code == GptpDiagnosticCode.GRANDMASTER_LOST:
            self.state = GptpSyncState.LISTENING

        self._update_health_score()
        if self.reg_table is not None:
            self.sync_to_registers()

    def simulate_sync_timeout(self) -> None:
        """Simulate missed sync message timeout (0xE001)."""
        self.trip_fault(GptpDiagnosticCode.SYNC_TIMEOUT, "Simulated Sync message timeout")

    def simulate_path_delay_exceeded(self, excursion_ns: int = 65_000) -> None:
        """Simulate path delay exceeding maximum threshold (0xE002)."""
        self.mean_path_delay_ns = excursion_ns
        self.trip_fault(GptpDiagnosticCode.PATH_DELAY_EXCEEDED, f"Simulated P2P path delay {excursion_ns}ns")

    def simulate_jitter_drift_exceeded(self, jitter_excursion_ns: int = 15_000) -> None:
        """Simulate jitter excursion trip (0xE003)."""
        self.offset_from_master_ns = jitter_excursion_ns
        self.jitter_ns = float(jitter_excursion_ns)
        self.trip_fault(GptpDiagnosticCode.JITTER_DRIFT_EXCEEDED, f"Simulated jitter excursion {jitter_excursion_ns}ns")

    def simulate_grandmaster_lost(self) -> None:
        """Simulate Grandmaster lost due to Announce timeout (0xE004)."""
        self.trip_fault(GptpDiagnosticCode.GRANDMASTER_LOST, "Simulated Announce timeout / Grandmaster lost")

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Operator fault reset handshake restoring engine to LISTENING state."""
        self.diagnostic_code = GptpDiagnosticCode.OK
        self.time_since_last_sync_s = 0.0
        self.time_since_last_announce_s = 0.0
        self.fault_trip = False

        if self.is_grandmaster:
            self.state = GptpSyncState.MASTER_GRANDMASTER
            self.is_synchronized = True
        else:
            self.state = GptpSyncState.LISTENING
            self.is_synchronized = False

        self.servo.reset()
        self._update_health_score()
        if self.reg_table is not None:
            self.sync_to_registers()

        return ExecutionResult.success(
            details=f"Fault latch cleared. Engine returned to {self.state.name} state.",
            data={"state": self.state.name, "diagnostic_code": int(self.diagnostic_code)},
        )

    # ------------------------------------------------------------------------
    # Register Table Synchronization (%R1690..%R1697, %M394..%M395)
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize internal gPTP engine telemetry and discrete coils to Horner OCS registers."""
        rt = reg_table if reg_table is not None else self.reg_table
        if rt is None:
            return

        # %R1690: SyncEngineState (0..6)
        safe_write_word(rt, "%R1690", int(self.state))

        # %R1691: CurrentTimeSecLow (INT16, low 16 bits of PTP timestamp seconds)
        # %R1692: CurrentTimeSecHigh (INT16, high 16 bits of PTP timestamp seconds)
        sec = int(self.local_clock.seconds)
        sec_low, sec_high = encode_dint_words(sec)
        safe_write_word(rt, "%R1691", sec_low)
        safe_write_word(rt, "%R1692", sec_high)

        # %R1693: SubsecondOffsetNsScaled (INT16 scaled, nanosecond offset from GM, clamped to -32768..32767)
        offset_scaled = max(-32768, min(32767, int(round(self.offset_from_master_ns))))
        safe_write_word(rt, "%R1693", offset_scaled)

        # %R1694: MeanPathDelayNsScaled (INT16 scaled, link P2P path delay in ns, clamped to 0..32767)
        delay_scaled = max(0, min(32767, int(round(self.mean_path_delay_ns))))
        safe_write_word(rt, "%R1694", delay_scaled)

        # %R1695: GrandmasterClockClass (INT16: 6, 7, 52, 248)
        gm_class = (
            self.gm_dataset.clockQuality.clockClass
            if self.gm_dataset is not None
            else self.local_dataset.clockQuality.clockClass
        )
        safe_write_word(rt, "%R1695", int(gm_class))

        # %R1696: SyncHealthScore (INT16: 0..100)
        safe_write_word(rt, "%R1696", int(self.health_score))

        # %R1697: DiagnosticStatusCode (0x0000=OK, 0xE001..0xE004)
        safe_write_uword(rt, "%R1697", int(self.diagnostic_code))

        # %M394: ClockSynchronized (BOOL, True when locked with jitter < 1.0 us)
        safe_write_bit(rt, "%M394", self.is_synchronized)

        # %M395: SyncFaultTrip (BOOL, True on timeout or loss of grandmaster)
        safe_write_bit(rt, "%M395", self.fault_trip)

    def get_cip_object(self) -> CipTimeSyncObject:
        """Return ODVA CIP Time Sync Object (Class 0x43) representation."""
        gm_id = str(self.gm_dataset.clockIdentity) if self.gm_dataset else str(self.clock_identity)
        gm_class = (
            self.gm_dataset.clockQuality.clockClass
            if self.gm_dataset
            else self.local_dataset.clockQuality.clockClass
        )
        return CipTimeSyncObject(
            IsSynchronized=self.is_synchronized,
            IsOwner=self.is_grandmaster,
            SystemTimeMicroseconds=int(self.local_clock.to_float_seconds() * 1_000_000),
            OffsetFromMasterNs=self.offset_from_master_ns,
            MeanPathDelayNs=self.mean_path_delay_ns,
            GrandmasterClockClass=int(gm_class),
            GrandmasterIdentity=gm_id,
            ClockState=int(self.state),
            StepsRemoved=self.gm_dataset.stepsRemoved if self.gm_dataset else 0,
            ClockType=0,  # Ordinary Clock
            SyncHealthScore=self.health_score,
            DiagnosticStatusCode=int(self.diagnostic_code),
            SyncFaultTrip=self.fault_trip,
            DomainNumber=DEFAULT_DOMAIN_NUMBER,
        )


CIPSyncGPTPEngine = CipSyncGptpEngine


# ============================================================================
# 11. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_sync_gptp_verification(output_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Execute rigorous deterministic 9-stage verification suite for W208 CIP Sync gPTP TSN Engine."""
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure IEC 61131-3 ST Syntax Validation & Anti-Ladder Guard
    # ------------------------------------------------------------------------
    val_pou = STParser.validate_code(CIP_SYNC_GPTP_SYNC_POU)
    parser = STParser(pou_type=POUType.PROGRAM)
    ast_pou = parser.parse_pou(CIP_SYNC_GPTP_SYNC_POU)

    expected_regs = {
        "%R1690", "%R1691", "%R1692", "%R1693",
        "%R1694", "%R1695", "%R1696", "%R1697",
        "%M394", "%M395",
    }
    bound_regs = set(ast_pou.bound_registers)

    ladder_rejected = True
    for bad_construct in ["---[ ]---", "---( )---", "RUNG 1", "XIC MasterGM_Sync"]:
        try:
            SecurityGuard.assert_pure_st_content(f"PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\n{bad_construct}\nEND_PROGRAM")
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    # Verify pure ST passes cleanly
    SecurityGuard.assert_pure_st_content(CIP_SYNC_GPTP_SYNC_POU)

    s1_pass = (
        val_pou.status == AgentStatus.SUCCESS
        and ast_pou.name == "CipSyncGptpSync"
        and expected_regs.issubset(bound_regs)
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "POU_ST_Syntax_Validation_And_Anti_Ladder_Check",
        "passed": s1_pass,
        "details": f"IEC 61131-3 POU 'CipSyncGptpSync' verified cleanly; bound {len(bound_regs)} registers; ladder rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: BMCA Dataset Comparison Across Clock Classes & Master Election
    # ------------------------------------------------------------------------
    ds_primary = GptpDataset(
        priority1=128,
        clockQuality=GptpClockQuality(clockClass=int(GptpClockClass.PRIMARY_REF), clockAccuracy=0x20, offsetScaledLogVariance=0x4000),
        priority2=128,
        clockIdentity=GptpClockIdentity("00-80-C2-FF-FE-01-00-01"),
    )
    ds_holdover = GptpDataset(
        priority1=128,
        clockQuality=GptpClockQuality(clockClass=int(GptpClockClass.HOLDOVER), clockAccuracy=0x21, offsetScaledLogVariance=0x5000),
        priority2=128,
        clockIdentity=GptpClockIdentity("00-80-C2-FF-FE-01-00-02"),
    )
    ds_degraded = GptpDataset(
        priority1=128,
        clockQuality=GptpClockQuality(clockClass=int(GptpClockClass.DEGRADED), clockAccuracy=0x30, offsetScaledLogVariance=0x8000),
        priority2=128,
        clockIdentity=GptpClockIdentity("00-80-C2-FF-FE-01-00-03"),
    )
    ds_default = GptpDataset(
        priority1=128,
        clockQuality=GptpClockQuality(clockClass=int(GptpClockClass.DEFAULT), clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF),
        priority2=128,
        clockIdentity=GptpClockIdentity("00-80-C2-FF-FE-01-00-04"),
    )
    ds_prio_win = GptpDataset(
        priority1=100,  # Higher priority (lower int)
        clockQuality=GptpClockQuality(clockClass=int(GptpClockClass.DEFAULT), clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF),
        priority2=128,
        clockIdentity=GptpClockIdentity("00-80-C2-FF-FE-01-00-05"),
    )

    cmp_pri_hol = BMCA.compare_datasets(ds_primary, ds_holdover)   # -1 (primary wins)
    cmp_hol_deg = BMCA.compare_datasets(ds_holdover, ds_degraded)  # -1 (holdover wins)
    cmp_deg_def = BMCA.compare_datasets(ds_degraded, ds_default)   # -1 (degraded wins)
    cmp_prio = BMCA.compare_datasets(ds_prio_win, ds_primary)      # -1 (prio1 wins)

    # Master election evaluation
    engine_bmca = CipSyncGptpEngine(clock_identity="00-80-C2-FF-FE-01-00-99", clock_class=GptpClockClass.DEFAULT)
    header_ann = GptpHeader.create(GptpMessageType.ANNOUNCE, ds_primary.clockIdentity, sequence_id=1)
    ann_msg = GptpAnnounceMessage(
        header=header_ann,
        grandmasterPriority1=ds_primary.priority1,
        grandmasterClockQuality=ds_primary.clockQuality,
        grandmasterPriority2=ds_primary.priority2,
        grandmasterIdentity=ds_primary.clockIdentity,
    )
    is_local_master = engine_bmca.process_announce(ann_msg)

    s2_pass = (
        cmp_pri_hol == -1
        and cmp_hol_deg == -1
        and cmp_deg_def == -1
        and cmp_prio == -1
        and is_local_master is False
        and engine_bmca.is_grandmaster is False
        and engine_bmca.state == GptpSyncState.LISTENING
    )
    test_results.append({
        "stage": 2,
        "check": "BMCA_Dataset_Comparison_Across_Clock_Classes_And_Master_Election",
        "passed": s2_pass,
        "details": "BMCA clock classes (6 < 7 < 52 < 248), priority1 override, and slave tracking verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Peer-to-Peer Path Delay Measurement (Pdelay_Req / Resp / Resp_Follow_Up)
    # ------------------------------------------------------------------------
    engine_pdelay = CipSyncGptpEngine(clock_identity="00-80-C2-FF-FE-01-00-10")
    t1_pdelay = GptpTimestamp(seconds=1000, nanoseconds=100_000)
    t2_pdelay = GptpTimestamp(seconds=1000, nanoseconds=101_450)  # +1450 ns propagation
    t3_pdelay = GptpTimestamp(seconds=1000, nanoseconds=121_450)  # +20,000 ns turnaround
    t4_pdelay = GptpTimestamp(seconds=1000, nanoseconds=122_900)  # +1450 ns propagation

    calc_pdelay = engine_pdelay.measure_pdelay(t1_pdelay, t2_pdelay, t3_pdelay, t4_pdelay)

    # turnaround = 121_450 - 101_450 = 20,000 ns
    # round_trip = 122_900 - 100_000 = 22,900 ns
    # mean_path_delay = (22_900 - 20_000) // 2 = 1,450 ns
    s3_pass = (
        calc_pdelay["mean_path_delay_ns"] == 1450
        and calc_pdelay["turnaround_ns"] == 20_000
        and calc_pdelay["round_trip_ns"] == 22_900
        and engine_pdelay.mean_path_delay_ns == 1450
    )
    test_results.append({
        "stage": 3,
        "check": "Peer_To_Peer_Path_Delay_Measurement_Pdelay_Req_Resp_Follow_Up",
        "passed": s3_pass,
        "details": f"P2P path delay verified: turnaround=20000ns, round_trip=22900ns, mean_path_delay={engine_pdelay.mean_path_delay_ns}ns.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Two-Step Sync & Follow-Up Processing with Subsecond Offset Tracking
    # ------------------------------------------------------------------------
    engine_sync = CipSyncGptpEngine(clock_identity="00-80-C2-FF-FE-01-00-20")
    engine_sync.mean_path_delay_ns = 1450

    t1_sync = GptpTimestamp(seconds=2000, nanoseconds=500_000)
    t2_sync = GptpTimestamp(seconds=2000, nanoseconds=501_200)

    # Master sends Sync
    header_sync = GptpHeader.create(GptpMessageType.SYNC, ds_primary.clockIdentity, sequence_id=101, two_step=True)
    sync_msg = GptpSyncMessage(header=header_sync, originTimestamp=GptpTimestamp(0, 0))
    engine_sync.process_sync(sync_msg, ingress_timestamp=t2_sync)

    # Master sends Follow_Up
    header_fu = GptpHeader.create(GptpMessageType.FOLLOW_UP, ds_primary.clockIdentity, sequence_id=101, two_step=True)
    fu_msg = GptpFollowUpMessage(header=header_fu, preciseOriginTimestamp=t1_sync)
    fu_ok = engine_sync.process_follow_up(fu_msg)

    # elapsed = t2 - t1 = 1200 ns
    # offset = elapsed - mean_delay = 1200 - 1450 = -250 ns
    s4_pass = (
        fu_ok is True
        and engine_sync.offset_from_master_ns == -250
        and engine_sync.mean_path_delay_ns == 1450
        and engine_sync.t1 == t1_sync
        and engine_sync.t2 == t2_sync
    )
    test_results.append({
        "stage": 4,
        "check": "Two_Step_Sync_And_Follow_Up_Subsecond_Offset_Tracking",
        "passed": s4_pass,
        "details": f"Two-step sync computed offset={engine_sync.offset_from_master_ns}ns with mean_delay={engine_sync.mean_path_delay_ns}ns.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Sub-Microsecond PI Clock Servo Convergence & Jitter Tracking (< 1.0 us)
    # ------------------------------------------------------------------------
    servo_test = GptpServo(kp=0.6, ki=1.0)
    sim_offset = -600  # -600 ns initial offset
    intrinsic_drift_ppb = 120

    for _ in range(40):
        drift, adj = servo_test.sample(sim_offset, dt=0.125)
        net_drift_ns = int(round((intrinsic_drift_ppb - drift) * 1e-9 * 0.125 * 1e9))
        sim_offset = int(sim_offset - adj + net_drift_ns)

    final_jitter = servo_test.current_jitter_ns
    s5_pass = (
        abs(sim_offset) < 50
        and servo_test.is_locked is True
        and final_jitter < 1000.0
    )
    test_results.append({
        "stage": 5,
        "check": "Sub_Microsecond_PI_Clock_Servo_Convergence_And_Jitter_Tracking",
        "passed": s5_pass,
        "details": f"PI clock servo locked (residual offset={sim_offset}ns, jitter={final_jitter:.1f}ns < 1.0 us).",
    })

    # ------------------------------------------------------------------------
    # Stage 6: TSN 802.1Qbv Time-Aware Traffic Scheduling & Credit-Based Shaper (CBS)
    # ------------------------------------------------------------------------
    tas = TsnTasSchedule.create_default(base_time=GptpTimestamp(0, 0))
    guard_band = tas.calculate_guard_band(link_speed_mbps=1000, max_frame_bytes=1518)

    # In slot 0 (0..200 us): TC7/TC6 open (0xC0), TC0..TC5 closed
    ts_critical = GptpTimestamp(seconds=0, nanoseconds=50_000)
    tc7_open = tas.is_traffic_class_open(ts_critical, 7)
    tc0_closed = not tas.is_traffic_class_open(ts_critical, 0)

    # In slot 1 (200..1000 us): TC7 closed, TC0 open (0x3F)
    ts_be = GptpTimestamp(seconds=0, nanoseconds=500_000)
    tc7_closed = not tas.is_traffic_class_open(ts_be, 7)
    tc0_open = tas.is_traffic_class_open(ts_be, 0)

    # Test Credit-Based Shaper (CBS)
    cbs = TsnCreditBasedShaper(idle_slope_kbps=100_000, send_slope_kbps=-900_000, hi_credit=2000, lo_credit=-2000)
    c_init = cbs.can_transmit()
    # Transmit 10 us (0.00001 s) -> credit decreases by -900,000 * 0.00001 = -9
    cbs.update(dt_s=0.00001, transmitting=True)
    c_trans = cbs.current_credit < 0.0
    # Idle for 100 us -> credit accumulates
    cbs.update(dt_s=0.0001, transmitting=False)
    c_accum = cbs.current_credit > 0.0

    s6_pass = (
        guard_band == 12144
        and tc7_open is True
        and tc0_closed is True
        and tc7_closed is True
        and tc0_open is True
        and c_init is True
        and c_trans is True
        and c_accum is True
    )
    test_results.append({
        "stage": 6,
        "check": "TSN_802_1Qbv_Time_Aware_Scheduling_And_Credit_Based_Shaper",
        "passed": s6_pass,
        "details": f"TSN 802.1Qbv TAS guard band={guard_band}ns; GCL slotting and 802.1Qav CBS credit validated.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Horner OCS Register Table Mapping (%R1690..%R1697, %M394..%M395)
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine_rt = CipSyncGptpEngine(reg_table=rt, clock_class=GptpClockClass.PRIMARY_REF)

    # Set known state
    engine_rt.state = GptpSyncState.SLAVE_LOCKED
    engine_rt.local_clock = GptpTimestamp(seconds=371661, nanoseconds=450)  # 0x0005ABCD
    engine_rt.offset_from_master_ns = -250
    engine_rt.mean_path_delay_ns = 1450
    engine_rt.diagnostic_code = GptpDiagnosticCode.OK
    engine_rt.health_score = 98
    engine_rt.is_synchronized = True
    engine_rt.fault_trip = False
    engine_rt.sync_to_registers(rt, PrivilegeMode.SYSTEM)

    r1690 = rt.read_word("%R1690")
    r1691 = rt.read_word("%R1691")
    r1692 = rt.read_word("%R1692")
    r1693 = rt.read_word("%R1693")
    r1694 = rt.read_word("%R1694")
    r1695 = rt.read_word("%R1695")
    r1696 = rt.read_word("%R1696")
    r1697 = rt.read_uword("%R1697")
    m394 = rt.read_bit("%M394")
    m395 = rt.read_bit("%M395")

    reconstructed_sec = decode_dint_words(r1691, r1692)

    s7_pass = (
        r1690 == int(GptpSyncState.SLAVE_LOCKED)
        and reconstructed_sec == 371661
        and r1693 == -250
        and r1694 == 1450
        and r1695 == int(GptpClockClass.PRIMARY_REF)
        and r1696 == 98
        and r1697 == 0x0000
        and m394 is True
        and m395 is False
    )
    test_results.append({
        "stage": 7,
        "check": "Horner_OCS_Register_Table_Mapping_R1690_R1697_M394_M395",
        "passed": s7_pass,
        "details": f"Horner OCS registers verified: state={r1690}, sec={reconstructed_sec}, offset={r1693}ns, delay={r1694}ns, %M394={m394}.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Discrete ILogicUnit 100-Cycle Scan Simulation
    # ------------------------------------------------------------------------
    engine_scan = CipSyncGptpEngine(reg_table=rt)
    engine_scan.state = GptpSyncState.SLAVE_LOCKED
    engine_scan.offset_from_master_ns = -250
    engine_scan.mean_path_delay_ns = 1450

    ctx = ScanContext(
        cycle=1,
        dt_ms=10.0,
        elapsed_time_ms=10.0,
        get_register=rt.read_register,
        set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
        get_variable=lambda k, d=None: d,
        set_variable=lambda k, v: None,
        record_fault=lambda f: None,
    )

    for c in range(1, 101):
        ctx.cycle = c
        ctx.elapsed_time_ms = c * 10.0
        engine_scan.execute(ctx)

    s8_pass = (
        engine_scan.name == "cip_sync_gptp"
        and engine_scan.priority == 93
        and engine_scan.is_enabled is True
        and engine_scan.total_scan_cycles == 100
        and round(engine_scan.elapsed_simulation_ms) == 1000
    )
    test_results.append({
        "stage": 8,
        "check": "Discrete_ILogicUnit_100_Cycle_Scan_Simulation",
        "passed": s8_pass,
        "details": f"100 scan cycles completed cleanly; simulation elapsed={engine_scan.elapsed_simulation_ms}ms.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Process Safety Interlocks, Diagnostics (0xE001..0xE004), & Fault Trips
    # ------------------------------------------------------------------------
    engine_safety = CipSyncGptpEngine(reg_table=rt)

    # 1. Sync Timeout (0xE001)
    engine_safety.simulate_sync_timeout()
    d1 = (
        engine_safety.diagnostic_code == GptpDiagnosticCode.SYNC_TIMEOUT
        and engine_safety.state == GptpSyncState.SYNC_TIMEOUT_FAULT
        and rt.read_word("%R1690") == 5
        and rt.read_uword("%R1697") == 0xE001
        and rt.read_bit("%M394") is False
        and rt.read_bit("%M395") is True
    )

    # 2. Path Delay Exceeded (0xE002)
    engine_safety.simulate_path_delay_exceeded(65_000)
    d2 = (
        engine_safety.diagnostic_code == GptpDiagnosticCode.PATH_DELAY_EXCEEDED
        and engine_safety.state == GptpSyncState.PATH_DELAY_EXCEEDED_FAULT
        and rt.read_word("%R1690") == 6
        and rt.read_uword("%R1697") == 0xE002
        and rt.read_bit("%M394") is False
        and rt.read_bit("%M395") is True
    )

    # 3. Jitter Drift Exceeded (0xE003)
    engine_safety.simulate_jitter_drift_exceeded(15_000)
    d3 = (
        engine_safety.diagnostic_code == GptpDiagnosticCode.JITTER_DRIFT_EXCEEDED
        and rt.read_uword("%R1697") == 0xE003
        and rt.read_bit("%M394") is False
        and rt.read_bit("%M395") is True
    )

    # 4. Grandmaster Lost (0xE004)
    engine_safety.simulate_grandmaster_lost()
    d4 = (
        engine_safety.diagnostic_code == GptpDiagnosticCode.GRANDMASTER_LOST
        and rt.read_uword("%R1697") == 0xE004
        and rt.read_bit("%M394") is False
        and rt.read_bit("%M395") is True
    )

    # 5. Operator Reset Handshake
    res_reset = engine_safety.reset_fault(force=True)
    d5 = (
        res_reset.status == AgentStatus.SUCCESS
        and engine_safety.diagnostic_code == GptpDiagnosticCode.OK
        and engine_safety.state == GptpSyncState.LISTENING
        and rt.read_uword("%R1697") == 0x0000
        and rt.read_bit("%M395") is False
    )

    s9_pass = d1 and d2 and d3 and d4 and d5
    test_results.append({
        "stage": 9,
        "check": "Process_Safety_Interlocks_Diagnostics_And_Fault_Trips",
        "passed": s9_pass,
        "details": "Safety interlocks verified: 0xE001..0xE004 diagnostic fault trips and operator reset confirmed.",
    })

    # ------------------------------------------------------------------------
    # Summary & Evidence Serialization
    # ------------------------------------------------------------------------
    passed_count = sum(1 for t in test_results if t["passed"])
    total_stages = len(test_results)
    all_passed = (passed_count == total_stages)

    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_FAILED",
        "details": f"CIP Sync gPTP TSN Engine (W208) verified cleanly ({passed_count}/{total_stages} stages passed).",
        "stages_passed": passed_count,
        "total_stages": total_stages,
        "data": {
            "work_package": "W208",
            "standards": [
                "IEEE 802.1AS-2020 (gPTP)",
                "ODVA CIP Sync Profile (Class 0x43)",
                "IEEE 802.1Qbv TAS & IEEE 802.1Qav CBS",
                "IEC 61131-3 Structured Text",
            ],
            "stages": test_results,
            "tests": test_results,
            "checks_passed": passed_count,
            "total_checks": total_stages,
            "register_map": {
                "%R1690": "SyncEngineState",
                "%R1691": "CurrentTimeSecLow",
                "%R1692": "CurrentTimeSecHigh",
                "%R1693": "SubsecondOffsetNsScaled",
                "%R1694": "MeanPathDelayNsScaled",
                "%R1695": "GrandmasterClockClass",
                "%R1696": "SyncHealthScore",
                "%R1697": "DiagnosticStatusCode",
                "%M394": "ClockSynchronized",
                "%M395": "SyncFaultTrip",
            },
            "registers": {
                "%R1690": rt.read_word("%R1690"),
                "%R1691": rt.read_word("%R1691"),
                "%R1692": rt.read_word("%R1692"),
                "%R1693": rt.read_word("%R1693"),
                "%R1694": rt.read_word("%R1694"),
                "%R1695": rt.read_word("%R1695"),
                "%R1696": rt.read_word("%R1696"),
                "%R1697": rt.read_uword("%R1697"),
                "%M394": rt.read_bit("%M394"),
                "%M395": rt.read_bit("%M395"),
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if output_path is not None:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    out_target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_cip_sync_gptp_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
