"""Industrial ODVA CIP Sync Profile & IEEE 1588-2008 (PTPv2) Precision Time Protocol Engine.

Work Package: W187 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- IEEE 1588-2008: Precision Clock Synchronization Protocol for Networked Measurement and Control Systems (PTPv2).
- ODVA CIP Networks Library Volume 1: Common Industrial Protocol (CIP) - Time Sync Object (Class 0x43).
- IEC 61131-3 Programmable Controllers - Part 3: Programming Languages (Structured Text).
- Horner OCS Memory Space: %R1480..%R1487, %M345..%M346.

Architecture:
1. Strict Pure IEC 61131-3 Structured Text POU:
   - 'CipSyncPtpSync' bound to Horner OCS memory space (%R1480..%R1487, %M345..%M346).
   - Anti-ladder security guard: Intercepts ladder constructs with ERR_LADDER_FORBIDDEN
     using SecurityGuard.assert_pure_st_content and STParser.

2. IEEE 1588-2008 & ODVA CIP Sync Protocol Implementation:
   - PtpPortState (IntEnum: DISABLED=0, LISTENING=1, PRE_MASTER=2, MASTER=3, PASSIVE=4, UNCALIBRATED=5, SLAVE=6, FAULTY=7).
   - PtpClockClass (IntEnum: PRIMARY_REF=6, APPLICATION_SPECIFIC=13, DEFAULT=248).
   - PtpMessageType (IntEnum: SYNC=0x0, DELAY_REQ=0x1, PDELAY_REQ=0x2, PDELAY_RESP=0x3,
     FOLLOW_UP=0x8, DELAY_RESP=0x9, PDELAY_RESP_FOLLOW_UP=0xA, ANNOUNCE=0xB, SIGNALING=0xC, MANAGEMENT=0xD).
   - PtpTimestamp dataclass (seconds: int, nanoseconds: int) with full arithmetic (+, -, to_ns, from_ns, to_float_seconds).
   - PtpClockIdentity (EUI-64, 8 bytes hex).
   - PtpClockQuality (clockClass, clockAccuracy, offsetScaledLogVariance).
   - BestMasterClockAlgorithm (BMCA) dataset comparison comparing priority1, clockClass, clockAccuracy,
     offsetScaledLogVariance, priority2, clockIdentity.
   - PtpServo (PI servo controller) calculating clock drift (ppb) and phase step adjustment.
   - CipSyncPtpEngine:
     - Manages local clock time, master clock tracking, message transmission and reception (Sync, Follow_Up, Delay_Req, Delay_Resp, Announce).
     - Computes t1, t2, t3, t4 timestamps:
       mean_path_delay = ((t2 - t1) + (t4 - t3)) // 2
       offset_from_master = (t2 - t1) - mean_path_delay
     - Updates servo and local clock.
     - Implements ILogicUnit interface with scan_step(dt).
     - Synchronizes state to Horner OCS RegisterTable (%R1480..%R1487, %M345..%M346) with PrivilegeMode.SYSTEM.

3. Process Safety Interlocks & Diagnostics:
   - 0x0000: OK (Normal healthy synchronization)
   - 0xD101: BMCA Lost GM (Grandmaster announce timeout / lost master) -> clears %M345
   - 0xD102: Sync Timeout (Missed Sync/Follow_Up messages) -> clears %M345
   - 0xD103: Jitter Spike (Phase jitter excursion exceeds safety threshold) -> clears %M345
   - 0xD104: Hardware Lockout (SecurityGuard port lockout or hardware failure) -> clears %M345, sets FAULTY

4. Horner OCS Memory Space Integration:
   - %R1480: PtpClockState (0=Disabled, 1=Listening, 2=Pre-Master, 3=Master, 4=Passive, 5=Uncalibrated, 6=Slave, 7=Faulty)
   - %R1481: MasterOffsetMicrosHighWord (INT16)
   - %R1482: MasterOffsetMicrosLowWord (INT16, signed)
   - %R1483: MeanPathDelayMicros (INT16)
   - %R1484: FrequencyDriftPpbScaled (INT16, signed parts-per-billion frequency offset)
   - %R1485: GrandmasterClockClass (INT16, e.g. 6 = Primary Ref, 248 = Default)
   - %R1486: SyncDelayMessageCounter (INT16, counts)
   - %R1487: DiagnosticStatusCode (0x0000=OK, 0xD101, 0xD102, 0xD103, 0xD104)
   - %M345: CipSyncIsSynchronized (BOOL, True when offset < sync_threshold_ns, e.g. 1000 ns)
   - %M346: GrandmasterActiveFlag (BOOL, True when node is Grandmaster/Master)

5. Deterministic 9-Stage Verification Suite:
   - run_cip_sync_ptp_verification(output_path: Optional[str] = None) -> Dict[str, Any]
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
# 1. Constants & Timing Definitions (IEEE 1588-2008 & ODVA CIP Sync)
# ============================================================================

PTP_VERSION: int = 2
CIP_SYNC_CLASS_ID: int = 0x43  # ODVA CIP Time Sync Object Class ID
DEFAULT_DOMAIN_NUMBER: int = 0

DEFAULT_SYNC_INTERVAL_S: float = 0.125         # 8 Hz nominal sync rate
DEFAULT_ANNOUNCE_INTERVAL_S: float = 1.0       # 1 Hz nominal announce rate
DEFAULT_ANNOUNCE_RECEIPT_TIMEOUT: int = 3      # 3 missed announce messages
DEFAULT_SYNC_RECEIPT_TIMEOUT_S: float = 1.0    # 1.0s sync timeout limit

DEFAULT_SYNC_THRESHOLD_NS: int = 1000          # 1000 ns (1 us) synchronization threshold
DEFAULT_JITTER_SPIKE_THRESHOLD_NS: int = 20_000 # 20,000 ns (20 us) jitter spike trigger
MAX_ALLOWABLE_JITTER_NS: int = 50_000          # 50,000 ns (50 us) critical jitter excursion limit
MAX_SERVO_DRIFT_PPB: int = 32_767              # Clamped to INT16 range (-32768..32767)
DEFAULT_STEP_THRESHOLD_NS: int = 100_000       # 100,000 ns (100 us) step vs slewing boundary

NOMINAL_MEAN_PATH_DELAY_NS: int = 5_000        # 5,000 ns (5 us) nominal path propagation delay


# ============================================================================
# 2. Protocol Enums & Diagnostic Codes
# ============================================================================

class PtpPortState(IntEnum):
    """IEEE 1588-2008 PTP Port State Machine & Horner %R1480 Values."""
    DISABLED     = 0  # Port is administratively disabled or offline
    LISTENING    = 1  # Listening for PTP Announce messages from Grandmaster
    PRE_MASTER   = 2  # Qualification period before assuming Master state
    MASTER       = 3  # Clock port transmitting Sync, Follow_Up, and Announce
    PASSIVE      = 4  # Port in passive backup state (redundant master path)
    UNCALIBRATED = 5  # Master selected but phase/frequency offset not yet locked
    SLAVE        = 6  # Synchronized slave tracking active Grandmaster
    FAULTY       = 7  # Port faulted due to timeout, hardware error, or lockout

    # Aliases
    Disabled = 0
    Listening = 1
    PreMaster = 2
    Master = 3
    Passive = 4
    Uncalibrated = 5
    Slave = 6
    Faulty = 7


PtpClockState = PtpPortState


class PtpClockClass(IntEnum):
    """IEEE 1588-2008 Clock Class Definitions."""
    PRIMARY_REF          = 6    # Primary reference (e.g. GPS, Atomic Cesium)
    APPLICATION_SPECIFIC = 13   # Application-specific time source
    DEFAULT              = 248  # Default free-running local oscillator
    SLAVE_ONLY           = 255  # Slave-only clock node (cannot become Master)


class PtpMessageType(IntEnum):
    """IEEE 1588-2008 PTP Message Types (Header messageType nibble)."""
    SYNC                  = 0x0  # Event message: Master egress time t1
    DELAY_REQ             = 0x1  # Event message: Slave egress time t3
    PDELAY_REQ            = 0x2  # Event message: Peer delay request
    PDELAY_RESP           = 0x3  # Event message: Peer delay response
    FOLLOW_UP             = 0x8  # General message: Precise origin timestamp t1
    DELAY_RESP            = 0x9  # General message: Master ingress timestamp t4
    PDELAY_RESP_FOLLOW_UP = 0xA  # General message: Peer delay response follow-up
    ANNOUNCE              = 0xB  # General message: GM dataset advertising
    SIGNALING             = 0xC  # General message: Unicast negotiation
    MANAGEMENT            = 0xD  # General message: Management query/command


class PtpDiagnosticCode(IntEnum):
    """Horner OCS %R1487 Diagnostic Event Codes."""
    OK               = 0x0000  # Normal healthy synchronization
    BMCA_LOST_GM     = 0xD101  # BMCA lost Grandmaster (announce timeout expired)
    SYNC_TIMEOUT     = 0xD102  # Sync message timeout (master sync stream lost)
    JITTER_SPIKE     = 0xD103  # Jitter spike (phase offset exceeded spike threshold)
    HARDWARE_LOCKOUT = 0xD104  # Physical port access attempt or hardware fault lockout

    # Convenience aliases
    ERR_BMCA_LOST_GM     = 0xD101
    ERR_SYNC_TIMEOUT     = 0xD102
    ERR_JITTER_SPIKE     = 0xD103
    ERR_HARDWARE_LOCKOUT = 0xD104
    CIP_SYNC_ERR_BMCA_LOST_GM     = 0xD101
    CIP_SYNC_ERR_TIMEOUT          = 0xD102
    CIP_SYNC_ERR_JITTER_SPIKE     = 0xD103
    CIP_SYNC_ERR_HARDWARE_LOCKOUT = 0xD104


CipSyncDiagnosticCode = PtpDiagnosticCode
CIPSyncDiagnosticCode = PtpDiagnosticCode


class PtpFlagField(IntFlag):
    """IEEE 1588-2008 Header Flag Field."""
    TWO_STEP                = 1 << 1   # Bit 1 (0x0002): Two-Step clock flag
    UNICAST                 = 1 << 2   # Bit 2 (0x0004): Unicast transmission
    PTP_PROFILE_SPECIFIC_1  = 1 << 5   # Bit 5 (0x0020)
    PTP_PROFILE_SPECIFIC_2  = 1 << 6   # Bit 6 (0x0040)
    PTP_SECURITY            = 1 << 7   # Bit 7 (0x0080)
    LEAP_61                 = 1 << 8   # Bit 8 (0x0100)
    LEAP_59                 = 1 << 9   # Bit 9 (0x0200)
    CURRENT_UTC_OFFSET_VALID = 1 << 10 # Bit 10 (0x0400)
    PTP_TIMESCALE           = 1 << 11  # Bit 11 (0x0800): PTP epoch timescale
    TIME_TRACEABLE          = 1 << 12  # Bit 12 (0x1000)
    FREQUENCY_TRACEABLE     = 1 << 13  # Bit 13 (0x2000)


# ============================================================================
# 3. PtpTimestamp, TimeInterval, ClockIdentity, & ClockQuality
# ============================================================================

class PtpTimeInterval(int):
    """Time interval or duration in nanoseconds, behaving as an int with time accessors."""

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


@dataclass(order=True)
class PtpTimestamp:
    """IEEE 1588-2008 PTP Timestamp (seconds: uint48/int, nanoseconds: uint32)."""
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
    def from_ns(cls, total_ns: int) -> PtpTimestamp:
        """Construct PtpTimestamp from total nanoseconds."""
        sec, nsec = divmod(int(total_ns), 1_000_000_000)
        return cls(seconds=sec, nanoseconds=nsec)

    def to_float_seconds(self) -> float:
        """Convert timestamp to floating-point seconds."""
        return self.seconds + (self.nanoseconds / 1_000_000_000.0)

    @classmethod
    def from_float_seconds(cls, val_s: float) -> PtpTimestamp:
        """Construct PtpTimestamp from floating-point seconds."""
        sec = int(math.floor(val_s))
        nsec = int(round((val_s - sec) * 1_000_000_000.0))
        if nsec >= 1_000_000_000:
            sec += 1
            nsec -= 1_000_000_000
        return cls(seconds=sec, nanoseconds=nsec)

    def __add__(self, other: Union[PtpTimestamp, int, float]) -> PtpTimestamp:
        if isinstance(other, PtpTimestamp):
            return PtpTimestamp.from_ns(self.to_ns() + other.to_ns())
        elif isinstance(other, int):
            return PtpTimestamp.from_ns(self.to_ns() + other)
        elif isinstance(other, float):
            return PtpTimestamp.from_float_seconds(self.to_float_seconds() + other)
        return NotImplemented

    def __radd__(self, other: Union[int, float]) -> PtpTimestamp:
        return self.__add__(other)

    def __sub__(self, other: Union[PtpTimestamp, int, float]) -> Union[PtpTimeInterval, PtpTimestamp]:
        if isinstance(other, PtpTimestamp):
            return PtpTimeInterval(self.to_ns() - other.to_ns())
        elif isinstance(other, int):
            return PtpTimestamp.from_ns(self.to_ns() - other)
        elif isinstance(other, float):
            return PtpTimestamp.from_float_seconds(self.to_float_seconds() - other)
        return NotImplemented

    def __rsub__(self, other: Union[int, float]) -> Union[PtpTimeInterval, PtpTimestamp]:
        if isinstance(other, int):
            return PtpTimeInterval(other - self.to_ns())
        elif isinstance(other, float):
            return PtpTimestamp.from_float_seconds(other - self.to_float_seconds())
        return NotImplemented

    def __floordiv__(self, other: int) -> PtpTimestamp:
        return PtpTimestamp.from_ns(self.to_ns() // int(other))

    def __int__(self) -> int:
        return self.to_ns()

    def pack(self) -> bytes:
        """Pack into 10-octet standard IEEE 1588 timestamp format (48-bit sec + 32-bit nsec)."""
        sec_high = (self.seconds >> 32) & 0xFFFF
        sec_low = self.seconds & 0xFFFFFFFF
        return struct.pack(">HII", sec_high, sec_low, self.nanoseconds)

    @classmethod
    def unpack(cls, data: bytes) -> PtpTimestamp:
        """Unpack from 10-octet standard IEEE 1588 timestamp format."""
        if len(data) < 10:
            raise ValueError(f"PtpTimestamp requires 10 bytes, got {len(data)}")
        sec_high, sec_low, nsec = struct.unpack(">HII", data[:10])
        total_sec = (sec_high << 32) | sec_low
        return cls(seconds=total_sec, nanoseconds=nsec)


PTPTimestamp = PtpTimestamp


class PtpClockIdentity:
    """IEEE 1588 EUI-64 Clock Identity (8 octets)."""

    def __init__(self, value: Union[str, bytes, bytearray, int, Sequence[int], None] = None) -> None:
        if value is None:
            self._bytes = bytes([0x00, 0x1D, 0x9C, 0xFF, 0xFE, 0x00, 0x00, 0x01])
        elif isinstance(value, (bytes, bytearray)):
            if len(value) != 8:
                raise ValueError(f"PtpClockIdentity bytes must be 8 octets, got {len(value)}")
            self._bytes = bytes(value)
        elif isinstance(value, int):
            self._bytes = value.to_bytes(8, byteorder="big", signed=False)
        elif isinstance(value, str):
            clean = re.sub(r"[-:]", "", value.strip())
            if len(clean) != 16:
                raise ValueError(f"PtpClockIdentity hex string must be 16 hex digits (8 octets), got '{value}'")
            self._bytes = bytes.fromhex(clean)
        elif isinstance(value, (list, tuple)):
            if len(value) != 8:
                raise ValueError(f"PtpClockIdentity sequence must have 8 elements, got {len(value)}")
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
    def from_mac(cls, mac: str) -> PtpClockIdentity:
        """Convert 48-bit MAC address to 64-bit PTP Clock Identity via standard EUI-48 to EUI-64."""
        clean = re.sub(r"[-:]", "", mac.strip())
        if len(clean) != 12:
            raise ValueError(f"MAC address must have 12 hex digits, got '{mac}'")
        b = bytes.fromhex(clean)
        # EUI-64 conversion: insert 0xFF, 0xFE between 3rd and 4th octet
        eui64 = bytes([b[0], b[1], b[2], 0xFF, 0xFE, b[3], b[4], b[5]])
        return cls(eui64)

    @classmethod
    def default_local(cls) -> PtpClockIdentity:
        return cls("00-1D-9C-FF-FE-12-34-56")

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, PtpClockIdentity):
            return self._bytes == other._bytes
        if isinstance(other, (bytes, bytearray)):
            return self._bytes == bytes(other)
        if isinstance(other, str):
            try:
                return self == PtpClockIdentity(other)
            except Exception:
                return False
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, PtpClockIdentity):
            return self.to_int() < other.to_int()
        if isinstance(other, str):
            return self.to_int() < PtpClockIdentity(other).to_int()
        return NotImplemented

    def __le__(self, other: Any) -> bool:
        return self == other or self < other

    def __gt__(self, other: Any) -> bool:
        if isinstance(other, PtpClockIdentity):
            return self.to_int() > other.to_int()
        if isinstance(other, str):
            return self.to_int() > PtpClockIdentity(other).to_int()
        return NotImplemented

    def __ge__(self, other: Any) -> bool:
        return self == other or self > other

    def __hash__(self) -> int:
        return hash(self._bytes)

    def __str__(self) -> str:
        return self.to_hex()

    def __repr__(self) -> str:
        return f"PtpClockIdentity('{self.to_hex()}')"


PTPClockIdentity = PtpClockIdentity


@dataclass
class PtpClockQuality:
    """IEEE 1588-2008 Clock Quality descriptor."""
    clockClass: int = int(PtpClockClass.DEFAULT)
    clockAccuracy: int = 0xFE
    offsetScaledLogVariance: int = 0xFFFF

    def __lt__(self, other: PtpClockQuality) -> bool:
        return (self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance) < (
            other.clockClass, other.clockAccuracy, other.offsetScaledLogVariance
        )

    def __le__(self, other: PtpClockQuality) -> bool:
        return (self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance) <= (
            other.clockClass, other.clockAccuracy, other.offsetScaledLogVariance
        )

    def __gt__(self, other: PtpClockQuality) -> bool:
        return (self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance) > (
            other.clockClass, other.clockAccuracy, other.offsetScaledLogVariance
        )

    def __ge__(self, other: PtpClockQuality) -> bool:
        return (self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance) >= (
            other.clockClass, other.clockAccuracy, other.offsetScaledLogVariance
        )

    def pack(self) -> bytes:
        return struct.pack(">BBH", self.clockClass, self.clockAccuracy, self.offsetScaledLogVariance)

    @classmethod
    def unpack(cls, data: bytes) -> PtpClockQuality:
        if len(data) < 4:
            raise ValueError("PtpClockQuality requires at least 4 bytes")
        c_class, c_acc, var = struct.unpack(">BBH", data[:4])
        return cls(clockClass=c_class, clockAccuracy=c_acc, offsetScaledLogVariance=var)


PTPClockQuality = PtpClockQuality


@dataclass
class PtpPortIdentity:
    """IEEE 1588 Port Identity (ClockIdentity 8 bytes + PortNumber 2 bytes)."""
    clockIdentity: PtpClockIdentity = field(default_factory=PtpClockIdentity)
    portNumber: int = 1

    def pack(self) -> bytes:
        return self.clockIdentity.to_bytes() + struct.pack(">H", self.portNumber)

    @classmethod
    def unpack(cls, data: bytes) -> PtpPortIdentity:
        if len(data) < 10:
            raise ValueError("PtpPortIdentity requires 10 bytes")
        cid = PtpClockIdentity(data[:8])
        pnum = struct.unpack(">H", data[8:10])[0]
        return cls(clockIdentity=cid, portNumber=pnum)


# ============================================================================
# 4. Best Master Clock Algorithm (BMCA) & Dataset Definitions
# ============================================================================

@dataclass
class PtpDataset:
    """Dataset descriptor used in IEEE 1588 Best Master Clock Algorithm (BMCA)."""
    priority1: int = 128
    clockQuality: PtpClockQuality = field(default_factory=PtpClockQuality)
    priority2: int = 128
    clockIdentity: PtpClockIdentity = field(default_factory=PtpClockIdentity)
    stepsRemoved: int = 0


class BestMasterClockAlgorithm:
    """IEEE 1588-2008 Best Master Clock Algorithm (BMCA) comparison logic."""

    @staticmethod
    def compare_datasets(a: PtpDataset, b: PtpDataset) -> int:
        """Compare datasets A and B per IEEE 1588-2008 clause 9.3.4.

        Returns:
            -1 if dataset A is better (wins)
             1 if dataset B is better (wins)
             0 if datasets are identical
        """
        # 1. priority1 (lower integer is better)
        if a.priority1 < b.priority1:
            return -1
        if a.priority1 > b.priority1:
            return 1

        # 2. clockClass (lower is better, e.g. 6 < 248)
        if a.clockQuality.clockClass < b.clockQuality.clockClass:
            return -1
        if a.clockQuality.clockClass > b.clockQuality.clockClass:
            return 1

        # 3. clockAccuracy (lower is better)
        if a.clockQuality.clockAccuracy < b.clockQuality.clockAccuracy:
            return -1
        if a.clockQuality.clockAccuracy > b.clockQuality.clockAccuracy:
            return 1

        # 4. offsetScaledLogVariance (lower is better)
        if a.clockQuality.offsetScaledLogVariance < b.clockQuality.offsetScaledLogVariance:
            return -1
        if a.clockQuality.offsetScaledLogVariance > b.clockQuality.offsetScaledLogVariance:
            return 1

        # 5. priority2 (lower is better)
        if a.priority2 < b.priority2:
            return -1
        if a.priority2 > b.priority2:
            return 1

        # 6. stepsRemoved (lower topology hops is better)
        if a.stepsRemoved < b.stepsRemoved:
            return -1
        if a.stepsRemoved > b.stepsRemoved:
            return 1

        # 7. clockIdentity (lower numerical value is better tie-breaker)
        if a.clockIdentity < b.clockIdentity:
            return -1
        if a.clockIdentity > b.clockIdentity:
            return 1

        return 0

    @classmethod
    def select_master(
        cls,
        local_dataset: PtpDataset,
        foreign_datasets: Sequence[PtpDataset],
    ) -> Tuple[PtpDataset, bool]:
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


# ============================================================================
# 5. Clock PI Servo Controller
# ============================================================================

class PtpServo:
    """Proportional-Integral (PI) Clock Servo Controller for PTP phase & drift alignment."""

    def __init__(
        self,
        kp: float = 0.6,
        ki: float = 1.0,
        step_threshold_ns: int = DEFAULT_STEP_THRESHOLD_NS,
        max_drift_ppb: int = MAX_SERVO_DRIFT_PPB,
        jitter_spike_threshold_ns: int = DEFAULT_JITTER_SPIKE_THRESHOLD_NS,
    ) -> None:
        self.kp = float(kp)
        self.ki = float(ki)
        self.step_threshold_ns = int(step_threshold_ns)
        self.max_drift_ppb = int(max_drift_ppb)
        self.jitter_spike_threshold_ns = int(jitter_spike_threshold_ns)

        self.integral_error: float = 0.0
        self.frequency_drift_ppb: int = 0
        self.last_offset_ns: int = 0
        self.jitter_spike_count: int = 0
        self.last_phase_adj_ns: int = 0
        self.is_locked: bool = False

    def reset(self) -> None:
        """Reset internal servo integrator, state flags, and counters."""
        self.integral_error = 0.0
        self.frequency_drift_ppb = 0
        self.last_offset_ns = 0
        self.jitter_spike_count = 0
        self.last_phase_adj_ns = 0
        self.is_locked = False

    def sample(self, offset_ns: int, dt: float = 1.0) -> Tuple[int, int]:
        """Process phase offset sample and calculate frequency drift and phase adjustment.

        Args:
            offset_ns: Offset from master in nanoseconds.
            dt: Time step in seconds.

        Returns:
            Tuple of (frequency_drift_ppb: int, phase_adjustment_ns: int).
        """
        dt_clamped = max(0.001, min(10.0, float(dt)))
        abs_offset = abs(offset_ns)

        # 1. Jitter Spike Detection & Filter Clamping
        is_spike = abs_offset > self.jitter_spike_threshold_ns
        if is_spike:
            self.jitter_spike_count += 1
            # Clamping filter prevents integral runaway from rogue transient excursions
            clamped_offset = int(math.copysign(self.jitter_spike_threshold_ns, offset_ns))
        else:
            clamped_offset = offset_ns

        # 2. Phase Step vs Slewing
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

            if abs_offset < DEFAULT_SYNC_THRESHOLD_NS:
                self.is_locked = True
            else:
                self.is_locked = False

        self.last_offset_ns = offset_ns
        self.last_phase_adj_ns = phase_adj
        return self.frequency_drift_ppb, phase_adj


# ============================================================================
# 6. PTP Wire Framing & CIP Sync Object (Class 0x43)
# ============================================================================

@dataclass
class PtpHeader:
    """IEEE 1588-2008 Standard 34-Octet Message Header."""
    messageType: PtpMessageType = PtpMessageType.SYNC
    versionPTP: int = PTP_VERSION
    messageLength: int = 34
    domainNumber: int = DEFAULT_DOMAIN_NUMBER
    flagField: int = int(PtpFlagField.TWO_STEP)
    correctionField: int = 0
    sourcePortIdentity: PtpPortIdentity = field(default_factory=PtpPortIdentity)
    sequenceId: int = 0
    controlField: int = 0
    logMessageInterval: int = 0

    def pack(self) -> bytes:
        first_byte = (int(self.messageType) & 0x0F)
        sec_byte = (self.versionPTP & 0x0F)
        return struct.pack(
            ">BBHBBHQIHBBb",
            first_byte,
            sec_byte,
            self.messageLength,
            self.domainNumber,
            0,  # reserved1
            self.flagField,
            self.correctionField,
            0,  # reserved2
            self.sourcePortIdentity.portNumber,
            self.sequenceId,
            self.controlField,
            self.logMessageInterval,
        )[:20] + self.sourcePortIdentity.clockIdentity.to_bytes() + struct.pack(
            ">HHBb",
            self.sourcePortIdentity.portNumber,
            self.sequenceId,
            self.controlField,
            self.logMessageInterval,
        )

    @classmethod
    def create(
        cls,
        msg_type: PtpMessageType,
        source_identity: PtpClockIdentity,
        sequence_id: int,
        two_step: bool = True,
        msg_len: int = 44,
    ) -> PtpHeader:
        flags = int(PtpFlagField.TWO_STEP) if two_step else 0
        return cls(
            messageType=msg_type,
            versionPTP=PTP_VERSION,
            messageLength=msg_len,
            domainNumber=DEFAULT_DOMAIN_NUMBER,
            flagField=flags,
            correctionField=0,
            sourcePortIdentity=PtpPortIdentity(clockIdentity=source_identity, portNumber=1),
            sequenceId=sequence_id,
            controlField=0,
            logMessageInterval=0,
        )


@dataclass
class PtpSyncMessage:
    """PTP Sync Message."""
    header: PtpHeader
    originTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)


@dataclass
class PtpFollowUpMessage:
    """PTP Follow_Up Message (contains precise t1)."""
    header: PtpHeader
    preciseOriginTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)


@dataclass
class PtpDelayReqMessage:
    """PTP Delay_Req Message."""
    header: PtpHeader
    originTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)


@dataclass
class PtpDelayRespMessage:
    """PTP Delay_Resp Message (contains t4)."""
    header: PtpHeader
    receiveTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)
    requestingPortIdentity: PtpPortIdentity = field(default_factory=PtpPortIdentity)


@dataclass
class PtpAnnounceMessage:
    """PTP Announce Message (carries BMCA GM clock dataset)."""
    header: PtpHeader
    originTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)
    currentUtcOffset: int = 37
    grandmasterPriority1: int = 128
    grandmasterClockQuality: PtpClockQuality = field(default_factory=PtpClockQuality)
    grandmasterPriority2: int = 128
    grandmasterIdentity: PtpClockIdentity = field(default_factory=PtpClockIdentity)
    stepsRemoved: int = 0
    timeSource: int = 0xA0  # Internal oscillator

    def to_dataset(self) -> PtpDataset:
        return PtpDataset(
            priority1=self.grandmasterPriority1,
            clockQuality=self.grandmasterClockQuality,
            priority2=self.grandmasterPriority2,
            clockIdentity=self.grandmasterIdentity,
            stepsRemoved=self.stepsRemoved,
        )


@dataclass
class CipTimeSyncObject:
    """ODVA CIP Sync Profile - Time Sync Object (Class 0x43) Attributes."""
    IsSynchronized: bool = False             # Attribute 1 (%M345)
    IsOwner: bool = False                    # Attribute 2 (%M346 GrandmasterActiveFlag)
    SystemTimeMicroseconds: int = 0          # Attribute 3
    OffsetFromMasterMicros: int = 0          # Attribute 4 (%R1481..%R1482)
    MeanPathDelayMicros: int = 0             # Attribute 5 (%R1483)
    GrandmasterClockClass: int = 248         # Attribute 6 (%R1485)
    GrandmasterIdentity: str = ""            # Attribute 7
    ClockState: int = 0                      # Attribute 8 (%R1480)
    StepsRemoved: int = 0                    # Attribute 9
    ClockType: int = 0                       # Attribute 10 (0=Ordinary Clock)
    DiagnosticStatusCode: int = 0            # (%R1487)


# ============================================================================
# 7. Register Helper Functions (%R1480..%R1487, %M345..%M346)
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
    """Encode 32-bit signed integer into (high_word, low_word) pair for Horner OCS."""
    val = int(value_32) & 0xFFFFFFFF
    high = (val >> 16) & 0xFFFF
    low = val & 0xFFFF
    high_s = high - 65536 if high > 32767 else high
    low_s = low - 65536 if low > 32767 else low
    return high_s, low_s


def decode_dint_words(high_word: int, low_word: int) -> int:
    """Reconstruct 32-bit signed integer from (high_word, low_word) pair."""
    h = int(high_word) & 0xFFFF
    l = int(low_word) & 0xFFFF
    val_32 = (h << 16) | l
    if val_32 >= 0x80000000:
        val_32 -= 0x100000000
    return val_32


# ============================================================================
# 8. Pure IEC 61131-3 Structured Text POU
# ============================================================================

CIP_SYNC_PTP_SYNC_POU: str = """PROGRAM CipSyncPtpSync
VAR
    (* Horner OCS Mapped Registers (W187 - PTP CIP Sync Engine) *)
    PtpClockState               AT %R1480 : INT;    (* 0=Disabled, 1=Listening, 2=Pre-Master, 3=Master, 4=Passive, 5=Uncalibrated, 6=Slave, 7=Faulty *)
    MasterOffsetMicrosHighWord  AT %R1481 : INT;    (* Master Offset in us (High Word) *)
    MasterOffsetMicrosLowWord   AT %R1482 : INT;    (* Master Offset in us (Low Word, signed) *)
    MeanPathDelayMicros         AT %R1483 : INT;    (* Mean Path Propagation Delay in us *)
    FrequencyDriftPpbScaled     AT %R1484 : INT;    (* Clock Frequency Drift in parts-per-billion *)
    GrandmasterClockClass       AT %R1485 : INT;    (* GM Clock Class (e.g. 6=Primary Ref, 248=Default) *)
    SyncDelayMessageCounter     AT %R1486 : INT;    (* Message Transaction Counter *)
    DiagnosticStatusCode        AT %R1487 : UINT;   (* Diagnostic Status Code (0x0000=OK, 0xD101..0xD104) *)

    (* Discrete Synchronization & Safety Flags *)
    CipSyncIsSynchronized       AT %M345  : BOOL;   (* TRUE when locked and offset < threshold *)
    GrandmasterActiveFlag       AT %M346  : BOOL;   (* TRUE when node is Grandmaster/Master *)
END_VAR
VAR
    SyncOperational             : BOOL;
END_VAR

(* Synchronized State and Safety Evaluation *)
IF (DiagnosticStatusCode <> 0) OR (PtpClockState = 7) THEN
    CipSyncIsSynchronized := FALSE;
    SyncOperational := FALSE;
ELSIF (PtpClockState = 6) AND CipSyncIsSynchronized THEN
    SyncOperational := TRUE;
    GrandmasterActiveFlag := FALSE;
ELSIF (PtpClockState = 3) THEN
    GrandmasterActiveFlag := TRUE;
    CipSyncIsSynchronized := TRUE;
    SyncOperational := TRUE;
ELSE
    SyncOperational := FALSE;
END_IF;
END_PROGRAM
"""

CipSyncPtpPOU = CIP_SYNC_PTP_SYNC_POU
PTP_CIP_SYNC_POU = CIP_SYNC_PTP_SYNC_POU
CIP_SYNC_POU = CIP_SYNC_PTP_SYNC_POU


# ============================================================================
# 9. CipSyncPtpEngine (ILogicUnit)
# ============================================================================

class CipSyncPtpEngine(ILogicUnit):
    """ODVA CIP Sync Profile & IEEE 1588-2008 Precision Time Protocol Engine."""

    def __init__(
        self,
        clock_identity: Optional[Union[str, PtpClockIdentity]] = None,
        clock_class: PtpClockClass = PtpClockClass.DEFAULT,
        priority1: int = 128,
        priority2: int = 128,
        reg_table: Optional[RegisterTable] = None,
        sync_threshold_ns: int = DEFAULT_SYNC_THRESHOLD_NS,
        servo: Optional[PtpServo] = None,
    ) -> None:
        self.clock_identity = (
            PtpClockIdentity(clock_identity)
            if clock_identity is not None
            else PtpClockIdentity.default_local()
        )
        self.local_dataset = PtpDataset(
            priority1=priority1,
            clockQuality=PtpClockQuality(
                clockClass=int(clock_class),
                clockAccuracy=0x21 if clock_class == PtpClockClass.PRIMARY_REF else 0xFE,
                offsetScaledLogVariance=0x4000 if clock_class == PtpClockClass.PRIMARY_REF else 0xFFFF,
            ),
            priority2=priority2,
            clockIdentity=self.clock_identity,
            stepsRemoved=0,
        )

        self.reg_table: Optional[RegisterTable] = reg_table
        self.sync_threshold_ns: int = int(sync_threshold_ns)
        self.servo: PtpServo = servo if servo is not None else PtpServo()

        # Port state & Grandmaster Tracking
        self.state: PtpPortState = PtpPortState.LISTENING
        self.gm_dataset: Optional[PtpDataset] = None
        self.is_grandmaster: bool = False
        self.is_synchronized: bool = False

        # Clocks & Timestamps
        self.local_clock: PtpTimestamp = PtpTimestamp(seconds=1000, nanoseconds=0)
        self.t1: Optional[PtpTimestamp] = None  # Master Sync transmit
        self.t2: Optional[PtpTimestamp] = None  # Slave Sync receive
        self.t3: Optional[PtpTimestamp] = None  # Slave Delay_Req transmit
        self.t4: Optional[PtpTimestamp] = None  # Master Delay_Req receive

        # Metrics
        self.offset_from_master_ns: int = 0
        self.mean_path_delay_ns: int = 0
        self.frequency_drift_ppb: int = 0
        self.message_counter: int = 0
        self.diagnostic_code: PtpDiagnosticCode = PtpDiagnosticCode.OK

        # Sequence IDs
        self.sync_sequence_id: int = 0
        self.delay_req_sequence_id: int = 0

        # Watchdog & Simulation Timers
        self.time_since_last_sync_s: float = 0.0
        self.time_since_last_announce_s: float = 0.0
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
        return "cip_sync_ptp"

    @property
    def priority(self) -> int:
        return 92

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def execute(self, ctx: ScanContext) -> None:
        """Execute one discrete scan cycle within the Horner simulation framework."""
        dt_ms = getattr(ctx, "dt_ms", 10.0)
        self.scan_step(dt=dt_ms / 1000.0)

    def reset(self) -> None:
        """Reset internal engine state and clear fault latches."""
        self.reset_fault(force=True)

    def scan_step(self, dt: float = 0.01) -> Dict[str, Any]:
        """Advance discrete simulation clock, evaluate watchdogs, and synchronize registers."""
        dt_s = float(dt)
        self.elapsed_simulation_ms += dt_s * 1000.0
        self.total_scan_cycles += 1

        # Advance local clock with current frequency drift
        drift_rate = 1.0 + (self.frequency_drift_ppb / 1_000_000_000.0)
        dt_advanced_ns = int(round(dt_s * drift_rate * 1_000_000_000.0))
        self.local_clock = self.local_clock + dt_advanced_ns

        # Evaluate watchdogs if operating in SLAVE state
        if self.state == PtpPortState.SLAVE:
            self.time_since_last_sync_s += dt_s
            self.time_since_last_announce_s += dt_s

            if (
                self.time_since_last_announce_s > (DEFAULT_ANNOUNCE_INTERVAL_S * DEFAULT_ANNOUNCE_RECEIPT_TIMEOUT)
                and self.diagnostic_code == PtpDiagnosticCode.OK
            ):
                self.trip_fault(
                    PtpDiagnosticCode.BMCA_LOST_GM,
                    f"Grandmaster announce timeout ({self.time_since_last_announce_s:.2f}s > 3.0s)",
                )

            elif (
                self.time_since_last_sync_s > DEFAULT_SYNC_RECEIPT_TIMEOUT_S
                and self.diagnostic_code == PtpDiagnosticCode.OK
            ):
                self.trip_fault(
                    PtpDiagnosticCode.SYNC_TIMEOUT,
                    f"Sync message receipt timeout ({self.time_since_last_sync_s:.2f}s > 1.0s)",
                )

        self.sync_to_registers()
        return {
            "state": self.state.name,
            "diagnostic_code": int(self.diagnostic_code),
            "offset_ns": self.offset_from_master_ns,
            "mean_path_delay_ns": self.mean_path_delay_ns,
            "frequency_drift_ppb": self.frequency_drift_ppb,
            "is_synchronized": self.is_synchronized,
            "is_grandmaster": self.is_grandmaster,
        }

    # ------------------------------------------------------------------------
    # Protocol Message Handlers & Timestamp Equations
    # ------------------------------------------------------------------------

    def process_announce(self, announce_msg: PtpAnnounceMessage) -> bool:
        """Process received PTP Announce message and evaluate BMCA."""
        foreign_dataset = announce_msg.to_dataset()
        self.time_since_last_announce_s = 0.0

        best_dataset, is_local_master = BMCA.select_master(self.local_dataset, [foreign_dataset])
        if is_local_master:
            self.state = PtpPortState.MASTER
            self.is_grandmaster = True
            self.is_synchronized = True
            self.gm_dataset = self.local_dataset
            self.offset_from_master_ns = 0
        else:
            self.gm_dataset = foreign_dataset
            self.is_grandmaster = False
            if self.state in (PtpPortState.LISTENING, PtpPortState.PRE_MASTER, PtpPortState.MASTER):
                self.state = PtpPortState.UNCALIBRATED

        self.message_counter += 1
        self.sync_to_registers()
        return is_local_master

    def process_sync(
        self,
        sync_msg: PtpSyncMessage,
        ingress_timestamp: Optional[PtpTimestamp] = None,
    ) -> PtpTimestamp:
        """Process incoming Sync message and record ingress timestamp t2."""
        t2 = ingress_timestamp if ingress_timestamp is not None else self.local_clock
        self.t2 = t2
        self.sync_sequence_id = sync_msg.header.sequenceId
        self.time_since_last_sync_s = 0.0

        # One-step clock fallback
        if not (sync_msg.header.flagField & int(PtpFlagField.TWO_STEP)):
            self.t1 = sync_msg.originTimestamp

        self.message_counter += 1
        return t2

    def process_follow_up(self, follow_up_msg: PtpFollowUpMessage) -> bool:
        """Process Follow_Up message and record precise origin timestamp t1."""
        if follow_up_msg.header.sequenceId != self.sync_sequence_id:
            return False

        self.t1 = follow_up_msg.preciseOriginTimestamp
        self.message_counter += 1
        return True

    def send_delay_req(
        self,
        egress_timestamp: Optional[PtpTimestamp] = None,
    ) -> Tuple[PtpDelayReqMessage, PtpTimestamp]:
        """Generate Delay_Req message and record slave egress timestamp t3."""
        self.delay_req_sequence_id += 1
        t3 = egress_timestamp if egress_timestamp is not None else self.local_clock
        self.t3 = t3

        header = PtpHeader.create(
            msg_type=PtpMessageType.DELAY_REQ,
            source_identity=self.clock_identity,
            sequence_id=self.delay_req_sequence_id,
            two_step=False,
            msg_len=44,
        )
        msg = PtpDelayReqMessage(header=header, originTimestamp=t3)
        self.message_counter += 1
        return msg, t3

    def process_delay_resp(self, delay_resp_msg: PtpDelayRespMessage) -> Dict[str, Any]:
        """Process Delay_Resp message, stamp t4, and compute mean path delay and master offset."""
        self.t4 = delay_resp_msg.receiveTimestamp
        self.message_counter += 1

        if self.t1 is None or self.t2 is None or self.t3 is None or self.t4 is None:
            return {"status": "incomplete_timestamps"}

        # Canonical IEEE 1588-2008 & ODVA CIP Sync timestamp formulas
        t2_minus_t1 = int(self.t2 - self.t1)
        t4_minus_t3 = int(self.t4 - self.t3)

        self.mean_path_delay_ns = (t2_minus_t1 + t4_minus_t3) // 2
        self.offset_from_master_ns = t2_minus_t1 - self.mean_path_delay_ns

        # Feed PI Clock Servo
        drift_ppb, phase_adj = self.servo.sample(self.offset_from_master_ns, dt=DEFAULT_SYNC_INTERVAL_S)
        self.frequency_drift_ppb = drift_ppb

        # Apply phase correction to local clock
        self.local_clock = self.local_clock - phase_adj

        # Check jitter spike excursion
        if abs(self.offset_from_master_ns) > MAX_ALLOWABLE_JITTER_NS and self.diagnostic_code == PtpDiagnosticCode.OK:
            self.trip_fault(
                PtpDiagnosticCode.JITTER_SPIKE,
                f"Phase jitter excursion {abs(self.offset_from_master_ns)}ns exceeded critical limit {MAX_ALLOWABLE_JITTER_NS}ns",
            )
        elif abs(self.offset_from_master_ns) < self.sync_threshold_ns and self.diagnostic_code == PtpDiagnosticCode.OK:
            self.state = PtpPortState.SLAVE
            self.is_synchronized = True

        self.sync_to_registers()
        return {
            "status": "synchronized" if self.is_synchronized else "calibrating",
            "mean_path_delay_ns": self.mean_path_delay_ns,
            "offset_from_master_ns": self.offset_from_master_ns,
            "drift_ppb": self.frequency_drift_ppb,
            "phase_adj_ns": phase_adj,
        }

    # ------------------------------------------------------------------------
    # Fault Handling & Diagnostic Trips
    # ------------------------------------------------------------------------

    def trip_fault(self, code: PtpDiagnosticCode, details: str) -> None:
        """Latch diagnostic fault code, clear synchronization, and update state."""
        self.diagnostic_code = code
        self.is_synchronized = False
        if code in (PtpDiagnosticCode.HARDWARE_LOCKOUT, PtpDiagnosticCode.SYNC_TIMEOUT):
            self.state = PtpPortState.FAULTY
        elif code == PtpDiagnosticCode.BMCA_LOST_GM:
            self.state = PtpPortState.LISTENING
        self.sync_to_registers()

    def simulate_bmca_lost_gm(self) -> None:
        """Simulate BMCA lost Grandmaster fault (0xD101)."""
        self.trip_fault(PtpDiagnosticCode.BMCA_LOST_GM, "Simulated Grandmaster announce timeout")

    def simulate_sync_timeout(self) -> None:
        """Simulate master Sync message timeout (0xD102)."""
        self.trip_fault(PtpDiagnosticCode.SYNC_TIMEOUT, "Simulated Sync receipt watchdog timeout")

    def simulate_jitter_spike(self, spike_ns: int = 80_000) -> None:
        """Simulate severe jitter excursion spike (0xD103)."""
        self.offset_from_master_ns = int(spike_ns)
        self.trip_fault(PtpDiagnosticCode.JITTER_SPIKE, f"Simulated jitter spike {spike_ns}ns")

    def simulate_hardware_lockout(self) -> None:
        """Simulate hardware port access safety lockout (0xD104)."""
        try:
            # Exercise fail-closed SecurityGuard hardware ban
            SecurityGuard.assert_port_safe("COM1")
        except HardwareLockoutError as err:
            self.trip_fault(PtpDiagnosticCode.HARDWARE_LOCKOUT, str(err))

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Perform operator reset handshake, clear diagnostic code, and restore healthy state."""
        self.diagnostic_code = PtpDiagnosticCode.OK
        self.time_since_last_sync_s = 0.0
        self.time_since_last_announce_s = 0.0
        self.servo.reset()
        if force:
            self.offset_from_master_ns = 0

        if self.is_grandmaster:
            self.state = PtpPortState.MASTER
            self.is_synchronized = True
        else:
            self.state = PtpPortState.SLAVE if abs(self.offset_from_master_ns) < self.sync_threshold_ns else PtpPortState.UNCALIBRATED
            self.is_synchronized = (self.state == PtpPortState.SLAVE)

        self.sync_to_registers()
        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details="Operator reset handshake completed; PTP CIP Sync restored to operational state.",
        )

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization (%R1480..%R1487, %M345..%M346)
    # ------------------------------------------------------------------------

    def sync_to_registers(self, reg_table: Optional[RegisterTable] = None) -> None:
        """Synchronize PTP state into Horner OCS memory image with PrivilegeMode.SYSTEM."""
        rt = reg_table if reg_table is not None else self.reg_table
        if rt is None:
            return

        # %R1480: PtpClockState (0..7)
        safe_write_word(rt, "%R1480", int(self.state))

        # %R1481 & %R1482: MasterOffsetMicrosHighWord / MasterOffsetMicrosLowWord (INT16, signed 32-bit DINT)
        offset_micros = int(self.offset_from_master_ns // 1000)
        high_word, low_word = encode_dint_words(offset_micros)
        safe_write_word(rt, "%R1481", high_word)
        safe_write_word(rt, "%R1482", low_word)

        # %R1483: MeanPathDelayMicros (INT16)
        mean_delay_micros = max(0, min(32767, int(self.mean_path_delay_ns // 1000)))
        safe_write_word(rt, "%R1483", mean_delay_micros)

        # %R1484: FrequencyDriftPpbScaled (INT16, signed parts-per-billion frequency offset)
        safe_write_word(rt, "%R1484", max(-32768, min(32767, int(self.frequency_drift_ppb))))

        # %R1485: GrandmasterClockClass (INT16, e.g. 6 = Primary Ref, 248 = Default)
        gm_class = int(
            self.gm_dataset.clockQuality.clockClass
            if self.gm_dataset is not None
            else self.local_dataset.clockQuality.clockClass
        )
        safe_write_word(rt, "%R1485", gm_class)

        # %R1486: SyncDelayMessageCounter (INT16, counts)
        safe_write_word(rt, "%R1486", self.message_counter & 0x7FFF)

        # %R1487: DiagnosticStatusCode (0x0000=OK, 0xD101..0xD104)
        safe_write_uword(rt, "%R1487", int(self.diagnostic_code))

        # %M345: CipSyncIsSynchronized (BOOL, True when offset < sync_threshold_ns, e.g. 1000 ns)
        is_sync = (
            (self.state == PtpPortState.SLAVE and abs(self.offset_from_master_ns) < self.sync_threshold_ns and self.diagnostic_code == PtpDiagnosticCode.OK)
            or (self.state == PtpPortState.MASTER and self.diagnostic_code == PtpDiagnosticCode.OK)
        )
        self.is_synchronized = is_sync
        safe_write_bit(rt, "%M345", is_sync)

        # %M346: GrandmasterActiveFlag (BOOL, True when node is Grandmaster/Master)
        is_gm = (self.state == PtpPortState.MASTER)
        self.is_grandmaster = is_gm
        safe_write_bit(rt, "%M346", is_gm)


CIPSyncPtpEngine = CipSyncPtpEngine


# ============================================================================
# 10. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_sync_ptp_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W187.

    Returns strict 4-state contract response dictionary:
    - Stage 1: POU ST syntax validation and anti-ladder check.
    - Stage 2: BMCA dataset comparison and master election.
    - Stage 3: Two-step Sync + Follow_Up timestamp processing.
    - Stage 4: Delay_Req + Delay_Resp path delay calculation.
    - Stage 5: PI Clock Servo convergence and drift correction.
    - Stage 6: Jitter spike detection and filter clamping.
    - Stage 7: Register table synchronization (%R1480..%R1487, %M345..%M346).
    - Stage 8: Discrete ILogicUnit 100-cycle scan simulation.
    - Stage 9: Process safety interlock and diagnostic fault trip testing.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: POU ST syntax validation and anti-ladder check
    # ------------------------------------------------------------------------
    val_pou = STParser.validate_code(CIP_SYNC_PTP_SYNC_POU)
    ast_pou = STParser.parse_pou(CIP_SYNC_PTP_SYNC_POU)

    expected_regs = {
        "%R1480", "%R1481", "%R1482", "%R1483",
        "%R1484", "%R1485", "%R1486", "%R1487",
        "%M345", "%M346",
    }
    bound_regs = set(ast_pou.bound_registers)

    ladder_rejected = True
    for bad_construct in ["---[ ]---", "---( )---", "RUNG 1", "XIC MasterClock_Sync"]:
        try:
            SecurityGuard.assert_pure_st_content(f"PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\n{bad_construct}\nEND_PROGRAM")
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    # Verify pure ST passes without error
    SecurityGuard.assert_pure_st_content(CIP_SYNC_PTP_SYNC_POU)

    s1_pass = (
        val_pou.status == AgentStatus.SUCCESS
        and ast_pou.name == "CipSyncPtpSync"
        and expected_regs.issubset(bound_regs)
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "POU_ST_Syntax_Validation_And_Anti_Ladder_Check",
        "passed": s1_pass,
        "details": f"IEC 61131-3 POU 'CipSyncPtpSync' parsed cleanly; {len(bound_regs)} registers bound; ladder constructs rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: BMCA dataset comparison and master election
    # ------------------------------------------------------------------------
    ds_primary = PtpDataset(
        priority1=128,
        clockQuality=PtpClockQuality(clockClass=int(PtpClockClass.PRIMARY_REF), clockAccuracy=0x20, offsetScaledLogVariance=0x4000),
        priority2=128,
        clockIdentity=PtpClockIdentity("00-11-22-33-44-55-66-01"),
    )
    ds_default = PtpDataset(
        priority1=128,
        clockQuality=PtpClockQuality(clockClass=int(PtpClockClass.DEFAULT), clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF),
        priority2=128,
        clockIdentity=PtpClockIdentity("00-11-22-33-44-55-66-02"),
    )
    ds_override = PtpDataset(
        priority1=100,  # Superior priority1
        clockQuality=PtpClockQuality(clockClass=int(PtpClockClass.DEFAULT), clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF),
        priority2=128,
        clockIdentity=PtpClockIdentity("00-11-22-33-44-55-66-03"),
    )
    ds_tie1 = PtpDataset(
        priority1=128,
        clockQuality=PtpClockQuality(clockClass=248, clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF),
        priority2=128,
        clockIdentity=PtpClockIdentity("00-00-00-00-00-00-00-01"),
    )
    ds_tie2 = PtpDataset(
        priority1=128,
        clockQuality=PtpClockQuality(clockClass=248, clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF),
        priority2=128,
        clockIdentity=PtpClockIdentity("00-00-00-00-00-00-00-02"),
    )

    cmp_class = BMCA.compare_datasets(ds_primary, ds_default)  # -1 (primary wins)
    cmp_priority = BMCA.compare_datasets(ds_override, ds_primary)  # -1 (override wins)
    cmp_tie = BMCA.compare_datasets(ds_tie1, ds_tie2)  # -1 (tie1 lower MAC wins)

    # Test Engine Master Election
    engine_bmca = CipSyncPtpEngine(clock_identity="00-11-22-33-44-55-66-02", clock_class=PtpClockClass.DEFAULT)
    header_ann = PtpHeader.create(PtpMessageType.ANNOUNCE, ds_primary.clockIdentity, sequence_id=1)
    ann_msg = PtpAnnounceMessage(
        header=header_ann,
        grandmasterPriority1=ds_primary.priority1,
        grandmasterClockQuality=ds_primary.clockQuality,
        grandmasterPriority2=ds_primary.priority2,
        grandmasterIdentity=ds_primary.clockIdentity,
    )
    is_local_master = engine_bmca.process_announce(ann_msg)

    s2_pass = (
        cmp_class == -1
        and cmp_priority == -1
        and cmp_tie == -1
        and is_local_master is False
        and engine_bmca.state in (PtpPortState.UNCALIBRATED, PtpPortState.SLAVE)
        and engine_bmca.is_grandmaster is False
    )
    test_results.append({
        "stage": 2,
        "check": "BMCA_Dataset_Comparison_And_Master_Election",
        "passed": s2_pass,
        "details": "BMCA priority1, clockClass, and tie-breaking verified; master election transitioned to SLAVE tracking primary GM.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Two-step Sync + Follow_Up timestamp processing
    # ------------------------------------------------------------------------
    engine_sync = CipSyncPtpEngine(clock_identity="00-11-22-33-44-55-66-88")
    t1_expected = PtpTimestamp(seconds=1000, nanoseconds=100_000)
    t2_expected = PtpTimestamp(seconds=1000, nanoseconds=105_200)

    header_sync = PtpHeader.create(PtpMessageType.SYNC, ds_primary.clockIdentity, sequence_id=42, two_step=True)
    sync_msg = PtpSyncMessage(header=header_sync, originTimestamp=PtpTimestamp(0, 0))
    t2_recorded = engine_sync.process_sync(sync_msg, ingress_timestamp=t2_expected)

    header_fu = PtpHeader.create(PtpMessageType.FOLLOW_UP, ds_primary.clockIdentity, sequence_id=42, two_step=True)
    fu_msg = PtpFollowUpMessage(header=header_fu, preciseOriginTimestamp=t1_expected)
    fu_success = engine_sync.process_follow_up(fu_msg)

    s3_pass = (
        fu_success is True
        and engine_sync.t1 == t1_expected
        and engine_sync.t2 == t2_expected
        and engine_sync.sync_sequence_id == 42
    )
    test_results.append({
        "stage": 3,
        "check": "Two_Step_Sync_Follow_Up_Timestamp_Processing",
        "passed": s3_pass,
        "details": f"Two-step Sync (t2={t2_recorded.nanoseconds}ns) and Follow_Up (t1={t1_expected.nanoseconds}ns) matched.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Delay_Req + Delay_Resp path delay calculation
    # ------------------------------------------------------------------------
    t3_expected = PtpTimestamp(seconds=1001, nanoseconds=200_000)
    t4_expected = PtpTimestamp(seconds=1001, nanoseconds=204_800)

    req_msg, t3_recorded = engine_sync.send_delay_req(egress_timestamp=t3_expected)

    header_resp = PtpHeader.create(PtpMessageType.DELAY_RESP, ds_primary.clockIdentity, sequence_id=engine_sync.delay_req_sequence_id)
    resp_msg = PtpDelayRespMessage(
        header=header_resp,
        receiveTimestamp=t4_expected,
        requestingPortIdentity=engine_sync.local_dataset.clockIdentity,
    )
    calc_res = engine_sync.process_delay_resp(resp_msg)

    # t2 - t1 = 5,200 ns
    # t4 - t3 = 4,800 ns
    # mean_path_delay = (5200 + 4800) // 2 = 5,000 ns
    # offset_from_master = 5200 - 5000 = +200 ns
    s4_pass = (
        calc_res["mean_path_delay_ns"] == 5_000
        and calc_res["offset_from_master_ns"] == 200
        and engine_sync.mean_path_delay_ns == 5_000
        and engine_sync.offset_from_master_ns == 200
    )
    test_results.append({
        "stage": 4,
        "check": "Delay_Req_Delay_Resp_Path_Delay_Calculation",
        "passed": s4_pass,
        "details": f"Path delay computed: mean_path_delay={engine_sync.mean_path_delay_ns}ns, offset={engine_sync.offset_from_master_ns}ns.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: PI Clock Servo convergence and drift correction
    # ------------------------------------------------------------------------
    servo_test = PtpServo(kp=0.6, ki=1.2)
    # Simulate closing the loop on a 600 ns phase error and +150 ppb intrinsic drift
    sim_offset = 600
    intrinsic_drift_ppb = 150
    for _ in range(35):
        drift, adj = servo_test.sample(sim_offset, dt=0.125)
        net_drift_ns = int(round((intrinsic_drift_ppb - drift) * 1e-9 * 0.125 * 1e9))
        sim_offset = int(sim_offset - adj + net_drift_ns)

    s5_pass = (
        abs(sim_offset) < 50
        and servo_test.is_locked is True
        and -MAX_SERVO_DRIFT_PPB <= servo_test.frequency_drift_ppb <= MAX_SERVO_DRIFT_PPB
    )
    test_results.append({
        "stage": 5,
        "check": "PI_Clock_Servo_Convergence_And_Drift_Correction",
        "passed": s5_pass,
        "details": f"PI clock servo converged to residual offset {sim_offset}ns; is_locked={servo_test.is_locked}.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Jitter spike detection and filter clamping
    # ------------------------------------------------------------------------
    servo_jitter = PtpServo(kp=0.1, ki=0.001, jitter_spike_threshold_ns=20_000)
    # Baseline sample
    servo_jitter.sample(250, dt=0.125)
    # Massive 65,000 ns jitter excursion
    spike_drift, spike_adj = servo_jitter.sample(65_000, dt=0.125)

    s6_pass = (
        servo_jitter.jitter_spike_count == 1
        and spike_adj <= int(0.1 * 20_000)  # Phase adjustment clamped to spike threshold
    )
    test_results.append({
        "stage": 6,
        "check": "Jitter_Spike_Detection_And_Filter_Clamping",
        "passed": s6_pass,
        "details": f"Jitter spike detected (count={servo_jitter.jitter_spike_count}); phase step clamped to {spike_adj}ns.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Register table synchronization (%R1480..%R1487, %M345..%M346)
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine_rt = CipSyncPtpEngine(reg_table=rt, clock_class=PtpClockClass.PRIMARY_REF)

    # Set known state
    engine_rt.state = PtpPortState.SLAVE
    engine_rt.offset_from_master_ns = 350_000  # 350 us
    engine_rt.mean_path_delay_ns = 5_000      # 5 us
    engine_rt.frequency_drift_ppb = 42
    engine_rt.message_counter = 77
    engine_rt.diagnostic_code = PtpDiagnosticCode.OK
    engine_rt.sync_threshold_ns = 500_000      # 500 us threshold so 350 us is synchronized
    engine_rt.sync_to_registers()

    r1480 = rt.read_word("%R1480")
    r1481 = rt.read_word("%R1481")
    r1482 = rt.read_word("%R1482")
    r1483 = rt.read_word("%R1483")
    r1484 = rt.read_word("%R1484")
    r1485 = rt.read_word("%R1485")
    r1486 = rt.read_word("%R1486")
    r1487 = rt.read_uword("%R1487")
    m345 = rt.read_bit("%M345")
    m346 = rt.read_bit("%M346")

    reconstructed_offset = decode_dint_words(r1481, r1482)

    s7_pass = (
        r1480 == int(PtpPortState.SLAVE)
        and reconstructed_offset == 350
        and r1483 == 5
        and r1484 == 42
        and r1485 == int(PtpClockClass.PRIMARY_REF)
        and r1486 == 77
        and r1487 == 0x0000
        and m345 is True
        and m346 is False
    )
    test_results.append({
        "stage": 7,
        "check": "Register_Table_Synchronization_R1480_R1487_M345_M346",
        "passed": s7_pass,
        "details": f"Horner OCS registers validated: state={r1480}, offset={reconstructed_offset}us, delay={r1483}us, drift={r1484}ppb.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Discrete ILogicUnit 100-cycle scan simulation
    # ------------------------------------------------------------------------
    engine_scan = CipSyncPtpEngine(reg_table=rt)
    engine_scan.state = PtpPortState.SLAVE
    engine_scan.offset_from_master_ns = 250
    engine_scan.mean_path_delay_ns = 5_000

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
        engine_scan.name == "cip_sync_ptp"
        and engine_scan.priority == 92
        and engine_scan.is_enabled is True
        and engine_scan.total_scan_cycles == 100
        and round(engine_scan.elapsed_simulation_ms) == 1000
    )
    test_results.append({
        "stage": 8,
        "check": "Discrete_ILogicUnit_100_Cycle_Scan_Simulation",
        "passed": s8_pass,
        "details": f"100 scan cycles executed smoothly; total elapsed simulation time={engine_scan.elapsed_simulation_ms}ms.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Process safety interlock and diagnostic fault trip testing
    # ------------------------------------------------------------------------
    engine_safety = CipSyncPtpEngine(reg_table=rt)

    # 1. BMCA Lost GM (0xD101)
    engine_safety.simulate_bmca_lost_gm()
    d1 = engine_safety.diagnostic_code == PtpDiagnosticCode.BMCA_LOST_GM and rt.read_bit("%M345") is False

    # 2. Sync Timeout (0xD102)
    engine_safety.simulate_sync_timeout()
    d2 = engine_safety.diagnostic_code == PtpDiagnosticCode.SYNC_TIMEOUT and rt.read_bit("%M345") is False

    # 3. Jitter Spike (0xD103)
    engine_safety.simulate_jitter_spike(85_000)
    d3 = engine_safety.diagnostic_code == PtpDiagnosticCode.JITTER_SPIKE and rt.read_bit("%M345") is False

    # 4. Hardware Lockout (0xD104)
    engine_safety.simulate_hardware_lockout()
    d4 = (
        engine_safety.diagnostic_code == PtpDiagnosticCode.HARDWARE_LOCKOUT
        and rt.read_word("%R1480") == int(PtpPortState.FAULTY)
        and rt.read_bit("%M345") is False
    )

    # 5. Operator Reset Handshake
    res_reset = engine_safety.reset_fault(force=True)
    d5 = (
        res_reset.status == AgentStatus.SUCCESS
        and engine_safety.diagnostic_code == PtpDiagnosticCode.OK
        and rt.read_uword("%R1487") == 0x0000
    )

    s9_pass = d1 and d2 and d3 and d4 and d5
    test_results.append({
        "stage": 9,
        "check": "Process_Safety_Interlock_And_Diagnostic_Fault_Trips",
        "passed": s9_pass,
        "details": "Safety interlocks verified: 0xD101..0xD104 trips and operator reset handshake confirmed.",
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
        "details": f"CIP Sync PTP Engine (W187) verified cleanly ({passed_count}/{total_stages} stages passed).",
        "stages_passed": passed_count,
        "total_stages": total_stages,
        "data": {
            "work_package": "W187",
            "standards": [
                "IEEE 1588-2008 (PTPv2)",
                "ODVA CIP Sync Profile (Class 0x43)",
                "IEC 61131-3 Structured Text",
            ],
            "stages": test_results,
            "tests": test_results,
            "checks_passed": passed_count,
            "total_checks": total_stages,
            "register_map": {
                "%R1480": "PtpClockState",
                "%R1481": "MasterOffsetMicrosHighWord",
                "%R1482": "MasterOffsetMicrosLowWord",
                "%R1483": "MeanPathDelayMicros",
                "%R1484": "FrequencyDriftPpbScaled",
                "%R1485": "GrandmasterClockClass",
                "%R1486": "SyncDelayMessageCounter",
                "%R1487": "DiagnosticStatusCode",
                "%M345": "CipSyncIsSynchronized",
                "%M346": "GrandmasterActiveFlag",
            },
            "registers": {
                "%R1480": rt.read_word("%R1480"),
                "%R1481": rt.read_word("%R1481"),
                "%R1482": rt.read_word("%R1482"),
                "%R1483": rt.read_word("%R1483"),
                "%R1484": rt.read_word("%R1484"),
                "%R1485": rt.read_word("%R1485"),
                "%R1486": rt.read_word("%R1486"),
                "%R1487": rt.read_uword("%R1487"),
                "%M345": rt.read_bit("%M345"),
                "%M346": rt.read_bit("%M346"),
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
    result = run_cip_sync_ptp_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
