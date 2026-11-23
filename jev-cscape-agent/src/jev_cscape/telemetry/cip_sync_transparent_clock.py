"""Industrial ODVA CIP Sync Profile & IEEE 1588 Boundary Clock & Transparent Clock (E2E & P2P) Protocol Engine.

Work Package: W211 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- IEEE 1588-2019: IEEE Standard for a Precision Clock Synchronization Protocol for Networked Measurement and Control Systems.
- IEEE 802.1AS-2020: Timing and Synchronization for Time-Sensitive Applications in Bridged Local Area Networks.
- ODVA CIP Networks Library Volume 1: Common Industrial Protocol (CIP) - Time Sync Object (Class 0x43).
- IEC 61131-3 Programmable Controllers - Part 3: Programming Languages (Structured Text).
- Horner OCS Memory Space: %R1720..%R1727, %M401..%M402.

Architecture:
1. Strict Pure IEC 61131-3 Structured Text POU:
   - 'CipSyncTransparentClockSync' bound to Horner OCS memory space (%R1720..%R1727, %M401..%M402).
   - Anti-ladder security guard: Intercepts ladder constructs with ERR_LADDER_FORBIDDEN
     using SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).

2. IEEE 1588 & ODVA CIP Sync Clock Architecture:
   - Clock modes:
     * 0 = Ordinary Clock (OC): Single port clock node terminating PTP.
     * 1 = Boundary Clock (BC): Multi-port clock terminating PTP on upstream slave port and regenerating on downstream master ports.
     * 2 = End-to-End Transparent Clock (E2E_TC): Multi-port bridge forwarding event frames and accumulating bridge residence time.
     * 3 = Peer-to-Peer Transparent Clock (P2P_TC): Multi-port bridge accumulating bridge residence time AND upstream link peer propagation delay.
   - Multi-port routing with 4 physical ports:
     * Port 1: Upstream Master Link (receives Sync/Follow_Up/Announce, transmits Delay_Req in E2E).
     * Ports 2-4: Downstream Slaves/Bridges (forwards Sync/Follow_Up, receives Delay_Req in E2E).
   - Port state machine per port:
     * UNINITIALIZED (0), INITIALIZING (1), LISTENING (2), MASTER (3), SLAVE (4), PASSIVE (5), DISABLED (6).
   - Residence time calculation:
     * residence_time_ns = egress_timestamp_ns - ingress_timestamp_ns.
   - Sub-nanosecond correction field accumulation:
     * correctionField_out = correctionField_in + (residence_time_ns * 65536) + (sub_ns_rate_ratio_correction)
       (+ peer_delay_ns * 65536 in P2P mode).
   - Syntonization rate ratio estimation across upstream master intervals:
     * Target frequency offset tracking in ppm: offset_ppm = (rate_ratio - 1.0) * 1e6.
     * Scaled representation in Horner register %R1725: offset_ppm * 10 (e.g. +1.5 ppm -> 15).

3. Process Safety Interlocks & Diagnostics:
   - 0x0000: OK (Normal healthy synchronization and transparent bridge forwarding)
   - 0xE301: RESIDENCE_TIME_EXCEEDED (Bridge residence time > 10.0 us / 10,000 ns) -> clears %M401
   - 0xE302: PORT_ASYMMETRY_FAULT (Physical port Rx/Tx delay asymmetry exceeds tolerance) -> sets %M402
   - 0xE303: SYNTONIZATION_RATE_DRIFT (Syntonization frequency drift rate exceeds ppm limit) -> sets %M402
   - 0xE304: ROGUE_CLOCK_INTERCEPTION (Unauthorized clock domain, rogue master, or downstream spoofing) -> blocks packet

4. Horner OCS Memory Space Integration:
   - %R1720: ClockTypeMode (0=OC, 1=BC, 2=E2E_TC, 3=P2P_TC)
   - %R1721: ActivePortCount (INT16, e.g. 4)
   - %R1722: MeanResidenceTimeNsScaled (INT16 scaled, link mean bridge residence time in ns, e.g. 350 ns)
   - %R1723: TotalCorrectionFieldNsLow (INT16, low 16 bits of cumulative correction field in ns)
   - %R1724: TotalCorrectionFieldNsHigh (INT16, high 16 bits of cumulative correction field in ns)
   - %R1725: SyntonizationRateRatioPpmScaled (INT16 scaled, e.g. 15 = +1.5 ppm frequency offset)
   - %R1726: ClockDomainNumber (INT16, 0..127)
   - %R1727: DiagnosticStatusCode (0x0000=OK, 0xE301..0xE304)
   - %M401: TransparentClockActive (BOOL, True when bridge forwarding with residence time < 10.0 us)
   - %M402: ClockAsymmetryFaultTrip (BOOL, True on asymmetry or excessive drift)

5. Deterministic 9-Stage Verification Suite:
   - run_cip_sync_transparent_clock_verification(output_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]
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
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Timing Definitions (IEEE 1588-2019 & ODVA CIP Sync)
# ============================================================================

PTP_VERSION: int = 2
CIP_SYNC_CLASS_ID: int = 0x43  # ODVA CIP Time Sync Object Class ID
DEFAULT_DOMAIN_NUMBER: int = 0
TOTAL_PHYSICAL_PORTS: int = 4

DEFAULT_SYNC_INTERVAL_S: float = 0.125            # 8 Hz nominal sync rate
DEFAULT_ANNOUNCE_INTERVAL_S: float = 1.0          # 1 Hz nominal announce rate
DEFAULT_PDELAY_INTERVAL_S: float = 1.0            # 1 Hz nominal Pdelay rate

# Residence Time & Safety Thresholds
NOMINAL_RESIDENCE_TIME_NS: float = 350.0          # 350 ns nominal bridge forwarding delay
MAX_ALLOWABLE_RESIDENCE_TIME_NS: float = 10_000.0 # 10.0 us (10,000 ns) maximum allowed residence time
MAX_PORT_ASYMMETRY_TOLERANCE_NS: float = 100.0    # 100 ns maximum acceptable port delay asymmetry
MAX_SYNTONIZATION_DRIFT_PPM: float = 50.0         # 50.0 ppm maximum syntonization rate drift limit
CORRECTION_FIELD_SCALE_FACTOR: int = 65536         # 2^16 fixed point sub-nanosecond scale factor

# Scaled Register Factors
PPM_REGISTER_SCALE_FACTOR: float = 10.0           # 1.5 ppm -> 15 in %R1725


# ============================================================================
# 2. Protocol Enums & Diagnostic Codes
# ============================================================================

class CipSyncClockMode(IntEnum):
    """IEEE 1588 / CIP Sync Clock Modes & Horner %R1720 Values."""
    ORDINARY_CLOCK   = 0  # 0=OC: Single port clock terminating PTP
    BOUNDARY_CLOCK   = 1  # 1=BC: Multi-port clock terminating and regenerating PTP
    END_TO_END_TC    = 2  # 2=E2E_TC: End-to-End Transparent Clock (measures bridge residence time)
    PEER_TO_PEER_TC  = 3  # 3=P2P_TC: Peer-to-Peer Transparent Clock (bridge residence time + peer link delay)

    # Convenience Aliases
    OC = 0
    BC = 1
    E2E_TC = 2
    P2P_TC = 3
    OrdinaryClock = 0
    BoundaryClock = 1
    EndToEndTC = 2
    PeerToPeerTC = 3


ClockMode = CipSyncClockMode
ClockType = CipSyncClockMode
ClockTypeMode = CipSyncClockMode
PtpClockType = CipSyncClockMode
TransparentClockType = CipSyncClockMode


class PtpPortState(IntEnum):
    """IEEE 1588 Port State Machine."""
    UNINITIALIZED = 0  # Port hardware uninitialized or down
    INITIALIZING  = 1  # Port initializing, configuring link and PHY
    LISTENING     = 2  # Listening for upstream Master announces / sync frames
    MASTER        = 3  # Port acting as Master transmitting sync frames downstream
    SLAVE         = 4  # Port acting as Slave tracking upstream master
    PASSIVE       = 5  # Redundant master port in passive backup state
    DISABLED      = 6  # Port administratively disabled or offline

    # Aliases
    Uninitialized = 0
    Initializing = 1
    Listening = 2
    Master = 3
    Slave = 4
    Passive = 5
    Disabled = 6


PortState = PtpPortState
TcPortState = PtpPortState
CipSyncPortState = PtpPortState


class TransparentClockDiagnosticCode(IntEnum):
    """Horner OCS %R1727 Diagnostic Event Codes."""
    OK                       = 0x0000  # Normal healthy operation & forwarding
    RESIDENCE_TIME_EXCEEDED  = 0xE301  # Residence time exceeds maximum limit (> 10.0 us)
    PORT_ASYMMETRY_FAULT     = 0xE302  # Egress/Ingress asymmetry exceeds tolerance threshold (> 100 ns)
    SYNTONIZATION_RATE_DRIFT = 0xE303  # Syntonization rate drift exceeds ppm limit (> 50.0 ppm)
    ROGUE_CLOCK_INTERCEPTION = 0xE304  # Rogue clock / untrusted domain / unauthorized master message detected

    # Convenience aliases
    ERR_RESIDENCE_TIME_EXCEEDED  = 0xE301
    ERR_PORT_ASYMMETRY_FAULT     = 0xE302
    ERR_SYNTONIZATION_RATE_DRIFT = 0xE303
    ERR_ROGUE_CLOCK_INTERCEPTION = 0xE304
    CIP_SYNC_ERR_RESIDENCE_TIME  = 0xE301
    CIP_SYNC_ERR_ASYMMETRY       = 0xE302
    CIP_SYNC_ERR_DRIFT           = 0xE303
    CIP_SYNC_ERR_ROGUE_CLOCK     = 0xE304


TcDiagnosticCode = TransparentClockDiagnosticCode
DiagnosticCode = TransparentClockDiagnosticCode
DiagnosticStatusCode = TransparentClockDiagnosticCode
CipSyncDiagnosticCode = TransparentClockDiagnosticCode
PtpDiagnosticCode = TransparentClockDiagnosticCode


class PtpMessageType(IntEnum):
    """IEEE 1588 / CIP Sync Message Types."""
    SYNC                  = 0x0  # Event message: Master egress timestamp
    DELAY_REQ             = 0x1  # Event message: Slave delay request egress timestamp
    PDELAY_REQ            = 0x2  # Event message: Peer delay request
    PDELAY_RESP           = 0x3  # Event message: Peer delay response
    FOLLOW_UP             = 0x8  # General message: Precise origin timestamp t1
    DELAY_RESP            = 0x9  # General message: Master delay request ingress timestamp t4
    PDELAY_RESP_FOLLOW_UP = 0xA  # General message: Peer delay response follow-up
    ANNOUNCE              = 0xB  # General message: Grandmaster dataset advertising
    SIGNALING             = 0xC  # General message: Unicast / link signaling
    MANAGEMENT            = 0xD  # General message: Management query/configuration


class PtpFlagField(IntFlag):
    """IEEE 1588 Header Flag Field."""
    TWO_STEP                 = 1 << 1   # Bit 1 (0x0002): Two-Step clock flag
    UNICAST                  = 1 << 2   # Bit 2 (0x0004): Unicast transmission
    PTP_TIMESCALE            = 1 << 3   # Bit 3 (0x0008): PTP timescale
    TIME_TRACEABLE           = 1 << 4   # Bit 4 (0x0010): Time traceable to PRC
    FREQUENCY_TRACEABLE      = 1 << 5   # Bit 5 (0x0020): Frequency traceable
    SYNCHRONIZATION_UNCERTAIN = 1 << 6  # Bit 6 (0x0040): Sync uncertain


# ============================================================================
# 3. PTP Data Structures: Timestamp, ClockIdentity, PortIdentity
# ============================================================================

class PtpTimeInterval(int):
    """Time interval or duration in nanoseconds with component accessors."""

    @property
    def seconds(self) -> int:
        return int(self) // 1_000_000_000

    @property
    def nanoseconds(self) -> int:
        return int(self) % 1_000_000_000

    def to_ns(self) -> int:
        return int(self)

    def to_float_seconds(self) -> float:
        return int(self) / 1_000_000_000.0


@dataclass(order=True)
class PtpTimestamp:
    """IEEE 1588 PTP Timestamp (seconds: uint48/int, nanoseconds: uint32)."""
    seconds: int = 0
    nanoseconds: int = 0

    def __post_init__(self) -> None:
        if self.nanoseconds >= 1_000_000_000 or self.nanoseconds < 0:
            sec_add, rem_ns = divmod(self.nanoseconds, 1_000_000_000)
            self.seconds += sec_add
            self.nanoseconds = rem_ns

    def to_ns(self) -> int:
        return self.seconds * 1_000_000_000 + self.nanoseconds

    @classmethod
    def from_ns(cls, total_ns: int) -> PtpTimestamp:
        sec, nsec = divmod(int(total_ns), 1_000_000_000)
        return cls(seconds=sec, nanoseconds=nsec)

    def to_float_seconds(self) -> float:
        return self.seconds + (self.nanoseconds / 1_000_000_000.0)

    @classmethod
    def from_float_seconds(cls, val_s: float) -> PtpTimestamp:
        sec = int(math.floor(val_s))
        nsec = int(round((val_s - sec) * 1_000_000_000.0))
        if nsec >= 1_000_000_000:
            sec += 1
            nsec -= 1_000_000_000
        return cls(seconds=sec, nanoseconds=nsec)

    def __add__(self, other: Union[PtpTimestamp, int, float]) -> PtpTimestamp:
        if isinstance(other, PtpTimestamp):
            return PtpTimestamp.from_ns(self.to_ns() + other.to_ns())
        elif isinstance(other, (int, float)):
            return PtpTimestamp.from_ns(self.to_ns() + int(round(other)))
        return NotImplemented

    def __radd__(self, other: Union[int, float]) -> PtpTimestamp:
        return self.__add__(other)

    def __sub__(self, other: Union[PtpTimestamp, int, float]) -> Union[PtpTimeInterval, PtpTimestamp]:
        if isinstance(other, PtpTimestamp):
            return PtpTimeInterval(self.to_ns() - other.to_ns())
        elif isinstance(other, (int, float)):
            return PtpTimestamp.from_ns(self.to_ns() - int(round(other)))
        return NotImplemented

    def __rsub__(self, other: Union[int, float]) -> Union[PtpTimeInterval, PtpTimestamp]:
        if isinstance(other, (int, float)):
            return PtpTimeInterval(int(round(other)) - self.to_ns())
        return NotImplemented

    def pack(self) -> bytes:
        sec_high = (self.seconds >> 32) & 0xFFFF
        sec_low = self.seconds & 0xFFFFFFFF
        return struct.pack(">HII", sec_high, sec_low, self.nanoseconds)

    @classmethod
    def unpack(cls, data: bytes) -> PtpTimestamp:
        if len(data) < 10:
            raise ValueError(f"PtpTimestamp requires 10 bytes, got {len(data)}")
        sec_high, sec_low, nsec = struct.unpack(">HII", data[:10])
        total_sec = (sec_high << 32) | sec_low
        return cls(seconds=total_sec, nanoseconds=nsec)


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
        clean = re.sub(r"[-:]", "", mac.strip())
        if len(clean) != 12:
            raise ValueError(f"MAC address must have 12 hex digits, got '{mac}'")
        b = bytes.fromhex(clean)
        eui64 = bytes([b[0], b[1], b[2], 0xFF, 0xFE, b[3], b[4], b[5]])
        return cls(eui64)

    @classmethod
    def default_bridge(cls) -> PtpClockIdentity:
        return cls("00-1D-9C-FF-FE-72-A1-04")

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

    def __hash__(self) -> int:
        return hash(self._bytes)

    def __str__(self) -> str:
        return self.to_hex()

    def __repr__(self) -> str:
        return f"PtpClockIdentity('{self.to_hex()}')"


@dataclass
class PtpPortIdentity:
    """IEEE 1588 Port Identity (ClockIdentity 8 bytes + PortNumber 2 bytes)."""
    clockIdentity: PtpClockIdentity = field(default_factory=PtpClockIdentity.default_bridge)
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


@dataclass
class PtpClockQuality:
    """IEEE 1588 Clock Quality descriptor."""
    clockClass: int = 248
    clockAccuracy: int = 0xFE
    offsetScaledLogVariance: int = 0xFFFF


# ============================================================================
# 4. PTP Frame Headers & Message Types
# ============================================================================

@dataclass
class PtpHeader:
    """IEEE 1588 Standard 34-Octet Message Header."""
    messageType: PtpMessageType = PtpMessageType.SYNC
    versionPTP: int = PTP_VERSION
    messageLength: int = 34
    domainNumber: int = DEFAULT_DOMAIN_NUMBER
    flagField: int = int(PtpFlagField.TWO_STEP | PtpFlagField.PTP_TIMESCALE)
    correctionField: int = 0  # 64-bit signed scaled nanoseconds (ns * 65536)
    sourcePortIdentity: PtpPortIdentity = field(default_factory=PtpPortIdentity)
    sequenceId: int = 0
    controlField: int = 0
    logMessageInterval: int = 0

    @classmethod
    def create(
        cls,
        msg_type: PtpMessageType,
        source_identity: PtpClockIdentity,
        port_number: int = 1,
        sequence_id: int = 0,
        correction_field: int = 0,
        domain_number: int = DEFAULT_DOMAIN_NUMBER,
        two_step: bool = True,
        msg_len: int = 44,
        log_interval: int = 0,
    ) -> PtpHeader:
        flags = int(PtpFlagField.PTP_TIMESCALE)
        if two_step:
            flags |= int(PtpFlagField.TWO_STEP)
        return cls(
            messageType=msg_type,
            versionPTP=PTP_VERSION,
            messageLength=msg_len,
            domainNumber=domain_number,
            flagField=flags,
            correctionField=correction_field,
            sourcePortIdentity=PtpPortIdentity(clockIdentity=source_identity, portNumber=port_number),
            sequenceId=sequence_id,
            controlField=0,
            logMessageInterval=log_interval,
        )

    def pack(self) -> bytes:
        first_byte = int(self.messageType.value) & 0x0F
        sec_byte = int(self.versionPTP) & 0x0F
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
                self.correctionField & 0xFFFFFFFFFFFFFFFF,
            )
            + b"\x00\x00\x00\x00"  # messageTypeSpecific
            + port_bytes
            + struct.pack(
                ">HBB",
                self.sequenceId,
                self.controlField,
                self.logMessageInterval & 0xFF,
            )
        )

    @classmethod
    def unpack(cls, data: bytes) -> PtpHeader:
        if len(data) < 34:
            raise ValueError(f"PtpHeader requires 34 bytes, got {len(data)}")
        first_byte, sec_byte, msg_len, domain, _, flags, corr = struct.unpack(">BBHBBHQ", data[:16])
        if corr >= (1 << 63):
            corr -= (1 << 64)
        port_id = PtpPortIdentity.unpack(data[20:30])
        seq_id, ctrl, log_int = struct.unpack(">HBB", data[30:34])
        return cls(
            messageType=PtpMessageType(first_byte & 0x0F),
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


@dataclass
class PtpSyncMessage:
    """IEEE 1588 Sync Message."""
    header: PtpHeader
    originTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)

    def pack(self) -> bytes:
        return self.header.pack() + self.originTimestamp.pack()

    @classmethod
    def unpack(cls, data: bytes) -> PtpSyncMessage:
        return cls(header=PtpHeader.unpack(data[:34]), originTimestamp=PtpTimestamp.unpack(data[34:44]))


@dataclass
class PtpFollowUpMessage:
    """IEEE 1588 Follow_Up Message."""
    header: PtpHeader
    preciseOriginTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)

    def pack(self) -> bytes:
        return self.header.pack() + self.preciseOriginTimestamp.pack()

    @classmethod
    def unpack(cls, data: bytes) -> PtpFollowUpMessage:
        return cls(header=PtpHeader.unpack(data[:34]), preciseOriginTimestamp=PtpTimestamp.unpack(data[34:44]))


@dataclass
class PtpDelayReqMessage:
    """IEEE 1588 Delay_Req Message (E2E mode)."""
    header: PtpHeader
    originTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)

    def pack(self) -> bytes:
        return self.header.pack() + self.originTimestamp.pack()

    @classmethod
    def unpack(cls, data: bytes) -> PtpDelayReqMessage:
        return cls(header=PtpHeader.unpack(data[:34]), originTimestamp=PtpTimestamp.unpack(data[34:44]))


@dataclass
class PtpDelayRespMessage:
    """IEEE 1588 Delay_Resp Message (E2E mode)."""
    header: PtpHeader
    receiveTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)
    requestingPortIdentity: PtpPortIdentity = field(default_factory=PtpPortIdentity)

    def pack(self) -> bytes:
        return self.header.pack() + self.receiveTimestamp.pack() + self.requestingPortIdentity.pack()

    @classmethod
    def unpack(cls, data: bytes) -> PtpDelayRespMessage:
        return cls(
            header=PtpHeader.unpack(data[:34]),
            receiveTimestamp=PtpTimestamp.unpack(data[34:44]),
            requestingPortIdentity=PtpPortIdentity.unpack(data[44:54]),
        )


@dataclass
class PtpPdelayReqMessage:
    """IEEE 1588 Peer Delay Request (P2P mode)."""
    header: PtpHeader
    originTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)

    def pack(self) -> bytes:
        return self.header.pack() + self.originTimestamp.pack() + b"\x00" * 10

    @classmethod
    def unpack(cls, data: bytes) -> PtpPdelayReqMessage:
        return cls(header=PtpHeader.unpack(data[:34]), originTimestamp=PtpTimestamp.unpack(data[34:44]))


@dataclass
class PtpPdelayRespMessage:
    """IEEE 1588 Peer Delay Response (P2P mode)."""
    header: PtpHeader
    requestReceiptTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)
    requestingPortIdentity: PtpPortIdentity = field(default_factory=PtpPortIdentity)

    def pack(self) -> bytes:
        return self.header.pack() + self.requestReceiptTimestamp.pack() + self.requestingPortIdentity.pack()

    @classmethod
    def unpack(cls, data: bytes) -> PtpPdelayRespMessage:
        return cls(
            header=PtpHeader.unpack(data[:34]),
            requestReceiptTimestamp=PtpTimestamp.unpack(data[34:44]),
            requestingPortIdentity=PtpPortIdentity.unpack(data[44:54]),
        )


@dataclass
class PtpPdelayRespFollowUpMessage:
    """IEEE 1588 Peer Delay Response Follow-Up (P2P mode)."""
    header: PtpHeader
    responseOriginTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)
    requestingPortIdentity: PtpPortIdentity = field(default_factory=PtpPortIdentity)

    def pack(self) -> bytes:
        return self.header.pack() + self.responseOriginTimestamp.pack() + self.requestingPortIdentity.pack()

    @classmethod
    def unpack(cls, data: bytes) -> PtpPdelayRespFollowUpMessage:
        return cls(
            header=PtpHeader.unpack(data[:34]),
            responseOriginTimestamp=PtpTimestamp.unpack(data[34:44]),
            requestingPortIdentity=PtpPortIdentity.unpack(data[44:54]),
        )


@dataclass
class PtpAnnounceMessage:
    """IEEE 1588 Announce Message carrying Master dataset."""
    header: PtpHeader
    originTimestamp: PtpTimestamp = field(default_factory=PtpTimestamp)
    currentUtcOffset: int = 37
    grandmasterPriority1: int = 128
    grandmasterClockQuality: PtpClockQuality = field(default_factory=PtpClockQuality)
    grandmasterPriority2: int = 128
    grandmasterIdentity: PtpClockIdentity = field(default_factory=PtpClockIdentity)
    stepsRemoved: int = 0
    timeSource: int = 0xA0

    def pack(self) -> bytes:
        cq = self.grandmasterClockQuality
        cq_bytes = struct.pack(">BBH", cq.clockClass, cq.clockAccuracy, cq.offsetScaledLogVariance)
        return (
            self.header.pack()
            + self.originTimestamp.pack()
            + struct.pack(
                ">HBB",
                self.currentUtcOffset,
                0,  # reserved
                self.grandmasterPriority1,
            )
            + cq_bytes
            + struct.pack(">B", self.grandmasterPriority2)
            + self.grandmasterIdentity.to_bytes()
            + struct.pack(">HB", self.stepsRemoved, self.timeSource)
        )

    @classmethod
    def unpack(cls, data: bytes) -> PtpAnnounceMessage:
        hdr = PtpHeader.unpack(data[:34])
        ts = PtpTimestamp.unpack(data[34:44])
        utc_off, _, p1 = struct.unpack(">HBB", data[44:48])
        c_class, c_acc, c_var = struct.unpack(">BBH", data[48:52])
        p2 = data[52]
        gm_id = PtpClockIdentity(data[53:61])
        steps, time_src = struct.unpack(">HB", data[61:64])[:2]
        return cls(
            header=hdr,
            originTimestamp=ts,
            currentUtcOffset=utc_off,
            grandmasterPriority1=p1,
            grandmasterClockQuality=PtpClockQuality(clockClass=c_class, clockAccuracy=c_acc, offsetScaledLogVariance=c_var),
            grandmasterPriority2=p2,
            grandmasterIdentity=gm_id,
            stepsRemoved=steps,
            timeSource=time_src,
        )


# Aliases for packet naming compatibility
PtpAnnouncePacket = PtpAnnounceMessage
PtpDelayReqPacket = PtpDelayReqMessage
PtpDelayRespPacket = PtpDelayRespMessage
PtpFollowUpPacket = PtpFollowUpMessage
PtpPdelayReqPacket = PtpPdelayReqMessage
PtpPdelayRespFollowUpPacket = PtpPdelayRespFollowUpMessage
PtpPdelayRespPacket = PtpPdelayRespMessage
PtpSyncPacket = PtpSyncMessage


# ============================================================================
# 5. Multi-Port Architecture (4 Ports)
# ============================================================================

@dataclass
class PtpPort:
    """Physical PTP Port descriptor for multi-port Boundary & Transparent Clock bridge."""
    port_id: int  # 1..4
    state: PtpPortState = PtpPortState.INITIALIZING
    is_enabled: bool = True
    peer_mean_path_delay_ns: float = 0.0     # P2P link propagation delay
    asymmetry_correction_ns: float = 0.0     # Delay asymmetry (Rx vs Tx)
    rx_packet_count: int = 0
    tx_packet_count: int = 0
    last_ingress_timestamp: Optional[PtpTimestamp] = None
    last_egress_timestamp: Optional[PtpTimestamp] = None
    is_upstream: bool = False                # Port 1 is upstream master link


TransparentClockPort = PtpPort


# ============================================================================
# 6. Mathematical Helper Functions & Syntonization Estimator
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
    return (h << 16) | l


def scale_correction_field(correction_ns: float) -> int:
    """Scale nanoseconds into 2^16 sub-nanosecond fixed point integer units."""
    return int(round(float(correction_ns) * float(CORRECTION_FIELD_SCALE_FACTOR)))


def unscale_correction_field(units: int) -> float:
    """Convert 2^16 sub-nanosecond integer units back to nanoseconds."""
    return float(units) / float(CORRECTION_FIELD_SCALE_FACTOR)


def accumulate_correction_field(
    correction_field_in: int,
    residence_time_ns: float,
    rate_ratio: float = 1.0,
    peer_delay_ns: float = 0.0,
) -> Tuple[int, int, int]:
    """Accumulate residence time, peer delay, and syntonization rate ratio into correction field.

    Formula:
        correctionField_out = correctionField_in + (residence_time_ns * 65536) + (sub_ns_rate_ratio_correction)
                              (+ peer_delay_ns * 65536)

    Args:
        correction_field_in: Incoming 64-bit correction field in 2^-16 ns units.
        residence_time_ns: Bridge residence time in nanoseconds.
        rate_ratio: Syntonization frequency rate ratio (nominal 1.0).
        peer_delay_ns: Peer link propagation delay in nanoseconds (for P2P TC).

    Returns:
        Tuple of (correction_field_out, total_delta_units, sub_ns_rate_ratio_correction_units).
    """
    sub_ns_rate_ratio_correction = int(round(residence_time_ns * (rate_ratio - 1.0) * float(CORRECTION_FIELD_SCALE_FACTOR)))
    res_scaled = int(round(residence_time_ns * float(CORRECTION_FIELD_SCALE_FACTOR)))
    peer_scaled = int(round(peer_delay_ns * float(CORRECTION_FIELD_SCALE_FACTOR)))
    total_delta = res_scaled + peer_scaled + sub_ns_rate_ratio_correction
    correction_field_out = int(correction_field_in) + total_delta
    return correction_field_out, total_delta, sub_ns_rate_ratio_correction


class SyntonizationEstimator:
    """Frequency offset & syntonization rate ratio estimator across master intervals."""

    def __init__(self, max_drift_ppm: float = MAX_SYNTONIZATION_DRIFT_PPM) -> None:
        self.max_drift_ppm = float(max_drift_ppm)
        self.rate_ratio: float = 1.0
        self.frequency_offset_ppm: float = 0.0
        self._prev_master_t1: Optional[PtpTimestamp] = None
        self._prev_local_t2: Optional[PtpTimestamp] = None

    def reset(self) -> None:
        """Reset estimator internal tracking state."""
        self.rate_ratio = 1.0
        self.frequency_offset_ppm = 0.0
        self._prev_master_t1 = None
        self._prev_local_t2 = None

    def update(
        self,
        master_timestamp: PtpTimestamp,
        local_timestamp: PtpTimestamp,
    ) -> Tuple[float, float]:
        """Update rate ratio from consecutive master message timestamps.

        Returns:
            Tuple of (rate_ratio, frequency_offset_ppm).
        """
        if self._prev_master_t1 is not None and self._prev_local_t2 is not None:
            delta_master_ns = (master_timestamp - self._prev_master_t1).to_ns()
            delta_local_ns = (local_timestamp - self._prev_local_t2).to_ns()

            if delta_local_ns > 0:
                self.rate_ratio = float(delta_master_ns) / float(delta_local_ns)
                self.frequency_offset_ppm = (self.rate_ratio - 1.0) * 1_000_000.0

        self._prev_master_t1 = master_timestamp
        self._prev_local_t2 = local_timestamp
        return self.rate_ratio, self.frequency_offset_ppm


# ============================================================================
# 7. Pure IEC 61131-3 Structured Text POU
# ============================================================================

CIP_SYNC_TRANSPARENT_CLOCK_SYNC_POU: str = """PROGRAM CipSyncTransparentClockSync
VAR
    (* Horner OCS Mapped Registers (W211 - ODVA CIP Sync / IEEE 1588 Transparent Clock) *)
    ClockTypeMode                AT %R1720 : INT;    (* 0=OC, 1=BC, 2=E2E_TC, 3=P2P_TC *)
    ActivePortCount              AT %R1721 : INT;    (* Number of active physical ports (e.g. 4) *)
    MeanResidenceTimeNsScaled    AT %R1722 : INT;    (* Bridge residence time in ns (e.g. 350 ns) *)
    TotalCorrectionFieldNsLow    AT %R1723 : INT;    (* Cumulative correction field nanoseconds low word *)
    TotalCorrectionFieldNsHigh   AT %R1724 : INT;    (* Cumulative correction field nanoseconds high word *)
    SyntonizationRateRatioPpmScaled AT %R1725 : INT; (* Frequency syntonization offset scaled ppm (15 = 1.5 ppm) *)
    ClockDomainNumber            AT %R1726 : INT;    (* PTP Domain Number (0..127) *)
    DiagnosticStatusCode         AT %R1727 : UINT;   (* Diagnostic Status Code (0x0000=OK, 0xE301..0xE304) *)

    (* Discrete Status & Fault Coils *)
    TransparentClockActive       AT %M401  : BOOL;   (* TRUE when bridge forwarding with residence time < 10.0 us *)
    ClockAsymmetryFaultTrip      AT %M402  : BOOL;   (* TRUE on port asymmetry fault or excessive drift *)
END_VAR
VAR
    IsTcModeActive               : BOOL;
    IsForwardingHealthy          : BOOL;
END_VAR

(* Process Safety Evaluation and Status Interlocking *)
IF (DiagnosticStatusCode <> 0) THEN
    IF (DiagnosticStatusCode = 16#E302) OR (DiagnosticStatusCode = 16#E303) THEN
        ClockAsymmetryFaultTrip := TRUE;
    ELSE
        ClockAsymmetryFaultTrip := FALSE;
    END_IF;
    TransparentClockActive := FALSE;
    IsForwardingHealthy := FALSE;
ELSIF (MeanResidenceTimeNsScaled > 10000) OR (MeanResidenceTimeNsScaled < 0) THEN
    (* Exceeds 10.0 us residence time threshold *)
    TransparentClockActive := FALSE;
    ClockAsymmetryFaultTrip := FALSE;
    IsForwardingHealthy := FALSE;
ELSE
    ClockAsymmetryFaultTrip := FALSE;
    IsTcModeActive := (ClockTypeMode = 2) OR (ClockTypeMode = 3);
    TransparentClockActive := IsTcModeActive AND (ActivePortCount >= 2);
    IsForwardingHealthy := TransparentClockActive;
END_IF;
END_PROGRAM
"""

CIP_SYNC_TRANSPARENT_CLOCK_POU = CIP_SYNC_TRANSPARENT_CLOCK_SYNC_POU


# ============================================================================
# 8. ODVA CIP Time Sync Object (Class 0x43)
# ============================================================================

@dataclass
class CipTimeSyncObject:
    """ODVA CIP Networks Library Volume 1 Time Sync Object (Class 0x43)."""
    class_id: int = CIP_SYNC_CLASS_ID
    clock_type: CipSyncClockMode = CipSyncClockMode.END_TO_END_TC
    domain_number: int = DEFAULT_DOMAIN_NUMBER
    physical_ports: int = TOTAL_PHYSICAL_PORTS
    ptp_enable: bool = True
    is_synchronized: bool = True
    clock_state: int = 2
    diagnostic_status_code: int = 0
    mean_residence_time_ns: float = NOMINAL_RESIDENCE_TIME_NS
    total_correction_ns: float = 0.0
    rate_ratio_ppm: float = 0.0

    def __init__(
        self,
        class_id: int = CIP_SYNC_CLASS_ID,
        clock_type: Union[CipSyncClockMode, int] = CipSyncClockMode.END_TO_END_TC,
        domain_number: int = DEFAULT_DOMAIN_NUMBER,
        physical_ports: int = TOTAL_PHYSICAL_PORTS,
        ptp_enable: bool = True,
        is_synchronized: bool = True,
        clock_state: int = 2,
        diagnostic_status_code: int = 0,
        mean_residence_time_ns: float = NOMINAL_RESIDENCE_TIME_NS,
        total_correction_ns: float = 0.0,
        rate_ratio_ppm: float = 0.0,
        **kwargs: Any,
    ) -> None:
        self.class_id = kwargs.get("ClassID", class_id)
        raw_clock_type = kwargs.get("ClockType", clock_type)
        self.clock_type = CipSyncClockMode(raw_clock_type) if isinstance(raw_clock_type, int) else raw_clock_type
        self.domain_number = kwargs.get("DomainNumber", domain_number)
        self.physical_ports = kwargs.get("PhysicalPorts", physical_ports)
        self.ptp_enable = kwargs.get("PtpEnable", ptp_enable)
        self.is_synchronized = kwargs.get("IsSynchronized", is_synchronized)
        self.clock_state = kwargs.get("ClockState", clock_state)
        self.diagnostic_status_code = kwargs.get("DiagnosticStatusCode", diagnostic_status_code)
        self.mean_residence_time_ns = float(kwargs.get("MeanResidenceTimeNs", mean_residence_time_ns))
        self.total_correction_ns = float(kwargs.get("TotalCorrectionNs", total_correction_ns))
        self.rate_ratio_ppm = float(kwargs.get("RateRatioPpm", rate_ratio_ppm))

    @property
    def ClassID(self) -> int:
        return self.class_id

    @property
    def IsSynchronized(self) -> bool:
        return self.is_synchronized

    @property
    def ClockType(self) -> int:
        return int(self.clock_type)

    @property
    def ClockState(self) -> int:
        return self.clock_state

    @property
    def DiagnosticStatusCode(self) -> int:
        return self.diagnostic_status_code

    @property
    def MeanResidenceTimeNs(self) -> float:
        return self.mean_residence_time_ns

    @property
    def DomainNumber(self) -> int:
        return self.domain_number

    def get_attribute(self, attr_id: int) -> Any:
        """Get CIP Sync Object Class 0x43 instance attributes."""
        attrs = {
            1: self.class_id,
            2: self.is_synchronized,
            3: "00-1D-9C-FF-FE-72-A1-04",
            8: int(self.clock_type),
            9: self.domain_number,
            18: int(round(self.mean_residence_time_ns)),
            19: int(round(self.total_correction_ns)),
            20: self.rate_ratio_ppm,
        }
        return attrs.get(attr_id, None)


# ============================================================================
# 9. CipSyncTransparentClockEngine (ILogicUnit Implementation)
# ============================================================================

class CipSyncTransparentClockEngine(ILogicUnit):
    """ODVA CIP Sync Profile & IEEE 1588 Boundary Clock & Transparent Clock (E2E & P2P) Protocol Engine."""

    @property
    def is_active(self) -> bool:
        return self.is_transparent_clock_active

    @property
    def is_fault_tripped(self) -> bool:
        return (
            self.clock_asymmetry_fault_trip
            or (self.diagnostic_code != TransparentClockDiagnosticCode.OK)
        )

    @property
    def syntonization_rate_ratio_ppm(self) -> float:
        return self.syntonization_estimator.frequency_offset_ppm

    def get_cip_object(self) -> CipTimeSyncObject:
        return CipTimeSyncObject(
            ClassID=0x43,
            ClockType=int(self.clock_mode),
            DomainNumber=self.clock_domain_number,
            PhysicalPorts=len(self.ports),
            PtpEnable=True,
            IsSynchronized=self.is_transparent_clock_active,
            ClockState=2,
            DiagnosticStatusCode=int(self.diagnostic_code),
            MeanResidenceTimeNs=self.mean_residence_time_ns,
            TotalCorrectionNs=self.total_correction_ns,
            RateRatioPpm=self.syntonization_rate_ratio_ppm,
        )

    def __init__(
        self,
        clock_mode: CipSyncClockMode = CipSyncClockMode.END_TO_END_TC,
        clock_domain_number: int = DEFAULT_DOMAIN_NUMBER,
        clock_identity: Optional[Union[str, PtpClockIdentity]] = None,
        reg_table: Optional[RegisterTable] = None,
        port_count: int = TOTAL_PHYSICAL_PORTS,
        max_residence_time_ns: float = MAX_ALLOWABLE_RESIDENCE_TIME_NS,
        max_asymmetry_ns: float = MAX_PORT_ASYMMETRY_TOLERANCE_NS,
        max_rate_drift_ppm: float = MAX_SYNTONIZATION_DRIFT_PPM,
    ) -> None:
        self.clock_mode = clock_mode
        self.clock_domain_number = clock_domain_number
        self.clock_identity = (
            PtpClockIdentity(clock_identity)
            if clock_identity is not None
            else PtpClockIdentity.default_bridge()
        )
        self.reg_table: Optional[RegisterTable] = reg_table
        self.max_residence_time_ns = float(max_residence_time_ns)
        self.max_asymmetry_ns = float(max_asymmetry_ns)
        self.max_rate_drift_ppm = float(max_rate_drift_ppm)

        # 4-Port Architecture Setup
        self.ports: Dict[int, PtpPort] = {}
        for p in range(1, port_count + 1):
            is_up = (p == 1)
            init_state = PtpPortState.SLAVE if is_up else PtpPortState.MASTER
            self.ports[p] = PtpPort(
                port_id=p,
                state=init_state,
                is_enabled=True,
                is_upstream=is_up,
                peer_mean_path_delay_ns=1450.0 if p == 1 else 1000.0,
            )

        # Telemetry & Operational State
        self.nominal_residence_time_ns: float = NOMINAL_RESIDENCE_TIME_NS
        self.mean_residence_time_ns: float = NOMINAL_RESIDENCE_TIME_NS
        self.total_correction_ns: float = 0.0
        self.total_correction_field_units: int = 0
        self.syntonization_rate_ratio: float = 1.0
        self.frequency_offset_ppm: float = 0.0
        self.diagnostic_code: TransparentClockDiagnosticCode = TransparentClockDiagnosticCode.OK
        self.is_transparent_clock_active: bool = True
        self.clock_asymmetry_fault_trip: bool = False
        self.fault_trip: bool = False

        # Master Interval Tracking (Syntonization)
        self._prev_master_t1: Optional[PtpTimestamp] = None
        self._prev_local_t2: Optional[PtpTimestamp] = None
        self.syntonization_estimator = SyntonizationEstimator(max_drift_ppm=max_rate_drift_ppm)

        # Residence Time Measurement History
        self._residence_time_history: List[float] = []
        self._max_history: int = 32

        # Discrete Simulation Clock
        self.local_clock: PtpTimestamp = PtpTimestamp(seconds=1000, nanoseconds=0)
        self.elapsed_simulation_ms: float = 0.0
        self.total_scan_cycles: int = 0
        self._enabled: bool = True

        # CIP Sync Object (Class 0x43)
        self.cip_object = CipTimeSyncObject(
            clock_type=self.clock_mode,
            domain_number=self.clock_domain_number,
            physical_ports=len(self.ports),
            mean_residence_time_ns=self.mean_residence_time_ns,
        )

        self._evaluate_tc_active()
        if self.reg_table is not None:
            self.sync_to_registers()

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def active_port_count(self) -> int:
        """Count of active, non-disabled ports participating in the bridge."""
        return sum(
            1 for p in self.ports.values()
            if p.is_enabled and p.state not in (PtpPortState.DISABLED, PtpPortState.UNINITIALIZED)
        )

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "cip_sync_transparent_clock"

    @property
    def priority(self) -> int:
        return 94

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
        self.total_scan_cycles = 0
        self.elapsed_simulation_ms = 0.0
        self.total_correction_ns = 0.0
        self.total_correction_field_units = 0

    def scan_step(self, dt: float = 0.01, context: Optional[ScanContext] = None) -> None:
        """Advance discrete simulation clock, evaluate safety watchdogs, and synchronize registers."""
        dt_s = float(dt)
        self.elapsed_simulation_ms += dt_s * 1000.0
        self.total_scan_cycles += 1

        # Advance local clock according to syntonization rate ratio
        dt_adv_ns = int(round(dt_s * self.syntonization_rate_ratio * 1_000_000_000.0))
        self.local_clock = self.local_clock + dt_adv_ns

        # Update TC Active state
        self._evaluate_tc_active()

        # Update register table if bound
        if self.reg_table is not None:
            self.sync_to_registers(reg_table=self.reg_table)

    # ------------------------------------------------------------------------
    # State Evaluation & Safety Interlocks
    # ------------------------------------------------------------------------

    def _evaluate_tc_active(self) -> bool:
        """Evaluate TransparentClockActive flag and fault interlocks."""
        if self.diagnostic_code != TransparentClockDiagnosticCode.OK:
            self.is_transparent_clock_active = False
            return False

        if (
            self.mean_residence_time_ns > self.max_residence_time_ns
            or self.mean_residence_time_ns < 0.0
        ):
            self.is_transparent_clock_active = False
            return False

        is_tc = self.clock_mode in (CipSyncClockMode.END_TO_END_TC, CipSyncClockMode.PEER_TO_PEER_TC)
        self.is_transparent_clock_active = is_tc and (self.active_port_count >= 2)
        return self.is_transparent_clock_active

    def trip_fault(self, code: TransparentClockDiagnosticCode, details: str = "") -> None:
        """Trip safety interlock, latch diagnostic code, and de-energize active flag."""
        self.diagnostic_code = code
        self.fault_trip = True

        if code in (
            TransparentClockDiagnosticCode.PORT_ASYMMETRY_FAULT,
            TransparentClockDiagnosticCode.SYNTONIZATION_RATE_DRIFT,
        ):
            self.clock_asymmetry_fault_trip = True

        if code == TransparentClockDiagnosticCode.RESIDENCE_TIME_EXCEEDED:
            self.is_transparent_clock_active = False

        self._evaluate_tc_active()
        if self.reg_table is not None:
            self.sync_to_registers()

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Operator fault reset handshake restoring engine to healthy state."""
        self.diagnostic_code = TransparentClockDiagnosticCode.OK
        self.fault_trip = False
        self.clock_asymmetry_fault_trip = False

        # Reset residence time to nominal if faulted
        if self.mean_residence_time_ns > self.max_residence_time_ns:
            self.mean_residence_time_ns = self.nominal_residence_time_ns
            self._residence_time_history.clear()

        self._evaluate_tc_active()
        if self.reg_table is not None:
            self.sync_to_registers()

        return ExecutionResult.success(
            details=f"Fault latch cleared. Engine restored to {self.clock_mode.name} mode.",
            data={"clock_mode": self.clock_mode.name, "diagnostic_code": int(self.diagnostic_code)},
        )

    # ------------------------------------------------------------------------
    # Fault Simulation Methods
    # ------------------------------------------------------------------------

    def simulate_residence_time_exceeded(self, residence_time_ns: float = 12_500.0) -> None:
        """Simulate excessive bridge residence time exceeding 10.0 us (0xE301)."""
        self.mean_residence_time_ns = residence_time_ns
        self.trip_fault(
            TransparentClockDiagnosticCode.RESIDENCE_TIME_EXCEEDED,
            f"Simulated residence time {residence_time_ns:.1f}ns > {self.max_residence_time_ns}ns",
        )

    def simulate_port_asymmetry_fault(self, asymmetry_ns: float = 250.0) -> None:
        """Simulate physical port delay asymmetry exceeding tolerance (0xE302)."""
        self.ports[1].asymmetry_correction_ns = asymmetry_ns
        self.trip_fault(
            TransparentClockDiagnosticCode.PORT_ASYMMETRY_FAULT,
            f"Simulated port asymmetry {asymmetry_ns:.1f}ns > {self.max_asymmetry_ns}ns",
        )

    def simulate_syntonization_drift(self, offset_ppm: float = 65.0) -> None:
        """Simulate syntonization rate ratio drift exceeding limit (0xE303)."""
        self.frequency_offset_ppm = offset_ppm
        self.syntonization_rate_ratio = 1.0 + (offset_ppm / 1_000_000.0)
        self.trip_fault(
            TransparentClockDiagnosticCode.SYNTONIZATION_RATE_DRIFT,
            f"Simulated syntonization drift {offset_ppm:.2f}ppm > {self.max_rate_drift_ppm}ppm",
        )

    def simulate_rogue_clock_interception(self, details: str = "Simulated rogue clock interception") -> None:
        """Simulate rogue clock frame interception (0xE304)."""
        self.trip_fault(
            TransparentClockDiagnosticCode.ROGUE_CLOCK_INTERCEPTION,
            details,
        )

    # ------------------------------------------------------------------------
    # Port & Mode Management
    # ------------------------------------------------------------------------

    def set_clock_mode(self, mode: CipSyncClockMode) -> None:
        """Configure engine clock mode."""
        self.clock_mode = mode
        self.cip_object.clock_type = mode
        self._evaluate_tc_active()
        if self.reg_table is not None:
            self.sync_to_registers()

    def set_port_state(self, port_id: int, state: PtpPortState) -> None:
        """Update operational state of a specific port."""
        if port_id in self.ports:
            self.ports[port_id].state = state
            self._evaluate_tc_active()
            if self.reg_table is not None:
                self.sync_to_registers()

    # ------------------------------------------------------------------------
    # Protocol Message Forwarding & Transparent Clock Processing
    # ------------------------------------------------------------------------

    def forward_sync(
        self,
        ingress_port_id: int,
        sync_msg: PtpSyncMessage,
        ingress_timestamp: PtpTimestamp,
        egress_timestamps: Optional[Dict[int, PtpTimestamp]] = None,
    ) -> List[Tuple[int, PtpSyncMessage]]:
        """Forward PTP Sync frame through the transparent bridge to active downstream ports.

        Updates the 64-bit sub-nanosecond correctionField with bridge residence time
        and upstream peer link delay (in P2P mode), incorporating syntonization rate ratio.

        Returns:
            List of (egress_port_id, forwarded_sync_message) tuples.
        """
        # 1. Rogue Clock & Domain Interception Check
        if sync_msg.header.domainNumber != self.clock_domain_number:
            self.simulate_rogue_clock_interception(
                f"Unauthorized domain {sync_msg.header.domainNumber} != {self.clock_domain_number}"
            )
            return []

        in_port = self.ports.get(ingress_port_id)
        if in_port is None or not in_port.is_enabled:
            return []

        # If incoming frame arrives on downstream port claiming master sync in TC mode:
        if not in_port.is_upstream and self.clock_mode in (CipSyncClockMode.END_TO_END_TC, CipSyncClockMode.PEER_TO_PEER_TC):
            self.simulate_rogue_clock_interception(
                f"Rogue sync detected on downstream port {ingress_port_id}"
            )
            return []

        in_port.rx_packet_count += 1
        in_port.last_ingress_timestamp = ingress_timestamp

        # In Boundary Clock (BC) or Ordinary Clock (OC), frames are terminated, not bridged
        if self.clock_mode in (CipSyncClockMode.ORDINARY_CLOCK, CipSyncClockMode.BOUNDARY_CLOCK):
            return []

        forwarded_messages: List[Tuple[int, PtpSyncMessage]] = []
        peer_delay_ns = in_port.peer_mean_path_delay_ns if self.clock_mode == CipSyncClockMode.PEER_TO_PEER_TC else 0.0

        # Forward to all active downstream ports
        for out_pid, out_port in self.ports.items():
            if out_pid == ingress_port_id or not out_port.is_enabled or out_port.state == PtpPortState.DISABLED:
                continue

            # Determine egress timestamp
            if egress_timestamps and out_pid in egress_timestamps:
                egress_ts = egress_timestamps[out_pid]
            else:
                egress_ts = ingress_timestamp + self.nominal_residence_time_ns

            out_port.last_egress_timestamp = egress_ts
            out_port.tx_packet_count += 1

            # Residence time calculation:
            residence_time_ns = float((egress_ts - ingress_timestamp).to_ns())

            # Evaluate residence time threshold
            if residence_time_ns > self.max_residence_time_ns:
                self.simulate_residence_time_exceeded(residence_time_ns)
                return []

            # Update running mean residence time
            self._record_residence_time(residence_time_ns)

            # Sub-nanosecond correction field accumulation
            new_corr, delta_units, sub_ns_corr = accumulate_correction_field(
                correction_field_in=sync_msg.header.correctionField,
                residence_time_ns=residence_time_ns,
                rate_ratio=self.syntonization_rate_ratio,
                peer_delay_ns=peer_delay_ns,
            )

            # Accumulate cumulative bridge correction
            delta_ns = delta_units / float(CORRECTION_FIELD_SCALE_FACTOR)
            self.total_correction_ns += delta_ns
            self.total_correction_field_units += delta_units

            # Clone header and create outbound message
            out_hdr = PtpHeader(
                messageType=sync_msg.header.messageType,
                versionPTP=sync_msg.header.versionPTP,
                messageLength=sync_msg.header.messageLength,
                domainNumber=sync_msg.header.domainNumber,
                flagField=sync_msg.header.flagField,
                correctionField=new_corr,
                sourcePortIdentity=PtpPortIdentity(
                    clockIdentity=sync_msg.header.sourcePortIdentity.clockIdentity,
                    portNumber=out_pid,
                ),
                sequenceId=sync_msg.header.sequenceId,
                controlField=sync_msg.header.controlField,
                logMessageInterval=sync_msg.header.logMessageInterval,
            )
            out_sync = PtpSyncMessage(header=out_hdr, originTimestamp=sync_msg.originTimestamp)
            forwarded_messages.append((out_pid, out_sync))

        self._evaluate_tc_active()
        if self.reg_table is not None:
            self.sync_to_registers()

        return forwarded_messages

    def forward_follow_up(
        self,
        ingress_port_id: int,
        fu_msg: PtpFollowUpMessage,
        residence_time_ns: Optional[float] = None,
        egress_timestamps: Optional[Dict[int, PtpTimestamp]] = None,
    ) -> List[Tuple[int, PtpFollowUpMessage]]:
        """Forward PTP Follow_Up message across transparent bridge."""
        if fu_msg.header.domainNumber != self.clock_domain_number:
            self.simulate_rogue_clock_interception(
                f"Unauthorized domain {fu_msg.header.domainNumber} != {self.clock_domain_number}"
            )
            return []

        in_port = self.ports.get(ingress_port_id)
        if in_port is None or not in_port.is_enabled:
            return []

        in_port.rx_packet_count += 1

        if self.clock_mode in (CipSyncClockMode.ORDINARY_CLOCK, CipSyncClockMode.BOUNDARY_CLOCK):
            return []

        res_ns = residence_time_ns if residence_time_ns is not None else self.nominal_residence_time_ns
        peer_delay_ns = in_port.peer_mean_path_delay_ns if self.clock_mode == CipSyncClockMode.PEER_TO_PEER_TC else 0.0

        forwarded: List[Tuple[int, PtpFollowUpMessage]] = []
        for out_pid, out_port in self.ports.items():
            if out_pid == ingress_port_id or not out_port.is_enabled:
                continue

            out_port.tx_packet_count += 1

            new_corr, delta_units, _ = accumulate_correction_field(
                correction_field_in=fu_msg.header.correctionField,
                residence_time_ns=res_ns,
                rate_ratio=self.syntonization_rate_ratio,
                peer_delay_ns=peer_delay_ns,
            )

            out_hdr = PtpHeader(
                messageType=fu_msg.header.messageType,
                versionPTP=fu_msg.header.versionPTP,
                messageLength=fu_msg.header.messageLength,
                domainNumber=fu_msg.header.domainNumber,
                flagField=fu_msg.header.flagField,
                correctionField=new_corr,
                sourcePortIdentity=PtpPortIdentity(
                    clockIdentity=fu_msg.header.sourcePortIdentity.clockIdentity,
                    portNumber=out_pid,
                ),
                sequenceId=fu_msg.header.sequenceId,
                controlField=fu_msg.header.controlField,
                logMessageInterval=fu_msg.header.logMessageInterval,
            )
            out_fu = PtpFollowUpMessage(header=out_hdr, preciseOriginTimestamp=fu_msg.preciseOriginTimestamp)
            forwarded.append((out_pid, out_fu))

        return forwarded

    def forward_delay_req(
        self,
        ingress_port_id: int,
        req_msg: PtpDelayReqMessage,
        ingress_timestamp: PtpTimestamp,
        egress_timestamp: Optional[PtpTimestamp] = None,
    ) -> Optional[PtpDelayReqMessage]:
        """Forward upstream Delay_Req from downstream port to upstream Port 1 (E2E mode only).

        In Peer-to-Peer Transparent Clock (P2P_TC), Delay_Req is prohibited / dropped.
        """
        # Delay_Req is not forwarded in P2P mode
        if self.clock_mode == CipSyncClockMode.PEER_TO_PEER_TC:
            return None

        if req_msg.header.domainNumber != self.clock_domain_number:
            self.simulate_rogue_clock_interception()
            return None

        in_port = self.ports.get(ingress_port_id)
        if in_port is None or not in_port.is_enabled:
            return None

        in_port.rx_packet_count += 1
        in_port.last_ingress_timestamp = ingress_timestamp

        egress_ts = egress_timestamp if egress_timestamp is not None else (ingress_timestamp + self.nominal_residence_time_ns)
        residence_time_ns = float((egress_ts - ingress_timestamp).to_ns())

        if residence_time_ns > self.max_residence_time_ns:
            self.simulate_residence_time_exceeded(residence_time_ns)
            return None

        self._record_residence_time(residence_time_ns)

        new_corr, delta_units, _ = accumulate_correction_field(
            correction_field_in=req_msg.header.correctionField,
            residence_time_ns=residence_time_ns,
            rate_ratio=self.syntonization_rate_ratio,
            peer_delay_ns=0.0,
        )

        out_port = self.ports[1]  # Upstream port
        out_port.tx_packet_count += 1
        out_port.last_egress_timestamp = egress_ts

        out_hdr = PtpHeader(
            messageType=req_msg.header.messageType,
            versionPTP=req_msg.header.versionPTP,
            messageLength=req_msg.header.messageLength,
            domainNumber=req_msg.header.domainNumber,
            flagField=req_msg.header.flagField,
            correctionField=new_corr,
            sourcePortIdentity=PtpPortIdentity(
                clockIdentity=req_msg.header.sourcePortIdentity.clockIdentity,
                portNumber=1,
            ),
            sequenceId=req_msg.header.sequenceId,
            controlField=req_msg.header.controlField,
            logMessageInterval=req_msg.header.logMessageInterval,
        )
        return PtpDelayReqMessage(header=out_hdr, originTimestamp=req_msg.originTimestamp)

    # ------------------------------------------------------------------------
    # Peer Delay Measurement (P2P Mode)
    # ------------------------------------------------------------------------

    def measure_peer_delay(
        self,
        port_id: int,
        t1: PtpTimestamp,
        t2: PtpTimestamp,
        t3: PtpTimestamp,
        t4: PtpTimestamp,
    ) -> Dict[str, Any]:
        """Compute Peer-to-Peer propagation delay for a given link port.

        turnaround = t3 - t2
        round_trip = t4 - t1
        peer_mean_path_delay = (round_trip - turnaround) // 2
        """
        turnaround_ns = (t3 - t2).to_ns()
        round_trip_ns = (t4 - t1).to_ns()
        mean_delay_ns = max(0.0, float(round_trip_ns - turnaround_ns) / 2.0)

        if port_id in self.ports:
            self.ports[port_id].peer_mean_path_delay_ns = mean_delay_ns

        return {
            "port_id": port_id,
            "turnaround_ns": turnaround_ns,
            "round_trip_ns": round_trip_ns,
            "peer_mean_path_delay_ns": mean_delay_ns,
        }

    # ------------------------------------------------------------------------
    # Syntonization Rate Ratio Estimation Across Master Intervals
    # ------------------------------------------------------------------------

    def update_syntonization(
        self,
        master_timestamp: PtpTimestamp,
        local_ingress_timestamp: PtpTimestamp,
    ) -> float:
        """Estimate syntonization rate ratio from consecutive master message timestamps.

        rate_ratio = delta_master_time / delta_local_time
        frequency_offset_ppm = (rate_ratio - 1.0) * 1e6
        """
        r, ppm = self.syntonization_estimator.update(master_timestamp, local_ingress_timestamp)
        self.syntonization_rate_ratio = r
        self.frequency_offset_ppm = ppm
        self.cip_object.rate_ratio_ppm = ppm

        # Evaluate syntonization drift limit
        if abs(ppm) > self.max_rate_drift_ppm:
            self.simulate_syntonization_drift(ppm)

        return self.syntonization_rate_ratio

    def _record_residence_time(self, res_ns: float) -> None:
        """Record residence time sample and update running mean."""
        self._residence_time_history.append(res_ns)
        if len(self._residence_time_history) > self._max_history:
            self._residence_time_history.pop(0)

        self.mean_residence_time_ns = sum(self._residence_time_history) / float(len(self._residence_time_history))
        self.cip_object.mean_residence_time_ns = self.mean_residence_time_ns

    # ------------------------------------------------------------------------
    # Register Table Synchronization (%R1720..%R1727, %M401..%M402)
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize internal engine state to Horner OCS memory space."""
        rt = reg_table if reg_table is not None else self.reg_table
        if rt is None:
            return

        # %R1720: ClockTypeMode (0..3)
        safe_write_word(rt, "%R1720", int(self.clock_mode))

        # %R1721: ActivePortCount (INT16, e.g. 4)
        safe_write_word(rt, "%R1721", int(self.active_port_count))

        # %R1722: MeanResidenceTimeNsScaled (INT16 scaled, link mean bridge residence time in ns, e.g. 350 ns)
        mean_res_scaled = max(-32768, min(32767, int(round(self.mean_residence_time_ns))))
        safe_write_word(rt, "%R1722", mean_res_scaled)

        # %R1723: TotalCorrectionFieldNsLow (INT16, low 16 bits of cumulative correction field in ns)
        # %R1724: TotalCorrectionFieldNsHigh (INT16, high 16 bits of cumulative correction field in ns)
        corr_ns_int = int(round(self.total_correction_ns))
        low_w, high_w = encode_dint_words(corr_ns_int)
        safe_write_word(rt, "%R1723", low_w)
        safe_write_word(rt, "%R1724", high_w)

        # %R1725: SyntonizationRateRatioPpmScaled (INT16 scaled, e.g. 15 = +1.5 ppm frequency offset)
        ppm_scaled = max(-32768, min(32767, int(round(self.frequency_offset_ppm * PPM_REGISTER_SCALE_FACTOR))))
        safe_write_word(rt, "%R1725", ppm_scaled)

        # %R1726: ClockDomainNumber (INT16, 0..127)
        safe_write_word(rt, "%R1726", int(self.clock_domain_number))

        # %R1727: DiagnosticStatusCode (0x0000=OK, 0xE301..0xE304)
        safe_write_uword(rt, "%R1727", int(self.diagnostic_code))

        # %M401: TransparentClockActive (BOOL, True when bridge forwarding with residence time < 10.0 us)
        safe_write_bit(rt, "%M401", bool(self.is_transparent_clock_active))

        # %M402: ClockAsymmetryFaultTrip (BOOL, True on asymmetry or excessive drift)
        safe_write_bit(rt, "%M402", bool(self.clock_asymmetry_fault_trip))


# ============================================================================
# 10. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_sync_transparent_clock_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute rigorous deterministic 9-stage verification suite for W211 CIP Sync Transparent Clock Engine."""
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure IEC 61131-3 ST Syntax Validation & Anti-Ladder Check
    # ------------------------------------------------------------------------
    val_pou = STParser.validate_code(CIP_SYNC_TRANSPARENT_CLOCK_SYNC_POU)
    parser = STParser(pou_type=POUType.PROGRAM)
    ast_pou = parser.parse_pou(CIP_SYNC_TRANSPARENT_CLOCK_SYNC_POU)

    expected_regs = {
        "%R1720", "%R1721", "%R1722", "%R1723",
        "%R1724", "%R1725", "%R1726", "%R1727",
        "%M401", "%M402",
    }
    bound_regs = set(ast_pou.bound_registers)

    ladder_rejected = True
    for bad_construct in ["---[ ]---", "---( )---", "RUNG 1", "XIC TransparentClock_Sync"]:
        try:
            SecurityGuard.assert_pure_st_content(
                f"PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\n{bad_construct}\nEND_PROGRAM"
            )
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    # Verify pure ST passes cleanly
    SecurityGuard.assert_pure_st_content(CIP_SYNC_TRANSPARENT_CLOCK_SYNC_POU)

    s1_pass = (
        val_pou.status == AgentStatus.SUCCESS
        and ast_pou.name == "CipSyncTransparentClockSync"
        and expected_regs.issubset(bound_regs)
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "POU_ST_Syntax_Validation_And_Anti_Ladder_Check",
        "passed": s1_pass,
        "details": f"IEC 61131-3 POU 'CipSyncTransparentClockSync' verified cleanly; bound {len(bound_regs)} registers; ladder rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Clock Modes (OC, BC, E2E_TC, P2P_TC) & 4-Port State Machine Transitions
    # ------------------------------------------------------------------------
    engine_modes = CipSyncTransparentClockEngine(clock_mode=CipSyncClockMode.ORDINARY_CLOCK)

    m0 = int(CipSyncClockMode.ORDINARY_CLOCK) == 0
    m1 = int(CipSyncClockMode.BOUNDARY_CLOCK) == 1
    m2 = int(CipSyncClockMode.END_TO_END_TC) == 2
    m3 = int(CipSyncClockMode.PEER_TO_PEER_TC) == 3

    # Check 4 physical ports
    p_cnt = len(engine_modes.ports) == 4 and engine_modes.ports[1].is_upstream is True

    # Test state transitions on Port 2
    engine_modes.set_port_state(2, PtpPortState.UNINITIALIZED)
    st0 = engine_modes.ports[2].state == PtpPortState.UNINITIALIZED
    engine_modes.set_port_state(2, PtpPortState.INITIALIZING)
    st1 = engine_modes.ports[2].state == PtpPortState.INITIALIZING
    engine_modes.set_port_state(2, PtpPortState.LISTENING)
    st2 = engine_modes.ports[2].state == PtpPortState.LISTENING
    engine_modes.set_port_state(2, PtpPortState.MASTER)
    st3 = engine_modes.ports[2].state == PtpPortState.MASTER
    engine_modes.set_port_state(2, PtpPortState.SLAVE)
    st4 = engine_modes.ports[2].state == PtpPortState.SLAVE
    engine_modes.set_port_state(2, PtpPortState.PASSIVE)
    st5 = engine_modes.ports[2].state == PtpPortState.PASSIVE
    engine_modes.set_port_state(2, PtpPortState.DISABLED)
    st6 = engine_modes.ports[2].state == PtpPortState.DISABLED

    # Restore to MASTER
    engine_modes.set_port_state(2, PtpPortState.MASTER)
    act_count = engine_modes.active_port_count

    s2_pass = m0 and m1 and m2 and m3 and p_cnt and st0 and st1 and st2 and st3 and st4 and st5 and st6 and (act_count == 4)
    test_results.append({
        "stage": 2,
        "check": "Clock_Modes_And_4_Port_State_Machine",
        "passed": s2_pass,
        "details": f"Clock modes (0=OC, 1=BC, 2=E2E_TC, 3=P2P_TC) and 4-port state machine validated ({act_count} active ports).",
    })

    # ------------------------------------------------------------------------
    # Stage 3: End-to-End Transparent Clock (E2E_TC) Bridge Forwarding & Residence Time
    # ------------------------------------------------------------------------
    engine_e2e = CipSyncTransparentClockEngine(clock_mode=CipSyncClockMode.END_TO_END_TC)

    # Master sends Sync to Port 1
    t_in = PtpTimestamp(seconds=1000, nanoseconds=100_000)
    t_out = PtpTimestamp(seconds=1000, nanoseconds=100_350)  # residence_time = 350 ns
    init_corr = 1000 * CORRECTION_FIELD_SCALE_FACTOR        # 1000 ns initial correction

    hdr_sync = PtpHeader.create(
        msg_type=PtpMessageType.SYNC,
        source_identity=PtpClockIdentity("00-80-C2-FF-FE-00-00-01"),
        sequence_id=42,
        correction_field=init_corr,
    )
    sync_in = PtpSyncMessage(header=hdr_sync, originTimestamp=PtpTimestamp(0, 0))

    egress_map = {2: t_out, 3: t_out, 4: t_out}
    forwarded_syncs = engine_e2e.forward_sync(
        ingress_port_id=1,
        sync_msg=sync_in,
        ingress_timestamp=t_in,
        egress_timestamps=egress_map,
    )

    # Expected correction: 1000*65536 + 350*65536 = 1350 * 65536
    expected_corr = (1000 + 350) * CORRECTION_FIELD_SCALE_FACTOR

    s3_pass = (
        len(forwarded_syncs) == 3
        and all(f[1].header.correctionField == expected_corr for f in forwarded_syncs)
        and engine_e2e.mean_residence_time_ns == 350.0
        and engine_e2e.is_transparent_clock_active is True
        and engine_e2e.ports[1].rx_packet_count == 1
        and engine_e2e.ports[2].tx_packet_count == 1
    )
    test_results.append({
        "stage": 3,
        "check": "End_To_End_Transparent_Clock_Bridge_Forwarding_And_Residence_Time",
        "passed": s3_pass,
        "details": f"E2E TC forwarded 3 packets; residence time=350ns; correctionField={expected_corr} ({expected_corr // 65536}ns).",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Peer-to-Peer Transparent Clock (P2P_TC) & Peer Path Delay Addition
    # ------------------------------------------------------------------------
    engine_p2p = CipSyncTransparentClockEngine(clock_mode=CipSyncClockMode.PEER_TO_PEER_TC)

    # Verify link peer delay measurement
    t1_pdelay = PtpTimestamp(seconds=500, nanoseconds=10_000)
    t2_pdelay = PtpTimestamp(seconds=500, nanoseconds=11_450)  # +1450 ns
    t3_pdelay = PtpTimestamp(seconds=500, nanoseconds=31_450)  # +20,000 ns
    t4_pdelay = PtpTimestamp(seconds=500, nanoseconds=32_900)  # +1450 ns
    pdelay_res = engine_p2p.measure_peer_delay(1, t1_pdelay, t2_pdelay, t3_pdelay, t4_pdelay)

    # In P2P mode, Sync forwarded through bridge adds BOTH residence time AND upstream link peer delay:
    hdr_p2p = PtpHeader.create(
        msg_type=PtpMessageType.SYNC,
        source_identity=PtpClockIdentity("00-80-C2-FF-FE-00-00-01"),
        sequence_id=88,
        correction_field=0,
    )
    sync_p2p = PtpSyncMessage(header=hdr_p2p, originTimestamp=PtpTimestamp(0, 0))

    t_in_p2p = PtpTimestamp(seconds=600, nanoseconds=50_000)
    t_out_p2p = PtpTimestamp(seconds=600, nanoseconds=50_350)  # residence_time = 350 ns
    egress_p2p_map = {2: t_out_p2p, 3: t_out_p2p, 4: t_out_p2p}

    forwarded_p2p = engine_p2p.forward_sync(1, sync_p2p, t_in_p2p, egress_p2p_map)

    # Expected correction: 0 + 350*65536 + 1450*65536 = 1800 * 65536 = 117,964,800
    expected_p2p_corr = (350 + 1450) * CORRECTION_FIELD_SCALE_FACTOR

    # Delay_Req should be blocked/dropped in P2P mode
    req_blocked = engine_p2p.forward_delay_req(
        ingress_port_id=2,
        req_msg=PtpDelayReqMessage(header=hdr_p2p),
        ingress_timestamp=t_in_p2p,
    )

    s4_pass = (
        pdelay_res["peer_mean_path_delay_ns"] == 1450.0
        and len(forwarded_p2p) == 3
        and all(f[1].header.correctionField == expected_p2p_corr for f in forwarded_p2p)
        and req_blocked is None
    )
    test_results.append({
        "stage": 4,
        "check": "Peer_To_Peer_Transparent_Clock_And_Peer_Delay_Addition",
        "passed": s4_pass,
        "details": f"P2P TC verified: peer link delay=1450ns, total correction={expected_p2p_corr} ({expected_p2p_corr // 65536}ns), Delay_Req blocked.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Sub-Nanosecond Correction Field Accumulation & Scaling
    # ------------------------------------------------------------------------
    # Test formula: correctionField_out = correctionField_in + (residence_time_ns * 65536) + (sub_ns_rate_ratio_correction)
    res_sub_ns = 350.25  # fractional residence time
    rate_ratio_test = 1.000005  # +5.0 ppm
    corr_in_test = 10_000 * CORRECTION_FIELD_SCALE_FACTOR

    corr_out_test, delta_test, sub_ns_corr = accumulate_correction_field(
        correction_field_in=corr_in_test,
        residence_time_ns=res_sub_ns,
        rate_ratio=rate_ratio_test,
        peer_delay_ns=0.0,
    )

    expected_res_units = int(round(350.25 * 65536))
    expected_sub_units = int(round(350.25 * 0.000005 * 65536))
    expected_delta = expected_res_units + expected_sub_units

    # Test Horner register 32-bit packing/unpacking
    test_total_corr_ns = 125_000
    low_w, high_w = encode_dint_words(test_total_corr_ns)
    decoded_corr = decode_dint_words(low_w, high_w)

    s5_pass = (
        delta_test == expected_delta
        and corr_out_test == corr_in_test + expected_delta
        and sub_ns_corr == expected_sub_units
        and decoded_corr == test_total_corr_ns
    )
    test_results.append({
        "stage": 5,
        "check": "Sub_Nanosecond_Correction_Field_Accumulation_And_Fixed_Point_Scaling",
        "passed": s5_pass,
        "details": f"Sub-ns correction: res={expected_res_units} units, rate_ratio={expected_sub_units} units, DINT low={low_w}, high={high_w}.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Syntonization Rate Ratio Estimation Across Master Intervals
    # ------------------------------------------------------------------------
    engine_synt = CipSyncTransparentClockEngine()

    # Master interval = 1,000,000,000 ns (1.000000 s)
    # Local interval = 999,998,500 ns (0.9999985 s)
    # rate_ratio = 1,000,000,000 / 999,998,500 = 1.000001500002 -> +1.500 ppm
    m_t0 = PtpTimestamp(seconds=10, nanoseconds=0)
    l_t0 = PtpTimestamp(seconds=10, nanoseconds=0)
    engine_synt.update_syntonization(m_t0, l_t0)

    m_t1 = PtpTimestamp(seconds=11, nanoseconds=0)
    l_t1 = PtpTimestamp(seconds=10, nanoseconds=999_998_500)
    r_est = engine_synt.update_syntonization(m_t1, l_t1)
    ppm_est = engine_synt.frequency_offset_ppm

    # Scaled register value = int(round(ppm_est * 10)) = 15
    scaled_ppm_reg = int(round(ppm_est * PPM_REGISTER_SCALE_FACTOR))

    s6_pass = (
        abs(ppm_est - 1.50) < 0.05
        and scaled_ppm_reg == 15
        and engine_synt.diagnostic_code == TransparentClockDiagnosticCode.OK
    )
    test_results.append({
        "stage": 6,
        "check": "Syntonization_Rate_Ratio_Estimation_Across_Master_Intervals",
        "passed": s6_pass,
        "details": f"Syntonization tracking: rate_ratio={r_est:.9f}, offset={ppm_est:.3f} ppm, %R1725 scaled={scaled_ppm_reg}.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Horner OCS Register Table Mapping (%R1720..%R1727, %M401..%M402)
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine_rt = CipSyncTransparentClockEngine(
        clock_mode=CipSyncClockMode.END_TO_END_TC,
        clock_domain_number=0,
        reg_table=rt,
    )

    # Set known state
    engine_rt.mean_residence_time_ns = 350.0
    engine_rt.total_correction_ns = 45_000.0
    engine_rt.frequency_offset_ppm = 1.5
    engine_rt.diagnostic_code = TransparentClockDiagnosticCode.OK
    engine_rt.is_transparent_clock_active = True
    engine_rt.clock_asymmetry_fault_trip = False
    engine_rt.sync_to_registers(rt, PrivilegeMode.SYSTEM)

    r1720 = rt.read_word("%R1720")
    r1721 = rt.read_word("%R1721")
    r1722 = rt.read_word("%R1722")
    r1723 = rt.read_word("%R1723")
    r1724 = rt.read_word("%R1724")
    r1725 = rt.read_word("%R1725")
    r1726 = rt.read_word("%R1726")
    r1727 = rt.read_uword("%R1727")
    m401 = rt.read_bit("%M401")
    m402 = rt.read_bit("%M402")

    reconstructed_corr = decode_dint_words(r1723, r1724)

    s7_pass = (
        r1720 == int(CipSyncClockMode.END_TO_END_TC)
        and r1721 == 4
        and r1722 == 350
        and reconstructed_corr == 45_000
        and r1725 == 15
        and r1726 == 0
        and r1727 == 0x0000
        and m401 is True
        and m402 is False
    )
    test_results.append({
        "stage": 7,
        "check": "Horner_OCS_Register_Table_Mapping_R1720_R1727_M401_M402",
        "passed": s7_pass,
        "details": f"Horner OCS registers verified: %R1720={r1720}, %R1721={r1721}, %R1722={r1722}ns, corr={reconstructed_corr}ns, %R1725={r1725}, %M401={m401}.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Discrete ILogicUnit 100-Cycle Scan Simulation
    # ------------------------------------------------------------------------
    engine_scan = CipSyncTransparentClockEngine(
        clock_mode=CipSyncClockMode.END_TO_END_TC,
        reg_table=rt,
    )

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
        engine_scan.name == "cip_sync_transparent_clock"
        and engine_scan.priority == 94
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
    # Stage 9: Process Safety Interlocks, Diagnostics (0xE301..0xE304), & Operator Reset
    # ------------------------------------------------------------------------
    engine_safety = CipSyncTransparentClockEngine(reg_table=rt)

    # 1. Residence Time Exceeded (0xE301)
    engine_safety.simulate_residence_time_exceeded(12_500.0)
    d1 = (
        engine_safety.diagnostic_code == TransparentClockDiagnosticCode.RESIDENCE_TIME_EXCEEDED
        and rt.read_uword("%R1727") == 0xE301
        and rt.read_bit("%M401") is False
    )

    # 2. Port Asymmetry Fault (0xE302)
    engine_safety.simulate_port_asymmetry_fault(250.0)
    d2 = (
        engine_safety.diagnostic_code == TransparentClockDiagnosticCode.PORT_ASYMMETRY_FAULT
        and rt.read_uword("%R1727") == 0xE302
        and rt.read_bit("%M402") is True
    )

    # 3. Syntonization Rate Drift (0xE303)
    engine_safety.simulate_syntonization_drift(65.0)
    d3 = (
        engine_safety.diagnostic_code == TransparentClockDiagnosticCode.SYNTONIZATION_RATE_DRIFT
        and rt.read_uword("%R1727") == 0xE303
        and rt.read_bit("%M402") is True
    )

    # 4. Rogue Clock Interception (0xE304)
    engine_safety.simulate_rogue_clock_interception("Rogue clock interception")
    d4 = (
        engine_safety.diagnostic_code == TransparentClockDiagnosticCode.ROGUE_CLOCK_INTERCEPTION
        and rt.read_uword("%R1727") == 0xE304
    )

    # 5. Operator Reset Handshake
    res_reset = engine_safety.reset_fault(force=True)
    d5 = (
        res_reset.status == AgentStatus.SUCCESS
        and engine_safety.diagnostic_code == TransparentClockDiagnosticCode.OK
        and rt.read_uword("%R1727") == 0x0000
        and rt.read_bit("%M401") is True
        and rt.read_bit("%M402") is False
    )

    s9_pass = d1 and d2 and d3 and d4 and d5
    test_results.append({
        "stage": 9,
        "check": "Process_Safety_Interlocks_Diagnostics_And_Fault_Trips",
        "passed": s9_pass,
        "details": "Safety interlocks verified: 0xE301..0xE304 diagnostic fault trips and operator reset confirmed.",
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
        "details": f"CIP Sync Transparent Clock Engine (W211) verified cleanly ({passed_count}/{total_stages} stages passed).",
        "stages_passed": passed_count,
        "total_stages": total_stages,
        "data": {
            "work_package": "W211",
            "standards": [
                "IEEE 1588-2019 (PTPv2.1)",
                "IEEE 802.1AS-2020",
                "ODVA CIP Sync Profile (Class 0x43)",
                "IEC 61131-3 Structured Text",
            ],
            "stages": test_results,
            "tests": test_results,
            "checks_passed": passed_count,
            "total_checks": total_stages,
            "register_map": {
                "%R1720": "ClockTypeMode",
                "%R1721": "ActivePortCount",
                "%R1722": "MeanResidenceTimeNsScaled",
                "%R1723": "TotalCorrectionFieldNsLow",
                "%R1724": "TotalCorrectionFieldNsHigh",
                "%R1725": "SyntonizationRateRatioPpmScaled",
                "%R1726": "ClockDomainNumber",
                "%R1727": "DiagnosticStatusCode",
                "%M401": "TransparentClockActive",
                "%M402": "ClockAsymmetryFaultTrip",
            },
            "registers": {
                "%R1720": rt.read_word("%R1720"),
                "%R1721": rt.read_word("%R1721"),
                "%R1722": rt.read_word("%R1722"),
                "%R1723": rt.read_word("%R1723"),
                "%R1724": rt.read_word("%R1724"),
                "%R1725": rt.read_word("%R1725"),
                "%R1726": rt.read_word("%R1726"),
                "%R1727": rt.read_uword("%R1727"),
                "%M401": rt.read_bit("%M401"),
                "%M402": rt.read_bit("%M402"),
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


__all__ = [
    "CIP_SYNC_TRANSPARENT_CLOCK_POU",
    "CIP_SYNC_TRANSPARENT_CLOCK_SYNC_POU",
    "CipSyncClockMode",
    "CipSyncDiagnosticCode",
    "CipSyncPortState",
    "CipSyncTransparentClockEngine",
    "CipTimeSyncObject",
    "ClockMode",
    "ClockType",
    "ClockTypeMode",
    "DiagnosticCode",
    "DiagnosticStatusCode",
    "PortState",
    "PtpAnnounceMessage",
    "PtpAnnouncePacket",
    "PtpClockIdentity",
    "PtpClockQuality",
    "PtpClockType",
    "PtpDelayReqMessage",
    "PtpDelayReqPacket",
    "PtpDelayRespMessage",
    "PtpDelayRespPacket",
    "PtpDiagnosticCode",
    "PtpFlagField",
    "PtpFollowUpMessage",
    "PtpFollowUpPacket",
    "PtpHeader",
    "PtpMessageType",
    "PtpPdelayReqMessage",
    "PtpPdelayReqPacket",
    "PtpPdelayRespFollowUpMessage",
    "PtpPdelayRespFollowUpPacket",
    "PtpPdelayRespMessage",
    "PtpPdelayRespPacket",
    "PtpPort",
    "PtpPortIdentity",
    "PtpPortState",
    "PtpSyncMessage",
    "PtpSyncPacket",
    "PtpTimeInterval",
    "PtpTimestamp",
    "SyntonizationEstimator",
    "TcDiagnosticCode",
    "TcPortState",
    "TransparentClockDiagnosticCode",
    "TransparentClockPort",
    "TransparentClockType",
    "accumulate_correction_field",
    "decode_dint_words",
    "encode_dint_words",
    "run_cip_sync_transparent_clock_verification",
    "safe_write_bit",
    "safe_write_uword",
    "safe_write_word",
    "scale_correction_field",
    "unscale_correction_field",
]


if __name__ == "__main__":
    out_target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_cip_sync_transparent_clock_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
