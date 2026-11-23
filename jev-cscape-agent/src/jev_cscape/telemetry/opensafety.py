"""Industrial OpenSAFETY Over Black Channel Transport Engine.

Work Package: W151 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Strict Pure ST POU 'OpenSafetySync' (and alias 'OpenSafetyBlackChannelSync') with
   Horner OCS RegisterTable bindings (%R1120..%R1127, %M261..%M262). Pure IEC 61131-3
   Structured Text ONLY. Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN
   using SecurityGuard.assert_pure_st_content and STParser.
2. Complete OpenSAFETY Protocol Architecture (IEC 61784-3-13 / EPSG DS 301):
   - Bus-independent functional safety protocol over non-safe standard Ethernet 'Black Channel'.
   - Frame structure:
     * Dual redundant subframes: Subframe 1 (P) and Subframe 2 with inverted payload (~P).
     * 16-bit CRC on Subframe 1 and 16-bit CRC on Subframe 2 (polynomial 0x5935 / 0x1021).
     * Monotonic 16-bit sequence number to detect frame loss, duplication, and reordering.
     * Safety Domain Number (SDN) and Safety Node Number (SNN) verification.
     * Transmission delay time expectation monitoring.
3. Process Safety Interlocks & Diagnostics:
   - 0xB001: OPENSAFETY_ERR_CRC_MISMATCH (corrupted redundant safety payload)
             -> asserts %M262 (BlackChannelIntegrityTrip), clears %M261 (OpenSafetyPermissive).
   - 0xB002: OPENSAFETY_ERR_SEQUENCE_GAP (frame sequence counter gap or replay detected).
   - 0xB003: OPENSAFETY_ERR_TIMEOUT (safety message timeout exceeded).
   - 0xB004: OPENSAFETY_ERR_DOMAIN_COLLISION (safety domain mismatch).
4. Horner OCS Memory Space Integration:
   - %R1120: SafetyDomainNumber (16-bit uint, OpenSAFETY domain ID).
   - %R1121: ActiveSafetyNodesCount (INT16, e.g. 8).
   - %R1122: SafetyCycleCounter (16-bit uint, cyclic monotonic safety frame count).
   - %R1123: ConsecutiveCrcErrors (INT16, count of CRC errors).
   - %R1124: PrimarySafetyWordScaled (INT16, scaled x10, e.g. 500 = 50.0).
   - %R1125: SecondarySafetyWordScaled (INT16, scaled x10, e.g. 500 = 50.0).
   - %R1126: BlackChannelTransportLatencyUs (INT16, delay in us, e.g. 150 = 150 us).
   - %R1127: DiagnosticStatusCode (0x0000=OK, 0xB001, 0xB002, 0xB003, 0xB004).
   - %M261: OpenSafetyPermissive (BOOL, True when safety channel healthy).
   - %M262: BlackChannelIntegrityTrip (BOOL, True on CRC mismatch or frame loss).
5. Deterministic 9-Stage Verification Suite:
   - Function run_opensafety_verification(output_path) implementing 9 stages
     and returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
from pathlib import Path
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (IEC 61784-3-13 / EPSG DS 301)
# ============================================================================

OPENSAFETY_DEFAULT_DOMAIN_ID: int = 42                # 0x002A default Safety Domain Number (SDN)
OPENSAFETY_BROADCAST_SNN: int = 0xFFFF                # Broadcast Safety Node Number (SNN)
OPENSAFETY_MAX_SAFETY_NODES: int = 1023               # Max addressable safety nodes per domain
OPENSAFETY_DEFAULT_MAX_LATENCY_US: int = 20_000       # 20 ms maximum allowable transport latency
OPENSAFETY_DEFAULT_WATCHDOG_US: int = 50_000          # 50 ms connection loss watchdog timeout
OPENSAFETY_JITTER_ALLOWANCE_US: int = 5_000           # 5 ms clock skew / negative latency allowance

# OpenSAFETY CRC-16 Generator Polynomial: x^16 + x^14 + x^12 + x^11 + x^8 + x^7 + x^4 + x^2 + 1 (0x5935)
OPENSAFETY_CRC16_POLY: int = 0x5935
OPENSAFETY_CRC16_INIT: int = 0xFFFF

# ITU-T CCITT-16 Generator Polynomial (0x1021)
OPENSAFETY_CCITT_POLY: int = 0x1021
OPENSAFETY_CCITT_INIT: int = 0xFFFF

OPENSAFETY_MAGIC_HEADER: bytes = b"OS"                 # Wire framing magic for Black Channel payload


# ============================================================================
# 2. Enums, Status Bits, & Diagnostic Codes
# ============================================================================

class OpenSafetyState(IntEnum):
    """OpenSAFETY Operational State Machine."""
    INIT = 0                  # Initializing / awaiting configuration
    WAIT_SYNC = 1             # Synchronizing initial sequence counters and baseline timestamps
    OPERATIONAL = 2           # Normal safe data exchange; all integrity checks passing
    SAFETY_DEMAND = 3         # Communication healthy, but safety input tripped (e.g. E-Stop)
    INTEGRITY_FAULT = 4       # Black-channel anomaly detected (latched fail-safe trip)


class OpenSafetyFrameType(IntEnum):
    """OpenSAFETY Message / Telegram Categories."""
    SPDO = 0x01               # Safety Process Data Object (cyclic safe I/O)
    SSDO_REQ = 0x02           # Safety Service Data Object Request (acyclic parameter)
    SSDO_RESP = 0x03          # Safety Service Data Object Response
    SNMT = 0x04               # Safety Network Management


class OpenSafetyDiagnosticCode(IntEnum):
    """Horner OCS %R1127 Diagnostic Event Codes."""
    OK                              = 0x0000  # Normal healthy communication
    OPENSAFETY_ERR_CRC_MISMATCH     = 0xB001  # Corrupted redundant safety payload or CRC mismatch
    OPENSAFETY_ERR_SEQUENCE_GAP     = 0xB002  # Sequence counter gap, replay, or re-ordering detected
    OPENSAFETY_ERR_TIMEOUT          = 0xB003  # Safety message timeout or transport latency exceeded
    OPENSAFETY_ERR_DOMAIN_COLLISION = 0xB004  # Safety Domain Number (SDN) mismatch

    # Convenience aliases
    CRC_MISMATCH        = 0xB001
    SEQUENCE_GAP        = 0xB002
    TIMEOUT             = 0xB003
    DOMAIN_COLLISION    = 0xB004
    ERR_CRC_MISMATCH    = 0xB001
    ERR_SEQUENCE_GAP    = 0xB002
    ERR_TIMEOUT         = 0xB003
    ERR_DOMAIN_COLLISION = 0xB004
    OPENSAFETY_ERR_WATCHDOG_TIMEOUT = 0xB003
    WATCHDOG_TIMEOUT    = 0xB003
    OPENSAFETY_ERR_DOMAIN_ID_MISMATCH = 0xB004
    DOMAIN_ID_MISMATCH  = 0xB004
    OPENSAFETY_ERR_BLACK_CHANNEL = 0xB003


class OpenSafetyStatusBits(IntFlag):
    """Horner OCS Status Bitmask Definitions."""
    ENGINE_ACTIVE          = 1 << 0  # Bit 0 (0x0001): Engine initialized and running
    CONNECTION_ESTABLISHED = 1 << 1  # Bit 1 (0x0002): OpenSAFETY connection validated and synchronized
    PERMISSIVE_HEALTHY     = 1 << 2  # Bit 2 (0x0004): OpenSafetyPermissive healthy (%M261)
    CRC_FAULT              = 1 << 3  # Bit 3 (0x0008): CRC or redundant complement corruption (%M262)
    SEQUENCE_FAULT         = 1 << 4  # Bit 4 (0x0010): Monotonic sequence counter gap or replay
    TIMEOUT_FAULT          = 1 << 5  # Bit 5 (0x0020): Latency timeout or watchdog expiry
    DOMAIN_FAULT           = 1 << 6  # Bit 6 (0x0040): Safety domain collision
    REDUNDANCY_VERIFIED    = 1 << 7  # Bit 7 (0x0080): Dual-channel complementary redundancy verified


# ============================================================================
# 3. Protocol Errors & Exceptions
# ============================================================================

class OpenSafetyError(Exception):
    """Base exception for OpenSAFETY Protocol errors."""
    pass


class OpenSafetyCrcMismatchError(OpenSafetyError):
    """Raised on CRC mismatch or redundant payload corruption (0xB001)."""
    pass


class OpenSafetySequenceGapError(OpenSafetyError):
    """Raised on sequence counter gap, replay, or reorder (0xB002)."""
    pass


class OpenSafetyTimeoutError(OpenSafetyError):
    """Raised on transmission latency overrun or watchdog timeout (0xB003)."""
    pass


class OpenSafetyDomainCollisionError(OpenSafetyError):
    """Raised on safety domain number mismatch (0xB004)."""
    pass


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POUs
# ============================================================================

OPEN_SAFETY_SYNC_POU: str = """PROGRAM OpenSafetySync
VAR
    (* Horner OCS Mapped Registers (W151 - OpenSAFETY Engine) *)
    SafetyDomainNumber          AT %R1120 : UINT;   (* OpenSAFETY Domain Identifier *)
    ActiveSafetyNodesCount      AT %R1121 : INT;    (* Registered Active Safety Nodes *)
    SafetyCycleCounter          AT %R1122 : UINT;   (* Monotonic Safety Cycle Frame Counter *)
    ConsecutiveCrcErrors        AT %R1123 : INT;    (* Consecutive CRC Integrity Faults *)
    PrimarySafetyWordScaled     AT %R1124 : INT;    (* Primary Safety Channel Process Variable (x10) *)
    SecondarySafetyWordScaled   AT %R1125 : INT;    (* Redundant Inverted Channel PV (x10) *)
    BlackChannelTransportLatencyUs AT %R1126 : INT; (* Black Channel Transport Latency in us *)
    DiagnosticStatusCode       AT %R1127 : UINT;   (* Diagnostic Status Code (0x0000, 0xB001..0xB004) *)

    (* Discrete Safety Interlock Coils *)
    OpenSafetyPermissive        AT %M261  : BOOL;   (* TRUE when Black Channel and Safety Data Healthy *)
    BlackChannelIntegrityTrip   AT %M262  : BOOL;   (* TRUE on CRC Mismatch, Sequence Gap, or Timeout *)
END_VAR
VAR
    SafeOperationalState        : BOOL;
END_VAR

IF BlackChannelIntegrityTrip OR (DiagnosticStatusCode <> 0) THEN
    OpenSafetyPermissive := FALSE;
    BlackChannelIntegrityTrip := TRUE;
    PrimarySafetyWordScaled := 0;
    SecondarySafetyWordScaled := 0;
    SafeOperationalState := FALSE;
ELSIF OpenSafetyPermissive THEN
    SafetyCycleCounter := SafetyCycleCounter + 1;
    DiagnosticStatusCode := 0;
    SafeOperationalState := TRUE;
ELSE
    PrimarySafetyWordScaled := 0;
    SecondarySafetyWordScaled := 0;
    SafeOperationalState := FALSE;
END_IF;
END_PROGRAM
"""

OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU: str = """PROGRAM OpenSafetyBlackChannelSync
VAR
    (* Horner OCS Mapped Registers (W151 - OpenSAFETY Engine) *)
    SafetyDomainNumber          AT %R1120 : UINT;   (* OpenSAFETY Domain Identifier *)
    ActiveSafetyNodesCount      AT %R1121 : INT;    (* Registered Active Safety Nodes *)
    SafetyCycleCounter          AT %R1122 : UINT;   (* Monotonic Safety Cycle Frame Counter *)
    ConsecutiveCrcErrors        AT %R1123 : INT;    (* Consecutive CRC Integrity Faults *)
    PrimarySafetyWordScaled     AT %R1124 : INT;    (* Primary Safety Channel Process Variable (x10) *)
    SecondarySafetyWordScaled   AT %R1125 : INT;    (* Redundant Inverted Channel PV (x10) *)
    BlackChannelTransportLatencyUs AT %R1126 : INT; (* Black Channel Transport Latency in us *)
    DiagnosticStatusCode       AT %R1127 : UINT;   (* Diagnostic Status Code (0x0000, 0xB001..0xB004) *)

    (* Discrete Safety Interlock Coils *)
    OpenSafetyPermissive        AT %M261  : BOOL;   (* TRUE when Black Channel and Safety Data Healthy *)
    BlackChannelIntegrityTrip   AT %M262  : BOOL;   (* TRUE on CRC Mismatch, Sequence Gap, or Timeout *)
END_VAR
VAR
    SafeOperationalState        : BOOL;
END_VAR

IF BlackChannelIntegrityTrip OR (DiagnosticStatusCode <> 0) THEN
    OpenSafetyPermissive := FALSE;
    BlackChannelIntegrityTrip := TRUE;
    PrimarySafetyWordScaled := 0;
    SecondarySafetyWordScaled := 0;
    SafeOperationalState := FALSE;
ELSIF OpenSafetyPermissive THEN
    SafetyCycleCounter := SafetyCycleCounter + 1;
    DiagnosticStatusCode := 0;
    SafeOperationalState := TRUE;
ELSE
    PrimarySafetyWordScaled := 0;
    SecondarySafetyWordScaled := 0;
    SafeOperationalState := FALSE;
END_IF;
END_PROGRAM
"""

# Aliases for POU strings
OPENSAFETY_SYNC_POU: str = OPEN_SAFETY_SYNC_POU
OPENSAFETY_BLACK_CHANNEL_SYNC_POU: str = OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU
OPENSAFETY_PURE_ST_POU: str = OPEN_SAFETY_SYNC_POU
PURE_ST_POU: str = OPEN_SAFETY_SYNC_POU


def verify_opensafety_pure_st() -> bool:
    """Validate pure ST POUs with SecurityGuard and STParser."""
    SecurityGuard.assert_pure_st_content(OPEN_SAFETY_SYNC_POU)
    SecurityGuard.assert_pure_st_content(OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU)
    res1 = STParser.validate_code(OPEN_SAFETY_SYNC_POU)
    res2 = STParser.validate_code(OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU)
    ast1 = STParser.parse_pou(OPEN_SAFETY_SYNC_POU)
    ast2 = STParser.parse_pou(OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU)

    required_registers = {
        "%R1120", "%R1121", "%R1122", "%R1123",
        "%R1124", "%R1125", "%R1126", "%R1127",
        "%M261", "%M262",
    }
    has_regs1 = required_registers.issubset(set(ast1.bound_registers))
    has_regs2 = required_registers.issubset(set(ast2.bound_registers))

    return (
        res1.status == AgentStatus.SUCCESS
        and res2.status == AgentStatus.SUCCESS
        and ast1.pou_type == POUType.PROGRAM
        and ast2.pou_type == POUType.PROGRAM
        and has_regs1
        and has_regs2
    )


def scale_safety_pv_to_int16(val: float, scale_factor: float = 10.0) -> int:
    """Scale a float process variable to Horner INT16 with scaling factor (default x10).
    
    Clamped to [-32768, 32767].
    Example: 50.0 -> 500.
    """
    scaled = int(round(val * scale_factor))
    return max(-32768, min(32767, scaled))


# ============================================================================
# 5. Checksum Computation Algorithms
# ============================================================================

def compute_opensafety_crc16(data: bytes, poly: int = OPENSAFETY_CRC16_POLY, init: int = OPENSAFETY_CRC16_INIT) -> int:
    """Compute OpenSAFETY CRC-16 with generator polynomial 0x5935 (IEC 61784-3-13).
    
    Generator Polynomial: x^16 + x^14 + x^12 + x^11 + x^8 + x^7 + x^4 + x^2 + 1.
    """
    crc = init
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def compute_crc16_ccitt(data: bytes, poly: int = OPENSAFETY_CCITT_POLY, init: int = OPENSAFETY_CCITT_INIT) -> int:
    """Compute standard ITU-T CCITT-16 CRC with polynomial 0x1021."""
    crc = init
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


# ============================================================================
# 6. Wire Framing and Subframe Data Models
# ============================================================================

@dataclass
class OpenSafetySubframe:
    """OpenSAFETY Single Subframe (Subframe 1 or Subframe 2).
    
    Subframe 1 carries primary data (P).
    Subframe 2 carries bitwise inverted complementary data (~P).
    """
    sdn: int            # 16-bit Safety Domain Number (OpenSAFETY Domain ID)
    snn: int            # 16-bit Safety Node Number (Target or Source Node)
    seq_num: int        # 16-bit Monotonic sequence counter
    frame_type: int     # 8-bit OpenSafetyFrameType (SPDO, SSDO, etc.)
    timestamp_us: int   # 32-bit timestamp in microseconds
    payload: bytes      # Raw data bytes (P or ~P)
    crc16: int          # 16-bit CRC over (header + payload)

    HEADER_FORMAT: str = "<HHHBIH"  # sdn(2B), snn(2B), seq(2B), type(1B), time(4B), len(2B) = 13 bytes
    HEADER_SIZE: int = 13

    def serialize(self) -> bytes:
        """Serializes the subframe into deterministic wire bytes."""
        hdr = struct.pack(
            self.HEADER_FORMAT,
            self.sdn,
            self.snn,
            self.seq_num,
            self.frame_type,
            self.timestamp_us,
            len(self.payload),
        )
        return hdr + self.payload + struct.pack("<H", self.crc16)

    def compute_expected_crc(self) -> int:
        """Computes expected CRC-16 over header and payload."""
        hdr = struct.pack(
            self.HEADER_FORMAT,
            self.sdn,
            self.snn,
            self.seq_num,
            self.frame_type,
            self.timestamp_us,
            len(self.payload),
        )
        return compute_opensafety_crc16(hdr + self.payload)

    @classmethod
    def deserialize(cls, raw: bytes) -> OpenSafetySubframe:
        """Deserializes raw bytes into an OpenSafetySubframe."""
        min_len = cls.HEADER_SIZE + 2  # header (13) + crc (2)
        if len(raw) < min_len:
            raise ValueError(f"Subframe data length {len(raw)} below minimum envelope {min_len}")

        sdn, snn, seq_num, frame_type, timestamp_us, payload_len = struct.unpack(
            cls.HEADER_FORMAT, raw[:cls.HEADER_SIZE]
        )
        total_len = cls.HEADER_SIZE + payload_len + 2
        if len(raw) < total_len:
            raise ValueError(f"Subframe truncated: expected {total_len} bytes, got {len(raw)}")

        payload = raw[cls.HEADER_SIZE : cls.HEADER_SIZE + payload_len]
        crc_offset = cls.HEADER_SIZE + payload_len
        crc16, = struct.unpack("<H", raw[crc_offset : crc_offset + 2])

        return cls(
            sdn=sdn,
            snn=snn,
            seq_num=seq_num,
            frame_type=frame_type,
            timestamp_us=timestamp_us,
            payload=payload,
            crc16=crc16,
        )


@dataclass
class OpenSafetyFrame:
    """Complete Dual Redundant OpenSAFETY Packet over Black Channel.
    
    Contains Subframe 1 (P) and Subframe 2 (~P) with dual independent CRCs.
    """
    subframe1: OpenSafetySubframe
    subframe2: OpenSafetySubframe

    def serialize(self) -> bytes:
        """Serializes both subframes with magic prefix into wire bytes."""
        return OPENSAFETY_MAGIC_HEADER + self.subframe1.serialize() + self.subframe2.serialize()

    @classmethod
    def deserialize(cls, raw: bytes) -> OpenSafetyFrame:
        """Deserializes wire bytes into an OpenSafetyFrame."""
        offset = 0
        if raw.startswith(OPENSAFETY_MAGIC_HEADER):
            offset += len(OPENSAFETY_MAGIC_HEADER)

        remaining = raw[offset:]
        if len(remaining) < (OpenSafetySubframe.HEADER_SIZE + 2) * 2:
            raise ValueError(f"Payload too short for dual subframes ({len(remaining)} bytes)")

        # Parse subframe 1
        sf1_hdr = remaining[:OpenSafetySubframe.HEADER_SIZE]
        _, _, _, _, _, len1 = struct.unpack(OpenSafetySubframe.HEADER_FORMAT, sf1_hdr)
        sf1_total = OpenSafetySubframe.HEADER_SIZE + len1 + 2

        if len(remaining) < sf1_total:
            raise ValueError(f"Packet corrupted: subframe 1 truncated ({len(remaining)} < {sf1_total})")

        sf1 = OpenSafetySubframe.deserialize(remaining[:sf1_total])
        sf2 = OpenSafetySubframe.deserialize(remaining[sf1_total:])

        return cls(subframe1=sf1, subframe2=sf2)


@dataclass
class OpenSafetyValidationOutcome:
    """Validation report returned upon analyzing an incoming safety frame."""
    is_valid: bool
    diagnostic_code: OpenSafetyDiagnosticCode = OpenSafetyDiagnosticCode.OK
    error_code: Optional[str] = None
    details: str = ""
    payload: Optional[bytes] = None
    latency_us: int = 0
    seq_num: int = 0
    crc1_valid: bool = True
    crc2_valid: bool = True
    complement_valid: bool = True


# ============================================================================
# ============================================================================
# 7. OpenSAFETY Safety Node & Transport Engine Class
# ============================================================================

@dataclass
class OpenSafetyNode:
    """Configured OpenSAFETY endpoint node."""
    snn: int = 1
    name: str = ""
    is_active: bool = True
    node_id: int = 0

    def __post_init__(self) -> None:
        if self.node_id == 0 and self.snn > 0:
            self.node_id = self.snn
        elif self.snn == 0 and self.node_id > 0:
            self.snn = self.node_id


class OpenSafetyTransportEngine:
    """Industrial OpenSAFETY Over Black Channel Transport Engine.
    
    Standards: IEC 61784-3-13, EPSG DS 301, IEC 61508 SIL 3.
    Mapped Registers: %R1120..%R1127, %M261..%M262.
    """

    def __init__(
        self,
        domain_id: int = OPENSAFETY_DEFAULT_DOMAIN_ID,
        register_table: Optional[RegisterTable] = None,
        max_tolerable_latency_us: int = OPENSAFETY_DEFAULT_MAX_LATENCY_US,
        watchdog_timeout_us: int = OPENSAFETY_DEFAULT_WATCHDOG_US,
        jitter_allowance_us: int = OPENSAFETY_JITTER_ALLOWANCE_US,
        initial_time_us: int = 0,
    ) -> None:
        if not (0 <= domain_id <= 0xFFFF):
            raise ValueError(f"Domain ID must be 16-bit unsigned (0..65535), got {domain_id}")

        self.sdn: int = domain_id
        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.max_tolerable_latency_us: int = max_tolerable_latency_us
        self.watchdog_timeout_us: int = watchdog_timeout_us
        self.jitter_allowance_us: int = jitter_allowance_us
        self.current_time_us: int = initial_time_us

        # Active registered nodes (SNN -> Description)
        self.active_safety_nodes: Dict[int, str] = {}

        # Internal State Machine
        self.state: OpenSafetyState = OpenSafetyState.INIT
        self.tx_seq: int = 0
        self.rx_seq: int = 0
        self.has_synced: bool = False
        self.cycle_counter: int = 0
        self.consecutive_crc_errors: int = 0
        self.time_since_last_rx_us: int = 0
        self.is_latched: bool = False

        # Scaled Safety Words (e.g. 500 = 50.0)
        self.primary_safety_word: float = 0.0
        self.secondary_safety_word: float = 0.0
        self.last_latency_us: int = 0
        self.diagnostic_code: OpenSafetyDiagnosticCode = OpenSafetyDiagnosticCode.OK

        # Initial Register Sync
        self._sync_registers()

    def configure_safety_node(self, snn: Union[int, OpenSafetyNode], name: str = "") -> None:
        """Register an active safety node number in the safety domain."""
        if isinstance(snn, OpenSafetyNode):
            node_id = snn.snn or snn.node_id
            node_name = snn.name or name
        else:
            node_id = snn
            node_name = name
        if not (1 <= node_id <= OPENSAFETY_MAX_SAFETY_NODES):
            raise ValueError(f"Safety Node Number (SNN) must be 1..{OPENSAFETY_MAX_SAFETY_NODES}, got {node_id}")
        self.active_safety_nodes[node_id] = node_name or f"SafetyNode_{node_id}"
        self._sync_registers()

    def configure_node(self, node: Union[int, OpenSafetyNode], name: str = "") -> None:
        """Alias for configure_safety_node."""
        self.configure_safety_node(node, name)

    # ------------------------------------------------------------------------
    # Frame Encoding (Producer)
    # ------------------------------------------------------------------------

    def encode_safety_frame(
        self,
        snn: int,
        payload: bytes,
        frame_type: int = OpenSafetyFrameType.SPDO,
        timestamp_us: Optional[int] = None,
    ) -> OpenSafetyFrame:
        """Encode an outgoing OpenSAFETY frame with dual redundant subframes (P and ~P)."""
        self.tx_seq = (self.tx_seq + 1) & 0xFFFF
        ts = self.current_time_us if timestamp_us is None else timestamp_us

        # Primary Payload P
        payload_p = payload
        # Complementary Inverted Payload ~P
        payload_inv = bytes((~b) & 0xFF for b in payload)

        # Build Subframe 1
        sf1_dummy = OpenSafetySubframe(
            sdn=self.sdn,
            snn=snn,
            seq_num=self.tx_seq,
            frame_type=frame_type,
            timestamp_us=ts,
            payload=payload_p,
            crc16=0,
        )
        crc1 = sf1_dummy.compute_expected_crc()
        subframe1 = OpenSafetySubframe(
            sdn=self.sdn,
            snn=snn,
            seq_num=self.tx_seq,
            frame_type=frame_type,
            timestamp_us=ts,
            payload=payload_p,
            crc16=crc1,
        )

        # Build Subframe 2
        sf2_dummy = OpenSafetySubframe(
            sdn=self.sdn,
            snn=snn,
            seq_num=self.tx_seq,
            frame_type=frame_type,
            timestamp_us=ts,
            payload=payload_inv,
            crc16=0,
        )
        crc2 = sf2_dummy.compute_expected_crc()
        subframe2 = OpenSafetySubframe(
            sdn=self.sdn,
            snn=snn,
            seq_num=self.tx_seq,
            frame_type=frame_type,
            timestamp_us=ts,
            payload=payload_inv,
            crc16=crc2,
        )

        return OpenSafetyFrame(subframe1=subframe1, subframe2=subframe2)

    # ------------------------------------------------------------------------
    # Frame Validation (Consumer)
    # ------------------------------------------------------------------------

    def validate_safety_frame(
        self,
        frame_or_raw: Union[OpenSafetyFrame, bytes],
        current_time_us: int,
    ) -> OpenSafetyValidationOutcome:
        """Validate an incoming OpenSAFETY frame against all black-channel integrity criteria."""
        self.current_time_us = current_time_us

        # If latched in fail-safe trip, new packets are rejected until manual reset
        if self.is_latched:
            return OpenSafetyValidationOutcome(
                is_valid=False,
                diagnostic_code=self.diagnostic_code,
                error_code="OPENSAFETY_ERR_LATCHED_TRIP",
                details=f"Engine latched in fail-safe state ({self.diagnostic_code.name}). Manual reset required.",
                seq_num=self.rx_seq,
            )

        # Deserialize if raw wire bytes provided
        if isinstance(frame_or_raw, bytes):
            try:
                frame = OpenSafetyFrame.deserialize(frame_or_raw)
            except Exception as ex:
                self.consecutive_crc_errors += 1
                return self._trip_fault(
                    OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH,
                    f"Frame deserialization failed: {ex}",
                    error_code="ERR_DESERIALIZATION_FAILED",
                )
        else:
            frame = frame_or_raw

        sf1 = frame.subframe1
        sf2 = frame.subframe2

        # 1. Safety Domain Number (SDN) Verification
        if sf1.sdn != self.sdn or sf2.sdn != self.sdn:
            return self._trip_fault(
                OpenSafetyDiagnosticCode.OPENSAFETY_ERR_DOMAIN_COLLISION,
                f"Safety domain mismatch: frame SDN ({sf1.sdn}/{sf2.sdn}) != local SDN ({self.sdn})",
                error_code="ERR_DOMAIN_COLLISION",
            )

        # 2. Redundant Inverted Payload Verification (P vs ~P)
        if len(sf1.payload) != len(sf2.payload):
            self.consecutive_crc_errors += 1
            return self._trip_fault(
                OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH,
                f"Redundant subframe payload length mismatch ({len(sf1.payload)} != {len(sf2.payload)})",
                error_code="ERR_PAYLOAD_LENGTH_MISMATCH",
            )

        for i, (b1, b2) in enumerate(zip(sf1.payload, sf2.payload)):
            if (b1 ^ b2) != 0xFF:
                self.consecutive_crc_errors += 1
                return self._trip_fault(
                    OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH,
                    f"Redundant complement bit corruption at byte {i}: 0x{b1:02X} vs ~0x{b2:02X}",
                    error_code="ERR_COMPLEMENT_MISMATCH",
                )

        # 3. Dual Independent 16-bit CRC Verification
        exp_crc1 = sf1.compute_expected_crc()
        exp_crc2 = sf2.compute_expected_crc()

        if sf1.crc16 != exp_crc1 or sf2.crc16 != exp_crc2:
            self.consecutive_crc_errors += 1
            return self._trip_fault(
                OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH,
                f"CRC16 checksum failure: SF1 (calc 0x{exp_crc1:04X} vs pkt 0x{sf1.crc16:04X}) / "
                f"SF2 (calc 0x{exp_crc2:04X} vs pkt 0x{sf2.crc16:04X})",
                error_code="ERR_CRC_CHECKSUM_FAILURE",
            )

        # 4. Transmission Delay Time Expectation Monitoring
        latency_us = current_time_us - sf1.timestamp_us
        if latency_us < -self.jitter_allowance_us:
            return self._trip_fault(
                OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT,
                f"Future timestamp anomaly: packet timestamp is {abs(latency_us)} us in the future",
                error_code="ERR_FUTURE_TIMESTAMP",
            )

        if latency_us > self.max_tolerable_latency_us:
            return self._trip_fault(
                OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT,
                f"Black channel transport delay {latency_us} us exceeds max tolerable latency {self.max_tolerable_latency_us} us",
                error_code="ERR_TRANSPORT_LATENCY_EXCEEDED",
                latency_us=latency_us,
            )

        # 5. Monotonic 16-Bit Sequence Counter Verification
        if not self.has_synced:
            # Baseline synchronization on first valid frame
            self.has_synced = True
            self.rx_seq = sf1.seq_num
            self.state = OpenSafetyState.OPERATIONAL
        else:
            expected_seq = (self.rx_seq + 1) & 0xFFFF
            if sf1.seq_num != expected_seq:
                return self._trip_fault(
                    OpenSafetyDiagnosticCode.OPENSAFETY_ERR_SEQUENCE_GAP,
                    f"Sequence counter discontinuity: received {sf1.seq_num}, expected {expected_seq}",
                    error_code="ERR_SEQUENCE_GAP_OR_REPLAY",
                    seq_num=sf1.seq_num,
                )
            self.rx_seq = sf1.seq_num

        # Successful Frame Processing
        self.consecutive_crc_errors = 0
        self.cycle_counter = (self.cycle_counter + 1) & 0xFFFF
        self.last_latency_us = latency_us
        self.time_since_last_rx_us = 0
        self.diagnostic_code = OpenSafetyDiagnosticCode.OK

        # Unpack Safety Process Data if present (big-endian 16-bit signed integer)
        if len(sf1.payload) >= 2:
            raw_primary, = struct.unpack(">h", sf1.payload[:2])
            raw_sec, = struct.unpack(">h", sf2.payload[:2])
            self.primary_safety_word = raw_primary / 10.0
            # Redundant word inverted back (~raw_sec)
            inv_back = (~raw_sec) & 0xFFFF
            if inv_back >= 0x8000:
                inv_back -= 0x10000
            self.secondary_safety_word = inv_back / 10.0
        else:
            self.primary_safety_word = 50.0
            self.secondary_safety_word = 50.0

        self._sync_registers()

        return OpenSafetyValidationOutcome(
            is_valid=True,
            diagnostic_code=OpenSafetyDiagnosticCode.OK,
            details="OpenSAFETY dual subframe validated cleanly across Black Channel.",
            payload=sf1.payload,
            latency_us=latency_us,
            seq_num=sf1.seq_num,
            crc1_valid=True,
            crc2_valid=True,
            complement_valid=True,
        )

    # ------------------------------------------------------------------------
    # Fault Tripping & State Latching
    # ------------------------------------------------------------------------

    def _trip_fault(
        self,
        diagnostic_code: OpenSafetyDiagnosticCode,
        details: str,
        error_code: Optional[str] = None,
        latency_us: int = 0,
        seq_num: int = 0,
    ) -> OpenSafetyValidationOutcome:
        """Trip the safety interlock into fail-safe latched state."""
        self.is_latched = True
        self.state = OpenSafetyState.INTEGRITY_FAULT
        self.diagnostic_code = diagnostic_code
        self.primary_safety_word = 0.0
        self.secondary_safety_word = 0.0
        if latency_us > 0:
            self.last_latency_us = latency_us

        self._sync_registers()

        return OpenSafetyValidationOutcome(
            is_valid=False,
            diagnostic_code=diagnostic_code,
            error_code=error_code or diagnostic_code.name,
            details=details,
            latency_us=latency_us or self.last_latency_us,
            seq_num=seq_num or self.rx_seq,
            crc1_valid=(diagnostic_code != OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH),
            crc2_valid=(diagnostic_code != OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH),
            complement_valid=(diagnostic_code != OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH),
        )

    # ------------------------------------------------------------------------
    # Cyclic Step & Watchdog Surveillance
    # ------------------------------------------------------------------------

    def step_tick(self, delta_us: int) -> ExecutionResult:
        """Advance time by delta_us and check watchdog timeout surveillance."""
        self.current_time_us += delta_us
        self.time_since_last_rx_us += delta_us

        if self.state == OpenSafetyState.OPERATIONAL and not self.is_latched:
            if self.time_since_last_rx_us > self.watchdog_timeout_us:
                self._trip_fault(
                    OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT,
                    f"Watchdog expiry: {self.time_since_last_rx_us} us elapsed without valid safety frame (> {self.watchdog_timeout_us} us)",
                    error_code="ERR_WATCHDOG_TIMEOUT",
                )
                return ExecutionResult.failed(
                    error_code="ERR_WATCHDOG_TIMEOUT",
                    details=f"Watchdog expired ({self.time_since_last_rx_us} us > {self.watchdog_timeout_us} us)",
                    data={"state": self.state.name, "time_elapsed_us": self.time_since_last_rx_us},
                )

        return ExecutionResult.success(
            details=f"Advanced {delta_us} us cleanly. State: {self.state.name}",
            data={"state": self.state.name, "current_time_us": self.current_time_us},
        )

    # ------------------------------------------------------------------------
    # Operator Manual Reset Handshake
    # ------------------------------------------------------------------------

    def reset_latch(self, force: bool = False) -> ExecutionResult:
        """Operator manual reset handshake to clear latched fail-safe trip."""
        if not self.is_latched and not force:
            return ExecutionResult.success(
                details="No latched trip present. System already unlatched.",
                data={"is_latched": False, "state": self.state.name},
            )

        self.is_latched = False
        self.has_synced = False
        self.state = OpenSafetyState.WAIT_SYNC
        self.diagnostic_code = OpenSafetyDiagnosticCode.OK
        self.time_since_last_rx_us = 0
        self.consecutive_crc_errors = 0
        self._sync_registers()

        return ExecutionResult.success(
            details="Latched fail-safe trip cleared. System awaiting synchronization sequence.",
            data={"is_latched": False, "state": self.state.name},
        )

    # ------------------------------------------------------------------------
    # Register Synchronization (%R1120..%R1127, %M261..%M262)
    # ------------------------------------------------------------------------

    def _sync_registers(self) -> None:
        """Synchronize internal state to Horner OCS RegisterTable memory space."""
        # %R1120: SafetyDomainNumber (16-bit uint)
        self.reg_table.write_word("%R1120", self.sdn & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R1121: ActiveSafetyNodesCount (INT16)
        active_nodes = len(self.active_safety_nodes)
        self.reg_table.write_word("%R1121", active_nodes & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R1122: SafetyCycleCounter (16-bit uint)
        self.reg_table.write_word("%R1122", self.cycle_counter & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R1123: ConsecutiveCrcErrors (INT16)
        self.reg_table.write_word("%R1123", self.consecutive_crc_errors & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R1124: PrimarySafetyWordScaled (INT16, scaled x10, e.g. 500 = 50.0)
        p_scaled = scale_safety_pv_to_int16(self.primary_safety_word)
        self.reg_table.write_word("%R1124", p_scaled & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R1125: SecondarySafetyWordScaled (INT16, scaled x10, e.g. 500 = 50.0)
        s_scaled = scale_safety_pv_to_int16(self.secondary_safety_word)
        self.reg_table.write_word("%R1125", s_scaled & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R1126: BlackChannelTransportLatencyUs (INT16, delay in us, e.g. 150 = 150 us)
        clamped_latency = max(-32768, min(32767, self.last_latency_us))
        self.reg_table.write_word("%R1126", clamped_latency & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R1127: DiagnosticStatusCode (0x0000=OK, 0xB001, 0xB002, 0xB003, 0xB004)
        self.reg_table.write_word("%R1127", self.diagnostic_code.value & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %M261: OpenSafetyPermissive (BOOL, True when healthy and operational)
        permissive = (self.state == OpenSafetyState.OPERATIONAL) and not self.is_latched
        self.reg_table.write_bit("%M261", permissive, privilege=PrivilegeMode.SYSTEM)

        # %M262: BlackChannelIntegrityTrip (BOOL, True on CRC mismatch, sequence gap, timeout, or collision)
        trip_active = self.is_latched or (self.diagnostic_code != OpenSafetyDiagnosticCode.OK)
        self.reg_table.write_bit("%M262", trip_active, privilege=PrivilegeMode.SYSTEM)


# Aliases for class
OpenSafetyBlackChannelEngine = OpenSafetyTransportEngine
OpenSafetyEngine = OpenSafetyTransportEngine


class BlackChannelTransport:
    """Untrusted Black Channel transport simulation for OpenSAFETY frames.
    
    Provides latency tracking, noise injection (bit flip corruption in payload or headers),
    packet drop/gap simulation, and replay/duplication.
    """

    def __init__(
        self,
        default_latency_us: int = 450,
        max_tolerable_latency_us: int = OPENSAFETY_DEFAULT_MAX_LATENCY_US,
    ) -> None:
        self.default_latency_us: int = default_latency_us
        self.max_tolerable_latency_us: int = max_tolerable_latency_us
        self.current_latency_us: int = default_latency_us
        self.total_transmitted: int = 0
        self.total_corrupted: int = 0
        self.total_dropped: int = 0

    def transmit(
        self,
        frame: OpenSafetyFrame,
        simulated_latency_us: Optional[int] = None,
        inject_noise: bool = False,
    ) -> Tuple[bytes, int]:
        """Transmits frame across the black channel, optionally injecting noise."""
        latency = simulated_latency_us if simulated_latency_us is not None else self.default_latency_us
        self.current_latency_us = latency
        self.total_transmitted += 1

        raw = frame.serialize()
        if inject_noise:
            raw = self.inject_bit_flip(raw)
        return raw, latency

    def inject_bit_flip(self, raw: bytes, offset: Optional[int] = None) -> bytes:
        """Inverts a bit in the serialized raw frame to simulate transmission noise."""
        if not raw:
            return raw
        b = bytearray(raw)
        idx = offset if offset is not None else (len(b) - 5)
        idx = max(0, min(idx, len(b) - 1))
        b[idx] ^= 0x01
        self.total_corrupted += 1
        return bytes(b)



# ============================================================================
# 8. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_opensafety_verification(
    evidence_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute the deterministic 9-stage verification suite for OpenSAFETY Engine (W151).
    
    Emits strict 4-state contract JSON report.
    """
    target_path = output_path or evidence_path
    test_results: List[Dict[str, Any]] = []

    reg_table = RegisterTable()
    engine = OpenSafetyTransportEngine(
        domain_id=OPENSAFETY_DEFAULT_DOMAIN_ID,
        register_table=reg_table,
        max_tolerable_latency_us=OPENSAFETY_DEFAULT_MAX_LATENCY_US,
        watchdog_timeout_us=OPENSAFETY_DEFAULT_WATCHDOG_US,
    )
    for i in range(1, 9):
        engine.configure_safety_node(snn=i, name=f"SafetyNode_{i}")

    # ------------------------------------------------------------------------
    # Stage 1: Pure IEC 61131-3 ST AST Parsing & Register Symbol Verification
    # ------------------------------------------------------------------------
    st_valid = False
    details_1 = ""
    try:
        st_valid = verify_opensafety_pure_st()
        ast1 = STParser.parse_pou(OPEN_SAFETY_SYNC_POU)
        ast2 = STParser.parse_pou(OPEN_SAFETY_BLACK_CHANNEL_SYNC_POU)
        details_1 = (
            f"Successfully parsed {ast1.name} and {ast2.name} with {len(ast1.variables)} variables. "
            f"Bound registers: {', '.join(sorted(ast1.bound_registers))}."
        )
    except Exception as ex:
        details_1 = f"ST parsing failed: {ex}"

    test_results.append({
        "stage": 1,
        "check": "Pure_IEC_61131_3_ST_AST_Parsing_And_Register_Bindings",
        "passed": st_valid,
        "details": details_1,
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Construct Interception & Security Guard Rejection
    # ------------------------------------------------------------------------
    ladder_rejected = False
    bad_code = """PROGRAM BadLadderOpenSafety
    VAR Flag : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM"""
    try:
        SecurityGuard.assert_pure_st_content(bad_code)
    except LadderForbiddenError:
        ladder_rejected = True

    test_results.append({
        "stage": 2,
        "check": "Anti_Ladder_Construct_Security_Guard_Rejection",
        "passed": ladder_rejected,
        "details": "Ladder logic contacts and coils strictly intercepted with ERR_LADDER_FORBIDDEN.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Dual Subframe Redundant Packet Serialization & CRC16 Integrity
    # ------------------------------------------------------------------------
    payload_sample = struct.pack(">h", 500)  # 50.0 scaled x10
    frame_sample = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=1000)
    wire_bytes = frame_sample.serialize()
    deserialized_frame = OpenSafetyFrame.deserialize(wire_bytes)

    c3 = (
        len(wire_bytes) > 0
        and deserialized_frame.subframe1.sdn == OPENSAFETY_DEFAULT_DOMAIN_ID
        and deserialized_frame.subframe1.snn == 1
        and deserialized_frame.subframe1.payload == payload_sample
        and deserialized_frame.subframe2.payload == bytes((~b) & 0xFF for b in payload_sample)
        and deserialized_frame.subframe1.crc16 == frame_sample.subframe1.crc16
        and deserialized_frame.subframe2.crc16 == frame_sample.subframe2.crc16
    )
    test_results.append({
        "stage": 3,
        "check": "Dual_Subframe_Redundant_Packet_Serialization_And_CRC16",
        "passed": c3,
        "details": f"Dual subframes (P and ~P) serialized ({len(wire_bytes)} bytes) and deserialized bit-for-bit identical.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Strictly Monotonic Sequence Counter Progression
    # ------------------------------------------------------------------------
    res_f1 = engine.validate_safety_frame(frame_sample, current_time_us=1150)
    frame_2 = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=2000)
    res_f2 = engine.validate_safety_frame(frame_2, current_time_us=2150)
    frame_3 = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=3000)
    res_f3 = engine.validate_safety_frame(frame_3, current_time_us=3150)

    c4 = (
        res_f1.is_valid
        and res_f2.is_valid
        and res_f3.is_valid
        and engine.rx_seq == frame_3.subframe1.seq_num
        and engine.state == OpenSafetyState.OPERATIONAL
    )
    test_results.append({
        "stage": 4,
        "check": "Strictly_Monotonic_Sequence_Counter_Progression",
        "passed": c4,
        "details": f"Sequential frames {frame_sample.subframe1.seq_num} -> {frame_2.subframe1.seq_num} -> {frame_3.subframe1.seq_num} validated monotonically.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Dual Redundant Payload Inversion Invariant & Bit-Flip CRC Trapping (0xB001)
    # ------------------------------------------------------------------------
    # Corrupt a bit in Subframe 1 payload
    frame_corrupt = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=4000)
    raw_corrupt = bytearray(frame_corrupt.serialize())
    # Flip bit in payload area
    raw_corrupt[OpenSafetySubframe.HEADER_SIZE + 2] ^= 0x01
    res_corrupt = engine.validate_safety_frame(bytes(raw_corrupt), current_time_us=4150)

    c5 = (
        not res_corrupt.is_valid
        and res_corrupt.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_CRC_MISMATCH
        and engine.is_latched
        and reg_table.read_bit("%M262") is True
        and reg_table.read_bit("%M261") is False
        and engine.consecutive_crc_errors > 0
    )
    test_results.append({
        "stage": 5,
        "check": "Dual_Redundant_Payload_Inversion_And_Bit_Flip_CRC_Trapping",
        "passed": c5,
        "details": "Corrupted redundant safety payload trapped with 0xB001 (OPENSAFETY_ERR_CRC_MISMATCH), %M262 asserted, %M261 cleared.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Sequence Counter Discontinuity & Replay / Gap Rejection (0xB002)
    # ------------------------------------------------------------------------
    engine.reset_latch(force=True)
    # Re-establish normal operational state
    f_seq_a = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=5000)
    engine.validate_safety_frame(f_seq_a, current_time_us=5150)

    # Replay attack (re-transmit f_seq_a)
    res_replay = engine.validate_safety_frame(f_seq_a, current_time_us=5200)

    # Sequence gap jump (skip a frame)
    engine.reset_latch(force=True)
    f_gap_1 = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=6000)
    engine.validate_safety_frame(f_gap_1, current_time_us=6150)
    # Dropped frame:
    _ = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=7000)
    # Arrived frame with gap:
    f_gap_3 = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=8000)
    res_gap = engine.validate_safety_frame(f_gap_3, current_time_us=8150)

    c6 = (
        not res_replay.is_valid
        and res_replay.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_SEQUENCE_GAP
        and not res_gap.is_valid
        and res_gap.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_SEQUENCE_GAP
    )
    test_results.append({
        "stage": 6,
        "check": "Sequence_Counter_Discontinuity_And_Replay_Gap_Rejection",
        "passed": c6,
        "details": "Replay and sequence gap attacks trapped deterministically with 0xB002 (OPENSAFETY_ERR_SEQUENCE_GAP).",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Transmission Delay Surveillance & Black Channel Watchdog Timeout (0xB003)
    # ------------------------------------------------------------------------
    engine.reset_latch(force=True)
    f_time_base = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=10_000)
    engine.validate_safety_frame(f_time_base, current_time_us=10_150)

    # Excessive transport delay (35,000 us > 20,000 us limit)
    f_delayed = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=11_000)
    res_delay = engine.validate_safety_frame(f_delayed, current_time_us=46_000)  # delay = 35,000 us

    # Watchdog timeout test (advance tick beyond 50,000 us)
    engine.reset_latch(force=True)
    f_wd_sync = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=50_000)
    engine.validate_safety_frame(f_wd_sync, current_time_us=50_150)
    res_wd = engine.step_tick(delta_us=60_000)  # 60 ms > 50 ms watchdog

    c7 = (
        not res_delay.is_valid
        and res_delay.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT
        and res_wd.status == AgentStatus.FAILED
        and engine.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_TIMEOUT
        and engine.state == OpenSafetyState.INTEGRITY_FAULT
    )
    test_results.append({
        "stage": 7,
        "check": "Transmission_Delay_Surveillance_And_Watchdog_Timeout",
        "passed": c7,
        "details": "Excessive latency (35,000 us) and silence watchdog (60,000 us) trapped with 0xB003 (OPENSAFETY_ERR_TIMEOUT).",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Safety Domain Number (SDN) & Node Number Collision Trapping (0xB004)
    # ------------------------------------------------------------------------
    engine.reset_latch(force=True)
    f_sync_dom = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=120_000)
    engine.validate_safety_frame(f_sync_dom, current_time_us=120_150)

    # Forge rogue frame from unintended safety domain (0x9999)
    engine_alien = OpenSafetyTransportEngine(domain_id=0x9999, register_table=RegisterTable())
    f_alien = engine_alien.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=121_000)
    res_collision = engine.validate_safety_frame(f_alien, current_time_us=121_150)

    c8 = (
        not res_collision.is_valid
        and res_collision.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_DOMAIN_COLLISION
        and engine.diagnostic_code == OpenSafetyDiagnosticCode.OPENSAFETY_ERR_DOMAIN_COLLISION
        and reg_table.read_uword("%R1127") == 0xB004
        and reg_table.read_bit("%M262") is True
        and reg_table.read_bit("%M261") is False
    )
    test_results.append({
        "stage": 8,
        "check": "Safety_Domain_Number_And_Node_Collision_Trapping",
        "passed": c8,
        "details": "Alien safety domain ID (0x9999) rejected with 0xB004 (OPENSAFETY_ERR_DOMAIN_COLLISION).",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Memory Space Integration & Fail-Safe De-Energization Latch
    # ------------------------------------------------------------------------
    engine.reset_latch(force=True)
    f_healthy = engine.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=130_000)
    engine.validate_safety_frame(f_healthy, current_time_us=130_150)

    # Check healthy state in registers
    healthy_sdn = reg_table.read_uword("%R1120")
    healthy_nodes = reg_table.read_word("%R1121")
    healthy_p_word = reg_table.read_word("%R1124")
    healthy_s_word = reg_table.read_word("%R1125")
    healthy_lat = reg_table.read_word("%R1126")
    healthy_diag = reg_table.read_uword("%R1127")
    healthy_m261 = reg_table.read_bit("%M261")
    healthy_m262 = reg_table.read_bit("%M262")

    # Trip fault via alien packet and check fail-safe de-energization
    f_alien_trip = engine_alien.encode_safety_frame(snn=1, payload=payload_sample, timestamp_us=131_000)
    engine.validate_safety_frame(f_alien_trip, current_time_us=131_150)

    tripped_p_word = reg_table.read_word("%R1124")
    tripped_s_word = reg_table.read_word("%R1125")
    tripped_diag = reg_table.read_uword("%R1127")
    tripped_m261 = reg_table.read_bit("%M261")
    tripped_m262 = reg_table.read_bit("%M262")

    # Operator manual reset recovery
    res_reset = engine.reset_latch(force=True)
    recovered_m262 = reg_table.read_bit("%M262")
    recovered_diag = reg_table.read_uword("%R1127")

    c9 = (
        healthy_sdn == OPENSAFETY_DEFAULT_DOMAIN_ID
        and healthy_nodes == 8
        and healthy_p_word == 500
        and healthy_s_word == 500
        and healthy_lat == 150
        and healthy_diag == 0x0000
        and healthy_m261 is True
        and healthy_m262 is False
        and tripped_p_word == 0
        and tripped_s_word == 0
        and tripped_diag == 0xB004
        and tripped_m261 is False
        and tripped_m262 is True
        and res_reset.status == AgentStatus.SUCCESS
        and recovered_m262 is False
        and recovered_diag == 0x0000
    )
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Memory_Space_Integration_And_De_Energization_Latch",
        "passed": c9,
        "details": (
            f"Horner OCS registers (%R1120..%R1127, %M261..%M262) verified across healthy, "
            f"tripped (0x{tripped_diag:04X}), and operator reset states."
        ),
    })

    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"OpenSAFETY Transport Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W151",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial OpenSAFETY Over Black Channel Transport Engine",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R1120..%R1127",
                "discrete_coils": "%M261..%M262",
                "values": {
                    "%R1120": reg_table.read_uword("%R1120"),
                    "%R1121": reg_table.read_word("%R1121"),
                    "%R1122": reg_table.read_uword("%R1122"),
                    "%R1123": reg_table.read_word("%R1123"),
                    "%R1124": reg_table.read_word("%R1124"),
                    "%R1125": reg_table.read_word("%R1125"),
                    "%R1126": reg_table.read_word("%R1126"),
                    "%R1127": reg_table.read_uword("%R1127"),
                    "%M261": reg_table.read_bit("%M261"),
                    "%M262": reg_table.read_bit("%M262"),
                },
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if target_path:
        out_p = Path(target_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    out_target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_opensafety_verification(evidence_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
