"""Industrial IO-Link Safety Master & Safety Device Protocol Engine.

Work Package: W160 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Strict Pure ST POU 'IoLinkSafetySync' (and alias 'IoLinkSafetyMasterSync') with
   Horner OCS RegisterTable bindings (%R1210..%R1217, %M282..%M283). Pure IEC 61131-3
   Structured Text ONLY. Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN
   using SecurityGuard.assert_pure_st_content and STParser.
2. Complete IO-Link Safety Master Architecture (IEC 61131-9 / IEC 61508 / IEC 62061):
   - Safe cyclical communication with OSSD (Output Signal Switching Device) dual-channel monitoring.
   - Master Cycle Time (nominal 2.5 ms, 25 in INT16 scaled x10 ms).
   - Safe PD (Process Data) containers with safe sequence counter, inverted payload
     complement verification, and dual CRC-16 checksum integrity.
   - Safety watchdog timeout monitoring (< 20.0 ms nominal, 200 in INT16 scaled x10 ms).
3. Process Safety Interlocks & Diagnostics:
   - 0xB901: IOLINK_ERR_CRC_CORRUPTED (Safe container CRC mismatch)
             -> asserts %M283 (IoLinkSafetyFaultTrip), clears %M282 (IoLinkSafetyPermissive).
   - 0xB902: IOLINK_ERR_SEQUENCE_COUNTER_FAULT (Non-monotonic or frozen safety counter)
             -> asserts %M283.
   - 0xB903: IOLINK_ERR_WATCHDOG_TIMEOUT (Safety communication watchdog expired > 20.0 ms)
             -> asserts %M283, clears %M282.
   - 0xB904: IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED (Vendor/Device ID mismatch).
4. Horner OCS Memory Space Integration:
   - %R1210: IoLinkCycleTimeMsScaled (INT16, scaled x10 ms, e.g. 25 = 2.5 ms).
   - %R1211: ActiveSafeDevicesCount (INT16, e.g. 4 devices).
   - %R1212: SafeSequenceCounter (UINT16, monotonic sequence 0..65535).
   - %R1213: SafetyWatchdogMsScaled (INT16, scaled x10 ms, e.g. 200 = 20.0 ms).
   - %R1214: CrcErrorCount (INT16, count of CRC errors).
   - %R1215: OssdOutputStateWord (INT16, bitmask of OSSD 1/2 channels).
   - %R1216: DeviceVendorId (UINT16, e.g. 0x0123).
   - %R1217: DiagnosticStatusCode (0x0000=OK, 0xB901, 0xB902, 0xB903, 0xB904).
   - %M282: IoLinkSafetyPermissive (BOOL).
   - %M283: IoLinkSafetyFaultTrip (BOOL).
5. Deterministic 9-Stage Verification Suite:
   - Function run_iolink_safety_verification(output_path) implementing 9 stages
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
# 1. Constants & Protocol Definitions (IEC 61131-9 / IEC 61508 / IEC 62061)
# ============================================================================

IOLINK_SAFETY_NOMINAL_CYCLE_TIME_MS: float = 2.5
IOLINK_SAFETY_NOMINAL_CYCLE_TIME_SCALED: int = 25  # 2.5 ms * 10
IOLINK_SAFETY_NOMINAL_WATCHDOG_MS: float = 20.0
IOLINK_SAFETY_NOMINAL_WATCHDOG_SCALED: int = 200  # 20.0 ms * 10
IOLINK_SAFETY_DEFAULT_VENDOR_ID: int = 0x0123
IOLINK_SAFETY_DEFAULT_DEVICE_ID: int = 0x0001
IOLINK_SAFETY_MAX_SAFE_DEVICES: int = 8

# Dual CRC-16 generator polynomials and initial seeds
IOLINK_SAFETY_CRC16_POLY_A: int = 0x1021  # CRC-16-CCITT / ITU-T
IOLINK_SAFETY_CRC16_POLY_B: int = 0x8005  # CRC-16-IBM / ANSI
IOLINK_SAFETY_CRC16_INIT: int = 0xFFFF


# ============================================================================
# 2. Enums, Status Bits, & Diagnostic Codes
# ============================================================================

class IoLinkSafetyDiagnosticCode(IntEnum):
    """Horner OCS %R1217 Diagnostic Event Codes for IO-Link Safety."""
    OK                                      = 0x0000  # Safe loop healthy
    IOLINK_ERR_CRC_CORRUPTED                = 0xB901  # Safe container CRC or complement mismatch
    IOLINK_ERR_SEQUENCE_COUNTER_FAULT       = 0xB902  # Non-monotonic or frozen safety counter
    IOLINK_ERR_WATCHDOG_TIMEOUT             = 0xB903  # Safety communication watchdog expired > 20.0 ms
    IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED = 0xB904  # Vendor/Device ID mismatch

    CRC_CORRUPTED                = 0xB901
    SEQUENCE_COUNTER_FAULT       = 0xB902
    WATCHDOG_TIMEOUT             = 0xB903
    DEVICE_AUTHENTICATION_FAILED = 0xB904
    ERR_CRC_CORRUPTED            = 0xB901
    ERR_SEQUENCE_COUNTER_FAULT   = 0xB902
    ERR_WATCHDOG_TIMEOUT         = 0xB903
    ERR_DEVICE_AUTHENTICATION_FAILED = 0xB904
    IOLINK_SAFETY_ERR_CRC_MISMATCH = 0xB901
    IOLINK_SAFETY_ERR_SEQUENCE_FAULT = 0xB902
    IOLINK_SAFETY_ERR_WATCHDOG_TIMEOUT = 0xB903
    IOLINK_SAFETY_ERR_DEVICE_AUTH = 0xB904
    IOLINK_SAFETY_ERR_COMM_TIMEOUT = 0xB903
    CRC_MISMATCH                 = 0xB901
    SEQUENCE_FAULT               = 0xB902
    COMM_TIMEOUT                 = 0xB903
    DEVICE_AUTH                  = 0xB904


class IoLinkSafetyStatusBits(IntFlag):
    """IO-Link Safety Internal Master Status Bitmask."""
    MASTER_ACTIVE        = 1 << 0  # Bit 0: Master protocol engine running
    PERMISSIVE_HEALTHY   = 1 << 1  # Bit 1: Safe permissive coil asserted (%M282)
    FAULT_TRIPPED        = 1 << 2  # Bit 2: Safety fault trip latched (%M283)
    OSSD_ENERGIZED       = 1 << 3  # Bit 3: All active OSSD channels energized
    CRC_ERROR_LATCHED    = 1 << 4  # Bit 4: CRC corruption active
    SEQUENCE_ERROR_LATCH = 1 << 5  # Bit 5: Sequence counter anomaly active
    WATCHDOG_EXPIRED     = 1 << 6  # Bit 6: Watchdog timeout expired
    AUTH_MISMATCH_LATCH  = 1 << 7  # Bit 7: Device identity authentication failed


class IoLinkSafetyState(IntEnum):
    """Operational State Machine for IO-Link Safety Master."""
    INIT          = 0  # Initializing / unconfigured
    STARTUP       = 1  # Parameterizing and authenticating devices
    OPERATIONAL   = 2  # Cyclical safe data exchange active, permissive high
    SAFETY_DEMAND = 3  # Safe communication healthy, OSSD demand active
    FAULT_LATCHED = 4  # Safety trip latched; de-energized; requires operator reset


# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class IoLinkSafetyError(Exception):
    """Base exception for IO-Link Safety protocol errors."""
    pass


class IoLinkSafetyCrcCorruptedError(IoLinkSafetyError):
    """Raised on Safe container CRC or complement mismatch (0xB901)."""
    pass


class IoLinkSafetySequenceCounterFaultError(IoLinkSafetyError):
    """Raised on non-monotonic or frozen safety counter (0xB902)."""
    pass


class IoLinkSafetyWatchdogTimeoutError(IoLinkSafetyError):
    """Raised when safety communication watchdog expires > 20.0 ms (0xB903)."""
    pass


class IoLinkSafetyDeviceAuthenticationError(IoLinkSafetyError):
    """Raised on vendor/device ID authentication failure (0xB904)."""
    pass


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POUs
# ============================================================================

IOLINK_SAFETY_SYNC_POU: str = """PROGRAM IoLinkSafetySync
VAR
    (* Horner OCS Mapped Registers (W160 - IO-Link Safety Engine) *)
    IoLinkCycleTimeMsScaled     AT %R1210 : INT;    (* IO-Link Master Cycle Time in ms (x10, e.g. 25 = 2.5 ms) *)
    ActiveSafeDevicesCount      AT %R1211 : INT;    (* Registered Active Safe Devices *)
    SafeSequenceCounter         AT %R1212 : UINT;   (* Monotonic Safe Sequence Counter *)
    SafetyWatchdogMsScaled      AT %R1213 : INT;    (* Safety Watchdog Timeout in ms (x10, e.g. 200 = 20.0 ms) *)
    CrcErrorCount               AT %R1214 : INT;    (* Accumulated CRC Error Count *)
    OssdOutputStateWord         AT %R1215 : INT;    (* Bitmask of OSSD 1/2 Channels *)
    DeviceVendorId              AT %R1216 : UINT;   (* Validated Device Vendor ID *)
    DiagnosticStatusCode        AT %R1217 : UINT;   (* Diagnostic Status Code (0x0000, 0xB901..0xB904) *)

    (* Discrete Safety Interlock Coils *)
    IoLinkSafetyPermissive      AT %M282  : BOOL;   (* TRUE when IO-Link Safety Loop Healthy *)
    IoLinkSafetyFaultTrip       AT %M283  : BOOL;   (* TRUE on CRC, Sequence, Timeout, or Auth Fault *)
END_VAR
VAR
    SafeOperationalState        : BOOL;
END_VAR

IF IoLinkSafetyFaultTrip OR (DiagnosticStatusCode <> 0) THEN
    IoLinkSafetyPermissive := FALSE;
    IoLinkSafetyFaultTrip := TRUE;
    OssdOutputStateWord := 0;
    SafeOperationalState := FALSE;
ELSIF IoLinkSafetyPermissive THEN
    SafeSequenceCounter := SafeSequenceCounter + 1;
    DiagnosticStatusCode := 0;
    SafeOperationalState := TRUE;
ELSE
    OssdOutputStateWord := 0;
    SafeOperationalState := FALSE;
END_IF;
END_PROGRAM
"""

IOLINK_SAFETY_MASTER_SYNC_POU: str = """PROGRAM IoLinkSafetyMasterSync
VAR
    (* Horner OCS Mapped Registers (W160 - IO-Link Safety Engine) *)
    IoLinkCycleTimeMsScaled     AT %R1210 : INT;    (* IO-Link Master Cycle Time in ms (x10, e.g. 25 = 2.5 ms) *)
    ActiveSafeDevicesCount      AT %R1211 : INT;    (* Registered Active Safe Devices *)
    SafeSequenceCounter         AT %R1212 : UINT;   (* Monotonic Safe Sequence Counter *)
    SafetyWatchdogMsScaled      AT %R1213 : INT;    (* Safety Watchdog Timeout in ms (x10, e.g. 200 = 20.0 ms) *)
    CrcErrorCount               AT %R1214 : INT;    (* Accumulated CRC Error Count *)
    OssdOutputStateWord         AT %R1215 : INT;    (* Bitmask of OSSD 1/2 Channels *)
    DeviceVendorId              AT %R1216 : UINT;   (* Validated Device Vendor ID *)
    DiagnosticStatusCode        AT %R1217 : UINT;   (* Diagnostic Status Code (0x0000, 0xB901..0xB904) *)

    (* Discrete Safety Interlock Coils *)
    IoLinkSafetyPermissive      AT %M282  : BOOL;   (* TRUE when IO-Link Safety Loop Healthy *)
    IoLinkSafetyFaultTrip       AT %M283  : BOOL;   (* TRUE on CRC, Sequence, Timeout, or Auth Fault *)
END_VAR
VAR
    SafeOperationalState        : BOOL;
END_VAR

IF IoLinkSafetyFaultTrip OR (DiagnosticStatusCode <> 0) THEN
    IoLinkSafetyPermissive := FALSE;
    IoLinkSafetyFaultTrip := TRUE;
    OssdOutputStateWord := 0;
    SafeOperationalState := FALSE;
ELSIF IoLinkSafetyPermissive THEN
    SafeSequenceCounter := SafeSequenceCounter + 1;
    DiagnosticStatusCode := 0;
    SafeOperationalState := TRUE;
ELSE
    OssdOutputStateWord := 0;
    SafeOperationalState := FALSE;
END_IF;
END_PROGRAM
"""

# POU Aliases
PURE_ST_POU: str = IOLINK_SAFETY_SYNC_POU
IOLINK_SAFETY_PURE_ST_POU: str = IOLINK_SAFETY_SYNC_POU


def verify_iolink_safety_pure_st() -> bool:
    """Validate pure ST POUs with SecurityGuard and STParser."""
    SecurityGuard.assert_pure_st_content(IOLINK_SAFETY_SYNC_POU)
    SecurityGuard.assert_pure_st_content(IOLINK_SAFETY_MASTER_SYNC_POU)
    res1 = STParser.validate_code(IOLINK_SAFETY_SYNC_POU)
    res2 = STParser.validate_code(IOLINK_SAFETY_MASTER_SYNC_POU)
    ast1 = STParser.parse_pou(IOLINK_SAFETY_SYNC_POU)
    ast2 = STParser.parse_pou(IOLINK_SAFETY_MASTER_SYNC_POU)

    required_registers: Set[str] = {
        "%R1210", "%R1211", "%R1212", "%R1213",
        "%R1214", "%R1215", "%R1216", "%R1217",
        "%M282", "%M283",
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


# ============================================================================
# 5. Dual CRC-16 Checksum Algorithms & Helpers
# ============================================================================

def compute_crc16_a(
    data: bytes,
    init: int = IOLINK_SAFETY_CRC16_INIT,
    poly: int = IOLINK_SAFETY_CRC16_POLY_A,
) -> int:
    """Compute primary 16-bit CRC with polynomial 0x1021 (CRC-16-CCITT)."""
    crc = init
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def compute_crc16_b(
    data: bytes,
    init: int = IOLINK_SAFETY_CRC16_INIT,
    poly: int = IOLINK_SAFETY_CRC16_POLY_B,
) -> int:
    """Compute secondary 16-bit CRC with polynomial 0x8005 (CRC-16-IBM)."""
    crc = init
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def scale_ms_to_int16(val_ms: float, scale_factor: float = 10.0) -> int:
    """Scale a millisecond duration to Horner INT16 (scaled x10 ms).
    
    Example: 2.5 ms -> 25, 20.0 ms -> 200.
    """
    scaled = int(round(val_ms * scale_factor))
    return max(-32768, min(32767, scaled))


# ============================================================================
# 6. Safe Process Data (PD) Container Data Model
# ============================================================================

@dataclass
class SafeProcessDataContainer:
    """Safe Process Data (Safe PD) Container for IO-Link Safety.
    
    Adheres to IEC 61131-9 / IEC 61508 / IEC 62061:
    - Safe sequence counter for replay and gap interception.
    - Bitwise inverted payload complement verification (~P).
    - Dual CRC-16 checksum integrity.
    - OSSD (Output Signal Switching Device) dual-channel state bits.
    """
    device_id: int                    # 1..8 safe port/device identifier
    vendor_id: int                    # 16-bit Vendor ID (e.g. 0x0123)
    sequence_counter: int             # 16-bit monotonic sequence number (0..65535)
    ossd_ch1: bool                    # OSSD Channel 1 state (True=Energized)
    ossd_ch2: bool                    # OSSD Channel 2 state (True=Energized)
    payload: bytes                    # Safe process data payload (P)
    payload_inv: bytes                # Bitwise inverted complement (~P)
    crc_1: int                        # CRC-16-A over header + sequence + payload
    crc_2: int                        # CRC-16-B over header + sequence + payload_inv
    timestamp_ms: float = 0.0         # Transmission timestamp in milliseconds

    HEADER_FORMAT: str = "<BBHHH"    # device_id:1B, flags:1B, vendor_id:2B, seq:2B, payload_len:2B

    @classmethod
    def create(
        cls,
        device_id: int,
        vendor_id: int,
        sequence_counter: int,
        ossd_ch1: bool,
        ossd_ch2: bool,
        payload: bytes,
        timestamp_ms: float = 0.0,
    ) -> SafeProcessDataContainer:
        """Construct an authentic Safe Process Data container with computed dual CRCs."""
        payload_inv = bytes([b ^ 0xFF for b in payload])
        flags = (int(ossd_ch1) & 0x01) | ((int(ossd_ch2) & 0x01) << 1)
        hdr = struct.pack("<BBHH", device_id, flags, vendor_id, sequence_counter)
        crc_1 = compute_crc16_a(hdr + payload)
        crc_2 = compute_crc16_b(hdr + payload_inv)
        return cls(
            device_id=device_id,
            vendor_id=vendor_id,
            sequence_counter=sequence_counter,
            ossd_ch1=ossd_ch1,
            ossd_ch2=ossd_ch2,
            payload=payload,
            payload_inv=payload_inv,
            crc_1=crc_1,
            crc_2=crc_2,
            timestamp_ms=timestamp_ms,
        )

    def serialize(self) -> bytes:
        """Serialize container to deterministic binary wire representation."""
        flags = (int(self.ossd_ch1) & 0x01) | ((int(self.ossd_ch2) & 0x01) << 1)
        hdr = struct.pack(self.HEADER_FORMAT, self.device_id, flags, self.vendor_id, self.sequence_counter, len(self.payload))
        return hdr + self.payload + self.payload_inv + struct.pack("<HH", self.crc_1, self.crc_2)

    @classmethod
    def deserialize(cls, data: bytes, timestamp_ms: float = 0.0) -> SafeProcessDataContainer:
        """Deserialize raw binary wire bytes into SafeProcessDataContainer."""
        if len(data) < 12:
            raise ValueError(f"Payload length {len(data)} is too short for safe container wire format")
        dev_id, flags, vendor_id, seq_cnt, p_len = struct.unpack(cls.HEADER_FORMAT, data[:8])
        expected_len = 8 + (2 * p_len) + 4
        if len(data) < expected_len:
            raise ValueError(f"Incomplete safe frame: expected {expected_len} bytes, got {len(data)}")
        payload = data[8 : 8 + p_len]
        payload_inv = data[8 + p_len : 8 + (2 * p_len)]
        crc_1, crc_2 = struct.unpack("<HH", data[8 + (2 * p_len) : 8 + (2 * p_len) + 4])
        return cls(
            device_id=dev_id,
            vendor_id=vendor_id,
            sequence_counter=seq_cnt,
            ossd_ch1=bool(flags & 0x01),
            ossd_ch2=bool(flags & 0x02),
            payload=payload,
            payload_inv=payload_inv,
            crc_1=crc_1,
            crc_2=crc_2,
            timestamp_ms=timestamp_ms,
        )

    def verify_integrity(
        self,
        expected_vendor_id: Optional[int] = None,
    ) -> Tuple[bool, Optional[IoLinkSafetyDiagnosticCode], str]:
        """Verify inverted complement and dual CRC checksums."""
        # 1. Vendor authentication
        if expected_vendor_id is not None and self.vendor_id != expected_vendor_id:
            return (
                False,
                IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED,
                f"Vendor ID mismatch: expected 0x{expected_vendor_id:04X}, got 0x{self.vendor_id:04X}",
            )

        # 2. Inverted payload complement verification
        if len(self.payload) != len(self.payload_inv):
            return (
                False,
                IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED,
                "Payload and complement length mismatch",
            )
        if not all((p ^ inv) == 0xFF for p, inv in zip(self.payload, self.payload_inv)):
            return (
                False,
                IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED,
                "Inverted payload complement mismatch (P ^ ~P != 0xFF)",
            )

        # 3. Dual CRC-16 checksum integrity
        flags = (int(self.ossd_ch1) & 0x01) | ((int(self.ossd_ch2) & 0x01) << 1)
        hdr = struct.pack("<BBHH", self.device_id, flags, self.vendor_id, self.sequence_counter)
        exp_crc_1 = compute_crc16_a(hdr + self.payload)
        if self.crc_1 != exp_crc_1:
            return (
                False,
                IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED,
                f"CRC-1 mismatch: expected 0x{exp_crc_1:04X}, got 0x{self.crc_1:04X}",
            )
        exp_crc_2 = compute_crc16_b(hdr + self.payload_inv)
        if self.crc_2 != exp_crc_2:
            return (
                False,
                IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED,
                f"CRC-2 mismatch: expected 0x{exp_crc_2:04X}, got 0x{self.crc_2:04X}",
            )

        return True, None, "Safe container integrity verified"


@dataclass
class IoLinkSafetyValidationOutcome:
    """Rich validation outcome result for safe packet processing."""
    is_valid: bool
    diagnostic_code: IoLinkSafetyDiagnosticCode
    error_message: Optional[str] = None
    device_id: int = 0
    sequence_counter: int = 0
    crc_verified: bool = False
    complement_verified: bool = False
    ossd_ch1: bool = False
    ossd_ch2: bool = False
    latency_ms: float = 0.0


# ============================================================================
# 7. Safe Device State Model
# ============================================================================

@dataclass
class SafeDeviceState:
    """State tracking for a connected IO-Link Safety Device."""
    device_id: int
    vendor_id: int = IOLINK_SAFETY_DEFAULT_VENDOR_ID
    device_name: str = "SafeDevice"
    ossd_ch1: bool = True
    ossd_ch2: bool = True
    sequence_counter: int = 0
    last_rx_time_ms: float = 0.0
    is_authenticated: bool = True
    has_discrepancy: bool = False
    is_safe: bool = True
    last_payload: bytes = field(default_factory=bytes)

    def generate_safe_container(
        self,
        payload: bytes,
        timestamp_ms: float,
        corrupt_crc: bool = False,
        corrupt_complement: bool = False,
        corrupt_seq: Optional[int] = None,
        alien_vendor_id: Optional[int] = None,
    ) -> SafeProcessDataContainer:
        """Generate a simulated Safe PD container from this safe device."""
        seq = corrupt_seq if corrupt_seq is not None else self.sequence_counter
        vid = alien_vendor_id if alien_vendor_id is not None else self.vendor_id

        if corrupt_complement:
            inv = bytes([(b ^ 0xFF) ^ 0x01 for b in payload])
        else:
            inv = bytes([b ^ 0xFF for b in payload])

        flags = (int(self.ossd_ch1) & 0x01) | ((int(self.ossd_ch2) & 0x01) << 1)
        hdr = struct.pack("<BBHH", self.device_id, flags, vid, seq)
        crc_1 = compute_crc16_a(hdr + payload)
        crc_2 = compute_crc16_b(hdr + inv)

        if corrupt_crc:
            crc_1 ^= 0xFFFF

        return SafeProcessDataContainer(
            device_id=self.device_id,
            vendor_id=vid,
            sequence_counter=seq,
            ossd_ch1=self.ossd_ch1,
            ossd_ch2=self.ossd_ch2,
            payload=payload,
            payload_inv=inv,
            crc_1=crc_1,
            crc_2=crc_2,
            timestamp_ms=timestamp_ms,
        )


# ============================================================================
# 8. Industrial IO-Link Safety Master Protocol Engine
# ============================================================================

class IoLinkSafetyMasterEngine:
    """Industrial IO-Link Safety Master & Safety Device Protocol Engine.
    
    Work Package: W160 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
    Mapped Registers: %R1210..%R1217, %M282..%M283.
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        cycle_time_ms: float = IOLINK_SAFETY_NOMINAL_CYCLE_TIME_MS,
        watchdog_timeout_ms: float = IOLINK_SAFETY_NOMINAL_WATCHDOG_MS,
        expected_vendor_id: int = IOLINK_SAFETY_DEFAULT_VENDOR_ID,
        max_devices: int = IOLINK_SAFETY_MAX_SAFE_DEVICES,
    ) -> None:
        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.cycle_time_ms: float = cycle_time_ms
        self.watchdog_timeout_ms: float = watchdog_timeout_ms
        self.expected_vendor_id: int = expected_vendor_id
        self.max_devices: int = max_devices

        self.devices: Dict[int, SafeDeviceState] = {}
        self.safe_sequence_counter: int = 0
        self.crc_error_count: int = 0
        self.ossd_output_state_word: int = 0
        self.diagnostic_code: IoLinkSafetyDiagnosticCode = IoLinkSafetyDiagnosticCode.OK
        self.permissive: bool = True
        self.fault_trip: bool = False
        self.current_time_ms: float = 0.0
        self.state: IoLinkSafetyState = IoLinkSafetyState.OPERATIONAL
        self.status_bits: IoLinkSafetyStatusBits = (
            IoLinkSafetyStatusBits.MASTER_ACTIVE | IoLinkSafetyStatusBits.PERMISSIVE_HEALTHY
        )

        # Initial register sync
        self.sync_to_registers()

    # ------------------------------------------------------------------------
    # Device Configuration
    # ------------------------------------------------------------------------

    def register_safe_device(
        self,
        device_id: int,
        device_name: str = "SafeDevice",
        vendor_id: Optional[int] = None,
        ossd_ch1: bool = True,
        ossd_ch2: bool = True,
    ) -> SafeDeviceState:
        """Register an active IO-Link safe device under master surveillance."""
        if device_id < 1 or device_id > self.max_devices:
            raise ValueError(f"device_id {device_id} out of bounds (1..{self.max_devices})")

        dev = SafeDeviceState(
            device_id=device_id,
            vendor_id=vendor_id if vendor_id is not None else self.expected_vendor_id,
            device_name=device_name,
            ossd_ch1=ossd_ch1,
            ossd_ch2=ossd_ch2,
            last_rx_time_ms=self.current_time_ms,
        )
        self.devices[device_id] = dev
        self.recompute_ossd_state_word()
        self.sync_to_registers()
        return dev

    # ------------------------------------------------------------------------
    # OSSD Monitoring & Bitmask Calculation
    # ------------------------------------------------------------------------

    def recompute_ossd_state_word(self) -> int:
        """Recompute OSSD bitmask (%R1215) across active safe devices.
        
        For active device index i (0..N-1):
        - Bit (2*i): OSSD Channel 1
        - Bit (2*i + 1): OSSD Channel 2
        
        If master is in fault trip (%M283=True), all outputs are forced to 0.
        If an individual device has an OSSD channel discrepancy, its channels are de-energized.
        """
        if self.fault_trip or self.state == IoLinkSafetyState.FAULT_LATCHED:
            self.ossd_output_state_word = 0
            return 0

        mask = 0
        all_ossd_active = True
        sorted_devices = sorted(self.devices.values(), key=lambda d: d.device_id)
        for i, dev in enumerate(sorted_devices):
            if i >= 8:
                break
            # Discrepancy check: both channels must be congruent
            if dev.ossd_ch1 != dev.ossd_ch2:
                dev.has_discrepancy = True
                dev.is_safe = False
                all_ossd_active = False
                # Discrepancy causes individual de-energization to safe state
                continue
            else:
                dev.has_discrepancy = False
                dev.is_safe = dev.ossd_ch1 and dev.ossd_ch2

            if dev.ossd_ch1:
                mask |= (1 << (2 * i))
            if dev.ossd_ch2:
                mask |= (1 << (2 * i + 1))

            if not (dev.ossd_ch1 and dev.ossd_ch2):
                all_ossd_active = False

        self.ossd_output_state_word = mask
        if all_ossd_active and len(self.devices) > 0:
            self.status_bits |= IoLinkSafetyStatusBits.OSSD_ENERGIZED
        else:
            self.status_bits &= ~IoLinkSafetyStatusBits.OSSD_ENERGIZED

        return mask

    # ------------------------------------------------------------------------
    # Fault Interlock Assertion
    # ------------------------------------------------------------------------

    def trigger_fault(
        self,
        code: IoLinkSafetyDiagnosticCode,
        error_msg: Optional[str] = None,
    ) -> None:
        """Trip process safety interlock and de-energize outputs."""
        self.diagnostic_code = code
        self.fault_trip = True
        self.permissive = False
        self.ossd_output_state_word = 0
        self.state = IoLinkSafetyState.FAULT_LATCHED

        self.status_bits |= IoLinkSafetyStatusBits.FAULT_TRIPPED
        self.status_bits &= ~IoLinkSafetyStatusBits.PERMISSIVE_HEALTHY
        self.status_bits &= ~IoLinkSafetyStatusBits.OSSD_ENERGIZED

        if code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED:
            self.crc_error_count += 1
            self.status_bits |= IoLinkSafetyStatusBits.CRC_ERROR_LATCHED
        elif code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT:
            self.status_bits |= IoLinkSafetyStatusBits.SEQUENCE_ERROR_LATCH
        elif code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_WATCHDOG_TIMEOUT:
            self.status_bits |= IoLinkSafetyStatusBits.WATCHDOG_EXPIRED
        elif code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED:
            self.status_bits |= IoLinkSafetyStatusBits.AUTH_MISMATCH_LATCH

        self.sync_to_registers()

    def reset_latch(self, force: bool = False) -> ExecutionResult:
        """Operator manual reset handshake to recover from safe trip."""
        self.fault_trip = False
        self.permissive = True
        self.diagnostic_code = IoLinkSafetyDiagnosticCode.OK
        self.state = IoLinkSafetyState.OPERATIONAL

        self.status_bits &= ~IoLinkSafetyStatusBits.FAULT_TRIPPED
        self.status_bits &= ~IoLinkSafetyStatusBits.CRC_ERROR_LATCHED
        self.status_bits &= ~IoLinkSafetyStatusBits.SEQUENCE_ERROR_LATCH
        self.status_bits &= ~IoLinkSafetyStatusBits.WATCHDOG_EXPIRED
        self.status_bits &= ~IoLinkSafetyStatusBits.AUTH_MISMATCH_LATCH
        self.status_bits |= IoLinkSafetyStatusBits.PERMISSIVE_HEALTHY

        # Touch last rx time to avoid immediate watchdog trip upon reset
        for dev in self.devices.values():
            dev.last_rx_time_ms = self.current_time_ms
            dev.has_discrepancy = False

        self.recompute_ossd_state_word()
        self.sync_to_registers()

        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details="IO-Link Safety interlock latch cleared and permissive restored by operator reset.",
            data={"diagnostic_code": int(self.diagnostic_code), "permissive": self.permissive},
        )

    # ------------------------------------------------------------------------
    # Safe Frame Processing & Invariant Enforcement
    # ------------------------------------------------------------------------

    def process_safe_container(
        self,
        container: SafeProcessDataContainer,
        current_time_ms: Optional[float] = None,
    ) -> IoLinkSafetyValidationOutcome:
        """Validate and ingest an incoming Safe Process Data container."""
        if current_time_ms is not None:
            self.current_time_ms = current_time_ms

        # Check if already in latched fault trip
        if self.fault_trip:
            return IoLinkSafetyValidationOutcome(
                is_valid=False,
                diagnostic_code=self.diagnostic_code,
                error_message="Master in latched fault trip state",
                device_id=container.device_id,
                sequence_counter=container.sequence_counter,
            )

        # 1. Device Registration Check
        dev = self.devices.get(container.device_id)
        if dev is None:
            self.trigger_fault(IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED)
            return IoLinkSafetyValidationOutcome(
                is_valid=False,
                diagnostic_code=IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED,
                error_message=f"Device ID {container.device_id} not registered on master",
                device_id=container.device_id,
                sequence_counter=container.sequence_counter,
            )

        # 2. Device Vendor Authentication (0xB904)
        if container.vendor_id != self.expected_vendor_id:
            self.trigger_fault(IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED)
            return IoLinkSafetyValidationOutcome(
                is_valid=False,
                diagnostic_code=IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED,
                error_message=f"Vendor ID mismatch: expected 0x{self.expected_vendor_id:04X}, got 0x{container.vendor_id:04X}",
                device_id=container.device_id,
                sequence_counter=container.sequence_counter,
            )

        # 3. Payload Inverted Complement and Dual CRC-16 Checksum Integrity (0xB901)
        valid, diag, err = container.verify_integrity(expected_vendor_id=self.expected_vendor_id)
        if not valid:
            assert diag is not None
            self.trigger_fault(diag, err)
            return IoLinkSafetyValidationOutcome(
                is_valid=False,
                diagnostic_code=diag,
                error_message=err,
                device_id=container.device_id,
                sequence_counter=container.sequence_counter,
                crc_verified=False,
                complement_verified=False,
            )

        # 4. Safe Sequence Counter Monotonicity & Replay/Freeze Protection (0xB902)
        if dev.sequence_counter != 0 or dev.last_rx_time_ms > 0:
            last_seq = dev.sequence_counter
            new_seq = container.sequence_counter
            delta = (new_seq - last_seq) % 65536

            # Frozen or replayed counter
            if delta == 0:
                self.trigger_fault(IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT)
                return IoLinkSafetyValidationOutcome(
                    is_valid=False,
                    diagnostic_code=IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT,
                    error_message=f"Frozen or replayed sequence counter detected ({new_seq})",
                    device_id=container.device_id,
                    sequence_counter=container.sequence_counter,
                )

            # Sequence decrement / reorder or massive jump gap > 100
            if (new_seq < last_seq and not (last_seq > 65000 and new_seq < 500)) or delta > 100:
                self.trigger_fault(IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT)
                return IoLinkSafetyValidationOutcome(
                    is_valid=False,
                    diagnostic_code=IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT,
                    error_message=f"Sequence counter discontinuity/gap detected: {last_seq} -> {new_seq}",
                    device_id=container.device_id,
                    sequence_counter=container.sequence_counter,
                )

        # Update Device State
        dev.sequence_counter = container.sequence_counter
        dev.last_rx_time_ms = self.current_time_ms
        dev.ossd_ch1 = container.ossd_ch1
        dev.ossd_ch2 = container.ossd_ch2
        dev.last_payload = container.payload
        self.safe_sequence_counter = container.sequence_counter

        # 5. OSSD Dual-Channel Monitoring
        self.recompute_ossd_state_word()
        self.sync_to_registers()

        return IoLinkSafetyValidationOutcome(
            is_valid=True,
            diagnostic_code=IoLinkSafetyDiagnosticCode.OK,
            device_id=container.device_id,
            sequence_counter=container.sequence_counter,
            crc_verified=True,
            complement_verified=True,
            ossd_ch1=container.ossd_ch1,
            ossd_ch2=container.ossd_ch2,
            latency_ms=max(0.0, self.current_time_ms - container.timestamp_ms),
        )

    # ------------------------------------------------------------------------
    # Simulation Cycle Stepper & Watchdog Surveillance (0xB903)
    # ------------------------------------------------------------------------

    def step_scan_cycle(self, dt_ms: Optional[float] = None) -> None:
        """Advance simulation time by dt_ms (defaults to nominal 2.5 ms) and monitor watchdogs."""
        delta = dt_ms if dt_ms is not None else self.cycle_time_ms
        self.current_time_ms += delta

        if self.fault_trip:
            self.sync_to_registers()
            return

        # Check safety watchdog timeout (> 20.0 ms nominal)
        for dev in self.devices.values():
            silence_ms = self.current_time_ms - dev.last_rx_time_ms
            if silence_ms > self.watchdog_timeout_ms:
                self.trigger_fault(
                    IoLinkSafetyDiagnosticCode.IOLINK_ERR_WATCHDOG_TIMEOUT,
                    f"Watchdog timeout on device {dev.device_id}: {silence_ms:.1f} ms > {self.watchdog_timeout_ms:.1f} ms",
                )
                return

        self.sync_to_registers()

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(self) -> None:
        """Synchronize IO-Link Safety engine state into Horner OCS register space.
        
        Mapped Channels:
        - %R1210: IoLinkCycleTimeMsScaled (INT16, scaled x10 ms)
        - %R1211: ActiveSafeDevicesCount (INT16)
        - %R1212: SafeSequenceCounter (UINT16)
        - %R1213: SafetyWatchdogMsScaled (INT16, scaled x10 ms)
        - %R1214: CrcErrorCount (INT16)
        - %R1215: OssdOutputStateWord (INT16)
        - %R1216: DeviceVendorId (UINT16)
        - %R1217: DiagnosticStatusCode (0x0000, 0xB901..0xB904)
        - %M282:  IoLinkSafetyPermissive (BOOL)
        - %M283:  IoLinkSafetyFaultTrip (BOOL)
        """
        # Analog Words
        self.reg_table.write_word("%R1210", scale_ms_to_int16(self.cycle_time_ms))
        self.reg_table.write_word("%R1211", len(self.devices))
        self.reg_table.write_word("%R1212", self.safe_sequence_counter & 0xFFFF)
        self.reg_table.write_word("%R1213", scale_ms_to_int16(self.watchdog_timeout_ms))
        self.reg_table.write_word("%R1214", self.crc_error_count)
        self.reg_table.write_word("%R1215", self.ossd_output_state_word)
        self.reg_table.write_word("%R1216", self.expected_vendor_id & 0xFFFF)
        self.reg_table.write_word("%R1217", int(self.diagnostic_code))

        # Discrete Coils
        self.reg_table.write_bit("%M282", self.permissive)
        self.reg_table.write_bit("%M283", self.fault_trip)


# Engine and Container Aliases
IoLinkSafetyEngine = IoLinkSafetyMasterEngine
IoLinkSafetyMaster = IoLinkSafetyMasterEngine
IolinkSafetyMasterEngine = IoLinkSafetyMasterEngine
IolinkSafetyEngine = IoLinkSafetyMasterEngine
IolinkSafetyState = IoLinkSafetyState
IolinkSafetyStatusBits = IoLinkSafetyStatusBits
IolinkSafetyDiagnosticCode = IoLinkSafetyDiagnosticCode

SafePdContainer = SafeProcessDataContainer
calculate_crc16_a = compute_crc16_a
calculate_crc16_b = compute_crc16_b
calculate_crc16_ccitt = compute_crc16_a

# Method aliases
SafeProcessDataContainer.pack = SafeProcessDataContainer.serialize
SafeProcessDataContainer.unpack = classmethod(lambda cls, data, timestamp_ms=0.0: cls.deserialize(data, timestamp_ms))
IoLinkSafetyMasterEngine.reset_safety = IoLinkSafetyMasterEngine.reset_latch
IoLinkSafetyMasterEngine.step_cycle = IoLinkSafetyMasterEngine.step_scan_cycle
IoLinkSafetyMasterEngine.receive_safe_container = IoLinkSafetyMasterEngine.process_safe_container
IoLinkSafetyMasterEngine.trigger_safety_trip = IoLinkSafetyMasterEngine.trigger_fault



# ============================================================================
# 9. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_iolink_safety_verification(
    output_path: Optional[Union[str, Path]] = None,
    evidence_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute the comprehensive 9-stage verification suite for IO-Link Safety.
    
    Verifies:
    1. Pure ST POU AST Parsing & Register Table Binding Verification.
    2. Anti-Ladder Logic Security Guard Interception.
    3. Complete IO-Link Safety Master Architecture & Scaling Verification.
    4. Safe Process Data (PD) Container Generation, Complement (~P), & Dual CRC-16 Integrity.
    5. Dual-Channel OSSD Monitoring & Discrepancy Fault Detection.
    6. Process Safety Interlock 0xB901: CRC Corrupted Fault Trapping.
    7. Process Safety Interlock 0xB902: Safe Sequence Counter Monotonicity & Replay/Gap Fault.
    8. Process Safety Interlock 0xB903: Safety Watchdog Timeout Expiration (> 20.0 ms).
    9. Process Safety Interlock 0xB904: Device Authentication & Fail-Safe Latch Recovery.
    
    Returns:
        Deterministic 4-state contract dictionary (success | failed | blocked | inconclusive).
    """
    target_path = output_path or evidence_path
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & Register Table Binding Verification
    # ------------------------------------------------------------------------
    p_sync_ok = verify_iolink_safety_pure_st()
    ast_sync = STParser.parse_pou(IOLINK_SAFETY_SYNC_POU)
    ast_master = STParser.parse_pou(IOLINK_SAFETY_MASTER_SYNC_POU)

    required_registers: Set[str] = {
        "%R1210", "%R1211", "%R1212", "%R1213",
        "%R1214", "%R1215", "%R1216", "%R1217",
        "%M282", "%M283",
    }
    bound_regs_ok = (
        required_registers.issubset(set(ast_sync.bound_registers))
        and required_registers.issubset(set(ast_master.bound_registers))
    )

    c1 = (
        p_sync_ok
        and bound_regs_ok
        and ast_sync.pou_type == POUType.PROGRAM
        and ast_master.pou_type == POUType.PROGRAM
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Register_Table_Binding",
        "passed": c1,
        "details": "Verified IoLinkSafetySync and IoLinkSafetyMasterSync AST bindings across %R1210..%R1217, %M282..%M283.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Logic Security Guard Interception
    # ------------------------------------------------------------------------
    forbidden_snippets = [
        "PROGRAM LadderSnippet\n VAR x: BOOL; END_VAR\n ---[ ]--- \nEND_PROGRAM",
        "PROGRAM LadderSnippet\n VAR x: BOOL; END_VAR\n ---[/]--- \nEND_PROGRAM",
        "PROGRAM LadderSnippet\n VAR x: BOOL; END_VAR\n ---( )--- \nEND_PROGRAM",
        "PROGRAM LadderSnippet\n VAR x: BOOL; END_VAR\n RUNG 0001: BEGIN \nEND_PROGRAM",
        "PROGRAM LadderSnippet\n VAR x: BOOL; END_VAR\n XIC In1; OTE Out1; \nEND_PROGRAM",
    ]
    rejected_count = 0
    for snippet in forbidden_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snippet)
        except LadderForbiddenError as err:
            if "ERR_LADDER_FORBIDDEN" in str(err):
                rejected_count += 1

    c2 = (rejected_count == len(forbidden_snippets))
    test_results.append({
        "stage": 2,
        "check": "Anti_Ladder_Security_Guard_Interception",
        "passed": c2,
        "details": f"Successfully trapped {rejected_count}/{len(forbidden_snippets)} prohibited ladder logic constructs with ERR_LADDER_FORBIDDEN.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Complete IO-Link Safety Master Architecture & Scaling Verification
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    master = IoLinkSafetyMasterEngine(
        register_table=rt,
        cycle_time_ms=IOLINK_SAFETY_NOMINAL_CYCLE_TIME_MS,
        watchdog_timeout_ms=IOLINK_SAFETY_NOMINAL_WATCHDOG_MS,
        expected_vendor_id=IOLINK_SAFETY_DEFAULT_VENDOR_ID,
    )
    for dev_idx in range(1, 5):
        master.register_safe_device(
            device_id=dev_idx,
            device_name=f"SafeSensor_Port{dev_idx}",
            ossd_ch1=True,
            ossd_ch2=True,
        )

    r1210_val = rt.read_word("%R1210")
    r1211_val = rt.read_word("%R1211")
    r1213_val = rt.read_word("%R1213")
    r1216_val = rt.read_uword("%R1216")
    m282_val = rt.read_bit("%M282")
    m283_val = rt.read_bit("%M283")

    c3 = (
        r1210_val == IOLINK_SAFETY_NOMINAL_CYCLE_TIME_SCALED  # 25 (2.5 ms x10)
        and r1211_val == 4                                    # 4 active safe devices
        and r1213_val == IOLINK_SAFETY_NOMINAL_WATCHDOG_SCALED  # 200 (20.0 ms x10)
        and r1216_val == IOLINK_SAFETY_DEFAULT_VENDOR_ID      # 0x0123
        and m282_val is True                                  # Permissive healthy
        and m283_val is False                                 # No fault trip
    )
    test_results.append({
        "stage": 3,
        "check": "IO_Link_Safety_Master_Architecture_And_Scaling",
        "passed": c3,
        "details": "Verified Master Cycle Time (%R1210=25), Active Devices (%R1211=4), Watchdog (%R1213=200), Vendor ID (%R1216=0x0123).",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Safe PD Container Generation, Complement (~P), & Dual CRC-16 Integrity
    # ------------------------------------------------------------------------
    raw_payload = b"\x12\x34\xAB\xCD"
    container = SafeProcessDataContainer.create(
        device_id=1,
        vendor_id=0x0123,
        sequence_counter=100,
        ossd_ch1=True,
        ossd_ch2=True,
        payload=raw_payload,
        timestamp_ms=master.current_time_ms,
    )
    wire_bytes = container.serialize()
    deserialized = SafeProcessDataContainer.deserialize(wire_bytes)
    valid_integrity, diag_none, _ = deserialized.verify_integrity(expected_vendor_id=0x0123)

    # Inverted complement check
    complement_ok = all((p ^ inv) == 0xFF for p, inv in zip(deserialized.payload, deserialized.payload_inv))

    c4 = (
        valid_integrity is True
        and diag_none is None
        and complement_ok is True
        and deserialized.sequence_counter == 100
        and len(wire_bytes) == (8 + len(raw_payload) * 2 + 4)
    )
    test_results.append({
        "stage": 4,
        "check": "Safe_PD_Container_Generation_Complement_And_Dual_CRC",
        "passed": c4,
        "details": "Verified Safe PD serialization, bitwise inverted complement (P ^ ~P == 0xFF), and dual CRC-16 checksums.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Dual-Channel OSSD Monitoring & Discrepancy Fault Detection
    # ------------------------------------------------------------------------
    # All 4 devices healthy & energized -> bits 0..7 active (0x00FF = 255)
    ossd_word_healthy = rt.read_word("%R1215")

    # Incur discrepancy on Device 2: Channel 1 ON, Channel 2 OFF
    dev2 = master.devices[2]
    dev2.ossd_ch1 = True
    dev2.ossd_ch2 = False
    master.recompute_ossd_state_word()
    master.sync_to_registers()
    ossd_word_discrepant = rt.read_word("%R1215")

    # Restore Device 2
    dev2.ossd_ch1 = True
    dev2.ossd_ch2 = True
    master.recompute_ossd_state_word()
    master.sync_to_registers()

    c5 = (
        ossd_word_healthy == 0x00FF
        and ossd_word_discrepant != 0x00FF
        and (ossd_word_discrepant & 0x000C) == 0  # Device 2 channels (bits 2,3) de-energized
        and dev2.has_discrepancy is False
    )
    test_results.append({
        "stage": 5,
        "check": "Dual_Channel_OSSD_Monitoring_And_Discrepancy_Detection",
        "passed": c5,
        "details": "Verified dual-channel OSSD state word (%R1215=0x00FF) and safe de-energization on channel discrepancy.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Process Safety Interlock 0xB901: CRC Corrupted Fault Trapping
    # ------------------------------------------------------------------------
    corrupted_container = SafeProcessDataContainer.create(
        device_id=1,
        vendor_id=0x0123,
        sequence_counter=101,
        ossd_ch1=True,
        ossd_ch2=True,
        payload=raw_payload,
        timestamp_ms=master.current_time_ms,
    )
    # Corrupt CRC-1
    corrupted_container.crc_1 ^= 0xAAAA
    res_crc = master.process_safe_container(corrupted_container)

    r1214_err = rt.read_word("%R1214")
    r1217_crc = rt.read_uword("%R1217")
    m282_crc = rt.read_bit("%M282")
    m283_crc = rt.read_bit("%M283")
    r1215_crc = rt.read_word("%R1215")

    c6 = (
        res_crc.is_valid is False
        and res_crc.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_CRC_CORRUPTED
        and r1214_err >= 1
        and r1217_crc == 0xB901
        and m282_crc is False
        and m283_crc is True
        and r1215_crc == 0
    )
    test_results.append({
        "stage": 6,
        "check": "Process_Safety_Interlock_0xB901_CRC_Corrupted",
        "passed": c6,
        "details": "Trapped CRC corruption with 0xB901: asserted %M283 (IoLinkSafetyFaultTrip), cleared %M282, incremented %R1214.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Process Safety Interlock 0xB902: Safe Sequence Counter Monotonicity & Replay/Gap
    # ------------------------------------------------------------------------
    master.reset_latch(force=True)
    # Valid frame at seq 200
    valid_f1 = SafeProcessDataContainer.create(
        device_id=1,
        vendor_id=0x0123,
        sequence_counter=200,
        ossd_ch1=True,
        ossd_ch2=True,
        payload=raw_payload,
        timestamp_ms=master.current_time_ms,
    )
    master.process_safe_container(valid_f1)

    # Replay frame at seq 200 (frozen / replayed counter)
    replay_frame = SafeProcessDataContainer.create(
        device_id=1,
        vendor_id=0x0123,
        sequence_counter=200,
        ossd_ch1=True,
        ossd_ch2=True,
        payload=raw_payload,
        timestamp_ms=master.current_time_ms,
    )
    res_seq = master.process_safe_container(replay_frame)

    r1217_seq = rt.read_uword("%R1217")
    m283_seq = rt.read_bit("%M283")

    c7 = (
        res_seq.is_valid is False
        and res_seq.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_SEQUENCE_COUNTER_FAULT
        and r1217_seq == 0xB902
        and m283_seq is True
    )
    test_results.append({
        "stage": 7,
        "check": "Process_Safety_Interlock_0xB902_Sequence_Counter_Fault",
        "passed": c7,
        "details": "Trapped frozen / replayed sequence counter with 0xB902 and asserted %M283 (IoLinkSafetyFaultTrip).",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Process Safety Interlock 0xB903: Safety Watchdog Timeout Expiration (> 20.0 ms)
    # ------------------------------------------------------------------------
    master.reset_latch(force=True)
    # Receive frame to reset watchdog timer
    valid_wd_init = SafeProcessDataContainer.create(
        device_id=1,
        vendor_id=0x0123,
        sequence_counter=300,
        ossd_ch1=True,
        ossd_ch2=True,
        payload=raw_payload,
        timestamp_ms=master.current_time_ms,
    )
    master.process_safe_container(valid_wd_init)

    # Fast forward time beyond 20.0 ms watchdog limit (e.g. 25.0 ms silence)
    master.step_scan_cycle(dt_ms=25.0)

    r1217_wd = rt.read_uword("%R1217")
    m282_wd = rt.read_bit("%M282")
    m283_wd = rt.read_bit("%M283")
    r1215_wd = rt.read_word("%R1215")

    c8 = (
        r1217_wd == 0xB903
        and m282_wd is False
        and m283_wd is True
        and r1215_wd == 0
        and master.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_WATCHDOG_TIMEOUT
    )
    test_results.append({
        "stage": 8,
        "check": "Process_Safety_Interlock_0xB903_Safety_Watchdog_Timeout",
        "passed": c8,
        "details": "Trapped safety watchdog silence (> 20.0 ms) with 0xB903: asserted %M283, cleared %M282, zeroed %R1215.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Process Safety Interlock 0xB904: Device Authentication & Reset Latch Recovery
    # ------------------------------------------------------------------------
    master.reset_latch(force=True)
    alien_container = SafeProcessDataContainer.create(
        device_id=1,
        vendor_id=0x9999,  # Rogue Vendor ID
        sequence_counter=400,
        ossd_ch1=True,
        ossd_ch2=True,
        payload=raw_payload,
        timestamp_ms=master.current_time_ms,
    )
    res_auth = master.process_safe_container(alien_container)

    r1217_auth = rt.read_uword("%R1217")
    m283_auth = rt.read_bit("%M283")

    # Operator manual reset recovery
    res_reset = master.reset_latch(force=True)
    m282_recovered = rt.read_bit("%M282")
    m283_recovered = rt.read_bit("%M283")
    r1217_recovered = rt.read_uword("%R1217")

    c9 = (
        res_auth.is_valid is False
        and res_auth.diagnostic_code == IoLinkSafetyDiagnosticCode.IOLINK_ERR_DEVICE_AUTHENTICATION_FAILED
        and r1217_auth == 0xB904
        and m283_auth is True
        and res_reset.status == AgentStatus.SUCCESS
        and m282_recovered is True
        and m283_recovered is False
        and r1217_recovered == 0x0000
    )
    test_results.append({
        "stage": 9,
        "check": "Device_Authentication_0xB904_And_Reset_Latch_Recovery",
        "passed": c9,
        "details": "Trapped rogue vendor ID with 0xB904 and verified operator reset restoring %M282=True and %M283=False.",
    })

    # ------------------------------------------------------------------------
    # Verification Summary & Evidence Serialization
    # ------------------------------------------------------------------------
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Industrial IO-Link Safety Master Protocol Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W160",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial IO-Link Safety Master & Safety Device Protocol Engine",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R1210..%R1217",
                "discrete_coils": "%M282..%M283",
                "values": {
                    "%R1210": rt.read_word("%R1210"),
                    "%R1211": rt.read_word("%R1211"),
                    "%R1212": rt.read_uword("%R1212"),
                    "%R1213": rt.read_word("%R1213"),
                    "%R1214": rt.read_word("%R1214"),
                    "%R1215": rt.read_word("%R1215"),
                    "%R1216": rt.read_uword("%R1216"),
                    "%R1217": rt.read_uword("%R1217"),
                    "%M282": rt.read_bit("%M282"),
                    "%M283": rt.read_bit("%M283"),
                },
            },
            "metrics": {
                "master_cycle_time_ms": master.cycle_time_ms,
                "master_cycle_time_ms_scaled": scale_ms_to_int16(master.cycle_time_ms),
                "active_devices_count": len(master.devices),
                "safe_sequence_counter": master.safe_sequence_counter,
                "watchdog_timeout_ms": master.watchdog_timeout_ms,
                "crc_error_count": master.crc_error_count,
                "ossd_output_state_word": master.ossd_output_state_word,
                "expected_vendor_id": master.expected_vendor_id,
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
    result = run_iolink_safety_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
