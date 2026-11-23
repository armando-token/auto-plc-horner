"""Industrial ODVA CIP Safety Over 5G URLLC (Ultra-Reliable Low-Latency Communication) Protocol Engine.

Work Package: W256 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- 3GPP Release 16 / Release 17 5G System (5GS) & URLLC:
  - 3GPP TS 23.501 / TS 38.300: 5G Non-Public Networks (NPN / SNPN / PNI-NPN)
  - 5G QoS Flow Identifier (QFI) & Standardized 5QI:
    - 5QI 82: Delay Critical GBR (Guaranteed Bit Rate)
    - Packet Delay Budget (PDB): 10 ms (10,000 us)
    - Packet Error Rate (PER): 10^-4 / 10^-5 (nominal 1 ppm loss)
  - Radio Quality Metrics:
    - RSRP (Reference Signal Received Power): -140 to -40 dBm (nominal -75 dBm; trips 0xEE21 if < -110 dBm)
    - SINR (Signal-to-Interference-plus-Noise Ratio): -10 to 30 dB (nominal 18 dB; trips 0xEE22 if < 0 dB)
    - Air-Interface URLLC Latency: 100 to 20,000 us (nominal 950 us; trips 0xEE23 if > 10,000 us)
    - Packet Loss Rate: 0 to 10,000 ppm (nominal 1 ppm; trips 0xEE23 if > 1,000 ppm)
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - Class 0x39: Safety Supervisor Object
  - Class 0x3A: Safety Validator Object
  - Class 0x3B: Safety Connection Object
  - Class 0x2F: CIP Safety 5G URLLC Extension Class ID
- Safe 5G State Machine:
  - 0: IDLE
  - 1: ATTACHING_NPN
  - 2: URLLC_SESSION_ESTABLISHED
  - 3: AUTHENTICATED_OPERATIONAL
  - 4: URLLC_TIMEOUT_SAFE_STOP
- Dual-Channel Diversified Safety Frame Transmission:
  - Diversified Sequence Counters (Primary seq_1 0..65535 rolling, Secondary seq_2 = ~seq_1 & 0xFFFF)
  - Dual 16-bit Safety CRCs:
    - CRC-S1: Generator polynomial 0x5935 (init 0xFFFF)
    - CRC-S2: Generator polynomial 0x755B (init 0xFFFF)
  - Electronic Product ID (EPID) 32-bit CRC32 Hash & Authentication
- 5G URLLC Latency Watchdog:
  - Watchdog silence timeout threshold: 10.0 ms (10,000 us) nominal
- Horner OCS Memory Space:
  - Analog registers %R2170..%R2177:
    - %R2170: REG_5G_SAFETY_LINK_STATE (0=IDLE, 1=ATTACHING_NPN, 2=URLLC_SESSION, 3=AUTH_OPERATIONAL, 4=SAFE_STOP)
    - %R2171: REG_5G_RSRP_DBM (INT16, -140..-40 dBm, nominal -75 dBm)
    - %R2172: REG_5G_SINR_DB (INT16, -10..30 dB, nominal 18 dB)
    - %R2173: REG_URLLC_LATENCY_US (INT16, 100..20000 us, nominal 950 us)
    - %R2174: REG_URLLC_PACKET_LOSS_RATE_PPM (UINT16/INT16, 0..10000 ppm, nominal 1 ppm)
    - %R2175: REG_5G_QOS_FLOW_ID (UINT16/INT16, nominal 82)
    - %R2176: REG_5G_HANDOVER_COUNT (UINT16, cumulative 5G handovers, nominal 0)
    - %R2177: REG_5G_SAFETY_DIAGNOSTIC_CODE (UINT16, 0x0000 OK, 0xEE21..0xEE24)
  - Discrete coils %M506..%M507:
    - %M506: COIL_5G_SAFETY_LINK_HEALTHY (BOOL, True nominally when authenticated & healthy)
    - %M507: COIL_5G_SAFETY_STOP_TRIPPED (BOOL, False nominally, True on safety trip or URLLC timeout)
- Implements ILogicUnit interface with scan_step(dt, context), step(dt, context), execute(context), and reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafety5GUrllcSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.
- Deterministic 10-stage verification suite run_cip_safety_5g_urllc_verification().
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
import zlib

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (ODVA CIP Safety Volume 5 / 3GPP 5G URLLC)
# ============================================================================

CIP_SAFETY_SUPERVISOR_CLASS_ID: int = 0x39          # Safety Supervisor Object
CIP_SAFETY_VALIDATOR_CLASS_ID: int = 0x3A           # Safety Validator Object
CIP_SAFETY_CONNECTION_CLASS_ID: int = 0x3B          # Safety Connection Object
CIP_SAFETY_5G_URLLC_CLASS_ID: int = 0x2F            # CIP Safety 5G URLLC Extension Class ID
CIP_SAFETY_URLLC_CLASS_ID: int = 0x2F

# 5G URLLC Radio & QoS Metrics Defaults
NOMINAL_5G_RSRP_DBM: int = -75                      # Nominal 5G RSRP (-75 dBm)
DEFAULT_RSRP_DBM: int = -75
MIN_RSRP_DBM: int = -140
MAX_RSRP_DBM: int = -40
DEFAULT_RSRP_TRIP_THRESHOLD_DBM: int = -110         # Trip 0xEE21 if RSRP < -110 dBm

NOMINAL_5G_SINR_DB: int = 18                        # Nominal 5G SINR (18 dB)
DEFAULT_SINR_DB: int = 18
MIN_SINR_DB: int = -10
MAX_SINR_DB: int = 30
DEFAULT_SINR_TRIP_THRESHOLD_DB: int = 0             # Trip 0xEE22 if SINR < 0 dB

NOMINAL_URLLC_LATENCY_US: int = 950                 # Nominal URLLC air latency (950 us = 0.95 ms)
NOMINAL_5G_LATENCY_US: int = 950
DEFAULT_LATENCY_US: int = 950
MIN_LATENCY_US: int = 100
MAX_LATENCY_US: int = 20000
DEFAULT_LATENCY_TRIP_THRESHOLD_US: int = 10000      # Trip 0xEE23 if latency > 10,000 us (10 ms)

NOMINAL_URLLC_PACKET_LOSS_RATE_PPM: int = 1         # Nominal packet loss (1 ppm = 0.0001% = 99.9999% reliability)
DEFAULT_PACKET_LOSS_RATE_PPM: int = 1
MIN_PACKET_LOSS_RATE_PPM: int = 0
MAX_PACKET_LOSS_RATE_PPM: int = 10000               # 10,000 ppm = 1%
DEFAULT_PACKET_LOSS_TRIP_THRESHOLD_PPM: int = 1000  # Trip 0xEE23 if packet loss > 1000 ppm (0.1%)

NOMINAL_5G_QOS_FLOW_ID: int = 82                    # 3GPP 5QI 82 (Delay Critical GBR, PDB 10ms)
DEFAULT_QOS_FLOW_ID: int = 82
DEFAULT_5QI: int = 82
DEFAULT_5QI_FLOW_ID: int = 82
DEFAULT_FIVE_QI: int = 82

NOMINAL_5G_HANDOVER_COUNT: int = 0
DEFAULT_HANDOVER_COUNT: int = 0
DEFAULT_RADIO_BEAM_ID: int = 1
DEFAULT_BEAM_ID: int = 1

NOMINAL_5G_WATCHDOG_MS: float = 10.0                # 5G URLLC Watchdog timeout: 10.0 ms
NOMINAL_URLLC_WATCHDOG_MS: float = 10.0
DEFAULT_WATCHDOG_TIMEOUT_MS: float = 10.0

DEFAULT_SAFETY_EPID: str = "HORNER-OCS-5G-URLLC-SIL3"
DEFAULT_EPID: str = DEFAULT_SAFETY_EPID

# CRC Polynomials and Seeds (ODVA CIP Safety Volume 5)
CIP_SAFETY_CRC_S1_POLY: int = 0x5935                # CRC-S1 generator polynomial
CIP_SAFETY_CRC_S2_POLY: int = 0x755B                # CRC-S2 generator polynomial
CRC_S1_POLY: int = 0x5935
CRC_S2_POLY: int = 0x755B
CIP_SAFETY_CRC_INIT: int = 0xFFFF                   # CRC-S initial seed
CRC_S_INIT: int = 0xFFFF
CRC16_CCITT_POLY: int = 0x1021                      # ODVA CCITT-16 CRC (compatibility)
CRC16_CCITT_INIT: int = 0xFFFF

# Canonical Register Table Mapping (%R2170..%R2177)
REG_5G_SAFETY_LINK_STATE: str = "%R2170"            # Safe 5G State Machine (0..4)
REG_5G_RSRP_DBM: str = "%R2171"                     # 5G RSRP dBm (-140..-40 dBm, nominal -75 dBm)
REG_5G_SINR_DB: str = "%R2172"                      # 5G SINR dB (-10..30 dB, nominal 18 dB)
REG_URLLC_LATENCY_US: str = "%R2173"                # URLLC latency in microseconds (100..20000 us, nominal 950 us)
REG_URLLC_PACKET_LOSS_RATE_PPM: str = "%R2174"      # URLLC packet loss rate PPM (0..10000 ppm, nominal 1 ppm)
REG_5G_QOS_FLOW_ID: str = "%R2175"                  # 5G QoS Flow Identifier / 5QI (nominal 82)
REG_5G_HANDOVER_COUNT: str = "%R2176"               # Cumulative 5G handover count (nominal 0)
REG_5G_SAFETY_DIAGNOSTIC_CODE: str = "%R2177"       # Safety Diagnostic Code (0x0000, 0xEE21..0xEE24)

# Canonical Discrete Coils Mapping (%M506..%M507)
COIL_5G_SAFETY_LINK_HEALTHY: str = "%M506"          # BOOL: True when 5G safety link is healthy & authenticated
COIL_5G_SAFETY_STOP_TRIPPED: str = "%M507"          # BOOL: True on safety stop trip or URLLC timeout

# Register & Coil Aliases
REG_URLLC_SAFETY_STATE: str = "%R2170"
REG_5G_SAFETY_STATE: str = "%R2170"
REG_5G_STATE: str = "%R2170"
REG_SAFETY_LINK_STATE: str = "%R2170"
REG_SAFETY_STATE: str = "%R2170"

REG_URLLC_RSRP_DBM: str = "%R2171"
REG_RSRP_DBM: str = "%R2171"
REG_5G_RSRP: str = "%R2171"

REG_URLLC_SINR_DB: str = "%R2172"
REG_SINR_DB: str = "%R2172"
REG_5G_SINR: str = "%R2172"

REG_5G_LATENCY_US: str = "%R2173"
REG_LATENCY_US: str = "%R2173"

REG_PACKET_LOSS_RATE_PPM: str = "%R2174"
REG_PACKET_LOSS_PPM: str = "%R2174"
REG_5G_PACKET_LOSS_PPM: str = "%R2174"
REG_URLLC_FIVE_QI_FLOW_ID: str = "%R2175"
REG_5G_5QI_FLOW_ID: str = "%R2175"

REG_QOS_FLOW_ID: str = "%R2175"
REG_5G_QFI: str = "%R2175"
REG_5QI: str = "%R2175"
REG_5QI_FLOW_ID: str = "%R2175"
REG_FIVE_QI_FLOW_ID: str = "%R2175"
REG_URLLC_RADIO_BEAM_ID: str = "%R2175"
REG_5G_RADIO_BEAM_ID: str = "%R2175"
REG_RADIO_BEAM_ID: str = "%R2175"
REG_BEAM_ID: str = "%R2175"

REG_HANDOVER_COUNT: str = "%R2176"
REG_5G_HANDOVERS: str = "%R2176"
REG_SAFETY_TRANSMIT_SEQUENCE: str = "%R2176"
REG_TRANSMIT_SEQUENCE: str = "%R2176"
REG_SAFETY_SEQUENCE: str = "%R2176"

REG_5G_DIAGNOSTIC_CODE: str = "%R2177"
REG_SAFETY_DIAGNOSTIC_CODE: str = "%R2177"
REG_DIAGNOSTIC_STATUS_CODE: str = "%R2177"
REG_DIAGNOSTIC_CODE: str = "%R2177"
REG_5G_DIAGNOSTIC_STATUS_CODE: str = "%R2177"
REG_URLLC_DIAGNOSTIC_STATUS_CODE: str = "%R2177"

COIL_SAFETY_LINK_HEALTHY: str = "%M506"
COIL_5G_LINK_HEALTHY: str = "%M506"
COIL_LINK_HEALTHY: str = "%M506"
COIL_URLLC_SAFETY_LINK_HEALTHY: str = "%M506"

COIL_SAFETY_STOP_TRIPPED: str = "%M507"
COIL_SAFE_STOP_TRIPPED: str = "%M507"
COIL_5G_STOP_TRIPPED: str = "%M507"
COIL_URLLC_SAFETY_STOP_TRIPPED: str = "%M507"


# ============================================================================
# 2. Diagnostic Codes & Enums
# ============================================================================

class DiagnosticCode(int):
    """Integer subclass for 16-bit diagnostic codes supporting signed/unsigned equality, masking (& 0xFFFF), and formatted representation.

    Diagnostic Codes:
    - 0x0000: OK (5G URLLC Safety Link operational and healthy)
    - 0xEE21: RSRP_DROP_TRIP (5G RSRP signal dropped below threshold -110 dBm)
    - 0xEE22: SINR_NOISE_TRIP (5G SINR dropped below noise threshold 0 dB)
    - 0xEE23: LATENCY_OVERRUN_TRIP (URLLC latency exceeded 10,000 us or watchdog timeout)
    - 0xEE24: AUTH_FAIL_TRIP (EPID authentication mismatch, sequence fault, or CRC corruption)
    """

    OK: DiagnosticCode
    RSRP_DROP_TRIP: DiagnosticCode
    SINR_NOISE_TRIP: DiagnosticCode
    LATENCY_OVERRUN_TRIP: DiagnosticCode
    AUTH_FAIL_TRIP: DiagnosticCode

    # Aliases
    SAFETY_OK: DiagnosticCode
    LINK_OK: DiagnosticCode
    URLLC_SAFETY_OK: DiagnosticCode
    RSRP_DROP: DiagnosticCode
    RSRP_LOW_TRIP: DiagnosticCode
    ERR_RSRP_DROP: DiagnosticCode
    SINR_NOISE: DiagnosticCode
    SINR_LOW_TRIP: DiagnosticCode
    ERR_SINR_NOISE: DiagnosticCode
    SINR_INTERFERENCE_TRIP: DiagnosticCode
    SINR_INTERFERENCE: DiagnosticCode
    ERR_SINR_INTERFERENCE: DiagnosticCode
    LATENCY_OVERRUN: DiagnosticCode
    LATENCY_EXCEEDED_TRIP: DiagnosticCode
    URLLC_TIMEOUT_TRIP: DiagnosticCode
    WATCHDOG_TIMEOUT: DiagnosticCode
    WATCHDOG_COMM_TIMEOUT: DiagnosticCode
    ERR_LATENCY_OVERRUN: DiagnosticCode
    AUTH_FAIL: DiagnosticCode
    AUTHENTICATION_FAILURE: DiagnosticCode
    EPID_MISMATCH_TRIP: DiagnosticCode
    FLOW_ID_MISMATCH_TRIP: DiagnosticCode
    CRC_FAULT: DiagnosticCode
    CRC_S_CHECKSUM_FAULT: DiagnosticCode
    ERR_AUTH_FAIL: DiagnosticCode

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
DiagnosticCode.RSRP_DROP_TRIP = DiagnosticCode(0xEE21, "RSRP_DROP_TRIP")
DiagnosticCode.SINR_NOISE_TRIP = DiagnosticCode(0xEE22, "SINR_NOISE_TRIP")
DiagnosticCode.LATENCY_OVERRUN_TRIP = DiagnosticCode(0xEE23, "LATENCY_OVERRUN_TRIP")
DiagnosticCode.AUTH_FAIL_TRIP = DiagnosticCode(0xEE24, "AUTH_FAIL_TRIP")

# Aliases
DiagnosticCode.SAFETY_OK = DiagnosticCode.OK
DiagnosticCode.LINK_OK = DiagnosticCode.OK
DiagnosticCode.URLLC_SAFETY_OK = DiagnosticCode.OK
DiagnosticCode.RSRP_DROP = DiagnosticCode.RSRP_DROP_TRIP
DiagnosticCode.RSRP_LOW_TRIP = DiagnosticCode.RSRP_DROP_TRIP
DiagnosticCode.ERR_RSRP_DROP = DiagnosticCode.RSRP_DROP_TRIP
DiagnosticCode.SINR_NOISE = DiagnosticCode.SINR_NOISE_TRIP
DiagnosticCode.SINR_LOW_TRIP = DiagnosticCode.SINR_NOISE_TRIP
DiagnosticCode.ERR_SINR_NOISE = DiagnosticCode.SINR_NOISE_TRIP
DiagnosticCode.SINR_INTERFERENCE_TRIP = DiagnosticCode.SINR_NOISE_TRIP
DiagnosticCode.SINR_INTERFERENCE = DiagnosticCode.SINR_NOISE_TRIP
DiagnosticCode.ERR_SINR_INTERFERENCE = DiagnosticCode.SINR_NOISE_TRIP
DiagnosticCode.LATENCY_OVERRUN = DiagnosticCode.LATENCY_OVERRUN_TRIP
DiagnosticCode.LATENCY_EXCEEDED_TRIP = DiagnosticCode.LATENCY_OVERRUN_TRIP
DiagnosticCode.URLLC_TIMEOUT_TRIP = DiagnosticCode.LATENCY_OVERRUN_TRIP
DiagnosticCode.WATCHDOG_TIMEOUT = DiagnosticCode.LATENCY_OVERRUN_TRIP
DiagnosticCode.WATCHDOG_COMM_TIMEOUT = DiagnosticCode.LATENCY_OVERRUN_TRIP
DiagnosticCode.ERR_LATENCY_OVERRUN = DiagnosticCode.LATENCY_OVERRUN_TRIP
DiagnosticCode.AUTH_FAIL = DiagnosticCode.AUTH_FAIL_TRIP
DiagnosticCode.AUTHENTICATION_FAILURE = DiagnosticCode.AUTH_FAIL_TRIP
DiagnosticCode.EPID_MISMATCH_TRIP = DiagnosticCode.AUTH_FAIL_TRIP
DiagnosticCode.FLOW_ID_MISMATCH_TRIP = DiagnosticCode.AUTH_FAIL_TRIP
DiagnosticCode.CRC_FAULT = DiagnosticCode.AUTH_FAIL_TRIP
DiagnosticCode.CRC_S_CHECKSUM_FAULT = DiagnosticCode.AUTH_FAIL_TRIP
DiagnosticCode.ERR_AUTH_FAIL = DiagnosticCode.AUTH_FAIL_TRIP

# Module-Level Diagnostic Code Exports
DIAG_OK = DiagnosticCode.OK
DIAG_RSRP_DROP_TRIP = DiagnosticCode.RSRP_DROP_TRIP
DIAG_SINR_NOISE_TRIP = DiagnosticCode.SINR_NOISE_TRIP
DIAG_LATENCY_OVERRUN_TRIP = DiagnosticCode.LATENCY_OVERRUN_TRIP
DIAG_AUTH_FAIL_TRIP = DiagnosticCode.AUTH_FAIL_TRIP

DiagnosticStatusCode = DiagnosticCode
CIP5GDiagnosticCode = DiagnosticCode
Cip5GDiagnosticCode = DiagnosticCode
FiveGDiagnosticCode = DiagnosticCode
URLLCDiagnosticCode = DiagnosticCode
CipSafety5gUrllcDiagnosticCode = DiagnosticCode


class Safe5GState(IntEnum):
    """Safe 5G State Machine mapped to %R2170."""
    IDLE = 0                        # Radio modem idle, disconnected from 5G NPN
    ATTACHING_NPN = 1               # Attaching to 5G Non-Public Network (gNodeB / 5GC)
    URLLC_SESSION_ESTABLISHED = 2   # 5G QoS Flow (5QI 82) established & active
    AUTHENTICATED_OPERATIONAL = 3   # CIP Safety session authenticated and operational
    URLLC_TIMEOUT_SAFE_STOP = 4     # Safe stop tripped due to timeout, latency, RF drop, or auth fault

    # Aliases
    Idle = 0
    AttachingNpn = 1
    UrllcSessionEstablished = 2
    AuthenticatedOperational = 3
    UrllcTimeoutSafeStop = 4

    # Backwards-compatible aliases with URLLCSafetyState
    DISCONNECTED = 0
    Disconnected = 0
    SEARCHING = 1
    Searching = 1
    ATTACHING = 1
    Attaching = 1
    PDU_SESSION_ESTABLISHED = 2
    PduSessionEstablished = 2
    Pairing = 2
    OPERATIONAL = 3
    SafeStop = 4
    SAFE_STOP = 4
    TRIPPED = 4


Cip5GSafetyState = Safe5GState
CIP5GSafetyState = Safe5GState
Safe5GLinkState = Safe5GState
FiveGSafetyState = Safe5GState
URLLCSafetyState = Safe5GState
CipSafety5gUrllcState = Safe5GState
SafeURLLCState = Safe5GState
URLLCState = Safe5GState


# ============================================================================
# 3. Exceptions
# ============================================================================

class CIP5GSafetyError(Exception):
    """Base exception for all CIP Safety Over 5G URLLC errors."""
    pass


CIP5GURLLCSafetyError = CIP5GSafetyError


class CIP5GRsrpDropError(CIP5GSafetyError):
    """Raised when 5G RSRP drops below safety threshold (0xEE21)."""
    pass


URLLCRsrpDropError = CIP5GRsrpDropError


class CIP5GSinrNoiseError(CIP5GSafetyError):
    """Raised when 5G SINR drops below noise floor threshold (0xEE22)."""
    pass


URLLCSinrInterferenceError = CIP5GSinrNoiseError


class CIP5GLatencyOverrunError(CIP5GSafetyError):
    """Raised when URLLC air latency exceeds safety threshold (0xEE23)."""
    pass


URLLCLatencyOverrunError = CIP5GLatencyOverrunError


class CIP5GAuthenticationError(CIP5GSafetyError):
    """Raised when EPID authentication, sequence diversion, or CRC fails (0xEE24)."""
    pass


URLLCAuthenticationError = CIP5GAuthenticationError


class CIP5GWatchdogTimeoutError(CIP5GSafetyError):
    """Raised when 5G silence exceeds watchdog timeout (0xEE23)."""
    pass


URLLCWatchdogTimeoutError = CIP5GWatchdogTimeoutError


class CIP5GCrcFaultError(CIP5GSafetyError):
    """Raised when CRC-S1 or CRC-S2 frame integrity verification fails (0xEE24)."""
    pass


URLLCCrcFaultError = CIP5GCrcFaultError


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POU Definition
# ============================================================================

CIP_SAFETY_5G_URLLC_PURE_ST_POU: str = """PROGRAM CipSafety5GUrllcSync
VAR
    (* Horner OCS Mapped Registers (W256 - ODVA CIP Safety Over 5G URLLC) *)
    SafetyLinkState              AT %R2170 : INT;    (* 0=IDLE, 1=ATTACHING_NPN, 2=URLLC_SESSION, 3=AUTH_OPERATIONAL, 4=SAFE_STOP *)
    RsrpDbm                      AT %R2171 : INT;    (* RSRP in dBm (-140..-40 dBm, nominal -75 dBm) *)
    SinrDb                       AT %R2172 : INT;    (* SINR in dB (-10..30 dB, nominal 18 dB) *)
    UrllcLatencyUs               AT %R2173 : INT;    (* URLLC latency in microseconds (100..20000 us, nominal 950 us) *)
    UrllcPacketLossRatePpm       AT %R2174 : INT;    (* Packet loss rate PPM (0..10000 ppm, nominal 1 ppm) *)
    QosFlowId                    AT %R2175 : INT;    (* 5G QoS Flow Identifier / 5QI (nominal 82) *)
    HandoverCount                AT %R2176 : INT;    (* Cumulative 5G handover count *)
    SafetyDiagnosticCode         AT %R2177 : UINT;   (* Diagnostic code: 0x0000 OK, 0xEE21..0xEE24 *)

    (* Discrete Safety Coils *)
    SafetyLinkHealthy            AT %M506  : BOOL;   (* TRUE when 5G URLLC safety link is healthy & operational *)
    SafetyStopTripped            AT %M507  : BOOL;   (* TRUE on safety stop trip or link timeout *)

    (* Internal Diagnostic Logic *)
    InternalLinkHealthy          : BOOL;
END_VAR

IF SafetyStopTripped OR (SafetyDiagnosticCode <> 0) THEN
    SafetyLinkHealthy := FALSE;
    SafetyStopTripped := TRUE;
    InternalLinkHealthy := FALSE;
ELSIF (SafetyLinkState = 3) AND (RsrpDbm >= -110) AND (SinrDb >= 0) AND (UrllcLatencyUs <= 10000) AND (UrllcPacketLossRatePpm <= 1000) THEN
    SafetyLinkHealthy := TRUE;
    SafetyStopTripped := FALSE;
    InternalLinkHealthy := TRUE;
ELSE
    SafetyLinkHealthy := FALSE;
    SafetyStopTripped := TRUE;
    InternalLinkHealthy := FALSE;
END_IF;
END_PROGRAM
"""

CIP_SAFETY_5G_URLLC_SYNC_POU: str = CIP_SAFETY_5G_URLLC_PURE_ST_POU
CIP_SAFETY_5G_URLLC_POU: str = CIP_SAFETY_5G_URLLC_PURE_ST_POU
CIP_SAFETY_5G_POU: str = CIP_SAFETY_5G_URLLC_PURE_ST_POU
PURE_ST_POU: str = CIP_SAFETY_5G_URLLC_PURE_ST_POU
CipSafety5GUrllcSync: str = CIP_SAFETY_5G_URLLC_PURE_ST_POU
CipSafety5gUrllcSync: str = CIP_SAFETY_5G_URLLC_PURE_ST_POU
CipSafety5GUrllcSyncPOU: str = CIP_SAFETY_5G_URLLC_PURE_ST_POU


def verify_cip_safety_5g_urllc_pure_st(pou_text: Optional[str] = None) -> bool:
    """Validate pure IEC 61131-3 ST POU with SecurityGuard and STParser."""
    try:
        text = pou_text if pou_text is not None else CIP_SAFETY_5G_URLLC_PURE_ST_POU
        SecurityGuard.assert_pure_st_content(text)
        res = STParser.validate_code(text)
        if res.status != AgentStatus.SUCCESS:
            return False
        ast = STParser.parse_pou(text)
        if ast.pou_type != POUType.PROGRAM:
            return False

        required_registers: Set[str] = {
            "%R2170", "%R2171", "%R2172", "%R2173",
            "%R2174", "%R2175", "%R2176", "%R2177",
            "%M506", "%M507",
        }
        return required_registers.issubset(set(ast.bound_registers))
    except Exception:
        return False


# ============================================================================
# 5. Checksum, EPID Hashing & Helper Functions
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


def compute_epid_hash(epid: Union[str, bytes, int]) -> int:
    """Compute 32-bit CRC32 hash of Electronic Product ID (EPID) or 5QI Flow ID."""
    if isinstance(epid, int):
        data = str(epid).encode("utf-8")
    elif isinstance(epid, str):
        data = epid.encode("utf-8")
    else:
        data = bytes(epid)
    return zlib.crc32(data) & 0xFFFFFFFF


compute_flow_id_hash = compute_epid_hash


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
# 6. Safety Frame Packet Structure & Dual CRC Verification
# ============================================================================

@dataclass
class CIP5GSafetyURLLCPacket:
    """ODVA CIP Safety Over 5G URLLC Frame Packet Container.

    Encapsulates dual-channel diversified safety sequence, EPID authentication hash,
    5G URLLC radio telemetry metrics (RSRP, SINR, latency_us, packet_loss_ppm, QoS Flow ID),
    and dual CRC-S checksums (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B).
    """
    epid: str = DEFAULT_SAFETY_EPID
    epid_hash: int = 0
    sequence_primary: int = 1
    sequence_diversified: int = 0  # (~sequence_primary) & 0xFFFF
    rsrp_dbm: int = NOMINAL_5G_RSRP_DBM
    sinr_db: int = NOMINAL_5G_SINR_DB
    latency_us: int = NOMINAL_URLLC_LATENCY_US
    packet_loss_ppm: int = NOMINAL_URLLC_PACKET_LOSS_RATE_PPM
    qos_flow_id: int = NOMINAL_5G_QOS_FLOW_ID
    handover_count: int = NOMINAL_5G_HANDOVER_COUNT
    payload: bytes = b"\x01\x00\x00\x00"
    crc_s1: int = 0
    crc_s2: int = 0
    timestamp_us: float = 0.0

    # Backwards-compatible kwargs support
    five_qi: Optional[int] = None
    flow_id: Optional[int] = None
    beam_id: Optional[int] = None

    def __post_init__(self) -> None:
        if self.five_qi is not None:
            self.qos_flow_id = self.five_qi
        elif self.flow_id is not None:
            self.qos_flow_id = self.flow_id

        if self.beam_id is not None:
            self.handover_count = self.beam_id

        if self.epid_hash == 0:
            self.epid_hash = compute_epid_hash(self.epid)
        if self.sequence_diversified == 0:
            self.sequence_diversified = (~self.sequence_primary) & 0xFFFF

    def serialize_for_crc_s1(self) -> bytes:
        """Serialize primary header, sequence, and payload for CRC-S1 (poly 0x5935)."""
        header = struct.pack(
            ">IHhhHHHHB",
            self.epid_hash & 0xFFFFFFFF,
            self.sequence_primary & 0xFFFF,
            self.rsrp_dbm,
            self.sinr_db,
            min(65535, max(0, self.latency_us)),
            min(65535, max(0, self.packet_loss_ppm)),
            self.qos_flow_id & 0xFFFF,
            self.handover_count & 0xFFFF,
            len(self.payload) & 0xFF,
        )
        return header + self.payload

    def serialize_for_crc_s2(self) -> bytes:
        """Serialize diversified header, inverted sequence, and inverted payload for CRC-S2 (poly 0x755B)."""
        header = struct.pack(
            ">IHhhHHHHB",
            (self.epid_hash ^ 0xFFFFFFFF) & 0xFFFFFFFF,
            self.sequence_diversified & 0xFFFF,
            self.rsrp_dbm,
            self.sinr_db,
            min(65535, max(0, self.latency_us)),
            min(65535, max(0, self.packet_loss_ppm)),
            self.qos_flow_id & 0xFFFF,
            self.handover_count & 0xFFFF,
            len(self.payload) & 0xFF,
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


CIP5GSafetyPacket = CIP5GSafetyURLLCPacket
CIP5GURLLCSafetyPacket = CIP5GSafetyURLLCPacket
CipSafety5GUrllcPacket = CIP5GSafetyURLLCPacket


def create_valid_5g_safety_packet(
    sequence_primary: int = 1,
    epid: str = DEFAULT_SAFETY_EPID,
    rsrp_dbm: int = NOMINAL_5G_RSRP_DBM,
    sinr_db: int = NOMINAL_5G_SINR_DB,
    latency_us: int = NOMINAL_URLLC_LATENCY_US,
    packet_loss_ppm: int = NOMINAL_URLLC_PACKET_LOSS_RATE_PPM,
    qos_flow_id: int = NOMINAL_5G_QOS_FLOW_ID,
    handover_count: int = NOMINAL_5G_HANDOVER_COUNT,
    payload: bytes = b"\x01\x00\x00\x00",
    **kwargs: Any,
) -> CIP5GSafetyURLLCPacket:
    """Factory creating valid CIP Safety Over 5G URLLC packet with pre-calculated CRCs."""
    pkt = CIP5GSafetyURLLCPacket(
        epid=epid,
        sequence_primary=sequence_primary,
        rsrp_dbm=rsrp_dbm,
        sinr_db=sinr_db,
        latency_us=latency_us,
        packet_loss_ppm=packet_loss_ppm,
        qos_flow_id=qos_flow_id,
        handover_count=handover_count,
        payload=payload,
        **kwargs,
    )
    pkt.calculate_crcs()
    return pkt


create_valid_5g_urllc_packet = create_valid_5g_safety_packet


# ============================================================================
# 7. Main Protocol Engine (ILogicUnit)
# ============================================================================

class CIP5GSafetyURLLCEngine(ILogicUnit):
    """Industrial ODVA CIP Safety Over 5G URLLC Protocol Engine.

    Governs the safe 5G state machine (IDLE, ATTACHING_NPN, URLLC_SESSION_ESTABLISHED,
    AUTHENTICATED_OPERATIONAL, URLLC_TIMEOUT_SAFE_STOP), diversified sequence verification,
    dual CRC-S1/S2 checking, 5G radio metrics surveillance (RSRP, SINR, latency, loss),
    and Horner OCS memory bindings: %R2170..%R2177 and %M506..%M507.
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        auto_activate: bool = True,
        watchdog_timeout_ms: float = DEFAULT_WATCHDOG_TIMEOUT_MS,
        rsrp_trip_threshold_dbm: int = DEFAULT_RSRP_TRIP_THRESHOLD_DBM,
        sinr_trip_threshold_db: int = DEFAULT_SINR_TRIP_THRESHOLD_DB,
        latency_trip_threshold_us: int = DEFAULT_LATENCY_TRIP_THRESHOLD_US,
        packet_loss_trip_threshold_ppm: int = DEFAULT_PACKET_LOSS_TRIP_THRESHOLD_PPM,
        epid: str = DEFAULT_SAFETY_EPID,
        qos_flow_id: int = NOMINAL_5G_QOS_FLOW_ID,
        **kwargs: Any,
    ) -> None:
        self.register_table = register_table
        self.auto_activate = bool(auto_activate)
        self.watchdog_timeout_ms = float(watchdog_timeout_ms)
        self.rsrp_trip_threshold_dbm = int(rsrp_trip_threshold_dbm)
        self.sinr_trip_threshold_db = int(sinr_trip_threshold_db)
        self.latency_trip_threshold_us = int(latency_trip_threshold_us)
        self.packet_loss_trip_threshold_ppm = int(packet_loss_trip_threshold_ppm)
        self.epid = str(epid)
        self.epid_hash = compute_epid_hash(self.epid)

        flow_arg = kwargs.get("five_qi", kwargs.get("flow_id", qos_flow_id))
        self.qos_flow_id = int(flow_arg)
        self.flow_id_hash = self.epid_hash
        self.beam_id = int(kwargs.get("beam_id", DEFAULT_RADIO_BEAM_ID))

        self.is_active = bool(auto_activate)
        self.state: Safe5GState = (
            Safe5GState.AUTHENTICATED_OPERATIONAL
            if auto_activate
            else Safe5GState.IDLE
        )
        self.diagnostic_code: DiagnosticCode = DiagnosticCode.OK

        # Telemetry & Metrics
        self.rsrp_dbm: int = NOMINAL_5G_RSRP_DBM
        self.sinr_db: int = NOMINAL_5G_SINR_DB
        self.latency_us: int = NOMINAL_URLLC_LATENCY_US
        self.packet_loss_ppm: int = NOMINAL_URLLC_PACKET_LOSS_RATE_PPM
        self.handover_count: int = NOMINAL_5G_HANDOVER_COUNT
        self.transmit_sequence: int = 0
        self.silence_timer_ms: float = 0.0

        self.cycles_count: int = 0
        self.packets_processed: int = 0
        self.packets_transmitted: int = 0

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    # ------------------------------------------------------------------------
    # Properties (ILogicUnit Compliance)
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        """ILogicUnit Unique Identifier."""
        return "CIP5GSafetyURLLCEngine"

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
        """Whether 5G URLLC safety link is operational and untripped."""
        return (
            self.state == Safe5GState.AUTHENTICATED_OPERATIONAL
            and self.diagnostic_code == DiagnosticCode.OK
        )

    @property
    def link_healthy(self) -> bool:
        """Alias for is_healthy."""
        return self.is_healthy

    @property
    def is_safe_stop_tripped(self) -> bool:
        """Whether safety stop is engaged."""
        return (
            self.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
            or self.state == Safe5GState.IDLE
            or self.diagnostic_code != DiagnosticCode.OK
        )

    @property
    def safe_stop_tripped(self) -> bool:
        """Alias for is_safe_stop_tripped."""
        return self.is_safe_stop_tripped

    @property
    def safety_state(self) -> Safe5GState:
        """Current safe 5G state machine state."""
        return self.state

    @property
    def link_state(self) -> Safe5GState:
        """Alias for safety_state."""
        return self.state

    @property
    def five_qi(self) -> int:
        """5QI Flow ID alias."""
        return self.qos_flow_id

    # ------------------------------------------------------------------------
    # State Machine & Interlocks
    # ------------------------------------------------------------------------

    def attach_npn(self) -> bool:
        """Progress state from IDLE to ATTACHING_NPN."""
        self.state = Safe5GState.ATTACHING_NPN
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def establish_urllc_session(self) -> bool:
        """Progress state from ATTACHING_NPN to URLLC_SESSION_ESTABLISHED."""
        self.state = Safe5GState.URLLC_SESSION_ESTABLISHED
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def authenticate(self) -> bool:
        """Progress state from URLLC_SESSION_ESTABLISHED to AUTHENTICATED_OPERATIONAL."""
        self.state = Safe5GState.AUTHENTICATED_OPERATIONAL
        self.diagnostic_code = DiagnosticCode.OK
        self.silence_timer_ms = 0.0
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return True

    def connect(self) -> bool:
        """Progress state machine through ATTACHING_NPN, URLLC_SESSION to AUTHENTICATED_OPERATIONAL."""
        self.attach_npn()
        self.establish_urllc_session()
        self.authenticate()
        return True

    def disconnect(self) -> None:
        """Transition radio into IDLE safe state."""
        self.state = Safe5GState.IDLE
        self.silence_timer_ms = 0.0
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def trip_fault(self, code: DiagnosticCode, reason: str = "") -> None:
        """Trip safety interlock into URLLC_TIMEOUT_SAFE_STOP (%M507=True, %M506=False)."""
        self.diagnostic_code = code
        self.state = Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def trigger_handover(self) -> int:
        """Simulate seamless 5G gNodeB handover event, incrementing cumulative handover count."""
        self.handover_count = (self.handover_count + 1) & 0xFFFF
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return self.handover_count

    def reset(self) -> None:
        """Reset internal unit state to initial nominal operational conditions."""
        self.diagnostic_code = DiagnosticCode.OK
        self.silence_timer_ms = 0.0
        self.rsrp_dbm = NOMINAL_5G_RSRP_DBM
        self.sinr_db = NOMINAL_5G_SINR_DB
        self.latency_us = NOMINAL_URLLC_LATENCY_US
        self.packet_loss_ppm = NOMINAL_URLLC_PACKET_LOSS_RATE_PPM
        self.qos_flow_id = NOMINAL_5G_QOS_FLOW_ID

        if self.auto_activate:
            self.state = Safe5GState.AUTHENTICATED_OPERATIONAL
        else:
            self.state = Safe5GState.IDLE

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    operator_reset = reset
    fault_reset = reset

    # ------------------------------------------------------------------------
    # Packet Processing & Frame Verification
    # ------------------------------------------------------------------------

    def create_packet(
        self,
        seq: Optional[int] = None,
        rsrp_dbm: Optional[int] = None,
        sinr_db: Optional[int] = None,
        latency_us: Optional[int] = None,
        packet_loss_ppm: Optional[int] = None,
        qos_flow_id: Optional[int] = None,
        handover_count: Optional[int] = None,
        payload: Optional[bytes] = None,
        **kwargs: Any,
    ) -> CIP5GSafetyURLLCPacket:
        """Generate valid outgoing 5G URLLC safety packet with fresh diversified sequence & CRCs."""
        sequence_num = seq if seq is not None else ((self.transmit_sequence + 1) & 0xFFFF)
        epid = kwargs.pop("epid", self.epid)
        epid_hash = compute_epid_hash(epid) if epid != self.epid else self.epid_hash
        flow_id = kwargs.pop("five_qi", kwargs.pop("flow_id", qos_flow_id))
        flow_val = flow_id if flow_id is not None else self.qos_flow_id
        pkt = CIP5GSafetyURLLCPacket(
            epid=epid,
            epid_hash=epid_hash,
            sequence_primary=sequence_num,
            sequence_diversified=(~sequence_num) & 0xFFFF,
            rsrp_dbm=rsrp_dbm if rsrp_dbm is not None else self.rsrp_dbm,
            sinr_db=sinr_db if sinr_db is not None else self.sinr_db,
            latency_us=latency_us if latency_us is not None else self.latency_us,
            packet_loss_ppm=packet_loss_ppm if packet_loss_ppm is not None else self.packet_loss_ppm,
            qos_flow_id=flow_val,
            handover_count=handover_count if handover_count is not None else self.handover_count,
            payload=payload if payload is not None else b"\x01\x00\x00\x00",
            timestamp_us=float(self.cycles_count * 10000.0),
            **kwargs,
        )
        pkt.calculate_crcs()
        return pkt

    def transmit_packet(self, payload: Optional[bytes] = None) -> CIP5GSafetyURLLCPacket:
        """Transmit safe frame: increments sequence counter and updates transmit statistics."""
        self.transmit_sequence = (self.transmit_sequence + 1) & 0xFFFF
        self.packets_transmitted += 1
        pkt = self.create_packet(seq=self.transmit_sequence, payload=payload)
        if self.register_table is not None:
            self.sync_to_registers(self.register_table)
        return pkt

    def process_packet(self, pkt: CIP5GSafetyURLLCPacket) -> bool:
        """Process incoming safe 5G URLLC frame with dual CRC, diversified sequence, and RF surveillance."""
        # 1. Dual CRC-S1 and CRC-S2 verification
        if not pkt.verify_crcs():
            self.trip_fault(DiagnosticCode.AUTH_FAIL_TRIP, "CRC-S checksum corruption detected")
            return False

        # 2. Diversified sequence counter verification
        if not pkt.verify_sequence():
            self.trip_fault(DiagnosticCode.AUTH_FAIL_TRIP, "Diversified sequence counter mismatch")
            return False

        # 3. EPID hash authentication
        if (pkt.epid_hash & 0xFFFFFFFF) != (self.epid_hash & 0xFFFFFFFF):
            self.trip_fault(DiagnosticCode.AUTH_FAIL_TRIP, "EPID hash mismatch / unauthorized 5G device")
            return False

        # 4. 5G RSRP drop surveillance
        self.rsrp_dbm = int(pkt.rsrp_dbm)
        if self.rsrp_dbm < self.rsrp_trip_threshold_dbm:
            self.trip_fault(
                DiagnosticCode.RSRP_DROP_TRIP,
                f"RSRP {self.rsrp_dbm} dBm below threshold {self.rsrp_trip_threshold_dbm} dBm",
            )
            return False

        # 5. 5G SINR noise surveillance
        self.sinr_db = int(pkt.sinr_db)
        if self.sinr_db < self.sinr_trip_threshold_db:
            self.trip_fault(
                DiagnosticCode.SINR_NOISE_TRIP,
                f"SINR {self.sinr_db} dB below threshold {self.sinr_trip_threshold_db} dB",
            )
            return False

        # 6. URLLC Latency overrun surveillance
        self.latency_us = int(pkt.latency_us)
        if self.latency_us > self.latency_trip_threshold_us:
            self.trip_fault(
                DiagnosticCode.LATENCY_OVERRUN_TRIP,
                f"URLLC latency {self.latency_us} us exceeded threshold {self.latency_trip_threshold_us} us",
            )
            return False

        # 7. Packet loss rate surveillance
        self.packet_loss_ppm = int(pkt.packet_loss_ppm)
        if self.packet_loss_ppm > self.packet_loss_trip_threshold_ppm:
            self.trip_fault(
                DiagnosticCode.LATENCY_OVERRUN_TRIP,
                f"Packet loss {self.packet_loss_ppm} ppm exceeded threshold {self.packet_loss_trip_threshold_ppm} ppm",
            )
            return False

        # Successful safe frame processing
        self.silence_timer_ms = 0.0
        self.packets_processed += 1
        self.handover_count = int(pkt.handover_count) & 0xFFFF
        self.qos_flow_id = int(pkt.qos_flow_id) & 0xFFFF

        if self.state in (Safe5GState.ATTACHING_NPN, Safe5GState.URLLC_SESSION_ESTABLISHED):
            self.state = Safe5GState.AUTHENTICATED_OPERATIONAL

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

        return True

    # ------------------------------------------------------------------------
    # Fault Injection Hooks
    # ------------------------------------------------------------------------

    def inject_rsrp_drop(self, rsrp_dbm: int = -125) -> None:
        """Inject 5G RSRP drop below safety trip threshold."""
        self.rsrp_dbm = int(rsrp_dbm)
        self.trip_fault(DiagnosticCode.RSRP_DROP_TRIP, f"Injected RSRP drop: {rsrp_dbm} dBm")

    def inject_sinr_noise(self, sinr_db: int = -5) -> None:
        """Inject 5G SINR noise excursion below safety threshold."""
        self.sinr_db = int(sinr_db)
        self.trip_fault(DiagnosticCode.SINR_NOISE_TRIP, f"Injected SINR noise: {sinr_db} dB")

    def inject_latency_overrun(self, latency_us: int = 15000) -> None:
        """Inject URLLC latency overrun exceeding safety threshold."""
        self.latency_us = int(latency_us)
        self.trip_fault(DiagnosticCode.LATENCY_OVERRUN_TRIP, f"Injected URLLC latency: {latency_us} us")

    def inject_packet_loss(self, packet_loss_ppm: int = 2500) -> None:
        """Inject packet loss excursion exceeding safety limit."""
        self.packet_loss_ppm = int(packet_loss_ppm)
        self.trip_fault(DiagnosticCode.LATENCY_OVERRUN_TRIP, f"Injected packet loss: {packet_loss_ppm} ppm")

    def inject_auth_failure(self) -> None:
        """Inject EPID authentication failure."""
        self.trip_fault(DiagnosticCode.AUTH_FAIL_TRIP, "Injected authentication failure")

    def inject_watchdog_timeout(self) -> None:
        """Force 5G URLLC watchdog silence timer beyond limit."""
        self.silence_timer_ms = self.watchdog_timeout_ms + 5.0
        self.trip_fault(DiagnosticCode.LATENCY_OVERRUN_TRIP, "5G URLLC silence watchdog timeout")

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: RegisterTable,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize internal state to Horner OCS %R2170..%R2177 and %M506..%M507."""
        # %R2170: Safe 5G State Machine (0..4)
        safe_write_word(reg_table, REG_5G_SAFETY_LINK_STATE, int(self.state), privilege=privilege)

        # %R2171: 5G RSRP dBm (-140..-40 dBm)
        safe_write_word(reg_table, REG_5G_RSRP_DBM, int(self.rsrp_dbm), privilege=privilege)

        # %R2172: 5G SINR dB (-10..30 dB)
        safe_write_word(reg_table, REG_5G_SINR_DB, int(self.sinr_db), privilege=privilege)

        # %R2173: URLLC Latency us (100..20000 us)
        safe_write_word(reg_table, REG_URLLC_LATENCY_US, int(self.latency_us), privilege=privilege)

        # %R2174: Packet Loss Rate PPM (0..10000 ppm)
        safe_write_uword(reg_table, REG_URLLC_PACKET_LOSS_RATE_PPM, int(self.packet_loss_ppm) & 0xFFFF, privilege=privilege)

        # %R2175: 5G QoS Flow Identifier / 5QI (nominal 82)
        safe_write_uword(reg_table, REG_5G_QOS_FLOW_ID, int(self.qos_flow_id) & 0xFFFF, privilege=privilege)

        # %R2176: Cumulative 5G Handover Count
        safe_write_uword(reg_table, REG_5G_HANDOVER_COUNT, int(self.handover_count) & 0xFFFF, privilege=privilege)

        # %R2177: Diagnostic Status Code (0x0000 OK, 0xEE21..0xEE24)
        safe_write_uword(reg_table, REG_5G_SAFETY_DIAGNOSTIC_CODE, int(self.diagnostic_code) & 0xFFFF, privilege=privilege)

        # %M506: 5G Safety Link Healthy (BOOL)
        safe_write_bit(reg_table, COIL_5G_SAFETY_LINK_HEALTHY, self.is_healthy, privilege=privilege)

        # %M507: 5G Safety Stop Tripped (BOOL)
        safe_write_bit(reg_table, COIL_5G_SAFETY_STOP_TRIPPED, self.is_safe_stop_tripped, privilege=privilege)

    # ------------------------------------------------------------------------
    # ILogicUnit Cyclic Execution
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.010, context: Optional[ScanContext] = None) -> None:
        """Deterministic scan step: surveillance of 5G URLLC watchdog timeout & link state."""
        dt_ms = dt * 1000.0
        self.cycles_count += 1

        if self.state == Safe5GState.AUTHENTICATED_OPERATIONAL:
            self.silence_timer_ms += dt_ms
            if self.silence_timer_ms > self.watchdog_timeout_ms:
                self.trip_fault(DiagnosticCode.LATENCY_OVERRUN_TRIP, "5G URLLC silence watchdog timeout")
                return

        if self.register_table is not None:
            self.sync_to_registers(self.register_table)

    def step(self, dt: float = 0.010, context: Optional[ScanContext] = None) -> None:
        """Alias for scan_step."""
        self.scan_step(dt, context)

    def execute(self, context: ScanContext) -> None:
        """ILogicUnit execute method invoked during simulation scan Phase 2."""
        dt = getattr(context, "dt_s", None) or (getattr(context, "dt_ms", 10.0) / 1000.0)
        self.scan_step(dt, context)


CIP5GURLLCSafetyEngine = CIP5GSafetyURLLCEngine
CipSafety5GUrllcEngine = CIP5GSafetyURLLCEngine
CIP5GSafetyEngine = CIP5GSafetyURLLCEngine
CIPSafety5GUrllcEngine = CIP5GSafetyURLLCEngine
CIP_SAFETY_5G_URLLC_ENGINE = CIP5GSafetyURLLCEngine


# ============================================================================
# 8. Deterministic 10-Stage Verification Suite
# ============================================================================

def run_cip_safety_5g_urllc_verification(
    output_path: Optional[str] = None,
    work_package: str = "W256",
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
        REG_5G_SAFETY_LINK_STATE == "%R2170"
        and REG_5G_RSRP_DBM == "%R2171"
        and REG_5G_SINR_DB == "%R2172"
        and REG_URLLC_LATENCY_US == "%R2173"
        and REG_URLLC_PACKET_LOSS_RATE_PPM == "%R2174"
        and REG_5G_QOS_FLOW_ID == "%R2175"
        and REG_5G_HANDOVER_COUNT == "%R2176"
        and REG_5G_SAFETY_DIAGNOSTIC_CODE == "%R2177"
        and COIL_5G_SAFETY_LINK_HEALTHY == "%M506"
        and COIL_5G_SAFETY_STOP_TRIPPED == "%M507"
        and DiagnosticCode.OK == 0x0000
        and DiagnosticCode.RSRP_DROP_TRIP == 0xEE21
        and DiagnosticCode.SINR_NOISE_TRIP == 0xEE22
        and DiagnosticCode.LATENCY_OVERRUN_TRIP == 0xEE23
        and DiagnosticCode.AUTH_FAIL_TRIP == 0xEE24
        # Signed 16-bit equality test
        and DiagnosticCode.RSRP_DROP_TRIP == (0xEE21 - 0x10000)
        and (DiagnosticCode.RSRP_DROP_TRIP & 0xFFFF) == 0xEE21
        and DiagnosticCode.SINR_NOISE_TRIP == (0xEE22 - 0x10000)
        and DiagnosticCode.LATENCY_OVERRUN_TRIP == (0xEE23 - 0x10000)
        and DiagnosticCode.AUTH_FAIL_TRIP == (0xEE24 - 0x10000)
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "Protocol_Constants_Registers_And_Diagnostic_Codes",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified register mappings %R2170..%R2177, %M506..%M507, and signed/unsigned DiagnosticCode equality.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Dual CRC-S1 (0x5935) & CRC-S2 (0x755B) Calculation & Corruption
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sample_payload = b"HornerOCS-5G-URLLC-SafePayload"
    c1 = compute_crc_s1(sample_payload)
    c2 = compute_crc_s2(sample_payload)

    # Deterministic recurrence check
    c1_again = compute_crc_s1(sample_payload)
    c2_again = compute_crc_s2(sample_payload)

    # Corruption detection
    corrupted_payload = bytearray(sample_payload)
    corrupted_payload[0] ^= 0x01
    c1_corrupted = compute_crc_s1(bytes(corrupted_payload))
    c2_corrupted = compute_crc_s2(bytes(corrupted_payload))

    s2_pass = (
        c1 == c1_again
        and c2 == c2_again
        and c1 != c1_corrupted
        and c2 != c2_corrupted
        and isinstance(c1, int)
        and 0 <= c1 <= 0xFFFF
        and 0 <= c2 <= 0xFFFF
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "Dual_CRC_S1_S2_Calculation_And_Single_Bit_Corruption",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": f"CRC-S1 (0x{c1:04X}) and CRC-S2 (0x{c2:04X}) deterministic calculations and bit mutation verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Diversified Sequence Counters & URLLC Frame Integrity
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    pkt = create_valid_5g_safety_packet(sequence_primary=101)
    seq_ok = pkt.verify_sequence()
    crc_ok = pkt.verify_crcs()

    # Invert sequence diversification
    pkt_bad_seq = create_valid_5g_safety_packet(sequence_primary=101)
    pkt_bad_seq.sequence_diversified = 101  # Violates ~seq & 0xFFFF
    bad_seq_caught = not pkt_bad_seq.verify_sequence()

    # Mutate payload
    pkt_corrupted = create_valid_5g_safety_packet(sequence_primary=101)
    pkt_corrupted.mutate_bit(0, 0)
    corrupt_caught = not pkt_corrupted.verify_crcs()

    s3_pass = seq_ok and crc_ok and bad_seq_caught and corrupt_caught
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "Diversified_Sequence_Counters_And_Frame_Integrity",
        "passed": bool(s3_pass),
        "timing_ms": round(t1, 3),
        "details": "Primary/diversified sequence relationship (~seq_1 & 0xFFFF) and payload mutation verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Safe 5G State Machine Transitions
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    engine_sm = CIP5GSafetyURLLCEngine(auto_activate=False)
    st0 = engine_sm.state == Safe5GState.IDLE
    st0_healthy = not engine_sm.is_healthy
    st0_stop = engine_sm.is_safe_stop_tripped

    engine_sm.attach_npn()
    st_npn = engine_sm.state == Safe5GState.ATTACHING_NPN

    engine_sm.establish_urllc_session()
    st_session = engine_sm.state == Safe5GState.URLLC_SESSION_ESTABLISHED

    engine_sm.authenticate()
    st_auth = engine_sm.state == Safe5GState.AUTHENTICATED_OPERATIONAL
    st_healthy = engine_sm.is_healthy
    st_no_stop = not engine_sm.is_safe_stop_tripped

    engine_sm.trip_fault(DiagnosticCode.RSRP_DROP_TRIP)
    st_trip = engine_sm.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
    st_trip_healthy = not engine_sm.is_healthy
    st_trip_stop = engine_sm.is_safe_stop_tripped

    engine_sm.reset()
    st_reset = engine_sm.state == (
        Safe5GState.AUTHENTICATED_OPERATIONAL
        if engine_sm.auto_activate
        else Safe5GState.IDLE
    )

    s4_pass = (
        st0 and st0_healthy and st0_stop
        and st_npn and st_session and st_auth
        and st_healthy and st_no_stop
        and st_trip and st_trip_healthy and st_trip_stop
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "Safe_5G_State_Machine_Transitions",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "Transitions IDLE -> ATTACHING_NPN -> URLLC_SESSION -> AUTHENTICATED_OPERATIONAL -> SAFE_STOP verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: EPID Authentication and Hash Verification
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    engine_auth = CIP5GSafetyURLLCEngine(auto_activate=True, epid="HORNER-OCS-5G-URLLC-SIL3")
    valid_pkt = engine_auth.create_packet()
    auth_ok = engine_auth.process_packet(valid_pkt)

    # Rogue EPID packet
    rogue_pkt = create_valid_5g_safety_packet(epid="ROGUE-UNAUTHORIZED-5G-NODE")
    auth_rejected = not engine_auth.process_packet(rogue_pkt)
    auth_trip_code = engine_auth.diagnostic_code == DiagnosticCode.AUTH_FAIL_TRIP
    auth_state_stop = engine_auth.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP

    s5_pass = auth_ok and auth_rejected and auth_trip_code and auth_state_stop
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "EPID_Authentication_And_Hash_Verification",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "Authorized EPID accepted; unauthorized rogue 5G node tripped 0xEE24 AUTH_FAIL_TRIP.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: 5G Radio Metrics Surveillance (RSRP & SINR)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 6a. RSRP Drop (< -110 dBm)
    engine_rf1 = CIP5GSafetyURLLCEngine(auto_activate=True)
    bad_rsrp_pkt = engine_rf1.create_packet(rsrp_dbm=-125)
    rf1_rejected = not engine_rf1.process_packet(bad_rsrp_pkt)
    rf1_code = engine_rf1.diagnostic_code == DiagnosticCode.RSRP_DROP_TRIP

    # 6b. SINR Noise Excursion (< 0 dB)
    engine_rf2 = CIP5GSafetyURLLCEngine(auto_activate=True)
    bad_sinr_pkt = engine_rf2.create_packet(sinr_db=-5)
    rf2_rejected = not engine_rf2.process_packet(bad_sinr_pkt)
    rf2_code = engine_rf2.diagnostic_code == DiagnosticCode.SINR_NOISE_TRIP

    s6_pass = rf1_rejected and rf1_code and rf2_rejected and rf2_code
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "Radio_Metrics_Surveillance_RSRP_And_SINR",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified 0xEE21 (RSRP drop trip < -110 dBm) and 0xEE22 (SINR noise trip < 0 dB).",
    })

    # ------------------------------------------------------------------------
    # Stage 7: URLLC Latency Overrun & Silence Watchdog Timeout
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 7a. Latency Overrun (> 10,000 us)
    engine_lat = CIP5GSafetyURLLCEngine(auto_activate=True)
    bad_lat_pkt = engine_lat.create_packet(latency_us=15000)
    lat_rejected = not engine_lat.process_packet(bad_lat_pkt)
    lat_code = engine_lat.diagnostic_code == DiagnosticCode.LATENCY_OVERRUN_TRIP

    # 7b. 5G URLLC Silence Watchdog (10.0 ms timeout)
    engine_wd = CIP5GSafetyURLLCEngine(auto_activate=True, watchdog_timeout_ms=10.0)
    # Advance time without packets (2 x 10ms = 20ms > 10ms)
    for _ in range(2):
        engine_wd.scan_step(0.010)

    wd_tripped = engine_wd.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
    wd_stopped = engine_wd.is_safe_stop_tripped
    wd_healthy_cleared = not engine_wd.is_healthy
    wd_code = engine_wd.diagnostic_code == DiagnosticCode.LATENCY_OVERRUN_TRIP

    s7_pass = lat_rejected and lat_code and wd_tripped and wd_stopped and wd_healthy_cleared and wd_code
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "URLLC_Latency_Overrun_And_Silence_Watchdog",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified 0xEE23 (Latency overrun > 10,000 us and 10ms silence watchdog trip).",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Horner OCS Register Table Synchronization & Operator Reset
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s8 = RegisterTable()
    engine_s8 = CIP5GSafetyURLLCEngine(register_table=rt_s8, auto_activate=True)

    s8_nom = (
        rt_s8.read_word("%R2170") == 3
        and rt_s8.read_word("%R2171") == -75
        and rt_s8.read_word("%R2172") == 18
        and rt_s8.read_word("%R2173") == 950
        and rt_s8.read_uword("%R2174") == 1
        and rt_s8.read_uword("%R2175") == 82
        and rt_s8.read_uword("%R2176") == 0
        and rt_s8.read_uword("%R2177") == 0x0000
        and rt_s8.read_bit("%M506") is True
        and rt_s8.read_bit("%M507") is False
    )

    # Trip and test synchronization
    engine_s8.trip_fault(DiagnosticCode.RSRP_DROP_TRIP)
    s8_trip = (
        rt_s8.read_word("%R2170") == 4
        and rt_s8.read_uword("%R2177") == 0xEE21
        and rt_s8.read_bit("%M506") is False
        and rt_s8.read_bit("%M507") is True
    )

    # Operator reset
    engine_s8.reset()
    s8_reset = (
        rt_s8.read_word("%R2170") == 3
        and rt_s8.read_uword("%R2177") == 0x0000
        and rt_s8.read_bit("%M506") is True
        and rt_s8.read_bit("%M507") is False
    )

    s8_pass = s8_nom and s8_trip and s8_reset
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "Horner_OCS_Register_Table_Synchronization_And_Operator_Reset",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact %R2170..%R2177 and %M506..%M507 synchronization verified under SYSTEM privilege.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Pure IEC 61131-3 ST POU & Ladder Rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_valid = verify_cip_safety_5g_urllc_pure_st()

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
        "details": "STParser / SecurityGuard confirmed CipSafety5GUrllcSync POU validity; LadderForbiddenError intercepted.",
    })

    # ------------------------------------------------------------------------
    # Stage 10: ILogicUnit 100-Cycle Soak Simulation & Zero Memory Leak
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s10 = RegisterTable()
    engine_s10 = CIP5GSafetyURLLCEngine(register_table=rt_s10, auto_activate=True)

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()
    soak_stable = True
    for cycle_i in range(1, 101):
        try:
            pkt_in = engine_s10.create_packet(seq=cycle_i)
            engine_s10.process_packet(pkt_in)
            engine_s10.scan_step(0.010)
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
        and rt_s10.read_word("%R2170") == 3
        and rt_s10.read_word("%R2171") == -75
        and rt_s10.read_uword("%R2177") == 0x0000
        and rt_s10.read_bit("%M506") is True
        and rt_s10.read_bit("%M507") is False
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
        f"Wave {work_package} CIP Safety Over 5G URLLC Protocol Engine Verification PASSED ({stages_passed}/{total_stages} stages)."
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
            "protocol": "ODVA CIP Safety Over 5G URLLC (3GPP Rel 16/17)",
            "work_package": work_package,
            "classes": {
                "0x39": "Safety Supervisor Object",
                "0x3A": "Safety Validator Object",
                "0x3B": "Safety Connection Object",
                "0x2F": "CIP Safety 5G URLLC Object",
            },
            "register_map": {
                "%R2170": "Safe 5G State Machine (0..4)",
                "%R2171": "5G RSRP (dBm)",
                "%R2172": "5G SINR (dB)",
                "%R2173": "URLLC Latency (us)",
                "%R2174": "URLLC Packet Loss Rate (PPM)",
                "%R2175": "5G QoS Flow Identifier (5QI)",
                "%R2176": "Cumulative 5G Handover Count",
                "%R2177": "Safety Diagnostic Code",
                "%M506": "5G Safety Link Healthy Coil",
                "%M507": "5G Safety Stop Tripped Coil",
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
    result = run_cip_safety_5g_urllc_verification()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
