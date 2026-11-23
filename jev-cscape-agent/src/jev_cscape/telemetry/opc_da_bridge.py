"""Industrial OPC DA / XML-DA Protocol Wrapper & Legacy COM/DCOM Bridge Engine.

Work Package: W178 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- OPC Data Access Custom Interface Standard v2.05a & v3.00 (OPC Foundation)
- OPC XML-DA Specification v1.01 (OPC Foundation)
- Microsoft COM/DCOM Architecture Specification (Component Object Model)
- IEC 61131-3 Programmable Controllers - Part 3: Programming Languages (Structured Text)

Architecture:
1. Strict Pure IEC 61131-3 Structured Text POUs:
   - 'OpcDaXmlBridgeSync' (and alias 'LegacyComDcomOpcBridgeSync').
   - Bound to Horner OCS registers (%R1390..%R1397, %M324..%M325).
   - Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN using SecurityGuard and STParser.

2. Complete OPC DA 2.05a/3.0 & XML-DA 1.01 Architecture:
   - Server status reporting: Server state, vendor info, start time, current time, group count, bandwidth.
   - Group management: Up to 16 groups, update rates (50ms, 100ms, 500ms, 1000ms), deadband filtering, active state.
   - Item address space browsing: Hierarchical branches (HornerOCS, ProcessUnits, Diagnostics) and flat leaf browsing.
   - Item properties: Canonical data types (VT_I2, VT_I4, VT_R4, VT_BOOL, VT_BSTR), access rights, engineering units.
   - Synchronous and Asynchronous read/write transactions (SyncIO, AsyncIO2 with OnDataChange notification emulation).
   - XML-DA 1.01 SOAP envelope marshaling and operations (GetStatus, Read, Write, Browse, GetProperties, Subscribe, SubscriptionPolledRefresh).
   - Legacy COM/DCOM marshaling emulation: CLSID and IID resolution, QueryInterface, and HRESULT diagnostics:
     * S_OK (0x00000000)
     * S_FALSE (0x00000001)
     * E_FAIL (0x80004005)
     * E_INVALIDARG (0x80070057)
     * E_NOINTERFACE (0x80004002)
     * OPC_E_INVALIDHANDLE (0xC0040001)
     * OPC_E_BADTYPE (0xC0040004)
     * OPC_E_UNKNOWNITEMID (0xC0040007)
     * OPC_E_INVALIDFILTER (0xC0040008)
     * OPC_S_UNSUPPORTEDRATE (0x0004000D)
     * OPC_S_CLAMP (0x00040002)
     * RPC_E_DISCONNECTED (0x80010108)
     * RPC_E_SERVER_DIED (0x800706BE)
     * RPC_E_CALL_FAILED (0x80010001)
     * REGDB_E_CLASSNOTREG (0x80040154)
   - Quality stamping: Good (0xC0), Bad (0x00), Uncertain (0x40).
   - Gateway state machine: OPC_DA_IDLE, CONNECTING, GROUP_ACTIVE, ASYNC_TRANSACTION, DCOM_RECONNECT, OPC_FAULT.
   - Round-trip latency tracking: Scaled x10 ms, nominal 3.5 ms -> 35.
   - Implements ILogicUnit interface with scan_step(dt).

3. Process Safety Interlocks & Diagnostics:
   - 0x0000: OK (Normal healthy bridge operation)
   - 0xCB01: OPC_ERR_DCOM_RPC_DISCONNECT (RPC connection lost to OPC server)
             -> asserts %M325 (OpcDaBridgeFaultTrip), clears %M324 (OpcDaBridgePermissive), increments %R1394
   - 0xCB02: OPC_ERR_GROUP_UPDATE_TIMEOUT (Asynchronous subscription update timeout > 2500ms)
             -> asserts %M325, clears %M324
   - 0xCB03: OPC_ERR_ITEM_BAD_QUALITY (Critical process items returned BAD quality status 0x00)
             -> asserts %M325, clears %M324
   - 0xCB04: OPC_ERR_INVALID_CLSID (Server CLSID resolution failure or COM registration missing)
             -> asserts %M325, clears %M324

4. Horner OCS Memory Space Integration:
   - %R1390: ConnectedOpcGroupsCount (INT16, 0..16)
   - %R1391: ActiveOpcItemsCount (INT16, e.g. 64)
   - %R1392: OpcDaTransactionLatencyMsScaled (INT16, scaled x10 ms, e.g. 35 = 3.5 ms)
   - %R1393: OpcItemQualityCodeWord (UINT16, 0x00C0 = OPC_QUALITY_GOOD)
   - %R1394: DcomReconnectFailuresCount (INT16 count)
   - %R1395: OpcBridgeStateWord (INT16 bitmask of gateway status, COM/DCOM listener, fault flags)
   - %R1396: OpcGroupUpdateRateMs (INT16, e.g. 100)
   - %R1397: DiagnosticStatusCode (0x0000=OK, 0xCB01, 0xCB02, 0xCB03, 0xCB04)
   - %M324: OpcDaBridgePermissive (BOOL)
   - %M325: OpcDaBridgeFaultTrip (BOOL)
   - All RegisterTable writes pass privilege=PrivilegeMode.SYSTEM.

5. Deterministic 9-Stage Verification Suite:
   - Function run_opc_da_bridge_verification(output_path) returning strict 4-state contract JSON.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
import json
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
# 1. Constants & Protocol Definitions (OPC DA 2.05a/3.0 & XML-DA 1.01)
# ============================================================================

MAX_OPC_GROUPS: int = 16
DEFAULT_GROUP_UPDATE_RATE_MS: int = 100
STANDARD_UPDATE_RATES_MS: Tuple[int, ...] = (50, 100, 500, 1000)

GROUP_UPDATE_TIMEOUT_MS: float = 2500.0
NOMINAL_TRANSACTION_LATENCY_MS: float = 3.5
NOMINAL_LATENCY_SCALED: int = 35  # 3.5 ms * 10

# Standard OPC Quality Codes
OPC_QUALITY_BAD: int = 0x00
OPC_QUALITY_UNCERTAIN: int = 0x40
OPC_QUALITY_GOOD: int = 0xC0
OPC_QUALITY_MASK: int = 0xC0

# Substatus Quality Masks
OPC_QUALITY_NON_SPECIFIC: int = 0x00
OPC_QUALITY_CONFIG_ERROR: int = 0x04
OPC_QUALITY_NOT_CONNECTED: int = 0x08
OPC_QUALITY_DEVICE_FAILURE: int = 0x0C
OPC_QUALITY_SENSOR_FAILURE: int = 0x10
OPC_QUALITY_LAST_KNOWN_VALUE: int = 0x14
OPC_QUALITY_COMM_FAILURE: int = 0x18
OPC_QUALITY_OUT_OF_SERVICE: int = 0x1C
OPC_QUALITY_LAST_USABLE_VALUE: int = 0x44
OPC_QUALITY_SENSOR_NOT_ACCURATE: int = 0x50
OPC_QUALITY_EU_EXCEEDED: int = 0x54
OPC_QUALITY_SUB_NORMAL: int = 0x58
OPC_QUALITY_LOCAL_OVERRIDE: int = 0xD8

# Standard COM / OPC HRESULT Error Codes
S_OK: int = 0x00000000
S_FALSE: int = 0x00000001
E_FAIL: int = 0x80004005
E_INVALIDARG: int = 0x80070057
E_NOINTERFACE: int = 0x80004002
REGDB_E_CLASSNOTREG: int = 0x80040154
RPC_E_DISCONNECTED: int = 0x80010108
RPC_E_SERVER_DIED: int = 0x800706BE
RPC_E_CALL_FAILED: int = 0x80010001

OPC_E_INVALIDHANDLE: int = 0xC0040001
OPC_E_BADTYPE: int = 0xC0040004
OPC_E_UNKNOWNITEMID: int = 0xC0040007
OPC_E_INVALIDFILTER: int = 0xC0040008
OPC_S_UNSUPPORTEDRATE: int = 0x0004000D
OPC_S_CLAMP: int = 0x00040002

# COM Variant Data Types (VARENUM)
VT_EMPTY: int = 0
VT_I2: int = 2        # 16-bit signed integer
VT_I4: int = 3        # 32-bit signed integer
VT_R4: int = 4        # 32-bit IEEE float
VT_R8: int = 5        # 64-bit IEEE double
VT_BSTR: int = 8      # OLE String
VT_BOOL: int = 11     # Boolean (-1 True, 0 False)
VT_UI1: int = 17      # 8-bit unsigned integer (Byte)
VT_UI2: int = 18      # 16-bit unsigned integer
VT_UI4: int = 19      # 32-bit unsigned integer

# OPC Access Rights
OPC_READABLE: int = 0x01
OPC_WRITEABLE: int = 0x02

# OPC Server Status Codes
OPC_STATUS_RUNNING: int = 1
OPC_STATUS_FAILED: int = 2
OPC_STATUS_NOCONFIG: int = 3
OPC_STATUS_SUSPENDED: int = 4
OPC_STATUS_TEST: int = 5
OPC_STATUS_COMM_FAULT: int = 6

# OPC Browse Types
OPC_BRANCH: int = 1
OPC_LEAF: int = 2
OPC_FLAT: int = 3

# OPC Browse Directions
OPC_BROWSE_UP: int = 1
OPC_BROWSE_TO: int = 2
OPC_BROWSE_DOWN: int = 3

# OPC Property IDs
OPC_PROP_CDT: int = 1           # Canonical Data Type
OPC_PROP_VALUE: int = 2         # Item Value
OPC_PROP_QUALITY: int = 3       # Item Quality
OPC_PROP_TIME: int = 4          # Item Timestamp
OPC_PROP_RIGHTS: int = 5        # Access Rights
OPC_PROP_SCANRATE: int = 6      # Server Scan Rate
OPC_PROP_UNIT: int = 7          # Engineering Units
OPC_PROP_DESC: int = 8          # Description
OPC_PROP_EUINFO: int = 100      # EU Info / Range

# Standard CLSIDs
CLSID_CscapeOpcDaServer: str = "{A4B3C2D1-1390-4821-A494-00C04F68C315}"
CLSID_LegacyHornerDcomServer: str = "{D4E5F6A1-1391-4821-A494-00C04F68C316}"
CLSID_OpcServerList: str = "{13486D51-4821-11D2-A494-3CB306C2F108}"

# Standard IIDs
IID_IUnknown: str = "{00000000-0000-0000-C000-000000000046}"
IID_IOPCServer: str = "{39C13A4D-011E-11D0-9675-0020AFD8ADB3}"
IID_IOPCServerPublicGroups: str = "{39C13A4E-011E-11D0-9675-0020AFD8ADB3}"
IID_IOPCBrowseServerAddressSpace: str = "{39C13A4F-011E-11D0-9675-0020AFD8ADB3}"
IID_IOPCGroupStateMgt: str = "{39C13A50-011E-11D0-9675-0020AFD8ADB3}"
IID_IOPCItemMgt: str = "{39C13A54-011E-11D0-9675-0020AFD8ADB3}"
IID_IOPCSyncIO: str = "{39C13A52-011E-11D0-9675-0020AFD8ADB3}"
IID_IOPCAsyncIO2: str = "{39C13A71-011E-11D0-9675-0020AFD8ADB3}"
IID_IOPCItemProperties: str = "{39227004-4F8F-431F-9F0D-2EC8140CE537}"
IID_IConnectionPointContainer: str = "{B196B284-BAB4-101A-B69C-00AA00341D07}"
IID_IOPCCommon: str = "{F31EE997-3764-11D3-9F53-0000F875A661}"

KNOWN_PROG_IDS: Dict[str, str] = {
    "Horner.Cscape.OPCDA": CLSID_CscapeOpcDaServer,
    "Horner.Cscape.OPCDAServer.1": CLSID_CscapeOpcDaServer,
    "Horner.Legacy.DCOM": CLSID_LegacyHornerDcomServer,
    "OPC.ServerList": CLSID_OpcServerList,
}

DEFAULT_PROGID_HORNER: str = "Horner.Cscape.OPCDA"

KNOWN_CLSIDS: Dict[str, str] = {
    CLSID_CscapeOpcDaServer: "Horner Cscape OPC DA 2.05a / 3.0 Server",
    CLSID_LegacyHornerDcomServer: "Horner Legacy COM/DCOM Bridge Server",
    CLSID_OpcServerList: "OPC Foundation Server List Enumerator",
}


# ============================================================================
# 2. Enums, Status Flags, & Diagnostic Codes
# ============================================================================

class OpcDaDiagnosticCode(IntEnum):
    """Horner OCS %R1397 Diagnostic Event Codes for OPC DA / XML-DA Bridge (W178)."""
    OK                            = 0x0000  # Normal healthy bridge operation
    OPC_ERR_DCOM_RPC_DISCONNECT   = 0xCB01  # RPC connection lost to OPC server
    OPC_ERR_GROUP_UPDATE_TIMEOUT  = 0xCB02  # Asynchronous subscription update timeout > 2500ms
    OPC_ERR_ITEM_BAD_QUALITY      = 0xCB03  # Critical process items returned BAD quality status 0x00
    OPC_ERR_INVALID_CLSID         = 0xCB04  # Server CLSID resolution failure or COM registration missing

    # Convenience aliases
    DCOM_RPC_DISCONNECT           = 0xCB01
    GROUP_UPDATE_TIMEOUT          = 0xCB02
    ITEM_BAD_QUALITY              = 0xCB03
    INVALID_CLSID                 = 0xCB04
    UPDATE_TIMEOUT                = 0xCB02
    BAD_QUALITY                   = 0xCB03
    ERR_DCOM_RPC_DISCONNECT       = 0xCB01
    ERR_GROUP_UPDATE_TIMEOUT      = 0xCB02
    ERR_ITEM_BAD_QUALITY          = 0xCB03
    ERR_INVALID_CLSID             = 0xCB04
    ERR_UPDATE_TIMEOUT            = 0xCB02
    ERR_BAD_QUALITY               = 0xCB03
    OPC_DA_ERR_DCOM_RPC_DISCONNECT = 0xCB01
    OPC_DA_ERR_UPDATE_TIMEOUT     = 0xCB02
    OPC_DA_ERR_BAD_QUALITY        = 0xCB03
    OPC_DA_ERR_INVALID_CLSID      = 0xCB04


DiagnosticStatusCode = OpcDaDiagnosticCode

# Module-level Diagnostic Constants
OPC_ERR_DCOM_RPC_DISCONNECT: int = 0xCB01
OPC_ERR_GROUP_UPDATE_TIMEOUT: int = 0xCB02
OPC_ERR_ITEM_BAD_QUALITY: int = 0xCB03
OPC_ERR_INVALID_CLSID: int = 0xCB04
OPC_DA_ERR_DCOM_RPC_DISCONNECT: int = 0xCB01
OPC_DA_ERR_UPDATE_TIMEOUT: int = 0xCB02
OPC_DA_ERR_BAD_QUALITY: int = 0xCB03
OPC_DA_ERR_INVALID_CLSID: int = 0xCB04
DCOM_RPC_DISCONNECT: int = 0xCB01
GROUP_UPDATE_TIMEOUT: int = 0xCB02
ITEM_BAD_QUALITY: int = 0xCB03
UPDATE_TIMEOUT: int = 0xCB02
BAD_QUALITY: int = 0xCB03
INVALID_CLSID: int = 0xCB04


class OpcGatewayState(IntEnum):
    """OPC DA / XML-DA Gateway Operating State Machine."""
    OPC_DA_IDLE         = 0  # Initialized, no server connected, bridge idle
    CONNECTING          = 1  # COM/DCOM handshake or XML-DA endpoint resolution in progress
    GROUP_ACTIVE        = 2  # Groups established, subscription polling and monitoring active
    ASYNC_TRANSACTION   = 3  # Executing asynchronous read/write transaction or XML-DA request
    DCOM_RECONNECT      = 4  # Recovering from RPC drop; backoff and reconnecting
    OPC_FAULT           = 5  # Latched diagnostic fault condition (disconnect, timeout, bad quality, CLSID)


class OpcBridgeStateBits(IntFlag):
    """Horner OCS %R1395 OpcBridgeStateWord Bitmask Definitions."""
    SERVER_CONNECTED       = 1 << 0   # Bit 0 (0x0001): DCOM server connection active
    GROUPS_ACTIVE          = 1 << 1   # Bit 1 (0x0002): At least 1 active group
    SUBSCRIPTION_POLLING   = 1 << 2   # Bit 2 (0x0004): Subscription polling active
    STATE_BIT_0            = 1 << 3   # Bit 3 (0x0008): State enum bit 0
    STATE_BIT_1            = 1 << 4   # Bit 4 (0x0010): State enum bit 1
    STATE_BIT_2            = 1 << 5   # Bit 5 (0x0020): State enum bit 2
    ASYNC_TX_IN_PROGRESS   = 1 << 6   # Bit 6 (0x0040): Async transaction in progress
    DCOM_RECONNECTING      = 1 << 7   # Bit 7 (0x0080): Reconnection backoff timer active
    XML_DA_ACTIVE          = 1 << 8   # Bit 8 (0x0100): XML-DA HTTP/SOAP bridge active
    PERMISSIVE             = 1 << 9   # Bit 9 (0x0200): OpcDaBridgePermissive (%M324)
    FAULT_TRIP             = 1 << 10  # Bit 10 (0x0400): OpcDaBridgeFaultTrip (%M325)
    RPC_DISCONNECT_FAULT   = 1 << 11  # Bit 11 (0x0800): 0xCB01 active
    GROUP_TIMEOUT_FAULT    = 1 << 12  # Bit 12 (0x1000): 0xCB02 active
    ITEM_BAD_QUALITY_FAULT = 1 << 13  # Bit 13 (0x2000): 0xCB03 active
    INVALID_CLSID_FAULT    = 1 << 14  # Bit 14 (0x4000): 0xCB04 active
    QUALITY_DEGRADED       = 1 << 15  # Bit 15 (0x8000): Non-good quality detected


# ============================================================================
# 3. Protocol Exceptions
# ============================================================================

class OpcDaBridgeError(Exception):
    """Base exception for OPC DA / XML-DA Bridge faults."""
    pass


class OpcDcomRpcDisconnectError(OpcDaBridgeError):
    """Raised when RPC connection to legacy COM/DCOM server is lost (0xCB01)."""
    pass


class OpcGroupUpdateTimeoutError(OpcDaBridgeError):
    """Raised when asynchronous subscription group updates time out (>2500ms) (0xCB02)."""
    pass


class OpcItemBadQualityError(OpcDaBridgeError):
    """Raised when critical process items report BAD quality (0x00) (0xCB03)."""
    pass


class OpcInvalidClsidError(OpcDaBridgeError):
    """Raised when server CLSID resolution fails or COM registration is missing (0xCB04)."""
    pass


class OpcGroupCapacityError(OpcDaBridgeError):
    """Raised when group creation exceeds maximum capacity of 16 groups."""
    pass


class OpcInvalidHandleError(OpcDaBridgeError):
    """Raised when invalid group or item handle is specified (0xC0040001)."""
    pass


class OpcBadTypeError(OpcDaBridgeError):
    """Raised when requested variant data type cannot be converted (0xC0040004)."""
    pass


# Convenience Aliases
DcomRpcDisconnectError = OpcDcomRpcDisconnectError
GroupUpdateTimeoutError = OpcGroupUpdateTimeoutError
ItemBadQualityError = OpcItemBadQualityError
InvalidClsidError = OpcInvalidClsidError
GroupCapacityError = OpcGroupCapacityError
InvalidHandleError = OpcInvalidHandleError
BadTypeError = OpcBadTypeError

OpcDaDcomRpcDisconnectError = OpcDcomRpcDisconnectError
OpcDaUpdateTimeoutError = OpcGroupUpdateTimeoutError
OpcDaBadQualityError = OpcItemBadQualityError
OpcDaInvalidClsidError = OpcInvalidClsidError
UpdateTimeoutError = OpcGroupUpdateTimeoutError
BadQualityError = OpcItemBadQualityError


# ============================================================================
# 4. Helper Functions for RegisterTable Access
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


def resolve_clsid(identifier: str) -> str:
    """Resolve ProgID or CLSID string into a validated COM CLSID.

    Args:
        identifier: ProgID (e.g. 'Horner.Cscape.OPCDA') or CLSID string.

    Returns:
        Formatted GUID CLSID string.

    Raises:
        OpcInvalidClsidError: If identifier is not in the registry.
    """
    ident = identifier.strip()
    if ident in KNOWN_PROG_IDS:
        return KNOWN_PROG_IDS[ident]

    if ident in KNOWN_CLSIDS:
        return ident

    # Check GUID format {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
    guid_pattern = re.compile(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
    if guid_pattern.match(ident):
        # Unregistered CLSID
        raise OpcInvalidClsidError(f"CLSID {ident} is not registered in COM registry (REGDB_E_CLASSNOTREG).")

    raise OpcInvalidClsidError(f"ProgID/CLSID '{ident}' resolution failed: Not found in COM/DCOM registry.")


def resolve_progid(identifier: str) -> str:
    """Convenience alias for resolve_clsid."""
    return resolve_clsid(identifier)


def validate_clsid_format(identifier: str) -> bool:
    """Validate standard GUID format."""
    guid_pattern = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")
    return bool(guid_pattern.match(identifier.strip()))


def is_good_quality(quality: int) -> bool:
    """Check if OPC quality code indicates Good (0xC0)."""
    return (int(quality) & OPC_QUALITY_MASK) == OPC_QUALITY_GOOD


def is_bad_quality(quality: int) -> bool:
    """Check if OPC quality code indicates Bad (0x00)."""
    return (int(quality) & OPC_QUALITY_MASK) == OPC_QUALITY_BAD


def is_uncertain_quality(quality: int) -> bool:
    """Check if OPC quality code indicates Uncertain (0x40)."""
    return (int(quality) & OPC_QUALITY_MASK) == OPC_QUALITY_UNCERTAIN


def evaluate_quality_summary(qualities: Sequence[int]) -> int:
    """Evaluate composite quality across items: Bad (0x00) if any bad, Uncertain (0x40) if any uncertain, else Good (0xC0)."""
    if not qualities:
        return OPC_QUALITY_GOOD
    has_bad = False
    has_uncertain = False
    for q in qualities:
        if is_bad_quality(q):
            has_bad = True
        elif is_uncertain_quality(q):
            has_uncertain = True
    if has_bad:
        return OPC_QUALITY_BAD
    if has_uncertain:
        return OPC_QUALITY_UNCERTAIN
    return OPC_QUALITY_GOOD


def format_hresult(hresult: int) -> str:
    """Format COM HRESULT into hex string and description."""
    hr_u32 = int(hresult) & 0xFFFFFFFF
    desc = {
        S_OK: "S_OK: Success",
        S_FALSE: "S_FALSE: Partial success",
        E_FAIL: "E_FAIL: Unspecified error",
        E_INVALIDARG: "E_INVALIDARG: Invalid argument",
        E_NOINTERFACE: "E_NOINTERFACE: Interface not supported",
        REGDB_E_CLASSNOTREG: "REGDB_E_CLASSNOTREG: Class not registered",
        RPC_E_DISCONNECTED: "RPC_E_DISCONNECTED: RPC disconnected",
        RPC_E_SERVER_DIED: "RPC_E_SERVER_DIED: RPC server died",
        RPC_E_CALL_FAILED: "RPC_E_CALL_FAILED: RPC call failed",
        OPC_E_INVALIDHANDLE: "OPC_E_INVALIDHANDLE: Invalid handle",
        OPC_E_BADTYPE: "OPC_E_BADTYPE: Requested variant type cannot be converted",
        OPC_E_UNKNOWNITEMID: "OPC_E_UNKNOWNITEMID: Unknown item ID",
        OPC_E_INVALIDFILTER: "OPC_E_INVALIDFILTER: Invalid filter",
        OPC_S_UNSUPPORTEDRATE: "OPC_S_UNSUPPORTEDRATE: Unsupported rate",
        OPC_S_CLAMP: "OPC_S_CLAMP: Clamped value",
    }.get(hr_u32, "UNKNOWN_HRESULT")
    return f"0x{hr_u32:08X} ({desc})"


def extract_hresult_word(hresult: int) -> int:
    """Extract lower 16-bit word from HRESULT."""
    return int(hresult) & 0xFFFF


# ============================================================================
# 5. Data Containers: Items, Groups, Transactions, and Address Space
# ============================================================================

@dataclass
class OpcItem:
    """OPC Data Access Monitored Item representation."""
    item_id: str
    client_handle: int
    server_handle: int
    active: bool = True
    canonical_data_type: int = VT_R4
    requested_data_type: int = VT_EMPTY
    access_rights: int = OPC_READABLE | OPC_WRITEABLE
    value: Any = 0.0
    quality: int = OPC_QUALITY_GOOD
    timestamp: float = field(default_factory=time.time)
    eu_type: int = 1  # 0=None, 1=Analog, 2=Enumerated
    eu_info: Union[str, Tuple[float, float]] = (0.0, 100.0)
    is_critical: bool = False
    last_published_value: Any = 0.0
    deadband_pct: float = 0.0
    register_binding: Optional[str] = None  # e.g. '%R1000' or '%M100'


@dataclass
class OpcGroup:
    """OPC Data Access Group container managing collection of monitored items."""
    name: str
    active: bool = True
    update_rate_ms: int = DEFAULT_GROUP_UPDATE_RATE_MS
    percent_deadband: float = 0.0
    client_handle: int = 1
    server_handle: int = 1
    time_bias: int = 0
    lcid: int = 1033  # English (United States)
    items: Dict[int, OpcItem] = field(default_factory=dict)  # Keyed by server_handle
    items_by_client: Dict[int, OpcItem] = field(default_factory=dict)
    items_by_id: Dict[str, OpcItem] = field(default_factory=dict)
    time_since_last_update_ms: float = 0.0
    last_update_timestamp: float = field(default_factory=time.time)

    def add_item(self, item: OpcItem) -> None:
        """Add item to group."""
        self.items[item.server_handle] = item
        self.items_by_client[item.client_handle] = item
        self.items_by_id[item.item_id] = item

    def remove_item(self, server_handle: int) -> Optional[OpcItem]:
        """Remove item by server handle."""
        item = self.items.pop(server_handle, None)
        if item:
            self.items_by_client.pop(item.client_handle, None)
            self.items_by_id.pop(item.item_id, None)
        return item

    def evaluate_deadband(self, item: OpcItem, new_val: Any) -> bool:
        """Evaluate if value change exceeds group/item deadband threshold.

        Returns True if change exceeds deadband (publish required), False if filtered out.
        """
        if self.percent_deadband <= 0.0 and item.deadband_pct <= 0.0:
            return True

        pct = item.deadband_pct if item.deadband_pct > 0.0 else self.percent_deadband
        try:
            val_f = float(new_val)
            last_f = float(item.last_published_value)
            diff = abs(val_f - last_f)

            if isinstance(item.eu_info, (tuple, list)) and len(item.eu_info) == 2:
                low_span, high_span = float(item.eu_info[0]), float(item.eu_info[1])
                span = abs(high_span - low_span)
                if span > 0.0:
                    change_pct = (diff / span) * 100.0
                    return change_pct >= pct

            # Fallback to relative change
            base = abs(last_f) if last_f != 0.0 else 1.0
            return (diff / base) * 100.0 >= pct
        except (ValueError, TypeError):
            # Non-numeric items (e.g. BOOL, STRING) cannot be deadband-filtered
            return new_val != item.last_published_value


@dataclass
class OpcDaTransaction:
    """OPC DA Synchronous or Asynchronous Transaction descriptor."""
    transaction_id: int
    group_handle: int
    transaction_type: str  # 'SYNC_READ', 'SYNC_WRITE', 'ASYNC_READ', 'ASYNC_WRITE'
    item_handles: List[int]
    values: Optional[List[Any]] = None
    qualities: Optional[List[int]] = None
    timestamps: Optional[List[float]] = None
    errors: List[int] = field(default_factory=list)  # HRESULTs
    latency_ms: float = NOMINAL_TRANSACTION_LATENCY_MS
    status: str = "COMPLETED"


@dataclass
class OpcAddressSpaceNode:
    """Node in hierarchical or flat address space."""
    name: str
    node_type: str  # 'branch' or 'leaf'
    item_id: Optional[str] = None
    canonical_data_type: int = VT_R4
    access_rights: int = OPC_READABLE | OPC_WRITEABLE
    eu_type: int = 1
    eu_info: Union[str, Tuple[float, float]] = (0.0, 100.0)
    description: str = ""
    children: Dict[str, OpcAddressSpaceNode] = field(default_factory=dict)


# ============================================================================
# 6. Pure IEC 61131-3 Structured Text (ST) POUs
# ============================================================================

OPC_DA_XML_BRIDGE_SYNC_POU: str = """PROGRAM OpcDaXmlBridgeSync
VAR
    (* Horner OCS Mapped Registers (W178 - OPC DA / XML-DA Protocol Wrapper & Legacy COM/DCOM Bridge) *)
    ConnectedOpcGroupsCount         AT %R1390 : INT;    (* Connected active OPC groups count (0..16) *)
    ActiveOpcItemsCount             AT %R1391 : INT;    (* Total active monitored items (e.g. 64) *)
    OpcDaTransactionLatencyMsScaled AT %R1392 : INT;    (* Transaction latency scaled x10 ms (e.g. 35 = 3.5 ms) *)
    OpcItemQualityCodeWord          AT %R1393 : UINT;   (* OPC Quality Code Word (0x00C0 = GOOD) *)
    DcomReconnectFailuresCount      AT %R1394 : INT;    (* Accumulated DCOM reconnect failures *)
    OpcBridgeStateWord              AT %R1395 : INT;    (* Gateway state bitmask and COM/DCOM status *)
    OpcGroupUpdateRateMs            AT %R1396 : INT;    (* Nominal group update rate in ms (50, 100, 500, 1000) *)
    DiagnosticStatusCode            AT %R1397 : UINT;   (* Diagnostic event code (0x0000, 0xCB01..0xCB04) *)

    (* Discrete Process Safety Interlocks *)
    OpcDaBridgePermissive           AT %M324  : BOOL;   (* TRUE when OPC DA / XML-DA bridge healthy *)
    OpcDaBridgeFaultTrip            AT %M325  : BOOL;   (* TRUE on RPC disconnect, update timeout, bad quality, or invalid CLSID *)
END_VAR
VAR
    BridgeHealthy                   : BOOL;
END_VAR

IF OpcDaBridgeFaultTrip OR (DiagnosticStatusCode <> 0) THEN
    OpcDaBridgePermissive := FALSE;
    OpcDaBridgeFaultTrip := TRUE;
    BridgeHealthy := FALSE;
ELSIF OpcDaBridgePermissive THEN
    BridgeHealthy := TRUE;
    DiagnosticStatusCode := 0;
ELSE
    BridgeHealthy := FALSE;
END_IF;

IF (ActiveOpcItemsCount > 0) AND (OpcItemQualityCodeWord = 0) THEN
    DiagnosticStatusCode := 51971; (* 0xCB03: OPC_ERR_ITEM_BAD_QUALITY *)
    OpcDaBridgePermissive := FALSE;
    OpcDaBridgeFaultTrip := TRUE;
ELSIF OpcDaTransactionLatencyMsScaled > 25000 THEN
    DiagnosticStatusCode := 51970; (* 0xCB02: OPC_ERR_GROUP_UPDATE_TIMEOUT *)
    OpcDaBridgePermissive := FALSE;
    OpcDaBridgeFaultTrip := TRUE;
END_IF;
END_PROGRAM
"""

LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU: str = OPC_DA_XML_BRIDGE_SYNC_POU.replace(
    "PROGRAM OpcDaXmlBridgeSync", "PROGRAM LegacyComDcomOpcBridgeSync"
)

# POU Aliases
PURE_ST_POU: str = OPC_DA_XML_BRIDGE_SYNC_POU
OPC_DA_BRIDGE_POU: str = OPC_DA_XML_BRIDGE_SYNC_POU
OPC_DA_BRIDGE_SYNC_POU: str = OPC_DA_XML_BRIDGE_SYNC_POU
LEGACY_COM_DCOM_POU: str = LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU


def verify_opc_da_bridge_pure_st() -> bool:
    """Validate OPC DA / XML-DA Bridge POUs for strict IEC 61131-3 syntax and anti-ladder safety.

    Returns:
        True if all checks pass deterministically.
    """
    SecurityGuard.assert_pure_st_content(OPC_DA_XML_BRIDGE_SYNC_POU)
    SecurityGuard.assert_pure_st_content(LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU)

    res1 = STParser.validate_code(OPC_DA_XML_BRIDGE_SYNC_POU)
    if res1.status != AgentStatus.SUCCESS:
        return False

    res2 = STParser.validate_code(LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU)
    if res2.status != AgentStatus.SUCCESS:
        return False

    ast1 = STParser.parse_pou(OPC_DA_XML_BRIDGE_SYNC_POU)
    ast2 = STParser.parse_pou(LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU)

    expected_regs = {
        "%R1390", "%R1391", "%R1392", "%R1393",
        "%R1394", "%R1395", "%R1396", "%R1397",
        "%M324", "%M325",
    }
    return set(ast1.bound_registers) == expected_regs and set(ast2.bound_registers) == expected_regs


# ============================================================================
# 7. COM / DCOM Interface & Address Space Implementation
# ============================================================================

class ComInterfaceEmulation:
    """Emulates COM QueryInterface, AddRef, and Release mechanism."""

    SUPPORTED_IIDS: Set[str] = {
        IID_IUnknown,
        IID_IOPCServer,
        IID_IOPCServerPublicGroups,
        IID_IOPCBrowseServerAddressSpace,
        IID_IOPCGroupStateMgt,
        IID_IOPCItemMgt,
        IID_IOPCSyncIO,
        IID_IOPCAsyncIO2,
        IID_IOPCItemProperties,
        IID_IConnectionPointContainer,
        IID_IOPCCommon,
    }

    def __init__(self) -> None:
        self.ref_count: int = 1

    def add_ref(self) -> int:
        self.ref_count += 1
        return self.ref_count

    def release(self) -> int:
        self.ref_count = max(0, self.ref_count - 1)
        return self.ref_count

    def query_interface(self, iid: str) -> Tuple[int, Optional[Any]]:
        """Emulate IUnknown::QueryInterface."""
        if iid in self.SUPPORTED_IIDS:
            self.add_ref()
            return S_OK, self
        return E_NOINTERFACE, None


class OpcAddressSpace:
    """Hierarchical and flat OPC address space model for Horner OCS & Plant."""

    def __init__(self) -> None:
        self.root = OpcAddressSpaceNode(name="Root", node_type="branch")
        self._items_flat: Dict[str, OpcAddressSpaceNode] = {}
        self._current_path: List[str] = []
        self._populate_standard_hierarchy()

    def _populate_standard_hierarchy(self) -> None:
        """Populate standard Horner OCS and industrial process branches."""
        # Branch: HornerOCS
        horner_branch = OpcAddressSpaceNode(name="HornerOCS", node_type="branch")
        self.root.children["HornerOCS"] = horner_branch

        hr_branch = OpcAddressSpaceNode(name="HoldingRegisters", node_type="branch")
        horner_branch.children["HoldingRegisters"] = hr_branch
        for r in range(1000, 1032):
            node = OpcAddressSpaceNode(
                name=f"%R{r}",
                node_type="leaf",
                item_id=f"HornerOCS.HoldingRegisters.%R{r}",
                canonical_data_type=VT_I2,
                access_rights=OPC_READABLE | OPC_WRITEABLE,
                eu_type=1,
                eu_info=(0.0, 32767.0),
                description=f"Horner OCS 16-bit register %R{r}",
            )
            hr_branch.children[f"%R{r}"] = node
            self._items_flat[node.item_id] = node

        # Branch: ProcessUnits
        proc_branch = OpcAddressSpaceNode(name="ProcessUnits", node_type="branch")
        self.root.children["ProcessUnits"] = proc_branch

        furnace_branch = OpcAddressSpaceNode(name="Furnace", node_type="branch")
        proc_branch.children["Furnace"] = furnace_branch
        for item_name, unit, r_min, r_max in [
            ("Zone1Temp", "degC", 0.0, 1200.0),
            ("Zone2Temp", "degC", 0.0, 1200.0),
            ("GasFlow", "Nm3/h", 0.0, 500.0),
            ("FurnacePressure", "mbar", -50.0, 50.0),
        ]:
            item_id = f"ProcessUnits.Furnace.{item_name}"
            node = OpcAddressSpaceNode(
                name=item_name,
                node_type="leaf",
                item_id=item_id,
                canonical_data_type=VT_R4,
                access_rights=OPC_READABLE | OPC_WRITEABLE,
                eu_type=1,
                eu_info=(r_min, r_max),
                description=f"Industrial Furnace {item_name}",
            )
            furnace_branch.children[item_name] = node
            self._items_flat[item_id] = node

        # Branch: Diagnostics
        diag_branch = OpcAddressSpaceNode(name="Diagnostics", node_type="branch")
        self.root.children["Diagnostics"] = diag_branch
        for diag_name, vt in [
            ("BridgePermissive", VT_BOOL),
            ("BridgeFaultTrip", VT_BOOL),
            ("LatencyMsScaled", VT_I2),
            ("QualityWord", VT_UI2),
        ]:
            item_id = f"Diagnostics.{diag_name}"
            node = OpcAddressSpaceNode(
                name=diag_name,
                node_type="leaf",
                item_id=item_id,
                canonical_data_type=vt,
                access_rights=OPC_READABLE,
                eu_type=0,
                eu_info="None",
                description=f"OPC Bridge Diagnostic {diag_name}",
            )
            diag_branch.children[diag_name] = node
            self._items_flat[item_id] = node

    def change_browse_position(self, direction: int, branch_name: Optional[str] = None) -> int:
        """Emulate IOPCBrowseServerAddressSpace::ChangeBrowsePosition."""
        if direction == OPC_BROWSE_UP:
            if self._current_path:
                self._current_path.pop()
            return S_OK
        elif direction == OPC_BROWSE_TO:
            self._current_path = []
            return S_OK
        elif direction == OPC_BROWSE_DOWN:
            if not branch_name:
                return E_INVALIDARG
            curr_node = self._get_node_at_path(self._current_path)
            if curr_node and branch_name in curr_node.children and curr_node.children[branch_name].node_type == "branch":
                self._current_path.append(branch_name)
                return S_OK
            return OPC_E_INVALIDFILTER
        return E_INVALIDARG

    def _get_node_at_path(self, path: List[str]) -> Optional[OpcAddressSpaceNode]:
        node = self.root
        for part in path:
            if part in node.children:
                node = node.children[part]
            else:
                return None
        return node

    def browse_item_ids(self, browse_type: int = OPC_FLAT, filter_criteria: str = "") -> List[str]:
        """Emulate IOPCBrowseServerAddressSpace::BrowseOPCItemIDs."""
        if browse_type == OPC_FLAT:
            return sorted([
                k for k in self._items_flat.keys()
                if not filter_criteria or filter_criteria in k
            ])

        curr_node = self._get_node_at_path(self._current_path)
        if not curr_node:
            return []

        results: List[str] = []
        target_type = "branch" if browse_type == OPC_BRANCH else "leaf"
        for name, child in curr_node.children.items():
            if child.node_type == target_type:
                if not filter_criteria or filter_criteria in name:
                    results.append(child.item_id if child.item_id else name)
        return sorted(results)

    def get_item_properties(self, item_id: str) -> Dict[int, Any]:
        """Emulate IOPCItemProperties::GetItemProperties."""
        node = self._items_flat.get(item_id)
        if not node:
            return {}

        return {
            OPC_PROP_CDT: node.canonical_data_type,
            OPC_PROP_VALUE: 0.0,
            OPC_PROP_QUALITY: OPC_QUALITY_GOOD,
            OPC_PROP_TIME: time.time(),
            OPC_PROP_RIGHTS: node.access_rights,
            OPC_PROP_SCANRATE: 100,
            OPC_PROP_UNIT: node.eu_info if isinstance(node.eu_info, str) else "Units",
            OPC_PROP_DESC: node.description,
            OPC_PROP_EUINFO: node.eu_info,
        }


# ============================================================================
# 8. XML-DA 1.01 SOAP Serialization & Marshaling Engine
# ============================================================================

class XmlDaBridge:
    """OPC XML-DA 1.01 SOAP envelope serialization and web services bridge."""

    SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
    XMLDA_NS = "http://opcfoundation.org/webservices/XMLDA/1.0/"

    def __init__(self, bridge_engine: OpcDaBridgeEngine) -> None:
        self.bridge: OpcDaBridgeEngine = bridge_engine
        self._subscriptions: Dict[str, Dict[str, Any]] = {}
        self._subscription_counter: int = 1000

    def format_soap_envelope(self, body_xml: str) -> str:
        """Wrap XML-DA response body within standard SOAP 1.1 envelope."""
        return (
            f'<?xml version="1.0" encoding="utf-8"?>\n'
            f'<SOAP-ENV:Envelope xmlns:SOAP-ENV="{self.SOAP_NS}" '
            f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            f'xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n'
            f'  <SOAP-ENV:Body>\n'
            f'    {body_xml}\n'
            f'  </SOAP-ENV:Body>\n'
            f'</SOAP-ENV:Envelope>'
        )

    def get_status(self) -> Dict[str, Any]:
        """XML-DA GetStatus service call."""
        status_data = {
            "StatusInfo": "Healthy",
            "VendorInfo": "Horner APG Cscape OPC DA / XML-DA Engine",
            "ServerState": "running" if self.bridge.permissive else "fault",
            "SupportedLocaleIDs": ["en-US"],
            "ProductVersion": "10.2.751.4 (XML-DA 1.01)",
            "StartTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.bridge.start_time)),
        }
        return status_data

    def read(self, item_paths: List[str]) -> Dict[str, Any]:
        """XML-DA Read service call."""
        results: List[Dict[str, Any]] = []
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        for path in item_paths:
            item = self.bridge.find_item_by_id(path)
            if item:
                results.append({
                    "ItemName": path,
                    "Value": item.value,
                    "Quality": "good" if item.quality == OPC_QUALITY_GOOD else ("uncertain" if item.quality == OPC_QUALITY_UNCERTAIN else "bad"),
                    "QualityCode": item.quality,
                    "Timestamp": now_str,
                    "ResultID": "S_OK",
                })
            else:
                results.append({
                    "ItemName": path,
                    "Value": None,
                    "Quality": "bad",
                    "QualityCode": OPC_QUALITY_BAD,
                    "Timestamp": now_str,
                    "ResultID": "OPC_E_UNKNOWNITEMID",
                })
        return {"Items": results}

    def write(
        self,
        item_values: Union[List[Tuple[str, Any]], List[str]],
        values: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """XML-DA Write service call."""
        if values is not None:
            pairs = list(zip(item_values, values))
        elif item_values and isinstance(item_values[0], tuple):
            pairs = list(item_values)  # type: ignore[arg-type]
        else:
            pairs = [(p, 0) for p in item_values]  # type: ignore[misc]

        results: List[Dict[str, Any]] = []
        errors: List[int] = []
        for path, val in pairs:
            item = self.bridge.find_item_by_id(path)
            if item:
                item.value = val
                item.last_published_value = val
                item.timestamp = time.time()
                # Update RegisterTable if mapped
                if item.register_binding:
                    if item.register_binding.startswith("%R"):
                        safe_write_word(self.bridge.reg_table, item.register_binding, int(val))
                    elif item.register_binding.startswith("%M"):
                        safe_write_bit(self.bridge.reg_table, item.register_binding, bool(val))
                results.append({"ItemName": path, "ResultID": "S_OK"})
                errors.append(S_OK)
            else:
                results.append({"ItemName": path, "ResultID": "OPC_E_UNKNOWNITEMID"})
                errors.append(OPC_E_UNKNOWNITEMID)
        return {"Items": results, "Errors": errors}

    def browse(self, item_path: str = "") -> Dict[str, Any]:
        """XML-DA Browse service call."""
        flat_items = self.bridge.address_space.browse_item_ids(OPC_FLAT, item_path)
        elements = [
            {"ItemName": name, "IsItem": True, "HasChildren": False}
            for name in flat_items
        ]
        return {"Elements": elements}

    def subscribe(self, item_paths: List[str], requested_sampling_rate_ms: int = 100) -> str:
        """XML-DA Subscribe service call."""
        self._subscription_counter += 1
        sub_id = f"SUB-{self._subscription_counter}"
        self._subscriptions[sub_id] = {
            "items": item_paths,
            "sampling_rate_ms": requested_sampling_rate_ms,
            "last_values": {},
        }
        return sub_id

    def subscription_polled_refresh(self, subscription_id: str) -> List[Dict[str, Any]]:
        """XML-DA SubscriptionPolledRefresh service call."""
        sub = self._subscriptions.get(subscription_id)
        if not sub:
            return []

        modified: List[Dict[str, Any]] = []
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for path in sub["items"]:
            item = self.bridge.find_item_by_id(path)
            if item:
                last_val = sub["last_values"].get(path)
                if last_val != item.value:
                    sub["last_values"][path] = item.value
                    modified.append({
                        "ItemName": path,
                        "Value": item.value,
                        "Quality": "good" if item.quality == OPC_QUALITY_GOOD else "bad",
                        "Timestamp": now_str,
                    })
        return modified

    def subscription_cancel(self, subscription_id: str) -> bool:
        """XML-DA SubscriptionCancel service call."""
        return self._subscriptions.pop(subscription_id, None) is not None


# ============================================================================
# 9. OPC DA / XML-DA Protocol Engine & COM Bridge (ILogicUnit)
# ============================================================================

class OpcDaBridgeEngine(ILogicUnit, ComInterfaceEmulation):
    """Industrial OPC DA / XML-DA Protocol Wrapper & Legacy COM/DCOM Bridge Engine.

    Work Package: W178 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
    Classification: PRODUCTION_READY
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        max_groups: int = MAX_OPC_GROUPS,
        nominal_update_rate_ms: int = DEFAULT_GROUP_UPDATE_RATE_MS,
    ) -> None:
        super().__init__()
        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.max_groups: int = max_groups
        self.nominal_group_update_rate_ms: int = nominal_update_rate_ms

        # Start time & Clock
        self.start_time: float = time.time()
        self.elapsed_time_ms: float = 0.0

        # State Machine & Safety Interlocks
        self.state: OpcGatewayState = OpcGatewayState.OPC_DA_IDLE
        self.permissive: bool = True
        self.fault_trip: bool = False
        self.diagnostic_code: OpcDaDiagnosticCode = OpcDaDiagnosticCode.OK

        # COM/DCOM Connectivity
        self.is_rpc_connected: bool = True
        self.server_clsid: Optional[str] = CLSID_CscapeOpcDaServer
        self.reconnect_failures_count: int = 0
        self.reconnecting: bool = False

        # Groups & Monitored Items
        self.groups: Dict[int, OpcGroup] = {}  # Keyed by server_handle
        self.groups_by_name: Dict[str, OpcGroup] = {}
        self._next_group_handle: int = 1
        self._next_item_handle: int = 1

        # Address Space & XML-DA Bridge
        self.address_space: OpcAddressSpace = OpcAddressSpace()
        self.xml_da_bridge: XmlDaBridge = XmlDaBridge(self)
        self.xml_da_enabled: bool = True

        # Telemetry & Latency
        self.transaction_latency_ms: float = NOMINAL_TRANSACTION_LATENCY_MS
        self.latency_scaled: int = NOMINAL_LATENCY_SCALED
        self.item_quality_code: int = OPC_QUALITY_GOOD
        self.subscription_polling: bool = True
        self.async_tx_in_progress: bool = False

        # Async Transactions
        self.active_async_transactions: Dict[int, OpcDaTransaction] = {}
        self._next_cancel_id: int = 5000

        # Populate standard initial monitored group & items (64 items)
        self._initialize_default_group_and_items()

        # Initial register synchronization
        self.sync_to_registers()

    def _initialize_default_group_and_items(self) -> None:
        """Create standard default OPC group with 64 monitored items."""
        group = self.add_group(
            name="HornerOCS_ProcessGroup",
            active=True,
            update_rate_ms=self.nominal_group_update_rate_ms,
            percent_deadband=0.5,
        )

        # 32 items mapped to Horner OCS registers (%R1000..%R1031)
        for r in range(1000, 1032):
            self.add_item_to_group(
                group_handle=group.server_handle,
                item_id=f"HornerOCS.HoldingRegisters.%R{r}",
                canonical_data_type=VT_I2,
                initial_value=0,
                is_critical=False,
                register_binding=f"%R{r}",
            )

        # 16 analog process items (Furnace and Reactor variables)
        process_items = [
            ("ProcessUnits.Furnace.Zone1Temp", 750.5, True, (0.0, 1200.0)),
            ("ProcessUnits.Furnace.Zone2Temp", 745.2, True, (0.0, 1200.0)),
            ("ProcessUnits.Furnace.GasFlow", 120.0, False, (0.0, 500.0)),
            ("ProcessUnits.Furnace.FurnacePressure", 1.2, False, (-50.0, 50.0)),
            ("ProcessUnits.Reactor.Temperature", 185.0, True, (0.0, 300.0)),
            ("ProcessUnits.Reactor.Pressure", 28.5, True, (0.0, 100.0)),
            ("ProcessUnits.Reactor.AgitatorSpeed", 300.0, False, (0.0, 1000.0)),
            ("ProcessUnits.Reactor.LiquidLevel", 65.4, False, (0.0, 100.0)),
            ("ProcessUnits.Boiler.SteamPressure", 45.0, True, (0.0, 100.0)),
            ("ProcessUnits.Boiler.FeedwaterFlow", 80.0, False, (0.0, 200.0)),
            ("ProcessUnits.Chiller.SupplyTemp", 4.5, False, (-10.0, 30.0)),
            ("ProcessUnits.Chiller.ReturnTemp", 9.2, False, (-10.0, 30.0)),
            ("ProcessUnits.Pump1.DischargePressure", 12.0, False, (0.0, 50.0)),
            ("ProcessUnits.Pump2.DischargePressure", 11.8, False, (0.0, 50.0)),
            ("ProcessUnits.Exhaust.CoPpm", 15.0, True, (0.0, 1000.0)),
            ("ProcessUnits.Exhaust.NoxPpm", 22.0, False, (0.0, 500.0)),
        ]
        for p_id, val, crit, eu_span in process_items:
            self.add_item_to_group(
                group_handle=group.server_handle,
                item_id=p_id,
                canonical_data_type=VT_R4,
                initial_value=val,
                is_critical=crit,
                eu_info=eu_span,
            )

        # 16 discrete / coil items
        discrete_items = [
            ("ProcessUnits.Pump1.RunStatus", True, False),
            ("ProcessUnits.Pump2.RunStatus", False, False),
            ("ProcessUnits.Valve1.OpenStatus", True, False),
            ("ProcessUnits.Valve2.OpenStatus", False, False),
            ("ProcessUnits.Burner.IgnitionOn", True, True),
            ("ProcessUnits.Burner.FlameDetected", True, True),
            ("ProcessUnits.Safety.EStopActive", False, True),
            ("ProcessUnits.Safety.GasLeakDetected", False, True),
            ("ProcessUnits.Cooling.Fan1Running", True, False),
            ("ProcessUnits.Cooling.Fan2Running", True, False),
            ("ProcessUnits.Chiller.CompressorOn", True, False),
            ("ProcessUnits.Agitator.MotorOverload", False, True),
            ("ProcessUnits.Feed.ConveyorRunning", True, False),
            ("ProcessUnits.Alarm.HighTempAlarm", False, True),
            ("ProcessUnits.Alarm.LowPressureAlarm", False, True),
            ("ProcessUnits.Alarm.CommonFault", False, True),
        ]
        for d_id, val, crit in discrete_items:
            self.add_item_to_group(
                group_handle=group.server_handle,
                item_id=d_id,
                canonical_data_type=VT_BOOL,
                initial_value=val,
                is_critical=crit,
            )

        self.state = OpcGatewayState.GROUP_ACTIVE

    # ------------------------------------------------------------------------
    # ILogicUnit Properties & Execution
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "opc_da_bridge"

    @property
    def priority(self) -> int:
        return 92

    @property
    def is_enabled(self) -> bool:
        return True

    def execute(self, ctx: ScanContext) -> None:
        """Scan cycle logic evaluation during simulation Phase 2."""
        dt_ms = getattr(ctx, "dt_ms", 1.0)
        self.scan_step(dt=dt_ms / 1000.0)

    def reset(self) -> None:
        """Reset internal bridge state."""
        self.reset_fault(force=True)

    # ------------------------------------------------------------------------
    # State Machine & Scan Step
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.001) -> Dict[str, Any]:
        """Advance deterministic simulation clock and evaluate safety watchdogs.

        Args:
            dt: Scan time delta in seconds.
        """
        dt_ms = dt if dt >= 1.0 else (dt * 1000.0)
        self.elapsed_time_ms += dt_ms

        # 1. Check DCOM RPC connectivity
        if not self.is_rpc_connected:
            self._trip_fault(
                OpcDaDiagnosticCode.OPC_ERR_DCOM_RPC_DISCONNECT,
                "DCOM RPC connection to OPC Server lost (RPC_E_DISCONNECTED 0x80010108)",
            )
            self.state = OpcGatewayState.DCOM_RECONNECT
            self.reconnect_failures_count += 1

        # 2. Check group subscription update timeout (> 2500 ms)
        for group in self.groups.values():
            if group.active:
                group.time_since_last_update_ms += dt_ms
                if group.time_since_last_update_ms > GROUP_UPDATE_TIMEOUT_MS:
                    self._trip_fault(
                        OpcDaDiagnosticCode.OPC_ERR_GROUP_UPDATE_TIMEOUT,
                        f"Group '{group.name}' update timed out ({group.time_since_last_update_ms:.1f}ms > 2500ms)",
                    )
                    break

        # 3. Check quality of all critical process items
        self._evaluate_critical_items_quality()

        # 4. Synchronize memory image
        self.sync_to_registers()

        return {
            "elapsed_ms": self.elapsed_time_ms,
            "groups_count": len(self.groups),
            "items_count": self.get_active_items_count(),
            "permissive": self.permissive,
            "fault_trip": self.fault_trip,
            "diagnostic_code": int(self.diagnostic_code),
        }

    def _evaluate_critical_items_quality(self) -> None:
        """Inspect quality of critical process items and trip 0xCB03 on BAD quality."""
        for group in self.groups.values():
            for item in group.items.values():
                if item.is_critical:
                    # Quality Bad is 0x00
                    if (item.quality & OPC_QUALITY_MASK) == OPC_QUALITY_BAD:
                        self.item_quality_code = item.quality
                        self._trip_fault(
                            OpcDaDiagnosticCode.OPC_ERR_ITEM_BAD_QUALITY,
                            f"Critical process item '{item.item_id}' returned BAD quality status (0x{item.quality:02X})",
                        )
                        return

    def _trip_fault(self, code: OpcDaDiagnosticCode, reason: str) -> None:
        """Trip safety interlock and latch fault condition."""
        self.diagnostic_code = code
        self.permissive = False
        self.fault_trip = True
        self.state = OpcGatewayState.OPC_FAULT

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Perform manual operator reset handshake.

        Args:
            force: If True, forces fault reset and clears trips.
        """
        if not force and (not self.is_rpc_connected):
            return ExecutionResult.failed(
                error_code="RESET_BLOCKED",
                details="Cannot reset fault: RPC is disconnected.",
            )

        self.diagnostic_code = OpcDaDiagnosticCode.OK
        self.permissive = True
        self.fault_trip = False
        self.state = OpcGatewayState.GROUP_ACTIVE if self.groups else OpcGatewayState.OPC_DA_IDLE
        self.reconnecting = False

        # Reset group update watchdog timers
        for group in self.groups.values():
            group.time_since_last_update_ms = 0.0

        # Restore good quality if critical items were fixed
        self.item_quality_code = OPC_QUALITY_GOOD

        self.sync_to_registers()
        return ExecutionResult.success(
            details="OPC DA / XML-DA Bridge fault trip reset successfully.",
            data={"diagnostic_code": 0, "permissive": True},
        )

    # ------------------------------------------------------------------------
    # Group Management (OPC DA 2.05a / 3.0)
    # ------------------------------------------------------------------------

    def add_group(
        self,
        name: str,
        active: bool = True,
        update_rate_ms: int = DEFAULT_GROUP_UPDATE_RATE_MS,
        percent_deadband: float = 0.0,
        client_handle: Optional[int] = None,
    ) -> OpcGroup:
        """Create and add a new OPC Group.

        Raises:
            OpcGroupCapacityError: If maximum 16 groups capacity is exceeded.
        """
        if len(self.groups) >= self.max_groups:
            raise OpcGroupCapacityError(f"Cannot add group '{name}': Maximum capacity of {self.max_groups} groups reached.")

        # Rate clamping / unsupported rate check
        revised_rate = self._clamp_update_rate(update_rate_ms)

        handle = self._next_group_handle
        self._next_group_handle += 1
        c_handle = client_handle if client_handle is not None else handle

        group = OpcGroup(
            name=name,
            active=active,
            update_rate_ms=revised_rate,
            percent_deadband=percent_deadband,
            client_handle=c_handle,
            server_handle=handle,
        )
        self.groups[handle] = group
        self.groups_by_name[name] = group

        self.sync_to_registers()
        return group

    def _clamp_update_rate(self, rate_ms: int) -> int:
        """Find closest supported standard update rate."""
        if rate_ms in STANDARD_UPDATE_RATES_MS:
            return rate_ms
        # Find closest
        return min(STANDARD_UPDATE_RATES_MS, key=lambda x: abs(x - rate_ms))

    def remove_group(self, server_handle: int) -> bool:
        """Remove an OPC group by server handle."""
        group = self.groups.pop(server_handle, None)
        if group:
            self.groups_by_name.pop(group.name, None)
            self.sync_to_registers()
            return True
        return False

    def get_group(self, server_handle: int) -> Optional[OpcGroup]:
        return self.groups.get(server_handle)

    def add_item_to_group(
        self,
        group_handle: int,
        item_id: str,
        canonical_data_type: int = VT_R4,
        initial_value: Any = 0.0,
        is_critical: bool = False,
        eu_info: Union[str, Tuple[float, float]] = (0.0, 100.0),
        register_binding: Optional[str] = None,
        deadband_pct: float = 0.0,
    ) -> OpcItem:
        """Add monitored item to an existing OPC group."""
        group = self.groups.get(group_handle)
        if not group:
            raise OpcInvalidHandleError(f"Group handle {group_handle} not found (OPC_E_INVALIDHANDLE).")

        item_handle = self._next_item_handle
        self._next_item_handle += 1

        item = OpcItem(
            item_id=item_id,
            client_handle=item_handle,
            server_handle=item_handle,
            active=True,
            canonical_data_type=canonical_data_type,
            value=initial_value,
            last_published_value=initial_value,
            quality=OPC_QUALITY_GOOD,
            eu_info=eu_info,
            is_critical=is_critical,
            register_binding=register_binding,
            deadband_pct=deadband_pct,
        )
        group.add_item(item)
        self.sync_to_registers()
        return item

    def get_active_items_count(self) -> int:
        """Count total active monitored items across all groups."""
        return sum(len(g.items) for g in self.groups.values() if g.active)

    def find_item_by_id(self, item_id: str) -> Optional[OpcItem]:
        """Find item across all registered groups."""
        for g in self.groups.values():
            if item_id in g.items_by_id:
                return g.items_by_id[item_id]
        return None

    # ------------------------------------------------------------------------
    # Synchronous & Asynchronous Transactions
    # ------------------------------------------------------------------------

    def sync_read(
        self,
        group_handle: int,
        item_handles: Sequence[int],
        simulated_latency_override_ms: Optional[float] = None,
    ) -> Tuple[List[Any], List[int], List[float], List[int]]:
        """Synchronous read (IOPCSyncIO::Read).

        Returns:
            (values, qualities, timestamps, errors)
        """
        if not self.is_rpc_connected:
            raise OpcDcomRpcDisconnectError("DCOM RPC disconnected (RPC_E_DISCONNECTED 0x80010108).")

        group = self.groups.get(group_handle)
        if not group:
            raise OpcInvalidHandleError(f"Invalid group handle {group_handle} (OPC_E_INVALIDHANDLE).")

        values: List[Any] = []
        qualities: List[int] = []
        timestamps: List[float] = []
        errors: List[int] = []

        now = time.time()
        for h in item_handles:
            item = group.items.get(h)
            if item:
                # If bound to RegisterTable, read live value
                if item.register_binding:
                    if item.register_binding.startswith("%R"):
                        item.value = self.reg_table.read_word(item.register_binding)
                    elif item.register_binding.startswith("%M"):
                        item.value = self.reg_table.read_bit(item.register_binding)

                values.append(item.value)
                qualities.append(item.quality)
                timestamps.append(item.timestamp)
                errors.append(S_OK)
            else:
                values.append(None)
                qualities.append(OPC_QUALITY_BAD)
                timestamps.append(now)
                errors.append(OPC_E_INVALIDHANDLE)

        # Track latency
        lat = simulated_latency_override_ms if simulated_latency_override_ms is not None else NOMINAL_TRANSACTION_LATENCY_MS
        self._record_transaction_latency(lat)

        # Reset group update timer
        group.time_since_last_update_ms = 0.0

        return values, qualities, timestamps, errors

    def sync_write(
        self,
        group_handle: int,
        item_handles: Sequence[int],
        values: Sequence[Any],
        simulated_latency_override_ms: Optional[float] = None,
    ) -> List[int]:
        """Synchronous write (IOPCSyncIO::Write).

        Returns:
            List of HRESULTs for each item.
        """
        if not self.is_rpc_connected:
            raise OpcDcomRpcDisconnectError("DCOM RPC disconnected (RPC_E_DISCONNECTED 0x80010108).")

        group = self.groups.get(group_handle)
        if not group:
            raise OpcInvalidHandleError(f"Invalid group handle {group_handle} (OPC_E_INVALIDHANDLE).")

        errors: List[int] = []
        for h, val in zip(item_handles, values):
            item = group.items.get(h)
            if not item:
                errors.append(OPC_E_INVALIDHANDLE)
                continue

            if not (item.access_rights & OPC_WRITEABLE):
                errors.append(E_FAIL)
                continue

            try:
                # Type validation
                if item.canonical_data_type in (VT_I2, VT_I4, VT_UI2, VT_UI4):
                    val_conv = int(val)
                elif item.canonical_data_type in (VT_R4, VT_R8):
                    val_conv = float(val)
                elif item.canonical_data_type == VT_BOOL:
                    val_conv = bool(val)
                else:
                    val_conv = str(val)

                item.value = val_conv
                item.last_published_value = val_conv
                item.timestamp = time.time()

                # Sync to RegisterTable if mapped
                if item.register_binding:
                    if item.register_binding.startswith("%R"):
                        safe_write_word(self.reg_table, item.register_binding, int(val_conv))
                    elif item.register_binding.startswith("%M"):
                        safe_write_bit(self.reg_table, item.register_binding, bool(val_conv))

                errors.append(S_OK)
            except (ValueError, TypeError):
                errors.append(OPC_E_BADTYPE)

        # Track latency
        lat = simulated_latency_override_ms if simulated_latency_override_ms is not None else NOMINAL_TRANSACTION_LATENCY_MS
        self._record_transaction_latency(lat)

        group.time_since_last_update_ms = 0.0
        return errors

    def async_read(
        self,
        group_handle: int,
        item_handles: Sequence[int],
        transaction_id: Optional[int] = None,
        simulated_latency_override_ms: Optional[float] = None,
    ) -> Tuple[int, OpcDaTransaction]:
        """Asynchronous read (IOPCAsyncIO2::Read).

        Returns:
            (cancel_id, transaction)
        """
        if not self.is_rpc_connected:
            raise OpcDcomRpcDisconnectError("DCOM RPC disconnected (RPC_E_DISCONNECTED 0x80010108).")

        self.state = OpcGatewayState.ASYNC_TRANSACTION
        self.async_tx_in_progress = True

        tx_id = transaction_id or int(time.time() * 1000) & 0xFFFF
        self._next_cancel_id += 1
        cancel_id = self._next_cancel_id

        values, qualities, timestamps, errors = self.sync_read(
            group_handle=group_handle,
            item_handles=item_handles,
            simulated_latency_override_ms=simulated_latency_override_ms,
        )

        tx = OpcDaTransaction(
            transaction_id=tx_id,
            group_handle=group_handle,
            transaction_type="ASYNC_READ",
            item_handles=list(item_handles),
            values=values,
            qualities=qualities,
            timestamps=timestamps,
            errors=errors,
            latency_ms=self.transaction_latency_ms,
            status="COMPLETED",
        )
        self.active_async_transactions[cancel_id] = tx

        self.async_tx_in_progress = False
        self.state = OpcGatewayState.GROUP_ACTIVE
        self.sync_to_registers()
        return cancel_id, tx

    def async_write(
        self,
        group_handle: int,
        item_handles: Sequence[int],
        values: Sequence[Any],
        transaction_id: Optional[int] = None,
        simulated_latency_override_ms: Optional[float] = None,
    ) -> Tuple[int, OpcDaTransaction]:
        """Asynchronous write (IOPCAsyncIO2::Write).

        Returns:
            (cancel_id, transaction)
        """
        if not self.is_rpc_connected:
            raise OpcDcomRpcDisconnectError("DCOM RPC disconnected (RPC_E_DISCONNECTED 0x80010108).")

        self.state = OpcGatewayState.ASYNC_TRANSACTION
        self.async_tx_in_progress = True

        tx_id = transaction_id or int(time.time() * 1000) & 0xFFFF
        self._next_cancel_id += 1
        cancel_id = self._next_cancel_id

        errors = self.sync_write(
            group_handle=group_handle,
            item_handles=item_handles,
            values=values,
            simulated_latency_override_ms=simulated_latency_override_ms,
        )

        tx = OpcDaTransaction(
            transaction_id=tx_id,
            group_handle=group_handle,
            transaction_type="ASYNC_WRITE",
            item_handles=list(item_handles),
            values=list(values),
            errors=errors,
            latency_ms=self.transaction_latency_ms,
            status="COMPLETED",
        )
        self.active_async_transactions[cancel_id] = tx

        self.async_tx_in_progress = False
        self.state = OpcGatewayState.GROUP_ACTIVE
        self.sync_to_registers()
        return cancel_id, tx

    def _record_transaction_latency(self, latency_ms: float) -> None:
        """Update transaction latency tracking registers."""
        self.transaction_latency_ms = float(latency_ms)
        self.latency_scaled = int(round(latency_ms * 10.0))
        safe_write_word(self.reg_table, "%R1392", self.latency_scaled)

    # ------------------------------------------------------------------------
    # COM/DCOM Fault Simulation & Reconnect Lifecycle
    # ------------------------------------------------------------------------

    def simulate_rpc_disconnect(self) -> None:
        """Simulate hardware RPC/DCOM disconnection from remote OPC Server."""
        self.is_rpc_connected = False
        self.reconnecting = True
        self.state = OpcGatewayState.DCOM_RECONNECT
        self._trip_fault(
            OpcDaDiagnosticCode.OPC_ERR_DCOM_RPC_DISCONNECT,
            "Simulated RPC transport disconnection (0xCB01)",
        )
        self.reconnect_failures_count += 1
        self.sync_to_registers()

    def reconnect_dcom(self) -> bool:
        """Simulate DCOM reconnection procedure."""
        self.is_rpc_connected = True
        self.reconnecting = False
        # Permissive and trip remain latched until operator reset handshake
        self.sync_to_registers()
        return True

    def connect_server(self, clsid_or_progid: str) -> bool:
        """Connect to OPC DA server via CLSID or ProgID.

        Raises:
            OpcInvalidClsidError: If CLSID/ProgID cannot be resolved.
        """
        try:
            resolved = resolve_clsid(clsid_or_progid)
            self.server_clsid = resolved
            self.is_rpc_connected = True
            return True
        except OpcInvalidClsidError as e:
            self._trip_fault(
                OpcDaDiagnosticCode.OPC_ERR_INVALID_CLSID,
                f"Failed to connect to server: {e}",
            )
            self.sync_to_registers()
            raise

    # ------------------------------------------------------------------------
    # Horner OCS Register Space Synchronization (%R1390..%R1397, %M324..%M325)
    # ------------------------------------------------------------------------

    def compute_state_word(self) -> int:
        """Compute bitmask for %R1395 OpcBridgeStateWord."""
        mask = 0
        if self.is_rpc_connected:
            mask |= int(OpcBridgeStateBits.SERVER_CONNECTED)
        if any(g.active for g in self.groups.values()):
            mask |= int(OpcBridgeStateBits.GROUPS_ACTIVE)
        if self.subscription_polling:
            mask |= int(OpcBridgeStateBits.SUBSCRIPTION_POLLING)

        # State enum in bits 3..5
        state_val = int(self.state) & 0x7
        if state_val & 1:
            mask |= int(OpcBridgeStateBits.STATE_BIT_0)
        if state_val & 2:
            mask |= int(OpcBridgeStateBits.STATE_BIT_1)
        if state_val & 4:
            mask |= int(OpcBridgeStateBits.STATE_BIT_2)

        if self.async_tx_in_progress:
            mask |= int(OpcBridgeStateBits.ASYNC_TX_IN_PROGRESS)
        if self.reconnecting:
            mask |= int(OpcBridgeStateBits.DCOM_RECONNECTING)
        if self.xml_da_enabled:
            mask |= int(OpcBridgeStateBits.XML_DA_ACTIVE)
        if self.permissive:
            mask |= int(OpcBridgeStateBits.PERMISSIVE)
        if self.fault_trip:
            mask |= int(OpcBridgeStateBits.FAULT_TRIP)

        if self.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_DCOM_RPC_DISCONNECT:
            mask |= int(OpcBridgeStateBits.RPC_DISCONNECT_FAULT)
        elif self.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_GROUP_UPDATE_TIMEOUT:
            mask |= int(OpcBridgeStateBits.GROUP_TIMEOUT_FAULT)
        elif self.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_ITEM_BAD_QUALITY:
            mask |= int(OpcBridgeStateBits.ITEM_BAD_QUALITY_FAULT)
        elif self.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_INVALID_CLSID:
            mask |= int(OpcBridgeStateBits.INVALID_CLSID_FAULT)

        if self.item_quality_code != OPC_QUALITY_GOOD:
            mask |= int(OpcBridgeStateBits.QUALITY_DEGRADED)

        return mask & 0xFFFF

    def sync_to_registers(self) -> None:
        """Synchronize internal bridge state to Horner OCS memory image with PrivilegeMode.SYSTEM."""
        # %R1390: ConnectedOpcGroupsCount (INT16, 0..16)
        safe_write_word(self.reg_table, "%R1390", len(self.groups))

        # %R1391: ActiveOpcItemsCount (INT16, e.g. 64)
        safe_write_word(self.reg_table, "%R1391", self.get_active_items_count())

        # %R1392: OpcDaTransactionLatencyMsScaled (INT16, scaled x10 ms)
        safe_write_word(self.reg_table, "%R1392", self.latency_scaled)

        # %R1393: OpcItemQualityCodeWord (UINT16, 0x00C0 = GOOD)
        safe_write_uword(self.reg_table, "%R1393", self.item_quality_code)

        # %R1394: DcomReconnectFailuresCount (INT16 count)
        safe_write_word(self.reg_table, "%R1394", self.reconnect_failures_count)

        # %R1395: OpcBridgeStateWord (INT16 bitmask)
        safe_write_word(self.reg_table, "%R1395", self.compute_state_word())

        # %R1396: OpcGroupUpdateRateMs (INT16, e.g. 100)
        safe_write_word(self.reg_table, "%R1396", self.nominal_group_update_rate_ms)

        # %R1397: DiagnosticStatusCode (0x0000, 0xCB01..0xCB04)
        safe_write_uword(self.reg_table, "%R1397", int(self.diagnostic_code))

        # %M324: OpcDaBridgePermissive (BOOL)
        safe_write_bit(self.reg_table, "%M324", self.permissive)

        # %M325: OpcDaBridgeFaultTrip (BOOL)
        safe_write_bit(self.reg_table, "%M325", self.fault_trip)


# Aliases
OpcDaXmlBridgeEngine = OpcDaBridgeEngine
LegacyComDcomOpcBridgeSyncEngine = OpcDaBridgeEngine
OpcDaBridge = OpcDaBridgeEngine
OpcDaXmlBridge = OpcDaBridgeEngine
LegacyComDcomOpcBridge = OpcDaBridgeEngine
OpcDaBridgeSync = OpcDaBridgeEngine
OpcDaXmlDaBridgeSync = OpcDaBridgeEngine
verify_opc_da_pure_st = verify_opc_da_bridge_pure_st


# ============================================================================
# 10. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_opc_da_bridge_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W178.

    Returns strict 4-state contract JSON response:
    - Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings (%R1390..%R1397, %M324..%M325)
    - Stage 2: Legacy COM/DCOM Architecture, CLSID/IID Resolution & HRESULT Diagnostics
    - Stage 3: OPC DA Group Management (16 Group Ceiling, Rates 50/100/500/1000ms, Deadband Filtering)
    - Stage 4: OPC DA Address Space Browsing & Item Property Dictionary (Hierarchical/Flat, Types, EU Info)
    - Stage 5: Synchronous & Asynchronous Read/Write Transactions & XML-DA 1.01 SOAP Serialization
    - Stage 6: DCOM RPC Disconnect Safety Interlock (0xCB01) & Permissive/Trip Assertions
    - Stage 7: Asynchronous Group Update Timeout Surveillance (> 2500 ms -> 0xCB02)
    - Stage 8: Item Bad Quality Safety Interlock (0xCB03) & Invalid CLSID Trapping (0xCB04)
    - Stage 9: Closed-Loop Scan Cycle Simulation (ILogicUnit), Operator Reset Handshake, & Register Synchronization
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & RegisterTable Bindings
    # ------------------------------------------------------------------------
    val_pou1 = STParser.validate_code(OPC_DA_XML_BRIDGE_SYNC_POU)
    ast_pou1 = STParser.parse_pou(OPC_DA_XML_BRIDGE_SYNC_POU)
    val_pou2 = STParser.validate_code(LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU)
    ast_pou2 = STParser.parse_pou(LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU)

    expected_regs = {
        "%R1390", "%R1391", "%R1392", "%R1393",
        "%R1394", "%R1395", "%R1396", "%R1397",
        "%M324", "%M325",
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
        and ast_pou1.name == "OpcDaXmlBridgeSync"
        and ast_pou2.name == "LegacyComDcomOpcBridgeSync"
        and set(ast_pou1.bound_registers) == expected_regs
        and set(ast_pou2.bound_registers) == expected_regs
        and verify_opc_da_bridge_pure_st() is True
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Register_Bindings",
        "passed": s1_pass,
        "details": f"Parsed OpcDaXmlBridgeSync and alias with 10 registered bindings: {sorted(ast_pou1.bound_registers)}.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Legacy COM/DCOM Architecture, CLSID/IID Resolution & HRESULTS
    # ------------------------------------------------------------------------
    clsid_da = resolve_clsid("Horner.Cscape.OPCDA")
    clsid_dcom = resolve_clsid("Horner.Legacy.DCOM")
    clsid_list = resolve_clsid("OPC.ServerList")

    engine = OpcDaBridgeEngine()
    hr_sync_io, iface_sync_io = engine.query_interface(IID_IOPCSyncIO)
    hr_async_io, iface_async_io = engine.query_interface(IID_IOPCAsyncIO2)
    hr_bad_iid, iface_bad_iid = engine.query_interface("{99999999-9999-9999-9999-999999999999}")

    s2_pass = (
        clsid_da == CLSID_CscapeOpcDaServer
        and clsid_dcom == CLSID_LegacyHornerDcomServer
        and clsid_list == CLSID_OpcServerList
        and hr_sync_io == S_OK
        and iface_sync_io is not None
        and hr_async_io == S_OK
        and iface_async_io is not None
        and hr_bad_iid == E_NOINTERFACE
        and iface_bad_iid is None
        and S_OK == 0x00000000
        and OPC_E_INVALIDHANDLE == 0xC0040001
        and RPC_E_DISCONNECTED == 0x80010108
        and OPC_E_BADTYPE == 0xC0040004
        and REGDB_E_CLASSNOTREG == 0x80040154
    )
    test_results.append({
        "stage": 2,
        "check": "Legacy_COM_DCOM_Architecture_And_CLSID_IID_HRESULT_Resolution",
        "passed": s2_pass,
        "details": "Validated ProgID/CLSID resolution, QueryInterface emulation, and OPC HRESULT constants.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: OPC DA Group Management (16 Group Capacity, Rates, Deadband)
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine_grp = OpcDaBridgeEngine(register_table=rt)

    # Initial group count is 1 (default initialized)
    init_groups = len(engine_grp.groups)

    # Add groups up to 16
    for i in range(init_groups + 1, 17):
        rate = STANDARD_UPDATE_RATES_MS[(i - 1) % len(STANDARD_UPDATE_RATES_MS)]
        engine_grp.add_group(name=f"TestGroup_{i}", update_rate_ms=rate, percent_deadband=1.0)

    count_16 = len(engine_grp.groups)
    r1390_count_16 = rt.read_word("%R1390")

    # Adding 17th group must raise OpcGroupCapacityError
    capacity_overflow = False
    try:
        engine_grp.add_group(name="OverflowGroup_17")
    except OpcGroupCapacityError:
        capacity_overflow = True

    # Test update rate clamping for non-standard rate 75 ms -> clamps to 50 or 100 ms
    clamped_rate = engine_grp._clamp_update_rate(75)

    # Test Deadband filtering on group 1
    g1 = engine_grp.groups[1]
    g1.percent_deadband = 5.0
    item_test = list(g1.items.values())[0]
    item_test.eu_info = (0.0, 100.0)
    item_test.last_published_value = 50.0

    # 1.0 change on span 100 is 1.0% < 5.0% deadband -> False (suppressed)
    deadband_suppressed = not g1.evaluate_deadband(item_test, 51.0)
    # 6.0 change on span 100 is 6.0% >= 5.0% deadband -> True (publish)
    deadband_published = g1.evaluate_deadband(item_test, 56.0)

    s3_pass = (
        count_16 == 16
        and r1390_count_16 == 16
        and capacity_overflow is True
        and clamped_rate in STANDARD_UPDATE_RATES_MS
        and deadband_suppressed is True
        and deadband_published is True
    )
    test_results.append({
        "stage": 3,
        "check": "OPC_DA_Group_Management_16_Capacity_Rates_And_Deadband",
        "passed": s3_pass,
        "details": "16-group ceiling, rate clamping (50/100/500/1000ms), and 5% deadband suppression verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: OPC DA Address Space Browsing & Item Property Dictionary
    # ------------------------------------------------------------------------
    addr_space = engine_grp.address_space

    # Root browse
    root_branches = addr_space.browse_item_ids(browse_type=OPC_BRANCH)
    flat_items = addr_space.browse_item_ids(browse_type=OPC_FLAT)

    # Navigate to HornerOCS -> HoldingRegisters
    hr_down1 = addr_space.change_browse_position(OPC_BROWSE_DOWN, "HornerOCS")
    hr_down2 = addr_space.change_browse_position(OPC_BROWSE_DOWN, "HoldingRegisters")
    leaf_items = addr_space.browse_item_ids(browse_type=OPC_LEAF)
    hr_up = addr_space.change_browse_position(OPC_BROWSE_UP)

    # Properties of furnace zone 1 temperature
    furnace_props = addr_space.get_item_properties("ProcessUnits.Furnace.Zone1Temp")

    s4_pass = (
        "HornerOCS" in root_branches
        and "ProcessUnits" in root_branches
        and "Diagnostics" in root_branches
        and len(flat_items) >= 40
        and hr_down1 == S_OK
        and hr_down2 == S_OK
        and len(leaf_items) == 32
        and hr_up == S_OK
        and furnace_props[OPC_PROP_CDT] == VT_R4
        and furnace_props[OPC_PROP_RIGHTS] == (OPC_READABLE | OPC_WRITEABLE)
        and furnace_props[OPC_PROP_EUINFO] == (0.0, 1200.0)
    )
    test_results.append({
        "stage": 4,
        "check": "Address_Space_Browsing_And_Item_Property_Dictionary",
        "passed": s4_pass,
        "details": "Hierarchical/flat address space navigation and item properties (VT_R4, EU range) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Sync/Async Transactions & XML-DA 1.01 Serialization
    # ------------------------------------------------------------------------
    engine_tx = OpcDaBridgeEngine(register_table=rt)
    g_tx = engine_tx.groups[1]
    item_handles = [it.server_handle for it in list(g_tx.items.values())[:4]]

    # 1. Sync Write values
    write_vals = [123, 456, 78.5, 82.1]
    w_errors = engine_tx.sync_write(g_tx.server_handle, item_handles, write_vals, simulated_latency_override_ms=3.5)

    # 2. Sync Read values
    r_vals, r_quals, r_times, r_errors = engine_tx.sync_read(g_tx.server_handle, item_handles)

    # 3. Async Read
    cancel_id, async_tx = engine_tx.async_read(g_tx.server_handle, item_handles)

    # 4. XML-DA methods
    xml_bridge = engine_tx.xml_da_bridge
    status_xml_data = xml_bridge.get_status()
    xml_read_res = xml_bridge.read(["ProcessUnits.Furnace.Zone1Temp"])
    xml_soap_envelope = xml_bridge.format_soap_envelope("<GetStatusResponse/>")

    r1392_scaled_latency = rt.read_word("%R1392")

    s5_pass = (
        all(e == S_OK for e in w_errors)
        and r_vals[:2] == [123, 456]
        and all(q == OPC_QUALITY_GOOD for q in r_quals)
        and cancel_id in engine_tx.active_async_transactions
        and async_tx.status == "COMPLETED"
        and r1392_scaled_latency == NOMINAL_LATENCY_SCALED
        and status_xml_data["ServerState"] == "running"
        and len(xml_read_res["Items"]) == 1
        and xml_read_res["Items"][0]["Quality"] == "good"
        and "<SOAP-ENV:Envelope" in xml_soap_envelope
        and "<GetStatusResponse/>" in xml_soap_envelope
    )
    test_results.append({
        "stage": 5,
        "check": "Sync_Async_Transactions_And_XML_DA_SOAP_Serialization",
        "passed": s5_pass,
        "details": "Sync/Async read/write transactions, scaled latency tracking (35 = 3.5ms), and XML-DA SOAP verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: DCOM RPC Disconnect Safety Interlock (0xCB01)
    # ------------------------------------------------------------------------
    engine_tx.reset_fault(force=True)
    engine_tx.simulate_rpc_disconnect()

    # Attempting transaction when RPC disconnected must raise OpcDcomRpcDisconnectError
    rpc_disconnect_caught = False
    try:
        engine_tx.sync_read(g_tx.server_handle, item_handles)
    except OpcDcomRpcDisconnectError:
        rpc_disconnect_caught = True

    r1397_rpc = rt.read_uword("%R1397")
    r1394_reconn = rt.read_word("%R1394")
    m324_rpc = rt.read_bit("%M324")
    m325_rpc = rt.read_bit("%M325")
    state_word_rpc = rt.read_word("%R1395")

    # Perform DCOM reconnect
    engine_tx.reconnect_dcom()

    s6_pass = (
        rpc_disconnect_caught is True
        and engine_tx.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_DCOM_RPC_DISCONNECT
        and r1397_rpc == 0xCB01
        and r1394_reconn >= 1
        and m324_rpc is False
        and m325_rpc is True
        and (state_word_rpc & int(OpcBridgeStateBits.RPC_DISCONNECT_FAULT)) != 0
        and (state_word_rpc & int(OpcBridgeStateBits.FAULT_TRIP)) != 0
        and engine_tx.is_rpc_connected is True
    )
    test_results.append({
        "stage": 6,
        "check": "DCOM_RPC_Disconnect_Safety_Interlock_And_Trip_Assertions",
        "passed": s6_pass,
        "details": "DCOM RPC disconnect trapped with 0xCB01, %M325 asserted, %M324 cleared, and %R1394 incremented.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Asynchronous Group Update Timeout Surveillance (> 2500 ms)
    # ------------------------------------------------------------------------
    engine_tx.reset_fault(force=True)

    # Force group update timer beyond 2500 ms threshold
    g1_timeout = engine_tx.groups[1]
    g1_timeout.time_since_last_update_ms = 2505.0

    # Execute scan step to trigger watchdog
    engine_tx.scan_step(dt=0.01)

    r1397_timeout = rt.read_uword("%R1397")
    m324_timeout = rt.read_bit("%M324")
    m325_timeout = rt.read_bit("%M325")
    state_word_timeout = rt.read_word("%R1395")

    s7_pass = (
        engine_tx.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_GROUP_UPDATE_TIMEOUT
        and r1397_timeout == 0xCB02
        and m324_timeout is False
        and m325_timeout is True
        and (state_word_timeout & int(OpcBridgeStateBits.GROUP_TIMEOUT_FAULT)) != 0
        and (state_word_timeout & int(OpcBridgeStateBits.FAULT_TRIP)) != 0
    )
    test_results.append({
        "stage": 7,
        "check": "Group_Update_Timeout_Surveillance_Over_2500ms",
        "passed": s7_pass,
        "details": "Subscription group update stall (> 2500ms) tripped safety interlock 0xCB02 and fault coils.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Item Bad Quality (0xCB03) & Invalid CLSID Trapping (0xCB04)
    # ------------------------------------------------------------------------
    # Part A: Bad Quality on critical item
    engine_tx.reset_fault(force=True)
    crit_item = engine_tx.find_item_by_id("ProcessUnits.Furnace.Zone1Temp")
    assert crit_item is not None
    crit_item.quality = OPC_QUALITY_BAD  # 0x00

    # Scan step detects critical item quality failure
    engine_tx.scan_step(dt=0.001)

    r1397_bad_qual = rt.read_uword("%R1397")
    r1393_bad_qual = rt.read_uword("%R1393")
    m324_bad_qual = rt.read_bit("%M324")
    m325_bad_qual = rt.read_bit("%M325")

    # Restore item quality
    crit_item.quality = OPC_QUALITY_GOOD

    # Part B: Invalid CLSID resolution trapping (0xCB04)
    engine_tx.reset_fault(force=True)
    invalid_clsid_caught = False
    try:
        engine_tx.connect_server("{DEADBEEF-0000-0000-0000-000000000000}")
    except OpcInvalidClsidError:
        invalid_clsid_caught = True

    r1397_clsid = rt.read_uword("%R1397")
    m324_clsid = rt.read_bit("%M324")
    m325_clsid = rt.read_bit("%M325")

    s8_pass = (
        r1397_bad_qual == 0xCB03
        and r1393_bad_qual == 0x0000
        and m324_bad_qual is False
        and m325_bad_qual is True
        and invalid_clsid_caught is True
        and r1397_clsid == 0xCB04
        and m324_clsid is False
        and m325_clsid is True
    )
    test_results.append({
        "stage": 8,
        "check": "Item_Bad_Quality_And_Invalid_CLSID_Trapping",
        "passed": s8_pass,
        "details": "Critical item BAD quality (0xCB03) and invalid CLSID resolution (0xCB04) trapped deterministically.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Closed-Loop Scan Cycle Simulation & Operator Reset Handshake
    # ------------------------------------------------------------------------
    # Reset engine and connect valid server
    engine_tx.connect_server("Horner.Cscape.OPCDA")
    res_reset = engine_tx.reset_fault(force=True)

    # Execute simulation cycle through ScanContext
    ctx = ScanContext(
        cycle=100,
        dt_ms=10.0,
        elapsed_time_ms=1000.0,
        get_register=rt.read_register,
        set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
        get_variable=lambda k, d=None: d,
        set_variable=lambda k, v: None,
        record_fault=lambda f: None,
    )
    engine_tx.execute(ctx)
    engine_tx.sync_to_registers()

    s9_pass = (
        engine_tx.name == "opc_da_bridge"
        and engine_tx.priority == 92
        and engine_tx.is_enabled is True
        and res_reset.status == AgentStatus.SUCCESS
        and engine_tx.diagnostic_code == OpcDaDiagnosticCode.OK
        and rt.read_uword("%R1397") == 0x0000
        and rt.read_bit("%M324") is True
        and rt.read_bit("%M325") is False
        and rt.read_uword("%R1393") == OPC_QUALITY_GOOD
        and rt.read_word("%R1392") == NOMINAL_LATENCY_SCALED
        and rt.read_word("%R1390") == 1
        and rt.read_word("%R1391") == 64
    )
    test_results.append({
        "stage": 9,
        "check": "Closed_Loop_Scan_Cycle_And_Operator_Reset_Synchronization",
        "passed": s9_pass,
        "details": "ILogicUnit scan execution, operator reset handshake, and Horner OCS memory synchronization verified.",
    })

    # ------------------------------------------------------------------------
    # Verification Summary & Evidence Serialization
    # ------------------------------------------------------------------------
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Industrial OPC DA / XML-DA Protocol Wrapper & Legacy COM/DCOM Bridge Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} stages passed).",
        "data": {
            "work_package": "W178",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial OPC DA / XML-DA Protocol Wrapper & Legacy COM/DCOM Bridge Engine",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R1390..%R1397",
                "discrete_coils": "%M324..%M325",
                "values": {
                    "%R1390": rt.read_word("%R1390"),
                    "%R1391": rt.read_word("%R1391"),
                    "%R1392": rt.read_word("%R1392"),
                    "%R1393": rt.read_uword("%R1393"),
                    "%R1394": rt.read_word("%R1394"),
                    "%R1395": rt.read_word("%R1395"),
                    "%R1396": rt.read_word("%R1396"),
                    "%R1397": rt.read_uword("%R1397"),
                    "%M324": rt.read_bit("%M324"),
                    "%M325": rt.read_bit("%M325"),
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


if __name__ == "__main__":
    out_target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_opc_da_bridge_verification(output_path=out_target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
