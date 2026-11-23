"""Industrial EtherCAT SubDevice (Slave) State Machine & CoE / SyncManager Engine.

Work Package: W139 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Strict Pure ST POU 'EtherCatSlaveSync' (and alias 'EtherCatSubDeviceSync') with
   Horner OCS RegisterTable bindings (%R1000..%R1007, %M233..%M234). Pure IEC 61131-3
   Structured Text ONLY. Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN
   using SecurityGuard.assert_pure_st_content and STParser.
2. Complete EtherCAT Application Layer (AL) State Machine (ETG.1000 / IEC 61158):
   - States: INIT (0x01), PREOP (0x02), SAFEOP (0x04), OP (0x08), with error flag (0x0010).
   - Valid transitions: INIT -> PREOP -> SAFEOP -> OP, and safe down-transitions.
   - SyncManager configuration: SM0 (Mailbox Out), SM1 (Mailbox In), SM2 (RxPDO Process Outputs), SM3 (TxPDO Process Inputs).
   - CANopen over EtherCAT (CoE) object dictionary (0x1000 Device Type, 0x1018 Identity, 0x1600 RxPDO, 0x1A00 TxPDO, application objects 0x6000/0x7000).
   - Distributed Clocks (DC) synchronization simulation: sub-microsecond Sync0 pulse generation, jitter error tracking in nanoseconds (target < 100 ns).
   - SyncManager 2 Watchdog timer (default 100ms) with fail-safe fallback to SafeOp upon timeout.
3. Process Safety Interlocks & Diagnostics:
   - 0xA401: ETHERCAT_ERR_SM_WATCHDOG (SyncManager watchdog expired) -> asserts %M234 (EtherCatWatchdogTrip), clears %M233 (EtherCatOperationalActive), sets AL error code 0x001B.
   - 0xA402: ETHERCAT_ERR_INVALID_TRANSITION (illegal state transition requested) -> sets AL error code 0x0011.
   - 0xA403: ETHERCAT_ERR_DC_SYNC_LOSS (DC jitter error exceeds 500 ns).
   - 0xA404: ETHERCAT_ERR_SDO_ABORT (CoE SDO transfer aborted).
4. Horner OCS Memory Space Integration:
   - %R1000: AlStatusStateWord (16-bit uint, active AL state and flags).
   - %R1001: AlStatusCode (16-bit uint, AL error code).
   - %R1002: SyncManagerCycleCounter (16-bit uint, SM event counter).
   - %R1003: RxPdoProcessDataScaled (INT16, scaled x10).
   - %R1004: TxPdoProcessDataScaled (INT16, scaled x10).
   - %R1005: DcSyncErrorNs (16-bit uint, DC sync jitter in ns).
   - %R1006: CoeObjectDirectoryCounter (16-bit uint, SDO transaction count).
   - %R1007: DiagnosticStatusCode (0x0000=OK, 0xA401, 0xA402, 0xA403, 0xA404).
   - %M233: EtherCatOperationalActive (BOOL, True strictly when AL State == OP and SMs active).
   - %M234: EtherCatWatchdogTrip (BOOL, True on watchdog expiry or AL fault).
5. Deterministic 9-Stage Verification Suite:
   - Function run_ethercat_slave_verification(output_path) implementing 9 stages and returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Enums and Protocol Definitions
# ============================================================================

class EtherCATCommand(IntEnum):
    """EtherCAT datagram commands per IEC 61158-4-12."""
    APRD = 0x01  # Auto Increment Read
    APWR = 0x02  # Auto Increment Write
    FPRD = 0x04  # Configured Address Read
    FPWR = 0x05  # Configured Address Write
    BRD  = 0x07  # Broadcast Read
    BWR  = 0x08  # Broadcast Write
    LRD  = 0x0A  # Logical Read
    LWR  = 0x0B  # Logical Write
    LRW  = 0x0C  # Logical Read Write


class ALState(IntEnum):
    """EtherCAT Application Layer (AL) State Machine states (ETG.1000 / IEC 61158-6-12)."""
    INIT       = 0x01  # Initialization
    PREOP      = 0x02  # Pre-Operational (Mailbox Active)
    BOOT       = 0x03  # Bootstrap Mode (Firmware update)
    SAFEOP     = 0x04  # Safe-Operational (Mailbox + TxPDO Active)
    OP         = 0x08  # Operational (Mailbox + TxPDO + RxPDO Active)
    ERROR_FLAG = 0x10  # Bit 4: Error flag set in AL Status register


ESMState = ALState


class EtherCATALStatusCode(IntEnum):
    """EtherCAT Application Layer (AL) Status Codes (ETG.1000 Register 0x0134)."""
    NO_ERROR                = 0x0000  # No error
    INVALID_STATE_CHANGE    = 0x0011  # Invalid requested state change
    UNKNOWN_STATE           = 0x0012  # Unknown requested state
    BOOTSTRAP_NOT_SUPPORTED = 0x0013  # Bootstrap not supported
    NO_VALID_FIRMWARE       = 0x0014  # No valid firmware
    INVALID_MAILBOX_CFG_IN  = 0x0015  # Invalid mailbox configuration (IN)
    INVALID_MAILBOX_CFG_OUT = 0x0016  # Invalid mailbox configuration (OUT)
    SM_WATCHDOG             = 0x001B  # SyncManager watchdog expired
    INVALID_SM_IN_CFG       = 0x001E  # Invalid SyncManager IN configuration
    INVALID_SM_OUT_CFG      = 0x001F  # Invalid SyncManager OUT configuration
    DC_PLL_NOT_LOCKED       = 0x0032  # Distributed Clocks PLL not locked / jitter loss
    DC_SYNC_IO_ERROR        = 0x0033  # DC Sync IO error


class EtherCATDiagnosticCode(IntEnum):
    """Horner OCS %R1007 Process Safety & Protocol Diagnostic Event Codes."""
    OK                              = 0x0000  # Normal operation, SMs active, no trips
    ETHERCAT_ERR_SM_WATCHDOG        = 0xA401  # SyncManager watchdog expired
    ETHERCAT_ERR_INVALID_TRANSITION = 0xA402  # Illegal state transition requested
    ETHERCAT_ERR_DC_SYNC_LOSS       = 0xA403  # DC jitter error exceeds 500 ns
    ETHERCAT_ERR_SDO_ABORT          = 0xA404  # CoE SDO transfer aborted

    # Convenience aliases
    ECAT_ERR_SM_WATCHDOG            = 0xA401
    ECAT_ERR_INVALID_TRANSITION     = 0xA402
    ECAT_ERR_DC_SYNC_LOSS           = 0xA403
    ECAT_ERR_SDO_ABORT              = 0xA404
    SM_WATCHDOG                     = 0xA401
    INVALID_TRANSITION              = 0xA402
    DC_SYNC_LOSS                    = 0xA403
    SDO_ABORT                       = 0xA404
    ECAT_ERR_SM_WATCHDOG_TRIP       = 0xA401
    ECAT_ERR_INVALID_TRANSITION_TRIP= 0xA402
    ECAT_ERR_DC_JITTER_EXCESSIVE    = 0xA403
    ECAT_ERR_DC_JITTER_TRIP         = 0xA403
    ECAT_ERR_COE_SDO_ABORT          = 0xA404
    ECAT_ERR_SDO_ABORT_TRIP         = 0xA404
    ECAT_ERR_WKC_INVALID            = 0xA404
    ECAT_ERR_WKC_INVALID_TRIP       = 0xA404


EtherCatDiagnosticCode = EtherCATDiagnosticCode
EtherCATSlaveDiagnosticCode = EtherCATDiagnosticCode


class EtherCATStatusBits(IntFlag):
    """Horner OCS %R1000 AL Status State Word Bitmask Definitions."""
    STATE_INIT           = 1 << 0   # Bit 0 (0x0001): INIT state active
    STATE_PREOP          = 1 << 1   # Bit 1 (0x0002): PREOP state active
    STATE_SAFEOP         = 1 << 2   # Bit 2 (0x0004): SAFEOP state active
    STATE_OP             = 1 << 3   # Bit 3 (0x0008): OP state active
    ERROR_ACTIVE         = 1 << 4   # Bit 4 (0x0010): AL Error flag active
    DC_SYNCHRONIZED      = 1 << 5   # Bit 5 (0x0020): Distributed Clocks synchronized (< 500 ns)
    SM_WATCHDOG_TRIP     = 1 << 6   # Bit 6 (0x0040): SyncManager 2 watchdog tripped
    SDO_ACCESS_ACTIVE    = 1 << 7   # Bit 7 (0x0080): CoE SDO mailbox active
    OPERATIONAL_ACTIVE   = 1 << 8   # Bit 8 (0x0100): Operational active (%M233)
    MAILBOX_READY        = 1 << 9   # Bit 9 (0x0200): SM0/SM1 Mailbox ready
    PROCESS_DATA_VALID   = 1 << 10  # Bit 10 (0x0400): RxPDO/TxPDO process data valid
    SLAVE_ACTIVE         = 1 << 8   # Bit 8 (0x0100): Operational active (%M233)
    ESM_OPERATIONAL      = 1 << 3
    ESM_SAFE_OP          = 1 << 2
    ESM_PRE_OP           = 1 << 1
    DC_SYNC_LOCKED       = 1 << 5
    JITTER_OK            = 1 << 5
    JITTER_WARNING       = 1 << 11
    WKC_VALID            = 1 << 10
    MAILBOX_ACTIVE       = 1 << 9
    WATCHDOG_TRIP        = 1 << 6
    SAFETY_TRIP          = 1 << 4


EtherCatStatusBits = EtherCATStatusBits
EtherCATSlaveStatusBits = EtherCATStatusBits


class MailboxType(IntEnum):
    """EtherCAT Mailbox protocol types."""
    ERR = 0x01
    ADS = 0x02
    COE = 0x03  # CAN Application Protocol over EtherCAT
    EOE = 0x04
    SOE = 0x05
    VOE = 0x0F


class CoEService(IntEnum):
    """CAN application protocol over EtherCAT service types."""
    EMERGENCY    = 0x01
    SDO_REQUEST  = 0x02
    SDO_RESPONSE = 0x03
    TXPDO        = 0x04
    RXPDO        = 0x05
    SDO_INFO     = 0x08


class SDOCommand(IntEnum):
    """CANopen SDO Command Specifiers (CS)."""
    DOWNLOAD_EXPEDITED_4B = 0x23
    DOWNLOAD_EXPEDITED_2B = 0x2B
    DOWNLOAD_EXPEDITED_1B = 0x2F
    DOWNLOAD_RESPONSE     = 0x60
    UPLOAD_REQUEST        = 0x40
    UPLOAD_EXPEDITED_4B   = 0x43
    UPLOAD_EXPEDITED_2B   = 0x4B
    UPLOAD_EXPEDITED_1B   = 0x4F
    ABORT_TRANSFER        = 0x80


class SDOAbortCode(IntEnum):
    """Standard CANopen SDO Abort Codes."""
    INVALID_COMMAND_SPECIFIER = 0x05040001
    UNSUPPORTED_ACCESS        = 0x06010000
    OBJECT_NOT_EXIST          = 0x06020000
    DATA_TYPE_LENGTH_MISMATCH = 0x06070010
    SUBINDEX_NOT_EXIST        = 0x06090011
    VALUE_RANGE_EXCEEDED      = 0x06090030
    GENERAL_ERROR             = 0x08000000
    DATA_CANNOT_BE_STORED     = 0x08000022


class FMMUType(IntEnum):
    """FMMU transfer direction."""
    READ       = 0x01
    WRITE      = 0x02
    READ_WRITE = 0x03


class EtherCATSlaveError(Exception):
    """Base exception for EtherCAT SubDevice errors."""
    pass


class ALStateTransitionError(EtherCATSlaveError):
    """Raised when an illegal ESM state transition is requested."""
    pass


class SyncManagerConfigError(EtherCATSlaveError):
    """Raised when a SyncManager channel configuration is invalid."""
    pass


class DistributedClocksJitterError(EtherCATSlaveError):
    """Raised when DC Sync0 jitter exceeds the safety limit."""
    pass


class CoESDOAbortError(EtherCATSlaveError):
    """Raised when a CoE SDO transaction encounters an abort condition."""
    pass


class ProcessDataWKCError(EtherCATSlaveError):
    """Raised when cyclic process data has invalid Working Counter."""
    pass


# ============================================================================
# 2. Dataclasses and Framing Structures
# ============================================================================

@dataclass
class SyncManagerChannel:
    """ESC SyncManager Channel Configuration Register Block."""
    index: int
    physical_start_address: int
    length: int
    control: int
    status: int = 0x00
    activate: int = 0x01
    pdi_control: int = 0x00

    @property
    def is_enabled(self) -> bool:
        return bool(self.activate & 0x01)

    @property
    def is_full(self) -> bool:
        return bool(self.status & 0x08)

    @property
    def is_read(self) -> bool:
        return (self.control & 0x0C) == 0x00

    @property
    def is_write(self) -> bool:
        return (self.control & 0x0C) == 0x04 or bool(self.control & 0x04)

    def set_full(self, full: bool) -> None:
        if full:
            self.status |= 0x08
        else:
            self.status &= ~0x08

    def serialize(self) -> bytes:
        return struct.pack(
            "<HHBBBB",
            self.physical_start_address,
            self.length,
            self.control,
            self.status,
            self.activate,
            self.pdi_control,
        )

    @classmethod
    def deserialize(cls, index: int, raw: bytes) -> SyncManagerChannel:
        addr, length, ctrl, stat, act, pdi = struct.unpack("<HHBBBB", raw[:8])
        return cls(
            index=index,
            physical_start_address=addr,
            length=length,
            control=ctrl,
            status=stat,
            activate=act,
            pdi_control=pdi,
        )


@dataclass
class FMMUChannel:
    """ESC Fieldbus Memory Management Unit Channel Configuration Block."""
    index: int
    logical_start_address: int
    length: int
    logical_start_bit: int = 0
    logical_stop_bit: int = 7
    physical_start_address: int = 0x0000
    physical_start_bit: int = 0
    fmmu_type: FMMUType = FMMUType.READ
    enable: bool = True

    @property
    def is_read(self) -> bool:
        return bool(int(self.fmmu_type) & FMMUType.READ)

    @property
    def is_write(self) -> bool:
        return bool(int(self.fmmu_type) & FMMUType.WRITE)

    def serialize(self) -> bytes:
        act = 0x01 if self.enable else 0x00
        return struct.pack(
            "<IHBBHBBB3x",
            self.logical_start_address,
            self.length,
            self.logical_start_bit,
            self.logical_stop_bit,
            self.physical_start_address,
            self.physical_start_bit,
            int(self.fmmu_type),
            act,
        )


@dataclass
class SDOFrame:
    """CANopen SDO Protocol Frame."""
    command: int
    index: int
    subindex: int
    data: bytes = b"\x00\x00\x00\x00"

    def serialize(self) -> bytes:
        data_pad = (self.data + b"\x00" * 4)[:4]
        return struct.pack("<BHB4s", self.command, self.index, self.subindex, data_pad)

    @classmethod
    def deserialize(cls, raw: bytes) -> SDOFrame:
        cs, idx, sub, d = struct.unpack("<BHB4s", raw[:8])
        return cls(command=cs, index=idx, subindex=sub, data=d)


@dataclass
class EMCYFrame:
    """CANopen Emergency Protocol Frame."""
    error_code: int
    error_register: int
    error_data: bytes = b"\x00\x00\x00\x00\x00"

    def serialize(self) -> bytes:
        ed_pad = (self.error_data + b"\x00" * 5)[:5]
        return struct.pack("<HB5s", self.error_code, self.error_register, ed_pad)

    @classmethod
    def deserialize(cls, raw: bytes) -> EMCYFrame:
        err, reg, d = struct.unpack("<HB5s", raw[:8])
        return cls(error_code=err, error_register=reg, error_data=d)


@dataclass
class MailboxEnvelope:
    """EtherCAT Mailbox Protocol Envelope per ETG.1000."""
    length: int
    address: int
    channel: int = 0
    priority: int = 0
    mbx_type: MailboxType = MailboxType.COE
    counter: int = 1
    payload: bytes = b""

    def serialize(self) -> bytes:
        b4 = (self.channel & 0x3F) | ((self.priority & 0x03) << 6)
        b5 = (int(self.mbx_type) & 0x0F) | ((self.counter & 0x07) << 4)
        return struct.pack("<HHBB", len(self.payload), self.address, b4, b5) + self.payload

    @classmethod
    def deserialize(cls, raw: bytes) -> MailboxEnvelope:
        length, addr, b4, b5 = struct.unpack("<HHBB", raw[:6])
        return cls(
            length=length,
            address=addr,
            channel=b4 & 0x3F,
            priority=(b4 >> 6) & 0x03,
            mbx_type=MailboxType(b5 & 0x0F),
            counter=(b5 >> 4) & 0x07,
            payload=raw[6 : 6 + length],
        )


@dataclass
class EtherCATDatagram:
    """Single EtherCAT Sub-Datagram per IEC 61158-4-12."""
    cmd: int
    index: int
    address: int
    data: bytes
    wkc: int = 0

    def serialize(self) -> bytes:
        dlen_flags = len(self.data) & 0x7FF
        return (
            struct.pack("<BBIHH", self.cmd, self.index, self.address, dlen_flags, 0)
            + self.data
            + struct.pack("<H", self.wkc)
        )

    @classmethod
    def deserialize(cls, raw: bytes) -> EtherCATDatagram:
        cmd, idx, addr, dlen_flags, irq = struct.unpack("<BBIHH", raw[:10])
        dlen = dlen_flags & 0x7FF
        data_end = 10 + dlen
        return cls(
            cmd=cmd,
            index=idx,
            address=addr,
            data=raw[10:data_end],
            wkc=struct.unpack("<H", raw[data_end : data_end + 2])[0],
        )


@dataclass
class EtherCATFrame:
    """Ethernet II Enclosed EtherCAT Frame."""
    datagrams: List[EtherCATDatagram] = field(default_factory=list)
    dst_mac: bytes = b"\x01\x01\x05\x10\x00\x00"
    src_mac: bytes = b"\x00\x1B\x21\xA4\xB5\xC6"
    ethertype: int = 0x88A4

    def serialize(self) -> bytes:
        dg_bytes = b"".join(dg.serialize() for dg in self.datagrams)
        ecat_hdr = struct.pack("<H", (len(dg_bytes) & 0x7FF) | (1 << 12))
        return self.dst_mac + self.src_mac + struct.pack(">H", self.ethertype) + ecat_hdr + dg_bytes


@dataclass
class ObjectDictionaryEntry:
    """Entry in CANopen over EtherCAT Object Dictionary."""
    index: int
    subindex: int
    name: str
    data_type: str
    writable: bool
    value: Any


# Constants
ETHERCAT_VENDOR_ID_HORNER: int = 0x00000059
ETHERCAT_PRODUCT_CODE_W139: int = 0x00000102
ETHERCAT_REVISION_W139: int = 0x00010001
ETHERCAT_SERIAL_DEFAULT: int = 0x00123456
DC_JITTER_THRESHOLD_NS: int = 100
ETHERCAT_DC_JITTER_THRESHOLD_NS: int = 100
DC_SYNC0_DEFAULT_CYCLE_NS: int = 1_000_000
SYNC0_CYCLE_TIME_NS: int = 1_000_000
SM0_MAILBOX_OUT_ADDR: int = 0x1000
SM1_MAILBOX_IN_ADDR: int = 0x1080
SM2_RXPDO_ADDR: int = 0x1100
SM3_TXPDO_ADDR: int = 0x1140
MAILBOX_BUFFER_SIZE: int = 128
PROCESS_DATA_SIZE: int = 8
FMMU0_LOGICAL_ADDR: int = 0x00010000
FMMU1_LOGICAL_ADDR: int = 0x00010008
ETHERCAT_ETHERTYPE: int = 0x88A4
ETHERCAT_FRAME_ETHERTYPE: int = 0x88A4


# ============================================================================
# 3. Scaling Utility
# ============================================================================

def scale_pv_to_int16(val: Union[float, int], scale_factor: float = 10.0) -> int:
    """Scale floating-point or integer process variable to INT16 register units."""
    scaled = int(round(float(val) * scale_factor))
    return max(-32768, min(32767, scaled))


scale_process_input_to_int16 = scale_pv_to_int16


def compute_dc_jitter(arrival_ns: int, expected_ns: int) -> int:
    """Calculate absolute jitter in nanoseconds between arrival and expected time."""
    return abs(arrival_ns - expected_ns)


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POUs
# ============================================================================

ETHERCAT_SLAVE_SYNC_POU = """PROGRAM EtherCatSlaveSync
VAR
    (* Horner OCS Mapped Registers (W139 - EtherCAT SubDevice Engine) *)
    AlStatusStateWord           AT %R1000 : INT;    (* Active AL state and bitmask flags *)
    AlStatusCode                AT %R1001 : INT;    (* AL error code per ETG.1000 *)
    SyncManagerCycleCounter     AT %R1002 : INT;    (* SM event cycle counter *)
    RxPdoProcessDataScaled      AT %R1003 : INT;    (* Process Output scaled x10 *)
    TxPdoProcessDataScaled      AT %R1004 : INT;    (* Process Input scaled x10 *)
    DcSyncErrorNs               AT %R1005 : INT;    (* DC sync jitter in nanoseconds *)
    CoeObjectDirectoryCounter   AT %R1006 : INT;    (* SDO transaction counter *)
    DiagnosticStatusCode       AT %R1007 : INT;    (* Diagnostic event code 0x0000, 0xA401..0xA404 *)

    (* Discrete Safety Interlock Coils *)
    EtherCatOperationalActive   AT %M233  : BOOL;   (* TRUE strictly when AL State == OP and SMs active *)
    EtherCatWatchdogTrip        AT %M234  : BOOL;   (* TRUE on SM watchdog expiry or AL fault *)
END_VAR
VAR
    LocalState                  : INT;
    LocalErrorCode              : INT;
END_VAR

IF EtherCatWatchdogTrip THEN
    EtherCatOperationalActive := FALSE;
    TxPdoProcessDataScaled := 0;
ELSIF EtherCatOperationalActive THEN
    TxPdoProcessDataScaled := RxPdoProcessDataScaled;
    SyncManagerCycleCounter := SyncManagerCycleCounter + 1;
    DiagnosticStatusCode := 0;
ELSE
    TxPdoProcessDataScaled := 0;
END_IF;
END_PROGRAM
"""

ETHERCAT_SUBDEVICE_SYNC_POU = """PROGRAM EtherCatSubDeviceSync
VAR
    (* Horner OCS Mapped Registers (W139 - EtherCAT SubDevice Engine) *)
    AlStatusStateWord           AT %R1000 : INT;    (* Active AL state and bitmask flags *)
    AlStatusCode                AT %R1001 : INT;    (* AL error code per ETG.1000 *)
    SyncManagerCycleCounter     AT %R1002 : INT;    (* SM event cycle counter *)
    RxPdoProcessDataScaled      AT %R1003 : INT;    (* Process Output scaled x10 *)
    TxPdoProcessDataScaled      AT %R1004 : INT;    (* Process Input scaled x10 *)
    DcSyncErrorNs               AT %R1005 : INT;    (* DC sync jitter in nanoseconds *)
    CoeObjectDirectoryCounter   AT %R1006 : INT;    (* SDO transaction counter *)
    DiagnosticStatusCode       AT %R1007 : INT;    (* Diagnostic event code 0x0000, 0xA401..0xA404 *)

    (* Discrete Safety Interlock Coils *)
    EtherCatOperationalActive   AT %M233  : BOOL;   (* TRUE strictly when AL State == OP and SMs active *)
    EtherCatWatchdogTrip        AT %M234  : BOOL;   (* TRUE on SM watchdog expiry or AL fault *)
END_VAR
VAR
    LocalState                  : INT;
    LocalErrorCode              : INT;
END_VAR

IF EtherCatWatchdogTrip THEN
    EtherCatOperationalActive := FALSE;
    TxPdoProcessDataScaled := 0;
ELSIF EtherCatOperationalActive THEN
    TxPdoProcessDataScaled := RxPdoProcessDataScaled;
    SyncManagerCycleCounter := SyncManagerCycleCounter + 1;
    DiagnosticStatusCode := 0;
ELSE
    TxPdoProcessDataScaled := 0;
END_IF;
END_PROGRAM
"""

ETHERCAT_SLAVE_STATE_MACHINE_PURE_ST_POU: str = ETHERCAT_SLAVE_SYNC_POU
ETHERCAT_SLAVE_SYNC_PURE_ST_POU: str = ETHERCAT_SLAVE_SYNC_POU
ETHERCAT_SLAVE_PURE_ST_POU: str = ETHERCAT_SLAVE_SYNC_POU
ETHERCAT_PURE_ST_POU: str = ETHERCAT_SLAVE_SYNC_POU


def verify_ethercat_slave_pure_st() -> bool:
    """Validate pure ST POUs with SecurityGuard and STParser."""
    SecurityGuard.assert_pure_st_content(ETHERCAT_SLAVE_SYNC_POU)
    SecurityGuard.assert_pure_st_content(ETHERCAT_SUBDEVICE_SYNC_POU)
    res1 = STParser.validate_code(ETHERCAT_SLAVE_SYNC_POU)
    res2 = STParser.validate_code(ETHERCAT_SUBDEVICE_SYNC_POU)
    return res1.status == AgentStatus.SUCCESS and res2.status == AgentStatus.SUCCESS


# ============================================================================
# 5. Industrial EtherCAT SubDevice (Slave) Engine
# ============================================================================

class EtherCATSlaveEngine:
    """Industrial EtherCAT SubDevice (Slave) Protocol & State Machine Engine."""

    def __init__(
        self,
        station_address: int = 0x1000,
        vendor_id: int = ETHERCAT_VENDOR_ID_HORNER,
        product_code: int = ETHERCAT_PRODUCT_CODE_W139,
        revision_number: int = ETHERCAT_REVISION_W139,
        serial_number: int = ETHERCAT_SERIAL_DEFAULT,
        register_table: Optional[RegisterTable] = None,
        watchdog_timeout_ms: float = 100.0,
        dc_jitter_threshold_ns: int = DC_JITTER_THRESHOLD_NS,
    ) -> None:
        self.station_address = station_address
        self.vendor_id = vendor_id
        self.product_code = product_code
        self.revision_number = revision_number
        self.serial_number = serial_number
        self.watchdog_timeout_ms = watchdog_timeout_ms
        self.dc_jitter_threshold_ns = dc_jitter_threshold_ns
        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.registers: RegisterTable = self.reg_table

        # Application Layer (AL) State Machine
        self.al_state: ALState = ALState.INIT
        self.error_flag: bool = False
        self.al_status_code: EtherCATALStatusCode = EtherCATALStatusCode.NO_ERROR
        self.diagnostic_code: EtherCATDiagnosticCode = EtherCATDiagnosticCode.OK

        # SyncManager configuration (ETG.1000)
        self.sync_managers: Dict[int, SyncManagerChannel] = {
            0: SyncManagerChannel(0, SM0_MAILBOX_OUT_ADDR, MAILBOX_BUFFER_SIZE, 0x26),  # SM0 Mailbox Out
            1: SyncManagerChannel(1, SM1_MAILBOX_IN_ADDR,  MAILBOX_BUFFER_SIZE, 0x22),  # SM1 Mailbox In
            2: SyncManagerChannel(2, SM2_RXPDO_ADDR,       PROCESS_DATA_SIZE,   0x64),  # SM2 RxPDO Outputs
            3: SyncManagerChannel(3, SM3_TXPDO_ADDR,       PROCESS_DATA_SIZE,   0x20),  # SM3 TxPDO Inputs
        }

        # Fieldbus Memory Management Units (FMMUs)
        self.fmmus: Dict[int, FMMUChannel] = {
            0: FMMUChannel(0, FMMU0_LOGICAL_ADDR, PROCESS_DATA_SIZE, 0, 7, SM2_RXPDO_ADDR, 0, FMMUType.WRITE, True),
            1: FMMUChannel(1, FMMU1_LOGICAL_ADDR, PROCESS_DATA_SIZE, 0, 7, SM3_TXPDO_ADDR, 0, FMMUType.READ,  True),
        }

        # Internal ESC RAM (4 KB)
        self.esc_ram: bytearray = bytearray(4096)

        # CANopen over EtherCAT (CoE) Object Dictionary
        self.od: Dict[Tuple[int, int], ObjectDictionaryEntry] = {}
        self.coe_od_counter: int = 0
        self._init_object_dictionary()

        # Distributed Clocks (DC) Simulation
        self.dc_enabled: bool = True
        self.dc_system_time_ns: int = 10_000_000_000
        self.dc_sync0_cycle_ns: int = DC_SYNC0_DEFAULT_CYCLE_NS
        self.dc_jitter_ns: int = 42
        self.dc_sync_loss: bool = False
        self.jitter_history: List[int] = []

        # Watchdog, Scan Cycle & Process Data
        self.sm_cycle_counter: int = 0
        self.cycle_counter: int = 0
        self.rx_pdo_val: float = 0.0
        self.tx_pdo_val: float = 0.0
        self.rx_pdo_scaled: int = 0
        self.tx_pdo_scaled: int = 0
        self.watchdog_tripped: bool = False
        self.is_safety_tripped: bool = False
        self.last_sm2_event_time_ms: float = 0.0
        self.simulated_clock_ms: float = 0.0
        self.last_wkc: int = 0
        self.mailbox_counter: int = 1
        self.alarm_latched: bool = False

        self.sync_registers()

    def _init_object_dictionary(self) -> None:
        """Populate CANopen standard profile and vendor-specific objects."""
        # 0x1000: Device Type (CiA 401 Digital/Analog I/O module)
        self.od[(0x1000, 0x00)] = ObjectDictionaryEntry(0x1000, 0x00, "Device Type", "uint32", False, 0x00020191)
        # 0x1008: Device Name
        self.od[(0x1008, 0x00)] = ObjectDictionaryEntry(0x1008, 0x00, "Device Name", "string", False, "Horner OCS-EXL1")
        # 0x1018: Identity Object
        self.od[(0x1018, 0x00)] = ObjectDictionaryEntry(0x1018, 0x00, "Identity Count", "uint8", False, 4)
        self.od[(0x1018, 0x01)] = ObjectDictionaryEntry(0x1018, 0x01, "Vendor ID", "uint32", False, self.vendor_id)
        self.od[(0x1018, 0x02)] = ObjectDictionaryEntry(0x1018, 0x02, "Product Code", "uint32", False, self.product_code)
        self.od[(0x1018, 0x03)] = ObjectDictionaryEntry(0x1018, 0x03, "Revision Number", "uint32", False, self.revision_number)
        self.od[(0x1018, 0x04)] = ObjectDictionaryEntry(0x1018, 0x04, "Serial Number", "uint32", False, self.serial_number)

        # 0x1600: RxPDO Mapping (Master Outputs -> Slave)
        self.od[(0x1600, 0x00)] = ObjectDictionaryEntry(0x1600, 0x00, "RxPDO Count", "uint8", False, 2)
        self.od[(0x1600, 0x01)] = ObjectDictionaryEntry(0x1600, 0x01, "Mapped Entry 1", "uint32", False, 0x60000110)
        self.od[(0x1600, 0x02)] = ObjectDictionaryEntry(0x1600, 0x02, "Mapped Entry 2", "uint32", False, 0x60000210)

        # 0x1A00: TxPDO Mapping (Slave Inputs -> Master)
        self.od[(0x1A00, 0x00)] = ObjectDictionaryEntry(0x1A00, 0x00, "TxPDO Count", "uint8", False, 2)
        self.od[(0x1A00, 0x01)] = ObjectDictionaryEntry(0x1A00, 0x01, "Mapped Entry 1", "uint32", False, 0x70000110)
        self.od[(0x1A00, 0x02)] = ObjectDictionaryEntry(0x1A00, 0x02, "Mapped Entry 2", "uint32", False, 0x70000210)

        # 0x6000: RxPDO Process Outputs (Master -> Slave, maps to %R1003)
        self.od[(0x6000, 0x00)] = ObjectDictionaryEntry(0x6000, 0x00, "RxPDO Channels", "uint8", False, 2)
        self.od[(0x6000, 0x01)] = ObjectDictionaryEntry(0x6000, 0x01, "Process Output Ch1", "int16", True, 0)
        self.od[(0x6000, 0x02)] = ObjectDictionaryEntry(0x6000, 0x02, "Process Output Ch2", "int16", True, 0)

        # 0x7000: TxPDO Process Inputs (Slave -> Master, maps to %R1004)
        self.od[(0x7000, 0x00)] = ObjectDictionaryEntry(0x7000, 0x00, "TxPDO Channels", "uint8", False, 2)
        self.od[(0x7000, 0x01)] = ObjectDictionaryEntry(0x7000, 0x01, "Process Input Ch1", "int16", False, 0)
        self.od[(0x7000, 0x02)] = ObjectDictionaryEntry(0x7000, 0x02, "Process Input Ch2", "int16", False, 0)

    @property
    def esm_state(self) -> ESMState:
        return self.al_state

    @esm_state.setter
    def esm_state(self, val: ESMState) -> None:
        self.al_state = val

    @property
    def is_active(self) -> bool:
        return self.reg_table.read_bit("%M233") and not self.watchdog_tripped and not self.is_safety_tripped

    @property
    def operational_active(self) -> bool:
        return (
            self.al_state == ALState.OP
            and not self.error_flag
            and not self.watchdog_tripped
            and not self.is_safety_tripped
            and self.sync_managers[2].is_enabled
            and self.sync_managers[3].is_enabled
            and self.reg_table.read_bit("%M233")
        )

    @property
    def mailbox_active(self) -> bool:
        return self.al_state in (ALState.PREOP, ALState.SAFEOP, ALState.OP)

    @property
    def rx_pdo_active(self) -> bool:
        return self.al_state == ALState.OP and not self.error_flag and not self.watchdog_tripped

    @property
    def tx_pdo_active(self) -> bool:
        return self.al_state in (ALState.SAFEOP, ALState.OP) and not self.watchdog_tripped

    def request_state_transition(self, target_state: Union[ALState, int]) -> Tuple[bool, EtherCATALStatusCode]:
        raw_val = int(target_state)
        target = raw_val & 0x0F

        if (raw_val & ~0x1F) != 0 or target not in (ALState.INIT, ALState.PREOP, ALState.BOOT, ALState.SAFEOP, ALState.OP):
            self.error_flag = True
            self.al_status_code = EtherCATALStatusCode.UNKNOWN_STATE
            self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_INVALID_TRANSITION
            self.sync_registers()
            return False, self.al_status_code

        if target == ALState.BOOT:
            self.error_flag = True
            self.al_status_code = EtherCATALStatusCode.BOOTSTRAP_NOT_SUPPORTED
            self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_INVALID_TRANSITION
            self.sync_registers()
            return False, self.al_status_code

        if target == self.al_state:
            if self.error_flag or self.al_status_code != EtherCATALStatusCode.NO_ERROR:
                self.error_flag = False
                self.al_status_code = EtherCATALStatusCode.NO_ERROR
                if self.diagnostic_code == EtherCATDiagnosticCode.ETHERCAT_ERR_INVALID_TRANSITION:
                    self.diagnostic_code = EtherCATDiagnosticCode.OK
            self.sync_registers()
            return True, EtherCATALStatusCode.NO_ERROR

        curr = self.al_state
        valid_forward = (
            (curr == ALState.INIT and target == ALState.PREOP)
            or (curr == ALState.PREOP and target == ALState.SAFEOP)
            or (curr == ALState.SAFEOP and target == ALState.OP)
        )
        valid_backward = (
            (curr == ALState.OP and target in (ALState.SAFEOP, ALState.PREOP, ALState.INIT))
            or (curr == ALState.SAFEOP and target in (ALState.PREOP, ALState.INIT))
            or (curr == ALState.PREOP and target == ALState.INIT)
        )

        if valid_forward or valid_backward:
            self.al_state = ALState(target)
            self.error_flag = False
            self.al_status_code = EtherCATALStatusCode.NO_ERROR
            if self.diagnostic_code == EtherCATDiagnosticCode.ETHERCAT_ERR_INVALID_TRANSITION:
                self.diagnostic_code = EtherCATDiagnosticCode.OK

            if self.al_state == ALState.INIT:
                self.sync_managers[0].activate = 0
                self.sync_managers[1].activate = 0
                self.sync_managers[2].activate = 0
                self.sync_managers[3].activate = 0
                self.reg_table.write_bit("%M233", False, privilege=PrivilegeMode.SYSTEM)
            elif self.al_state == ALState.PREOP:
                self.sync_managers[0].activate = 1
                self.sync_managers[1].activate = 1
                self.sync_managers[2].activate = 0
                self.sync_managers[3].activate = 0
                self.reg_table.write_bit("%M233", False, privilege=PrivilegeMode.SYSTEM)
            elif self.al_state == ALState.SAFEOP:
                self.sync_managers[0].activate = 1
                self.sync_managers[1].activate = 1
                self.sync_managers[2].activate = 0
                self.sync_managers[3].activate = 1
                self.reg_table.write_bit("%M233", False, privilege=PrivilegeMode.SYSTEM)
            elif self.al_state == ALState.OP:
                self.sync_managers[0].activate = 1
                self.sync_managers[1].activate = 1
                self.sync_managers[2].activate = 1
                self.sync_managers[3].activate = 1
                self.reg_table.write_bit("%M233", True, privilege=PrivilegeMode.SYSTEM)

            self.sync_registers()
            return True, EtherCATALStatusCode.NO_ERROR

        # Illegal transition
        self.error_flag = True
        self.al_status_code = EtherCATALStatusCode.INVALID_STATE_CHANGE
        self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_INVALID_TRANSITION
        self.sync_registers()
        return False, self.al_status_code

    def check_sm_watchdog(self, simulated_elapsed_ms: float = 0.0) -> bool:
        self.simulated_clock_ms += simulated_elapsed_ms
        if self.al_state == ALState.OP and not self.watchdog_tripped:
            time_since_sm2 = self.simulated_clock_ms - self.last_sm2_event_time_ms
            if time_since_sm2 >= self.watchdog_timeout_ms:
                self.watchdog_tripped = True
                self.is_safety_tripped = True
                self.al_state = ALState.SAFEOP
                self.error_flag = True
                self.al_status_code = EtherCATALStatusCode.SM_WATCHDOG
                self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_SM_WATCHDOG
                self.tx_pdo_scaled = 0
                self.tx_pdo_val = 0.0
                self.od[(0x7000, 0x01)].value = 0
                self.sync_registers()
                return True
        return False

    def check_watchdog(self, elapsed_ms: float = 0.0) -> bool:
        return self.check_sm_watchdog(elapsed_ms)

    def trigger_safety_trip(self, code: EtherCATDiagnosticCode) -> None:
        self.is_safety_tripped = True
        self.watchdog_tripped = True
        self.diagnostic_code = code
        self.al_state = ALState.SAFEOP
        self.error_flag = True
        self.sync_registers()

    def evaluate_dc_jitter(self, arrival_timestamp_ns: int, expected_timestamp_ns: int) -> Tuple[int, bool]:
        jitter = abs(arrival_timestamp_ns - expected_timestamp_ns)
        self.dc_jitter_ns = jitter
        self.jitter_history.append(jitter)
        is_ok = jitter <= self.dc_jitter_threshold_ns
        if not is_ok:
            self.dc_sync_loss = True
            self.is_safety_tripped = True
            self.error_flag = True
            self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_DC_SYNC_LOSS
        else:
            self.dc_sync_loss = False
            if self.diagnostic_code == EtherCATDiagnosticCode.ETHERCAT_ERR_DC_SYNC_LOSS:
                self.diagnostic_code = EtherCATDiagnosticCode.OK
                self.is_safety_tripped = False
                self.error_flag = False
        self.sync_registers()
        return jitter, is_ok

    def read_sync_manager(self, channel_idx: int) -> SyncManagerChannel:
        if channel_idx not in self.sync_managers:
            raise SyncManagerConfigError(f"SyncManager channel {channel_idx} does not exist")
        return self.sync_managers[channel_idx]

    def write_sync_manager(self, channel_idx: int, channel: SyncManagerChannel) -> None:
        self.sync_managers[channel_idx] = channel

    def read_sdo(self, index: int, subindex: int) -> SDOFrame:
        req = SDOFrame(command=SDOCommand.UPLOAD_REQUEST, index=index, subindex=subindex)
        return self.handle_sdo_request(req)

    def write_sdo(self, index: int, subindex: int, value: Union[int, str, bytes]) -> SDOFrame:
        if isinstance(value, int):
            data = struct.pack("<I", value & 0xFFFFFFFF)
            cmd = SDOCommand.DOWNLOAD_EXPEDITED_4B
        elif isinstance(value, str):
            raw = value.encode("utf-8")[:4]
            data = (raw + b"\x00" * 4)[:4]
            cmd = SDOCommand.DOWNLOAD_EXPEDITED_4B
        else:
            data = (value + b"\x00" * 4)[:4]
            cmd = SDOCommand.DOWNLOAD_EXPEDITED_4B
        req = SDOFrame(command=cmd, index=index, subindex=subindex, data=data)
        return self.handle_sdo_request(req)

    def sync_dc_system_time(self, master_time_ns: int, propagation_delay_ns: int = 150) -> int:
        self.dc_system_time_ns = master_time_ns + propagation_delay_ns
        self.dc_enabled = True
        self.sync_registers()
        return self.dc_system_time_ns

    def generate_sync0_event(self, cycle_time_ns: int = DC_SYNC0_DEFAULT_CYCLE_NS) -> Dict[str, Any]:
        self.dc_sync0_cycle_ns = cycle_time_ns
        next_sync0 = ((self.dc_system_time_ns // cycle_time_ns) + 1) * cycle_time_ns
        return {
            "current_system_time_ns": self.dc_system_time_ns,
            "next_sync0_timestamp_ns": next_sync0,
            "cycle_time_ns": cycle_time_ns,
        }

    def simulate_sync0_pulse(self, jitter_offset_ns: int = 0) -> Tuple[int, bool]:
        expected = self.dc_system_time_ns + self.dc_sync0_cycle_ns
        arrival = expected + jitter_offset_ns
        self.dc_system_time_ns = arrival
        return self.evaluate_dc_jitter(arrival, expected)

    def handle_sdo_request(self, sdo: SDOFrame) -> SDOFrame:
        self.coe_od_counter = (self.coe_od_counter + 1) & 0xFFFF
        key = (sdo.index, sdo.subindex)

        # 1. SDO Upload Request
        if sdo.command == SDOCommand.UPLOAD_REQUEST:
            if key not in self.od:
                code = (
                    SDOAbortCode.SUBINDEX_NOT_EXIST
                    if any(k[0] == sdo.index for k in self.od)
                    else SDOAbortCode.OBJECT_NOT_EXIST
                )
                self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_SDO_ABORT
                self.sync_registers()
                return SDOFrame(SDOCommand.ABORT_TRANSFER, sdo.index, sdo.subindex, struct.pack("<I", code))

            entry = self.od[key]
            self.sync_registers()
            if entry.data_type == "uint32":
                return SDOFrame(SDOCommand.UPLOAD_EXPEDITED_4B, sdo.index, sdo.subindex, struct.pack("<I", int(entry.value)))
            elif entry.data_type in ("uint16", "int16"):
                return SDOFrame(SDOCommand.UPLOAD_EXPEDITED_2B, sdo.index, sdo.subindex, struct.pack("<H2x", int(entry.value) & 0xFFFF))
            elif entry.data_type == "string":
                return SDOFrame(SDOCommand.UPLOAD_EXPEDITED_4B, sdo.index, sdo.subindex, entry.value.encode("utf-8")[:4])
            else:
                return SDOFrame(SDOCommand.UPLOAD_EXPEDITED_1B, sdo.index, sdo.subindex, struct.pack("<B3x", int(entry.value) & 0xFF))

        # 2. SDO Download Request
        elif sdo.command in (SDOCommand.DOWNLOAD_EXPEDITED_4B, SDOCommand.DOWNLOAD_EXPEDITED_2B, SDOCommand.DOWNLOAD_EXPEDITED_1B):
            if key not in self.od:
                code = (
                    SDOAbortCode.SUBINDEX_NOT_EXIST
                    if any(k[0] == sdo.index for k in self.od)
                    else SDOAbortCode.OBJECT_NOT_EXIST
                )
                self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_SDO_ABORT
                self.sync_registers()
                return SDOFrame(SDOCommand.ABORT_TRANSFER, sdo.index, sdo.subindex, struct.pack("<I", code))

            entry = self.od[key]
            if not entry.writable:
                self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_SDO_ABORT
                self.sync_registers()
                return SDOFrame(SDOCommand.ABORT_TRANSFER, sdo.index, sdo.subindex, struct.pack("<I", SDOAbortCode.UNSUPPORTED_ACCESS))

            if sdo.command == SDOCommand.DOWNLOAD_EXPEDITED_4B:
                val = struct.unpack("<I", sdo.data[:4])[0]
            elif sdo.command == SDOCommand.DOWNLOAD_EXPEDITED_2B:
                val = struct.unpack("<H", sdo.data[:2])[0]
            else:
                val = sdo.data[0]

            entry.value = val
            if sdo.index == 0x6000 and sdo.subindex == 1:
                self.rx_pdo_scaled = int(val)
                self.rx_pdo_val = float(val) / 10.0
                if self.al_state == ALState.OP and not self.watchdog_tripped:
                    self.tx_pdo_scaled = self.rx_pdo_scaled
                    self.tx_pdo_val = self.rx_pdo_val
            self.sync_registers()
            return SDOFrame(SDOCommand.DOWNLOAD_RESPONSE, sdo.index, sdo.subindex, b"\x00\x00\x00\x00")

        self.diagnostic_code = EtherCATDiagnosticCode.ETHERCAT_ERR_SDO_ABORT
        self.sync_registers()
        return SDOFrame(SDOCommand.ABORT_TRANSFER, sdo.index, sdo.subindex, struct.pack("<I", SDOAbortCode.INVALID_COMMAND_SPECIFIER))

    def emit_emcy(
        self,
        error_code: int = 0x8210,
        error_register: int = 0x11,
        error_data: bytes = b"\x00\x00\x00\x00\x00",
    ) -> EtherCATDatagram:
        emcy_payload = struct.pack("<H", CoEService.EMERGENCY << 12) + EMCYFrame(error_code, error_register, error_data).serialize()
        mbx_bytes = MailboxEnvelope(
            length=len(emcy_payload),
            address=self.station_address,
            channel=0,
            priority=0,
            mbx_type=MailboxType.COE,
            counter=self.mailbox_counter,
            payload=emcy_payload,
        ).serialize()

        p_addr = self.sync_managers[1].physical_start_address
        self.esc_ram[p_addr : p_addr + len(mbx_bytes)] = mbx_bytes
        self.sync_managers[1].set_full(True)
        return EtherCATDatagram(EtherCATCommand.FPRD, 1, (self.station_address << 16) | p_addr, mbx_bytes, 1)

    def process_rx_pdo(self, data: Union[float, int, bytes], ch2_data: Optional[Union[float, int]] = None) -> None:
        self.sm_cycle_counter = (self.sm_cycle_counter + 1) & 0xFFFF
        self.cycle_counter = self.sm_cycle_counter
        self.last_sm2_event_time_ms = self.simulated_clock_ms

        if isinstance(data, bytes):
            if len(data) >= 4:
                w1, w2 = struct.unpack("<hh", data[:4])
                self.rx_pdo_scaled = w1
                self.rx_pdo_val = float(w1) / 10.0
                self.od[(0x6000, 0x01)].value = w1
                self.od[(0x6000, 0x02)].value = w2
            elif len(data) >= 2:
                w1 = struct.unpack("<h", data[:2])[0]
                self.rx_pdo_scaled = w1
                self.rx_pdo_val = float(w1) / 10.0
                self.od[(0x6000, 0x01)].value = w1
        else:
            self.rx_pdo_val = float(data)
            self.rx_pdo_scaled = scale_pv_to_int16(data, 10.0)
            self.od[(0x6000, 0x01)].value = self.rx_pdo_scaled
            if ch2_data is not None:
                self.od[(0x6000, 0x02)].value = scale_pv_to_int16(ch2_data, 10.0)

        if self.al_state == ALState.OP and not self.watchdog_tripped and not self.is_safety_tripped:
            self.tx_pdo_scaled = self.rx_pdo_scaled
            self.tx_pdo_val = self.rx_pdo_val
            self.od[(0x7000, 0x01)].value = self.tx_pdo_scaled
            if ch2_data is not None:
                self.od[(0x7000, 0x02)].value = self.od[(0x6000, 0x02)].value
        else:
            self.tx_pdo_scaled = 0
            self.tx_pdo_val = 0.0

        self.sync_registers()

    def step_scan_cycle(self, rx_word0: int = 0, rx_word1: int = 0, elapsed_ms: float = 10.0, cycles: int = 1) -> Dict[str, Any]:
        for _ in range(cycles):
            self.check_sm_watchdog(simulated_elapsed_ms=elapsed_ms)
        self.cycle_counter = (self.cycle_counter + 1) & 0xFFFF
        self.sm_cycle_counter = self.cycle_counter

        if self.operational_active:
            self.rx_pdo_scaled = rx_word0
            self.rx_pdo_val = float(rx_word0) / 10.0
            self.tx_pdo_scaled = rx_word0
            self.tx_pdo_val = float(rx_word0) / 10.0
            self.od[(0x6000, 0x01)].value = rx_word0
            self.od[(0x6000, 0x02)].value = rx_word1
            self.od[(0x7000, 0x01)].value = rx_word0
        self.sync_registers()
        return {
            "cycle": self.cycle_counter,
            "esm_state": self.al_state.name,
            "is_tripped": self.watchdog_tripped or self.is_safety_tripped,
            "diagnostic_code": f"0x{int(self.diagnostic_code):04X}",
        }

    def reset_safety(self) -> None:
        self.watchdog_tripped = False
        self.is_safety_tripped = False
        self.error_flag = False
        self.al_status_code = EtherCATALStatusCode.NO_ERROR
        self.diagnostic_code = EtherCATDiagnosticCode.OK
        self.dc_sync_loss = False
        self.alarm_latched = False
        self.last_sm2_event_time_ms = self.simulated_clock_ms
        self.reg_table.write_bit("%M233", True, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M234", False, privilege=PrivilegeMode.SYSTEM)
        self.sync_registers()

    def reset_fault(self) -> None:
        self.reset_safety()

    def process_datagram(self, dg: EtherCATDatagram) -> EtherCATDatagram:
        resp = EtherCATDatagram(dg.cmd, dg.index, dg.address, dg.data, dg.wkc)

        if dg.cmd == EtherCATCommand.FPWR:
            addr_st = (dg.address >> 16) & 0xFFFF
            addr_off = dg.address & 0xFFFF
            if addr_st == self.station_address and addr_off == self.sync_managers[0].physical_start_address:
                mbx = MailboxEnvelope.deserialize(dg.data)
                if mbx.mbx_type == MailboxType.COE:
                    sdo_req = SDOFrame.deserialize(mbx.payload[2:])
                    sdo_resp = self.handle_sdo_request(sdo_req)
                    resp_pay = struct.pack("<H", CoEService.SDO_RESPONSE << 12) + sdo_resp.serialize()
                    resp_mbx = MailboxEnvelope(
                        length=len(resp_pay),
                        address=self.station_address,
                        channel=0,
                        priority=0,
                        mbx_type=MailboxType.COE,
                        counter=mbx.counter,
                        payload=resp_pay,
                    ).serialize()

                    sm1_addr = self.sync_managers[1].physical_start_address
                    self.esc_ram[sm1_addr : sm1_addr + len(resp_mbx)] = resp_mbx
                    self.sync_managers[1].set_full(True)
                resp.wkc += 1
                return resp

        elif dg.cmd == EtherCATCommand.FPRD:
            addr_st = (dg.address >> 16) & 0xFFFF
            addr_off = dg.address & 0xFFFF
            if addr_st == self.station_address and addr_off == self.sync_managers[1].physical_start_address:
                if self.sync_managers[1].is_full:
                    resp.data = bytes(self.esc_ram[addr_off : addr_off + len(dg.data)])
                    self.sync_managers[1].set_full(False)
                    resp.wkc += 1
                return resp

        elif dg.cmd in (EtherCATCommand.LRW, EtherCATCommand.LWR, EtherCATCommand.LRD):
            data_arr = bytearray(dg.data)
            wkc_inc = 0

            if self.fmmus[0].enable and self.fmmus[0].is_write:
                f0_start = self.fmmus[0].logical_start_address
                if dg.address <= f0_start and dg.address + len(dg.data) >= f0_start + self.fmmus[0].length:
                    off = f0_start - dg.address
                    out_bytes = bytes(data_arr[off : off + self.fmmus[0].length])
                    if len(out_bytes) >= 4 and self.al_state == ALState.OP and not self.watchdog_tripped:
                        w1, w2 = struct.unpack("<hh", out_bytes[:4])
                        self.od[(0x6000, 0x01)].value = w1
                        self.od[(0x6000, 0x02)].value = w2
                        self.rx_pdo_scaled = w1
                        self.rx_pdo_val = float(w1) / 10.0
                    wkc_inc += 1

            if self.fmmus[1].enable and self.fmmus[1].is_read:
                f1_start = self.fmmus[1].logical_start_address
                if dg.address <= f1_start and dg.address + len(dg.data) >= f1_start + self.fmmus[1].length:
                    off = f1_start - dg.address
                    if self.al_state in (ALState.SAFEOP, ALState.OP) and not self.watchdog_tripped:
                        if self.al_state == ALState.OP:
                            self.tx_pdo_scaled = self.rx_pdo_scaled
                            self.tx_pdo_val = self.rx_pdo_val
                        tx_val = self.tx_pdo_scaled
                    else:
                        tx_val = 0
                    in_bytes = struct.pack("<hh4x", tx_val, 0)
                    data_arr[off : off + self.fmmus[1].length] = in_bytes
                    wkc_inc += 2

            self.last_wkc = wkc_inc
            self.sm_cycle_counter = (self.sm_cycle_counter + 1) & 0xFFFF
            self.cycle_counter = self.sm_cycle_counter
            self.last_sm2_event_time_ms = self.simulated_clock_ms
            self.sync_registers()
            resp.data = bytes(data_arr)
            resp.wkc += wkc_inc
            return resp

        return resp

    def sync_registers(self) -> None:
        status_word = int(self.al_state) & 0x0F
        if self.error_flag or self.is_safety_tripped:
            status_word |= EtherCATStatusBits.ERROR_ACTIVE
        if self.dc_enabled:
            status_word |= EtherCATStatusBits.DC_SYNCHRONIZED
            if self.dc_jitter_ns <= self.dc_jitter_threshold_ns:
                status_word |= EtherCATStatusBits.JITTER_OK
            else:
                status_word |= EtherCATStatusBits.JITTER_WARNING
        if self.watchdog_tripped or self.is_safety_tripped:
            status_word |= EtherCATStatusBits.SM_WATCHDOG_TRIP
        if self.operational_active:
            status_word |= EtherCATStatusBits.OPERATIONAL_ACTIVE
        if self.mailbox_active:
            status_word |= EtherCATStatusBits.MAILBOX_READY
        if self.al_state == ALState.OP and not self.watchdog_tripped:
            status_word |= EtherCATStatusBits.PROCESS_DATA_VALID

        self.reg_table.write_word("%R1000", status_word & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R1001", int(self.al_status_code) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R1002", self.sm_cycle_counter & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R1003", self.rx_pdo_scaled, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R1004", self.tx_pdo_scaled, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R1005", min(65535, self.dc_jitter_ns), privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R1006", self.coe_od_counter & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R1007", int(self.diagnostic_code) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        self.reg_table.write_bit("%M233", self.operational_active, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M234", bool(self.watchdog_tripped or self.is_safety_tripped), privilege=PrivilegeMode.SYSTEM)

    def sync_to_registers(self) -> None:
        self.sync_registers()


EtherCatSlaveEngine = EtherCATSlaveEngine
EtherCATSubDeviceEngine = EtherCATSlaveEngine
EtherCatSubDeviceSyncEngine = EtherCATSlaveEngine
EtherCATSubDeviceAdapter = EtherCATSlaveEngine
EtherCATSlaveAdapter = EtherCATSlaveEngine


# ============================================================================
# 6. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_ethercat_slave_verification(
    output_path: Optional[str] = None,
    evidence_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute end-to-end 9-stage verification for EtherCAT SubDevice Engine (W139)."""
    tests_record: List[Dict[str, Any]] = []

    # 1. Pure ST POU & Anti-Ladder Security Guard
    SecurityGuard.assert_pure_st_content(ETHERCAT_SLAVE_SYNC_POU)
    SecurityGuard.assert_pure_st_content(ETHERCAT_SUBDEVICE_SYNC_POU)

    ladder_snippets = [
        ETHERCAT_SLAVE_SYNC_POU + "\n---[ ]---",
        ETHERCAT_SLAVE_SYNC_POU + "\n---( )---",
        ETHERCAT_SLAVE_SYNC_POU + "\nRUNG 1",
        ETHERCAT_SLAVE_SYNC_POU + "\nNETWORK 1",
        ETHERCAT_SLAVE_SYNC_POU + "\nXIC MyBit",
        ETHERCAT_SLAVE_SYNC_POU + "\nOTE OutCoil",
    ]
    ladder_rejected = True
    for snip in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snip)
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    st_res = STParser.validate_code(ETHERCAT_SLAVE_SYNC_POU)
    ast = STParser.parse_pou(ETHERCAT_SLAVE_SYNC_POU)

    required_registers = {
        "%R1000", "%R1001", "%R1002", "%R1003",
        "%R1004", "%R1005", "%R1006", "%R1007",
        "%M233", "%M234"
    }
    bound_ok = all(r in ast.bound_registers for r in required_registers)

    s1_pass = (
        st_res.status == AgentStatus.SUCCESS
        and ast.name == "EtherCatSlaveSync"
        and ast.pou_type == POUType.PROGRAM
        and bound_ok
        and ladder_rejected
    )
    tests_record.append({
        "stage": 1,
        "check": "Pure_ST_POU_And_Anti_Ladder_Security_Guard",
        "passed": s1_pass,
        "details": "Verified IEC 61131-3 Pure ST POU, bound %R1000..%R1007 & %M233..%M234, rejected ladder constructs.",
    })

    # 2. AL State Machine Sequential Transitions & Safe Down-Transitions
    engine = EtherCATSlaveEngine()
    s2_init = (engine.al_state == ALState.INIT)

    ok_pre, c_pre = engine.request_state_transition(ALState.PREOP)
    ok_safe, c_safe = engine.request_state_transition(ALState.SAFEOP)
    ok_op, c_op = engine.request_state_transition(ALState.OP)

    in_op_m233 = engine.reg_table.read_bit("%M233")
    in_op_m234 = engine.reg_table.read_bit("%M234")
    r1000_op = engine.reg_table.read_uword("%R1000")

    ok_down_safe, _ = engine.request_state_transition(ALState.SAFEOP)
    down_m233 = engine.reg_table.read_bit("%M233")
    ok_down_pre, _ = engine.request_state_transition(ALState.PREOP)
    ok_down_init, _ = engine.request_state_transition(ALState.INIT)

    s2_pass = (
        s2_init
        and ok_pre and c_pre == EtherCATALStatusCode.NO_ERROR
        and ok_safe and c_safe == EtherCATALStatusCode.NO_ERROR
        and ok_op and c_op == EtherCATALStatusCode.NO_ERROR
        and in_op_m233 is True
        and in_op_m234 is False
        and (r1000_op & 0x0F) == ALState.OP
        and ok_down_safe and (down_m233 is False)
        and ok_down_pre and ok_down_init
        and engine.al_state == ALState.INIT
    )
    tests_record.append({
        "stage": 2,
        "check": "AL_State_Machine_Sequential_Transitions",
        "passed": s2_pass,
        "details": "Sequential transitions INIT -> PREOP -> SAFEOP -> OP and safe down-transitions verified cleanly.",
    })

    # 3. Illegal Transition Rejection & AL Status Code 0x0011 (Diagnostic 0xA402)
    engine.request_state_transition(ALState.INIT)
    illegal_ok, illegal_code = engine.request_state_transition(ALState.OP)

    r1001_illegal = engine.reg_table.read_uword("%R1001")
    r1007_illegal = engine.reg_table.read_uword("%R1007")
    r1000_err_flag = bool(engine.reg_table.read_uword("%R1000") & EtherCATStatusBits.ERROR_ACTIVE)

    ack_ok, ack_code = engine.request_state_transition(ALState.INIT)
    r1001_ack = engine.reg_table.read_uword("%R1001")
    r1007_ack = engine.reg_table.read_uword("%R1007")

    engine.request_state_transition(ALState.PREOP)
    skip_ok, skip_code = engine.request_state_transition(ALState.OP)
    r1007_skip = engine.reg_table.read_uword("%R1007")

    s3_pass = (
        not illegal_ok
        and illegal_code == EtherCATALStatusCode.INVALID_STATE_CHANGE
        and r1001_illegal == 0x0011
        and r1007_illegal == 0xA402
        and r1000_err_flag is True
        and ack_ok is True
        and ack_code == EtherCATALStatusCode.NO_ERROR
        and r1001_ack == 0x0000
        and r1007_ack == 0x0000
        and not skip_ok
        and skip_code == EtherCATALStatusCode.INVALID_STATE_CHANGE
        and r1007_skip == 0xA402
    )
    tests_record.append({
        "stage": 3,
        "check": "Illegal_Transition_Rejection_And_Diagnostics_0xA402",
        "passed": s3_pass,
        "details": f"Illegal skip transitions rejected with AL status code 0x0011 and diagnostic code 0x{r1007_illegal:04X}.",
    })

    # 4. SyncManager Configuration & Channel Activation (SM0..SM3)
    sm_eng = EtherCATSlaveEngine()
    sm0 = sm_eng.sync_managers[0]
    sm1 = sm_eng.sync_managers[1]
    sm2 = sm_eng.sync_managers[2]
    sm3 = sm_eng.sync_managers[3]

    cfg_ok = (
        sm0.physical_start_address == 0x1000 and sm0.length == 128
        and sm1.physical_start_address == 0x1080 and sm1.length == 128
        and sm2.physical_start_address == 0x1100 and sm2.length == 8
        and sm3.physical_start_address == 0x1140 and sm3.length == 8
    )

    sm_eng.request_state_transition(ALState.PREOP)
    mbx_active_preop = sm_eng.mailbox_active and (not sm_eng.rx_pdo_active)
    sm_eng.request_state_transition(ALState.SAFEOP)
    tx_active_safeop = sm_eng.tx_pdo_active and (not sm_eng.rx_pdo_active)
    sm_eng.request_state_transition(ALState.OP)
    all_active_op = sm_eng.rx_pdo_active and sm_eng.tx_pdo_active and sm_eng.operational_active

    for _ in range(5):
        sm_eng.process_rx_pdo(data=10.0)
    cycle_count = sm_eng.reg_table.read_uword("%R1002")

    s4_pass = cfg_ok and mbx_active_preop and tx_active_safeop and all_active_op and (cycle_count == 5)
    tests_record.append({
        "stage": 4,
        "check": "SyncManager_Configuration_And_Channel_Activation",
        "passed": s4_pass,
        "details": "SM0..SM3 channels configured, state-dependent activation verified, cycle counter incremented to 5.",
    })

    # 5. CoE Object Dictionary & SDO Transactions
    sdo_eng = EtherCATSlaveEngine()
    sdo_eng.request_state_transition(ALState.PREOP)

    up_req = SDOFrame(command=SDOCommand.UPLOAD_REQUEST, index=0x1018, subindex=0x01)
    up_resp = sdo_eng.handle_sdo_request(up_req)
    vendor_val = struct.unpack("<I", up_resp.data[:4])[0]

    down_req = SDOFrame(
        command=SDOCommand.DOWNLOAD_EXPEDITED_2B,
        index=0x6000,
        subindex=0x01,
        data=struct.pack("<H2x", 450),
    )
    down_resp = sdo_eng.handle_sdo_request(down_req)
    od_written_val = sdo_eng.od[(0x6000, 0x01)].value
    sdo_counter = sdo_eng.reg_table.read_uword("%R1006")

    s5_pass = (
        up_resp.command == SDOCommand.UPLOAD_EXPEDITED_4B
        and vendor_val == 0x00000059
        and down_resp.command == SDOCommand.DOWNLOAD_RESPONSE
        and od_written_val == 450
        and sdo_counter >= 2
    )
    tests_record.append({
        "stage": 5,
        "check": "CoE_Object_Dictionary_And_SDO_Transactions",
        "passed": s5_pass,
        "details": f"CoE SDO Upload (Vendor ID 0x{vendor_val:08X}) and Download expedited write (450) verified.",
    })

    # 6. SDO Abort Code Exception Trapping (Diagnostic 0xA404)
    abort_eng = EtherCATSlaveEngine()
    abort_eng.request_state_transition(ALState.PREOP)

    bad_obj_req = SDOFrame(command=SDOCommand.UPLOAD_REQUEST, index=0x9999, subindex=0x00)
    bad_obj_resp = abort_eng.handle_sdo_request(bad_obj_req)
    code_obj_abort = struct.unpack("<I", bad_obj_resp.data[:4])[0]
    r1007_obj = abort_eng.reg_table.read_uword("%R1007")

    ro_req = SDOFrame(command=SDOCommand.DOWNLOAD_EXPEDITED_4B, index=0x1000, subindex=0x00, data=struct.pack("<I", 0x1234))
    ro_resp = abort_eng.handle_sdo_request(ro_req)
    code_ro_abort = struct.unpack("<I", ro_resp.data[:4])[0]
    r1007_ro = abort_eng.reg_table.read_uword("%R1007")

    bad_sub_req = SDOFrame(command=SDOCommand.UPLOAD_REQUEST, index=0x1018, subindex=0x09)
    bad_sub_resp = abort_eng.handle_sdo_request(bad_sub_req)
    code_sub_abort = struct.unpack("<I", bad_sub_resp.data[:4])[0]

    s6_pass = (
        bad_obj_resp.command == SDOCommand.ABORT_TRANSFER
        and code_obj_abort == SDOAbortCode.OBJECT_NOT_EXIST
        and r1007_obj == 0xA404
        and ro_resp.command == SDOCommand.ABORT_TRANSFER
        and code_ro_abort == SDOAbortCode.UNSUPPORTED_ACCESS
        and r1007_ro == 0xA404
        and bad_sub_resp.command == SDOCommand.ABORT_TRANSFER
        and code_sub_abort == SDOAbortCode.SUBINDEX_NOT_EXIST
    )
    tests_record.append({
        "stage": 6,
        "check": "SDO_Abort_Exception_Trapping_0xA404",
        "passed": s6_pass,
        "details": f"SDO abort traps asserted diagnostic code 0x{r1007_obj:04X}.",
    })

    # 7. Distributed Clocks (DC) Sub-Microsecond Jitter & Sync Loss (0xA403)
    dc_eng = EtherCATSlaveEngine()
    j_nom, ok_nom = dc_eng.simulate_sync0_pulse(jitter_offset_ns=45)
    r1005_nom = dc_eng.reg_table.read_uword("%R1005")
    r1007_nom = dc_eng.reg_table.read_uword("%R1007")

    j_spike, ok_spike = dc_eng.simulate_sync0_pulse(jitter_offset_ns=620)
    r1005_spike = dc_eng.reg_table.read_uword("%R1005")
    r1007_spike = dc_eng.reg_table.read_uword("%R1007")

    s7_pass = (
        j_nom == 45
        and ok_nom is True
        and r1005_nom == 45
        and r1007_nom == 0x0000
        and j_spike == 620
        and ok_spike is False
        and r1005_spike == 620
        and r1007_spike == 0xA403
    )
    tests_record.append({
        "stage": 7,
        "check": "Distributed_Clocks_Sub_Microsecond_Jitter_And_Sync_Loss_0xA403",
        "passed": s7_pass,
        "details": f"DC Sync0 jitter tracked nominal {j_nom} ns and detected sync loss {j_spike} ns (diagnostic 0x{r1007_spike:04X}).",
    })

    # 8. SyncManager Watchdog Timer Expiry & Process Safety Fallback (0xA401)
    wd_eng = EtherCATSlaveEngine(watchdog_timeout_ms=100.0)
    wd_eng.request_state_transition(ALState.PREOP)
    wd_eng.request_state_transition(ALState.SAFEOP)
    wd_eng.request_state_transition(ALState.OP)
    wd_eng.process_rx_pdo(data=42.0)

    pre_m233 = wd_eng.reg_table.read_bit("%M233")
    pre_m234 = wd_eng.reg_table.read_bit("%M234")

    tripped = wd_eng.check_sm_watchdog(simulated_elapsed_ms=150.0)
    post_m233 = wd_eng.reg_table.read_bit("%M233")
    post_m234 = wd_eng.reg_table.read_bit("%M234")
    r1001_wd = wd_eng.reg_table.read_uword("%R1001")
    r1007_wd = wd_eng.reg_table.read_uword("%R1007")
    r1004_wd = wd_eng.reg_table.read_word("%R1004")
    fallback_state = wd_eng.al_state

    s8_pass = (
        pre_m233 is True
        and pre_m234 is False
        and tripped is True
        and wd_eng.watchdog_tripped is True
        and fallback_state == ALState.SAFEOP
        and post_m233 is False
        and post_m234 is True
        and r1001_wd == 0x001B
        and r1007_wd == 0xA401
        and r1004_wd == 0
    )
    tests_record.append({
        "stage": 8,
        "check": "SyncManager_Watchdog_Timer_Expiry_And_Process_Safety_0xA401",
        "passed": s8_pass,
        "details": "SM2 watchdog timeout tripped 0xA401, cleared %M233, asserted %M234, and clamped outputs to zero in SAFEOP.",
    })

    # 9. Horner OCS Full Register Space Synchronization & Fault Recovery Pipeline
    wd_eng.reset_fault()
    rec_m234 = wd_eng.reg_table.read_bit("%M234")
    rec_r1001 = wd_eng.reg_table.read_uword("%R1001")
    rec_r1007 = wd_eng.reg_table.read_uword("%R1007")

    wd_eng.request_state_transition(ALState.SAFEOP)
    wd_eng.request_state_transition(ALState.OP)
    wd_eng.process_rx_pdo(data=27.4, ch2_data=88.2)

    r1000_full = wd_eng.reg_table.read_uword("%R1000")
    r1003_full = wd_eng.reg_table.read_word("%R1003")
    r1004_full = wd_eng.reg_table.read_word("%R1004")
    r1007_full = wd_eng.reg_table.read_uword("%R1007")
    final_m233 = wd_eng.reg_table.read_bit("%M233")
    final_m234 = wd_eng.reg_table.read_bit("%M234")

    s9_pass = (
        rec_m234 is False
        and rec_r1001 == 0x0000
        and rec_r1007 == 0x0000
        and final_m233 is True
        and final_m234 is False
        and r1003_full == 274
        and r1004_full == 274
        and r1007_full == 0x0000
        and bool(r1000_full & EtherCATStatusBits.OPERATIONAL_ACTIVE) is True
    )
    tests_record.append({
        "stage": 9,
        "check": "Horner_OCS_Full_Register_Space_Sync_And_Fault_Recovery_Pipeline",
        "passed": s9_pass,
        "details": "Fault recovery restored %M233=TRUE, %M234=FALSE, %R1007=0x0000, and synchronized process data scaled x10 (%R1003=274, %R1004=274).",
    })

    all_passed = all(t["passed"] for t in tests_record)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": (
            f"Industrial EtherCAT SubDevice (Slave) State Machine & CoE / SyncManager Engine verified cleanly "
            f"({sum(1 for t in tests_record if t['passed'])}/{len(tests_record)} checks passed)."
        ),
        "data": {
            "work_package": "W139",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial EtherCAT SubDevice (Slave) State Machine & CoE / SyncManager Engine",
            "checks_passed": sum(1 for t in tests_record if t["passed"]),
            "total_checks": len(tests_record),
            "tests": tests_record,
            "metrics": {
                "station_address": "0x1000",
                "vendor_id": f"0x{engine.vendor_id:08X} (Horner APG)",
                "product_code": f"0x{engine.product_code:08X}",
                "watchdog_timeout_ms": 100.0,
                "target_jitter_ns": 100,
                "dc_jitter_threshold_ns": 100,
                "jitter_trip_threshold_ns": 500,
                "sync0_cycle_ns": 1_000_000,
                "sync_manager_channels": 4,
                "sm0_mailbox_out_address": 0x1000,
                "sm1_mailbox_in_address": 0x1080,
                "sm2_rx_pdo_address": 0x1100,
                "sm3_tx_pdo_address": 0x1140,
            },
            "register_map": {
                "%R1000": "AlStatusStateWord",
                "%R1001": "AlStatusCode",
                "%R1002": "SyncManagerCycleCounter",
                "%R1003": "RxPdoProcessDataScaled",
                "%R1004": "TxPdoProcessDataScaled",
                "%R1005": "DcSyncErrorNs",
                "%R1006": "CoeObjectDirectoryCounter",
                "%R1007": "DiagnosticStatusCode",
                "%M233": "EtherCatOperationalActive",
                "%M234": "EtherCatWatchdogTrip",
                "status_word": "%R1000",
                "state_word": "%R1001",
                "al_status_code": "%R1001",
                "cycle_counter": "%R1002",
                "rx_pdo_0": "%R1003",
                "rx_pdo_1": "%R1004",
                "tx_pdo_0": "%R1004",
                "dc_jitter_ns": "%R1005",
                "dc_sync_error_ns": "%R1005",
                "coe_od_counter": "%R1006",
                "diagnostic_status_code": "%R1007",
                "slave_active": "%M233",
                "safety_trip": "%M234",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    target_path = output_path or evidence_path
    if target_path:
        out_p = Path(target_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence
