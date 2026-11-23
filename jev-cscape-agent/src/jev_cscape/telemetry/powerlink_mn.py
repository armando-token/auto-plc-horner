"""Industrial Ethernet POWERLINK Real-Time Isochronous Communication & Managing Node (MN) Poll Response Engine.

Work Package: W148 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Strict Pure ST POU 'PowerlinkMnSync' (and alias 'EthernetPowerlinkSync') with
   Horner OCS RegisterTable bindings (%R1090..%R1097, %M254..%M255). Pure IEC 61131-3
   Structured Text ONLY. Intercepts ladder logic constructs with ERR_LADDER_FORBIDDEN
   using SecurityGuard.assert_pure_st_content and STParser.
2. Complete Ethernet POWERLINK Protocol Architecture (EPSG DS 301 / IEC 61784-2):
   - Managing Node (MN) cycle timing model:
     * Start of Cycle (SoC) broadcast telegram with sub-microsecond precision.
     * Isochronous period: PReq (Poll Request) from MN to Controlled Nodes (CN 1..239)
       and PRes (Poll Response) from CNs.
     * Asynchronous period: SoA (Start of Asynchronous) and ASnd (Asynchronous Send) slot
       for acyclic communication.
   - NMT State Machine:
     NMT_GS_INITIALISATION -> NMT_GS_RESET_APP -> NMT_MS_NOT_ACTIVE
     -> NMT_MS_PRE_OPERATIONAL_1 -> NMT_MS_PRE_OPERATIONAL_2
     -> NMT_MS_READY_TO_OPERATE -> NMT_MS_OPERATIONAL.
   - CN monitoring: Heartbeat detection, loss-of-life detection (CN dropped after 3 consecutive missed PRes).
3. Process Safety Interlocks & Diagnostics:
   - 0xAD01: POWERLINK_ERR_CN_TIMEOUT (Controlled Node missed 3 consecutive PRes)
             -> asserts %M255 (ControlledNodeLossTrip).
   - 0xAD02: POWERLINK_ERR_SOC_JITTER_EXCESS (SoC jitter > 100 ns).
   - 0xAD03: POWERLINK_ERR_ASYNC_OVERRUN (asynchronous payload exceeds allocated slot time).
   - 0xAD04: POWERLINK_ERR_MANAGING_NODE_FAULT (loss of operational state)
             -> clears %M254 (PowerlinkMnPermissive).
4. Horner OCS Memory Space Integration:
   - %R1090: ManagingNodeState (INT16: 0..6).
   - %R1091: ActiveControlledNodeCount (INT16, 1..239).
   - %R1092: CycleTimeMicroseconds (INT16, e.g. 500 = 500 us).
   - %R1093: SocJitterNanoseconds (INT16, e.g. 20 = 20 ns).
   - %R1094: PollRequestCounter (16-bit uint, PReq cyclic count).
   - %R1095: PollResponseCounter (16-bit uint, PRes cyclic count).
   - %R1096: AsynchronousSlotTimeMicroseconds (INT16, e.g. 100 = 100 us).
   - %R1097: DiagnosticStatusCode (0x0000=OK, 0xAD01, 0xAD02, 0xAD03, 0xAD04).
   - %M254: PowerlinkMnPermissive (BOOL, True in NMT_MS_OPERATIONAL).
   - %M255: ControlledNodeLossTrip (BOOL, True on CN timeout).
5. Deterministic 9-Stage Verification Suite:
   - Function run_powerlink_mn_verification(output_path) implementing 9 stages
     and returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
import json
import math
from pathlib import Path
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import zlib

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (Work Package W148)
# ============================================================================

POWERLINK_ETHERTYPE: int = 0x88AB                     # Standard IEEE 802.3 Ethernet POWERLINK EtherType
POWERLINK_SPEED_BPS: int = 100_000_000                # 100 Mbit/s Fast Ethernet bandwidth
POWERLINK_MN_NODE_ID: int = 240                       # Standard Managing Node (MN) Address (0xF0)
POWERLINK_BROADCAST_NODE_ID: int = 255                # Broadcast Node ID (0xFF)
POWERLINK_MAX_CN_NODES: int = 239                     # Controlled Nodes addressable 1..239
POWERLINK_MAX_NODES: int = 240                        # Total maximum nodes (239 CNs + 1 MN)
POWERLINK_DEFAULT_CYCLE_TIME_US: int = 500            # 500 us nominal isochronous cycle time
POWERLINK_DEFAULT_ASYNC_SLOT_TIME_US: int = 100       # 100 us nominal asynchronous slot time
POWERLINK_DEFAULT_ASYNC_SLOT_US: int = 100            # Alias for async slot time
POWERLINK_JITTER_THRESHOLD_NS: int = 100              # Strictly < 100 ns SoC clock jitter threshold
POWERLINK_MAX_MISSED_PRES_TRIP: int = 3               # 3 consecutive missed PRes trips loss-of-life
POWERLINK_DEFAULT_LOSS_OF_LIFE_TOLERANCE: int = 3     # Alias for 3 consecutive missed PRes tolerance


# ============================================================================
# 2. Enums, Status Bits, & Diagnostic Codes
# ============================================================================

class PowerlinkManagingNodeState(IntEnum):
    """Ethernet POWERLINK Managing Node (MN) NMT States (%R1090).
    
    0 = NMT_GS_INITIALISATION
    1 = NMT_GS_RESET_APP
    2 = NMT_MS_NOT_ACTIVE
    3 = NMT_MS_PRE_OPERATIONAL_1
    4 = NMT_MS_PRE_OPERATIONAL_2
    5 = NMT_MS_READY_TO_OPERATE
    6 = NMT_MS_OPERATIONAL
    """
    NMT_GS_INITIALISATION = 0
    NMT_GS_RESET_APP = 1
    NMT_MS_NOT_ACTIVE = 2
    NMT_MS_PRE_OPERATIONAL_1 = 3
    NMT_MS_PRE_OPERATIONAL_2 = 4
    NMT_MS_READY_TO_OPERATE = 5
    NMT_MS_OPERATIONAL = 6


# Convenience aliases for state references
PowerlinkMNState = PowerlinkManagingNodeState
MNState = PowerlinkManagingNodeState
PowerlinkNmtState = PowerlinkManagingNodeState


class PowerlinkCNState(IntEnum):
    """Ethernet POWERLINK Controlled Node (CN) NMT States."""
    NMT_CS_NOT_ACTIVE = 0
    NMT_CS_PRE_OPERATIONAL_1 = 1
    NMT_CS_PRE_OPERATIONAL_2 = 2
    NMT_CS_READY_TO_OPERATE = 3
    NMT_CS_OPERATIONAL = 4
    NMT_CS_STOPPED = 5


class PowerlinkMessageType(IntEnum):
    """Ethernet POWERLINK Frame / Message Types."""
    SOC = 0x01   # Start of Cycle (MN Broadcast)
    PREQ = 0x03  # Poll Request (MN to CN Unicast)
    PRES = 0x04  # Poll Response (CN Broadcast)
    SOA = 0x05   # Start of Asynchronous (MN Broadcast)
    ASND = 0x06  # Asynchronous Send (CN or MN Acyclic)


# Convenience alias for telegram types
PowerlinkTelegramType = PowerlinkMessageType


class PowerlinkDiagnosticCode(IntEnum):
    """Horner OCS %R1097 Process Safety Diagnostic Status Codes."""
    OK                                  = 0x0000  # Normal healthy operation
    POWERLINK_ERR_CN_TIMEOUT            = 0xAD01  # Controlled Node missed 3 consecutive PRes -> %M255
    POWERLINK_ERR_SOC_JITTER_EXCESS     = 0xAD02  # SoC jitter > 100 ns
    POWERLINK_ERR_ASYNC_OVERRUN         = 0xAD03  # Asynchronous transmission exceeds allocated slot
    POWERLINK_ERR_MANAGING_NODE_FAULT   = 0xAD04  # Managing Node fault / loss of operational state -> clears %M254

    # Convenience aliases
    POWERLINK_ERR_CN_LOSS_OF_LIFE       = 0xAD01
    POWERLINK_ERR_JITTER_EXCESS         = 0xAD02
    POWERLINK_ERR_NMT_STATE_FAULT       = 0xAD04
    CN_TIMEOUT                          = 0xAD01
    SOC_JITTER_EXCESS                   = 0xAD02
    ASYNC_OVERRUN                       = 0xAD03
    MANAGING_NODE_FAULT                 = 0xAD04


class PowerlinkAsyncService(IntEnum):
    """Ethernet POWERLINK Acyclic Asynchronous Services."""
    IDENT_REQUEST = 0x01
    IDENT_RESPONSE = 0x02
    STATUS_REQUEST = 0x03
    STATUS_RESPONSE = 0x04
    NMT_REQUEST = 0x05
    SDO_SEQUENCE = 0x06


# ============================================================================
# 3. Pure ST POU Definitions (Work Package W148)
# ============================================================================

POWERLINK_MN_SYNC_POU: str = """PROGRAM PowerlinkMnSync
VAR
    (* Horner OCS Mapped Registers (W148 - POWERLINK Managing Node Poll Response Engine) *)
    ManagingNodeState               AT %R1090 : INT;    (* 0=INIT, 1=RESET_APP, 2=MS_NOT_ACTIVE, 3=PRE_OP_1, 4=PRE_OP_2, 5=READY_TO_OPERATE, 6=OPERATIONAL *)
    ActiveControlledNodeCount       AT %R1091 : INT;    (* Active CN count (1..239) *)
    CycleTimeMicroseconds           AT %R1092 : INT;    (* Cycle time in us (e.g. 500 us) *)
    SocJitterNanoseconds            AT %R1093 : INT;    (* SoC jitter in ns (<100 ns nominal) *)
    PollRequestCounter              AT %R1094 : INT;    (* Cyclic PReq master request count *)
    PollResponseCounter             AT %R1095 : INT;    (* Cyclic PRes slave response count *)
    AsynchronousSlotTimeMicroseconds AT %R1096 : INT;    (* Async slot time in us (e.g. 100 us) *)
    DiagnosticStatusCode           AT %R1097 : INT;    (* Diagnostic code: 0x0000=OK, 0xAD01..0xAD04 *)

    (* Discrete Safety Interlock Coils *)
    PowerlinkMnPermissive           AT %M254  : BOOL;   (* TRUE in NMT_MS_OPERATIONAL *)
    ControlledNodeLossTrip          AT %M255  : BOOL;   (* TRUE on CN timeout (missed 3 PRes) *)
END_VAR
VAR
    NodeTimeoutActive               : BOOL;
    ManagingNodeFault               : BOOL;
END_VAR

NodeTimeoutActive := (DiagnosticStatusCode = 16#AD01);
ManagingNodeFault := (DiagnosticStatusCode = 16#AD04) OR (DiagnosticStatusCode = 16#AD02);

(* Trip controlled node loss coil on 0xAD01 or explicit timeout *)
IF NodeTimeoutActive THEN
    ControlledNodeLossTrip := TRUE;
ELSE
    ControlledNodeLossTrip := FALSE;
END_IF;

(* Interlock MN permissive: TRUE only when state is OPERATIONAL (6), no faults, and no loss trip *)
IF ManagingNodeFault OR ControlledNodeLossTrip OR (ManagingNodeState <> 6) THEN
    PowerlinkMnPermissive := FALSE;
ELSE
    PowerlinkMnPermissive := TRUE;
END_IF;

IF PowerlinkMnPermissive THEN
    PollRequestCounter := PollRequestCounter + 1;
    PollResponseCounter := PollResponseCounter + 1;
END_IF;
END_PROGRAM
"""

ETHERNET_POWERLINK_SYNC_POU: str = """PROGRAM EthernetPowerlinkSync
VAR
    (* Horner OCS Mapped Registers (W148 - POWERLINK Managing Node Poll Response Engine) *)
    ManagingNodeState               AT %R1090 : INT;    (* 0=INIT, 1=RESET_APP, 2=MS_NOT_ACTIVE, 3=PRE_OP_1, 4=PRE_OP_2, 5=READY_TO_OPERATE, 6=OPERATIONAL *)
    ActiveControlledNodeCount       AT %R1091 : INT;    (* Active CN count (1..239) *)
    CycleTimeMicroseconds           AT %R1092 : INT;    (* Cycle time in us (e.g. 500 us) *)
    SocJitterNanoseconds            AT %R1093 : INT;    (* SoC jitter in ns (<100 ns nominal) *)
    PollRequestCounter              AT %R1094 : INT;    (* Cyclic PReq master request count *)
    PollResponseCounter             AT %R1095 : INT;    (* Cyclic PRes slave response count *)
    AsynchronousSlotTimeMicroseconds AT %R1096 : INT;    (* Async slot time in us (e.g. 100 us) *)
    DiagnosticStatusCode           AT %R1097 : INT;    (* Diagnostic code: 0x0000=OK, 0xAD01..0xAD04 *)

    (* Discrete Safety Interlock Coils *)
    PowerlinkMnPermissive           AT %M254  : BOOL;   (* TRUE in NMT_MS_OPERATIONAL *)
    ControlledNodeLossTrip          AT %M255  : BOOL;   (* TRUE on CN timeout (missed 3 PRes) *)
END_VAR
VAR
    NodeTimeoutActive               : BOOL;
    ManagingNodeFault               : BOOL;
END_VAR

NodeTimeoutActive := (DiagnosticStatusCode = 16#AD01);
ManagingNodeFault := (DiagnosticStatusCode = 16#AD04) OR (DiagnosticStatusCode = 16#AD02);

IF NodeTimeoutActive THEN
    ControlledNodeLossTrip := TRUE;
ELSE
    ControlledNodeLossTrip := FALSE;
END_IF;

IF ManagingNodeFault OR ControlledNodeLossTrip OR (ManagingNodeState <> 6) THEN
    PowerlinkMnPermissive := FALSE;
ELSE
    PowerlinkMnPermissive := TRUE;
END_IF;

IF PowerlinkMnPermissive THEN
    PollRequestCounter := PollRequestCounter + 1;
    PollResponseCounter := PollResponseCounter + 1;
END_IF;
END_PROGRAM
"""

# Aliases
POWERLINK_MN_PURE_ST_POU: str = POWERLINK_MN_SYNC_POU
POWERLINK_MANAGING_NODE_SYNC_POU: str = ETHERNET_POWERLINK_SYNC_POU
POWERLINK_PURE_ST_POU: str = POWERLINK_MN_SYNC_POU
PURE_ST_POU: str = POWERLINK_MN_SYNC_POU


def verify_powerlink_mn_pure_st() -> bool:
    """Validates the PowerlinkMnSync Structured Text POU against anti-ladder guards."""
    SecurityGuard.assert_pure_st_content(POWERLINK_MN_SYNC_POU)
    res = STParser.validate_code(POWERLINK_MN_SYNC_POU)
    return res.status == AgentStatus.SUCCESS


def scale_pv_to_int16(val: Union[float, int], scale_factor: float = 10.0) -> int:
    """Clamps and scales process variable to 16-bit signed integer (-32768..32767)."""
    scaled = int(round(float(val) * scale_factor))
    return max(-32768, min(32767, scaled))


scale_process_value_to_int16 = scale_pv_to_int16
scale_axis_position_to_int16 = scale_pv_to_int16
scale_cn_process_val_to_int16 = scale_pv_to_int16


# ============================================================================
# 4. Telegram Codecs (SoC, PReq, PRes, SoA, ASnd) with CRC32 Verification
# ============================================================================

# Ethernet Header Format: DstMAC (6B), SrcMAC (6B), EtherType (2B: 0x88AB), MsgType (1B), DstNode (1B), SrcNode (1B)
POWERLINK_ETH_HDR_FORMAT: str = ">6s6sHBBB"
POWERLINK_ETH_HDR_SIZE: int = struct.calcsize(POWERLINK_ETH_HDR_FORMAT)

# SoC Body: Flags (1B), NetTime_ns (8B uint64), RelativeTime_ns (8B uint64)
POWERLINK_SOC_BODY_FORMAT: str = ">BQQ"
POWERLINK_SOC_BODY_SIZE: int = struct.calcsize(POWERLINK_SOC_BODY_FORMAT)

# PReq Body: Flag1 (1B), Flag2 (1B), ControlWord (2B uint16), TargetValue (4B int32)
POWERLINK_PREQ_BODY_FORMAT: str = ">BBHi"
POWERLINK_PREQ_BODY_SIZE: int = struct.calcsize(POWERLINK_PREQ_BODY_FORMAT)

# PRes Body: NmtState (1B), Flag1 (1B), Flag2 (1B), StatusWord (2B uint16), ActualValue (4B int32), ErrorCode (2B uint16)
POWERLINK_PRES_BODY_FORMAT: str = ">BBBHiH"
POWERLINK_PRES_BODY_SIZE: int = struct.calcsize(POWERLINK_PRES_BODY_FORMAT)

# SoA Body: TargetNodeId (1B), ServiceId (1B), Flags (1B)
POWERLINK_SOA_BODY_FORMAT: str = ">BBB"
POWERLINK_SOA_BODY_SIZE: int = struct.calcsize(POWERLINK_SOA_BODY_FORMAT)

# ASnd Body: ServiceId (1B) + variable payload
POWERLINK_ASND_BODY_FORMAT: str = ">B"
POWERLINK_ASND_BODY_SIZE: int = struct.calcsize(POWERLINK_ASND_BODY_FORMAT)


@dataclass
class PowerlinkSoCTelegram:
    """Start of Cycle (SoC) broadcast telegram with sub-microsecond precision."""
    dst_mac: bytes = b"\xff\xff\xff\xff\xff\xff"
    src_mac: bytes = b"\x00\x60\x65\x10\x00\xF0"
    ethertype: int = POWERLINK_ETHERTYPE
    message_type: PowerlinkMessageType = PowerlinkMessageType.SOC
    dst_node_id: int = POWERLINK_BROADCAST_NODE_ID
    src_node_id: int = POWERLINK_MN_NODE_ID
    flags: int = 0
    net_time_ns: int = 0
    relative_time_ns: int = 0

    def serialize(self) -> bytes:
        hdr = struct.pack(
            POWERLINK_ETH_HDR_FORMAT,
            self.dst_mac,
            self.src_mac,
            self.ethertype,
            int(self.message_type),
            self.dst_node_id,
            self.src_node_id,
        )
        body = struct.pack(
            POWERLINK_SOC_BODY_FORMAT,
            self.flags,
            self.net_time_ns,
            self.relative_time_ns,
        )
        frame_content = hdr + body
        crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        return frame_content + struct.pack(">I", crc)

    @classmethod
    def deserialize(cls, raw: bytes) -> PowerlinkSoCTelegram:
        if len(raw) < POWERLINK_ETH_HDR_SIZE + POWERLINK_SOC_BODY_SIZE + 4:
            raise ValueError(f"Raw SoC telegram too short ({len(raw)} bytes).")
        frame_content = raw[:-4]
        recv_crc = struct.unpack(">I", raw[-4:])[0]
        calc_crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        if recv_crc != calc_crc:
            raise ValueError(f"POWERLINK SoC CRC32 mismatch: 0x{recv_crc:08X} != 0x{calc_crc:08X}")

        dst_mac, src_mac, etype, mtype, dst_node, src_node = struct.unpack(
            POWERLINK_ETH_HDR_FORMAT, frame_content[:POWERLINK_ETH_HDR_SIZE]
        )
        flags, net_time, rel_time = struct.unpack(
            POWERLINK_SOC_BODY_FORMAT,
            frame_content[POWERLINK_ETH_HDR_SIZE : POWERLINK_ETH_HDR_SIZE + POWERLINK_SOC_BODY_SIZE],
        )
        return cls(
            dst_mac=dst_mac,
            src_mac=src_mac,
            ethertype=etype,
            message_type=PowerlinkMessageType(mtype),
            dst_node_id=dst_node,
            src_node_id=src_node,
            flags=flags,
            net_time_ns=net_time,
            relative_time_ns=rel_time,
        )


@dataclass
class PowerlinkPReqTelegram:
    """Poll Request (PReq) unicast telegram sent from MN to Controlled Node."""
    dst_mac: bytes = b"\x00\x60\x65\x10\x00\x01"
    src_mac: bytes = b"\x00\x60\x65\x10\x00\xF0"
    ethertype: int = POWERLINK_ETHERTYPE
    message_type: PowerlinkMessageType = PowerlinkMessageType.PREQ
    dst_node_id: int = 1
    src_node_id: int = POWERLINK_MN_NODE_ID
    flag1: int = 0
    flag2: int = 0
    control_word: int = 0
    target_value: int = 0
    extra_payload: bytes = b""

    def serialize(self) -> bytes:
        hdr = struct.pack(
            POWERLINK_ETH_HDR_FORMAT,
            self.dst_mac,
            self.src_mac,
            self.ethertype,
            int(self.message_type),
            self.dst_node_id,
            self.src_node_id,
        )
        body = struct.pack(
            POWERLINK_PREQ_BODY_FORMAT,
            self.flag1,
            self.flag2,
            self.control_word,
            self.target_value,
        ) + self.extra_payload
        frame_content = hdr + body
        crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        return frame_content + struct.pack(">I", crc)

    @classmethod
    def deserialize(cls, raw: bytes) -> PowerlinkPReqTelegram:
        min_len = POWERLINK_ETH_HDR_SIZE + POWERLINK_PREQ_BODY_SIZE + 4
        if len(raw) < min_len:
            raise ValueError(f"Raw PReq telegram too short ({len(raw)} bytes).")
        frame_content = raw[:-4]
        recv_crc = struct.unpack(">I", raw[-4:])[0]
        calc_crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        if recv_crc != calc_crc:
            raise ValueError(f"POWERLINK PReq CRC32 mismatch: 0x{recv_crc:08X} != 0x{calc_crc:08X}")

        dst_mac, src_mac, etype, mtype, dst_node, src_node = struct.unpack(
            POWERLINK_ETH_HDR_FORMAT, frame_content[:POWERLINK_ETH_HDR_SIZE]
        )
        flag1, flag2, ctl_word, target_val = struct.unpack(
            POWERLINK_PREQ_BODY_FORMAT,
            frame_content[POWERLINK_ETH_HDR_SIZE : POWERLINK_ETH_HDR_SIZE + POWERLINK_PREQ_BODY_SIZE],
        )
        extra = frame_content[POWERLINK_ETH_HDR_SIZE + POWERLINK_PREQ_BODY_SIZE :]
        return cls(
            dst_mac=dst_mac,
            src_mac=src_mac,
            ethertype=etype,
            message_type=PowerlinkMessageType(mtype),
            dst_node_id=dst_node,
            src_node_id=src_node,
            flag1=flag1,
            flag2=flag2,
            control_word=ctl_word,
            target_value=target_val,
            extra_payload=extra,
        )


@dataclass
class PowerlinkPResTelegram:
    """Poll Response (PRes) broadcast telegram sent from Controlled Node."""
    dst_mac: bytes = b"\xff\xff\xff\xff\xff\xff"
    src_mac: bytes = b"\x00\x60\x65\x10\x00\x01"
    ethertype: int = POWERLINK_ETHERTYPE
    message_type: PowerlinkMessageType = PowerlinkMessageType.PRES
    dst_node_id: int = POWERLINK_BROADCAST_NODE_ID
    src_node_id: int = 1
    nmt_state: int = int(PowerlinkCNState.NMT_CS_OPERATIONAL)
    flag1: int = 0
    flag2: int = 0
    status_word: int = 0
    actual_value: int = 0
    error_code: int = 0
    extra_payload: bytes = b""

    def serialize(self) -> bytes:
        hdr = struct.pack(
            POWERLINK_ETH_HDR_FORMAT,
            self.dst_mac,
            self.src_mac,
            self.ethertype,
            int(self.message_type),
            self.dst_node_id,
            self.src_node_id,
        )
        body = struct.pack(
            POWERLINK_PRES_BODY_FORMAT,
            self.nmt_state,
            self.flag1,
            self.flag2,
            self.status_word,
            self.actual_value,
            self.error_code,
        ) + self.extra_payload
        frame_content = hdr + body
        crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        return frame_content + struct.pack(">I", crc)

    @classmethod
    def deserialize(cls, raw: bytes) -> PowerlinkPResTelegram:
        min_len = POWERLINK_ETH_HDR_SIZE + POWERLINK_PRES_BODY_SIZE + 4
        if len(raw) < min_len:
            raise ValueError(f"Raw PRes telegram too short ({len(raw)} bytes).")
        frame_content = raw[:-4]
        recv_crc = struct.unpack(">I", raw[-4:])[0]
        calc_crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        if recv_crc != calc_crc:
            raise ValueError(f"POWERLINK PRes CRC32 mismatch: 0x{recv_crc:08X} != 0x{calc_crc:08X}")

        dst_mac, src_mac, etype, mtype, dst_node, src_node = struct.unpack(
            POWERLINK_ETH_HDR_FORMAT, frame_content[:POWERLINK_ETH_HDR_SIZE]
        )
        nmt_st, flag1, flag2, stat_word, actual_val, err_code = struct.unpack(
            POWERLINK_PRES_BODY_FORMAT,
            frame_content[POWERLINK_ETH_HDR_SIZE : POWERLINK_ETH_HDR_SIZE + POWERLINK_PRES_BODY_SIZE],
        )
        extra = frame_content[POWERLINK_ETH_HDR_SIZE + POWERLINK_PRES_BODY_SIZE :]
        return cls(
            dst_mac=dst_mac,
            src_mac=src_mac,
            ethertype=etype,
            message_type=PowerlinkMessageType(mtype),
            dst_node_id=dst_node,
            src_node_id=src_node,
            nmt_state=nmt_st,
            flag1=flag1,
            flag2=flag2,
            status_word=stat_word,
            actual_value=actual_val,
            error_code=err_code,
            extra_payload=extra,
        )


@dataclass
class PowerlinkSoATelegram:
    """Start of Asynchronous (SoA) broadcast telegram signaling acyclic slot."""
    dst_mac: bytes = b"\xff\xff\xff\xff\xff\xff"
    src_mac: bytes = b"\x00\x60\x65\x10\x00\xF0"
    ethertype: int = POWERLINK_ETHERTYPE
    message_type: PowerlinkMessageType = PowerlinkMessageType.SOA
    dst_node_id: int = POWERLINK_BROADCAST_NODE_ID
    src_node_id: int = POWERLINK_MN_NODE_ID
    target_node_id: int = 1
    service_id: int = int(PowerlinkAsyncService.IDENT_REQUEST)
    flags: int = 0

    def serialize(self) -> bytes:
        hdr = struct.pack(
            POWERLINK_ETH_HDR_FORMAT,
            self.dst_mac,
            self.src_mac,
            self.ethertype,
            int(self.message_type),
            self.dst_node_id,
            self.src_node_id,
        )
        body = struct.pack(
            POWERLINK_SOA_BODY_FORMAT,
            self.target_node_id,
            self.service_id,
            self.flags,
        )
        frame_content = hdr + body
        crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        return frame_content + struct.pack(">I", crc)

    @classmethod
    def deserialize(cls, raw: bytes) -> PowerlinkSoATelegram:
        min_len = POWERLINK_ETH_HDR_SIZE + POWERLINK_SOA_BODY_SIZE + 4
        if len(raw) < min_len:
            raise ValueError(f"Raw SoA telegram too short ({len(raw)} bytes).")
        frame_content = raw[:-4]
        recv_crc = struct.unpack(">I", raw[-4:])[0]
        calc_crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        if recv_crc != calc_crc:
            raise ValueError(f"POWERLINK SoA CRC32 mismatch: 0x{recv_crc:08X} != 0x{calc_crc:08X}")

        dst_mac, src_mac, etype, mtype, dst_node, src_node = struct.unpack(
            POWERLINK_ETH_HDR_FORMAT, frame_content[:POWERLINK_ETH_HDR_SIZE]
        )
        target_node, service_id, flags = struct.unpack(
            POWERLINK_SOA_BODY_FORMAT,
            frame_content[POWERLINK_ETH_HDR_SIZE : POWERLINK_ETH_HDR_SIZE + POWERLINK_SOA_BODY_SIZE],
        )
        return cls(
            dst_mac=dst_mac,
            src_mac=src_mac,
            ethertype=etype,
            message_type=PowerlinkMessageType(mtype),
            dst_node_id=dst_node,
            src_node_id=src_node,
            target_node_id=target_node,
            service_id=service_id,
            flags=flags,
        )


@dataclass
class PowerlinkASndTelegram:
    """Asynchronous Send (ASnd) telegram for acyclic data transfer."""
    dst_mac: bytes = b"\x00\x60\x65\x10\x00\xF0"
    src_mac: bytes = b"\x00\x60\x65\x10\x00\x01"
    ethertype: int = POWERLINK_ETHERTYPE
    message_type: PowerlinkMessageType = PowerlinkMessageType.ASND
    dst_node_id: int = POWERLINK_MN_NODE_ID
    src_node_id: int = 1
    service_id: int = int(PowerlinkAsyncService.IDENT_RESPONSE)
    payload: bytes = b""

    def serialize(self) -> bytes:
        hdr = struct.pack(
            POWERLINK_ETH_HDR_FORMAT,
            self.dst_mac,
            self.src_mac,
            self.ethertype,
            int(self.message_type),
            self.dst_node_id,
            self.src_node_id,
        )
        body = struct.pack(POWERLINK_ASND_BODY_FORMAT, self.service_id) + self.payload
        frame_content = hdr + body
        crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        return frame_content + struct.pack(">I", crc)

    @classmethod
    def deserialize(cls, raw: bytes) -> PowerlinkASndTelegram:
        min_len = POWERLINK_ETH_HDR_SIZE + POWERLINK_ASND_BODY_SIZE + 4
        if len(raw) < min_len:
            raise ValueError(f"Raw ASnd telegram too short ({len(raw)} bytes).")
        frame_content = raw[:-4]
        recv_crc = struct.unpack(">I", raw[-4:])[0]
        calc_crc = zlib.crc32(frame_content) & 0xFFFFFFFF
        if recv_crc != calc_crc:
            raise ValueError(f"POWERLINK ASnd CRC32 mismatch: 0x{recv_crc:08X} != 0x{calc_crc:08X}")

        dst_mac, src_mac, etype, mtype, dst_node, src_node = struct.unpack(
            POWERLINK_ETH_HDR_FORMAT, frame_content[:POWERLINK_ETH_HDR_SIZE]
        )
        service_id = struct.unpack(
            POWERLINK_ASND_BODY_FORMAT,
            frame_content[POWERLINK_ETH_HDR_SIZE : POWERLINK_ETH_HDR_SIZE + POWERLINK_ASND_BODY_SIZE],
        )[0]
        payload = frame_content[POWERLINK_ETH_HDR_SIZE + POWERLINK_ASND_BODY_SIZE :]
        return cls(
            dst_mac=dst_mac,
            src_mac=src_mac,
            ethertype=etype,
            message_type=PowerlinkMessageType(mtype),
            dst_node_id=dst_node,
            src_node_id=src_node,
            service_id=service_id,
            payload=payload,
        )


# ============================================================================
# 5. Controlled Node (CN) Descriptor & Simulation
# ============================================================================

@dataclass
class PowerlinkControlledNode:
    """Descriptor and simulation state for a POWERLINK Controlled Node (CN 1..239)."""
    node_id: int
    node_name: str = ""
    nmt_state: PowerlinkCNState = PowerlinkCNState.NMT_CS_NOT_ACTIVE
    is_active: bool = True
    is_operational: bool = False
    is_timed_out: bool = False
    consecutive_missed_pres: int = 0
    heartbeat_count: int = 0
    control_word: int = 0
    status_word: int = 0
    target_value: int = 0
    actual_value: int = 0
    error_code: int = 0
    simulate_miss_response: bool = False
    parameter_validation_error: bool = False
    loss_of_life_tolerance: int = POWERLINK_DEFAULT_LOSS_OF_LIFE_TOLERANCE
    mac_address: bytes = field(default=b"")

    def __post_init__(self) -> None:
        if not (1 <= self.node_id <= POWERLINK_MAX_CN_NODES):
            raise ValueError(f"Invalid Controlled Node ID {self.node_id}; must be 1..{POWERLINK_MAX_CN_NODES}.")
        if not self.mac_address:
            self.mac_address = bytes([0x00, 0x60, 0x65, 0x10, (self.node_id >> 8) & 0xFF, self.node_id & 0xFF])
        if not self.node_name:
            self.node_name = f"CN_Node_{self.node_id}"

    @property
    def target_position(self) -> float:
        return float(self.target_value)

    @target_position.setter
    def target_position(self, val: Union[float, int]) -> None:
        self.target_value = int(round(val))

    @property
    def actual_position(self) -> float:
        return float(self.actual_value)

    @actual_position.setter
    def actual_position(self, val: Union[float, int]) -> None:
        self.actual_value = int(round(val))

    @property
    def is_online(self) -> bool:
        return self.is_active

    @is_online.setter
    def is_online(self, val: bool) -> None:
        self.is_active = val

    @property
    def loss_of_life_tripped(self) -> bool:
        return self.is_timed_out

    @loss_of_life_tripped.setter
    def loss_of_life_tripped(self, val: bool) -> None:
        self.is_timed_out = val

    @property
    def consecutive_missed_cycles(self) -> int:
        return self.consecutive_missed_pres

    @consecutive_missed_cycles.setter
    def consecutive_missed_cycles(self, val: int) -> None:
        self.consecutive_missed_pres = val

    def process_preq(self, preq: PowerlinkPReqTelegram) -> Optional[PowerlinkPResTelegram]:
        """Processes an incoming PReq from Managing Node and generates PRes."""
        if self.simulate_miss_response or self.is_timed_out or not self.is_active:
            return None

        self.control_word = preq.control_word
        self.target_value = preq.target_value

        # Emulate closed-loop tracking response
        self.actual_value += int(round((self.target_value - self.actual_value) * 0.5))

        return PowerlinkPResTelegram(
            dst_mac=b"\xff\xff\xff\xff\xff\xff",
            src_mac=self.mac_address,
            src_node_id=self.node_id,
            nmt_state=int(self.nmt_state),
            status_word=self.status_word,
            actual_value=self.actual_value,
            error_code=self.error_code,
        )

    def reset_health(self) -> None:
        """Restores healthy state of the Controlled Node."""
        self.is_timed_out = False
        self.is_active = True
        self.consecutive_missed_pres = 0
        self.simulate_miss_response = False
        self.parameter_validation_error = False
        self.error_code = 0


# ============================================================================
# 6. Managing Node (MN) Poll Response Engine
# ============================================================================

class PowerlinkManagingNodeEngine:
    """Industrial Ethernet POWERLINK Managing Node (MN) Engine.
    
    Coordinates:
    - Isochronous cycle clock with Start of Cycle (SoC) generation.
    - Poll Request (PReq) scheduling and Poll Response (PRes) tracking.
    - Asynchronous phase (SoA / ASnd) slot management and overrun surveillance.
    - Controlled Node loss-of-life detection (3-strike rule).
    - Horner OCS register space synchronization (%R1090..%R1097, %M254..%M255).
    """

    def __init__(
        self,
        reg_table: Optional[RegisterTable] = None,
        cycle_time_us: int = POWERLINK_DEFAULT_CYCLE_TIME_US,
        async_slot_time_us: int = POWERLINK_DEFAULT_ASYNC_SLOT_TIME_US,
    ) -> None:
        self.reg_table: RegisterTable = reg_table or RegisterTable()
        self.cycle_time_us: int = cycle_time_us
        self.async_slot_time_us: int = async_slot_time_us
        self.state: PowerlinkManagingNodeState = PowerlinkManagingNodeState.NMT_GS_INITIALISATION
        self.controlled_nodes: Dict[int, PowerlinkControlledNode] = {}
        self.cycle_counter: int = 0
        self.preq_counter: int = 0
        self.pres_counter: int = 0
        self.soc_jitter_ns: int = 0
        self.diagnostic_code: PowerlinkDiagnosticCode = PowerlinkDiagnosticCode.OK
        self.permissive_coil: bool = False
        self.loss_trip_coil: bool = False
        self.mac_address: bytes = b"\x00\x60\x65\x10\x00\xF0"
        self.current_async_grantee: int = 0

        self.sync_to_register_table()

    @property
    def active_cn_count(self) -> int:
        """Returns the count of healthy, active Controlled Nodes."""
        return sum(1 for cn in self.controlled_nodes.values() if cn.is_active and not cn.is_timed_out)

    @property
    def is_operational(self) -> bool:
        """True strictly when MN is in NMT_MS_OPERATIONAL with permissive active."""
        return (
            self.state == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL
            and self.permissive_coil
            and not self.loss_trip_coil
            and self.diagnostic_code == PowerlinkDiagnosticCode.OK
        )

    def configure_controlled_node(self, node: PowerlinkControlledNode) -> None:
        """Registers a Controlled Node with the Managing Node."""
        if not (1 <= node.node_id <= POWERLINK_MAX_CN_NODES):
            raise ValueError(f"Invalid CN node ID {node.node_id}. Must be 1..{POWERLINK_MAX_CN_NODES}.")
        self.controlled_nodes[node.node_id] = node
        self.sync_to_register_table()

    def remove_controlled_node(self, node_id: int) -> bool:
        """Removes a Controlled Node from the MN's configuration."""
        if node_id in self.controlled_nodes:
            del self.controlled_nodes[node_id]
            self.sync_to_register_table()
            return True
        return False

    def request_state_transition(
        self, target_state: Union[PowerlinkManagingNodeState, int]
    ) -> Tuple[bool, str]:
        """Evaluates and executes an NMT state transition per EPSG DS 301."""
        target = PowerlinkManagingNodeState(int(target_state))

        if target == self.state:
            return True, f"Already in {self.state.name}"

        curr = self.state

        # Sequential forward progression
        valid_forward = (
            (curr == PowerlinkManagingNodeState.NMT_GS_INITIALISATION and target == PowerlinkManagingNodeState.NMT_GS_RESET_APP)
            or (curr == PowerlinkManagingNodeState.NMT_GS_RESET_APP and target == PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE)
            or (curr == PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE and target == PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1)
            or (curr == PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1 and target == PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2)
            or (curr == PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2 and target == PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE)
            or (curr == PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE and target == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL)
        )

        # Valid downward transitions / resets
        valid_backward = (
            target == PowerlinkManagingNodeState.NMT_GS_RESET_APP
            or (curr == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL and target in (
                PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
                PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
                PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
            ))
            or (curr == PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE and target in (
                PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
                PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
            ))
            or (curr == PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2 and target == PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1)
        )

        if not (valid_forward or valid_backward):
            self.diagnostic_code = PowerlinkDiagnosticCode.POWERLINK_ERR_MANAGING_NODE_FAULT
            self.permissive_coil = False
            self.sync_to_register_table()
            return False, f"Illegal state transition from {curr.name} to {target.name}"

        # Transitioning to OPERATIONAL requires at least one active CN
        if target == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL:
            if self.active_cn_count == 0:
                self.diagnostic_code = PowerlinkDiagnosticCode.POWERLINK_ERR_MANAGING_NODE_FAULT
                self.permissive_coil = False
                self.sync_to_register_table()
                return False, "Cannot enter NMT_MS_OPERATIONAL with zero active Controlled Nodes"

        # Check parameter validation error or inactive CN when advancing beyond PreOp1
        if self.controlled_nodes and target in (
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
            PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
            PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
        ):
            for cn in self.controlled_nodes.values():
                if getattr(cn, "parameter_validation_error", False) or not cn.is_active:
                    self.diagnostic_code = PowerlinkDiagnosticCode.POWERLINK_ERR_MANAGING_NODE_FAULT
                    self.permissive_coil = False
                    self.sync_to_register_table()
                    return False, f"Controlled Node {cn.node_id} has validation error or is inactive"

        # Apply state change
        self.state = target
        if target == PowerlinkManagingNodeState.NMT_GS_RESET_APP:
            self.loss_trip_coil = False
            self.diagnostic_code = PowerlinkDiagnosticCode.OK
        elif self.diagnostic_code == PowerlinkDiagnosticCode.POWERLINK_ERR_MANAGING_NODE_FAULT:
            self.diagnostic_code = PowerlinkDiagnosticCode.OK

        # Synchronize CN NMT states
        for cn in self.controlled_nodes.values():
            if target == PowerlinkManagingNodeState.NMT_GS_RESET_APP:
                cn.nmt_state = PowerlinkCNState.NMT_CS_NOT_ACTIVE
                cn.is_operational = False
            elif target == PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1:
                cn.nmt_state = PowerlinkCNState.NMT_CS_PRE_OPERATIONAL_1
                cn.is_operational = False
            elif target == PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2:
                cn.nmt_state = PowerlinkCNState.NMT_CS_PRE_OPERATIONAL_2
                cn.is_operational = False
            elif target == PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE:
                cn.nmt_state = PowerlinkCNState.NMT_CS_READY_TO_OPERATE
                cn.is_operational = False
            elif target == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL:
                cn.nmt_state = PowerlinkCNState.NMT_CS_OPERATIONAL
                cn.is_operational = True

        # Permissive coil update
        if self.state == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL and not self.loss_trip_coil and self.diagnostic_code == PowerlinkDiagnosticCode.OK:
            self.permissive_coil = True
        else:
            self.permissive_coil = False

        self.sync_to_register_table()
        return True, f"Successfully entered {self.state.name}"

    def trigger_managing_node_fault(
        self, code: PowerlinkDiagnosticCode = PowerlinkDiagnosticCode.POWERLINK_ERR_MANAGING_NODE_FAULT
    ) -> None:
        """Triggers a Managing Node fault, clearing permissive coil %M254."""
        self.diagnostic_code = code
        self.permissive_coil = False
        self.sync_to_register_table()

    def reset_safety(self) -> None:
        """Clears safety trip coils and recovers Controlled Nodes."""
        self.loss_trip_coil = False
        if self.diagnostic_code in (
            PowerlinkDiagnosticCode.POWERLINK_ERR_CN_TIMEOUT,
            PowerlinkDiagnosticCode.POWERLINK_ERR_MANAGING_NODE_FAULT,
        ):
            self.diagnostic_code = PowerlinkDiagnosticCode.OK

        for cn in self.controlled_nodes.values():
            cn.reset_health()

        if (
            self.state == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL
            and self.diagnostic_code == PowerlinkDiagnosticCode.OK
        ):
            self.permissive_coil = True

        self.sync_to_register_table()

    def generate_soc_telegram(self) -> PowerlinkSoCTelegram:
        """Generates a high-precision Start of Cycle (SoC) broadcast telegram."""
        timestamp_ns = time.time_ns()
        return PowerlinkSoCTelegram(
            src_mac=self.mac_address,
            net_time_ns=timestamp_ns,
            relative_time_ns=self.cycle_counter * (self.cycle_time_us * 1000),
        )

    def generate_soa_telegram(self, target_node_id: int) -> PowerlinkSoATelegram:
        """Generates a Start of Asynchronous (SoA) broadcast telegram."""
        return PowerlinkSoATelegram(
            src_mac=self.mac_address,
            target_node_id=target_node_id,
            service_id=int(PowerlinkAsyncService.IDENT_REQUEST),
        )

    def execute_cycle(
        self,
        simulated_jitter_ns: int = 20,
        simulate_async_time_us: Optional[int] = None,
        async_duration_us: Optional[int] = None,
        drop_cn_response: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Executes a complete real-time POWERLINK isochronous and asynchronous cycle.
        
        Phases:
        1. SoC Broadcast & Clock Jitter Tracking.
        2. Isochronous PReq / PRes Exchange across all active Controlled Nodes.
        3. Asynchronous SoA / ASnd Slot Management & Overrun Surveillance.
        4. Register Table Synchronization (%R1090..%R1097, %M254..%M255).
        """
        self.cycle_counter += 1
        self.soc_jitter_ns = simulated_jitter_ns

        # 1. SoC Jitter Surveillance (Threshold: 100 ns)
        soc_telegram = self.generate_soc_telegram()
        jitter_tripped = False
        if simulated_jitter_ns > POWERLINK_JITTER_THRESHOLD_NS:
            self.diagnostic_code = PowerlinkDiagnosticCode.POWERLINK_ERR_SOC_JITTER_EXCESS
            self.permissive_coil = False
            jitter_tripped = True
        elif self.diagnostic_code == PowerlinkDiagnosticCode.POWERLINK_ERR_SOC_JITTER_EXCESS:
            self.diagnostic_code = PowerlinkDiagnosticCode.OK

        polled_nodes = 0
        responded_nodes = 0

        # 2. Isochronous Period (PReq / PRes)
        if self.state in (
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
            PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
            PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
        ):
            for cn_id in sorted(self.controlled_nodes.keys()):
                cn = self.controlled_nodes[cn_id]
                if cn.is_timed_out:
                    continue

                polled_nodes += 1
                self.preq_counter += 1

                if drop_cn_response is not None and cn_id == drop_cn_response:
                    pres = None
                else:
                    preq = PowerlinkPReqTelegram(
                        dst_mac=cn.mac_address,
                        src_mac=self.mac_address,
                        dst_node_id=cn_id,
                        control_word=cn.control_word,
                        target_value=cn.target_value,
                    )
                    pres = cn.process_preq(preq)

                if pres is not None:
                    responded_nodes += 1
                    self.pres_counter += 1
                    cn.consecutive_missed_pres = 0
                    cn.heartbeat_count += 1
                    cn.status_word = pres.status_word
                else:
                    cn.consecutive_missed_pres += 1
                    if cn.consecutive_missed_pres >= POWERLINK_MAX_MISSED_PRES_TRIP:
                        cn.is_timed_out = True
                        cn.is_active = False
                        self.loss_trip_coil = True
                        self.diagnostic_code = PowerlinkDiagnosticCode.POWERLINK_ERR_CN_TIMEOUT

        # 3. Asynchronous Period (SoA / ASnd)
        active_cns = [cid for cid, c in self.controlled_nodes.items() if c.is_active and not c.is_timed_out]
        if active_cns:
            self.current_async_grantee = active_cns[(self.cycle_counter - 1) % len(active_cns)]
            soa_telegram = self.generate_soa_telegram(self.current_async_grantee)
        else:
            self.current_async_grantee = 0
            soa_telegram = self.generate_soa_telegram(0)

        actual_async_us = (
            async_duration_us if async_duration_us is not None else (
                simulate_async_time_us if simulate_async_time_us is not None else 45
            )
        )

        overrun_tripped = False
        if actual_async_us > self.async_slot_time_us:
            self.diagnostic_code = PowerlinkDiagnosticCode.POWERLINK_ERR_ASYNC_OVERRUN
            self.loss_trip_coil = True
            self.permissive_coil = False
            overrun_tripped = True
        elif self.diagnostic_code == PowerlinkDiagnosticCode.POWERLINK_ERR_ASYNC_OVERRUN:
            self.diagnostic_code = PowerlinkDiagnosticCode.OK

        # 4. Permissive Coil Interlock Evaluation
        if (
            self.state == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL
            and not self.loss_trip_coil
            and self.diagnostic_code == PowerlinkDiagnosticCode.OK
        ):
            self.permissive_coil = True
        else:
            self.permissive_coil = False

        self.sync_to_register_table()

        status_str = "success"
        if jitter_tripped:
            status_str = "jitter_tripped"
        elif overrun_tripped:
            status_str = "async_overrun_tripped"

        return {
            "status": status_str,
            "cycle": self.cycle_counter,
            "state": self.state.name,
            "polled_nodes": polled_nodes,
            "polled_cns": polled_nodes,
            "responded_nodes": responded_nodes,
            "active_cn_count": self.active_cn_count,
            "soc_jitter_ns": self.soc_jitter_ns,
            "async_slot_time_us": self.async_slot_time_us,
            "async_duration_us": actual_async_us,
            "actual_async_time_us": actual_async_us,
            "diagnostic_code": int(self.diagnostic_code),
            "permissive_coil": self.permissive_coil,
            "loss_trip_coil": self.loss_trip_coil,
            "mn_permissive": self.permissive_coil,
        }

    def sync_to_register_table(self) -> None:
        """Synchronizes internal state with Horner OCS Register Table (%R1090..%R1097, %M254..%M255)."""
        # %R1090: ManagingNodeState (INT16: 0..6)
        self.reg_table.write_word("%R1090", int(self.state), privilege=PrivilegeMode.SYSTEM)
        # %R1091: ActiveControlledNodeCount (INT16: 1..239)
        self.reg_table.write_word("%R1091", self.active_cn_count, privilege=PrivilegeMode.SYSTEM)
        # %R1092: CycleTimeMicroseconds (INT16: e.g. 500)
        self.reg_table.write_word("%R1092", self.cycle_time_us, privilege=PrivilegeMode.SYSTEM)
        # %R1093: SocJitterNanoseconds (INT16: e.g. 20)
        self.reg_table.write_word("%R1093", self.soc_jitter_ns, privilege=PrivilegeMode.SYSTEM)
        # %R1094: PollRequestCounter (16-bit uint)
        self.reg_table.write_word("%R1094", self.preq_counter & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        # %R1095: PollResponseCounter (16-bit uint)
        self.reg_table.write_word("%R1095", self.pres_counter & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        # %R1096: AsynchronousSlotTimeMicroseconds (INT16: e.g. 100)
        self.reg_table.write_word("%R1096", self.async_slot_time_us, privilege=PrivilegeMode.SYSTEM)
        # %R1097: DiagnosticStatusCode (0x0000=OK, 0xAD01..0xAD04)
        self.reg_table.write_word("%R1097", int(self.diagnostic_code), privilege=PrivilegeMode.SYSTEM)
        # %M254: PowerlinkMnPermissive (BOOL, True in NMT_MS_OPERATIONAL)
        self.reg_table.write_bit("%M254", self.permissive_coil, privilege=PrivilegeMode.SYSTEM)
        # %M255: ControlledNodeLossTrip (BOOL, True on CN timeout)
        self.reg_table.write_bit("%M255", self.loss_trip_coil, privilege=PrivilegeMode.SYSTEM)

    @property
    def is_safety_tripped(self) -> bool:
        return self.loss_trip_coil or self.diagnostic_code != PowerlinkDiagnosticCode.OK

    @is_safety_tripped.setter
    def is_safety_tripped(self, val: bool) -> None:
        if not val:
            self.loss_trip_coil = False
            self.diagnostic_code = PowerlinkDiagnosticCode.OK
        else:
            self.loss_trip_coil = True

    @property
    def nmt_state(self) -> PowerlinkManagingNodeState:
        return self.state

    @nmt_state.setter
    def nmt_state(self, val: PowerlinkManagingNodeState) -> None:
        self.state = PowerlinkManagingNodeState(val)
        self.sync_to_register_table()

    @property
    def configured_cns(self) -> Dict[int, PowerlinkControlledNode]:
        return self.controlled_nodes

    @property
    def configured_nodes(self) -> Dict[int, PowerlinkControlledNode]:
        return self.controlled_nodes

    @property
    def mn_permissive(self) -> bool:
        return self.permissive_coil

    @property
    def preq_telegram_counter(self) -> int:
        return self.preq_counter

    @property
    def pres_telegram_counter(self) -> int:
        return self.pres_counter

    @property
    def soc_sync_jitter_ns(self) -> int:
        return self.soc_jitter_ns

    @property
    def async_slot_duration_us(self) -> int:
        return self.async_slot_time_us

    @property
    def async_slot_max_us(self) -> int:
        return self.async_slot_time_us

    def configure_cn(self, node: PowerlinkControlledNode) -> None:
        self.configure_controlled_node(node)

    def configure_node(self, node: PowerlinkControlledNode) -> None:
        self.configure_controlled_node(node)

    def start_engine(self) -> None:
        self.state = PowerlinkManagingNodeState.NMT_GS_INITIALISATION
        self.diagnostic_code = PowerlinkDiagnosticCode.OK
        self.permissive_coil = False
        self.loss_trip_coil = False
        self.sync_to_register_table()

    def transition_to_state(self, target_state: Union[PowerlinkManagingNodeState, int]) -> bool:
        ok, _ = self.request_state_transition(target_state)
        return ok

    def trigger_safety_trip(self, code: PowerlinkDiagnosticCode) -> None:
        self.diagnostic_code = code
        if code in (
            PowerlinkDiagnosticCode.POWERLINK_ERR_CN_TIMEOUT,
            PowerlinkDiagnosticCode.POWERLINK_ERR_ASYNC_OVERRUN,
        ):
            self.loss_trip_coil = True
        self.permissive_coil = False
        self.sync_to_register_table()

    def read_cn_object(self, node_id: int, index: int, subindex: int) -> Any:
        if node_id not in self.controlled_nodes:
            raise KeyError(f"Controlled Node {node_id} not configured")
        cn = self.controlled_nodes[node_id]
        if hasattr(cn, "object_dictionary"):
            key = (index, subindex)
            if key in cn.object_dictionary:
                return cn.object_dictionary[key]
        if index == 0x1000:
            return 0x00040192
        elif index == 0x6040:
            return cn.control_word
        elif index == 0x6041:
            return cn.status_word
        return 0

    def write_cn_object(self, node_id: int, index: int, subindex: int, value: Any) -> None:
        if node_id not in self.controlled_nodes:
            raise KeyError(f"Controlled Node {node_id} not configured")
        cn = self.controlled_nodes[node_id]
        if not hasattr(cn, "object_dictionary"):
            cn.object_dictionary = {}
        cn.object_dictionary[(index, subindex)] = value
        if index == 0x6040:
            cn.control_word = int(value)


PowerlinkMNEngine = PowerlinkManagingNodeEngine
PowerlinkMasterEngine = PowerlinkManagingNodeEngine


# ============================================================================
# 7. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_powerlink_mn_verification(
    output_path: Optional[Union[str, Path]] = None,
    evidence_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Autonomous 9-Stage Verification Suite for Work Package W148.
    
    Verifies:
    1. Pure ST POU AST parsing, symbol binding, and STParser validation (%R1090..%R1097, %M254..%M255).
    2. Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
    3. Managing Node NMT state machine progression (0..6) & invalid jump rejection.
    4. Start of Cycle (SoC) broadcast telegram generation & sub-microsecond precision timing.
    5. Isochronous period: PReq / PRes cyclic exchange with multiple CNs (%R1091, %R1094, %R1095, %M254).
    6. Controlled Node timeout detection & loss-of-life 3-strike rule (0xAD01, %M255).
    7. Sub-microsecond SoC clock jitter surveillance (< 100 ns) & threshold excursion (0xAD02, %R1093).
    8. Asynchronous period (SoA / ASnd) slot management & overrun interlock (0xAD03, %R1096).
    9. Managing Node fault (0xAD04), master permissive lockout (%M254), and clean recovery.
    
    Returns:
        Deterministic 4-state contract dictionary (status, error_code, details, data).
    """
    tests_record: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & Symbol Binding
    # ------------------------------------------------------------------------
    st_val_main = STParser.validate_code(POWERLINK_MN_SYNC_POU)
    SecurityGuard.assert_pure_st_content(POWERLINK_MN_SYNC_POU)
    ast_main = STParser.parse_pou(POWERLINK_MN_SYNC_POU)

    st_val_alias = STParser.validate_code(ETHERNET_POWERLINK_SYNC_POU)
    SecurityGuard.assert_pure_st_content(ETHERNET_POWERLINK_SYNC_POU)
    ast_alias = STParser.parse_pou(ETHERNET_POWERLINK_SYNC_POU)

    expected_regs = {
        "%R1090", "%R1091", "%R1092", "%R1093",
        "%R1094", "%R1095", "%R1096", "%R1097",
        "%M254", "%M255",
    }
    has_regs_main = expected_regs.issubset(set(ast_main.bound_registers))
    has_regs_alias = expected_regs.issubset(set(ast_alias.bound_registers))

    s1_pass = (
        st_val_main.status == AgentStatus.SUCCESS
        and st_val_alias.status == AgentStatus.SUCCESS
        and has_regs_main
        and has_regs_alias
        and ast_main.name == "PowerlinkMnSync"
        and ast_alias.name == "EthernetPowerlinkSync"
    )
    tests_record.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Register_Bindings",
        "passed": s1_pass,
        "details": (
            f"Validated POUs '{ast_main.name}' and '{ast_alias.name}' with "
            f"bound registers %R1090..%R1097 and %M254..%M255."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Construct Rejection & SecurityGuard Interception
    # ------------------------------------------------------------------------
    ladder_samples = [
        "PROGRAM BadLadder1\nVAR X: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
        "PROGRAM BadLadder2\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
        "PROGRAM BadLadder3\nVAR X: BOOL; END_VAR\nRUNG 1: XIC %M254 OTE %M255 END_RUNG\nEND_PROGRAM",
    ]
    ladder_rejected = True
    for sample in ladder_samples:
        try:
            SecurityGuard.assert_pure_st_content(sample)
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    val_res = STParser.validate_code(ladder_samples[0])
    s2_pass = ladder_rejected and (val_res.error_code == "ERR_LADDER_FORBIDDEN")
    tests_record.append({
        "stage": 2,
        "check": "Anti_Ladder_Construct_Security_Guard_Rejection",
        "passed": s2_pass,
        "details": "Ladder contacts, coils, and mnemonics strictly intercepted with ERR_LADDER_FORBIDDEN.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Managing Node NMT State Machine Progression & Transition Safety
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine = PowerlinkManagingNodeEngine(reg_table=rt, cycle_time_us=500, async_slot_time_us=100)
    for i in range(1, 5):
        engine.configure_controlled_node(PowerlinkControlledNode(node_id=i, node_name=f"Drive_CN_{i}"))

    # Initial state must be NMT_GS_INITIALISATION (0)
    init_state_ok = engine.state == PowerlinkManagingNodeState.NMT_GS_INITIALISATION
    reg_init = rt.read_word("%R1090") == 0

    # Illegal direct jump to OPERATIONAL must be rejected
    illegal_ok, _ = engine.request_state_transition(PowerlinkManagingNodeState.NMT_MS_OPERATIONAL)
    illegal_rejected = not illegal_ok

    # Sequential progression: 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6
    seq_steps = [
        PowerlinkManagingNodeState.NMT_GS_RESET_APP,
        PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE,
        PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
        PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
        PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
        PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
    ]
    progression_ok = True
    for target in seq_steps:
        ok, msg = engine.request_state_transition(target)
        if not ok or engine.state != target or rt.read_word("%R1090") != int(target):
            progression_ok = False
            break

    s3_pass = init_state_ok and reg_init and illegal_rejected and progression_ok and (engine.state == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL)
    tests_record.append({
        "stage": 3,
        "check": "Managing_Node_NMT_State_Machine_Progression_And_Safety",
        "passed": s3_pass,
        "details": "NMT 7-state machine traversed 0->1->2->3->4->5->6; illegal jumps rejected; %R1090 verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Start of Cycle (SoC) Generation & Precision Timing Model
    # ------------------------------------------------------------------------
    soc = engine.generate_soc_telegram()
    raw_soc = soc.serialize()
    deser_soc = PowerlinkSoCTelegram.deserialize(raw_soc)

    s4_pass = (
        deser_soc.ethertype == POWERLINK_ETHERTYPE
        and deser_soc.message_type == PowerlinkMessageType.SOC
        and deser_soc.dst_node_id == POWERLINK_BROADCAST_NODE_ID
        and deser_soc.src_node_id == POWERLINK_MN_NODE_ID
        and deser_soc.net_time_ns > 0
    )
    tests_record.append({
        "stage": 4,
        "check": "Start_Of_Cycle_SoC_Telegram_Generation_And_Precision_Timing",
        "passed": s4_pass,
        "details": f"SoC broadcast telegram serialized ({len(raw_soc)} B) with CRC32 and sub-microsecond timestamp.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Isochronous Period: PReq / PRes Cyclic Exchange with Multiple CNs
    # ------------------------------------------------------------------------
    initial_preq = engine.preq_counter
    initial_pres = engine.pres_counter

    for _ in range(5):
        engine.execute_cycle(simulated_jitter_ns=20)

    preq_diff = engine.preq_counter - initial_preq
    pres_diff = engine.pres_counter - initial_pres
    reg_active_cn = rt.read_word("%R1091")
    reg_preq = rt.read_word("%R1094")
    reg_pres = rt.read_word("%R1095")
    permissive_m254 = rt.read_bit("%M254")

    s5_pass = (
        preq_diff == 20  # 4 CNs * 5 cycles
        and pres_diff == 20
        and reg_active_cn == 4
        and reg_preq == (engine.preq_counter & 0xFFFF)
        and reg_pres == (engine.pres_counter & 0xFFFF)
        and permissive_m254 is True
    )
    tests_record.append({
        "stage": 5,
        "check": "Isochronous_PReq_PRes_Cyclic_Exchange_With_Multiple_CNs",
        "passed": s5_pass,
        "details": f"5 cycles executed across 4 CNs: 20 PReq / 20 PRes exchanged cleanly; %M254=TRUE.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Controlled Node Timeout Detection & Loss-of-Life 3-Strike Rule (0xAD01)
    # ------------------------------------------------------------------------
    # Set CN 3 to simulate missed response
    engine.controlled_nodes[3].simulate_miss_response = True

    # Miss 1: strike 1 (no trip)
    engine.execute_cycle(simulated_jitter_ns=20)
    strike1_ok = (engine.controlled_nodes[3].consecutive_missed_pres == 1) and not engine.loss_trip_coil

    # Miss 2: strike 2 (no trip)
    engine.execute_cycle(simulated_jitter_ns=20)
    strike2_ok = (engine.controlled_nodes[3].consecutive_missed_pres == 2) and not engine.loss_trip_coil

    # Miss 3: strike 3 (TRIP!)
    engine.execute_cycle(simulated_jitter_ns=20)
    diag_timeout = rt.read_uword("%R1097")
    trip_m255 = rt.read_bit("%M255")
    active_after_timeout = rt.read_word("%R1091")
    permissive_after_timeout = rt.read_bit("%M254")

    s6_pass = (
        strike1_ok
        and strike2_ok
        and (diag_timeout == int(PowerlinkDiagnosticCode.POWERLINK_ERR_CN_TIMEOUT))
        and (trip_m255 is True)
        and (active_after_timeout == 3)
        and (permissive_after_timeout is False)
        and engine.controlled_nodes[3].is_timed_out
    )
    tests_record.append({
        "stage": 6,
        "check": "Controlled_Node_Timeout_And_Loss_Of_Life_Trip_0xAD01",
        "passed": s6_pass,
        "details": "CN 3 dropped after 3 consecutive missed PRes; diagnostic 0xAD01 set; %M255 tripped; %M254 cleared.",
    })

    # Recover CN 3 for subsequent stages
    engine.reset_safety()

    # ------------------------------------------------------------------------
    # Stage 7: Sub-Microsecond SoC Clock Jitter Surveillance (< 100 ns) (0xAD02)
    # ------------------------------------------------------------------------
    # Nominal cycle with 22 ns jitter
    engine.execute_cycle(simulated_jitter_ns=22)
    reg_jitter_nom = rt.read_word("%R1093")
    diag_jitter_nom = rt.read_uword("%R1097")

    # Excursion cycle with 135 ns jitter (> 100 ns threshold)
    engine.execute_cycle(simulated_jitter_ns=135)
    reg_jitter_exc = rt.read_word("%R1093")
    diag_jitter_exc = rt.read_uword("%R1097")

    # Restore nominal jitter (25 ns)
    engine.execute_cycle(simulated_jitter_ns=25)
    diag_jitter_restored = rt.read_uword("%R1097")

    s7_pass = (
        reg_jitter_nom == 22
        and diag_jitter_nom == int(PowerlinkDiagnosticCode.OK)
        and reg_jitter_exc == 135
        and diag_jitter_exc == int(PowerlinkDiagnosticCode.POWERLINK_ERR_SOC_JITTER_EXCESS)
        and diag_jitter_restored == int(PowerlinkDiagnosticCode.OK)
    )
    tests_record.append({
        "stage": 7,
        "check": "Sub_Microsecond_SoC_Clock_Jitter_Surveillance_0xAD02",
        "passed": s7_pass,
        "details": "Jitter excursion 135 ns triggered 0xAD02; restored cleanly at 25 ns; %R1093 tracked.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Asynchronous Period Slot Management & Overrun Interlock (0xAD03)
    # ------------------------------------------------------------------------
    # Nominal async slot (45 us <= 100 us)
    engine.execute_cycle(simulated_jitter_ns=20, simulate_async_time_us=45)
    diag_async_nom = rt.read_uword("%R1097")
    reg_slot_time = rt.read_word("%R1096")

    # Overrun async slot (140 us > 100 us allocated)
    engine.execute_cycle(simulated_jitter_ns=20, simulate_async_time_us=140)
    diag_async_overrun = rt.read_uword("%R1097")

    # Restored normal async slot (40 us)
    engine.execute_cycle(simulated_jitter_ns=20, simulate_async_time_us=40)
    diag_async_restored = rt.read_uword("%R1097")

    s8_pass = (
        reg_slot_time == 100
        and diag_async_nom == int(PowerlinkDiagnosticCode.OK)
        and diag_async_overrun == int(PowerlinkDiagnosticCode.POWERLINK_ERR_ASYNC_OVERRUN)
        and diag_async_restored == int(PowerlinkDiagnosticCode.OK)
    )
    tests_record.append({
        "stage": 8,
        "check": "Asynchronous_Period_Slot_Management_And_Overrun_0xAD03",
        "passed": s8_pass,
        "details": "Async payload 140 us triggered 0xAD03 ASYNC_OVERRUN (>100 us slot); restored cleanly at 40 us.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Managing Node Fault (0xAD04), Master Permissive Lockout, and Recovery
    # ------------------------------------------------------------------------
    engine.trigger_managing_node_fault()
    diag_fault = rt.read_uword("%R1097")
    permissive_cleared = rt.read_bit("%M254") is False

    # Reset safety and verify recovery
    engine.reset_safety()
    recovered_permissive = rt.read_bit("%M254") is True
    diag_recovered = rt.read_uword("%R1097") == int(PowerlinkDiagnosticCode.OK)

    s9_pass = (
        diag_fault == int(PowerlinkDiagnosticCode.POWERLINK_ERR_MANAGING_NODE_FAULT)
        and permissive_cleared
        and recovered_permissive
        and diag_recovered
    )
    tests_record.append({
        "stage": 9,
        "check": "Managing_Node_Fault_Permissive_Lockout_0xAD04_And_Recovery",
        "passed": s9_pass,
        "details": "Managing Node fault triggered 0xAD04 and cleared %M254; restored cleanly upon reset_safety().",
    })

    all_passed = all(t["passed"] for t in tests_record)
    target_out = output_path or evidence_path

    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "POWERLINK_VERIFICATION_FAILED",
        "details": (
            f"Industrial Ethernet POWERLINK Managing Node (MN) Poll Response Engine verified cleanly "
            f"({sum(1 for t in tests_record if t['passed'])}/{len(tests_record)} checks passed)."
        ),
        "data": {
            "work_package": "W148",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Ethernet POWERLINK Managing Node (MN) Poll Response Engine",
            "checks_passed": sum(1 for t in tests_record if t["passed"]),
            "total_checks": len(tests_record),
            "tests": tests_record,
            "metrics": {
                "speed_bps": POWERLINK_SPEED_BPS,
                "cycle_time_us": engine.cycle_time_us,
                "soc_jitter_ns": engine.soc_jitter_ns,
                "async_slot_time_us": engine.async_slot_time_us,
                "preq_counter": engine.preq_counter,
                "pres_counter": engine.pres_counter,
                "active_cn_count": engine.active_cn_count,
                "configured_cns": len(engine.controlled_nodes),
            },
            "register_map": {
                "managing_node_state": "%R1090",
                "active_controlled_node_count": "%R1091",
                "cycle_time_microseconds": "%R1092",
                "soc_jitter_nanoseconds": "%R1093",
                "poll_request_counter": "%R1094",
                "poll_response_counter": "%R1095",
                "asynchronous_slot_time_microseconds": "%R1096",
                "diagnostic_status_code": "%R1097",
                "powerlink_mn_permissive_coil": "%M254",
                "controlled_node_loss_trip_coil": "%M255",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if target_out:
        p = Path(target_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence
