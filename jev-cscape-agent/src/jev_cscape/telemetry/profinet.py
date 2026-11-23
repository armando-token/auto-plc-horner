"""Industrial PROFINET IO RT (Real-Time) & DCP Protocol Telemetry Adapter Engine.

Work Package: W082 (Gate G8 Telemetry Protocols & Scaling Bridge / Gate G4 Simulation)
Standards: IEC 61158-6-10, IEC 61784-2 (Profiles CPF 3/4, 3/5, 3/6)
Conformance:
- PROFINET EtherType 0x8892 Framing
- Discovery and Basic Configuration Protocol (DCP) Identify / Get / Set
- DCP Block Options: IP Parameter (0x01), Device Properties (0x02), Control (0x05)
- Device Identification: Vendor 0x011B (Horner Electric), Device 0x0102, Station 'horner-ocs-exl1'
- Real-Time Cyclic IO Data Exchange (Frame ID 0x8000..0xBBFF)
- Multi-Slot IO Packing: Slot 1 (Analog %R 32 bytes), Slot 2 (Discrete %M 16 bytes)
- Provider / Consumer Status: IOPS (0x80 Good, 0x00 Bad), IOCS
- Cycle Counter, Data Status (0x35 Valid/Run), Transfer Status
- Horner OCS Register Table Mapping (%R430..%R435, %M100..%M101)
- Pure Structured Text (ST) POU Definition & Ladder Logic Rejection Guard
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import os
import struct
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Enums (IEC 61158-6-10)
# ============================================================================

class ProfinetConstants:
    ETHERTYPE_PROFINET: int = 0x8892
    
    # Frame ID Ranges
    FRAME_ID_DCP_HELLO: int = 0xFEFC
    FRAME_ID_DCP_GET_SET: int = 0xFEFD
    FRAME_ID_DCP_IDENT_REQ: int = 0xFEFD
    FRAME_ID_DCP_IDENT_RESP: int = 0xFEFE
    
    FRAME_ID_CYCLIC_MIN: int = 0x8000
    FRAME_ID_CYCLIC_MAX: int = 0xBBFF
    FRAME_ID_DEFAULT_CYCLIC: int = 0x8000
    
    FRAME_ID_ALARM_HIGH: int = 0xFC01
    FRAME_ID_ALARM_LOW: int = 0xFE01

    DEFAULT_STATION_NAME: str = "horner-ocs-exl1"
    DEFAULT_VENDOR_ID: int = 0x011B  # Horner Electric Vendor ID
    DEFAULT_DEVICE_ID: int = 0x0102  # OCS Controller Device ID


class DCPServiceId(IntEnum):
    GET = 0x03
    SET = 0x04
    IDENTIFY = 0x05
    HELLO = 0x06


class DCPServiceType(IntEnum):
    REQUEST = 0x00
    RESPONSE_SUCCESS = 0x01
    RESPONSE_ERROR = 0x05


class DCPOption(IntEnum):
    IP_PARAMETER = 0x01
    DEVICE_PROPERTIES = 0x02
    DHCP = 0x03
    RESERVED = 0x04
    CONTROL = 0x05
    DEVICE_INITIATIVE = 0x06
    ALL_SELECTOR = 0xFF


class DCPSuboptionIP(IntEnum):
    MAC_ADDRESS = 0x01
    IP_PARAMETER = 0x02
    FULL_IP_SUITE = 0x03


class DCPSuboptionDevice(IntEnum):
    MANUFACTURER_SPECIFIC = 0x01
    STATION_NAME = 0x02
    DEVICE_ID = 0x03
    DEVICE_ROLE = 0x04
    DEVICE_OPTIONS = 0x05
    ALIAS_NAME = 0x06
    DEVICE_INSTANCE = 0x07
    OEM_DEVICE_ID = 0x08


class DCPSuboptionControl(IntEnum):
    START_TRANSACTION = 0x01
    END_TRANSACTION = 0x02
    SIGNAL = 0x03
    RESPONSE = 0x04
    FACTORY_RESET = 0x05


class IOStatusQuality(IntEnum):
    BAD = 0x00
    GOOD = 0x80


class DataStatusBits(IntFlag):
    STATE_GOOD = 0x01       # 0 = Bad, 1 = Good
    REDUNDANCY_BACKUP = 0x02
    DATA_VALID = 0x04       # 0 = Invalid, 1 = Valid
    RESERVED_BIT3 = 0x08
    REDUNDANCY_PRIMARY = 0x10
    RUN_STOP = 0x20         # 0 = Stop, 1 = Run
    STATION_FAILURE = 0x40


# Standard RUN + VALID + GOOD DataStatus
NORMAL_DATA_STATUS: int = 0x35  # Bit 0 (Good), Bit 2 (Valid), Bit 4 (Primary), Bit 5 (Run)


class ProfinetStatusBits(IntFlag):
    """Bit definitions for Horner OCS %R430 Status Word."""
    ENGINE_ACTIVE = 1 << 0             # Bit 0: %M100 is ON and engine running
    DCP_IDENTIFIED = 1 << 1            # Bit 1: Station identified/configured via DCP
    CYCLIC_IO_ACTIVE = 1 << 2          # Bit 2: Cyclic RT IO frames currently exchanging
    PROVIDER_IOPS_GOOD = 1 << 3        # Bit 3: Local provider IOPS is Good (0x80)
    CONSUMER_FAULT_BAD = 1 << 4        # Bit 4: Consumer fault or remote IOCS is Bad
    FRAME_ID_MISMATCH = 1 << 5         # Bit 5: Unknown or out-of-range Frame ID received


# ============================================================================
# 2. DCP Block & Packet Structures
# ============================================================================

@dataclass
class DCPBlock:
    """Standard PROFINET DCP Data Block."""
    option: Union[DCPOption, int]
    suboption: int
    payload: bytes = b""
    block_status: Optional[int] = None  # 2 octets in response frames

    def serialize(self, is_response: bool = False) -> bytes:
        dlen = len(self.payload)
        if is_response:
            status = self.block_status if self.block_status is not None else 0x0000
            # Length covers status + payload
            total_len = dlen + 2
            # Option(1), Suboption(1), Length(2), BlockStatus(2), Payload
            out = struct.pack(">BBHH", int(self.option), self.suboption, total_len, status) + self.payload
        else:
            out = struct.pack(">BBH", int(self.option), self.suboption, dlen) + self.payload
        # If length is odd, PROFINET DCP pads with 1 octet (padding not counted in length)
        if len(out) % 2 != 0:
            out += b"\x00"
        return out

    @classmethod
    def deserialize(cls, data: bytes, is_response: bool = False) -> Tuple["DCPBlock", bytes]:
        if len(data) < 4:
            raise ValueError(f"DCP block requires at least 4 octets, got {len(data)}")
        opt, subopt, dlen = struct.unpack_from(">BBH", data, 0)
        offset = 4
        block_status = None
        if is_response:
            if dlen < 2:
                raise ValueError("DCP response block length must be >= 2 for block status")
            block_status = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            payload_len = dlen - 2
        else:
            payload_len = dlen
        
        if len(data) < offset + payload_len:
            raise ValueError(f"Insufficient data for DCP block payload: expected {payload_len} octets")
        payload = data[offset:offset + payload_len]
        total_consumed = offset + payload_len
        # Adjust for 2-octet alignment padding if needed
        if total_consumed % 2 != 0 and total_consumed < len(data):
            total_consumed += 1
        return cls(option=opt, suboption=subopt, payload=payload, block_status=block_status), data[total_consumed:]


@dataclass
class DCPPacket:
    """PROFINET DCP Protocol Header & Frame."""
    frame_id: int
    service_id: Union[DCPServiceId, int]
    service_type: Union[DCPServiceType, int]
    xid: int = 0x12345678
    response_delay: int = 0x0000
    blocks: List[DCPBlock] = field(default_factory=list)

    HEADER_SIZE: int = 12

    def serialize(self) -> bytes:
        is_resp = (int(self.service_type) in (DCPServiceType.RESPONSE_SUCCESS, DCPServiceType.RESPONSE_ERROR))
        body = b"".join(b.serialize(is_response=is_resp) for b in self.blocks)
        dcp_data_len = len(body)
        header = struct.pack(
            ">HBBHIH",
            self.frame_id,
            int(self.service_id),
            int(self.service_type),
            self.xid >> 16,
            ((self.xid & 0xFFFF) << 16) | (self.response_delay & 0xFFFF),
            dcp_data_len,
        )
        return header + body

    @classmethod
    def deserialize(cls, data: bytes) -> "DCPPacket":
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"DCP packet requires at least {cls.HEADER_SIZE} octets, got {len(data)}")
        frame_id, s_id, s_type, xid_hi, xid_lo_delay, dcp_len = struct.unpack_from(">HBBHIH", data, 0)
        xid = (xid_hi << 16) | (xid_lo_delay >> 16)
        response_delay = xid_lo_delay & 0xFFFF

        remaining = data[cls.HEADER_SIZE:cls.HEADER_SIZE + dcp_len]
        is_resp = (s_type in (DCPServiceType.RESPONSE_SUCCESS, DCPServiceType.RESPONSE_ERROR))
        blocks: List[DCPBlock] = []
        while remaining:
            block, remaining = DCPBlock.deserialize(remaining, is_response=is_resp)
            blocks.append(block)

        return cls(
            frame_id=frame_id,
            service_id=s_id,
            service_type=s_type,
            xid=xid,
            response_delay=response_delay,
            blocks=blocks,
        )


# ============================================================================
# 3. PROFINET IO RT Cyclic Frame Structure
# ============================================================================

@dataclass
class ProfinetRTCyclicFrame:
    """PROFINET IO Real-Time (RT) Cyclic Data Frame.
    
    Frame Layout:
    - Frame ID (2 octets, Big-Endian: 0x8000..0xBBFF)
    - Slot 1 Data (32 octets Analog Inputs %R430..%R445 or custom)
    - Slot 1 IOPS (1 octet: 0x80 Good / 0x00 Bad)
    - Slot 2 Data (16 octets Discrete Inputs/Coils %M)
    - Slot 2 IOPS (1 octet: 0x80 Good / 0x00 Bad)
    - Cycle Counter (2 octets, Big-Endian)
    - Data Status (1 octet: 0x35 Normal)
    - Transfer Status (1 octet: 0x00)
    """
    frame_id: int = ProfinetConstants.FRAME_ID_DEFAULT_CYCLIC
    slot1_data: bytes = b"\x00" * 32
    slot1_iops: int = IOStatusQuality.GOOD
    slot2_data: bytes = b"\x00" * 16
    slot2_iops: int = IOStatusQuality.GOOD
    cycle_counter: int = 0
    data_status: int = NORMAL_DATA_STATUS
    transfer_status: int = 0x00

    def serialize(self) -> bytes:
        s1 = self.slot1_data.ljust(32, b"\x00")[:32]
        s2 = self.slot2_data.ljust(16, b"\x00")[:16]
        payload = (
            struct.pack(">H", self.frame_id)
            + s1
            + struct.pack("B", self.slot1_iops)
            + s2
            + struct.pack("B", self.slot2_iops)
            + struct.pack(">HBB", self.cycle_counter & 0xFFFF, self.data_status, self.transfer_status)
        )
        return payload

    @classmethod
    def deserialize(cls, data: bytes) -> "ProfinetRTCyclicFrame":
        min_len = 2 + 32 + 1 + 16 + 1 + 2 + 1 + 1  # 54 bytes
        if len(data) < min_len:
            raise ValueError(f"Cyclic RT frame requires at least {min_len} octets, got {len(data)}")
        
        frame_id = struct.unpack_from(">H", data, 0)[0]
        offset = 2
        slot1_data = data[offset:offset + 32]
        offset += 32
        slot1_iops = data[offset]
        offset += 1
        slot2_data = data[offset:offset + 16]
        offset += 16
        slot2_iops = data[offset]
        offset += 1
        cycle_counter, data_status, transfer_status = struct.unpack_from(">HBB", data, offset)
        return cls(
            frame_id=frame_id,
            slot1_data=slot1_data,
            slot1_iops=slot1_iops,
            slot2_data=slot2_data,
            slot2_iops=slot2_iops,
            cycle_counter=cycle_counter,
            data_status=data_status,
            transfer_status=transfer_status,
        )


# ============================================================================
# 4. Pure ST POU Definition (IEC 61131-3)
# ============================================================================

PROFINET_PURE_ST_POU = """PROGRAM ProfinetIoRtAdapter
VAR
    (* Horner OCS Mapped Registers (W082 - Industrial PROFINET IO RT Adapter) *)
    StatusWord AT %R430 : INT;
    CyclicSequenceCounter AT %R431 : UINT;
    CyclicFramesRxCounter AT %R432 : UINT;
    CyclicFramesTxCounter AT %R433 : UINT;
    LastDcpServiceId AT %R434 : INT;
    ProviderIopsStatus AT %R435 : INT;

    (* Control & Command Coils *)
    EnableAdapter AT %M100 : BOOL;
    ResetCounters AT %M101 : BOOL;

    (* Internal Protocol Engine Working Variables *)
    BitEngineActive : BOOL;
    BitDcpIdentified : BOOL;
    BitConnectionActive : BOOL;
    BitProviderIopsGood : BOOL;
    BitConsumerFault : BOOL;
    BitFrameIdMismatch : BOOL;
    CalculatedStatus : INT;
END_VAR

(* 1. Asynchronous Error & Connection Reset Handshake *)
IF ResetCounters THEN
    CyclicSequenceCounter := 0;
    CyclicFramesRxCounter := 0;
    CyclicFramesTxCounter := 0;
    BitConnectionActive := FALSE;
    BitConsumerFault := FALSE;
    BitFrameIdMismatch := FALSE;
    ResetCounters := FALSE;
END_IF;

(* 2. Main PROFINET IO RT Protocol Execution Pipeline *)
IF EnableAdapter THEN
    BitEngineActive := TRUE;

    IF LastDcpServiceId = 5 THEN
        BitDcpIdentified := TRUE;
    ELSIF LastDcpServiceId = 3 THEN
        BitDcpIdentified := TRUE;
    ELSIF LastDcpServiceId = 4 THEN
        BitDcpIdentified := TRUE;
    ELSIF LastDcpServiceId = 0 THEN
        BitDcpIdentified := FALSE;
    ELSE
        BitDcpIdentified := FALSE;
    END_IF;

    IF CyclicFramesRxCounter > 0 THEN
        BitConnectionActive := TRUE;
    ELSE
        BitConnectionActive := FALSE;
    END_IF;

    IF ProviderIopsStatus = 128 THEN
        BitProviderIopsGood := TRUE;
        BitConsumerFault := FALSE;
    ELSIF ProviderIopsStatus = 0 THEN
        BitProviderIopsGood := FALSE;
        BitConsumerFault := TRUE;
    ELSE
        BitProviderIopsGood := FALSE;
        BitConsumerFault := TRUE;
    END_IF;

    (* Synthesize %R430 Status Word Bitfield *)
    CalculatedStatus := 0;
    IF BitEngineActive THEN
        CalculatedStatus := CalculatedStatus + 1;
    END_IF;
    IF BitDcpIdentified THEN
        CalculatedStatus := CalculatedStatus + 2;
    END_IF;
    IF BitConnectionActive THEN
        CalculatedStatus := CalculatedStatus + 4;
    END_IF;
    IF BitProviderIopsGood THEN
        CalculatedStatus := CalculatedStatus + 8;
    END_IF;
    IF BitConsumerFault THEN
        CalculatedStatus := CalculatedStatus + 16;
    END_IF;
    IF BitFrameIdMismatch THEN
        CalculatedStatus := CalculatedStatus + 32;
    END_IF;

    StatusWord := CalculatedStatus;
ELSE
    BitEngineActive := FALSE;
    BitConnectionActive := FALSE;
    StatusWord := 0;
END_IF;
END_PROGRAM
"""


# ============================================================================
# 5. PROFINET IO RT Adapter Engine
# ============================================================================

class ProfinetAdapterEngine:
    """Industrial PROFINET IO RT Telemetry Adapter and Emulation Engine."""

    def __init__(
        self,
        station_name: str = ProfinetConstants.DEFAULT_STATION_NAME,
        vendor_id: int = ProfinetConstants.DEFAULT_VENDOR_ID,
        device_id: int = ProfinetConstants.DEFAULT_DEVICE_ID,
        ip_address: str = "192.168.1.100",
        subnet_mask: str = "255.255.255.0",
        gateway: str = "192.168.1.1",
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.station_name = station_name
        self.vendor_id = vendor_id
        self.device_id = device_id
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask
        self.gateway = gateway
        self.registers = register_table or RegisterTable()

        # Operational status flags
        self.dcp_identified: bool = False
        self.cyclic_io_active: bool = False
        self.provider_iops: int = IOStatusQuality.GOOD
        self.consumer_fault: bool = False
        self.frame_id_mismatch: bool = False

        # Counters
        self.cyclic_sequence: int = 0
        self.cyclic_rx_count: int = 0
        self.cyclic_tx_count: int = 0
        self.last_dcp_service_id: int = 0

        # Enable engine coil by default
        self.registers.write_bit("%M100", True, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_bit("%M101", False, privilege=PrivilegeMode.SYSTEM)
        self.sync_registers_to_table()

    def sync_registers_to_table(self) -> None:
        """Pushes protocol state to Horner OCS registers %R430..%R435."""
        engine_active = self.registers.read_bit("%M100")
        
        status_word = 0
        if engine_active:
            status_word |= ProfinetStatusBits.ENGINE_ACTIVE
        if self.dcp_identified:
            status_word |= ProfinetStatusBits.DCP_IDENTIFIED
        if self.cyclic_io_active:
            status_word |= ProfinetStatusBits.CYCLIC_IO_ACTIVE
        if self.provider_iops == IOStatusQuality.GOOD:
            status_word |= ProfinetStatusBits.PROVIDER_IOPS_GOOD
        if self.consumer_fault:
            status_word |= ProfinetStatusBits.CONSUMER_FAULT_BAD
        if self.frame_id_mismatch:
            status_word |= ProfinetStatusBits.FRAME_ID_MISMATCH

        self.registers.write_word("%R430", status_word, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R431", self.cyclic_sequence & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R432", self.cyclic_rx_count & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R433", self.cyclic_tx_count & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R434", self.last_dcp_service_id, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R435", self.provider_iops, privilege=PrivilegeMode.SYSTEM)

    def handle_dcp_packet(self, raw_bytes: bytes) -> Optional[bytes]:
        """Processes an incoming PROFINET DCP discovery/configuration packet."""
        if not self.registers.read_bit("%M100"):
            return None  # Adapter disabled

        try:
            packet = DCPPacket.deserialize(raw_bytes)
        except Exception:
            self.frame_id_mismatch = True
            self.sync_registers_to_table()
            return None

        self.last_dcp_service_id = int(packet.service_id)

        # Handle Identify Request
        if packet.service_id == DCPServiceId.IDENTIFY and packet.service_type == DCPServiceType.REQUEST:
            self.dcp_identified = True
            resp_blocks: List[DCPBlock] = []

            # 1. Device Properties: Station Name
            name_bytes = self.station_name.encode("ascii")
            resp_blocks.append(DCPBlock(
                option=DCPOption.DEVICE_PROPERTIES,
                suboption=DCPSuboptionDevice.STATION_NAME,
                payload=name_bytes,
                block_status=0x0000,
            ))

            # 2. Device Properties: Device ID (Vendor ID 2 bytes, Device ID 2 bytes)
            dev_id_bytes = struct.pack(">HH", self.vendor_id, self.device_id)
            resp_blocks.append(DCPBlock(
                option=DCPOption.DEVICE_PROPERTIES,
                suboption=DCPSuboptionDevice.DEVICE_ID,
                payload=dev_id_bytes,
                block_status=0x0000,
            ))

            # 3. Device Properties: Device Role (0x01 = IO-Device)
            resp_blocks.append(DCPBlock(
                option=DCPOption.DEVICE_PROPERTIES,
                suboption=DCPSuboptionDevice.DEVICE_ROLE,
                payload=bytes([0x01, 0x00]),
                block_status=0x0000,
            ))

            # 4. IP Parameter Block
            ip_octets = bytes(int(x) for x in self.ip_address.split("."))
            sub_octets = bytes(int(x) for x in self.subnet_mask.split("."))
            gw_octets = bytes(int(x) for x in self.gateway.split("."))
            resp_blocks.append(DCPBlock(
                option=DCPOption.IP_PARAMETER,
                suboption=DCPSuboptionIP.IP_PARAMETER,
                payload=ip_octets + sub_octets + gw_octets,
                block_status=0x0000,
            ))

            resp_packet = DCPPacket(
                frame_id=ProfinetConstants.FRAME_ID_DCP_IDENT_RESP,
                service_id=DCPServiceId.IDENTIFY,
                service_type=DCPServiceType.RESPONSE_SUCCESS,
                xid=packet.xid,
                response_delay=0x0000,
                blocks=resp_blocks,
            )
            self.sync_registers_to_table()
            return resp_packet.serialize()

        # Handle DCP Set (e.g. Set IP parameters or Station Name)
        elif packet.service_id == DCPServiceId.SET and packet.service_type == DCPServiceType.REQUEST:
            for b in packet.blocks:
                if b.option == DCPOption.IP_PARAMETER and b.suboption == DCPSuboptionIP.IP_PARAMETER and len(b.payload) >= 12:
                    self.ip_address = ".".join(str(x) for x in b.payload[:4])
                    self.subnet_mask = ".".join(str(x) for x in b.payload[4:8])
                    self.gateway = ".".join(str(x) for x in b.payload[8:12])
                elif b.option == DCPOption.DEVICE_PROPERTIES and b.suboption == DCPSuboptionDevice.STATION_NAME:
                    self.station_name = b.payload.decode("ascii", errors="replace")

            resp_packet = DCPPacket(
                frame_id=ProfinetConstants.FRAME_ID_DCP_GET_SET,
                service_id=DCPServiceId.SET,
                service_type=DCPServiceType.RESPONSE_SUCCESS,
                xid=packet.xid,
                response_delay=0x0000,
                blocks=[DCPBlock(option=DCPOption.CONTROL, suboption=DCPSuboptionControl.RESPONSE, payload=b"", block_status=0x0000)],
            )
            self.dcp_identified = True
            self.sync_registers_to_table()
            return resp_packet.serialize()

        self.sync_registers_to_table()
        return None

    def handle_cyclic_frame(self, raw_bytes: bytes) -> Optional[bytes]:
        """Processes an incoming cyclic RT IO frame and produces return IO frame."""
        if not self.registers.read_bit("%M100"):
            return None

        # Check reset command
        if self.registers.read_bit("%M101"):
            self.cyclic_sequence = 0
            self.cyclic_rx_count = 0
            self.cyclic_tx_count = 0
            self.consumer_fault = False
            self.frame_id_mismatch = False
            self.registers.write_bit("%M101", False, privilege=PrivilegeMode.SYSTEM)

        try:
            rx_frame = ProfinetRTCyclicFrame.deserialize(raw_bytes)
        except Exception:
            self.frame_id_mismatch = True
            self.sync_registers_to_table()
            return None

        if not (ProfinetConstants.FRAME_ID_CYCLIC_MIN <= rx_frame.frame_id <= ProfinetConstants.FRAME_ID_CYCLIC_MAX):
            self.frame_id_mismatch = True
            self.sync_registers_to_table()
            return None

        self.cyclic_rx_count += 1
        self.cyclic_io_active = True

        # Consumer status check
        if rx_frame.slot1_iops != IOStatusQuality.GOOD or rx_frame.slot2_iops != IOStatusQuality.GOOD:
            self.consumer_fault = True
        else:
            self.consumer_fault = False

        # Build response cyclic frame packing local %R and %M registers
        self.cyclic_sequence = (self.cyclic_sequence + 1) & 0xFFFF
        self.cyclic_tx_count += 1

        # Slot 1: Read 16 analog words (%R430..%R445) -> 32 bytes
        s1_bytes = bytearray(32)
        for i in range(16):
            r_val = self.registers.read_word(f"%R{430 + i}")
            struct.pack_into(">H", s1_bytes, i * 2, r_val & 0xFFFF)

        # Slot 2: Read 16 discrete coils (%M100..%M115) -> 16 bytes
        s2_bytes = bytearray(16)
        for i in range(16):
            bit_val = 1 if self.registers.read_bit(f"%M{100 + i}") else 0
            s2_bytes[i] = bit_val

        tx_frame = ProfinetRTCyclicFrame(
            frame_id=rx_frame.frame_id,
            slot1_data=bytes(s1_bytes),
            slot1_iops=self.provider_iops,
            slot2_data=bytes(s2_bytes),
            slot2_iops=self.provider_iops,
            cycle_counter=self.cyclic_sequence,
            data_status=NORMAL_DATA_STATUS,
            transfer_status=0x00,
        )

        self.sync_registers_to_table()
        return tx_frame.serialize()


# ============================================================================
# 6. Verification Harness (G8 / G4 Evidence)
# ============================================================================

def run_profinet_verification(output_evidence_path: str = "artifacts/telemetry/profinet_evidence.json") -> Dict[str, Any]:
    """Executes the full PROFINET IO RT & DCP protocol verification suite."""
    tests_record: List[Dict[str, Any]] = []

    # 1. Pure ST POU Validation
    val_st = STParser.validate_code(PROFINET_PURE_ST_POU)
    SecurityGuard.assert_pure_st_content(PROFINET_PURE_ST_POU)
    st_passed = (val_st.status == AgentStatus.SUCCESS)
    tests_record.append({
        "check": "Pure_ST_POU_Validation",
        "pou_name": "ProfinetIoRtAdapter",
        "passed": st_passed,
    })

    # 2. Ladder Logic Rejection Guard
    forbidden_samples = [
        "PROGRAM Bad (* ---[ ]--- *) END_PROGRAM",
        "PROGRAM Bad (* ---[/]--- *) END_PROGRAM",
        "PROGRAM Bad (* ---( )--- *) END_PROGRAM",
        "PROGRAM Bad RUNG 1: XIC %M100 OTE %M101 END_RUNG END_PROGRAM",
    ]
    ladder_rejected = True
    for sample in forbidden_samples:
        try:
            SecurityGuard.assert_pure_st_content(sample)
            ladder_rejected = False
        except LadderForbiddenError:
            pass
    tests_record.append({
        "check": "Forbidden_Ladder_Construct_Rejection",
        "passed": ladder_rejected,
    })

    # 3. DCP Identify Request & Response Roundtrip
    engine = ProfinetAdapterEngine()
    ident_req = DCPPacket(
        frame_id=ProfinetConstants.FRAME_ID_DCP_IDENT_REQ,
        service_id=DCPServiceId.IDENTIFY,
        service_type=DCPServiceType.REQUEST,
        xid=0xCAFE1234,
        response_delay=0x0000,
        blocks=[DCPBlock(option=DCPOption.ALL_SELECTOR, suboption=0xFF, payload=b"")],
    )
    raw_ident = ident_req.serialize()
    resp_bytes = engine.handle_dcp_packet(raw_ident)
    dcp_passed = False
    if resp_bytes:
        resp_pkt = DCPPacket.deserialize(resp_bytes)
        dcp_passed = (
            resp_pkt.frame_id == ProfinetConstants.FRAME_ID_DCP_IDENT_RESP
            and resp_pkt.service_id == DCPServiceId.IDENTIFY
            and resp_pkt.service_type == DCPServiceType.RESPONSE_SUCCESS
            and resp_pkt.xid == 0xCAFE1234
            and len(resp_pkt.blocks) >= 4
            and engine.registers.read_word("%R434") == 0x05
            and (engine.registers.read_word("%R430") & ProfinetStatusBits.DCP_IDENTIFIED) != 0
        )
    tests_record.append({
        "check": "DCP_Identify_Discovery_Roundtrip",
        "passed": dcp_passed,
    })

    # 4. DCP Set IP Parameter Configuration
    new_ip = bytes([192, 168, 50, 20])
    new_sub = bytes([255, 255, 255, 0])
    new_gw = bytes([192, 168, 50, 1])
    set_req = DCPPacket(
        frame_id=ProfinetConstants.FRAME_ID_DCP_GET_SET,
        service_id=DCPServiceId.SET,
        service_type=DCPServiceType.REQUEST,
        xid=0x5678ABCD,
        blocks=[
            DCPBlock(option=DCPOption.IP_PARAMETER, suboption=DCPSuboptionIP.IP_PARAMETER, payload=new_ip + new_sub + new_gw),
            DCPBlock(option=DCPOption.DEVICE_PROPERTIES, suboption=DCPSuboptionDevice.STATION_NAME, payload=b"horner-cell-node"),
        ],
    )
    set_resp = engine.handle_dcp_packet(set_req.serialize())
    set_passed = (
        set_resp is not None
        and engine.ip_address == "192.168.50.20"
        and engine.station_name == "horner-cell-node"
    )
    tests_record.append({
        "check": "DCP_Set_IP_and_Station_Name",
        "passed": set_passed,
    })

    # 5. PROFINET IO RT Cyclic Data Exchange
    rx_cyclic = ProfinetRTCyclicFrame(
        frame_id=0x8001,
        slot1_data=b"\x12\x34" * 16,
        slot1_iops=IOStatusQuality.GOOD,
        slot2_data=b"\x01" * 16,
        slot2_iops=IOStatusQuality.GOOD,
        cycle_counter=101,
        data_status=NORMAL_DATA_STATUS,
    )
    tx_bytes = engine.handle_cyclic_frame(rx_cyclic.serialize())
    cyclic_passed = False
    if tx_bytes:
        tx_frame = ProfinetRTCyclicFrame.deserialize(tx_bytes)
        cyclic_passed = (
            tx_frame.frame_id == 0x8001
            and tx_frame.slot1_iops == IOStatusQuality.GOOD
            and tx_frame.cycle_counter == 1
            and engine.cyclic_rx_count == 1
            and engine.cyclic_tx_count == 1
            and (engine.registers.read_word("%R430") & ProfinetStatusBits.CYCLIC_IO_ACTIVE) != 0
        )
    tests_record.append({
        "check": "PROFINET_IO_RT_Cyclic_Data_Exchange",
        "passed": cyclic_passed,
    })

    # 6. Consumer Fault Handling
    fault_cyclic = ProfinetRTCyclicFrame(
        frame_id=0x8001,
        slot1_iops=IOStatusQuality.BAD,
        slot2_iops=IOStatusQuality.GOOD,
    )
    engine.handle_cyclic_frame(fault_cyclic.serialize())
    fault_passed = (
        engine.consumer_fault is True
        and (engine.registers.read_word("%R430") & ProfinetStatusBits.CONSUMER_FAULT_BAD) != 0
    )
    tests_record.append({
        "check": "Consumer_IOCS_Fault_Detection",
        "passed": fault_passed,
    })

    # 7. Asynchronous Reset Handshake
    engine.registers.write_bit("%M101", True, privilege=PrivilegeMode.SYSTEM)
    engine.handle_cyclic_frame(rx_cyclic.serialize())
    reset_passed = (
        engine.cyclic_sequence == 1
        and engine.cyclic_rx_count == 1
        and engine.consumer_fault is False
        and engine.registers.read_bit("%M101") is False
    )
    tests_record.append({
        "check": "Asynchronous_Reset_Handshake",
        "passed": reset_passed,
    })

    all_passed = all(t["passed"] for t in tests_record)
    status_str = "success" if all_passed else "failed"

    evidence: Dict[str, Any] = {
        "status": status_str,
        "error_code": None if all_passed else "PROFINET_VERIFICATION_FAILED",
        "details": f"PROFINET IO RT protocol verification: {sum(1 for t in tests_record if t['passed'])}/{len(tests_record)} checks passed.",
        "data": {
            "protocol": "PROFINET IO RT / DCP (IEC 61158-6-10)",
            "tests": tests_record,
            "register_map": {
                "analog_registers": "%R430..%R435",
                "discrete_coils": "%M100..%M101",
            },
            "timestamp": time.time(),
        },
    }

    os.makedirs(os.path.dirname(output_evidence_path), exist_ok=True)
    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence
