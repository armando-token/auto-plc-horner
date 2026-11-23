"""Unit Test Suite for Industrial CANopen & DeviceNet Telemetry Adapter.

Work Package: W085 (Gate G8 / G4)
Classification: PRODUCTION_READY

Covers:
1. CANopen SDO expedited read/write parsing and generation across 1B, 2B, 4B.
2. CANopen SDO abort code generation (0x06010000, 0x06020000, 0x06090011, 0x05040001, 0x08000022).
3. TPDO/RPDO 8-byte payload packing/unpacking with Intel Little-Endian and Motorola Big-Endian byte swapping.
4. NMT state machine transitions and heartbeat watchdog timeout detection.
5. DeviceNet CIP Explicit message parsing (Get_Attribute_Single, Set_Attribute_Single).
6. DeviceNet Polled I/O connection produce/consume validation.
7. DeviceNet frame fragmentation reassembly engine.
8. Horner OCS register space synchronization (%R460..%R465, %M107..%M108) and reset handshake.
9. Pure IEC 61131-3 Structured Text (ST) POU compliance and anti-ladder guard.
"""

from __future__ import annotations

import struct
import time
from typing import Any, Dict

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.canopen_devicenet import (
    CANFrame,
    CANopenDeviceNetAdapterEngine,
    CANopenNMTCommand,
    CANopenNMTState,
    CANopenSDOAbort,
    CANopenSDOCommand,
    CANopenStatusBits,
    CanopenStatusBits,
    CANOPEN_DEVICENET_PURE_ST_POU,
    DeviceNetCIPService,
    DeviceNetCIPStatus,
    DeviceNetState,
    SDOFrame,
    run_canopen_devicenet_verification,
)


@pytest.fixture
def adapter() -> CANopenDeviceNetAdapterEngine:
    reg_table = RegisterTable()
    return CANopenDeviceNetAdapterEngine(node_id=16, mac_id=16, register_table=reg_table)


# ============================================================================
# Suite 1: CANopen SDO Expedited Read / Write
# ============================================================================

def test_sdo_expedited_write_4bytes(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify SDO expedited 4-byte download request and response."""
    payload = struct.pack("<BHB4s", CANopenSDOCommand.DOWNLOAD_EXPEDITED_4B, 0x2000, 0x01, struct.pack("<I", 0x12345678))
    frame = CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=payload)
    resp = adapter.handle_sdo_request(frame)

    assert resp.arbitration_id == adapter.cob_sdo_tx
    assert resp.dlc == 8
    assert resp.data[0] == CANopenSDOCommand.DOWNLOAD_RESPONSE
    idx, sub = struct.unpack("<HB", resp.data[1:4])
    assert idx == 0x2000
    assert sub == 0x01
    assert adapter.od[(0x2000, 0x01)].value == 0x12345678


def test_sdo_expedited_write_2bytes_and_1byte(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify SDO expedited 2-byte and 1-byte download writes."""
    # 2-byte write to %R462 via 0x6411:01
    payload2 = struct.pack("<BHB4s", CANopenSDOCommand.DOWNLOAD_EXPEDITED_2B, 0x6411, 0x01, struct.pack("<H2x", 4321))
    resp2 = adapter.handle_sdo_request(CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=payload2))
    assert resp2.data[0] == CANopenSDOCommand.DOWNLOAD_RESPONSE
    assert adapter.registers.read_word("%R462") == 4321

    # 1-byte write
    payload1 = struct.pack("<BHB4s", CANopenSDOCommand.DOWNLOAD_EXPEDITED_1B, 0x2002, 0x00, struct.pack("<B3x", 0x55))
    resp1 = adapter.handle_sdo_request(CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=payload1))
    assert resp1.data[0] == CANopenSDOCommand.DOWNLOAD_RESPONSE
    assert adapter.od[(0x2002, 0x00)].value == 0x55


def test_sdo_expedited_read_identity(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify SDO expedited upload read of standard identity objects."""
    # Read Device Type (0x1000)
    req1000 = struct.pack("<BHB4s", CANopenSDOCommand.UPLOAD_REQUEST, 0x1000, 0x00, b"\x00\x00\x00\x00")
    resp1000 = adapter.handle_sdo_request(CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=req1000))
    assert resp1000.data[0] == CANopenSDOCommand.UPLOAD_EXPEDITED_4B
    dev_type = struct.unpack("<I", resp1000.data[4:8])[0]
    assert dev_type == 0x00020191  # CiA 401

    # Read Vendor ID (0x1018:01)
    req1018 = struct.pack("<BHB4s", CANopenSDOCommand.UPLOAD_REQUEST, 0x1018, 0x01, b"\x00\x00\x00\x00")
    resp1018 = adapter.handle_sdo_request(CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=req1018))
    vendor_id = struct.unpack("<I", resp1018.data[4:8])[0]
    assert vendor_id == 0x00000059  # Horner APG


# ============================================================================
# Suite 2: CANopen SDO Abort Codes
# ============================================================================

def test_sdo_abort_object_not_exist(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify SDO abort when accessing non-existent index (0x06020000)."""
    req = struct.pack("<BHB4s", CANopenSDOCommand.UPLOAD_REQUEST, 0x9999, 0x00, b"\x00\x00\x00\x00")
    resp = adapter.handle_sdo_request(CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=req))
    assert resp.data[0] == CANopenSDOCommand.ABORT_TRANSFER
    abort_code = struct.unpack("<I", resp.data[4:8])[0]
    assert abort_code == CANopenSDOAbort.OBJECT_NOT_EXIST
    assert adapter.last_abort_code == CANopenSDOAbort.OBJECT_NOT_EXIST


def test_sdo_abort_subindex_not_exist(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify SDO abort when accessing invalid sub-index on existing object (0x06090011)."""
    req = struct.pack("<BHB4s", CANopenSDOCommand.UPLOAD_REQUEST, 0x1018, 0xFF, b"\x00\x00\x00\x00")
    resp = adapter.handle_sdo_request(CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=req))
    assert resp.data[0] == CANopenSDOCommand.ABORT_TRANSFER
    abort_code = struct.unpack("<I", resp.data[4:8])[0]
    assert abort_code == CANopenSDOAbort.SUBINDEX_NOT_EXIST


def test_sdo_abort_unsupported_write_access(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify SDO abort when writing to read-only object (0x06010000)."""
    req = struct.pack("<BHB4s", CANopenSDOCommand.DOWNLOAD_EXPEDITED_4B, 0x1000, 0x00, struct.pack("<I", 0x1234))
    resp = adapter.handle_sdo_request(CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=req))
    assert resp.data[0] == CANopenSDOCommand.ABORT_TRANSFER
    abort_code = struct.unpack("<I", resp.data[4:8])[0]
    assert abort_code == CANopenSDOAbort.UNSUPPORTED_ACCESS


def test_sdo_abort_in_stopped_state(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify SDO abort when device is in STOPPED state (0x08000022)."""
    adapter.transition_nmt(CANopenNMTState.STOPPED)
    req = struct.pack("<BHB4s", CANopenSDOCommand.UPLOAD_REQUEST, 0x1000, 0x00, b"\x00\x00\x00\x00")
    resp = adapter.handle_sdo_request(CANFrame(arbitration_id=adapter.cob_sdo_rx, dlc=8, data=req))
    assert resp.data[0] == CANopenSDOCommand.ABORT_TRANSFER
    abort_code = struct.unpack("<I", resp.data[4:8])[0]
    assert abort_code == CANopenSDOAbort.DATA_CANNOT_BE_STORED_DEVICE_STATE


# ============================================================================
# Suite 3: PDO Packing, Unpacking, and Endianness Control
# ============================================================================

def test_pdo_packing_and_unpacking_intel_le(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify TPDO assembly and RPDO ingestion with standard Intel Little-Endian."""
    adapter.transition_nmt(CANopenNMTState.OPERATIONAL)
    adapter.registers.write_word("%R464", 1234, privilege=PrivilegeMode.SYSTEM)
    adapter.registers.write_word("%R465", 5678, privilege=PrivilegeMode.SYSTEM)

    tpdo = adapter.assemble_tpdo1(byte_swap=False)
    assert tpdo is not None
    assert tpdo.arbitration_id == adapter.cob_tpdo1
    w0, w1 = struct.unpack("<2H", tpdo.data[:4])
    assert w0 == 1234
    assert w1 == 5678

    # Unpack RPDO
    rpdo_payload = struct.pack("<4H", 9876, 5432, 0, 0)
    rpdo_frame = CANFrame(arbitration_id=adapter.cob_rpdo1, dlc=8, data=rpdo_payload)
    success = adapter.ingest_rpdo1(rpdo_frame, byte_swap=False)
    assert success is True
    assert adapter.registers.read_word("%R462") == 9876
    assert adapter.registers.read_word("%R463") == 5432


def test_pdo_packing_motorola_big_endian(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify TPDO assembly and RPDO ingestion with Motorola Big-Endian byte swap."""
    adapter.transition_nmt(CANopenNMTState.OPERATIONAL)
    adapter.registers.write_word("%R464", 0x1234, privilege=PrivilegeMode.SYSTEM)
    adapter.registers.write_word("%R465", 0x5678, privilege=PrivilegeMode.SYSTEM)

    tpdo = adapter.assemble_tpdo1(byte_swap=True)
    assert tpdo is not None
    assert tpdo.data[:4] == b"\x12\x34\x56\x78"

    rpdo_payload = b"\xAB\xCD\xEF\x01\x00\x00\x00\x00"
    rpdo_frame = CANFrame(arbitration_id=adapter.cob_rpdo1, dlc=8, data=rpdo_payload)
    success = adapter.ingest_rpdo1(rpdo_frame, byte_swap=True)
    assert success is True
    assert adapter.registers.read_word("%R462") & 0xFFFF == 0xABCD
    assert adapter.registers.read_word("%R463") & 0xFFFF == 0xEF01


def test_pdo_gating_by_nmt_state(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify PDO communication is blocked in PRE_OPERATIONAL and STOPPED states."""
    adapter.transition_nmt(CANopenNMTState.PRE_OPERATIONAL)
    assert adapter.assemble_tpdo1() is None

    rpdo_frame = CANFrame(arbitration_id=adapter.cob_rpdo1, dlc=8, data=b"\x00" * 8)
    assert adapter.ingest_rpdo1(rpdo_frame) is False

    adapter.transition_nmt(CANopenNMTState.STOPPED)
    assert adapter.assemble_tpdo1() is None
    assert adapter.ingest_rpdo1(rpdo_frame) is False


# ============================================================================
# Suite 4: NMT State Machine & Heartbeat Watchdog
# ============================================================================

def test_nmt_state_machine_transitions(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify standard NMT master commands trigger expected slave state transitions."""
    assert adapter.nmt_state == CANopenNMTState.PRE_OPERATIONAL

    # Start Node -> OPERATIONAL
    assert adapter.handle_nmt_command(CANopenNMTCommand.START_REMOTE_NODE, 16) is True
    assert adapter.nmt_state == CANopenNMTState.OPERATIONAL

    # Enter Pre-Operational -> PRE_OPERATIONAL
    assert adapter.handle_nmt_command(CANopenNMTCommand.ENTER_PRE_OPERATIONAL, 16) is True
    assert adapter.nmt_state == CANopenNMTState.PRE_OPERATIONAL

    # Stop Node -> STOPPED
    assert adapter.handle_nmt_command(CANopenNMTCommand.STOP_REMOTE_NODE, 16) is True
    assert adapter.nmt_state == CANopenNMTState.STOPPED

    # Reset Node -> INITIALISING -> PRE_OPERATIONAL (auto-boot)
    assert adapter.handle_nmt_command(CANopenNMTCommand.RESET_NODE, 16) is True
    assert adapter.nmt_state == CANopenNMTState.PRE_OPERATIONAL


def test_heartbeat_watchdog_timeout(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify heartbeat consumer watchdog detects timeout and transitions to safe state."""
    adapter.transition_nmt(CANopenNMTState.OPERATIONAL)
    # Simulate elapsed time of 1500ms (> 1000ms threshold)
    adapter.last_heartbeat_rx_time = time.time() - 1.5
    timed_out = adapter.check_heartbeat_watchdog()

    assert timed_out is True
    assert adapter.heartbeat_timeout_detected is True
    assert adapter.nmt_state == CANopenNMTState.PRE_OPERATIONAL
    assert bool(adapter.registers.read_word("%R460") & CanopenStatusBits.HEARTBEAT_TIMEOUT_ERR)


# ============================================================================
# Suite 5: DeviceNet CIP Explicit Messaging
# ============================================================================

def test_devicenet_explicit_get_identity(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify DeviceNet CIP Get_Attribute_Single returns Horner APG Vendor ID."""
    req = CANFrame(
        arbitration_id=adapter.dnet_explicit_rx,
        dlc=8,
        data=bytes([0x01, DeviceNetCIPService.GET_ATTRIBUTE_SINGLE, 0x20, 0x01, 0x24, 0x01, 0x30, 0x01]),
    )
    resp = adapter.handle_devicenet_explicit(req)
    assert resp is not None
    assert resp.arbitration_id == adapter.dnet_explicit_tx
    assert resp.data[1] == (DeviceNetCIPService.GET_ATTRIBUTE_SINGLE | 0x80)
    assert resp.data[2] == DeviceNetCIPStatus.SUCCESS
    vendor_id = struct.unpack("<H", resp.data[3:5])[0]
    assert vendor_id == 0x0059


def test_devicenet_explicit_set_attribute(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify DeviceNet CIP Set_Attribute_Single updates Assembly parameter."""
    req_payload = bytes([0x02, DeviceNetCIPService.SET_ATTRIBUTE_SINGLE, 0x20, 0x04, 0x24, 0x01, 0x30, 0x03]) + struct.pack("<H", 7777)
    req = CANFrame(arbitration_id=adapter.dnet_explicit_rx, dlc=len(req_payload), data=req_payload)
    resp = adapter.handle_devicenet_explicit(req)

    assert resp is not None
    assert resp.data[1] == (DeviceNetCIPService.SET_ATTRIBUTE_SINGLE | 0x80)
    assert resp.data[2] == DeviceNetCIPStatus.SUCCESS
    assert adapter.registers.read_word("%R462") == 7777


def test_devicenet_explicit_unsupported_service(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify DeviceNet CIP error for unsupported service code."""
    req = CANFrame(
        arbitration_id=adapter.dnet_explicit_rx,
        dlc=4,
        data=bytes([0x03, 0x4F, 0x20, 0x01]),
    )
    resp = adapter.handle_devicenet_explicit(req)
    assert resp is not None
    assert resp.data[2] == DeviceNetCIPStatus.SERVICE_NOT_SUPPORTED


# ============================================================================
# Suite 6: DeviceNet Polled I/O Connection
# ============================================================================

def test_devicenet_polled_io_produce_consume(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify DeviceNet master poll consumed into %R462..%R463 and slave response produced."""
    adapter.registers.write_word("%R464", 1122, privilege=PrivilegeMode.SYSTEM)
    adapter.registers.write_word("%R465", 3344, privilege=PrivilegeMode.SYSTEM)

    poll_req = CANFrame(
        arbitration_id=adapter.dnet_poll_req,
        dlc=4,
        data=struct.pack("<2H", 5566, 7788),
    )
    poll_resp = adapter.handle_devicenet_poll(poll_req)

    assert poll_resp is not None
    assert poll_resp.arbitration_id == adapter.dnet_poll_resp
    assert adapter.registers.read_word("%R462") == 5566
    assert adapter.registers.read_word("%R463") == 7788
    p0, p1 = struct.unpack("<2H", poll_resp.data[:4])
    assert p0 == 1122
    assert p1 == 3344
    assert adapter.devicenet_poll_cycles == 1


# ============================================================================
# Suite 7: DeviceNet Multi-Frame Fragmentation Reassembly
# ============================================================================

def test_devicenet_fragmentation_reassembly(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify DeviceNet fragmentation engine correctly collects and reassembles frames."""
    # First fragment: FragType=2, Seq=0 -> 0x80
    f1 = CANFrame(
        arbitration_id=adapter.dnet_explicit_rx,
        dlc=8,
        data=bytes([0x80, 0x01, DeviceNetCIPService.GET_ATTRIBUTE_SINGLE, 0x20, 0x01, 0x24, 0x01, 0x30]),
    )
    r1 = adapter.handle_devicenet_explicit(f1)
    assert r1 is None
    assert adapter.fragmentation_active is True

    # Last fragment: FragType=3, Seq=1 -> 0xC1
    f2 = CANFrame(
        arbitration_id=adapter.dnet_explicit_rx,
        dlc=2,
        data=bytes([0xC1, 0x01]),
    )
    r2 = adapter.handle_devicenet_explicit(f2)
    assert r2 is not None
    assert r2.data[2] == DeviceNetCIPStatus.SUCCESS
    assert adapter.fragmented_messages_reassembled == 1


# ============================================================================
# Suite 8: Horner Register Space Synchronization & Reset
# ============================================================================

def test_horner_register_sync_and_reset(adapter: CANopenDeviceNetAdapterEngine) -> None:
    """Verify register table synchronization and %M108 asynchronous reset handshake."""
    adapter.last_abort_code = CANopenSDOAbort.OBJECT_NOT_EXIST
    adapter.heartbeat_timeout_detected = True
    adapter.sync_registers()

    r460 = adapter.registers.read_word("%R460")
    assert bool(r460 & CanopenStatusBits.PROTOCOL_ABORT_ERR)
    assert bool(r460 & CanopenStatusBits.HEARTBEAT_TIMEOUT_ERR)

    # Trigger reset via %M108
    adapter.registers.write_bit("%M108", True, privilege=PrivilegeMode.SYSTEM)
    adapter.sync_registers()

    # Coil should be self-cleared
    assert adapter.registers.read_bit("%M108") is False
    assert adapter.last_abort_code is None
    assert adapter.heartbeat_timeout_detected is False


# ============================================================================
# Suite 9: Pure ST POU Compliance and Ladder Guard
# ============================================================================

def test_pure_st_pou_ast_parsing_and_ladder_rejection() -> None:
    """Verify pure ST POU validates cleanly and rejects ladder constructs."""
    # ST Validation
    st_res = STParser.validate_code(CANOPEN_DEVICENET_PURE_ST_POU)
    assert st_res.status == AgentStatus.SUCCESS

    ast = STParser.parse_pou(CANOPEN_DEVICENET_PURE_ST_POU)
    assert ast.name == "CanopenDeviceNetAdapter"
    assert ast.pou_type == POUType.PROGRAM
    assert "%R460" in ast.bound_registers
    assert "%M107" in ast.bound_registers

    # Anti-Ladder Guard
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("---[ ]---")

    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("---( )---")

    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("RUNG 1: XIC %M107 OTE %M108 END_RUNG")


def test_full_canopen_devicenet_verification_runner(tmp_path: Any) -> None:
    """Verify end-to-end verification runner produces valid evidence JSON."""
    ev_path = str(tmp_path / "canopen_devicenet_evidence.json")
    evidence = run_canopen_devicenet_verification(ev_path)

    assert evidence["status"] == "success"
    assert evidence["data"]["checks_passed"] == 9
    assert evidence["data"]["total_checks"] == 9
    assert len(evidence["data"]["tests"]) == 9
