"""Unit and integration tests for EtherNet/IP & CIP Protocol Telemetry Adapter Engine.

Work Package: W079 (Gate G8 Telemetry Protocols & Scaling Bridge / Gate G4 Simulation)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import struct
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.telemetry.ethernet_ip import (
    CIPClassCode,
    CIPDataType,
    CIPDataTypeCodec,
    CIPGeneralStatus,
    CIPRequest,
    CIPResponse,
    CIPServiceCode,
    CPFItem,
    CPFTypeId,
    EIPCommand,
    EIPHeader,
    EIPStatus,
    EPATH,
    EIP_CIP_ST_POU,
    EtherNetIpAdapterEngine,
    IdentityObject,
    IdentityStatusBits,
    LogicalSegment,
    LogicalType,
    SymbolicSegment,
    deserialize_cpf,
    serialize_cpf,
    validate_pure_st,
)


# ============================================================================
# 1. Encapsulation Header & CPF Tests
# ============================================================================

def test_eip_header_serialization_round_trip() -> None:
    """Verify 24-octet little-endian encapsulation header round trip."""
    header = EIPHeader(
        command=EIPCommand.REGISTER_SESSION,
        length=4,
        session_handle=0x12345678,
        status=EIPStatus.SUCCESS,
        sender_context=b"SCADA001",
        options=0,
    )
    raw = header.serialize()
    assert len(raw) == 24

    # Verify little-endian byte unpacking
    cmd, length, sess, status, ctx, opt = struct.unpack("<HHII8sI", raw)
    assert cmd == 0x0065
    assert length == 4
    assert sess == 0x12345678
    assert status == 0
    assert ctx == b"SCADA001"
    assert opt == 0

    deser, rem = EIPHeader.deserialize(raw + b"extra_data")
    assert deser.command == EIPCommand.REGISTER_SESSION
    assert deser.length == 4
    assert deser.session_handle == 0x12345678
    assert deser.sender_context == b"SCADA001"
    assert rem == b"extra_data"


def test_cpf_item_serialization() -> None:
    """Verify Common Packet Format (CPF) item and multi-item serialization."""
    null_addr = CPFItem.null_address()
    assert null_addr.type_id == CPFTypeId.NULL_ADDRESS
    assert null_addr.length == 0

    unconn_data = CPFItem.unconnected_data(b"\x0E\x03\x20\x01\x24\x01\x30\x01")
    assert unconn_data.type_id == CPFTypeId.UNCONNECTED_DATA
    assert unconn_data.length == 8

    cpf_bytes = serialize_cpf([null_addr, unconn_data])
    assert len(cpf_bytes) == 2 + (4 + 0) + (4 + 8)

    items = deserialize_cpf(cpf_bytes)
    assert len(items) == 2
    assert items[0].type_id == CPFTypeId.NULL_ADDRESS
    assert items[0].data == b""
    assert items[1].type_id == CPFTypeId.UNCONNECTED_DATA
    assert items[1].data == b"\x0E\x03\x20\x01\x24\x01\x30\x01"


def test_cpf_connected_address_and_data() -> None:
    """Verify Connected Address (0x00A1) and Connected Transport Data (0x00B1)."""
    conn_addr = CPFItem.connected_address(0xAABBCCDD)
    assert conn_addr.type_id == CPFTypeId.CONNECTED_ADDRESS
    assert len(conn_addr.data) == 4
    assert struct.unpack("<I", conn_addr.data)[0] == 0xAABBCCDD

    conn_data = CPFItem.connected_data(b"payload", sequence_count=42)
    assert conn_data.type_id == CPFTypeId.CONNECTED_DATA
    assert len(conn_data.data) == 2 + len(b"payload")
    seq = struct.unpack_from("<H", conn_data.data, 0)[0]
    assert seq == 42


# ============================================================================
# 2. CIP EPATH & Codec Tests
# ============================================================================

def test_epath_logical_segments() -> None:
    """Verify logical segment encoding and word count alignment."""
    # Class 1, Instance 1, Attribute 7 (Product Name)
    path = EPATH.from_logical(class_id=0x01, instance_id=0x01, attribute_id=0x07)
    b = path.encode()
    assert b == b"\x20\x01\x24\x01\x30\x07"
    assert len(b) == 6
    assert path.word_count == 3

    decoded = EPATH.decode(b)
    assert len(decoded.segments) == 3
    assert decoded.segments[0] == LogicalSegment(LogicalType.CLASS, 0x01)
    assert decoded.segments[1] == LogicalSegment(LogicalType.INSTANCE, 0x01)
    assert decoded.segments[2] == LogicalSegment(LogicalType.ATTRIBUTE, 0x07)


def test_epath_symbolic_tag_padding() -> None:
    """Verify ANSI extended symbol segment 0x91 with 16-bit word alignment padding."""
    # Odd length string "TagA" -> 4 chars, even
    # "TotalFlow" -> 9 chars, odd -> must append 0x00 pad byte
    seg_odd = SymbolicSegment("TotalFlow")
    encoded_odd = seg_odd.encode()
    assert encoded_odd[0] == 0x91
    assert encoded_odd[1] == 9
    assert encoded_odd[-1] == 0x00
    assert len(encoded_odd) % 2 == 0  # 12 bytes = 6 words

    seg_even = SymbolicSegment("Pressure")
    encoded_even = seg_even.encode()
    assert encoded_even[0] == 0x91
    assert encoded_even[1] == 8
    assert len(encoded_even) == 10  # 10 bytes = 5 words


def test_cip_request_response_codecs() -> None:
    """Verify CIP Request and Response binary wire encoding/decoding."""
    path = EPATH.from_logical(0x01, 0x01, 0x01)
    req = CIPRequest(service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE, epath=path)
    wire = req.encode()
    assert wire[0] == 0x0E
    assert wire[1] == 3  # 3 words

    decoded_req = CIPRequest.decode(wire)
    assert decoded_req.service_code == CIPServiceCode.GET_ATTRIBUTE_SINGLE
    assert decoded_req.epath.word_count == 3

    resp = CIPResponse(
        reply_service_code=0x8E,
        general_status=CIPGeneralStatus.SUCCESS,
        data=struct.pack("<H", 0x0059),
    )
    resp_wire = resp.encode()
    assert resp_wire[0] == 0x8E
    assert resp_wire[2] == 0x00  # Success

    decoded_resp = CIPResponse.decode(resp_wire)
    assert decoded_resp.reply_service_code == 0x8E
    assert decoded_resp.general_status == CIPGeneralStatus.SUCCESS
    assert decoded_resp.data == struct.pack("<H", 0x0059)


# ============================================================================
# 3. CIP Identity & Assembly Object Tests
# ============================================================================

def test_cip_identity_object() -> None:
    """Verify CIP Identity Object (Class 0x01, Instance 0x01) attributes."""
    ident = IdentityObject()
    # Vendor ID (Horner = 0x0059)
    status, data = ident.get_attribute_single(1)
    assert status == CIPGeneralStatus.SUCCESS
    assert struct.unpack("<H", data)[0] == 0x0059

    # Device Type (PLC = 0x000E)
    status, data = ident.get_attribute_single(2)
    assert status == CIPGeneralStatus.SUCCESS
    assert struct.unpack("<H", data)[0] == 0x000E

    # Product Name
    status, data = ident.get_attribute_single(7)
    assert status == CIPGeneralStatus.SUCCESS
    str_len = data[0]
    assert data[1:1 + str_len].decode("ascii") == "HE-EXL1E2"

    # Get Attributes All
    status, all_data = ident.get_attributes_all()
    assert status == CIPGeneralStatus.SUCCESS
    assert len(all_data) > 16


def test_cip_assembly_object() -> None:
    """Verify Assembly Object (Class 0x04) Input (100) and Output (101) instances."""
    engine = EtherNetIpAdapterEngine()
    # Read input assembly (read-only)
    input_bytes = engine.input_assembly.read_buffer()
    assert len(input_bytes) == 32

    # Write to input assembly should fail with ATTRIBUTE_NOT_SETTABLE
    res = engine.input_assembly.write_buffer(b"\x00" * 32)
    assert res == CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE

    # Output assembly is read-write
    out_payload = b"\x01\x02\x03\x04" * 4  # 16 bytes
    res_out = engine.output_assembly.write_buffer(out_payload)
    assert res_out == CIPGeneralStatus.SUCCESS
    assert engine.output_assembly.read_buffer() == out_payload


# ============================================================================
# 4. Engine Session & Packet Dispatch Tests
# ============================================================================

def test_engine_session_lifecycle() -> None:
    """Verify RegisterSession and UnRegisterSession lifecycle in adapter engine."""
    engine = EtherNetIpAdapterEngine()

    # RegisterSession
    reg_req = EIPHeader(command=EIPCommand.REGISTER_SESSION, length=4).serialize() + struct.pack("<HH", 1, 0)
    reg_resp = engine.handle_packet(reg_req)
    assert len(reg_resp) >= 28

    resp_hdr, resp_rem = EIPHeader.deserialize(reg_resp)
    assert resp_hdr.command == EIPCommand.REGISTER_SESSION
    assert resp_hdr.session_handle != 0
    assigned_handle = resp_hdr.session_handle
    assert assigned_handle in engine.active_sessions
    assert engine.registers.read_register("%R401") == 1

    # UnRegisterSession
    unreg_req = EIPHeader(command=EIPCommand.UNREGISTER_SESSION, session_handle=assigned_handle).serialize()
    engine.handle_packet(unreg_req)
    assert assigned_handle not in engine.active_sessions
    assert engine.registers.read_register("%R401") == 0


def test_engine_send_rr_data_get_attribute_single() -> None:
    """Verify SendRRData carrying CIP Get_Attribute_Single over registered session."""
    engine = EtherNetIpAdapterEngine()

    # Register session
    reg_req = EIPHeader(command=EIPCommand.REGISTER_SESSION, length=4).serialize() + struct.pack("<HH", 1, 0)
    resp = engine.handle_packet(reg_req)
    sess_handle = EIPHeader.deserialize(resp)[0].session_handle

    # Build SendRRData packet with CIP Get_Attribute_Single (Class 1, Instance 1, Attribute 1)
    path = EPATH.from_logical(0x01, 0x01, 0x01)
    cip_req = CIPRequest(service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE, epath=path).encode()
    cpf_payload = serialize_cpf([CPFItem.null_address(), CPFItem.unconnected_data(cip_req)])
    send_payload = struct.pack("<IH", 0, 0) + cpf_payload

    send_req = EIPHeader(command=EIPCommand.SEND_RR_DATA, length=len(send_payload), session_handle=sess_handle).serialize() + send_payload
    send_resp = engine.handle_packet(send_req)

    resp_hdr, resp_rem = EIPHeader.deserialize(send_resp)
    assert resp_hdr.command == EIPCommand.SEND_RR_DATA
    assert resp_hdr.status == EIPStatus.SUCCESS

    # Unpack response CPF
    resp_cpf = deserialize_cpf(resp_rem[6:])
    data_item = next(it for it in resp_cpf if it.type_id == CPFTypeId.UNCONNECTED_DATA)
    cip_resp = CIPResponse.decode(data_item.data)
    assert cip_resp.reply_service_code == 0x8E
    assert cip_resp.general_status == CIPGeneralStatus.SUCCESS
    assert struct.unpack("<H", cip_resp.data)[0] == 0x0059  # Horner Vendor ID


def test_engine_symbolic_tag_read_write() -> None:
    """Verify CIP Read Tag (0x4C) and Write Tag (0x4D) services."""
    engine = EtherNetIpAdapterEngine()

    # Register session
    reg_req = EIPHeader(command=EIPCommand.REGISTER_SESSION, length=4).serialize() + struct.pack("<HH", 1, 0)
    sess_handle = EIPHeader.deserialize(engine.handle_packet(reg_req))[0].session_handle

    # 1. Read Tag "SolidsDischargeTemp"
    path = EPATH.from_tag("SolidsDischargeTemp")
    read_cip = CIPRequest(service_code=CIPServiceCode.READ_TAG, epath=path, data=struct.pack("<H", 1)).encode()
    cpf_read = serialize_cpf([CPFItem.null_address(), CPFItem.unconnected_data(read_cip)])
    payload = struct.pack("<IH", 0, 0) + cpf_read
    packet = EIPHeader(command=EIPCommand.SEND_RR_DATA, length=len(payload), session_handle=sess_handle).serialize() + payload

    resp_raw = engine.handle_packet(packet)
    resp_items = deserialize_cpf(EIPHeader.deserialize(resp_raw)[1][6:])
    data_item = next(it for it in resp_items if it.type_id == CPFTypeId.UNCONNECTED_DATA)
    cip_resp = CIPResponse.decode(data_item.data)
    assert cip_resp.general_status == CIPGeneralStatus.SUCCESS

    # Payload has UINT16 type + float32
    raw_type, val = struct.unpack("<Hf", cip_resp.data)
    assert raw_type == int(CIPDataType.REAL)
    assert pytest.approx(val, rel=1e-3) == 1050.0

    # 2. Write Tag "SolidsDischargeTemp" -> 1120.5
    new_val_bytes = CIPDataTypeCodec.encode(CIPDataType.REAL, 1120.5)
    write_payload = struct.pack("<HH", int(CIPDataType.REAL), 1) + new_val_bytes
    write_cip = CIPRequest(service_code=CIPServiceCode.WRITE_TAG, epath=path, data=write_payload).encode()
    cpf_write = serialize_cpf([CPFItem.null_address(), CPFItem.unconnected_data(write_cip)])
    payload_w = struct.pack("<IH", 0, 0) + cpf_write
    packet_w = EIPHeader(command=EIPCommand.SEND_RR_DATA, length=len(payload_w), session_handle=sess_handle).serialize() + payload_w

    resp_w_raw = engine.handle_packet(packet_w)
    resp_w_items = deserialize_cpf(EIPHeader.deserialize(resp_w_raw)[1][6:])
    data_w_item = next(it for it in resp_w_items if it.type_id == CPFTypeId.UNCONNECTED_DATA)
    cip_w_resp = CIPResponse.decode(data_w_item.data)
    assert cip_w_resp.general_status == CIPGeneralStatus.SUCCESS
    assert engine.named_tags["SolidsDischargeTemp"][1] == pytest.approx(1120.5, rel=1e-3)


# ============================================================================
# 5. Register Synchronization & Reset Tests
# ============================================================================

def test_engine_register_table_synchronization() -> None:
    """Verify Horner OCS register reflection (%R400..%R405, %M93..%M94)."""
    table = RegisterTable()
    table.write_register("%M93", True)   # Enable adapter
    table.write_register("%M94", False)  # No reset

    engine = EtherNetIpAdapterEngine(register_table=table)
    engine.sync_registers()

    status_word = table.read_register("%R400")
    assert status_word & 0x0001 != 0  # Bit 0: EIP Server Active
    assert table.read_register("%R401") == 0
    assert table.read_register("%R402") == 0

    # Simulate packet handling
    reg_req = EIPHeader(command=EIPCommand.REGISTER_SESSION, length=4).serialize() + struct.pack("<HH", 1, 0)
    engine.handle_packet(reg_req)

    status_word = table.read_register("%R400")
    assert status_word & 0x0002 != 0  # Bit 1: Active Session Registered
    assert table.read_register("%R401") == 1
    assert table.read_register("%R402") == 1
    assert table.read_register("%R403") == 1

    # Trigger %M94 reset
    table.write_register("%M94", True)
    engine.sync_registers()
    assert table.read_register("%M94") is False  # Self-cleared
    assert table.read_register("%R401") == 0
    assert table.read_register("%R402") == 0
    assert table.read_register("%R403") == 0


# ============================================================================
# 6. Pure ST POU & Forbidden Ladder Logic Guard Tests
# ============================================================================

def test_pure_st_pou_ast_parsing() -> None:
    """Verify Pure ST POU syntax and register bindings."""
    val = validate_pure_st()
    assert val.status == AgentStatus.SUCCESS
    assert val.error_code is None

    ast = STParser.parse_pou(EIP_CIP_ST_POU)
    assert ast.name == "EtherNetIpTelemetryAdapter"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {"%R400", "%R401", "%R402", "%R403", "%R404", "%R405", "%M93", "%M94"}
    assert set(ast.bound_registers) == expected_bindings
    assert ast.statements_count > 0


@pytest.mark.parametrize(
    "ladder_token",
    [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 10",
        "XIC EnableAdapter",
        "XIO ResetCounters",
        "OTE StatusWord",
        "OTL BitServerActive",
        "OTU BitProtocolError",
    ],
)
def test_eip_forbidden_ladder_constructs_rejected(ladder_token: str) -> None:
    """Verify that any ladder logic constructs are strictly rejected."""
    tainted = f"{EIP_CIP_ST_POU}\n{ladder_token}\n"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(tainted)
    res = STParser.validate_code(tainted)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True
